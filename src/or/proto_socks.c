/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#include "addressmap.h"
#include "buffers.h"
#include "control.h"
#include "config.h"
#include "ext_orport.h"
#include "proto_socks.h"
#include "reasons.h"

static void socks_request_set_socks5_error(socks_request_t *req,
                              socks5_reply_status_t reason);

static int parse_socks(const char *data, size_t datalen, socks_request_t *req,
                       int log_sockstype, int safe_socks, ssize_t *drain_out,
                       size_t *want_length_out);
static int parse_socks_client(const uint8_t *data, size_t datalen,
                              int state, char **reason,
                              ssize_t *drain_out);
/**
 * Wait this many seconds before warning the user about using SOCKS unsafely
 * again. */
#define SOCKS_WARN_INTERVAL 5

/** Warn that the user application has made an unsafe socks request using
 * protocol <b>socks_protocol</b> on port <b>port</b>.  Don't warn more than
 * once per SOCKS_WARN_INTERVAL, unless <b>safe_socks</b> is set. */
static void
log_unsafe_socks_warning(int socks_protocol, const char *address,
                         uint16_t port, int safe_socks)
{
  static ratelim_t socks_ratelim = RATELIM_INIT(SOCKS_WARN_INTERVAL);

  if (safe_socks) {
    log_fn_ratelim(&socks_ratelim, LOG_WARN, LD_APP,
             "Your application (using socks%d to port %d) is giving "
             "Tor only an IP address. Applications that do DNS resolves "
             "themselves may leak information. Consider using Socks4A "
             "(e.g. via privoxy or socat) instead. For more information, "
             "please see https://wiki.torproject.org/TheOnionRouter/"
             "TorFAQ#SOCKSAndDNS.%s",
             socks_protocol,
             (int)port,
             safe_socks ? " Rejecting." : "");
  }
  control_event_client_status(LOG_WARN,
                              "DANGEROUS_SOCKS PROTOCOL=SOCKS%d ADDRESS=%s:%d",
                              socks_protocol, address, (int)port);
}

/** Do not attempt to parse socks messages longer than this.  This value is
 * actually significantly higher than the longest possible socks message. */
#define MAX_SOCKS_MESSAGE_LEN 512

/** Return a new socks_request_t. */
socks_request_t *
socks_request_new(void)
{
  return tor_malloc_zero(sizeof(socks_request_t));
}

/** Free all storage held in the socks_request_t <b>req</b>. */
void
socks_request_free(socks_request_t *req)
{
  if (!req)
    return;
  if (req->username) {
    memwipe(req->username, 0x10, req->usernamelen);
    tor_free(req->username);
  }
  if (req->password) {
    memwipe(req->password, 0x04, req->passwordlen);
    tor_free(req->password);
  }
  memwipe(req, 0xCC, sizeof(socks_request_t));
  tor_free(req);
}

/** There is a (possibly incomplete) socks handshake on <b>buf</b>, of one
 * of the forms
 *  - socks4: "socksheader username\\0"
 *  - socks4a: "socksheader username\\0 destaddr\\0"
 *  - socks5 phase one: "version #methods methods"
 *  - socks5 phase two: "version command 0 addresstype..."
 * If it's a complete and valid handshake, and destaddr fits in
 *   MAX_SOCKS_ADDR_LEN bytes, then pull the handshake off the buf,
 *   assign to <b>req</b>, and return 1.
 *
 * If it's invalid or too big, return -1.
 *
 * Else it's not all there yet, leave buf alone and return 0.
 *
 * If you want to specify the socks reply, write it into <b>req->reply</b>
 *   and set <b>req->replylen</b>, else leave <b>req->replylen</b> alone.
 *
 * If <b>log_sockstype</b> is non-zero, then do a notice-level log of whether
 * the connection is possibly leaking DNS requests locally or not.
 *
 * If <b>safe_socks</b> is true, then reject unsafe socks protocols.
 *
 * If returning 0 or -1, <b>req->address</b> and <b>req->port</b> are
 * undefined.
 */
int
fetch_from_buf_socks(buf_t *buf, socks_request_t *req,
                     int log_sockstype, int safe_socks)
{
  int res;
  ssize_t n_drain;
  size_t want_length = 128;
  const char *head = NULL;
  size_t datalen = 0;

  if (buf_datalen(buf) < 2) /* version and another byte */
    return 0;

  do {
    n_drain = 0;
    buf_pullup(buf, want_length, &head, &datalen);
    tor_assert(head && datalen >= 2);
    want_length = 0;

    res = parse_socks(head, datalen, req, log_sockstype,
                      safe_socks, &n_drain, &want_length);

    if (n_drain < 0)
      buf_clear(buf);
    else if (n_drain > 0)
      buf_drain(buf, n_drain);

  } while (res == 0 && head && want_length < buf_datalen(buf) &&
           buf_datalen(buf) >= 2);

  return res;
}

/** Create a SOCKS5 reply message with <b>reason</b> in its REP field and
 * have Tor send it as error response to <b>req</b>.
 */
static void
socks_request_set_socks5_error(socks_request_t *req,
                  socks5_reply_status_t reason)
{
   req->replylen = 10;
   memset(req->reply,0,10);

   req->reply[0] = 0x05;   // VER field.
   req->reply[1] = reason; // REP field.
   req->reply[3] = 0x01;   // ATYP field.
}

static const char SOCKS_PROXY_IS_NOT_AN_HTTP_PROXY_MSG[] =
  "HTTP/1.0 501 Tor is not an HTTP Proxy\r\n"
  "Content-Type: text/html; charset=iso-8859-1\r\n\r\n"
  "<html>\n"
  "<head>\n"
  "<title>This is a SOCKS Proxy, Not An HTTP Proxy</title>\n"
  "</head>\n"
  "<body>\n"
  "<h1>This is a SOCKs proxy, not an HTTP proxy.</h1>\n"
  "<p>\n"
  "It appears you have configured your web browser to use this Tor port as\n"
  "an HTTP proxy.\n"
  "</p><p>\n"
  "This is not correct: This port is configured as a SOCKS proxy, not\n"
  "an HTTP proxy. If you need an HTTP proxy tunnel, use the HTTPTunnelPort\n"
  "configuration option in place of, or in addition to, SOCKSPort.\n"
  "Please configure your client accordingly.\n"
  "</p>\n"
  "<p>\n"
  "See <a href=\"https://www.torproject.org/documentation.html\">"
  "https://www.torproject.org/documentation.html</a> for more "
  "information.\n"
  "</p>\n"
  "</body>\n"
  "</html>\n";

/** Implementation helper to implement fetch_from_*_socks.  Instead of looking
 * at a buffer's contents, we look at the <b>datalen</b> bytes of data in
 * <b>data</b>. Instead of removing data from the buffer, we set
 * <b>drain_out</b> to the amount of data that should be removed (or -1 if the
 * buffer should be cleared).  Instead of pulling more data into the first
 * chunk of the buffer, we set *<b>want_length_out</b> to the number of bytes
 * we'd like to see in the input buffer, if they're available. */
static int
parse_socks(const char *data, size_t datalen, socks_request_t *req,
            int log_sockstype, int safe_socks, ssize_t *drain_out,
            size_t *want_length_out)
{
  unsigned int len;
  char tmpbuf[TOR_ADDR_BUF_LEN+1];
  tor_addr_t destaddr;
  uint32_t destip;
  uint8_t socksver;
  char *next, *startaddr;
  unsigned char usernamelen, passlen;
  struct in_addr in;

  if (datalen < 2) {
    /* We always need at least 2 bytes. */
    *want_length_out = 2;
    return 0;
  }

  if (req->socks_version == 5 && !req->got_auth) {
    /* See if we have received authentication.  Strictly speaking, we should
       also check whether we actually negotiated username/password
       authentication.  But some broken clients will send us authentication
       even if we negotiated SOCKS_NO_AUTH. */
    if (*data == 1) { /* username/pass version 1 */
      /* Format is: authversion [1 byte] == 1
                    usernamelen [1 byte]
                    username    [usernamelen bytes]
                    passlen     [1 byte]
                    password    [passlen bytes] */
      usernamelen = (unsigned char)*(data + 1);
      if (datalen < 2u + usernamelen + 1u) {
        *want_length_out = 2u + usernamelen + 1u;
        return 0;
      }
      passlen = (unsigned char)*(data + 2u + usernamelen);
      if (datalen < 2u + usernamelen + 1u + passlen) {
        *want_length_out = 2u + usernamelen + 1u + passlen;
        return 0;
      }
      req->replylen = 2; /* 2 bytes of response */
      req->reply[0] = 1; /* authversion == 1 */
      req->reply[1] = 0; /* authentication successful */
      log_debug(LD_APP,
               "socks5: Accepted username/password without checking.");
      if (usernamelen) {
        req->username = tor_memdup(data+2u, usernamelen);
        req->usernamelen = usernamelen;
      }
      if (passlen) {
        req->password = tor_memdup(data+3u+usernamelen, passlen);
        req->passwordlen = passlen;
      }
      *drain_out = 2u + usernamelen + 1u + passlen;
      req->got_auth = 1;
      *want_length_out = 7; /* Minimal socks5 command. */
      return 0;
    } else if (req->auth_type == SOCKS_USER_PASS) {
      /* unknown version byte */
      log_warn(LD_APP, "Socks5 username/password version %d not recognized; "
               "rejecting.", (int)*data);
      return -1;
    }
  }

  socksver = *data;

  switch (socksver) { /* which version of socks? */
    case 5: /* socks5 */

      if (req->socks_version != 5) { /* we need to negotiate a method */
        unsigned char nummethods = (unsigned char)*(data+1);
        int have_user_pass, have_no_auth;
        int r=0;
        tor_assert(!req->socks_version);
        if (datalen < 2u+nummethods) {
          *want_length_out = 2u+nummethods;
          return 0;
        }
        if (!nummethods)
          return -1;
        req->replylen = 2; /* 2 bytes of response */
        req->reply[0] = 5; /* socks5 reply */
        have_user_pass = (memchr(data+2, SOCKS_USER_PASS, nummethods) !=NULL);
        have_no_auth   = (memchr(data+2, SOCKS_NO_AUTH,   nummethods) !=NULL);
        if (have_user_pass && !(have_no_auth && req->socks_prefer_no_auth)) {
          req->auth_type = SOCKS_USER_PASS;
          req->reply[1] = SOCKS_USER_PASS; /* tell client to use "user/pass"
                                              auth method */
          req->socks_version = 5; /* remember we've already negotiated auth */
          log_debug(LD_APP,"socks5: accepted method 2 (username/password)");
          r=0;
        } else if (have_no_auth) {
          req->reply[1] = SOCKS_NO_AUTH; /* tell client to use "none" auth
                                            method */
          req->socks_version = 5; /* remember we've already negotiated auth */
          log_debug(LD_APP,"socks5: accepted method 0 (no authentication)");
          r=0;
        } else {
          log_warn(LD_APP,
                    "socks5: offered methods don't include 'no auth' or "
                    "username/password. Rejecting.");
          req->reply[1] = '\xFF'; /* reject all methods */
          r=-1;
        }
        /* Remove packet from buf. Some SOCKS clients will have sent extra
         * junk at this point; let's hope it's an authentication message. */
        *drain_out = 2u + nummethods;

        return r;
      }
      if (req->auth_type != SOCKS_NO_AUTH && !req->got_auth) {
        log_warn(LD_APP,
                 "socks5: negotiated authentication, but none provided");
        return -1;
      }
      /* we know the method; read in the request */
      log_debug(LD_APP,"socks5: checking request");
      if (datalen < 7) {/* basic info plus >=1 for addr plus 2 for port */
        *want_length_out = 7;
        return 0; /* not yet */
      }
      req->command = (unsigned char) *(data+1);
      if (req->command != SOCKS_COMMAND_CONNECT &&
          req->command != SOCKS_COMMAND_RESOLVE &&
          req->command != SOCKS_COMMAND_RESOLVE_PTR) {
        /* not a connect or resolve or a resolve_ptr? we don't support it. */
        socks_request_set_socks5_error(req,SOCKS5_COMMAND_NOT_SUPPORTED);

        log_warn(LD_APP,"socks5: command %d not recognized. Rejecting.",
                 req->command);
        return -1;
      }
      switch (*(data+3)) { /* address type */
        case 1: /* IPv4 address */
        case 4: /* IPv6 address */ {
          const int is_v6 = *(data+3) == 4;
          const unsigned addrlen = is_v6 ? 16 : 4;
          log_debug(LD_APP,"socks5: ipv4 address type");
          if (datalen < 6+addrlen) {/* ip/port there? */
            *want_length_out = 6+addrlen;
            return 0; /* not yet */
          }

          if (is_v6)
            tor_addr_from_ipv6_bytes(&destaddr, data+4);
          else
            tor_addr_from_ipv4n(&destaddr, get_uint32(data+4));

          tor_addr_to_str(tmpbuf, &destaddr, sizeof(tmpbuf), 1);

          if (BUG(strlen(tmpbuf)+1 > MAX_SOCKS_ADDR_LEN)) {
            /* LCOV_EXCL_START -- This branch is unreachable, given the
             * size of tmpbuf and the actual value of MAX_SOCKS_ADDR_LEN */
            socks_request_set_socks5_error(req, SOCKS5_GENERAL_ERROR);
            log_warn(LD_APP,
                     "socks5 IP takes %d bytes, which doesn't fit in %d. "
                     "Rejecting.",
                     (int)strlen(tmpbuf)+1,(int)MAX_SOCKS_ADDR_LEN);
            return -1;
            /* LCOV_EXCL_STOP */
          }
          strlcpy(req->address,tmpbuf,sizeof(req->address));
          req->port = ntohs(get_uint16(data+4+addrlen));
          *drain_out = 6+addrlen;
          if (req->command != SOCKS_COMMAND_RESOLVE_PTR &&
              !addressmap_have_mapping(req->address,0)) {
            log_unsafe_socks_warning(5, req->address, req->port, safe_socks);
            if (safe_socks) {
              socks_request_set_socks5_error(req, SOCKS5_NOT_ALLOWED);
              return -1;
            }
          }
          return 1;
        }
        case 3: /* fqdn */
          log_debug(LD_APP,"socks5: fqdn address type");
          if (req->command == SOCKS_COMMAND_RESOLVE_PTR) {
            socks_request_set_socks5_error(req,
                                           SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED);
            log_warn(LD_APP, "socks5 received RESOLVE_PTR command with "
                     "hostname type. Rejecting.");
            return -1;
          }
          len = (unsigned char)*(data+4);
          if (datalen < 7+len) { /* addr/port there? */
            *want_length_out = 7+len;
            return 0; /* not yet */
          }
          if (BUG(len+1 > MAX_SOCKS_ADDR_LEN)) {
            /* LCOV_EXCL_START -- unreachable, since len is at most 255,
             * and MAX_SOCKS_ADDR_LEN is 256. */
            socks_request_set_socks5_error(req, SOCKS5_GENERAL_ERROR);
            log_warn(LD_APP,
                     "socks5 hostname is %d bytes, which doesn't fit in "
                     "%d. Rejecting.", len+1,MAX_SOCKS_ADDR_LEN);
            return -1;
            /* LCOV_EXCL_STOP */
          }
          memcpy(req->address,data+5,len);
          req->address[len] = 0;
          req->port = ntohs(get_uint16(data+5+len));
          *drain_out = 5+len+2;

          if (!string_is_valid_hostname(req->address)) {
            socks_request_set_socks5_error(req, SOCKS5_GENERAL_ERROR);

            log_warn(LD_PROTOCOL,
                     "Your application (using socks5 to port %d) gave Tor "
                     "a malformed hostname: %s. Rejecting the connection.",
                     req->port, escaped_safe_str_client(req->address));
            return -1;
          }
          if (log_sockstype)
            log_notice(LD_APP,
                  "Your application (using socks5 to port %d) instructed "
                  "Tor to take care of the DNS resolution itself if "
                  "necessary. This is good.", req->port);
          return 1;
        default: /* unsupported */
          socks_request_set_socks5_error(req,
                                         SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED);
          log_warn(LD_APP,"socks5: unsupported address type %d. Rejecting.",
                   (int) *(data+3));
          return -1;
      }
      tor_assert(0);
      break;
    case 4: { /* socks4 */
      enum {socks4, socks4a} socks4_prot = socks4a;
      const char *authstart, *authend;
      /* http://ss5.sourceforge.net/socks4.protocol.txt */
      /* http://ss5.sourceforge.net/socks4A.protocol.txt */

      req->socks_version = 4;
      if (datalen < SOCKS4_NETWORK_LEN) {/* basic info available? */
        *want_length_out = SOCKS4_NETWORK_LEN;
        return 0; /* not yet */
      }
      // buf_pullup(buf, 1280);
      req->command = (unsigned char) *(data+1);
      if (req->command != SOCKS_COMMAND_CONNECT &&
          req->command != SOCKS_COMMAND_RESOLVE) {
        /* not a connect or resolve? we don't support it. (No resolve_ptr with
         * socks4.) */
        log_warn(LD_APP,"socks4: command %d not recognized. Rejecting.",
                 req->command);
        return -1;
      }

      req->port = ntohs(get_uint16(data+2));
      destip = ntohl(get_uint32(data+4));
      if ((!req->port && req->command!=SOCKS_COMMAND_RESOLVE) || !destip) {
        log_warn(LD_APP,"socks4: Port or DestIP is zero. Rejecting.");
        return -1;
      }
      if (destip >> 8) {
        log_debug(LD_APP,"socks4: destip not in form 0.0.0.x.");
        in.s_addr = htonl(destip);
        tor_inet_ntoa(&in,tmpbuf,sizeof(tmpbuf));
        if (BUG(strlen(tmpbuf)+1 > MAX_SOCKS_ADDR_LEN)) {
          /* LCOV_EXCL_START -- This branch is unreachable, given the
           * size of tmpbuf and the actual value of MAX_SOCKS_ADDR_LEN */
          log_debug(LD_APP,"socks4 addr (%d bytes) too long. Rejecting.",
                    (int)strlen(tmpbuf));
          return -1;
          /* LCOV_EXCL_STOP */
        }
        log_debug(LD_APP,
                  "socks4: successfully read destip (%s)",
                  safe_str_client(tmpbuf));
        socks4_prot = socks4;
      }

      authstart = data + SOCKS4_NETWORK_LEN;
      next = memchr(authstart, 0,
                    datalen-SOCKS4_NETWORK_LEN);
      if (!next) {
        if (datalen >= 1024) {
          log_debug(LD_APP, "Socks4 user name too long; rejecting.");
          return -1;
        }
        log_debug(LD_APP,"socks4: Username not here yet.");
        *want_length_out = datalen+1024; /* More than we need, but safe */
        return 0;
      }
      authend = next;
      tor_assert(next < data+datalen);

      startaddr = NULL;
      if (socks4_prot != socks4a &&
          !addressmap_have_mapping(tmpbuf,0)) {
        log_unsafe_socks_warning(4, tmpbuf, req->port, safe_socks);

        if (safe_socks)
          return -1;
      }
      if (socks4_prot == socks4a) {
        if (next+1 == data+datalen) {
          log_debug(LD_APP,"socks4: No part of destaddr here yet.");
          *want_length_out = datalen + 1024; /* More than we need, but safe */
          return 0;
        }
        startaddr = next+1;
        next = memchr(startaddr, 0, data + datalen - startaddr);
        if (!next) {
          if (datalen >= 1024) {
            log_debug(LD_APP,"socks4: Destaddr too long.");
            return -1;
          }
          log_debug(LD_APP,"socks4: Destaddr not all here yet.");
          *want_length_out = datalen + 1024; /* More than we need, but safe */
          return 0;
        }
        if (MAX_SOCKS_ADDR_LEN <= next-startaddr) {
          log_warn(LD_APP,"socks4: Destaddr too long. Rejecting.");
          return -1;
        }
        // tor_assert(next < buf->cur+buf_datalen(buf));

        if (log_sockstype)
          log_notice(LD_APP,
                     "Your application (using socks4a to port %d) instructed "
                     "Tor to take care of the DNS resolution itself if "
                     "necessary. This is good.", req->port);
      }
      log_debug(LD_APP,"socks4: Everything is here. Success.");
      strlcpy(req->address, startaddr ? startaddr : tmpbuf,
              sizeof(req->address));
      if (!string_is_valid_hostname(req->address)) {
        log_warn(LD_PROTOCOL,
                 "Your application (using socks4 to port %d) gave Tor "
                 "a malformed hostname: %s. Rejecting the connection.",
                 req->port, escaped_safe_str_client(req->address));
        return -1;
      }
      if (authend != authstart) {
        req->got_auth = 1;
        req->usernamelen = authend - authstart;
        req->username = tor_memdup(authstart, authend - authstart);
      }
      /* next points to the final \0 on inbuf */
      *drain_out = next - data + 1;
      return 1;
    }
    case 'G': /* get */
    case 'H': /* head */
    case 'P': /* put/post */
    case 'C': /* connect */
      strlcpy((char*)req->reply, SOCKS_PROXY_IS_NOT_AN_HTTP_PROXY_MSG,
              MAX_SOCKS_REPLY_LEN);
      req->replylen = strlen((char*)req->reply)+1;
      /* fall through */
    default: /* version is not socks4 or socks5 */
      log_warn(LD_APP,
               "Socks version %d not recognized. (This port is not an "
               "HTTP proxy; did you want to use HTTPTunnelPort?)",
               *(data));
      {
        /* Tell the controller the first 8 bytes. */
        char *tmp = tor_strndup(data, datalen < 8 ? datalen : 8);
        control_event_client_status(LOG_WARN,
                                    "SOCKS_UNKNOWN_PROTOCOL DATA=\"%s\"",
                                    escaped(tmp));
        tor_free(tmp);
      }
      return -1;
  }
}

/** Inspect a reply from SOCKS server stored in <b>buf</b> according
 * to <b>state</b>, removing the protocol data upon success. Return 0 on
 * incomplete response, 1 on success and -1 on error, in which case
 * <b>reason</b> is set to a descriptive message (free() when finished
 * with it).
 *
 * As a special case, 2 is returned when user/pass is required
 * during SOCKS5 handshake and user/pass is configured.
 */
int
fetch_from_buf_socks_client(buf_t *buf, int state, char **reason)
{
  ssize_t drain = 0;
  int r;
  const char *head = NULL;
  size_t datalen = 0;

  if (buf_datalen(buf) < 2)
    return 0;

  buf_pullup(buf, MAX_SOCKS_MESSAGE_LEN, &head, &datalen);
  tor_assert(head && datalen >= 2);

  r = parse_socks_client((uint8_t*)head, datalen,
                         state, reason, &drain);
  if (drain > 0)
    buf_drain(buf, drain);
  else if (drain < 0)
    buf_clear(buf);

  return r;
}

/** Implementation logic for fetch_from_*_socks_client. */
static int
parse_socks_client(const uint8_t *data, size_t datalen,
                   int state, char **reason,
                   ssize_t *drain_out)
{
  unsigned int addrlen;
  *drain_out = 0;
  if (datalen < 2)
    return 0;

  switch (state) {
    case PROXY_SOCKS4_WANT_CONNECT_OK:
      /* Wait for the complete response */
      if (datalen < 8)
        return 0;

      if (data[1] != 0x5a) {
        *reason = tor_strdup(socks4_response_code_to_string(data[1]));
        return -1;
      }

      /* Success */
      *drain_out = 8;
      return 1;

    case PROXY_SOCKS5_WANT_AUTH_METHOD_NONE:
      /* we don't have any credentials */
      if (data[1] != 0x00) {
        *reason = tor_strdup("server doesn't support any of our "
                             "available authentication methods");
        return -1;
      }

      log_info(LD_NET, "SOCKS 5 client: continuing without authentication");
      *drain_out = -1;
      return 1;

    case PROXY_SOCKS5_WANT_AUTH_METHOD_RFC1929:
      /* we have a username and password. return 1 if we can proceed without
       * providing authentication, or 2 otherwise. */
      switch (data[1]) {
        case 0x00:
          log_info(LD_NET, "SOCKS 5 client: we have auth details but server "
                            "doesn't require authentication.");
          *drain_out = -1;
          return 1;
        case 0x02:
          log_info(LD_NET, "SOCKS 5 client: need authentication.");
          *drain_out = -1;
          return 2;
        /* fall through */
      }

      *reason = tor_strdup("server doesn't support any of our available "
                           "authentication methods");
      return -1;

    case PROXY_SOCKS5_WANT_AUTH_RFC1929_OK:
      /* handle server reply to rfc1929 authentication */
      if (data[1] != 0x00) {
        *reason = tor_strdup("authentication failed");
        return -1;
      }

      log_info(LD_NET, "SOCKS 5 client: authentication successful.");
      *drain_out = -1;
      return 1;

    case PROXY_SOCKS5_WANT_CONNECT_OK:
      /* response is variable length. BND.ADDR, etc, isn't needed
       * (don't bother with buf_pullup()), but make sure to eat all
       * the data used */

      /* wait for address type field to arrive */
      if (datalen < 4)
        return 0;

      switch (data[3]) {
        case 0x01: /* ip4 */
          addrlen = 4;
          break;
        case 0x04: /* ip6 */
          addrlen = 16;
          break;
        case 0x03: /* fqdn (can this happen here?) */
          if (datalen < 5)
            return 0;
          addrlen = 1 + data[4];
          break;
        default:
          *reason = tor_strdup("invalid response to connect request");
          return -1;
      }

      /* wait for address and port */
      if (datalen < 6 + addrlen)
        return 0;

      if (data[1] != 0x00) {
        *reason = tor_strdup(socks5_response_code_to_string(data[1]));
        return -1;
      }

      *drain_out = 6 + addrlen;
      return 1;
  }

  /* LCOV_EXCL_START */
  /* shouldn't get here if the input state is one we know about... */
  tor_assert(0);

  return -1;
  /* LCOV_EXCL_STOP */
}

