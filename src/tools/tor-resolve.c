/* Copyright 2004-2005 Roger Dingledine, Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id$ */

#include "orconfig.h"

#include "../common/compat.h"
#include "../common/util.h"
#include "../common/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h> /* Must be included before sys/stat.h for Ultrix */
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef MS_WINDOWS
#if (_MSC_VER <= 1300)
#include <winsock.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#endif

#define RESPONSE_LEN_4 8
#define log_sock_error(act, _s)                                         \
  do { log_fn(LOG_ERR, LD_NET, "Error while %s: %s", act,              \
              tor_socket_strerror(tor_socket_errno(_s))); } while (0)

/** Set *<b>out</b> to a newly allocated SOCKS4a resolve request with
 * <b>username</b> and <b>hostname</b> as provided.  Return the number
 * of bytes in the request. */
static int
build_socks_resolve_request(char **out,
                            const char *username,
                            const char *hostname,
                            int reverse,
                            int version)
{
  size_t len = 0;
  tor_assert(out);
  tor_assert(username);
  tor_assert(hostname);

  if (version == 4) {
    len = 8 + strlen(username) + 1 + strlen(hostname) + 1;
    *out = tor_malloc(len);
    (*out)[0] = 4;      /* SOCKS version 4 */
    (*out)[1] = '\xF0'; /* Command: resolve. */
    set_uint16((*out)+2, htons(0)); /* port: 0. */
    set_uint32((*out)+4, htonl(0x00000001u)); /* addr: 0.0.0.1 */
    memcpy((*out)+8, username, strlen(username)+1);
    memcpy((*out)+8+strlen(username)+1, hostname, strlen(hostname)+1);
  } else if (version == 5) {
    int is_ip_address;
    struct in_addr in;
    size_t addrlen;
    is_ip_address = tor_inet_aton(hostname, &in);
    if (!is_ip_address && reverse) {
      log_err(LD_GENERAL, "Tried to do a reverse lookup on a non-IP!");
      return -1;
    }
    addrlen = is_ip_address ? 4 : 1 + strlen(hostname);
    len = 6 + addrlen;
    *out = tor_malloc(len);
    (*out)[0] = 5; /* SOCKS version 5 */
    (*out)[1] = reverse ? '\xF1' : '\xF0'; /* RESOLVE_PTR or RESOLVE */
    (*out)[2] = 0; /* reserved. */
    (*out)[3] = is_ip_address ? 1 : 3;
    if (is_ip_address) {
      set_uint32((*out)+4, in.s_addr);
    } else {
      (*out)[4] = (char)(uint8_t)(addrlen - 1);
      memcpy((*out)+5, hostname, addrlen - 1);
    }
    set_uint16((*out)+4+addrlen, 0); /* port */
  } else {
    tor_assert(0);
  }

  return len;
}

/** Given a <b>len</b>-byte SOCKS4a response in <b>response</b>, set
 * *<b>addr_out</b> to the address it contains (in host order).
 * Return 0 on success, -1 on error.
 */
static int
parse_socks4a_resolve_response(const char *response, size_t len,
                               uint32_t *addr_out)
{
  uint8_t status;
  tor_assert(response);
  tor_assert(addr_out);

  if (len < RESPONSE_LEN_4) {
    log_warn(LD_PROTOCOL,"Truncated socks response.");
    return -1;
  }
  if (((uint8_t)response[0])!=0) { /* version: 0 */
    log_warn(LD_PROTOCOL,"Nonzero version in socks response: bad format.");
    return -1;
  }
  status = (uint8_t)response[1];
  if (get_uint16(response+2)!=0) { /* port: 0 */
    log_warn(LD_PROTOCOL,"Nonzero port in socks response: bad format.");
    return -1;
  }
  if (status != 90) {
    log_warn(LD_NET,"Got status response '%d': socks request failed.", status);
    return -1;
  }

  *addr_out = ntohl(get_uint32(response+4));
  return 0;
}

/** Send a resolve request for <b>hostname</b> to the Tor listening on
 * <b>sockshost</b>:<b>socksport</b>.  Store the resulting IPv4
 * address (in host order) into *<b>result_addr</b>.
 */
static int
do_resolve(const char *hostname, uint32_t sockshost, uint16_t socksport,
           int reverse, int version,
           uint32_t *result_addr, char **result_hostname)
{
  int s;
  struct sockaddr_in socksaddr;
  char *req = NULL;
  int len = 0;

  tor_assert(hostname);
  tor_assert(result_addr);
  tor_assert(version == 4 || version == 5);

  *result_addr = 0;
  *result_hostname = NULL;

  s = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
  if (s<0) {
    log_sock_error("creating_socket", -1);
    return -1;
  }

  memset(&socksaddr, 0, sizeof(socksaddr));
  socksaddr.sin_family = AF_INET;
  socksaddr.sin_port = htons(socksport);
  socksaddr.sin_addr.s_addr = htonl(sockshost);
  if (connect(s, (struct sockaddr*)&socksaddr, sizeof(socksaddr))) {
    log_sock_error("connecting to SOCKS host", s);
    return -1;
  }

  if (version == 5) {
    char method_buf[2];
    if (write_all(s, "\x05\x01\x00", 3, 1) != 3) {
      log_err(LD_NET, "Error sending SOCKS5 method list.");
      return -1;
    }
    if (read_all(s, method_buf, 2, 1) != 2) {
      log_err(LD_NET, "Error reading SOCKS5 methods.");
      return -1;
    }
    if (method_buf[0] != '\x05') {
      log_err(LD_NET, "Unrecognized socks version: %u",
              (unsigned)method_buf[0]);
      return -1;
    }
    if (method_buf[1] != '\x00') {
      log_err(LD_NET, "Unrecognized socks authentication method: %u",
              (unsigned)method_buf[1]);
      return -1;
    }
  }

  if ((len = build_socks_resolve_request(&req, "", hostname, reverse,
                                         version))<0) {
    log_err(LD_BUG,"Error generating SOCKS request");
    return -1;
  }
  if (write_all(s, req, len, 1) != len) {
    log_sock_error("sending SOCKS request", s);
    tor_free(req);
    return -1;
  }
  tor_free(req);

  if (version == 4) {
    char reply_buf[RESPONSE_LEN_4];
    if (read_all(s, reply_buf, RESPONSE_LEN_4, 1) != RESPONSE_LEN_4) {
      log_err(LD_NET, "Error reading SOCKS4 response.");
      return -1;
    }
    if (parse_socks4a_resolve_response(reply_buf, RESPONSE_LEN_4,
                                       result_addr)<0){
      return -1;
    }
  } else {
    char reply_buf[4];
    if (read_all(s, reply_buf, 4, 1) != 4) {
      log_err(LD_NET, "Error reading SOCKS5 response.");
      return -1;
    }
    if (reply_buf[0] != 5) {
      log_err(LD_NET, "Bad SOCKS5 reply version.");
      return -1;
    }
    if (reply_buf[1] != 0) {
      log_warn(LD_NET,"Got status response '%u': SOCKS5 request failed.",
               (unsigned)reply_buf[1]);
      return -1;
    }
    if (reply_buf[3] == 1) {
      /* IPv4 address */
      if (read_all(s, reply_buf, 4, 1) != 4) {
        log_err(LD_NET, "Error reading address in socks5 response.");
        return -1;
      }
      *result_addr = ntohl(get_uint32(reply_buf));
    } else if (reply_buf[3] == 3) {
      size_t len;
      if (read_all(s, reply_buf, 1, 1) != 1) {
        log_err(LD_NET, "Error reading address_length in socks5 response.");
        return -1;
      }
      len = *(uint8_t*)(reply_buf);
      *result_hostname = tor_malloc(len+1);
      if (read_all(s, *result_hostname, len, 1) != (int) len) {
        log_err(LD_NET, "Error reading hostname in socks5 response.");
        return -1;
      }
      (*result_hostname)[len] = '\0';
    }
  }

  return 0;
}

/** Print a usage message and exit. */
static void
usage(void)
{
  puts("Syntax: tor-resolve [-4] [-v] [-x] hostname [sockshost:socksport]");
  exit(1);
}

/** Entry point to tor-resolve */
int
main(int argc, char **argv)
{
  uint32_t sockshost;
  uint16_t socksport;
  int isSocks4 = 0, isVerbose = 0, isReverse = 0;
  char **arg;
  int n_args;
  struct in_addr a;
  uint32_t result = 0;
  char *result_hostname = NULL;
  char buf[INET_NTOA_BUF_LEN];

  arg = &argv[1];
  n_args = argc-1;

  if (!n_args)
    usage();

  if (!strcmp(arg[0],"--version")) {
    printf("Tor version %s.\n",VERSION);
    return 0;
  }
  while (n_args && *arg[0] == '-') {
    if (!strcmp("-v", arg[0]))
      isVerbose = 1;
    else if (!strcmp("-4", arg[0]))
      isSocks4 = 1;
    else if (!strcmp("-5", arg[0]))
      isSocks4 = 0;
    else if (!strcmp("-x", arg[0]))
      isReverse = 1;
    else {
      fprintf(stderr, "Unrecognized flag '%s'\n", arg[0]);
      usage();
    }
    ++arg;
    --n_args;
  }

  if (isSocks4 && isReverse) {
    fprintf(stderr, "Reverse lookups not supported with SOCKS4a\n");
    usage();
  }

  if (isVerbose) {
    add_stream_log(LOG_DEBUG, LOG_ERR, "<stderr>", stderr);
  } else {
    add_stream_log(LOG_WARN, LOG_ERR, "<stderr>", stderr);
  }
  if (n_args == 1) {
    log_debug(LD_CONFIG, "defaulting to localhost:9050");
    sockshost = 0x7f000001u; /* localhost */
    socksport = 9050; /* 9050 */
  } else if (n_args == 2) {
    if (parse_addr_port(LOG_WARN, arg[1], NULL, &sockshost, &socksport)<0) {
      fprintf(stderr, "Couldn't parse/resolve address %s", arg[1]);
      return 1;
    }
    if (socksport == 0) {
      log_debug(LD_CONFIG, "defaulting to port 9050");
      socksport = 9050;
    }
  } else {
    usage();
  }

  if (!strcasecmpend(arg[0], ".onion")) {
    fprintf(stderr,
       "%s is a hidden service; those don't have IP addresses.\n\n"
       "To connect to a hidden service, you need to send the hostname\n"
       "to Tor; we suggest an application that uses SOCKS 4a.\n", arg[0]);
    return 1;
  }

  if (network_init()<0) {
    log_err(LD_BUG,"Error initializing network; exiting.");
    return 1;
  }

  if (do_resolve(arg[0], sockshost, socksport, isReverse,
                 isSocks4 ? 4 : 5, &result,
                 &result_hostname))
    return 1;

  if (result_hostname) {
    printf("%s\n", result_hostname);
  } else {
    a.s_addr = htonl(result);
    tor_inet_ntoa(&a, buf, sizeof(buf));
    printf("%s\n", buf);
  }
  return 0;
}

