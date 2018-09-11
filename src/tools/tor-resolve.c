/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson
 * Copyright (c) 2007-2018, The Tor Project, Inc.
 */
/* See LICENSE for licensing information */

#include "orconfig.h"

#include "lib/arch/bytes.h"
#include "lib/log/log.h"
#include "lib/malloc/malloc.h"
#include "lib/net/address.h"
#include "lib/net/resolve.h"
#include "lib/net/socket.h"
#include "lib/sandbox/sandbox.h"
#include "lib/string/util_string.h"

#include "lib/net/socks5_status.h"
#include "socks5.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

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

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#define RESPONSE_LEN_4 8
#define log_sock_error(act, _s)                                         \
  STMT_BEGIN log_fn(LOG_ERR, LD_NET, "Error while %s: %s", act,         \
              tor_socket_strerror(tor_socket_errno(_s))); STMT_END

static void usage(void) ATTR_NORETURN;

/**
 * Set <b>out</b> to a pointer to newly allocated buffer containing
 * SOCKS4a RESOLVE request with <b>username</b> and <b>hostname</b>.
 * Return number of bytes in the buffer if succeeded or -1 if failed.
 */
static ssize_t
build_socks4a_resolve_request(uint8_t **out,
                              const char *username,
                              const char *hostname)
{
  tor_assert(out);
  tor_assert(username);
  tor_assert(hostname);

  const char *errmsg = NULL;
  uint8_t *output = NULL;
  socks4_client_request_t *rq = socks4_client_request_new();

  socks4_client_request_set_version(rq, 4);
  socks4_client_request_set_command(rq, CMD_RESOLVE);
  socks4_client_request_set_port(rq, 0);
  socks4_client_request_set_addr(rq, 0x00000001u);
  socks4_client_request_set_username(rq, username);
  socks4_client_request_set_socks4a_addr_hostname(rq, hostname);

  errmsg = socks4_client_request_check(rq);
  if (errmsg) {
    goto cleanup;
  }

  ssize_t encoded_len = socks4_client_request_encoded_len(rq);
  if (encoded_len <= 0) {
    errmsg = "socks4_client_request_encoded_len failed";
    goto cleanup;
  }

  output = tor_malloc(encoded_len);
  memset(output, 0, encoded_len);

  encoded_len = socks4_client_request_encode(output, encoded_len, rq);
  if (encoded_len <= 0) {
    errmsg = "socks4_client_request_encode failed";
    goto cleanup;
  }

  *out = output;

 cleanup:
  socks4_client_request_free(rq);
  if (errmsg) {
    log_err(LD_NET, "build_socks4a_resolve_request failed: %s", errmsg);
    *out = NULL;
    tor_free(output);
  }
  return errmsg ? -1 : encoded_len;
}

/** Set *<b>out</b> to a newly allocated SOCKS4a resolve request with
 * <b>username</b> and <b>hostname</b> as provided.  Return the number
 * of bytes in the request. */
static ssize_t
build_socks_resolve_request(uint8_t **out,
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
    return build_socks4a_resolve_request(out, username, hostname);
  } else if (version == 5) {
    int is_ip_address;
    tor_addr_t addr;
    size_t addrlen;
    int ipv6;
    is_ip_address = tor_addr_parse(&addr, hostname) != -1;
    if (!is_ip_address && reverse) {
      log_err(LD_GENERAL, "Tried to do a reverse lookup on a non-IP!");
      return -1;
    }
    ipv6 = reverse && tor_addr_family(&addr) == AF_INET6;
    addrlen = reverse ? (ipv6 ? 16 : 4) : 1 + strlen(hostname);
    if (addrlen > UINT8_MAX) {
      log_err(LD_GENERAL, "Hostname is too long!");
      return -1;
    }
    len = 6 + addrlen;
    *out = tor_malloc(len);
    (*out)[0] = 5; /* SOCKS version 5 */
    (*out)[1] = reverse ? '\xF1' : '\xF0'; /* RESOLVE_PTR or RESOLVE */
    (*out)[2] = 0; /* reserved. */
    if (reverse) {
      (*out)[3] = ipv6 ? 4 : 1;
      if (ipv6)
        memcpy((*out)+4, tor_addr_to_in6_addr8(&addr), 16);
      else
        set_uint32((*out)+4, tor_addr_to_ipv4n(&addr));
    } else {
      (*out)[3] = 3;
      (*out)[4] = (char)(uint8_t)(addrlen - 1);
      memcpy((*out)+5, hostname, addrlen - 1);
    }
    set_uint16((*out)+4+addrlen, 0); /* port */
  } else {
    tor_assert(0);
  }

  return len;
}

static void
onion_warning(const char *hostname)
{
  log_warn(LD_NET,
        "%s is a hidden service; those don't have IP addresses. "
        "You can use the AutomapHostsOnResolve option to have Tor return a "
        "fake address for hidden services.  Or you can have your "
        "application send the address to Tor directly; we recommend an "
        "application that uses SOCKS 5 with hostnames.",
           hostname);
}

/** Given a <b>len</b>-byte SOCKS4a response in <b>response</b>, set
 * *<b>addr_out</b> to the address it contains (in host order).
 * Return 0 on success, -1 on error.
 */
static int
parse_socks4a_resolve_response(const char *hostname,
                               const char *response, size_t len,
                               tor_addr_t *addr_out)
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
    if (!strcasecmpend(hostname, ".onion")) {
      onion_warning(hostname);
      return -1;
    }
    return -1;
  }

  tor_addr_from_ipv4n(addr_out, get_uint32(response+4));
  return 0;
}

/* It would be nice to let someone know what SOCKS5 issue a user may have */
static const char *
socks5_reason_to_string(char reason)
{
  switch (reason) {
    case SOCKS5_SUCCEEDED:
      return "succeeded";
    case SOCKS5_GENERAL_ERROR:
      return "general error";
    case SOCKS5_NOT_ALLOWED:
      return "not allowed";
    case SOCKS5_NET_UNREACHABLE:
      return "network is unreachable";
    case SOCKS5_HOST_UNREACHABLE:
      return "host is unreachable";
    case SOCKS5_CONNECTION_REFUSED:
      return "connection refused";
    case SOCKS5_TTL_EXPIRED:
      return "ttl expired";
    case SOCKS5_COMMAND_NOT_SUPPORTED:
      return "command not supported";
    case SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED:
      return "address type not supported";
    default:
      return "unknown SOCKS5 code";
  }
}

/** Send a resolve request for <b>hostname</b> to the Tor listening on
 * <b>sockshost</b>:<b>socksport</b>.  Store the resulting IPv4
 * address (in host order) into *<b>result_addr</b>.
 */
static int
do_resolve(const char *hostname,
           const tor_addr_t *sockshost, uint16_t socksport,
           int reverse, int version,
           tor_addr_t *result_addr, char **result_hostname)
{
  int s = -1;
  struct sockaddr_storage ss;
  socklen_t socklen;
  uint8_t *req = NULL;
  ssize_t len = 0;

  tor_assert(hostname);
  tor_assert(result_addr);
  tor_assert(version == 4 || version == 5);

  tor_addr_make_unspec(result_addr);
  *result_hostname = NULL;

  s = tor_open_socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
  if (s<0) {
    log_sock_error("creating_socket", -1);
    return -1;
  }

  socklen = tor_addr_to_sockaddr(sockshost, socksport,
                                 (struct sockaddr *)&ss, sizeof(ss));

  if (connect(s, (struct sockaddr*)&ss, socklen)) {
    log_sock_error("connecting to SOCKS host", s);
    goto err;
  }

  if (version == 5) {
    char method_buf[2];
    if (write_all_to_socket(s, (const char *)"\x05\x01\x00", 3) != 3) {
      log_err(LD_NET, "Error sending SOCKS5 method list.");
      goto err;
    }
    if (read_all_from_socket(s, method_buf, 2) != 2) {
      log_err(LD_NET, "Error reading SOCKS5 methods.");
      goto err;
    }
    if (method_buf[0] != '\x05') {
      log_err(LD_NET, "Unrecognized socks version: %u",
              (unsigned)method_buf[0]);
      goto err;
    }
    if (method_buf[1] != '\x00') {
      log_err(LD_NET, "Unrecognized socks authentication method: %u",
              (unsigned)method_buf[1]);
      goto err;
    }
  }

  if ((len = build_socks_resolve_request(&req, "", hostname, reverse,
                                         version))<0) {
    log_err(LD_BUG,"Error generating SOCKS request");
    tor_assert(!req);
    goto err;
  }
  if (write_all_to_socket(s, (const char *)req, len) != len) {
    log_sock_error("sending SOCKS request", s);
    tor_free(req);
    goto err;
  }
  tor_free(req);

  if (version == 4) {
    char reply_buf[RESPONSE_LEN_4];
    if (read_all_from_socket(s, reply_buf, RESPONSE_LEN_4) != RESPONSE_LEN_4) {
      log_err(LD_NET, "Error reading SOCKS4 response.");
      goto err;
    }
    if (parse_socks4a_resolve_response(hostname,
                                       reply_buf, RESPONSE_LEN_4,
                                       result_addr)<0) {
      goto err;
    }
  } else {
    char reply_buf[16];
    if (read_all_from_socket(s, reply_buf, 4) != 4) {
      log_err(LD_NET, "Error reading SOCKS5 response.");
      goto err;
    }
    if (reply_buf[0] != 5) {
      log_err(LD_NET, "Bad SOCKS5 reply version.");
      goto err;
    }
    /* Give a user some useful feedback about SOCKS5 errors */
    if (reply_buf[1] != 0) {
      log_warn(LD_NET,"Got SOCKS5 status response '%u': %s",
               (unsigned)reply_buf[1],
               socks5_reason_to_string(reply_buf[1]));
      if (reply_buf[1] == 4 && !strcasecmpend(hostname, ".onion")) {
        onion_warning(hostname);
      }
      goto err;
    }
    if (reply_buf[3] == 1) {
      /* IPv4 address */
      if (read_all_from_socket(s, reply_buf, 4) != 4) {
        log_err(LD_NET, "Error reading address in socks5 response.");
        goto err;
      }
      tor_addr_from_ipv4n(result_addr, get_uint32(reply_buf));
    } else if (reply_buf[3] == 4) {
      /* IPv6 address */
      if (read_all_from_socket(s, reply_buf, 16) != 16) {
        log_err(LD_NET, "Error reading address in socks5 response.");
        goto err;
      }
      tor_addr_from_ipv6_bytes(result_addr, reply_buf);
    } else if (reply_buf[3] == 3) {
      /* Domain name */
      size_t result_len;
      if (read_all_from_socket(s, reply_buf, 1) != 1) {
        log_err(LD_NET, "Error reading address_length in socks5 response.");
        goto err;
      }
      result_len = *(uint8_t*)(reply_buf);
      *result_hostname = tor_malloc(result_len+1);
      if (read_all_from_socket(s, *result_hostname, result_len)
          != (int) result_len) {
        log_err(LD_NET, "Error reading hostname in socks5 response.");
        goto err;
      }
      (*result_hostname)[result_len] = '\0';
    }
  }

  tor_close_socket(s);
  return 0;
 err:
  tor_close_socket(s);
  return -1;
}

/** Print a usage message and exit. */
static void
usage(void)
{
  puts("Syntax: tor-resolve [-4] [-5] [-v] [-x] [-p port] "
       "hostname [sockshost[:socksport]]");
  exit(1);
}

/** Entry point to tor-resolve */
int
main(int argc, char **argv)
{
  tor_addr_t sockshost;
  uint16_t socksport = 0, port_option = 0;
  int isSocks4 = 0, isVerbose = 0, isReverse = 0;
  char **arg;
  int n_args;
  tor_addr_t result;
  char *result_hostname = NULL;

  init_logging(1);
  sandbox_disable_getaddrinfo_cache();

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
    else if (!strcmp("-p", arg[0])) {
      int p;
      if (n_args < 2) {
        fprintf(stderr, "No arguments given to -p\n");
        usage();
      }
      p = atoi(arg[1]);
      if (p<1 || p > 65535) {
        fprintf(stderr, "-p requires a number between 1 and 65535\n");
        usage();
      }
      port_option = (uint16_t) p;
      ++arg; /* skip the port */
      --n_args;
    } else {
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

  log_severity_list_t *severities =
    tor_malloc_zero(sizeof(log_severity_list_t));
  if (isVerbose)
    set_log_severity_config(LOG_DEBUG, LOG_ERR, severities);
  else
    set_log_severity_config(LOG_WARN, LOG_ERR, severities);
  add_stream_log(severities, "<stderr>", fileno(stderr));
  tor_free(severities);

  if (n_args == 1) {
    log_debug(LD_CONFIG, "defaulting to localhost");
    tor_addr_from_ipv4h(&sockshost, 0x7f000001u); /* localhost */
    if (port_option) {
      log_debug(LD_CONFIG, "Using port %d", (int)port_option);
      socksport = port_option;
    } else {
      log_debug(LD_CONFIG, "defaulting to port 9050");
      socksport = 9050; /* 9050 */
    }
  } else if (n_args == 2) {
    if (tor_addr_port_lookup(arg[1], &sockshost, &socksport)<0) {
      fprintf(stderr, "Couldn't parse/resolve address %s", arg[1]);
      return 1;
    }
    if (socksport && port_option && socksport != port_option) {
      log_warn(LD_CONFIG, "Conflicting ports; using %d, not %d",
               (int)socksport, (int)port_option);
    } else if (port_option) {
      socksport = port_option;
    } else if (!socksport) {
      log_debug(LD_CONFIG, "defaulting to port 9050");
      socksport = 9050;
    }
  } else {
    usage();
  }

  if (network_init()<0) {
    log_err(LD_BUG,"Error initializing network; exiting.");
    return 1;
  }

  if (do_resolve(arg[0], &sockshost, socksport, isReverse,
                 isSocks4 ? 4 : 5, &result,
                 &result_hostname))
    return 1;

  if (result_hostname) {
    printf("%s\n", result_hostname);
  } else {
    printf("%s\n", fmt_addr(&result));
  }
  return 0;
}
