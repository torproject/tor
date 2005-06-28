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

#define RESPONSE_LEN 8
#define log_sock_error(act, _s)                             \
  do { log_fn(LOG_ERR, "Error while %s: %s", act,           \
              tor_socket_strerror(tor_socket_errno(_s))); } while (0)

/** Set *<b>out</b> to a newly allocated SOCKS4a resolve request with
 * <b>username</b> and <b>hostname</b> as provided.  Return the number
 * of bytes in the request. */
static int
build_socks4a_resolve_request(char **out,
                              const char *username,
                              const char *hostname)
{
  size_t len;
  tor_assert(out);
  tor_assert(username);
  tor_assert(hostname);

  len = 8 + strlen(username) + 1 + strlen(hostname) + 1;
  *out = tor_malloc(len);
  (*out)[0] = 4;      /* SOCKS version 4 */
  (*out)[1] = '\xF0'; /* Command: resolve. */
  set_uint16((*out)+2, htons(0)); /* port: 0. */
  set_uint32((*out)+4, htonl(0x00000001u)); /* addr: 0.0.0.1 */
  strcpy((*out)+8, username);
  strcpy((*out)+8+strlen(username)+1, hostname);

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

  if (len < RESPONSE_LEN) {
    log_fn(LOG_WARN,"Truncated socks response.");
    return -1;
  }
  if (((uint8_t)response[0])!=0) { /* version: 0 */
    log_fn(LOG_WARN,"Nonzero version in socks response: bad format.");
    return -1;
  }
  status = (uint8_t)response[1];
  if (get_uint16(response+2)!=0) { /* port: 0 */
    log_fn(LOG_WARN,"Nonzero port in socks response: bad format.");
    return -1;
  }
  if (status != 90) {
    log_fn(LOG_WARN,"Got status response '%d': socks request failed.", status);
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
           uint32_t *result_addr)
{
  int s;
  struct sockaddr_in socksaddr;
  char *req, *cp;
  int r, len;
  char response_buf[RESPONSE_LEN];

  tor_assert(hostname);
  tor_assert(result_addr);

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

  if ((len = build_socks4a_resolve_request(&req, "", hostname))<0) {
    log_fn(LOG_ERR, "Error generating SOCKS request");
    return -1;
  }

  cp = req;
  while (len) {
    r = send(s, cp, len, 0);
    if (r<0) {
      log_sock_error("sending SOCKS request", s);
      tor_free(req);
      return -1;
    }
    len -= r;
    cp += r;
  }
  tor_free(req);

  len = 0;
  while (len < RESPONSE_LEN) {
    r = recv(s, response_buf+len, RESPONSE_LEN-len, 0);
    if (r==0) {
      log_fn(LOG_WARN,"EOF while reading SOCKS response");
      return -1;
    }
    if (r<0) {
      log_sock_error("reading SOCKS response", s);
      return -1;
    }
    len += r;
  }

  if (parse_socks4a_resolve_response(response_buf, RESPONSE_LEN,result_addr)<0){
    return -1;
  }

  return 0;
}

/** Print a usage message and exit. */
static void
usage(void)
{
  puts("Syntax: tor-resolve [-v] hostname [sockshost:socksport]");
  exit(1);
}

/** Entry point to tor-resolve */
int
main(int argc, char **argv)
{
  uint32_t sockshost;
  uint16_t socksport;
  char **arg;
  int n_args;
  struct in_addr a;
  uint32_t result;
  char buf[INET_NTOA_BUF_LEN];

  arg = &argv[1];
  n_args = argc-1;

  if (!n_args)
    usage();

  if (!strcmp(arg[0],"--version")) {
    printf("Tor version %s.\n",VERSION);
    return 0;
  }

  if (!strcmp("-v", arg[0])) {
    add_stream_log(LOG_DEBUG, LOG_ERR, "<stderr>", stderr);
    ++arg; --n_args;
  } else {
    add_stream_log(LOG_WARN, LOG_ERR, "<stderr>", stderr);
  }
  if (n_args == 1) {
    log_fn(LOG_DEBUG, "defaulting to localhost:9050");
    sockshost = 0x7f000001u; /* localhost */
    socksport = 9050; /* 9050 */
  } else if (n_args == 2) {
    if (parse_addr_port(arg[1], NULL, &sockshost, &socksport)<0) {
      fprintf(stderr, "Couldn't parse/resolve address %s", arg[1]);
      return 1;
    }
    if (socksport == 0) {
      log_fn(LOG_DEBUG, "defaulting to port 9050");
      socksport = 9050;
    }
  } else {
    usage();
  }

  if (!strcasecmpend(arg[0], ".onion")) {
    fprintf(stderr, "%s is a hidden service; those don't have IP addresses.\n\n"
       "To connect to a hidden service, you need to send the hostname to Tor;\n"
       "we suggest SOCKS 4a.\n", arg[0]);
    return 1;
  }

  if (network_init()<0) {
    log_fn(LOG_ERR,"Error initializing network; exiting.");
    return 1;
  }

  if (do_resolve(arg[0], sockshost, socksport, &result))
    return 1;

  a.s_addr = htonl(result);
  tor_inet_ntoa(&a, buf, sizeof(buf));
  printf("%s\n", buf);
  return 0;
}

