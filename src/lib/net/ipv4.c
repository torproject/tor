/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file ipv4.c
 * \brief Functions for encoding and decoding IPv4 addresses into strings
 **/

#include "orconfig.h"
#include "lib/cc/torint.h"
#include "lib/net/ipv4.h"
#include "lib/string/printf.h"
#include "lib/string/scanf.h"

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef _WIN32
#include <winsock2.h>
#endif

/** Set *addr to the IP address (in dotted-quad notation) stored in *str.
 * Return 1 on success, 0 if *str is badly formatted.
 * (Like inet_aton(str,addr), but works on Windows and Solaris.)
 */
int
tor_inet_aton(const char *str, struct in_addr* addr)
{
  unsigned a,b,c,d;
  char more;
  if (tor_sscanf(str, "%3u.%3u.%3u.%3u%c", &a,&b,&c,&d,&more) != 4)
    return 0;
  if (a > 255) return 0;
  if (b > 255) return 0;
  if (c > 255) return 0;
  if (d > 255) return 0;
  addr->s_addr = htonl((a<<24) | (b<<16) | (c<<8) | d);
  return 1;
}

/** Given an IPv4 in_addr struct *<b>in</b> (in network order, as usual),
 *  write it as a string into the <b>buf_len</b>-byte buffer in
 *  <b>buf</b>. Returns a non-negative integer on success.
 *  Returns -1 on failure.
 */
int
tor_inet_ntoa(const struct in_addr *in, char *buf, size_t buf_len)
{
  uint32_t a = ntohl(in->s_addr);
  return tor_snprintf(buf, buf_len, "%d.%d.%d.%d",
                      (int)(uint8_t)((a>>24)&0xff),
                      (int)(uint8_t)((a>>16)&0xff),
                      (int)(uint8_t)((a>>8 )&0xff),
                      (int)(uint8_t)((a    )&0xff));
}
