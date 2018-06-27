/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_IPV4_H
#define TOR_IPV4_H

#include <stddef.h>

struct in_addr;
int tor_inet_aton(const char *str, struct in_addr *addr);
/** Length of a buffer to allocate to hold the results of tor_inet_ntoa.*/
#define INET_NTOA_BUF_LEN 16
int tor_inet_ntoa(const struct in_addr *in, char *buf, size_t buf_len);

#endif
