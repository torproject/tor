/* Copyright 2003 Roger Dingledine */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef __UTIL_H
#define __UTIL_H

#include <sys/time.h>

void *tor_malloc(size_t size);

/* Same as gettimeofday, but no need to check exit value. */
void my_gettimeofday(struct timeval *timeval);
/* Returns the number of microseconds between start and end.  Requires that
 * end >= start, and that the number of microseconds < LONG_MAX. */
long tv_udiff(struct timeval *start, struct timeval *end);

void tv_addms(struct timeval *a, long ms);
void tv_add(struct timeval *a, struct timeval *b);
int tv_cmp(struct timeval *a, struct timeval *b);

#endif
