/* Copyright 2003 Roger Dingledine */
/* See LICENSE for licensing information */
/* $Id$ */

#include <stdlib.h>
#include <limits.h>
#include "util.h"
#include "log.h"

void 
my_gettimeofday(struct timeval *timeval) 
{
  if (gettimeofday(timeval, NULL)) {
    log(LOG_ERR, "my_gettimeofday: gettimeofday failed.");
    /* If gettimeofday dies, we have either given a bad timezone (we didn't),
       or segfaulted.*/
    exit(1);
  }
  return;
}

long
tv_udiff(struct timeval *start, struct timeval *end)
{
  long udiff;
  long end_usec = end->tv_usec;
  long secdiff = end->tv_sec - start->tv_sec;

  if (secdiff+1 > LONG_MAX/1000000) {
    log(LOG_NOTICE, "tv_udiff(): comparing times too far apart.");
    return LONG_MAX;
  }
  if (end_usec < start->tv_usec) {
    secdiff--;
    end_usec += 1000000L;
  }
  udiff = secdiff*1000000L + (end_usec - start->tv_usec);
  if(udiff < 0) {
    log(LOG_NOTICE, "tv_udiff(): start is after end. Returning 0.");
    return 0;
  }
  return udiff;
}

int tv_cmp(struct timeval *a, struct timeval *b) {
  if (a->tv_sec > b->tv_sec)
    return 1;
  if (a->tv_sec < b->tv_sec)
    return -1;
  if (a->tv_usec > b->tv_usec)
    return 1;
  if (a->tv_usec < b->tv_usec)
    return -1;
  return 0;
}

void tv_add(struct timeval *a, struct timeval *b) {
  a->tv_usec += b->tv_usec;
  a->tv_sec += b->tv_sec + (a->tv_usec / 1000000);
  a->tv_usec %= 1000000;
}

void tv_addms(struct timeval *a, long ms) {
  a->tv_usec += (ms * 1000) % 1000000;
  a->tv_sec += ((ms * 1000) / 1000000) + (a->tv_usec / 1000000);
  a->tv_usec %= 1000000;
}
