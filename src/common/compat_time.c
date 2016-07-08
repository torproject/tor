/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file compat_time.c
 * \brief Portable wrappers for finding out the current time, running
 *   timers, etc.
 **/

#define COMPAT_PRIVATE
#include "compat.h"

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef TOR_UNIT_TESTS
#if !defined(HAVE_USLEEP) && defined(HAVE_SYS_SELECT_H)
/* as fallback implementation for tor_sleep_msec */
#include <sys/select.h>
#endif
#endif

#include "torlog.h"
#include "util.h"
#include "container.h"

#ifndef HAVE_GETTIMEOFDAY
#ifdef HAVE_FTIME
#include <sys/timeb.h>
#endif
#endif

#ifdef TOR_UNIT_TESTS
/** Delay for <b>msec</b> milliseconds.  Only used in tests. */
void
tor_sleep_msec(int msec)
{
#ifdef _WIN32
  Sleep(msec);
#elif defined(HAVE_USLEEP)
  sleep(msec / 1000);
  /* Some usleep()s hate sleeping more than 1 sec */
  usleep((msec % 1000) * 1000);
#elif defined(HAVE_SYS_SELECT_H)
  struct timeval tv = { msec / 1000, (msec % 1000) * 1000};
  select(0, NULL, NULL, NULL, &tv);
#else
  sleep(CEIL_DIV(msec, 1000));
#endif
}
#endif

/** Set *timeval to the current time of day.  On error, log and terminate.
 * (Same as gettimeofday(timeval,NULL), but never returns -1.)
 */
void
tor_gettimeofday(struct timeval *timeval)
{
#ifdef _WIN32
  /* Epoch bias copied from perl: number of units between windows epoch and
   * Unix epoch. */
#define EPOCH_BIAS U64_LITERAL(116444736000000000)
#define UNITS_PER_SEC U64_LITERAL(10000000)
#define USEC_PER_SEC U64_LITERAL(1000000)
#define UNITS_PER_USEC U64_LITERAL(10)
  union {
    uint64_t ft_64;
    FILETIME ft_ft;
  } ft;
  /* number of 100-nsec units since Jan 1, 1601 */
  GetSystemTimeAsFileTime(&ft.ft_ft);
  if (ft.ft_64 < EPOCH_BIAS) {
    /* LCOV_EXCL_START */
    log_err(LD_GENERAL,"System time is before 1970; failing.");
    exit(1);
    /* LCOV_EXCL_STOP */
  }
  ft.ft_64 -= EPOCH_BIAS;
  timeval->tv_sec = (unsigned) (ft.ft_64 / UNITS_PER_SEC);
  timeval->tv_usec = (unsigned) ((ft.ft_64 / UNITS_PER_USEC) % USEC_PER_SEC);
#elif defined(HAVE_GETTIMEOFDAY)
  if (gettimeofday(timeval, NULL)) {
    /* LCOV_EXCL_START */
    log_err(LD_GENERAL,"gettimeofday failed.");
    /* If gettimeofday dies, we have either given a bad timezone (we didn't),
       or segfaulted.*/
    exit(1);
    /* LCOV_EXCL_STOP */
  }
#elif defined(HAVE_FTIME)
  struct timeb tb;
  ftime(&tb);
  timeval->tv_sec = tb.time;
  timeval->tv_usec = tb.millitm * 1000;
#else
#error "No way to get time."
#endif
  return;
}

