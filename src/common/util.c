/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file util.c
 * \brief Common functions for strings, IO, network, data structures,
 * process control.
 **/

#include "orconfig.h"
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#define UTIL_PRIVATE
#include "common/util.h"
#include "lib/log/torlog.h"
#include "lib/crypt_ops/crypto_digest.h"
#include "lib/cc/torint.h"
#include "lib/container/smartlist.h"
#include "lib/fdio/fdio.h"
#include "lib/net/address.h"
#include "lib/sandbox/sandbox.h"
#include "lib/err/backtrace.h"
#include "lib/process/waitpid.h"
#include "lib/encoding/binascii.h"

#ifdef _WIN32
#include <io.h>
#include <direct.h>
#include <process.h>
#include <tchar.h>
#include <winbase.h>
#else /* !(defined(_WIN32)) */
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#endif /* defined(_WIN32) */

/* math.h needs this on Linux */
#ifndef _USE_ISOC99_
#define _USE_ISOC99_ 1
#endif
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_FCNTL_H
#include <sys/fcntl.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_MALLOC_MALLOC_H
#include <malloc/malloc.h>
#endif
#ifdef HAVE_MALLOC_H
#if !defined(OpenBSD) && !defined(__FreeBSD__)
/* OpenBSD has a malloc.h, but for our purposes, it only exists in order to
 * scold us for being so stupid as to autodetect its presence.  To be fair,
 * they've done this since 1996, when autoconf was only 5 years old. */
#include <malloc.h>
#endif /* !defined(OpenBSD) && !defined(__FreeBSD__) */
#endif /* defined(HAVE_MALLOC_H) */
#ifdef HAVE_MALLOC_NP_H
#include <malloc_np.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#if defined(HAVE_SYS_PRCTL_H) && defined(__linux__)
#include <sys/prctl.h>
#endif

/* =====
 * Memory management
 * ===== */

DISABLE_GCC_WARNING(aggregate-return)
/** Call the platform malloc info function, and dump the results to the log at
 * level <b>severity</b>.  If no such function exists, do nothing. */
void
tor_log_mallinfo(int severity)
{
#ifdef HAVE_MALLINFO
  struct mallinfo mi;
  memset(&mi, 0, sizeof(mi));
  mi = mallinfo();
  tor_log(severity, LD_MM,
      "mallinfo() said: arena=%d, ordblks=%d, smblks=%d, hblks=%d, "
      "hblkhd=%d, usmblks=%d, fsmblks=%d, uordblks=%d, fordblks=%d, "
      "keepcost=%d",
      mi.arena, mi.ordblks, mi.smblks, mi.hblks,
      mi.hblkhd, mi.usmblks, mi.fsmblks, mi.uordblks, mi.fordblks,
      mi.keepcost);
#else /* !(defined(HAVE_MALLINFO)) */
  (void)severity;
#endif /* defined(HAVE_MALLINFO) */
}
ENABLE_GCC_WARNING(aggregate-return)

/* =====
 * Math
 * ===== */

/* =====
 * String manipulation
 * ===== */

/* =====
 * Time
 * ===== */

#define TOR_USEC_PER_SEC 1000000

/** Return the difference between start->tv_sec and end->tv_sec.
 * Returns INT64_MAX on overflow and underflow.
 */
static int64_t
tv_secdiff_impl(const struct timeval *start, const struct timeval *end)
{
  const int64_t s = (int64_t)start->tv_sec;
  const int64_t e = (int64_t)end->tv_sec;

  /* This may not be the most efficient way of implemeting this check,
   * but it's easy to see that it's correct and doesn't overflow */

  if (s > 0 && e < INT64_MIN + s) {
    /* s is positive: equivalent to e - s < INT64_MIN, but without any
     * overflow */
    return INT64_MAX;
  } else if (s < 0 && e > INT64_MAX + s) {
    /* s is negative: equivalent to e - s > INT64_MAX, but without any
     * overflow */
    return INT64_MAX;
  }

  return e - s;
}

/** Return the number of microseconds elapsed between *start and *end.
 * Returns LONG_MAX on overflow and underflow.
 */
long
tv_udiff(const struct timeval *start, const struct timeval *end)
{
  /* Sanity check tv_usec */
  if (start->tv_usec > TOR_USEC_PER_SEC || start->tv_usec < 0) {
    log_warn(LD_GENERAL, "comparing times on microsecond detail with bad "
             "start tv_usec: " I64_FORMAT " microseconds",
             I64_PRINTF_ARG(start->tv_usec));
    return LONG_MAX;
  }

  if (end->tv_usec > TOR_USEC_PER_SEC || end->tv_usec < 0) {
    log_warn(LD_GENERAL, "comparing times on microsecond detail with bad "
             "end tv_usec: " I64_FORMAT " microseconds",
             I64_PRINTF_ARG(end->tv_usec));
    return LONG_MAX;
  }

  /* Some BSDs have struct timeval.tv_sec 64-bit, but time_t (and long) 32-bit
   */
  int64_t udiff;
  const int64_t secdiff = tv_secdiff_impl(start, end);

  /* end->tv_usec - start->tv_usec can be up to 1 second either way */
  if (secdiff > (int64_t)(LONG_MAX/1000000 - 1) ||
      secdiff < (int64_t)(LONG_MIN/1000000 + 1)) {
    log_warn(LD_GENERAL, "comparing times on microsecond detail too far "
             "apart: " I64_FORMAT " seconds", I64_PRINTF_ARG(secdiff));
    return LONG_MAX;
  }

  /* we'll never get an overflow here, because we check that both usecs are
   * between 0 and TV_USEC_PER_SEC. */
  udiff = secdiff*1000000 + ((int64_t)end->tv_usec - (int64_t)start->tv_usec);

  /* Some compilers are smart enough to work out this is a no-op on L64 */
#if SIZEOF_LONG < 8
  if (udiff > (int64_t)LONG_MAX || udiff < (int64_t)LONG_MIN) {
    return LONG_MAX;
  }
#endif

  return (long)udiff;
}

/** Return the number of milliseconds elapsed between *start and *end.
 * If the tv_usec difference is 500, rounds away from zero.
 * Returns LONG_MAX on overflow and underflow.
 */
long
tv_mdiff(const struct timeval *start, const struct timeval *end)
{
  /* Sanity check tv_usec */
  if (start->tv_usec > TOR_USEC_PER_SEC || start->tv_usec < 0) {
    log_warn(LD_GENERAL, "comparing times on millisecond detail with bad "
             "start tv_usec: " I64_FORMAT " microseconds",
             I64_PRINTF_ARG(start->tv_usec));
    return LONG_MAX;
  }

  if (end->tv_usec > TOR_USEC_PER_SEC || end->tv_usec < 0) {
    log_warn(LD_GENERAL, "comparing times on millisecond detail with bad "
             "end tv_usec: " I64_FORMAT " microseconds",
             I64_PRINTF_ARG(end->tv_usec));
    return LONG_MAX;
  }

  /* Some BSDs have struct timeval.tv_sec 64-bit, but time_t (and long) 32-bit
   */
  int64_t mdiff;
  const int64_t secdiff = tv_secdiff_impl(start, end);

  /* end->tv_usec - start->tv_usec can be up to 1 second either way, but the
   * mdiff calculation may add another temporary second for rounding.
   * Whether this actually causes overflow depends on the compiler's constant
   * folding and order of operations. */
  if (secdiff > (int64_t)(LONG_MAX/1000 - 2) ||
      secdiff < (int64_t)(LONG_MIN/1000 + 1)) {
    log_warn(LD_GENERAL, "comparing times on millisecond detail too far "
             "apart: " I64_FORMAT " seconds", I64_PRINTF_ARG(secdiff));
    return LONG_MAX;
  }

  /* Subtract and round */
  mdiff = secdiff*1000 +
      /* We add a million usec here to ensure that the result is positive,
       * so that the round-towards-zero behavior of the division will give
       * the right result for rounding to the nearest msec. Later we subtract
       * 1000 in order to get the correct result.
       * We'll never get an overflow here, because we check that both usecs are
       * between 0 and TV_USEC_PER_SEC. */
      ((int64_t)end->tv_usec - (int64_t)start->tv_usec + 500 + 1000000) / 1000
      - 1000;

  /* Some compilers are smart enough to work out this is a no-op on L64 */
#if SIZEOF_LONG < 8
  if (mdiff > (int64_t)LONG_MAX || mdiff < (int64_t)LONG_MIN) {
    return LONG_MAX;
  }
#endif

  return (long)mdiff;
}

/**
 * Converts timeval to milliseconds.
 */
int64_t
tv_to_msec(const struct timeval *tv)
{
  int64_t conv = ((int64_t)tv->tv_sec)*1000L;
  /* Round ghetto-style */
  conv += ((int64_t)tv->tv_usec+500)/1000L;
  return conv;
}

#ifdef _WIN32
HANDLE
load_windows_system_library(const TCHAR *library_name)
{
  TCHAR path[MAX_PATH];
  unsigned n;
  n = GetSystemDirectory(path, MAX_PATH);
  if (n == 0 || n + _tcslen(library_name) + 2 >= MAX_PATH)
    return 0;
  _tcscat(path, TEXT("\\"));
  _tcscat(path, library_name);
  return LoadLibrary(path);
}
#endif /* defined(_WIN32) */
