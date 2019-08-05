/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file raw_log.c
 * @brief This file contains common raw file descriptor logging code used by
 *        torerr.c and control_trace.c. See those files for details.
 **/

#include "orconfig.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include "lib/err/raw_log.h"

/** Log granularity in milliseconds. */
static int log_granularity = 1000;

/** Write <b>s</b> to each of the <b>n_raw_log_fds</b> elements of
 * <b>raw_log_fds</b>.
 * Return 0 on success, -1 on failure. */
int
tor_log_raw_write(int *raw_log_fds, int n_raw_log_fds, const char *s)
{
  int i;
  ssize_t r;
  size_t len = strlen(s);
  int err = 0;
  for (i=0; i < n_raw_log_fds; ++i) {
    r = write(raw_log_fds[i], s, len);
    err += (r != (ssize_t)len);
  }
  return err ? -1 : 0;
}

/** Given <b>m</b> and a list of string arguments <b>ap</b> ending with a NULL,
 * writes them to to each of the <b>n_raw_log_fds</b> elements o
 * <b>raw_log_fds</b>.
 *
 * If <b>error_fmt</b> is true, separate the log message from previous log
 * messages with a line of equals characters, followed by a timestamp.
 * If false, assume that the log message is all on one line, and start that
 * line with a timestamp.
 *
 * This function is safe to call from within a signal handler. */
void
tor_log_raw_ap(int *raw_log_fds, int n_raw_log_fds, bool error_fmt,
               const char *m, va_list ap)
{
  const char *x;
  char timebuf[33];
  time_t now = time(NULL);

  if (!m)
    return;
  if (log_granularity >= 2000) {
    int g = log_granularity / 1000;
    now -= now % g;
  }
  timebuf[0] = now < 0 ? '-' : ' ';
  if (now < 0) now = -now;
  timebuf[1] = '\0';
  format_dec_number_sigsafe(now, timebuf+1, sizeof(timebuf)-1);
  if (error_fmt) {
    tor_log_raw_write(raw_log_fds, n_raw_log_fds, "\n");
    tor_log_raw_write(raw_log_fds, n_raw_log_fds,
                      "=========================================="
                      "================== ");
  }
  tor_log_raw_write(raw_log_fds, n_raw_log_fds, "T=");
  tor_log_raw_write(raw_log_fds, n_raw_log_fds, timebuf);
  if (error_fmt) {
    tor_log_raw_write(raw_log_fds, n_raw_log_fds, "\n");
  } else {
    tor_log_raw_write(raw_log_fds, n_raw_log_fds, " ");
  }
  tor_log_raw_write(raw_log_fds, n_raw_log_fds, m);
  while ((x = va_arg(ap, const char*))) {
    tor_log_raw_write(raw_log_fds, n_raw_log_fds, x);
  }
}

/**
 * Set the granularity (in ms) to use when reporting fatal errors or controller
 * trace debug logs outside the logging system.
 */
void
tor_log_raw_set_granularity(int ms)
{
  log_granularity = ms;
}

/**
 * Returns the granularity (in ms) to use when reporting fatal errors or
 * controller trace debug logs outside the logging system.
 */
int
tor_log_raw_get_granularity(void)
{
  return log_granularity;
}

/* As format_{hex,dex}_number_sigsafe, but takes a <b>radix</b> argument
 * in range 2..16 inclusive. */
static int
format_number_sigsafe(unsigned long x, char *buf, int buf_len,
                      unsigned int radix)
{
  unsigned long tmp;
  int len;
  char *cp;

  /* NOT tor_assert. This needs to be safe to run from within a signal
   * handler, and from within the 'tor_assert() has failed' code.  Not even
   * raw_assert(), since raw_assert() calls this function on failure. */
  if (radix < 2 || radix > 16)
    return 0;

  /* Count how many digits we need. */
  tmp = x;
  len = 1;
  while (tmp >= radix) {
    tmp /= radix;
    ++len;
  }

  /* Not long enough */
  if (!buf || len >= buf_len)
    return 0;

  cp = buf + len;
  *cp = '\0';
  do {
    unsigned digit = (unsigned) (x % radix);
    if (cp <= buf) {
      /* Not tor_assert(); see above. */
      abort();
    }
    --cp;
    *cp = "0123456789ABCDEF"[digit];
    x /= radix;
  } while (x);

  /* NOT tor_assert; see above. */
  if (cp != buf) {
    abort(); // LCOV_EXCL_LINE
  }

  return len;
}

/**
 * Helper function to output hex numbers from within a signal handler.
 *
 * Writes the nul-terminated hexadecimal digits of <b>x</b> into a buffer
 * <b>buf</b> of size <b>buf_len</b>, and return the actual number of digits
 * written, not counting the terminal NUL.
 *
 * If there is insufficient space, write nothing and return 0.
 *
 * This accepts an unsigned int because format_helper_exit_status() needs to
 * call it with a signed int and an unsigned char, and since the C standard
 * does not guarantee that an int is wider than a char (an int must be at
 * least 16 bits but it is permitted for a char to be that wide as well), we
 * can't assume a signed int is sufficient to accommodate an unsigned char.
 * Thus, format_helper_exit_status() will still need to emit any require '-'
 * on its own.
 *
 * For most purposes, you'd want to use tor_snprintf("%x") instead of this
 * function; it's designed to be used in code paths where you can't call
 * arbitrary C functions.
 */
int
format_hex_number_sigsafe(unsigned long x, char *buf, int buf_len)
{
  return format_number_sigsafe(x, buf, buf_len, 16);
}

/** As format_hex_number_sigsafe, but format the number in base 10. */
int
format_dec_number_sigsafe(unsigned long x, char *buf, int buf_len)
{
  return format_number_sigsafe(x, buf, buf_len, 10);
}
