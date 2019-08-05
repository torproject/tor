/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file torerr.c
 *
 * \brief Handling code for unrecoverable emergencies, at a lower level
 *   than the logging code.
 *
 * There are plenty of places that things can go wrong in Tor's backend
 * libraries: the allocator can fail, the locking subsystem can fail, and so
 * on.  But since these subsystems are used themselves by the logging module,
 * they can't use the logging code directly to report their errors.
 *
 * As a workaround, the logging code provides this module with a set of raw
 * fds to be used for reporting errors in the lowest-level Tor code.
 */

#include "orconfig.h"
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "lib/err/torerr.h"
#include "lib/err/backtrace.h"
#include "lib/err/raw_log.h"

/** Array of fds to log crash-style warnings to. */
static int sigsafe_log_fds[TOR_SIGSAFE_LOG_MAX_FDS] = { STDERR_FILENO };
/** The number of elements used in sigsafe_log_fds */
static int n_sigsafe_log_fds = 1;

/** Write <b>s</b> to to our logs and to stderr (if possible).
 * Return 0 on success, -1 on failure. */
static int
tor_log_err_sigsafe_write(const char *s)
{
  return tor_log_raw_write(sigsafe_log_fds, n_sigsafe_log_fds, s);
}

/** Given a list of string arguments ending with a NULL, writes them
 * to our logs and to stderr (if possible).  This function is safe to call
 * from within a signal handler. */
void
tor_log_err_sigsafe(const char *m, ...)
{
  va_list ap;
  va_start(ap, m);
  tor_log_raw_ap(sigsafe_log_fds, n_sigsafe_log_fds, true, m, ap);
  va_end(ap);
}

/** Set *<b>out</b> to a pointer to an array of the fds to log errors to from
 * inside a signal handler or other emergency condition. Return the number of
 * elements in the array. */
int
tor_log_get_sigsafe_err_fds(const int **out)
{
  *out = sigsafe_log_fds;
  return n_sigsafe_log_fds;
}

/**
 * Update the list of fds that get errors from inside a signal handler or
 * other emergency condition. Ignore any beyond the first
 * TOR_SIGSAFE_LOG_MAX_FDS.
 */
void
tor_log_set_sigsafe_err_fds(const int *fds, int n)
{
  if (n > TOR_SIGSAFE_LOG_MAX_FDS) {
    n = TOR_SIGSAFE_LOG_MAX_FDS;
  }

  memcpy(sigsafe_log_fds, fds, n * sizeof(int));
  n_sigsafe_log_fds = n;
}

/**
 * Reset the list of emergency error fds to its default.
 */
void
tor_log_reset_sigsafe_err_fds(void)
{
  int fds[] = { STDERR_FILENO };
  tor_log_set_sigsafe_err_fds(fds, 1);
}

/**
 * Log an emergency assertion failure message.
 *
 * This kind of message is safe to send from within a log handler,
 * a signal handler, or other emergency situation.
 */
void
tor_raw_assertion_failed_msg_(const char *file, int line, const char *expr,
                              const char *msg)
{
  char linebuf[16];
  format_dec_number_sigsafe(line, linebuf, sizeof(linebuf));
  tor_log_err_sigsafe("INTERNAL ERROR: Raw assertion failed at ",
                      file, ":", linebuf, ": ", expr, NULL);
  if (msg) {
    tor_log_err_sigsafe_write(msg);
    tor_log_err_sigsafe_write("\n");
  }

  dump_stack_symbols_to_error_fds();
}
