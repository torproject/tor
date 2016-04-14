/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file util_bug.c
 **/

#include "orconfig.h"
#include "util_bug.h"
#include "torlog.h"
#include "backtrace.h"

/** Helper for tor_assert: report the assertion failure. */
void
tor_assertion_failed_(const char *fname, unsigned int line,
                      const char *func, const char *expr)
{
  char buf[256];
  log_err(LD_BUG, "%s:%u: %s: Assertion %s failed; aborting.",
          fname, line, func, expr);
  tor_snprintf(buf, sizeof(buf),
               "Assertion %s failed in %s at %s:%u",
               expr, func, fname, line);
  log_backtrace(LOG_ERR, LD_BUG, buf);
}

/** Helper for tor_assert_nonfatal: report the assertion failure. */
void
tor_bug_occurred_(const char *fname, unsigned int line,
                  const char *func, const char *expr,
                  int once)
{
  char buf[256];
  const char *once_str = once ?
    " (Future instances of this warning will be silenced.)": "";
  if (! expr) {
    log_warn(LD_BUG, "%s:%u: %s: This line should not have been reached.%s",
             fname, line, func, once_str);
    tor_snprintf(buf, sizeof(buf),
                 "Line unexpectedly reached at %s at %s:%u",
                 func, fname, line);
  } else {
    log_warn(LD_BUG, "%s:%u: %s: Non-fatal assertion %s failed.%s",
             fname, line, func, expr, once_str);
    tor_snprintf(buf, sizeof(buf),
                 "Non-fatal assertion %s failed in %s at %s:%u",
                 expr, func, fname, line);
  }
  log_backtrace(LOG_WARN, LD_BUG, buf);
}

