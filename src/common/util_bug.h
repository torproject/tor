/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file util_bug.h
 **/

#ifndef TOR_UTIL_BUG_H
#define TOR_UTIL_BUG_H

#include "orconfig.h"
#include "compat.h"
#include "testsupport.h"

/* Replace assert() with a variant that sends failures to the log before
 * calling assert() normally.
 */
#ifdef NDEBUG
/* Nobody should ever want to build with NDEBUG set.  99% of our asserts will
 * be outside the critical path anyway, so it's silly to disable bug-checking
 * throughout the entire program just because a few asserts are slowing you
 * down.  Profile, optimize the critical path, and keep debugging on.
 *
 * And I'm not just saying that because some of our asserts check
 * security-critical properties.
 */
#error "Sorry; we don't support building with NDEBUG."
#endif

/* Sometimes we don't want to use assertions during branch coverage tests; it
 * leads to tons of unreached branches which in reality are only assertions we
 * didn't hit. */
#if defined(TOR_UNIT_TESTS) && defined(DISABLE_ASSERTS_IN_UNIT_TESTS)
#define tor_assert(a) STMT_BEGIN                                        \
  (void)(a);                                                            \
  STMT_END
#else
/** Like assert(3), but send assertion failures to the log as well as to
 * stderr. */
#define tor_assert(expr) STMT_BEGIN                                     \
  if (PREDICT_UNLIKELY(!(expr))) {                                      \
    tor_assertion_failed_(SHORT_FILE__, __LINE__, __func__, #expr);     \
    abort();                                                            \
  } STMT_END
#endif

/** Define this if you want Tor to crash when any problem comes up,
 * so you can get a coredump and track things down. */
// #define tor_fragile_assert() tor_assert(0)
#define tor_fragile_assert()

void tor_assertion_failed_(const char *fname, unsigned int line,
                           const char *func, const char *expr);

#endif

