/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file util_bug.h
 *
 * \brief Macros to manage assertions, fatal and non-fatal.
 *
 * Guidelines: All the different kinds of assertion in this file are for
 * bug-checking only. Don't write code that can assert based on bad inputs.
 *
 * We provide two kinds of assertion here: "fatal" and "nonfatal". Use
 * nonfatal assertions for any bug you can reasonably recover from -- and
 * please, try to recover!  Many severe bugs in Tor have been caused by using
 * a regular assertion when a nonfatal assertion would have been better.
 *
 * If you need to check a condition with a nonfatal assertion, AND recover
 * from that same condition, consider using the BUG() macro inside a
 * conditional.  For example:
 *
 * <code>
 *  // wrong -- use tor_assert_nonfatal() if you just want an assertion.
 *  BUG(ptr == NULL);
 *
 *  // okay, but needlessly verbose
 *  tor_assert_nonfatal(ptr != NULL);
 *  if (ptr == NULL) { ... }
 *
 *  // this is how we do it:
 *  if (BUG(ptr == NULL)) { ... }
 * </code>
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
#endif /* defined(NDEBUG) */

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
#endif /* defined(TOR_UNIT_TESTS) && defined(DISABLE_ASSERTS_IN_UNIT_TESTS) */

#define tor_assert_unreached() tor_assert(0)

/* Non-fatal bug assertions. The "unreached" variants mean "this line should
 * never be reached." The "once" variants mean "Don't log a warning more than
 * once".
 *
 * The 'BUG' macro checks a boolean condition and logs an error message if it
 * is true.  Example usage:
 *   if (BUG(x == NULL))
 *     return -1;
 */

#ifdef __COVERITY__
extern int bug_macro_deadcode_dummy__;
#undef BUG
// Coverity defines this in global headers; let's override it.  This is a
// magic coverity-only preprocessor thing.
// We use this "deadcode_dummy__" trick to prevent coverity from
// complaining about unreachable bug cases.
#nodef BUG(x) ((x)?(__coverity_panic__(),1):(0+bug_macro_deadcode_dummy__))
#endif /* defined(__COVERITY__) */

#if defined(__COVERITY__) || defined(__clang_analyzer__)
// We're running with a static analysis tool: let's treat even nonfatal
// assertion failures as something that we need to avoid.
#define ALL_BUGS_ARE_FATAL
#endif

#ifdef ALL_BUGS_ARE_FATAL
#define tor_assert_nonfatal_unreached() tor_assert(0)
#define tor_assert_nonfatal(cond) tor_assert((cond))
#define tor_assert_nonfatal_unreached_once() tor_assert(0)
#define tor_assert_nonfatal_once(cond) tor_assert((cond))
#define BUG(cond)                                                       \
  (PREDICT_UNLIKELY(cond) ?                                             \
   (tor_assertion_failed_(SHORT_FILE__,__LINE__,__func__,"!("#cond")"), \
    abort(), 1)                                                         \
   : 0)
#elif defined(TOR_UNIT_TESTS) && defined(DISABLE_ASSERTS_IN_UNIT_TESTS)
#define tor_assert_nonfatal_unreached() STMT_NIL
#define tor_assert_nonfatal(cond) ((void)(cond))
#define tor_assert_nonfatal_unreached_once() STMT_NIL
#define tor_assert_nonfatal_once(cond) ((void)(cond))
#define BUG(cond) (PREDICT_UNLIKELY(cond) ? 1 : 0)
#else /* Normal case, !ALL_BUGS_ARE_FATAL, !DISABLE_ASSERTS_IN_UNIT_TESTS */
#define tor_assert_nonfatal_unreached() STMT_BEGIN                      \
  tor_bug_occurred_(SHORT_FILE__, __LINE__, __func__, NULL, 0);         \
  STMT_END
#define tor_assert_nonfatal(cond) STMT_BEGIN                            \
  if (PREDICT_UNLIKELY(!(cond))) {                                      \
    tor_bug_occurred_(SHORT_FILE__, __LINE__, __func__, #cond, 0);  \
  }                                                                     \
  STMT_END
#define tor_assert_nonfatal_unreached_once() STMT_BEGIN                 \
  static int warning_logged__ = 0;                                      \
  if (!warning_logged__) {                                              \
    warning_logged__ = 1;                                               \
    tor_bug_occurred_(SHORT_FILE__, __LINE__, __func__, NULL, 1);       \
  }                                                                     \
  STMT_END
#define tor_assert_nonfatal_once(cond) STMT_BEGIN                       \
  static int warning_logged__ = 0;                                      \
  if (!warning_logged__ && PREDICT_UNLIKELY(!(cond))) {                 \
    warning_logged__ = 1;                                               \
    tor_bug_occurred_(SHORT_FILE__, __LINE__, __func__, #cond, 1);      \
  }                                                                     \
  STMT_END
#define BUG(cond)                                                       \
  (PREDICT_UNLIKELY(cond) ?                                             \
   (tor_bug_occurred_(SHORT_FILE__,__LINE__,__func__,"!("#cond")",0), 1) \
   : 0)
#endif /* defined(ALL_BUGS_ARE_FATAL) || ... */

#ifdef __GNUC__
#define IF_BUG_ONCE__(cond,var)                                         \
  if (( {                                                               \
      static int var = 0;                                               \
      int bool_result = (cond);                                         \
      if (PREDICT_UNLIKELY(bool_result) && !var) {                      \
        var = 1;                                                        \
        tor_bug_occurred_(SHORT_FILE__, __LINE__, __func__,             \
                          "!("#cond")", 1);                             \
      }                                                                 \
      PREDICT_UNLIKELY(bool_result); } ))
#else /* !(defined(__GNUC__)) */
#define IF_BUG_ONCE__(cond,var)                                         \
  static int var = 0;                                                   \
  if (PREDICT_UNLIKELY(cond) ?                                          \
      (var ? 1 :                                                        \
       (var=1,                                                          \
        tor_bug_occurred_(SHORT_FILE__, __LINE__, __func__,             \
                           "!("#cond")", 1),                            \
        1))                                                             \
      : 0)
#endif /* defined(__GNUC__) */
#define IF_BUG_ONCE_VARNAME_(a)               \
  warning_logged_on_ ## a ## __
#define IF_BUG_ONCE_VARNAME__(a)              \
  IF_BUG_ONCE_VARNAME_(a)

/** This macro behaves as 'if (bug(x))', except that it only logs its
 * warning once, no matter how many times it triggers.
 */

#define IF_BUG_ONCE(cond)                                       \
  IF_BUG_ONCE__((cond),                                         \
                IF_BUG_ONCE_VARNAME__(__LINE__))

/** Define this if you want Tor to crash when any problem comes up,
 * so you can get a coredump and track things down. */
// #define tor_fragile_assert() tor_assert_unreached(0)
#define tor_fragile_assert() tor_assert_nonfatal_unreached_once()

void tor_assertion_failed_(const char *fname, unsigned int line,
                           const char *func, const char *expr);
void tor_bug_occurred_(const char *fname, unsigned int line,
                       const char *func, const char *expr,
                       int once);

#ifdef TOR_UNIT_TESTS
void tor_capture_bugs_(int n);
void tor_end_capture_bugs_(void);
const struct smartlist_t *tor_get_captured_bug_log_(void);
void tor_set_failed_assertion_callback(void (*fn)(void));
#endif /* defined(TOR_UNIT_TESTS) */

#endif /* !defined(TOR_UTIL_BUG_H) */

