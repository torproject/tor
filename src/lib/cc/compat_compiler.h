/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_COMPAT_COMPILER_H
#define TOR_COMPAT_COMPILER_H

#include "orconfig.h"

#if defined(__has_feature)
#  if __has_feature(address_sanitizer)
/* Some of the fancy glibc strcmp() macros include references to memory that
 * clang rejects because it is off the end of a less-than-3. Clang hates this,
 * even though those references never actually happen. */
#    undef strcmp
#endif /* __has_feature(address_sanitizer) */
#endif /* defined(__has_feature) */

#ifndef NULL_REP_IS_ZERO_BYTES
#error "It seems your platform does not represent NULL as zero. We can't cope."
#endif

#ifndef DOUBLE_0_REP_IS_ZERO_BYTES
#error "It seems your platform does not represent 0.0 as zeros. We can't cope."
#endif

#if 'a'!=97 || 'z'!=122 || 'A'!=65 || ' '!=32
#error "It seems that you encode characters in something other than ASCII."
#endif

/* GCC can check printf and scanf types on arbitrary functions. */
#ifdef __GNUC__
#define CHECK_PRINTF(formatIdx, firstArg) \
   __attribute__ ((format(printf, formatIdx, firstArg)))
#else
#define CHECK_PRINTF(formatIdx, firstArg)
#endif /* defined(__GNUC__) */
#ifdef __GNUC__
#define CHECK_SCANF(formatIdx, firstArg) \
   __attribute__ ((format(scanf, formatIdx, firstArg)))
#else
#define CHECK_SCANF(formatIdx, firstArg)
#endif /* defined(__GNUC__) */

/* What GCC do we have? */
#ifdef __GNUC__
#define GCC_VERSION (__GNUC__ * 100 + __GNUC_MINOR__)
#else
#define GCC_VERSION 0
#endif

/* Temporarily enable and disable warnings. */
#ifdef __GNUC__
#  define PRAGMA_STRINGIFY_(s) #s
#  define PRAGMA_JOIN_STRINGIFY_(a,b) PRAGMA_STRINGIFY_(a ## b)
/* Support for macro-generated pragmas (c99) */
#  define PRAGMA_(x) _Pragma (#x)
#  ifdef __clang__
#    define PRAGMA_DIAGNOSTIC_(x) PRAGMA_(clang diagnostic x)
#  else
#    define PRAGMA_DIAGNOSTIC_(x) PRAGMA_(GCC diagnostic x)
#  endif
#  if defined(__clang__) || GCC_VERSION >= 406
/* we have push/pop support */
#    define DISABLE_GCC_WARNING(warningopt) \
          PRAGMA_DIAGNOSTIC_(push) \
          PRAGMA_DIAGNOSTIC_(ignored PRAGMA_JOIN_STRINGIFY_(-W,warningopt))
#    define ENABLE_GCC_WARNING(warningopt) \
          PRAGMA_DIAGNOSTIC_(pop)
#else /* !(defined(__clang__) || GCC_VERSION >= 406) */
/* older version of gcc: no push/pop support. */
#    define DISABLE_GCC_WARNING(warningopt) \
         PRAGMA_DIAGNOSTIC_(ignored PRAGMA_JOIN_STRINGIFY_(-W,warningopt))
#    define ENABLE_GCC_WARNING(warningopt) \
         PRAGMA_DIAGNOSTIC_(warning PRAGMA_JOIN_STRINGIFY_(-W,warningopt))
#endif /* defined(__clang__) || GCC_VERSION >= 406 */
#else /* !(defined(__GNUC__)) */
/* not gcc at all */
# define DISABLE_GCC_WARNING(warning)
# define ENABLE_GCC_WARNING(warning)
#endif /* defined(__GNUC__) */

/* inline is __inline on windows. */
#ifdef _WIN32
#define inline __inline
#endif

/* Try to get a reasonable __func__ substitute in place. */
#if defined(_MSC_VER)

#define __func__ __FUNCTION__

#else
/* For platforms where autoconf works, make sure __func__ is defined
 * sanely. */
#ifndef HAVE_MACRO__func__
#ifdef HAVE_MACRO__FUNCTION__
#define __func__ __FUNCTION__
#elif HAVE_MACRO__FUNC__
#define __func__ __FUNC__
#else
#define __func__ "???"
#endif /* defined(HAVE_MACRO__FUNCTION__) || ... */
#endif /* !defined(HAVE_MACRO__func__) */
#endif /* defined(_MSC_VER) */

#define U64_TO_DBL(x) ((double) (x))
#define DBL_TO_U64(x) ((uint64_t) (x))

#ifdef ENUM_VALS_ARE_SIGNED
#define ENUM_BF(t) unsigned
#else
/** Wrapper for having a bitfield of an enumerated type. Where possible, we
 * just use the enumerated type (so the compiler can help us and notice
 * problems), but if enumerated types are unsigned, we must use unsigned,
 * so that the loss of precision doesn't make large values negative. */
#define ENUM_BF(t) t
#endif /* defined(ENUM_VALS_ARE_SIGNED) */

/* GCC has several useful attributes. */
#if defined(__GNUC__) && __GNUC__ >= 3
#define ATTR_NORETURN __attribute__((noreturn))
#define ATTR_CONST __attribute__((const))
#define ATTR_MALLOC __attribute__((malloc))
#define ATTR_NORETURN __attribute__((noreturn))
#define ATTR_WUR __attribute__((warn_unused_result))
/* Alas, nonnull is not at present a good idea for us.  We'd like to get
 * warnings when we pass NULL where we shouldn't (which nonnull does, albeit
 * spottily), but we don't want to tell the compiler to make optimizations
 * with the assumption that the argument can't be NULL (since this would make
 * many of our checks go away, and make our code less robust against
 * programming errors).  Unfortunately, nonnull currently does both of these
 * things, and there's no good way to split them up.
 *
 * #define ATTR_NONNULL(x) __attribute__((nonnull x)) */
#define ATTR_NONNULL(x)
#define ATTR_UNUSED __attribute__ ((unused))

/** Macro: Evaluates to <b>exp</b> and hints the compiler that the value
 * of <b>exp</b> will probably be true.
 *
 * In other words, "if (PREDICT_LIKELY(foo))" is the same as "if (foo)",
 * except that it tells the compiler that the branch will be taken most of the
 * time.  This can generate slightly better code with some CPUs.
 */
#define PREDICT_LIKELY(exp) __builtin_expect(!!(exp), 1)
/** Macro: Evaluates to <b>exp</b> and hints the compiler that the value
 * of <b>exp</b> will probably be false.
 *
 * In other words, "if (PREDICT_UNLIKELY(foo))" is the same as "if (foo)",
 * except that it tells the compiler that the branch will usually not be
 * taken.  This can generate slightly better code with some CPUs.
 */
#define PREDICT_UNLIKELY(exp) __builtin_expect(!!(exp), 0)
#else /* !(defined(__GNUC__) && __GNUC__ >= 3) */
#define ATTR_NORETURN
#define ATTR_CONST
#define ATTR_MALLOC
#define ATTR_NORETURN
#define ATTR_NONNULL(x)
#define ATTR_UNUSED
#define ATTR_WUR
#define PREDICT_LIKELY(exp) (exp)
#define PREDICT_UNLIKELY(exp) (exp)
#endif /* defined(__GNUC__) && __GNUC__ >= 3 */

/** Expands to a syntactically valid empty statement.  */
#define STMT_NIL (void)0

/** Expands to a syntactically valid empty statement, explicitly (void)ing its
 * argument. */
#define STMT_VOID(a) while (0) { (void)(a); }

#ifdef __GNUC__
/** STMT_BEGIN and STMT_END are used to wrap blocks inside macros so that
 * the macro can be used as if it were a single C statement. */
#define STMT_BEGIN (void) ({
#define STMT_END })
#elif defined(sun) || defined(__sun__)
#define STMT_BEGIN if (1) {
#define STMT_END } else STMT_NIL
#else
#define STMT_BEGIN do {
#define STMT_END } while (0)
#endif /* defined(__GNUC__) || ... */

/* Some tools (like coccinelle) don't like to see operators as macro
 * arguments. */
#define OP_LT <
#define OP_GT >
#define OP_GE >=
#define OP_LE <=
#define OP_EQ ==
#define OP_NE !=

#ifdef _MSC_VER
/** Casts the uint64_t value in <b>a</b> to the right type for an argument
 * to printf. */
#define U64_PRINTF_ARG(a) (a)
/** Casts the uint64_t* value in <b>a</b> to the right type for an argument
 * to scanf. */
#define U64_SCANF_ARG(a) (a)
/** Expands to a literal uint64_t-typed constant for the value <b>n</b>. */
#define U64_LITERAL(n) (n ## ui64)
#define I64_PRINTF_ARG(a) (a)
#define I64_SCANF_ARG(a) (a)
#define I64_LITERAL(n) (n ## i64)
#else /* !(defined(_MSC_VER)) */
#define U64_PRINTF_ARG(a) ((long long unsigned int)(a))
#define U64_SCANF_ARG(a) ((long long unsigned int*)(a))
#define U64_LITERAL(n) (n ## llu)
#define I64_PRINTF_ARG(a) ((long long signed int)(a))
#define I64_SCANF_ARG(a) ((long long signed int*)(a))
#define I64_LITERAL(n) (n ## ll)
#endif /* defined(_MSC_VER) */

#if defined(__MINGW32__) || defined(__MINGW64__)
#define MINGW_ANY
#endif

#if defined(_MSC_VER) || defined(MINGW_ANY)
/** The formatting string used to put a uint64_t value in a printf() or
 * scanf() function.  See also U64_PRINTF_ARG and U64_SCANF_ARG. */
#define U64_FORMAT "%I64u"
#define I64_FORMAT "%I64d"
#else /* !(defined(_MSC_VER) || defined(MINGW_ANY)) */
#define U64_FORMAT "%llu"
#define I64_FORMAT "%lld"
#endif /* defined(_MSC_VER) || defined(MINGW_ANY) */

#if (SIZEOF_INTPTR_T == SIZEOF_INT)
#define INTPTR_T_FORMAT "%d"
#define INTPTR_PRINTF_ARG(x) ((int)(x))
#elif (SIZEOF_INTPTR_T == SIZEOF_LONG)
#define INTPTR_T_FORMAT "%ld"
#define INTPTR_PRINTF_ARG(x) ((long)(x))
#elif (SIZEOF_INTPTR_T == 8)
#define INTPTR_T_FORMAT I64_FORMAT
#define INTPTR_PRINTF_ARG(x) I64_PRINTF_ARG(x)
#else
#error Unknown: SIZEOF_INTPTR_T
#endif /* (SIZEOF_INTPTR_T == SIZEOF_INT) || ... */

#endif /* !defined(TOR_COMPAT_H) */
