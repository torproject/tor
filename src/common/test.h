/* Copyright 2001,2002,2003 Roger Dingledine.
 * Copyright 2004-2005 Roger Dingledine, Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef __TEST_H
#define __TEST_H
#define TEST_H_ID "$Id$"

/**
 * \file test.h
 * \brief Headers for test.c
 */

#include <string.h>
#include <stdio.h>
#include "compat.h"

#define STMT_BEGIN  do {
#define STMT_END    } while (0)

#ifdef __GNUC__
#define PRETTY_FUNCTION __PRETTY_FUNCTION__
#else
#define PRETTY_FUNCTION ""
#endif

extern int have_failed;

#define test_fail()                                             \
  STMT_BEGIN                                                    \
    have_failed = 1;                                            \
    printf("\nFile %s: line %d (%s): assertion failed.",        \
      _SHORT_FILE_,                                             \
      __LINE__,                                                 \
      PRETTY_FUNCTION);                                         \
    return;                                                     \
  STMT_END

#define test_assert(expr)                                       \
  STMT_BEGIN                                                    \
  if (expr) { printf("."); fflush(stdout); } else {             \
    have_failed = 1;                                            \
    printf("\nFile %s: line %d (%s): assertion failed: (%s)\n", \
      _SHORT_FILE_,                                             \
      __LINE__,                                                 \
      PRETTY_FUNCTION,                                          \
      #expr);                                                   \
    return;                                                     \
  } STMT_END

#define test_eq(expr1, expr2)                                   \
  STMT_BEGIN                                                    \
    long v1=(long)(expr1), v2=(long)(expr2);                    \
    if (v1==v2) { printf("."); fflush(stdout); } else {         \
    have_failed = 1;                                            \
    printf("\nFile %s: line %d (%s): Assertion failed: (%s==%s)\n"\
           "      (%ld != %ld)\n",                              \
      _SHORT_FILE_,                                             \
      __LINE__,                                                 \
      PRETTY_FUNCTION,                                          \
      #expr1, #expr2,                                           \
      v1, v2);                                                  \
    return;                                                     \
  } STMT_END

#define test_neq(expr1, expr2)                                  \
  STMT_BEGIN                                                    \
    long v1=(long)(expr1), v2=(long)(expr2);                    \
    if (v1!=v2) { printf("."); fflush(stdout); } else {         \
    have_failed = 1;                                            \
    printf("\nFile %s: line %d (%s): Assertion failed: (%s!=%s)\n"\
           "      (%ld == %ld)\n",                              \
      _SHORT_FILE_,                                             \
      __LINE__,                                                 \
      PRETTY_FUNCTION,                                          \
      #expr1, #expr2,                                           \
      v1, v2);                                                  \
    return;                                                     \
  } STMT_END

#define test_streq(expr1, expr2)                                \
  STMT_BEGIN                                                    \
    const char *v1=(expr1), *v2=(expr2);                        \
    if (!strcmp(v1,v2)) { printf("."); fflush(stdout); } else { \
    have_failed = 1;                                            \
    printf("\nFile %s: line %d (%s): Assertion failed: (%s==%s)\n"\
           "      (\"%s\" != \"%s\")\n",                        \
      _SHORT_FILE_,                                             \
      __LINE__,                                                 \
      PRETTY_FUNCTION,                                          \
      #expr1, #expr2,                                           \
      v1, v2);                                                  \
    return;                                                     \
  } STMT_END

#define test_strneq(expr1, expr2)                               \
  STMT_BEGIN                                                    \
    const char *v1=(expr1), *v2=(expr2);                        \
    if (strcmp(v1,v2)) { printf("."); fflush(stdout); } else {  \
    have_failed = 1;                                            \
    printf("\nFile %s: line %d (%s): Assertion failed: (%s!=%s)\n"\
           "      (\"%s\" == \"%s\")\n",                        \
      _SHORT_FILE_,                                             \
      __LINE__,                                                 \
      PRETTY_FUNCTION,                                          \
      #expr1, #expr2,                                           \
      v1, v2);                                                  \
    return;                                                     \
  } STMT_END

#define test_memeq(expr1, expr2, len)                           \
  STMT_BEGIN                                                    \
    const void *v1=(expr1), *v2=(expr2);                        \
    if (!memcmp(v1,v2,(len))) { printf("."); fflush(stdout); } else {\
    have_failed = 1;                                            \
    printf("\nFile %s: line %d (%s): Assertion failed: (%s==%s)\n", \
      _SHORT_FILE_,                                             \
      __LINE__,                                                 \
      PRETTY_FUNCTION,                                          \
      #expr1, #expr2);                                          \
    return;                                                     \
  } STMT_END

#define test_memneq(expr1, expr2, len)                          \
  STMT_BEGIN                                                    \
    void *v1=(expr1), *v2=(expr2);                              \
    if (memcmp(v1,v2,(len))) { printf("."); fflush(stdout); } else {\
    have_failed = 1;                                            \
    printf("\nFile %s: line %d (%s): Assertion failed: (%s!=%s)\n", \
      _SHORT_FILE_,                                             \
      __LINE__,                                                 \
      PRETTY_FUNCTION,                                          \
      #expr1, #expr2);                                          \
    return;                                                     \
  } STMT_END

#endif

