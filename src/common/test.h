/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef __TEST_H
#define __TEST_H

#define test_fail()                                             \
  if (1) {                                                      \
    printf("\nFile %s: line %d (%s): assertion failed.",        \
      __FILE__,                                                 \
      __LINE__,                                                 \
      __PRETTY_FUNCTION__);                                     \
    return;                                                     \
  }

#define test_assert(expr)                                       \
  if(expr) { printf("."); } else {                              \
    printf("\nFile %s: line %d (%s): assertion failed: (%s)\n", \
      __FILE__,                                                 \
      __LINE__,                                                 \
      __PRETTY_FUNCTION__,                                      \
      #expr);                                                   \
    return;                                                     \
  }

#define test_eq(expr1, expr2)                                   \
  if(expr1==expr2) { printf("."); } else {                      \
    printf("\nFile %s: line %d (%s): Assertion failed: (%s==%s)\n"\
           "      (%ld != %ld)\n",                              \
      __FILE__,                                                 \
      __LINE__,                                                 \
      __PRETTY_FUNCTION__,                                      \
      #expr1, #expr2,                                           \
      (long)expr1, (long)expr2);                                \
    return;                                                     \
  }

#define test_neq(expr1, expr2)                                  \
  if(expr1!=expr2) { printf("."); } else {                      \
    printf("\nFile %s: line %d (%s): Assertion failed: (%s!=%s)\n"\
           "      (%ld == %ld)\n",                              \
      __FILE__,                                                 \
      __LINE__,                                                 \
      __PRETTY_FUNCTION__,                                      \
      #expr1, #expr2,                                           \
      (long)expr1, (long)expr2);                                \
    return;                                                     \
  }

#define test_streq(expr1, expr2)                                \
  if(!strcmp(expr1,expr2)) { printf("."); } else {              \
    printf("\nFile %s: line %d (%s): Assertion failed: (%s==%s)\n"\
           "      (%s != %s)\n",                                \
      __FILE__,                                                 \
      __LINE__,                                                 \
      __PRETTY_FUNCTION__,                                      \
      #expr1, #expr2,                                           \
      (long)expr1, (long)expr2);                                \
    return;                                                     \
  }

#define test_strneq(expr1, expr2)                               \
  if(strcmp(expr1,expr2)) { printf("."); } else {               \
    printf("\nFile %s: line %d (%s): Assertion failed: (%s!=%s)\n"\
           "      (%s == %s)\n",                                \
      __FILE__,                                                 \
      __LINE__,                                                 \
      __PRETTY_FUNCTION__,                                      \
      #expr1, #expr2,                                           \
      expr1, expr2);                                            \
    return;                                                     \
  }

#endif
