/* Copyright (c) 2001-2003, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_TEST_H
#define TOR_TEST_H

/**
 * \file test.h
 * \brief Macros and functions used by unit tests.
 */

#include "compat.h"
#include "tinytest.h"
#define TT_EXIT_TEST_FUNCTION STMT_BEGIN goto done; STMT_END
#include "tinytest_macros.h"

#ifdef __GNUC__
#define PRETTY_FUNCTION __PRETTY_FUNCTION__
#else
#define PRETTY_FUNCTION ""
#endif

#define test_fail_msg(msg) TT_DIE((msg))

#define test_fail() test_fail_msg("Assertion failed.")

#define test_assert(expr) tt_assert(expr)

#define test_eq(expr1, expr2) tt_int_op((expr1), ==, (expr2))
#define test_eq_ptr(expr1, expr2) tt_ptr_op((expr1), ==, (expr2))
#define test_neq(expr1, expr2) tt_int_op((expr1), !=, (expr2))
#define test_neq_ptr(expr1, expr2) tt_ptr_op((expr1), !=, (expr2))
#define test_streq(expr1, expr2) tt_str_op((expr1), ==, (expr2))
#define test_strneq(expr1, expr2) tt_str_op((expr1), !=, (expr2))

#define test_mem_op(expr1, op, expr2, len)                              \
  tt_mem_op((expr1), op, (expr2), (len))

#define test_memeq(expr1, expr2, len) test_mem_op((expr1), ==, (expr2), len)
#define test_memneq(expr1, expr2, len) test_mem_op((expr1), !=, (expr2), len)

/* As test_mem_op, but decodes 'hex' before comparing.  There must be a
 * local char* variable called mem_op_hex_tmp for this to work. */
#define test_mem_op_hex(expr1, op, hex)                                 \
  STMT_BEGIN                                                            \
  size_t length = strlen(hex);                                          \
  tor_free(mem_op_hex_tmp);                                             \
  mem_op_hex_tmp = tor_malloc(length/2);                                \
  tor_assert((length&1)==0);                                            \
  base16_decode(mem_op_hex_tmp, length/2, hex, length);                 \
  test_mem_op(expr1, op, mem_op_hex_tmp, length/2);                     \
  STMT_END

#define test_memeq_hex(expr1, hex) test_mem_op_hex(expr1, ==, hex)

#define tt_double_op(a,op,b)                                            \
  tt_assert_test_type(a,b,#a" "#op" "#b,double,(val1_ op val2_),"%f",   \
                      TT_EXIT_TEST_FUNCTION)

const char *get_fname(const char *name);
crypto_pk_t *pk_generate(int idx);

void legacy_test_helper(void *data);
extern const struct testcase_setup_t legacy_setup;

#endif

