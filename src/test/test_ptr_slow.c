/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include "core/or/or.h"
#include "test/test.h"

#include <stdint.h>
#include <limits.h>

/** Check that all values of int can be cast to void * and back. */
static void
test_int_voidstar_interop(void *arg)
{
  int a;
  (void)arg;

  for (a = INT_MIN; a < INT_MAX; a++) {
   intptr_t ap = (intptr_t)a;
   void *b = (void *)ap;
   intptr_t c = (intptr_t)b;
   void *d = (void *)c;

   tt_assert(ap == c);
   tt_assert(b == d);
  }

 done:
  return;
}

/** Check that all values of unsigned int can be cast to void * and back. */
static void
test_uint_voidstar_interop(void *arg)
{
  unsigned int a;
  (void)arg;

  for (a = 0; a < UINT_MAX; a++) {
   intptr_t ap = (intptr_t)a;
   void *b = (void *)ap;
   intptr_t c = (intptr_t)b;
   void *d = (void *)c;

   tt_assert(ap == c);
   tt_assert(b == d);
  }

 done:
  return;
}

struct testcase_t slow_ptr_tests[] = {
  { .name = "int_voidstar_interop",
    .fn = test_int_voidstar_interop,
    .flags = 0,
    .setup = NULL,
    .setup_data = NULL },
  { .name = "uint_voidstar_interop",
    .fn = test_uint_voidstar_interop,
    .flags = 0,
    .setup = NULL,
    .setup_data = NULL },
  END_OF_TESTCASES
};
