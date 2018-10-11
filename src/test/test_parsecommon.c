/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "core/or/or.h"
#include "test/test.h"
#include "lib/memarea/memarea.h"
#include "lib/encoding/binascii.h"
#include "feature/dirparse/parsecommon.h"
#include "test/log_test_helpers.h"

static void
test_parsecommon_tokenize_string_null(void *arg)
{

  memarea_t *area = memarea_new();
  smartlist_t *tokens = smartlist_new();

  (void)arg;

  const char *str_with_null = "a\0bccccccccc";

  int retval =
  tokenize_string(area, str_with_null,
                  str_with_null + 3,
                  tokens, NULL, 0);

  tt_int_op(retval, OP_EQ, -1);

 done:
  memarea_drop_all(area);
  smartlist_free(tokens);
  return;
}

#define PARSECOMMON_TEST(name) \
  { #name, test_parsecommon_ ## name, 0, NULL, NULL }

struct testcase_t parsecommon_tests[] = {
  PARSECOMMON_TEST(tokenize_string_null),
  END_OF_TESTCASES
};

