/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include "compat_rust.h"
#include "test.h"
#include "util.h"

static void
test_welcome_string(void *arg)
{
  (void)arg;
  rust_str_t s = rust_welcome_string();
  const char *c_str = rust_str_get(s);
  tt_assert(c_str);
  size_t len = strlen(c_str);
#ifdef HAVE_RUST
  tt_assert(len > 0);
#else
  tt_assert(len == 0);
#endif

 done:
  rust_str_free(s);
}

struct testcase_t rust_tests[] = {
  { "welcome_string", test_welcome_string, 0, NULL, NULL },
  END_OF_TESTCASES
};

