/* Copyright (c) 2012-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define REPLAYCACHE_PRIVATE

#include "orconfig.h"
#include "or.h"
#include "replaycache.h"
#include "test.h"

static const char *test_buffer =
  "Lorem ipsum dolor sit amet, consectetur adipisici elit, sed do eiusmod"
  " tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim"
  " veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea"
  " commodo consequat. Duis aute irure dolor in reprehenderit in voluptate"
  " velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint"
  " occaecat cupidatat non proident, sunt in culpa qui officia deserunt"
  " mollit anim id est laborum.";

static void
test_replaycache_alloc(void)
{
  replaycache_t *r = NULL;

  r = replaycache_new(600, 300);
  test_assert(r != NULL);

 done:
  if (r) replaycache_free(r);

  return;
}

static void
test_replaycache_miss(void)
{
  replaycache_t *r = NULL;
  int result;

  r = replaycache_new(600, 300);
  test_assert(r != NULL);

  result =
    replaycache_add_and_test_internal(1200, r, test_buffer,
        (int)strlen(test_buffer), NULL);
  test_eq(result, 0);

 done:
  if (r) replaycache_free(r);

  return;
}

static void
test_replaycache_hit(void)
{
  replaycache_t *r = NULL;
  int result;

  r = replaycache_new(600, 300);
  test_assert(r != NULL);

  result =
    replaycache_add_and_test_internal(1200, r, test_buffer,
        (int)strlen(test_buffer), NULL);
  test_eq(result, 0);

  result =
    replaycache_add_and_test_internal(1300, r, test_buffer,
        (int)strlen(test_buffer), NULL);
  test_eq(result, 1);

 done:
  if (r) replaycache_free(r);

  return;
}

static void
test_replaycache_age(void)
{
  replaycache_t *r = NULL;
  int result;

  r = replaycache_new(600, 300);
  test_assert(r != NULL);

  result =
    replaycache_add_and_test_internal(1200, r, test_buffer,
        (int)strlen(test_buffer), NULL);
  test_eq(result, 0);

  result =
    replaycache_add_and_test_internal(1300, r, test_buffer,
        (int)strlen(test_buffer), NULL);
  test_eq(result, 1);

  result =
    replaycache_add_and_test_internal(3000, r, test_buffer,
        (int)strlen(test_buffer), NULL);
  test_eq(result, 0);

 done:
  if (r) replaycache_free(r);

  return;
}

static void
test_replaycache_elapsed(void)
{
  replaycache_t *r = NULL;
  int result;
  time_t elapsed;

  r = replaycache_new(600, 300);
  test_assert(r != NULL);

  result =
    replaycache_add_and_test_internal(1200, r, test_buffer,
        (int)strlen(test_buffer), NULL);
  test_eq(result, 0);

  result =
    replaycache_add_and_test_internal(1300, r, test_buffer,
        (int)strlen(test_buffer), &elapsed);
  test_eq(result, 1);
  test_eq(elapsed, 100);

 done:
  if (r) replaycache_free(r);

  return;
}

static void
test_replaycache_noexpire(void)
{
  replaycache_t *r = NULL;
  int result;

  r = replaycache_new(0, 0);
  test_assert(r != NULL);

  result =
    replaycache_add_and_test_internal(1200, r, test_buffer,
        (int)strlen(test_buffer), NULL);
  test_eq(result, 0);

  result =
    replaycache_add_and_test_internal(1300, r, test_buffer,
        (int)strlen(test_buffer), NULL);
  test_eq(result, 1);

  result =
    replaycache_add_and_test_internal(3000, r, test_buffer,
        (int)strlen(test_buffer), NULL);
  test_eq(result, 1);

 done:
  if (r) replaycache_free(r);

  return;
}

#define REPLAYCACHE_LEGACY(name) \
  { #name, legacy_test_helper, 0, &legacy_setup, test_replaycache_ ## name }

struct testcase_t replaycache_tests[] = {
  REPLAYCACHE_LEGACY(alloc),
  REPLAYCACHE_LEGACY(miss),
  REPLAYCACHE_LEGACY(hit),
  REPLAYCACHE_LEGACY(age),
  REPLAYCACHE_LEGACY(elapsed),
  REPLAYCACHE_LEGACY(noexpire),
  END_OF_TESTCASES
};

