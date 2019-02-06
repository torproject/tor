/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#define CRYPTO_RAND_PRIVATE
#include "core/or/or.h"
#include "test/test.h"
#include "lib/crypt_ops/aes.h"
#include "lib/crypt_ops/crypto_format.h"
#include "lib/crypt_ops/crypto_rand.h"

/** Run unit tests for our random number generation function and its wrappers.
 */
static void
test_crypto_rng(void *arg)
{
  int i, j, allok;
  char data1[100], data2[100];
  double d;
  char *h=NULL;

  /* Try out RNG. */
  (void)arg;
  tt_assert(! crypto_seed_rng());
  crypto_rand(data1, 100);
  crypto_rand(data2, 100);
  tt_mem_op(data1,OP_NE, data2,100);
  allok = 1;
  for (i = 0; i < 100; ++i) {
    uint64_t big;
    char *host;
    j = crypto_rand_int(100);
    if (j < 0 || j >= 100)
      allok = 0;
    big = crypto_rand_uint64(UINT64_C(1)<<40);
    if (big >= (UINT64_C(1)<<40))
      allok = 0;
    big = crypto_rand_uint64(UINT64_C(5));
    if (big >= 5)
      allok = 0;
    d = crypto_rand_double();
    tt_assert(d >= 0);
    tt_assert(d < 1.0);
    host = crypto_random_hostname(3,8,"www.",".onion");
    if (strcmpstart(host,"www.") ||
        strcmpend(host,".onion") ||
        strlen(host) < 13 ||
        strlen(host) > 18)
      allok = 0;
    tor_free(host);
  }

  /* Make sure crypto_random_hostname clips its inputs properly. */
  h = crypto_random_hostname(20000, 9000, "www.", ".onion");
  tt_assert(! strcmpstart(h,"www."));
  tt_assert(! strcmpend(h,".onion"));
  tt_int_op(63+4+6, OP_EQ, strlen(h));

  tt_assert(allok);
 done:
  tor_free(h);
}

static void
test_crypto_rng_range(void *arg)
{
  int got_smallest = 0, got_largest = 0;
  int i;

  (void)arg;
  for (i = 0; i < 1000; ++i) {
    int x = crypto_rand_int_range(5,9);
    tt_int_op(x, OP_GE, 5);
    tt_int_op(x, OP_LT, 9);
    if (x == 5)
      got_smallest = 1;
    if (x == 8)
      got_largest = 1;
  }
  /* These fail with probability 1/10^603. */
  tt_assert(got_smallest);
  tt_assert(got_largest);

  got_smallest = got_largest = 0;
  const uint64_t ten_billion = 10 * ((uint64_t)1000000000000);
  for (i = 0; i < 1000; ++i) {
    uint64_t x = crypto_rand_uint64_range(ten_billion, ten_billion+10);
    tt_u64_op(x, OP_GE, ten_billion);
    tt_u64_op(x, OP_LT, ten_billion+10);
    if (x == ten_billion)
      got_smallest = 1;
    if (x == ten_billion+9)
      got_largest = 1;
  }

  tt_assert(got_smallest);
  tt_assert(got_largest);

  const time_t now = time(NULL);
  for (i = 0; i < 2000; ++i) {
    time_t x = crypto_rand_time_range(now, now+60);
    tt_i64_op(x, OP_GE, now);
    tt_i64_op(x, OP_LT, now+60);
    if (x == now)
      got_smallest = 1;
    if (x == now+59)
      got_largest = 1;
  }

  tt_assert(got_smallest);
  tt_assert(got_largest);
 done:
  ;
}

static void
test_crypto_rng_strongest(void *arg)
{
  const char *how = arg;
  int broken = 0;

  if (how == NULL) {
    ;
  } else if (!strcmp(how, "nosyscall")) {
    break_strongest_rng_syscall = 1;
  } else if (!strcmp(how, "nofallback")) {
    break_strongest_rng_fallback = 1;
  } else if (!strcmp(how, "broken")) {
    broken = break_strongest_rng_syscall = break_strongest_rng_fallback = 1;
  }

#define N 128
  uint8_t combine_and[N];
  uint8_t combine_or[N];
  int i, j;

  memset(combine_and, 0xff, N);
  memset(combine_or, 0, N);

  for (i = 0; i < 100; ++i) { /* 2^-100 chances just don't happen. */
    uint8_t output[N];
    memset(output, 0, N);
    if (how == NULL) {
      /* this one can't fail. */
      crypto_strongest_rand(output, sizeof(output));
    } else {
      int r = crypto_strongest_rand_raw(output, sizeof(output));
      if (r == -1) {
        if (broken) {
          goto done; /* we're fine. */
        }
        /* This function is allowed to break, but only if it always breaks. */
        tt_int_op(i, OP_EQ, 0);
        tt_skip();
      } else {
        tt_assert(! broken);
      }
    }
    for (j = 0; j < N; ++j) {
      combine_and[j] &= output[j];
      combine_or[j] |= output[j];
    }
  }

  for (j = 0; j < N; ++j) {
    tt_int_op(combine_and[j], OP_EQ, 0);
    tt_int_op(combine_or[j], OP_EQ, 0xff);
  }
 done:
  ;
#undef N
}

struct testcase_t crypto_rng_tests[] = {
  { "rng", test_crypto_rng, 0, NULL, NULL },
  { "rng_range", test_crypto_rng_range, 0, NULL, NULL },
  { "rng_strongest", test_crypto_rng_strongest, TT_FORK, NULL, NULL },
  { "rng_strongest_nosyscall", test_crypto_rng_strongest, TT_FORK,
    &passthrough_setup, (void*)"nosyscall" },
  { "rng_strongest_nofallback", test_crypto_rng_strongest, TT_FORK,
    &passthrough_setup, (void*)"nofallback" },
  { "rng_strongest_broken", test_crypto_rng_strongest, TT_FORK,
    &passthrough_setup, (void*)"broken" },
  END_OF_TESTCASES
};
