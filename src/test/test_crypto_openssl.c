/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"

#define CRYPTO_PRIVATE

#include "crypto.h"
#include "test.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include "compat_openssl.h"

/* Test for rectifying openssl RAND engine. */
static void
test_crypto_rng_engine(void *arg)
{
  (void)arg;
  RAND_METHOD dummy_method;
  memset(&dummy_method, 0, sizeof(dummy_method));

  /* We should be a no-op if we're already on RAND_OpenSSL */
  tt_int_op(0, ==, crypto_force_rand_ssleay());
  tt_assert(RAND_get_rand_method() == RAND_OpenSSL());

  /* We should correct the method if it's a dummy. */
  RAND_set_rand_method(&dummy_method);
#ifdef LIBRESSL_VERSION_NUMBER
  /* On libressl, you can't override the RNG. */
  tt_assert(RAND_get_rand_method() == RAND_OpenSSL());
  tt_int_op(0, ==, crypto_force_rand_ssleay());
#else
  tt_assert(RAND_get_rand_method() == &dummy_method);
  tt_int_op(1, ==, crypto_force_rand_ssleay());
#endif
  tt_assert(RAND_get_rand_method() == RAND_OpenSSL());

  /* Make sure we aren't calling dummy_method */
  crypto_rand((void *) &dummy_method, sizeof(dummy_method));
  crypto_rand((void *) &dummy_method, sizeof(dummy_method));

 done:
  ;
}

struct testcase_t crypto_openssl_tests[] = {
  { "rng_engine", test_crypto_rng_engine, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};
