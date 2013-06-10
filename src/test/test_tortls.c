/* Copyright (c) 2013-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include <openssl/evp.h>

#include "orconfig.h"
#define CRYPTO_PRIVATE
#define TORTLS_PRIVATE
#include "or.h"
#include "test.h"


static void
test_tortls_evp_pkey_eq(void)
{
  crypto_pk_t *pk1 = NULL, *pk2 = NULL;
  EVP_PKEY *evp1 = NULL, *evp2 = NULL;

  pk1 = pk_generate(0);
  pk2 = pk_generate(1);
  test_assert(pk1 && pk2);

  evp1 = crypto_pk_get_evp_pkey_(pk1, 0);
  evp2 = crypto_pk_get_evp_pkey_(pk2, 0);
  test_assert(evp1 && evp2);

  test_assert(tor_tls_evp_pkey_eq(evp1, evp2) == 0);
  test_assert(tor_tls_evp_pkey_eq(evp1, evp1) == 1);

done:
  crypto_pk_free(pk1);
  crypto_pk_free(pk2);
  if (evp1)
    EVP_PKEY_free(evp1);
  if (evp2)
    EVP_PKEY_free(evp2);
}

#define TORTLS_LEGACY(name) \
  { #name, legacy_test_helper, 0, &legacy_setup, test_tortls_ ## name }

struct testcase_t tortls_tests[] = {
  TORTLS_LEGACY(evp_pkey_eq),
  END_OF_TESTCASES
};
