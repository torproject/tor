/* Copyright (c) 2017, The Tor Project, Inc. */
/* Copyright (c) 2017, isis agora lovecruft  */
/* See LICENSE for licensing information     */

/**
 * \file test_router.c
 * \brief Unittests for code in src/or/router.c
 **/

#include "or.h"
#include "config.h"
#include "crypto_curve25519.h"
#include "crypto_ed25519.h"
#include "router.h"
#include "routerlist.h"

/* Test suite stuff */
#include "test.h"

NS_DECL(const routerinfo_t *, router_get_my_routerinfo, (void));

static routerinfo_t* mock_routerinfo;

static const routerinfo_t*
NS(router_get_my_routerinfo)(void)
{
  crypto_pk_t* ident_key;
  crypto_pk_t* tap_key;
  time_t now;

  if (!mock_routerinfo) {
    /* Mock the published timestamp, otherwise router_dump_router_to_string()
     * will poop its pants. */
    time(&now);

    /* We'll need keys, or router_dump_router_to_string() would return NULL. */
    ident_key = pk_generate(0);
    tap_key = pk_generate(0);

    tor_assert(ident_key != NULL);
    tor_assert(tap_key != NULL);

    mock_routerinfo = tor_malloc_zero(sizeof(routerinfo_t));
    mock_routerinfo->nickname = tor_strdup("ConlonNancarrow");
    mock_routerinfo->addr = 123456789;
    mock_routerinfo->or_port = 443;
    mock_routerinfo->platform = tor_strdup("unittest");
    mock_routerinfo->cache_info.published_on = now;
    mock_routerinfo->identity_pkey = crypto_pk_dup_key(ident_key);
    mock_routerinfo->onion_pkey = crypto_pk_dup_key(tap_key);
    mock_routerinfo->bandwidthrate = 9001;
    mock_routerinfo->bandwidthburst = 9002;
  }

  return mock_routerinfo;
}

/* If no distribution option was set, then check_bridge_distribution_setting()
 * should have set it to "any". */
static void
test_router_dump_router_to_string_no_bridge_distribution_method(void *arg)
{
  const char* needle = "bridge-distribution-request any";
  or_options_t* options = get_options_mutable();
  routerinfo_t* router = NULL;
  curve25519_keypair_t ntor_keypair;
  ed25519_keypair_t signing_keypair;
  char* desc = NULL;
  char* found = NULL;
  (void)arg;

  NS_MOCK(router_get_my_routerinfo);

  options->ORPort_set = 1;
  options->BridgeRelay = 1;

  /* Generate keys which router_dump_router_to_string() expects to exist. */
  tt_int_op(0, ==, curve25519_keypair_generate(&ntor_keypair, 0));
  tt_int_op(0, ==, ed25519_keypair_generate(&signing_keypair, 0));

  /* Set up part of our routerinfo_t so that we don't trigger any other
   * assertions in router_dump_router_to_string(). */
  router = (routerinfo_t*)router_get_my_routerinfo();
  tt_ptr_op(router, !=, NULL);

  router->onion_curve25519_pkey = &ntor_keypair.pubkey;

  /* Generate our server descriptor and ensure that the substring
   * "bridge-distribution-request any" occurs somewhere within it. */
  desc = router_dump_router_to_string(router,
                                      router->identity_pkey,
                                      router->onion_pkey,
                                      &ntor_keypair,
                                      &signing_keypair);
  tt_ptr_op(desc, !=, NULL);
  found = strstr(desc, needle);
  tt_ptr_op(found, !=, NULL);

 done:
  NS_UNMOCK(router_get_my_routerinfo);

  tor_free(desc);
}

#define ROUTER_TEST(name, flags)                          \
  { #name, test_router_ ## name, flags, NULL, NULL }

struct testcase_t router_tests[] = {
  ROUTER_TEST(dump_router_to_string_no_bridge_distribution_method, TT_FORK),
  END_OF_TESTCASES
};

