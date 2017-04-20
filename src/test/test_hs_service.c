/* Copyright (c) 2016-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_service.c
 * \brief Test hidden service functionality.
 */

#define CIRCUITBUILD_PRIVATE
#define CIRCUITLIST_PRIVATE
#define CONFIG_PRIVATE
#define CONNECTION_PRIVATE
#define CRYPTO_PRIVATE
#define HS_COMMON_PRIVATE
#define HS_SERVICE_PRIVATE
#define HS_INTROPOINT_PRIVATE
#define MAIN_PRIVATE
#define TOR_CHANNEL_INTERNAL_

#include "test.h"
#include "test_helpers.h"
#include "log_test_helpers.h"
#include "rend_test_helpers.h"

#include "or.h"
#include "channeltls.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "config.h"
#include "connection.h"
#include "crypto.h"
#include "hs_circuit.h"
#include "hs_common.h"
#include "hs_config.h"
#include "hs_ident.h"
#include "hs_intropoint.h"
#include "hs_ntor.h"
#include "hs_service.h"
#include "main.h"
#include "rendservice.h"

/* Trunnel */
#include "hs/cell_establish_intro.h"

/* Helper: from a set of options in conf, configure a service which will add
 * it to the staging list of the HS subsytem. */
static int
helper_config_service(const char *conf)
{
  int ret = 0;
  or_options_t *options = NULL;
  tt_assert(conf);
  options = helper_parse_options(conf);
  tt_assert(options);
  ret = hs_config_service_all(options, 0);
 done:
  or_options_free(options);
  return ret;
}

/** Test the HS ntor handshake. Simulate the sending of an encrypted INTRODUCE1
 *  cell, and verify the proper derivation of decryption keys on the other end.
 *  Then simulate the sending of an authenticated RENDEZVOUS1 cell and verify
 *  the proper verification on the other end. */
static void
test_hs_ntor(void *arg)
{
  int retval;

  uint8_t subcredential[DIGEST256_LEN];

  ed25519_keypair_t service_intro_auth_keypair;
  curve25519_keypair_t service_intro_enc_keypair;
  curve25519_keypair_t service_ephemeral_rend_keypair;

  curve25519_keypair_t client_ephemeral_enc_keypair;

  hs_ntor_intro_cell_keys_t client_hs_ntor_intro_cell_keys;
  hs_ntor_intro_cell_keys_t service_hs_ntor_intro_cell_keys;

  hs_ntor_rend_cell_keys_t service_hs_ntor_rend_cell_keys;
  hs_ntor_rend_cell_keys_t client_hs_ntor_rend_cell_keys;

  (void) arg;

  /* Generate fake data for this unittest */
  {
    /* Generate fake subcredential */
    memset(subcredential, 'Z', DIGEST256_LEN);

    /* service */
    curve25519_keypair_generate(&service_intro_enc_keypair, 0);
    ed25519_keypair_generate(&service_intro_auth_keypair, 0);
    curve25519_keypair_generate(&service_ephemeral_rend_keypair, 0);
    /* client */
    curve25519_keypair_generate(&client_ephemeral_enc_keypair, 0);
  }

  /* Client: Simulate the sending of an encrypted INTRODUCE1 cell */
  retval =
    hs_ntor_client_get_introduce1_keys(&service_intro_auth_keypair.pubkey,
                                       &service_intro_enc_keypair.pubkey,
                                       &client_ephemeral_enc_keypair,
                                       subcredential,
                                       &client_hs_ntor_intro_cell_keys);
  tt_int_op(retval, ==, 0);

  /* Service: Simulate the decryption of the received INTRODUCE1 */
  retval =
    hs_ntor_service_get_introduce1_keys(&service_intro_auth_keypair.pubkey,
                                        &service_intro_enc_keypair,
                                        &client_ephemeral_enc_keypair.pubkey,
                                        subcredential,
                                        &service_hs_ntor_intro_cell_keys);
  tt_int_op(retval, ==, 0);

  /* Test that the INTRODUCE1 encryption/mac keys match! */
  tt_mem_op(client_hs_ntor_intro_cell_keys.enc_key, OP_EQ,
            service_hs_ntor_intro_cell_keys.enc_key,
            CIPHER256_KEY_LEN);
  tt_mem_op(client_hs_ntor_intro_cell_keys.mac_key, OP_EQ,
            service_hs_ntor_intro_cell_keys.mac_key,
            DIGEST256_LEN);

  /* Service: Simulate creation of RENDEZVOUS1 key material. */
  retval =
    hs_ntor_service_get_rendezvous1_keys(&service_intro_auth_keypair.pubkey,
                                         &service_intro_enc_keypair,
                                         &service_ephemeral_rend_keypair,
                                         &client_ephemeral_enc_keypair.pubkey,
                                         &service_hs_ntor_rend_cell_keys);
  tt_int_op(retval, ==, 0);

  /* Client: Simulate the verification of a received RENDEZVOUS1 cell */
  retval =
    hs_ntor_client_get_rendezvous1_keys(&service_intro_auth_keypair.pubkey,
                                        &client_ephemeral_enc_keypair,
                                        &service_intro_enc_keypair.pubkey,
                                        &service_ephemeral_rend_keypair.pubkey,
                                        &client_hs_ntor_rend_cell_keys);
  tt_int_op(retval, ==, 0);

  /* Test that the RENDEZVOUS1 key material match! */
  tt_mem_op(client_hs_ntor_rend_cell_keys.rend_cell_auth_mac, OP_EQ,
            service_hs_ntor_rend_cell_keys.rend_cell_auth_mac,
            DIGEST256_LEN);
  tt_mem_op(client_hs_ntor_rend_cell_keys.ntor_key_seed, OP_EQ,
            service_hs_ntor_rend_cell_keys.ntor_key_seed,
            DIGEST256_LEN);
 done:
  ;
}

static void
test_validate_address(void *arg)
{
  int ret;

  (void) arg;

  /* Address too short and too long. */
  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_address_is_valid("blah");
  tt_int_op(ret, OP_EQ, 0);
  expect_log_msg_containing("has an invalid length");
  teardown_capture_of_logs();

  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_address_is_valid(
           "p3xnclpu4mu22dwaurjtsybyqk4xfjmcfz6z62yl24uwmhjatiwnlnadb");
  tt_int_op(ret, OP_EQ, 0);
  expect_log_msg_containing("has an invalid length");
  teardown_capture_of_logs();

  /* Invalid checksum (taken from prop224) */
  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_address_is_valid(
           "l5satjgud6gucryazcyvyvhuxhr74u6ygigiuyixe3a6ysis67ororad");
  tt_int_op(ret, OP_EQ, 0);
  expect_log_msg_containing("invalid checksum");
  teardown_capture_of_logs();

  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_address_is_valid(
           "btojiu7nu5y5iwut64eufevogqdw4wmqzugnoluw232r4t3ecsfv37ad");
  tt_int_op(ret, OP_EQ, 0);
  expect_log_msg_containing("invalid checksum");
  teardown_capture_of_logs();

  /* Non base32 decodable string. */
  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_address_is_valid(
           "????????????????????????????????????????????????????????");
  tt_int_op(ret, OP_EQ, 0);
  expect_log_msg_containing("can't be decoded");
  teardown_capture_of_logs();

  /* Valid address. */
  ret = hs_address_is_valid(
           "p3xnclpu4mu22dwaurjtsybyqk4xfjmcfz6z62yl24uwmhjatiwnlnad");
  tt_int_op(ret, OP_EQ, 1);

 done:
  ;
}

static void
test_build_address(void *arg)
{
  int ret;
  char onion_addr[HS_SERVICE_ADDR_LEN_BASE32 + 1];
  ed25519_public_key_t pubkey;

  (void) arg;

  /* The following has been created with hs_build_address.py script that
   * follows proposal 224 specification to build an onion address. */
  static const char *test_addr =
    "ijbeeqscijbeeqscijbeeqscijbeeqscijbeeqscijbeeqscijbezhid";

  /* Let's try to build the same onion address that the script can do. Key is
   * a long set of very random \x42 :). */
  memset(&pubkey, '\x42', sizeof(pubkey));
  hs_build_address(&pubkey, HS_VERSION_THREE, onion_addr);
  tt_str_op(test_addr, OP_EQ, onion_addr);
  /* Validate that address. */
  ret = hs_address_is_valid(onion_addr);
  tt_int_op(ret, OP_EQ, 1);

 done:
  ;
}

/** Test that our HS time period calculation functions work properly */
static void
test_time_period(void *arg)
{
  (void) arg;
  uint64_t tn;
  int retval;
  time_t fake_time;

  /* Let's do the example in prop224 section [TIME-PERIODS] */
  retval = parse_rfc1123_time("Wed, 13 Apr 2016 11:00:00 UTC",
                              &fake_time);
  tt_int_op(retval, ==, 0);

  /* Check that the time period number is right */
  tn = hs_get_time_period_num(fake_time);
  tt_u64_op(tn, ==, 16903);

  /* Increase current time to 11:59:59 UTC and check that the time period
     number is still the same */
  fake_time += 3599;
  tn = hs_get_time_period_num(fake_time);
  tt_u64_op(tn, ==, 16903);

  /* Now take time to 12:00:00 UTC and check that the time period rotated */
  fake_time += 1;
  tn = hs_get_time_period_num(fake_time);
  tt_u64_op(tn, ==, 16904);

  /* Now also check our hs_get_next_time_period_num() function */
  tn = hs_get_next_time_period_num(fake_time);
  tt_u64_op(tn, ==, 16905);

 done:
  ;
}

/* Test: Ensure that setting up rendezvous circuits works correctly. */
static void
test_e2e_rend_circuit_setup(void *arg)
{
  ed25519_public_key_t service_pk;
  origin_circuit_t *or_circ;
  int retval;

  /** In this test we create a v3 prop224 service-side rendezvous circuit.
   *  We simulate an HS ntor key exchange with a client, and check that
   *  the circuit was setup correctly and is ready to accept rendezvous data */

  (void) arg;

  /* Now make dummy circuit */
  {
    or_circ = origin_circuit_new();

    or_circ->base_.purpose = CIRCUIT_PURPOSE_S_CONNECT_REND;

    or_circ->build_state = tor_malloc_zero(sizeof(cpath_build_state_t));
    or_circ->build_state->is_internal = 1;

    /* prop224: Setup hs conn identifier on the stream */
    ed25519_secret_key_t sk;
    tt_int_op(0, OP_EQ, ed25519_secret_key_generate(&sk, 0));
    tt_int_op(0, OP_EQ, ed25519_public_key_generate(&service_pk, &sk));

    or_circ->hs_ident = hs_ident_circuit_new(&service_pk,
                                             HS_IDENT_CIRCUIT_RENDEZVOUS);

    TO_CIRCUIT(or_circ)->state = CIRCUIT_STATE_OPEN;
  }

  /* Check number of hops */
  retval = cpath_get_n_hops(&or_circ->cpath);
  tt_int_op(retval, OP_EQ, 0);

  /* Setup the circuit: do the ntor key exchange */
  {
    uint8_t ntor_key_seed[DIGEST256_LEN] = {2};
    retval = hs_circuit_setup_e2e_rend_circ(or_circ,
                                       ntor_key_seed, sizeof(ntor_key_seed),
                                       1);
    tt_int_op(retval, OP_EQ, 0);
  }

  /* See that a hop was added to the circuit's cpath */
  retval = cpath_get_n_hops(&or_circ->cpath);
  tt_int_op(retval, OP_EQ, 1);

  /* Check the digest algo */
  tt_int_op(crypto_digest_get_algorithm(or_circ->cpath->f_digest),
            OP_EQ, DIGEST_SHA3_256);
  tt_int_op(crypto_digest_get_algorithm(or_circ->cpath->b_digest),
            OP_EQ, DIGEST_SHA3_256);
  tt_assert(or_circ->cpath->f_crypto);
  tt_assert(or_circ->cpath->b_crypto);

  /* Ensure that circ purpose was changed */
  tt_int_op(or_circ->base_.purpose, OP_EQ, CIRCUIT_PURPOSE_S_REND_JOINED);

 done:
  circuit_free(TO_CIRCUIT(or_circ));
}

static void
test_load_keys(void *arg)
{
  int ret;
  char *conf = NULL;
  char *hsdir_v2 = tor_strdup(get_fname("hs2"));
  char *hsdir_v3 = tor_strdup(get_fname("hs3"));
  char addr[HS_SERVICE_ADDR_LEN_BASE32 + 1];

  (void) arg;

  /* We'll register two services, a v2 and a v3, then we'll load keys and
   * validate that both are in a correct state. */

  hs_init();

#define conf_fmt \
  "HiddenServiceDir %s\n" \
  "HiddenServiceVersion %d\n" \
  "HiddenServicePort 65535\n"

  /* v2 service. */
  tor_asprintf(&conf, conf_fmt, hsdir_v2, HS_VERSION_TWO);
  ret = helper_config_service(conf);
  tor_free(conf);
  tt_int_op(ret, OP_EQ, 0);
  /* This one should now be registered into the v2 list. */
  tt_int_op(get_hs_service_staging_list_size(), OP_EQ, 0);
  tt_int_op(num_rend_services(), OP_EQ, 1);

  /* v3 service. */
  tor_asprintf(&conf, conf_fmt, hsdir_v3, HS_VERSION_THREE);
  ret = helper_config_service(conf);
  tor_free(conf);
  tt_int_op(ret, OP_EQ, 0);
  /* It's in staging? */
  tt_int_op(get_hs_service_staging_list_size(), OP_EQ, 1);

  /* Load the keys for these. After that, the v3 service should be registered
   * in the global map. */
  hs_service_load_all_keys();
  tt_int_op(get_hs_service_map_size(), OP_EQ, 1);
  hs_service_t *s = get_first_service();
  tt_assert(s);

  /* Ok we have the service object. Validate few things. */
  tt_assert(!tor_mem_is_zero(s->onion_address, sizeof(s->onion_address)));
  tt_int_op(hs_address_is_valid(s->onion_address), OP_EQ, 1);
  tt_assert(!tor_mem_is_zero((char *) s->keys.identity_sk.seckey,
                             ED25519_SECKEY_LEN));
  tt_assert(!tor_mem_is_zero((char *) s->keys.identity_pk.pubkey,
                             ED25519_PUBKEY_LEN));
  /* Check onion address from identity key. */
  hs_build_address(&s->keys.identity_pk, s->config.version, addr);
  tt_int_op(hs_address_is_valid(addr), OP_EQ, 1);
  tt_str_op(addr, OP_EQ, s->onion_address);

 done:
  tor_free(hsdir_v2);
  tor_free(hsdir_v3);
  hs_free_all();
}

static void
test_access_service(void *arg)
{
  int ret;
  char *conf = NULL;
  char *hsdir_v3 = tor_strdup(get_fname("hs3"));
  hs_service_ht *global_map;
  hs_service_t *s = NULL;

  (void) arg;

  /* We'll register two services, a v2 and a v3, then we'll load keys and
   * validate that both are in a correct state. */

  hs_init();

#define conf_fmt \
  "HiddenServiceDir %s\n" \
  "HiddenServiceVersion %d\n" \
  "HiddenServicePort 65535\n"

  /* v3 service. */
  tor_asprintf(&conf, conf_fmt, hsdir_v3, HS_VERSION_THREE);
  ret = helper_config_service(conf);
  tor_free(conf);
  tt_int_op(ret, OP_EQ, 0);
  /* It's in staging? */
  tt_int_op(get_hs_service_staging_list_size(), OP_EQ, 1);

  /* Load the keys for these. After that, the v3 service should be registered
   * in the global map. */
  hs_service_load_all_keys();
  tt_int_op(get_hs_service_map_size(), OP_EQ, 1);
  s = get_first_service();
  tt_assert(s);
  global_map = get_hs_service_map();
  tt_assert(global_map);

  /* From here, we'll try the service accessors. */
  hs_service_t *query = find_service(global_map, &s->keys.identity_pk);
  tt_assert(query);
  tt_mem_op(query, OP_EQ, s, sizeof(hs_service_t));
  /* Remove service, check if it actually works and then put it back. */
  remove_service(global_map, s);
  tt_int_op(get_hs_service_map_size(), OP_EQ, 0);
  query = find_service(global_map, &s->keys.identity_pk);
  tt_assert(!query);

  /* Register back the service in the map. */
  ret = register_service(global_map, s);
  tt_int_op(ret, OP_EQ, 0);
  tt_int_op(get_hs_service_map_size(), OP_EQ, 1);
  /* Twice should fail. */
  ret = register_service(global_map, s);
  tt_int_op(ret, OP_EQ, -1);
  /* Remove service from map so we don't double free on cleanup. */
  remove_service(global_map, s);
  tt_int_op(get_hs_service_map_size(), OP_EQ, 0);
  query = find_service(global_map, &s->keys.identity_pk);
  tt_assert(!query);
  /* Let's try to remove twice for fun. */
  setup_full_capture_of_logs(LOG_WARN);
  remove_service(global_map, s);
  expect_log_msg_containing("Could not find service in the global map");
  teardown_capture_of_logs();

 done:
  hs_service_free(s);
  tor_free(hsdir_v3);
  hs_free_all();
}

/** Test that our HS overlap period functions work properly. */
static void
test_desc_overlap_period(void *arg)
{
  (void) arg;
  int retval;
  time_t now = time(NULL);
  networkstatus_t *dummy_consensus = NULL;

  /* First try with a consensus inside the overlap period */
  dummy_consensus = tor_malloc_zero(sizeof(networkstatus_t));
  retval = parse_rfc1123_time("Wed, 13 Apr 2016 10:00:00 UTC",
                              &dummy_consensus->valid_after);
  tt_int_op(retval, ==, 0);

  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, ==, 1);

  /* Now increase the valid_after so that it goes to 11:00:00 UTC. Overlap
     period is still active. */
  dummy_consensus->valid_after += 3600;
  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, ==, 1);

  /* Now increase the valid_after so that it goes to 11:59:59 UTC. Overlap
     period is still active. */
  dummy_consensus->valid_after += 3599;
  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, ==, 1);

  /* Now increase the valid_after so that it drifts to noon, and check that
     overlap mode is not active anymore. */
  dummy_consensus->valid_after += 1;
  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, ==, 0);

  /* Check that overlap mode is also inactive at 23:59:59 UTC */
  retval = parse_rfc1123_time("Wed, 13 Apr 2016 23:59:59 UTC",
                              &dummy_consensus->valid_after);
  tt_int_op(retval, ==, 0);
  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, ==, 0);

 done:
  tor_free(dummy_consensus);
}

struct testcase_t hs_service_tests[] = {
  { "hs_ntor", test_hs_ntor, TT_FORK,
    NULL, NULL },
  { "time_period", test_time_period, TT_FORK,
    NULL, NULL },
  { "e2e_rend_circuit_setup", test_e2e_rend_circuit_setup, TT_FORK,
    NULL, NULL },
  { "build_address", test_build_address, TT_FORK,
    NULL, NULL },
  { "validate_address", test_validate_address, TT_FORK,
    NULL, NULL },
  { "load_keys", test_load_keys, TT_FORK,
    NULL, NULL },
  { "access_service", test_access_service, TT_FORK,
    NULL, NULL },
  { "desc_overlap_period", test_desc_overlap_period, TT_FORK,
    NULL, NULL },

  END_OF_TESTCASES
};

