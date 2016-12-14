/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_service.c
 * \brief Test hidden service functionality.
 */

#define HS_SERVICE_PRIVATE
#define HS_INTROPOINT_PRIVATE

#include "test.h"
#include "log_test_helpers.h"
#include "crypto.h"

#include "hs/cell_establish_intro.h"
#include "hs_service.h"
#include "hs_intropoint.h"

/** We simulate the creation of an outgoing ESTABLISH_INTRO cell, and then we
 *  parse it from the receiver side. */
static void
test_gen_establish_intro_cell(void *arg)
{
  (void) arg;
  ssize_t retval;
  uint8_t circuit_key_material[DIGEST_LEN] = {0};
  uint8_t buf[RELAY_PAYLOAD_SIZE];
  hs_cell_establish_intro_t *cell_out = NULL;
  hs_cell_establish_intro_t *cell_in = NULL;

  crypto_rand((char *) circuit_key_material, sizeof(circuit_key_material));

  /* Create outgoing ESTABLISH_INTRO cell and extract its payload so that we
     attempt to parse it. */
  {
    cell_out = generate_establish_intro_cell(circuit_key_material,
                                             sizeof(circuit_key_material));
    tt_assert(cell_out);

    retval = get_establish_intro_payload(buf, sizeof(buf), cell_out);
    tt_int_op(retval, >=, 0);
  }

  /* Parse it as the receiver */
  {
    ssize_t parse_result = hs_cell_establish_intro_parse(&cell_in,
                                                         buf, sizeof(buf));
    tt_int_op(parse_result, >=, 0);

    retval = verify_establish_intro_cell(cell_in,
                                         circuit_key_material,
                                         sizeof(circuit_key_material));
    tt_int_op(retval, >=, 0);
  }

 done:
  hs_cell_establish_intro_free(cell_out);
  hs_cell_establish_intro_free(cell_in);
}

/* Mocked ed25519_sign_prefixed() function that always fails :) */
static int
mock_ed25519_sign_prefixed(ed25519_signature_t *signature_out,
                           const uint8_t *msg, size_t msg_len,
                           const char *prefix_str,
                           const ed25519_keypair_t *keypair) {
  (void) signature_out;
  (void) msg;
  (void) msg_len;
  (void) prefix_str;
  (void) keypair;
  return -1;
}

/** We simulate a failure to create an ESTABLISH_INTRO cell */
static void
test_gen_establish_intro_cell_bad(void *arg)
{
  (void) arg;
  hs_cell_establish_intro_t *cell = NULL;
  uint8_t circuit_key_material[DIGEST_LEN] = {0};

  MOCK(ed25519_sign_prefixed, mock_ed25519_sign_prefixed);

  crypto_rand((char *) circuit_key_material, sizeof(circuit_key_material));

  setup_full_capture_of_logs(LOG_WARN);
  /* Easiest way to make that function fail is to mock the
     ed25519_sign_prefixed() function and make it fail. */
  cell = generate_establish_intro_cell(circuit_key_material,
                                       sizeof(circuit_key_material));
  expect_log_msg_containing("Unable to gen signature for "
                            "ESTABLISH_INTRO cell.");
  teardown_capture_of_logs();
  tt_assert(!cell);

 done:
  hs_cell_establish_intro_free(cell);
  UNMOCK(ed25519_sign_prefixed);
}

struct testcase_t hs_service_tests[] = {
  { "gen_establish_intro_cell", test_gen_establish_intro_cell, TT_FORK,
    NULL, NULL },
  { "gen_establish_intro_cell_bad", test_gen_establish_intro_cell_bad, TT_FORK,
    NULL, NULL },

  END_OF_TESTCASES
};

