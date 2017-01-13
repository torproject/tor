/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_service.c
 * \brief Test hidden service functionality.
 */

#define HS_SERVICE_PRIVATE
#define HS_INTROPOINT_PRIVATE
#define RENDSERVICE_PRIVATE
#define CIRCUITLIST_PRIVATE

#include "test.h"
#include "log_test_helpers.h"
#include "crypto.h"

#include "or.h"
#include "ht.h"

#include "hs/cell_establish_intro.h"
#include "hs_common.h"
#include "hs_service.h"
#include "hs_circuitmap.h"
#include "hs_intropoint.h"

#include "circuitlist.h"
#include "circuituse.h"
#include "rendservice.h"

/* Mock function to avoid networking in unittests */
static int
mock_send_intro_established_cell(or_circuit_t *circ)
{
  (void) circ;
  return 0;
}

/* Try sending an ESTABLISH_INTRO cell on a circuit that is already an intro
 * point. Should fail. */
static void
test_establish_intro_wrong_purpose(void *arg)
{
  int retval;
  hs_cell_establish_intro_t *establish_intro_cell = NULL;
  or_circuit_t *intro_circ = or_circuit_new(0,NULL);;
  uint8_t cell_body[RELAY_PAYLOAD_SIZE];
  ssize_t cell_len = 0;
  uint8_t circuit_key_material[DIGEST_LEN] = {0};

  (void)arg;

  /* Get the auth key of the intro point */
  crypto_rand((char *) circuit_key_material, sizeof(circuit_key_material));
  memcpy(intro_circ->rend_circ_nonce, circuit_key_material, DIGEST_LEN);

  /* Set a bad circuit purpose!! :) */
  circuit_change_purpose(TO_CIRCUIT(intro_circ), CIRCUIT_PURPOSE_INTRO_POINT);

  /* Create outgoing ESTABLISH_INTRO cell and extract its payload so that we
     attempt to parse it. */
  establish_intro_cell = generate_establish_intro_cell(circuit_key_material,
                                           sizeof(circuit_key_material));
  tt_assert(establish_intro_cell);
  cell_len = get_establish_intro_payload(cell_body, sizeof(cell_body),
                                         establish_intro_cell);
  tt_int_op(cell_len, >, 0);

  /* Receive the cell */
  retval = hs_intro_received_establish_intro(intro_circ, cell_body, cell_len);
  tt_int_op(retval, ==, -1);

 done:
  hs_cell_establish_intro_free(establish_intro_cell);
  circuit_free(TO_CIRCUIT(intro_circ));
}

/* Prepare a circuit for accepting an ESTABLISH_INTRO cell */
static void
helper_prepare_circ_for_intro(or_circuit_t *circ,
                              uint8_t *circuit_key_material)
{
  /* Prepare the circuit for the incoming ESTABLISH_INTRO */
  circuit_change_purpose(TO_CIRCUIT(circ), CIRCUIT_PURPOSE_OR);
  memcpy(circ->rend_circ_nonce, circuit_key_material, DIGEST_LEN);
}

/* Send an empty ESTABLISH_INTRO cell. Should fail. */
static void
test_establish_intro_wrong_keytype(void *arg)
{
  int retval;
  or_circuit_t *intro_circ = or_circuit_new(0,NULL);;
  uint8_t circuit_key_material[DIGEST_LEN] = {0};

  (void)arg;

  /* Get the auth key of the intro point */
  crypto_rand((char *) circuit_key_material, sizeof(circuit_key_material));
  helper_prepare_circ_for_intro(intro_circ, circuit_key_material);

  /* Receive the cell. Should fail. */
  retval = hs_intro_received_establish_intro(intro_circ, (uint8_t*)"", 0);
  tt_int_op(retval, ==, -1);

 done:
  circuit_free(TO_CIRCUIT(intro_circ));
}

/* Send an ESTABLISH_INTRO cell with an unknown auth key type. Should fail. */
static void
test_establish_intro_wrong_keytype2(void *arg)
{
  int retval;
  hs_cell_establish_intro_t *establish_intro_cell = NULL;
  or_circuit_t *intro_circ = or_circuit_new(0,NULL);;
  uint8_t cell_body[RELAY_PAYLOAD_SIZE];
  ssize_t cell_len = 0;
  uint8_t circuit_key_material[DIGEST_LEN] = {0};

  (void)arg;

  /* Get the auth key of the intro point */
  crypto_rand((char *) circuit_key_material, sizeof(circuit_key_material));
  helper_prepare_circ_for_intro(intro_circ, circuit_key_material);

  /* Create outgoing ESTABLISH_INTRO cell and extract its payload so that we
     attempt to parse it. */
  establish_intro_cell = generate_establish_intro_cell(circuit_key_material,
                                           sizeof(circuit_key_material));
  tt_assert(establish_intro_cell);
  cell_len = get_establish_intro_payload(cell_body, sizeof(cell_body),
                                         establish_intro_cell);
  tt_int_op(cell_len, >, 0);

  /* Mutate the auth key type! :) */
  cell_body[0] = 42;

  /* Receive the cell. Should fail. */
  retval = hs_intro_received_establish_intro(intro_circ, cell_body, cell_len);
  tt_int_op(retval, ==, -1);

 done:
  hs_cell_establish_intro_free(establish_intro_cell);
  circuit_free(TO_CIRCUIT(intro_circ));
}

/* Send a legit ESTABLISH_INTRO cell but with a wrong MAC. Should fail. */
static void
test_establish_intro_wrong_mac(void *arg)
{
  int retval;
  hs_cell_establish_intro_t *establish_intro_cell = NULL;
  or_circuit_t *intro_circ = or_circuit_new(0,NULL);;
  uint8_t cell_body[RELAY_PAYLOAD_SIZE];
  ssize_t cell_len = 0;
  uint8_t circuit_key_material[DIGEST_LEN] = {0};

  (void)arg;

  /* Get the auth key of the intro point */
  crypto_rand((char *) circuit_key_material, sizeof(circuit_key_material));
  helper_prepare_circ_for_intro(intro_circ, circuit_key_material);

  /* Create outgoing ESTABLISH_INTRO cell and extract its payload so that we
     attempt to parse it. */
  establish_intro_cell = generate_establish_intro_cell(circuit_key_material,
                                                       sizeof(circuit_key_material));
  tt_assert(establish_intro_cell);
  /* Mangle one byte of the MAC. */
  uint8_t *handshake_ptr =
    hs_cell_establish_intro_getarray_handshake_mac(establish_intro_cell);
  handshake_ptr[TRUNNEL_SHA3_256_LEN - 1]++;
  /* We need to resign the payload with that change. */
  {
    ed25519_signature_t sig;
    ed25519_keypair_t key_struct;
    /* New keypair for the signature since we don't have access to the private
     * key material generated earlier when creating the cell. */
    retval = ed25519_keypair_generate(&key_struct, 0);
    tt_int_op(retval, OP_EQ, 0);
    uint8_t *auth_key_ptr =
      hs_cell_establish_intro_getarray_auth_key(establish_intro_cell);
    memcpy(auth_key_ptr, key_struct.pubkey.pubkey, ED25519_PUBKEY_LEN);
    /* Encode payload so we can sign it. */
    cell_len = get_establish_intro_payload(cell_body, sizeof(cell_body),
                                           establish_intro_cell);
    tt_int_op(cell_len, >, 0);

    retval = ed25519_sign_prefixed(&sig, cell_body,
                                   cell_len -
                                   (ED25519_SIG_LEN +
                                    sizeof(establish_intro_cell->sig_len)),
                                   ESTABLISH_INTRO_SIG_PREFIX, &key_struct);
    tt_int_op(retval, OP_EQ, 0);
    /* And write the signature to the cell */
    uint8_t *sig_ptr =
      hs_cell_establish_intro_getarray_sig(establish_intro_cell);
    memcpy(sig_ptr, sig.sig, establish_intro_cell->sig_len);
    /* Re-encode with the new signature. */
    cell_len = get_establish_intro_payload(cell_body, sizeof(cell_body),
                                           establish_intro_cell);
  }

  /* Receive the cell. Should fail because our MAC is wrong. */
  setup_full_capture_of_logs(LOG_INFO);
  retval = hs_intro_received_establish_intro(intro_circ, cell_body, cell_len);
  expect_log_msg_containing("ESTABLISH_INTRO handshake_auth not as expected");
  teardown_capture_of_logs();
  tt_int_op(retval, ==, -1);

 done:
  hs_cell_establish_intro_free(establish_intro_cell);
  circuit_free(TO_CIRCUIT(intro_circ));
}

/* Send a legit ESTABLISH_INTRO cell but with a wrong auth key length. Should
 * fail. */
static void
test_establish_intro_wrong_auth_key_len(void *arg)
{
  int retval;
  hs_cell_establish_intro_t *establish_intro_cell = NULL;
  or_circuit_t *intro_circ = or_circuit_new(0,NULL);;
  uint8_t cell_body[RELAY_PAYLOAD_SIZE];
  ssize_t cell_len = 0;
  size_t bad_auth_key_len = ED25519_PUBKEY_LEN - 1;
  uint8_t circuit_key_material[DIGEST_LEN] = {0};

  (void)arg;

  /* Get the auth key of the intro point */
  crypto_rand((char *) circuit_key_material, sizeof(circuit_key_material));
  helper_prepare_circ_for_intro(intro_circ, circuit_key_material);

  /* Create outgoing ESTABLISH_INTRO cell and extract its payload so that we
     attempt to parse it. */
  establish_intro_cell = generate_establish_intro_cell(circuit_key_material,
                                                       sizeof(circuit_key_material));
  tt_assert(establish_intro_cell);
  /* Mangle the auth key length. */
  hs_cell_establish_intro_set_auth_key_len(establish_intro_cell,
                                           bad_auth_key_len);
  hs_cell_establish_intro_setlen_auth_key(establish_intro_cell,
                                          bad_auth_key_len);
  cell_len = get_establish_intro_payload(cell_body, sizeof(cell_body),
                                         establish_intro_cell);
  tt_int_op(cell_len, >, 0);

  /* Receive the cell. Should fail. */
  setup_full_capture_of_logs(LOG_INFO);
  retval = hs_intro_received_establish_intro(intro_circ, cell_body, cell_len);
  expect_log_msg_containing("ESTABLISH_INTRO auth key length is invalid");
  teardown_capture_of_logs();
  tt_int_op(retval, ==, -1);

 done:
  hs_cell_establish_intro_free(establish_intro_cell);
  circuit_free(TO_CIRCUIT(intro_circ));
}

/* Send a legit ESTABLISH_INTRO cell but with a wrong sig length. Should
 * fail. */
static void
test_establish_intro_wrong_sig_len(void *arg)
{
  int retval;
  hs_cell_establish_intro_t *establish_intro_cell = NULL;
  or_circuit_t *intro_circ = or_circuit_new(0,NULL);;
  uint8_t cell_body[RELAY_PAYLOAD_SIZE];
  ssize_t cell_len = 0;
  size_t bad_sig_len = ED25519_SIG_LEN - 1;
  uint8_t circuit_key_material[DIGEST_LEN] = {0};

  (void)arg;

  /* Get the auth key of the intro point */
  crypto_rand((char *) circuit_key_material, sizeof(circuit_key_material));
  helper_prepare_circ_for_intro(intro_circ, circuit_key_material);

  /* Create outgoing ESTABLISH_INTRO cell and extract its payload so that we
     attempt to parse it. */
  establish_intro_cell = generate_establish_intro_cell(circuit_key_material,
                                                       sizeof(circuit_key_material));
  tt_assert(establish_intro_cell);
  /* Mangle the signature length. */
  hs_cell_establish_intro_set_sig_len(establish_intro_cell, bad_sig_len);
  hs_cell_establish_intro_setlen_sig(establish_intro_cell, bad_sig_len);
  cell_len = get_establish_intro_payload(cell_body, sizeof(cell_body),
                                         establish_intro_cell);
  tt_int_op(cell_len, >, 0);

  /* Receive the cell. Should fail. */
  setup_full_capture_of_logs(LOG_INFO);
  retval = hs_intro_received_establish_intro(intro_circ, cell_body, cell_len);
  expect_log_msg_containing("ESTABLISH_INTRO sig len is invalid");
  teardown_capture_of_logs();
  tt_int_op(retval, ==, -1);

 done:
  hs_cell_establish_intro_free(establish_intro_cell);
  circuit_free(TO_CIRCUIT(intro_circ));
}

/* Send a legit ESTABLISH_INTRO cell but slightly change the signature. Should
 * fail. */
static void
test_establish_intro_wrong_sig(void *arg)
{
  int retval;
  hs_cell_establish_intro_t *establish_intro_cell = NULL;
  or_circuit_t *intro_circ = or_circuit_new(0,NULL);;
  uint8_t cell_body[RELAY_PAYLOAD_SIZE];
  ssize_t cell_len = 0;
  uint8_t circuit_key_material[DIGEST_LEN] = {0};

  (void)arg;

  /* Get the auth key of the intro point */
  crypto_rand((char *) circuit_key_material, sizeof(circuit_key_material));
  helper_prepare_circ_for_intro(intro_circ, circuit_key_material);

  /* Create outgoing ESTABLISH_INTRO cell and extract its payload so that we
     attempt to parse it. */
  establish_intro_cell = generate_establish_intro_cell(circuit_key_material,
                                           sizeof(circuit_key_material));
  tt_assert(establish_intro_cell);
  cell_len = get_establish_intro_payload(cell_body, sizeof(cell_body),
                                         establish_intro_cell);
  tt_int_op(cell_len, >, 0);

  /* Mutate the last byte (signature)! :) */
  cell_body[cell_len-1]++;

  /* Receive the cell. Should fail. */
  retval = hs_intro_received_establish_intro(intro_circ, cell_body, cell_len);
  tt_int_op(retval, ==, -1);

 done:
  hs_cell_establish_intro_free(establish_intro_cell);
  circuit_free(TO_CIRCUIT(intro_circ));
}

/* Helper function: Send a well-formed v3 ESTABLISH_INTRO cell to
 * <b>intro_circ</b>. Return the cell. */
static hs_cell_establish_intro_t *
helper_establish_intro_v3(or_circuit_t *intro_circ)
{
  int retval;
  hs_cell_establish_intro_t *establish_intro_cell = NULL;
  uint8_t cell_body[RELAY_PAYLOAD_SIZE];
  ssize_t cell_len = 0;
  uint8_t circuit_key_material[DIGEST_LEN] = {0};

  tt_assert(intro_circ);

  /* Prepare the circuit for the incoming ESTABLISH_INTRO */
  crypto_rand((char *) circuit_key_material, sizeof(circuit_key_material));
  helper_prepare_circ_for_intro(intro_circ, circuit_key_material);

  /* Create outgoing ESTABLISH_INTRO cell and extract its payload so that we
     attempt to parse it. */
  establish_intro_cell = generate_establish_intro_cell(circuit_key_material,
                                           sizeof(circuit_key_material));
  tt_assert(establish_intro_cell);
  cell_len = get_establish_intro_payload(cell_body, sizeof(cell_body),
                                         establish_intro_cell);
  tt_int_op(cell_len, >, 0);

  /* Receive the cell */
  retval = hs_intro_received_establish_intro(intro_circ, cell_body, cell_len);
  tt_int_op(retval, ==, 0);

 done:
  return establish_intro_cell;
}

/* Helper function: Send a well-formed v2 ESTABLISH_INTRO cell to
 * <b>intro_circ</b>. Return the public key advertised in the cell. */
static crypto_pk_t *
helper_establish_intro_v2(or_circuit_t *intro_circ)
{
  crypto_pk_t *key1 = NULL;
  int retval;
  uint8_t cell_body[RELAY_PAYLOAD_SIZE];
  ssize_t cell_len = 0;
  uint8_t circuit_key_material[DIGEST_LEN] = {0};

  tt_assert(intro_circ);

  /* Prepare the circuit for the incoming ESTABLISH_INTRO */
  crypto_rand((char *) circuit_key_material, sizeof(circuit_key_material));
  helper_prepare_circ_for_intro(intro_circ, circuit_key_material);

  /* Send legacy establish_intro */
  key1 = pk_generate(0);

  /* Use old circuit_key_material why not */
  cell_len = encode_establish_intro_cell_legacy((char*)cell_body,
                                                key1,
                                                (char *) circuit_key_material);
  tt_int_op(cell_len, >, 0);

  /* Receive legacy establish_intro */
  retval = hs_intro_received_establish_intro(intro_circ,
                                       cell_body, cell_len);
  tt_int_op(retval, ==, 0);

 done:
  return key1;
}

/** Successfuly register a v2 intro point and a v3 intro point. Ensure that HS
 *  circuitmap is maintained properly. */
static void
test_intro_point_registration(void *arg)
{
  int retval;
  hs_circuitmap_ht *the_hs_circuitmap = NULL;

  or_circuit_t *intro_circ = NULL;
  hs_cell_establish_intro_t *establish_intro_cell = NULL;
  ed25519_public_key_t auth_key;

  crypto_pk_t *legacy_auth_key = NULL;
  or_circuit_t *legacy_intro_circ = NULL;

  or_circuit_t *returned_intro_circ = NULL;

  (void) arg;

  MOCK(hs_intro_send_intro_established_cell, mock_send_intro_established_cell);

  hs_circuitmap_init();

  /* Check that the circuitmap is currently empty */
  {
    the_hs_circuitmap = get_hs_circuitmap();
    tt_assert(the_hs_circuitmap);
    tt_int_op(0, ==, HT_SIZE(the_hs_circuitmap));
    /* Do a circuitmap query in any case */
    returned_intro_circ = hs_circuitmap_get_intro_circ_v3(&auth_key);
    tt_ptr_op(returned_intro_circ, ==, NULL);
  }

  /* Create a v3 intro point */
  {
    intro_circ = or_circuit_new(0, NULL);
    tt_assert(intro_circ);
    establish_intro_cell = helper_establish_intro_v3(intro_circ);

    /* Check that the intro point was registered on the HS circuitmap */
    the_hs_circuitmap = get_hs_circuitmap();
    tt_assert(the_hs_circuitmap);
    tt_int_op(1, ==, HT_SIZE(the_hs_circuitmap));
    get_auth_key_from_establish_intro_cell(&auth_key, establish_intro_cell);
    returned_intro_circ = hs_circuitmap_get_intro_circ_v3(&auth_key);
    tt_ptr_op(intro_circ, ==, returned_intro_circ);
  }

  /* Create a v2 intro point */
  {
    char key_digest[DIGEST_LEN];

    legacy_intro_circ = or_circuit_new(1, NULL);
    tt_assert(legacy_intro_circ);
    legacy_auth_key = helper_establish_intro_v2(legacy_intro_circ);
    tt_assert(legacy_auth_key);

    /* Check that the circuitmap now has two elements */
    the_hs_circuitmap = get_hs_circuitmap();
    tt_assert(the_hs_circuitmap);
    tt_int_op(2, ==, HT_SIZE(the_hs_circuitmap));

    /* Check that the new element is our legacy intro circuit. */
    retval = crypto_pk_get_digest(legacy_auth_key, key_digest);
    tt_int_op(retval, ==, 0);
    returned_intro_circ= hs_circuitmap_get_intro_circ_v2((uint8_t*)key_digest);
    tt_ptr_op(legacy_intro_circ, ==, returned_intro_circ);
  }

  /* XXX Continue test and try to register a second v3 intro point with the
   * same auth key. Make sure that old intro circuit gets closed. */

 done:
  crypto_pk_free(legacy_auth_key);
  circuit_free(TO_CIRCUIT(intro_circ));
  circuit_free(TO_CIRCUIT(legacy_intro_circ));
  hs_cell_establish_intro_free(establish_intro_cell);

  { /* Test circuitmap free_all function. */
    the_hs_circuitmap = get_hs_circuitmap();
    tt_assert(the_hs_circuitmap);
    hs_circuitmap_free_all();
    the_hs_circuitmap = get_hs_circuitmap();
    tt_assert(!the_hs_circuitmap);
  }

  UNMOCK(hs_intro_send_intro_established_cell);
}

struct testcase_t hs_intropoint_tests[] = {
  { "intro_point_registration",
    test_intro_point_registration, TT_FORK, NULL, NULL },

  { "receive_establish_intro_wrong_keytype",
    test_establish_intro_wrong_keytype, TT_FORK, NULL, NULL },

  { "receive_establish_intro_wrong_keytype2",
    test_establish_intro_wrong_keytype2, TT_FORK, NULL, NULL },

  { "receive_establish_intro_wrong_purpose",
    test_establish_intro_wrong_purpose, TT_FORK, NULL, NULL },

  { "receive_establish_intro_wrong_sig",
    test_establish_intro_wrong_sig, TT_FORK, NULL, NULL },

  { "receive_establish_intro_wrong_sig_len",
    test_establish_intro_wrong_sig_len, TT_FORK, NULL, NULL },

  { "receive_establish_intro_wrong_auth_key_len",
    test_establish_intro_wrong_auth_key_len, TT_FORK, NULL, NULL },

  { "receive_establish_intro_wrong_mac",
    test_establish_intro_wrong_mac, TT_FORK, NULL, NULL },

  END_OF_TESTCASES
};

