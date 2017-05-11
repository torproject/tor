/* Copyright (c) 2016-2017, The Tor Project, Inc. */
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
#include "log_test_helpers.h"

#include "or.h"
#include "ht.h"

/* Trunnel. */
#include "hs/cell_establish_intro.h"
#include "hs/cell_introduce1.h"
#include "hs/cell_common.h"
#include "hs_service.h"
#include "hs_common.h"
#include "hs_circuitmap.h"
#include "hs_intropoint.h"

#include "circuitlist.h"
#include "circuituse.h"
#include "rendservice.h"
#include "relay.h"

/* Mock function to avoid networking in unittests */
static int
mock_send_intro_established_cell(or_circuit_t *circ)
{
  (void) circ;
  return 0;
}

static int
mock_relay_send_command_from_edge(streamid_t stream_id, circuit_t *circ,
                                  uint8_t relay_command, const char *payload,
                                  size_t payload_len,
                                  crypt_path_t *cpath_layer,
                                  const char *filename, int lineno)
{
  (void) stream_id;
  (void) circ;
  (void) relay_command;
  (void) payload;
  (void) payload_len;
  (void) cpath_layer;
  (void) filename;
  (void) lineno;
  return 0;
}

static or_circuit_t *
helper_create_intro_circuit(void)
{
  or_circuit_t *circ = or_circuit_new(0, NULL);
  tt_assert(circ);
  circuit_change_purpose(TO_CIRCUIT(circ), CIRCUIT_PURPOSE_OR);
 done:
  return circ;
}

static trn_cell_introduce1_t *
helper_create_introduce1_cell(void)
{
  trn_cell_introduce1_t *cell = NULL;
  ed25519_keypair_t auth_key_kp;

  /* Generate the auth_key of the cell. */
  if (ed25519_keypair_generate(&auth_key_kp, 0) < 0) {
    goto err;
  }

  cell = trn_cell_introduce1_new();
  tt_assert(cell);

  /* Set the auth key. */
  {
    size_t auth_key_len = sizeof(auth_key_kp.pubkey);
    trn_cell_introduce1_set_auth_key_type(cell,
                                         HS_INTRO_AUTH_KEY_TYPE_ED25519);
    trn_cell_introduce1_set_auth_key_len(cell, auth_key_len);
    trn_cell_introduce1_setlen_auth_key(cell, auth_key_len);
    uint8_t *auth_key_ptr = trn_cell_introduce1_getarray_auth_key(cell);
    memcpy(auth_key_ptr, auth_key_kp.pubkey.pubkey, auth_key_len);
  }

  /* Set the cell extentions to none. */
  {
    trn_cell_extension_t *ext = trn_cell_extension_new();
    trn_cell_extension_set_num(ext, 0);
    trn_cell_introduce1_set_extensions(cell, ext);
  }

  /* Set the encrypted section to some data. */
  {
    size_t enc_len = 128;
    trn_cell_introduce1_setlen_encrypted(cell, enc_len);
    uint8_t *enc_ptr = trn_cell_introduce1_getarray_encrypted(cell);
    memset(enc_ptr, 'a', enc_len);
  }

  return cell;
 err:
 done:
  trn_cell_introduce1_free(cell);
  return NULL;
}

/* Try sending an ESTABLISH_INTRO cell on a circuit that is already an intro
 * point. Should fail. */
static void
test_establish_intro_wrong_purpose(void *arg)
{
  int retval;
  trn_cell_establish_intro_t *establish_intro_cell = NULL;
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

  /* Receive the cell. Should fail. */
  setup_full_capture_of_logs(LOG_INFO);
  retval = hs_intro_received_establish_intro(intro_circ, cell_body, cell_len);
  expect_log_msg_containing("Rejecting ESTABLISH_INTRO on non-OR circuit.");
  teardown_capture_of_logs();
  tt_int_op(retval, ==, -1);

 done:
  trn_cell_establish_intro_free(establish_intro_cell);
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
  setup_full_capture_of_logs(LOG_INFO);
  retval = hs_intro_received_establish_intro(intro_circ, (uint8_t*)"", 0);
  expect_log_msg_containing("Empty ESTABLISH_INTRO cell.");
  teardown_capture_of_logs();
  tt_int_op(retval, ==, -1);

 done:
  circuit_free(TO_CIRCUIT(intro_circ));
}

/* Send an ESTABLISH_INTRO cell with an unknown auth key type. Should fail. */
static void
test_establish_intro_wrong_keytype2(void *arg)
{
  int retval;
  trn_cell_establish_intro_t *establish_intro_cell = NULL;
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
  setup_full_capture_of_logs(LOG_INFO);
  retval = hs_intro_received_establish_intro(intro_circ, cell_body, cell_len);
  expect_log_msg_containing("Unrecognized AUTH_KEY_TYPE 42.");
  teardown_capture_of_logs();
  tt_int_op(retval, ==, -1);

 done:
  trn_cell_establish_intro_free(establish_intro_cell);
  circuit_free(TO_CIRCUIT(intro_circ));
}

/* Send a legit ESTABLISH_INTRO cell but with a wrong MAC. Should fail. */
static void
test_establish_intro_wrong_mac(void *arg)
{
  int retval;
  trn_cell_establish_intro_t *establish_intro_cell = NULL;
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
    trn_cell_establish_intro_getarray_handshake_mac(establish_intro_cell);
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
      trn_cell_establish_intro_getarray_auth_key(establish_intro_cell);
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
      trn_cell_establish_intro_getarray_sig(establish_intro_cell);
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
  trn_cell_establish_intro_free(establish_intro_cell);
  circuit_free(TO_CIRCUIT(intro_circ));
}

/* Send a legit ESTABLISH_INTRO cell but with a wrong auth key length. Should
 * fail. */
static void
test_establish_intro_wrong_auth_key_len(void *arg)
{
  int retval;
  trn_cell_establish_intro_t *establish_intro_cell = NULL;
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
  trn_cell_establish_intro_set_auth_key_len(establish_intro_cell,
                                           bad_auth_key_len);
  trn_cell_establish_intro_setlen_auth_key(establish_intro_cell,
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
  trn_cell_establish_intro_free(establish_intro_cell);
  circuit_free(TO_CIRCUIT(intro_circ));
}

/* Send a legit ESTABLISH_INTRO cell but with a wrong sig length. Should
 * fail. */
static void
test_establish_intro_wrong_sig_len(void *arg)
{
  int retval;
  trn_cell_establish_intro_t *establish_intro_cell = NULL;
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
  trn_cell_establish_intro_set_sig_len(establish_intro_cell, bad_sig_len);
  trn_cell_establish_intro_setlen_sig(establish_intro_cell, bad_sig_len);
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
  trn_cell_establish_intro_free(establish_intro_cell);
  circuit_free(TO_CIRCUIT(intro_circ));
}

/* Send a legit ESTABLISH_INTRO cell but slightly change the signature. Should
 * fail. */
static void
test_establish_intro_wrong_sig(void *arg)
{
  int retval;
  trn_cell_establish_intro_t *establish_intro_cell = NULL;
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
  setup_full_capture_of_logs(LOG_INFO);
  retval = hs_intro_received_establish_intro(intro_circ, cell_body, cell_len);
  expect_log_msg_containing("Failed to verify ESTABLISH_INTRO cell.");
  teardown_capture_of_logs();
  tt_int_op(retval, ==, -1);

 done:
  trn_cell_establish_intro_free(establish_intro_cell);
  circuit_free(TO_CIRCUIT(intro_circ));
}

/* Helper function: Send a well-formed v3 ESTABLISH_INTRO cell to
 * <b>intro_circ</b>. Return the cell. */
static trn_cell_establish_intro_t *
helper_establish_intro_v3(or_circuit_t *intro_circ)
{
  int retval;
  trn_cell_establish_intro_t *establish_intro_cell = NULL;
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
                                                sizeof(cell_body),
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

/* Helper function: test circuitmap free_all function outside of
 * test_intro_point_registration to prevent Coverity from seeing a
 * double free if the assertion hypothetically fails.
 */
static void
test_circuitmap_free_all(void)
{
  hs_circuitmap_ht *the_hs_circuitmap = NULL;

  the_hs_circuitmap = get_hs_circuitmap();
  tt_assert(the_hs_circuitmap);
  hs_circuitmap_free_all();
  the_hs_circuitmap = get_hs_circuitmap();
  tt_assert(!the_hs_circuitmap);
 done:
  ;
}

/** Successfuly register a v2 intro point and a v3 intro point. Ensure that HS
 *  circuitmap is maintained properly. */
static void
test_intro_point_registration(void *arg)
{
  int retval;
  hs_circuitmap_ht *the_hs_circuitmap = NULL;

  or_circuit_t *intro_circ = NULL;
  trn_cell_establish_intro_t *establish_intro_cell = NULL;
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
    returned_intro_circ =hs_circuitmap_get_intro_circ_v3_relay_side(&auth_key);
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
    get_auth_key_from_cell(&auth_key, RELAY_COMMAND_ESTABLISH_INTRO,
                           establish_intro_cell);
    returned_intro_circ =
      hs_circuitmap_get_intro_circ_v3_relay_side(&auth_key);
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
    returned_intro_circ =
      hs_circuitmap_get_intro_circ_v2_relay_side((uint8_t*)key_digest);
    tt_ptr_op(legacy_intro_circ, ==, returned_intro_circ);
  }

  /* XXX Continue test and try to register a second v3 intro point with the
   * same auth key. Make sure that old intro circuit gets closed. */

 done:
  crypto_pk_free(legacy_auth_key);
  circuit_free(TO_CIRCUIT(intro_circ));
  circuit_free(TO_CIRCUIT(legacy_intro_circ));
  trn_cell_establish_intro_free(establish_intro_cell);
  test_circuitmap_free_all();

  UNMOCK(hs_intro_send_intro_established_cell);
}

static void
test_introduce1_suitable_circuit(void *arg)
{
  int ret;
  or_circuit_t *circ = NULL;

  (void) arg;

  /* Valid suitable circuit. */
  {
    circ = or_circuit_new(0, NULL);
    circuit_change_purpose(TO_CIRCUIT(circ), CIRCUIT_PURPOSE_OR);
    ret = circuit_is_suitable_for_introduce1(circ);
    circuit_free(TO_CIRCUIT(circ));
    tt_int_op(ret, OP_EQ, 1);
  }

  /* Test if the circuit purpose safeguard works correctly. */
  {
    circ = or_circuit_new(0, NULL);
    circuit_change_purpose(TO_CIRCUIT(circ), CIRCUIT_PURPOSE_INTRO_POINT);
    ret = circuit_is_suitable_for_introduce1(circ);
    circuit_free(TO_CIRCUIT(circ));
    tt_int_op(ret, OP_EQ, 0);
  }

  /* Test the non-edge circuit safeguard works correctly. */
  {
    circ = or_circuit_new(0, NULL);
    circuit_change_purpose(TO_CIRCUIT(circ), CIRCUIT_PURPOSE_OR);
    /* Bogus pointer, the check is against NULL on n_chan. */
    circ->base_.n_chan = (channel_t *) circ;
    ret = circuit_is_suitable_for_introduce1(circ);
    circuit_free(TO_CIRCUIT(circ));
    tt_int_op(ret, OP_EQ, 0);
  }

  /* Mangle the circuit a bit more so see if our only one INTRODUCE1 cell
   * limit works correctly. */
  {
    circ = or_circuit_new(0, NULL);
    circuit_change_purpose(TO_CIRCUIT(circ), CIRCUIT_PURPOSE_OR);
    circ->already_received_introduce1 = 1;
    ret = circuit_is_suitable_for_introduce1(circ);
    circuit_free(TO_CIRCUIT(circ));
    tt_int_op(ret, OP_EQ, 0);
  }

 done:
  ;
}

static void
test_introduce1_is_legacy(void *arg)
{
  int ret;
  uint8_t request[256];

  (void) arg;

  /* For a cell to be considered legacy, according to the specification, the
   * first 20 bytes MUST BE non-zero else it's a v3 cell. */
  memset(request, 'a', DIGEST_LEN);
  memset(request + DIGEST_LEN, 0, sizeof(request) - DIGEST_LEN);
  ret = introduce1_cell_is_legacy(request);
  tt_int_op(ret, OP_EQ, 1);

  /* This is a NON legacy cell. */
  memset(request, 0, DIGEST_LEN);
  memset(request + DIGEST_LEN, 'a', sizeof(request) - DIGEST_LEN);
  ret = introduce1_cell_is_legacy(request);
  tt_int_op(ret, OP_EQ, 0);

 done:
  ;
}

static void
test_introduce1_validation(void *arg)
{
  int ret;
  trn_cell_introduce1_t *cell = NULL;

  (void) arg;

  /* Create our decoy cell that we'll modify as we go to test the validation
   * function of that parsed cell. */
  cell = helper_create_introduce1_cell();

  /* It should NOT be a legacy cell which will trigger a BUG(). */
  memset(cell->legacy_key_id, 'a', sizeof(cell->legacy_key_id));
  tor_capture_bugs_(1);
  ret = validate_introduce1_parsed_cell(cell);
  tor_end_capture_bugs_();
  tt_int_op(ret, OP_EQ, -1);
  /* Reset legacy ID and make sure it's correct. */
  memset(cell->legacy_key_id, 0, sizeof(cell->legacy_key_id));
  ret = validate_introduce1_parsed_cell(cell);
  tt_int_op(ret, OP_EQ, 0);

  /* Non existing auth key type. */
  cell->auth_key_type = 42;
  ret = validate_introduce1_parsed_cell(cell);
  tt_int_op(ret, OP_EQ, -1);
  /* Reset is to correct value and make sure it's correct. */
  cell->auth_key_type = HS_INTRO_AUTH_KEY_TYPE_ED25519;
  ret = validate_introduce1_parsed_cell(cell);
  tt_int_op(ret, OP_EQ, 0);

  /* Really bad key length. */
  cell->auth_key_len = 0;
  ret = validate_introduce1_parsed_cell(cell);
  tt_int_op(ret, OP_EQ, -1);
  cell->auth_key_len = UINT16_MAX;
  ret = validate_introduce1_parsed_cell(cell);
  tt_int_op(ret, OP_EQ, -1);
  /* Correct size, let's try that. */
  cell->auth_key_len = sizeof(ed25519_public_key_t);
  ret = validate_introduce1_parsed_cell(cell);
  tt_int_op(ret, OP_EQ, 0);
  /* Set an invalid size of the auth key buffer. */
  trn_cell_introduce1_setlen_auth_key(cell, 3);
  ret = validate_introduce1_parsed_cell(cell);
  tt_int_op(ret, OP_EQ, -1);
  /* Reset auth key buffer and make sure it works. */
  trn_cell_introduce1_setlen_auth_key(cell, sizeof(ed25519_public_key_t));
  ret = validate_introduce1_parsed_cell(cell);
  tt_int_op(ret, OP_EQ, 0);

  /* Empty encrypted section. */
  trn_cell_introduce1_setlen_encrypted(cell, 0);
  ret = validate_introduce1_parsed_cell(cell);
  tt_int_op(ret, OP_EQ, -1);
  /* Reset it to some non zero bytes and validate. */
  trn_cell_introduce1_setlen_encrypted(cell, 1);
  ret = validate_introduce1_parsed_cell(cell);
  tt_int_op(ret, OP_EQ, 0);

 done:
  trn_cell_introduce1_free(cell);
}

static void
test_received_introduce1_handling(void *arg)
{
  int ret;
  uint8_t *request = NULL, buf[128];
  trn_cell_introduce1_t *cell = NULL;
  or_circuit_t *circ = NULL;

  (void) arg;

  MOCK(relay_send_command_from_edge_, mock_relay_send_command_from_edge);

  hs_circuitmap_init();

  /* Too small request length. An INTRODUCE1 expect at the very least a
   * DIGEST_LEN size. */
  {
    circ = helper_create_intro_circuit();
    ret = hs_intro_received_introduce1(circ, buf, DIGEST_LEN - 1);
    tt_int_op(ret, OP_EQ, -1);
    circuit_free(TO_CIRCUIT(circ));
  }

  /* We have a unit test only for the suitability of a circuit to receive an
   * INTRODUCE1 cell so from now on we'll only test the handling of a cell. */

  /* Bad request. */
  {
    circ = helper_create_intro_circuit();
    uint8_t test[2]; /* Too small request. */
    ret = handle_introduce1(circ, test, sizeof(test));
    tor_free(circ->p_chan);
    circuit_free(TO_CIRCUIT(circ));
    tt_int_op(ret, OP_EQ, -1);
  }

  /* Valid case. */
  {
    cell = helper_create_introduce1_cell();
    ssize_t request_len = trn_cell_introduce1_encoded_len(cell);
    tt_int_op((int)request_len, OP_GT, 0);
    request = tor_malloc_zero(request_len);
    ssize_t encoded_len =
      trn_cell_introduce1_encode(request, request_len, cell);
    tt_int_op((int)encoded_len, OP_GT, 0);

    circ = helper_create_intro_circuit();
    or_circuit_t *service_circ = helper_create_intro_circuit();
    circuit_change_purpose(TO_CIRCUIT(service_circ),
                           CIRCUIT_PURPOSE_INTRO_POINT);
    /* Register the circuit in the map for the auth key of the cell. */
    ed25519_public_key_t auth_key;
    const uint8_t *cell_auth_key =
      trn_cell_introduce1_getconstarray_auth_key(cell);
    memcpy(auth_key.pubkey, cell_auth_key, ED25519_PUBKEY_LEN);
    hs_circuitmap_register_intro_circ_v3_relay_side(service_circ, &auth_key);
    ret = hs_intro_received_introduce1(circ, request, request_len);
    circuit_free(TO_CIRCUIT(circ));
    circuit_free(TO_CIRCUIT(service_circ));
    tt_int_op(ret, OP_EQ, 0);
  }

  /* Valid legacy cell. */
  {
    tor_free(request);
    trn_cell_introduce1_free(cell);
    cell = helper_create_introduce1_cell();
    uint8_t *legacy_key_id = trn_cell_introduce1_getarray_legacy_key_id(cell);
    memset(legacy_key_id, 'a', DIGEST_LEN);
    /* Add an arbitrary amount of data for the payload of a v2 cell. */
    size_t request_len = trn_cell_introduce1_encoded_len(cell) + 256;
    tt_size_op(request_len, OP_GT, 0);
    request = tor_malloc_zero(request_len + 256);
    ssize_t encoded_len =
      trn_cell_introduce1_encode(request, request_len, cell);
    tt_int_op((int)encoded_len, OP_GT, 0);

    circ = helper_create_intro_circuit();
    or_circuit_t *service_circ = helper_create_intro_circuit();
    circuit_change_purpose(TO_CIRCUIT(service_circ),
                           CIRCUIT_PURPOSE_INTRO_POINT);
    /* Register the circuit in the map for the auth key of the cell. */
    uint8_t token[REND_TOKEN_LEN];
    memcpy(token, legacy_key_id, sizeof(token));
    hs_circuitmap_register_intro_circ_v2_relay_side(service_circ, token);
    ret = hs_intro_received_introduce1(circ, request, request_len);
    circuit_free(TO_CIRCUIT(circ));
    circuit_free(TO_CIRCUIT(service_circ));
    tt_int_op(ret, OP_EQ, 0);
  }

 done:
  trn_cell_introduce1_free(cell);
  tor_free(request);
  hs_circuitmap_free_all();
  UNMOCK(relay_send_command_from_edge_);
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

  { "introduce1_suitable_circuit",
    test_introduce1_suitable_circuit, TT_FORK, NULL, NULL },

  { "introduce1_is_legacy",
    test_introduce1_is_legacy, TT_FORK, NULL, NULL },

  { "introduce1_validation",
    test_introduce1_validation, TT_FORK, NULL, NULL },

  { "received_introduce1_handling",
    test_received_introduce1_handling, TT_FORK, NULL, NULL },

  END_OF_TESTCASES
};

