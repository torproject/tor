/* Copyright (c) 2016-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_client.c
 * \brief Test prop224 HS client functionality.
 */

#define CRYPTO_PRIVATE
#define MAIN_PRIVATE
#define TOR_CHANNEL_INTERNAL_
#define CIRCUITBUILD_PRIVATE
#define CIRCUITLIST_PRIVATE
#define CONNECTION_PRIVATE

#include "test.h"
#include "test_helpers.h"
#include "log_test_helpers.h"
#include "rend_test_helpers.h"

#include "config.h"
#include "crypto.h"
#include "channeltls.h"

#include "hs_circuit.h"
#include "hs_ident.h"
#include "circuitlist.h"
#include "circuitbuild.h"
#include "connection.h"
#include "connection_edge.h"

static int
mock_connection_ap_handshake_send_begin(entry_connection_t *ap_conn)
{
  (void) ap_conn;
  return 0;
}

/* Test helper function: Setup a circuit and a stream with the same hidden
 * service destination, and put them in <b>circ_out</b> and
 * <b>conn_out</b>. Make the stream wait for circuits to be established to the
 * hidden service. */
static int
helper_get_circ_and_stream_for_test(origin_circuit_t **circ_out,
                                    connection_t **conn_out,
                                    int is_legacy)
{
  int retval;
  channel_tls_t *n_chan=NULL;
  rend_data_t *conn_rend_data = NULL;
  origin_circuit_t *or_circ = NULL;
  connection_t *conn = NULL;
  ed25519_public_key_t service_pk;

  /* Make a dummy connection stream and make it wait for our circuit */
  conn = test_conn_get_connection(AP_CONN_STATE_CIRCUIT_WAIT,
                                  CONN_TYPE_AP /* ??? */,
                                  0);
  if (is_legacy) {
    /* Legacy: Setup rend_data of stream */
    char service_id[REND_SERVICE_ID_LEN_BASE32+1] = {0};
    TO_EDGE_CONN(conn)->rend_data = mock_rend_data(service_id);
    conn_rend_data = TO_EDGE_CONN(conn)->rend_data;
  } else {
    /* prop224: Setup hs conn identifier on the stream */
    ed25519_secret_key_t sk;
    tt_int_op(0, OP_EQ, ed25519_secret_key_generate(&sk, 0));
    tt_int_op(0, OP_EQ, ed25519_public_key_generate(&service_pk, &sk));

    /* Setup hs_conn_identifier of stream */
    TO_EDGE_CONN(conn)->hs_ident = hs_ident_edge_conn_new(&service_pk);
  }

  /* Make it wait for circuit */
  connection_ap_mark_as_pending_circuit(TO_ENTRY_CONN(conn));

  /* This is needed to silence a BUG warning from
     connection_edge_update_circuit_isolation() */
  TO_ENTRY_CONN(conn)->original_dest_address =
    tor_strdup(TO_ENTRY_CONN(conn)->socks_request->address);

  /****************************************************/

  /* Now make dummy circuit */
  or_circ = origin_circuit_new();

  or_circ->base_.purpose = CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED;

  or_circ->build_state = tor_malloc_zero(sizeof(cpath_build_state_t));
  or_circ->build_state->is_internal = 1;

  if (is_legacy) {
    /* Legacy: Setup rend data and final cpath */
    or_circ->build_state->pending_final_cpath =
      tor_malloc_zero(sizeof(crypt_path_t));
    or_circ->build_state->pending_final_cpath->magic = CRYPT_PATH_MAGIC;
    or_circ->build_state->pending_final_cpath->rend_dh_handshake_state =
      crypto_dh_new(DH_TYPE_REND);
    tt_assert(
         or_circ->build_state->pending_final_cpath->rend_dh_handshake_state);
    retval = crypto_dh_generate_public(
           or_circ->build_state->pending_final_cpath->rend_dh_handshake_state);
    tt_int_op(retval, OP_EQ, 0);
    or_circ->rend_data = rend_data_dup(conn_rend_data);
  } else {
    /* prop224: Setup hs ident on the circuit */
    or_circ->hs_ident = hs_ident_circuit_new(&service_pk,
                                             HS_IDENT_CIRCUIT_RENDEZVOUS);
  }

  TO_CIRCUIT(or_circ)->state = CIRCUIT_STATE_OPEN;

  /* fake n_chan */
  n_chan = tor_malloc_zero(sizeof(channel_tls_t));
  n_chan->base_.global_identifier = 1;
  or_circ->base_.n_chan = &(n_chan->base_);

  *circ_out = or_circ;
  *conn_out = conn;

  return 0;

 done:
  /* something failed */
  return -1;
}

/* Test: Ensure that setting up legacy e2e rendezvous circuits works
 * correctly. */
static void
test_e2e_rend_circuit_setup_legacy(void *arg)
{
  ssize_t retval;
  origin_circuit_t *or_circ = NULL;
  connection_t *conn = NULL;

  (void) arg;

  /** In this test we create a v2 legacy HS stream and a circuit with the same
   *  hidden service destination. We make the stream wait for circuits to be
   *  established to the hidden service, and then we complete the circuit using
   *  the hs_circuit_setup_e2e_rend_circ_legacy_client() function. We then
   *  check that the end-to-end cpath was setup correctly and that the stream
   *  was attached to the circuit as expected. */

  MOCK(connection_ap_handshake_send_begin,
       mock_connection_ap_handshake_send_begin);

  /* Setup */
  retval = helper_get_circ_and_stream_for_test( &or_circ, &conn, 1);
  tt_int_op(retval, OP_EQ, 0);
  tt_assert(or_circ);
  tt_assert(conn);

  /* Check number of hops */
  retval = cpath_get_n_hops(&or_circ->cpath);
  tt_int_op(retval, OP_EQ, 0);

  /* Check that our stream is not attached on any circuits */
  tt_ptr_op(TO_EDGE_CONN(conn)->on_circuit, OP_EQ, NULL);

  /********************************************** */

  /* Make a good RENDEZVOUS1 cell body because it needs to pass key exchange
   * digest verification... */
  uint8_t rend_cell_body[DH_KEY_LEN+DIGEST_LEN] = {2};
  {
    char keys[DIGEST_LEN+CPATH_KEY_MATERIAL_LEN];
    crypto_dh_t *dh_state =
      or_circ->build_state->pending_final_cpath->rend_dh_handshake_state;
    /* compute and overwrite digest of cell body with the right value */
    retval = crypto_dh_compute_secret(LOG_PROTOCOL_WARN, dh_state,
                                      (char*)rend_cell_body, DH_KEY_LEN,
                                      keys, DIGEST_LEN+CPATH_KEY_MATERIAL_LEN);
    tt_int_op(retval, OP_GT, 0);
    memcpy(rend_cell_body+DH_KEY_LEN, keys, DIGEST_LEN);
  }

  /* Setup the circuit */
  retval = hs_circuit_setup_e2e_rend_circ_legacy_client(or_circ,
                                                        rend_cell_body);
  tt_int_op(retval, OP_EQ, 0);

  /**********************************************/

  /* See that a hop was added to the circuit's cpath */
  retval = cpath_get_n_hops(&or_circ->cpath);
  tt_int_op(retval, OP_EQ, 1);

  /* Check the digest algo */
  tt_int_op(crypto_digest_get_algorithm(or_circ->cpath->f_digest),
            OP_EQ, DIGEST_SHA1);
  tt_int_op(crypto_digest_get_algorithm(or_circ->cpath->b_digest),
            OP_EQ, DIGEST_SHA1);
  tt_assert(or_circ->cpath->f_crypto);
  tt_assert(or_circ->cpath->b_crypto);

  /* Ensure that circ purpose was changed */
  tt_int_op(or_circ->base_.purpose, OP_EQ, CIRCUIT_PURPOSE_C_REND_JOINED);

  /* Test that stream got attached */
  tt_ptr_op(TO_EDGE_CONN(conn)->on_circuit, OP_EQ, TO_CIRCUIT(or_circ));

 done:
  connection_free_(conn);
  if (or_circ)
    tor_free(TO_CIRCUIT(or_circ)->n_chan);
  circuit_free(TO_CIRCUIT(or_circ));
}

/* Test: Ensure that setting up v3 rendezvous circuits works correctly. */
static void
test_e2e_rend_circuit_setup(void *arg)
{
  uint8_t ntor_key_seed[DIGEST256_LEN] = {0};
  origin_circuit_t *or_circ = NULL;
  int retval;
  connection_t *conn = NULL;

  (void) arg;

  /** In this test we create a prop224 v3 HS stream and a circuit with the same
   *  hidden service destination. We make the stream wait for circuits to be
   *  established to the hidden service, and then we complete the circuit using
   *  the hs_circuit_setup_e2e_rend_circ() function. We then check that the
   *  end-to-end cpath was setup correctly and that the stream was attached to
   *  the circuit as expected. */

  MOCK(connection_ap_handshake_send_begin,
       mock_connection_ap_handshake_send_begin);

  /* Setup */
  retval = helper_get_circ_and_stream_for_test( &or_circ, &conn, 0);
  tt_int_op(retval, OP_EQ, 0);
  tt_assert(or_circ);
  tt_assert(conn);

  /* Check number of hops: There should be no hops yet to this circ */
  retval = cpath_get_n_hops(&or_circ->cpath);
  tt_int_op(retval, OP_EQ, 0);
  tt_ptr_op(or_circ->cpath, OP_EQ, NULL);

  /* Check that our stream is not attached on any circuits */
  tt_ptr_op(TO_EDGE_CONN(conn)->on_circuit, OP_EQ, NULL);

  /**********************************************/

  /* Setup the circuit */
  retval = hs_circuit_setup_e2e_rend_circ(or_circ,
                                          ntor_key_seed, sizeof(ntor_key_seed),
                                          0);
  tt_int_op(retval, OP_EQ, 0);

  /**********************************************/

  /* See that a hop was added to the circuit's cpath */
  retval = cpath_get_n_hops(&or_circ->cpath);
  tt_int_op(retval, OP_EQ, 1);

  /* Check that the crypt path has prop224 algorithm parameters */
  tt_int_op(crypto_digest_get_algorithm(or_circ->cpath->f_digest),
            OP_EQ, DIGEST_SHA3_256);
  tt_int_op(crypto_digest_get_algorithm(or_circ->cpath->b_digest),
            OP_EQ, DIGEST_SHA3_256);
  tt_assert(or_circ->cpath->f_crypto);
  tt_assert(or_circ->cpath->b_crypto);

  /* Ensure that circ purpose was changed */
  tt_int_op(or_circ->base_.purpose, OP_EQ, CIRCUIT_PURPOSE_C_REND_JOINED);

  /* Test that stream got attached */
  tt_ptr_op(TO_EDGE_CONN(conn)->on_circuit, OP_EQ, TO_CIRCUIT(or_circ));

 done:
  connection_free_(conn);
  if (or_circ)
    tor_free(TO_CIRCUIT(or_circ)->n_chan);
  circuit_free(TO_CIRCUIT(or_circ));
}

struct testcase_t hs_client_tests[] = {
  { "e2e_rend_circuit_setup_legacy", test_e2e_rend_circuit_setup_legacy,
    TT_FORK, NULL, NULL },
  { "e2e_rend_circuit_setup", test_e2e_rend_circuit_setup,
    TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};

