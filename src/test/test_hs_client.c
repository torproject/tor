/* Copyright (c) 2016-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_client.c
 * \brief Test prop224 HS client functionality.
 */

#define CRYPTO_PRIVATE
#define MAIN_PRIVATE
#define HS_CLIENT_PRIVATE
#define TOR_CHANNEL_INTERNAL_
#define CIRCUITBUILD_PRIVATE
#define CIRCUITLIST_PRIVATE
#define CONNECTION_PRIVATE

#include "test.h"
#include "test_helpers.h"
#include "log_test_helpers.h"
#include "rend_test_helpers.h"
#include "hs_test_helpers.h"

#include "config.h"
#include "crypto.h"
#include "channeltls.h"
#include "main.h"
#include "nodelist.h"
#include "routerset.h"

#include "hs_circuit.h"
#include "hs_client.h"
#include "hs_ident.h"
#include "hs_cache.h"
#include "circuitlist.h"
#include "circuitbuild.h"
#include "connection.h"
#include "connection_edge.h"
#include "networkstatus.h"

static int
mock_connection_ap_handshake_send_begin(entry_connection_t *ap_conn)
{
  (void) ap_conn;
  return 0;
}

static networkstatus_t mock_ns;

/* Always return NULL. */
static networkstatus_t *
mock_networkstatus_get_live_consensus_false(time_t now)
{
  (void) now;
  return NULL;
}

static networkstatus_t *
mock_networkstatus_get_live_consensus(time_t now)
{
  (void) now;
  return &mock_ns;
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

/** Test client logic for picking intro points from a descriptor. Also test how
 *  ExcludeNodes and intro point failures affect picking intro points. */
static void
test_client_pick_intro(void *arg)
{
  int ret;
  ed25519_keypair_t service_kp;
  hs_descriptor_t *desc = NULL;

  MOCK(networkstatus_get_live_consensus,
       mock_networkstatus_get_live_consensus);

  (void) arg;

  hs_init();

  /* Generate service keypair */
  tt_int_op(0, OP_EQ, ed25519_keypair_generate(&service_kp, 0));

  /* Set time */
  ret = parse_rfc1123_time("Sat, 26 Oct 1985 13:00:00 UTC",
                           &mock_ns.valid_after);
  tt_int_op(ret, OP_EQ, 0);
  ret = parse_rfc1123_time("Sat, 26 Oct 1985 14:00:00 UTC",
                           &mock_ns.fresh_until);
  tt_int_op(ret, OP_EQ, 0);

  update_approx_time(mock_ns.fresh_until-10);
  time_t now = approx_time();

  /* Test logic:
   *
   * 1) Add our desc with intro points to the HS cache.
   *
   * 2) Mark all descriptor intro points except _the chosen one_ as
   *    failed. Then query the desc to get a random intro: check that we got
   *    _the chosen one_. Then fail the chosen one as well, and see that no
   *    intros are returned.
   *
   * 3) Then clean the intro state cache and get an intro point.
   *
   * 4) Try fetching an intro with the wrong service key: shouldn't work
   *
   * 5) Set StrictNodes and put all our intro points in ExcludeNodes: see that
   *    nothing is returned.
   */

  /* 1) Add desc to HS cache */
  {
    char *encoded = NULL;
    desc = hs_helper_build_hs_desc_with_ip(&service_kp);
    ret = hs_desc_encode_descriptor(desc, &service_kp, &encoded);
    tt_int_op(ret, OP_EQ, 0);
    tt_assert(encoded);

    /* store it */
    hs_cache_store_as_client(encoded, &service_kp.pubkey);

    /* fetch it to make sure it works */
    const hs_descriptor_t *fetched_desc =
      hs_cache_lookup_as_client(&service_kp.pubkey);
    tt_assert(fetched_desc);
    tt_mem_op(fetched_desc->subcredential, OP_EQ, desc->subcredential,
              DIGEST256_LEN);
    tt_assert(!tor_mem_is_zero((char*)fetched_desc->subcredential,
                               DIGEST256_LEN));
    tor_free(encoded);
  }

  /* 2) Mark all intro points except _the chosen one_ as failed. Then query the
   *   desc and get a random intro: check that we got _the chosen one_. */
  {
    /* Pick the chosen intro point and get its ei */
    hs_desc_intro_point_t *chosen_intro_point =
      smartlist_get(desc->encrypted_data.intro_points, 0);
    extend_info_t *chosen_intro_ei =
      desc_intro_point_to_extend_info(chosen_intro_point);
    tt_assert(chosen_intro_point);
    tt_assert(chosen_intro_ei);

    /* Now mark all other intro points as failed */
    SMARTLIST_FOREACH_BEGIN(desc->encrypted_data.intro_points,
                            hs_desc_intro_point_t *, ip) {
      /* Skip the chosen intro point */
      if (ip == chosen_intro_point) {
        continue;
      }
      ed25519_public_key_t *intro_auth_key = &ip->auth_key_cert->signed_key;
      hs_cache_client_intro_state_note(&service_kp.pubkey,
                                       intro_auth_key,
                                       INTRO_POINT_FAILURE_GENERIC);
    } SMARTLIST_FOREACH_END(ip);

    /* Try to get a random intro: Should return the chosen one! */
    extend_info_t *ip = client_get_random_intro(&service_kp.pubkey);
    tor_assert(ip);
    tt_assert(!tor_mem_is_zero((char*)ip->identity_digest, DIGEST_LEN));
    tt_mem_op(ip->identity_digest, OP_EQ, chosen_intro_ei->identity_digest,
              DIGEST_LEN);

    extend_info_free(chosen_intro_ei);
    extend_info_free(ip);

    /* Now also mark the chosen one as failed: See that we can't get any intro
       points anymore. */
    hs_cache_client_intro_state_note(&service_kp.pubkey,
                                &chosen_intro_point->auth_key_cert->signed_key,
                                     INTRO_POINT_FAILURE_TIMEOUT);
    ip = client_get_random_intro(&service_kp.pubkey);
    tor_assert(!ip);
  }

  /* 3) Clean the intro state cache and get an intro point */
  {
    /* Pretend we are 5 mins in the future and order a cleanup of the intro
     * state. This should clean up the intro point failures and allow us to get
     * an intro. */
    hs_cache_client_intro_state_clean(now + 5*60);

    /* Get an intro. It should work! */
    extend_info_t *ip = client_get_random_intro(&service_kp.pubkey);
    tor_assert(ip);
    extend_info_free(ip);
  }

  /* 4) Try fetching an intro with the wrong service key: shouldn't work */
  {
    ed25519_keypair_t dummy_kp;
    tt_int_op(0, OP_EQ, ed25519_keypair_generate(&dummy_kp, 0));
    extend_info_t *ip = client_get_random_intro(&dummy_kp.pubkey);
    tor_assert(!ip);
  }

  /* 5) Set StrictNodes and put all our intro points in ExcludeNodes: see that
   *    nothing is returned. */
  {
    get_options_mutable()->ExcludeNodes = routerset_new();
    get_options_mutable()->StrictNodes = 1;
    SMARTLIST_FOREACH_BEGIN(desc->encrypted_data.intro_points,
                            hs_desc_intro_point_t *, ip) {
      extend_info_t *intro_ei = desc_intro_point_to_extend_info(ip);
      if (intro_ei) {
        const char *ptr;
        char ip_addr[TOR_ADDR_BUF_LEN];
        /* We need to decorate in case it is an IPv6 else routerset_parse()
         * doesn't like it. */
        ptr = tor_addr_to_str(ip_addr, &intro_ei->addr, sizeof(ip_addr), 1);
        tt_assert(ptr == ip_addr);
        ret = routerset_parse(get_options_mutable()->ExcludeNodes,
                              ip_addr, "");
        tt_int_op(ret, OP_EQ, 0);
        extend_info_free(intro_ei);
      }
    } SMARTLIST_FOREACH_END(ip);

    extend_info_t *ip = client_get_random_intro(&service_kp.pubkey);
    tt_assert(!ip);
  }

 done:
  hs_descriptor_free(desc);
}

static int
mock_router_have_minimum_dir_info_false(void)
{
  return 0;
}
static int
mock_router_have_minimum_dir_info_true(void)
{
  return 1;
}

static hs_client_fetch_status_t
mock_fetch_v3_desc_error(const ed25519_public_key_t *key)
{
  (void) key;
  return HS_CLIENT_FETCH_ERROR;
}

static void
mock_connection_mark_unattached_ap_(entry_connection_t *conn, int endreason,
                                    int line, const char *file)
{
  (void) line;
  (void) file;
  conn->edge_.end_reason = endreason;
}

static void
test_descriptor_fetch(void *arg)
{
  int ret;
  entry_connection_t *ec = NULL;
  ed25519_public_key_t service_pk;
  ed25519_secret_key_t service_sk;

  (void) arg;

  hs_init();
  memset(&service_sk, 'A', sizeof(service_sk));
  ret = ed25519_public_key_generate(&service_pk, &service_sk);
  tt_int_op(ret, OP_EQ, 0);

  /* Initialize this so get_voting_interval() doesn't freak out. */
  ret = parse_rfc1123_time("Sat, 26 Oct 1985 13:00:00 UTC",
                           &mock_ns.valid_after);
  tt_int_op(ret, OP_EQ, 0);
  ret = parse_rfc1123_time("Sat, 26 Oct 1985 14:00:00 UTC",
                           &mock_ns.fresh_until);
  tt_int_op(ret, OP_EQ, 0);

  ec = entry_connection_new(CONN_TYPE_AP, AF_INET);
  tt_assert(ec);
  ENTRY_TO_EDGE_CONN(ec)->hs_ident = hs_ident_edge_conn_new(&service_pk);
  tt_assert(ENTRY_TO_EDGE_CONN(ec)->hs_ident);
  TO_CONN(ENTRY_TO_EDGE_CONN(ec))->state = AP_CONN_STATE_RENDDESC_WAIT;
  smartlist_add(get_connection_array(), &ec->edge_.base_);

  /* 1. FetchHidServDescriptors is false so we shouldn't be able to fetch. */
  get_options_mutable()->FetchHidServDescriptors = 0;
  ret = hs_client_refetch_hsdesc(&service_pk);
  tt_int_op(ret, OP_EQ, HS_CLIENT_FETCH_NOT_ALLOWED);
  get_options_mutable()->FetchHidServDescriptors = 1;

  /* 2. We don't have a live consensus. */
  MOCK(networkstatus_get_live_consensus,
       mock_networkstatus_get_live_consensus_false);
  ret = hs_client_refetch_hsdesc(&service_pk);
  UNMOCK(networkstatus_get_live_consensus);
  tt_int_op(ret, OP_EQ, HS_CLIENT_FETCH_MISSING_INFO);

  /* From now on, return a live consensus. */
  MOCK(networkstatus_get_live_consensus,
       mock_networkstatus_get_live_consensus);

  /* 3. Not enough dir information. */
  MOCK(router_have_minimum_dir_info,
       mock_router_have_minimum_dir_info_false);
  ret = hs_client_refetch_hsdesc(&service_pk);
  UNMOCK(router_have_minimum_dir_info);
  tt_int_op(ret, OP_EQ, HS_CLIENT_FETCH_MISSING_INFO);

  /* From now on, we do have enough directory information. */
  MOCK(router_have_minimum_dir_info,
       mock_router_have_minimum_dir_info_true);

  /* 4. We do have a pending directory request. */
  {
    dir_connection_t *dir_conn = dir_connection_new(AF_INET);
    dir_conn->hs_ident = tor_malloc_zero(sizeof(hs_ident_dir_conn_t));
    TO_CONN(dir_conn)->purpose = DIR_PURPOSE_FETCH_HSDESC;
    ed25519_pubkey_copy(&dir_conn->hs_ident->identity_pk, &service_pk);
    smartlist_add(get_connection_array(), TO_CONN(dir_conn));
    ret = hs_client_refetch_hsdesc(&service_pk);
    smartlist_remove(get_connection_array(), TO_CONN(dir_conn));
    connection_free_(TO_CONN(dir_conn));
    tt_int_op(ret, OP_EQ, HS_CLIENT_FETCH_PENDING);
  }

  /* 5. We'll trigger an error on the fetch_desc_v3 and force to close all
   *    pending SOCKS request. */
  MOCK(router_have_minimum_dir_info,
       mock_router_have_minimum_dir_info_true);
  MOCK(fetch_v3_desc, mock_fetch_v3_desc_error);
  MOCK(connection_mark_unattached_ap_,
       mock_connection_mark_unattached_ap_);
  ret = hs_client_refetch_hsdesc(&service_pk);
  UNMOCK(fetch_v3_desc);
  UNMOCK(connection_mark_unattached_ap_);
  tt_int_op(ret, OP_EQ, HS_CLIENT_FETCH_ERROR);
  /* The close waiting for descriptor function has been called. */
  tt_int_op(ec->edge_.end_reason, OP_EQ, END_STREAM_REASON_RESOLVEFAILED);

 done:
  connection_free_(ENTRY_TO_CONN(ec));
  UNMOCK(networkstatus_get_live_consensus);
  UNMOCK(router_have_minimum_dir_info);
  hs_free_all();
}

struct testcase_t hs_client_tests[] = {
  { "e2e_rend_circuit_setup_legacy", test_e2e_rend_circuit_setup_legacy,
    TT_FORK, NULL, NULL },
  { "e2e_rend_circuit_setup", test_e2e_rend_circuit_setup,
    TT_FORK, NULL, NULL },
  { "client_pick_intro", test_client_pick_intro,
    TT_FORK, NULL, NULL },
  { "descriptor_fetch", test_descriptor_fetch,
    TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};

