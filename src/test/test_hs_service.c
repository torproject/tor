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
#define HS_CIRCUIT_PRIVATE
#define MAIN_PRIVATE
#define NETWORKSTATUS_PRIVATE
#define STATEFILE_PRIVATE
#define TOR_CHANNEL_INTERNAL_
#define HS_CLIENT_PRIVATE

#include "test.h"
#include "test_helpers.h"
#include "log_test_helpers.h"
#include "rend_test_helpers.h"
#include "hs_test_helpers.h"

#include "or.h"
#include "config.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "crypto.h"
#include "dirvote.h"
#include "networkstatus.h"
#include "nodelist.h"
#include "relay.h"

#include "hs_common.h"
#include "hs_config.h"
#include "hs_ident.h"
#include "hs_intropoint.h"
#include "hs_ntor.h"
#include "hs_circuit.h"
#include "hs_service.h"
#include "hs_client.h"
#include "main.h"
#include "rendservice.h"
#include "statefile.h"
#include "shared_random_state.h"

/* Trunnel */
#include "hs/cell_establish_intro.h"

static networkstatus_t mock_ns;

static networkstatus_t *
mock_networkstatus_get_live_consensus(time_t now)
{
  (void) now;
  return &mock_ns;
}

static or_state_t *dummy_state = NULL;

/* Mock function to get fake or state (used for rev counters) */
static or_state_t *
get_or_state_replacement(void)
{
  return dummy_state;
}

/* Mock function because we are not trying to test the close circuit that does
 * an awful lot of checks on the circuit object. */
static void
mock_circuit_mark_for_close(circuit_t *circ, int reason, int line,
                            const char *file)
{
  (void) circ;
  (void) reason;
  (void) line;
  (void) file;
  return;
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

/* Helper: Return a newly allocated and initialized origin circuit with
 * purpose and flags. A default HS identifier is set to an ed25519
 * authentication key for introduction point. */
static origin_circuit_t *
helper_create_origin_circuit(int purpose, int flags)
{
  origin_circuit_t *circ = NULL;

  circ = origin_circuit_init(purpose, flags);
  tt_assert(circ);
  circ->cpath = tor_malloc_zero(sizeof(crypt_path_t));
  circ->cpath->magic = CRYPT_PATH_MAGIC;
  circ->cpath->state = CPATH_STATE_OPEN;
  circ->cpath->package_window = circuit_initial_package_window();
  circ->cpath->deliver_window = CIRCWINDOW_START;
  circ->cpath->prev = circ->cpath;
  /* Random nonce. */
  crypto_rand(circ->cpath->prev->rend_circ_nonce, DIGEST_LEN);
  /* Create a default HS identifier. */
  circ->hs_ident = tor_malloc_zero(sizeof(hs_ident_circuit_t));

 done:
  return circ;
}

/* Helper: Return a newly allocated service object with the identity keypair
 * sets and the current descriptor. Then register it to the global map.
 * Caller should us hs_free_all() to free this service or remove it from the
 * global map before freeing. */
static hs_service_t *
helper_create_service(void)
{
  /* Set a service for this circuit. */
  hs_service_t *service = hs_service_new(get_options());
  tt_assert(service);
  service->config.version = HS_VERSION_THREE;
  ed25519_secret_key_generate(&service->keys.identity_sk, 0);
  ed25519_public_key_generate(&service->keys.identity_pk,
                              &service->keys.identity_sk);
  service->desc_current = service_descriptor_new();
  tt_assert(service->desc_current);
  /* Register service to global map. */
  int ret = register_service(get_hs_service_map(), service);
  tt_int_op(ret, OP_EQ, 0);

 done:
  return service;
}

/* Helper: Return a newly allocated service intro point with two link
 * specifiers, one IPv4 and one legacy ID set to As. */
static hs_service_intro_point_t *
helper_create_service_ip(void)
{
  hs_desc_link_specifier_t *ls;
  hs_service_intro_point_t *ip = service_intro_point_new(NULL, 0);
  tt_assert(ip);
  /* Add a first unused link specifier. */
  ls = tor_malloc_zero(sizeof(*ls));
  ls->type = LS_IPV4;
  smartlist_add(ip->base.link_specifiers, ls);
  /* Add a second link specifier used by a test. */
  ls = tor_malloc_zero(sizeof(*ls));
  ls->type = LS_LEGACY_ID;
  memset(ls->u.legacy_id, 'A', sizeof(ls->u.legacy_id));
  smartlist_add(ip->base.link_specifiers, ls);

 done:
  return ip;
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
  tt_int_op(rend_num_services(), OP_EQ, 1);

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
  tt_ptr_op(query, OP_EQ, NULL);

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
  tt_ptr_op(query, OP_EQ, NULL);
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

/** Test that we can create intro point objects, index them and find them */
static void
test_service_intro_point(void *arg)
{
  hs_service_t *service = NULL;
  hs_service_intro_point_t *ip = NULL;

  (void) arg;

  /* Test simple creation of an object. */
  {
    time_t now = time(NULL);
    ip = helper_create_service_ip();
    tt_assert(ip);
    /* Make sure the authentication keypair is not zeroes. */
    tt_int_op(tor_mem_is_zero((const char *) &ip->auth_key_kp,
                              sizeof(ed25519_keypair_t)), OP_EQ, 0);
    /* The introduce2_max MUST be in that range. */
    tt_u64_op(ip->introduce2_max, OP_GE,
              INTRO_POINT_MIN_LIFETIME_INTRODUCTIONS);
    tt_u64_op(ip->introduce2_max, OP_LE,
              INTRO_POINT_MAX_LIFETIME_INTRODUCTIONS);
    /* Time to expire MUST also be in that range. We add 5 seconds because
     * there could be a gap between setting now and the time taken in
     * service_intro_point_new. On ARM, it can be surprisingly slow... */
    tt_u64_op(ip->time_to_expire, OP_GE,
              now + INTRO_POINT_LIFETIME_MIN_SECONDS + 5);
    tt_u64_op(ip->time_to_expire, OP_LE,
              now + INTRO_POINT_LIFETIME_MAX_SECONDS + 5);
    tt_assert(ip->replay_cache);
    tt_assert(ip->base.link_specifiers);
    /* By default, this is NOT a legacy object. */
    tt_int_op(ip->base.is_only_legacy, OP_EQ, 0);
  }

  /* Test functions that uses a service intropoints map with that previously
   * created object (non legacy). */
  {
    ed25519_public_key_t garbage = { {0} };
    hs_service_intro_point_t *query;

    service = hs_service_new(get_options());
    tt_assert(service);
    service->desc_current = service_descriptor_new();
    tt_assert(service->desc_current);
    /* Add intropoint to descriptor map. */
    service_intro_point_add(service->desc_current->intro_points.map, ip);
    query = service_intro_point_find(service, &ip->auth_key_kp.pubkey);
    tt_mem_op(query, OP_EQ, ip, sizeof(hs_service_intro_point_t));
    query = service_intro_point_find(service, &garbage);
    tt_ptr_op(query, OP_EQ, NULL);

    /* While at it, can I find the descriptor with the intro point? */
    hs_service_descriptor_t *desc_lookup =
      service_desc_find_by_intro(service, ip);
    tt_mem_op(service->desc_current, OP_EQ, desc_lookup,
              sizeof(hs_service_descriptor_t));

    /* Remove object from service descriptor and make sure it is out. */
    service_intro_point_remove(service, ip);
    query = service_intro_point_find(service, &ip->auth_key_kp.pubkey);
    tt_ptr_op(query, OP_EQ, NULL);
  }

 done:
  /* If the test succeed, this object is no longer referenced in the service
   * so we can free it without use after free. Else, it might explode because
   * it's still in the service descriptor map. */
  service_intro_point_free(ip);
  hs_service_free(service);
}

static node_t mock_node;
static const node_t *
mock_node_get_by_id(const char *digest)
{
  (void) digest;
  memset(mock_node.identity, 'A', DIGEST_LEN);
  /* Only return the matchin identity of As */
  if (!tor_memcmp(mock_node.identity, digest, DIGEST_LEN)) {
    return &mock_node;
  }
  return NULL;
}

static void
test_helper_functions(void *arg)
{
  int ret;
  hs_service_t *service = NULL;
  hs_service_intro_point_t *ip = NULL;
  hs_ident_circuit_t ident;

  (void) arg;

  MOCK(node_get_by_id, mock_node_get_by_id);

  hs_service_init();

  service = helper_create_service();

  ip = helper_create_service_ip();
  /* Immediately add the intro point to the service so the free service at the
   * end cleans it as well. */
  service_intro_point_add(service->desc_current->intro_points.map, ip);

  /* Setup the circuit identifier. */
  ed25519_pubkey_copy(&ident.intro_auth_pk, &ip->auth_key_kp.pubkey);
  ed25519_pubkey_copy(&ident.identity_pk, &service->keys.identity_pk);

  /* Testing get_objects_from_ident(). */
  {
    hs_service_t *s_lookup = NULL;
    hs_service_intro_point_t *ip_lookup = NULL;
    hs_service_descriptor_t *desc_lookup = NULL;

    get_objects_from_ident(&ident, &s_lookup, &ip_lookup, &desc_lookup);
    tt_mem_op(s_lookup, OP_EQ, service, sizeof(hs_service_t));
    tt_mem_op(ip_lookup, OP_EQ, ip, sizeof(hs_service_intro_point_t));
    tt_mem_op(desc_lookup, OP_EQ, service->desc_current,
              sizeof(hs_service_descriptor_t));
    /* Reset */
    s_lookup = NULL; ip_lookup = NULL; desc_lookup = NULL;

    /* NULL parameter should work. */
    get_objects_from_ident(&ident, NULL, &ip_lookup, &desc_lookup);
    tt_mem_op(ip_lookup, OP_EQ, ip, sizeof(hs_service_intro_point_t));
    tt_mem_op(desc_lookup, OP_EQ, service->desc_current,
              sizeof(hs_service_descriptor_t));
    /* Reset. */
    s_lookup = NULL; ip_lookup = NULL; desc_lookup = NULL;

    /* Break the ident and we should find nothing. */
    memset(&ident, 0, sizeof(ident));
    get_objects_from_ident(&ident, &s_lookup, &ip_lookup, &desc_lookup);
    tt_ptr_op(s_lookup, OP_EQ, NULL);
    tt_ptr_op(ip_lookup, OP_EQ, NULL);
    tt_ptr_op(desc_lookup, OP_EQ, NULL);
  }

  /* Testing get_node_from_intro_point() */
  {
    const node_t *node = get_node_from_intro_point(ip);
    tt_ptr_op(node, OP_EQ, &mock_node);
    SMARTLIST_FOREACH_BEGIN(ip->base.link_specifiers,
                            hs_desc_link_specifier_t *, ls) {
      if (ls->type == LS_LEGACY_ID) {
        /* Change legacy id in link specifier which is not the mock node. */
        memset(ls->u.legacy_id, 'B', sizeof(ls->u.legacy_id));
      }
    } SMARTLIST_FOREACH_END(ls);
    node = get_node_from_intro_point(ip);
    tt_ptr_op(node, OP_EQ, NULL);
  }

  /* Testing can_service_launch_intro_circuit() */
  {
    time_t now = time(NULL);
    /* Put the start of the retry period back in time, we should be allowed.
     * to launch intro circuit. */
    service->state.num_intro_circ_launched = 2;
    service->state.intro_circ_retry_started_time =
      (now - INTRO_CIRC_RETRY_PERIOD - 1);
    ret = can_service_launch_intro_circuit(service, now);
    tt_int_op(ret, OP_EQ, 1);
    tt_u64_op(service->state.intro_circ_retry_started_time, OP_EQ, now);
    tt_u64_op(service->state.num_intro_circ_launched, OP_EQ, 0);
    /* Call it again, we should still be allowed because we are under
     * MAX_INTRO_CIRCS_PER_PERIOD which been set to 0 previously. */
    ret = can_service_launch_intro_circuit(service, now);
    tt_int_op(ret, OP_EQ, 1);
    tt_u64_op(service->state.intro_circ_retry_started_time, OP_EQ, now);
    tt_u64_op(service->state.num_intro_circ_launched, OP_EQ, 0);
    /* Too many intro circuit launched means we are not allowed. */
    service->state.num_intro_circ_launched = 20;
    ret = can_service_launch_intro_circuit(service, now);
    tt_int_op(ret, OP_EQ, 0);
  }

  /* Testing intro_point_should_expire(). */
  {
    time_t now = time(NULL);
    /* Just some basic test of the current state. */
    tt_u64_op(ip->introduce2_max, OP_GE,
              INTRO_POINT_MIN_LIFETIME_INTRODUCTIONS);
    tt_u64_op(ip->introduce2_max, OP_LE,
              INTRO_POINT_MAX_LIFETIME_INTRODUCTIONS);
    tt_u64_op(ip->time_to_expire, OP_GE,
              now + INTRO_POINT_LIFETIME_MIN_SECONDS);
    tt_u64_op(ip->time_to_expire, OP_LE,
              now + INTRO_POINT_LIFETIME_MAX_SECONDS);

    /* This newly created IP from above shouldn't expire now. */
    ret = intro_point_should_expire(ip, now);
    tt_int_op(ret, OP_EQ, 0);
    /* Maximum number of INTRODUCE2 cell reached, it should expire. */
    ip->introduce2_count = INTRO_POINT_MAX_LIFETIME_INTRODUCTIONS + 1;
    ret = intro_point_should_expire(ip, now);
    tt_int_op(ret, OP_EQ, 1);
    ip->introduce2_count = 0;
    /* It should expire if time to expire has been reached. */
    ip->time_to_expire = now - 1000;
    ret = intro_point_should_expire(ip, now);
    tt_int_op(ret, OP_EQ, 1);
  }

 done:
  /* This will free the service and all objects associated to it. */
  hs_service_free_all();
  UNMOCK(node_get_by_id);
}

/** Test that we do the right operations when an intro circuit opens */
static void
test_intro_circuit_opened(void *arg)
{
  int flags = CIRCLAUNCH_NEED_UPTIME | CIRCLAUNCH_IS_INTERNAL;
  hs_service_t *service;
  origin_circuit_t *circ = NULL;

  (void) arg;

  hs_init();
  MOCK(circuit_mark_for_close_, mock_circuit_mark_for_close);
  MOCK(relay_send_command_from_edge_, mock_relay_send_command_from_edge);

  circ = helper_create_origin_circuit(CIRCUIT_PURPOSE_S_ESTABLISH_INTRO,
                                      flags);

  /* No service associated with this circuit. */
  setup_full_capture_of_logs(LOG_WARN);
  hs_service_circuit_has_opened(circ);
  expect_log_msg_containing("Unknown service identity key");
  teardown_capture_of_logs();

  /* Set a service for this circuit. */
  {
    service = helper_create_service();
    ed25519_pubkey_copy(&circ->hs_ident->identity_pk,
                        &service->keys.identity_pk);

    /* No intro point associated with this circuit. */
    setup_full_capture_of_logs(LOG_WARN);
    hs_service_circuit_has_opened(circ);
    expect_log_msg_containing("Unknown introduction point auth key");
    teardown_capture_of_logs();
  }

  /* Set an IP object now for this circuit. */
  {
    hs_service_intro_point_t *ip = helper_create_service_ip();
    service_intro_point_add(service->desc_current->intro_points.map, ip);
    /* Update ident to contain the intro point auth key. */
    ed25519_pubkey_copy(&circ->hs_ident->intro_auth_pk,
                        &ip->auth_key_kp.pubkey);
  }

  /* This one should go all the way. */
  setup_full_capture_of_logs(LOG_INFO);
  hs_service_circuit_has_opened(circ);
  expect_log_msg_containing("Introduction circuit 0 established for service");
  teardown_capture_of_logs();

 done:
  circuit_free(TO_CIRCUIT(circ));
  hs_free_all();
  UNMOCK(circuit_mark_for_close_);
  UNMOCK(relay_send_command_from_edge_);
}

/** Test the operations we do on a circuit after we learn that we successfuly
 *  established an intro point on it */
static void
test_intro_established(void *arg)
{
  int ret;
  int flags = CIRCLAUNCH_NEED_UPTIME | CIRCLAUNCH_IS_INTERNAL;
  uint8_t payload[RELAY_PAYLOAD_SIZE] = {0};
  origin_circuit_t *circ = NULL;
  hs_service_t *service;
  hs_service_intro_point_t *ip = NULL;

  (void) arg;

  hs_init();
  MOCK(circuit_mark_for_close_, mock_circuit_mark_for_close);

  circ = helper_create_origin_circuit(CIRCUIT_PURPOSE_S_ESTABLISH_INTRO,
                                      flags);
  tt_assert(circ);

  /* Test a wrong purpose. */
  TO_CIRCUIT(circ)->purpose = CIRCUIT_PURPOSE_S_INTRO;
  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_service_receive_intro_established(circ, payload, sizeof(payload));
  tt_int_op(ret, OP_EQ, -1);
  expect_log_msg_containing("Received an INTRO_ESTABLISHED cell on a "
                            "non introduction circuit of purpose");
  teardown_capture_of_logs();

  /* Back to normal. */
  TO_CIRCUIT(circ)->purpose = CIRCUIT_PURPOSE_S_ESTABLISH_INTRO;

  /* No service associated to it. */
  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_service_receive_intro_established(circ, payload, sizeof(payload));
  tt_int_op(ret, OP_EQ, -1);
  expect_log_msg_containing("Unknown service identity key");
  teardown_capture_of_logs();

  /* Set a service for this circuit. */
  service = helper_create_service();
  ed25519_pubkey_copy(&circ->hs_ident->identity_pk,
                      &service->keys.identity_pk);
  /* No introduction point associated to it. */
  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_service_receive_intro_established(circ, payload, sizeof(payload));
  tt_int_op(ret, OP_EQ, -1);
  expect_log_msg_containing("Introduction circuit established without an "
                            "intro point object on circuit");
  teardown_capture_of_logs();

  /* Set an IP object now for this circuit. */
  {
    ip = helper_create_service_ip();
    service_intro_point_add(service->desc_current->intro_points.map, ip);
    /* Update ident to contain the intro point auth key. */
    ed25519_pubkey_copy(&circ->hs_ident->intro_auth_pk,
                        &ip->auth_key_kp.pubkey);
  }

  /* Send an empty payload. INTRO_ESTABLISHED cells are basically zeroes. */
  ret = hs_service_receive_intro_established(circ, payload, sizeof(payload));
  tt_int_op(ret, OP_EQ, 0);
  tt_u64_op(ip->circuit_established, OP_EQ, 1);
  tt_int_op(TO_CIRCUIT(circ)->purpose, OP_EQ, CIRCUIT_PURPOSE_S_INTRO);

 done:
  if (circ)
    circuit_free(TO_CIRCUIT(circ));
  hs_free_all();
  UNMOCK(circuit_mark_for_close_);
}

/** Check the operations we do on a rendezvous circuit after we learn it's
 *  open */
static void
test_rdv_circuit_opened(void *arg)
{
  int flags = CIRCLAUNCH_NEED_UPTIME | CIRCLAUNCH_IS_INTERNAL;
  origin_circuit_t *circ = NULL;
  hs_service_t *service;

  (void) arg;

  hs_init();
  MOCK(circuit_mark_for_close_, mock_circuit_mark_for_close);
  MOCK(relay_send_command_from_edge_, mock_relay_send_command_from_edge);

  circ = helper_create_origin_circuit(CIRCUIT_PURPOSE_S_CONNECT_REND, flags);
  crypto_rand((char *) circ->hs_ident->rendezvous_cookie, REND_COOKIE_LEN);
  crypto_rand((char *) circ->hs_ident->rendezvous_handshake_info,
              sizeof(circ->hs_ident->rendezvous_handshake_info));

  /* No service associated with this circuit. */
  setup_full_capture_of_logs(LOG_WARN);
  hs_service_circuit_has_opened(circ);
  expect_log_msg_containing("Unknown service identity key");
  teardown_capture_of_logs();
  /* This should be set to a non zero timestamp. */
  tt_u64_op(TO_CIRCUIT(circ)->timestamp_dirty, OP_NE, 0);

  /* Set a service for this circuit. */
  service = helper_create_service();
  ed25519_pubkey_copy(&circ->hs_ident->identity_pk,
                      &service->keys.identity_pk);
  /* Should be all good. */
  hs_service_circuit_has_opened(circ);
  tt_int_op(TO_CIRCUIT(circ)->purpose, OP_EQ, CIRCUIT_PURPOSE_S_REND_JOINED);

 done:
  circuit_free(TO_CIRCUIT(circ));
  hs_free_all();
  UNMOCK(circuit_mark_for_close_);
  UNMOCK(relay_send_command_from_edge_);
}

static void
mock_assert_circuit_ok(const circuit_t *c)
{
  (void) c;
  return;
}

/** Test for the general mechanism for closing intro circs.
 *  Also a way to identify that #23603 has been fixed. */
static void
test_closing_intro_circs(void *arg)
{
  hs_service_t *service = NULL;
  hs_service_intro_point_t *ip = NULL, *entry = NULL;
  origin_circuit_t *intro_circ = NULL, *tmp_circ;
  int flags = CIRCLAUNCH_NEED_UPTIME | CIRCLAUNCH_IS_INTERNAL;

  (void) arg;

  MOCK(assert_circuit_ok, mock_assert_circuit_ok);

  hs_init();

  /* Initialize service */
  service = helper_create_service();
  /* Initialize intro point */
  ip = helper_create_service_ip();
  tt_assert(ip);
  service_intro_point_add(service->desc_current->intro_points.map, ip);

  /* Initialize intro circuit */
  intro_circ = origin_circuit_init(CIRCUIT_PURPOSE_S_ESTABLISH_INTRO, flags);
  intro_circ->hs_ident = hs_ident_circuit_new(&service->keys.identity_pk,
                                              HS_IDENT_CIRCUIT_INTRO);
  /* Register circuit in the circuitmap . */
  hs_circuitmap_register_intro_circ_v3_service_side(intro_circ,
                                                    &ip->auth_key_kp.pubkey);
  tmp_circ =
    hs_circuitmap_get_intro_circ_v3_service_side(&ip->auth_key_kp.pubkey);
  tt_ptr_op(tmp_circ, OP_EQ, intro_circ);

  /* Pretend that intro point has failed too much */
  ip->circuit_retries = MAX_INTRO_POINT_CIRCUIT_RETRIES+1;

  /* Now pretend we are freeing this intro circuit. We want to see that our
   * destructor is not gonna kill our intro point structure since that's the
   * job of the cleanup routine. */
  circuit_free(TO_CIRCUIT(intro_circ));
  intro_circ = NULL;
  entry = service_intro_point_find(service, &ip->auth_key_kp.pubkey);
  tt_assert(entry);
  /* The free should also remove the circuit from the circuitmap. */
  tmp_circ =
    hs_circuitmap_get_intro_circ_v3_service_side(&ip->auth_key_kp.pubkey);
  tt_assert(!tmp_circ);

  /* Now pretend that a new intro point circ was launched and opened. Check
   * that the intro point will be established correctly. */
  intro_circ = origin_circuit_init(CIRCUIT_PURPOSE_S_ESTABLISH_INTRO, flags);
  intro_circ->hs_ident = hs_ident_circuit_new(&service->keys.identity_pk,
                                              HS_IDENT_CIRCUIT_INTRO);
  ed25519_pubkey_copy(&intro_circ->hs_ident->intro_auth_pk,
                      &ip->auth_key_kp.pubkey);
  /* Register circuit in the circuitmap . */
  hs_circuitmap_register_intro_circ_v3_service_side(intro_circ,
                                                    &ip->auth_key_kp.pubkey);
  tmp_circ =
    hs_circuitmap_get_intro_circ_v3_service_side(&ip->auth_key_kp.pubkey);
  tt_ptr_op(tmp_circ, OP_EQ, intro_circ);
  tt_int_op(TO_CIRCUIT(intro_circ)->marked_for_close, OP_EQ, 0);
  circuit_mark_for_close(TO_CIRCUIT(intro_circ), END_CIRC_REASON_INTERNAL);
  tt_int_op(TO_CIRCUIT(intro_circ)->marked_for_close, OP_NE, 0);
  /* At this point, we should not be able to find it in the circuitmap. */
  tmp_circ =
    hs_circuitmap_get_intro_circ_v3_service_side(&ip->auth_key_kp.pubkey);
  tt_assert(!tmp_circ);

 done:
  if (intro_circ) {
    circuit_free(TO_CIRCUIT(intro_circ));
  }
  /* Frees the service object. */
  hs_free_all();
  UNMOCK(assert_circuit_ok);
}

/** Test sending and receiving introduce2 cells */
static void
test_introduce2(void *arg)
{
  int ret;
  int flags = CIRCLAUNCH_NEED_UPTIME | CIRCLAUNCH_IS_INTERNAL;
  uint8_t payload[RELAY_PAYLOAD_SIZE] = {0};
  origin_circuit_t *circ = NULL;
  hs_service_t *service;
  hs_service_intro_point_t *ip = NULL;

  (void) arg;

  hs_init();
  MOCK(circuit_mark_for_close_, mock_circuit_mark_for_close);
  MOCK(get_or_state,
       get_or_state_replacement);

  dummy_state = tor_malloc_zero(sizeof(or_state_t));

  circ = helper_create_origin_circuit(CIRCUIT_PURPOSE_S_INTRO, flags);
  tt_assert(circ);

  /* Test a wrong purpose. */
  TO_CIRCUIT(circ)->purpose = CIRCUIT_PURPOSE_S_ESTABLISH_INTRO;
  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_service_receive_introduce2(circ, payload, sizeof(payload));
  tt_int_op(ret, OP_EQ, -1);
  expect_log_msg_containing("Received an INTRODUCE2 cell on a "
                            "non introduction circuit of purpose");
  teardown_capture_of_logs();

  /* Back to normal. */
  TO_CIRCUIT(circ)->purpose = CIRCUIT_PURPOSE_S_INTRO;

  /* No service associated to it. */
  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_service_receive_introduce2(circ, payload, sizeof(payload));
  tt_int_op(ret, OP_EQ, -1);
  expect_log_msg_containing("Unknown service identity key");
  teardown_capture_of_logs();

  /* Set a service for this circuit. */
  service = helper_create_service();
  ed25519_pubkey_copy(&circ->hs_ident->identity_pk,
                      &service->keys.identity_pk);
  /* No introduction point associated to it. */
  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_service_receive_introduce2(circ, payload, sizeof(payload));
  tt_int_op(ret, OP_EQ, -1);
  expect_log_msg_containing("Unknown introduction auth key when handling "
                            "an INTRODUCE2 cell on circuit");
  teardown_capture_of_logs();

  /* Set an IP object now for this circuit. */
  {
    ip = helper_create_service_ip();
    service_intro_point_add(service->desc_current->intro_points.map, ip);
    /* Update ident to contain the intro point auth key. */
    ed25519_pubkey_copy(&circ->hs_ident->intro_auth_pk,
                        &ip->auth_key_kp.pubkey);
  }

  /* This will fail because receiving an INTRODUCE2 cell implies a valid cell
   * and then launching circuits so let's not do that and instead test that
   * behaviour differently. */
  ret = hs_service_receive_introduce2(circ, payload, sizeof(payload));
  tt_int_op(ret, OP_EQ, -1);
  tt_u64_op(ip->introduce2_count, OP_EQ, 0);

 done:
  or_state_free(dummy_state);
  dummy_state = NULL;
  if (circ)
    circuit_free(TO_CIRCUIT(circ));
  hs_free_all();
  UNMOCK(circuit_mark_for_close_);
}

/** Test basic hidden service housekeeping operations (maintaining intro
 *  points, etc) */
static void
test_service_event(void *arg)
{
  int flags = CIRCLAUNCH_NEED_UPTIME | CIRCLAUNCH_IS_INTERNAL;
  time_t now = time(NULL);
  hs_service_t *service;
  origin_circuit_t *circ = NULL;

  (void) arg;

  hs_init();
  MOCK(circuit_mark_for_close_, mock_circuit_mark_for_close);

  circ = helper_create_origin_circuit(CIRCUIT_PURPOSE_S_INTRO, flags);

  /* Set a service for this circuit. */
  service = helper_create_service();
  ed25519_pubkey_copy(&circ->hs_ident->identity_pk,
                      &service->keys.identity_pk);

  /* Currently this consists of cleaning invalid intro points. So adding IPs
   * here that should get cleaned up. */
  {
    hs_service_intro_point_t *ip = helper_create_service_ip();
    service_intro_point_add(service->desc_current->intro_points.map, ip);
    /* This run will remove the IP because we have no circuits nor node_t
     * associated with it. */
    run_housekeeping_event(now);
    tt_int_op(digest256map_size(service->desc_current->intro_points.map),
              OP_EQ, 0);
    /* We'll trigger a removal because we've reached our maximum amount of
     * times we should retry a circuit. For this, we need to have a node_t
     * that matches the identity of this IP. */
    routerinfo_t ri;
    memset(&ri, 0, sizeof(ri));
    ip = helper_create_service_ip();
    service_intro_point_add(service->desc_current->intro_points.map, ip);
    memset(ri.cache_info.identity_digest, 'A', DIGEST_LEN);
    /* This triggers a node_t creation. */
    tt_assert(nodelist_set_routerinfo(&ri, NULL));
    ip->circuit_retries = MAX_INTRO_POINT_CIRCUIT_RETRIES + 1;
    run_housekeeping_event(now);
    tt_int_op(digest256map_size(service->desc_current->intro_points.map),
              OP_EQ, 0);
    /* No removal but no circuit so this means the IP object will stay in the
     * descriptor map so we can retry it. */
    ip = helper_create_service_ip();
    service_intro_point_add(service->desc_current->intro_points.map, ip);
    ip->circuit_established = 1;  /* We'll test that, it MUST be 0 after. */
    run_housekeeping_event(now);
    tt_int_op(digest256map_size(service->desc_current->intro_points.map),
              OP_EQ, 1);
    /* Remove the IP object at once for the next test. */
    ip->circuit_retries = MAX_INTRO_POINT_CIRCUIT_RETRIES + 1;
    run_housekeeping_event(now);
    tt_int_op(digest256map_size(service->desc_current->intro_points.map),
              OP_EQ, 0);
    /* Now, we'll create an IP with a registered circuit. The IP object
     * shouldn't go away. */
    ip = helper_create_service_ip();
    service_intro_point_add(service->desc_current->intro_points.map, ip);
    ed25519_pubkey_copy(&circ->hs_ident->intro_auth_pk,
                        &ip->auth_key_kp.pubkey);
    hs_circuitmap_register_intro_circ_v3_service_side(
                                         circ, &ip->auth_key_kp.pubkey);
    run_housekeeping_event(now);
    tt_int_op(digest256map_size(service->desc_current->intro_points.map),
              OP_EQ, 1);
    /* We'll mangle the IP object to expire. */
    ip->time_to_expire = now;
    run_housekeeping_event(now);
    tt_int_op(digest256map_size(service->desc_current->intro_points.map),
              OP_EQ, 0);
  }

 done:
  hs_circuitmap_remove_circuit(TO_CIRCUIT(circ));
  circuit_free(TO_CIRCUIT(circ));
  hs_free_all();
  UNMOCK(circuit_mark_for_close_);
}

/** Test that we rotate descriptors correctly. */
static void
test_rotate_descriptors(void *arg)
{
  int ret;
  time_t next_rotation_time, now = time(NULL);
  hs_service_t *service;
  hs_service_descriptor_t *desc_next;

  (void) arg;

  dummy_state = tor_malloc_zero(sizeof(or_state_t));

  hs_init();
  MOCK(get_or_state, get_or_state_replacement);
  MOCK(circuit_mark_for_close_, mock_circuit_mark_for_close);
  MOCK(networkstatus_get_live_consensus,
       mock_networkstatus_get_live_consensus);

  /* Descriptor rotation happens with a consensus with a new SRV. */

  ret = parse_rfc1123_time("Sat, 26 Oct 1985 13:00:00 UTC",
                           &mock_ns.valid_after);
  tt_int_op(ret, OP_EQ, 0);
  ret = parse_rfc1123_time("Sat, 26 Oct 1985 14:00:00 UTC",
                           &mock_ns.fresh_until);
  tt_int_op(ret, OP_EQ, 0);
  dirvote_recalculate_timing(get_options(), mock_ns.valid_after);

  /* Create a service with a default descriptor and state. It's added to the
   * global map. */
  service = helper_create_service();
  service_descriptor_free(service->desc_current);
  service->desc_current = NULL;
  /* This triggers a build for both descriptors. The time now is only used in
   * the descriptor certificate which is important to be now else the decoding
   * will complain that the cert has expired if we use valid_after. */
  build_all_descriptors(now);
  tt_assert(service->desc_current);
  tt_assert(service->desc_next);

  /* Tweak our service next rotation time so we can use a custom time. */
  service->state.next_rotation_time = next_rotation_time =
    mock_ns.valid_after + (11 * 60 * 60);

  /* Nothing should happen, we are not at a new SRV. Our next rotation time
   * should be untouched. */
  rotate_all_descriptors(mock_ns.valid_after);
  tt_u64_op(service->state.next_rotation_time, OP_EQ, next_rotation_time);
  tt_assert(service->desc_current);
  tt_assert(service->desc_next);
  tt_u64_op(service->desc_current->time_period_num, OP_EQ,
            hs_get_previous_time_period_num(0));
  tt_u64_op(service->desc_next->time_period_num, OP_EQ,
            hs_get_time_period_num(0));
  /* Keep a reference so we can compare it after rotation to the current. */
  desc_next = service->desc_next;

  /* Going right after a new SRV. */
  ret = parse_rfc1123_time("Sat, 27 Oct 1985 01:00:00 UTC",
                           &mock_ns.valid_after);
  tt_int_op(ret, OP_EQ, 0);
  ret = parse_rfc1123_time("Sat, 27 Oct 1985 02:00:00 UTC",
                           &mock_ns.fresh_until);
  tt_int_op(ret, OP_EQ, 0);
  dirvote_recalculate_timing(get_options(), mock_ns.valid_after);

  /* Note down what to expect for the next rotation time which is 01:00 + 23h
   * meaning 00:00:00. */
  next_rotation_time = mock_ns.valid_after + (23 * 60 * 60);
  /* We should have our next rotation time modified, our current descriptor
   * cleaned up and the next descriptor becoming the current. */
  rotate_all_descriptors(mock_ns.valid_after);
  tt_u64_op(service->state.next_rotation_time, OP_EQ, next_rotation_time);
  tt_mem_op(service->desc_current, OP_EQ, desc_next, sizeof(*desc_next));
  tt_assert(service->desc_next == NULL);

  /* A second time should do nothing. */
  rotate_all_descriptors(mock_ns.valid_after);
  tt_u64_op(service->state.next_rotation_time, OP_EQ, next_rotation_time);
  tt_mem_op(service->desc_current, OP_EQ, desc_next, sizeof(*desc_next));
  tt_assert(service->desc_next == NULL);

  build_all_descriptors(now);
  tt_mem_op(service->desc_current, OP_EQ, desc_next, sizeof(*desc_next));
  tt_u64_op(service->desc_current->time_period_num, OP_EQ,
            hs_get_time_period_num(0));
  tt_u64_op(service->desc_next->time_period_num, OP_EQ,
            hs_get_next_time_period_num(0));
  tt_assert(service->desc_next);

 done:
  hs_free_all();
  UNMOCK(get_or_state);
  UNMOCK(circuit_mark_for_close_);
  UNMOCK(networkstatus_get_live_consensus);
}

/** Test building descriptors: picking intro points, setting up their link
 *  specifiers, etc. */
static void
test_build_update_descriptors(void *arg)
{
  int ret;
  time_t now = time(NULL);
  node_t *node;
  hs_service_t *service;
  hs_service_intro_point_t *ip_cur, *ip_next;
  routerinfo_t ri;

  (void) arg;

  hs_init();

  MOCK(get_or_state,
       get_or_state_replacement);
  MOCK(networkstatus_get_live_consensus,
       mock_networkstatus_get_live_consensus);

  dummy_state = tor_malloc_zero(sizeof(or_state_t));

  ret = parse_rfc1123_time("Sat, 26 Oct 1985 03:00:00 UTC",
                           &mock_ns.valid_after);
  tt_int_op(ret, OP_EQ, 0);
  ret = parse_rfc1123_time("Sat, 26 Oct 1985 04:00:00 UTC",
                           &mock_ns.fresh_until);
  tt_int_op(ret, OP_EQ, 0);
  dirvote_recalculate_timing(get_options(), mock_ns.valid_after);

  /* Create a service without a current descriptor to trigger a build. */
  service = helper_create_service();
  tt_assert(service);
  /* Unfortunately, the helper creates a dummy descriptor so get rid of it. */
  service_descriptor_free(service->desc_current);
  service->desc_current = NULL;

  /* We have a fresh service so this should trigger a build for both
   * descriptors for specific time period that we'll test. */
  build_all_descriptors(now);
  /* Check *current* descriptor. */
  tt_assert(service->desc_current);
  tt_assert(service->desc_current->desc);
  tt_assert(service->desc_current->intro_points.map);
  /* The current time period is the one expected when starting at 03:00. */
  tt_u64_op(service->desc_current->time_period_num, OP_EQ,
            hs_get_time_period_num(0));
  /* This should be untouched, the update descriptor process changes it. */
  tt_u64_op(service->desc_current->next_upload_time, OP_EQ, 0);

  /* Check *next* descriptor. */
  tt_assert(service->desc_next);
  tt_assert(service->desc_next->desc);
  tt_assert(service->desc_next->intro_points.map);
  tt_assert(service->desc_current != service->desc_next);
  tt_u64_op(service->desc_next->time_period_num, OP_EQ,
            hs_get_next_time_period_num(0));
  /* This should be untouched, the update descriptor process changes it. */
  tt_u64_op(service->desc_next->next_upload_time, OP_EQ, 0);

  /* Time to test the update of those descriptors. At first, we have no node
   * in the routerlist so this will find NO suitable node for the IPs. */
  setup_full_capture_of_logs(LOG_INFO);
  update_all_descriptors(now);
  expect_log_msg_containing("Unable to find a suitable node to be an "
                            "introduction point for service");
  teardown_capture_of_logs();
  tt_int_op(digest256map_size(service->desc_current->intro_points.map),
            OP_EQ, 0);
  tt_int_op(digest256map_size(service->desc_next->intro_points.map),
            OP_EQ, 0);

  /* Now, we'll setup a node_t. */
  {
    tor_addr_t ipv4_addr;
    curve25519_secret_key_t curve25519_secret_key;

    memset(&ri, 0, sizeof(routerinfo_t));

    tor_addr_parse(&ipv4_addr, "127.0.0.1");
    ri.addr = tor_addr_to_ipv4h(&ipv4_addr);
    ri.or_port = 1337;
    ri.purpose = ROUTER_PURPOSE_GENERAL;
    /* Ugly yes but we never free the "ri" object so this just makes things
     * easier. */
    ri.protocol_list = (char *) "HSDir=1-2 LinkAuth=3";
    ret = curve25519_secret_key_generate(&curve25519_secret_key, 0);
    tt_int_op(ret, OP_EQ, 0);
    ri.onion_curve25519_pkey =
      tor_malloc_zero(sizeof(curve25519_public_key_t));
    ri.onion_pkey = crypto_pk_new();
    curve25519_public_key_generate(ri.onion_curve25519_pkey,
                                   &curve25519_secret_key);
    memset(ri.cache_info.identity_digest, 'A', DIGEST_LEN);
    /* Setup ed25519 identity */
    ed25519_keypair_t kp1;
    ed25519_keypair_generate(&kp1, 0);
    ri.cache_info.signing_key_cert = tor_malloc_zero(sizeof(tor_cert_t));
    tt_assert(ri.cache_info.signing_key_cert);
    ed25519_pubkey_copy(&ri.cache_info.signing_key_cert->signing_key,
                        &kp1.pubkey);
    nodelist_set_routerinfo(&ri, NULL);
    node = node_get_mutable_by_id(ri.cache_info.identity_digest);
    tt_assert(node);
    node->is_running = node->is_valid = node->is_fast = node->is_stable = 1;
  }

  /* We expect to pick only one intro point from the node above. */
  setup_full_capture_of_logs(LOG_INFO);
  update_all_descriptors(now);
  tor_free(node->ri->onion_curve25519_pkey); /* Avoid memleak. */
  tor_free(node->ri->cache_info.signing_key_cert);
  crypto_pk_free(node->ri->onion_pkey);
  expect_log_msg_containing("just picked 1 intro points and wanted 3 for next "
                            "descriptor. It currently has 0 intro points. "
                            "Launching ESTABLISH_INTRO circuit shortly.");
  teardown_capture_of_logs();
  tt_int_op(digest256map_size(service->desc_current->intro_points.map),
            OP_EQ, 1);
  tt_int_op(digest256map_size(service->desc_next->intro_points.map),
            OP_EQ, 1);
  /* Get the IP object. Because we don't have the auth key of the IP, we can't
   * query it so get the first element in the map. */
  {
    void *obj = NULL;
    const uint8_t *key;
    digest256map_iter_t *iter =
      digest256map_iter_init(service->desc_current->intro_points.map);
    digest256map_iter_get(iter, &key, &obj);
    tt_assert(obj);
    ip_cur = obj;
    /* Get also the IP from the next descriptor. We'll make sure it's not the
     * same object as in the current descriptor. */
    iter = digest256map_iter_init(service->desc_next->intro_points.map);
    digest256map_iter_get(iter, &key, &obj);
    tt_assert(obj);
    ip_next = obj;
  }
  tt_mem_op(ip_cur, OP_NE, ip_next, sizeof(hs_desc_intro_point_t));

  /* We won't test the service IP object because there is a specific test
   * already for this but we'll make sure that the state is coherent.*/

  /* Three link specifiers are mandatoy so make sure we do have them. */
  tt_int_op(smartlist_len(ip_cur->base.link_specifiers), OP_EQ, 3);
  /* Make sure we have a valid encryption keypair generated when we pick an
   * intro point in the update process. */
  tt_assert(!tor_mem_is_zero((char *) ip_cur->enc_key_kp.seckey.secret_key,
                             CURVE25519_SECKEY_LEN));
  tt_assert(!tor_mem_is_zero((char *) ip_cur->enc_key_kp.pubkey.public_key,
                             CURVE25519_PUBKEY_LEN));
  tt_u64_op(ip_cur->time_to_expire, OP_GE, now +
            INTRO_POINT_LIFETIME_MIN_SECONDS);
  tt_u64_op(ip_cur->time_to_expire, OP_LE, now +
            INTRO_POINT_LIFETIME_MAX_SECONDS);

  /* Now, we will try to set up a service after a new time period has started
   * and see if it behaves as expected. */

  ret = parse_rfc1123_time("Sat, 26 Oct 1985 13:00:00 UTC",
                           &mock_ns.valid_after);
  tt_int_op(ret, OP_EQ, 0);
  ret = parse_rfc1123_time("Sat, 26 Oct 1985 14:00:00 UTC",
                           &mock_ns.fresh_until);
  tt_int_op(ret, OP_EQ, 0);

  /* Create a service without a current descriptor to trigger a build. */
  service = helper_create_service();
  tt_assert(service);
  /* Unfortunately, the helper creates a dummy descriptor so get rid of it. */
  service_descriptor_free(service->desc_current);
  service->desc_current = NULL;

  /* We have a fresh service so this should trigger a build for both
   * descriptors for specific time period that we'll test. */
  build_all_descriptors(now);
  /* Check *current* descriptor. */
  tt_assert(service->desc_current);
  tt_assert(service->desc_current->desc);
  tt_assert(service->desc_current->intro_points.map);
  /* This should be for the previous time period. */
  tt_u64_op(service->desc_current->time_period_num, OP_EQ,
            hs_get_previous_time_period_num(0));
  /* This should be untouched, the update descriptor process changes it. */
  tt_u64_op(service->desc_current->next_upload_time, OP_EQ, 0);

  /* Check *next* descriptor. */
  tt_assert(service->desc_next);
  tt_assert(service->desc_next->desc);
  tt_assert(service->desc_next->intro_points.map);
  tt_assert(service->desc_current != service->desc_next);
  tt_u64_op(service->desc_next->time_period_num, OP_EQ,
            hs_get_time_period_num(0));
  /* This should be untouched, the update descriptor process changes it. */
  tt_u64_op(service->desc_next->next_upload_time, OP_EQ, 0);

  /* Let's remove the next descriptor to simulate a rotation. */
  service_descriptor_free(service->desc_next);
  service->desc_next = NULL;

  build_all_descriptors(now);
  /* Check *next* descriptor. */
  tt_assert(service->desc_next);
  tt_assert(service->desc_next->desc);
  tt_assert(service->desc_next->intro_points.map);
  tt_assert(service->desc_current != service->desc_next);
  tt_u64_op(service->desc_next->time_period_num, OP_EQ,
            hs_get_next_time_period_num(0));
  /* This should be untouched, the update descriptor process changes it. */
  tt_u64_op(service->desc_next->next_upload_time, OP_EQ, 0);

 done:
  hs_free_all();
  nodelist_free_all();
}

static void
test_upload_descriptors(void *arg)
{
  int ret;
  time_t now = time(NULL);
  hs_service_t *service;

  (void) arg;

  hs_init();
  MOCK(get_or_state,
       get_or_state_replacement);
  MOCK(networkstatus_get_live_consensus,
       mock_networkstatus_get_live_consensus);

  dummy_state = tor_malloc_zero(sizeof(or_state_t));

  ret = parse_rfc1123_time("Sat, 26 Oct 1985 13:00:00 UTC",
                           &mock_ns.valid_after);
  tt_int_op(ret, OP_EQ, 0);
  ret = parse_rfc1123_time("Sat, 26 Oct 1985 14:00:00 UTC",
                           &mock_ns.fresh_until);
  tt_int_op(ret, OP_EQ, 0);

  /* Create a service with no descriptor. It's added to the global map. */
  service = hs_service_new(get_options());
  tt_assert(service);
  service->config.version = HS_VERSION_THREE;
  ed25519_secret_key_generate(&service->keys.identity_sk, 0);
  ed25519_public_key_generate(&service->keys.identity_pk,
                              &service->keys.identity_sk);
  /* Register service to global map. */
  ret = register_service(get_hs_service_map(), service);
  tt_int_op(ret, OP_EQ, 0);
  /* But first, build our descriptor. */
  build_all_descriptors(now);

  /* Nothing should happen because we have 0 introduction circuit established
   * and we want (by default) 3 intro points. */
  run_upload_descriptor_event(now);
  /* If no upload happened, this should be untouched. */
  tt_u64_op(service->desc_current->next_upload_time, OP_EQ, 0);
  /* We'll simulate that we've opened our intro point circuit and that we only
   * want one intro point. */
  service->config.num_intro_points = 1;

  /* Set our next upload time after now which will skip the upload. */
  service->desc_current->next_upload_time = now + 1000;
  run_upload_descriptor_event(now);
  /* If no upload happened, this should be untouched. */
  tt_u64_op(service->desc_current->next_upload_time, OP_EQ, now + 1000);

 done:
  hs_free_all();
  UNMOCK(get_or_state);
}

/** Test the functions that save and load HS revision counters to state. */
static void
test_revision_counter_state(void *arg)
{
  char *state_line_one = NULL;
  char *state_line_two = NULL;

  hs_service_descriptor_t *desc_one = service_descriptor_new();
  hs_service_descriptor_t *desc_two = service_descriptor_new();

  (void) arg;

  /* Prepare both descriptors */
  desc_one->desc->plaintext_data.revision_counter = 42;
  desc_two->desc->plaintext_data.revision_counter = 240;
  memset(&desc_one->blinded_kp.pubkey.pubkey, 66,
         sizeof(desc_one->blinded_kp.pubkey.pubkey));
  memset(&desc_two->blinded_kp.pubkey.pubkey, 240,
         sizeof(desc_one->blinded_kp.pubkey.pubkey));

  /* Turn the descriptor rev counters into state lines */
  state_line_one = encode_desc_rev_counter_for_state(desc_one);
  tt_str_op(state_line_one, OP_EQ,
            "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI 42");

  state_line_two = encode_desc_rev_counter_for_state(desc_two);
  tt_str_op(state_line_two, OP_EQ,
            "8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PA 240");

  /* Now let's test our state parsing function: */
  int service_found;
  uint64_t cached_rev_counter;

  /* First's try with wrong pubkey and check that no service was found */
  cached_rev_counter =check_state_line_for_service_rev_counter(state_line_one,
                                                 &desc_two->blinded_kp.pubkey,
                                                               &service_found);
  tt_int_op(service_found, OP_EQ, 0);
  tt_u64_op(cached_rev_counter, OP_EQ, 0);

  /* Now let's try with the right pubkeys */
  cached_rev_counter =check_state_line_for_service_rev_counter(state_line_one,
                                                 &desc_one->blinded_kp.pubkey,
                                                               &service_found);
  tt_int_op(service_found, OP_EQ, 1);
  tt_u64_op(cached_rev_counter, OP_EQ, 42);

  cached_rev_counter =check_state_line_for_service_rev_counter(state_line_two,
                                                 &desc_two->blinded_kp.pubkey,
                                                               &service_found);
  tt_int_op(service_found, OP_EQ, 1);
  tt_u64_op(cached_rev_counter, OP_EQ, 240);

 done:
  tor_free(state_line_one);
  tor_free(state_line_two);
  service_descriptor_free(desc_one);
  service_descriptor_free(desc_two);
}

/** Global vars used by test_rendezvous1_parsing() */
static char rend1_payload[RELAY_PAYLOAD_SIZE];
static size_t rend1_payload_len = 0;

/** Mock for relay_send_command_from_edge() to send a RENDEZVOUS1 cell. Instead
 *  of sending it to the network, instead save it to the global `rend1_payload`
 *  variable so that we can inspect it in the test_rendezvous1_parsing()
 *  test. */
static int
mock_relay_send_rendezvous1(streamid_t stream_id, circuit_t *circ,
                            uint8_t relay_command, const char *payload,
                            size_t payload_len,
                            crypt_path_t *cpath_layer,
                            const char *filename, int lineno)
{
  (void) stream_id;
  (void) circ;
  (void) relay_command;
  (void) cpath_layer;
  (void) filename;
  (void) lineno;

  memcpy(rend1_payload, payload, payload_len);
  rend1_payload_len = payload_len;

  return 0;
}

/** Send a RENDEZVOUS1 as a service, and parse it as a client. */
static void
test_rendezvous1_parsing(void *arg)
{
  int retval;
  static const char *test_addr =
    "4acth47i6kxnvkewtm6q7ib2s3ufpo5sqbsnzjpbi7utijcltosqemad.onion";
  hs_service_t *service = NULL;
  origin_circuit_t *service_circ = NULL;
  origin_circuit_t *client_circ = NULL;
  ed25519_keypair_t ip_auth_kp;
  curve25519_keypair_t ephemeral_kp;
  curve25519_keypair_t client_kp;
  curve25519_keypair_t ip_enc_kp;
  int flags = CIRCLAUNCH_NEED_UPTIME | CIRCLAUNCH_IS_INTERNAL;

  (void) arg;

  MOCK(relay_send_command_from_edge_, mock_relay_send_rendezvous1);

  {
    /* Let's start by setting up the service that will start the rend */
    service = tor_malloc_zero(sizeof(hs_service_t));
    ed25519_secret_key_generate(&service->keys.identity_sk, 0);
    ed25519_public_key_generate(&service->keys.identity_pk,
                                &service->keys.identity_sk);
    memcpy(service->onion_address, test_addr, sizeof(service->onion_address));
    tt_assert(service);
  }

  {
    /* Now let's set up the service rendezvous circuit and its keys. */
    service_circ = helper_create_origin_circuit(CIRCUIT_PURPOSE_S_CONNECT_REND,
                                                flags);
    tor_free(service_circ->hs_ident);
    hs_ntor_rend_cell_keys_t hs_ntor_rend_cell_keys;
    uint8_t rendezvous_cookie[HS_REND_COOKIE_LEN];
    curve25519_keypair_generate(&ip_enc_kp, 0);
    curve25519_keypair_generate(&ephemeral_kp, 0);
    curve25519_keypair_generate(&client_kp, 0);
    ed25519_keypair_generate(&ip_auth_kp, 0);
    retval = hs_ntor_service_get_rendezvous1_keys(&ip_auth_kp.pubkey,
                                                  &ip_enc_kp,
                                                  &ephemeral_kp,
                                                  &client_kp.pubkey,
                                                  &hs_ntor_rend_cell_keys);
    tt_int_op(retval, OP_EQ, 0);

    memset(rendezvous_cookie, 2, sizeof(rendezvous_cookie));
    service_circ->hs_ident =
      create_rp_circuit_identifier(service, rendezvous_cookie,
                                   &ephemeral_kp.pubkey,
                                   &hs_ntor_rend_cell_keys);
  }

  /* Send out the RENDEZVOUS1 and make sure that our mock func worked */
  tt_assert(tor_mem_is_zero(rend1_payload, 32));
  hs_circ_service_rp_has_opened(service, service_circ);
  tt_assert(!tor_mem_is_zero(rend1_payload, 32));
  tt_int_op(rend1_payload_len, OP_EQ, HS_LEGACY_RENDEZVOUS_CELL_SIZE);

  /******************************/

  /** Now let's create the client rendezvous circuit */
  client_circ =
    helper_create_origin_circuit(CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED,
                                 flags);
  /* fix up its circ ident */
  ed25519_pubkey_copy(&client_circ->hs_ident->intro_auth_pk,
                      &ip_auth_kp.pubkey);
  memcpy(&client_circ->hs_ident->rendezvous_client_kp,
         &client_kp, sizeof(client_circ->hs_ident->rendezvous_client_kp));
  memcpy(&client_circ->hs_ident->intro_enc_pk.public_key,
         &ip_enc_kp.pubkey.public_key,
         sizeof(client_circ->hs_ident->intro_enc_pk.public_key));

  /* Now parse the rendezvous2 circuit and make sure it was fine. We are
   * skipping 20 bytes off its payload, since that's the rendezvous cookie
   * which is only present in REND1. */
  retval = handle_rendezvous2(client_circ,
                              (uint8_t*)rend1_payload+20,
                              rend1_payload_len-20);
  tt_int_op(retval, OP_EQ, 0);

  /* TODO: We are only simulating client/service here. We could also simulate
   * the rendezvous point by plugging in rend_mid_establish_rendezvous(). We
   * would need an extra circuit and some more stuff but it's doable. */

 done:
  circuit_free(TO_CIRCUIT(service_circ));
  circuit_free(TO_CIRCUIT(client_circ));
  hs_service_free(service);
  hs_free_all();
  UNMOCK(relay_send_command_from_edge_);
}

struct testcase_t hs_service_tests[] = {
  { "e2e_rend_circuit_setup", test_e2e_rend_circuit_setup, TT_FORK,
    NULL, NULL },
  { "load_keys", test_load_keys, TT_FORK,
    NULL, NULL },
  { "access_service", test_access_service, TT_FORK,
    NULL, NULL },
  { "service_intro_point", test_service_intro_point, TT_FORK,
    NULL, NULL },
  { "helper_functions", test_helper_functions, TT_FORK,
    NULL, NULL },
  { "intro_circuit_opened", test_intro_circuit_opened, TT_FORK,
    NULL, NULL },
  { "intro_established", test_intro_established, TT_FORK,
    NULL, NULL },
  { "closing_intro_circs", test_closing_intro_circs, TT_FORK,
    NULL, NULL },
  { "rdv_circuit_opened", test_rdv_circuit_opened, TT_FORK,
    NULL, NULL },
  { "introduce2", test_introduce2, TT_FORK,
    NULL, NULL },
  { "service_event", test_service_event, TT_FORK,
    NULL, NULL },
  { "rotate_descriptors", test_rotate_descriptors, TT_FORK,
    NULL, NULL },
  { "build_update_descriptors", test_build_update_descriptors, TT_FORK,
    NULL, NULL },
  { "upload_descriptors", test_upload_descriptors, TT_FORK,
    NULL, NULL },
  { "revision_counter_state", test_revision_counter_state, TT_FORK,
    NULL, NULL },
  { "rendezvous1_parsing", test_rendezvous1_parsing, TT_FORK,
    NULL, NULL },

  END_OF_TESTCASES
};

