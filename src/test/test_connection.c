/* Copyright (c) 2015-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"

#define CONNECTION_PRIVATE
#define MAIN_PRIVATE
#define CONNECTION_OR_PRIVATE

#include "or.h"
#include "test.h"

#include "connection.h"
#include "hs_common.h"
#include "main.h"
#include "microdesc.h"
#include "nodelist.h"
#include "networkstatus.h"
#include "rendcache.h"
#include "directory.h"
#include "connection_or.h"

#include "test_connection.h"
#include "test_helpers.h"

static void * test_conn_get_basic_setup(const struct testcase_t *tc);
static int test_conn_get_basic_teardown(const struct testcase_t *tc,
                                        void *arg);

static void * test_conn_get_rend_setup(const struct testcase_t *tc);
static int test_conn_get_rend_teardown(const struct testcase_t *tc,
                                        void *arg);

static void * test_conn_get_rsrc_setup(const struct testcase_t *tc);
static int test_conn_get_rsrc_teardown(const struct testcase_t *tc,
                                        void *arg);

/* Arbitrary choice - IPv4 Directory Connection to localhost */
#define TEST_CONN_TYPE          (CONN_TYPE_DIR)
/* We assume every machine has IPv4 localhost, is that ok? */
#define TEST_CONN_ADDRESS       "127.0.0.1"
#define TEST_CONN_PORT          (12345)
#define TEST_CONN_ADDRESS_PORT  "127.0.0.1:12345"
#define TEST_CONN_FAMILY        (AF_INET)
#define TEST_CONN_STATE         (DIR_CONN_STATE_MIN_)
#define TEST_CONN_ADDRESS_2     "127.0.0.2"

#define TEST_CONN_BASIC_PURPOSE (DIR_PURPOSE_MIN_)

#define TEST_CONN_REND_ADDR     "cfs3rltphxxvabci"
#define TEST_CONN_REND_PURPOSE  (DIR_PURPOSE_FETCH_RENDDESC_V2)
#define TEST_CONN_REND_PURPOSE_SUCCESSFUL (DIR_PURPOSE_HAS_FETCHED_RENDDESC_V2)
#define TEST_CONN_REND_TYPE_2   (CONN_TYPE_AP)
#define TEST_CONN_REND_ADDR_2   "icbavxxhptlr3sfc"

#define TEST_CONN_RSRC          (networkstatus_get_flavor_name(FLAV_MICRODESC))
#define TEST_CONN_RSRC_PURPOSE  (DIR_PURPOSE_FETCH_CONSENSUS)
#define TEST_CONN_RSRC_STATE_SUCCESSFUL (DIR_CONN_STATE_CLIENT_FINISHED)
#define TEST_CONN_RSRC_2        (networkstatus_get_flavor_name(FLAV_NS))

#define TEST_CONN_DL_STATE      (DIR_CONN_STATE_CLIENT_READING)

/* see AP_CONN_STATE_IS_UNATTACHED() */
#define TEST_CONN_UNATTACHED_STATE (AP_CONN_STATE_CIRCUIT_WAIT)
#define TEST_CONN_ATTACHED_STATE   (AP_CONN_STATE_CONNECT_WAIT)

void
test_conn_lookup_addr_helper(const char *address, int family, tor_addr_t *addr)
{
  int rv = 0;

  tt_assert(addr);

  rv = tor_addr_lookup(address, family, addr);
  /* XXXX - should we retry on transient failure? */
  tt_int_op(rv, OP_EQ, 0);
  tt_assert(tor_addr_is_loopback(addr));
  tt_assert(tor_addr_is_v4(addr));

  return;

 done:
  tor_addr_make_null(addr, TEST_CONN_FAMILY);
}

static void *
test_conn_get_basic_setup(const struct testcase_t *tc)
{
  (void)tc;
  return test_conn_get_connection(TEST_CONN_STATE, TEST_CONN_TYPE,
                                  TEST_CONN_BASIC_PURPOSE);
}

static int
test_conn_get_basic_teardown(const struct testcase_t *tc, void *arg)
{
  (void)tc;
  connection_t *conn = arg;

  tt_assert(conn);
  assert_connection_ok(conn, time(NULL));

  /* teardown the connection as fast as possible */
  if (conn->linked_conn) {
    assert_connection_ok(conn->linked_conn, time(NULL));

    /* We didn't call tor_libevent_initialize(), so event_base was NULL,
     * so we can't rely on connection_unregister_events() use of event_del().
     */
    if (conn->linked_conn->read_event) {
      tor_free(conn->linked_conn->read_event);
      conn->linked_conn->read_event = NULL;
    }
    if (conn->linked_conn->write_event) {
      tor_free(conn->linked_conn->write_event);
      conn->linked_conn->write_event = NULL;
    }

    if (!conn->linked_conn->marked_for_close) {
      connection_close_immediate(conn->linked_conn);
      if (CONN_IS_EDGE(conn->linked_conn)) {
        /* Suppress warnings about all the stuff we didn't do */
        TO_EDGE_CONN(conn->linked_conn)->edge_has_sent_end = 1;
        TO_EDGE_CONN(conn->linked_conn)->end_reason =
          END_STREAM_REASON_INTERNAL;
        if (conn->linked_conn->type == CONN_TYPE_AP) {
          TO_ENTRY_CONN(conn->linked_conn)->socks_request->has_finished = 1;
        }
      }
      connection_mark_for_close(conn->linked_conn);
    }

    close_closeable_connections();
  }

  /* We didn't set the events up properly, so we can't use event_del() in
   * close_closeable_connections() > connection_free()
   * > connection_unregister_events() */
  if (conn->read_event) {
    tor_free(conn->read_event);
    conn->read_event = NULL;
  }
  if (conn->write_event) {
    tor_free(conn->write_event);
    conn->write_event = NULL;
  }

  if (!conn->marked_for_close) {
    connection_close_immediate(conn);
    if (CONN_IS_EDGE(conn)) {
      /* Suppress warnings about all the stuff we didn't do */
      TO_EDGE_CONN(conn)->edge_has_sent_end = 1;
      TO_EDGE_CONN(conn)->end_reason = END_STREAM_REASON_INTERNAL;
      if (conn->type == CONN_TYPE_AP) {
        TO_ENTRY_CONN(conn)->socks_request->has_finished = 1;
      }
    }
    connection_mark_for_close(conn);
  }

  close_closeable_connections();

  /* The unit test will fail if we return 0 */
  return 1;

  /* When conn == NULL, we can't cleanup anything */
 done:
  return 0;
}

static void *
test_conn_get_rend_setup(const struct testcase_t *tc)
{
  dir_connection_t *conn = DOWNCAST(dir_connection_t,
                                    test_conn_get_connection(
                                                    TEST_CONN_STATE,
                                                    TEST_CONN_TYPE,
                                                    TEST_CONN_REND_PURPOSE));
  tt_assert(conn);
  assert_connection_ok(&conn->base_, time(NULL));

  rend_cache_init();

  /* TODO: use directory_initiate_request() to do this - maybe? */
  tor_assert(strlen(TEST_CONN_REND_ADDR) == REND_SERVICE_ID_LEN_BASE32);
  conn->rend_data = rend_data_client_create(TEST_CONN_REND_ADDR, NULL, NULL,
                                            REND_NO_AUTH);
  assert_connection_ok(&conn->base_, time(NULL));
  return conn;

  /* On failure */
 done:
  test_conn_get_rend_teardown(tc, conn);
  /* Returning NULL causes the unit test to fail */
  return NULL;
}

static int
test_conn_get_rend_teardown(const struct testcase_t *tc, void *arg)
{
  dir_connection_t *conn = DOWNCAST(dir_connection_t, arg);
  int rv = 0;

  tt_assert(conn);
  assert_connection_ok(&conn->base_, time(NULL));

  /* avoid a last-ditch attempt to refetch the descriptor */
  conn->base_.purpose = TEST_CONN_REND_PURPOSE_SUCCESSFUL;

  /* connection_free_() cleans up rend_data */
  rv = test_conn_get_basic_teardown(tc, arg);
 done:
  rend_cache_free_all();
  return rv;
}

static dir_connection_t *
test_conn_download_status_add_a_connection(const char *resource)
{
  dir_connection_t *conn = DOWNCAST(dir_connection_t,
                                    test_conn_get_connection(
                                                      TEST_CONN_STATE,
                                                      TEST_CONN_TYPE,
                                                      TEST_CONN_RSRC_PURPOSE));

  tt_assert(conn);
  assert_connection_ok(&conn->base_, time(NULL));

  /* Replace the existing resource with the one we want */
  if (resource) {
    if (conn->requested_resource) {
      tor_free(conn->requested_resource);
    }
    conn->requested_resource = tor_strdup(resource);
    assert_connection_ok(&conn->base_, time(NULL));
  }

  return conn;

 done:
  test_conn_get_rsrc_teardown(NULL, conn);
  return NULL;
}

static void *
test_conn_get_rsrc_setup(const struct testcase_t *tc)
{
  (void)tc;
  return test_conn_download_status_add_a_connection(TEST_CONN_RSRC);
}

static int
test_conn_get_rsrc_teardown(const struct testcase_t *tc, void *arg)
{
  int rv = 0;

  connection_t *conn = (connection_t *)arg;
  tt_assert(conn);
  assert_connection_ok(conn, time(NULL));

  if (conn->type == CONN_TYPE_DIR) {
    dir_connection_t *dir_conn = DOWNCAST(dir_connection_t, arg);

    tt_assert(dir_conn);
    assert_connection_ok(&dir_conn->base_, time(NULL));

    /* avoid a last-ditch attempt to refetch the consensus */
    dir_conn->base_.state = TEST_CONN_RSRC_STATE_SUCCESSFUL;
    assert_connection_ok(&dir_conn->base_, time(NULL));
  }

  /* connection_free_() cleans up requested_resource */
  rv = test_conn_get_basic_teardown(tc, conn);

 done:
  return rv;
}

static void *
test_conn_download_status_setup(const struct testcase_t *tc)
{
  return (void*)tc;
}

static int
test_conn_download_status_teardown(const struct testcase_t *tc, void *arg)
{
  (void)arg;
  int rv = 0;

  /* Ignore arg, and just loop through the connection array */
  SMARTLIST_FOREACH_BEGIN(get_connection_array(), connection_t *, conn) {
    if (conn) {
      assert_connection_ok(conn, time(NULL));

      /* connection_free_() cleans up requested_resource */
      rv = test_conn_get_rsrc_teardown(tc, conn);
      tt_int_op(rv, OP_EQ, 1);
    }
  } SMARTLIST_FOREACH_END(conn);

 done:
  return rv;
}

/* Like connection_ap_make_link(), but does much less */
static connection_t *
test_conn_get_linked_connection(connection_t *l_conn, uint8_t state)
{
  tt_assert(l_conn);
  assert_connection_ok(l_conn, time(NULL));

  /* AP connections don't seem to have purposes */
  connection_t *conn = test_conn_get_connection(state, CONN_TYPE_AP,
                                                       0);

  tt_assert(conn);
  assert_connection_ok(conn, time(NULL));

  conn->linked = 1;
  l_conn->linked = 1;
  conn->linked_conn = l_conn;
  l_conn->linked_conn = conn;
  /* we never opened a real socket, so we can just overwrite it */
  conn->s = TOR_INVALID_SOCKET;
  l_conn->s = TOR_INVALID_SOCKET;

  assert_connection_ok(conn, time(NULL));
  assert_connection_ok(l_conn, time(NULL));

  return conn;

 done:
  test_conn_download_status_teardown(NULL, NULL);
  return NULL;
}

static struct testcase_setup_t test_conn_get_basic_st = {
  test_conn_get_basic_setup, test_conn_get_basic_teardown
};

static struct testcase_setup_t test_conn_get_rend_st = {
  test_conn_get_rend_setup, test_conn_get_rend_teardown
};

static struct testcase_setup_t test_conn_get_rsrc_st = {
  test_conn_get_rsrc_setup, test_conn_get_rsrc_teardown
};

static struct testcase_setup_t test_conn_download_status_st = {
  test_conn_download_status_setup, test_conn_download_status_teardown
};

static void
test_conn_get_basic(void *arg)
{
  connection_t *conn = (connection_t*)arg;
  tor_addr_t addr, addr2;

  tt_assert(conn);
  assert_connection_ok(conn, time(NULL));

  test_conn_lookup_addr_helper(TEST_CONN_ADDRESS, TEST_CONN_FAMILY, &addr);
  tt_assert(!tor_addr_is_null(&addr));
  test_conn_lookup_addr_helper(TEST_CONN_ADDRESS_2, TEST_CONN_FAMILY, &addr2);
  tt_assert(!tor_addr_is_null(&addr2));

  /* Check that we get this connection back when we search for it by
   * its attributes, but get NULL when we supply a different value. */

  tt_assert(connection_get_by_global_id(conn->global_identifier) == conn);
  tt_ptr_op(connection_get_by_global_id(!conn->global_identifier), OP_EQ,
            NULL);

  tt_assert(connection_get_by_type(conn->type) == conn);
  tt_assert(connection_get_by_type(TEST_CONN_TYPE) == conn);
  tt_ptr_op(connection_get_by_type(!conn->type), OP_EQ, NULL);
  tt_ptr_op(connection_get_by_type(!TEST_CONN_TYPE), OP_EQ, NULL);

  tt_assert(connection_get_by_type_state(conn->type, conn->state)
            == conn);
  tt_assert(connection_get_by_type_state(TEST_CONN_TYPE, TEST_CONN_STATE)
            == conn);
  tt_assert(connection_get_by_type_state(!conn->type, !conn->state)
            == NULL);
  tt_assert(connection_get_by_type_state(!TEST_CONN_TYPE, !TEST_CONN_STATE)
            == NULL);

  /* Match on the connection fields themselves */
  tt_assert(connection_get_by_type_addr_port_purpose(conn->type,
                                                     &conn->addr,
                                                     conn->port,
                                                     conn->purpose)
            == conn);
  /* Match on the original inputs to the connection */
  tt_assert(connection_get_by_type_addr_port_purpose(TEST_CONN_TYPE,
                                                     &conn->addr,
                                                     conn->port,
                                                     conn->purpose)
            == conn);
  tt_assert(connection_get_by_type_addr_port_purpose(conn->type,
                                                     &addr,
                                                     conn->port,
                                                     conn->purpose)
            == conn);
  tt_assert(connection_get_by_type_addr_port_purpose(conn->type,
                                                     &conn->addr,
                                                     TEST_CONN_PORT,
                                                     conn->purpose)
            == conn);
  tt_assert(connection_get_by_type_addr_port_purpose(conn->type,
                                                     &conn->addr,
                                                     conn->port,
                                                     TEST_CONN_BASIC_PURPOSE)
            == conn);
  tt_assert(connection_get_by_type_addr_port_purpose(TEST_CONN_TYPE,
                                                     &addr,
                                                     TEST_CONN_PORT,
                                                     TEST_CONN_BASIC_PURPOSE)
            == conn);
  /* Then try each of the not-matching combinations */
  tt_assert(connection_get_by_type_addr_port_purpose(!conn->type,
                                                     &conn->addr,
                                                     conn->port,
                                                     conn->purpose)
            == NULL);
  tt_assert(connection_get_by_type_addr_port_purpose(conn->type,
                                                     &addr2,
                                                     conn->port,
                                                     conn->purpose)
            == NULL);
  tt_assert(connection_get_by_type_addr_port_purpose(conn->type,
                                                     &conn->addr,
                                                     !conn->port,
                                                     conn->purpose)
            == NULL);
  tt_assert(connection_get_by_type_addr_port_purpose(conn->type,
                                                     &conn->addr,
                                                     conn->port,
                                                     !conn->purpose)
            == NULL);
  /* Then try everything not-matching */
  tt_assert(connection_get_by_type_addr_port_purpose(!conn->type,
                                                     &addr2,
                                                     !conn->port,
                                                     !conn->purpose)
            == NULL);
  tt_assert(connection_get_by_type_addr_port_purpose(!TEST_CONN_TYPE,
                                                     &addr2,
                                                     !TEST_CONN_PORT,
                                                     !TEST_CONN_BASIC_PURPOSE)
            == NULL);

 done:
  ;
}

static void
test_conn_get_rend(void *arg)
{
  dir_connection_t *conn = DOWNCAST(dir_connection_t, arg);
  tt_assert(conn);
  assert_connection_ok(&conn->base_, time(NULL));

  tt_assert(connection_get_by_type_state_rendquery(
                                            conn->base_.type,
                                            conn->base_.state,
                                            rend_data_get_address(
                                                      conn->rend_data))
            == TO_CONN(conn));
  tt_assert(connection_get_by_type_state_rendquery(
                                            TEST_CONN_TYPE,
                                            TEST_CONN_STATE,
                                            TEST_CONN_REND_ADDR)
            == TO_CONN(conn));
  tt_assert(connection_get_by_type_state_rendquery(TEST_CONN_REND_TYPE_2,
                                                   !conn->base_.state,
                                                   "")
            == NULL);
  tt_assert(connection_get_by_type_state_rendquery(TEST_CONN_REND_TYPE_2,
                                                   !TEST_CONN_STATE,
                                                   TEST_CONN_REND_ADDR_2)
            == NULL);

 done:
  ;
}

#define sl_is_conn_assert(sl_input, conn) \
  do {                                               \
    the_sl = (sl_input);                             \
    tt_int_op(smartlist_len((the_sl)), OP_EQ, 1);         \
    tt_assert(smartlist_get((the_sl), 0) == (conn)); \
    smartlist_free(the_sl); the_sl = NULL;           \
  } while (0)

#define sl_no_conn_assert(sl_input)          \
  do {                                       \
    the_sl = (sl_input);                     \
    tt_int_op(smartlist_len((the_sl)), OP_EQ, 0); \
    smartlist_free(the_sl); the_sl = NULL;   \
  } while (0)

static void
test_conn_get_rsrc(void *arg)
{
  dir_connection_t *conn = DOWNCAST(dir_connection_t, arg);
  smartlist_t *the_sl = NULL;
  tt_assert(conn);
  assert_connection_ok(&conn->base_, time(NULL));

  sl_is_conn_assert(connection_dir_list_by_purpose_and_resource(
                                                    conn->base_.purpose,
                                                    conn->requested_resource),
                    conn);
  sl_is_conn_assert(connection_dir_list_by_purpose_and_resource(
                                                    TEST_CONN_RSRC_PURPOSE,
                                                    TEST_CONN_RSRC),
                    conn);
  sl_no_conn_assert(connection_dir_list_by_purpose_and_resource(
                                                    !conn->base_.purpose,
                                                    ""));
  sl_no_conn_assert(connection_dir_list_by_purpose_and_resource(
                                                    !TEST_CONN_RSRC_PURPOSE,
                                                    TEST_CONN_RSRC_2));

  sl_is_conn_assert(connection_dir_list_by_purpose_resource_and_state(
                                                    conn->base_.purpose,
                                                    conn->requested_resource,
                                                    conn->base_.state),
                    conn);
  sl_is_conn_assert(connection_dir_list_by_purpose_resource_and_state(
                                                    TEST_CONN_RSRC_PURPOSE,
                                                    TEST_CONN_RSRC,
                                                    TEST_CONN_STATE),
                    conn);
  sl_no_conn_assert(connection_dir_list_by_purpose_resource_and_state(
                                                    !conn->base_.purpose,
                                                    "",
                                                    !conn->base_.state));
  sl_no_conn_assert(connection_dir_list_by_purpose_resource_and_state(
                                                    !TEST_CONN_RSRC_PURPOSE,
                                                    TEST_CONN_RSRC_2,
                                                    !TEST_CONN_STATE));

  tt_int_op(connection_dir_count_by_purpose_and_resource(
                 conn->base_.purpose, conn->requested_resource),
            OP_EQ, 1);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                 TEST_CONN_RSRC_PURPOSE, TEST_CONN_RSRC),
            OP_EQ, 1);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                 !conn->base_.purpose, ""),
            OP_EQ, 0);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                 !TEST_CONN_RSRC_PURPOSE, TEST_CONN_RSRC_2),
            OP_EQ, 0);

  tt_int_op(connection_dir_count_by_purpose_resource_and_state(
                 conn->base_.purpose, conn->requested_resource,
                 conn->base_.state),
            OP_EQ, 1);
  tt_int_op(connection_dir_count_by_purpose_resource_and_state(
                 TEST_CONN_RSRC_PURPOSE, TEST_CONN_RSRC, TEST_CONN_STATE),
            OP_EQ, 1);
  tt_int_op(connection_dir_count_by_purpose_resource_and_state(
                 !conn->base_.purpose, "", !conn->base_.state),
            OP_EQ, 0);
  tt_int_op(connection_dir_count_by_purpose_resource_and_state(
                 !TEST_CONN_RSRC_PURPOSE, TEST_CONN_RSRC_2, !TEST_CONN_STATE),
            OP_EQ, 0);

 done:
  smartlist_free(the_sl);
}

static void
test_conn_download_status(void *arg)
{
  dir_connection_t *conn = NULL;
  dir_connection_t *conn2 = NULL;
  dir_connection_t *conn4 = NULL;
  connection_t *ap_conn = NULL;

  const struct testcase_t *tc = arg;
  consensus_flavor_t usable_flavor = (consensus_flavor_t)tc->setup_data;

  /* The "other flavor" trick only works if there are two flavors */
  tor_assert(N_CONSENSUS_FLAVORS == 2);
  consensus_flavor_t other_flavor = ((usable_flavor == FLAV_NS)
                                     ? FLAV_MICRODESC
                                     : FLAV_NS);
  const char *res = networkstatus_get_flavor_name(usable_flavor);
  const char *other_res = networkstatus_get_flavor_name(other_flavor);

  /* no connections */
  tt_int_op(networkstatus_consensus_is_already_downloading(res), OP_EQ, 0);
  tt_int_op(networkstatus_consensus_is_already_downloading(other_res), OP_EQ,
            0);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, res),
            OP_EQ, 0);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, other_res),
            OP_EQ, 0);

  /* one connection, not downloading */
  conn = test_conn_download_status_add_a_connection(res);
  tt_int_op(networkstatus_consensus_is_already_downloading(res), OP_EQ, 0);
  tt_int_op(networkstatus_consensus_is_already_downloading(other_res), OP_EQ,
            0);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, res),
            OP_EQ, 1);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, other_res),
            OP_EQ, 0);

  /* one connection, downloading but not linked (not possible on a client,
   * but possible on a relay) */
  conn->base_.state = TEST_CONN_DL_STATE;
  tt_int_op(networkstatus_consensus_is_already_downloading(res), OP_EQ, 0);
  tt_int_op(networkstatus_consensus_is_already_downloading(other_res), OP_EQ,
            0);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, res),
            OP_EQ, 1);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, other_res),
            OP_EQ, 0);

  /* one connection, downloading and linked, but not yet attached */
  ap_conn = test_conn_get_linked_connection(TO_CONN(conn),
                                            TEST_CONN_UNATTACHED_STATE);
  tt_int_op(networkstatus_consensus_is_already_downloading(res), OP_EQ, 0);
  tt_int_op(networkstatus_consensus_is_already_downloading(other_res), OP_EQ,
            0);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, res),
            OP_EQ, 1);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, other_res),
            OP_EQ, 0);

    /* one connection, downloading and linked and attached */
  ap_conn->state = TEST_CONN_ATTACHED_STATE;
  tt_int_op(networkstatus_consensus_is_already_downloading(res), OP_EQ, 1);
  tt_int_op(networkstatus_consensus_is_already_downloading(other_res), OP_EQ,
            0);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, res),
            OP_EQ, 1);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, other_res),
            OP_EQ, 0);

  /* one connection, linked and attached but not downloading */
  conn->base_.state = TEST_CONN_STATE;
  tt_int_op(networkstatus_consensus_is_already_downloading(res), OP_EQ, 0);
  tt_int_op(networkstatus_consensus_is_already_downloading(other_res), OP_EQ,
            0);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, res),
            OP_EQ, 1);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, other_res),
            OP_EQ, 0);

  /* two connections, both not downloading */
  conn2 = test_conn_download_status_add_a_connection(res);
  tt_int_op(networkstatus_consensus_is_already_downloading(res), OP_EQ, 0);
  tt_int_op(networkstatus_consensus_is_already_downloading(other_res), OP_EQ,
            0);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, res),
            OP_EQ, 2);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, other_res),
            OP_EQ, 0);

  /* two connections, one downloading */
  conn->base_.state = TEST_CONN_DL_STATE;
  tt_int_op(networkstatus_consensus_is_already_downloading(res), OP_EQ, 1);
  tt_int_op(networkstatus_consensus_is_already_downloading(other_res), OP_EQ,
            0);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, res),
            OP_EQ, 2);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, other_res),
            OP_EQ, 0);
  conn->base_.state = TEST_CONN_STATE;

  /* more connections, all not downloading */
  /* ignore the return value, it's free'd using the connection list */
  (void)test_conn_download_status_add_a_connection(res);
  tt_int_op(networkstatus_consensus_is_already_downloading(res), OP_EQ, 0);
  tt_int_op(networkstatus_consensus_is_already_downloading(other_res), OP_EQ,
            0);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, res),
            OP_EQ, 3);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, other_res),
            OP_EQ, 0);

  /* more connections, one downloading */
  conn->base_.state = TEST_CONN_DL_STATE;
  tt_int_op(networkstatus_consensus_is_already_downloading(res), OP_EQ, 1);
  tt_int_op(networkstatus_consensus_is_already_downloading(other_res), OP_EQ,
            0);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, res),
            OP_EQ, 3);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, other_res),
            OP_EQ, 0);

  /* more connections, two downloading (should never happen, but needs
   * to be tested for completeness) */
  conn2->base_.state = TEST_CONN_DL_STATE;
  /* ignore the return value, it's free'd using the connection list */
  (void)test_conn_get_linked_connection(TO_CONN(conn2),
                                        TEST_CONN_ATTACHED_STATE);
  tt_int_op(networkstatus_consensus_is_already_downloading(res), OP_EQ, 1);
  tt_int_op(networkstatus_consensus_is_already_downloading(other_res), OP_EQ,
            0);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, res),
            OP_EQ, 3);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, other_res),
            OP_EQ, 0);
  conn->base_.state = TEST_CONN_STATE;

  /* more connections, a different one downloading */
  tt_int_op(networkstatus_consensus_is_already_downloading(res), OP_EQ, 1);
  tt_int_op(networkstatus_consensus_is_already_downloading(other_res), OP_EQ,
            0);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, res),
            OP_EQ, 3);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                           TEST_CONN_RSRC_PURPOSE, other_res),
            OP_EQ, 0);

  /* a connection for the other flavor (could happen if a client is set to
   * cache directory documents), one preferred flavor downloading
   */
  conn4 = test_conn_download_status_add_a_connection(other_res);
  tt_int_op(networkstatus_consensus_is_already_downloading(res), OP_EQ, 1);
  tt_int_op(networkstatus_consensus_is_already_downloading(other_res), OP_EQ,
            0);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                   TEST_CONN_RSRC_PURPOSE, res),
            OP_EQ, 3);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                   TEST_CONN_RSRC_PURPOSE, other_res),
            OP_EQ, 1);

  /* a connection for the other flavor (could happen if a client is set to
   * cache directory documents), both flavors downloading
   */
  conn4->base_.state = TEST_CONN_DL_STATE;
  /* ignore the return value, it's free'd using the connection list */
  (void)test_conn_get_linked_connection(TO_CONN(conn4),
                                        TEST_CONN_ATTACHED_STATE);
  tt_int_op(networkstatus_consensus_is_already_downloading(res), OP_EQ, 1);
  tt_int_op(networkstatus_consensus_is_already_downloading(other_res), OP_EQ,
            1);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                   TEST_CONN_RSRC_PURPOSE, res),
            OP_EQ, 3);
  tt_int_op(connection_dir_count_by_purpose_and_resource(
                                   TEST_CONN_RSRC_PURPOSE, other_res),
            OP_EQ, 1);

 done:
  /* the teardown function removes all the connections in the global list*/;
}

static node_t test_node;

static node_t *
mock_node_get_mutable_by_id(const char *digest)
{
  (void) digest;
  static routerinfo_t node_ri;
  memset(&node_ri, 0, sizeof(node_ri));

  test_node.ri = &node_ri;
  memset(test_node.identity, 'c', sizeof(test_node.identity));

  tor_addr_t ipv4_addr;
  tor_addr_parse(&ipv4_addr, "18.0.0.1");
  node_ri.addr = tor_addr_to_ipv4h(&ipv4_addr);
  node_ri.or_port = 1;

  return &test_node;
}

static const node_t *
mock_node_get_by_id(const char *digest)
{
  (void) digest;
  memset(test_node.identity, 'c', sizeof(test_node.identity));
  return &test_node;
}

/* Test whether we correctly track failed connections between relays. */
static void
test_failed_orconn_tracker(void *arg)
{
  (void) arg;

  int can_connect;
  time_t now = 1281533250; /* 2010-08-11 13:27:30 UTC */
  (void) now;

  update_approx_time(now);

  /* Prepare the OR connection that will be used in this test */
  or_connection_t or_conn;
  tt_int_op(AF_INET,OP_EQ, tor_addr_parse(&or_conn.real_addr, "18.0.0.1"));
  tt_int_op(AF_INET,OP_EQ, tor_addr_parse(&or_conn.base_.addr, "18.0.0.1"));
  or_conn.base_.port = 1;
  memset(or_conn.identity_digest, 'c', sizeof(or_conn.identity_digest));

  /* Check whether we can connect with an empty failure cache:
   * this should succeed */
  can_connect = should_connect_to_relay(&or_conn);
  tt_int_op(can_connect, OP_EQ, 1);

  /* Now add the destination to the failure cache */
  note_or_connect_failed(&or_conn);

  /* Check again: now it shouldn't connect */
  can_connect = should_connect_to_relay(&or_conn);
  tt_int_op(can_connect, OP_EQ, 0);

  /* Move time forward and check again: the cache should have been cleared and
   * now it should connect */
  now += 3600;
  update_approx_time(now);
  can_connect = should_connect_to_relay(&or_conn);
  tt_int_op(can_connect, OP_EQ, 1);

  /* Now mock the node_get_*by_id() functions to start using the node subsystem
   * optimization. */
  MOCK(node_get_by_id, mock_node_get_by_id);
  MOCK(node_get_mutable_by_id, mock_node_get_mutable_by_id);

  /* Since we just started using the node subsystem it will allow connections
   * now */
  can_connect = should_connect_to_relay(&or_conn);
  tt_int_op(can_connect, OP_EQ, 1);

  /* Mark it as failed */
  note_or_connect_failed(&or_conn);

  /* Check that it shouldn't connect now */
  can_connect = should_connect_to_relay(&or_conn);
  tt_int_op(can_connect, OP_EQ, 0);

  /* Move time forward and check again: now it should connect  */
  now += 3600;
  update_approx_time(now);
  can_connect = should_connect_to_relay(&or_conn);
  tt_int_op(can_connect, OP_EQ, 1);

 done:
  ;
}

#define CONNECTION_TESTCASE(name, fork, setup)                           \
  { #name, test_conn_##name, fork, &setup, NULL }

/* where arg is an expression (constant, variable, compound expression) */
#define CONNECTION_TESTCASE_ARG(name, fork, setup, arg)                  \
  { #name "_" #arg, test_conn_##name, fork, &setup, (void *)arg }

struct testcase_t connection_tests[] = {
  CONNECTION_TESTCASE(get_basic, TT_FORK, test_conn_get_basic_st),
  CONNECTION_TESTCASE(get_rend,  TT_FORK, test_conn_get_rend_st),
  CONNECTION_TESTCASE(get_rsrc,  TT_FORK, test_conn_get_rsrc_st),
  CONNECTION_TESTCASE_ARG(download_status,  TT_FORK,
                          test_conn_download_status_st, FLAV_MICRODESC),
  CONNECTION_TESTCASE_ARG(download_status,  TT_FORK,
                          test_conn_download_status_st, FLAV_NS),
//CONNECTION_TESTCASE(func_suffix, TT_FORK, setup_func_pair),
  { "failed_orconn_tracker", test_failed_orconn_tracker, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};

