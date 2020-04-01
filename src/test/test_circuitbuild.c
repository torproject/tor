/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define CIRCUITBUILD_PRIVATE
#define CIRCUITLIST_PRIVATE
#define ENTRYNODES_PRIVATE

#include "core/or/or.h"
#include "test/test.h"
#include "test/test_helpers.h"
#include "test/log_test_helpers.h"
#include "app/config/config.h"
#include "core/or/circuitbuild.h"
#include "core/or/circuitlist.h"
#include "core/or/channel.h"

#include "core/or/cpath_build_state_st.h"
#include "core/or/extend_info_st.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/or_circuit_st.h"

#include "feature/client/entrynodes.h"
#include "feature/relay/circuitbuild_relay.h"
#include "feature/relay/routermode.h"

/* Dummy nodes smartlist for testing */
static smartlist_t dummy_nodes;
/* Dummy exit extend_info for testing */
static extend_info_t dummy_ei;

static int
mock_count_acceptable_nodes(const smartlist_t *nodes, int direct)
{
  (void)nodes;

  return direct ? 1 : DEFAULT_ROUTE_LEN + 1;
}

/* Test route lengths when the caller of new_route_len() doesn't
 * specify exit_ei. */
static void
test_new_route_len_noexit(void *arg)
{
  int r;

  (void)arg;
  MOCK(count_acceptable_nodes, mock_count_acceptable_nodes);

  r = new_route_len(CIRCUIT_PURPOSE_C_GENERAL, NULL, &dummy_nodes);
  tt_int_op(DEFAULT_ROUTE_LEN, OP_EQ, r);

  r = new_route_len(CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT, NULL, &dummy_nodes);
  tt_int_op(DEFAULT_ROUTE_LEN, OP_EQ, r);

  r = new_route_len(CIRCUIT_PURPOSE_S_CONNECT_REND, NULL, &dummy_nodes);
  tt_int_op(DEFAULT_ROUTE_LEN, OP_EQ, r);

 done:
  UNMOCK(count_acceptable_nodes);
}

/* Test route lengths where someone else chose the "exit" node, which
 * require an extra hop for safety. */
static void
test_new_route_len_unsafe_exit(void *arg)
{
  int r;

  (void)arg;
  MOCK(count_acceptable_nodes, mock_count_acceptable_nodes);

  /* connecting to hidden service directory */
  r = new_route_len(CIRCUIT_PURPOSE_C_GENERAL, &dummy_ei, &dummy_nodes);
  tt_int_op(DEFAULT_ROUTE_LEN + 1, OP_EQ, r);

  /* client connecting to introduction point */
  r = new_route_len(CIRCUIT_PURPOSE_C_INTRODUCING, &dummy_ei, &dummy_nodes);
  tt_int_op(DEFAULT_ROUTE_LEN + 1, OP_EQ, r);

  /* hidden service connecting to rendezvous point */
  r = new_route_len(CIRCUIT_PURPOSE_S_CONNECT_REND, &dummy_ei, &dummy_nodes);
  tt_int_op(DEFAULT_ROUTE_LEN + 1, OP_EQ, r);

 done:
  UNMOCK(count_acceptable_nodes);
}

/* Test route lengths where we chose the "exit" node, which don't
 * require an extra hop for safety. */
static void
test_new_route_len_safe_exit(void *arg)
{
  int r;

  (void)arg;
  MOCK(count_acceptable_nodes, mock_count_acceptable_nodes);

  /* hidden service connecting to introduction point */
  r = new_route_len(CIRCUIT_PURPOSE_S_ESTABLISH_INTRO, &dummy_ei,
                    &dummy_nodes);
  tt_int_op(DEFAULT_ROUTE_LEN, OP_EQ, r);

  /* router testing its own reachability */
  r = new_route_len(CIRCUIT_PURPOSE_TESTING, &dummy_ei, &dummy_nodes);
  tt_int_op(DEFAULT_ROUTE_LEN, OP_EQ, r);

 done:
  UNMOCK(count_acceptable_nodes);
}

/* Make sure a non-fatal assertion fails when new_route_len() gets an
 * unexpected circuit purpose. */
static void
test_new_route_len_unhandled_exit(void *arg)
{
  int r;

  (void)arg;
#ifdef ALL_BUGS_ARE_FATAL
  /* Coverity (and maybe clang analyser) complain that the code following
   * tt_skip() is unconditionally unreachable. */
#if !defined(__COVERITY__) && !defined(__clang_analyzer__)
  tt_skip();
#endif
#endif

  MOCK(count_acceptable_nodes, mock_count_acceptable_nodes);

  tor_capture_bugs_(1);
  setup_full_capture_of_logs(LOG_WARN);
  r = new_route_len(CIRCUIT_PURPOSE_CONTROLLER, &dummy_ei, &dummy_nodes);
  tt_int_op(DEFAULT_ROUTE_LEN + 1, OP_EQ, r);
  tt_int_op(smartlist_len(tor_get_captured_bug_log_()), OP_EQ, 1);
  tt_str_op(smartlist_get(tor_get_captured_bug_log_(), 0), OP_EQ,
            "!(exit_ei && !known_purpose)");
  expect_single_log_msg_containing("Unhandled purpose");
  expect_single_log_msg_containing("with a chosen exit; assuming routelen");

 done:
  teardown_capture_of_logs();
  tor_end_capture_bugs_();
  UNMOCK(count_acceptable_nodes);
}

static void
test_upgrade_from_guard_wait(void *arg)
{
  circuit_t *circ = NULL;
  origin_circuit_t *orig_circ = NULL;
  entry_guard_t *guard = NULL;
  smartlist_t *list = NULL;

  (void) arg;

  circ = dummy_origin_circuit_new(0);
  orig_circ = TO_ORIGIN_CIRCUIT(circ);
  tt_assert(orig_circ);

  orig_circ->build_state = tor_malloc_zero(sizeof(cpath_build_state_t));

  circuit_set_state(circ, CIRCUIT_STATE_GUARD_WAIT);

  /* Put it in guard wait state. */
  guard = tor_malloc_zero(sizeof(*guard));
  guard->in_selection = get_guard_selection_info();

  orig_circ->guard_state =
    circuit_guard_state_new(guard, GUARD_CIRC_STATE_WAITING_FOR_BETTER_GUARD,
                            NULL);

  /* Mark the circuit for close. */
  circuit_mark_for_close(circ, END_CIRC_REASON_TORPROTOCOL);
  tt_int_op(circ->marked_for_close, OP_NE, 0);

  /* We shouldn't pick the mark for close circuit. */
  list = circuit_find_circuits_to_upgrade_from_guard_wait();
  tt_assert(!list);

 done:
  smartlist_free(list);
  circuit_free(circ);
  entry_guard_free_(guard);
}

static int server = 0;
static int
mock_server_mode(const or_options_t *options)
{
  (void)options;
  return server;
}

/* Test the different cases in circuit_extend_state_valid_helper(). */
static void
test_circuit_extend_state_valid(void *arg)
{
  (void)arg;
  circuit_t *circ = tor_malloc_zero(sizeof(circuit_t));

  server = 0;
  MOCK(server_mode, mock_server_mode);

  setup_full_capture_of_logs(LOG_INFO);

  /* Clients can't extend */
  server = 0;
  tt_int_op(circuit_extend_state_valid_helper(NULL), OP_EQ, -1);
  expect_log_msg("Got an extend cell, but running as a client. Closing.\n");
  mock_clean_saved_logs();

  /* Circuit must be non-NULL */
  tor_capture_bugs_(1);
  server = 1;
  tt_int_op(circuit_extend_state_valid_helper(NULL), OP_EQ, -1);
  tt_int_op(smartlist_len(tor_get_captured_bug_log_()), OP_EQ, 1);
  tt_str_op(smartlist_get(tor_get_captured_bug_log_(), 0), OP_EQ,
            "!(ASSERT_PREDICT_UNLIKELY_(!circ))");
  tor_end_capture_bugs_();
  mock_clean_saved_logs();

  /* n_chan and n_hop are NULL, this should succeed */
  server = 1;
  tt_int_op(circuit_extend_state_valid_helper(circ), OP_EQ, 0);
  mock_clean_saved_logs();

  /* But clients still can't extend */
  server = 0;
  tt_int_op(circuit_extend_state_valid_helper(circ), OP_EQ, -1);
  expect_log_msg("Got an extend cell, but running as a client. Closing.\n");
  mock_clean_saved_logs();

  /* n_chan must be NULL */
  circ->n_chan = tor_malloc_zero(sizeof(channel_t));
  server = 1;
  tt_int_op(circuit_extend_state_valid_helper(circ), OP_EQ, -1);
  expect_log_msg("n_chan already set. Bug/attack. Closing.\n");
  mock_clean_saved_logs();
  tor_free(circ->n_chan);

  /* n_hop must be NULL */
  circ->n_hop = tor_malloc_zero(sizeof(extend_info_t));
  server = 1;
  tt_int_op(circuit_extend_state_valid_helper(circ), OP_EQ, -1);
  expect_log_msg("conn to next hop already launched. Bug/attack. Closing.\n");
  mock_clean_saved_logs();
  tor_free(circ->n_hop);

 done:
  tor_end_capture_bugs_();
  teardown_capture_of_logs();

  UNMOCK(server_mode);
  server = 0;

  tor_free(circ->n_chan);
  tor_free(circ->n_hop);
  tor_free(circ);
}

#define TEST(name, flags, setup, cleanup) \
  { #name, test_ ## name, flags, setup, cleanup }

#define TEST_NEW_ROUTE_LEN(name, flags) \
  { #name, test_new_route_len_ ## name, flags, NULL, NULL }

#define TEST_CIRCUIT(name, flags) \
  { #name, test_circuit_ ## name, flags, NULL, NULL }

struct testcase_t circuitbuild_tests[] = {
  TEST_NEW_ROUTE_LEN(noexit, 0),
  TEST_NEW_ROUTE_LEN(safe_exit, 0),
  TEST_NEW_ROUTE_LEN(unsafe_exit, 0),
  TEST_NEW_ROUTE_LEN(unhandled_exit, 0),

  TEST(upgrade_from_guard_wait, TT_FORK, &helper_pubsub_setup, NULL),

  TEST_CIRCUIT(extend_state_valid, 0),
  END_OF_TESTCASES
};
