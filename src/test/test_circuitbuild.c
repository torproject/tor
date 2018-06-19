/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define CIRCUITBUILD_PRIVATE

#include "or.h"
#include "test.h"
#include "test_helpers.h"
#include "log_test_helpers.h"
#include "config.h"
#include "circuitbuild.h"

#include "extend_info_st.h"

/* Dummy nodes smartlist for testing */
static smartlist_t dummy_nodes;
/* Dummy exit extend_info for testing */
static extend_info_t dummy_ei;

static int
mock_count_acceptable_nodes(smartlist_t *nodes)
{
  (void)nodes;

  return DEFAULT_ROUTE_LEN + 1;
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
  teardown_capture_of_logs();
  tor_end_capture_bugs_();

 done:
  UNMOCK(count_acceptable_nodes);
}

struct testcase_t circuitbuild_tests[] = {
  { "noexit", test_new_route_len_noexit, 0, NULL, NULL },
  { "safe_exit", test_new_route_len_safe_exit, 0, NULL, NULL },
  { "unsafe_exit", test_new_route_len_unsafe_exit, 0, NULL, NULL },
  { "unhandled_exit", test_new_route_len_unhandled_exit, 0, NULL, NULL },
  END_OF_TESTCASES
};

