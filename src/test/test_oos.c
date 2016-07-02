/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/* Unit tests for OOS handler */

#define CONNECTION_PRIVATE

#include "or.h"
#include "config.h"
#include "connection.h"
#include "connection_or.h"
#include "main.h"
#include "test.h"

static or_options_t mock_options;

static void
reset_options_mock(void)
{
  memset(&mock_options, 0, sizeof(or_options_t));
}

static const or_options_t *
mock_get_options(void)
{
  return &mock_options;
}

static int moribund_calls = 0;
static int moribund_conns = 0;

static int
mock_connection_count_moribund(void)
{
  ++moribund_calls;

  return moribund_conns;
}

/*
 * For unit test purposes it's sufficient to tell that
 * kill_conn_list_for_oos() was called with an approximately
 * sane argument; it's just the thing we returned from the
 * mock for pick_oos_victims().
 */

static int kill_conn_list_calls = 0;
static int kill_conn_list_killed = 0;

static void
kill_conn_list_mock(smartlist_t *conns)
{
  ++kill_conn_list_calls;

  tt_assert(conns != NULL);

  kill_conn_list_killed += smartlist_len(conns);

 done:
  return;
}

static int pick_oos_mock_calls = 0;
static int pick_oos_mock_fail = 0;
static int pick_oos_mock_last_n = 0;

static smartlist_t *
pick_oos_victims_mock(int n)
{
  smartlist_t *l;
  int i;

  ++pick_oos_mock_calls;

  tt_int_op(n, OP_GT, 0);

  if (!pick_oos_mock_fail) {
    /*
     * connection_handle_oos() just passes the list onto
     * kill_conn_list_for_oos(); we don't need to simulate
     * its content for this mock, just its existence, but
     * we do need to check the parameter.
     */
    l = smartlist_new();
    for (i = 0; i < n; ++i) smartlist_add(l, NULL);
  } else {
    l = NULL;
  }

  pick_oos_mock_last_n = n;

 done:
  return l;
}

/** Unit test for the logic in connection_handle_oos(), which is concerned
 * with comparing thresholds and connection counts to decide if an OOS has
 * occurred and if so, how many connections to try to kill, and then using
 * pick_oos_victims() and kill_conn_list_for_oos() to carry out its grim
 * duty.
 */
static void
test_oos_connection_handle_oos(void *arg)
{
  (void)arg;

  /* Set up mocks */
  reset_options_mock();
  /* OOS handling is only sensitive to these fields */
  mock_options.ConnLimit = 32;
  mock_options.ConnLimit_ = 64;
  mock_options.ConnLimit_high_thresh = 60;
  mock_options.ConnLimit_low_thresh = 50;
  MOCK(get_options, mock_get_options);
  moribund_calls = 0;
  moribund_conns = 0;
  MOCK(connection_count_moribund, mock_connection_count_moribund);
  kill_conn_list_calls = 0;
  kill_conn_list_killed = 0;
  MOCK(kill_conn_list_for_oos, kill_conn_list_mock);
  pick_oos_mock_calls = 0;
  pick_oos_mock_fail = 0;
  MOCK(pick_oos_victims, pick_oos_victims_mock);

  /* No OOS case */
  connection_handle_oos(50, 0);
  tt_int_op(moribund_calls, OP_EQ, 0);
  tt_int_op(pick_oos_mock_calls, OP_EQ, 0);
  tt_int_op(kill_conn_list_calls, OP_EQ, 0);

  /* OOS from socket count, nothing moribund */
  connection_handle_oos(62, 0);
  tt_int_op(moribund_calls, OP_EQ, 1);
  tt_int_op(pick_oos_mock_calls, OP_EQ, 1);
  /* 12 == 62 - ConnLimit_low_thresh */
  tt_int_op(pick_oos_mock_last_n, OP_EQ, 12);
  tt_int_op(kill_conn_list_calls, OP_EQ, 1);
  tt_int_op(kill_conn_list_killed, OP_EQ, 12);

  /* OOS from socket count, some are moribund */
  kill_conn_list_killed = 0;
  moribund_conns = 5;
  connection_handle_oos(62, 0);
  tt_int_op(moribund_calls, OP_EQ, 2);
  tt_int_op(pick_oos_mock_calls, OP_EQ, 2);
  /* 7 == 62 - ConnLimit_low_thresh - moribund_conns */
  tt_int_op(pick_oos_mock_last_n, OP_EQ, 7);
  tt_int_op(kill_conn_list_calls, OP_EQ, 2);
  tt_int_op(kill_conn_list_killed, OP_EQ, 7);

  /* OOS from socket count, but pick fails */
  kill_conn_list_killed = 0;
  moribund_conns = 0;
  pick_oos_mock_fail = 1;
  connection_handle_oos(62, 0);
  tt_int_op(moribund_calls, OP_EQ, 3);
  tt_int_op(pick_oos_mock_calls, OP_EQ, 3);
  tt_int_op(kill_conn_list_calls, OP_EQ, 2);
  tt_int_op(kill_conn_list_killed, OP_EQ, 0);
  pick_oos_mock_fail = 0;

  /*
   * OOS from socket count with so many moribund conns
   * we have none to kill.
   */
  kill_conn_list_killed = 0;
  moribund_conns = 15;
  connection_handle_oos(62, 0);
  tt_int_op(moribund_calls, OP_EQ, 4);
  tt_int_op(pick_oos_mock_calls, OP_EQ, 3);
  tt_int_op(kill_conn_list_calls, OP_EQ, 2);

  /*
   * OOS from socket exhaustion; OOS handler will try to
   * kill 1/10 (5) of the connections.
   */
  kill_conn_list_killed = 0;
  moribund_conns = 0;
  connection_handle_oos(50, 1);
  tt_int_op(moribund_calls, OP_EQ, 5);
  tt_int_op(pick_oos_mock_calls, OP_EQ, 4);
  tt_int_op(kill_conn_list_calls, OP_EQ, 3);
  tt_int_op(kill_conn_list_killed, OP_EQ, 5);

  /* OOS from socket exhaustion with moribund conns */
  kill_conn_list_killed = 0;
  moribund_conns = 2;
  connection_handle_oos(50, 1);
  tt_int_op(moribund_calls, OP_EQ, 6);
  tt_int_op(pick_oos_mock_calls, OP_EQ, 5);
  tt_int_op(kill_conn_list_calls, OP_EQ, 4);
  tt_int_op(kill_conn_list_killed, OP_EQ, 3);

  /* OOS from socket exhaustion with many moribund conns */
  kill_conn_list_killed = 0;
  moribund_conns = 7;
  connection_handle_oos(50, 1);
  tt_int_op(moribund_calls, OP_EQ, 7);
  tt_int_op(pick_oos_mock_calls, OP_EQ, 5);
  tt_int_op(kill_conn_list_calls, OP_EQ, 4);

  /* OOS with both socket exhaustion and above-threshold */
  kill_conn_list_killed = 0;
  moribund_conns = 0;
  connection_handle_oos(62, 1);
  tt_int_op(moribund_calls, OP_EQ, 8);
  tt_int_op(pick_oos_mock_calls, OP_EQ, 6);
  tt_int_op(kill_conn_list_calls, OP_EQ, 5);
  tt_int_op(kill_conn_list_killed, OP_EQ, 12);

  /*
   * OOS with both socket exhaustion and above-threshold with some
   * moribund conns
   */
  kill_conn_list_killed = 0;
  moribund_conns = 5;
  connection_handle_oos(62, 1);
  tt_int_op(moribund_calls, OP_EQ, 9);
  tt_int_op(pick_oos_mock_calls, OP_EQ, 7);
  tt_int_op(kill_conn_list_calls, OP_EQ, 6);
  tt_int_op(kill_conn_list_killed, OP_EQ, 7);

  /*
   * OOS with both socket exhaustion and above-threshold with many
   * moribund conns
   */
  kill_conn_list_killed = 0;
  moribund_conns = 15;
  connection_handle_oos(62, 1);
  tt_int_op(moribund_calls, OP_EQ, 10);
  tt_int_op(pick_oos_mock_calls, OP_EQ, 7);
  tt_int_op(kill_conn_list_calls, OP_EQ, 6);

 done:

  UNMOCK(pick_oos_victims);
  UNMOCK(kill_conn_list_for_oos);
  UNMOCK(connection_count_moribund);
  UNMOCK(get_options);

  return;
}

static int cfe_calls = 0;

static void
close_for_error_mock(or_connection_t *orconn, int flush)
{
  (void)flush;

  tt_assert(orconn != NULL);
  ++cfe_calls;

 done:
  return;
}

static int mark_calls = 0;

static void
mark_for_close_oos_mock(connection_t *conn,
                        int line, const char *file)
{
  (void)line;
  (void)file;

  tt_assert(conn != NULL);
  ++mark_calls;

 done:
  return;
}

static void
test_oos_kill_conn_list(void *arg)
{
  connection_t *c1, *c2;
  or_connection_t *or_c1 = NULL;
  dir_connection_t *dir_c2 = NULL;
  smartlist_t *l = NULL;
  (void)arg;

  /* Set up mocks */
  mark_calls = 0;
  MOCK(connection_mark_for_close_internal_, mark_for_close_oos_mock);
  cfe_calls = 0;
  MOCK(connection_or_close_for_error, close_for_error_mock);

  /* Make fake conns */
  or_c1 = tor_malloc_zero(sizeof(*or_c1));
  or_c1->base_.magic = OR_CONNECTION_MAGIC;
  or_c1->base_.type = CONN_TYPE_OR;
  c1 = TO_CONN(or_c1);
  dir_c2 = tor_malloc_zero(sizeof(*dir_c2));
  dir_c2->base_.magic = DIR_CONNECTION_MAGIC;
  dir_c2->base_.type = CONN_TYPE_DIR;
  c2 = TO_CONN(dir_c2);

  tt_assert(c1 != NULL);
  tt_assert(c2 != NULL);

  /* Make list */
  l = smartlist_new();
  smartlist_add(l, c1);
  smartlist_add(l, c2);

  /* Run kill_conn_list_for_oos() */
  kill_conn_list_for_oos(l);

  /* Check call counters */
  tt_int_op(mark_calls, OP_EQ, 1);
  tt_int_op(cfe_calls, OP_EQ, 1);

 done:
 
  UNMOCK(connection_or_close_for_error);
  UNMOCK(connection_mark_for_close_internal_);

  if (l) smartlist_free(l);
  tor_free(or_c1);
  tor_free(dir_c2);

  return;
}

struct testcase_t oos_tests[] = {
  { "connection_handle_oos", test_oos_connection_handle_oos,
    TT_FORK, NULL, NULL },
  { "kill_conn_list", test_oos_kill_conn_list, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};

