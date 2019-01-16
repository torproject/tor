/* Copyright (c) 2013-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "core/or/or.h"

#include "test/test.h"
#include "test/log_test_helpers.h"

#define OCIRC_EVENT_PRIVATE
#define ORCONN_EVENT_PRIVATE
#include "core/or/ocirc_event.h"
#include "core/or/orconn_event.h"

static void
test_btrack_launch(void *arg)
{
  orconn_event_msg_t conn;
  ocirc_event_msg_t circ;

  (void)arg;
  conn.type = ORCONN_MSGTYPE_STATE;
  conn.u.state.gid = 1;
  conn.u.state.chan = 1;
  conn.u.state.proxy_type = PROXY_NONE;
  conn.u.state.state = OR_CONN_STATE_CONNECTING;

  setup_full_capture_of_logs(LOG_DEBUG);
  orconn_event_publish(&conn);
  expect_log_msg_containing("ORCONN gid=1 chan=1 proxy_type=0 state=1");
  expect_no_log_msg_containing("ORCONN BEST_");
  teardown_capture_of_logs();

  circ.type = OCIRC_MSGTYPE_CHAN;
  circ.u.chan.chan = 1;
  circ.u.chan.onehop = true;

  setup_full_capture_of_logs(LOG_DEBUG);
  ocirc_event_publish(&circ);
  expect_log_msg_containing("ORCONN LAUNCH chan=1 onehop=1");
  expect_log_msg_containing("ORCONN BEST_ANY state -1->1 gid=1");
  teardown_capture_of_logs();

  conn.u.state.gid = 2;
  conn.u.state.chan = 2;

  setup_full_capture_of_logs(LOG_DEBUG);
  orconn_event_publish(&conn);
  expect_log_msg_containing("ORCONN gid=2 chan=2 proxy_type=0 state=1");
  expect_no_log_msg_containing("ORCONN BEST_");
  teardown_capture_of_logs();

  circ.u.chan.chan = 2;
  circ.u.chan.onehop = false;

  setup_full_capture_of_logs(LOG_DEBUG);
  ocirc_event_publish(&circ);
  expect_log_msg_containing("ORCONN LAUNCH chan=2 onehop=0");
  expect_log_msg_containing("ORCONN BEST_AP state -1->1 gid=2");
  teardown_capture_of_logs();

 done:
  ;
}

static void
test_btrack_delete(void *arg)
{
  orconn_event_msg_t conn;

  (void)arg;
  conn.type = ORCONN_MSGTYPE_STATE;
  conn.u.state.gid = 1;
  conn.u.state.chan = 1;
  conn.u.state.proxy_type = PROXY_NONE;
  conn.u.state.state = OR_CONN_STATE_CONNECTING;

  setup_full_capture_of_logs(LOG_DEBUG);
  orconn_event_publish(&conn);
  expect_log_msg_containing("ORCONN gid=1 chan=1 proxy_type=0");
  teardown_capture_of_logs();

  conn.type = ORCONN_MSGTYPE_STATUS;
  conn.u.status.gid = 1;
  conn.u.status.status = OR_CONN_EVENT_CLOSED;
  conn.u.status.reason = 0;

  setup_full_capture_of_logs(LOG_DEBUG);
  orconn_event_publish(&conn);
  expect_log_msg_containing("ORCONN DELETE gid=1 status=3 reason=0");
  teardown_capture_of_logs();

 done:
  ;
}

struct testcase_t btrack_tests[] = {
  { "launch", test_btrack_launch, TT_FORK, 0, NULL },
  { "delete", test_btrack_delete, TT_FORK, 0, NULL },
  END_OF_TESTCASES
};
