/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_mainloop.c
 * \brief Tests for functions closely related to the Tor main loop
 */

#include "test.h"
#include "log_test_helpers.h"

#include "or.h"
#include "main.h"

static void
test_mainloop_update_time_normal(void *arg)
{
  (void)arg;

  /* This time is in the past as of when this test was written. */
  time_t now = 1525272090;
  reset_uptime();
  update_current_time(now);
  tt_int_op(approx_time(), OP_EQ, now);
  tt_int_op(get_uptime(), OP_EQ, 0);

  update_current_time(now); // Same time as before is a no-op.
  tt_int_op(get_uptime(), OP_EQ, 0);

  now += 1;
  update_current_time(now);
  tt_int_op(approx_time(), OP_EQ, now);
  tt_int_op(get_uptime(), OP_EQ, 1);

  now += 2; // two-second jump is unremarkable.
  update_current_time(now);
  tt_int_op(approx_time(), OP_EQ, now);
  tt_int_op(get_uptime(), OP_EQ, 3);

  now -= 1; // a one-second hop backwards is also unremarkable.
  update_current_time(now);
  tt_int_op(approx_time(), OP_EQ, now); // it changes the approx time...
  tt_int_op(get_uptime(), OP_EQ, 3); // but it doesn't roll back our uptime

 done:
  ;
}

static void
test_mainloop_update_time_jumps(void *arg)
{
  (void)arg;

  /* This time is in the past as of when this test was written. */
  time_t now = 220897152;
  reset_uptime();
  update_current_time(now);
  tt_int_op(approx_time(), OP_EQ, now);
  tt_int_op(get_uptime(), OP_EQ, 0);

  /* Put some uptime on the clock.. */
  now += 3;
  update_current_time(now);
  tt_int_op(approx_time(), OP_EQ, now);
  tt_int_op(get_uptime(), OP_EQ, 3);

  /* Now try jumping forward. */
  setup_capture_of_logs(LOG_NOTICE);
  now += 3600;
  update_current_time(now);
  expect_single_log_msg_containing(
               "Your system clock just jumped 3600 seconds forward");
  tt_int_op(approx_time(), OP_EQ, now);
  tt_int_op(get_uptime(), OP_EQ, 3); // no uptime change.
  mock_clean_saved_logs();

  now -= 600;
  update_current_time(now);
  expect_single_log_msg_containing(
               "Your system clock just jumped 600 seconds backward");
  tt_int_op(approx_time(), OP_EQ, now);
  tt_int_op(get_uptime(), OP_EQ, 3); // no uptime change.

  /* uptime tracking should go normally now if the clock moves sensibly. */
  now += 2;
  update_current_time(now);
  tt_int_op(approx_time(), OP_EQ, now);
  tt_int_op(get_uptime(), OP_EQ, 5);

 done:
  teardown_capture_of_logs();
}

#define MAINLOOP_TEST(name) \
  { #name, test_mainloop_## name , TT_FORK, NULL, NULL }

struct testcase_t mainloop_tests[] = {
  MAINLOOP_TEST(update_time_normal),
  MAINLOOP_TEST(update_time_jumps),
  END_OF_TESTCASES
};

