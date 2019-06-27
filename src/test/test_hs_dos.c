/* Copyright (c) 2017-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_cell.c
 * \brief Test hidden service cell functionality.
 */

#define CIRCUITLIST_PRIVATE
#define NETWORKSTATUS_PRIVATE

#include "test/test.h"
#include "test/test_helpers.h"
#include "test/log_test_helpers.h"

#include "app/config/config.h"

#include "core/or/circuitlist.h"
#include "core/or/circuituse.h"
#include "core/or/or_circuit_st.h"

#include "feature/hs/hs_dos.h"
#include "feature/nodelist/networkstatus.h"

static void
setup_mock_consensus(void)
{
  current_ns_consensus = tor_malloc_zero(sizeof(networkstatus_t));
  current_ns_consensus->net_params = smartlist_new();
  smartlist_add(current_ns_consensus->net_params,
                (void *) "HiddenServiceEnableIntroDoSDefense=1");
  hs_dos_consensus_has_changed(current_ns_consensus);
}

static void
free_mock_consensus(void)
{
  smartlist_free(current_ns_consensus->net_params);
  tor_free(current_ns_consensus);
}

static void
test_can_send_intro2(void *arg)
{
  uint32_t now = (uint32_t) approx_time();
  or_circuit_t *or_circ = NULL;

  (void) arg;

  hs_init();
  hs_dos_init();

  get_options_mutable()->ORPort_set = 1;
  setup_mock_consensus();

  or_circ =  or_circuit_new(1, NULL);

  /* Make that circuit a service intro point. */
  circuit_change_purpose(TO_CIRCUIT(or_circ), CIRCUIT_PURPOSE_INTRO_POINT);
  /* Initialize the INTRODUCE2 token bucket for the rate limiting. */
  token_bucket_ctr_init(&or_circ->introduce2_bucket, hs_dos_get_intro2_rate(),
                        hs_dos_get_intro2_burst(), now);

  /* Brand new circuit, we should be able to send INTRODUCE2 cells. */
  tt_int_op(true, OP_EQ, hs_dos_can_send_intro2(or_circ));

  /* Simulate that 10 cells have arrived in 1 second. There should be no
   * refill since the bucket is already at maximum on the first cell. */
  update_approx_time(++now);
  for (int i = 0; i < 10; i++) {
    tt_int_op(true, OP_EQ, hs_dos_can_send_intro2(or_circ));
  }
  tt_uint_op(token_bucket_ctr_get(&or_circ->introduce2_bucket), OP_EQ,
             hs_dos_get_intro2_burst() - 10);

  /* Fully refill the bucket minus 1 cell. */
  update_approx_time(++now);
  tt_int_op(true, OP_EQ, hs_dos_can_send_intro2(or_circ));
  tt_uint_op(token_bucket_ctr_get(&or_circ->introduce2_bucket), OP_EQ,
             hs_dos_get_intro2_burst() - 1);

  /* Receive an INTRODUCE2 at each second. We should have the bucket full
   * since at every second it gets refilled. */
  for (int i = 0; i < 10; i++) {
    update_approx_time(++now);
    tt_int_op(true, OP_EQ, hs_dos_can_send_intro2(or_circ));
  }
  /* Last check if we can send the cell decrements the bucket so minus 1. */
  tt_uint_op(token_bucket_ctr_get(&or_circ->introduce2_bucket), OP_EQ,
             hs_dos_get_intro2_burst() - 1);

  /* Manually reset bucket for next test. */
  token_bucket_ctr_reset(&or_circ->introduce2_bucket, now);
  tt_uint_op(token_bucket_ctr_get(&or_circ->introduce2_bucket), OP_EQ,
             hs_dos_get_intro2_burst());

  /* Do a full burst in the current second which should empty the bucket and
   * we shouldn't be allowed to send one more cell after that. We go minus 1
   * cell else the very last check if we can send the INTRO2 cell returns
   * false because the bucket goes down to 0. */
  for (uint32_t i = 0; i < hs_dos_get_intro2_burst() - 1; i++) {
    tt_int_op(true, OP_EQ, hs_dos_can_send_intro2(or_circ));
  }
  tt_uint_op(token_bucket_ctr_get(&or_circ->introduce2_bucket), OP_EQ, 1);
  /* Get the last remaining cell, we shouldn't be allowed to send it. */
  tt_int_op(false, OP_EQ, hs_dos_can_send_intro2(or_circ));
  tt_uint_op(token_bucket_ctr_get(&or_circ->introduce2_bucket), OP_EQ, 0);

  /* Make sure the next 100 cells aren't allowed and bucket stays at 0. */
  for (int i = 0; i < 100; i++) {
    tt_int_op(false, OP_EQ, hs_dos_can_send_intro2(or_circ));
    tt_uint_op(token_bucket_ctr_get(&or_circ->introduce2_bucket), OP_EQ, 0);
  }

  /* One second has passed, we should have the rate minus 1 cell added. */
  update_approx_time(++now);
  tt_int_op(true, OP_EQ, hs_dos_can_send_intro2(or_circ));
  tt_uint_op(token_bucket_ctr_get(&or_circ->introduce2_bucket), OP_EQ,
             hs_dos_get_intro2_rate() - 1);

 done:
  circuit_free_(TO_CIRCUIT(or_circ));

  hs_free_all();
  free_mock_consensus();
}

struct testcase_t hs_dos_tests[] = {
  { "can_send_intro2", test_can_send_intro2, TT_FORK,
    NULL, NULL },

  END_OF_TESTCASES
};

