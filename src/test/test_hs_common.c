/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_common.c
 * \brief Test hidden service common functionalities.
 */

#define HS_COMMON_PRIVATE

#include "test.h"
#include "test_helpers.h"
#include "log_test_helpers.h"
#include "hs_test_helpers.h"

#include "hs_common.h"

static void
test_validate_address(void *arg)
{
  int ret;

  (void) arg;

  /* Address too short and too long. */
  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_address_is_valid("blah");
  tt_int_op(ret, OP_EQ, 0);
  expect_log_msg_containing("has an invalid length");
  teardown_capture_of_logs();

  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_address_is_valid(
           "p3xnclpu4mu22dwaurjtsybyqk4xfjmcfz6z62yl24uwmhjatiwnlnadb");
  tt_int_op(ret, OP_EQ, 0);
  expect_log_msg_containing("has an invalid length");
  teardown_capture_of_logs();

  /* Invalid checksum (taken from prop224) */
  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_address_is_valid(
           "l5satjgud6gucryazcyvyvhuxhr74u6ygigiuyixe3a6ysis67ororad");
  tt_int_op(ret, OP_EQ, 0);
  expect_log_msg_containing("invalid checksum");
  teardown_capture_of_logs();

  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_address_is_valid(
           "btojiu7nu5y5iwut64eufevogqdw4wmqzugnoluw232r4t3ecsfv37ad");
  tt_int_op(ret, OP_EQ, 0);
  expect_log_msg_containing("invalid checksum");
  teardown_capture_of_logs();

  /* Non base32 decodable string. */
  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_address_is_valid(
           "????????????????????????????????????????????????????????");
  tt_int_op(ret, OP_EQ, 0);
  expect_log_msg_containing("can't be decoded");
  teardown_capture_of_logs();

  /* Valid address. */
  ret = hs_address_is_valid(
           "p3xnclpu4mu22dwaurjtsybyqk4xfjmcfz6z62yl24uwmhjatiwnlnad");
  tt_int_op(ret, OP_EQ, 1);

 done:
  ;
}

static void
test_build_address(void *arg)
{
  int ret;
  char onion_addr[HS_SERVICE_ADDR_LEN_BASE32 + 1];
  ed25519_public_key_t pubkey;

  (void) arg;

  /* The following has been created with hs_build_address.py script that
   * follows proposal 224 specification to build an onion address. */
  static const char *test_addr =
    "ijbeeqscijbeeqscijbeeqscijbeeqscijbeeqscijbeeqscijbezhid";

  /* Let's try to build the same onion address that the script can do. Key is
   * a long set of very random \x42 :). */
  memset(&pubkey, '\x42', sizeof(pubkey));
  hs_build_address(&pubkey, HS_VERSION_THREE, onion_addr);
  tt_str_op(test_addr, OP_EQ, onion_addr);
  /* Validate that address. */
  ret = hs_address_is_valid(onion_addr);
  tt_int_op(ret, OP_EQ, 1);

 done:
  ;
}

/** Test that our HS time period calculation functions work properly */
static void
test_time_period(void *arg)
{
  (void) arg;
  uint64_t tn;
  int retval;
  time_t fake_time;

  /* Let's do the example in prop224 section [TIME-PERIODS] */
  retval = parse_rfc1123_time("Wed, 13 Apr 2016 11:00:00 UTC",
                              &fake_time);
  tt_int_op(retval, ==, 0);

  /* Check that the time period number is right */
  tn = hs_get_time_period_num(fake_time);
  tt_u64_op(tn, ==, 16903);

  /* Increase current time to 11:59:59 UTC and check that the time period
     number is still the same */
  fake_time += 3599;
  tn = hs_get_time_period_num(fake_time);
  tt_u64_op(tn, ==, 16903);

  /* Now take time to 12:00:00 UTC and check that the time period rotated */
  fake_time += 1;
  tn = hs_get_time_period_num(fake_time);
  tt_u64_op(tn, ==, 16904);

  /* Now also check our hs_get_next_time_period_num() function */
  tn = hs_get_next_time_period_num(fake_time);
  tt_u64_op(tn, ==, 16905);

 done:
  ;
}

/** Test that our HS overlap period functions work properly. */
static void
test_desc_overlap_period(void *arg)
{
  (void) arg;
  int retval;
  time_t now = time(NULL);
  networkstatus_t *dummy_consensus = NULL;

  /* First try with a consensus inside the overlap period */
  dummy_consensus = tor_malloc_zero(sizeof(networkstatus_t));
  retval = parse_rfc1123_time("Wed, 13 Apr 2016 10:00:00 UTC",
                              &dummy_consensus->valid_after);
  tt_int_op(retval, ==, 0);

  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, ==, 1);

  /* Now increase the valid_after so that it goes to 11:00:00 UTC. Overlap
     period is still active. */
  dummy_consensus->valid_after += 3600;
  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, ==, 1);

  /* Now increase the valid_after so that it goes to 11:59:59 UTC. Overlap
     period is still active. */
  dummy_consensus->valid_after += 3599;
  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, ==, 1);

  /* Now increase the valid_after so that it drifts to noon, and check that
     overlap mode is not active anymore. */
  dummy_consensus->valid_after += 1;
  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, ==, 0);

  /* Check that overlap mode is also inactive at 23:59:59 UTC */
  retval = parse_rfc1123_time("Wed, 13 Apr 2016 23:59:59 UTC",
                              &dummy_consensus->valid_after);
  tt_int_op(retval, ==, 0);
  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, ==, 0);

 done:
  tor_free(dummy_consensus);
}

struct testcase_t hs_common_tests[] = {
  { "build_address", test_build_address, TT_FORK,
    NULL, NULL },
  { "validate_address", test_validate_address, TT_FORK,
    NULL, NULL },
  { "time_period", test_time_period, TT_FORK,
    NULL, NULL },
  { "desc_overlap_period", test_desc_overlap_period, TT_FORK,
    NULL, NULL },

  END_OF_TESTCASES
};

