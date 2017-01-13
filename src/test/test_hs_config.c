/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_config.c
 * \brief Test hidden service configuration functionality.
 */

#define CONFIG_PRIVATE

#include "test.h"
#include "test_helpers.h"
#include "log_test_helpers.h"
#include "hs_config.h"
#include "config.h"

static int
helper_config_service_v2(const char *conf, int validate_only)
{
  int ret = 0;
  or_options_t *options = NULL;
  tt_assert(conf);
  options = helper_parse_options(conf);
  tt_assert(options);
  ret = hs_config_service_all(options, validate_only);
 done:
  or_options_free(options);
  return ret;
}

static void
test_invalid_service_v2(void *arg)
{
  int validate_only = 1, ret;

  (void) arg;

  /* Try with a missing port configuration. */
  {
    const char *conf =
      "HiddenServiceDir /tmp/tor-test-hs-RANDOM/hs1\n"
      "HiddenServiceVersion 2\n";
    setup_full_capture_of_logs(LOG_WARN);
    ret = helper_config_service_v2(conf, validate_only);
    tt_int_op(ret, OP_EQ, -1);
    expect_log_msg_containing("with no ports configured.");
    teardown_capture_of_logs();
  }

  /* Out of order directives. */
  {
    const char *conf =
      "HiddenServiceVersion 2\n"
      "HiddenServiceDir /tmp/tor-test-hs-RANDOM/hs1\n"
      "HiddenServicePort 80\n";
    setup_full_capture_of_logs(LOG_WARN);
    ret = helper_config_service_v2(conf, validate_only);
    tt_int_op(ret, OP_EQ, -1);
    expect_log_msg_containing("HiddenServiceVersion with no preceding "
                              "HiddenServiceDir directive");
    teardown_capture_of_logs();
  }

  /* Bad port. */
  {
    const char *conf =
      "HiddenServiceDir /tmp/tor-test-hs-RANDOM/hs1\n"
      "HiddenServiceVersion 2\n"
      "HiddenServicePort 65536\n";
    setup_full_capture_of_logs(LOG_WARN);
    ret = helper_config_service_v2(conf, validate_only);
    tt_int_op(ret, OP_EQ, -1);
    expect_log_msg_containing("Missing or invalid port");
    teardown_capture_of_logs();
  }

  /* Too many introduction points. */
  {
    const char *conf =
      "HiddenServiceDir /tmp/tor-test-hs-RANDOM/hs1\n"
      "HiddenServiceVersion 2\n"
      "HiddenServicePort 80\n"
      "HiddenServiceNumIntroductionPoints 11\n"; /* One too many. */
    setup_full_capture_of_logs(LOG_WARN);
    ret = helper_config_service_v2(conf, validate_only);
    tt_int_op(ret, OP_EQ, -1);
    expect_log_msg_containing("HiddenServiceNumIntroductionPoints should "
                              "be between 0 and 10, not 11");
    teardown_capture_of_logs();
  }

  /* Too much max streams. */
  {
    const char *conf =
      "HiddenServiceDir /tmp/tor-test-hs-RANDOM/hs1\n"
      "HiddenServiceVersion 2\n"
      "HiddenServicePort 80\n"
      "HiddenServiceMaxStreams 65536\n"; /* One too many. */
    setup_full_capture_of_logs(LOG_WARN);
    ret = helper_config_service_v2(conf, validate_only);
    tt_int_op(ret, OP_EQ, -1);
    expect_log_msg_containing("HiddenServiceMaxStreams should be between "
                              "0 and 65535, not 65536");
    teardown_capture_of_logs();
  }

  /* Bad authorized client type. */
  {
    const char *conf =
      "HiddenServiceDir /tmp/tor-test-hs-RANDOM/hs1\n"
      "HiddenServiceVersion 2\n"
      "HiddenServicePort 80\n"
      "HiddenServiceAuthorizeClient blah alice,bob\n"; /* blah is no good. */
    setup_full_capture_of_logs(LOG_WARN);
    ret = helper_config_service_v2(conf, validate_only);
    tt_int_op(ret, OP_EQ, -1);
    expect_log_msg_containing("HiddenServiceAuthorizeClient contains "
                              "unrecognized auth-type");
    teardown_capture_of_logs();
  }

  /* Duplicate directory directive. */
  {
    const char *conf =
      "HiddenServiceDir /tmp/tor-test-hs-RANDOM/hs1\n"
      "HiddenServiceVersion 2\n"
      "HiddenServicePort 80\n"
      "HiddenServiceDir /tmp/tor-test-hs-RANDOM/hs1\n"
      "HiddenServiceVersion 2\n"
      "HiddenServicePort 81\n";
    setup_full_capture_of_logs(LOG_WARN);
    ret = helper_config_service_v2(conf, validate_only);
    tt_int_op(ret, OP_EQ, -1);
    expect_log_msg_containing("Another hidden service is already "
                              "configured for directory");
    teardown_capture_of_logs();
  }

 done:
  ;
}

static void
test_valid_service_v2(void *arg)
{
  int ret;

  (void) arg;

  /* Valid complex configuration. Basic client authorization. */
  {
    const char *conf =
      "HiddenServiceDir /tmp/tor-test-hs-RANDOM/hs1\n"
      "HiddenServiceVersion 2\n"
      "HiddenServicePort 80\n"
      "HiddenServicePort 22 localhost:22\n"
      "HiddenServicePort 42 unix:/path/to/socket\n"
      "HiddenServiceAuthorizeClient basic alice,bob,eve\n"
      "HiddenServiceAllowUnknownPorts 1\n"
      "HiddenServiceMaxStreams 42\n"
      "HiddenServiceMaxStreamsCloseCircuit 0\n"
      "HiddenServiceDirGroupReadable 1\n"
      "HiddenServiceNumIntroductionPoints 7\n";
    ret = helper_config_service_v2(conf, 1);
    tt_int_op(ret, OP_EQ, 0);
  }

  /* Valid complex configuration. Stealth client authorization. */
  {
    const char *conf =
      "HiddenServiceDir /tmp/tor-test-hs-RANDOM/hs2\n"
      "HiddenServiceVersion 2\n"
      "HiddenServicePort 65535\n"
      "HiddenServicePort 22 1.1.1.1:22\n"
      "HiddenServicePort 9000 unix:/path/to/socket\n"
      "HiddenServiceAuthorizeClient stealth charlie,romeo\n"
      "HiddenServiceAllowUnknownPorts 0\n"
      "HiddenServiceMaxStreams 42\n"
      "HiddenServiceMaxStreamsCloseCircuit 0\n"
      "HiddenServiceDirGroupReadable 1\n"
      "HiddenServiceNumIntroductionPoints 8\n";
    ret = helper_config_service_v2(conf, 1);
    tt_int_op(ret, OP_EQ, 0);
  }

 done:
  ;
}

struct testcase_t hs_config_tests[] = {
  { "invalid_service_v2", test_invalid_service_v2, TT_FORK,
    NULL, NULL },
  { "valid_service_v2", test_valid_service_v2, TT_FORK,
    NULL, NULL },

  END_OF_TESTCASES
};

