/* Copyright (c) 2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define TOR_CHANNEL_INTERNAL_
#include "or.h"
#include "channel.h"
#include "channeltls.h"
/* For init/free stuff */
#include "scheduler.h"

/* Test suite stuff */
#include "test.h"
#include "fakechans.h"

struct testcase_t channeltls_tests[] = {
  END_OF_TESTCASES
};

