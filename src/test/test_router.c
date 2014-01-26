/* Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_router.c
 * \brief Unit tests for router related functions.
 **/

#include "or.h"
#include "nodelist.h"
#include "router.h"
#include "test.h"


/** Tese the case when node_get_by_id() returns NULL, node_describe_by_id
 * should return the base 16 encoding of the id.
 */
static void
test_node_describe_by_id_null_node(void *arg)
{
  (void) arg;

  #define ID "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"

  /* make sure node_get_by_id returns NULL */
  test_assert(!node_get_by_id(ID));
  test_streq(node_describe_by_id(ID),
              "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
done:
  return;
}

struct testcase_t router_tests[] = {
  { "node_get_by_id_null_node", test_node_describe_by_id_null_node, TT_FORK,
    NULL, NULL },
  END_OF_TESTCASES
};

