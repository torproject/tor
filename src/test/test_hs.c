/* Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs.c
 * \brief Unit tests for hidden service.
 **/

#define CONTROL_PRIVATE
#define CIRCUITBUILD_PRIVATE

#include "or.h"
#include "test.h"
#include "control.h"
#include "testhelper.h"
#include "config.h"
#include "routerset.h"
#include "circuitbuild.h"

/* mock ID digest and longname for node that's in nodelist */
#define HSDIR_EXIST_ID "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA" \
                       "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
#define STR_HSDIR_EXIST_LONGNAME \
                       "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=TestDir"
/* mock ID digest and longname for node that's not in nodelist */
#define HSDIR_NONE_EXIST_ID "\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB" \
                            "\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
#define STR_HSDIR_NONE_EXIST_LONGNAME \
                       "$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

/* Helper global variable for hidden service descriptor event test.
 * It's used as a pointer to dynamically created message buffer in
 * send_control_event_string_replacement function, which mocks
 * send_control_event_string function.
 *
 * Always free it after use! */
static char *received_msg = NULL;

/** Mock function for send_control_event_string
 */
static void
send_control_event_string_replacement(uint16_t event, event_format_t which,
                                      const char *msg)
{
  (void) event;
  (void) which;
  tor_free(received_msg);
  received_msg = tor_strdup(msg);
}

/** Mock function for node_describe_longname_by_id, it returns either
 * STR_HSDIR_EXIST_LONGNAME or STR_HSDIR_NONE_EXIST_LONGNAME
 */
static const char *
node_describe_longname_by_id_replacement(const char *id_digest)
{
  if (!strcmp(id_digest, HSDIR_EXIST_ID)) {
    return STR_HSDIR_EXIST_LONGNAME;
  } else {
    return STR_HSDIR_NONE_EXIST_LONGNAME;
  }
}

/** Make sure each hidden service descriptor async event generation
 *
 * function generates the message in expected format.
 */
static void
test_hs_desc_event(void *arg)
{
  #define STR_HS_ADDR "ajhb7kljbiru65qo"
  #define STR_HS_ID "b3oeducbhjmbqmgw2i3jtz4fekkrinwj"

  rend_data_t rend_query;
  const char *expected_msg;

  (void) arg;
  MOCK(send_control_event_string,
       send_control_event_string_replacement);
  MOCK(node_describe_longname_by_id,
       node_describe_longname_by_id_replacement);

  /* setup rend_query struct */
  strncpy(rend_query.onion_address, STR_HS_ADDR,
          REND_SERVICE_ID_LEN_BASE32+1);
  rend_query.auth_type = 0;

  /* test request event */
  control_event_hs_descriptor_requested(&rend_query, HSDIR_EXIST_ID,
                                        STR_HS_ID);
  expected_msg = "650 HS_DESC REQUESTED "STR_HS_ADDR" NO_AUTH "\
                  STR_HSDIR_EXIST_LONGNAME" "STR_HS_ID"\r\n";
  tt_assert(received_msg);
  tt_str_op(received_msg,OP_EQ, expected_msg);
  tor_free(received_msg);

  /* test received event */
  rend_query.auth_type = 1;
  control_event_hs_descriptor_received(&rend_query, HSDIR_EXIST_ID);
  expected_msg = "650 HS_DESC RECEIVED "STR_HS_ADDR" BASIC_AUTH "\
                  STR_HSDIR_EXIST_LONGNAME"\r\n";
  tt_assert(received_msg);
  tt_str_op(received_msg,OP_EQ, expected_msg);
  tor_free(received_msg);

  /* test failed event */
  rend_query.auth_type = 2;
  control_event_hs_descriptor_failed(&rend_query, HSDIR_NONE_EXIST_ID,
                                     "QUERY_REJECTED");
  expected_msg = "650 HS_DESC FAILED "STR_HS_ADDR" STEALTH_AUTH "\
                  STR_HSDIR_NONE_EXIST_LONGNAME" REASON=QUERY_REJECTED\r\n";
  tt_assert(received_msg);
  tt_str_op(received_msg,OP_EQ, expected_msg);
  tor_free(received_msg);

  /* test invalid auth type */
  rend_query.auth_type = 999;
  control_event_hs_descriptor_failed(&rend_query, HSDIR_EXIST_ID,
                                     "QUERY_REJECTED");
  expected_msg = "650 HS_DESC FAILED "STR_HS_ADDR" UNKNOWN "\
                  STR_HSDIR_EXIST_LONGNAME" REASON=QUERY_REJECTED\r\n";
  tt_assert(received_msg);
  tt_str_op(received_msg,OP_EQ, expected_msg);
  tor_free(received_msg);

 done:
  UNMOCK(send_control_event_string);
  UNMOCK(node_describe_longname_by_id);
  tor_free(received_msg);
}

/* Make sure we always pick the right RP, given a well formatted
 * Tor2webRendezvousPoints value. */
static void
test_pick_tor2web_rendezvous_node(void *arg)
{
  or_options_t *options = get_options_mutable();
  const node_t *chosen_rp = NULL;
  router_crn_flags_t flags = CRN_NEED_DESC;
  int retval, i;
  const char *tor2web_rendezvous_str = "test003r";

  (void) arg;

  /* Setup fake routerlist. */
  helper_setup_fake_routerlist();

  /* Parse Tor2webRendezvousPoints as a routerset. */
  options->Tor2webRendezvousPoints = routerset_new();
  retval = routerset_parse(options->Tor2webRendezvousPoints,
                           tor2web_rendezvous_str,
                           "test_tor2web_rp");
  tt_int_op(retval, >=, 0);

  /* Pick rendezvous point. Make sure the correct one is
     picked. Repeat many times to make sure it works properly. */
  for (i = 0; i < 50 ; i++) {
    chosen_rp = pick_tor2web_rendezvous_node(flags, options);
    tt_assert(chosen_rp);
    tt_str_op(chosen_rp->ri->nickname, ==, tor2web_rendezvous_str);
  }

 done:
  routerset_free(options->Tor2webRendezvousPoints);
}

/* Make sure we never pick an RP if Tor2webRendezvousPoints doesn't
 * correspond to an actual node. */
static void
test_pick_bad_tor2web_rendezvous_node(void *arg)
{
  or_options_t *options = get_options_mutable();
  const node_t *chosen_rp = NULL;
  router_crn_flags_t flags = CRN_NEED_DESC;
  int retval, i;
  const char *tor2web_rendezvous_str = "dummy";

  (void) arg;

  /* Setup fake routerlist. */
  helper_setup_fake_routerlist();

  /* Parse Tor2webRendezvousPoints as a routerset. */
  options->Tor2webRendezvousPoints = routerset_new();
  retval = routerset_parse(options->Tor2webRendezvousPoints,
                           tor2web_rendezvous_str,
                           "test_tor2web_rp");
  tt_int_op(retval, >=, 0);

  /* Pick rendezvous point. Since Tor2webRendezvousPoints was set to a
     dummy value, we shouldn't find any eligible RPs. */
  for (i = 0; i < 50 ; i++) {
    chosen_rp = pick_tor2web_rendezvous_node(flags, options);
    tt_assert(!chosen_rp);
  }

 done:
  routerset_free(options->Tor2webRendezvousPoints);
}

struct testcase_t hs_tests[] = {
  { "hs_desc_event", test_hs_desc_event, TT_FORK,
    NULL, NULL },
  { "pick_tor2web_rendezvous_node", test_pick_tor2web_rendezvous_node, TT_FORK,
    NULL, NULL },
  { "pick_bad_tor2web_rendezvous_node",
    test_pick_bad_tor2web_rendezvous_node, TT_FORK,
    NULL, NULL },
  END_OF_TESTCASES
};

