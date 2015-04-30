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
#include "config.h"
#include "routerset.h"
#include "circuitbuild.h"
#include "test_helpers.h"

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

/* DuckDuckGo descriptor as an example. */
static const char *hs_desc_content = "\
rendezvous-service-descriptor g5ojobzupf275beh5ra72uyhb3dkpxwg\r\n\
version 2\r\n\
permanent-key\r\n\
-----BEGIN RSA PUBLIC KEY-----\r\n\
MIGJAoGBAJ/SzzgrXPxTlFrKVhXh3buCWv2QfcNgncUpDpKouLn3AtPH5Ocys0jE\r\n\
aZSKdvaiQ62md2gOwj4x61cFNdi05tdQjS+2thHKEm/KsB9BGLSLBNJYY356bupg\r\n\
I5gQozM65ENelfxYlysBjJ52xSDBd8C4f/p9umdzaaaCmzXG/nhzAgMBAAE=\r\n\
-----END RSA PUBLIC KEY-----\r\n\
secret-id-part anmjoxxwiupreyajjt5yasimfmwcnxlf\r\n\
publication-time 2015-03-11 19:00:00\r\n\
protocol-versions 2,3\r\n\
introduction-points\r\n\
-----BEGIN MESSAGE-----\r\n\
aW50cm9kdWN0aW9uLXBvaW50IDd1bnd4cmg2dG5kNGh6eWt1Z3EzaGZzdHduc2ll\r\n\
cmhyCmlwLWFkZHJlc3MgMTg4LjEzOC4xMjEuMTE4Cm9uaW9uLXBvcnQgOTAwMQpv\r\n\
bmlvbi1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dC\r\n\
QUxGRVVyeVpDbk9ROEhURmV5cDVjMTRObWVqL1BhekFLTTBxRENTNElKUWh0Y3g1\r\n\
NXpRSFdOVWIKQ2hHZ0JqR1RjV3ZGRnA0N3FkdGF6WUZhVXE2c0lQKzVqeWZ5b0Q4\r\n\
UmJ1bzBwQmFWclJjMmNhYUptWWM0RDh6Vgpuby9sZnhzOVVaQnZ1cWY4eHIrMDB2\r\n\
S0JJNmFSMlA2OE1WeDhrMExqcUpUU2RKOE9idm9yQWdNQkFBRT0KLS0tLS1FTkQg\r\n\
UlNBIFBVQkxJQyBLRVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQ\r\n\
VUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBTnJHb0ozeTlHNXQzN2F2ekI1cTlwN1hG\r\n\
VUplRUVYMUNOaExnWmJXWGJhVk5OcXpoZFhyL0xTUQppM1Z6dW5OaUs3cndUVnE2\r\n\
K2QyZ1lRckhMMmIvMXBBY3ZKWjJiNSs0bTRRc0NibFpjRENXTktRbHJnRWN5WXRJ\r\n\
CkdscXJTbFFEaXA0ZnNrUFMvNDVkWTI0QmJsQ3NGU1k3RzVLVkxJck4zZFpGbmJr\r\n\
NEZIS1hBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCmludHJv\r\n\
ZHVjdGlvbi1wb2ludCBiNGM3enlxNXNheGZzN2prNXFibG1wN3I1b3pwdHRvagpp\r\n\
cC1hZGRyZXNzIDEwOS4xNjkuNDUuMjI2Cm9uaW9uLXBvcnQgOTAwMQpvbmlvbi1r\r\n\
ZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQU8xSXpw\r\n\
WFFUTUY3RXZUb1NEUXpzVnZiRVFRQUQrcGZ6NzczMVRXZzVaUEJZY1EyUkRaeVp4\r\n\
OEQKNUVQSU1FeUE1RE83cGd0ak5LaXJvYXJGMC8yempjMkRXTUlSaXZyU29YUWVZ\r\n\
ZXlMM1pzKzFIajJhMDlCdkYxZAp6MEswblRFdVhoNVR5V3lyMHdsbGI1SFBnTlI0\r\n\
MS9oYkprZzkwZitPVCtIeGhKL1duUml2QWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBV\r\n\
QkxJQyBLRVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMg\r\n\
S0VZLS0tLS0KTUlHSkFvR0JBSzNWZEJ2ajFtQllLL3JrcHNwcm9Ub0llNUtHVmth\r\n\
QkxvMW1tK1I2YUVJek1VZFE1SjkwNGtyRwpCd3k5NC8rV0lGNFpGYXh5Z2phejl1\r\n\
N2pKY1k3ZGJhd1pFeG1hYXFCRlRwL2h2ZG9rcHQ4a1ByRVk4OTJPRHJ1CmJORUox\r\n\
N1FPSmVMTVZZZk5Kcjl4TWZCQ3JQai8zOGh2RUdrbWVRNmRVWElvbVFNaUJGOVRB\r\n\
Z01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCmludHJvZHVjdGlv\r\n\
bi1wb2ludCBhdjVtcWl0Y2Q3cjJkandsYmN0c2Jlc2R3eGt0ZWtvegppcC1hZGRy\r\n\
ZXNzIDE0NC43Ni44LjczCm9uaW9uLXBvcnQgNDQzCm9uaW9uLWtleQotLS0tLUJF\r\n\
R0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBTzVweVZzQmpZQmNmMXBE\r\n\
dklHUlpmWXUzQ05nNldka0ZLMGlvdTBXTGZtejZRVDN0NWhzd3cyVwpjejlHMXhx\r\n\
MmN0Nkd6VWkrNnVkTDlITTRVOUdHTi9BbW8wRG9GV1hKWHpBQkFXd2YyMVdsd1lW\r\n\
eFJQMHRydi9WCkN6UDkzcHc5OG5vSmdGUGRUZ05iMjdKYmVUZENLVFBrTEtscXFt\r\n\
b3NveUN2RitRa25vUS9BZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0t\r\n\
LS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpN\r\n\
SUdKQW9HQkFMVjNKSmtWN3lTNU9jc1lHMHNFYzFQOTVRclFRR3ZzbGJ6Wi9zRGxl\r\n\
RlpKYXFSOUYvYjRUVERNClNGcFMxcU1GbldkZDgxVmRGMEdYRmN2WVpLamRJdHU2\r\n\
SndBaTRJeEhxeXZtdTRKdUxrcXNaTEFLaXRLVkx4eGsKeERlMjlDNzRWMmJrOTRJ\r\n\
MEgybTNKS2tzTHVwc3VxWWRVUmhOVXN0SElKZmgyZmNIalF0bEFnTUJBQUU9Ci0t\r\n\
LS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0KCg==\r\n\
-----END MESSAGE-----\r\n\
signature\r\n\
-----BEGIN SIGNATURE-----\r\n\
d4OuCE5OLAOnRB6cQN6WyMEmg/BHem144Vec+eYgeWoKwx3MxXFplUjFxgnMlmwN\r\n\
PcftsZf2ztN0sbNCtPgDL3d0PqvxY3iHTQAI8EbaGq/IAJUZ8U4y963dD5+Bn6JQ\r\n\
myE3ctmh0vy5+QxSiRjmQBkuEpCyks7LvWvHYrhnmcg=\r\n\
-----END SIGNATURE-----";

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
  #define STR_DESC_ID "g5ojobzupf275beh5ra72uyhb3dkpxwg"

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
  control_event_hs_descriptor_received(rend_query.onion_address,
                                       &rend_query, HSDIR_EXIST_ID);
  expected_msg = "650 HS_DESC RECEIVED "STR_HS_ADDR" BASIC_AUTH "\
                  STR_HSDIR_EXIST_LONGNAME"\r\n";
  tt_assert(received_msg);
  tt_str_op(received_msg,OP_EQ, expected_msg);
  tor_free(received_msg);

  /* test failed event */
  rend_query.auth_type = 2;
  control_event_hs_descriptor_failed(&rend_query,
                                     HSDIR_NONE_EXIST_ID,
                                     "QUERY_REJECTED");
  expected_msg = "650 HS_DESC FAILED "STR_HS_ADDR" STEALTH_AUTH "\
                  STR_HSDIR_NONE_EXIST_LONGNAME" REASON=QUERY_REJECTED\r\n";
  tt_assert(received_msg);
  tt_str_op(received_msg,OP_EQ, expected_msg);
  tor_free(received_msg);

  /* test invalid auth type */
  rend_query.auth_type = 999;
  control_event_hs_descriptor_failed(&rend_query,
                                     HSDIR_EXIST_ID,
                                     "QUERY_REJECTED");
  expected_msg = "650 HS_DESC FAILED "STR_HS_ADDR" UNKNOWN "\
                  STR_HSDIR_EXIST_LONGNAME" REASON=QUERY_REJECTED\r\n";
  tt_assert(received_msg);
  tt_str_op(received_msg,OP_EQ, expected_msg);
  tor_free(received_msg);

  /* test valid content. */
  char *exp_msg;
  control_event_hs_descriptor_content(rend_query.onion_address, STR_DESC_ID,
                                      HSDIR_EXIST_ID, hs_desc_content);
  tor_asprintf(&exp_msg, "650+HS_DESC_CONTENT " STR_HS_ADDR " " STR_DESC_ID \
               " " STR_HSDIR_EXIST_LONGNAME "\r\n%s\r\n.\r\n650 OK\r\n",
               hs_desc_content);
  tt_assert(received_msg);
  tt_str_op(received_msg, OP_EQ, exp_msg);
  tor_free(received_msg);
  tor_free(exp_msg);

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

