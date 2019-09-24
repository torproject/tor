/* Copyright (c) 2015-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define POLICIES_PRIVATE

#include "test/test.h"
#include "test/test_helpers.h"
#include "test/rend_test_helpers.h"

#include "core/or/or.h"
#include "core/or/circuitbuild.h"
#include "core/or/circuitlist.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "feature/control/control_fmt.h"
#include "core/or/cpath_build_state_st.h"
#include "core/or/addr_policy_st.h"
#include "feature/dirparse/policy_parse.h"

static void
test_rend_getinfo_circuit_status(void *arg) {
  (void) arg;
  const char onion_address[DIGEST_LEN] = "add2e33";
  origin_circuit_t *circ = TO_ORIGIN_CIRCUIT(dummy_origin_circuit_new(1));
  // PATH
  tor_addr_t addr;
  crypt_path_t *cpath = tor_malloc_zero(sizeof(crypt_path_t));
  cpath->magic = CRYPT_PATH_MAGIC;
  cpath->state = CPATH_STATE_OPEN;
  cpath->package_window = circuit_initial_package_window();
  cpath->deliver_window = CIRCWINDOW_START;
  cpath->prev = cpath;
  cpath->extend_info = extend_info_new(
      "nickname", onion_address, NULL, NULL, NULL, &addr, 0
      );
  circ->cpath = cpath;
  // BUILD_FLAGS
  cpath_build_state_t *build = tor_malloc_zero(sizeof(cpath_build_state_t));
  build->onehop_tunnel = 0;
  build->is_internal = 1;
  build->need_capacity = 0;
  build->need_uptime = 1;
  circ->build_state = build;
  // PURPOSE, HS_STATE
  circ->base_.purpose = CIRCUIT_PURPOSE_INTRO_POINT;
  // REND_QUERY
  circ->rend_data = mock_rend_data(onion_address);
  // SOCKS_USERNAME
  circ->socks_username = tor_strdup("username");
  circ->socks_username_len = strlen(circ->socks_username);
  // SOCKS_PASSWORD
  circ->socks_password = tor_strdup("password");
  circ->socks_password_len = strlen(circ->socks_password);
  // PATH_STATE
  circ->path_state = PATH_STATE_NEW_CIRC;
  // PREPEND_POLICY
  circ->prepend_policy = smartlist_new();
  int malformed_list = -1;
  addr_policy_t *reject_policy, *accept_policy;
  reject_policy = router_parse_addr_policy_item_from_string(
      "reject 127.0.0.1:1-2", ADDR_POLICY_REJECT, &malformed_list);
  accept_policy = router_parse_addr_policy_item_from_string(
      "accept 127.0.0.1:3-4", ADDR_POLICY_ACCEPT, &malformed_list);
  smartlist_add(circ->prepend_policy, reject_policy);
  smartlist_add(circ->prepend_policy, accept_policy);

   // Building expected fields in order from control-spec.txt
  smartlist_t *expected = smartlist_new();
  smartlist_add(expected, circuit_list_path_for_controller(circ));
  smartlist_add_strdup(expected, "BUILD_FLAGS=IS_INTERNAL,NEED_UPTIME");
  smartlist_add_strdup(expected, "PURPOSE=SERVER");
  smartlist_add_strdup(expected, "HS_STATE=OR_HSSI_ESTABLISHED");
  smartlist_add_asprintf(expected, "REND_QUERY=%s", onion_address);
  char tbuf[ISO_TIME_USEC_LEN+1];
  format_iso_time_nospace_usec(tbuf, &circ->base_.timestamp_created);
  smartlist_add_asprintf(expected, "TIME_CREATED=%s", tbuf);
  smartlist_add_asprintf(expected, "SOCKS_USERNAME=\"%s\"", circ->socks_username);
  smartlist_add_asprintf(expected, "SOCKS_PASSWORD=\"%s\"", circ->socks_password);
  smartlist_add_asprintf(expected, "UNUSABLE_FOR_NEW_CONNS=%u",
                         circ->unusable_for_new_conns);
  smartlist_add_asprintf(expected, "IDLE_TIMEOUT=%d",
                         circ->circuit_idle_timeout);
  smartlist_add_asprintf(expected, "EARLY_CELLS_SENT=%u",
                         circ->relay_early_cells_sent);
  smartlist_add_asprintf(expected, "REMAINING_RELAY_EARLY_CELLS=%u",
                         circ->remaining_relay_early_cells);
  smartlist_add_asprintf(expected, "PADDING_NEGOTIATION_FAILED=%u",
                         circ->padding_negotiation_failed);
  smartlist_add_strdup(expected, "PATH_STATE=NEW");
  smartlist_add_asprintf(expected, "HAS_RELAXED_TIMEOUT=%u",
                         circ->relaxed_timeout);
  smartlist_add_asprintf(expected, "IS_ANCIENT=%u", circ->is_ancient);
  smartlist_add_asprintf(expected, "HAS_OPENED=%u", circ->has_opened);
  smartlist_add_asprintf(expected, "HS_HAS_TIMED_OUT=%u",
                         circ->hs_circ_has_timed_out);
  smartlist_add_strdup(expected, "PREPEND_POLICY="
                                 "REJECT_127.0.0.1:1-2,"
                                 "ACCEPT_127.0.0.1:3-4");

  char *rendered = circuit_describe_status_for_controller(circ);
  smartlist_t *fields = smartlist_new();
  smartlist_split_string(fields, rendered, " ", 0, 0);

  // Assert number of fields & equality
  tt_int_op(fields->num_used, OP_EQ, expected->num_used);
  for (int i = 0; i < fields->num_used; ++i) {
    tt_str_op(smartlist_get(fields, i), OP_EQ, smartlist_get(expected, i));
  }

  done:
    tor_free(rendered);
    SMARTLIST_FOREACH(circ->prepend_policy, char *, cp, tor_free(cp));
    smartlist_free(circ->prepend_policy);
    SMARTLIST_FOREACH(expected, char *, cp, tor_free(cp));
    smartlist_free(expected);
    SMARTLIST_FOREACH(fields, char *, cp, tor_free(cp));
    smartlist_free(fields);
}

struct testcase_t controller_fmt_tests[] = {
    { "rend_getinfo_circuitstatus", test_rend_getinfo_circuit_status, TT_FORK,
      NULL, NULL },
    END_OF_TESTCASES
};
