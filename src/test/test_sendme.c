/* Copyright (c) 2014-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/* Unit tests for handling different kinds of relay cell */

#define CIRCUITLIST_PRIVATE
#define NETWORKSTATUS_PRIVATE
#define SENDME_PRIVATE
#define RELAY_PRIVATE

#include "core/or/circuit_st.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/circuitlist.h"
#include "core/or/relay.h"
#include "core/or/sendme.h"

#include "feature/nodelist/networkstatus.h"
#include "feature/nodelist/networkstatus_st.h"

#include "lib/crypt_ops/crypto_digest.h"

#include "test/test.h"
#include "test/log_test_helpers.h"

static void
setup_mock_consensus(void)
{
  current_md_consensus = current_ns_consensus =
    tor_malloc_zero(sizeof(networkstatus_t));
  current_md_consensus->net_params = smartlist_new();
  current_md_consensus->routerstatus_list = smartlist_new();
}

static void
free_mock_consensus(void)
{
  SMARTLIST_FOREACH(current_md_consensus->routerstatus_list, void *, r,
                    tor_free(r));
  smartlist_free(current_md_consensus->routerstatus_list);
  smartlist_free(current_ns_consensus->net_params);
  tor_free(current_ns_consensus);
}

static void
test_v1_record_digest(void *arg)
{
  or_circuit_t *or_circ = NULL;
  origin_circuit_t *orig_circ = NULL;
  circuit_t *circ = NULL;

  (void) arg;

  /* Create our dummy circuits. */
  orig_circ = origin_circuit_new();
  tt_assert(orig_circ);
  or_circ = or_circuit_new(1, NULL);

  /* Start by pointing to the origin circuit. */
  circ = TO_CIRCUIT(orig_circ);
  circ->purpose = CIRCUIT_PURPOSE_S_REND_JOINED;

  /* We should never note SENDME digest on origin circuit. */
  sendme_record_cell_digest(circ);
  tt_assert(!circ->sendme_last_digests);
  /* We do not need the origin circuit for now. */
  orig_circ = NULL;
  circuit_free_(circ);
  /* Points it to the OR circuit now. */
  circ = TO_CIRCUIT(or_circ);

  /* The package window has to be a multiple of CIRCWINDOW_INCREMENT minus 1
   * in order to catched the CIRCWINDOW_INCREMENT-nth cell. Try something that
   * shouldn't be noted. */
  circ->package_window = CIRCWINDOW_INCREMENT;
  sendme_record_cell_digest(circ);
  tt_assert(!circ->sendme_last_digests);

  /* This should work now. Package window at CIRCWINDOW_INCREMENT + 1. */
  circ->package_window++;
  sendme_record_cell_digest(circ);
  tt_assert(circ->sendme_last_digests);
  tt_int_op(smartlist_len(circ->sendme_last_digests), OP_EQ, 1);

  /* Next cell in the package window shouldn't do anything. */
  circ->package_window++;
  sendme_record_cell_digest(circ);
  tt_int_op(smartlist_len(circ->sendme_last_digests), OP_EQ, 1);

  /* The next CIRCWINDOW_INCREMENT should add one more digest. */
  circ->package_window = (CIRCWINDOW_INCREMENT * 2) + 1;
  sendme_record_cell_digest(circ);
  tt_int_op(smartlist_len(circ->sendme_last_digests), OP_EQ, 2);

 done:
  circuit_free_(circ);
}

static void
test_v1_consensus_params(void *arg)
{
  (void) arg;

  setup_mock_consensus();
  tt_assert(current_md_consensus);

  /* Both zeroes. */
  smartlist_add(current_md_consensus->net_params,
                (void *) "sendme_emit_min_version=0");
  smartlist_add(current_md_consensus->net_params,
                (void *) "sendme_accept_min_version=0");
  tt_int_op(get_emit_min_version(), OP_EQ, 0);
  tt_int_op(get_accept_min_version(), OP_EQ, 0);
  smartlist_clear(current_md_consensus->net_params);

  /* Both ones. */
  smartlist_add(current_md_consensus->net_params,
                (void *) "sendme_emit_min_version=1");
  smartlist_add(current_md_consensus->net_params,
                (void *) "sendme_accept_min_version=1");
  tt_int_op(get_emit_min_version(), OP_EQ, 1);
  tt_int_op(get_accept_min_version(), OP_EQ, 1);
  smartlist_clear(current_md_consensus->net_params);

  /* Different values from each other. */
  smartlist_add(current_md_consensus->net_params,
                (void *) "sendme_emit_min_version=1");
  smartlist_add(current_md_consensus->net_params,
                (void *) "sendme_accept_min_version=0");
  tt_int_op(get_emit_min_version(), OP_EQ, 1);
  tt_int_op(get_accept_min_version(), OP_EQ, 0);
  smartlist_clear(current_md_consensus->net_params);

  /* Validate is the cell version is coherent with our internal default value
   * and the one in the consensus. */
  smartlist_add(current_md_consensus->net_params,
                (void *) "sendme_accept_min_version=1");
  /* Minimum acceptable value is 1. */
  tt_int_op(cell_version_is_valid(1), OP_EQ, true);
  /* Minimum acceptable value is 1 so a cell version of 0 is refused. */
  tt_int_op(cell_version_is_valid(0), OP_EQ, false);

 done:
  free_mock_consensus();
}

static void
test_v1_build_cell(void *arg)
{
  uint8_t payload[RELAY_PAYLOAD_SIZE], digest[DIGEST_LEN];
  ssize_t ret;
  crypto_digest_t *cell_digest = NULL;
  or_circuit_t *or_circ = NULL;
  circuit_t *circ = NULL;

  (void) arg;

  or_circ = or_circuit_new(1, NULL);
  circ = TO_CIRCUIT(or_circ);

  cell_digest = crypto_digest_new();
  tt_assert(cell_digest);
  crypto_digest_add_bytes(cell_digest, "AAAAAAAAAAAAAAAAAAAA", 20);
  crypto_digest_get_digest(cell_digest, (char *) digest, sizeof(digest));

  /* SENDME v1 payload is 3 bytes + 20 bytes digest. See spec. */
  ret = build_cell_payload_v1(digest, payload);
  tt_int_op(ret, OP_EQ, 23);

  /* Validation. */

  /* An empty payload means SENDME version 0 thus valid. */
  tt_int_op(sendme_is_valid(circ, payload, 0), OP_EQ, true);

  /* An unparseable cell means invalid. */
  setup_full_capture_of_logs(LOG_INFO);
  tt_int_op(sendme_is_valid(circ, (const uint8_t *) "A", 1), OP_EQ, false);
  expect_log_msg_containing("Unparseable SENDME cell received. "
                            "Closing circuit.");
  teardown_capture_of_logs();

  /* No cell digest recorded for this. */
  setup_full_capture_of_logs(LOG_INFO);
  tt_int_op(sendme_is_valid(circ, payload, sizeof(payload)), OP_EQ, false);
  expect_log_msg_containing("We received a SENDME but we have no cell digests "
                            "to match. Closing circuit.");
  teardown_capture_of_logs();

  /* Note the wrong digest in the circuit, cell should fail validation. */
  circ->package_window = CIRCWINDOW_INCREMENT + 1;
  sendme_record_cell_digest(circ);
  tt_int_op(smartlist_len(circ->sendme_last_digests), OP_EQ, 1);
  setup_full_capture_of_logs(LOG_INFO);
  tt_int_op(sendme_is_valid(circ, payload, sizeof(payload)), OP_EQ, false);
  /* After a validation, the last digests is always popped out. */
  tt_int_op(smartlist_len(circ->sendme_last_digests), OP_EQ, 0);
  expect_log_msg_containing("SENDME v1 cell digest do not match.");
  teardown_capture_of_logs();

  /* Record the cell digest into the circuit, cell should validate. */
  memcpy(or_circ->crypto.sendme_digest, digest, sizeof(digest));
  circ->package_window = CIRCWINDOW_INCREMENT + 1;
  sendme_record_cell_digest(circ);
  tt_int_op(smartlist_len(circ->sendme_last_digests), OP_EQ, 1);
  tt_int_op(sendme_is_valid(circ, payload, sizeof(payload)), OP_EQ, true);
  /* After a validation, the last digests is always popped out. */
  tt_int_op(smartlist_len(circ->sendme_last_digests), OP_EQ, 0);

 done:
  crypto_digest_free(cell_digest);
  circuit_free_(circ);
}

static void
test_cell_payload_pad(void *arg)
{
  size_t pad_offset, payload_len, expected_offset;

  (void) arg;

  /* Offset should be 0, not enough room for padding. */
  payload_len = RELAY_PAYLOAD_SIZE;
  pad_offset = get_pad_cell_offset(payload_len);
  tt_int_op(pad_offset, OP_EQ, 0);
  tt_int_op(CELL_PAYLOAD_SIZE - pad_offset, OP_LE, CELL_PAYLOAD_SIZE);

  /* Still no room because we keep 4 extra bytes. */
  pad_offset = get_pad_cell_offset(payload_len - 4);
  tt_int_op(pad_offset, OP_EQ, 0);
  tt_int_op(CELL_PAYLOAD_SIZE - pad_offset, OP_LE, CELL_PAYLOAD_SIZE);

  /* We should have 1 byte of padding. Meaning, the offset should be the
   * CELL_PAYLOAD_SIZE minus 1 byte. */
  expected_offset = CELL_PAYLOAD_SIZE - 1;
  pad_offset = get_pad_cell_offset(payload_len - 5);
  tt_int_op(pad_offset, OP_EQ, expected_offset);
  tt_int_op(CELL_PAYLOAD_SIZE - pad_offset, OP_LE, CELL_PAYLOAD_SIZE);

  /* Now some arbitrary small payload length. The cell size is header + 10 +
   * extra 4 bytes we keep so the offset should be there. */
  expected_offset = RELAY_HEADER_SIZE + 10 + 4;
  pad_offset = get_pad_cell_offset(10);
  tt_int_op(pad_offset, OP_EQ, expected_offset);
  tt_int_op(CELL_PAYLOAD_SIZE - pad_offset, OP_LE, CELL_PAYLOAD_SIZE);

  /* Data length of 0. */
  expected_offset = RELAY_HEADER_SIZE + 4;
  pad_offset = get_pad_cell_offset(0);
  tt_int_op(pad_offset, OP_EQ, expected_offset);
  tt_int_op(CELL_PAYLOAD_SIZE - pad_offset, OP_LE, CELL_PAYLOAD_SIZE);

 done:
  ;
}

struct testcase_t sendme_tests[] = {
  { "v1_record_digest", test_v1_record_digest, TT_FORK,
    NULL, NULL },
  { "v1_consensus_params", test_v1_consensus_params, TT_FORK,
    NULL, NULL },
  { "v1_build_cell", test_v1_build_cell, TT_FORK,
    NULL, NULL },
  { "cell_payload_pad", test_cell_payload_pad, TT_FORK,
    NULL, NULL },

  END_OF_TESTCASES
};
