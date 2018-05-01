/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information     */

/**
 * \file test_onion.c
 * \brief Unittests for code in src/or/onion.c
 **/

#define TOR_ONION_PRIVATE

#include "or.h"
#include "connection_or.h"
#include "compat.h"
#include "onion.h"

/* Trunnel */
#include "cell_created2v.h"

/* Test suite stuff */
#include "test.h"
#include "log_test_helpers.h"
#include "torlog.h"

static create2v_cell_t*
helper_get_mock_create2v_cell(void)
{
  const uint16_t handshake_type = 9001;
  const uint8_t handshake_len = 32;
  const uint8_t handshake_data[32] = {  1,  2,  3,  4,  5,  6,  7,  8,
                                        9, 10, 11, 12, 13, 14, 15, 16,
                                       17, 18, 19, 20, 21, 22, 23, 24,
                                       25, 16, 27, 28, 29, 30, 31, 32, };
  const uint8_t padding_len = handshake_len;
  const uint8_t *padding_data = handshake_data;

  create2v_cell_t *mocked = create2v_cell_new();

  create2v_cell_init(mocked, handshake_type, handshake_data, handshake_len,
                     padding_data, padding_len);

  return mocked;
}

static create2v_cell_t*
helper_get_mock_create2v_cell_no_padding(void)
{
  const uint16_t handshake_type = 9001;
  const uint8_t handshake_len = 32;
  const uint8_t handshake_data[32] = {  1,  2,  3,  4,  5,  6,  7,  8,
                                        9, 10, 11, 12, 13, 14, 15, 16,
                                       17, 18, 19, 20, 21, 22, 23, 24,
                                       25, 16, 27, 28, 29, 30, 31, 32, };
  const uint8_t padding_len = 0;
  const uint8_t *padding_data = 0;

  create2v_cell_t *mocked = create2v_cell_new();

  create2v_cell_init(mocked, handshake_type, handshake_data, handshake_len,
                     padding_data, padding_len);

  return mocked;
}

static created2v_cell_t*
helper_get_mock_created2v_cell(void)
{
  const uint16_t handshake_type = 9001;
  const uint8_t handshake_len = 32;
  const uint8_t handshake_data[32] = {  1,  2,  3,  4,  5,  6,  7,  8,
                                        9, 10, 11, 12, 13, 14, 15, 16,
                                       17, 18, 19, 20, 21, 22, 23, 24,
                                       25, 16, 27, 28, 29, 30, 31, 32, };
  const uint8_t padding_len = handshake_len;
  const uint8_t *padding_data = handshake_data;
  created2v_cell_t *mocked = created2v_cell_new();

  created2v_cell_init(mocked, handshake_type, handshake_data, handshake_len,
                      padding_data, padding_len);

  return mocked;
}

/**
 * Calling create2v_cell_parse() with a cell with an unknown command
 * should return false.
 */
static void
test_onion_create2v_cell_parse_unknown_command(void *arg)
{
  (void)arg;

  create2v_cell_t *mocked = helper_get_mock_create2v_cell();
  create2v_cell_t *decoded;
  var_cell_t *encoded;
  size_t payload_len;

  payload_len = create2v_cell_body_encoded_len(mocked->body);
  encoded = var_cell_new(payload_len);
  decoded = create2v_cell_new();

  tt_assert(create2v_cell_format_relayed(encoded, payload_len, mocked));

  encoded->headers.command = RELAY_COMMAND_EXTEND2;

  tt_assert(!create2v_cell_parse(decoded, encoded));

 done:
  create2v_cell_free(mocked);
  create2v_cell_free(decoded);
  var_cell_free(encoded);
}

/**
 * Calling create2v_cell_parse() with a cell with greater than the
 * maximum allowed payload size should return false.
 */
static void
test_onion_create2v_cell_parse_payload_too_large(void *arg)
{
  (void)arg;

  create2v_cell_t *mocked = helper_get_mock_create2v_cell();
  create2v_cell_t *decoded;
  var_cell_t *encoded;
  size_t payload_len;

  payload_len = create2v_cell_body_encoded_len(mocked->body);
  encoded = var_cell_new(payload_len);
  decoded = create2v_cell_new();

  tt_assert(create2v_cell_format_relayed(encoded, payload_len, mocked));

  encoded->payload_len = 10240 + 2 + 2 + (sizeof(size_t) * 4) + 1 + 1;

  tt_assert(!create2v_cell_parse(decoded, encoded));

 done:
  create2v_cell_free(mocked);
  create2v_cell_free(decoded);
  var_cell_free(encoded);
}

/**
 * Calling create2v_cell_parse() with a cell with zero length
 * should return false.
 */
static void
test_onion_create2v_cell_parse_empty(void *arg)
{
  (void)arg;

  create2v_cell_t *mocked = helper_get_mock_create2v_cell();
  create2v_cell_t *decoded;
  var_cell_t *encoded;
  size_t payload_len;

  payload_len = create2v_cell_body_encoded_len(mocked->body);
  encoded = var_cell_new(payload_len);
  decoded = create2v_cell_new();

  tt_assert(create2v_cell_format_relayed(encoded, payload_len, mocked));

  encoded->payload_len = 0;

  tt_assert(!create2v_cell_parse(decoded, encoded));

 done:
  create2v_cell_free(mocked);
  create2v_cell_free(decoded);
  var_cell_free(encoded);
}

/**
 * Calling both create2v_cell_format_relayed() and then create2v_cell_parse()
 * twice should roundtrip for both the encoded and decoded cells.
 */
static void
test_onion_create2v_cell_format_parse_roundtrip(void *arg)
{
  (void)arg;

  create2v_cell_t *mocked = helper_get_mock_create2v_cell();
  create2v_cell_t *decoded;
  var_cell_t *encoded;
  var_cell_t *reencoded;
  size_t payload_len;

  payload_len = create2v_cell_body_encoded_len(mocked->body);
  reencoded = var_cell_new(payload_len);
  encoded = var_cell_new(payload_len);
  decoded = create2v_cell_new();

  /* Call the "relayed" version of create2v_cell_format_impl() because
   * the handshake 9001 likely isn't recognised. (I hope.) */
  tt_assert(create2v_cell_format_relayed(encoded, payload_len, mocked));
  tt_assert(create2v_cell_parse(decoded, encoded));

  tt_int_op(create2v_cell_body_get_htype(decoded->body), OP_EQ,
            create2v_cell_body_get_htype(mocked->body));
  tt_int_op(create2v_cell_body_get_hlen(decoded->body), OP_EQ,
            create2v_cell_body_get_hlen(mocked->body));
  tt_int_op(create2v_cell_body_encoded_len(decoded->body), OP_EQ,
            create2v_cell_body_encoded_len(mocked->body));
  tt_mem_op(create2v_cell_body_getarray_hdata(decoded->body), OP_EQ,
            create2v_cell_body_getarray_hdata(mocked->body),
            create2v_cell_body_get_hlen(mocked->body));
  tt_mem_op(create2v_cell_body_getarray_ignored(decoded->body), OP_EQ,
            create2v_cell_body_getarray_ignored(mocked->body),
            create2v_cell_body_getlen_ignored(mocked->body));

  tt_assert(create2v_cell_format_relayed(reencoded, payload_len, decoded));

  tt_mem_op(reencoded, OP_EQ, encoded, payload_len);

 done:
  create2v_cell_free(mocked);
  create2v_cell_free(decoded);
  var_cell_free(encoded);
  var_cell_free(reencoded);
}

static void
test_onion_create2v_cell_format_parse_no_padding(void *arg)
{
  (void)arg;

  create2v_cell_t *mocked = helper_get_mock_create2v_cell_no_padding();
  create2v_cell_t *decoded;
  var_cell_t *encoded;
  size_t payload_len;

  payload_len = create2v_cell_body_encoded_len(mocked->body);
  encoded = var_cell_new(payload_len);
  decoded = create2v_cell_new();

  /* Call the "relayed" version of create2v_cell_format_impl() because
   * the handshake 9001 likely isn't recognised. (I hope.) */
  tt_assert(create2v_cell_format_relayed(encoded, payload_len, mocked));
  tt_assert(create2v_cell_parse(decoded, encoded));
  tt_assert(create2v_cell_check(decoded, true));

  tt_int_op(create2v_cell_body_get_htype(decoded->body), OP_EQ,
            create2v_cell_body_get_htype(mocked->body));
  tt_int_op(create2v_cell_body_get_hlen(decoded->body), OP_EQ,
            create2v_cell_body_get_hlen(mocked->body));
  tt_int_op(create2v_cell_body_encoded_len(decoded->body), OP_EQ,
            create2v_cell_body_encoded_len(mocked->body));
  tt_mem_op(create2v_cell_body_getarray_hdata(decoded->body), OP_EQ,
            create2v_cell_body_getarray_hdata(mocked->body),
            create2v_cell_body_get_hlen(mocked->body));
  tt_int_op(create2v_cell_body_getlen_ignored(decoded->body), OP_EQ, 0);

 done:
  create2v_cell_free(mocked);
  create2v_cell_free(decoded);
  var_cell_free(encoded);
}

/**
 * Calling create2v_cell_check() with a recognised handshake type should
 * succeed.
 */
static void
test_onion_create2v_cell_check_recognised_htype(void *arg)
{
  (void)arg;

  create2v_cell_t *mocked = helper_get_mock_create2v_cell();

  /* Set the handshake type to something we recognise. */
  create2v_cell_body_set_htype(mocked->body, ONION_HANDSHAKE_TYPE_NTOR2_NULL);

  tt_assert(create2v_cell_check(mocked, false));

 done:
  create2v_cell_free(mocked);
}

/**
 * Calling create2v_cell_check() with an unrecognised handshake type should
 * fail.
 */
static void
test_onion_create2v_cell_check_unrecognised_htype(void *arg)
{
  (void)arg;

  create2v_cell_t *mocked = helper_get_mock_create2v_cell();

  tt_assert(!create2v_cell_check(mocked, false));

 done:
  create2v_cell_free(mocked);
}

/**
 * Calling create2v_cell_check() with a handshake length longer than expected
 * should fail.
 */
static void
test_onion_create2v_cell_check_hlen_too_long(void *arg)
{
  (void)arg;

  create2v_cell_t *mocked = helper_get_mock_create2v_cell();

  const uint8_t hdata[85] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                              0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24,
                              0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32,
                              0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40,
                              0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
                              0x49, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56,
                              0x57, 0x58, 0x59, 0x60, 0x61, 0x62, 0x63, 0x64,
                              0x65, 0x66, 0x67, 0x68, 0x69, 0x70, 0x71, 0x72,
                              0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x80,
                              0x81, 0x82, 0x83, 0x84, 0x85, };

  /* Set the handshake type to something we recognise. */
  create2v_cell_body_set_htype(mocked->body, ONION_HANDSHAKE_TYPE_NTOR2_NULL);

  /* Set the handshake data and length to something longer than expected. */
  create2v_cell_body_setlen_hdata(mocked->body, 85);
  memcpy(create2v_cell_body_getarray_hdata(mocked->body), hdata, 85);
  create2v_cell_body_set_hlen(mocked->body, 85);

  tt_assert(!create2v_cell_check(mocked, false));

 done:
  create2v_cell_free(mocked);
}

/**
 * Calling create2v_cell_check() with a mismatched hlen and hdata.len
 * should fail the create2v_cell_body_check().
 */
static void
test_onion_create2v_cell_check_hlen_mismatch(void *arg)
{
  (void)arg;

  create2v_cell_t *mocked = helper_get_mock_create2v_cell();

  create2v_cell_body_set_hlen(mocked->body, 85);

  setup_full_capture_of_logs(LOG_WARN);
  create2v_cell_check(mocked, false);
  expect_log_msg_containing("Length mismatch for hdata");

 done:
  teardown_capture_of_logs();
  create2v_cell_free(mocked);
}

/**
 * Calling create2v_cell_format() with an unrecognised handshake type should
 * fail.
 */
static void
test_onion_create2v_cell_format_unrecognised(void *arg)
{
  (void)arg;

  create2v_cell_t *mocked = helper_get_mock_create2v_cell();
  var_cell_t *encoded;
  size_t payload_len;

  payload_len = create2v_cell_body_encoded_len(mocked->body);
  encoded = var_cell_new(payload_len);

  tt_assert(!create2v_cell_format(encoded, payload_len, mocked));

 done:
  create2v_cell_free(mocked);
  var_cell_free(encoded);
}

/**
 * Calling create2v_cell_format() with an recognised handshake type should
 * succeed.
 */
static void
test_onion_create2v_cell_format_recognised(void *arg)
{
  (void)arg;

  create2v_cell_t *mocked = helper_get_mock_create2v_cell();
  var_cell_t *encoded;
  size_t payload_len;

  payload_len = create2v_cell_body_encoded_len(mocked->body);
  encoded = var_cell_new(payload_len);

  /* Set the handshake type to something we recognise. */
  create2v_cell_body_set_htype(mocked->body, ONION_HANDSHAKE_TYPE_NTOR2_NULL);

  tt_assert(create2v_cell_format(encoded, payload_len, mocked));

 done:
  create2v_cell_free(mocked);
  var_cell_free(encoded);
}

/**
 * Calling both created2v_cell_format() and then created2v_cell_parse()
 * twice should roundtrip for both the encoded and decoded cells.
 */
static void
test_onion_created2v_cell_format_parse_roundtrip(void *arg)
{
  (void)arg;

  created2v_cell_t *mocked = helper_get_mock_created2v_cell();
  created2v_cell_t *decoded;
  var_cell_t *encoded;
  var_cell_t *reencoded;
  size_t payload_len;

  payload_len = created2v_cell_body_encoded_len(mocked->body);
  reencoded = var_cell_new(payload_len);
  encoded = var_cell_new(payload_len);
  decoded = created2v_cell_new();

  tt_assert(created2v_cell_format(encoded, payload_len, mocked));
  tt_assert(created2v_cell_parse(decoded, encoded));

  tt_int_op(created2v_cell_body_get_hlen(decoded->body), OP_EQ,
            created2v_cell_body_get_hlen(mocked->body));
  tt_int_op(created2v_cell_body_encoded_len(decoded->body), OP_EQ,
            created2v_cell_body_encoded_len(mocked->body));
  tt_mem_op(created2v_cell_body_getarray_hdata(decoded->body), OP_EQ,
            created2v_cell_body_getarray_hdata(mocked->body),
            created2v_cell_body_get_hlen(mocked->body));
  tt_mem_op(created2v_cell_body_getarray_ignored(decoded->body), OP_EQ,
            created2v_cell_body_getarray_ignored(mocked->body),
            created2v_cell_body_getlen_ignored(mocked->body));

  tt_assert(created2v_cell_format(reencoded, payload_len, decoded));

  tt_mem_op(reencoded, OP_EQ, encoded, payload_len);

 done:
  created2v_cell_free(mocked);
  created2v_cell_free(decoded);
  var_cell_free(encoded);
  var_cell_free(reencoded);
}

/**
 * Calling created2v_cell_check() with a mismatched hlen and hdata.len
 * should fail the created2v_cell_body_check().
 */
static void
test_onion_created2v_cell_check_hlen_mismatch(void *arg)
{
  (void)arg;

  created2v_cell_t *mocked = helper_get_mock_created2v_cell();

  created2v_cell_body_set_hlen(mocked->body, 85);

  setup_full_capture_of_logs(LOG_WARN);
  created2v_cell_check(mocked);
  expect_log_msg_containing("Length mismatch for hdata");

 done:
  teardown_capture_of_logs();
  created2v_cell_free(mocked);
}

#define ONION_TEST(name, flags) \
  { #name, test_onion_ ##name, (flags), NULL, NULL }

struct testcase_t onion_tests[] = {
  ONION_TEST(create2v_cell_parse_unknown_command, 0),
  ONION_TEST(create2v_cell_parse_payload_too_large, 0),
  ONION_TEST(create2v_cell_parse_empty, 0),
  ONION_TEST(create2v_cell_format_parse_roundtrip, 0),
  ONION_TEST(create2v_cell_format_parse_no_padding, 0),
  ONION_TEST(create2v_cell_format_unrecognised, 0),
  ONION_TEST(create2v_cell_format_recognised, 0),
  ONION_TEST(create2v_cell_check_recognised_htype, 0),
  ONION_TEST(create2v_cell_check_unrecognised_htype, 0),
  ONION_TEST(create2v_cell_check_hlen_too_long, 0),
  ONION_TEST(create2v_cell_check_hlen_mismatch, 0),
  ONION_TEST(created2v_cell_format_parse_roundtrip, 0),
  ONION_TEST(created2v_cell_check_hlen_mismatch, 0),
  END_OF_TESTCASES
};

