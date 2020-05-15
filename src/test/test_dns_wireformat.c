/* Copyright (c) 2019 Christian Hofer.
 * Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_dns_wireformat.c
 * \brief Tests for DNS message wire-format encoding.
 */

#define DNS_WIREFORMAT_PRIVATE

#include "test/test.h"
#include "test/log_test_helpers.h"

#include "lib/container/dns_message.h"
#include "lib/container/dns_message_st.h"
#include "lib/encoding/dns_string.h"
#include "lib/encoding/dns_wireformat.h"
#include "lib/defs/dns_types.h"

//
// Message

static void
test_dns_wireformat_encode_message_with_invalid_question(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();

  dns_message_t *message = dns_message_new();
  message->header->qdcount = 1;

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of("abcd01234567890123456789012345678901234567890"
                                "1234567890123456789.example.com");
  smartlist_add(message->question_list, question);

  tt_int_op(dns_encode_message_udp(buf, message), OP_EQ, -2);

 done:
  buf_free(buf);
  dns_message_free(message);
}

static void
test_dns_wireformat_encode_message_with_invalid_answer(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();

  dns_message_t *message = dns_message_new();
  message->header->ancount = 1;

  dns_rr_t *rr = dns_rr_new();
  rr->rrtype = dns_type_of(DNS_TYPE_A);
  smartlist_add(message->answer_list, rr);

  tt_int_op(dns_encode_message_udp(buf, message), OP_EQ, -3);

 done:
  buf_free(buf);
  dns_message_free(message);
}

static void
test_dns_wireformat_encode_message_with_invalid_name_server(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();

  dns_message_t *message = dns_message_new();
  message->header->nscount = 1;

  dns_rr_t *rr = dns_rr_new();
  rr->rrtype = dns_type_of(DNS_TYPE_A);
  smartlist_add(message->name_server_list, rr);

  tt_int_op(dns_encode_message_udp(buf, message), OP_EQ, -4);

 done:
  buf_free(buf);
  dns_message_free(message);
}

static void
test_dns_wireformat_encode_message_with_invalid_additional_record(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();

  dns_message_t *message = dns_message_new();
  message->header->arcount = 1;

  dns_rr_t *rr = dns_rr_new();
  rr->rrtype = dns_type_of(DNS_TYPE_A);
  smartlist_add(message->additional_record_list, rr);

  tt_int_op(dns_encode_message_udp(buf, message), OP_EQ, -5);

 done:
  buf_free(buf);
  dns_message_free(message);
}

static void
test_dns_wireformat_encode_and_decode_message(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();

  dns_message_t *expected = dns_message_new();
  dns_message_t *actual = dns_message_new();

  expected->header->opcode = DNS_OPCODE_QUERY;
  expected->header->rd = true;
  expected->header->qdcount = 1;
  expected->header->ancount = 1;
  expected->header->nscount = 1;
  expected->header->arcount = 1;

  dns_question_t *dq = dns_question_new();
  dq->qname = dns_name_of("hello.");
  dq->qtype = dns_type_of(DNS_TYPE_SINK);
  dq->qclass = DNS_CLASS_CHAOS;
  smartlist_add(expected->question_list, dq);

  dns_rr_t *dan = dns_rr_new();
  dan->rrtype = dns_type_of(DNS_TYPE_SINK);
  dan->rrclass = DNS_CLASS_CHAOS;
  smartlist_add(expected->answer_list, dan);

  dns_rr_t *dns = dns_rr_new();
  dns->rrtype = dns_type_of(DNS_TYPE_SINK);
  dns->rrclass = DNS_CLASS_CHAOS;
  smartlist_add(expected->name_server_list, dns);

  dns_rr_t *dar = dns_rr_new();
  dar->rrtype = dns_type_of(DNS_TYPE_SINK);
  dar->rrclass = DNS_CLASS_CHAOS;
  smartlist_add(expected->additional_record_list, dar);

  tt_int_op(dns_encode_message_tcp(buf, expected), OP_EQ, 56);

  tt_int_op(dns_decode_message_tcp(actual, buf), OP_EQ, 56);
  tt_uint_op(actual->header->rd, OP_EQ, expected->header->rd);
  tt_uint_op(actual->header->qdcount, OP_EQ, expected->header->qdcount);
  tt_uint_op(actual->header->ancount, OP_EQ, expected->header->ancount);
  tt_uint_op(actual->header->nscount, OP_EQ, expected->header->nscount);
  tt_uint_op(actual->header->arcount, OP_EQ, expected->header->arcount);

 done:
  buf_free(buf);
  dns_message_free(expected);
  dns_message_free(actual);
}

static void
test_dns_wireformat_decode_message_with_invalid_header(void *arg)
{
  (void) arg;

  size_t size = 1;
  uint8_t data[1] = {
    0x001
  };

  buf_t *buf = buf_new();
  buf_add(buf, (const char *) data, size);

  dns_message_t *message = dns_message_new();

  tt_int_op(dns_decode_message_udp(message, buf), OP_EQ, -1);

 done:
  buf_free(buf);
  dns_message_free(message);
}

static void
test_dns_wireformat_decode_message_with_invalid_question(void *arg)
{
  (void) arg;

  size_t size = 12;
  uint8_t data[12] = {
    0x08, 0x4B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  };

  buf_t *buf = buf_new();
  buf_add(buf, (const char *) data, size);

  dns_message_t *message = dns_message_new();

  tt_int_op(dns_decode_message_udp(message, buf), OP_EQ, -2);

 done:
  buf_free(buf);
  dns_message_free(message);
}

static void
test_dns_wireformat_decode_message_with_invalid_answer(void *arg)
{
  (void) arg;

  size_t size = 12;
  uint8_t data[12] = {
    0x08, 0x4B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00
  };

  buf_t *buf = buf_new();
  buf_add(buf, (const char *) data, size);

  dns_message_t *message = dns_message_new();

  tt_int_op(dns_decode_message_udp(message, buf), OP_EQ, -3);

 done:
  buf_free(buf);
  dns_message_free(message);
}

static void
test_dns_wireformat_decode_message_with_invalid_name_server(void *arg)
{
  (void) arg;

  size_t size = 12;
  uint8_t data[12] = {
    0x08, 0x4B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00
  };

  buf_t *buf = buf_new();
  buf_add(buf, (const char *) data, size);

  dns_message_t *message = dns_message_new();

  tt_int_op(dns_decode_message_udp(message, buf), OP_EQ, -4);

 done:
  buf_free(buf);
  dns_message_free(message);
}

static void
test_dns_wireformat_decode_message_with_invalid_additional_record(void *arg)
{
  (void) arg;

  size_t size = 12;
  uint8_t data[12] = {
    0x08, 0x4B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01
  };

  buf_t *buf = buf_new();
  buf_add(buf, (const char *) data, size);

  dns_message_t *message = dns_message_new();

  tt_int_op(dns_decode_message_udp(message, buf), OP_EQ, -5);

 done:
  buf_free(buf);
  dns_message_free(message);
}

static void
test_dns_wireformat_decode_message_with_invalid_length(void *arg)
{
  (void) arg;

  size_t size = 13;
  uint8_t data[13] = {
    0x08, 0x4B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01
  };

  buf_t *buf = buf_new();
  buf_add(buf, (const char *) data, size);

  dns_message_t *message = dns_message_new();

  tt_int_op(dns_decode_message_udp(message, buf), OP_EQ, -6);

 done:
  buf_free(buf);
  dns_message_free(message);
}

static void
test_dns_wireformat_encode_digest_data(void *arg)
{
  (void) arg;

  uint8_t expected[] = {
    0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0x01,
    0x01, 0x03, 0x08, 0x03, 0x01, 0x00, 0x01
  };

  uint8_t rdata[] = {
    0x01, 0x01, 0x03, 0x08, 0x03, 0x01, 0x00, 0x01
  };

  dns_rr_t *rr = dns_rr_new();
  rr->name = dns_name_of("heLLo.");
  rr->rdata = tor_memdup(rdata, 8);
  rr->rdlength = 8;

  size_t data_len = 0;
  uint8_t *data = dns_encode_digest_data(rr, &data_len);

  tt_int_op(data_len, OP_EQ, 15);
  tt_mem_op(data, OP_EQ, expected, data_len);

 done:
  dns_rr_free(rr);
  tor_free(data);
}

static void
test_dns_wireformat_encode_digest_data_with_invalid_name(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();
  rr->name = dns_name_of("abcd012345678901234567890123456789012345678901234567"
                         "890123456789.example.com");

  size_t data_len = 0;
  dns_encode_digest_data(rr, &data_len);

  tt_int_op(data_len, OP_EQ, 0);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_key_tag(void *arg)
{
  (void) arg;

  uint8_t rdata[] = {
    0x01, 0x01, 0x03, 0x08, 0x03, 0x01, 0x00, 0x01,
    0xAC, 0xFF, 0xB4, 0x09, 0xBC, 0xC9, 0x39, 0xF8,
    0x31, 0xF7, 0xA1, 0xE5, 0xEC, 0x88, 0xF7, 0xA5,
    0x92, 0x55, 0xEC, 0x53, 0x04, 0x0B, 0xE4, 0x32
  };

  dns_rr_t *rr = dns_rr_new();
  rr->rdata = tor_memdup(rdata, 32);
  rr->rdlength = 32;

  tt_int_op(dns_encode_key_tag(rr), OP_EQ, 32201);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_pack_name_without_data(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  dns_name_t *name = dns_name_new();

  tt_int_op(dns_pack_name(buf, name), OP_EQ, 1);

 done:
  buf_free(buf);
  dns_name_free(name);
}

static void
test_dns_wireformat_pack_name_with_too_long_label(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  dns_name_t *name = dns_name_of("abcd0123456789012345678901234567890123456789"
                                 "01234567890123456789.example.com");
  tt_int_op(dns_pack_name(buf, name), OP_EQ, -1);

 done:
  buf_free(buf);
  dns_name_free(name);
}

static void
test_dns_wireformat_pack_name_root(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size;
  char *data = NULL;
  dns_name_t *name = dns_name_of(".");

  tt_int_op(dns_pack_name(buf, name), OP_EQ, 1);
  data = buf_extract(buf, &size);
  tt_uint_op(size, OP_EQ, 1);
  tt_str_op(data, OP_EQ, "\0");

 done:
  buf_free(buf);
  tor_free(data);
  dns_name_free(name);
}

static void
test_dns_wireformat_pack_and_consume_name(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size;
  char *data = NULL;

  dns_name_t *actual = dns_name_new();
  dns_name_t *expected = dns_name_of("www.example.com.");
  tt_int_op(dns_pack_name(buf, expected), OP_EQ, 17);

  data = buf_extract(buf, &size);
  tt_int_op(size, OP_EQ, 17);

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_name(actual, &ptr, (const uint8_t *) data, size),
            OP_EQ, 17);
  tt_uint_op(actual->length, OP_EQ, expected->length);
  tt_str_op(actual->value, OP_EQ, expected->value);

 done:
  buf_free(buf);
  tor_free(data);
  dns_name_free(actual);
  dns_name_free(expected);
}

static void
test_dns_wireformat_consume_name_using_compression(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size;
  char *data = NULL;

  dns_name_t *part1 = dns_name_of("www");
  dns_name_t *part2 = dns_name_of("example.com");
  dns_name_t *actual = dns_name_new();

  buf_add(buf, "abcdef", 5);
  tt_int_op(13, OP_EQ, dns_pack_name(buf, part2));

  tt_int_op(5, OP_EQ, dns_pack_name(buf, part1));
  data = buf_extract(buf, &size);
  buf_clear(buf);

  buf_add(buf, data, size - 1);
  tor_free(data);
  buf_add_printf(buf, "%c%c", 0xc0, 0x05);

  data = buf_extract(buf, &size);
  tt_int_op(size, OP_EQ, 24);

  uint8_t *ptr = (uint8_t *) &data[18];
  tt_int_op(dns_consume_name(actual, &ptr, (const uint8_t *) data, size),
            OP_EQ, 6);
  tt_uint_op(actual->length, OP_EQ, 16);
  tt_str_op(actual->value, OP_EQ, "www.example.com.");

 done:
  buf_free(buf);
  tor_free(data);
  dns_name_free(part1);
  dns_name_free(part2);
  dns_name_free(actual);
}

static void
test_dns_wireformat_consume_name_starting_with_null_byte(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size;
  char *data = NULL;

  dns_name_t *actual = dns_name_new();
  dns_name_t *expected = dns_name_new();
  expected->length = 14;
  expected->value = (char *) tor_memdup("\0.example.com.", 14);
  tt_int_op(dns_pack_name(buf, expected), OP_EQ, 15);

  data = buf_extract(buf, &size);
  tt_int_op(size, OP_EQ, 15);

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_name(actual, &ptr, (const uint8_t *) data, size),
            OP_EQ, 15);
  tt_uint_op(actual->length, OP_EQ, expected->length);
  tt_str_op(actual->value, OP_EQ, expected->value);

 done:
  buf_free(buf);
  tor_free(data);
  dns_name_free(actual);
  dns_name_free(expected);
}

static void
test_dns_wireformat_consume_name_without_data(void *arg)
{
  (void) arg;

  size_t size = 0;
  char data[1] = {
    0x01
  };

  dns_name_t *name = dns_name_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_consume_name(name, &ptr, (const uint8_t *) &data, size),
            OP_EQ, -2);

 done:
  dns_name_free(name);
}

static void
test_dns_wireformat_consume_name_with_missing_end(void *arg)
{
  (void) arg;

  size_t size = 2;
  char data[2] = {
    0x01, 'a'
  };

  dns_name_t *name = dns_name_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_name(name, &ptr, (const uint8_t *) &data, size),
            OP_EQ, -3);

 done:
  dns_name_free(name);
}

static void
test_dns_wireformat_consume_name_with_missing_compression_pointer(void *arg)
{
  (void) arg;

  size_t size = 9;
  char data[9] = {
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0xc0,
  };

  dns_name_t *name = dns_name_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_name(name, &ptr, (const uint8_t *) &data, size),
            OP_EQ, -4);

 done:
  dns_name_free(name);
}

static void
test_dns_wireformat_consume_name_with_invalid_compression_pointer(void *arg)
{
  (void) arg;

  size_t size = 2;
  char data[2] = {
    0xc0, 0x05
  };

  dns_name_t *name = dns_name_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_name(name, &ptr, (const uint8_t *) &data, size),
            OP_EQ, -5);

 done:
  dns_name_free(name);
}

static void
test_dns_wireformat_consume_name_with_invalid_compression_label(void *arg)
{
  (void) arg;

  size_t size = 3;
  char data[3] = {
    0x10, 0xc0, 0x00
  };

  dns_name_t *name = dns_name_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_consume_name(name, &ptr, (const uint8_t *) &data, size),
            OP_EQ, -6);

 done:
  dns_name_free(name);
}

static void
test_dns_wireformat_consume_name_with_compression_pointer_loop(void *arg)
{
  (void) arg;

  size_t size = 14;
  char data[14] = {
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0xc0, 0x0c
  };

  dns_name_t *name = dns_name_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_name(name, &ptr, (const uint8_t *) &data, size),
            OP_EQ, -6);

 done:
  dns_name_free(name);
}

static void
test_dns_wireformat_consume_name_with_invalid_label_length(void *arg)
{
  (void) arg;

  size_t size = 1;
  char data[1] = {
    0x01
  };

  dns_name_t *name = dns_name_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_name(name, &ptr, (const uint8_t *) &data, size),
            OP_EQ, -7);

 done:
  dns_name_free(name);
}

static void
test_dns_wireformat_pack_type_bitmaps_without_data(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  smartlist_t *types = smartlist_new();

  tt_int_op(dns_pack_type_bitmaps(buf, types), OP_EQ, 0);

 done:
  buf_free(buf);
  smartlist_free(types);
}

static void
test_dns_wireformat_pack_type_bitmaps_with_type65535(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  smartlist_t *types = smartlist_new();
  smartlist_add(types, dns_type_of(65535));

  tt_int_op(dns_pack_type_bitmaps(buf, types), OP_EQ, 36);

 done:
  buf_free(buf);
  SMARTLIST_FOREACH(types, dns_type_t *, dt, dns_type_free(dt));
  smartlist_free(types);
}

static void
test_dns_wireformat_pack_and_consume_type_bitmaps(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size;
  char *data = NULL;

  smartlist_t *actual = smartlist_new();
  smartlist_t *expected = smartlist_new();
  smartlist_add(expected, dns_type_of(DNS_TYPE_A));
  smartlist_add(expected, dns_type_of(DNS_TYPE_MX));
  smartlist_add(expected, dns_type_of(DNS_TYPE_RRSIG));
  smartlist_add(expected, dns_type_of(DNS_TYPE_NSEC));
  smartlist_add(expected, dns_type_of(1234));
  tt_int_op(dns_pack_type_bitmaps(buf, expected), OP_EQ, 37);

  data = buf_extract(buf, &size);
  tt_int_op(size, OP_EQ, 37);

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_type_bitmaps(actual, &ptr, (const uint8_t *) data,
                                     size), OP_EQ, 37);

  tt_int_op(smartlist_len(actual), OP_EQ, smartlist_len(expected));
  for (int i = 0; i < smartlist_len(expected); i++) {
    dns_type_t *expected_type = (dns_type_t *) smartlist_get(expected, i);
    dns_type_t *actual_type = (dns_type_t *) smartlist_get(actual, i);
    tt_uint_op(actual_type->value, OP_EQ, expected_type->value);
  }

 done:
  buf_free(buf);
  tor_free(data);
  SMARTLIST_FOREACH(expected, dns_type_t *, dt, dns_type_free(dt));
  smartlist_free(expected);
  SMARTLIST_FOREACH(actual, dns_type_t *, dt, dns_type_free(dt));
  smartlist_free(actual);
}

static void
test_dns_wireformat_consume_type_bitmaps_without_data(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 0;
  char data[1] = {
    0x01
  };

  smartlist_t *types = smartlist_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_consume_type_bitmaps(types, &ptr, (const uint8_t *) &data,
                                     size), OP_EQ, -1);

 done:
  buf_free(buf);
  smartlist_free(types);
}

static void
test_dns_wireformat_consume_type_bitmaps_with_missing_length(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 1;
  char data[1] = {
    0x01
  };

  smartlist_t *types = smartlist_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_type_bitmaps(types, &ptr, (const uint8_t *) &data,
                                     size), OP_EQ, -2);

 done:
  buf_free(buf);
  smartlist_free(types);
}

static void
test_dns_wireformat_consume_type_bitmaps_with_truncated_bitmap(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 3;
  char data[3] = {
    0x00, 0x02, 0x00
  };

  smartlist_t *types = smartlist_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_type_bitmaps(types, &ptr, (const uint8_t *) &data,
                                     size), OP_EQ, -3);

 done:
  buf_free(buf);
  smartlist_free(types);
}

static void
test_dns_wireformat_consume_type_bitmaps_with_excessive_bitmap(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 5;
  char data[5] = {
    0x00, 0x02, 0x00, 0x00, 0x00
  };

  smartlist_t *types = smartlist_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_type_bitmaps(types, &ptr, (const uint8_t *) &data,
                                     size), OP_EQ, -2);

 done:
  buf_free(buf);
  smartlist_free(types);
}

//
// Header

static void
test_dns_wireformat_pack_and_consume_header(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size;
  char *data = NULL;

  dns_header_t *actual = dns_header_new();
  dns_header_t *expected = dns_header_new();
  expected->id = 0x1234;
  expected->qr = true;
  expected->opcode = 1;
  expected->tc = true;
  expected->rd = true;
  expected->ra = true;
  expected->z = true;
  expected->ad = true;
  expected->cd = true;
  expected->rcode = 1;
  expected->qdcount = 1;
  expected->ancount = 1;
  expected->nscount = 1;
  expected->arcount = 1;
  tt_int_op(dns_pack_header(buf, expected), OP_EQ, 12);

  data = buf_extract(buf, &size);
  tt_int_op(size, OP_EQ, 12);

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_header(actual, &ptr, (const uint8_t *) data, size),
            OP_EQ, 12);
  tt_uint_op(actual->id, OP_EQ, expected->id);
  tt_uint_op(actual->qr, OP_EQ, expected->qr);
  tt_uint_op(actual->opcode, OP_EQ, expected->opcode);
  tt_uint_op(actual->tc, OP_EQ, expected->tc);
  tt_uint_op(actual->rd, OP_EQ, expected->rd);
  tt_uint_op(actual->ra, OP_EQ, expected->ra);
  tt_uint_op(actual->z, OP_EQ, expected->z);
  tt_uint_op(actual->ad, OP_EQ, expected->ad);
  tt_uint_op(actual->cd, OP_EQ, expected->cd);
  tt_uint_op(actual->rcode, OP_EQ, expected->rcode);
  tt_uint_op(actual->qdcount, OP_EQ, expected->qdcount);
  tt_uint_op(actual->ancount, OP_EQ, expected->ancount);
  tt_uint_op(actual->nscount, OP_EQ, expected->nscount);
  tt_uint_op(actual->arcount, OP_EQ, expected->arcount);

 done:
  buf_free(buf);
  tor_free(data);
  dns_header_free(actual);
  dns_header_free(expected);
}

static void
test_dns_wireformat_consume_header_with_missing_data(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 0;
  char data[1] = {
    0x01
  };

  dns_header_t *header = dns_header_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_consume_header(header, &ptr, (const uint8_t *) &data, size),
            OP_EQ, -1);

 done:
  buf_free(buf);
  dns_header_free(header);
}

static void
test_dns_wireformat_consume_header_with_invalid_data(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 3;
  char data[3] = {
    0x01, 0x02, 0x03
  };

  dns_header_t *header = dns_header_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_header(header, &ptr, (const uint8_t *) data, size),
            OP_EQ, -2);

 done:
  buf_free(buf);
  dns_header_free(header);
}

//
// Question

static void
test_dns_wireformat_pack_question_with_missing_type(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  dns_question_t *question = dns_question_new();

  tt_int_op(dns_pack_question(buf, question), OP_EQ, -1);

 done:
  buf_free(buf);
  dns_question_free(question);
}

static void
test_dns_wireformat_pack_question_with_invalid_qname(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  dns_question_t *question = dns_question_new();

  question->qname = dns_name_of("abcd01234567890123456789012345678901234567890"
                                "1234567890123456789.example.com");
  question->qtype = dns_type_of(DNS_TYPE_A);
  tt_int_op(dns_pack_question(buf, question), OP_EQ, -2);

 done:
  buf_free(buf);
  dns_question_free(question);
}

static void
test_dns_wireformat_pack_and_consume_question(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size;
  char *data = NULL;

  dns_question_t *actual = dns_question_new();
  dns_question_t *expected = dns_question_new();
  expected->qname = dns_name_of("hello.");
  expected->qtype = dns_type_of(DNS_TYPE_SINK);
  expected->qclass = DNS_CLASS_CHAOS;
  tt_int_op(dns_pack_question(buf, expected), OP_EQ, 11);

  data = buf_extract(buf, &size);
  tt_int_op(size, OP_EQ, 11);

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_question(actual, &ptr, (const uint8_t *) data, size),
            OP_EQ, 11);
  tt_str_op(dns_name_str(actual->qname), OP_EQ, dns_name_str(expected->qname));
  tt_uint_op(actual->qtype->value, OP_EQ, expected->qtype->value);
  tt_uint_op(actual->qclass, OP_EQ, expected->qclass);

 done:
  buf_free(buf);
  tor_free(data);
  dns_question_free(actual);
  dns_question_free(expected);
}

static void
test_dns_wireformat_consume_question_with_missing_data(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 0;
  char data[1] = {
    0x01
  };

  dns_question_t *question = dns_question_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_consume_question(question, &ptr, (const uint8_t *) &data,
                                 size), OP_EQ, -1);

 done:
  buf_free(buf);
  dns_question_free(question);
}

static void
test_dns_wireformat_consume_question_with_invalid_qname(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 1;
  char data[1] = {
    0x01
  };

  dns_question_t *question = dns_question_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_question(question, &ptr, (const uint8_t *) &data,
                                 size), OP_EQ, -2);

 done:
  buf_free(buf);
  dns_question_free(question);
}

static void
test_dns_wireformat_consume_question_with_invalid_data(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 2;
  char data[2] = {
    0x00, 0x02
  };

  dns_question_t *question = dns_question_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_question(question, &ptr, (const uint8_t *) &data,
                                 size), OP_EQ, -3);

 done:
  buf_free(buf);
  dns_question_free(question);
}

//
// Resource Record - A

static void
test_dns_wireformat_encode_a_with_missing_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  tt_int_op(dns_encode_a(rr), OP_EQ, -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_a_with_invalid_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  rr->a = tor_strdup("w.x.y.z");
  tt_int_op(dns_encode_a(rr), OP_EQ, -2);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_and_decode_a(void *arg)
{
  (void) arg;

  dns_rr_t *expected = dns_rr_new();
  dns_rr_t *actual = dns_rr_new();

  expected->a = tor_strdup("1.2.3.4");
  tt_int_op(dns_encode_a(expected), OP_EQ, 0);

  uint8_t *ptr = (uint8_t *) expected->rdata;
  tt_int_op(dns_decode_a(actual, ptr, (const uint8_t *) expected->rdata,
                         expected->rdlength), OP_EQ, 0);
  tt_str_op(actual->a, OP_EQ, expected->a);

 done:
  dns_rr_free(expected);
  dns_rr_free(actual);
}

static void
test_dns_wireformat_decode_a_with_missing_rdata(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 0;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_decode_a(rr, ptr, (const uint8_t *) &data, size), OP_EQ, -1);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_a_with_invalid_rdata(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 3;
  char data[3] = {
    0x01, 0x02, 0x03
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_a(rr, ptr, (const uint8_t *) data, size), OP_EQ, -2);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

//
// Resource Record - NS

static void
test_dns_wireformat_encode_ns_with_missing_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  tt_int_op(dns_encode_ns(rr), OP_EQ, -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_ns_with_invalid_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  rr->ns = dns_name_of("abcd01234567890123456789012345678901234567890123456789"
                       "0123456789.example.com");
  tt_int_op(dns_encode_ns(rr), OP_EQ, -2);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_and_decode_ns(void *arg)
{
  (void) arg;

  dns_rr_t *expected = dns_rr_new();
  dns_rr_t *actual = dns_rr_new();

  expected->ns = dns_name_of("hello.");
  tt_int_op(dns_encode_ns(expected), OP_EQ, 0);

  uint8_t *ptr = (uint8_t *) expected->rdata;
  tt_int_op(dns_decode_ns(actual, ptr, (const uint8_t *) expected->rdata,
                          expected->rdlength), OP_EQ, 0);
  tt_str_op(dns_name_str(actual->ns), OP_EQ, dns_name_str(expected->ns));

 done:
  dns_rr_free(expected);
  dns_rr_free(actual);
}

static void
test_dns_wireformat_decode_ns_with_missing_rdata(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 0;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_decode_ns(rr, ptr, (const uint8_t *) &data, size), OP_EQ, -1);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_ns_with_invalid_rdata(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 1;
  char data[1] = { 0x01};

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_ns(rr, ptr, (const uint8_t *) data, size), OP_EQ, -2);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

//
// Resource Record - CNAME

static void
test_dns_wireformat_encode_cname_with_missing_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  tt_int_op(dns_encode_cname(rr), OP_EQ, -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_cname_with_invalid_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  rr->cname = dns_name_of("abcd01234567890123456789012345678901234567890123456"
                          "7890123456789.example.com");
  tt_int_op(dns_encode_cname(rr), OP_EQ, -2);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_and_decode_cname(void *arg)
{
  (void) arg;

  dns_rr_t *expected = dns_rr_new();
  dns_rr_t *actual = dns_rr_new();

  expected->cname = dns_name_of("hello.");
  tt_int_op(dns_encode_cname(expected), OP_EQ, 0);

  uint8_t *ptr = (uint8_t *) expected->rdata;
  tt_int_op(dns_decode_cname(actual, ptr, (const uint8_t *) expected->rdata,
                             expected->rdlength), OP_EQ, 0);
  tt_str_op(dns_name_str(actual->cname), OP_EQ, dns_name_str(expected->cname));

 done:
  dns_rr_free(expected);
  dns_rr_free(actual);
}

static void
test_dns_wireformat_decode_cname_with_missing_rdata(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 0;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_decode_cname(rr, ptr, (const uint8_t *) &data, size), OP_EQ,
            -1);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_cname_with_invalid_rdata(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 1;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_cname(rr, ptr, (const uint8_t *) data, size), OP_EQ,
            -2);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

//
// Resource Record - SOA

static void
test_dns_wireformat_encode_soa_with_missing_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  tt_int_op(dns_encode_soa(rr), OP_EQ, -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_soa_with_invalid_mname(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();
  rr->soa = dns_soa_new();
  rr->soa->mname = dns_name_of("abcd012345678901234567890123456789012345678901"
                               "234567890123456789.example.com");
  tt_int_op(dns_encode_soa(rr), OP_EQ, -2);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_soa_with_invalid_rname(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();
  rr->soa = dns_soa_new();
  rr->soa->mname = dns_name_of("hello.");
  rr->soa->rname = dns_name_of("abcd012345678901234567890123456789012345678901"
                               "234567890123456789.example.com");
  tt_int_op(dns_encode_soa(rr), OP_EQ, -3);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_and_decode_soa(void *arg)
{
  (void) arg;

  dns_rr_t *expected = dns_rr_new();
  dns_rr_t *actual = dns_rr_new();

  expected->soa = dns_soa_new();
  expected->soa->mname = dns_name_of("hello.");
  expected->soa->rname = dns_name_of("world.");
  expected->soa->serial = 0x1ffff;
  expected->soa->refresh = 0x2ffff;
  expected->soa->retry = 0x3ffff;
  expected->soa->expire = 0x4ffff;
  expected->soa->minimum = 0x5ffff;
  tt_int_op(dns_encode_soa(expected), OP_EQ, 0);

  uint8_t *ptr = (uint8_t *) expected->rdata;
  tt_int_op(dns_decode_soa(actual, ptr, (const uint8_t *) expected->rdata,
                           expected->rdlength), OP_EQ, 0);
  tt_str_op(dns_name_str(actual->soa->mname), OP_EQ,
            dns_name_str(expected->soa->mname));
  tt_str_op(dns_name_str(actual->soa->rname), OP_EQ,
            dns_name_str(expected->soa->rname));
  tt_int_op(actual->soa->serial, OP_EQ, expected->soa->serial);
  tt_int_op(actual->soa->refresh, OP_EQ, expected->soa->refresh);
  tt_int_op(actual->soa->retry, OP_EQ, expected->soa->retry);
  tt_int_op(actual->soa->expire, OP_EQ, expected->soa->expire);
  tt_int_op(actual->soa->minimum, OP_EQ, expected->soa->minimum);

 done:
  dns_rr_free(expected);
  dns_rr_free(actual);
}

static void
test_dns_wireformat_decode_soa_with_missing_rdata(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 0;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_decode_soa(rr, ptr, (const uint8_t *) &data, size), OP_EQ, -1);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_soa_with_invalid_mname(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 1;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_soa(rr, ptr, (const uint8_t *) data, size), OP_EQ, -2);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_soa_with_invalid_rname(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 2;
  char data[2] = {
    0x00, 0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_soa(rr, ptr, (const uint8_t *) data, size), OP_EQ, -3);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_soa_with_invalid_rdata(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 3;
  char data[3] = {
    0x00, 0x00, 0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_soa(rr, ptr, (const uint8_t *) data, size), OP_EQ, -4);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

//
// Resource Record - PTR

static void
test_dns_wireformat_encode_ptr_with_missing_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  tt_int_op(dns_encode_ptr(rr), OP_EQ, -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_ptr_with_invalid_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  rr->ptr = dns_name_of("abcd0123456789012345678901234567890123456789012345678"
                        "90123456789.example.com");
  tt_int_op(dns_encode_ptr(rr), OP_EQ, -2);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_and_decode_ptr(void *arg)
{
  (void) arg;

  dns_rr_t *expected = dns_rr_new();
  dns_rr_t *actual = dns_rr_new();

  expected->ptr = dns_name_of("hello.");
  tt_int_op(dns_encode_ptr(expected), OP_EQ, 0);

  uint8_t *ptr = (uint8_t *) expected->rdata;
  tt_int_op(dns_decode_ptr(actual, ptr, (const uint8_t *) expected->rdata,
                           expected->rdlength), OP_EQ, 0);
  tt_str_op(dns_name_str(actual->ptr), OP_EQ, dns_name_str(expected->ptr));

 done:
  dns_rr_free(expected);
  dns_rr_free(actual);
}

static void
test_dns_wireformat_decode_ptr_with_missing_rdata(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 0;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_decode_ptr(rr, ptr, (const uint8_t *) &data, size), OP_EQ, -1);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_ptr_with_invalid_rdata(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 1;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_ptr(rr, ptr, (const uint8_t *) data, size), OP_EQ, -2);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

//
// Resource Record - MX

static void
test_dns_wireformat_encode_mx_with_missing_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  tt_int_op(dns_encode_mx(rr), OP_EQ, -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_mx_with_invalid_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  rr->mx = dns_mx_new();
  rr->mx->preference = 1234;
  rr->mx->exchange = dns_name_of("abcd0123456789012345678901234567890123456789"
                                 "01234567890123456789.example.com");
  tt_int_op(dns_encode_mx(rr), OP_EQ, -2);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_and_decode_mx(void *arg)
{
  (void) arg;

  dns_rr_t *expected = dns_rr_new();
  dns_rr_t *actual = dns_rr_new();

  expected->mx = dns_mx_new();
  expected->mx->preference = 1234;
  expected->mx->exchange = dns_name_of("mail.example.com.");
  tt_int_op(dns_encode_mx(expected), OP_EQ, 0);

  uint8_t *ptr = (uint8_t *) expected->rdata;
  tt_int_op(dns_decode_mx(actual, ptr, (const uint8_t *) expected->rdata,
                          expected->rdlength), OP_EQ, 0);
  tt_int_op(actual->mx->preference, OP_EQ, expected->mx->preference);
  tt_str_op(dns_name_str(actual->mx->exchange), OP_EQ,
            dns_name_str(expected->mx->exchange));

 done:
  dns_rr_free(expected);
  dns_rr_free(actual);
}

static void
test_dns_wireformat_decode_mx_with_missing_rdata(void *arg)
{
  (void) arg;

  size_t size = 0;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_decode_mx(rr, ptr, (const uint8_t *) &data, size), OP_EQ, -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_mx_with_invalid_rdata(void *arg)
{
  (void) arg;

  size_t size = 1;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_mx(rr, ptr, (const uint8_t *) data, size), OP_EQ, -2);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_mx_with_empty_exchange(void *arg)
{
  (void) arg;

  size_t size = 2;
  char data[2] = {
    0x01, 0x02
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_mx(rr, ptr, (const uint8_t *) data, size), OP_EQ, -3);

 done:
  dns_rr_free(rr);
}

//
// Resource Record - KEY

static void
test_dns_wireformat_encode_key_with_missing_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  tt_int_op(dns_encode_key(rr), OP_EQ, -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_and_decode_key(void *arg)
{
  (void) arg;

  dns_rr_t *expected = dns_rr_new();
  dns_rr_t *actual = dns_rr_new();

  uint8_t public_key[2] = {
    0x01, 0x02
  };

  expected->key = dns_key_new();
  expected->key->flags = 1234;
  expected->key->protocol = 1;
  expected->key->algorithm = 8;
  expected->key->public_key = tor_memdup(public_key, 2);
  expected->key->public_key_len = 2;
  tt_int_op(dns_encode_key(expected), OP_EQ, 0);

  uint8_t *ptr = (uint8_t *) expected->rdata;
  tt_int_op(dns_decode_key(actual, ptr, (const uint8_t *) expected->rdata,
                           expected->rdlength), OP_EQ, 0);
  tt_uint_op(actual->key->flags, OP_EQ, expected->key->flags);
  tt_uint_op(actual->key->protocol, OP_EQ, expected->key->protocol);
  tt_uint_op(actual->key->algorithm, OP_EQ, expected->key->algorithm);
  tt_mem_op(actual->key->public_key, OP_EQ, expected->key->public_key,
            expected->key->public_key_len);

 done:
  dns_rr_free(expected);
  dns_rr_free(actual);
}

static void
test_dns_wireformat_decode_key_with_missing_rdata(void *arg)
{
  (void) arg;

  size_t size = 0;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_decode_key(rr, ptr, (const uint8_t *) &data, size), OP_EQ, -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_key_with_invalid_rdata(void *arg)
{
  (void) arg;

  size_t size = 3;
  char data[3] = {
    0x01, 0x02, 0x03
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_key(rr, ptr, (const uint8_t *) data, size), OP_EQ, -2);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_key_with_empty_public_key(void *arg)
{
  (void) arg;

  size_t size = 4;
  char data[4] = {
    0x01, 0x02, 0x03, 0x04
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_key(rr, ptr, (const uint8_t *) data, size), OP_EQ, 0);

 done:
  dns_rr_free(rr);
}

//
// Resource Record - AAAA

static void
test_dns_wireformat_encode_aaaa_with_missing_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  tt_int_op(dns_encode_aaaa(rr), OP_EQ, -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_aaaa_with_invalid_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  rr->aaaa = tor_strdup("u:v:w:x:y:z");
  tt_int_op(dns_encode_aaaa(rr), OP_EQ, -2);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_and_decode_aaaa(void *arg)
{
  (void) arg;

  dns_rr_t *expected = dns_rr_new();
  dns_rr_t *actual = dns_rr_new();

  expected->aaaa = tor_strdup("2::3:0:0:4");
  tt_int_op(dns_encode_aaaa(expected), OP_EQ, 0);

  uint8_t *ptr = (uint8_t *) expected->rdata;
  tt_int_op(dns_decode_aaaa(actual, ptr, (const uint8_t *) expected->rdata,
                            expected->rdlength), OP_EQ, 0);
  tt_str_op(actual->aaaa, OP_EQ, expected->aaaa);

 done:
  dns_rr_free(expected);
  dns_rr_free(actual);
}

static void
test_dns_wireformat_decode_aaaa_with_missing_rdata(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 0;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_decode_aaaa(rr, ptr, (const uint8_t *) &data, size), OP_EQ,
            -1);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_aaaa_with_invalid_rdata(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 7;
  char data[7] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_aaaa(rr, ptr, (const uint8_t *) data, size), OP_EQ, -2);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

//
// Resource Record - DS

static void
test_dns_wireformat_encode_ds_with_missing_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  tt_int_op(dns_encode_ds(rr), OP_EQ, -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_and_decode_ds(void *arg)
{
  (void) arg;

  dns_rr_t *expected = dns_rr_new();
  dns_rr_t *actual = dns_rr_new();

  uint8_t digest[2] = {
    0x01, 0x02
  };

  expected->ds = dns_ds_new();
  expected->ds->key_tag = 1234;
  expected->ds->algorithm = 8;
  expected->ds->digest_type = 1;
  expected->ds->digest = tor_memdup(digest, 2);
  expected->ds->digest_len = 2;
  tt_int_op(dns_encode_ds(expected), OP_EQ, 0);

  uint8_t *ptr = (uint8_t *) expected->rdata;
  tt_int_op(dns_decode_ds(actual, ptr, (const uint8_t *) expected->rdata,
                          expected->rdlength), OP_EQ, 0);
  tt_uint_op(actual->ds->key_tag, OP_EQ, expected->ds->key_tag);
  tt_uint_op(actual->ds->algorithm, OP_EQ, expected->ds->algorithm);
  tt_uint_op(actual->ds->digest_type, OP_EQ, expected->ds->digest_type);
  tt_mem_op(actual->ds->digest, OP_EQ, expected->ds->digest,
            expected->ds->digest_len);

 done:
  dns_rr_free(expected);
  dns_rr_free(actual);
}

static void
test_dns_wireformat_decode_ds_with_missing_rdata(void *arg)
{
  (void) arg;

  size_t size = 0;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_decode_ds(rr, ptr, (const uint8_t *) &data, size), OP_EQ, -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_ds_with_invalid_rdata(void *arg)
{
  (void) arg;

  size_t size = 3;
  char data[3] = {
    0x01, 0x02, 0x03
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_ds(rr, ptr, (const uint8_t *) data, size), OP_EQ, -2);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_ds_with_empty_digest(void *arg)
{
  (void) arg;

  size_t size = 4;
  char data[4] = {
    0x01, 0x02, 0x03, 0x04
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_ds(rr, ptr, (const uint8_t *) data, size), OP_EQ, 0);

 done:
  dns_rr_free(rr);
}

//
// Resource Record - RRSIG

static void
test_dns_wireformat_encode_rrsig_with_missing_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  tt_int_op(dns_encode_rrsig(rr), OP_EQ, -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_rrsig_with_invalid_signer_name(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();
  rr->rrsig = dns_rrsig_new();
  rr->rrsig->type_covered = dns_type_of(DNS_TYPE_SINK);
  rr->rrsig->signer_name = dns_name_of("abcd0123456789012345678901234567890123"
                                       "45678901234567890123456789.example.com"
                                      );

  tt_int_op(dns_encode_rrsig(rr), OP_EQ, -2);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_and_decode_rrsig(void *arg)
{
  (void) arg;

  dns_rr_t *expected = dns_rr_new();
  dns_rr_t *actual = dns_rr_new();

  uint8_t signature[2] = {0x01, 0x02};
  expected->rrsig = dns_rrsig_new();
  expected->rrsig->type_covered = dns_type_of(DNS_TYPE_SINK);
  expected->rrsig->algorithm = 8;
  expected->rrsig->labels = 1;
  expected->rrsig->original_ttl = 1;
  expected->rrsig->signature_expiration = 1;
  expected->rrsig->signature_inception = 1;
  expected->rrsig->key_tag = 1;
  expected->rrsig->signer_name = dns_name_of("hello.");
  expected->rrsig->signature = tor_memdup(signature, 2);
  expected->rrsig->signature_len = 2;
  tt_int_op(dns_encode_rrsig(expected), OP_EQ, 0);

  uint8_t *ptr = (uint8_t *) expected->rdata;
  tt_int_op(dns_decode_rrsig(actual, ptr, (const uint8_t *) expected->rdata,
                             expected->rdlength), OP_EQ, 0);
  tt_uint_op(actual->rrsig->type_covered->value, OP_EQ,
             expected->rrsig->type_covered->value);
  tt_uint_op(actual->rrsig->algorithm, OP_EQ, expected->rrsig->algorithm);
  tt_uint_op(actual->rrsig->labels, OP_EQ, expected->rrsig->labels);
  tt_uint_op(actual->rrsig->original_ttl, OP_EQ,
             expected->rrsig->original_ttl);
  tt_uint_op(actual->rrsig->signature_expiration, OP_EQ,
             expected->rrsig->signature_expiration);
  tt_uint_op(actual->rrsig->signature_inception, OP_EQ,
             expected->rrsig->signature_inception);
  tt_uint_op(actual->rrsig->key_tag, OP_EQ, expected->rrsig->key_tag);
  tt_str_op(dns_name_str(actual->rrsig->signer_name), OP_EQ,
            dns_name_str(expected->rrsig->signer_name));
  tt_mem_op(actual->rrsig->signature, OP_EQ, expected->rrsig->signature,
            expected->rrsig->signature_len);

 done:
  dns_rr_free(expected);
  dns_rr_free(actual);
}

static void
test_dns_wireformat_decode_rrsig_with_missing_rdata(void *arg)
{
  (void) arg;

  size_t size = 0;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_decode_rrsig(rr, ptr, (const uint8_t *) &data, size), OP_EQ,
            -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_rrsig_with_invalid_rdata(void *arg)
{
  (void) arg;

  size_t size = 3;
  char data[3] = {
    0x01, 0x02, 0x03
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_rrsig(rr, ptr, (const uint8_t *) data, size), OP_EQ,
            -2);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_rrsig_with_invalid_signer_name(void *arg)
{
  (void) arg;

  size_t size = 19;
  char data[19] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_rrsig(rr, ptr, (const uint8_t *) data, size), OP_EQ,
            -3);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_rrsig_with_empty_signature(void *arg)
{
  (void) arg;

  size_t size = 19;
  char data[19] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x00
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_rrsig(rr, ptr, (const uint8_t *) data, size), OP_EQ, 0);

 done:
  dns_rr_free(rr);
}

//
// Resource Record - NSEC

static void
test_dns_wireformat_encode_nsec_with_missing_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  tt_int_op(dns_encode_nsec(rr), OP_EQ, -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_nsec_with_invalid_next_domain_name(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();
  rr->nsec = dns_nsec_new();
  rr->nsec->next_domain_name = dns_name_of("abcd012345678901234567890123456789"
                                           "012345678901234567890123456789.exa"
                                           "mple.com");

  tt_int_op(dns_encode_nsec(rr), OP_EQ, -2);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_and_decode_nsec(void *arg)
{
  (void) arg;

  dns_rr_t *expected = dns_rr_new();
  dns_rr_t *actual = dns_rr_new();

  expected->nsec = dns_nsec_new();
  expected->nsec->next_domain_name = dns_name_of("hello.");
  smartlist_add(expected->nsec->types, dns_type_of(DNS_TYPE_A));
  tt_int_op(dns_encode_nsec(expected), OP_EQ, 0);

  uint8_t *ptr = (uint8_t *) expected->rdata;
  tt_int_op(dns_decode_nsec(actual, ptr, (const uint8_t *) expected->rdata,
                            expected->rdlength), OP_EQ, 0);
  tt_str_op(dns_name_str(actual->nsec->next_domain_name), OP_EQ,
            dns_name_str(expected->nsec->next_domain_name));
  tt_int_op(smartlist_len(actual->nsec->types), OP_EQ,
            smartlist_len(expected->nsec->types));

 done:
  dns_rr_free(expected);
  dns_rr_free(actual);
}

static void
test_dns_wireformat_decode_nsec_with_missing_rdata(void *arg)
{
  (void) arg;

  size_t size = 0;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_decode_nsec(rr, ptr, (const uint8_t *) &data, size), OP_EQ,
            -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_nsec_with_invalid_next_domain_name(void *arg)
{
  (void) arg;

  size_t size = 1;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_nsec(rr, ptr, (const uint8_t *) &data, size), OP_EQ,
            -2);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_nsec_with_invalid_type_bitmaps(void *arg)
{
  (void) arg;

  size_t size = 2;
  char data[2] = {
    0x00, 0x00
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_nsec(rr, ptr, (const uint8_t *) &data, size), OP_EQ,
            -3);

 done:
  dns_rr_free(rr);
}

//
// Resource Record - DNSKEY

static void
test_dns_wireformat_encode_dnskey_with_missing_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  tt_int_op(dns_encode_dnskey(rr), OP_EQ, -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_and_decode_dnskey(void *arg)
{
  (void) arg;

  dns_rr_t *expected = dns_rr_new();
  dns_rr_t *actual = dns_rr_new();

  uint8_t public_key[2] = {
    0x01, 0x02
  };

  expected->dnskey = dns_dnskey_new();
  expected->dnskey->flags = 1234;
  expected->dnskey->protocol = 1;
  expected->dnskey->algorithm = 8;
  expected->dnskey->public_key = tor_memdup(public_key, 2);
  expected->dnskey->public_key_len = 2;
  tt_int_op(dns_encode_dnskey(expected), OP_EQ, 0);

  uint8_t *ptr = (uint8_t *) expected->rdata;
  tt_int_op(dns_decode_dnskey(actual, ptr, (const uint8_t *) expected->rdata,
                              expected->rdlength), OP_EQ, 0);
  tt_uint_op(actual->dnskey->flags, OP_EQ, expected->dnskey->flags);
  tt_uint_op(actual->dnskey->protocol, OP_EQ, expected->dnskey->protocol);
  tt_uint_op(actual->dnskey->algorithm, OP_EQ, expected->dnskey->algorithm);
  tt_mem_op(actual->dnskey->public_key, OP_EQ, expected->dnskey->public_key,
            expected->dnskey->public_key_len);

 done:
  dns_rr_free(expected);
  dns_rr_free(actual);
}

static void
test_dns_wireformat_decode_dnskey_with_missing_rdata(void *arg)
{
  (void) arg;

  size_t size = 0;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_decode_dnskey(rr, ptr, (const uint8_t *) &data, size), OP_EQ,
            -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_dnskey_with_invalid_rdata(void *arg)
{
  (void) arg;

  size_t size = 3;
  char data[3] = {
    0x01, 0x02, 0x03
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_dnskey(rr, ptr, (const uint8_t *) data, size), OP_EQ,
            -2);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_dnskey_with_empty_public_key(void *arg)
{
  (void) arg;

  size_t size = 4;
  char data[4] = {
    0x01, 0x02, 0x03, 0x04
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_dnskey(rr, ptr, (const uint8_t *) data, size), OP_EQ,
            0);

 done:
  dns_rr_free(rr);
}

//
// Resource Record - NSEC3

static void
test_dns_wireformat_encode_nsec3_with_missing_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  tt_int_op(dns_encode_nsec3(rr), OP_EQ, -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_and_decode_nsec3(void *arg)
{
  (void) arg;

  dns_rr_t *expected = dns_rr_new();
  dns_rr_t *actual = dns_rr_new();

  uint8_t salt_length = 2;
  uint8_t salt[] = {0xca, 0xfe};

  uint8_t hash_length = 2;
  uint8_t next_hashed_owner_name[] = {0xab, 0xcd};

  expected->nsec3 = dns_nsec3_new();
  expected->nsec3->hash_algorithm = 1;
  expected->nsec3->flags = 0;
  expected->nsec3->iterations = 8;
  expected->nsec3->salt_length = salt_length;
  expected->nsec3->salt = tor_memdup(salt, salt_length);
  expected->nsec3->hash_length = hash_length;
  expected->nsec3->next_hashed_owner_name =
    tor_memdup(next_hashed_owner_name, hash_length);
  smartlist_add(expected->nsec3->types, dns_type_of(DNS_TYPE_A));
  tt_int_op(dns_encode_nsec3(expected), OP_EQ, 0);

  uint8_t *ptr = (uint8_t *) expected->rdata;
  tt_int_op(dns_decode_nsec3(actual, ptr, (const uint8_t *) expected->rdata,
                             expected->rdlength), OP_EQ, 0);
  tt_int_op(actual->nsec3->hash_algorithm, OP_EQ,
            expected->nsec3->hash_algorithm);
  tt_int_op(actual->nsec3->flags, OP_EQ, expected->nsec3->flags);
  tt_int_op(actual->nsec3->iterations, OP_EQ, expected->nsec3->iterations);
  tt_int_op(actual->nsec3->salt_length, OP_EQ, expected->nsec3->salt_length);
  tt_mem_op(actual->nsec3->salt, OP_EQ,
            expected->nsec3->salt, expected->nsec3->salt_length);
  tt_int_op(actual->nsec3->hash_length, OP_EQ, expected->nsec3->hash_length);
  tt_mem_op(actual->nsec3->next_hashed_owner_name, OP_EQ,
            expected->nsec3->next_hashed_owner_name,
            expected->nsec3->hash_length);
  tt_int_op(smartlist_len(actual->nsec3->types), OP_EQ,
            smartlist_len(expected->nsec3->types));

 done:
  dns_rr_free(expected);
  dns_rr_free(actual);
}

static void
test_dns_wireformat_decode_nsec3_with_missing_rdata(void *arg)
{
  (void) arg;

  size_t size = 0;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_decode_nsec3(rr, ptr, (const uint8_t *) &data, size), OP_EQ,
            -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_nsec3_with_invalid_rdata(void *arg)
{
  (void) arg;

  size_t size = 3;
  char data[3] = {
    0x01, 0x02, 0x03
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_nsec3(rr, ptr, (const uint8_t *) data, size), OP_EQ,
            -2);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_nsec3_with_missing_salt(void *arg)
{
  (void) arg;

  size_t size = 4;
  char data[4] = {
    0x01, 0x02, 0x03, 0x04
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_nsec3(rr, ptr, (const uint8_t *) data, size), OP_EQ,
            -3);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_nsec3_with_invalid_salt(void *arg)
{
  (void) arg;

  size_t size = 5;
  char data[5] = {
    0x01, 0x02, 0x03, 0x04, 0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_nsec3(rr, ptr, (const uint8_t *) data, size), OP_EQ,
            -4);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_nsec3_with_empty_hash(void *arg)
{
  (void) arg;

  size_t size = 5;
  char data[5] = {
    0x01, 0x02, 0x03, 0x04, 0x00
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_nsec3(rr, ptr, (const uint8_t *) data, size), OP_EQ,
            -5);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_nsec3_with_invalid_hash(void *arg)
{
  (void) arg;

  size_t size = 6;
  char data[6] = {
    0x01, 0x02, 0x03, 0x04, 0x00, 0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_nsec3(rr, ptr, (const uint8_t *) data, size), OP_EQ,
            -6);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_nsec3_with_invalid_type_bitmaps(void *arg)
{
  (void) arg;

  size_t size = 7;
  char data[7] = {
    0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_nsec3(rr, ptr, (const uint8_t *) &data, size), OP_EQ,
            -7);

 done:
  dns_rr_free(rr);
}

//
// Resource Record - NSEC3PARAM

static void
test_dns_wireformat_encode_nsec3param_with_missing_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  tt_int_op(dns_encode_nsec3param(rr), OP_EQ, -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_and_decode_nsec3param(void *arg)
{
  (void) arg;

  dns_rr_t *expected = dns_rr_new();
  dns_rr_t *actual = dns_rr_new();

  uint8_t salt_length = 2;
  uint8_t salt[] = {0xca, 0xfe};

  expected->nsec3param = dns_nsec3param_new();
  expected->nsec3param->hash_algorithm = 1;
  expected->nsec3param->flags = 0;
  expected->nsec3param->iterations = 8;
  expected->nsec3param->salt_length = salt_length;
  expected->nsec3param->salt = tor_memdup(salt, salt_length);
  tt_int_op(dns_encode_nsec3param(expected), OP_EQ, 0);

  uint8_t *ptr = (uint8_t *) expected->rdata;
  tt_int_op(dns_decode_nsec3param(actual, ptr,
                                  (const uint8_t *) expected->rdata,
                                  expected->rdlength), OP_EQ, 0);
  tt_int_op(actual->nsec3param->hash_algorithm, OP_EQ,
            expected->nsec3param->hash_algorithm);
  tt_int_op(actual->nsec3param->flags, OP_EQ, expected->nsec3param->flags);
  tt_int_op(actual->nsec3param->iterations, OP_EQ,
            expected->nsec3param->iterations);
  tt_int_op(actual->nsec3param->salt_length, OP_EQ,
            expected->nsec3param->salt_length);
  tt_mem_op(actual->nsec3param->salt, OP_EQ, expected->nsec3param->salt,
            expected->nsec3param->salt_length);

 done:
  dns_rr_free(expected);
  dns_rr_free(actual);
}

static void
test_dns_wireformat_decode_nsec3param_with_missing_rdata(void *arg)
{
  (void) arg;

  size_t size = 0;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_decode_nsec3param(rr, ptr, (const uint8_t *) &data, size),
            OP_EQ, -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_nsec3param_with_invalid_rdata(void *arg)
{
  (void) arg;

  size_t size = 3;
  char data[3] = {
    0x01, 0x02, 0x03
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_nsec3param(rr, ptr, (const uint8_t *) data, size),
            OP_EQ, -2);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_nsec3param_with_missing_salt(void *arg)
{
  (void) arg;

  size_t size = 4;
  char data[4] = {
    0x01, 0x02, 0x03, 0x04
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_nsec3param(rr, ptr, (const uint8_t *) data, size),
            OP_EQ, -3);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_nsec3param_with_invalid_salt(void *arg)
{
  (void) arg;

  size_t size = 5;
  char data[5] = {
    0x01, 0x02, 0x03, 0x04, 0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_nsec3param(rr, ptr, (const uint8_t *) data, size),
            OP_EQ, -4);

 done:
  dns_rr_free(rr);
}

//
// Resource Record - URI

static void
test_dns_wireformat_encode_uri_with_missing_rdata(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();

  tt_int_op(dns_encode_uri(rr), OP_EQ, -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_encode_and_decode_uri(void *arg)
{
  (void) arg;

  dns_rr_t *expected = dns_rr_new();
  dns_rr_t *actual = dns_rr_new();

  expected->uri = dns_uri_new();
  expected->uri->priority = 1234;
  expected->uri->weight = 4567;
  expected->uri->target = tor_strdup("hello");
  tt_int_op(dns_encode_uri(expected), OP_EQ, 0);

  uint8_t *ptr = (uint8_t *) expected->rdata;
  tt_int_op(dns_decode_uri(actual, ptr, (const uint8_t *) expected->rdata,
                           expected->rdlength), OP_EQ, 0);
  tt_uint_op(actual->uri->priority, OP_EQ, expected->uri->priority);
  tt_uint_op(actual->uri->weight, OP_EQ, expected->uri->weight);
  tt_str_op(actual->uri->target, OP_EQ, expected->uri->target);

 done:
  dns_rr_free(expected);
  dns_rr_free(actual);
}

static void
test_dns_wireformat_decode_uri_with_missing_rdata(void *arg)
{
  (void) arg;

  size_t size = 0;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_decode_uri(rr, ptr, (const uint8_t *) &data, size), OP_EQ, -1);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_uri_with_invalid_rdata(void *arg)
{
  (void) arg;

  size_t size = 3;
  char data[3] = {
    0x01, 0x02, 0x03
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_uri(rr, ptr, (const uint8_t *) data, size), OP_EQ, -2);

 done:
  dns_rr_free(rr);
}

static void
test_dns_wireformat_decode_uri_with_empty_target(void *arg)
{
  (void) arg;

  size_t size = 4;
  char data[4] = {
    0x01, 0x02, 0x03, 0x04
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_decode_uri(rr, ptr, (const uint8_t *) data, size), OP_EQ, 0);

 done:
  dns_rr_free(rr);
}

//
// Resource Record

static void
test_dns_wireformat_pack_rr_with_missing_type(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  dns_rr_t *rr = dns_rr_new();

  tt_int_op(dns_pack_rr(buf, rr), OP_EQ, -1);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

static void
test_dns_wireformat_pack_rr_with_invalid_rdata(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  dns_rr_t *rr = dns_rr_new();

  rr->rrtype = dns_type_of(DNS_TYPE_A);
  tt_int_op(dns_pack_rr(buf, rr), OP_EQ, -2);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

static void
test_dns_wireformat_pack_rr_with_invalid_name(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  dns_rr_t *rr = dns_rr_new();

  rr->name = dns_name_of("abcd012345678901234567890123456789012345678901234567"
                         "890123456789.example.com");
  rr->rrtype = dns_type_of(DNS_TYPE_SINK);
  tt_int_op(dns_pack_rr(buf, rr), OP_EQ, -3);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

static void
test_dns_wireformat_pack_and_consume_rr(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size;
  char *data = NULL;

  dns_rr_t *actual = dns_rr_new();
  dns_rr_t *expected = dns_rr_new();
  expected->name = dns_name_of("hello.");
  expected->rrtype = dns_type_of(DNS_TYPE_A);
  expected->rrclass = DNS_CLASS_CHAOS;
  expected->a = tor_strdup("1.2.3.4");
  tt_int_op(dns_pack_rr(buf, expected), OP_EQ, 21);

  data = buf_extract(buf, &size);
  tt_int_op(size, OP_EQ, 21);

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_rr(actual, &ptr, (const uint8_t *) data, size), OP_EQ,
            21);
  tt_str_op(dns_name_str(actual->name), OP_EQ, dns_name_str(expected->name));
  tt_uint_op(actual->rrtype->value, OP_EQ, expected->rrtype->value);
  tt_uint_op(actual->rrclass, OP_EQ, expected->rrclass);
  tt_str_op(actual->a, OP_EQ, expected->a);

 done:
  buf_free(buf);
  tor_free(data);
  dns_rr_free(actual);
  dns_rr_free(expected);
}

static void
test_dns_wireformat_consume_rr_with_missing_data(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 0;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) &data[1];
  tt_int_op(dns_consume_rr(rr, &ptr, (const uint8_t *) &data, size), OP_EQ,
            -1);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

static void
test_dns_wireformat_consume_rr_with_invalid_name(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 1;
  char data[1] = {
    0x01
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_rr(rr, &ptr, (const uint8_t *) &data, size), OP_EQ,
            -2);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

static void
test_dns_wireformat_consume_rr_with_invalid_data(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 2;
  char data[2] = {
    0x00, 0x02
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_rr(rr, &ptr, (const uint8_t *) &data, size), OP_EQ,
            -3);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

static void
test_dns_wireformat_consume_rr_with_missing_rdata(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 11;
  char data[11] = {
    0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x04
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_rr(rr, &ptr, (const uint8_t *) &data, size), OP_EQ,
            -4);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

static void
test_dns_wireformat_consume_rr_with_malformed_rdata(void *arg)
{
  (void) arg;

  buf_t *buf = buf_new();
  size_t size = 14;
  char data[14] = {
    0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x03, 0x01, 0x02, 0x03
  };

  dns_rr_t *rr = dns_rr_new();

  uint8_t *ptr = (uint8_t *) data;
  tt_int_op(dns_consume_rr(rr, &ptr, (const uint8_t *) &data, size), OP_EQ,
            -5);

 done:
  buf_free(buf);
  dns_rr_free(rr);
}

#define DNS_WIREFORMAT_TEST(name, flags)                          \
  { #name, test_dns_wireformat_ ## name, flags, NULL, NULL }

struct testcase_t dns_wireformat_tests[] = {

  DNS_WIREFORMAT_TEST(encode_message_with_invalid_question, 0),
  DNS_WIREFORMAT_TEST(encode_message_with_invalid_additional_record, 0),
  DNS_WIREFORMAT_TEST(encode_message_with_invalid_answer, 0),
  DNS_WIREFORMAT_TEST(encode_message_with_invalid_name_server, 0),
  DNS_WIREFORMAT_TEST(encode_and_decode_message, 0),
  DNS_WIREFORMAT_TEST(decode_message_with_invalid_header, 0),
  DNS_WIREFORMAT_TEST(decode_message_with_invalid_question, 0),
  DNS_WIREFORMAT_TEST(decode_message_with_invalid_answer, 0),
  DNS_WIREFORMAT_TEST(decode_message_with_invalid_name_server, 0),
  DNS_WIREFORMAT_TEST(decode_message_with_invalid_additional_record, 0),
  DNS_WIREFORMAT_TEST(decode_message_with_invalid_length, 0),

  DNS_WIREFORMAT_TEST(encode_digest_data, 0),
  DNS_WIREFORMAT_TEST(encode_digest_data_with_invalid_name, 0),
  DNS_WIREFORMAT_TEST(encode_key_tag, 0),

  DNS_WIREFORMAT_TEST(pack_name_without_data, 0),
  DNS_WIREFORMAT_TEST(pack_name_with_too_long_label, 0),
  DNS_WIREFORMAT_TEST(pack_name_root, 0),
  DNS_WIREFORMAT_TEST(pack_and_consume_name, 0),
  DNS_WIREFORMAT_TEST(consume_name_using_compression, 0),
  DNS_WIREFORMAT_TEST(consume_name_starting_with_null_byte, 0),
  DNS_WIREFORMAT_TEST(consume_name_without_data, 0),
  DNS_WIREFORMAT_TEST(consume_name_with_missing_end, 0),
  DNS_WIREFORMAT_TEST(consume_name_with_missing_compression_pointer, 0),
  DNS_WIREFORMAT_TEST(consume_name_with_invalid_compression_pointer, 0),
  DNS_WIREFORMAT_TEST(consume_name_with_invalid_compression_label, 0),
  DNS_WIREFORMAT_TEST(consume_name_with_compression_pointer_loop, 0),
  DNS_WIREFORMAT_TEST(consume_name_with_invalid_label_length, 0),

  DNS_WIREFORMAT_TEST(pack_type_bitmaps_without_data, 0),
  DNS_WIREFORMAT_TEST(pack_type_bitmaps_with_type65535, 0),
  DNS_WIREFORMAT_TEST(pack_and_consume_type_bitmaps, 0),
  DNS_WIREFORMAT_TEST(consume_type_bitmaps_without_data, 0),
  DNS_WIREFORMAT_TEST(consume_type_bitmaps_with_missing_length, 0),
  DNS_WIREFORMAT_TEST(consume_type_bitmaps_with_truncated_bitmap, 0),
  DNS_WIREFORMAT_TEST(consume_type_bitmaps_with_excessive_bitmap, 0),

  DNS_WIREFORMAT_TEST(pack_and_consume_header, 0),
  DNS_WIREFORMAT_TEST(consume_header_with_missing_data, 0),
  DNS_WIREFORMAT_TEST(consume_header_with_invalid_data, 0),

  DNS_WIREFORMAT_TEST(pack_question_with_missing_type, 0),
  DNS_WIREFORMAT_TEST(pack_question_with_invalid_qname, 0),
  DNS_WIREFORMAT_TEST(pack_and_consume_question, 0),
  DNS_WIREFORMAT_TEST(consume_question_with_missing_data, 0),
  DNS_WIREFORMAT_TEST(consume_question_with_invalid_qname, 0),
  DNS_WIREFORMAT_TEST(consume_question_with_invalid_data, 0),

  DNS_WIREFORMAT_TEST(encode_a_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_a_with_invalid_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_and_decode_a, 0),
  DNS_WIREFORMAT_TEST(decode_a_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_a_with_invalid_rdata, 0),

  DNS_WIREFORMAT_TEST(encode_ns_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_ns_with_invalid_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_and_decode_ns, 0),
  DNS_WIREFORMAT_TEST(decode_ns_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_ns_with_invalid_rdata, 0),

  DNS_WIREFORMAT_TEST(encode_cname_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_cname_with_invalid_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_and_decode_cname, 0),
  DNS_WIREFORMAT_TEST(decode_cname_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_cname_with_invalid_rdata, 0),

  DNS_WIREFORMAT_TEST(encode_soa_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_soa_with_invalid_mname, 0),
  DNS_WIREFORMAT_TEST(encode_soa_with_invalid_rname, 0),
  DNS_WIREFORMAT_TEST(encode_and_decode_soa, 0),
  DNS_WIREFORMAT_TEST(decode_soa_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_soa_with_invalid_mname, 0),
  DNS_WIREFORMAT_TEST(decode_soa_with_invalid_rname, 0),
  DNS_WIREFORMAT_TEST(decode_soa_with_invalid_rdata, 0),

  DNS_WIREFORMAT_TEST(encode_ptr_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_ptr_with_invalid_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_and_decode_ptr, 0),
  DNS_WIREFORMAT_TEST(decode_ptr_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_ptr_with_invalid_rdata, 0),

  DNS_WIREFORMAT_TEST(encode_mx_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_mx_with_invalid_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_and_decode_mx, 0),
  DNS_WIREFORMAT_TEST(decode_mx_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_mx_with_invalid_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_mx_with_empty_exchange, 0),

  DNS_WIREFORMAT_TEST(encode_key_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_and_decode_key, 0),
  DNS_WIREFORMAT_TEST(decode_key_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_key_with_invalid_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_key_with_empty_public_key, 0),

  DNS_WIREFORMAT_TEST(encode_aaaa_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_aaaa_with_invalid_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_and_decode_aaaa, 0),
  DNS_WIREFORMAT_TEST(decode_aaaa_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_aaaa_with_invalid_rdata, 0),

  DNS_WIREFORMAT_TEST(encode_ds_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_and_decode_ds, 0),
  DNS_WIREFORMAT_TEST(decode_ds_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_ds_with_invalid_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_ds_with_empty_digest, 0),

  DNS_WIREFORMAT_TEST(encode_rrsig_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_rrsig_with_invalid_signer_name, 0),
  DNS_WIREFORMAT_TEST(encode_and_decode_rrsig, 0),
  DNS_WIREFORMAT_TEST(decode_rrsig_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_rrsig_with_invalid_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_rrsig_with_invalid_signer_name, 0),
  DNS_WIREFORMAT_TEST(decode_rrsig_with_empty_signature, 0),

  DNS_WIREFORMAT_TEST(encode_nsec_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_nsec_with_invalid_next_domain_name, 0),
  DNS_WIREFORMAT_TEST(encode_and_decode_nsec, 0),
  DNS_WIREFORMAT_TEST(decode_nsec_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_nsec_with_invalid_next_domain_name, 0),
  DNS_WIREFORMAT_TEST(decode_nsec_with_invalid_type_bitmaps, 0),

  DNS_WIREFORMAT_TEST(encode_dnskey_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_and_decode_dnskey, 0),
  DNS_WIREFORMAT_TEST(decode_dnskey_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_dnskey_with_invalid_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_dnskey_with_empty_public_key, 0),

  DNS_WIREFORMAT_TEST(encode_nsec3_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_and_decode_nsec3, 0),
  DNS_WIREFORMAT_TEST(decode_nsec3_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_nsec3_with_invalid_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_nsec3_with_missing_salt, 0),
  DNS_WIREFORMAT_TEST(decode_nsec3_with_invalid_salt, 0),
  DNS_WIREFORMAT_TEST(decode_nsec3_with_empty_hash, 0),
  DNS_WIREFORMAT_TEST(decode_nsec3_with_invalid_hash, 0),
  DNS_WIREFORMAT_TEST(decode_nsec3_with_invalid_type_bitmaps, 0),

  DNS_WIREFORMAT_TEST(encode_nsec3param_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_and_decode_nsec3param, 0),
  DNS_WIREFORMAT_TEST(decode_nsec3param_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_nsec3param_with_invalid_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_nsec3param_with_missing_salt, 0),
  DNS_WIREFORMAT_TEST(decode_nsec3param_with_invalid_salt, 0),

  DNS_WIREFORMAT_TEST(encode_uri_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(encode_and_decode_uri, 0),
  DNS_WIREFORMAT_TEST(decode_uri_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_uri_with_invalid_rdata, 0),
  DNS_WIREFORMAT_TEST(decode_uri_with_empty_target, 0),

  DNS_WIREFORMAT_TEST(pack_rr_with_missing_type, 0),
  DNS_WIREFORMAT_TEST(pack_rr_with_invalid_rdata, 0),
  DNS_WIREFORMAT_TEST(pack_rr_with_invalid_name, 0),
  DNS_WIREFORMAT_TEST(pack_and_consume_rr, 0),
  DNS_WIREFORMAT_TEST(consume_rr_with_missing_data, 0),
  DNS_WIREFORMAT_TEST(consume_rr_with_invalid_name, 0),
  DNS_WIREFORMAT_TEST(consume_rr_with_invalid_data, 0),
  DNS_WIREFORMAT_TEST(consume_rr_with_missing_rdata, 0),
  DNS_WIREFORMAT_TEST(consume_rr_with_malformed_rdata, 0),

  END_OF_TESTCASES
};
