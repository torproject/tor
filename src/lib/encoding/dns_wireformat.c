/* Copyright (c) 2019 Christian Hofer.
 * Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file dns_wireformat.c
 * \brief Encode DNS messages to wire-format and decode DNS messages from
 *  wire-format.
 **/

#define DNS_WIREFORMAT_PRIVATE
#include "lib/encoding/dns_wireformat.h"

#include "lib/buf/buffers.h"
#include "lib/container/dns_message.h"
#include "lib/container/dns_message_st.h"
#include "lib/container/smartlist.h"
#include "lib/defs/dns_types.h"
#include "lib/encoding/binascii.h"
#include "lib/encoding/dns_string.h"
#include "lib/log/log.h"
#include "lib/log/util_bug.h"
#include "lib/malloc/malloc.h"
#include "lib/net/inaddr.h"
#include "lib/string/util_string.h"

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

//
// Header

/** Pack the given header <b>dh</b> to wire-format. */
int
dns_pack_header(buf_t *buf, const dns_header_t *dh)
{
  // LCOV_EXCL_START
  tor_assert(buf);
  tor_assert(dh);
  // LCOV_EXCL_STOP

  char *res = NULL;
  size_t res_len = 0;

  log_debug(LD_GENERAL, "pack: %s", dns_header_str(dh));

  struct dns_header_wireformat_s wire;
  wire.id = htons(dh->id);
  wire.qr = dh->qr ? 1 : 0;
  wire.opcode = dh->opcode;
  wire.aa = dh->aa ? 1 : 0;
  wire.tc = dh->tc ? 1 : 0;
  wire.rd = dh->rd ? 1 : 0;
  wire.ra = dh->ra ? 1 : 0;
  wire.z = dh->z ? 1 : 0;
  wire.ad = dh->ad ? 1 : 0;
  wire.cd = dh->cd ? 1 : 0;
  wire.rcode = dh->rcode;
  wire.qdcount = htons(dh->qdcount);
  wire.ancount = htons(dh->ancount);
  wire.nscount = htons(dh->nscount);
  wire.arcount = htons(dh->arcount);

  res = (char *) &wire;
  res_len = sizeof(struct dns_header_wireformat_s);
  buf_add(buf, (const char *) res, res_len);
  log_debug(LD_GENERAL, "packed (%d): %s", (int) res_len,
            hex_str((const char *) res, res_len));

  return (int) res_len;
}

/** Consume wire-format data and interpret it as header. */
int
dns_consume_header(dns_header_t *dh, uint8_t **ptr, const uint8_t *data,
                   const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(dh);
  tor_assert(ptr);
  tor_assert(data);
  // LCOV_EXCL_STOP

  size_t pos = (*ptr - data);
  int consumed = 0;

  if (pos > size) {
    log_debug(LD_GENERAL, "no data left");
    return -1;
  }
  log_debug(LD_GENERAL, "consume: %s", hex_str((const char *) *ptr,
            size - pos));

  size_t header_len = sizeof(struct dns_header_wireformat_s);
  if (header_len > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d",
              (int) header_len, (int) (size - pos));
    return -2;
  }

  struct dns_header_wireformat_s *wire =
    (struct dns_header_wireformat_s *) *ptr;
  consumed += header_len;
  *ptr += header_len;

  dh->id = ntohs(wire->id);
  dh->qr = wire->qr == 1 ? true : false;
  dh->opcode = wire->opcode;
  dh->aa = wire->aa == 1 ? true : false;
  dh->tc = wire->tc == 1 ? true : false;
  dh->rd = wire->rd == 1 ? true : false;
  dh->ra = wire->ra == 1 ? true : false;
  dh->z = wire->z == 1 ? true : false;
  dh->ad = wire->ad == 1 ? true : false;
  dh->cd = wire->cd == 1 ? true : false;
  dh->rcode = wire->rcode;
  dh->qdcount = ntohs(wire->qdcount);
  dh->ancount = ntohs(wire->ancount);
  dh->nscount = ntohs(wire->nscount);
  dh->arcount = ntohs(wire->arcount);

  log_debug(LD_GENERAL, "consumed (%d):\n%s", consumed, dns_header_str(dh));
  return consumed;
}

//
// Question

/** Pack the given question <b>dq</b> to wire-format. */
int
dns_pack_question(buf_t *buf, const dns_question_t *dq)
{
  // LCOV_EXCL_START
  tor_assert(buf);
  tor_assert(dq);
  // LCOV_EXCL_STOP

  buf_t *stash = buf_new();
  char *res = NULL;
  size_t res_len = 0;

  if (!dq->qtype) {
    log_debug(LD_GENERAL, "missing question type");
    res_len = -1;
    goto cleanup;
  }
  log_debug(LD_GENERAL, "pack: %s", dns_question_str(dq));

  if (dns_pack_name(stash, dq->qname) < 0) {
    log_debug(LD_GENERAL, "failed packing name");
    res_len = -2;
    goto cleanup;
  }

  struct dns_question_wireformat_s wire;
  wire.qtype = htons(dq->qtype->value);
  wire.qclass = htons(dq->qclass);

  buf_add(stash, (const char *)&wire,
          sizeof(struct dns_question_wireformat_s));

  res = buf_extract(stash, &res_len);
  buf_add(buf, (const char *) res, res_len);
  log_debug(LD_GENERAL, "packed (%d): %s", (int) res_len,
            hex_str((const char *) res, res_len));

 cleanup:
  buf_free(stash);
  tor_free(res);
  return (int) res_len;
}

/** Consume wire-format data and interpret it as question. */
int
dns_consume_question(dns_question_t *dq, uint8_t **ptr, const uint8_t *data,
                     const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(dq);
  tor_assert(ptr);
  tor_assert(data);
  // LCOV_EXCL_STOP

  size_t pos = (*ptr - data);
  int consumed = 0;

  if (pos > size) {
    log_debug(LD_GENERAL, "no data left");
    return -1;
  }
  log_debug(LD_GENERAL, "consume: %s", hex_str((const char *) *ptr,
            size - pos));

  dns_name_free(dq->qname);
  dq->qname = dns_name_new();

  consumed = dns_consume_name(dq->qname, ptr, data, size);
  if (consumed < 0) {
    log_debug(LD_GENERAL, "failed consuming name");
    return -2;
  }

  pos = (*ptr - data);
  size_t question_len = sizeof(struct dns_question_wireformat_s);
  if (question_len > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d",
              (int) question_len, (int) (size - pos));
    return -3;
  }

  struct dns_question_wireformat_s *wire =
    (struct dns_question_wireformat_s *) *ptr;
  consumed += question_len;
  *ptr += question_len;

  dq->qtype = dns_type_of(ntohs(wire->qtype));
  dq->qclass = ntohs(wire->qclass);

  log_debug(LD_GENERAL, "consumed (%d): %s", consumed, dns_question_str(dq));
  return consumed;
}

//
// Resource Record - A

/** Encode the given A record in <b>drr</b> to wire-format. */
int
dns_encode_a(dns_rr_t *drr)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  // LCOV_EXCL_STOP

  if (!drr->a) {
    log_debug(LD_GENERAL, "missing rdata");
    return -1;
  }
  log_debug(LD_GENERAL, "encode: %s", dns_a_str(drr->a));

  struct sockaddr_in addr;
  if (!tor_inet_pton(AF_INET, drr->a, &addr.sin_addr)) {
    log_debug(LD_GENERAL, "inet_ntop conversion error");
    return -2;
  }

  tor_free(drr->rdata);
  drr->rdlength = sizeof(addr.sin_addr.s_addr);
  drr->rdata = tor_memdup((const char *) &addr.sin_addr.s_addr, drr->rdlength);

  log_debug(LD_GENERAL, "encoded: %s", hex_str((const char *) drr->rdata,
    drr->rdlength));

  return 0;
}

/** Decode wire-format data and interpret it as A record. */
int
dns_decode_a(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
             const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  tor_assert(ptr);
  tor_assert(data);
  // LCOV_EXCL_STOP

  size_t pos = (ptr - data);
  if (pos > size) {
    log_debug(LD_GENERAL, "no data left");
    return -1;
  }
  log_debug(LD_GENERAL, "decode: %s", hex_str((const char *) ptr, size - pos));

  struct sockaddr_in addr;
  size_t a_len = sizeof(addr.sin_addr.s_addr);

  if (a_len > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d", (int) a_len,
              (int) (size - pos));
    return -2;
  }
  memcpy(&addr.sin_addr.s_addr, ptr, a_len);

  char address[INET_ADDRSTRLEN];
  tor_inet_ntop(AF_INET, &addr.sin_addr, address, INET_ADDRSTRLEN);

  tor_free(drr->a);
  drr->a = tor_strdup(address);
  log_debug(LD_GENERAL, "decoded: %s", dns_a_str(drr->a));

  return 0;
}

//
// Resource Record - NS

/** Encode the given NS record in <b>drr</b> to wire-format. */
int
dns_encode_ns(dns_rr_t *drr)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  // LCOV_EXCL_STOP

  buf_t *stash = buf_new();
  int ret = 0;

  if (!drr->ns) {
    log_debug(LD_GENERAL, "missing rdata");
    ret = -1;
    goto cleanup;
  }
  log_debug(LD_GENERAL, "encode: %s", dns_ns_str(drr->ns));

  if (dns_pack_name(stash, drr->ns) < 0) {
    log_debug(LD_GENERAL, "failed packing name");
    ret = -2;
    goto cleanup;
  }

  size_t sz_out = 0;
  tor_free(drr->rdata);
  drr->rdata = (uint8_t *) buf_extract(stash, &sz_out);
  drr->rdlength = (uint16_t) sz_out;

  log_debug(LD_GENERAL, "encoded: %s",
            hex_str((const char *) drr->rdata, drr->rdlength));

 cleanup:
  buf_free(stash);
  return ret;
}

/** Decode wire-format data and interpret it as NS record. */
int
dns_decode_ns(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
              const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  tor_assert(ptr);
  tor_assert(data);
  // LCOV_EXCL_STOP

  size_t pos = (ptr - data);
  if (pos > size) {
    log_debug(LD_GENERAL, "no data left");
    return -1;
  }
  log_debug(LD_GENERAL, "decode: %s", hex_str((const char *) ptr, size - pos));

  dns_name_free(drr->ns);
  drr->ns = dns_name_new();

  if (dns_consume_name(drr->ns, &ptr, data, size) < 0) {
    log_debug(LD_GENERAL, "failed consuming name");
    return -2;
  }
  log_debug(LD_GENERAL, "decoded: %s", dns_ns_str(drr->ns));

  return 0;
}

//
// Resource Record - CNAME

/** Encode the given CNAME record in <b>drr</b> to wire-format. */
int
dns_encode_cname(dns_rr_t *drr)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  // LCOV_EXCL_STOP

  buf_t *stash = buf_new();
  int ret = 0;

  if (!drr->cname) {
    log_debug(LD_GENERAL, "missing rdata");
    ret = -1;
    goto cleanup;
  }
  log_debug(LD_GENERAL, "encode: %s", dns_cname_str(drr->cname));

  if (dns_pack_name(stash, drr->cname) < 0) {
    log_debug(LD_GENERAL, "failed packing name");
    ret = -2;
    goto cleanup;
  }

  size_t sz_out = 0;
  tor_free(drr->rdata);
  drr->rdata = (uint8_t *) buf_extract(stash, &sz_out);
  drr->rdlength = (uint16_t) sz_out;

  log_debug(LD_GENERAL, "encoded: %s",
            hex_str((const char *) drr->rdata, drr->rdlength));

 cleanup:
  buf_free(stash);
  return ret;
}

/** Decode wire-format data and interpret it as CNAME record. */
int
dns_decode_cname(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                 const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  tor_assert(ptr);
  tor_assert(data);
  // LCOV_EXCL_STOP

  size_t pos = (ptr - data);
  if (pos > size) {
    log_debug(LD_GENERAL, "no data left");
    return -1;
  }
  log_debug(LD_GENERAL, "decode: %s", hex_str((const char *) ptr, size - pos));

  dns_name_free(drr->cname);
  drr->cname = dns_name_new();

  if (dns_consume_name(drr->cname, &ptr, data, size) < 0) {
    log_debug(LD_GENERAL, "failed consuming name");
    return -2;
  }
  log_debug(LD_GENERAL, "decoded: %s", dns_cname_str(drr->cname));

  return 0;
}

//
// Resource Record - SOA

/** Encode the given SOA record in <b>drr</b> to wire-format. */
int
dns_encode_soa(dns_rr_t *drr)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  // LCOV_EXCL_STOP

  buf_t *stash = buf_new();
  int ret = 0;

  if (!drr->soa) {
    log_debug(LD_GENERAL, "missing rdata");
    ret = -1;
    goto cleanup;
  }
  log_debug(LD_GENERAL, "encode: %s", dns_soa_str(drr->soa));

  if (dns_pack_name(stash, drr->soa->mname) < 0) {
    log_debug(LD_GENERAL, "failed packing mname");
    ret = -2;
    goto cleanup;
  }

  if (dns_pack_name(stash, drr->soa->rname) < 0) {
    log_debug(LD_GENERAL, "failed packing rname");
    ret = -3;
    goto cleanup;
  }

  struct dns_soa_wireformat_s wire;
  wire.serial = htonl(drr->soa->serial);
  wire.refresh = htonl(drr->soa->refresh);
  wire.retry = htonl(drr->soa->retry);
  wire.expire = htonl(drr->soa->expire);
  wire.minimum = htonl(drr->soa->minimum);

  buf_add(stash, (const char *) &wire, sizeof(struct dns_soa_wireformat_s));

  size_t sz_out = 0;
  tor_free(drr->rdata);
  drr->rdata = (uint8_t *) buf_extract(stash, &sz_out);
  drr->rdlength = (uint16_t) sz_out;

  log_debug(LD_GENERAL, "encoded: %s",
            hex_str((const char *) drr->rdata, drr->rdlength));

 cleanup:
  buf_free(stash);
  return ret;
}

/** Decode wire-format data and interpret it as SOA record. */
int
dns_decode_soa(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
               const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  tor_assert(ptr);
  tor_assert(data);
  // LCOV_EXCL_STOP

  size_t pos = (ptr - data);
  if (pos > size) {
    log_debug(LD_GENERAL, "no data left");
    return -1;
  }
  log_debug(LD_GENERAL, "decode: %s", hex_str((const char *) ptr, size - pos));

  dns_soa_free(drr->soa);
  drr->soa = dns_soa_new();

  drr->soa->mname = dns_name_new();
  if (dns_consume_name(drr->soa->mname, &ptr, data, size) < 0) {
    log_debug(LD_GENERAL, "failed consuming mname");
    return -2;
  }

  drr->soa->rname = dns_name_new();
  if (dns_consume_name(drr->soa->rname, &ptr, data, size) < 0) {
    log_debug(LD_GENERAL, "failed consuming rname");
    return -3;
  }

  size_t soa_len = sizeof(struct dns_soa_wireformat_s);
  if (soa_len > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d", (int) soa_len,
              (int) (size - pos));
    return -4;
  }

  struct dns_soa_wireformat_s *wire =
    (struct dns_soa_wireformat_s *) ptr;

  drr->soa->serial = ntohl(wire->serial);
  drr->soa->refresh = ntohl(wire->refresh);
  drr->soa->retry = ntohl(wire->retry);
  drr->soa->expire = ntohl(wire->expire);
  drr->soa->minimum = ntohl(wire->minimum);

  log_debug(LD_GENERAL, "decoded: %s", dns_soa_str(drr->soa));

  return 0;
}

//
// Resource Record - PTR

/** Encode the given PTR record in <b>drr</b> to wire-format. */
int
dns_encode_ptr(dns_rr_t *drr)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  // LCOV_EXCL_STOP

  buf_t *stash = buf_new();
  int ret = 0;

  if (!drr->ptr) {
    log_debug(LD_GENERAL, "missing rdata");
    ret = -1;
    goto cleanup;
  }
  log_debug(LD_GENERAL, "encode: %s", dns_ptr_str(drr->ptr));

  if (dns_pack_name(stash, drr->ptr) < 0) {
    log_debug(LD_GENERAL, "failed packing name");
    ret = -2;
    goto cleanup;
  }

  size_t sz_out = 0;
  tor_free(drr->rdata);
  drr->rdata = (uint8_t *) buf_extract(stash, &sz_out);
  drr->rdlength = (uint16_t) sz_out;

  log_debug(LD_GENERAL, "encoded: %s",
            hex_str((const char *) drr->rdata, drr->rdlength));

 cleanup:
  buf_free(stash);
  return ret;
}

/** Decode wire-format data and interpret it as PTR record. */
int
dns_decode_ptr(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
               const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  tor_assert(ptr);
  tor_assert(data);
  // LCOV_EXCL_STOP

  size_t pos = (ptr - data);
  if (pos > size) {
    log_debug(LD_GENERAL, "no data left");
    return -1;
  }
  log_debug(LD_GENERAL, "decode: %s", hex_str((const char *) ptr, size - pos));

  dns_name_free(drr->ptr);
  drr->ptr = dns_name_new();

  if (dns_consume_name(drr->ptr, &ptr, data, size) < 0) {
    log_debug(LD_GENERAL, "failed consuming name");
    return -2;
  }
  log_debug(LD_GENERAL, "decoded: %s", dns_ptr_str(drr->ptr));

  return 0;
}

//
// Resource Record - MX

/** Encode the given MX record in <b>drr</b> to wire-format. */
int
dns_encode_mx(dns_rr_t *drr)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  // LCOV_EXCL_STOP

  buf_t *stash = buf_new();
  int ret = 0;

  if (!drr->mx) {
    log_debug(LD_GENERAL, "missing rdata");
    ret = -1;
    goto cleanup;
  }
  log_debug(LD_GENERAL, "encode: %s", dns_mx_str(drr->mx));

  struct dns_mx_wireformat_s wire;
  wire.preference = htons(drr->mx->preference);

  buf_add(stash, (const char *) &wire, sizeof(struct dns_mx_wireformat_s));

  if (dns_pack_name(stash, drr->mx->exchange) < 0) {
    log_debug(LD_GENERAL, "failed packing name");
    ret = -2;
    goto cleanup;
  }

  size_t sz_out = 0;
  tor_free(drr->rdata);
  drr->rdata = (uint8_t *) buf_extract(stash, &sz_out);
  drr->rdlength = (uint16_t) sz_out;

  log_debug(LD_GENERAL, "encoded: %s",
            hex_str((const char *) drr->rdata, drr->rdlength));

 cleanup:
  buf_free(stash);
  return ret;
}

/** Decode wire-format data and interpret it as MX record. */
int
dns_decode_mx(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
              const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  tor_assert(ptr);
  tor_assert(data);
  // LCOV_EXCL_STOP

  size_t pos = (ptr - data);
  if (pos > size) {
    log_debug(LD_GENERAL, "no data left");
    return -1;
  }
  log_debug(LD_GENERAL, "decode: %s", hex_str((const char *) ptr, size - pos));

  size_t mx_len = sizeof(struct dns_mx_wireformat_s);
  if (mx_len > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d", (int) mx_len,
              (int) (size - pos));
    return -2;
  }

  struct dns_mx_wireformat_s *wire =
      (struct dns_mx_wireformat_s *) ptr;
  ptr += mx_len;

  dns_mx_free(drr->mx);
  drr->mx = dns_mx_new();
  drr->mx->preference = ntohs(wire->preference);

  drr->mx->exchange = dns_name_new();
  if (dns_consume_name(drr->mx->exchange, &ptr, data, size) < 0) {
    log_debug(LD_GENERAL, "failed consuming name");
    return -3;
  }
  log_debug(LD_GENERAL, "decoded: %s", dns_mx_str(drr->mx));

  return 0;
}

//
// Resource Record - KEY

/** Encode KEY record in <b>drr</b> to wire-format. */
int
dns_encode_key(dns_rr_t *drr)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  // LCOV_EXCL_STOP

  buf_t *stash = buf_new();
  int ret = 0;

  if (!drr->key) {
    log_debug(LD_GENERAL, "missing rdata");
    ret = -1;
    goto cleanup;
  }
  log_debug(LD_GENERAL, "encode: %s", dns_key_str(drr->key));

  struct dns_key_wireformat_s wire;
  wire.flags = htons(drr->key->flags);
  wire.protocol = drr->key->protocol;
  wire.algorithm = drr->key->algorithm;

  buf_add(stash, (const char *) &wire, sizeof(struct dns_key_wireformat_s));
  buf_add(stash, (const char *) drr->key->public_key,
          drr->key->public_key_len);

  size_t sz_out = 0;
  tor_free(drr->rdata);
  drr->rdata = (uint8_t *) buf_extract(stash, &sz_out);
  drr->rdlength = (uint16_t) sz_out;

  log_debug(LD_GENERAL, "encoded: %s",
            hex_str((const char *) drr->rdata, drr->rdlength));

 cleanup:
  buf_free(stash);
  return ret;
}

/** Decode wire-format data and interpret it as KEY record. */
int
dns_decode_key(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
               const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  tor_assert(ptr);
  tor_assert(data);
  // LCOV_EXCL_STOP

  size_t pos = (ptr - data);
  if (pos > size) {
    log_debug(LD_GENERAL, "decode: no data left");
    return -1;
  }
  log_debug(LD_GENERAL, "decode: %s", hex_str((const char *) ptr, size - pos));

  size_t key_len = sizeof(struct dns_key_wireformat_s);
  if (key_len > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d", (int) key_len,
              (int) (size - pos));
    return -2;
  }

  struct dns_key_wireformat_s *wire =
    (struct dns_key_wireformat_s *) ptr;
  ptr += key_len;

  dns_key_free(drr->key);
  drr->key = dns_key_new();
  drr->key->flags = ntohs(wire->flags);
  drr->key->protocol = wire->protocol;
  drr->key->algorithm = wire->algorithm;

  pos = (ptr - data);
  uint16_t public_key_len = size - (ptr - data);

  drr->key->public_key = tor_memdup(ptr, public_key_len);
  drr->key->public_key_len = public_key_len;
  ptr += public_key_len;

  log_debug(LD_GENERAL, "decoded: %s", dns_key_str(drr->key));

  return 0;
}

//
// Resource Record - AAAA

/** Encode the given AAAA record in <b>drr</b> to wire-format. */
int
dns_encode_aaaa(dns_rr_t *drr)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  // LCOV_EXCL_STOP

  if (!drr->aaaa) {
    log_debug(LD_GENERAL, "missing rdata");
    return -1;
  }
  log_debug(LD_GENERAL, "encode: %s", dns_aaaa_str(drr->aaaa));

  struct sockaddr_in6 addr;
  if (!tor_inet_pton(AF_INET6, drr->aaaa, &addr.sin6_addr)) {
    log_debug(LD_GENERAL, "inet_ntop conversion error");
    return -2;
  }

  tor_free(drr->rdata);
  drr->rdlength = sizeof(addr.sin6_addr.s6_addr);
  drr->rdata = tor_memdup((const char *) &addr.sin6_addr.s6_addr,
      drr->rdlength);

  log_debug(LD_GENERAL, "encoded: %s", hex_str((const char *) drr->rdata,
            drr->rdlength));

  return 0;
}

/** Decode wire-format data and interpret it as AAAA record. */
int
dns_decode_aaaa(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  tor_assert(ptr);
  tor_assert(data);
  // LCOV_EXCL_STOP

  size_t pos = (ptr - data);

  if (pos > size) {
    log_debug(LD_GENERAL, "no data left");
    return -1;
  }
  log_debug(LD_GENERAL, "decode: %s", hex_str((const char *) ptr, size - pos));

  struct sockaddr_in6 addr;
  size_t aaaa_len = sizeof(addr.sin6_addr.s6_addr);

  if (aaaa_len > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d", (int) aaaa_len,
              (int) (size - pos));
    return -2;
  }
  memcpy(&addr.sin6_addr.s6_addr, ptr, aaaa_len);

  char address[INET6_ADDRSTRLEN];
  tor_inet_ntop(AF_INET6, &addr.sin6_addr, address, INET6_ADDRSTRLEN);

  tor_free(drr->aaaa);
  drr->aaaa = tor_strdup(address);
  log_debug(LD_GENERAL, "decoded: %s", dns_aaaa_str(drr->aaaa));

  return 0;
}

//
// Resource Record - DS

/** Encode the given DS record in <b>drr</b> to wire-format. */
int
dns_encode_ds(dns_rr_t *drr)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  // LCOV_EXCL_STOP

  buf_t *stash = buf_new();
  int ret = 0;

  if (!drr->ds) {
    log_debug(LD_GENERAL, "missing rdata");
    ret = -1;
    goto cleanup;
  }
  log_debug(LD_GENERAL, "encode: %s", dns_ds_str(drr->ds));

  struct dns_ds_wireformat_s wire;
  wire.key_tag = htons(drr->ds->key_tag);
  wire.algorithm = drr->ds->algorithm;
  wire.digest_type = drr->ds->digest_type;

  buf_add(stash, (const char *) &wire, sizeof(struct dns_ds_wireformat_s));
  buf_add(stash, (const char *) drr->ds->digest, drr->ds->digest_len);

  size_t sz_out = 0;
  tor_free(drr->rdata);
  drr->rdata = (uint8_t *) buf_extract(stash, &sz_out);
  drr->rdlength = (uint16_t) sz_out;

  log_debug(LD_GENERAL, "encoded: %s",
            hex_str((const char *) drr->rdata, drr->rdlength));

 cleanup:
  buf_free(stash);
  return ret;
}

/** Decode wire-format data and interpret it as DS record. */
int
dns_decode_ds(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
              const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  tor_assert(ptr);
  tor_assert(data);
  // LCOV_EXCL_STOP

  size_t pos = (ptr - data);
  if (pos > size) {
    log_debug(LD_GENERAL, "no data left");
    return -1;
  }
  log_debug(LD_GENERAL, "decode: %s", hex_str((const char *) ptr, size - pos));

  size_t ds_len = sizeof(struct dns_ds_wireformat_s);
  if (ds_len > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d", (int) ds_len,
              (int) (size - pos));
    return -2;
  }

  struct dns_ds_wireformat_s *wire =
    (struct dns_ds_wireformat_s *) ptr;
  ptr += ds_len;

  dns_ds_free(drr->ds);
  drr->ds = dns_ds_new();
  drr->ds->key_tag = ntohs(wire->key_tag);
  drr->ds->algorithm = wire->algorithm;
  drr->ds->digest_type = wire->digest_type;

  pos = (ptr - data);
  uint16_t digest_len = size - (ptr - data);

  drr->ds->digest = tor_memdup(ptr, digest_len);
  drr->ds->digest_len = digest_len;
  ptr += digest_len;

  log_debug(LD_GENERAL, "decoded: %s", dns_ds_str(drr->ds));

  return 0;
}

//
// Resource Record - RRSIG

/** Encode the given RRSIG record in <b>drr</b> to wire-format. */
int
dns_encode_rrsig(dns_rr_t *drr)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  // LCOV_EXCL_STOP

  buf_t *stash = buf_new();
  int ret = 0;

  if (!drr->rrsig || !drr->rrsig->type_covered) {
    log_debug(LD_GENERAL, "missing rdata");
    ret = -1;
    goto cleanup;
  }
  log_debug(LD_GENERAL, "encode: %s", dns_rrsig_str(drr->rrsig));

  struct dns_rrsig_wireformat_s wire;
  wire.type_covered = htons(drr->rrsig->type_covered->value);
  wire.algorithm = drr->rrsig->algorithm;
  wire.labels = drr->rrsig->labels;
  wire.original_ttl = htonl(drr->rrsig->original_ttl);
  wire.signature_expiration = htonl(drr->rrsig->signature_expiration);
  wire.signature_inception = htonl(drr->rrsig->signature_inception);
  wire.key_tag = htons(drr->rrsig->key_tag);

  buf_add(stash, (const char *) &wire, sizeof(struct dns_rrsig_wireformat_s));

  if (dns_pack_name(stash, drr->rrsig->signer_name) < 0) {
    log_debug(LD_GENERAL, "failed packing name");
    ret = -2;
    goto cleanup;
  }

  buf_add(stash, (const char *) drr->rrsig->signature,
          drr->rrsig->signature_len);

  size_t sz_out = 0;
  tor_free(drr->rdata);
  drr->rdata = (uint8_t *) buf_extract(stash, &sz_out);
  drr->rdlength = (uint16_t) sz_out;

  log_debug(LD_GENERAL, "encoded: %s",
            hex_str((const char *) drr->rdata, drr->rdlength));

 cleanup:
  buf_free(stash);
  return ret;
}

/** Decode wire-format data and interpret it as RRSIG record. */
int
dns_decode_rrsig(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                 const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  tor_assert(ptr);
  tor_assert(data);
  // LCOV_EXCL_STOP

  size_t pos = (ptr - data);
  if (pos > size) {
    log_debug(LD_GENERAL, "no data left");
    return -1;
  }
  log_debug(LD_GENERAL, "decode: %s", hex_str((const char *) ptr, size - pos));

  size_t rrsig_len = sizeof(struct dns_rrsig_wireformat_s);
  if (rrsig_len > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d", (int) rrsig_len,
              (int) (size - pos));
    return -2;
  }

  struct dns_rrsig_wireformat_s *wire =
    (struct dns_rrsig_wireformat_s *) ptr;
  ptr += rrsig_len;

  dns_rrsig_free(drr->rrsig);
  drr->rrsig = dns_rrsig_new();
  drr->rrsig->type_covered = dns_type_of(ntohs(wire->type_covered));
  drr->rrsig->algorithm = wire->algorithm;
  drr->rrsig->labels = wire->labels;
  drr->rrsig->original_ttl = ntohl(wire->original_ttl);
  drr->rrsig->signature_expiration = ntohl(wire->signature_expiration);
  drr->rrsig->signature_inception = ntohl(wire->signature_inception);
  drr->rrsig->key_tag = ntohs(wire->key_tag);

  drr->rrsig->signer_name = dns_name_new();
  if (dns_consume_name(drr->rrsig->signer_name, &ptr, data, size) < 0) {
    log_debug(LD_GENERAL, "failed consuming name");
    return -3;
  }

  pos = (ptr - data);
  uint16_t signature_len = size - (ptr - data);

  drr->rrsig->signature = tor_memdup(ptr, signature_len);
  drr->rrsig->signature_len = signature_len;
  ptr += signature_len;

  log_debug(LD_GENERAL, "decoded: %s", dns_rrsig_str(drr->rrsig));

  return 0;
}

//
// Resource Record - NSEC

/** Encode the given NSEC record in <b>drr</b> to wire-format. */
int
dns_encode_nsec(dns_rr_t *drr)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  // LCOV_EXCL_STOP

  buf_t *stash = buf_new();
  int ret = 0;

  if (!drr->nsec) {
    log_debug(LD_GENERAL, "missing rdata");
    ret = -1;
    goto cleanup;
  }
  log_debug(LD_GENERAL, "encode: %s", dns_nsec_str(drr->nsec));

  if (dns_pack_name(stash, drr->nsec->next_domain_name) < 0) {
    log_debug(LD_GENERAL, "failed packing next domain name");
    ret = -2;
    goto cleanup;
  }

  if (dns_pack_type_bitmaps(stash, drr->nsec->types) < 0) {
    // LCOV_EXCL_START
    log_debug(LD_GENERAL, "failed packing type bitmaps");
    ret = -3;
    goto cleanup;
    // LCOV_EXCL_STOP
  }

  size_t sz_out = 0;
  tor_free(drr->rdata);
  drr->rdata = (uint8_t *) buf_extract(stash, &sz_out);
  drr->rdlength = (uint16_t) sz_out;

  log_debug(LD_GENERAL, "encoded: %s",
            hex_str((const char *) drr->rdata, drr->rdlength));

 cleanup:
  buf_free(stash);
  return ret;
}

/** Decode wire-format data and interpret it as NSEC record. */
int
dns_decode_nsec(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
  const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  tor_assert(ptr);
  tor_assert(data);
  // LCOV_EXCL_STOP

  size_t pos = (ptr - data);
  if (pos > size) {
    log_debug(LD_GENERAL, "no data left");
    return -1;
  }
  log_debug(LD_GENERAL, "decode: %s", hex_str((const char *) ptr, size - pos));

  dns_nsec_free(drr->nsec);
  drr->nsec = dns_nsec_new();

  drr->nsec->next_domain_name = dns_name_new();
  if (dns_consume_name(drr->nsec->next_domain_name, &ptr, data, size) < 0) {
    log_debug(LD_GENERAL, "failed consuming next domain name");
    return -2;
  }

  if (dns_consume_type_bitmaps(drr->nsec->types, &ptr, data, size) < 0) {
    log_debug(LD_GENERAL, "failed consuming type bitmaps");
    return -3;
  }

  log_debug(LD_GENERAL, "decoded: %s", dns_nsec_str(drr->nsec));

  return 0;
}

//
// Resource Record - DNSKEY

/** Encode the given DNSKEY record in <b>drr</b> to wire-format. */
int
dns_encode_dnskey(dns_rr_t *drr)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  // LCOV_EXCL_STOP

  buf_t *stash = buf_new();
  int ret = 0;

  if (!drr->dnskey) {
    log_debug(LD_GENERAL, "missing rdata");
    ret = -1;
    goto cleanup;
  }
  log_debug(LD_GENERAL, "encode: %s", dns_dnskey_str(drr->dnskey));

  struct dns_dnskey_wireformat_s wire;
  wire.flags = htons(drr->dnskey->flags);
  wire.protocol = drr->dnskey->protocol;
  wire.algorithm = drr->dnskey->algorithm;

  buf_add(stash, (const char *) &wire, sizeof(struct dns_dnskey_wireformat_s));
  buf_add(stash, (const char *) drr->dnskey->public_key,
          drr->dnskey->public_key_len);

  size_t sz_out = 0;
  tor_free(drr->rdata);
  drr->rdata = (uint8_t *) buf_extract(stash, &sz_out);
  drr->rdlength = (uint16_t) sz_out;

  log_debug(LD_GENERAL, "encoded: %s", hex_str((const char *) drr->rdata,
                                           drr->rdlength));

 cleanup:
  buf_free(stash);
  return ret;
}

/** Decode wire-format data and interpret it as DNSKEY record. */
int
dns_decode_dnskey(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                  const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  tor_assert(ptr);
  tor_assert(data);
  // LCOV_EXCL_STOP

  size_t pos = (ptr - data);
  if (pos > size) {
    log_debug(LD_GENERAL, "decode: no data left");
    return -1;
  }
  log_debug(LD_GENERAL, "decode: %s", hex_str((const char *) ptr, size - pos));

  size_t dnskey_len = sizeof(struct dns_dnskey_wireformat_s);
  if (dnskey_len > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d",
              (int) dnskey_len, (int) (size - pos));
    return -2;
  }

  struct dns_dnskey_wireformat_s *wire =
    (struct dns_dnskey_wireformat_s *) ptr;
  ptr += dnskey_len;

  dns_dnskey_free(drr->dnskey);
  drr->dnskey = dns_dnskey_new();
  drr->dnskey->flags = ntohs(wire->flags);
  drr->dnskey->protocol = wire->protocol;
  drr->dnskey->algorithm = wire->algorithm;

  pos = (ptr - data);
  uint16_t public_key_len = size - (ptr - data);

  drr->dnskey->public_key = tor_memdup(ptr, public_key_len);
  drr->dnskey->public_key_len = public_key_len;
  ptr += public_key_len;

  log_debug(LD_GENERAL, "decoded: %s", dns_dnskey_str(drr->dnskey));

  return 0;
}

//
// Resource Record - NSEC3

/** Encode the given NSEC3 record in <b>drr</b> to wire-format. */
int
dns_encode_nsec3(dns_rr_t *drr)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  // LCOV_EXCL_STOP

  buf_t *stash = buf_new();
  int ret = 0;

  if (!drr->nsec3) {
    log_debug(LD_GENERAL, "missing rdata");
    ret = -1;
    goto cleanup;
  }
  log_debug(LD_GENERAL, "encode: %s", dns_nsec3_str(drr->nsec3));

  struct dns_nsec3_wireformat_s wire;
  wire.hash_algorithm = drr->nsec3->hash_algorithm;
  wire.flags = drr->nsec3->flags;
  wire.iterations = htons(drr->nsec3->iterations);

  buf_add(stash, (const char *) &wire, sizeof(struct dns_nsec3_wireformat_s));

  buf_add(stash, (const char *) &drr->nsec3->salt_length, 1);
  buf_add(stash, (const char *) drr->nsec3->salt,
    drr->nsec3->salt_length);

  buf_add(stash, (const char *) &drr->nsec3->hash_length, 1);
  buf_add(stash, (const char *) drr->nsec3->next_hashed_owner_name,
          drr->nsec3->hash_length);

  if (dns_pack_type_bitmaps(stash, drr->nsec3->types) < 0) {
    // LCOV_EXCL_START
    log_debug(LD_GENERAL, "failed packing type bitmaps");
    ret = -2;
    goto cleanup;
    // LCOV_EXCL_STOP
  }

  size_t sz_out = 0;
  tor_free(drr->rdata);
  drr->rdata = (uint8_t *) buf_extract(stash, &sz_out);
  drr->rdlength = (uint16_t) sz_out;

  log_debug(LD_GENERAL, "encoded: %s", hex_str((const char *) drr->rdata,
                                           drr->rdlength));

 cleanup:
  buf_free(stash);
  return ret;
}

/** Decode wire-format data and interpret it as NSEC3 record. */
int
dns_decode_nsec3(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                 const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  tor_assert(ptr);
  tor_assert(data);
  // LCOV_EXCL_STOP

  size_t pos = (ptr - data);
  if (pos > size) {
    log_debug(LD_GENERAL, "no data left");
    return -1;
  }
  log_debug(LD_GENERAL, "decode: %s", hex_str((const char *) ptr, size - pos));

  size_t nsec3_len = sizeof(struct dns_nsec3_wireformat_s);
  if (nsec3_len > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d", (int) nsec3_len,
              (int) (size - pos));
    return -2;
  }

  struct dns_nsec3_wireformat_s *wire =
      (struct dns_nsec3_wireformat_s *) ptr;
  ptr += nsec3_len;
  pos = (ptr - data);

  dns_nsec3_free(drr->nsec3);
  drr->nsec3 = dns_nsec3_new();
  drr->nsec3->hash_algorithm = wire->hash_algorithm;
  drr->nsec3->flags = wire->flags;
  drr->nsec3->iterations = ntohs(wire->iterations);

  if (1 > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d", 1,
              (int) (size - pos));
    return -3;
  }

  uint8_t salt_length = *ptr;
  ptr += 1;
  pos = (ptr - data);

  if (salt_length > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d",
              (int) salt_length, (int) (size - pos));
    return -4;
  }
  drr->nsec3->salt = tor_memdup(ptr, salt_length);
  drr->nsec3->salt_length = salt_length;
  ptr += salt_length;
  pos = (ptr - data);

  if (1 > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d", 1,
              (int) (size - pos));
    return -5;
  }

  uint8_t hash_length = *ptr;
  ptr += 1;
  pos = (ptr - data);

  if (hash_length > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d",
              (int) hash_length, (int) (size - pos));
    return -6;
  }
  drr->nsec3->next_hashed_owner_name = tor_memdup(ptr, hash_length);
  drr->nsec3->hash_length = hash_length;
  ptr += hash_length;

  if (dns_consume_type_bitmaps(drr->nsec3->types, &ptr, data, size) < 0) {
    log_debug(LD_GENERAL, "failed consuming type bitmaps");
    return -7;
  }

  log_debug(LD_GENERAL, "decoded: %s", dns_nsec3_str(drr->nsec3));

  return 0;
}

//
// Resource Record - NSEC3PARAM

/** Encode the given NSEC3PARAM record in <b>drr</b> to wire-format. */
int
dns_encode_nsec3param(dns_rr_t *drr)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  // LCOV_EXCL_STOP

  buf_t *stash = buf_new();
  int ret = 0;

  if (!drr->nsec3param) {
    log_debug(LD_GENERAL, "missing rdata");
    ret = -1;
    goto cleanup;
  }
  log_debug(LD_GENERAL, "encode: %s", dns_nsec3param_str(drr->nsec3param));

  struct dns_nsec3param_wireformat_s wire;
  wire.hash_algorithm = drr->nsec3param->hash_algorithm;
  wire.flags = drr->nsec3param->flags;
  wire.iterations = htons(drr->nsec3param->iterations);

  buf_add(stash, (const char *) &wire,
          sizeof(struct dns_nsec3param_wireformat_s));

  buf_add(stash, (const char *) &drr->nsec3param->salt_length, 1);
  buf_add(stash, (const char *) drr->nsec3param->salt,
          drr->nsec3param->salt_length);

  size_t sz_out = 0;
  tor_free(drr->rdata);
  drr->rdata = (uint8_t *) buf_extract(stash, &sz_out);
  drr->rdlength = (uint16_t) sz_out;

  log_debug(LD_GENERAL, "encoded: %s",
            hex_str((const char *) drr->rdata, drr->rdlength));

 cleanup:
  buf_free(stash);
  return ret;
}

/** Decode wire-format data and interpret it as NSEC3PARAM record. */
int
dns_decode_nsec3param(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                      const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  tor_assert(ptr);
  tor_assert(data);
  // LCOV_EXCL_STOP

  size_t pos = (ptr - data);
  if (pos > size) {
    log_debug(LD_GENERAL, "no data left");
    return -1;
  }
  log_debug(LD_GENERAL, "decode: %s", hex_str((const char *) ptr, size - pos));

  size_t nsec3param_len = sizeof(struct dns_nsec3param_wireformat_s);
  if (nsec3param_len > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d",
              (int) nsec3param_len, (int) (size - pos));
    return -2;
  }

  struct dns_nsec3param_wireformat_s *wire =
      (struct dns_nsec3param_wireformat_s *) ptr;
  ptr += nsec3param_len;
  pos = (ptr - data);

  dns_nsec3param_free(drr->nsec3param);
  drr->nsec3param = dns_nsec3param_new();
  drr->nsec3param->hash_algorithm = wire->hash_algorithm;
  drr->nsec3param->flags = wire->flags;
  drr->nsec3param->iterations = ntohs(wire->iterations);

  if (1 > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d", 1,
              (int) (size - pos));
    return -3;
  }

  uint8_t salt_length = *ptr;
  ptr += 1;
  pos = (ptr - data);

  if (salt_length > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d",
              (int) salt_length, (int) (size - pos));
    return -4;
  }
  drr->nsec3param->salt = tor_memdup(ptr, salt_length);
  drr->nsec3param->salt_length = salt_length;
  ptr += salt_length;

  log_debug(LD_GENERAL, "decoded: %s", dns_nsec3param_str(drr->nsec3param));

  return 0;
}

//
// Resource Record - URI

/** Encode the given URI record in <b>drr</b> to wire-format. */
int
dns_encode_uri(dns_rr_t *drr)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  // LCOV_EXCL_STOP

  buf_t *stash = buf_new();
  int ret = 0;

  if (!drr->uri) {
    log_debug(LD_GENERAL, "missing rdata");
    ret = -1;
    goto cleanup;
  }
  log_debug(LD_GENERAL, "encode: %s", dns_uri_str(drr->uri));

  struct dns_uri_wireformat_s wire;
  wire.priority = htons(drr->uri->priority);
  wire.weight = htons(drr->uri->weight);

  buf_add(stash, (const char *) &wire, sizeof(struct dns_uri_wireformat_s));
  buf_add_string(stash, (const char *) drr->uri->target);

  size_t sz_out = 0;
  tor_free(drr->rdata);
  drr->rdata = (uint8_t *) buf_extract(stash, &sz_out);
  drr->rdlength = (uint16_t) sz_out;

  log_debug(LD_GENERAL, "encoded: %s",
            hex_str((const char *) drr->rdata, drr->rdlength));

 cleanup:
  buf_free(stash);
  return ret;
}

/** Decode wire-format data and interpret it as URI record. */
int
dns_decode_uri(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
               const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  tor_assert(ptr);
  tor_assert(data);
  // LCOV_EXCL_STOP

  size_t pos = (ptr - data);
  if (pos > size) {
    log_debug(LD_GENERAL, "no data left");
    return -1;
  }
  log_debug(LD_GENERAL, "decode: %s", hex_str((const char *) ptr, size - pos));

  size_t uri_len = sizeof(struct dns_uri_wireformat_s);
  if (uri_len > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d", (int) uri_len,
              (int) (size - pos));
    return -2;
  }

  struct dns_uri_wireformat_s *wire =
    (struct dns_uri_wireformat_s *) ptr;
  ptr += uri_len;

  dns_uri_free(drr->uri);
  drr->uri = dns_uri_new();
  drr->uri->priority = ntohs(wire->priority);
  drr->uri->weight = ntohs(wire->weight);

  size_t target_len = size - (ptr - data);
  drr->uri->target = tor_memdup_nulterm(ptr, target_len);

  log_debug(LD_GENERAL, "decoded: %s", dns_uri_str(drr->uri));

  return 0;
}

//
// Resource Record

/** Pack the given RR in <b>drr</b> to wire-format. */
int
dns_pack_rr(buf_t *buf, const dns_rr_t *drr)
{
  // LCOV_EXCL_START
  tor_assert(buf);
  tor_assert(drr);
  // LCOV_EXCL_STOP

  buf_t *stash = buf_new();
  char *res = NULL;
  size_t res_len = 0;

  if (!drr->rrtype) {
    log_debug(LD_GENERAL, "missing rr type");
    res_len = -1;
    goto cleanup;
  }
  log_debug(LD_GENERAL, "pack: %s", dns_rr_str(drr));

  if (dns_encode_rr_rdata((dns_rr_t *) drr) < 0) {
    log_debug(LD_GENERAL, "failed encoding rdata");
    res_len = -2;
    goto cleanup;
  }

  if (dns_pack_name(stash, drr->name) < 0) {
    log_debug(LD_GENERAL, "failed packing name");
    res_len = -3;
    goto cleanup;
  }

  struct dns_rr_wireformat_s wire;
  wire.rrtype = htons(drr->rrtype->value);
  wire.rrclass = htons(drr->rrclass);
  wire.ttl = htonl(drr->ttl);
  wire.rdlength = htons(drr->rdlength);

  buf_add(stash, (const char *)&wire,
          sizeof(struct dns_rr_wireformat_s));
  buf_add(stash, (const char *)drr->rdata, drr->rdlength);

  res = buf_extract(stash, &res_len);
  buf_add(buf, (const char *) res, res_len);
  log_debug(LD_GENERAL, "packed (%d): %s", (int) res_len,
            hex_str((const char *) res, res_len));

 cleanup:
  buf_free(stash);
  tor_free(res);
  return (int) res_len;
}

/** Encode RR rdata to wire-format. */
int
dns_encode_rr_rdata(dns_rr_t *drr)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  tor_assert(drr->rrtype);
  // LCOV_EXCL_STOP

  switch (drr->rrtype->value) {
    case DNS_TYPE_A:
      return dns_encode_a(drr);
    case DNS_TYPE_NS:
      return dns_encode_ns(drr);
    case DNS_TYPE_CNAME:
      return dns_encode_cname(drr);
    case DNS_TYPE_SOA:
      return dns_encode_soa(drr);
    case DNS_TYPE_PTR:
      return dns_encode_ptr(drr);
    case DNS_TYPE_MX:
      return dns_encode_mx(drr);
    case DNS_TYPE_KEY:
      return dns_encode_key(drr);
    case DNS_TYPE_AAAA:
      return dns_encode_aaaa(drr);
    case DNS_TYPE_DS:
      return dns_encode_ds(drr);
    case DNS_TYPE_RRSIG:
      return dns_encode_rrsig(drr);
    case DNS_TYPE_NSEC:
      return dns_encode_nsec(drr);
    case DNS_TYPE_DNSKEY:
      return dns_encode_dnskey(drr);
    case DNS_TYPE_NSEC3:
      return dns_encode_nsec3(drr);
    case DNS_TYPE_NSEC3PARAM:
      return dns_encode_nsec3param(drr);
    case DNS_TYPE_URI:
      return dns_encode_uri(drr);
    default:
      log_debug(LD_GENERAL, "dns encode rdata: %s not implemented",
                drr->rrtype->name);
      return 0;
  }
}

/** Consume wire-format data and interpret it as RR. */
int
dns_consume_rr(dns_rr_t *drr, uint8_t **ptr, const uint8_t *data,
               const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  tor_assert(ptr);
  tor_assert(data);
  // LCOV_EXCL_STOP

  size_t pos = (*ptr - data);
  int consumed = 0;

  if (pos > size) {
    log_debug(LD_GENERAL, "no data left");
    return -1;
  }
  log_debug(LD_GENERAL, "consume: %s",
            hex_str((const char *) *ptr, size - pos));

  dns_name_free(drr->name);
  drr->name = dns_name_new();

  consumed = dns_consume_name(drr->name, ptr, data, size);
  if (consumed < 0) {
    log_debug(LD_GENERAL, "failed consuming name");
    return -2;
  }

  pos = (*ptr - data);
  size_t rr_len = sizeof(struct dns_rr_wireformat_s);
  if (rr_len > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d", (int) rr_len,
              (int) (size - pos));
    return -3;
  }

  struct dns_rr_wireformat_s *wire =
    (struct dns_rr_wireformat_s *) *ptr;
  consumed += rr_len;
  *ptr += rr_len;

  drr->rrtype = dns_type_of(ntohs(wire->rrtype));
  drr->rrclass = ntohs(wire->rrclass);
  drr->ttl = ntohl(wire->ttl);
  drr->rdlength = ntohs(wire->rdlength);

  pos = (*ptr - data);
  if (drr->rdlength > size - pos) {
    log_debug(LD_GENERAL, "invalid length: wanted %d, got %d",
              (int) drr->rdlength, (int) (size - pos));
    return -4;
  }

  uint8_t *rdata_ptr = *ptr;
  drr->rdata = tor_memdup(*ptr, drr->rdlength);
  consumed += drr->rdlength;
  *ptr += drr->rdlength;

  if (dns_decode_rr_rdata(drr, rdata_ptr, data, pos + drr->rdlength) < 0) {
    log_debug(LD_GENERAL, "failed decoding rdata");
    return -5;
  }

  log_debug(LD_GENERAL, "consumed (%d): %s", consumed, dns_rr_str(drr));
  return consumed;
}

/** Decode wire-format data and interpret it as RR rdata. */
int
dns_decode_rr_rdata(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                    const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  tor_assert(drr->rrtype);
  // LCOV_EXCL_STOP

  switch (drr->rrtype->value) {
    case DNS_TYPE_A:
      return dns_decode_a(drr, ptr, data, size);
    case DNS_TYPE_NS:
      return dns_decode_ns(drr, ptr, data, size);
    case DNS_TYPE_CNAME:
      return dns_decode_cname(drr, ptr, data, size);
    case DNS_TYPE_SOA:
      return dns_decode_soa(drr, ptr, data, size);
    case DNS_TYPE_PTR:
      return dns_decode_ptr(drr, ptr, data, size);
    case DNS_TYPE_MX:
      return dns_decode_mx(drr, ptr, data, size);
    case DNS_TYPE_KEY:
      return dns_decode_key(drr, ptr, data, size);
    case DNS_TYPE_AAAA:
      return dns_decode_aaaa(drr, ptr, data, size);
    case DNS_TYPE_DS:
      return dns_decode_ds(drr, ptr, data, size);
    case DNS_TYPE_RRSIG:
      return dns_decode_rrsig(drr, ptr, data, size);
    case DNS_TYPE_NSEC:
      return dns_decode_nsec(drr, ptr, data, size);
    case DNS_TYPE_DNSKEY:
      return dns_decode_dnskey(drr, ptr, data, size);
    case DNS_TYPE_NSEC3:
      return dns_decode_nsec3(drr, ptr, data, size);
    case DNS_TYPE_NSEC3PARAM:
      return dns_decode_nsec3param(drr, ptr, data, size);
    case DNS_TYPE_URI:
      return dns_decode_uri(drr, ptr, data, size);
    default:
      log_debug(LD_GENERAL, "dns decode rdata: %s not implemented",
                drr->rrtype->name);
      return 0;
  }
}

//
// Message

/** Encode the given message <b>dm</b> to wire-format when using TCP sockets.*/
int
dns_encode_message_tcp(buf_t *buf, const dns_message_t *dm)
{
  // LCOV_EXCL_START
  tor_assert(buf);
  tor_assert(dm);
  // LCOV_EXCL_STOP

  uint8_t *data = NULL;
  size_t size = 0;

  int ret = 0;
  buf_t *stash = buf_new();
  ret = dns_encode_message_udp(stash, dm);

  if (ret >= 0) {
    data = (uint8_t *) buf_extract(stash, &size);

    uint16_t bytes = htons((uint16_t) size);
    buf_add(buf, (const char *) &bytes, 2);
    buf_add(buf, (const char *) data, size);

    tor_free(data);
  }

  buf_free(stash);
  return ret;
}

/** Encode the given message <b>dm</b> to wire-format when using UDP sockets.*/
int
dns_encode_message_udp(buf_t *buf, const dns_message_t *dm)
{
  // LCOV_EXCL_START
  tor_assert(buf);
  tor_assert(dm);
  // LCOV_EXCL_STOP

  buf_t *stash = buf_new();
  char *res = NULL;
  size_t res_len = 0;

  log_debug(LD_GENERAL, "pack:\n%s", dns_message_str(dm));

  if (dns_pack_header(stash, dm->header) < 0) {
    log_debug(LD_GENERAL, "failed packing header");
    res_len = -1;
    goto cleanup;
  }

  SMARTLIST_FOREACH_BEGIN(dm->question_list, dns_question_t *, dq) {
    if (dns_pack_question(stash, dq) < 0) {
      log_debug(LD_GENERAL, "failed packing question");
      res_len = -2;
      goto cleanup;
    }
  } SMARTLIST_FOREACH_END(dq);

  SMARTLIST_FOREACH_BEGIN(dm->answer_list, dns_rr_t *, dan) {
    if (dns_pack_rr(stash, dan) < 0) {
      log_debug(LD_GENERAL, "failed packing answer");
      res_len = -3;
      goto cleanup;
    }
  } SMARTLIST_FOREACH_END(dan);

  SMARTLIST_FOREACH_BEGIN(dm->name_server_list, dns_rr_t *, dns) {
    if (dns_pack_rr(stash, dns) < 0) {
      log_debug(LD_GENERAL, "failed packing name server");
      res_len = -4;
      goto cleanup;
    }
  } SMARTLIST_FOREACH_END(dns);

  SMARTLIST_FOREACH_BEGIN(dm->additional_record_list, dns_rr_t *, drr) {
    if (dns_pack_rr(stash, drr) < 0) {
      log_debug(LD_GENERAL, "failed packing additional record");
      res_len = -5;
      goto cleanup;
    }
  } SMARTLIST_FOREACH_END(drr);

  res = buf_extract(stash, &res_len);
  buf_add(buf, (const char *) res, res_len);
  log_debug(LD_GENERAL, "packed (%d): %s", (int) res_len,
            hex_str((const char *) res, res_len));

 cleanup:
  buf_free(stash);
  tor_free(res);
  return (int) res_len;
}

/** Decode the given message <b>dm</b> from wire-format when using TCP sockets.
 */
int
dns_decode_message_tcp(dns_message_t *dm, buf_t *buf)
{
  // LCOV_EXCL_START
  tor_assert(dm);
  tor_assert(buf);
  // LCOV_EXCL_STOP

  const uint8_t *data = NULL;
  size_t size = 0;

  buf_pullup(buf, 2, (const char **) &data, &size);

  if (size < 2) {
    log_debug(LD_GENERAL, "there is no message waiting");
    return -1;
  }

  size_t bytes = ntohs(*((uint16_t *) data));
  if (bytes != size - 2) {
    log_debug(LD_GENERAL, "invalid message size: wanted %d, got %d",
              (int) bytes, (int) size - 2);
    return -2;
  }

  buf_drain(buf, 2);
  return dns_decode_message_udp(dm, buf);
}

/** Decode the given message <b>dm</b> from wire-format when using UDP sockets.
 */
int
dns_decode_message_udp(dns_message_t *dm, buf_t *buf)
{
  // LCOV_EXCL_START
  tor_assert(dm);
  tor_assert(buf);
  // LCOV_EXCL_STOP

  int consumed = 0;
  size_t size = 0;
  uint8_t *data = (uint8_t *) buf_extract(buf, &size);
  uint8_t *ptr = (uint8_t *) data;
  log_debug(LD_GENERAL, "consume: %s", hex_str((const char *) ptr, size));

  consumed = dns_consume_header(dm->header, &ptr, data, size);
  if (consumed < 0) {
    log_debug(LD_GENERAL, "failed consuming header");
    consumed = -1;
    goto cleanup;
  }

  SMARTLIST_FOREACH(dm->question_list, dns_question_t *, dq,
                    dns_question_free(dq));
  SMARTLIST_FOREACH(dm->answer_list, dns_rr_t *, dan, dns_rr_free(dan));
  SMARTLIST_FOREACH(dm->name_server_list, dns_rr_t *, dns, dns_rr_free(dns));
  SMARTLIST_FOREACH(dm->additional_record_list, dns_rr_t *, dar,
                    dns_rr_free(dar));

  smartlist_clear(dm->question_list);
  smartlist_clear(dm->answer_list);
  smartlist_clear(dm->name_server_list);
  smartlist_clear(dm->additional_record_list);

  for (uint16_t i = 0; i < dm->header->qdcount; i++) {
    dns_question_t *dq = dns_question_new();
    smartlist_add(dm->question_list, dq);

    int question_len = dns_consume_question(dq, &ptr, data, size);
    consumed += question_len;

    if (question_len < 0) {
      log_debug(LD_GENERAL, "failed consuming question");
      consumed = -2;
      goto cleanup;
    }
  }

  for (uint16_t i = 0; i < dm->header->ancount; i++) {
    dns_rr_t *drr = dns_rr_new();
    smartlist_add(dm->answer_list, drr);

    int rr_len = dns_consume_rr(drr, &ptr, data, size);
    consumed += rr_len;

    if (rr_len < 0) {
      log_debug(LD_GENERAL, "failed consuming answer");
      consumed = -3;
      goto cleanup;
    }
  }

  for (uint16_t i = 0; i < dm->header->nscount; i++) {
    dns_rr_t *drr = dns_rr_new();
    smartlist_add(dm->name_server_list, drr);

    int rr_len = dns_consume_rr(drr, &ptr, data, size);
    consumed += rr_len;

    if (rr_len < 0) {
      log_debug(LD_GENERAL, "failed consuming name server");
      consumed = -4;
      goto cleanup;
    }
  }

  for (uint16_t i = 0; i < dm->header->arcount; i++) {
    dns_rr_t *dar = dns_rr_new();
    smartlist_add(dm->additional_record_list, dar);

    int rr_len = dns_consume_rr(dar, &ptr, data, size);
    consumed += rr_len;

    if (rr_len < 0) {
      log_debug(LD_GENERAL, "failed consuming additional record");
      consumed = -5;
      goto cleanup;
    }
  }

  if (consumed != (int) size) {
    log_debug(LD_GENERAL, "failed decoding message: wanted %d, got %d",
              (int) size, consumed);
    consumed = -6;
    goto cleanup;
  }
  log_debug(LD_GENERAL, "decoded:\n%s", dns_message_str(dm));

 cleanup:
  buf_drain(buf, size);
  tor_free(data);
  return consumed;
}

//
// Utilities

/** Encode signed data to wire-format. */
int
dns_encode_signed_data(uint8_t **data, size_t *size, const dns_rr_t *crrsig,
                       const smartlist_t *crrset)
{
  // LCOV_EXCL_START
  tor_assert(data);
  tor_assert(size);
  tor_assert(crrsig);
  tor_assert(crrset);
  // LCOV_EXCL_STOP

  tor_free(*data);
  *size = 0;

  int ret = 0;
  buf_t *buf = buf_new();
  ret = dns_encode_signed_data_to_buf(buf, crrsig, crrset);

  if (ret >= 0) {
    *data = (uint8_t *) buf_extract(buf, size);
  }

  buf_free(buf);
  return ret;
}

/** Encode signed data to wire-format. */
int
dns_encode_signed_data_to_buf(buf_t *buf, const dns_rr_t *crrsig,
                              const smartlist_t *crrset)
{
  // LCOV_EXCL_START
  tor_assert(buf);
  tor_assert(crrsig);
  tor_assert(crrset);
  // LCOV_EXCL_STOP

  buf_t *stash = buf_new();
  char *res = NULL;
  size_t res_len = 0;

  log_debug(LD_GENERAL, "pack sig: %s", dns_rr_str(crrsig));

  buf_add(stash, (const char *) crrsig->rdata, crrsig->rdlength);

  SMARTLIST_FOREACH_BEGIN(crrset, dns_rr_t *, crr) {
    log_debug(LD_GENERAL, "pack rr: %s", dns_rr_str(crr));
    if (dns_pack_rr(stash, crr) < 0) {
      log_debug(LD_GENERAL, "failed packing rr");
      res_len = -1;
      goto cleanup;
    }
  } SMARTLIST_FOREACH_END(crr);

  res = buf_extract(stash, &res_len);
  buf_add(buf, (const char *) res, res_len);
  log_debug(LD_GENERAL, "packed (%d): %s", (int) res_len,
            hex_str((const char *) res, res_len));

 cleanup:
  buf_free(stash);
  tor_free(res);
  return (int) res_len;
}

/** Get canonical form of name. First transform the name to meet the following
 * criterions: it is fully expanded, it contains only lowercase letters, and no
 * wildcard expansion is applied.
 * Then the name is converted to wire-format. */
uint8_t *
dns_encode_canonical_name(const dns_name_t *owner_name, size_t *sz_out)
{
  // LCOV_EXCL_START
  tor_assert(owner_name);
  // LCOV_EXCL_STOP

  *sz_out = 0;
  uint8_t *data = NULL;
  buf_t *buf = buf_new();

  dns_name_t *name = dns_name_dup(owner_name);
  tor_strlower(name->value);

  if (dns_pack_name(buf, name) < 0) {
    log_debug(LD_GENERAL, "failed packing name");
    data = NULL;
    goto cleanup;
  }

  data = (uint8_t *) buf_extract(buf, sz_out);

 cleanup:
  dns_name_free(name);
  buf_free(buf);
  return data;
}

/** Get canonical form of resource record. The record name is converted to
 * lowercase, additionally all names within record types are converted to
 * lowercase as well. For RRsig records the signature is removed. */
dns_rr_t *
dns_encode_canonical_rr(const dns_rr_t *drr, const dns_name_t *name,
                        const uint32_t original_ttl)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  tor_assert(drr->rrtype);
  tor_assert(name);
  // LCOV_EXCL_STOP

  log_debug(LD_GENERAL, "canonicalize: %s", dns_rr_str(drr));

  dns_rr_t *dcrr = dns_rr_dup(drr);
  dns_name_free(dcrr->name);
  dcrr->name = dns_name_dup(name);
  tor_strlower(dcrr->name->value);
  dcrr->ttl = original_ttl;

  switch (dcrr->rrtype->value) {
    case DNS_TYPE_NS:
      if (dcrr->ns && dcrr->ns->value) {
        tor_strlower(dcrr->ns->value);
      }
      break;
    case DNS_TYPE_MD:
    case DNS_TYPE_MF:
      log_debug(LD_GENERAL, "dns canonical encode rdata: %s not implemented",
                dcrr->rrtype->name);
      break;
    case DNS_TYPE_CNAME:
      if (dcrr->cname && dcrr->cname->value) {
        tor_strlower(dcrr->cname->value);
      }
      break;
    case DNS_TYPE_SOA:
      if (dcrr->soa->mname && dcrr->soa->mname->value) {
        tor_strlower(dcrr->soa->mname->value);
      }
      if (dcrr->soa->rname && dcrr->soa->rname->value) {
        tor_strlower(dcrr->soa->rname->value);
      }
      break;
    case DNS_TYPE_MB:
    case DNS_TYPE_MG:
    case DNS_TYPE_MR:
      log_debug(LD_GENERAL, "dns canonical encode rdata: %s not implemented",
                dcrr->rrtype->name);
      break;
    case DNS_TYPE_PTR:
      if (dcrr->ptr && dcrr->ptr->value) {
        tor_strlower(dcrr->ptr->value);
      }
      break;
    case DNS_TYPE_HINFO:
    case DNS_TYPE_MINFO:
      log_debug(LD_GENERAL, "dns canonical encode rdata: %s not implemented",
                dcrr->rrtype->name);
      break;
    case DNS_TYPE_MX:
      if (dcrr->mx->exchange && dcrr->mx->exchange->value) {
        tor_strlower(dcrr->mx->exchange->value);
      }
      break;
    case DNS_TYPE_RP:
    case DNS_TYPE_AFSDB:
    case DNS_TYPE_RT:
    case DNS_TYPE_SIG:
    case DNS_TYPE_PX:
    case DNS_TYPE_NXT:
    case DNS_TYPE_NAPTR:
    case DNS_TYPE_KX:
    case DNS_TYPE_SRV:
    case DNS_TYPE_A6:
    case DNS_TYPE_DNAME:
      log_debug(LD_GENERAL, "dns canonical encode rdata: %s not implemented",
                dcrr->rrtype->name);
      break;
    case DNS_TYPE_RRSIG:
      if (dcrr->rrsig && dcrr->rrsig->signer_name &&
          dcrr->rrsig->signer_name->value) {
        tor_strlower(dcrr->rrsig->signer_name->value);
      }
      if (dcrr->rrsig && dcrr->rrsig->signature &&
          dcrr->rrsig->signature_len > 0) {
        tor_free(dcrr->rrsig->signature);
        dcrr->rrsig->signature = NULL;
        dcrr->rrsig->signature_len = 0;
      }
      break;
    case DNS_TYPE_NSEC:
      if (dcrr->nsec->next_domain_name &&
          dcrr->nsec->next_domain_name->value) {
        tor_strlower(dcrr->nsec->next_domain_name->value);
      }
      break;
    default:
      log_debug(LD_GENERAL, "unknown type: %s", dcrr->rrtype->name);
  }
  if (dns_encode_rr_rdata(dcrr) < 0) {
    log_debug(LD_GENERAL, "failed encoding rdata");
  }
  return dcrr;
}

/** Get data from DNSKEY that is used for verifying the DNSSEC digest. */
uint8_t *
dns_encode_digest_data(const dns_rr_t *drr, size_t *sz_out)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  // LCOV_EXCL_STOP

  *sz_out = 0;
  uint8_t *data = NULL;
  buf_t *buf = buf_new();

  dns_name_t *name = dns_name_dup(drr->name);
  tor_strlower(name->value);

  if (dns_pack_name(buf, name) < 0) {
    log_debug(LD_GENERAL, "failed packing name");
    goto cleanup;
  }

  buf_add(buf, (const char *) drr->rdata, drr->rdlength);
  data = (uint8_t *) buf_extract(buf, sz_out);

 cleanup:
  dns_name_free(name);
  buf_free(buf);
  return data;
}

/** Calculate the key tag of the given DNSKEY in <b>drr</b>. */
uint16_t
dns_encode_key_tag(const dns_rr_t *drr)
{
  uint32_t ac = 0;

  for (uint16_t i = 0; i < drr->rdlength; ++i) {
    ac += (i & 1) ? drr->rdata[i] : drr->rdata[i] << 8;
  }

  ac += (ac >> 16) & 0xFFFF;
  return (uint16_t) (ac & 0xFFFF);
}

/** Pack the given DNS <b>name</b> to wire-format. */
int
dns_pack_name(buf_t *buf, const dns_name_t *name)
{
  // LCOV_EXCL_START
  tor_assert(buf);
  // LCOV_EXCL_STOP

  buf_t *stash = buf_new();
  char *res = NULL;
  size_t res_len = 0;

  log_debug(LD_GENERAL, "pack: %s", dns_name_str(name));

  if (name && name->value && name->length > 1) {
    char *ptr = name->value;
    for (uint8_t i = 0; i < name->length; i++) {
      if (i == name->length - 1 || name->value[i + 1] == '.') {
        int label_len = (int) (&(name->value[i + 1]) - ptr);
        if (label_len > 0) {
          if (label_len > DNS_MAX_LABEL_LEN) {
            log_debug(LD_GENERAL, "label too long: len %d, max: %d", label_len,
                      DNS_MAX_LABEL_LEN);
            res_len = -1;
            goto cleanup;
          }

          buf_add_printf(stash, "%c", (char) label_len);
          buf_add(stash, ptr, label_len);
          ptr = &(name->value[i + 2]);
        }
      }
    }
  }

  buf_add(stash, "\0", 1);

  res = buf_extract(stash, &res_len);
  buf_add(buf, (const char *) res, res_len);
  log_debug(LD_GENERAL, "packed (%d): %s", (int) res_len,
            hex_str((const char *) res, res_len));

 cleanup:
  buf_free(stash);
  tor_free(res);
  return (int) res_len;
}

/** Consume wire-format data and interpret it as DNS name. */
int
dns_consume_name(dns_name_t *name, uint8_t **ptr, const uint8_t *data,
                 const size_t size)
{
  return dns_consume_name_impl(name, ptr, 0, data, size);
}

int
dns_consume_name_impl(dns_name_t *name, uint8_t **ptr, uint8_t recursions,
                      const uint8_t *data, const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(name);
  tor_assert(*ptr);
  tor_assert(data);
  // LCOV_EXCL_STOP

  size_t pos = (*ptr - data);
  int consumed = 0;

  buf_t *stash = buf_new();
  size_t label_len;
  dns_name_t *compr_name = dns_name_new();

  if (recursions > 10) {
    log_debug(LD_GENERAL, "too many pointers, maybe there's a loop");
    consumed = -1;
    goto cleanup;
  }

  if (pos > size) {
    log_debug(LD_GENERAL, "no data left");
    consumed = -2;
    goto cleanup;
  }
  log_debug(LD_GENERAL, "consume: %s",
            hex_str((const char *) *ptr, size - pos));

  bool done = false;
  while (!done) {
    pos = (*ptr - data);
    if (1 > size - pos) {
      log_debug(LD_GENERAL, "invalid length: wanted %d, got %d", 1,
                (int) (size - pos));
      consumed = -3;
      goto cleanup;
    }

    label_len = **ptr;
    consumed += 1;
    *ptr += 1;

    if (label_len == 0x00) {
      buf_add_string(stash, ".");
      done = true;
    } else if ((label_len & 0xc0) == 0xc0) {

      pos = (*ptr - data);
      if (1 > size - pos) {
        log_debug(LD_GENERAL, "invalid length: wanted %d, got %d", 1,
                  (int) (size - pos));
        consumed = -4;
        goto cleanup;
      }

      uint16_t name_pos = ((label_len & DNS_MAX_LABEL_LEN) << 8) + **ptr;
      consumed += 1;
      *ptr += 1;

      if (name_pos > size) {
        log_debug(LD_GENERAL, "invalid name position: pos %d, max %d",
                  (int) name_pos, (int) size);
        consumed = -5;
        goto cleanup;
      }

      uint8_t *compr_ptr = (uint8_t *) &data[name_pos];
      if (dns_consume_name_impl(compr_name, &compr_ptr, recursions + 1, data,
                                size) < 0) {
        log_debug(LD_GENERAL, "invalid name compression");
        consumed = -6;
        goto cleanup;
      }

      if (buf_datalen(stash) > 0) {
        buf_add_string(stash, ".");
      }
      buf_add_string(stash, compr_name->value);

      done = true;
    } else {
      pos = (*ptr - data);
      if (label_len > size - pos) {
        log_debug(LD_GENERAL, "invalid length: wanted %d, got %d",
                  (int) label_len, (int) (size - pos));
        consumed = -7;
        goto cleanup;
      }

      if (buf_datalen(stash) > 0) {
        buf_add_string(stash, ".");
      }

      buf_add(stash, (const char *) *ptr, label_len);
      consumed += label_len;
      *ptr += label_len;
    }
  }

  size_t sz_out = 0;
  tor_free(name->value);
  name->value = buf_extract(stash, &sz_out);
  name->length = (uint8_t) sz_out;

  log_debug(LD_GENERAL, "consumed (%d): %s", consumed, name->value);

 cleanup:
  buf_free(stash);
  dns_name_free(compr_name);
  return consumed;
}

/** Comparator for sorting DNS types in ascending order. */
static int
dns_comperator_for_sorting_types_in_ascending_order(const void **a_,
                                                    const void **b_)
{
  const dns_type_t *a = *a_,
                   *b = *b_;
  return a->value - b->value;
}

/** Pack the given list of DNS <b>types</b> to wire-format. */
int
dns_pack_type_bitmaps(buf_t *buf, smartlist_t *types)
{
  // LCOV_EXCL_START
  tor_assert(buf);
  tor_assert(types);
  // LCOV_EXCL_STOP

  buf_t *stash = buf_new();
  uint8_t *bitmap = tor_malloc_zero(DNS_MAX_TYPE_BITMAP_LEN);
  char *res = NULL;
  size_t res_len = 0;

  log_debug(LD_GENERAL, "pack: %s", dns_types_str(types));

  if (smartlist_len(types) > 0) {
    uint8_t active_window = 0;
    uint8_t window  = 0;
    uint8_t subtype = 0;

    smartlist_sort(types, dns_comperator_for_sorting_types_in_ascending_order);

    SMARTLIST_FOREACH_BEGIN(types, dns_type_t *, type) {
      window = type->value >> 8;
      subtype = type->value & 0xff;

      if (active_window != window) {
        dns_buf_add_type_bitmap_field(stash, active_window, bitmap);
        active_window = window;
        memset(bitmap, 0, DNS_MAX_TYPE_BITMAP_LEN);
      }

      bitmap[subtype / 8] |= (0x80 >> (subtype % 8));
    } SMARTLIST_FOREACH_END(type);

    dns_buf_add_type_bitmap_field(stash, active_window, bitmap);
  }

  res = buf_extract(stash, &res_len);
  buf_add(buf, (const char *) res, res_len);
  log_debug(LD_GENERAL, "packed (%d): %s", (int) res_len,
            hex_str((const char *) res, res_len));

  buf_free(stash);
  tor_free(bitmap);
  tor_free(res);
  return (int) res_len;
}

/** Write type bitmap to buffer. */
int
dns_buf_add_type_bitmap_field(buf_t *buf, const uint8_t window,
                              const uint8_t *bitmap)
{
  // LCOV_EXCL_START
  tor_assert(buf);
  tor_assert(bitmap);
  // LCOV_EXCL_STOP

  uint8_t len = 0;
  for (uint8_t i = 0; i < DNS_MAX_TYPE_BITMAP_LEN; i++) {
    if (bitmap[i] && (i + 1) > len) {
      len = (i + 1);
    }
  }

  char *field = tor_malloc_zero(len + 2);
  field[0] = window;
  field[1] = len;

  for (uint8_t i = 0; i < len; i++) {
    field[i + 2] = bitmap[i];
  }

  buf_add(buf, field, len + 2);
  tor_free(field);

  return len + 2;
}

/** Consume wire-format data and interpret it as DNS types. */
int
dns_consume_type_bitmaps(smartlist_t *types, uint8_t **ptr,
                         const uint8_t *data, const size_t size)
{
  // LCOV_EXCL_START
  tor_assert(types);
  tor_assert(*ptr);
  tor_assert(data);
  // LCOV_EXCL_STOP

  size_t pos = (*ptr - data);
  int consumed = 0;

  if (pos > size) {
    log_debug(LD_GENERAL, "no data left");
    return -1;
  }
  log_debug(LD_GENERAL, "consume: %s",
            hex_str((const char *) *ptr, size - pos));

  smartlist_clear(types);

  uint8_t window = 0;
  uint8_t bitmap_len = 0;

  bool done = (pos == size);
  while (!done) {
    if (2 > size - pos) {
      log_debug(LD_GENERAL, "invalid length: wanted %d, got %d", 2,
                (int) (size - pos));
      return -2;
    }

    window = (*ptr)[0];
    bitmap_len = (*ptr)[1];
    consumed += 2;
    *ptr += 2;

    pos = (*ptr - data);
    if (bitmap_len > size - pos) {
      log_debug(LD_GENERAL, "invalid length: wanted %d, got %d",
                (int) bitmap_len, (int) (size - pos));
      return -3;
    }

    for (uint8_t byte = 0; byte < bitmap_len; byte++) {
      for (uint8_t bit = 0; bit < 8; bit++) {
        if ((*ptr)[byte] & (0x80 >> bit)) {
          uint16_t value = (window * 256) + (byte * 8) + bit;
          dns_type_t *type = dns_type_of(value);
          smartlist_add(types, type);
        }
      }
    }

    consumed += bitmap_len;
    *ptr += bitmap_len;

    pos = (*ptr - data);
    done = (size - pos) == 0;
  }

  log_debug(LD_GENERAL, "consumed (%d): %s", consumed, dns_types_str(types));
  return consumed;
}
