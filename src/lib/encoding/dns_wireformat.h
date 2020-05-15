/* Copyright (c) 2019 Christian Hofer.
 * Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file dns_wireformat.h
 * \brief Header file for dns_wireformat.c.
 **/

#ifndef TOR_DNS_WIREFORMAT_H
#define TOR_DNS_WIREFORMAT_H

#include "lib/buf/buffers.h"
#include "lib/cc/torint.h"
#include "lib/container/dns_message_st.h"
#include "lib/smartlist_core/smartlist_core.h"

int dns_encode_message_tcp(buf_t *buf, const dns_message_t *dm);
int dns_encode_message_udp(buf_t *buf, const dns_message_t *dm);

int dns_decode_message_tcp(dns_message_t *dm, buf_t *buf);
int dns_decode_message_udp(dns_message_t *dm, buf_t *buf);

int dns_encode_signed_data(uint8_t **data, size_t *size,
                           const dns_rr_t *crrsig, const smartlist_t *crrset);
int dns_encode_signed_data_to_buf(buf_t *buf, const dns_rr_t *crrsig,
                                  const smartlist_t *crrset);

uint8_t *dns_encode_canonical_name(const dns_name_t *owner_name,
                                   size_t *sz_out);
dns_rr_t *dns_encode_canonical_rr(const dns_rr_t *drr, const dns_name_t *name,
                                  const uint32_t original_ttl);
uint8_t *dns_encode_digest_data(const dns_rr_t *drr, size_t *sz_out);
uint16_t dns_encode_key_tag(const dns_rr_t *drr);

#ifdef DNS_WIREFORMAT_PRIVATE

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define IS_LITTLE_ENDIAN 1
#elif defined(BYTE_ORDER) && defined(ORDER_LITTLE_ENDIAN) &&     \
      BYTE_ORDER == __ORDER_LITTLE_ENDIAN
#  define IS_LITTLE_ENDIAN 1
#elif defined(_WIN32)
#  define IS_LITTLE_ENDIAN 1
#elif defined(__APPLE__)
#  include <libkern/OSByteOrder.h>
#  define BSWAP64(x) OSSwapLittleToHostInt64(x)
#elif defined(sun) || defined(__sun)
#  include <sys/byteorder.h>
#  ifndef _BIG_ENDIAN
#    define IS_LITTLE_ENDIAN
#  endif
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(OpenBSD)
# include <sys/endian.h>
# if defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && \
     __BYTE_ORDER == __LITTLE_ENDIAN
#   define IS_LITTLE_ENDIAN
# endif
#else
# include <endian.h>
# if defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && \
     __BYTE_ORDER == __LITTLE_ENDIAN
#   define IS_LITTLE_ENDIAN
# endif
#endif

#define DNS_MAX_LABEL_LEN 63

int dns_pack_name(buf_t *buf, const dns_name_t *name);
int dns_consume_name(dns_name_t *name, uint8_t **ptr, const uint8_t *data,
                     const size_t size);
int dns_consume_name_impl(dns_name_t *name, uint8_t **ptr, uint8_t recursions,
                          const uint8_t *data, const size_t size);

#define DNS_MAX_TYPE_BITMAP_LEN 32

int dns_pack_type_bitmaps(buf_t *buf, smartlist_t *types);
int dns_buf_add_type_bitmap_field(buf_t *buf, const uint8_t window,
                                  const uint8_t *bitmap);
int dns_consume_type_bitmaps(smartlist_t *types, uint8_t **ptr,
                             const uint8_t *data, const size_t size);

//
// Header

struct dns_header_wireformat_s {
  uint16_t id      : 16;
# ifdef IS_LITTLE_ENDIAN
  uint8_t rd        : 1;
  uint8_t tc        : 1;
  uint8_t aa        : 1;
  uint8_t opcode    : 4;
  uint8_t qr        : 1;
  uint8_t rcode     : 4;
  uint8_t cd        : 1;
  uint8_t ad        : 1;
  uint8_t z         : 1;
  uint8_t ra        : 1;
# else
  uint8_t qr        : 1;
  uint8_t opcode    : 4;
  uint8_t aa        : 1;
  uint8_t tc        : 1;
  uint8_t rd        : 1;
  uint8_t ra        : 1;
  uint8_t z         : 1;
  uint8_t ad        : 1;
  uint8_t cd        : 1;
  uint8_t rcode     : 4;
# endif
  uint16_t qdcount : 16;
  uint16_t ancount : 16;
  uint16_t nscount : 16;
  uint16_t arcount : 16;
};

int dns_pack_header(buf_t *buf, const dns_header_t *dh);
int dns_consume_header(dns_header_t *dh, uint8_t **ptr,
                       const uint8_t *data, const size_t size);

//
// Question

struct dns_question_wireformat_s {
  uint16_t qtype  : 16;
  uint16_t qclass : 16;
};

int dns_pack_question(buf_t *buf, const dns_question_t *dq);
int dns_consume_question(dns_question_t *dq, uint8_t **ptr,
                         const uint8_t *data, const size_t size);

//
// Resource Record - A

int dns_encode_a(dns_rr_t *drr);
int dns_decode_a(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                 const size_t size);

//
// Resource Record - NS

int dns_encode_ns(dns_rr_t *drr);
int dns_decode_ns(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                  const size_t size);

//
// Resource Record - CNAME

int dns_encode_cname(dns_rr_t *drr);
int dns_decode_cname(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                     const size_t size);

//
// Resource Record - SOA

struct dns_soa_wireformat_s {
  uint32_t serial  : 32;
  uint32_t refresh : 32;
  uint32_t retry   : 32;
  uint32_t expire  : 32;
  uint32_t minimum : 32;
};

int dns_encode_soa(dns_rr_t *drr);
int dns_decode_soa(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                   const size_t size);

//
// Resource Record - PTR

int dns_encode_ptr(dns_rr_t *drr);
int dns_decode_ptr(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                   const size_t size);

//
// Resource Record - MX

struct dns_mx_wireformat_s {
  uint16_t preference : 16;
};

int dns_encode_mx(dns_rr_t *drr);
int dns_decode_mx(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                  const size_t size);

//
// Resource Record - KEY

struct dns_key_wireformat_s {
  uint16_t flags    : 16;
  uint8_t protocol  : 8;
  uint8_t algorithm : 8;
};

int dns_encode_key(dns_rr_t *drr);
int dns_decode_key(dns_rr_t *drr, uint8_t *ptr,
                   const uint8_t *data, const size_t size);

//
// Resource Record - AAAA

int dns_encode_aaaa(dns_rr_t *drr);
int dns_decode_aaaa(dns_rr_t *drr, uint8_t *ptr,
                    const uint8_t *data, const size_t size);

//
// Resource Record - DS

struct dns_ds_wireformat_s {
  uint16_t key_tag    : 16;
  uint8_t algorithm   : 8;
  uint8_t digest_type : 8;
};

int dns_encode_ds(dns_rr_t *drr);
int dns_decode_ds(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                  const size_t size);

//
// Resource Record - RRSIG

#pragma pack(2)
struct dns_rrsig_wireformat_s {
  uint16_t type_covered         : 16;
  uint8_t algorithm             : 8;
  uint8_t labels                : 8;
  uint32_t original_ttl         : 32;
  uint32_t signature_expiration : 32;
  uint32_t signature_inception  : 32;
  uint16_t key_tag              : 16;
};
#pragma pack()

int dns_encode_rrsig(dns_rr_t *drr);
int dns_decode_rrsig(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                     const size_t size);

//
// Resource Record - NSEC

int dns_encode_nsec(dns_rr_t *drr);
int dns_decode_nsec(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                    const size_t size);

//
// Resource Record - DNSKEY

struct dns_dnskey_wireformat_s {
  uint16_t flags    : 16;
  uint8_t protocol  : 8;
  uint8_t algorithm : 8;
};

int dns_encode_dnskey(dns_rr_t *drr);
int dns_decode_dnskey(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                      const size_t size);

//
// Resource Record - NSEC3

struct dns_nsec3_wireformat_s {
  uint8_t hash_algorithm : 8;
  uint8_t flags          : 8;
  uint16_t iterations    : 16;
};

int dns_encode_nsec3(dns_rr_t *drr);
int dns_decode_nsec3(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                     const size_t size);

//
// Resource Record - NSEC3PARAM

struct dns_nsec3param_wireformat_s {
  uint8_t hash_algorithm : 8;
  uint8_t flags          : 8;
  uint16_t iterations    : 16;
};

int dns_encode_nsec3param(dns_rr_t *drr);
int dns_decode_nsec3param(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                          const size_t size);

//
// Resource Record - URI

struct dns_uri_wireformat_s {
  uint16_t priority : 16;
  uint16_t weight   : 16;
};

int dns_encode_uri(dns_rr_t *drr);
int dns_decode_uri(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                   const size_t size);

//
// Resource Record

#pragma pack(2)
struct dns_rr_wireformat_s {
  uint16_t rrtype   : 16;
  uint16_t rrclass  : 16;
  uint32_t ttl      : 32;
  uint16_t rdlength : 16;
};
#pragma pack()

int dns_pack_rr(buf_t *buf, const dns_rr_t *drr);
int dns_encode_rr_rdata(dns_rr_t *drr);

int dns_consume_rr(dns_rr_t *drr, uint8_t **ptr, const uint8_t *data,
                   const size_t size);
int dns_decode_rr_rdata(dns_rr_t *drr, uint8_t *ptr, const uint8_t *data,
                        const size_t size);

#endif /* defined(DNS_WIREFORMAT_PRIVATE) */

#endif /* !defined(TOR_DNS_WIREFORMAT_H) */
