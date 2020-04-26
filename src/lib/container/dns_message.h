/* Copyright (c) 2019 Christian Hofer.
 * Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_DNS_MESSAGE_H
#define TOR_DNS_MESSAGE_H

/**
 * \file dns_message.h
 *
 * \brief Headers for dns_message.c.
 **/

#include "lib/cc/torint.h"
#include "lib/container/dns_message_st.h"
#include "lib/smartlist_core/smartlist_core.h"

//
// Name

dns_name_t *dns_name_new(void);
dns_name_t *dns_name_dup(const dns_name_t *dn);
void dns_name_free_(dns_name_t *dn);
#define dns_name_free(dn) \
  FREE_AND_NULL(dns_name_t, dns_name_free_, (dn))

void dns_name_normalize(dns_name_t *name);
int dns_name_is_part_of(const dns_name_t *needle, const dns_name_t *haystack);
int dns_name_compare(const dns_name_t *this, const dns_name_t *that);
int dns_name_present_in_smartlist(const smartlist_t *sl,
                                  const dns_name_t *name);

//
// Type

dns_type_t *dns_type_new(void);
dns_type_t *dns_type_dup(const dns_type_t *dt);
bool dns_type_is(dns_type_t *type, uint16_t value);
void dns_type_free_(dns_type_t *dt);
#define dns_type_free(dt) \
  FREE_AND_NULL(dns_type_t, dns_type_free_, (dt))

int dns_type_present_in_smartlist(const smartlist_t *sl, const int type);

//
// Header

dns_header_t *dns_header_new(void);
dns_header_t *dns_header_dup(const dns_header_t *dh);
void dns_header_free_(dns_header_t *dh);
#define dns_header_free(dh) \
  FREE_AND_NULL(dns_header_t, dns_header_free_, (dh))

//
// Question

dns_question_t *dns_question_new(void);
dns_question_t *dns_question_dup(const dns_question_t *dq);
void dns_question_free_(dns_question_t *dq);
#define dns_question_free(dq) \
  FREE_AND_NULL(dns_question_t, dns_question_free_, (dq))

//
// Resource Record - SOA

dns_soa_t *dns_soa_new(void);
dns_soa_t *dns_soa_dup(const dns_soa_t *dsoa);
void dns_soa_free_(dns_soa_t *dsoa);
#define dns_soa_free(dsoa) \
  FREE_AND_NULL(dns_soa_t, dns_soa_free_, (dsoa))

//
// Resource Record - MX

dns_mx_t *dns_mx_new(void);
dns_mx_t *dns_mx_dup(const dns_mx_t *dmx);
void dns_mx_free_(dns_mx_t *dmx);
#define dns_mx_free(dmx) \
  FREE_AND_NULL(dns_mx_t, dns_mx_free_, (dmx))

//
// Resource Record - KEY

dns_key_t *dns_key_new(void);
dns_key_t *dns_key_dup(const dns_key_t *dkey);
void dns_key_free_(dns_key_t *dkey);
#define dns_key_free(dkey) \
  FREE_AND_NULL(dns_key_t, dns_key_free_, (dkey))

//
// Resource Record - DS

dns_ds_t *dns_ds_new(void);
dns_ds_t *dns_ds_dup(const dns_ds_t *dds);
void dns_ds_free_(dns_ds_t *dds);
#define dns_ds_free(dds) \
  FREE_AND_NULL(dns_ds_t, dns_ds_free_, (dds))

//
// Resource Record - RRSIG

dns_rrsig_t *dns_rrsig_new(void);
dns_rrsig_t *dns_rrsig_dup(const dns_rrsig_t *drrsig);
void dns_rrsig_free_(dns_rrsig_t *drrsig);
#define dns_rrsig_free(drrsig) \
  FREE_AND_NULL(dns_rrsig_t, dns_rrsig_free_, (drrsig))

//
// Resource Record - NSEC

dns_nsec_t *dns_nsec_new(void);
dns_nsec_t *dns_nsec_dup(const dns_nsec_t *dnsec);
void dns_nsec_free_(dns_nsec_t *dnsec);
#define dns_nsec_free(dnsec) \
  FREE_AND_NULL(dns_nsec_t, dns_nsec_free_, (dnsec))

//
// Resource Record - DNSKEY

dns_dnskey_t *dns_dnskey_new(void);
dns_dnskey_t *dns_dnskey_dup(const dns_dnskey_t *ddnskey);
void dns_dnskey_free_(dns_dnskey_t *ddnskey);
#define dns_dnskey_free(ddnskey) \
  FREE_AND_NULL(dns_dnskey_t, dns_dnskey_free_, (ddnskey))

//
// Resource Record - NSEC3

dns_nsec3_t *dns_nsec3_new(void);
dns_nsec3_t *dns_nsec3_dup(const dns_nsec3_t *dnsec3);
void dns_nsec3_free_(dns_nsec3_t *dnsec3);
#define dns_nsec3_free(dnsec3) \
  FREE_AND_NULL(dns_nsec3_t, dns_nsec3_free_, (dnsec3))

//
// Resource Record - NSEC3PARAM

dns_nsec3param_t *dns_nsec3param_new(void);
dns_nsec3param_t *dns_nsec3param_dup(const dns_nsec3param_t *dnsec3param);
void dns_nsec3param_free_(dns_nsec3param_t *dnsec3param);
#define dns_nsec3param_free(dnsec3param) \
  FREE_AND_NULL(dns_nsec3param_t, dns_nsec3param_free_, (dnsec3param))

//
// Resource Record - URI

dns_uri_t *dns_uri_new(void);
dns_uri_t *dns_uri_dup(const dns_uri_t *duri);
void dns_uri_free_(dns_uri_t *duri);
#define dns_uri_free(duri) \
  FREE_AND_NULL(dns_uri_t, dns_uri_free_, (duri))

//
// Resource Record

dns_rr_t *dns_rr_new(void);
dns_rr_t *dns_rr_dup(const dns_rr_t *drr);
void dns_rr_free_(dns_rr_t *drr);
#define dns_rr_free(drr) \
  FREE_AND_NULL(dns_rr_t, dns_rr_free_, (drr))

//
// Message

dns_message_t *dns_message_new(void);
dns_message_t *dns_message_dup(const dns_message_t *dm);
void dns_message_free_(dns_message_t *dm);
#define dns_message_free(dm) \
  FREE_AND_NULL(dns_message_t, dns_message_free_, (dm))

dns_question_t *dns_message_get_question(const dns_message_t *dm);

#endif /* !defined(TOR_DNS_MESSAGE_H) */
