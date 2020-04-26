/* Copyright (c) 2019 Christian Hofer.
 * Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file dns_string.h
 * \brief Header file for dns_string.c.
 **/

#ifndef TOR_DNS_STRING_H
#define TOR_DNS_STRING_H

#include "lib/cc/torint.h"
#include "lib/container/dns_message_st.h"
#include "lib/smartlist_core/smartlist_core.h"

dns_name_t *dns_name_of(const char *value);
const char *dns_name_str(const dns_name_t *name);

dns_type_t *dns_type_of(uint16_t value);
const char *dns_type_str(uint16_t type);
dns_type_t *dns_type_value_of(const char *value);
const char *dns_types_str(const smartlist_t *types);

const char *dns_header_str(const dns_header_t *dh);

const char *dns_question_str(const dns_question_t *dq);

char *dns_a_value_of(const smartlist_t *parts);
const char *dns_a_str(const char *da);

dns_name_t *dns_ns_value_of(const smartlist_t *parts);
const char *dns_ns_str(const dns_name_t *dns);

dns_name_t *dns_cname_value_of(const smartlist_t *parts);
const char *dns_cname_str(const dns_name_t *dcname);

dns_soa_t *dns_soa_value_of(const smartlist_t *parts);
const char *dns_soa_str(const dns_soa_t *dsoa);

dns_name_t *dns_ptr_value_of(const smartlist_t *parts);
const char *dns_ptr_str(const dns_name_t *dptr);

dns_mx_t *dns_mx_value_of(const smartlist_t *parts);
const char *dns_mx_str(const dns_mx_t *dmx);

dns_key_t *dns_key_value_of(const smartlist_t *parts);
const char *dns_key_str(const dns_key_t *dkey);

char *dns_aaaa_value_of(const smartlist_t *parts);
const char *dns_aaaa_str(const char *daaaa);

dns_ds_t *dns_ds_value_of(const smartlist_t *parts);
const char *dns_ds_str(const dns_ds_t *dds);

dns_rrsig_t *dns_rrsig_value_of(const smartlist_t *parts);
const char *dns_rrsig_str(const dns_rrsig_t *drrsig);

dns_nsec_t *dns_nsec_value_of(const smartlist_t *parts);
const char *dns_nsec_str(const dns_nsec_t *dnsec);

dns_dnskey_t *dns_dnskey_value_of(const smartlist_t *parts);
const char *dns_dnskey_str(const dns_dnskey_t *ddnskey);

dns_nsec3_t *dns_nsec3_value_of(const smartlist_t *parts);
const char *dns_nsec3_str(const dns_nsec3_t *dnsec3);

dns_nsec3param_t *dns_nsec3param_value_of(const smartlist_t *parts);
const char *dns_nsec3param_str(const dns_nsec3param_t *dnsec3param);

dns_uri_t *dns_uri_value_of(const smartlist_t *parts);
const char *dns_uri_str(const dns_uri_t *duri);

dns_rr_t *dns_rr_value_of(const char *value);
const char *dns_rr_str(const dns_rr_t *drr);
const char *dns_rdata_str(const dns_rr_t *drr);

const char *dns_message_str(const dns_message_t *dm);

#endif /* !defined(TOR_DNS_STRING_H) */
