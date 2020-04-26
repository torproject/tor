/* Copyright (c) 2019 Christian Hofer.
 * Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file dns_message.c
 *
 * \brief DNS message containers.
 **/

#include "lib/container/dns_message.h"

#include "lib/container/dns_message_st.h"
#include "lib/container/smartlist.h"
#include "lib/defs/dns_types.h"
#include "lib/log/log.h"
#include "lib/log/util_bug.h"
#include "lib/malloc/malloc.h"
#include "lib/string/compat_ctype.h"
#include "lib/string/util_string.h"

#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

//
// Name

/** Return a new dns_name_t. */
dns_name_t *
dns_name_new(void)
{
  dns_name_t *dn = tor_malloc_zero(sizeof(dns_name_t));
  dn->length = 0;
  dn->value = NULL;
  return dn;
}

/** Return a newly allocated copy of dns_name_t <b>dn</b>. */
dns_name_t *
dns_name_dup(const dns_name_t *dn)
{
  // LCOV_EXCL_START
  tor_assert(dn);
  // LCOV_EXCL_STOP

  dns_name_t *duplicate = tor_malloc_zero(sizeof(dns_name_t));
  if (dn->value) {
    duplicate->length = dn->length;
    duplicate->value = tor_memdup(dn->value, dn->length + 1);
  }
  return duplicate;
}

/** Free all storage held in the dns_name_t <b>dn</b>. */
void
dns_name_free_(dns_name_t *dn)
{
  if (!dn) {
    return;
  }
  tor_free(dn->value);
  tor_free(dn);
}

/** Normalize the given DNS name. */
void
dns_name_normalize(dns_name_t *name)
{
  if (!name || !name->value) {
    return;
  }

  for (uint8_t i=0; name->value[i]; i++) {
    if (name->value[i] == ' ') {
      name->length--;
    }
  }

  tor_strstrip(name->value, " ");
  tor_strlower(name->value);

  if (name->length == 0 || name->value[name->length - 1] != '.') {
    char *extended_name = tor_malloc_zero(name->length + 2);
    memcpy(extended_name, name->value, name->length);
    extended_name[name->length] = '.';
    name->length += 1;

    tor_free(name->value);
    name->value = tor_memdup(extended_name, name->length + 1);
    tor_free(extended_name);
  }
}

/** Return label count of <b>needle</b> if it is part of <b>haystack</b>,
 * -1 otherwise. */
int
dns_name_is_part_of(const dns_name_t *needle, const dns_name_t *haystack)
{
  if (!needle || !needle->value || !haystack || !haystack->value) {
    return -1;
  }

  int label_len = 0;
  int labels = 0;

  for (int i = (int) needle->length - 1, j = (int) haystack->length - 1;
       i >= 0 && j >= 0;
       i--, j--) {

    if (needle->value[i] == '.') {
      if (label_len > 0) {
        labels++;
      }
      label_len = 0;
    } else if (!TOR_ISSPACE(needle->value[i])) {
      label_len++;
    }

    if (needle->value[i] == '.' || haystack->value[j] == '.') {
      if (needle->value[i] != haystack->value[j]) {
        if (label_len > 0) {
          j--;
        } else {
          j++;
        }
      }
    }

    if (i > 0 && j == 0) {
      return -1;
    }

    if (i < 0 || j < 0) {
      return -1;
    }

    if (label_len > 0 &&
        TOR_TOLOWER(needle->value[i]) != TOR_TOLOWER(haystack->value[j])) {
      return -1;
    }
  }

  if (label_len > 0) {
    labels++;
  }

  return labels;
}

/** Compare the two DNS names <b>this</b> and <b>that</b>.
 * Return < 0 if this is less than that, 0 if they are equal, and > 0 this is
 * greater than that. */
int
dns_name_compare(const dns_name_t *this, const dns_name_t *that)
{
  if (!this || !this->value) {
    return -1;
  }

  if (!that || !that->value) {
    return 1;
  }

  int ret = 0;

  int this_len = (int) this->length;
  int that_len = (int) that->length;

  int i = this_len - 1;
  int j = that_len - 1;

  int label_len = 0;
  for (; ret == 0 && i >= 0 && j >= 0; i--, j--) {
    if (this->value[i] == '.') {
      label_len = 0;
    } else if (!TOR_ISSPACE(this->value[i])) {
      label_len++;
    }

    if (this->value[i] == '.' || that->value[j] == '.') {
      if (this->value[i] != that->value[j]) {
        if (label_len > 0) {
          j--;
        } else {
          j++;
        }
      }
    }

    if (i < 0) {
      return -1;
    }

    if (j < 0) {
      return 1;
    }

    if (label_len > 0 &&
        TOR_TOLOWER(this->value[i]) != TOR_TOLOWER(that->value[j])) {
      ret = TOR_TOLOWER(this->value[i]) - TOR_TOLOWER(that->value[j]);
    }
  }

  if (ret == 0) {
    return i - j;
  }

  for (i++; i > 0; i--) {
    if (this->value[i] == '.') {
      i++;
      break;
    }
  }
  for (j++; j > 0; j--) {
    if (that->value[j] == '.') {
      j++;
      break;
    }
  }

  for (; i < this_len && j < that_len; i++, j++) {
    if (this->value[i] == '.') {
      return -1;
    }
    if (that->value[j] == '.') {
      return 1;
    }

    if (TOR_TOLOWER(this->value[i]) != TOR_TOLOWER(that->value[j])) {
      return TOR_TOLOWER(this->value[i]) - TOR_TOLOWER(that->value[j]);
    }
  }

  return 0;
}

/** Return True iff <b>sl</b> contains dns name <b>name</b>. */
int
dns_name_present_in_smartlist(const smartlist_t *sl, const dns_name_t *name)
{
  // LCOV_EXCL_START
  tor_assert(sl);
  // LCOV_EXCL_STOP

  SMARTLIST_FOREACH_BEGIN(sl, dns_name_t *, dns_name) {
    if (dns_name_compare(dns_name, name) == 0) {
      return 1;
    }
  } SMARTLIST_FOREACH_END(dns_name);

  return 0;
}

//
// Type

/** Return a new dns_type_t. */
dns_type_t *
dns_type_new(void)
{
  dns_type_t *dt = tor_malloc_zero(sizeof(dns_type_t));
  dt->value = 0;
  dt->name = NULL;
  return dt;
}

/** Return a newly allocated copy of dns_type_t <b>dt</b>. */
dns_type_t *
dns_type_dup(const dns_type_t *dt)
{
  // LCOV_EXCL_START
  tor_assert(dt);
  // LCOV_EXCL_STOP

  dns_type_t *duplicate = tor_malloc_zero(sizeof(dns_type_t));
  duplicate->name = tor_strdup(dt->name);
  duplicate->value = dt->value;
  return duplicate;
}

/** Return True in case the value of dns_type_t <b>type</b> equals the given
 * <b>value</b>, False otherwise. */
bool
dns_type_is(dns_type_t *type, uint16_t value)
{
  if (!type) {
    return false;
  }
  return type->value == value;
}

/** Free all storage held in the dns_type_t <b>dt</b>. */
void
dns_type_free_(dns_type_t *dt)
{
  if (!dt) {
    return;
  }
  tor_free(dt->name);
  tor_free(dt);
}

/** Return True iff <b>sl</b> contains dns type <b>type</b>. */
int
dns_type_present_in_smartlist(const smartlist_t *sl, const int type)
{
  // LCOV_EXCL_START
  tor_assert(sl);
  // LCOV_EXCL_STOP

  SMARTLIST_FOREACH_BEGIN(sl, dns_type_t *, dns_type) {
    if (dns_type_is(dns_type, type)) {
      return 1;
    }
  } SMARTLIST_FOREACH_END(dns_type);

  return 0;
}

//
// Header

/** Return a new dns_header_t. */
dns_header_t *
dns_header_new(void)
{
  dns_header_t *dh = tor_malloc_zero(sizeof(dns_header_t));
#ifdef _WIN32
  dh->id = (uint16_t) _getpid();
#else
  dh->id = (uint16_t) getpid();
#endif
  dh->qr = false;
  dh->opcode = 0;
  dh->tc = false;
  dh->rd = false;
  dh->ra = false;
  dh->z = false;
  dh->ad = false;
  dh->cd = false;
  dh->rcode = 0;
  dh->qdcount = 0;
  dh->ancount = 0;
  dh->nscount = 0;
  dh->arcount = 0;
  return dh;
}

/** Return a newly allocated copy of dns_header_t <b>dh</b>. */
dns_header_t *
dns_header_dup(const dns_header_t *dh)
{
  // LCOV_EXCL_START
  tor_assert(dh);
  // LCOV_EXCL_STOP

  dns_header_t *duplicate = tor_malloc_zero(sizeof(dns_header_t));
  duplicate->id = dh->id;
  duplicate->qr = dh->qr;
  duplicate->opcode = dh->opcode;
  duplicate->tc = dh->tc;
  duplicate->rd = dh->rd;
  duplicate->ra = dh->ra;
  duplicate->z = dh->z;
  duplicate->ad = dh->ad;
  duplicate->cd = dh->cd;
  duplicate->rcode = dh->rcode;
  duplicate->qdcount = dh->qdcount;
  duplicate->ancount = dh->ancount;
  duplicate->nscount = dh->nscount;
  duplicate->arcount = dh->arcount;
  return duplicate;
}

/** Free all storage held in the dns_header_t <b>dh</b>. */
void
dns_header_free_(dns_header_t *dh)
{
  if (!dh) {
    return;
  }
  tor_free(dh);
}

//
// Question

/** Return a new dns_question_t. */
dns_question_t *
dns_question_new(void)
{
  dns_question_t *dq = tor_malloc_zero(sizeof(dns_question_t));
  dq->qname = NULL;
  dq->qtype = NULL;
  dq->qclass = 0;
  return dq;
}

/** Return a newly allocated copy of dns_question_t <b>dq</b>. */
dns_question_t *
dns_question_dup(const dns_question_t *dq)
{
  // LCOV_EXCL_START
  tor_assert(dq);
  // LCOV_EXCL_STOP

  dns_question_t *duplicate = tor_malloc_zero(sizeof(dns_question_t));
  if (dq->qname) {
    duplicate->qname = dns_name_dup(dq->qname);
  }
  if (dq->qtype) {
    duplicate->qtype = dns_type_dup(dq->qtype);
  }
  duplicate->qclass = dq->qclass;
  return duplicate;
}

/** Free all storage held in the dns_question_t <b>dq</b>. */
void
dns_question_free_(dns_question_t *dq)
{
  if (!dq) {
    return;
  }
  dns_name_free(dq->qname);
  dns_type_free(dq->qtype);
  tor_free(dq);
}

//
// Resource Record - SOA

/** Return a new dns_soa_t. */
dns_soa_t *
dns_soa_new(void)
{
  dns_soa_t *dsoa = tor_malloc_zero(sizeof(dns_soa_t));
  dsoa->mname = NULL;
  dsoa->rname = NULL;
  dsoa->serial = 0;
  dsoa->refresh = 0;
  dsoa->retry = 0;
  dsoa->expire = 0;
  dsoa->minimum = 0;
  return dsoa;
}

/** Return a newly allocated copy of dns_soa_t <b>dsoa</b>. */
dns_soa_t *
dns_soa_dup(const dns_soa_t *dsoa)
{
  // LCOV_EXCL_START
  tor_assert(dsoa);
  // LCOV_EXCL_STOP

  dns_soa_t *duplicate = tor_malloc_zero(sizeof(dns_soa_t));
  if (dsoa->mname) {
    duplicate->mname = dns_name_dup(dsoa->mname);
  }
  if (dsoa->rname) {
    duplicate->rname = dns_name_dup(dsoa->rname);
  }
  duplicate->serial = dsoa->serial;
  duplicate->refresh = dsoa->refresh;
  duplicate->retry = dsoa->retry;
  duplicate->expire = dsoa->expire;
  duplicate->minimum = dsoa->minimum;
  return duplicate;
}

/** Free all storage held in the dns_soa_t <b>dsoa</b>. */
void
dns_soa_free_(dns_soa_t *dsoa)
{
  if (!dsoa) {
    return;
  }
  dns_name_free(dsoa->mname);
  dns_name_free(dsoa->rname);
  tor_free(dsoa);
}

//
// Resource Record - MX

/** Return a new dns_mx_t. */
dns_mx_t *
dns_mx_new(void)
{
  dns_mx_t *dmx = tor_malloc_zero(sizeof(dns_mx_t));
  dmx->preference = 0;
  dmx->exchange = NULL;
  return dmx;
}

/** Return a newly allocated copy of dns_mx_t <b>dmx</b>. */
dns_mx_t *
dns_mx_dup(const dns_mx_t *dmx)
{
  // LCOV_EXCL_START
  tor_assert(dmx);
  // LCOV_EXCL_STOP

  dns_mx_t *duplicate = tor_malloc_zero(sizeof(dns_mx_t));
  duplicate->preference = dmx->preference;
  if (dmx->exchange) {
    duplicate->exchange = dns_name_dup(dmx->exchange);
  }
  return duplicate;
}

/** Free all storage held in the dns_mx_t <b>dmx</b>. */
void
dns_mx_free_(dns_mx_t *dmx)
{
  if (!dmx) {
    return;
  }
  dns_name_free(dmx->exchange);
  tor_free(dmx);
}

//
// Resource Record - KEY

/** Return a new dns_key_t. */
dns_key_t *
dns_key_new(void)
{
  dns_key_t *dkey = tor_malloc_zero(sizeof(dns_key_t));
  dkey->flags = 0;
  dkey->protocol = 0;
  dkey->algorithm = 0;
  dkey->public_key = NULL;
  dkey->public_key_len = 0;
  return dkey;
}

/** Return a newly allocated copy of dns_key_t <b>dkey</b>. */
dns_key_t *
dns_key_dup(const dns_key_t *dkey)
{
  // LCOV_EXCL_START
  tor_assert(dkey);
  // LCOV_EXCL_STOP

  dns_key_t *duplicate = tor_malloc_zero(sizeof(dns_key_t));
  duplicate->flags = dkey->flags;
  duplicate->protocol = dkey->protocol;
  duplicate->algorithm = dkey->algorithm;
  if (dkey->public_key && dkey->public_key_len > 0) {
    duplicate->public_key = tor_memdup(dkey->public_key, dkey->public_key_len);
    duplicate->public_key_len = dkey->public_key_len;
  }
  return duplicate;
}

/** Free all storage held in the dns_key_t <b>dkey</b>. */
void
dns_key_free_(dns_key_t *dkey)
{
  if (!dkey) {
    return;
  }
  tor_free(dkey->public_key);
  tor_free(dkey);
}

//
// Resource Record - DS

/** Return a new dns_ds_t. */
dns_ds_t *
dns_ds_new(void)
{
  dns_ds_t *dds = tor_malloc_zero(sizeof(dns_ds_t));
  dds->key_tag = 0;
  dds->algorithm = 0;
  dds->digest_type = 0;
  dds->digest = NULL;
  dds->digest_len = 0;
  return dds;
}

/** Return a newly allocated copy of dns_ds_t <b>dds</b>. */
dns_ds_t *
dns_ds_dup(const dns_ds_t *dds)
{
  // LCOV_EXCL_START
  tor_assert(dds);
  // LCOV_EXCL_STOP

  dns_ds_t *duplicate = tor_malloc_zero(sizeof(dns_ds_t));
  duplicate->key_tag = dds->key_tag;
  duplicate->algorithm = dds->algorithm;
  duplicate->digest_type = dds->digest_type;
  if (dds->digest && dds->digest_len > 0) {
    duplicate->digest = tor_memdup(dds->digest, dds->digest_len);
    duplicate->digest_len = dds->digest_len;
  }
  return duplicate;
}

/** Free all storage held in the dns_ds_t <b>dds</b>. */
void
dns_ds_free_(dns_ds_t *dds)
{
  if (!dds) {
    return;
  }
  tor_free(dds->digest);
  tor_free(dds);
}

//
// Resource Record - RRSIG

/** Return a new dns_rrsig_t. */
dns_rrsig_t *
dns_rrsig_new(void)
{
  dns_rrsig_t *drrsig = tor_malloc_zero(sizeof(dns_rrsig_t));
  drrsig->type_covered = NULL;
  drrsig->algorithm = 0;
  drrsig->labels = 0;
  drrsig->original_ttl = 0;
  drrsig->signature_expiration = 0;
  drrsig->signature_inception = 0;
  drrsig->key_tag = 0;
  drrsig->signer_name = NULL;
  drrsig->signature = NULL;
  drrsig->signature_len = 0;
  return drrsig;
}

/** Return a newly allocated copy of dns_rrsig_t <b>drrsig</b>. */
dns_rrsig_t *
dns_rrsig_dup(const dns_rrsig_t *drrsig)
{
  // LCOV_EXCL_START
  tor_assert(drrsig);
  // LCOV_EXCL_STOP

  dns_rrsig_t *duplicate = tor_malloc_zero(sizeof(dns_rrsig_t));
  if (drrsig->type_covered) {
    duplicate->type_covered = dns_type_dup(drrsig->type_covered);
  }
  duplicate->algorithm = drrsig->algorithm;
  duplicate->labels = drrsig->labels;
  duplicate->original_ttl = drrsig->original_ttl;
  duplicate->signature_expiration = drrsig->signature_expiration;
  duplicate->signature_inception = drrsig->signature_inception;
  duplicate->key_tag = drrsig->key_tag;
  if (drrsig->signer_name) {
    duplicate->signer_name = dns_name_dup(drrsig->signer_name);
  }
  if (drrsig->signature && drrsig->signature_len > 0) {
    duplicate->signature =
      tor_memdup(drrsig->signature, drrsig->signature_len);
    duplicate->signature_len = drrsig->signature_len;
  }
  return duplicate;
}

/** Free all storage held in the dns_rrsig_t <b>drrsig</b>. */
void
dns_rrsig_free_(dns_rrsig_t *drrsig)
{
  if (!drrsig) {
    return;
  }
  dns_type_free(drrsig->type_covered);
  dns_name_free(drrsig->signer_name);
  tor_free(drrsig->signature);
  tor_free(drrsig);
}

//
// Resource Record - NSEC

/** Return a new dns_nsec_t. */
dns_nsec_t *
dns_nsec_new(void)
{
  dns_nsec_t *dnsec = tor_malloc_zero(sizeof(dns_nsec_t));
  dnsec->next_domain_name = NULL;
  dnsec->types = smartlist_new();
  return dnsec;
}

/** Return a newly allocated copy of dns_nsec_t <b>dnsec</b>. */
dns_nsec_t *
dns_nsec_dup(const dns_nsec_t *dnsec)
{
  // LCOV_EXCL_START
  tor_assert(dnsec);
  // LCOV_EXCL_STOP

  dns_nsec_t *duplicate = tor_malloc_zero(sizeof(dns_nsec_t));
  if (dnsec->next_domain_name) {
    duplicate->next_domain_name = dns_name_dup(dnsec->next_domain_name);
  }
  duplicate->types = smartlist_new();
  SMARTLIST_FOREACH(dnsec->types, dns_type_t *, dt,
    smartlist_add(duplicate->types, dns_type_dup(dt)));
  return duplicate;
}

/** Free all storage held in the dns_nsec_t <b>dnsec</b>. */
void
dns_nsec_free_(dns_nsec_t *dnsec)
{
  if (!dnsec) {
    return;
  }
  dns_name_free(dnsec->next_domain_name);
  SMARTLIST_FOREACH(dnsec->types, dns_type_t *, dt,
    dns_type_free(dt));
  smartlist_free(dnsec->types);
  tor_free(dnsec);
}

//
// Resource Record - DNSKEY

/** Return a new dns_dnskey_t. */
dns_dnskey_t *
dns_dnskey_new(void)
{
  dns_dnskey_t *ddnskey = tor_malloc_zero(sizeof(dns_dnskey_t));
  ddnskey->flags = 0;
  ddnskey->protocol = 0;
  ddnskey->algorithm = 0;
  ddnskey->public_key = NULL;
  ddnskey->public_key_len = 0;
  return ddnskey;
}

/** Return a newly allocated copy of dns_dnskey_t <b>ddnskey</b>. */
dns_dnskey_t *
dns_dnskey_dup(const dns_dnskey_t *ddnskey)
{
  // LCOV_EXCL_START
  tor_assert(ddnskey);
  // LCOV_EXCL_STOP

  dns_dnskey_t *duplicate = tor_malloc_zero(sizeof(dns_dnskey_t));
  duplicate->flags = ddnskey->flags;
  duplicate->protocol = ddnskey->protocol;
  duplicate->algorithm = ddnskey->algorithm;
  if (ddnskey->public_key && ddnskey->public_key_len > 0) {
    duplicate->public_key =
      tor_memdup(ddnskey->public_key, ddnskey->public_key_len);
    duplicate->public_key_len = ddnskey->public_key_len;
  }
  return duplicate;
}

/** Free all storage held in the dns_dnskey_t <b>ddnskey</b>. */
void
dns_dnskey_free_(dns_dnskey_t *ddnskey)
{
  if (!ddnskey) {
    return;
  }
  tor_free(ddnskey->public_key);
  tor_free(ddnskey);
}

//
// Resource Record - NSEC3

/** Return a new dns_nsec3_t. */
dns_nsec3_t *
dns_nsec3_new(void)
{
  dns_nsec3_t *dnsec3 = tor_malloc_zero(sizeof(dns_nsec3_t));
  dnsec3->hash_algorithm = 0;
  dnsec3->flags = 0;
  dnsec3->iterations = 0;
  dnsec3->salt_length = 0;
  dnsec3->salt = NULL;
  dnsec3->hash_length = 0;
  dnsec3->next_hashed_owner_name = NULL;
  dnsec3->types = smartlist_new();
  return dnsec3;
}

/** Return a newly allocated copy of dns_nsec3_t <b>dnsec3</b>. */
dns_nsec3_t *
dns_nsec3_dup(const dns_nsec3_t *dnsec3)
{
  // LCOV_EXCL_START
  tor_assert(dnsec3);
  // LCOV_EXCL_STOP

  dns_nsec3_t *duplicate = tor_malloc_zero(sizeof(dns_nsec3_t));
  duplicate->hash_algorithm = dnsec3->hash_algorithm;
  duplicate->flags = dnsec3->flags;
  duplicate->iterations = dnsec3->iterations;
  if (dnsec3->salt && dnsec3->salt_length > 0) {
    duplicate->salt_length = dnsec3->salt_length;
    duplicate->salt = tor_memdup(dnsec3->salt, dnsec3->salt_length);
  }
  if (dnsec3->next_hashed_owner_name && dnsec3->hash_length > 0) {
    duplicate->hash_length = dnsec3->hash_length;
    duplicate->next_hashed_owner_name =
      tor_memdup(dnsec3->next_hashed_owner_name, dnsec3->hash_length);
  }
  duplicate->types = smartlist_new();
  SMARTLIST_FOREACH(dnsec3->types, dns_type_t *, dt,
    smartlist_add(duplicate->types, dns_type_dup(dt)));
  return duplicate;
}

/** Free all storage held in the dns_nsec3_t <b>dnsec3</b>. */
void
dns_nsec3_free_(dns_nsec3_t *dnsec3)
{
  if (!dnsec3) {
    return;
  }
  tor_free(dnsec3->salt);
  tor_free(dnsec3->next_hashed_owner_name);
  SMARTLIST_FOREACH(dnsec3->types, dns_type_t *, dt,
                    dns_type_free(dt));
  smartlist_free(dnsec3->types);
  tor_free(dnsec3);
}

//
// Resource Record - NSEC3PARAM

/** Return a new dns_nsec3param_t. */
dns_nsec3param_t *
dns_nsec3param_new(void)
{
  dns_nsec3param_t *dnsec3param = tor_malloc_zero(sizeof(dns_nsec3param_t));
  dnsec3param->hash_algorithm = 0;
  dnsec3param->flags = 0;
  dnsec3param->iterations = 0;
  dnsec3param->salt_length = 0;
  dnsec3param->salt = NULL;
  return dnsec3param;
}

/** Return a newly allocated copy of dns_nsec3param_t <b>dnsec3param</b>. */
dns_nsec3param_t *
dns_nsec3param_dup(const dns_nsec3param_t *dnsec3param)
{
  // LCOV_EXCL_START
  tor_assert(dnsec3param);
  // LCOV_EXCL_STOP

  dns_nsec3param_t *duplicate = tor_malloc_zero(sizeof(dns_nsec3param_t));
  duplicate->hash_algorithm = dnsec3param->hash_algorithm;
  duplicate->flags = dnsec3param->flags;
  duplicate->iterations = dnsec3param->iterations;
  if (dnsec3param->salt && dnsec3param->salt_length > 0) {
    duplicate->salt_length = dnsec3param->salt_length;
    duplicate->salt = tor_memdup(dnsec3param->salt, dnsec3param->salt_length);
  }
  return duplicate;
}

/** Free all storage held in the dns_nsec3param_t <b>dnsec3param</b>. */
void
dns_nsec3param_free_(dns_nsec3param_t *dnsec3param)
{
  if (!dnsec3param) {
    return;
  }
  tor_free(dnsec3param->salt);
  tor_free(dnsec3param);
}

//
// Resource Record - URI

/** Return a new dns_uri_t. */
dns_uri_t *
dns_uri_new(void)
{
  dns_uri_t *duri = tor_malloc_zero(sizeof(dns_uri_t));
  duri->priority = 0;
  duri->weight = 0;
  duri->target = NULL;
  return duri;
}

/** Return a newly allocated copy of dns_uri_t <b>duri</b>. */
dns_uri_t *
dns_uri_dup(const dns_uri_t *duri)
{
  // LCOV_EXCL_START
  tor_assert(duri);
  // LCOV_EXCL_STOP

  dns_uri_t *duplicate = tor_malloc_zero(sizeof(dns_uri_t));
  duplicate->priority = duri->priority;
  duplicate->weight = duri->weight;
  if (duri->target) {
    duplicate->target = tor_strdup(duri->target);
  }
  return duplicate;
}

/** Free all storage held in the dns_uri_t <b>duri</b>. */
void
dns_uri_free_(dns_uri_t *duri)
{
  if (!duri) {
    return;
  }
  tor_free(duri->target);
  tor_free(duri);
}

//
// Resource Record

/** Return a new dns_rr_t. */
dns_rr_t *
dns_rr_new(void)
{
  dns_rr_t *drr = tor_malloc_zero(sizeof(dns_rr_t));
  drr->name = NULL;
  drr->rrtype = NULL;
  drr->rrclass = DNS_CLASS_IN;
  drr->ttl = 0;
  drr->rdlength = 0;
  drr->rdata = NULL;
  drr->a = NULL;
  drr->ns = NULL;
  drr->cname = NULL;
  drr->soa = NULL;
  drr->ptr = NULL;
  drr->mx = NULL;
  drr->key = NULL;
  drr->aaaa = NULL;
  drr->ds = NULL;
  drr->rrsig = NULL;
  drr->nsec = NULL;
  drr->dnskey = NULL;
  drr->nsec3 = NULL;
  drr->nsec3param = NULL;
  drr->uri = NULL;
  drr->validation_state = -1;
  drr->signer = NULL;
  return drr;
}

/** Return a newly allocated copy of dns_rr_t <b>drr</b>. */
dns_rr_t *
dns_rr_dup(const dns_rr_t *drr)
{
  // LCOV_EXCL_START
  tor_assert(drr);
  // LCOV_EXCL_STOP

  dns_rr_t *duplicate = tor_malloc_zero(sizeof(dns_rr_t));
  if (drr->name) {
    duplicate->name = dns_name_dup(drr->name);
  }
  if (drr->rrtype) {
    duplicate->rrtype = dns_type_dup(drr->rrtype);
  }
  duplicate->rrclass = drr->rrclass;
  duplicate->ttl = drr->ttl;
  if (drr->rdata && drr->rdlength > 0) {
    duplicate->rdlength = drr->rdlength;
    duplicate->rdata = tor_memdup(drr->rdata, drr->rdlength);
  }
  if (drr->a) {
    duplicate->a = tor_strdup(drr->a);
  }
  if (drr->ns) {
    duplicate->ns = dns_name_dup(drr->ns);
  }
  if (drr->cname) {
    duplicate->cname = dns_name_dup(drr->cname);
  }
  if (drr->soa) {
    duplicate->soa = dns_soa_dup(drr->soa);
  }
  if (drr->ptr) {
    duplicate->ptr = dns_name_dup(drr->ptr);
  }
  if (drr->mx) {
    duplicate->mx = dns_mx_dup(drr->mx);
  }
  if (drr->key) {
    duplicate->key = dns_key_dup(drr->key);
  }
  if (drr->aaaa) {
    duplicate->aaaa = tor_strdup(drr->aaaa);
  }
  if (drr->ds) {
    duplicate->ds = dns_ds_dup(drr->ds);
  }
  if (drr->rrsig) {
    duplicate->rrsig = dns_rrsig_dup(drr->rrsig);
  }
  if (drr->nsec) {
    duplicate->nsec = dns_nsec_dup(drr->nsec);
  }
  if (drr->dnskey) {
    duplicate->dnskey = dns_dnskey_dup(drr->dnskey);
  }
  if (drr->nsec3) {
    duplicate->nsec3 = dns_nsec3_dup(drr->nsec3);
  }
  if (drr->nsec3param) {
    duplicate->nsec3param = dns_nsec3param_dup(drr->nsec3param);
  }
  if (drr->uri) {
    duplicate->uri = dns_uri_dup(drr->uri);
  }
  duplicate->validation_state = drr->validation_state;
  duplicate->signer = drr->signer;
  return duplicate;
}

/** Free all storage held in the dns_rr_t <b>drr</b>. */
void
dns_rr_free_(dns_rr_t *drr)
{
  if (!drr) {
    return;
  }
  dns_name_free(drr->name);
  dns_type_free(drr->rrtype);
  tor_free(drr->rdata);
  tor_free(drr->a);
  dns_name_free(drr->ns);
  dns_name_free(drr->cname);
  dns_soa_free(drr->soa);
  dns_name_free(drr->ptr);
  dns_mx_free(drr->mx);
  dns_key_free(drr->key);
  tor_free(drr->aaaa);
  dns_ds_free(drr->ds);
  dns_rrsig_free(drr->rrsig);
  dns_nsec_free(drr->nsec);
  dns_dnskey_free(drr->dnskey);
  dns_nsec3_free(drr->nsec3);
  dns_nsec3param_free(drr->nsec3param);
  dns_uri_free(drr->uri);
  tor_free(drr);
}

//
// Message

/** Return a new dns_message_t. */
dns_message_t *
dns_message_new(void)
{
  dns_message_t *dm = tor_malloc_zero(sizeof(dns_message_t));
  dm->header = dns_header_new();
  dm->question_list = smartlist_new();
  dm->answer_list = smartlist_new();
  dm->name_server_list = smartlist_new();
  dm->additional_record_list = smartlist_new();
  return dm;
}

/** Return a newly allocated copy of dns_message_t <b>dm</b>. */
dns_message_t *
dns_message_dup(const dns_message_t *dm)
{
  // LCOV_EXCL_START
  tor_assert(dm);
  // LCOV_EXCL_STOP

  dns_message_t *duplicate = tor_malloc_zero(sizeof(dns_message_t));
  if (dm->header) {
    duplicate->header = dns_header_dup(dm->header);
  }
  duplicate->question_list = smartlist_new();
  if (dm->question_list) {
    SMARTLIST_FOREACH(dm->question_list, dns_question_t *, dq,
        smartlist_add(duplicate->question_list, dns_question_dup(dq)));
  }
  duplicate->answer_list = smartlist_new();
  if (dm->answer_list) {
    SMARTLIST_FOREACH(dm->answer_list, dns_rr_t *, dan,
        smartlist_add(duplicate->answer_list, dns_rr_dup(dan)));
  }
  duplicate->name_server_list = smartlist_new();
  if (dm->name_server_list) {
    SMARTLIST_FOREACH(dm->name_server_list, dns_rr_t *, dns,
        smartlist_add(duplicate->name_server_list, dns_rr_dup(dns)));
  }
  duplicate->additional_record_list = smartlist_new();
  if (dm->additional_record_list) {
    SMARTLIST_FOREACH(dm->additional_record_list, dns_rr_t *, dar,
        smartlist_add(duplicate->additional_record_list, dns_rr_dup(dar)));
  }
  duplicate->cached_at.tv_sec = dm->cached_at.tv_sec;
  duplicate->cached_at.tv_usec = dm->cached_at.tv_usec;
  return duplicate;
}

/** Free all storage held in the dns_message_t <b>dm</b>. */
void
dns_message_free_(dns_message_t *dm)
{
  if (!dm) {
    return;
  }
  dns_header_free(dm->header);

  SMARTLIST_FOREACH(dm->question_list, dns_question_t *, dq,
    dns_question_free(dq));
  smartlist_free(dm->question_list);

  SMARTLIST_FOREACH(dm->answer_list, dns_rr_t *, dan,
    dns_rr_free(dan));
  smartlist_free(dm->answer_list);

  SMARTLIST_FOREACH(dm->name_server_list, dns_rr_t *, dns,
    dns_rr_free(dns));
  smartlist_free(dm->name_server_list);

  SMARTLIST_FOREACH(dm->additional_record_list, dns_rr_t *, dar,
    dns_rr_free(dar));
  smartlist_free(dm->additional_record_list);

  tor_free(dm);
}

/** Return the message's question. */
dns_question_t *
dns_message_get_question(const dns_message_t *dm)
{
  // LCOV_EXCL_START
  tor_assert(dm);
  // LCOV_EXCL_STOP

  if (dm->header->qdcount != 1 || smartlist_len(dm->question_list) != 1) {
    log_debug(LD_GENERAL, "malformed message");
    return NULL;
  }

  return smartlist_get(dm->question_list, 0);
}
