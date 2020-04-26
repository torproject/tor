/* Copyright (c) 2019 Christian Hofer.
 * Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypto_dnssec.c
 * \brief Functions to handle DNSSEC validation of DNS messages.
 **/

#define CRYPTO_DNSSEC_PRIVATE
#include "lib/crypt_ops/crypto_dnssec.h"

#include "lib/container/dns_message.h"
#include "lib/container/dns_message_st.h"
#include "lib/container/smartlist.h"
#include "lib/crypt_ops/crypto_digest.h"
#include "lib/ctime/di_ops.h"
#include "lib/defs/dns_types.h"
#include "lib/encoding/dns_string.h"
#include "lib/encoding/dns_wireformat.h"
#include "lib/encoding/binascii.h"
#include "lib/intmath/cmp.h"
#include "lib/log/log.h"
#include "lib/log/util_bug.h"
#include "lib/string/compat_ctype.h"
#include "lib/wallclock/timeval.h"
#include "lib/wallclock/tor_gettimeofday.h"

#include <string.h>

/** Authenticating RRset in <b>unauthenticated_rrset</b> as described in
 * RFC 4035 section 5.3.
 * Return 0 in case rrset was authenticated, < 0 otherwise. */
MOCK_IMPL(int,
dnssec_authenticate_rrset, (const smartlist_t *unauthenticated_rrset,
                            const smartlist_t *authenticated_dnskey_rrset))
{
  // LCOV_EXCL_START
  tor_assert(unauthenticated_rrset);
  tor_assert(authenticated_dnskey_rrset);
  // LCOV_EXCL_STOP

  int ret = 0;
  smartlist_t *signatures = dnssec_collect_signatures(unauthenticated_rrset,
                                                   authenticated_dnskey_rrset);
  smartlist_t *rrset = NULL;

  if (smartlist_len(signatures) == 0) {
    log_debug(LD_CRYPTO, "could not find signatures for authenticating the "
              "RRSet");
    ret = -1;
    goto cleanup;
  }

  SMARTLIST_FOREACH_BEGIN(signatures, dns_rr_t *, signature) {

    smartlist_free(rrset);
    rrset = dnssec_collect_rrset(signature, unauthenticated_rrset);

    // LCOV_EXCL_START
    if (PREDICT_UNLIKELY(log_global_min_severity_ == LOG_DEBUG)) {
      log_notice(LD_CRYPTO, "RRSet for %s",
                 dns_name_str(signature->rrsig->signer_name));
      SMARTLIST_FOREACH_BEGIN(rrset, dns_rr_t *, rr) {
        log_notice(LD_CRYPTO, "%d - %s", rr->validation_state, dns_rr_str(rr));
      } SMARTLIST_FOREACH_END(rr);
    }
    // LCOV_EXCL_STOP

    if (dnssec_validate_rrset(rrset, authenticated_dnskey_rrset,
                              signatures) < 0) {
      log_debug(LD_CRYPTO, "failed validating rrset with signature: %s",
                dns_rr_str(signature));
      ret = -2;
      goto cleanup;
    }

  } SMARTLIST_FOREACH_END(signature);

 cleanup:
  smartlist_free(signatures);
  smartlist_free(rrset);
  return ret;
}

/** Comparator for sorting DS RRs by digest_type in descending order. */
static int
sort_ds_by_digest_type_desc(const void **a_, const void **b_)
{
  const dns_rr_t *a = *a_,
                 *b = *b_;

  if (!a->rrtype || !b->rrtype || !a->ds || !b->ds ||
      a->rrtype->value != DNS_TYPE_DS || b->rrtype->value != DNS_TYPE_DS) {
    return 0;
  }

  return b->ds->digest_type - a->ds->digest_type;
}

/** Authenticate delegation to child zone as described in RFC 4035 section 5.2
 * Verified DNSKEYs are put to <b>authenticated_dnskey_rrset</b>.
 * Return 0 in case delegation was authenticated, < 0 otherwise.
 * */
MOCK_IMPL(int,
dnssec_authenticate_delegation_to_child_zone,
                                     (smartlist_t *authenticated_dnskey_rrset,
                                      const smartlist_t *unauthenticated_rrset,
                                      const smartlist_t *ds_rrset))
{
  // LCOV_EXCL_START
  tor_assert(authenticated_dnskey_rrset);
  tor_assert(unauthenticated_rrset);
  tor_assert(ds_rrset);
  // LCOV_EXCL_STOP

  log_debug(LD_CRYPTO, "dnsresolv_authenticate_delegation_to_child_zone");
  smartlist_clear(authenticated_dnskey_rrset);

  // find DNSKEYs with the zone flag set
  smartlist_t *dnskey_rrset = smartlist_new();
  SMARTLIST_FOREACH_BEGIN(unauthenticated_rrset, dns_rr_t *, rr) {
    if (dns_type_is(rr->rrtype, DNS_TYPE_DNSKEY) && rr->dnskey != NULL &&
        (rr->dnskey->flags & DNS_DNSKEY_FLAG_ZONE)) {
      smartlist_add(dnskey_rrset, rr);
    }
  } SMARTLIST_FOREACH_END(rr);

  // sort ds records by digest type to ensure that always the strongest
  // available digest is used first
  smartlist_t *sorted_ds_rrset = smartlist_new();
  SMARTLIST_FOREACH(ds_rrset, dns_rr_t *, rr,
                    smartlist_add(sorted_ds_rrset, rr));
  smartlist_sort(sorted_ds_rrset, sort_ds_by_digest_type_desc);

  SMARTLIST_FOREACH_BEGIN(dnskey_rrset, dns_rr_t *, dnskey_rr) {

    uint16_t key_tag = dns_encode_key_tag(dnskey_rr);
    size_t data_len = 0;
    uint8_t *data = dns_encode_digest_data(dnskey_rr, &data_len);

    SMARTLIST_FOREACH_BEGIN(sorted_ds_rrset, dns_rr_t *, ds_rr) {
      if (ds_rr->validation_state == DNSSEC_VALIDATION_STATE_SECURE &&
          ds_rr->ds != NULL && ds_rr->ds->key_tag == key_tag &&
          ds_rr->ds->algorithm == dnskey_rr->dnskey->algorithm) {
        int res = -1;

#ifdef ENABLE_OPENSSL

        const uint8_t *digest = ds_rr->ds->digest;
        const size_t digest_len = ds_rr->ds->digest_len;

#endif /* defined(ENABLE_OPENSSL) */

        switch (ds_rr->ds->digest_type) {

#ifdef ENABLE_OPENSSL

          case DNSSEC_DIGEST_SHA1:
            res = crypto_dnssec_verify_digest_sha1(data, data_len,
                                                   digest, digest_len);
            break;
          case DNSSEC_DIGEST_SHA256:
            res = crypto_dnssec_verify_digest_sha256(data, data_len,
                                                     digest, digest_len);
            break;
          case DNSSEC_DIGEST_SHA384:
            res = crypto_dnssec_verify_digest_sha384(data, data_len,
                                                     digest, digest_len);
            break;

#endif /* defined(ENABLE_OPENSSL) */

          default:
            log_info(LD_CRYPTO, "DNSSEC digest type %d not implemented.",
                     ds_rr->ds->digest_type);
            continue;
        }

        if (res == 0) {
          dnskey_rr->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
          smartlist_add(authenticated_dnskey_rrset, dnskey_rr);
          log_debug(LD_CRYPTO, "authenticated: %s\nusing: %s",
                    dns_rr_str(dnskey_rr), dns_rr_str(ds_rr));
        } else {
          dnskey_rr->validation_state = DNSSEC_VALIDATION_STATE_INSECURE;
        }
        break;
      }
    } SMARTLIST_FOREACH_END(ds_rr);

    tor_free(data);

  } SMARTLIST_FOREACH_END(dnskey_rr);

  smartlist_free(dnskey_rrset);
  smartlist_free(sorted_ds_rrset);

  log_debug(LD_CRYPTO, "found %d authenticated DNSKEYs",
            smartlist_len(authenticated_dnskey_rrset));

  if (smartlist_len(authenticated_dnskey_rrset) > 0) {
    return 0;
  }
  return -1;
}

/** Authenticated denial of existence as described in RFC 4035 section 5.4
 * and RFC 5155. */
MOCK_IMPL(denial_of_existence_t,
dnssec_denial_of_existence, (const dns_name_t *qname, const uint16_t qtype,
                             const smartlist_t *rrset))
{
  // LCOV_EXCL_START
  tor_assert(qname);
  tor_assert(rrset);
  // LCOV_EXCL_STOP

  bool has_nsec3 = false;

  SMARTLIST_FOREACH_BEGIN(rrset, dns_rr_t *, rr) {

    if (rr->validation_state == DNSSEC_VALIDATION_STATE_SECURE) {
      if (dns_type_is(rr->rrtype, DNS_TYPE_NSEC)) {
        denial_of_existence_t result = DNSSEC_DENIAL_OF_EXISTENCE_NODATA;
        if (dnssec_nsec_denial_of_existence(
                &result, qname, qtype, rr, rrset) > 0) {
          return result;
        }
      } else if (dns_type_is(rr->rrtype, DNS_TYPE_NSEC3)) {
        has_nsec3 = true;
        denial_of_existence_t result = DNSSEC_DENIAL_OF_EXISTENCE_NODATA;
        if (dnssec_nsec3_denial_of_existence(&result, qname, qtype, rr) > 0) {
          return result;
        }
      }
    }

  } SMARTLIST_FOREACH_END(rr);

  if (has_nsec3) {
    denial_of_existence_t result = DNSSEC_DENIAL_OF_EXISTENCE_NODATA;
    if (dnssec_nsec3_encloser_proof(&result, qname, qtype, rrset) > 0) {
      return result;
    }
  }

  return DNSSEC_DENIAL_OF_EXISTENCE_NODATA;
}

/** Set the validation state to <b>validation_state</b> in all resource records
 * in <b>rrset</b>. In case a signer is given its validation state is updated
 * too. Additionally the minimum TTL is determined and set for the resource
 * records and signer. */
void
dnssec_set_rrset_validation_state(smartlist_t *rrset,
                                  const validation_state_t validation_state,
                                  dns_rr_t *signer)
{
  // determine minimum TTL as described in RFC 4035 section 5.3.3 last
  // paragraph.
  uint32_t minimum_ttl = 0;
  if (signer) {
    struct timeval now;
    tor_gettimeofday(&now);

    minimum_ttl = MIN(signer->ttl, signer->rrsig->original_ttl);
    minimum_ttl = MIN(minimum_ttl, signer->rrsig->signature_expiration -
                      (uint32_t) now.tv_sec);

    SMARTLIST_FOREACH_BEGIN(rrset, dns_rr_t *, rr) {
      minimum_ttl = MIN(minimum_ttl, rr->ttl);
    } SMARTLIST_FOREACH_END(rr);
  }

  // update validation state of all RRs in RRSet
  SMARTLIST_FOREACH_BEGIN(rrset, dns_rr_t *, rr) {
    if (minimum_ttl > 0) {
      rr->ttl = minimum_ttl;
      if (signer) {
        signer->ttl = minimum_ttl;
      }
    }

    rr->validation_state = validation_state;
    if (signer) {
      rr->signer = signer;
      signer->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
    }
    log_debug(LD_CRYPTO, "set rr validation state to %d for: %s",
              validation_state, dns_rr_str(rr));
  } SMARTLIST_FOREACH_END(rr);
}

/** Find potential signatures in <b>unauthenticated_rrset</b> as described in
 * RFC 4035 section 5.3.2.
 * Return the list of found signatures. */
smartlist_t *
dnssec_collect_signatures(const smartlist_t *unauthenticated_rrset,
                          const smartlist_t *authenticated_dnskey_rrset)
{
  // LCOV_EXCL_START
  tor_assert(unauthenticated_rrset);
  tor_assert(authenticated_dnskey_rrset);
  // LCOV_EXCL_STOP

  struct timeval now;
  tor_gettimeofday(&now);
  smartlist_t *signatures = smartlist_new();

  SMARTLIST_FOREACH_BEGIN(unauthenticated_rrset, dns_rr_t *, rr) {
    if (dns_type_is(rr->rrtype, DNS_TYPE_RRSIG) && rr->rrsig != NULL) {
      bool add = true;

      // The validator's notion of the current time MUST be less than or equal
      // to the time listed in the RRSIG RR's Expiration field.
      if ((uint32_t) now.tv_sec > rr->rrsig->signature_expiration) {
        log_debug(LD_CRYPTO, "signature expired (%d > %d)", (int) now.tv_sec,
                  (int) rr->rrsig->signature_expiration);
        add = false;
      }

      // The validator's notion of the current time MUST be greater than or
      // equal to the time listed in the RRSIG RR's Inception field.
      if ((uint32_t) now.tv_sec < rr->rrsig->signature_inception) {
        log_debug(LD_CRYPTO, "signature is not valid yet (%d > %d)",
                  (int) now.tv_sec, (int) rr->rrsig->signature_inception);
        add = false;
      }

      // There MUST be an RRSIG for each RRset using at least one DNSKEY of
      // each algorithm in the zone apex DNSKEY RRset.
      if (!dnssec_has_potential_dnskey(rr, authenticated_dnskey_rrset)) {
        log_debug(LD_CRYPTO, "missing potential DNSKEY");
        add = false;
      }

      if (add) {
        smartlist_add(signatures, rr);
      }
    }
  } SMARTLIST_FOREACH_END(rr);

  return signatures;
}

/** Assess if there is a potential DNSKEY present in
 * <b>authenticated_dnskey_rrset</b> for the given <b>rrsig</b> as described
 * in RFC 4034 section 2.1.2 and RFC 4035 section 5.3.2.
 * Return True if so, False otherwise. */
bool
dnssec_has_potential_dnskey(const dns_rr_t *signature,
                            const smartlist_t *authenticated_dnskey_rrset)
{
  // LCOV_EXCL_START
  tor_assert(signature);
  tor_assert(signature->rrsig);
  tor_assert(authenticated_dnskey_rrset);
  // LCOV_EXCL_STOP

  SMARTLIST_FOREACH_BEGIN(authenticated_dnskey_rrset, dns_rr_t *, dnskey) {
    bool potential_dnskey = dns_type_is(dnskey->rrtype, DNS_TYPE_DNSKEY);

    // The Protocol Field MUST have value 3, and the DNSKEY RR MUST be treated
    // as invalid during signature verification if it is found to be some value
    // other than 3.
    if (potential_dnskey && dnskey->dnskey->protocol != 3) {
      log_debug(LD_CRYPTO, "invalid protocol (%d)", dnskey->dnskey->protocol);
      potential_dnskey = false;
    }

    // The RRSIG RR's Signer's Name field MUST match the owner name for DNSKEY
    if (potential_dnskey && dns_name_compare(signature->rrsig->signer_name,
                                dnskey->name) != 0) {
      log_debug(LD_CRYPTO, "signer's name MUST be the owner name (%s != %s)",
                dns_name_str(signature->rrsig->signer_name),
                dnskey->name->value);
      potential_dnskey = false;
    }

    // The RRSIG RR's Algorithm field MUST match the algorithm for DNSKEY
    if (potential_dnskey &&
        signature->rrsig->algorithm != dnskey->dnskey->algorithm) {
      log_debug(LD_CRYPTO, "invalid algorithm (%d != %d)",
                signature->rrsig->algorithm, dnskey->dnskey->algorithm);
      potential_dnskey = false;
    }

    // The RRSIG RR's Key Tag field MUST match the key tag for DNSKEY
    uint16_t key_tag = dns_encode_key_tag(dnskey);
    if (potential_dnskey && signature->rrsig->key_tag != key_tag) {
      log_debug(LD_CRYPTO, "invalid key_tag (%d != %d)",
                signature->rrsig->key_tag, key_tag);
      potential_dnskey = false;
    }

    // This authentication process is only meaningful if the validator
    // authenticates the DNSKEY RR before using it to validate signatures.
    if (potential_dnskey &&
        dnskey->validation_state != DNSSEC_VALIDATION_STATE_SECURE) {
      log_debug(LD_CRYPTO, "invalid validation state (%d != %d)",
                dnskey->validation_state, DNSSEC_VALIDATION_STATE_SECURE);
      potential_dnskey = false;
    }

    // The matching DNSKEY RR MUST be present in the zone's apex DNSKEY RRset,
    // and MUST have the Zone Flag bit (DNSKEY RDATA Flag bit 7) set.
    if (potential_dnskey &&
        !(dnskey->dnskey->flags & DNS_DNSKEY_FLAG_ZONE)) {
      log_debug(LD_CRYPTO, "zone flag bit is not set (%d)",
                dnskey->dnskey->flags);
      potential_dnskey = false;
    }

    if (potential_dnskey) {
      return true;
    }
  } SMARTLIST_FOREACH_END(dnskey);

  return false;
}

/** Find resource records in <b>unauthenticated_rrset</b> that were signed with
 * the signature in <b>signature</b> as described in RFC 4035 section 5.3.1.
 * Return the list of resource records. */
smartlist_t *
dnssec_collect_rrset(const dns_rr_t *signature,
                     const smartlist_t *unauthenticated_rrset)
{
  // LCOV_EXCL_START
  tor_assert(signature);
  tor_assert(unauthenticated_rrset);
  // LCOV_EXCL_STOP

  smartlist_t *rrset = smartlist_new();
  SMARTLIST_FOREACH_BEGIN(unauthenticated_rrset, dns_rr_t *, rr) {
    bool potential_rr = true;

    // The RRSIG RR and the RRset MUST have the same owner name.
    if (potential_rr && dns_name_compare(signature->name, rr->name) != 0) {
      log_debug(LD_CRYPTO, "invalid owner name (%s != %s)",
                dns_name_str(signature->name), dns_name_str(rr->name));
      potential_rr = false;
    }

    // The RRSIG RR and the RRset MUST have the same class.
    if (potential_rr && signature->rrclass != rr->rrclass) {
      log_debug(LD_CRYPTO, "invalid class (%d != %d)", signature->rrclass,
                rr->rrclass);
      potential_rr = false;
    }

    // The RRSIG RR's Signer's Name field MUST be the name of the zone that
    // contains the RRset.
    if (potential_rr &&
        dns_name_is_part_of(signature->rrsig->signer_name, rr->name) < 0) {
      log_debug(LD_CRYPTO, "signer's name is not part of name (%s < %s)",
                dns_name_str(signature->rrsig->signer_name),
                dns_name_str(rr->name));
      potential_rr = false;
    }

    // The RRSIG RR's Type Covered field MUST equal the RRset's type.
    if (potential_rr && rr->rrtype &&
        signature->rrsig->type_covered->value != rr->rrtype->value) {
      log_debug(LD_CRYPTO, "rrset type is not covered (%s != %s)",
                rr->rrtype->name, signature->rrsig->type_covered->name);
      potential_rr = false;
    }

    // The number of labels in the RRset owner name MUST be greater than or
    // equal to the value in the RRSIG RR's Labels field.
    int rr_labels = dns_labels(rr->name);
    if (potential_rr && rr_labels < signature->rrsig->labels) {
      log_debug(LD_CRYPTO, "invalid number of labels (%d >= %d)", rr_labels,
                signature->rrsig->labels);
      potential_rr = false;
    }

    if (potential_rr) {
      log_debug(LD_CRYPTO, "adding: %s", dns_name_str(rr->name));
      smartlist_add(rrset, rr);
    }
  } SMARTLIST_FOREACH_END(rr);

  return rrset;
}

/** Validate RRSet by reconstructing the original signed data as described in
 * RFC 4035 section 5.3.2 and checking the signature as described in RFC 4035
 * section 5.3.3.
 * Return 0 in case the RRSet is valid, < 0 otherwise. */
int
dnssec_validate_rrset(smartlist_t *rrset, const smartlist_t *dnskey_rrset,
                      const smartlist_t *rrsig_rrset)
{
  // LCOV_EXCL_START
  tor_assert(rrset);
  tor_assert(dnskey_rrset);
  tor_assert(rrsig_rrset);
  // LCOV_EXCL_STOP

  int ret = -1;
  dns_rr_t *crrsig = NULL;
  smartlist_t *crrset = smartlist_new();
  uint8_t *signed_data = NULL;

  SMARTLIST_FOREACH_BEGIN(rrsig_rrset, dns_rr_t *, rrsig) {

    // prepare rrsig: remove signature and canonical form of signer's name
    dns_rr_free(crrsig);
    crrsig = dns_encode_canonical_rr(rrsig, rrsig->name, rrsig->ttl);

    // prepare rrset: update names to canonical form, and replace TTL with
    // original TTL
    SMARTLIST_FOREACH(crrset, dns_rr_t *, rr, dns_rr_free(rr));
    smartlist_clear(crrset);

    SMARTLIST_FOREACH_BEGIN(rrset, dns_rr_t *, rr) {
      dns_name_t *owner = dnssec_get_rr_owner(rr, rrsig->rrsig);
      log_debug(LD_CRYPTO, "set owner to %s and TTL to %d",
                dns_name_str(owner), rrsig->rrsig->original_ttl);
      smartlist_add(crrset, dns_encode_canonical_rr(rr, owner,
                                rrsig->rrsig->original_ttl));
      dns_name_free(owner);
    } SMARTLIST_FOREACH_END(rr);

    smartlist_sort(crrset, dnssec_comparator_canonical_rdata_ordering);

    // reconstruct the original signed data
    tor_free(signed_data);
    size_t signed_data_len = 0;

    if (dns_encode_signed_data(&signed_data, &signed_data_len, crrsig,
                               crrset) < 0) {
      // LCOV_EXCL_START
      log_debug(LD_CRYPTO, "creating signed data failed");
      ret = -2;
      goto cleanup;
      // LCOV_EXCL_STOP
    }

    // verify the original signed data
    SMARTLIST_FOREACH_BEGIN(dnskey_rrset, dns_rr_t *, dnskey) {
      if (dnssec_verify_signature(signed_data, signed_data_len, dnskey,
                                  rrsig) == 0) {
        dnssec_set_rrset_validation_state(rrset,
                                          DNSSEC_VALIDATION_STATE_SECURE,
                                          rrsig);
        ret = 0;
        goto cleanup;
      }
    } SMARTLIST_FOREACH_END(dnskey);

  } SMARTLIST_FOREACH_END(rrsig);

  dnssec_set_rrset_validation_state(rrset,
                                    DNSSEC_VALIDATION_STATE_INSECURE,
                                    NULL);

 cleanup:
  dns_rr_free(crrsig);
  SMARTLIST_FOREACH(crrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(crrset);
  tor_free(signed_data);
  return ret;
}

/** Verify signature in <b>rrsig</b> using the signed data in <b>data</b> as
 * described in RFC 4035 section 5.3.3.
 * Return 0 in case signature is verified, < 0 otherwise. */
int
dnssec_verify_signature(const uint8_t *data, const size_t data_len,
                        const dns_rr_t *dnskey, const dns_rr_t *rrsig)
{
  // LCOV_EXCL_START
  tor_assert(data);
  (void) data_len;
  tor_assert(dnskey);
  tor_assert(dnskey->dnskey);
  tor_assert(rrsig);
  tor_assert(rrsig->rrsig);
  // LCOV_EXCL_STOP

#ifdef ENABLE_OPENSSL

  const uint8_t *public_key = dnskey->dnskey->public_key;
  const size_t public_key_len = dnskey->dnskey->public_key_len;

  const uint8_t *signature = rrsig->rrsig->signature;
  const size_t signature_len = rrsig->rrsig->signature_len;

#endif /* defined(ENABLE_OPENSSL) */

  switch (rrsig->rrsig->algorithm) {

#ifdef ENABLE_OPENSSL

    case DNSSEC_ALG_RSASHA1:
    case DNSSEC_ALG_RSASHA1NSEC3SHA1:
      if (crypto_dnssec_verify_signature_rsa_sha1(data, data_len, public_key,
                                                  public_key_len, signature,
                                                  signature_len) < 0) {
        log_debug(LD_CRYPTO, "failed verifying signature using algorithm %d",
                  rrsig->rrsig->algorithm);
        return -1;
      }
      break;
    case DNSSEC_ALG_RSASHA256:
      if (crypto_dnssec_verify_signature_rsa_sha256(data, data_len, public_key,
                                                    public_key_len, signature,
                                                    signature_len) < 0) {
        log_debug(LD_CRYPTO, "failed verifying signature using algorithm %d",
                  rrsig->rrsig->algorithm);
        return -2;
      }
      break;
    case DNSSEC_ALG_RSASHA512:
      if (crypto_dnssec_verify_signature_rsa_sha512(data, data_len, public_key,
                                                    public_key_len, signature,
                                                    signature_len) < 0) {
        log_debug(LD_CRYPTO, "failed verifying signature using algorithm %d",
                  rrsig->rrsig->algorithm);
        return -3;
      }
      break;
    case DNSSEC_ALG_ECDSAP256SHA256:
      if (crypto_dnssec_verify_signature_ecdsa_p256_sha256(data, data_len,
                                                          public_key,
                                                          public_key_len,
                                                          signature,
                                                          signature_len) < 0) {
        log_debug(LD_CRYPTO, "failed verifying signature using algorithm %d",
                  rrsig->rrsig->algorithm);
        return -4;
      }
      break;
    case DNSSEC_ALG_ECDSAP384SHA384:
      if (crypto_dnssec_verify_signature_ecdsa_p384_sha384(data, data_len,
                                                          public_key,
                                                          public_key_len,
                                                          signature,
                                                          signature_len) < 0) {
        log_debug(LD_CRYPTO, "failed verifying signature using algorithm %d",
                  rrsig->rrsig->algorithm);
        return -5;
      }
      break;

#endif /* defined(ENABLE_OPENSSL) */

    default:
      log_info(LD_CRYPTO, "DNSSEC algorithm %d not implemented,",
               rrsig->rrsig->algorithm);
      return -6;
  }
  return 0;
}

/** Deny existence of <b>qname</b> or <b>qtype</b> using NSEC and store the
 * result in <b>result</b>. */
int
dnssec_nsec_denial_of_existence(denial_of_existence_t *result,
                                const dns_name_t *qname, const uint16_t qtype,
                                const dns_rr_t *rr, const smartlist_t *rrset)
{
  // LCOV_EXCL_START
  tor_assert(result);
  tor_assert(qname);
  tor_assert(rr);
  tor_assert(rr->nsec);
  tor_assert(rr->signer);
  tor_assert(rrset);
  // LCOV_EXCL_STOP

  int ret = 0;
  dns_name_t *owner = dnssec_get_rr_owner(rr, rr->signer->rrsig);

  // RFC 6840 section 4.1
  if (qtype != DNS_TYPE_DS && dns_name_is_part_of(owner, qname) >= 0 &&
      dnssec_is_ancestor_delegation(
          owner, rr->signer->rrsig->signer_name, rr->nsec->types)) {
    log_debug(LD_CRYPTO, "can only deny DS records");
    *result = DNSSEC_DENIAL_OF_EXISTENCE_NODATA;
    ret = 1;
    goto cleanup;
  }

  if (dns_name_compare(qname, owner) == 0) {

    // RFC 4035 section 5.4 bullet 1
    if (dns_type_present_in_smartlist(rr->nsec->types, qtype) == 1) {
      log_debug(LD_CRYPTO, "type exists: %d", qtype);
      *result = DNSSEC_DENIAL_OF_EXISTENCE_NODATA;
      ret = 2;
      goto cleanup;
    }

    // RFC 6840 section 4.3
    if (dns_type_present_in_smartlist(rr->nsec->types, DNS_TYPE_CNAME) == 1) {
      log_debug(LD_CRYPTO, "cname is present");
      *result = DNSSEC_DENIAL_OF_EXISTENCE_NODATA;
      ret = 3;
      goto cleanup;
    }

    // RFC 4035 section 2.3
    if (qtype == DNS_TYPE_DS &&
        dns_type_present_in_smartlist(rr->nsec->types, DNS_TYPE_NS) == 0) {
      log_debug(LD_CRYPTO, "insecure delegation: absent NS bit");
      *result = DNSSEC_DENIAL_OF_EXISTENCE_NODATA;
      ret = 4;
      goto cleanup;
    }

    // RFC 4035 section 5.4 bullet 1
    uint8_t owner_labels = dns_labels(owner);
    uint8_t signer_labels = dns_labels(rr->signer->rrsig->signer_name);

    bool wildcard_expanded = signer_labels < owner_labels;
    bool wildcard_expanded_onto_itself = owner->value[0] == '*' &&
                                         owner_labels == signer_labels;
    bool needWildcardProof = wildcard_expanded &&
                             !wildcard_expanded_onto_itself;

    if (!needWildcardProof ||
        dnssec_nsec_prove_no_wildcard(NULL, qname, qtype, rrset)) {
      log_debug(LD_CRYPTO, "denies existence of type: %d", qtype);
      *result = DNSSEC_DENIAL_OF_EXISTENCE_NXQTYPE;
      ret = 5;
      goto cleanup;
    }

    log_debug(LD_CRYPTO, "wildcard exists for: %s", dns_name_str(qname));
    *result = DNSSEC_DENIAL_OF_EXISTENCE_NODATA;
    ret = 6;
    goto cleanup;
  }

  if (dnssec_nsec_name_is_covered(qname, owner,
                                  rr->nsec->next_domain_name)) {

    bool wildcard_exists = false;
    if (dnssec_nsec_prove_no_wildcard(
            &wildcard_exists, qname, qtype, rrset) == 1 ||
        wildcard_exists) {
      log_debug(LD_CRYPTO, "wildcard exists for: %s", dns_name_str(qname));
      *result = DNSSEC_DENIAL_OF_EXISTENCE_NODATA;
      ret = 7;
      goto cleanup;
    }

    *result = DNSSEC_DENIAL_OF_EXISTENCE_NXDOMAIN;
    ret = 8;
    goto cleanup;
  }

  cleanup:
    dns_name_free(owner);
    return ret;
}

/** Prove that wildcard does not exist.
 * Return 0 if existence is denied, 1 if the wildcard or type is not denied. */
int
dnssec_nsec_prove_no_wildcard(bool *wildcard_exists, const dns_name_t *qname,
                              const uint16_t qtype, const smartlist_t *rrset)
{
  // LCOV_EXCL_START
  tor_assert(qname);
  tor_assert(rrset);
  // LCOV_EXCL_STOP

  int ret = 1;
  dns_name_t *owner = NULL;
  dns_name_t *wildcard = NULL;

  smartlist_t *sorted_rrset = smartlist_new();
  SMARTLIST_FOREACH(rrset, dns_rr_t *, rr, smartlist_add(sorted_rrset, rr));
  smartlist_sort(sorted_rrset, dnssec_comparator_canonical_name_ordering);

  SMARTLIST_FOREACH_BEGIN(sorted_rrset, dns_rr_t *, rr) {
    if (rr->validation_state == DNSSEC_VALIDATION_STATE_SECURE &&
        dns_type_is(rr->rrtype, DNS_TYPE_NSEC)) {
      dns_name_free(owner);
      owner = dnssec_get_rr_owner(rr, rr->signer->rrsig);
      int common_labels = dns_common_labels(owner, rr->nsec->next_domain_name);

      dns_name_free(wildcard);
      wildcard = dns_name_dup(qname);
      while (dns_labels(wildcard) > common_labels) {
        dns_strip_left_label(wildcard);
        dns_prepend_wildcard(wildcard);

        if (dns_name_compare(wildcard, rr->name) == 0) {
          if (wildcard_exists) {
            *wildcard_exists = true;
          }

          if (dns_type_present_in_smartlist(rr->nsec->types, qtype) == 0) {
            log_debug(LD_CRYPTO, "denies existence of type: %d", qtype);
            ret = 0;
            goto cleanup;
          }

          log_debug(LD_CRYPTO, "type exists: %d", qtype);
          ret = 1;
          goto cleanup;
        }

        if (dnssec_nsec_name_is_covered(
                wildcard, owner,
                rr->nsec->next_domain_name)) {
          log_debug(LD_CRYPTO, "denies existence of wildcard: %s",
                    dns_name_str(wildcard));
          ret = 0;
          goto cleanup;
        }

        dns_strip_left_label(wildcard);
      }
    }
  } SMARTLIST_FOREACH_END(rr);

 cleanup:
  smartlist_free(sorted_rrset);
  dns_name_free(owner);
  dns_name_free(wildcard);
  return ret;
}

/** Determine if <b>name</b> falls in between the interval of <b>owner</b>
 * and <b>next</b>.
 * Return True if so, False otherwise.
 */
bool
dnssec_nsec_name_is_covered(const dns_name_t *name, const dns_name_t *owner,
                            const dns_name_t *next)
{
  // LCOV_EXCL_START
  tor_assert(name);
  tor_assert(owner);
  tor_assert(next);
  // LCOV_EXCL_STOP

  log_debug(LD_CRYPTO, "%s <- %s -> %s", dns_name_str(owner),
            dns_name_str(name), dns_name_str(next));
  return dns_name_compare(owner, name) < 0 &&
         dns_name_compare(name, next) < 0;
}

/** Deny existence of <b>qtype</b> for <b>qname</b> using NSEC3 and store the
 * result in <b>result</b>. */
int
dnssec_nsec3_denial_of_existence(denial_of_existence_t *result,
                                 const dns_name_t *qname, const uint16_t qtype,
                                 const dns_rr_t *rr)
{
  // LCOV_EXCL_START
  tor_assert(result);
  tor_assert(qname);
  tor_assert(rr);
  tor_assert(rr->nsec3);
  tor_assert(rr->signer);
  // LCOV_EXCL_STOP

  int ret = 0;
  char *hash = NULL;
  if (dnssec_nsec3_hash(&hash, qname, rr) < 0) {
    // LCOV_EXCL_START
    log_debug(LD_CRYPTO, "failed computing nsec3 hash");
    *result = DNSSEC_DENIAL_OF_EXISTENCE_INSECURE;
    return -1;
    // LCOV_EXCL_STOP
  }

  // RFC 6840 section 4.1
  if (qtype != DNS_TYPE_DS &&
      strncasecmp(hash, dns_name_str(rr->name), strlen(hash)) == 0 &&
      dnssec_is_ancestor_delegation(
          rr->name, rr->signer->rrsig->signer_name, rr->nsec3->types)) {
    log_debug(LD_CRYPTO, "can only deny DS records");
    *result = DNSSEC_DENIAL_OF_EXISTENCE_NODATA;
    ret = 1;
    goto cleanup;
  }

  if (strncasecmp(hash, dns_name_str(rr->name), strlen(hash)) == 0) {

    // RFC 4035 section 5.4 bullet 1
    if (dns_type_present_in_smartlist(rr->nsec3->types, qtype) == 1) {
      log_debug(LD_CRYPTO, "type exists: %d", qtype);
      *result = DNSSEC_DENIAL_OF_EXISTENCE_NODATA;
      ret = 2;
      goto cleanup;
    }

    // RFC 6840 section 4.3
    if (dns_type_present_in_smartlist(rr->nsec3->types, DNS_TYPE_CNAME) == 1) {
      log_debug(LD_CRYPTO, "cname is present");
      *result = DNSSEC_DENIAL_OF_EXISTENCE_NODATA;
      ret = 3;
      goto cleanup;
    }

    // RFC 5155 section 8.9
    if (qtype == DNS_TYPE_DS &&
        dns_type_present_in_smartlist(rr->nsec3->types, DNS_TYPE_NS) == 0) {
      log_debug(LD_CRYPTO, "insecure delegation: absent NS bit");
      *result = DNSSEC_DENIAL_OF_EXISTENCE_NODATA;
      ret = 4;
      goto cleanup;
    }

    log_debug(LD_CRYPTO, "denies existence of type: %d", qtype);
    *result = DNSSEC_DENIAL_OF_EXISTENCE_NXQTYPE;
    ret = 5;
    goto cleanup;
  }

 cleanup:
  tor_free(hash);
  return ret;
}

/** Deny existence of <b>qname</b> or <b>qtype</b> using NSEC3 and store the
 * outcome in <b>result</b>. */
int
dnssec_nsec3_encloser_proof(denial_of_existence_t *result,
                            const dns_name_t *qname, const uint16_t qtype,
                            const smartlist_t *rrset)
{
  // LCOV_EXCL_START
  tor_assert(result);
  tor_assert(qname);
  tor_assert(rrset);
  // LCOV_EXCL_STOP

  int ret = 0;
  dns_name_t *closest_encloser = dns_name_new();

  // RFC 7129 section 5.5
  if (dnssec_nsec3_closest_encloser(
          &closest_encloser, qname, qtype, rrset) == 0) {

    bool opt_out = false;
    if (dnssec_nsec3_next_closer(
            &opt_out, closest_encloser, qname, qtype, rrset) == 0) {
      if (opt_out) {
        *result = DNSSEC_DENIAL_OF_EXISTENCE_OPTOUT;
        ret = 1;
        goto cleanup;
      }

      // RFC 7129 section 5.6
      bool wildcard_exists = false;
      if (dnssec_nsec3_prove_no_wildcard(
              &wildcard_exists, closest_encloser, qtype, rrset) == 1) {
        log_debug(LD_CRYPTO, "wildcard exists for: %s", dns_name_str(qname));
        *result = DNSSEC_DENIAL_OF_EXISTENCE_NODATA;
        ret = 2;
        goto cleanup;
      }

      if (wildcard_exists) {
        *result = DNSSEC_DENIAL_OF_EXISTENCE_NODATA;
        ret = 3;
        goto cleanup;
      }

      *result = DNSSEC_DENIAL_OF_EXISTENCE_NXDOMAIN;
      ret = 4;
      goto cleanup;
    }
  }

 cleanup:
  dns_name_free(closest_encloser);
  return ret;
}

/** Find closest encloser for <b>qname</b> using nsec records from
 * <b>rrset</b>.
 * Return 0 when found, < 0 otherwise. */
int
dnssec_nsec3_closest_encloser(dns_name_t **closest_encloser,
                              const dns_name_t *qname, const uint16_t qtype,
                              const smartlist_t *rrset)
{
  // LCOV_EXCL_START
  tor_assert(closest_encloser);
  tor_assert(qname);
  tor_assert(rrset);
  // LCOV_EXCL_STOP

  int ret = -1;
  char *hash = NULL;

  dns_name_free(*closest_encloser);
  *closest_encloser = dns_name_dup(qname);

  while ((*closest_encloser)->length > 0) {
    dns_strip_left_label(*closest_encloser);

    SMARTLIST_FOREACH_BEGIN(rrset, dns_rr_t *, rr) {
      if (rr->validation_state == DNSSEC_VALIDATION_STATE_SECURE &&
          dns_type_is(rr->rrtype, DNS_TYPE_NSEC3)) {
        if (dnssec_nsec3_hash(&hash, *closest_encloser, rr) < 0) {
          // LCOV_EXCL_START
          log_debug(LD_CRYPTO, "failed computing nsec3 hash");
          ret = -2;
          goto cleanup;
          // LCOV_EXCL_STOP
        }

        if (strncasecmp(hash, dns_name_str(rr->name), strlen(hash)) == 0) {
          if (qtype != DNS_TYPE_DS &&
              dnssec_is_ancestor_delegation(rr->name,
                                            rr->signer->rrsig->signer_name,
                                            rr->nsec3->types)) {
            log_debug(LD_CRYPTO, "can only deny DS records");
          } else {
            log_debug(LD_CRYPTO, "closest encloser for %s is %s",
                      dns_name_str(qname), dns_name_str(*closest_encloser));
            ret = 0;
            goto cleanup;
          }
        }
      }
    } SMARTLIST_FOREACH_END(rr);
  }

 cleanup:
  tor_free(hash);
  return ret;
}

/** Find next closer encloser for <b>qname</b> using <b>closest_encloser</b>
 * and nsec records from <b>rrset</b>.
 * Return 0 when found, < 0 otherwise. */
int
dnssec_nsec3_next_closer(bool *opt_out, const dns_name_t *closest_encloser,
                         const dns_name_t *qname, const uint16_t qtype,
                         const smartlist_t *rrset)
{
  // LCOV_EXCL_START
  tor_assert(opt_out);
  tor_assert(closest_encloser);
  tor_assert(qname);
  tor_assert(rrset);
  // LCOV_EXCL_STOP

  int ret = -1;
  char *hash = NULL;
  dns_name_t *next_closer = NULL;

  int zone_index = dns_labels(qname) - dns_labels(closest_encloser);

  if (zone_index == 0) {
    log_debug(LD_CRYPTO, "closest encloser is qname");
    ret = -2;
    goto cleanup;
  }

  if (zone_index > 0) {
    next_closer = dns_name_dup(qname);
    for (int labels = zone_index - 1; labels > 0; labels--) {
      dns_strip_left_label(next_closer);
    }

    SMARTLIST_FOREACH_BEGIN(rrset, dns_rr_t *, rr) {
      if (rr->validation_state == DNSSEC_VALIDATION_STATE_SECURE &&
          dns_type_is(rr->rrtype, DNS_TYPE_NSEC3)) {
        if (dnssec_nsec3_hash(&hash, next_closer, rr) < 0) {
          // LCOV_EXCL_START
          log_debug(LD_CRYPTO, "failed computing nsec3 hash");
          ret = -3;
          goto cleanup;
          // LCOV_EXCL_STOP
        }

        if (dnssec_nsec3_hash_is_covered(hash, rr->name,
                rr->nsec3->next_hashed_owner_name, rr->nsec3->hash_length)) {

          if (qtype == DNS_TYPE_DS &&
              rr->nsec3->flags & DNS_NSEC3_FLAG_OPT_OUT) {
            log_debug(LD_CRYPTO, "NSEC3 opt-out flag is present");
            *opt_out = true;
          }

          log_debug(LD_CRYPTO, "denies existence of name %s/%d",
                    dns_name_str(qname), qtype);
          ret = 0;
          goto cleanup;
        }
      }
    } SMARTLIST_FOREACH_END(rr);
  }

 cleanup:
  tor_free(hash);
  dns_name_free(next_closer);
  return ret;
}

/** Prove that either wildcard does not exist or that the type for a wildcard
 * record does not exist.
 * Return 0 if existence is denied, 1 if the wildcard or type is not denied,
 * and < 0 if an error occurred. */
int
dnssec_nsec3_prove_no_wildcard(bool *wildcard_exists,
                               const dns_name_t *closest_encloser,
                               const uint16_t qtype, const smartlist_t *rrset)
{
  // LCOV_EXCL_START
  tor_assert(closest_encloser);
  tor_assert(rrset);
  // LCOV_EXCL_STOP

  int ret = 1;
  char *hash = NULL;
  dns_name_t *wildcard = dns_name_dup(closest_encloser);
  dns_prepend_wildcard(wildcard);

  SMARTLIST_FOREACH_BEGIN(rrset, dns_rr_t *, rr) {
    if (rr->validation_state == DNSSEC_VALIDATION_STATE_SECURE &&
        dns_type_is(rr->rrtype, DNS_TYPE_NSEC3)) {
      if (dnssec_nsec3_hash(&hash, wildcard, rr) < 0) {
        // LCOV_EXCL_START
        log_debug(LD_CRYPTO, "failed computing nsec3 hash");
        ret = -1;
        goto cleanup;
        // LCOV_EXCL_STOP
      }

      if (strncasecmp(hash, dns_name_str(rr->name), strlen(hash)) == 0) {
        if (wildcard_exists) {
          *wildcard_exists = true;
        }

        if (dns_type_present_in_smartlist(rr->nsec3->types, qtype) == 0) {
          log_debug(LD_CRYPTO, "denies existence of type: %d", qtype);
          ret = 0;
          goto cleanup;
        }

        log_debug(LD_CRYPTO, "type exists: %d", qtype);
        ret = 1;
        goto cleanup;
      }

      if (dnssec_nsec3_hash_is_covered(hash,
                                       rr->name,
                                       rr->nsec3->next_hashed_owner_name,
                                       rr->nsec3->hash_length)) {
        log_debug(LD_CRYPTO, "denies existence of wildcard: %s",
                  dns_name_str(wildcard));
        ret = 0;
        goto cleanup;
      }
    }
  } SMARTLIST_FOREACH_END(rr);

 cleanup:
  dns_name_free(wildcard);
  tor_free(hash);
  return ret;
}

/** Determine if <b>hash</b> falls in between the interval of <b>owner</b>
 * and <b>next_hashed_owner_name</b>.
 * Return True if so, False otherwise.
 */
bool
dnssec_nsec3_hash_is_covered(const char *hash, const dns_name_t *owner,
                             const uint8_t *next_hashed_owner_name,
                             const uint8_t hash_length)
{
  // LCOV_EXCL_START
  tor_assert(hash);
  tor_assert(owner);
  tor_assert(next_hashed_owner_name);
  // LCOV_EXCL_STOP

  char next[BASE32_DIGEST_LEN + 1];
  base32hex_encode(next, sizeof(next),
      (const char *) next_hashed_owner_name, hash_length);

  log_debug(LD_CRYPTO, "%s <- %s -> %s", dns_name_str(owner), hash, next);
  return strncasecmp(dns_name_str(owner), hash, strlen(hash)) < 0 &&
         strncasecmp(hash, next, strlen(hash)) < 0;
}

/** Return NSEC3 hash in <b>hash</b> for <b>name</b> using the parameters
 * (salt, iterations) from given <b>rr</b>.
 * Return 0 on success, < 0 otherwise.
 */
int
dnssec_nsec3_hash(char **hash, const dns_name_t *name, const dns_rr_t *rr)
{
  // LCOV_EXCL_START
  tor_assert(hash);
  tor_assert(name);
  tor_assert(rr);
  tor_assert(rr->rrtype);
  // LCOV_EXCL_STOP

  int ret = 0;
  uint8_t *qname = NULL;

  uint16_t iterations = 0;
  uint8_t salt_length = 0;
  uint8_t *salt = NULL;

  if (dns_type_is(rr->rrtype, DNS_TYPE_NSEC3) && rr->nsec3) {
    iterations = rr->nsec3->iterations;
    salt_length = rr->nsec3->salt_length;
    salt = rr->nsec3->salt;
  }

  if (dns_type_is(rr->rrtype, DNS_TYPE_NSEC3PARAM) && rr->nsec3param) {
    iterations = rr->nsec3param->iterations;
    salt_length = rr->nsec3param->salt_length;
    salt = rr->nsec3param->salt;
  }

  if (!salt) {
    log_debug(LD_CRYPTO, "unable to get salt from rr of type: %s",
              rr->rrtype->name);
    ret = -1;
    goto cleanup;
  }

  size_t qname_len = 0;
  qname = dns_encode_canonical_name(name, &qname_len);

  uint8_t digest[DIGEST_LEN];
  if (dnssec_nsec3_digest_sha1(digest, qname, qname_len,
                               salt, salt_length, iterations) < 0) {
    // LCOV_EXCL_START
    log_debug(LD_CRYPTO, "failed computing digest");
    ret = -2;
    goto cleanup;
    // LCOV_EXCL_STOP
  }

  tor_free(*hash);
  *hash = tor_malloc_zero(BASE32_DIGEST_LEN + 1);
  base32hex_encode(*hash, BASE32_DIGEST_LEN + 1,
                   (const char *) digest, DIGEST_LEN);

 cleanup:
  tor_free(qname);
  return ret;
}

/** Compute the NSEC3 SHA1 digest for the given <b>name</b> and <b>salt</b>.
 * The number of rounds are defined by <b>iterations</b>.
 * The resulting DIGEST_LEN bytes are written to <b>digest</b>.
 * Return 0 on success, < 0 otherwise.
 */
int
dnssec_nsec3_digest_sha1(uint8_t *digest, const uint8_t *name,
                         const uint8_t name_length, const uint8_t *salt,
                         const uint8_t salt_length, const uint16_t iterations)
{
  // LCOV_EXCL_START
  tor_assert(digest);
  tor_assert(name);
  tor_assert(salt);
  // LCOV_EXCL_STOP

  char buf[2 * 255];

  memcpy(buf, name, name_length);
  memcpy(buf + name_length, salt, salt_length);
  size_t buf_len = name_length + salt_length;

  if (crypto_digest((char *) digest, (const char *) buf, buf_len) < 0) {
    // LCOV_EXCL_START
    log_debug(LD_CRYPTO, "failed computing digest");
    return -1;
    // LCOV_EXCL_STOP
  }

  if (iterations > 0) {
    return dnssec_nsec3_digest_sha1(digest, digest, DIGEST_LEN, salt,
                                    salt_length, iterations - 1);
  }
  return 0;
}

/** Determine if ancestor delegation constraints are met as described in
 * RFC 6840 section 4.1 */
bool
dnssec_is_ancestor_delegation(const dns_name_t *owner,
                              const dns_name_t *signer,
                              const smartlist_t *types)
{
  // LCOV_EXCL_START
  tor_assert(types);
  // LCOV_EXCL_STOP

  return dns_type_present_in_smartlist(types, DNS_TYPE_NS) == 1 &&
         dns_type_present_in_smartlist(types, DNS_TYPE_SOA) == 0 &&
         dns_labels(signer) < dns_labels(owner);
}

/** Return RR owner name as described in RFC 4034 section 3.1.3 */
dns_name_t *
dnssec_get_rr_owner(const dns_rr_t *rr, const dns_rrsig_t *rrsig)
{
  // LCOV_EXCL_START
  tor_assert(rr);
  tor_assert(rr->name);
  tor_assert(rrsig);
  // LCOV_EXCL_STOP

  dns_name_t *name = dns_name_dup(rr->name);
  uint8_t labels = dns_labels(name);

  if (rrsig->labels > 0 && rrsig->labels < labels) {
    for (int i = 0; i < labels - rrsig->labels; i++) {
      dns_strip_left_label(name);
    }
    dns_prepend_wildcard(name);
  }

  return name;
}

/** Comparator for canonical name ordering. */
int
dnssec_comparator_canonical_name_ordering(const void **a_, const void **b_)
{
  const dns_rr_t *a = *a_,
                 *b = *b_;
  if (!a || !b || !a->rdata || !b->rdata) {
    return 0;
  }
  return dns_name_compare(a->name, b->name);
}

/** Comparator for canonical rdata ordering. */
int
dnssec_comparator_canonical_rdata_ordering(const void **a_, const void **b_)
{
  const dns_rr_t *a = *a_,
                 *b = *b_;
  if (!a || !b || !a->rdata || !b->rdata) {
    return 0;
  }
  return fast_memcmp(a->rdata, b->rdata, MIN(a->rdlength, b->rdlength));
}

/** Return the number of labels of given DNS name. */
int
dns_labels(const dns_name_t *name)
{
  if (!name || !name->value) {
    return 0;
  }

  int label_len = 0;
  int labels = 0;

  for (uint8_t i = 0; i < name->length; i++) {
    if (name->value[i] == '.') {
      if (label_len > 0) {
        labels++;
      }
      label_len = 0;
    } else if (!TOR_ISSPACE(name->value[i])) {
      label_len++;
    }
  }

  if (label_len > 0) {
    labels++;
  }

  return labels;
}

/** Return the number of labels the two given DNS names <b>this</b> and
 * <b>that</b> have in common. */
int
dns_common_labels(const dns_name_t *this, const dns_name_t *that)
{
  if (!this || !this->value || !that || !that->value) {
    return 0;
  }

  int label_len = 0;
  int labels = 0;

  for (int i = (int) this->length - 1, j = (int) that->length - 1;
       i >= 0 && j >= 0;
       i--, j--) {

    if (this->value[i] == '.') {
      if (label_len > 0) {
        labels++;
      }
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

    if (label_len > 0 &&
        TOR_TOLOWER(this->value[i]) != TOR_TOLOWER(that->value[j])) {
      return labels;
    }
  }

  if (label_len > 0) {
    labels++;
  }

  return labels;
}

/** Remove the left label from the given DNS name. */
void
dns_strip_left_label(dns_name_t *name)
{
  if (!name || !name->value) {
    return;
  }

  int pos = 0;
  while (pos < name->length && name->value[pos++] != '.');

  if (pos > 0) {
    name->length -= pos;
    char *short_name = tor_memdup(&name->value[pos], name->length + 1);
    tor_free(name->value);
    name->value = tor_memdup(short_name, name->length + 1);
    tor_free(short_name);
  }
}

/** Prepend wildcard to the given DNS name. */
void
dns_prepend_wildcard(dns_name_t *name)
{
  if (!name || !name->value) {
    return;
  }

  char *wildcard_name = NULL;
  if (name->value[0] == '.') {
    wildcard_name = tor_malloc_zero(name->length + 2);
    wildcard_name[0] = '*';
    memcpy(&wildcard_name[1], name->value, name->length);
    name->length += 1;
  } else {
    wildcard_name = tor_malloc_zero(name->length + 3);
    wildcard_name[0] = '*';
    wildcard_name[1] = '.';
    memcpy(&wildcard_name[2], name->value, name->length);
    name->length += 2;
  }

  tor_free(name->value);
  name->value = tor_memdup(wildcard_name, name->length + 1);
  tor_free(wildcard_name);
}
