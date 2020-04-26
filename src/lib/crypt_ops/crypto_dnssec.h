/* Copyright (c) 2019 Christian Hofer.
 * Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypto_dnssec.h
 * \brief Header file for crypto_dnssec.c.
 **/

#ifndef TOR_CRYPTO_DNSSEC_H
#define TOR_CRYPTO_DNSSEC_H

#include "lib/cc/torint.h"
#include "lib/container/dns_message_st.h"
#include "lib/smartlist_core/smartlist_core.h"
#include "lib/testsupport/testsupport.h"

//
// DNSSEC Signature Algorithms

#define DNSSEC_ALG_DELETE              0  // Delete DS
                                          //        [RFC4034][RFC4398][RFC8078]
#define DNSSEC_ALG_RSAMD5              1  // RSA/MD5         [RFC3110][RFC4034]
#define DNSSEC_ALG_DH                  2  // Diffie-Hellman           [RFC2539]
#define DNSSEC_ALG_DSA                 3  // DSA/SHA-1       [RFC3755][RFC2536]
#define DNSSEC_ALG_4                   4  // Reserved                 [RFC6725]
#define DNSSEC_ALG_RSASHA1             5  // RSA/SHA-1       [RFC3110][RFC4034]
#define DNSSEC_ALG_DSANSEC3SHA1        6  // DSA-NSEC3-SHA1           [RFC5155]
#define DNSSEC_ALG_RSASHA1NSEC3SHA1    7  // RSASHA1-NSEC3-SHA1       [RFC5155]
#define DNSSEC_ALG_RSASHA256           8  // RSA/SHA-256              [RFC5702]
#define DNSSEC_ALG_9                   9  // Reserved                 [RFC6725]
#define DNSSEC_ALG_RSASHA512          10  // RSA/SHA-512              [RFC5702]
#define DNSSEC_ALG_11                 11  // Reserved                 [RFC6725]
#define DNSSEC_ALG_ECCGOST            12  // GOST R 34.10-2001        [RFC5933]
#define DNSSEC_ALG_ECDSAP256SHA256    13  // ECDSA Curve P-256 with SHA-256
                                          //                          [RFC6605]
#define DNSSEC_ALG_ECDSAP384SHA384    14  // ECDSA Curve P-384 with SHA-384
                                          //                          [RFC6605]
#define DNSSEC_ALG_ED25519            15  // Ed25519                  [RFC8080]
#define DNSSEC_ALG_ED448              16  // Ed448                    [RFC8080]
#define DNSSEC_ALG_INDIRECT          252  // Reserved for Indirect Keys
                                          //                          [RFC4034]
#define DNSSEC_ALG_PRIVATEDNS        253  // Private algorithm        [RFC4034]
#define DNSSEC_ALG_PRIVATEOID        254  // Private algorithm OID    [RFC4034]
#define DNSSEC_ALG_255               255  // Reserved                 [RFC4034]

//
// DNSSEC Digest Algorithms

#define DNSSEC_DIGEST_0       0  // Reserved         [RFC3658]
#define DNSSEC_DIGEST_SHA1    1  // SHA-1            [RFC3658]
#define DNSSEC_DIGEST_SHA256  2  // SHA-256          [RFC4509]
#define DNSSEC_DIGEST_GOST    3  // GOST R 34.11-94  [RFC5933]
#define DNSSEC_DIGEST_SHA384  4  // SHA-384          [RFC6605]

//
// DNSSEC Denial of Existence States

typedef enum denial_of_existence_t {
  DNSSEC_DENIAL_OF_EXISTENCE_NODATA,
  DNSSEC_DENIAL_OF_EXISTENCE_NXDOMAIN,
  DNSSEC_DENIAL_OF_EXISTENCE_NXQTYPE,
  DNSSEC_DENIAL_OF_EXISTENCE_INSECURE,
  DNSSEC_DENIAL_OF_EXISTENCE_OPTOUT
} denial_of_existence_t;

MOCK_DECL(int, dnssec_authenticate_rrset,
          (const smartlist_t *unauthenticated_rrset,
           const smartlist_t *authenticated_dnskey_rrset));

MOCK_DECL(int, dnssec_authenticate_delegation_to_child_zone,
          (smartlist_t *authenticated_dnskey_rrset,
           const smartlist_t *unauthenticated_rrset,
           const smartlist_t *ds_rrset));

MOCK_DECL(denial_of_existence_t, dnssec_denial_of_existence,
          (const dns_name_t *qname, const uint16_t qtype,
           const smartlist_t *rrset));

#ifdef CRYPTO_DNSSEC_PRIVATE

void dnssec_set_rrset_validation_state(smartlist_t *rrset,
                                     const validation_state_t validation_state,
                                     dns_rr_t *signer);

smartlist_t *dnssec_collect_signatures(
                                const smartlist_t *unauthenticated_rrset,
                                const smartlist_t *authenticated_dnskey_rrset);
bool dnssec_has_potential_dnskey(const dns_rr_t *signature,
                                const smartlist_t *authenticated_dnskey_rrset);
smartlist_t *dnssec_collect_rrset(const dns_rr_t *signature,
                                  const smartlist_t *unauthenticated_rrset);

int dnssec_validate_rrset(smartlist_t *rrset, const smartlist_t *dnskey_rrset,
                          const smartlist_t *rrsig_rrset);
int dnssec_verify_signature(const uint8_t *data, const size_t data_len,
                            const dns_rr_t * dnskey, const dns_rr_t * rrsig);

int crypto_dnssec_verify_signature_rsa_sha1(const uint8_t *data,
                                            const size_t data_len,
                                            const uint8_t *public_key,
                                            const size_t public_key_len,
                                            const uint8_t *signature,
                                            const size_t signature_len);
int crypto_dnssec_verify_signature_rsa_sha256(const uint8_t *data,
                                              const size_t data_len,
                                              const uint8_t *public_key,
                                              const size_t public_key_len,
                                              const uint8_t *signature,
                                              const size_t signature_len);
int crypto_dnssec_verify_signature_rsa_sha512(const uint8_t *data,
                                              const size_t data_len,
                                              const uint8_t *public_key,
                                              const size_t public_key_len,
                                              const uint8_t *signature,
                                              const size_t signature_len);
int crypto_dnssec_verify_signature_ecdsa_p256_sha256(const uint8_t *data,
                                                   const size_t data_len,
                                                   const uint8_t *public_key,
                                                   const size_t public_key_len,
                                                   const uint8_t *signature,
                                                   const size_t signature_len);
int crypto_dnssec_verify_signature_ecdsa_p384_sha384(const uint8_t *data,
                                                   const size_t data_len,
                                                   const uint8_t *public_key,
                                                   const size_t public_key_len,
                                                   const uint8_t *signature,
                                                   const size_t signature_len);

int crypto_dnssec_verify_digest_sha1(const uint8_t *data,
                                     const size_t data_len,
                                     const uint8_t *digest,
                                     const size_t digest_len);
int crypto_dnssec_verify_digest_sha256(const uint8_t *data,
                                       const size_t data_len,
                                       const uint8_t *digest,
                                       const size_t digest_len);
int crypto_dnssec_verify_digest_sha384(const uint8_t *data,
                                       const size_t data_len,
                                       const uint8_t *digest,
                                       const size_t digest_len);

int dnssec_nsec_denial_of_existence(denial_of_existence_t *result,
                                    const dns_name_t *qname,
                                    const uint16_t qtype, const dns_rr_t *rr,
                                    const smartlist_t *rrset);
int dnssec_nsec_prove_no_wildcard(bool *wildcard_exists,
                                  const dns_name_t *qname,
                                  const uint16_t qtype,
                                  const smartlist_t *rrset);
bool dnssec_nsec_name_is_covered(const dns_name_t *name,
                                 const dns_name_t *owner,
                                 const dns_name_t *next);
int dnssec_nsec3_denial_of_existence(denial_of_existence_t *result,
                                     const dns_name_t *qname,
                                     const uint16_t qtype, const dns_rr_t *rr);
int dnssec_nsec3_encloser_proof(denial_of_existence_t *result,
                                const dns_name_t *qname, const uint16_t qtype,
                                const smartlist_t *rrset);
int dnssec_nsec3_closest_encloser(dns_name_t **closest_encloser,
                                  const dns_name_t *qname,
                                  const uint16_t qtype,
                                  const smartlist_t *rrset);
int dnssec_nsec3_next_closer(bool *opt_out, const dns_name_t *closest_encloser,
                             const dns_name_t *qname, const uint16_t qtype,
                             const smartlist_t *rrset);
int dnssec_nsec3_prove_no_wildcard(bool *wildcard_exists,
                                   const dns_name_t *closest_encloser,
                                   const uint16_t qtype,
                                   const smartlist_t *rrset);
bool dnssec_nsec3_hash_is_covered(const char *hash, const dns_name_t *owner,
                                  const uint8_t *next_hashed_owner_name,
                                  const uint8_t hash_length);
int dnssec_nsec3_hash(char **hash, const dns_name_t *name, const dns_rr_t *rr);
int dnssec_nsec3_digest_sha1(uint8_t *digest, const uint8_t *name,
                             const uint8_t name_length, const uint8_t *salt,
                             const uint8_t salt_length,
                             const uint16_t iterations);

bool dnssec_is_ancestor_delegation(const dns_name_t *owner,
                                   const dns_name_t *signer,
                                   const smartlist_t *types);
dns_name_t *dnssec_get_rr_owner(const dns_rr_t *rr, const dns_rrsig_t *rrsig);

int dnssec_comparator_canonical_name_ordering(const void **a_,
                                              const void **b_);
int dnssec_comparator_canonical_rdata_ordering(const void **a_,
                                               const void **b_);

int dns_labels(const dns_name_t *name);
int dns_common_labels(const dns_name_t *this, const dns_name_t *that);
void dns_strip_left_label(dns_name_t *name);
void dns_prepend_wildcard(dns_name_t *name);

#endif /* defined(CRYPTO_DNSSEC_PRIVATE) */

#endif
