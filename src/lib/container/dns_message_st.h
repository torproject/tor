/* Copyright (c) 2019 Christian Hofer.
 * Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_DNS_MESSAGE_ST_H
#define TOR_DNS_MESSAGE_ST_H

#include "lib/cc/torint.h"
#include "lib/smartlist_core/smartlist_core.h"
#include "lib/wallclock/timeval.h"

typedef struct dns_name_t {
  uint8_t length;
  char *value;
} dns_name_t;

typedef struct dns_type_t {
  uint16_t value;
  char *name;
} dns_type_t;

//
// Header

typedef struct dns_header_t {
  /** A 16 bit identifier assigned by the program that generates any kind of
   * query. This identifier is copied the corresponding reply and can be used
   * by the requester to match up replies to outstanding queries.
   */
  uint16_t id;
  /** A one bit field that specifies whether this message is a query (0), or
   * a response (1).
   */
  bool qr;
  /** A four bit field that specifies kind of query in this message. This value
   * is set by the originator of a query and copied into the response.
   */
  uint8_t opcode;
  /** Authoritative Answer - this bit is valid in responses, and specifies that
   * the responding name server is an authority for the domain name in question
   * section. Note that the contents of the answer section may have multiple
   * owner names because of aliases. The AA bit corresponds to the name which
   * matches the query name, or the first owner name in the answer section.
   */
  bool aa;
  /** TrunCation - specifies that this message was truncated due to length
   * greater than that permitted on the transmission channel.
   */
  bool tc;
  /** Recursion Desired - this bit may be set in a query and is copied into the
   * response. If RD is set, it directs the name server to pursue the query
   * recursively. Recursive query support is optional.
   */
  bool rd;
  /** Recursion Available - this bit is set or cleared in a response, and
   * denotes whether recursive query support is available in the name
   * server.
   */
  bool ra;
  /** Reserved for future use. Must be zero in all queries and responses.
   */
  bool z;
  /** Indicates in a response that all the data included in the answer and
   * authority portion of the response has been authenticated by the server
   * according to the policies of that server.
   */
  bool ad;
  /** Indicates in a query that Pending (non-authenticated) data is acceptable
   * to the resolver sending the query.
   */
  bool cd;
  /** Response code - this 4 bit field is set as part of responses.
   */
  uint8_t rcode;
  /** An unsigned 16 bit integer specifying the number of entries in the
   * question section.
   */
  uint16_t qdcount;
  /** An unsigned 16 bit integer specifying the number of resource records in
   * the answer section.
   */
  uint16_t ancount;
  /** An unsigned 16 bit integer specifying the number of name server resource
   * records in the authority records section.
   */
  uint16_t nscount;
  /** An unsigned 16 bit integer specifying the number of resource records in
   * the additional records section.
   */
  uint16_t arcount;
} dns_header_t;

//
// Question

typedef struct dns_question_t {
  /** A domain name represented as a sequence of labels, where each label
   * consists of a length octet followed by that number of octets. The domain
   * name terminates with the zero length octet for the null label of the root.
   * Note that this field may be an odd number of octets; no padding is used.
   */
  dns_name_t *qname;
  /** A two octet code which specifies the type of the query. The values for
   * this field include all codes valid for a TYPE field, together with some
   * more general codes which can match more than one type of RR.
   */
  dns_type_t *qtype;
  /** A two octet code that specifies the class of the query. For example, the
   * QCLASS field is IN for the Internet.
   */
  uint16_t qclass;
} dns_question_t;

//
// Resource Record - SOA

typedef struct dns_soa_t {
  /** The <domain-name> of the name server that was the
   * original or primary source of data for this zone.
   */
  dns_name_t *mname;
  /** A <domain-name> which specifies the mailbox of the
   * person responsible for this zone.
   */
  dns_name_t *rname;
  /** The unsigned 32 bit version number of the original copy
   * of the zone. Zone transfers preserve this value. This
   * value wraps and should be compared using sequence space
   * arithmetic.
   */
  uint32_t serial;
  /** A 32 bit time interval before the zone should be
   * refreshed.
   */
  uint32_t refresh;
  /** A 32 bit time interval that should elapse before a
   * failed refresh should be retried.
   */
  uint32_t retry;
  /** A 32 bit time value that specifies the upper limit on
   * the time interval that can elapse before the zone is no
   * longer authoritative.
   */
  uint32_t expire;
  /** The unsigned 32 bit minimum TTL field that should be
   * exported with any RR from this zone.
   */
    uint32_t minimum;
} dns_soa_t;

//
// Resource Record - MX

typedef struct dns_mx_t {
  /** A 16 bit integer which specifies the preference given to this RR among
   * others at the same owner. Lower values are preferred.
   */
  uint16_t preference;
  /** A <domain-name> which specifies a host willing to act as a mail exchange
   * for the owner name.
   */
  dns_name_t *exchange;
} dns_mx_t;

//
// Resource Record - KEY

typedef struct dns_key_t {
  /** Bit 0 and 1 are the key "type" bits,
   * Bits 2 is reserved and must be zero.
   * Bits 3 is reserved as a flag extension bit.
   * Bits 4-5 are reserved and must be zero.
   * Bits 6 and 7 form a field that encodes the name type.
   * Bits 8-11 are reserved and must be zero.
   * Bits 12-15 are the "signatory" field.
   */
  uint16_t flags;
  /** It is anticipated that keys stored in DNS will be used in conjunction
   * with a variety of Internet protocols.  It is intended that the
   * protocol octet and possibly some of the currently unused (must be
   * zero) bits in the KEY RR flags as specified in the future will be
   * used to indicate a key's validity for different protocols.
   */
  uint8_t protocol;
  /** This octet is the key algorithm parallel to the same field for the
   * SIG resource as described in RFC 2535 section 4.1.
   */
  uint8_t algorithm;
  /** The Public Key Field holds the public key material.
   */
  uint8_t *public_key;
  uint16_t public_key_len;
} dns_key_t;

//
// Resource Record - DS

typedef struct dns_ds_t {
  /** The Key Tag field lists the key tag of the DNSKEY RR referred to by
   * the DS record, in network byte order.
   */
  uint16_t key_tag;
  /** The Algorithm field lists the algorithm number of the DNSKEY RR
   * referred to by the DS record.
   */
  uint8_t algorithm;
  /** The DS RR refers to a DNSKEY RR by including a digest of that DNSKEY
   * RR. The Digest Type field identifies the algorithm used to construct
   * the digest.
   */
  uint8_t digest_type;
  /** The DS record refers to a DNSKEY RR by including a digest of that
   * DNSKEY RR.
   */
  uint8_t *digest;
  uint16_t digest_len;
} dns_ds_t;

//
// Resource Record - RRSIG

typedef struct dns_rrsig_t {
  /** The Type Covered field identifies the type of the RRset that is
   * covered by this RRSIG record.
   */
  dns_type_t *type_covered;
  /** The Algorithm Number field identifies the cryptographic algorithm
   * used to create the signature.
   */
  uint8_t algorithm;
  /** The Labels field specifies the number of labels in the original RRSIG
   * RR owner name.
   */
  uint8_t labels;
  /** The Original TTL field specifies the TTL of the covered RRset as it
   * appears in the authoritative zone.
   */
  uint32_t original_ttl;
  /** The Signature Expiration and Inception fields specify a validity
   * period for the signature. The RRSIG record MUST NOT be used for
   * authentication prior to the inception date and MUST NOT be used for
   * authentication after the expiration date.
   */
  uint32_t signature_expiration;
  uint32_t signature_inception;
  /** The Key Tag field contains the key tag value of the DNSKEY RR that
   * validates this signature.
   */
  uint16_t key_tag;
  /** The Signer's Name field value identifies the owner name of the DNSKEY
   * RR that a validator is supposed to use to validate this signature.
   */
  dns_name_t *signer_name;
  /** The Signature field contains the cryptographic signature that covers
   * the RRSIG RDATA (excluding the Signature field) and the RRset
   * specified by the RRSIG owner name, RRSIG class, and RRSIG Type
   * Covered field.
   */
  uint8_t *signature;
  uint16_t signature_len;
} dns_rrsig_t;

//
// Resource Record - NSEC

typedef struct dns_nsec_t {
  /** The Next Domain field contains the next owner name that has
   * authoritative data or contains a delegation point NS RRset.
   */
  dns_name_t *next_domain_name;
  /** The Type Bit Maps field identifies the RRset types that exist at the
   * NSEC RR's owner name.
   */
  smartlist_t *types;
} dns_nsec_t;

//
// Resource Record - DNSKEY

typedef struct dns_dnskey_t {
  /** Bit 7 of the Flags field is the Zone Key flag.
   * Bit 15 of the Flags field is the Secure Entry Point flag.
   */
  uint16_t flags;
  /** The Protocol Field MUST have value 3, and the DNSKEY RR MUST be
   * treated as invalid during signature verification if it is found to be
   * some value other than 3.
   */
  uint8_t protocol;
  /** The Algorithm field identifies the public key's cryptographic
   * algorithm and determines the format of the Public Key field.
   */
  uint8_t algorithm;
  /** The Public Key Field holds the public key material.
   */
  uint8_t *public_key;
  uint16_t public_key_len;
} dns_dnskey_t;

//
// Resource Record - NSEC3

typedef struct dns_nsec3_t {
  /** The Hash Algorithm field identifies the cryptographic hash algorithm
   * used to construct the hash-value.
   */
  uint8_t hash_algorithm;
  /** The Flags field contains 8 one-bit flags that can be used to indicate
   * different processing. All undefined flags must be zero.
   */
  uint8_t flags;
  /** The Iterations field defines the number of additional times the hash
   * function has been performed.
   */
  uint16_t iterations;
  /** The Salt Length field defines the length of the Salt field in octets,
   * ranging in value from 0 to 255.
   */
  uint8_t salt_length;
  /** The Salt field is appended to the original owner name before hashing
   * in order to defend against pre-calculated dictionary attacks.
   */
  uint8_t *salt;
  /** The Hash Length field defines the length of the Next Hashed Owner
   * Name field, ranging in value from 1 to 255 octets.
   */
  uint8_t hash_length;
  /** The Next Hashed Owner Name field contains the next hashed owner name
   in hash order. This value is in binary format.
   */
  uint8_t *next_hashed_owner_name;
  /** The Type Bit Maps field identifies the RRSet types that exist at the
   * original owner name of the NSEC3 RR.
   */
  smartlist_t *types;
} dns_nsec3_t;

//
// Resource Record - NSEC3PARAM

typedef struct dns_nsec3param_t {
  /** The Hash Algorithm field identifies the cryptographic hash algorithm
   * used to construct the hash-value.
   */
  uint8_t hash_algorithm;
  /** The Opt-Out flag is not used and is set to zero. All other flags are
   * reserved for future use, and must be zero.
   */
  uint8_t flags;
  /** The Iterations field defines the number of additional times the hash
   * is performed.
   */
  uint16_t iterations;
  /** The Salt Length field defines the length of the Salt field in octets,
   * ranging in value from 0 to 255.
   */
  uint8_t salt_length;
  /** The Salt field is appended to the original owner name before hashing.
   */
  uint8_t *salt;
} dns_nsec3param_t;

//
// Resource Record - URI

typedef struct dns_uri_t {
  /** This field holds the priority of the target URI in this RR. Its
   * range is 0-65535.
   */
  uint16_t priority;
  /** This field holds the server selection mechanism. The weight field
   * specifies a relative weight for entries with the same priority.
   */
  uint16_t weight;
  /** his field holds the URI of the target, enclosed in double-quote
   * characters ('"'), where the URI is as specified in RFC 3986
   * [RFC3986].
   */
  char *target;
} dns_uri_t;

//
// Resource Record

typedef enum validation_state_t {
  DNSSEC_VALIDATION_STATE_SECURE,
  /* All the signatures in the response are verified. [RFC4033] */
  DNSSEC_VALIDATION_STATE_INSECURE,
  /* Signature is missing, is expired, or uses an unsupported algorithm.
   * [RFC4033] */
  DNSSEC_VALIDATION_STATE_BOGUS,
  /* Unverified because no trust anchor is available. [RFC4033] */
  DNSSEC_VALIDATION_STATE_INDETERMINATE
} validation_state_t;

typedef struct dns_rr_t {
  /** The domain system utilizes a compression scheme which eliminates the
   * repetition of domain names in a message.  In this scheme, an entire domain
   * name or a list of labels at the end of a domain name is replaced with a
   * pointer to a prior occurrence of the same name.
   */
  dns_name_t *name;
  /** A two octets containing one of the RR type codes. This field specifies
   * the meaning of the data in the RDATA field.
   */
  dns_type_t *rrtype;
  /** A two octets which specify the class of the data in the RDATA field.
   */
  uint16_t rrclass;
  /** A 32 bit unsigned integer that specifies the time interval (in seconds)
   * that the resource record may be cached before it should be discarded.
   * Zero values are interpreted to mean that the RR can only be used for the
   * transaction in progress, and should not be cached.
   */
  uint32_t ttl;
  /** An unsigned 16 bit integer that specifies the length in octets of the
   * RDATA field.
   */
  uint16_t rdlength;
  /** A variable length string of octets that describes the resource. The
   * format of this information varies according to the TYPE and CLASS of the
   * resource record. For example, the if the TYPE is A and the CLASS is IN,
   * the RDATA field is a 4 octet ARPA Internet address.
   */
  uint8_t *rdata;
  char *a;
  dns_name_t *ns;
  dns_name_t *cname;
  dns_soa_t *soa;
  dns_name_t *ptr;
  dns_mx_t *mx;
  dns_key_t *key;
  char *aaaa;
  dns_ds_t *ds;
  dns_rrsig_t *rrsig;
  dns_nsec_t *nsec;
  dns_dnskey_t *dnskey;
  dns_nsec3_t *nsec3;
  dns_nsec3param_t *nsec3param;
  dns_uri_t *uri;
  validation_state_t validation_state;
  struct dns_rr_t *signer;
} dns_rr_t;

//
// Message

typedef struct dns_message_t {
  dns_header_t *header;
  smartlist_t *question_list;
  smartlist_t *answer_list;
  smartlist_t *name_server_list;
  smartlist_t *additional_record_list;
  struct timeval cached_at;
} dns_message_t;

#endif /* !defined(TOR_DNS_MESSAGE_ST_H) */
