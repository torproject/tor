/* Copyright (c) 2019 Christian Hofer.
 * Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_DNS_DEFS_H
#define TOR_DNS_DEFS_H

/**
 * \file dns_types.h
 *
 * \brief Definitions for DNS constants.
 **/

//
// OP Codes

#define DNS_OPCODE_QUERY    0  // Query                             [RFC1035]
#define DNS_OPCODE_IQUERY   1  // IQuery (Inverse Query, Obsolete)  [RFC3425]
#define DNS_OPCODE_STATUS   2  // Status                            [RFC1035]
#define DNS_OPCODE_UNKNOWN  3  // available for assignment
#define DNS_OPCODE_NOTIFY   4  // Notify                            [RFC1996]
#define DNS_OPCODE_UPDATE   5  // Update                            [RFC2136]

//
// Classes

#define DNS_CLASS_IN        1  // Internet (IN)
#define DNS_CLASS_CHAOS     3  // Chaos (CH)     [Moon1981]
#define DNS_CLASS_HESIOD    4  // Hesiod (HS)    [Dyer1987]
#define DNS_CLASS_NONE    254  // QCLASS None    [RFC2136]
#define DNS_CLASS_ANY     255  // QCLASS Any     [RFC1035]

//
// Response Codes

#define DNS_RCODE_NOERROR    0  // No Error.                          [RFC1035]
#define DNS_RCODE_FORMERR    1  // Format Error.                      [RFC1035]
#define DNS_RCODE_SERVFAIL   2  // Server Failure.                    [RFC1035]
#define DNS_RCODE_NXDOMAIN   3  // Non-Existent Domain.               [RFC1035]
#define DNS_RCODE_NOTIMPL    4  // Not Implemented.                   [RFC1035]
#define DNS_RCODE_REFUSED    5  // Query Refused.                     [RFC1035]
#define DNS_RCODE_YXDOMAIN   6  // Name Exists when it should not.    [RFC2136]
#define DNS_RCODE_YXRRSET    7  // RR Set Exists when it should not.  [RFC2136]
#define DNS_RCODE_NXRRSET    8  // RR Set that should exist does not. [RFC2136]
#define DNS_RCODE_NOTAUTH    9  // Server Not Authoritative for zone. [RFC2136]
#define DNS_RCODE_NOTZONE   10  // Name not contained in zone.        [RFC2136]

//
//  Extended Response Codes

#define DNS_RCODE_BADSIG   16  // TSIG Signature Failure.       [RFC2845]
#define DNS_RCODE_BADKEY   17  // Key not recognized.           [RFC2845]
#define DNS_RCODE_BADTIME  18  // Signature out of time window. [RFC2845]
#define DNS_RCODE_BADMODE  19  // Bad TKEY Mode.                [RFC2930]
#define DNS_RCODE_BADNAME  20  // Duplicate key name.           [RFC2930]
#define DNS_RCODE_BADALG   21  // Algorithm not supported.      [RFC2930]
#define DNS_RCODE_BADTRUC  22  // Bad Truncation.               [RFC4635]

//
// Types

#define DNS_TYPE_NONE            0  // None.
#define DNS_TYPE_A               1  // Address record.                [RFC1035]
#define DNS_TYPE_NS              2  // Name server record.            [RFC1035]
#define DNS_TYPE_MD              3  // Obsolete - use MX.              [RFC973]
#define DNS_TYPE_MF              4  // Obsolete - use MX.              [RFC973]
#define DNS_TYPE_CNAME           5  // Canonical name record.         [RFC1035]
#define DNS_TYPE_SOA             6  // Start of [a zone of] authority record.
                                    //                       [RFC1035, RFC2308]
#define DNS_TYPE_MB              7  // Mailbox domain name.            [RFC883]
#define DNS_TYPE_MG              8  // Mail group member.              [RFC883]
#define DNS_TYPE_MR              9  // Mail rename domain name.        [RFC883]
#define DNS_TYPE_NULL           10  // Null RR.                        [RFC883]
#define DNS_TYPE_WKS            11  // Well known service description.
                                    //                        [RFC883, RFC1035]
#define DNS_TYPE_PTR            12  // Pointer record.                [RFC1035]
#define DNS_TYPE_HINFO          13  // Host information.               [RFC883]
#define DNS_TYPE_MINFO          14  // Mailbox or mail list information.
                                    //                                 [RFC883]
#define DNS_TYPE_MX             15  // Mail exchange record.
                                    //                       [RFC1035, RFC7505]
#define DNS_TYPE_TXT            16  // Text record.                   [RFC1035]
#define DNS_TYPE_RP             17  // Responsible Person.            [RFC1183]
#define DNS_TYPE_AFSDB          18  // AFS database record.           [RFC1183]
#define DNS_TYPE_X25            19  // X_25 calling address.
#define DNS_TYPE_ISDN           20  // ISDN calling address.
#define DNS_TYPE_RT             21  // Router.
#define DNS_TYPE_NSAP           22  // NSAP address.
#define DNS_TYPE_NSAP_PTR       23  // Reverse NSAP lookup.
#define DNS_TYPE_SIG            24  // Signature.                     [RFC2535]
#define DNS_TYPE_KEY            25  // Key record.                    [RFC2930]
#define DNS_TYPE_PX             26  // X.400 mail mapping.
#define DNS_TYPE_GPOS           27  // Geographical position.
#define DNS_TYPE_AAAA           28  // IPv6 address record.           [RFC3596]
#define DNS_TYPE_LOC            29  // Location record.               [RFC1876]
#define DNS_TYPE_NXT            30  // Obsolete.                      [RFC2065]
#define DNS_TYPE_EID            31  // Endpoint identifier.
#define DNS_TYPE_NIMLOC         32  // Nimrod Locator.
#define DNS_TYPE_SRV            33  // Service locator.               [RFC2782]
#define DNS_TYPE_ATMA           34  // ATM Address.
#define DNS_TYPE_NAPTR          35  // Naming Authority Pointer.      [RFC3403]
#define DNS_TYPE_KX             36  // Key Exchanger record.          [RFC2230]
#define DNS_TYPE_CERT           37  // Certificate record.            [RFC4398]
#define DNS_TYPE_A6             38  // Obsolete - use AAAA.           [RFC2874]
#define DNS_TYPE_DNAME          39  // Canonical name record including its
                                    // subnames.                      [RFC6672]
#define DNS_TYPE_SINK           40  // Kitchen sink.
#define DNS_TYPE_OPT            41  // Option.                        [RFC6891]
#define DNS_TYPE_APL            42  // Address Prefix List.           [RFC3123]
#define DNS_TYPE_DS             43  // Delegation signer.             [RFC4034]
#define DNS_TYPE_SSHFP          44  // SSH Public Key Fingerprint.    [RFC4255]
#define DNS_TYPE_IPSECKEY       45  // IPsec Key.                     [RFC4025]
#define DNS_TYPE_RRSIG          46  // DNSSEC signature.              [RFC4034]
#define DNS_TYPE_NSEC           47  // Next Secure record.            [RFC4034]
#define DNS_TYPE_DNSKEY         48  // DNS Key record.                [RFC4034]
#define DNS_TYPE_DHCID          49  // DHCP identifier.               [RFC4701]
#define DNS_TYPE_NSEC3          50  // Next Secure record version 3.  [RFC5155]
#define DNS_TYPE_NSEC3PARAM     51  // NSEC3 parameters.              [RFC5155]
#define DNS_TYPE_TLSA           52  // TLSA certificate association.  [RFC6698]
#define DNS_TYPE_SMIMEA         53  // S/MIME cert association.       [RFC8162]
#define DNS_TYPE_HIP            55  // Host Identity Protocol.        [RFC8005]
#define DNS_TYPE_CDS            59  // Child DS.                      [RFC7344]
#define DNS_TYPE_CDNSKEY        60  // Child DNS Key.                 [RFC7344]
#define DNS_TYPE_OPENPGPKEY     61  // OpenPGP public key record.     [RFC7929]
#define DNS_TYPE_TKEY          249  // Transaction Key record.        [RFC2930]
#define DNS_TYPE_TSIG          250  // Transaction Signature.         [RFC2845]
#define DNS_TYPE_IXFR          251  // Incremental Zone Transfer.     [RFC1996]
#define DNS_TYPE_AXFR          252  // Authoritative Zone Transfer.   [RFC1035]
#define DNS_TYPE_MAILB         253  // Mailbox-related records.        [RFC883]
#define DNS_TYPE_MAILA         254  // Obsolete - see MX.              [RFC973]
#define DNS_TYPE_ALL           255  // All cached records.            [RFC1035]
#define DNS_TYPE_URI           256  // Uniform Resource Identifier.   [RFC7553]
#define DNS_TYPE_CAA           257  // Certification Authority Authorization.
                                    //                                [RFC6844]
#define DNS_TYPE_TA          32768  // DNSSEC Trust Authorities.
#define DNS_TYPE_DLV         32769  // DNSSEC Lookaside Validation record.
                                    //                                [RFC4431]

//
// KEY Protocols

#define DNS_KEY_PROTO_0         0  // Reservered  [RFC2535]
#define DNS_KEY_PROTO_TLS       1  // TLS         [RFC2535]
#define DNS_KEY_PROTO_EMAIL     2  // Email       [RFC2535]
#define DNS_KEY_PROTO_DNSSEC    3  // DNSSEC      [RFC2535]
#define DNS_KEY_PROTO_IPSEC     4  // IPSEC       [RFC2535]
#define DNS_KEY_PROTO_ONION     5  // Onion
#define DNS_KEY_PROTO_ALL     255  // All         [RFC2535]

//
// KEY Algorithms

#define DNS_KEY_ALG_0         0  // Reservered                  [RFC2535]
#define DNS_KEY_ALG_RSAMD5    1  // RSA/MD5                     [RFC2535]
#define DNS_KEY_ALG_DH        2  // Diffie-Hellman              [RFC2535]
#define DNS_KEY_ALG_DSA       3  // DSA                         [RFC2535]
#define DNS_KEY_ALG_4         4  // Reserved for elliptic curve crypto
                                 //                             [RFC2535]
#define DNS_KEY_ALG_HSV2     32  // Hidden Service v2
#define DNS_KEY_ALG_HSV3     33  // Hidden Service v3
#define DNS_KEY_ALG_252     252  // Reserved for indirect keys  [RFC2535]
#define DNS_KEY_ALG_253     253  // Private - domain name       [RFC2535]
#define DNS_KEY_ALG_254     254  // Private - OID               [RFC2535]
#define DNS_KEY_ALG_255     255  // Reserved                    [RFC2535]

//
// NSEC3 Flags

#define DNS_NSEC3_FLAG_0        1 << 7  // 0  Unassigned  [RFC5155]
#define DNS_NSEC3_FLAG_1        1 << 6  // 1  Unassigned  [RFC5155]
#define DNS_NSEC3_FLAG_2        1 << 5  // 2  Unassigned  [RFC5155]
#define DNS_NSEC3_FLAG_3        1 << 4  // 3  Unassigned  [RFC5155]
#define DNS_NSEC3_FLAG_4        1 << 3  // 4  Unassigned  [RFC5155]
#define DNS_NSEC3_FLAG_5        1 << 2  // 5  Unassigned  [RFC5155]
#define DNS_NSEC3_FLAG_6        1 << 1  // 6  Unassigned  [RFC5155]
#define DNS_NSEC3_FLAG_OPT_OUT  1       // 7  Opt-Out     [RFC5155]

//
// DNSKEY Flags

#define DNS_DNSKEY_FLAG_0       1 << 15 //  0  Unassigned  [RFC3755][RFC4034]
#define DNS_DNSKEY_FLAG_1       1 << 14 //  1  Unassigned  [RFC3755][RFC4034]
#define DNS_DNSKEY_FLAG_2       1 << 13 //  2  Unassigned  [RFC3755][RFC4034]
#define DNS_DNSKEY_FLAG_3       1 << 12 //  3  Unassigned  [RFC3755][RFC4034]
#define DNS_DNSKEY_FLAG_4       1 << 11 //  4  Unassigned  [RFC3755][RFC4034]
#define DNS_DNSKEY_FLAG_5       1 << 10 //  5  Unassigned  [RFC3755][RFC4034]
#define DNS_DNSKEY_FLAG_6       1 << 9  //  6  Unassigned  [RFC3755][RFC4034]
#define DNS_DNSKEY_FLAG_ZONE    1 << 8  //  7  ZONE        [RFC3755][RFC4034]
#define DNS_DNSKEY_FLAG_REVOKE  1 << 7  //  8  REVOKE      [RFC5011]
#define DNS_DNSKEY_FLAG_9       1 << 6  //  9  Unassigned  [RFC3755][RFC4034]
#define DNS_DNSKEY_FLAG_10      1 << 5  // 10  Unassigned  [RFC3755][RFC4034]
#define DNS_DNSKEY_FLAG_11      1 << 4  // 11  Unassigned  [RFC3755][RFC4034]
#define DNS_DNSKEY_FLAG_12      1 << 3  // 12  Unassigned  [RFC3755][RFC4034]
#define DNS_DNSKEY_FLAG_13      1 << 2  // 13  Unassigned  [RFC3755][RFC4034]
#define DNS_DNSKEY_FLAG_14      1 << 1  // 14  Unassigned  [RFC3755][RFC4034]
#define DNS_DNSKEY_FLAG_SEP     1       // 15  Secure Entry Point (SEP)
                                        //     [RFC3757][RFC4034]

#endif /* !defined(TOR_DNS_DEFS_H) */
