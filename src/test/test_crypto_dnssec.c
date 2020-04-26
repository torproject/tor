/* Copyright (c) 2019 Christian Hofer.
 * Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_crypto_dnssec.c
 * \brief Tests for DNSSEC crypto.
 */

#define CRYPTO_DNSSEC_PRIVATE

#include "test/test.h"
#include "test/log_test_helpers.h"

#include "lib/container/dns_message.h"
#include "lib/container/dns_message_st.h"
#include "lib/crypt_ops/crypto_dnssec.h"
#include "lib/defs/dns_types.h"
#include "lib/encoding/dns_string.h"
#include "lib/encoding/dns_wireformat.h"

static void
test_crypto_dnssec_authenticate_rrset_rfc4035_b1_answer(void *arg)
{
  (void) arg;

  smartlist_t *unauthenticated_rrset = smartlist_new();
  smartlist_add(unauthenticated_rrset,
                dns_rr_value_of("x.w.example. 3600 IN MX 1 xx.example."));
  smartlist_add(unauthenticated_rrset,
                dns_rr_value_of("x.w.example. 3600 IN RRSIG MX 5 3 3600 "
                                "1081528579 1084120579 38519 example. Il2WTZ+B"
                                "kv+OytBx4LItNW5mjB4RCwhOO8y1XzPHZmZUTVYL7LaA6"
                                "3f6T9ysVBzJRI3KRjAPH3U1qaYnDoN1DrWqmi9RJe4FoO"
                                "bkbcdm7P3Ikx70ePCoFgRz1Yq+bVVXCvGuAU4xALv3W/Y"
                                "1jNSlwZ2mSWKHfxFQxPtLj8s32+k="));

  dns_rr_t *dnskey1 =
    dns_rr_value_of("example. 3600 IN DNSKEY 256 3 5 AQOy1bZVvpPqhg4j7EJoM9rI3"
                    "ZmyEx2OzDBVrZy/lvI5CQePxXHZS4i8dANH4DX3tbHol61ek8EFMcsGXx"
                    "KciJFHyhl94C+NwILQdzsUlSFovBZsyl/NX6yEbtw/xN9ZNcrbYvgjjZ/"
                    "UVPZIySFNsgEYvh0z2542lzMKR4Dh8uZffQ==");
  dnskey1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;

  dns_rr_t *dnskey2 =
    dns_rr_value_of("example. 3600 IN DNSKEY 257 3 5 AQOeX7+baTmvpVHb2CcLnL1dM"
                    "RWbuscRvHXlLnXwDzvqp4tZVKp1sZMepFb8MvxhhW3y/0QZsyCjczGJ1q"
                    "k8vJe52iOhInKROVLRwxGpMfzPRLMlGybr51bOV/1se0ODacj3DomyB4Q"
                    "B5gKTYot/K9alk5/j8vfd4jWCWD+E1Sze0Q==");
  dnskey2->validation_state = DNSSEC_VALIDATION_STATE_SECURE;

  smartlist_t *authenticated_dnskey_rrset = smartlist_new();
  smartlist_add(authenticated_dnskey_rrset, dnskey1);
  smartlist_add(authenticated_dnskey_rrset, dnskey2);

#ifndef ENABLE_OPENSSL
  tt_skip();
#endif
  tt_int_op(dnssec_authenticate_rrset(unauthenticated_rrset,
                                      authenticated_dnskey_rrset), OP_EQ, -1);

 done:
  SMARTLIST_FOREACH(unauthenticated_rrset, dns_rr_t *, anchor,
                    dns_rr_free(anchor));
  smartlist_free(unauthenticated_rrset);
  SMARTLIST_FOREACH(authenticated_dnskey_rrset, dns_rr_t *, anchor,
                    dns_rr_free(anchor));
  smartlist_free(authenticated_dnskey_rrset);
}

static void
test_crypto_dnssec_authenticate_rrset_fails(void *arg)
{
  (void) arg;

  smartlist_t *unauthenticated_rrset = smartlist_new();
  smartlist_add(unauthenticated_rrset,
                dns_rr_value_of("x.w.example. 3600 IN MX 1 xx.example."));
  smartlist_add(unauthenticated_rrset,
                dns_rr_value_of("x.w.example. 3600 IN RRSIG MX 5 3 3600 "
                                "1081528579 7281748800 38519 example. Il2WTZ+B"
                                "kv+OytBx4LItNW5mjB4RCwhOO8y1XzPHZmZUTVYL7LaA6"
                                "3f6T9ysVBzJRI3KRjAPH3U1qaYnDoN1DrWqmi9RJe4FoO"
                                "bkbcdm7P3Ikx70ePCoFgRz1Yq+bVVXCvGuAU4xALv3W/Y"
                                "1jNSlwZ2mSWKHfxFQxPtLj8s32+k="));

  dns_rr_t *dnskey =
    dns_rr_value_of("example. 3600 IN DNSKEY 256 3 5 AQOy1bZVvpPqhg4j7EJoM9rI3"
                    "ZmyEx2OzDBVrZy/lvI5CQePxXHZS4i8dANH4DX3tbHol61ek8EFMcsGXx"
                    "KciJFHyhl94C+NwILQdzsUlSFovBZsyl/NX6yEbtw/xN9ZNcrbYvgjjZ/"
                    "UVPZIySFNsgEYvh0z2542lzMKR4Dh8uZffQ==");
  dnskey->validation_state = DNSSEC_VALIDATION_STATE_SECURE;

  smartlist_t *authenticated_dnskey_rrset = smartlist_new();
  smartlist_add(authenticated_dnskey_rrset, dnskey);

#ifndef ENABLE_OPENSSL
  tt_skip();
#endif
  tt_int_op(dnssec_authenticate_rrset(unauthenticated_rrset,
                                      authenticated_dnskey_rrset), OP_EQ, -2);

 done:
  SMARTLIST_FOREACH(unauthenticated_rrset, dns_rr_t *, anchor,
                    dns_rr_free(anchor));
  smartlist_free(unauthenticated_rrset);
  SMARTLIST_FOREACH(authenticated_dnskey_rrset, dns_rr_t *, anchor,
                    dns_rr_free(anchor));
  smartlist_free(authenticated_dnskey_rrset);
}

static void
test_crypto_dnssec_authenticate_delegation_to_child_zone(void *arg)
{
  (void) arg;

  dns_rr_t *ds1 =
    dns_rr_value_of("example.com. 123 IN DS 31406 8 1 189968811e6eba862dd6c209"
                    "f75623d8d9ed9142");
  ds1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;

  dns_rr_t *ds2 =
    dns_rr_value_of("example.com. 123 IN DS 31406 8 255 189968811e6eba862dd6c2"
                    "09f75623d8d9ed9142");
  ds2->validation_state = DNSSEC_VALIDATION_STATE_SECURE;

  dns_rr_t *ds3 =
    dns_rr_value_of("example.com. 123 IN DS 31406 8 2 f78cf3344f72137235098ecb"
                    "bd08947c2c9001c7f6a085a17f518b5d8f6b916d");
  ds3->validation_state = DNSSEC_VALIDATION_STATE_SECURE;

  smartlist_t *ds_rrset = smartlist_new();
  smartlist_add(ds_rrset, ds1);
  smartlist_add(ds_rrset, ds2);
  smartlist_add(ds_rrset, ds3);

  smartlist_t *dnskey_rrset = smartlist_new();
  smartlist_add(dnskey_rrset,
                dns_rr_value_of("example.com. 2718 IN DNSKEY 257 3 8 AwEAAbOFA"
                                "xl+Lkt0UMglZizKEC1AxUu8zlj65KYatR5wBWMrh18TYz"
                                "K/ig6Y1t5YTWCO68bynorpNu9fqNFALX7bVl9/gybA0v0"
                                "EhF+dgXmoUfRX7ksMGgBvtfa2/Y9a3klXNLqkTszIQ4PE"
                                "MVCjtryl19Be9/PkFeC9ITjgMRQsQhmB39eyMYnal+f3b"
                                "UxKk4fq7cuEU0dbRpue4H/N6jPucXWOwiMAkTJhghqgy+"
                                "o9FfIp+tR/emKao94/wpVXDcPf5B18j7xz2SvTTxiuqCz"
                                "CMtsxnikZHcoh1j4g+Y1B8zIMIvrEM+pZGhh/Yuf4RwCB"
                                "gaYCi9hpiMWVvS4WBzx0/lU="));

  smartlist_t *trusted_dnskeys = smartlist_new();

#ifndef ENABLE_OPENSSL
  tt_skip();
#endif
  tt_int_op(dnssec_authenticate_delegation_to_child_zone(trusted_dnskeys,
                                                         dnskey_rrset,
                                                         ds_rrset), OP_EQ, 0);
  tt_int_op(smartlist_len(trusted_dnskeys), OP_EQ, 1);

 done:
  SMARTLIST_FOREACH(ds_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(ds_rrset);
  SMARTLIST_FOREACH(dnskey_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(dnskey_rrset);
  smartlist_free(trusted_dnskeys);
}

static void
test_crypto_dnssec_authenticate_delegation_to_child_zone_using_invalid_digest(
                                                                     void *arg)
{
  (void) arg;

  dns_rr_t *ds1 =
    dns_rr_value_of("example.com. 123 IN DS 31406 8 1 189968811e6eba862dd6c209"
                    "f75623d8d9ed9142");
  ds1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;

  dns_rr_t *ds2 =
    dns_rr_value_of("example.com. 123 IN DS 31406 8 255 189968811e6eba862dd6c2"
                    "09f75623d8d9ed9142");
  ds2->validation_state = DNSSEC_VALIDATION_STATE_SECURE;

  dns_rr_t *ds3 =
    dns_rr_value_of("example.com. 123 IN DS 31406 8 2 0001020304050607");
  ds3->validation_state = DNSSEC_VALIDATION_STATE_SECURE;

  smartlist_t *ds_rrset = smartlist_new();
  smartlist_add(ds_rrset, ds1);
  smartlist_add(ds_rrset, ds2);
  smartlist_add(ds_rrset, ds3);

  smartlist_t *dnskey_rrset = smartlist_new();
  smartlist_add(dnskey_rrset,
                dns_rr_value_of("example.com. 2718 IN DNSKEY 257 3 8 AwEAAbOFA"
                                "xl+Lkt0UMglZizKEC1AxUu8zlj65KYatR5wBWMrh18TYz"
                                "K/ig6Y1t5YTWCO68bynorpNu9fqNFALX7bVl9/gybA0v0"
                                "EhF+dgXmoUfRX7ksMGgBvtfa2/Y9a3klXNLqkTszIQ4PE"
                                "MVCjtryl19Be9/PkFeC9ITjgMRQsQhmB39eyMYnal+f3b"
                                "UxKk4fq7cuEU0dbRpue4H/N6jPucXWOwiMAkTJhghqgy+"
                                "o9FfIp+tR/emKao94/wpVXDcPf5B18j7xz2SvTTxiuqCz"
                                "CMtsxnikZHcoh1j4g+Y1B8zIMIvrEM+pZGhh/Yuf4RwCB"
                                "gaYCi9hpiMWVvS4WBzx0/lU="));

  smartlist_t *trusted_dnskeys = smartlist_new();
  tt_int_op(dnssec_authenticate_delegation_to_child_zone(trusted_dnskeys,
                                                         dnskey_rrset,
                                                         ds_rrset), OP_EQ, -1);
  tt_int_op(smartlist_len(trusted_dnskeys), OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(ds_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(ds_rrset);
  SMARTLIST_FOREACH(dnskey_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(dnskey_rrset);
  smartlist_free(trusted_dnskeys);
}

static void
test_crypto_dnssec_denial_of_existence_rfc4035_b2_name_error(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("ml.example.");

  // Error in example after applying rfc6840 section 4.1? -> remove NS from
  // NSEC types
  dns_rr_t *rr1 =
    dns_rr_value_of("b.example. 0 IN NSEC ns1.example. RRSIG NSEC");
  rr1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr1->signer =
    dns_rr_value_of("b.example. 0 IN RRSIG NSEC 0 2 0 0 0 0 example. abc");

  dns_rr_t *rr2 =
    dns_rr_value_of("example. 0 IN NSEC a.example. NS SOA MX RRSIG NSEC "
                    "DNSKEY");
  rr2->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr2->signer =
    dns_rr_value_of("example. 0 IN RRSIG NSEC 0 1 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr1);
  smartlist_add(rrset, rr2);

  tt_int_op(dnssec_denial_of_existence(qname, DNS_TYPE_A, rrset), OP_EQ,
            DNSSEC_DENIAL_OF_EXISTENCE_NXDOMAIN);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(rr1->signer);
  dns_rr_free(rr1);
  dns_rr_free(rr2->signer);
  dns_rr_free(rr2);
}

static void
test_crypto_dnssec_denial_of_existence_rfc4035_b3_no_data_error(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("ns1.example.");

  dns_rr_t *rr1 =
    dns_rr_value_of("ns1.example. 0 IN NSEC ns2.example. A RRSIG NSEC");
  rr1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr1->signer =
    dns_rr_value_of("ns1.example. 0 IN RRSIG NSEC 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr1);

  tt_int_op(dnssec_denial_of_existence(qname, DNS_TYPE_MX, rrset), OP_EQ,
            DNSSEC_DENIAL_OF_EXISTENCE_NXQTYPE);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(rr1->signer);
  dns_rr_free(rr1);
}

static void
test_crypto_dnssec_denial_of_existence_rfc4035_b5_referral_to_unsigned_zone(
                                                                     void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("mc.b.example.");

  dns_rr_t *rr1 =
    dns_rr_value_of("b.example. 0 IN NSEC ns1.example. NS RRSIG NSEC");
  rr1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr1->signer =
    dns_rr_value_of("b.example. 0 IN RRSIG NSEC 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr1);

  tt_int_op(dnssec_denial_of_existence(qname, DNS_TYPE_MX, rrset), OP_EQ,
            DNSSEC_DENIAL_OF_EXISTENCE_NODATA);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(rr1->signer);
  dns_rr_free(rr1);
}

static void
test_crypto_dnssec_denial_of_existence_rfc4035_b7_wildcard_no_data_error(
                                                                     void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("a.z.w.example.");

  dns_rr_t *rr1 =
    dns_rr_value_of("x.y.w.example. 0 IN NSEC xx.example. MX RRSIG NSEC");
  rr1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr1->signer =
    dns_rr_value_of("x.y.w.example. 0 IN RRSIG NSEC 0 4 0 0 0 0 example. abc");

  dns_rr_t *rr2 =
    dns_rr_value_of("*.w.example. 0 IN NSEC x.w.example. MX RRSIG NSEC");
  rr2->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr2->signer =
    dns_rr_value_of("*.w.example. 0 IN RRSIG NSEC 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr1);
  smartlist_add(rrset, rr2);

  tt_int_op(dnssec_denial_of_existence(qname, DNS_TYPE_AAAA, rrset), OP_EQ,
            DNSSEC_DENIAL_OF_EXISTENCE_NODATA);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(rr1->signer);
  dns_rr_free(rr1);
  dns_rr_free(rr2->signer);
  dns_rr_free(rr2);
}

static void
test_crypto_dnssec_denial_of_existence_rfc4035_b8_ds_child_zone_no_data_error(
                                                                     void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("example.");

  dns_rr_t *rr1 =
    dns_rr_value_of("example. 0 IN NSEC a.example. NS SOA MX RRSIG NSEC "
                    "DNSKEY");
  rr1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr1->signer =
    dns_rr_value_of("example. 0 IN RRSIG NSEC 0 1 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr1);

  tt_int_op(dnssec_denial_of_existence(qname, DNS_TYPE_DS, rrset),
            OP_EQ, DNSSEC_DENIAL_OF_EXISTENCE_NXQTYPE);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(rr1->signer);
  dns_rr_free(rr1);
}

static void
test_crypto_dnssec_denial_of_existence_rfc5155_b1_name_error(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("a.c.x.w.example.");

  dns_rr_t *rr1 =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD 2t7b4g4vsa5smi47k61mv5bv1a22bojr NS SOA MX "
                    "RRSIG DNSKEY NSEC3PARAM");
  rr1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr1->signer =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  dns_rr_t *rr2 =
    dns_rr_value_of("b4um86eghhds6nea196smvmlo4ors995.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD gjeqe526plbf1g8mklp59enfd789njgi MX RRSIG");
  rr2->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr2->signer =
    dns_rr_value_of("b4um86eghhds6nea196smvmlo4ors995.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  dns_rr_t *rr3 =
    dns_rr_value_of("35mthgpgcu1qg68fab165klnsnk3dpvl.example. 0 IN NSEC3 1 0 "
                   "12 AABBCCDD b4um86eghhds6nea196smvmlo4ors995 NS DS RRSIG");
  rr3->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr3->signer =
    dns_rr_value_of("35mthgpgcu1qg68fab165klnsnk3dpvl.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr1);
  smartlist_add(rrset, rr2);
  smartlist_add(rrset, rr3);

  tt_int_op(dnssec_denial_of_existence(qname, DNS_TYPE_A, rrset), OP_EQ,
            DNSSEC_DENIAL_OF_EXISTENCE_NXDOMAIN);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(rr1->signer);
  dns_rr_free(rr1);
  dns_rr_free(rr2->signer);
  dns_rr_free(rr2);
  dns_rr_free(rr3->signer);
  dns_rr_free(rr3);
}

static void
test_crypto_dnssec_denial_of_existence_rfc5155_b2_no_data_error(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("ns1.example.");

  dns_rr_t *rr1 =
    dns_rr_value_of("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD 2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG");
  rr1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr1->signer =
    dns_rr_value_of("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr1);

  tt_int_op(dnssec_denial_of_existence(qname, DNS_TYPE_MX, rrset), OP_EQ,
            DNSSEC_DENIAL_OF_EXISTENCE_NXQTYPE);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(rr1->signer);
  dns_rr_free(rr1);
}

static void
test_crypto_dnssec_denial_of_existence_rfc5155_b21_no_data_error_ent(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("y.w.example.");

  dns_rr_t *rr1 =
    dns_rr_value_of("ji6neoaepv8b5o6k4ev33abha8ht9fgc.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD k8udemvp1j2f7eg6jebps17vp3n8i58h");
  rr1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr1->signer =
    dns_rr_value_of("ji6neoaepv8b5o6k4ev33abha8ht9fgc.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr1);

  tt_int_op(dnssec_denial_of_existence(qname, DNS_TYPE_A, rrset), OP_EQ,
            DNSSEC_DENIAL_OF_EXISTENCE_NXQTYPE);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(rr1->signer);
  dns_rr_free(rr1);
}

static void
test_crypto_dnssec_denial_of_existence_rfc5155_b3_referral_to_opt_out_unsigned(
                                                                     void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("mc.c.example.");

  dns_rr_t *rr1 =
    dns_rr_value_of("35mthgpgcu1qg68fab165klnsnk3dpvl.example. 0 IN NSEC3 1 0 "
                   "12 AABBCCDD b4um86eghhds6nea196smvmlo4ors995 NS DS RRSIG");
  rr1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr1->signer =
    dns_rr_value_of("35mthgpgcu1qg68fab165klnsnk3dpvl.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  dns_rr_t *rr2 =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD 2t7b4g4vsa5smi47k61mv5bv1a22bojr NS SOA MX "
                    "RRSIG DNSKEY NSEC3PARAM");
  rr2->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr2->signer =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr1);
  smartlist_add(rrset, rr2);

  tt_int_op(dnssec_denial_of_existence(qname, DNS_TYPE_MX, rrset), OP_EQ,
            DNSSEC_DENIAL_OF_EXISTENCE_NODATA);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(rr1->signer);
  dns_rr_free(rr1);
  dns_rr_free(rr2->signer);
  dns_rr_free(rr2);
}

static void
test_crypto_dnssec_denial_of_existence_rfc5155_b4_wildcard_expansion(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("a.z.w.example.");

  dns_rr_t *rr1 =
    dns_rr_value_of("q04jkcevqvmu85r014c7dkba38o0ji5r.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD r53bq7cc2uvmubfu5ocmm6pers9tk9en A RRSIG");
  rr1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr1->signer =
    dns_rr_value_of("q04jkcevqvmu85r014c7dkba38o0ji5r.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr1);

  tt_int_op(dnssec_denial_of_existence(qname, DNS_TYPE_MX, rrset), OP_EQ,
            DNSSEC_DENIAL_OF_EXISTENCE_NODATA);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(rr1->signer);
  dns_rr_free(rr1);
}

static void
test_crypto_dnssec_denial_of_existence_rfc5155_b5_wildcard_no_data_error(
                                                                     void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("a.z.w.example.");

  dns_rr_t *rr1 =
    dns_rr_value_of("k8udemvp1j2f7eg6jebps17vp3n8i58h.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD kohar7mbb8dc2ce8a9qvl8hon4k53uhi");
  rr1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr1->signer =
    dns_rr_value_of("k8udemvp1j2f7eg6jebps17vp3n8i58h.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  dns_rr_t *rr2 =
    dns_rr_value_of("q04jkcevqvmu85r014c7dkba38o0ji5r.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD r53bq7cc2uvmubfu5ocmm6pers9tk9en A RRSIG");
  rr2->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr2->signer =
    dns_rr_value_of("q04jkcevqvmu85r014c7dkba38o0ji5r.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  dns_rr_t *rr3 =
    dns_rr_value_of("r53bq7cc2uvmubfu5ocmm6pers9tk9en.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD t644ebqk9bibcna874givr6joj62mlhv MX RRSIG");
  rr3->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr3->signer =
    dns_rr_value_of("r53bq7cc2uvmubfu5ocmm6pers9tk9en.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr1);
  smartlist_add(rrset, rr2);
  smartlist_add(rrset, rr3);

  tt_int_op(dnssec_denial_of_existence(qname, DNS_TYPE_AAAA, rrset), OP_EQ,
            DNSSEC_DENIAL_OF_EXISTENCE_NODATA);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(rr1->signer);
  dns_rr_free(rr1);
  dns_rr_free(rr2->signer);
  dns_rr_free(rr2);
  dns_rr_free(rr3->signer);
  dns_rr_free(rr3);
}

static void
test_crypto_dnssec_denial_of_existence_rfc5155_b6_ds_child_zone_no_data_error(
                                                                     void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("example.");

  dns_rr_t *rr1 =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD 2t7b4g4vsa5smi47k61mv5bv1a22bojr NS SOA MX "
                    "RRSIG DNSKEY NSEC3PARAM");
  rr1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr1->signer =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr1);

  tt_int_op(dnssec_denial_of_existence(qname, DNS_TYPE_DS, rrset), OP_EQ,
            DNSSEC_DENIAL_OF_EXISTENCE_NXQTYPE);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(rr1->signer);
  dns_rr_free(rr1);
}

static void
test_crypto_dnssec_set_rrset_validation_state_minimum_parameters(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();
  rr->name = dns_name_of("example.");
  rr->validation_state = DNSSEC_VALIDATION_STATE_INDETERMINATE;
  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr);

  dnssec_set_rrset_validation_state(rrset, DNSSEC_VALIDATION_STATE_SECURE,
                                    NULL);
  tt_int_op(rr->validation_state, OP_EQ, DNSSEC_VALIDATION_STATE_SECURE);

 done:
  SMARTLIST_FOREACH(rrset, dns_rr_t *, anchor, dns_rr_free(anchor));
  smartlist_free(rrset);
}

static void
test_crypto_dnssec_set_rrset_validation_state_full_parameters(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();
  rr->name = dns_name_of("example.");
  rr->ttl = 789;
  rr->validation_state = DNSSEC_VALIDATION_STATE_INDETERMINATE;

  dns_rr_t *signer = dns_rr_new();
  signer->name = dns_name_of(".");
  signer->ttl = 789;
  signer->validation_state = DNSSEC_VALIDATION_STATE_INDETERMINATE;
  signer->rrsig = dns_rrsig_new();
  signer->rrsig->original_ttl = 123;

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr);

  dnssec_set_rrset_validation_state(rrset, DNSSEC_VALIDATION_STATE_SECURE,
                                    signer);
  tt_int_op(rr->ttl, OP_EQ, 123);
  tt_ptr_op(rr->signer, OP_EQ, signer);
  tt_int_op(rr->validation_state, OP_EQ, DNSSEC_VALIDATION_STATE_SECURE);
  tt_int_op(signer->ttl, OP_EQ, 123);
  tt_int_op(signer->validation_state, OP_EQ, DNSSEC_VALIDATION_STATE_SECURE);

 done:
  SMARTLIST_FOREACH(rrset, dns_rr_t *, anchor, dns_rr_free(anchor));
  smartlist_free(rrset);
  dns_rr_free(signer);
}

static void
test_crypto_dnssec_collect_signatures_succeeds(void *arg)
{
  (void) arg;

  uint32_t now = (uint32_t) approx_time();

  dns_rr_t *rrsig = dns_rr_new();
  rrsig->rrtype = dns_type_of(DNS_TYPE_RRSIG);
  rrsig->rrsig = dns_rrsig_new();
  rrsig->rrsig->signer_name = dns_name_of("com.");
  rrsig->rrsig->algorithm = DNSSEC_ALG_RSASHA256;
  rrsig->rrsig->key_tag = 0;
  rrsig->rrsig->signature_expiration = now + 360;
  rrsig->rrsig->signature_inception = now - 360;

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rrsig);

  dns_rr_t *dnskey = dns_rr_new();
  dnskey->name = dns_name_of("com.");
  dnskey->rrtype = dns_type_of(DNS_TYPE_DNSKEY);
  dnskey->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  dnskey->dnskey = dns_dnskey_new();
  dnskey->dnskey->protocol = 3;
  dnskey->dnskey->flags = 257;
  dnskey->dnskey->algorithm = DNSSEC_ALG_RSASHA256;

  smartlist_t *dnskey_rrset = smartlist_new();
  smartlist_add(dnskey_rrset, dnskey);

  smartlist_t *signatures = dnssec_collect_signatures(rrset, dnskey_rrset);
  tt_int_op(smartlist_len(signatures), OP_EQ, 1);

 done:
  SMARTLIST_FOREACH(rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(rrset);
  SMARTLIST_FOREACH(dnskey_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(dnskey_rrset);
  smartlist_free(signatures);
}

static void
test_crypto_dnssec_collect_signatures_exceeds_expiration(void *arg)
{
  (void) arg;

  uint32_t now = (uint32_t) approx_time();

  dns_rr_t *rrsig = dns_rr_new();
  rrsig->rrtype = dns_type_of(DNS_TYPE_RRSIG);
  rrsig->rrsig = dns_rrsig_new();
  rrsig->rrsig->signer_name = dns_name_of("com.");
  rrsig->rrsig->algorithm = DNSSEC_ALG_RSASHA256;
  rrsig->rrsig->key_tag = 0;
  rrsig->rrsig->signature_expiration = now - 180;
  rrsig->rrsig->signature_inception = now - 360;

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rrsig);

  dns_rr_t *dnskey = dns_rr_new();
  dnskey->name = dns_name_of("com.");
  dnskey->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  dnskey->dnskey = dns_dnskey_new();
  dnskey->dnskey->protocol = 3;
  dnskey->dnskey->flags = 257;
  dnskey->dnskey->algorithm = DNSSEC_ALG_RSASHA256;

  smartlist_t *dnskey_rrset = smartlist_new();
  smartlist_add(dnskey_rrset, dnskey);

  smartlist_t *signatures = dnssec_collect_signatures(rrset, dnskey_rrset);
  tt_int_op(smartlist_len(signatures), OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(rrset);
  SMARTLIST_FOREACH(dnskey_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(dnskey_rrset);
  smartlist_free(signatures);
}

static void
test_crypto_dnssec_collect_signatures_precedes_inception(void *arg)
{
  (void) arg;

  uint32_t now = (uint32_t) approx_time();

  dns_rr_t *rrsig = dns_rr_new();
  rrsig->rrtype = dns_type_of(DNS_TYPE_RRSIG);
  rrsig->rrsig = dns_rrsig_new();
  rrsig->rrsig->signer_name = dns_name_of("com.");
  rrsig->rrsig->algorithm = DNSSEC_ALG_RSASHA256;
  rrsig->rrsig->key_tag = 0;
  rrsig->rrsig->signature_expiration = now + 360;
  rrsig->rrsig->signature_inception = now + 180;

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rrsig);

  dns_rr_t *dnskey = dns_rr_new();
  dnskey->name = dns_name_of("com.");
  dnskey->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  dnskey->dnskey = dns_dnskey_new();
  dnskey->dnskey->protocol = 3;
  dnskey->dnskey->flags = 257;
  dnskey->dnskey->algorithm = DNSSEC_ALG_RSASHA256;

  smartlist_t *dnskey_rrset = smartlist_new();
  smartlist_add(dnskey_rrset, dnskey);

  smartlist_t *signatures = dnssec_collect_signatures(rrset, dnskey_rrset);
  tt_int_op(smartlist_len(signatures), OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(rrset);
  SMARTLIST_FOREACH(dnskey_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(dnskey_rrset);
  smartlist_free(signatures);
}

static void
test_crypto_dnssec_collect_signatures_misses_dnskey(void *arg)
{
  (void) arg;

  uint32_t now = (uint32_t) approx_time();

  dns_rr_t *rrsig = dns_rr_new();
  rrsig->rrtype = dns_type_of(DNS_TYPE_RRSIG);
  rrsig->rrsig = dns_rrsig_new();
  rrsig->rrsig->signer_name = dns_name_of("com.");
  rrsig->rrsig->algorithm = DNSSEC_ALG_RSASHA256;
  rrsig->rrsig->key_tag = 0;
  rrsig->rrsig->signature_expiration = now + 360;
  rrsig->rrsig->signature_inception = now - 360;

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rrsig);

  dns_rr_t *dnskey = dns_rr_new();
  dnskey->name = dns_name_of("com.");
  dnskey->validation_state = DNSSEC_VALIDATION_STATE_INSECURE;
  dnskey->dnskey = dns_dnskey_new();
  dnskey->dnskey->protocol = 3;
  dnskey->dnskey->flags = 257;
  dnskey->dnskey->algorithm = DNSSEC_ALG_RSASHA256;

  smartlist_t *dnskey_rrset = smartlist_new();
  smartlist_add(dnskey_rrset, dnskey);

  smartlist_t *signatures = dnssec_collect_signatures(rrset, dnskey_rrset);
  tt_int_op(smartlist_len(signatures), OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(rrset);
  SMARTLIST_FOREACH(dnskey_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(dnskey_rrset);
  smartlist_free(signatures);
}

static void
test_crypto_dnssec_has_potential_dnskey_is_present(void *arg)
{
  (void) arg;

  dns_rr_t *signature = dns_rr_new();
  signature->rrsig = dns_rrsig_new();
  signature->rrsig->signer_name = dns_name_of("com.");
  signature->rrtype = dns_type_of(DNS_TYPE_RRSIG);
  signature->rrsig->algorithm = DNSSEC_ALG_RSASHA256;
  signature->rrsig->key_tag = 0;

  dns_rr_t *dnskey = dns_rr_new();
  dnskey->name = dns_name_of("com.");
  dnskey->rrtype = dns_type_of(DNS_TYPE_DNSKEY);
  dnskey->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  dnskey->dnskey = dns_dnskey_new();
  dnskey->dnskey->protocol = 3;
  dnskey->dnskey->flags = 257;
  dnskey->dnskey->algorithm = DNSSEC_ALG_RSASHA256;

  smartlist_t *dnskey_rrset = smartlist_new();
  smartlist_add(dnskey_rrset, dnskey);

  tt_assert(dnssec_has_potential_dnskey(signature, dnskey_rrset));

 done:
  SMARTLIST_FOREACH(dnskey_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(dnskey_rrset);
  dns_rr_free(signature);
}

static void
test_crypto_dnssec_has_potential_dnskey_missess_zone_flag_bit(void *arg)
{
  (void) arg;

  dns_rr_t *signature = dns_rr_new();
  signature->rrsig = dns_rrsig_new();
  signature->rrsig->signer_name = dns_name_of("com.");
  signature->rrsig->algorithm = DNSSEC_ALG_RSASHA256;
  signature->rrsig->key_tag = 0;

  dns_rr_t *dnskey = dns_rr_new();
  dnskey->name = dns_name_of("com.");
  dnskey->rrtype = dns_type_of(DNS_TYPE_DNSKEY);
  dnskey->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  dnskey->dnskey = dns_dnskey_new();
  dnskey->dnskey->protocol = 3;
  dnskey->dnskey->flags = 1;
  dnskey->dnskey->algorithm = DNSSEC_ALG_RSASHA256;

  smartlist_t *dnskey_rrset = smartlist_new();
  smartlist_add(dnskey_rrset, dnskey);

  tt_assert(!dnssec_has_potential_dnskey(signature, dnskey_rrset));

 done:
  SMARTLIST_FOREACH(dnskey_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(dnskey_rrset);
  dns_rr_free(signature);
}

static void
test_crypto_dnssec_has_potential_dnskey_unauthenticated(void *arg)
{
  (void) arg;

  dns_rr_t *signature = dns_rr_new();
  signature->rrsig = dns_rrsig_new();
  signature->rrsig->signer_name = dns_name_of("com.");
  signature->rrsig->algorithm = DNSSEC_ALG_RSASHA256;
  signature->rrsig->key_tag = 0;

  dns_rr_t *dnskey = dns_rr_new();
  dnskey->name = dns_name_of("com.");
  dnskey->rrtype = dns_type_of(DNS_TYPE_DNSKEY);
  dnskey->validation_state = DNSSEC_VALIDATION_STATE_INSECURE;
  dnskey->dnskey = dns_dnskey_new();
  dnskey->dnskey->protocol = 3;
  dnskey->dnskey->flags = 257;
  dnskey->dnskey->algorithm = DNSSEC_ALG_RSASHA256;

  smartlist_t *dnskey_rrset = smartlist_new();
  smartlist_add(dnskey_rrset, dnskey);

  tt_assert(!dnssec_has_potential_dnskey(signature, dnskey_rrset));

 done:
  SMARTLIST_FOREACH(dnskey_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(dnskey_rrset);
  dns_rr_free(signature);
}

static void
test_crypto_dnssec_has_potential_dnskey_invalid_key_tag(void *arg)
{
  (void) arg;

  dns_rr_t *signature = dns_rr_new();
  signature->rrsig = dns_rrsig_new();
  signature->rrsig->signer_name = dns_name_of("com.");
  signature->rrsig->algorithm = DNSSEC_ALG_RSASHA256;
  signature->rrsig->key_tag = 123;

  dns_rr_t *dnskey = dns_rr_new();
  dnskey->name = dns_name_of("com.");
  dnskey->rrtype = dns_type_of(DNS_TYPE_DNSKEY);
  dnskey->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  dnskey->dnskey = dns_dnskey_new();
  dnskey->dnskey->protocol = 3;
  dnskey->dnskey->flags = 257;
  dnskey->dnskey->algorithm = DNSSEC_ALG_RSASHA256;

  smartlist_t *dnskey_rrset = smartlist_new();
  smartlist_add(dnskey_rrset, dnskey);

  tt_assert(!dnssec_has_potential_dnskey(signature, dnskey_rrset));

 done:
  SMARTLIST_FOREACH(dnskey_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(dnskey_rrset);
  dns_rr_free(signature);
}

static void
test_crypto_dnssec_has_potential_dnskey_different_algorithms(void *arg)
{
  (void) arg;

  dns_rr_t *signature = dns_rr_new();
  signature->rrsig = dns_rrsig_new();
  signature->rrsig->signer_name = dns_name_of("com.");
  signature->rrsig->algorithm = DNSSEC_ALG_RSASHA1;
  signature->rrsig->key_tag = 0;

  dns_rr_t *dnskey = dns_rr_new();
  dnskey->name = dns_name_of("com.");
  dnskey->rrtype = dns_type_of(DNS_TYPE_DNSKEY);
  dnskey->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  dnskey->dnskey = dns_dnskey_new();
  dnskey->dnskey->protocol = 3;
  dnskey->dnskey->flags = 257;
  dnskey->dnskey->algorithm = DNSSEC_ALG_RSASHA256;

  smartlist_t *dnskey_rrset = smartlist_new();
  smartlist_add(dnskey_rrset, dnskey);

  tt_assert(!dnssec_has_potential_dnskey(signature, dnskey_rrset));

 done:
  SMARTLIST_FOREACH(dnskey_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(dnskey_rrset);
  dns_rr_free(signature);
}

static void
test_crypto_dnssec_has_potential_dnskey_not_covering_signers_name(void *arg)
{
  (void) arg;

  dns_rr_t *signature = dns_rr_new();
  signature->rrsig = dns_rrsig_new();
  signature->rrsig->signer_name = dns_name_of("com.");
  signature->rrsig->algorithm = DNSSEC_ALG_RSASHA256;
  signature->rrsig->key_tag = 0;

  dns_rr_t *dnskey = dns_rr_new();
  dnskey->name = dns_name_of("example.com.");
  dnskey->rrtype = dns_type_of(DNS_TYPE_DNSKEY);
  dnskey->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  dnskey->dnskey = dns_dnskey_new();
  dnskey->dnskey->protocol = 3;
  dnskey->dnskey->flags = 257;
  dnskey->dnskey->algorithm = DNSSEC_ALG_RSASHA256;

  smartlist_t *dnskey_rrset = smartlist_new();
  smartlist_add(dnskey_rrset, dnskey);

  tt_assert(!dnssec_has_potential_dnskey(signature, dnskey_rrset));

 done:
  SMARTLIST_FOREACH(dnskey_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(dnskey_rrset);
  dns_rr_free(signature);
}

static void
test_crypto_dnssec_has_potential_dnskey_invalid_protocol(void *arg)
{
  (void) arg;

  dns_rr_t *signature = dns_rr_new();
  signature->rrsig = dns_rrsig_new();
  signature->rrsig->signer_name = dns_name_of("com.");
  signature->rrsig->algorithm = DNSSEC_ALG_RSASHA256;
  signature->rrsig->key_tag = 0;

  dns_rr_t *dnskey = dns_rr_new();
  dnskey->name = dns_name_of("com.");
  dnskey->rrtype = dns_type_of(DNS_TYPE_DNSKEY);
  dnskey->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  dnskey->dnskey = dns_dnskey_new();
  dnskey->dnskey->protocol = 0;
  dnskey->dnskey->flags = 257;
  dnskey->dnskey->algorithm = DNSSEC_ALG_RSASHA256;

  smartlist_t *dnskey_rrset = smartlist_new();
  smartlist_add(dnskey_rrset, dnskey);

  tt_assert(!dnssec_has_potential_dnskey(signature, dnskey_rrset));

 done:
  SMARTLIST_FOREACH(dnskey_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(dnskey_rrset);
  dns_rr_free(signature);
}

static void
test_crypto_dnssec_collect_rrset_succeeds(void *arg)
{
  (void) arg;

  dns_rr_t *signature = dns_rr_new();
  signature->name = dns_name_of("example.com.");
  signature->rrclass = DNS_CLASS_IN;
  signature->rrsig = dns_rrsig_new();
  signature->rrsig->signer_name = dns_name_of("com.");
  signature->rrsig->type_covered = dns_type_of(DNS_TYPE_RRSIG);
  signature->rrsig->labels = 1;

  dns_rr_t *rrsig = dns_rr_new();
  rrsig->name = dns_name_of("example.com.");
  rrsig->rrclass = DNS_CLASS_IN;
  rrsig->rrtype = dns_type_of(DNS_TYPE_RRSIG);

  smartlist_t *unauthenticated_rrset = smartlist_new();
  smartlist_add(unauthenticated_rrset, rrsig);

  smartlist_t *rrset = dnssec_collect_rrset(signature, unauthenticated_rrset);
  tt_int_op(smartlist_len(rrset), OP_EQ, 1);

 done:
  SMARTLIST_FOREACH(unauthenticated_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(unauthenticated_rrset);
  dns_rr_free(signature);
  smartlist_free(rrset);
}

static void
test_crypto_dnssec_collect_rrset_invalid_signature_labels(void *arg)
{
  (void) arg;

  dns_rr_t *signature = dns_rr_new();
  signature->name = dns_name_of("example.com.");
  signature->rrclass = DNS_CLASS_IN;
  signature->rrsig = dns_rrsig_new();
  signature->rrsig->signer_name = dns_name_of("com.");
  signature->rrsig->type_covered = dns_type_of(DNS_TYPE_RRSIG);
  signature->rrsig->labels = 3;

  dns_rr_t *rrsig = dns_rr_new();
  rrsig->name = dns_name_of("example.com.");
  rrsig->rrclass = DNS_CLASS_IN;
  rrsig->rrtype = dns_type_of(DNS_TYPE_RRSIG);

  smartlist_t *unauthenticated_rrset = smartlist_new();
  smartlist_add(unauthenticated_rrset, rrsig);

  smartlist_t *rrset = dnssec_collect_rrset(signature, unauthenticated_rrset);
  tt_int_op(smartlist_len(rrset), OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(unauthenticated_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(unauthenticated_rrset);
  dns_rr_free(signature);
  smartlist_free(rrset);
}

static void
test_crypto_dnssec_collect_rrset_invalid_cover_type(void *arg)
{
  (void) arg;

  dns_rr_t *signature = dns_rr_new();
  signature->name = dns_name_of("example.com.");
  signature->rrclass = DNS_CLASS_IN;
  signature->rrsig = dns_rrsig_new();
  signature->rrsig->signer_name = dns_name_of("com.");
  signature->rrsig->type_covered = dns_type_of(DNS_TYPE_RRSIG);
  signature->rrsig->labels = 1;

  dns_rr_t *rrsig = dns_rr_new();
  rrsig->name = dns_name_of("example.com.");
  rrsig->rrclass = DNS_CLASS_IN;
  rrsig->rrtype = dns_type_of(DNS_TYPE_A);

  smartlist_t *unauthenticated_rrset = smartlist_new();
  smartlist_add(unauthenticated_rrset, rrsig);

  smartlist_t *rrset = dnssec_collect_rrset(signature, unauthenticated_rrset);
  tt_int_op(smartlist_len(rrset), OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(unauthenticated_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(unauthenticated_rrset);
  dns_rr_free(signature);
  smartlist_free(rrset);
}

static void
test_crypto_dnssec_collect_rrset_invalid_signer_name(void *arg)
{
  (void) arg;

  dns_rr_t *signature = dns_rr_new();
  signature->name = dns_name_of("example.com.");
  signature->rrclass = DNS_CLASS_IN;
  signature->rrsig = dns_rrsig_new();
  signature->rrsig->signer_name = dns_name_of("org.");
  signature->rrsig->type_covered = dns_type_of(DNS_TYPE_RRSIG);
  signature->rrsig->labels = 1;

  dns_rr_t *rrsig = dns_rr_new();
  rrsig->name = dns_name_of("example.com.");
  rrsig->rrclass = DNS_CLASS_IN;
  rrsig->rrtype = dns_type_of(DNS_TYPE_RRSIG);

  smartlist_t *unauthenticated_rrset = smartlist_new();
  smartlist_add(unauthenticated_rrset, rrsig);

  smartlist_t *rrset = dnssec_collect_rrset(signature, unauthenticated_rrset);
  tt_int_op(smartlist_len(rrset), OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(unauthenticated_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(unauthenticated_rrset);
  dns_rr_free(signature);
  smartlist_free(rrset);
}

static void
test_crypto_dnssec_collect_rrset_invalid_class(void *arg)
{
  (void) arg;

  dns_rr_t *signature = dns_rr_new();
  signature->name = dns_name_of("example.com.");
  signature->rrclass = DNS_CLASS_IN;
  signature->rrsig = dns_rrsig_new();
  signature->rrsig->signer_name = dns_name_of("com.");
  signature->rrsig->type_covered = dns_type_of(DNS_TYPE_RRSIG);
  signature->rrsig->labels = 1;

  dns_rr_t *rrsig = dns_rr_new();
  rrsig->name = dns_name_of("example.com.");
  rrsig->rrclass = DNS_CLASS_CHAOS;
  rrsig->rrtype = dns_type_of(DNS_TYPE_RRSIG);

  smartlist_t *unauthenticated_rrset = smartlist_new();
  smartlist_add(unauthenticated_rrset, rrsig);

  smartlist_t *rrset = dnssec_collect_rrset(signature, unauthenticated_rrset);
  tt_int_op(smartlist_len(rrset), OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(unauthenticated_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(unauthenticated_rrset);
  dns_rr_free(signature);
  smartlist_free(rrset);
}

static void
test_crypto_dnssec_collect_rrset_invalid_name(void *arg)
{
  (void) arg;

  dns_rr_t *signature = dns_rr_new();
  signature->name = dns_name_of("example.com.");
  signature->rrclass = DNS_CLASS_IN;
  signature->rrsig = dns_rrsig_new();
  signature->rrsig->signer_name = dns_name_of("com.");
  signature->rrsig->type_covered = dns_type_of(DNS_TYPE_RRSIG);
  signature->rrsig->labels = 1;

  dns_rr_t *rrsig = dns_rr_new();
  rrsig->name = dns_name_of("example.org.");
  rrsig->rrclass = DNS_CLASS_IN;
  rrsig->rrtype = dns_type_of(DNS_TYPE_RRSIG);

  smartlist_t *unauthenticated_rrset = smartlist_new();
  smartlist_add(unauthenticated_rrset, rrsig);

  smartlist_t *rrset = dnssec_collect_rrset(signature, unauthenticated_rrset);
  tt_int_op(smartlist_len(rrset), OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(unauthenticated_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(unauthenticated_rrset);
  dns_rr_free(signature);
  smartlist_free(rrset);
}

static void
test_crypto_dnssec_validate_rrset_succeeds(void *arg)
{
  (void) arg;

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset,
                dns_rr_value_of("example.com. 85799 IN DS 31406 8 1 189968811e"
                                "6eba862dd6c209f75623d8d9ed9142"));
  smartlist_add(rrset,
                dns_rr_value_of("example.com. 85799 IN DS 43547 8 2 615a642335"
                                "43f66f44d68933625b17497c89a70e858ed76a2145997"
                                "edf96a918"));
  smartlist_add(rrset,
                dns_rr_value_of("example.com. 85799 IN DS 31406 8 2 f78cf3344f"
                                "72137235098ecbbd08947c2c9001c7f6a085a17f518b5"
                                "d8f6b916d"));
  smartlist_add(rrset,
                dns_rr_value_of("example.com. 85799 IN DS 31589 8 1 3490a6806d"
                                "47f17a34c29e2ce80e8a999ffbe4be"));
  smartlist_add(rrset,
                dns_rr_value_of("example.com. 85799 IN DS 43547 8 1 b6225ab2cc"
                                "613e0dca7962bdc2342ea4f1b56083"));
  smartlist_add(rrset,
                dns_rr_value_of("example.com. 85799 IN DS 31589 8 2 cde0d742d6"
                                "998aa554a92d890f8184c698cfac8a26fa59875a990c0"
                                "3e576343c"));

  dns_rr_t *dnskey1 =
    dns_rr_value_of("com. 1791 IN DNSKEY 257 3 8 AQPDzldNmMvZFX4NcNJ0uEnKDg7tm"
                    "v/F3MyQR0lpBmVcNcsIszxNFxsBfKNW9JYCYqpik8366LE7VbIcNRzfp2"
                    "h9OO8HRl+H+E08zauK8k7evWEmu/6od+2boggPoiEfGNyvNPaSI7FOIro"
                    "Dsnw/taggzHRX1Z7SOiOiPWPNIwSUyWOZ79VmcQ1GLkC6NlYvG3HwYmyn"
                    "Qv6oFwGv/KELSw7ZSdrbTQ0HXvZbqMUI7BaMskmvgm1G7oKZ1YiF7O9io"
                    "VNc0+7ASbqmZN7Z98EGU/Qh2K/BgUe8Hs0XVcdPKrtyYnoQHd2ynKPcMM"
                    "lTEih2/2HDHjRPJ2aywIpKNnv4oPo/");
  dnskey1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;

  dns_rr_t *dnskey2 =
    dns_rr_value_of("com. 1791 IN DNSKEY 256 3 8 AwEAAaMxolj/9YeqFVf9oKhuUwsMg"
                    "bhQGOipS3Gxz2Fl9HNHrFwiQyG0jIRteAq8Q5NKSVLqDyQfulgzY7Rtvh"
                    "BFj6EWQgaqCJ2gzK7SxvTwFfGrXzoRynkqcTRjkBOFvHCwHu6gOQ9TkOk"
                    "f4BN0e9OBIP2HIG7uRa5RfeplfuGBY/JNu4/N/o+CMsY/TpGvgvBIk6m7"
                    "In8vVQxZvzHhY9yD+2M=");
  dnskey2->validation_state = DNSSEC_VALIDATION_STATE_SECURE;

  dns_rr_t *dnskey3 =
    dns_rr_value_of("com. 1791 IN DNSKEY 256 3 8 AQPVjPYYiWkWvFhogUC0Q8L0oenMR"
                    "6EDF5n7veG6sXTs1FcRzOnI9k0dWSe5g7VFgzZ6Zo/W/gXIsyrli5oL0j"
                    "bzz2zHX7z7RbnrnTlt5p2fbvezMTJrsqiNRCsx1/YiLyGLk52o+u+265H"
                    "i4SM1Zu4bPsjYjCJChxuwZWOvQZ3sZQ==");
  dnskey3->validation_state = DNSSEC_VALIDATION_STATE_SECURE;

  smartlist_t *dnskey_rrset = smartlist_new();
  smartlist_add(dnskey_rrset, dnskey1);
  smartlist_add(dnskey_rrset, dnskey2);
  smartlist_add(dnskey_rrset, dnskey3);

  smartlist_t *rrsig_rrset = smartlist_new();
  smartlist_add(rrsig_rrset,
                dns_rr_value_of("example.org. 37155 IN RRSIG DS 7 2 86400 "
                                "1576765692 1578583692 41987 org. Lic5NgMm4fMc"
                                "j4zx4dzzvnMm59xqGkM90KxZ5tWtlWnUOpIWlY/x/D1ZZ"
                                "6yLv7d+FUvahPs82cr1iZmO5me0vLVmsjU4p703HMHEMY"
                                "Ifkffr7Gt13tfSUOSagO8/O65u9wI6P0e+/5bCKOIBfaP"
                                "dExGerwchrxHA1OBuj1zceCI="));
  smartlist_add(rrsig_rrset,
                dns_rr_value_of("example.com. 85799 IN RRSIG DS 8 2 86400 "
                                "1576901556 1577510556 12163 com. EGDnYqgfVIb4"
                                "W6MMQRA3KpSehoJkWRSuWB357XrtZs5gOruDa2KYWWI7q"
                                "rhT70p92XqvnxKnV0eDmb3SnzCcWdzqgdwSmIqtXXgd4Y"
                                "FhecgfP28mSO7XUstCL337y/v21m1ao6Djv6CLYpTJR6T"
                                "IWnlM6B5uXN18zXzEYcaiJVcYBZR+173MnIZihoO8Wqfe"
                                "d3J78nYAA3QbKqtF8+u1NQ=="));

#ifndef ENABLE_OPENSSL
  tt_skip();
#endif
  tt_int_op(dnssec_validate_rrset(rrset, dnskey_rrset, rrsig_rrset), OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(rrset);
  SMARTLIST_FOREACH(dnskey_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(dnskey_rrset);
  SMARTLIST_FOREACH(rrsig_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(rrsig_rrset);
}

static void
test_crypto_dnssec_validate_rrset_fails(void *arg)
{
  (void) arg;

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset,
                dns_rr_value_of("example.com. 85799 IN DS 31406 8 1 189968811e"
                                "6eba862dd6c209f75623d8d9ed9142"));
  smartlist_add(rrset,
                dns_rr_value_of("example.com. 85799 IN DS 43547 8 2 615a642335"
                                "43f66f44d68933625b17497c89a70e858ed76a2145997"
                                "edf96a918"));

  dns_rr_t *dnskey1 =
    dns_rr_value_of("com. 1791 IN DNSKEY 257 3 8 AQPDzldNmMvZFX4NcNJ0uEnKDg7tm"
                    "v/F3MyQR0lpBmVcNcsIszxNFxsBfKNW9JYCYqpik8366LE7VbIcNRzfp2"
                    "h9OO8HRl+H+E08zauK8k7evWEmu/6od+2boggPoiEfGNyvNPaSI7FOIro"
                    "Dsnw/taggzHRX1Z7SOiOiPWPNIwSUyWOZ79VmcQ1GLkC6NlYvG3HwYmyn"
                    "Qv6oFwGv/KELSw7ZSdrbTQ0HXvZbqMUI7BaMskmvgm1G7oKZ1YiF7O9io"
                    "VNc0+7ASbqmZN7Z98EGU/Qh2K/BgUe8Hs0XVcdPKrtyYnoQHd2ynKPcMM"
                    "lTEih2/2HDHjRPJ2aywIpKNnv4oPo/");
  dnskey1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;

  dns_rr_t *dnskey2 =
    dns_rr_value_of("com. 1791 IN DNSKEY 256 3 8 AwEAAaMxolj/9YeqFVf9oKhuUwsMg"
                    "bhQGOipS3Gxz2Fl9HNHrFwiQyG0jIRteAq8Q5NKSVLqDyQfulgzY7Rtvh"
                    "BFj6EWQgaqCJ2gzK7SxvTwFfGrXzoRynkqcTRjkBOFvHCwHu6gOQ9TkOk"
                    "f4BN0e9OBIP2HIG7uRa5RfeplfuGBY/JNu4/N/o+CMsY/TpGvgvBIk6m7"
                    "In8vVQxZvzHhY9yD+2M=");
  dnskey2->validation_state = DNSSEC_VALIDATION_STATE_SECURE;

  smartlist_t *dnskey_rrset = smartlist_new();
  smartlist_add(dnskey_rrset, dnskey1);
  smartlist_add(dnskey_rrset, dnskey2);

  smartlist_t *rrsig_rrset = smartlist_new();
  smartlist_add(rrsig_rrset,
                dns_rr_value_of("example.com. 85799 IN RRSIG DS 8 2 86400 "
                                "1576901556 1577510556 12163 com. EGDnYqgfVIb4"
                                "W6MMQRA3KpSehoJkWRSuWB357XrtZs5gOruDa2KYWWI7q"
                                "rhT70p92XqvnxKnV0eDmb3SnzCcWdzqgdwSmIqtXXgd4Y"
                                "FhecgfP28mSO7XUstCL337y/v21m1ao6Djv6CLYpTJR6T"
                                "IWnlM6B5uXN18zXzEYcaiJVcYBZR+173MnIZihoO8Wqfe"
                                "d3J78nYAA3QbKqtF8+u1NQ=="));

#ifndef ENABLE_OPENSSL
  tt_skip();
#endif
  tt_int_op(dnssec_validate_rrset(rrset, dnskey_rrset, rrsig_rrset), OP_EQ,
            -1);

 done:
  SMARTLIST_FOREACH(rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(rrset);
  SMARTLIST_FOREACH(dnskey_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(dnskey_rrset);
  SMARTLIST_FOREACH(rrsig_rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(rrsig_rrset);
}

static void
test_crypto_dnssec_verify_signature_rsasha1(void *arg)
{
  (void) arg;

  uint8_t data[] = {
    0x00
  };

  dns_rr_t *dnskey = dns_rr_new();
  dnskey->dnskey = dns_dnskey_new();

  dns_rr_t *rrsig = dns_rr_new();
  rrsig->rrsig = dns_rrsig_new();
  rrsig->rrsig->algorithm = DNSSEC_ALG_RSASHA1;

#ifndef ENABLE_OPENSSL
  tt_skip();
#endif
  tt_int_op(dnssec_verify_signature(data, 0, dnskey, rrsig), OP_EQ, -1);

 done:
  dns_rr_free(dnskey);
  dns_rr_free(rrsig);
}

static void
test_crypto_dnssec_verify_signature_rsasha1nsec3sha1(void *arg)
{
  (void) arg;

  uint8_t data[] = {
    0x00
  };

  dns_rr_t *dnskey = dns_rr_new();
  dnskey->dnskey = dns_dnskey_new();

  dns_rr_t *rrsig = dns_rr_new();
  rrsig->rrsig = dns_rrsig_new();
  rrsig->rrsig->algorithm = DNSSEC_ALG_RSASHA1NSEC3SHA1;

#ifndef ENABLE_OPENSSL
  tt_skip();
#endif
  tt_int_op(dnssec_verify_signature(data, 0, dnskey, rrsig), OP_EQ, -1);

 done:
  dns_rr_free(dnskey);
  dns_rr_free(rrsig);
}

static void
test_crypto_dnssec_verify_signature_rsasha256(void *arg)
{
  (void) arg;

  uint8_t data[] = {
    0x00
  };

  dns_rr_t *dnskey = dns_rr_new();
  dnskey->dnskey = dns_dnskey_new();

  dns_rr_t *rrsig = dns_rr_new();
  rrsig->rrsig = dns_rrsig_new();
  rrsig->rrsig->algorithm = DNSSEC_ALG_RSASHA256;

#ifndef ENABLE_OPENSSL
  tt_skip();
#endif
  tt_int_op(dnssec_verify_signature(data, 0, dnskey, rrsig), OP_EQ, -2);

 done:
  dns_rr_free(dnskey);
  dns_rr_free(rrsig);
}

static void
test_crypto_dnssec_verify_signature_rsasha512(void *arg)
{
  (void) arg;

  uint8_t data[] = {
    0x00
  };

  dns_rr_t *dnskey = dns_rr_new();
  dnskey->dnskey = dns_dnskey_new();

  dns_rr_t *rrsig = dns_rr_new();
  rrsig->rrsig = dns_rrsig_new();
  rrsig->rrsig->algorithm = DNSSEC_ALG_RSASHA512;

#ifndef ENABLE_OPENSSL
  tt_skip();
#endif
  tt_int_op(dnssec_verify_signature(data, 0, dnskey, rrsig), OP_EQ, -3);

 done:
  dns_rr_free(dnskey);
  dns_rr_free(rrsig);
}

static void
test_crypto_dnssec_verify_signature_ecdsap256sha256(void *arg)
{
  (void) arg;

  uint8_t data[] = {
    0x00
  };

  dns_rr_t *dnskey = dns_rr_new();
  dnskey->dnskey = dns_dnskey_new();

  dns_rr_t *rrsig = dns_rr_new();
  rrsig->rrsig = dns_rrsig_new();
  rrsig->rrsig->algorithm = DNSSEC_ALG_ECDSAP256SHA256;

#ifndef ENABLE_OPENSSL
  tt_skip();
#endif
  tt_int_op(dnssec_verify_signature(data, 0, dnskey, rrsig), OP_EQ, -4);

 done:
  dns_rr_free(dnskey);
  dns_rr_free(rrsig);
}

static void
test_crypto_dnssec_verify_signature_ecdsap384sha384(void *arg)
{
  (void) arg;

  uint8_t data[] = {
    0x00
  };

  dns_rr_t *dnskey = dns_rr_new();
  dnskey->dnskey = dns_dnskey_new();

  dns_rr_t *rrsig = dns_rr_new();
  rrsig->rrsig = dns_rrsig_new();
  rrsig->rrsig->algorithm = DNSSEC_ALG_ECDSAP384SHA384;

#ifndef ENABLE_OPENSSL
  tt_skip();
#endif
  tt_int_op(dnssec_verify_signature(data, 0, dnskey, rrsig), OP_EQ, -5);

 done:
  dns_rr_free(dnskey);
  dns_rr_free(rrsig);
}

static void
test_crypto_dnssec_verify_signature_unsupported_algorithm(void *arg)
{
  (void) arg;

  uint8_t data[] = {
    0x00
  };

  dns_rr_t *dnskey = dns_rr_new();
  dnskey->dnskey = dns_dnskey_new();

  dns_rr_t *rrsig = dns_rr_new();
  rrsig->rrsig = dns_rrsig_new();
  rrsig->rrsig->algorithm = DNSSEC_ALG_RSAMD5;

  tt_int_op(dnssec_verify_signature(data, 0, dnskey, rrsig), OP_EQ, -6);

 done:
  dns_rr_free(dnskey);
  dns_rr_free(rrsig);
}

static void
test_crypto_dnssec_verify_signature_succeeds(void *arg)
{
  (void) arg;

  uint8_t data[] = {
      0x00, 0x01, 0x05, 0x02, 0x00, 0x00, 0x01, 0x2C,
      0x5D, 0x4C, 0xD2, 0x7B, 0x5D, 0x25, 0x38, 0x6D,
      0x2E, 0x23, 0x06, 0x70, 0x61, 0x79, 0x70, 0x61,
      0x6C, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x06, 0x70,
      0x61, 0x79, 0x70, 0x61, 0x6C, 0x03, 0x63, 0x6F,
      0x6D, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
      0x01, 0x2C, 0x00, 0x04, 0x40, 0x04, 0xFA, 0x24,
      0x06, 0x70, 0x61, 0x79, 0x70, 0x61, 0x6C, 0x03,
      0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01,
      0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 0x40, 0x04,
      0xFA, 0x25
  };
  size_t data_len = 82;

  uint8_t public_key[] = {
      0x03, 0x01, 0x00, 0x01, 0xCF, 0xFB, 0xAF, 0xBC,
      0x3A, 0xA8, 0x48, 0x39, 0xF6, 0xFC, 0xF2, 0x7D,
      0xC2, 0xA0, 0x22, 0x6E, 0xCA, 0xDE, 0x1E, 0x37,
      0xB6, 0x09, 0x4A, 0x38, 0x98, 0xE8, 0x17, 0x22,
      0xB9, 0x97, 0x18, 0x65, 0xD9, 0xEE, 0xEF, 0x87,
      0xC0, 0xB0, 0xBE, 0x3D, 0xDC, 0xC0, 0xA4, 0x07,
      0x71, 0xCB, 0x2F, 0x5A, 0xEB, 0xC0, 0x2B, 0x4B,
      0xA6, 0x99, 0x34, 0xB2, 0xB3, 0x16, 0x53, 0xD0,
      0x92, 0x60, 0xC3, 0xC8, 0x24, 0x84, 0x81, 0x86,
      0x89, 0x9E, 0xB7, 0x30, 0x94, 0xDC, 0x6E, 0x87,
      0x03, 0x7B, 0x38, 0x19, 0x88, 0x0F, 0xEA, 0xE1,
      0xE8, 0xE9, 0x8D, 0xDA, 0xE3, 0xDB, 0xB8, 0x2C,
      0xE6, 0x60, 0x87, 0x02, 0xCC, 0x82, 0xF4, 0x10,
      0x15, 0x66, 0x2C, 0xAC, 0x7C, 0x8C, 0x2A, 0xB5,
      0x11, 0x6C, 0x3F, 0x41, 0xA3, 0x8A, 0xF3, 0x58,
      0xCC, 0x87, 0x3A, 0xA8, 0x65, 0x80, 0x5D, 0xC0,
      0x09, 0x28, 0xB2, 0xD7
  };
  dns_rr_t *dnskey = dns_rr_new();
  dnskey->dnskey = dns_dnskey_new();
  dnskey->dnskey->public_key = tor_memdup(public_key, 132);
  dnskey->dnskey->public_key_len = 132;

  uint8_t signature[] = {
      0x78, 0x5E, 0x9D, 0x62, 0xCE, 0xE2, 0x1D, 0xCF,
      0xD6, 0x6E, 0x47, 0xE9, 0x6E, 0x0A, 0x9D, 0x5E,
      0xA0, 0xFD, 0x95, 0xF1, 0x5F, 0x39, 0x0E, 0x68,
      0x37, 0x38, 0xD2, 0xD9, 0x30, 0xD1, 0x4A, 0xB4,
      0x08, 0xF1, 0xEB, 0x1B, 0x2F, 0x6B, 0x61, 0xE3,
      0xEF, 0xB8, 0x11, 0x83, 0xF3, 0x05, 0x14, 0x33,
      0x01, 0x36, 0x94, 0xBF, 0x58, 0xC6, 0xE2, 0x60,
      0xD0, 0xEF, 0x98, 0xA0, 0xFA, 0xC0, 0xA4, 0x0A,
      0xFC, 0xEB, 0xD9, 0x58, 0x31, 0x97, 0x14, 0x4D,
      0x6A, 0x91, 0x0B, 0x9F, 0x73, 0x89, 0x48, 0x40,
      0x28, 0x3E, 0x9F, 0xDE, 0x68, 0x58, 0x64, 0x81,
      0x6F, 0x26, 0x8F, 0x2A, 0x8E, 0xFB, 0x34, 0xC3,
      0xCD, 0xF4, 0x48, 0x12, 0x64, 0x63, 0x63, 0x1D,
      0x29, 0xBD, 0x24, 0xDC, 0xCB, 0x95, 0xE8, 0x2B,
      0xB6, 0x7B, 0x73, 0xF9, 0x87, 0xE7, 0x17, 0x0B,
      0x4F, 0x26, 0x09, 0x9E, 0x79, 0x93, 0xCB, 0x76
  };
  dns_rr_t *rrsig = dns_rr_new();
  rrsig->rrsig = dns_rrsig_new();
  rrsig->rrsig->algorithm = DNSSEC_ALG_RSASHA1;
  rrsig->rrsig->signature = tor_memdup(signature, 128);
  rrsig->rrsig->signature_len = 128;

#ifndef ENABLE_OPENSSL
  tt_skip();
#endif
  tt_int_op(dnssec_verify_signature(data, data_len, dnskey, rrsig), OP_EQ, 0);

 done:
  dns_rr_free(dnskey);
  dns_rr_free(rrsig);
}

static void
test_crypto_dnssec_nsec_denial_of_existence_name_error(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("ml.example.");

  dns_rr_t *rr1 = dns_rr_value_of("b.example. 0 IN NSEC ns1.example.");
  rr1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr1->signer =
    dns_rr_value_of("b.example. 0 IN RRSIG NSEC 0 2 0 0 0 0 example. abc");

  dns_rr_t *rr2 = dns_rr_value_of("example. 0 IN NSEC a.example.");
  rr2->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr2->signer =
    dns_rr_value_of("example. 0 IN RRSIG NSEC 0 1 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr1);
  smartlist_add(rrset, rr2);

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec_denial_of_existence(&result, qname, DNS_TYPE_A, rr1,
                                            rrset), OP_EQ, 8);
  tt_int_op(result, OP_EQ, DNSSEC_DENIAL_OF_EXISTENCE_NXDOMAIN);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(rr1->signer);
  dns_rr_free(rr1);
  dns_rr_free(rr2->signer);
  dns_rr_free(rr2);
}

static void
test_crypto_dnssec_nsec_denial_of_existence_wildcard_exists(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("ml.example.");

  dns_rr_t *rr1 = dns_rr_value_of("b.example. 0 IN NSEC ns1.example.");
  rr1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr1->signer =
    dns_rr_value_of("b.example. 0 IN RRSIG NSEC 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr1);

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec_denial_of_existence(&result, qname, DNS_TYPE_A, rr1,
                                            rrset), OP_EQ, 7);
  tt_int_op(result, OP_EQ, DNSSEC_DENIAL_OF_EXISTENCE_NODATA);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(rr1->signer);
  dns_rr_free(rr1);
}

static void
test_crypto_dnssec_nsec_denial_of_existence_has_wildcard(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("ns1.example");

  dns_rr_t *covers_wildcard = dns_rr_value_of("example. 0 IN NSEC a.example.");
  covers_wildcard->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  covers_wildcard->signer =
    dns_rr_value_of("example. 0 IN RRSIG NSEC 0 1 0 0 0 0 example. abc");

  dns_rr_t *matches_qname =
    dns_rr_value_of("ns1.example. 0 IN NSEC ns2.example. A RRSIG");
  matches_qname->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  matches_qname->signer =
    dns_rr_value_of("ns1.example. 0 IN RRSIG NSEC 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, covers_wildcard);
  smartlist_add(rrset, matches_qname);

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec_denial_of_existence(&result, qname, DNS_TYPE_MX,
                                            matches_qname, rrset),
            OP_EQ, 6);
  tt_int_op(result, OP_EQ, DNSSEC_DENIAL_OF_EXISTENCE_NODATA);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(covers_wildcard->signer);
  dns_rr_free(covers_wildcard);
  dns_rr_free(matches_qname->signer);
  dns_rr_free(matches_qname);
}

static void
test_crypto_dnssec_nsec_denial_of_existence_no_data_error(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("ns1.example");

  dns_rr_t *matches_qname =
    dns_rr_value_of("ns1.example. 0 IN NSEC ns2.example. A RRSIG");
  matches_qname->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  matches_qname->signer =
    dns_rr_value_of("ns1.example. 0 IN RRSIG NSEC 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, matches_qname);

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec_denial_of_existence(&result, qname, DNS_TYPE_MX,
                                            matches_qname, rrset),
            OP_EQ, 5);
  tt_int_op(result, OP_EQ, DNSSEC_DENIAL_OF_EXISTENCE_NXQTYPE);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(matches_qname->signer);
  dns_rr_free(matches_qname);
}

static void
test_crypto_dnssec_nsec_denial_of_existence_insecure_ancestor_delegation(
                                                                     void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("ns1.example");

  dns_rr_t *matches_qname =
    dns_rr_value_of("ns1.example. 0 IN NSEC ns2.example. A RRSIG");
  matches_qname->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  matches_qname->signer =
    dns_rr_value_of("ns1.example. 0 IN RRSIG NSEC 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, matches_qname);

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec_denial_of_existence(&result, qname, DNS_TYPE_DS,
                                            matches_qname, rrset),
            OP_EQ, 4);
  tt_int_op(result, OP_EQ, DNSSEC_DENIAL_OF_EXISTENCE_NODATA);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(matches_qname->signer);
  dns_rr_free(matches_qname);
}

static void
test_crypto_dnssec_nsec_denial_of_existence_cname_is_present(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("ns1.example");

  dns_rr_t *matches_qname =
    dns_rr_value_of("ns1.example. 0 IN NSEC ns2.example. CNAME RRSIG");
  matches_qname->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  matches_qname->signer =
    dns_rr_value_of("ns1.example. 0 IN RRSIG NSEC 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, matches_qname);

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec_denial_of_existence(&result, qname, DNS_TYPE_A,
                                            matches_qname, rrset), OP_EQ, 3);
  tt_int_op(result, OP_EQ, DNSSEC_DENIAL_OF_EXISTENCE_NODATA);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(matches_qname->signer);
  dns_rr_free(matches_qname);
}

static void
test_crypto_dnssec_nsec_denial_of_existence_bit_is_present(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("ns1.example");

  dns_rr_t *matches_qname =
    dns_rr_value_of("ns1.example. 0 IN NSEC ns2.example. A RRSIG");
  matches_qname->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  matches_qname->signer =
    dns_rr_value_of("ns1.example. 0 IN RRSIG NSEC 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, matches_qname);

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec_denial_of_existence(&result, qname, DNS_TYPE_A,
                                            matches_qname, rrset), OP_EQ, 2);
  tt_int_op(result, OP_EQ, DNSSEC_DENIAL_OF_EXISTENCE_NODATA);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(matches_qname->signer);
  dns_rr_free(matches_qname);
}

static void
test_crypto_dnssec_nsec_denial_of_existence_invalid_ancestor_delegation(
                                                                     void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("ns1.example");

  dns_rr_t *matches_qname =
    dns_rr_value_of("ns1.example. 0 IN NSEC ns2.example. A NS RRSIG");
  matches_qname->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  matches_qname->signer =
    dns_rr_value_of("ns1.example. 0 IN RRSIG NSEC 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, matches_qname);

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec_denial_of_existence(&result, qname, DNS_TYPE_A,
                                            matches_qname, rrset), OP_EQ, 1);
  tt_int_op(result, OP_EQ, DNSSEC_DENIAL_OF_EXISTENCE_NODATA);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(matches_qname->signer);
  dns_rr_free(matches_qname);
}

static void
test_crypto_dnssec_nsec_denial_of_existence_without_matching_owner(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("ns1.different");

  dns_rr_t *matches_qname =
    dns_rr_value_of("ns1.example. 0 IN NSEC ns2.example. A NS RRSIG");
  matches_qname->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  matches_qname->signer =
    dns_rr_value_of("ns1.example. 0 IN RRSIG NSEC 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, matches_qname);

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec_denial_of_existence(&result, qname, DNS_TYPE_A,
                                            matches_qname, rrset),
            OP_EQ, 0);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(matches_qname->signer);
  dns_rr_free(matches_qname);
}

static void
test_crypto_dnssec_nsec_denial_of_existence_covering_nsec_is_absent(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("ml.example.");

  dns_rr_t *rr = dns_rr_value_of("example. 0 IN NSEC a.example.");
  rr->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr->signer =
    dns_rr_value_of("example. 0 IN RRSIG NSEC 0 1 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr);

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec_denial_of_existence(&result, qname, DNS_TYPE_A,
                                            rr, rrset), OP_EQ, 0);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(rr->signer);
  dns_rr_free(rr);
}

static void
test_crypto_dnssec_nsec_prove_no_wildcard_with_covering_nsec(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("ml.example");

  dns_rr_t *rr = dns_rr_value_of("example. 0 IN NSEC a.example.");
  rr->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr->signer =
    dns_rr_value_of("example. 0 IN RRSIG NSEC 0 1 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr);

  bool wildcard_exists = false;
  tt_int_op(dnssec_nsec_prove_no_wildcard(&wildcard_exists, qname,
                                          DNS_TYPE_A, rrset), OP_EQ, 0);
  tt_assert(!wildcard_exists);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(rr->signer);
  dns_rr_free(rr);
}

static void
test_crypto_dnssec_nsec_prove_no_wildcard_covering_nsec_is_absent(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("w.example");

  dns_rr_t *rr = dns_rr_value_of("b.example. 0 IN NSEC ns1.example.");
  rr->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr->signer =
    dns_rr_value_of("b.example. 0 IN RRSIG NSEC 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr);

  bool wildcard_exists = false;
  tt_int_op(dnssec_nsec_prove_no_wildcard(&wildcard_exists, qname,
                                          DNS_TYPE_A, rrset), OP_EQ, 1);
  tt_assert(!wildcard_exists);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(rr->signer);
  dns_rr_free(rr);
}

static void
test_crypto_dnssec_nsec_prove_no_wildcard_with_matching_absent_type(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("a.z.w.example.");

  dns_rr_t *rr1 = dns_rr_value_of("x.y.w.example. 0 IN NSEC xx.example.");
  rr1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr1->signer =
    dns_rr_value_of("x.y.w.example. 0 IN RRSIG NSEC 0 4 0 0 0 0 example. abc");

  dns_rr_t *rr2 = dns_rr_value_of("*.w.example. 0 IN NSEC x.w.example.");
  rr2->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr2->signer =
    dns_rr_value_of("*.w.example. 0 IN RRSIG NSEC 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr1);
  smartlist_add(rrset, rr2);

  bool wildcard_exists = false;
  tt_int_op(dnssec_nsec_prove_no_wildcard(&wildcard_exists, qname,
                                          DNS_TYPE_AAAA, rrset), OP_EQ, 0);
  tt_assert(wildcard_exists);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(rr1->signer);
  dns_rr_free(rr1);
  dns_rr_free(rr2->signer);
  dns_rr_free(rr2);
}

static void
test_crypto_dnssec_nsec_prove_no_wildcard_with_matching_existing_type(
                                                                     void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("a.z.w.example.");

  dns_rr_t *rr1 = dns_rr_value_of("x.y.w.example. 0 IN NSEC xx.example.");
  rr1->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr1->signer =
    dns_rr_value_of("x.y.w.example. 0 IN RRSIG NSEC 0 4 0 0 0 0 example. abc");

  dns_rr_t *rr2 = dns_rr_value_of("*.w.example. 0 IN NSEC x.w.example. AAAA");
  rr2->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr2->signer =
    dns_rr_value_of("*.w.example. 0 IN RRSIG NSEC 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, rr1);
  smartlist_add(rrset, rr2);

  bool wildcard_exists = false;
  tt_int_op(dnssec_nsec_prove_no_wildcard(&wildcard_exists, qname,
                                          DNS_TYPE_AAAA, rrset), OP_EQ, 1);
  tt_assert(wildcard_exists);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(rr1->signer);
  dns_rr_free(rr1);
  dns_rr_free(rr2->signer);
  dns_rr_free(rr2);
}

static void
test_crypto_dnssec_nsec_name_is_covered_within_bounds(void *arg)
{
  (void) arg;

  dns_name_t *name = dns_name_of("ml.example.");
  dns_name_t *owner = dns_name_of("b.example.");
  dns_name_t *next = dns_name_of("ns1.example.");

  tt_assert(dnssec_nsec_name_is_covered(name, owner, next));

 done:
  dns_name_free(name);
  dns_name_free(owner);
  dns_name_free(next);
}

static void
test_crypto_dnssec_nsec_name_is_covered_beyond_left_bound(void *arg)
{
  (void) arg;

  dns_name_t *name = dns_name_of("ml.example.");
  dns_name_t *owner = dns_name_of("ns1.example.");
  dns_name_t *next = dns_name_of("ns2.example.");

  tt_assert(!dnssec_nsec_name_is_covered(name, owner, next));

 done:
  dns_name_free(name);
  dns_name_free(owner);
  dns_name_free(next);
}

static void
test_crypto_dnssec_nsec_name_is_covered_beyond_right_bound(void *arg)
{
  (void) arg;

  dns_name_t *name = dns_name_of("a.z.w.example.");
  dns_name_t *owner = dns_name_of("ns1.example.");
  dns_name_t *next = dns_name_of("ns2.example.");

  tt_assert(!dnssec_nsec_name_is_covered(name, owner, next));

 done:
  dns_name_free(name);
  dns_name_free(owner);
  dns_name_free(next);
}

static void
test_crypto_dnssec_nsec3_denial_of_existence_no_data_error(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("ns1.example");

  dns_rr_t *rr =
    dns_rr_value_of("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD 2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG");
  rr->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr->signer =
    dns_rr_value_of("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec3_denial_of_existence(&result, qname, DNS_TYPE_MX, rr),
            OP_EQ, 5);
  tt_int_op(result, OP_EQ, DNSSEC_DENIAL_OF_EXISTENCE_NXQTYPE);

 done:
  dns_name_free(qname);
  dns_rr_free(rr->signer);
  dns_rr_free(rr);
}

static void
test_crypto_dnssec_nsec3_denial_of_existence_insecure_ancestor_delegation(
                                                                     void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("example");

  dns_rr_t *rr =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD 2t7b4g4vsa5smi47k61mv5bv1a22bojr A RRSIG");
  rr->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr->signer =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec3_denial_of_existence(&result, qname, DNS_TYPE_DS, rr),
            OP_EQ, 4);
  tt_int_op(result, OP_EQ, DNSSEC_DENIAL_OF_EXISTENCE_NODATA);

 done:
  dns_name_free(qname);
  dns_rr_free(rr->signer);
  dns_rr_free(rr);
}

static void
test_crypto_dnssec_nsec3_denial_of_existence_cname_is_present(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("x.y.w.example");

  dns_rr_t *rr =
    dns_rr_value_of("2vptu5timamqttgl4luu9kg21e0aor3s.example. 0 IN NSEC3 1 0 "
                   "12 AABBCCDD 35mthgpgcu1qg68fab165klnsnk3dpvl CNAME RRSIG");
  rr->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr->signer =
    dns_rr_value_of("2vptu5timamqttgl4luu9kg21e0aor3s.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec3_denial_of_existence(&result, qname, DNS_TYPE_A, rr),
            OP_EQ, 3);
  tt_int_op(result, OP_EQ, DNSSEC_DENIAL_OF_EXISTENCE_NODATA);

 done:
  dns_name_free(qname);
  dns_rr_free(rr->signer);
  dns_rr_free(rr);
}

static void
test_crypto_dnssec_nsec3_denial_of_existence_bit_is_present(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("x.y.w.example");

  dns_rr_t *rr =
    dns_rr_value_of("2vptu5timamqttgl4luu9kg21e0aor3s.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD 35mthgpgcu1qg68fab165klnsnk3dpvl A RRSIG");
  rr->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr->signer =
    dns_rr_value_of("2vptu5timamqttgl4luu9kg21e0aor3s.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec3_denial_of_existence(&result, qname, DNS_TYPE_A, rr),
            OP_EQ, 2);
  tt_int_op(result, OP_EQ, DNSSEC_DENIAL_OF_EXISTENCE_NODATA);

 done:
  dns_name_free(qname);
  dns_rr_free(rr->signer);
  dns_rr_free(rr);
}

static void
test_crypto_dnssec_nsec3_denial_of_existence_invalid_ancestor_delegation(
                                                                     void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("x.y.w.example");

  dns_rr_t *rr =
    dns_rr_value_of("2vptu5timamqttgl4luu9kg21e0aor3s.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD 35mthgpgcu1qg68fab165klnsnk3dpvl A NS RRSIG");
  rr->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr->signer =
    dns_rr_value_of("2vptu5timamqttgl4luu9kg21e0aor3s.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec3_denial_of_existence(&result, qname, DNS_TYPE_A, rr),
            OP_EQ, 1);
  tt_int_op(result, OP_EQ, DNSSEC_DENIAL_OF_EXISTENCE_NODATA);

 done:
  dns_name_free(qname);
  dns_rr_free(rr->signer);
  dns_rr_free(rr);
}

static void
test_crypto_dnssec_nsec3_denial_of_existence_without_matching_owner(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("x.y.w.different");

  dns_rr_t *rr =
    dns_rr_value_of("2vptu5timamqttgl4luu9kg21e0aor3s.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD 35mthgpgcu1qg68fab165klnsnk3dpvl A NS RRSIG");
  rr->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  rr->signer =
    dns_rr_value_of("2vptu5timamqttgl4luu9kg21e0aor3s.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec3_denial_of_existence(&result, qname, DNS_TYPE_A, rr),
            OP_EQ, 0);

 done:
  dns_name_free(qname);
  dns_rr_free(rr->signer);
  dns_rr_free(rr);
}

static void
test_crypto_dnssec_nsec3_encloser_proof_name_error(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("a.c.x.w.example");

  dns_rr_t *covers_next_closer =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD 2t7b4g4vsa5smi47k61mv5bv1a22bojr");
  covers_next_closer->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  covers_next_closer->signer =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  dns_rr_t *matches_closest_encloser =
    dns_rr_value_of("b4um86eghhds6nea196smvmlo4ors995.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD gjeqe526plbf1g8mklp59enfd789njgi");
  matches_closest_encloser->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  matches_closest_encloser->signer =
    dns_rr_value_of("b4um86eghhds6nea196smvmlo4ors995.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  dns_rr_t *covers_wildcard_closest_encloser =
    dns_rr_value_of("35mthgpgcu1qg68fab165klnsnk3dpvl.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD b4um86eghhds6nea196smvmlo4ors995");
  covers_wildcard_closest_encloser->validation_state =
    DNSSEC_VALIDATION_STATE_SECURE;
  covers_wildcard_closest_encloser->signer =
    dns_rr_value_of("35mthgpgcu1qg68fab165klnsnk3dpvl.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, covers_next_closer);
  smartlist_add(rrset, matches_closest_encloser);
  smartlist_add(rrset, covers_wildcard_closest_encloser);

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec3_encloser_proof(&result, qname, DNS_TYPE_A, rrset),
            OP_EQ, 4);
  tt_int_op(result, OP_EQ, DNSSEC_DENIAL_OF_EXISTENCE_NXDOMAIN);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(covers_next_closer->signer);
  dns_rr_free(covers_next_closer);
  dns_rr_free(matches_closest_encloser->signer);
  dns_rr_free(matches_closest_encloser);
  dns_rr_free(covers_wildcard_closest_encloser->signer);
  dns_rr_free(covers_wildcard_closest_encloser);
}

static void
test_crypto_dnssec_nsec3_encloser_proof_type_error(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("a.c.x.w.example");

  dns_rr_t *covers_next_closer =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD 2t7b4g4vsa5smi47k61mv5bv1a22bojr");
  covers_next_closer->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  covers_next_closer->signer =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  dns_rr_t *matches_closest_encloser =
    dns_rr_value_of("b4um86eghhds6nea196smvmlo4ors995.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD gjeqe526plbf1g8mklp59enfd789njgi");
  matches_closest_encloser->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  matches_closest_encloser->signer =
    dns_rr_value_of("b4um86eghhds6nea196smvmlo4ors995.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  dns_rr_t *matches_wildcard_closest_encloser =
    dns_rr_value_of("92pqneegtaue7pjatc3l3qnk738c6v5m.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD b4um86eghhds6nea196smvmlo4ors995");
  matches_wildcard_closest_encloser->validation_state =
    DNSSEC_VALIDATION_STATE_SECURE;
  matches_wildcard_closest_encloser->signer =
    dns_rr_value_of("92pqneegtaue7pjatc3l3qnk738c6v5m.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, covers_next_closer);
  smartlist_add(rrset, matches_closest_encloser);
  smartlist_add(rrset, matches_wildcard_closest_encloser);

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec3_encloser_proof(&result, qname, DNS_TYPE_A, rrset),
            OP_EQ, 3);
  tt_int_op(result, OP_EQ, DNSSEC_DENIAL_OF_EXISTENCE_NODATA);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(covers_next_closer->signer);
  dns_rr_free(covers_next_closer);
  dns_rr_free(matches_closest_encloser->signer);
  dns_rr_free(matches_closest_encloser);
  dns_rr_free(matches_wildcard_closest_encloser->signer);
  dns_rr_free(matches_wildcard_closest_encloser);
}

static void
test_crypto_dnssec_nsec3_encloser_proof_wildcard_exists(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("a.c.x.w.example");

  dns_rr_t *covers_next_closer =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD 2t7b4g4vsa5smi47k61mv5bv1a22bojr");
  covers_next_closer->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  covers_next_closer->signer =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  dns_rr_t *matches_closest_encloser =
    dns_rr_value_of("b4um86eghhds6nea196smvmlo4ors995.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD gjeqe526plbf1g8mklp59enfd789njgi");
  matches_closest_encloser->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  matches_closest_encloser->signer =
    dns_rr_value_of("b4um86eghhds6nea196smvmlo4ors995.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  dns_rr_t *matches_wildcard_closest_encloser =
    dns_rr_value_of("92pqneegtaue7pjatc3l3qnk738c6v5m.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD b4um86eghhds6nea196smvmlo4ors995 A");
  matches_wildcard_closest_encloser->validation_state =
    DNSSEC_VALIDATION_STATE_SECURE;
  matches_wildcard_closest_encloser->signer =
    dns_rr_value_of("92pqneegtaue7pjatc3l3qnk738c6v5m.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, covers_next_closer);
  smartlist_add(rrset, matches_closest_encloser);
  smartlist_add(rrset, matches_wildcard_closest_encloser);

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec3_encloser_proof(&result, qname, DNS_TYPE_A, rrset),
            OP_EQ, 2);
  tt_int_op(result, OP_EQ, DNSSEC_DENIAL_OF_EXISTENCE_NODATA);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(covers_next_closer->signer);
  dns_rr_free(covers_next_closer);
  dns_rr_free(matches_closest_encloser->signer);
  dns_rr_free(matches_closest_encloser);
  dns_rr_free(matches_wildcard_closest_encloser->signer);
  dns_rr_free(matches_wildcard_closest_encloser);
}

static void
test_crypto_dnssec_nsec3_encloser_proof_has_opt_out_flag(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("a.c.x.w.example");

  dns_rr_t *covers_next_closer =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN NSEC3 1 1 "
                    "12 AABBCCDD 2t7b4g4vsa5smi47k61mv5bv1a22bojr");
  covers_next_closer->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  covers_next_closer->signer =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  dns_rr_t *matches_closest_encloser =
    dns_rr_value_of("b4um86eghhds6nea196smvmlo4ors995.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD gjeqe526plbf1g8mklp59enfd789njgi");
  matches_closest_encloser->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  matches_closest_encloser->signer =
    dns_rr_value_of("b4um86eghhds6nea196smvmlo4ors995.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  dns_rr_t *matches_wildcard_closest_encloser =
    dns_rr_value_of("92pqneegtaue7pjatc3l3qnk738c6v5m.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD b4um86eghhds6nea196smvmlo4ors995 A");
  matches_wildcard_closest_encloser->validation_state =
    DNSSEC_VALIDATION_STATE_SECURE;
  matches_wildcard_closest_encloser->signer =
    dns_rr_value_of("92pqneegtaue7pjatc3l3qnk738c6v5m.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, covers_next_closer);
  smartlist_add(rrset, matches_closest_encloser);
  smartlist_add(rrset, matches_wildcard_closest_encloser);

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec3_encloser_proof(&result, qname, DNS_TYPE_DS, rrset),
            OP_EQ, 1);
  tt_int_op(result, OP_EQ, DNSSEC_DENIAL_OF_EXISTENCE_OPTOUT);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(covers_next_closer->signer);
  dns_rr_free(covers_next_closer);
  dns_rr_free(matches_closest_encloser->signer);
  dns_rr_free(matches_closest_encloser);
  dns_rr_free(matches_wildcard_closest_encloser->signer);
  dns_rr_free(matches_wildcard_closest_encloser);
}

static void
test_crypto_dnssec_nsec3_encloser_proof_without_closest_encloser(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("a.c.x.w.example");

  dns_rr_t *covers_next_closer =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD 2t7b4g4vsa5smi47k61mv5bv1a22bojr");
  covers_next_closer->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  covers_next_closer->signer =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  dns_rr_t *matches_wildcard_closest_encloser =
    dns_rr_value_of("92pqneegtaue7pjatc3l3qnk738c6v5m.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD b4um86eghhds6nea196smvmlo4ors995 A");
  matches_wildcard_closest_encloser->validation_state =
    DNSSEC_VALIDATION_STATE_SECURE;
  matches_wildcard_closest_encloser->signer =
    dns_rr_value_of("92pqneegtaue7pjatc3l3qnk738c6v5m.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, covers_next_closer);
  smartlist_add(rrset, matches_wildcard_closest_encloser);

  denial_of_existence_t result;
  tt_int_op(dnssec_nsec3_encloser_proof(&result, qname, DNS_TYPE_A, rrset),
            OP_EQ, 0);

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(covers_next_closer->signer);
  dns_rr_free(covers_next_closer);
  dns_rr_free(matches_wildcard_closest_encloser->signer);
  dns_rr_free(matches_wildcard_closest_encloser);
}

static void
test_crypto_dnssec_nsec3_closest_encloser_with_matching_nsec(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("a.c.x.w.example");

  dns_rr_t *matches_closest_encloser =
    dns_rr_value_of("b4um86eghhds6nea196smvmlo4ors995.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD gjeqe526plbf1g8mklp59enfd789njgi");
  matches_closest_encloser->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  matches_closest_encloser->signer =
    dns_rr_value_of("b4um86eghhds6nea196smvmlo4ors995.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, matches_closest_encloser);

  dns_name_t *closest_encloser = NULL;
  tt_int_op(dnssec_nsec3_closest_encloser(&closest_encloser, qname, DNS_TYPE_A,
                                          rrset), OP_EQ, 0);
  tt_str_op(dns_name_str(closest_encloser), OP_EQ, "x.w.example");

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(matches_closest_encloser->signer);
  dns_rr_free(matches_closest_encloser);
  dns_name_free(closest_encloser);
}

static void
test_crypto_dnssec_nsec3_closest_encloser_matching_nsec_is_absent(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("a.c.x.w.example");

  dns_rr_t *covers_wildcard_closest_encloser =
    dns_rr_value_of("35mthgpgcu1qg68fab165klnsnk3dpvl.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD b4um86eghhds6nea196smvmlo4ors995");
  covers_wildcard_closest_encloser->validation_state =
    DNSSEC_VALIDATION_STATE_SECURE;
  covers_wildcard_closest_encloser->signer =
    dns_rr_value_of("35mthgpgcu1qg68fab165klnsnk3dpvl.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, covers_wildcard_closest_encloser);

  dns_name_t *closest_encloser = NULL;
  tt_int_op(dnssec_nsec3_closest_encloser(&closest_encloser, qname, DNS_TYPE_A,
                                          rrset), OP_EQ, -1);
  tt_str_op(dns_name_str(closest_encloser), OP_EQ, "");

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(covers_wildcard_closest_encloser->signer);
  dns_rr_free(covers_wildcard_closest_encloser);
  dns_name_free(closest_encloser);
}

static void
test_crypto_dnssec_nsec3_closest_encloser_invalid_ancestor_delegation(
                                                                     void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("a.c.x.w.example");

  dns_rr_t *matches_closest_encloser =
    dns_rr_value_of("b4um86eghhds6nea196smvmlo4ors995.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD gjeqe526plbf1g8mklp59enfd789njgi A NS RRSIG");
  matches_closest_encloser->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  matches_closest_encloser->signer =
    dns_rr_value_of("b4um86eghhds6nea196smvmlo4ors995.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, matches_closest_encloser);

  dns_name_t *closest_encloser = NULL;
  tt_int_op(dnssec_nsec3_closest_encloser(&closest_encloser, qname, DNS_TYPE_A,
                                          rrset), OP_EQ, -1);
  tt_str_op(dns_name_str(closest_encloser), OP_EQ, "");

 done:
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(matches_closest_encloser->signer);
  dns_rr_free(matches_closest_encloser);
  dns_name_free(closest_encloser);
}

static void
test_crypto_dnssec_nsec3_next_closer_with_covering_nsec(void *arg)
{
  (void) arg;

  dns_name_t *closest_encloser = dns_name_of("x.w.example");
  dns_name_t *qname = dns_name_of("a.c.x.w.example");

  dns_rr_t *covers_next_closer =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD 2t7b4g4vsa5smi47k61mv5bv1a22bojr");
  covers_next_closer->validation_state =
    DNSSEC_VALIDATION_STATE_SECURE;
  covers_next_closer->signer =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, covers_next_closer);

  bool opt_out = false;
  tt_int_op(dnssec_nsec3_next_closer(&opt_out, closest_encloser, qname,
                                     DNS_TYPE_A, rrset),
            OP_EQ, 0);
  tt_assert(!opt_out);

 done:
  dns_name_free(closest_encloser);
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(covers_next_closer->signer);
  dns_rr_free(covers_next_closer);
}

static void
test_crypto_dnssec_nsec3_next_closer_covering_nsec_is_absent(void *arg)
{
  (void) arg;

  dns_name_t *closest_encloser = dns_name_of("x.w.example");
  dns_name_t *qname = dns_name_of("a.c.x.w.example");

  dns_rr_t *matches_closest_encloser =
    dns_rr_value_of("b4um86eghhds6nea196smvmlo4ors995.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD gjeqe526plbf1g8mklp59enfd789njgi");
  matches_closest_encloser->validation_state =
    DNSSEC_VALIDATION_STATE_SECURE;
  matches_closest_encloser->signer =
    dns_rr_value_of("b4um86eghhds6nea196smvmlo4ors995.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, matches_closest_encloser);

  bool opt_out = false;
  tt_int_op(dnssec_nsec3_next_closer(&opt_out, closest_encloser, qname,
                                     DNS_TYPE_A, rrset),
            OP_EQ, -1);
  tt_assert(!opt_out);

 done:
  dns_name_free(closest_encloser);
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(matches_closest_encloser->signer);
  dns_rr_free(matches_closest_encloser);
}

static void
test_crypto_dnssec_nsec3_next_closer_qname_is_closest_encloser(void *arg)
{
  (void) arg;

  dns_name_t *closest_encloser = dns_name_of("a.c.x.w.example");
  dns_name_t *qname = dns_name_of("a.c.x.w.example");

  dns_rr_t *covers_next_closer =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD 2t7b4g4vsa5smi47k61mv5bv1a22bojr");
  covers_next_closer->validation_state =
    DNSSEC_VALIDATION_STATE_SECURE;
  covers_next_closer->signer =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, covers_next_closer);

  bool opt_out = false;
  tt_int_op(dnssec_nsec3_next_closer(&opt_out, closest_encloser, qname,
                                     DNS_TYPE_A, rrset),
            OP_EQ, -2);
  tt_assert(!opt_out);

 done:
  dns_name_free(closest_encloser);
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(covers_next_closer->signer);
  dns_rr_free(covers_next_closer);
}

static void
test_crypto_dnssec_nsec3_next_closer_has_opt_out_flag(void *arg)
{
  (void) arg;

  dns_name_t *closest_encloser = dns_name_of("x.w.example");
  dns_name_t *qname = dns_name_of("a.c.x.w.example");

  dns_rr_t *covers_next_closer =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN NSEC3 1 1 "
                    "12 AABBCCDD 2t7b4g4vsa5smi47k61mv5bv1a22bojr");
  covers_next_closer->validation_state =
    DNSSEC_VALIDATION_STATE_SECURE;
  covers_next_closer->signer =
    dns_rr_value_of("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, covers_next_closer);

  bool opt_out = false;
  tt_int_op(dnssec_nsec3_next_closer(&opt_out, closest_encloser, qname,
                                     DNS_TYPE_DS, rrset),
            OP_EQ, 0);
  tt_assert(opt_out);

 done:
  dns_name_free(closest_encloser);
  dns_name_free(qname);
  smartlist_free(rrset);
  dns_rr_free(covers_next_closer->signer);
  dns_rr_free(covers_next_closer);
}

static void
test_crypto_dnssec_nsec3_prove_no_wildcard_with_covering_nsec(void *arg)
{
  (void) arg;

  dns_name_t *closest_encloser = dns_name_of("x.w.example");

  dns_rr_t *covers_wildcard_closest_encloser =
    dns_rr_value_of("35mthgpgcu1qg68fab165klnsnk3dpvl.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD b4um86eghhds6nea196smvmlo4ors995");
  covers_wildcard_closest_encloser->validation_state =
    DNSSEC_VALIDATION_STATE_SECURE;
  covers_wildcard_closest_encloser->signer =
    dns_rr_value_of("35mthgpgcu1qg68fab165klnsnk3dpvl.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, covers_wildcard_closest_encloser);

  bool wildcard_exists = false;
  tt_int_op(dnssec_nsec3_prove_no_wildcard(&wildcard_exists, closest_encloser,
                                           DNS_TYPE_A, rrset), OP_EQ, 0);
  tt_assert(!wildcard_exists);

 done:
  dns_name_free(closest_encloser);
  smartlist_free(rrset);
  dns_rr_free(covers_wildcard_closest_encloser->signer);
  dns_rr_free(covers_wildcard_closest_encloser);
}

static void
test_crypto_dnssec_nsec3_prove_no_wildcard_covering_nsec_is_absent(void *arg)
{
  (void) arg;

  dns_name_t *closest_encloser = dns_name_of("w.example");

  dns_rr_t *covers_wildcard_closest_encloser =
    dns_rr_value_of("35mthgpgcu1qg68fab165klnsnk3dpvl.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD b4um86eghhds6nea196smvmlo4ors995");
  covers_wildcard_closest_encloser->validation_state =
    DNSSEC_VALIDATION_STATE_SECURE;
  covers_wildcard_closest_encloser->signer =
    dns_rr_value_of("35mthgpgcu1qg68fab165klnsnk3dpvl.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, covers_wildcard_closest_encloser);

  bool wildcard_exists = false;
  tt_int_op(dnssec_nsec3_prove_no_wildcard(&wildcard_exists, closest_encloser,
                                           DNS_TYPE_A, rrset), OP_EQ, 1);
  tt_assert(!wildcard_exists);

 done:
  dns_name_free(closest_encloser);
  smartlist_free(rrset);
  dns_rr_free(covers_wildcard_closest_encloser->signer);
  dns_rr_free(covers_wildcard_closest_encloser);
}

static void
test_crypto_dnssec_nsec3_prove_no_wildcard_with_matching_absent_type(void *arg)
{
  (void) arg;

  dns_name_t *closest_encloser = dns_name_of("w.example");

  dns_rr_t *matches_wildcard_closest_encloser =
    dns_rr_value_of("r53bq7cc2uvmubfu5ocmm6pers9tk9en.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD t644ebqk9bibcna874givr6joj62mlhv");
  matches_wildcard_closest_encloser->validation_state =
    DNSSEC_VALIDATION_STATE_SECURE;
  matches_wildcard_closest_encloser->signer =
    dns_rr_value_of("r53bq7cc2uvmubfu5ocmm6pers9tk9en.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, matches_wildcard_closest_encloser);

  bool wildcard_exists = false;
  tt_int_op(dnssec_nsec3_prove_no_wildcard(&wildcard_exists, closest_encloser,
                                           DNS_TYPE_A, rrset), OP_EQ, 0);
  tt_assert(wildcard_exists);

 done:
  dns_name_free(closest_encloser);
  smartlist_free(rrset);
  dns_rr_free(matches_wildcard_closest_encloser->signer);
  dns_rr_free(matches_wildcard_closest_encloser);
}

static void
test_crypto_dnssec_nsec3_prove_no_wildcard_with_matching_existing_type(
                                                                     void *arg)
{
  (void) arg;

  dns_name_t *closest_encloser = dns_name_of("w.example");

  dns_rr_t *matches_wildcard_closest_encloser =
    dns_rr_value_of("r53bq7cc2uvmubfu5ocmm6pers9tk9en.example. 0 IN NSEC3 1 0 "
                    "12 AABBCCDD t644ebqk9bibcna874givr6joj62mlhv A");
  matches_wildcard_closest_encloser->validation_state =
    DNSSEC_VALIDATION_STATE_SECURE;
  matches_wildcard_closest_encloser->signer =
    dns_rr_value_of("r53bq7cc2uvmubfu5ocmm6pers9tk9en.example. 0 IN RRSIG "
                    "NSEC3 0 2 0 0 0 0 example. abc");

  smartlist_t *rrset = smartlist_new();
  smartlist_add(rrset, matches_wildcard_closest_encloser);

  bool wildcard_exists = false;
  tt_int_op(dnssec_nsec3_prove_no_wildcard(&wildcard_exists, closest_encloser,
                                           DNS_TYPE_A, rrset), OP_EQ, 1);
  tt_assert(wildcard_exists);

 done:
  dns_name_free(closest_encloser);
  smartlist_free(rrset);
  dns_rr_free(matches_wildcard_closest_encloser->signer);
  dns_rr_free(matches_wildcard_closest_encloser);
}

static void
test_crypto_dnssec_nsec3_hash_is_covered_within_bounds(void *arg)
{
  (void) arg;

  char *hash = (char *) "22670trplhsr72pqqmedltg1kdqeolb7";
  dns_name_t *owner = dns_name_of("1avvqn74sg75ukfvf25dgcethgq638ek.example."
                                  "org.");
  char *next_hashed_owner_name = (char *) "75B9ID679QQOV6LDFHD8OCSHSSSB6JVQ";

  char decoded_next[DIGEST_LEN];
  base32hex_decode(decoded_next, sizeof(decoded_next), next_hashed_owner_name,
                   strlen(next_hashed_owner_name));
  tt_assert(dnssec_nsec3_hash_is_covered(hash, owner,
            (const uint8_t *) decoded_next, sizeof(decoded_next)));

 done:
  dns_name_free(owner);
}

static void
test_crypto_dnssec_nsec3_hash_is_covered_beyond_left_bound(void *arg)
{
  (void) arg;

  char *hash = (char *) "15bg9l6359f5ch23e34ddua6n1rihl9h";
  dns_name_t *owner = dns_name_of("15bg9l6359f5ch23e34ddua6n1rihl9h.example."
                                  "org.");
  char *next_hashed_owner_name = (char *) "1AVVQN74SG75UKFVF25DGCETHGQ638EK";

  char decoded_next[DIGEST_LEN];
  base32hex_decode(decoded_next, sizeof(decoded_next), next_hashed_owner_name,
                   strlen(next_hashed_owner_name));
  tt_assert(!dnssec_nsec3_hash_is_covered(hash, owner,
            (const uint8_t *) decoded_next, sizeof(decoded_next)));

 done:
  dns_name_free(owner);
}

static void
test_crypto_dnssec_nsec3_hash_is_covered_beyond_right_bound(void *arg)
{
  (void) arg;

  char *hash = (char *) "ndtu6dste50pr4a1f2qvr1v31g00i2i1";
  dns_name_t *owner = dns_name_of("15bg9l6359f5ch23e34ddua6n1rihl9h.example."
                                  "org.");
  char *next_hashed_owner_name = (char *) "1AVVQN74SG75UKFVF25DGCETHGQ638EK";

  char decoded_next[DIGEST_LEN];
  base32hex_decode(decoded_next, sizeof(decoded_next), next_hashed_owner_name,
                   strlen(next_hashed_owner_name));
  tt_assert(!dnssec_nsec3_hash_is_covered(hash, owner,
                                          (const uint8_t *) decoded_next,
                                          sizeof(decoded_next)));

 done:
  dns_name_free(owner);
}

static void
test_crypto_dnssec_nsec3_hash_providing_parameters_by_nsec3param(void *arg)
{
  (void) arg;

  dns_name_t *name = dns_name_of("example");

  uint8_t salt[] = {
      0xAA, 0xBB, 0xCC, 0xDD
  };

  dns_rr_t *rr = dns_rr_new();
  rr->rrtype = dns_type_of(DNS_TYPE_NSEC3PARAM);
  rr->nsec3param = dns_nsec3param_new();
  rr->nsec3param->iterations = 12;
  rr->nsec3param->salt = tor_memdup(salt, sizeof(salt));
  rr->nsec3param->salt_length = sizeof(salt);

  char *hash = NULL;
  tt_int_op(dnssec_nsec3_hash(&hash, name, rr), OP_EQ, 0);
  tt_str_op(hash, OP_EQ, "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM");

 done:
  dns_name_free(name);
  dns_rr_free(rr);
  tor_free(hash);
}

static void
test_crypto_dnssec_nsec3_hash_providing_parameters_by_nsec3(void *arg)
{
  (void) arg;

  dns_name_t *name = dns_name_of("x.y.w.example");

  uint8_t salt[] = {
      0xAA, 0xBB, 0xCC, 0xDD
  };

  dns_rr_t *rr = dns_rr_new();
  rr->rrtype = dns_type_of(DNS_TYPE_NSEC3);
  rr->nsec3 = dns_nsec3_new();
  rr->nsec3->iterations = 12;
  rr->nsec3->salt = tor_memdup(salt, sizeof(salt));
  rr->nsec3->salt_length = sizeof(salt);

  char *hash = NULL;
  tt_int_op(dnssec_nsec3_hash(&hash, name, rr), OP_EQ, 0);
  tt_str_op(hash, OP_EQ, "2VPTU5TIMAMQTTGL4LUU9KG21E0AOR3S");

 done:
  dns_name_free(name);
  dns_rr_free(rr);
  tor_free(hash);
}

static void
test_crypto_dnssec_nsec3_hash_providing_invalid_parameters(void *arg)
{
  (void) arg;

  dns_name_t *name = dns_name_of("x.y.w.example");

  dns_rr_t *rr = dns_rr_new();
  rr->rrtype = dns_type_of(DNS_TYPE_A);

  char *hash = NULL;
  tt_int_op(dnssec_nsec3_hash(&hash, name, rr), OP_EQ, -1);

 done:
  dns_name_free(name);
  dns_rr_free(rr);
  tor_free(hash);
}

static void
test_crypto_dnssec_nsec3_digest_sha1(void *arg)
{
  (void) arg;

  dns_name_t *example = dns_name_of("example");

  size_t qname_len = 0;
  uint8_t *qname = dns_encode_canonical_name(example, &qname_len);
  uint8_t salt[] = {
      0xAA, 0xBB, 0xCC, 0xDD
  };
  uint8_t digest[DIGEST_LEN];

  tt_int_op(dnssec_nsec3_digest_sha1(digest, qname, qname_len, salt,
                                     sizeof(salt), 1), OP_EQ, 0);

 done:
  dns_name_free(example);
  tor_free(qname);
}

static void
test_crypto_dnssec_is_ancestor_delegation_all_conditions_met(void *arg)
{
  (void) arg;

  dns_name_t *ns1_example = dns_name_of("ns1.example.");
  dns_name_t *example = dns_name_of("example.");

  smartlist_t *types = smartlist_new();
  smartlist_add(types, dns_type_of(DNS_TYPE_NS));

  tt_assert(dnssec_is_ancestor_delegation(ns1_example, example, types));

 done:
  dns_name_free(ns1_example);
  dns_name_free(example);
  SMARTLIST_FOREACH(types, dns_type_t *, type, dns_type_free(type));
  smartlist_free(types);
}

static void
test_crypto_dnssec_is_ancestor_delegation_with_invalid_types(void *arg)
{
  (void) arg;

  dns_name_t *ns1_example = dns_name_of("ns1.example.");
  dns_name_t *example = dns_name_of("example.");

  smartlist_t *types = smartlist_new();
  smartlist_add(types, dns_type_of(DNS_TYPE_NS));
  smartlist_add(types, dns_type_of(DNS_TYPE_SOA));

  tt_assert(!dnssec_is_ancestor_delegation(ns1_example, example, types));

 done:
  dns_name_free(ns1_example);
  dns_name_free(example);
  SMARTLIST_FOREACH(types, dns_type_t *, type, dns_type_free(type));
  smartlist_free(types);
}

static void
test_crypto_dnssec_is_ancestor_delegation_with_invalid_signer(void *arg)
{
  (void) arg;

  dns_name_t *ns1_example = dns_name_of("ns1.example.");

  smartlist_t *types = smartlist_new();
  smartlist_add(types, dns_type_of(DNS_TYPE_NS));

  tt_assert(!dnssec_is_ancestor_delegation(ns1_example, ns1_example, types));

 done:
  dns_name_free(ns1_example);
  SMARTLIST_FOREACH(types, dns_type_t *, type, dns_type_free(type));
  smartlist_free(types);
}

static void
test_crypto_dnssec_get_rr_owner_for_original_name(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();
  rr->name = dns_name_of("example.");

  dns_rrsig_t *rrsig = dns_rrsig_new();
  rrsig->labels = 1;

  dns_name_t *owner = dnssec_get_rr_owner(rr, rrsig);
  tt_str_op(dns_name_str(owner), OP_EQ, "example.");

 done:
  dns_rr_free(rr);
  dns_rrsig_free(rrsig);
  dns_name_free(owner);
}

static void
test_crypto_dnssec_get_rr_owner_for_expanded_name(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();
  rr->name = dns_name_of("x.y.w.example.");

  dns_rrsig_t *rrsig = dns_rrsig_new();
  rrsig->labels = 2;

  dns_name_t *owner = dnssec_get_rr_owner(rr, rrsig);
  tt_str_op(dns_name_str(owner), OP_EQ, "*.w.example.");

 done:
  dns_rr_free(rr);
  dns_rrsig_free(rrsig);
  dns_name_free(owner);
}

static void
test_crypto_dnssec_comparator_canonical_name_ordering(void *arg)
{
  (void) arg;

  smartlist_t *rrset = smartlist_new();

  dns_rr_t *rr1 = dns_rr_value_of("example. 0 IN A 0.0.0.0");
  dns_rr_t *rr2 = dns_rr_value_of("a.example. 0 IN A 0.0.0.0");
  dns_rr_t *rr3 = dns_rr_value_of("yljkjljk.a.example. 0 IN A 0.0.0.0");
  dns_rr_t *rr4 = dns_rr_value_of("Z.a.example. 0 IN A 0.0.0.0");
  dns_rr_t *rr5 = dns_rr_value_of("zABC.a.EXAMPLE. 0 IN A 0.0.0.0");
  dns_rr_t *rr6 = dns_rr_value_of("z.example. 0 IN A 0.0.0.0");
  dns_rr_t *rr7 = dns_rr_value_of("\001.z.example. 0 IN A 0.0.0.0");
  dns_rr_t *rr8 = dns_rr_value_of("*.z.example. 0 IN A 0.0.0.0");
  dns_rr_t *rr9 = dns_rr_value_of("\200.z.example. 0 IN A 0.0.0.0");

  smartlist_add(rrset, rr2);
  smartlist_add(rrset, rr9);
  smartlist_add(rrset, rr1);
  smartlist_add(rrset, rr8);
  smartlist_add(rrset, rr3);
  smartlist_add(rrset, rr7);
  smartlist_add(rrset, rr6);
  smartlist_add(rrset, rr5);
  smartlist_add(rrset, rr4);

  smartlist_sort(rrset, dnssec_comparator_canonical_name_ordering);

  tt_str_op(dns_name_str(((dns_rr_t *) smartlist_get(rrset, 0))->name), OP_EQ,
            dns_name_str(rr1->name));
  tt_str_op(dns_name_str(((dns_rr_t *) smartlist_get(rrset, 1))->name), OP_EQ,
            dns_name_str(rr2->name));
  tt_str_op(dns_name_str(((dns_rr_t *) smartlist_get(rrset, 2))->name), OP_EQ,
            dns_name_str(rr3->name));
  tt_str_op(dns_name_str(((dns_rr_t *) smartlist_get(rrset, 3))->name), OP_EQ,
            dns_name_str(rr4->name));
  tt_str_op(dns_name_str(((dns_rr_t *) smartlist_get(rrset, 4))->name), OP_EQ,
            dns_name_str(rr5->name));
  tt_str_op(dns_name_str(((dns_rr_t *) smartlist_get(rrset, 5))->name), OP_EQ,
            dns_name_str(rr6->name));
  tt_str_op(dns_name_str(((dns_rr_t *) smartlist_get(rrset, 6))->name), OP_EQ,
            dns_name_str(rr7->name));
  tt_str_op(dns_name_str(((dns_rr_t *) smartlist_get(rrset, 7))->name), OP_EQ,
            dns_name_str(rr8->name));
  tt_str_op(dns_name_str(((dns_rr_t *) smartlist_get(rrset, 8))->name), OP_EQ,
            dns_name_str(rr9->name));

 done:
  SMARTLIST_FOREACH(rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(rrset);
}

static void
test_crypto_dnssec_comparator_canonical_rdata_ordering(void *arg)
{
  (void) arg;

  smartlist_t *rrset = smartlist_new();

  dns_rr_t *rr1 = dns_rr_value_of("example.com. 0 IN A 1.2.3.4");
  dns_rr_t *rr2 = dns_rr_value_of("example.com. 0 IN A 5.6.7.8");
  dns_rr_t *rr3 = dns_rr_value_of("example.com. 0 IN A 11.2.3.4");
  dns_rr_t *rr4 = dns_rr_value_of("example.com. 0 IN A 12.2.3.4");

  smartlist_add(rrset, rr4);
  smartlist_add(rrset, rr2);
  smartlist_add(rrset, rr3);
  smartlist_add(rrset, rr1);

  smartlist_sort(rrset, dnssec_comparator_canonical_rdata_ordering);

  tt_str_op(rr1->a, OP_EQ, ((dns_rr_t *)smartlist_get(rrset, 0))->a);
  tt_str_op(rr2->a, OP_EQ, ((dns_rr_t *)smartlist_get(rrset, 1))->a);
  tt_str_op(rr3->a, OP_EQ, ((dns_rr_t *)smartlist_get(rrset, 2))->a);
  tt_str_op(rr4->a, OP_EQ, ((dns_rr_t *)smartlist_get(rrset, 3))->a);

 done:
  SMARTLIST_FOREACH(rrset, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(rrset);
}

static void
test_crypto_dnssec_labels(void *arg)
{
  (void) arg;

  dns_name_t *name_empty = dns_name_of("");
  dns_name_t *name_space = dns_name_of(" ");
  dns_name_t *name_root = dns_name_of(".");
  dns_name_t *name_trailing_space = dns_name_of(". ");
  dns_name_t *name_missing_trailing_dot = dns_name_of("net");
  dns_name_t *name_contains_space = dns_name_of("org .");
  dns_name_t *name_two_labels = dns_name_of("example.org.");
  dns_name_t *name_three_labels = dns_name_of("www.example.net");
  dns_name_t *name_four_labels = dns_name_of("x.y.w.example");

  int empty = dns_labels(name_empty);
  int space = dns_labels(name_space);
  int root = dns_labels(name_root);
  int trailing_space = dns_labels(name_trailing_space);
  int missing_trailing_dot = dns_labels(name_missing_trailing_dot);
  int contains_space = dns_labels(name_contains_space);
  int two_labels = dns_labels(name_two_labels);
  int three_labels = dns_labels(name_three_labels);
  int four_labels = dns_labels(name_four_labels);

  tt_int_op(empty, OP_EQ, 0);
  tt_int_op(space, OP_EQ, 0);
  tt_int_op(root, OP_EQ, 0);
  tt_int_op(trailing_space, OP_EQ, 0);
  tt_int_op(missing_trailing_dot, OP_EQ, 1);
  tt_int_op(contains_space, OP_EQ, 1);
  tt_int_op(two_labels, OP_EQ, 2);
  tt_int_op(three_labels, OP_EQ, 3);
  tt_int_op(four_labels, OP_EQ, 4);

 done:
  dns_name_free(name_empty);
  dns_name_free(name_space);
  dns_name_free(name_root);
  dns_name_free(name_trailing_space);
  dns_name_free(name_missing_trailing_dot);
  dns_name_free(name_contains_space);
  dns_name_free(name_two_labels);
  dns_name_free(name_three_labels);
  dns_name_free(name_four_labels);
}

static void
test_crypto_dnssec_common_labels(void *arg)
{
  (void) arg;

  dns_name_t *empty = dns_name_of("");
  dns_name_t *example = dns_name_of("example");
  dns_name_t *example_com = dns_name_of("example.com");
  dns_name_t *example_org = dns_name_of("example.org");
  dns_name_t *example_root = dns_name_of("eXaMple.");
  dns_name_t *ns1_example_root = dns_name_of("ns1.example.");
  dns_name_t *root = dns_name_of(".");
  dns_name_t *x_y_w_example = dns_name_of("x.y.w.example");
  dns_name_t *z_y_w_example = dns_name_of("z.y.w.example");

  tt_int_op(dns_common_labels(example, empty), OP_EQ, 0);
  tt_int_op(dns_common_labels(example_com, example_org), OP_EQ, 0);
  tt_int_op(dns_common_labels(root, root), OP_EQ, 0);
  tt_int_op(dns_common_labels(example, example_root), OP_EQ, 1);
  tt_int_op(dns_common_labels(ns1_example_root, example), OP_EQ, 1);
  tt_int_op(dns_common_labels(x_y_w_example, z_y_w_example), OP_EQ, 3);

 done:
  dns_name_free(empty);
  dns_name_free(example);
  dns_name_free(example_com);
  dns_name_free(example_org);
  dns_name_free(example_root);
  dns_name_free(ns1_example_root);
  dns_name_free(root);
  dns_name_free(x_y_w_example);
  dns_name_free(z_y_w_example);
}

static void
test_crypto_dnssec_strip_left_label_from_invalid_name(void *arg)
{
  (void) arg;

  dns_name_t *name = dns_name_new();

  dns_strip_left_label(name);

  tt_str_op(dns_name_str(name), OP_EQ, "");

 done:
  dns_name_free(name);
}

static void
test_crypto_dnssec_strip_left_label_from_empty_name(void *arg)
{
  (void) arg;

  dns_name_t *name = dns_name_of("");

  dns_strip_left_label(name);

  tt_str_op(dns_name_str(name), OP_EQ, "");

 done:
  dns_name_free(name);
}

static void
test_crypto_dnssec_strip_left_label_from_root(void *arg)
{
  (void) arg;

  dns_name_t *name = dns_name_of(".");

  dns_strip_left_label(name);

  tt_str_op(dns_name_str(name), OP_EQ, "");

 done:
  dns_name_free(name);
}

static void
test_crypto_dnssec_strip_left_label_from_name(void *arg)
{
  (void) arg;

  dns_name_t *name = dns_name_of("hello.world.");

  dns_strip_left_label(name);

  tt_str_op(dns_name_str(name), OP_EQ, "world.");

 done:
  dns_name_free(name);
}

static void
test_crypto_dnssec_prepend_wildcard_to_invalid_name(void *arg)
{
  (void) arg;

  dns_name_t *name = dns_name_new();

  dns_prepend_wildcard(name);

  tt_str_op(dns_name_str(name), OP_EQ, "");

 done:
  dns_name_free(name);
}

static void
test_crypto_dnssec_prepend_wildcard_to_empty_name(void *arg)
{
  (void) arg;

  dns_name_t *name = dns_name_of("");

  dns_prepend_wildcard(name);

  tt_str_op(dns_name_str(name), OP_EQ, "*.");

 done:
  dns_name_free(name);
}

static void
test_crypto_dnssec_prepend_wildcard_to_root(void *arg)
{
  (void) arg;

  dns_name_t *name = dns_name_of(".");

  dns_prepend_wildcard(name);

  tt_str_op(dns_name_str(name), OP_EQ, "*.");

 done:
  dns_name_free(name);
}

static void
test_crypto_dnssec_prepend_wildcard_to_name(void *arg)
{
  (void) arg;

  dns_name_t *name = dns_name_of("world.");

  dns_prepend_wildcard(name);

  tt_str_op(dns_name_str(name), OP_EQ, "*.world.");

 done:
  dns_name_free(name);
}

#define CRYPTO_DNSSEC_TEST(name, flags)                          \
  { #name, test_crypto_dnssec_ ## name, flags, NULL, NULL }

struct testcase_t crypto_dnssec_tests[] = {
  CRYPTO_DNSSEC_TEST(authenticate_rrset_rfc4035_b1_answer, 0),
  CRYPTO_DNSSEC_TEST(authenticate_rrset_fails, 0),

  CRYPTO_DNSSEC_TEST(authenticate_delegation_to_child_zone, 0),
  CRYPTO_DNSSEC_TEST(
    authenticate_delegation_to_child_zone_using_invalid_digest, 0),

  CRYPTO_DNSSEC_TEST(denial_of_existence_rfc4035_b2_name_error, 0),
  CRYPTO_DNSSEC_TEST(denial_of_existence_rfc4035_b3_no_data_error, 0),
  CRYPTO_DNSSEC_TEST(
    denial_of_existence_rfc4035_b5_referral_to_unsigned_zone, 0),
  CRYPTO_DNSSEC_TEST(denial_of_existence_rfc4035_b7_wildcard_no_data_error, 0),
  CRYPTO_DNSSEC_TEST(
    denial_of_existence_rfc4035_b8_ds_child_zone_no_data_error, 0),
  CRYPTO_DNSSEC_TEST(denial_of_existence_rfc5155_b1_name_error, 0),
  CRYPTO_DNSSEC_TEST(denial_of_existence_rfc5155_b2_no_data_error, 0),
  CRYPTO_DNSSEC_TEST(denial_of_existence_rfc5155_b21_no_data_error_ent, 0),
  CRYPTO_DNSSEC_TEST(
    denial_of_existence_rfc5155_b3_referral_to_opt_out_unsigned, 0),
  CRYPTO_DNSSEC_TEST(denial_of_existence_rfc5155_b4_wildcard_expansion, 0),
  CRYPTO_DNSSEC_TEST(denial_of_existence_rfc5155_b5_wildcard_no_data_error, 0),
  CRYPTO_DNSSEC_TEST(
    denial_of_existence_rfc5155_b6_ds_child_zone_no_data_error, 0),

  CRYPTO_DNSSEC_TEST(set_rrset_validation_state_minimum_parameters, 0),
  CRYPTO_DNSSEC_TEST(set_rrset_validation_state_full_parameters, 0),

  CRYPTO_DNSSEC_TEST(collect_signatures_succeeds, 0),
  CRYPTO_DNSSEC_TEST(collect_signatures_exceeds_expiration, 0),
  CRYPTO_DNSSEC_TEST(collect_signatures_precedes_inception, 0),
  CRYPTO_DNSSEC_TEST(collect_signatures_misses_dnskey, 0),

  CRYPTO_DNSSEC_TEST(has_potential_dnskey_is_present, 0),
  CRYPTO_DNSSEC_TEST(has_potential_dnskey_missess_zone_flag_bit, 0),
  CRYPTO_DNSSEC_TEST(has_potential_dnskey_unauthenticated, 0),
  CRYPTO_DNSSEC_TEST(has_potential_dnskey_invalid_key_tag, 0),
  CRYPTO_DNSSEC_TEST(has_potential_dnskey_different_algorithms, 0),
  CRYPTO_DNSSEC_TEST(has_potential_dnskey_not_covering_signers_name, 0),
  CRYPTO_DNSSEC_TEST(has_potential_dnskey_invalid_protocol, 0),

  CRYPTO_DNSSEC_TEST(collect_rrset_succeeds, 0),
  CRYPTO_DNSSEC_TEST(collect_rrset_invalid_signature_labels, 0),
  CRYPTO_DNSSEC_TEST(collect_rrset_invalid_cover_type, 0),
  CRYPTO_DNSSEC_TEST(collect_rrset_invalid_signer_name, 0),
  CRYPTO_DNSSEC_TEST(collect_rrset_invalid_class, 0),
  CRYPTO_DNSSEC_TEST(collect_rrset_invalid_name, 0),

  CRYPTO_DNSSEC_TEST(validate_rrset_succeeds, 0),
  CRYPTO_DNSSEC_TEST(validate_rrset_fails, 0),

  CRYPTO_DNSSEC_TEST(verify_signature_rsasha1, 0),
  CRYPTO_DNSSEC_TEST(verify_signature_rsasha1nsec3sha1, 0),
  CRYPTO_DNSSEC_TEST(verify_signature_rsasha256, 0),
  CRYPTO_DNSSEC_TEST(verify_signature_rsasha512, 0),
  CRYPTO_DNSSEC_TEST(verify_signature_ecdsap256sha256, 0),
  CRYPTO_DNSSEC_TEST(verify_signature_ecdsap384sha384, 0),
  CRYPTO_DNSSEC_TEST(verify_signature_unsupported_algorithm, 0),
  CRYPTO_DNSSEC_TEST(verify_signature_succeeds, 0),

  CRYPTO_DNSSEC_TEST(nsec_denial_of_existence_name_error, 0),
  CRYPTO_DNSSEC_TEST(nsec_denial_of_existence_wildcard_exists, 0),
  CRYPTO_DNSSEC_TEST(nsec_denial_of_existence_has_wildcard, 0),
  CRYPTO_DNSSEC_TEST(nsec_denial_of_existence_no_data_error, 0),
  CRYPTO_DNSSEC_TEST(nsec_denial_of_existence_insecure_ancestor_delegation, 0),
  CRYPTO_DNSSEC_TEST(nsec_denial_of_existence_cname_is_present, 0),
  CRYPTO_DNSSEC_TEST(nsec_denial_of_existence_bit_is_present, 0),
  CRYPTO_DNSSEC_TEST(nsec_denial_of_existence_invalid_ancestor_delegation, 0),
  CRYPTO_DNSSEC_TEST(nsec_denial_of_existence_without_matching_owner, 0),
  CRYPTO_DNSSEC_TEST(nsec_denial_of_existence_covering_nsec_is_absent, 0),

  CRYPTO_DNSSEC_TEST(nsec_prove_no_wildcard_with_covering_nsec, 0),
  CRYPTO_DNSSEC_TEST(nsec_prove_no_wildcard_covering_nsec_is_absent, 0),
  CRYPTO_DNSSEC_TEST(nsec_prove_no_wildcard_with_matching_absent_type, 0),
  CRYPTO_DNSSEC_TEST(nsec_prove_no_wildcard_with_matching_existing_type, 0),

  CRYPTO_DNSSEC_TEST(nsec_name_is_covered_within_bounds, 0),
  CRYPTO_DNSSEC_TEST(nsec_name_is_covered_beyond_left_bound, 0),
  CRYPTO_DNSSEC_TEST(nsec_name_is_covered_beyond_right_bound, 0),

  CRYPTO_DNSSEC_TEST(nsec3_denial_of_existence_no_data_error, 0),
  CRYPTO_DNSSEC_TEST(nsec3_denial_of_existence_insecure_ancestor_delegation,
                     0),
  CRYPTO_DNSSEC_TEST(nsec3_denial_of_existence_cname_is_present, 0),
  CRYPTO_DNSSEC_TEST(nsec3_denial_of_existence_bit_is_present, 0),
  CRYPTO_DNSSEC_TEST(nsec3_denial_of_existence_invalid_ancestor_delegation, 0),
  CRYPTO_DNSSEC_TEST(nsec3_denial_of_existence_without_matching_owner, 0),

  CRYPTO_DNSSEC_TEST(nsec3_encloser_proof_name_error, 0),
  CRYPTO_DNSSEC_TEST(nsec3_encloser_proof_type_error, 0),
  CRYPTO_DNSSEC_TEST(nsec3_encloser_proof_wildcard_exists, 0),
  CRYPTO_DNSSEC_TEST(nsec3_encloser_proof_has_opt_out_flag, 0),
  CRYPTO_DNSSEC_TEST(nsec3_encloser_proof_without_closest_encloser, 0),

  CRYPTO_DNSSEC_TEST(nsec3_closest_encloser_with_matching_nsec, 0),
  CRYPTO_DNSSEC_TEST(nsec3_closest_encloser_matching_nsec_is_absent, 0),
  CRYPTO_DNSSEC_TEST(nsec3_closest_encloser_invalid_ancestor_delegation, 0),

  CRYPTO_DNSSEC_TEST(nsec3_next_closer_with_covering_nsec, 0),
  CRYPTO_DNSSEC_TEST(nsec3_next_closer_covering_nsec_is_absent, 0),
  CRYPTO_DNSSEC_TEST(nsec3_next_closer_qname_is_closest_encloser, 0),
  CRYPTO_DNSSEC_TEST(nsec3_next_closer_has_opt_out_flag, 0),

  CRYPTO_DNSSEC_TEST(nsec3_prove_no_wildcard_with_covering_nsec, 0),
  CRYPTO_DNSSEC_TEST(nsec3_prove_no_wildcard_covering_nsec_is_absent, 0),
  CRYPTO_DNSSEC_TEST(nsec3_prove_no_wildcard_with_matching_absent_type, 0),
  CRYPTO_DNSSEC_TEST(nsec3_prove_no_wildcard_with_matching_existing_type, 0),

  CRYPTO_DNSSEC_TEST(nsec3_hash_is_covered_within_bounds, 0),
  CRYPTO_DNSSEC_TEST(nsec3_hash_is_covered_beyond_left_bound, 0),
  CRYPTO_DNSSEC_TEST(nsec3_hash_is_covered_beyond_right_bound, 0),

  CRYPTO_DNSSEC_TEST(nsec3_hash_providing_parameters_by_nsec3param, 0),
  CRYPTO_DNSSEC_TEST(nsec3_hash_providing_parameters_by_nsec3, 0),
  CRYPTO_DNSSEC_TEST(nsec3_hash_providing_invalid_parameters, 0),

  CRYPTO_DNSSEC_TEST(nsec3_digest_sha1, 0),

  CRYPTO_DNSSEC_TEST(is_ancestor_delegation_all_conditions_met, 0),
  CRYPTO_DNSSEC_TEST(is_ancestor_delegation_with_invalid_types, 0),
  CRYPTO_DNSSEC_TEST(is_ancestor_delegation_with_invalid_signer, 0),

  CRYPTO_DNSSEC_TEST(get_rr_owner_for_original_name, 0),
  CRYPTO_DNSSEC_TEST(get_rr_owner_for_expanded_name, 0),

  CRYPTO_DNSSEC_TEST(comparator_canonical_name_ordering, 0),
  CRYPTO_DNSSEC_TEST(comparator_canonical_rdata_ordering, 0),

  CRYPTO_DNSSEC_TEST(labels, 0),
  CRYPTO_DNSSEC_TEST(common_labels, 0),

  CRYPTO_DNSSEC_TEST(strip_left_label_from_invalid_name, 0),
  CRYPTO_DNSSEC_TEST(strip_left_label_from_empty_name, 0),
  CRYPTO_DNSSEC_TEST(strip_left_label_from_root, 0),
  CRYPTO_DNSSEC_TEST(strip_left_label_from_name, 0),

  CRYPTO_DNSSEC_TEST(prepend_wildcard_to_invalid_name, 0),
  CRYPTO_DNSSEC_TEST(prepend_wildcard_to_empty_name, 0),
  CRYPTO_DNSSEC_TEST(prepend_wildcard_to_root, 0),
  CRYPTO_DNSSEC_TEST(prepend_wildcard_to_name, 0),

  END_OF_TESTCASES
};
