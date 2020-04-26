/* Copyright (c) 2019 Christian Hofer.
 * Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_dns_string.c
 * \brief Tests for DNS message string encoding.
 */

#include "test/test.h"
#include "test/log_test_helpers.h"

#include "lib/container/dns_message.h"
#include "lib/container/dns_message_st.h"
#include "lib/encoding/dns_string.h"
#include "lib/defs/dns_types.h"

static void
test_dns_string_a_value_of_succeeds(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("1.2.3.4"));

  char *a = dns_a_value_of(parts);
  tt_str_op(a, OP_EQ, "1.2.3.4");

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  tor_free(a);
}

static void
test_dns_string_a_value_of_missing_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));

  char *a = dns_a_value_of(parts);
  tt_ptr_op(a, OP_EQ, NULL);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  tor_free(a);
}

//
// Resource Record - NS

static void
test_dns_string_ns_value_of_succeeds(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("hello."));

  dns_name_t *ns = dns_ns_value_of(parts);
  tt_str_op(dns_name_str(ns), OP_EQ, "hello.");

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_name_free(ns);
}

static void
test_dns_string_ns_value_of_missing_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));

  dns_name_t *ns = dns_ns_value_of(parts);
  tt_str_op(dns_name_str(ns), OP_EQ, "");

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_name_free(ns);
}

//
// Resource Record - CNAME

static void
test_dns_string_cname_value_of_succeeds(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("hello."));

  dns_name_t *cname = dns_cname_value_of(parts);
  tt_str_op(dns_name_str(cname), OP_EQ, "hello.");

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_name_free(cname);
}

static void
test_dns_string_cname_value_of_missing_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));

  dns_name_t *cname = dns_cname_value_of(parts);
  tt_str_op(dns_name_str(cname), OP_EQ, "");

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_name_free(cname);
}

//
// Resource Record - SOA

static void
test_dns_string_soa_value_of_succeeds(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("hello."));
  smartlist_add(parts, tor_strdup("world."));
  smartlist_add(parts, tor_strdup("131071"));
  smartlist_add(parts, tor_strdup("196607"));
  smartlist_add(parts, tor_strdup("262143"));
  smartlist_add(parts, tor_strdup("327679"));
  smartlist_add(parts, tor_strdup("393215"));

  dns_soa_t *soa = dns_soa_value_of(parts);
  tt_str_op(dns_name_str(soa->mname), OP_EQ, "hello.");
  tt_str_op(dns_name_str(soa->rname), OP_EQ, "world.");
  tt_uint_op(soa->serial, OP_EQ, 131071);
  tt_uint_op(soa->refresh, OP_EQ, 196607);
  tt_uint_op(soa->retry, OP_EQ, 262143);
  tt_uint_op(soa->expire, OP_EQ, 327679);
  tt_uint_op(soa->minimum, OP_EQ, 393215);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_soa_free(soa);
}

static void
test_dns_string_soa_value_of_missing_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("hello."));
  smartlist_add(parts, tor_strdup("world."));
  smartlist_add(parts, tor_strdup("131071"));
  smartlist_add(parts, tor_strdup("196607"));
  smartlist_add(parts, tor_strdup("262143"));
  smartlist_add(parts, tor_strdup("327679"));

  dns_soa_t *soa = dns_soa_value_of(parts);
  tt_str_op(dns_name_str(soa->mname), OP_EQ, "");
  tt_str_op(dns_name_str(soa->rname), OP_EQ, "");
  tt_uint_op(soa->serial, OP_EQ, 0);
  tt_uint_op(soa->refresh, OP_EQ, 0);
  tt_uint_op(soa->retry, OP_EQ, 0);
  tt_uint_op(soa->expire, OP_EQ, 0);
  tt_uint_op(soa->minimum, OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_soa_free(soa);
}

static void
test_dns_string_soa_value_of_invalid_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("."));
  smartlist_add(parts, tor_strdup("."));
  smartlist_add(parts, tor_strdup("abcdef"));
  smartlist_add(parts, tor_strdup("ghijkl"));
  smartlist_add(parts, tor_strdup("mnopqr"));
  smartlist_add(parts, tor_strdup("stuvwx"));
  smartlist_add(parts, tor_strdup("ABCDEF"));

  dns_soa_t *soa = dns_soa_value_of(parts);
  tt_str_op(dns_name_str(soa->mname), OP_EQ, ".");
  tt_str_op(dns_name_str(soa->rname), OP_EQ, ".");
  tt_uint_op(soa->serial, OP_EQ, 0);
  tt_uint_op(soa->refresh, OP_EQ, 0);
  tt_uint_op(soa->retry, OP_EQ, 0);
  tt_uint_op(soa->expire, OP_EQ, 0);
  tt_uint_op(soa->minimum, OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_soa_free(soa);
}

//
// Resource Record - PTR

static void
test_dns_string_ptr_value_of_succeeds(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("hello."));

  dns_name_t *ptr = dns_ptr_value_of(parts);
  tt_str_op(dns_name_str(ptr), OP_EQ, "hello.");

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_name_free(ptr);
}

static void
test_dns_string_ptr_value_of_missing_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));

  dns_name_t *ptr = dns_ptr_value_of(parts);
  tt_str_op(dns_name_str(ptr), OP_EQ, "");

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_name_free(ptr);
}

//
// Resource Record - MX

static void
test_dns_string_mx_value_of_succeeds(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("10"));
  smartlist_add(parts, tor_strdup("mail.example.com"));

  dns_mx_t *mx = dns_mx_value_of(parts);
  tt_uint_op(mx->preference, OP_EQ, 10);
  tt_str_op(dns_name_str(mx->exchange), OP_EQ, "mail.example.com");

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_mx_free(mx);
}

static void
test_dns_string_mx_value_of_missing_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("10"));

  dns_mx_t *mx = dns_mx_value_of(parts);
  tt_uint_op(mx->preference, OP_EQ, 0);
  tt_ptr_op(mx->exchange, OP_EQ, NULL);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_mx_free(mx);
}

static void
test_dns_string_mx_value_of_invalid_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("abcdef"));
  smartlist_add(parts, tor_strdup("."));

  dns_mx_t *mx = dns_mx_value_of(parts);
  tt_uint_op(mx->preference, OP_EQ, 0);
  tt_str_op(dns_name_str(mx->exchange), OP_EQ, ".");

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_mx_free(mx);
}

//
// Resource Record - KEY

static void
test_dns_string_key_value_of_succeeds(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("257"));
  smartlist_add(parts, tor_strdup("3"));
  smartlist_add(parts, tor_strdup("8"));
  smartlist_add(parts, tor_strdup("AQPDzldNmMvZFX4NcNJ0uEnKDg7tmv/F3MyQR0lpBmV"
                "cNcsIszxNFxsBfKNW9JYCYqpik8366LE7VbIcNRzfp2h9OO8HRl+H+E08zauK"
                "8k7evWEmu/6od+2boggPoiEfGNyvNPaSI7FOIroDsnw/taggzHRX1Z7SOiOiP"
                "WPNIwSUyWOZ79VmcQ1GLkC6NlYvG3HwYmynQv6oFwGv/KELSw7ZSdrbTQ0HXv"
                "ZbqMUI7BaMskmvgm1G7oKZ1YiF7O9ioVNc0+7ASbqmZN7Z98EGU/Qh2K/BgUe"
                "8Hs0XVcdPKrtyYnoQHd2ynKPcMMlTEih2/2HDHjRPJ2aywIpKNnv4oPo/"));

  dns_key_t *key = dns_key_value_of(parts);
  tt_uint_op(key->flags, OP_EQ, 257);
  tt_uint_op(key->protocol, OP_EQ, 3);
  tt_uint_op(key->algorithm, OP_EQ, 8);

  char public_key[400];
  memset(&public_key, 0, sizeof(public_key));
  base64_encode(public_key, sizeof(public_key), (const char *) key->public_key,
                key->public_key_len, 0);
  tt_str_op(public_key, OP_EQ, "AQPDzldNmMvZFX4NcNJ0uEnKDg7tmv/F3MyQR0lpBmVcNc"
            "sIszxNFxsBfKNW9JYCYqpik8366LE7VbIcNRzfp2h9OO8HRl+H+E08zauK8k7evWE"
            "mu/6od+2boggPoiEfGNyvNPaSI7FOIroDsnw/taggzHRX1Z7SOiOiPWPNIwSUyWOZ"
            "79VmcQ1GLkC6NlYvG3HwYmynQv6oFwGv/KELSw7ZSdrbTQ0HXvZbqMUI7BaMskmvg"
            "m1G7oKZ1YiF7O9ioVNc0+7ASbqmZN7Z98EGU/Qh2K/BgUe8Hs0XVcdPKrtyYnoQHd"
            "2ynKPcMMlTEih2/2HDHjRPJ2aywIpKNnv4oPo/");
  tt_uint_op(key->public_key_len, OP_EQ, 258);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_key_free(key);
}

static void
test_dns_string_key_value_of_missing_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("257"));
  smartlist_add(parts, tor_strdup("3"));
  smartlist_add(parts, tor_strdup("8"));

  dns_key_t *key = dns_key_value_of(parts);
  tt_uint_op(key->flags, OP_EQ, 0);
  tt_uint_op(key->protocol, OP_EQ, 0);
  tt_uint_op(key->algorithm, OP_EQ, 0);
  tt_ptr_op(key->public_key, OP_EQ, NULL);
  tt_uint_op(key->public_key_len, OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_key_free(key);
}

static void
test_dns_string_key_value_of_invalid_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("abcdef"));
  smartlist_add(parts, tor_strdup("ghijkl"));
  smartlist_add(parts, tor_strdup("mnopqr"));
  smartlist_add(parts, tor_strdup("{[()]}"));

  dns_key_t *key = dns_key_value_of(parts);
  tt_uint_op(key->flags, OP_EQ, 0);
  tt_uint_op(key->protocol, OP_EQ, 0);
  tt_uint_op(key->algorithm, OP_EQ, 0);
  tt_ptr_op(key->public_key, OP_EQ, NULL);
  tt_uint_op(key->public_key_len, OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_key_free(key);
}

//
// Resource Record - AAAA

static void
test_dns_string_aaaa_value_of_succeeds(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("2::3:0:0:4"));

  char *aaaa = dns_aaaa_value_of(parts);
  tt_str_op(aaaa, OP_EQ, "2::3:0:0:4");

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  tor_free(aaaa);
}

static void
test_dns_string_aaaa_value_of_missing_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));

  char *aaaa = dns_aaaa_value_of(parts);
  tt_ptr_op(aaaa, OP_EQ, NULL);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  tor_free(aaaa);
}

//
// Resource Record - DS

static void
test_dns_string_ds_value_of_succeeds(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("20326"));
  smartlist_add(parts, tor_strdup("8"));
  smartlist_add(parts, tor_strdup("2"));
  smartlist_add(parts, tor_strdup("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BB"
                                  "C683457104237C7F8EC8D"));

  dns_ds_t *ds = dns_ds_value_of(parts);
  tt_uint_op(ds->key_tag, OP_EQ, 20326);
  tt_uint_op(ds->algorithm, OP_EQ, 8);
  tt_uint_op(ds->digest_type, OP_EQ, 2);
  tt_str_op(hex_str((const char *) ds->digest, ds->digest_len), OP_EQ, "E06D44"
            "B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D");
  tt_uint_op(ds->digest_len, OP_EQ, 32);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_ds_free(ds);
}

static void
test_dns_string_ds_value_of_missing_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("20326"));
  smartlist_add(parts, tor_strdup("8"));
  smartlist_add(parts, tor_strdup("2"));

  dns_ds_t *ds = dns_ds_value_of(parts);
  tt_uint_op(ds->key_tag, OP_EQ, 0);
  tt_uint_op(ds->algorithm, OP_EQ, 0);
  tt_uint_op(ds->digest_type, OP_EQ, 0);
  tt_ptr_op(ds->digest, OP_EQ, NULL);
  tt_uint_op(ds->digest_len, OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_ds_free(ds);
}

static void
test_dns_string_ds_value_of_invalid_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("abcdef"));
  smartlist_add(parts, tor_strdup("ghijkl"));
  smartlist_add(parts, tor_strdup("mnopqr"));
  smartlist_add(parts, tor_strdup("stuvwx"));

  dns_ds_t *ds = dns_ds_value_of(parts);
  tt_uint_op(ds->key_tag, OP_EQ, 0);
  tt_uint_op(ds->algorithm, OP_EQ, 0);
  tt_uint_op(ds->digest_type, OP_EQ, 0);
  tt_ptr_op(ds->digest, OP_EQ, NULL);
  tt_uint_op(ds->digest_len, OP_EQ, 3);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_ds_free(ds);
}

//
// Resource Record - RRSIG

static void
test_dns_string_rrsig_value_of_succeeds(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("MX"));
  smartlist_add(parts, tor_strdup("5"));
  smartlist_add(parts, tor_strdup("3"));
  smartlist_add(parts, tor_strdup("3600"));
  smartlist_add(parts, tor_strdup("1081528579"));
  smartlist_add(parts, tor_strdup("1084120579"));
  smartlist_add(parts, tor_strdup("38519"));
  smartlist_add(parts, tor_strdup("example."));
  smartlist_add(parts, tor_strdup("Il2WTZ+Bkv+OytBx4LItNW5mjB4RCwhOO8y1XzPHZmZ"
                "UTVYL7LaA63f6T9ysVBzJRI3KRjAPH3U1qaYnDoN1DrWqmi9RJe4FoObkbcdm"
                "7P3Ikx70ePCoFgRz1Yq+bVVXCvGuAU4xALv3W/Y1jNSlwZ2mSWKHfxFQxPtLj"
                "8s32+k="));

  dns_rrsig_t *rrsig = dns_rrsig_value_of(parts);
  tt_uint_op(rrsig->type_covered->value, OP_EQ, DNS_TYPE_MX);
  tt_uint_op(rrsig->algorithm, OP_EQ, 5);
  tt_uint_op(rrsig->labels, OP_EQ, 3);
  tt_uint_op(rrsig->original_ttl, OP_EQ, 3600);
  tt_uint_op(rrsig->signature_inception, OP_EQ, 1081528579);
  tt_uint_op(rrsig->signature_expiration, OP_EQ, 1084120579);
  tt_uint_op(rrsig->key_tag, OP_EQ, 38519);
  tt_str_op(dns_name_str(rrsig->signer_name), OP_EQ, "example.");

  char signature[400];
  memset(&signature, 0, sizeof(signature));
  base64_encode(signature, sizeof(signature), (const char *) rrsig->signature,
                rrsig->signature_len, 0);
  tt_str_op(signature, OP_EQ, "Il2WTZ+Bkv+OytBx4LItNW5mjB4RCwhOO8y1XzPHZmZUTVY"
            "L7LaA63f6T9ysVBzJRI3KRjAPH3U1qaYnDoN1DrWqmi9RJe4FoObkbcdm7P3Ikx70"
            "ePCoFgRz1Yq+bVVXCvGuAU4xALv3W/Y1jNSlwZ2mSWKHfxFQxPtLj8s32+k=");
  tt_uint_op(rrsig->signature_len, OP_EQ, 128);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_rrsig_free(rrsig);
}

static void
test_dns_string_rrsig_value_of_missing_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("MX"));
  smartlist_add(parts, tor_strdup("5"));
  smartlist_add(parts, tor_strdup("3"));
  smartlist_add(parts, tor_strdup("3600"));
  smartlist_add(parts, tor_strdup("1081528579"));
  smartlist_add(parts, tor_strdup("1084120579"));
  smartlist_add(parts, tor_strdup("38519"));
  smartlist_add(parts, tor_strdup("example."));

  dns_rrsig_t *rrsig = dns_rrsig_value_of(parts);
  tt_ptr_op(rrsig->type_covered, OP_EQ, NULL);
  tt_uint_op(rrsig->algorithm, OP_EQ, 0);
  tt_uint_op(rrsig->labels, OP_EQ, 0);
  tt_uint_op(rrsig->original_ttl, OP_EQ, 0);
  tt_uint_op(rrsig->signature_inception, OP_EQ, 0);
  tt_uint_op(rrsig->signature_expiration, OP_EQ, 0);
  tt_uint_op(rrsig->key_tag, OP_EQ, 0);
  tt_str_op(dns_name_str(rrsig->signer_name), OP_EQ, "");
  tt_ptr_op(rrsig->signature, OP_EQ, NULL);
  tt_uint_op(rrsig->signature_len, OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_rrsig_free(rrsig);
}

static void
test_dns_string_rrsig_value_of_invalid_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("abcdef"));
  smartlist_add(parts, tor_strdup("ghijkl"));
  smartlist_add(parts, tor_strdup("mnopqr"));
  smartlist_add(parts, tor_strdup("stuvwx"));
  smartlist_add(parts, tor_strdup("ABCDEF"));
  smartlist_add(parts, tor_strdup("GHIJKL"));
  smartlist_add(parts, tor_strdup("MNOPQR"));
  smartlist_add(parts, tor_strdup("."));
  smartlist_add(parts, tor_strdup("{[()]}"));

  dns_rrsig_t *rrsig = dns_rrsig_value_of(parts);
  tt_ptr_op(rrsig->type_covered, OP_EQ, NULL);
  tt_uint_op(rrsig->algorithm, OP_EQ, 0);
  tt_uint_op(rrsig->labels, OP_EQ, 0);
  tt_uint_op(rrsig->original_ttl, OP_EQ, 0);
  tt_uint_op(rrsig->signature_inception, OP_EQ, 0);
  tt_uint_op(rrsig->signature_expiration, OP_EQ, 0);
  tt_uint_op(rrsig->key_tag, OP_EQ, 0);
  tt_str_op(dns_name_str(rrsig->signer_name), OP_EQ, ".");
  tt_ptr_op(rrsig->signature, OP_EQ, NULL);
  tt_uint_op(rrsig->signature_len, OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_rrsig_free(rrsig);
}

//
// Resource Record - NSEC

static uint16_t
nsec_type(smartlist_t *list, int idx)
{
  tor_assert(list);
  tor_assert(smartlist_get(list, idx));
  return ((dns_type_t *) smartlist_get(list, idx))->value;
}

static void
test_dns_string_nsec_value_of_succeeds(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("a.example."));
  smartlist_add(parts, tor_strdup("NS"));
  smartlist_add(parts, tor_strdup("SOA"));
  smartlist_add(parts, tor_strdup("MX"));
  smartlist_add(parts, tor_strdup("RRSIG"));
  smartlist_add(parts, tor_strdup("NSEC"));
  smartlist_add(parts, tor_strdup("DNSKEY"));

  dns_nsec_t *nsec = dns_nsec_value_of(parts);
  tt_str_op(dns_name_str(nsec->next_domain_name), OP_EQ, "a.example.");
  tt_uint_op(smartlist_len(nsec->types), OP_EQ, 6);
  tt_uint_op(nsec_type(nsec->types, 0), OP_EQ, DNS_TYPE_NS);
  tt_uint_op(nsec_type(nsec->types, 1), OP_EQ, DNS_TYPE_SOA);
  tt_uint_op(nsec_type(nsec->types, 2), OP_EQ, DNS_TYPE_MX);
  tt_uint_op(nsec_type(nsec->types, 3), OP_EQ, DNS_TYPE_RRSIG);
  tt_uint_op(nsec_type(nsec->types, 4), OP_EQ, DNS_TYPE_NSEC);
  tt_uint_op(nsec_type(nsec->types, 5), OP_EQ, DNS_TYPE_DNSKEY);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_nsec_free(nsec);
}

static void
test_dns_string_nsec_value_of_missing_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));

  dns_nsec_t *nsec = dns_nsec_value_of(parts);
  tt_str_op(dns_name_str(nsec->next_domain_name), OP_EQ, "");
  tt_uint_op(smartlist_len(nsec->types), OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_nsec_free(nsec);
}

static void
test_dns_string_nsec_value_of_invalid_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("."));
  smartlist_add(parts, tor_strdup("abcdef"));
  smartlist_add(parts, tor_strdup("ghijkl"));
  smartlist_add(parts, tor_strdup("mnopqr"));
  smartlist_add(parts, tor_strdup("stuvwx"));

  dns_nsec_t *nsec = dns_nsec_value_of(parts);
  tt_str_op(dns_name_str(nsec->next_domain_name), OP_EQ, ".");
  tt_uint_op(smartlist_len(nsec->types), OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_nsec_free(nsec);
}

//
// Resource Record - DNSKEY

static void
test_dns_string_dnskey_value_of_succeeds(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("257"));
  smartlist_add(parts, tor_strdup("3"));
  smartlist_add(parts, tor_strdup("8"));
  smartlist_add(parts, tor_strdup("AQPDzldNmMvZFX4NcNJ0uEnKDg7tmv/F3MyQR0lpBmV"
                "cNcsIszxNFxsBfKNW9JYCYqpik8366LE7VbIcNRzfp2h9OO8HRl+H+E08zauK"
                "8k7evWEmu/6od+2boggPoiEfGNyvNPaSI7FOIroDsnw/taggzHRX1Z7SOiOiP"
                "WPNIwSUyWOZ79VmcQ1GLkC6NlYvG3HwYmynQv6oFwGv/KELSw7ZSdrbTQ0HXv"
                "ZbqMUI7BaMskmvgm1G7oKZ1YiF7O9ioVNc0+7ASbqmZN7Z98EGU/Qh2K/BgUe"
                "8Hs0XVcdPKrtyYnoQHd2ynKPcMMlTEih2/2HDHjRPJ2aywIpKNnv4oPo/"));

  dns_dnskey_t *dnskey = dns_dnskey_value_of(parts);
  tt_uint_op(dnskey->flags, OP_EQ, 257);
  tt_uint_op(dnskey->protocol, OP_EQ, 3);
  tt_uint_op(dnskey->algorithm, OP_EQ, 8);

  char public_key[400];
  memset(&public_key, 0, sizeof(public_key));
  base64_encode(public_key, sizeof(public_key),
                (const char *) dnskey->public_key, dnskey->public_key_len, 0);
  tt_str_op(public_key, OP_EQ, "AQPDzldNmMvZFX4NcNJ0uEnKDg7tmv/F3MyQR0lpBmVcNc"
            "sIszxNFxsBfKNW9JYCYqpik8366LE7VbIcNRzfp2h9OO8HRl+H+E08zauK8k7evWE"
            "mu/6od+2boggPoiEfGNyvNPaSI7FOIroDsnw/taggzHRX1Z7SOiOiPWPNIwSUyWOZ"
            "79VmcQ1GLkC6NlYvG3HwYmynQv6oFwGv/KELSw7ZSdrbTQ0HXvZbqMUI7BaMskmvg"
            "m1G7oKZ1YiF7O9ioVNc0+7ASbqmZN7Z98EGU/Qh2K/BgUe8Hs0XVcdPKrtyYnoQHd"
            "2ynKPcMMlTEih2/2HDHjRPJ2aywIpKNnv4oPo/");
  tt_uint_op(dnskey->public_key_len, OP_EQ, 258);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_dnskey_free(dnskey);
}

static void
test_dns_string_dnskey_value_of_missing_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("257"));
  smartlist_add(parts, tor_strdup("3"));
  smartlist_add(parts, tor_strdup("8"));

  dns_dnskey_t *dnskey = dns_dnskey_value_of(parts);
  tt_uint_op(dnskey->flags, OP_EQ, 0);
  tt_uint_op(dnskey->protocol, OP_EQ, 0);
  tt_uint_op(dnskey->algorithm, OP_EQ, 0);
  tt_ptr_op(dnskey->public_key, OP_EQ, NULL);
  tt_uint_op(dnskey->public_key_len, OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_dnskey_free(dnskey);
}

static void
test_dns_string_dnskey_value_of_invalid_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("abcdef"));
  smartlist_add(parts, tor_strdup("ghijkl"));
  smartlist_add(parts, tor_strdup("mnopqr"));
  smartlist_add(parts, tor_strdup("{[()]}"));

  dns_dnskey_t *dnskey = dns_dnskey_value_of(parts);
  tt_uint_op(dnskey->flags, OP_EQ, 0);
  tt_uint_op(dnskey->protocol, OP_EQ, 0);
  tt_uint_op(dnskey->algorithm, OP_EQ, 0);
  tt_ptr_op(dnskey->public_key, OP_EQ, NULL);
  tt_uint_op(dnskey->public_key_len, OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_dnskey_free(dnskey);
}

//
// Resource Record - NSEC3

static uint16_t
nsec3_type(smartlist_t *list, int idx)
{
  tor_assert(list);
  tor_assert(smartlist_get(list, idx));
  return ((dns_type_t *) smartlist_get(list, idx))->value;
}

static void
test_dns_string_nsec3_value_of_succeeds(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("1"));
  smartlist_add(parts, tor_strdup("0"));
  smartlist_add(parts, tor_strdup("12"));
  smartlist_add(parts, tor_strdup("AABBCCDD"));
  smartlist_add(parts, tor_strdup("2T7B4G4VSA5SMI47K61MV5BV1A22BOJR"));
  smartlist_add(parts, tor_strdup("NS"));
  smartlist_add(parts, tor_strdup("SOA"));
  smartlist_add(parts, tor_strdup("MX"));
  smartlist_add(parts, tor_strdup("RRSIG"));
  smartlist_add(parts, tor_strdup("DNSKEY"));
  smartlist_add(parts, tor_strdup("NSEC3PARAM"));

  uint8_t salt[] = {
      0xAA, 0xBB, 0xCC, 0xDD
  };

  uint8_t next_hashed_owner_name[] = {
      0x17, 0x4E, 0xB2, 0x40, 0x9F, 0xE2, 0x8B, 0xCB,
      0x48, 0x87, 0xA1, 0x83, 0x6F, 0x95, 0x7F, 0x0A,
      0x84, 0x25, 0xE2, 0x7B
  };

  dns_nsec3_t *nsec3 = dns_nsec3_value_of(parts);
  tt_uint_op(nsec3->hash_algorithm, OP_EQ, 1);
  tt_uint_op(nsec3->flags, OP_EQ, 0);
  tt_uint_op(nsec3->iterations, OP_EQ, 12);
  tt_mem_op(nsec3->salt, OP_EQ, salt, nsec3->salt_length);
  tt_uint_op(nsec3->salt_length, OP_EQ, 4);
  tt_mem_op(nsec3->next_hashed_owner_name, OP_EQ, next_hashed_owner_name,
            nsec3->hash_length);
  tt_uint_op(nsec3->hash_length, OP_EQ, 20);
  tt_uint_op(smartlist_len(nsec3->types), OP_EQ, 6);
  tt_uint_op(nsec3_type(nsec3->types, 0), OP_EQ, DNS_TYPE_NS);
  tt_uint_op(nsec3_type(nsec3->types, 1), OP_EQ, DNS_TYPE_SOA);
  tt_uint_op(nsec3_type(nsec3->types, 2), OP_EQ, DNS_TYPE_MX);
  tt_uint_op(nsec3_type(nsec3->types, 3), OP_EQ, DNS_TYPE_RRSIG);
  tt_uint_op(nsec3_type(nsec3->types, 4), OP_EQ, DNS_TYPE_DNSKEY);
  tt_uint_op(nsec3_type(nsec3->types, 5), OP_EQ, DNS_TYPE_NSEC3PARAM);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_nsec3_free(nsec3);
}

static void
test_dns_string_nsec3_value_of_missing_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("1"));
  smartlist_add(parts, tor_strdup("0"));
  smartlist_add(parts, tor_strdup("12"));
  smartlist_add(parts, tor_strdup("AABBCCDD"));

  dns_nsec3_t *nsec3 = dns_nsec3_value_of(parts);
  tt_uint_op(nsec3->hash_algorithm, OP_EQ, 0);
  tt_uint_op(nsec3->flags, OP_EQ, 0);
  tt_uint_op(nsec3->iterations, OP_EQ, 0);
  tt_ptr_op(nsec3->salt, OP_EQ, NULL);
  tt_uint_op(nsec3->salt_length, OP_EQ, 0);
  tt_ptr_op(nsec3->next_hashed_owner_name, OP_EQ, NULL);
  tt_uint_op(nsec3->hash_length, OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_nsec3_free(nsec3);
}

static void
test_dns_string_nsec3_value_of_invalid_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("abcdef"));
  smartlist_add(parts, tor_strdup("ghijkl"));
  smartlist_add(parts, tor_strdup("mnopqr"));
  smartlist_add(parts, tor_strdup("{[()]}"));
  smartlist_add(parts, tor_strdup("{[()]}"));
  smartlist_add(parts, tor_strdup("ABCDEF"));
  smartlist_add(parts, tor_strdup("GHIJKL"));
  smartlist_add(parts, tor_strdup("NOPQRS"));
  smartlist_add(parts, tor_strdup("TUVWXY"));

  dns_nsec3_t *nsec3 = dns_nsec3_value_of(parts);
  tt_uint_op(nsec3->hash_algorithm, OP_EQ, 0);
  tt_uint_op(nsec3->flags, OP_EQ, 0);
  tt_uint_op(nsec3->iterations, OP_EQ, 0);
  tt_ptr_op(nsec3->salt, OP_EQ, NULL);
  tt_uint_op(nsec3->salt_length, OP_EQ, 3);
  tt_ptr_op(nsec3->next_hashed_owner_name, OP_EQ, NULL);
  tt_uint_op(nsec3->hash_length, OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_nsec3_free(nsec3);
}

//
// Resource Record - NSEC3PARAM

static void
test_dns_string_nsec3param_value_of_succeeds(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("1"));
  smartlist_add(parts, tor_strdup("0"));
  smartlist_add(parts, tor_strdup("12"));
  smartlist_add(parts, tor_strdup("AABBCCDD"));

  uint8_t salt[] = {
      0xAA, 0xBB, 0xCC, 0xDD
  };

  dns_nsec3param_t *nsec3param = dns_nsec3param_value_of(parts);
  tt_uint_op(nsec3param->hash_algorithm, OP_EQ, 1);
  tt_uint_op(nsec3param->flags, OP_EQ, 0);
  tt_uint_op(nsec3param->iterations, OP_EQ, 12);
  tt_mem_op(nsec3param->salt, OP_EQ, salt, nsec3param->salt_length);
  tt_uint_op(nsec3param->salt_length, OP_EQ, 4);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_nsec3param_free(nsec3param);
}

static void
test_dns_string_nsec3param_value_of_missing_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("1"));
  smartlist_add(parts, tor_strdup("0"));
  smartlist_add(parts, tor_strdup("12"));

  dns_nsec3param_t *nsec3param = dns_nsec3param_value_of(parts);
  tt_uint_op(nsec3param->hash_algorithm, OP_EQ, 0);
  tt_uint_op(nsec3param->flags, OP_EQ, 0);
  tt_uint_op(nsec3param->iterations, OP_EQ, 0);
  tt_ptr_op(nsec3param->salt, OP_EQ, NULL);
  tt_uint_op(nsec3param->salt_length, OP_EQ, 0);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_nsec3param_free(nsec3param);
}

static void
test_dns_string_nsec3param_value_of_invalid_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("abcdef"));
  smartlist_add(parts, tor_strdup("ghijkl"));
  smartlist_add(parts, tor_strdup("mnopqr"));
  smartlist_add(parts, tor_strdup("{[()]}"));

  dns_nsec3param_t *nsec3param = dns_nsec3param_value_of(parts);
  tt_uint_op(nsec3param->hash_algorithm, OP_EQ, 0);
  tt_uint_op(nsec3param->flags, OP_EQ, 0);
  tt_uint_op(nsec3param->iterations, OP_EQ, 0);
  tt_ptr_op(nsec3param->salt, OP_EQ, NULL);
  tt_uint_op(nsec3param->salt_length, OP_EQ, 3);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_nsec3param_free(nsec3param);
}

//
// Resource Record - URI

static void
test_dns_string_uri_value_of_succeeds(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("1"));
  smartlist_add(parts, tor_strdup("10"));
  smartlist_add(parts, tor_strdup("http://example.com"));

  dns_uri_t *uri = dns_uri_value_of(parts);
  tt_uint_op(uri->priority, OP_EQ, 1);
  tt_uint_op(uri->weight, OP_EQ, 10);
  tt_str_op(uri->target, OP_EQ, "http://example.com");

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_uri_free(uri);
}

static void
test_dns_string_uri_value_of_missing_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("1"));
  smartlist_add(parts, tor_strdup("10"));

  dns_uri_t *uri = dns_uri_value_of(parts);
  tt_uint_op(uri->priority, OP_EQ, 0);
  tt_uint_op(uri->weight, OP_EQ, 0);
  tt_ptr_op(uri->target, OP_EQ, NULL);

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_uri_free(uri);
}

static void
test_dns_string_uri_value_of_invalid_data(void *arg)
{
  (void) arg;

  smartlist_t *parts = smartlist_new();
  smartlist_add(parts, tor_strdup("rr-name"));
  smartlist_add(parts, tor_strdup("rr-ttl"));
  smartlist_add(parts, tor_strdup("rr-class"));
  smartlist_add(parts, tor_strdup("rr-type"));
  smartlist_add(parts, tor_strdup("abcdef"));
  smartlist_add(parts, tor_strdup("ghijkl"));
  smartlist_add(parts, tor_strdup("."));

  dns_uri_t *uri = dns_uri_value_of(parts);
  tt_uint_op(uri->priority, OP_EQ, 0);
  tt_uint_op(uri->weight, OP_EQ, 0);
  tt_str_op(uri->target, OP_EQ, ".");

 done:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  dns_uri_free(uri);
}

//
// Resource Record

static void
test_dns_string_rr_value_of_succeeds(void *arg)
{
  (void) arg;

  dns_rr_t *a = dns_rr_value_of((char *) "com. 3475 IN A 1.2.3.4");
  dns_rr_t *ns = dns_rr_value_of((char *) "com. 3475 IN NS hello.");
  dns_rr_t *cname = dns_rr_value_of((char *) "com. 3475 IN CNAME hello.");
  dns_rr_t *soa = dns_rr_value_of((char *) "com. 3475 IN SOA hello. world. "
                                  "131071 196607 262143 327679 393215");
  dns_rr_t *ptr = dns_rr_value_of((char *) "com. 3475 IN PTR hello.");
  dns_rr_t *mx = dns_rr_value_of((char *) "com. 3475 IN MX 1234 "
                                 "mail.example.com.");
  dns_rr_t *key = dns_rr_value_of((char *) "com. 3475 IN KEY 1234 1 8 0102");
  dns_rr_t *aaaa = dns_rr_value_of((char *) "com. 3475 IN AAAA 2::3:0:0:4");
  dns_rr_t *ds = dns_rr_value_of((char *) "com. 3475 IN DS 1234 1 8 0102");
  dns_rr_t *rrsig = dns_rr_value_of((char *) "com. 3475 IN RRSIG A 8 1 1 99 "
                                    "77 13 hello. 0102");
  dns_rr_t *nsec = dns_rr_value_of((char *) "com. 3475 IN NSEC hello. A");
  dns_rr_t *dnskey = dns_rr_value_of((char *) "com. 3475 IN DNSKEY 1234 1 8 "
                                     "0102");
  dns_rr_t *nsec3 = dns_rr_value_of((char *) "com. 3475 IN NSEC3 1 0 8 cafe "
                                    "000102030405060708090a0b0c0d0e0f A");
  dns_rr_t *nsec3param = dns_rr_value_of((char *) "com. 3475 IN NSEC3PARAM 1 "
                                         "0 8 cafe");
  dns_rr_t *uri = dns_rr_value_of((char *) "com. 3475 IN URI 1234 4567 "
                                  "hello.");

  tt_str_op(dns_rr_str(a), OP_EQ, "com.       \t3475\tIN\tA\t1.2.3.4");
  tt_str_op(dns_rr_str(ns), OP_EQ, "com.       \t3475\tIN\tNS\thello.");
  tt_str_op(dns_rr_str(cname), OP_EQ, "com.       \t3475\tIN\tCNAME\thello.");
  tt_str_op(dns_rr_str(soa), OP_EQ, "com.       \t3475\tIN\tSOA\thello. "
                                    "world. 131071 196607 262143 327679 "
                                    "393215");
  tt_str_op(dns_rr_str(ptr), OP_EQ, "com.       \t3475\tIN\tPTR\thello.");
  tt_str_op(dns_rr_str(mx), OP_EQ, "com.       \t3475\tIN\tMX\t1234 "
                                   "mail.example.com.");
  tt_str_op(dns_rr_str(key), OP_EQ, "com.       \t3475\tIN\tKEY\t1234 1 8 "
                                    "0102");
  tt_str_op(dns_rr_str(aaaa), OP_EQ, "com.       \t3475\tIN\tAAAA\t"
                                     "2::3:0:0:4");
  tt_str_op(dns_rr_str(ds), OP_EQ, "com.       \t3475\tIN\tDS\t1234 1 8 0102");
  tt_str_op(dns_rr_str(rrsig), OP_EQ, "com.       \t3475\tIN\tRRSIG\tA 8 1 1 "
                                      "99 77 13 hello. 0102");
  tt_str_op(dns_rr_str(nsec), OP_EQ, "com.       \t3475\tIN\tNSEC\thello. A");
  tt_str_op(dns_rr_str(dnskey), OP_EQ, "com.       \t3475\tIN\tDNSKEY\t1234 1 "
                                       "8 0102");
  tt_str_op(dns_rr_str(nsec3), OP_EQ, "com.       \t3475\tIN\tNSEC3\t1 0 8 "
                                      "CAFE 000102030405060708090A0B0C0D0E0F "
                                      "A");
  tt_str_op(dns_rr_str(nsec3param), OP_EQ, "com.       \t3475\tIN\tNSEC3PARAM"
                                           "\t1 0 8 CAFE");
  tt_str_op(dns_rr_str(uri), OP_EQ, "com.       \t3475\tIN\tURI\t1234 4567 "
                                    "hello.");

 done:
  dns_rr_free(a);
  dns_rr_free(ns);
  dns_rr_free(cname);
  dns_rr_free(soa);
  dns_rr_free(ptr);
  dns_rr_free(mx);
  dns_rr_free(key);
  dns_rr_free(aaaa);
  dns_rr_free(ds);
  dns_rr_free(rrsig);
  dns_rr_free(nsec);
  dns_rr_free(dnskey);
  dns_rr_free(nsec3);
  dns_rr_free(nsec3param);
  dns_rr_free(uri);
}

static void
test_dns_string_rr_value_of_missing_data(void *arg)
{
  (void) arg;

  char *value = (char *) "com.       \t3475\tIN\t";

  dns_rr_t *rr = dns_rr_value_of(value);
  tt_ptr_op(rr->name, OP_EQ, NULL);
  tt_int_op(rr->ttl, OP_EQ, 0);
  tt_ptr_op(rr->rrtype, OP_EQ, NULL);
  tt_uint_op(rr->rrclass, OP_EQ, DNS_CLASS_IN);
  tt_str_op(dns_rr_str(rr), OP_EQ, "");

 done:
  dns_rr_free(rr);
}

static void
test_dns_string_rr_value_of_invalid_data(void *arg)
{
  (void) arg;

  char *value = (char *) "com.       \tabcdef\tghijkl\tmnopqr\t";

  dns_rr_t *rr = dns_rr_value_of(value);
  tt_str_op(dns_name_str(rr->name), OP_EQ, "com.");
  tt_int_op(rr->ttl, OP_EQ, 0);
  tt_ptr_op(rr->rrtype, OP_EQ, NULL);
  tt_uint_op(rr->rrclass, OP_EQ, DNS_CLASS_NONE);
  tt_str_op(dns_rr_str(rr), OP_EQ, "");

 done:
  dns_rr_free(rr);
}

#define DNS_STRING_TEST(name, flags)                          \
  { #name, test_dns_string_ ## name, flags, NULL, NULL }

struct testcase_t dns_string_tests[] = {
  DNS_STRING_TEST(a_value_of_succeeds, 0),
  DNS_STRING_TEST(a_value_of_missing_data, 0),

  DNS_STRING_TEST(ns_value_of_succeeds, 0),
  DNS_STRING_TEST(ns_value_of_missing_data, 0),

  DNS_STRING_TEST(cname_value_of_succeeds, 0),
  DNS_STRING_TEST(cname_value_of_missing_data, 0),

  DNS_STRING_TEST(soa_value_of_succeeds, 0),
  DNS_STRING_TEST(soa_value_of_missing_data, 0),
  DNS_STRING_TEST(soa_value_of_invalid_data, 0),

  DNS_STRING_TEST(ptr_value_of_succeeds, 0),
  DNS_STRING_TEST(ptr_value_of_missing_data, 0),

  DNS_STRING_TEST(mx_value_of_succeeds, 0),
  DNS_STRING_TEST(mx_value_of_missing_data, 0),
  DNS_STRING_TEST(mx_value_of_invalid_data, 0),

  DNS_STRING_TEST(key_value_of_succeeds, 0),
  DNS_STRING_TEST(key_value_of_missing_data, 0),
  DNS_STRING_TEST(key_value_of_invalid_data, 0),

  DNS_STRING_TEST(aaaa_value_of_succeeds, 0),
  DNS_STRING_TEST(aaaa_value_of_missing_data, 0),

  DNS_STRING_TEST(ds_value_of_succeeds, 0),
  DNS_STRING_TEST(ds_value_of_missing_data, 0),
  DNS_STRING_TEST(ds_value_of_invalid_data, 0),

  DNS_STRING_TEST(rrsig_value_of_succeeds, 0),
  DNS_STRING_TEST(rrsig_value_of_missing_data, 0),
  DNS_STRING_TEST(rrsig_value_of_invalid_data, 0),

  DNS_STRING_TEST(nsec_value_of_succeeds, 0),
  DNS_STRING_TEST(nsec_value_of_missing_data, 0),
  DNS_STRING_TEST(nsec_value_of_invalid_data, 0),

  DNS_STRING_TEST(dnskey_value_of_succeeds, 0),
  DNS_STRING_TEST(dnskey_value_of_missing_data, 0),
  DNS_STRING_TEST(dnskey_value_of_invalid_data, 0),

  DNS_STRING_TEST(nsec3_value_of_succeeds, 0),
  DNS_STRING_TEST(nsec3_value_of_missing_data, 0),
  DNS_STRING_TEST(nsec3_value_of_invalid_data, 0),

  DNS_STRING_TEST(nsec3param_value_of_succeeds, 0),
  DNS_STRING_TEST(nsec3param_value_of_missing_data, 0),
  DNS_STRING_TEST(nsec3param_value_of_invalid_data, 0),

  DNS_STRING_TEST(uri_value_of_succeeds, 0),
  DNS_STRING_TEST(uri_value_of_missing_data, 0),
  DNS_STRING_TEST(uri_value_of_invalid_data, 0),

  DNS_STRING_TEST(rr_value_of_succeeds, 0),
  DNS_STRING_TEST(rr_value_of_missing_data, 0),
  DNS_STRING_TEST(rr_value_of_invalid_data, 0),

  END_OF_TESTCASES
};
