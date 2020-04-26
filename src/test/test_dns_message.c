/* Copyright (c) 2019 Christian Hofer.
 * Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_dns_message.c
 * \brief Tests for DNS message container.
 */

#include "test/test.h"
#include "test/log_test_helpers.h"

#include "lib/container/dns_message.h"
#include "lib/container/dns_message_st.h"
#include "lib/encoding/dns_string.h"
#include "lib/defs/dns_types.h"

static void
test_dns_message_name_dup(void *arg)
{
  (void) arg;

  dns_name_t *name = dns_name_of("hello.");
  dns_name_t *duplicate = dns_name_dup(name);

  tt_str_op(duplicate->value, OP_EQ, name->value);
  tt_uint_op(duplicate->length, OP_EQ, name->length);

 done:
  dns_name_free(name);
  dns_name_free(duplicate);
}

static void
test_dns_message_name_normalize(void *arg)
{
  (void) arg;

  dns_name_t *empty = dns_name_of("");
  dns_name_t *space = dns_name_of(" ");
  dns_name_t *root = dns_name_of(".");
  dns_name_t *trailing_space = dns_name_of(". ");
  dns_name_t *mixed_cases = dns_name_of("CoM.");
  dns_name_t *missing_trailing_dot = dns_name_of("net");
  dns_name_t *contains_space = dns_name_of("org .");

  dns_name_normalize(empty);
  tt_str_op(empty->value, OP_EQ, ".");

  dns_name_normalize(space);
  tt_str_op(space->value, OP_EQ, ".");

  dns_name_normalize(root);
  tt_str_op(root->value, OP_EQ, ".");

  dns_name_normalize(trailing_space);
  tt_str_op(trailing_space->value, OP_EQ, ".");

  dns_name_normalize(mixed_cases);
  tt_str_op(mixed_cases->value, OP_EQ, "com.");

  dns_name_normalize(missing_trailing_dot);
  tt_str_op(missing_trailing_dot->value, OP_EQ, "net.");

  dns_name_normalize(contains_space);
  tt_str_op(contains_space->value, OP_EQ, "org.");

 done:
  dns_name_free(empty);
  dns_name_free(space);
  dns_name_free(root);
  dns_name_free(trailing_space);
  dns_name_free(mixed_cases);
  dns_name_free(missing_trailing_dot);
  dns_name_free(contains_space);
}

static void
test_dns_message_name_is_part_of(void *arg)
{
  (void) arg;

  dns_name_t *a1 = dns_name_of("");
  dns_name_t *b1 = dns_name_of("");

  dns_name_t *a2 = dns_name_of("");
  dns_name_t *b2 = dns_name_of(".");

  dns_name_t *a3 = dns_name_of(".");
  dns_name_t *b3 = dns_name_of("");

  dns_name_t *a4 = dns_name_of("com");
  dns_name_t *b4 = dns_name_of("com.");

  dns_name_t *a5 = dns_name_of("com");
  dns_name_t *b5 = dns_name_of("example.com.");

  dns_name_t *a6 = dns_name_of("example.com.");
  dns_name_t *b6 = dns_name_of("example.com");

  dns_name_t *a7 = dns_name_of("sample.com");
  dns_name_t *b7 = dns_name_of("www.example.com.");

  dns_name_t *a8 = dns_name_of("example.com");
  dns_name_t *b8 = dns_name_of("com.");

  tt_int_op(dns_name_is_part_of(a1, b1), OP_EQ, 0);
  tt_int_op(dns_name_is_part_of(a2, b2), OP_EQ, 0);
  tt_int_op(dns_name_is_part_of(a3, b3), OP_EQ, 0);
  tt_int_op(dns_name_is_part_of(a4, b4), OP_EQ, 1);
  tt_int_op(dns_name_is_part_of(a5, b5), OP_EQ, 1);
  tt_int_op(dns_name_is_part_of(a6, b6), OP_EQ, 2);
  tt_int_op(dns_name_is_part_of(a7, b7), OP_EQ, -1);
  tt_int_op(dns_name_is_part_of(a8, b8), OP_EQ, -1);

 done:
  dns_name_free(a1);
  dns_name_free(b1);

  dns_name_free(a2);
  dns_name_free(b2);

  dns_name_free(a3);
  dns_name_free(b3);

  dns_name_free(a4);
  dns_name_free(b4);

  dns_name_free(a5);
  dns_name_free(b5);

  dns_name_free(a6);
  dns_name_free(b6);

  dns_name_free(a7);
  dns_name_free(b7);

  dns_name_free(a8);
  dns_name_free(b8);
}

static void
test_dns_message_name_compare(void *arg)
{
  (void) arg;

  dns_name_t *a1 = dns_name_of("Z.a.example");
  dns_name_t *b1 = dns_name_of("z.example");

  dns_name_t *a2 = dns_name_of("yljkjljk.a.example.");
  dns_name_t *b2 = dns_name_of("z.a.example.");

  dns_name_t *a3 = dns_name_of("Z.a.example");
  dns_name_t *b3 = dns_name_of("zABC.a.EXAMPLE");

  dns_name_t *a4 = dns_name_of("example");
  dns_name_t *b4 = dns_name_of("example");

  dns_name_t *a5 = dns_name_of("Z.a.example");
  dns_name_t *b5 = dns_name_of("z.a.example");

  dns_name_t *a6 = dns_name_of("\001.z.example");
  dns_name_t *b6 = dns_name_of("z.example");

  dns_name_t *a7 = dns_name_of("z.example");
  dns_name_t *b7 = dns_name_of("zABC.a.EXAMPLE");

  dns_name_t *a8 = dns_name_of("\200.z.example");
  dns_name_t *b8 = dns_name_of("*.z.example");

  tt_int_op(dns_name_compare(a1, b1), OP_EQ, -25);
  tt_int_op(dns_name_compare(a2, b2), OP_EQ, -1);
  tt_int_op(dns_name_compare(a3, b3), OP_EQ, -1);
  tt_int_op(dns_name_compare(a4, b4), OP_EQ, 0);
  tt_int_op(dns_name_compare(a5, b5), OP_EQ, 0);
  tt_int_op(dns_name_compare(a6, b6), OP_EQ, 2);
  tt_int_op(dns_name_compare(a7, b7), OP_EQ, 25);
  tt_int_op(dns_name_compare(a8, b8), OP_EQ, 86);

 done:
  dns_name_free(a1);
  dns_name_free(b1);

  dns_name_free(a2);
  dns_name_free(b2);

  dns_name_free(a3);
  dns_name_free(b3);

  dns_name_free(a4);
  dns_name_free(b4);

  dns_name_free(a5);
  dns_name_free(b5);

  dns_name_free(a6);
  dns_name_free(b6);

  dns_name_free(a7);
  dns_name_free(b7);

  dns_name_free(a8);
  dns_name_free(b8);
}

static void
test_dns_message_type_dup(void *arg)
{
  (void) arg;

  dns_type_t *type = dns_type_new();
  type->value = 1234;
  type->name = tor_strdup("hello.");

  dns_type_t *duplicate = dns_type_dup(type);
  tt_uint_op(duplicate->value, OP_EQ, type->value);
  tt_str_op(duplicate->name, OP_EQ, type->name);

 done:
  dns_type_free(type);
  dns_type_free(duplicate);
}

static void
test_dns_message_header_dup(void *arg)
{
  (void) arg;

  dns_header_t *header = dns_header_new();
  header->id = 0x1234;
  header->qr = true;
  header->opcode = 1;
  header->tc = true;
  header->rd = true;
  header->ra = true;
  header->z = true;
  header->ad = true;
  header->cd = true;
  header->rcode = 1;
  header->qdcount = 1;
  header->ancount = 1;
  header->nscount = 1;
  header->arcount = 1;

  dns_header_t *duplicate = dns_header_dup(header);
  tt_uint_op(duplicate->id, OP_EQ, header->id);
  tt_uint_op(duplicate->qr, OP_EQ, header->qr);
  tt_uint_op(duplicate->opcode, OP_EQ, header->opcode);
  tt_uint_op(duplicate->tc, OP_EQ, header->tc);
  tt_uint_op(duplicate->rd, OP_EQ, header->rd);
  tt_uint_op(duplicate->ra, OP_EQ, header->ra);
  tt_uint_op(duplicate->z, OP_EQ, header->z);
  tt_uint_op(duplicate->ad, OP_EQ, header->ad);
  tt_uint_op(duplicate->cd, OP_EQ, header->cd);
  tt_uint_op(duplicate->rcode, OP_EQ, header->rcode);
  tt_uint_op(duplicate->qdcount, OP_EQ, header->qdcount);
  tt_uint_op(duplicate->ancount, OP_EQ, header->ancount);
  tt_uint_op(duplicate->nscount, OP_EQ, header->nscount);
  tt_uint_op(duplicate->arcount, OP_EQ, header->arcount);

 done:
  dns_header_free(header);
  dns_header_free(duplicate);
}

static void
test_dns_message_question_dup(void *arg)
{
  (void) arg;

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of("hello.");
  question->qtype = dns_type_of(DNS_TYPE_SINK);
  question->qclass = DNS_CLASS_CHAOS;

  dns_question_t *duplicate = dns_question_dup(question);
  tt_str_op(dns_name_str(duplicate->qname), OP_EQ,
            dns_name_str(question->qname));
  tt_uint_op(duplicate->qtype->value, OP_EQ, question->qtype->value);
  tt_uint_op(duplicate->qclass, OP_EQ, question->qclass);

 done:
  dns_question_free(question);
  dns_question_free(duplicate);
}

static void
test_dns_message_soa_dup(void *arg)
{
  (void) arg;

  dns_soa_t *soa = dns_soa_new();
  soa->mname = dns_name_of("hello.");
  soa->rname = dns_name_of("world.");
  soa->serial = 0x1ffff;
  soa->refresh = 0x2ffff;
  soa->retry = 0x3ffff;
  soa->expire = 0x4ffff;
  soa->minimum = 0x5ffff;

  dns_soa_t *duplicate = dns_soa_dup(soa);
  tt_str_op(dns_name_str(duplicate->mname), OP_EQ, dns_name_str(soa->mname));
  tt_str_op(dns_name_str(duplicate->rname), OP_EQ, dns_name_str(soa->rname));
  tt_int_op(duplicate->serial, OP_EQ, soa->serial);
  tt_int_op(duplicate->refresh, OP_EQ, soa->refresh);
  tt_int_op(duplicate->retry, OP_EQ, soa->retry);
  tt_int_op(duplicate->expire, OP_EQ, soa->expire);
  tt_int_op(duplicate->minimum, OP_EQ, soa->minimum);

 done:
  dns_soa_free(soa);
  dns_soa_free(duplicate);
}

static void
test_dns_message_mx_dup(void *arg)
{
  (void) arg;

  dns_mx_t *mx = dns_mx_new();
  mx->preference = 1234;
  mx->exchange = dns_name_of("hello");

  dns_mx_t *duplicate = dns_mx_dup(mx);
  tt_int_op(duplicate->preference, OP_EQ, mx->preference);
  tt_str_op(dns_name_str(duplicate->exchange), OP_EQ,
            dns_name_str(mx->exchange));

 done:
  dns_mx_free(mx);
  dns_mx_free(duplicate);
}

static void
test_dns_message_key_dup(void *arg)
{
  (void) arg;

  uint8_t public_key[2] = {0x01, 0x02};
  dns_key_t *key = dns_key_new();
  key->flags = 1234;
  key->protocol = 1;
  key->algorithm = 8;
  key->public_key = tor_memdup(public_key, 2);
  key->public_key_len = 2;

  dns_key_t *duplicate = dns_key_dup(key);
  tt_uint_op(duplicate->flags, OP_EQ, key->flags);
  tt_uint_op(duplicate->protocol, OP_EQ, key->protocol);
  tt_uint_op(duplicate->algorithm, OP_EQ, key->algorithm);
  tt_mem_op(duplicate->public_key, OP_EQ, key->public_key,
            key->public_key_len);

 done:
  dns_key_free(key);
  dns_key_free(duplicate);
}

static void
test_dns_message_ds_dup(void *arg)
{
  (void) arg;

  uint8_t digest[2] = {0x01, 0x02};
  dns_ds_t *ds = dns_ds_new();
  ds->key_tag = 1234;
  ds->algorithm = 8;
  ds->digest_type = 1;
  ds->digest = tor_memdup(digest, 2);
  ds->digest_len = 2;

  dns_ds_t *duplicate = dns_ds_dup(ds);
  tt_uint_op(duplicate->key_tag, OP_EQ, ds->key_tag);
  tt_uint_op(duplicate->algorithm, OP_EQ, ds->algorithm);
  tt_uint_op(duplicate->digest_type, OP_EQ, ds->digest_type);
  tt_mem_op(duplicate->digest, OP_EQ, ds->digest, ds->digest_len);

 done:
  dns_ds_free(ds);
  dns_ds_free(duplicate);
}

static void
test_dns_message_rrsig_dup(void *arg)
{
  (void) arg;

  uint8_t signature[2] = {0x01, 0x02};
  dns_rrsig_t *rrsig = dns_rrsig_new();
  rrsig->type_covered = dns_type_of(DNS_TYPE_SINK);
  rrsig->algorithm = 8;
  rrsig->labels = 1;
  rrsig->original_ttl = 1;
  rrsig->signature_expiration = 1;
  rrsig->signature_inception = 1;
  rrsig->key_tag = 1;
  rrsig->signer_name = dns_name_of("HellO.");
  rrsig->signature = tor_memdup(signature, 2);
  rrsig->signature_len = 2;

  dns_rrsig_t *duplicate = dns_rrsig_dup(rrsig);
  tt_uint_op(duplicate->type_covered->value, OP_EQ,
             rrsig->type_covered->value);
  tt_uint_op(duplicate->algorithm, OP_EQ, rrsig->algorithm);
  tt_uint_op(duplicate->labels, OP_EQ, rrsig->labels);
  tt_uint_op(duplicate->original_ttl, OP_EQ, rrsig->original_ttl);
  tt_uint_op(duplicate->signature_expiration, OP_EQ,
             rrsig->signature_expiration);
  tt_uint_op(duplicate->signature_inception, OP_EQ,
             rrsig->signature_inception);
  tt_uint_op(duplicate->key_tag, OP_EQ, rrsig->key_tag);
  tt_str_op(dns_name_str(duplicate->signer_name), OP_EQ,
            dns_name_str(rrsig->signer_name));
  tt_mem_op(duplicate->signature, OP_EQ, rrsig->signature,
            rrsig->signature_len);

 done:
  dns_rrsig_free(rrsig);
  dns_rrsig_free(duplicate);
}

static void
test_dns_message_nsec_dup(void *arg)
{
  (void) arg;

  dns_nsec_t *nsec = dns_nsec_new();
  nsec->next_domain_name = dns_name_of("HellO.");
  smartlist_add(nsec->types, dns_type_of(DNS_TYPE_A));

  dns_nsec_t *duplicate = dns_nsec_dup(nsec);
  tt_str_op(dns_name_str(duplicate->next_domain_name), OP_EQ,
            dns_name_str(nsec->next_domain_name));
  tt_int_op(smartlist_len(duplicate->types), OP_EQ,
            smartlist_len(nsec->types));

 done:
  dns_nsec_free(nsec);
  dns_nsec_free(duplicate);
}

static void
test_dns_message_dnskey_dup(void *arg)
{
  (void) arg;

  uint8_t public_key[2] = {0x01, 0x02};
  dns_dnskey_t *dnskey = dns_dnskey_new();
  dnskey->flags = 1234;
  dnskey->protocol = 1;
  dnskey->algorithm = 8;
  dnskey->public_key = tor_memdup(public_key, 2);
  dnskey->public_key_len = 2;

  dns_dnskey_t *duplicate = dns_dnskey_dup(dnskey);
  tt_uint_op(duplicate->flags, OP_EQ, dnskey->flags);
  tt_uint_op(duplicate->protocol, OP_EQ, dnskey->protocol);
  tt_uint_op(duplicate->algorithm, OP_EQ, dnskey->algorithm);
  tt_mem_op(duplicate->public_key, OP_EQ, dnskey->public_key,
            dnskey->public_key_len);

 done:
  dns_dnskey_free(dnskey);
  dns_dnskey_free(duplicate);
}

static void
test_dns_message_nsec3_dup(void *arg)
{
  (void) arg;

  uint8_t salt_length = 2;
  uint8_t salt[] = {0xca, 0xfe};

  uint8_t hash_length = 2;
  uint8_t next_hashed_owner_name[] = {0xab, 0xcd};

  dns_nsec3_t *nsec3 = dns_nsec3_new();
  nsec3->hash_algorithm = 1;
  nsec3->flags = 0;
  nsec3->iterations = 8;
  nsec3->salt_length = salt_length;
  nsec3->salt = tor_memdup(salt, salt_length);
  nsec3->hash_length = hash_length;
  nsec3->next_hashed_owner_name = tor_memdup(next_hashed_owner_name,
                                             hash_length);
  smartlist_add(nsec3->types, dns_type_of(DNS_TYPE_A));

  dns_nsec3_t *duplicate = dns_nsec3_dup(nsec3);
  tt_int_op(duplicate->hash_algorithm, OP_EQ, nsec3->hash_algorithm);
  tt_int_op(duplicate->flags, OP_EQ, nsec3->flags);
  tt_int_op(duplicate->iterations, OP_EQ, nsec3->iterations);
  tt_int_op(duplicate->salt_length, OP_EQ, nsec3->salt_length);
  tt_mem_op(duplicate->salt, OP_EQ, nsec3->salt, nsec3->salt_length);
  tt_int_op(duplicate->hash_length, OP_EQ, nsec3->hash_length);
  tt_mem_op(duplicate->next_hashed_owner_name, OP_EQ,
            nsec3->next_hashed_owner_name, nsec3->hash_length);
  tt_int_op(smartlist_len(duplicate->types), OP_EQ,
            smartlist_len(nsec3->types));

  done:
    dns_nsec3_free(nsec3);
    dns_nsec3_free(duplicate);
}

static void
test_dns_message_nsec3param_dup(void *arg)
{
  (void) arg;

  uint8_t salt_length = 2;
  uint8_t salt[] = {0xca, 0xfe};

  dns_nsec3param_t *nsec3param = dns_nsec3param_new();
  nsec3param->hash_algorithm = 1;
  nsec3param->flags = 0;
  nsec3param->iterations = 8;
  nsec3param->salt_length = salt_length;
  nsec3param->salt = tor_memdup(salt, salt_length);

  dns_nsec3param_t *duplicate = dns_nsec3param_dup(nsec3param);
  tt_int_op(duplicate->hash_algorithm, OP_EQ, nsec3param->hash_algorithm);
  tt_int_op(duplicate->flags, OP_EQ, nsec3param->flags);
  tt_int_op(duplicate->iterations, OP_EQ, nsec3param->iterations);
  tt_int_op(duplicate->salt_length, OP_EQ, nsec3param->salt_length);
  tt_mem_op(duplicate->salt, OP_EQ, nsec3param->salt, duplicate->salt_length);

 done:
  dns_nsec3param_free(nsec3param);
  dns_nsec3param_free(duplicate);
}

static void
test_dns_message_uri_dup(void *arg)
{
  (void) arg;

  dns_uri_t *uri = dns_uri_new();
  uri->priority = 1234;
  uri->weight = 4567;
  uri->target = tor_strdup("hello");

  dns_uri_t *duplicate = dns_uri_dup(uri);
  tt_uint_op(duplicate->priority, OP_EQ, uri->priority);
  tt_uint_op(duplicate->weight, OP_EQ, uri->weight);
  tt_str_op(duplicate->target, OP_EQ, uri->target);

 done:
  dns_uri_free(uri);
  dns_uri_free(duplicate);
}

static void
test_dns_message_rr_dup(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();
  rr->name = dns_name_of("hello.");
  rr->rrtype = dns_type_of(DNS_TYPE_A);
  rr->rrclass = DNS_CLASS_CHAOS;
  rr->a = tor_strdup("1.2.3.4");
  rr->ns = dns_name_of("hello.");
  rr->cname = dns_name_of("hello.");
  rr->soa = dns_soa_new();
  rr->soa->mname = dns_name_of("hello.");
  rr->ptr = dns_name_of("hello.");
  rr->mx = dns_mx_new();
  rr->mx->exchange = dns_name_of("mail.example.com.");
  rr->key = dns_key_new();
  rr->key->flags = 1234;
  rr->aaaa = tor_strdup("2::3:0:0:4");
  rr->ds = dns_ds_new();
  rr->ds->key_tag = 1234;
  rr->rrsig = dns_rrsig_new();
  rr->rrsig->signer_name = dns_name_of("hello.");
  rr->nsec = dns_nsec_new();
  rr->nsec->next_domain_name = dns_name_of("hello.");
  rr->dnskey = dns_dnskey_new();
  rr->dnskey->flags = 1234;
  rr->nsec3 = dns_nsec3_new();
  rr->nsec3->hash_algorithm = 1;
  rr->nsec3param = dns_nsec3param_new();
  rr->nsec3param->hash_algorithm = 1;
  rr->uri = dns_uri_new();
  rr->uri->priority = 1234;

  dns_rr_t *duplicate = dns_rr_dup(rr);
  tt_str_op(dns_name_str(duplicate->name), OP_EQ, dns_name_str(rr->name));
  tt_uint_op(duplicate->rrtype->value, OP_EQ, rr->rrtype->value);
  tt_uint_op(duplicate->rrclass, OP_EQ, rr->rrclass);
  tt_str_op(duplicate->a, OP_EQ, rr->a);
  tt_str_op(dns_name_str(duplicate->ns), OP_EQ, dns_name_str(rr->ns));
  tt_str_op(dns_name_str(duplicate->cname), OP_EQ, dns_name_str(rr->cname));
  tt_str_op(dns_name_str(duplicate->soa->mname), OP_EQ,
            dns_name_str(rr->soa->mname));
  tt_str_op(dns_name_str(duplicate->ptr), OP_EQ, dns_name_str(rr->ptr));
  tt_str_op(dns_name_str(duplicate->mx->exchange), OP_EQ,
            dns_name_str(rr->mx->exchange));
  tt_int_op(duplicate->key->flags, OP_EQ, rr->key->flags);
  tt_str_op(duplicate->aaaa, OP_EQ, rr->aaaa);
  tt_int_op(duplicate->ds->key_tag, OP_EQ, rr->ds->key_tag);
  tt_str_op(dns_name_str(duplicate->rrsig->signer_name), OP_EQ,
            dns_name_str(rr->rrsig->signer_name));
  tt_str_op(dns_name_str(duplicate->nsec->next_domain_name), OP_EQ,
            dns_name_str(rr->nsec->next_domain_name));
  tt_int_op(duplicate->dnskey->flags, OP_EQ, rr->dnskey->flags);
  tt_int_op(duplicate->nsec3->hash_algorithm, OP_EQ,
            rr->nsec3->hash_algorithm);
  tt_int_op(duplicate->nsec3param->hash_algorithm, OP_EQ,
            rr->nsec3param->hash_algorithm);
  tt_int_op(duplicate->uri->priority, OP_EQ, rr->uri->priority);

 done:
  dns_rr_free(rr);
  dns_rr_free(duplicate);
}

static void
test_dns_message_dup(void *arg)
{
  (void) arg;

  dns_message_t *message = dns_message_new();
  message->header->id = 1234;
  smartlist_add(message->question_list, dns_question_new());
  smartlist_add(message->answer_list, dns_rr_new());
  smartlist_add(message->name_server_list, dns_rr_new());
  smartlist_add(message->additional_record_list, dns_rr_new());

  dns_message_t *duplicate = dns_message_dup(message);
  tt_uint_op(duplicate->header->id, OP_EQ, message->header->id);
  tt_uint_op(smartlist_len(duplicate->question_list), OP_EQ,
             smartlist_len(message->question_list));
  tt_uint_op(smartlist_len(duplicate->answer_list), OP_EQ,
             smartlist_len(message->answer_list));
  tt_uint_op(smartlist_len(duplicate->name_server_list), OP_EQ,
             smartlist_len(message->name_server_list));
  tt_uint_op(smartlist_len(duplicate->additional_record_list), OP_EQ,
             smartlist_len(message->additional_record_list));
  tt_uint_op(duplicate->cached_at.tv_sec, OP_EQ, message->cached_at.tv_sec);
  tt_uint_op(duplicate->cached_at.tv_usec, OP_EQ, message->cached_at.tv_usec);

 done:
  dns_message_free(message);
  dns_message_free(duplicate);
}

static void
test_dns_message_get_question_succeeds(void *arg)
{
  (void) arg;

  dns_question_t *question = dns_question_new();

  dns_message_t *message = dns_message_new();
  message->header->qdcount = 1;
  smartlist_add(message->question_list, question);

  tt_ptr_op(dns_message_get_question(message), OP_EQ, question);

 done:
  dns_message_free(message);
}

static void
test_dns_message_get_question_invalid_header(void *arg)
{
  (void) arg;

  dns_question_t *question = dns_question_new();

  dns_message_t *message = dns_message_new();
  message->header->qdcount = 0;
  smartlist_add(message->question_list, question);

  tt_ptr_op(dns_message_get_question(message), OP_EQ, NULL);

 done:
  dns_message_free(message);
}

static void
test_dns_message_get_question_missing_question(void *arg)
{
  (void) arg;

  dns_message_t *message = dns_message_new();
  message->header->qdcount = 1;

  tt_ptr_op(dns_message_get_question(message), OP_EQ, NULL);

 done:
  dns_message_free(message);
}

#define DNS_MESSAGE_TEST(name, flags)                          \
  { #name, test_dns_message_ ## name, flags, NULL, NULL }

struct testcase_t dns_message_tests[] = {
  DNS_MESSAGE_TEST(name_dup, 0),
  DNS_MESSAGE_TEST(name_normalize, 0),
  DNS_MESSAGE_TEST(name_is_part_of, 0),
  DNS_MESSAGE_TEST(name_compare, 0),
  DNS_MESSAGE_TEST(type_dup, 0),
  DNS_MESSAGE_TEST(header_dup, 0),
  DNS_MESSAGE_TEST(question_dup, 0),
  DNS_MESSAGE_TEST(soa_dup, 0),
  DNS_MESSAGE_TEST(mx_dup, 0),
  DNS_MESSAGE_TEST(key_dup, 0),
  DNS_MESSAGE_TEST(ds_dup, 0),
  DNS_MESSAGE_TEST(rrsig_dup, 0),
  DNS_MESSAGE_TEST(nsec_dup, 0),
  DNS_MESSAGE_TEST(dnskey_dup, 0),
  DNS_MESSAGE_TEST(nsec3_dup, 0),
  DNS_MESSAGE_TEST(nsec3param_dup, 0),
  DNS_MESSAGE_TEST(uri_dup, 0),
  DNS_MESSAGE_TEST(rr_dup, 0),
  DNS_MESSAGE_TEST(dup, 0),

  DNS_MESSAGE_TEST(get_question_succeeds, 0),
  DNS_MESSAGE_TEST(get_question_invalid_header, 0),
  DNS_MESSAGE_TEST(get_question_missing_question, 0),

  END_OF_TESTCASES
};
