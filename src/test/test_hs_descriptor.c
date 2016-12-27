/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_descriptor.c
 * \brief Test hidden service descriptor encoding and decoding.
 */

#define HS_DESCRIPTOR_PRIVATE

#include "crypto_ed25519.h"
#include "ed25519_cert.h"
#include "or.h"
#include "hs_descriptor.h"
#include "test.h"
#include "torcert.h"

static hs_desc_intro_point_t *
helper_build_intro_point(const ed25519_keypair_t *blinded_kp, time_t now,
                         const char *addr, int legacy)
{
  int ret;
  ed25519_keypair_t auth_kp;
  hs_desc_intro_point_t *intro_point = NULL;
  hs_desc_intro_point_t *ip = tor_malloc_zero(sizeof(*ip));
  ip->link_specifiers = smartlist_new();

  {
    hs_desc_link_specifier_t *ls = tor_malloc_zero(sizeof(*ls));
    if (legacy) {
      ls->type = LS_LEGACY_ID;
      memcpy(ls->u.legacy_id, "0299F268FCA9D55CD157976D39AE92B4B455B3A8",
             DIGEST_LEN);
    } else {
      ls->u.ap.port = 9001;
      int family = tor_addr_parse(&ls->u.ap.addr, addr);
      switch (family) {
      case AF_INET:
        ls->type = LS_IPV4;
        break;
      case AF_INET6:
        ls->type = LS_IPV6;
        break;
      default:
        /* Stop the test, not suppose to have an error. */
        tt_int_op(family, OP_EQ, AF_INET);
      }
    }
    smartlist_add(ip->link_specifiers, ls);
  }

  ret = ed25519_keypair_generate(&auth_kp, 0);
  tt_int_op(ret, ==, 0);
  ip->auth_key_cert = tor_cert_create(blinded_kp, CERT_TYPE_AUTH_HS_IP_KEY,
                                      &auth_kp.pubkey, now,
                                      HS_DESC_CERT_LIFETIME,
                                      CERT_FLAG_INCLUDE_SIGNING_KEY);
  tt_assert(ip->auth_key_cert);

  if (legacy) {
    ip->enc_key.legacy = crypto_pk_new();
    ip->enc_key_type = HS_DESC_KEY_TYPE_LEGACY;
    tt_assert(ip->enc_key.legacy);
    ret = crypto_pk_generate_key(ip->enc_key.legacy);
    tt_int_op(ret, ==, 0);
  } else {
    ret = curve25519_keypair_generate(&ip->enc_key.curve25519, 0);
    tt_int_op(ret, ==, 0);
    ip->enc_key_type = HS_DESC_KEY_TYPE_CURVE25519;
  }

  intro_point = ip;
 done:
  return intro_point;
}

/* Return a valid hs_descriptor_t object. If no_ip is set, no introduction
 * points are added. */
static hs_descriptor_t *
helper_build_hs_desc(unsigned int no_ip, ed25519_public_key_t *signing_pubkey)
{
  int ret;
  time_t now = time(NULL);
  ed25519_keypair_t blinded_kp;
  hs_descriptor_t *descp = NULL, *desc = tor_malloc_zero(sizeof(*desc));

  desc->plaintext_data.version = HS_DESC_SUPPORTED_FORMAT_VERSION_MAX;

  /* Copy only the public key into the descriptor. */
  memcpy(&desc->plaintext_data.signing_pubkey, signing_pubkey,
         sizeof(ed25519_public_key_t));

  ret = ed25519_keypair_generate(&blinded_kp, 0);
  tt_int_op(ret, ==, 0);
  /* Copy only the public key into the descriptor. */
  memcpy(&desc->plaintext_data.blinded_pubkey, &blinded_kp.pubkey,
         sizeof(ed25519_public_key_t));

  desc->plaintext_data.signing_key_cert =
    tor_cert_create(&blinded_kp, CERT_TYPE_SIGNING_HS_DESC, signing_pubkey,
                    now, 3600, CERT_FLAG_INCLUDE_SIGNING_KEY);
  tt_assert(desc->plaintext_data.signing_key_cert);
  desc->plaintext_data.revision_counter = 42;
  desc->plaintext_data.lifetime_sec = 3 * 60 * 60;

  /* Setup encrypted data section. */
  desc->encrypted_data.create2_ntor = 1;
  desc->encrypted_data.auth_types = smartlist_new();
  desc->encrypted_data.single_onion_service = 1;
  smartlist_add(desc->encrypted_data.auth_types, tor_strdup("ed25519"));
  desc->encrypted_data.intro_points = smartlist_new();
  if (!no_ip) {
    /* Add four intro points. */
    smartlist_add(desc->encrypted_data.intro_points,
                helper_build_intro_point(&blinded_kp, now, "1.2.3.4", 0));
    smartlist_add(desc->encrypted_data.intro_points,
                helper_build_intro_point(&blinded_kp, now, "[2600::1]", 0));
    smartlist_add(desc->encrypted_data.intro_points,
                helper_build_intro_point(&blinded_kp, now, "3.2.1.4", 1));
    smartlist_add(desc->encrypted_data.intro_points,
                helper_build_intro_point(&blinded_kp, now, "", 1));
  }

  descp = desc;
 done:
  return descp;
}

static void
helper_compare_hs_desc(const hs_descriptor_t *desc1,
                       const hs_descriptor_t *desc2)
{
  char *addr1 = NULL, *addr2 = NULL;
  /* Plaintext data section. */
  tt_int_op(desc1->plaintext_data.version, OP_EQ,
            desc2->plaintext_data.version);
  tt_uint_op(desc1->plaintext_data.lifetime_sec, OP_EQ,
             desc2->plaintext_data.lifetime_sec);
  tt_assert(tor_cert_eq(desc1->plaintext_data.signing_key_cert,
                        desc2->plaintext_data.signing_key_cert));
  tt_mem_op(desc1->plaintext_data.signing_pubkey.pubkey, OP_EQ,
            desc2->plaintext_data.signing_pubkey.pubkey,
            ED25519_PUBKEY_LEN);
  tt_mem_op(desc1->plaintext_data.blinded_pubkey.pubkey, OP_EQ,
            desc2->plaintext_data.blinded_pubkey.pubkey,
            ED25519_PUBKEY_LEN);
  tt_u64_op(desc1->plaintext_data.revision_counter, ==,
             desc2->plaintext_data.revision_counter);

  /* NOTE: We can't compare the encrypted blob because when encoding the
   * descriptor, the object is immutable thus we don't update it with the
   * encrypted blob. As contrast to the decoding process where we populate a
   * descriptor object. */

  /* Encrypted data section. */
  tt_uint_op(desc1->encrypted_data.create2_ntor, ==,
             desc2->encrypted_data.create2_ntor);

  /* Authentication type. */
  tt_int_op(!!desc1->encrypted_data.auth_types, ==,
            !!desc2->encrypted_data.auth_types);
  if (desc1->encrypted_data.auth_types && desc2->encrypted_data.auth_types) {
    tt_int_op(smartlist_len(desc1->encrypted_data.auth_types), ==,
              smartlist_len(desc2->encrypted_data.auth_types));
    for (int i = 0; i < smartlist_len(desc1->encrypted_data.auth_types); i++) {
      tt_str_op(smartlist_get(desc1->encrypted_data.auth_types, i), OP_EQ,
                smartlist_get(desc2->encrypted_data.auth_types, i));
    }
  }

  /* Introduction points. */
  {
    tt_assert(desc1->encrypted_data.intro_points);
    tt_assert(desc2->encrypted_data.intro_points);
    tt_int_op(smartlist_len(desc1->encrypted_data.intro_points), ==,
              smartlist_len(desc2->encrypted_data.intro_points));
    for (int i=0; i < smartlist_len(desc1->encrypted_data.intro_points); i++) {
      hs_desc_intro_point_t *ip1 = smartlist_get(desc1->encrypted_data
                                                 .intro_points, i),
                            *ip2 = smartlist_get(desc2->encrypted_data
                                                 .intro_points, i);
      tt_assert(tor_cert_eq(ip1->auth_key_cert, ip2->auth_key_cert));
      tt_int_op(ip1->enc_key_type, OP_EQ, ip2->enc_key_type);
      tt_assert(ip1->enc_key_type == HS_DESC_KEY_TYPE_LEGACY ||
                ip1->enc_key_type == HS_DESC_KEY_TYPE_CURVE25519);
      switch (ip1->enc_key_type) {
      case HS_DESC_KEY_TYPE_LEGACY:
        tt_int_op(crypto_pk_cmp_keys(ip1->enc_key.legacy, ip2->enc_key.legacy),
                  OP_EQ, 0);
        break;
      case HS_DESC_KEY_TYPE_CURVE25519:
        tt_mem_op(ip1->enc_key.curve25519.pubkey.public_key, OP_EQ,
                  ip2->enc_key.curve25519.pubkey.public_key,
                  CURVE25519_PUBKEY_LEN);
        break;
      }

      tt_int_op(smartlist_len(ip1->link_specifiers), ==,
                smartlist_len(ip2->link_specifiers));
      for (int j = 0; j < smartlist_len(ip1->link_specifiers); j++) {
        hs_desc_link_specifier_t *ls1 = smartlist_get(ip1->link_specifiers, j),
                                 *ls2 = smartlist_get(ip2->link_specifiers, j);
        tt_int_op(ls1->type, ==, ls2->type);
        switch (ls1->type) {
        case LS_IPV4:
        case LS_IPV6:
        {
          addr1 = tor_addr_to_str_dup(&ls1->u.ap.addr);
          addr2 = tor_addr_to_str_dup(&ls2->u.ap.addr);
          tt_str_op(addr1, OP_EQ, addr2);
          tor_free(addr1);
          tor_free(addr2);
          tt_int_op(ls1->u.ap.port, ==, ls2->u.ap.port);
        }
        break;
        case LS_LEGACY_ID:
          tt_mem_op(ls1->u.legacy_id, OP_EQ, ls2->u.legacy_id,
                    sizeof(ls1->u.legacy_id));
          break;
        default:
          /* Unknown type, caught it and print its value. */
          tt_int_op(ls1->type, OP_EQ, -1);
        }
      }
    }
  }

 done:
  tor_free(addr1);
  tor_free(addr2);
}

/* Test certificate encoding put in a descriptor. */
static void
test_cert_encoding(void *arg)
{
  int ret;
  char *encoded = NULL;
  time_t now = time(NULL);
  ed25519_keypair_t kp;
  ed25519_public_key_t signed_key;
  ed25519_secret_key_t secret_key;
  tor_cert_t *cert = NULL;

  (void) arg;

  ret = ed25519_keypair_generate(&kp, 0);
  tt_int_op(ret, == , 0);
  ret = ed25519_secret_key_generate(&secret_key, 0);
  tt_int_op(ret, == , 0);
  ret = ed25519_public_key_generate(&signed_key, &secret_key);
  tt_int_op(ret, == , 0);

  cert = tor_cert_create(&kp, CERT_TYPE_SIGNING_AUTH, &signed_key,
                         now, 3600 * 2, CERT_FLAG_INCLUDE_SIGNING_KEY);
  tt_assert(cert);

  /* Test the certificate encoding function. */
  ret = tor_cert_encode_ed22519(cert, &encoded);
  tt_int_op(ret, ==, 0);

  /* Validated the certificate string. */
  {
    char *end, *pos = encoded;
    char *b64_cert, buf[256];
    size_t b64_cert_len;
    tor_cert_t *parsed_cert;

    tt_int_op(strcmpstart(pos, "-----BEGIN ED25519 CERT-----\n"), ==, 0);
    pos += strlen("-----BEGIN ED25519 CERT-----\n");

    /* Isolate the base64 encoded certificate and try to decode it. */
    end = strstr(pos, "-----END ED25519 CERT-----");
    tt_assert(end);
    b64_cert = pos;
    b64_cert_len = end - pos;
    ret = base64_decode(buf, sizeof(buf), b64_cert, b64_cert_len);
    tt_int_op(ret, >, 0);
    /* Parseable? */
    parsed_cert = tor_cert_parse((uint8_t *) buf, ret);
    tt_assert(parsed_cert);
    /* Signature is valid? */
    ret = tor_cert_checksig(parsed_cert, &kp.pubkey, now + 10);
    tt_int_op(ret, ==, 0);
    ret = tor_cert_eq(cert, parsed_cert);
    tt_int_op(ret, ==, 1);
    /* The cert did have the signing key? */
    ret= ed25519_pubkey_eq(&parsed_cert->signing_key, &kp.pubkey);
    tt_int_op(ret, ==, 1);
    tor_cert_free(parsed_cert);

    /* Get to the end part of the certificate. */
    pos += b64_cert_len;
    tt_int_op(strcmpstart(pos, "-----END ED25519 CERT-----"), ==, 0);
    pos += strlen("-----END ED25519 CERT-----");
  }

 done:
  tor_cert_free(cert);
  tor_free(encoded);
}

/* Test the descriptor padding. */
static void
test_descriptor_padding(void *arg)
{
  char *plaintext;
  size_t plaintext_len, padded_len;
  uint8_t *padded_plaintext = NULL;

/* Example: if l = 129, the ceiled division gives 2 and then multiplied by 128
 * to give 256. With l = 127, ceiled division gives 1 then times 128. */
#define PADDING_EXPECTED_LEN(l) \
  CEIL_DIV(l, HS_DESC_PLAINTEXT_PADDING_MULTIPLE) * \
  HS_DESC_PLAINTEXT_PADDING_MULTIPLE

  (void) arg;

  { /* test #1: no padding */
    plaintext_len = HS_DESC_PLAINTEXT_PADDING_MULTIPLE;
    plaintext = tor_malloc(plaintext_len);
    padded_len = build_plaintext_padding(plaintext, plaintext_len,
                                         &padded_plaintext);
    tt_assert(padded_plaintext);
    tor_free(plaintext);
    /* Make sure our padding has been zeroed. */
    tt_int_op(tor_mem_is_zero((char *) padded_plaintext + plaintext_len,
                              padded_len - plaintext_len), OP_EQ, 1);
    tor_free(padded_plaintext);
    /* Never never have a padded length smaller than the plaintext. */
    tt_int_op(padded_len, OP_GE, plaintext_len);
    tt_int_op(padded_len, OP_EQ, PADDING_EXPECTED_LEN(plaintext_len));
  }

  { /* test #2: one byte padding? */
    plaintext_len = HS_DESC_PLAINTEXT_PADDING_MULTIPLE - 1;
    plaintext = tor_malloc(plaintext_len);
    padded_plaintext = NULL;
    padded_len = build_plaintext_padding(plaintext, plaintext_len,
                                         &padded_plaintext);
    tt_assert(padded_plaintext);
    tor_free(plaintext);
    /* Make sure our padding has been zeroed. */
    tt_int_op(tor_mem_is_zero((char *) padded_plaintext + plaintext_len,
                              padded_len - plaintext_len), OP_EQ, 1);
    tor_free(padded_plaintext);
    /* Never never have a padded length smaller than the plaintext. */
    tt_int_op(padded_len, OP_GE, plaintext_len);
    tt_int_op(padded_len, OP_EQ, PADDING_EXPECTED_LEN(plaintext_len));
  }

  { /* test #3: Lots more bytes of padding? */
    plaintext_len = HS_DESC_PLAINTEXT_PADDING_MULTIPLE + 1;
    plaintext = tor_malloc(plaintext_len);
    padded_plaintext = NULL;
    padded_len = build_plaintext_padding(plaintext, plaintext_len,
                                         &padded_plaintext);
    tt_assert(padded_plaintext);
    tor_free(plaintext);
    /* Make sure our padding has been zeroed. */
    tt_int_op(tor_mem_is_zero((char *) padded_plaintext + plaintext_len,
                              padded_len - plaintext_len), OP_EQ, 1);
    tor_free(padded_plaintext);
    /* Never never have a padded length smaller than the plaintext. */
    tt_int_op(padded_len, OP_GE, plaintext_len);
    tt_int_op(padded_len, OP_EQ, PADDING_EXPECTED_LEN(plaintext_len));
  }

 done:
  return;
}

static void
test_link_specifier(void *arg)
{
  ssize_t ret;
  hs_desc_link_specifier_t spec;
  smartlist_t *link_specifiers = smartlist_new();

  (void) arg;

  /* Always this port. */
  spec.u.ap.port = 42;
  smartlist_add(link_specifiers, &spec);

  /* Test IPv4 for starter. */
  {
    char *b64, buf[256];
    uint32_t ipv4;
    link_specifier_t *ls;

    spec.type = LS_IPV4;
    ret = tor_addr_parse(&spec.u.ap.addr, "1.2.3.4");
    tt_int_op(ret, ==, AF_INET);
    b64 = encode_link_specifiers(link_specifiers);
    tt_assert(b64);

    /* Decode it and validate the format. */
    ret = base64_decode(buf, sizeof(buf), b64, strlen(b64));
    tt_int_op(ret, >, 0);
    /* First byte is the number of link specifier. */
    tt_int_op(get_uint8(buf), ==, 1);
    ret = link_specifier_parse(&ls, (uint8_t *) buf + 1, ret - 1);
    tt_int_op(ret, ==, 8);
    /* Should be 2 bytes for port and 4 bytes for IPv4. */
    tt_int_op(link_specifier_get_ls_len(ls), ==, 6);
    ipv4 = link_specifier_get_un_ipv4_addr(ls);
    tt_int_op(tor_addr_to_ipv4h(&spec.u.ap.addr), ==, ipv4);
    tt_int_op(link_specifier_get_un_ipv4_port(ls), ==, spec.u.ap.port);

    link_specifier_free(ls);
    tor_free(b64);
  }

  /* Test IPv6. */
  {
    char *b64, buf[256];
    uint8_t ipv6[16];
    link_specifier_t *ls;

    spec.type = LS_IPV6;
    ret = tor_addr_parse(&spec.u.ap.addr, "[1:2:3:4::]");
    tt_int_op(ret, ==, AF_INET6);
    b64 = encode_link_specifiers(link_specifiers);
    tt_assert(b64);

    /* Decode it and validate the format. */
    ret = base64_decode(buf, sizeof(buf), b64, strlen(b64));
    tt_int_op(ret, >, 0);
    /* First byte is the number of link specifier. */
    tt_int_op(get_uint8(buf), ==, 1);
    ret = link_specifier_parse(&ls, (uint8_t *) buf + 1, ret - 1);
    tt_int_op(ret, ==, 20);
    /* Should be 2 bytes for port and 16 bytes for IPv6. */
    tt_int_op(link_specifier_get_ls_len(ls), ==, 18);
    for (unsigned int i = 0; i < sizeof(ipv6); i++) {
      ipv6[i] = link_specifier_get_un_ipv6_addr(ls, i);
    }
    tt_mem_op(tor_addr_to_in6_addr8(&spec.u.ap.addr), ==, ipv6, sizeof(ipv6));
    tt_int_op(link_specifier_get_un_ipv6_port(ls), ==, spec.u.ap.port);

    link_specifier_free(ls);
    tor_free(b64);
  }

  /* Test legacy. */
  {
    char *b64, buf[256];
    uint8_t *id;
    link_specifier_t *ls;

    spec.type = LS_LEGACY_ID;
    memset(spec.u.legacy_id, 'Y', sizeof(spec.u.legacy_id));
    b64 = encode_link_specifiers(link_specifiers);
    tt_assert(b64);

    /* Decode it and validate the format. */
    ret = base64_decode(buf, sizeof(buf), b64, strlen(b64));
    tt_int_op(ret, >, 0);
    /* First byte is the number of link specifier. */
    tt_int_op(get_uint8(buf), ==, 1);
    ret = link_specifier_parse(&ls, (uint8_t *) buf + 1, ret - 1);
    /* 20 bytes digest + 1 byte type + 1 byte len. */
    tt_int_op(ret, ==, 22);
    tt_int_op(link_specifier_getlen_un_legacy_id(ls), OP_EQ, DIGEST_LEN);
    /* Digest length is 20 bytes. */
    tt_int_op(link_specifier_get_ls_len(ls), OP_EQ, DIGEST_LEN);
    id = link_specifier_getarray_un_legacy_id(ls);
    tt_mem_op(spec.u.legacy_id, OP_EQ, id, DIGEST_LEN);

    link_specifier_free(ls);
    tor_free(b64);
  }

 done:
  smartlist_free(link_specifiers);
}

static void
test_encode_descriptor(void *arg)
{
  int ret;
  char *encoded = NULL;
  ed25519_keypair_t signing_kp;
  hs_descriptor_t *desc = NULL;

  (void) arg;

  ret = ed25519_keypair_generate(&signing_kp, 0);
  tt_int_op(ret, ==, 0);
  desc = helper_build_hs_desc(0, &signing_kp.pubkey);
  ret = hs_desc_encode_descriptor(desc, &signing_kp, &encoded);
  tt_int_op(ret, ==, 0);
  tt_assert(encoded);

 done:
  hs_descriptor_free(desc);
  tor_free(encoded);
}

static void
test_decode_descriptor(void *arg)
{
  int ret;
  char *encoded = NULL;
  ed25519_keypair_t signing_kp;
  hs_descriptor_t *desc = NULL;
  hs_descriptor_t *decoded = NULL;
  hs_descriptor_t *desc_no_ip = NULL;

  (void) arg;

  ret = ed25519_keypair_generate(&signing_kp, 0);
  tt_int_op(ret, ==, 0);
  desc = helper_build_hs_desc(0, &signing_kp.pubkey);

  /* Give some bad stuff to the decoding function. */
  ret = hs_desc_decode_descriptor("hladfjlkjadf", NULL, &decoded);
  tt_int_op(ret, OP_EQ, -1);

  ret = hs_desc_encode_descriptor(desc, &signing_kp, &encoded);
  tt_int_op(ret, ==, 0);
  tt_assert(encoded);

  ret = hs_desc_decode_descriptor(encoded, NULL, &decoded);
  tt_int_op(ret, ==, 0);
  tt_assert(decoded);

  helper_compare_hs_desc(desc, decoded);

  /* Decode a descriptor with _no_ introduction points. */
  {
    ed25519_keypair_t signing_kp_no_ip;
    ret = ed25519_keypair_generate(&signing_kp_no_ip, 0);
    tt_int_op(ret, ==, 0);
    desc_no_ip = helper_build_hs_desc(1, &signing_kp_no_ip.pubkey);
    tt_assert(desc_no_ip);
    tor_free(encoded);
    ret = hs_desc_encode_descriptor(desc_no_ip, &signing_kp_no_ip, &encoded);
    tt_int_op(ret, ==, 0);
    tt_assert(encoded);
    hs_descriptor_free(decoded);
    ret = hs_desc_decode_descriptor(encoded, NULL, &decoded);
    tt_int_op(ret, ==, 0);
    tt_assert(decoded);
  }

 done:
  hs_descriptor_free(desc);
  hs_descriptor_free(desc_no_ip);
  hs_descriptor_free(decoded);
  tor_free(encoded);
}

static void
test_supported_version(void *arg)
{
  int ret;

  (void) arg;

  /* Unsupported. */
  ret = hs_desc_is_supported_version(42);
  tt_int_op(ret, OP_EQ, 0);
  /* To early. */
  ret = hs_desc_is_supported_version(HS_DESC_SUPPORTED_FORMAT_VERSION_MIN - 1);
  tt_int_op(ret, OP_EQ, 0);
  /* One too new. */
  ret = hs_desc_is_supported_version(HS_DESC_SUPPORTED_FORMAT_VERSION_MAX + 1);
  tt_int_op(ret, OP_EQ, 0);
  /* Valid version. */
  ret = hs_desc_is_supported_version(3);
  tt_int_op(ret, OP_EQ, 1);

 done:
  ;
}

static void
test_encrypted_data_len(void *arg)
{
  int ret;
  size_t value;

  (void) arg;

  /* No length, error. */
  ret = encrypted_data_length_is_valid(0);
  tt_int_op(ret, OP_EQ, 0);
  /* Not a multiple of our encryption algorithm (thus no padding). It's
   * suppose to be aligned on HS_DESC_PLAINTEXT_PADDING_MULTIPLE. */
  value = HS_DESC_PLAINTEXT_PADDING_MULTIPLE * 10 - 1;
  ret = encrypted_data_length_is_valid(value);
  tt_int_op(ret, OP_EQ, 0);
  /* Valid value. */
  value = HS_DESC_PADDED_PLAINTEXT_MAX_LEN + HS_DESC_ENCRYPTED_SALT_LEN +
          DIGEST256_LEN;
  ret = encrypted_data_length_is_valid(value);
  tt_int_op(ret, OP_EQ, 1);

  /* XXX: Test maximum possible size. */

 done:
  ;
}

static void
test_decode_intro_point(void *arg)
{
  int ret;
  char *encoded_ip = NULL;
  size_t len_out;
  hs_desc_intro_point_t *ip = NULL;
  ed25519_keypair_t signing_kp;
  hs_descriptor_t *desc = NULL;

  (void) arg;

  /* The following certificate expires in 2036. After that, one of the test
   * will fail because of the expiry time. */

  /* Seperate pieces of a valid encoded introduction point. */
  const char *intro_point =
    "introduction-point AQIUMDI5OUYyNjhGQ0E5RDU1Q0QxNTc=";
  const char *auth_key =
    "auth-key\n"
    "-----BEGIN ED25519 CERT-----\n"
    "AQkACOhAAQW8ltYZMIWpyrfyE/b4Iyi8CNybCwYs6ADk7XfBaxsFAQAgBAD3/BE4\n"
    "XojGE/N2bW/wgnS9r2qlrkydGyuCKIGayYx3haZ39LD4ZTmSMRxwmplMAqzG/XNP\n"
    "0Kkpg4p2/VnLFJRdU1SMFo1lgQ4P0bqw7Tgx200fulZ4KUM5z5V7m+a/mgY=\n"
    "-----END ED25519 CERT-----";
  const char *enc_key =
    "enc-key ntor bpZKLsuhxP6woDQ3yVyjm5gUKSk7RjfAijT2qrzbQk0=";
  const char *enc_key_legacy =
    "enc-key legacy\n"
    "-----BEGIN RSA PUBLIC KEY-----\n"
    "MIGJAoGBAO4bATcW8kW4h6RQQAKEgg+aXCpF4JwbcO6vGZtzXTDB+HdPVQzwqkbh\n"
    "XzFM6VGArhYw4m31wcP1Z7IwULir7UMnAFd7Zi62aYfU6l+Y1yAoZ1wzu1XBaAMK\n"
    "ejpwQinW9nzJn7c2f69fVke3pkhxpNdUZ+vplSA/l9iY+y+v+415AgMBAAE=\n"
    "-----END RSA PUBLIC KEY-----";
  const char *enc_key_cert =
    "enc-key-certification\n"
    "-----BEGIN ED25519 CERT-----\n"
    "AQsACOhZAUpNvCZ1aJaaR49lS6MCdsVkhVGVrRqoj0Y2T4SzroAtAQAgBABFOcGg\n"
    "lbTt1DF5nKTE/gU3Fr8ZtlCIOhu1A+F5LM7fqCUupfesg0KTHwyIZOYQbJuM5/he\n"
    "/jDNyLy9woPJdjkxywaY2RPUxGjLYtMQV0E8PUxWyICV+7y52fTCYaKpYQw=\n"
    "-----END ED25519 CERT-----";
  const char *enc_key_cert_legacy =
    "enc-key-certification\n"
    "-----BEGIN CROSSCERT-----\n"
    "Sk28JnVolppHj2VLowJ2xWSFUZWtGqiPRjZPhLOugC0ACOhZgFPA5egeRDUXMM1U\n"
    "Fn3c7Je0gJS6mVma5FzwlgwggeriF13UZcaT71vEAN/ZJXbxOfQVGMZ0rXuFpjUq\n"
    "C8CvqmZIwEUaPE1nDFtmnTcucvNS1YQl9nsjH3ejbxc+4yqps/cXh46FmXsm5yz7\n"
    "NZjBM9U1fbJhlNtOvrkf70K8bLk6\n"
    "-----END CROSSCERT-----";

  (void) enc_key_legacy;
  (void) enc_key_cert_legacy;

  /* Start by testing the "decode all intro points" function. */
  {
    char *line;
    ret = ed25519_keypair_generate(&signing_kp, 0);
    tt_int_op(ret, ==, 0);
    desc = helper_build_hs_desc(0, &signing_kp.pubkey);
    tt_assert(desc);
    /* Only try to decode an incomplete introduction point section. */
    tor_asprintf(&line, "\n%s", intro_point);
    ret = decode_intro_points(desc, &desc->encrypted_data, line);
    tor_free(line);
    tt_int_op(ret, ==, -1);

    /* Decode one complete intro point. */
    smartlist_t *lines = smartlist_new();
    smartlist_add(lines, (char *) intro_point);
    smartlist_add(lines, (char *) auth_key);
    smartlist_add(lines, (char *) enc_key);
    smartlist_add(lines, (char *) enc_key_cert);
    encoded_ip = smartlist_join_strings(lines, "\n", 0, &len_out);
    tt_assert(encoded_ip);
    tor_asprintf(&line, "\n%s", encoded_ip);
    tor_free(encoded_ip);
    ret = decode_intro_points(desc, &desc->encrypted_data, line);
    tor_free(line);
    smartlist_free(lines);
    tt_int_op(ret, ==, 0);
  }

  /* Try to decode a junk string. */
  {
    hs_descriptor_free(desc);
    desc = NULL;
    ret = ed25519_keypair_generate(&signing_kp, 0);
    tt_int_op(ret, ==, 0);
    desc = helper_build_hs_desc(0, &signing_kp.pubkey);
    const char *junk = "this is not a descriptor";
    ip = decode_introduction_point(desc, junk);
    tt_assert(!ip);
    desc_intro_point_free(ip);
    ip = NULL;
  }

  /* Invalid link specifiers. */
  {
    smartlist_t *lines = smartlist_new();
    const char *bad_line = "introduction-point blah";
    smartlist_add(lines, (char *) bad_line);
    smartlist_add(lines, (char *) auth_key);
    smartlist_add(lines, (char *) enc_key);
    smartlist_add(lines, (char *) enc_key_cert);
    encoded_ip = smartlist_join_strings(lines, "\n", 0, &len_out);
    tt_assert(encoded_ip);
    ip = decode_introduction_point(desc, encoded_ip);
    tt_assert(!ip);
    tor_free(encoded_ip);
    smartlist_free(lines);
    desc_intro_point_free(ip);
    ip = NULL;
  }

  /* Invalid auth key type. */
  {
    smartlist_t *lines = smartlist_new();
    /* Try to put a valid object that our tokenize function will be able to
     * parse but that has nothing to do with the auth_key. */
    const char *bad_line =
      "auth-key\n"
      "-----BEGIN UNICORN CERT-----\n"
      "MIGJAoGBAO4bATcW8kW4h6RQQAKEgg+aXCpF4JwbcO6vGZtzXTDB+HdPVQzwqkbh\n"
      "XzFM6VGArhYw4m31wcP1Z7IwULir7UMnAFd7Zi62aYfU6l+Y1yAoZ1wzu1XBaAMK\n"
      "ejpwQinW9nzJn7c2f69fVke3pkhxpNdUZ+vplSA/l9iY+y+v+415AgMBAAE=\n"
      "-----END UNICORN CERT-----";
    /* Build intro point text. */
    smartlist_add(lines, (char *) intro_point);
    smartlist_add(lines, (char *) bad_line);
    smartlist_add(lines, (char *) enc_key);
    smartlist_add(lines, (char *) enc_key_cert);
    encoded_ip = smartlist_join_strings(lines, "\n", 0, &len_out);
    tt_assert(encoded_ip);
    ip = decode_introduction_point(desc, encoded_ip);
    tt_assert(!ip);
    tor_free(encoded_ip);
    smartlist_free(lines);
  }

  /* Invalid enc-key. */
  {
    smartlist_t *lines = smartlist_new();
    const char *bad_line =
      "enc-key unicorn bpZKLsuhxP6woDQ3yVyjm5gUKSk7RjfAijT2qrzbQk0=";
    /* Build intro point text. */
    smartlist_add(lines, (char *) intro_point);
    smartlist_add(lines, (char *) auth_key);
    smartlist_add(lines, (char *) bad_line);
    smartlist_add(lines, (char *) enc_key_cert);
    encoded_ip = smartlist_join_strings(lines, "\n", 0, &len_out);
    tt_assert(encoded_ip);
    ip = decode_introduction_point(desc, encoded_ip);
    tt_assert(!ip);
    tor_free(encoded_ip);
    smartlist_free(lines);
  }

  /* Invalid enc-key object. */
  {
    smartlist_t *lines = smartlist_new();
    const char *bad_line = "enc-key ntor";
    /* Build intro point text. */
    smartlist_add(lines, (char *) intro_point);
    smartlist_add(lines, (char *) auth_key);
    smartlist_add(lines, (char *) bad_line);
    smartlist_add(lines, (char *) enc_key_cert);
    encoded_ip = smartlist_join_strings(lines, "\n", 0, &len_out);
    tt_assert(encoded_ip);
    ip = decode_introduction_point(desc, encoded_ip);
    tt_assert(!ip);
    tor_free(encoded_ip);
    smartlist_free(lines);
  }

  /* Invalid enc-key base64 curv25519 key. */
  {
    smartlist_t *lines = smartlist_new();
    const char *bad_line = "enc-key ntor blah===";
    /* Build intro point text. */
    smartlist_add(lines, (char *) intro_point);
    smartlist_add(lines, (char *) auth_key);
    smartlist_add(lines, (char *) bad_line);
    smartlist_add(lines, (char *) enc_key_cert);
    encoded_ip = smartlist_join_strings(lines, "\n", 0, &len_out);
    tt_assert(encoded_ip);
    ip = decode_introduction_point(desc, encoded_ip);
    tt_assert(!ip);
    tor_free(encoded_ip);
    smartlist_free(lines);
  }

  /* Invalid enc-key invalid legacy. */
  {
    smartlist_t *lines = smartlist_new();
    const char *bad_line = "enc-key legacy blah===";
    /* Build intro point text. */
    smartlist_add(lines, (char *) intro_point);
    smartlist_add(lines, (char *) auth_key);
    smartlist_add(lines, (char *) bad_line);
    smartlist_add(lines, (char *) enc_key_cert);
    encoded_ip = smartlist_join_strings(lines, "\n", 0, &len_out);
    tt_assert(encoded_ip);
    ip = decode_introduction_point(desc, encoded_ip);
    tt_assert(!ip);
    tor_free(encoded_ip);
    smartlist_free(lines);
  }

  /* Valid object. */
  {
    smartlist_t *lines = smartlist_new();
    /* Build intro point text. */
    smartlist_add(lines, (char *) intro_point);
    smartlist_add(lines, (char *) auth_key);
    smartlist_add(lines, (char *) enc_key);
    smartlist_add(lines, (char *) enc_key_cert);
    encoded_ip = smartlist_join_strings(lines, "\n", 0, &len_out);
    tt_assert(encoded_ip);
    ip = decode_introduction_point(desc, encoded_ip);
    tt_assert(ip);
    tor_free(encoded_ip);
    smartlist_free(lines);
  }

 done:
  hs_descriptor_free(desc);
  desc_intro_point_free(ip);
}

static void
test_decode_plaintext(void *arg)
{
  int ret;
  hs_desc_plaintext_data_t desc_plaintext;
  const char *bad_value = "unicorn";

  (void) arg;

#define template \
    "hs-descriptor %s\n" \
    "descriptor-lifetime %s\n" \
    "descriptor-signing-key-cert\n" \
    "-----BEGIN ED25519 CERT-----\n" \
    "AQgABjvPAQaG3g+dc6oV/oJV4ODAtkvx56uBnPtBT9mYVuHVOhn7AQAgBABUg3mQ\n" \
    "myBr4bu5LCr53wUEbW2EXui01CbUgU7pfo9LvJG3AcXRojj6HlfsUs9BkzYzYdjF\n" \
    "A69Apikgu0ewHYkFFASt7Il+gB3w6J8YstQJZT7dtbtl+doM7ug8B68Qdg8=\n" \
    "-----END ED25519 CERT-----\n" \
    "revision-counter %s\n" \
    "encrypted\n" \
    "-----BEGIN %s-----\n" \
    "UNICORN\n" \
    "-----END MESSAGE-----\n" \
    "signature m20WJH5agqvwhq7QeuEZ1mYyPWQDO+eJOZUjLhAiKu8DbL17DsDfJE6kXbWy" \
    "HimbNj2we0enV3cCOOAsmPOaAw\n"

  /* Invalid version. */
  {
    char *plaintext;
    tor_asprintf(&plaintext, template, bad_value, "180", "42", "MESSAGE");
    ret = hs_desc_decode_plaintext(plaintext, &desc_plaintext);
    tor_free(plaintext);
    tt_int_op(ret, OP_EQ, -1);
  }

  /* Missing fields. */
  {
    const char *plaintext = "hs-descriptor 3\n";
    ret = hs_desc_decode_plaintext(plaintext, &desc_plaintext);
    tt_int_op(ret, OP_EQ, -1);
  }

  /* Max length. */
  {
    size_t big = 64000;
    /* Must always be bigger than HS_DESC_MAX_LEN. */
    tt_int_op(HS_DESC_MAX_LEN, <, big);
    char *plaintext = tor_malloc_zero(big);
    memset(plaintext, 'a', big);
    plaintext[big - 1] = '\0';
    ret = hs_desc_decode_plaintext(plaintext, &desc_plaintext);
    tor_free(plaintext);
    tt_int_op(ret, OP_EQ, -1);
  }

  /* Bad lifetime value. */
  {
    char *plaintext;
    tor_asprintf(&plaintext, template, "3", bad_value, "42", "MESSAGE");
    ret = hs_desc_decode_plaintext(plaintext, &desc_plaintext);
    tor_free(plaintext);
    tt_int_op(ret, OP_EQ, -1);
  }

  /* Huge lifetime value. */
  {
    char *plaintext;
    tor_asprintf(&plaintext, template, "3", "7181615", "42", "MESSAGE");
    ret = hs_desc_decode_plaintext(plaintext, &desc_plaintext);
    tor_free(plaintext);
    tt_int_op(ret, OP_EQ, -1);
  }

  /* Invalid encrypted section. */
  {
    char *plaintext;
    tor_asprintf(&plaintext, template, "3", "180", "42", bad_value);
    ret = hs_desc_decode_plaintext(plaintext, &desc_plaintext);
    tor_free(plaintext);
    tt_int_op(ret, OP_EQ, -1);
  }

  /* Invalid revision counter. */
  {
    char *plaintext;
    tor_asprintf(&plaintext, template, "3", "180", bad_value, "MESSAGE");
    ret = hs_desc_decode_plaintext(plaintext, &desc_plaintext);
    tor_free(plaintext);
    tt_int_op(ret, OP_EQ, -1);
  }

 done:
  ;
}

static void
test_validate_cert(void *arg)
{
  int ret;
  time_t now = time(NULL);
  ed25519_keypair_t kp;
  tor_cert_t *cert = NULL;

  (void) arg;

  ret = ed25519_keypair_generate(&kp, 0);
  tt_int_op(ret, ==, 0);

  /* Cert of type CERT_TYPE_AUTH_HS_IP_KEY. */
  cert = tor_cert_create(&kp, CERT_TYPE_AUTH_HS_IP_KEY,
                                     &kp.pubkey, now, 3600,
                                     CERT_FLAG_INCLUDE_SIGNING_KEY);
  tt_assert(cert);
  /* Test with empty certificate. */
  ret = cert_is_valid(NULL, CERT_TYPE_AUTH_HS_IP_KEY, "unicorn");
  tt_int_op(ret, OP_EQ, 0);
  /* Test with a bad type. */
  ret = cert_is_valid(cert, CERT_TYPE_SIGNING_HS_DESC, "unicorn");
  tt_int_op(ret, OP_EQ, 0);
  /* Normal validation. */
  ret = cert_is_valid(cert, CERT_TYPE_AUTH_HS_IP_KEY, "unicorn");
  tt_int_op(ret, OP_EQ, 1);
  /* Break signing key so signature verification will fails. */
  memset(&cert->signing_key, 0, sizeof(cert->signing_key));
  ret = cert_is_valid(cert, CERT_TYPE_AUTH_HS_IP_KEY, "unicorn");
  tt_int_op(ret, OP_EQ, 0);
  tor_cert_free(cert);

  /* Try a cert without including the signing key. */
  cert = tor_cert_create(&kp, CERT_TYPE_AUTH_HS_IP_KEY, &kp.pubkey, now,
                         3600, 0);
  tt_assert(cert);
  /* Test with a bad type. */
  ret = cert_is_valid(cert, CERT_TYPE_AUTH_HS_IP_KEY, "unicorn");
  tt_int_op(ret, OP_EQ, 0);

 done:
  tor_cert_free(cert);
}

static void
test_desc_signature(void *arg)
{
  int ret;
  char *data = NULL, *desc = NULL;
  char sig_b64[ED25519_SIG_BASE64_LEN + 1];
  ed25519_keypair_t kp;
  ed25519_signature_t sig;

  (void) arg;

  ed25519_keypair_generate(&kp, 0);
  /* Setup a phoony descriptor but with a valid signature token that is the
   * signature is verifiable. */
  tor_asprintf(&data, "This is a signed descriptor\n");
  ret = ed25519_sign_prefixed(&sig, (const uint8_t *) data, strlen(data),
                              "Tor onion service descriptor sig v3", &kp);
  tt_int_op(ret, ==, 0);
  ret = ed25519_signature_to_base64(sig_b64, &sig);
  tt_int_op(ret, ==, 0);
  /* Build the descriptor that should be valid. */
  tor_asprintf(&desc, "%ssignature %s\n", data, sig_b64);
  ret = desc_sig_is_valid(sig_b64, &kp.pubkey, desc, strlen(desc));
  tt_int_op(ret, ==, 1);
  /* Junk signature. */
  ret = desc_sig_is_valid("JUNK", &kp.pubkey, desc, strlen(desc));
  tt_int_op(ret, ==, 0);

 done:
  tor_free(desc);
  tor_free(data);
}

struct testcase_t hs_descriptor[] = {
  /* Encoding tests. */
  { "cert_encoding", test_cert_encoding, TT_FORK,
    NULL, NULL },
  { "link_specifier", test_link_specifier, TT_FORK,
    NULL, NULL },
  { "encode_descriptor", test_encode_descriptor, TT_FORK,
    NULL, NULL },
  { "descriptor_padding", test_descriptor_padding, TT_FORK,
    NULL, NULL },

  /* Decoding tests. */
  { "decode_descriptor", test_decode_descriptor, TT_FORK,
    NULL, NULL },
  { "encrypted_data_len", test_encrypted_data_len, TT_FORK,
    NULL, NULL },
  { "decode_intro_point", test_decode_intro_point, TT_FORK,
    NULL, NULL },
  { "decode_plaintext", test_decode_plaintext, TT_FORK,
    NULL, NULL },

  /* Misc. */
  { "version", test_supported_version, TT_FORK,
    NULL, NULL },
  { "validate_cert", test_validate_cert, TT_FORK,
    NULL, NULL },
  { "desc_signature", test_desc_signature, TT_FORK,
    NULL, NULL },

  END_OF_TESTCASES
};

