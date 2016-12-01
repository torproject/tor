/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_descriptor.c
 * \brief Handle hidden service descriptor encoding/decoding.
 **/

/* For unit tests.*/
#define HS_DESCRIPTOR_PRIVATE

#include "hs_descriptor.h"

#include "or.h"
#include "ed25519_cert.h" /* Trunnel interface. */
#include "parsecommon.h"
#include "rendcache.h"
#include "torcert.h" /* tor_cert_encode_ed22519() */

/* Constant string value used for the descriptor format. */
#define str_hs_desc "hs-descriptor"
#define str_desc_cert "descriptor-signing-key-cert"
#define str_rev_counter "revision-counter"
#define str_encrypted "encrypted"
#define str_signature "signature"
#define str_lifetime "descriptor-lifetime"
/* Constant string value for the encrypted part of the descriptor. */
#define str_create2_formats "create2-formats"
#define str_auth_required "authentication-required"
#define str_single_onion "single-onion-service"
#define str_intro_point "introduction-point"
#define str_ip_auth_key "auth-key"
#define str_ip_enc_key "enc-key"
#define str_ip_enc_key_cert "enc-key-certification"
#define str_intro_point_start "\n" str_intro_point " "
/* Constant string value for the construction to encrypt the encrypted data
 * section. */
#define str_enc_hsdir_data "hsdir-encrypted-data"
/* Prefix required to compute/verify HS desc signatures */
#define str_desc_sig_prefix "Tor onion service descriptor sig v3"

/* Authentication supported types. */
static const struct {
  hs_desc_auth_type_t type;
  const char *identifier;
} auth_types[] = {
  { HS_DESC_AUTH_PASSWORD, "password" },
  { HS_DESC_AUTH_ED25519, "ed25519" },
  /* Indicate end of array. */
  { 0, NULL }
};

/* Descriptor ruleset. */
static token_rule_t hs_desc_v3_token_table[] = {
  T1_START(str_hs_desc, R_HS_DESCRIPTOR, EQ(1), NO_OBJ),
  T1(str_lifetime, R3_DESC_LIFETIME, EQ(1), NO_OBJ),
  T1(str_desc_cert, R3_DESC_SIGNING_CERT, NO_ARGS, NEED_OBJ),
  T1(str_rev_counter, R3_REVISION_COUNTER, EQ(1), NO_OBJ),
  T1(str_encrypted, R3_ENCRYPTED, NO_ARGS, NEED_OBJ),
  T1_END(str_signature, R3_SIGNATURE, EQ(1), NO_OBJ),
  END_OF_TABLE
};

/* Descriptor ruleset for the encrypted section. */
static token_rule_t hs_desc_encrypted_v3_token_table[] = {
  T1_START(str_create2_formats, R3_CREATE2_FORMATS, CONCAT_ARGS, NO_OBJ),
  T01(str_auth_required, R3_AUTHENTICATION_REQUIRED, ARGS, NO_OBJ),
  T01(str_single_onion, R3_SINGLE_ONION_SERVICE, ARGS, NO_OBJ),
  END_OF_TABLE
};

/* Descriptor ruleset for the introduction points section. */
static token_rule_t hs_desc_intro_point_v3_token_table[] = {
  T1_START(str_intro_point, R3_INTRODUCTION_POINT, EQ(1), NO_OBJ),
  T1(str_ip_auth_key, R3_INTRO_AUTH_KEY, NO_ARGS, NEED_OBJ),
  T1(str_ip_enc_key, R3_INTRO_ENC_KEY, ARGS, OBJ_OK),
  T1_END(str_ip_enc_key_cert, R3_INTRO_ENC_KEY_CERTIFICATION,
         NO_ARGS, NEED_OBJ),
  END_OF_TABLE
};

/* Free a descriptor intro point object. */
STATIC void
desc_intro_point_free(hs_desc_intro_point_t *ip)
{
  if (!ip) {
    return;
  }
  if (ip->link_specifiers) {
    SMARTLIST_FOREACH(ip->link_specifiers, hs_desc_link_specifier_t *,
                      ls, tor_free(ls));
    smartlist_free(ip->link_specifiers);
  }
  tor_cert_free(ip->auth_key_cert);
  if (ip->enc_key_type == HS_DESC_KEY_TYPE_LEGACY) {
    crypto_pk_free(ip->enc_key.legacy);
  }
  tor_free(ip);
}

/* Free the content of the plaintext section of a descriptor. */
static void
desc_plaintext_data_free_contents(hs_desc_plaintext_data_t *desc)
{
  if (!desc) {
    return;
  }

  if (desc->encrypted_blob) {
    tor_free(desc->encrypted_blob);
  }
  tor_cert_free(desc->signing_key_cert);

  memwipe(desc, 0, sizeof(*desc));
}

/* Free the content of the encrypted section of a descriptor. */
static void
desc_encrypted_data_free_contents(hs_desc_encrypted_data_t *desc)
{
  if (!desc) {
    return;
  }

  if (desc->auth_types) {
    SMARTLIST_FOREACH(desc->auth_types, char *, a, tor_free(a));
    smartlist_free(desc->auth_types);
  }
  if (desc->intro_points) {
    SMARTLIST_FOREACH(desc->intro_points, hs_desc_intro_point_t *, ip,
                      desc_intro_point_free(ip));
    smartlist_free(desc->intro_points);
  }
  memwipe(desc, 0, sizeof(*desc));
}

/* === ENCODING === */

/* Encode the given link specifier objects into a newly allocated string.
 * This can't fail so caller can always assume a valid string being
 * returned. */
STATIC char *
encode_link_specifiers(const smartlist_t *specs)
{
  char *encoded_b64 = NULL;
  link_specifier_list_t *lslist = link_specifier_list_new();

  tor_assert(specs);
  /* No link specifiers is a code flow error, can't happen. */
  tor_assert(smartlist_len(specs) > 0);
  tor_assert(smartlist_len(specs) <= UINT8_MAX);

  link_specifier_list_set_n_spec(lslist, smartlist_len(specs));

  SMARTLIST_FOREACH_BEGIN(specs, const hs_desc_link_specifier_t *,
                          spec) {
    link_specifier_t *ls = link_specifier_new();
    link_specifier_set_ls_type(ls, spec->type);

    switch (spec->type) {
    case LS_IPV4:
      link_specifier_set_un_ipv4_addr(ls,
                                      tor_addr_to_ipv4h(&spec->u.ap.addr));
      link_specifier_set_un_ipv4_port(ls, spec->u.ap.port);
      /* Four bytes IPv4 and two bytes port. */
      link_specifier_set_ls_len(ls, sizeof(spec->u.ap.addr.addr.in_addr) +
                                    sizeof(spec->u.ap.port));
      break;
    case LS_IPV6:
    {
      size_t addr_len = link_specifier_getlen_un_ipv6_addr(ls);
      const uint8_t *in6_addr = tor_addr_to_in6_addr8(&spec->u.ap.addr);
      uint8_t *ipv6_array = link_specifier_getarray_un_ipv6_addr(ls);
      memcpy(ipv6_array, in6_addr, addr_len);
      link_specifier_set_un_ipv6_port(ls, spec->u.ap.port);
      /* Sixteen bytes IPv6 and two bytes port. */
      link_specifier_set_ls_len(ls, addr_len + sizeof(spec->u.ap.port));
      break;
    }
    case LS_LEGACY_ID:
    {
      size_t legacy_id_len = link_specifier_getlen_un_legacy_id(ls);
      uint8_t *legacy_id_array = link_specifier_getarray_un_legacy_id(ls);
      memcpy(legacy_id_array, spec->u.legacy_id, legacy_id_len);
      link_specifier_set_ls_len(ls, legacy_id_len);
      break;
    }
    default:
      tor_assert(0);
    }

    link_specifier_list_add_spec(lslist, ls);
  } SMARTLIST_FOREACH_END(spec);

  {
    uint8_t *encoded;
    ssize_t encoded_len, encoded_b64_len, ret;

    encoded_len = link_specifier_list_encoded_len(lslist);
    tor_assert(encoded_len > 0);
    encoded = tor_malloc_zero(encoded_len);
    ret = link_specifier_list_encode(encoded, encoded_len, lslist);
    tor_assert(ret == encoded_len);

    /* Base64 encode our binary format. Add extra NUL byte for the base64
     * encoded value. */
    encoded_b64_len = base64_encode_size(encoded_len, 0) + 1;
    encoded_b64 = tor_malloc_zero(encoded_b64_len);
    ret = base64_encode(encoded_b64, encoded_b64_len, (const char *) encoded,
                        encoded_len, 0);
    tor_assert(ret == (encoded_b64_len - 1));
    tor_free(encoded);
  }

  link_specifier_list_free(lslist);
  return encoded_b64;
}

/* Encode an introduction point encryption key and return a newly allocated
 * string with it. On failure, return NULL. */
static char *
encode_enc_key(const ed25519_keypair_t *sig_key,
               const hs_desc_intro_point_t *ip)
{
  char *encoded = NULL;
  time_t now = time(NULL);

  tor_assert(sig_key);
  tor_assert(ip);

  switch (ip->enc_key_type) {
  case HS_DESC_KEY_TYPE_LEGACY:
  {
    char *key_str, b64_cert[256];
    ssize_t cert_len;
    size_t key_str_len;
    uint8_t *cert_data = NULL;

    /* Create cross certification cert. */
    cert_len = tor_make_rsa_ed25519_crosscert(&sig_key->pubkey,
                                              ip->enc_key.legacy,
                                              now + HS_DESC_CERT_LIFETIME,
                                              &cert_data);
    if (cert_len < 0) {
      log_warn(LD_REND, "Unable to create legacy crosscert.");
      goto err;
    }
    /* Encode cross cert. */
    if (base64_encode(b64_cert, sizeof(b64_cert), (const char *) cert_data,
                      cert_len, BASE64_ENCODE_MULTILINE) < 0) {
      tor_free(cert_data);
      log_warn(LD_REND, "Unable to encode legacy crosscert.");
      goto err;
    }
    tor_free(cert_data);
    /* Convert the encryption key to a string. */
    if (crypto_pk_write_public_key_to_string(ip->enc_key.legacy, &key_str,
                                             &key_str_len) < 0) {
      log_warn(LD_REND, "Unable to encode legacy encryption key.");
      goto err;
    }
    tor_asprintf(&encoded,
                 "%s legacy\n%s"  /* Newline is added by the call above. */
                 "%s\n"
                 "-----BEGIN CROSSCERT-----\n"
                 "%s"
                 "-----END CROSSCERT-----",
                 str_ip_enc_key, key_str,
                 str_ip_enc_key_cert, b64_cert);
    tor_free(key_str);
    break;
  }
  case HS_DESC_KEY_TYPE_CURVE25519:
  {
    int signbit, ret;
    char *encoded_cert, key_fp_b64[CURVE25519_BASE64_PADDED_LEN + 1];
    ed25519_keypair_t curve_kp;

    if (ed25519_keypair_from_curve25519_keypair(&curve_kp, &signbit,
                                                &ip->enc_key.curve25519)) {
      goto err;
    }
    tor_cert_t *cross_cert = tor_cert_create(&curve_kp,
                                             CERT_TYPE_CROSS_HS_IP_KEYS,
                                             &sig_key->pubkey, now,
                                             HS_DESC_CERT_LIFETIME,
                                             CERT_FLAG_INCLUDE_SIGNING_KEY);
    memwipe(&curve_kp, 0, sizeof(curve_kp));
    if (!cross_cert) {
      goto err;
    }
    ret = tor_cert_encode_ed22519(cross_cert, &encoded_cert);
    tor_cert_free(cross_cert);
    if (ret) {
      goto err;
    }
    if (curve25519_public_to_base64(key_fp_b64,
                                    &ip->enc_key.curve25519.pubkey) < 0) {
      tor_free(encoded_cert);
      goto err;
    }
    tor_asprintf(&encoded,
                 "%s ntor %s\n"
                 "%s\n%s",
                 str_ip_enc_key, key_fp_b64,
                 str_ip_enc_key_cert, encoded_cert);
    tor_free(encoded_cert);
    break;
  }
  default:
    tor_assert(0);
  }

 err:
  return encoded;
}

/* Encode an introduction point object and return a newly allocated string
 * with it. On failure, return NULL. */
static char *
encode_intro_point(const ed25519_keypair_t *sig_key,
                   const hs_desc_intro_point_t *ip)
{
  char *encoded_ip = NULL;
  smartlist_t *lines = smartlist_new();

  tor_assert(ip);
  tor_assert(sig_key);

  /* Encode link specifier. */
  {
    char *ls_str = encode_link_specifiers(ip->link_specifiers);
    smartlist_add_asprintf(lines, "%s %s", str_intro_point, ls_str);
    tor_free(ls_str);
  }

  /* Authentication key encoding. */
  {
    char *encoded_cert;
    if (tor_cert_encode_ed22519(ip->auth_key_cert, &encoded_cert) < 0) {
      goto err;
    }
    smartlist_add_asprintf(lines, "%s\n%s", str_ip_auth_key, encoded_cert);
    tor_free(encoded_cert);
  }

  /* Encryption key encoding. */
  {
    char *encoded_enc_key = encode_enc_key(sig_key, ip);
    if (encoded_enc_key == NULL) {
      goto err;
    }
    smartlist_add_asprintf(lines, "%s", encoded_enc_key);
    tor_free(encoded_enc_key);
  }

  /* Join them all in one blob of text. */
  encoded_ip = smartlist_join_strings(lines, "\n", 1, NULL);

 err:
  SMARTLIST_FOREACH(lines, char *, l, tor_free(l));
  smartlist_free(lines);
  return encoded_ip;
}

/* Using a given decriptor object, build the secret input needed for the
 * KDF and put it in the dst pointer which is an already allocated buffer
 * of size dstlen. */
static void
build_secret_input(const hs_descriptor_t *desc, uint8_t *dst, size_t dstlen)
{
  size_t offset = 0;

  tor_assert(desc);
  tor_assert(dst);
  tor_assert(HS_DESC_ENCRYPTED_SECRET_INPUT_LEN <= dstlen);

  /* XXX use the destination length as the memcpy length */
  /* Copy blinded public key. */
  memcpy(dst, desc->plaintext_data.blinded_kp.pubkey.pubkey,
         sizeof(desc->plaintext_data.blinded_kp.pubkey.pubkey));
  offset += sizeof(desc->plaintext_data.blinded_kp.pubkey.pubkey);
  /* Copy subcredential. */
  memcpy(dst + offset, desc->subcredential, sizeof(desc->subcredential));
  offset += sizeof(desc->subcredential);
  /* Copy revision counter value. */
  set_uint64(dst + offset, tor_ntohll(desc->plaintext_data.revision_counter));
  offset += sizeof(uint64_t);
  tor_assert(HS_DESC_ENCRYPTED_SECRET_INPUT_LEN == offset);
}

/* Do the KDF construction and put the resulting data in key_out which is of
 * key_out_len length. It uses SHAKE-256 as specified in the spec. */
static void
build_kdf_key(const hs_descriptor_t *desc,
              const uint8_t *salt, size_t salt_len,
              uint8_t *key_out, size_t key_out_len)
{
  uint8_t secret_input[HS_DESC_ENCRYPTED_SECRET_INPUT_LEN];
  crypto_xof_t *xof;

  tor_assert(desc);
  tor_assert(salt);
  tor_assert(key_out);

  /* Build the secret input for the KDF computation. */
  build_secret_input(desc, secret_input, sizeof(secret_input));

  xof = crypto_xof_new();
  /* Feed our KDF. [SHAKE it like a polaroid picture --Yawning]. */
  crypto_xof_add_bytes(xof, secret_input, sizeof(secret_input));
  crypto_xof_add_bytes(xof, salt, salt_len);
  crypto_xof_add_bytes(xof, (const uint8_t *) str_enc_hsdir_data,
                       strlen(str_enc_hsdir_data));
  /* Eat from our KDF. */
  crypto_xof_squeeze_bytes(xof, key_out, key_out_len);
  crypto_xof_free(xof);
  memwipe(secret_input,  0, sizeof(secret_input));
}

/* Using the given descriptor and salt, run it through our KDF function and
 * then extract a secret key in key_out, the IV in iv_out and MAC in mac_out.
 * This function can't fail. */
static void
build_secret_key_iv_mac(const hs_descriptor_t *desc,
                        const uint8_t *salt, size_t salt_len,
                        uint8_t *key_out, size_t key_len,
                        uint8_t *iv_out, size_t iv_len,
                        uint8_t *mac_out, size_t mac_len)
{
  size_t offset = 0;
  uint8_t kdf_key[HS_DESC_ENCRYPTED_KDF_OUTPUT_LEN];

  tor_assert(desc);
  tor_assert(salt);
  tor_assert(key_out);
  tor_assert(iv_out);
  tor_assert(mac_out);

  build_kdf_key(desc, salt, salt_len, kdf_key, sizeof(kdf_key));
  /* Copy the bytes we need for both the secret key and IV. */
  memcpy(key_out, kdf_key, key_len);
  offset += key_len;
  memcpy(iv_out, kdf_key + offset, iv_len);
  offset += iv_len;
  memcpy(mac_out, kdf_key + offset, mac_len);
  /* Extra precaution to make sure we are not out of bound. */
  tor_assert((offset + mac_len) == sizeof(kdf_key));
  memwipe(kdf_key, 0, sizeof(kdf_key));
}

/* Using a key, salt and encrypted payload, build a MAC and put it in mac_out.
 * We use SHA3-256 for the MAC computation.
 * This function can't fail. */
static void
build_mac(const uint8_t *mac_key, size_t mac_key_len,
          const uint8_t *salt, size_t salt_len,
          const uint8_t *encrypted, size_t encrypted_len,
          uint8_t *mac_out, size_t mac_len)
{
  crypto_digest_t *digest;

  const uint64_t mac_len_netorder = tor_htonll(mac_key_len);
  const uint64_t salt_len_netorder = tor_htonll(salt_len);

  tor_assert(mac_key);
  tor_assert(salt);
  tor_assert(encrypted);
  tor_assert(mac_out);

  digest = crypto_digest256_new(DIGEST_SHA3_256);
  /* As specified in section 2.5 of proposal 224, first add the mac key
   * then add the salt first and then the encrypted section. */

  crypto_digest_add_bytes(digest, (const char *) &mac_len_netorder, 8);
  crypto_digest_add_bytes(digest, (const char *) mac_key, mac_key_len);
  crypto_digest_add_bytes(digest, (const char *) &salt_len_netorder, 8);
  crypto_digest_add_bytes(digest, (const char *) salt, salt_len);
  crypto_digest_add_bytes(digest, (const char *) encrypted, encrypted_len);
  crypto_digest_get_digest(digest, (char *) mac_out, mac_len);
  crypto_digest_free(digest);
}

/* Given a source length, return the new size including padding for the
 * plaintext encryption. */
static size_t
compute_padded_plaintext_length(size_t plaintext_len)
{
  size_t plaintext_padded_len;

  /* Make sure we won't overflow. */
  tor_assert(plaintext_len <=
             (SIZE_T_CEILING - HS_DESC_PLAINTEXT_PADDING_MULTIPLE));

  /* Get the extra length we need to add. For example, if srclen is 234 bytes,
   * this will expand to (2 * 128) == 256 thus an extra 22 bytes. */
  plaintext_padded_len = CEIL_DIV(plaintext_len,
                                  HS_DESC_PLAINTEXT_PADDING_MULTIPLE) *
                         HS_DESC_PLAINTEXT_PADDING_MULTIPLE;
  /* Can never be extra careful. Make sure we are _really_ padded. */
  tor_assert(!(plaintext_padded_len % HS_DESC_PLAINTEXT_PADDING_MULTIPLE));
  return plaintext_padded_len;
}

/* Given a buffer, pad it up to the encrypted section padding requirement. Set
 * the newly allocated string in padded_out and return the length of the
 * padded buffer. */
STATIC size_t
build_plaintext_padding(const char *plaintext, size_t plaintext_len,
                        uint8_t **padded_out)
{
  size_t padded_len;
  uint8_t *padded;

  tor_assert(plaintext);
  tor_assert(padded_out);

  /* Allocate the final length including padding. */
  padded_len = compute_padded_plaintext_length(plaintext_len);
  tor_assert(padded_len >= plaintext_len);
  padded = tor_malloc_zero(padded_len);

  memcpy(padded, plaintext, plaintext_len);
  *padded_out = padded;
  return padded_len;
}

/* Using a key, IV and plaintext data of length plaintext_len, create the
 * encrypted section by encrypting it and setting encrypted_out with the
 * data. Return size of the encrypted data buffer. */
static size_t
build_encrypted(const uint8_t *key, const uint8_t *iv, const char *plaintext,
                size_t plaintext_len, uint8_t **encrypted_out)
{
  size_t encrypted_len;
  uint8_t *padded_plaintext, *encrypted;
  crypto_cipher_t *cipher;

  tor_assert(key);
  tor_assert(iv);
  tor_assert(plaintext);
  tor_assert(encrypted_out);

  /* This creates a cipher for AES128. It can't fail. */
  cipher = crypto_cipher_new_with_iv((const char *) key, (const char *) iv);
  /* This can't fail. */
  encrypted_len = build_plaintext_padding(plaintext, plaintext_len,
                                          &padded_plaintext);
  /* Extra precautions that we have a valie padding length. */
  tor_assert(encrypted_len <= HS_DESC_PADDED_PLAINTEXT_MAX_LEN);
  tor_assert(!(encrypted_len % HS_DESC_PLAINTEXT_PADDING_MULTIPLE));
  /* We use a stream cipher so the encrypted length will be the same as the
   * plaintext padded length. */
  encrypted = tor_malloc_zero(encrypted_len);
  /* This can't fail. */
  crypto_cipher_encrypt(cipher, (char *) encrypted,
                        (const char *) padded_plaintext, encrypted_len);
  *encrypted_out = encrypted;
  /* Cleanup. */
  crypto_cipher_free(cipher);
  tor_free(padded_plaintext);
  return encrypted_len;
}

/* Encrypt the given plaintext buffer and using the descriptor to get the
 * keys. Set encrypted_out with the encrypted data and return the length of
 * it. */
static size_t
encrypt_descriptor_data(const hs_descriptor_t *desc, const char *plaintext,
             char **encrypted_out)
{
  char *final_blob;
  size_t encrypted_len, final_blob_len, offset = 0;
  uint8_t *encrypted;
  uint8_t salt[HS_DESC_ENCRYPTED_SALT_LEN];
  uint8_t secret_key[CIPHER_KEY_LEN], secret_iv[CIPHER_IV_LEN];
  uint8_t mac_key[DIGEST256_LEN], mac[DIGEST256_LEN];

  tor_assert(desc);
  tor_assert(plaintext);
  tor_assert(encrypted_out);

  /* Get our salt. The returned bytes are already hashed. */
  crypto_strongest_rand(salt, sizeof(salt));

  /* KDF construction resulting in a key from which the secret key, IV and MAC
   * key are extracted which is what we need for the encryption. */
  build_secret_key_iv_mac(desc, salt, sizeof(salt),
                          secret_key, sizeof(secret_key),
                          secret_iv, sizeof(secret_iv),
                          mac_key, sizeof(mac_key));

  /* Build the encrypted part that is do the actual encryption. */
  encrypted_len = build_encrypted(secret_key, secret_iv, plaintext,
                                  strlen(plaintext), &encrypted);
  memwipe(secret_key, 0, sizeof(secret_key));
  memwipe(secret_iv, 0, sizeof(secret_iv));
  /* This construction is specified in section 2.5 of proposal 224. */
  final_blob_len = sizeof(salt) + encrypted_len + DIGEST256_LEN;
  final_blob = tor_malloc_zero(final_blob_len);

  /* Build the MAC. */
  build_mac(mac_key, sizeof(mac_key), salt, sizeof(salt),
            encrypted, encrypted_len, mac, sizeof(mac));
  memwipe(mac_key, 0, sizeof(mac_key));

  /* The salt is the first value. */
  memcpy(final_blob, salt, sizeof(salt));
  offset = sizeof(salt);
  /* Second value is the encrypted data. */
  memcpy(final_blob + offset, encrypted, encrypted_len);
  offset += encrypted_len;
  /* Third value is the MAC. */
  memcpy(final_blob + offset, mac, sizeof(mac));
  offset += sizeof(mac);
  /* Cleanup the buffers. */
  memwipe(salt, 0, sizeof(salt));
  memwipe(encrypted, 0, encrypted_len);
  tor_free(encrypted);
  /* Extra precaution. */
  tor_assert(offset == final_blob_len);

  *encrypted_out = final_blob;
  return final_blob_len;
}

/* Take care of encoding the encrypted data section and then encrypting it
 * with the descriptor's key. A newly allocated NUL terminated string pointer
 * containing the encrypted encoded blob is put in encrypted_blob_out. Return
 * 0 on success else a negative value. */
static int
encode_encrypted_data(const hs_descriptor_t *desc,
                      char **encrypted_blob_out)
{
  int ret = -1;
  char *encoded_str, *encrypted_blob;
  smartlist_t *lines = smartlist_new();

  tor_assert(desc);
  tor_assert(encrypted_blob_out);

  /* Build the start of the section prior to the introduction points. */
  {
    if (!desc->encrypted_data.create2_ntor) {
      log_err(LD_BUG, "HS desc doesn't have recognized handshake type.");
      goto err;
    }
    smartlist_add_asprintf(lines, "%s %d\n", str_create2_formats,
                           ONION_HANDSHAKE_TYPE_NTOR);

    if (desc->encrypted_data.auth_types &&
        smartlist_len(desc->encrypted_data.auth_types)) {
      /* Put the authentication-required line. */
      char *buf = smartlist_join_strings(desc->encrypted_data.auth_types, " ",
                                         0, NULL);
      smartlist_add_asprintf(lines, "%s %s\n", str_auth_required, buf);
      tor_free(buf);
    }

    if (desc->encrypted_data.single_onion_service) {
      smartlist_add_asprintf(lines, "%s\n", str_single_onion);
    }
  }

  /* Build the introduction point(s) section. */
  SMARTLIST_FOREACH_BEGIN(desc->encrypted_data.intro_points,
                          const hs_desc_intro_point_t *, ip) {
    char *encoded_ip = encode_intro_point(&desc->plaintext_data.signing_kp,
                                          ip);
    if (encoded_ip == NULL) {
      log_err(LD_BUG, "HS desc intro point is malformed.");
      goto err;
    }
    smartlist_add(lines, encoded_ip);
  } SMARTLIST_FOREACH_END(ip);

  /* Build the entire encrypted data section into one encoded plaintext and
   * then encrypt it. */
  encoded_str = smartlist_join_strings(lines, "", 0, NULL);

  /* Encrypt the section into an encrypted blob that we'll base64 encode
   * before returning it. */
  {
    char *enc_b64;
    ssize_t enc_b64_len, ret_len, enc_len;

    enc_len = encrypt_descriptor_data(desc, encoded_str, &encrypted_blob);
    tor_free(encoded_str);
    /* Get the encoded size plus a NUL terminating byte. */
    enc_b64_len = base64_encode_size(enc_len, BASE64_ENCODE_MULTILINE) + 1;
    enc_b64 = tor_malloc_zero(enc_b64_len);
    /* Base64 the encrypted blob before returning it. */
    ret_len = base64_encode(enc_b64, enc_b64_len, encrypted_blob, enc_len,
                            BASE64_ENCODE_MULTILINE);
    /* Return length doesn't count the NUL byte. */
    tor_assert(ret_len == (enc_b64_len - 1));
    tor_free(encrypted_blob);
    *encrypted_blob_out = enc_b64;
  }
  /* Success! */
  ret = 0;

 err:
  SMARTLIST_FOREACH(lines, char *, l, tor_free(l));
  smartlist_free(lines);
  return ret;
}

/* Encode a v3 HS descriptor. Return 0 on success and set encoded_out to the
 * newly allocated string of the encoded descriptor. On error, -1 is returned
 * and encoded_out is untouched. */
static int
desc_encode_v3(const hs_descriptor_t *desc, char **encoded_out)
{
  int ret = -1;
  char *encoded_str = NULL;
  size_t encoded_len;
  smartlist_t *lines = smartlist_new();

  tor_assert(desc);
  tor_assert(encoded_out);
  tor_assert(desc->plaintext_data.version == 3);

  /* Build the non-encrypted values. */
  {
    char *encoded_cert;
    /* Encode certificate then create the first line of the descriptor. */
    if (desc->plaintext_data.signing_key_cert->cert_type
        != CERT_TYPE_SIGNING_HS_DESC) {
      log_err(LD_BUG, "HS descriptor signing key has an unexpected cert type "
              "(%d)", (int) desc->plaintext_data.signing_key_cert->cert_type);
      goto err;
    }
    if (tor_cert_encode_ed22519(desc->plaintext_data.signing_key_cert,
                    &encoded_cert) < 0) {
      /* The function will print error logs. */
      goto err;
    }
    /* Create the hs descriptor line. */
    smartlist_add_asprintf(lines, "%s %" PRIu32, str_hs_desc,
                           desc->plaintext_data.version);
    /* Add the descriptor lifetime line (in minutes). */
    smartlist_add_asprintf(lines, "%s %" PRIu32, str_lifetime,
                           desc->plaintext_data.lifetime_sec / 60);
    /* Create the descriptor certificate line. */
    smartlist_add_asprintf(lines, "%s\n%s", str_desc_cert, encoded_cert);
    tor_free(encoded_cert);
    /* Create the revision counter line. */
    smartlist_add_asprintf(lines, "%s %" PRIu64, str_rev_counter,
                           desc->plaintext_data.revision_counter);
  }

  /* Build the encrypted data section. */
  {
    char *enc_b64_blob=NULL;
    if (encode_encrypted_data(desc, &enc_b64_blob) < 0) {
      goto err;
    }
    smartlist_add_asprintf(lines,
                           "%s\n"
                           "-----BEGIN MESSAGE-----\n"
                           "%s"
                           "-----END MESSAGE-----",
                           str_encrypted, enc_b64_blob);
    tor_free(enc_b64_blob);
  }

  /* Join all lines in one string so we can generate a signature and append
   * it to the descriptor. */
  encoded_str = smartlist_join_strings(lines, "\n", 1, &encoded_len);

  /* Sign all fields of the descriptor with our short term signing key. */
  {
    ed25519_signature_t sig;
    char ed_sig_b64[ED25519_SIG_BASE64_LEN + 1];
    if (ed25519_sign_prefixed(&sig,
                              (const uint8_t *) encoded_str, encoded_len,
                              str_desc_sig_prefix,
                              &desc->plaintext_data.signing_kp) < 0) {
      log_warn(LD_BUG, "Can't sign encoded HS descriptor!");
      tor_free(encoded_str);
      goto err;
    }
    if (ed25519_signature_to_base64(ed_sig_b64, &sig) < 0) {
      log_warn(LD_BUG, "Can't base64 encode descriptor signature!");
      tor_free(encoded_str);
      goto err;
    }
    /* Create the signature line. */
    smartlist_add_asprintf(lines, "%s %s", str_signature, ed_sig_b64);
  }
  /* Free previous string that we used so compute the signature. */
  tor_free(encoded_str);
  encoded_str = smartlist_join_strings(lines, "\n", 1, NULL);
  *encoded_out = encoded_str;

  /* XXX: Trigger a control port event. */

  /* Success! */
  ret = 0;

 err:
  SMARTLIST_FOREACH(lines, char *, l, tor_free(l));
  smartlist_free(lines);
  return ret;
}

/* === DECODING === */

/* Given an encoded string of the link specifiers, return a newly allocated
 * list of decoded link specifiers. Return NULL on error. */
STATIC smartlist_t *
decode_link_specifiers(const char *encoded)
{
  int decoded_len;
  size_t encoded_len, i;
  uint8_t *decoded;
  smartlist_t *results = NULL;
  link_specifier_list_t *specs = NULL;

  tor_assert(encoded);

  encoded_len = strlen(encoded);
  decoded = tor_malloc(encoded_len);
  decoded_len = base64_decode((char *) decoded, encoded_len, encoded,
                              encoded_len);
  if (decoded_len < 0) {
    goto err;
  }

  if (link_specifier_list_parse(&specs, decoded,
                                (size_t) decoded_len) < decoded_len) {
    goto err;
  }
  tor_assert(specs);
  results = smartlist_new();

  for (i = 0; i < link_specifier_list_getlen_spec(specs); i++) {
    hs_desc_link_specifier_t *hs_spec;
    link_specifier_t *ls = link_specifier_list_get_spec(specs, i);
    tor_assert(ls);

    hs_spec = tor_malloc_zero(sizeof(*hs_spec));
    hs_spec->type = link_specifier_get_ls_type(ls);
    switch (hs_spec->type) {
    case LS_IPV4:
      tor_addr_from_ipv4h(&hs_spec->u.ap.addr,
                          link_specifier_get_un_ipv4_addr(ls));
      hs_spec->u.ap.port = link_specifier_get_un_ipv4_port(ls);
      break;
    case LS_IPV6:
      tor_addr_from_ipv6_bytes(&hs_spec->u.ap.addr, (const char *)
                               link_specifier_getarray_un_ipv6_addr(ls));
      hs_spec->u.ap.port = link_specifier_get_un_ipv6_port(ls);
      break;
    case LS_LEGACY_ID:
      /* Both are known at compile time so let's make sure they are the same
       * else we can copy memory out of bound. */
      tor_assert(link_specifier_getlen_un_legacy_id(ls) ==
                 sizeof(hs_spec->u.legacy_id));
      memcpy(hs_spec->u.legacy_id, link_specifier_getarray_un_legacy_id(ls),
             sizeof(hs_spec->u.legacy_id));
      break;
    default:
      goto err;
    }

    smartlist_add(results, hs_spec);
  }

  goto done;
 err:
  if (results) {
    SMARTLIST_FOREACH(results, hs_desc_link_specifier_t *, s, tor_free(s));
    smartlist_free(results);
    results = NULL;
  }
 done:
  link_specifier_list_free(specs);
  tor_free(decoded);
  return results;
}

/* Given a list of authentication types, decode it and put it in the encrypted
 * data section. Return 1 if we at least know one of the type or 0 if we know
 * none of them. */
static int
decode_auth_type(hs_desc_encrypted_data_t *desc, const char *list)
{
  int match = 0;

  tor_assert(desc);
  tor_assert(list);

  desc->auth_types = smartlist_new();
  smartlist_split_string(desc->auth_types, list, " ", 0, 0);

  /* Validate the types that we at least know about one. */
  SMARTLIST_FOREACH_BEGIN(desc->auth_types, const char *, auth) {
    for (int idx = 0; auth_types[idx].identifier; idx++) {
      if (!strncmp(auth, auth_types[idx].identifier,
                   strlen(auth_types[idx].identifier))) {
        match = 1;
        break;
      }
    }
  } SMARTLIST_FOREACH_END(auth);

  return match;
}

/* Parse a space-delimited list of integers representing CREATE2 formats into
 * the bitfield in hs_desc_encrypted_data_t. Ignore unrecognized values. */
static void
decode_create2_list(hs_desc_encrypted_data_t *desc, const char *list)
{
  smartlist_t *tokens;

  tor_assert(desc);
  tor_assert(list);

  tokens = smartlist_new();
  smartlist_split_string(tokens, list, " ", 0, 0);

  SMARTLIST_FOREACH_BEGIN(tokens, char *, s) {
    int ok;
    unsigned long type = tor_parse_ulong(s, 10, 1, UINT16_MAX, &ok, NULL);
    if (!ok) {
      log_warn(LD_REND, "Unparseable value %s in create2 list", escaped(s));
      continue;
    }
    switch (type) {
    case ONION_HANDSHAKE_TYPE_NTOR:
      desc->create2_ntor = 1;
      break;
    default:
      /* We deliberately ignore unsupported handshake types */
      continue;
    }
  } SMARTLIST_FOREACH_END(s);

  SMARTLIST_FOREACH(tokens, char *, s, tor_free(s));
  smartlist_free(tokens);
}

/* Given a certificate, validate the certificate for certain conditions which
 * are if the given type matches the cert's one, if the signing key is
 * included and if the that key was actually used to sign the certificate.
 *
 * Return 1 iff if all conditions pass or 0 if one of them fails. */
STATIC int
cert_is_valid(tor_cert_t *cert, uint8_t type, const char *log_obj_type)
{
  tor_assert(log_obj_type);

  if (cert == NULL) {
    log_warn(LD_REND, "Certificate for %s couldn't be parsed.", log_obj_type);
    goto err;
  }
  if (cert->cert_type != type) {
    log_warn(LD_REND, "Invalid cert type %02x for %s.", cert->cert_type,
             log_obj_type);
    goto err;
  }
  /* All certificate must have its signing key included. */
  if (!cert->signing_key_included) {
    log_warn(LD_REND, "Signing key is NOT included for %s.", log_obj_type);
    goto err;
  }
  /* The following will not only check if the signature matches but also the
   * expiration date and overall validity. */
  if (tor_cert_checksig(cert, &cert->signing_key, time(NULL)) < 0) {
    log_warn(LD_REND, "Invalid signature for %s.", log_obj_type);
    goto err;
  }

  return 1;
 err:
  return 0;
}

/* Given some binary data, try to parse it to get a certificate object. If we
 * have a valid cert, validate it using the given wanted type. On error, print
 * a log using the err_msg has the certificate identifier adding semantic to
 * the log and cert_out is set to NULL. On success, 0 is returned and cert_out
 * points to a newly allocated certificate object. */
static int
cert_parse_and_validate(tor_cert_t **cert_out, const char *data,
                        size_t data_len, unsigned int cert_type_wanted,
                        const char *err_msg)
{
  tor_cert_t *cert;

  tor_assert(cert_out);
  tor_assert(data);
  tor_assert(err_msg);

  /* Parse certificate. */
  cert = tor_cert_parse((const uint8_t *) data, data_len);
  if (!cert) {
    log_warn(LD_REND, "Certificate for %s couldn't be parsed.", err_msg);
    goto err;
  }

  /* Validate certificate. */
  if (!cert_is_valid(cert, cert_type_wanted, err_msg)) {
    goto err;
  }

  *cert_out = cert;
  return 0;

 err:
  tor_cert_free(cert);
  *cert_out = NULL;
  return -1;
}

/* Return true iff the given length of the encrypted data of a descriptor
 * passes validation. */
STATIC int
encrypted_data_length_is_valid(size_t len)
{
  /* Check for the minimum length possible. */
  if (len < HS_DESC_ENCRYPTED_MIN_LEN) {
    log_warn(LD_REND, "Length of descriptor's encrypted data is too small. "
                      "Got %lu but minimum value is %d",
             (unsigned long)len, HS_DESC_ENCRYPTED_MIN_LEN);
    goto err;
  }

  /* Encrypted data has the salt and MAC concatenated to it so remove those
   * from the validation calculation. */
  len -= HS_DESC_ENCRYPTED_SALT_LEN + DIGEST256_LEN;

  /* Check that it's aligned on the block size of the crypto algorithm. */
  if (len % HS_DESC_PLAINTEXT_PADDING_MULTIPLE) {
    log_warn(LD_REND, "Length of descriptor's encrypted data is invalid. "
                      "Got %lu which is not a multiple of %d.",
             (unsigned long) len, HS_DESC_PLAINTEXT_PADDING_MULTIPLE);
    goto err;
  }

  /* XXX: Check maximum size. Will strongly depends on the maximum intro point
   * allowed we decide on and probably if they will all have to use the legacy
   * key which is bigger than the ed25519 key. */

  return 1;
 err:
  return 0;
}

/* Decrypt the encrypted section of the descriptor using the given descriptor
 * object desc. A newly allocated NUL terminated string is put in
 * decrypted_out. Return the length of decrypted_out on success else 0 is
 * returned and decrypted_out is set to NULL. */
static size_t
desc_decrypt_data_v3(const hs_descriptor_t *desc, char **decrypted_out)
{
  uint8_t *decrypted = NULL;
  uint8_t secret_key[CIPHER_KEY_LEN], secret_iv[CIPHER_IV_LEN];
  uint8_t mac_key[DIGEST256_LEN], our_mac[DIGEST256_LEN];
  const uint8_t *salt, *encrypted, *desc_mac;
  size_t encrypted_len, result_len = 0;

  tor_assert(decrypted_out);
  tor_assert(desc);
  tor_assert(desc->plaintext_data.encrypted_blob);

  /* Construction is as follow: SALT | ENCRYPTED_DATA | MAC */
  if (!encrypted_data_length_is_valid(
                desc->plaintext_data.encrypted_blob_size)) {
    goto err;
  }

  /* Start of the blob thus the salt. */
  salt = desc->plaintext_data.encrypted_blob;
  /* Next is the encrypted data. */
  encrypted = desc->plaintext_data.encrypted_blob +
    HS_DESC_ENCRYPTED_SALT_LEN;
  encrypted_len = desc->plaintext_data.encrypted_blob_size -
    (HS_DESC_ENCRYPTED_SALT_LEN + DIGEST256_LEN);

  /* At the very end is the MAC. Make sure it's of the right size. */
  {
    desc_mac = encrypted + encrypted_len;
    size_t desc_mac_size = desc->plaintext_data.encrypted_blob_size -
                           (desc_mac - desc->plaintext_data.encrypted_blob);
    if (desc_mac_size != DIGEST256_LEN) {
      log_warn(LD_REND, "Service descriptor MAC length of encrypted data "
                        "is invalid (%lu, expected %u)",
               (unsigned long) desc_mac_size, DIGEST256_LEN);
      goto err;
    }
  }

  /* KDF construction resulting in a key from which the secret key, IV and MAC
   * key are extracted which is what we need for the decryption. */
  build_secret_key_iv_mac(desc, salt, HS_DESC_ENCRYPTED_SALT_LEN,
                          secret_key, sizeof(secret_key),
                          secret_iv, sizeof(secret_iv),
                          mac_key, sizeof(mac_key));

  /* Build MAC. */
  build_mac(mac_key, sizeof(mac_key), salt, HS_DESC_ENCRYPTED_SALT_LEN,
            encrypted, encrypted_len, our_mac, sizeof(our_mac));
  memwipe(mac_key, 0, sizeof(mac_key));
  /* Verify MAC; MAC is H(mac_key || salt || encrypted)
   *
   * This is a critical check that is making sure the computed MAC matches the
   * one in the descriptor. */
  if (!tor_memeq(our_mac, desc_mac, sizeof(our_mac))) {
    log_warn(LD_REND, "Encrypted service descriptor MAC check failed");
    goto err;
  }

  {
    /* Decrypt. Here we are assured that the encrypted length is valid for
     * decryption. */
    crypto_cipher_t *cipher;
    cipher = crypto_cipher_new_with_iv((const char *) secret_key,
                                       (const char *) secret_iv);
    /* Extra byte for the NUL terminated byte. */
    decrypted = tor_malloc_zero(encrypted_len + 1);
    crypto_cipher_decrypt(cipher, (char *) decrypted,
                          (const char *) encrypted, encrypted_len);
    crypto_cipher_free(cipher);
  }

  {
    /* Adjust length to remove NULL padding bytes */
    uint8_t *end = memchr(decrypted, 0, encrypted_len);
    result_len = encrypted_len;
    if (end) {
      result_len = end - decrypted;
    }
  }

  /* Make sure to NUL terminate the string. */
  decrypted[encrypted_len] = '\0';
  *decrypted_out = (char *) decrypted;
  goto done;

 err:
  if (decrypted) {
    tor_free(decrypted);
  }
  *decrypted_out = NULL;
  result_len = 0;

 done:
  memwipe(secret_key, 0, sizeof(secret_key));
  memwipe(secret_iv, 0, sizeof(secret_iv));
  return result_len;
}

/* Given the start of a section and the end of it, decode a single
 * introduction point from that section. Return a newly allocated introduction
 * point object containing the decoded data. Return NULL if the section can't
 * be decoded. */
STATIC hs_desc_intro_point_t *
decode_introduction_point(const hs_descriptor_t *desc, const char *start)
{
  hs_desc_intro_point_t *ip = NULL;
  memarea_t *area = NULL;
  smartlist_t *tokens = NULL;
  tor_cert_t *cross_cert = NULL;
  const directory_token_t *tok;

  tor_assert(desc);
  tor_assert(start);

  area = memarea_new();
  tokens = smartlist_new();
  if (tokenize_string(area, start, start + strlen(start),
                      tokens, hs_desc_intro_point_v3_token_table, 0) < 0) {
    log_warn(LD_REND, "Introduction point is not parseable");
    goto err;
  }

  /* Ok we seem to have a well formed section containing enough tokens to
   * parse. Allocate our IP object and try to populate it. */
  ip = tor_malloc_zero(sizeof(hs_desc_intro_point_t));

  /* "introduction-point" SP link-specifiers NL */
  tok = find_by_keyword(tokens, R3_INTRODUCTION_POINT);
  tor_assert(tok->n_args == 1);
  ip->link_specifiers = decode_link_specifiers(tok->args[0]);
  if (!ip->link_specifiers) {
    log_warn(LD_REND, "Introduction point has invalid link specifiers");
    goto err;
  }

  /* "auth-key" NL certificate NL */
  tok = find_by_keyword(tokens, R3_INTRO_AUTH_KEY);
  tor_assert(tok->object_body);
  if (strcmp(tok->object_type, "ED25519 CERT")) {
    log_warn(LD_REND, "Unexpected object type for introduction auth key");
    goto err;
  }

  /* Parse cert and do some validation. */
  if (cert_parse_and_validate(&ip->auth_key_cert, tok->object_body,
                              tok->object_size, CERT_TYPE_AUTH_HS_IP_KEY,
                              "introduction point auth-key") < 0) {
    goto err;
  }

  /* Exactly one "enc-key" ... */
  tok = find_by_keyword(tokens, R3_INTRO_ENC_KEY);
  if (!strcmp(tok->args[0], "ntor")) {
    /* "enc-key" SP "ntor" SP key NL */
    if (tok->n_args != 2 || tok->object_body) {
      log_warn(LD_REND, "Introduction point ntor encryption key is invalid");
      goto err;
    }

    if (curve25519_public_from_base64(&ip->enc_key.curve25519.pubkey,
                                      tok->args[1]) < 0) {
      log_warn(LD_REND, "Introduction point ntor encryption key is invalid");
      goto err;
    }
    ip->enc_key_type = HS_DESC_KEY_TYPE_CURVE25519;
  } else if (!strcmp(tok->args[0], "legacy")) {
    /* "enc-key" SP "legacy" NL key NL */
    if (!tok->key) {
      log_warn(LD_REND, "Introduction point legacy encryption key is "
               "invalid");
      goto err;
    }
    ip->enc_key.legacy = crypto_pk_dup_key(tok->key);
    ip->enc_key_type = HS_DESC_KEY_TYPE_LEGACY;
  } else {
    /* Unknown key type so we can't use that introduction point. */
    log_warn(LD_REND, "Introduction point encryption key is unrecognized.");
    goto err;
  }

  /* "enc-key-certification" NL certificate NL */
  tok = find_by_keyword(tokens, R3_INTRO_ENC_KEY_CERTIFICATION);
  tor_assert(tok->object_body);
  /* Do the cross certification. */
  switch (ip->enc_key_type) {
  case HS_DESC_KEY_TYPE_CURVE25519:
  {
    if (strcmp(tok->object_type, "ED25519 CERT")) {
      log_warn(LD_REND, "Introduction point ntor encryption key "
                        "cross-certification has an unknown format.");
      goto err;
    }
    if (cert_parse_and_validate(&cross_cert, tok->object_body,
                       tok->object_size, CERT_TYPE_CROSS_HS_IP_KEYS,
                       "introduction point enc-key-certification") < 0) {
      goto err;
    }
    break;
  }
  case HS_DESC_KEY_TYPE_LEGACY:
    if (strcmp(tok->object_type, "CROSSCERT")) {
      log_warn(LD_REND, "Introduction point legacy encryption key "
                        "cross-certification has an unknown format.");
      goto err;
    }
    if (rsa_ed25519_crosscert_check((const uint8_t *) tok->object_body,
          tok->object_size, ip->enc_key.legacy,
          &desc->plaintext_data.signing_key_cert->signed_key,
          approx_time()-86400)) {
      log_warn(LD_REND, "Unable to check cross-certification on the "
                        "introduction point legacy encryption key.");
      goto err;
    }
    break;
  default:
    tor_assert(0);
    break;
  }
  /* It is successfully cross certified. Flag the object. */
  ip->cross_certified = 1;
  goto done;

 err:
  desc_intro_point_free(ip);
  ip = NULL;

 done:
  tor_cert_free(cross_cert);
  SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
  smartlist_free(tokens);
  memarea_drop_all(area);

  return ip;
}

/* Given a descriptor string at <b>data</b>, decode all possible introduction
 * points that we can find. Add the introduction point object to desc_enc as we
 * find them. Return 0 on success.
 *
 * On error, a negative value is returned. It is possible that some intro
 * point object have been added to the desc_enc, they should be considered
 * invalid. One single bad encoded introduction point will make this function
 * return an error. */
STATIC int
decode_intro_points(const hs_descriptor_t *desc,
                    hs_desc_encrypted_data_t *desc_enc,
                    const char *data)
{
  int retval = -1;
  smartlist_t *chunked_desc = smartlist_new();
  smartlist_t *intro_points = smartlist_new();

  tor_assert(desc);
  tor_assert(desc_enc);
  tor_assert(data);
  tor_assert(desc_enc->intro_points);

  /* Take the desc string, and extract the intro point substrings out of it */
  {
    /* Split the descriptor string using the intro point header as delimiter */
    smartlist_split_string(chunked_desc, data, str_intro_point_start, 0, 0);

    /* Check if there are actually any intro points included. The first chunk
     * should be other descriptor fields (e.g. create2-formats), so it's not an
     * intro point. */
    if (smartlist_len(chunked_desc) < 2) {
      goto done;
    }
  }

  /* Take the intro point substrings, and prepare them for parsing */
  {
    int i = 0;
    /* Prepend the introduction-point header to all the chunks, since
       smartlist_split_string() devoured it. */
    SMARTLIST_FOREACH_BEGIN(chunked_desc, char *, chunk) {
      /* Ignore first chunk. It's other descriptor fields. */
      if (i++ == 0) {
        continue;
      }

      smartlist_add_asprintf(intro_points, "%s %s", str_intro_point, chunk);
    } SMARTLIST_FOREACH_END(chunk);
  }

  /* Parse the intro points! */
  SMARTLIST_FOREACH_BEGIN(intro_points, const char *, intro_point) {
    hs_desc_intro_point_t *ip = decode_introduction_point(desc, intro_point);
    if (!ip) {
      /* Malformed introduction point section. Stop right away, this
       * descriptor shouldn't be used. */
      goto err;
    }
    smartlist_add(desc_enc->intro_points, ip);
  } SMARTLIST_FOREACH_END(intro_point);

 done:
  retval = 0;

 err:
  SMARTLIST_FOREACH(chunked_desc, char *, a, tor_free(a));
  smartlist_free(chunked_desc);
  SMARTLIST_FOREACH(intro_points, char *, a, tor_free(a));
  smartlist_free(intro_points);
  return retval;
}
/* Return 1 iff the given base64 encoded signature in b64_sig from the encoded
 * descriptor in encoded_desc validates the descriptor content. */
STATIC int
desc_sig_is_valid(const char *b64_sig, const ed25519_keypair_t *signing_kp,
                  const char *encoded_desc, size_t encoded_len)
{
  int ret = 0;
  ed25519_signature_t sig;
  const char *sig_start;

  tor_assert(b64_sig);
  tor_assert(signing_kp);
  tor_assert(encoded_desc);
  /* Verifying nothing won't end well :). */
  tor_assert(encoded_len > 0);

  /* Signature length check. */
  if (strlen(b64_sig) != ED25519_SIG_BASE64_LEN) {
    log_warn(LD_REND, "Service descriptor has an invalid signature length."
                      "Exptected %d but got %lu",
             ED25519_SIG_BASE64_LEN, (unsigned long) strlen(b64_sig));
    goto err;
  }

  /* First, convert base64 blob to an ed25519 signature. */
  if (ed25519_signature_from_base64(&sig, b64_sig) != 0) {
    log_warn(LD_REND, "Service descriptor does not contain a valid "
                      "signature");
    goto err;
  }

  /* Find the start of signature. */
  sig_start = tor_memstr(encoded_desc, encoded_len, "\n" str_signature);
  /* Getting here means the token parsing worked for the signature so if we
   * can't find the start of the signature, we have a code flow issue. */
  if (BUG(!sig_start)) {
    goto err;
  }
  /* Skip newline, it has to go in the signature check. */
  sig_start++;

  /* Validate signature with the full body of the descriptor. */
  if (ed25519_checksig_prefixed(&sig,
                                (const uint8_t *) encoded_desc,
                                sig_start - encoded_desc,
                                str_desc_sig_prefix,
                                &signing_kp->pubkey) != 0) {
    log_warn(LD_REND, "Invalid signature on service descriptor");
    goto err;
  }
  /* Valid signature! All is good. */
  ret = 1;

 err:
  return ret;
}

/* Decode descriptor plaintext data for version 3. Given a list of tokens, an
 * allocated plaintext object that will be populated and the encoded
 * descriptor with its length. The last one is needed for signature
 * verification. Unknown tokens are simply ignored so this won't error on
 * unknowns but requires that all v3 token be present and valid.
 *
 * Return 0 on success else a negative value. */
static int
desc_decode_plaintext_v3(smartlist_t *tokens,
                         hs_desc_plaintext_data_t *desc,
                         const char *encoded_desc, size_t encoded_len)
{
  int ok;
  directory_token_t *tok;

  tor_assert(tokens);
  tor_assert(desc);
  /* Version higher could still use this function to decode most of the
   * descriptor and then they decode the extra part. */
  tor_assert(desc->version >= 3);

  /* Descriptor lifetime parsing. */
  tok = find_by_keyword(tokens, R3_DESC_LIFETIME);
  tor_assert(tok->n_args == 1);
  desc->lifetime_sec = (uint32_t) tor_parse_ulong(tok->args[0], 10, 0,
                                                  UINT32_MAX, &ok, NULL);
  if (!ok) {
    log_warn(LD_REND, "Service descriptor lifetime value is invalid");
    goto err;
  }
  /* Put it from minute to second. */
  desc->lifetime_sec *= 60;
  if (desc->lifetime_sec > HS_DESC_MAX_LIFETIME) {
    log_warn(LD_REND, "Service descriptor lifetime is too big. "
                      "Got %" PRIu32 " but max is %d",
             desc->lifetime_sec, HS_DESC_MAX_LIFETIME);
    goto err;
  }

  /* Descriptor signing certificate. */
  tok = find_by_keyword(tokens, R3_DESC_SIGNING_CERT);
  tor_assert(tok->object_body);
  /* Expecting a prop220 cert with the signing key extension, which contains
   * the blinded public key. */
  if (strcmp(tok->object_type, "ED25519 CERT") != 0) {
    log_warn(LD_REND, "Service descriptor signing cert wrong type (%s)",
             escaped(tok->object_type));
    goto err;
  }
  if (cert_parse_and_validate(&desc->signing_key_cert, tok->object_body,
                              tok->object_size, CERT_TYPE_SIGNING_HS_DESC,
                              "service descriptor signing key") < 0) {
    goto err;
  }

  /* Copy the public keys into signing_kp and blinded_kp */
  memcpy(&desc->signing_kp.pubkey, &desc->signing_key_cert->signed_key,
         sizeof(ed25519_public_key_t));
  memcpy(&desc->blinded_kp.pubkey, &desc->signing_key_cert->signing_key,
         sizeof(ed25519_public_key_t));

  /* Extract revision counter value. */
  tok = find_by_keyword(tokens, R3_REVISION_COUNTER);
  tor_assert(tok->n_args == 1);
  desc->revision_counter = tor_parse_uint64(tok->args[0], 10, 0,
                                            UINT64_MAX, &ok, NULL);
  if (!ok) {
    log_warn(LD_REND, "Service descriptor revision-counter is invalid");
    goto err;
  }

  /* Extract the encrypted data section. */
  tok = find_by_keyword(tokens, R3_ENCRYPTED);
  tor_assert(tok->object_body);
  if (strcmp(tok->object_type, "MESSAGE") != 0) {
    log_warn(LD_REND, "Service descriptor encrypted data section is invalid");
    goto err;
  }
  /* Make sure the length of the encrypted blob is valid. */
  if (!encrypted_data_length_is_valid(tok->object_size)) {
    goto err;
  }

  /* Copy the encrypted blob to the descriptor object so we can handle it
   * latter if needed. */
  desc->encrypted_blob = tor_memdup(tok->object_body, tok->object_size);
  desc->encrypted_blob_size = tok->object_size;

  /* Extract signature and verify it. */
  tok = find_by_keyword(tokens, R3_SIGNATURE);
  tor_assert(tok->n_args == 1);
  /* First arg here is the actual encoded signature. */
  if (!desc_sig_is_valid(tok->args[0], &desc->signing_kp,
                         encoded_desc, encoded_len)) {
    goto err;
  }

  return 0;

 err:
  return -1;
}

/* Decode the version 3 encrypted section of the given descriptor desc. The
 * desc_encrypted_out will be populated with the decoded data. Return 0 on
 * success else -1. */
static int
desc_decode_encrypted_v3(const hs_descriptor_t *desc,
                         hs_desc_encrypted_data_t *desc_encrypted_out)
{
  int result = -1;
  char *message = NULL;
  size_t message_len;
  memarea_t *area = NULL;
  directory_token_t *tok;
  smartlist_t *tokens = NULL;

  tor_assert(desc);
  tor_assert(desc_encrypted_out);

  /* Decrypt the encrypted data that is located in the plaintext section in
   * the descriptor as a blob of bytes. The following functions will use the
   * keys found in the same section. */
  message_len = desc_decrypt_data_v3(desc, &message);
  if (!message_len) {
    log_warn(LD_REND, "Service descriptor decryption failed.");
    goto err;
  }
  tor_assert(message);

  area = memarea_new();
  tokens = smartlist_new();
  if (tokenize_string(area, message, message + message_len,
                      tokens, hs_desc_encrypted_v3_token_table, 0) < 0) {
    log_warn(LD_REND, "Encrypted service descriptor is not parseable.");
    goto err;
  }

  /* CREATE2 supported cell format. It's mandatory. */
  tok = find_by_keyword(tokens, R3_CREATE2_FORMATS);
  tor_assert(tok);
  decode_create2_list(desc_encrypted_out, tok->args[0]);
  /* Must support ntor according to the specification */
  if (!desc_encrypted_out->create2_ntor) {
    log_warn(LD_REND, "Service create2-formats does not include ntor.");
    goto err;
  }

  /* Authentication type. It's optional but only once. */
  tok = find_opt_by_keyword(tokens, R3_AUTHENTICATION_REQUIRED);
  if (tok) {
    if (!decode_auth_type(desc_encrypted_out, tok->args[0])) {
      log_warn(LD_REND, "Service descriptor authentication type has "
                        "invalid entry(ies).");
      goto err;
    }
  }

  /* Is this service a single onion service? */
  tok = find_opt_by_keyword(tokens, R3_SINGLE_ONION_SERVICE);
  if (tok) {
    desc_encrypted_out->single_onion_service = 1;
  }

  /* Initialize the descriptor's introduction point list before we start
   * decoding. Having 0 intro point is valid. Then decode them all. */
  desc_encrypted_out->intro_points = smartlist_new();
  if (decode_intro_points(desc, desc_encrypted_out, message) < 0) {
    goto err;
  }
  /* Validation of maximum introduction points allowed. */
  if (smartlist_len(desc_encrypted_out->intro_points) > MAX_INTRO_POINTS) {
    log_warn(LD_REND, "Service descriptor contains too many introduction "
                      "points. Maximum allowed is %d but we have %d",
             MAX_INTRO_POINTS,
             smartlist_len(desc_encrypted_out->intro_points));
    goto err;
  }

  /* NOTE: Unknown fields are allowed because this function could be used to
   * decode other descriptor version. */

  result = 0;
  goto done;

 err:
  tor_assert(result < 0);
  desc_encrypted_data_free_contents(desc_encrypted_out);

 done:
  if (tokens) {
    SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
    smartlist_free(tokens);
  }
  if (area) {
    memarea_drop_all(area);
  }
  if (message) {
    tor_free(message);
  }
  return result;
}

/* Table of encrypted decode function version specific. The function are
 * indexed by the version number so v3 callback is at index 3 in the array. */
static int
  (*decode_encrypted_handlers[])(
      const hs_descriptor_t *desc,
      hs_desc_encrypted_data_t *desc_encrypted) =
{
  /* v0 */ NULL, /* v1 */ NULL, /* v2 */ NULL,
  desc_decode_encrypted_v3,
};

/* Decode the encrypted data section of the given descriptor and store the
 * data in the given encrypted data object. Return 0 on success else a
 * negative value on error. */
int
hs_desc_decode_encrypted(const hs_descriptor_t *desc,
                         hs_desc_encrypted_data_t *desc_encrypted)
{
  int ret;
  uint32_t version;

  tor_assert(desc);
  /* Ease our life a bit. */
  version = desc->plaintext_data.version;
  tor_assert(desc_encrypted);
  /* Calling this function without an encrypted blob to parse is a code flow
   * error. The plaintext parsing should never succeed in the first place
   * without an encrypted section. */
  tor_assert(desc->plaintext_data.encrypted_blob);
  /* Let's make sure we have a supported version as well. By correctly parsing
   * the plaintext, this should not fail. */
  if (BUG(!hs_desc_is_supported_version(version))) {
    ret = -1;
    goto err;
  }
  /* Extra precaution. Having no handler for the supported version should
   * never happened else we forgot to add it but we bumped the version. */
  tor_assert(ARRAY_LENGTH(decode_encrypted_handlers) >= version);
  tor_assert(decode_encrypted_handlers[version]);

  /* Run the version specific plaintext decoder. */
  ret = decode_encrypted_handlers[version](desc, desc_encrypted);
  if (ret < 0) {
    goto err;
  }

 err:
  return ret;
}

/* Table of plaintext decode function version specific. The function are
 * indexed by the version number so v3 callback is at index 3 in the array. */
static int
  (*decode_plaintext_handlers[])(
      smartlist_t *tokens,
      hs_desc_plaintext_data_t *desc,
      const char *encoded_desc,
      size_t encoded_len) =
{
  /* v0 */ NULL, /* v1 */ NULL, /* v2 */ NULL,
  desc_decode_plaintext_v3,
};

/* Fully decode the given descriptor plaintext and store the data in the
 * plaintext data object. Returns 0 on success else a negative value. */
int
hs_desc_decode_plaintext(const char *encoded,
                         hs_desc_plaintext_data_t *plaintext)
{
  int ok = 0, ret = -1;
  memarea_t *area = NULL;
  smartlist_t *tokens = NULL;
  size_t encoded_len;
  directory_token_t *tok;

  tor_assert(encoded);
  tor_assert(plaintext);

  encoded_len = strlen(encoded);
  if (encoded_len >= HS_DESC_MAX_LEN) {
    log_warn(LD_REND, "Service descriptor is too big (%lu bytes)",
             (unsigned long) encoded_len);
    goto err;
  }

  area = memarea_new();
  tokens = smartlist_new();
  /* Tokenize the descriptor so we can start to parse it. */
  if (tokenize_string(area, encoded, encoded + encoded_len, tokens,
                      hs_desc_v3_token_table, 0) < 0) {
    log_warn(LD_REND, "Service descriptor is not parseable");
    goto err;
  }

  /* Get the version of the descriptor which is the first mandatory field of
   * the descriptor. From there, we'll decode the right descriptor version. */
  tok = find_by_keyword(tokens, R_HS_DESCRIPTOR);
  tor_assert(tok->n_args == 1);
  plaintext->version = (uint32_t) tor_parse_ulong(tok->args[0], 10, 0,
                                                  UINT32_MAX, &ok, NULL);
  if (!ok) {
    log_warn(LD_REND, "Service descriptor has unparseable version %s",
             escaped(tok->args[0]));
    goto err;
  }
  if (!hs_desc_is_supported_version(plaintext->version)) {
    log_warn(LD_REND, "Service descriptor has unsupported version %" PRIu32,
             plaintext->version);
    goto err;
  }
  /* Extra precaution. Having no handler for the supported version should
   * never happened else we forgot to add it but we bumped the version. */
  tor_assert(ARRAY_LENGTH(decode_plaintext_handlers) >= plaintext->version);
  tor_assert(decode_plaintext_handlers[plaintext->version]);

  /* Run the version specific plaintext decoder. */
  ret = decode_plaintext_handlers[plaintext->version](tokens, plaintext,
                                                      encoded, encoded_len);
  if (ret < 0) {
    goto err;
  }
  /* Success. Descriptor has been populated with the data. */
  ret = 0;

 err:
  if (tokens) {
    SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
    smartlist_free(tokens);
  }
  if (area) {
    memarea_drop_all(area);
  }
  return ret;
}

/* Fully decode an encoded descriptor and set a newly allocated descriptor
 * object in desc_out. Subcredentials are used if not NULL else it's ignored.
 *
 * Return 0 on success. A negative value is returned on error and desc_out is
 * set to NULL. */
int
hs_desc_decode_descriptor(const char *encoded,
                          const uint8_t *subcredential,
                          hs_descriptor_t **desc_out)
{
  int ret;
  hs_descriptor_t *desc;

  tor_assert(encoded);

  desc = tor_malloc_zero(sizeof(hs_descriptor_t));

  /* Subcredentials are optional. */
  if (subcredential) {
    memcpy(desc->subcredential, subcredential, sizeof(desc->subcredential));
  }

  ret = hs_desc_decode_plaintext(encoded, &desc->plaintext_data);
  if (ret < 0) {
    goto err;
  }

  ret = hs_desc_decode_encrypted(desc, &desc->encrypted_data);
  if (ret < 0) {
    goto err;
  }

  if (desc_out) {
    *desc_out = desc;
  } else {
    hs_descriptor_free(desc);
  }
  return ret;

 err:
  hs_descriptor_free(desc);
  if (desc_out) {
    *desc_out = NULL;
  }

  tor_assert(ret < 0);
  return ret;
}

/* Table of encode function version specific. The function are indexed by the
 * version number so v3 callback is at index 3 in the array. */
static int
  (*encode_handlers[])(
      const hs_descriptor_t *desc,
      char **encoded_out) =
{
  /* v0 */ NULL, /* v1 */ NULL, /* v2 */ NULL,
  desc_encode_v3,
};

/* Encode the given descriptor desc. On success, encoded_out points to a newly
 * allocated NUL terminated string that contains the encoded descriptor as a
 * string.
 *
 * Return 0 on success and encoded_out is a valid pointer. On error, -1 is
 * returned and encoded_out is set to NULL. */
int
hs_desc_encode_descriptor(const hs_descriptor_t *desc, char **encoded_out)
{
  int ret = -1;

  tor_assert(desc);
  tor_assert(encoded_out);

  /* Make sure we support the version of the descriptor format. */
  if (!hs_desc_is_supported_version(desc->plaintext_data.version)) {
    goto err;
  }
  /* Extra precaution. Having no handler for the supported version should
   * never happened else we forgot to add it but we bumped the version. */
  tor_assert(ARRAY_LENGTH(encode_handlers) >= desc->plaintext_data.version);
  tor_assert(encode_handlers[desc->plaintext_data.version]);

  ret = encode_handlers[desc->plaintext_data.version](desc, encoded_out);
  if (ret < 0) {
    goto err;
  }

  /* Try to decode what we just encoded. Symmetry is nice! */
  ret = hs_desc_decode_descriptor(*encoded_out, desc->subcredential, NULL);
  if (BUG(ret < 0)) {
    goto err;
  }

  return 0;

 err:
  *encoded_out = NULL;
  return ret;
}

/* Free the descriptor plaintext data object. */
void
hs_desc_plaintext_data_free(hs_desc_plaintext_data_t *desc)
{
  desc_plaintext_data_free_contents(desc);
  tor_free(desc);
}

/* Free the descriptor encrypted data object. */
void
hs_desc_encrypted_data_free(hs_desc_encrypted_data_t *desc)
{
  desc_encrypted_data_free_contents(desc);
  tor_free(desc);
}

/* Free the given descriptor object. */
void
hs_descriptor_free(hs_descriptor_t *desc)
{
  if (!desc) {
    return;
  }

  desc_plaintext_data_free_contents(&desc->plaintext_data);
  desc_encrypted_data_free_contents(&desc->encrypted_data);
  tor_free(desc);
}

/* Return the size in bytes of the given plaintext data object. A sizeof() is
 * not enough because the object contains pointers and the encrypted blob.
 * This is particularly useful for our OOM subsystem that tracks the HSDir
 * cache size for instance. */
size_t
hs_desc_plaintext_obj_size(const hs_desc_plaintext_data_t *data)
{
  tor_assert(data);
  return (sizeof(*data) + sizeof(*data->signing_key_cert) +
          data->encrypted_blob_size);
}

