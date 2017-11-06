/* Copyright (c) 2016-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_descriptor.c
 * \brief Handle hidden service descriptor encoding/decoding.
 *
 * \details
 * Here is a graphical depiction of an HS descriptor and its layers:
 *
 *      +------------------------------------------------------+
 *      |DESCRIPTOR HEADER:                                    |
 *      |  hs-descriptor 3                                     |
 *      |  descriptor-lifetime 180                             |
 *      |  ...                                                 |
 *      |  superencrypted                                      |
 *      |+---------------------------------------------------+ |
 *      ||SUPERENCRYPTED LAYER (aka OUTER ENCRYPTED LAYER):  | |
 *      ||  desc-auth-type x25519                            | |
 *      ||  desc-auth-ephemeral-key                          | |
 *      ||  auth-client                                      | |
 *      ||  auth-client                                      | |
 *      ||  ...                                              | |
 *      ||  encrypted                                        | |
 *      ||+-------------------------------------------------+| |
 *      |||ENCRYPTED LAYER (aka INNER ENCRYPTED LAYER):     || |
 *      |||  create2-formats                                || |
 *      |||  intro-auth-required                            || |
 *      |||  introduction-point                             || |
 *      |||  introduction-point                             || |
 *      |||  ...                                            || |
 *      ||+-------------------------------------------------+| |
 *      |+---------------------------------------------------+ |
 *      +------------------------------------------------------+
 *
 * The DESCRIPTOR HEADER section is completely unencrypted and contains generic
 * descriptor metadata.
 *
 * The SUPERENCRYPTED LAYER section is the first layer of encryption, and it's
 * encrypted using the blinded public key of the hidden service to protect
 * against entities who don't know its onion address. The clients of the hidden
 * service know its onion address and blinded public key, whereas third-parties
 * (like HSDirs) don't know it (except if it's a public hidden service).
 *
 * The ENCRYPTED LAYER section is the second layer of encryption, and it's
 * encrypted using the client authorization key material (if those exist). When
 * client authorization is enabled, this second layer of encryption protects
 * the descriptor content from unauthorized entities. If client authorization
 * is disabled, this second layer of encryption does not provide any extra
 * security but is still present. The plaintext of this layer contains all the
 * information required to connect to the hidden service like its list of
 * introduction points.
 **/

/* For unit tests.*/
#define HS_DESCRIPTOR_PRIVATE

#include "or.h"
#include "ed25519_cert.h" /* Trunnel interface. */
#include "hs_descriptor.h"
#include "circuitbuild.h"
#include "parsecommon.h"
#include "rendcache.h"
#include "hs_cache.h"
#include "hs_config.h"
#include "torcert.h" /* tor_cert_encode_ed22519() */

/* Constant string value used for the descriptor format. */
#define str_hs_desc "hs-descriptor"
#define str_desc_cert "descriptor-signing-key-cert"
#define str_rev_counter "revision-counter"
#define str_superencrypted "superencrypted"
#define str_encrypted "encrypted"
#define str_signature "signature"
#define str_lifetime "descriptor-lifetime"
/* Constant string value for the encrypted part of the descriptor. */
#define str_create2_formats "create2-formats"
#define str_intro_auth_required "intro-auth-required"
#define str_single_onion "single-onion-service"
#define str_intro_point "introduction-point"
#define str_ip_onion_key "onion-key"
#define str_ip_auth_key "auth-key"
#define str_ip_enc_key "enc-key"
#define str_ip_enc_key_cert "enc-key-cert"
#define str_ip_legacy_key "legacy-key"
#define str_ip_legacy_key_cert "legacy-key-cert"
#define str_intro_point_start "\n" str_intro_point " "
/* Constant string value for the construction to encrypt the encrypted data
 * section. */
#define str_enc_const_superencryption "hsdir-superencrypted-data"
#define str_enc_const_encryption "hsdir-encrypted-data"
/* Prefix required to compute/verify HS desc signatures */
#define str_desc_sig_prefix "Tor onion service descriptor sig v3"
#define str_desc_auth_type "desc-auth-type"
#define str_desc_auth_key "desc-auth-ephemeral-key"
#define str_desc_auth_client "auth-client"
#define str_encrypted "encrypted"

/* Authentication supported types. */
static const struct {
  hs_desc_auth_type_t type;
  const char *identifier;
} intro_auth_types[] = {
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
  T1(str_superencrypted, R3_SUPERENCRYPTED, NO_ARGS, NEED_OBJ),
  T1_END(str_signature, R3_SIGNATURE, EQ(1), NO_OBJ),
  END_OF_TABLE
};

/* Descriptor ruleset for the superencrypted section. */
static token_rule_t hs_desc_superencrypted_v3_token_table[] = {
  T1_START(str_desc_auth_type, R3_DESC_AUTH_TYPE, GE(1), NO_OBJ),
  T1(str_desc_auth_key, R3_DESC_AUTH_KEY, GE(1), NO_OBJ),
  T1N(str_desc_auth_client, R3_DESC_AUTH_CLIENT, GE(3), NO_OBJ),
  T1(str_encrypted, R3_ENCRYPTED, NO_ARGS, NEED_OBJ),
  END_OF_TABLE
};

/* Descriptor ruleset for the encrypted section. */
static token_rule_t hs_desc_encrypted_v3_token_table[] = {
  T1_START(str_create2_formats, R3_CREATE2_FORMATS, CONCAT_ARGS, NO_OBJ),
  T01(str_intro_auth_required, R3_INTRO_AUTH_REQUIRED, ARGS, NO_OBJ),
  T01(str_single_onion, R3_SINGLE_ONION_SERVICE, ARGS, NO_OBJ),
  END_OF_TABLE
};

/* Descriptor ruleset for the introduction points section. */
static token_rule_t hs_desc_intro_point_v3_token_table[] = {
  T1_START(str_intro_point, R3_INTRODUCTION_POINT, EQ(1), NO_OBJ),
  T1N(str_ip_onion_key, R3_INTRO_ONION_KEY, GE(2), OBJ_OK),
  T1(str_ip_auth_key, R3_INTRO_AUTH_KEY, NO_ARGS, NEED_OBJ),
  T1(str_ip_enc_key, R3_INTRO_ENC_KEY, GE(2), OBJ_OK),
  T1(str_ip_enc_key_cert, R3_INTRO_ENC_KEY_CERT, ARGS, OBJ_OK),
  T01(str_ip_legacy_key, R3_INTRO_LEGACY_KEY, ARGS, NEED_KEY_1024),
  T01(str_ip_legacy_key_cert, R3_INTRO_LEGACY_KEY_CERT, ARGS, OBJ_OK),
  END_OF_TABLE
};

/* Free the content of the plaintext section of a descriptor. */
STATIC void
desc_plaintext_data_free_contents(hs_desc_plaintext_data_t *desc)
{
  if (!desc) {
    return;
  }

  if (desc->superencrypted_blob) {
    tor_free(desc->superencrypted_blob);
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

  if (desc->intro_auth_types) {
    SMARTLIST_FOREACH(desc->intro_auth_types, char *, a, tor_free(a));
    smartlist_free(desc->intro_auth_types);
  }
  if (desc->intro_points) {
    SMARTLIST_FOREACH(desc->intro_points, hs_desc_intro_point_t *, ip,
                      hs_desc_intro_point_free(ip));
    smartlist_free(desc->intro_points);
  }
  memwipe(desc, 0, sizeof(*desc));
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
  memcpy(dst, desc->plaintext_data.blinded_pubkey.pubkey,
         sizeof(desc->plaintext_data.blinded_pubkey.pubkey));
  offset += sizeof(desc->plaintext_data.blinded_pubkey.pubkey);
  /* Copy subcredential. */
  memcpy(dst + offset, desc->subcredential, sizeof(desc->subcredential));
  offset += sizeof(desc->subcredential);
  /* Copy revision counter value. */
  set_uint64(dst + offset, tor_htonll(desc->plaintext_data.revision_counter));
  offset += sizeof(uint64_t);
  tor_assert(HS_DESC_ENCRYPTED_SECRET_INPUT_LEN == offset);
}

/* Do the KDF construction and put the resulting data in key_out which is of
 * key_out_len length. It uses SHAKE-256 as specified in the spec. */
static void
build_kdf_key(const hs_descriptor_t *desc,
              const uint8_t *salt, size_t salt_len,
              uint8_t *key_out, size_t key_out_len,
              int is_superencrypted_layer)
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

  /* Feed in the right string constant based on the desc layer */
  if (is_superencrypted_layer) {
    crypto_xof_add_bytes(xof, (const uint8_t *) str_enc_const_superencryption,
                         strlen(str_enc_const_superencryption));
  } else {
    crypto_xof_add_bytes(xof, (const uint8_t *) str_enc_const_encryption,
                         strlen(str_enc_const_encryption));
  }

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
                        uint8_t *mac_out, size_t mac_len,
                        int is_superencrypted_layer)
{
  size_t offset = 0;
  uint8_t kdf_key[HS_DESC_ENCRYPTED_KDF_OUTPUT_LEN];

  tor_assert(desc);
  tor_assert(salt);
  tor_assert(key_out);
  tor_assert(iv_out);
  tor_assert(mac_out);

  build_kdf_key(desc, salt, salt_len, kdf_key, sizeof(kdf_key),
                is_superencrypted_layer);
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
    link_specifier_t *ls = hs_desc_lspec_to_trunnel(spec);
    if (ls) {
      link_specifier_list_add_spec(lslist, ls);
    }
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

/* Encode an introduction point legacy key and certificate. Return a newly
 * allocated string with it. On failure, return NULL. */
static char *
encode_legacy_key(const hs_desc_intro_point_t *ip)
{
  char *key_str, b64_cert[256], *encoded = NULL;
  size_t key_str_len;

  tor_assert(ip);

  /* Encode cross cert. */
  if (base64_encode(b64_cert, sizeof(b64_cert),
                    (const char *) ip->legacy.cert.encoded,
                    ip->legacy.cert.len, BASE64_ENCODE_MULTILINE) < 0) {
    log_warn(LD_REND, "Unable to encode legacy crosscert.");
    goto done;
  }
  /* Convert the encryption key to PEM format NUL terminated. */
  if (crypto_pk_write_public_key_to_string(ip->legacy.key, &key_str,
                                           &key_str_len) < 0) {
    log_warn(LD_REND, "Unable to encode legacy encryption key.");
    goto done;
  }
  tor_asprintf(&encoded,
               "%s \n%s"  /* Newline is added by the call above. */
               "%s\n"
               "-----BEGIN CROSSCERT-----\n"
               "%s"
               "-----END CROSSCERT-----",
               str_ip_legacy_key, key_str,
               str_ip_legacy_key_cert, b64_cert);
  tor_free(key_str);

 done:
  return encoded;
}

/* Encode an introduction point encryption key and certificate. Return a newly
 * allocated string with it. On failure, return NULL. */
static char *
encode_enc_key(const hs_desc_intro_point_t *ip)
{
  char *encoded = NULL, *encoded_cert;
  char key_b64[CURVE25519_BASE64_PADDED_LEN + 1];

  tor_assert(ip);

  /* Base64 encode the encryption key for the "enc-key" field. */
  if (curve25519_public_to_base64(key_b64, &ip->enc_key) < 0) {
    goto done;
  }
  if (tor_cert_encode_ed22519(ip->enc_key_cert, &encoded_cert) < 0) {
    goto done;
  }
  tor_asprintf(&encoded,
               "%s ntor %s\n"
               "%s\n%s",
               str_ip_enc_key, key_b64,
               str_ip_enc_key_cert, encoded_cert);
  tor_free(encoded_cert);

 done:
  return encoded;
}

/* Encode an introduction point onion key. Return a newly allocated string
 * with it. On failure, return NULL. */
static char *
encode_onion_key(const hs_desc_intro_point_t *ip)
{
  char *encoded = NULL;
  char key_b64[CURVE25519_BASE64_PADDED_LEN + 1];

  tor_assert(ip);

  /* Base64 encode the encryption key for the "onion-key" field. */
  if (curve25519_public_to_base64(key_b64, &ip->onion_key) < 0) {
    goto done;
  }
  tor_asprintf(&encoded, "%s ntor %s", str_ip_onion_key, key_b64);

 done:
  return encoded;
}

/* Encode an introduction point object and return a newly allocated string
 * with it. On failure, return NULL. */
static char *
encode_intro_point(const ed25519_public_key_t *sig_key,
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

  /* Onion key encoding. */
  {
    char *encoded_onion_key = encode_onion_key(ip);
    if (encoded_onion_key == NULL) {
      goto err;
    }
    smartlist_add_asprintf(lines, "%s", encoded_onion_key);
    tor_free(encoded_onion_key);
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
    char *encoded_enc_key = encode_enc_key(ip);
    if (encoded_enc_key == NULL) {
      goto err;
    }
    smartlist_add_asprintf(lines, "%s", encoded_enc_key);
    tor_free(encoded_enc_key);
  }

  /* Legacy key if any. */
  if (ip->legacy.key != NULL) {
    /* Strong requirement else the IP creation was badly done. */
    tor_assert(ip->legacy.cert.encoded);
    char *encoded_legacy_key = encode_legacy_key(ip);
    if (encoded_legacy_key == NULL) {
      goto err;
    }
    smartlist_add_asprintf(lines, "%s", encoded_legacy_key);
    tor_free(encoded_legacy_key);
  }

  /* Join them all in one blob of text. */
  encoded_ip = smartlist_join_strings(lines, "\n", 1, NULL);

 err:
  SMARTLIST_FOREACH(lines, char *, l, tor_free(l));
  smartlist_free(lines);
  return encoded_ip;
}

/* Given a source length, return the new size including padding for the
 * plaintext encryption. */
static size_t
compute_padded_plaintext_length(size_t plaintext_len)
{
  size_t plaintext_padded_len;
  const int padding_block_length = HS_DESC_SUPERENC_PLAINTEXT_PAD_MULTIPLE;

  /* Make sure we won't overflow. */
  tor_assert(plaintext_len <= (SIZE_T_CEILING - padding_block_length));

  /* Get the extra length we need to add. For example, if srclen is 10200
   * bytes, this will expand to (2 * 10k) == 20k thus an extra 9800 bytes. */
  plaintext_padded_len = CEIL_DIV(plaintext_len, padding_block_length) *
                         padding_block_length;
  /* Can never be extra careful. Make sure we are _really_ padded. */
  tor_assert(!(plaintext_padded_len % padding_block_length));
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
                size_t plaintext_len, uint8_t **encrypted_out,
                int is_superencrypted_layer)
{
  size_t encrypted_len;
  uint8_t *padded_plaintext, *encrypted;
  crypto_cipher_t *cipher;

  tor_assert(key);
  tor_assert(iv);
  tor_assert(plaintext);
  tor_assert(encrypted_out);

  /* If we are encrypting the middle layer of the descriptor, we need to first
     pad the plaintext */
  if (is_superencrypted_layer) {
    encrypted_len = build_plaintext_padding(plaintext, plaintext_len,
                                            &padded_plaintext);
    /* Extra precautions that we have a valid padding length. */
    tor_assert(!(encrypted_len % HS_DESC_SUPERENC_PLAINTEXT_PAD_MULTIPLE));
  } else { /* No padding required for inner layers */
    padded_plaintext = tor_memdup(plaintext, plaintext_len);
    encrypted_len = plaintext_len;
  }

  /* This creates a cipher for AES. It can't fail. */
  cipher = crypto_cipher_new_with_iv_and_bits(key, iv,
                                              HS_DESC_ENCRYPTED_BIT_SIZE);
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

/* Encrypt the given <b>plaintext</b> buffer using <b>desc</b> to get the
 * keys. Set encrypted_out with the encrypted data and return the length of
 * it. <b>is_superencrypted_layer</b> is set if this is the outer encrypted
 * layer of the descriptor. */
static size_t
encrypt_descriptor_data(const hs_descriptor_t *desc, const char *plaintext,
                        char **encrypted_out, int is_superencrypted_layer)
{
  char *final_blob;
  size_t encrypted_len, final_blob_len, offset = 0;
  uint8_t *encrypted;
  uint8_t salt[HS_DESC_ENCRYPTED_SALT_LEN];
  uint8_t secret_key[HS_DESC_ENCRYPTED_KEY_LEN], secret_iv[CIPHER_IV_LEN];
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
                          mac_key, sizeof(mac_key),
                          is_superencrypted_layer);

  /* Build the encrypted part that is do the actual encryption. */
  encrypted_len = build_encrypted(secret_key, secret_iv, plaintext,
                                  strlen(plaintext), &encrypted,
                                  is_superencrypted_layer);
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

/* Create and return a string containing a fake client-auth entry. It's the
 * responsibility of the caller to free the returned string. This function will
 * never fail. */
static char *
get_fake_auth_client_str(void)
{
  char *auth_client_str = NULL;
  /* We are gonna fill these arrays with fake base64 data. They are all double
   * the size of their binary representation to fit the base64 overhead. */
  char client_id_b64[8*2];
  char iv_b64[16*2];
  char encrypted_cookie_b64[16*2];
  int retval;

  /* This is a macro to fill a field with random data and then base64 it. */
#define FILL_WITH_FAKE_DATA_AND_BASE64(field) STMT_BEGIN         \
  crypto_rand((char *)field, sizeof(field));                     \
  retval = base64_encode_nopad(field##_b64, sizeof(field##_b64), \
                               field, sizeof(field));            \
  tor_assert(retval > 0);                                        \
  STMT_END

  { /* Get those fakes! */
    uint8_t client_id[8]; /* fake client-id */
    uint8_t iv[16]; /* fake IV (initialization vector) */
    uint8_t encrypted_cookie[16]; /* fake encrypted cookie */

    FILL_WITH_FAKE_DATA_AND_BASE64(client_id);
    FILL_WITH_FAKE_DATA_AND_BASE64(iv);
    FILL_WITH_FAKE_DATA_AND_BASE64(encrypted_cookie);
  }

  /* Build the final string */
  tor_asprintf(&auth_client_str, "%s %s %s %s", str_desc_auth_client,
               client_id_b64, iv_b64, encrypted_cookie_b64);

#undef FILL_WITH_FAKE_DATA_AND_BASE64

  return auth_client_str;
}

/** How many lines of "client-auth" we want in our descriptors; fake or not. */
#define CLIENT_AUTH_ENTRIES_BLOCK_SIZE 16

/** Create the "client-auth" part of the descriptor and return a
 *  newly-allocated string with it. It's the responsibility of the caller to
 *  free the returned string. */
static char *
get_fake_auth_client_lines(void)
{
  /* XXX: Client authorization is still not implemented, so all this function
     does is make fake clients */
  int i = 0;
  smartlist_t *auth_client_lines = smartlist_new();
  char *auth_client_lines_str = NULL;

  /* Make a line for each fake client */
  const int num_fake_clients = CLIENT_AUTH_ENTRIES_BLOCK_SIZE;
  for (i = 0; i < num_fake_clients; i++) {
    char *auth_client_str = get_fake_auth_client_str();
    tor_assert(auth_client_str);
    smartlist_add(auth_client_lines, auth_client_str);
  }

  /* Join all lines together to form final string */
  auth_client_lines_str = smartlist_join_strings(auth_client_lines,
                                                 "\n", 1, NULL);
  /* Cleanup the mess */
  SMARTLIST_FOREACH(auth_client_lines, char *, a, tor_free(a));
  smartlist_free(auth_client_lines);

  return auth_client_lines_str;
}

/* Create the inner layer of the descriptor (which includes the intro points,
 * etc.). Return a newly-allocated string with the layer plaintext, or NULL if
 * an error occured. It's the responsibility of the caller to free the returned
 * string. */
static char *
get_inner_encrypted_layer_plaintext(const hs_descriptor_t *desc)
{
  char *encoded_str = NULL;
  smartlist_t *lines = smartlist_new();

  /* Build the start of the section prior to the introduction points. */
  {
    if (!desc->encrypted_data.create2_ntor) {
      log_err(LD_BUG, "HS desc doesn't have recognized handshake type.");
      goto err;
    }
    smartlist_add_asprintf(lines, "%s %d\n", str_create2_formats,
                           ONION_HANDSHAKE_TYPE_NTOR);

    if (desc->encrypted_data.intro_auth_types &&
        smartlist_len(desc->encrypted_data.intro_auth_types)) {
      /* Put the authentication-required line. */
      char *buf = smartlist_join_strings(desc->encrypted_data.intro_auth_types,
                                         " ", 0, NULL);
      smartlist_add_asprintf(lines, "%s %s\n", str_intro_auth_required, buf);
      tor_free(buf);
    }

    if (desc->encrypted_data.single_onion_service) {
      smartlist_add_asprintf(lines, "%s\n", str_single_onion);
    }
  }

  /* Build the introduction point(s) section. */
  SMARTLIST_FOREACH_BEGIN(desc->encrypted_data.intro_points,
                          const hs_desc_intro_point_t *, ip) {
    char *encoded_ip = encode_intro_point(&desc->plaintext_data.signing_pubkey,
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

 err:
  SMARTLIST_FOREACH(lines, char *, l, tor_free(l));
  smartlist_free(lines);

  return encoded_str;
}

/* Create the middle layer of the descriptor, which includes the client auth
 * data and the encrypted inner layer (provided as a base64 string at
 * <b>layer2_b64_ciphertext</b>). Return a newly-allocated string with the
 * layer plaintext, or NULL if an error occured. It's the responsibility of the
 * caller to free the returned string. */
static char *
get_outer_encrypted_layer_plaintext(const hs_descriptor_t *desc,
                                    const char *layer2_b64_ciphertext)
{
  char *layer1_str = NULL;
  smartlist_t *lines = smartlist_new();

  /* XXX: Disclaimer: This function generates only _fake_ client auth
   * data. Real client auth is not yet implemented, but client auth data MUST
   * always be present in descriptors. In the future this function will be
   * refactored to use real client auth data if they exist (#20700). */
  (void) *desc;

  /* Specify auth type */
  smartlist_add_asprintf(lines, "%s %s\n", str_desc_auth_type, "x25519");

  {  /* Create fake ephemeral x25519 key */
    char fake_key_base64[CURVE25519_BASE64_PADDED_LEN + 1];
    curve25519_keypair_t fake_x25519_keypair;
    if (curve25519_keypair_generate(&fake_x25519_keypair, 0) < 0) {
      goto done;
    }
    if (curve25519_public_to_base64(fake_key_base64,
                                    &fake_x25519_keypair.pubkey) < 0) {
      goto done;
    }
    smartlist_add_asprintf(lines, "%s %s\n",
                           str_desc_auth_key, fake_key_base64);
    /* No need to memwipe any of these fake keys. They will go unused. */
  }

  {  /* Create fake auth-client lines. */
    char *auth_client_lines = get_fake_auth_client_lines();
    tor_assert(auth_client_lines);
    smartlist_add(lines, auth_client_lines);
  }

  /* create encrypted section */
  {
    smartlist_add_asprintf(lines,
                           "%s\n"
                           "-----BEGIN MESSAGE-----\n"
                           "%s"
                           "-----END MESSAGE-----",
                           str_encrypted, layer2_b64_ciphertext);
  }

  layer1_str = smartlist_join_strings(lines, "", 0, NULL);

 done:
  SMARTLIST_FOREACH(lines, char *, a, tor_free(a));
  smartlist_free(lines);

  return layer1_str;
}

/* Encrypt <b>encoded_str</b> into an encrypted blob and then base64 it before
 * returning it. <b>desc</b> is provided to derive the encryption
 * keys. <b>is_superencrypted_layer</b> is set if <b>encoded_str</b> is the
 * middle (superencrypted) layer of the descriptor. It's the responsibility of
 * the caller to free the returned string. */
static char *
encrypt_desc_data_and_base64(const hs_descriptor_t *desc,
                             const char *encoded_str,
                             int is_superencrypted_layer)
{
  char *enc_b64;
  ssize_t enc_b64_len, ret_len, enc_len;
  char *encrypted_blob = NULL;

  enc_len = encrypt_descriptor_data(desc, encoded_str, &encrypted_blob,
                                    is_superencrypted_layer);
  /* Get the encoded size plus a NUL terminating byte. */
  enc_b64_len = base64_encode_size(enc_len, BASE64_ENCODE_MULTILINE) + 1;
  enc_b64 = tor_malloc_zero(enc_b64_len);
  /* Base64 the encrypted blob before returning it. */
  ret_len = base64_encode(enc_b64, enc_b64_len, encrypted_blob, enc_len,
                          BASE64_ENCODE_MULTILINE);
  /* Return length doesn't count the NUL byte. */
  tor_assert(ret_len == (enc_b64_len - 1));
  tor_free(encrypted_blob);

  return enc_b64;
}

/* Generate and encode the superencrypted portion of <b>desc</b>. This also
 * involves generating the encrypted portion of the descriptor, and performing
 * the superencryption. A newly allocated NUL-terminated string pointer
 * containing the encrypted encoded blob is put in encrypted_blob_out. Return 0
 * on success else a negative value. */
static int
encode_superencrypted_data(const hs_descriptor_t *desc,
                           char **encrypted_blob_out)
{
  int ret = -1;
  char *layer2_str = NULL;
  char *layer2_b64_ciphertext = NULL;
  char *layer1_str = NULL;
  char *layer1_b64_ciphertext = NULL;

  tor_assert(desc);
  tor_assert(encrypted_blob_out);

  /* Func logic: We first create the inner layer of the descriptor (layer2).
   * We then encrypt it and use it to create the middle layer of the descriptor
   * (layer1).  Finally we superencrypt the middle layer and return it to our
   * caller. */

  /* Create inner descriptor layer */
  layer2_str = get_inner_encrypted_layer_plaintext(desc);
  if (!layer2_str) {
    goto err;
  }

  /* Encrypt and b64 the inner layer */
  layer2_b64_ciphertext = encrypt_desc_data_and_base64(desc, layer2_str, 0);
  if (!layer2_b64_ciphertext) {
    goto err;
  }

  /* Now create middle descriptor layer given the inner layer */
  layer1_str = get_outer_encrypted_layer_plaintext(desc,layer2_b64_ciphertext);
  if (!layer1_str) {
    goto err;
  }

  /* Encrypt and base64 the middle layer */
  layer1_b64_ciphertext = encrypt_desc_data_and_base64(desc, layer1_str, 1);
  if (!layer1_b64_ciphertext) {
    goto err;
  }

  /* Success! */
  ret = 0;

 err:
  tor_free(layer1_str);
  tor_free(layer2_str);
  tor_free(layer2_b64_ciphertext);

  *encrypted_blob_out = layer1_b64_ciphertext;
  return ret;
}

/* Encode a v3 HS descriptor. Return 0 on success and set encoded_out to the
 * newly allocated string of the encoded descriptor. On error, -1 is returned
 * and encoded_out is untouched. */
static int
desc_encode_v3(const hs_descriptor_t *desc,
               const ed25519_keypair_t *signing_kp, char **encoded_out)
{
  int ret = -1;
  char *encoded_str = NULL;
  size_t encoded_len;
  smartlist_t *lines = smartlist_new();

  tor_assert(desc);
  tor_assert(signing_kp);
  tor_assert(encoded_out);
  tor_assert(desc->plaintext_data.version == 3);

  if (BUG(desc->subcredential == NULL)) {
    goto err;
  }

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

  /* Build the superencrypted data section. */
  {
    char *enc_b64_blob=NULL;
    if (encode_superencrypted_data(desc, &enc_b64_blob) < 0) {
      goto err;
    }
    smartlist_add_asprintf(lines,
                           "%s\n"
                           "-----BEGIN MESSAGE-----\n"
                           "%s"
                           "-----END MESSAGE-----",
                           str_superencrypted, enc_b64_blob);
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
                              str_desc_sig_prefix, signing_kp) < 0) {
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

  if (strlen(encoded_str) >= hs_cache_get_max_descriptor_size()) {
    log_warn(LD_GENERAL, "We just made an HS descriptor that's too big (%d)."
             "Failing.", (int)strlen(encoded_str));
    tor_free(encoded_str);
    goto err;
  }

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
    case LS_ED25519_ID:
      /* Both are known at compile time so let's make sure they are the same
       * else we can copy memory out of bound. */
      tor_assert(link_specifier_getlen_un_ed25519_id(ls) ==
                 sizeof(hs_spec->u.ed25519_id));
      memcpy(hs_spec->u.ed25519_id,
             link_specifier_getconstarray_un_ed25519_id(ls),
             sizeof(hs_spec->u.ed25519_id));
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

  desc->intro_auth_types = smartlist_new();
  smartlist_split_string(desc->intro_auth_types, list, " ", 0, 0);

  /* Validate the types that we at least know about one. */
  SMARTLIST_FOREACH_BEGIN(desc->intro_auth_types, const char *, auth) {
    for (int idx = 0; intro_auth_types[idx].identifier; idx++) {
      if (!strncmp(auth, intro_auth_types[idx].identifier,
                   strlen(intro_auth_types[idx].identifier))) {
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
  if (tor_cert_checksig(cert, &cert->signing_key, approx_time()) < 0) {
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
  /* Make sure there is enough data for the salt and the mac. The equality is
     there to ensure that there is at least one byte of encrypted data. */
  if (len <= HS_DESC_ENCRYPTED_SALT_LEN + DIGEST256_LEN) {
    log_warn(LD_REND, "Length of descriptor's encrypted data is too small. "
                      "Got %lu but minimum value is %d",
             (unsigned long)len, HS_DESC_ENCRYPTED_SALT_LEN + DIGEST256_LEN);
    goto err;
  }

  return 1;
 err:
  return 0;
}

/** Decrypt an encrypted descriptor layer at <b>encrypted_blob</b> of size
 *  <b>encrypted_blob_size</b>. Use the descriptor object <b>desc</b> to
 *  generate the right decryption keys; set <b>decrypted_out</b> to the
 *  plaintext. If <b>is_superencrypted_layer</b> is set, this is the outter
 *  encrypted layer of the descriptor.
 *
 * On any error case, including an empty output, return 0 and set
 * *<b>decrypted_out</b> to NULL.
 */
MOCK_IMPL(STATIC size_t,
decrypt_desc_layer,(const hs_descriptor_t *desc,
                    const uint8_t *encrypted_blob,
                    size_t encrypted_blob_size,
                    int is_superencrypted_layer,
                    char **decrypted_out))
{
  uint8_t *decrypted = NULL;
  uint8_t secret_key[HS_DESC_ENCRYPTED_KEY_LEN], secret_iv[CIPHER_IV_LEN];
  uint8_t mac_key[DIGEST256_LEN], our_mac[DIGEST256_LEN];
  const uint8_t *salt, *encrypted, *desc_mac;
  size_t encrypted_len, result_len = 0;

  tor_assert(decrypted_out);
  tor_assert(desc);
  tor_assert(encrypted_blob);

  /* Construction is as follow: SALT | ENCRYPTED_DATA | MAC .
   * Make sure we have enough space for all these things. */
  if (!encrypted_data_length_is_valid(encrypted_blob_size)) {
    goto err;
  }

  /* Start of the blob thus the salt. */
  salt = encrypted_blob;

  /* Next is the encrypted data. */
  encrypted = encrypted_blob + HS_DESC_ENCRYPTED_SALT_LEN;
  encrypted_len = encrypted_blob_size -
    (HS_DESC_ENCRYPTED_SALT_LEN + DIGEST256_LEN);
  tor_assert(encrypted_len > 0); /* guaranteed by the check above */

  /* And last comes the MAC. */
  desc_mac = encrypted_blob + encrypted_blob_size - DIGEST256_LEN;

  /* KDF construction resulting in a key from which the secret key, IV and MAC
   * key are extracted which is what we need for the decryption. */
  build_secret_key_iv_mac(desc, salt, HS_DESC_ENCRYPTED_SALT_LEN,
                          secret_key, sizeof(secret_key),
                          secret_iv, sizeof(secret_iv),
                          mac_key, sizeof(mac_key),
                          is_superencrypted_layer);

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

    cipher = crypto_cipher_new_with_iv_and_bits(secret_key, secret_iv,
                                                HS_DESC_ENCRYPTED_BIT_SIZE);
    /* Extra byte for the NUL terminated byte. */
    decrypted = tor_malloc_zero(encrypted_len + 1);
    crypto_cipher_decrypt(cipher, (char *) decrypted,
                          (const char *) encrypted, encrypted_len);
    crypto_cipher_free(cipher);
  }

  {
    /* Adjust length to remove NUL padding bytes */
    uint8_t *end = memchr(decrypted, 0, encrypted_len);
    result_len = encrypted_len;
    if (end) {
      result_len = end - decrypted;
    }
  }

  if (result_len == 0) {
    /* Treat this as an error, so that somebody will free the output. */
    goto err;
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

/* Basic validation that the superencrypted client auth portion of the
 * descriptor is well-formed and recognized. Return True if so, otherwise
 * return False. */
static int
superencrypted_auth_data_is_valid(smartlist_t *tokens)
{
  /* XXX: This is just basic validation for now. When we implement client auth,
     we can refactor this function so that it actually parses and saves the
     data. */

  { /* verify desc auth type */
    const directory_token_t *tok;
    tok = find_by_keyword(tokens, R3_DESC_AUTH_TYPE);
    tor_assert(tok->n_args >= 1);
    if (strcmp(tok->args[0], "x25519")) {
      log_warn(LD_DIR, "Unrecognized desc auth type");
      return 0;
    }
  }

  { /* verify desc auth key */
    const directory_token_t *tok;
    curve25519_public_key_t k;
    tok = find_by_keyword(tokens, R3_DESC_AUTH_KEY);
    tor_assert(tok->n_args >= 1);
    if (curve25519_public_from_base64(&k, tok->args[0]) < 0) {
      log_warn(LD_DIR, "Bogus desc auth key in HS desc");
      return 0;
    }
  }

  /* verify desc auth client items */
  SMARTLIST_FOREACH_BEGIN(tokens, const directory_token_t *, tok) {
    if (tok->tp == R3_DESC_AUTH_CLIENT) {
      tor_assert(tok->n_args >= 3);
    }
  } SMARTLIST_FOREACH_END(tok);

  return 1;
}

/* Parse <b>message</b>, the plaintext of the superencrypted portion of an HS
 * descriptor. Set <b>encrypted_out</b> to the encrypted blob, and return its
 * size */
STATIC size_t
decode_superencrypted(const char *message, size_t message_len,
                     uint8_t **encrypted_out)
{
  int retval = 0;
  memarea_t *area = NULL;
  smartlist_t *tokens = NULL;

  area = memarea_new();
  tokens = smartlist_new();
  if (tokenize_string(area, message, message + message_len, tokens,
                      hs_desc_superencrypted_v3_token_table, 0) < 0) {
    log_warn(LD_REND, "Superencrypted portion is not parseable");
    goto err;
  }

  /* Do some rudimentary validation of the authentication data */
  if (!superencrypted_auth_data_is_valid(tokens)) {
    log_warn(LD_REND, "Invalid auth data");
    goto err;
  }

  /* Extract the encrypted data section. */
  {
    const directory_token_t *tok;
    tok = find_by_keyword(tokens, R3_ENCRYPTED);
    tor_assert(tok->object_body);
    if (strcmp(tok->object_type, "MESSAGE") != 0) {
      log_warn(LD_REND, "Desc superencrypted data section is invalid");
      goto err;
    }
    /* Make sure the length of the encrypted blob is valid. */
    if (!encrypted_data_length_is_valid(tok->object_size)) {
      goto err;
    }

    /* Copy the encrypted blob to the descriptor object so we can handle it
     * latter if needed. */
    tor_assert(tok->object_size <= INT_MAX);
    *encrypted_out = tor_memdup(tok->object_body, tok->object_size);
    retval = (int) tok->object_size;
  }

 err:
  SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
  smartlist_free(tokens);
  if (area) {
    memarea_drop_all(area);
  }

  return retval;
}

/* Decrypt both the superencrypted and the encrypted section of the descriptor
 * using the given descriptor object <b>desc</b>. A newly allocated NUL
 * terminated string is put in decrypted_out which contains the inner encrypted
 * layer of the descriptor. Return the length of decrypted_out on success else
 * 0 is returned and decrypted_out is set to NULL. */
static size_t
desc_decrypt_all(const hs_descriptor_t *desc, char **decrypted_out)
{
  size_t  decrypted_len = 0;
  size_t encrypted_len = 0;
  size_t superencrypted_len = 0;
  char *superencrypted_plaintext = NULL;
  uint8_t *encrypted_blob = NULL;

  /** Function logic: This function takes us from the descriptor header to the
   *  inner encrypted layer, by decrypting and decoding the middle descriptor
   *  layer. In the end we return the contents of the inner encrypted layer to
   *  our caller. */

  /* 1. Decrypt middle layer of descriptor */
  superencrypted_len = decrypt_desc_layer(desc,
                                 desc->plaintext_data.superencrypted_blob,
                                 desc->plaintext_data.superencrypted_blob_size,
                                 1,
                                 &superencrypted_plaintext);
  if (!superencrypted_len) {
    log_warn(LD_REND, "Decrypting superencrypted desc failed.");
    goto err;
  }
  tor_assert(superencrypted_plaintext);

  /* 2. Parse "superencrypted" */
  encrypted_len = decode_superencrypted(superencrypted_plaintext,
                                        superencrypted_len,
                                        &encrypted_blob);
  if (!encrypted_len) {
    log_warn(LD_REND, "Decrypting encrypted desc failed.");
    goto err;
  }
  tor_assert(encrypted_blob);

  /* 3. Decrypt "encrypted" and set decrypted_out */
  char *decrypted_desc;
  decrypted_len = decrypt_desc_layer(desc,
                                     encrypted_blob, encrypted_len,
                                     0, &decrypted_desc);
  if (!decrypted_len) {
    log_warn(LD_REND, "Decrypting encrypted desc failed.");
    goto err;
  }
  tor_assert(decrypted_desc);

  *decrypted_out = decrypted_desc;

 err:
  tor_free(superencrypted_plaintext);
  tor_free(encrypted_blob);

  return decrypted_len;
}

/* Given the token tok for an intro point legacy key, the list of tokens, the
 * introduction point ip being decoded and the descriptor desc from which it
 * comes from, decode the legacy key and set the intro point object. Return 0
 * on success else -1 on failure. */
static int
decode_intro_legacy_key(const directory_token_t *tok,
                        smartlist_t *tokens,
                        hs_desc_intro_point_t *ip,
                        const hs_descriptor_t *desc)
{
  tor_assert(tok);
  tor_assert(tokens);
  tor_assert(ip);
  tor_assert(desc);

  if (!crypto_pk_public_exponent_ok(tok->key)) {
    log_warn(LD_REND, "Introduction point legacy key is invalid");
    goto err;
  }
  ip->legacy.key = crypto_pk_dup_key(tok->key);
  /* Extract the legacy cross certification cert which MUST be present if we
   * have a legacy key. */
  tok = find_opt_by_keyword(tokens, R3_INTRO_LEGACY_KEY_CERT);
  if (!tok) {
    log_warn(LD_REND, "Introduction point legacy key cert is missing");
    goto err;
  }
  tor_assert(tok->object_body);
  if (strcmp(tok->object_type, "CROSSCERT")) {
    /* Info level because this might be an unknown field that we should
     * ignore. */
    log_info(LD_REND, "Introduction point legacy encryption key "
                      "cross-certification has an unknown format.");
    goto err;
  }
  /* Keep a copy of the certificate. */
  ip->legacy.cert.encoded = tor_memdup(tok->object_body, tok->object_size);
  ip->legacy.cert.len = tok->object_size;
  /* The check on the expiration date is for the entire lifetime of a
   * certificate which is 24 hours. However, a descriptor has a maximum
   * lifetime of 12 hours meaning we have a 12h difference between the two
   * which ultimately accomodate the clock skewed client. */
  if (rsa_ed25519_crosscert_check(ip->legacy.cert.encoded,
                                  ip->legacy.cert.len, ip->legacy.key,
                                  &desc->plaintext_data.signing_pubkey,
                                  approx_time() - HS_DESC_CERT_LIFETIME)) {
    log_warn(LD_REND, "Unable to check cross-certification on the "
                      "introduction point legacy encryption key.");
    ip->cross_certified = 0;
    goto err;
  }

  /* Success. */
  return 0;
 err:
  return -1;
}

/* Dig into the descriptor <b>tokens</b> to find the onion key we should use
 * for this intro point, and set it into <b>onion_key_out</b>. Return 0 if it
 * was found and well-formed, otherwise return -1 in case of errors. */
static int
set_intro_point_onion_key(curve25519_public_key_t *onion_key_out,
                          const smartlist_t *tokens)
{
  int retval = -1;
  smartlist_t *onion_keys = NULL;

  tor_assert(onion_key_out);

  onion_keys = find_all_by_keyword(tokens, R3_INTRO_ONION_KEY);
  if (!onion_keys) {
    log_warn(LD_REND, "Descriptor did not contain intro onion keys");
    goto err;
  }

  SMARTLIST_FOREACH_BEGIN(onion_keys, directory_token_t *, tok) {
    /* This field is using GE(2) so for possible forward compatibility, we
     * accept more fields but must be at least 2. */
    tor_assert(tok->n_args >= 2);

    /* Try to find an ntor key, it's the only recognized type right now */
    if (!strcmp(tok->args[0], "ntor")) {
      if (curve25519_public_from_base64(onion_key_out, tok->args[1]) < 0) {
        log_warn(LD_REND, "Introduction point ntor onion-key is invalid");
        goto err;
      }
      /* Got the onion key! Set the appropriate retval */
      retval = 0;
    }
  } SMARTLIST_FOREACH_END(tok);

  /* Log an error if we didn't find it :( */
  if (retval < 0) {
    log_warn(LD_REND, "Descriptor did not contain ntor onion keys");
  }

 err:
  smartlist_free(onion_keys);
  return retval;
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
  ip = hs_desc_intro_point_new();

  /* "introduction-point" SP link-specifiers NL */
  tok = find_by_keyword(tokens, R3_INTRODUCTION_POINT);
  tor_assert(tok->n_args == 1);
  /* Our constructor creates this list by default so free it. */
  smartlist_free(ip->link_specifiers);
  ip->link_specifiers = decode_link_specifiers(tok->args[0]);
  if (!ip->link_specifiers) {
    log_warn(LD_REND, "Introduction point has invalid link specifiers");
    goto err;
  }

  /* "onion-key" SP ntor SP key NL */
  if (set_intro_point_onion_key(&ip->onion_key, tokens) < 0) {
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
  /* Validate authentication certificate with descriptor signing key. */
  if (tor_cert_checksig(ip->auth_key_cert,
                        &desc->plaintext_data.signing_pubkey, 0) < 0) {
    log_warn(LD_REND, "Invalid authentication key signature");
    goto err;
  }

  /* Exactly one "enc-key" SP "ntor" SP key NL */
  tok = find_by_keyword(tokens, R3_INTRO_ENC_KEY);
  if (!strcmp(tok->args[0], "ntor")) {
    /* This field is using GE(2) so for possible forward compatibility, we
     * accept more fields but must be at least 2. */
    tor_assert(tok->n_args >= 2);

    if (curve25519_public_from_base64(&ip->enc_key, tok->args[1]) < 0) {
      log_warn(LD_REND, "Introduction point ntor enc-key is invalid");
      goto err;
    }
  } else {
    /* Unknown key type so we can't use that introduction point. */
    log_warn(LD_REND, "Introduction point encryption key is unrecognized.");
    goto err;
  }

  /* Exactly once "enc-key-cert" NL certificate NL */
  tok = find_by_keyword(tokens, R3_INTRO_ENC_KEY_CERT);
  tor_assert(tok->object_body);
  /* Do the cross certification. */
  if (strcmp(tok->object_type, "ED25519 CERT")) {
      log_warn(LD_REND, "Introduction point ntor encryption key "
                        "cross-certification has an unknown format.");
      goto err;
  }
  if (cert_parse_and_validate(&ip->enc_key_cert, tok->object_body,
                              tok->object_size, CERT_TYPE_CROSS_HS_IP_KEYS,
                              "introduction point enc-key-cert") < 0) {
    goto err;
  }
  if (tor_cert_checksig(ip->enc_key_cert,
                        &desc->plaintext_data.signing_pubkey, 0) < 0) {
    log_warn(LD_REND, "Invalid encryption key signature");
    goto err;
  }
  /* It is successfully cross certified. Flag the object. */
  ip->cross_certified = 1;

  /* Do we have a "legacy-key" SP key NL ?*/
  tok = find_opt_by_keyword(tokens, R3_INTRO_LEGACY_KEY);
  if (tok) {
    if (decode_intro_legacy_key(tok, tokens, ip, desc) < 0) {
      goto err;
    }
  }

  /* Introduction point has been parsed successfully. */
  goto done;

 err:
  hs_desc_intro_point_free(ip);
  ip = NULL;

 done:
  SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_clear(t));
  smartlist_free(tokens);
  if (area) {
    memarea_drop_all(area);
  }

  return ip;
}

/* Given a descriptor string at <b>data</b>, decode all possible introduction
 * points that we can find. Add the introduction point object to desc_enc as we
 * find them. This function can't fail and it is possible that zero
 * introduction points can be decoded. */
static void
decode_intro_points(const hs_descriptor_t *desc,
                    hs_desc_encrypted_data_t *desc_enc,
                    const char *data)
{
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
      /* Malformed introduction point section. We'll ignore this introduction
       * point and continue parsing. New or unknown fields are possible for
       * forward compatibility. */
      continue;
    }
    smartlist_add(desc_enc->intro_points, ip);
  } SMARTLIST_FOREACH_END(intro_point);

 done:
  SMARTLIST_FOREACH(chunked_desc, char *, a, tor_free(a));
  smartlist_free(chunked_desc);
  SMARTLIST_FOREACH(intro_points, char *, a, tor_free(a));
  smartlist_free(intro_points);
}
/* Return 1 iff the given base64 encoded signature in b64_sig from the encoded
 * descriptor in encoded_desc validates the descriptor content. */
STATIC int
desc_sig_is_valid(const char *b64_sig,
                  const ed25519_public_key_t *signing_pubkey,
                  const char *encoded_desc, size_t encoded_len)
{
  int ret = 0;
  ed25519_signature_t sig;
  const char *sig_start;

  tor_assert(b64_sig);
  tor_assert(signing_pubkey);
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
  if (!sig_start) {
    log_warn(LD_GENERAL, "Malformed signature line. Rejecting.");
    goto err;
  }
  /* Skip newline, it has to go in the signature check. */
  sig_start++;

  /* Validate signature with the full body of the descriptor. */
  if (ed25519_checksig_prefixed(&sig,
                                (const uint8_t *) encoded_desc,
                                sig_start - encoded_desc,
                                str_desc_sig_prefix,
                                signing_pubkey) != 0) {
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

  /* Copy the public keys into signing_pubkey and blinded_pubkey */
  memcpy(&desc->signing_pubkey, &desc->signing_key_cert->signed_key,
         sizeof(ed25519_public_key_t));
  memcpy(&desc->blinded_pubkey, &desc->signing_key_cert->signing_key,
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
  tok = find_by_keyword(tokens, R3_SUPERENCRYPTED);
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
  desc->superencrypted_blob = tor_memdup(tok->object_body, tok->object_size);
  desc->superencrypted_blob_size = tok->object_size;

  /* Extract signature and verify it. */
  tok = find_by_keyword(tokens, R3_SIGNATURE);
  tor_assert(tok->n_args == 1);
  /* First arg here is the actual encoded signature. */
  if (!desc_sig_is_valid(tok->args[0], &desc->signing_pubkey,
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

  /* Decrypt the superencrypted data that is located in the plaintext section
   * in the descriptor as a blob of bytes. */
  message_len = desc_decrypt_all(desc, &message);
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
  tok = find_opt_by_keyword(tokens, R3_INTRO_AUTH_REQUIRED);
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
  decode_intro_points(desc, desc_encrypted_out, message);

  /* Validation of maximum introduction points allowed. */
  if (smartlist_len(desc_encrypted_out->intro_points) >
      HS_CONFIG_V3_MAX_INTRO_POINTS) {
    log_warn(LD_REND, "Service descriptor contains too many introduction "
                      "points. Maximum allowed is %d but we have %d",
             HS_CONFIG_V3_MAX_INTRO_POINTS,
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
  tor_assert(desc->plaintext_data.superencrypted_blob);
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

  /* Check that descriptor is within size limits. */
  encoded_len = strlen(encoded);
  if (encoded_len >= hs_cache_get_max_descriptor_size()) {
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
  int ret = -1;
  hs_descriptor_t *desc;

  tor_assert(encoded);

  desc = tor_malloc_zero(sizeof(hs_descriptor_t));

  /* Subcredentials are optional. */
  if (BUG(!subcredential)) {
    log_warn(LD_GENERAL, "Tried to decrypt without subcred. Impossible!");
    goto err;
  }

  memcpy(desc->subcredential, subcredential, sizeof(desc->subcredential));

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

/* Table of encode function version specific. The functions are indexed by the
 * version number so v3 callback is at index 3 in the array. */
static int
  (*encode_handlers[])(
      const hs_descriptor_t *desc,
      const ed25519_keypair_t *signing_kp,
      char **encoded_out) =
{
  /* v0 */ NULL, /* v1 */ NULL, /* v2 */ NULL,
  desc_encode_v3,
};

/* Encode the given descriptor desc including signing with the given key pair
 * signing_kp. On success, encoded_out points to a newly allocated NUL
 * terminated string that contains the encoded descriptor as a string.
 *
 * Return 0 on success and encoded_out is a valid pointer. On error, -1 is
 * returned and encoded_out is set to NULL. */
MOCK_IMPL(int,
hs_desc_encode_descriptor,(const hs_descriptor_t *desc,
                           const ed25519_keypair_t *signing_kp,
                           char **encoded_out))
{
  int ret = -1;
  uint32_t version;

  tor_assert(desc);
  tor_assert(encoded_out);

  /* Make sure we support the version of the descriptor format. */
  version = desc->plaintext_data.version;
  if (!hs_desc_is_supported_version(version)) {
    goto err;
  }
  /* Extra precaution. Having no handler for the supported version should
   * never happened else we forgot to add it but we bumped the version. */
  tor_assert(ARRAY_LENGTH(encode_handlers) >= version);
  tor_assert(encode_handlers[version]);

  ret = encode_handlers[version](desc, signing_kp, encoded_out);
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
          data->superencrypted_blob_size);
}

/* Return the size in bytes of the given encrypted data object. Used by OOM
 * subsystem. */
static size_t
hs_desc_encrypted_obj_size(const hs_desc_encrypted_data_t *data)
{
  tor_assert(data);
  size_t intro_size = 0;
  if (data->intro_auth_types) {
    intro_size +=
      smartlist_len(data->intro_auth_types) * sizeof(intro_auth_types);
  }
  if (data->intro_points) {
    /* XXX could follow pointers here and get more accurate size */
    intro_size +=
      smartlist_len(data->intro_points) * sizeof(hs_desc_intro_point_t);
  }

  return sizeof(*data) + intro_size;
}

/* Return the size in bytes of the given descriptor object. Used by OOM
 * subsystem. */
  size_t
hs_desc_obj_size(const hs_descriptor_t *data)
{
  tor_assert(data);
  return (hs_desc_plaintext_obj_size(&data->plaintext_data) +
          hs_desc_encrypted_obj_size(&data->encrypted_data) +
          sizeof(data->subcredential));
}

/* Return a newly allocated descriptor intro point. */
hs_desc_intro_point_t *
hs_desc_intro_point_new(void)
{
  hs_desc_intro_point_t *ip = tor_malloc_zero(sizeof(*ip));
  ip->link_specifiers = smartlist_new();
  return ip;
}

/* Free a descriptor intro point object. */
void
hs_desc_intro_point_free(hs_desc_intro_point_t *ip)
{
  if (ip == NULL) {
    return;
  }
  if (ip->link_specifiers) {
    SMARTLIST_FOREACH(ip->link_specifiers, hs_desc_link_specifier_t *,
                      ls, hs_desc_link_specifier_free(ls));
    smartlist_free(ip->link_specifiers);
  }
  tor_cert_free(ip->auth_key_cert);
  tor_cert_free(ip->enc_key_cert);
  crypto_pk_free(ip->legacy.key);
  tor_free(ip->legacy.cert.encoded);
  tor_free(ip);
}

/* Free the given descriptor link specifier. */
void
hs_desc_link_specifier_free(hs_desc_link_specifier_t *ls)
{
  if (ls == NULL) {
    return;
  }
  tor_free(ls);
}

/* Return a newly allocated descriptor link specifier using the given extend
 * info and requested type. Return NULL on error. */
hs_desc_link_specifier_t *
hs_desc_link_specifier_new(const extend_info_t *info, uint8_t type)
{
  hs_desc_link_specifier_t *ls = NULL;

  tor_assert(info);

  ls = tor_malloc_zero(sizeof(*ls));
  ls->type = type;
  switch (ls->type) {
  case LS_IPV4:
    if (info->addr.family != AF_INET) {
      goto err;
    }
    tor_addr_copy(&ls->u.ap.addr, &info->addr);
    ls->u.ap.port = info->port;
    break;
  case LS_IPV6:
    if (info->addr.family != AF_INET6) {
      goto err;
    }
    tor_addr_copy(&ls->u.ap.addr, &info->addr);
    ls->u.ap.port = info->port;
    break;
  case LS_LEGACY_ID:
    /* Bug out if the identity digest is not set */
    if (BUG(tor_mem_is_zero(info->identity_digest,
                            sizeof(info->identity_digest)))) {
      goto err;
    }
    memcpy(ls->u.legacy_id, info->identity_digest, sizeof(ls->u.legacy_id));
    break;
  case LS_ED25519_ID:
    /* ed25519 keys are optional for intro points */
    if (ed25519_public_key_is_zero(&info->ed_identity)) {
      goto err;
    }
    memcpy(ls->u.ed25519_id, info->ed_identity.pubkey,
           sizeof(ls->u.ed25519_id));
    break;
  default:
    /* Unknown type is code flow error. */
    tor_assert(0);
  }

  return ls;
 err:
  tor_free(ls);
  return NULL;
}

/* From the given descriptor, remove and free every introduction point. */
void
hs_descriptor_clear_intro_points(hs_descriptor_t *desc)
{
  smartlist_t *ips;

  tor_assert(desc);

  ips = desc->encrypted_data.intro_points;
  if (ips) {
    SMARTLIST_FOREACH(ips, hs_desc_intro_point_t *,
                      ip, hs_desc_intro_point_free(ip));
    smartlist_clear(ips);
  }
}

/* From a descriptor link specifier object spec, returned a newly allocated
 * link specifier object that is the encoded representation of spec. Return
 * NULL on error. */
link_specifier_t *
hs_desc_lspec_to_trunnel(const hs_desc_link_specifier_t *spec)
{
  tor_assert(spec);

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
  case LS_ED25519_ID:
  {
    size_t ed25519_id_len = link_specifier_getlen_un_ed25519_id(ls);
    uint8_t *ed25519_id_array = link_specifier_getarray_un_ed25519_id(ls);
    memcpy(ed25519_id_array, spec->u.ed25519_id, ed25519_id_len);
    link_specifier_set_ls_len(ls, ed25519_id_len);
    break;
  }
  default:
    tor_assert_nonfatal_unreached();
    link_specifier_free(ls);
    ls = NULL;
  }

  return ls;
}

