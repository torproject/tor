/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_descriptor.c
 * \brief Handle hidden service descriptor encoding/decoding.
 **/

#include "hs_descriptor.h"

#include "or.h"
#include "ed25519_cert.h" /* Trunnel interface. */

/* Constant string value used for the descriptor format. */
static const char *str_hs_desc = "hs-descriptor";
static const char *str_desc_cert = "descriptor-signing-key-cert";
static const char *str_rev_counter = "revision-counter";
static const char *str_encrypted = "encrypted";
static const char *str_signature = "signature";
static const char *str_lifetime = "descriptor-lifetime";
/* Constant string value for the encrypted part of the descriptor. */
static const char *str_create2_formats = "create2-formats";
static const char *str_auth_required = "authentication-required";
static const char *str_intro_point = "introduction-point";
static const char *str_ip_auth_key = "auth-key";
static const char *str_ip_enc_key = "enc-key";
static const char *str_ip_enc_key_cert = "enc-key-certification";
/* Constant string value for the construction to encrypt the encrypted data
 * section. */
static const char *str_enc_hsdir_data = "hsdir-encrypted-data";

/* Encode the ed25519 certificate <b>cert</b> and put the newly allocated
 * string in <b>cert_str_out</b>. Return 0 on success else a negative value. */
static int
encode_cert(const tor_cert_t *cert, char **cert_str_out)
{
  int ret = -1;
  char *ed_cert_b64 = NULL;
  size_t ed_cert_b64_len;

  tor_assert(cert);
  tor_assert(cert_str_out);

  /* Get the encoded size and add the NUL byte. */
  ed_cert_b64_len = base64_encode_size(cert->encoded_len,
                                       BASE64_ENCODE_MULTILINE) + 1;
  ed_cert_b64 = tor_malloc_zero(ed_cert_b64_len);

  /* Base64 encode the encoded certificate. */
  if (base64_encode(ed_cert_b64, ed_cert_b64_len,
                    (const char *) cert->encoded, cert->encoded_len,
                    BASE64_ENCODE_MULTILINE) < 0) {
    log_err(LD_BUG, "Couldn't base64-encode descriptor signing key cert!");
    goto err;
  }

  /* Put everything together in a NUL terminated string. */
  tor_asprintf(cert_str_out,
               "-----BEGIN ED25519 CERT-----\n"
               "%s"
               "-----END ED25519 CERT-----",
               ed_cert_b64);
  /* Success! */
  ret = 0;

err:
  tor_free(ed_cert_b64);
  return ret;
}

/* Encode the given link specifier objects into a newly allocated string.
 * This can't fail so caller can always assume a valid string being
 * returned. */
static char *
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
    uint8_t *cert_data;

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
      log_warn(LD_REND, "Unable to encode legacy crosscert.");
      goto err;
    }
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
    int signbit;
    char *encoded_cert, key_fp_b64[CURVE25519_BASE64_PADDED_LEN + 1];
    ed25519_keypair_t curve_kp;

    if (ed25519_keypair_from_curve25519_keypair(&curve_kp, &signbit,
                                                &ip->enc_key.curve25519)) {
      goto err;
    }
    tor_cert_t *cross_cert = tor_cert_create(&curve_kp, CERT_TYPE_HS_IP_ENC,
                                             &sig_key->pubkey, now,
                                             HS_DESC_CERT_LIFETIME,
                                             CERT_FLAG_INCLUDE_SIGNING_KEY);
    memwipe(&curve_kp, 0, sizeof(curve_kp));
    if (!cross_cert) {
      goto err;
    }
    if (encode_cert(cross_cert, &encoded_cert)) {
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
    if (encode_cert(ip->auth_key_cert, &encoded_cert) < 0) {
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
 * The length of the mac key and salt must be fixed and if not, you can't rely
 * on the result to be a valid MAC. We use SHA3-256 for the MAC computation.
 * This function can't fail. */
static void
build_mac(const uint8_t *mac_key, size_t mac_key_len,
          const uint8_t *salt, size_t salt_len,
          const uint8_t *encrypted, size_t encrypted_len,
          uint8_t *mac_out, size_t mac_len)
{
  crypto_digest_t *digest;

  tor_assert(mac_key);
  tor_assert(salt);
  tor_assert(encrypted);
  tor_assert(mac_out);

  digest = crypto_digest256_new(DIGEST_SHA3_256);
  /* As specified in section 2.5 of proposal 224, first add the mac key
   * then add the salt first and then the encrypted section. */
  crypto_digest_add_bytes(digest, (const char *) mac_key, mac_key_len);
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
static size_t
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
        != CERT_TYPE_HS_DESC_SIGN) {
      log_err(LD_BUG, "HS descriptor signing key has an unexpected cert type "
              "(%d)", (int) desc->plaintext_data.signing_key_cert->cert_type);
      goto err;
    }
    if (encode_cert(desc->plaintext_data.signing_key_cert,
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
    char *enc_b64_blob;
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
    /* XXX: Add signature prefix. */
    ed25519_signature_t sig;
    char ed_sig_b64[ED25519_SIG_BASE64_LEN + 1];
    if (ed25519_sign(&sig, (const uint8_t *) encoded_str, encoded_len,
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

  /* XXX: Decode the generated descriptor as an extra validation. */

  /* XXX: Trigger a control port event. */

  /* Success! */
  ret = 0;

 err:
  SMARTLIST_FOREACH(lines, char *, l, tor_free(l));
  smartlist_free(lines);
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
 * returned and encoded_out is untouched. */
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

 err:
  return ret;
}
