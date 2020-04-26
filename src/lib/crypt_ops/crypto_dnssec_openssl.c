/* Copyright (c) 2019 Christian Hofer.
 * Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypto_dnssec_openssl.c
 * \brief Functions to handle DNSSEC validation of DNS messages.
 **/

#define CRYPTO_DNSSEC_PRIVATE
#include "lib/crypt_ops/crypto_dnssec.h"

#include "lib/crypt_ops/compat_openssl.h"
#include "lib/crypt_ops/crypto_digest.h"
#include "lib/ctime/di_ops.h"
#include "lib/log/log.h"
#include "lib/log/util_bug.h"

DISABLE_GCC_WARNING("-Wredundant-decls")

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>

ENABLE_GCC_WARNING("-Wredundant-decls")

#include <string.h>

/** Verify RSA SHA1 signature in <b>rrsig</b> using the signed data in
 * <b>data</b>.
 * Return 0 in case signature is verified, < 0 otherwise. */
int
crypto_dnssec_verify_signature_rsa_sha1(const uint8_t *data,
                                        const size_t data_len,
                                        const uint8_t *public_key,
                                        const size_t public_key_len,
                                        const uint8_t *signature,
                                        const size_t signature_len)
{
  // LCOV_EXCL_START
  tor_assert(data);
  // LCOV_EXCL_STOP

  if (public_key == NULL || public_key_len == 0) {
    log_debug(LD_CRYPTO, "invalid public_key");
    return -1;
  }

  if (signature == NULL || signature_len == 0) {
    log_debug(LD_CRYPTO, "invalid signature");
    return -2;
  }

  int ret = 0;
  RSA *pubkey = RSA_new();

  char digest[DIGEST_LEN];
  if (crypto_digest(digest, (const char *) data, data_len) < 0) {
    // LCOV_EXCL_START
    log_debug(LD_CRYPTO, "failed computing digest");
    ret = -3;
    goto cleanup;
    // LCOV_EXCL_STOP
  }

  uint8_t exponent_len = public_key[0];
  if (exponent_len > public_key_len - 1) {
    log_debug(LD_CRYPTO, "invalid length: wanted %d, got %d", exponent_len,
              (int) (public_key_len - 1));
    ret = -4;
    goto cleanup;
  }

  BIGNUM *exponent = BN_bin2bn(&public_key[1], exponent_len, NULL);
  BIGNUM *modulus = BN_bin2bn(&public_key[exponent_len + 1],
                              (int) (public_key_len - exponent_len - 1), NULL);
  RSA_set0_key(pubkey, modulus, exponent, NULL);

  if (RSA_verify(NID_sha1, (const unsigned char *) digest, DIGEST_LEN,
                 (const unsigned char *) signature,
                 (unsigned int) signature_len, pubkey)
      != 1) {
    log_debug(LD_CRYPTO, "failed verifying RSA signature");
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
      log_debug(LD_APP, " - %s", ERR_error_string(err, NULL));
    }
    ret = -5;
  }

 cleanup:
  RSA_free(pubkey);
  return ret;
}

/** Verify RSA SHA256 signature in <b>rrsig</b> using the signed data in
 * <b>data</b>.
 * Return 0 in case signature is verified, < 0 otherwise. */
int
crypto_dnssec_verify_signature_rsa_sha256(const uint8_t *data,
                                          const size_t data_len,
                                          const uint8_t *public_key,
                                          const size_t public_key_len,
                                          const uint8_t *signature,
                                          const size_t signature_len)
{
  // LCOV_EXCL_START
  tor_assert(data);
  // LCOV_EXCL_STOP

  if (public_key == NULL || public_key_len == 0) {
    log_debug(LD_CRYPTO, "invalid public_key");
    return -1;
  }

  if (signature == NULL || signature_len == 0) {
    log_debug(LD_CRYPTO, "invalid signature");
    return -2;
  }

  int ret = 0;
  RSA *pubkey = RSA_new();

  char digest[DIGEST256_LEN];
  if (crypto_digest256(digest, (const char *) data, data_len,
                       DIGEST_SHA256) < 0) {
    // LCOV_EXCL_START
    log_debug(LD_CRYPTO, "failed computing digest");
    ret = -3;
    goto cleanup;
    // LCOV_EXCL_STOP
  }

  uint8_t exponent_len = public_key[0];
  if (exponent_len > public_key_len - 1) {
    log_debug(LD_CRYPTO, "invalid length: wanted %d, got %d", exponent_len,
              (int) (public_key_len - 1));
    ret = -4;
    goto cleanup;
  }

  BIGNUM *exponent = BN_bin2bn(&public_key[1], exponent_len, NULL);
  BIGNUM *modulus = BN_bin2bn(&public_key[exponent_len + 1],
                              (int) (public_key_len - exponent_len - 1), NULL);
  RSA_set0_key(pubkey, modulus, exponent, NULL);

  if (RSA_verify(NID_sha256, (const unsigned char *) digest, DIGEST256_LEN,
                 (const unsigned char *) signature,
                 (unsigned int) signature_len, pubkey) != 1) {
    log_debug(LD_CRYPTO, "failed verifying RSA signature");
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
      log_debug(LD_APP, " - %s", ERR_error_string(err, NULL));
    }
    ret = -5;
  }

 cleanup:
  RSA_free(pubkey);
  return ret;
}

/** Verify RSA SHA512 signature in <b>rrsig</b> using the signed data in
 * <b>data</b>.
 * Return 0 in case signature is verified, < 0 otherwise. */
int
crypto_dnssec_verify_signature_rsa_sha512(const uint8_t *data,
                                          const size_t data_len,
                                          const uint8_t *public_key,
                                          const size_t public_key_len,
                                          const uint8_t *signature,
                                          const size_t signature_len)
{
  // LCOV_EXCL_START
  tor_assert(data);
  // LCOV_EXCL_STOP

  if (public_key == NULL || public_key_len == 0) {
    log_debug(LD_CRYPTO, "invalid public_key");
    return -1;
  }

  if (signature == NULL || signature_len == 0) {
    log_debug(LD_CRYPTO, "invalid signature");
    return -2;
  }

  int ret = 0;
  RSA *pubkey = RSA_new();

  char digest[DIGEST512_LEN];
  if (crypto_digest512(digest, (const char *) data, data_len,
                       DIGEST_SHA512) < 0) {
    // LCOV_EXCL_START
    log_debug(LD_CRYPTO, "failed computing digest");
    ret = -3;
    goto cleanup;
    // LCOV_EXCL_STOP
  }

  uint8_t exponent_len = public_key[0];
  if (exponent_len > public_key_len - 1) {
    log_debug(LD_CRYPTO, "invalid length: wanted %d, got %d", exponent_len,
              (int) (public_key_len - 1));
    ret = -4;
    goto cleanup;
  }

  BIGNUM *exponent = BN_bin2bn(&public_key[1], exponent_len, NULL);
  BIGNUM *modulus = BN_bin2bn(&public_key[exponent_len + 1],
                              (int) (public_key_len - exponent_len - 1), NULL);
  RSA_set0_key(pubkey, modulus, exponent, NULL);

  if (RSA_verify(NID_sha512, (const unsigned char *) digest, DIGEST512_LEN,
                 (const unsigned char *) signature,
                 (unsigned int) signature_len, pubkey) != 1) {
    log_debug(LD_CRYPTO, "failed verifying RSA signature");
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
      log_debug(LD_APP, " - %s", ERR_error_string(err, NULL));
    }
    ret = -5;
  }

 cleanup:
  RSA_free(pubkey);
  return ret;
}

/** Verify ECDSA P256 SHA256 signature in <b>rrsig</b> using the signed data in
 * <b>data</b>.
 * Return 0 in case signature is verified, < 0 otherwise. */
int
crypto_dnssec_verify_signature_ecdsa_p256_sha256(const uint8_t *data,
                                                 const size_t data_len,
                                                 const uint8_t *public_key,
                                                 const size_t public_key_len,
                                                 const uint8_t *signature,
                                                 const size_t signature_len)
{
  // LCOV_EXCL_START
  tor_assert(data);
  // LCOV_EXCL_STOP

  if (public_key == NULL || public_key_len == 0 || public_key_len % 2 != 0) {
    log_debug(LD_CRYPTO, "invalid public_key");
    return -1;
  }

  if (signature == NULL || signature_len == 0 || signature_len % 2 != 0) {
    log_debug(LD_CRYPTO, "invalid signature");
    return -2;
  }

  int ret = 0;

  EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  EC_KEY *ec_key = EC_KEY_new();
  EC_KEY_set_group(ec_key, ec_group);

  ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();

  char digest[DIGEST256_LEN];
  if (crypto_digest256(digest, (const char *) data, data_len,
                       DIGEST_SHA256) < 0) {
    // LCOV_EXCL_START
    log_debug(LD_CRYPTO, "failed computing digest");
    ret = -3;
    goto cleanup;
    // LCOV_EXCL_STOP
  }

  uint16_t public_key_point_len = public_key_len / 2;
  BIGNUM *x = BN_bin2bn(public_key, public_key_point_len, NULL);
  BIGNUM *y = BN_bin2bn(&public_key[public_key_point_len],
                        public_key_point_len, NULL);
  EC_KEY_set_public_key_affine_coordinates(ec_key, x, y);
  BN_free(x);
  BN_free(y);

  if (EC_KEY_check_key(ec_key) != 1) {
    log_debug(LD_CRYPTO, "invalid elliptic curve key");
    ret = -4;
    goto cleanup;
  }

  uint16_t signature_point_len = signature_len / 2;
  BIGNUM *r = BN_bin2bn(signature, signature_point_len, NULL);
  BIGNUM *s = BN_bin2bn(&signature[signature_point_len],
                        signature_point_len, NULL);
  ECDSA_SIG_set0(ecdsa_sig, r, s);

  if (ECDSA_do_verify((const unsigned char *) digest, DIGEST256_LEN,
                      ecdsa_sig, ec_key) != 1) {
    log_debug(LD_CRYPTO, "failed verifying ECDSA signature");
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
      log_debug(LD_APP, " - %s", ERR_error_string(err, NULL));
    }
    ret = -5;
  }

 cleanup:
  EC_GROUP_free(ec_group);
  EC_KEY_free(ec_key);
  ECDSA_SIG_free(ecdsa_sig);
  return ret;
}

/** Verify ECDSA P384 SHA384 signature in <b>rrsig</b> using the signed data in
 * <b>data</b>.
 * Return 0 in case signature is verified, < 0 otherwise. */
int
crypto_dnssec_verify_signature_ecdsa_p384_sha384(const uint8_t *data,
                                                 const size_t data_len,
                                                 const uint8_t *public_key,
                                                 const size_t public_key_len,
                                                 const uint8_t *signature,
                                                 const size_t signature_len)
{
  // LCOV_EXCL_START
  tor_assert(data);
  // LCOV_EXCL_STOP

  if (public_key == NULL || public_key_len == 0 || public_key_len % 2 != 0) {
    log_debug(LD_CRYPTO, "invalid public_key");
    return -1;
  }

  if (signature == NULL || signature_len == 0 || signature_len % 2 != 0) {
    log_debug(LD_CRYPTO, "invalid signature");
    return -2;
  }

  int ret = 0;

  EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_secp384r1);
  EC_KEY *ec_key = EC_KEY_new();
  EC_KEY_set_group(ec_key, ec_group);

  ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();

  char digest[DIGEST384_LEN];
  if (crypto_digest384(digest, (const char *) data, data_len,
                       DIGEST_SHA384) < 0) {
    // LCOV_EXCL_START
    log_debug(LD_CRYPTO, "failed computing digest");
    ret = -3;
    goto cleanup;
    // LCOV_EXCL_STOP
  }

  uint16_t public_key_point_len = public_key_len / 2;
  BIGNUM *x = BN_bin2bn(public_key, public_key_point_len, NULL);
  BIGNUM *y = BN_bin2bn(&public_key[public_key_point_len],
                        public_key_point_len, NULL);
  EC_KEY_set_public_key_affine_coordinates(ec_key, x, y);
  BN_free(x);
  BN_free(y);

  if (EC_KEY_check_key(ec_key) != 1) {
    log_debug(LD_CRYPTO, "invalid elliptic curve key");
    ret = -4;
    goto cleanup;
  }

  uint16_t signature_point_len = signature_len / 2;
  BIGNUM *r = BN_bin2bn(signature, signature_point_len, NULL);
  BIGNUM *s = BN_bin2bn(&signature[signature_point_len],
                        signature_point_len, NULL);
  ECDSA_SIG_set0(ecdsa_sig, r, s);

  if (ECDSA_do_verify((const unsigned char *) digest, DIGEST384_LEN,
                      ecdsa_sig, ec_key) != 1) {
    log_debug(LD_CRYPTO, "failed verifying ECDSA signature");
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
      log_debug(LD_APP, " - %s", ERR_error_string(err, NULL));
    }
    ret = -5;
  }

 cleanup:
  EC_GROUP_free(ec_group);
  EC_KEY_free(ec_key);
  ECDSA_SIG_free(ecdsa_sig);
  return ret;
}

/** Verify that SHA1 digest of <b>data</b> is equal to the given <b>digest</b>.
 * Return 0 in case data is verified, < 0 in case of error. */
int
crypto_dnssec_verify_digest_sha1(const uint8_t *data,
                                 const size_t data_len,
                                 const uint8_t *digest,
                                 const size_t digest_len)
{
  // LCOV_EXCL_START
  tor_assert(data);
  tor_assert(digest);
  // LCOV_EXCL_STOP

  if (digest_len != DIGEST_LEN) {
    log_debug(LD_CRYPTO, "invalid digest");
    return -1;
  }

  char actual_digest[DIGEST_LEN];
  if (crypto_digest(actual_digest, (const char *) data, data_len) < 0) {
    // LCOV_EXCL_START
    log_debug(LD_CRYPTO, "failed computing digest");
    return -2;
    // LCOV_EXCL_STOP
  }

  if (fast_memcmp(actual_digest, digest, DIGEST_LEN) != 0) {
    log_debug(LD_CRYPTO, "digest does not match");
    return -3;
  }

  return 0;
}

/** Verify that SHA256 digest of <b>data</b> is equal to the given
 * <b>digest</b>.
 * Return 0 in case data is verified, < 0 in case of error. */
int
crypto_dnssec_verify_digest_sha256(const uint8_t *data,
                                   const size_t data_len,
                                   const uint8_t *digest,
                                   const size_t digest_len)
{
  // LCOV_EXCL_START
  tor_assert(data);
  tor_assert(digest);
  // LCOV_EXCL_STOP

  if (digest_len != DIGEST256_LEN) {
    log_debug(LD_CRYPTO, "invalid digest");
    return -1;
  }

  char actual_digest[DIGEST256_LEN];
  if (crypto_digest256(actual_digest, (const char *) data, data_len,
                       DIGEST_SHA256) < 0) {
    // LCOV_EXCL_START
    log_debug(LD_CRYPTO, "failed computing digest");
    return -2;
    // LCOV_EXCL_STOP
  }

  if (fast_memcmp(actual_digest, digest, DIGEST256_LEN) != 0) {
    log_debug(LD_CRYPTO, "digest does not match");
    return -3;
  }

  return 0;
}

/** Verify that SHA384 digest of <b>data</b> is equal to the given
 * <b>digest</b>.
 * Return 0 in case data is verified, < 0 in case of error. */
int
crypto_dnssec_verify_digest_sha384(const uint8_t *data,
                                   const size_t data_len,
                                   const uint8_t *digest,
                                   const size_t digest_len)
{
  // LCOV_EXCL_START
  tor_assert(data);
  tor_assert(digest);
  // LCOV_EXCL_STOP

  if (digest_len != DIGEST384_LEN) {
    log_debug(LD_CRYPTO, "invalid digest");
    return -1;
  }

  char actual_digest[DIGEST384_LEN];
  if (crypto_digest384(actual_digest, (const char *) data, data_len,
                       DIGEST_SHA384) < 0) {
    // LCOV_EXCL_START
    log_debug(LD_CRYPTO, "failed computing digest");
    return -2;
    // LCOV_EXCL_STOP
  }

  if (fast_memcmp(actual_digest, digest, DIGEST384_LEN) != 0) {
    log_debug(LD_CRYPTO, "digest does not match");
    return -3;
  }

  return 0;
}
