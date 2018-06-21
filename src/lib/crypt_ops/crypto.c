/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypto.c
 * \brief Wrapper functions to present a consistent interface to
 * public-key and symmetric cryptography operations from OpenSSL and
 * other places.
 **/

#include "orconfig.h"

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
/* Windows defines this; so does OpenSSL 0.9.8h and later. We don't actually
 * use either definition. */
#undef OCSP_RESPONSE
#endif /* defined(_WIN32) */

#define CRYPTO_PRIVATE
#include "lib/crypt_ops/compat_openssl.h"
#include "lib/crypt_ops/crypto.h"
#include "lib/crypt_ops/crypto_curve25519.h"
#include "lib/crypt_ops/crypto_digest.h"
#include "lib/crypt_ops/crypto_dh.h"
#include "lib/crypt_ops/crypto_ed25519.h"
#include "lib/crypt_ops/crypto_format.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/crypt_ops/crypto_rsa.h"
#include "lib/crypt_ops/crypto_util.h"

DISABLE_GCC_WARNING(redundant-decls)

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/conf.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>

ENABLE_GCC_WARNING(redundant-decls)

#if __GNUC__ && GCC_VERSION >= 402
#if GCC_VERSION >= 406
#pragma GCC diagnostic pop
#else
#pragma GCC diagnostic warning "-Wredundant-decls"
#endif
#endif /* __GNUC__ && GCC_VERSION >= 402 */

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "common/torlog.h"
#include "lib/cc/torint.h"
#include "lib/crypt_ops/aes.h"
#include "common/util.h"
#include "common/container.h"
#include "common/compat.h"
#include "common/sandbox.h"
#include "common/util_format.h"

#include "keccak-tiny/keccak-tiny.h"

/** Boolean: has OpenSSL's crypto been initialized? */
static int crypto_early_initialized_ = 0;

/** Boolean: has OpenSSL's crypto been initialized? */
static int crypto_global_initialized_ = 0;

#ifndef DISABLE_ENGINES
/** Log any OpenSSL engines we're using at NOTICE. */
static void
log_engine(const char *fn, ENGINE *e)
{
  if (e) {
    const char *name, *id;
    name = ENGINE_get_name(e);
    id = ENGINE_get_id(e);
    log_notice(LD_CRYPTO, "Default OpenSSL engine for %s is %s [%s]",
               fn, name?name:"?", id?id:"?");
  } else {
    log_info(LD_CRYPTO, "Using default implementation for %s", fn);
  }
}
#endif /* !defined(DISABLE_ENGINES) */

#ifndef DISABLE_ENGINES
/** Try to load an engine in a shared library via fully qualified path.
 */
static ENGINE *
try_load_engine(const char *path, const char *engine)
{
  ENGINE *e = ENGINE_by_id("dynamic");
  if (e) {
    if (!ENGINE_ctrl_cmd_string(e, "ID", engine, 0) ||
        !ENGINE_ctrl_cmd_string(e, "DIR_LOAD", "2", 0) ||
        !ENGINE_ctrl_cmd_string(e, "DIR_ADD", path, 0) ||
        !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
      ENGINE_free(e);
      e = NULL;
    }
  }
  return e;
}
#endif /* !defined(DISABLE_ENGINES) */

static int have_seeded_siphash = 0;

/** Set up the siphash key if we haven't already done so. */
int
crypto_init_siphash_key(void)
{
  struct sipkey key;
  if (have_seeded_siphash)
    return 0;

  crypto_rand((char*) &key, sizeof(key));
  siphash_set_global_key(&key);
  have_seeded_siphash = 1;
  return 0;
}

/** Initialize the crypto library.  Return 0 on success, -1 on failure.
 */
int
crypto_early_init(void)
{
  if (!crypto_early_initialized_) {

    crypto_early_initialized_ = 1;

#ifdef OPENSSL_1_1_API
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                     OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
                     OPENSSL_INIT_ADD_ALL_CIPHERS |
                     OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
#else
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
#endif

    setup_openssl_threading();

    unsigned long version_num = OpenSSL_version_num();
    const char *version_str = OpenSSL_version(OPENSSL_VERSION);
    if (version_num == OPENSSL_VERSION_NUMBER &&
        !strcmp(version_str, OPENSSL_VERSION_TEXT)) {
      log_info(LD_CRYPTO, "OpenSSL version matches version from headers "
                 "(%lx: %s).", version_num, version_str);
    } else {
      log_warn(LD_CRYPTO, "OpenSSL version from headers does not match the "
               "version we're running with. If you get weird crashes, that "
               "might be why. (Compiled with %lx: %s; running with %lx: %s).",
               (unsigned long)OPENSSL_VERSION_NUMBER, OPENSSL_VERSION_TEXT,
               version_num, version_str);
    }

    crypto_force_rand_ssleay();

    if (crypto_seed_rng() < 0)
      return -1;
    if (crypto_init_siphash_key() < 0)
      return -1;

    curve25519_init();
    ed25519_init();
  }
  return 0;
}

/** Initialize the crypto library.  Return 0 on success, -1 on failure.
 */
int
crypto_global_init(int useAccel, const char *accelName, const char *accelDir)
{
  if (!crypto_global_initialized_) {
    if (crypto_early_init() < 0)
      return -1;

    crypto_global_initialized_ = 1;

    if (useAccel > 0) {
#ifdef DISABLE_ENGINES
      (void)accelName;
      (void)accelDir;
      log_warn(LD_CRYPTO, "No OpenSSL hardware acceleration support enabled.");
#else
      ENGINE *e = NULL;

      log_info(LD_CRYPTO, "Initializing OpenSSL engine support.");
      ENGINE_load_builtin_engines();
      ENGINE_register_all_complete();

      if (accelName) {
        if (accelDir) {
          log_info(LD_CRYPTO, "Trying to load dynamic OpenSSL engine \"%s\""
                   " via path \"%s\".", accelName, accelDir);
          e = try_load_engine(accelName, accelDir);
        } else {
          log_info(LD_CRYPTO, "Initializing dynamic OpenSSL engine \"%s\""
                   " acceleration support.", accelName);
          e = ENGINE_by_id(accelName);
        }
        if (!e) {
          log_warn(LD_CRYPTO, "Unable to load dynamic OpenSSL engine \"%s\".",
                   accelName);
        } else {
          log_info(LD_CRYPTO, "Loaded dynamic OpenSSL engine \"%s\".",
                   accelName);
        }
      }
      if (e) {
        log_info(LD_CRYPTO, "Loaded OpenSSL hardware acceleration engine,"
                 " setting default ciphers.");
        ENGINE_set_default(e, ENGINE_METHOD_ALL);
      }
      /* Log, if available, the intersection of the set of algorithms
         used by Tor and the set of algorithms available in the engine */
      log_engine("RSA", ENGINE_get_default_RSA());
      log_engine("DH", ENGINE_get_default_DH());
#ifdef OPENSSL_1_1_API
      log_engine("EC", ENGINE_get_default_EC());
#else
      log_engine("ECDH", ENGINE_get_default_ECDH());
      log_engine("ECDSA", ENGINE_get_default_ECDSA());
#endif /* defined(OPENSSL_1_1_API) */
      log_engine("RAND", ENGINE_get_default_RAND());
      log_engine("RAND (which we will not use)", ENGINE_get_default_RAND());
      log_engine("SHA1", ENGINE_get_digest_engine(NID_sha1));
      log_engine("3DES-CBC", ENGINE_get_cipher_engine(NID_des_ede3_cbc));
      log_engine("AES-128-ECB", ENGINE_get_cipher_engine(NID_aes_128_ecb));
      log_engine("AES-128-CBC", ENGINE_get_cipher_engine(NID_aes_128_cbc));
#ifdef NID_aes_128_ctr
      log_engine("AES-128-CTR", ENGINE_get_cipher_engine(NID_aes_128_ctr));
#endif
#ifdef NID_aes_128_gcm
      log_engine("AES-128-GCM", ENGINE_get_cipher_engine(NID_aes_128_gcm));
#endif
      log_engine("AES-256-CBC", ENGINE_get_cipher_engine(NID_aes_256_cbc));
#ifdef NID_aes_256_gcm
      log_engine("AES-256-GCM", ENGINE_get_cipher_engine(NID_aes_256_gcm));
#endif

#endif /* defined(DISABLE_ENGINES) */
    } else {
      log_info(LD_CRYPTO, "NOT using OpenSSL engine support.");
    }

    if (crypto_force_rand_ssleay()) {
      if (crypto_seed_rng() < 0)
        return -1;
    }

    evaluate_evp_for_aes(-1);
    evaluate_ctr_for_aes();
  }
  return 0;
}

/** Free crypto resources held by this thread. */
void
crypto_thread_cleanup(void)
{
#ifndef NEW_THREAD_API
  ERR_remove_thread_state(NULL);
#endif
}

/** Allocate and return a new symmetric cipher using the provided key and iv.
 * The key is <b>bits</b> bits long; the IV is CIPHER_IV_LEN bytes.  Both
 * must be provided. Key length must be 128, 192, or 256 */
crypto_cipher_t *
crypto_cipher_new_with_iv_and_bits(const uint8_t *key,
                                   const uint8_t *iv,
                                   int bits)
{
  tor_assert(key);
  tor_assert(iv);

  return aes_new_cipher((const uint8_t*)key, (const uint8_t*)iv, bits);
}

/** Allocate and return a new symmetric cipher using the provided key and iv.
 * The key is CIPHER_KEY_LEN bytes; the IV is CIPHER_IV_LEN bytes.  Both
 * must be provided.
 */
crypto_cipher_t *
crypto_cipher_new_with_iv(const char *key, const char *iv)
{
  return crypto_cipher_new_with_iv_and_bits((uint8_t*)key, (uint8_t*)iv,
                                            128);
}

/** Return a new crypto_cipher_t with the provided <b>key</b> and an IV of all
 * zero bytes and key length <b>bits</b>.  Key length must be 128, 192, or
 * 256. */
crypto_cipher_t *
crypto_cipher_new_with_bits(const char *key, int bits)
{
  char zeroiv[CIPHER_IV_LEN];
  memset(zeroiv, 0, sizeof(zeroiv));
  return crypto_cipher_new_with_iv_and_bits((uint8_t*)key, (uint8_t*)zeroiv,
                                            bits);
}

/** Return a new crypto_cipher_t with the provided <b>key</b> (of
 * CIPHER_KEY_LEN bytes) and an IV of all zero bytes.  */
crypto_cipher_t *
crypto_cipher_new(const char *key)
{
  return crypto_cipher_new_with_bits(key, 128);
}

/** Free a symmetric cipher.
 */
void
crypto_cipher_free_(crypto_cipher_t *env)
{
  if (!env)
    return;

  aes_cipher_free(env);
}

/** Copy <b>in</b> to the <b>outlen</b>-byte buffer <b>out</b>, adding spaces
 * every four characters. */
void
crypto_add_spaces_to_fp(char *out, size_t outlen, const char *in)
{
  int n = 0;
  char *end = out+outlen;
  tor_assert(outlen < SIZE_T_CEILING);

  while (*in && out<end) {
    *out++ = *in++;
    if (++n == 4 && *in && out<end) {
      n = 0;
      *out++ = ' ';
    }
  }
  tor_assert(out<end);
  *out = '\0';
}

/* symmetric crypto */

/** Encrypt <b>fromlen</b> bytes from <b>from</b> using the cipher
 * <b>env</b>; on success, store the result to <b>to</b> and return 0.
 * Does not check for failure.
 */
int
crypto_cipher_encrypt(crypto_cipher_t *env, char *to,
                      const char *from, size_t fromlen)
{
  tor_assert(env);
  tor_assert(env);
  tor_assert(from);
  tor_assert(fromlen);
  tor_assert(to);
  tor_assert(fromlen < SIZE_T_CEILING);

  memcpy(to, from, fromlen);
  aes_crypt_inplace(env, to, fromlen);
  return 0;
}

/** Decrypt <b>fromlen</b> bytes from <b>from</b> using the cipher
 * <b>env</b>; on success, store the result to <b>to</b> and return 0.
 * Does not check for failure.
 */
int
crypto_cipher_decrypt(crypto_cipher_t *env, char *to,
                      const char *from, size_t fromlen)
{
  tor_assert(env);
  tor_assert(from);
  tor_assert(to);
  tor_assert(fromlen < SIZE_T_CEILING);

  memcpy(to, from, fromlen);
  aes_crypt_inplace(env, to, fromlen);
  return 0;
}

/** Encrypt <b>len</b> bytes on <b>from</b> using the cipher in <b>env</b>;
 * on success. Does not check for failure.
 */
void
crypto_cipher_crypt_inplace(crypto_cipher_t *env, char *buf, size_t len)
{
  tor_assert(len < SIZE_T_CEILING);
  aes_crypt_inplace(env, buf, len);
}

/** Encrypt <b>fromlen</b> bytes (at least 1) from <b>from</b> with the key in
 * <b>key</b> to the buffer in <b>to</b> of length
 * <b>tolen</b>. <b>tolen</b> must be at least <b>fromlen</b> plus
 * CIPHER_IV_LEN bytes for the initialization vector. On success, return the
 * number of bytes written, on failure, return -1.
 */
int
crypto_cipher_encrypt_with_iv(const char *key,
                              char *to, size_t tolen,
                              const char *from, size_t fromlen)
{
  crypto_cipher_t *cipher;
  tor_assert(from);
  tor_assert(to);
  tor_assert(fromlen < INT_MAX);

  if (fromlen < 1)
    return -1;
  if (tolen < fromlen + CIPHER_IV_LEN)
    return -1;

  char iv[CIPHER_IV_LEN];
  crypto_rand(iv, sizeof(iv));
  cipher = crypto_cipher_new_with_iv(key, iv);

  memcpy(to, iv, CIPHER_IV_LEN);
  crypto_cipher_encrypt(cipher, to+CIPHER_IV_LEN, from, fromlen);
  crypto_cipher_free(cipher);
  memwipe(iv, 0, sizeof(iv));
  return (int)(fromlen + CIPHER_IV_LEN);
}

/** Decrypt <b>fromlen</b> bytes (at least 1+CIPHER_IV_LEN) from <b>from</b>
 * with the key in <b>key</b> to the buffer in <b>to</b> of length
 * <b>tolen</b>. <b>tolen</b> must be at least <b>fromlen</b> minus
 * CIPHER_IV_LEN bytes for the initialization vector. On success, return the
 * number of bytes written, on failure, return -1.
 */
int
crypto_cipher_decrypt_with_iv(const char *key,
                              char *to, size_t tolen,
                              const char *from, size_t fromlen)
{
  crypto_cipher_t *cipher;
  tor_assert(key);
  tor_assert(from);
  tor_assert(to);
  tor_assert(fromlen < INT_MAX);

  if (fromlen <= CIPHER_IV_LEN)
    return -1;
  if (tolen < fromlen - CIPHER_IV_LEN)
    return -1;

  cipher = crypto_cipher_new_with_iv(key, from);

  crypto_cipher_encrypt(cipher, to, from+CIPHER_IV_LEN, fromlen-CIPHER_IV_LEN);
  crypto_cipher_free(cipher);
  return (int)(fromlen - CIPHER_IV_LEN);
}

/** @{ */
/** Uninitialize the crypto library. Return 0 on success. Does not detect
 * failure.
 */
int
crypto_global_cleanup(void)
{
#ifndef OPENSSL_1_1_API
  EVP_cleanup();
#endif
#ifndef NEW_THREAD_API
  ERR_remove_thread_state(NULL);
#endif
#ifndef OPENSSL_1_1_API
  ERR_free_strings();
#endif

  crypto_dh_free_all();

#ifndef DISABLE_ENGINES
#ifndef OPENSSL_1_1_API
  ENGINE_cleanup();
#endif
#endif

  CONF_modules_unload(1);
#ifndef OPENSSL_1_1_API
  CRYPTO_cleanup_all_ex_data();
#endif

  crypto_openssl_free_all();

  crypto_early_initialized_ = 0;
  crypto_global_initialized_ = 0;
  have_seeded_siphash = 0;
  siphash_unset_global_key();

  return 0;
}

/** @} */
