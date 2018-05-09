/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
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
#include "compat_openssl.h"
#include "crypto.h"
#include "crypto_curve25519.h"
#include "crypto_digest.h"
#include "crypto_ed25519.h"
#include "crypto_format.h"
#include "crypto_rand.h"
#include "crypto_rsa.h"
#include "crypto_util.h"

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

#include "torlog.h"
#include "torint.h"
#include "aes.h"
#include "util.h"
#include "container.h"
#include "compat.h"
#include "sandbox.h"
#include "util_format.h"

#include "keccak-tiny/keccak-tiny.h"

/** A structure to hold the first half (x, g^x) of a Diffie-Hellman handshake
 * while we're waiting for the second.*/
struct crypto_dh_t {
  DH *dh; /**< The openssl DH object */
};

static int tor_check_dh_key(int severity, const BIGNUM *bn);

/** Boolean: has OpenSSL's crypto been initialized? */
static int crypto_early_initialized_ = 0;

/** Boolean: has OpenSSL's crypto been initialized? */
static int crypto_global_initialized_ = 0;

/** Log all pending crypto errors at level <b>severity</b>.  Use
 * <b>doing</b> to describe our current activities.
 */
static void
crypto_log_errors(int severity, const char *doing)
{
  unsigned long err;
  const char *msg, *lib, *func;
  while ((err = ERR_get_error()) != 0) {
    msg = (const char*)ERR_reason_error_string(err);
    lib = (const char*)ERR_lib_error_string(err);
    func = (const char*)ERR_func_error_string(err);
    if (!msg) msg = "(null)";
    if (!lib) lib = "(null)";
    if (!func) func = "(null)";
    if (BUG(!doing)) doing = "(null)";
    tor_log(severity, LD_CRYPTO, "crypto error while %s: %s (in %s:%s)",
              doing, msg, lib, func);
  }
}

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

/** Used by tortls.c: Get the DH* from a crypto_dh_t.
 */
DH *
crypto_dh_get_dh_(crypto_dh_t *dh)
{
  return dh->dh;
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

/* DH */

/** Our DH 'g' parameter */
#define DH_GENERATOR 2

/** Shared P parameter for our circuit-crypto DH key exchanges. */
static BIGNUM *dh_param_p = NULL;
/** Shared P parameter for our TLS DH key exchanges. */
static BIGNUM *dh_param_p_tls = NULL;
/** Shared G parameter for our DH key exchanges. */
static BIGNUM *dh_param_g = NULL;

/** Validate a given set of Diffie-Hellman parameters.  This is moderately
 * computationally expensive (milliseconds), so should only be called when
 * the DH parameters change. Returns 0 on success, * -1 on failure.
 */
static int
crypto_validate_dh_params(const BIGNUM *p, const BIGNUM *g)
{
  DH *dh = NULL;
  int ret = -1;

  /* Copy into a temporary DH object, just so that DH_check() can be called. */
  if (!(dh = DH_new()))
      goto out;
#ifdef OPENSSL_1_1_API
  BIGNUM *dh_p, *dh_g;
  if (!(dh_p = BN_dup(p)))
    goto out;
  if (!(dh_g = BN_dup(g)))
    goto out;
  if (!DH_set0_pqg(dh, dh_p, NULL, dh_g))
    goto out;
#else /* !(defined(OPENSSL_1_1_API)) */
  if (!(dh->p = BN_dup(p)))
    goto out;
  if (!(dh->g = BN_dup(g)))
    goto out;
#endif /* defined(OPENSSL_1_1_API) */

  /* Perform the validation. */
  int codes = 0;
  if (!DH_check(dh, &codes))
    goto out;
  if (BN_is_word(g, DH_GENERATOR_2)) {
    /* Per https://wiki.openssl.org/index.php/Diffie-Hellman_parameters
     *
     * OpenSSL checks the prime is congruent to 11 when g = 2; while the
     * IETF's primes are congruent to 23 when g = 2.
     */
    BN_ULONG residue = BN_mod_word(p, 24);
    if (residue == 11 || residue == 23)
      codes &= ~DH_NOT_SUITABLE_GENERATOR;
  }
  if (codes != 0) /* Specifics on why the params suck is irrelevant. */
    goto out;

  /* Things are probably not evil. */
  ret = 0;

 out:
  if (dh)
    DH_free(dh);
  return ret;
}

/** Set the global Diffie-Hellman generator, used for both TLS and internal
 * DH stuff.
 */
static void
crypto_set_dh_generator(void)
{
  BIGNUM *generator;
  int r;

  if (dh_param_g)
    return;

  generator = BN_new();
  tor_assert(generator);

  r = BN_set_word(generator, DH_GENERATOR);
  tor_assert(r);

  dh_param_g = generator;
}

/** Set the global TLS Diffie-Hellman modulus.  Use the Apache mod_ssl DH
 * modulus. */
void
crypto_set_tls_dh_prime(void)
{
  BIGNUM *tls_prime = NULL;
  int r;

  /* If the space is occupied, free the previous TLS DH prime */
  if (BUG(dh_param_p_tls)) {
    /* LCOV_EXCL_START
     *
     * We shouldn't be calling this twice.
     */
    BN_clear_free(dh_param_p_tls);
    dh_param_p_tls = NULL;
    /* LCOV_EXCL_STOP */
  }

  tls_prime = BN_new();
  tor_assert(tls_prime);

  /* This is the 1024-bit safe prime that Apache uses for its DH stuff; see
   * modules/ssl/ssl_engine_dh.c; Apache also uses a generator of 2 with this
   * prime.
   */
  r = BN_hex2bn(&tls_prime,
               "D67DE440CBBBDC1936D693D34AFD0AD50C84D239A45F520BB88174CB98"
               "BCE951849F912E639C72FB13B4B4D7177E16D55AC179BA420B2A29FE324A"
               "467A635E81FF5901377BEDDCFD33168A461AAD3B72DAE8860078045B07A7"
               "DBCA7874087D1510EA9FCC9DDD330507DD62DB88AEAA747DE0F4D6E2BD68"
               "B0E7393E0F24218EB3");
  tor_assert(r);

  tor_assert(tls_prime);

  dh_param_p_tls = tls_prime;
  crypto_set_dh_generator();
  tor_assert(0 == crypto_validate_dh_params(dh_param_p_tls, dh_param_g));
}

/** Initialize dh_param_p and dh_param_g if they are not already
 * set. */
static void
init_dh_param(void)
{
  BIGNUM *circuit_dh_prime;
  int r;
  if (BUG(dh_param_p && dh_param_g))
    return; // LCOV_EXCL_LINE This function isn't supposed to be called twice.

  circuit_dh_prime = BN_new();
  tor_assert(circuit_dh_prime);

  /* This is from rfc2409, section 6.2.  It's a safe prime, and
     supposedly it equals:
        2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 }.
  */
  r = BN_hex2bn(&circuit_dh_prime,
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
                "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
                "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
                "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
                "49286651ECE65381FFFFFFFFFFFFFFFF");
  tor_assert(r);

  /* Set the new values as the global DH parameters. */
  dh_param_p = circuit_dh_prime;
  crypto_set_dh_generator();
  tor_assert(0 == crypto_validate_dh_params(dh_param_p, dh_param_g));

  if (!dh_param_p_tls) {
    crypto_set_tls_dh_prime();
  }
}

/** Number of bits to use when choosing the x or y value in a Diffie-Hellman
 * handshake.  Since we exponentiate by this value, choosing a smaller one
 * lets our handhake go faster.
 */
#define DH_PRIVATE_KEY_BITS 320

/** Allocate and return a new DH object for a key exchange. Returns NULL on
 * failure.
 */
crypto_dh_t *
crypto_dh_new(int dh_type)
{
  crypto_dh_t *res = tor_malloc_zero(sizeof(crypto_dh_t));

  tor_assert(dh_type == DH_TYPE_CIRCUIT || dh_type == DH_TYPE_TLS ||
             dh_type == DH_TYPE_REND);

  if (!dh_param_p)
    init_dh_param();

  if (!(res->dh = DH_new()))
    goto err;

#ifdef OPENSSL_1_1_API
  BIGNUM *dh_p = NULL, *dh_g = NULL;

  if (dh_type == DH_TYPE_TLS) {
    dh_p = BN_dup(dh_param_p_tls);
  } else {
    dh_p = BN_dup(dh_param_p);
  }
  if (!dh_p)
    goto err;

  dh_g = BN_dup(dh_param_g);
  if (!dh_g) {
    BN_free(dh_p);
    goto err;
  }

  if (!DH_set0_pqg(res->dh, dh_p, NULL, dh_g)) {
    goto err;
  }

  if (!DH_set_length(res->dh, DH_PRIVATE_KEY_BITS))
    goto err;
#else /* !(defined(OPENSSL_1_1_API)) */
  if (dh_type == DH_TYPE_TLS) {
    if (!(res->dh->p = BN_dup(dh_param_p_tls)))
      goto err;
  } else {
    if (!(res->dh->p = BN_dup(dh_param_p)))
      goto err;
  }

  if (!(res->dh->g = BN_dup(dh_param_g)))
    goto err;

  res->dh->length = DH_PRIVATE_KEY_BITS;
#endif /* defined(OPENSSL_1_1_API) */

  return res;

  /* LCOV_EXCL_START
   * This error condition is only reached when an allocation fails */
 err:
  crypto_log_errors(LOG_WARN, "creating DH object");
  if (res->dh) DH_free(res->dh); /* frees p and g too */
  tor_free(res);
  return NULL;
  /* LCOV_EXCL_STOP */
}

/** Return a copy of <b>dh</b>, sharing its internal state. */
crypto_dh_t *
crypto_dh_dup(const crypto_dh_t *dh)
{
  crypto_dh_t *dh_new = tor_malloc_zero(sizeof(crypto_dh_t));
  tor_assert(dh);
  tor_assert(dh->dh);
  dh_new->dh = dh->dh;
  DH_up_ref(dh->dh);
  return dh_new;
}

/** Return the length of the DH key in <b>dh</b>, in bytes.
 */
int
crypto_dh_get_bytes(crypto_dh_t *dh)
{
  tor_assert(dh);
  return DH_size(dh->dh);
}

/** Generate \<x,g^x\> for our part of the key exchange.  Return 0 on
 * success, -1 on failure.
 */
int
crypto_dh_generate_public(crypto_dh_t *dh)
{
#ifndef OPENSSL_1_1_API
 again:
#endif
  if (!DH_generate_key(dh->dh)) {
    /* LCOV_EXCL_START
     * To test this we would need some way to tell openssl to break DH. */
    crypto_log_errors(LOG_WARN, "generating DH key");
    return -1;
    /* LCOV_EXCL_STOP */
  }
#ifdef OPENSSL_1_1_API
  /* OpenSSL 1.1.x doesn't appear to let you regenerate a DH key, without
   * recreating the DH object.  I have no idea what sort of aliasing madness
   * can occur here, so do the check, and just bail on failure.
   */
  const BIGNUM *pub_key, *priv_key;
  DH_get0_key(dh->dh, &pub_key, &priv_key);
  if (tor_check_dh_key(LOG_WARN, pub_key)<0) {
    log_warn(LD_CRYPTO, "Weird! Our own DH key was invalid.  I guess once-in-"
             "the-universe chances really do happen.  Treating as a failure.");
    return -1;
  }
#else /* !(defined(OPENSSL_1_1_API)) */
  if (tor_check_dh_key(LOG_WARN, dh->dh->pub_key)<0) {
    /* LCOV_EXCL_START
     * If this happens, then openssl's DH implementation is busted. */
    log_warn(LD_CRYPTO, "Weird! Our own DH key was invalid.  I guess once-in-"
             "the-universe chances really do happen.  Trying again.");
    /* Free and clear the keys, so OpenSSL will actually try again. */
    BN_clear_free(dh->dh->pub_key);
    BN_clear_free(dh->dh->priv_key);
    dh->dh->pub_key = dh->dh->priv_key = NULL;
    goto again;
    /* LCOV_EXCL_STOP */
  }
#endif /* defined(OPENSSL_1_1_API) */
  return 0;
}

/** Generate g^x as necessary, and write the g^x for the key exchange
 * as a <b>pubkey_len</b>-byte value into <b>pubkey</b>. Return 0 on
 * success, -1 on failure.  <b>pubkey_len</b> must be \>= DH_BYTES.
 */
int
crypto_dh_get_public(crypto_dh_t *dh, char *pubkey, size_t pubkey_len)
{
  int bytes;
  tor_assert(dh);

  const BIGNUM *dh_pub;

#ifdef OPENSSL_1_1_API
  const BIGNUM *dh_priv;
  DH_get0_key(dh->dh, &dh_pub, &dh_priv);
#else
  dh_pub = dh->dh->pub_key;
#endif /* defined(OPENSSL_1_1_API) */

  if (!dh_pub) {
    if (crypto_dh_generate_public(dh)<0)
      return -1;
    else {
#ifdef OPENSSL_1_1_API
      DH_get0_key(dh->dh, &dh_pub, &dh_priv);
#else
      dh_pub = dh->dh->pub_key;
#endif
    }
  }

  tor_assert(dh_pub);
  bytes = BN_num_bytes(dh_pub);
  tor_assert(bytes >= 0);
  if (pubkey_len < (size_t)bytes) {
    log_warn(LD_CRYPTO,
             "Weird! pubkey_len (%d) was smaller than DH_BYTES (%d)",
             (int) pubkey_len, bytes);
    return -1;
  }

  memset(pubkey, 0, pubkey_len);
  BN_bn2bin(dh_pub, (unsigned char*)(pubkey+(pubkey_len-bytes)));

  return 0;
}

/** Check for bad Diffie-Hellman public keys (g^x).  Return 0 if the key is
 * okay (in the subgroup [2,p-2]), or -1 if it's bad.
 * See http://www.cl.cam.ac.uk/ftp/users/rja14/psandqs.ps.gz for some tips.
 */
static int
tor_check_dh_key(int severity, const BIGNUM *bn)
{
  BIGNUM *x;
  char *s;
  tor_assert(bn);
  x = BN_new();
  tor_assert(x);
  if (BUG(!dh_param_p))
    init_dh_param(); //LCOV_EXCL_LINE we already checked whether we did this.
  BN_set_word(x, 1);
  if (BN_cmp(bn,x)<=0) {
    log_fn(severity, LD_CRYPTO, "DH key must be at least 2.");
    goto err;
  }
  BN_copy(x,dh_param_p);
  BN_sub_word(x, 1);
  if (BN_cmp(bn,x)>=0) {
    log_fn(severity, LD_CRYPTO, "DH key must be at most p-2.");
    goto err;
  }
  BN_clear_free(x);
  return 0;
 err:
  BN_clear_free(x);
  s = BN_bn2hex(bn);
  log_fn(severity, LD_CRYPTO, "Rejecting insecure DH key [%s]", s);
  OPENSSL_free(s);
  return -1;
}

/** Given a DH key exchange object, and our peer's value of g^y (as a
 * <b>pubkey_len</b>-byte value in <b>pubkey</b>) generate
 * <b>secret_bytes_out</b> bytes of shared key material and write them
 * to <b>secret_out</b>.  Return the number of bytes generated on success,
 * or -1 on failure.
 *
 * (We generate key material by computing
 *         SHA1( g^xy || "\x00" ) || SHA1( g^xy || "\x01" ) || ...
 * where || is concatenation.)
 */
ssize_t
crypto_dh_compute_secret(int severity, crypto_dh_t *dh,
                         const char *pubkey, size_t pubkey_len,
                         char *secret_out, size_t secret_bytes_out)
{
  char *secret_tmp = NULL;
  BIGNUM *pubkey_bn = NULL;
  size_t secret_len=0, secret_tmp_len=0;
  int result=0;
  tor_assert(dh);
  tor_assert(secret_bytes_out/DIGEST_LEN <= 255);
  tor_assert(pubkey_len < INT_MAX);

  if (!(pubkey_bn = BN_bin2bn((const unsigned char*)pubkey,
                              (int)pubkey_len, NULL)))
    goto error;
  if (tor_check_dh_key(severity, pubkey_bn)<0) {
    /* Check for invalid public keys. */
    log_fn(severity, LD_CRYPTO,"Rejected invalid g^x");
    goto error;
  }
  secret_tmp_len = crypto_dh_get_bytes(dh);
  secret_tmp = tor_malloc(secret_tmp_len);
  result = DH_compute_key((unsigned char*)secret_tmp, pubkey_bn, dh->dh);
  if (result < 0) {
    log_warn(LD_CRYPTO,"DH_compute_key() failed.");
    goto error;
  }
  secret_len = result;
  if (crypto_expand_key_material_TAP((uint8_t*)secret_tmp, secret_len,
                                     (uint8_t*)secret_out, secret_bytes_out)<0)
    goto error;
  secret_len = secret_bytes_out;

  goto done;
 error:
  result = -1;
 done:
  crypto_log_errors(LOG_WARN, "completing DH handshake");
  if (pubkey_bn)
    BN_clear_free(pubkey_bn);
  if (secret_tmp) {
    memwipe(secret_tmp, 0, secret_tmp_len);
    tor_free(secret_tmp);
  }
  if (result < 0)
    return result;
  else
    return secret_len;
}

/** Given <b>key_in_len</b> bytes of negotiated randomness in <b>key_in</b>
 * ("K"), expand it into <b>key_out_len</b> bytes of negotiated key material in
 * <b>key_out</b> by taking the first <b>key_out_len</b> bytes of
 *    H(K | [00]) | H(K | [01]) | ....
 *
 * This is the key expansion algorithm used in the "TAP" circuit extension
 * mechanism; it shouldn't be used for new protocols.
 *
 * Return 0 on success, -1 on failure.
 */
int
crypto_expand_key_material_TAP(const uint8_t *key_in, size_t key_in_len,
                               uint8_t *key_out, size_t key_out_len)
{
  int i, r = -1;
  uint8_t *cp, *tmp = tor_malloc(key_in_len+1);
  uint8_t digest[DIGEST_LEN];

  /* If we try to get more than this amount of key data, we'll repeat blocks.*/
  tor_assert(key_out_len <= DIGEST_LEN*256);

  memcpy(tmp, key_in, key_in_len);
  for (cp = key_out, i=0; cp < key_out+key_out_len;
       ++i, cp += DIGEST_LEN) {
    tmp[key_in_len] = i;
    if (crypto_digest((char*)digest, (const char *)tmp, key_in_len+1) < 0)
      goto exit;
    memcpy(cp, digest, MIN(DIGEST_LEN, key_out_len-(cp-key_out)));
  }

  r = 0;
 exit:
  memwipe(tmp, 0, key_in_len+1);
  tor_free(tmp);
  memwipe(digest, 0, sizeof(digest));
  return r;
}

/** Expand some secret key material according to RFC5869, using SHA256 as the
 * underlying hash.  The <b>key_in_len</b> bytes at <b>key_in</b> are the
 * secret key material; the <b>salt_in_len</b> bytes at <b>salt_in</b> and the
 * <b>info_in_len</b> bytes in <b>info_in_len</b> are the algorithm's "salt"
 * and "info" parameters respectively.  On success, write <b>key_out_len</b>
 * bytes to <b>key_out</b> and return 0.  Assert on failure.
 */
int
crypto_expand_key_material_rfc5869_sha256(
                                    const uint8_t *key_in, size_t key_in_len,
                                    const uint8_t *salt_in, size_t salt_in_len,
                                    const uint8_t *info_in, size_t info_in_len,
                                    uint8_t *key_out, size_t key_out_len)
{
  uint8_t prk[DIGEST256_LEN];
  uint8_t tmp[DIGEST256_LEN + 128 + 1];
  uint8_t mac[DIGEST256_LEN];
  int i;
  uint8_t *outp;
  size_t tmp_len;

  crypto_hmac_sha256((char*)prk,
                     (const char*)salt_in, salt_in_len,
                     (const char*)key_in, key_in_len);

  /* If we try to get more than this amount of key data, we'll repeat blocks.*/
  tor_assert(key_out_len <= DIGEST256_LEN * 256);
  tor_assert(info_in_len <= 128);
  memset(tmp, 0, sizeof(tmp));
  outp = key_out;
  i = 1;

  while (key_out_len) {
    size_t n;
    if (i > 1) {
      memcpy(tmp, mac, DIGEST256_LEN);
      memcpy(tmp+DIGEST256_LEN, info_in, info_in_len);
      tmp[DIGEST256_LEN+info_in_len] = i;
      tmp_len = DIGEST256_LEN + info_in_len + 1;
    } else {
      memcpy(tmp, info_in, info_in_len);
      tmp[info_in_len] = i;
      tmp_len = info_in_len + 1;
    }
    crypto_hmac_sha256((char*)mac,
                       (const char*)prk, DIGEST256_LEN,
                       (const char*)tmp, tmp_len);
    n = key_out_len < DIGEST256_LEN ? key_out_len : DIGEST256_LEN;
    memcpy(outp, mac, n);
    key_out_len -= n;
    outp += n;
    ++i;
  }

  memwipe(tmp, 0, sizeof(tmp));
  memwipe(mac, 0, sizeof(mac));
  return 0;
}

/** Free a DH key exchange object.
 */
void
crypto_dh_free_(crypto_dh_t *dh)
{
  if (!dh)
    return;
  tor_assert(dh->dh);
  DH_free(dh->dh);
  tor_free(dh);
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

  if (dh_param_p)
    BN_clear_free(dh_param_p);
  if (dh_param_p_tls)
    BN_clear_free(dh_param_p_tls);
  if (dh_param_g)
    BN_clear_free(dh_param_g);

  dh_param_p = dh_param_p_tls = dh_param_g = NULL;

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

#ifdef USE_DMALLOC
/** Tell the crypto library to use Tor's allocation functions rather than
 * calling libc's allocation functions directly. Return 0 on success, -1
 * on failure. */
int
crypto_use_tor_alloc_functions(void)
{
  int r = CRYPTO_set_mem_ex_functions(tor_malloc_, tor_realloc_, tor_free_);
  return r ? 0 : -1;
}
#endif /* defined(USE_DMALLOC) */

