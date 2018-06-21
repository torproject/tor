/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypto_dh.c
 * \brief Block of functions related with DH utilities and operations.
 **/

#include "lib/crypt_ops/compat_openssl.h"
#include "lib/crypt_ops/crypto_dh.h"
#include "lib/crypt_ops/crypto_digest.h"
#include "lib/crypt_ops/crypto_hkdf.h"
#include "lib/crypt_ops/crypto_util.h"

DISABLE_GCC_WARNING(redundant-decls)

#include <openssl/dh.h>

ENABLE_GCC_WARNING(redundant-decls)

#include <openssl/bn.h>

#include "common/torlog.h"

/** A structure to hold the first half (x, g^x) of a Diffie-Hellman handshake
 * while we're waiting for the second.*/
struct crypto_dh_t {
  DH *dh; /**< The openssl DH object */
};

static int tor_check_dh_key(int severity, const BIGNUM *bn);

/** Used by tortls.c: Get the DH* from a crypto_dh_t.
 */
DH *
crypto_dh_get_dh_(crypto_dh_t *dh)
{
  return dh->dh;
}

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

void
crypto_dh_free_all(void)
{
  if (dh_param_p)
    BN_clear_free(dh_param_p);
  if (dh_param_p_tls)
    BN_clear_free(dh_param_p_tls);
  if (dh_param_g)
    BN_clear_free(dh_param_g);

  dh_param_p = dh_param_p_tls = dh_param_g = NULL;
}
