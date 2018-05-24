/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypto_rsa.c
 * \brief Block of functions related with RSA utilities and operations.
 **/

#include "crypto.h"
#include "crypto_curve25519.h"
#include "crypto_digest.h"
#include "crypto_format.h"
#include "compat_openssl.h"
#include "crypto_rand.h"
#include "crypto_rsa.h"
#include "crypto_util.h"

DISABLE_GCC_WARNING(redundant-decls)

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/conf.h>
#include <openssl/hmac.h>

ENABLE_GCC_WARNING(redundant-decls)

#include "torlog.h"
#include "util.h"
#include "util_format.h"

/** Declaration for crypto_pk_t structure. */
struct crypto_pk_t
{
  int refs; /**< reference count, so we don't have to copy keys */
  RSA *key; /**< The key itself */
};

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

/** Return the number of bytes added by padding method <b>padding</b>.
 */
int
crypto_get_rsa_padding_overhead(int padding)
{
  switch (padding)
    {
    case RSA_PKCS1_OAEP_PADDING: return PKCS1_OAEP_PADDING_OVERHEAD;
    default: tor_assert(0); return -1; // LCOV_EXCL_LINE
    }
}

/** Given a padding method <b>padding</b>, return the correct OpenSSL constant.
 */
int
crypto_get_rsa_padding(int padding)
{
  switch (padding)
    {
    case PK_PKCS1_OAEP_PADDING: return RSA_PKCS1_OAEP_PADDING;
    default: tor_assert(0); return -1; // LCOV_EXCL_LINE
    }
}

/** used internally: quicly validate a crypto_pk_t object as a private key.
 * Return 1 iff the public key is valid, 0 if obviously invalid.
 */
static int
crypto_pk_private_ok(const crypto_pk_t *k)
{
#ifdef OPENSSL_1_1_API
  if (!k || !k->key)
    return 0;

  const BIGNUM *p, *q;
  RSA_get0_factors(k->key, &p, &q);
  return p != NULL; /* XXX/yawning: Should we check q? */
#else /* !(defined(OPENSSL_1_1_API)) */
  return k && k->key && k->key->p;
#endif /* defined(OPENSSL_1_1_API) */
}

/** used by tortls.c: wrap an RSA* in a crypto_pk_t. */
crypto_pk_t *
crypto_new_pk_from_rsa_(RSA *rsa)
{
  crypto_pk_t *env;
  tor_assert(rsa);
  env = tor_malloc(sizeof(crypto_pk_t));
  env->refs = 1;
  env->key = rsa;
  return env;
}

/** Helper, used by tor-gencert.c.  Return the RSA from a
 * crypto_pk_t. */
RSA *
crypto_pk_get_rsa_(crypto_pk_t *env)
{
  return env->key;
}

/** used by tortls.c: get an equivalent EVP_PKEY* for a crypto_pk_t.  Iff
 * private is set, include the private-key portion of the key. Return a valid
 * pointer on success, and NULL on failure. */
MOCK_IMPL(EVP_PKEY *,
crypto_pk_get_evp_pkey_,(crypto_pk_t *env, int private))
{
  RSA *key = NULL;
  EVP_PKEY *pkey = NULL;
  tor_assert(env->key);
  if (private) {
    if (!(key = RSAPrivateKey_dup(env->key)))
      goto error;
  } else {
    if (!(key = RSAPublicKey_dup(env->key)))
      goto error;
  }
  if (!(pkey = EVP_PKEY_new()))
    goto error;
  if (!(EVP_PKEY_assign_RSA(pkey, key)))
    goto error;
  return pkey;
 error:
  if (pkey)
    EVP_PKEY_free(pkey);
  if (key)
    RSA_free(key);
  return NULL;
}

/** Allocate and return storage for a public key.  The key itself will not yet
 * be set.
 */
MOCK_IMPL(crypto_pk_t *,
crypto_pk_new,(void))
{
  RSA *rsa;

  rsa = RSA_new();
  tor_assert(rsa);
  return crypto_new_pk_from_rsa_(rsa);
}

/** Release a reference to an asymmetric key; when all the references
 * are released, free the key.
 */
void
crypto_pk_free_(crypto_pk_t *env)
{
  if (!env)
    return;

  if (--env->refs > 0)
    return;
  tor_assert(env->refs == 0);

  if (env->key)
    RSA_free(env->key);

  tor_free(env);
}

/** Generate a <b>bits</b>-bit new public/private keypair in <b>env</b>.
 * Return 0 on success, -1 on failure.
 */
MOCK_IMPL(int,
crypto_pk_generate_key_with_bits,(crypto_pk_t *env, int bits))
{
  tor_assert(env);

  if (env->key) {
    RSA_free(env->key);
    env->key = NULL;
  }

  {
    BIGNUM *e = BN_new();
    RSA *r = NULL;
    if (!e)
      goto done;
    if (! BN_set_word(e, 65537))
      goto done;
    r = RSA_new();
    if (!r)
      goto done;
    if (RSA_generate_key_ex(r, bits, e, NULL) == -1)
      goto done;

    env->key = r;
    r = NULL;
  done:
    if (e)
      BN_clear_free(e);
    if (r)
      RSA_free(r);
  }

  if (!env->key) {
    crypto_log_errors(LOG_WARN, "generating RSA key");
    return -1;
  }

  return 0;
}

/** A PEM callback that always reports a failure to get a password */
static int
pem_no_password_cb(char *buf, int size, int rwflag, void *u)
{
  (void)buf;
  (void)size;
  (void)rwflag;
  (void)u;
  return -1;
}

/** Read a PEM-encoded private key from the <b>len</b>-byte string <b>s</b>
 * into <b>env</b>.  Return 0 on success, -1 on failure.  If len is -1,
 * the string is nul-terminated.
 */
int
crypto_pk_read_private_key_from_string(crypto_pk_t *env,
                                       const char *s, ssize_t len)
{
  BIO *b;

  tor_assert(env);
  tor_assert(s);
  tor_assert(len < INT_MAX && len < SSIZE_T_CEILING);

  /* Create a read-only memory BIO, backed by the string 's' */
  b = BIO_new_mem_buf((char*)s, (int)len);
  if (!b)
    return -1;

  if (env->key)
    RSA_free(env->key);

  env->key = PEM_read_bio_RSAPrivateKey(b,NULL,pem_no_password_cb,NULL);

  BIO_free(b);

  if (!env->key) {
    crypto_log_errors(LOG_WARN, "Error parsing private key");
    return -1;
  }
  return 0;
}

/** Read a PEM-encoded private key from the file named by
 * <b>keyfile</b> into <b>env</b>.  Return 0 on success, -1 on failure.
 */
int
crypto_pk_read_private_key_from_filename(crypto_pk_t *env,
                                         const char *keyfile)
{
  char *contents;
  int r;

  /* Read the file into a string. */
  contents = read_file_to_str(keyfile, 0, NULL);
  if (!contents) {
    log_warn(LD_CRYPTO, "Error reading private key from \"%s\"", keyfile);
    return -1;
  }

  /* Try to parse it. */
  r = crypto_pk_read_private_key_from_string(env, contents, -1);
  memwipe(contents, 0, strlen(contents));
  tor_free(contents);
  if (r)
    return -1; /* read_private_key_from_string already warned, so we don't.*/

  /* Make sure it's valid. */
  if (crypto_pk_check_key(env) <= 0)
    return -1;

  return 0;
}

/** Helper function to implement crypto_pk_write_*_key_to_string. Return 0 on
 * success, -1 on failure. */
static int
crypto_pk_write_key_to_string_impl(crypto_pk_t *env, char **dest,
                                   size_t *len, int is_public)
{
  BUF_MEM *buf;
  BIO *b;
  int r;

  tor_assert(env);
  tor_assert(env->key);
  tor_assert(dest);

  b = BIO_new(BIO_s_mem()); /* Create a memory BIO */
  if (!b)
    return -1;

  /* Now you can treat b as if it were a file.  Just use the
   * PEM_*_bio_* functions instead of the non-bio variants.
   */
  if (is_public)
    r = PEM_write_bio_RSAPublicKey(b, env->key);
  else
    r = PEM_write_bio_RSAPrivateKey(b, env->key, NULL,NULL,0,NULL,NULL);

  if (!r) {
    crypto_log_errors(LOG_WARN, "writing RSA key to string");
    BIO_free(b);
    return -1;
  }

  BIO_get_mem_ptr(b, &buf);

  *dest = tor_malloc(buf->length+1);
  memcpy(*dest, buf->data, buf->length);
  (*dest)[buf->length] = 0; /* nul terminate it */
  *len = buf->length;

  BIO_free(b);

  return 0;
}

/** PEM-encode the public key portion of <b>env</b> and write it to a
 * newly allocated string.  On success, set *<b>dest</b> to the new
 * string, *<b>len</b> to the string's length, and return 0.  On
 * failure, return -1.
 */
int
crypto_pk_write_public_key_to_string(crypto_pk_t *env, char **dest,
                                     size_t *len)
{
  return crypto_pk_write_key_to_string_impl(env, dest, len, 1);
}

/** PEM-encode the private key portion of <b>env</b> and write it to a
 * newly allocated string.  On success, set *<b>dest</b> to the new
 * string, *<b>len</b> to the string's length, and return 0.  On
 * failure, return -1.
 */
int
crypto_pk_write_private_key_to_string(crypto_pk_t *env, char **dest,
                                     size_t *len)
{
  return crypto_pk_write_key_to_string_impl(env, dest, len, 0);
}

/** Read a PEM-encoded public key from the first <b>len</b> characters of
 * <b>src</b>, and store the result in <b>env</b>.  Return 0 on success, -1 on
 * failure.
 */
int
crypto_pk_read_public_key_from_string(crypto_pk_t *env, const char *src,
                                      size_t len)
{
  BIO *b;

  tor_assert(env);
  tor_assert(src);
  tor_assert(len<INT_MAX);

  b = BIO_new(BIO_s_mem()); /* Create a memory BIO */
  if (!b)
    return -1;

  BIO_write(b, src, (int)len);

  if (env->key)
    RSA_free(env->key);
  env->key = PEM_read_bio_RSAPublicKey(b, NULL, pem_no_password_cb, NULL);
  BIO_free(b);
  if (!env->key) {
    crypto_log_errors(LOG_WARN, "reading public key from string");
    return -1;
  }

  return 0;
}

/** Write the private key from <b>env</b> into the file named by <b>fname</b>,
 * PEM-encoded.  Return 0 on success, -1 on failure.
 */
int
crypto_pk_write_private_key_to_filename(crypto_pk_t *env,
                                        const char *fname)
{
  BIO *bio;
  char *cp;
  long len;
  char *s;
  int r;

  tor_assert(crypto_pk_private_ok(env));

  if (!(bio = BIO_new(BIO_s_mem())))
    return -1;
  if (PEM_write_bio_RSAPrivateKey(bio, env->key, NULL,NULL,0,NULL,NULL)
      == 0) {
    crypto_log_errors(LOG_WARN, "writing private key");
    BIO_free(bio);
    return -1;
  }
  len = BIO_get_mem_data(bio, &cp);
  tor_assert(len >= 0);
  s = tor_malloc(len+1);
  memcpy(s, cp, len);
  s[len]='\0';
  r = write_str_to_file(fname, s, 0);
  BIO_free(bio);
  memwipe(s, 0, strlen(s));
  tor_free(s);
  return r;
}

/** Return true iff <b>env</b> has a valid key.
 */
int
crypto_pk_check_key(crypto_pk_t *env)
{
  int r;
  tor_assert(env);

  r = RSA_check_key(env->key);
  if (r <= 0)
    crypto_log_errors(LOG_WARN,"checking RSA key");
  return r;
}

/** Return true iff <b>key</b> contains the private-key portion of the RSA
 * key. */
int
crypto_pk_key_is_private(const crypto_pk_t *key)
{
  tor_assert(key);
  return crypto_pk_private_ok(key);
}

/** Return true iff <b>env</b> contains a public key whose public exponent
 * equals 65537.
 */
int
crypto_pk_public_exponent_ok(crypto_pk_t *env)
{
  tor_assert(env);
  tor_assert(env->key);

  const BIGNUM *e;

#ifdef OPENSSL_1_1_API
  const BIGNUM *n, *d;
  RSA_get0_key(env->key, &n, &e, &d);
#else
  e = env->key->e;
#endif /* defined(OPENSSL_1_1_API) */
  return BN_is_word(e, 65537);
}

/** Compare the public-key components of a and b.  Return less than 0
 * if a\<b, 0 if a==b, and greater than 0 if a\>b.  A NULL key is
 * considered to be less than all non-NULL keys, and equal to itself.
 *
 * Note that this may leak information about the keys through timing.
 */
int
crypto_pk_cmp_keys(const crypto_pk_t *a, const crypto_pk_t *b)
{
  int result;
  char a_is_non_null = (a != NULL) && (a->key != NULL);
  char b_is_non_null = (b != NULL) && (b->key != NULL);
  char an_argument_is_null = !a_is_non_null | !b_is_non_null;

  result = tor_memcmp(&a_is_non_null, &b_is_non_null, sizeof(a_is_non_null));
  if (an_argument_is_null)
    return result;

  const BIGNUM *a_n, *a_e;
  const BIGNUM *b_n, *b_e;

#ifdef OPENSSL_1_1_API
  const BIGNUM *a_d, *b_d;
  RSA_get0_key(a->key, &a_n, &a_e, &a_d);
  RSA_get0_key(b->key, &b_n, &b_e, &b_d);
#else
  a_n = a->key->n;
  a_e = a->key->e;
  b_n = b->key->n;
  b_e = b->key->e;
#endif /* defined(OPENSSL_1_1_API) */

  tor_assert(a_n != NULL && a_e != NULL);
  tor_assert(b_n != NULL && b_e != NULL);

  result = BN_cmp(a_n, b_n);
  if (result)
    return result;
  return BN_cmp(a_e, b_e);
}

/** Compare the public-key components of a and b.  Return non-zero iff
 * a==b.  A NULL key is considered to be distinct from all non-NULL
 * keys, and equal to itself.
 *
 *  Note that this may leak information about the keys through timing.
 */
int
crypto_pk_eq_keys(const crypto_pk_t *a, const crypto_pk_t *b)
{
  return (crypto_pk_cmp_keys(a, b) == 0);
}

/** Return the size of the public key modulus in <b>env</b>, in bytes. */
size_t
crypto_pk_keysize(const crypto_pk_t *env)
{
  tor_assert(env);
  tor_assert(env->key);

  return (size_t) RSA_size((RSA*)env->key);
}

/** Return the size of the public key modulus of <b>env</b>, in bits. */
int
crypto_pk_num_bits(crypto_pk_t *env)
{
  tor_assert(env);
  tor_assert(env->key);

#ifdef OPENSSL_1_1_API
  /* It's so stupid that there's no other way to check that n is valid
   * before calling RSA_bits().
   */
  const BIGNUM *n, *e, *d;
  RSA_get0_key(env->key, &n, &e, &d);
  tor_assert(n != NULL);

  return RSA_bits(env->key);
#else /* !(defined(OPENSSL_1_1_API)) */
  tor_assert(env->key->n);
  return BN_num_bits(env->key->n);
#endif /* defined(OPENSSL_1_1_API) */
}

/** Increase the reference count of <b>env</b>, and return it.
 */
crypto_pk_t *
crypto_pk_dup_key(crypto_pk_t *env)
{
  tor_assert(env);
  tor_assert(env->key);

  env->refs++;
  return env;
}

#ifdef TOR_UNIT_TESTS
/** For testing: replace dest with src.  (Dest must have a refcount
 * of 1) */
void
crypto_pk_assign_(crypto_pk_t *dest, const crypto_pk_t *src)
{
  tor_assert(dest);
  tor_assert(dest->refs == 1);
  tor_assert(src);
  RSA_free(dest->key);
  dest->key = RSAPrivateKey_dup(src->key);
}
#endif /* defined(TOR_UNIT_TESTS) */

/** Make a real honest-to-goodness copy of <b>env</b>, and return it.
 * Returns NULL on failure. */
crypto_pk_t *
crypto_pk_copy_full(crypto_pk_t *env)
{
  RSA *new_key;
  int privatekey = 0;
  tor_assert(env);
  tor_assert(env->key);

  if (crypto_pk_private_ok(env)) {
    new_key = RSAPrivateKey_dup(env->key);
    privatekey = 1;
  } else {
    new_key = RSAPublicKey_dup(env->key);
  }
  if (!new_key) {
    /* LCOV_EXCL_START
     *
     * We can't cause RSA*Key_dup() to fail, so we can't really test this.
     */
    log_err(LD_CRYPTO, "Unable to duplicate a %s key: openssl failed.",
            privatekey?"private":"public");
    crypto_log_errors(LOG_ERR,
                      privatekey ? "Duplicating a private key" :
                      "Duplicating a public key");
    tor_fragile_assert();
    return NULL;
    /* LCOV_EXCL_STOP */
  }

  return crypto_new_pk_from_rsa_(new_key);
}

/** Perform a hybrid (public/secret) encryption on <b>fromlen</b>
 * bytes of data from <b>from</b>, with padding type 'padding',
 * storing the results on <b>to</b>.
 *
 * Returns the number of bytes written on success, -1 on failure.
 *
 * The encrypted data consists of:
 *   - The source data, padded and encrypted with the public key, if the
 *     padded source data is no longer than the public key, and <b>force</b>
 *     is false, OR
 *   - The beginning of the source data prefixed with a 16-byte symmetric key,
 *     padded and encrypted with the public key; followed by the rest of
 *     the source data encrypted in AES-CTR mode with the symmetric key.
 *
 * NOTE that this format does not authenticate the symmetrically encrypted
 * part of the data, and SHOULD NOT BE USED for new protocols.
 */
int
crypto_pk_obsolete_public_hybrid_encrypt(crypto_pk_t *env,
                                char *to, size_t tolen,
                                const char *from,
                                size_t fromlen,
                                int padding, int force)
{
  int overhead, outlen, r;
  size_t pkeylen, symlen;
  crypto_cipher_t *cipher = NULL;
  char *buf = NULL;

  tor_assert(env);
  tor_assert(from);
  tor_assert(to);
  tor_assert(fromlen < SIZE_T_CEILING);

  overhead = crypto_get_rsa_padding_overhead(crypto_get_rsa_padding(padding));
  pkeylen = crypto_pk_keysize(env);

  if (!force && fromlen+overhead <= pkeylen) {
    /* It all fits in a single encrypt. */
    return crypto_pk_public_encrypt(env,to,
                                    tolen,
                                    from,fromlen,padding);
  }
  tor_assert(tolen >= fromlen + overhead + CIPHER_KEY_LEN);
  tor_assert(tolen >= pkeylen);

  char key[CIPHER_KEY_LEN];
  crypto_rand(key, sizeof(key)); /* generate a new key. */
  cipher = crypto_cipher_new(key);

  buf = tor_malloc(pkeylen+1);
  memcpy(buf, key, CIPHER_KEY_LEN);
  memcpy(buf+CIPHER_KEY_LEN, from, pkeylen-overhead-CIPHER_KEY_LEN);

  /* Length of symmetrically encrypted data. */
  symlen = fromlen-(pkeylen-overhead-CIPHER_KEY_LEN);

  outlen = crypto_pk_public_encrypt(env,to,tolen,buf,pkeylen-overhead,padding);
  if (outlen!=(int)pkeylen) {
    goto err;
  }
  r = crypto_cipher_encrypt(cipher, to+outlen,
                            from+pkeylen-overhead-CIPHER_KEY_LEN, symlen);

  if (r<0) goto err;
  memwipe(buf, 0, pkeylen);
  memwipe(key, 0, sizeof(key));
  tor_free(buf);
  crypto_cipher_free(cipher);
  tor_assert(outlen+symlen < INT_MAX);
  return (int)(outlen + symlen);
 err:

  memwipe(buf, 0, pkeylen);
  memwipe(key, 0, sizeof(key));
  tor_free(buf);
  crypto_cipher_free(cipher);
  return -1;
}

/** Invert crypto_pk_obsolete_public_hybrid_encrypt. Returns the number of
 * bytes written on success, -1 on failure.
 *
 * NOTE that this format does not authenticate the symmetrically encrypted
 * part of the data, and SHOULD NOT BE USED for new protocols.
 */
int
crypto_pk_obsolete_private_hybrid_decrypt(crypto_pk_t *env,
                                 char *to,
                                 size_t tolen,
                                 const char *from,
                                 size_t fromlen,
                                 int padding, int warnOnFailure)
{
  int outlen, r;
  size_t pkeylen;
  crypto_cipher_t *cipher = NULL;
  char *buf = NULL;

  tor_assert(fromlen < SIZE_T_CEILING);
  pkeylen = crypto_pk_keysize(env);

  if (fromlen <= pkeylen) {
    return crypto_pk_private_decrypt(env,to,tolen,from,fromlen,padding,
                                     warnOnFailure);
  }

  buf = tor_malloc(pkeylen);
  outlen = crypto_pk_private_decrypt(env,buf,pkeylen,from,pkeylen,padding,
                                     warnOnFailure);
  if (outlen<0) {
    log_fn(warnOnFailure?LOG_WARN:LOG_DEBUG, LD_CRYPTO,
           "Error decrypting public-key data");
    goto err;
  }
  if (outlen < CIPHER_KEY_LEN) {
    log_fn(warnOnFailure?LOG_WARN:LOG_INFO, LD_CRYPTO,
           "No room for a symmetric key");
    goto err;
  }
  cipher = crypto_cipher_new(buf);
  if (!cipher) {
    goto err;
  }
  memcpy(to,buf+CIPHER_KEY_LEN,outlen-CIPHER_KEY_LEN);
  outlen -= CIPHER_KEY_LEN;
  tor_assert(tolen - outlen >= fromlen - pkeylen);
  r = crypto_cipher_decrypt(cipher, to+outlen, from+pkeylen, fromlen-pkeylen);
  if (r<0)
    goto err;
  memwipe(buf,0,pkeylen);
  tor_free(buf);
  crypto_cipher_free(cipher);
  tor_assert(outlen + fromlen < INT_MAX);
  return (int)(outlen + (fromlen-pkeylen));
 err:
  memwipe(buf,0,pkeylen);
  tor_free(buf);
  crypto_cipher_free(cipher);
  return -1;
}

/** Encrypt <b>fromlen</b> bytes from <b>from</b> with the public key
 * in <b>env</b>, using the padding method <b>padding</b>.  On success,
 * write the result to <b>to</b>, and return the number of bytes
 * written.  On failure, return -1.
 *
 * <b>tolen</b> is the number of writable bytes in <b>to</b>, and must be
 * at least the length of the modulus of <b>env</b>.
 */
int
crypto_pk_public_encrypt(crypto_pk_t *env, char *to, size_t tolen,
                         const char *from, size_t fromlen, int padding)
{
  int r;
  tor_assert(env);
  tor_assert(from);
  tor_assert(to);
  tor_assert(fromlen<INT_MAX);
  tor_assert(tolen >= crypto_pk_keysize(env));

  r = RSA_public_encrypt((int)fromlen,
                         (unsigned char*)from, (unsigned char*)to,
                         env->key, crypto_get_rsa_padding(padding));
  if (r<0) {
    crypto_log_errors(LOG_WARN, "performing RSA encryption");
    return -1;
  }
  return r;
}

/** Decrypt <b>fromlen</b> bytes from <b>from</b> with the private key
 * in <b>env</b>, using the padding method <b>padding</b>.  On success,
 * write the result to <b>to</b>, and return the number of bytes
 * written.  On failure, return -1.
 *
 * <b>tolen</b> is the number of writable bytes in <b>to</b>, and must be
 * at least the length of the modulus of <b>env</b>.
 */
int
crypto_pk_private_decrypt(crypto_pk_t *env, char *to,
                          size_t tolen,
                          const char *from, size_t fromlen,
                          int padding, int warnOnFailure)
{
  int r;
  tor_assert(env);
  tor_assert(from);
  tor_assert(to);
  tor_assert(env->key);
  tor_assert(fromlen<INT_MAX);
  tor_assert(tolen >= crypto_pk_keysize(env));
  if (!crypto_pk_key_is_private(env))
    /* Not a private key */
    return -1;

  r = RSA_private_decrypt((int)fromlen,
                          (unsigned char*)from, (unsigned char*)to,
                          env->key, crypto_get_rsa_padding(padding));

  if (r<0) {
    crypto_log_errors(warnOnFailure?LOG_WARN:LOG_DEBUG,
                      "performing RSA decryption");
    return -1;
  }
  return r;
}

/** Check the signature in <b>from</b> (<b>fromlen</b> bytes long) with the
 * public key in <b>env</b>, using PKCS1 padding.  On success, write the
 * signed data to <b>to</b>, and return the number of bytes written.
 * On failure, return -1.
 *
 * <b>tolen</b> is the number of writable bytes in <b>to</b>, and must be
 * at least the length of the modulus of <b>env</b>.
 */
MOCK_IMPL(int,
crypto_pk_public_checksig,(const crypto_pk_t *env, char *to,
                           size_t tolen,
                           const char *from, size_t fromlen))
{
  int r;
  tor_assert(env);
  tor_assert(from);
  tor_assert(to);
  tor_assert(fromlen < INT_MAX);
  tor_assert(tolen >= crypto_pk_keysize(env));
  r = RSA_public_decrypt((int)fromlen,
                         (unsigned char*)from, (unsigned char*)to,
                         env->key, RSA_PKCS1_PADDING);

  if (r<0) {
    crypto_log_errors(LOG_INFO, "checking RSA signature");
    return -1;
  }
  return r;
}

/** Sign <b>fromlen</b> bytes of data from <b>from</b> with the private key in
 * <b>env</b>, using PKCS1 padding.  On success, write the signature to
 * <b>to</b>, and return the number of bytes written.  On failure, return
 * -1.
 *
 * <b>tolen</b> is the number of writable bytes in <b>to</b>, and must be
 * at least the length of the modulus of <b>env</b>.
 */
int
crypto_pk_private_sign(const crypto_pk_t *env, char *to, size_t tolen,
                       const char *from, size_t fromlen)
{
  int r;
  tor_assert(env);
  tor_assert(from);
  tor_assert(to);
  tor_assert(fromlen < INT_MAX);
  tor_assert(tolen >= crypto_pk_keysize(env));
  if (!crypto_pk_key_is_private(env))
    /* Not a private key */
    return -1;

  r = RSA_private_encrypt((int)fromlen,
                          (unsigned char*)from, (unsigned char*)to,
                          (RSA*)env->key, RSA_PKCS1_PADDING);
  if (r<0) {
    crypto_log_errors(LOG_WARN, "generating RSA signature");
    return -1;
  }
  return r;
}

/** ASN.1-encode the public portion of <b>pk</b> into <b>dest</b>.
 * Return -1 on error, or the number of characters used on success.
 */
int
crypto_pk_asn1_encode(const crypto_pk_t *pk, char *dest, size_t dest_len)
{
  int len;
  unsigned char *buf = NULL;

  len = i2d_RSAPublicKey(pk->key, &buf);
  if (len < 0 || buf == NULL)
    return -1;

  if ((size_t)len > dest_len || dest_len > SIZE_T_CEILING) {
    OPENSSL_free(buf);
    return -1;
  }
  /* We don't encode directly into 'dest', because that would be illegal
   * type-punning.  (C99 is smarter than me, C99 is smarter than me...)
   */
  memcpy(dest,buf,len);
  OPENSSL_free(buf);
  return len;
}

/** Decode an ASN.1-encoded public key from <b>str</b>; return the result on
 * success and NULL on failure.
 */
crypto_pk_t *
crypto_pk_asn1_decode(const char *str, size_t len)
{
  RSA *rsa;
  unsigned char *buf;
  const unsigned char *cp;
  cp = buf = tor_malloc(len);
  memcpy(buf,str,len);
  rsa = d2i_RSAPublicKey(NULL, &cp, len);
  tor_free(buf);
  if (!rsa) {
    crypto_log_errors(LOG_WARN,"decoding public key");
    return NULL;
  }
  return crypto_new_pk_from_rsa_(rsa);
}

/** Given a private or public key <b>pk</b>, put a fingerprint of the
 * public key into <b>fp_out</b> (must have at least FINGERPRINT_LEN+1 bytes of
 * space).  Return 0 on success, -1 on failure.
 *
 * Fingerprints are computed as the SHA1 digest of the ASN.1 encoding
 * of the public key, converted to hexadecimal, in upper case, with a
 * space after every four digits.
 *
 * If <b>add_space</b> is false, omit the spaces.
 */
int
crypto_pk_get_fingerprint(crypto_pk_t *pk, char *fp_out, int add_space)
{
  char digest[DIGEST_LEN];
  char hexdigest[HEX_DIGEST_LEN+1];
  if (crypto_pk_get_digest(pk, digest)) {
    return -1;
  }
  base16_encode(hexdigest,sizeof(hexdigest),digest,DIGEST_LEN);
  if (add_space) {
    crypto_add_spaces_to_fp(fp_out, FINGERPRINT_LEN+1, hexdigest);
  } else {
    strncpy(fp_out, hexdigest, HEX_DIGEST_LEN+1);
  }
  return 0;
}

/** Given a private or public key <b>pk</b>, put a hashed fingerprint of
 * the public key into <b>fp_out</b> (must have at least FINGERPRINT_LEN+1
 * bytes of space).  Return 0 on success, -1 on failure.
 *
 * Hashed fingerprints are computed as the SHA1 digest of the SHA1 digest
 * of the ASN.1 encoding of the public key, converted to hexadecimal, in
 * upper case.
 */
int
crypto_pk_get_hashed_fingerprint(crypto_pk_t *pk, char *fp_out)
{
  char digest[DIGEST_LEN], hashed_digest[DIGEST_LEN];
  if (crypto_pk_get_digest(pk, digest)) {
    return -1;
  }
  if (crypto_digest(hashed_digest, digest, DIGEST_LEN) < 0) {
    return -1;
  }
  base16_encode(fp_out, FINGERPRINT_LEN + 1, hashed_digest, DIGEST_LEN);
  return 0;
}

/** Check a siglen-byte long signature at <b>sig</b> against
 * <b>datalen</b> bytes of data at <b>data</b>, using the public key
 * in <b>env</b>. Return 0 if <b>sig</b> is a correct signature for
 * SHA1(data).  Else return -1.
 */
MOCK_IMPL(int,
crypto_pk_public_checksig_digest,(crypto_pk_t *env, const char *data,
                                  size_t datalen, const char *sig,
                                  size_t siglen))
{
  char digest[DIGEST_LEN];
  char *buf;
  size_t buflen;
  int r;

  tor_assert(env);
  tor_assert(data);
  tor_assert(sig);
  tor_assert(datalen < SIZE_T_CEILING);
  tor_assert(siglen < SIZE_T_CEILING);

  if (crypto_digest(digest,data,datalen)<0) {
    log_warn(LD_BUG, "couldn't compute digest");
    return -1;
  }
  buflen = crypto_pk_keysize(env);
  buf = tor_malloc(buflen);
  r = crypto_pk_public_checksig(env,buf,buflen,sig,siglen);
  if (r != DIGEST_LEN) {
    log_warn(LD_CRYPTO, "Invalid signature");
    tor_free(buf);
    return -1;
  }
  if (tor_memneq(buf, digest, DIGEST_LEN)) {
    log_warn(LD_CRYPTO, "Signature mismatched with digest.");
    tor_free(buf);
    return -1;
  }
  tor_free(buf);

  return 0;
}

/** Compute a SHA1 digest of <b>fromlen</b> bytes of data stored at
 * <b>from</b>; sign the data with the private key in <b>env</b>, and
 * store it in <b>to</b>.  Return the number of bytes written on
 * success, and -1 on failure.
 *
 * <b>tolen</b> is the number of writable bytes in <b>to</b>, and must be
 * at least the length of the modulus of <b>env</b>.
 */
int
crypto_pk_private_sign_digest(crypto_pk_t *env, char *to, size_t tolen,
                              const char *from, size_t fromlen)
{
  int r;
  char digest[DIGEST_LEN];
  if (crypto_digest(digest,from,fromlen)<0)
    return -1;
  r = crypto_pk_private_sign(env,to,tolen,digest,DIGEST_LEN);
  memwipe(digest, 0, sizeof(digest));
  return r;
}

/** Given a private or public key <b>pk</b>, put a SHA1 hash of the
 * public key into <b>digest_out</b> (must have DIGEST_LEN bytes of space).
 * Return 0 on success, -1 on failure.
 */
int
crypto_pk_get_digest(const crypto_pk_t *pk, char *digest_out)
{
  char *buf;
  size_t buflen;
  int len;
  int rv = -1;

  buflen = crypto_pk_keysize(pk)*2;
  buf = tor_malloc(buflen);
  len = crypto_pk_asn1_encode(pk, buf, buflen);
  if (len < 0)
    goto done;

  if (crypto_digest(digest_out, buf, len) < 0)
    goto done;

  rv = 0;
  done:
  tor_free(buf);
  return rv;
}

/** Compute all digests of the DER encoding of <b>pk</b>, and store them
 * in <b>digests_out</b>.  Return 0 on success, -1 on failure. */
int
crypto_pk_get_common_digests(crypto_pk_t *pk, common_digests_t *digests_out)
{
  char *buf;
  size_t buflen;
  int len;
  int rv = -1;

  buflen = crypto_pk_keysize(pk)*2;
  buf = tor_malloc(buflen);
  len = crypto_pk_asn1_encode(pk, buf, buflen);
  if (len < 0)
    goto done;

  if (crypto_common_digests(digests_out, (char*)buf, len) < 0)
    goto done;

  rv = 0;
 done:
  tor_free(buf);
  return rv;
}

/** Given a crypto_pk_t <b>pk</b>, allocate a new buffer containing the
 * Base64 encoding of the DER representation of the private key as a NUL
 * terminated string, and return it via <b>priv_out</b>.  Return 0 on
 * success, -1 on failure.
 *
 * It is the caller's responsibility to sanitize and free the resulting buffer.
 */
int
crypto_pk_base64_encode(const crypto_pk_t *pk, char **priv_out)
{
  unsigned char *der = NULL;
  int der_len;
  int ret = -1;

  *priv_out = NULL;

  der_len = i2d_RSAPrivateKey(pk->key, &der);
  if (der_len < 0 || der == NULL)
    return ret;

  size_t priv_len = base64_encode_size(der_len, 0) + 1;
  char *priv = tor_malloc_zero(priv_len);
  if (base64_encode(priv, priv_len, (char *)der, der_len, 0) >= 0) {
    *priv_out = priv;
    ret = 0;
  } else {
    tor_free(priv);
  }

  memwipe(der, 0, der_len);
  OPENSSL_free(der);
  return ret;
}

/** Given a string containing the Base64 encoded DER representation of the
 * private key <b>str</b>, decode and return the result on success, or NULL
 * on failure.
 */
crypto_pk_t *
crypto_pk_base64_decode(const char *str, size_t len)
{
  crypto_pk_t *pk = NULL;

  char *der = tor_malloc_zero(len + 1);
  int der_len = base64_decode(der, len, str, len);
  if (der_len <= 0) {
    log_warn(LD_CRYPTO, "Stored RSA private key seems corrupted (base64).");
    goto out;
  }

  const unsigned char *dp = (unsigned char*)der; /* Shut the compiler up. */
  RSA *rsa = d2i_RSAPrivateKey(NULL, &dp, der_len);
  if (!rsa) {
    crypto_log_errors(LOG_WARN, "decoding private key");
    goto out;
  }

  pk = crypto_new_pk_from_rsa_(rsa);

  /* Make sure it's valid. */
  if (crypto_pk_check_key(pk) <= 0) {
    crypto_pk_free(pk);
    pk = NULL;
    goto out;
  }

 out:
  memwipe(der, 0, len + 1);
  tor_free(der);
  return pk;
}

