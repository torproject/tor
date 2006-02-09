/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char crypto_c_id[] =
  "$Id$";

/**
 * \file crypto.c
 * \brief Wrapper functions to present a consistent interface to
 * public-key and symmetric cryptography operations from OpenSSL.
 **/

#include "orconfig.h"

#ifdef MS_WINDOWS
#define WIN32_WINNT 0x400
#define _WIN32_WINNT 0x400
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#endif

#include <string.h>

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/conf.h>

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <limits.h>

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_FCNTL_H
#include <sys/fcntl.h>
#endif

#include "crypto.h"
#include "log.h"
#include "aes.h"
#include "util.h"
#include "container.h"
#include "compat.h"

#if OPENSSL_VERSION_NUMBER < 0x00905000l
#error "We require openssl >= 0.9.5"
#elif OPENSSL_VERSION_NUMBER < 0x00906000l
#define OPENSSL_095
#endif

#if OPENSSL_VERSION_NUMBER < 0x00907000l
#define OPENSSL_PRE_097
#define NO_ENGINES
#else
#include <openssl/engine.h>
#endif

/* Certain functions that return a success code in OpenSSL 0.9.6 return void
 * (and don't indicate errors) in OpenSSL version 0.9.5.
 *
 * [OpenSSL 0.9.5 matters, because it ships with Redhat 6.2.]
 */
#ifdef OPENSSL_095
#define RETURN_SSL_OUTCOME(exp) (exp); return 0
#else
#define RETURN_SSL_OUTCOME(exp) return !(exp)
#endif

/** Macro: is k a valid RSA public or private key? */
#define PUBLIC_KEY_OK(k) ((k) && (k)->key && (k)->key->n)
/** Macro: is k a valid RSA private key? */
#define PRIVATE_KEY_OK(k) ((k) && (k)->key && (k)->key->p)

#ifdef TOR_IS_MULTITHREADED
static tor_mutex_t **_openssl_mutexes = NULL;
static int _n_openssl_mutexes = -1;
#endif

/** A public key, or a public/private keypair. */
struct crypto_pk_env_t
{
  int refs; /* reference counting so we don't have to copy keys */
  RSA *key;
};

/** Key and stream information for a stream cipher. */
struct crypto_cipher_env_t
{
  char key[CIPHER_KEY_LEN];
  aes_cnt_cipher_t *cipher;
};

/** A structure to hold the first half (x, g^x) of a Diffie-Hellman handshake
 * while we're waiting for the second.*/
struct crypto_dh_env_t {
  DH *dh;
};

/* Prototypes for functions only used by tortls.c */
crypto_pk_env_t *_crypto_new_pk_env_rsa(RSA *rsa);
RSA *_crypto_pk_env_get_rsa(crypto_pk_env_t *env);
EVP_PKEY *_crypto_pk_env_get_evp_pkey(crypto_pk_env_t *env, int private);
DH *_crypto_dh_env_get_dh(crypto_dh_env_t *dh);

static int setup_openssl_threading(void);
static int tor_check_dh_key(BIGNUM *bn);

/** Return the number of bytes added by padding method <b>padding</b>.
 */
static INLINE int
crypto_get_rsa_padding_overhead(int padding)
{
  switch (padding)
    {
    case RSA_NO_PADDING: return 0;
    case RSA_PKCS1_OAEP_PADDING: return 42;
    case RSA_PKCS1_PADDING: return 11;
    default: tor_assert(0); return -1;
    }
}

/** Given a padding method <b>padding</b>, return the correct OpenSSL constant.
 */
static INLINE int
crypto_get_rsa_padding(int padding)
{
  switch (padding)
    {
    case PK_NO_PADDING: return RSA_NO_PADDING;
    case PK_PKCS1_PADDING: return RSA_PKCS1_PADDING;
    case PK_PKCS1_OAEP_PADDING: return RSA_PKCS1_OAEP_PADDING;
    default: tor_assert(0); return -1;
    }
}

/** Boolean: has OpenSSL's crypto been initialized? */
static int _crypto_global_initialized = 0;

/** Log all pending crypto errors at level <b>severity</b>.  Use
 * <b>doing</b> to describe our current activities.
 */
static void
crypto_log_errors(int severity, const char *doing)
{
  unsigned int err;
  const char *msg, *lib, *func;
  while ((err = ERR_get_error()) != 0) {
    msg = (const char*)ERR_reason_error_string(err);
    lib = (const char*)ERR_lib_error_string(err);
    func = (const char*)ERR_func_error_string(err);
    if (!msg) msg = "(null)";
    if (doing) {
      log(severity, LD_CRYPTO, "crypto error while %s: %s (in %s:%s)",
          doing, msg, lib, func);
    } else {
      log(severity, LD_CRYPTO, "crypto error: %s (in %s:%s)", msg, lib, func);
    }
  }
}

#ifndef NO_ENGINES
static void
log_engine(const char *fn, ENGINE *e)
{
  if (e) {
    const char *name, *id;
    name = ENGINE_get_name(e);
    id = ENGINE_get_id(e);
    log(LOG_NOTICE, LD_CRYPTO, "Using OpenSSL engine %s [%s] for %s",
        name?name:"?", id?id:"?", fn);
  } else {
    log(LOG_INFO, LD_CRYPTO, "Using default implementation for %s", fn);
  }
}
#endif

/** Initialize the crypto library.  Return 0 on success, -1 on failure.
 */
int
crypto_global_init(int useAccel)
{
  if (!_crypto_global_initialized) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    _crypto_global_initialized = 1;
    setup_openssl_threading();
#ifndef NO_ENGINES
    if (useAccel) {
      if (useAccel < 0)
        warn(LD_CRYPTO, "Initializing OpenSSL via tor_tls_init().");
      info(LD_CRYPTO, "Initializing OpenSSL engine support.");
      ENGINE_load_builtin_engines();
      if (!ENGINE_register_all_complete())
        return -1;

      /* XXXX make sure this isn't leaking. */
      log_engine("RSA", ENGINE_get_default_RSA());
      log_engine("DH", ENGINE_get_default_DH());
      log_engine("RAND", ENGINE_get_default_RAND());
      log_engine("SHA1", ENGINE_get_digest_engine(NID_sha1));
      log_engine("3DES", ENGINE_get_cipher_engine(NID_des_ede3_ecb));
      log_engine("AES", ENGINE_get_cipher_engine(NID_aes_128_ecb));
    }
#endif
  }
  return 0;
}

/** Free crypto resources held by this thread. */
void
crypto_thread_cleanup(void)
{
#ifndef ENABLE_0119_PARANOIA_B1
  ERR_remove_state(0);
#endif
}

/** Uninitialize the crypto library. Return 0 on success, -1 on failure.
 */
int
crypto_global_cleanup(void)
{
  EVP_cleanup();
#ifndef ENABLE_0119_PARANOIA_C
  ERR_remove_state(0);
#endif
  ERR_free_strings();
#ifndef NO_ENGINES
  ENGINE_cleanup();
#ifndef ENABLE_0119_PARANOIA_C
  CONF_modules_unload(1);
  CRYPTO_cleanup_all_ex_data();
#endif
#endif
#ifdef TOR_IS_MULTITHREADED
  if (_n_openssl_mutexes) {
    int n = _n_openssl_mutexes;
    tor_mutex_t **ms = _openssl_mutexes;
    int i;
    _openssl_mutexes = NULL;
    _n_openssl_mutexes = 0;
    for (i=0;i<n;++i) {
      tor_mutex_free(ms[i]);
    }
    tor_free(ms);
  }
#endif
  return 0;
}

/** used by tortls.c: wrap an RSA* in a crypto_pk_env_t. */
crypto_pk_env_t *
_crypto_new_pk_env_rsa(RSA *rsa)
{
  crypto_pk_env_t *env;
  tor_assert(rsa);
  env = tor_malloc(sizeof(crypto_pk_env_t));
  env->refs = 1;
  env->key = rsa;
  return env;
}

/** used by tortls.c: return the RSA* from a crypto_pk_env_t. */
RSA *
_crypto_pk_env_get_rsa(crypto_pk_env_t *env)
{
  return env->key;
}

/** used by tortls.c: get an equivalent EVP_PKEY* for a crypto_pk_env_t.  Iff
 * private is set, include the private-key portion of the key. */
EVP_PKEY *
_crypto_pk_env_get_evp_pkey(crypto_pk_env_t *env, int private)
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

/** Used by tortls.c: Get the DH* from a crypto_dh_env_t.
 */
DH *
_crypto_dh_env_get_dh(crypto_dh_env_t *dh)
{
  return dh->dh;
}

/** Allocate and return storage for a public key.  The key itself will not yet
 * be set.
 */
crypto_pk_env_t *
crypto_new_pk_env(void)
{
  RSA *rsa;

  rsa = RSA_new();
  if (!rsa) return NULL;
  return _crypto_new_pk_env_rsa(rsa);
}

/** Release a reference to an asymmetric key; when all the references
 * are released, free the key.
 */
void
crypto_free_pk_env(crypto_pk_env_t *env)
{
  tor_assert(env);

  if (--env->refs > 0)
    return;

  if (env->key)
    RSA_free(env->key);

  tor_free(env);
}

/** Create a new symmetric cipher for a given key and encryption flag
 * (1=encrypt, 0=decrypt).  Return the crypto object on success; NULL
 * on failure.
 */
crypto_cipher_env_t *
crypto_create_init_cipher(const char *key, int encrypt_mode)
{
  int r;
  crypto_cipher_env_t *crypto = NULL;

  if (! (crypto = crypto_new_cipher_env())) {
    warn(LD_CRYPTO, "Unable to allocate crypto object");
    return NULL;
  }

  if (crypto_cipher_set_key(crypto, key)) {
    crypto_log_errors(LOG_WARN, "setting symmetric key");
    goto error;
  }

  if (encrypt_mode)
    r = crypto_cipher_encrypt_init_cipher(crypto);
  else
    r = crypto_cipher_decrypt_init_cipher(crypto);

  if (r)
    goto error;
  return crypto;

 error:
  if (crypto)
    crypto_free_cipher_env(crypto);
  return NULL;
}

/** Allocate and return a new symmetric cipher.
 */
crypto_cipher_env_t *
crypto_new_cipher_env(void)
{
  crypto_cipher_env_t *env;

  env = tor_malloc_zero(sizeof(crypto_cipher_env_t));
  env->cipher = aes_new_cipher();
  return env;
}

/** Free a symmetric cipher.
 */
void
crypto_free_cipher_env(crypto_cipher_env_t *env)
{
  tor_assert(env);

  tor_assert(env->cipher);
  aes_free_cipher(env->cipher);
  tor_free(env);
}

/* public key crypto */

/** Generate a new public/private keypair in <b>env</b>.  Return 0 on
 * success, -1 on failure.
 */
int
crypto_pk_generate_key(crypto_pk_env_t *env)
{
  tor_assert(env);

  if (env->key)
    RSA_free(env->key);
  env->key = RSA_generate_key(PK_BYTES*8,65537, NULL, NULL);
  if (!env->key) {
    crypto_log_errors(LOG_WARN, "generating RSA key");
    return -1;
  }

  return 0;
}

/** Read a PEM-encoded private key from the string <b>s</b> into <b>env</b>.
 * Return 0 on success, -1 on failure.
 */
static int
crypto_pk_read_private_key_from_string(crypto_pk_env_t *env,
                                       const char *s)
{
  BIO *b;

  tor_assert(env);
  tor_assert(s);

  /* Create a read-only memory BIO, backed by the nul-terminated string 's' */
  b = BIO_new_mem_buf((char*)s, -1);

  if (env->key)
    RSA_free(env->key);

  env->key = PEM_read_bio_RSAPrivateKey(b,NULL,NULL,NULL);

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
crypto_pk_read_private_key_from_filename(crypto_pk_env_t *env,
                                         const char *keyfile)
{
  char *contents;
  int r;

  /* Read the file into a string. */
  contents = read_file_to_str(keyfile, 0);
  if (!contents) {
    warn(LD_CRYPTO, "Error reading private key from \"%s\"", keyfile);
    return -1;
  }

  /* Try to parse it. */
  r = crypto_pk_read_private_key_from_string(env, contents);
  tor_free(contents);
  if (r)
    return -1; /* read_private_key_from_string already warned, so we don't.*/

  /* Make sure it's valid. */
  if (crypto_pk_check_key(env) <= 0)
    return -1;

  return 0;
}

/** PEM-encode the public key portion of <b>env</b> and write it to a
 * newly allocated string.  On success, set *<b>dest</b> to the new
 * string, *<b>len</b> to the string's length, and return 0.  On
 * failure, return -1.
 */
int
crypto_pk_write_public_key_to_string(crypto_pk_env_t *env, char **dest,
                                     size_t *len)
{
  BUF_MEM *buf;
  BIO *b;

  tor_assert(env);
  tor_assert(env->key);
  tor_assert(dest);

  b = BIO_new(BIO_s_mem()); /* Create a memory BIO */

  /* Now you can treat b as if it were a file.  Just use the
   * PEM_*_bio_* functions instead of the non-bio variants.
   */
  if (!PEM_write_bio_RSAPublicKey(b, env->key)) {
    crypto_log_errors(LOG_WARN, "writing public key to string");
    return -1;
  }

  BIO_get_mem_ptr(b, &buf);
  BIO_set_close(b, BIO_NOCLOSE); /* so BIO_free doesn't free buf */
  BIO_free(b);

  tor_assert(buf->length >= 0);
  *dest = tor_malloc(buf->length+1);
  memcpy(*dest, buf->data, buf->length);
  (*dest)[buf->length] = 0; /* null terminate it */
  *len = buf->length;
  BUF_MEM_free(buf);

  return 0;
}

/** Read a PEM-encoded public key from the first <b>len</b> characters of
 * <b>src</b>, and store the result in <b>env</b>.  Return 0 on success, -1 on
 * failure.
 */
int
crypto_pk_read_public_key_from_string(crypto_pk_env_t *env, const char *src,
                                      size_t len)
{
  BIO *b;

  tor_assert(env);
  tor_assert(src);

  b = BIO_new(BIO_s_mem()); /* Create a memory BIO */

  BIO_write(b, src, len);

  if (env->key)
    RSA_free(env->key);
  env->key = PEM_read_bio_RSAPublicKey(b, NULL, NULL, NULL);
  BIO_free(b);
  if (!env->key) {
    crypto_log_errors(LOG_WARN, "reading public key from string");
    return -1;
  }

  return 0;
}

/* Write the private key from 'env' into the file named by 'fname',
 * PEM-encoded.  Return 0 on success, -1 on failure.
 */
int
crypto_pk_write_private_key_to_filename(crypto_pk_env_t *env,
                                        const char *fname)
{
  BIO *bio;
  char *cp;
  long len;
  char *s;
  int r;

  tor_assert(PRIVATE_KEY_OK(env));

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
  tor_free(s);
  return r;
}

/** Allocate a new string in *<b>out</b>, containing the public portion of the
 * RSA key in <b>env</b>, encoded first with DER, then in base-64.  Return the
 * length of the encoded representation on success, and -1 on failure.
 *
 * <i>This function is for temporary use only.  We need a simple
 * one-line representation for keys to work around a bug in parsing
 * directories containing "opt keyword\n-----BEGIN OBJECT----" entries
 * in versions of Tor up to 0.0.9pre2.</i>
 */
int
crypto_pk_DER64_encode_public_key(crypto_pk_env_t *env, char **out)
{
  int len;
  char buf[PK_BYTES*2]; /* Too long, but hey, stacks are big. */
  tor_assert(env);
  tor_assert(out);
  len = crypto_pk_asn1_encode(env, buf, sizeof(buf));
  if (len < 0) {
    return -1;
  }
  *out = tor_malloc(len * 2); /* too long, but safe. */
  if (base64_encode(*out, len*2, buf, len) < 0) {
    warn(LD_CRYPTO, "Error base64-encoding DER-encoded key");
    tor_free(*out);
    return -1;
  }
  /* Remove spaces */
  tor_strstrip(*out, " \r\n\t");
  return strlen(*out);
}

/** Decode a base-64 encoded DER representation of an RSA key from <b>in</b>,
 * and store the result in <b>env</b>.  Return 0 on success, -1 on failure.
 *
 * <i>This function is for temporary use only.  We need a simple
 * one-line representation for keys to work around a bug in parsing
 * directories containing "opt keyword\n-----BEGIN OBJECT----" entries
 * in versions of Tor up to 0.0.9pre2.</i>
 */
crypto_pk_env_t *
crypto_pk_DER64_decode_public_key(const char *in)
{
  char partitioned[PK_BYTES*2 + 16];
  char buf[PK_BYTES*2];
  int len;
  tor_assert(in);
  len = strlen(in);

  if (strlen(in) > PK_BYTES*2) {
    return NULL;
  }
  /* base64_decode doesn't work unless we insert linebreaks every 64
   * characters.  how dumb. */
  if (tor_strpartition(partitioned, sizeof(partitioned), in, "\n", 64,
                       ALWAYS_TERMINATE))
    return NULL;
  len = base64_decode(buf, sizeof(buf), partitioned, strlen(partitioned));
  if (len<0) {
    warn(LD_CRYPTO,"Error base-64 decoding key");
    return NULL;
  }
  return crypto_pk_asn1_decode(buf, len);
}

/** Return true iff <b>env</b> has a valid key.
 */
int
crypto_pk_check_key(crypto_pk_env_t *env)
{
  int r;
  tor_assert(env);

  r = RSA_check_key(env->key);
  if (r <= 0)
    crypto_log_errors(LOG_WARN,"checking RSA key");
  return r;
}

/** Compare the public-key components of a and b.  Return -1 if a\<b, 0
 * if a==b, and 1 if a\>b.
 */
int
crypto_pk_cmp_keys(crypto_pk_env_t *a, crypto_pk_env_t *b)
{
  int result;

  if (!a || !b)
    return -1;

  if (!a->key || !b->key)
    return -1;

  tor_assert(PUBLIC_KEY_OK(a));
  tor_assert(PUBLIC_KEY_OK(b));
  result = BN_cmp((a->key)->n, (b->key)->n);
  if (result)
    return result;
  return BN_cmp((a->key)->e, (b->key)->e);
}

/** Return the size of the public key modulus in <b>env</b>, in bytes. */
size_t
crypto_pk_keysize(crypto_pk_env_t *env)
{
  tor_assert(env);
  tor_assert(env->key);

  return (size_t) RSA_size(env->key);
}

/** Increase the reference count of <b>env</b>, and return it.
 */
crypto_pk_env_t *
crypto_pk_dup_key(crypto_pk_env_t *env)
{
  tor_assert(env);
  tor_assert(env->key);

  env->refs++;
  return env;
}

/** Encrypt <b>fromlen</b> bytes from <b>from</b> with the public key
 * in <b>env</b>, using the padding method <b>padding</b>.  On success,
 * write the result to <b>to</b>, and return the number of bytes
 * written.  On failure, return -1.
 */
int
crypto_pk_public_encrypt(crypto_pk_env_t *env, char *to,
                         const char *from, size_t fromlen, int padding)
{
  int r;
  tor_assert(env);
  tor_assert(from);
  tor_assert(to);

  r = RSA_public_encrypt(fromlen, (unsigned char*)from, (unsigned char*)to,
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
 */
int
crypto_pk_private_decrypt(crypto_pk_env_t *env, char *to,
                          const char *from, size_t fromlen,
                          int padding, int warnOnFailure)
{
  int r;
  tor_assert(env);
  tor_assert(from);
  tor_assert(to);
  tor_assert(env->key);
  if (!env->key->p)
    /* Not a private key */
    return -1;

  r = RSA_private_decrypt(fromlen, (unsigned char*)from, (unsigned char*)to,
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
 */
int
crypto_pk_public_checksig(crypto_pk_env_t *env, char *to,
                          const char *from, size_t fromlen)
{
  int r;
  tor_assert(env);
  tor_assert(from);
  tor_assert(to);
  r = RSA_public_decrypt(fromlen, (unsigned char*)from, (unsigned char*)to,
                         env->key, RSA_PKCS1_PADDING);

  if (r<0) {
    crypto_log_errors(LOG_WARN, "checking RSA signature");
    return -1;
  }
  return r;
}

/** Check a siglen-byte long signature at <b>sig</b> against
 * <b>datalen</b> bytes of data at <b>data</b>, using the public key
 * in <b>env</b>. Return 0 if <b>sig</b> is a correct signature for
 * SHA1(data).  Else return -1.
 */
int
crypto_pk_public_checksig_digest(crypto_pk_env_t *env, const char *data,
                                 int datalen, const char *sig, int siglen)
{
  char digest[DIGEST_LEN];
  char buf[PK_BYTES+1];
  int r;

  tor_assert(env);
  tor_assert(data);
  tor_assert(sig);

  if (crypto_digest(digest,data,datalen)<0) {
    warn(LD_CRYPTO, "couldn't compute digest");
    return -1;
  }
  r = crypto_pk_public_checksig(env,buf,sig,siglen);
  if (r != DIGEST_LEN) {
    warn(LD_CRYPTO, "Invalid signature");
    return -1;
  }
  if (memcmp(buf, digest, DIGEST_LEN)) {
    warn(LD_CRYPTO, "Signature mismatched with digest.");
    return -1;
  }

  return 0;
}

/** Sign <b>fromlen</b> bytes of data from <b>from</b> with the private key in
 * <b>env</b>, using PKCS1 padding.  On success, write the signature to
 * <b>to</b>, and return the number of bytes written.  On failure, return
 * -1.
 */
int
crypto_pk_private_sign(crypto_pk_env_t *env, char *to,
                       const char *from, size_t fromlen)
{
  int r;
  tor_assert(env);
  tor_assert(from);
  tor_assert(to);
  if (!env->key->p)
    /* Not a private key */
    return -1;

  r = RSA_private_encrypt(fromlen, (unsigned char*)from, (unsigned char*)to,
                          env->key, RSA_PKCS1_PADDING);
  if (r<0) {
    crypto_log_errors(LOG_WARN, "generating RSA signature");
    return -1;
  }
  return r;
}

/** Compute a SHA1 digest of <b>fromlen</b> bytes of data stored at
 * <b>from</b>; sign the data with the private key in <b>env</b>, and
 * store it in <b>to</b>.  Return the number of bytes written on
 * success, and -1 on failure.
 */
int
crypto_pk_private_sign_digest(crypto_pk_env_t *env, char *to,
                              const char *from, size_t fromlen)
{
  char digest[DIGEST_LEN];
  if (crypto_digest(digest,from,fromlen)<0)
    return -1;
  return crypto_pk_private_sign(env,to,digest,DIGEST_LEN);
}

/** Perform a hybrid (public/secret) encryption on <b>fromlen</b>
 * bytes of data from <b>from</b>, with padding type 'padding',
 * storing the results on <b>to</b>.
 *
 * If no padding is used, the public key must be at least as large as
 * <b>from</b>.
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
 */
int
crypto_pk_public_hybrid_encrypt(crypto_pk_env_t *env,
                                char *to,
                                const char *from,
                                size_t fromlen,
                                int padding, int force)
{
  int overhead, outlen, r, symlen;
  size_t pkeylen;
  crypto_cipher_env_t *cipher = NULL;
  char buf[PK_BYTES+1];

  tor_assert(env);
  tor_assert(from);
  tor_assert(to);

  overhead = crypto_get_rsa_padding_overhead(crypto_get_rsa_padding(padding));
  pkeylen = crypto_pk_keysize(env);

  if (padding == PK_NO_PADDING && fromlen < pkeylen)
    return -1;

  if (!force && fromlen+overhead <= pkeylen) {
    /* It all fits in a single encrypt. */
    return crypto_pk_public_encrypt(env,to,from,fromlen,padding);
  }
  cipher = crypto_new_cipher_env();
  if (!cipher) return -1;
  if (crypto_cipher_generate_key(cipher)<0)
    goto err;
  /* You can't just run around RSA-encrypting any bitstream: if it's
   * greater than the RSA key, then OpenSSL will happily encrypt, and
   * later decrypt to the wrong value.  So we set the first bit of
   * 'cipher->key' to 0 if we aren't padding.  This means that our
   * symmetric key is really only 127 bits.
   */
  if (padding == PK_NO_PADDING)
    cipher->key[0] &= 0x7f;
  if (crypto_cipher_encrypt_init_cipher(cipher)<0)
    goto err;
  memcpy(buf, cipher->key, CIPHER_KEY_LEN);
  memcpy(buf+CIPHER_KEY_LEN, from, pkeylen-overhead-CIPHER_KEY_LEN);

  /* Length of symmetrically encrypted data. */
  symlen = fromlen-(pkeylen-overhead-CIPHER_KEY_LEN);

  outlen = crypto_pk_public_encrypt(env,to,buf,pkeylen-overhead,padding);
  if (outlen!=(int)pkeylen) {
    goto err;
  }
  r = crypto_cipher_encrypt(cipher, to+outlen,
                            from+pkeylen-overhead-CIPHER_KEY_LEN, symlen);

  if (r<0) goto err;
  memset(buf, 0, sizeof(buf));
  crypto_free_cipher_env(cipher);
  return outlen + symlen;
 err:
  memset(buf, 0, sizeof(buf));
  if (cipher) crypto_free_cipher_env(cipher);
  return -1;
}

/** Invert crypto_pk_public_hybrid_encrypt. */
int
crypto_pk_private_hybrid_decrypt(crypto_pk_env_t *env,
                                 char *to,
                                 const char *from,
                                 size_t fromlen,
                                 int padding, int warnOnFailure)
{
  int overhead, outlen, r;
  size_t pkeylen;
  crypto_cipher_env_t *cipher = NULL;
  char buf[PK_BYTES+1];

  overhead = crypto_get_rsa_padding_overhead(crypto_get_rsa_padding(padding));
  pkeylen = crypto_pk_keysize(env);

  if (fromlen <= pkeylen) {
    return crypto_pk_private_decrypt(env,to,from,fromlen,padding,
                                     warnOnFailure);
  }
  outlen = crypto_pk_private_decrypt(env,buf,from,pkeylen,padding,
                                     warnOnFailure);
  if (outlen<0) {
    log_fn(warnOnFailure?LOG_WARN:LOG_DEBUG, LD_CRYPTO,
           "Error decrypting public-key data");
    return -1;
  }
  if (outlen < CIPHER_KEY_LEN) {
    log_fn(warnOnFailure?LOG_WARN:LOG_INFO, LD_CRYPTO,
           "No room for a symmetric key");
    return -1;
  }
  cipher = crypto_create_init_cipher(buf, 0);
  if (!cipher) {
    return -1;
  }
  memcpy(to,buf+CIPHER_KEY_LEN,outlen-CIPHER_KEY_LEN);
  outlen -= CIPHER_KEY_LEN;
  r = crypto_cipher_decrypt(cipher, to+outlen, from+pkeylen, fromlen-pkeylen);
  if (r<0)
    goto err;
  memset(buf,0,sizeof(buf));
  crypto_free_cipher_env(cipher);
  return outlen + (fromlen-pkeylen);
 err:
  memset(buf,0,sizeof(buf));
  if (cipher) crypto_free_cipher_env(cipher);
  return -1;
}

/** ASN.1-encode the public portion of <b>pk</b> into <b>dest</b>.
 * Return -1 on error, or the number of characters used on success.
 */
int
crypto_pk_asn1_encode(crypto_pk_env_t *pk, char *dest, int dest_len)
{
  int len;
  unsigned char *buf, *cp;
  len = i2d_RSAPublicKey(pk->key, NULL);
  if (len < 0 || len > dest_len)
    return -1;
  cp = buf = tor_malloc(len+1);
  len = i2d_RSAPublicKey(pk->key, &cp);
  if (len < 0) {
    crypto_log_errors(LOG_WARN,"encoding public key");
    tor_free(buf);
    return -1;
  }
  /* We don't encode directly into 'dest', because that would be illegal
   * type-punning.  (C99 is smarter than me, C99 is smarter than me...)
   */
  memcpy(dest,buf,len);
  tor_free(buf);
  return len;
}

/** Decode an ASN.1-encoded public key from <b>str</b>; return the result on
 * success and NULL on failure.
 */
crypto_pk_env_t *
crypto_pk_asn1_decode(const char *str, size_t len)
{
  RSA *rsa;
  unsigned char *buf;
  /* This ifdef suppresses a type warning.  Take out the first case once
   * everybody is using openssl 0.9.7 or later.
   */
#if OPENSSL_VERSION_NUMBER < 0x00907000l
  unsigned char *cp;
#else
  const unsigned char *cp;
#endif
  cp = buf = tor_malloc(len);
  memcpy(buf,str,len);
  rsa = d2i_RSAPublicKey(NULL, &cp, len);
  tor_free(buf);
  if (!rsa) {
    crypto_log_errors(LOG_WARN,"decoding public key");
    return NULL;
  }
  return _crypto_new_pk_env_rsa(rsa);
}

/** Given a private or public key <b>pk</b>, put a SHA1 hash of the
 * public key into <b>digest_out</b> (must have DIGEST_LEN bytes of space).
 * Return 0 on success, -1 on failure.
 */
int
crypto_pk_get_digest(crypto_pk_env_t *pk, char *digest_out)
{
  unsigned char *buf, *bufp;
  int len;

  len = i2d_RSAPublicKey(pk->key, NULL);
  if (len < 0)
    return -1;
  buf = bufp = tor_malloc(len+1);
  len = i2d_RSAPublicKey(pk->key, &bufp);
  if (len < 0) {
    crypto_log_errors(LOG_WARN,"encoding public key");
    tor_free(buf);
    return -1;
  }
  if (crypto_digest(digest_out, (char*)buf, len) < 0) {
    tor_free(buf);
    return -1;
  }
  tor_free(buf);
  return 0;
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
crypto_pk_get_fingerprint(crypto_pk_env_t *pk, char *fp_out, int add_space)
{
  char digest[DIGEST_LEN];
  char hexdigest[HEX_DIGEST_LEN+1];
  if (crypto_pk_get_digest(pk, digest)) {
    return -1;
  }
  base16_encode(hexdigest,sizeof(hexdigest),digest,DIGEST_LEN);
  if (add_space) {
    if (tor_strpartition(fp_out, FINGERPRINT_LEN+1, hexdigest, " ", 4,
                         NEVER_TERMINATE)<0)
      return -1;
  } else {
    strcpy(fp_out, hexdigest);
  }
  return 0;
}

/** Return true iff <b>s</b> is in the correct format for a fingerprint.
 */
int
crypto_pk_check_fingerprint_syntax(const char *s)
{
  int i;
  for (i = 0; i < FINGERPRINT_LEN; ++i) {
    if ((i%5) == 4) {
      if (!TOR_ISSPACE(s[i])) return 0;
    } else {
      if (!TOR_ISXDIGIT(s[i])) return 0;
    }
  }
  if (s[FINGERPRINT_LEN]) return 0;
  return 1;
}

/* symmetric crypto */

/** Generate a new random key for the symmetric cipher in <b>env</b>.
 * Return 0 on success, -1 on failure.  Does not initialize the cipher.
 */
int
crypto_cipher_generate_key(crypto_cipher_env_t *env)
{
  tor_assert(env);

  return crypto_rand(env->key, CIPHER_KEY_LEN);
}

/** Set the symmetric key for the cipher in <b>env</b> to the first
 * CIPHER_KEY_LEN bytes of <b>key</b>. Does not initialize the cipher.
 * Return 0 on success, -1 on failure.
 */
int
crypto_cipher_set_key(crypto_cipher_env_t *env, const char *key)
{
  tor_assert(env);
  tor_assert(key);

  if (!env->key)
    return -1;

  memcpy(env->key, key, CIPHER_KEY_LEN);

  return 0;
}

/** Return a pointer to the key set for the cipher in <b>env</b>.
 */
const char *
crypto_cipher_get_key(crypto_cipher_env_t *env)
{
  return env->key;
}

/** Initialize the cipher in <b>env</b> for encryption.  Return 0 on
 * success, -1 on failure.
 */
int
crypto_cipher_encrypt_init_cipher(crypto_cipher_env_t *env)
{
  tor_assert(env);

  aes_set_key(env->cipher, env->key, CIPHER_KEY_LEN*8);
  return 0;
}

/** Initialize the cipher in <b>env</b> for decryption. Return 0 on
 * success, -1 on failure.
 */
int
crypto_cipher_decrypt_init_cipher(crypto_cipher_env_t *env)
{
  tor_assert(env);

  aes_set_key(env->cipher, env->key, CIPHER_KEY_LEN*8);
  return 0;
}

/** Encrypt <b>fromlen</b> bytes from <b>from</b> using the cipher
 * <b>env</b>; on success, store the result to <b>to</b> and return 0.
 * On failure, return -1.
 */
int
crypto_cipher_encrypt(crypto_cipher_env_t *env, char *to,
                      const char *from, size_t fromlen)
{
  tor_assert(env);
  tor_assert(env->cipher);
  tor_assert(from);
  tor_assert(fromlen);
  tor_assert(to);

  aes_crypt(env->cipher, from, fromlen, to);
  return 0;
}

/** Decrypt <b>fromlen</b> bytes from <b>from</b> using the cipher
 * <b>env</b>; on success, store the result to <b>to</b> and return 0.
 * On failure, return -1.
 */
int
crypto_cipher_decrypt(crypto_cipher_env_t *env, char *to,
                      const char *from, size_t fromlen)
{
  tor_assert(env);
  tor_assert(from);
  tor_assert(to);

  aes_crypt(env->cipher, from, fromlen, to);
  return 0;
}

/* SHA-1 */

/** Compute the SHA1 digest of <b>len</b> bytes in data stored in
 * <b>m</b>.  Write the DIGEST_LEN byte result into <b>digest</b>.
 * Return 0 on success, -1 on failure.
 */
int
crypto_digest(char *digest, const char *m, size_t len)
{
  tor_assert(m);
  tor_assert(digest);
  return (SHA1((const unsigned char*)m,len,(unsigned char*)digest) == NULL);
}

/** Intermediate information about the digest of a stream of data. */
struct crypto_digest_env_t {
  SHA_CTX d;
};

/** Allocate and return a new digest object.
 */
crypto_digest_env_t *
crypto_new_digest_env(void)
{
  crypto_digest_env_t *r;
  r = tor_malloc(sizeof(crypto_digest_env_t));
  SHA1_Init(&r->d);
  return r;
}

/** Deallocate a digest object.
 */
void
crypto_free_digest_env(crypto_digest_env_t *digest)
{
  tor_free(digest);
}

/** Add <b>len</b> bytes from <b>data</b> to the digest object.
 */
void
crypto_digest_add_bytes(crypto_digest_env_t *digest, const char *data,
                        size_t len)
{
  tor_assert(digest);
  tor_assert(data);
  /* Using the SHA1_*() calls directly means we don't support doing
   * sha1 in hardware. But so far the delay of getting the question
   * to the hardware, and hearing the answer, is likely higher than
   * just doing it ourselves. Hashes are fast.
   */
  SHA1_Update(&digest->d, (void*)data, len);
}

/** Compute the hash of the data that has been passed to the digest
 * object; write the first out_len bytes of the result to <b>out</b>.
 * <b>out_len</b> must be \<= DIGEST_LEN.
 */
void
crypto_digest_get_digest(crypto_digest_env_t *digest,
                         char *out, size_t out_len)
{
  static unsigned char r[DIGEST_LEN];
  SHA_CTX tmpctx;
  tor_assert(digest);
  tor_assert(out);
  tor_assert(out_len <= DIGEST_LEN);
  /* memcpy into a temporary ctx, since SHA1_Final clears the context */
  memcpy(&tmpctx, &digest->d, sizeof(SHA_CTX));
  SHA1_Final(r, &tmpctx);
  memcpy(out, r, out_len);
}

/** Allocate and return a new digest object with the same state as
 * <b>digest</b>
 */
crypto_digest_env_t *
crypto_digest_dup(const crypto_digest_env_t *digest)
{
  crypto_digest_env_t *r;
  tor_assert(digest);
  r = tor_malloc(sizeof(crypto_digest_env_t));
  memcpy(r,digest,sizeof(crypto_digest_env_t));
  return r;
}

/** Replace the state of the digest object <b>into</b> with the state
 * of the digest object <b>from</b>.
 */
void
crypto_digest_assign(crypto_digest_env_t *into,
                     const crypto_digest_env_t *from)
{
  tor_assert(into);
  tor_assert(from);
  memcpy(into,from,sizeof(crypto_digest_env_t));
}

/* DH */

/** Shared P parameter for our DH key exchanged. */
static BIGNUM *dh_param_p = NULL;
/** Shared G parameter for our DH key exchanges. */
static BIGNUM *dh_param_g = NULL;

/** Initialize dh_param_p and dh_param_g if they are not already
 * set. */
static void
init_dh_param(void)
{
  BIGNUM *p, *g;
  int r;
  if (dh_param_p && dh_param_g)
    return;

  p = BN_new();
  g = BN_new();
  tor_assert(p);
  tor_assert(g);

  /* This is from rfc2409, section 6.2.  It's a safe prime, and
     supposedly it equals:
        2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 }.
  */
  r = BN_hex2bn(&p,
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
                "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
                "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
                "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
                "49286651ECE65381FFFFFFFFFFFFFFFF");
  tor_assert(r);

  r = BN_set_word(g, 2);
  tor_assert(r);
  dh_param_p = p;
  dh_param_g = g;
}

#define DH_PRIVATE_KEY_BITS 320

/** Allocate and return a new DH object for a key exchange.
 */
crypto_dh_env_t *
crypto_dh_new(void)
{
  crypto_dh_env_t *res = NULL;

  if (!dh_param_p)
    init_dh_param();

  res = tor_malloc_zero(sizeof(crypto_dh_env_t));

  if (!(res->dh = DH_new()))
    goto err;

  if (!(res->dh->p = BN_dup(dh_param_p)))
    goto err;

  if (!(res->dh->g = BN_dup(dh_param_g)))
    goto err;

#ifndef ENABLE_0119_PARANOIA_A
  res->dh->length = DH_PRIVATE_KEY_BITS;
#endif

  return res;
 err:
  crypto_log_errors(LOG_WARN, "creating DH object");
  if (res && res->dh) DH_free(res->dh); /* frees p and g too */
  if (res) tor_free(res);
  return NULL;
}

/** Return the length of the DH key in <b>dh</b>, in bytes.
 */
int
crypto_dh_get_bytes(crypto_dh_env_t *dh)
{
  tor_assert(dh);
  return DH_size(dh->dh);
}

/** Generate \<x,g^x\> for our part of the key exchange.  Return 0 on
 * success, -1 on failure.
 */
int
crypto_dh_generate_public(crypto_dh_env_t *dh)
{
 again:
  if (!DH_generate_key(dh->dh)) {
    crypto_log_errors(LOG_WARN, "generating DH key");
    return -1;
  }
  if (tor_check_dh_key(dh->dh->pub_key)<0) {
    warn(LD_CRYPTO, "Weird! Our own DH key was invalid.  I guess once-in-"
         "the-universe chances really do happen.  Trying again.");
    /* Free and clear the keys, so openssl will actually try again. */
    BN_free(dh->dh->pub_key);
    BN_free(dh->dh->priv_key);
    dh->dh->pub_key = dh->dh->priv_key = NULL;
    goto again;
  }
  return 0;
}

/** Generate g^x as necessary, and write the g^x for the key exchange
 * as a <b>pubkey_len</b>-byte value into <b>pubkey</b>. Return 0 on
 * success, -1 on failure.  <b>pubkey_len</b> must be \>= DH_BYTES.
 */
int
crypto_dh_get_public(crypto_dh_env_t *dh, char *pubkey, size_t pubkey_len)
{
  int bytes;
  tor_assert(dh);
  if (!dh->dh->pub_key) {
    if (crypto_dh_generate_public(dh)<0)
      return -1;
  }

  tor_assert(dh->dh->pub_key);
  bytes = BN_num_bytes(dh->dh->pub_key);
  tor_assert(bytes >= 0);
  if (pubkey_len < (size_t)bytes) {
    warn(LD_CRYPTO, "Weird! pubkey_len (%d) was smaller than DH_BYTES (%d)",
         (int) pubkey_len, bytes);
    return -1;
  }

  memset(pubkey, 0, pubkey_len);
  BN_bn2bin(dh->dh->pub_key, (unsigned char*)(pubkey+(pubkey_len-bytes)));

  return 0;
}

/** Check for bad diffie-hellman public keys (g^x).  Return 0 if the key is
 * okay (in the subgroup [2,p-2]), or -1 if it's bad.
 * See http://www.cl.cam.ac.uk/ftp/users/rja14/psandqs.ps.gz for some tips.
 */
static int
tor_check_dh_key(BIGNUM *bn)
{
  BIGNUM *x;
  char *s;
  tor_assert(bn);
  x = BN_new();
  tor_assert(x);
  if (!dh_param_p)
    init_dh_param();
  BN_set_word(x, 1);
  if (BN_cmp(bn,x)<=0) {
    warn(LD_CRYPTO, "DH key must be at least 2.");
    goto err;
  }
  BN_copy(x,dh_param_p);
  BN_sub_word(x, 1);
  if (BN_cmp(bn,x)>=0) {
    warn(LD_CRYPTO, "DH key must be at most p-2.");
    goto err;
  }
  BN_free(x);
  return 0;
 err:
  BN_free(x);
  s = BN_bn2hex(bn);
  warn(LD_CRYPTO, "Rejecting insecure DH key [%s]", s);
  OPENSSL_free(s);
  return -1;
}

#undef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
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
int
crypto_dh_compute_secret(crypto_dh_env_t *dh,
                         const char *pubkey, size_t pubkey_len,
                         char *secret_out, size_t secret_bytes_out)
{
  char *secret_tmp = NULL;
  BIGNUM *pubkey_bn = NULL;
  size_t secret_len=0;
  int result=0;
  tor_assert(dh);
  tor_assert(secret_bytes_out/DIGEST_LEN <= 255);

  if (!(pubkey_bn = BN_bin2bn((const unsigned char*)pubkey, pubkey_len, NULL)))
    goto error;
  if (tor_check_dh_key(pubkey_bn)<0) {
    /* Check for invalid public keys. */
    warn(LD_CRYPTO,"Rejected invalid g^x");
    goto error;
  }
  secret_tmp = tor_malloc(crypto_dh_get_bytes(dh));
  result = DH_compute_key((unsigned char*)secret_tmp, pubkey_bn, dh->dh);
  if (result < 0) {
    warn(LD_CRYPTO,"DH_compute_key() failed.");
    goto error;
  }
  secret_len = result;
  /* sometimes secret_len might be less than 128, e.g., 127. that's ok. */
  /* Actually, http://www.faqs.org/rfcs/rfc2631.html says:
   *   Leading zeros MUST be preserved, so that ZZ occupies as many
   *   octets as p. For instance, if p is 1024 bits, ZZ should be 128
   *   bytes long.
   * What are the security implications here?
   */
  if (crypto_expand_key_material(secret_tmp, secret_len,
                                 secret_out, secret_bytes_out)<0)
    goto error;
  secret_len = secret_bytes_out;

  goto done;
 error:
  result = -1;
 done:
  crypto_log_errors(LOG_WARN, "completing DH handshake");
  if (pubkey_bn)
    BN_free(pubkey_bn);
  tor_free(secret_tmp);
  if (result < 0)
    return result;
  else
    return secret_len;
}

/** Given <b>key_in_len</b> bytes of negotiated randomness in <b>key_in</b>
 * ("K"), expand it into <b>key_out_len</b> bytes of negotiated key material in
 * <b>key_out</b> by taking the first key_out_len bytes of
 *    H(K | [00]) | H(K | [01]) | ....
 *
 * Return 0 on success, -1 on failure.
 */
int
crypto_expand_key_material(const char *key_in, size_t key_in_len,
                           char *key_out, size_t key_out_len)
{
  int i;
  char *cp, *tmp = tor_malloc(key_in_len+1);
  char digest[DIGEST_LEN];

  /* If we try to get more than this amount of key data, we'll repeat blocks.*/
  tor_assert(key_out_len <= DIGEST_LEN*256);

  memcpy(tmp, key_in, key_in_len);
  for (cp = key_out, i=0; key_out_len; ++i, cp += DIGEST_LEN) {
    tmp[key_in_len] = i;
    if (crypto_digest(digest, tmp, key_in_len+1))
      goto err;
    memcpy(cp, digest, MIN(DIGEST_LEN, key_out_len));
    if (key_out_len < DIGEST_LEN)
      break;
    key_out_len -= DIGEST_LEN;
  }
  memset(tmp, 0, key_in_len+1);
  tor_free(tmp);
  return 0;

 err:
  memset(tmp, 0, key_in_len+1);
  tor_free(tmp);
  return -1;
}

/** Free a DH key exchange object.
 */
void
crypto_dh_free(crypto_dh_env_t *dh)
{
  tor_assert(dh);
  tor_assert(dh->dh);
  DH_free(dh->dh);
  tor_free(dh);
}

/* random numbers */

/* This is how much entropy OpenSSL likes to add right now, so maybe it will
 * work for us too. */
#define ADD_ENTROPY 32

/* Use RAND_poll if openssl is 0.9.6 release or later.  (The "f" means
   "release".)  */
#ifndef ENABLE_0119_PARANOIA_B2
#define USE_RAND_POLL (OPENSSL_VERSION_NUMBER >= 0x0090600fl)
#else
#define USE_RAND_POLL 0
#endif

/** Seed OpenSSL's random number generator with bytes from the
 * operating system.  Return 0 on success, -1 on failure.
 */
int
crypto_seed_rng(void)
{
  char buf[ADD_ENTROPY];
  int rand_poll_status;

  /* local variables */
#ifdef MS_WINDOWS
  static int provider_set = 0;
  static HCRYPTPROV provider;
#else
  static const char *filenames[] = {
    "/dev/srandom", "/dev/urandom", "/dev/random", NULL
  };
  int fd;
  int i, n;
#endif

#if USE_RAND_POLL
  /* OpenSSL 0.9.6 adds a RAND_poll function that knows about more kinds of
   * entropy than we do.  We'll try calling that, *and* calling our own entropy
   * functions.  If one succeeds, we'll accept the RNG as seeded. */
  rand_poll_status = RAND_poll();
  if (rand_poll_status == 0)
    warn(LD_CRYPTO, "RAND_poll() failed.");
#else
  rand_poll_status = 0;
#endif

#ifdef MS_WINDOWS
  if (!provider_set) {
    if (!CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT)) {
      if (GetLastError() != NTE_BAD_KEYSET) {
        warn(LD_CRYPTO, "Can't get CryptoAPI provider [1]");
        return rand_poll_status ? 0 : -1;
      }
    }
    provider_set = 1;
  }
  if (!CryptGenRandom(provider, sizeof(buf), buf)) {
    warn(LD_CRYPTO, "Can't get entropy from CryptoAPI.");
    return rand_poll_status ? 0 : -1;
  }
  RAND_seed(buf, sizeof(buf));
  return 0;
#else
  for (i = 0; filenames[i]; ++i) {
    fd = open(filenames[i], O_RDONLY, 0);
    if (fd<0) continue;
    info(LD_CRYPTO, "Seeding RNG from \"%s\"", filenames[i]);
    n = read_all(fd, buf, sizeof(buf), 0);
    close(fd);
    if (n != sizeof(buf)) {
      warn(LD_CRYPTO,
           "Error reading from entropy source (read only %d bytes).", n);
      return -1;
    }
    RAND_seed(buf, sizeof(buf));
    return 0;
  }

  warn(LD_CRYPTO, "Cannot seed RNG -- no entropy source found.");
  return rand_poll_status ? 0 : -1;
#endif
}

/** Write n bytes of strong random data to <b>to</b>. Return 0 on
 * success, -1 on failure.
 */
int
crypto_rand(char *to, size_t n)
{
  int r;
  tor_assert(to);
  r = RAND_bytes((unsigned char*)to, n);
  if (r == 0)
    crypto_log_errors(LOG_WARN, "generating random data");
  return (r == 1) ? 0 : -1;
}

/** Return a pseudorandom integer, chosen uniformly from the values
 * between 0 and max-1. */
int
crypto_rand_int(unsigned int max)
{
  unsigned int val;
  unsigned int cutoff;
  tor_assert(max < UINT_MAX);
  tor_assert(max > 0); /* don't div by 0 */

  /* We ignore any values that are >= 'cutoff,' to avoid biasing the
   * distribution with clipping at the upper end of unsigned int's
   * range.
   */
  cutoff = UINT_MAX - (UINT_MAX%max);
  while (1) {
    crypto_rand((char*)&val, sizeof(val));
    if (val < cutoff)
      return val % max;
  }
}

/** Return a randomly chosen element of sl; or NULL if sl is empty.
 */
void *
smartlist_choose(const smartlist_t *sl)
{
  size_t len;
  len = smartlist_len(sl);
  if (len)
    return smartlist_get(sl,crypto_rand_int(len));
  return NULL; /* no elements to choose from */
}

/** Base-64 encode <b>srclen</b> bytes of data from <b>src</b>.  Write
 * the result into <b>dest</b>, if it will fit within <b>destlen</b>
 * bytes.  Return the number of bytes written on success; -1 if
 * destlen is too short, or other failure.
 */
int
base64_encode(char *dest, size_t destlen, const char *src, size_t srclen)
{
  EVP_ENCODE_CTX ctx;
  int len, ret;

  /* 48 bytes of input -> 64 bytes of output plus newline.
     Plus one more byte, in case I'm wrong.
  */
  if (destlen < ((srclen/48)+1)*66)
    return -1;
  if (destlen > SIZE_T_CEILING)
    return -1;

  EVP_EncodeInit(&ctx);
  EVP_EncodeUpdate(&ctx, (unsigned char*)dest, &len,
                   (unsigned char*)src, srclen);
  EVP_EncodeFinal(&ctx, (unsigned char*)(dest+len), &ret);
  ret += len;
  return ret;
}

/** Base-64 decode <b>srclen</b> bytes of data from <b>src</b>.  Write
 * the result into <b>dest</b>, if it will fit within <b>destlen</b>
 * bytes.  Return the number of bytes written on success; -1 if
 * destlen is too short, or other failure.
 *
 * NOTE: destlen should be a little longer than the amount of data it
 * will contain, since we check for sufficient space conservatively.
 * Here, "a little" is around 64-ish bytes.
 */
int
base64_decode(char *dest, size_t destlen, const char *src, size_t srclen)
{
  EVP_ENCODE_CTX ctx;
  int len, ret;
  /* 64 bytes of input -> *up to* 48 bytes of output.
     Plus one more byte, in case I'm wrong.
  */
  if (destlen < ((srclen/64)+1)*49)
    return -1;
  if (destlen > SIZE_T_CEILING)
    return -1;

  EVP_DecodeInit(&ctx);
  EVP_DecodeUpdate(&ctx, (unsigned char*)dest, &len,
                   (unsigned char*)src, srclen);
  EVP_DecodeFinal(&ctx, (unsigned char*)dest, &ret);
  ret += len;
  return ret;
}

int
digest_to_base64(char *d64, const char *digest)
{
  char buf[256];
  base64_encode(buf, sizeof(buf), digest, DIGEST_LEN);
  buf[BASE64_DIGEST_LEN] = '\0';
  memcpy(d64, buf, BASE64_DIGEST_LEN+1);
  return 0;
}

int
digest_from_base64(char *digest, const char *d64)
{
  char buf_in[BASE64_DIGEST_LEN+3];
  char buf[256];
  if (strlen(d64) != BASE64_DIGEST_LEN)
    return -1;
  memcpy(buf_in, d64, BASE64_DIGEST_LEN);
  memcpy(buf_in+BASE64_DIGEST_LEN, "=\n\0", 3);
  if (base64_decode(buf, sizeof(buf), buf_in, strlen(buf_in)) != DIGEST_LEN)
    return -1;
  memcpy(digest, buf, DIGEST_LEN);
  return 0;
}

/** Implements base32 encoding as in rfc3548.  Limitation: Requires
 * that srclen*8 is a multiple of 5.
 */
void
base32_encode(char *dest, size_t destlen, const char *src, size_t srclen)
{
  unsigned int nbits, i, bit, v, u;
  nbits = srclen * 8;

  tor_assert((nbits%5) == 0); /* We need an even multiple of 5 bits. */
  tor_assert((nbits/5)+1 <= destlen); /* We need enough space. */
  tor_assert(destlen < SIZE_T_CEILING);

  for (i=0,bit=0; bit < nbits; ++i, bit+=5) {
    /* set v to the 16-bit value starting at src[bits/8], 0-padded. */
    v = ((uint8_t)src[bit/8]) << 8;
    if (bit+5<nbits) v += (uint8_t)src[(bit/8)+1];
    /* set u to the 5-bit value at the bit'th bit of src. */
    u = (v >> (11-(bit%8))) & 0x1F;
    dest[i] = BASE32_CHARS[u];
  }
  dest[i] = '\0';
}

/** Implement RFC2440-style iterated-salted S2K conversion: convert the
 * <b>secret_len</b>-byte <b>secret</b> into a <b>key_out_len</b> byte
 * <b>key_out</b>.  As in RFC2440, the first 8 bytes of s2k_specifier
 * are a salt; the 9th byte describes how much iteration to do.
 * Does not support <b>key_out_len</b> &gt; DIGEST_LEN.
 */
void
secret_to_key(char *key_out, size_t key_out_len, const char *secret,
              size_t secret_len, const char *s2k_specifier)
{
  crypto_digest_env_t *d;
  uint8_t c;
  size_t count;
  char *tmp;
  tor_assert(key_out_len < SIZE_T_CEILING);

#define EXPBIAS 6
  c = s2k_specifier[8];
  count = ((uint32_t)16 + (c & 15)) << ((c >> 4) + EXPBIAS);
#undef EXPBIAS

  tor_assert(key_out_len <= DIGEST_LEN);

  d = crypto_new_digest_env();
  tmp = tor_malloc(8+secret_len);
  memcpy(tmp,s2k_specifier,8);
  memcpy(tmp+8,secret,secret_len);
  secret_len += 8;
  while (count) {
    if (count >= secret_len) {
      crypto_digest_add_bytes(d, tmp, secret_len);
      count -= secret_len;
    } else {
      crypto_digest_add_bytes(d, tmp, count);
      count = 0;
    }
  }
  crypto_digest_get_digest(d, key_out, key_out_len);
  tor_free(tmp);
  crypto_free_digest_env(d);
}

#ifdef TOR_IS_MULTITHREADED
static void
_openssl_locking_cb(int mode, int n, const char *file, int line)
{
  if (!_openssl_mutexes)
    /* This is not a really good  fix for the
     * "release-freed-lock-from-separate-thread-on-shutdown" problem, but
     * it can't hurt. */
    return;
  if (mode & CRYPTO_LOCK)
    tor_mutex_acquire(_openssl_mutexes[n]);
  else
    tor_mutex_release(_openssl_mutexes[n]);
}

static int
setup_openssl_threading(void)
{
  int i;
  int n = CRYPTO_num_locks();
  _n_openssl_mutexes = n;
  _openssl_mutexes = tor_malloc(n*sizeof(tor_mutex_t *));
  for (i=0; i < n; ++i)
    _openssl_mutexes[i] = tor_mutex_new();
  CRYPTO_set_locking_callback(_openssl_locking_cb);
  CRYPTO_set_id_callback(tor_get_thread_id);
  return 0;
}
#else
static int
setup_openssl_threading(void)
{
  return 0;
}
#endif

