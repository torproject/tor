/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "orconfig.h"

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

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <limits.h>

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#include "crypto.h"
#include "log.h"
#include "aes.h"
#include "util.h"

#ifdef MS_WINDOWS
#include <wincrypt.h>
#endif

#if OPENSSL_VERSION_NUMBER < 0x00905000l
#error "We require openssl >= 0.9.5"
#elif OPENSSL_VERSION_NUMBER < 0x00906000l
#define OPENSSL_095
#endif

/*
 * Certain functions that return a success code in OpenSSL 0.9.6 return void
 * (and don't indicate errors) in OpenSSL version 0.9.5.
 *
 * [OpenSSL 0.9.5 matters, because it ships with Redhat 6.2.]
 */
#ifdef OPENSSL_095
#define RETURN_SSL_OUTCOME(exp) (exp); return 0
#else
#define RETURN_SSL_OUTCOME(exp) return !(exp)
#endif

struct crypto_pk_env_t
{
  int refs; /* reference counting; so we don't have to copy keys */
  RSA *key;
};

struct crypto_cipher_env_t
{
  unsigned char key[CIPHER_KEY_LEN];
  unsigned char iv[CIPHER_IV_LEN];
  aes_cnt_cipher_t *cipher;
};

struct crypto_dh_env_t {
  DH *dh;
};

static INLINE int
crypto_get_rsa_padding_overhead(int padding) {
  switch(padding)
    {
    case RSA_NO_PADDING: return 0;
    case RSA_PKCS1_OAEP_PADDING: return 42;
    case RSA_PKCS1_PADDING: return 11;
    default: assert(0); return -1;
    }
}

static INLINE int
crypto_get_rsa_padding(int padding) {
  switch(padding)
    {
    case PK_NO_PADDING: return RSA_NO_PADDING;
    case PK_PKCS1_PADDING: return RSA_PKCS1_PADDING;
    case PK_PKCS1_OAEP_PADDING: return RSA_PKCS1_OAEP_PADDING;
    default: assert(0); return -1;
    }
}

static int _crypto_global_initialized = 0;

int crypto_global_init()
{
  if (!_crypto_global_initialized) {
      ERR_load_crypto_strings();
      _crypto_global_initialized = 1;
  }
  return 0;
}

int crypto_global_cleanup()
{
  ERR_free_strings();
  return 0;
}

/* used by tortls.c */
crypto_pk_env_t *_crypto_new_pk_env_rsa(RSA *rsa)
{
  crypto_pk_env_t *env;
  assert(rsa);
  env = tor_malloc(sizeof(crypto_pk_env_t));
  env->refs = 1;
  env->key = rsa;
  return env;
}

/* used by tortls.c */
RSA *_crypto_pk_env_get_rsa(crypto_pk_env_t *env)
{
  return env->key;
}

/* used by tortls.c */
EVP_PKEY *_crypto_pk_env_get_evp_pkey(crypto_pk_env_t *env)
{
  RSA *key = NULL;
  EVP_PKEY *pkey = NULL;
  assert(env->key);
  if (!(key = RSAPrivateKey_dup(env->key)))
    goto error;
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

DH *_crypto_dh_env_get_dh(crypto_dh_env_t *dh)
{
  return dh->dh;
}

crypto_pk_env_t *crypto_new_pk_env(void)
{
  RSA *rsa;

  rsa = RSA_new();
  if (!rsa) return NULL;
  return _crypto_new_pk_env_rsa(rsa);
}

void crypto_free_pk_env(crypto_pk_env_t *env)
{
  assert(env);

  if(--env->refs > 0)
    return;

  if (env->key)
    RSA_free(env->key);

  free(env);
}


/* Create a new crypto_cipher_env_t for a given onion cipher type, key,
 * iv, and encryption flag (1=encrypt, 0=decrypt).  Return the crypto object
 * on success; NULL on failure.
 */
crypto_cipher_env_t *
crypto_create_init_cipher(const char *key, const char *iv, int encrypt_mode)
{
  int r;
  crypto_cipher_env_t *crypto = NULL;

  if (! (crypto = crypto_new_cipher_env())) {
    log_fn(LOG_WARN, "Unable to allocate crypto object");
    return NULL;
  }

  if (crypto_cipher_set_key(crypto, key)) {
    log_fn(LOG_WARN, "Unable to set key: %s", crypto_perror());
    goto error;
  }

  if (crypto_cipher_set_iv(crypto, iv)) {
    log_fn(LOG_WARN, "Unable to set iv: %s", crypto_perror());
    goto error;
  }

  if (encrypt_mode)
    r = crypto_cipher_encrypt_init_cipher(crypto);
  else
    r = crypto_cipher_decrypt_init_cipher(crypto);

  if (r) {
    log_fn(LOG_WARN, "Unable to initialize cipher: %s", crypto_perror());
    goto error;
  }
  return crypto;

 error:
  if (crypto)
    crypto_free_cipher_env(crypto);
  return NULL;
}

crypto_cipher_env_t *crypto_new_cipher_env()
{
  crypto_cipher_env_t *env;

  env = tor_malloc_zero(sizeof(crypto_cipher_env_t));
  env->cipher = aes_new_cipher();
  return env;
}

void crypto_free_cipher_env(crypto_cipher_env_t *env)
{
  assert(env);

  assert(env->cipher);
  aes_free_cipher(env->cipher);
  tor_free(env);
}

/* public key crypto */
int crypto_pk_generate_key(crypto_pk_env_t *env)
{
  assert(env);

  if (env->key)
    RSA_free(env->key);
  env->key = RSA_generate_key(PK_BITS,65537, NULL, NULL);
  if (!env->key)
    return -1;

  return 0;
}

int crypto_pk_read_private_key_from_file(crypto_pk_env_t *env, FILE *src)
{
  assert(env && src);

  if (env->key)
    RSA_free(env->key);
  env->key = PEM_read_RSAPrivateKey(src, NULL, NULL, NULL);
  if (!env->key)
    return -1;

  return 0;
}

int crypto_pk_read_private_key_from_filename(crypto_pk_env_t *env, const char *keyfile)
{
  FILE *f_pr;

  assert(env && keyfile);

  if(strspn(keyfile,CONFIG_LEGAL_FILENAME_CHARACTERS) != strlen(keyfile)) {
    /* filename contains nonlegal characters */
    return -1;
  }

  /* open the keyfile */
  f_pr=fopen(keyfile,"rb");
  if (!f_pr)
    return -1;

  /* read the private key */
  if(crypto_pk_read_private_key_from_file(env, f_pr) < 0) {
    log_fn(LOG_WARN,"Error reading private key : %s",crypto_perror());
    fclose(f_pr);
    return -1;
  }
  fclose(f_pr);

  /* check the private key */
  switch(crypto_pk_check_key(env)) {
    case 0:
      log_fn(LOG_WARN,"Private key read but is invalid : %s.", crypto_perror());
      return -1;
    case -1:
      log_fn(LOG_WARN,"Private key read but validity checking failed : %s",crypto_perror());
      return -1;
    /* case 1: fall through */
  }
  return 0;
}

int crypto_pk_read_public_key_from_file(crypto_pk_env_t *env, FILE *src)
{
  assert(env && src);

  if(env->key)
    RSA_free(env->key);
  env->key = PEM_read_RSAPublicKey(src, NULL, NULL, NULL);
  if (!env->key)
    return -1;

  return 0;
}

int crypto_pk_write_public_key_to_string(crypto_pk_env_t *env, char **dest, int *len) {
  BUF_MEM *buf;
  BIO *b;

  assert(env && env->key && dest);

  b = BIO_new(BIO_s_mem()); /* Create a memory BIO */

  /* Now you can treat b as if it were a file.  Just use the
   * PEM_*_bio_* functions instead of the non-bio variants.
   */
  if(!PEM_write_bio_RSAPublicKey(b, env->key))
    return -1;

  BIO_get_mem_ptr(b, &buf);
  BIO_set_close(b, BIO_NOCLOSE); /* so BIO_free doesn't free buf */
  BIO_free(b);

  *dest = tor_malloc(buf->length+1);
  memcpy(*dest, buf->data, buf->length);
  (*dest)[buf->length] = 0; /* null terminate it */
  *len = buf->length;
  BUF_MEM_free(buf);

  return 0;
}

int crypto_pk_read_public_key_from_string(crypto_pk_env_t *env, const char *src, int len) {
  BIO *b;

  assert(env && src);

  b = BIO_new(BIO_s_mem()); /* Create a memory BIO */

  BIO_write(b, src, len);

  if (env->key)
    RSA_free(env->key);
  env->key = PEM_read_bio_RSAPublicKey(b, NULL, NULL, NULL);
  if(!env->key)
    return -1;

  return 0;
}

int
crypto_pk_write_private_key_to_filename(crypto_pk_env_t *env,
                                        const char *fname)
{
  BIO *bio;
  char *cp;
  long len;
  char *s;
  int r;

  if (!(bio = BIO_new(BIO_s_mem())))
    return -1;
  if (PEM_write_bio_RSAPrivateKey(bio, env->key, NULL,NULL,0,NULL,NULL)
      == 0) {
    BIO_free(bio);
    return -1;
  }
  len = BIO_get_mem_data(bio, &cp);
  s = tor_malloc(len+1);
  strncpy(s, cp, len);
  s[len] = '\0';
  r = write_str_to_file(fname, s);
  BIO_free(bio);
  free(s);
  return r;
}

int crypto_pk_write_private_key_to_file(crypto_pk_env_t *env, FILE *dest)
{
  assert(env && dest);

  if (!env->key)
    return -1;
  if (PEM_write_RSAPrivateKey(dest, env->key, NULL, NULL, 0,0, NULL) == 0)
    return -1;

  return 0;
}
int crypto_pk_write_public_key_to_file(crypto_pk_env_t *env, FILE *dest)
{
  assert(env && dest);

  if (!env->key)
    return -1;
  if (PEM_write_RSAPublicKey(dest, env->key) == 0)
    return -1;

  return 0;
}

int crypto_pk_check_key(crypto_pk_env_t *env)
{
  assert(env);

  return RSA_check_key(env->key);
}

int crypto_pk_cmp_keys(crypto_pk_env_t *a, crypto_pk_env_t *b) {
  int result;

  if (!a || !b)
    return -1;

  if (!a->key || !b->key)
    return -1;

  assert((a->key)->n && (a->key)->e && (b->key)->n && (b->key)->e);
  result = BN_cmp((a->key)->n, (b->key)->n);
  if (result)
    return result;
  return BN_cmp((a->key)->e, (b->key)->e);
}

/* return the size of the public key modulus in 'env', in bytes. */
int crypto_pk_keysize(crypto_pk_env_t *env)
{
  assert(env && env->key);

  return RSA_size(env->key);
}

crypto_pk_env_t *crypto_pk_dup_key(crypto_pk_env_t *env) {
  assert(env && env->key);

  env->refs++;
  return env;
}

int crypto_pk_public_encrypt(crypto_pk_env_t *env, const unsigned char *from, int fromlen, unsigned char *to, int padding)
{
  assert(env && from && to);

  return RSA_public_encrypt(fromlen, (unsigned char*)from, to, env->key,
                            crypto_get_rsa_padding(padding));
}

int crypto_pk_private_decrypt(crypto_pk_env_t *env, const unsigned char *from, int fromlen, unsigned char *to, int padding)
{
  assert(env && from && to && env->key);
  if (!env->key->p)
    /* Not a private key */
    return -1;

  return RSA_private_decrypt(fromlen, (unsigned char*)from, to, env->key,
                             crypto_get_rsa_padding(padding));
}

int crypto_pk_public_checksig(crypto_pk_env_t *env, const unsigned char *from, int fromlen, unsigned char *to)
{
  assert(env && from && to);
  return RSA_public_decrypt(fromlen, (unsigned char*)from, to, env->key, RSA_PKCS1_PADDING);
}

int crypto_pk_private_sign(crypto_pk_env_t *env, const unsigned char *from, int fromlen, unsigned char *to)
{
  assert(env && from && to);
  if (!env->key->p)
    /* Not a private key */
    return -1;

  return RSA_private_encrypt(fromlen, (unsigned char*)from, to, env->key, RSA_PKCS1_PADDING);
}

/* Return 0 if sig is a correct signature for SHA1(data).  Else return -1.
 */
int crypto_pk_public_checksig_digest(crypto_pk_env_t *env, const unsigned char *data, int datalen, const unsigned char *sig, int siglen)
{
  char digest[DIGEST_LEN];
  char buf[PK_BYTES+1];
  int r;

  assert(env && data && sig);

  if (crypto_digest(data,datalen,digest)<0) {
    log_fn(LOG_WARN, "couldn't compute digest");
    return -1;
  }
  r = crypto_pk_public_checksig(env,sig,siglen,buf);
  if (r != DIGEST_LEN) {
    log_fn(LOG_WARN, "Invalid signature");
    return -1;
  }
  if (memcmp(buf, digest, DIGEST_LEN)) {
    log_fn(LOG_WARN, "Signature mismatched with digest.");
    return -1;
  }

  return 0;
}

/* Fill 'to' with a signature of SHA1(from).
 */
int crypto_pk_private_sign_digest(crypto_pk_env_t *env, const unsigned char *from, int fromlen, unsigned char *to)
{
  char digest[DIGEST_LEN];
  if (crypto_digest(from,fromlen,digest)<0)
    return 0;
  return crypto_pk_private_sign(env,digest,DIGEST_LEN,to);
}


/* Perform a hybrid (public/secret) encryption on 'fromlen' bytes of data
 * from 'from', with padding type 'padding', storing the results on 'to'.
 *
 * If no padding is used, the public key must be at least as large as
 * 'from'.
 *
 * Returns the number of bytes written on success, -1 on failure.
 *
 * The encrypted data consists of:
 *
 *   The source data, padded and encrypted with the public key, if the
 *   padded source data is no longer than the public key.
 *  OR
 *   The beginning of the source data prefixed with a 16-symmetric key,
 *   padded and encrypted with the public key; followed by the rest of
 *   the source data encrypted in AES-CTR mode with the symmetric key.
 */
int crypto_pk_public_hybrid_encrypt(crypto_pk_env_t *env,
                                    const unsigned char *from,
                                    int fromlen, unsigned char *to,
                                    int padding)
{
  int overhead, pkeylen, outlen, r, symlen;
  crypto_cipher_env_t *cipher = NULL;
  char buf[PK_BYTES+1];

  assert(env && from && to);

  overhead = crypto_get_rsa_padding_overhead(crypto_get_rsa_padding(padding));
  pkeylen = crypto_pk_keysize(env);

  if (padding == PK_NO_PADDING && fromlen < pkeylen)
    return -1;

  if (fromlen+overhead <= pkeylen) {
    /* It all fits in a single encrypt. */
    return crypto_pk_public_encrypt(env,from,fromlen,to,padding);
  }
  cipher = crypto_new_cipher_env();
  if (!cipher) return -1;
  if (crypto_cipher_generate_key(cipher)<0)
    goto err;
  if (padding == PK_NO_PADDING)
    cipher->key[0] &= 0x7f;
  if (crypto_cipher_encrypt_init_cipher(cipher)<0)
    goto err;
  memcpy(buf, cipher->key, CIPHER_KEY_LEN);
  memcpy(buf+CIPHER_KEY_LEN, from, pkeylen-overhead-CIPHER_KEY_LEN);

  /* Length of symmetrically encrypted data. */
  symlen = fromlen-(pkeylen-overhead-CIPHER_KEY_LEN);

  outlen = crypto_pk_public_encrypt(env,buf,pkeylen-overhead,to,padding);
  if (outlen!=pkeylen) {
    goto err;
  }
  r = crypto_cipher_encrypt(cipher,
                            from+pkeylen-overhead-CIPHER_KEY_LEN, symlen,
                            to+outlen);

  if (r<0) goto err;
  memset(buf, 0, sizeof(buf));
  crypto_free_cipher_env(cipher);
  return outlen + symlen;
 err:
  memset(buf, 0, sizeof(buf));
  if (cipher) crypto_free_cipher_env(cipher);
  return -1;
}

/* Invert crypto_pk_public_hybrid_encrypt. */
int crypto_pk_private_hybrid_decrypt(crypto_pk_env_t *env,
                                     const unsigned char *from,
                                     int fromlen, unsigned char *to,
                                     int padding)
{
  int overhead, pkeylen, outlen, r;
  crypto_cipher_env_t *cipher = NULL;
  char buf[PK_BYTES+1];

  overhead = crypto_get_rsa_padding_overhead(crypto_get_rsa_padding(padding));
  pkeylen = crypto_pk_keysize(env);

  if (fromlen <= pkeylen) {
    return crypto_pk_private_decrypt(env,from,fromlen,to,padding);
  }
  outlen = crypto_pk_private_decrypt(env,from,pkeylen,buf,padding);
  if (outlen<0) {
    log_fn(LOG_WARN, "Error decrypting public-key data");
    return -1;
  }
  if (outlen < CIPHER_KEY_LEN) {
    log_fn(LOG_WARN, "No room for a symmetric key");
    return -1;
  }
  cipher = crypto_create_init_cipher(buf, NULL, 0);
  if (!cipher) {
    return -1;
  }
  memcpy(to,buf+CIPHER_KEY_LEN,outlen-CIPHER_KEY_LEN);
  outlen -= CIPHER_KEY_LEN;
  r = crypto_cipher_decrypt(cipher, from+pkeylen, fromlen-pkeylen,
                            to+outlen);
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

/* Encode the public portion of 'pk' into 'dest'.  Return -1 on error,
 * or the number of characters used on success.
 */
int crypto_pk_asn1_encode(crypto_pk_env_t *pk, char *dest, int dest_len)
{
  int len;
  unsigned char *buf, *cp;
  len = i2d_RSAPublicKey(pk->key, NULL);
  if (len < 0 || len > dest_len)
    return -1;
  cp = buf = tor_malloc(len+1);
  len = i2d_RSAPublicKey(pk->key, &cp);
  if (len < 0) {
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

/* Decode an ASN1-encoded public key from str.
 */
crypto_pk_env_t *crypto_pk_asn1_decode(const char *str, int len)
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
  if (!rsa)
    return NULL; /* XXXX log openssl error */
  return _crypto_new_pk_env_rsa(rsa);
}

/* Given a private or public key pk, put a SHA1 hash of the public key into
 * digest_out (must have DIGEST_LEN bytes of space).
 */
int crypto_pk_get_digest(crypto_pk_env_t *pk, char *digest_out)
{
  unsigned char *buf, *bufp;
  int len;

  len = i2d_RSAPublicKey(pk->key, NULL);
  if (len < 0)
    return -1;
  buf = bufp = tor_malloc(len+1);
  len = i2d_RSAPublicKey(pk->key, &bufp);
  if (len < 0) {
    free(buf);
    return -1;
  }
  if (crypto_digest(buf, len, digest_out) < 0) {
    free(buf);
    return -1;
  }
  return 0;
}

/* Given a private or public key pk, put a fingerprint of the
 * public key into fp_out (must have at least FINGERPRINT_LEN+1 bytes of
 * space).
 */
int
crypto_pk_get_fingerprint(crypto_pk_env_t *pk, char *fp_out)
{
  unsigned char *bufp;
  unsigned char digest[DIGEST_LEN];
  unsigned char buf[FINGERPRINT_LEN+1];
  int i;
  if (crypto_pk_get_digest(pk, digest)) {
    return -1;
  }
  bufp = buf;
  for (i = 0; i < DIGEST_LEN; ++i) {
    sprintf(bufp,"%02X",digest[i]);
    bufp += 2;
    if (i%2 && i != 19) {
      *bufp++ = ' ';
    }
  }
  *bufp = '\0';
  assert(strlen(buf) == FINGERPRINT_LEN);
  assert(crypto_pk_check_fingerprint_syntax(buf));
  strcpy(fp_out, buf);
  return 0;
}

int
crypto_pk_check_fingerprint_syntax(const char *s)
{
  int i;
  for (i = 0; i < FINGERPRINT_LEN; ++i) {
    if ((i%5) == 4) {
      if (!isspace((int)s[i])) return 0;
    } else {
      if (!isxdigit((int)s[i])) return 0;
    }
  }
  if (s[FINGERPRINT_LEN]) return 0;
  return 1;
}

/* symmetric crypto */
int crypto_cipher_generate_key(crypto_cipher_env_t *env)
{
  assert(env);

  return crypto_rand(CIPHER_KEY_LEN, env->key);
}

int crypto_cipher_set_iv(crypto_cipher_env_t *env, const unsigned char *iv)
{
  assert(env && (CIPHER_IV_LEN==0 || iv));

  if (!CIPHER_IV_LEN)
    return 0;

  if (!env->iv)
    return -1;

  memcpy(env->iv, iv, CIPHER_IV_LEN);

  return 0;
}

int crypto_cipher_set_key(crypto_cipher_env_t *env, const unsigned char *key)
{
  assert(env && key);

  if (!env->key)
    return -1;

  memcpy(env->key, key, CIPHER_KEY_LEN);

  return 0;
}

const unsigned char *crypto_cipher_get_key(crypto_cipher_env_t *env)
{
  return env->key;
}

int crypto_cipher_encrypt_init_cipher(crypto_cipher_env_t *env)
{
  assert(env);

  aes_set_key(env->cipher, env->key, CIPHER_KEY_LEN*8);
  return 0;
}

int crypto_cipher_decrypt_init_cipher(crypto_cipher_env_t *env)
{
  assert(env);

  aes_set_key(env->cipher, env->key, CIPHER_KEY_LEN*8);
  return 0;
}

int crypto_cipher_encrypt(crypto_cipher_env_t *env, const unsigned char *from, unsigned int fromlen, unsigned char *to)
{
  assert(env && env->cipher && from && fromlen && to);

  aes_crypt(env->cipher, from, fromlen, to);
  return 0;
}

int crypto_cipher_decrypt(crypto_cipher_env_t *env, const unsigned char *from, unsigned int fromlen, unsigned char *to)
{
  assert(env && from && to);

  aes_crypt(env->cipher, from, fromlen, to);
  return 0;
}

int
crypto_cipher_rewind(crypto_cipher_env_t *env, long delta)
{
  return crypto_cipher_advance(env, -delta);
}

int
crypto_cipher_advance(crypto_cipher_env_t *env, long delta)
{
  aes_adjust_counter(env->cipher, delta);
  return 0;
}

/* SHA-1 */
int crypto_digest(const unsigned char *m, int len, unsigned char *digest)
{
  assert(m && digest);
  return (SHA1(m,len,digest) == NULL);
}

struct crypto_digest_env_t {
  SHA_CTX d;
};

crypto_digest_env_t *
crypto_new_digest_env(void)
{
  crypto_digest_env_t *r;
  r = tor_malloc(sizeof(crypto_digest_env_t));
  SHA1_Init(&r->d);
  return r;
}

void
crypto_free_digest_env(crypto_digest_env_t *digest) {
  tor_free(digest);
}

void
crypto_digest_add_bytes(crypto_digest_env_t *digest, const char *data,
                        size_t len)
{
  assert(digest);
  assert(data);
  SHA1_Update(&digest->d, (void*)data, len);
}

void crypto_digest_get_digest(crypto_digest_env_t *digest,
                              char *out, size_t out_len)
{
  static char r[DIGEST_LEN];
  assert(digest && out);
  assert(out_len <= DIGEST_LEN);
  SHA1_Final(r, &digest->d);
  memcpy(out, r, out_len);
}

crypto_digest_env_t *
crypto_digest_dup(const crypto_digest_env_t *digest)
{
  crypto_digest_env_t *r;
  assert(digest);
  r = tor_malloc(sizeof(crypto_digest_env_t));
  memcpy(r,digest,sizeof(crypto_digest_env_t));
  return r;
}

void
crypto_digest_assign(crypto_digest_env_t *into,
                     const crypto_digest_env_t *from)
{
  assert(into && from);
  memcpy(into,from,sizeof(crypto_digest_env_t));
}

/* DH */
static BIGNUM *dh_param_p = NULL;
static BIGNUM *dh_param_g = NULL;

static void init_dh_param() {
  BIGNUM *p, *g;
  int r;
  if (dh_param_p && dh_param_g)
    return;

  p = BN_new();
  g = BN_new();
  assert(p && g);

#if 0
  /* This is from draft-ietf-ipsec-ike-modp-groups-05.txt.  It's a safe
     prime, and supposedly it equals:
      2^1536 - 2^1472 - 1 + 2^64 * { [2^1406 pi] + 741804 }
  */
  r = BN_hex2bn(&p,
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF");
#endif

  /* This is from rfc2409, section 6.2.  It's a safe prime, and
     supposedly it equals:
        2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 }.
  */
  /* See also rfc 3536 */
  r = BN_hex2bn(&p,
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
                "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
                "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
                "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
                "49286651ECE65381FFFFFFFFFFFFFFFF");
  assert(r);

  r = BN_set_word(g, 2);
  assert(r);
  dh_param_p = p;
  dh_param_g = g;
}

crypto_dh_env_t *crypto_dh_new()
{
  crypto_dh_env_t *res = NULL;

  if (!dh_param_p)
    init_dh_param();

  res = tor_malloc(sizeof(crypto_dh_env_t));
  res->dh = NULL;

  if (!(res->dh = DH_new()))
    goto err;

  if (!(res->dh->p = BN_dup(dh_param_p)))
    goto err;

  if (!(res->dh->g = BN_dup(dh_param_g)))
    goto err;

  return res;
 err:
  if (res && res->dh) DH_free(res->dh); /* frees p and g too */
  if (res) free(res);
  return NULL;
}
int crypto_dh_get_bytes(crypto_dh_env_t *dh)
{
  assert(dh);
  return DH_size(dh->dh);
}
int crypto_dh_generate_public(crypto_dh_env_t *dh)
{
  if (!DH_generate_key(dh->dh))
    return -1;
  return 0;
}
int crypto_dh_get_public(crypto_dh_env_t *dh, char *pubkey, int pubkey_len)
{
  int bytes;
  assert(dh);
  if (!dh->dh->pub_key) {
    if (!DH_generate_key(dh->dh))
      return -1;
  }

  assert(dh->dh->pub_key);
  bytes = BN_num_bytes(dh->dh->pub_key);
  if (pubkey_len < bytes)
    return -1;

  memset(pubkey, 0, pubkey_len);
  BN_bn2bin(dh->dh->pub_key, pubkey+(pubkey_len-bytes));

  return 0;
}

#undef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
int crypto_dh_compute_secret(crypto_dh_env_t *dh,
                             const char *pubkey, int pubkey_len,
                             char *secret_out, int secret_bytes_out)
{
  unsigned char hash[DIGEST_LEN];
  unsigned char *secret_tmp = NULL;
  BIGNUM *pubkey_bn = NULL;
  int secret_len;
  int i;
  assert(dh);
  assert(secret_bytes_out/DIGEST_LEN <= 255);

  if (!(pubkey_bn = BN_bin2bn(pubkey, pubkey_len, NULL)))
    goto error;
  secret_tmp = tor_malloc(crypto_dh_get_bytes(dh)+1);
  secret_len = DH_compute_key(secret_tmp, pubkey_bn, dh->dh);
  /* sometimes secret_len might be less than 128, e.g., 127. that's ok. */
  for (i = 0; i < secret_bytes_out; i += DIGEST_LEN) {
    secret_tmp[secret_len] = (unsigned char) i/DIGEST_LEN;
    if (crypto_digest(secret_tmp, secret_len+1, hash))
      goto error;
    memcpy(secret_out+i, hash, MIN(DIGEST_LEN, secret_bytes_out-i));
  }
  secret_len = secret_bytes_out;

  goto done;
 error:
  secret_len = -1;
 done:
  if (pubkey_bn)
    BN_free(pubkey_bn);
  tor_free(secret_tmp);
  return secret_len;
}
void crypto_dh_free(crypto_dh_env_t *dh)
{
  assert(dh && dh->dh);
  DH_free(dh->dh);
  free(dh);
}

/* random numbers */
#ifdef MS_WINDOWS
int crypto_seed_rng()
{
  static int provider_set = 0;
  static HCRYPTPROV provider;
  char buf[DIGEST_LEN+1];

  if (!provider_set) {
    if (!CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL, 0)) {
      if (GetLastError() != NTE_BAD_KEYSET) {
        log_fn(LOG_ERR,"Can't get CryptoAPI provider [1]");
        return -1;
      }
      /* Yes, we need to try it twice. */
      if (!CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL,
                               CRYPT_NEWKEYSET)) {
        log_fn(LOG_ERR,"Can't get CryptoAPI provider [2]");
        return -1;
      }
    }
    provider_set = 1;
  }
  if (!CryptGenRandom(provider, DIGEST_LEN, buf)) {
    log_fn(LOG_ERR,"Can't get entropy from CryptoAPI.");
    return -1;
  }
  RAND_seed(buf, DIGEST_LEN);
  /* And add the current screen state to the entopy pool for
   * good measure. */
  RAND_screen();
  return 0;
}
#else
int crypto_seed_rng()
{
  static char *filenames[] = {
    "/dev/srandom", "/dev/urandom", "/dev/random", NULL
  };
  int i, n;
  char buf[DIGEST_LEN+1];
  FILE *f;

  for (i = 0; filenames[i]; ++i) {
    f = fopen(filenames[i], "rb");
    if (!f) continue;
    log_fn(LOG_INFO, "Seeding RNG from %s", filenames[i]);
    n = fread(buf, 1, DIGEST_LEN, f);
    fclose(f);
    if (n != DIGEST_LEN) {
      log_fn(LOG_WARN, "Error reading from entropy source");
      return -1;
    }
    RAND_seed(buf, DIGEST_LEN);
    return 0;
  }

  log_fn(LOG_WARN, "Cannot seed RNG -- no entropy source found.");
  return -1;
}
#endif

int crypto_rand(unsigned int n, unsigned char *to)
{
  assert(to);
  return (RAND_bytes(to, n) != 1);
}

void crypto_pseudo_rand(unsigned int n, unsigned char *to)
{
  assert(to);
  if (RAND_pseudo_bytes(to, n) == -1) {
    log_fn(LOG_ERR, "RAND_pseudo_bytes failed unexpectedly.");
    exit(1);
  }
}

/* return a pseudo random number between 0 and max-1 */
int crypto_pseudo_rand_int(unsigned int max) {
  unsigned int val;
  unsigned int cutoff;
  assert(max < UINT_MAX);
  assert(max > 0); /* don't div by 0 */

  /* We ignore any values that are >= 'cutoff,' to avoid biasing the
   * distribution with clipping at the upper end of unsigned int's
   * range.
   */
  cutoff = UINT_MAX - (UINT_MAX%max);
  while(1) {
    crypto_pseudo_rand(sizeof(val), (unsigned char*) &val);
    if (val < cutoff)
      return val % max;
  }
}

/* errors */
const char *crypto_perror()
{
  return (const char *)ERR_reason_error_string(ERR_get_error());
}

int
base64_encode(char *dest, int destlen, const char *src, int srclen)
{
  EVP_ENCODE_CTX ctx;
  int len, ret;

  /* 48 bytes of input -> 64 bytes of output plus newline.
     Plus one more byte, in case I'm wrong.
  */
  if (destlen < ((srclen/48)+1)*66)
    return -1;

  EVP_EncodeInit(&ctx);
  EVP_EncodeUpdate(&ctx, dest, &len, (char*) src, srclen);
  EVP_EncodeFinal(&ctx, dest+len, &ret);
  ret += len;
  return ret;
}
int
base64_decode(char *dest, int destlen, const char *src, int srclen)
{
  EVP_ENCODE_CTX ctx;
  int len, ret;
  /* 64 bytes of input -> *up to* 48 bytes of output.
     Plus one more byte, in caes I'm wrong.
  */
  if (destlen < ((srclen/64)+1)*49)
    return -1;

  EVP_DecodeInit(&ctx);
  EVP_DecodeUpdate(&ctx, dest, &len, (char*) src, srclen);
  EVP_DecodeFinal(&ctx, dest, &ret);
  ret += len;
  return ret;
}

int
base32_encode(char *dest, int destlen, const char *src, int srclen)
{
  int nbits, i, bit, v, u;
  nbits = srclen * 8;

  if ((nbits%5) != 0)
    /* We need an even multiple of 5 bits. */
    return -1;
  if ((nbits/5)+1 < destlen)
    /* Not enough space. */
    return -1;

  for (i=0,bit=0; bit < nbits; ++i, bit+=5) {
    /* set v to the 16-bit value starting at src[bits/8], 0-padded. */
    v = ((unsigned char)src[bit/8]) << 8;
    if (bit+5<nbits) v += src[(bit/8)+1];
    /* set u to the 5-bit value at the bit'th bit of src. */
    u = (v >> (11-(bit%8))) & 0x1F;
    dest[i] = BASE32_CHARS[u];
  }
  dest[i] = '\0';
  return 0;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
