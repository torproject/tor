/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "../or/or.h"

#include <string.h>

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include <openssl/bn.h>
#include <openssl/dh.h>

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <limits.h>

#include "crypto.h"
#include "log.h"
#include "aes.h"

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
  int type;
  int refs; /* reference counting; so we don't have to copy keys */
  unsigned char *key;
  /* auxiliary data structure(s) used by the underlying crypto library */
  unsigned char *aux;
};

struct crypto_cipher_env_t
{
  int type;
  unsigned char *key;
  unsigned char *iv;
  /* auxiliary data structure(s) used by the underlying crypto library */
  unsigned char *aux;
};

/* static INLINE const EVP_CIPHER *
   crypto_cipher_evp_cipher(int type, int enc);
*/

static INLINE int
crypto_cipher_iv_length(int type) {
  /*
  printf("%d -> %d IV\n",type,
         EVP_CIPHER_iv_length(crypto_cipher_evp_cipher(type,0)));
  */
  switch(type)
    {
    case CRYPTO_CIPHER_IDENTITY: return 0;
    case CRYPTO_CIPHER_DES: return 8;
    case CRYPTO_CIPHER_RC4: return 16;
    case CRYPTO_CIPHER_3DES: return 8;
    case CRYPTO_CIPHER_AES_CTR: return 0;
    default: assert(0); return -1;
    }
}

static INLINE int
crypto_cipher_key_length(int type) {
  /*
  printf("%d -> %d\n",type,
         EVP_CIPHER_key_length(crypto_cipher_evp_cipher(type,0)));
  */
  switch(type)
    {
    case CRYPTO_CIPHER_IDENTITY: return 0;
    case CRYPTO_CIPHER_DES: return 8;
    case CRYPTO_CIPHER_RC4: return 16;
    case CRYPTO_CIPHER_3DES: return 16;
    case CRYPTO_CIPHER_AES_CTR: return 16;
    default: assert(0); return -1;
    }
}

static INLINE const EVP_CIPHER *
crypto_cipher_evp_cipher(int type, int enc) {
  switch(type)
    {
    case CRYPTO_CIPHER_IDENTITY: return EVP_enc_null();
    case CRYPTO_CIPHER_DES: return EVP_des_ofb();
    case CRYPTO_CIPHER_RC4: return EVP_rc4();
    case CRYPTO_CIPHER_3DES: return EVP_des_ede_ofb();
    default: return NULL;
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

crypto_pk_env_t *_crypto_new_pk_env_rsa(RSA *rsa)
{
  crypto_pk_env_t *env;
  assert(rsa);
  env = (crypto_pk_env_t *)tor_malloc(sizeof(crypto_pk_env_t));
  env->type = CRYPTO_PK_RSA;
  env->refs = 1;
  env->key = (unsigned char*)rsa;
  env->aux = NULL;
  return env;
}

RSA *_crypto_pk_env_get_rsa(crypto_pk_env_t *env)
{
  if (env->type != CRYPTO_PK_RSA)
    return NULL;
  return (RSA*)env->key;
}

EVP_PKEY *_crypto_pk_env_get_evp_pkey(crypto_pk_env_t *env)
{
  RSA *key = NULL;
  EVP_PKEY *pkey = NULL;
  if (env->type != CRYPTO_PK_RSA)
    return NULL;
  assert(env->key);
  if (!(key = RSAPrivateKey_dup((RSA*)env->key)))
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

crypto_pk_env_t *crypto_new_pk_env(int type)
{
  RSA *rsa;

  switch(type) {
    case CRYPTO_PK_RSA:
      rsa = RSA_new();
      if (!rsa) return NULL;
      return _crypto_new_pk_env_rsa(rsa);
    default:
      return NULL;
  }
}

void crypto_free_pk_env(crypto_pk_env_t *env)
{
  assert(env);

  if(--env->refs > 0)
    return;

  switch(env->type) {
    case CRYPTO_PK_RSA:
      if (env->key)
        RSA_free((RSA *)env->key);
      break;
    default:
      break;
  }

  free(env);
}


/* Create a new crypto_cipher_env_t for a given onion cipher type, key,
 * iv, and encryption flag (1=encrypt, 0=decrypt).  Return the crypto object
 * on success; NULL on failure.
 */
crypto_cipher_env_t *
crypto_create_init_cipher(int cipher_type, char *key, char *iv, int encrypt_mode)
{
  int r;
  crypto_cipher_env_t *crypto = NULL;

  if (! (crypto = crypto_new_cipher_env(cipher_type))) {
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

crypto_cipher_env_t *crypto_new_cipher_env(int type)
{
  crypto_cipher_env_t *env;
  int iv_len, key_len;

  env = (crypto_cipher_env_t *)tor_malloc(sizeof(crypto_cipher_env_t));

  env->type = type;
  env->key = NULL;
  env->iv = NULL;
  env->aux = NULL;

  iv_len = crypto_cipher_iv_length(type);
  key_len = crypto_cipher_key_length(type);

  if (type == CRYPTO_CIPHER_AES_CTR) {
    env->aux = (unsigned char *)aes_new_cipher();
  } else if (! crypto_cipher_evp_cipher(type,0))
    /* This is not an openssl cipher */
    goto err;
  else {
    env->aux = (unsigned char *)tor_malloc(sizeof(EVP_CIPHER_CTX));
    EVP_CIPHER_CTX_init((EVP_CIPHER_CTX *)env->aux);
  }

  if(iv_len)
    env->iv = (unsigned char *)tor_malloc(iv_len);

  if(key_len)
    env->key = (unsigned char *)tor_malloc(key_len);

  return env;
err:
  if (env->key)
    free(env->key);
  if (env->iv)
    free(env->iv);
  if (env->aux)
    free(env->aux);
  if (env)
    free(env);
  return NULL;
}

void crypto_free_cipher_env(crypto_cipher_env_t *env)
{
  assert(env);

  if (env->type == CRYPTO_CIPHER_AES_CTR) {
    assert(env->aux);
    aes_free_cipher((aes_cnt_cipher_t*)env->aux);
    env->aux = NULL;
  } else if (crypto_cipher_evp_cipher(env->type,0)) {
    /* This is an openssl cipher */
    assert(env->aux);
    EVP_CIPHER_CTX_cleanup((EVP_CIPHER_CTX *)env->aux);
  }

  if (env->aux)
    free((void *)env->aux);
  if (env->iv)
    free((void *)env->iv);
  if (env->key)
    free((void *)env->key);

  free((void *)env);
}

/* public key crypto */
int crypto_pk_generate_key(crypto_pk_env_t *env)
{
  assert(env);

  switch(env->type) {
    case CRYPTO_PK_RSA:
    if (env->key)
      RSA_free((RSA *)env->key);
    env->key = (unsigned char *)RSA_generate_key(1024,65537, NULL, NULL);
    if (!env->key)
      return -1;
    break;
    default:
    return -1;
  }

  return 0;
}

int crypto_pk_read_private_key_from_file(crypto_pk_env_t *env, FILE *src)
{
  assert(env && src);

  switch(env->type) {
    case CRYPTO_PK_RSA:
    if (env->key)
      RSA_free((RSA *)env->key);
    env->key = (unsigned char *)PEM_read_RSAPrivateKey(src, NULL, NULL, NULL);
    if (!env->key)
      return -1;
    break;
    default :
    return -1;
  }

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

  switch(env->type) {
    case CRYPTO_PK_RSA:
    if(env->key)
      RSA_free((RSA *)env->key);
    env->key = (unsigned char *)PEM_read_RSAPublicKey(src, NULL, NULL, NULL);
    if (!env->key)
      return -1;
    break;
    default :
    return -1;
  }

  return 0;
}

int crypto_pk_write_public_key_to_string(crypto_pk_env_t *env, char **dest, int *len) {
  BUF_MEM *buf;
  BIO *b;

  assert(env && env->key && dest);

  switch(env->type) {
    case CRYPTO_PK_RSA:

        b = BIO_new(BIO_s_mem()); /* Create a memory BIO */

        /* Now you can treat b as if it were a file.  Just use the
         * PEM_*_bio_* functions instead of the non-bio variants.
         */
        if(!PEM_write_bio_RSAPublicKey(b, (RSA *)env->key))
          return -1;

        BIO_get_mem_ptr(b, &buf);
        BIO_set_close(b, BIO_NOCLOSE); /* so BIO_free doesn't free buf */
        BIO_free(b);

        *dest = tor_malloc(buf->length+1);
        memcpy(*dest, buf->data, buf->length);
        (*dest)[buf->length] = 0; /* null terminate it */
        *len = buf->length;
        BUF_MEM_free(buf);

      break;
    default:
      return -1;
  }

  return 0;
}

int crypto_pk_read_public_key_from_string(crypto_pk_env_t *env, const char *src, int len) {
  BIO *b;

  assert(env && src);

  switch(env->type) {
    case CRYPTO_PK_RSA:
      b = BIO_new(BIO_s_mem()); /* Create a memory BIO */

      BIO_write(b, src, len);

      RSA_free((RSA *)env->key);
      env->key = (unsigned char *)PEM_read_bio_RSAPublicKey(b, NULL, NULL, NULL);
      if(!env->key)
        return -1;

      BIO_free(b);
      break;
    default:
      return -1;
  }

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
  assert(env->type == CRYPTO_PK_RSA);
  if (!(bio = BIO_new(BIO_s_mem())))
    return -1;
  if (PEM_write_bio_RSAPrivateKey(bio, (RSA*)env->key, NULL,NULL,0,NULL,NULL)
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

  switch(env->type) {
    case CRYPTO_PK_RSA:
      if (!env->key)
        return -1;
      if (PEM_write_RSAPrivateKey(dest, (RSA *)env->key, NULL, NULL, 0,0, NULL) == 0)
        return -1;
      break;
    default :
      return -1;
  }

  return 0;
}
int crypto_pk_write_public_key_to_file(crypto_pk_env_t *env, FILE *dest)
{
  assert(env && dest);

  switch(env->type) {
    case CRYPTO_PK_RSA:
      if (!env->key)
        return -1;
      if (PEM_write_RSAPublicKey(dest, (RSA *)env->key) == 0)
        return -1;
      break;
    default :
      return -1;
  }

  return 0;
}

int crypto_pk_check_key(crypto_pk_env_t *env)
{
  assert(env);

  switch(env->type) {
    case CRYPTO_PK_RSA:
      return RSA_check_key((RSA *)env->key);
    default:
      return -1;
  }
}

int crypto_pk_cmp_keys(crypto_pk_env_t *a, crypto_pk_env_t *b) {
  int result;

  if (!a || !b)
    return -1;

  if (!a->key || !b->key)
    return -1;

  if (a->type != b->type)
    return -1;

  switch(a->type) {
    case CRYPTO_PK_RSA:
      assert(((RSA *)a->key)->n && ((RSA *)a->key)->e && ((RSA *)b->key)->n && ((RSA *)b->key)->e);
      result = BN_cmp(((RSA *)a->key)->n, ((RSA *)b->key)->n);
      if (result)
        return result;
      return BN_cmp(((RSA *)a->key)->e, ((RSA *)b->key)->e);
    default:
      return -1;
  }
}

int crypto_pk_keysize(crypto_pk_env_t *env)
{
  assert(env && env->key);

  return RSA_size((RSA *)env->key);
}

crypto_pk_env_t *crypto_pk_dup_key(crypto_pk_env_t *env) {
  assert(env && env->key);

  switch(env->type) {
    case CRYPTO_PK_RSA:
      env->refs++;
      break;
    default:
      return NULL;
  }

  return env;
}

int crypto_pk_public_encrypt(crypto_pk_env_t *env, unsigned char *from, int fromlen, unsigned char *to, int padding)
{
  assert(env && from && to);

  switch(env->type) {
    case CRYPTO_PK_RSA:
      return RSA_public_encrypt(fromlen, from, to, (RSA *)env->key, padding);
    default:
      return -1;
  }
}

int crypto_pk_private_decrypt(crypto_pk_env_t *env, unsigned char *from, int fromlen, unsigned char *to, int padding)
{
  assert(env && from && to);

  switch(env->type) {
    case CRYPTO_PK_RSA:
      if (!(((RSA*)env->key)->p))
        return -1;
      return RSA_private_decrypt(fromlen, from, to, (RSA *)env->key, padding);
    default:
      return -1;
  }
}

int crypto_pk_public_checksig(crypto_pk_env_t *env, unsigned char *from, int fromlen, unsigned char *to)
{
  assert(env && from && to);

  switch(env->type) {
    case CRYPTO_PK_RSA:
      return RSA_public_decrypt(fromlen, from, to, (RSA *)env->key,
                                RSA_PKCS1_PADDING);
    default:
      return -1;
  }
}

int crypto_pk_private_sign(crypto_pk_env_t *env, unsigned char *from, int fromlen, unsigned char *to)
{
  assert(env && from && to);

  switch(env->type) {
    case CRYPTO_PK_RSA:
      if (!(((RSA*)env->key)->p))
        return -1;
      return RSA_private_encrypt(fromlen, from, to, (RSA *)env->key,
                                 RSA_PKCS1_PADDING);
    default:
      return -1;
  }
}

/* Encode the public portion of 'pk' into 'dest'.  Return -1 on error,
 * or the number of characters used on success.
 */
int crypto_pk_asn1_encode(crypto_pk_env_t *pk, char *dest, int dest_len)
{
  int len;
  unsigned char *buf, *bufp;
  len = i2d_RSAPublicKey((RSA*)pk->key, NULL);
  if (len < 0 || len > dest_len)
    return -1;
  bufp = buf = (unsigned char *)tor_malloc(len+1);
  len = i2d_RSAPublicKey((RSA*)pk->key, &bufp);
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
  unsigned char *buf, *bufp;
  bufp = buf = (unsigned char *)tor_malloc(len);
  memcpy(buf,str,len);
  /* This ifdef suppresses a type warning.  Take out the first case once
   * everybody is using openssl 0.9.7 or later.
   */
#if OPENSSL_VERSION_NUMBER < 0x00907000l
  rsa = d2i_RSAPublicKey(NULL, &bufp, len);
#else
  rsa = d2i_RSAPublicKey(NULL, (const unsigned char **)&bufp, len);
#endif
  tor_free(buf);
  if (!rsa)
    return NULL; /* XXXX log openssl error */
  return _crypto_new_pk_env_rsa(rsa);
}

/* Given a private or public key pk, put a SHA1 hash of the public key into
 * digest_out (must have 20 bytes of space).
 */
int crypto_pk_get_digest(crypto_pk_env_t *pk, char *digest_out)
{
  unsigned char *buf, *bufp;
  int len;
  assert(pk->type == CRYPTO_PK_RSA);
  len = i2d_RSAPublicKey((RSA*)pk->key, NULL);
  if (len < 0)
    return -1;
  buf = bufp = tor_malloc(len+1);
  len = i2d_RSAPublicKey((RSA*)pk->key, &bufp);
  if (len < 0) {
    free(buf);
    return -1;
  }
  if (crypto_SHA_digest(buf, len, digest_out) < 0) {
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
  unsigned char digest[20];
  unsigned char buf[FINGERPRINT_LEN+1];
  int i;
  if (crypto_pk_get_digest(pk, digest)) {
    return -1;
  }
  bufp = buf;
  for (i = 0; i < 20; ++i) {
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
  int key_len;
  assert(env);

  key_len = crypto_cipher_key_length(env->type);

  if (key_len > 0)
    return crypto_rand(key_len, env->key);
  else if (key_len == 0)
    return 0;
  else
    return -1;
}

int crypto_cipher_set_iv(crypto_cipher_env_t *env, unsigned char *iv)
{
  int iv_len;
  assert(env && iv);

  iv_len = crypto_cipher_iv_length(env->type);
  if (!iv_len)
    return 0;

  if (!env->iv)
    return -1;

  memcpy((void*)env->iv, (void*)iv, iv_len);

  return 0;
}

int crypto_cipher_set_key(crypto_cipher_env_t *env, unsigned char *key)
{
  int key_len;
  assert(env && key);

  key_len = crypto_cipher_key_length(env->type);
  if (!key_len)
    return 0;

  if (!env->key)
    return -1;

  memcpy((void*)env->key, (void*)key, key_len);

  return 0;
}

unsigned char *crypto_cipher_get_key(crypto_cipher_env_t *env)
{
  return env->key;
}

int crypto_cipher_encrypt_init_cipher(crypto_cipher_env_t *env)
{
  assert(env);

  if (crypto_cipher_evp_cipher(env->type, 1)) {
    RETURN_SSL_OUTCOME(EVP_EncryptInit((EVP_CIPHER_CTX *)env->aux,
                                       crypto_cipher_evp_cipher(env->type, 1),
                                       env->key, env->iv));
  } else if (env->type == CRYPTO_CIPHER_AES_CTR) {
    aes_set_key((aes_cnt_cipher_t*)env->aux, env->key, 128);
    return 0;
  } else {
    return -1;
  }
}

int crypto_cipher_decrypt_init_cipher(crypto_cipher_env_t *env)
{
  assert(env);

  if (crypto_cipher_evp_cipher(env->type, 0)) {
    RETURN_SSL_OUTCOME(EVP_EncryptInit((EVP_CIPHER_CTX *)env->aux,
                                       crypto_cipher_evp_cipher(env->type, 0),
                                       env->key, env->iv));
  } else if (env->type == CRYPTO_CIPHER_AES_CTR) {
    aes_set_key((aes_cnt_cipher_t*)env->aux, env->key, 128);
    return 0;
  } else {
    return -1;
  }
}

int crypto_cipher_encrypt(crypto_cipher_env_t *env, unsigned char *from, unsigned int fromlen, unsigned char *to)
{
  int tolen;

  assert(env && from && to);

  if (env->type == CRYPTO_CIPHER_AES_CTR) {
    aes_crypt((aes_cnt_cipher_t*)env->aux, from, fromlen, to);
    return 0;
  } else {
    RETURN_SSL_OUTCOME(EVP_EncryptUpdate((EVP_CIPHER_CTX *)env->aux, to, &tolen, from, fromlen));
  }
}

int crypto_cipher_decrypt(crypto_cipher_env_t *env, unsigned char *from, unsigned int fromlen, unsigned char *to)
{
  int tolen;

  assert(env && from && to);

  if (env->type == CRYPTO_CIPHER_AES_CTR) {
    aes_crypt((aes_cnt_cipher_t*)env->aux, from, fromlen, to);
    return 0;
  } else {
    RETURN_SSL_OUTCOME(EVP_DecryptUpdate((EVP_CIPHER_CTX *)env->aux, to, &tolen, from, fromlen));
  }
}

int
crypto_cipher_rewind(crypto_cipher_env_t *env, long delta)
{
  return crypto_cipher_advance(env, -delta);
}

int
crypto_cipher_advance(crypto_cipher_env_t *env, long delta)
{
  if (env->type == CRYPTO_CIPHER_AES_CTR) {
    aes_adjust_counter((aes_cnt_cipher_t*)env->aux, delta);
    return 0;
  } else {
    return -1;
  }
}

/* SHA-1 */
int crypto_SHA_digest(const unsigned char *m, int len, unsigned char *digest)
{
  assert(m && digest);
  return (SHA1(m,len,digest) == NULL);
}

struct crypto_digest_env_t {
  SHA_CTX d;
};

crypto_digest_env_t *
crypto_new_digest_env(int type)
{
  crypto_digest_env_t *r;
  assert(type == CRYPTO_SHA1_DIGEST);
  r = tor_malloc(sizeof(crypto_digest_env_t));
  SHA1_Init(&r->d);
  return r;
}

void
crypto_free_digest_env(crypto_digest_env_t *digest) {
  if(digest)
    free(digest);
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
  static char r[SHA_DIGEST_LENGTH];
  assert(digest && out);
  assert(out_len <= SHA_DIGEST_LENGTH);
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
int crypto_dh_get_public(crypto_dh_env_t *dh, char *pubkey, int pubkey_len)
{
  int bytes;
  assert(dh);
  if (!DH_generate_key(dh->dh))
    return -1;

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
                             char *pubkey, int pubkey_len,
                             char *secret_out, int secret_bytes_out)
{
  unsigned char hash[20];
  unsigned char *secret_tmp = NULL;
  BIGNUM *pubkey_bn = NULL;
  int secret_len;
  int i;
  assert(dh);
  assert(secret_bytes_out/20 <= 255);

  if (!(pubkey_bn = BN_bin2bn(pubkey, pubkey_len, NULL)))
    goto error;
  secret_tmp = tor_malloc(crypto_dh_get_bytes(dh)+1);
  secret_len = DH_compute_key(secret_tmp, pubkey_bn, dh->dh);
  /* sometimes secret_len might be less than 128, e.g., 127. that's ok. */
  for (i = 0; i < secret_bytes_out; i += 20) {
    secret_tmp[secret_len] = (unsigned char) i/20;
    if (crypto_SHA_digest(secret_tmp, secret_len+1, hash))
      goto error;
    memcpy(secret_out+i, hash, MIN(20, secret_bytes_out-i));
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
  char buf[21];

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
  if (!CryptGenRandom(provider, 20, buf)) {
    log_fn(LOG_ERR,"Can't get entropy from CryptoAPI.");
    return -1;
  }
  RAND_seed(buf, 20);
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
  char buf[21];
  FILE *f;

  for (i = 0; filenames[i]; ++i) {
    f = fopen(filenames[i], "rb");
    if (!f) continue;
    log_fn(LOG_INFO, "Seeding RNG from %s", filenames[i]);
    n = fread(buf, 1, 20, f);
    fclose(f);
    if (n != 20) {
      log_fn(LOG_WARN, "Error reading from entropy source");
      return -1;
    }
    RAND_seed(buf, 20);
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
char *crypto_perror()
{
  return (char *)ERR_reason_error_string(ERR_get_error());
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

static const char BASE32_CHARS[] = "abcdefghijklmnopqrstuvwxyz012345";

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
