/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include <string.h>

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

#include <stdlib.h>
#include <assert.h>

#include "crypto.h"
#include "config.h"
#include "log.h"

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

int crypto_global_init() 
{
  ERR_load_crypto_strings();
  return 0;
}

int crypto_global_cleanup()
{
  ERR_free_strings();
  return 0;
}

crypto_pk_env_t *crypto_new_pk_env(int type)
{
  crypto_pk_env_t *env;
  
  env = (crypto_pk_env_t *)malloc(sizeof(crypto_pk_env_t));
  if (!env)
    return 0;
  
  env->type = type;
  env->key = NULL;
  env->aux = NULL;
  
  switch(type) {
    case CRYPTO_PK_RSA:
    env->key = (unsigned char *)RSA_new();
    if (!env->key) {
      free((void *)env);
      return NULL;
    }
    break;
    default:
    free((void *)env);
    return NULL;
    break;
  }

  return env;
}

void crypto_free_pk_env(crypto_pk_env_t *env)
{
  assert(env);
  
  switch(env->type) {
    case CRYPTO_PK_RSA:
    if (env->key)
      RSA_free((RSA *)env->key);
    break;
    default:
    break;
  }
  
  free((void *)env);
  return;
}

crypto_cipher_env_t *crypto_new_cipher_env(int type)
{
  crypto_cipher_env_t *env;
  
  env = (crypto_cipher_env_t *)malloc(sizeof(crypto_cipher_env_t));
  if (!env)
    return NULL;
  
  env->type = type;
  env->key = NULL;
  env->iv = NULL;
  env->aux = NULL;
  
  switch(type) {
    case CRYPTO_CIPHER_IDENTITY:
    env->aux = (unsigned char *)malloc(sizeof(EVP_CIPHER_CTX));
    if (!env->aux) {
      free((void *)env);
      return NULL;
    }
    EVP_CIPHER_CTX_init((EVP_CIPHER_CTX *)env->aux);
    break;
    case CRYPTO_CIPHER_DES:
    env->aux = (unsigned char *)malloc(sizeof(EVP_CIPHER_CTX));
    if (!env->aux) {
      free((void *)env);
      return NULL;
    }
    env->key = (unsigned char *)malloc(8);
    if (!env->key) {
      free((void *)env->aux);
      free((void *)env);
      return NULL;
    }
    env->iv = (unsigned char *)malloc(8);
    if (!env->iv) {
      free((void *)env->key);
      free((void *)env->aux);
      return NULL;
    }
    EVP_CIPHER_CTX_init((EVP_CIPHER_CTX *)env->aux);
    break;
    case CRYPTO_CIPHER_RC4:
    env->aux = (unsigned char *)malloc(sizeof(EVP_CIPHER_CTX));
    if (!env->aux) {
      free((void *)env);
      return NULL;
    }
    env->key = (unsigned char *)malloc(16);
    if (!env->key) {
      free((void *)env->aux);
      free((void *)env);
      return NULL;
    }
    env->iv = (unsigned char *)malloc(16);
    if (!env->iv) {
      free((void *)env->key);
      free((void *)env->aux);
      return NULL;
    }
    break;
    EVP_CIPHER_CTX_init((EVP_CIPHER_CTX *)env->aux);
    default:
    free((void *)env);
    return NULL;
    break;
  }
  
  return env;
}

void crypto_free_cipher_env(crypto_cipher_env_t *env)
{
  assert(env);
  
  switch(env->type) {
    case CRYPTO_CIPHER_IDENTITY:
    if (env->aux) {
      EVP_CIPHER_CTX_cleanup((EVP_CIPHER_CTX *)env->aux);
      free((void *)env->aux);
    }
    break;
    case CRYPTO_CIPHER_DES:
    if (env->aux) {
      EVP_CIPHER_CTX_cleanup((EVP_CIPHER_CTX *)env->aux);
      free((void *)env->aux);
    }
    if (env->key)
      free((void *)env->key);
    if (env->iv)
      free((void *)env->iv);
    break;
    case CRYPTO_CIPHER_RC4:
    if (env->aux) {
      EVP_CIPHER_CTX_cleanup((EVP_CIPHER_CTX *)env->aux);
      free((void *)env->aux);
    }
    if (env->key)
      free((void *)env->key);
    if (env->iv)
      free((void *)env->iv);
    break;
    default:
    break;
  }
  
  free((void *)env);
  return;
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

int crypto_pk_read_private_key(crypto_pk_env_t *env, FILE *src)
{
  assert(env && src);
  
  switch(env->type) {
    case CRYPTO_PK_RSA:
/*
    if (env->key)
      RSA_free((RSA *)env->key);*/
    env->key = (unsigned char *)PEM_read_RSAPrivateKey(src, (RSA **)&env->key, NULL, NULL);
    if (!env->key)
      return -1;
    break;
    default :
    return -1;
  }
  
  return 0;
}

int crypto_pk_read_private_key_filename(crypto_pk_env_t *env, unsigned char *keyfile)
{
  FILE *f_pr;
  int retval = 0;
 
  assert(env && keyfile);
  
  if (strspn(keyfile,CONFIG_LEGAL_FILENAME_CHARACTERS) == strlen(keyfile)) /* filename contains legal characters only */
  {
    /* open the keyfile */
    f_pr=fopen(keyfile,"r");
    if (!f_pr)
      return -1;
      
    /* read the private key */
    retval = crypto_pk_read_private_key(env, f_pr);
    fclose(f_pr);
    if (retval == -1)
    {
      log(LOG_ERR,"Error reading private key : %s",crypto_perror());
      return -1;
    }
      
    /* check the private key */
    retval = crypto_pk_check_key(env);
    if (retval == 0)
    {
      log(LOG_ERR,"Private key read but is invalid : %s.", crypto_perror());
      return -1;
    }
    else if (retval == -1)
    {
      log(LOG_ERR,"Private key read but validity checking failed : %s",crypto_perror());
      return -1;
    }
    else if (retval == 1)
    {
      return 0;
    }
  } /* filename contains legal characters only */
  
  return -1; /* report error */
}

int crypto_pk_read_public_key(crypto_pk_env_t *env, FILE *src)
{
  assert(env && src);
  
  switch(env->type) {
    case CRYPTO_PK_RSA:
    /*
    if (env->key)
      RSA_free((RSA *)env->key);*/
    env->key = (unsigned char *)PEM_read_RSAPublicKey(src, (RSA **)&env->key, NULL, NULL);
    if (!env->key)
      return -1;
    break;
    default :
    return -1;
  }
  
  return 0;
}

int crypto_pk_write_private_key(crypto_pk_env_t *env, FILE *dest)
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
int crypto_pk_write_public_key(crypto_pk_env_t *env, FILE *dest)
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

int crypto_pk_set_key(crypto_pk_env_t *env, unsigned char *key)
{
  assert(env && key);
  
  switch(env->type) {
    case CRYPTO_PK_RSA:
    if (!env->key)
      return -1;
    memcpy((void *)env->key, (void *)key, sizeof(RSA));
    break;
    default :
    return -1;
  }
  
  return 0;
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
    return RSA_private_decrypt(fromlen, from, to, (RSA *)env->key, padding);
    default:
    return -1;
  }
}

/* symmetric crypto */
int crypto_cipher_generate_key(crypto_cipher_env_t *env)
{
  assert(env);
  
  switch(env->type) {
    case CRYPTO_CIPHER_IDENTITY:
    return 0;
    case CRYPTO_CIPHER_DES:
    return crypto_rand(8, env->key);
    case CRYPTO_CIPHER_RC4:
    return crypto_rand(16, env->key);
    default:
    return -1;
  }

}

int crypto_cipher_set_iv(crypto_cipher_env_t *env, unsigned char *iv)
{
  assert(env && iv);
  
  switch(env->type) {
    case CRYPTO_CIPHER_IDENTITY:
     break;
    case CRYPTO_CIPHER_DES:
    if (!env->iv)
      return -1;
    memcpy((void *)env->iv, (void *)iv, 8);
    break;
    case CRYPTO_CIPHER_RC4:
    if (!env->iv)
      return -1;
    memcpy((void *)env->iv, (void *)iv, 16);
    break;
    default:
    return -1;
  }
  
  return 0;
}
int crypto_cipher_set_key(crypto_cipher_env_t *env, unsigned char *key)
{
  assert(env && key);
  
  switch(env->type) {
    case CRYPTO_CIPHER_IDENTITY:
    break;
    case CRYPTO_CIPHER_DES:
    if (!env->key)
      return -1;
    memcpy((void *)env->key, (void *)key, 8);
    break;
    case CRYPTO_CIPHER_RC4:
    if (!env->key)
      return -1;
    memcpy((void *)env->key, (void *)key, 16);
    break;
    default:
    return -1;
  }
  
  return 0;
}

int crypto_cipher_encrypt_init_cipher(crypto_cipher_env_t *env)
{
  assert(env);

  switch(env->type) {
    case CRYPTO_CIPHER_IDENTITY:
      RETURN_SSL_OUTCOME(EVP_EncryptInit((EVP_CIPHER_CTX *)env->aux, EVP_enc_null(), env->key, env->iv));
    case CRYPTO_CIPHER_DES:
      RETURN_SSL_OUTCOME(EVP_EncryptInit((EVP_CIPHER_CTX *)env->aux, EVP_des_ofb(), env->key, env->iv));
    case CRYPTO_CIPHER_RC4:
      RETURN_SSL_OUTCOME(EVP_EncryptInit((EVP_CIPHER_CTX *)env->aux, EVP_rc4(), env->key, env->iv));
    default:
      return -1;
  }
  
  return 0;
}

int crypto_cipher_decrypt_init_cipher(crypto_cipher_env_t *env)
{
  assert(env);
  
  switch(env->type) {
    case CRYPTO_CIPHER_IDENTITY:
      RETURN_SSL_OUTCOME(EVP_DecryptInit((EVP_CIPHER_CTX *)env->aux, EVP_enc_null(), env->key, env->iv));
    case CRYPTO_CIPHER_DES:
      RETURN_SSL_OUTCOME(EVP_DecryptInit((EVP_CIPHER_CTX *)env->aux, EVP_des_ofb(), env->key, env->iv));
    case CRYPTO_CIPHER_RC4:
      RETURN_SSL_OUTCOME(EVP_DecryptInit((EVP_CIPHER_CTX *)env->aux, EVP_rc4(), env->key, env->iv));
    default:
    return -1;
  }
  
    return 0;
}

int crypto_cipher_encrypt(crypto_cipher_env_t *env, unsigned char *from, unsigned int fromlen, unsigned char *to)
{
  int tolen;
  
  assert(env && from && to);
  
  RETURN_SSL_OUTCOME(EVP_EncryptUpdate((EVP_CIPHER_CTX *)env->aux, to, &tolen, from, fromlen));
}

int crypto_cipher_decrypt(crypto_cipher_env_t *env, unsigned char *from, unsigned int fromlen, unsigned char *to)
{
  int tolen;
  
  assert(env && from && to);
  
  RETURN_SSL_OUTCOME(EVP_DecryptUpdate((EVP_CIPHER_CTX *)env->aux, to, &tolen, from, fromlen));
}

/* SHA-1 */
int crypto_SHA_digest(unsigned char *m, int len, unsigned char *digest)
{
  assert(m && digest);
  return (SHA1(m,len,digest) == NULL);
}

/* random numbers */
int crypto_rand(unsigned int n, unsigned char *to)
{
  assert(to);
  return (RAND_bytes(to, n) != 1);
}

int crypto_pseudo_rand(unsigned int n, unsigned char *to)
{
  assert(to);
  return (RAND_pseudo_bytes(to, n) == -1);
}

/* errors */
char *crypto_perror()
{
  return (char *)ERR_reason_error_string(ERR_get_error());
}
