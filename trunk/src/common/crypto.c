/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "crypto.h"

#include <stdlib.h>

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
  if (!env)
    return;
  
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
  if (!env)
    return;
  
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
  return 0;
}

int crypto_pk_read_private_key(crypto_pk_env_t *env, FILE *src)
{
  return 0;
}
int crypto_pk_read_public_key(crypto_pk_env_t *env, FILE *src)
{
  return 0;
}
int crypto_pk_write_private_key(crypto_pk_env_t *env, FILE *dest)
{
  return 0;
}
int crypto_pk_write_public_key(crypto_pk_env_t *env, FILE *dest)
{
  return 0;
}

int crypto_pk_set_key(crypto_pk_env_t *env, unsigned char *key)
{
  return 0;
}

/* symmetric crypto */
int crypto_cipher_set_iv(crypto_cipher_env_t *env, unsigned char *iv)
{
  return 0;
}
int crypto_cipher_set_key(crypto_cipher_env_t *env, unsigned char *key)
{
  return 0;
}
int crypto_cipher_init_cipher()
{
  return 0;
}

int crypto_cipher_encrypt(crypto_cipher_env_t *env, unsigned char *from, unsigned int fromlen, unsigned char *to)
{
  return 0;
}

int crypto_cipher_decrypt(crypto_cipher_env_t *env, unsigned char *from, unsigned int fromlen, unsigned char *to)
{
  return 0;
}

/* SHA-1 */
int crypto_SHA_digest(unsigned char *m, unsigned char *digest)
{
  return 0;
}

/* random numbers */
int crypto_rand(unsigned int n, unsigned char *to)
{
  return 0;
}
int crypto_pseudo_rand(unsigned int n, unsigned char *to)
{
  return 0;
}
