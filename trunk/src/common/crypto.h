/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef __CRYPTO_H
#define __CRYPTO_H

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/* available encryption primitives */
#define CRYPTO_CIPHER_IDENTITY 0
#define CRYPTO_CIPHER_DES 1
#define CRYPTO_CIPHER_RC4 2

#define CRYPTO_PK_RSA 0

typedef struct 
{
  int type;
  unsigned char *key;
  /* auxiliary data structure(s) used by the underlying crypto library */
  unsigned char *aux;
} crypto_pk_env_t;

typedef struct
{
  int type;
  unsigned char *key;
  unsigned char *iv;
  /* auxiliary data structure(s) used by the underlying crypto library */
  unsigned char *aux;
} crypto_cipher_env_t;

/* global state */
int crypto_global_init();
int crypto_global_cleanup();

/* environment setup */
crypto_pk_env_t *crypto_new_pk_env(int type);
void crypto_free_pk_env(crypto_pk_env_t *env);

crypto_cipher_env_t *crypto_new_cipher_env(int type);
void crypto_free_cipher_env(crypto_cipher_env_t *env);

/* public key crypto */
int crypto_pk_generate_key(crypto_pk_env_t *env);

int crypto_pk_read_private_key(crypto_pk_env_t *env, FILE *src);
int crypto_pk_read_public_key(crypto_pk_env_t *env, FILE *src);
int crypto_pk_write_private_key(crypto_pk_env_t *env, FILE *dest);
int crypto_pk_write_public_key(crypto_pk_env_t *env, FILE *dest);

int crypto_pk_set_key(crypto_pk_env_t *env, unsigned char *key);

/* symmetric crypto */
int crypto_cipher_set_iv(crypto_cipher_env_t *env, unsigned char *iv);
int crypto_cipher_set_key(crypto_cipher_env_t *env, unsigned char *key);
int crypto_cipher_init_cipher();

int crypto_cipher_encrypt(crypto_cipher_env_t *env, unsigned char *from, unsigned int fromlen, unsigned char *to);
int crypto_cipher_decrypt(crypto_cipher_env_t *env, unsigned char *from, unsigned int fromlen, unsigned char *to);

/* SHA-1 */
int crypto_SHA_digest(unsigned char *m, unsigned char *digest);

/* random numbers */
int crypto_rand(unsigned int n, unsigned char *to);
int crypto_pseudo_rand(unsigned int n, unsigned char *to);

#endif
