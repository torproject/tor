/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef __CRYPTO_H
#define __CRYPTO_H

#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>

/* available encryption primitives */
#define CRYPTO_CIPHER_IDENTITY 0
#define CRYPTO_CIPHER_DES 1
#define CRYPTO_CIPHER_RC4 2
#define CRYPTO_CIPHER_3DES 3
#define CRYPTO_CIPHER_AES_CTR 4

#define CRYPTO_PK_RSA 0

typedef struct crypto_pk_env_t crypto_pk_env_t;
typedef struct crypto_cipher_env_t crypto_cipher_env_t;

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

int crypto_pk_read_private_key_from_file(crypto_pk_env_t *env, FILE *src);
int crypto_pk_read_public_key_from_file(crypto_pk_env_t *env, FILE *src);
int crypto_pk_write_public_key_to_string(crypto_pk_env_t *env, char **dest, int *len);
int crypto_pk_read_public_key_from_string(crypto_pk_env_t *env, char *src, int len);
int crypto_pk_write_private_key_to_file(crypto_pk_env_t *env, FILE *dest);
int crypto_pk_write_private_key_to_filename(crypto_pk_env_t *env, const char *fname);
int crypto_pk_write_public_key_to_file(crypto_pk_env_t *env, FILE *dest);
int crypto_pk_check_key(crypto_pk_env_t *env);
int crypto_pk_read_private_key_from_filename(crypto_pk_env_t *env, const char *keyfile);

int crypto_pk_set_key(crypto_pk_env_t *env, unsigned char *key);
int crypto_pk_cmp_keys(crypto_pk_env_t *a, crypto_pk_env_t *b);
crypto_pk_env_t *crypto_pk_dup_key(crypto_pk_env_t *orig);
int crypto_pk_keysize(crypto_pk_env_t *env);

int crypto_pk_public_encrypt(crypto_pk_env_t *env, unsigned char *from, int fromlen, unsigned char *to, int padding);
int crypto_pk_private_decrypt(crypto_pk_env_t *env, unsigned char *from, int fromlen, unsigned char *to, int padding);
int crypto_pk_private_sign(crypto_pk_env_t *env, unsigned char *from, int fromlen, unsigned char *to);
int crypto_pk_public_checksig(crypto_pk_env_t *env, unsigned char *from, int fromlen, unsigned char *to);
#define FINGERPRINT_LEN 49
int crypto_pk_get_fingerprint(crypto_pk_env_t *pk, char *fp_out);
int crypto_pk_check_fingerprint_syntax(const char *s);

int base64_encode(char *dest, int destlen, char *src, int srclen);
int base64_decode(char *dest, int destlen, char *src, int srclen);

/* Key negotiation */
typedef struct crypto_dh_env_st {
  DH *dh;
} crypto_dh_env_t;

/* #define CRYPTO_DH_SIZE (1536 / 8) */
#define CRYPTO_DH_SIZE (1024 / 8)
crypto_dh_env_t *crypto_dh_new();
int crypto_dh_get_bytes(crypto_dh_env_t *dh);
int crypto_dh_get_public(crypto_dh_env_t *dh, char *pubkey_out, 
			 int pubkey_out_len);
int crypto_dh_compute_secret(crypto_dh_env_t *dh, 
			     char *pubkey, int pubkey_len,
			     char *secret_out, int secret_out_len);
void crypto_dh_free(crypto_dh_env_t *dh);

/* symmetric crypto */
int crypto_cipher_generate_key(crypto_cipher_env_t *env);
int crypto_cipher_set_iv(crypto_cipher_env_t *env, unsigned char *iv);
int crypto_cipher_set_key(crypto_cipher_env_t *env, unsigned char *key);
int crypto_cipher_encrypt_init_cipher(crypto_cipher_env_t *env);
int crypto_cipher_decrypt_init_cipher(crypto_cipher_env_t *env);
unsigned char *crypto_cipher_get_key(crypto_cipher_env_t *env);

int crypto_cipher_encrypt(crypto_cipher_env_t *env, unsigned char *from, unsigned int fromlen, unsigned char *to);
int crypto_cipher_decrypt(crypto_cipher_env_t *env, unsigned char *from, unsigned int fromlen, unsigned char *to);

/* only implemented for CRYPTO_CIPHER_AES_CTR */
int crypto_cipher_advance(crypto_cipher_env_t *env, long delta);

/* convenience function: wraps crypto_create_crypto_env, set_key, set_iv, and init. */
crypto_cipher_env_t *crypto_create_init_cipher(int cipher_type, char *key, char *iv, int encrypt_mode);

/* SHA-1 */
int crypto_SHA_digest(unsigned char *m, int len, unsigned char *digest);

/* random numbers */
int crypto_seed_rng();
int crypto_rand(unsigned int n, unsigned char *to);
int crypto_pseudo_rand(unsigned int n, unsigned char *to);

#define CRYPTO_PSEUDO_RAND_INT(v) crypto_pseudo_rand(sizeof(v),(char*)&(v))

/* errors */
char *crypto_perror();
#endif
