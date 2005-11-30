/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar.
 * Copyright 2004-2005 Roger Dingledine, Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file crypto.h
 *
 * \brief Headers for crypto.c
 **/

#ifndef __CRYPTO_H
#define __CRYPTO_H
#define CRYPTO_H_ID "$Id$"

#include <stdio.h>

/** Length of the output of our message digest. */
#define DIGEST_LEN 20
/** Length of our symmetric cipher's keys. */
#define CIPHER_KEY_LEN 16
/** Length of our public keys. */
#define PK_BYTES (1024/8)
/** Length of our DH keys. */
#define DH_BYTES (1024/8)

/** Length of a message digest when encoded in base64 with trailing = signs
 * removed. */
#define BASE64_DIGEST_LEN 27

/** Constants used to indicate no padding for public-key encryption */
#define PK_NO_PADDING         60000
/** Constants used to indicate PKCS1 padding for public-key encryption */
#define PK_PKCS1_PADDING      60001
/** Constants used to indicate OAEP padding for public-key encryption */
#define PK_PKCS1_OAEP_PADDING 60002

/** Number of bytes added for PKCS1 padding. */
#define PKCS1_PADDING_OVERHEAD 11
/** Number of bytes added for PKCS1-OAEP padding. */
#define PKCS1_OAEP_PADDING_OVERHEAD 42

/** Length of encoded public key fingerprints, including space; but not
 * including terminating NUL. */
#define FINGERPRINT_LEN 49
/** Length of hex encoding of SHA1 digest, not including final NUL. */
#define HEX_DIGEST_LEN 40

typedef struct crypto_pk_env_t crypto_pk_env_t;
typedef struct crypto_cipher_env_t crypto_cipher_env_t;
typedef struct crypto_digest_env_t crypto_digest_env_t;
typedef struct crypto_dh_env_t crypto_dh_env_t;

/* global state */
int crypto_global_init(int hardwareAccel);
void crypto_thread_cleanup(void);
int crypto_global_cleanup(void);

/* environment setup */
crypto_pk_env_t *crypto_new_pk_env(void);
void crypto_free_pk_env(crypto_pk_env_t *env);

/* convenience function: wraps crypto_create_crypto_env, set_key, and init. */
crypto_cipher_env_t *crypto_create_init_cipher(const char *key, int encrypt_mode);

crypto_cipher_env_t *crypto_new_cipher_env(void);
void crypto_free_cipher_env(crypto_cipher_env_t *env);

/* public key crypto */
int crypto_pk_generate_key(crypto_pk_env_t *env);

int crypto_pk_read_private_key_from_filename(crypto_pk_env_t *env, const char *keyfile);
int crypto_pk_write_public_key_to_string(crypto_pk_env_t *env, char **dest, size_t *len);
int crypto_pk_read_public_key_from_string(crypto_pk_env_t *env, const char *src, size_t len);
int crypto_pk_write_private_key_to_filename(crypto_pk_env_t *env, const char *fname);
int crypto_pk_DER64_encode_public_key(crypto_pk_env_t *env, char **dest);
crypto_pk_env_t *crypto_pk_DER64_decode_public_key(const char *in);

int crypto_pk_check_key(crypto_pk_env_t *env);
int crypto_pk_cmp_keys(crypto_pk_env_t *a, crypto_pk_env_t *b);
size_t crypto_pk_keysize(crypto_pk_env_t *env);
crypto_pk_env_t *crypto_pk_dup_key(crypto_pk_env_t *orig);

int crypto_pk_public_encrypt(crypto_pk_env_t *env, char *to,
                             const char *from, size_t fromlen, int padding);
int crypto_pk_private_decrypt(crypto_pk_env_t *env, char *to,
                              const char *from, size_t fromlen,
                              int padding, int warnOnFailure);
int crypto_pk_public_checksig(crypto_pk_env_t *env, char *to,
                              const char *from, size_t fromlen);
int crypto_pk_public_checksig_digest(crypto_pk_env_t *env, const char *data,
                                     int datalen, const char *sig, int siglen);
int crypto_pk_private_sign(crypto_pk_env_t *env, char *to,
                           const char *from, size_t fromlen);
int crypto_pk_private_sign_digest(crypto_pk_env_t *env, char *to,
                                  const char *from, size_t fromlen);
int crypto_pk_public_hybrid_encrypt(crypto_pk_env_t *env, char *to,
                                    const char *from, size_t fromlen,
                                    int padding, int force);
int crypto_pk_private_hybrid_decrypt(crypto_pk_env_t *env, char *to,
                                     const char *from, size_t fromlen,
                                     int padding, int warnOnFailure);

int crypto_pk_asn1_encode(crypto_pk_env_t *pk, char *dest, int dest_len);
crypto_pk_env_t *crypto_pk_asn1_decode(const char *str, size_t len);
int crypto_pk_get_digest(crypto_pk_env_t *pk, char *digest_out);
int crypto_pk_get_fingerprint(crypto_pk_env_t *pk, char *fp_out,int add_space);
int crypto_pk_check_fingerprint_syntax(const char *s);

/* symmetric crypto */
int crypto_cipher_generate_key(crypto_cipher_env_t *env);
int crypto_cipher_set_key(crypto_cipher_env_t *env, const char *key);
const char *crypto_cipher_get_key(crypto_cipher_env_t *env);
int crypto_cipher_encrypt_init_cipher(crypto_cipher_env_t *env);
int crypto_cipher_decrypt_init_cipher(crypto_cipher_env_t *env);

int crypto_cipher_encrypt(crypto_cipher_env_t *env, char *to,
                          const char *from, size_t fromlen);
int crypto_cipher_decrypt(crypto_cipher_env_t *env, char *to,
                          const char *from, size_t fromlen);

/* only implemented for CRYPTO_CIPHER_AES_CTR */
int crypto_cipher_advance(crypto_cipher_env_t *env, long delta);

/* SHA-1 */
int crypto_digest(char *digest, const char *m, size_t len);
crypto_digest_env_t *crypto_new_digest_env(void);
void crypto_free_digest_env(crypto_digest_env_t *digest);
void crypto_digest_add_bytes(crypto_digest_env_t *digest, const char *data,
                             size_t len);
void crypto_digest_get_digest(crypto_digest_env_t *digest,
                              char *out, size_t out_len);
crypto_digest_env_t *crypto_digest_dup(const crypto_digest_env_t *digest);
void crypto_digest_assign(crypto_digest_env_t *into,
                          const crypto_digest_env_t *from);

/* Key negotiation */
crypto_dh_env_t *crypto_dh_new(void);
int crypto_dh_get_bytes(crypto_dh_env_t *dh);
int crypto_dh_generate_public(crypto_dh_env_t *dh);
int crypto_dh_get_public(crypto_dh_env_t *dh, char *pubkey_out,
                         size_t pubkey_out_len);
int crypto_dh_compute_secret(crypto_dh_env_t *dh,
                             const char *pubkey, size_t pubkey_len,
                             char *secret_out, size_t secret_out_len);
void crypto_dh_free(crypto_dh_env_t *dh);

/* random numbers */
int crypto_seed_rng(void);
int crypto_rand(char *to, size_t n);
int crypto_rand_int(unsigned int max);

struct smartlist_t;
void *smartlist_choose(const struct smartlist_t *sl);

int base64_encode(char *dest, size_t destlen, const char *src, size_t srclen);
int base64_decode(char *dest, size_t destlen, const char *src, size_t srclen);
#define BASE32_CHARS "abcdefghijklmnopqrstuvwxyz234567"
void base32_encode(char *dest, size_t destlen, const char *src, size_t srclen);

int digest_to_base64(char *d64, const char *digest);
int digest_from_base64(char *digest, const char *d64);

#define S2K_SPECIFIER_LEN 9
void secret_to_key(char *key_out, size_t key_out_len, const char *secret,
                   size_t secret_len, const char *s2k_specifier);

#endif

