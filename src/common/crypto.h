/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef __CRYPTO_H
#define __CRYPTO_H

#include <stdio.h>

#define DIGEST_LEN 20
#define CIPHER_KEY_LEN 16
#define CIPHER_IV_LEN 0
#define PK_BITS 1024
#define PK_BYTES (PK_BITS/8)
#define DH_BITS 1024
#define DH_BYTES (DH_BITS/8)
#define CRYPTO_DH_SIZE DH_BYTES

#define PK_NO_PADDING         60000
#define PK_PKCS1_PADDING      60001
#define PK_PKCS1_OAEP_PADDING 60002

typedef struct crypto_pk_env_t crypto_pk_env_t;
typedef struct crypto_cipher_env_t crypto_cipher_env_t;
typedef struct crypto_digest_env_t crypto_digest_env_t;
typedef struct crypto_dh_env_t crypto_dh_env_t;

/* global state */
int crypto_global_init();
int crypto_global_cleanup();

/* environment setup */
crypto_pk_env_t *crypto_new_pk_env(void);
void crypto_free_pk_env(crypto_pk_env_t *env);

crypto_cipher_env_t *crypto_new_cipher_env(void);
void crypto_free_cipher_env(crypto_cipher_env_t *env);

/* public key crypto */
int crypto_pk_generate_key(crypto_pk_env_t *env);

int crypto_pk_read_private_key_from_file(crypto_pk_env_t *env, FILE *src);
int crypto_pk_read_public_key_from_file(crypto_pk_env_t *env, FILE *src);
int crypto_pk_write_public_key_to_string(crypto_pk_env_t *env, char **dest, int *len);
int crypto_pk_read_public_key_from_string(crypto_pk_env_t *env, const char *src, int len);
int crypto_pk_write_private_key_to_file(crypto_pk_env_t *env, FILE *dest);
int crypto_pk_write_private_key_to_filename(crypto_pk_env_t *env, const char *fname);
int crypto_pk_write_public_key_to_file(crypto_pk_env_t *env, FILE *dest);
int crypto_pk_check_key(crypto_pk_env_t *env);
int crypto_pk_read_private_key_from_filename(crypto_pk_env_t *env, const char *keyfile);

int crypto_pk_cmp_keys(crypto_pk_env_t *a, crypto_pk_env_t *b);
crypto_pk_env_t *crypto_pk_dup_key(crypto_pk_env_t *orig);
int crypto_pk_keysize(crypto_pk_env_t *env);

int crypto_pk_public_encrypt(crypto_pk_env_t *env, const unsigned char *from, int fromlen, unsigned char *to, int padding);
int crypto_pk_private_decrypt(crypto_pk_env_t *env, const unsigned char *from, int fromlen, unsigned char *to, int padding);
int crypto_pk_private_sign(crypto_pk_env_t *env, const unsigned char *from, int fromlen, unsigned char *to);
int crypto_pk_private_sign_digest(crypto_pk_env_t *env, const unsigned char *from, int fromlen, unsigned char *to);
int crypto_pk_public_checksig(crypto_pk_env_t *env, const unsigned char *from, int fromlen, unsigned char *to);
int crypto_pk_public_checksig_digest(crypto_pk_env_t *env, const unsigned char *data, int datalen, const unsigned char *sig, int siglen);
int crypto_pk_public_hybrid_encrypt(crypto_pk_env_t *env,
                                    const unsigned char *from, int fromlen,
                                    unsigned char *to, int padding);
int crypto_pk_private_hybrid_decrypt(crypto_pk_env_t *env,
                                     const unsigned char *from, int fromlen,
                                     unsigned char *to,int padding);

#define FINGERPRINT_LEN 49
int crypto_pk_asn1_encode(crypto_pk_env_t *pk, char *dest, int dest_len);
crypto_pk_env_t *crypto_pk_asn1_decode(const char *str, int len);
int crypto_pk_get_digest(crypto_pk_env_t *pk, char *digest_out);
int crypto_pk_get_fingerprint(crypto_pk_env_t *pk, char *fp_out);
int crypto_pk_check_fingerprint_syntax(const char *s);

int base64_encode(char *dest, int destlen, const char *src, int srclen);
int base64_decode(char *dest, int destlen, const char *src, int srclen);
#define BASE32_CHARS "abcdefghijklmnopqrstuvwxyz012345"
int base32_encode(char *dest, int destlen, const char *src, int srclen);

/* Key negotiation */
crypto_dh_env_t *crypto_dh_new();
int crypto_dh_get_bytes(crypto_dh_env_t *dh);
int crypto_dh_generate_public(crypto_dh_env_t *dh);
int crypto_dh_get_public(crypto_dh_env_t *dh, char *pubkey_out,
                         int pubkey_out_len);
int crypto_dh_compute_secret(crypto_dh_env_t *dh,
                             const char *pubkey, int pubkey_len,
                             char *secret_out, int secret_out_len);
void crypto_dh_free(crypto_dh_env_t *dh);

/* symmetric crypto */
int crypto_cipher_generate_key(crypto_cipher_env_t *env);
int crypto_cipher_set_iv(crypto_cipher_env_t *env, const unsigned char *iv);
int crypto_cipher_set_key(crypto_cipher_env_t *env, const unsigned char *key);
int crypto_cipher_encrypt_init_cipher(crypto_cipher_env_t *env);
int crypto_cipher_decrypt_init_cipher(crypto_cipher_env_t *env);
const unsigned char *crypto_cipher_get_key(crypto_cipher_env_t *env);

int crypto_cipher_encrypt(crypto_cipher_env_t *env, const unsigned char *from, unsigned int fromlen, unsigned char *to);
int crypto_cipher_decrypt(crypto_cipher_env_t *env, const unsigned char *from, unsigned int fromlen, unsigned char *to);

/* only implemented for CRYPTO_CIPHER_AES_CTR */
int crypto_cipher_rewind(crypto_cipher_env_t *env, long delta);
int crypto_cipher_advance(crypto_cipher_env_t *env, long delta);

/* convenience function: wraps crypto_create_crypto_env, set_key, set_iv, and init. */
crypto_cipher_env_t *crypto_create_init_cipher(const char *key, const char *iv, int encrypt_mode);

/* SHA-1 */
int crypto_digest(const unsigned char *m, int len, unsigned char *digest);
crypto_digest_env_t *crypto_new_digest_env();
void crypto_free_digest_env(crypto_digest_env_t *digest);
void crypto_digest_add_bytes(crypto_digest_env_t *digest, const char *data,
                             size_t len);
void crypto_digest_get_digest(crypto_digest_env_t *digest,
                              char *out, size_t out_len);
crypto_digest_env_t *crypto_digest_dup(const crypto_digest_env_t *digest);
void crypto_digest_assign(crypto_digest_env_t *into,
                          const crypto_digest_env_t *from);

/* random numbers */
int crypto_seed_rng();
int crypto_rand(unsigned int n, unsigned char *to);
void crypto_pseudo_rand(unsigned int n, unsigned char *to);
int crypto_pseudo_rand_int(unsigned int max);

/* errors */
const char *crypto_perror();
#endif

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
