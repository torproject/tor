/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypto.h
 *
 * \brief Headers for crypto.c
 **/

#ifndef TOR_CRYPTO_H
#define TOR_CRYPTO_H

#include "orconfig.h"

#include <stdio.h>
#include "torint.h"
#include "testsupport.h"
#include "compat.h"
#include "util.h"
#include "crypto_rsa.h"

#include "keccak-tiny/keccak-tiny.h"

/** Length of our symmetric cipher's keys of 128-bit. */
#define CIPHER_KEY_LEN 16
/** Length of our symmetric cipher's IV of 128-bit. */
#define CIPHER_IV_LEN 16
/** Length of our symmetric cipher's keys of 256-bit. */
#define CIPHER256_KEY_LEN 32
/** Length of our DH keys. */
#define DH_BYTES (1024/8)

/** Length of encoded public key fingerprints, including space; but not
 * including terminating NUL. */
#define FINGERPRINT_LEN 49

typedef struct aes_cnt_cipher crypto_cipher_t;
typedef struct crypto_dh_t crypto_dh_t;

/* global state */
int crypto_early_init(void) ATTR_WUR;
int crypto_global_init(int hardwareAccel,
                       const char *accelName,
                       const char *accelPath) ATTR_WUR;
#ifdef USE_DMALLOC
int crypto_use_tor_alloc_functions(void);
#endif

void crypto_thread_cleanup(void);
int crypto_global_cleanup(void);

/* environment setup */
void crypto_set_tls_dh_prime(void);
crypto_cipher_t *crypto_cipher_new(const char *key);
crypto_cipher_t *crypto_cipher_new_with_bits(const char *key, int bits);
crypto_cipher_t *crypto_cipher_new_with_iv(const char *key, const char *iv);
crypto_cipher_t *crypto_cipher_new_with_iv_and_bits(const uint8_t *key,
                                                    const uint8_t *iv,
                                                    int bits);
void crypto_cipher_free_(crypto_cipher_t *env);
#define crypto_cipher_free(c) \
  FREE_AND_NULL(crypto_cipher_t, crypto_cipher_free_, (c))

/* public key crypto  */
int crypto_pk_obsolete_public_hybrid_encrypt(crypto_pk_t *env, char *to,
                                    size_t tolen,
                                    const char *from, size_t fromlen,
                                    int padding, int force);
int crypto_pk_obsolete_private_hybrid_decrypt(crypto_pk_t *env, char *to,
                                     size_t tolen,
                                     const char *from, size_t fromlen,
                                     int padding, int warnOnFailure);

/* symmetric crypto */
const char *crypto_cipher_get_key(crypto_cipher_t *env);

int crypto_cipher_encrypt(crypto_cipher_t *env, char *to,
                          const char *from, size_t fromlen);
int crypto_cipher_decrypt(crypto_cipher_t *env, char *to,
                          const char *from, size_t fromlen);
void crypto_cipher_crypt_inplace(crypto_cipher_t *env, char *d, size_t len);

int crypto_cipher_encrypt_with_iv(const char *key,
                                  char *to, size_t tolen,
                                  const char *from, size_t fromlen);
int crypto_cipher_decrypt_with_iv(const char *key,
                                  char *to, size_t tolen,
                                  const char *from, size_t fromlen);

/* Key negotiation */
#define DH_TYPE_CIRCUIT 1
#define DH_TYPE_REND 2
#define DH_TYPE_TLS 3
crypto_dh_t *crypto_dh_new(int dh_type);
crypto_dh_t *crypto_dh_dup(const crypto_dh_t *dh);
int crypto_dh_get_bytes(crypto_dh_t *dh);
int crypto_dh_generate_public(crypto_dh_t *dh);
int crypto_dh_get_public(crypto_dh_t *dh, char *pubkey_out,
                         size_t pubkey_out_len);
ssize_t crypto_dh_compute_secret(int severity, crypto_dh_t *dh,
                             const char *pubkey, size_t pubkey_len,
                             char *secret_out, size_t secret_out_len);
void crypto_dh_free_(crypto_dh_t *dh);
#define crypto_dh_free(dh) FREE_AND_NULL(crypto_dh_t, crypto_dh_free_, (dh))

int crypto_expand_key_material_TAP(const uint8_t *key_in,
                                   size_t key_in_len,
                                   uint8_t *key_out, size_t key_out_len);
int crypto_expand_key_material_rfc5869_sha256(
                                    const uint8_t *key_in, size_t key_in_len,
                                    const uint8_t *salt_in, size_t salt_in_len,
                                    const uint8_t *info_in, size_t info_in_len,
                                    uint8_t *key_out, size_t key_out_len);

/* random numbers */
int crypto_seed_rng(void) ATTR_WUR;
MOCK_DECL(void,crypto_rand,(char *to, size_t n));
void crypto_rand_unmocked(char *to, size_t n);
void crypto_strongest_rand(uint8_t *out, size_t out_len);
int crypto_rand_int(unsigned int max);
int crypto_rand_int_range(unsigned int min, unsigned int max);
uint64_t crypto_rand_uint64_range(uint64_t min, uint64_t max);
time_t crypto_rand_time_range(time_t min, time_t max);
uint64_t crypto_rand_uint64(uint64_t max);
double crypto_rand_double(void);
struct tor_weak_rng_t;
void crypto_seed_weak_rng(struct tor_weak_rng_t *rng);
int crypto_init_siphash_key(void);

char *crypto_random_hostname(int min_rand_len, int max_rand_len,
                             const char *prefix, const char *suffix);

struct smartlist_t;
void *smartlist_choose(const struct smartlist_t *sl);
void smartlist_shuffle(struct smartlist_t *sl);

/** OpenSSL-based utility functions. */
void memwipe(void *mem, uint8_t byte, size_t sz);

/* Prototypes for private functions only used by tortls.c, crypto.c, and the
 * unit tests. */
struct dh_st;
struct dh_st *crypto_dh_get_dh_(crypto_dh_t *dh);

void crypto_add_spaces_to_fp(char *out, size_t outlen, const char *in);

#ifdef CRYPTO_PRIVATE

STATIC int crypto_force_rand_ssleay(void);
STATIC int crypto_strongest_rand_raw(uint8_t *out, size_t out_len);

#ifdef TOR_UNIT_TESTS
extern int break_strongest_rng_syscall;
extern int break_strongest_rng_fallback;
#endif
#endif /* defined(CRYPTO_PRIVATE) */

#endif /* !defined(TOR_CRYPTO_H) */

