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

/** Length of the output of our message digest. */
#define DIGEST_LEN 20
/** Length of the output of our second (improved) message digests.  (For now
 * this is just sha256, but it could be any other 256-bit digest.) */
#define DIGEST256_LEN 32
/** Length of the output of our 64-bit optimized message digests (SHA512). */
#define DIGEST512_LEN 64
/** Length of our symmetric cipher's keys of 128-bit. */
#define CIPHER_KEY_LEN 16
/** Length of our symmetric cipher's IV of 128-bit. */
#define CIPHER_IV_LEN 16
/** Length of our symmetric cipher's keys of 256-bit. */
#define CIPHER256_KEY_LEN 32
/** Length of our DH keys. */
#define DH_BYTES (1024/8)

/** Length of a sha1 message digest when encoded in base32 with trailing =
 * signs removed. */
#define BASE32_DIGEST_LEN 32
/** Length of a sha1 message digest when encoded in base64 with trailing =
 * signs removed. */
#define BASE64_DIGEST_LEN 27
/** Length of a sha256 message digest when encoded in base64 with trailing =
 * signs removed. */
#define BASE64_DIGEST256_LEN 43
/** Length of a sha512 message digest when encoded in base64 with trailing =
 * signs removed. */
#define BASE64_DIGEST512_LEN 86

/** Length of encoded public key fingerprints, including space; but not
 * including terminating NUL. */
#define FINGERPRINT_LEN 49
/** Length of hex encoding of SHA1 digest, not including final NUL. */
#define HEX_DIGEST_LEN 40
/** Length of hex encoding of SHA256 digest, not including final NUL. */
#define HEX_DIGEST256_LEN 64
/** Length of hex encoding of SHA512 digest, not including final NUL. */
#define HEX_DIGEST512_LEN 128

typedef enum {
  DIGEST_SHA1 = 0,
  DIGEST_SHA256 = 1,
  DIGEST_SHA512 = 2,
  DIGEST_SHA3_256 = 3,
  DIGEST_SHA3_512 = 4,
} digest_algorithm_t;
#define  N_DIGEST_ALGORITHMS (DIGEST_SHA3_512+1)
#define  N_COMMON_DIGEST_ALGORITHMS (DIGEST_SHA256+1)

/** A set of all the digests we commonly compute, taken on a single
 * string.  Any digests that are shorter than 512 bits are right-padded
 * with 0 bits.
 *
 * Note that this representation wastes 44 bytes for the SHA1 case, so
 * don't use it for anything where we need to allocate a whole bunch at
 * once.
 **/
typedef struct {
  char d[N_COMMON_DIGEST_ALGORITHMS][DIGEST256_LEN];
} common_digests_t;

typedef struct aes_cnt_cipher crypto_cipher_t;
typedef struct crypto_digest_t crypto_digest_t;
typedef struct crypto_xof_t crypto_xof_t;
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
MOCK_DECL(int, crypto_pk_public_checksig_digest,(crypto_pk_t *env,
                                         const char *data, size_t datalen,
                                         const char *sig, size_t siglen));
int crypto_pk_private_sign_digest(crypto_pk_t *env, char *to, size_t tolen,
                                  const char *from, size_t fromlen);
int crypto_pk_obsolete_public_hybrid_encrypt(crypto_pk_t *env, char *to,
                                    size_t tolen,
                                    const char *from, size_t fromlen,
                                    int padding, int force);
int crypto_pk_obsolete_private_hybrid_decrypt(crypto_pk_t *env, char *to,
                                     size_t tolen,
                                     const char *from, size_t fromlen,
                                     int padding, int warnOnFailure);
int crypto_pk_get_digest(const crypto_pk_t *pk, char *digest_out);
int crypto_pk_get_common_digests(crypto_pk_t *pk,
                                 common_digests_t *digests_out);

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

/* SHA-1 and other digests. */
int crypto_digest(char *digest, const char *m, size_t len);
int crypto_digest256(char *digest, const char *m, size_t len,
                     digest_algorithm_t algorithm);
int crypto_digest512(char *digest, const char *m, size_t len,
                     digest_algorithm_t algorithm);
int crypto_common_digests(common_digests_t *ds_out, const char *m, size_t len);
struct smartlist_t;
void crypto_digest_smartlist_prefix(char *digest_out, size_t len_out,
                                    const char *prepend,
                                    const struct smartlist_t *lst,
                                    const char *append,
                                    digest_algorithm_t alg);
void crypto_digest_smartlist(char *digest_out, size_t len_out,
                             const struct smartlist_t *lst, const char *append,
                             digest_algorithm_t alg);
const char *crypto_digest_algorithm_get_name(digest_algorithm_t alg);
size_t crypto_digest_algorithm_get_length(digest_algorithm_t alg);
int crypto_digest_algorithm_parse_name(const char *name);
crypto_digest_t *crypto_digest_new(void);
crypto_digest_t *crypto_digest256_new(digest_algorithm_t algorithm);
crypto_digest_t *crypto_digest512_new(digest_algorithm_t algorithm);
void crypto_digest_free_(crypto_digest_t *digest);
#define crypto_digest_free(d) \
  FREE_AND_NULL(crypto_digest_t, crypto_digest_free_, (d))
void crypto_digest_add_bytes(crypto_digest_t *digest, const char *data,
                             size_t len);
void crypto_digest_get_digest(crypto_digest_t *digest,
                              char *out, size_t out_len);
crypto_digest_t *crypto_digest_dup(const crypto_digest_t *digest);
void crypto_digest_assign(crypto_digest_t *into,
                          const crypto_digest_t *from);
void crypto_hmac_sha256(char *hmac_out,
                        const char *key, size_t key_len,
                        const char *msg, size_t msg_len);
void crypto_mac_sha3_256(uint8_t *mac_out, size_t len_out,
                         const uint8_t *key, size_t key_len,
                         const uint8_t *msg, size_t msg_len);

crypto_xof_t *crypto_xof_new(void);
void crypto_xof_add_bytes(crypto_xof_t *xof, const uint8_t *data, size_t len);
void crypto_xof_squeeze_bytes(crypto_xof_t *xof, uint8_t *out, size_t len);
void crypto_xof_free_(crypto_xof_t *xof);
#define crypto_xof_free(xof) \
  FREE_AND_NULL(crypto_xof_t, crypto_xof_free_, (xof))

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

#ifdef TOR_UNIT_TESTS
digest_algorithm_t crypto_digest_get_algorithm(crypto_digest_t *digest);
#endif

#endif /* !defined(TOR_CRYPTO_H) */

