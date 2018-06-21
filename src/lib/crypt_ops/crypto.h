/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
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
#include "lib/cc/torint.h"
#include "common/compat.h"
#include "common/util.h"
#include "lib/crypt_ops/crypto_rsa.h"

/** Length of our symmetric cipher's keys of 128-bit. */
#define CIPHER_KEY_LEN 16
/** Length of our symmetric cipher's IV of 128-bit. */
#define CIPHER_IV_LEN 16
/** Length of our symmetric cipher's keys of 256-bit. */
#define CIPHER256_KEY_LEN 32

/** Length of encoded public key fingerprints, including space; but not
 * including terminating NUL. */
#define FINGERPRINT_LEN 49

typedef struct aes_cnt_cipher crypto_cipher_t;

/* global state */
int crypto_init_siphash_key(void);
int crypto_early_init(void) ATTR_WUR;
int crypto_global_init(int hardwareAccel,
                       const char *accelName,
                       const char *accelPath) ATTR_WUR;

void crypto_thread_cleanup(void);
int crypto_global_cleanup(void);

/* environment setup */
crypto_cipher_t *crypto_cipher_new(const char *key);
crypto_cipher_t *crypto_cipher_new_with_bits(const char *key, int bits);
crypto_cipher_t *crypto_cipher_new_with_iv(const char *key, const char *iv);
crypto_cipher_t *crypto_cipher_new_with_iv_and_bits(const uint8_t *key,
                                                    const uint8_t *iv,
                                                    int bits);
void crypto_cipher_free_(crypto_cipher_t *env);
#define crypto_cipher_free(c) \
  FREE_AND_NULL(crypto_cipher_t, crypto_cipher_free_, (c))

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

void crypto_add_spaces_to_fp(char *out, size_t outlen, const char *in);

#endif /* !defined(TOR_CRYPTO_H) */
