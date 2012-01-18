/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/* Implements a minimal interface to counter-mode AES. */

#ifndef _TOR_AES_H
#define _TOR_AES_H

/**
 * \file aes.h
 * \brief Headers for aes.c
 */

struct aes_cnt_cipher;
typedef struct aes_cnt_cipher aes_cnt_cipher_t;

aes_cnt_cipher_t* aes_new_cipher(void);
void aes_cipher_free(aes_cnt_cipher_t *cipher);
void aes_set_key(aes_cnt_cipher_t *cipher, const char *key, int key_bits);
void aes_crypt(aes_cnt_cipher_t *cipher, const char *input, size_t len,
               char *output);
void aes_crypt_inplace(aes_cnt_cipher_t *cipher, char *data, size_t len);
void aes_set_iv(aes_cnt_cipher_t *cipher, const char *iv);

int evaluate_evp_for_aes(int force_value);
int evaluate_ctr_for_aes(void);

#endif

