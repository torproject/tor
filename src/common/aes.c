/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file aes.c
 * \brief Implements a counter-mode stream cipher on top of AES.
 **/

#include "orconfig.h"
#include <openssl/opensslv.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "compat.h"
#include "aes.h"
#include "util.h"
#include "torlog.h"

/* We have 2 strategies for getting AES: Via OpenSSL's AES_encrypt function,
 * via OpenSSL's EVP_EncryptUpdate function. */

/** Defined iff we're using OpenSSL's AES functions for AES. */
#undef USE_OPENSSL_AES
/** Defined iff we're using OpenSSL's EVP code for AES. */
#undef USE_OPENSSL_EVP

/* Here we pick which to use, if none is force-defined above */
#if (!defined(USE_OPENSSL_AES) && \
     !defined(USE_OPENSSL_EVP))

#define USE_OPENSSL_EVP

#endif

/* Include OpenSSL headers as needed. */
#ifdef USE_OPENSSL_AES
# include <openssl/aes.h>
#endif
#ifdef USE_OPENSSL_EVP
# include <openssl/evp.h>
#endif

/*======================================================================*/
/* Interface to AES code, and counter implementation */

/** Implements an AES counter-mode cipher. */
struct aes_cnt_cipher {
/** This next element (however it's defined) is the AES key. */
#if defined(USE_OPENSSL_EVP)
  EVP_CIPHER_CTX key;
#elif defined(USE_OPENSSL_AES)
  AES_KEY key;
#endif

#if !defined(WORDS_BIGENDIAN) || defined(USE_RIJNDAEL_COUNTER_OPTIMIZATION)
#define USING_COUNTER_VARS
  /** These four values, together, implement a 128-bit counter, with
   * counter0 as the low-order word and counter3 as the high-order word. */
  uint32_t counter3;
  uint32_t counter2;
  uint32_t counter1;
  uint32_t counter0;
#endif

#ifndef USE_RIJNDAEL_COUNTER_OPTIMIZATION
#define USING_COUNTER_BUFS
  union {
    /** The counter, in big-endian order, as bytes. */
    uint8_t buf[16];
    /** The counter, in big-endian order, as big-endian words.  Note that
     * on big-endian platforms, this is redundant with counter3...0,
     * so we just use these values instead. */
    uint32_t buf32[4];
  } ctr_buf;
#endif
  /** The encrypted value of ctr_buf. */
  uint8_t buf[16];
  /** Our current stream position within buf. */
  uint8_t pos;
};

#if !defined(USING_COUNTER_VARS)
#define COUNTER(c, n) ((c)->ctr_buf.buf32[3-(n)])
#else
#define COUNTER(c, n) ((c)->counter ## n)
#endif

/**
 * Helper function: set <b>cipher</b>'s internal buffer to the encrypted
 * value of the current counter.
 */
static INLINE void
_aes_fill_buf(aes_cnt_cipher_t *cipher)
{
  /* We don't currently use OpenSSL's counter mode implementation because:
   *  1) some versions have known bugs
   *  2) its attitude towards IVs is not our own
   *  3) changing the counter position was not trivial, last time I looked.
   * None of these issues are insurmountable in principle.
   */

#if defined(USE_OPENSSL_EVP)
  {
    int outl=16, inl=16;
    EVP_EncryptUpdate(&cipher->key, cipher->buf, &outl,
                      cipher->ctr_buf.buf, inl);
  }
#elif defined(USE_OPENSSL_AES)
  AES_encrypt(cipher->ctr_buf.buf, cipher->buf, &cipher->key);
#endif
}

/**
 * Return a newly allocated counter-mode AES128 cipher implementation.
 */
aes_cnt_cipher_t*
aes_new_cipher(void)
{
  aes_cnt_cipher_t* result = tor_malloc_zero(sizeof(aes_cnt_cipher_t));

  return result;
}

/** Set the key of <b>cipher</b> to <b>key</b>, which is
 * <b>key_bits</b> bits long (must be 128, 192, or 256).  Also resets
 * the counter to 0.
 */
void
aes_set_key(aes_cnt_cipher_t *cipher, const char *key, int key_bits)
{
#if defined(USE_OPENSSL_EVP)
  const EVP_CIPHER *c;
  switch (key_bits) {
    case 128: c = EVP_aes_128_ecb(); break;
    case 192: c = EVP_aes_192_ecb(); break;
    case 256: c = EVP_aes_256_ecb(); break;
    default: tor_assert(0);
  }
  EVP_EncryptInit(&cipher->key, c, (const unsigned char*)key, NULL);
#elif defined(USE_OPENSSL_AES)
  AES_set_encrypt_key((const unsigned char *)key, key_bits, &(cipher->key));
#endif
#ifdef USING_COUNTER_VARS
  cipher->counter0 = 0;
  cipher->counter1 = 0;
  cipher->counter2 = 0;
  cipher->counter3 = 0;
#endif
#ifdef USING_COUNTER_BUFS
  memset(cipher->ctr_buf.buf, 0, sizeof(cipher->ctr_buf.buf));
#endif

  cipher->pos = 0;
  _aes_fill_buf(cipher);
}

/** Release storage held by <b>cipher</b>
 */
void
aes_free_cipher(aes_cnt_cipher_t *cipher)
{
  if (!cipher)
    return;
#ifdef USE_OPENSSL_EVP
  EVP_CIPHER_CTX_cleanup(&cipher->key);
#endif
  memset(cipher, 0, sizeof(aes_cnt_cipher_t));
  tor_free(cipher);
}

#if defined(USING_COUNTER_VARS) && defined(USING_COUNTER_BUFS)
#define UPDATE_CTR_BUF(c, n) STMT_BEGIN                 \
  (c)->ctr_buf.buf32[3-(n)] = htonl((c)->counter ## n); \
  STMT_END
#else
#define UPDATE_CTR_BUF(c, n)
#endif

/** Encrypt <b>len</b> bytes from <b>input</b>, storing the result in
 * <b>output</b>.  Uses the key in <b>cipher</b>, and advances the counter
 * by <b>len</b> bytes as it encrypts.
 */
void
aes_crypt(aes_cnt_cipher_t *cipher, const char *input, size_t len,
          char *output)
{
  /* This function alone is up to 5% of our runtime in some profiles; anything
   * we could do to make it faster would be great.
   *
   * Experimenting suggests that unrolling the inner loop into a switch
   * statement doesn't help.  What does seem to help is making the input and
   * output buffers word aligned, and never crypting anything besides an
   * integer number of words at a time -- it shaves maybe 4-5% of the per-byte
   * encryption time measured by bench_aes. We can't do that with the current
   * Tor protocol, though: Tor really likes to crypt things in 509-byte
   * chunks.
   *
   * If we were really ambitous, we'd force len to be a multiple of the block
   * size, and shave maybe another 4-5% off.
   */
  int c = cipher->pos;
  if (PREDICT_UNLIKELY(!len)) return;

  while (1) {
    do {
      if (len-- == 0) { cipher->pos = c; return; }
      *(output++) = *(input++) ^ cipher->buf[c];
    } while (++c != 16);
    cipher->pos = c = 0;
    if (PREDICT_UNLIKELY(! ++COUNTER(cipher, 0))) {
      if (PREDICT_UNLIKELY(! ++COUNTER(cipher, 1))) {
        if (PREDICT_UNLIKELY(! ++COUNTER(cipher, 2))) {
          ++COUNTER(cipher, 3);
          UPDATE_CTR_BUF(cipher, 3);
        }
        UPDATE_CTR_BUF(cipher, 2);
      }
      UPDATE_CTR_BUF(cipher, 1);
    }
    UPDATE_CTR_BUF(cipher, 0);
    _aes_fill_buf(cipher);
  }
}

/** Encrypt <b>len</b> bytes from <b>input</b>, storing the results in place.
 * Uses the key in <b>cipher</b>, and advances the counter by <b>len</b> bytes
 * as it encrypts.
 */
void
aes_crypt_inplace(aes_cnt_cipher_t *cipher, char *data, size_t len)
{

  /* XXXX This function is up to 5% of our runtime in some profiles;
   * we should look into unrolling some of the loops; taking advantage
   * of alignment, using a bigger buffer, and so on. Not till after 0.1.2.x,
   * though. */
  int c = cipher->pos;
  if (PREDICT_UNLIKELY(!len)) return;

  while (1) {
    do {
      if (len-- == 0) { cipher->pos = c; return; }
      *(data++) ^= cipher->buf[c];
    } while (++c != 16);
    cipher->pos = c = 0;
    if (PREDICT_UNLIKELY(! ++COUNTER(cipher, 0))) {
      if (PREDICT_UNLIKELY(! ++COUNTER(cipher, 1))) {
        if (PREDICT_UNLIKELY(! ++COUNTER(cipher, 2))) {
          ++COUNTER(cipher, 3);
          UPDATE_CTR_BUF(cipher, 3);
        }
        UPDATE_CTR_BUF(cipher, 2);
      }
      UPDATE_CTR_BUF(cipher, 1);
    }
    UPDATE_CTR_BUF(cipher, 0);
    _aes_fill_buf(cipher);
  }
}

/** Reset the 128-bit counter of <b>cipher</b> to the 16-bit big-endian value
 * in <b>iv</b>. */
void
aes_set_iv(aes_cnt_cipher_t *cipher, const char *iv)
{
#ifdef USING_COUNTER_VARS
  cipher->counter3 = ntohl(get_uint32(iv));
  cipher->counter2 = ntohl(get_uint32(iv+4));
  cipher->counter1 = ntohl(get_uint32(iv+8));
  cipher->counter0 = ntohl(get_uint32(iv+12));
#endif
  cipher->pos = 0;
#ifndef USE_RIJNDAEL_COUNTER_OPTIMIZATION
  memcpy(cipher->ctr_buf.buf, iv, 16);
#endif

  _aes_fill_buf(cipher);
}

