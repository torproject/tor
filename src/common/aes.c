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
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#if OPENSSL_VERSION_NUMBER >= 0x1000001fL
/* See comments about which counter mode implementation to use below. */
#include <openssl/modes.h>
#define USE_OPENSSL_CTR
#endif
#include "compat.h"
#include "aes.h"
#include "util.h"
#include "torlog.h"

#ifdef ANDROID
/* Android's OpenSSL seems to have removed all of its Engine support. */
#define DISABLE_ENGINES
#endif

/* We have 2 strategies for getting AES: Via OpenSSL's AES_encrypt function,
 * via OpenSSL's EVP_EncryptUpdate function.
 *
 * If there's any hardware acceleration in play, we want to be using EVP_* so
 * we can get it.  Otherwise, we'll want AES_*, which seems to be about 5%
 * faster than indirecting through the EVP layer.
 */

/* We have 2 strategies for counter mode: use our own, or use OpenSSL's.
 *
 * Here we have a counter mode that's faster than the one shipping with
 * OpenSSL pre-1.0 (by about 10%!).  But OpenSSL 1.0.0 added a counter mode
 * implementation faster than the one here (by about 7%).  So we pick which
 * one to used based on the Openssl version above.  (OpenSSL 1.0.0a fixed a
 * critical bug in that counter mode implementation, so we actually require
 * that one.)
 */

/*======================================================================*/
/* Interface to AES code, and counter implementation */

/** Implements an AES counter-mode cipher. */
struct aes_cnt_cipher {
/** This next element (however it's defined) is the AES key. */
  union {
    EVP_CIPHER_CTX evp;
    AES_KEY aes;
  } key;

#if !defined(WORDS_BIGENDIAN) && !defined(USE_OPENSSL_CTR)
#define USING_COUNTER_VARS
  /** These four values, together, implement a 128-bit counter, with
   * counter0 as the low-order word and counter3 as the high-order word. */
  uint32_t counter3;
  uint32_t counter2;
  uint32_t counter1;
  uint32_t counter0;
#endif

  union {
    /** The counter, in big-endian order, as bytes. */
    uint8_t buf[16];
    /** The counter, in big-endian order, as big-endian words.  Note that
     * on big-endian platforms, this is redundant with counter3...0,
     * so we just use these values instead. */
    uint32_t buf32[4];
  } ctr_buf;

  /** The encrypted value of ctr_buf. */
  uint8_t buf[16];
  /** Our current stream position within buf. */
#ifdef USE_OPENSSL_CTR
  unsigned int pos;
#else
  uint8_t pos;
#endif

  /** True iff we're using the evp implementation of this cipher. */
  uint8_t using_evp;
};

/** True if we should prefer the EVP implementation for AES, either because
 * we're testing it or because we have hardware acceleration configured */
static int should_use_EVP = 0;

/** Check whether we should use the EVP interface for AES. If <b>force_val</b>
 * is nonnegative, we use use EVP iff it is true.  Otherwise, we use EVP
 * if there is an engine enabled for aes-ecb. */
int
evaluate_evp_for_aes(int force_val)
{
  ENGINE *e;

  if (force_val >= 0) {
    should_use_EVP = force_val;
    return 0;
  }
#ifdef DISABLE_ENGINES
  should_use_EVP = 0;
#else
  e = ENGINE_get_cipher_engine(NID_aes_128_ecb);

  if (e) {
    log_notice(LD_CRYPTO, "AES engine \"%s\" found; using EVP_* functions.",
               ENGINE_get_name(e));
    should_use_EVP = 1;
  } else {
    log_notice(LD_CRYPTO, "No AES engine found; using AES_* functions.");
    should_use_EVP = 0;
  }
#endif

  return 0;
}

#ifndef USE_OPENSSL_CTR
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

  if (cipher->using_evp) {
    int outl=16, inl=16;
    EVP_EncryptUpdate(&cipher->key.evp, cipher->buf, &outl,
                      cipher->ctr_buf.buf, inl);
  } else {
    AES_encrypt(cipher->ctr_buf.buf, cipher->buf, &cipher->key.aes);
  }
}
#endif

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
  if (should_use_EVP) {
    const EVP_CIPHER *c;
    switch (key_bits) {
      case 128: c = EVP_aes_128_ecb(); break;
      case 192: c = EVP_aes_192_ecb(); break;
      case 256: c = EVP_aes_256_ecb(); break;
      default: tor_assert(0);
    }
    EVP_EncryptInit(&cipher->key.evp, c, (const unsigned char*)key, NULL);
    cipher->using_evp = 1;
  } else {
    AES_set_encrypt_key((const unsigned char *)key, key_bits, &cipher->key.aes);
    cipher->using_evp = 0;
  }

#ifdef USING_COUNTER_VARS
  cipher->counter0 = 0;
  cipher->counter1 = 0;
  cipher->counter2 = 0;
  cipher->counter3 = 0;
#endif

  memset(cipher->ctr_buf.buf, 0, sizeof(cipher->ctr_buf.buf));

  cipher->pos = 0;

#ifdef USE_OPENSSL_CTR
  memset(cipher->buf, 0, sizeof(cipher->buf));
#else
  _aes_fill_buf(cipher);
#endif
}

/** Release storage held by <b>cipher</b>
 */
void
aes_free_cipher(aes_cnt_cipher_t *cipher)
{
  if (!cipher)
    return;
  if (cipher->using_evp) {
    EVP_CIPHER_CTX_cleanup(&cipher->key.evp);
  }
  memset(cipher, 0, sizeof(aes_cnt_cipher_t));
  tor_free(cipher);
}

#if defined(USING_COUNTER_VARS)
#define UPDATE_CTR_BUF(c, n) STMT_BEGIN                 \
  (c)->ctr_buf.buf32[3-(n)] = htonl((c)->counter ## n); \
  STMT_END
#else
#define UPDATE_CTR_BUF(c, n)
#endif

#ifdef USE_OPENSSL_CTR
/* Helper function to use EVP with openssl's counter-mode wrapper. */
static void evp_block128_fn(const uint8_t in[16],
                            uint8_t out[16],
                            const void *key)
{
  EVP_CIPHER_CTX *ctx = (void*)key;
  int inl=16, outl=16;
  EVP_EncryptUpdate(ctx, out, &outl, in, inl);
}
#endif

/** Encrypt <b>len</b> bytes from <b>input</b>, storing the result in
 * <b>output</b>.  Uses the key in <b>cipher</b>, and advances the counter
 * by <b>len</b> bytes as it encrypts.
 */
void
aes_crypt(aes_cnt_cipher_t *cipher, const char *input, size_t len,
          char *output)
{
#ifdef USE_OPENSSL_CTR
  if (cipher->using_evp) {
    /* In openssl 1.0.0, there's an if'd out EVP_aes_128_ctr in evp.h.  If
     * it weren't disabled, it might be better just to use that.
     */
    CRYPTO_ctr128_encrypt((const unsigned char *)input,
                          (unsigned char *)output,
                          len,
                          &cipher->key.evp,
                          cipher->ctr_buf.buf,
                          cipher->buf,
                          &cipher->pos,
                          evp_block128_fn);
  } else {
    AES_ctr128_encrypt((const unsigned char *)input,
                       (unsigned char *)output,
                       len,
                       &cipher->key.aes,
                       cipher->ctr_buf.buf,
                       cipher->buf,
                       &cipher->pos);
  }
#else
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
#endif
}

/** Encrypt <b>len</b> bytes from <b>input</b>, storing the results in place.
 * Uses the key in <b>cipher</b>, and advances the counter by <b>len</b> bytes
 * as it encrypts.
 */
void
aes_crypt_inplace(aes_cnt_cipher_t *cipher, char *data, size_t len)
{
#ifdef USE_OPENSSL_CTR
  aes_crypt(cipher, data, len, data);
#else
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
#endif
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
  memcpy(cipher->ctr_buf.buf, iv, 16);

#ifndef USE_OPENSSL_CTR
  _aes_fill_buf(cipher);
#endif
}

