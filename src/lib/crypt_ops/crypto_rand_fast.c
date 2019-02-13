/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypto_rand_fast.c
 *
 * \brief A fast strong PRNG for use when our underlying cryptographic
 *   library's PRNG isn't fast enough.
 **/

/* This library is currently implemented to use the same implementation
 * technique as libottery, using AES-CTR-256 as our underlying stream cipher.
 * It's backtracking-resistant immediately, and prediction-resistant after
 * a while.
 *
 * Here's how it works:
 *
 * We generate pseudorandom bytes using AES-CTR-256.  We generate BUFLEN bytes
 * at a time.  When we do this, we keep the first SEED_LEN bytes as the key
 * and the IV for our next invocation of AES_CTR, and yield the remaining
 * BUFLEN - SEED_LEN bytes to the user as they invoke the PRNG.  As we yield
 * bytes to the user, we clear them from the buffer.
 *
 * After we have refilled the buffer RESEED_AFTER times, we mix in an
 * additional SEED_LEN bytes from our strong PRNG into the seed.
 *
 * If the user ever asks for a huge number of bytes at once, we pull SEED_LEN
 * bytes from the PRNG and use them with our stream cipher to fill the user's
 * request.
 */

#define CRYPTO_RAND_FAST_PRIVATE

#include "lib/crypt_ops/crypto_rand.h"
#include "lib/crypt_ops/crypto_cipher.h"
#include "lib/crypt_ops/crypto_digest.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/intmath/cmp.h"
#include "lib/cc/ctassert.h"
#include "lib/malloc/map_anon.h"

#include "lib/log/util_bug.h"

#include <string.h>

/* Alias for CRYPTO_FAST_RNG_SEED_LEN to make our code shorter.
 */
#define SEED_LEN (CRYPTO_FAST_RNG_SEED_LEN)

/* The amount of space that we mmap for a crypto_fast_rng_t.
 */
#define MAPLEN 4096

/* The number of random bytes that we can yield to the user after each
 * time we fill a crypto_fast_rng_t's buffer.
 */
#define BUFLEN (MAPLEN - 2*sizeof(uint16_t) - SEED_LEN)

/* The number of buffer refills after which we should fetch more
 * entropy from crypto_strongest_rand().
 */
#define RESEED_AFTER 16

/* The length of the stream cipher key we will use for the PRNG, in bytes.
 */
#define KEY_LEN (CRYPTO_FAST_RNG_SEED_LEN - CIPHER_IV_LEN)
/* The length of the stream cipher key we will use for the PRNG, in bits.
 */
#define KEY_BITS (KEY_LEN * 8)

/* Make sure that we have a key length we can actually use with AES. */
CTASSERT(KEY_BITS == 128 || KEY_BITS == 192 || KEY_BITS == 256);

struct crypto_fast_rng_t {
  /** How many more fills does this buffer have before we should mix
   * in the output of crypto_rand()? */
  uint16_t n_till_reseed;
  /** How many bytes are remaining in cbuf.bytes? */
  uint16_t bytes_left;
  struct cbuf {
    /** The seed (key and IV) that we will use the next time that we refill
     * cbuf. */
    uint8_t seed[SEED_LEN];
    /**
     * Bytes that we are yielding to the user.  The next byte to be
     * yielded is at bytes[BUFLEN-bytes_left]; all other bytes in this
     * array are set to zero.
     */
    uint8_t bytes[BUFLEN];
  } buf;
};

/* alignof(uint8_t) should be 1, so there shouldn't be any padding in cbuf.
 */
CTASSERT(sizeof(struct cbuf) == BUFLEN+SEED_LEN);
/* We're trying to fit all of the RNG state into a nice mmapable chunk.
 */
CTASSERT(sizeof(crypto_fast_rng_t) <= MAPLEN);

/**
 * Initialize and return a new fast PRNG, using a strong random seed.
 *
 * Note that this object is NOT thread-safe.  If you need a thread-safe
 * prng, use crypto_rand(), or wrap this in a mutex.
 **/
crypto_fast_rng_t *
crypto_fast_rng_new(void)
{
  uint8_t seed[SEED_LEN];
  crypto_strongest_rand(seed, sizeof(seed));
  crypto_fast_rng_t *result = crypto_fast_rng_new_from_seed(seed);
  memwipe(seed, 0, sizeof(seed));
  return result;
}

/**
 * Initialize and return a new fast PRNG, using a seed value specified
 * in <b>seed</b>.  This value must be CRYPTO_FAST_RNG_SEED_LEN bytes
 * long.
 *
 * Note that this object is NOT thread-safe.  If you need a thread-safe
 * prng, use crypto_rand(), or wrap this in a mutex.
 **/
crypto_fast_rng_t *
crypto_fast_rng_new_from_seed(const uint8_t *seed)
{
  /* We try to allocate this object as securely as we can, to avoid
   * having it get dumped, swapped, or shared after fork.
   */
  crypto_fast_rng_t *result = tor_mmap_anonymous(sizeof(*result),
                                ANONMAP_PRIVATE | ANONMAP_NOINHERIT);

  memcpy(result->buf.seed, seed, SEED_LEN);
  /* Causes an immediate refill once the user asks for data. */
  result->bytes_left = 0;
  result->n_till_reseed = RESEED_AFTER;
  return result;
}

/**
 * Helper: create a crypto_cipher_t object from SEED_LEN bytes of
 * input.  The first KEY_LEN bytes are used as the stream cipher's key,
 * and the remaining CIPHER_IV_LEN bytes are used as its IV.
 **/
static inline crypto_cipher_t *
cipher_from_seed(const uint8_t *seed)
{
  return crypto_cipher_new_with_iv_and_bits(seed, seed+KEY_LEN, KEY_BITS);
}

/**
 * Helper: refill the seed bytes and output buffer of <b>rng</b>, using
 * the input seed bytes as input (key and IV) for the stream cipher.
 *
 * If the n_till_reseed counter has reached zero, mix more random bytes into
 * the seed before refilling the buffer.
 **/
static void
crypto_fast_rng_refill(crypto_fast_rng_t *rng)
{
  if (rng->n_till_reseed-- == 0) {
    /* It's time to reseed the RNG.  We'll do this by using our XOF to mix the
     * old value for the seed with some additional bytes from
     * crypto_strongest_rand(). */
    crypto_xof_t *xof = crypto_xof_new();
    crypto_xof_add_bytes(xof, rng->buf.seed, SEED_LEN);
    {
      uint8_t seedbuf[SEED_LEN];
      crypto_strongest_rand(seedbuf, SEED_LEN);
      crypto_xof_add_bytes(xof, seedbuf, SEED_LEN);
      memwipe(seedbuf, 0, SEED_LEN);
    }
    crypto_xof_squeeze_bytes(xof, rng->buf.seed, SEED_LEN);
    crypto_xof_free(xof);

    rng->n_till_reseed = RESEED_AFTER;
  }
  /* Now fill rng->buf with output from our stream cipher, initialized from
   * that seed value. */
  crypto_cipher_t *c = cipher_from_seed(rng->buf.seed);
  memset(&rng->buf, 0, sizeof(rng->buf));
  crypto_cipher_crypt_inplace(c, (char*)&rng->buf, sizeof(rng->buf));
  crypto_cipher_free(c);

  rng->bytes_left = sizeof(rng->buf.bytes);
}

/**
 * Release all storage held by <b>rng</b>.
 **/
void
crypto_fast_rng_free_(crypto_fast_rng_t *rng)
{
  if (!rng)
    return;
  memwipe(rng, 0, sizeof(*rng));
  tor_munmap_anonymous(rng, sizeof(*rng));
}

/**
 * Helper: extract bytes from the PRNG, refilling it as necessary. Does not
 * optimize the case when the user has asked for a huge output.
 **/
static void
crypto_fast_rng_getbytes_impl(crypto_fast_rng_t *rng, uint8_t *out,
                              const size_t n)
{
  size_t bytes_to_yield = n;

  while (bytes_to_yield) {
    if (rng->bytes_left == 0)
      crypto_fast_rng_refill(rng);

    const size_t to_copy = MIN(rng->bytes_left, bytes_to_yield);

    tor_assert(sizeof(rng->buf.bytes) >= rng->bytes_left);
    uint8_t *copy_from = rng->buf.bytes +
      (sizeof(rng->buf.bytes) - rng->bytes_left);
    memcpy(out, copy_from, to_copy);
    memset(copy_from, 0, to_copy);

    out += to_copy;
    bytes_to_yield -= to_copy;
    rng->bytes_left -= to_copy;
  }
}

/**
 * Extract <b>n</b> bytes from <b>rng</b> into the buffer at <b>out</b>.
 **/
void
crypto_fast_rng_getbytes(crypto_fast_rng_t *rng, uint8_t *out, size_t n)
{
  if (PREDICT_UNLIKELY(n > BUFLEN)) {
    /* The user has asked for a lot of output; generate it from a stream
     * cipher seeded by the PRNG rather than by pulling it out of the PRNG
     * directly.
     */
    uint8_t seed[SEED_LEN];
    crypto_fast_rng_getbytes_impl(rng, seed, SEED_LEN);
    crypto_cipher_t *c = cipher_from_seed(seed);
    memset(out, 0, n);
    crypto_cipher_crypt_inplace(c, (char*)out, n);
    crypto_cipher_free(c);
    memwipe(seed, 0, sizeof(seed));
    return;
  }

  crypto_fast_rng_getbytes_impl(rng, out, n);
}

#if defined(TOR_UNIT_TESTS)
/** for white-box testing: return the number of bytes that are returned from
 * the user for each invocation of the stream cipher in this RNG. */
size_t
crypto_fast_rng_get_bytes_used_per_stream(void)
{
  return BUFLEN;
}
#endif
