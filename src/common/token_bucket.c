/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file token_bucket.c
 * \brief Functions to use and manipulate token buckets, used for
 *    rate-limiting on connections and globally.
 *
 * Tor uses these token buckets to keep track of bandwidth usage, and
 * sometimes other things too.
 *
 * The time units we use internally are based on "timestamp" units -- see
 * monotime_coarse_to_stamp() for a rationale.
 *
 * Token buckets may become negative.
 **/

#define TOKEN_BUCKET_PRIVATE

#include "token_bucket.h"
#include "util_bug.h"

/** Convert a rate in bytes per second to a rate in bytes per step */
static uint32_t
rate_per_sec_to_rate_per_step(uint32_t rate)
{
  return rate / (STAMP_TICKS_PER_SECOND / TICKS_PER_STEP);
}

/**
 * Initialize a token bucket in *<b>bucket</b>, set up to allow <b>rate</b>
 * bytes per second, with a maximum burst of <b>burst</b> bytes. The bucket
 * is created such that <b>now_ts</b> is the current timestamp.  The bucket
 * starts out full.
 */
void
token_bucket_init(token_bucket_t *bucket,
                  uint32_t rate,
                  uint32_t burst,
                  uint32_t now_ts)
{
  memset(bucket, 0, sizeof(token_bucket_t));
  token_bucket_adjust(bucket, rate, burst);
  token_bucket_reset(bucket, now_ts);
}

/**
 * Change the configured rate (in bytes per second) and burst (in bytes)
 * for the token bucket in *<b>bucket</b>.
 */
void
token_bucket_adjust(token_bucket_t *bucket,
                    uint32_t rate,
                    uint32_t burst)
{
  tor_assert_nonfatal(rate > 0);
  tor_assert_nonfatal(burst > 0);
  if (burst > TOKEN_BUCKET_MAX_BURST)
    burst = TOKEN_BUCKET_MAX_BURST;

  bucket->rate = rate_per_sec_to_rate_per_step(rate);
  bucket->burst = burst;
  bucket->read_bucket = MIN(bucket->read_bucket, (int32_t)burst);
  bucket->read_bucket = MIN(bucket->write_bucket, (int32_t)burst);
}

/**
 * Reset <b>bucket</b> to be full, as of timestamp <b>now_ts</b>.
 */
void
token_bucket_reset(token_bucket_t *bucket,
                   uint32_t now_ts)
{
  bucket->read_bucket = bucket->burst;
  bucket->write_bucket = bucket->burst;
  bucket->last_refilled_at_ts = now_ts;
}

/* Helper: see token_bucket_refill */
static int
refill_single_bucket(int32_t *bucketptr,
                     const uint32_t rate,
                     const int32_t burst,
                     const uint32_t elapsed_steps)
{
  const int was_empty = *bucketptr <= 0;
  /* The casts here prevent an underflow. */
  const size_t gap = ((size_t)burst) - ((size_t)*bucketptr);

  if (elapsed_steps > gap / rate) {
    *bucketptr = burst;
  } else {
    *bucketptr += rate * elapsed_steps;
  }

  return was_empty && *bucketptr > 0;
}

/**
 * Refill <b>bucket</b> as appropriate, given that the current timestamp
 * is <b>now_ts</b>.
 *
 * Return a bitmask containing TB_READ iff read bucket was empty and became
 * nonempty, and TB_WRITE iff the write bucket was empty and became nonempty.
 */
int
token_bucket_refill(token_bucket_t *bucket,
                    uint32_t now_ts)
{
  const uint32_t elapsed_ticks = (now_ts - bucket->last_refilled_at_ts);
  const uint32_t elapsed_steps = elapsed_ticks / TICKS_PER_STEP;

  if (!elapsed_steps) {
    /* Note that if less than one whole step elapsed, we don't advance the
     * time in last_refilled_at_ts. That's intentional: we want to make sure
     * that we add some bytes to it eventually. */
    return 0;
  }

  int flags = 0;
  if (refill_single_bucket(&bucket->read_bucket,
                           bucket->rate, bucket->burst, elapsed_steps))
    flags |= TB_READ;
  if (refill_single_bucket(&bucket->write_bucket,
                           bucket->rate, bucket->burst, elapsed_steps))
    flags |= TB_WRITE;

  bucket->last_refilled_at_ts = now_ts;
  return flags;
}

static int
decrement_single_bucket(int32_t *bucketptr,
                        ssize_t n)
{
  if (BUG(n < 0))
    return 0;
  const int becomes_empty = *bucketptr > 0 && n >= *bucketptr;
  *bucketptr -= n;
  return becomes_empty;
}

/**
 * Decrement the read token bucket in <b>bucket</b> by <b>n</b> bytes.
 *
 * Return true if the bucket was nonempty and became empty; return false
 * otherwise.
 */
int
token_bucket_dec_read(token_bucket_t *bucket,
                      ssize_t n)
{
  return decrement_single_bucket(&bucket->read_bucket, n);
}

/**
 * Decrement the write token bucket in <b>bucket</b> by <b>n</b> bytes.
 *
 * Return true if the bucket was nonempty and became empty; return false
 * otherwise.
 */
int
token_bucket_dec_write(token_bucket_t *bucket,
                       ssize_t n)
{
  return decrement_single_bucket(&bucket->write_bucket, n);
}

/**
 * As token_bucket_dec_read and token_bucket_dec_write, in a single operation.
 */
void
token_bucket_dec(token_bucket_t *bucket,
                 ssize_t n_read, ssize_t n_written)
{
  token_bucket_dec_read(bucket, n_read);
  token_bucket_dec_read(bucket, n_written);
}

