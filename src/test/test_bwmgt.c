/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_bwmgt.c
 * \brief tests for bandwidth management / token bucket functions
 */

#define TOKEN_BUCKET_PRIVATE

#include "or.h"
#include "test.h"

#include "token_bucket.h"

// an imaginary time, in timestamp units. Chosen so it will roll over.
static const uint32_t START_TS = UINT32_MAX-10;
static const int32_t KB = 1024;

static void
test_bwmgt_token_buf_init(void *arg)
{
  (void)arg;
  token_bucket_t b;

  token_bucket_init(&b, 16*KB, 64*KB, START_TS);
  // Burst is correct
  tt_uint_op(b.burst, OP_EQ, 64*KB);
  // Rate is correct, within 1 percent.
  {
    uint32_t rate_per_sec = b.rate * (STAMP_TICKS_PER_SECOND / TICKS_PER_STEP);
    tt_uint_op(rate_per_sec, OP_GT, 16*KB-160);
    tt_uint_op(rate_per_sec, OP_LT, 16*KB+160);
  }
  // Bucket starts out full:
  tt_uint_op(b.last_refilled_at_ts, OP_EQ, START_TS);
  tt_int_op(b.read_bucket, OP_EQ, 64*KB);

 done:
  ;
}

static void
test_bwmgt_token_buf_adjust(void *arg)
{
  (void)arg;
  token_bucket_t b;

  token_bucket_init(&b, 16*KB, 64*KB, START_TS);

  uint32_t rate_orig = b.rate;
  // Increasing burst
  token_bucket_adjust(&b, 16*KB, 128*KB);
  tt_uint_op(b.rate, OP_EQ, rate_orig);
  tt_uint_op(b.read_bucket, OP_EQ, 64*KB);
  tt_uint_op(b.burst, OP_EQ, 128*KB);

  // Decreasing burst but staying above bucket
  token_bucket_adjust(&b, 16*KB, 96*KB);
  tt_uint_op(b.rate, OP_EQ, rate_orig);
  tt_uint_op(b.read_bucket, OP_EQ, 64*KB);
  tt_uint_op(b.burst, OP_EQ, 96*KB);

  // Decreasing burst below bucket,
  token_bucket_adjust(&b, 16*KB, 48*KB);
  tt_uint_op(b.rate, OP_EQ, rate_orig);
  tt_uint_op(b.read_bucket, OP_EQ, 48*KB);
  tt_uint_op(b.burst, OP_EQ, 48*KB);

  // Changing rate.
  token_bucket_adjust(&b, 32*KB, 48*KB);
  tt_uint_op(b.rate, OP_GE, rate_orig*2 - 10);
  tt_uint_op(b.rate, OP_LE, rate_orig*2 + 10);
  tt_uint_op(b.read_bucket, OP_EQ, 48*KB);
  tt_uint_op(b.burst, OP_EQ, 48*KB);

 done:
  ;
}

static void
test_bwmgt_token_buf_dec(void *arg)
{
  (void)arg;
  token_bucket_t b;
  token_bucket_init(&b, 16*KB, 64*KB, START_TS);

  // full-to-not-full.
  tt_int_op(0, OP_EQ, token_bucket_dec_read(&b, KB));
  tt_int_op(b.read_bucket, OP_EQ, 63*KB);

  // Full to almost-not-full
  tt_int_op(0, OP_EQ, token_bucket_dec_read(&b, 63*KB - 1));
  tt_int_op(b.read_bucket, OP_EQ, 1);

  // almost-not-full to empty.
  tt_int_op(1, OP_EQ, token_bucket_dec_read(&b, 1));
  tt_int_op(b.read_bucket, OP_EQ, 0);

  // reset bucket, try full-to-empty
  token_bucket_init(&b, 16*KB, 64*KB, START_TS);
  tt_int_op(1, OP_EQ, token_bucket_dec_read(&b, 64*KB));
  tt_int_op(b.read_bucket, OP_EQ, 0);

  // reset bucket, try underflow.
  token_bucket_init(&b, 16*KB, 64*KB, START_TS);
  tt_int_op(1, OP_EQ, token_bucket_dec_read(&b, 64*KB + 1));
  tt_int_op(b.read_bucket, OP_EQ, -1);

  // A second underflow does not make the bucket empty.
  tt_int_op(0, OP_EQ, token_bucket_dec_read(&b, 1000));
  tt_int_op(b.read_bucket, OP_EQ, -1001);

 done:
  ;
}

static void
test_bwmgt_token_buf_refill(void *arg)
{
  (void)arg;
  token_bucket_t b;
  const uint32_t SEC = STAMP_TICKS_PER_SECOND;
  token_bucket_init(&b, 16*KB, 64*KB, START_TS);

  /* Make the buffer much emptier, then let one second elapse. */
  token_bucket_dec_read(&b, 48*KB);
  tt_int_op(b.read_bucket, OP_EQ, 16*KB);
  tt_int_op(0, OP_EQ, token_bucket_refill(&b, START_TS + SEC));
  tt_int_op(b.read_bucket, OP_GT, 32*KB - 300);
  tt_int_op(b.read_bucket, OP_LT, 32*KB + 300);

  /* Another half second. */
  tt_int_op(0, OP_EQ, token_bucket_refill(&b, START_TS + SEC*3/2));
  tt_int_op(b.read_bucket, OP_GT, 40*KB - 400);
  tt_int_op(b.read_bucket, OP_LT, 40*KB + 400);
  tt_uint_op(b.last_refilled_at_ts, OP_EQ, START_TS + SEC*3/2);

  /* No time: nothing happens. */
  {
    const uint32_t bucket_orig = b.read_bucket;
    tt_int_op(0, OP_EQ, token_bucket_refill(&b, START_TS + SEC*3/2));
    tt_int_op(b.read_bucket, OP_EQ, bucket_orig);
  }

  /* Another 30 seconds: fill the bucket. */
  tt_int_op(0, OP_EQ, token_bucket_refill(&b, START_TS + SEC*3/2 + SEC*30));
  tt_int_op(b.read_bucket, OP_EQ, b.burst);
  tt_uint_op(b.last_refilled_at_ts, OP_EQ, START_TS + SEC*3/2 + SEC*30);

  /* Another 30 seconds: nothing happens. */
  tt_int_op(0, OP_EQ, token_bucket_refill(&b, START_TS + SEC*3/2 + SEC*60));
  tt_int_op(b.read_bucket, OP_EQ, b.burst);
  tt_uint_op(b.last_refilled_at_ts, OP_EQ, START_TS + SEC*3/2 + SEC*60);

  /* Empty the bucket, let two seconds pass, and make sure that a refill is
   * noticed. */
  tt_int_op(1, OP_EQ, token_bucket_dec_read(&b, b.burst));
  tt_int_op(0, OP_EQ, b.read_bucket);
  tt_int_op(1, OP_EQ, token_bucket_refill(&b, START_TS + SEC*3/2 + SEC*61));
  tt_int_op(0, OP_EQ, token_bucket_refill(&b, START_TS + SEC*3/2 + SEC*62));
  tt_int_op(b.read_bucket, OP_GT, 32*KB-300);
  tt_int_op(b.read_bucket, OP_LT, 32*KB+300);

  /* Underflow the bucket, make sure we detect when it has tokens again. */
  tt_int_op(1, OP_EQ, token_bucket_dec_read(&b, b.read_bucket+16*KB));
  tt_int_op(-16*KB, OP_EQ, b.read_bucket);
  // half a second passes...
  tt_int_op(0, OP_EQ, token_bucket_refill(&b, START_TS + SEC*64));
  tt_int_op(b.read_bucket, OP_GT, -8*KB-200);
  tt_int_op(b.read_bucket, OP_LT, -8*KB+200);
  // a second passes
  tt_int_op(1, OP_EQ, token_bucket_refill(&b, START_TS + SEC*65));
  tt_int_op(b.read_bucket, OP_GT, 8*KB-200);
  tt_int_op(b.read_bucket, OP_LT, 8*KB+200);

  // a ridiculous amount of time passes
  tt_int_op(0, OP_EQ, token_bucket_refill(&b, START_TS + SEC*64));
  tt_int_op(b.read_bucket, OP_EQ, b.burst);

 done:
  ;
}

#define BWMGT(name)                                          \
  { #name, test_bwmgt_ ## name , 0, NULL, NULL }

struct testcase_t bwmgt_tests[] = {
  BWMGT(token_buf_init),
  BWMGT(token_buf_adjust),
  BWMGT(token_buf_dec),
  BWMGT(token_buf_refill),
  END_OF_TESTCASES
};

