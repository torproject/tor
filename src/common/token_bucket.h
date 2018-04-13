/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file token_bucket_rw.h
 * \brief Headers for token_bucket_rw.c
 **/

#ifndef TOR_TOKEN_BUCKET_H
#define TOR_TOKEN_BUCKET_H

#include "torint.h"

typedef struct token_bucket_rw_t {
  uint32_t rate;
  int32_t burst;
  int32_t read_bucket;
  int32_t write_bucket;
  uint32_t last_refilled_at_ts;
} token_bucket_rw_t;

#define TOKEN_BUCKET_RW_MAX_BURST INT32_MAX

void token_bucket_rw_init(token_bucket_rw_t *bucket,
                       uint32_t rate,
                       uint32_t burst,
                       uint32_t now_ts);

void token_bucket_rw_adjust(token_bucket_rw_t *bucket,
                         uint32_t rate, uint32_t burst);

void token_bucket_rw_reset(token_bucket_rw_t *bucket,
                        uint32_t now_ts);

#define TB_READ 1
#define TB_WRITE 2

int token_bucket_rw_refill(token_bucket_rw_t *bucket,
                        uint32_t now_ts);

int token_bucket_rw_dec_read(token_bucket_rw_t *bucket,
                          ssize_t n);
int token_bucket_rw_dec_write(token_bucket_rw_t *bucket,
                           ssize_t n);

void token_bucket_rw_dec(token_bucket_rw_t *bucket,
                      ssize_t n_read, ssize_t n_written);

static inline size_t token_bucket_rw_get_read(const token_bucket_rw_t *bucket);
static inline size_t
token_bucket_rw_get_read(const token_bucket_rw_t *bucket)
{
  const ssize_t b = bucket->read_bucket;
  return b >= 0 ? b : 0;
}

static inline size_t token_bucket_rw_get_write(
                                            const token_bucket_rw_t *bucket);
static inline size_t
token_bucket_rw_get_write(const token_bucket_rw_t *bucket)
{
  const ssize_t b = bucket->write_bucket;
  return b >= 0 ? b : 0;
}

#ifdef TOKEN_BUCKET_PRIVATE

/* To avoid making the rates too small, we consider units of "steps",
 * where a "step" is defined as this many timestamp ticks.  Keep this
 * a power of two if you can. */
#define TICKS_PER_STEP 16

#endif

#endif /* TOR_TOKEN_BUCKET_H */

