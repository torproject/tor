/* Copyright (c) 2007-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file bw_array_st.h
 * @brief Bandwidth array manipulation functions.
 **/

#ifndef BW_ARRAY_H
#define BW_ARRAY_H

#include "feature/stats/bw_array_st.h"

STATIC void commit_max(bw_array_t *b);
STATIC void advance_obs(bw_array_t *b);
STATIC bw_array_t *bw_array_new(void);
STATIC void bw_array_free_(bw_array_t *b);
STATIC uint64_t find_largest_max(bw_array_t *b);
STATIC void bw_arrays_init(void);
STATIC void bw_arrays_free_all(void);
STATIC size_t
rep_hist_fill_bandwidth_history(char *buf, size_t len, const bw_array_t *b);

/** Add <b>n</b> bytes to the number of bytes in <b>b</b> for second
 * <b>when</b>. */
STATIC inline void
add_obs(bw_array_t *b, time_t when, uint64_t n)
{
  if (when < b->cur_obs_time)
    return; /* Don't record data in the past. */

  /* If we're currently adding observations for an earlier second than
   * 'when', advance b->cur_obs_time and b->cur_obs_idx by an
   * appropriate number of seconds, and do all the other housekeeping. */
  while (when > b->cur_obs_time) {
    /* Doing this one second at a time is potentially inefficient, if we start
       with a state file that is very old.  Fortunately, it doesn't seem to
       show up in profiles, so we can just ignore it for now. */
    advance_obs(b);
  }

  b->obs[b->cur_obs_idx] += n;
  b->total_in_period += n;
}

#define bw_array_free(val) \
  FREE_AND_NULL(bw_array_t, bw_array_free_, (val))

#endif /* !defined(BW_ARRAY_H). */
