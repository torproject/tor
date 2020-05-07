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
STATIC void add_obs(bw_array_t *b, time_t when, uint64_t n);
STATIC void advance_obs(bw_array_t *b);
STATIC bw_array_t *bw_array_new(void);
STATIC void bw_array_free_(bw_array_t *b);
STATIC uint64_t find_largest_max(bw_array_t *b);
STATIC void bw_arrays_init(void);
STATIC void bw_arrays_free_all(void);
STATIC size_t
rep_hist_fill_bandwidth_history(char *buf, size_t len, const bw_array_t *b);

#define bw_array_free(val) \
  FREE_AND_NULL(bw_array_t, bw_array_free_, (val))

#endif /* !defined(BW_ARRAY_H). */
