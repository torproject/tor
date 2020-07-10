/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file bwhist.h
 * @brief Header for feature/stats/bwhist.c
 **/

#ifndef TOR_FEATURE_STATS_BWHIST_H
#define TOR_FEATURE_STATS_BWHIST_H

void bwhist_init(void);
void bwhist_free_all(void);

void bwhist_note_bytes_read(uint64_t num_bytes, time_t when);
void bwhist_note_bytes_written(uint64_t num_bytes, time_t when);
void bwhist_note_dir_bytes_read(uint64_t num_bytes, time_t when);
void bwhist_note_dir_bytes_written(uint64_t num_bytes, time_t when);

MOCK_DECL(int, bwhist_bandwidth_assess, (void));
char *bwhist_get_bandwidth_lines(void);
struct or_state_t;
void bwhist_update_state(struct or_state_t *state);
int bwhist_load_state(struct or_state_t *state, char **err);

#ifdef BWHIST_PRIVATE
typedef struct bw_array_t bw_array_t;
STATIC uint64_t find_largest_max(bw_array_t *b);
STATIC void commit_max(bw_array_t *b);
STATIC void advance_obs(bw_array_t *b);
#endif /* defined(REPHIST_PRIVATE) */

#ifdef TOR_UNIT_TESTS
extern struct bw_array_t *write_array;
#endif

#endif /* !defined(TOR_FEATURE_STATS_BWHIST_H) */
