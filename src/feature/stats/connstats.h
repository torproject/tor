/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file connstats.h
 * @brief Header for feature/stats/connstats.c
 **/

#ifndef TOR_FEATURE_STATS_CONNSTATS_H
#define TOR_FEATURE_STATS_CONNSTATS_H

void rep_hist_conn_stats_init(time_t now);
void rep_hist_note_or_conn_bytes(uint64_t conn_id, size_t num_read,
                                 size_t num_written, time_t when);
void rep_hist_reset_conn_stats(time_t now);
char *rep_hist_format_conn_stats(time_t now);
time_t rep_hist_conn_stats_write(time_t now);
void rep_hist_conn_stats_term(void);
void bidi_map_free_all(void);

#endif /* !defined(TOR_FEATURE_STATS_CONNSTATS_H) */
