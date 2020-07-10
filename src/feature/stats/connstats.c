/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file connstats.c
 * @brief Count bidirectional vs one-way connections.
 *
 * Connection statistics, used by relays to count connections, and track
 * one-way and bidirectional connections.
 **/

#include "orconfig.h"
#include "core/or/or.h"
#include "feature/stats/connstats.h"
#include "app/config/config.h"

/** Start of the current connection stats interval or 0 if we're not
 * collecting connection statistics. */
static time_t start_of_conn_stats_interval;

/** Initialize connection stats. */
void
rep_hist_conn_stats_init(time_t now)
{
  start_of_conn_stats_interval = now;
}

/* Count connections that we read and wrote less than these many bytes
 * from/to as below threshold. */
#define BIDI_THRESHOLD 20480

/* Count connections that we read or wrote at least this factor as many
 * bytes from/to than we wrote or read to/from as mostly reading or
 * writing. */
#define BIDI_FACTOR 10

/* Interval length in seconds for considering read and written bytes for
 * connection stats. */
#define BIDI_INTERVAL 10

/** Start of next BIDI_INTERVAL second interval. */
static time_t bidi_next_interval = 0;

/** Number of connections that we read and wrote less than BIDI_THRESHOLD
 * bytes from/to in BIDI_INTERVAL seconds. */
static uint32_t below_threshold = 0;

/** Number of connections that we read at least BIDI_FACTOR times more
 * bytes from than we wrote to in BIDI_INTERVAL seconds. */
static uint32_t mostly_read = 0;

/** Number of connections that we wrote at least BIDI_FACTOR times more
 * bytes to than we read from in BIDI_INTERVAL seconds. */
static uint32_t mostly_written = 0;

/** Number of connections that we read and wrote at least BIDI_THRESHOLD
 * bytes from/to, but not BIDI_FACTOR times more in either direction in
 * BIDI_INTERVAL seconds. */
static uint32_t both_read_and_written = 0;

/** Entry in a map from connection ID to the number of read and written
 * bytes on this connection in a BIDI_INTERVAL second interval. */
typedef struct bidi_map_entry_t {
  HT_ENTRY(bidi_map_entry_t) node;
  uint64_t conn_id; /**< Connection ID */
  size_t read; /**< Number of read bytes */
  size_t written; /**< Number of written bytes */
} bidi_map_entry_t;

/** Map of OR connections together with the number of read and written
 * bytes in the current BIDI_INTERVAL second interval. */
static HT_HEAD(bidimap, bidi_map_entry_t) bidi_map =
     HT_INITIALIZER();

static int
bidi_map_ent_eq(const bidi_map_entry_t *a, const bidi_map_entry_t *b)
{
  return a->conn_id == b->conn_id;
}

/* DOCDOC bidi_map_ent_hash */
static unsigned
bidi_map_ent_hash(const bidi_map_entry_t *entry)
{
  return (unsigned) entry->conn_id;
}

HT_PROTOTYPE(bidimap, bidi_map_entry_t, node, bidi_map_ent_hash,
             bidi_map_ent_eq);
HT_GENERATE2(bidimap, bidi_map_entry_t, node, bidi_map_ent_hash,
             bidi_map_ent_eq, 0.6, tor_reallocarray_, tor_free_);

/** Release all storage held in connstats.c */
void
bidi_map_free_all(void)
{
  bidi_map_entry_t **ptr, **next, *ent;
  for (ptr = HT_START(bidimap, &bidi_map); ptr; ptr = next) {
    ent = *ptr;
    next = HT_NEXT_RMV(bidimap, &bidi_map, ptr);
    tor_free(ent);
  }
  HT_CLEAR(bidimap, &bidi_map);
}

/** Reset counters for conn statistics. */
void
rep_hist_reset_conn_stats(time_t now)
{
  start_of_conn_stats_interval = now;
  below_threshold = 0;
  mostly_read = 0;
  mostly_written = 0;
  both_read_and_written = 0;
  bidi_map_free_all();
}

/** Stop collecting connection stats in a way that we can re-start doing
 * so in rep_hist_conn_stats_init(). */
void
rep_hist_conn_stats_term(void)
{
  rep_hist_reset_conn_stats(0);
}

/** We read <b>num_read</b> bytes and wrote <b>num_written</b> from/to OR
 * connection <b>conn_id</b> in second <b>when</b>. If this is the first
 * observation in a new interval, sum up the last observations. Add bytes
 * for this connection. */
void
rep_hist_note_or_conn_bytes(uint64_t conn_id, size_t num_read,
                            size_t num_written, time_t when)
{
  if (!start_of_conn_stats_interval)
    return;
  /* Initialize */
  if (bidi_next_interval == 0)
    bidi_next_interval = when + BIDI_INTERVAL;
  /* Sum up last period's statistics */
  if (when >= bidi_next_interval) {
    bidi_map_entry_t **ptr, **next, *ent;
    for (ptr = HT_START(bidimap, &bidi_map); ptr; ptr = next) {
      ent = *ptr;
      if (ent->read + ent->written < BIDI_THRESHOLD)
        below_threshold++;
      else if (ent->read >= ent->written * BIDI_FACTOR)
        mostly_read++;
      else if (ent->written >= ent->read * BIDI_FACTOR)
        mostly_written++;
      else
        both_read_and_written++;
      next = HT_NEXT_RMV(bidimap, &bidi_map, ptr);
      tor_free(ent);
    }
    while (when >= bidi_next_interval)
      bidi_next_interval += BIDI_INTERVAL;
    log_info(LD_GENERAL, "%d below threshold, %d mostly read, "
             "%d mostly written, %d both read and written.",
             below_threshold, mostly_read, mostly_written,
             both_read_and_written);
  }
  /* Add this connection's bytes. */
  if (num_read > 0 || num_written > 0) {
    bidi_map_entry_t *entry, lookup;
    lookup.conn_id = conn_id;
    entry = HT_FIND(bidimap, &bidi_map, &lookup);
    if (entry) {
      entry->written += num_written;
      entry->read += num_read;
    } else {
      entry = tor_malloc_zero(sizeof(bidi_map_entry_t));
      entry->conn_id = conn_id;
      entry->written = num_written;
      entry->read = num_read;
      HT_INSERT(bidimap, &bidi_map, entry);
    }
  }
}

/** Return a newly allocated string containing the connection statistics
 * until <b>now</b>, or NULL if we're not collecting conn stats. Caller must
 * ensure start_of_conn_stats_interval is in the past. */
char *
rep_hist_format_conn_stats(time_t now)
{
  char *result, written[ISO_TIME_LEN+1];

  if (!start_of_conn_stats_interval)
    return NULL; /* Not initialized. */

  tor_assert(now >= start_of_conn_stats_interval);

  format_iso_time(written, now);
  tor_asprintf(&result, "conn-bi-direct %s (%d s) %d,%d,%d,%d\n",
               written,
               (unsigned) (now - start_of_conn_stats_interval),
               below_threshold,
               mostly_read,
               mostly_written,
               both_read_and_written);
  return result;
}

/** If 24 hours have passed since the beginning of the current conn stats
 * period, write conn stats to $DATADIR/stats/conn-stats (possibly
 * overwriting an existing file) and reset counters.  Return when we would
 * next want to write conn stats or 0 if we never want to write. */
time_t
rep_hist_conn_stats_write(time_t now)
{
  char *str = NULL;

  if (!start_of_conn_stats_interval)
    return 0; /* Not initialized. */
  if (start_of_conn_stats_interval + WRITE_STATS_INTERVAL > now)
    goto done; /* Not ready to write */

  /* Generate history string. */
  str = rep_hist_format_conn_stats(now);

  /* Reset counters. */
  rep_hist_reset_conn_stats(now);

  /* Try to write to disk. */
  if (!check_or_create_data_subdir("stats")) {
    write_to_data_subdir("stats", "conn-stats", str, "connection statistics");
  }

 done:
  tor_free(str);
  return start_of_conn_stats_interval + WRITE_STATS_INTERVAL;
}