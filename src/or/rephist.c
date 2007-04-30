/* Copyright 2004-2007 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char rephist_c_id[] =
  "$Id$";

/**
 * \file rephist.c
 * \brief Basic history and "reputation" functionality to remember
 *    which servers have worked in the past, how much bandwidth we've
 *    been using, which ports we tend to want, and so on.
 **/

#include "or.h"

static void bw_arrays_init(void);
static void predicted_ports_init(void);
static void hs_usage_init(void);

uint64_t rephist_total_alloc=0;
uint32_t rephist_total_num=0;

/** History of an OR-\>OR link. */
typedef struct link_history_t {
  /** When did we start tracking this list? */
  time_t since;
  /** When did we most recently note a change to this link */
  time_t changed;
  /** How many times did extending from OR1 to OR2 succeed? */
  unsigned long n_extend_ok;
  /** How many times did extending from OR1 to OR2 fail? */
  unsigned long n_extend_fail;
} link_history_t;

/** History of an OR. */
typedef struct or_history_t {
  /** When did we start tracking this OR? */
  time_t since;
  /** When did we most recently note a change to this OR? */
  time_t changed;
  /** How many times did we successfully connect? */
  unsigned long n_conn_ok;
  /** How many times did we try to connect and fail?*/
  unsigned long n_conn_fail;
  /** How many seconds have we been connected to this OR before
   * 'up_since'? */
  unsigned long uptime;
  /** How many seconds have we been unable to connect to this OR before
   * 'down_since'? */
  unsigned long downtime;
  /** If nonzero, we have been connected since this time. */
  time_t up_since;
  /** If nonzero, we have been unable to connect since this time. */
  time_t down_since;
  /** Map from hex OR2 identity digest to a link_history_t for the link
   * from this OR to OR2. */
  digestmap_t *link_history_map;
} or_history_t;

/** Map from hex OR identity digest to or_history_t. */
static digestmap_t *history_map = NULL;

/** Return the or_history_t for the named OR, creating it if necessary. */
static or_history_t *
get_or_history(const char* id)
{
  or_history_t *hist;

  if (tor_mem_is_zero(id, DIGEST_LEN))
    return NULL;

  hist = digestmap_get(history_map, id);
  if (!hist) {
    hist = tor_malloc_zero(sizeof(or_history_t));
    rephist_total_alloc += sizeof(or_history_t);
    rephist_total_num++;
    hist->link_history_map = digestmap_new();
    hist->since = hist->changed = time(NULL);
    digestmap_set(history_map, id, hist);
  }
  return hist;
}

/** Return the link_history_t for the link from the first named OR to
 * the second, creating it if necessary. (ORs are identified by
 * identity digest.)
 */
static link_history_t *
get_link_history(const char *from_id, const char *to_id)
{
  or_history_t *orhist;
  link_history_t *lhist;
  orhist = get_or_history(from_id);
  if (!orhist)
    return NULL;
  if (tor_mem_is_zero(to_id, DIGEST_LEN))
    return NULL;
  lhist = (link_history_t*) digestmap_get(orhist->link_history_map, to_id);
  if (!lhist) {
    lhist = tor_malloc_zero(sizeof(link_history_t));
    rephist_total_alloc += sizeof(link_history_t);
    lhist->since = lhist->changed = time(NULL);
    digestmap_set(orhist->link_history_map, to_id, lhist);
  }
  return lhist;
}

/** Helper: free storage held by a single link history entry. */
static void
_free_link_history(void *val)
{
  rephist_total_alloc -= sizeof(link_history_t);
  tor_free(val);
}

/** Helper: free storage held by a single OR history entry. */
static void
free_or_history(void *_hist)
{
  or_history_t *hist = _hist;
  digestmap_free(hist->link_history_map, _free_link_history);
  rephist_total_alloc -= sizeof(or_history_t);
  rephist_total_num--;
  tor_free(hist);
}

/** Update an or_history_t object <b>hist</b> so that its uptime/downtime
 * count is up-to-date as of <b>when</b>.
 */
static void
update_or_history(or_history_t *hist, time_t when)
{
  tor_assert(hist);
  if (hist->up_since) {
    tor_assert(!hist->down_since);
    hist->uptime += (when - hist->up_since);
    hist->up_since = when;
  } else if (hist->down_since) {
    hist->downtime += (when - hist->down_since);
    hist->down_since = when;
  }
}

/** Initialize the static data structures for tracking history. */
void
rep_hist_init(void)
{
  history_map = digestmap_new();
  bw_arrays_init();
  predicted_ports_init();
  hs_usage_init();
}

/** Remember that an attempt to connect to the OR with identity digest
 * <b>id</b> failed at <b>when</b>.
 */
void
rep_hist_note_connect_failed(const char* id, time_t when)
{
  or_history_t *hist;
  hist = get_or_history(id);
  if (!hist)
    return;
  ++hist->n_conn_fail;
  if (hist->up_since) {
    hist->uptime += (when - hist->up_since);
    hist->up_since = 0;
  }
  if (!hist->down_since)
    hist->down_since = when;
  hist->changed = when;
}

/** Remember that an attempt to connect to the OR with identity digest
 * <b>id</b> succeeded at <b>when</b>.
 */
void
rep_hist_note_connect_succeeded(const char* id, time_t when)
{
  or_history_t *hist;
  hist = get_or_history(id);
  if (!hist)
    return;
  ++hist->n_conn_ok;
  if (hist->down_since) {
    hist->downtime += (when - hist->down_since);
    hist->down_since = 0;
  }
  if (!hist->up_since)
    hist->up_since = when;
  hist->changed = when;
}

/** Remember that we intentionally closed our connection to the OR
 * with identity digest <b>id</b> at <b>when</b>.
 */
void
rep_hist_note_disconnect(const char* id, time_t when)
{
  or_history_t *hist;
  hist = get_or_history(id);
  if (!hist)
    return;
  ++hist->n_conn_ok;
  if (hist->up_since) {
    hist->uptime += (when - hist->up_since);
    hist->up_since = 0;
  }
  hist->changed = when;
}

/** Remember that our connection to the OR with identity digest
 * <b>id</b> had an error and stopped working at <b>when</b>.
 */
void
rep_hist_note_connection_died(const char* id, time_t when)
{
  or_history_t *hist;
  if (!id) {
    /* If conn has no nickname, it didn't complete its handshake, or something
     * went wrong.  Ignore it.
     */
    return;
  }
  hist = get_or_history(id);
  if (!hist)
    return;
  if (hist->up_since) {
    hist->uptime += (when - hist->up_since);
    hist->up_since = 0;
  }
  if (!hist->down_since)
    hist->down_since = when;
  hist->changed = when;
}

/** Remember that we successfully extended from the OR with identity
 * digest <b>from_id</b> to the OR with identity digest
 * <b>to_name</b>.
 */
void
rep_hist_note_extend_succeeded(const char *from_id, const char *to_id)
{
  link_history_t *hist;
  /* log_fn(LOG_WARN, "EXTEND SUCCEEDED: %s->%s",from_name,to_name); */
  hist = get_link_history(from_id, to_id);
  if (!hist)
    return;
  ++hist->n_extend_ok;
  hist->changed = time(NULL);
}

/** Remember that we tried to extend from the OR with identity digest
 * <b>from_id</b> to the OR with identity digest <b>to_name</b>, but
 * failed.
 */
void
rep_hist_note_extend_failed(const char *from_id, const char *to_id)
{
  link_history_t *hist;
  /* log_fn(LOG_WARN, "EXTEND FAILED: %s->%s",from_name,to_name); */
  hist = get_link_history(from_id, to_id);
  if (!hist)
    return;
  ++hist->n_extend_fail;
  hist->changed = time(NULL);
}

/** Log all the reliability data we have remembered, with the chosen
 * severity.
 */
void
rep_hist_dump_stats(time_t now, int severity)
{
  digestmap_iter_t *lhist_it;
  digestmap_iter_t *orhist_it;
  const char *name1, *name2, *digest1, *digest2;
  char hexdigest1[HEX_DIGEST_LEN+1];
  or_history_t *or_history;
  link_history_t *link_history;
  void *or_history_p, *link_history_p;
  double uptime;
  char buffer[2048];
  size_t len;
  int ret;
  unsigned long upt, downt;
  routerinfo_t *r;

  rep_history_clean(now - get_options()->RephistTrackTime);

  log(severity, LD_GENERAL, "--------------- Dumping history information:");

  for (orhist_it = digestmap_iter_init(history_map);
       !digestmap_iter_done(orhist_it);
       orhist_it = digestmap_iter_next(history_map,orhist_it)) {
    digestmap_iter_get(orhist_it, &digest1, &or_history_p);
    or_history = (or_history_t*) or_history_p;

    if ((r = router_get_by_digest(digest1)))
      name1 = r->nickname;
    else
      name1 = "(unknown)";
    base16_encode(hexdigest1, sizeof(hexdigest1), digest1, DIGEST_LEN);
    update_or_history(or_history, now);
    upt = or_history->uptime;
    downt = or_history->downtime;
    if (upt+downt) {
      uptime = ((double)upt) / (upt+downt);
    } else {
      uptime=1.0;
    }
    log(severity, LD_GENERAL,
        "OR %s [%s]: %ld/%ld good connections; uptime %ld/%ld sec (%.2f%%)",
        name1, hexdigest1,
        or_history->n_conn_ok, or_history->n_conn_fail+or_history->n_conn_ok,
        upt, upt+downt, uptime*100.0);

    if (!digestmap_isempty(or_history->link_history_map)) {
      strlcpy(buffer, "    Extend attempts: ", sizeof(buffer));
      len = strlen(buffer);
      for (lhist_it = digestmap_iter_init(or_history->link_history_map);
           !digestmap_iter_done(lhist_it);
           lhist_it = digestmap_iter_next(or_history->link_history_map,
                                          lhist_it)) {
        digestmap_iter_get(lhist_it, &digest2, &link_history_p);
        if ((r = router_get_by_digest(digest2)))
          name2 = r->nickname;
        else
          name2 = "(unknown)";

        link_history = (link_history_t*) link_history_p;

        ret = tor_snprintf(buffer+len, 2048-len, "%s(%ld/%ld); ", name2,
                        link_history->n_extend_ok,
                        link_history->n_extend_ok+link_history->n_extend_fail);
        if (ret<0)
          break;
        else
          len += ret;
      }
      log(severity, LD_GENERAL, "%s", buffer);
    }
  }
}

/** Remove history info for routers/links that haven't changed since
 * <b>before</b>.
 */
void
rep_history_clean(time_t before)
{
  or_history_t *or_history;
  link_history_t *link_history;
  void *or_history_p, *link_history_p;
  digestmap_iter_t *orhist_it, *lhist_it;
  const char *d1, *d2;

  orhist_it = digestmap_iter_init(history_map);
  while (!digestmap_iter_done(orhist_it)) {
    digestmap_iter_get(orhist_it, &d1, &or_history_p);
    or_history = or_history_p;
    if (or_history->changed < before) {
      orhist_it = digestmap_iter_next_rmv(history_map, orhist_it);
      free_or_history(or_history);
      continue;
    }
    for (lhist_it = digestmap_iter_init(or_history->link_history_map);
         !digestmap_iter_done(lhist_it); ) {
      digestmap_iter_get(lhist_it, &d2, &link_history_p);
      link_history = link_history_p;
      if (link_history->changed < before) {
        lhist_it = digestmap_iter_next_rmv(or_history->link_history_map,
                                           lhist_it);
        rephist_total_alloc -= sizeof(link_history_t);
        tor_free(link_history);
        continue;
      }
      lhist_it = digestmap_iter_next(or_history->link_history_map,lhist_it);
    }
    orhist_it = digestmap_iter_next(history_map, orhist_it);
  }
}

/** For how many seconds do we keep track of individual per-second bandwidth
 * totals? */
#define NUM_SECS_ROLLING_MEASURE 10
/** How large are the intervals for which we track and report bandwidth use? */
#define NUM_SECS_BW_SUM_INTERVAL (15*60)
/** How far in the past do we remember and publish bandwidth use? */
#define NUM_SECS_BW_SUM_IS_VALID (24*60*60)
/** How many bandwidth usage intervals do we remember? (derived) */
#define NUM_TOTALS (NUM_SECS_BW_SUM_IS_VALID/NUM_SECS_BW_SUM_INTERVAL)

/** Structure to track bandwidth use, and remember the maxima for a given
 * time period.
 */
typedef struct bw_array_t {
  /** Observation array: Total number of bytes transferred in each of the last
   * NUM_SECS_ROLLING_MEASURE seconds. This is used as a circular array. */
  uint64_t obs[NUM_SECS_ROLLING_MEASURE];
  int cur_obs_idx; /**< Current position in obs. */
  time_t cur_obs_time; /**< Time represented in obs[cur_obs_idx] */
  uint64_t total_obs; /**< Total for all members of obs except
                       * obs[cur_obs_idx] */
  uint64_t max_total; /**< Largest value that total_obs has taken on in the
                       * current period. */
  uint64_t total_in_period; /**< Total bytes transferred in the current
                             * period. */

  /** When does the next period begin? */
  time_t next_period;
  /** Where in 'maxima' should the maximum bandwidth usage for the current
   * period be stored? */
  int next_max_idx;
  /** How many values in maxima/totals have been set ever? */
  int num_maxes_set;
  /** Circular array of the maximum
   * bandwidth-per-NUM_SECS_ROLLING_MEASURE usage for the last
   * NUM_TOTALS periods */
  uint64_t maxima[NUM_TOTALS];
  /** Circular array of the total bandwidth usage for the last NUM_TOTALS
   * periods */
  uint64_t totals[NUM_TOTALS];
} bw_array_t;

/** Shift the current period of b forward by one. */
static void
commit_max(bw_array_t *b)
{
  /* Store total from current period. */
  b->totals[b->next_max_idx] = b->total_in_period;
  /* Store maximum from current period. */
  b->maxima[b->next_max_idx++] = b->max_total;
  /* Advance next_period and next_max_idx */
  b->next_period += NUM_SECS_BW_SUM_INTERVAL;
  if (b->next_max_idx == NUM_TOTALS)
    b->next_max_idx = 0;
  if (b->num_maxes_set < NUM_TOTALS)
    ++b->num_maxes_set;
  /* Reset max_total. */
  b->max_total = 0;
  /* Reset total_in_period. */
  b->total_in_period = 0;
}

/** Shift the current observation time of 'b' forward by one second. */
static INLINE void
advance_obs(bw_array_t *b)
{
  int nextidx;
  uint64_t total;

  /* Calculate the total bandwidth for the last NUM_SECS_ROLLING_MEASURE
   * seconds; adjust max_total as needed.*/
  total = b->total_obs + b->obs[b->cur_obs_idx];
  if (total > b->max_total)
    b->max_total = total;

  nextidx = b->cur_obs_idx+1;
  if (nextidx == NUM_SECS_ROLLING_MEASURE)
    nextidx = 0;

  b->total_obs = total - b->obs[nextidx];
  b->obs[nextidx]=0;
  b->cur_obs_idx = nextidx;

  if (++b->cur_obs_time >= b->next_period)
    commit_max(b);
}

/** Add 'n' bytes to the number of bytes in b for second 'when'. */
static INLINE void
add_obs(bw_array_t *b, time_t when, uint64_t n)
{
  /* Don't record data in the past. */
  if (when<b->cur_obs_time)
    return;
  /* If we're currently adding observations for an earlier second than
   * 'when', advance b->cur_obs_time and b->cur_obs_idx by an
   * appropriate number of seconds, and do all the other housekeeping */
  while (when>b->cur_obs_time)
    advance_obs(b);

  b->obs[b->cur_obs_idx] += n;
  b->total_in_period += n;
}

/** Allocate, initialize, and return a new bw_array. */
static bw_array_t *
bw_array_new(void)
{
  bw_array_t *b;
  time_t start;
  b = tor_malloc_zero(sizeof(bw_array_t));
  rephist_total_alloc += sizeof(bw_array_t);
  start = time(NULL);
  b->cur_obs_time = start;
  b->next_period = start + NUM_SECS_BW_SUM_INTERVAL;
  return b;
}

static bw_array_t *read_array = NULL;
static bw_array_t *write_array = NULL;

/** Set up read_array and write_array. */
static void
bw_arrays_init(void)
{
  read_array = bw_array_new();
  write_array = bw_array_new();
}

/** We read <b>num_bytes</b> more bytes in second <b>when</b>.
 *
 * Add num_bytes to the current running total for <b>when</b>.
 *
 * <b>when</b> can go back to time, but it's safe to ignore calls
 * earlier than the latest <b>when</b> you've heard of.
 */
void
rep_hist_note_bytes_written(int num_bytes, time_t when)
{
/* Maybe a circular array for recent seconds, and step to a new point
 * every time a new second shows up. Or simpler is to just to have
 * a normal array and push down each item every second; it's short.
 */
/* When a new second has rolled over, compute the sum of the bytes we've
 * seen over when-1 to when-1-NUM_SECS_ROLLING_MEASURE, and stick it
 * somewhere. See rep_hist_bandwidth_assess() below.
 */
  add_obs(write_array, when, num_bytes);
}

/** We wrote <b>num_bytes</b> more bytes in second <b>when</b>.
 * (like rep_hist_note_bytes_written() above)
 */
void
rep_hist_note_bytes_read(int num_bytes, time_t when)
{
/* if we're smart, we can make this func and the one above share code */
  add_obs(read_array, when, num_bytes);
}

/** Helper: Return the largest value in b->maxima.  (This is equal to the
 * most bandwidth used in any NUM_SECS_ROLLING_MEASURE period for the last
 * NUM_SECS_BW_SUM_IS_VALID seconds.)
 */
static uint64_t
find_largest_max(bw_array_t *b)
{
  int i;
  uint64_t max;
  max=0;
  for (i=0; i<NUM_TOTALS; ++i) {
    if (b->maxima[i]>max)
      max = b->maxima[i];
  }
  return max;
}

/** Find the largest sums in the past NUM_SECS_BW_SUM_IS_VALID (roughly)
 * seconds. Find one sum for reading and one for writing. They don't have
 * to be at the same time).
 *
 * Return the smaller of these sums, divided by NUM_SECS_ROLLING_MEASURE.
 */
int
rep_hist_bandwidth_assess(void)
{
  uint64_t w,r;
  r = find_largest_max(read_array);
  w = find_largest_max(write_array);
  if (r>w)
    return (int)(U64_TO_DBL(w)/NUM_SECS_ROLLING_MEASURE);
  else
    return (int)(U64_TO_DBL(r)/NUM_SECS_ROLLING_MEASURE);
}

/** Print the bandwidth history of b (either read_array or write_array)
 * into the buffer pointed to by buf.  The format is simply comma
 * separated numbers, from oldest to newest.
 *
 * It returns the number of bytes written.
 */
static size_t
rep_hist_fill_bandwidth_history(char *buf, size_t len, bw_array_t *b)
{
  char *cp = buf;
  int i, n;

  if (b->num_maxes_set <= b->next_max_idx) {
    /* We haven't been through the circular array yet; time starts at i=0.*/
    i = 0;
  } else {
    /* We've been around the array at least once.  The next i to be
       overwritten is the oldest. */
    i = b->next_max_idx;
  }

  for (n=0; n<b->num_maxes_set; ++n,++i) {
    uint64_t total;
    while (i >= NUM_TOTALS) i -= NUM_TOTALS;
    /* Round the bandwidth used down to the nearest 1k. */
    total = b->totals[i] & ~0x3ff;
    if (n==(b->num_maxes_set-1))
      tor_snprintf(cp, len-(cp-buf), U64_FORMAT, U64_PRINTF_ARG(total));
    else
      tor_snprintf(cp, len-(cp-buf), U64_FORMAT",", U64_PRINTF_ARG(total));
    cp += strlen(cp);
  }
  return cp-buf;
}

/** Allocate and return lines for representing this server's bandwidth
 * history in its descriptor.
 */
char *
rep_hist_get_bandwidth_lines(int for_extrainfo)
{
  char *buf, *cp;
  char t[ISO_TIME_LEN+1];
  int r;
  bw_array_t *b;
  size_t len;

  /* opt (read|write)-history yyyy-mm-dd HH:MM:SS (n s) n,n,n,n,n... */
  len = (60+20*NUM_TOTALS)*2;
  buf = tor_malloc_zero(len);
  cp = buf;
  for (r=0;r<2;++r) {
    b = r?read_array:write_array;
    tor_assert(b);
    format_iso_time(t, b->next_period-NUM_SECS_BW_SUM_INTERVAL);
    tor_snprintf(cp, len-(cp-buf), "%s%s %s (%d s) ",
                 for_extrainfo ? "" : "opt ",
                 r ? "read-history" : "write-history", t,
                 NUM_SECS_BW_SUM_INTERVAL);
    cp += strlen(cp);
    cp += rep_hist_fill_bandwidth_history(cp, len-(cp-buf), b);
    strlcat(cp, "\n", len-(cp-buf));
    ++cp;
  }
  return buf;
}

/** Update <b>state</b> with the newest bandwidth history. */
void
rep_hist_update_state(or_state_t *state)
{
  int len, r;
  char *buf, *cp;
  smartlist_t **s_values;
  time_t *s_begins;
  int *s_interval;
  bw_array_t *b;

  len = 20*NUM_TOTALS+1;
  buf = tor_malloc_zero(len);

  for (r=0;r<2;++r) {
    b = r?read_array:write_array;
    s_begins  = r?&state->BWHistoryReadEnds    :&state->BWHistoryWriteEnds;
    s_interval= r?&state->BWHistoryReadInterval:&state->BWHistoryWriteInterval;
    s_values  = r?&state->BWHistoryReadValues  :&state->BWHistoryWriteValues;

    if (*s_values) {
      SMARTLIST_FOREACH(*s_values, char *, cp, tor_free(cp));
      smartlist_free(*s_values);
    }
    if (! server_mode(get_options())) {
      /* Clients don't need to store bandwidth history persistently;
       * force these values to the defaults. */
      /* FFFF we should pull the default out of config.c's state table,
       * so we don't have two defaults. */
      if (*s_begins != 0 || *s_interval != 900) {
        time_t now = time(NULL);
        time_t save_at = get_options()->AvoidDiskWrites ? now+3600 : now+600;
        or_state_mark_dirty(state, save_at);
      }
      *s_begins = 0;
      *s_interval = 900;
      *s_values = smartlist_create();
      continue;
    }
    *s_begins = b->next_period;
    *s_interval = NUM_SECS_BW_SUM_INTERVAL;
    cp = buf;
    cp += rep_hist_fill_bandwidth_history(cp, len, b);
    tor_snprintf(cp, len-(cp-buf), cp == buf ? U64_FORMAT : ","U64_FORMAT,
                 U64_PRINTF_ARG(b->total_in_period));
    *s_values = smartlist_create();
    if (server_mode(get_options()))
      smartlist_split_string(*s_values, buf, ",", SPLIT_SKIP_SPACE, 0);
  }
  tor_free(buf);
  if (server_mode(get_options())) {
    or_state_mark_dirty(get_or_state(), time(NULL)+(2*3600));
  }
}

/** Set bandwidth history from our saved state. */
int
rep_hist_load_state(or_state_t *state, char **err)
{
  time_t s_begins, start;
  time_t now = time(NULL);
  uint64_t v;
  int r,i,ok;
  int all_ok = 1;
  int s_interval;
  smartlist_t *s_values;
  bw_array_t *b;

  /* Assert they already have been malloced */
  tor_assert(read_array && write_array);

  for (r=0;r<2;++r) {
    b = r?read_array:write_array;
    s_begins = r?state->BWHistoryReadEnds:state->BWHistoryWriteEnds;
    s_interval =  r?state->BWHistoryReadInterval:state->BWHistoryWriteInterval;
    s_values =  r?state->BWHistoryReadValues:state->BWHistoryWriteValues;
    if (s_values && s_begins >= now - NUM_SECS_BW_SUM_INTERVAL*NUM_TOTALS) {
      start = s_begins - s_interval*(smartlist_len(s_values));

      b->cur_obs_time = start;
      b->next_period = start + NUM_SECS_BW_SUM_INTERVAL;
      SMARTLIST_FOREACH(s_values, char *, cp, {
        v = tor_parse_uint64(cp, 10, 0, UINT64_MAX, &ok, NULL);
        if (!ok) {
          all_ok=0;
          log_notice(LD_GENERAL, "Could not parse '%s' into a number.'", cp);
        }
        add_obs(b, start, v);
        start += NUM_SECS_BW_SUM_INTERVAL;
      });
    }

    /* Clean up maxima and observed */
    /* Do we really want to zero this for the purpose of max capacity? */
    for (i=0; i<NUM_SECS_ROLLING_MEASURE; ++i) {
      b->obs[i] = 0;
    }
    b->total_obs = 0;
    for (i=0; i<NUM_TOTALS; ++i) {
      b->maxima[i] = 0;
    }
    b->max_total = 0;
  }

  if (!all_ok) {
    *err = tor_strdup("Parsing of bandwidth history values failed");
    /* and create fresh arrays */
    tor_free(read_array);
    tor_free(write_array);
    read_array = bw_array_new();
    write_array = bw_array_new();
    return -1;
  }
  return 0;
}

/*********************************************************************/

/** A list of port numbers that have been used recently. */
static smartlist_t *predicted_ports_list=NULL;
/** The corresponding most recently used time for each port. */
static smartlist_t *predicted_ports_times=NULL;

/** We just got an application request for a connection with
 * port <b>port</b>. Remember it for the future, so we can keep
 * some circuits open that will exit to this port.
 */
static void
add_predicted_port(uint16_t port, time_t now)
{
  /* XXXX we could just use uintptr_t here, I think. */
  uint16_t *tmp_port = tor_malloc(sizeof(uint16_t));
  time_t *tmp_time = tor_malloc(sizeof(time_t));
  *tmp_port = port;
  *tmp_time = now;
  rephist_total_alloc += sizeof(uint16_t) + sizeof(time_t);
  smartlist_add(predicted_ports_list, tmp_port);
  smartlist_add(predicted_ports_times, tmp_time);
}

/** Initialize whatever memory and structs are needed for predicting
 * which ports will be used. Also seed it with port 80, so we'll build
 * circuits on start-up.
 */
static void
predicted_ports_init(void)
{
  predicted_ports_list = smartlist_create();
  predicted_ports_times = smartlist_create();
  add_predicted_port(80, time(NULL)); /* add one to kickstart us */
}

/** Free whatever memory is needed for predicting which ports will
 * be used.
 */
static void
predicted_ports_free(void)
{
  rephist_total_alloc -= smartlist_len(predicted_ports_list)*sizeof(uint16_t);
  SMARTLIST_FOREACH(predicted_ports_list, char *, cp, tor_free(cp));
  smartlist_free(predicted_ports_list);
  rephist_total_alloc -= smartlist_len(predicted_ports_times)*sizeof(time_t);
  SMARTLIST_FOREACH(predicted_ports_times, char *, cp, tor_free(cp));
  smartlist_free(predicted_ports_times);
}

/** Remember that <b>port</b> has been asked for as of time <b>now</b>.
 * This is used for predicting what sorts of streams we'll make in the
 * future and making exit circuits to anticipate that.
 */
void
rep_hist_note_used_port(uint16_t port, time_t now)
{
  int i;
  uint16_t *tmp_port;
  time_t *tmp_time;

  tor_assert(predicted_ports_list);
  tor_assert(predicted_ports_times);

  if (!port) /* record nothing */
    return;

  for (i = 0; i < smartlist_len(predicted_ports_list); ++i) {
    tmp_port = smartlist_get(predicted_ports_list, i);
    tmp_time = smartlist_get(predicted_ports_times, i);
    if (*tmp_port == port) {
      *tmp_time = now;
      return;
    }
  }
  /* it's not there yet; we need to add it */
  add_predicted_port(port, now);
}

/** For this long after we've seen a request for a given port, assume that
 * we'll want to make connections to the same port in the future.  */
#define PREDICTED_CIRCS_RELEVANCE_TIME (60*60)

/** Return a pointer to the list of port numbers that
 * are likely to be asked for in the near future.
 *
 * The caller promises not to mess with it.
 */
smartlist_t *
rep_hist_get_predicted_ports(time_t now)
{
  int i;
  uint16_t *tmp_port;
  time_t *tmp_time;

  tor_assert(predicted_ports_list);
  tor_assert(predicted_ports_times);

  /* clean out obsolete entries */
  for (i = 0; i < smartlist_len(predicted_ports_list); ++i) {
    tmp_time = smartlist_get(predicted_ports_times, i);
    if (*tmp_time + PREDICTED_CIRCS_RELEVANCE_TIME < now) {
      tmp_port = smartlist_get(predicted_ports_list, i);
      log_debug(LD_CIRC, "Expiring predicted port %d", *tmp_port);
      smartlist_del(predicted_ports_list, i);
      smartlist_del(predicted_ports_times, i);
      rephist_total_alloc -= sizeof(uint16_t)+sizeof(time_t);
      tor_free(tmp_port);
      tor_free(tmp_time);
      i--;
    }
  }
  return predicted_ports_list;
}

/** The user asked us to do a resolve. Rather than keeping track of
 * timings and such of resolves, we fake it for now by making treating
 * it the same way as a connection to port 80. This way we will continue
 * to have circuits lying around if the user only uses Tor for resolves.
 */
void
rep_hist_note_used_resolve(time_t now)
{
  rep_hist_note_used_port(80, now);
}

/** The last time at which we needed an internal circ. */
static time_t predicted_internal_time = 0;
/** The last time we needed an internal circ with good uptime. */
static time_t predicted_internal_uptime_time = 0;
/** The last time we needed an internal circ with good capacity. */
static time_t predicted_internal_capacity_time = 0;

/** Remember that we used an internal circ at time <b>now</b>. */
void
rep_hist_note_used_internal(time_t now, int need_uptime, int need_capacity)
{
  predicted_internal_time = now;
  if (need_uptime)
    predicted_internal_uptime_time = now;
  if (need_capacity)
    predicted_internal_capacity_time = now;
}

/** Return 1 if we've used an internal circ recently; else return 0. */
int
rep_hist_get_predicted_internal(time_t now, int *need_uptime,
                                int *need_capacity)
{
  if (!predicted_internal_time) { /* initialize it */
    predicted_internal_time = now;
    predicted_internal_uptime_time = now;
    predicted_internal_capacity_time = now;
  }
  if (predicted_internal_time + PREDICTED_CIRCS_RELEVANCE_TIME < now)
    return 0; /* too long ago */
  if (predicted_internal_uptime_time + PREDICTED_CIRCS_RELEVANCE_TIME >= now)
    *need_uptime = 1;
  if (predicted_internal_capacity_time + PREDICTED_CIRCS_RELEVANCE_TIME >= now)
    *need_capacity = 1;
  return 1;
}

/** Any ports used lately? These are pre-seeded if we just started
 * up or if we're running a hidden service. */
int
any_predicted_circuits(time_t now)
{
  return smartlist_len(predicted_ports_list) ||
         predicted_internal_time + PREDICTED_CIRCS_RELEVANCE_TIME >= now;
}

/** Return 1 if we have no need for circuits currently, else return 0. */
int
rep_hist_circbuilding_dormant(time_t now)
{
  if (any_predicted_circuits(now))
    return 0;

  /* see if we'll still need to build testing circuits */
  if (server_mode(get_options()) && !check_whether_orport_reachable())
    return 0;
  if (!check_whether_dirport_reachable())
    return 0;

  return 1;
}

static uint32_t n_signed_dir_objs = 0;
static uint32_t n_signed_routerdescs = 0;
static uint32_t n_verified_dir_objs = 0;
static uint32_t n_verified_routerdescs = 0;
static uint32_t n_onionskins_encrypted = 0;
static uint32_t n_onionskins_decrypted = 0;
static uint32_t n_tls_client_handshakes = 0;
static uint32_t n_tls_server_handshakes = 0;
static uint32_t n_rend_client_ops = 0;
static uint32_t n_rend_mid_ops = 0;
static uint32_t n_rend_server_ops = 0;

/** Increment the count of the number of times we've done <b>operation</b>. */
void
note_crypto_pk_op(pk_op_t operation)
{
  switch (operation)
    {
    case SIGN_DIR:
      n_signed_dir_objs++;
      break;
    case SIGN_RTR:
      n_signed_routerdescs++;
      break;
    case VERIFY_DIR:
      n_verified_dir_objs++;
      break;
    case VERIFY_RTR:
      n_verified_routerdescs++;
      break;
    case ENC_ONIONSKIN:
      n_onionskins_encrypted++;
      break;
    case DEC_ONIONSKIN:
      n_onionskins_decrypted++;
      break;
    case TLS_HANDSHAKE_C:
      n_tls_client_handshakes++;
      break;
    case TLS_HANDSHAKE_S:
      n_tls_server_handshakes++;
      break;
    case REND_CLIENT:
      n_rend_client_ops++;
      break;
    case REND_MID:
      n_rend_mid_ops++;
      break;
    case REND_SERVER:
      n_rend_server_ops++;
      break;
    default:
      log_warn(LD_BUG, "Unknown pk operation %d", operation);
  }
}

/** Log the number of times we've done each public/private-key operation. */
void
dump_pk_ops(int severity)
{
  log(severity, LD_GENERAL,
      "PK operations: %lu directory objects signed, "
      "%lu directory objects verified, "
      "%lu routerdescs signed, "
      "%lu routerdescs verified, "
      "%lu onionskins encrypted, "
      "%lu onionskins decrypted, "
      "%lu client-side TLS handshakes, "
      "%lu server-side TLS handshakes, "
      "%lu rendezvous client operations, "
      "%lu rendezvous middle operations, "
      "%lu rendezvous server operations.",
      (unsigned long) n_signed_dir_objs,
      (unsigned long) n_verified_dir_objs,
      (unsigned long) n_signed_routerdescs,
      (unsigned long) n_verified_routerdescs,
      (unsigned long) n_onionskins_encrypted,
      (unsigned long) n_onionskins_decrypted,
      (unsigned long) n_tls_client_handshakes,
      (unsigned long) n_tls_server_handshakes,
      (unsigned long) n_rend_client_ops,
      (unsigned long) n_rend_mid_ops,
      (unsigned long) n_rend_server_ops);
}

/** Free all storage held by the OR/link history caches, by the
 * bandwidth history arrays, or by the port history. */
void
rep_hist_free_all(void)
{
  digestmap_free(history_map, free_or_history);
  tor_free(read_array);
  tor_free(write_array);
  predicted_ports_free();
}

/****************** hidden service usage statistics ******************/

/** How large are the intervals for which we track and report hidden service
 * use? */
#define NUM_SECS_HS_USAGE_SUM_INTERVAL (15*60)
/** How far in the past do we remember and publish hidden service use? */
#define NUM_SECS_HS_USAGE_SUM_IS_VALID (24*60*60)
/** How many hidden service usage intervals do we remember? (derived) */
#define NUM_TOTALS_HS_USAGE (NUM_SECS_HS_USAGE_SUM_IS_VALID/ \
                             NUM_SECS_HS_USAGE_SUM_INTERVAL)

/** List element containing a service id and the count. */
typedef struct hs_usage_list_elem_t {
   /** Service id of this elem. */
  char service_id[REND_SERVICE_ID_LEN+1];
  /** Number of occurrences for the given service id. */
  uint32_t count;
  /* Pointer to next list elem */
  struct hs_usage_list_elem_t *next;
} hs_usage_list_elem_t;

/* Ordered list that stores service ids and the number of observations. It is
 * ordered by the number of occurrences in descending order. Its purpose is to
 * calculate the frequency distribution when the period is over. */
typedef struct hs_usage_list_t {
  /* Pointer to the first element in the list. */
  hs_usage_list_elem_t *start;
  /* Number of total occurrences for all list elements. */
  uint32_t total_count;
  /* Number of service ids, i.e. number of list elements. */
  uint32_t total_service_ids;
} hs_usage_list_t;

/** Tracks service-related observations in the current period and their
 * history. */
typedef struct hs_usage_service_related_observation_t {
  /** Ordered list that stores service ids and the number of observations in
   * the current period. It is ordered by the number of occurrences in
   * descending order. Its purpose is to calculate the frequency distribution
   * when the period is over. */
  hs_usage_list_t *list;
  /** Circular arrays that store the history of observations. totals stores all
   * observations, twenty (ten, five) the number of observations related to a
   * service id being accounted for the top 20 (10, 5) percent of all
   * observations. */
  uint32_t totals[NUM_TOTALS_HS_USAGE];
  uint32_t five[NUM_TOTALS_HS_USAGE];
  uint32_t ten[NUM_TOTALS_HS_USAGE];
  uint32_t twenty[NUM_TOTALS_HS_USAGE];
} hs_usage_service_related_observation_t;

/** Tracks the history of general period-related observations, i.e. those that
 * cannot be related to a specific service id. */
typedef struct hs_usage_general_period_related_observations_t {
  /** Circular array that stores the history of observations. */
  uint32_t totals[NUM_TOTALS_HS_USAGE];
} hs_usage_general_period_related_observations_t;

/** Keeps information about the current observation period and its relation to
 * the histories of observations. */
typedef struct hs_usage_current_observation_period_t {
  /** Where do we write the next history entry? */
  int next_idx;
  /** How many values in history have been set ever? (upper bound!) */
  int num_set;
  /** When did this period begin? */
  time_t start_of_current_period;
  /** When does the next period begin? */
  time_t start_of_next_period;
} hs_usage_current_observation_period_t;

static hs_usage_current_observation_period_t *current_period = NULL;
static hs_usage_service_related_observation_t *publish_total = NULL;
static hs_usage_service_related_observation_t *publish_novel = NULL;
static hs_usage_service_related_observation_t *fetch_total = NULL;
static hs_usage_service_related_observation_t *fetch_successful = NULL;
static hs_usage_general_period_related_observations_t *descs = NULL;

/** Creates an empty ordered list element. */
static hs_usage_list_elem_t *
hs_usage_list_elem_new(void)
{
  hs_usage_list_elem_t *e;
  e = tor_malloc_zero(sizeof(hs_usage_list_elem_t));
  rephist_total_alloc += sizeof(hs_usage_list_elem_t);
  e->count = 1;
  e->next = NULL;
  return e;
}

/** Creates an empty ordered list. */
static hs_usage_list_t *
hs_usage_list_new(void)
{
  hs_usage_list_t *l;
  l = tor_malloc_zero(sizeof(hs_usage_list_t));
  rephist_total_alloc += sizeof(hs_usage_list_t);
  l->start = NULL;
  l->total_count = 0;
  l->total_service_ids = 0;
  return l;
}

/** Creates an empty structure for storing service-related observations. */
static hs_usage_service_related_observation_t *
hs_usage_service_related_observation_new(void)
{
  hs_usage_service_related_observation_t *h;
  h = tor_malloc_zero(sizeof(hs_usage_service_related_observation_t));
  rephist_total_alloc += sizeof(hs_usage_service_related_observation_t);
  h->list = hs_usage_list_new();
  return h;
}

/** Creates an empty structure for storing general period-related
 * observations. */
static hs_usage_general_period_related_observations_t *
hs_usage_general_period_related_observations_new(void)
{
  hs_usage_general_period_related_observations_t *p;
  p = tor_malloc_zero(sizeof(hs_usage_general_period_related_observations_t));
  rephist_total_alloc+= sizeof(hs_usage_general_period_related_observations_t);
  return p;
}

/** Creates an empty structure for storing period-specific information. */
static hs_usage_current_observation_period_t *
hs_usage_current_observation_period_new(void)
{
  hs_usage_current_observation_period_t *c;
  time_t now;
  c = tor_malloc_zero(sizeof(hs_usage_current_observation_period_t));
  rephist_total_alloc += sizeof(hs_usage_current_observation_period_t);
  now = time(NULL);
  c->start_of_current_period = now;
  c->start_of_next_period = now + NUM_SECS_HS_USAGE_SUM_INTERVAL;
  return c;
}

/** Initializes the structures for collecting hidden service usage data. */
static void
hs_usage_init(void)
{
  current_period = hs_usage_current_observation_period_new();
  publish_total = hs_usage_service_related_observation_new();
  publish_novel = hs_usage_service_related_observation_new();
  fetch_total = hs_usage_service_related_observation_new();
  fetch_successful = hs_usage_service_related_observation_new();
  descs = hs_usage_general_period_related_observations_new();
}

/** Clears the given ordered list by resetting its attributes and releasing
 * the memory allocated by its elements. */
static void
hs_usage_list_clear(hs_usage_list_t *lst)
{
  /* walk through elements and free memory */
  hs_usage_list_elem_t *current = lst->start;
  hs_usage_list_elem_t *tmp;
  while (current != NULL) {
    tmp = current->next;
    rephist_total_alloc -= sizeof(hs_usage_list_elem_t);
    tor_free(current);
    current = tmp;
  }
  /* reset attributes */
  lst->start = NULL;
  lst->total_count = 0;
  lst->total_service_ids = 0;
  return;
}

/** Frees the memory used by the given list. */
static void
hs_usage_list_free(hs_usage_list_t *lst)
{
  if (!lst)
    return;
  hs_usage_list_clear(lst);
  rephist_total_alloc -= sizeof(hs_usage_list_t);
  tor_free(lst);
}

/** Frees the memory used by the given service-related observations. */
static void
hs_usage_service_related_observation_free(
                                    hs_usage_service_related_observation_t *s)
{
  if (!s)
    return;
  hs_usage_list_free(s->list);
  rephist_total_alloc -= sizeof(hs_usage_service_related_observation_t);
  tor_free(s);
}

/** Frees the memory used by the given period-specific observations. */
static void
hs_usage_general_period_related_observations_free(
                             hs_usage_general_period_related_observations_t *s)
{
  rephist_total_alloc-=sizeof(hs_usage_general_period_related_observations_t);
  tor_free(s);
}

/** Frees the memory used by period-specific information. */
static void
hs_usage_current_observation_period_free(
                                    hs_usage_current_observation_period_t *s)
{
  rephist_total_alloc -= sizeof(hs_usage_current_observation_period_t);
  tor_free(s);
}

/** Frees all memory that was used for collecting hidden service usage data. */
void
hs_usage_free_all(void)
{
  hs_usage_general_period_related_observations_free(descs);
  descs = NULL;
  hs_usage_service_related_observation_free(fetch_successful);
  hs_usage_service_related_observation_free(fetch_total);
  hs_usage_service_related_observation_free(publish_novel);
  hs_usage_service_related_observation_free(publish_total);
  fetch_successful = fetch_total = publish_novel = publish_total = NULL;
  hs_usage_current_observation_period_free(current_period);
  current_period = NULL;
}

/** Inserts a new occurence for the given service id to the given ordered
 * list. */
static void
hs_usage_insert_value(hs_usage_list_t *lst, const char *service_id)
{
  /* search if there is already an elem with same service_id in list */
  hs_usage_list_elem_t *current = lst->start;
  hs_usage_list_elem_t *previous = NULL;
  while (current != NULL && strcmp(current->service_id,service_id)) {
    previous = current;
    current = current->next;
  }
  /* found an element with same service_id? */
  if (current == NULL) {
    /* not found! append to end (which could also be the end of a zero-length
     * list), don't need to sort (1 is smallest value). */
    /* create elem */
    hs_usage_list_elem_t *e = hs_usage_list_elem_new();
    /* update list attributes (one new elem, one new occurence) */
    lst->total_count++;
    lst->total_service_ids++;
    /* copy service id to elem */
    strlcpy(e->service_id,service_id,sizeof(e->service_id));
    /* let either l->start or previously last elem point to new elem */
    if (lst->start == NULL) {
      /* this is the first elem */
      lst->start = e;
    } else {
      /* there were elems in the list before */
      previous->next = e;
    }
  } else {
    /* found! add occurence to elem and consider resorting */
    /* update list attributes (no new elem, but one new occurence) */
    lst->total_count++;
    /* add occurence to elem */
    current->count++;
    /* is it another than the first list elem? and has previous elem fewer
     * count than current? then we need to resort */
    if (previous != NULL && previous->count < current->count) {
      /* yes! we need to resort */
      /* remove current elem first */
      previous->next = current->next;
      /* can we prepend elem to all other elements? */
      if (lst->start->count <= current->count) {
        /* yes! prepend elem */
        current->next = lst->start;
        lst->start = current;
      } else {
        /* no! walk through list a second time and insert at correct place */
        hs_usage_list_elem_t *insert_current = lst->start->next;
        hs_usage_list_elem_t *insert_previous = lst->start;
        while (insert_current != NULL &&
               insert_current->count > current->count) {
          insert_previous = insert_current;
          insert_current = insert_current->next;
        }
        /* insert here */
        current->next = insert_current;
        insert_previous->next = current;
      }
    }
  }
}

/** Writes the current service-related observations to the history array and
 * clears the observations of the current period. */
static void
hs_usage_write_service_related_observations_to_history(
                                    hs_usage_current_observation_period_t *p,
                                    hs_usage_service_related_observation_t *h)
{
  /* walk through the first 20 % of list elements and calculate frequency
   * distributions */
  /* maximum indices for the three frequencies */
  int five_percent_idx = h->list->total_service_ids/20;
  int ten_percent_idx = h->list->total_service_ids/10;
  int twenty_percent_idx = h->list->total_service_ids/5;
  /* temp values */
  uint32_t five_percent = 0;
  uint32_t ten_percent = 0;
  uint32_t twenty_percent = 0;
  /* walk through list */
  hs_usage_list_elem_t *current = h->list->start;
  int i=0;
  while (current != NULL && i <= twenty_percent_idx) {
    twenty_percent += current->count;
    if (i <= ten_percent_idx)
      ten_percent += current->count;
    if (i <= five_percent_idx)
      five_percent += current->count;
    current = current->next;
    i++;
  }
  /* copy frequencies */
  h->twenty[p->next_idx] = twenty_percent;
  h->ten[p->next_idx] = ten_percent;
  h->five[p->next_idx] = five_percent;
  /* copy total number of observations */
  h->totals[p->next_idx] = h->list->total_count;
  /* free memory of old list */
  hs_usage_list_clear(h->list);
}

/** Advances to next observation period */
static void
hs_usage_advance_current_observation_period(void)
{
  /* aggregate observations to history, including frequency distribution
   * arrays */
  hs_usage_write_service_related_observations_to_history(
                                    current_period, publish_total);
  hs_usage_write_service_related_observations_to_history(
                                    current_period, publish_novel);
  hs_usage_write_service_related_observations_to_history(
                                    current_period, fetch_total);
  hs_usage_write_service_related_observations_to_history(
                                    current_period, fetch_successful);
  /* write current number of descriptors to descs history */
  descs->totals[current_period->next_idx] = rend_cache_size();
  /* advance to next period */
  current_period->next_idx++;
  if (current_period->next_idx == NUM_TOTALS_HS_USAGE)
    current_period->next_idx = 0;
  if (current_period->num_set < NUM_TOTALS_HS_USAGE)
    ++current_period->num_set;
  current_period->start_of_current_period=current_period->start_of_next_period;
  current_period->start_of_next_period += NUM_SECS_HS_USAGE_SUM_INTERVAL;
}

/** Checks if the current period is up to date, and if not, advances it. */
static void
hs_usage_check_if_current_period_is_up_to_date(time_t now)
{
  while (now > current_period->start_of_next_period) {
    hs_usage_advance_current_observation_period();
  }
}

/** Adds a service-related observation, maybe after advancing to next
 * observation period. */
static void
hs_usage_add_service_related_observation(
                                    hs_usage_service_related_observation_t *h,
                                    time_t now,
                                    const char *service_id)
{
  if (now < current_period->start_of_current_period) {
    /* don't record old data */
    return;
  }
  /* check if we are up-to-date */
  hs_usage_check_if_current_period_is_up_to_date(now);
  /* add observation */
  hs_usage_insert_value(h->list, service_id);
}

/** Adds the observation of storing a rendezvous service descriptor to our
 * cache in our role as HS authoritative directory. */
void
hs_usage_note_publish_total(const char *service_id, time_t now)
{
  hs_usage_add_service_related_observation(publish_total, now, service_id);
}

/** Adds the observation of storing a novel rendezvous service descriptor to
 * our cache in our role as HS authoritative directory. */
void
hs_usage_note_publish_novel(const char *service_id, time_t now)
{
  hs_usage_add_service_related_observation(publish_novel, now, service_id);
}

/** Adds the observation of being requested for a rendezvous service descriptor
* in our role as HS authoritative directory. */
void
hs_usage_note_fetch_total(const char *service_id, time_t now)
{
  hs_usage_add_service_related_observation(fetch_total, now, service_id);
}

/** Adds the observation of being requested for a rendezvous service descriptor
* in our role as HS authoritative directory and being able to answer that
* request successfully. */
void
hs_usage_note_fetch_successful(const char *service_id, time_t now)
{
  hs_usage_add_service_related_observation(fetch_successful, now, service_id);
}

/** Writes the given circular array to a string */
static size_t
hs_usage_format_history(char *buf, size_t len, uint32_t *data)
{
  char *cp = buf; /* pointer where we are in the buffer */
  int i, n;
  if (current_period->num_set <= current_period->next_idx) {
    i = 0; /* not been through circular array */
  } else {
    i = current_period->next_idx;
  }
  for (n = 0; n < current_period->num_set; ++n,++i) {
    while (i >= NUM_TOTALS_HS_USAGE) i -= NUM_TOTALS_HS_USAGE;
    if (n == (current_period->num_set-1))
      tor_snprintf(cp, len-(cp-buf), "%d", data[i]);
    else
      tor_snprintf(cp, len-(cp-buf), "%d,", data[i]);
    cp += strlen(cp);
  }
  return cp-buf;
}

/** Writes the complete usage history as hidden service authoritative directory
 * to a string */
static char *
hs_usage_format_statistics(void)
{
  char *buf, *cp, *s = NULL;
  char t[ISO_TIME_LEN+1];
  int r;
  uint32_t *data = NULL;
  size_t len;
  len = (70+20*NUM_TOTALS_HS_USAGE)*11;
  buf = tor_malloc_zero(len);
  cp = buf;
  for (r = 0; r < 11; ++r) {
    switch (r) {
    case 0:
      s = (char*) "publish-total-history";
      data = publish_total->totals;
      break;
    case 1:
      s = (char*) "publish-novel-history";
      data = publish_novel->totals;
      break;
    case 2:
      s = (char*) "publish-top-5-percent-history";
      data = publish_total->five;
      break;
    case 3:
      s = (char*) "publish-top-10-percent-history";
      data = publish_total->ten;
      break;
    case 4:
      s = (char*) "publish-top-20-percent-history";
      data = publish_total->twenty;
      break;
    case 5:
      s = (char*) "fetch-total-history";
      data = fetch_total->totals;
      break;
    case 6:
      s = (char*) "fetch-successful-history";
      data = fetch_successful->totals;
      break;
    case 7:
      s = (char*) "fetch-top-5-percent-history";
      data = fetch_total->five;
      break;
    case 8:
      s = (char*) "fetch-top-10-percent-history";
      data = fetch_total->ten;
      break;
    case 9:
      s = (char*) "fetch-top-20-percent-history";
      data = fetch_total->twenty;
      break;
    case 10:
      s = (char*) "desc-total-history";
      data = descs->totals;
      break;
    }
    format_iso_time(t, current_period->start_of_current_period);
    tor_snprintf(cp, len-(cp-buf), "%s %s (%d s) ", s, t,
                 NUM_SECS_HS_USAGE_SUM_INTERVAL);
    cp += strlen(cp);
    cp += hs_usage_format_history(cp, len-(cp-buf), data);
    strlcat(cp, "\n", len-(cp-buf));
    ++cp;
  }
  return buf;
}

/** Writes current statistics to file. */
void
hs_usage_write_statistics_to_file(time_t now)
{
  char *buf;
  size_t len;
  char *fname;
  or_options_t *options;
  /* check if we are up-to-date */
  hs_usage_check_if_current_period_is_up_to_date(now);
  buf = hs_usage_format_statistics();
  options = get_options();
  len = strlen(options->DataDirectory) + 16;
  fname = tor_malloc(len);
  tor_snprintf(fname,len, "%s"PATH_SEPARATOR"hsusage", options->DataDirectory);
  write_str_to_file(fname,buf,0);
  tor_free(buf);
  tor_free(fname);
}

