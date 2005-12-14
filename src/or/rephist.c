/* Copyright 2004-2005 Roger Dingledine, Nick Mathewson. */
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

/** Return the or_history_t for the named OR, creating it if necessary.
 */
static or_history_t *
get_or_history(const char* id)
{
  or_history_t *hist;

  if (!memcmp(id, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", DIGEST_LEN))
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
 * identity digest)
 */
static link_history_t *
get_link_history(const char *from_id, const char *to_id)
{
  or_history_t *orhist;
  link_history_t *lhist;
  orhist = get_or_history(from_id);
  if (!orhist)
    return NULL;
  if (!memcmp(to_id, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", DIGEST_LEN))
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

/** Helper: free storage held by a single link history entry */
static void
_free_link_history(void *val)
{
  rephist_total_alloc -= sizeof(link_history_t);
  tor_free(val);
}

/** Helper: free storage held by a single OR history entry */
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

/** Initialize the static data structures for tracking history.
 */
void
rep_hist_init(void)
{
  history_map = digestmap_new();
  bw_arrays_init();
  predicted_ports_init();
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
    /* XXXX009 Well, everybody has an ID now. Hm. */
    /* If conn has no nickname, it's either an OP, or it is an OR
     * which didn't complete its handshake (or did and was unapproved).
     * Ignore it.
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
 *  <b>to_name</b>.
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
 * <b>before</b> */
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

#define NUM_SECS_ROLLING_MEASURE 10
#define NUM_SECS_BW_SUM_IS_VALID (24*60*60) /* one day */
#define NUM_SECS_BW_SUM_INTERVAL (15*60)
#define NUM_TOTALS (NUM_SECS_BW_SUM_IS_VALID/NUM_SECS_BW_SUM_INTERVAL)

/**
 * Structure to track bandwidth use, and remember the maxima for a given
 * time period.
 */
typedef struct bw_array_t {
  /** Observation array: Total number of bytes transferred in each of the last
   * NUM_SECS_ROLLING_MEASURE seconds. This is used as a circular array. */
  int obs[NUM_SECS_ROLLING_MEASURE];
  int cur_obs_idx; /**< Current position in obs. */
  time_t cur_obs_time; /**< Time represented in obs[cur_obs_idx] */
  int total_obs; /**< Total for all members of obs except obs[cur_obs_idx] */
  int max_total; /**< Largest value that total_obs has taken on in the current
                  * period. */
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
  int maxima[NUM_TOTALS];
  /** Circular array of the total bandwidth usage for the last NUM_TOTALS
   * periods */
  uint64_t totals[NUM_TOTALS];
} bw_array_t;

/** Shift the current period of b forward by one.
 */
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

/** Shift the current observation time of 'b' forward by one second.
 */
static INLINE void
advance_obs(bw_array_t *b)
{
  int nextidx;
  int total;

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

/** Add 'n' bytes to the number of bytes in b for second 'when'.
 */
static INLINE void
add_obs(bw_array_t *b, time_t when, int n)
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

/** Allocate, initialize, and return a new bw_array.
 */
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

/** Set up read_array and write_array
 */
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
static int
find_largest_max(bw_array_t *b)
{
  int i,max;
  max=0;
  for (i=0; i<NUM_TOTALS; ++i) {
    if (b->maxima[i]>max)
      max = b->maxima[i];
  }
  return max;
}

/**
 * Find the largest sums in the past NUM_SECS_BW_SUM_IS_VALID (roughly)
 * seconds. Find one sum for reading and one for writing. They don't have
 * to be at the same time).
 *
 * Return the smaller of these sums, divided by NUM_SECS_ROLLING_MEASURE.
 */
int
rep_hist_bandwidth_assess(void)
{
  int w,r;
  r = find_largest_max(read_array);
  w = find_largest_max(write_array);
  if (r>w)
    return (int)(w/(double)NUM_SECS_ROLLING_MEASURE);
  else
    return (int)(r/(double)NUM_SECS_ROLLING_MEASURE);

  return 0;
}

/**
 * Allocate and return lines for representing this server's bandwidth
 * history in its descriptor.
 */
char *
rep_hist_get_bandwidth_lines(void)
{
  char *buf, *cp;
  char t[ISO_TIME_LEN+1];
  int r, i, n;
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
    tor_snprintf(cp, len-(cp-buf), "opt %s %s (%d s) ",
                 r ? "read-history" : "write-history", t,
                 NUM_SECS_BW_SUM_INTERVAL);
    cp += strlen(cp);

    if (b->num_maxes_set <= b->next_max_idx)
      /* We haven't been through the circular array yet; time starts at i=0.*/
      i = 0;
    else
      /* We've been around the array at least once.  The next i to be
         overwritten is the oldest. */
      i = b->next_max_idx;

    for (n=0; n<b->num_maxes_set; ++n,++i) {
      while (i >= NUM_TOTALS) i -= NUM_TOTALS;
      if (n==(b->num_maxes_set-1))
        tor_snprintf(cp, len-(cp-buf), U64_FORMAT,
                     U64_PRINTF_ARG(b->totals[i]));
      else
        tor_snprintf(cp, len-(cp-buf), U64_FORMAT",",
                     U64_PRINTF_ARG(b->totals[i]));
      cp += strlen(cp);
    }
    strlcat(cp, "\n", len-(cp-buf));
    ++cp;
  }
  return buf;
}

/** A list of port numbers that have been used recently. */
static smartlist_t *predicted_ports_list=NULL;
/** The corresponding most recently used time for each port. */
static smartlist_t *predicted_ports_times=NULL;

/** DOCDOC */
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

/** DOCDOC */
static void
predicted_ports_init(void)
{
  predicted_ports_list = smartlist_create();
  predicted_ports_times = smartlist_create();
  add_predicted_port(80, time(NULL)); /* add one to kickstart us */
}

/** DOCDOC */
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

#define PREDICTED_CIRCS_RELEVANCE_TIME (3600) /* 1 hour */

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
      debug(LD_CIRC, "Expiring predicted port %d", *tmp_port);
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

#if 0
int
rep_hist_get_predicted_resolve(time_t now)
{
  return 0;
}
#endif

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
  if (predicted_internal_uptime_time + PREDICTED_CIRCS_RELEVANCE_TIME < now)
    *need_uptime = 1;
  if (predicted_internal_capacity_time + PREDICTED_CIRCS_RELEVANCE_TIME < now)
    *need_capacity = 1;
  return 1;
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

