/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file hibernate.c
 * \brief Functions to close listeners, stop allowing new circuits,
 * etc in preparation for closing down or going dormant; and to track
 * bandwidth and time intervals to know when to hibernate and when to
 * stop hibernating.
 **/

/*
hibernating, phase 1:
  - send destroy in response to create cells
  - send end (policy failed) in response to begin cells
  - close an OR conn when it has no circuits

hibernating, phase 2:
  (entered when bandwidth hard limit reached)
  - close all OR/AP/exit conns)
*/

#include "or.h"

#define HIBERNATE_STATE_LIVE 1
#define HIBERNATE_STATE_EXITING 2
#define HIBERNATE_STATE_LOWBANDWIDTH 3
#define HIBERNATE_STATE_DORMANT 4

#define SHUTDOWN_WAIT_LENGTH 30 /* seconds */

static int hibernate_state = HIBERNATE_STATE_LIVE;
static time_t hibernate_timeout = 0;

/** How many bytes have we read/written in this accounting interval? */
static uint64_t n_bytes_read_in_interval = 0;
static uint64_t n_bytes_written_in_interval = 0;
/** How many seconds have we been running this interval? */
static uint32_t n_seconds_active_in_interval = 0;
/** When did this accounting interval start? */
static time_t interval_start_time = 0;
/** When will this accounting interval end? */
static time_t interval_end_time = 0;
/** How far into the accounting interval should we hibernate? */
static time_t interval_wakeup_time = 0;
/** How much bandwidth do we 'expect' to use per minute? */
static uint32_t expected_bandwidth_usage = 0;

static void reset_accounting(time_t now);
static int read_bandwidth_usage(void);
static int record_bandwidth_usage(time_t now);
static time_t start_of_accounting_period_after(time_t now);
static time_t start_of_accounting_period_containing(time_t now);
static void accounting_set_wakeup_time(void);

/* ************
 * Functions for bandwidth accounting.
 * ************/

void
accounting_add_bytes(size_t n_read, size_t n_written, int seconds)
{
  n_bytes_read_in_interval += n_read;
  n_bytes_written_in_interval += n_written;
  /* If we haven't been called in 10 seconds, we're probably jumping
   * around in time. */
  n_seconds_active_in_interval += (seconds < 10) ? seconds : 0;
}

static INLINE void
incr_month(struct tm *tm, unsigned int delta)
{
  tm->tm_mon += delta;
  while (tm->tm_mon > 11) {
    ++tm->tm_year;
    tm->tm_mon -= 12;
  }
}

static INLINE void
decr_month(struct tm *tm, unsigned int delta)
{
  tm->tm_mon -= delta;
  while (tm->tm_mon < 0) {
    --tm->tm_year;
    tm->tm_mon += 12;
  }
}

static time_t
start_of_accounting_period_containing(time_t now)
{
  struct tm *tm;
  /* Only months are supported. */
  tm = gmtime(&now);
  /* If this is before the Nth, we want the Nth of last month. */
  if (tm->tm_mday < get_options()->AccountingStart) {
    decr_month(tm, 1);
  }
  /* Otherwise, the month and year are correct.*/

  tm->tm_mday = get_options()->AccountingStart;
  tm->tm_hour = 0;
  tm->tm_min = 0;
  tm->tm_sec = 0;
  return tor_timegm(tm);
}
static time_t
start_of_accounting_period_after(time_t now)
{
  time_t start;
  struct tm *tm;
  start = start_of_accounting_period_containing(now);

  tm = gmtime(&start);
  incr_month(tm, 1);
  return tor_timegm(tm);
}

void
configure_accounting(time_t now)
{
  if (!interval_start_time)
    read_bandwidth_usage(); /* If we fail, we'll leave values at zero, and
                             * reset below.*/
  if (!interval_start_time ||
      start_of_accounting_period_after(interval_start_time) <= now) {
    /* We start a new interval. */
    log_fn(LOG_INFO, "Starting new accounting interval.");
    reset_accounting(now);
  } if (interval_start_time ==
        start_of_accounting_period_containing(interval_start_time)) {
    log_fn(LOG_INFO, "Continuing accounting interval.");
    /* We are in the interval we thought we were in. Do nothing.*/
  } else {
    log_fn(LOG_WARN, "Mismatched accounting interval; starting a fresh one.");
    reset_accounting(now);
  }
  accounting_set_wakeup_time();
}

static void
update_expected_bandwidth(void)
{
  uint64_t used;
  uint32_t max_configured = (get_options()->BandwidthRateBytes * 60);

  if (n_seconds_active_in_interval < 1800) {
    expected_bandwidth_usage = max_configured;
  } else {
    used = n_bytes_written_in_interval < n_bytes_read_in_interval ?
      n_bytes_read_in_interval : n_bytes_written_in_interval;
    expected_bandwidth_usage = (uint32_t)
      (used / (n_seconds_active_in_interval / 60));
    if (expected_bandwidth_usage > max_configured)
      expected_bandwidth_usage = max_configured;
  }
}

static void
reset_accounting(time_t now) {
  log_fn(LOG_INFO, "Starting new accounting interval.");
  update_expected_bandwidth();
  interval_start_time = start_of_accounting_period_containing(now);
  interval_end_time = start_of_accounting_period_after(interval_start_time);
  n_bytes_read_in_interval = 0;
  n_bytes_written_in_interval = 0;
  n_seconds_active_in_interval = 0;
}

static INLINE int time_to_record_bandwidth_usage(time_t now)
{
  /* Note every 5 minutes */
#define NOTE_INTERVAL (5*60)
  /* Or every 20 megabytes */
#define NOTE_BYTES 20*(1024*1024)
  static uint64_t last_read_bytes_noted = 0;
  static uint64_t last_written_bytes_noted = 0;
  static time_t last_time_noted = 0;

  if (last_time_noted + NOTE_INTERVAL <= now ||
      last_read_bytes_noted + NOTE_BYTES <= n_bytes_read_in_interval ||
      last_written_bytes_noted + NOTE_BYTES <= n_bytes_written_in_interval ||
      (interval_end_time && interval_end_time <= now)) {
    last_time_noted = now;
    last_read_bytes_noted = n_bytes_read_in_interval;
    last_written_bytes_noted = n_bytes_written_in_interval;
    return 1;
  }
  return 0;
}

void
accounting_run_housekeeping(time_t now)
{
  if (now >= interval_end_time) {
    configure_accounting(now);
  }
  if (time_to_record_bandwidth_usage(now)) {
    if (record_bandwidth_usage(now)) {
      log_fn(LOG_ERR, "Couldn't record bandwidth usage; exiting.");
      exit(1);
    }
  }
}

static void
accounting_set_wakeup_time(void)
{
  struct tm *tm;
  char buf[ISO_TIME_LEN+1];
  char digest[DIGEST_LEN];
  crypto_digest_env_t *d;
  int n_days_in_interval;
  int n_days_to_exhaust_bw;
  int n_days_to_consider;

  format_iso_time(buf, interval_start_time);
  crypto_pk_get_digest(get_identity_key(), digest);

  d = crypto_new_digest_env();
  crypto_digest_add_bytes(d, buf, ISO_TIME_LEN);
  crypto_digest_add_bytes(d, digest, DIGEST_LEN);
  crypto_digest_get_digest(d, digest, DIGEST_LEN);
  crypto_free_digest_env(d);

  n_days_to_exhaust_bw = (get_options()->AccountingMaxKB/expected_bandwidth_usage)
    /(24*60);

  tm = gmtime(&interval_start_time);
  if (++tm->tm_mon > 11) { tm->tm_mon = 0; ++tm->tm_year; }
  n_days_in_interval = (tor_timegm(tm)-interval_start_time+1)/(24*60*60);

  n_days_to_consider = n_days_in_interval - n_days_to_exhaust_bw;

  /* XXX can we simplify this just by picking a random (non-deterministic)
   * time to be up? If we go down and come up, then we pick a new one. Is
   * that good enough? -RD */
  while (((unsigned char)digest[0]) > n_days_to_consider)
    crypto_digest(digest, digest, DIGEST_LEN);

  interval_wakeup_time = interval_start_time +
    24*60*60 * (unsigned char)digest[0];
}

#define BW_ACCOUNTING_VERSION 1
static int record_bandwidth_usage(time_t now)
{
  char buf[128];
  char fname[512];
  char time1[ISO_TIME_LEN+1];
  char time2[ISO_TIME_LEN+1];
  char *cp = buf;
  /* Format is:
     Version\nTime\nTime\nRead\nWrite\nSeconds\nExpected-Rate\n */

  format_iso_time(time1, interval_start_time);
  format_iso_time(time2, now);
  tor_snprintf(cp, sizeof(buf),
               "%d\n%s\n%s\n"U64_FORMAT"\n"U64_FORMAT"\n%lu\n%lu\n",
               BW_ACCOUNTING_VERSION,
               time1,
               time2,
               U64_PRINTF_ARG(n_bytes_read_in_interval),
               U64_PRINTF_ARG(n_bytes_written_in_interval),
               (unsigned long)n_seconds_active_in_interval,
               (unsigned long)expected_bandwidth_usage);
  tor_snprintf(fname, sizeof(fname), "%s/bw_accounting",
               get_data_directory());

  return write_str_to_file(fname, buf, 0);
}

static int read_bandwidth_usage(void)
{
  char *s = NULL;
  char fname[512];
  time_t t1, t2;
  uint64_t n_read, n_written;
  uint32_t expected_bw, n_seconds;
  smartlist_t *elts;
  int ok;

  tor_snprintf(fname, sizeof(fname), "%s/bw_accounting",
               get_data_directory());
  if (!(s = read_file_to_str(fname, 0))) {
    return 0;
  }
  elts = smartlist_create();
  smartlist_split_string(elts, s, "\n", SPLIT_SKIP_SPACE, SPLIT_IGNORE_BLANK);
  tor_free(s);

  if (smartlist_len(elts)<1 ||
      atoi(smartlist_get(elts,0)) != BW_ACCOUNTING_VERSION) {
    log_fn(LOG_WARN, "Unrecognized bw_accounting file version: %s",
           (const char*)smartlist_get(elts,0));
    goto err;
  }
  if (smartlist_len(elts) < 7) {
    log_fn(LOG_WARN, "Corrupted bw_accounting file: %d lines",
           smartlist_len(elts));
    goto err;
  }
  if (parse_iso_time(smartlist_get(elts,1), &t1)) {
    log_fn(LOG_WARN, "Error parsing bandwidth usage start time.");
    goto err;
  }
  if (parse_iso_time(smartlist_get(elts,2), &t2)) {
    log_fn(LOG_WARN, "Error parsing bandwidth usage last-written time");
    goto err;
  }
  n_read = tor_parse_uint64(smartlist_get(elts,3), 10, 0, UINT64_MAX,
                            &ok, NULL);
  if (!ok) {
    log_fn(LOG_WARN, "Error parsing number of bytes read");
    goto err;
  }
  n_written = tor_parse_uint64(smartlist_get(elts,4), 10, 0, UINT64_MAX,
                               &ok, NULL);
  if (!ok) {
    log_fn(LOG_WARN, "Error parsing number of bytes read");
    goto err;
  }
  n_seconds = (uint32_t)tor_parse_ulong(smartlist_get(elts,5), 10,0,ULONG_MAX,
                                        &ok, NULL);
  if (!ok) {
    log_fn(LOG_WARN, "Error parsing number of seconds live");
    goto err;
  }
  expected_bw =(uint32_t)tor_parse_ulong(smartlist_get(elts,6), 10,0,ULONG_MAX,
                                        &ok, NULL);
  if (!ok) {
    log_fn(LOG_WARN, "Error parsing expected bandwidth");
    goto err;
  }

  n_bytes_read_in_interval = n_read;
  n_bytes_written_in_interval = n_written;
  n_seconds_active_in_interval = n_seconds;
  interval_start_time = t1;
  expected_bandwidth_usage = expected_bw;

  accounting_set_wakeup_time();
  return 0;
 err:
  SMARTLIST_FOREACH(elts, char *, cp, tor_free(cp));
  smartlist_free(elts);
  return -1;
}

static int hibernate_hard_limit_reached(void)
{
  uint64_t hard_limit = get_options()->AccountingMaxKB<<10;
  if (!hard_limit)
    return 0;
  return n_bytes_read_in_interval >= hard_limit
    || n_bytes_written_in_interval >= hard_limit;
}

static int hibernate_soft_limit_reached(void)
{
  uint64_t soft_limit = (uint64_t) ((get_options()->AccountingMaxKB<<10) * .99);
  if (!soft_limit)
    return 0;
  return n_bytes_read_in_interval >= soft_limit
    || n_bytes_written_in_interval >= soft_limit;
}

/** Called when we get a SIGINT, or when bandwidth soft limit
 * is reached. */
static void hibernate_begin(int new_state, time_t now) {
  connection_t *conn;

  if(hibernate_state == HIBERNATE_STATE_EXITING) {
    /* we've been called twice now. close immediately. */
    log(LOG_NOTICE,"Second sigint received; exiting now.");
    tor_cleanup();
    exit(0);
  }

  tor_assert(hibernate_state == HIBERNATE_STATE_LIVE);

  /* close listeners */
  while((conn = connection_get_by_type(CONN_TYPE_OR_LISTENER)) ||
        (conn = connection_get_by_type(CONN_TYPE_AP_LISTENER)) ||
        (conn = connection_get_by_type(CONN_TYPE_DIR_LISTENER))) {
    log_fn(LOG_INFO,"Closing listener type %d", conn->type);
    connection_mark_for_close(conn);
  }

  /* XXX kill intro point circs */
  /* XXX upload rendezvous service descriptors with no intro points */

  if(new_state == HIBERNATE_STATE_EXITING) {
    log(LOG_NOTICE,"Interrupt: will shut down in %d seconds. Interrupt again to exit now.", SHUTDOWN_WAIT_LENGTH);
    hibernate_timeout = time(NULL) + SHUTDOWN_WAIT_LENGTH;
  } else { /* soft limit reached */
    log_fn(LOG_NOTICE,"Bandwidth limit reached; beginning hibernation.");
    hibernate_timeout = interval_end_time;
  }

  hibernate_state = new_state;
}

/** Called when we've been hibernating and our timeout is reached. */
static void hibernate_end(int new_state) {

  tor_assert(hibernate_state == HIBERNATE_STATE_LOWBANDWIDTH ||
             hibernate_state == HIBERNATE_STATE_DORMANT);

  /* listeners will be relaunched in run_scheduled_events() in main.c */
  log_fn(LOG_NOTICE,"Hibernation period ended. Resuming normal activity.");

  hibernate_state = new_state;
  hibernate_timeout = 0; /* no longer hibernating */
}

/** A wrapper around hibernate_begin, for when we get SIGINT. */
void hibernate_begin_shutdown(void) {
  hibernate_begin(HIBERNATE_STATE_EXITING, time(NULL));
}

/** A wrapper to expose whether we're hibernating. */
int we_are_hibernating(void) {
  return hibernate_state != HIBERNATE_STATE_LIVE;
}

/** The big function. Consider our environment and decide if it's
 * time to start/stop hibernating.
 */
void consider_hibernation(time_t now) {
  connection_t *conn;

  if (hibernate_state == HIBERNATE_STATE_EXITING) {
    tor_assert(hibernate_timeout);
    if(hibernate_timeout <= now) {
      log(LOG_NOTICE,"Clean shutdown finished. Exiting.");
      tor_cleanup();
      exit(0);
    }
    return; /* if exiting soon, don't worry about bandwidth limits */
  }

  if(hibernate_state != HIBERNATE_STATE_LIVE) {
    /* We've been hibernating because of bandwidth accounting. */
    tor_assert(hibernate_timeout);
    if (hibernate_timeout > now) {
      /* If we're hibernating, don't wake up until it's time, regardless of
       * whether we're in a new interval */
      return ;
    } else {
      /* The interval has ended, or it is wakeup time.  Find out which */
      accounting_run_housekeeping(now);
      if (interval_wakeup_time <= now) {
        /* The interval hasn't changed, but interval_wakeup_time has passed.
         * It's time to wake up. */
        hibernate_end(HIBERNATE_STATE_LIVE);
        return;
      } else {
        /* The interval has changed, and it isn't time to wake up yet. */
        hibernate_timeout = interval_wakeup_time;
      }
    }
  }

  /* Else, see if it's time to start hibernating, or to go dormant. */
  if (hibernate_state == HIBERNATE_STATE_LIVE &&
      hibernate_soft_limit_reached()) {
    log_fn(LOG_NOTICE,"Bandwidth soft limit reached; commencing hibernation.");
    hibernate_begin(HIBERNATE_STATE_LOWBANDWIDTH, now);
  }

  if (hibernate_state == HIBERNATE_STATE_LOWBANDWIDTH &&
      hibernate_hard_limit_reached()) {
    hibernate_state = HIBERNATE_STATE_DORMANT;
    log_fn(LOG_NOTICE,"Going dormant. Blowing away remaining connections.");

    /* Close all OR/AP/exit conns. Leave dir conns. */
    while((conn = connection_get_by_type(CONN_TYPE_OR)) ||
          (conn = connection_get_by_type(CONN_TYPE_AP)) ||
          (conn = connection_get_by_type(CONN_TYPE_EXIT))) {
      log_fn(LOG_INFO,"Closing conn type %d", conn->type);
      connection_mark_for_close(conn);
    }
  }
}

