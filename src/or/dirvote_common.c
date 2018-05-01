/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file dirvote_common.c
 * \brief This file contains functions that are from the directory authority
 *        subsystem related to voting specifically but used by many part of
 *        tor. The full feature is built as part of the dirauth module.
 **/

#define DIRVOTE_COMMON_PRIVATE
#include "dirvote_common.h"

#include "or.h"
#include "config.h"
#include "networkstatus.h"

/* =====
 * Vote scheduling
 * ===== */

/** Set *<b>timing_out</b> to the intervals at which we would like to vote.
 * Note that these aren't the intervals we'll use to vote; they're the ones
 * that we'll vote to use. */
void
dirvote_get_preferred_voting_intervals(vote_timing_t *timing_out)
{
  const or_options_t *options = get_options();

  tor_assert(timing_out);

  timing_out->vote_interval = options->V3AuthVotingInterval;
  timing_out->n_intervals_valid = options->V3AuthNIntervalsValid;
  timing_out->vote_delay = options->V3AuthVoteDelay;
  timing_out->dist_delay = options->V3AuthDistDelay;
}

/** Return the start of the next interval of size <b>interval</b> (in
 * seconds) after <b>now</b>, plus <b>offset</b>. Midnight always
 * starts a fresh interval, and if the last interval of a day would be
 * truncated to less than half its size, it is rolled into the
 * previous interval. */
time_t
dirvote_get_start_of_next_interval(time_t now, int interval, int offset)
{
  struct tm tm;
  time_t midnight_today=0;
  time_t midnight_tomorrow;
  time_t next;

  tor_gmtime_r(&now, &tm);
  tm.tm_hour = 0;
  tm.tm_min = 0;
  tm.tm_sec = 0;

  if (tor_timegm(&tm, &midnight_today) < 0) {
    log_warn(LD_BUG, "Ran into an invalid time when trying to find midnight.");
  }
  midnight_tomorrow = midnight_today + (24*60*60);

  next = midnight_today + ((now-midnight_today)/interval + 1)*interval;

  /* Intervals never cross midnight. */
  if (next > midnight_tomorrow)
    next = midnight_tomorrow;

  /* If the interval would only last half as long as it's supposed to, then
   * skip over to the next day. */
  if (next + interval/2 > midnight_tomorrow)
    next = midnight_tomorrow;

  next += offset;
  if (next - interval > now)
    next -= interval;

  return next;
}

/* Populate and return a new voting_schedule_t that can be used to schedule
 * voting. The object is allocated on the heap and it's the responsibility of
 * the caller to free it. Can't fail. */
static voting_schedule_t *
get_voting_schedule(const or_options_t *options, time_t now, int severity)
{
  int interval, vote_delay, dist_delay;
  time_t start;
  time_t end;
  networkstatus_t *consensus;
  voting_schedule_t *new_voting_schedule;

  new_voting_schedule = tor_malloc_zero(sizeof(voting_schedule_t));

  consensus = networkstatus_get_live_consensus(now);

  if (consensus) {
    interval = (int)( consensus->fresh_until - consensus->valid_after );
    vote_delay = consensus->vote_seconds;
    dist_delay = consensus->dist_seconds;
  } else {
    interval = options->TestingV3AuthInitialVotingInterval;
    vote_delay = options->TestingV3AuthInitialVoteDelay;
    dist_delay = options->TestingV3AuthInitialDistDelay;
  }

  tor_assert(interval > 0);

  if (vote_delay + dist_delay > interval/2)
    vote_delay = dist_delay = interval / 4;

  start = new_voting_schedule->interval_starts =
    dirvote_get_start_of_next_interval(now,interval,
                                      options->TestingV3AuthVotingStartOffset);
  end = dirvote_get_start_of_next_interval(start+1, interval,
                                      options->TestingV3AuthVotingStartOffset);

  tor_assert(end > start);

  new_voting_schedule->fetch_missing_signatures = start - (dist_delay/2);
  new_voting_schedule->voting_ends = start - dist_delay;
  new_voting_schedule->fetch_missing_votes =
    start - dist_delay - (vote_delay/2);
  new_voting_schedule->voting_starts = start - dist_delay - vote_delay;

  {
    char tbuf[ISO_TIME_LEN+1];
    format_iso_time(tbuf, new_voting_schedule->interval_starts);
    tor_log(severity, LD_DIR,"Choosing expected valid-after time as %s: "
            "consensus_set=%d, interval=%d",
            tbuf, consensus?1:0, interval);
  }

  return new_voting_schedule;
}

#define voting_schedule_free(s) \
  FREE_AND_NULL(voting_schedule_t, voting_schedule_free_, (s))

/** Frees a voting_schedule_t. This should be used instead of the generic
 * tor_free. */
static void
voting_schedule_free_(voting_schedule_t *voting_schedule_to_free)
{
  if (!voting_schedule_to_free)
    return;
  tor_free(voting_schedule_to_free);
}

voting_schedule_t voting_schedule;

/* Using the time <b>now</b>, return the next voting valid-after time. */
time_t
dirvote_get_next_valid_after_time(void)
{
  /* This is a safe guard in order to make sure that the voting schedule
   * static object is at least initialized. Using this function with a zeroed
   * voting schedule can lead to bugs. */
  if (tor_mem_is_zero((const char *) &voting_schedule,
                      sizeof(voting_schedule))) {
    dirvote_recalculate_timing(get_options(), time(NULL));
    voting_schedule.created_on_demand = 1;
  }
  return voting_schedule.interval_starts;
}

/** Set voting_schedule to hold the timing for the next vote we should be
 * doing. All type of tor do that because HS subsystem needs the timing as
 * well to function properly. */
void
dirvote_recalculate_timing(const or_options_t *options, time_t now)
{
  voting_schedule_t *new_voting_schedule;

  /* get the new voting schedule */
  new_voting_schedule = get_voting_schedule(options, now, LOG_INFO);
  tor_assert(new_voting_schedule);

  /* Fill in the global static struct now */
  memcpy(&voting_schedule, new_voting_schedule, sizeof(voting_schedule));
  voting_schedule_free(new_voting_schedule);
}

/** Return the signature made by <b>voter</b> using the algorithm
 * <b>alg</b>, or NULL if none is found. */
document_signature_t *
dirvote_get_voter_sig_by_alg(const networkstatus_voter_info_t *voter,
                             digest_algorithm_t alg)
{
  if (!voter->sigs)
    return NULL;
  SMARTLIST_FOREACH(voter->sigs, document_signature_t *, sig,
                    if (sig->alg == alg)
                    return sig);
  return NULL;
}

