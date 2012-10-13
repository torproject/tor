/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitbuild.c
 * \brief The actual details of building circuits.
 **/

#define CIRCUIT_PRIVATE

#include "or.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "config.h"
#include "connection.h"
#include "connection_edge.h"
#include "connection_or.h"
#include "control.h"
#include "directory.h"
#include "main.h"
#include "networkstatus.h"
#include "nodelist.h"
#include "onion.h"
#include "policies.h"
#include "transports.h"
#include "relay.h"
#include "rephist.h"
#include "router.h"
#include "routerlist.h"
#include "routerparse.h"
#include "crypto.h"
#undef log
#include <math.h>

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#define CBT_BIN_TO_MS(bin) ((bin)*CBT_BIN_WIDTH + (CBT_BIN_WIDTH/2))

/********* START VARIABLES **********/
/** Global list of circuit build times */
// XXXX: Add this as a member for entry_guard_t instead of global?
// Then we could do per-guard statistics, as guards are likely to
// vary in their own latency. The downside of this is that guards
// can change frequently, so we'd be building a lot more circuits
// most likely.
/* XXXX024 Make this static; add accessor functions. */
circuit_build_times_t circ_times;

/** A global list of all circuits at this hop. */
extern circuit_t *global_circuitlist;

/** An entry_guard_t represents our information about a chosen long-term
 * first hop, known as a "helper" node in the literature. We can't just
 * use a node_t, since we want to remember these even when we
 * don't have any directory info. */
typedef struct {
  char nickname[MAX_NICKNAME_LEN+1];
  char identity[DIGEST_LEN];
  time_t chosen_on_date; /**< Approximately when was this guard added?
                          * "0" if we don't know. */
  char *chosen_by_version; /**< What tor version added this guard? NULL
                            * if we don't know. */
  unsigned int made_contact : 1; /**< 0 if we have never connected to this
                                  * router, 1 if we have. */
  unsigned int can_retry : 1; /**< Should we retry connecting to this entry,
                               * in spite of having it marked as unreachable?*/
  unsigned int path_bias_notice : 1; /**< Did we alert the user about path bias
                                      * for this node already? */
  unsigned int path_bias_disabled : 1; /**< Have we disabled this node because
                                        * of path bias issues? */
  time_t bad_since; /**< 0 if this guard is currently usable, or the time at
                      * which it was observed to become (according to the
                      * directory or the user configuration) unusable. */
  time_t unreachable_since; /**< 0 if we can connect to this guard, or the
                             * time at which we first noticed we couldn't
                             * connect to it. */
  time_t last_attempted; /**< 0 if we can connect to this guard, or the time
                          * at which we last failed to connect to it. */

  unsigned first_hops; /**< Number of first hops this guard has completed */
  unsigned circuit_successes; /**< Number of successfully built circuits using
                               * this guard as first hop. */
} entry_guard_t;

/** Information about a configured bridge. Currently this just matches the
 * ones in the torrc file, but one day we may be able to learn about new
 * bridges on our own, and remember them in the state file. */
typedef struct {
  /** Address of the bridge. */
  tor_addr_t addr;
  /** TLS port for the bridge. */
  uint16_t port;
  /** Boolean: We are re-parsing our bridge list, and we are going to remove
   * this one if we don't find it in the list of configured bridges. */
  unsigned marked_for_removal : 1;
  /** Expected identity digest, or all zero bytes if we don't know what the
   * digest should be. */
  char identity[DIGEST_LEN];

  /** Name of pluggable transport protocol taken from its config line. */
  char *transport_name;

  /** When should we next try to fetch a descriptor for this bridge? */
  download_status_t fetch_status;
} bridge_info_t;

/** A list of our chosen entry guards. */
static smartlist_t *entry_guards = NULL;
/** A value of 1 means that the entry_guards list has changed
 * and those changes need to be flushed to disk. */
static int entry_guards_dirty = 0;

/** If set, we're running the unit tests: we should avoid clobbering
 * our state file or accessing get_options() or get_or_state() */
static int unit_tests = 0;

/********* END VARIABLES ************/

static int circuit_deliver_create_cell(circuit_t *circ,
                                       uint8_t cell_type, const char *payload);
static int onion_pick_cpath_exit(origin_circuit_t *circ, extend_info_t *exit);
static crypt_path_t *onion_next_hop_in_cpath(crypt_path_t *cpath);
static int onion_extend_cpath(origin_circuit_t *circ);
static int count_acceptable_nodes(smartlist_t *routers);
static int onion_append_hop(crypt_path_t **head_ptr, extend_info_t *choice);

static void entry_guards_changed(void);
static entry_guard_t *entry_guard_get_by_id_digest(const char *digest);

static void bridge_free(bridge_info_t *bridge);

static int entry_guard_inc_first_hop_count(entry_guard_t *guard);
static void pathbias_count_success(origin_circuit_t *circ);

/**
 * This function decides if CBT learning should be disabled. It returns
 * true if one or more of the following four conditions are met:
 *
 *  1. If the cbtdisabled consensus parameter is set.
 *  2. If the torrc option LearnCircuitBuildTimeout is false.
 *  3. If we are a directory authority
 *  4. If we fail to write circuit build time history to our state file.
 */
static int
circuit_build_times_disabled(void)
{
  if (unit_tests) {
    return 0;
  } else {
    int consensus_disabled = networkstatus_get_param(NULL, "cbtdisabled",
                                                     0, 0, 1);
    int config_disabled = !get_options()->LearnCircuitBuildTimeout;
    int dirauth_disabled = get_options()->AuthoritativeDir;
    int state_disabled = did_last_state_file_write_fail() ? 1 : 0;

    if (consensus_disabled || config_disabled || dirauth_disabled ||
           state_disabled) {
      log_debug(LD_CIRC,
               "CircuitBuildTime learning is disabled. "
               "Consensus=%d, Config=%d, AuthDir=%d, StateFile=%d",
               consensus_disabled, config_disabled, dirauth_disabled,
               state_disabled);
      return 1;
    } else {
      log_debug(LD_CIRC,
                "CircuitBuildTime learning is not disabled. "
                "Consensus=%d, Config=%d, AuthDir=%d, StateFile=%d",
                consensus_disabled, config_disabled, dirauth_disabled,
                state_disabled);
      return 0;
    }
  }
}

/**
 * Retrieve and bounds-check the cbtmaxtimeouts consensus paramter.
 *
 * Effect: When this many timeouts happen in the last 'cbtrecentcount'
 * circuit attempts, the client should discard all of its history and
 * begin learning a fresh timeout value.
 */
static int32_t
circuit_build_times_max_timeouts(void)
{
  int32_t cbt_maxtimeouts;

  cbt_maxtimeouts = networkstatus_get_param(NULL, "cbtmaxtimeouts",
                                 CBT_DEFAULT_MAX_RECENT_TIMEOUT_COUNT,
                                 CBT_MIN_MAX_RECENT_TIMEOUT_COUNT,
                                 CBT_MAX_MAX_RECENT_TIMEOUT_COUNT);

  if (!(get_options()->LearnCircuitBuildTimeout)) {
    log_debug(LD_BUG,
              "circuit_build_times_max_timeouts() called, cbtmaxtimeouts is"
              " %d",
              cbt_maxtimeouts);
  }

  return cbt_maxtimeouts;
}

/**
 * Retrieve and bounds-check the cbtnummodes consensus paramter.
 *
 * Effect: This value governs how many modes to use in the weighted
 * average calculation of Pareto parameter Xm. A value of 3 introduces
 * some bias (2-5% of CDF) under ideal conditions, but allows for better
 * performance in the event that a client chooses guard nodes of radically
 * different performance characteristics.
 */
static int32_t
circuit_build_times_default_num_xm_modes(void)
{
  int32_t num = networkstatus_get_param(NULL, "cbtnummodes",
                                        CBT_DEFAULT_NUM_XM_MODES,
                                        CBT_MIN_NUM_XM_MODES,
                                        CBT_MAX_NUM_XM_MODES);

  if (!(get_options()->LearnCircuitBuildTimeout)) {
    log_debug(LD_BUG,
              "circuit_build_times_default_num_xm_modes() called, cbtnummodes"
              " is %d",
              num);
  }

  return num;
}

/**
 * Retrieve and bounds-check the cbtmincircs consensus paramter.
 *
 * Effect: This is the minimum number of circuits to build before
 * computing a timeout.
 */
static int32_t
circuit_build_times_min_circs_to_observe(void)
{
  int32_t num = networkstatus_get_param(NULL, "cbtmincircs",
                                        CBT_DEFAULT_MIN_CIRCUITS_TO_OBSERVE,
                                        CBT_MIN_MIN_CIRCUITS_TO_OBSERVE,
                                        CBT_MAX_MIN_CIRCUITS_TO_OBSERVE);

  if (!(get_options()->LearnCircuitBuildTimeout)) {
    log_debug(LD_BUG,
              "circuit_build_times_min_circs_to_observe() called, cbtmincircs"
              " is %d",
              num);
  }

  return num;
}

/** Return true iff <b>cbt</b> has recorded enough build times that we
 * want to start acting on the timeout it implies. */
int
circuit_build_times_enough_to_compute(circuit_build_times_t *cbt)
{
  return cbt->total_build_times >= circuit_build_times_min_circs_to_observe();
}

/**
 * Retrieve and bounds-check the cbtquantile consensus paramter.
 *
 * Effect: This is the position on the quantile curve to use to set the
 * timeout value. It is a percent (10-99).
 */
double
circuit_build_times_quantile_cutoff(void)
{
  int32_t num = networkstatus_get_param(NULL, "cbtquantile",
                                        CBT_DEFAULT_QUANTILE_CUTOFF,
                                        CBT_MIN_QUANTILE_CUTOFF,
                                        CBT_MAX_QUANTILE_CUTOFF);

  if (!(get_options()->LearnCircuitBuildTimeout)) {
    log_debug(LD_BUG,
              "circuit_build_times_quantile_cutoff() called, cbtquantile"
              " is %d",
              num);
  }

  return num/100.0;
}

/* DOCDOC circuit_build_times_get_bw_scale */
int
circuit_build_times_get_bw_scale(networkstatus_t *ns)
{
  return networkstatus_get_param(ns, "bwweightscale",
                                 BW_WEIGHT_SCALE,
                                 BW_MIN_WEIGHT_SCALE,
                                 BW_MAX_WEIGHT_SCALE);
}

/**
 * Retrieve and bounds-check the cbtclosequantile consensus paramter.
 *
 * Effect: This is the position on the quantile curve to use to set the
 * timeout value to use to actually close circuits. It is a percent
 * (0-99).
 */
static double
circuit_build_times_close_quantile(void)
{
  int32_t param;
  /* Cast is safe - circuit_build_times_quantile_cutoff() is capped */
  int32_t min = (int)tor_lround(100*circuit_build_times_quantile_cutoff());
  param = networkstatus_get_param(NULL, "cbtclosequantile",
             CBT_DEFAULT_CLOSE_QUANTILE,
             CBT_MIN_CLOSE_QUANTILE,
             CBT_MAX_CLOSE_QUANTILE);

  if (!(get_options()->LearnCircuitBuildTimeout)) {
    log_debug(LD_BUG,
              "circuit_build_times_close_quantile() called, cbtclosequantile"
              " is %d", param);
  }

  if (param < min) {
    log_warn(LD_DIR, "Consensus parameter cbtclosequantile is "
             "too small, raising to %d", min);
    param = min;
  }
  return param / 100.0;
}

/**
 * Retrieve and bounds-check the cbttestfreq consensus paramter.
 *
 * Effect: Describes how often in seconds to build a test circuit to
 * gather timeout values. Only applies if less than 'cbtmincircs'
 * have been recorded.
 */
static int32_t
circuit_build_times_test_frequency(void)
{
  int32_t num = networkstatus_get_param(NULL, "cbttestfreq",
                                        CBT_DEFAULT_TEST_FREQUENCY,
                                        CBT_MIN_TEST_FREQUENCY,
                                        CBT_MAX_TEST_FREQUENCY);

  if (!(get_options()->LearnCircuitBuildTimeout)) {
    log_debug(LD_BUG,
              "circuit_build_times_test_frequency() called, cbttestfreq is %d",
              num);
  }

  return num;
}

/**
 * Retrieve and bounds-check the cbtmintimeout consensus parameter.
 *
 * Effect: This is the minimum allowed timeout value in milliseconds.
 * The minimum is to prevent rounding to 0 (we only check once
 * per second).
 */
static int32_t
circuit_build_times_min_timeout(void)
{
  int32_t num = networkstatus_get_param(NULL, "cbtmintimeout",
                                        CBT_DEFAULT_TIMEOUT_MIN_VALUE,
                                        CBT_MIN_TIMEOUT_MIN_VALUE,
                                        CBT_MAX_TIMEOUT_MIN_VALUE);

  if (!(get_options()->LearnCircuitBuildTimeout)) {
    log_debug(LD_BUG,
              "circuit_build_times_min_timeout() called, cbtmintimeout is %d",
              num);
  }

  return num;
}

/**
 * Retrieve and bounds-check the cbtinitialtimeout consensus paramter.
 *
 * Effect: This is the timeout value to use before computing a timeout,
 * in milliseconds.
 */
int32_t
circuit_build_times_initial_timeout(void)
{
  int32_t min = circuit_build_times_min_timeout();
  int32_t param = networkstatus_get_param(NULL, "cbtinitialtimeout",
                                          CBT_DEFAULT_TIMEOUT_INITIAL_VALUE,
                                          CBT_MIN_TIMEOUT_INITIAL_VALUE,
                                          CBT_MAX_TIMEOUT_INITIAL_VALUE);

  if (!(get_options()->LearnCircuitBuildTimeout)) {
    log_debug(LD_BUG,
              "circuit_build_times_initial_timeout() called, "
              "cbtinitialtimeout is %d",
              param);
  }

  if (param < min) {
    log_warn(LD_DIR, "Consensus parameter cbtinitialtimeout is too small, "
             "raising to %d", min);
    param = min;
  }
  return param;
}

/**
 * Retrieve and bounds-check the cbtrecentcount consensus paramter.
 *
 * Effect: This is the number of circuit build times to keep track of
 * for deciding if we hit cbtmaxtimeouts and need to reset our state
 * and learn a new timeout.
 */
static int32_t
circuit_build_times_recent_circuit_count(networkstatus_t *ns)
{
  int32_t num;
  num = networkstatus_get_param(ns, "cbtrecentcount",
                                CBT_DEFAULT_RECENT_CIRCUITS,
                                CBT_MIN_RECENT_CIRCUITS,
                                CBT_MAX_RECENT_CIRCUITS);

  if (!(get_options()->LearnCircuitBuildTimeout)) {
    log_debug(LD_BUG,
              "circuit_build_times_recent_circuit_count() called, "
              "cbtrecentcount is %d",
              num);
  }

  return num;
}

/**
 * This function is called when we get a consensus update.
 *
 * It checks to see if we have changed any consensus parameters
 * that require reallocation or discard of previous stats.
 */
void
circuit_build_times_new_consensus_params(circuit_build_times_t *cbt,
                                         networkstatus_t *ns)
{
  int32_t num;

  /*
   * First check if we're doing adaptive timeouts at all; nothing to
   * update if we aren't.
   */

  if (!circuit_build_times_disabled()) {
    num = circuit_build_times_recent_circuit_count(ns);

    if (num > 0) {
      if (num != cbt->liveness.num_recent_circs) {
        int8_t *recent_circs;
        log_notice(LD_CIRC, "The Tor Directory Consensus has changed how many "
                   "circuits we must track to detect network failures from %d "
                   "to %d.", cbt->liveness.num_recent_circs, num);

        tor_assert(cbt->liveness.timeouts_after_firsthop ||
                   cbt->liveness.num_recent_circs == 0);

        /*
         * Technically this is a circular array that we are reallocating
         * and memcopying. However, since it only consists of either 1s
         * or 0s, and is only used in a statistical test to determine when
         * we should discard our history after a sufficient number of 1's
         * have been reached, it is fine if order is not preserved or
         * elements are lost.
         *
         * cbtrecentcount should only be changing in cases of severe network
         * distress anyway, so memory correctness here is paramount over
         * doing acrobatics to preserve the array.
         */
        recent_circs = tor_malloc_zero(sizeof(int8_t)*num);
        if (cbt->liveness.timeouts_after_firsthop &&
            cbt->liveness.num_recent_circs > 0) {
          memcpy(recent_circs, cbt->liveness.timeouts_after_firsthop,
                 sizeof(int8_t)*MIN(num, cbt->liveness.num_recent_circs));
        }

        // Adjust the index if it needs it.
        if (num < cbt->liveness.num_recent_circs) {
          cbt->liveness.after_firsthop_idx = MIN(num-1,
                  cbt->liveness.after_firsthop_idx);
        }

        tor_free(cbt->liveness.timeouts_after_firsthop);
        cbt->liveness.timeouts_after_firsthop = recent_circs;
        cbt->liveness.num_recent_circs = num;
      }
      /* else no change, nothing to do */
    } else { /* num == 0 */
      /*
       * Weird.  This probably shouldn't happen, so log a warning, but try
       * to do something sensible anyway.
       */

      log_warn(LD_CIRC,
               "The cbtrecentcircs consensus parameter came back zero!  "
               "This disables adaptive timeouts since we can't keep track of "
               "any recent circuits.");

      circuit_build_times_free_timeouts(cbt);
    }
  } else {
    /*
     * Adaptive timeouts are disabled; this might be because of the
     * LearnCircuitBuildTimes config parameter, and hence permanent, or
     * the cbtdisabled consensus parameter, so it may be a new condition.
     * Treat it like getting num == 0 above and free the circuit history
     * if we have any.
     */

    circuit_build_times_free_timeouts(cbt);
  }
}

/** Make a note that we're running unit tests (rather than running Tor
 * itself), so we avoid clobbering our state file. */
void
circuitbuild_running_unit_tests(void)
{
  unit_tests = 1;
}

/**
 * Return the initial default or configured timeout in milliseconds
 */
static double
circuit_build_times_get_initial_timeout(void)
{
  double timeout;

  /*
   * Check if we have LearnCircuitBuildTimeout, and if we don't,
   * always use CircuitBuildTimeout, no questions asked.
   */
  if (get_options()->LearnCircuitBuildTimeout) {
    if (!unit_tests && get_options()->CircuitBuildTimeout) {
      timeout = get_options()->CircuitBuildTimeout*1000;
      if (timeout < circuit_build_times_min_timeout()) {
        log_warn(LD_CIRC, "Config CircuitBuildTimeout too low. Setting to %ds",
                 circuit_build_times_min_timeout()/1000);
        timeout = circuit_build_times_min_timeout();
      }
    } else {
      timeout = circuit_build_times_initial_timeout();
    }
  } else {
    timeout = get_options()->CircuitBuildTimeout*1000;
  }

  return timeout;
}

/**
 * Reset the build time state.
 *
 * Leave estimated parameters, timeout and network liveness intact
 * for future use.
 */
void
circuit_build_times_reset(circuit_build_times_t *cbt)
{
  memset(cbt->circuit_build_times, 0, sizeof(cbt->circuit_build_times));
  cbt->total_build_times = 0;
  cbt->build_times_idx = 0;
  cbt->have_computed_timeout = 0;
}

/**
 * Initialize the buildtimes structure for first use.
 *
 * Sets the initial timeout values based on either the config setting,
 * the consensus param, or the default (CBT_DEFAULT_TIMEOUT_INITIAL_VALUE).
 */
void
circuit_build_times_init(circuit_build_times_t *cbt)
{
  memset(cbt, 0, sizeof(*cbt));
  /*
   * Check if we really are using adaptive timeouts, and don't keep
   * track of this stuff if not.
   */
  if (!circuit_build_times_disabled()) {
    cbt->liveness.num_recent_circs =
      circuit_build_times_recent_circuit_count(NULL);
    cbt->liveness.timeouts_after_firsthop =
      tor_malloc_zero(sizeof(int8_t)*cbt->liveness.num_recent_circs);
  } else {
    cbt->liveness.num_recent_circs = 0;
    cbt->liveness.timeouts_after_firsthop = NULL;
  }
  cbt->close_ms = cbt->timeout_ms = circuit_build_times_get_initial_timeout();
  control_event_buildtimeout_set(cbt, BUILDTIMEOUT_SET_EVENT_RESET);
}

/**
 * Free the saved timeouts, if the cbtdisabled consensus parameter got turned
 * on or something.
 */

void
circuit_build_times_free_timeouts(circuit_build_times_t *cbt)
{
  if (!cbt) return;

  if (cbt->liveness.timeouts_after_firsthop) {
    tor_free(cbt->liveness.timeouts_after_firsthop);
  }

  cbt->liveness.num_recent_circs = 0;
}

#if 0
/**
 * Rewind our build time history by n positions.
 */
static void
circuit_build_times_rewind_history(circuit_build_times_t *cbt, int n)
{
  int i = 0;

  cbt->build_times_idx -= n;
  cbt->build_times_idx %= CBT_NCIRCUITS_TO_OBSERVE;

  for (i = 0; i < n; i++) {
    cbt->circuit_build_times[(i+cbt->build_times_idx)
                             %CBT_NCIRCUITS_TO_OBSERVE]=0;
  }

  if (cbt->total_build_times > n) {
    cbt->total_build_times -= n;
  } else {
    cbt->total_build_times = 0;
  }

  log_info(LD_CIRC,
          "Rewound history by %d places. Current index: %d. "
          "Total: %d", n, cbt->build_times_idx, cbt->total_build_times);
}
#endif

/**
 * Add a new build time value <b>time</b> to the set of build times. Time
 * units are milliseconds.
 *
 * circuit_build_times <b>cbt</b> is a circular array, so loop around when
 * array is full.
 */
int
circuit_build_times_add_time(circuit_build_times_t *cbt, build_time_t time)
{
  if (time <= 0 || time > CBT_BUILD_TIME_MAX) {
    log_warn(LD_BUG, "Circuit build time is too large (%u)."
                      "This is probably a bug.", time);
    tor_fragile_assert();
    return -1;
  }

  log_debug(LD_CIRC, "Adding circuit build time %u", time);

  cbt->circuit_build_times[cbt->build_times_idx] = time;
  cbt->build_times_idx = (cbt->build_times_idx + 1) % CBT_NCIRCUITS_TO_OBSERVE;
  if (cbt->total_build_times < CBT_NCIRCUITS_TO_OBSERVE)
    cbt->total_build_times++;

  if ((cbt->total_build_times % CBT_SAVE_STATE_EVERY) == 0) {
    /* Save state every n circuit builds */
    if (!unit_tests && !get_options()->AvoidDiskWrites)
      or_state_mark_dirty(get_or_state(), 0);
  }

  return 0;
}

/**
 * Return maximum circuit build time
 */
static build_time_t
circuit_build_times_max(circuit_build_times_t *cbt)
{
  int i = 0;
  build_time_t max_build_time = 0;
  for (i = 0; i < CBT_NCIRCUITS_TO_OBSERVE; i++) {
    if (cbt->circuit_build_times[i] > max_build_time
            && cbt->circuit_build_times[i] != CBT_BUILD_ABANDONED)
      max_build_time = cbt->circuit_build_times[i];
  }
  return max_build_time;
}

#if 0
/** Return minimum circuit build time */
build_time_t
circuit_build_times_min(circuit_build_times_t *cbt)
{
  int i = 0;
  build_time_t min_build_time = CBT_BUILD_TIME_MAX;
  for (i = 0; i < CBT_NCIRCUITS_TO_OBSERVE; i++) {
    if (cbt->circuit_build_times[i] && /* 0 <-> uninitialized */
        cbt->circuit_build_times[i] < min_build_time)
      min_build_time = cbt->circuit_build_times[i];
  }
  if (min_build_time == CBT_BUILD_TIME_MAX) {
    log_warn(LD_CIRC, "No build times less than CBT_BUILD_TIME_MAX!");
  }
  return min_build_time;
}
#endif

/**
 * Calculate and return a histogram for the set of build times.
 *
 * Returns an allocated array of histrogram bins representing
 * the frequency of index*CBT_BIN_WIDTH millisecond
 * build times. Also outputs the number of bins in nbins.
 *
 * The return value must be freed by the caller.
 */
static uint32_t *
circuit_build_times_create_histogram(circuit_build_times_t *cbt,
                                     build_time_t *nbins)
{
  uint32_t *histogram;
  build_time_t max_build_time = circuit_build_times_max(cbt);
  int i, c;

  *nbins = 1 + (max_build_time / CBT_BIN_WIDTH);
  histogram = tor_malloc_zero(*nbins * sizeof(build_time_t));

  // calculate histogram
  for (i = 0; i < CBT_NCIRCUITS_TO_OBSERVE; i++) {
    if (cbt->circuit_build_times[i] == 0
            || cbt->circuit_build_times[i] == CBT_BUILD_ABANDONED)
      continue; /* 0 <-> uninitialized */

    c = (cbt->circuit_build_times[i] / CBT_BIN_WIDTH);
    histogram[c]++;
  }

  return histogram;
}

/**
 * Return the Pareto start-of-curve parameter Xm.
 *
 * Because we are not a true Pareto curve, we compute this as the
 * weighted average of the N most frequent build time bins. N is either
 * 1 if we don't have enough circuit build time data collected, or
 * determined by the consensus parameter cbtnummodes (default 3).
 */
static build_time_t
circuit_build_times_get_xm(circuit_build_times_t *cbt)
{
  build_time_t i, nbins;
  build_time_t *nth_max_bin;
  int32_t bin_counts=0;
  build_time_t ret = 0;
  uint32_t *histogram = circuit_build_times_create_histogram(cbt, &nbins);
  int n=0;
  int num_modes = circuit_build_times_default_num_xm_modes();

  tor_assert(nbins > 0);
  tor_assert(num_modes > 0);

  // Only use one mode if < 1000 buildtimes. Not enough data
  // for multiple.
  if (cbt->total_build_times < CBT_NCIRCUITS_TO_OBSERVE)
    num_modes = 1;

  nth_max_bin = (build_time_t*)tor_malloc_zero(num_modes*sizeof(build_time_t));

  /* Determine the N most common build times */
  for (i = 0; i < nbins; i++) {
    if (histogram[i] >= histogram[nth_max_bin[0]]) {
      nth_max_bin[0] = i;
    }

    for (n = 1; n < num_modes; n++) {
      if (histogram[i] >= histogram[nth_max_bin[n]] &&
           (!histogram[nth_max_bin[n-1]]
               || histogram[i] < histogram[nth_max_bin[n-1]])) {
        nth_max_bin[n] = i;
      }
    }
  }

  for (n = 0; n < num_modes; n++) {
    bin_counts += histogram[nth_max_bin[n]];
    ret += CBT_BIN_TO_MS(nth_max_bin[n])*histogram[nth_max_bin[n]];
    log_info(LD_CIRC, "Xm mode #%d: %u %u", n, CBT_BIN_TO_MS(nth_max_bin[n]),
             histogram[nth_max_bin[n]]);
  }

  /* The following assert is safe, because we don't get called when we
   * haven't observed at least CBT_MIN_MIN_CIRCUITS_TO_OBSERVE circuits. */
  tor_assert(bin_counts > 0);

  ret /= bin_counts;
  tor_free(histogram);
  tor_free(nth_max_bin);

  return ret;
}

/**
 * Output a histogram of current circuit build times to
 * the or_state_t state structure.
 */
void
circuit_build_times_update_state(circuit_build_times_t *cbt,
                                 or_state_t *state)
{
  uint32_t *histogram;
  build_time_t i = 0;
  build_time_t nbins = 0;
  config_line_t **next, *line;

  histogram = circuit_build_times_create_histogram(cbt, &nbins);
  // write to state
  config_free_lines(state->BuildtimeHistogram);
  next = &state->BuildtimeHistogram;
  *next = NULL;

  state->TotalBuildTimes = cbt->total_build_times;
  state->CircuitBuildAbandonedCount = 0;

  for (i = 0; i < CBT_NCIRCUITS_TO_OBSERVE; i++) {
    if (cbt->circuit_build_times[i] == CBT_BUILD_ABANDONED)
      state->CircuitBuildAbandonedCount++;
  }

  for (i = 0; i < nbins; i++) {
    // compress the histogram by skipping the blanks
    if (histogram[i] == 0) continue;
    *next = line = tor_malloc_zero(sizeof(config_line_t));
    line->key = tor_strdup("CircuitBuildTimeBin");
    tor_asprintf(&line->value, "%d %d",
            CBT_BIN_TO_MS(i), histogram[i]);
    next = &(line->next);
  }

  if (!unit_tests) {
    if (!get_options()->AvoidDiskWrites)
      or_state_mark_dirty(get_or_state(), 0);
  }

  tor_free(histogram);
}

/**
 * Shuffle the build times array.
 *
 * Adapted from http://en.wikipedia.org/wiki/Fisher-Yates_shuffle
 */
static void
circuit_build_times_shuffle_and_store_array(circuit_build_times_t *cbt,
                                            build_time_t *raw_times,
                                            uint32_t num_times)
{
  uint32_t n = num_times;
  if (num_times > CBT_NCIRCUITS_TO_OBSERVE) {
    log_notice(LD_CIRC, "The number of circuit times that this Tor version "
               "uses to calculate build times is less than the number stored "
               "in your state file. Decreasing the circuit time history from "
               "%lu to %d.", (unsigned long)num_times,
               CBT_NCIRCUITS_TO_OBSERVE);
  }

  if (n > INT_MAX-1) {
    log_warn(LD_CIRC, "For some insane reasons, you had %lu circuit build "
             "observations in your state file. That's far too many; probably "
             "there's a bug here.", (unsigned long)n);
    n = INT_MAX-1;
  }

  /* This code can only be run on a compact array */
  while (n-- > 1) {
    int k = crypto_rand_int(n + 1); /* 0 <= k <= n. */
    build_time_t tmp = raw_times[k];
    raw_times[k] = raw_times[n];
    raw_times[n] = tmp;
  }

  /* Since the times are now shuffled, take a random CBT_NCIRCUITS_TO_OBSERVE
   * subset (ie the first CBT_NCIRCUITS_TO_OBSERVE values) */
  for (n = 0; n < MIN(num_times, CBT_NCIRCUITS_TO_OBSERVE); n++) {
    circuit_build_times_add_time(cbt, raw_times[n]);
  }
}

/**
 * Filter old synthetic timeouts that were created before the
 * new right-censored Pareto calculation was deployed.
 *
 * Once all clients before 0.2.1.13-alpha are gone, this code
 * will be unused.
 */
static int
circuit_build_times_filter_timeouts(circuit_build_times_t *cbt)
{
  int num_filtered=0, i=0;
  double timeout_rate = 0;
  build_time_t max_timeout = 0;

  timeout_rate = circuit_build_times_timeout_rate(cbt);
  max_timeout = (build_time_t)cbt->close_ms;

  for (i = 0; i < CBT_NCIRCUITS_TO_OBSERVE; i++) {
    if (cbt->circuit_build_times[i] > max_timeout) {
      build_time_t replaced = cbt->circuit_build_times[i];
      num_filtered++;
      cbt->circuit_build_times[i] = CBT_BUILD_ABANDONED;

      log_debug(LD_CIRC, "Replaced timeout %d with %d", replaced,
               cbt->circuit_build_times[i]);
    }
  }

  log_info(LD_CIRC,
           "We had %d timeouts out of %d build times, "
           "and filtered %d above the max of %u",
          (int)(cbt->total_build_times*timeout_rate),
          cbt->total_build_times, num_filtered, max_timeout);

  return num_filtered;
}

/**
 * Load histogram from <b>state</b>, shuffling the resulting array
 * after we do so. Use this result to estimate parameters and
 * calculate the timeout.
 *
 * Return -1 on error.
 */
int
circuit_build_times_parse_state(circuit_build_times_t *cbt,
                                or_state_t *state)
{
  int tot_values = 0;
  uint32_t loaded_cnt = 0, N = 0;
  config_line_t *line;
  unsigned int i;
  build_time_t *loaded_times;
  int err = 0;
  circuit_build_times_init(cbt);

  if (circuit_build_times_disabled()) {
    return 0;
  }

  /* build_time_t 0 means uninitialized */
  loaded_times = tor_malloc_zero(sizeof(build_time_t)*state->TotalBuildTimes);

  for (line = state->BuildtimeHistogram; line; line = line->next) {
    smartlist_t *args = smartlist_new();
    smartlist_split_string(args, line->value, " ",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    if (smartlist_len(args) < 2) {
      log_warn(LD_GENERAL, "Unable to parse circuit build times: "
                           "Too few arguments to CircuitBuildTime");
      err = 1;
      SMARTLIST_FOREACH(args, char*, cp, tor_free(cp));
      smartlist_free(args);
      break;
    } else {
      const char *ms_str = smartlist_get(args,0);
      const char *count_str = smartlist_get(args,1);
      uint32_t count, k;
      build_time_t ms;
      int ok;
      ms = (build_time_t)tor_parse_ulong(ms_str, 0, 0,
                                         CBT_BUILD_TIME_MAX, &ok, NULL);
      if (!ok) {
        log_warn(LD_GENERAL, "Unable to parse circuit build times: "
                             "Unparsable bin number");
        err = 1;
        SMARTLIST_FOREACH(args, char*, cp, tor_free(cp));
        smartlist_free(args);
        break;
      }
      count = (uint32_t)tor_parse_ulong(count_str, 0, 0,
                                        UINT32_MAX, &ok, NULL);
      if (!ok) {
        log_warn(LD_GENERAL, "Unable to parse circuit build times: "
                             "Unparsable bin count");
        err = 1;
        SMARTLIST_FOREACH(args, char*, cp, tor_free(cp));
        smartlist_free(args);
        break;
      }

      if (loaded_cnt+count+state->CircuitBuildAbandonedCount
            > state->TotalBuildTimes) {
        log_warn(LD_CIRC,
                 "Too many build times in state file. "
                 "Stopping short before %d",
                 loaded_cnt+count);
        SMARTLIST_FOREACH(args, char*, cp, tor_free(cp));
        smartlist_free(args);
        break;
      }

      for (k = 0; k < count; k++) {
        loaded_times[loaded_cnt++] = ms;
      }
      N++;
      SMARTLIST_FOREACH(args, char*, cp, tor_free(cp));
      smartlist_free(args);
    }
  }

  log_info(LD_CIRC,
           "Adding %d timeouts.", state->CircuitBuildAbandonedCount);
  for (i=0; i < state->CircuitBuildAbandonedCount; i++) {
    loaded_times[loaded_cnt++] = CBT_BUILD_ABANDONED;
  }

  if (loaded_cnt != state->TotalBuildTimes) {
    log_warn(LD_CIRC,
            "Corrupt state file? Build times count mismatch. "
            "Read %d times, but file says %d", loaded_cnt,
            state->TotalBuildTimes);
    err = 1;
    circuit_build_times_reset(cbt);
    goto done;
  }

  circuit_build_times_shuffle_and_store_array(cbt, loaded_times, loaded_cnt);

  /* Verify that we didn't overwrite any indexes */
  for (i=0; i < CBT_NCIRCUITS_TO_OBSERVE; i++) {
    if (!cbt->circuit_build_times[i])
      break;
    tot_values++;
  }
  log_info(LD_CIRC,
           "Loaded %d/%d values from %d lines in circuit time histogram",
           tot_values, cbt->total_build_times, N);

  if (cbt->total_build_times != tot_values
        || cbt->total_build_times > CBT_NCIRCUITS_TO_OBSERVE) {
    log_warn(LD_CIRC,
            "Corrupt state file? Shuffled build times mismatch. "
            "Read %d times, but file says %d", tot_values,
            state->TotalBuildTimes);
    err = 1;
    circuit_build_times_reset(cbt);
    goto done;
  }

  circuit_build_times_set_timeout(cbt);

  if (!state->CircuitBuildAbandonedCount && cbt->total_build_times) {
    circuit_build_times_filter_timeouts(cbt);
  }

 done:
  tor_free(loaded_times);
  return err ? -1 : 0;
}

/**
 * Estimates the Xm and Alpha parameters using
 * http://en.wikipedia.org/wiki/Pareto_distribution#Parameter_estimation
 *
 * The notable difference is that we use mode instead of min to estimate Xm.
 * This is because our distribution is frechet-like. We claim this is
 * an acceptable approximation because we are only concerned with the
 * accuracy of the CDF of the tail.
 */
int
circuit_build_times_update_alpha(circuit_build_times_t *cbt)
{
  build_time_t *x=cbt->circuit_build_times;
  double a = 0;
  int n=0,i=0,abandoned_count=0;
  build_time_t max_time=0;

  /* http://en.wikipedia.org/wiki/Pareto_distribution#Parameter_estimation */
  /* We sort of cheat here and make our samples slightly more pareto-like
   * and less frechet-like. */
  cbt->Xm = circuit_build_times_get_xm(cbt);

  tor_assert(cbt->Xm > 0);

  for (i=0; i< CBT_NCIRCUITS_TO_OBSERVE; i++) {
    if (!x[i]) {
      continue;
    }

    if (x[i] < cbt->Xm) {
      a += tor_mathlog(cbt->Xm);
    } else if (x[i] == CBT_BUILD_ABANDONED) {
      abandoned_count++;
    } else {
      a += tor_mathlog(x[i]);
      if (x[i] > max_time)
        max_time = x[i];
    }
    n++;
  }

  /*
   * We are erring and asserting here because this can only happen
   * in codepaths other than startup. The startup state parsing code
   * performs this same check, and resets state if it hits it. If we
   * hit it at runtime, something serious has gone wrong.
   */
  if (n!=cbt->total_build_times) {
    log_err(LD_CIRC, "Discrepancy in build times count: %d vs %d", n,
            cbt->total_build_times);
  }
  tor_assert(n==cbt->total_build_times);

  if (max_time <= 0) {
    /* This can happen if Xm is actually the *maximum* value in the set.
     * It can also happen if we've abandoned every single circuit somehow.
     * In either case, tell the caller not to compute a new build timeout. */
    log_warn(LD_BUG,
             "Could not determine largest build time (%d). "
             "Xm is %dms and we've abandoned %d out of %d circuits.", max_time,
             cbt->Xm, abandoned_count, n);
    return 0;
  }

  a += abandoned_count*tor_mathlog(max_time);

  a -= n*tor_mathlog(cbt->Xm);
  // Estimator comes from Eq #4 in:
  // "Bayesian estimation based on trimmed samples from Pareto populations"
  // by Arturo J. Fernández. We are right-censored only.
  a = (n-abandoned_count)/a;

  cbt->alpha = a;

  return 1;
}

/**
 * This is the Pareto Quantile Function. It calculates the point x
 * in the distribution such that F(x) = quantile (ie quantile*100%
 * of the mass of the density function is below x on the curve).
 *
 * We use it to calculate the timeout and also to generate synthetic
 * values of time for circuits that timeout before completion.
 *
 * See http://en.wikipedia.org/wiki/Quantile_function,
 * http://en.wikipedia.org/wiki/Inverse_transform_sampling and
 * http://en.wikipedia.org/wiki/Pareto_distribution#Generating_a_
 *     random_sample_from_Pareto_distribution
 * That's right. I'll cite wikipedia all day long.
 *
 * Return value is in milliseconds.
 */
double
circuit_build_times_calculate_timeout(circuit_build_times_t *cbt,
                                      double quantile)
{
  double ret;
  tor_assert(quantile >= 0);
  tor_assert(1.0-quantile > 0);
  tor_assert(cbt->Xm > 0);

  ret = cbt->Xm/pow(1.0-quantile,1.0/cbt->alpha);
  if (ret > INT32_MAX) {
    ret = INT32_MAX;
  }
  tor_assert(ret > 0);
  return ret;
}

/** Pareto CDF */
double
circuit_build_times_cdf(circuit_build_times_t *cbt, double x)
{
  double ret;
  tor_assert(cbt->Xm > 0);
  ret = 1.0-pow(cbt->Xm/x,cbt->alpha);
  tor_assert(0 <= ret && ret <= 1.0);
  return ret;
}

/**
 * Generate a synthetic time using our distribution parameters.
 *
 * The return value will be within the [q_lo, q_hi) quantile points
 * on the CDF.
 */
build_time_t
circuit_build_times_generate_sample(circuit_build_times_t *cbt,
                                    double q_lo, double q_hi)
{
  double randval = crypto_rand_double();
  build_time_t ret;
  double u;

  /* Generate between [q_lo, q_hi) */
  /*XXXX This is what nextafter is supposed to be for; we should use it on the
   * platforms that support it. */
  q_hi -= 1.0/(INT32_MAX);

  tor_assert(q_lo >= 0);
  tor_assert(q_hi < 1);
  tor_assert(q_lo < q_hi);

  u = q_lo + (q_hi-q_lo)*randval;

  tor_assert(0 <= u && u < 1.0);
  /* circuit_build_times_calculate_timeout returns <= INT32_MAX */
  ret = (build_time_t)
    tor_lround(circuit_build_times_calculate_timeout(cbt, u));
  tor_assert(ret > 0);
  return ret;
}

/**
 * Estimate an initial alpha parameter by solving the quantile
 * function with a quantile point and a specific timeout value.
 */
void
circuit_build_times_initial_alpha(circuit_build_times_t *cbt,
                                  double quantile, double timeout_ms)
{
  // Q(u) = Xm/((1-u)^(1/a))
  // Q(0.8) = Xm/((1-0.8))^(1/a)) = CircBuildTimeout
  // CircBuildTimeout = Xm/((1-0.8))^(1/a))
  // CircBuildTimeout = Xm*((1-0.8))^(-1/a))
  // ln(CircBuildTimeout) = ln(Xm)+ln(((1-0.8)))*(-1/a)
  // -ln(1-0.8)/(ln(CircBuildTimeout)-ln(Xm))=a
  tor_assert(quantile >= 0);
  tor_assert(cbt->Xm > 0);
  cbt->alpha = tor_mathlog(1.0-quantile)/
    (tor_mathlog(cbt->Xm)-tor_mathlog(timeout_ms));
  tor_assert(cbt->alpha > 0);
}

/**
 * Returns true if we need circuits to be built
 */
int
circuit_build_times_needs_circuits(circuit_build_times_t *cbt)
{
  /* Return true if < MIN_CIRCUITS_TO_OBSERVE */
  return !circuit_build_times_enough_to_compute(cbt);
}

/**
 * Returns true if we should build a timeout test circuit
 * right now.
 */
int
circuit_build_times_needs_circuits_now(circuit_build_times_t *cbt)
{
  return circuit_build_times_needs_circuits(cbt) &&
    approx_time()-cbt->last_circ_at > circuit_build_times_test_frequency();
}

/**
 * Called to indicate that the network showed some signs of liveness,
 * i.e. we received a cell.
 *
 * This is used by circuit_build_times_network_check_live() to decide
 * if we should record the circuit build timeout or not.
 *
 * This function is called every time we receive a cell. Avoid
 * syscalls, events, and other high-intensity work.
 */
void
circuit_build_times_network_is_live(circuit_build_times_t *cbt)
{
  time_t now = approx_time();
  if (cbt->liveness.nonlive_timeouts > 0) {
    log_notice(LD_CIRC,
               "Tor now sees network activity. Restoring circuit build "
               "timeout recording. Network was down for %d seconds "
               "during %d circuit attempts.",
               (int)(now - cbt->liveness.network_last_live),
               cbt->liveness.nonlive_timeouts);
  }
  cbt->liveness.network_last_live = now;
  cbt->liveness.nonlive_timeouts = 0;
}

/**
 * Called to indicate that we completed a circuit. Because this circuit
 * succeeded, it doesn't count as a timeout-after-the-first-hop.
 *
 * This is used by circuit_build_times_network_check_changed() to determine
 * if we had too many recent timeouts and need to reset our learned timeout
 * to something higher.
 */
void
circuit_build_times_network_circ_success(circuit_build_times_t *cbt)
{
  /* Check for NULLness because we might not be using adaptive timeouts */
  if (cbt->liveness.timeouts_after_firsthop &&
      cbt->liveness.num_recent_circs > 0) {
    cbt->liveness.timeouts_after_firsthop[cbt->liveness.after_firsthop_idx]
      = 0;
    cbt->liveness.after_firsthop_idx++;
    cbt->liveness.after_firsthop_idx %= cbt->liveness.num_recent_circs;
  }
}

/**
 * A circuit just timed out. If it failed after the first hop, record it
 * in our history for later deciding if the network speed has changed.
 *
 * This is used by circuit_build_times_network_check_changed() to determine
 * if we had too many recent timeouts and need to reset our learned timeout
 * to something higher.
 */
static void
circuit_build_times_network_timeout(circuit_build_times_t *cbt,
                                    int did_onehop)
{
  /* Check for NULLness because we might not be using adaptive timeouts */
  if (cbt->liveness.timeouts_after_firsthop &&
      cbt->liveness.num_recent_circs > 0) {
    if (did_onehop) {
      cbt->liveness.timeouts_after_firsthop[cbt->liveness.after_firsthop_idx]
        = 1;
      cbt->liveness.after_firsthop_idx++;
      cbt->liveness.after_firsthop_idx %= cbt->liveness.num_recent_circs;
    }
  }
}

/**
 * A circuit was just forcibly closed. If there has been no recent network
 * activity at all, but this circuit was launched back when we thought the
 * network was live, increment the number of "nonlive" circuit timeouts.
 *
 * This is used by circuit_build_times_network_check_live() to decide
 * if we should record the circuit build timeout or not.
 */
static void
circuit_build_times_network_close(circuit_build_times_t *cbt,
                                    int did_onehop, time_t start_time)
{
  time_t now = time(NULL);
  /*
   * Check if this is a timeout that was for a circuit that spent its
   * entire existence during a time where we have had no network activity.
   */
  if (cbt->liveness.network_last_live < start_time) {
    if (did_onehop) {
      char last_live_buf[ISO_TIME_LEN+1];
      char start_time_buf[ISO_TIME_LEN+1];
      char now_buf[ISO_TIME_LEN+1];
      format_local_iso_time(last_live_buf, cbt->liveness.network_last_live);
      format_local_iso_time(start_time_buf, start_time);
      format_local_iso_time(now_buf, now);
      log_warn(LD_BUG,
               "Circuit somehow completed a hop while the network was "
               "not live. Network was last live at %s, but circuit launched "
               "at %s. It's now %s.", last_live_buf, start_time_buf,
               now_buf);
    }
    cbt->liveness.nonlive_timeouts++;
    if (cbt->liveness.nonlive_timeouts == 1) {
      log_notice(LD_CIRC,
                 "Tor has not observed any network activity for the past %d "
                 "seconds. Disabling circuit build timeout recording.",
                 (int)(now - cbt->liveness.network_last_live));
    } else {
      log_info(LD_CIRC,
             "Got non-live timeout. Current count is: %d",
             cbt->liveness.nonlive_timeouts);
    }
  }
}

/**
 * When the network is not live, we do not record circuit build times.
 *
 * The network is considered not live if there has been at least one
 * circuit build that began and ended (had its close_ms measurement
 * period expire) since we last received a cell.
 *
 * Also has the side effect of rewinding the circuit time history
 * in the case of recent liveness changes.
 */
int
circuit_build_times_network_check_live(circuit_build_times_t *cbt)
{
  if (cbt->liveness.nonlive_timeouts > 0) {
    return 0;
  }

  return 1;
}

/**
 * Returns true if we have seen more than MAX_RECENT_TIMEOUT_COUNT of
 * the past RECENT_CIRCUITS time out after the first hop. Used to detect
 * if the network connection has changed significantly, and if so,
 * resets our circuit build timeout to the default.
 *
 * Also resets the entire timeout history in this case and causes us
 * to restart the process of building test circuits and estimating a
 * new timeout.
 */
int
circuit_build_times_network_check_changed(circuit_build_times_t *cbt)
{
  int total_build_times = cbt->total_build_times;
  int timeout_count=0;
  int i;

  if (cbt->liveness.timeouts_after_firsthop &&
      cbt->liveness.num_recent_circs > 0) {
    /* how many of our recent circuits made it to the first hop but then
     * timed out? */
    for (i = 0; i < cbt->liveness.num_recent_circs; i++) {
      timeout_count += cbt->liveness.timeouts_after_firsthop[i];
    }
  }

  /* If 80% of our recent circuits are timing out after the first hop,
   * we need to re-estimate a new initial alpha and timeout. */
  if (timeout_count < circuit_build_times_max_timeouts()) {
    return 0;
  }

  circuit_build_times_reset(cbt);
  if (cbt->liveness.timeouts_after_firsthop &&
      cbt->liveness.num_recent_circs > 0) {
    memset(cbt->liveness.timeouts_after_firsthop, 0,
            sizeof(*cbt->liveness.timeouts_after_firsthop)*
            cbt->liveness.num_recent_circs);
  }
  cbt->liveness.after_firsthop_idx = 0;

  /* Check to see if this has happened before. If so, double the timeout
   * to give people on abysmally bad network connections a shot at access */
  if (cbt->timeout_ms >= circuit_build_times_get_initial_timeout()) {
    if (cbt->timeout_ms > INT32_MAX/2 || cbt->close_ms > INT32_MAX/2) {
      log_warn(LD_CIRC, "Insanely large circuit build timeout value. "
              "(timeout = %fmsec, close = %fmsec)",
               cbt->timeout_ms, cbt->close_ms);
    } else {
      cbt->timeout_ms *= 2;
      cbt->close_ms *= 2;
    }
  } else {
    cbt->close_ms = cbt->timeout_ms
                  = circuit_build_times_get_initial_timeout();
  }

  control_event_buildtimeout_set(cbt, BUILDTIMEOUT_SET_EVENT_RESET);

  log_notice(LD_CIRC,
            "Your network connection speed appears to have changed. Resetting "
            "timeout to %lds after %d timeouts and %d buildtimes.",
            tor_lround(cbt->timeout_ms/1000), timeout_count,
            total_build_times);

  return 1;
}

/**
 * Count the number of timeouts in a set of cbt data.
 */
double
circuit_build_times_timeout_rate(const circuit_build_times_t *cbt)
{
  int i=0,timeouts=0;
  for (i = 0; i < CBT_NCIRCUITS_TO_OBSERVE; i++) {
    if (cbt->circuit_build_times[i] >= cbt->timeout_ms) {
       timeouts++;
    }
  }

  if (!cbt->total_build_times)
    return 0;

  return ((double)timeouts)/cbt->total_build_times;
}

/**
 * Count the number of closed circuits in a set of cbt data.
 */
double
circuit_build_times_close_rate(const circuit_build_times_t *cbt)
{
  int i=0,closed=0;
  for (i = 0; i < CBT_NCIRCUITS_TO_OBSERVE; i++) {
    if (cbt->circuit_build_times[i] == CBT_BUILD_ABANDONED) {
       closed++;
    }
  }

  if (!cbt->total_build_times)
    return 0;

  return ((double)closed)/cbt->total_build_times;
}

/**
 * Store a timeout as a synthetic value.
 *
 * Returns true if the store was successful and we should possibly
 * update our timeout estimate.
 */
int
circuit_build_times_count_close(circuit_build_times_t *cbt,
                                int did_onehop,
                                time_t start_time)
{
  if (circuit_build_times_disabled()) {
    cbt->close_ms = cbt->timeout_ms
                  = circuit_build_times_get_initial_timeout();
    return 0;
  }

  /* Record this force-close to help determine if the network is dead */
  circuit_build_times_network_close(cbt, did_onehop, start_time);

  /* Only count timeouts if network is live.. */
  if (!circuit_build_times_network_check_live(cbt)) {
    return 0;
  }

  circuit_build_times_add_time(cbt, CBT_BUILD_ABANDONED);
  return 1;
}

/**
 * Update timeout counts to determine if we need to expire
 * our build time history due to excessive timeouts.
 *
 * We do not record any actual time values at this stage;
 * we are only interested in recording the fact that a timeout
 * happened. We record the time values via
 * circuit_build_times_count_close() and circuit_build_times_add_time().
 */
void
circuit_build_times_count_timeout(circuit_build_times_t *cbt,
                                  int did_onehop)
{
  if (circuit_build_times_disabled()) {
    cbt->close_ms = cbt->timeout_ms
                  = circuit_build_times_get_initial_timeout();
    return;
  }

  /* Register the fact that a timeout just occurred. */
  circuit_build_times_network_timeout(cbt, did_onehop);

  /* If there are a ton of timeouts, we should reset
   * the circuit build timeout. */
  circuit_build_times_network_check_changed(cbt);
}

/**
 * Estimate a new timeout based on history and set our timeout
 * variable accordingly.
 */
static int
circuit_build_times_set_timeout_worker(circuit_build_times_t *cbt)
{
  build_time_t max_time;
  if (!circuit_build_times_enough_to_compute(cbt))
    return 0;

  if (!circuit_build_times_update_alpha(cbt))
    return 0;

  cbt->timeout_ms = circuit_build_times_calculate_timeout(cbt,
                                circuit_build_times_quantile_cutoff());

  cbt->close_ms = circuit_build_times_calculate_timeout(cbt,
                                circuit_build_times_close_quantile());

  max_time = circuit_build_times_max(cbt);

  /* Sometimes really fast guard nodes give us such a steep curve
   * that this ends up being not that much greater than timeout_ms.
   * Make it be at least 1 min to handle this case. */
  cbt->close_ms = MAX(cbt->close_ms, circuit_build_times_initial_timeout());

  if (cbt->timeout_ms > max_time) {
    log_info(LD_CIRC,
               "Circuit build timeout of %dms is beyond the maximum build "
               "time we have ever observed. Capping it to %dms.",
               (int)cbt->timeout_ms, max_time);
    cbt->timeout_ms = max_time;
  }

  if (max_time < INT32_MAX/2 && cbt->close_ms > 2*max_time) {
    log_info(LD_CIRC,
               "Circuit build measurement period of %dms is more than twice "
               "the maximum build time we have ever observed. Capping it to "
               "%dms.", (int)cbt->close_ms, 2*max_time);
    cbt->close_ms = 2*max_time;
  }

  cbt->have_computed_timeout = 1;
  return 1;
}

/**
 * Exposed function to compute a new timeout. Dispatches events and
 * also filters out extremely high timeout values.
 */
void
circuit_build_times_set_timeout(circuit_build_times_t *cbt)
{
  long prev_timeout = tor_lround(cbt->timeout_ms/1000);
  double timeout_rate;

  /*
   * Just return if we aren't using adaptive timeouts
   */
  if (circuit_build_times_disabled())
    return;

  if (!circuit_build_times_set_timeout_worker(cbt))
    return;

  if (cbt->timeout_ms < circuit_build_times_min_timeout()) {
    log_info(LD_CIRC, "Set buildtimeout to low value %fms. Setting to %dms",
             cbt->timeout_ms, circuit_build_times_min_timeout());
    cbt->timeout_ms = circuit_build_times_min_timeout();
    if (cbt->close_ms < cbt->timeout_ms) {
      /* This shouldn't happen because of MAX() in timeout_worker above,
       * but doing it just in case */
      cbt->close_ms = circuit_build_times_initial_timeout();
    }
  }

  control_event_buildtimeout_set(cbt, BUILDTIMEOUT_SET_EVENT_COMPUTED);

  timeout_rate = circuit_build_times_timeout_rate(cbt);

  if (prev_timeout > tor_lround(cbt->timeout_ms/1000)) {
    log_info(LD_CIRC,
               "Based on %d circuit times, it looks like we don't need to "
               "wait so long for circuits to finish. We will now assume a "
               "circuit is too slow to use after waiting %ld seconds.",
               cbt->total_build_times,
               tor_lround(cbt->timeout_ms/1000));
    log_info(LD_CIRC,
             "Circuit timeout data: %fms, %fms, Xm: %d, a: %f, r: %f",
             cbt->timeout_ms, cbt->close_ms, cbt->Xm, cbt->alpha,
             timeout_rate);
  } else if (prev_timeout < tor_lround(cbt->timeout_ms/1000)) {
    log_info(LD_CIRC,
               "Based on %d circuit times, it looks like we need to wait "
               "longer for circuits to finish. We will now assume a "
               "circuit is too slow to use after waiting %ld seconds.",
               cbt->total_build_times,
               tor_lround(cbt->timeout_ms/1000));
    log_info(LD_CIRC,
             "Circuit timeout data: %fms, %fms, Xm: %d, a: %f, r: %f",
             cbt->timeout_ms, cbt->close_ms, cbt->Xm, cbt->alpha,
             timeout_rate);
  } else {
    log_info(LD_CIRC,
             "Set circuit build timeout to %lds (%fms, %fms, Xm: %d, a: %f,"
             " r: %f) based on %d circuit times",
             tor_lround(cbt->timeout_ms/1000),
             cbt->timeout_ms, cbt->close_ms, cbt->Xm, cbt->alpha, timeout_rate,
             cbt->total_build_times);
  }
}

/** Iterate over values of circ_id, starting from conn-\>next_circ_id,
 * and with the high bit specified by conn-\>circ_id_type, until we get
 * a circ_id that is not in use by any other circuit on that conn.
 *
 * Return it, or 0 if can't get a unique circ_id.
 */
static circid_t
get_unique_circ_id_by_conn(or_connection_t *conn)
{
  circid_t test_circ_id;
  circid_t attempts=0;
  circid_t high_bit;

  tor_assert(conn);
  if (conn->circ_id_type == CIRC_ID_TYPE_NEITHER) {
    log_warn(LD_BUG, "Trying to pick a circuit ID for a connection from "
             "a client with no identity.");
    return 0;
  }
  high_bit = (conn->circ_id_type == CIRC_ID_TYPE_HIGHER) ? 1<<15 : 0;
  do {
    /* Sequentially iterate over test_circ_id=1...1<<15-1 until we find a
     * circID such that (high_bit|test_circ_id) is not already used. */
    test_circ_id = conn->next_circ_id++;
    if (test_circ_id == 0 || test_circ_id >= 1<<15) {
      test_circ_id = 1;
      conn->next_circ_id = 2;
    }
    if (++attempts > 1<<15) {
      /* Make sure we don't loop forever if all circ_id's are used. This
       * matters because it's an external DoS opportunity.
       */
      log_warn(LD_CIRC,"No unused circ IDs. Failing.");
      return 0;
    }
    test_circ_id |= high_bit;
  } while (circuit_id_in_use_on_orconn(test_circ_id, conn));
  return test_circ_id;
}

/** If <b>verbose</b> is false, allocate and return a comma-separated list of
 * the currently built elements of <b>circ</b>. If <b>verbose</b> is true, also
 * list information about link status in a more verbose format using spaces.
 * If <b>verbose_names</b> is false, give nicknames for Named routers and hex
 * digests for others; if <b>verbose_names</b> is true, use $DIGEST=Name style
 * names.
 */
static char *
circuit_list_path_impl(origin_circuit_t *circ, int verbose, int verbose_names)
{
  crypt_path_t *hop;
  smartlist_t *elements;
  const char *states[] = {"closed", "waiting for keys", "open"};
  char *s;

  elements = smartlist_new();

  if (verbose) {
    const char *nickname = build_state_get_exit_nickname(circ->build_state);
    smartlist_add_asprintf(elements, "%s%s circ (length %d%s%s):",
                 circ->build_state->is_internal ? "internal" : "exit",
                 circ->build_state->need_uptime ? " (high-uptime)" : "",
                 circ->build_state->desired_path_len,
                 circ->_base.state == CIRCUIT_STATE_OPEN ? "" : ", last hop ",
                 circ->_base.state == CIRCUIT_STATE_OPEN ? "" :
                 (nickname?nickname:"*unnamed*"));
  }

  hop = circ->cpath;
  do {
    char *elt;
    const char *id;
    const node_t *node;
    if (!hop)
      break;
    if (!verbose && hop->state != CPATH_STATE_OPEN)
      break;
    if (!hop->extend_info)
      break;
    id = hop->extend_info->identity_digest;
    if (verbose_names) {
      elt = tor_malloc(MAX_VERBOSE_NICKNAME_LEN+1);
      if ((node = node_get_by_id(id))) {
        node_get_verbose_nickname(node, elt);
      } else if (is_legal_nickname(hop->extend_info->nickname)) {
        elt[0] = '$';
        base16_encode(elt+1, HEX_DIGEST_LEN+1, id, DIGEST_LEN);
        elt[HEX_DIGEST_LEN+1]= '~';
        strlcpy(elt+HEX_DIGEST_LEN+2,
                hop->extend_info->nickname, MAX_NICKNAME_LEN+1);
      } else {
        elt[0] = '$';
        base16_encode(elt+1, HEX_DIGEST_LEN+1, id, DIGEST_LEN);
      }
    } else { /* ! verbose_names */
      node = node_get_by_id(id);
      if (node && node_is_named(node)) {
        elt = tor_strdup(node_get_nickname(node));
      } else {
        elt = tor_malloc(HEX_DIGEST_LEN+2);
        elt[0] = '$';
        base16_encode(elt+1, HEX_DIGEST_LEN+1, id, DIGEST_LEN);
      }
    }
    tor_assert(elt);
    if (verbose) {
      tor_assert(hop->state <= 2);
      smartlist_add_asprintf(elements,"%s(%s)",elt,states[hop->state]);
      tor_free(elt);
    } else {
      smartlist_add(elements, elt);
    }
    hop = hop->next;
  } while (hop != circ->cpath);

  s = smartlist_join_strings(elements, verbose?" ":",", 0, NULL);
  SMARTLIST_FOREACH(elements, char*, cp, tor_free(cp));
  smartlist_free(elements);
  return s;
}

/** If <b>verbose</b> is false, allocate and return a comma-separated
 * list of the currently built elements of <b>circ</b>.  If
 * <b>verbose</b> is true, also list information about link status in
 * a more verbose format using spaces.
 */
char *
circuit_list_path(origin_circuit_t *circ, int verbose)
{
  return circuit_list_path_impl(circ, verbose, 0);
}

/** Allocate and return a comma-separated list of the currently built elements
 * of <b>circ</b>, giving each as a verbose nickname.
 */
char *
circuit_list_path_for_controller(origin_circuit_t *circ)
{
  return circuit_list_path_impl(circ, 0, 1);
}

/** Log, at severity <b>severity</b>, the nicknames of each router in
 * <b>circ</b>'s cpath. Also log the length of the cpath, and the intended
 * exit point.
 */
void
circuit_log_path(int severity, unsigned int domain, origin_circuit_t *circ)
{
  char *s = circuit_list_path(circ,1);
  tor_log(severity,domain,"%s",s);
  tor_free(s);
}

/** Tell the rep(utation)hist(ory) module about the status of the links
 * in <b>circ</b>.  Hops that have become OPEN are marked as successfully
 * extended; the _first_ hop that isn't open (if any) is marked as
 * unable to extend.
 */
/* XXXX Someday we should learn from OR circuits too. */
void
circuit_rep_hist_note_result(origin_circuit_t *circ)
{
  crypt_path_t *hop;
  const char *prev_digest = NULL;
  hop = circ->cpath;
  if (!hop) /* circuit hasn't started building yet. */
    return;
  if (server_mode(get_options())) {
    const routerinfo_t *me = router_get_my_routerinfo();
    if (!me)
      return;
    prev_digest = me->cache_info.identity_digest;
  }
  do {
    const node_t *node = node_get_by_id(hop->extend_info->identity_digest);
    if (node) { /* Why do we check this?  We know the identity. -NM XXXX */
      if (prev_digest) {
        if (hop->state == CPATH_STATE_OPEN)
          rep_hist_note_extend_succeeded(prev_digest, node->identity);
        else {
          rep_hist_note_extend_failed(prev_digest, node->identity);
          break;
        }
      }
      prev_digest = node->identity;
    } else {
      prev_digest = NULL;
    }
    hop=hop->next;
  } while (hop!=circ->cpath);
}

/** Pick all the entries in our cpath. Stop and return 0 when we're
 * happy, or return -1 if an error occurs. */
static int
onion_populate_cpath(origin_circuit_t *circ)
{
  int r;
 again:
  r = onion_extend_cpath(circ);
  if (r < 0) {
    log_info(LD_CIRC,"Generating cpath hop failed.");
    return -1;
  }
  if (r == 0)
    goto again;
  return 0; /* if r == 1 */
}

/** Create and return a new origin circuit. Initialize its purpose and
 * build-state based on our arguments.  The <b>flags</b> argument is a
 * bitfield of CIRCLAUNCH_* flags. */
origin_circuit_t *
origin_circuit_init(uint8_t purpose, int flags)
{
  /* sets circ->p_circ_id and circ->p_conn */
  origin_circuit_t *circ = origin_circuit_new();
  circuit_set_state(TO_CIRCUIT(circ), CIRCUIT_STATE_OR_WAIT);
  circ->build_state = tor_malloc_zero(sizeof(cpath_build_state_t));
  circ->build_state->onehop_tunnel =
    ((flags & CIRCLAUNCH_ONEHOP_TUNNEL) ? 1 : 0);
  circ->build_state->need_uptime =
    ((flags & CIRCLAUNCH_NEED_UPTIME) ? 1 : 0);
  circ->build_state->need_capacity =
    ((flags & CIRCLAUNCH_NEED_CAPACITY) ? 1 : 0);
  circ->build_state->is_internal =
    ((flags & CIRCLAUNCH_IS_INTERNAL) ? 1 : 0);
  circ->_base.purpose = purpose;
  return circ;
}

/** Build a new circuit for <b>purpose</b>. If <b>exit</b>
 * is defined, then use that as your exit router, else choose a suitable
 * exit node.
 *
 * Also launch a connection to the first OR in the chosen path, if
 * it's not open already.
 */
origin_circuit_t *
circuit_establish_circuit(uint8_t purpose, extend_info_t *exit, int flags)
{
  origin_circuit_t *circ;
  int err_reason = 0;

  circ = origin_circuit_init(purpose, flags);

  if (onion_pick_cpath_exit(circ, exit) < 0 ||
      onion_populate_cpath(circ) < 0) {
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_NOPATH);
    return NULL;
  }

  control_event_circuit_status(circ, CIRC_EVENT_LAUNCHED, 0);

  if ((err_reason = circuit_handle_first_hop(circ)) < 0) {
    circuit_mark_for_close(TO_CIRCUIT(circ), -err_reason);
    return NULL;
  }
  return circ;
}

/** Start establishing the first hop of our circuit. Figure out what
 * OR we should connect to, and if necessary start the connection to
 * it. If we're already connected, then send the 'create' cell.
 * Return 0 for ok, -reason if circ should be marked-for-close. */
int
circuit_handle_first_hop(origin_circuit_t *circ)
{
  crypt_path_t *firsthop;
  or_connection_t *n_conn;
  int err_reason = 0;
  const char *msg = NULL;
  int should_launch = 0;

  firsthop = onion_next_hop_in_cpath(circ->cpath);
  tor_assert(firsthop);
  tor_assert(firsthop->extend_info);

  /* now see if we're already connected to the first OR in 'route' */
  log_debug(LD_CIRC,"Looking for firsthop '%s:%u'",
            fmt_addr(&firsthop->extend_info->addr),
            firsthop->extend_info->port);

  n_conn = connection_or_get_for_extend(firsthop->extend_info->identity_digest,
                                        &firsthop->extend_info->addr,
                                        &msg,
                                        &should_launch);

  if (!n_conn) {
    /* not currently connected in a useful way. */
    log_info(LD_CIRC, "Next router is %s: %s",
             safe_str_client(extend_info_describe(firsthop->extend_info)),
             msg?msg:"???");
    circ->_base.n_hop = extend_info_dup(firsthop->extend_info);

    if (should_launch) {
      if (circ->build_state->onehop_tunnel)
        control_event_bootstrap(BOOTSTRAP_STATUS_CONN_DIR, 0);
      n_conn = connection_or_connect(&firsthop->extend_info->addr,
                                     firsthop->extend_info->port,
                                     firsthop->extend_info->identity_digest);
      if (!n_conn) { /* connect failed, forget the whole thing */
        log_info(LD_CIRC,"connect to firsthop failed. Closing.");
        return -END_CIRC_REASON_CONNECTFAILED;
      }
    }

    log_debug(LD_CIRC,"connecting in progress (or finished). Good.");
    /* return success. The onion/circuit/etc will be taken care of
     * automatically (may already have been) whenever n_conn reaches
     * OR_CONN_STATE_OPEN.
     */
    return 0;
  } else { /* it's already open. use it. */
    tor_assert(!circ->_base.n_hop);
    circ->_base.n_conn = n_conn;
    log_debug(LD_CIRC,"Conn open. Delivering first onion skin.");
    if ((err_reason = circuit_send_next_onion_skin(circ)) < 0) {
      log_info(LD_CIRC,"circuit_send_next_onion_skin failed.");
      return err_reason;
    }
  }
  return 0;
}

/** Find any circuits that are waiting on <b>or_conn</b> to become
 * open and get them to send their create cells forward.
 *
 * Status is 1 if connect succeeded, or 0 if connect failed.
 */
void
circuit_n_conn_done(or_connection_t *or_conn, int status)
{
  smartlist_t *pending_circs;
  int err_reason = 0;

  log_debug(LD_CIRC,"or_conn to %s/%s, status=%d",
            or_conn->nickname ? or_conn->nickname : "NULL",
            or_conn->_base.address, status);

  pending_circs = smartlist_new();
  circuit_get_all_pending_on_or_conn(pending_circs, or_conn);

  SMARTLIST_FOREACH_BEGIN(pending_circs, circuit_t *, circ)
    {
      /* These checks are redundant wrt get_all_pending_on_or_conn, but I'm
       * leaving them in in case it's possible for the status of a circuit to
       * change as we're going down the list. */
      if (circ->marked_for_close || circ->n_conn || !circ->n_hop ||
          circ->state != CIRCUIT_STATE_OR_WAIT)
        continue;

      if (tor_digest_is_zero(circ->n_hop->identity_digest)) {
        /* Look at addr/port. This is an unkeyed connection. */
        if (!tor_addr_eq(&circ->n_hop->addr, &or_conn->_base.addr) ||
            circ->n_hop->port != or_conn->_base.port)
          continue;
      } else {
        /* We expected a key. See if it's the right one. */
        if (tor_memneq(or_conn->identity_digest,
                   circ->n_hop->identity_digest, DIGEST_LEN))
          continue;
      }
      if (!status) { /* or_conn failed; close circ */
        log_info(LD_CIRC,"or_conn failed. Closing circ.");
        circuit_mark_for_close(circ, END_CIRC_REASON_OR_CONN_CLOSED);
        continue;
      }
      log_debug(LD_CIRC, "Found circ, sending create cell.");
      /* circuit_deliver_create_cell will set n_circ_id and add us to
       * orconn_circuid_circuit_map, so we don't need to call
       * set_circid_orconn here. */
      circ->n_conn = or_conn;
      extend_info_free(circ->n_hop);
      circ->n_hop = NULL;

      if (CIRCUIT_IS_ORIGIN(circ)) {
        if ((err_reason =
             circuit_send_next_onion_skin(TO_ORIGIN_CIRCUIT(circ))) < 0) {
          log_info(LD_CIRC,
                   "send_next_onion_skin failed; circuit marked for closing.");
          circuit_mark_for_close(circ, -err_reason);
          continue;
          /* XXX could this be bad, eg if next_onion_skin failed because conn
           *     died? */
        }
      } else {
        /* pull the create cell out of circ->onionskin, and send it */
        tor_assert(circ->n_conn_onionskin);
        if (circuit_deliver_create_cell(circ,CELL_CREATE,
                                        circ->n_conn_onionskin)<0) {
          circuit_mark_for_close(circ, END_CIRC_REASON_RESOURCELIMIT);
          continue;
        }
        tor_free(circ->n_conn_onionskin);
        circuit_set_state(circ, CIRCUIT_STATE_OPEN);
      }
    }
  SMARTLIST_FOREACH_END(circ);

  smartlist_free(pending_circs);
}

/** Find a new circid that isn't currently in use on the circ->n_conn
 * for the outgoing
 * circuit <b>circ</b>, and deliver a cell of type <b>cell_type</b>
 * (either CELL_CREATE or CELL_CREATE_FAST) with payload <b>payload</b>
 * to this circuit.
 * Return -1 if we failed to find a suitable circid, else return 0.
 */
static int
circuit_deliver_create_cell(circuit_t *circ, uint8_t cell_type,
                            const char *payload)
{
  cell_t cell;
  circid_t id;

  tor_assert(circ);
  tor_assert(circ->n_conn);
  tor_assert(payload);
  tor_assert(cell_type == CELL_CREATE || cell_type == CELL_CREATE_FAST);

  id = get_unique_circ_id_by_conn(circ->n_conn);
  if (!id) {
    log_warn(LD_CIRC,"failed to get unique circID.");
    return -1;
  }
  log_debug(LD_CIRC,"Chosen circID %u.", id);
  circuit_set_n_circid_orconn(circ, id, circ->n_conn);

  memset(&cell, 0, sizeof(cell_t));
  cell.command = cell_type;
  cell.circ_id = circ->n_circ_id;

  memcpy(cell.payload, payload, ONIONSKIN_CHALLENGE_LEN);
  append_cell_to_circuit_queue(circ, circ->n_conn, &cell,
                               CELL_DIRECTION_OUT, 0);

  if (CIRCUIT_IS_ORIGIN(circ)) {
    /* mark it so it gets better rate limiting treatment. */
    circ->n_conn->client_used = time(NULL);
  }

  return 0;
}

/** We've decided to start our reachability testing. If all
 * is set, log this to the user. Return 1 if we did, or 0 if
 * we chose not to log anything. */
int
inform_testing_reachability(void)
{
  char dirbuf[128];
  const routerinfo_t *me = router_get_my_routerinfo();
  if (!me)
    return 0;
  control_event_server_status(LOG_NOTICE,
                              "CHECKING_REACHABILITY ORADDRESS=%s:%d",
                              me->address, me->or_port);
  if (me->dir_port) {
    tor_snprintf(dirbuf, sizeof(dirbuf), " and DirPort %s:%d",
                 me->address, me->dir_port);
    control_event_server_status(LOG_NOTICE,
                                "CHECKING_REACHABILITY DIRADDRESS=%s:%d",
                                me->address, me->dir_port);
  }
  log_notice(LD_OR, "Now checking whether ORPort %s:%d%s %s reachable... "
                         "(this may take up to %d minutes -- look for log "
                         "messages indicating success)",
      me->address, me->or_port,
      me->dir_port ? dirbuf : "",
      me->dir_port ? "are" : "is",
      TIMEOUT_UNTIL_UNREACHABILITY_COMPLAINT/60);

  return 1;
}

/** Return true iff we should send a create_fast cell to start building a given
 * circuit */
static INLINE int
should_use_create_fast_for_circuit(origin_circuit_t *circ)
{
  const or_options_t *options = get_options();
  tor_assert(circ->cpath);
  tor_assert(circ->cpath->extend_info);

  if (!circ->cpath->extend_info->onion_key)
    return 1; /* our hand is forced: only a create_fast will work. */
  if (!options->FastFirstHopPK)
    return 0; /* we prefer to avoid create_fast */
  if (public_server_mode(options)) {
    /* We're a server, and we know an onion key. We can choose.
     * Prefer to blend our circuit into the other circuits we are
     * creating on behalf of others. */
    return 0;
  }

  return 1;
}

/** Return true if <b>circ</b> is the type of circuit we want to count
 * timeouts from. In particular, we want it to have not completed yet
 * (already completing indicates we cannibalized it), and we want it to
 * have exactly three hops.
 */
int
circuit_timeout_want_to_count_circ(origin_circuit_t *circ)
{
  return !circ->has_opened
          && circ->build_state->desired_path_len == DEFAULT_ROUTE_LEN;
}

/** This is the backbone function for building circuits.
 *
 * If circ's first hop is closed, then we need to build a create
 * cell and send it forward.
 *
 * Otherwise, we need to build a relay extend cell and send it
 * forward.
 *
 * Return -reason if we want to tear down circ, else return 0.
 */
int
circuit_send_next_onion_skin(origin_circuit_t *circ)
{
  crypt_path_t *hop;
  const node_t *node;
  char payload[2+4+DIGEST_LEN+ONIONSKIN_CHALLENGE_LEN];
  char *onionskin;
  size_t payload_len;

  tor_assert(circ);

  if (circ->cpath->state == CPATH_STATE_CLOSED) {
    int fast;
    uint8_t cell_type;
    log_debug(LD_CIRC,"First skin; sending create cell.");
    if (circ->build_state->onehop_tunnel)
      control_event_bootstrap(BOOTSTRAP_STATUS_ONEHOP_CREATE, 0);
    else
      control_event_bootstrap(BOOTSTRAP_STATUS_CIRCUIT_CREATE, 0);

    node = node_get_by_id(circ->_base.n_conn->identity_digest);
    fast = should_use_create_fast_for_circuit(circ);
    if (!fast) {
      /* We are an OR and we know the right onion key: we should
       * send an old slow create cell.
       */
      cell_type = CELL_CREATE;
      if (onion_skin_create(circ->cpath->extend_info->onion_key,
                            &(circ->cpath->dh_handshake_state),
                            payload) < 0) {
        log_warn(LD_CIRC,"onion_skin_create (first hop) failed.");
        return - END_CIRC_REASON_INTERNAL;
      }
      note_request("cell: create", 1);
    } else {
      /* We are not an OR, and we're building the first hop of a circuit to a
       * new OR: we can be speedy and use CREATE_FAST to save an RSA operation
       * and a DH operation. */
      cell_type = CELL_CREATE_FAST;
      memset(payload, 0, sizeof(payload));
      crypto_rand((char*) circ->cpath->fast_handshake_state,
                  sizeof(circ->cpath->fast_handshake_state));
      memcpy(payload, circ->cpath->fast_handshake_state,
             sizeof(circ->cpath->fast_handshake_state));
      note_request("cell: create fast", 1);
    }

    if (circuit_deliver_create_cell(TO_CIRCUIT(circ), cell_type, payload) < 0)
      return - END_CIRC_REASON_RESOURCELIMIT;

    circ->cpath->state = CPATH_STATE_AWAITING_KEYS;
    circuit_set_state(TO_CIRCUIT(circ), CIRCUIT_STATE_BUILDING);
    log_info(LD_CIRC,"First hop: finished sending %s cell to '%s'",
             fast ? "CREATE_FAST" : "CREATE",
             node ? node_describe(node) : "<unnamed>");
  } else {
    tor_assert(circ->cpath->state == CPATH_STATE_OPEN);
    tor_assert(circ->_base.state == CIRCUIT_STATE_BUILDING);
    log_debug(LD_CIRC,"starting to send subsequent skin.");
    hop = onion_next_hop_in_cpath(circ->cpath);
    if (!hop) {
      /* done building the circuit. whew. */
      circuit_set_state(TO_CIRCUIT(circ), CIRCUIT_STATE_OPEN);
      if (circuit_timeout_want_to_count_circ(circ)) {
        struct timeval end;
        long timediff;
        tor_gettimeofday(&end);
        timediff = tv_mdiff(&circ->_base.timestamp_created, &end);

        /*
         * If the circuit build time is much greater than we would have cut
         * it off at, we probably had a suspend event along this codepath,
         * and we should discard the value.
         */
        if (timediff < 0 || timediff > 2*circ_times.close_ms+1000) {
          log_notice(LD_CIRC, "Strange value for circuit build time: %ldmsec. "
                              "Assuming clock jump. Purpose %d (%s)", timediff,
                     circ->_base.purpose,
                     circuit_purpose_to_string(circ->_base.purpose));
        } else if (!circuit_build_times_disabled()) {
          /* Only count circuit times if the network is live */
          if (circuit_build_times_network_check_live(&circ_times)) {
            circuit_build_times_add_time(&circ_times, (build_time_t)timediff);
            circuit_build_times_set_timeout(&circ_times);
          }

          if (circ->_base.purpose != CIRCUIT_PURPOSE_C_MEASURE_TIMEOUT) {
            circuit_build_times_network_circ_success(&circ_times);
          }
        }
      }
      log_info(LD_CIRC,"circuit built!");
      circuit_reset_failure_count(0);

      if (circ->build_state->onehop_tunnel || circ->has_opened) {
        control_event_bootstrap(BOOTSTRAP_STATUS_REQUESTING_STATUS, 0);
      }

      if (!can_complete_circuit && !circ->build_state->onehop_tunnel) {
        const or_options_t *options = get_options();
        can_complete_circuit=1;
        /* FFFF Log a count of known routers here */
        log_notice(LD_GENERAL,
            "Tor has successfully opened a circuit. "
            "Looks like client functionality is working.");
        control_event_bootstrap(BOOTSTRAP_STATUS_DONE, 0);
        control_event_client_status(LOG_NOTICE, "CIRCUIT_ESTABLISHED");
        clear_broken_connection_map(1);
        if (server_mode(options) && !check_whether_orport_reachable()) {
          inform_testing_reachability();
          consider_testing_reachability(1, 1);
        }
      }

      pathbias_count_success(circ);
      circuit_rep_hist_note_result(circ);
      circuit_has_opened(circ); /* do other actions as necessary */

      /* We're done with measurement circuits here. Just close them */
      if (circ->_base.purpose == CIRCUIT_PURPOSE_C_MEASURE_TIMEOUT)
        circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_FINISHED);
      return 0;
    }

    if (tor_addr_family(&hop->extend_info->addr) != AF_INET) {
      log_warn(LD_BUG, "Trying to extend to a non-IPv4 address.");
      return - END_CIRC_REASON_INTERNAL;
    }

    set_uint32(payload, tor_addr_to_ipv4n(&hop->extend_info->addr));
    set_uint16(payload+4, htons(hop->extend_info->port));

    onionskin = payload+2+4;
    memcpy(payload+2+4+ONIONSKIN_CHALLENGE_LEN,
           hop->extend_info->identity_digest, DIGEST_LEN);
    payload_len = 2+4+ONIONSKIN_CHALLENGE_LEN+DIGEST_LEN;

    if (onion_skin_create(hop->extend_info->onion_key,
                          &(hop->dh_handshake_state), onionskin) < 0) {
      log_warn(LD_CIRC,"onion_skin_create failed.");
      return - END_CIRC_REASON_INTERNAL;
    }

    log_info(LD_CIRC,"Sending extend relay cell.");
    note_request("cell: extend", 1);
    /* send it to hop->prev, because it will transfer
     * it to a create cell and then send to hop */
    if (relay_send_command_from_edge(0, TO_CIRCUIT(circ),
                                     RELAY_COMMAND_EXTEND,
                                     payload, payload_len, hop->prev) < 0)
      return 0; /* circuit is closed */

    hop->state = CPATH_STATE_AWAITING_KEYS;
  }
  return 0;
}

/** Our clock just jumped by <b>seconds_elapsed</b>. Assume
 * something has also gone wrong with our network: notify the user,
 * and abandon all not-yet-used circuits. */
void
circuit_note_clock_jumped(int seconds_elapsed)
{
  int severity = server_mode(get_options()) ? LOG_WARN : LOG_NOTICE;
  tor_log(severity, LD_GENERAL, "Your system clock just jumped %d seconds %s; "
      "assuming established circuits no longer work.",
      seconds_elapsed >=0 ? seconds_elapsed : -seconds_elapsed,
      seconds_elapsed >=0 ? "forward" : "backward");
  control_event_general_status(LOG_WARN, "CLOCK_JUMPED TIME=%d",
                               seconds_elapsed);
  can_complete_circuit=0; /* so it'll log when it works again */
  control_event_client_status(severity, "CIRCUIT_NOT_ESTABLISHED REASON=%s",
                              "CLOCK_JUMPED");
  circuit_mark_all_unused_circs();
  circuit_expire_all_dirty_circs();
}

/** Take the 'extend' <b>cell</b>, pull out addr/port plus the onion
 * skin and identity digest for the next hop. If we're already connected,
 * pass the onion skin to the next hop using a create cell; otherwise
 * launch a new OR connection, and <b>circ</b> will notice when the
 * connection succeeds or fails.
 *
 * Return -1 if we want to warn and tear down the circuit, else return 0.
 */
int
circuit_extend(cell_t *cell, circuit_t *circ)
{
  or_connection_t *n_conn;
  relay_header_t rh;
  char *onionskin;
  char *id_digest=NULL;
  uint32_t n_addr32;
  uint16_t n_port;
  tor_addr_t n_addr;
  const char *msg = NULL;
  int should_launch = 0;

  if (circ->n_conn) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "n_conn already set. Bug/attack. Closing.");
    return -1;
  }
  if (circ->n_hop) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "conn to next hop already launched. Bug/attack. Closing.");
    return -1;
  }

  if (!server_mode(get_options())) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Got an extend cell, but running as a client. Closing.");
    return -1;
  }

  relay_header_unpack(&rh, cell->payload);

  if (rh.length < 4+2+ONIONSKIN_CHALLENGE_LEN+DIGEST_LEN) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Wrong length %d on extend cell. Closing circuit.",
           rh.length);
    return -1;
  }

  n_addr32 = ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE));
  n_port = ntohs(get_uint16(cell->payload+RELAY_HEADER_SIZE+4));
  onionskin = (char*) cell->payload+RELAY_HEADER_SIZE+4+2;
  id_digest = (char*) cell->payload+RELAY_HEADER_SIZE+4+2+
    ONIONSKIN_CHALLENGE_LEN;
  tor_addr_from_ipv4h(&n_addr, n_addr32);

  if (!n_port || !n_addr32) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Client asked me to extend to zero destination port or addr.");
    return -1;
  }

  if (tor_addr_is_internal(&n_addr, 0) &&
      !get_options()->ExtendAllowPrivateAddresses) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Client asked me to extend to a private address");
    return -1;
  }

  /* Check if they asked us for 0000..0000. We support using
   * an empty fingerprint for the first hop (e.g. for a bridge relay),
   * but we don't want to let people send us extend cells for empty
   * fingerprints -- a) because it opens the user up to a mitm attack,
   * and b) because it lets an attacker force the relay to hold open a
   * new TLS connection for each extend request. */
  if (tor_digest_is_zero(id_digest)) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Client asked me to extend without specifying an id_digest.");
    return -1;
  }

  /* Next, check if we're being asked to connect to the hop that the
   * extend cell came from. There isn't any reason for that, and it can
   * assist circular-path attacks. */
  if (tor_memeq(id_digest, TO_OR_CIRCUIT(circ)->p_conn->identity_digest,
              DIGEST_LEN)) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Client asked me to extend back to the previous hop.");
    return -1;
  }

  n_conn = connection_or_get_for_extend(id_digest,
                                        &n_addr,
                                        &msg,
                                        &should_launch);

  if (!n_conn) {
    log_debug(LD_CIRC|LD_OR,"Next router (%s:%d): %s",
              fmt_addr(&n_addr), (int)n_port, msg?msg:"????");

    circ->n_hop = extend_info_alloc(NULL /*nickname*/,
                                    id_digest,
                                    NULL /*onion_key*/,
                                    &n_addr, n_port);

    circ->n_conn_onionskin = tor_malloc(ONIONSKIN_CHALLENGE_LEN);
    memcpy(circ->n_conn_onionskin, onionskin, ONIONSKIN_CHALLENGE_LEN);
    circuit_set_state(circ, CIRCUIT_STATE_OR_WAIT);

    if (should_launch) {
      /* we should try to open a connection */
      n_conn = connection_or_connect(&n_addr, n_port, id_digest);
      if (!n_conn) {
        log_info(LD_CIRC,"Launching n_conn failed. Closing circuit.");
        circuit_mark_for_close(circ, END_CIRC_REASON_CONNECTFAILED);
        return 0;
      }
      log_debug(LD_CIRC,"connecting in progress (or finished). Good.");
    }
    /* return success. The onion/circuit/etc will be taken care of
     * automatically (may already have been) whenever n_conn reaches
     * OR_CONN_STATE_OPEN.
     */
    return 0;
  }

  tor_assert(!circ->n_hop); /* Connection is already established. */
  circ->n_conn = n_conn;
  log_debug(LD_CIRC,"n_conn is %s:%u",
            n_conn->_base.address,n_conn->_base.port);

  if (circuit_deliver_create_cell(circ, CELL_CREATE, onionskin) < 0)
    return -1;
  return 0;
}

/** Initialize cpath-\>{f|b}_{crypto|digest} from the key material in
 * key_data.  key_data must contain CPATH_KEY_MATERIAL bytes, which are
 * used as follows:
 *   - 20 to initialize f_digest
 *   - 20 to initialize b_digest
 *   - 16 to key f_crypto
 *   - 16 to key b_crypto
 *
 * (If 'reverse' is true, then f_XX and b_XX are swapped.)
 */
int
circuit_init_cpath_crypto(crypt_path_t *cpath, const char *key_data,
                          int reverse)
{
  crypto_digest_t *tmp_digest;
  crypto_cipher_t *tmp_crypto;

  tor_assert(cpath);
  tor_assert(key_data);
  tor_assert(!(cpath->f_crypto || cpath->b_crypto ||
             cpath->f_digest || cpath->b_digest));

  cpath->f_digest = crypto_digest_new();
  crypto_digest_add_bytes(cpath->f_digest, key_data, DIGEST_LEN);
  cpath->b_digest = crypto_digest_new();
  crypto_digest_add_bytes(cpath->b_digest, key_data+DIGEST_LEN, DIGEST_LEN);

  if (!(cpath->f_crypto =
        crypto_cipher_new(key_data+(2*DIGEST_LEN)))) {
    log_warn(LD_BUG,"Forward cipher initialization failed.");
    return -1;
  }
  if (!(cpath->b_crypto =
        crypto_cipher_new(key_data+(2*DIGEST_LEN)+CIPHER_KEY_LEN))) {
    log_warn(LD_BUG,"Backward cipher initialization failed.");
    return -1;
  }

  if (reverse) {
    tmp_digest = cpath->f_digest;
    cpath->f_digest = cpath->b_digest;
    cpath->b_digest = tmp_digest;
    tmp_crypto = cpath->f_crypto;
    cpath->f_crypto = cpath->b_crypto;
    cpath->b_crypto = tmp_crypto;
  }

  return 0;
}

/** The minimum number of first hop completions before we start
  * thinking about warning about path bias and dropping guards */
static int
pathbias_get_min_circs(const or_options_t *options)
{
#define DFLT_PATH_BIAS_MIN_CIRC 20
  if (options->PathBiasCircThreshold >= 5)
    return options->PathBiasCircThreshold;
  else
    return networkstatus_get_param(NULL, "pb_mincircs",
                                   DFLT_PATH_BIAS_MIN_CIRC,
                                   5, INT32_MAX);
}

static double
pathbias_get_notice_rate(const or_options_t *options)
{
#define DFLT_PATH_BIAS_NOTICE_PCT 40
  if (options->PathBiasNoticeRate >= 0.0)
    return options->PathBiasNoticeRate;
  else
    return networkstatus_get_param(NULL, "pb_noticepct",
                                   DFLT_PATH_BIAS_NOTICE_PCT, 0, 100)/100.0;
}

static double
pathbias_get_disable_rate(const or_options_t *options)
{
// XXX: This needs tuning based on use + experimentation before we set it
#define DFLT_PATH_BIAS_DISABLE_PCT 0
  if (options->PathBiasDisableRate >= 0.0)
    return options->PathBiasDisableRate;
  else
    return networkstatus_get_param(NULL, "pb_disablepct",
                                   DFLT_PATH_BIAS_DISABLE_PCT, 0, 100)/100.0;
}

static int
pathbias_get_scale_threshold(const or_options_t *options)
{
#define DFLT_PATH_BIAS_SCALE_THRESHOLD 200
  if (options->PathBiasScaleThreshold >= 2)
    return options->PathBiasScaleThreshold;
  else
    return networkstatus_get_param(NULL, "pb_scalecircs",
                                   DFLT_PATH_BIAS_SCALE_THRESHOLD, 10,
                                   INT32_MAX);
}

static int
pathbias_get_scale_factor(const or_options_t *options)
{
#define DFLT_PATH_BIAS_SCALE_FACTOR 4
  if (options->PathBiasScaleFactor >= 1)
    return options->PathBiasScaleFactor;
  else
    return networkstatus_get_param(NULL, "pb_scalefactor",
                                DFLT_PATH_BIAS_SCALE_THRESHOLD, 1, INT32_MAX);
}

static const char *
pathbias_state_to_string(path_state_t state)
{
  switch (state) {
    case PATH_STATE_NEW_CIRC:
      return "new";
    case PATH_STATE_DID_FIRST_HOP:
      return "first hop";
    case PATH_STATE_SUCCEEDED:
      return "succeeded";
  }

  return "unknown";
}

/**
 * Check our circuit state to see if this is a successful first hop.
 * If so, record it in the current guard's path bias first_hop count.
 *
 * Also check for several potential error cases for bug #6475.
 */
static int
pathbias_count_first_hop(origin_circuit_t *circ)
{
#define FIRST_HOP_NOTICE_INTERVAL (600)
  static ratelim_t first_hop_notice_limit =
    RATELIM_INIT(FIRST_HOP_NOTICE_INTERVAL);
  char *rate_msg = NULL;

  /* Completely ignore one hop circuits */
  if (circ->build_state->onehop_tunnel ||
      circ->build_state->desired_path_len == 1) {
    /* Check for inconsistency */
    if (circ->build_state->desired_path_len != 1 ||
        !circ->build_state->onehop_tunnel) {
      if ((rate_msg = rate_limit_log(&first_hop_notice_limit,
              approx_time()))) {
        log_info(LD_BUG,
               "One-hop circuit has length %d. Path state is %s. "
               "Circuit is a %s currently %s.%s",
               circ->build_state->desired_path_len,
               pathbias_state_to_string(circ->path_state),
               circuit_purpose_to_string(circ->_base.purpose),
               circuit_state_to_string(circ->_base.state),
               rate_msg);
        tor_free(rate_msg);
      }
      tor_fragile_assert();
    }
    return 0;
  }

  if (circ->cpath->state == CPATH_STATE_AWAITING_KEYS) {
    /* Help track down the real cause of bug #6475: */
    if (circ->has_opened && circ->path_state != PATH_STATE_DID_FIRST_HOP) {
      if ((rate_msg = rate_limit_log(&first_hop_notice_limit,
                                     approx_time()))) {
        log_info(LD_BUG,
                "Opened circuit is in strange path state %s. "
                "Circuit is a %s currently %s.%s",
                pathbias_state_to_string(circ->path_state),
                circuit_purpose_to_string(circ->_base.purpose),
                circuit_state_to_string(circ->_base.state),
                rate_msg);
        tor_free(rate_msg);
      }
    }

    /* Don't count cannibalized circs for path bias */
    if (!circ->has_opened) {
      entry_guard_t *guard;

      guard = entry_guard_get_by_id_digest(
              circ->_base.n_conn->identity_digest);
      if (guard) {
        if (circ->path_state == PATH_STATE_NEW_CIRC) {
          circ->path_state = PATH_STATE_DID_FIRST_HOP;

          if (entry_guard_inc_first_hop_count(guard) < 0) {
            /* Bogus guard; we already warned. */
            return -END_CIRC_REASON_TORPROTOCOL;
          }
        } else {
          if ((rate_msg = rate_limit_log(&first_hop_notice_limit,
                  approx_time()))) {
            log_info(LD_BUG,
                   "Unopened circuit has strange path state %s. "
                   "Circuit is a %s currently %s.%s",
                   pathbias_state_to_string(circ->path_state),
                   circuit_purpose_to_string(circ->_base.purpose),
                   circuit_state_to_string(circ->_base.state),
                   rate_msg);
            tor_free(rate_msg);
          }
        }
      } else {
        if ((rate_msg = rate_limit_log(&first_hop_notice_limit,
                approx_time()))) {
          log_info(LD_BUG,
              "Unopened circuit has no known guard. "
              "Circuit is a %s currently %s.%s",
              circuit_purpose_to_string(circ->_base.purpose),
              circuit_state_to_string(circ->_base.state),
              rate_msg);
          tor_free(rate_msg);
        }
      }
    }
  } else {
    /* Help track down the real cause of bug #6475: */
    if (circ->path_state == PATH_STATE_NEW_CIRC) {
      if ((rate_msg = rate_limit_log(&first_hop_notice_limit,
                approx_time()))) {
        log_info(LD_BUG,
            "A %s circuit is in cpath state %d (opened: %d). "
            "Circuit is a %s currently %s.%s",
            pathbias_state_to_string(circ->path_state),
            circ->cpath->state, circ->has_opened,
            circuit_purpose_to_string(circ->_base.purpose),
            circuit_state_to_string(circ->_base.state),
            rate_msg);
        tor_free(rate_msg);
      }
    }
  }

  return 0;
}

/**
 * Check our circuit state to see if this is a successful circuit
 * completion. If so, record it in the current guard's path bias
 * success count.
 *
 * Also check for several potential error cases for bug #6475.
 */
static void
pathbias_count_success(origin_circuit_t *circ)
{
#define SUCCESS_NOTICE_INTERVAL (600)
  static ratelim_t success_notice_limit =
    RATELIM_INIT(SUCCESS_NOTICE_INTERVAL);
  char *rate_msg = NULL;

  /* Ignore one hop circuits */
  if (circ->build_state->onehop_tunnel ||
      circ->build_state->desired_path_len == 1) {
    /* Check for consistency */
    if (circ->build_state->desired_path_len != 1 ||
        !circ->build_state->onehop_tunnel) {
      if ((rate_msg = rate_limit_log(&success_notice_limit,
              approx_time()))) {
        log_info(LD_BUG,
               "One-hop circuit has length %d. Path state is %s. "
               "Circuit is a %s currently %s.%s",
               circ->build_state->desired_path_len,
               pathbias_state_to_string(circ->path_state),
               circuit_purpose_to_string(circ->_base.purpose),
               circuit_state_to_string(circ->_base.state),
               rate_msg);
        tor_free(rate_msg);
      }
      tor_fragile_assert();
    }
    return;
  }

  /* Don't count cannibalized/reused circs for path bias */
  if (!circ->has_opened) {
    entry_guard_t *guard =
      entry_guard_get_by_id_digest(circ->_base.n_conn->identity_digest);

    if (guard) {
      if (circ->path_state == PATH_STATE_DID_FIRST_HOP) {
        circ->path_state = PATH_STATE_SUCCEEDED;
        guard->circuit_successes++;

        log_info(LD_PROTOCOL, "Got success count %u/%u for guard %s=%s",
                 guard->circuit_successes, guard->first_hops,
                 guard->nickname, hex_str(guard->identity, DIGEST_LEN));
      } else {
        if ((rate_msg = rate_limit_log(&success_notice_limit,
                approx_time()))) {
          log_info(LD_BUG,
              "Succeeded circuit is in strange path state %s. "
              "Circuit is a %s currently %s.%s",
              pathbias_state_to_string(circ->path_state),
              circuit_purpose_to_string(circ->_base.purpose),
              circuit_state_to_string(circ->_base.state),
              rate_msg);
          tor_free(rate_msg);
        }
      }

      if (guard->first_hops < guard->circuit_successes) {
        log_info(LD_BUG, "Unexpectedly high circuit_successes (%u/%u) "
                 "for guard %s=%s",
                 guard->circuit_successes, guard->first_hops,
                 guard->nickname, hex_str(guard->identity, DIGEST_LEN));
      }
    } else {
      if ((rate_msg = rate_limit_log(&success_notice_limit,
              approx_time()))) {
        log_info(LD_BUG,
            "Completed circuit has no known guard. "
            "Circuit is a %s currently %s.%s",
            circuit_purpose_to_string(circ->_base.purpose),
            circuit_state_to_string(circ->_base.state),
            rate_msg);
        tor_free(rate_msg);
      }
    }
  } else {
    if (circ->path_state != PATH_STATE_SUCCEEDED) {
      if ((rate_msg = rate_limit_log(&success_notice_limit,
              approx_time()))) {
        log_info(LD_BUG,
            "Opened circuit is in strange path state %s. "
            "Circuit is a %s currently %s.%s",
            pathbias_state_to_string(circ->path_state),
            circuit_purpose_to_string(circ->_base.purpose),
            circuit_state_to_string(circ->_base.state),
            rate_msg);
        tor_free(rate_msg);
      }
    }
  }
}

/** Increment the number of times we successfully extended a circuit to
 * 'guard', first checking if the failure rate is high enough that we should
 * eliminate the guard.  Return -1 if the guard looks no good; return 0 if the
 * guard looks fine. */
static int
entry_guard_inc_first_hop_count(entry_guard_t *guard)
{
  const or_options_t *options = get_options();

  entry_guards_changed();

  if (guard->first_hops > (unsigned)pathbias_get_min_circs(options)) {
    /* Note: We rely on the < comparison here to allow us to set a 0
     * rate and disable the feature entirely. If refactoring, don't
     * change to <= */
    if (guard->circuit_successes/((double)guard->first_hops)
        < pathbias_get_disable_rate(options)) {

      log_info(LD_PROTOCOL,
               "Extremely low circuit success rate %u/%u for guard %s=%s. "
               "This might indicate an attack, or a bug.",
               guard->circuit_successes, guard->first_hops, guard->nickname,
               hex_str(guard->identity, DIGEST_LEN));

      guard->path_bias_disabled = 1;
      guard->bad_since = approx_time();
      return -1;
    } else if (guard->circuit_successes/((double)guard->first_hops)
               < pathbias_get_notice_rate(options)
               && !guard->path_bias_notice) {
      guard->path_bias_notice = 1;
      log_info(LD_PROTOCOL,
                 "Low circuit success rate %u/%u for guard %s=%s.",
                 guard->circuit_successes, guard->first_hops, guard->nickname,
                 hex_str(guard->identity, DIGEST_LEN));
    }
  }

  /* If we get a ton of circuits, just scale everything down */
  if (guard->first_hops > (unsigned)pathbias_get_scale_threshold(options)) {
    const int scale_factor = pathbias_get_scale_factor(options);
    guard->first_hops /= scale_factor;
    guard->circuit_successes /= scale_factor;
  }
  guard->first_hops++;
  log_info(LD_PROTOCOL, "Got success count %u/%u for guard %s=%s",
           guard->circuit_successes, guard->first_hops, guard->nickname,
           hex_str(guard->identity, DIGEST_LEN));
  return 0;
}

/** A created or extended cell came back to us on the circuit, and it included
 * <b>reply</b> as its body.  (If <b>reply_type</b> is CELL_CREATED, the body
 * contains (the second DH key, plus KH).  If <b>reply_type</b> is
 * CELL_CREATED_FAST, the body contains a secret y and a hash H(x|y).)
 *
 * Calculate the appropriate keys and digests, make sure KH is
 * correct, and initialize this hop of the cpath.
 *
 * Return - reason if we want to mark circ for close, else return 0.
 */
int
circuit_finish_handshake(origin_circuit_t *circ, uint8_t reply_type,
                         const uint8_t *reply)
{
  char keys[CPATH_KEY_MATERIAL_LEN];
  crypt_path_t *hop;
  int rv;

  if ((rv = pathbias_count_first_hop(circ)) < 0)
    return rv;

  if (circ->cpath->state == CPATH_STATE_AWAITING_KEYS) {
    hop = circ->cpath;
  } else {
    hop = onion_next_hop_in_cpath(circ->cpath);
    if (!hop) { /* got an extended when we're all done? */
      log_warn(LD_PROTOCOL,"got extended when circ already built? Closing.");
      return - END_CIRC_REASON_TORPROTOCOL;
    }
  }
  tor_assert(hop->state == CPATH_STATE_AWAITING_KEYS);

  if (reply_type == CELL_CREATED && hop->dh_handshake_state) {
    if (onion_skin_client_handshake(hop->dh_handshake_state, (char*)reply,keys,
                                    DIGEST_LEN*2+CIPHER_KEY_LEN*2) < 0) {
      log_warn(LD_CIRC,"onion_skin_client_handshake failed.");
      return -END_CIRC_REASON_TORPROTOCOL;
    }
    /* Remember hash of g^xy */
    memcpy(hop->handshake_digest, reply+DH_KEY_LEN, DIGEST_LEN);
  } else if (reply_type == CELL_CREATED_FAST && !hop->dh_handshake_state) {
    if (fast_client_handshake(hop->fast_handshake_state, reply,
                              (uint8_t*)keys,
                              DIGEST_LEN*2+CIPHER_KEY_LEN*2) < 0) {
      log_warn(LD_CIRC,"fast_client_handshake failed.");
      return -END_CIRC_REASON_TORPROTOCOL;
    }
    memcpy(hop->handshake_digest, reply+DIGEST_LEN, DIGEST_LEN);
  } else {
    log_warn(LD_PROTOCOL,"CREATED cell type did not match CREATE cell type.");
    return -END_CIRC_REASON_TORPROTOCOL;
  }

  crypto_dh_free(hop->dh_handshake_state); /* don't need it anymore */
  hop->dh_handshake_state = NULL;

  memset(hop->fast_handshake_state, 0, sizeof(hop->fast_handshake_state));

  if (circuit_init_cpath_crypto(hop, keys, 0)<0) {
    return -END_CIRC_REASON_TORPROTOCOL;
  }

  hop->state = CPATH_STATE_OPEN;
  log_info(LD_CIRC,"Finished building %scircuit hop:",
           (reply_type == CELL_CREATED_FAST) ? "fast " : "");
  circuit_log_path(LOG_INFO,LD_CIRC,circ);
  control_event_circuit_status(circ, CIRC_EVENT_EXTENDED, 0);

  return 0;
}

/** We received a relay truncated cell on circ.
 *
 * Since we don't ask for truncates currently, getting a truncated
 * means that a connection broke or an extend failed. For now,
 * just give up: for circ to close, and return 0.
 */
int
circuit_truncated(origin_circuit_t *circ, crypt_path_t *layer)
{
//  crypt_path_t *victim;
//  connection_t *stream;

  tor_assert(circ);
  tor_assert(layer);

  /* XXX Since we don't ask for truncates currently, getting a truncated
   *     means that a connection broke or an extend failed. For now,
   *     just give up.
   */
  circuit_mark_for_close(TO_CIRCUIT(circ),
          END_CIRC_REASON_FLAG_REMOTE|END_CIRC_REASON_OR_CONN_CLOSED);
  return 0;

#if 0
  while (layer->next != circ->cpath) {
    /* we need to clear out layer->next */
    victim = layer->next;
    log_debug(LD_CIRC, "Killing a layer of the cpath.");

    for (stream = circ->p_streams; stream; stream=stream->next_stream) {
      if (stream->cpath_layer == victim) {
        log_info(LD_APP, "Marking stream %d for close because of truncate.",
                 stream->stream_id);
        /* no need to send 'end' relay cells,
         * because the other side's already dead
         */
        connection_mark_unattached_ap(stream, END_STREAM_REASON_DESTROY);
      }
    }

    layer->next = victim->next;
    circuit_free_cpath_node(victim);
  }

  log_info(LD_CIRC, "finished");
  return 0;
#endif
}

/** Given a response payload and keys, initialize, then send a created
 * cell back.
 */
int
onionskin_answer(or_circuit_t *circ, uint8_t cell_type, const char *payload,
                 const char *keys)
{
  cell_t cell;
  crypt_path_t *tmp_cpath;

  tmp_cpath = tor_malloc_zero(sizeof(crypt_path_t));
  tmp_cpath->magic = CRYPT_PATH_MAGIC;

  memset(&cell, 0, sizeof(cell_t));
  cell.command = cell_type;
  cell.circ_id = circ->p_circ_id;

  circuit_set_state(TO_CIRCUIT(circ), CIRCUIT_STATE_OPEN);

  memcpy(cell.payload, payload,
         cell_type == CELL_CREATED ? ONIONSKIN_REPLY_LEN : DIGEST_LEN*2);

  log_debug(LD_CIRC,"init digest forward 0x%.8x, backward 0x%.8x.",
            (unsigned int)get_uint32(keys),
            (unsigned int)get_uint32(keys+20));
  if (circuit_init_cpath_crypto(tmp_cpath, keys, 0)<0) {
    log_warn(LD_BUG,"Circuit initialization failed");
    tor_free(tmp_cpath);
    return -1;
  }
  circ->n_digest = tmp_cpath->f_digest;
  circ->n_crypto = tmp_cpath->f_crypto;
  circ->p_digest = tmp_cpath->b_digest;
  circ->p_crypto = tmp_cpath->b_crypto;
  tmp_cpath->magic = 0;
  tor_free(tmp_cpath);

  if (cell_type == CELL_CREATED)
    memcpy(circ->handshake_digest, cell.payload+DH_KEY_LEN, DIGEST_LEN);
  else
    memcpy(circ->handshake_digest, cell.payload+DIGEST_LEN, DIGEST_LEN);

  circ->is_first_hop = (cell_type == CELL_CREATED_FAST);

  append_cell_to_circuit_queue(TO_CIRCUIT(circ),
                               circ->p_conn, &cell, CELL_DIRECTION_IN, 0);
  log_debug(LD_CIRC,"Finished sending '%s' cell.",
            circ->is_first_hop ? "created_fast" : "created");

  if (!is_local_addr(&circ->p_conn->_base.addr) &&
      !connection_or_nonopen_was_started_here(circ->p_conn)) {
    /* record that we could process create cells from a non-local conn
     * that we didn't initiate; presumably this means that create cells
     * can reach us too. */
    router_orport_found_reachable();
  }

  return 0;
}

/** Choose a length for a circuit of purpose <b>purpose</b>.
 * Default length is 3 + the number of endpoints that would give something
 * away. If the routerlist <b>routers</b> doesn't have enough routers
 * to handle the desired path length, return as large a path length as
 * is feasible, except if it's less than 2, in which case return -1.
 */
static int
new_route_len(uint8_t purpose, extend_info_t *exit,
              smartlist_t *nodes)
{
  int num_acceptable_routers;
  int routelen;

  tor_assert(nodes);

  routelen = DEFAULT_ROUTE_LEN;
  if (exit &&
      purpose != CIRCUIT_PURPOSE_TESTING &&
      purpose != CIRCUIT_PURPOSE_S_ESTABLISH_INTRO)
    routelen++;

  num_acceptable_routers = count_acceptable_nodes(nodes);

  log_debug(LD_CIRC,"Chosen route length %d (%d/%d routers suitable).",
            routelen, num_acceptable_routers, smartlist_len(nodes));

  if (num_acceptable_routers < 2) {
    log_info(LD_CIRC,
             "Not enough acceptable routers (%d). Discarding this circuit.",
             num_acceptable_routers);
    return -1;
  }

  if (num_acceptable_routers < routelen) {
    log_info(LD_CIRC,"Not enough routers: cutting routelen from %d to %d.",
             routelen, num_acceptable_routers);
    routelen = num_acceptable_routers;
  }

  return routelen;
}

/** Return a newly allocated list of uint16_t * for each predicted port not
 * handled by a current circuit. */
static smartlist_t *
circuit_get_unhandled_ports(time_t now)
{
  smartlist_t *dest = rep_hist_get_predicted_ports(now);
  circuit_remove_handled_ports(dest);
  return dest;
}

/** Return 1 if we already have circuits present or on the way for
 * all anticipated ports. Return 0 if we should make more.
 *
 * If we're returning 0, set need_uptime and need_capacity to
 * indicate any requirements that the unhandled ports have.
 */
int
circuit_all_predicted_ports_handled(time_t now, int *need_uptime,
                                    int *need_capacity)
{
  int i, enough;
  uint16_t *port;
  smartlist_t *sl = circuit_get_unhandled_ports(now);
  smartlist_t *LongLivedServices = get_options()->LongLivedPorts;
  tor_assert(need_uptime);
  tor_assert(need_capacity);
  // Always predict need_capacity
  *need_capacity = 1;
  enough = (smartlist_len(sl) == 0);
  for (i = 0; i < smartlist_len(sl); ++i) {
    port = smartlist_get(sl, i);
    if (smartlist_string_num_isin(LongLivedServices, *port))
      *need_uptime = 1;
    tor_free(port);
  }
  smartlist_free(sl);
  return enough;
}

/** Return 1 if <b>node</b> can handle one or more of the ports in
 * <b>needed_ports</b>, else return 0.
 */
static int
node_handles_some_port(const node_t *node, smartlist_t *needed_ports)
{ /* XXXX MOVE */
  int i;
  uint16_t port;

  for (i = 0; i < smartlist_len(needed_ports); ++i) {
    addr_policy_result_t r;
    /* alignment issues aren't a worry for this dereference, since
       needed_ports is explicitly a smartlist of uint16_t's */
    port = *(uint16_t *)smartlist_get(needed_ports, i);
    tor_assert(port);
    if (node)
      r = compare_tor_addr_to_node_policy(NULL, port, node);
    else
      continue;
    if (r != ADDR_POLICY_REJECTED && r != ADDR_POLICY_PROBABLY_REJECTED)
      return 1;
  }
  return 0;
}

/** Return true iff <b>conn</b> needs another general circuit to be
 * built. */
static int
ap_stream_wants_exit_attention(connection_t *conn)
{
  entry_connection_t *entry;
  if (conn->type != CONN_TYPE_AP)
    return 0;
  entry = TO_ENTRY_CONN(conn);

  if (conn->state == AP_CONN_STATE_CIRCUIT_WAIT &&
      !conn->marked_for_close &&
      !(entry->want_onehop) && /* ignore one-hop streams */
      !(entry->use_begindir) && /* ignore targeted dir fetches */
      !(entry->chosen_exit_name) && /* ignore defined streams */
      !connection_edge_is_rendezvous_stream(TO_EDGE_CONN(conn)) &&
      !circuit_stream_is_being_handled(TO_ENTRY_CONN(conn), 0,
                                       MIN_CIRCUITS_HANDLING_STREAM))
    return 1;
  return 0;
}

/** Return a pointer to a suitable router to be the exit node for the
 * general-purpose circuit we're about to build.
 *
 * Look through the connection array, and choose a router that maximizes
 * the number of pending streams that can exit from this router.
 *
 * Return NULL if we can't find any suitable routers.
 */
static const node_t *
choose_good_exit_server_general(int need_uptime, int need_capacity)
{
  int *n_supported;
  int n_pending_connections = 0;
  smartlist_t *connections;
  int best_support = -1;
  int n_best_support=0;
  const or_options_t *options = get_options();
  const smartlist_t *the_nodes;
  const node_t *node=NULL;

  connections = get_connection_array();

  /* Count how many connections are waiting for a circuit to be built.
   * We use this for log messages now, but in the future we may depend on it.
   */
  SMARTLIST_FOREACH(connections, connection_t *, conn,
  {
    if (ap_stream_wants_exit_attention(conn))
      ++n_pending_connections;
  });
//  log_fn(LOG_DEBUG, "Choosing exit node; %d connections are pending",
//         n_pending_connections);
  /* Now we count, for each of the routers in the directory, how many
   * of the pending connections could possibly exit from that
   * router (n_supported[i]). (We can't be sure about cases where we
   * don't know the IP address of the pending connection.)
   *
   * -1 means "Don't use this router at all."
   */
  the_nodes = nodelist_get_list();
  n_supported = tor_malloc(sizeof(int)*smartlist_len(the_nodes));
  SMARTLIST_FOREACH_BEGIN(the_nodes, const node_t *, node) {
    const int i = node_sl_idx;
    if (router_digest_is_me(node->identity)) {
      n_supported[i] = -1;
//      log_fn(LOG_DEBUG,"Skipping node %s -- it's me.", router->nickname);
      /* XXX there's probably a reverse predecessor attack here, but
       * it's slow. should we take this out? -RD
       */
      continue;
    }
    if (!node_has_descriptor(node)) {
      n_supported[i] = -1;
      continue;
    }
    if (!node->is_running || node->is_bad_exit) {
      n_supported[i] = -1;
      continue; /* skip routers that are known to be down or bad exits */
    }
    if (node_get_purpose(node) != ROUTER_PURPOSE_GENERAL) {
      /* never pick a non-general node as a random exit. */
      n_supported[i] = -1;
      continue;
    }
    if (routerset_contains_node(options->_ExcludeExitNodesUnion, node)) {
      n_supported[i] = -1;
      continue; /* user asked us not to use it, no matter what */
    }
    if (options->ExitNodes &&
        !routerset_contains_node(options->ExitNodes, node)) {
      n_supported[i] = -1;
      continue; /* not one of our chosen exit nodes */
    }

    if (node_is_unreliable(node, need_uptime, need_capacity, 0)) {
      n_supported[i] = -1;
      continue; /* skip routers that are not suitable.  Don't worry if
                 * this makes us reject all the possible routers: if so,
                 * we'll retry later in this function with need_update and
                 * need_capacity set to 0. */
    }
    if (!(node->is_valid || options->_AllowInvalid & ALLOW_INVALID_EXIT)) {
      /* if it's invalid and we don't want it */
      n_supported[i] = -1;
//      log_fn(LOG_DEBUG,"Skipping node %s (index %d) -- invalid router.",
//             router->nickname, i);
      continue; /* skip invalid routers */
    }
    if (options->ExcludeSingleHopRelays &&
        node_allows_single_hop_exits(node)) {
      n_supported[i] = -1;
      continue;
    }
    if (node_exit_policy_rejects_all(node)) {
      n_supported[i] = -1;
//      log_fn(LOG_DEBUG,"Skipping node %s (index %d) -- it rejects all.",
//             router->nickname, i);
      continue; /* skip routers that reject all */
    }
    n_supported[i] = 0;
    /* iterate over connections */
    SMARTLIST_FOREACH_BEGIN(connections, connection_t *, conn) {
      if (!ap_stream_wants_exit_attention(conn))
        continue; /* Skip everything but APs in CIRCUIT_WAIT */
      if (connection_ap_can_use_exit(TO_ENTRY_CONN(conn), node)) {
        ++n_supported[i];
//        log_fn(LOG_DEBUG,"%s is supported. n_supported[%d] now %d.",
//               router->nickname, i, n_supported[i]);
      } else {
//        log_fn(LOG_DEBUG,"%s (index %d) would reject this stream.",
//               router->nickname, i);
      }
    } SMARTLIST_FOREACH_END(conn);
    if (n_pending_connections > 0 && n_supported[i] == 0) {
      /* Leave best_support at -1 if that's where it is, so we can
       * distinguish it later. */
      continue;
    }
    if (n_supported[i] > best_support) {
      /* If this router is better than previous ones, remember its index
       * and goodness, and start counting how many routers are this good. */
      best_support = n_supported[i]; n_best_support=1;
//      log_fn(LOG_DEBUG,"%s is new best supported option so far.",
//             router->nickname);
    } else if (n_supported[i] == best_support) {
      /* If this router is _as good_ as the best one, just increment the
       * count of equally good routers.*/
      ++n_best_support;
    }
  } SMARTLIST_FOREACH_END(node);
  log_info(LD_CIRC,
           "Found %d servers that might support %d/%d pending connections.",
           n_best_support, best_support >= 0 ? best_support : 0,
           n_pending_connections);

  /* If any routers definitely support any pending connections, choose one
   * at random. */
  if (best_support > 0) {
    smartlist_t *supporting = smartlist_new();

    SMARTLIST_FOREACH(the_nodes, const node_t *, node, {
      if (n_supported[node_sl_idx] == best_support)
        smartlist_add(supporting, (void*)node);
    });

    node = node_sl_choose_by_bandwidth(supporting, WEIGHT_FOR_EXIT);
    smartlist_free(supporting);
  } else {
    /* Either there are no pending connections, or no routers even seem to
     * possibly support any of them.  Choose a router at random that satisfies
     * at least one predicted exit port. */

    int attempt;
    smartlist_t *needed_ports, *supporting;

    if (best_support == -1) {
      if (need_uptime || need_capacity) {
        log_info(LD_CIRC,
                 "We couldn't find any live%s%s routers; falling back "
                 "to list of all routers.",
                 need_capacity?", fast":"",
                 need_uptime?", stable":"");
        tor_free(n_supported);
        return choose_good_exit_server_general(0, 0);
      }
      log_notice(LD_CIRC, "All routers are down or won't exit%s -- "
                 "choosing a doomed exit at random.",
                 options->_ExcludeExitNodesUnion ? " or are Excluded" : "");
    }
    supporting = smartlist_new();
    needed_ports = circuit_get_unhandled_ports(time(NULL));
    for (attempt = 0; attempt < 2; attempt++) {
      /* try once to pick only from routers that satisfy a needed port,
       * then if there are none, pick from any that support exiting. */
      SMARTLIST_FOREACH_BEGIN(the_nodes, const node_t *, node) {
        if (n_supported[node_sl_idx] != -1 &&
            (attempt || node_handles_some_port(node, needed_ports))) {
//          log_fn(LOG_DEBUG,"Try %d: '%s' is a possibility.",
//                 try, router->nickname);
          smartlist_add(supporting, (void*)node);
        }
      } SMARTLIST_FOREACH_END(node);

      node = node_sl_choose_by_bandwidth(supporting, WEIGHT_FOR_EXIT);
      if (node)
        break;
      smartlist_clear(supporting);
      /* If we reach this point, we can't actually support any unhandled
       * predicted ports, so clear all the remaining ones. */
      if (smartlist_len(needed_ports))
        rep_hist_remove_predicted_ports(needed_ports);
    }
    SMARTLIST_FOREACH(needed_ports, uint16_t *, cp, tor_free(cp));
    smartlist_free(needed_ports);
    smartlist_free(supporting);
  }

  tor_free(n_supported);
  if (node) {
    log_info(LD_CIRC, "Chose exit server '%s'", node_describe(node));
    return node;
  }
  if (options->ExitNodes) {
    log_warn(LD_CIRC,
             "No specified %sexit routers seem to be running: "
             "can't choose an exit.",
             options->_ExcludeExitNodesUnion ? "non-excluded " : "");
  }
  return NULL;
}

/** Return a pointer to a suitable router to be the exit node for the
 * circuit of purpose <b>purpose</b> that we're about to build (or NULL
 * if no router is suitable).
 *
 * For general-purpose circuits, pass it off to
 * choose_good_exit_server_general()
 *
 * For client-side rendezvous circuits, choose a random node, weighted
 * toward the preferences in 'options'.
 */
static const node_t *
choose_good_exit_server(uint8_t purpose,
                        int need_uptime, int need_capacity, int is_internal)
{
  const or_options_t *options = get_options();
  router_crn_flags_t flags = CRN_NEED_DESC;
  if (need_uptime)
    flags |= CRN_NEED_UPTIME;
  if (need_capacity)
    flags |= CRN_NEED_CAPACITY;

  switch (purpose) {
    case CIRCUIT_PURPOSE_C_GENERAL:
      if (options->_AllowInvalid & ALLOW_INVALID_MIDDLE)
        flags |= CRN_ALLOW_INVALID;
      if (is_internal) /* pick it like a middle hop */
        return router_choose_random_node(NULL, options->ExcludeNodes, flags);
      else
        return choose_good_exit_server_general(need_uptime,need_capacity);
    case CIRCUIT_PURPOSE_C_ESTABLISH_REND:
      if (options->_AllowInvalid & ALLOW_INVALID_RENDEZVOUS)
        flags |= CRN_ALLOW_INVALID;
      return router_choose_random_node(NULL, options->ExcludeNodes, flags);
  }
  log_warn(LD_BUG,"Unhandled purpose %d", purpose);
  tor_fragile_assert();
  return NULL;
}

/** Log a warning if the user specified an exit for the circuit that
 * has been excluded from use by ExcludeNodes or ExcludeExitNodes. */
static void
warn_if_last_router_excluded(origin_circuit_t *circ, const extend_info_t *exit)
{
  const or_options_t *options = get_options();
  routerset_t *rs = options->ExcludeNodes;
  const char *description;
  uint8_t purpose = circ->_base.purpose;

  if (circ->build_state->onehop_tunnel)
    return;

  switch (purpose)
    {
    default:
    case CIRCUIT_PURPOSE_OR:
    case CIRCUIT_PURPOSE_INTRO_POINT:
    case CIRCUIT_PURPOSE_REND_POINT_WAITING:
    case CIRCUIT_PURPOSE_REND_ESTABLISHED:
      log_warn(LD_BUG, "Called on non-origin circuit (purpose %d, %s)",
               (int)purpose,
               circuit_purpose_to_string(purpose));
      return;
    case CIRCUIT_PURPOSE_C_GENERAL:
      if (circ->build_state->is_internal)
        return;
      description = "requested exit node";
      rs = options->_ExcludeExitNodesUnion;
      break;
    case CIRCUIT_PURPOSE_C_INTRODUCING:
    case CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT:
    case CIRCUIT_PURPOSE_C_INTRODUCE_ACKED:
    case CIRCUIT_PURPOSE_S_ESTABLISH_INTRO:
    case CIRCUIT_PURPOSE_S_CONNECT_REND:
    case CIRCUIT_PURPOSE_S_REND_JOINED:
    case CIRCUIT_PURPOSE_TESTING:
      return;
    case CIRCUIT_PURPOSE_C_ESTABLISH_REND:
    case CIRCUIT_PURPOSE_C_REND_READY:
    case CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED:
    case CIRCUIT_PURPOSE_C_REND_JOINED:
      description = "chosen rendezvous point";
      break;
    case CIRCUIT_PURPOSE_CONTROLLER:
      rs = options->_ExcludeExitNodesUnion;
      description = "controller-selected circuit target";
      break;
    }

  if (routerset_contains_extendinfo(rs, exit)) {
    /* We should never get here if StrictNodes is set to 1. */
    if (options->StrictNodes) {
      log_warn(LD_BUG, "Using %s '%s' which is listed in ExcludeNodes%s, "
               "even though StrictNodes is set. Please report. "
               "(Circuit purpose: %s)",
               description, extend_info_describe(exit),
               rs==options->ExcludeNodes?"":" or ExcludeExitNodes",
               circuit_purpose_to_string(purpose));
    } else {
      log_warn(LD_CIRC, "Using %s '%s' which is listed in "
               "ExcludeNodes%s, because no better options were available. To "
               "prevent this (and possibly break your Tor functionality), "
               "set the StrictNodes configuration option. "
               "(Circuit purpose: %s)",
               description, extend_info_describe(exit),
               rs==options->ExcludeNodes?"":" or ExcludeExitNodes",
               circuit_purpose_to_string(purpose));
    }
    circuit_log_path(LOG_WARN, LD_CIRC, circ);
  }

  return;
}

/** Decide a suitable length for circ's cpath, and pick an exit
 * router (or use <b>exit</b> if provided). Store these in the
 * cpath. Return 0 if ok, -1 if circuit should be closed. */
static int
onion_pick_cpath_exit(origin_circuit_t *circ, extend_info_t *exit)
{
  cpath_build_state_t *state = circ->build_state;

  if (state->onehop_tunnel) {
    log_debug(LD_CIRC, "Launching a one-hop circuit for dir tunnel.");
    state->desired_path_len = 1;
  } else {
    int r = new_route_len(circ->_base.purpose, exit, nodelist_get_list());
    if (r < 1) /* must be at least 1 */
      return -1;
    state->desired_path_len = r;
  }

  if (exit) { /* the circuit-builder pre-requested one */
    warn_if_last_router_excluded(circ, exit);
    log_info(LD_CIRC,"Using requested exit node '%s'",
             extend_info_describe(exit));
    exit = extend_info_dup(exit);
  } else { /* we have to decide one */
    const node_t *node =
      choose_good_exit_server(circ->_base.purpose, state->need_uptime,
                              state->need_capacity, state->is_internal);
    if (!node) {
      log_warn(LD_CIRC,"failed to choose an exit server");
      return -1;
    }
    exit = extend_info_from_node(node, 0);
    tor_assert(exit);
  }
  state->chosen_exit = exit;
  return 0;
}

/** Give <b>circ</b> a new exit destination to <b>exit</b>, and add a
 * hop to the cpath reflecting this. Don't send the next extend cell --
 * the caller will do this if it wants to.
 */
int
circuit_append_new_exit(origin_circuit_t *circ, extend_info_t *exit)
{
  cpath_build_state_t *state;
  tor_assert(exit);
  tor_assert(circ);

  state = circ->build_state;
  tor_assert(state);
  extend_info_free(state->chosen_exit);
  state->chosen_exit = extend_info_dup(exit);

  ++circ->build_state->desired_path_len;
  onion_append_hop(&circ->cpath, exit);
  return 0;
}

/** Take an open <b>circ</b>, and add a new hop at the end, based on
 * <b>info</b>. Set its state back to CIRCUIT_STATE_BUILDING, and then
 * send the next extend cell to begin connecting to that hop.
 */
int
circuit_extend_to_new_exit(origin_circuit_t *circ, extend_info_t *exit)
{
  int err_reason = 0;
  warn_if_last_router_excluded(circ, exit);
  circuit_append_new_exit(circ, exit);
  circuit_set_state(TO_CIRCUIT(circ), CIRCUIT_STATE_BUILDING);
  if ((err_reason = circuit_send_next_onion_skin(circ))<0) {
    log_warn(LD_CIRC, "Couldn't extend circuit to new point %s.",
             extend_info_describe(exit));
    circuit_mark_for_close(TO_CIRCUIT(circ), -err_reason);
    return -1;
  }
  return 0;
}

/** Return the number of routers in <b>routers</b> that are currently up
 * and available for building circuits through.
 */
static int
count_acceptable_nodes(smartlist_t *nodes)
{
  int num=0;

  SMARTLIST_FOREACH_BEGIN(nodes, const node_t *, node) {
    //    log_debug(LD_CIRC,
//              "Contemplating whether router %d (%s) is a new option.",
//              i, r->nickname);
    if (! node->is_running)
//      log_debug(LD_CIRC,"Nope, the directory says %d is not running.",i);
      continue;
    if (! node->is_valid)
//      log_debug(LD_CIRC,"Nope, the directory says %d is not valid.",i);
      continue;
    if (! node_has_descriptor(node))
      continue;
      /* XXX This clause makes us count incorrectly: if AllowInvalidRouters
       * allows this node in some places, then we're getting an inaccurate
       * count. For now, be conservative and don't count it. But later we
       * should try to be smarter. */
    ++num;
  } SMARTLIST_FOREACH_END(node);

//    log_debug(LD_CIRC,"I like %d. num_acceptable_routers now %d.",i, num);

  return num;
}

/** Add <b>new_hop</b> to the end of the doubly-linked-list <b>head_ptr</b>.
 * This function is used to extend cpath by another hop.
 */
void
onion_append_to_cpath(crypt_path_t **head_ptr, crypt_path_t *new_hop)
{
  if (*head_ptr) {
    new_hop->next = (*head_ptr);
    new_hop->prev = (*head_ptr)->prev;
    (*head_ptr)->prev->next = new_hop;
    (*head_ptr)->prev = new_hop;
  } else {
    *head_ptr = new_hop;
    new_hop->prev = new_hop->next = new_hop;
  }
}

/** A helper function used by onion_extend_cpath(). Use <b>purpose</b>
 * and <b>state</b> and the cpath <b>head</b> (currently populated only
 * to length <b>cur_len</b> to decide a suitable middle hop for a
 * circuit. In particular, make sure we don't pick the exit node or its
 * family, and make sure we don't duplicate any previous nodes or their
 * families. */
static const node_t *
choose_good_middle_server(uint8_t purpose,
                          cpath_build_state_t *state,
                          crypt_path_t *head,
                          int cur_len)
{
  int i;
  const node_t *r, *choice;
  crypt_path_t *cpath;
  smartlist_t *excluded;
  const or_options_t *options = get_options();
  router_crn_flags_t flags = CRN_NEED_DESC;
  tor_assert(_CIRCUIT_PURPOSE_MIN <= purpose &&
             purpose <= _CIRCUIT_PURPOSE_MAX);

  log_debug(LD_CIRC, "Contemplating intermediate hop: random choice.");
  excluded = smartlist_new();
  if ((r = build_state_get_exit_node(state))) {
    nodelist_add_node_and_family(excluded, r);
  }
  for (i = 0, cpath = head; i < cur_len; ++i, cpath=cpath->next) {
    if ((r = node_get_by_id(cpath->extend_info->identity_digest))) {
      nodelist_add_node_and_family(excluded, r);
    }
  }

  if (state->need_uptime)
    flags |= CRN_NEED_UPTIME;
  if (state->need_capacity)
    flags |= CRN_NEED_CAPACITY;
  if (options->_AllowInvalid & ALLOW_INVALID_MIDDLE)
    flags |= CRN_ALLOW_INVALID;
  choice = router_choose_random_node(excluded, options->ExcludeNodes, flags);
  smartlist_free(excluded);
  return choice;
}

/** Pick a good entry server for the circuit to be built according to
 * <b>state</b>.  Don't reuse a chosen exit (if any), don't use this
 * router (if we're an OR), and respect firewall settings; if we're
 * configured to use entry guards, return one.
 *
 * If <b>state</b> is NULL, we're choosing a router to serve as an entry
 * guard, not for any particular circuit.
 */
static const node_t *
choose_good_entry_server(uint8_t purpose, cpath_build_state_t *state)
{
  const node_t *choice;
  smartlist_t *excluded;
  const or_options_t *options = get_options();
  router_crn_flags_t flags = CRN_NEED_GUARD|CRN_NEED_DESC;
  const node_t *node;

  if (state && options->UseEntryGuards &&
      (purpose != CIRCUIT_PURPOSE_TESTING || options->BridgeRelay)) {
    /* This request is for an entry server to use for a regular circuit,
     * and we use entry guard nodes.  Just return one of the guard nodes.  */
    return choose_random_entry(state);
  }

  excluded = smartlist_new();

  if (state && (node = build_state_get_exit_node(state))) {
    /* Exclude the exit node from the state, if we have one.  Also exclude its
     * family. */
    nodelist_add_node_and_family(excluded, node);
  }
  if (firewall_is_fascist_or()) {
    /* Exclude all ORs that we can't reach through our firewall */
    smartlist_t *nodes = nodelist_get_list();
    SMARTLIST_FOREACH(nodes, const node_t *, node, {
      if (!fascist_firewall_allows_node(node))
        smartlist_add(excluded, (void*)node);
    });
  }
  /* and exclude current entry guards and their families, if applicable */
  if (options->UseEntryGuards && entry_guards) {
    SMARTLIST_FOREACH(entry_guards, entry_guard_t *, entry,
      {
        if ((node = node_get_by_id(entry->identity))) {
          nodelist_add_node_and_family(excluded, node);
        }
      });
  }

  if (state) {
    if (state->need_uptime)
      flags |= CRN_NEED_UPTIME;
    if (state->need_capacity)
      flags |= CRN_NEED_CAPACITY;
  }
  if (options->_AllowInvalid & ALLOW_INVALID_ENTRY)
    flags |= CRN_ALLOW_INVALID;

  choice = router_choose_random_node(excluded, options->ExcludeNodes, flags);
  smartlist_free(excluded);
  return choice;
}

/** Return the first non-open hop in cpath, or return NULL if all
 * hops are open. */
static crypt_path_t *
onion_next_hop_in_cpath(crypt_path_t *cpath)
{
  crypt_path_t *hop = cpath;
  do {
    if (hop->state != CPATH_STATE_OPEN)
      return hop;
    hop = hop->next;
  } while (hop != cpath);
  return NULL;
}

/** Choose a suitable next hop in the cpath <b>head_ptr</b>,
 * based on <b>state</b>. Append the hop info to head_ptr.
 */
static int
onion_extend_cpath(origin_circuit_t *circ)
{
  uint8_t purpose = circ->_base.purpose;
  cpath_build_state_t *state = circ->build_state;
  int cur_len = circuit_get_cpath_len(circ);
  extend_info_t *info = NULL;

  if (cur_len >= state->desired_path_len) {
    log_debug(LD_CIRC, "Path is complete: %d steps long",
              state->desired_path_len);
    return 1;
  }

  log_debug(LD_CIRC, "Path is %d long; we want %d", cur_len,
            state->desired_path_len);

  if (cur_len == state->desired_path_len - 1) { /* Picking last node */
    info = extend_info_dup(state->chosen_exit);
  } else if (cur_len == 0) { /* picking first node */
    const node_t *r = choose_good_entry_server(purpose, state);
    if (r) {
      /* If we're extending to a bridge, use the preferred address
         rather than the primary, for potentially extending to an IPv6
         bridge.  */
      int use_pref_addr = (r->ri != NULL &&
                           r->ri->purpose == ROUTER_PURPOSE_BRIDGE);
      info = extend_info_from_node(r, use_pref_addr);
      tor_assert(info);
    }
  } else {
    const node_t *r =
      choose_good_middle_server(purpose, state, circ->cpath, cur_len);
    if (r) {
      info = extend_info_from_node(r, 0);
      tor_assert(info);
    }
  }

  if (!info) {
    log_warn(LD_CIRC,"Failed to find node for hop %d of our path. Discarding "
             "this circuit.", cur_len);
    return -1;
  }

  log_debug(LD_CIRC,"Chose router %s for hop %d (exit is %s)",
            extend_info_describe(info),
            cur_len+1, build_state_get_exit_nickname(state));

  onion_append_hop(&circ->cpath, info);
  extend_info_free(info);
  return 0;
}

/** Create a new hop, annotate it with information about its
 * corresponding router <b>choice</b>, and append it to the
 * end of the cpath <b>head_ptr</b>. */
static int
onion_append_hop(crypt_path_t **head_ptr, extend_info_t *choice)
{
  crypt_path_t *hop = tor_malloc_zero(sizeof(crypt_path_t));

  /* link hop into the cpath, at the end. */
  onion_append_to_cpath(head_ptr, hop);

  hop->magic = CRYPT_PATH_MAGIC;
  hop->state = CPATH_STATE_CLOSED;

  hop->extend_info = extend_info_dup(choice);

  hop->package_window = circuit_initial_package_window();
  hop->deliver_window = CIRCWINDOW_START;

  return 0;
}

/** Allocate a new extend_info object based on the various arguments. */
extend_info_t *
extend_info_alloc(const char *nickname, const char *digest,
                  crypto_pk_t *onion_key,
                  const tor_addr_t *addr, uint16_t port)
{
  extend_info_t *info = tor_malloc_zero(sizeof(extend_info_t));
  memcpy(info->identity_digest, digest, DIGEST_LEN);
  if (nickname)
    strlcpy(info->nickname, nickname, sizeof(info->nickname));
  if (onion_key)
    info->onion_key = crypto_pk_dup_key(onion_key);
  tor_addr_copy(&info->addr, addr);
  info->port = port;
  return info;
}

/** Allocate and return a new extend_info_t that can be used to build
 * a circuit to or through the router <b>r</b>. Use the primary
 * address of the router unless <b>for_direct_connect</b> is true, in
 * which case the preferred address is used instead. */
extend_info_t *
extend_info_from_router(const routerinfo_t *r, int for_direct_connect)
{
  tor_addr_port_t ap;
  tor_assert(r);

  if (for_direct_connect)
    router_get_pref_orport(r, &ap);
  else
    router_get_prim_orport(r, &ap);
  return extend_info_alloc(r->nickname, r->cache_info.identity_digest,
                           r->onion_pkey, &ap.addr, ap.port);
}

/** Allocate and return a new extend_info that can be used to build a
 * circuit to or through the node <b>node</b>. Use the primary address
 * of the node unless <b>for_direct_connect</b> is true, in which case
 * the preferred address is used instead. May return NULL if there is
 * not enough info about <b>node</b> to extend to it--for example, if
 * there is no routerinfo_t or microdesc_t.
 **/
extend_info_t *
extend_info_from_node(const node_t *node, int for_direct_connect)
{
  if (node->ri) {
    return extend_info_from_router(node->ri, for_direct_connect);
  } else if (node->rs && node->md) {
    tor_addr_t addr;
    tor_addr_from_ipv4h(&addr, node->rs->addr);
    return extend_info_alloc(node->rs->nickname,
                             node->identity,
                             node->md->onion_pkey,
                             &addr,
                             node->rs->or_port);
  } else {
    return NULL;
  }
}

/** Release storage held by an extend_info_t struct. */
void
extend_info_free(extend_info_t *info)
{
  if (!info)
    return;
  crypto_pk_free(info->onion_key);
  tor_free(info);
}

/** Allocate and return a new extend_info_t with the same contents as
 * <b>info</b>. */
extend_info_t *
extend_info_dup(extend_info_t *info)
{
  extend_info_t *newinfo;
  tor_assert(info);
  newinfo = tor_malloc(sizeof(extend_info_t));
  memcpy(newinfo, info, sizeof(extend_info_t));
  if (info->onion_key)
    newinfo->onion_key = crypto_pk_dup_key(info->onion_key);
  else
    newinfo->onion_key = NULL;
  return newinfo;
}

/** Return the routerinfo_t for the chosen exit router in <b>state</b>.
 * If there is no chosen exit, or if we don't know the routerinfo_t for
 * the chosen exit, return NULL.
 */
const node_t *
build_state_get_exit_node(cpath_build_state_t *state)
{
  if (!state || !state->chosen_exit)
    return NULL;
  return node_get_by_id(state->chosen_exit->identity_digest);
}

/** Return the nickname for the chosen exit router in <b>state</b>. If
 * there is no chosen exit, or if we don't know the routerinfo_t for the
 * chosen exit, return NULL.
 */
const char *
build_state_get_exit_nickname(cpath_build_state_t *state)
{
  if (!state || !state->chosen_exit)
    return NULL;
  return state->chosen_exit->nickname;
}

/** Check whether the entry guard <b>e</b> is usable, given the directory
 * authorities' opinion about the router (stored in <b>ri</b>) and the user's
 * configuration (in <b>options</b>). Set <b>e</b>-&gt;bad_since
 * accordingly. Return true iff the entry guard's status changes.
 *
 * If it's not usable, set *<b>reason</b> to a static string explaining why.
 */
static int
entry_guard_set_status(entry_guard_t *e, const node_t *node,
                       time_t now, const or_options_t *options,
                       const char **reason)
{
  char buf[HEX_DIGEST_LEN+1];
  int changed = 0;

  *reason = NULL;

  /* Do we want to mark this guard as bad? */
  if (!node)
    *reason = "unlisted";
  else if (!node->is_running)
    *reason = "down";
  else if (options->UseBridges && (!node->ri ||
                                   node->ri->purpose != ROUTER_PURPOSE_BRIDGE))
    *reason = "not a bridge";
  else if (options->UseBridges && !node_is_a_configured_bridge(node))
    *reason = "not a configured bridge";
  else if (!options->UseBridges && !node->is_possible_guard &&
           !routerset_contains_node(options->EntryNodes,node))
    *reason = "not recommended as a guard";
  else if (routerset_contains_node(options->ExcludeNodes, node))
    *reason = "excluded";
  else if (e->path_bias_disabled)
    *reason = "path-biased";

  if (*reason && ! e->bad_since) {
    /* Router is newly bad. */
    base16_encode(buf, sizeof(buf), e->identity, DIGEST_LEN);
    log_info(LD_CIRC, "Entry guard %s (%s) is %s: marking as unusable.",
             e->nickname, buf, *reason);

    e->bad_since = now;
    control_event_guard(e->nickname, e->identity, "BAD");
    changed = 1;
  } else if (!*reason && e->bad_since) {
    /* There's nothing wrong with the router any more. */
    base16_encode(buf, sizeof(buf), e->identity, DIGEST_LEN);
    log_info(LD_CIRC, "Entry guard %s (%s) is no longer unusable: "
             "marking as ok.", e->nickname, buf);

    e->bad_since = 0;
    control_event_guard(e->nickname, e->identity, "GOOD");
    changed = 1;
  }
  return changed;
}

/** Return true iff enough time has passed since we last tried to connect
 * to the unreachable guard <b>e</b> that we're willing to try again. */
static int
entry_is_time_to_retry(entry_guard_t *e, time_t now)
{
  long diff;
  if (e->last_attempted < e->unreachable_since)
    return 1;
  diff = now - e->unreachable_since;
  if (diff < 6*60*60)
    return now > (e->last_attempted + 60*60);
  else if (diff < 3*24*60*60)
    return now > (e->last_attempted + 4*60*60);
  else if (diff < 7*24*60*60)
    return now > (e->last_attempted + 18*60*60);
  else
    return now > (e->last_attempted + 36*60*60);
}

/** Return the node corresponding to <b>e</b>, if <b>e</b> is
 * working well enough that we are willing to use it as an entry
 * right now. (Else return NULL.) In particular, it must be
 * - Listed as either up or never yet contacted;
 * - Present in the routerlist;
 * - Listed as 'stable' or 'fast' by the current dirserver consensus,
 *   if demanded by <b>need_uptime</b> or <b>need_capacity</b>
 *   (unless it's a configured EntryNode);
 * - Allowed by our current ReachableORAddresses config option; and
 * - Currently thought to be reachable by us (unless <b>assume_reachable</b>
 *   is true).
 *
 * If the answer is no, set *<b>msg</b> to an explanation of why.
 */
static INLINE const node_t *
entry_is_live(entry_guard_t *e, int need_uptime, int need_capacity,
              int assume_reachable, const char **msg)
{
  const node_t *node;
  const or_options_t *options = get_options();
  tor_assert(msg);

  if (e->path_bias_disabled) {
    *msg = "path-biased";
    return NULL;
  }
  if (e->bad_since) {
    *msg = "bad";
    return NULL;
  }
  /* no good if it's unreachable, unless assume_unreachable or can_retry. */
  if (!assume_reachable && !e->can_retry &&
      e->unreachable_since && !entry_is_time_to_retry(e, time(NULL))) {
    *msg = "unreachable";
    return NULL;
  }
  node = node_get_by_id(e->identity);
  if (!node || !node_has_descriptor(node)) {
    *msg = "no descriptor";
    return NULL;
  }
  if (get_options()->UseBridges) {
    if (node_get_purpose(node) != ROUTER_PURPOSE_BRIDGE) {
      *msg = "not a bridge";
      return NULL;
    }
    if (!node_is_a_configured_bridge(node)) {
      *msg = "not a configured bridge";
      return NULL;
    }
  } else { /* !get_options()->UseBridges */
    if (node_get_purpose(node) != ROUTER_PURPOSE_GENERAL) {
      *msg = "not general-purpose";
      return NULL;
    }
  }
  if (routerset_contains_node(options->EntryNodes, node)) {
    /* they asked for it, they get it */
    need_uptime = need_capacity = 0;
  }
  if (node_is_unreliable(node, need_uptime, need_capacity, 0)) {
    *msg = "not fast/stable";
    return NULL;
  }
  if (!fascist_firewall_allows_node(node)) {
    *msg = "unreachable by config";
    return NULL;
  }
  return node;
}

/** Return the number of entry guards that we think are usable. */
static int
num_live_entry_guards(void)
{
  int n = 0;
  const char *msg;
  if (! entry_guards)
    return 0;
  SMARTLIST_FOREACH(entry_guards, entry_guard_t *, entry,
    {
      if (entry_is_live(entry, 0, 1, 0, &msg))
        ++n;
    });
  return n;
}

/** If <b>digest</b> matches the identity of any node in the
 * entry_guards list, return that node. Else return NULL. */
static entry_guard_t *
entry_guard_get_by_id_digest(const char *digest)
{
  SMARTLIST_FOREACH(entry_guards, entry_guard_t *, entry,
                    if (tor_memeq(digest, entry->identity, DIGEST_LEN))
                      return entry;
                   );
  return NULL;
}

/** Dump a description of our list of entry guards to the log at level
 * <b>severity</b>. */
static void
log_entry_guards(int severity)
{
  smartlist_t *elements = smartlist_new();
  char *s;

  SMARTLIST_FOREACH_BEGIN(entry_guards, entry_guard_t *, e)
    {
      const char *msg = NULL;
      if (entry_is_live(e, 0, 1, 0, &msg))
        smartlist_add_asprintf(elements, "%s [%s] (up %s)",
                     e->nickname,
                     hex_str(e->identity, DIGEST_LEN),
                     e->made_contact ? "made-contact" : "never-contacted");
      else
        smartlist_add_asprintf(elements, "%s [%s] (%s, %s)",
                     e->nickname,
                     hex_str(e->identity, DIGEST_LEN),
                     msg,
                     e->made_contact ? "made-contact" : "never-contacted");
    }
  SMARTLIST_FOREACH_END(e);

  s = smartlist_join_strings(elements, ",", 0, NULL);
  SMARTLIST_FOREACH(elements, char*, cp, tor_free(cp));
  smartlist_free(elements);
  log_fn(severity,LD_CIRC,"%s",s);
  tor_free(s);
}

/** Called when one or more guards that we would previously have used for some
 * purpose are no longer in use because a higher-priority guard has become
 * usable again. */
static void
control_event_guard_deferred(void)
{
  /* XXXX We don't actually have a good way to figure out _how many_ entries
   * are live for some purpose.  We need an entry_is_even_slightly_live()
   * function for this to work right.  NumEntryGuards isn't reliable: if we
   * need guards with weird properties, we can have more than that number
   * live.
   **/
#if 0
  int n = 0;
  const char *msg;
  const or_options_t *options = get_options();
  if (!entry_guards)
    return;
  SMARTLIST_FOREACH(entry_guards, entry_guard_t *, entry,
    {
      if (entry_is_live(entry, 0, 1, 0, &msg)) {
        if (n++ == options->NumEntryGuards) {
          control_event_guard(entry->nickname, entry->identity, "DEFERRED");
          return;
        }
      }
    });
#endif
}

/** Add a new (preferably stable and fast) router to our
 * entry_guards list. Return a pointer to the router if we succeed,
 * or NULL if we can't find any more suitable entries.
 *
 * If <b>chosen</b> is defined, use that one, and if it's not
 * already in our entry_guards list, put it at the *beginning*.
 * Else, put the one we pick at the end of the list. */
static const node_t *
add_an_entry_guard(const node_t *chosen, int reset_status, int prepend)
{
  const node_t *node;
  entry_guard_t *entry;

  if (chosen) {
    node = chosen;
    entry = entry_guard_get_by_id_digest(node->identity);
    if (entry) {
      if (reset_status) {
        entry->bad_since = 0;
        entry->can_retry = 1;
      }
      return NULL;
    }
  } else {
    node = choose_good_entry_server(CIRCUIT_PURPOSE_C_GENERAL, NULL);
    if (!node)
      return NULL;
  }
  entry = tor_malloc_zero(sizeof(entry_guard_t));
  log_info(LD_CIRC, "Chose %s as new entry guard.",
           node_describe(node));
  strlcpy(entry->nickname, node_get_nickname(node), sizeof(entry->nickname));
  memcpy(entry->identity, node->identity, DIGEST_LEN);
  /* Choose expiry time smudged over the past month. The goal here
   * is to a) spread out when Tor clients rotate their guards, so they
   * don't all select them on the same day, and b) avoid leaving a
   * precise timestamp in the state file about when we first picked
   * this guard. For details, see the Jan 2010 or-dev thread. */
  entry->chosen_on_date = time(NULL) - crypto_rand_int(3600*24*30);
  entry->chosen_by_version = tor_strdup(VERSION);
  if (prepend)
    smartlist_insert(entry_guards, 0, entry);
  else
    smartlist_add(entry_guards, entry);
  control_event_guard(entry->nickname, entry->identity, "NEW");
  control_event_guard_deferred();
  log_entry_guards(LOG_INFO);
  return node;
}

/** If the use of entry guards is configured, choose more entry guards
 * until we have enough in the list. */
static void
pick_entry_guards(const or_options_t *options)
{
  int changed = 0;

  tor_assert(entry_guards);

  while (num_live_entry_guards() < options->NumEntryGuards) {
    if (!add_an_entry_guard(NULL, 0, 0))
      break;
    changed = 1;
  }
  if (changed)
    entry_guards_changed();
}

/** How long (in seconds) do we allow an entry guard to be nonfunctional,
 * unlisted, excluded, or otherwise nonusable before we give up on it? */
#define ENTRY_GUARD_REMOVE_AFTER (30*24*60*60)

/** Release all storage held by <b>e</b>. */
static void
entry_guard_free(entry_guard_t *e)
{
  if (!e)
    return;
  tor_free(e->chosen_by_version);
  tor_free(e);
}

/** Remove any entry guard which was selected by an unknown version of Tor,
 * or which was selected by a version of Tor that's known to select
 * entry guards badly, or which was selected more 2 months ago. */
/* XXXX The "obsolete guards" and "chosen long ago guards" things should
 * probably be different functions. */
static int
remove_obsolete_entry_guards(time_t now)
{
  int changed = 0, i;

  for (i = 0; i < smartlist_len(entry_guards); ++i) {
    entry_guard_t *entry = smartlist_get(entry_guards, i);
    const char *ver = entry->chosen_by_version;
    const char *msg = NULL;
    tor_version_t v;
    int version_is_bad = 0, date_is_bad = 0;
    if (!ver) {
      msg = "does not say what version of Tor it was selected by";
      version_is_bad = 1;
    } else if (tor_version_parse(ver, &v)) {
      msg = "does not seem to be from any recognized version of Tor";
      version_is_bad = 1;
    } else {
      char *tor_ver = NULL;
      tor_asprintf(&tor_ver, "Tor %s", ver);
      if ((tor_version_as_new_as(tor_ver, "0.1.0.10-alpha") &&
           !tor_version_as_new_as(tor_ver, "0.1.2.16-dev")) ||
          (tor_version_as_new_as(tor_ver, "0.2.0.0-alpha") &&
           !tor_version_as_new_as(tor_ver, "0.2.0.6-alpha")) ||
          /* above are bug 440; below are bug 1217 */
          (tor_version_as_new_as(tor_ver, "0.2.1.3-alpha") &&
           !tor_version_as_new_as(tor_ver, "0.2.1.23")) ||
          (tor_version_as_new_as(tor_ver, "0.2.2.0-alpha") &&
           !tor_version_as_new_as(tor_ver, "0.2.2.7-alpha"))) {
        msg = "was selected without regard for guard bandwidth";
        version_is_bad = 1;
      }
      tor_free(tor_ver);
    }
    if (!version_is_bad && entry->chosen_on_date + 3600*24*60 < now) {
      /* It's been 2 months since the date listed in our state file. */
      msg = "was selected several months ago";
      date_is_bad = 1;
    }

    if (version_is_bad || date_is_bad) { /* we need to drop it */
      char dbuf[HEX_DIGEST_LEN+1];
      tor_assert(msg);
      base16_encode(dbuf, sizeof(dbuf), entry->identity, DIGEST_LEN);
      log_fn(version_is_bad ? LOG_NOTICE : LOG_INFO, LD_CIRC,
             "Entry guard '%s' (%s) %s. (Version=%s.) Replacing it.",
             entry->nickname, dbuf, msg, ver?escaped(ver):"none");
      control_event_guard(entry->nickname, entry->identity, "DROPPED");
      entry_guard_free(entry);
      smartlist_del_keeporder(entry_guards, i--);
      log_entry_guards(LOG_INFO);
      changed = 1;
    }
  }

  return changed ? 1 : 0;
}

/** Remove all entry guards that have been down or unlisted for so
 * long that we don't think they'll come up again. Return 1 if we
 * removed any, or 0 if we did nothing. */
static int
remove_dead_entry_guards(time_t now)
{
  char dbuf[HEX_DIGEST_LEN+1];
  char tbuf[ISO_TIME_LEN+1];
  int i;
  int changed = 0;

  for (i = 0; i < smartlist_len(entry_guards); ) {
    entry_guard_t *entry = smartlist_get(entry_guards, i);
    if (entry->bad_since &&
        ! entry->path_bias_disabled &&
        entry->bad_since + ENTRY_GUARD_REMOVE_AFTER < now) {

      base16_encode(dbuf, sizeof(dbuf), entry->identity, DIGEST_LEN);
      format_local_iso_time(tbuf, entry->bad_since);
      log_info(LD_CIRC, "Entry guard '%s' (%s) has been down or unlisted "
               "since %s local time; removing.",
               entry->nickname, dbuf, tbuf);
      control_event_guard(entry->nickname, entry->identity, "DROPPED");
      entry_guard_free(entry);
      smartlist_del_keeporder(entry_guards, i);
      log_entry_guards(LOG_INFO);
      changed = 1;
    } else
      ++i;
  }
  return changed ? 1 : 0;
}

/** A new directory or router-status has arrived; update the down/listed
 * status of the entry guards.
 *
 * An entry is 'down' if the directory lists it as nonrunning.
 * An entry is 'unlisted' if the directory doesn't include it.
 *
 * Don't call this on startup; only on a fresh download. Otherwise we'll
 * think that things are unlisted.
 */
void
entry_guards_compute_status(const or_options_t *options, time_t now)
{
  int changed = 0;
  digestmap_t *reasons;

  if (! entry_guards)
    return;

  if (options->EntryNodes) /* reshuffle the entry guard list if needed */
    entry_nodes_should_be_added();

  reasons = digestmap_new();
  SMARTLIST_FOREACH_BEGIN(entry_guards, entry_guard_t *, entry)
    {
      const node_t *r = node_get_by_id(entry->identity);
      const char *reason = NULL;
      if (entry_guard_set_status(entry, r, now, options, &reason))
        changed = 1;

      if (entry->bad_since)
        tor_assert(reason);
      if (reason)
        digestmap_set(reasons, entry->identity, (char*)reason);
    }
  SMARTLIST_FOREACH_END(entry);

  if (remove_dead_entry_guards(now))
    changed = 1;
  if (remove_obsolete_entry_guards(now))
    changed = 1;

  if (changed) {
    SMARTLIST_FOREACH_BEGIN(entry_guards, entry_guard_t *, entry) {
      const char *reason = digestmap_get(reasons, entry->identity);
      const char *live_msg = "";
      const node_t *r = entry_is_live(entry, 0, 1, 0, &live_msg);
      log_info(LD_CIRC, "Summary: Entry %s [%s] is %s, %s%s%s, and %s%s.",
               entry->nickname,
               hex_str(entry->identity, DIGEST_LEN),
               entry->unreachable_since ? "unreachable" : "reachable",
               entry->bad_since ? "unusable" : "usable",
               reason ? ", ": "",
               reason ? reason : "",
               r ? "live" : "not live / ",
               r ? "" : live_msg);
    } SMARTLIST_FOREACH_END(entry);
    log_info(LD_CIRC, "    (%d/%d entry guards are usable/new)",
             num_live_entry_guards(), smartlist_len(entry_guards));
    log_entry_guards(LOG_INFO);
    entry_guards_changed();
  }

  digestmap_free(reasons, NULL);
}

/** Called when a connection to an OR with the identity digest <b>digest</b>
 * is established (<b>succeeded</b>==1) or has failed (<b>succeeded</b>==0).
 * If the OR is an entry, change that entry's up/down status.
 * Return 0 normally, or -1 if we want to tear down the new connection.
 *
 * If <b>mark_relay_status</b>, also call router_set_status() on this
 * relay.
 *
 * XXX024 change succeeded and mark_relay_status into 'int flags'.
 */
int
entry_guard_register_connect_status(const char *digest, int succeeded,
                                    int mark_relay_status, time_t now)
{
  int changed = 0;
  int refuse_conn = 0;
  int first_contact = 0;
  entry_guard_t *entry = NULL;
  int idx = -1;
  char buf[HEX_DIGEST_LEN+1];

  if (! entry_guards)
    return 0;

  SMARTLIST_FOREACH_BEGIN(entry_guards, entry_guard_t *, e) {
    tor_assert(e);
    if (tor_memeq(e->identity, digest, DIGEST_LEN)) {
      entry = e;
      idx = e_sl_idx;
      break;
    }
  } SMARTLIST_FOREACH_END(e);

  if (!entry)
    return 0;

  base16_encode(buf, sizeof(buf), entry->identity, DIGEST_LEN);

  if (succeeded) {
    if (entry->unreachable_since) {
      log_info(LD_CIRC, "Entry guard '%s' (%s) is now reachable again. Good.",
               entry->nickname, buf);
      entry->can_retry = 0;
      entry->unreachable_since = 0;
      entry->last_attempted = now;
      control_event_guard(entry->nickname, entry->identity, "UP");
      changed = 1;
    }
    if (!entry->made_contact) {
      entry->made_contact = 1;
      first_contact = changed = 1;
    }
  } else { /* ! succeeded */
    if (!entry->made_contact) {
      /* We've never connected to this one. */
      log_info(LD_CIRC,
               "Connection to never-contacted entry guard '%s' (%s) failed. "
               "Removing from the list. %d/%d entry guards usable/new.",
               entry->nickname, buf,
               num_live_entry_guards()-1, smartlist_len(entry_guards)-1);
      control_event_guard(entry->nickname, entry->identity, "DROPPED");
      entry_guard_free(entry);
      smartlist_del_keeporder(entry_guards, idx);
      log_entry_guards(LOG_INFO);
      changed = 1;
    } else if (!entry->unreachable_since) {
      log_info(LD_CIRC, "Unable to connect to entry guard '%s' (%s). "
               "Marking as unreachable.", entry->nickname, buf);
      entry->unreachable_since = entry->last_attempted = now;
      control_event_guard(entry->nickname, entry->identity, "DOWN");
      changed = 1;
      entry->can_retry = 0; /* We gave it an early chance; no good. */
    } else {
      char tbuf[ISO_TIME_LEN+1];
      format_iso_time(tbuf, entry->unreachable_since);
      log_debug(LD_CIRC, "Failed to connect to unreachable entry guard "
                "'%s' (%s).  It has been unreachable since %s.",
                entry->nickname, buf, tbuf);
      entry->last_attempted = now;
      entry->can_retry = 0; /* We gave it an early chance; no good. */
    }
  }

  /* if the caller asked us to, also update the is_running flags for this
   * relay */
  if (mark_relay_status)
    router_set_status(digest, succeeded);

  if (first_contact) {
    /* We've just added a new long-term entry guard. Perhaps the network just
     * came back? We should give our earlier entries another try too,
     * and close this connection so we don't use it before we've given
     * the others a shot. */
    SMARTLIST_FOREACH_BEGIN(entry_guards, entry_guard_t *, e) {
        if (e == entry)
          break;
        if (e->made_contact) {
          const char *msg;
          const node_t *r = entry_is_live(e, 0, 1, 1, &msg);
          if (r && e->unreachable_since) {
            refuse_conn = 1;
            e->can_retry = 1;
          }
        }
    } SMARTLIST_FOREACH_END(e);
    if (refuse_conn) {
      log_info(LD_CIRC,
               "Connected to new entry guard '%s' (%s). Marking earlier "
               "entry guards up. %d/%d entry guards usable/new.",
               entry->nickname, buf,
               num_live_entry_guards(), smartlist_len(entry_guards));
      log_entry_guards(LOG_INFO);
      changed = 1;
    }
  }

  if (changed)
    entry_guards_changed();
  return refuse_conn ? -1 : 0;
}

/** When we try to choose an entry guard, should we parse and add
 * config's EntryNodes first? */
static int should_add_entry_nodes = 0;

/** Called when the value of EntryNodes changes in our configuration. */
void
entry_nodes_should_be_added(void)
{
  log_info(LD_CIRC, "EntryNodes config option set. Putting configured "
           "relays at the front of the entry guard list.");
  should_add_entry_nodes = 1;
}

/** Adjust the entry guards list so that it only contains entries from
 * EntryNodes, adding new entries from EntryNodes to the list as needed. */
static void
entry_guards_set_from_config(const or_options_t *options)
{
  smartlist_t *entry_nodes, *worse_entry_nodes, *entry_fps;
  smartlist_t *old_entry_guards_on_list, *old_entry_guards_not_on_list;
  tor_assert(entry_guards);

  should_add_entry_nodes = 0;

  if (!options->EntryNodes) {
    /* It's possible that a controller set EntryNodes, thus making
     * should_add_entry_nodes set, then cleared it again, all before the
     * call to choose_random_entry() that triggered us. If so, just return.
     */
    return;
  }

  {
    char *string = routerset_to_string(options->EntryNodes);
    log_info(LD_CIRC,"Adding configured EntryNodes '%s'.", string);
    tor_free(string);
  }

  entry_nodes = smartlist_new();
  worse_entry_nodes = smartlist_new();
  entry_fps = smartlist_new();
  old_entry_guards_on_list = smartlist_new();
  old_entry_guards_not_on_list = smartlist_new();

  /* Split entry guards into those on the list and those not. */

  routerset_get_all_nodes(entry_nodes, options->EntryNodes,
                          options->ExcludeNodes, 0);
  SMARTLIST_FOREACH(entry_nodes, const node_t *,node,
                    smartlist_add(entry_fps, (void*)node->identity));

  SMARTLIST_FOREACH(entry_guards, entry_guard_t *, e, {
    if (smartlist_digest_isin(entry_fps, e->identity))
      smartlist_add(old_entry_guards_on_list, e);
    else
      smartlist_add(old_entry_guards_not_on_list, e);
  });

  /* Remove all currently configured guard nodes, excluded nodes, unreachable
   * nodes, or non-Guard nodes from entry_nodes. */
  SMARTLIST_FOREACH_BEGIN(entry_nodes, const node_t *, node) {
    if (entry_guard_get_by_id_digest(node->identity)) {
      SMARTLIST_DEL_CURRENT(entry_nodes, node);
      continue;
    } else if (routerset_contains_node(options->ExcludeNodes, node)) {
      SMARTLIST_DEL_CURRENT(entry_nodes, node);
      continue;
    } else if (!fascist_firewall_allows_node(node)) {
      SMARTLIST_DEL_CURRENT(entry_nodes, node);
      continue;
    } else if (! node->is_possible_guard) {
      smartlist_add(worse_entry_nodes, (node_t*)node);
      SMARTLIST_DEL_CURRENT(entry_nodes, node);
    }
  } SMARTLIST_FOREACH_END(node);

  /* Now build the new entry_guards list. */
  smartlist_clear(entry_guards);
  /* First, the previously configured guards that are in EntryNodes. */
  smartlist_add_all(entry_guards, old_entry_guards_on_list);
  /* Next, scramble the rest of EntryNodes, putting the guards first. */
  smartlist_shuffle(entry_nodes);
  smartlist_shuffle(worse_entry_nodes);
  smartlist_add_all(entry_nodes, worse_entry_nodes);

  /* Next, the rest of EntryNodes */
  SMARTLIST_FOREACH_BEGIN(entry_nodes, const node_t *, node) {
    add_an_entry_guard(node, 0, 0);
    if (smartlist_len(entry_guards) > options->NumEntryGuards * 10)
      break;
  } SMARTLIST_FOREACH_END(node);
  log_notice(LD_GENERAL, "%d entries in guards", smartlist_len(entry_guards));
  /* Finally, free the remaining previously configured guards that are not in
   * EntryNodes. */
  SMARTLIST_FOREACH(old_entry_guards_not_on_list, entry_guard_t *, e,
                    entry_guard_free(e));

  smartlist_free(entry_nodes);
  smartlist_free(worse_entry_nodes);
  smartlist_free(entry_fps);
  smartlist_free(old_entry_guards_on_list);
  smartlist_free(old_entry_guards_not_on_list);
  entry_guards_changed();
}

/** Return 0 if we're fine adding arbitrary routers out of the
 * directory to our entry guard list, or return 1 if we have a
 * list already and we must stick to it.
 */
int
entry_list_is_constrained(const or_options_t *options)
{
  if (options->EntryNodes)
    return 1;
  if (options->UseBridges)
    return 1;
  return 0;
}

/** Pick a live (up and listed) entry guard from entry_guards. If
 * <b>state</b> is non-NULL, this is for a specific circuit --
 * make sure not to pick this circuit's exit or any node in the
 * exit's family. If <b>state</b> is NULL, we're looking for a random
 * guard (likely a bridge). */
const node_t *
choose_random_entry(cpath_build_state_t *state)
{
  const or_options_t *options = get_options();
  smartlist_t *live_entry_guards = smartlist_new();
  smartlist_t *exit_family = smartlist_new();
  const node_t *chosen_exit =
    state?build_state_get_exit_node(state) : NULL;
  const node_t *node = NULL;
  int need_uptime = state ? state->need_uptime : 0;
  int need_capacity = state ? state->need_capacity : 0;
  int preferred_min, consider_exit_family = 0;

  if (chosen_exit) {
    nodelist_add_node_and_family(exit_family, chosen_exit);
    consider_exit_family = 1;
  }

  if (!entry_guards)
    entry_guards = smartlist_new();

  if (should_add_entry_nodes)
    entry_guards_set_from_config(options);

  if (!entry_list_is_constrained(options) &&
      smartlist_len(entry_guards) < options->NumEntryGuards)
    pick_entry_guards(options);

 retry:
  smartlist_clear(live_entry_guards);
  SMARTLIST_FOREACH_BEGIN(entry_guards, entry_guard_t *, entry) {
      const char *msg;
      node = entry_is_live(entry, need_uptime, need_capacity, 0, &msg);
      if (!node)
        continue; /* down, no point */
      if (node == chosen_exit)
        continue; /* don't pick the same node for entry and exit */
      if (consider_exit_family && smartlist_isin(exit_family, node))
        continue; /* avoid relays that are family members of our exit */
#if 0 /* since EntryNodes is always strict now, this clause is moot */
      if (options->EntryNodes &&
          !routerset_contains_node(options->EntryNodes, node)) {
        /* We've come to the end of our preferred entry nodes. */
        if (smartlist_len(live_entry_guards))
          goto choose_and_finish; /* only choose from the ones we like */
        if (options->StrictNodes) {
          /* in theory this case should never happen, since
           * entry_guards_set_from_config() drops unwanted relays */
          tor_fragile_assert();
        } else {
          log_info(LD_CIRC,
                   "No relays from EntryNodes available. Using others.");
        }
      }
#endif
      smartlist_add(live_entry_guards, (void*)node);
      if (!entry->made_contact) {
        /* Always start with the first not-yet-contacted entry
         * guard. Otherwise we might add several new ones, pick
         * the second new one, and now we've expanded our entry
         * guard list without needing to. */
        goto choose_and_finish;
      }
      if (smartlist_len(live_entry_guards) >= options->NumEntryGuards)
        goto choose_and_finish; /* we have enough */
  } SMARTLIST_FOREACH_END(entry);

  if (entry_list_is_constrained(options)) {
    /* If we prefer the entry nodes we've got, and we have at least
     * one choice, that's great. Use it. */
    preferred_min = 1;
  } else {
    /* Try to have at least 2 choices available. This way we don't
     * get stuck with a single live-but-crummy entry and just keep
     * using him.
     * (We might get 2 live-but-crummy entry guards, but so be it.) */
    preferred_min = 2;
  }

  if (smartlist_len(live_entry_guards) < preferred_min) {
    if (!entry_list_is_constrained(options)) {
      /* still no? try adding a new entry then */
      /* XXX if guard doesn't imply fast and stable, then we need
       * to tell add_an_entry_guard below what we want, or it might
       * be a long time til we get it. -RD */
      node = add_an_entry_guard(NULL, 0, 0);
      if (node) {
        entry_guards_changed();
        /* XXX we start over here in case the new node we added shares
         * a family with our exit node. There's a chance that we'll just
         * load up on entry guards here, if the network we're using is
         * one big family. Perhaps we should teach add_an_entry_guard()
         * to understand nodes-to-avoid-if-possible? -RD */
        goto retry;
      }
    }
    if (!node && need_uptime) {
      need_uptime = 0; /* try without that requirement */
      goto retry;
    }
    if (!node && need_capacity) {
      /* still no? last attempt, try without requiring capacity */
      need_capacity = 0;
      goto retry;
    }
#if 0
    /* Removing this retry logic: if we only allow one exit, and it is in the
       same family as all our entries, then we are just plain not going to win
       here. */
    if (!node && entry_list_is_constrained(options) && consider_exit_family) {
      /* still no? if we're using bridges or have strictentrynodes
       * set, and our chosen exit is in the same family as all our
       * bridges/entry guards, then be flexible about families. */
      consider_exit_family = 0;
      goto retry;
    }
#endif
    /* live_entry_guards may be empty below. Oh well, we tried. */
  }

 choose_and_finish:
  if (entry_list_is_constrained(options)) {
    /* We need to weight by bandwidth, because our bridges or entryguards
     * were not already selected proportional to their bandwidth. */
    node = node_sl_choose_by_bandwidth(live_entry_guards, WEIGHT_FOR_GUARD);
  } else {
    /* We choose uniformly at random here, because choose_good_entry_server()
     * already weights its choices by bandwidth, so we don't want to
     * *double*-weight our guard selection. */
    node = smartlist_choose(live_entry_guards);
  }
  smartlist_free(live_entry_guards);
  smartlist_free(exit_family);
  return node;
}

/** Parse <b>state</b> and learn about the entry guards it describes.
 * If <b>set</b> is true, and there are no errors, replace the global
 * entry_list with what we find.
 * On success, return 0. On failure, alloc into *<b>msg</b> a string
 * describing the error, and return -1.
 */
int
entry_guards_parse_state(or_state_t *state, int set, char **msg)
{
  entry_guard_t *node = NULL;
  smartlist_t *new_entry_guards = smartlist_new();
  config_line_t *line;
  time_t now = time(NULL);
  const char *state_version = state->TorVersion;
  digestmap_t *added_by = digestmap_new();

  *msg = NULL;
  for (line = state->EntryGuards; line; line = line->next) {
    if (!strcasecmp(line->key, "EntryGuard")) {
      smartlist_t *args = smartlist_new();
      node = tor_malloc_zero(sizeof(entry_guard_t));
      /* all entry guards on disk have been contacted */
      node->made_contact = 1;
      smartlist_add(new_entry_guards, node);
      smartlist_split_string(args, line->value, " ",
                             SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
      if (smartlist_len(args)<2) {
        *msg = tor_strdup("Unable to parse entry nodes: "
                          "Too few arguments to EntryGuard");
      } else if (!is_legal_nickname(smartlist_get(args,0))) {
        *msg = tor_strdup("Unable to parse entry nodes: "
                          "Bad nickname for EntryGuard");
      } else {
        strlcpy(node->nickname, smartlist_get(args,0), MAX_NICKNAME_LEN+1);
        if (base16_decode(node->identity, DIGEST_LEN, smartlist_get(args,1),
                          strlen(smartlist_get(args,1)))<0) {
          *msg = tor_strdup("Unable to parse entry nodes: "
                            "Bad hex digest for EntryGuard");
        }
      }
      SMARTLIST_FOREACH(args, char*, cp, tor_free(cp));
      smartlist_free(args);
      if (*msg)
        break;
    } else if (!strcasecmp(line->key, "EntryGuardDownSince") ||
               !strcasecmp(line->key, "EntryGuardUnlistedSince")) {
      time_t when;
      time_t last_try = 0;
      if (!node) {
        *msg = tor_strdup("Unable to parse entry nodes: "
               "EntryGuardDownSince/UnlistedSince without EntryGuard");
        break;
      }
      if (parse_iso_time(line->value, &when)<0) {
        *msg = tor_strdup("Unable to parse entry nodes: "
                          "Bad time in EntryGuardDownSince/UnlistedSince");
        break;
      }
      if (when > now) {
        /* It's a bad idea to believe info in the future: you can wind
         * up with timeouts that aren't allowed to happen for years. */
        continue;
      }
      if (strlen(line->value) >= ISO_TIME_LEN+ISO_TIME_LEN+1) {
        /* ignore failure */
        (void) parse_iso_time(line->value+ISO_TIME_LEN+1, &last_try);
      }
      if (!strcasecmp(line->key, "EntryGuardDownSince")) {
        node->unreachable_since = when;
        node->last_attempted = last_try;
      } else {
        node->bad_since = when;
      }
    } else if (!strcasecmp(line->key, "EntryGuardAddedBy")) {
      char d[DIGEST_LEN];
      /* format is digest version date */
      if (strlen(line->value) < HEX_DIGEST_LEN+1+1+1+ISO_TIME_LEN) {
        log_warn(LD_BUG, "EntryGuardAddedBy line is not long enough.");
        continue;
      }
      if (base16_decode(d, sizeof(d), line->value, HEX_DIGEST_LEN)<0 ||
          line->value[HEX_DIGEST_LEN] != ' ') {
        log_warn(LD_BUG, "EntryGuardAddedBy line %s does not begin with "
                 "hex digest", escaped(line->value));
        continue;
      }
      digestmap_set(added_by, d, tor_strdup(line->value+HEX_DIGEST_LEN+1));
    } else if (!strcasecmp(line->key, "EntryGuardPathBias")) {
      const or_options_t *options = get_options();
      unsigned hop_cnt, success_cnt;

      if (!node) {
        *msg = tor_strdup("Unable to parse entry nodes: "
               "EntryGuardPathBias without EntryGuard");
        break;
      }

      if (tor_sscanf(line->value, "%u %u", &success_cnt, &hop_cnt) != 2) {
        log_warn(LD_GENERAL, "Unable to parse guard path bias info: "
                 "Misformated EntryGuardPathBias %s", escaped(line->value));
        continue;
      }

      node->first_hops = hop_cnt;
      node->circuit_successes = success_cnt;
      log_info(LD_GENERAL, "Read %u/%u path bias for node %s",
               node->circuit_successes, node->first_hops, node->nickname);
      /* Note: We rely on the < comparison here to allow us to set a 0
       * rate and disable the feature entirely. If refactoring, don't
       * change to <= */
      if (node->circuit_successes/((double)node->first_hops)
          < pathbias_get_disable_rate(options)) {
        node->path_bias_disabled = 1;
        log_info(LD_GENERAL,
                 "Path bias is too high (%u/%u); disabling node %s",
                 node->circuit_successes, node->first_hops, node->nickname);
      }

    } else {
      log_warn(LD_BUG, "Unexpected key %s", line->key);
    }
  }

  SMARTLIST_FOREACH_BEGIN(new_entry_guards, entry_guard_t *, e) {
     char *sp;
     char *val = digestmap_get(added_by, e->identity);
     if (val && (sp = strchr(val, ' '))) {
       time_t when;
       *sp++ = '\0';
       if (parse_iso_time(sp, &when)<0) {
         log_warn(LD_BUG, "Can't read time %s in EntryGuardAddedBy", sp);
       } else {
         e->chosen_by_version = tor_strdup(val);
         e->chosen_on_date = when;
       }
     } else {
       if (state_version) {
         e->chosen_by_version = tor_strdup(state_version);
         e->chosen_on_date = time(NULL) - crypto_rand_int(3600*24*30);
       }
     }
     if (e->path_bias_disabled && !e->bad_since)
       e->bad_since = time(NULL);
    }
  SMARTLIST_FOREACH_END(e);

  if (*msg || !set) {
    SMARTLIST_FOREACH(new_entry_guards, entry_guard_t *, e,
                      entry_guard_free(e));
    smartlist_free(new_entry_guards);
  } else { /* !err && set */
    if (entry_guards) {
      SMARTLIST_FOREACH(entry_guards, entry_guard_t *, e,
                        entry_guard_free(e));
      smartlist_free(entry_guards);
    }
    entry_guards = new_entry_guards;
    entry_guards_dirty = 0;
    /* XXX024 hand new_entry_guards to this func, and move it up a
     * few lines, so we don't have to re-dirty it */
    if (remove_obsolete_entry_guards(now))
      entry_guards_dirty = 1;
  }
  digestmap_free(added_by, _tor_free);
  return *msg ? -1 : 0;
}

/** Our list of entry guards has changed, or some element of one
 * of our entry guards has changed. Write the changes to disk within
 * the next few minutes.
 */
static void
entry_guards_changed(void)
{
  time_t when;
  entry_guards_dirty = 1;

  /* or_state_save() will call entry_guards_update_state(). */
  when = get_options()->AvoidDiskWrites ? time(NULL) + 3600 : time(NULL)+600;
  or_state_mark_dirty(get_or_state(), when);
}

/** If the entry guard info has not changed, do nothing and return.
 * Otherwise, free the EntryGuards piece of <b>state</b> and create
 * a new one out of the global entry_guards list, and then mark
 * <b>state</b> dirty so it will get saved to disk.
 */
void
entry_guards_update_state(or_state_t *state)
{
  config_line_t **next, *line;
  if (! entry_guards_dirty)
    return;

  config_free_lines(state->EntryGuards);
  next = &state->EntryGuards;
  *next = NULL;
  if (!entry_guards)
    entry_guards = smartlist_new();
  SMARTLIST_FOREACH_BEGIN(entry_guards, entry_guard_t *, e) {
      char dbuf[HEX_DIGEST_LEN+1];
      if (!e->made_contact)
        continue; /* don't write this one to disk */
      *next = line = tor_malloc_zero(sizeof(config_line_t));
      line->key = tor_strdup("EntryGuard");
      base16_encode(dbuf, sizeof(dbuf), e->identity, DIGEST_LEN);
      tor_asprintf(&line->value, "%s %s", e->nickname, dbuf);
      next = &(line->next);
      if (e->unreachable_since) {
        *next = line = tor_malloc_zero(sizeof(config_line_t));
        line->key = tor_strdup("EntryGuardDownSince");
        line->value = tor_malloc(ISO_TIME_LEN+1+ISO_TIME_LEN+1);
        format_iso_time(line->value, e->unreachable_since);
        if (e->last_attempted) {
          line->value[ISO_TIME_LEN] = ' ';
          format_iso_time(line->value+ISO_TIME_LEN+1, e->last_attempted);
        }
        next = &(line->next);
      }
      if (e->bad_since) {
        *next = line = tor_malloc_zero(sizeof(config_line_t));
        line->key = tor_strdup("EntryGuardUnlistedSince");
        line->value = tor_malloc(ISO_TIME_LEN+1);
        format_iso_time(line->value, e->bad_since);
        next = &(line->next);
      }
      if (e->chosen_on_date && e->chosen_by_version &&
          !strchr(e->chosen_by_version, ' ')) {
        char d[HEX_DIGEST_LEN+1];
        char t[ISO_TIME_LEN+1];
        *next = line = tor_malloc_zero(sizeof(config_line_t));
        line->key = tor_strdup("EntryGuardAddedBy");
        base16_encode(d, sizeof(d), e->identity, DIGEST_LEN);
        format_iso_time(t, e->chosen_on_date);
        tor_asprintf(&line->value, "%s %s %s",
                     d, e->chosen_by_version, t);
        next = &(line->next);
      }
      if (e->first_hops) {
        *next = line = tor_malloc_zero(sizeof(config_line_t));
        line->key = tor_strdup("EntryGuardPathBias");
        tor_asprintf(&line->value, "%u %u",
                     e->circuit_successes, e->first_hops);
        next = &(line->next);
      }

  } SMARTLIST_FOREACH_END(e);
  if (!get_options()->AvoidDiskWrites)
    or_state_mark_dirty(get_or_state(), 0);
  entry_guards_dirty = 0;
}

/** If <b>question</b> is the string "entry-guards", then dump
 * to *<b>answer</b> a newly allocated string describing all of
 * the nodes in the global entry_guards list. See control-spec.txt
 * for details.
 * For backward compatibility, we also handle the string "helper-nodes".
 * */
int
getinfo_helper_entry_guards(control_connection_t *conn,
                            const char *question, char **answer,
                            const char **errmsg)
{
  (void) conn;
  (void) errmsg;

  if (!strcmp(question,"entry-guards") ||
      !strcmp(question,"helper-nodes")) {
    smartlist_t *sl = smartlist_new();
    char tbuf[ISO_TIME_LEN+1];
    char nbuf[MAX_VERBOSE_NICKNAME_LEN+1];
    if (!entry_guards)
      entry_guards = smartlist_new();
    SMARTLIST_FOREACH_BEGIN(entry_guards, entry_guard_t *, e) {
        const char *status = NULL;
        time_t when = 0;
        const node_t *node;

        if (!e->made_contact) {
          status = "never-connected";
        } else if (e->bad_since) {
          when = e->bad_since;
          status = "unusable";
        } else {
          status = "up";
        }

        node = node_get_by_id(e->identity);
        if (node) {
          node_get_verbose_nickname(node, nbuf);
        } else {
          nbuf[0] = '$';
          base16_encode(nbuf+1, sizeof(nbuf)-1, e->identity, DIGEST_LEN);
          /* e->nickname field is not very reliable if we don't know about
           * this router any longer; don't include it. */
        }

        if (when) {
          format_iso_time(tbuf, when);
          smartlist_add_asprintf(sl, "%s %s %s\n", nbuf, status, tbuf);
        } else {
          smartlist_add_asprintf(sl, "%s %s\n", nbuf, status);
        }
    } SMARTLIST_FOREACH_END(e);
    *answer = smartlist_join_strings(sl, "", 0, NULL);
    SMARTLIST_FOREACH(sl, char *, c, tor_free(c));
    smartlist_free(sl);
  }
  return 0;
}

/** A list of configured bridges. Whenever we actually get a descriptor
 * for one, we add it as an entry guard.  Note that the order of bridges
 * in this list does not necessarily correspond to the order of bridges
 * in the torrc. */
static smartlist_t *bridge_list = NULL;

/** Mark every entry of the bridge list to be removed on our next call to
 * sweep_bridge_list unless it has first been un-marked. */
void
mark_bridge_list(void)
{
  if (!bridge_list)
    bridge_list = smartlist_new();
  SMARTLIST_FOREACH(bridge_list, bridge_info_t *, b,
                    b->marked_for_removal = 1);
}

/** Remove every entry of the bridge list that was marked with
 * mark_bridge_list if it has not subsequently been un-marked. */
void
sweep_bridge_list(void)
{
  if (!bridge_list)
    bridge_list = smartlist_new();
  SMARTLIST_FOREACH_BEGIN(bridge_list, bridge_info_t *, b) {
    if (b->marked_for_removal) {
      SMARTLIST_DEL_CURRENT(bridge_list, b);
      bridge_free(b);
    }
  } SMARTLIST_FOREACH_END(b);
}

/** Initialize the bridge list to empty, creating it if needed. */
static void
clear_bridge_list(void)
{
  if (!bridge_list)
    bridge_list = smartlist_new();
  SMARTLIST_FOREACH(bridge_list, bridge_info_t *, b, bridge_free(b));
  smartlist_clear(bridge_list);
}

/** Free the bridge <b>bridge</b>. */
static void
bridge_free(bridge_info_t *bridge)
{
  if (!bridge)
    return;

  tor_free(bridge->transport_name);
  tor_free(bridge);
}

/** A list of pluggable transports found in torrc. */
static smartlist_t *transport_list = NULL;

/** Mark every entry of the transport list to be removed on our next call to
 * sweep_transport_list unless it has first been un-marked. */
void
mark_transport_list(void)
{
  if (!transport_list)
    transport_list = smartlist_new();
  SMARTLIST_FOREACH(transport_list, transport_t *, t,
                    t->marked_for_removal = 1);
}

/** Remove every entry of the transport list that was marked with
 * mark_transport_list if it has not subsequently been un-marked. */
void
sweep_transport_list(void)
{
  if (!transport_list)
    transport_list = smartlist_new();
  SMARTLIST_FOREACH_BEGIN(transport_list, transport_t *, t) {
    if (t->marked_for_removal) {
      SMARTLIST_DEL_CURRENT(transport_list, t);
      transport_free(t);
    }
  } SMARTLIST_FOREACH_END(t);
}

/** Initialize the pluggable transports list to empty, creating it if
 *  needed. */
void
clear_transport_list(void)
{
  if (!transport_list)
    transport_list = smartlist_new();
  SMARTLIST_FOREACH(transport_list, transport_t *, t, transport_free(t));
  smartlist_clear(transport_list);
}

/** Free the pluggable transport struct <b>transport</b>. */
void
transport_free(transport_t *transport)
{
  if (!transport)
    return;

  tor_free(transport->name);
  tor_free(transport);
}

/** Returns the transport in our transport list that has the name <b>name</b>.
 *  Else returns NULL. */
transport_t *
transport_get_by_name(const char *name)
{
  tor_assert(name);

  if (!transport_list)
    return NULL;

  SMARTLIST_FOREACH_BEGIN(transport_list, transport_t *, transport) {
    if (!strcmp(transport->name, name))
      return transport;
  } SMARTLIST_FOREACH_END(transport);

  return NULL;
}

/** Returns a transport_t struct for a transport proxy supporting the
    protocol <b>name</b> listening at <b>addr</b>:<b>port</b> using
    SOCKS version <b>socks_ver</b>. */
transport_t *
transport_new(const tor_addr_t *addr, uint16_t port,
                 const char *name, int socks_ver)
{
  transport_t *t = tor_malloc_zero(sizeof(transport_t));

  tor_addr_copy(&t->addr, addr);
  t->port = port;
  t->name = tor_strdup(name);
  t->socks_version = socks_ver;

  return t;
}

/** Resolve any conflicts that the insertion of transport <b>t</b>
 *  might cause.
 *  Return 0 if <b>t</b> is OK and should be registered, 1 if there is
 *  a transport identical to <b>t</b> already registered and -1 if
 *  <b>t</b> cannot be added due to conflicts. */
static int
transport_resolve_conflicts(transport_t *t)
{
  /* This is how we resolve transport conflicts:

     If there is already a transport with the same name and addrport,
     we either have duplicate torrc lines OR we are here post-HUP and
     this transport was here pre-HUP as well. In any case, mark the
     old transport so that it doesn't get removed and ignore the new
     one. Our caller has to free the new transport so we return '1' to
     signify this.

     If there is already a transport with the same name but different
     addrport:
     * if it's marked for removal, it means that it either has a lower
     priority than 't' in torrc (otherwise the mark would have been
     cleared by the paragraph above), or it doesn't exist at all in
     the post-HUP torrc. We destroy the old transport and register 't'.
     * if it's *not* marked for removal, it means that it was newly
     added in the post-HUP torrc or that it's of higher priority, in
     this case we ignore 't'. */
  transport_t *t_tmp = transport_get_by_name(t->name);
  if (t_tmp) { /* same name */
    if (tor_addr_eq(&t->addr, &t_tmp->addr) && (t->port == t_tmp->port)) {
      /* same name *and* addrport */
      t_tmp->marked_for_removal = 0;
      return 1;
    } else { /* same name but different addrport */
      char *new_transport_addr = tor_strdup(fmt_addr(&t->addr));
      if (t_tmp->marked_for_removal) { /* marked for removal */
        log_notice(LD_GENERAL, "You tried to add transport '%s' at '%s:%u' "
                   "but there was already a transport marked for deletion at "
                   "'%s:%u'. We deleted the old transport and registered the "
                   "new one.", t->name, new_transport_addr, t->port,
                   fmt_addr(&t_tmp->addr), t_tmp->port);
        smartlist_remove(transport_list, t_tmp);
        transport_free(t_tmp);
        tor_free(new_transport_addr);
      } else { /* *not* marked for removal */
        log_notice(LD_GENERAL, "You tried to add transport '%s' at '%s:%u' "
                   "but the same transport already exists at '%s:%u'. "
                   "Skipping.", t->name, new_transport_addr, t->port,
                   fmt_addr(&t_tmp->addr), t_tmp->port);
        tor_free(new_transport_addr);
        return -1;
      }
    }
  }

  return 0;
}

/** Add transport <b>t</b> to the internal list of pluggable
 *  transports.
 *  Returns 0 if the transport was added correctly, 1 if the same
 *  transport was already registered (in this case the caller must
 *  free the transport) and -1 if there was an error.  */
int
transport_add(transport_t *t)
{
  int r;
  tor_assert(t);

  r = transport_resolve_conflicts(t);

  switch (r) {
  case 0: /* should register transport */
    if (!transport_list)
      transport_list = smartlist_new();
    smartlist_add(transport_list, t);
    return 0;
  default: /* let our caller know the return code */
    return r;
  }
}

/** Remember a new pluggable transport proxy at <b>addr</b>:<b>port</b>.
 *  <b>name</b> is set to the name of the protocol this proxy uses.
 *  <b>socks_ver</b> is set to the SOCKS version of the proxy. */
int
transport_add_from_config(const tor_addr_t *addr, uint16_t port,
                          const char *name, int socks_ver)
{
  transport_t *t = transport_new(addr, port, name, socks_ver);

  int r = transport_add(t);

  switch (r) {
  case -1:
  default:
    log_notice(LD_GENERAL, "Could not add transport %s at %s:%u. Skipping.",
               t->name, fmt_addr(&t->addr), t->port);
    transport_free(t);
    return -1;
  case 1:
    log_info(LD_GENERAL, "Succesfully registered transport %s at %s:%u.",
             t->name, fmt_addr(&t->addr), t->port);
     transport_free(t); /* falling */
     return 0;
  case 0:
    log_info(LD_GENERAL, "Succesfully registered transport %s at %s:%u.",
             t->name, fmt_addr(&t->addr), t->port);
    return 0;
  }
}

/** Return a bridge pointer if <b>ri</b> is one of our known bridges
 * (either by comparing keys if possible, else by comparing addr/port).
 * Else return NULL. */
static bridge_info_t *
get_configured_bridge_by_addr_port_digest(const tor_addr_t *addr,
                                          uint16_t port,
                                          const char *digest)
{
  if (!bridge_list)
    return NULL;
  SMARTLIST_FOREACH_BEGIN(bridge_list, bridge_info_t *, bridge)
    {
      if (tor_digest_is_zero(bridge->identity) &&
          !tor_addr_compare(&bridge->addr, addr, CMP_EXACT) &&
          bridge->port == port)
        return bridge;
      if (digest && tor_memeq(bridge->identity, digest, DIGEST_LEN))
        return bridge;
    }
  SMARTLIST_FOREACH_END(bridge);
  return NULL;
}

/** Wrapper around get_configured_bridge_by_addr_port_digest() to look
 * it up via router descriptor <b>ri</b>. */
static bridge_info_t *
get_configured_bridge_by_routerinfo(const routerinfo_t *ri)
{
  tor_addr_port_t ap;

  router_get_pref_orport(ri, &ap);
  return get_configured_bridge_by_addr_port_digest(&ap.addr, ap.port,
                                               ri->cache_info.identity_digest);
}

/** Return 1 if <b>ri</b> is one of our known bridges, else 0. */
int
routerinfo_is_a_configured_bridge(const routerinfo_t *ri)
{
  return get_configured_bridge_by_routerinfo(ri) ? 1 : 0;
}

/** Return 1 if <b>node</b> is one of our configured bridges, else 0. */
int
node_is_a_configured_bridge(const node_t *node)
{
  int retval = 0;               /* Negative.  */
  smartlist_t *orports = NULL;

  if (!node)
    goto out;

  orports = node_get_all_orports(node);
  if (orports == NULL)
    goto out;

  SMARTLIST_FOREACH_BEGIN(orports, tor_addr_port_t *, orport) {
    if (get_configured_bridge_by_addr_port_digest(&orport->addr, orport->port,
                                                  node->identity) != NULL) {
      retval = 1;
      goto out;
    }
  } SMARTLIST_FOREACH_END(orport);

 out:
  if (orports != NULL) {
    SMARTLIST_FOREACH(orports, tor_addr_port_t *, p, tor_free(p));
    smartlist_free(orports);
    orports = NULL;
  }
  return retval;
}

/** We made a connection to a router at <b>addr</b>:<b>port</b>
 * without knowing its digest. Its digest turned out to be <b>digest</b>.
 * If it was a bridge, and we still don't know its digest, record it.
 */
void
learned_router_identity(const tor_addr_t *addr, uint16_t port,
                        const char *digest)
{
  bridge_info_t *bridge =
    get_configured_bridge_by_addr_port_digest(addr, port, digest);
  if (bridge && tor_digest_is_zero(bridge->identity)) {
    memcpy(bridge->identity, digest, DIGEST_LEN);
    log_notice(LD_DIR, "Learned fingerprint %s for bridge %s:%d",
               hex_str(digest, DIGEST_LEN), fmt_addr(addr), port);
  }
}

/** Return true if <b>bridge</b> has the same identity digest as
 *  <b>digest</b>. If <b>digest</b> is NULL, it matches
 *  bridges with unspecified identity digests. */
static int
bridge_has_digest(const bridge_info_t *bridge, const char *digest)
{
  if (digest)
    return tor_memeq(digest, bridge->identity, DIGEST_LEN);
  else
    return tor_digest_is_zero(bridge->identity);
}

/** We are about to add a new bridge at <b>addr</b>:<b>port</b>, with optional
 * <b>digest</b> and <b>transport_name</b>. Mark for removal any previously
 * existing bridge with the same address and port, and warn the user as
 * appropriate.
 */
static void
bridge_resolve_conflicts(const tor_addr_t *addr, uint16_t port,
                         const char *digest, const char *transport_name)
{
  /* Iterate the already-registered bridge list:

     If you find a bridge with the same adress and port, mark it for
     removal. It doesn't make sense to have two active bridges with
     the same IP:PORT. If the bridge in question has a different
     digest or transport than <b>digest</b>/<b>transport_name</b>,
     it's probably a misconfiguration and we should warn the user.
  */
  SMARTLIST_FOREACH_BEGIN(bridge_list, bridge_info_t *, bridge) {
    if (bridge->marked_for_removal)
      continue;

    if (tor_addr_eq(&bridge->addr, addr) && (bridge->port == port)) {

      bridge->marked_for_removal = 1;

      if (!bridge_has_digest(bridge, digest) ||
          strcmp_opt(bridge->transport_name, transport_name)) {
        /* warn the user */
        char *bridge_description_new, *bridge_description_old;
        tor_asprintf(&bridge_description_new, "%s:%u:%s:%s",
                     fmt_addr(addr), port,
                     digest ? hex_str(digest, DIGEST_LEN) : "",
                     transport_name ? transport_name : "");
        tor_asprintf(&bridge_description_old, "%s:%u:%s:%s",
                     fmt_addr(&bridge->addr), bridge->port,
                     tor_digest_is_zero(bridge->identity) ?
                     "" : hex_str(bridge->identity,DIGEST_LEN),
                     bridge->transport_name ? bridge->transport_name : "");

        log_warn(LD_GENERAL,"Tried to add bridge '%s', but we found a conflict"
                 " with the already registered bridge '%s'. We will discard"
                 " the old bridge and keep '%s'. If this is not what you"
                 " wanted, please change your configuration file accordingly.",
                 bridge_description_new, bridge_description_old,
                 bridge_description_new);

        tor_free(bridge_description_new);
        tor_free(bridge_description_old);
      }
    }
  } SMARTLIST_FOREACH_END(bridge);
}

/** Remember a new bridge at <b>addr</b>:<b>port</b>. If <b>digest</b>
 * is set, it tells us the identity key too.  If we already had the
 * bridge in our list, unmark it, and don't actually add anything new.
 * If <b>transport_name</b> is non-NULL - the bridge is associated with a
 * pluggable transport - we assign the transport to the bridge. */
void
bridge_add_from_config(const tor_addr_t *addr, uint16_t port,
                       const char *digest, const char *transport_name)
{
  bridge_info_t *b;

  bridge_resolve_conflicts(addr, port, digest, transport_name);

  b = tor_malloc_zero(sizeof(bridge_info_t));
  tor_addr_copy(&b->addr, addr);
  b->port = port;
  if (digest)
    memcpy(b->identity, digest, DIGEST_LEN);
  if (transport_name)
    b->transport_name = tor_strdup(transport_name);
  b->fetch_status.schedule = DL_SCHED_BRIDGE;
  if (!bridge_list)
    bridge_list = smartlist_new();

  smartlist_add(bridge_list, b);
}

/** Return true iff <b>routerset</b> contains the bridge <b>bridge</b>. */
static int
routerset_contains_bridge(const routerset_t *routerset,
                          const bridge_info_t *bridge)
{
  int result;
  extend_info_t *extinfo;
  tor_assert(bridge);
  if (!routerset)
    return 0;

  extinfo = extend_info_alloc(
         NULL, bridge->identity, NULL, &bridge->addr, bridge->port);
  result = routerset_contains_extendinfo(routerset, extinfo);
  extend_info_free(extinfo);
  return result;
}

/** If <b>digest</b> is one of our known bridges, return it. */
static bridge_info_t *
find_bridge_by_digest(const char *digest)
{
  SMARTLIST_FOREACH(bridge_list, bridge_info_t *, bridge,
    {
      if (tor_memeq(bridge->identity, digest, DIGEST_LEN))
        return bridge;
    });
  return NULL;
}

/* DOCDOC find_transport_name_by_bridge_addrport */
const char *
find_transport_name_by_bridge_addrport(const tor_addr_t *addr, uint16_t port)
{
  if (!bridge_list)
    return NULL;

  SMARTLIST_FOREACH_BEGIN(bridge_list, const bridge_info_t *, bridge) {
    if (tor_addr_eq(&bridge->addr, addr) &&
        (bridge->port == port))
      return bridge->transport_name;
  } SMARTLIST_FOREACH_END(bridge);

  return NULL;
}

/** If <b>addr</b> and <b>port</b> match the address and port of a
 * bridge of ours that uses pluggable transports, place its transport
 * in <b>transport</b>.
 *
 * Return 0 on success (found a transport, or found a bridge with no
 * transport, or found no bridge); return -1 if we should be using a
 * transport, but the transport could not be found.
 */
int
find_transport_by_bridge_addrport(const tor_addr_t *addr, uint16_t port,
                                  const transport_t **transport)
{
  *transport = NULL;
  if (!bridge_list)
    return 0;

  SMARTLIST_FOREACH_BEGIN(bridge_list, const bridge_info_t *, bridge) {
    if (tor_addr_eq(&bridge->addr, addr) &&
        (bridge->port == port)) { /* bridge matched */
      if (bridge->transport_name) { /* it also uses pluggable transports */
        *transport = transport_get_by_name(bridge->transport_name);
        if (*transport == NULL) { /* it uses pluggable transports, but
                                     the transport could not be found! */
          return -1;
        }
        return 0;
      } else { /* bridge matched, but it doesn't use transports. */
        break;
      }
    }
  } SMARTLIST_FOREACH_END(bridge);

  *transport = NULL;
  return 0;
}

/** We need to ask <b>bridge</b> for its server descriptor. */
static void
launch_direct_bridge_descriptor_fetch(bridge_info_t *bridge)
{
  char *address;
  const or_options_t *options = get_options();

  if (connection_get_by_type_addr_port_purpose(
      CONN_TYPE_DIR, &bridge->addr, bridge->port,
      DIR_PURPOSE_FETCH_SERVERDESC))
    return; /* it's already on the way */

  if (routerset_contains_bridge(options->ExcludeNodes, bridge)) {
    download_status_mark_impossible(&bridge->fetch_status);
    log_warn(LD_APP, "Not using bridge at %s: it is in ExcludeNodes.",
             safe_str_client(fmt_addr(&bridge->addr)));
    return;
  }

  address = tor_dup_addr(&bridge->addr);

  directory_initiate_command(address, &bridge->addr,
                             bridge->port, 0,
                             0, /* does not matter */
                             1, bridge->identity,
                             DIR_PURPOSE_FETCH_SERVERDESC,
                             ROUTER_PURPOSE_BRIDGE,
                             0, "authority.z", NULL, 0, 0);
  tor_free(address);
}

/** Fetching the bridge descriptor from the bridge authority returned a
 * "not found". Fall back to trying a direct fetch. */
void
retry_bridge_descriptor_fetch_directly(const char *digest)
{
  bridge_info_t *bridge = find_bridge_by_digest(digest);
  if (!bridge)
    return; /* not found? oh well. */

  launch_direct_bridge_descriptor_fetch(bridge);
}

/** For each bridge in our list for which we don't currently have a
 * descriptor, fetch a new copy of its descriptor -- either directly
 * from the bridge or via a bridge authority. */
void
fetch_bridge_descriptors(const or_options_t *options, time_t now)
{
  int num_bridge_auths = get_n_authorities(BRIDGE_DIRINFO);
  int ask_bridge_directly;
  int can_use_bridge_authority;

  if (!bridge_list)
    return;

  /* If we still have unconfigured managed proxies, don't go and
     connect to a bridge. */
  if (pt_proxies_configuration_pending())
    return;

  SMARTLIST_FOREACH_BEGIN(bridge_list, bridge_info_t *, bridge)
    {
      if (!download_status_is_ready(&bridge->fetch_status, now,
                                    IMPOSSIBLE_TO_DOWNLOAD))
        continue; /* don't bother, no need to retry yet */
      if (routerset_contains_bridge(options->ExcludeNodes, bridge)) {
        download_status_mark_impossible(&bridge->fetch_status);
        log_warn(LD_APP, "Not using bridge at %s: it is in ExcludeNodes.",
                 safe_str_client(fmt_addr(&bridge->addr)));
        continue;
      }

      /* schedule another fetch as if this one will fail, in case it does */
      download_status_failed(&bridge->fetch_status, 0);

      can_use_bridge_authority = !tor_digest_is_zero(bridge->identity) &&
                                 num_bridge_auths;
      ask_bridge_directly = !can_use_bridge_authority ||
                            !options->UpdateBridgesFromAuthority;
      log_debug(LD_DIR, "ask_bridge_directly=%d (%d, %d, %d)",
                ask_bridge_directly, tor_digest_is_zero(bridge->identity),
                !options->UpdateBridgesFromAuthority, !num_bridge_auths);

      if (ask_bridge_directly &&
          !fascist_firewall_allows_address_or(&bridge->addr, bridge->port)) {
        log_notice(LD_DIR, "Bridge at '%s:%d' isn't reachable by our "
                   "firewall policy. %s.", fmt_addr(&bridge->addr),
                   bridge->port,
                   can_use_bridge_authority ?
                     "Asking bridge authority instead" : "Skipping");
        if (can_use_bridge_authority)
          ask_bridge_directly = 0;
        else
          continue;
      }

      if (ask_bridge_directly) {
        /* we need to ask the bridge itself for its descriptor. */
        launch_direct_bridge_descriptor_fetch(bridge);
      } else {
        /* We have a digest and we want to ask an authority. We could
         * combine all the requests into one, but that may give more
         * hints to the bridge authority than we want to give. */
        char resource[10 + HEX_DIGEST_LEN];
        memcpy(resource, "fp/", 3);
        base16_encode(resource+3, HEX_DIGEST_LEN+1,
                      bridge->identity, DIGEST_LEN);
        memcpy(resource+3+HEX_DIGEST_LEN, ".z", 3);
        log_info(LD_DIR, "Fetching bridge info '%s' from bridge authority.",
                 resource);
        directory_get_from_dirserver(DIR_PURPOSE_FETCH_SERVERDESC,
                ROUTER_PURPOSE_BRIDGE, resource, 0);
      }
    }
  SMARTLIST_FOREACH_END(bridge);
}

/** If our <b>bridge</b> is configured to be a different address than
 * the bridge gives in <b>node</b>, rewrite the routerinfo
 * we received to use the address we meant to use. Now we handle
 * multihomed bridges better.
 */
static void
rewrite_node_address_for_bridge(const bridge_info_t *bridge, node_t *node)
{
  /* XXXX move this function. */
  /* XXXX overridden addresses should really live in the node_t, so that the
   *   routerinfo_t and the microdesc_t can be immutable.  But we can only
   *   do that safely if we know that no function that connects to an OR
   *   does so through an address from any source other than node_get_addr().
   */
  tor_addr_t addr;

  if (node->ri) {
    routerinfo_t *ri = node->ri;
    tor_addr_from_ipv4h(&addr, ri->addr);

    if ((!tor_addr_compare(&bridge->addr, &addr, CMP_EXACT) &&
         bridge->port == ri->or_port) ||
        (!tor_addr_compare(&bridge->addr, &ri->ipv6_addr, CMP_EXACT) &&
         bridge->port == ri->ipv6_orport)) {
      /* they match, so no need to do anything */
    } else {
      if (tor_addr_family(&bridge->addr) == AF_INET) {
        ri->addr = tor_addr_to_ipv4h(&bridge->addr);
        tor_free(ri->address);
        ri->address = tor_dup_ip(ri->addr);
        ri->or_port = bridge->port;
        log_info(LD_DIR,
                 "Adjusted bridge routerinfo for '%s' to match configured "
                 "address %s:%d.",
                 ri->nickname, ri->address, ri->or_port);
      } else if (tor_addr_family(&bridge->addr) == AF_INET6) {
        tor_addr_copy(&ri->ipv6_addr, &bridge->addr);
        ri->ipv6_orport = bridge->port;
        log_info(LD_DIR,
                 "Adjusted bridge routerinfo for '%s' to match configured "
                 "address %s:%d.",
                 ri->nickname, fmt_addr(&ri->ipv6_addr), ri->ipv6_orport);
      } else {
        log_err(LD_BUG, "Address family not supported: %d.",
                tor_addr_family(&bridge->addr));
        return;
      }
    }

    /* Indicate that we prefer connecting to this bridge over the
       protocol that the bridge address indicates.  Last bridge
       descriptor handled wins.  */
    ri->ipv6_preferred = tor_addr_family(&bridge->addr) == AF_INET6;

    /* XXXipv6 we lack support for falling back to another address for
       the same relay, warn the user */
    if (!tor_addr_is_null(&ri->ipv6_addr)) {
      tor_addr_port_t ap;
      router_get_pref_orport(ri, &ap);
      log_notice(LD_CONFIG,
                 "Bridge '%s' has both an IPv4 and an IPv6 address.  "
                 "Will prefer using its %s address (%s:%d).",
                 ri->nickname,
                 ri->ipv6_preferred ? "IPv6" : "IPv4",
                 fmt_addr(&ap.addr), ap.port);
    }
  }
  if (node->rs) {
    routerstatus_t *rs = node->rs;
    tor_addr_from_ipv4h(&addr, rs->addr);

    if (!tor_addr_compare(&bridge->addr, &addr, CMP_EXACT) &&
        bridge->port == rs->or_port) {
      /* they match, so no need to do anything */
    } else {
      rs->addr = tor_addr_to_ipv4h(&bridge->addr);
      rs->or_port = bridge->port;
      log_info(LD_DIR,
               "Adjusted bridge routerstatus for '%s' to match "
               "configured address %s:%d.",
               rs->nickname, fmt_addr(&bridge->addr), rs->or_port);
    }
  }
}

/** We just learned a descriptor for a bridge. See if that
 * digest is in our entry guard list, and add it if not. */
void
learned_bridge_descriptor(routerinfo_t *ri, int from_cache)
{
  tor_assert(ri);
  tor_assert(ri->purpose == ROUTER_PURPOSE_BRIDGE);
  if (get_options()->UseBridges) {
    int first = !any_bridge_descriptors_known();
    bridge_info_t *bridge = get_configured_bridge_by_routerinfo(ri);
    time_t now = time(NULL);
    router_set_status(ri->cache_info.identity_digest, 1);

    if (bridge) { /* if we actually want to use this one */
      node_t *node;
      /* it's here; schedule its re-fetch for a long time from now. */
      if (!from_cache)
        download_status_reset(&bridge->fetch_status);

      node = node_get_mutable_by_id(ri->cache_info.identity_digest);
      tor_assert(node);
      rewrite_node_address_for_bridge(bridge, node);
      add_an_entry_guard(node, 1, 1);

      log_notice(LD_DIR, "new bridge descriptor '%s' (%s): %s", ri->nickname,
                 from_cache ? "cached" : "fresh", router_describe(ri));
      /* set entry->made_contact so if it goes down we don't drop it from
       * our entry node list */
      entry_guard_register_connect_status(ri->cache_info.identity_digest,
                                          1, 0, now);
      if (first)
        routerlist_retry_directory_downloads(now);
    }
  }
}

/** Return 1 if any of our entry guards have descriptors that
 * are marked with purpose 'bridge' and are running. Else return 0.
 *
 * We use this function to decide if we're ready to start building
 * circuits through our bridges, or if we need to wait until the
 * directory "server/authority" requests finish. */
int
any_bridge_descriptors_known(void)
{
  tor_assert(get_options()->UseBridges);
  return choose_random_entry(NULL)!=NULL ? 1 : 0;
}

/** Return 1 if there are any directory conns fetching bridge descriptors
 * that aren't marked for close. We use this to guess if we should tell
 * the controller that we have a problem. */
int
any_pending_bridge_descriptor_fetches(void)
{
  smartlist_t *conns = get_connection_array();
  SMARTLIST_FOREACH_BEGIN(conns, connection_t *, conn) {
    if (conn->type == CONN_TYPE_DIR &&
        conn->purpose == DIR_PURPOSE_FETCH_SERVERDESC &&
        TO_DIR_CONN(conn)->router_purpose == ROUTER_PURPOSE_BRIDGE &&
        !conn->marked_for_close &&
        conn->linked &&
        conn->linked_conn && !conn->linked_conn->marked_for_close) {
      log_debug(LD_DIR, "found one: %s", conn->address);
      return 1;
    }
  } SMARTLIST_FOREACH_END(conn);
  return 0;
}

/** Return 1 if we have at least one descriptor for an entry guard
 * (bridge or member of EntryNodes) and all descriptors we know are
 * down. Else return 0. If <b>act</b> is 1, then mark the down guards
 * up; else just observe and report. */
static int
entries_retry_helper(const or_options_t *options, int act)
{
  const node_t *node;
  int any_known = 0;
  int any_running = 0;
  int need_bridges = options->UseBridges != 0;
  if (!entry_guards)
    entry_guards = smartlist_new();
  SMARTLIST_FOREACH_BEGIN(entry_guards, entry_guard_t *, e) {
      node = node_get_by_id(e->identity);
      if (node && node_has_descriptor(node) &&
          node_is_bridge(node) == need_bridges) {
        any_known = 1;
        if (node->is_running)
          any_running = 1; /* some entry is both known and running */
        else if (act) {
          /* Mark all current connections to this OR as unhealthy, since
           * otherwise there could be one that started 30 seconds
           * ago, and in 30 seconds it will time out, causing us to mark
           * the node down and undermine the retry attempt. We mark even
           * the established conns, since if the network just came back
           * we'll want to attach circuits to fresh conns. */
          connection_or_set_bad_connections(node->identity, 1);

          /* mark this entry node for retry */
          router_set_status(node->identity, 1);
          e->can_retry = 1;
          e->bad_since = 0;
        }
      }
  } SMARTLIST_FOREACH_END(e);
  log_debug(LD_DIR, "%d: any_known %d, any_running %d",
            act, any_known, any_running);
  return any_known && !any_running;
}

/** Do we know any descriptors for our bridges / entrynodes, and are
 * all the ones we have descriptors for down? */
int
entries_known_but_down(const or_options_t *options)
{
  tor_assert(entry_list_is_constrained(options));
  return entries_retry_helper(options, 0);
}

/** Mark all down known bridges / entrynodes up. */
void
entries_retry_all(const or_options_t *options)
{
  tor_assert(entry_list_is_constrained(options));
  entries_retry_helper(options, 1);
}

/** Return true if we've ever had a bridge running a Tor version that can't
 * provide microdescriptors to us. In that case fall back to asking for
 * full descriptors. Eventually all bridges will support microdescriptors
 * and we can take this check out; see bug 4013. */
int
any_bridges_dont_support_microdescriptors(void)
{
  const node_t *node;
  static int ever_answered_yes = 0;
  if (!get_options()->UseBridges || !entry_guards)
    return 0;
  if (ever_answered_yes)
    return 1; /* if we ever answer 'yes', always answer 'yes' */
  SMARTLIST_FOREACH_BEGIN(entry_guards, entry_guard_t *, e) {
    node = node_get_by_id(e->identity);
    if (node && node->ri &&
        node_is_bridge(node) && node_is_a_configured_bridge(node) &&
        !tor_version_supports_microdescriptors(node->ri->platform)) {
      /* This is one of our current bridges, and we know enough about
       * it to know that it won't be able to answer our microdescriptor
       * questions. */
      ever_answered_yes = 1;
      return 1;
    }
  } SMARTLIST_FOREACH_END(e);
  return 0;
}

/** Release all storage held by the list of entry guards and related
 * memory structs. */
void
entry_guards_free_all(void)
{
  if (entry_guards) {
    SMARTLIST_FOREACH(entry_guards, entry_guard_t *, e,
                      entry_guard_free(e));
    smartlist_free(entry_guards);
    entry_guards = NULL;
  }
  clear_bridge_list();
  clear_transport_list();
  smartlist_free(bridge_list);
  smartlist_free(transport_list);
  bridge_list = NULL;
  transport_list = NULL;
}

