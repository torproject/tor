/* Copyright (c) 2019-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file congestion_control_vegas.c
 * \brief Code that implements the TOR_VEGAS congestion control algorithm
 *        from Proposal #324.
 */

#define TOR_CONGESTION_CONTROL_VEGAS_PRIVATE

#include "core/or/or.h"

#include "core/or/crypt_path.h"
#include "core/or/or_circuit_st.h"
#include "core/or/sendme.h"
#include "core/or/congestion_control_st.h"
#include "core/or/congestion_control_common.h"
#include "core/or/congestion_control_vegas.h"
#include "core/or/circuitlist.h"
#include "core/or/circuituse.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/channel.h"
#include "feature/nodelist/networkstatus.h"
#include "feature/control/control_events.h"
#include "lib/math/stats.h"

#define OUTBUF_CELLS (2*TLS_RECORD_MAX_CELLS)

#define SS_CWND_MAX_DFLT (5000)

/* sbws circs are two hops, so params are based on 2 outbufs of cells */
#define VEGAS_ALPHA_SBWS_DFLT (2*OUTBUF_CELLS-TLS_RECORD_MAX_CELLS)
#define VEGAS_BETA_SBWS_DFLT (2*OUTBUF_CELLS+TLS_RECORD_MAX_CELLS)
#define VEGAS_GAMMA_SBWS_DFLT (2*OUTBUF_CELLS)
#define VEGAS_DELTA_SBWS_DFLT (4*OUTBUF_CELLS)
#define VEGAS_SSCAP_SBWS_DFLT (400)

/* Exits are three hops, so params are based on 3 outbufs of cells */
#define VEGAS_ALPHA_EXIT_DFLT (2*OUTBUF_CELLS)
#define VEGAS_BETA_EXIT_DFLT (4*OUTBUF_CELLS)
#define VEGAS_GAMMA_EXIT_DFLT (3*OUTBUF_CELLS)
#define VEGAS_DELTA_EXIT_DFLT (6*OUTBUF_CELLS)
#define VEGAS_SSCAP_EXIT_DFLT (500)

/* Onion rends are six hops, so params are based on 6 outbufs of cells */
#define VEGAS_ALPHA_ONION_DFLT (3*OUTBUF_CELLS)
#define VEGAS_BETA_ONION_DFLT (7*OUTBUF_CELLS)
#define VEGAS_GAMMA_ONION_DFLT (5*OUTBUF_CELLS)
#define VEGAS_DELTA_ONION_DFLT (9*OUTBUF_CELLS)
#define VEGAS_SSCAP_ONION_DFLT (600)

/** Moving average of the cc->cwnd from each circuit exiting slowstart. */
double cc_stats_vegas_exit_ss_cwnd_ma = 0;
double cc_stats_vegas_exit_ss_bdp_ma = 0;
double cc_stats_vegas_exit_ss_inc_ma = 0;
double cc_stats_vegas_gamma_drop_ma = 0;
double cc_stats_vegas_delta_drop_ma = 0;
double cc_stats_vegas_ss_csig_blocked_ma = 0;
double cc_stats_vegas_csig_blocked_ma = 0;
double cc_stats_vegas_csig_alpha_ma = 0;
double cc_stats_vegas_csig_beta_ma = 0;
double cc_stats_vegas_csig_delta_ma = 0;

double cc_stats_vegas_ss_queue_ma = 0;
double cc_stats_vegas_queue_ma = 0;
double cc_stats_vegas_bdp_ma = 0;

/** Stats on how many times we reached "delta" param. */
uint64_t cc_stats_vegas_above_delta = 0;
/** Stats on how many times we reached "ss_cwnd_max" param. */
uint64_t cc_stats_vegas_above_ss_cwnd_max = 0;
uint64_t cc_stats_vegas_below_ss_inc_floor = 0;
uint64_t cc_stats_vegas_circ_exited_ss = 0;

/**
 * The original TCP Vegas congestion window BDP estimator.
 */
static inline uint64_t
vegas_bdp(const congestion_control_t *cc)
{
  return cc->bdp[BDP_ALG_CWND_RTT];
}

/**
 * Cache Vegas consensus parameters.
 */
void
congestion_control_vegas_set_params(congestion_control_t *cc,
                                    cc_path_t path)
{
  tor_assert(cc->cc_alg == CC_ALG_VEGAS);
  const char *alpha_str = NULL, *beta_str = NULL, *gamma_str = NULL;
  const char *delta_str = NULL, *sscap_str = NULL;
  int alpha, beta, gamma, delta, ss_cwnd_cap;

  switch (path) {
    case CC_PATH_SBWS:
      alpha_str = "cc_vegas_alpha_sbws";
      beta_str = "cc_vegas_beta_sbws";
      gamma_str = "cc_vegas_gamma_sbws";
      delta_str = "cc_vegas_delta_sbws";
      sscap_str = "cc_sscap_sbws";
      alpha = VEGAS_ALPHA_SBWS_DFLT;
      beta = VEGAS_BETA_SBWS_DFLT;
      gamma = VEGAS_GAMMA_SBWS_DFLT;
      delta = VEGAS_DELTA_SBWS_DFLT;
      ss_cwnd_cap = VEGAS_SSCAP_SBWS_DFLT;
      break;
    case CC_PATH_EXIT:
    case CC_PATH_ONION_SOS:
      alpha_str = "cc_vegas_alpha_exit";
      beta_str = "cc_vegas_beta_exit";
      gamma_str = "cc_vegas_gamma_exit";
      delta_str = "cc_vegas_delta_exit";
      sscap_str = "cc_sscap_exit";
      alpha = VEGAS_ALPHA_EXIT_DFLT;
      beta = VEGAS_BETA_EXIT_DFLT;
      gamma = VEGAS_GAMMA_EXIT_DFLT;
      delta = VEGAS_DELTA_EXIT_DFLT;
      ss_cwnd_cap = VEGAS_SSCAP_EXIT_DFLT;
      break;
    case CC_PATH_ONION:
    case CC_PATH_ONION_VG:
      alpha_str = "cc_vegas_alpha_onion";
      beta_str = "cc_vegas_beta_onion";
      gamma_str = "cc_vegas_gamma_onion";
      delta_str = "cc_vegas_delta_onion";
      sscap_str = "cc_sscap_onion";
      alpha = VEGAS_ALPHA_ONION_DFLT;
      beta = VEGAS_BETA_ONION_DFLT;
      gamma = VEGAS_GAMMA_ONION_DFLT;
      delta = VEGAS_DELTA_ONION_DFLT;
      ss_cwnd_cap = VEGAS_SSCAP_ONION_DFLT;
      break;
    default:
      tor_assert(0);
      break;
  }

  cc->vegas_params.ss_cwnd_cap =
   networkstatus_get_param(NULL, sscap_str,
      ss_cwnd_cap,
      100,
      INT32_MAX);

  cc->vegas_params.ss_cwnd_max =
   networkstatus_get_param(NULL, "cc_ss_max",
      SS_CWND_MAX_DFLT,
      500,
      INT32_MAX);

  cc->vegas_params.alpha =
   networkstatus_get_param(NULL, alpha_str,
      alpha,
      0,
      1000);

  cc->vegas_params.beta =
   networkstatus_get_param(NULL, beta_str,
      beta,
      0,
      1000);

  cc->vegas_params.gamma =
   networkstatus_get_param(NULL, gamma_str,
      gamma,
      0,
      1000);

  cc->vegas_params.delta =
   networkstatus_get_param(NULL, delta_str,
      delta,
      0,
      INT32_MAX);
}

/**
 * Common log function for tracking all vegas state.
 */
static void
congestion_control_vegas_log(const circuit_t *circ,
                             const congestion_control_t *cc)
{
  uint64_t queue_use = cc->cwnd - vegas_bdp(cc);

  if (CIRCUIT_IS_ORIGIN(circ) &&
      circ->purpose == CIRCUIT_PURPOSE_S_REND_JOINED) {
    log_info(LD_CIRC,
               "CC: TOR_VEGAS Onion Circuit %d "
               "RTT: %"PRIu64", %"PRIu64", %"PRIu64", "
               "CWND: %"PRIu64", "
               "INFL: %"PRIu64", "
               "VBDP: %"PRIu64", "
               "QUSE: %"PRIu64", "
               "BWE: %"PRIu64", "
               "SS: %d",
             CONST_TO_ORIGIN_CIRCUIT(circ)->global_identifier,
             cc->min_rtt_usec/1000,
             cc->ewma_rtt_usec/1000,
             cc->max_rtt_usec/1000,
             cc->cwnd,
             cc->inflight,
             vegas_bdp(cc),
             queue_use,
             cc->cwnd*CELL_MAX_NETWORK_SIZE*1000/
                MAX(cc->min_rtt_usec,cc->ewma_rtt_usec),
             cc->in_slow_start
             );
  } else {
    log_info(LD_CIRC,
               "CC: TOR_VEGAS "
               "RTT: %"PRIu64", %"PRIu64", %"PRIu64", "
               "CWND: %"PRIu64", "
               "INFL: %"PRIu64", "
               "VBDP: %"PRIu64", "
               "QUSE: %"PRIu64", "
               "BWE: %"PRIu64", "
               "SS: %d",
             cc->min_rtt_usec/1000,
             cc->ewma_rtt_usec/1000,
             cc->max_rtt_usec/1000,
             cc->cwnd,
             cc->inflight,
             vegas_bdp(cc),
             queue_use,
             cc->cwnd*CELL_MAX_NETWORK_SIZE*1000/
                MAX(cc->min_rtt_usec,cc->ewma_rtt_usec),
             cc->in_slow_start
             );
  }
}

/**
 * Implements RFC3742: Limited Slow Start.
 * https://datatracker.ietf.org/doc/html/rfc3742#section-2
 */
static inline uint64_t
rfc3742_ss_inc(const congestion_control_t *cc)
{
  if (cc->cwnd <= cc->vegas_params.ss_cwnd_cap) {
    /* If less than the cap, round and always grow by at least 1 sendme_inc. */
    return ((uint64_t)cc->cwnd_inc_pct_ss*cc->sendme_inc + 50)/100;
  } else {
    // K = int(cwnd/(0.5 max_ssthresh));
    //  => K = 2*cwnd/max_ssthresh
    // cwnd += int(MSS/K);
    //  => cwnd += MSS*max_ssthresh/(2*cwnd)
    return ((uint64_t)cc->sendme_inc*cc->vegas_params.ss_cwnd_cap + cc->cwnd)/
            (2*cc->cwnd);
  }
}

/**
 * Exit Vegas slow start.
 *
 * This function sets our slow-start state to 0, and emits logs
 * and control port information signifying end of slow start.
 * It also schedules the next CWND update for steady-state.
 */
static void
congestion_control_vegas_exit_slow_start(const circuit_t *circ,
                                         congestion_control_t *cc)
{
  congestion_control_vegas_log(circ, cc);
  cc->in_slow_start = 0;
  cc->next_cc_event = CWND_UPDATE_RATE(cc);
  congestion_control_vegas_log(circ, cc);

  /* Update metricsport metrics */
  cc_stats_vegas_exit_ss_cwnd_ma =
    stats_update_running_avg(cc_stats_vegas_exit_ss_cwnd_ma,
                             cc->cwnd);
  cc_stats_vegas_exit_ss_bdp_ma =
    stats_update_running_avg(cc_stats_vegas_exit_ss_bdp_ma,
                             vegas_bdp(cc));
  cc_stats_vegas_exit_ss_inc_ma =
    stats_update_running_avg(cc_stats_vegas_exit_ss_inc_ma,
                             rfc3742_ss_inc(cc));
  cc_stats_vegas_circ_exited_ss++;

  /* We need to report that slow start has exited ASAP,
   * for sbws bandwidth measurement. */
  if (CIRCUIT_IS_ORIGIN(circ)) {
    /* We must discard const here because the event modifies fields :/ */
    control_event_circ_bandwidth_used_for_circ(
            TO_ORIGIN_CIRCUIT((circuit_t*)circ));
  }
}

/**
 * Process a SENDME and update the congestion window according to the
 * rules specified in TOR_VEGAS of Proposal #324.
 *
 * Essentially, this algorithm attempts to measure queue lengths on
 * the circuit by subtracting the bandwidth-delay-product estimate
 * from the current congestion window.
 *
 * If the congestion window is larger than the bandwidth-delay-product,
 * then data is assumed to be queuing. We reduce the congestion window
 * in that case.
 *
 * If the congestion window is smaller than the bandwidth-delay-product,
 * then there is spare bandwidth capacity on the circuit. We increase the
 * congestion window in that case.
 *
 * The congestion window is updated only once every congestion window worth of
 * packets, even if the signal persists. It is also updated whenever the
 * upstream orcon blocks, or unblocks. This minimizes local client queues.
 */
int
congestion_control_vegas_process_sendme(congestion_control_t *cc,
                                        const circuit_t *circ,
                                        const crypt_path_t *layer_hint)
{
  uint64_t queue_use;

  tor_assert(cc && cc->cc_alg == CC_ALG_VEGAS);
  tor_assert(circ);

  /* Update ack counter until next congestion signal event is allowed */
  if (cc->next_cc_event)
    cc->next_cc_event--;

  /* Compute BDP and RTT. If we did not update, don't run the alg */
  if (!congestion_control_update_circuit_estimates(cc, circ, layer_hint)) {
    cc->inflight = cc->inflight - cc->sendme_inc;
    return 0;
  }

  /* The queue use is the amount in which our cwnd is above BDP;
   * if it is below, then 0 queue use. */
  if (vegas_bdp(cc) > cc->cwnd)
    queue_use = 0; // This should not happen anymore..
  else
    queue_use = cc->cwnd - vegas_bdp(cc);

  if (cc->in_slow_start) {
    if (queue_use < cc->vegas_params.gamma && !cc->blocked_chan) {
      /* Get the "Limited Slow Start" increment */
      uint64_t inc = rfc3742_ss_inc(cc);

      // Check if inc is less than what we would do in steady-state
      // avoidance
      if (inc*SENDME_PER_CWND(cc) <= CWND_INC(cc)) {
        cc->cwnd += inc;
        congestion_control_vegas_exit_slow_start(circ, cc);

        cc_stats_vegas_below_ss_inc_floor++;

        /* We exited slow start without being blocked */
        cc_stats_vegas_ss_csig_blocked_ma =
          stats_update_running_avg(cc_stats_vegas_ss_csig_blocked_ma,
                                   0);
      } else {
        cc->cwnd += inc;
        cc->next_cc_event = 1; // Technically irellevant, but for consistency
      }
    } else {
      uint64_t old_cwnd = cc->cwnd;

      /* Congestion signal: Set cwnd to gamma threshhold */
      cc->cwnd = vegas_bdp(cc) + cc->vegas_params.gamma;

      /* Compute the percentage we experience a blocked csig vs RTT sig */
      if (cc->blocked_chan) {
        cc_stats_vegas_ss_csig_blocked_ma =
          stats_update_running_avg(cc_stats_vegas_ss_csig_blocked_ma,
                                   100);
      } else {
        uint64_t cwnd_diff = (old_cwnd > cc->cwnd ? old_cwnd - cc->cwnd : 0);

        cc_stats_vegas_ss_csig_blocked_ma =
          stats_update_running_avg(cc_stats_vegas_ss_csig_blocked_ma,
                                   0);

        /* Account the amount we reduced the cwnd by for the gamma cutoff */
        cc_stats_vegas_gamma_drop_ma =
          stats_update_running_avg(cc_stats_vegas_gamma_drop_ma,
                               cwnd_diff);
      }

      congestion_control_vegas_exit_slow_start(circ, cc);
    }

    if (cc->cwnd >= cc->vegas_params.ss_cwnd_max) {
      cc->cwnd = cc->vegas_params.ss_cwnd_max;
      congestion_control_vegas_exit_slow_start(circ, cc);
      cc_stats_vegas_above_ss_cwnd_max++;
    }

    cc_stats_vegas_ss_queue_ma =
       stats_update_running_avg(cc_stats_vegas_ss_queue_ma,
                             queue_use);
  /* After slow start, We only update once per window */
  } else if (cc->next_cc_event == 0) {
    if (queue_use > cc->vegas_params.delta) {
      uint64_t old_cwnd = cc->cwnd;
      uint64_t cwnd_diff;

      /* If we are above the delta threshhold, drop cwnd down to the
       * delta threshhold. */
      cc->cwnd = vegas_bdp(cc) + cc->vegas_params.delta - CWND_INC(cc);

      /* Account the amount we reduced the cwnd by for the gamma cutoff */
      cwnd_diff = (old_cwnd > cc->cwnd ? old_cwnd - cc->cwnd : 0);
      cc_stats_vegas_delta_drop_ma =
        stats_update_running_avg(cc_stats_vegas_delta_drop_ma,
                             cwnd_diff);

      cc_stats_vegas_above_delta++;

      /* Percentage metrics: Add 100% delta, 0 for other two */
      cc_stats_vegas_csig_alpha_ma =
          stats_update_running_avg(cc_stats_vegas_csig_alpha_ma,
                                   0);
      cc_stats_vegas_csig_beta_ma =
          stats_update_running_avg(cc_stats_vegas_csig_beta_ma,
                                   0);
      cc_stats_vegas_csig_delta_ma =
          stats_update_running_avg(cc_stats_vegas_csig_delta_ma,
                                   100);
    } else if (queue_use > cc->vegas_params.beta || cc->blocked_chan) {
      cc->cwnd -= CWND_INC(cc);

      /* Compute the percentage we experience a blocked csig vs RTT sig */
      if (cc->blocked_chan) {
        cc_stats_vegas_csig_blocked_ma =
          stats_update_running_avg(cc_stats_vegas_csig_blocked_ma,
                                   100);
      } else {
        cc_stats_vegas_csig_blocked_ma =
          stats_update_running_avg(cc_stats_vegas_csig_blocked_ma,
                                   0);
      }

      /* Percentage counters: Add 100% beta, 0 for other two */
      cc_stats_vegas_csig_alpha_ma =
          stats_update_running_avg(cc_stats_vegas_csig_alpha_ma,
                                   0);
      cc_stats_vegas_csig_beta_ma =
          stats_update_running_avg(cc_stats_vegas_csig_beta_ma,
                                   100);
      cc_stats_vegas_csig_delta_ma =
          stats_update_running_avg(cc_stats_vegas_csig_delta_ma,
                                   0);
    } else if (queue_use < cc->vegas_params.alpha) {
      cc->cwnd += CWND_INC(cc);

      /* Percentage counters: Add 100% alpha, 0 for other two */
      cc_stats_vegas_csig_alpha_ma =
          stats_update_running_avg(cc_stats_vegas_csig_alpha_ma,
                                   100);
      cc_stats_vegas_csig_beta_ma =
          stats_update_running_avg(cc_stats_vegas_csig_beta_ma,
                                   0);
      cc_stats_vegas_csig_delta_ma =
          stats_update_running_avg(cc_stats_vegas_csig_delta_ma,
                                   0);
    } else {
      /* Percentage counters: No signal this round. Add 0% to all */
      cc_stats_vegas_csig_alpha_ma =
          stats_update_running_avg(cc_stats_vegas_csig_alpha_ma,
                                   0);
      cc_stats_vegas_csig_beta_ma =
          stats_update_running_avg(cc_stats_vegas_csig_beta_ma,
                                   0);
      cc_stats_vegas_csig_delta_ma =
          stats_update_running_avg(cc_stats_vegas_csig_delta_ma,
                                   0);
    }

    /* cwnd can never fall below 1 increment */
    cc->cwnd = MAX(cc->cwnd, cc->cwnd_min);

    /* Schedule next update */
    cc->next_cc_event = CWND_UPDATE_RATE(cc);

    congestion_control_vegas_log(circ, cc);

    /* Update metrics */
    cc_stats_vegas_queue_ma =
        stats_update_running_avg(cc_stats_vegas_queue_ma,
                                 queue_use);
    cc_stats_vegas_bdp_ma =
        stats_update_running_avg(cc_stats_vegas_bdp_ma,
                                 vegas_bdp(cc));

    /* Log if we're above the ss_cap */
    if (cc->cwnd >= cc->vegas_params.ss_cwnd_max) {
      log_info(LD_CIRC,
            "CC: TOR_VEGAS above ss_max in steady state for circ %d: %"PRIu64,
            circ->purpose, cc->cwnd);
    }
  }

  /* Update inflight with ack */
  cc->inflight = cc->inflight - cc->sendme_inc;

  return 0;
}
