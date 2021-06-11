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

#define VEGAS_GAMMA(cc)   (6*(cc)->sendme_inc)
#define VEGAS_ALPHA(cc)   (3*(cc)->sendme_inc)
#define VEGAS_BETA(cc)    (6*(cc)->sendme_inc)

#define VEGAS_BDP_MIX_PCT       0

/**
 * The original TCP Vegas used only a congestion window BDP estimator. We
 * believe that the piecewise estimator is likely to perform better, but
 * for purposes of experimentation, we might as well have a way to blend
 * them. It also lets us set Vegas to its original estimator while other
 * algorithms on the same network use piecewise (by setting the
 * 'vegas_bdp_mix_pct' consensus parameter to 100, while leaving the
 * 'cc_bdp_alg' parameter set to piecewise).
 *
 * Returns a percentage weighted average between the CWND estimator and
 * the specified consensus BDP estimator.
 */
static inline uint64_t
vegas_bdp_mix(const congestion_control_t *cc)
{
  return cc->vegas_params.bdp_mix_pct*cc->bdp[BDP_ALG_CWND_RTT]/100 +
         (100-cc->vegas_params.bdp_mix_pct)*cc->bdp[cc->bdp_alg]/100;
}

/**
 * Cache Vegas consensus parameters.
 */
void
congestion_control_vegas_set_params(congestion_control_t *cc)
{
  tor_assert(cc->cc_alg == CC_ALG_VEGAS);

  cc->vegas_params.gamma =
   networkstatus_get_param(NULL, "cc_vegas_gamma",
      VEGAS_GAMMA(cc),
      0,
      1000);

  cc->vegas_params.alpha =
   networkstatus_get_param(NULL, "cc_vegas_alpha",
      VEGAS_ALPHA(cc),
      0,
      1000);

  cc->vegas_params.beta =
   networkstatus_get_param(NULL, "cc_vegas_beta",
      VEGAS_BETA(cc),
      0,
      1000);

  cc->vegas_params.bdp_mix_pct =
   networkstatus_get_param(NULL, "cc_vegas_bdp_mix",
      VEGAS_BDP_MIX_PCT,
      0,
      100);
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

  /* We only update anything once per window */
  if (cc->next_cc_event == 0) {
    /* The queue use is the amount in which our cwnd is above BDP;
     * if it is below, then 0 queue use. */
    if (vegas_bdp_mix(cc) > cc->cwnd)
      queue_use = 0;
    else
      queue_use = cc->cwnd - vegas_bdp_mix(cc);

    if (cc->in_slow_start) {
      if (queue_use < cc->vegas_params.gamma && !cc->blocked_chan) {
        /* Grow to BDP immediately, then exponential growth until
         * congestion signal */
        cc->cwnd = MAX(cc->cwnd + CWND_INC_SS(cc),
                       vegas_bdp_mix(cc));
      } else {
        /* Congestion signal: Fall back to Vegas equilibrium (BDP) */
        cc->cwnd = vegas_bdp_mix(cc);
        cc->in_slow_start = 0;
        log_info(LD_CIRC, "CC: TOR_VEGAS exiting slow start");
      }
    } else {
      if (queue_use > cc->vegas_params.beta || cc->blocked_chan) {
        cc->cwnd -= CWND_INC(cc);
      } else if (queue_use < cc->vegas_params.alpha) {
        cc->cwnd += CWND_INC(cc);
      }
    }

    /* cwnd can never fall below 1 increment */
    cc->cwnd = MAX(cc->cwnd, cc->cwnd_min);

    /* Schedule next update */
    cc->next_cc_event = CWND_UPDATE_RATE(cc);

    if (CIRCUIT_IS_ORIGIN(circ)) {
      log_info(LD_CIRC,
                 "CC: TOR_VEGAS Circuit %d "
                 "CWND: %"PRIu64", "
                 "INFL: %"PRIu64", "
                 "VBDP: %"PRIu64", "
                 "QUSE: %"PRIu64", "
                 "NCCE: %"PRIu64", "
                 "SS: %d",
               CONST_TO_ORIGIN_CIRCUIT(circ)->global_identifier,
               cc->cwnd,
               cc->inflight,
               vegas_bdp_mix(cc),
               queue_use,
               cc->next_cc_event,
               cc->in_slow_start
               );
    } else {
      log_info(LD_CIRC,
                 "CC: TOR_VEGAS Circuit %"PRIu64":%d "
                 "CWND: %"PRIu64", "
                 "INFL: %"PRIu64", "
                 "VBDP: %"PRIu64", "
                 "QUSE: %"PRIu64", "
                 "NCCE: %"PRIu64", "
                 "SS: %d",
                 circ->n_chan->global_identifier, circ->n_circ_id,
               cc->cwnd,
               cc->inflight,
               vegas_bdp_mix(cc),
               queue_use,
               cc->next_cc_event,
               cc->in_slow_start
               );
    }
  }

  /* Update inflight with ack */
  cc->inflight = cc->inflight - cc->sendme_inc;

  return 0;
}
