/* Copyright (c) 2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file congestion_control_common.c
 * \brief Common code used by all congestion control algorithms.
 */

#define TOR_CONGESTION_CONTROL_COMMON_PRIVATE

#include "core/or/or.h"

#include "core/or/circuitlist.h"
#include "core/or/crypt_path.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/channel.h"
#include "core/mainloop/connection.h"
#include "core/or/sendme.h"
#include "core/or/congestion_control_common.h"
#include "core/or/congestion_control_vegas.h"
#include "core/or/congestion_control_nola.h"
#include "core/or/congestion_control_westwood.h"
#include "core/or/congestion_control_st.h"
#include "core/or/trace_probes_cc.h"
#include "lib/time/compat_time.h"
#include "feature/nodelist/networkstatus.h"

/* Consensus parameter defaults.
 *
 * More details for each of the parameters can be found in proposal 324,
 * section 6.5 including tuning notes. */
#define CIRCWINDOW_INIT (500)
#define SENDME_INC_DFLT (50)

#define CWND_INC_DFLT (50)
#define CWND_INC_PCT_SS_DFLT (100)
#define CWND_INC_RATE_DFLT (1)
#define CWND_MAX_DFLT (INT32_MAX)
#define CWND_MIN_DFLT (MAX(100, SENDME_INC_DFLT))

#define BWE_SENDME_MIN_DFLT (5)
#define EWMA_CWND_COUNT_DFLT (2)

/* BDP algorithms for each congestion control algorithms use the piecewise
 * estimattor. See section 3.1.4 of proposal 324. */
#define WESTWOOD_BDP_ALG BDP_ALG_PIECEWISE
#define VEGAS_BDP_MIX_ALG BDP_ALG_PIECEWISE
#define NOLA_BDP_ALG BDP_ALG_PIECEWISE

/* Indicate OR connection buffer limitations used to stop or start accepting
 * cells in its outbuf.
 *
 * These watermarks are historical to tor in a sense that they've been used
 * almost from the genesis point. And were likely defined to fit the bounds of
 * TLS records of 16KB which would be around 32 cells.
 *
 * These are defaults of the consensus parameter "orconn_high" and "orconn_low"
 * values. */
#define OR_CONN_HIGHWATER_DFLT (32*1024)
#define OR_CONN_LOWWATER_DFLT (16*1024)

/* Low and high values of circuit cell queue sizes. They are used to tell when
 * to start or stop reading on the streams attached on the circuit.
 *
 * These are defaults of the consensus parameters "cellq_high" and "cellq_low".
 */
#define CELL_QUEUE_LOW_DFLT (10)
#define CELL_QUEUE_HIGH_DFLT (256)

static uint64_t congestion_control_update_circuit_rtt(congestion_control_t *,
                                                      uint64_t);
static bool congestion_control_update_circuit_bdp(congestion_control_t *,
                                                  const circuit_t *,
                                                  const crypt_path_t *,
                                                  uint64_t, uint64_t);

/* Consensus parameters cached. The non static ones are extern. */
static uint32_t cwnd_max = CWND_MAX_DFLT;
int32_t cell_queue_high = CELL_QUEUE_HIGH_DFLT;
int32_t cell_queue_low = CELL_QUEUE_LOW_DFLT;
uint32_t or_conn_highwater = OR_CONN_HIGHWATER_DFLT;
uint32_t or_conn_lowwater = OR_CONN_LOWWATER_DFLT;

/**
 * Update global congestion control related consensus parameter values,
 * every consensus update.
 */
void
congestion_control_new_consensus_params(const networkstatus_t *ns)
{
#define CELL_QUEUE_HIGH_MIN (1)
#define CELL_QUEUE_HIGH_MAX (1000)
  cell_queue_high = networkstatus_get_param(ns, "cellq_high",
      CELL_QUEUE_HIGH_DFLT,
      CELL_QUEUE_HIGH_MIN,
      CELL_QUEUE_HIGH_MAX);

#define CELL_QUEUE_LOW_MIN (1)
#define CELL_QUEUE_LOW_MAX (1000)
  cell_queue_low = networkstatus_get_param(ns, "cellq_low",
      CELL_QUEUE_LOW_DFLT,
      CELL_QUEUE_LOW_MIN,
      CELL_QUEUE_LOW_MAX);

#define OR_CONN_HIGHWATER_MIN (CELL_PAYLOAD_SIZE)
#define OR_CONN_HIGHWATER_MAX (INT32_MAX)
  or_conn_highwater =
    networkstatus_get_param(ns, "orconn_high",
        OR_CONN_HIGHWATER_DFLT,
        OR_CONN_HIGHWATER_MIN,
        OR_CONN_HIGHWATER_MAX);

#define OR_CONN_LOWWATER_MIN (CELL_PAYLOAD_SIZE)
#define OR_CONN_LOWWATER_MAX (INT32_MAX)
  or_conn_lowwater =
    networkstatus_get_param(ns, "orconn_low",
        OR_CONN_LOWWATER_DFLT,
        OR_CONN_LOWWATER_MIN,
        OR_CONN_LOWWATER_MAX);

#define CWND_MAX_MIN 500
#define CWND_MAX_MAX (INT32_MAX)
  cwnd_max =
    networkstatus_get_param(NULL, "cc_cwnd_max",
        CWND_MAX_DFLT,
        CWND_MAX_MIN,
        CWND_MAX_MAX);
}

/**
 * Set congestion control parameters on a circuit's congestion
 * control object based on values from the consensus.
 *
 * cc_alg is the negotiated congestion control algorithm.
 *
 * sendme_inc is the number of packaged cells that a sendme cell
 * acks. This parameter will come from circuit negotiation.
 */
static void
congestion_control_init_params(congestion_control_t *cc,
                               cc_alg_t cc_alg,
                               int sendme_inc)
{
#define CWND_INIT_MIN 100
#define CWND_INIT_MAX (10000)
  cc->cwnd =
    networkstatus_get_param(NULL, "cc_cwnd_init",
        CIRCWINDOW_INIT,
        CWND_INIT_MIN,
        CWND_INIT_MAX);

#define CWND_INC_PCT_SS_MIN 1
#define CWND_INC_PCT_SS_MAX (500)
  cc->cwnd_inc_pct_ss =
    networkstatus_get_param(NULL, "cc_cwnd_inc_pct_ss",
        CWND_INC_PCT_SS_DFLT,
        CWND_INC_PCT_SS_MIN,
        CWND_INC_PCT_SS_MAX);

#define CWND_INC_MIN 1
#define CWND_INC_MAX (1000)
  cc->cwnd_inc =
    networkstatus_get_param(NULL, "cc_cwnd_inc",
        CWND_INC_DFLT,
        CWND_INC_MIN,
        CWND_INC_MAX);

#define CWND_INC_RATE_MIN 1
#define CWND_INC_RATE_MAX (250)
  cc->cwnd_inc_rate =
    networkstatus_get_param(NULL, "cc_cwnd_inc_rate",
        CWND_INC_RATE_DFLT,
        CWND_INC_RATE_MIN,
        CWND_INC_RATE_MAX);

#define SENDME_INC_MIN 10
#define SENDME_INC_MAX (1000)
  cc->sendme_inc =
    networkstatus_get_param(NULL, "cc_sendme_inc",
        sendme_inc,
        SENDME_INC_MIN,
        SENDME_INC_MAX);

  // XXX: this min needs to abide by sendme_inc range rules somehow
#define CWND_MIN_MIN sendme_inc
#define CWND_MIN_MAX (1000)
  cc->cwnd_min =
    networkstatus_get_param(NULL, "cc_cwnd_min",
        CWND_MIN_DFLT,
        CWND_MIN_MIN,
        CWND_MIN_MAX);

#define EWMA_CWND_COUNT_MIN 1
#define EWMA_CWND_COUNT_MAX (100)
  cc->ewma_cwnd_cnt =
    networkstatus_get_param(NULL, "cc_ewma_cwnd_cnt",
        EWMA_CWND_COUNT_DFLT,
        EWMA_CWND_COUNT_MIN,
        EWMA_CWND_COUNT_MAX);

#define BWE_SENDME_MIN_MIN 2
#define BWE_SENDME_MIN_MAX (20)
  cc->bwe_sendme_min =
    networkstatus_get_param(NULL, "cc_bwe_min",
        BWE_SENDME_MIN_DFLT,
        BWE_SENDME_MIN_MIN,
        BWE_SENDME_MIN_MAX);

#define CC_ALG_MIN 0
#define CC_ALG_MAX (NUM_CC_ALGS-1)
  cc->cc_alg =
    networkstatus_get_param(NULL, "cc_alg",
        cc_alg,
        CC_ALG_MIN,
        CC_ALG_MAX);

  bdp_alg_t default_bdp_alg = 0;

  switch (cc->cc_alg) {
    case CC_ALG_WESTWOOD:
      default_bdp_alg = WESTWOOD_BDP_ALG;
      break;
    case CC_ALG_VEGAS:
      default_bdp_alg = VEGAS_BDP_MIX_ALG;
      break;
    case CC_ALG_NOLA:
      default_bdp_alg = NOLA_BDP_ALG;
      break;
    case CC_ALG_SENDME:
    default:
      tor_fragile_assert();
      return; // No alg-specific params
  }

  cc->bdp_alg =
    networkstatus_get_param(NULL, "cc_bdp_alg",
        default_bdp_alg,
        0,
        NUM_BDP_ALGS-1);

  /* Algorithm-specific parameters */
  if (cc->cc_alg == CC_ALG_WESTWOOD) {
    congestion_control_westwood_set_params(cc);
  } else if (cc->cc_alg == CC_ALG_VEGAS) {
    congestion_control_vegas_set_params(cc);
  } else if (cc->cc_alg == CC_ALG_NOLA) {
    congestion_control_nola_set_params(cc);
  }
}

/**
 * Allocate and initialize fields in congestion control object.
 *
 * cc_alg is the negotiated congestion control algorithm.
 *
 * sendme_inc is the number of packaged cells that a sendme cell
 * acks. This parameter will come from circuit negotiation.
 */
static void
congestion_control_init(congestion_control_t *cc, cc_alg_t cc_alg,
                        int sendme_inc)
{
  cc->sendme_pending_timestamps = smartlist_new();
  cc->sendme_arrival_timestamps = smartlist_new();

  cc->in_slow_start = 1;
  congestion_control_init_params(cc, cc_alg, sendme_inc);

  cc->next_cc_event = CWND_UPDATE_RATE(cc);
}

/** Allocate and initialize a new congestion control object */
congestion_control_t *
congestion_control_new(void)
{
  congestion_control_t *cc = tor_malloc_zero(sizeof(congestion_control_t));

  // XXX: the alg and the sendme_inc need to be negotiated during
  // circuit handshake
  congestion_control_init(cc, CC_ALG_VEGAS, SENDME_INC_DFLT);

  return cc;
}

/**
 * Free a congestion control object and its asssociated state.
 */
void
congestion_control_free_(congestion_control_t *cc)
{
  if (!cc)
    return;

  SMARTLIST_FOREACH(cc->sendme_pending_timestamps, uint64_t *, t, tor_free(t));
  SMARTLIST_FOREACH(cc->sendme_arrival_timestamps, uint64_t *, t, tor_free(t));
  smartlist_free(cc->sendme_pending_timestamps);
  smartlist_free(cc->sendme_arrival_timestamps);

  tor_free(cc);
}

/**
 * Enqueue a u64 timestamp to the end of a queue of timestamps.
 */
static inline void
enqueue_timestamp(smartlist_t *timestamps_u64, uint64_t timestamp_usec)
{
  uint64_t *timestamp_ptr = tor_malloc(sizeof(uint64_t));
  *timestamp_ptr = timestamp_usec;

  smartlist_add(timestamps_u64, timestamp_ptr);
}

/**
 * Peek at the head of a smartlist queue of u64 timestamps.
 */
static inline uint64_t
peek_timestamp(const smartlist_t *timestamps_u64_usecs)
{
  uint64_t *timestamp_ptr = smartlist_get(timestamps_u64_usecs, 0);

  if (BUG(!timestamp_ptr)) {
    log_err(LD_CIRC, "Congestion control timestamp list became empty!");
    return 0;
  }

  return *timestamp_ptr;
}

/**
 * Dequeue a u64 monotime usec timestamp from the front of a
 * smartlist of pointers to 64.
 */
static inline uint64_t
dequeue_timestamp(smartlist_t *timestamps_u64_usecs)
{
  uint64_t *timestamp_ptr = smartlist_get(timestamps_u64_usecs, 0);
  uint64_t timestamp_u64;

  if (BUG(!timestamp_ptr)) {
    log_err(LD_CIRC, "Congestion control timestamp list became empty!");
    return 0;
  }

  timestamp_u64 = *timestamp_ptr;
  smartlist_del_keeporder(timestamps_u64_usecs, 0);
  tor_free(timestamp_ptr);

  return timestamp_u64;
}

/**
 * Returns the number of sendme acks that will be recieved in the
 * current congestion window size, rounded to nearest int.
 */
static inline uint64_t
sendme_acks_per_cwnd(const congestion_control_t *cc)
{
  /* We add half a sendme_inc to cwnd to round to the nearest int */
  return ((cc->cwnd + cc->sendme_inc/2)/cc->sendme_inc);
}

/**
 * Get a package window from either old sendme logic, or congestion control.
 *
 * A package window is how many cells you can still send.
 */
int
congestion_control_get_package_window(const circuit_t *circ,
                                      const crypt_path_t *cpath)
{
  int package_window;
  congestion_control_t *cc;

  tor_assert(circ);

  if (cpath) {
    package_window = cpath->package_window;
    cc = cpath->ccontrol;
  } else {
    package_window = circ->package_window;
    cc = circ->ccontrol;
  }

  if (!cc) {
    return package_window;
  } else {
    /* Inflight can be above cwnd if cwnd was just reduced */
    if (cc->inflight > cc->cwnd)
      return 0;
    /* In the extremely unlikely event that cwnd-inflight is larger than
     * INT32_MAX, just return that cap, so old code doesn't explode. */
    else if (cc->cwnd - cc->inflight > INT32_MAX)
      return INT32_MAX;
    else
      return (int)(cc->cwnd - cc->inflight);
  }
}

/**
 * Returns the number of cells that are acked by every sendme.
 */
int
sendme_get_inc_count(const circuit_t *circ, const crypt_path_t *layer_hint)
{
  int sendme_inc = CIRCWINDOW_INCREMENT;
  congestion_control_t *cc = NULL;

  if (layer_hint) {
    cc = layer_hint->ccontrol;
  } else {
    cc = circ->ccontrol;
  }

  if (cc) {
    sendme_inc = cc->sendme_inc;
  }

  return sendme_inc;
}

/** Return true iff the next cell we send will result in the other endpoint
 * sending a SENDME.
 *
 * We are able to know that because the package or inflight window value minus
 * one cell (the possible SENDME cell) should be a multiple of the
 * cells-per-sendme increment value (set via consensus parameter, negotiated
 * for the circuit, and passed in as sendme_inc).
 *
 * This function is used when recording a cell digest and this is done quite
 * low in the stack when decrypting or encrypting a cell. The window is only
 * updated once the cell is actually put in the outbuf.
 */
bool
circuit_sent_cell_for_sendme(const circuit_t *circ,
                             const crypt_path_t *layer_hint)
{
  congestion_control_t *cc;
  int window;

  tor_assert(circ);

  if (layer_hint) {
    window = layer_hint->package_window;
    cc = layer_hint->ccontrol;
  } else {
    window = circ->package_window;
    cc = circ->ccontrol;
  }

  /* If we are using congestion control and the alg is not
   * old-school 'fixed', then use cc->inflight to determine
   * when sendmes will be sent */
  if (cc) {
    if (!cc->inflight)
      return false;

    /* This check must be +1 because this function is called *before*
     * inflight is incremented for the sent cell */
    if ((cc->inflight+1) % cc->sendme_inc != 0)
      return false;

    return true;
  }

  /* At the start of the window, no SENDME will be expected. */
  if (window == CIRCWINDOW_START) {
    return false;
  }

  /* Are we at the limit of the increment and if not, we don't expect next
   * cell is a SENDME.
   *
   * We test against the window minus 1 because when we are looking if the
   * next cell is a SENDME, the window (either package or deliver) hasn't been
   * decremented just yet so when this is called, we are currently processing
   * the "window - 1" cell.
   */
  if (((window - 1) % CIRCWINDOW_INCREMENT) != 0) {
    return false;
  }

  /* Next cell is expected to be a SENDME. */
  return true;
}

/**
 * Call-in to tell congestion control code that this circuit sent a cell.
 *
 * This updates the 'inflight' counter, and if this is a cell that will
 * cause the other end to send a SENDME, record the current time in a list
 * of pending timestamps, so that we can later compute the circuit RTT when
 * the SENDME comes back. */
void
congestion_control_note_cell_sent(congestion_control_t *cc,
                                  const circuit_t *circ,
                                  const crypt_path_t *cpath)
{
  tor_assert(circ);
  tor_assert(cc);

  /* Is this the last cell before a SENDME? The idea is that if the
   * package_window reaches a multiple of the increment, after this cell, we
   * should expect a SENDME. Note that this function must be called *before*
   * we account for the sent cell. */
  if (!circuit_sent_cell_for_sendme(circ, cpath)) {
    cc->inflight++;
    return;
  }

  cc->inflight++;

  /* Record this cell time for RTT computation when SENDME arrives */
  enqueue_timestamp(cc->sendme_pending_timestamps,
                    monotime_absolute_usec());
}

/**
 * Returns true if any edge connections are active.
 *
 * We need to know this so that we can stop computing BDP if the
 * edges are not sending on the circuit.
 */
static int
circuit_has_active_streams(const circuit_t *circ,
                           const crypt_path_t *layer_hint)
{
  const edge_connection_t *streams;

  if (CIRCUIT_IS_ORIGIN(circ)) {
    streams = CONST_TO_ORIGIN_CIRCUIT(circ)->p_streams;
  } else {
    streams = CONST_TO_OR_CIRCUIT(circ)->n_streams;
  }

  /* Check linked list of streams */
  for (const edge_connection_t *conn = streams; conn != NULL;
       conn = conn->next_stream) {
    if (conn->base_.marked_for_close)
      continue;

    if (!layer_hint || conn->cpath_layer == layer_hint) {
      if (connection_get_inbuf_len(TO_CONN(conn)) > 0) {
        log_info(LD_CIRC, "CC: More in edge inbuf...");
        return 1;
      }

      /* If we did not reach EOF on this read, there's more */
      if (!TO_CONN(conn)->inbuf_reached_eof) {
        log_info(LD_CIRC, "CC: More on edge conn...");
        return 1;
      }

      if (TO_CONN(conn)->linked_conn) {
        if (connection_get_inbuf_len(TO_CONN(conn)->linked_conn) > 0) {
          log_info(LD_CIRC, "CC: More in linked inbuf...");
          return 1;
        }

        /* If there is a linked conn, and *it* did not each EOF,
         * there's more */
        if (!TO_CONN(conn)->linked_conn->inbuf_reached_eof) {
          log_info(LD_CIRC, "CC: More on linked conn...");
          return 1;
        }
      }
    }
  }

  return 0;
}

/**
 * Upon receipt of a SENDME, pop the oldest timestamp off the timestamp
 * list, and use this to update RTT.
 *
 * Returns true if circuit estimates were successfully updated, false
 * otherwise.
 */
bool
congestion_control_update_circuit_estimates(congestion_control_t *cc,
                                            const circuit_t *circ,
                                            const crypt_path_t *layer_hint)
{
  uint64_t now_usec = monotime_absolute_usec();

  /* Update RTT first, then BDP. BDP needs fresh RTT */
  uint64_t curr_rtt_usec = congestion_control_update_circuit_rtt(cc, now_usec);
  return congestion_control_update_circuit_bdp(cc, circ, layer_hint, now_usec,
                                               curr_rtt_usec);
}

/**
 * Returns true if we have enough time data to use heuristics
 * to compare RTT to a baseline.
 */
static bool
time_delta_should_use_heuristics(const congestion_control_t *cc)
{

  /* If we have exited slow start, we should have processed at least
   * a cwnd worth of RTTs */
  if (!cc->in_slow_start) {
    return true;
  }

  /* If we managed to get enough acks to estimate a SENDME BDP, then
   * we have enough to estimate clock jumps relative to a baseline,
   * too. (This is at least 'cc_bwe_min' acks). */
  if (cc->bdp[BDP_ALG_SENDME_RATE]) {
    return true;
  }

  /* Not enough data to estimate clock jumps */
  return false;
}

static bool is_monotime_clock_broken = false;

/**
 * Returns true if the monotime delta is 0, or is significantly
 * different than the previous delta. Either case indicates
 * that the monotime time source stalled or jumped.
 *
 * Also caches the clock state in the is_monotime_clock_broken flag,
 * so we can also provide a is_monotime_clock_reliable() function,
 * used by flow control rate timing.
 */
static bool
time_delta_stalled_or_jumped(const congestion_control_t *cc,
                             uint64_t old_delta, uint64_t new_delta)
{
#define DELTA_DISCREPENCY_RATIO_MAX 100
  /* If we have a 0 new_delta, that is definitely a monotime stall */
  if (new_delta == 0) {
    static ratelim_t stall_info_limit = RATELIM_INIT(60);
    log_fn_ratelim(&stall_info_limit, LOG_INFO, LD_CIRC,
           "Congestion control cannot measure RTT due to monotime stall.");

    /* If delta is every 0, the monotime clock has stalled, and we should
     * not use it anywhere. */
    is_monotime_clock_broken = true;

    return is_monotime_clock_broken;
  }

  /* If the old_delta is 0, we have no previous values on this circuit.
   *
   * So, return the global monotime status from other circuits, and
   * do not update.
   */
  if (old_delta == 0) {
    return is_monotime_clock_broken;
  }

  /*
   * For the heuristic cases, we need at least a few timestamps,
   * to average out any previous partial stalls or jumps. So until
   * than point, let's just use the cached status from other circuits.
   */
  if (!time_delta_should_use_heuristics(cc)) {
    return is_monotime_clock_broken;
  }

  /* If old_delta is significantly larger than new_delta, then
   * this means that the monotime clock recently stopped moving
   * forward. */
  if (old_delta > new_delta * DELTA_DISCREPENCY_RATIO_MAX) {
    static ratelim_t dec_notice_limit = RATELIM_INIT(300);
    log_fn_ratelim(&dec_notice_limit, LOG_NOTICE, LD_CIRC,
           "Sudden decrease in circuit RTT (%"PRIu64" vs %"PRIu64
           "), likely due to clock jump.",
           new_delta/1000, old_delta/1000);

    is_monotime_clock_broken = true;

    return is_monotime_clock_broken;
  }

  /* If new_delta is significantly larger than old_delta, then
   * this means that the monotime clock suddenly jumped forward. */
  if (new_delta > old_delta * DELTA_DISCREPENCY_RATIO_MAX) {
    static ratelim_t dec_notice_limit = RATELIM_INIT(300);
    log_fn_ratelim(&dec_notice_limit, LOG_NOTICE, LD_CIRC,
           "Sudden increase in circuit RTT (%"PRIu64" vs %"PRIu64
           "), likely due to clock jump.",
           new_delta/1000, old_delta/1000);

    is_monotime_clock_broken = true;

    return is_monotime_clock_broken;
  }

  /* All good! Update cached status, too */
  is_monotime_clock_broken = false;

  return is_monotime_clock_broken;
}

/**
 * Is the monotime clock stalled according to any circuits?
 */
bool
is_monotime_clock_reliable(void)
{
  return !is_monotime_clock_broken;
}

/**
 * Called when we get a SENDME. Updates circuit RTT by pulling off a
 * timestamp of when we sent the CIRCWINDOW_INCREMENT-th cell from
 * the queue of such timestamps, and comparing that to current time.
 *
 * Also updates min, max, and EWMA of RTT.
 *
 * Returns the current circuit RTT in usecs, or 0 if it could not be
 * measured (due to clock jump, stall, etc).
 */
static uint64_t
congestion_control_update_circuit_rtt(congestion_control_t *cc,
                                      uint64_t now_usec)
{
  uint64_t rtt, ewma_cnt;
  uint64_t sent_at_timestamp;

  tor_assert(cc);

  /* Get the time that we sent the cell that resulted in the other
   * end sending this sendme. Use this to calculate RTT */
  sent_at_timestamp = dequeue_timestamp(cc->sendme_pending_timestamps);

  rtt = now_usec - sent_at_timestamp;

  /* Do not update RTT at all if it looks fishy */
  if (time_delta_stalled_or_jumped(cc, cc->ewma_rtt_usec, rtt)) {
    return 0;
  }

  ewma_cnt = cc->ewma_cwnd_cnt*sendme_acks_per_cwnd(cc);
  ewma_cnt = MAX(ewma_cnt, 2); // Use at least 2

  cc->ewma_rtt_usec = n_count_ewma(rtt, cc->ewma_rtt_usec, ewma_cnt);

  if (rtt > cc->max_rtt_usec) {
    cc->max_rtt_usec = rtt;
  }

  if (cc->min_rtt_usec == 0 || rtt < cc->min_rtt_usec) {
    cc->min_rtt_usec = rtt;
  }

  return rtt;
}

/**
 * Called when we get a SENDME. Updates the bandwidth-delay-product (BDP)
 * estimates of a circuit. Several methods of computing BDP are used,
 * depending on scenario. While some congestion control algorithms only
 * use one of these methods, we update them all because it's quick and easy.
 *
 * - now_usec is the current monotime in usecs.
 * - curr_rtt_usec is the current circuit RTT in usecs. It may be 0 if no
 *   RTT could bemeasured.
 *
 * Returns true if we were able to update BDP, false otherwise.
 */
static bool
congestion_control_update_circuit_bdp(congestion_control_t *cc,
                                      const circuit_t *circ,
                                      const crypt_path_t *layer_hint,
                                      uint64_t now_usec,
                                      uint64_t curr_rtt_usec)
{
  int chan_q = 0;
  unsigned int blocked_on_chan = 0;
  uint64_t timestamp_usec;
  uint64_t sendme_rate_bdp = 0;

  tor_assert(cc);

  if (CIRCUIT_IS_ORIGIN(circ)) {
    /* origin circs use n_chan */
    chan_q = circ->n_chan_cells.n;
    blocked_on_chan = circ->streams_blocked_on_n_chan;
  } else {
    /* Both onion services and exits use or_circuit and p_chan */
    chan_q = CONST_TO_OR_CIRCUIT(circ)->p_chan_cells.n;
    blocked_on_chan = circ->streams_blocked_on_p_chan;
  }

  /* If we have no EWMA RTT, it is because monotime has been stalled
   * or messed up the entire time so far. Set our BDP estimates directly
   * to current cwnd */
  if (!cc->ewma_rtt_usec) {
     uint64_t cwnd = cc->cwnd;

     /* If the channel is blocked, keep subtracting off the chan_q
      * until we hit the min cwnd. */
     if (blocked_on_chan) {
       cwnd = MAX(cwnd - chan_q, cc->cwnd_min);
       cc->blocked_chan = 1;
     } else {
       cc->blocked_chan = 0;
     }

     cc->bdp[BDP_ALG_CWND_RTT] = cwnd;
     cc->bdp[BDP_ALG_INFLIGHT_RTT] = cwnd;
     cc->bdp[BDP_ALG_SENDME_RATE] = cwnd;
     cc->bdp[BDP_ALG_PIECEWISE] = cwnd;

     static ratelim_t dec_notice_limit = RATELIM_INIT(300);
     log_fn_ratelim(&dec_notice_limit, LOG_NOTICE, LD_CIRC,
            "Our clock has been stalled for the entire lifetime of a circuit. "
            "Performance may be sub-optimal.");

     return blocked_on_chan;
  }

  /* Congestion window based BDP will respond to changes in RTT only, and is
   * relative to cwnd growth. It is useful for correcting for BDP
   * overestimation, but if BDP is higher than the current cwnd, it will
   * underestimate it.
   *
   * We multiply here first to avoid precision issues from min_RTT being
   * close to ewma RTT. Since all fields are u64, there is plenty of
   * room here to multiply first.
   */
  cc->bdp[BDP_ALG_CWND_RTT] = cc->cwnd*cc->min_rtt_usec/cc->ewma_rtt_usec;

  /*
   * If we have no pending streams, we do not have enough data to fill
   * the BDP, so preserve our old estimates but do not make any more.
   */
  if (!blocked_on_chan && !circuit_has_active_streams(circ, layer_hint)) {
    log_info(LD_CIRC,
               "CC: Streams drained. Spare package window: %"PRIu64
               ", no BDP update", cc->cwnd - cc->inflight);

    /* Clear SENDME timestamps; they will be wrong with intermittent data */
    SMARTLIST_FOREACH(cc->sendme_arrival_timestamps, uint64_t *, t,
                      tor_free(t));
    smartlist_clear(cc->sendme_arrival_timestamps);
  } else if (curr_rtt_usec && is_monotime_clock_reliable()) {
    /* Sendme-based BDP will quickly measure BDP in much less than
     * a cwnd worth of data when in use (in 2-10 SENDMEs).
     *
     * But if the link goes idle, it will be vastly lower than true BDP. Hence
     * we only compute it if we have either pending stream data, or streams
     * are still blocked on the channel queued data.
     *
     * We also do not compute it if we do not have a current RTT passed in,
     * because that means that monotime is currently stalled or just jumped.
     */
    enqueue_timestamp(cc->sendme_arrival_timestamps, now_usec);

    if (smartlist_len(cc->sendme_arrival_timestamps) >= cc->bwe_sendme_min) {
      /* If we have more sendmes than fit in a cwnd, trim the list.
       * Those are not acurrately measuring throughput, if cwnd is
       * currently smaller than BDP */
      while (smartlist_len(cc->sendme_arrival_timestamps) >
             cc->bwe_sendme_min &&
             (uint64_t)smartlist_len(cc->sendme_arrival_timestamps) >
                       sendme_acks_per_cwnd(cc)) {
        (void)dequeue_timestamp(cc->sendme_arrival_timestamps);
      }
      int sendme_cnt = smartlist_len(cc->sendme_arrival_timestamps);

      /* Calculate SENDME_BWE_COUNT pure average */
      timestamp_usec = peek_timestamp(cc->sendme_arrival_timestamps);
      uint64_t delta = now_usec - timestamp_usec;

      /* The acked data is in sendme_cnt-1 chunks, because we are counting the
       * data that is processed by the other endpoint *between* all of these
       * sendmes. There's one less gap between the sendmes than the number
       * of sendmes. */
      uint64_t cells = (sendme_cnt-1)*cc->sendme_inc;

      /* The bandwidth estimate is cells/delta, which when multiplied
       * by min RTT obtains the BDP. However, we multiply first to
       * avoid precision issues with the RTT being close to delta in size. */
      sendme_rate_bdp = cells*cc->min_rtt_usec/delta;

      /* Calculate BDP_EWMA_COUNT N-EWMA */
      cc->bdp[BDP_ALG_SENDME_RATE] =
                 n_count_ewma(sendme_rate_bdp, cc->bdp[BDP_ALG_SENDME_RATE],
                              cc->ewma_cwnd_cnt*sendme_acks_per_cwnd(cc));
    }

    /* In-flight BDP will cause the cwnd to drift down when underutilized.
     * It is most useful when the local OR conn is blocked, so we only
     * compute it if we're utilized. */
    cc->bdp[BDP_ALG_INFLIGHT_RTT] =
        (cc->inflight - chan_q)*cc->min_rtt_usec/
                              MAX(cc->ewma_rtt_usec, curr_rtt_usec);
  } else {
    /* We can still update inflight with just an EWMA RTT, but only
     * if there is data flowing */
    cc->bdp[BDP_ALG_INFLIGHT_RTT] =
        (cc->inflight - chan_q)*cc->min_rtt_usec/cc->ewma_rtt_usec;
  }

  /* The orconn is blocked; use smaller of inflight vs SENDME */
  if (blocked_on_chan) {
    log_info(LD_CIRC, "CC: Streams blocked on circ channel. Chanq: %d",
             chan_q);

    /* A blocked channel is an immediate congestion signal, but it still
     * happens only once per cwnd */
    if (!cc->blocked_chan) {
      cc->next_cc_event = 0;
      cc->blocked_chan = 1;
    }

    if (cc->bdp[BDP_ALG_SENDME_RATE]) {
      cc->bdp[BDP_ALG_PIECEWISE] = MIN(cc->bdp[BDP_ALG_INFLIGHT_RTT],
                                      cc->bdp[BDP_ALG_SENDME_RATE]);
    } else {
      cc->bdp[BDP_ALG_PIECEWISE] = cc->bdp[BDP_ALG_INFLIGHT_RTT];
    }
  } else {
    /* If we were previously blocked, emit a new congestion event
     * now that we are unblocked, to re-evaluate cwnd */
    if (cc->blocked_chan) {
      cc->blocked_chan = 0;
      cc->next_cc_event = 0;
      log_info(LD_CIRC, "CC: Streams un-blocked on circ channel. Chanq: %d",
               chan_q);
    }

    cc->bdp[BDP_ALG_PIECEWISE] = MAX(cc->bdp[BDP_ALG_SENDME_RATE],
                                     cc->bdp[BDP_ALG_CWND_RTT]);
  }

  /* We can end up with no piecewise value if we didn't have either
   * a SENDME estimate or enough data for an inflight estimate.
   * It also happens on the very first sendme, since we need two
   * to get a BDP. In these cases, use the cwnd method. */
  if (!cc->bdp[BDP_ALG_PIECEWISE]) {
    cc->bdp[BDP_ALG_PIECEWISE] = cc->bdp[BDP_ALG_CWND_RTT];
    log_info(LD_CIRC, "CC: No piecewise BDP. Using %"PRIu64,
             cc->bdp[BDP_ALG_PIECEWISE]);
  }

  if (cc->next_cc_event == 0) {
    if (CIRCUIT_IS_ORIGIN(circ)) {
      log_info(LD_CIRC,
                 "CC: Circuit %d "
                 "SENDME RTT: %"PRIu64", %"PRIu64", %"PRIu64", %"PRIu64", "
                 "BDP estimates: "
                 "%"PRIu64", "
                 "%"PRIu64", "
                 "%"PRIu64", "
                 "%"PRIu64", "
                 "%"PRIu64". ",
               CONST_TO_ORIGIN_CIRCUIT(circ)->global_identifier,
               cc->min_rtt_usec/1000,
               curr_rtt_usec/1000,
               cc->ewma_rtt_usec/1000,
               cc->max_rtt_usec/1000,
               cc->bdp[BDP_ALG_INFLIGHT_RTT],
               cc->bdp[BDP_ALG_CWND_RTT],
               sendme_rate_bdp,
               cc->bdp[BDP_ALG_SENDME_RATE],
               cc->bdp[BDP_ALG_PIECEWISE]
               );
    } else {
      log_info(LD_CIRC,
                 "CC: Circuit %"PRIu64":%d "
                 "SENDME RTT: %"PRIu64", %"PRIu64", %"PRIu64", %"PRIu64", "
                 "%"PRIu64", "
                 "%"PRIu64", "
                 "%"PRIu64", "
                 "%"PRIu64", "
                 "%"PRIu64". ",
                 // XXX: actually, is this p_chan here? This is
                 // an or_circuit (exit or onion)
                 circ->n_chan->global_identifier, circ->n_circ_id,
                 cc->min_rtt_usec/1000,
                 curr_rtt_usec/1000,
                 cc->ewma_rtt_usec/1000,
                 cc->max_rtt_usec/1000,
                 cc->bdp[BDP_ALG_INFLIGHT_RTT],
                 cc->bdp[BDP_ALG_CWND_RTT],
                 sendme_rate_bdp,
                 cc->bdp[BDP_ALG_SENDME_RATE],
                 cc->bdp[BDP_ALG_PIECEWISE]
                 );
    }
  }

  /* We updated BDP this round if either we had a blocked channel, or
   * the curr_rtt_usec was not 0. */
  bool ret = (blocked_on_chan || curr_rtt_usec != 0);
  if (ret) {
    tor_trace(TR_SUBSYS(cc), TR_EV(bdp_update), circ, cc, curr_rtt_usec,
              sendme_rate_bdp);
  }
  return ret;
}

/**
 * Dispatch the sendme to the appropriate congestion control algorithm.
 */
int
congestion_control_dispatch_cc_alg(congestion_control_t *cc,
                                   const circuit_t *circ,
                                   const crypt_path_t *layer_hint)
{
  int ret = -END_CIRC_REASON_INTERNAL;
  switch (cc->cc_alg) {
    case CC_ALG_WESTWOOD:
      ret = congestion_control_westwood_process_sendme(cc, circ, layer_hint);
      break;

    case CC_ALG_VEGAS:
      ret = congestion_control_vegas_process_sendme(cc, circ, layer_hint);
      break;

    case CC_ALG_NOLA:
      ret = congestion_control_nola_process_sendme(cc, circ, layer_hint);
      break;

    case CC_ALG_SENDME:
    default:
      tor_assert(0);
  }

  if (cc->cwnd > cwnd_max) {
    static ratelim_t cwnd_limit = RATELIM_INIT(60);
    log_fn_ratelim(&cwnd_limit, LOG_NOTICE, LD_CIRC,
           "Congestion control cwnd %"PRIu64" exceeds max %d, clamping.",
           cc->cwnd, cwnd_max);
    cc->cwnd = cwnd_max;
  }

  return ret;
}
