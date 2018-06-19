/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitstats.h
 * \brief Header file for circuitstats.c
 **/

#ifndef TOR_CIRCUITSTATS_H
#define TOR_CIRCUITSTATS_H

const circuit_build_times_t *get_circuit_build_times(void);
circuit_build_times_t *get_circuit_build_times_mutable(void);
double get_circuit_build_close_time_ms(void);
double get_circuit_build_timeout_ms(void);

int circuit_build_times_disabled(const or_options_t *options);
int circuit_build_times_disabled_(const or_options_t *options,
                                  int ignore_consensus);

int circuit_build_times_enough_to_compute(const circuit_build_times_t *cbt);
void circuit_build_times_update_state(const circuit_build_times_t *cbt,
                                      or_state_t *state);
int circuit_build_times_parse_state(circuit_build_times_t *cbt,
                                    or_state_t *state);
void circuit_build_times_count_timeout(circuit_build_times_t *cbt,
                                       int did_onehop);
int circuit_build_times_count_close(circuit_build_times_t *cbt,
                                    int did_onehop, time_t start_time);
void circuit_build_times_set_timeout(circuit_build_times_t *cbt);
int circuit_build_times_add_time(circuit_build_times_t *cbt,
                                 build_time_t time);
int circuit_build_times_needs_circuits(const circuit_build_times_t *cbt);
void circuit_build_times_handle_completed_hop(origin_circuit_t *circ);

int circuit_build_times_needs_circuits_now(const circuit_build_times_t *cbt);
void circuit_build_times_init(circuit_build_times_t *cbt);
void circuit_build_times_free_timeouts(circuit_build_times_t *cbt);
void circuit_build_times_new_consensus_params(circuit_build_times_t *cbt,
                                              networkstatus_t *ns);
double circuit_build_times_timeout_rate(const circuit_build_times_t *cbt);
double circuit_build_times_close_rate(const circuit_build_times_t *cbt);

void circuit_build_times_update_last_circ(circuit_build_times_t *cbt);
void circuit_build_times_mark_circ_as_measurement_only(origin_circuit_t *circ);

#ifdef CIRCUITSTATS_PRIVATE
STATIC double circuit_build_times_calculate_timeout(circuit_build_times_t *cbt,
                                             double quantile);
STATIC int circuit_build_times_update_alpha(circuit_build_times_t *cbt);
STATIC void circuit_build_times_reset(circuit_build_times_t *cbt);

/* Network liveness functions */
STATIC int circuit_build_times_network_check_changed(
                                             circuit_build_times_t *cbt);
#endif /* defined(CIRCUITSTATS_PRIVATE) */

#ifdef TOR_UNIT_TESTS
build_time_t circuit_build_times_generate_sample(circuit_build_times_t *cbt,
                                                 double q_lo, double q_hi);
double circuit_build_times_cdf(circuit_build_times_t *cbt, double x);
void circuit_build_times_initial_alpha(circuit_build_times_t *cbt,
                                       double quantile, double time_ms);
void circuitbuild_running_unit_tests(void);
#endif /* defined(TOR_UNIT_TESTS) */

/* Network liveness functions */
void circuit_build_times_network_is_live(circuit_build_times_t *cbt);
int circuit_build_times_network_check_live(const circuit_build_times_t *cbt);
void circuit_build_times_network_circ_success(circuit_build_times_t *cbt);

#ifdef CIRCUITSTATS_PRIVATE
/** Information about the state of our local network connection */
typedef struct {
  /** The timestamp we last completed a TLS handshake or received a cell */
  time_t network_last_live;
  /** If the network is not live, how many timeouts has this caused? */
  int nonlive_timeouts;
  /** Circular array of circuits that have made it to the first hop. Slot is
   * 1 if circuit timed out, 0 if circuit succeeded */
  int8_t *timeouts_after_firsthop;
  /** Number of elements allocated for the above array */
  int num_recent_circs;
  /** Index into circular array. */
  int after_firsthop_idx;
} network_liveness_t;

/** Structure for circuit build times history */
struct circuit_build_times_s {
  /** The circular array of recorded build times in milliseconds */
  build_time_t circuit_build_times[CBT_NCIRCUITS_TO_OBSERVE];
  /** Current index in the circuit_build_times circular array */
  int build_times_idx;
  /** Total number of build times accumulated. Max CBT_NCIRCUITS_TO_OBSERVE */
  int total_build_times;
  /** Information about the state of our local network connection */
  network_liveness_t liveness;
  /** Last time we built a circuit. Used to decide to build new test circs */
  time_t last_circ_at;
  /** "Minimum" value of our pareto distribution (actually mode) */
  build_time_t Xm;
  /** alpha exponent for pareto dist. */
  double alpha;
  /** Have we computed a timeout? */
  int have_computed_timeout;
  /** The exact value for that timeout in milliseconds. Stored as a double
   * to maintain precision from calculations to and from quantile value. */
  double timeout_ms;
  /** How long we wait before actually closing the circuit. */
  double close_ms;
  /** Total succeeded counts. Old measurements may be scaled downward if
   * we've seen a lot of circuits. */
  uint32_t num_circ_succeeded;
  /** Total timeout counts.  Old measurements may be scaled downward if
   * we've seen a lot of circuits. */
  uint32_t num_circ_timeouts;
  /** Total closed counts.  Old measurements may be scaled downward if
   * we've seen a lot of circuits.*/
  uint32_t num_circ_closed;

};
#endif /* defined(CIRCUITSTATS_PRIVATE) */

#endif /* !defined(TOR_CIRCUITSTATS_H) */

