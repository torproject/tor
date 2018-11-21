/*
 * Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitpadding.h
 * \brief Header file for circuitpadding.c.
 **/
#ifndef TOR_CIRCUITPADDING_H
#define TOR_CIRCUITPADDING_H

#include "circpad_negotiation.h"
#include "lib/evloop/timers.h"

typedef struct circuit_t circuit_t;
typedef struct origin_circuit_t origin_circuit_t;
typedef struct cell_t cell_t;

/**
 * Circpad state specifier.
 *
 * Each circuit has up to two state machines, and each state
 * machine consists of these states. Machines transition between
 * these states using the event transition specifiers below.
 */
typedef enum {
  CIRCPAD_STATE_START = 0,
  CIRCPAD_STATE_BURST = 1,
  CIRCPAD_STATE_GAP = 2,
  CIRCPAD_STATE_END = 3
} circpad_statenum_t;
#define CIRCPAD_NUM_STATES  ((uint8_t)CIRCPAD_STATE_END+1)

/**
 * These constants form a bitfield to specify the types of events
 * that can cause transitions between state machine states.
 *
 * Note that SENT and RECV are relative to this endpoint. For
 * relays, SENT means packets destined towards the client and
 * RECV means packets destined towards the relay. On the client,
 * SENT means packets destined towards the relay, where as RECV
 * means packets destined towards the client.
 */
typedef enum {
  CIRCPAD_EVENT_NONPADDING_RECV = 1<<0,
  CIRCPAD_EVENT_NONPADDING_SENT = 1<<1,
  CIRCPAD_EVENT_PADDING_SENT = 1<<2,
  CIRCPAD_EVENT_PADDING_RECV = 1<<3,
  CIRCPAD_EVENT_INFINITY = 1<<4,
  CIRCPAD_EVENT_BINS_EMPTY = 1<<5,
  CIRCPAD_EVENT_LENGTH_COUNT = 1<<6
} circpad_event_t;

/** Boolean type that says if we decided to transition states or not */
typedef enum {
  CIRCPAD_STATE_UNCHANGED = 0,
  CIRCPAD_STATE_CHANGED = 1
} circpad_decision_t;

/** The type for histogram bins */
typedef uint16_t circpad_hist_bin_t;

/** The type for absolute time, from monotime_absolute_usec() */
typedef uint64_t circpad_time_t;

/** The type for timer delays, in microseconds */
typedef uint32_t circpad_delay_t;

/**
 * An infinite padding cell delay means don't schedule any padding --
 * simply wait until a different event triggers a transition.
 *
 * This means that the maximum delay we can scedule is UINT32_MAX-1
 * microseconds, or about 4300 seconds (1.25 hours).
 * XXX: Is this enough if we want to simulate light, intermittent
 * activity on an onion service?
 */
#define CIRCPAD_DELAY_INFINITE  (UINT32_MAX)

/**
 * These constants form a bitfield that specifies when a state machine
 * should be applied to a circuit.
 *
 * The helper function circpad_circuit_state() converts circuit state
 * flags into this more compact representation.
 */
typedef enum {
  CIRCPAD_CIRC_BUILDING = 1<<0,
  CIRCPAD_CIRC_OPENED = 1<<1,
  CIRCPAD_CIRC_NO_STREAMS = 1<<2,
  CIRCPAD_CIRC_STREAMS = 1<<3,
  CIRCPAD_CIRC_HAS_RELAY_EARLY = 1<<4,
  CIRCPAD_CIRC_HAS_NO_RELAY_EARLY = 1<<5
} circpad_circuit_state_t;

/** Bitmask that says "apply this machine to all states" */
#define CIRCPAD_STATE_ALL   \
    (CIRCPAD_CIRC_BUILDING|CIRCPAD_CIRC_OPENED| \
     CIRCPAD_CIRC_STREAMS|CIRCPAD_CIRC_NO_STREAMS| \
     CIRCPAD_CIRC_HAS_RELAY_EARLY|CIRCPAD_CIRC_HAS_NO_RELAY_EARLY)

/**
 * A compact circuit purpose bitfield mask that allows us to compactly
 * specify which circuit purposes a machine should apply to.
 *
 * The helper function circpad_circ_purpose_to_mask() converts circuit
 * purposes into bit positions in this bitmask.
 */
typedef uint32_t circpad_purpose_mask_t;

/** Bitmask that says "apply this machine to all purposes". */
#define CIRCPAD_PURPOSE_ALL (0xFFFFFFFF)

/**
 * This type specifies all of the conditions that must be met before
 * a client decides to initiate padding on a circuit.
 *
 * A circuit must satisfy every sub-field in this type in order
 * to be considered to match the conditions.
 */
typedef struct circpad_machine_conditions_t {
  /** Only apply the machine *if* the circuit has at least this many hops */
  uint8_t min_hops : 3;

  /** Only apply the machine *if* vanguards are enabled */
  uint8_t requires_vanguards : 1;

  /** Only apply the machine *if* the circuit's state matches any of
   *  the bits set in this bitmask. */
  circpad_circuit_state_t state_mask;

  /** Only apply a machine *if* the circuit's purpose matches one
   *  of the bits set in this bitmask */
  circpad_purpose_mask_t purpose_mask;

} circpad_machine_conditions_t;

/**
 * Token removal strategy options.
 *
 * The WTF-PAD histograms are meant to specify a target distribution to shape
 * traffic towards. This is accomplished by removing tokens from the histogram
 * when either padding or non-padding cells are sent.
 *
 * When we see a non-padding cell at a particular time since the last cell, you
 * remove a token from the corresponding delay bin. These flags specify
 * which bin to choose if that bin is already empty.
 */
typedef enum {
  /** Don't remove any tokens */
  CIRCPAD_TOKEN_REMOVAL_NONE = 0,
  /**
   * Remove from the first non-zero higher bin index when current is zero.
   * This is the recommended strategy from the Adaptive Padding paper. */
  CIRCPAD_TOKEN_REMOVAL_HIGHER = 1,
  /** Remove from the first non-zero lower bin index when current is empty. */
  CIRCPAD_TOKEN_REMOVAL_LOWER = 2,
  /** Remove from the closest non-zero bin index when current is empty. */
  CIRCPAD_TOKEN_REMOVAL_CLOSEST = 3,
  /** Remove from the closest bin by time value (since bins are
   *  exponentially spaced). */
  CIRCPAD_TOKEN_REMOVAL_CLOSEST_USEC = 4,
  /** Only remove from the exact bin corresponding to this delay. If
   *  the bin is 0, simply do nothing. Don't pick another bin. */
  CIRCPAD_TOKEN_REMOVAL_EXACT = 5
} circpad_removal_t;

/** The maximum length any histogram can be. */
/** Each bin is twice as large as the previous, with an extra bin for 0 */
#define CIRCPAD_MAX_HISTOGRAM_LEN (sizeof(circpad_delay_t)*8 + 1)

/**
 * Distribution types supported by circpad_distribution_sample().
 *
 * These can be used instead of histograms for the inter-packet
 * timing distribution, or to specify a distribution on the number
 * of cells that can be sent while in a specific state of the state
 * machine. */
typedef enum {
  CIRCPAD_DIST_NONE = 0,
  CIRCPAD_DIST_UNIFORM = 1,
  CIRCPAD_DIST_LOGISTIC = 2,
  CIRCPAD_DIST_LOG_LOGISTIC = 3,
  CIRCPAD_DIST_GEOMETRIC = 4,
  CIRCPAD_DIST_WEIBULL = 5,
  CIRCPAD_DIST_PARETO = 6
} circpad_distribution_type_t;

/**
 * Distribution information.
 *
 * This type specifies a specific distribution above, as well as
 * up to two parameters for that distribution. The specific
 * per-distribution meaning of these parameters is specified
 * in circpad_distribution_sample().
 */
typedef struct circpad_distribution_t {
  circpad_distribution_type_t type;
  double param1;
  double param2;
} circpad_distribution_t;

/**
 * A circuit padding state machine state.
 *
 * This struct describes the histograms and parameters of a single
 * state in the adaptive padding machine. Instances of this struct
 * exist in global circpad machine definitions that come from torrc
 * or the consensus, and are immutable.
 */
typedef struct circpad_state_t {
  /** how long the histogram is (in bins). Histograms must have at least 2
   *  bins (or 0, if iat distributions are in use). */
  uint8_t histogram_len;
  /** histogram itself: an array of uint16s of tokens, whose
   * widths are exponentially spaced, in microseconds */
  circpad_hist_bin_t histogram[CIRCPAD_MAX_HISTOGRAM_LEN];
  /** total number of tokens */
  uint32_t histogram_total;

  /** Microseconds of the first bin of histogram, or base of iat dist */
  circpad_delay_t start_usec;
  /** The span of the histogram in seconds, used to calculate bin with.
   *  For iat dist use, this is used as a max delay cap on the distribution. */
  uint16_t range_sec;

  /**
   * The iat_dist is a parametrized way of encoding inter-packet delay
   * information in microseconds. It can be used instead of histograms.
   *
   * If it is used, token_removal below must be set to
   * CIRCPAD_TOKEN_REMOVAL_NONE.
   *
   * Start_usec, range_sec, and rtt_estimates are still applied to the
   * results of sampling from this distribution (range_sec is used as a max).
   */
  circpad_distribution_t iat_dist;

  /**
   * The length dist is a parameterized way of encoding how long this
   * state machine runs in terms of sent padding cells or all
   * sent cells. Values are sampled from this distribution, clamped
   * to max_len, and then start_len is added to that value.
   *
   * It may be specified instead of or in addition to
   * the infinity bins and bins empty conditions. */
  circpad_distribution_t length_dist;

  /** A minimum length value, added to the output of length_dist */
  uint16_t start_length;

  /** A cap on the length value that can be sampled from the length_dist */
  uint64_t max_length;

  /** Should we decrement length when we see a nonpadding packet?
   * XXX: Are there any machines that actually want to set this to 0? There may
   * not be. OTOH, it's only a bit.. */
  uint8_t length_includes_nonpadding : 1;

  /**
   * This is a bitfield that specifies which direction and types
   * of traffic that cause us to remain in the current state. Cancel the
   * pending padding packet (if any), and then await the next event.
   *
   * Example: Cancel padding if I saw a regular data packet.
   */
  circpad_event_t transition_cancel_events;

  /**
   * This is an array of bitfields that specifies which direction and
   * types of traffic that cause us to abort our scheduled packet and
   * switch to the state corresponding to the index of the array.
   *
   * Example: If the bins are empty (CIRCPAD_TRANSITION_ON_BINS_EMPTY) and that
   * bit is set in the burst state index, then transition to the burst state.
   */
  circpad_event_t transition_events[CIRCPAD_NUM_STATES];

  /**
   * If true, estimate the RTT from this relay to the exit/website and add that
   * to start_usec for use as the histogram bin 0 start delay.
   *
   * Right now this is only supported for relay-side state machines.
   */
  uint8_t use_rtt_estimate : 1;

  /** This specifies the token removal strategy to use upon padding and
   *  non-padding activity. */
  circpad_removal_t token_removal;
} circpad_state_t;

/**
 * Mutable padding machine info.
 *
 * This structure contains mutable information about a padding
 * machine. The mutable information must be kept separate because
 * it exists per-circuit, where as the machines themselves are global.
 * This separation is done to conserve space in the circuit structure.
 *
 * This is the per-circuit state that changes regarding the global state
 * machine. Some parts of it are optional (ie NULL).
 *
 * XXX: Play with layout to minimize space on x64 Linux (most common relay).
 */
typedef struct circpad_machineinfo_t {
  /** The callback pointer for the padding callbacks */
  tor_timer_t *padding_timer;

  /** The circuit for this machine */
  circuit_t *on_circ;

  /** A mutable copy of the histogram for the current state.
   *  NULL if remove_tokens is false for that state */
  circpad_hist_bin_t *histogram;
  /** Length of the above histogram.
   * XXX: This field *could* be removed at the expense of added
   * complexity+overhead for reaching back into the immutable machine
   * state every time we need to inspect the histogram. It's only a byte,
   * though, so it seemed worth it.
   */
  uint8_t histogram_len;
  /** Remove token from this index upon sending padding */
  uint8_t chosen_bin;

  /** Stop padding/transition if this many cells sent */
  uint64_t state_length;
#define CIRCPAD_STATE_LENGTH_INFINITE UINT64_MAX

  /** A scaled count of padding packets sent, used to limit padding overhead.
   * When this reaches UINT16_MAX, we cut it and nonpadding_sent in half. */
  uint16_t padding_sent;
  /** A scaled count of non-padding packets sent, used to limit padding
   *  overhead. When this reaches UINT16_MAX, we cut it and padding_sent in
   *  half. */
  uint16_t nonpadding_sent;

  /**
   * EWMA estimate of the RTT of the circuit from this hop
   * to the exit end, in microseconds. */
  circpad_delay_t rtt_estimate_us;

  /**
   * The last time we got an event relevant to estimating
   * the RTT. Monotonic time in microseconds since system
   * start.
   */
  circpad_time_t last_received_time_us;

  /**
   * The time at which we scheduled a non-padding packet,
   * or selected an infinite delay.
   *
   * Monotonic time in microseconds since system start.
   * This is 0 if we haven't chosen a padding delay.
   */
  circpad_time_t padding_scheduled_at_us;

  /** What state is this machine in? */
  ENUM_BF(circpad_statenum_t) current_state : 2;

  /**
   * True if we have scheduled a timer for padding.
   *
   * This is 1 if a timer is pending. It is 0 if
   * no timer is scheduled. (It can be 0 even when
   * padding_was_scheduled_at_us is non-zero).
   */
  uint8_t padding_timer_scheduled : 1;

  /**
   * If this is true, we have seen full duplex behavior.
   * Stop updating the RTT.
   */
  uint8_t stop_rtt_update : 1;

/** Max number of padding machines on each circuit. If changed,
 * also ensure the machine_index bitwith supports the new size. */
#define CIRCPAD_MAX_MACHINES    (2)
  /** Which padding machine index was this for.
   * (make sure changes to the bitwidth can support the
   * CIRCPAD_MAX_MACHINES define). */
  uint8_t machine_index : 1;

} circpad_machineinfo_t;

/** Helper macro to get an actual state machine from a machineinfo */
#define CIRCPAD_GET_MACHINE(machineinfo) \
    ((machineinfo)->on_circ->padding_machine[(machineinfo)->machine_index])

/**
 * This specifies a particular padding machine to use after negotiation.
 *
 * The constants for machine_num_t are in trunnel.
 * We want to be able to define extra numbers in the consensus/torrc, though.
 */
typedef uint8_t circpad_machine_num_t;

/** Global state machine structure from the consensus */
typedef struct circpad_machine_t {
  /** Global machine number */
  circpad_machine_num_t machine_num;

  /** Which machine index slot should this machine go into in
   *  the array on the circuit_t */
  uint8_t machine_index : 1;

  /** Send a padding negotiate to shut down machine at end state? */
  uint8_t negotiate_end : 1;

  // These next three fields are origin machine-only...
  /** Origin side or relay side */
  uint8_t origin_side : 1;

  /** Which hop in the circuit should we send padding to/from?
   *  1-indexed (ie: hop #1 is guard, #2 middle, #3 exit). */
  uint8_t target_hopnum : 3;

  /** This machine only kills fascists if the following conditions are met. */
  circpad_machine_conditions_t conditions;

  /** How many padding cells can be sent before we apply overhead limits?
   * XXX: Note that we can only allow up to 64k of padding cells on an
   * otherwise quiet circuit. Is this enough? It's 33MB. */
  uint16_t allowed_padding_count;

  /** Padding percent cap: Stop padding if we exceed this percent overhead.
   * 0 means no limit. Overhead is defined as percent of total traffic, so
   * that we can use 0..100 here. This is the same definition as used in
   * Prop#265. */
  uint8_t max_padding_percent;

  /**
   * The start state for this machine.
   *
   * In the original WTF-PAD, this is only used for transition to/from
   * the burst state. All other fields are not used. But to simplify the
   * code we've made it a first-class state. This has no performance
   * consequences, but may make naive serialization of the state machine
   * large, if we're not careful about how we represent empty fields.
   */
  circpad_state_t start;

  /**
   * The burst state for this machine.
   *
   * In the original Adaptive Padding algorithm and in WTF-PAD
   * (https://www.freehaven.net/anonbib/cache/ShWa-Timing06.pdf and
   * https://www.cs.kau.se/pulls/hot/thebasketcase-wtfpad/), the burst
   * state serves to detect bursts in traffic. This is done by using longer
   * delays in its histogram, which represent the expected delays between
   * bursts of packets in the target stream. If this delay expires without a
   * real packet being sent, the burst state sends a padding packet and then
   * immediately transitions to the gap state, which is used to generate
   * a synthetic padding packet train. In this implementation, this transition
   * needs to be explicitly specified in the burst state's transition events.
   *
   * Because of this flexibility, other padding mechanisms can transition
   * between these two states arbitrarily, to encode other dynamics of
   * target traffic.
   */
  circpad_state_t burst;

  /**
   * The gap state for this machine.
   *
   * In the original Adaptive Padding algorithm and in WTF-PAD, the gap
   * state serves to simulate an artificial packet train composed of padding
   * packets. It does this by specifying much lower inter-packet delays than
   * the burst state, and transitioning back to itself after padding is sent
   * if these timers expire before real traffic is sent. If real traffic is
   * sent, it transitions back to the burst state.
   *
   * Again, in this implementation, these transitions must be specified
   * explicitly, and other transitions are also permitted.
   */
  circpad_state_t gap;

} circpad_machine_t;

void circpad_new_consensus_params(networkstatus_t *ns);

/**
 * The following are event call-in points that are of interest to
 * the state machines. They are called during cell processing. */
void circpad_deliver_unrecognized_cell_events(circuit_t *circ,
                                              cell_direction_t dir);
void circpad_deliver_sent_relay_cell_events(circuit_t *circ,
                                            uint8_t relay_command);
void circpad_deliver_recognized_relay_cell_events(circuit_t *circ,
                                                  uint8_t relay_command,
                                                  crypt_path_t *layer_hint);

/** Cell events are delivered by the above delivery functions */
void circpad_cell_event_nonpadding_sent(circuit_t *on_circ);
void circpad_cell_event_nonpadding_received(circuit_t *on_circ);
void circpad_cell_event_padding_sent(circuit_t *on_circ);
void circpad_cell_event_padding_received(circuit_t *on_circ);

/** Internal events are events the machines send to themselves */
circpad_decision_t circpad_internal_event_infinity(circpad_machineinfo_t *mi);
circpad_decision_t circpad_internal_event_bins_empty(circpad_machineinfo_t *);
circpad_decision_t circpad_internal_event_state_length_up(
                                  circpad_machineinfo_t *);

/** Machine creation events are events that cause us to set up or
 *  tear down padding state machines. */
void circpad_machine_event_circ_added_hop(origin_circuit_t *on_circ);
void circpad_machine_event_circ_built(origin_circuit_t *circ);
void circpad_machine_event_circ_purpose_changed(origin_circuit_t *circ);
void circpad_machine_event_circ_has_streams(origin_circuit_t *circ);
void circpad_machine_event_circ_has_no_streams(origin_circuit_t *circ);
void circpad_machine_event_circ_has_no_relay_early(origin_circuit_t *circ);

void circpad_machines_init(void);
void circpad_machines_free(void);

void circpad_circuit_machineinfo_free(circuit_t *circ);

bool circpad_padding_is_from_expected_hop(circuit_t *circ,
                                         crypt_path_t *from_hop);

/** Serializaton functions for writing to/from torrc and consensus */
char *circpad_machine_to_string(const circpad_machine_t *machine);
const circpad_machine_t *circpad_string_to_machine(const char *str);

/* Padding negotiation between client and middle */
int circpad_handle_padding_negotiate(circuit_t *circ, cell_t *cell);
int circpad_handle_padding_negotiated(circuit_t *circ, cell_t *cell,
                                      crypt_path_t *layer_hint);
bool circpad_negotiate_padding(origin_circuit_t *circ,
                          circpad_machine_num_t machine,
                          int target_hopnum,
                          int command);
bool circpad_padding_negotiated(circuit_t *circ,
                           circpad_machine_num_t machine,
                           int command,
                           int response);

#endif
