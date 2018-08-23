#define TOR_CHANNEL_INTERNAL_
#include "core/or/or.h"
#include "test.h"
#include "lib/testsupport/testsupport.h"
#include "core/or/connection_or.h"
#include "core/or/channel.h"
#include "core/or/channeltls.h"
#include <event.h>
#include "lib/evloop/compat_libevent.h"
#include "lib/time/compat_time.h"
#include "core/or/relay.h"
#include "core/or/circuitlist.h"
#include "core/or/circuitbuild.h"
#include "core/or/circuitpadding.h"
#include "core/crypto/relay_crypto.h"
#include "core/or/protover.h"
#include "feature/nodelist/nodelist.h"
#include "lib/evloop/compat_libevent.h"

#include "feature/nodelist/routerstatus_st.h"
#include "feature/nodelist/node_st.h"
#include "core/or/cell_st.h"
#include "core/or/crypt_path_st.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"

extern smartlist_t *connection_array;
extern networkstatus_t *current_ns_consensus;
extern networkstatus_t *current_md_consensus;

#define USEC_PER_SEC (1000000)
circid_t get_unique_circ_id_by_chan(channel_t *chan);
circpad_delay_t circpad_histogram_bin_to_usec(circpad_machineinfo_t *mi,
                                       int bin);
int circpad_histogram_usec_to_bin(circpad_machineinfo_t *mi,
                                       circpad_delay_t us);

const circpad_state_t *circpad_machine_current_state(
        circpad_machineinfo_t *machine);
void circpad_circ_token_machine_setup(circuit_t *on_circ);

circpad_machineinfo_t *circpad_circuit_machineinfo_new(circuit_t *on_circ,
                                               int machine_index);
void circpad_machine_remove_higher_token(circpad_machineinfo_t *mi,
                                         circpad_delay_t target_bin_us);
void circpad_machine_remove_lower_token(circpad_machineinfo_t *mi,
                                         circpad_delay_t target_bin_us);
void circpad_machine_remove_closest_token(circpad_machineinfo_t *mi,
                                         circpad_delay_t target_bin_us,
                                         int use_usec);
STATIC void circpad_machine_setup_tokens(circpad_machineinfo_t *mi);

static or_circuit_t * new_fake_orcirc(channel_t *nchan, channel_t *pchan);
channel_t *new_fake_channel(void);
void test_circuitpadding_negotiation(void *arg);

void test_circuitpadding_serialize(void *arg);
void test_circuitpadding_rtt(void *arg);
void test_circuitpadding_tokens(void *arg);
void test_circuitpadding_circuitsetup_machine(void *arg);

static void
simulate_single_hop_extend(circuit_t *client, circuit_t *mid_relay,
                           int padding);
void free_fake_orcirc(circuit_t *circ);
void free_fake_origin_circuit(origin_circuit_t *circ);

static node_t padding_node;
static node_t non_padding_node;

static channel_t dummy_channel;

static void
nodes_init(void)
{
  padding_node.rs = tor_malloc_zero(sizeof(routerstatus_t));
  padding_node.rs->pv.supports_padding = 1;

  non_padding_node.rs = tor_malloc_zero(sizeof(routerstatus_t));
  non_padding_node.rs->pv.supports_padding = 0;
}

static void
nodes_free(void)
{
  tor_free(padding_node.rs);

  tor_free(non_padding_node.rs);
}

static const node_t *
node_get_by_id_mock(const char *identity_digest)
{
  if (identity_digest[0] == 1) {
    return &padding_node;
  } else if (identity_digest[0] == 0) {
    return &non_padding_node;
  }

  return NULL;
}

static or_circuit_t *
new_fake_orcirc(channel_t *nchan, channel_t *pchan)
{
  or_circuit_t *orcirc = NULL;
  circuit_t *circ = NULL;
  crypt_path_t tmp_cpath;
  char whatevs_key[CPATH_KEY_MATERIAL_LEN];

  orcirc = tor_malloc_zero(sizeof(*orcirc));
  circ = &(orcirc->base_);
  circ->magic = OR_CIRCUIT_MAGIC;

  //circ->n_chan = nchan;
  circ->n_circ_id = get_unique_circ_id_by_chan(nchan);
  circ->n_mux = NULL; /* ?? */
  cell_queue_init(&(circ->n_chan_cells));
  circ->n_hop = NULL;
  circ->streams_blocked_on_n_chan = 0;
  circ->streams_blocked_on_p_chan = 0;
  circ->n_delete_pending = 0;
  circ->p_delete_pending = 0;
  circ->received_destroy = 0;
  circ->state = CIRCUIT_STATE_OPEN;
  circ->purpose = CIRCUIT_PURPOSE_OR;
  circ->package_window = CIRCWINDOW_START_MAX;
  circ->deliver_window = CIRCWINDOW_START_MAX;
  circ->n_chan_create_cell = NULL;

  //orcirc->p_chan = pchan;
  orcirc->p_circ_id = get_unique_circ_id_by_chan(pchan);
  cell_queue_init(&(orcirc->p_chan_cells));

  circuit_set_p_circid_chan(orcirc, orcirc->p_circ_id, pchan);
  circuit_set_n_circid_chan(circ, circ->n_circ_id, nchan);

  memset(&tmp_cpath, 0, sizeof(tmp_cpath));
  if (circuit_init_cpath_crypto(&tmp_cpath, whatevs_key,
                                sizeof(whatevs_key), 0, 0)<0) {
    log_warn(LD_BUG,"Circuit initialization failed");
    return NULL;
  }
  orcirc->crypto = tmp_cpath.crypto;

  return orcirc;
}

void
free_fake_orcirc(circuit_t *circ)
{
  or_circuit_t *orcirc = TO_OR_CIRCUIT(circ);

  relay_crypto_clear(&orcirc->crypto);

  circpad_circuit_machineinfo_free(circ);
  tor_free(circ);
}

void
free_fake_origin_circuit(origin_circuit_t *circ)
{
  circpad_circuit_machineinfo_free(TO_CIRCUIT(circ));
  circuit_clear_cpath(circ);
  tor_free(circ);
}

void dummy_nop_timer(void);

//static int dont_stop_libevent = 0;

static circuit_t *client_side;
static circuit_t *relay_side;

static int n_client_cells = 0;
static int n_relay_cells = 0;

static int
circuit_package_relay_cell_mock(cell_t *cell, circuit_t *circ,
                           cell_direction_t cell_direction,
                           crypt_path_t *layer_hint, streamid_t on_stream,
                           const char *filename, int lineno);

static void
circuitmux_attach_circuit_mock(circuitmux_t *cmux, circuit_t *circ,
                               cell_direction_t direction);

static void
circuitmux_attach_circuit_mock(circuitmux_t *cmux, circuit_t *circ,
                               cell_direction_t direction)
{
  (void)cmux;
  (void)circ;
  (void)direction;

  return;
}

static int
circuit_package_relay_cell_mock(cell_t *cell, circuit_t *circ,
                           cell_direction_t cell_direction,
                           crypt_path_t *layer_hint, streamid_t on_stream,
                           const char *filename, int lineno) {
  (void)cell; (void)on_stream; (void)filename; (void)lineno;

  if (circ == client_side) {
    if (cell->payload[0] == RELAY_COMMAND_PADDING_NEGOTIATE) {
      // Deliver to relay
      circpad_handle_padding_negotiate(relay_side, cell);
    } else {

      int is_target_hop = circpad_padding_is_from_expected_hop(circ,
                                                             layer_hint);
      tt_int_op(cell_direction, OP_EQ, CELL_DIRECTION_OUT);
      tt_int_op(is_target_hop, OP_EQ, 1);

      // Pretend a padding cell was sent
      circpad_cell_event_padding_sent(client_side);

      // Receive padding cell at middle
      circpad_cell_event_padding_received(relay_side);
    }
    n_client_cells++;
  } else if (circ == relay_side) {
    tt_int_op(cell_direction, OP_EQ, CELL_DIRECTION_IN);

    if (cell->payload[0] == RELAY_COMMAND_PADDING_NEGOTIATED) {
      // XXX: blah need right layer_hint..
      circpad_handle_padding_negotiated(client_side, cell,
                                        TO_ORIGIN_CIRCUIT(client_side)
                                           ->cpath->next);
    } else {
      // Pretend a padding cell was sent
      circpad_cell_event_padding_sent(relay_side);
      // Receive padding cell at client
      circpad_cell_event_padding_received(client_side);
    }

    n_relay_cells++;
  }

 done:
  event_base_loopbreak(tor_libevent_get_base());
  return 0;
}

// Test reading and writing padding to strings (or options_t + consensus)
void
test_circuitpadding_serialize(void *arg)
{
  (void)arg;
}

void
test_circuitpadding_rtt(void *arg)
{
  /* Test Plan:
   *
   * 1. Test RTT measurement server side
   *    a. test usage of measured RTT
   * 2. Test termination of RTT measurement
   *    a. test non-update of RTT
   * 3. Test client side circuit and non-application of RTT..
   */
  circpad_delay_t rtt_estimate;
  (void)arg;

  MOCK(circuitmux_attach_circuit, circuitmux_attach_circuit_mock);

  dummy_channel.cmux = circuitmux_alloc();
  relay_side = (circuit_t *)new_fake_orcirc(&dummy_channel,
                                            &dummy_channel);
  client_side = (circuit_t *)origin_circuit_new();
  relay_side->purpose = CIRCUIT_PURPOSE_OR;
  client_side->purpose = CIRCUIT_PURPOSE_C_GENERAL;

  monotime_init();
  timers_initialize();
  circpad_machines_init();

  MOCK(circuit_package_relay_cell,
       circuit_package_relay_cell_mock);

  circpad_circ_token_machine_setup(client_side);
  circpad_circ_token_machine_setup(relay_side);

  /* Test 1: Test measuring RTT */
  circpad_cell_event_nonpadding_received((circuit_t*)relay_side);
  tt_int_op(relay_side->padding_info[0]->last_received_time_us, OP_NE, 0);

  tor_sleep_msec(20);
  circpad_cell_event_nonpadding_sent((circuit_t*)relay_side);
  tt_int_op(relay_side->padding_info[0]->last_received_time_us, OP_EQ, 0);

  tt_int_op(relay_side->padding_info[0]->rtt_estimate_us, OP_GE, 19000);
  tt_int_op(relay_side->padding_info[0]->rtt_estimate_us, OP_LE, 30000);
  tt_int_op(circpad_histogram_bin_to_usec(relay_side->padding_info[0], 0),
            OP_EQ,
            relay_side->padding_info[0]->rtt_estimate_us+
            circpad_machine_current_state(
             relay_side->padding_info[0])->start_usec);

  circpad_cell_event_nonpadding_received((circuit_t*)relay_side);
  circpad_cell_event_nonpadding_received((circuit_t*)relay_side);
  tt_int_op(relay_side->padding_info[0]->last_received_time_us, OP_NE, 0);
  tor_sleep_msec(40);
  circpad_cell_event_nonpadding_sent((circuit_t*)relay_side);
  circpad_cell_event_nonpadding_sent((circuit_t*)relay_side);
  tt_int_op(relay_side->padding_info[0]->last_received_time_us, OP_EQ, 0);

  tt_int_op(relay_side->padding_info[0]->rtt_estimate_us, OP_GE, 29000);
  tt_int_op(relay_side->padding_info[0]->rtt_estimate_us, OP_LE, 50000);
  tt_int_op(circpad_histogram_bin_to_usec(relay_side->padding_info[0], 0),
            OP_EQ,
            relay_side->padding_info[0]->rtt_estimate_us+
            circpad_machine_current_state(
             relay_side->padding_info[0])->start_usec);

  /* Test 2: Termination of RTT measurement (from the previous test) */
  tt_int_op(relay_side->padding_info[0]->stop_rtt_update, OP_EQ, 1);
  rtt_estimate = relay_side->padding_info[0]->rtt_estimate_us;

  circpad_cell_event_nonpadding_received((circuit_t*)relay_side);
  tor_sleep_msec(4);
  circpad_cell_event_nonpadding_sent((circuit_t*)relay_side);

  tt_int_op(relay_side->padding_info[0]->rtt_estimate_us, OP_EQ, rtt_estimate);
  tt_int_op(relay_side->padding_info[0]->last_received_time_us, OP_EQ, 0);
  tt_int_op(relay_side->padding_info[0]->stop_rtt_update, OP_EQ, 1);
  tt_int_op(circpad_histogram_bin_to_usec(relay_side->padding_info[0], 0),
            OP_EQ,
            relay_side->padding_info[0]->rtt_estimate_us+
            circpad_machine_current_state(
             relay_side->padding_info[0])->start_usec);

  /* Test 3: Make sure client side machine properly ignores RTT */
  circpad_cell_event_nonpadding_received((circuit_t*)client_side);
  tt_int_op(client_side->padding_info[0]->last_received_time_us, OP_EQ, 0);

  tor_sleep_msec(20);
  circpad_cell_event_nonpadding_sent((circuit_t*)client_side);
  tt_int_op(client_side->padding_info[0]->last_received_time_us, OP_EQ, 0);

  tt_int_op(client_side->padding_info[0]->rtt_estimate_us, OP_EQ, 0);
  tt_int_op(circpad_histogram_bin_to_usec(client_side->padding_info[0], 0),
            OP_NE, client_side->padding_info[0]->rtt_estimate_us);
  tt_int_op(circpad_histogram_bin_to_usec(client_side->padding_info[0], 0),
            OP_EQ,
            circpad_machine_current_state(
                client_side->padding_info[0])->start_usec);
 done:
  free_fake_orcirc(relay_side);
  circuitmux_detach_all_circuits(dummy_channel.cmux, NULL);
  circuitmux_free(dummy_channel.cmux);
  timers_shutdown();
  UNMOCK(circuit_package_relay_cell);
  UNMOCK(circuitmux_attach_circuit);

  return;
}

static circpad_machine_t circ_client_machine;
void
circpad_circ_token_machine_setup(circuit_t *on_circ)
{
  on_circ->padding_machine[0] = &circ_client_machine;
  on_circ->padding_info[0] = circpad_circuit_machineinfo_new(on_circ, 0);

   circ_client_machine.start.transition_events[CIRCPAD_STATE_BURST] =
    CIRCPAD_EVENT_NONPADDING_RECV;

  circ_client_machine.burst.transition_events[CIRCPAD_STATE_BURST] =
    CIRCPAD_EVENT_PADDING_RECV |
    CIRCPAD_EVENT_NONPADDING_RECV;

  circ_client_machine.burst.transition_cancel_events =
    CIRCPAD_EVENT_NONPADDING_SENT;

  // FIXME: Is this what we want?
  circ_client_machine.burst.token_removal = CIRCPAD_TOKEN_REMOVAL_HIGHER;

  // FIXME: Tune this histogram
  circ_client_machine.burst.histogram_len = 5;
  circ_client_machine.burst.start_usec = 500;
  circ_client_machine.burst.range_sec = 1;
  circ_client_machine.burst.histogram[0] = 1;
  circ_client_machine.burst.histogram[1] = 0;
  circ_client_machine.burst.histogram[2] = 2;
  circ_client_machine.burst.histogram[3] = 2;
  circ_client_machine.burst.histogram[4] = 2;
  circ_client_machine.burst.histogram_total = 7;
  circ_client_machine.burst.use_rtt_estimate = 1;

  return;
}

void
test_circuitpadding_tokens(void *arg)
{
  const circpad_state_t *state;
  circpad_machineinfo_t *mi;
  (void)arg;

  /** Test plan:
   *
   * 1. Test symmetry between bin_to_usec and usec_to_bin
   *    a. Test conversion
   *    b. Test edge transitions (lower, upper)
   * 2. Test remove higher on an empty bin
   *    a. Normal bin
   *    b. Infinity bin
   *    c. Bin 0
   *    d. No higher
   * 3. Test remove lower
   *    a. Normal bin
   *    b. Bin 0
   *    c. No lower
   * 4. Test remove closest
   *    a. Closest lower
   *    b. Closest higher
   *    c. Closest 0
   *    d. Closest Infinity
   */
  client_side = (circuit_t *)origin_circuit_new();
  client_side->purpose = CIRCUIT_PURPOSE_C_GENERAL;

  monotime_init();
  timers_initialize();

  circpad_circ_token_machine_setup(client_side);

  mi = client_side->padding_info[0];

  // Pretend a non-padding cell was sent
  // XXX: This messes us up.. Padding gets scheduled..
  circpad_cell_event_nonpadding_sent((circuit_t*)client_side);
  circpad_cell_event_nonpadding_received((circuit_t*)client_side);
  tt_int_op(client_side->padding_info[0]->current_state, OP_EQ,
            CIRCPAD_STATE_BURST);

  state = circpad_machine_current_state(client_side->padding_info[0]);

  // Test 1: converting usec->bin->usec->usec
  for (circpad_delay_t i = 0;
           i < state->start_usec + state->range_sec*USEC_PER_SEC*2;
           i++) {
    int bin = circpad_histogram_usec_to_bin(client_side->padding_info[0],
                                            i);
    circpad_delay_t usec =
        circpad_histogram_bin_to_usec(client_side->padding_info[0], bin);
    int bin2 = circpad_histogram_usec_to_bin(client_side->padding_info[0],
                                             usec);
    tt_int_op(bin, OP_EQ, bin2);
  }

  /* 2.a. Normal higher bin */
  {
    tt_int_op(mi->histogram[2], OP_EQ, 2);
    tt_int_op(mi->histogram[3], OP_EQ, 2);
    circpad_machine_remove_higher_token(mi,
         circpad_histogram_bin_to_usec(mi, 2)+1);
    tt_int_op(mi->histogram[2], OP_EQ, 1);

    circpad_machine_remove_higher_token(mi,
         circpad_histogram_bin_to_usec(mi, 2)+1);
    tt_int_op(mi->histogram[2], OP_EQ, 0);

    tt_int_op(mi->histogram[3], OP_EQ, 2);
    circpad_machine_remove_higher_token(mi,
         circpad_histogram_bin_to_usec(mi, 2)+1);
    circpad_machine_remove_higher_token(mi,
         circpad_histogram_bin_to_usec(mi, 2)+1);
    circpad_machine_remove_higher_token(mi,
         circpad_histogram_bin_to_usec(mi, 2)+1);
    tt_int_op(mi->histogram[3], OP_EQ, 0);
  }

  /* 2.b. Higher Infinity bin */
  {
    tt_int_op(mi->histogram[4], OP_EQ, 2);
    circpad_machine_remove_higher_token(mi,
         circpad_histogram_bin_to_usec(mi, 2)+1);
    tt_int_op(mi->histogram[4], OP_EQ, 2);

    /* Test past the infinity bin */
    circpad_machine_remove_higher_token(mi,
         circpad_histogram_bin_to_usec(mi, 5)+1000000);

    tt_int_op(mi->histogram[4], OP_EQ, 2);
  }

  /* 2.c. Bin 0 */
  {
    tt_int_op(mi->histogram[0], OP_EQ, 1);
    circpad_machine_remove_higher_token(mi,
         state->start_usec/2);
    tt_int_op(mi->histogram[0], OP_EQ, 0);
  }

  /* Drain the infinity bin and cause a refill */
  tt_int_op(mi->histogram[4], OP_EQ, 2);
  circpad_cell_event_nonpadding_received((circuit_t*)client_side);
  tt_int_op(mi->histogram[4], OP_EQ, 1);
  circpad_cell_event_nonpadding_received((circuit_t*)client_side);
  tt_int_op(mi->histogram[4], OP_EQ, 0);

  circpad_cell_event_nonpadding_sent((circuit_t*)client_side);

  // We should have refilled here.
  tt_int_op(mi->histogram[4], OP_EQ, 2);

  /* 3.a. Bin 0 */
  {
    tt_int_op(mi->histogram[0], OP_EQ, 1);
    circpad_machine_remove_higher_token(mi,
         state->start_usec/2);
    tt_int_op(mi->histogram[0], OP_EQ, 0);
  }

  /* 3.b. Test remove lower normal bin */
  {
    tt_int_op(mi->histogram[3], OP_EQ, 2);
    circpad_machine_remove_lower_token(mi,
         circpad_histogram_bin_to_usec(mi, 3)+1);
    circpad_machine_remove_lower_token(mi,
         circpad_histogram_bin_to_usec(mi, 3)+1);
    tt_int_op(mi->histogram[3], OP_EQ, 0);
    tt_int_op(mi->histogram[2], OP_EQ, 2);
    circpad_machine_remove_lower_token(mi,
         circpad_histogram_bin_to_usec(mi, 3)+1);
    circpad_machine_remove_lower_token(mi,
         circpad_histogram_bin_to_usec(mi, 3)+1);
    /* 3.c. No lower */
    circpad_machine_remove_lower_token(mi,
         circpad_histogram_bin_to_usec(mi, 3)+1);
    tt_int_op(mi->histogram[2], OP_EQ, 0);
  }

  /* 4. Test remove closest
   *    a. Closest lower
   *    b. Closest higher
   *    c. Closest 0
   *    d. Closest Infinity
   */
  circpad_machine_setup_tokens(mi);
  tt_int_op(mi->histogram[2], OP_EQ, 2);
  circpad_machine_remove_closest_token(mi,
         circpad_histogram_bin_to_usec(mi, 2)+1, 0);
  circpad_machine_remove_closest_token(mi,
         circpad_histogram_bin_to_usec(mi, 2)+1, 0);
  tt_int_op(mi->histogram[2], OP_EQ, 0);
  tt_int_op(mi->histogram[3], OP_EQ, 2);
  circpad_machine_remove_closest_token(mi,
         circpad_histogram_bin_to_usec(mi, 2)+1, 0);
  circpad_machine_remove_closest_token(mi,
         circpad_histogram_bin_to_usec(mi, 2)+1, 0);
  tt_int_op(mi->histogram[3], OP_EQ, 0);
  tt_int_op(mi->histogram[0], OP_EQ, 1);
  circpad_machine_remove_closest_token(mi,
         circpad_histogram_bin_to_usec(mi, 2)+1, 0);
  tt_int_op(mi->histogram[0], OP_EQ, 0);
  tt_int_op(mi->histogram[4], OP_EQ, 2);
  circpad_machine_remove_closest_token(mi,
         circpad_histogram_bin_to_usec(mi, 2)+1, 0);
  tt_int_op(mi->histogram[4], OP_EQ, 2);

  /* 5. Test remove closest usec
   *    a. Closest 0
   *    b. Closest lower (below midpoint)
   *    c. Closest higher (above midpoint)
   *    d. Closest Infinity
   */
  circpad_machine_setup_tokens(mi);

  tt_int_op(mi->histogram[0], OP_EQ, 1);
  circpad_machine_remove_closest_token(mi,
         circpad_histogram_bin_to_usec(mi, 0)/3, 1);
  tt_int_op(mi->histogram[0], OP_EQ, 0);
  tt_int_op(mi->histogram[2], OP_EQ, 2);
  circpad_machine_remove_closest_token(mi,
         circpad_histogram_bin_to_usec(mi, 0)/3, 1);
  circpad_machine_remove_closest_token(mi,
         circpad_histogram_bin_to_usec(mi, 0)/3, 1);
  tt_int_op(mi->histogram[2], OP_EQ, 0);
  tt_int_op(mi->histogram[3], OP_EQ, 2);
  circpad_machine_remove_closest_token(mi,
         circpad_histogram_bin_to_usec(mi, 4), 1);
  circpad_machine_remove_closest_token(mi,
         circpad_histogram_bin_to_usec(mi, 4), 1);
  tt_int_op(mi->histogram[3], OP_EQ, 0);
  tt_int_op(mi->histogram[4], OP_EQ, 2);
  circpad_machine_remove_closest_token(mi,
         circpad_histogram_bin_to_usec(mi, 4), 1);
  circpad_machine_remove_closest_token(mi,
         circpad_histogram_bin_to_usec(mi, 4), 1);
  tt_int_op(mi->histogram[4], OP_EQ, 2);

  // XXX: Need more coverage of the actual usec branches

 done:
  free_fake_origin_circuit(TO_ORIGIN_CIRCUIT(client_side));
}

void
test_circuitpadding_negotiation(void *arg)
{
  /**
   * Test plan:
   * 1. Test circuit where padding is supported by middle
   *    a. Make sure padding negotiation is sent
   *    b. Test padding negotiation delivery and parsing
   * 2. Test circuit where padding is unsupported by middle
   *    a. Make sure padding negotiation is not sent
   * FIXME: Test the actual relay and circuit functions that
   * call us. And maybe test the leaky hop delivery?
   */
  (void)arg;

  MOCK(circuitmux_attach_circuit, circuitmux_attach_circuit_mock);

  client_side = (circuit_t *)origin_circuit_new();
  dummy_channel.cmux = circuitmux_alloc();
  relay_side = (circuit_t *)new_fake_orcirc(&dummy_channel,
                                            &dummy_channel);

  relay_side->purpose = CIRCUIT_PURPOSE_OR;
  client_side->purpose = CIRCUIT_PURPOSE_C_GENERAL;
  nodes_init();
  monotime_init();
  timers_initialize();
  circpad_machines_init();

  MOCK(node_get_by_id,
       node_get_by_id_mock);

  MOCK(circuit_package_relay_cell,
       circuit_package_relay_cell_mock);

  /* Build two hops */
  simulate_single_hop_extend(client_side, relay_side, 1);
  simulate_single_hop_extend(client_side, relay_side, 1);

  /* verify padding was negotiated */
  tt_ptr_op(relay_side->padding_machine[0], OP_NE, NULL);
  tt_ptr_op(relay_side->padding_info[0], OP_NE, NULL);

  /* verify echo was sent */
  tt_int_op(n_relay_cells, OP_EQ, 1);
  tt_int_op(n_client_cells, OP_EQ, 1);

  /* Finish circuit */
  simulate_single_hop_extend(client_side, relay_side, 1);

  /* Test 2: Test no padding */
  free_fake_origin_circuit(TO_ORIGIN_CIRCUIT(client_side));
  free_fake_orcirc(relay_side);

  client_side = (circuit_t *)origin_circuit_new();
  relay_side = (circuit_t *)new_fake_orcirc(&dummy_channel,
                                            &dummy_channel);
  relay_side->purpose = CIRCUIT_PURPOSE_OR;
  client_side->purpose = CIRCUIT_PURPOSE_C_GENERAL;

  simulate_single_hop_extend(client_side, relay_side, 1);
  simulate_single_hop_extend(client_side, relay_side, 0);

  /* verify no padding was negotiated */
  tt_ptr_op(relay_side->padding_machine[0], OP_EQ, NULL);
  tt_int_op(n_relay_cells, OP_EQ, 1);
  tt_int_op(n_client_cells, OP_EQ, 1);

  /* verify no echo was sent */
  tt_int_op(n_relay_cells, OP_EQ, 1);
  tt_int_op(n_client_cells, OP_EQ, 1);

  /* Finish circuit */
  simulate_single_hop_extend(client_side, relay_side, 1);

  /* Force negotiate padding. */
  circpad_negotiate_padding(TO_ORIGIN_CIRCUIT(client_side),
                            CIRCPAD_MACHINE_CIRC_SETUP,
                            2, CIRCPAD_COMMAND_START);

  /* verify no padding was negotiated */
  tt_ptr_op(relay_side->padding_machine[0], OP_EQ, NULL);

  /* verify no echo was sent */
  tt_int_op(n_relay_cells, OP_EQ, 1);
  tt_int_op(n_client_cells, OP_EQ, 1);

 done:
  free_fake_origin_circuit(TO_ORIGIN_CIRCUIT(client_side));
  free_fake_orcirc(relay_side);
  circuitmux_detach_all_circuits(dummy_channel.cmux, NULL);
  circuitmux_free(dummy_channel.cmux);
  UNMOCK(node_get_by_id);
  UNMOCK(circuit_package_relay_cell);
  UNMOCK(circuitmux_attach_circuit);
  nodes_free();
}

static void
simulate_single_hop_extend(circuit_t *client, circuit_t *mid_relay,
                           int padding)
{
  char whatevs_key[CPATH_KEY_MATERIAL_LEN];
  char digest[DIGEST_LEN];
  tor_addr_t addr;

  // Pretend a non-padding cell was sent
  circpad_cell_event_nonpadding_sent((circuit_t*)client);

  // Receive extend cell at middle
  circpad_cell_event_nonpadding_received((circuit_t*)mid_relay);

  // Sleep a tiny bit so we can calculate an RTT
  tor_sleep_msec(10);

  // Receive extended cell at middle
  circpad_cell_event_nonpadding_sent((circuit_t*)mid_relay);

  // Receive extended cell at first hop
  circpad_cell_event_nonpadding_received((circuit_t*)client);

  // Add a hop to cpath
  crypt_path_t *hop = tor_malloc_zero(sizeof(crypt_path_t));
  onion_append_to_cpath(&TO_ORIGIN_CIRCUIT(client)->cpath, hop);

  hop->magic = CRYPT_PATH_MAGIC;
  hop->state = CPATH_STATE_OPEN;

  // add an extend info to indicate if this node supports padding or not.
  // (set the first byte of the digest for our mocked node_get_by_id)
  digest[0] = padding;

  hop->extend_info = extend_info_new(
          padding ? "padding" : "non-padding",
          digest, NULL, NULL, NULL,
          &addr, padding);

  circuit_init_cpath_crypto(hop, whatevs_key, sizeof(whatevs_key), 0, 0);

  hop->package_window = circuit_initial_package_window();
  hop->deliver_window = CIRCWINDOW_START;

  // Signal that the hop was added
  circpad_machine_event_circ_added_hop(TO_ORIGIN_CIRCUIT(client));
}

void
test_circuitpadding_circuitsetup_machine(void *arg)
{
  /**
   * Test case plan:
   *
   * 1. Simulate a normal circuit setup pattern
   *    a. Application traffic
   *
   * FIXME: This should focus more on exercising the machine
   * features rather than actual traffic patterns. For example,
   * test cancellation and bins empty/refill
   */
  (void)arg;

  MOCK(circuitmux_attach_circuit, circuitmux_attach_circuit_mock);

  dummy_channel.cmux = circuitmux_alloc();
  client_side = (circuit_t *)origin_circuit_new();
  relay_side = (circuit_t *)new_fake_orcirc(&dummy_channel, &dummy_channel);

  relay_side->purpose = CIRCUIT_PURPOSE_OR;
  client_side->purpose = CIRCUIT_PURPOSE_C_GENERAL;

  nodes_init();
  monotime_init();
  timers_initialize();
  circpad_machines_init();

  MOCK(circuit_package_relay_cell,
       circuit_package_relay_cell_mock);
  MOCK(node_get_by_id,
       node_get_by_id_mock);

  /* Test case #1: Build a 3 hop circuit, then wait and let pad */
  simulate_single_hop_extend(client_side, relay_side, 1);
  simulate_single_hop_extend(client_side, relay_side, 1);
  simulate_single_hop_extend(client_side, relay_side, 1);

  tt_int_op(n_client_cells, OP_EQ, 1);
  tt_int_op(n_relay_cells, OP_EQ, 1);
  tt_int_op(client_side->padding_info[0]->current_state, OP_EQ,
                CIRCPAD_STATE_BURST);
  tt_int_op(relay_side->padding_info[0]->current_state, OP_EQ,
          CIRCPAD_STATE_BURST);

  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_us,
            OP_NE, 0);
  tt_int_op(relay_side->padding_info[0]->padding_timer_scheduled,
            OP_EQ, 0);
  event_base_loop(tor_libevent_get_base(), 0);
  tt_int_op(n_client_cells, OP_EQ, 2);
  tt_int_op(n_relay_cells, OP_EQ, 1);

  tt_int_op(relay_side->padding_info[0]->current_state, OP_EQ,
              CIRCPAD_STATE_GAP);

  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_us,
            OP_EQ, 0);
  tt_int_op(relay_side->padding_info[0]->padding_scheduled_at_us,
            OP_NE, 0);
  event_base_loop(tor_libevent_get_base(), 0);
  tt_int_op(n_client_cells, OP_EQ, 2);
  tt_int_op(n_relay_cells, OP_EQ, 2);

  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_us,
            OP_NE, 0);
  tt_int_op(relay_side->padding_info[0]->padding_scheduled_at_us,
            OP_EQ, 0);
  event_base_loop(tor_libevent_get_base(), 0);
  tt_int_op(n_client_cells, OP_EQ, 3);
  tt_int_op(n_relay_cells, OP_EQ, 2);

  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_us,
            OP_EQ, 0);
  tt_int_op(relay_side->padding_info[0]->padding_scheduled_at_us,
            OP_NE, 0);
  event_base_loop(tor_libevent_get_base(), 0);
  tt_int_op(n_client_cells, OP_EQ, 3);
  tt_int_op(n_relay_cells, OP_EQ, 3);

  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_us,
            OP_NE, 0);
  tt_int_op(relay_side->padding_info[0]->padding_scheduled_at_us,
            OP_EQ, 0);
  event_base_loop(tor_libevent_get_base(), 0);
  tt_int_op(n_client_cells, OP_EQ, 4);
  tt_int_op(n_relay_cells, OP_EQ, 3);

  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_us,
            OP_EQ, 0);
  tt_int_op(relay_side->padding_info[0]->padding_scheduled_at_us,
            OP_NE, 0);
  event_base_loop(tor_libevent_get_base(), 0);
  tt_int_op(n_client_cells, OP_EQ, 4);
  tt_int_op(n_relay_cells, OP_EQ, 4);

  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_us,
            OP_NE, 0);
  tt_int_op(relay_side->padding_info[0]->padding_scheduled_at_us,
            OP_EQ, 0);
  event_base_loop(tor_libevent_get_base(), 0);
  tt_int_op(n_client_cells, OP_EQ, 5);
  tt_int_op(n_relay_cells, OP_EQ, 4);

  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_us,
            OP_EQ, 0);
  tt_int_op(relay_side->padding_info[0]->padding_scheduled_at_us,
            OP_NE, 0);
  event_base_loop(tor_libevent_get_base(), 0);
  tt_int_op(n_client_cells, OP_EQ, 5);
  tt_int_op(n_relay_cells, OP_EQ, 5);

  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_us,
            OP_NE, 0);
  tt_int_op(relay_side->padding_info[0]->padding_scheduled_at_us,
            OP_EQ, 0);
  event_base_loop(tor_libevent_get_base(), 0);
  tt_int_op(n_client_cells, OP_EQ, 6);
  tt_int_op(n_relay_cells, OP_EQ, 5);

  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_us,
            OP_EQ, 0);
  tt_int_op(relay_side->padding_info[0]->padding_scheduled_at_us,
            OP_NE, 0);
  event_base_loop(tor_libevent_get_base(), 0);
  tt_int_op(n_client_cells, OP_EQ, 6);
  tt_int_op(n_relay_cells, OP_EQ, 6);

  tt_int_op(client_side->padding_info[0]->current_state,
            OP_EQ, CIRCPAD_STATE_END);
  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_us,
            OP_EQ, 0);
  tt_int_op(relay_side->padding_info[0]->current_state,
            OP_EQ, CIRCPAD_STATE_GAP);
  tt_int_op(relay_side->padding_info[0]->padding_scheduled_at_us,
            OP_EQ, 0);

  /* Simulate application traffic */
  circpad_cell_event_nonpadding_sent((circuit_t*)client_side);
  circpad_cell_event_nonpadding_received((circuit_t*)relay_side);
  circpad_cell_event_nonpadding_sent((circuit_t*)relay_side);
  circpad_cell_event_nonpadding_received((circuit_t*)client_side);

  tt_ptr_op(client_side->padding_info[0], OP_EQ, NULL);
  tt_ptr_op(client_side->padding_machine[0], OP_EQ, NULL);

  tt_ptr_op(relay_side->padding_info[0], OP_EQ, NULL);
  tt_ptr_op(relay_side->padding_machine[0], OP_EQ, NULL);

  // FIXME: Test refill
  // FIXME: Test timer cancellation

 done:
  free_fake_origin_circuit(TO_ORIGIN_CIRCUIT(client_side));
  free_fake_orcirc(relay_side);

  circuitmux_detach_all_circuits(dummy_channel.cmux, NULL);
  circuitmux_free(dummy_channel.cmux);
  timers_shutdown();
  UNMOCK(circuit_package_relay_cell);
  UNMOCK(circuitmux_attach_circuit);

  return;
}

#define TEST_CIRCUITPADDING(name, flags) \
    { #name, test_##name, (flags), NULL, NULL }

struct testcase_t circuitpadding_tests[] = {
  //TEST_CIRCUITPADDING(circuitpadding_circuitsetup_machine, 0),
  TEST_CIRCUITPADDING(circuitpadding_tokens, TT_FORK),
  TEST_CIRCUITPADDING(circuitpadding_negotiation, TT_FORK),
  TEST_CIRCUITPADDING(circuitpadding_circuitsetup_machine, TT_FORK),
  TEST_CIRCUITPADDING(circuitpadding_rtt, TT_FORK),
  END_OF_TESTCASES
};

