#define TOR_CHANNEL_INTERNAL_
#define TOR_TIMERS_PRIVATE
#define CIRCUITPADDING_PRIVATE
#define NETWORKSTATUS_PRIVATE

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
#include "feature/nodelist/networkstatus_st.h"
#include "feature/nodelist/node_st.h"
#include "core/or/cell_st.h"
#include "core/or/crypt_path_st.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"

extern smartlist_t *connection_array;

#define USEC_PER_SEC (1000000)
#define NSEC_PER_USEC (1000)
#define NSEC_PER_MSEC (1000*1000)

circid_t get_unique_circ_id_by_chan(channel_t *chan);
void helper_create_basic_machine(void);

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

static int64_t curr_mocked_time;

static node_t padding_node;
static node_t non_padding_node;

static channel_t dummy_channel;
static circpad_machine_t circ_client_machine;

static void
timers_advance_and_run(int64_t msec_update)
{
  curr_mocked_time += msec_update*NSEC_PER_MSEC;
  monotime_coarse_set_mock_time_nsec(curr_mocked_time);
  monotime_set_mock_time_nsec(curr_mocked_time);
  timers_run_pending();
}

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
  timers_advance_and_run(1);
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
  relay_side = TO_CIRCUIT(new_fake_orcirc(&dummy_channel, &dummy_channel));
  client_side = TO_CIRCUIT(origin_circuit_new());
  relay_side->purpose = CIRCUIT_PURPOSE_OR;
  client_side->purpose = CIRCUIT_PURPOSE_C_GENERAL;

  monotime_init();
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(1*NSEC_PER_USEC);
  monotime_coarse_set_mock_time_nsec(1*NSEC_PER_USEC);
  curr_mocked_time = 1*NSEC_PER_USEC;

  timers_initialize();
  circpad_machines_init();
  helper_create_basic_machine();

  MOCK(circuit_package_relay_cell,
       circuit_package_relay_cell_mock);

  client_side->padding_machine[0] = &circ_client_machine;
  client_side->padding_info[0] = circpad_circuit_machineinfo_new(client_side,
                                                                 0);

  relay_side->padding_machine[0] = &circ_client_machine;
  relay_side->padding_info[0] = circpad_circuit_machineinfo_new(client_side,0);

  /* Test 1: Test measuring RTT */
  circpad_cell_event_nonpadding_received((circuit_t*)relay_side);
  tt_int_op(relay_side->padding_info[0]->last_received_time_usec, OP_NE, 0);

  timers_advance_and_run(20);

  circpad_cell_event_nonpadding_sent((circuit_t*)relay_side);
  tt_int_op(relay_side->padding_info[0]->last_received_time_usec, OP_EQ, 0);

  tt_int_op(relay_side->padding_info[0]->rtt_estimate_usec, OP_GE, 19000);
  tt_int_op(relay_side->padding_info[0]->rtt_estimate_usec, OP_LE, 30000);
  tt_int_op(circpad_histogram_bin_to_usec(relay_side->padding_info[0], 0),
            OP_EQ,
            relay_side->padding_info[0]->rtt_estimate_usec+
            circpad_machine_current_state(
             relay_side->padding_info[0])->start_usec);

  circpad_cell_event_nonpadding_received((circuit_t*)relay_side);
  circpad_cell_event_nonpadding_received((circuit_t*)relay_side);
  tt_int_op(relay_side->padding_info[0]->last_received_time_usec, OP_NE, 0);
  timers_advance_and_run(20);
  circpad_cell_event_nonpadding_sent((circuit_t*)relay_side);
  circpad_cell_event_nonpadding_sent((circuit_t*)relay_side);
  tt_int_op(relay_side->padding_info[0]->last_received_time_usec, OP_EQ, 0);

  tt_int_op(relay_side->padding_info[0]->rtt_estimate_usec, OP_GE, 20000);
  tt_int_op(relay_side->padding_info[0]->rtt_estimate_usec, OP_LE, 21000);
  tt_int_op(circpad_histogram_bin_to_usec(relay_side->padding_info[0], 0),
            OP_EQ,
            relay_side->padding_info[0]->rtt_estimate_usec+
            circpad_machine_current_state(
             relay_side->padding_info[0])->start_usec);

  /* Test 2: Termination of RTT measurement (from the previous test) */
  tt_int_op(relay_side->padding_info[0]->stop_rtt_update, OP_EQ, 1);
  rtt_estimate = relay_side->padding_info[0]->rtt_estimate_usec;

  circpad_cell_event_nonpadding_received((circuit_t*)relay_side);
  timers_advance_and_run(4);
  circpad_cell_event_nonpadding_sent((circuit_t*)relay_side);

  tt_int_op(relay_side->padding_info[0]->rtt_estimate_usec, OP_EQ,
            rtt_estimate);
  tt_int_op(relay_side->padding_info[0]->last_received_time_usec, OP_EQ, 0);
  tt_int_op(relay_side->padding_info[0]->stop_rtt_update, OP_EQ, 1);
  tt_int_op(circpad_histogram_bin_to_usec(relay_side->padding_info[0], 0),
            OP_EQ,
            relay_side->padding_info[0]->rtt_estimate_usec+
            circpad_machine_current_state(
             relay_side->padding_info[0])->start_usec);

  /* Test 3: Make sure client side machine properly ignores RTT */
  circpad_cell_event_nonpadding_received((circuit_t*)client_side);
  tt_int_op(client_side->padding_info[0]->last_received_time_usec, OP_EQ, 0);

  timers_advance_and_run(20);
  circpad_cell_event_nonpadding_sent((circuit_t*)client_side);
  tt_int_op(client_side->padding_info[0]->last_received_time_usec, OP_EQ, 0);

  tt_int_op(client_side->padding_info[0]->rtt_estimate_usec, OP_EQ, 0);
  tt_int_op(circpad_histogram_bin_to_usec(client_side->padding_info[0], 0),
            OP_NE, client_side->padding_info[0]->rtt_estimate_usec);
  tt_int_op(circpad_histogram_bin_to_usec(client_side->padding_info[0], 0),
            OP_EQ,
            circpad_machine_current_state(
                client_side->padding_info[0])->start_usec);
 done:
  free_fake_orcirc(relay_side);
  circuitmux_detach_all_circuits(dummy_channel.cmux, NULL);
  circuitmux_free(dummy_channel.cmux);
  timers_shutdown();
  monotime_disable_test_mocking();
  UNMOCK(circuit_package_relay_cell);
  UNMOCK(circuitmux_attach_circuit);
  tor_free(circ_client_machine.states);

  return;
}

void
helper_create_basic_machine(void)
{
  /* Start, burst */
  circpad_machine_states_init(&circ_client_machine, 2);

  circ_client_machine.states[CIRCPAD_STATE_START].
      next_state[CIRCPAD_EVENT_NONPADDING_RECV] = CIRCPAD_STATE_BURST;

  circ_client_machine.states[CIRCPAD_STATE_BURST].
      next_state[CIRCPAD_EVENT_PADDING_RECV] = CIRCPAD_STATE_BURST;
  circ_client_machine.states[CIRCPAD_STATE_BURST].
      next_state[CIRCPAD_EVENT_NONPADDING_RECV] = CIRCPAD_STATE_BURST;

  circ_client_machine.states[CIRCPAD_STATE_BURST].
      next_state[CIRCPAD_EVENT_NONPADDING_SENT] = CIRCPAD_STATE_CANCEL;

  // FIXME: Is this what we want?
  circ_client_machine.states[CIRCPAD_STATE_BURST].token_removal =
      CIRCPAD_TOKEN_REMOVAL_HIGHER;

  // FIXME: Tune this histogram
  circ_client_machine.states[CIRCPAD_STATE_BURST].histogram_len = 5;
  circ_client_machine.states[CIRCPAD_STATE_BURST].start_usec = 500;
  circ_client_machine.states[CIRCPAD_STATE_BURST].range_usec = 1000000;
  circ_client_machine.states[CIRCPAD_STATE_BURST].histogram[0] = 1;
  circ_client_machine.states[CIRCPAD_STATE_BURST].histogram[1] = 0;
  circ_client_machine.states[CIRCPAD_STATE_BURST].histogram[2] = 2;
  circ_client_machine.states[CIRCPAD_STATE_BURST].histogram[3] = 2;
  circ_client_machine.states[CIRCPAD_STATE_BURST].histogram[4] = 2;
  circ_client_machine.states[CIRCPAD_STATE_BURST].histogram_total_tokens = 7;
  circ_client_machine.states[CIRCPAD_STATE_BURST].use_rtt_estimate = 1;

  return;
}

#define BIG_HISTOGRAM_LEN 10

/** Setup a machine with a big histogram */
static void
helper_create_machine_with_big_histogram(circpad_removal_t removal_strategy)
{
  const int tokens_per_bin = 2;

  /* Start, burst */
  circpad_machine_states_init(&circ_client_machine, 2);

  circpad_state_t *burst_state =
    &circ_client_machine.states[CIRCPAD_STATE_BURST];

  circ_client_machine.states[CIRCPAD_STATE_START].
    next_state[CIRCPAD_EVENT_NONPADDING_RECV] = CIRCPAD_STATE_BURST;

  burst_state->next_state[CIRCPAD_EVENT_PADDING_RECV] = CIRCPAD_STATE_BURST;
  burst_state->next_state[CIRCPAD_EVENT_NONPADDING_RECV] =CIRCPAD_STATE_BURST;

  burst_state->next_state[CIRCPAD_EVENT_NONPADDING_SENT] =CIRCPAD_STATE_CANCEL;

  burst_state->token_removal = CIRCPAD_TOKEN_REMOVAL_HIGHER;

  burst_state->histogram_len = BIG_HISTOGRAM_LEN;
  burst_state->start_usec = 0;
  burst_state->range_usec = 1000;

  int n_tokens = 0;
  for (int i = 0; i < BIG_HISTOGRAM_LEN ; i++) {
    burst_state->histogram[i] = tokens_per_bin;
    n_tokens += 2;
  }

  burst_state->histogram_total_tokens = n_tokens;
  burst_state->use_rtt_estimate = 1;
  burst_state->token_removal = removal_strategy;
}

static circpad_decision_t
circpad_machine_schedule_padding_mock(circpad_machineinfo_t *mi)
{
  (void)mi;
  return 0;
}

static uint64_t
mock_monotime_absolute_usec(void)
{
  return 100;
}

/** Test closest token removal strategy with usec  */
static void
test_circuitpadding_closest_token_removal_usec(void *arg)
{
  circpad_machineinfo_t *mi;
  (void)arg;

  /* Mock it up */
  MOCK(monotime_absolute_usec, mock_monotime_absolute_usec);
  MOCK(circpad_machine_schedule_padding,circpad_machine_schedule_padding_mock);

  /* Setup test environment (time etc.) */
  client_side = (circuit_t *)origin_circuit_new();
  client_side->purpose = CIRCUIT_PURPOSE_C_GENERAL;
  monotime_enable_test_mocking();

  /* Create test machine */
  helper_create_machine_with_big_histogram(CIRCPAD_TOKEN_REMOVAL_CLOSEST_USEC);
  client_side->padding_machine[0] = &circ_client_machine;
  client_side->padding_info[0] =
    circpad_circuit_machineinfo_new(client_side, 0);

  /* move the machine to the right state */
  circpad_cell_event_nonpadding_received((circuit_t*)client_side);
  tt_int_op(client_side->padding_info[0]->current_state, OP_EQ,
            CIRCPAD_STATE_BURST);

  /* Get the machine and setup tokens */
  mi = client_side->padding_info[0];
  tt_assert(mi);

  /*************************************************************************/

  uint64_t current_time = monotime_absolute_usec();

  /* Test left boundaries of each histogram bin: */
  const circpad_delay_t bin_left_bounds[] =
    {0, 1, 7, 15, 31, 62, 125, 250, 500, CIRCPAD_DELAY_INFINITE};
  for (int i = 0; i < BIG_HISTOGRAM_LEN ; i++) {
    tt_uint_op(bin_left_bounds[i], OP_EQ,
               circpad_histogram_bin_to_usec(mi, i));
  }

  /* XXX we want to test remove_token_exact and
     circpad_machine_remove_closest_token() with usec */

  /* Check that all bins have two tokens right now */
  for (int i = 0; i < BIG_HISTOGRAM_LEN ; i++) {
    tt_int_op(mi->histogram[i], OP_EQ, 2);
  }

  /* This is the right order to remove tokens from this histogram. That is, we
   * first remove tokens from the 4th bin since 57 usec is nearest to the 4th
   * bin midpoint (31 + (62-31)/2 == 46). Then we remove from the 3rd bin for
   * the same reason, then from the 5th, etc. */
  const int bin_removal_order[] = {4, 3, 5, 2, 1, 0, 6, 7, 8, 9};

  /* Remove all tokens from all bins apart from the infinity bin */
  for (int i = 0; i < BIG_HISTOGRAM_LEN-1 ; i++) {
    int bin_to_remove = bin_removal_order[i];
    log_debug(LD_GENERAL, "Testing that %d attempt removes %d bin",
              i, bin_to_remove);

    tt_int_op(mi->histogram[bin_to_remove], OP_EQ, 2);

    mi->padding_scheduled_at_usec = current_time - 57;
    circpad_machine_remove_token(mi);

    tt_int_op(mi->histogram[bin_to_remove], OP_EQ, 1);

    mi->padding_scheduled_at_usec = current_time - 57;
    circpad_machine_remove_token(mi);

    /* Test that we cleaned out this bin. Don't do this in the case of the last
       bin since the tokens will get refilled */
    if (i != BIG_HISTOGRAM_LEN - 2) {
      tt_int_op(mi->histogram[bin_to_remove], OP_EQ, 0);
    }
  }

  /* Check that all bins have been refilled */
  for (int i = 0; i < BIG_HISTOGRAM_LEN ; i++) {
    tt_int_op(mi->histogram[i], OP_EQ, 2);
  }

 done:
  free_fake_origin_circuit(TO_ORIGIN_CIRCUIT(client_side));
  monotime_disable_test_mocking();
  tor_free(circ_client_machine.states);
}

/** Test closest token removal strategy with usec  */
static void
test_circuitpadding_token_removal_exact(void *arg)
{
  circpad_machineinfo_t *mi;
  (void)arg;

  /* Mock it up */
  MOCK(monotime_absolute_usec, mock_monotime_absolute_usec);
  MOCK(circpad_machine_schedule_padding,circpad_machine_schedule_padding_mock);

  /* Setup test environment (time etc.) */
  client_side = (circuit_t *)origin_circuit_new();
  client_side->purpose = CIRCUIT_PURPOSE_C_GENERAL;
  monotime_enable_test_mocking();

  /* Create test machine */
  helper_create_machine_with_big_histogram(CIRCPAD_TOKEN_REMOVAL_EXACT);
  client_side->padding_machine[0] = &circ_client_machine;
  client_side->padding_info[0] =
    circpad_circuit_machineinfo_new(client_side, 0);

  /* move the machine to the right state */
  circpad_cell_event_nonpadding_received((circuit_t*)client_side);
  tt_int_op(client_side->padding_info[0]->current_state, OP_EQ,
            CIRCPAD_STATE_BURST);

  /* Get the machine and setup tokens */
  mi = client_side->padding_info[0];
  tt_assert(mi);

  /**********************************************************************/
  uint64_t current_time = monotime_absolute_usec();

  /* Ensure that we will clear out bin #4 with this usec */
  mi->padding_scheduled_at_usec = current_time - 57;
  tt_int_op(mi->histogram[4], OP_EQ, 2);
  circpad_machine_remove_token(mi);
  mi->padding_scheduled_at_usec = current_time - 57;
  tt_int_op(mi->histogram[4], OP_EQ, 1);
  circpad_machine_remove_token(mi);
  tt_int_op(mi->histogram[4], OP_EQ, 0);

  /* Ensure that we will not remove any other tokens even tho we try to, since
   * this is what the exact strategy dictates */
  mi->padding_scheduled_at_usec = current_time - 57;
  circpad_machine_remove_token(mi);
  for (int i = 0; i < BIG_HISTOGRAM_LEN ; i++) {
    if (i != 4) {
      tt_int_op(mi->histogram[i], OP_EQ, 2);
    }
  }

 done:
  free_fake_origin_circuit(TO_ORIGIN_CIRCUIT(client_side));
  monotime_disable_test_mocking();
  tor_free(circ_client_machine.states);
}

#undef BIG_HISTOGRAM_LEN

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
  client_side = TO_CIRCUIT(origin_circuit_new());
  client_side->purpose = CIRCUIT_PURPOSE_C_GENERAL;

  monotime_init();
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(1*NSEC_PER_USEC);
  monotime_coarse_set_mock_time_nsec(1*NSEC_PER_USEC);
  curr_mocked_time = 1*NSEC_PER_USEC;

  timers_initialize();

  helper_create_basic_machine();
  client_side->padding_machine[0] = &circ_client_machine;
  client_side->padding_info[0] = circpad_circuit_machineinfo_new(client_side,
                                                                 0);

  mi = client_side->padding_info[0];

  // Pretend a non-padding cell was sent
  // XXX: This messes us up.. Padding gets scheduled..
  circpad_cell_event_nonpadding_sent((circuit_t*)client_side);
  circpad_cell_event_nonpadding_received((circuit_t*)client_side);
  /* We have to save the infinity bin because one inf delay
   * could have been chosen when we transition to burst */
  circpad_hist_token_t inf_bin = mi->histogram[4];

  tt_int_op(client_side->padding_info[0]->current_state, OP_EQ,
            CIRCPAD_STATE_BURST);

  state = circpad_machine_current_state(client_side->padding_info[0]);

  // Test 0: convert bin->usec->bin
  // Bin 0+1 have different semantics
  for (int bin = 0; bin < 2; bin++) {
    circpad_delay_t usec =
        circpad_histogram_bin_to_usec(client_side->padding_info[0], bin);
    int bin2 = circpad_histogram_usec_to_bin(client_side->padding_info[0],
                                             usec);
    tt_int_op(bin, OP_EQ, bin2);
  }
  for (int bin = 2; bin < state->histogram_len-1; bin++) {
    circpad_delay_t usec =
        circpad_histogram_bin_to_usec(client_side->padding_info[0], bin);
    int bin2 = circpad_histogram_usec_to_bin(client_side->padding_info[0],
                                             usec);
    tt_int_op(bin, OP_EQ, bin2);
    /* Verify we round down */
    bin2 = circpad_histogram_usec_to_bin(client_side->padding_info[0],
                                             usec+3);
    tt_int_op(bin, OP_EQ, bin2);

    bin2 = circpad_histogram_usec_to_bin(client_side->padding_info[0],
                                             usec-1);
    tt_int_op(bin, OP_EQ, bin2+1);
  }

  // Test 1: converting usec->bin->usec->bin
  // Bin 0+1 have different semantics.
  for (circpad_delay_t i = 0; i <= state->start_usec+1; i++) {
    int bin = circpad_histogram_usec_to_bin(client_side->padding_info[0],
                                            i);
    circpad_delay_t usec =
        circpad_histogram_bin_to_usec(client_side->padding_info[0], bin);
    int bin2 = circpad_histogram_usec_to_bin(client_side->padding_info[0],
                                             usec);
    tt_int_op(bin, OP_EQ, bin2);
    tt_int_op(i, OP_LE, usec);
  }
  for (circpad_delay_t i = state->start_usec+1;
           i <= state->start_usec + state->range_usec; i++) {
    int bin = circpad_histogram_usec_to_bin(client_side->padding_info[0],
                                            i);
    circpad_delay_t usec =
        circpad_histogram_bin_to_usec(client_side->padding_info[0], bin);
    int bin2 = circpad_histogram_usec_to_bin(client_side->padding_info[0],
                                             usec);
    tt_int_op(bin, OP_EQ, bin2);
    tt_int_op(i, OP_GE, usec);
  }

  /* 2.a. Normal higher bin */
  {
    tt_int_op(mi->histogram[2], OP_EQ, 2);
    tt_int_op(mi->histogram[3], OP_EQ, 2);
    circpad_machine_remove_higher_token(mi,
         circpad_histogram_bin_to_usec(mi, 2)+1);
    tt_int_op(mi->histogram[3], OP_EQ, 2);
    tt_int_op(mi->histogram[2], OP_EQ, 1);

    circpad_machine_remove_higher_token(mi,
         circpad_histogram_bin_to_usec(mi, 2)+1);
    tt_int_op(mi->histogram[2], OP_EQ, 0);

    tt_int_op(mi->histogram[3], OP_EQ, 2);
    circpad_machine_remove_higher_token(mi,
         circpad_histogram_bin_to_usec(mi, 2)+1);
    circpad_machine_remove_higher_token(mi,
         circpad_histogram_bin_to_usec(mi, 2)+1);
    tt_int_op(mi->histogram[3], OP_EQ, 0);
    circpad_machine_remove_higher_token(mi,
         circpad_histogram_bin_to_usec(mi, 2)+1);
    tt_int_op(mi->histogram[3], OP_EQ, 0);
  }

  /* 2.b. Higher Infinity bin */
  {
    tt_int_op(mi->histogram[4], OP_EQ, inf_bin);
    circpad_machine_remove_higher_token(mi,
         circpad_histogram_bin_to_usec(mi, 2)+1);
    tt_int_op(mi->histogram[4], OP_EQ, inf_bin);

    /* Test past the infinity bin */
    circpad_machine_remove_higher_token(mi,
         circpad_histogram_bin_to_usec(mi, 5)+1000000);

    tt_int_op(mi->histogram[4], OP_EQ, inf_bin);
  }

  /* 2.c. Bin 0 */
  {
    tt_int_op(mi->histogram[0], OP_EQ, 1);
    circpad_machine_remove_higher_token(mi,
         state->start_usec/2);
    tt_int_op(mi->histogram[0], OP_EQ, 0);
  }

  /* Drain the infinity bin and cause a refill */
  while (inf_bin != 0) {
    tt_int_op(mi->histogram[4], OP_EQ, inf_bin);
    circpad_cell_event_nonpadding_received((circuit_t*)client_side);
    inf_bin--;
  }

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
  monotime_disable_test_mocking();
  tor_free(circ_client_machine.states);
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

  client_side = TO_CIRCUIT(origin_circuit_new());
  dummy_channel.cmux = circuitmux_alloc();
  relay_side = TO_CIRCUIT(new_fake_orcirc(&dummy_channel, &dummy_channel));

  relay_side->purpose = CIRCUIT_PURPOSE_OR;
  client_side->purpose = CIRCUIT_PURPOSE_C_GENERAL;
  nodes_init();

  monotime_init();
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(1*NSEC_PER_USEC);
  monotime_coarse_set_mock_time_nsec(1*NSEC_PER_USEC);
  curr_mocked_time = 1*NSEC_PER_USEC;

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

  client_side = TO_CIRCUIT(origin_circuit_new());
  relay_side = TO_CIRCUIT(new_fake_orcirc(&dummy_channel, &dummy_channel));
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
  monotime_disable_test_mocking();
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

  // Advance time a tiny bit so we can calculate an RTT
  curr_mocked_time += 10 * NSEC_PER_MSEC;
  monotime_coarse_set_mock_time_nsec(curr_mocked_time);
  monotime_set_mock_time_nsec(curr_mocked_time);

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
  client_side = TO_CIRCUIT(origin_circuit_new());
  relay_side = TO_CIRCUIT(new_fake_orcirc(&dummy_channel, &dummy_channel));

  relay_side->purpose = CIRCUIT_PURPOSE_OR;
  client_side->purpose = CIRCUIT_PURPOSE_C_GENERAL;

  nodes_init();

  monotime_init();
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(1*NSEC_PER_USEC);
  monotime_coarse_set_mock_time_nsec(1*NSEC_PER_USEC);
  curr_mocked_time = 1*NSEC_PER_USEC;

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

  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_usec,
            OP_NE, 0);
  tt_int_op(relay_side->padding_info[0]->is_padding_timer_scheduled,
            OP_EQ, 0);
  timers_advance_and_run(2000);
  tt_int_op(n_client_cells, OP_EQ, 2);
  tt_int_op(n_relay_cells, OP_EQ, 1);

  tt_int_op(relay_side->padding_info[0]->current_state, OP_EQ,
              CIRCPAD_STATE_GAP);

  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_usec,
            OP_EQ, 0);
  tt_int_op(relay_side->padding_info[0]->padding_scheduled_at_usec,
            OP_NE, 0);
  timers_advance_and_run(5000);
  tt_int_op(n_client_cells, OP_EQ, 2);
  tt_int_op(n_relay_cells, OP_EQ, 2);

  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_usec,
            OP_NE, 0);
  tt_int_op(relay_side->padding_info[0]->padding_scheduled_at_usec,
            OP_EQ, 0);
  timers_advance_and_run(2000);
  tt_int_op(n_client_cells, OP_EQ, 3);
  tt_int_op(n_relay_cells, OP_EQ, 2);

  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_usec,
            OP_EQ, 0);
  tt_int_op(relay_side->padding_info[0]->padding_scheduled_at_usec,
            OP_NE, 0);
  timers_advance_and_run(5000);
  tt_int_op(n_client_cells, OP_EQ, 3);
  tt_int_op(n_relay_cells, OP_EQ, 3);

  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_usec,
            OP_NE, 0);
  tt_int_op(relay_side->padding_info[0]->padding_scheduled_at_usec,
            OP_EQ, 0);
  timers_advance_and_run(2000);
  tt_int_op(n_client_cells, OP_EQ, 4);
  tt_int_op(n_relay_cells, OP_EQ, 3);

  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_usec,
            OP_EQ, 0);
  tt_int_op(relay_side->padding_info[0]->padding_scheduled_at_usec,
            OP_NE, 0);
  timers_advance_and_run(5000);
  tt_int_op(n_client_cells, OP_EQ, 4);
  tt_int_op(n_relay_cells, OP_EQ, 4);

  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_usec,
            OP_NE, 0);
  tt_int_op(relay_side->padding_info[0]->padding_scheduled_at_usec,
            OP_EQ, 0);
  timers_advance_and_run(2000);
  tt_int_op(n_client_cells, OP_EQ, 5);
  tt_int_op(n_relay_cells, OP_EQ, 4);

  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_usec,
            OP_EQ, 0);
  tt_int_op(relay_side->padding_info[0]->padding_scheduled_at_usec,
            OP_NE, 0);
  timers_advance_and_run(5000);
  tt_int_op(n_client_cells, OP_EQ, 5);
  tt_int_op(n_relay_cells, OP_EQ, 5);

  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_usec,
            OP_NE, 0);
  tt_int_op(relay_side->padding_info[0]->padding_scheduled_at_usec,
            OP_EQ, 0);
  timers_advance_and_run(2000);
  tt_int_op(n_client_cells, OP_EQ, 6);
  tt_int_op(n_relay_cells, OP_EQ, 5);

  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_usec,
            OP_EQ, 0);
  tt_int_op(relay_side->padding_info[0]->padding_scheduled_at_usec,
            OP_NE, 0);
  timers_advance_and_run(5000);
  tt_int_op(n_client_cells, OP_EQ, 6);
  tt_int_op(n_relay_cells, OP_EQ, 6);

  tt_int_op(client_side->padding_info[0]->current_state,
            OP_EQ, CIRCPAD_STATE_END);
  tt_int_op(client_side->padding_info[0]->padding_scheduled_at_usec,
            OP_EQ, 0);
  tt_int_op(relay_side->padding_info[0]->current_state,
            OP_EQ, CIRCPAD_STATE_GAP);
  tt_int_op(relay_side->padding_info[0]->padding_scheduled_at_usec,
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
  monotime_disable_test_mocking();
  UNMOCK(circuit_package_relay_cell);
  UNMOCK(circuitmux_attach_circuit);

  return;
}

/** Helper function: Initializes a padding machine where every state uses the
 *  uniform probability distribution.  */
static void
helper_circpad_circ_distribution_machine_setup(double min, double max)
{
  circpad_machine_states_init(&circ_client_machine, 6);

  circpad_state_t *zero_st = &circ_client_machine.states[0];
  zero_st->next_state[CIRCPAD_EVENT_NONPADDING_RECV] = 1;
  zero_st->iat_dist.type = CIRCPAD_DIST_UNIFORM;
  zero_st->iat_dist.param1 = min;
  zero_st->iat_dist.param2 = max;
  zero_st->range_usec = 500; /* max delay */

  circpad_state_t *first_st = &circ_client_machine.states[1];
  first_st->next_state[CIRCPAD_EVENT_NONPADDING_RECV] = 2;
  first_st->iat_dist.type = CIRCPAD_DIST_UNIFORM;
  first_st->iat_dist.param1 = min;
  first_st->iat_dist.param2 = max;
  first_st->range_usec = 500; /* max delay */

  circpad_state_t *second_st = &circ_client_machine.states[2];
  second_st->next_state[CIRCPAD_EVENT_NONPADDING_RECV] = 3;
  second_st->iat_dist.type = CIRCPAD_DIST_UNIFORM;
  second_st->iat_dist.param1 = min;
  second_st->iat_dist.param2 = max;
  second_st->range_usec = 500; /* max delay */

  circpad_state_t *third_st = &circ_client_machine.states[3];
  third_st->next_state[CIRCPAD_EVENT_NONPADDING_RECV] = 4;
  third_st->iat_dist.type = CIRCPAD_DIST_UNIFORM;
  third_st->iat_dist.param1 = min;
  third_st->iat_dist.param2 = max;
  third_st->range_usec = 500; /* max delay */

  circpad_state_t *fourth_st = &circ_client_machine.states[4];
  fourth_st->next_state[CIRCPAD_EVENT_NONPADDING_RECV] = 5;
  fourth_st->iat_dist.type = CIRCPAD_DIST_UNIFORM;
  fourth_st->iat_dist.param1 = min;
  fourth_st->iat_dist.param2 = max;
  fourth_st->range_usec = 500; /* max delay */

  circpad_state_t *fifth_st = &circ_client_machine.states[5];
  fifth_st->next_state[CIRCPAD_EVENT_NONPADDING_RECV] = 6;
  fifth_st->iat_dist.type = CIRCPAD_DIST_UNIFORM;
  fifth_st->iat_dist.param1 = min;
  fifth_st->iat_dist.param2 = max;
  fifth_st->range_usec = 500; /* max delay */
}

/** Simple test that the padding delays sampled from a uniform distribution
 *  actually faill within the uniform distribution range. */
/* TODO: Upgrade this test so that each state tests a different prob
 * distribution */
static void
test_circuitpadding_sample_distribution(void *arg)
{
  circpad_machineinfo_t *mi;
  int n_samples;
  int n_states;

  (void) arg;

  /* mock this function so that we dont actually schedule any padding */
  MOCK(circpad_machine_schedule_padding,
       circpad_machine_schedule_padding_mock);

  /* Initialize a machine with multiple probability distributions that should
   * return values between 0 and 5 */
  circpad_machines_init();
  helper_circpad_circ_distribution_machine_setup(0, 10);

  /* Initialize machine and circuits */
  client_side = TO_CIRCUIT(origin_circuit_new());
  client_side->purpose = CIRCUIT_PURPOSE_C_GENERAL;
  client_side->padding_machine[0] = &circ_client_machine;
  client_side->padding_info[0] =
    circpad_circuit_machineinfo_new(client_side, 0);
  mi = client_side->padding_info[0];

  /* For every state, sample a bunch of values from the distribution and ensure
   * they fall within range. */
  for (n_states = 0 ; n_states < 5; n_states++) {
    /* Make sure we in the right state */
    tt_int_op(client_side->padding_info[0]->current_state, OP_EQ, n_states);

    for (n_samples = 0; n_samples < 100; n_samples++) {
      circpad_delay_t delay = circpad_machine_sample_delay(mi);
      tt_int_op(delay, OP_GE, 0);
      tt_int_op(delay, OP_LE, 10);
    }

    /* send a non-padding cell to move to the next machine state */
    circpad_cell_event_nonpadding_received((circuit_t*)client_side);
  }

 done:
  free_fake_origin_circuit(TO_ORIGIN_CIRCUIT(client_side));
  UNMOCK(circpad_machine_schedule_padding);
}

static circpad_decision_t
circpad_machine_transition_mock(circpad_machineinfo_t *mi,
                                circpad_event_t event)
{
  (void) mi;
  (void) event;

  return CIRCPAD_STATE_UNCHANGED;
}

/* Test per-machine padding rate limits */
static void
test_circuitpadding_machine_rate_limiting(void *arg)
{
  (void) arg;
  bool retval;
  circpad_machineinfo_t *mi;
  int i;

  /* Ignore machine transitions for the purposes of this function, we only
   * really care about padding counts */
  MOCK(circpad_machine_transition, circpad_machine_transition_mock);

  /* Setup machine and circuits */
  client_side = TO_CIRCUIT(origin_circuit_new());
  client_side->purpose = CIRCUIT_PURPOSE_C_GENERAL;
  helper_create_basic_machine();
  client_side->padding_machine[0] = &circ_client_machine;
  client_side->padding_info[0] =
    circpad_circuit_machineinfo_new(client_side, 0);
  mi = client_side->padding_info[0];
  /* Set up the machine info so that we can get through the basic functions */
  mi->state_length = 500;

  /* First we are going to test the per-machine rate limits */
  circ_client_machine.max_padding_percent = 50;
  circ_client_machine.allowed_padding_count = 100;

  /* Check padding limit, should be fine since we haven't sent anything yet. */
  retval = circpad_machine_reached_padding_limit(mi);
  tt_int_op(retval, OP_EQ, 0);

  /* Send 99 padding cells which is below circpad_global_allowed_cells=100, so
   * the rate limit will not trigger */
  for (i=0;i<99;i++) {
    circpad_send_padding_cell_for_callback(mi);
  }
  retval = circpad_machine_reached_padding_limit(mi);
  tt_int_op(retval, OP_EQ, 0);

  /* Now send another padding cell to pass circpad_global_allowed_cells=100,
     and see that the limit will trigger */
  circpad_send_padding_cell_for_callback(mi);
  retval = circpad_machine_reached_padding_limit(mi);
  tt_int_op(retval, OP_EQ, 1);

  circpad_machine_schedule_padding(mi);

 done:
  free_fake_origin_circuit(TO_ORIGIN_CIRCUIT(client_side));
}

/* Test global padding rate limits */
static void
test_circuitpadding_global_rate_limiting(void *arg)
{
  (void) arg;
  bool retval;
  circpad_machineinfo_t *mi;
  int i;

  /* Ignore machine transitions for the purposes of this function, we only
   * really care about padding counts */
  MOCK(circpad_machine_transition, circpad_machine_transition_mock);

  /* Setup machine and circuits */
  client_side = TO_CIRCUIT(origin_circuit_new());
  client_side->purpose = CIRCUIT_PURPOSE_C_GENERAL;
  helper_create_basic_machine();
  client_side->padding_machine[0] = &circ_client_machine;
  client_side->padding_info[0] =
    circpad_circuit_machineinfo_new(client_side, 0);
  mi = client_side->padding_info[0];
  /* Set up the machine info so that we can get through the basic functions */
  mi->state_length = 500;

  /* Now test the global limits by setting up the consensus */
  networkstatus_t vote1;
  vote1.net_params = smartlist_new();
  smartlist_split_string(vote1.net_params,
         "circpad_global_allowed_cells=100 circpad_global_max_padding_pct=50",
                         NULL, 0, 0);
  /* Register global limits with the padding subsystem */
  circpad_new_consensus_params(&vote1);

  /* Check padding limit, should be fine since we haven't sent anything yet. */
  retval = circpad_machine_reached_padding_limit(mi);
  tt_int_op(retval, OP_EQ, 0);

  /* Send 99 padding cells which is below circpad_global_allowed_cells=100, so
   * the rate limit will not trigger */
  for (i=0;i<99;i++) {
    circpad_send_padding_cell_for_callback(mi);
  }
  retval = circpad_machine_reached_padding_limit(mi);
  tt_int_op(retval, OP_EQ, 0);

  /* Now send another padding cell to pass circpad_global_allowed_cells=100,
     and see that the limit will trigger */
  circpad_send_padding_cell_for_callback(mi);
  retval = circpad_machine_reached_padding_limit(mi);
  tt_int_op(retval, OP_EQ, 1);

  /* Now send 96 non-padding cells to get near the
   * circpad_global_max_padding_pct=50 limit; in particular with 96 non-padding
   * cells, the padding traffic is still 51% of total traffic so limit should
   * trigger */
  for (i=0;i<96;i++) {
    circpad_cell_event_nonpadding_sent(client_side);
  }
  retval = circpad_machine_reached_padding_limit(mi);
  tt_int_op(retval, OP_EQ, 1);

  /* Send another non-padding cell to bring the padding traffic to 50% of total
   * traffic and get past the limit */
  circpad_cell_event_nonpadding_sent(client_side);
  retval = circpad_machine_reached_padding_limit(mi);
  tt_int_op(retval, OP_EQ, 0);

 done:
  free_fake_origin_circuit(TO_ORIGIN_CIRCUIT(client_side));
  SMARTLIST_FOREACH(vote1.net_params, char *, cp, tor_free(cp));
  smartlist_free(vote1.net_params);
}

#define TEST_CIRCUITPADDING(name, flags) \
    { #name, test_##name, (flags), NULL, NULL }

struct testcase_t circuitpadding_tests[] = {
  //TEST_CIRCUITPADDING(circuitpadding_circuitsetup_machine, 0),
  TEST_CIRCUITPADDING(circuitpadding_tokens, TT_FORK),
  TEST_CIRCUITPADDING(circuitpadding_negotiation, TT_FORK),
  TEST_CIRCUITPADDING(circuitpadding_circuitsetup_machine, TT_FORK),
  TEST_CIRCUITPADDING(circuitpadding_rtt, TT_FORK),
  TEST_CIRCUITPADDING(circuitpadding_sample_distribution, TT_FORK),
  TEST_CIRCUITPADDING(circuitpadding_machine_rate_limiting, TT_FORK),
  TEST_CIRCUITPADDING(circuitpadding_global_rate_limiting, TT_FORK),
  TEST_CIRCUITPADDING(circuitpadding_closest_token_removal_usec, TT_FORK),
  TEST_CIRCUITPADDING(circuitpadding_token_removal_exact, TT_FORK),
  END_OF_TESTCASES
};

