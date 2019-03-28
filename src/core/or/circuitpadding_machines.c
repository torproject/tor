/* Copyright (c) 2019 The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitpadding_machines.c
 * \brief Circuit padding state machines
 *
 * \detail
 *
 * Introduce the various circuit padding machines that will be used by Tor
 * circuits.
 *
 * Right now this file introduces two machines that aim to hide the client-side
 * of onion service circuits against naive classifiers like the ones from the
 * "Circuit Fingerprinting Attacks: Passive Deanonymization of Tor Hidden
 * Services" paper from USENIX. By naive classifiers we mean classifiers that
 * use basic features like "circuit construction circuits" and "incoming and
 * outgoing cell counts" and "duration of activity".
 *
 * In particular, these machines aim to be lightweight and protect against
 * these basic classifiers. They don't aim to protect against more advanced
 * attacks that use deep learning or even correlate various circuit
 * construction events together. Machines that fool such advanced classifiers
 * are also possible, but they can't be so lightweight and might require more
 * WTF-PAD features. So for now we opt for the following two machines:
 *
 * Client-side introduction circuit hiding machine:
 *
 *    This machine hides client-side introduction circuits by sending padding
 *    during circuit construction and also after the circuit has opened. The
 *    circuit is kept open until all the padding has been sent, since intro
 *    circuits are usually very short lived and this act as a
 *    distinguisher. Both sides of this machine send maximum 20 padding cells
 *    from each direction (so max 40 padding cells per circuit).
 *
 * Client-side rendezvous circuit hiding machine:
 *
 *    This machine hides client-side rendezvous circuits by sending padding
 *    during circuit construction and also after the circuit has opened. Both
 *    sides of this machine send maximum 20 padding cells from each direction
 *    (so max 40 padding cells per circuit).
 *
 * TODO: An easy improvement for these machines would be to add another state
 *       to the padding machine so that we separate the circuit setup from the
 *       actual opened circuit. We want to send padding fast while in circuit
 *       setup to make sure that we detroy any circuit construction
 *       fingerprints, and then send padding slowly when the circuit is opened
 *       to pretend its fake traffic.
 *
 *       This improvement is not yet implemented both for KISS reasons, and
 *       also because to make such an improvement actually effective we would
 *       have to introduce per-state state_length, whereas now it's global to
 *       the machine (so that the different states have different randomized
 *       padding limits).
 **/

#define CIRCUITPADDING_MACHINES_PRIVATE

#include "core/or/or.h"
#include "feature/nodelist/networkstatus.h"

#include "lib/crypt_ops/crypto_rand.h"

#include "core/or/circuitlist.h"

#include "core/or/circuitpadding_machines.h"
#include "core/or/circuitpadding.h"

/* Setup the simple state machine we use for all HS padding machines */
static void
setup_state_machine_for_hiding_hs_circuits(circpad_machine_spec_t *machine)
{
  /* Two states: START, BURST (and END) */
  circpad_machine_states_init(machine, 2);

  /* START -> BURST transition upon first cell received/sent */
  machine->states[CIRCPAD_STATE_START].
    next_state[CIRCPAD_EVENT_NONPADDING_RECV] = CIRCPAD_STATE_BURST;
  machine->states[CIRCPAD_STATE_START].
    next_state[CIRCPAD_EVENT_NONPADDING_SENT] = CIRCPAD_STATE_BURST;

  /* BURST -> END transition when we finish all the tokens */
  machine->states[CIRCPAD_STATE_BURST].
      next_state[CIRCPAD_EVENT_BINS_EMPTY] = CIRCPAD_STATE_END;
  /* or when the length finishes */
  machine->states[CIRCPAD_STATE_BURST].
      next_state[CIRCPAD_EVENT_LENGTH_COUNT] = CIRCPAD_STATE_END;

  /* Keep sending DROP cells without caring of what the other end is doing */
  machine->states[CIRCPAD_STATE_BURST].
      next_state[CIRCPAD_EVENT_PADDING_SENT] = CIRCPAD_STATE_BURST;
  machine->states[CIRCPAD_STATE_BURST].
      next_state[CIRCPAD_EVENT_PADDING_RECV] = CIRCPAD_STATE_BURST;
}

/* Setup the BURST state of the machine that hides client-side intro
 * circuits. */
static void
setup_burst_state_for_hiding_intro_circuits(circpad_state_t *burst_state,
                                            bool is_client)
{
  /* Token removal strategy for BURST state */
  burst_state->token_removal = CIRCPAD_TOKEN_REMOVAL_CLOSEST;

  /* Histogram for BURST state:
   *
   * We want a machine that will send up to 20 fake cells over a reasonable
   * time frame, to obfuscate the fact that introduction circuits always send 4
   * cells both ways */

  /* Figure out the length of the BURST state so that it's randomized. See
     definition of these constants for rationale. */
  burst_state->length_dist.type = CIRCPAD_DIST_UNIFORM;
  burst_state->length_dist.param1 = is_client ?
    HS_MACHINE_PADDING_MINIMUM_CLIENT : HS_MACHINE_PADDING_MINIMUM_SERVICE;
  burst_state->length_dist.param2 = is_client ?
    HS_MACHINE_PADDING_MAXIMUM_CLIENT : HS_MACHINE_PADDING_MAXIMUM_SERVICE;

  /* We mainly care about destroying circuit construction fingerprints. Here is
   * an example intro circuit construction, where the timestamp granularity is
   * 1 millisecond:
   *
   * IP circuit relay cells:
   *  0: 11:56:59.703 -> EXTEND2
   *  1: 11:57:00.074 <- EXTENDED2
   *  2: 11:57:00.075 -> EXTEND2
   *  3: 11:57:00.243 <- EXTENDED2
   *  4: 11:57:17.406 -> EXTEND
   *  5: 11:57:17.708 <- EXTENDED
   *  6: 11:57:17.709 -> INTRODUCE1
   *  7: 11:57:17.904 <- INTRODUCE_ACK
   *
   * So with about 200 milliseconds latency between each cell, we appropriately
   * set the histogram edges to from 30 milliseconds to 100 milliseconds, to
   * account for faster connections.
   */

  /* Histogram is: (30 msecs, 100 msecs, infinity). */
  burst_state->histogram_len = 2;
  burst_state->histogram_edges[0] = 30000;
  burst_state->histogram_edges[1] = 100000;

  /* Maximum number of tokens for the BURST state */
  burst_state->histogram[0] = 1000;
  burst_state->histogram_total_tokens = 1000;
}

/* Setup the BURST state of the machine that hides client-side rend
 * circuits. If <b>is_client</b> is true, then this is the client-side part of
 * this machine, otherwise it's the service-side of this machine. */
static void
setup_burst_state_for_hiding_rend_circuits(circpad_state_t *burst_state,
                                           bool is_client)
{
  /* Token removal strategy for BURST state */
  burst_state->token_removal =
      CIRCPAD_TOKEN_REMOVAL_CLOSEST;

  /* Histogram for BURST state:
   *
   * We want a machine that will send a bunch of fake cells over a reasonable
   * time frame, to obfuscate the fact that introduction circuits always send 4
   * cells both ways */

  /* Figure out the length of the BURST state so that it's randomized. See
     definition of these constants for rationale. */
  burst_state->length_dist.type = CIRCPAD_DIST_UNIFORM;
  burst_state->length_dist.param1 = is_client ?
    HS_MACHINE_PADDING_MINIMUM_CLIENT : HS_MACHINE_PADDING_MINIMUM_SERVICE;
  burst_state->length_dist.param2 = is_client ?
    HS_MACHINE_PADDING_MAXIMUM_CLIENT : HS_MACHINE_PADDING_MAXIMUM_SERVICE;

  /* Histogram is: (30 msecs, 100 msecs, infinity).
   * See analysis above.
  */
  burst_state->histogram_len = 2;
  burst_state->histogram_edges[0] = 30000;
  burst_state->histogram_edges[1] = 100000;

  /* Maximum number of tokens for the BURST state. We control the BURST state
   * duration based on the length_dist so the token count does not really
   * matter, it just needs to be bigger than all possible lengths. */
  burst_state->histogram[0] = 1000;
  burst_state->histogram_total_tokens = 1000;
}

/** Create a client-side padding machine that aims to hide IP circuits. In
 *  particular, it keeps intro circuits alive until a bunch of fake traffic has
 *  been pushed through.
 *
 *  This aims to hide the fingerprint of client-side introduction circuits
 *  which is the fact that they are short-lived and always send 4 cells to the
 *  intro point (3 EXTEND and 1 INTRODUCE1) (section 5.1).
 */
void
circpad_machine_client_hide_intro_circuits(smartlist_t *machines_sl)
{
  circpad_machine_spec_t *client_machine
      = tor_malloc_zero(sizeof(circpad_machine_spec_t));

  client_machine->name = "client_ip_circ";

  client_machine->conditions.state_mask =
    CIRCPAD_CIRC_BUILDING|CIRCPAD_CIRC_OPENED;
  client_machine->target_hopnum = 2;

  /* This is a client machine */
  client_machine->is_origin_side = 1;

  /* For this machine we only pad in client-side introduction circuits even
   * after introduction has finished */
  client_machine->conditions.purpose_mask =
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_INTRODUCING)|
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT)|
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_INTRODUCE_ACKED);

  /* XXX Keep the circuit alive even after the introduction has been finished,
   * otherwise the short-term lifetime of the circuit will blow our cover */
  // client_machine->manage_circ_lifetime = 1;

  /* Setup states and histograms */
  setup_state_machine_for_hiding_hs_circuits(client_machine);
  setup_burst_state_for_hiding_intro_circuits(
                         &client_machine->states[CIRCPAD_STATE_BURST],
                         true);

  /* Register the machine */
  client_machine->machine_num = smartlist_len(machines_sl);
  circpad_register_padding_machine(client_machine, machines_sl);

  log_warn(LD_GENERAL,
           "Registered client intro point hiding padding machine (%u)",
           client_machine->machine_num);
}

/** Create a relay-side padding machine that aims to hide IP circuits.
 *
 *  This aims to hide the fingerprint of client-side introduction circuits
 *  which is the fact that they are short-lived and always send 4 cells to the
 *  intro point (3 EXTENDED and 1 INTRODUCE_ACK).
 */
void
circpad_machine_relay_hide_intro_circuits(smartlist_t *machines_sl)
{
  circpad_machine_spec_t *relay_machine
      = tor_malloc_zero(sizeof(circpad_machine_spec_t));

  relay_machine->name = "relay_ip_circ";

  relay_machine->conditions.state_mask =
    CIRCPAD_CIRC_BUILDING|CIRCPAD_CIRC_OPENED;
  relay_machine->target_hopnum = 2;

  /* This is a relay-side machine */
  relay_machine->is_origin_side = 0;

  /* No need to keep the circuit alive no our side, let the client control the
   * circuit lifetime */
  // relay_machine->manage_circ_lifetime = 0;

  /* Setup states and histograms */
  setup_state_machine_for_hiding_hs_circuits(relay_machine);
  setup_burst_state_for_hiding_intro_circuits(
                 &relay_machine->states[CIRCPAD_STATE_BURST],
                 false);

  /* Register the machine */
  relay_machine->machine_num = smartlist_len(machines_sl);
  circpad_register_padding_machine(relay_machine, machines_sl);

  log_warn(LD_GENERAL,
           "Registered relay intro circuit hiding padding machine (%u)",
           relay_machine->machine_num);
}

/** Create a client-side padding machine that aims to hide rendezvous circuits.
 *
 *  This aims to hide the fingerprint of client-side rendezvous circuits which
 *  is the fact that they have a unique packet sequence (section 5.1), and also
 *  the fact that they have more 'client <- HS' cells than the other way around
 *  (section 3.2). */
void
circpad_machine_client_hide_rend_circuits(smartlist_t *machines_sl)
{
  circpad_machine_spec_t *client_machine
      = tor_malloc_zero(sizeof(circpad_machine_spec_t));

  client_machine->name = "client_rp_circ";

  /* Only pad after the circuit has been built and pad to the middle */
  client_machine->conditions.min_hops = 2;
  client_machine->conditions.state_mask =
    CIRCPAD_CIRC_BUILDING|CIRCPAD_CIRC_OPENED;
  client_machine->target_hopnum = 2;

  /* This is a client machine */
  client_machine->is_origin_side = 1;

  client_machine->conditions.purpose_mask =
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_ESTABLISH_REND)|
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_REND_READY)|
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED)|
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_REND_JOINED);

  /* Setup states and histograms */
  setup_state_machine_for_hiding_hs_circuits(client_machine);
  setup_burst_state_for_hiding_rend_circuits(
                         &client_machine->states[CIRCPAD_STATE_BURST],
                         true);

  /* Register the machine */
  client_machine->machine_num = smartlist_len(machines_sl);
  circpad_register_padding_machine(client_machine, machines_sl);

  log_warn(LD_GENERAL,
           "Registered client rendezvous circuit hiding padding machine (%u)",
           client_machine->machine_num);
}

/** Create a relay-side padding machine that aims to hide IP circuits.
 *
 *  This is meant to follow the client-side machine.
 */
void
circpad_machine_relay_hide_rend_circuits(smartlist_t *machines_sl)
{
  circpad_machine_spec_t *relay_machine
    = tor_malloc_zero(sizeof(circpad_machine_spec_t));

  relay_machine->name = "relay_rp_circ";

  /* Only pad after the circuit has been built and pad to the middle */
  relay_machine->conditions.min_hops = 2;
  relay_machine->conditions.state_mask =
    CIRCPAD_CIRC_BUILDING|CIRCPAD_CIRC_OPENED;
  relay_machine->target_hopnum = 2;

  /* This is a relay-side machine */
  relay_machine->is_origin_side = 0;

  /* Setup states and histograms */
  setup_state_machine_for_hiding_hs_circuits(relay_machine);
  setup_burst_state_for_hiding_rend_circuits(
                 &relay_machine->states[CIRCPAD_STATE_BURST],
                 false);

  /* Register the machine */
  relay_machine->machine_num = smartlist_len(machines_sl);
  circpad_register_padding_machine(relay_machine, machines_sl);

  log_warn(LD_GENERAL,
           "Registered relay rendezvous circuit hiding padding machine (%u)",
           relay_machine->machine_num);
}
