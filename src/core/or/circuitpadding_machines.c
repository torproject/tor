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
 *    This machine hides client-side introduction circuits by making their
 *    circuit consruction sequence look like normal general circuits that
 *    download directory information. Furthermore, the circuits are kept open
 *    until all the padding has been sent, since intro circuits are usually
 *    very short lived and this act as a distinguisher. For more info see
 *    circpad_machine_client_hide_intro_circuits() and the sec.
 *
 * Client-side rendezvous circuit hiding machine:
 *
 *    This machine hides client-side rendezvous circuits by making their
 *    circuit construction sequence look like normal general circuits. For more
 *    details see circpad_machine_client_hide_rend_circuits() and the spec.
 *
 * TODO: These are simple machines that carefully manipulate the cells of the
 *   initial circuit setup procedure to make them look like general
 *   circuits. In the future, more states can be baked into their state machine
 *   to do more advanced obfuscation.
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
setup_state_machine_for_hiding_intro_circuits(circpad_machine_spec_t *machine)
{
  /* Two states: START, OBFUSCATE_CIRC_SETUP (and END) */
  circpad_machine_states_init(machine, 2);

  /* For the relay-side machine, we want to transition
   * START -> OBFUSCATE_CIRC_SETUP upon first non-padding
   * cell sent (PADDING_NEGOTIATED in this case).
   *
   * For the origin-side machine, we transition to OBFUSCATE_CIRC_SETUP after
   * sending PADDING_NEGOTIATE, and we stay there (without sending any padding)
   * until we receive a STOP from the other side. */
  machine->states[CIRCPAD_STATE_START].
    next_state[CIRCPAD_EVENT_NONPADDING_SENT] =
    CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP;

  /* For the relay-side, we want to transition from OBFUSCATE_CIRC_SETUP to END
   * state when the length finishes.
   *
   * For the origin-side, we don't care because the relay-side machine is gonna
   * END us. */
  machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
      next_state[CIRCPAD_EVENT_LENGTH_COUNT] = CIRCPAD_STATE_END;

  /* Now let's define the OBF -> OBF transitions that maintain our padding
   * flow:
   *
   * For the relay-side machine, we want to keep on sending padding bytes even
   * when nothing else happens on this circuit. */
  machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    next_state[CIRCPAD_EVENT_PADDING_SENT] =
    CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP;
  /* For the relay-side machine, we need this transition so that we re-enter
     the state, after PADDING_NEGOTIATED is sent. Otherwise, the remove token
     function will disable the timer, and nothing will restart it since there
     is no other motion on an intro circuit. */
  machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    next_state[CIRCPAD_EVENT_NONPADDING_SENT] =
    CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP;
}

/* Setup the OBFUSCATE_CIRC_SETUP state of the machine that hides client-side
 * intro circuits. */
static void
setup_obf_state_for_hiding_intro_circuits(circpad_state_t *obf_state,
                                            bool is_client)
{
  /* Token removal strategy for OBFUSCATE_CIRC_SETUP state. We pick the
   * simplest one since we rely on the state length sampling and not the
   * tokens. */
  obf_state->token_removal = CIRCPAD_TOKEN_REMOVAL_NONE;

  /* Figure out the length of the OBFUSCATE_CIRC_SETUP state so that it's
   * randomized. We will set the histogram such that we don't send any padding
   * from the origin-side, so just tune these parameteres for the
   * relay-side. */
  obf_state->length_dist.type = CIRCPAD_DIST_UNIFORM;
  obf_state->length_dist.param1 = INTRO_MACHINE_MINIMUM_PADDING;
  obf_state->length_dist.param2 = INTRO_MACHINE_MAXIMUM_PADDING;

  /* Configure histogram */
  obf_state->histogram_len = 2;
  if (is_client) {
    /* For the origin-side machine we don't want to send any padding, so setup
     * infinite delays. */
    obf_state->histogram_edges[0] = CIRCPAD_DELAY_INFINITE-1;
    obf_state->histogram_edges[1] = CIRCPAD_DELAY_INFINITE;
    /* zero tokens */
    obf_state->histogram[0] = 0;
  } else {
    /* For the relay-side machine we want to batch padding instantly to pretend
     * its an incoming directory download. So set the histogram edges tight:
     * (1, 10ms, infinity). */
    obf_state->histogram_edges[0] = 1000;
    obf_state->histogram_edges[1] = 10000;
    /* padding is controlled by state length, so this is just a high value */
    obf_state->histogram[0] = 1000;
  }

  /* just one bin, so setup the total tokens */
  obf_state->histogram_total_tokens = obf_state->histogram[0];
}

/** Create a client-side padding machine that aims to hide IP circuits. In
 *  particular, it keeps intro circuits alive until a bunch of fake traffic has
 *  been pushed through.
 */
void
circpad_machine_client_hide_intro_circuits(smartlist_t *machines_sl)
{
  circpad_machine_spec_t *client_machine
      = tor_malloc_zero(sizeof(circpad_machine_spec_t));

  client_machine->name = "client_ip_circ";

  client_machine->conditions.state_mask = CIRCPAD_CIRC_OPENED;
  client_machine->target_hopnum = 2;

  /* This is a client machine */
  client_machine->is_origin_side = 1;

  /* We only want to pad introduction circuits, and we want to start padding
   * only after the INTRODUCE1 cell has been sent, so set the purposes
   * appropriately.
   *
   * In particular we want introduction circuits to blend as much as possible
   * with general circuits. Most general circuits have the following initial
   * relay cell sequence (outgoing cells marked in [brackets]):
   *
   * [EXTEND2] -> EXTENDED2 -> [EXTEND2] -> EXTENDED2 -> [BEGIN] -> CONNECTED
   *
   * followed usually by a [DATA] -> [DATA] -> DATA -> DATA.
   *
   * Whereas normal introduction circuits usually look like:
   *
   * [EXTEND2] -> EXTENDED2 -> [EXTEND2] -> EXTENDED2 -> [EXTEND2] -> EXTENDED2
   *  -> [INTRODUCE1] -> INTRODUCE_ACK
   *
   * This means that up to the sixth cell, both general and intro circuits have
   * identical cell sequences. After that we want to mimic the
   * [DATA] -> [DATA] -> DATA -> DATA sequence, which we achieve by padding
   * after the INTRODUCE1 has been sent which usually looks like:
   *
   *     [INTRODUCE1] -> [PADDING_NEGOTIATE] -> PADDING_NEGOTIATED -> INTRO_ACK
   *
   * effectively blending with general circuits up until the end of the circuit
   * setup. */
  client_machine->conditions.purpose_mask =
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT)|
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_INTRODUCE_ACKED)|
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_CIRCUIT_PADDING);

  /* Keep the circuit alive even after the introduction has been finished,
   * otherwise the short-term lifetime of the circuit will blow our cover */
  client_machine->manage_circ_lifetime = 1;

  /* Setup states and histograms */
  setup_state_machine_for_hiding_intro_circuits(client_machine);
  setup_obf_state_for_hiding_intro_circuits(
                   &client_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP],
                   true);

  /* Register the machine */
  client_machine->machine_num = smartlist_len(machines_sl);
  circpad_register_padding_machine(client_machine, machines_sl);

  log_warn(LD_GENERAL,
           "Registered client intro point hiding padding machine (%u)",
           client_machine->machine_num);
}

/** Create a relay-side padding machine that aims to hide IP circuits. See
 *  comments on the function above for more details on the workings of the
 *  machine. */
void
circpad_machine_relay_hide_intro_circuits(smartlist_t *machines_sl)
{
  circpad_machine_spec_t *relay_machine
      = tor_malloc_zero(sizeof(circpad_machine_spec_t));

  relay_machine->name = "relay_ip_circ";

  relay_machine->conditions.state_mask = CIRCPAD_CIRC_OPENED;
  relay_machine->target_hopnum = 2;

  /* This is a relay-side machine */
  relay_machine->is_origin_side = 0;

  /* We want to negotiate END from this side after all our padding is done, so
   * that the origin-side machine goes into END state, and eventually closes
   * the circuit. */
  relay_machine->should_negotiate_end = 1;

  /* Setup states and histograms */
  setup_state_machine_for_hiding_intro_circuits(relay_machine);
  setup_obf_state_for_hiding_intro_circuits(
                 &relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP],
                 false);

  /* Register the machine */
  relay_machine->machine_num = smartlist_len(machines_sl);
  circpad_register_padding_machine(relay_machine, machines_sl);

  log_warn(LD_GENERAL,
           "Registered relay intro circuit hiding padding machine (%u)",
           relay_machine->machine_num);
}

/************************** Rendezvous-circuit machine ***********************/

/* Setup the obf state of the machine that hides client-side rend
 * circuits. */
static void
setup_obf_state_for_hiding_rend_circuits(circpad_state_t *obf_state)
{
  /* Don't use a token removal strategy since we don't want to use monotime
     functions. We want this machine to be light. */
  obf_state->token_removal = CIRCPAD_TOKEN_REMOVAL_NONE;

  /* Instead, to control the volume of padding (we just want to send a single
   * padding cell) we will use a static state length. We just want one token,
   * since we want to make the following pattern:
   * [PADDING_NEGOTIATE] -> [DROP] -> PADDING_NEGOTIATED -> DROP */
  obf_state->length_dist.type = CIRCPAD_DIST_UNIFORM;
  obf_state->length_dist.param1 = 1;
  obf_state->length_dist.param2 = 2;

  /* Histogram is: (0 msecs, 50 msecs, infinity). We want this to be fast so
   * that the incoming PADDING_NEGOTIATED cell always arrives after the
   * outgoing [DROP]. */
  obf_state->histogram_len = 2;
  obf_state->histogram_edges[0] = 0;
  obf_state->histogram_edges[1] = 1000;

  /* dummy amount of tokens. they dont matter */
  obf_state->histogram[0] = 1;
  obf_state->histogram_total_tokens = 1;
}

/* Setup the simple state machine we use for all HS padding machines */
static void
setup_state_machine_for_hiding_rend_circuits(circpad_machine_spec_t *machine)
{
  /* Two states: START, OBFUSCATE_CIRC_SETUP (and END) */
  circpad_machine_states_init(machine, 2);

  /* START -> OBFUSCATE_CIRC_SETUP transition upon sending the first
   * non-padding cell (which is PADDING_NEGOTIATE) */
  machine->states[CIRCPAD_STATE_START].
    next_state[CIRCPAD_EVENT_NONPADDING_SENT] =
    CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP;

  /* OBFUSCATE_CIRC_SETUP -> END transition when we finish all the tokens */
  machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
      next_state[CIRCPAD_EVENT_PADDING_RECV] = CIRCPAD_STATE_END;
  machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
      next_state[CIRCPAD_EVENT_LENGTH_COUNT] = CIRCPAD_STATE_END;
}

/** Create a client-side padding machine that aims to hide rendezvous
 *  circuits.*/
void
circpad_machine_client_hide_rend_circuits(smartlist_t *machines_sl)
{
  circpad_machine_spec_t *client_machine
      = tor_malloc_zero(sizeof(circpad_machine_spec_t));

  client_machine->name = "client_rp_circ";

  /* Only pad after the circuit has been built and pad to the middle */
  client_machine->conditions.state_mask = CIRCPAD_CIRC_OPENED;
  client_machine->target_hopnum = 2;

  /* This is a client machine */
  client_machine->is_origin_side = 1;

  /* We only want to pad rendezvous circuits, and we want to start padding only
   * after the rendezvous circuit has been established.
   *
   * Following a similar argument as above we are aiming for padded rendezvous
   * circuits to blend in with the initial cell sequence of general circuits
   * which usually look like this:
   *
   * [EXTEND2] -> EXTENDED2 -> [EXTEND2] -> EXTENDED2 -> [BEGIN] -> CONNECTED
   *
   * followed usually by a [DATA] -> [DATA] -> DATA -> DATA sequence.
   *
   * Whereas normal rendezvous circuits usually look like:
   *
   * [EXTEND2] -> EXTENDED2 -> [EXTEND2] -> EXTENDED2 -> [ESTABLISH_REND]
   *  -> REND_ESTABLISHED -> RENDEZVOUS2 -> [BEGIN]
   *
   * This means that up to the sixth cell, both general and intro circuits have
   * identical cell sequences. After that we want to mimic a
   * [DATA] -> [DATA] -> DATA -> DATA sequence, which we achieve by sending a
   * [PADDING_NEGOTIATE] right after receiving REND_ESTABLISHED, followed by
   * sending a [DROP] cell, and then receiving a PADDING_NEGOTIATED -> DROP
   * sequence.
   *
   * Hence this way we make rendezvous circuits look like general circuits up
   * till the end of the circuit setup. */
  client_machine->conditions.purpose_mask =
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_REND_JOINED)|
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_REND_READY)|
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED);

  /* Setup states and histograms */
  setup_state_machine_for_hiding_rend_circuits(client_machine);
  setup_obf_state_for_hiding_rend_circuits(
                  &client_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP]);

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
  relay_machine->conditions.state_mask = CIRCPAD_CIRC_OPENED;
  relay_machine->target_hopnum = 2;

  /* This is a relay-side machine */
  relay_machine->is_origin_side = 0;

  /* Setup states and histograms */
  setup_state_machine_for_hiding_rend_circuits(relay_machine);
  setup_obf_state_for_hiding_rend_circuits(
                   &relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP]);

  /* Register the machine */
  relay_machine->machine_num = smartlist_len(machines_sl);
  circpad_register_padding_machine(relay_machine, machines_sl);

  log_warn(LD_GENERAL,
           "Registered relay rendezvous circuit hiding padding machine (%u)",
           relay_machine->machine_num);
}
