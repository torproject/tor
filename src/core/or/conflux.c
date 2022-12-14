/* Copyright (c) 2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file conflux.c
 * \brief Conflux multipath core algorithms
 */

#define TOR_CONFLUX_PRIVATE

#include "core/or/or.h"

#include "core/or/circuit_st.h"
#include "core/or/sendme.h"
#include "core/or/congestion_control_common.h"
#include "core/or/congestion_control_st.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/circuitlist.h"
#include "core/or/circuituse.h"
#include "core/or/conflux.h"
#include "core/or/conflux_params.h"
#include "core/or/conflux_util.h"
#include "core/or/conflux_st.h"
#include "lib/time/compat_time.h"
#include "app/config/config.h"

#include "trunnel/extension.h"

/** One million microseconds in a second */
#define USEC_PER_SEC 1000000

/**
 * Determine if we should multiplex a specific relay command or not.
 *
 * TODO: Version of this that is the set of forbidden commands
 * on linked circuits
 */
bool
conflux_should_multiplex(int relay_command)
{
  switch (relay_command) {
    /* These are all fine to multiplex, and must be
     * so that ordering is preserved */
    case RELAY_COMMAND_BEGIN:
    case RELAY_COMMAND_DATA:
    case RELAY_COMMAND_END:
    case RELAY_COMMAND_CONNECTED:
      return true;

    /* We can't multiplex these because they are
     * circuit-specific */
    case RELAY_COMMAND_SENDME:
    case RELAY_COMMAND_EXTEND:
    case RELAY_COMMAND_EXTENDED:
    case RELAY_COMMAND_TRUNCATE:
    case RELAY_COMMAND_TRUNCATED:
    case RELAY_COMMAND_DROP:
      return false;

    /* We must multiplex RESOLVEs because their ordering
     * impacts begin/end. */
    case RELAY_COMMAND_RESOLVE:
    case RELAY_COMMAND_RESOLVED:
      return true;

    /* These are all circuit-specific */
    case RELAY_COMMAND_BEGIN_DIR:
    case RELAY_COMMAND_EXTEND2:
    case RELAY_COMMAND_EXTENDED2:
    case RELAY_COMMAND_ESTABLISH_INTRO:
    case RELAY_COMMAND_ESTABLISH_RENDEZVOUS:
    case RELAY_COMMAND_INTRODUCE1:
    case RELAY_COMMAND_INTRODUCE2:
    case RELAY_COMMAND_RENDEZVOUS1:
    case RELAY_COMMAND_RENDEZVOUS2:
    case RELAY_COMMAND_INTRO_ESTABLISHED:
    case RELAY_COMMAND_RENDEZVOUS_ESTABLISHED:
    case RELAY_COMMAND_INTRODUCE_ACK:
    case RELAY_COMMAND_PADDING_NEGOTIATE:
    case RELAY_COMMAND_PADDING_NEGOTIATED:
      return false;

    /* These must be multiplexed because their ordering
     * relative to BEGIN/END must be preserved */
    case RELAY_COMMAND_XOFF:
    case RELAY_COMMAND_XON:
      return true;

    /* These two are not multiplexed, because they must
     * be processed immediately to update sequence numbers
     * before any other cells are processed on the circuit */
    case RELAY_COMMAND_CONFLUX_SWITCH:
    case RELAY_COMMAND_CONFLUX_LINK:
    case RELAY_COMMAND_CONFLUX_LINKED:
    case RELAY_COMMAND_CONFLUX_LINKED_ACK:
      return false;

    default:
      log_warn(LD_BUG, "Conflux asked to multiplex unknown relay command %d",
               relay_command);
      return false;
  }
}

/** Return the leg for a circuit in a conflux set. Return NULL if not found. */
conflux_leg_t *
conflux_get_leg(conflux_t *cfx, const circuit_t *circ)
{
  conflux_leg_t *leg_found = NULL;

  // Find the leg that the cell is written on
  CONFLUX_FOR_EACH_LEG_BEGIN(cfx, leg) {
    if (leg->circ == circ) {
      leg_found = leg;
      break;
    }
  } CONFLUX_FOR_EACH_LEG_END(leg);

  return leg_found;
}

/**
 * Comparison function for ooo_q pqueue.
 *
 * Ensures that lower sequence numbers are at the head of the pqueue.
 */
static int
conflux_queue_cmp(const void *a, const void *b)
{
  // Compare a and b as conflux_cell_t using the seq field, and return a
  // comparison result such that the lowest seq is at the head of the pqueue.
  const conflux_cell_t *cell_a = a;
  const conflux_cell_t *cell_b = b;

  tor_assert(cell_a);
  tor_assert(cell_b);

  if (cell_a->seq < cell_b->seq) {
    return -1;
  } else if (cell_a->seq > cell_b->seq) {
    return 1;
  } else {
    return 0;
  }
}

/**
 * Get the congestion control object for a conflux circuit.
 *
 * Because conflux can only be negotiated with the last hop, we
 * can use the last hop of the cpath to obtain the congestion
 * control object for origin circuits. For non-origin circuits,
 * we can use the circuit itself.
 */
const congestion_control_t *
circuit_ccontrol(const circuit_t *circ)
{
  const congestion_control_t *ccontrol = NULL;
  tor_assert(circ);

  if (CIRCUIT_IS_ORIGIN(circ)) {
    tor_assert(CONST_TO_ORIGIN_CIRCUIT(circ)->cpath);
    tor_assert(CONST_TO_ORIGIN_CIRCUIT(circ)->cpath->prev);
    ccontrol = CONST_TO_ORIGIN_CIRCUIT(circ)->cpath->prev->ccontrol;
  } else {
    ccontrol = circ->ccontrol;
  }

  /* Conflux circuits always have congestion control*/
  tor_assert(ccontrol);
  return ccontrol;
}

/**
 * Process an incoming relay cell for conflux. Called from
 * connection_edge_process_relay_cell().
 *
 * Returns true if the conflux system now has well-ordered cells to deliver
 * to streams, false otherwise.
 */
bool
conflux_process_cell(conflux_t *cfx, circuit_t *in_circ,
                     crypt_path_t *layer_hint, cell_t *cell)
{
  // TODO-329-TUNING: Temporarily validate legs here. We can remove
  // this after tuning is complete.
  conflux_validate_legs(cfx);

  conflux_leg_t *leg = conflux_get_leg(cfx, in_circ);
  if (!leg) {
    log_warn(LD_BUG, "Got a conflux cell on a circuit without "
             "conflux leg. Closing circuit.");
    circuit_mark_for_close(in_circ, END_CIRC_REASON_INTERNAL);
    return false;
  }

  /* We need to make sure this cell came from the expected hop, or
   * else it could be a data corruption attack from a middle node. */
  if (!conflux_validate_source_hop(in_circ, layer_hint)) {
    circuit_mark_for_close(in_circ, END_CIRC_REASON_TORPROTOCOL);
    return false;
  }

  /* Update the running absolute sequence number */
  leg->last_seq_recv++;

  /* If this cell is next, fast-path it by processing the cell in-place */
  if (leg->last_seq_recv == cfx->last_seq_delivered + 1) {
    /* The cell is now ready to be processed, and rest of the queue should
     * now be checked for remaining elements */
    cfx->last_seq_delivered++;
    return true;
  } else if (BUG(leg->last_seq_recv <= cfx->last_seq_delivered)) {
    log_warn(LD_BUG, "Got a conflux cell with a sequence number "
             "less than the last delivered. Closing circuit.");
    circuit_mark_for_close(in_circ, END_CIRC_REASON_INTERNAL);
    return false;
  } else {
    conflux_cell_t *c_cell = tor_malloc_zero(sizeof(conflux_cell_t));
    c_cell->seq = leg->last_seq_recv;

    memcpy(&c_cell->cell, cell, sizeof(cell_t));

    smartlist_pqueue_add(cfx->ooo_q, conflux_queue_cmp,
            offsetof(conflux_cell_t, heap_idx), c_cell);
    total_ooo_q_bytes += sizeof(cell_t);

    /* This cell should not be processed yet, and the queue is not ready
     * to process because the next absolute seqnum has not yet arrived */
    return false;
  }
}

/**
 * Dequeue the top cell from our queue.
 *
 * Returns the cell as a conflux_cell_t, or NULL if the queue is empty
 * or has a hole.
 */
conflux_cell_t *
conflux_dequeue_cell(conflux_t *cfx)
{
  conflux_cell_t *top = NULL;
  if (smartlist_len(cfx->ooo_q) == 0)
    return NULL;

  top = smartlist_get(cfx->ooo_q, 0);

  /* If the top cell is the next sequence number we need, then
   * pop and return it. */
  if (top->seq == cfx->last_seq_delivered+1) {
    smartlist_pqueue_pop(cfx->ooo_q, conflux_queue_cmp,
                         offsetof(conflux_cell_t, heap_idx));
    total_ooo_q_bytes -= sizeof(cell_t);
    cfx->last_seq_delivered++;
    return top;
  } else {
    return NULL;
  }
}
