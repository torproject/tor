/* * Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitmux.c
 * \brief Circuit mux/cell selection abstraction
 **/

#include "or.h"
#include "circuitmux.h"

/*
 * A circuitmux is a collection of circuits; it tracks which subset
 * of the attached circuits are 'active' (i.e., have cells available
 * to transmit) and how many cells on each.  It expoes three distinct
 * interfaces to other components:
 *
 * To channels, which each have a circuitmux_t, the supported operations
 * are:
 *
 * circuitmux_flush_cells():
 *
 *   Retrieve a cell from one of the active circuits, chosen according to
 *   the circuitmux_t's cell selection policy.
 *
 * circuitmux_unlink_all():
 *
 *   The channel is closing down, all circuits must be detached.
 *
 * To circuits, the exposed operations are:
 *
 *   TODO
 *
 * To circuit selection policies, the exposed operations are:
 *
 *   TODO
 *
 * General status inquiries?
 *     
 */

struct circuitmux_s {
  /*
   * Double-linked ring of circuits with queued cells waiting for room to
   * free up on this connection's outbuf.  Every time we pull cells from
   * a circuit, we advance this pointer to the next circuit in the ring.
   */
  struct circuit_t *active_circuits;

  /*
   * Priority queue of cell_ewma_t for circuits with queued cells waiting
   * for room to free up on this connection's outbuf.  Kept in heap order
   * according to EWMA.
   *
   * This is redundant with active_circuits; if we ever decide only to use
   * the cell_ewma algorithm for choosing circuits, we can remove
   * active_circuits.
   */
  smartlist_t *active_circuit_pqueue;

  /*
   * The tick on which the cell_ewma_ts in active_circuit_pqueue last had
   * their ewma values rescaled.
   */
  unsigned active_circuit_pqueue_last_recalibrated;
};

