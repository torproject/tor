/* * Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitmux.c
 * \brief Circuit mux/cell selection abstraction
 **/

#include "or.h"
#include "circuitmux.h"

/*
 * Private typedefs for circuitmux.c
 */

/*
 * Map of muxinfos for circuitmux_t to use; struct is defined below (name
 * of struct must match HT_HEAD line).
 */
typedef struct chanid_circid_muxinfo_map chanid_circid_muxinfo_map_t;

/*
 * Hash table entry (yeah, calling it chanid_circid_muxinfo_s seems to
 * break the hash table code).
 */
typedef struct chanid_circid_muxinfo_t chanid_circid_muxinfo_t;

/*
 * Anything the mux wants to store per-circuit in the map; right now just
 * a count of queued cells.
 */

typedef struct circuit_muxinfo_s circuit_muxinfo_t;

/*
 * Structures for circuitmux.c
 */

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
  /* Keep count of attached, active circuits */
  unsigned int n_circuits, n_active_circuits;

  /*
   * Map from (channel ID, circuit ID) pairs to circuit_muxinfo_t
   */
  chanid_circid_muxinfo_map_t *chanid_circid_map;

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
  unsigned int active_circuit_pqueue_last_recalibrated;
};

/*
 * This struct holds whatever we want to store per attached circuit on a
 * circuitmux_t; right now, just the count of queued cells.
 */

struct circuit_muxinfo_s {
  unsigned int cell_count;
};

/*
 * A map from channel ID and circuit ID to a circuit_muxinfo_t for that
 * circuit.
 */

struct chanid_circid_muxinfo_t {
  HT_ENTRY(chanid_circid_muxinfo_t) node;
  uint64_t chan_id;
  circid_t circ_id;
  circuit_muxinfo_t muxinfo;
};

/*
 * Static function declarations
 */

static INLINE int
chanid_circid_entries_eq(chanid_circid_muxinfo_t *a,
                         chanid_circid_muxinfo_t *b);
static INLINE unsigned int
chanid_circid_entry_hash(chanid_circid_muxinfo_t *a);

/* Function definitions */

/**
 * Helper for chanid_circid_cell_count_map_t hash table: compare the channel
 * ID and circuit ID for a and b, and return less than, equal to, or greater
 * than zero appropriately.
 */

static INLINE int
chanid_circid_entries_eq(chanid_circid_muxinfo_t *a,
                         chanid_circid_muxinfo_t *b)
{
    return a->chan_id == b->chan_id && a->circ_id == b->circ_id;
}

/**
 * Helper: return a hash based on circuit ID and channel ID in a.
 */

static INLINE unsigned int
chanid_circid_entry_hash(chanid_circid_muxinfo_t *a)
{
    return (((unsigned int)(a->circ_id) << 8) ^
            ((unsigned int)((a->chan_id >> 32) & 0xffffffff)) ^
            ((unsigned int)(a->chan_id & 0xffffffff)));
}

/* Declare the struct chanid_circid_muxinfo_map type */
HT_HEAD(chanid_circid_muxinfo_map, chanid_circid_muxinfo_t);

/* Emit a bunch of hash table stuff */
HT_PROTOTYPE(chanid_circid_muxinfo_map, chanid_circid_muxinfo_t, node,
             chanid_circid_entry_hash, chanid_circid_entries_eq);
HT_GENERATE(chanid_circid_muxinfo_map, chanid_circid_muxinfo_t, node,
            chanid_circid_entry_hash, chanid_circid_entries_eq, 0.6,
            malloc, realloc, free);

/**
 * Allocate a new circuitmux_t
 */

circuitmux_t *
circuitmux_alloc(void)
{
  circuitmux_t *rv = NULL;

  rv = tor_malloc_zero(sizeof(*rv));
  rv->chanid_circid_map = tor_malloc_zero(sizeof(*( rv->chanid_circid_map)));
  HT_INIT(chanid_circid_muxinfo_map, rv->chanid_circid_map);

  return rv;
}

/**
 * Free a circuitmux_t; the circuits must be detached first with
 * circuitmux_detach_all_circuits().
 */

void
circuitmux_free(circuitmux_t *cmux)
{
  if (!cmux) return;

  tor_assert(cmux->n_circuits == 0);
  tor_assert(cmux->n_active_circuits == 0);

  smartlist_free(cmux->active_circuit_pqueue);

  if (cmux->chanid_circid_map) {
    HT_CLEAR(chanid_circid_muxinfo_map, cmux->chanid_circid_map);
    tor_free(cmux->chanid_circid_map);
  }

  tor_free(cmux);
}

