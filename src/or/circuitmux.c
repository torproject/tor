/* * Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitmux.c
 * \brief Circuit mux/cell selection abstraction
 **/

#include "or.h"
#include "channel.h"
#include "circuitlist.h"
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

  /* Total number of queued cells on all circuits */
  unsigned int n_cells;

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
 * circuitmux_t; right now, just the count of queued cells and the direction.
 */

struct circuit_muxinfo_s {
  /* Count of cells on this circuit at last update */
  unsigned int cell_count;
  /* Direction of flow */
  cell_direction_t direction;
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
static chanid_circid_muxinfo_t *
circuitmux_find_map_entry(circuitmux_t *cmux, circuit_t *circ);

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

/*
 * Circuitmux alloc/free functions
 */

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
 * Detach all circuits from a circuitmux (use before circuitmux_free())
 */

void
circuitmux_detach_all_circuits(circuitmux_t *cmux)
{
  chanid_circid_muxinfo_t **i = NULL, *to_remove;
  channel_t *chan = NULL;
  circuit_t *circ = NULL;

  tor_assert(cmux);

  i = HT_START(chanid_circid_muxinfo_map, cmux->chanid_circid_map);
  while (i) {
    to_remove = *i;
    i = HT_NEXT_RMV(chanid_circid_muxinfo_map, cmux->chanid_circid_map, i);
    if (to_remove) {
      /* Find a channel and circuit */
      chan = channel_find_by_global_id(to_remove->chan_id);
      if (chan) {
        circ = circuit_get_by_circid_channel(to_remove->circ_id, chan);
        if (circ) {
          /* Clear the circuit's mux for this direction */
          if (to_remove->muxinfo.direction == CELL_DIRECTION_OUT) {
            /* Clear n_mux */
            circ->n_mux = NULL;
          } else if (circ->magic == OR_CIRCUIT_MAGIC) {
            /*
             * It has a sensible p_chan and direction == CELL_DIRECTION_IN,
             * so clear p_mux.
             */
            TO_OR_CIRCUIT(circ)->p_mux = NULL;
          } else {
            /* Complain and move on */
            log_warn(LD_CIRC,
                     "Circuit %d/channel " U64_FORMAT " had direction == "
                     "CELL_DIRECTION_IN, but isn't an or_circuit_t",
                     to_remove->circ_id,
                     U64_PRINTF_ARG(to_remove->chan_id));
          }

          /* TODO update active_circuits / active_circuit_pqueue */
        } else {
          /* Complain and move on */
          log_warn(LD_CIRC,
                   "Couldn't find circuit %d (for channel " U64_FORMAT ")",
                   to_remove->circ_id,
                   U64_PRINTF_ARG(to_remove->chan_id));
        }
      } else {
        /* Complain and move on */
        log_warn(LD_CIRC,
                 "Couldn't find channel " U64_FORMAT " (for circuit id %d)",
                 U64_PRINTF_ARG(to_remove->chan_id),
                 to_remove->circ_id);
      }

      /* Free it */
      tor_free(to_remove);
    }
  }

  cmux->n_circuits = 0;
  cmux->n_active_circuits = 0;
  cmux->n_cells = 0;
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

/*
 * Circuitmux/circuit attachment status inquiry functions
 */

/**
 * Query the direction of an attached circuit
 */

cell_direction_t
circuitmux_attached_circuit_direction(circuitmux_t *cmux, circuit_t *circ)
{
  chanid_circid_muxinfo_t *hashent = NULL;

  /* Try to find a map entry */
  hashent = circuitmux_find_map_entry(cmux, circ);

  /*
   * This function should only be called on attached circuits; assert that
   * we had a map entry.
   */
  tor_assert(hashent);

  /* Return the direction from the map entry */
  return hashent->muxinfo.direction;
}

/**
 * Find an entry in the cmux's map for this circuit or return NULL if there
 * is none.
 */

static chanid_circid_muxinfo_t *
circuitmux_find_map_entry(circuitmux_t *cmux, circuit_t *circ)
{
  chanid_circid_muxinfo_t search, *hashent = NULL;

  /* Sanity-check parameters */
  tor_assert(cmux);
  tor_assert(cmux->chanid_circid_map);
  tor_assert(circ);
  tor_assert(circ->n_chan);

  /* Okay, let's see if it's attached for n_chan/n_circ_id */
  search.chan_id = circ->n_chan->global_identifier;
  search.circ_id = circ->n_circ_id;

  /* Query */
  hashent = HT_FIND(chanid_circid_muxinfo_map, cmux->chanid_circid_map,
                    &search);

  /* Found something? */
  if (hashent) {
    /*
     * Assert that the direction makes sense for a hashent we found by
     * n_chan/n_circ_id before we return it.
     */
    tor_assert(hashent->muxinfo.direction == CELL_DIRECTION_OUT);
  } else {
    /* Not there, have we got a p_chan/p_circ_id to try? */
    if (circ->magic == OR_CIRCUIT_MAGIC) {
      search.circ_id = TO_OR_CIRCUIT(circ)->p_circ_id;
      /* Check for p_chan */
      if (TO_OR_CIRCUIT(circ)->p_chan) {
        search.chan_id = TO_OR_CIRCUIT(circ)->p_chan->global_identifier;
        /* Okay, search for that */
        hashent = HT_FIND(chanid_circid_muxinfo_map, cmux->chanid_circid_map,
                          &search);
        /* Find anything? */
        if (hashent) {
          /* Assert that the direction makes sense before we return it */
          tor_assert(hashent->muxinfo.direction == CELL_DIRECTION_IN);
        }
      }
    }
  }

  /* Okay, hashent is it if it was there */
  return hashent;
}

/**
 * Query whether a circuit is attached to a circuitmux
 */

int
circuitmux_is_circuit_attached(circuitmux_t *cmux, circuit_t *circ)
{
  chanid_circid_muxinfo_t *hashent = NULL;

  /* Look if it's in the circuit map */
  hashent = circuitmux_find_map_entry(cmux, circ);

  return (hashent != NULL);
}

/**
 * Query whether a circuit is active on a circuitmux
 */

int
circuitmux_is_circuit_active(circuitmux_t *cmux, circuit_t *circ)
{
  chanid_circid_muxinfo_t *hashent = NULL;
  int is_active = 0;

  tor_assert(cmux);
  tor_assert(circ);

  /* Look if it's in the circuit map */
  hashent = circuitmux_find_map_entry(cmux, circ);
  if (hashent) {
    /* Check the number of cells on this circuit */
    is_active = (hashent->muxinfo.cell_count > 0);
  }
  /* else not attached, so not active */

  return is_active;
}

/**
 * Query number of available cells for a circuit on a circuitmux
 */

unsigned int
circuitmux_num_cells_for_circuit(circuitmux_t *cmux, circuit_t *circ)
{
  chanid_circid_muxinfo_t *hashent = NULL;
  unsigned int n_cells = 0;

  tor_assert(cmux);
  tor_assert(circ);

  /* Look if it's in the circuit map */
  hashent = circuitmux_find_map_entry(cmux, circ);
  if (hashent) {
    /* Just get the cell count for this circuit */
    n_cells = hashent->muxinfo.cell_count;
  }
  /* else not attached, so 0 cells */

  return n_cells;
}


/**
 * Query total number of available cells on a circuitmux
 */

unsigned int
circuitmux_num_cells(circuitmux_t *cmux)
{
  tor_assert(cmux);

  return cmux->n_cells;
}

/**
 * Query total number of circuits active on a circuitmux
 */

unsigned int
circuitmux_num_active_circuits(circuitmux_t *cmux)
{
  tor_assert(cmux);

  return cmux->n_active_circuits;
}

/**
 * Query total number of circuits attached to a circuitmux
 */

unsigned int
circuitmux_num_circuits(circuitmux_t *cmux)
{
  tor_assert(cmux);

  return cmux->n_circuits;
}

/*
 * Functions for circuit code to call to update circuit status
 */

/**
 * Attach a circuit to a circuitmux, for the specified direction.
 */

void
circuitmux_attach_circuit(circuitmux_t *cmux, circuit_t *circ,
                          cell_direction_t direction)
{
  channel_t *chan = NULL;
  uint64_t channel_id;
  circid_t circ_id;
  chanid_circid_muxinfo_t search, *hashent = NULL;
  unsigned int cell_count;

  tor_assert(cmux);
  tor_assert(circ);
  tor_assert(direction == CELL_DIRECTION_IN ||
             direction == CELL_DIRECTION_OUT);

  /*
   * Figure out which channel we're using, and get the circuit's current
   * cell count and circuit ID; assert that the circuit is not already
   * attached to another mux.
   */
  if (direction == CELL_DIRECTION_OUT) {
    /* It's n_chan */
    chan = circ->n_chan;
    cell_count = circ->n_chan_cells.n;
    circ_id = circ->n_circ_id;
  } else {
    /* We want p_chan */
    chan = TO_OR_CIRCUIT(circ)->p_chan;
    cell_count = TO_OR_CIRCUIT(circ)->p_chan_cells.n;
    circ_id = TO_OR_CIRCUIT(circ)->p_circ_id;
  }
  /* Assert that we did get a channel */
  tor_assert(chan);
  /* Assert that the circuit ID is sensible */
  tor_assert(circ_id != 0);

  /* Get the channel ID */
  channel_id = chan->global_identifier;

  /* See if we already have this one */
  search.chan_id = channel_id;
  search.circ_id = circ_id;
  hashent = HT_FIND(chanid_circid_muxinfo_map, cmux->chanid_circid_map,
                    &search);

  if (hashent) {
    /*
     * This circuit was already attached to this cmux; make sure the
     * directions match and update the cell count and active circuit count.
     */
    log_info(LD_CIRC,
             "Circuit %u on channel " U64_FORMAT " was already attached to "
             "cmux %p (trying to attach to %p)",
             circ_id, U64_PRINTF_ARG(channel_id),
             ((direction == CELL_DIRECTION_OUT) ?
                circ->n_mux : TO_OR_CIRCUIT(circ)->p_mux),
             cmux);

    /*
     * The mux pointer on this circuit and the direction in result should
     * match; otherwise assert.
     */
    if (direction == CELL_DIRECTION_OUT) tor_assert(circ->n_mux == cmux);
    else tor_assert(TO_OR_CIRCUIT(circ)->p_mux == cmux);
    tor_assert(hashent->muxinfo.direction == direction);

    /*
     * Looks okay; just update the cell count and active circuits if we must
     */
    if (hashent->muxinfo.cell_count > 0 && cell_count == 0) {
      --(cmux->n_active_circuits);
    } else if (hashent->muxinfo.cell_count == 0 && cell_count > 0) {
      ++(cmux->n_active_circuits);
    }
    cmux->n_cells -= hashent->muxinfo.cell_count;
    cmux->n_cells += cell_count;
    hashent->muxinfo.cell_count = cell_count;

    /* TODO update active_circuits / active_circuit_pqueue */
  } else {
    /*
     * New circuit; add an entry and update the circuit/active circuit
     * counts.
     */
    log_debug(LD_CIRC,
             "Attaching circuit %u on channel " U64_FORMAT " to cmux %p",
             circ_id, U64_PRINTF_ARG(channel_id), cmux);

    /*
     * Assert that the circuit doesn't already have a mux for this
     * direction.
     */
    if (direction == CELL_DIRECTION_OUT) tor_assert(circ->n_mux == NULL);
    else tor_assert(TO_OR_CIRCUIT(circ)->p_mux == NULL);

    /* Insert it in the map */
    hashent = tor_malloc_zero(sizeof(*hashent));
    hashent->chan_id = channel_id;
    hashent->circ_id = circ_id;
    hashent->muxinfo.cell_count = cell_count;
    hashent->muxinfo.direction = direction;
    HT_INSERT(chanid_circid_muxinfo_map, cmux->chanid_circid_map,
              hashent);

    /* Set the circuit's mux for this direction */
    if (direction == CELL_DIRECTION_OUT) circ->n_mux = cmux;
    else TO_OR_CIRCUIT(circ)->p_mux = cmux;

    /* Make sure the next/prev pointers are NULL */
    if (direction == CELL_DIRECTION_OUT) {
      circ->next_active_on_n_chan = NULL;
      circ->prev_active_on_n_chan = NULL;
    } else {
      TO_OR_CIRCUIT(circ)->next_active_on_p_chan = NULL;
      TO_OR_CIRCUIT(circ)->prev_active_on_p_chan = NULL;
    }

    /* Update counters */
    ++(cmux->n_circuits);
    if (cell_count > 0) {
      ++(cmux->n_active_circuits);
      circuitmux_make_circuit_active(cmux, circ, direction);
    }
    cmux->n_cells += cell_count;

    /* TODO update active_circuits / active_circuit_pqueue */
  }
}

/**
 * Detach a circuit from a circuitmux and update all counters as needed;
 * no-op if not attached.
 */

void
circuitmux_detach_circuit(circuitmux_t *cmux, circuit_t *circ)
{
  chanid_circid_muxinfo_t search, *hashent = NULL;
  /*
   * Use this to keep track of whether we found it for n_chan or
   * p_chan for consistency checking.
   */
  cell_direction_t last_searched_direction;

  tor_assert(cmux);
  tor_assert(cmux->chanid_circid_map);
  tor_assert(circ);
  tor_assert(circ->n_chan);

  /* See if we have it for n_chan/n_circ_id */
  search.chan_id = circ->n_chan->global_identifier;
  search.circ_id = circ->n_circ_id;
  hashent = HT_REMOVE(chanid_circid_muxinfo_map, cmux->chanid_circid_map,
                      &search);
  last_searched_direction = CELL_DIRECTION_OUT;

  /* Got one? If not, see if it's an or_circuit_t and try p_chan/p_circ_id */
  if (!hashent) {
    if (circ->magic == OR_CIRCUIT_MAGIC) {
      search.circ_id = TO_OR_CIRCUIT(circ)->p_circ_id;
      if (TO_OR_CIRCUIT(circ)->p_chan) {
        search.chan_id = TO_OR_CIRCUIT(circ)->p_chan->global_identifier;
        hashent = HT_REMOVE(chanid_circid_muxinfo_map,
                            cmux->chanid_circid_map,
                            &search);
        last_searched_direction = CELL_DIRECTION_IN;
      }
    }
  }

  /* If hashent isn't NULL, we just removed it from the map */
  if (hashent) {
    /* Update counters */
    --(cmux->n_circuits);
    if (hashent->muxinfo.cell_count > 0) --(cmux->n_active_circuits);
    cmux->n_cells -= hashent->muxinfo.cell_count;
    /* TODO update active_circuits / active_circuit_pqueue */

    /* Consistency check: the direction must match the direction searched */
    tor_assert(last_searched_direction == hashent->muxinfo.direction);
    /* Clear the circuit's mux for this direction */
    if (last_searched_direction == CELL_DIRECTION_OUT) circ->n_mux = NULL;
    else TO_OR_CIRCUIT(circ)->p_mux = NULL;

    /* Free the hash entry */
    tor_free(hashent);
  }
}

/**
 * Clear the cell counter for a circuit on a circuitmux
 */

void
circuitmux_clear_num_cells(circuitmux_t *cmux, circuit_t *circ)
{
  /* This is the same as setting the cell count to zero */
  circuitmux_set_num_cells(cmux, circ, 0);
}

/**
 * Set the cell counter for a circuit on a circuitmux
 */

void
circuitmux_set_num_cells(circuitmux_t *cmux, circuit_t *circ,
                         unsigned int n_cells)
{
  chanid_circid_muxinfo_t *hashent = NULL;

  tor_assert(cmux);
  tor_assert(circ);

  /* Search for this circuit's entry */
  hashent = circuitmux_find_map_entry(cmux, circ);
  /* Assert that we found one */
  tor_assert(hashent);

  /* Update cmux cell counter */
  cmux->n_cells -= hashent->muxinfo.cell_count;
  cmux->n_cells += n_cells;

  /*
   * Update cmux active circuit counter: is the old cell count > 0 and the
   * new cell count == 0 ?
   */
  if (hashent->muxinfo.cell_count > 0 && n_cells == 0) {
    --(cmux->n_active_circuits);
    /* TODO update active_circuits / active_circuit_pqueue */
  /* Is the old cell count == 0 and the new cell count > 0 ? */
  } else if (hashent->muxinfo.cell_count == 0 && n_cells > 0) {
    ++(cmux->n_active_circuits);
    /* TODO update active_circuits / active_circuit_pqueue */
  }

  /* Update hash entry cell counter */
  hashent->muxinfo.cell_count = n_cells;
}

