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
  struct circuit_t *active_circuits_head, *active_circuits_tail;

  /*
   * Circuitmux policy; if this is non-NULL, it can override the built-
   * in round-robin active circuits behavior.  This is how EWMA works in
   * the new circuitmux_t world.
   */
  const circuitmux_policy_t *policy;

  /* Policy-specific data */
  circuitmux_policy_data_t *policy_data;
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
  /* Policy-specific data */
  circuitmux_policy_circ_data_t *policy_data;
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
static void
circuitmux_make_circuit_active(circuitmux_t *cmux, circuit_t *circ,
                               cell_direction_t direction);
static void
circuitmux_make_circuit_inactive(circuitmux_t *cmux, circuit_t *circ,
                                 cell_direction_t direction);
static INLINE void
circuitmux_move_active_circ_to_tail(circuitmux_t *cmux, circuit_t *circ,
                                    cell_direction_t direction);
static INLINE circuit_t **
circuitmux_next_active_circ_p(circuitmux_t *cmux, circuit_t *circ);
static INLINE circuit_t **
circuitmux_prev_active_circ_p(circuitmux_t *cmux, circuit_t *circ);

/* Function definitions */

/**
 * Linked list helpers
 */

/**
 * Move an active circuit to the tail of the cmux's active circuits list;
 * used by circuitmux_notify_xmit_cells().
 */

static INLINE void
circuitmux_move_active_circ_to_tail(circuitmux_t *cmux, circuit_t *circ,
                                    cell_direction_t direction)
{
  circuit_t **next_p = NULL, **prev_p = NULL;
  circuit_t **next_prev = NULL, **prev_next = NULL;
  or_circuit_t *or_circ = NULL;

  tor_assert(cmux);
  tor_assert(circ);

  /* Figure out our next_p and prev_p for this cmux/direction */
  if (direction) {
    if (direction == CELL_DIRECTION_OUT) {
      tor_assert(circ->n_mux == cmux);
      next_p = &(circ->next_active_on_n_chan);
      prev_p = &(circ->prev_active_on_n_chan);
    } else {
      or_circ = TO_OR_CIRCUIT(circ);
      tor_assert(or_circ->p_mux == cmux);
      next_p = &(or_circ->next_active_on_p_chan);
      prev_p = &(or_circ->prev_active_on_p_chan);
    }
  } else {
    if (circ->n_mux == cmux) {
      next_p = &(circ->next_active_on_n_chan);
      prev_p = &(circ->prev_active_on_n_chan);
      direction = CELL_DIRECTION_OUT;
    } else {
      or_circ = TO_OR_CIRCUIT(circ);
      tor_assert(or_circ->p_mux == cmux);
      next_p = &(or_circ->next_active_on_p_chan);
      prev_p = &(or_circ->prev_active_on_p_chan);
      direction = CELL_DIRECTION_IN;
    }
  }
  tor_assert(next_p);
  tor_assert(prev_p);

  /* Check if this really is an active circuit */
  if ((*next_p == NULL && *prev_p == NULL) &&
      !(circ == cmux->active_circuits_head ||
        circ == cmux->active_circuits_tail)) {
    /* Not active, no-op */
    return;
  }

  /* Check if this is already the tail */
  if (circ == cmux->active_circuits_tail) return;

  /* Okay, we have to move it; figure out next_prev and prev_next */
  if (*next_p) next_prev = circuitmux_prev_active_circ_p(cmux, *next_p);
  if (*prev_p) prev_next = circuitmux_next_active_circ_p(cmux, *prev_p);
  /* Adjust the previous node's next pointer, if any */
  if (prev_next) *prev_next = *next_p;
  /* Otherwise, we were the head */
  else cmux->active_circuits_head = *next_p;
  /* Adjust the next node's previous pointer, if any */
  if (next_prev) *next_prev = *prev_p;
  /* Adjust our next and prev pointers */
  *next_p = NULL;
  *prev_p = cmux->active_circuits_tail;
  /* Set the tail to this circuit */
  cmux->active_circuits_tail = circ;
}

static INLINE circuit_t **
circuitmux_next_active_circ_p(circuitmux_t *cmux, circuit_t *circ)
{
  tor_assert(cmux);
  tor_assert(circ);

  if (circ->n_mux == cmux) return &(circ->next_active_on_n_chan);
  else {
    tor_assert(TO_OR_CIRCUIT(circ)->p_mux == cmux);
    return &(TO_OR_CIRCUIT(circ)->next_active_on_p_chan);
  }
}

static INLINE circuit_t **
circuitmux_prev_active_circ_p(circuitmux_t *cmux, circuit_t *circ)
{
  tor_assert(cmux);
  tor_assert(circ);

  if (circ->n_mux == cmux) return &(circ->prev_active_on_n_chan);
  else {
    tor_assert(TO_OR_CIRCUIT(circ)->p_mux == cmux);
    return &(TO_OR_CIRCUIT(circ)->prev_active_on_p_chan);
  }
}

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
            /*
             * Update active_circuits et al.; this does policy notifies, so
             * comes before freeing policy data
             */
            circuitmux_make_circuit_inactive(cmux, circ, CELL_DIRECTION_OUT);
          } else if (circ->magic == OR_CIRCUIT_MAGIC) {
            /*
             * It has a sensible p_chan and direction == CELL_DIRECTION_IN,
             * so clear p_mux.
             */
            TO_OR_CIRCUIT(circ)->p_mux = NULL;
            /*
             * Update active_circuits et al.; this does policy notifies, so
             * comes before freeing policy data
             */
            circuitmux_make_circuit_inactive(cmux, circ, CELL_DIRECTION_IN);
          } else {
            /* Complain and move on */
            log_warn(LD_CIRC,
                     "Circuit %d/channel " U64_FORMAT " had direction == "
                     "CELL_DIRECTION_IN, but isn't an or_circuit_t",
                     to_remove->circ_id,
                     U64_PRINTF_ARG(to_remove->chan_id));
          }


          /* Free policy-specific data if we have it */
          if (to_remove->muxinfo.policy_data) {
            /*
             * If we have policy data, assert that we have the means to
             * free it
             */
            tor_assert(cmux->policy);
            tor_assert(cmux->policy->free_circ_data);
            /* Call free_circ_data() */
            cmux->policy->free_circ_data(cmux,
                                         cmux->policy_data,
                                         circ,
                                         to_remove->muxinfo.policy_data);
            to_remove->muxinfo.policy_data = NULL;
          }
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

      /* Assert that we don't have un-freed policy data for this circuit */
      tor_assert(to_remove->muxinfo.policy_data == NULL);

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

  /*
   * Free policy-specific data if we have any; we don't
   * need to do circuitmux_set_policy(cmux, NULL) to cover
   * the circuits because they would have been handled in
   * circuitmux_detach_all_circuits() before this was
   * called.
   */
  if (cmux->policy && cmux->policy->free_cmux_data) {
    if (cmux->policy_data) {
      cmux->policy->free_cmux_data(cmux, cmux->policy_data);
      cmux->policy_data = NULL;
    }
  } else tor_assert(cmux->policy_data == NULL);

  if (cmux->chanid_circid_map) {
    HT_CLEAR(chanid_circid_muxinfo_map, cmux->chanid_circid_map);
    tor_free(cmux->chanid_circid_map);
  }

  tor_free(cmux);
}

/*
 * Circuitmux policy control functions
 */

/**
 * Remove any policy installed on cmux; all policy data will be freed and
 * cmux behavior will revert to the built-in round-robin active_circuits
 * mechanism.
 */

void
circuitmux_clear_policy(circuitmux_t *cmux)
{
  tor_assert(cmux);

  /* Internally, this is just setting policy to NULL */
  if (cmux->policy) {
    circuitmux_set_policy(cmux, NULL);
  }
}

/**
 * Return the policy currently installed on a circuitmux_t
 */

const circuitmux_policy_t *
circuitmux_get_policy(circuitmux_t *cmux)
{
  tor_assert(cmux);

  return cmux->policy;
}

/**
 * Set policy; allocate for new policy, detach all circuits from old policy
 * if any, attach them to new policy, and free old policy data.
 */

void
circuitmux_set_policy(circuitmux_t *cmux,
                      const circuitmux_policy_t *pol)
{
  const circuitmux_policy_t *old_pol = NULL, *new_pol = NULL;
  circuitmux_policy_data_t *old_pol_data = NULL, *new_pol_data = NULL;
  chanid_circid_muxinfo_t **i = NULL;
  channel_t *chan = NULL;
  uint64_t last_chan_id_searched = 0;
  circuit_t *circ = NULL;

  tor_assert(cmux);

  /* Set up variables */
  old_pol = cmux->policy;
  old_pol_data = cmux->policy_data;
  new_pol = pol;

  /* Check if this is the trivial case */
  if (old_pol == new_pol) return;

  /* Allocate data for new policy, if any */
  if (new_pol && new_pol->alloc_cmux_data) {
    /*
     * If alloc_cmux_data is not null, then we expect to get some policy
     * data.  Assert that we also have free_cmux_data so we can free it
     * when the time comes, and allocate it.
     */
    tor_assert(new_pol->free_cmux_data);
    new_pol_data = new_pol->alloc_cmux_data(cmux);
    tor_assert(new_pol_data);
  }

  /* Install new policy and new policy data on cmux */
  cmux->policy = new_pol;
  cmux->policy_data = new_pol_data;

  /* Iterate over all circuits, attaching/detaching each one */
  i = HT_START(chanid_circid_muxinfo_map, cmux->chanid_circid_map);
  while (i) {
    /* Assert that this entry isn't NULL */
    tor_assert(*i);

    /*
     * Get the channel; since normal case is all circuits on the mux share a
     * channel, we cache last_chan_id_searched
     */
    if (!chan || last_chan_id_searched != (*i)->chan_id) {
      chan = channel_find_by_global_id((*i)->chan_id);
      last_chan_id_searched = (*i)->chan_id;
    }
    tor_assert(chan);

    /* Get the circuit */
    circ = circuit_get_by_circid_channel((*i)->circ_id, chan);
    tor_assert(circ);

    /* Need to tell old policy it becomes inactive (i.e., it is active) ? */
    if (old_pol && old_pol->notify_circ_inactive &&
        (*i)->muxinfo.cell_count > 0) {
      old_pol->notify_circ_inactive(cmux, old_pol_data, circ,
                                    (*i)->muxinfo.policy_data);
    }

    /* Need to free old policy data? */
    if ((*i)->muxinfo.policy_data) {
      /* Assert that we have the means to free it if we have policy data */
      tor_assert(old_pol);
      tor_assert(old_pol->free_circ_data);
      /* Free it */
      old_pol->free_circ_data(cmux, old_pol_data, circ,
                             (*i)->muxinfo.policy_data);
      (*i)->muxinfo.policy_data = NULL;
    }

    /* Need to allocate new policy data? */
    if (new_pol && new_pol->alloc_circ_data) {
      /*
       * If alloc_circ_data is not null, we expect to get some per-circuit
       * policy data.  Assert that we also have free_circ_data so we can
       * free it when the time comes, and allocate it.
       */
      tor_assert(new_pol->free_circ_data);
      (*i)->muxinfo.policy_data =
        new_pol->alloc_circ_data(cmux, new_pol_data, circ,
                                 (*i)->muxinfo.direction,
                                 (*i)->muxinfo.cell_count);
    }

    /* Need to make active on new policy? */
    if (new_pol && new_pol->notify_circ_active &&
        (*i)->muxinfo.cell_count > 0) {
      new_pol->notify_circ_active(cmux, new_pol_data, circ,
                                  (*i)->muxinfo.policy_data);
    }

    /* Advance to next circuit map entry */
    i = HT_NEXT(chanid_circid_muxinfo_map, cmux->chanid_circid_map, i);
  }

  /* Free data for old policy, if any */
  if (old_pol_data) {
    /*
     * If we had old policy data, we should have an old policy and a free
     * function for it.
     */
    tor_assert(old_pol);
    tor_assert(old_pol->free_cmux_data);
    old_pol->free_cmux_data(cmux, old_pol_data);
    old_pol_data = NULL;
  }
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
      circuitmux_make_circuit_inactive(cmux, circ, direction);
    } else if (hashent->muxinfo.cell_count == 0 && cell_count > 0) {
      ++(cmux->n_active_circuits);
      circuitmux_make_circuit_active(cmux, circ, direction);
    }
    cmux->n_cells -= hashent->muxinfo.cell_count;
    cmux->n_cells += cell_count;
    hashent->muxinfo.cell_count = cell_count;
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
    /* Allocate policy specific circuit data if we need it */
    if (cmux->policy && cmux->policy->alloc_circ_data) {
      /* Assert that we have the means to free policy-specific data */
      tor_assert(cmux->policy->free_circ_data);
      /* Allocate it */
      hashent->muxinfo.policy_data =
        cmux->policy->alloc_circ_data(cmux,
                                      cmux->policy_data,
                                      circ,
                                      direction,
                                      cell_count);
      /* If we wanted policy data, it's an error  not to get any */
      tor_assert(hashent->muxinfo.policy_data);
    }
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
    if (hashent->muxinfo.cell_count > 0) {
      --(cmux->n_active_circuits);
      /* This does policy notifies, so comes before freeing policy data */
      circuitmux_make_circuit_inactive(cmux, circ, last_searched_direction);
    }
    cmux->n_cells -= hashent->muxinfo.cell_count;

    /* Free policy-specific data if we have it */
    if (hashent->muxinfo.policy_data) {
      /* If we have policy data, assert that we have the means to free it */
      tor_assert(cmux->policy);
      tor_assert(cmux->policy->free_circ_data);
      /* Call free_circ_data() */
      cmux->policy->free_circ_data(cmux,
                                   cmux->policy_data,
                                   circ,
                                   hashent->muxinfo.policy_data);
      hashent->muxinfo.policy_data = NULL;
    }

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
 * Make a circuit active; update active list and policy-specific info, but
 * we don't mess with the counters or hash table here.
 */

static void
circuitmux_make_circuit_active(circuitmux_t *cmux, circuit_t *circ,
                               cell_direction_t direction)
{
  circuit_t **next_active = NULL, **prev_active = NULL, **next_prev = NULL;
  circuitmux_t *circuit_cmux = NULL;
  chanid_circid_muxinfo_t *hashent = NULL;
  channel_t *chan = NULL;
  circid_t circ_id;
  int already_active;

  tor_assert(cmux);
  tor_assert(circ);
  tor_assert(direction == CELL_DIRECTION_OUT ||
             direction == CELL_DIRECTION_IN);

  /* Get the right set of active list links for this direction */
  if (direction == CELL_DIRECTION_OUT) {
    next_active = &(circ->next_active_on_n_chan);
    prev_active = &(circ->prev_active_on_n_chan);
    circuit_cmux = circ->n_mux;
    chan = circ->n_chan;
    circ_id = circ->n_circ_id;
  } else {
    next_active = &(TO_OR_CIRCUIT(circ)->next_active_on_p_chan);
    prev_active = &(TO_OR_CIRCUIT(circ)->prev_active_on_p_chan);
    circuit_cmux = TO_OR_CIRCUIT(circ)->p_mux;
    chan = TO_OR_CIRCUIT(circ)->p_chan;
    circ_id = TO_OR_CIRCUIT(circ)->p_circ_id;
  }

  /* Assert that it is attached to this mux and a channel */
  tor_assert(cmux == circuit_cmux);
  tor_assert(chan != NULL);

  /*
   * Check if the circuit really was inactive; if it's active, at least one
   * of the next_active and prev_active pointers will not be NULL, or this
   * circuit will be either the head or tail of the list for this cmux.
   */
  already_active = (*prev_active != NULL || *next_active != NULL ||
                    cmux->active_circuits_head == circ ||
                    cmux->active_circuits_tail == circ);

  /* If we're already active, log a warning and finish */
  if (already_active) {
    log_warn(LD_CIRC,
             "Circuit %d on channel " U64_FORMAT " was already active",
             circ_id, U64_PRINTF_ARG(chan->global_identifier));
    return;
  }

  /*
   * This is going at the head of the list; if the old head is not NULL,
   * then its prev pointer should point to this.
   */
  *next_active = cmux->active_circuits_head; /* Next is old head */
  *prev_active = NULL; /* Prev is NULL (this will be the head) */
  if (cmux->active_circuits_head) {
    /* The list had an old head; update its prev pointer */
    next_prev =
      circuitmux_prev_active_circ_p(cmux, cmux->active_circuits_head);
    tor_assert(next_prev);
    *next_prev = circ;
  } else {
    /* The list was empty; this becomes the tail as well */
    cmux->active_circuits_tail = circ;
  }
  /* This becomes the new head of the list */
  cmux->active_circuits_head = circ;

  /* Policy-specific notification */
  if (cmux->policy &&
      cmux->policy->notify_circ_active) {
    /* Okay, we need to check the circuit for policy data now */
    hashent = circuitmux_find_map_entry(cmux, circ);
    /* We should have found something */
    tor_assert(hashent);
    /* Notify */
    cmux->policy->notify_circ_active(cmux, cmux->policy_data,
                                     circ, hashent->muxinfo.policy_data);
  }
}

/**
 * Make a circuit inactive; update active list and policy-specific info, but
 * we don't mess with the counters or hash table here.
 */

static void
circuitmux_make_circuit_inactive(circuitmux_t *cmux, circuit_t *circ,
                                 cell_direction_t direction)
{
  circuit_t **next_active = NULL, **prev_active = NULL;
  circuit_t **next_prev = NULL, **prev_next = NULL;
  circuitmux_t *circuit_cmux = NULL;
  chanid_circid_muxinfo_t *hashent = NULL;
  channel_t *chan = NULL;
  circid_t circ_id;
  int already_inactive;

  tor_assert(cmux);
  tor_assert(circ);
  tor_assert(direction == CELL_DIRECTION_OUT ||
             direction == CELL_DIRECTION_IN);

  /* Get the right set of active list links for this direction */
  if (direction == CELL_DIRECTION_OUT) {
    next_active = &(circ->next_active_on_n_chan);
    prev_active = &(circ->prev_active_on_n_chan);
    circuit_cmux = circ->n_mux;
    chan = circ->n_chan;
    circ_id = circ->n_circ_id;
  } else {
    next_active = &(TO_OR_CIRCUIT(circ)->next_active_on_p_chan);
    prev_active = &(TO_OR_CIRCUIT(circ)->prev_active_on_p_chan);
    circuit_cmux = TO_OR_CIRCUIT(circ)->p_mux;
    chan = TO_OR_CIRCUIT(circ)->p_chan;
    circ_id = TO_OR_CIRCUIT(circ)->p_circ_id;
  }

  /* Assert that it is attached to this mux and a channel */
  tor_assert(cmux == circuit_cmux);
  tor_assert(chan != NULL);

  /*
   * Check if the circuit really was active; if it's inactive, the
   * next_active and prev_active pointers will be NULL and this circuit
   * will not be the head or tail of the list for this cmux.
   */
  already_inactive = (*prev_active == NULL && *next_active == NULL &&
                      cmux->active_circuits_head != circ &&
                      cmux->active_circuits_tail != circ);

  /* If we're already inactive, log a warning and finish */
  if (already_inactive) {
    log_warn(LD_CIRC,
             "Circuit %d on channel " U64_FORMAT " was already inactive",
             circ_id, U64_PRINTF_ARG(chan->global_identifier));
    return;
  }

  /* Remove from the list; first get next_prev and prev_next */
  if (*next_active) {
    /*
     * If there's a next circuit, its previous circuit becomes this
     * circuit's previous circuit.
     */
    next_prev = circuitmux_prev_active_circ_p(cmux, *next_active);
  } else {
    /* Else, the tail becomes this circuit's previous circuit */
    next_prev = &(cmux->active_circuits_tail);
  }

  /* Got next_prev, now prev_next */
  if (*prev_active) {
    /*
     * If there's a previous circuit, its next circuit becomes this circuit's
     * next circuit.
     */
    prev_next = circuitmux_next_active_circ_p(cmux, *prev_active);
  } else {
    /* Else, the head becomes this circuit's next circuit */
    prev_next = &(cmux->active_circuits_head);
  }

  /* Assert that we got sensible values for the next/prev pointers */
  tor_assert(next_prev != NULL);
  tor_assert(prev_next != NULL);

  /* Update the next/prev pointers - this removes circ from the list */
  *next_prev = *prev_active;
  *prev_next = *next_active;

  /* Now null out prev_active/next_active */
  *prev_active = NULL;
  *next_active = NULL;

  /* Policy-specific notification */
  if (cmux->policy &&
      cmux->policy->notify_circ_inactive) {
    /* Okay, we need to check the circuit for policy data now */
    hashent = circuitmux_find_map_entry(cmux, circ);
    /* We should have found something */
    tor_assert(hashent);
    /* Notify */
    cmux->policy->notify_circ_inactive(cmux, cmux->policy_data,
                                       circ, hashent->muxinfo.policy_data);
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

  /* Do we need to notify a cmux policy? */
  if (cmux->policy && cmux->policy->notify_set_n_cells) {
    /* Call notify_set_n_cells */
    cmux->policy->notify_set_n_cells(cmux,
                                     cmux->policy_data,
                                     circ,
                                     hashent->muxinfo.policy_data,
                                     n_cells);
  }

  /*
   * Update cmux active circuit counter: is the old cell count > 0 and the
   * new cell count == 0 ?
   */
  if (hashent->muxinfo.cell_count > 0 && n_cells == 0) {
    --(cmux->n_active_circuits);
    circuitmux_make_circuit_inactive(cmux, circ, hashent->muxinfo.direction);
  /* Is the old cell count == 0 and the new cell count > 0 ? */
  } else if (hashent->muxinfo.cell_count == 0 && n_cells > 0) {
    ++(cmux->n_active_circuits);
    circuitmux_make_circuit_active(cmux, circ, hashent->muxinfo.direction);
  }

  /* Update hash entry cell counter */
  hashent->muxinfo.cell_count = n_cells;
}

/*
 * Functions for channel code to call to get a circuit to transmit from or
 * notify that cells have been transmitted.
 */

void
circuitmux_notify_xmit_cells(circuitmux_t *cmux, circuit_t *circ,
                             unsigned int n_cells)
{
  chanid_circid_muxinfo_t *hashent = NULL;
  int becomes_inactive = 0;

  tor_assert(cmux);
  tor_assert(circ);

  if (n_cells == 0) return;

  /*
   * To handle this, we have to:
   *
   * 1.) Adjust the circuit's cell counter in the cmux hash table
   * 2.) Move the circuit to the tail of the active_circuits linked list
   *     for this cmux, or make the circuit inactive if the cell count
   *     went to zero.
   * 3.) Call cmux->policy->notify_xmit_cells(), if any
   */

  /* Find the hash entry */
  hashent = circuitmux_find_map_entry(cmux, circ);
  /* Assert that we found one */
  tor_assert(hashent);

  /* Adjust the cell counter and assert that we had that many cells to send */
  tor_assert(n_cells <= hashent->muxinfo.cell_count);
  hashent->muxinfo.cell_count -= n_cells;
  /* Do we need to make the circuit inactive? */
  if (hashent->muxinfo.cell_count == 0) becomes_inactive = 1;

  /* If we aren't making it inactive later, move it to the tail of the list */
  if (!becomes_inactive) {
    circuitmux_move_active_circ_to_tail(cmux, circ,
                                        hashent->muxinfo.direction);
  }

  /*
   * We call notify_xmit_cells() before making the circuit inactive if needed,
   * so the policy can always count on this coming in on an active circuit.
   */
  if (cmux->policy && cmux->policy->notify_xmit_cells) {
    cmux->policy->notify_xmit_cells(cmux, cmux->policy_data, circ,
                                    hashent->muxinfo.policy_data,
                                    n_cells);
  }

  /*
   * Now make the circuit inactive if needed; this will call the policy's
   * notify_circ_inactive() if present. 
   */
  if (becomes_inactive) {
    --(cmux->n_active_circuits);
    circuitmux_make_circuit_inactive(cmux, circ, hashent->muxinfo.direction);
  }
}

