/* * Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file channel.c
 * \brief OR-to-OR channel abstraction layer
 **/

/*
 * Define this so channel.h gives us things only channel_t subclasses
 * should touch.
 */

#define _TOR_CHANNEL_INTERNAL

#include "or.h"
#include "channel.h"
#include "channeltls.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "geoip.h"
#include "nodelist.h"
#include "relay.h"
#include "rephist.h"
#include "router.h"
#include "routerlist.h"

/* Cell queue structure */

typedef struct cell_queue_entry_s cell_queue_entry_t;
struct cell_queue_entry_s {
  enum {
    CELL_QUEUE_FIXED,
    CELL_QUEUE_VAR,
    CELL_QUEUE_PACKED
  } type;
  union {
    struct {
      cell_t *cell;
    } fixed;
    struct {
      var_cell_t *var_cell;
    } var;
    struct {
      packed_cell_t *packed_cell;
    } packed;
  } u;
};

/* Global lists of channels */

/* All channel_t instances */
static smartlist_t *all_channels = NULL;

/* All channel_t instances not in ERROR or CLOSED states */
static smartlist_t *active_channels = NULL;

/* All channel_t instances in LISTENING state */
static smartlist_t *listening_channels = NULL;

/* All channel_t instances in ERROR or CLOSED states */
static smartlist_t *finished_channels = NULL;

/* Counter for ID numbers */
static uint64_t n_channels_allocated = 0;

/* Digest->channel map
 *
 * Similar to the one used in connection_or.c, this maps from the identity
 * digest of a remote endpoint to a channel_t to that endpoint.  Channels
 * should be placed here when registered and removed when they close or error.
 * If more than one channel exists, follow the next_with_same_id pointer
 * as a linked list.
 */
static digestmap_t *channel_identity_map = NULL;

/* Functions to maintain the digest map */
static void channel_add_to_digest_map(channel_t *chan);
static void channel_remove_from_digest_map(channel_t *chan);

/*
 * Flush cells from just the outgoing queue without trying to get them
 * from circuits; used internall by channel_flush_some_cells().
 */
static ssize_t
channel_flush_some_cells_from_outgoing_queue(channel_t *chan,
                                             ssize_t num_cells);

/***********************************
 * Channel state utility functions *
 **********************************/

/**
 * Indicate whether a given channel state is valid
 *
 * @param state A channel state
 * @return A boolean value indicating whether state is a valid channel state
 */

int
channel_state_is_valid(channel_state_t state)
{
  int is_valid;

  switch (state) {
    case CHANNEL_STATE_CLOSED:
    case CHANNEL_STATE_CLOSING:
    case CHANNEL_STATE_ERROR:
    case CHANNEL_STATE_LISTENING:
    case CHANNEL_STATE_MAINT:
    case CHANNEL_STATE_OPENING:
    case CHANNEL_STATE_OPEN:
      is_valid = 1;
      break;
    case CHANNEL_STATE_LAST:
    default:
      is_valid = 0;
  }

  return is_valid;
}

/**
 * Indicate whether a channel state transition is valid
 *
 * This function takes two channel states and indicates whether a
 * transition between them is permitted (see the state definitions and
 * transition table in or.h at the channel_state_t typedef).
 *
 * @param from Proposed state to transition from
 * @param to Proposed state to transition to
 * @return A boolean value indicating whether the posposed transition is valid
 */

int
channel_state_can_transition(channel_state_t from, channel_state_t to)
{
  int is_valid;

  switch (from) {
    case CHANNEL_STATE_CLOSED:
      is_valid = (to == CHANNEL_STATE_LISTENING ||
                  to == CHANNEL_STATE_OPENING);
      break;
    case CHANNEL_STATE_CLOSING:
      is_valid = (to == CHANNEL_STATE_CLOSED ||
                  to == CHANNEL_STATE_ERROR);
      break;
    case CHANNEL_STATE_ERROR:
      is_valid = 0;
      break;
    case CHANNEL_STATE_LISTENING:
      is_valid = (to == CHANNEL_STATE_CLOSING ||
                  to == CHANNEL_STATE_ERROR);
      break;
    case CHANNEL_STATE_MAINT:
      is_valid = (to == CHANNEL_STATE_CLOSING ||
                  to == CHANNEL_STATE_ERROR ||
                  to == CHANNEL_STATE_OPEN);
      break;
    case CHANNEL_STATE_OPENING:
      is_valid = (to == CHANNEL_STATE_CLOSING ||
                  to == CHANNEL_STATE_ERROR ||
                  to == CHANNEL_STATE_OPEN);
      break;
    case CHANNEL_STATE_OPEN:
      is_valid = (to == CHANNEL_STATE_CLOSING ||
                  to == CHANNEL_STATE_ERROR ||
                  to == CHANNEL_STATE_MAINT);
      break;
    case CHANNEL_STATE_LAST:
    default:
      is_valid = 0;
  }

  return is_valid;
}

/**
 * Return a human-readable description for a channel state
 *
 * @param state A channel state
 * @return A pointer to a string with a human-readable description of state
 */

const char *
channel_state_to_string(channel_state_t state)
{
  const char *descr;

  switch (state) {
    case CHANNEL_STATE_CLOSED:
      descr = "closed";
      break;
    case CHANNEL_STATE_CLOSING:
      descr = "closing";
      break;
    case CHANNEL_STATE_ERROR:
      descr = "channel error";
      break;
    case CHANNEL_STATE_LISTENING:
      descr = "listening";
      break;
    case CHANNEL_STATE_MAINT:
      descr = "temporarily suspended for maintenance";
      break;
    case CHANNEL_STATE_OPENING:
      descr = "opening";
      break;
    case CHANNEL_STATE_OPEN:
      descr = "open";
      break;
    case CHANNEL_STATE_LAST:
    default:
      descr = "unknown or invalid channel state";
  }

  return descr;
}

/***************************************
 * Channel registration/unregistration *
 ***************************************/

/**
 * Register a channel
 *
 * This function registers a newly created channel in the global lists/maps
 * of active channels.
 *
 * @param chan A pointer to an unregistered channel
 */

void
channel_register(channel_t *chan)
{
  tor_assert(chan);

  /* No-op if already registered */
  if (chan->registered) return;

  if (chan->is_listener) {
    log_debug(LD_CHANNEL,
              "Registering listener channel %p (ID " U64_FORMAT ") "
              "in state %s (%d)",
              chan, U64_PRINTF_ARG(chan->global_identifier),
              channel_state_to_string(chan->state), chan->state);
  } else {
    log_debug(LD_CHANNEL,
              "Registering cell channel %p (ID " U64_FORMAT ") "
              "in state %s (%d) with digest %s",
              chan, U64_PRINTF_ARG(chan->global_identifier),
              channel_state_to_string(chan->state), chan->state,
              hex_str(chan->u.cell_chan.identity_digest, DIGEST_LEN));
  }

  /* Make sure we have all_channels, then add it */
  if (!all_channels) all_channels = smartlist_new();
  smartlist_add(all_channels, chan);

  /* Is it finished? */
  if (chan->state == CHANNEL_STATE_CLOSED ||
      chan->state == CHANNEL_STATE_ERROR) {
    /* Put it in the finished list, creating it if necessary */
    if (!finished_channels) finished_channels = smartlist_new();
    smartlist_add(finished_channels, chan);
  } else {
    /* Put it in the active list, creating it if necessary */
    if (!active_channels) active_channels = smartlist_new();
    smartlist_add(active_channels, chan);

    /* Is it a listener? */
    if (chan->is_listener &&
        chan->state == CHANNEL_STATE_LISTENING) {
      /* Put it in the listening list, creating it if necessary */
      if (!listening_channels) listening_channels = smartlist_new();
      smartlist_add(listening_channels, chan);
    } else if (chan->state != CHANNEL_STATE_CLOSING) {
      if (!(chan->is_listener)) {
        /* It should have a digest set */
        if (!tor_digest_is_zero(chan->u.cell_chan.identity_digest)) {
          /* Yeah, we're good, add it to the map */
          channel_add_to_digest_map(chan);
        } else {
          log_info(LD_CHANNEL,
                  "Channel %p (global ID " U64_FORMAT ") "
                  "in state %s (%d) registered with no identity digest",
                  chan, U64_PRINTF_ARG(chan->global_identifier),
                  channel_state_to_string(chan->state), chan->state);
        }
      }
    }
  }

  /* Mark it as registered */
  chan->registered = 1;
}

/**
 * Unregister a channel
 *
 * This function removes a channel from the global lists and maps and is used
 * when freeing a closed/errored channel.
 *
 * @param chan A pointer to a channel to be unregistered
 */

void
channel_unregister(channel_t *chan)
{
  tor_assert(chan);

  /* No-op if not registered */
  if (!(chan->registered)) return;

  /* Is it finished? */
  if (chan->state == CHANNEL_STATE_CLOSED ||
      chan->state == CHANNEL_STATE_ERROR) {
    /* Get it out of the finished list */
    if (finished_channels) smartlist_remove(finished_channels, chan);
  } else {
    /* Get it out of the active list */
    if (active_channels) smartlist_remove(active_channels, chan);

    /* Is it listening? */
    if (chan->state == CHANNEL_STATE_LISTENING) {
      /* Get it out of the listening list */
      if (listening_channels) smartlist_remove(listening_channels, chan);
    }
  }

  /* Get it out of all_channels */
 if (all_channels) smartlist_remove(all_channels, chan);

  /* Mark it as unregistered */
  chan->registered = 0;

  if (!(chan->is_listener)) {
    /* Should it be in the digest map? */
    if (!tor_digest_is_zero(chan->u.cell_chan.identity_digest) &&
        !(chan->state == CHANNEL_STATE_LISTENING ||
          chan->state == CHANNEL_STATE_CLOSING ||
          chan->state == CHANNEL_STATE_CLOSED ||
          chan->state == CHANNEL_STATE_ERROR)) {
      /* Remove it */
      channel_remove_from_digest_map(chan);
    }
  }
}

/*********************************
 * Channel digest map maintenance
 *********************************/

/**
 * Add a channel to the digest map
 *
 * This function adds a channel to the digest map and inserts it into the
 * correct linked list if channels with that remote endpoint identity digest
 * already exist.
 *
 * @param chan A pointer to a channel to add
 */

static void
channel_add_to_digest_map(channel_t *chan)
{
  channel_t *tmp;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  /* Assert that the state makes sense */
  tor_assert(!(chan->state == CHANNEL_STATE_LISTENING ||
               chan->state == CHANNEL_STATE_CLOSING ||
               chan->state == CHANNEL_STATE_CLOSED ||
               chan->state == CHANNEL_STATE_ERROR));

  /* Assert that there is a digest */
  tor_assert(!tor_digest_is_zero(chan->u.cell_chan.identity_digest));

  /* Allocate the identity map if we have to */
  if (!channel_identity_map) channel_identity_map = digestmap_new();

  /* Insert it */
  tmp = digestmap_set(channel_identity_map,
                      chan->u.cell_chan.identity_digest,
                      chan);
  if (tmp) {
    tor_assert(!(tmp->is_listener));
    /* There already was one, this goes at the head of the list */
    chan->u.cell_chan.next_with_same_id = tmp;
    chan->u.cell_chan.prev_with_same_id = NULL;
    tmp->u.cell_chan.prev_with_same_id = chan;
  } else {
    /* First with this digest */
    chan->u.cell_chan.next_with_same_id = NULL;
    chan->u.cell_chan.prev_with_same_id = NULL;
  }

  log_debug(LD_CHANNEL,
            "Added channel %p (global ID " U64_FORMAT ") "
            "to identity map in state %s (%d) with digest %s",
            chan, U64_PRINTF_ARG(chan->global_identifier),
            channel_state_to_string(chan->state), chan->state,
            hex_str(chan->u.cell_chan.identity_digest, DIGEST_LEN));
}

/**
 * Remove a channel from the digest map
 *
 * This function removes a channel from the digest map and the linked list of
 * channels for that digest if more than one exists.
 *
 * @param chan A pointer to a channel to remove
 */

static void
channel_remove_from_digest_map(channel_t *chan)
{
  channel_t *tmp, *head;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  /* Assert that there is a digest */
  tor_assert(!tor_digest_is_zero(chan->u.cell_chan.identity_digest));

  /* Make sure we have a map */
  if (!channel_identity_map) {
    /*
     * No identity map, so we can't find it by definition.  This
     * case is similar to digestmap_get() failing below.
     */
    log_warn(LD_BUG,
             "Trying to remove channel %p (global ID " U64_FORMAT ") "
             "with digest %s from identity map, but didn't have any identity "
             "map",
             chan, U64_PRINTF_ARG(chan->global_identifier),
             hex_str(chan->u.cell_chan.identity_digest, DIGEST_LEN));
    /* Clear out its next/prev pointers */
    if (chan->u.cell_chan.next_with_same_id) {
      tor_assert(!(chan->u.cell_chan.next_with_same_id->is_listener));
      chan->u.cell_chan.next_with_same_id->u.cell_chan.prev_with_same_id
        = chan->u.cell_chan.prev_with_same_id;
    }
    if (chan->u.cell_chan.prev_with_same_id) {
      tor_assert(!(chan->u.cell_chan.prev_with_same_id->is_listener));
      chan->u.cell_chan.prev_with_same_id->u.cell_chan.next_with_same_id
        = chan->u.cell_chan.next_with_same_id;
    }
    chan->u.cell_chan.next_with_same_id = NULL;
    chan->u.cell_chan.prev_with_same_id = NULL;

    return;
  }

  /* Look for it in the map */
  tmp = digestmap_get(channel_identity_map, chan->u.cell_chan.identity_digest);
  if (tmp) {
    /* Okay, it's here */
    head = tmp; /* Keep track of list head */
    /* Look for this channel */
    while (tmp && tmp != chan) {
      tor_assert(!(tmp->is_listener));
      tmp = tmp->u.cell_chan.next_with_same_id;
    }

    if (tmp == chan) {
      /* Found it, good */
      if (chan->u.cell_chan.next_with_same_id) {
        tor_assert(!(chan->u.cell_chan.next_with_same_id->is_listener));
        chan->u.cell_chan.next_with_same_id->u.cell_chan.prev_with_same_id
          = chan->u.cell_chan.prev_with_same_id;
      }
      /* else we're the tail of the list */
      if (chan->u.cell_chan.prev_with_same_id) {
        tor_assert(!(chan->u.cell_chan.prev_with_same_id->is_listener));
        /* We're not the head of the list, so we can *just* unlink */
        chan->u.cell_chan.prev_with_same_id->u.cell_chan.next_with_same_id
          = chan->u.cell_chan.next_with_same_id;
      } else {
        /* We're the head, so we have to point the digest map entry at our
         * next if we have one, or remove it if we're also the tail */
        if (chan->u.cell_chan.next_with_same_id) {
          tor_assert(!(chan->u.cell_chan.next_with_same_id->is_listener));
          digestmap_set(channel_identity_map,
                        chan->u.cell_chan.identity_digest,
                        chan->u.cell_chan.next_with_same_id);
        } else {
          digestmap_remove(channel_identity_map,
                           chan->u.cell_chan.identity_digest);
        }
      }

      /* NULL out its next/prev pointers, and we're finished */
      chan->u.cell_chan.next_with_same_id = NULL;
      chan->u.cell_chan.prev_with_same_id = NULL;

      log_debug(LD_CHANNEL,
                "Removed channel %p (global ID " U64_FORMAT ") from "
                "identity map in state %s (%d) with digest %s",
                chan, U64_PRINTF_ARG(chan->global_identifier),
                channel_state_to_string(chan->state), chan->state,
                hex_str(chan->u.cell_chan.identity_digest, DIGEST_LEN));
    } else {
      /* This is not good */
      log_warn(LD_BUG,
               "Trying to remove channel %p (global ID " U64_FORMAT ") "
               "with digest %s from identity map, but couldn't find it in "
               "the list for that digest",
               chan, U64_PRINTF_ARG(chan->global_identifier),
               hex_str(chan->u.cell_chan.identity_digest, DIGEST_LEN));
      /* Unlink it and hope for the best */
      if (chan->u.cell_chan.next_with_same_id) {
        tor_assert(!(chan->u.cell_chan.next_with_same_id->is_listener));
        chan->u.cell_chan.next_with_same_id->u.cell_chan.prev_with_same_id
          = chan->u.cell_chan.prev_with_same_id;
      }
      if (chan->u.cell_chan.prev_with_same_id) {
        tor_assert(!(chan->u.cell_chan.prev_with_same_id->is_listener));
        chan->u.cell_chan.prev_with_same_id->u.cell_chan.next_with_same_id
          = chan->u.cell_chan.next_with_same_id;
      }
      chan->u.cell_chan.next_with_same_id = NULL;
      chan->u.cell_chan.prev_with_same_id = NULL;
    }
  } else {
    /* Shouldn't happen */
    log_warn(LD_BUG,
             "Trying to remove channel %p (global ID " U64_FORMAT ") with "
             "digest %s from identity map, but couldn't find any with "
             "that digest",
             chan, U64_PRINTF_ARG(chan->global_identifier),
             hex_str(chan->u.cell_chan.identity_digest, DIGEST_LEN));
    /* Clear out its next/prev pointers */
    if (chan->u.cell_chan.next_with_same_id) {
      tor_assert(!(chan->u.cell_chan.next_with_same_id->is_listener));
      chan->u.cell_chan.next_with_same_id->u.cell_chan.prev_with_same_id
        = chan->u.cell_chan.prev_with_same_id;
    }
    if (chan->u.cell_chan.prev_with_same_id) {
      chan->u.cell_chan.prev_with_same_id->u.cell_chan.next_with_same_id
        = chan->u.cell_chan.next_with_same_id;
    }
    chan->u.cell_chan.next_with_same_id = NULL;
    chan->u.cell_chan.prev_with_same_id = NULL;
  }
}

/****************************
 * Channel lookup functions *
 ***************************/

/**
 * Find channel by global ID
 *
 * This function searches for a channel by the global_identifier assigned
 * at initialization time.  This identifier is unique for the lifetime of the
 * Tor process.
 *
 * @param global_identifier The global_identifier value to search for
 * @return A pointer to the channel with that global identifier, or NULL if
 *         none exists.
 */

channel_t *
channel_find_by_global_id(uint64_t global_identifier)
{
  channel_t *rv = NULL;

  if (all_channels && smartlist_len(all_channels) > 0) {
    SMARTLIST_FOREACH_BEGIN(all_channels, channel_t *, curr) {
      if (curr->global_identifier == global_identifier) {
        rv = curr;
        break;
      }
    } SMARTLIST_FOREACH_END(curr);
  }

  return rv;
}

/**
 * Find channel by digest of the remote endpoint
 *
 * This function looks up a channel by the digest of its remote endpoint in
 * the channel digest map.  It's possible that more than one channel to a
 * given endpoint exists.  Use channel_next_with_digest() and
 * channel_prev_with_digest() to walk the list.
 *
 * @param identity_digest A digest to search for
 * @return A channel pointer, or NULL if no channel to this endpoint exists.
 */

channel_t *
channel_find_by_remote_digest(const char *identity_digest)
{
  channel_t *rv = NULL, *tmp;

  tor_assert(identity_digest);

  /* Search for it in the identity map */
  if (channel_identity_map) {
    tmp = digestmap_get(channel_identity_map, identity_digest);
    rv = tmp;
  }

  return rv;
}

/**
 * Find channel by remote nickname
 *
 * This function looks up a channel by the nickname of the remote
 * endpoint.  It's possible that more than one channel to that endpoint
 * nickname exists, but there is not currently any supported way to iterate
 * them.  Use digests.
 *
 * @param nickname A node nickname
 * @return A channel pointer to a channel to a node with that nickname, or
 *         NULL if none is available.
 */

channel_t *
channel_find_by_remote_nickname(const char *nickname)
{
  channel_t *rv = NULL;

  tor_assert(nickname);

  if (all_channels && smartlist_len(all_channels) > 0) {
    SMARTLIST_FOREACH_BEGIN(all_channels, channel_t *, curr) {
      if (!(curr->is_listener)) {
        if (curr->u.cell_chan.nickname &&
            strncmp(curr->u.cell_chan.nickname, nickname,
                    MAX_NICKNAME_LEN) == 0) {
          rv = curr;
          break;
        }
      }
    } SMARTLIST_FOREACH_END(curr);
  }

  return rv;
}

/**
 * Next channel with digest
 *
 * This function takes a channel and finds the next channel in the list
 * with the same digest.
 *
 * @param chan Channel pointer to iterate
 * @return A pointer to the next channel after chan with the same remote
 *         endpoint identity digest, or NULL if none exists.
 */

channel_t *
channel_next_with_digest(channel_t *chan)
{
  channel_t *rv = NULL;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  if (chan->u.cell_chan.next_with_same_id)
    rv = chan->u.cell_chan.next_with_same_id;

  return rv;
}

/**
 * Previous channel with digest
 *
 * This function takes a channel and finds the previos channel in the list
 * with the same digest.
 *
 * @param chan Channel pointer to iterate
 * @return A pointer to the previous channel after chan with the same remote
 *         endpoint identity digest, or NULL if none exists.
 */

channel_t *
channel_prev_with_digest(channel_t *chan)
{
  channel_t *rv = NULL;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  if (chan->u.cell_chan.prev_with_same_id)
    rv = chan->u.cell_chan.prev_with_same_id;

  return rv;
}

/**
 * Internal-only channel init function for cell channels
 *
 * This function should be called by subclasses to set up some per-channel
 * variables.  I.e., this is the superclass constructor.  Before this, the
 * channel should be allocated with tor_malloc_zero().
 *
 * @param chan Pointer to a channel to initialize.
 */

void
channel_init_for_cells(channel_t *chan)
{
  tor_assert(chan);

  /* Assign an ID and bump the counter */
  chan->global_identifier = n_channels_allocated++;

  /* Mark as a non-listener */
  chan->is_listener = 0;

  /* Init timestamp */
  chan->u.cell_chan.timestamp_last_added_nonpadding = time(NULL);

  /* Init next_circ_id */
  chan->u.cell_chan.next_circ_id = crypto_rand_int(1 << 15);

  /* Timestamp it */
  channel_timestamp_created(chan);
}

/**
 * Internal-only channel init function for listener channels
 *
 * This function should be called by subclasses to set up some per-channel
 * variables.  I.e., this is the superclass constructor.  Before this, the
 * channel should be allocated with tor_malloc_zero().
 *
 * @param chan Pointer to a channel to initialize.
 */

void
channel_init_listener(channel_t *chan)
{
  tor_assert(chan);

  /* Assign an ID and bump the counter */
  chan->global_identifier = n_channels_allocated++;

  /* Mark as a listener */
  chan->is_listener = 1;

  /* Timestamp it */
  channel_timestamp_created(chan);
}

/**
 * Internal-only channel free function
 *
 * Nothing outside of channel.c should call this; it frees channels after
 * they have closed and been unregistered.
 *
 * @param chan Channel to free
 */

void
channel_free(channel_t *chan)
{
  tor_assert(chan);
  /* It must be closed or errored */
  tor_assert(chan->state == CHANNEL_STATE_CLOSED ||
             chan->state == CHANNEL_STATE_ERROR);
  /* It must be deregistered */
  tor_assert(!(chan->registered));

  /* Call a free method if there is one */
  if (chan->free) chan->free(chan);

  if (!(chan->is_listener)) {
    channel_clear_remote_end(chan);

    if (chan->u.cell_chan.active_circuit_pqueue) {
      smartlist_free(chan->u.cell_chan.active_circuit_pqueue);
      chan->u.cell_chan.active_circuit_pqueue = NULL;
    }
  }

  /* We're in CLOSED or ERROR, so the cell queue is already empty */

  tor_free(chan);
}

/**
 * Internal-only forcible channel free function
 *
 * This is like channel_free, but doesn't do the state/registration asserts;
 * it should only be used from channel_free_all() when shutting down.
 */

void
channel_force_free(channel_t *chan)
{
  cell_queue_entry_t *tmp = NULL;
  channel_t *tmpchan = NULL;

  tor_assert(chan);

  /* Call a free method if there is one */
  if (chan->free) chan->free(chan);

  if (chan->is_listener) {
    /*
     * The incoming list just gets emptied and freed; we request close on
     * any channels we find there, but since we got called while shutting
     * down they will get deregistered and freed elsewhere anyway.
     */
    if (chan->u.listener.incoming_list) {
      SMARTLIST_FOREACH_BEGIN(chan->u.listener.incoming_list,
                              channel_t *, qchan) {
        tmpchan = qchan;
        SMARTLIST_DEL_CURRENT(chan->u.listener.incoming_list, qchan);
        channel_request_close(tmpchan);
      } SMARTLIST_FOREACH_END(qchan);

      smartlist_free(chan->u.listener.incoming_list);
      chan->u.listener.incoming_list = NULL;
    }
  } else {
    channel_clear_remote_end(chan);
    smartlist_free(chan->u.cell_chan.active_circuit_pqueue);

    /* We might still have a cell queue; kill it */
    if (chan->u.cell_chan.cell_queue) {
      SMARTLIST_FOREACH_BEGIN(chan->u.cell_chan.cell_queue,
                              cell_queue_entry_t *, q) {
        tmp = q;
        SMARTLIST_DEL_CURRENT(chan->u.cell_chan.cell_queue, q);
        tor_free(q);
      } SMARTLIST_FOREACH_END(q);

      smartlist_free(chan->u.cell_chan.cell_queue);
      chan->u.cell_chan.cell_queue = NULL;
    }

    /* Outgoing cell queue is similar, but we can have to free packed cells */
    if (chan->u.cell_chan.outgoing_queue) {
      SMARTLIST_FOREACH_BEGIN(chan->u.cell_chan.outgoing_queue,
                              cell_queue_entry_t *, q) {
        tmp = q;
        SMARTLIST_DEL_CURRENT(chan->u.cell_chan.outgoing_queue, q);
        if (tmp->type == CELL_QUEUE_PACKED) {
          if (tmp->u.packed.packed_cell) {
            packed_cell_free(tmp->u.packed.packed_cell);
          }
        }
        tor_free(tmp);
      } SMARTLIST_FOREACH_END(q);

      smartlist_free(chan->u.cell_chan.outgoing_queue);
      chan->u.cell_chan.outgoing_queue = NULL;
    }
  }

  tor_free(chan);
}

/**
 * Return the current registered listener for a channel
 *
 * This function returns a function pointer to the current registered
 * handler for new incoming channels on a listener channel.
 *
 * @param chan Channel to get listener for
 * @return Function pointer to an incoming channel handler
 */

void
(* channel_get_listener(channel_t *chan))
  (channel_t *, channel_t *)
{
  tor_assert(chan);
  tor_assert(chan->is_listener);

  if (chan->state == CHANNEL_STATE_LISTENING)
    return chan->u.listener.listener;

  return NULL;
}

/**
 * Set the listener for a channel
 *
 * This function sets the handler for new incoming channels on a listener
 * channel.
 *
 * @param chan Listener channel to set handler on
 * @param listener Function pointer to new incoming channel handler
 */

void
channel_set_listener(channel_t *chan,
                     void (*listener)(channel_t *, channel_t *) )
{
  tor_assert(chan);
  tor_assert(chan->is_listener);
  tor_assert(chan->state == CHANNEL_STATE_LISTENING);

  log_debug(LD_CHANNEL,
           "Setting listener callback for channel %p to %p",
           chan, listener);

  chan->u.listener.listener = listener;
  if (chan->u.listener.listener) channel_process_incoming(chan);
}

/**
 * Return the fixed-length cell handler for a channel
 *
 * This function gets the handler for incoming fixed-length cells installed
 * on a channel.
 *
 * @param chan Channel to get the fixed-length cell handler for
 * @return A function pointer to chan's fixed-length cell handler, if any.
 */

void
(* channel_get_cell_handler(channel_t *chan))
  (channel_t *, cell_t *)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  if (chan->state == CHANNEL_STATE_OPENING ||
      chan->state == CHANNEL_STATE_OPEN ||
      chan->state == CHANNEL_STATE_MAINT)
    return chan->u.cell_chan.cell_handler;

  return NULL;
}

/**
 * Return the variable-length cell handler for a channel
 *
 * This function gets the handler for incoming variable-length cells
 * installed on a channel.
 *
 * @param chan Channel to get the variable-length cell handler for
 * @return A function pointer to chan's variable-length cell handler, if any.
 */

void
(* channel_get_var_cell_handler(channel_t *chan))
  (channel_t *, var_cell_t *)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  if (chan->state == CHANNEL_STATE_OPENING ||
      chan->state == CHANNEL_STATE_OPEN ||
      chan->state == CHANNEL_STATE_MAINT)
    return chan->u.cell_chan.var_cell_handler;

  return NULL;
}

/**
 * Set the fixed-length cell handler for a channel
 *
 * This function sets the fixed-length cell handler for a channel and
 * processes any incoming cells that had been blocked in the queue because
 * none was available.
 *
 * @param chan Channel to set the fixed-length cell handler for
 * @param cell_handler Function pointer to new fixed-length cell handler
 */

void
channel_set_cell_handler(channel_t *chan,
                         void (*cell_handler)(channel_t *, cell_t *))
{
  int changed = 0;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));
  tor_assert(chan->state == CHANNEL_STATE_OPENING ||
             chan->state == CHANNEL_STATE_OPEN ||
             chan->state == CHANNEL_STATE_MAINT);

  log_debug(LD_CHANNEL,
           "Setting cell_handler callback for channel %p to %p",
           chan, cell_handler);

  /*
   * Keep track whether we've changed it so we know if there's any point in
   * re-running the queue.
   */
  if (cell_handler != chan->u.cell_chan.cell_handler) changed = 1;

  /* Change it */
  chan->u.cell_chan.cell_handler = cell_handler;

  /* Re-run the queue if we have one and there's any reason to */
  if (chan->u.cell_chan.cell_queue &&
      (smartlist_len(chan->u.cell_chan.cell_queue) > 0) &&
      changed &&
      chan->u.cell_chan.cell_handler) channel_process_cells(chan);
}

/**
 * Set the both cell handlers for a channel
 *
 * This function sets both the fixed-length and variable length cell handlers
 * for a channel and processes any incoming cells that had been blocked in the
 * queue because none were available.
 *
 * @param chan Channel to set the fixed-length cell handler for
 * @param cell_handler Function pointer to new fixed-length cell handler
 * @param var_cell_handler Function pointer to new variable-length cell
          handler
 */

void
channel_set_cell_handlers(channel_t *chan,
                          void (*cell_handler)(channel_t *, cell_t *),
                          void (*var_cell_handler)(channel_t *,
                                                   var_cell_t *))
{
  int try_again = 0;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));
  tor_assert(chan->state == CHANNEL_STATE_OPENING ||
             chan->state == CHANNEL_STATE_OPEN ||
             chan->state == CHANNEL_STATE_MAINT);

  log_debug(LD_CHANNEL,
           "Setting cell_handler callback for channel %p to %p",
           chan, cell_handler);
  log_debug(LD_CHANNEL,
           "Setting var_cell_handler callback for channel %p to %p",
           chan, var_cell_handler);

  /* Should we try the queue? */
  if (cell_handler &&
      cell_handler != chan->u.cell_chan.cell_handler) try_again = 1;
  if (var_cell_handler &&
      var_cell_handler != chan->u.cell_chan.var_cell_handler) try_again = 1;

  /* Change them */
  chan->u.cell_chan.cell_handler = cell_handler;
  chan->u.cell_chan.var_cell_handler = var_cell_handler;

  /* Re-run the queue if we have one and there's any reason to */
  if (chan->u.cell_chan.cell_queue &&
      (smartlist_len(chan->u.cell_chan.cell_queue) > 0) &&
      try_again &&
      (chan->u.cell_chan.cell_handler ||
       chan->u.cell_chan.var_cell_handler)) channel_process_cells(chan);
}

/**
 * Set the variable-length cell handler for a channel
 *
 * This function sets the variable-length cell handler for a channel and
 * processes any incoming cells that had been blocked in the queue because
 * none was available.
 *
 * @param chan Channel to set the variable-length cell handler for
 * @param cell_handler Function pointer to new variable-length cell handler
 */

void
channel_set_var_cell_handler(channel_t *chan,
                             void (*var_cell_handler)(channel_t *,
                                                      var_cell_t *))
{
  int changed = 0;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));
  tor_assert(chan->state == CHANNEL_STATE_OPENING ||
             chan->state == CHANNEL_STATE_OPEN ||
             chan->state == CHANNEL_STATE_MAINT);

  log_debug(LD_CHANNEL,
           "Setting var_cell_handler callback for channel %p to %p",
           chan, var_cell_handler);

  /*
   * Keep track whether we've changed it so we know if there's any point in
   * re-running the queue.
   */
  if (var_cell_handler != chan->u.cell_chan.var_cell_handler) changed = 1;

  /* Change it */
  chan->u.cell_chan.var_cell_handler = var_cell_handler;

  /* Re-run the queue if we have one and there's any reason to */
  if (chan->u.cell_chan.cell_queue &&
      (smartlist_len(chan->u.cell_chan.cell_queue) > 0) &&
      changed && chan->u.cell_chan.var_cell_handler)
    channel_process_cells(chan);
}

/**
 * Request a channel be closed
 *
 * This function tries to close a channel_t; it will go into the CLOSING
 * state, and eventually the lower layer should put it into the CLOSED or
 * ERROR state.  Then, channel_run_cleanup() will eventually free it.
 *
 * @param chan Channel to close
 */

void
channel_request_close(channel_t *chan)
{
  tor_assert(chan != NULL);
  tor_assert(chan->close != NULL);

  /* If it's already in CLOSING, CLOSED or ERROR, this is a no-op */
  if (chan->state == CHANNEL_STATE_CLOSING ||
      chan->state == CHANNEL_STATE_CLOSED ||
      chan->state == CHANNEL_STATE_ERROR) return;

  log_debug(LD_CHANNEL,
            "Closing channel %p by request",
            chan);

  /* Note closing by request from above */
  chan->reason_for_closing = CHANNEL_CLOSE_REQUESTED;

  /* Change state to CLOSING */
  channel_change_state(chan, CHANNEL_STATE_CLOSING);

  /* Tell the lower layer */
  chan->close(chan);

  /*
   * It's up to the lower layer to change state to CLOSED or ERROR when we're
   * ready; we'll try to free channels that are in the finished list from
   * channel_run_cleanup().  The lower layer should do this by calling
   * channel_closed().
   */
}

/**
 * Close a channel from the lower layer
 *
 * Notify the channel code that the channel is being closed due to a non-error
 * condition in the lower layer.  This does not call the close() method, since
 * the lower layer already knows.
 *
 * @param chan Channel to notify for close
 */

void
channel_close_from_lower_layer(channel_t *chan)
{
  tor_assert(chan != NULL);

  /* If it's already in CLOSING, CLOSED or ERROR, this is a no-op */
  if (chan->state == CHANNEL_STATE_CLOSING ||
      chan->state == CHANNEL_STATE_CLOSED ||
      chan->state == CHANNEL_STATE_ERROR) return;

  log_debug(LD_CHANNEL,
            "Closing channel %p due to lower-layer event",
            chan);

  /* Note closing by event from below */
  chan->reason_for_closing = CHANNEL_CLOSE_FROM_BELOW;

  /* Change state to CLOSING */
  channel_change_state(chan, CHANNEL_STATE_CLOSING);
}

/**
 * Notify that the channel is being closed due to an error condition
 *
 * This function is called by the lower layer implementing the transport
 * when a channel must be closed due to an error condition.  This does not
 * call the channel's close method, since the lower layer already knows.
 *
 * @param chan Channel to notify for error
 */

void
channel_close_for_error(channel_t *chan)
{
  tor_assert(chan != NULL);

  /* If it's already in CLOSING, CLOSED or ERROR, this is a no-op */
  if (chan->state == CHANNEL_STATE_CLOSING ||
      chan->state == CHANNEL_STATE_CLOSED ||
      chan->state == CHANNEL_STATE_ERROR) return;

  log_debug(LD_CHANNEL,
            "Closing channel %p due to lower-layer error",
            chan);

  /* Note closing by event from below */
  chan->reason_for_closing = CHANNEL_CLOSE_FOR_ERROR;

  /* Change state to CLOSING */
  channel_change_state(chan, CHANNEL_STATE_CLOSING);
}

/**
 * Notify that the lower layer is finished closing the channel
 *
 * This function should be called by the lower layer when a channel
 * is finished closing and it should be regarded as inactive and
 * freed by the channel code.
 *
 * @param chan Channel to notify closure on
 */

void
channel_closed(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(chan->state == CHANNEL_STATE_CLOSING ||
             chan->state == CHANNEL_STATE_CLOSED ||
             chan->state == CHANNEL_STATE_ERROR);

  /* No-op if already inactive */
  if (chan->state == CHANNEL_STATE_CLOSED ||
      chan->state == CHANNEL_STATE_ERROR) return;

  if (chan->reason_for_closing == CHANNEL_CLOSE_FOR_ERROR) {
    /* Inform any pending (not attached) circs that they should
     * give up. */
    circuit_n_chan_done(chan, 0);
  }
  /* Now close all the attached circuits on it. */
  circuit_unlink_all_from_channel(chan, END_CIRC_REASON_CHANNEL_CLOSED);

  if (chan->reason_for_closing != CHANNEL_CLOSE_FOR_ERROR) {
    channel_change_state(chan, CHANNEL_STATE_CLOSED);
  } else {
    channel_change_state(chan, CHANNEL_STATE_ERROR);
  }
}

/**
 * Clear the identity_digest of a channel
 *
 * This function clears the identity digest of the remote endpoint for a
 * channel; this is intended for use by the lower layer.
 *
 * @param chan Channel to clear
 */

void
channel_clear_identity_digest(channel_t *chan)
{
  int state_not_in_map;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  log_debug(LD_CHANNEL,
            "Clearing remote endpoint digest on channel %p with "
            "global ID " U64_FORMAT,
            chan, U64_PRINTF_ARG(chan->global_identifier));

  state_not_in_map =
    (chan->state == CHANNEL_STATE_LISTENING ||
     chan->state == CHANNEL_STATE_CLOSING ||
     chan->state == CHANNEL_STATE_CLOSED ||
     chan->state == CHANNEL_STATE_ERROR);

  if (!state_not_in_map && chan->registered &&
      !tor_digest_is_zero(chan->u.cell_chan.identity_digest))
    /* if it's registered get it out of the digest map */
    channel_remove_from_digest_map(chan);

  memset(chan->u.cell_chan.identity_digest, 0,
         sizeof(chan->u.cell_chan.identity_digest));
}

/**
 * Set the identity_digest of a channel
 *
 * This function sets the identity digest of the remote endpoint for a
 * channel; this is intended for use by the lower layer.
 *
 * @param chan Channel to clear
 * @param identity_digest New identity digest for chan
 */

void
channel_set_identity_digest(channel_t *chan,
                            const char *identity_digest)
{
  int was_in_digest_map, should_be_in_digest_map, state_not_in_map;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  log_debug(LD_CHANNEL,
            "Setting remote endpoint digest on channel %p with "
            "global ID " U64_FORMAT " to digest %s",
            chan, U64_PRINTF_ARG(chan->global_identifier),
            identity_digest ?
              hex_str(identity_digest, DIGEST_LEN) : "(null)");

  state_not_in_map =
    (chan->state == CHANNEL_STATE_LISTENING ||
     chan->state == CHANNEL_STATE_CLOSING ||
     chan->state == CHANNEL_STATE_CLOSED ||
     chan->state == CHANNEL_STATE_ERROR);
  was_in_digest_map =
    !state_not_in_map &&
    chan->registered &&
    !tor_digest_is_zero(chan->u.cell_chan.identity_digest);
  should_be_in_digest_map =
    !state_not_in_map &&
    chan->registered &&
    (identity_digest &&
     !tor_digest_is_zero(identity_digest));

  if (was_in_digest_map)
    /* We should always remove it; we'll add it back if we're writing
     * in a new digest.
     */
    channel_remove_from_digest_map(chan);

  if (identity_digest) {
    memcpy(chan->u.cell_chan.identity_digest,
           identity_digest,
           sizeof(chan->u.cell_chan.identity_digest));
  } else {
    memset(chan->u.cell_chan.identity_digest, 0,
           sizeof(chan->u.cell_chan.identity_digest));
  }

  /* Put it in the digest map if we should */
  if (should_be_in_digest_map)
    channel_add_to_digest_map(chan);
}

/**
 * Clear the remote end metadata (identity_digest/nickname) of a channel
 *
 * This function clears all the remote end info from a channel; this is
 * intended for use by the lower layer.
 *
 * @param chan Channel to clear
 */

void
channel_clear_remote_end(channel_t *chan)
{
  int state_not_in_map;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  log_debug(LD_CHANNEL,
            "Clearing remote endpoint identity on channel %p with "
            "global ID " U64_FORMAT,
            chan, U64_PRINTF_ARG(chan->global_identifier));

  state_not_in_map =
    (chan->state == CHANNEL_STATE_LISTENING ||
     chan->state == CHANNEL_STATE_CLOSING ||
     chan->state == CHANNEL_STATE_CLOSED ||
     chan->state == CHANNEL_STATE_ERROR);

  if (!state_not_in_map && chan->registered &&
      !tor_digest_is_zero(chan->u.cell_chan.identity_digest))
    /* if it's registered get it out of the digest map */
    channel_remove_from_digest_map(chan);

  memset(chan->u.cell_chan.identity_digest, 0,
         sizeof(chan->u.cell_chan.identity_digest));
  tor_free(chan->u.cell_chan.nickname);
}

/**
 * Set the remote end metadata (identity_digest/nickname) of a channel
 *
 * This function sets new remote end info on a channel; this is intended
 * for use by the lower layer.
 *
 * @chan Channel to set data on
 * @chan identity_digest New identity digest for chan
 * @chan nickname New remote nickname for chan
 */

void
channel_set_remote_end(channel_t *chan,
                       const char *identity_digest,
                       const char *nickname)
{
  int was_in_digest_map, should_be_in_digest_map, state_not_in_map;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  log_debug(LD_CHANNEL,
            "Setting remote endpoint identity on channel %p with "
            "global ID " U64_FORMAT " to nickname %s, digest %s",
            chan, U64_PRINTF_ARG(chan->global_identifier),
            nickname ? nickname : "(null)",
            identity_digest ?
              hex_str(identity_digest, DIGEST_LEN) : "(null)");

  state_not_in_map =
    (chan->state == CHANNEL_STATE_LISTENING ||
     chan->state == CHANNEL_STATE_CLOSING ||
     chan->state == CHANNEL_STATE_CLOSED ||
     chan->state == CHANNEL_STATE_ERROR);
  was_in_digest_map =
    !state_not_in_map &&
    chan->registered &&
    !tor_digest_is_zero(chan->u.cell_chan.identity_digest);
  should_be_in_digest_map =
    !state_not_in_map &&
    chan->registered &&
    (identity_digest &&
     !tor_digest_is_zero(identity_digest));

  if (was_in_digest_map)
    /* We should always remove it; we'll add it back if we're writing
     * in a new digest.
     */
    channel_remove_from_digest_map(chan);

  if (identity_digest) {
    memcpy(chan->u.cell_chan.identity_digest,
           identity_digest,
           sizeof(chan->u.cell_chan.identity_digest));

  } else {
    memset(chan->u.cell_chan.identity_digest, 0,
           sizeof(chan->u.cell_chan.identity_digest));
  }

  tor_free(chan->u.cell_chan.nickname);
  if (nickname)
    chan->u.cell_chan.nickname = tor_strdup(nickname);

  /* Put it in the digest map if we should */
  if (should_be_in_digest_map)
    channel_add_to_digest_map(chan);
}

/**
 * Write a cell to a channel
 *
 * Write a fixed-length cell to a channel using the write_cell() method.
 * This is equivalent to the pre-channels connection_or_write_cell_to_buf().
 *
 * @param chan Channel to write a cell to
 * @param cell Cell to write to chan
 */

void
channel_write_cell(channel_t *chan, cell_t *cell)
{
  cell_queue_entry_t *q;
  int sent = 0;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));
  tor_assert(cell);
  tor_assert(chan->u.cell_chan.write_cell);

  /* Assert that the state makes sense for a cell write */
  tor_assert(chan->state == CHANNEL_STATE_OPENING ||
             chan->state == CHANNEL_STATE_OPEN ||
             chan->state == CHANNEL_STATE_MAINT);

  log_debug(LD_CHANNEL,
            "Writing cell_t %p to channel %p with global ID "
            U64_FORMAT,
            cell, chan, U64_PRINTF_ARG(chan->global_identifier));

  /* Increment the timestamp unless it's padding */
  if (!(cell->command == CELL_PADDING ||
        cell->command == CELL_VPADDING)) {
    chan->u.cell_chan.timestamp_last_added_nonpadding = approx_time();
  }

  /* Can we send it right out?  If so, try */
  if (!(chan->u.cell_chan.outgoing_queue &&
        (smartlist_len(chan->u.cell_chan.outgoing_queue) > 0)) &&
       chan->state == CHANNEL_STATE_OPEN) {
    if (chan->u.cell_chan.write_cell(chan, cell)) {
      sent = 1;
      /* Timestamp for transmission */
      channel_timestamp_xmit(chan);
      /* If we're here the queue is empty, so it's drained too */
      channel_timestamp_drained(chan);
      /* Update the counter */
      ++(chan->u.cell_chan.n_cells_xmitted);
    }
  }

  if (!sent) {
    /* Not sent, queue it */
    if (!(chan->u.cell_chan.outgoing_queue))
      chan->u.cell_chan.outgoing_queue = smartlist_new();
    q = tor_malloc(sizeof(*q));
    q->type = CELL_QUEUE_FIXED;
    q->u.fixed.cell = cell;
    smartlist_add(chan->u.cell_chan.outgoing_queue, q);
    /* Try to process the queue? */
    if (chan->state == CHANNEL_STATE_OPEN) channel_flush_cells(chan);
  }
}

/**
 * Write a packed cell to a channel
 *
 * Write a packed cell to a channel using the write_cell() method.
 *
 * @param chan Channel to write a cell to
 * @param packed_cell Cell to write to chan
 */

void
channel_write_packed_cell(channel_t *chan, packed_cell_t *packed_cell)
{
  cell_queue_entry_t *q;
  int sent = 0;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));
  tor_assert(packed_cell);
  tor_assert(chan->u.cell_chan.write_packed_cell);

  /* Assert that the state makes sense for a cell write */
  tor_assert(chan->state == CHANNEL_STATE_OPENING ||
             chan->state == CHANNEL_STATE_OPEN ||
             chan->state == CHANNEL_STATE_MAINT);

  log_debug(LD_CHANNEL,
            "Writing packed_cell_t %p to channel %p with global ID "
            U64_FORMAT,
            packed_cell, chan,
            U64_PRINTF_ARG(chan->global_identifier));

  /* Increment the timestamp */
  chan->u.cell_chan.timestamp_last_added_nonpadding = approx_time();

  /* Can we send it right out?  If so, try */
  if (!(chan->u.cell_chan.outgoing_queue &&
        (smartlist_len(chan->u.cell_chan.outgoing_queue) > 0)) &&
       chan->state == CHANNEL_STATE_OPEN) {
    if (chan->u.cell_chan.write_packed_cell(chan, packed_cell)) {
      sent = 1;
      /* Timestamp for transmission */
      channel_timestamp_xmit(chan);
      /* If we're here the queue is empty, so it's drained too */
      channel_timestamp_drained(chan);
      /* Update the counter */
      ++(chan->u.cell_chan.n_cells_xmitted);
    }
  }

  if (!sent) {
    /* Not sent, queue it */
    if (!(chan->u.cell_chan.outgoing_queue))
      chan->u.cell_chan.outgoing_queue = smartlist_new();
    q = tor_malloc(sizeof(*q));
    q->type = CELL_QUEUE_PACKED;
    q->u.packed.packed_cell = packed_cell;
    smartlist_add(chan->u.cell_chan.outgoing_queue, q);
    /* Try to process the queue? */
    if (chan->state == CHANNEL_STATE_OPEN) channel_flush_cells(chan);
  }
}

/**
 * Write a variable-length cell to a channel
 *
 * Write a variable-length cell to a channel using the write_cell() method.
 * This is equivalent to the pre-channels
 * connection_or_write_var_cell_to_buf().
 *
 * @param chan Channel to write a cell to
 * @param var_cell Cell to write to chan
 */

void
channel_write_var_cell(channel_t *chan, var_cell_t *var_cell)
{
  cell_queue_entry_t *q;
  int sent = 0;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));
  tor_assert(var_cell);
  tor_assert(chan->u.cell_chan.write_var_cell);

  /* Assert that the state makes sense for a cell write */
  tor_assert(chan->state == CHANNEL_STATE_OPENING ||
             chan->state == CHANNEL_STATE_OPEN ||
             chan->state == CHANNEL_STATE_MAINT);

  log_debug(LD_CHANNEL,
            "Writing var_cell_t %p to channel %p with global ID "
            U64_FORMAT,
            var_cell, chan,
            U64_PRINTF_ARG(chan->global_identifier));

  /* Increment the timestamp unless it's padding */
  if (!(var_cell->command == CELL_PADDING ||
        var_cell->command == CELL_VPADDING)) {
    chan->u.cell_chan.timestamp_last_added_nonpadding = approx_time();
  }

  /* Can we send it right out? If so, then try */
  if (!(chan->u.cell_chan.outgoing_queue &&
        (smartlist_len(chan->u.cell_chan.outgoing_queue) > 0)) &&
       chan->state == CHANNEL_STATE_OPEN) {
    if (chan->u.cell_chan.write_var_cell(chan, var_cell)) {
      sent = 1;
      /* Timestamp for transmission */
      channel_timestamp_xmit(chan);
      /* If we're here the queue is empty, so it's drained too */
      channel_timestamp_drained(chan);
      /* Update the counter */
      ++(chan->u.cell_chan.n_cells_xmitted);
    }
  }

  if (!sent) {
    /* Not sent, queue it */
    if (!(chan->u.cell_chan.outgoing_queue))
      chan->u.cell_chan.outgoing_queue = smartlist_new();
    q = tor_malloc(sizeof(*q));
    q->type = CELL_QUEUE_VAR;
    q->u.var.var_cell = var_cell;
    smartlist_add(chan->u.cell_chan.outgoing_queue, q);
    /* Try to process the queue? */
    if (chan->state == CHANNEL_STATE_OPEN) channel_flush_cells(chan);
  }
}

/**
 * Change channel state
 *
 * This internal and subclass use only function is used to change channel
 * state, performing all transition validity checks and whatever actions
 * are appropriate to the state transition in question.
 *
 * @param chan Channel to change state on
 * @param to_state State to change chan to
 */

void
channel_change_state(channel_t *chan, channel_state_t to_state)
{
  channel_state_t from_state;
  unsigned char was_active, is_active, was_listening, is_listening;
  unsigned char was_in_id_map, is_in_id_map;

  tor_assert(chan);
  from_state = chan->state;

  tor_assert(channel_state_is_valid(from_state));
  tor_assert(channel_state_is_valid(to_state));
  tor_assert(channel_state_can_transition(chan->state, to_state));

  if (chan->is_listener) {
    tor_assert(from_state == CHANNEL_STATE_LISTENING ||
               from_state == CHANNEL_STATE_CLOSING ||
               from_state == CHANNEL_STATE_CLOSED ||
               from_state == CHANNEL_STATE_ERROR);
    tor_assert(to_state == CHANNEL_STATE_LISTENING ||
               to_state == CHANNEL_STATE_CLOSING ||
               to_state == CHANNEL_STATE_CLOSED ||
               to_state == CHANNEL_STATE_ERROR);
  } else {
    tor_assert(from_state != CHANNEL_STATE_LISTENING);
    tor_assert(to_state != CHANNEL_STATE_LISTENING);
  }

  /* Check for no-op transitions */
  if (from_state == to_state) {
    log_debug(LD_CHANNEL,
              "Got no-op transition from \"%s\" to itself on channel %p",
              channel_state_to_string(to_state),
              chan);
    return;
  }

  /* If we're going to a closing or closed state, we must have a reason set */
  if (to_state == CHANNEL_STATE_CLOSING ||
      to_state == CHANNEL_STATE_CLOSED ||
      to_state == CHANNEL_STATE_ERROR) {
    tor_assert(chan->reason_for_closing != CHANNEL_NOT_CLOSING);
  }

  /*
   * We need to maintain the queues here for some transitions:
   * when we enter CHANNEL_STATE_OPEN (especially from CHANNEL_STATE_MAINT)
   * we may have a backlog of cells to transmit, so drain the queues in
   * that case, and when going to CHANNEL_STATE_CLOSED the subclass
   * should have made sure to finish sending things (or gone to
   * CHANNEL_STATE_ERROR if not possible), so we assert for that here.
   */

  log_debug(LD_CHANNEL,
            "Changing state of channel %p from \"%s\" to \"%s\"",
            chan,
            channel_state_to_string(chan->state),
            channel_state_to_string(to_state));

  chan->state = to_state;

  /* Need to add to the right lists if the channel is registered */
  if (chan->registered) {
    was_active = !(from_state == CHANNEL_STATE_CLOSED ||
                   from_state == CHANNEL_STATE_ERROR);
    is_active = !(to_state == CHANNEL_STATE_CLOSED ||
                  to_state == CHANNEL_STATE_ERROR);

    /* Need to take off active list and put on finished list? */
    if (was_active && !is_active) {
      if (active_channels) smartlist_remove(active_channels, chan);
      if (!finished_channels) finished_channels = smartlist_new();
      smartlist_add(finished_channels, chan);
    }
    /* Need to put on active list? */
    else if (!was_active && is_active) {
      if (finished_channels) smartlist_remove(finished_channels, chan);
      if (!active_channels) active_channels = smartlist_new();
      smartlist_add(active_channels, chan);
    }

    was_listening = (from_state == CHANNEL_STATE_LISTENING);
    is_listening = (to_state == CHANNEL_STATE_LISTENING);

    /* Need to put on listening list? */
    if (!was_listening && is_listening) {
      if (!listening_channels) listening_channels = smartlist_new();
      smartlist_add(listening_channels, chan);
    }
    /* Need to remove from listening list? */
    else if (was_listening && !is_listening) {
      if (listening_channels) smartlist_remove(listening_channels, chan);
    }

    if (!(chan->is_listener) &&
        !tor_digest_is_zero(chan->u.cell_chan.identity_digest)) {
      /* Now we need to handle the identity map */
      was_in_id_map = !(from_state == CHANNEL_STATE_LISTENING ||
                        from_state == CHANNEL_STATE_CLOSING ||
                        from_state == CHANNEL_STATE_CLOSED ||
                        from_state == CHANNEL_STATE_ERROR);
      is_in_id_map = !(to_state == CHANNEL_STATE_LISTENING ||
                       to_state == CHANNEL_STATE_CLOSING ||
                       to_state == CHANNEL_STATE_CLOSED ||
                       to_state == CHANNEL_STATE_ERROR);

      if (!was_in_id_map && is_in_id_map) channel_add_to_digest_map(chan);
      else if (was_in_id_map && !is_in_id_map)
        channel_remove_from_digest_map(chan);
    }
  }

  /* Tell circuits if we opened and stuff */
  if (to_state == CHANNEL_STATE_OPEN) channel_do_open_actions(chan);

  if (!(chan->is_listener) &&
      to_state == CHANNEL_STATE_OPEN) {
    /* Check for queued cells to process */
    if (chan->u.cell_chan.cell_queue &&
        smartlist_len(chan->u.cell_chan.cell_queue) > 0)
      channel_process_cells(chan);
    if (chan->u.cell_chan.outgoing_queue &&
        smartlist_len(chan->u.cell_chan.outgoing_queue) > 0)
      channel_flush_cells(chan);
  } else if (to_state == CHANNEL_STATE_CLOSED ||
             to_state == CHANNEL_STATE_ERROR) {
    /* Assert that all queues are empty */
    if (chan->is_listener) {
      tor_assert(!(chan->u.listener.incoming_list) ||
                  smartlist_len(chan->u.listener.incoming_list) == 0);
    } else {
      tor_assert(!(chan->u.cell_chan.cell_queue) ||
                  smartlist_len(chan->u.cell_chan.cell_queue) == 0);
      tor_assert(!(chan->u.cell_chan.outgoing_queue) ||
                  smartlist_len(chan->u.cell_chan.outgoing_queue) == 0);
    }
  }
}

/**
 * Try to flush cells to the lower layer
 *
 * this is called by the lower layer to indicate that it wants more cells;
 * it will try to write up to num_cells cells from the channel's cell queue or
 * from circuits active on that channel, or as many as it has available if
 * num_cells == -1.
 *
 * @param chan Channel to flush from
 * @param num_cells Maximum number of cells to flush, or -1 for unlimited
 * @return Number of cells flushed
 */

#define MAX_CELLS_TO_GET_FROM_CIRCUITS_FOR_UNLIMITED 256

ssize_t
channel_flush_some_cells(channel_t *chan, ssize_t num_cells)
{
  unsigned int unlimited = 0;
  ssize_t flushed = 0;
  int num_cells_from_circs;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  if (num_cells < 0) unlimited = 1;
  if (!unlimited && num_cells <= flushed) goto done;

  /* If we aren't in CHANNEL_STATE_OPEN, nothing goes through */
  if (chan->state == CHANNEL_STATE_OPEN) {
    /* Try to flush as much as we can that's already queued */
    flushed += channel_flush_some_cells_from_outgoing_queue(chan,
        (unlimited ? -1 : num_cells - flushed));
    if (!unlimited && num_cells <= flushed) goto done;

    if (chan->u.cell_chan.active_circuits) {
      /* Try to get more cells from any active circuits */
      num_cells_from_circs =
        channel_flush_from_first_active_circuit(chan,
            (unlimited ? MAX_CELLS_TO_GET_FROM_CIRCUITS_FOR_UNLIMITED :
                         (num_cells - flushed)));

      /* If it claims we got some, process the queue again */
      if (num_cells_from_circs > 0) {
        flushed += channel_flush_some_cells_from_outgoing_queue(chan,
          (unlimited ? -1 : num_cells - flushed));
      }
    }
  }

 done:
  return flushed;
}

/**
 * Flush cells from just the channel's out going cell queue
 *
 * This gets called from channel_flush_some_cells() above to flush cells
 * just from the queue without trying for active_circuits.
 *
 * @param chan Channel to flush from
 * @param num_cells Maximum number of cells to flush, or -1 for unlimited
 * @return Number of cells flushed
 */

static ssize_t
channel_flush_some_cells_from_outgoing_queue(channel_t *chan,
                                             ssize_t num_cells)
{
  unsigned int unlimited = 0;
  ssize_t flushed = 0;
  cell_queue_entry_t *q = NULL;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));
  tor_assert(chan->u.cell_chan.write_cell);
  tor_assert(chan->u.cell_chan.write_packed_cell);
  tor_assert(chan->u.cell_chan.write_var_cell);

  if (num_cells < 0) unlimited = 1;
  if (!unlimited && num_cells <= flushed) return 0;

  /* If we aren't in CHANNEL_STATE_OPEN, nothing goes through */
  if (chan->state == CHANNEL_STATE_OPEN) {
    while ((unlimited || num_cells > flushed) &&
           (chan->u.cell_chan.outgoing_queue &&
            (smartlist_len(chan->u.cell_chan.outgoing_queue) > 0))) {
      /*
       * Ewww, smartlist_del_keeporder() is O(n) in list length; maybe a
       * a linked list would make more sense for the queue.
       */

      /* Get the head of the queue */
      q = smartlist_get(chan->u.cell_chan.outgoing_queue, 0);
      /* That shouldn't happen; bail out */
      if (q) {
        /*
         * Okay, we have a good queue entry, try to give it to the lower
         * layer.
         */
        switch (q->type) {
          case CELL_QUEUE_FIXED:
            if (q->u.fixed.cell) {
              if (chan->u.cell_chan.write_cell(chan,
                    q->u.fixed.cell)) {
                tor_free(q);
                ++flushed;
                channel_timestamp_xmit(chan);
                ++(chan->u.cell_chan.n_cells_xmitted);
              }
              /* Else couldn't write it; leave it on the queue */
            } else {
              /* This shouldn't happen */
              log_info(LD_CHANNEL,
                       "Saw broken cell queue entry of type CELL_QUEUE_FIXED "
                       "with no cell on channel %p.",
                       chan);
              /* Throw it away */
              tor_free(q);
            }
            break;
         case CELL_QUEUE_PACKED:
            if (q->u.packed.packed_cell) {
              if (chan->u.cell_chan.write_packed_cell(chan,
                    q->u.packed.packed_cell)) {
                tor_free(q);
                ++flushed;
                channel_timestamp_xmit(chan);
                ++(chan->u.cell_chan.n_cells_xmitted);
              }
              /* Else couldn't write it; leave it on the queue */
            } else {
              /* This shouldn't happen */
              log_info(LD_CHANNEL,
                       "Saw broken cell queue entry of type CELL_QUEUE_PACKED "
                       "with no cell on channel %p.",
                       chan);
              /* Throw it away */
              tor_free(q);
            }
            break;
         case CELL_QUEUE_VAR:
            if (q->u.var.var_cell) {
              if (chan->u.cell_chan.write_var_cell(chan,
                    q->u.var.var_cell)) {
                tor_free(q);
                ++flushed;
                channel_timestamp_xmit(chan);
                ++(chan->u.cell_chan.n_cells_xmitted);
              }
              /* Else couldn't write it; leave it on the queue */
            } else {
              /* This shouldn't happen */
              log_info(LD_CHANNEL,
                       "Saw broken cell queue entry of type CELL_QUEUE_VAR "
                       "with no cell on channel %p.",
                       chan);
              /* Throw it away */
              tor_free(q);
            }
            break;
          default:
            /* Unknown type, log and free it */
            log_info(LD_CHANNEL,
                     "Saw an unknown cell queue entry type %d on channel %p; "
                     "ignoring it.  Someone should fix this.",
                     q->type, chan);
            tor_free(q); /* tor_free() NULLs it out */
        }
      } else {
        /* This shouldn't happen; log and throw it away */
        log_info(LD_CHANNEL,
                 "Saw a NULL entry in the outgoing cell queue on channel %p; "
                 "this is definitely a bug.",
                 chan);
        /* q is already NULL, so we know to delete that queue entry */
      }

      /* if q got NULLed out, we used it and should remove the queue entry */
      if (!q) smartlist_del_keeporder(chan->u.cell_chan.outgoing_queue, 0);
      /* No cell removed from list, so we can't go on any further */
      else break;
    }
  }

  /* Did we drain the queue? */
  if (!(chan->u.cell_chan.outgoing_queue) ||
      smartlist_len(chan->u.cell_chan.outgoing_queue) == 0) {
    /* Timestamp it */
    channel_timestamp_drained(chan);
  }

  return flushed;
}

/**
 * Try to flush as many cells as we possibly can from the queue
 *
 * This tries to flush as many cells from the queue as the lower layer
 * will take.  It just calls channel_flush_some_cells_from_outgoing_queue()
 * in unlimited mode.
 *
 * @param chan Channel to flush
 */

void
channel_flush_cells(channel_t *chan)
{
  channel_flush_some_cells_from_outgoing_queue(chan, -1);
}

/**
 * Check if any cells are available
 *
 * This gets used from the lower layer to check if any more cells are
 * available.
 *
 * @param chan Channel to check on
 * @return 1 if cells are available, 0 otherwise
 */

int
channel_more_to_flush(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  /* Check if we have any queued */
  if (chan->u.cell_chan.cell_queue &&
      smartlist_len(chan->u.cell_chan.cell_queue) > 0) return 1;

  /* Check if any circuits would like to queue some */
  if (chan->u.cell_chan.active_circuits) return 1;

  /* Else no */
  return 0;
}

/**
 * Notify the channel we're done flushing the output in the lower layer
 *
 * Connection.c will call this when we've flushed the output; there's some
 * dirreq-related maintenance to do.
 *
 * @param chan Channel to notify
 */

void
channel_notify_flushed(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  if (chan->u.cell_chan.dirreq_id != 0)
    geoip_change_dirreq_state(chan->u.cell_chan.dirreq_id,
                              DIRREQ_TUNNELED,
                              DIRREQ_CHANNEL_BUFFER_FLUSHED);
}

/**
 * Process the queue of incoming channels on a listener
 *
 * Use a listener's registered callback to process as many entries in the
 * queue of incoming channels as possible.
 *
 * @param listener Pointer to a listening channel.
 */

void
channel_process_incoming(channel_t *listener)
{
  tor_assert(listener);
  tor_assert(listener->is_listener);
  /*
   * CHANNEL_STATE_CLOSING permitted because we drain the queue while
   * closing a listener.
   */
  tor_assert(listener->state == CHANNEL_STATE_LISTENING ||
             listener->state == CHANNEL_STATE_CLOSING);
  tor_assert(listener->u.listener.listener);

  log_debug(LD_CHANNEL,
            "Processing queue of incoming connections for listening "
            "channel %p (global ID " U64_FORMAT ")",
            listener, U64_PRINTF_ARG(listener->global_identifier));

  if (!(listener->u.listener.incoming_list)) return;

  SMARTLIST_FOREACH_BEGIN(listener->u.listener.incoming_list,
                          channel_t *, chan) {
    tor_assert(chan);
    tor_assert(!(chan->is_listener));

    log_debug(LD_CHANNEL,
              "Handling incoming connection %p (" U64_FORMAT ") "
              "for listener %p (" U64_FORMAT ")",
              chan,
              U64_PRINTF_ARG(chan->global_identifier),
              listener,
              U64_PRINTF_ARG(listener->global_identifier));
    /* Make sure this is set correctly */
    channel_mark_incoming(chan);
    listener->u.listener.listener(listener, chan);
    SMARTLIST_DEL_CURRENT(listener->u.listener.incoming_list, chan);
  } SMARTLIST_FOREACH_END(chan);

  tor_assert(smartlist_len(listener->u.listener.incoming_list) == 0);
  smartlist_free(listener->u.listener.incoming_list);
  listener->u.listener.incoming_list = NULL;
}

/**
 * Take actions required when a channel becomes open
 *
 * Handle actions we should do when we know a channel is open; a lot of
 * this comes from the old connection_or_set_state_open() of connection_or.c.
 *
 * Because of this mechanism, future channel_t subclasses should take care
 * not to change a channel to from CHANNEL_STATE_OPENING to CHANNEL_STATE_OPEN
 * until there is positive confirmation that the network is operational.
 * In particular, anything UDP-based should not make this transition until a
 * packet is received from the other side.
 *
 * @param chan Channel that has become open
 */

void
channel_do_open_actions(channel_t *chan)
{
  tor_addr_t remote_addr;
  int started_here, not_using = 0;
  time_t now = time(NULL);

  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  started_here = channel_is_outgoing(chan);

  if (started_here) {
    circuit_build_times_network_is_live(&circ_times);
    rep_hist_note_connect_succeeded(chan->u.cell_chan.identity_digest, now);
    if (entry_guard_register_connect_status(
          chan->u.cell_chan.identity_digest, 1, 0, now) < 0) {
      /* Close any circuits pending on this channel. We leave it in state
       * 'open' though, because it didn't actually *fail* -- we just
       * chose not to use it. */
      log_debug(LD_OR,
                "New entry guard was reachable, but closing this "
                "connection so we can retry the earlier entry guards.");
      circuit_n_chan_done(chan, 0);
      not_using = 1;
    }
    router_set_status(chan->u.cell_chan.identity_digest, 1);
  } else {
    /* only report it to the geoip module if it's not a known router */
    if (!router_get_by_id_digest(chan->u.cell_chan.identity_digest)) {
      if (channel_get_addr_if_possible(chan, &remote_addr)) {
        geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &remote_addr,
                               now);
      }
      /* Otherwise the underlying transport can't tell us this, so skip it */
    }
  }

  if (!not_using) circuit_n_chan_done(chan, 1);
}

/**
 * Queue an incoming channel on a listener
 *
 * Internal and subclass use only function to queue an incoming channel from
 * a listening one.  A subclass of channel_t should call this when a new
 * incoming channel is created.
 *
 * @param listener Listening channel to queue on
 * @param incoming New incoming channel
 */

void
channel_queue_incoming(channel_t *listener, channel_t *incoming)
{
  int need_to_queue = 0;

  tor_assert(listener);
  tor_assert(listener->is_listener);
  tor_assert(listener->state == CHANNEL_STATE_LISTENING);
  tor_assert(incoming);
  tor_assert(!(incoming->is_listener));
  /*
   * Other states are permitted because subclass might process activity
   * on a channel at any time while it's queued, but a listener returning
   * another listener makes no sense.
   */
  tor_assert(incoming->state != CHANNEL_STATE_LISTENING);

  log_debug(LD_CHANNEL,
            "Queueing incoming channel %p on listening channel %p",
            incoming, listener);

  /* Do we need to queue it, or can we just call the listener right away? */
  if (!(listener->u.listener.listener)) need_to_queue = 1;
  if (listener->u.listener.incoming_list &&
      (smartlist_len(listener->u.listener.incoming_list) > 0))
    need_to_queue = 1;

  /* If we need to queue and have no queue, create one */
  if (need_to_queue && !(listener->u.listener.incoming_list)) {
    listener->u.listener.incoming_list = smartlist_new();
  }

  /* Bump the counter and timestamp it */
  channel_timestamp_active(listener);
  channel_timestamp_accepted(listener);
  ++(listener->u.listener.n_accepted);

  /* If we don't need to queue, process it right away */
  if (!need_to_queue) {
    tor_assert(listener->u.listener.listener);
    listener->u.listener.listener(listener, incoming);
  }
  /*
   * Otherwise, we need to queue; queue and then process the queue if
   * we can.
   */
  else {
    tor_assert(listener->u.listener.incoming_list);
    smartlist_add(listener->u.listener.incoming_list, incoming);
    if (listener->u.listener.listener) channel_process_incoming(listener);
  }
}

/**
 * Process queued incoming cells
 *
 * Process as many queued cells as we can from the incoming
 * cell queue.
 *
 * @param chan Channel to process incoming cell queue on
 */

void
channel_process_cells(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));
  tor_assert(chan->state == CHANNEL_STATE_CLOSING ||
             chan->state == CHANNEL_STATE_MAINT ||
             chan->state == CHANNEL_STATE_OPEN);

  log_debug(LD_CHANNEL,
            "Processing as many incoming cells as we can for channel %p",
            chan);

  /* Nothing we can do if we have no registered cell handlers */
  if (!(chan->u.cell_chan.cell_handler ||
        chan->u.cell_chan.var_cell_handler)) return;
  /* Nothing we can do if we have no cells */
  if (!(chan->u.cell_chan.cell_queue)) return;

  /*
   * Process cells until we're done or find one we have no current handler
   * for.
   */
  SMARTLIST_FOREACH_BEGIN(chan->u.cell_chan.cell_queue,
                          cell_queue_entry_t *, q) {
    tor_assert(q);
    tor_assert(q->type == CELL_QUEUE_FIXED ||
               q->type == CELL_QUEUE_VAR);

    if (q->type == CELL_QUEUE_FIXED &&
        chan->u.cell_chan.cell_handler) {
      /* Handle a fixed-length cell */
      tor_assert(q->u.fixed.cell);
      log_debug(LD_CHANNEL,
                "Processing incoming cell_t %p for channel %p",
                q->u.fixed.cell, chan);
      chan->u.cell_chan.cell_handler(chan, q->u.fixed.cell);
      SMARTLIST_DEL_CURRENT(chan->u.cell_chan.cell_queue, q);
      tor_free(q);
    } else if (q->type == CELL_QUEUE_VAR &&
               chan->u.cell_chan.var_cell_handler) {
      /* Handle a variable-length cell */
      tor_assert(q->u.var.var_cell);
      log_debug(LD_CHANNEL,
                "Processing incoming var_cell_t %p for channel %p",
                q->u.var.var_cell, chan);
      chan->u.cell_chan.var_cell_handler(chan, q->u.var.var_cell);
      SMARTLIST_DEL_CURRENT(chan->u.cell_chan.cell_queue, q);
      tor_free(q);
    } else {
      /* Can't handle this one */
      break;
    }
  } SMARTLIST_FOREACH_END(q);

  /* If the list is empty, free it */
  if (smartlist_len(chan->u.cell_chan.cell_queue) == 0 ) {
    smartlist_free(chan->u.cell_chan.cell_queue);
    chan->u.cell_chan.cell_queue = NULL;
  }
}

/**
 * Queue incoming cell
 *
 * This should be called by a channel_t subclass to queue an incoming fixed-
 * length cell for processing, and process it if possible.
 *
 * @param chan Channel the cell is arriving on
 * @param cell Incoming cell to queue and process
 */

void
channel_queue_cell(channel_t *chan, cell_t *cell)
{
  int need_to_queue = 0;
  cell_queue_entry_t *q;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));
  tor_assert(cell);
  tor_assert(chan->state == CHANNEL_STATE_OPEN);

  /* Do we need to queue it, or can we just call the handler right away? */
  if (!(chan->u.cell_chan.cell_handler)) need_to_queue = 1;
  if (chan->u.cell_chan.cell_queue &&
      (smartlist_len(chan->u.cell_chan.cell_queue) > 0))
    need_to_queue = 1;

  /* If we need to queue and have no queue, create one */
  if (need_to_queue && !(chan->u.cell_chan.cell_queue)) {
    chan->u.cell_chan.cell_queue = smartlist_new();
  }

  /* Timestamp for receiving */
  channel_timestamp_recv(chan);

  /* Update the counter */
  ++(chan->u.cell_chan.n_cells_recved);

  /* If we don't need to queue we can just call cell_handler */
  if (!need_to_queue) {
    tor_assert(chan->u.cell_chan.cell_handler);
    log_debug(LD_CHANNEL,
              "Directly handling incoming cell_t %p for channel %p",
              cell, chan);
    chan->u.cell_chan.cell_handler(chan, cell);
  } else {
    /* Otherwise queue it and then process the queue if possible. */
    tor_assert(chan->u.cell_chan.cell_queue);
    q = tor_malloc(sizeof(*q));
    q->type = CELL_QUEUE_FIXED;
    q->u.fixed.cell = cell;
    log_debug(LD_CHANNEL,
              "Queueing incoming cell_t %p for channel %p",
              cell, chan);
    smartlist_add(chan->u.cell_chan.cell_queue, q);
    if (chan->u.cell_chan.cell_handler ||
        chan->u.cell_chan.var_cell_handler) {
      channel_process_cells(chan);
    }
  }
}

/**
 * Queue incoming variable-length cell
 *
 * This should be called by a channel_t subclass to queue an incoming
 * variable-length cell for processing, and process it if possible.
 *
 * @param chan Channel the cell is arriving on
 * @param var_cell Incoming cell to queue and process
 */

void
channel_queue_var_cell(channel_t *chan, var_cell_t *var_cell)
{
  int need_to_queue = 0;
  cell_queue_entry_t *q;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));
  tor_assert(var_cell);
  tor_assert(chan->state == CHANNEL_STATE_OPEN);

  /* Do we need to queue it, or can we just call the handler right away? */
  if (!(chan->u.cell_chan.var_cell_handler)) need_to_queue = 1;
  if (chan->u.cell_chan.cell_queue &&
      (smartlist_len(chan->u.cell_chan.cell_queue) > 0))
    need_to_queue = 1;

  /* If we need to queue and have no queue, create one */
  if (need_to_queue && !(chan->u.cell_chan.cell_queue)) {
    chan->u.cell_chan.cell_queue = smartlist_new();
  }

  /* Timestamp for receiving */
  channel_timestamp_recv(chan);

  /* Update the counter */
  ++(chan->u.cell_chan.n_cells_recved);

  /* If we don't need to queue we can just call cell_handler */
  if (!need_to_queue) {
    tor_assert(chan->u.cell_chan.var_cell_handler);
    log_debug(LD_CHANNEL,
              "Directly handling incoming var_cell_t %p for channel %p",
              var_cell, chan);
    chan->u.cell_chan.var_cell_handler(chan, var_cell);
  } else {
    /* Otherwise queue it and then process the queue if possible. */
    tor_assert(chan->u.cell_chan.cell_queue);
    q = tor_malloc(sizeof(*q));
    q->type = CELL_QUEUE_VAR;
    q->u.var.var_cell = var_cell;
    log_debug(LD_CHANNEL,
              "Queueing incoming var_cell_t %p for channel %p",
              var_cell, chan);
    smartlist_add(chan->u.cell_chan.cell_queue, q);
    if (chan->u.cell_chan.cell_handler ||
        chan->u.cell_chan.var_cell_handler) {
      channel_process_cells(chan);
    }
  }
}

/**
 * Send destroy cell on a channel
 *
 * Write a destroy cell with circ ID <b>circ_id</b> and reason <b>reason</b>
 * onto channel <b>chan</b>.  Don't perform range-checking on reason:
 * we may want to propagate reasons from other cells.
 *
 * @param circ_id Circuit ID to destroy
 * @param chan Channel to send on
 * @param reason Reason code
 * @return Always 0
 */

int
channel_send_destroy(circid_t circ_id, channel_t *chan, int reason)
{
  cell_t cell;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  memset(&cell, 0, sizeof(cell_t));
  cell.circ_id = circ_id;
  cell.command = CELL_DESTROY;
  cell.payload[0] = (uint8_t) reason;
  log_debug(LD_OR,"Sending destroy (circID %d).", circ_id);

  channel_write_cell(chan, &cell);

  return 0;
}

/**
 * Channel statistics
 *
 * This is called from dumpstats() in main.c and spams the log with
 * statistics on channels.
 */

void
channel_dumpstats(int severity)
{
  if (all_channels && smartlist_len(all_channels) > 0) {
    log(severity, LD_GENERAL,
        "Dumping statistics about %d channels:",
        smartlist_len(all_channels));
    log(severity, LD_GENERAL,
        "%d are active, %d are listeners, and %d are done and "
        "waiting for cleanup",
        (active_channels != NULL) ?
          smartlist_len(active_channels) : 0,
        (listening_channels != NULL) ?
          smartlist_len(listening_channels) : 0,
        (finished_channels != NULL) ?
          smartlist_len(finished_channels) : 0);

    SMARTLIST_FOREACH(all_channels, channel_t *, chan,
                      channel_dump_statistics(chan, severity));

    log(severity, LD_GENERAL,
        "Done spamming about channels now");
  } else {
    log(severity, LD_GENERAL,
        "No channels to dump");
  }
}

/**
 * Channel cleanup
 *
 * This gets called periodically from run_scheduled_events() in main.c;
 * it cleans up after closed channels.
 */

void
channel_run_cleanup(void)
{
  channel_t *tmp = NULL;

  /* Check if we need to do anything */
  if (!finished_channels || smartlist_len(finished_channels) == 0) return;

  /* Iterate through finished_channels and get rid of them */
  SMARTLIST_FOREACH_BEGIN(finished_channels, channel_t *, curr) {
    tmp = curr;
    /* Remove it from the list */
    SMARTLIST_DEL_CURRENT(finished_channels, curr);
    /* Also unregister it */
    channel_unregister(tmp);
    /* ... and free it */
    channel_free(tmp);
  } SMARTLIST_FOREACH_END(curr);
}

/**
 * Close all channels and free everything
 *
 * This gets called from tor_free_all() in main.c to clean up on exit.
 * It will close all registered channels and free associated storage,
 * then free the all_channels, active_channels, listening_channels and
 * finished_channels lists and also channel_identity_map.
 */

void
channel_free_all(void)
{
  channel_t *tmp = NULL;

  log_debug(LD_CHANNEL,
            "Shutting down channels...");

  /* First, let's go for finished channels */
  if (finished_channels) {
    SMARTLIST_FOREACH_BEGIN(finished_channels, channel_t *, curr) {
      tmp = curr;
      /* Remove it from the list */
      SMARTLIST_DEL_CURRENT(finished_channels, curr);
      /* Deregister and free it */
      tor_assert(tmp);
      log_debug(LD_CHANNEL,
                "Cleaning up finished channel %p (ID " U64_FORMAT ") "
                "in state %s (%d)",
                tmp, U64_PRINTF_ARG(tmp->global_identifier),
                channel_state_to_string(tmp->state), tmp->state);
      channel_unregister(tmp);
      channel_free(tmp);
    } SMARTLIST_FOREACH_END(curr);

    smartlist_free(finished_channels);
    finished_channels = NULL;
    tmp = NULL;
  }

  /* Now the listeners */
  if (listening_channels) {
    SMARTLIST_FOREACH_BEGIN(listening_channels, channel_t *, curr) {
      tmp = curr;
      /* Remove it from the list */
      SMARTLIST_DEL_CURRENT(listening_channels, curr);
      /* Close, deregister and free it */
      tor_assert(tmp);
      log_debug(LD_CHANNEL,
                "Cleaning up listening channel %p (ID " U64_FORMAT ") "
                "in state %s (%d)",
                tmp, U64_PRINTF_ARG(tmp->global_identifier),
                channel_state_to_string(tmp->state), tmp->state);
      /*
       * We have to unregister first so we don't put it in finished_channels
       * and allocate that again on close.
       */
      channel_unregister(tmp);
      channel_request_close(tmp);
      channel_force_free(tmp);
    } SMARTLIST_FOREACH_END(curr);

    smartlist_free(listening_channels);
    listening_channels = NULL;
  }

  /* Now all active channels */
  if (active_channels) {
    SMARTLIST_FOREACH_BEGIN(active_channels, channel_t *, curr) {
      tmp = curr;
      /* Remove it from the list */
      SMARTLIST_DEL_CURRENT(active_channels, curr);
      /* Close, deregister and free it */
      tor_assert(tmp);
      log_debug(LD_CHANNEL,
                "Cleaning up active channel %p (ID " U64_FORMAT ") "
                "in state %s (%d)",
                tmp, U64_PRINTF_ARG(tmp->global_identifier),
                channel_state_to_string(tmp->state), tmp->state);
      /*
       * We have to unregister first so we don't put it in finished_channels
       * and allocate that again on close.
       */
      channel_unregister(tmp);
      channel_request_close(tmp);
      channel_force_free(tmp);
    } SMARTLIST_FOREACH_END(curr);

    smartlist_free(active_channels);
    active_channels = NULL;
  }

  /* Now all channels, in case any are left over */
  if (all_channels) {
    SMARTLIST_FOREACH_BEGIN(all_channels, channel_t *, curr) {
      tmp = curr;
      /* Remove it from the list */
      SMARTLIST_DEL_CURRENT(all_channels, curr);
      /* Close, deregister and free it */
      tor_assert(tmp);
      log_debug(LD_CHANNEL,
                "Cleaning up leftover channel %p (ID " U64_FORMAT ") "
                "in state %s (%d)",
                tmp, U64_PRINTF_ARG(tmp->global_identifier),
                channel_state_to_string(tmp->state), tmp->state);
      channel_unregister(tmp);
      if (!(tmp->state == CHANNEL_STATE_CLOSING ||
            tmp->state == CHANNEL_STATE_CLOSED ||
            tmp->state == CHANNEL_STATE_ERROR)) {
        channel_request_close(tmp);
      }
      channel_force_free(tmp);
    } SMARTLIST_FOREACH_END(curr);

    smartlist_free(all_channels);
    all_channels = NULL;
  }

  /* Now free channel_identity_map */
  if (channel_identity_map) {
    log_debug(LD_CHANNEL,
              "Freeing channel_identity_map");
    /* Geez, anything still left over just won't die ... let it leak then */
    digestmap_free(channel_identity_map, NULL);
    channel_identity_map = NULL;
  }

  log_debug(LD_CHANNEL,
            "Done cleaning up after channels");
}

/**
 * Connect to a given addr/port/digest
 *
 * This sets up a new outgoing channel; in the future if multiple
 * channel_t subclasses are available, this is where the selection policy
 * should go.  It may also be desirable to fold port into tor_addr_t
 * or make a new type including a tor_addr_t and port, so we have a
 * single abstract object encapsulating all the protocol details of
 * how to contact an OR.
 *
 * @param addr Address of remote node to establish a channel to
 * @param port ORport of remote OR
 * @param id_digest Identity digest of remote OR
 * @return New channel, or NULL if failure
 */

channel_t *
channel_connect(const tor_addr_t *addr, uint16_t port,
                const char *id_digest)
{
  return channel_tls_connect(addr, port, id_digest);
}

/**
 * Decide which of two channels to prefer for extending a circuit
 *
 * This function is called while extending a circuit and returns true iff
 * a is 'better' than b.  The most important criterion here is that a
 * canonical channel is always better than a non-canonical one, but the
 * number of circuits and the age are used as tie-breakers.
 *
 * This is based on the former connection_or_is_better() of connection_or.c
 *
 * @param now Current time to use for deciding grace period for new channels
 * @param a Channel A for comparison
 * @param b Channel B for comparison
 * @param forgive_new_connections Whether to use grace period for new channels
 * @return 1 iff a is better than b
 */

int
channel_is_better(time_t now, channel_t *a, channel_t *b,
                  int forgive_new_connections)
{
  int a_grace, b_grace;
  int a_is_canonical, b_is_canonical;
  int a_has_circs, b_has_circs;

  /*
   * Do not definitively deprecate a new channel with no circuits on it
   * until this much time has passed.
   */
#define NEW_CHAN_GRACE_PERIOD (15*60)

  tor_assert(a);
  tor_assert(b);
  tor_assert(!(a->is_listener));
  tor_assert(!(b->is_listener));

  /* Check if one is canonical and the other isn't first */
  a_is_canonical = channel_is_canonical(a);
  b_is_canonical = channel_is_canonical(b);

  if (a_is_canonical && !b_is_canonical) return 1;
  if (!a_is_canonical && b_is_canonical) return 0;

  /*
   * Okay, if we're here they tied on canonicity. Next we check if
   * they have any circuits, and if one does and the other doesn't,
   * we prefer the one that does, unless we are forgiving and the
   * one that has no circuits is in its grace period.
   */

  a_has_circs = (a->u.cell_chan.n_circuits > 0);
  b_has_circs = (b->u.cell_chan.n_circuits > 0);
  a_grace = (forgive_new_connections &&
             (now < channel_when_created(a) + NEW_CHAN_GRACE_PERIOD));
  b_grace = (forgive_new_connections &&
             (now < channel_when_created(b) + NEW_CHAN_GRACE_PERIOD));

  if (a_has_circs && !b_has_circs && !b_grace) return 1;
  if (!a_has_circs && b_has_circs && !a_grace) return 0;

  /* They tied on circuits too; just prefer whichever is newer */

  if (channel_when_created(a) > channel_when_created(b)) return 1;
  else return 0;
}

/**
 * Get a channel to extend a circuit
 *
 * Pick a suitable channel to extend a circuit to given the desired digest
 * the address we believe is correct for that digest; this tries to see
 * if we already have one for the requested endpoint, but if there is no good
 * channel, set *msg_out to a message describing the channel's state
 * and our next action, and set *launch_out to a boolean indicated whether
 * the caller should try to launch a new channel with channel_connect().
 *
 * @param digest Endpoint digest we want
 * @param target_addr Endpoint address we want
 * @param msg_out Write out status message here if we fail
 * @param launch_out Write 1 here if caller should try to connect a new
 *        channel.
 * @return Pointer to selected channel, or NULL if none available
 */

channel_t *
channel_get_for_extend(const char *digest,
                       const tor_addr_t *target_addr,
                       const char **msg_out,
                       int *launch_out)
{
  channel_t *chan, *best = NULL;
  int n_inprogress_goodaddr = 0, n_old = 0;
  int n_noncanonical = 0, n_possible = 0;
  time_t now = approx_time();

  tor_assert(msg_out);
  tor_assert(launch_out);

  if (!channel_identity_map) {
    *msg_out = "Router not connected (nothing is).  Connecting.";
    *launch_out = 1;
    return NULL;
  }

  chan = channel_find_by_remote_digest(digest);

  /* Walk the list, unrefing the old one and refing the new at each
   * iteration.
   */
  for (; chan; chan = channel_next_with_digest(chan)) {
    tor_assert(!(chan->is_listener));
    tor_assert(tor_memeq(chan->u.cell_chan.identity_digest,
                         digest, DIGEST_LEN));

    if (chan->state == CHANNEL_STATE_CLOSING ||
        chan->state == CHANNEL_STATE_CLOSED ||
        chan->state == CHANNEL_STATE_ERROR ||
        chan->state == CHANNEL_STATE_LISTENING)
      continue;

    /* Never return a channel on which the other end appears to be
     * a client. */
    if (channel_is_client(chan)) {
      continue;
    }

    /* Never return a non-open connection. */
    if (chan->state != CHANNEL_STATE_OPEN) {
      /* If the address matches, don't launch a new connection for this
       * circuit. */
      if (!channel_matches_target_addr_for_extend(chan, target_addr))
        ++n_inprogress_goodaddr;
      continue;
    }

    /* Never return a connection that shouldn't be used for circs. */
    if (channel_is_bad_for_new_circs(chan)) {
      ++n_old;
      continue;
    }

    /* Never return a non-canonical connection using a recent link protocol
     * if the address is not what we wanted.
     *
     * The channel_is_canonical_is_reliable() function asks the lower layer
     * if we should trust channel_is_canonical().  The below is from the
     * comments of the old circuit_or_get_for_extend() and applies when
     * the lower-layer transport is channel_tls_t.
     *
     * (For old link protocols, we can't rely on is_canonical getting
     * set properly if we're talking to the right address, since we might
     * have an out-of-date descriptor, and we will get no NETINFO cell to
     * tell us about the right address.)
     */
    if (!channel_is_canonical(chan) &&
         channel_is_canonical_is_reliable(chan) &&
        !channel_matches_target_addr_for_extend(chan, target_addr)) {
      ++n_noncanonical;
      continue;
    }

    ++n_possible;

    if (!best) {
      best = chan; /* If we have no 'best' so far, this one is good enough. */
      continue;
    }

    if (channel_is_better(now, chan, best, 0))
      best = chan;
  }

  if (best) {
    *msg_out = "Connection is fine; using it.";
    *launch_out = 0;
    return best;
  } else if (n_inprogress_goodaddr) {
    *msg_out = "Connection in progress; waiting.";
    *launch_out = 0;
    return NULL;
  } else if (n_old || n_noncanonical) {
    *msg_out = "Connections all too old, or too non-canonical. "
               " Launching a new one.";
    *launch_out = 1;
    return NULL;
  } else {
    *msg_out = "Not connected. Connecting.";
    *launch_out = 1;
    return NULL;
  }
}

/**
 * Describe the transport subclass
 *
 * Invoke a method to get a string description of the lower-layer
 * transport for this channel.
 */

const char *
channel_describe_transport(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(chan->describe_transport);

  return chan->describe_transport(chan);
}

/**
 * Dump channel statistics
 *
 * Dump statistics for one channel to the log
 */

void
channel_dump_statistics(channel_t *chan, int severity)
{
  double avg, interval, age;
  time_t now = time(NULL);
  tor_addr_t remote_addr;
  int have_remote_addr;
  char *remote_addr_str;

  tor_assert(chan);

  age = (double)(now - chan->timestamp_created);

  log(severity, LD_GENERAL,
      "Channel " U64_FORMAT " (at %p) with transport %s is in state "
      "%s (%d) and %s",
      U64_PRINTF_ARG(chan->global_identifier), chan,
      channel_describe_transport(chan),
      channel_state_to_string(chan->state), chan->state,
      chan->is_listener ?
        "listens for incoming connections" :
        "transports cells");
  log(severity, LD_GENERAL,
      " * Channel " U64_FORMAT " was created at " U64_FORMAT
      " (" U64_FORMAT " seconds ago) "
      "and last active at " U64_FORMAT " (" U64_FORMAT " seconds ago)",
      U64_PRINTF_ARG(chan->global_identifier),
      U64_PRINTF_ARG(chan->timestamp_created),
      U64_PRINTF_ARG(now - chan->timestamp_created),
      U64_PRINTF_ARG(chan->timestamp_active),
      U64_PRINTF_ARG(now - chan->timestamp_active));
  if (chan->is_listener) {
    log(severity, LD_GENERAL,
        " * Listener channel " U64_FORMAT " last accepted an incoming "
        "channel at " U64_FORMAT " (" U64_FORMAT " seconds ago) "
        "and has accepted " U64_FORMAT " channels in total",
        U64_PRINTF_ARG(chan->global_identifier),
        U64_PRINTF_ARG(chan->u.listener.timestamp_accepted),
        U64_PRINTF_ARG(now - chan->u.listener.timestamp_accepted),
        U64_PRINTF_ARG(chan->u.listener.n_accepted));

    /*
     * If it's sensible to do so, get the rate of incoming channels on this
     * listener
     */
    if (now > chan->timestamp_created &&
        chan->timestamp_created > 0 &&
        chan->u.listener.n_accepted > 0) {
      avg = (double)(chan->u.listener.n_accepted) / age;
      if (avg >= 1.0) {
        log(severity, LD_GENERAL,
            " * Listener channel " U64_FORMAT " has averaged %f incoming "
            "channels per second",
            U64_PRINTF_ARG(chan->global_identifier), avg);
      } else if (avg >= 0.0) {
        interval = 1.0 / avg;
        log(severity, LD_GENERAL,
            " * Listener channel " U64_FORMAT " has averaged %f seconds "
            "between incoming channels",
            U64_PRINTF_ARG(chan->global_identifier), interval);
      }
    }
  } else {
    /* Handle digest and nickname */
    if (!tor_digest_is_zero(chan->u.cell_chan.identity_digest)) {
      if (chan->u.cell_chan.nickname) {
        log(severity, LD_GENERAL,
            " * Cell-bearing channel " U64_FORMAT " says it is connected "
            "to an OR with digest %s and nickname %s",
            U64_PRINTF_ARG(chan->global_identifier),
            hex_str(chan->u.cell_chan.identity_digest, DIGEST_LEN),
            chan->u.cell_chan.nickname);
      } else {
        log(severity, LD_GENERAL,
            " * Cell-bearing channel " U64_FORMAT " says it is connected "
            "to an OR with digest %s and no known nickname",
            U64_PRINTF_ARG(chan->global_identifier),
            hex_str(chan->u.cell_chan.identity_digest, DIGEST_LEN));
      }
    } else {
      if (chan->u.cell_chan.nickname) {
        log(severity, LD_GENERAL,
            " * Cell-bearing channel " U64_FORMAT " does not know the digest"
            " of the OR it is connected to, but reports its nickname is %s",
            U64_PRINTF_ARG(chan->global_identifier),
            chan->u.cell_chan.nickname);
      } else {
        log(severity, LD_GENERAL,
            " * Cell-bearing channel " U64_FORMAT " does not know the digest"
            " or the nickname of the OR it is connected to",
            U64_PRINTF_ARG(chan->global_identifier));
      }
    }

    /* Handle remote address and descriptions */
    have_remote_addr = channel_get_addr_if_possible(chan, &remote_addr);
    if (have_remote_addr) {
      remote_addr_str = tor_dup_addr(&remote_addr);
      log(severity, LD_GENERAL,
          " * Cell-bearing channel " U64_FORMAT " says its remote address"
          " is %s, and gives a canonical description of \"%s\" and an "
          "actual description of \"%s\"",
          U64_PRINTF_ARG(chan->global_identifier),
          remote_addr_str,
          channel_get_canonical_remote_descr(chan),
          channel_get_actual_remote_descr(chan));
      tor_free(remote_addr_str);
    } else {
      log(severity, LD_GENERAL,
          " * Cell-bearing channel " U64_FORMAT " does not know its remote "
          "address, but gives a canonical description of \"%s\" and an "
          "actual description of \"%s\"",
          U64_PRINTF_ARG(chan->global_identifier),
          channel_get_canonical_remote_descr(chan),
          channel_get_actual_remote_descr(chan));
    }

    /* Handle marks */
    log(severity, LD_GENERAL,
        " * Cell-bearing channel " U64_FORMAT " has these marks: %s %s %s "
        "%s %s %s",
        U64_PRINTF_ARG(chan->global_identifier),
        channel_is_bad_for_new_circs(chan) ?
          "bad_for_new_circs" : "!bad_for_new_circs",
        channel_is_canonical(chan) ?
          "canonical" : "!canonical",
        channel_is_canonical_is_reliable(chan) ?
          "is_canonical_is_reliable" :
          "!is_canonical_is_reliable",
        channel_is_client(chan) ?
          "client" : "!client",
        channel_is_local(chan) ?
          "local" : "!local",
        channel_is_incoming(chan) ?
          "incoming" : "outgoing");

    /* Describe queues */
    log(severity, LD_GENERAL,
        " * Cell-bearing channel " U64_FORMAT " has %d queued incoming cells"
        " and %d queued outgoing cells",
        U64_PRINTF_ARG(chan->global_identifier),
        (chan->u.cell_chan.cell_queue != NULL) ?
          smartlist_len(chan->u.cell_chan.cell_queue) : 0,
        (chan->u.cell_chan.outgoing_queue != NULL) ?
          smartlist_len(chan->u.cell_chan.outgoing_queue) : 0);

    /* Describe circuits */
    log(severity, LD_GENERAL,
        " * Cell-bearing channel " U64_FORMAT " has %d active circuits out of"
        " %d in total",
        U64_PRINTF_ARG(chan->global_identifier),
        (chan->u.cell_chan.active_circuit_pqueue != NULL) ?
          smartlist_len(chan->u.cell_chan.active_circuit_pqueue) : 0,
        chan->u.cell_chan.n_circuits);
    /* TODO better circuit info once circuit structure refactor is finished */

    /* Describe timestamps */
    log(severity, LD_GENERAL,
        " * Cell-bearing channel " U64_FORMAT " was last used by a "
        "client at " U64_FORMAT " (" U64_FORMAT " seconds ago)",
        U64_PRINTF_ARG(chan->global_identifier),
        U64_PRINTF_ARG(chan->u.cell_chan.timestamp_client),
        U64_PRINTF_ARG(now - chan->u.cell_chan.timestamp_client));
    log(severity, LD_GENERAL,
        " * Cell-bearing channel " U64_FORMAT " was last drained at "
        U64_FORMAT " (" U64_FORMAT " seconds ago)",
        U64_PRINTF_ARG(chan->global_identifier),
        U64_PRINTF_ARG(chan->u.cell_chan.timestamp_drained),
        U64_PRINTF_ARG(now - chan->u.cell_chan.timestamp_drained));
    log(severity, LD_GENERAL,
        " * Cell-bearing channel " U64_FORMAT " last received a cell "
        "at " U64_FORMAT " (" U64_FORMAT " seconds ago)",
        U64_PRINTF_ARG(chan->global_identifier),
        U64_PRINTF_ARG(chan->u.cell_chan.timestamp_recv),
        U64_PRINTF_ARG(now - chan->u.cell_chan.timestamp_recv));
    log(severity, LD_GENERAL,
        " * Cell-bearing channel " U64_FORMAT " last trasmitted a cell "
        "at " U64_FORMAT " (" U64_FORMAT " seconds ago)",
        U64_PRINTF_ARG(chan->global_identifier),
        U64_PRINTF_ARG(chan->u.cell_chan.timestamp_xmit),
        U64_PRINTF_ARG(now - chan->u.cell_chan.timestamp_xmit));

    /* Describe counters and rates */
    log(severity, LD_GENERAL,
        " * Cell-bearing channel " U64_FORMAT " has received "
        U64_FORMAT " cells and transmitted " U64_FORMAT,
        U64_PRINTF_ARG(chan->global_identifier),
        U64_PRINTF_ARG(chan->u.cell_chan.n_cells_recved),
        U64_PRINTF_ARG(chan->u.cell_chan.n_cells_xmitted));
    if (now > chan->timestamp_created &&
        chan->timestamp_created > 0) {
      if (chan->u.cell_chan.n_cells_recved > 0) {
        avg = (double)(chan->u.cell_chan.n_cells_recved) / age;
        if (avg >= 1.0) {
          log(severity, LD_GENERAL,
              " * Cell-bearing channel " U64_FORMAT " has averaged %f "
              "cells received per second",
              U64_PRINTF_ARG(chan->global_identifier), avg);
        } else if (avg >= 0.0) {
          interval = 1.0 / avg;
          log(severity, LD_GENERAL,
              " * Cell-bearing channel " U64_FORMAT " has averaged %f "
              "seconds between received cells",
              U64_PRINTF_ARG(chan->global_identifier), interval);
        }
      }
      if (chan->u.cell_chan.n_cells_xmitted > 0) {
        avg = (double)(chan->u.cell_chan.n_cells_xmitted) / age;
        if (avg >= 1.0) {
          log(severity, LD_GENERAL,
              " * Cell-bearing channel " U64_FORMAT " has averaged %f "
              "cells transmitted per second",
              U64_PRINTF_ARG(chan->global_identifier), avg);
        } else if (avg >= 0.0) {
          interval = 1.0 / avg;
          log(severity, LD_GENERAL,
              " * Cell-bearing channel " U64_FORMAT " has averaged %f "
              "seconds between transmitted cells",
              U64_PRINTF_ARG(chan->global_identifier), interval);
        }
      }
    }
  }

  /* Dump anything the lower layer has to say */
  channel_dump_transport_statistics(chan, severity);
}

/**
 * Invoke transport-specific stats dump
 *
 * If there is a lower-layer statistics dump method, invoke it
 */

void
channel_dump_transport_statistics(channel_t *chan, int severity)
{
  tor_assert(chan);

  if (chan->dumpstats) chan->dumpstats(chan, severity);
}

/**
 * Return text description of the remote endpoint
 *
 * This function return a test provided by the lower layer of the remote
 * endpoint for this channel; it should specify the actual address connected
 * to/from.
 *
 * @param chan Channel to describe
 * @return Pointer to string description
 */

const char *
channel_get_actual_remote_descr(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));
  tor_assert(chan->u.cell_chan.get_remote_descr);

  /* Param 1 indicates the actual description */
  return chan->u.cell_chan.get_remote_descr(chan, 1);
}

/**
 * Return text description of the remote endpoint canonical address
 *
 * This function return a test provided by the lower layer of the remote
 * endpoint for this channel; it should use the known canonical address for
 * this OR's identity digest if possible.
 *
 * @param chan Channel to describe
 * @return Pointer to string description
 */

const char *
channel_get_canonical_remote_descr(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));
  tor_assert(chan->u.cell_chan.get_remote_descr);

  /* Param 0 indicates the canonicalized description */
  return chan->u.cell_chan.get_remote_descr(chan, 0);
}

/**
 * Get remote address if possible
 *
 * Write the remote address out to a tor_addr_t if the underlying transport
 * supports this operation.
 *
 * @param chan Channel to request remote address from
 * @param addr_out Write the address out here
 * @return 1 if successful, 0 if not
 */

int
channel_get_addr_if_possible(channel_t *chan, tor_addr_t *addr_out)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));
  tor_assert(addr_out);

  if (chan->u.cell_chan.get_remote_addr)
    return chan->u.cell_chan.get_remote_addr(chan, addr_out);
  /* Else no support, method not implemented */
  else return 0;
}

/**
 * Check if there are outgoing queue writes on this channel
 *
 * Indicate if either we have queued cells, or if not, whether the underlying
 * lower-layer transport thinks it has an output queue.
 *
 * @param chan Channel to query
 * @return 1 if there are queued writes, 0 otherwise
 */

int
channel_has_queued_writes(channel_t *chan)
{
  int has_writes = 0;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));
  tor_assert(chan->u.cell_chan.has_queued_writes);

  if (chan->u.cell_chan.outgoing_queue &&
      smartlist_len(chan->u.cell_chan.outgoing_queue) > 0) {
    has_writes = 1;
  } else {
    /* Check with the lower layer */
    has_writes = chan->u.cell_chan.has_queued_writes(chan);
  }

  return has_writes;
}

/**
 * Check the is_bad_for_new_circs flag
 *
 * This function returns the is_bad_for_new_circs flag of the specified
 * channel.
 *
 * @param chan Channel to get flag on
 * @return Flag value
 */

int
channel_is_bad_for_new_circs(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  return chan->u.cell_chan.is_bad_for_new_circs;
}

/**
 * Mark a channel as bad for new circuits
 *
 * Set the is_bad_for_new_circs_flag on chan.
 *
 * @param chan Channel to mark
 */

void
channel_mark_bad_for_new_circs(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  chan->u.cell_chan.is_bad_for_new_circs = 1;
}

/**
 * Get the client flag
 *
 * This returns the client flag of a channel, which will be set if
 * command_process_create_cell() in command.c thinks this is a connection
 * from a client.
 *
 * @param chan Channel to query flag
 * @return Flag value
 */

int
channel_is_client(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  return chan->u.cell_chan.is_client;
}

/**
 * Set the client flag
 *
 * Mark a channel as being from a client
 *
 * @param chan Channel to mark
 */

void
channel_mark_client(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  chan->u.cell_chan.is_client = 1;
}

/**
 * Get the canonical flag for a channel
 *
 * This returns the is_canonical for a channel; this flag is determined by
 * the lower layer and can't be set in a transport-independent way.
 *
 * @param chan Channel to query
 * @return Flag value
 */

int
channel_is_canonical(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));
  tor_assert(chan->u.cell_chan.is_canonical);

  return chan->u.cell_chan.is_canonical(chan, 0);
}

/**
 * Test if the canonical flag is reliable
 *
 * This function asks if the lower layer thinks it's safe to trust the
 * result of channel_is_canonical()
 *
 * @param chan Channel to query
 * @return 1 if the lower layer thinks the is_canonical flag is reliable, 0
 *         otherwise.
 */

int
channel_is_canonical_is_reliable(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));
  tor_assert(chan->u.cell_chan.is_canonical);

  return chan->u.cell_chan.is_canonical(chan, 1);
}

/**
 * Test incoming flag
 *
 * This function gets the incoming flag; this is set when a listener spawns
 * a channel.  If this returns true the channel was remotely initiated.
 *
 * @param chan Channel to query
 * @return Flag value
 */

int
channel_is_incoming(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  return chan->u.cell_chan.is_incoming;
}

/**
 * Set the incoming flag
 *
 * This function is called when a channel arrives on a listening channel
 * to mark it as incoming.
 *
 * @param chan Channel to mark
 */

void
channel_mark_incoming(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  chan->u.cell_chan.is_incoming = 1;
}

/**
 * Test local flag
 *
 * This function gets the local flag; the lower layer should set this when
 * setting up the channel if is_local_addr() is true for all of the
 * destinations it will communicate with on behalf of this channel.  It's
 * used to decide whether to declare the network reachable when seeing incoming
 * traffic on the channel.
 *
 * @param chan Channel to query
 * @return Flag value
 */

int
channel_is_local(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  return chan->u.cell_chan.is_local;
}

/**
 * Set the local flag
 *
 * This internal-only function should be called by the lower layer if the
 * channel is to a local address.  See channel_is_local() above or the
 * description of the is_local bit in channel.h
 *
 * @param chan Channel to mark
 */

void
channel_mark_local(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  chan->u.cell_chan.is_local = 1;
}

/**
 * Test outgoing flag
 *
 * This function gets the outgoing flag; this is the inverse of the incoming
 * bit set when a listener spawns a channel.  If this returns true the channel
 * was locally initiated.
 *
 * @param chan Channel to query
 * @return Flag value
 */

int
channel_is_outgoing(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  return !(chan->u.cell_chan.is_incoming);
}

/**
 * Mark a channel as outgoing
 *
 * This function clears the incoming flag and thus marks a channel as
 * outgoing.
 *
 * @param chan Channel to mark
 */

void
channel_mark_outgoing(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  chan->u.cell_chan.is_incoming = 0;
}

/*********************
 * Timestamp updates *
 ********************/

/**
 * Update the created timestamp
 *
 * This updates the channel's created timestamp and should only be called
 * from channel_init().
 *
 * @param chan Channel to update
 */

void
channel_timestamp_created(channel_t *chan)
{
  time_t now = time(NULL);

  tor_assert(chan);

  chan->timestamp_created = now;
}

/**
 * Update the last active timestamp.
 *
 * This function updates the channel's last active timestamp; it should be
 * called by the lower layer whenever there is activity on the channel which
 * does not lead to a cell being transmitted or received; the active timestamp
 * is also updated from channel_timestamp_recv() and channel_timestamp_xmit(),
 * but it should be updated for things like the v3 handshake and stuff that
 * produce activity only visible to the lower layer.
 *
 * @param chan Channel to update
 */

void
channel_timestamp_active(channel_t *chan)
{
  time_t now = time(NULL);

  tor_assert(chan);

  chan->timestamp_active = now;
}

/**
 * Update the last accepted timestamp.
 *
 * This function updates the channel's last accepted timestamp; it should be
 * called whenever a new incoming channel is accepted on a listener.
 *
 * @param chan Channel to update
 */

void
channel_timestamp_accepted(channel_t *chan)
{
  time_t now = time(NULL);

  tor_assert(chan);
  tor_assert(chan->is_listener);

  chan->u.listener.timestamp_accepted = now;
}

/**
 * Update client timestamp
 *
 * This function is called by relay.c to timestamp a channel that appears to
 * be used as a client.
 *
 * @param chan Channel to update
 */

void
channel_timestamp_client(channel_t *chan)
{
  time_t now = time(NULL);

  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  chan->u.cell_chan.timestamp_client = now;
}

/**
 * Update the last drained timestamp
 *
 * This is called whenever we transmit a cell which leaves the outgoing cell
 * queue completely empty.  It also updates the xmit time and the active time.
 *
 * @param chan Channel to update
 */

void
channel_timestamp_drained(channel_t *chan)
{
  time_t now = time(NULL);

  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  chan->timestamp_active = now;
  chan->u.cell_chan.timestamp_drained = now;
  chan->u.cell_chan.timestamp_xmit = now;
}

/**
 * Update the recv timestamp
 *
 * This is called whenever we get an incoming cell from the lower layer.
 * This also updates the active timestamp.
 *
 * @param chan Channel to update
 */

void
channel_timestamp_recv(channel_t *chan)
{
  time_t now = time(NULL);

  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  chan->timestamp_active = now;
  chan->u.cell_chan.timestamp_recv = now;
}

/**
 * Update the xmit timestamp
 * This is called whenever we pass an outgoing cell to the lower layer.  This
 * also updates the active timestamp.
 *
 * @param chan Channel to update
 */

void
channel_timestamp_xmit(channel_t *chan)
{
  time_t now = time(NULL);

  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  chan->timestamp_active = now;
  chan->u.cell_chan.timestamp_xmit = now;
}

/***************************************************************
 * Timestamp queries - see above for definitions of timestamps *
 **************************************************************/

/**
 * Query created timestamp
 *
 * @param chan Channel to query
 * @return Created timestamp value for chan
 */

time_t
channel_when_created(channel_t *chan)
{
  tor_assert(chan);

  return chan->timestamp_created;
}

/**
 * Query last active timestamp
 *
 * @param chan Channel to query
 * @return Last active timestamp value for chan
 */

time_t
channel_when_last_active(channel_t *chan)
{
  tor_assert(chan);

  return chan->timestamp_active;
}

/**
 * Query last accepted timestamp
 *
 * @param chan Channel to query
 * @return Last accepted timestamp value for chan
 */

time_t
channel_when_last_accepted(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(chan->is_listener);

  return chan->u.listener.timestamp_accepted;
}

/**
 * Query client timestamp
 *
 * @param chan Channel to query
 * @return Client timestamp value for chan
 */

time_t
channel_when_last_client(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  return chan->u.cell_chan.timestamp_client;
}

/**
 * Query drained timestamp
 *
 * @param chan Channel to query
 * @return drained timestamp value for chan
 */

time_t
channel_when_last_drained(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  return chan->u.cell_chan.timestamp_drained;
}

/**
 * Query recv timestamp
 *
 * @param chan Channel to query
 * @return Recv timestamp value for chan
 */

time_t
channel_when_last_recv(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  return chan->u.cell_chan.timestamp_recv;
}

/**
 * Query xmit timestamp
 *
 * @param chan Channel to query
 * @return Xmit timestamp value for chan
 */

time_t
channel_when_last_xmit(channel_t *chan)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  return chan->u.cell_chan.timestamp_xmit;
}

/**
 * Query accepted counter
 *
 * @param chan Channel to query
 * @return Number of incoming channels accepted by this listener
 */

uint64_t
channel_count_accepted(channel_t *chan)
{
  tor_assert(chan);

  if (chan->is_listener) return chan->u.listener.n_accepted;
  else return 0;
}

/**
 * Query received cell counter
 *
 * @param chan Channel to query
 * @return Number of cells received by this channel
 */

uint64_t
channel_count_recved(channel_t *chan)
{
  tor_assert(chan);

  if (!(chan->is_listener)) return chan->u.cell_chan.n_cells_recved;
  else return 0;
}

/**
 * Query transmitted cell counter
 *
 * @param chan Channel to query
 * @return Number of cells transmitted by this channel
 */

uint64_t
channel_count_xmitted(channel_t *chan)
{
  tor_assert(chan);

  if (!(chan->is_listener)) return chan->u.cell_chan.n_cells_xmitted;
  else return 0;
}

/**
 * Check if a channel matches an extend_info_t
 *
 * This function calls the lower layer and asks if this channel matches a
 * given extend_info_t.
 *
 * @param chan Channel to test
 * @param extend_info Pointer to extend_info_t to match
 * @return 1 if they match, 0 otherwise
 */

int
channel_matches_extend_info(channel_t *chan, extend_info_t *extend_info)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));
  tor_assert(chan->u.cell_chan.matches_extend_info);
  tor_assert(extend_info);

  return chan->u.cell_chan.matches_extend_info(chan, extend_info);
}

/**
 * Check if a channel matches a given target address
 *
 * This function calls into the lower layer and asks if this channel thinks
 * it matches a given target address for circuit extension purposes.
 *
 * @param chan Channel to test
 * @param target Address to match
 * @return 1 if they match, 0 otherwise
 */

int
channel_matches_target_addr_for_extend(channel_t *chan,
                                       const tor_addr_t *target)
{
  tor_assert(chan);
  tor_assert(!(chan->is_listener));
  tor_assert(chan->u.cell_chan.matches_target);
  tor_assert(target);

  return chan->u.cell_chan.matches_target(chan, target);
}

/**
 * Set up circuit ID generation
 *
 * This is called when setting up a channel and replaces the old
 * connection_or_set_circid_type()
 *
 * @param chan Channel to set up
 * @param identity_rcvd Remote end's identity public key
 */

void
channel_set_circid_type(channel_t *chan, crypto_pk_t *identity_rcvd)
{
  int started_here;
  crypto_pk_t *our_identity;

  tor_assert(chan);
  tor_assert(!(chan->is_listener));

  started_here = channel_is_outgoing(chan);
  our_identity = started_here ?
    get_tlsclient_identity_key() : get_server_identity_key();

  if (identity_rcvd) {
    if (crypto_pk_cmp_keys(our_identity, identity_rcvd) < 0) {
      chan->u.cell_chan.circ_id_type = CIRC_ID_TYPE_LOWER;
    } else {
      chan->u.cell_chan.circ_id_type = CIRC_ID_TYPE_HIGHER;
    }
  } else {
    chan->u.cell_chan.circ_id_type = CIRC_ID_TYPE_NEITHER;
  }
}

