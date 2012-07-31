/* * Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file channel.h
 * \brief Header file for channel.c
 **/

#ifndef _TOR_CHANNEL_H
#define _TOR_CHANNEL_H

#include "or.h"

/*
 * Channel struct; see thw channel_t typedef in or.h.  A channel is an
 * abstract interface for the OR-to-OR connection, similar to connection_or_t,
 * but without the strong coupling to the underlying TLS implementation.  They
 * are constructed by calling a protocol-specific function to open a channel
 * to a particular node, and once constructed support the abstract operations
 * defined below.
 */

struct channel_s {
  /* Current channel state */
  channel_state_t state;

  /* Globally unique ID number for a channel over the lifetime of a Tor
   * process.
   */
  uint64_t global_identifier;

  /* Should we expect to see this channel in the channel lists? */
  unsigned char registered:1;

  /** Set this if this channel is created in CHANNEL_STATE_LISTEN, so
   * lower-layer close methods that see the channel in CHANNEL_STATE_CLOSING
   * know.
   */
  unsigned int is_listener:1;

  /** Why did we close?
   */
  enum {
    CHANNEL_NOT_CLOSING = 0,
    CHANNEL_CLOSE_REQUESTED,
    CHANNEL_CLOSE_FROM_BELOW,
    CHANNEL_CLOSE_FOR_ERROR
  } reason_for_closing;

  /* Timestamps for both cell channels and listeners */
  time_t timestamp_created; /* Channel created */
  time_t timestamp_active; /* Any activity */

  /* Methods implemented by the lower layer */

  /* Free a channel */
  void (*free)(channel_t *);
  /* Close an open channel */
  void (*close)(channel_t *);

  union {
    struct {
      /* Registered listen handler to call on incoming connection */
      void (*listener)(channel_t *, channel_t *);

      /* List of pending incoming connections */
      smartlist_t *incoming_list;
    } listener;
    struct {
      /* Registered handlers for incoming cells */
      void (*cell_handler)(channel_t *, cell_t *);
      void (*var_cell_handler)(channel_t *, var_cell_t *);

      /* Methods implemented by the lower layer */

      /*
       * Ask the underlying transport what the remote endpoint address is, in
       * a tor_addr_t.  This is optional and subclasses may leave this NULL.
       * If they implement it, they should write the address out to the
       * provided tor_addr_t *, and return 1 if successful or 0 if no address
       * available.
       */
      int (*get_remote_addr)(channel_t *, tor_addr_t *);
      /*
       * Get a text description of the remote endpoint; canonicalized if the
       * arg is 0, or the one we originally connected to/received from if it's
       * 1.
       */
      const char * (*get_remote_descr)(channel_t *, int);
      /* Check if the lower layer has queued writes */
      int (*has_queued_writes)(channel_t *);
      /*
       * If the second param is zero, ask the lower layer if this is
       * 'canonical', for a transport-specific definition of canonical; if
       * it is 1, ask if the answer to the preceding query is safe to rely
       * on.
       */
      int (*is_canonical)(channel_t *, int);
      /* Check if this channel matches a specified extend_info_t */
      int (*matches_extend_info)(channel_t *, extend_info_t *);
      /* Check if this channel matches a target address when extending */
      int (*matches_target)(channel_t *, const tor_addr_t *);
      /* Write a cell to an open channel */
      int (*write_cell)(channel_t *, cell_t *);
      /* Write a packed cell to an open channel */
      int (*write_packed_cell)(channel_t *, packed_cell_t *);
      /* Write a variable-length cell to an open channel */
      int (*write_var_cell)(channel_t *, var_cell_t *);

      /*
       * Hash of the public RSA key for the other side's identity key, or
       * zeroes if the other side hasn't shown us a valid identity key.
       */
      char identity_digest[DIGEST_LEN];
      /* Nickname of the OR on the other side, or NULL if none. */
      char *nickname;

      /*
       * Linked list of channels with the same identity digest, for the
       * digest->channel map
       */
      channel_t *next_with_same_id, *prev_with_same_id;

      /* List of incoming cells to handle */
      smartlist_t *cell_queue;

      /* List of queued outgoing cells */
      smartlist_t *outgoing_queue;

      /*
       * When we last used this conn for any client traffic. If not
       * recent, we can rate limit it further.
       */
      time_t client_used;

      /* Circuit stuff for use by relay.c */

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

      /* Circuit ID generation stuff for use by circuitbuild.c */

      /*
       * When we send CREATE cells along this connection, which half of the
       * space should we use?
       */
      circ_id_type_t circ_id_type:2;
      /*
       * Which circ_id do we try to use next on this connection?  This is
       * always in the range 0..1<<15-1.
       */
      circid_t next_circ_id;

      /* How many circuits use this connection as p_chan or n_chan? */
      int n_circuits;

      /*
       * True iff this channel shouldn't get any new circs attached to it,
       * because the connection is too old, or because there's a better one.
       * More generally, this flag is used to note an unhealthy connection;
       * for example, if a bad connection fails we shouldn't assume that the
       * router itself has a problem.
       */
      unsigned int is_bad_for_new_circs:1;

      /** True iff we have decided that the other end of this connection
       * is a client.  Channels with this flag set should never be used
       * to satisfy an EXTEND request.  */
      unsigned int is_client:1;

      /** Set if the channel was initiated remotely (came from a listener) */
      unsigned int is_incoming:1;

      /** Set by lower layer if this is local; i.e., everything it communicates
       * with for this channel returns true for is_local_addr().  This is used
       * to decide whether to declare reachability when we receive something on
       * this channel in circuitbuild.c
       */
      unsigned int is_local:1;

      /** Channel timestamps for cell channels */
      time_t timestamp_client; /* Client used this, according to relay.c */
      time_t timestamp_drained; /* Output queue empty */
      time_t timestamp_recv; /* Cell received from lower layer */
      time_t timestamp_xmit; /* Cell sent to lower layer */

      /* Timestamp for relay.c */
      time_t timestamp_last_added_nonpadding;

      /** Unique ID for measuring direct network status requests;vtunneled ones
       * come over a circuit_t, which has a dirreq_id field as well, but is a
       * distinct namespace. */
      uint64_t dirreq_id;
    } cell_chan;
  } u;
};

/* Channel state manipulations */

int channel_state_is_valid(channel_state_t state);
int channel_state_can_transition(channel_state_t from, channel_state_t to);
const char * channel_state_to_string(channel_state_t state);

/* Abstract channel operations */

void channel_request_close(channel_t *chan);
void channel_write_cell(channel_t *chan, cell_t *cell);
void channel_write_packed_cell(channel_t *chan, packed_cell_t *cell);
void channel_write_var_cell(channel_t *chan, var_cell_t *cell);

/* Channel callback registrations */

/* Listener callback */
void (* channel_get_listener(channel_t *chan))(channel_t *, channel_t *);
void channel_set_listener(channel_t *chan,
                          void (*listener)(channel_t *, channel_t *) );

/* Incoming cell callbacks */
void (* channel_get_cell_handler(channel_t *chan))
  (channel_t *, cell_t *);
void (* channel_get_var_cell_handler(channel_t *chan))
  (channel_t *, var_cell_t *);
void channel_set_cell_handler(channel_t *chan,
                              void (*cell_handler)(channel_t *, cell_t *));
void channel_set_cell_handlers(channel_t *chan,
                               void (*cell_handler)(channel_t *, cell_t *),
                               void (*var_cell_handler)(channel_t *,
                                                        var_cell_t *));
void channel_set_var_cell_handler(channel_t *chan,
                                  void (*var_cell_handler)(channel_t *,
                                                           var_cell_t *));

/* Clean up closed channels periodically; called from run_scheduled_events()
 * in main.c
 */
void channel_run_cleanup(void);

/* Close all channels and deallocate everything */
void channel_free_all(void);

#ifdef _TOR_CHANNEL_INTERNAL

/* Channel operations for subclasses and internal use only */

/* Initialize a newly allocated channel - do this first in subclass
 * constructors.
 */

void channel_init_for_cells(channel_t *chan);
void channel_init_listener(channel_t *chan);

/* Channel registration/unregistration */
void channel_register(channel_t *chan);
void channel_unregister(channel_t *chan);

/* Close from below */
void channel_close_from_lower_layer(channel_t *chan);
void channel_close_for_error(channel_t *chan);
void channel_closed(channel_t *chan);

/* Free a channel */
void channel_free(channel_t *chan);
void channel_force_free(channel_t *chan);

/* State/metadata setters */

void channel_change_state(channel_t *chan, channel_state_t to_state);
void channel_clear_identity_digest(channel_t *chan);
void channel_clear_remote_end(channel_t *chan);
void channel_mark_local(channel_t *chan);
void channel_mark_incoming(channel_t *chan);
void channel_mark_outgoing(channel_t *chan);
void channel_set_identity_digest(channel_t *chan,
                                 const char *identity_digest);
void channel_set_remote_end(channel_t *chan,
                            const char *identity_digest,
                            const char *nickname);

/* Timestamp updates */
void channel_timestamp_created(channel_t *chan);
void channel_timestamp_active(channel_t *chan);
void channel_timestamp_drained(channel_t *chan);
void channel_timestamp_recv(channel_t *chan);
void channel_timestamp_xmit(channel_t *chan);

/* Incoming channel handling */
void channel_process_incoming(channel_t *listener);
void channel_queue_incoming(channel_t *listener, channel_t *incoming);

/* Incoming cell handling */
void channel_process_cells(channel_t *chan);
void channel_queue_cell(channel_t *chan, cell_t *cell);
void channel_queue_var_cell(channel_t *chan, var_cell_t *var_cell);

/* Outgoing cell handling */
void channel_flush_cells(channel_t *chan);

/* Request from lower layer for more cells if available */
ssize_t channel_flush_some_cells(channel_t *chan, ssize_t num_cells);

/* Query if data available on this channel */
int channel_more_to_flush(channel_t *chan);

/* Notify flushed outgoing for dirreq handling */
void channel_notify_flushed(channel_t *chan);

/* Handle stuff we need to do on open like notifying circuits */
void channel_do_open_actions(channel_t *chan);

#endif

/* Helper functions to perform operations on channels */

int channel_send_destroy(circid_t circ_id, channel_t *chan,
                         int reason);

/*
 * Outside abstract interfaces that should eventually get turned into
 * something transport/address format independent.
 */

channel_t * channel_connect(const tor_addr_t *addr, uint16_t port,
                            const char *id_digest);

channel_t * channel_get_for_extend(const char *digest,
                                   const tor_addr_t *target_addr,
                                   const char **msg_out,
                                   int *launch_out);

/* Ask which of two channels is better for circuit-extension purposes */
int channel_is_better(time_t now,
                      channel_t *a, channel_t *b,
                      int forgive_new_connections);

/** Channel lookups
 */

channel_t * channel_find_by_global_id(uint64_t global_identifier);
channel_t * channel_find_by_remote_digest(const char *identity_digest);
channel_t * channel_find_by_remote_nickname(const char *nickname);

/** For things returned by channel_find_by_remote_digest(), walk the list.
 */

channel_t * channel_next_with_digest(channel_t *chan);
channel_t * channel_prev_with_digest(channel_t *chan);

/*
 * Metadata queries/updates
 */

const char * channel_get_actual_remote_descr(channel_t *chan);
int channel_get_addr_if_possible(channel_t *chan, tor_addr_t *addr_out);
const char * channel_get_canonical_remote_descr(channel_t *chan);
int channel_has_queued_writes(channel_t *chan);
int channel_is_bad_for_new_circs(channel_t *chan);
void channel_mark_bad_for_new_circs(channel_t *chan);
int channel_is_canonical(channel_t *chan);
int channel_is_canonical_is_reliable(channel_t *chan);
int channel_is_client(channel_t *chan);
int channel_is_local(channel_t *chan);
int channel_is_incoming(channel_t *chan);
int channel_is_outgoing(channel_t *chan);
void channel_mark_client(channel_t *chan);
int channel_matches_extend_info(channel_t *chan, extend_info_t *extend_info);
int channel_matches_target_addr_for_extend(channel_t *chan,
                                           const tor_addr_t *target);
void channel_set_circid_type(channel_t *chan, crypto_pk_t *identity_rcvd);
void channel_timestamp_client(channel_t *chan);

/* Timestamp queries */
time_t channel_when_created(channel_t *chan);
time_t channel_when_last_active(channel_t *chan);
time_t channel_when_last_client(channel_t *chan);
time_t channel_when_last_drained(channel_t *chan);
time_t channel_when_last_recv(channel_t *chan);
time_t channel_when_last_xmit(channel_t *chan);

#endif

