/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file dispatch_st.h
 *
 * @brief private structures used for the dispatcher module
 */

#ifndef TOR_DISPATCH_ST_H
#define TOR_DISPATCH_ST_H

#ifdef DISPATCH_PRIVATE

#include "lib/container/smartlist.h"
#include "lib/container/mqueue.h"
#include "lib/dispatch/namemap.h"

// XXXX detect orphaned types

/**
 * Configuration for a single publication or subscription request.
 *
 * These are stored while the dispatcher is in use, but are only used for
 * setup, teardown, and debugging.
 *
 * There are various fields in this request describing the message; all of
 * them must match other descriptions of the message, or a bug has occurred.
 **/
typedef struct pubsub_cfg_t {
  /** True if this is a publishing request; false for a subscribing request. */
  bool is_publish;
  /** The system making this request. */
  subsys_id_t subsys;
  /** The channel on which the message is to be sent. */
  channel_id_t channel;
  /** The message ID to be sent or received. */
  message_id_t msg;
  /** The C type associated with the message. */
  msg_type_id_t type;
  /** One or more DISP_FLAGS_* items, combined with bitwise OR. */
  unsigned flags;

  /**
   * Publishing only: a pub_binding object that will receive the binding for
   * this request.  We will finish filling this in when the dispatcher is
   * constructed, so that the subsystem can publish then and not before.
   */
  pub_binding_t *pub_binding;

  /**
   * Subscribing only: a function to receive message objects for this request.
   */
  recv_fn_t recv_fn;

  /** The file from which this message was configured */
  const char *added_by_file;
  /** The line at which this message was configured */
  unsigned added_by_line;
} pubsub_cfg_t;

/**
 * Configuration request for a single C type.
 *
 * These are stored while the dispatcher is in use, but are only used for
 * setup, teardown, and debugging.
 **/
typedef struct pubsub_type_cfg_t {
  /**
   * The identifier for this type.
   */
  msg_type_id_t type;
  /**
   * Functions to use when manipulating the type.
   */
  dispatch_typefns_t fns;

  /** The subsystem that configured this type. */
  subsys_id_t subsys;
  /** The file from which this type was configured */
  const char *added_by_file;
  /** The line at which this type was configured */
  unsigned added_by_line;
} pubsub_type_cfg_t;

/**
 * The set of configuration requests for a dispatcher, as made by various
 * subsystems.
 **/
typedef struct dispatch_cfg_t {
  smartlist_t *items;
  smartlist_t *type_items;
} dispatch_cfg_t;

/**
 * The number of function pointers that are stored inline in each
 * dispatch_table_entry, instead of being allocated elsewhere on the heap.
 */
/* XXXX NOTE: This value is intentionally set a little too low right now, so
 * that we'll definitely exercise this code in practice.  I think 4 or 8 would
 * be better. */
#define N_FAST_FNS 2

/**
 * Information used by a dispatcher to handle and dispatch a single message
 * ID.
 *
 * This structure is used when the dispatcher is running.
 **/
typedef struct dispatch_table_entry_t {
  /** The number of enabled non-stub subscribers for this message.
   *
   * Note that for now, this will be the same as <b>n_fns</b>, since there is
   * no way to turn these subscribers on an off yet. */
  uint16_t n_enabled;
  /** The channel that handles this message. */
  channel_id_t channel;
  /** The associated C type for this message. */
  msg_type_id_t type;
  /**
   * The number of functions pointers for subscribers that receive this
   * message, in <b>fns</b> and <b>more_fns</b>. */
  uint16_t n_fns;
  /**
   * The first N_FAST_FNS function pointers for recipients for this message.
   *
   * These are kept inline in this structure for efficieny in the common case
   * where a message only has a few subscribers.
   */
  recv_fn_t fns[N_FAST_FNS];
  /**
   * Array of remaining function pointers for recipients for this message.  If
   * there are N_FAST_FNS or fewer such recipients, then is pointer is NULL.
   */
  recv_fn_t *more_fns;
} dispatch_table_entry_t;

/**
 * A queue of messages for a given channel, used by a live dispatcher.
 */
typedef struct dispatch_queue_t {
  /** The queue of messages itself. */
  mqueue_t queue;
  /** A function to be called when the queue becomes nonempty. */
  dispatch_alertfn_t alert_fn;
  /** An argument for the alert_fn. */
  void *alert_fn_arg;
} dispatch_queue_t ;

/**
 * A single dispatcher for cross-module messages.
 */
struct dispatcher_t {
  /**
   * The configuration object used to make this dispatcher. We only use it
   * for constructing, teardown, and debugging.
   */
  const dispatch_cfg_t *cfg;
  /**
   * The length of <b>table</b>: the number of message IDs that this
   * dispatcher can handle.
   */
  size_t n_msgs;
  /**
   * The length of <b>queues</b>: the number of channels that this dispatcher
   * has configured.
   */
  size_t n_queues;
  /**
   * The length of <b>typefns</b>: the number of C type IDs that this
   * dispatcher has configured.
   */
  size_t n_types;
  /**
   * An array of message queues, indexed by channel ID.
   */
  dispatch_queue_t *queues;
  /**
   * An array of entries about how to handle particular message types, indexed
   * by message ID.
   */
  dispatch_table_entry_t *table;
  /**
   * An array of function tables for manipulating types, index by message
   * type ID.
   **/
  dispatch_typefns_t *typefns;
};

/**
 * Type used to construct a dispatcher.  We use this type to build up the
 * configuration for a dispatcher, and then pass ownership of that
 * configuration to the newly constructed dispatcher.
 **/
struct dispatch_builder_t {
  /** Number of outstanding dispatch_connector_t objects pointing to this
   * dispatcher. */
  int n_connectors;
  /** In-progress configuration that we're constructing. */
  dispatch_cfg_t *cfg;
};

/**
 * Type given to a subsystem when adding connections to a dispatch_builder.
 * We use this type to force each subsystem to get blamed for the
 * publications, subscriptions, and types that it adds.
 **/
struct dispatch_connector_t {
  /** The dispatch builder that this connector refers to. */
  struct dispatch_builder_t *builder;
  /** The subsystem that has been given this connector. */
  subsys_id_t subsys_id;
};

/**
 * Helper structure used when constructing a dispatcher that sorts the
 * pubsub_cfg_t objects in various ways.
 **/
typedef struct dispatch_adjacency_map_t {
  /* XXXX The next three fields are currently constructed but not yet
   * XXXX used. I beleive we'll want them in the future, though. -nickm
   */
  /** Number of subsystems; length of the *_by_subsys arrays. */
  size_t n_subsystems;
  /** Array of lists of publisher pubsub_cfg_t objects, indexed by
   * subsystem. */
  smartlist_t **pub_by_subsys;
  /** Array of lists of subscriber pubsub_cfg_t objects, indexed by
   * subsystem. */
  smartlist_t **sub_by_subsys;

  /** Number of message IDs; length of the *_by_msg arrays. */
  size_t n_msgs;
  /** Array of lists of publisher pubsub_cfg_t objects, indexed by
   * message ID. */
  smartlist_t **pub_by_msg;
  /** Array of lists of subscriber pubsub_cfg_t objects, indexed by
   * message ID. */
  smartlist_t **sub_by_msg;
} dispatch_adjacency_map_t;

#endif

#endif
