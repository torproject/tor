/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_DISPATCH_CORE_H
#define TOR_DISPATCH_CORE_H

#include "lib/dispatch/msgtypes.h"

/**
 * Overview: Messages are sent over channels.  Before sending a message on a
 * channel, or receiving a message on a channel, a subsystem needs to register
 * that it publishes, or subscribes, to that message, on that channel.
 *
 * Messages, channels, and subsystems are represented internally as short
 * integers, though they are associated with human-readable strings for
 * initialization and debugging.
 *
 * When registering for a message, a subsystem must say whether it is an
 * exclusive publisher/subscriber to that message type, or whether other
 * subsystems may also publish/subscribe to it.
 *
 * All messages and their publishers/subscribers must be registered early in
 * the initialization process.
 *
 * By default, it is an error for a message type to have publishers and no
 * subscribers on a channel, or subscribers and no publishers on a channel.
 *
 * A subsystem may register for a message with a note that delivery or
 * production is disabled -- for example, because the subsystem is
 * disabled at compile-time. It is not an error for a message type to
 * have all of its publishers or subscribers disabled.
 *
 * After a message is sent, it is delivered to every recipient.  This
 * delivery happens from the top level of the event loop; it may be
 * interleaved with network events, timers, etc.
 *
 * Messages may have associated data.  This data is typed, and is owned
 * by the message.  Strings, byte-arrays, and integers have built-in
 * support.  Other types may be added.  If objects are to be sent,
 * they should be identified by handle.  If an object requires cleanup,
 * it should be declared with an associated free function.
 *
 * Semantically, if two subsystems communicate only by this kind of
 * message passing, neither is considered to depend on the other, though
 * both are considered to have a dependency on the message and on any
 * types it contains.
 *
 * (Or generational index?)
 **/

/**
 * A "dispatcher" is the highest-level object; it handles making sure that
 * messages are received and delivered properly.  Only the mainloop
 * handles this type directly.
 */
typedef struct dispatcher_t dispatcher_t;

/**
 * A "dispatch builder" is an incomplete dispatcher, used when
 * registering messages.  It does not have the same integrity guarantees
 * as a dispatcher.  It cannot actually handle messages itself: once all
 * subsystems have registered, it is converted into a dispatcher_t.
 **/
typedef struct dispatch_builder_t dispatch_builder_t;

/**
 * Create a new dispatch_builder. This should only happen in the
 * main-init code.
 */
dispatch_builder_t *dispatch_builder_new(void);

/**
 * Free a dispatch builder.  This should only happen on error paths, where
 * we have decided not to construct a dispatcher for some reason.
 */
void dispatch_builder_free(dispatch_builder_t *);

/**
 * Create a dispatch connector that a single subsystem will use to
 * register its messages.  The main-init code does this during susbsystem
 * initialization.
 */
dispatch_connector_t *dispatch_connector_for_subsystem(dispatch_builder_t *,
                                                       subsys_id_t);

/**
 * The main-init code does this after subsystem initialization.
 */
void dispatch_connector_free(dispatch_connector_t *);

/**
 * Constructs a dispatcher from a dispatch_builder, after checking that the
 * invariances on the messages, channels, and connections have been
 * respected.
 *
 * This should happen after every subsystem has initialized, and before
 * entering the mainloop.
 */
dispatcher_t *dispatch_finalize(dispatch_builder_t *);

/**
 * Free a dispatcher.  Tor does this at exit.
 */
void dispatch_free(dispatcher_t *);

/* Flush up to <b>max_msgs</b> currently pending messages from the
 * dispatcher.  Messages that are not pending when this function are
 * called, are not flushed by this call.  Return 0 on success, -1 on
 * unrecoverable error.
 */
int dispatch_flush(dispatcher_t *, int max_msgs);

// ============================================================
// Inner message handling: registration

/* Lowest level function to add a message to be published.  You won't be
 * calling this directly.  It return 0 on success and -1 on failure.
 */
int dispatch_connector_add_pub_message_internal(dispatch_connector_t *,
                                                channel_id_t,
                                                message_id_t,
                                                msg_type_id_t,
                                                unsigned flags);

typedef void (*recv_fn_t)(const msg_t *);

/* Lowest level function to add a message to be received. You won't be
 * calling this one directly either.  It returns 0 on succcess and -1 on
 * failure.
 */
int dispatch_connector_add_sub_message_internal(dispatch_connector_t *,
                                                channel_id_t,
                                                message_id_t,
                                                msg_type_id_t,
                                                unsigned flags,
                                                recv_fn_t recv_fn);

// Inner message handling: type registration.  We jump through some hoops
// for typesafety.

typedef void (*freefn_t)(void *);

int dispatch_connector_define_type(dispatch_connector_t *,
                                   msg_type_id_t,
                                   freefn_t,
                                   recv_fn_t);

#endif
