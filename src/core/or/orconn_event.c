/* Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file orconn_event.c
 * \brief Publish state change messages for OR connections
 *
 * Implements a basic publish-subscribe framework for messages about
 * the state of OR connections.  The publisher calls the subscriber
 * callback functions synchronously.
 *
 * Although the synchronous calls might not simplify the call graph,
 * this approach improves data isolation because the publisher doesn't
 * need knowledge about the internals of subscribing subsystems.  It
 * also avoids race conditions that might occur in asynchronous
 * frameworks.
 **/

#include "core/or/or.h"
#include "lib/subsys/subsys.h"

#define ORCONN_EVENT_PRIVATE
#include "core/or/orconn_event.h"
#include "core/or/orconn_event_sys.h"

/** List of subscribers */
static smartlist_t *orconn_event_rcvrs;

/** Initialize subscriber list */
static int
orconn_event_init(void)
{
  orconn_event_rcvrs = smartlist_new();
  return 0;
}

/** Free subscriber list */
static void
orconn_event_fini(void)
{
  smartlist_free(orconn_event_rcvrs);
}

/**
 * Subscribe to messages about OR connection events
 *
 * Register a callback function to receive messages about ORCONNs.
 * The publisher calls this function synchronously.
 **/
void
orconn_event_subscribe(orconn_event_rcvr_t fn)
{
  tor_assert(fn);
  /* Don't duplicate subscriptions. */
  if (smartlist_contains(orconn_event_rcvrs, fn))
    return;

  smartlist_add(orconn_event_rcvrs, fn);
}

/**
 * Publish a message about OR connection events
 *
 * This calls the subscriber receiver function synchronously.
 **/
void
orconn_event_publish(const orconn_event_msg_t *msg)
{
  SMARTLIST_FOREACH_BEGIN(orconn_event_rcvrs, orconn_event_rcvr_t, fn) {
    tor_assert(fn);
    (*fn)(msg);
  } SMARTLIST_FOREACH_END(fn);
}

const subsys_fns_t sys_orconn_event = {
  .name = "orconn_event",
  .supported = true,
  .level = -33,
  .initialize = orconn_event_init,
  .shutdown = orconn_event_fini,
};
