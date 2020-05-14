/* Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file ocirc_event.c
 * \brief Publish state change messages for origin circuits
 *
 * Implements a basic publish-subscribe framework for messages about
 * the state of origin circuits.  The publisher calls the subscriber
 * callback functions synchronously.
 *
 * Although the synchronous calls might not simplify the call graph,
 * this approach improves data isolation because the publisher doesn't
 * need knowledge about the internals of subscribing subsystems.  It
 * also avoids race conditions that might occur in asynchronous
 * frameworks.
 **/

#include "core/or/or.h"

#define OCIRC_EVENT_PRIVATE

#include "core/or/cpath_build_state_st.h"
#include "core/or/ocirc_event.h"
#include "core/or/ocirc_event_sys.h"
#include "core/or/origin_circuit_st.h"
#include "lib/subsys/subsys.h"

/** List of subscribers */
static smartlist_t *ocirc_event_rcvrs;

/** Initialize subscriber list */
static int
ocirc_event_init(void)
{
  ocirc_event_rcvrs = smartlist_new();
  return 0;
}

/** Free subscriber list */
static void
ocirc_event_fini(void)
{
  smartlist_free(ocirc_event_rcvrs);
}

/**
 * Subscribe to messages about origin circuit events
 *
 * Register a callback function to receive messages about origin
 * circuits.  The publisher calls this function synchronously.
 **/
void
ocirc_event_subscribe(ocirc_event_rcvr_t fn)
{
  tor_assert(fn);
  /* Don't duplicate subscriptions. */
  if (smartlist_contains(ocirc_event_rcvrs, fn))
    return;

  smartlist_add(ocirc_event_rcvrs, fn);
}

/**
 * Publish a message about OR connection events
 *
 * This calls the subscriber receiver function synchronously.
 **/
void
ocirc_event_publish(const ocirc_event_msg_t *msg)
{
  SMARTLIST_FOREACH_BEGIN(ocirc_event_rcvrs, ocirc_event_rcvr_t, fn) {
    tor_assert(fn);
    (*fn)(msg);
  } SMARTLIST_FOREACH_END(fn);
}

const subsys_fns_t sys_ocirc_event = {
  .name = "ocirc_event",
  .supported = true,
  .level = -32,
  .initialize = ocirc_event_init,
  .shutdown = ocirc_event_fini,
};
