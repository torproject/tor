/* Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file btrack_orconn.c
 * \brief Bootstrap tracker for OR connections
 *
 * Track state changes of OR connections, as published by the
 * connection subsystem.  Also track circuit launch events, because
 * they're one of the few ways to discover the association between a
 * channel (and OR connection) and a circuit.
 *
 * We track all OR connections that we receive events for, whether or
 * not they're carrying origin circuits.  (An OR connection might
 * carry origin circuits only after we first find out about that
 * connection.)
 *
 * All origin ORCONN events update the "any" state variables, while
 * only application ORCONN events update the "ap" state variables (and
 * also update the "any") variables.
 *
 * We do this because we want to report the first increments of
 * connection progress as the earliest bootstrap phases.  This results
 * in a better user experience because failures here translate into
 * zero or very small amounts of displayed progress, instead of
 * progress stuck near completion.  The first connection to a relay
 * might be a one-hop circuit for directory lookups, or it might be a
 * connection for an application circuit because we already have
 * enough directory info to build an application circuit.
 *
 * We call functions in btrack_orconn_cevent.c to generate the actual
 * controller events, because some of the state decoding we need to do
 * is complicated.
 **/

#include <stdbool.h>

#include "core/or/or.h"

#define BTRACK_ORCONN_PRIVATE

#include "core/or/ocirc_event.h"
#include "core/or/orconn_event.h"
#include "feature/control/btrack_orconn.h"
#include "feature/control/btrack_orconn_cevent.h"
#include "feature/control/btrack_orconn_maps.h"
#include "lib/log/log.h"

/** Pair of a best ORCONN GID and with its state */
typedef struct bto_best_t {
  uint64_t gid;
  int state;
} bto_best_t;

/** GID and state of the best ORCONN we've seen so far */
static bto_best_t best_any = { 0, -1 };
/** GID and state of the best application circuit ORCONN we've seen so far */
static bto_best_t best_ap = { 0, -1 };

/**
 * Update a cached state of a best ORCONN progress we've seen so far.
 *
 * Return true if the new state is better than the old.
 **/
static bool
bto_update_best(const bt_orconn_t *bto, bto_best_t *best, const char *type)
{
  if (bto->state < best->state)
    return false;
  /* Update even if we won't change best->state, because it's more
   * recent information that a particular connection transitioned to
   * that state. */
  best->gid = bto->gid;
  if (bto->state > best->state) {
    log_info(LD_BTRACK, "ORCONN BEST_%s state %d->%d gid=%"PRIu64, type,
             best->state, bto->state, bto->gid);
    best->state = bto->state;
    return true;
  }
  return false;
}

/**
 * Update cached states of best ORCONN progress we've seen
 *
 * Only update the application ORCONN state if we know it's carrying
 * an application circuit.
 **/
static void
bto_update_bests(const bt_orconn_t *bto)
{
  tor_assert(bto->is_orig);

  if (bto_update_best(bto, &best_any, "ANY"))
    bto_cevent_anyconn(bto);
  if (!bto->is_onehop && bto_update_best(bto, &best_ap, "AP"))
    bto_cevent_apconn(bto);
}

/** Reset cached "best" values */
static void
bto_reset_bests(void)
{
  best_any.gid = best_ap.gid = 0;
  best_any.state = best_ap.state = -1;
}

/**
 * Update cached states of ORCONNs from the incoming message.  This
 * message comes from code in connection_or.c.
 **/
static void
bto_state_rcvr(const orconn_state_msg_t *msg)
{
  bt_orconn_t *bto;

  bto = bto_find_or_new(msg->gid, msg->chan);
  log_debug(LD_BTRACK, "ORCONN gid=%"PRIu64" chan=%"PRIu64
            " proxy_type=%d state=%d",
            msg->gid, msg->chan, msg->proxy_type, msg->state);
  bto->proxy_type = msg->proxy_type;
  bto->state = msg->state;
  if (bto->is_orig)
    bto_update_bests(bto);
}

/**
 * Delete a cached ORCONN state if we get an incoming message saying
 * the ORCONN is failed or closed.  This message comes from code in
 * control.c.
 **/
static void
bto_status_rcvr(const orconn_status_msg_t *msg)
{
  switch (msg->status) {
  case OR_CONN_EVENT_FAILED:
  case OR_CONN_EVENT_CLOSED:
    log_info(LD_BTRACK, "ORCONN DELETE gid=%"PRIu64" status=%d reason=%d",
             msg->gid, msg->status, msg->reason);
    return bto_delete(msg->gid);
  default:
    break;
  }
}

/** Dispatch to individual ORCONN message handlers */
static void
bto_event_rcvr(const orconn_event_msg_t *msg)
{
  switch (msg->type) {
  case ORCONN_MSGTYPE_STATE:
    return bto_state_rcvr(&msg->u.state);
  case ORCONN_MSGTYPE_STATUS:
    return bto_status_rcvr(&msg->u.status);
  default:
    tor_assert(false);
  }
}

/**
 * Create or update a cached ORCONN state for a newly launched
 * connection, including whether it's launched by an origin circuit
 * and whether it's a one-hop circuit.
 **/
static void
bto_chan_rcvr(const ocirc_event_msg_t *msg)
{
  bt_orconn_t *bto;

  /* Ignore other kinds of origin circuit events; we don't need them */
  if (msg->type != OCIRC_MSGTYPE_CHAN)
    return;

  bto = bto_find_or_new(0, msg->u.chan.chan);
  if (!bto->is_orig || (bto->is_onehop && !msg->u.chan.onehop)) {
    log_debug(LD_BTRACK, "ORCONN LAUNCH chan=%"PRIu64" onehop=%d",
              msg->u.chan.chan, msg->u.chan.onehop);
  }
  bto->is_orig = true;
  if (!msg->u.chan.onehop)
    bto->is_onehop = false;
  bto_update_bests(bto);
}

/**
 * Initialize the hash maps and subscribe to ORCONN and origin
 * circuit events.
 **/
int
btrack_orconn_init(void)
{
  bto_init_maps();
  orconn_event_subscribe(bto_event_rcvr);
  ocirc_event_subscribe(bto_chan_rcvr);

  return 0;
}

/** Clear the hash maps and reset the "best" states */
void
btrack_orconn_fini(void)
{
  bto_clear_maps();
  bto_reset_bests();
  bto_cevent_reset();
}
