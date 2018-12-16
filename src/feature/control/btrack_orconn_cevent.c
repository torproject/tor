/* Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file btrack_orconn_cevent.c
 * \brief Emit bootstrap status events for OR connections
 **/

#include <stdbool.h>

#include "core/or/or.h"

#define BTRACK_ORCONN_PRIVATE

#include "core/or/orconn_event.h"
#include "feature/control/btrack_orconn.h"
#include "feature/control/btrack_orconn_cevent.h"
#include "feature/control/control.h"

/**
 * Have we completed our first OR connection?
 *
 * Block display of application circuit progress until we do, to avoid
 * some misleading behavior of jumping to high progress.
 **/
static bool bto_first_orconn = false;

/**
 * Emit control events when we have updated our idea of the best state
 * that any OR connection has reached.
 **/
void
bto_cevent_anyconn(const bt_orconn_t *bto)
{
  switch (bto->state) {
  case OR_CONN_STATE_CONNECTING:
  case OR_CONN_STATE_PROXY_HANDSHAKING:
    /* XXX This isn't quite right, because this isn't necessarily a
       directory server we're talking to, but we'll improve the
       bootstrap tags and messages later */
    control_event_bootstrap(BOOTSTRAP_STATUS_CONN_DIR, 0);
    break;
  case OR_CONN_STATE_TLS_HANDSHAKING:
    /* Here we should report a connection completed (TCP or proxied),
       if we had the states */
    break;
  case OR_CONN_STATE_TLS_CLIENT_RENEGOTIATING:
  case OR_CONN_STATE_OR_HANDSHAKING_V2:
  case OR_CONN_STATE_OR_HANDSHAKING_V3:
    /* XXX Again, this isn't quite right, because it's not necessarily
       a directory server we're talking to. */
    control_event_bootstrap(BOOTSTRAP_STATUS_HANDSHAKE_DIR, 0);
    break;
  case OR_CONN_STATE_OPEN:
    /* Unblock directory progress display */
    control_event_boot_first_orconn();
    /* Unblock apconn progress display */
    bto_first_orconn = true;
    break;
  default:
    break;
  }
}

/**
 * Emit control events when we have updated our idea of the best state
 * that any application circuit OR connection has reached.
 **/
void
bto_cevent_apconn(const bt_orconn_t *bto)
{
  if (!bto_first_orconn)
    return;

  switch (bto->state) {
  case OR_CONN_STATE_CONNECTING:
  case OR_CONN_STATE_PROXY_HANDSHAKING:
    control_event_bootstrap(BOOTSTRAP_STATUS_CONN_OR, 0);
    break;
  case OR_CONN_STATE_TLS_HANDSHAKING:
    /* Here we should report a connection completed (TCP or proxied) */
    break;
  case OR_CONN_STATE_TLS_CLIENT_RENEGOTIATING:
  case OR_CONN_STATE_OR_HANDSHAKING_V2:
  case OR_CONN_STATE_OR_HANDSHAKING_V3:
    control_event_bootstrap(BOOTSTRAP_STATUS_HANDSHAKE_OR, 0);
    break;
  case OR_CONN_STATE_OPEN:
    /* XXX Not quite right, because it implictly reports the next
       state, but we'll improve it later. */
    control_event_bootstrap(BOOTSTRAP_STATUS_CIRCUIT_CREATE, 0);
  default:
    break;
  }
}

/** Forget that we completed our first OR connection */
void
bto_cevent_reset(void)
{
  bto_first_orconn = false;
}
