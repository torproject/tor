/* Copyright (c) 2016-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_service.c
 * \brief Implement next generation hidden service client functionality
 **/

#include "or.h"
#include "hs_circuit.h"
#include "connection_edge.h"
#include "rendclient.h"

#include "hs_client.h"

/** A prop224 v3 HS circuit successfully connected to the hidden
 *  service. Update the stream state at <b>hs_conn_ident</b> appropriately. */
static void
hs_client_attempt_succeeded(const hs_ident_edge_conn_t *hs_conn_ident)
{
  (void) hs_conn_ident;

  /* TODO: When implementing client side */
  return;
}

/** A circuit just finished connecting to a hidden service that the stream
 *  <b>conn</b> has been waiting for. Let the HS subsystem know about this. */
void
hs_client_note_connection_attempt_succeeded(const edge_connection_t *conn)
{
  tor_assert(connection_edge_is_rendezvous_stream(conn));

  if (BUG(conn->rend_data && conn->hs_ident)) {
    log_warn(LD_BUG, "Stream had both rend_data and hs_ident..."
             "Prioritizing hs_ident");
  }

  if (conn->hs_ident) { /* It's v3: pass it to the prop224 handler */
    hs_client_attempt_succeeded(conn->hs_ident);
    return;
  } else if (conn->rend_data) { /* It's v2: pass it to the legacy handler */
    rend_client_note_connection_attempt_ended(conn->rend_data);
    return;
  }
}

