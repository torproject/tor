/* Copyright (c) 2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file sendme.c
 * \brief Code that is related to SENDME cells both in terms of
 *        creating/parsing cells and handling the content.
 */

#include "core/or/or.h"

#include "core/mainloop/connection.h"
#include "core/or/circuitlist.h"
#include "core/or/relay.h"
#include "core/or/sendme.h"

/** Called when we've just received a relay data cell, when
 * we've just finished flushing all bytes to stream <b>conn</b>,
 * or when we've flushed *some* bytes to the stream <b>conn</b>.
 *
 * If conn->outbuf is not too full, and our deliver window is
 * low, send back a suitable number of stream-level sendme cells.
 */
void
sendme_connection_edge_consider_sending(edge_connection_t *conn)
{
  circuit_t *circ;

  if (connection_outbuf_too_full(TO_CONN(conn)))
    return;

  circ = circuit_get_by_edge_conn(conn);
  if (!circ) {
    /* this can legitimately happen if the destroy has already
     * arrived and torn down the circuit */
    log_info(LD_APP,"No circuit associated with conn. Skipping.");
    return;
  }

  while (conn->deliver_window <= STREAMWINDOW_START - STREAMWINDOW_INCREMENT) {
    log_debug(conn->base_.type == CONN_TYPE_AP ?LD_APP:LD_EXIT,
              "Outbuf %d, Queuing stream sendme.",
              (int)conn->base_.outbuf_flushlen);
    conn->deliver_window += STREAMWINDOW_INCREMENT;
    if (connection_edge_send_command(conn, RELAY_COMMAND_SENDME,
                                     NULL, 0) < 0) {
      log_warn(LD_APP,"connection_edge_send_command failed. Skipping.");
      return; /* the circuit's closed, don't continue */
    }
  }
}

/** Check if the deliver_window for circuit <b>circ</b> (at hop
 * <b>layer_hint</b> if it's defined) is low enough that we should
 * send a circuit-level sendme back down the circuit. If so, send
 * enough sendmes that the window would be overfull if we sent any
 * more.
 */
void
sendme_circuit_consider_sending(circuit_t *circ, crypt_path_t *layer_hint)
{
  while ((layer_hint ? layer_hint->deliver_window : circ->deliver_window) <=
          CIRCWINDOW_START - CIRCWINDOW_INCREMENT) {
    log_debug(LD_CIRC,"Queuing circuit sendme.");
    if (layer_hint)
      layer_hint->deliver_window += CIRCWINDOW_INCREMENT;
    else
      circ->deliver_window += CIRCWINDOW_INCREMENT;
    if (relay_send_command_from_edge(0, circ, RELAY_COMMAND_SENDME,
                                     NULL, 0, layer_hint) < 0) {
      log_warn(LD_CIRC,
               "relay_send_command_from_edge failed. Circuit's closed.");
      return; /* the circuit's closed, don't continue */
    }
  }
}
