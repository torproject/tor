/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relay.c
 * \brief Handle relay cell encryption/decryption, plus packaging and
 *    receiving from circuits, plus queuing on circuits.
 **/

#include <math.h>
#define RELAY_PRIVATE
#include "or.h"
#include "buffers.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "config.h"
#include "connection.h"
#include "connection_edge.h"
#include "connection_or.h"
#include "control.h"
#include "geoip.h"
#include "main.h"
#include "mempool.h"
#include "networkstatus.h"
#include "nodelist.h"
#include "policies.h"
#include "reasons.h"
#include "relay.h"
#include "rendcommon.h"
#include "router.h"
#include "routerlist.h"
#include "routerparse.h"

static edge_connection_t *relay_lookup_conn(circuit_t *circ, cell_t *cell,
                                            cell_direction_t cell_direction,
                                            crypt_path_t *layer_hint);

static int connection_edge_process_relay_cell(cell_t *cell, circuit_t *circ,
                                              edge_connection_t *conn,
                                              crypt_path_t *layer_hint);
static void circuit_consider_sending_sendme(circuit_t *circ,
                                            crypt_path_t *layer_hint);
static void circuit_resume_edge_reading(circuit_t *circ,
                                        crypt_path_t *layer_hint);
static int circuit_resume_edge_reading_helper(edge_connection_t *conn,
                                              circuit_t *circ,
                                              crypt_path_t *layer_hint);
static int circuit_consider_stop_edge_reading(circuit_t *circ,
                                              crypt_path_t *layer_hint);
static int circuit_queue_streams_are_blocked(circuit_t *circ);

/** Stop reading on edge connections when we have this many cells
 * waiting on the appropriate queue. */
#define CELL_QUEUE_HIGHWATER_SIZE 256
/** Start reading from edge connections again when we get down to this many
 * cells. */
#define CELL_QUEUE_LOWWATER_SIZE 64

/** Stats: how many relay cells have originated at this hop, or have
 * been relayed onward (not recognized at this hop)?
 */
uint64_t stats_n_relay_cells_relayed = 0;
/** Stats: how many relay cells have been delivered to streams at this
 * hop?
 */
uint64_t stats_n_relay_cells_delivered = 0;

/** Update digest from the payload of cell. Assign integrity part to
 * cell.
 */
static void
relay_set_digest(crypto_digest_t *digest, cell_t *cell)
{
  char integrity[4];
  relay_header_t rh;

  crypto_digest_add_bytes(digest, (char*)cell->payload, CELL_PAYLOAD_SIZE);
  crypto_digest_get_digest(digest, integrity, 4);
//  log_fn(LOG_DEBUG,"Putting digest of %u %u %u %u into relay cell.",
//    integrity[0], integrity[1], integrity[2], integrity[3]);
  relay_header_unpack(&rh, cell->payload);
  memcpy(rh.integrity, integrity, 4);
  relay_header_pack(cell->payload, &rh);
}

/** Does the digest for this circuit indicate that this cell is for us?
 *
 * Update digest from the payload of cell (with the integrity part set
 * to 0). If the integrity part is valid, return 1, else restore digest
 * and cell to their original state and return 0.
 */
static int
relay_digest_matches(crypto_digest_t *digest, cell_t *cell)
{
  char received_integrity[4], calculated_integrity[4];
  relay_header_t rh;
  crypto_digest_t *backup_digest=NULL;

  backup_digest = crypto_digest_dup(digest);

  relay_header_unpack(&rh, cell->payload);
  memcpy(received_integrity, rh.integrity, 4);
  memset(rh.integrity, 0, 4);
  relay_header_pack(cell->payload, &rh);

//  log_fn(LOG_DEBUG,"Reading digest of %u %u %u %u from relay cell.",
//    received_integrity[0], received_integrity[1],
//    received_integrity[2], received_integrity[3]);

  crypto_digest_add_bytes(digest, (char*) cell->payload, CELL_PAYLOAD_SIZE);
  crypto_digest_get_digest(digest, calculated_integrity, 4);

  if (tor_memneq(received_integrity, calculated_integrity, 4)) {
//    log_fn(LOG_INFO,"Recognized=0 but bad digest. Not recognizing.");
// (%d vs %d).", received_integrity, calculated_integrity);
    /* restore digest to its old form */
    crypto_digest_assign(digest, backup_digest);
    /* restore the relay header */
    memcpy(rh.integrity, received_integrity, 4);
    relay_header_pack(cell->payload, &rh);
    crypto_digest_free(backup_digest);
    return 0;
  }
  crypto_digest_free(backup_digest);
  return 1;
}

/** Apply <b>cipher</b> to CELL_PAYLOAD_SIZE bytes of <b>in</b>
 * (in place).
 *
 * If <b>encrypt_mode</b> is 1 then encrypt, else decrypt.
 *
 * Return -1 if the crypto fails, else return 0.
 */
static int
relay_crypt_one_payload(crypto_cipher_t *cipher, uint8_t *in,
                        int encrypt_mode)
{
  int r;
  (void)encrypt_mode;
  r = crypto_cipher_crypt_inplace(cipher, (char*) in, CELL_PAYLOAD_SIZE);

  if (r) {
    log_warn(LD_BUG,"Error during relay encryption");
    return -1;
  }
  return 0;
}

/** Receive a relay cell:
 *  - Crypt it (encrypt if headed toward the origin or if we <b>are</b> the
 *    origin; decrypt if we're headed toward the exit).
 *  - Check if recognized (if exitward).
 *  - If recognized and the digest checks out, then find if there's a stream
 *    that the cell is intended for, and deliver it to the right
 *    connection_edge.
 *  - If not recognized, then we need to relay it: append it to the appropriate
 *    cell_queue on <b>circ</b>.
 *
 * Return -<b>reason</b> on failure.
 */
int
circuit_receive_relay_cell(cell_t *cell, circuit_t *circ,
                           cell_direction_t cell_direction)
{
  or_connection_t *or_conn=NULL;
  crypt_path_t *layer_hint=NULL;
  char recognized=0;
  int reason;

  tor_assert(cell);
  tor_assert(circ);
  tor_assert(cell_direction == CELL_DIRECTION_OUT ||
             cell_direction == CELL_DIRECTION_IN);
  if (circ->marked_for_close)
    return 0;

  if (relay_crypt(circ, cell, cell_direction, &layer_hint, &recognized) < 0) {
    log_warn(LD_BUG,"relay crypt failed. Dropping connection.");
    return -END_CIRC_REASON_INTERNAL;
  }

  if (recognized) {
    edge_connection_t *conn = relay_lookup_conn(circ, cell, cell_direction,
                                                layer_hint);
    if (cell_direction == CELL_DIRECTION_OUT) {
      ++stats_n_relay_cells_delivered;
      log_debug(LD_OR,"Sending away from origin.");
      if ((reason=connection_edge_process_relay_cell(cell, circ, conn, NULL))
          < 0) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "connection_edge_process_relay_cell (away from origin) "
               "failed.");
        return reason;
      }
    }
    if (cell_direction == CELL_DIRECTION_IN) {
      ++stats_n_relay_cells_delivered;
      log_debug(LD_OR,"Sending to origin.");
      if ((reason = connection_edge_process_relay_cell(cell, circ, conn,
                                                       layer_hint)) < 0) {
        log_warn(LD_OR,
                 "connection_edge_process_relay_cell (at origin) failed.");
        return reason;
      }
    }
    return 0;
  }

  /* not recognized. pass it on. */
  if (cell_direction == CELL_DIRECTION_OUT) {
    cell->circ_id = circ->n_circ_id; /* switch it */
    or_conn = circ->n_conn;
  } else if (! CIRCUIT_IS_ORIGIN(circ)) {
    cell->circ_id = TO_OR_CIRCUIT(circ)->p_circ_id; /* switch it */
    or_conn = TO_OR_CIRCUIT(circ)->p_conn;
  } else {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Dropping unrecognized inbound cell on origin circuit.");
    return 0;
  }

  if (!or_conn) {
    // XXXX Can this splice stuff be done more cleanly?
    if (! CIRCUIT_IS_ORIGIN(circ) &&
        TO_OR_CIRCUIT(circ)->rend_splice &&
        cell_direction == CELL_DIRECTION_OUT) {
      or_circuit_t *splice = TO_OR_CIRCUIT(circ)->rend_splice;
      tor_assert(circ->purpose == CIRCUIT_PURPOSE_REND_ESTABLISHED);
      tor_assert(splice->_base.purpose == CIRCUIT_PURPOSE_REND_ESTABLISHED);
      cell->circ_id = splice->p_circ_id;
      cell->command = CELL_RELAY; /* can't be relay_early anyway */
      if ((reason = circuit_receive_relay_cell(cell, TO_CIRCUIT(splice),
                                               CELL_DIRECTION_IN)) < 0) {
        log_warn(LD_REND, "Error relaying cell across rendezvous; closing "
                 "circuits");
        /* XXXX Do this here, or just return -1? */
        circuit_mark_for_close(circ, -reason);
        return reason;
      }
      return 0;
    }
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Didn't recognize cell, but circ stops here! Closing circ.");
    return -END_CIRC_REASON_TORPROTOCOL;
  }

  log_debug(LD_OR,"Passing on unrecognized cell.");

  ++stats_n_relay_cells_relayed; /* XXXX no longer quite accurate {cells}
                                  * we might kill the circ before we relay
                                  * the cells. */

  append_cell_to_circuit_queue(circ, or_conn, cell, cell_direction, 0);
  return 0;
}

/** Do the appropriate en/decryptions for <b>cell</b> arriving on
 * <b>circ</b> in direction <b>cell_direction</b>.
 *
 * If cell_direction == CELL_DIRECTION_IN:
 *   - If we're at the origin (we're the OP), for hops 1..N,
 *     decrypt cell. If recognized, stop.
 *   - Else (we're not the OP), encrypt one hop. Cell is not recognized.
 *
 * If cell_direction == CELL_DIRECTION_OUT:
 *   - decrypt one hop. Check if recognized.
 *
 * If cell is recognized, set *recognized to 1, and set
 * *layer_hint to the hop that recognized it.
 *
 * Return -1 to indicate that we should mark the circuit for close,
 * else return 0.
 */
int
relay_crypt(circuit_t *circ, cell_t *cell, cell_direction_t cell_direction,
            crypt_path_t **layer_hint, char *recognized)
{
  relay_header_t rh;

  tor_assert(circ);
  tor_assert(cell);
  tor_assert(recognized);
  tor_assert(cell_direction == CELL_DIRECTION_IN ||
             cell_direction == CELL_DIRECTION_OUT);

  if (cell_direction == CELL_DIRECTION_IN) {
    if (CIRCUIT_IS_ORIGIN(circ)) { /* We're at the beginning of the circuit.
                                    * We'll want to do layered decrypts. */
      crypt_path_t *thishop, *cpath = TO_ORIGIN_CIRCUIT(circ)->cpath;
      thishop = cpath;
      if (thishop->state != CPATH_STATE_OPEN) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "Relay cell before first created cell? Closing.");
        return -1;
      }
      do { /* Remember: cpath is in forward order, that is, first hop first. */
        tor_assert(thishop);

        if (relay_crypt_one_payload(thishop->b_crypto, cell->payload, 0) < 0)
          return -1;

        relay_header_unpack(&rh, cell->payload);
        if (rh.recognized == 0) {
          /* it's possibly recognized. have to check digest to be sure. */
          if (relay_digest_matches(thishop->b_digest, cell)) {
            *recognized = 1;
            *layer_hint = thishop;
            return 0;
          }
        }

        thishop = thishop->next;
      } while (thishop != cpath && thishop->state == CPATH_STATE_OPEN);
      log_fn(LOG_PROTOCOL_WARN, LD_OR,
             "Incoming cell at client not recognized. Closing.");
      return -1;
    } else { /* we're in the middle. Just one crypt. */
      if (relay_crypt_one_payload(TO_OR_CIRCUIT(circ)->p_crypto,
                                  cell->payload, 1) < 0)
        return -1;
//      log_fn(LOG_DEBUG,"Skipping recognized check, because we're not "
//             "the client.");
    }
  } else /* cell_direction == CELL_DIRECTION_OUT */ {
    /* we're in the middle. Just one crypt. */

    if (relay_crypt_one_payload(TO_OR_CIRCUIT(circ)->n_crypto,
                                cell->payload, 0) < 0)
      return -1;

    relay_header_unpack(&rh, cell->payload);
    if (rh.recognized == 0) {
      /* it's possibly recognized. have to check digest to be sure. */
      if (relay_digest_matches(TO_OR_CIRCUIT(circ)->n_digest, cell)) {
        *recognized = 1;
        return 0;
      }
    }
  }
  return 0;
}

/** Package a relay cell from an edge:
 *  - Encrypt it to the right layer
 *  - Append it to the appropriate cell_queue on <b>circ</b>.
 */
static int
circuit_package_relay_cell(cell_t *cell, circuit_t *circ,
                           cell_direction_t cell_direction,
                           crypt_path_t *layer_hint, streamid_t on_stream)
{
  or_connection_t *conn; /* where to send the cell */

  if (cell_direction == CELL_DIRECTION_OUT) {
    crypt_path_t *thishop; /* counter for repeated crypts */
    conn = circ->n_conn;
    if (!CIRCUIT_IS_ORIGIN(circ) || !conn) {
      log_warn(LD_BUG,"outgoing relay cell has n_conn==NULL. Dropping.");
      return 0; /* just drop it */
    }

    relay_set_digest(layer_hint->f_digest, cell);

    thishop = layer_hint;
    /* moving from farthest to nearest hop */
    do {
      tor_assert(thishop);
      /* XXXX RD This is a bug, right? */
      log_debug(LD_OR,"crypting a layer of the relay cell.");
      if (relay_crypt_one_payload(thishop->f_crypto, cell->payload, 1) < 0) {
        return -1;
      }

      thishop = thishop->prev;
    } while (thishop != TO_ORIGIN_CIRCUIT(circ)->cpath->prev);

  } else { /* incoming cell */
    or_circuit_t *or_circ;
    if (CIRCUIT_IS_ORIGIN(circ)) {
      /* We should never package an _incoming_ cell from the circuit
       * origin; that means we messed up somewhere. */
      log_warn(LD_BUG,"incoming relay cell at origin circuit. Dropping.");
      assert_circuit_ok(circ);
      return 0; /* just drop it */
    }
    or_circ = TO_OR_CIRCUIT(circ);
    conn = or_circ->p_conn;
    relay_set_digest(or_circ->p_digest, cell);
    if (relay_crypt_one_payload(or_circ->p_crypto, cell->payload, 1) < 0)
      return -1;
  }
  ++stats_n_relay_cells_relayed;

  append_cell_to_circuit_queue(circ, conn, cell, cell_direction, on_stream);
  return 0;
}

/** If cell's stream_id matches the stream_id of any conn that's
 * attached to circ, return that conn, else return NULL.
 */
static edge_connection_t *
relay_lookup_conn(circuit_t *circ, cell_t *cell,
                  cell_direction_t cell_direction, crypt_path_t *layer_hint)
{
  edge_connection_t *tmpconn;
  relay_header_t rh;

  relay_header_unpack(&rh, cell->payload);

  if (!rh.stream_id)
    return NULL;

  /* IN or OUT cells could have come from either direction, now
   * that we allow rendezvous *to* an OP.
   */

  if (CIRCUIT_IS_ORIGIN(circ)) {
    for (tmpconn = TO_ORIGIN_CIRCUIT(circ)->p_streams; tmpconn;
         tmpconn=tmpconn->next_stream) {
      if (rh.stream_id == tmpconn->stream_id &&
          !tmpconn->_base.marked_for_close &&
          tmpconn->cpath_layer == layer_hint) {
        log_debug(LD_APP,"found conn for stream %d.", rh.stream_id);
        return tmpconn;
      }
    }
  } else {
    for (tmpconn = TO_OR_CIRCUIT(circ)->n_streams; tmpconn;
         tmpconn=tmpconn->next_stream) {
      if (rh.stream_id == tmpconn->stream_id &&
          !tmpconn->_base.marked_for_close) {
        log_debug(LD_EXIT,"found conn for stream %d.", rh.stream_id);
        if (cell_direction == CELL_DIRECTION_OUT ||
            connection_edge_is_rendezvous_stream(tmpconn))
          return tmpconn;
      }
    }
    for (tmpconn = TO_OR_CIRCUIT(circ)->resolving_streams; tmpconn;
         tmpconn=tmpconn->next_stream) {
      if (rh.stream_id == tmpconn->stream_id &&
          !tmpconn->_base.marked_for_close) {
        log_debug(LD_EXIT,"found conn for stream %d.", rh.stream_id);
        return tmpconn;
      }
    }
  }
  return NULL; /* probably a begin relay cell */
}

/** Pack the relay_header_t host-order structure <b>src</b> into
 * network-order in the buffer <b>dest</b>. See tor-spec.txt for details
 * about the wire format.
 */
void
relay_header_pack(uint8_t *dest, const relay_header_t *src)
{
  set_uint8(dest, src->command);
  set_uint16(dest+1, htons(src->recognized));
  set_uint16(dest+3, htons(src->stream_id));
  memcpy(dest+5, src->integrity, 4);
  set_uint16(dest+9, htons(src->length));
}

/** Unpack the network-order buffer <b>src</b> into a host-order
 * relay_header_t structure <b>dest</b>.
 */
void
relay_header_unpack(relay_header_t *dest, const uint8_t *src)
{
  dest->command = get_uint8(src);
  dest->recognized = ntohs(get_uint16(src+1));
  dest->stream_id = ntohs(get_uint16(src+3));
  memcpy(dest->integrity, src+5, 4);
  dest->length = ntohs(get_uint16(src+9));
}

/** Convert the relay <b>command</b> into a human-readable string. */
static const char *
relay_command_to_string(uint8_t command)
{
  switch (command) {
    case RELAY_COMMAND_BEGIN: return "BEGIN";
    case RELAY_COMMAND_DATA: return "DATA";
    case RELAY_COMMAND_END: return "END";
    case RELAY_COMMAND_CONNECTED: return "CONNECTED";
    case RELAY_COMMAND_SENDME: return "SENDME";
    case RELAY_COMMAND_EXTEND: return "EXTEND";
    case RELAY_COMMAND_EXTENDED: return "EXTENDED";
    case RELAY_COMMAND_TRUNCATE: return "TRUNCATE";
    case RELAY_COMMAND_TRUNCATED: return "TRUNCATED";
    case RELAY_COMMAND_DROP: return "DROP";
    case RELAY_COMMAND_RESOLVE: return "RESOLVE";
    case RELAY_COMMAND_RESOLVED: return "RESOLVED";
    case RELAY_COMMAND_BEGIN_DIR: return "BEGIN_DIR";
    case RELAY_COMMAND_ESTABLISH_INTRO: return "ESTABLISH_INTRO";
    case RELAY_COMMAND_ESTABLISH_RENDEZVOUS: return "ESTABLISH_RENDEZVOUS";
    case RELAY_COMMAND_INTRODUCE1: return "INTRODUCE1";
    case RELAY_COMMAND_INTRODUCE2: return "INTRODUCE2";
    case RELAY_COMMAND_RENDEZVOUS1: return "RENDEZVOUS1";
    case RELAY_COMMAND_RENDEZVOUS2: return "RENDEZVOUS2";
    case RELAY_COMMAND_INTRO_ESTABLISHED: return "INTRO_ESTABLISHED";
    case RELAY_COMMAND_RENDEZVOUS_ESTABLISHED:
      return "RENDEZVOUS_ESTABLISHED";
    case RELAY_COMMAND_INTRODUCE_ACK: return "INTRODUCE_ACK";
    default: return "(unrecognized)";
  }
}

/** Make a relay cell out of <b>relay_command</b> and <b>payload</b>, and send
 * it onto the open circuit <b>circ</b>. <b>stream_id</b> is the ID on
 * <b>circ</b> for the stream that's sending the relay cell, or 0 if it's a
 * control cell.  <b>cpath_layer</b> is NULL for OR->OP cells, or the
 * destination hop for OP->OR cells.
 *
 * If you can't send the cell, mark the circuit for close and return -1. Else
 * return 0.
 */
int
relay_send_command_from_edge(streamid_t stream_id, circuit_t *circ,
                             uint8_t relay_command, const char *payload,
                             size_t payload_len, crypt_path_t *cpath_layer)
{
  cell_t cell;
  relay_header_t rh;
  cell_direction_t cell_direction;
  /* XXXX NM Split this function into a separate versions per circuit type? */

  tor_assert(circ);
  tor_assert(payload_len <= RELAY_PAYLOAD_SIZE);

  memset(&cell, 0, sizeof(cell_t));
  cell.command = CELL_RELAY;
  if (cpath_layer) {
    cell.circ_id = circ->n_circ_id;
    cell_direction = CELL_DIRECTION_OUT;
  } else if (! CIRCUIT_IS_ORIGIN(circ)) {
    cell.circ_id = TO_OR_CIRCUIT(circ)->p_circ_id;
    cell_direction = CELL_DIRECTION_IN;
  } else {
    return -1;
  }

  memset(&rh, 0, sizeof(rh));
  rh.command = relay_command;
  rh.stream_id = stream_id;
  rh.length = payload_len;
  relay_header_pack(cell.payload, &rh);
  if (payload_len)
    memcpy(cell.payload+RELAY_HEADER_SIZE, payload, payload_len);

  log_debug(LD_OR,"delivering %d cell %s.", relay_command,
            cell_direction == CELL_DIRECTION_OUT ? "forward" : "backward");

  /* If we are sending an END cell and this circuit is used for a tunneled
   * directory request, advance its state. */
  if (relay_command == RELAY_COMMAND_END && circ->dirreq_id)
    geoip_change_dirreq_state(circ->dirreq_id, DIRREQ_TUNNELED,
                              DIRREQ_END_CELL_SENT);

  if (cell_direction == CELL_DIRECTION_OUT && circ->n_conn) {
    /* if we're using relaybandwidthrate, this conn wants priority */
    circ->n_conn->client_used = approx_time();
  }

  if (cell_direction == CELL_DIRECTION_OUT) {
    origin_circuit_t *origin_circ = TO_ORIGIN_CIRCUIT(circ);
    if (origin_circ->remaining_relay_early_cells > 0 &&
        (relay_command == RELAY_COMMAND_EXTEND ||
         cpath_layer != origin_circ->cpath)) {
      /* If we've got any relay_early cells left and (we're sending
       * an extend cell or we're not talking to the first hop), use
       * one of them.  Don't worry about the conn protocol version:
       * append_cell_to_circuit_queue will fix it up. */
      cell.command = CELL_RELAY_EARLY;
      --origin_circ->remaining_relay_early_cells;
      log_debug(LD_OR, "Sending a RELAY_EARLY cell; %d remaining.",
                (int)origin_circ->remaining_relay_early_cells);
      /* Memorize the command that is sent as RELAY_EARLY cell; helps debug
       * task 878. */
      origin_circ->relay_early_commands[
          origin_circ->relay_early_cells_sent++] = relay_command;
    } else if (relay_command == RELAY_COMMAND_EXTEND) {
      /* If no RELAY_EARLY cells can be sent over this circuit, log which
       * commands have been sent as RELAY_EARLY cells before; helps debug
       * task 878. */
      smartlist_t *commands_list = smartlist_new();
      int i = 0;
      char *commands = NULL;
      for (; i < origin_circ->relay_early_cells_sent; i++)
        smartlist_add(commands_list, (char *)
            relay_command_to_string(origin_circ->relay_early_commands[i]));
      commands = smartlist_join_strings(commands_list, ",", 0, NULL);
      log_warn(LD_BUG, "Uh-oh.  We're sending a RELAY_COMMAND_EXTEND cell, "
               "but we have run out of RELAY_EARLY cells on that circuit. "
               "Commands sent before: %s", commands);
      tor_free(commands);
      smartlist_free(commands_list);
    }
  }

  if (circuit_package_relay_cell(&cell, circ, cell_direction, cpath_layer,
                                 stream_id) < 0) {
    log_warn(LD_BUG,"circuit_package_relay_cell failed. Closing.");
    circuit_mark_for_close(circ, END_CIRC_REASON_INTERNAL);
    return -1;
  }
  return 0;
}

/** Make a relay cell out of <b>relay_command</b> and <b>payload</b>, and
 * send it onto the open circuit <b>circ</b>. <b>fromconn</b> is the stream
 * that's sending the relay cell, or NULL if it's a control cell.
 * <b>cpath_layer</b> is NULL for OR->OP cells, or the destination hop
 * for OP->OR cells.
 *
 * If you can't send the cell, mark the circuit for close and
 * return -1. Else return 0.
 */
int
connection_edge_send_command(edge_connection_t *fromconn,
                             uint8_t relay_command, const char *payload,
                             size_t payload_len)
{
  /* XXXX NM Split this function into a separate versions per circuit type? */
  circuit_t *circ;
  crypt_path_t *cpath_layer = fromconn->cpath_layer;
  tor_assert(fromconn);
  circ = fromconn->on_circuit;

  if (fromconn->_base.marked_for_close) {
    log_warn(LD_BUG,
             "called on conn that's already marked for close at %s:%d.",
             fromconn->_base.marked_for_close_file,
             fromconn->_base.marked_for_close);
    return 0;
  }

  if (!circ) {
    if (fromconn->_base.type == CONN_TYPE_AP) {
      log_info(LD_APP,"no circ. Closing conn.");
      connection_mark_unattached_ap(EDGE_TO_ENTRY_CONN(fromconn),
                                    END_STREAM_REASON_INTERNAL);
    } else {
      log_info(LD_EXIT,"no circ. Closing conn.");
      fromconn->edge_has_sent_end = 1; /* no circ to send to */
      fromconn->end_reason = END_STREAM_REASON_INTERNAL;
      connection_mark_for_close(TO_CONN(fromconn));
    }
    return -1;
  }

  return relay_send_command_from_edge(fromconn->stream_id, circ,
                                      relay_command, payload,
                                      payload_len, cpath_layer);
}

/** How many times will I retry a stream that fails due to DNS
 * resolve failure or misc error?
 */
#define MAX_RESOLVE_FAILURES 3

/** Return 1 if reason is something that you should retry if you
 * get the end cell before you've connected; else return 0. */
static int
edge_reason_is_retriable(int reason)
{
  return reason == END_STREAM_REASON_HIBERNATING ||
         reason == END_STREAM_REASON_RESOURCELIMIT ||
         reason == END_STREAM_REASON_EXITPOLICY ||
         reason == END_STREAM_REASON_RESOLVEFAILED ||
         reason == END_STREAM_REASON_MISC ||
         reason == END_STREAM_REASON_NOROUTE;
}

/** Called when we receive an END cell on a stream that isn't open yet,
 * from the client side.
 * Arguments are as for connection_edge_process_relay_cell().
 */
static int
connection_ap_process_end_not_open(
    relay_header_t *rh, cell_t *cell, origin_circuit_t *circ,
    entry_connection_t *conn, crypt_path_t *layer_hint)
{
  struct in_addr in;
  node_t *exitrouter;
  int reason = *(cell->payload+RELAY_HEADER_SIZE);
  int control_reason = reason | END_STREAM_REASON_FLAG_REMOTE;
  edge_connection_t *edge_conn = ENTRY_TO_EDGE_CONN(conn);
  (void) layer_hint; /* unused */

  if (rh->length > 0 && edge_reason_is_retriable(reason) &&
      /* avoid retry if rend */
      !connection_edge_is_rendezvous_stream(edge_conn)) {
    const char *chosen_exit_digest =
      circ->build_state->chosen_exit->identity_digest;
    log_info(LD_APP,"Address '%s' refused due to '%s'. Considering retrying.",
             safe_str(conn->socks_request->address),
             stream_end_reason_to_string(reason));
    exitrouter = node_get_mutable_by_id(chosen_exit_digest);
    switch (reason) {
      case END_STREAM_REASON_EXITPOLICY:
        if (rh->length >= 5) {
          uint32_t addr = ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE+1));
          int ttl;
          if (!addr) {
            log_info(LD_APP,"Address '%s' resolved to 0.0.0.0. Closing,",
                     safe_str(conn->socks_request->address));
            connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
            return 0;
          }
          if (rh->length >= 9)
            ttl = (int)ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE+5));
          else
            ttl = -1;

          if (get_options()->ClientDNSRejectInternalAddresses &&
              is_internal_IP(addr, 0)) {
            log_info(LD_APP,"Address '%s' resolved to internal. Closing,",
                     safe_str(conn->socks_request->address));
            connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
            return 0;
          }
          client_dns_set_addressmap(conn->socks_request->address, addr,
                                    conn->chosen_exit_name, ttl);
        }
        /* check if he *ought* to have allowed it */
        if (exitrouter &&
            (rh->length < 5 ||
             (tor_inet_aton(conn->socks_request->address, &in) &&
              !conn->chosen_exit_name))) {
          log_info(LD_APP,
                 "Exitrouter %s seems to be more restrictive than its exit "
                 "policy. Not using this router as exit for now.",
                 node_describe(exitrouter));
          policies_set_node_exitpolicy_to_reject_all(exitrouter);
        }
        /* rewrite it to an IP if we learned one. */
        if (addressmap_rewrite(conn->socks_request->address,
                               sizeof(conn->socks_request->address),
                               NULL, NULL)) {
          control_event_stream_status(conn, STREAM_EVENT_REMAP, 0);
        }
        if (conn->chosen_exit_optional ||
            conn->chosen_exit_retries) {
          /* stop wanting a specific exit */
          conn->chosen_exit_optional = 0;
          /* A non-zero chosen_exit_retries can happen if we set a
           * TrackHostExits for this address under a port that the exit
           * relay allows, but then try the same address with a different
           * port that it doesn't allow to exit. We shouldn't unregister
           * the mapping, since it is probably still wanted on the
           * original port. But now we give away to the exit relay that
           * we probably have a TrackHostExits on it. So be it. */
          conn->chosen_exit_retries = 0;
          tor_free(conn->chosen_exit_name); /* clears it */
        }
        if (connection_ap_detach_retriable(conn, circ, control_reason) >= 0)
          return 0;
        /* else, conn will get closed below */
        break;
      case END_STREAM_REASON_CONNECTREFUSED:
        if (!conn->chosen_exit_optional)
          break; /* break means it'll close, below */
        /* Else fall through: expire this circuit, clear the
         * chosen_exit_name field, and try again. */
      case END_STREAM_REASON_RESOLVEFAILED:
      case END_STREAM_REASON_TIMEOUT:
      case END_STREAM_REASON_MISC:
      case END_STREAM_REASON_NOROUTE:
        if (client_dns_incr_failures(conn->socks_request->address)
            < MAX_RESOLVE_FAILURES) {
          /* We haven't retried too many times; reattach the connection. */
          circuit_log_path(LOG_INFO,LD_APP,circ);
          /* Mark this circuit "unusable for new streams". */
          /* XXXX024 this is a kludgy way to do this. */
          tor_assert(circ->_base.timestamp_dirty);
          circ->_base.timestamp_dirty -= get_options()->MaxCircuitDirtiness;

          if (conn->chosen_exit_optional) {
            /* stop wanting a specific exit */
            conn->chosen_exit_optional = 0;
            tor_free(conn->chosen_exit_name); /* clears it */
          }
          if (connection_ap_detach_retriable(conn, circ, control_reason) >= 0)
            return 0;
          /* else, conn will get closed below */
        } else {
          log_notice(LD_APP,
                     "Have tried resolving or connecting to address '%s' "
                     "at %d different places. Giving up.",
                     safe_str(conn->socks_request->address),
                     MAX_RESOLVE_FAILURES);
          /* clear the failures, so it will have a full try next time */
          client_dns_clear_failures(conn->socks_request->address);
        }
        break;
      case END_STREAM_REASON_HIBERNATING:
      case END_STREAM_REASON_RESOURCELIMIT:
        if (exitrouter) {
          policies_set_node_exitpolicy_to_reject_all(exitrouter);
        }
        if (conn->chosen_exit_optional) {
          /* stop wanting a specific exit */
          conn->chosen_exit_optional = 0;
          tor_free(conn->chosen_exit_name); /* clears it */
        }
        if (connection_ap_detach_retriable(conn, circ, control_reason) >= 0)
          return 0;
        /* else, will close below */
        break;
    } /* end switch */
    log_info(LD_APP,"Giving up on retrying; conn can't be handled.");
  }

  log_info(LD_APP,
           "Edge got end (%s) before we're connected. Marking for close.",
       stream_end_reason_to_string(rh->length > 0 ? reason : -1));
  circuit_log_path(LOG_INFO,LD_APP,circ);
  /* need to test because of detach_retriable */
  if (!ENTRY_TO_CONN(conn)->marked_for_close)
    connection_mark_unattached_ap(conn, control_reason);
  return 0;
}

/** Helper: change the socks_request-&gt;address field on conn to the
 * dotted-quad representation of <b>new_addr</b> (given in host order),
 * and send an appropriate REMAP event. */
static void
remap_event_helper(entry_connection_t *conn, uint32_t new_addr)
{
  struct in_addr in;

  in.s_addr = htonl(new_addr);
  tor_inet_ntoa(&in, conn->socks_request->address,
                sizeof(conn->socks_request->address));
  control_event_stream_status(conn, STREAM_EVENT_REMAP,
                              REMAP_STREAM_SOURCE_EXIT);
}

/** An incoming relay cell has arrived from circuit <b>circ</b> to
 * stream <b>conn</b>.
 *
 * The arguments here are the same as in
 * connection_edge_process_relay_cell() below; this function is called
 * from there when <b>conn</b> is defined and not in an open state.
 */
static int
connection_edge_process_relay_cell_not_open(
    relay_header_t *rh, cell_t *cell, circuit_t *circ,
    edge_connection_t *conn, crypt_path_t *layer_hint)
{
  if (rh->command == RELAY_COMMAND_END) {
    if (CIRCUIT_IS_ORIGIN(circ) && conn->_base.type == CONN_TYPE_AP) {
      return connection_ap_process_end_not_open(rh, cell,
                                                TO_ORIGIN_CIRCUIT(circ),
                                                EDGE_TO_ENTRY_CONN(conn),
                                                layer_hint);
    } else {
      /* we just got an 'end', don't need to send one */
      conn->edge_has_sent_end = 1;
      conn->end_reason = *(cell->payload+RELAY_HEADER_SIZE) |
                         END_STREAM_REASON_FLAG_REMOTE;
      connection_mark_for_close(TO_CONN(conn));
      return 0;
    }
  }

  if (conn->_base.type == CONN_TYPE_AP &&
      rh->command == RELAY_COMMAND_CONNECTED) {
    entry_connection_t *entry_conn = EDGE_TO_ENTRY_CONN(conn);
    tor_assert(CIRCUIT_IS_ORIGIN(circ));
    if (conn->_base.state != AP_CONN_STATE_CONNECT_WAIT) {
      log_fn(LOG_PROTOCOL_WARN, LD_APP,
             "Got 'connected' while not in state connect_wait. Dropping.");
      return 0;
    }
    conn->_base.state = AP_CONN_STATE_OPEN;
    log_info(LD_APP,"'connected' received after %d seconds.",
             (int)(time(NULL) - conn->_base.timestamp_lastread));
    if (rh->length >= 4) {
      uint32_t addr = ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE));
      int ttl;
      if (!addr || (get_options()->ClientDNSRejectInternalAddresses &&
                    is_internal_IP(addr, 0))) {
        log_info(LD_APP, "...but it claims the IP address was %s. Closing.",
                 fmt_addr32(addr));
        connection_edge_end(conn, END_STREAM_REASON_TORPROTOCOL);
        connection_mark_unattached_ap(entry_conn,
                                      END_STREAM_REASON_TORPROTOCOL);
        return 0;
      }
      if (rh->length >= 8)
        ttl = (int)ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE+4));
      else
        ttl = -1;
      client_dns_set_addressmap(entry_conn->socks_request->address, addr,
                                entry_conn->chosen_exit_name, ttl);

      remap_event_helper(entry_conn, addr);
    }
    circuit_log_path(LOG_INFO,LD_APP,TO_ORIGIN_CIRCUIT(circ));
    /* don't send a socks reply to transparent conns */
    tor_assert(entry_conn->socks_request != NULL);
    if (!entry_conn->socks_request->has_finished)
      connection_ap_handshake_socks_reply(entry_conn, NULL, 0, 0);

    /* Was it a linked dir conn? If so, a dir request just started to
     * fetch something; this could be a bootstrap status milestone. */
    log_debug(LD_APP, "considering");
    if (TO_CONN(conn)->linked_conn &&
        TO_CONN(conn)->linked_conn->type == CONN_TYPE_DIR) {
      connection_t *dirconn = TO_CONN(conn)->linked_conn;
      log_debug(LD_APP, "it is! %d", dirconn->purpose);
      switch (dirconn->purpose) {
        case DIR_PURPOSE_FETCH_CERTIFICATE:
          if (consensus_is_waiting_for_certs())
            control_event_bootstrap(BOOTSTRAP_STATUS_LOADING_KEYS, 0);
          break;
        case DIR_PURPOSE_FETCH_CONSENSUS:
          control_event_bootstrap(BOOTSTRAP_STATUS_LOADING_STATUS, 0);
          break;
        case DIR_PURPOSE_FETCH_SERVERDESC:
          control_event_bootstrap(BOOTSTRAP_STATUS_LOADING_DESCRIPTORS,
                                  count_loading_descriptors_progress());
          break;
      }
    }
    /* This is definitely a success, so forget about any pending data we
     * had sent. */
    if (entry_conn->pending_optimistic_data) {
      generic_buffer_free(entry_conn->pending_optimistic_data);
      entry_conn->pending_optimistic_data = NULL;
    }

    /* handle anything that might have queued */
    if (connection_edge_package_raw_inbuf(conn, 1, NULL) < 0) {
      /* (We already sent an end cell if possible) */
      connection_mark_for_close(TO_CONN(conn));
      return 0;
    }
    return 0;
  }
  if (conn->_base.type == CONN_TYPE_AP &&
      rh->command == RELAY_COMMAND_RESOLVED) {
    int ttl;
    int answer_len;
    uint8_t answer_type;
    entry_connection_t *entry_conn = EDGE_TO_ENTRY_CONN(conn);
    if (conn->_base.state != AP_CONN_STATE_RESOLVE_WAIT) {
      log_fn(LOG_PROTOCOL_WARN, LD_APP, "Got a 'resolved' cell while "
             "not in state resolve_wait. Dropping.");
      return 0;
    }
    tor_assert(SOCKS_COMMAND_IS_RESOLVE(entry_conn->socks_request->command));
    answer_len = cell->payload[RELAY_HEADER_SIZE+1];
    if (rh->length < 2 || answer_len+2>rh->length) {
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
             "Dropping malformed 'resolved' cell");
      connection_mark_unattached_ap(entry_conn, END_STREAM_REASON_TORPROTOCOL);
      return 0;
    }
    answer_type = cell->payload[RELAY_HEADER_SIZE];
    if (rh->length >= answer_len+6)
      ttl = (int)ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE+
                                  2+answer_len));
    else
      ttl = -1;
    if (answer_type == RESOLVED_TYPE_IPV4 && answer_len == 4) {
      uint32_t addr = ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE+2));
      if (get_options()->ClientDNSRejectInternalAddresses &&
          is_internal_IP(addr, 0)) {
        log_info(LD_APP,"Got a resolve with answer %s. Rejecting.",
                 fmt_addr32(addr));
        connection_ap_handshake_socks_resolved(entry_conn,
                                               RESOLVED_TYPE_ERROR_TRANSIENT,
                                               0, NULL, 0, TIME_MAX);
        connection_mark_unattached_ap(entry_conn,
                                      END_STREAM_REASON_TORPROTOCOL);
        return 0;
      }
    }
    connection_ap_handshake_socks_resolved(entry_conn,
                   answer_type,
                   cell->payload[RELAY_HEADER_SIZE+1], /*answer_len*/
                   cell->payload+RELAY_HEADER_SIZE+2, /*answer*/
                   ttl,
                   -1);
    if (answer_type == RESOLVED_TYPE_IPV4 && answer_len == 4) {
      uint32_t addr = ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE+2));
      remap_event_helper(entry_conn, addr);
    }
    connection_mark_unattached_ap(entry_conn,
                              END_STREAM_REASON_DONE |
                              END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
    return 0;
  }

  log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
         "Got an unexpected relay command %d, in state %d (%s). Dropping.",
         rh->command, conn->_base.state,
         conn_state_to_string(conn->_base.type, conn->_base.state));
  return 0; /* for forward compatibility, don't kill the circuit */
//  connection_edge_end(conn, END_STREAM_REASON_TORPROTOCOL);
//  connection_mark_for_close(conn);
//  return -1;
}

/** An incoming relay cell has arrived on circuit <b>circ</b>. If
 * <b>conn</b> is NULL this is a control cell, else <b>cell</b> is
 * destined for <b>conn</b>.
 *
 * If <b>layer_hint</b> is defined, then we're the origin of the
 * circuit, and it specifies the hop that packaged <b>cell</b>.
 *
 * Return -reason if you want to warn and tear down the circuit, else 0.
 */
static int
connection_edge_process_relay_cell(cell_t *cell, circuit_t *circ,
                                   edge_connection_t *conn,
                                   crypt_path_t *layer_hint)
{
  static int num_seen=0;
  relay_header_t rh;
  unsigned domain = layer_hint?LD_APP:LD_EXIT;
  int reason;
  int optimistic_data = 0; /* Set to 1 if we receive data on a stream
                            * that's in the EXIT_CONN_STATE_RESOLVING
                            * or EXIT_CONN_STATE_CONNECTING states. */

  tor_assert(cell);
  tor_assert(circ);

  relay_header_unpack(&rh, cell->payload);
//  log_fn(LOG_DEBUG,"command %d stream %d", rh.command, rh.stream_id);
  num_seen++;
  log_debug(domain, "Now seen %d relay cells here (command %d, stream %d).",
            num_seen, rh.command, rh.stream_id);

  if (rh.length > RELAY_PAYLOAD_SIZE) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Relay cell length field too long. Closing circuit.");
    return - END_CIRC_REASON_TORPROTOCOL;
  }

  if (rh.stream_id == 0) {
    switch (rh.command) {
      case RELAY_COMMAND_BEGIN:
      case RELAY_COMMAND_CONNECTED:
      case RELAY_COMMAND_DATA:
      case RELAY_COMMAND_END:
      case RELAY_COMMAND_RESOLVE:
      case RELAY_COMMAND_RESOLVED:
      case RELAY_COMMAND_BEGIN_DIR:
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL, "Relay command %d with zero "
               "stream_id. Dropping.", (int)rh.command);
        return 0;
      default:
        ;
    }
  }

  /* either conn is NULL, in which case we've got a control cell, or else
   * conn points to the recognized stream. */

  if (conn && !connection_state_is_open(TO_CONN(conn))) {
    if (conn->_base.type == CONN_TYPE_EXIT &&
        (conn->_base.state == EXIT_CONN_STATE_CONNECTING ||
         conn->_base.state == EXIT_CONN_STATE_RESOLVING) &&
        rh.command == RELAY_COMMAND_DATA) {
      /* Allow DATA cells to be delivered to an exit node in state
       * EXIT_CONN_STATE_CONNECTING or EXIT_CONN_STATE_RESOLVING.
       * This speeds up HTTP, for example. */
      optimistic_data = 1;
    } else {
      return connection_edge_process_relay_cell_not_open(
               &rh, cell, circ, conn, layer_hint);
    }
  }

  switch (rh.command) {
    case RELAY_COMMAND_DROP:
//      log_info(domain,"Got a relay-level padding cell. Dropping.");
      return 0;
    case RELAY_COMMAND_BEGIN:
    case RELAY_COMMAND_BEGIN_DIR:
      if (layer_hint &&
          circ->purpose != CIRCUIT_PURPOSE_S_REND_JOINED) {
        log_fn(LOG_PROTOCOL_WARN, LD_APP,
               "Relay begin request unsupported at AP. Dropping.");
        return 0;
      }
      if (circ->purpose == CIRCUIT_PURPOSE_S_REND_JOINED &&
          layer_hint != TO_ORIGIN_CIRCUIT(circ)->cpath->prev) {
        log_fn(LOG_PROTOCOL_WARN, LD_APP,
               "Relay begin request to Hidden Service "
               "from intermediary node. Dropping.");
        return 0;
      }
      if (conn) {
        log_fn(LOG_PROTOCOL_WARN, domain,
               "Begin cell for known stream. Dropping.");
        return 0;
      }
      if (rh.command == RELAY_COMMAND_BEGIN_DIR) {
        /* Assign this circuit and its app-ward OR connection a unique ID,
         * so that we can measure download times. The local edge and dir
         * connection will be assigned the same ID when they are created
         * and linked. */
        static uint64_t next_id = 0;
        circ->dirreq_id = ++next_id;
        TO_CONN(TO_OR_CIRCUIT(circ)->p_conn)->dirreq_id = circ->dirreq_id;
      }

      return connection_exit_begin_conn(cell, circ);
    case RELAY_COMMAND_DATA:
      ++stats_n_data_cells_received;
      if (( layer_hint && --layer_hint->deliver_window < 0) ||
          (!layer_hint && --circ->deliver_window < 0)) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "(relay data) circ deliver_window below 0. Killing.");
        if (conn) {
          /* XXXX Do we actually need to do this?  Will killing the circuit
           * not send an END and mark the stream for close as appropriate? */
          connection_edge_end(conn, END_STREAM_REASON_TORPROTOCOL);
          connection_mark_for_close(TO_CONN(conn));
        }
        return -END_CIRC_REASON_TORPROTOCOL;
      }
      log_debug(domain,"circ deliver_window now %d.", layer_hint ?
                layer_hint->deliver_window : circ->deliver_window);

      circuit_consider_sending_sendme(circ, layer_hint);

      if (!conn) {
        log_info(domain,"data cell dropped, unknown stream (streamid %d).",
                 rh.stream_id);
        return 0;
      }

      if (--conn->deliver_window < 0) { /* is it below 0 after decrement? */
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "(relay data) conn deliver_window below 0. Killing.");
        return -END_CIRC_REASON_TORPROTOCOL;
      }

      stats_n_data_bytes_received += rh.length;
      connection_write_to_buf((char*)(cell->payload + RELAY_HEADER_SIZE),
                              rh.length, TO_CONN(conn));

      if (!optimistic_data) {
        /* Only send a SENDME if we're not getting optimistic data; otherwise
         * a SENDME could arrive before the CONNECTED.
         */
        connection_edge_consider_sending_sendme(conn);
      }

      return 0;
    case RELAY_COMMAND_END:
      reason = rh.length > 0 ?
        get_uint8(cell->payload+RELAY_HEADER_SIZE) : END_STREAM_REASON_MISC;
      if (!conn) {
        log_info(domain,"end cell (%s) dropped, unknown stream.",
                 stream_end_reason_to_string(reason));
        return 0;
      }
/* XXX add to this log_fn the exit node's nickname? */
      log_info(domain,"%d: end cell (%s) for stream %d. Removing stream.",
               conn->_base.s,
               stream_end_reason_to_string(reason),
               conn->stream_id);
      if (conn->_base.type == CONN_TYPE_AP) {
        entry_connection_t *entry_conn = EDGE_TO_ENTRY_CONN(conn);
        if (entry_conn->socks_request &&
            !entry_conn->socks_request->has_finished)
          log_warn(LD_BUG,
                   "open stream hasn't sent socks answer yet? Closing.");
      }
      /* We just *got* an end; no reason to send one. */
      conn->edge_has_sent_end = 1;
      if (!conn->end_reason)
        conn->end_reason = reason | END_STREAM_REASON_FLAG_REMOTE;
      if (!conn->_base.marked_for_close) {
        /* only mark it if not already marked. it's possible to
         * get the 'end' right around when the client hangs up on us. */
        connection_mark_and_flush(TO_CONN(conn));
      }
      return 0;
    case RELAY_COMMAND_EXTEND: {
      static uint64_t total_n_extend=0, total_nonearly=0;
      total_n_extend++;
      if (conn) {
        log_fn(LOG_PROTOCOL_WARN, domain,
               "'extend' cell received for non-zero stream. Dropping.");
        return 0;
      }
      if (cell->command != CELL_RELAY_EARLY &&
          !networkstatus_get_param(NULL,"AllowNonearlyExtend",0,0,1)) {
#define EARLY_WARNING_INTERVAL 3600
        static ratelim_t early_warning_limit =
          RATELIM_INIT(EARLY_WARNING_INTERVAL);
        char *m;
        if (cell->command == CELL_RELAY) {
          ++total_nonearly;
          if ((m = rate_limit_log(&early_warning_limit, approx_time()))) {
            double percentage = ((double)total_nonearly)/total_n_extend;
            percentage *= 100;
            log_fn(LOG_PROTOCOL_WARN, domain, "EXTEND cell received, "
                   "but not via RELAY_EARLY. Dropping.%s", m);
            log_fn(LOG_PROTOCOL_WARN, domain, "  (We have dropped %.02f%% of "
                   "all EXTEND cells for this reason)", percentage);
            tor_free(m);
          }
        } else {
          log_fn(LOG_WARN, domain,
                 "EXTEND cell received, in a cell with type %d! Dropping.",
                 cell->command);
        }
        return 0;
      }
      return circuit_extend(cell, circ);
    }
    case RELAY_COMMAND_EXTENDED:
      if (!layer_hint) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "'extended' unsupported at non-origin. Dropping.");
        return 0;
      }
      log_debug(domain,"Got an extended cell! Yay.");
      if ((reason = circuit_finish_handshake(TO_ORIGIN_CIRCUIT(circ),
                                       CELL_CREATED,
                                       cell->payload+RELAY_HEADER_SIZE)) < 0) {
        log_warn(domain,"circuit_finish_handshake failed.");
        return reason;
      }
      if ((reason=circuit_send_next_onion_skin(TO_ORIGIN_CIRCUIT(circ)))<0) {
        log_info(domain,"circuit_send_next_onion_skin() failed.");
        return reason;
      }
      return 0;
    case RELAY_COMMAND_TRUNCATE:
      if (layer_hint) {
        log_fn(LOG_PROTOCOL_WARN, LD_APP,
               "'truncate' unsupported at origin. Dropping.");
        return 0;
      }
      if (circ->n_conn) {
        uint8_t trunc_reason = *(uint8_t*)(cell->payload + RELAY_HEADER_SIZE);
        circuit_clear_cell_queue(circ, circ->n_conn);
        connection_or_send_destroy(circ->n_circ_id, circ->n_conn,
                                   trunc_reason);
        circuit_set_n_circid_orconn(circ, 0, NULL);
      }
      log_debug(LD_EXIT, "Processed 'truncate', replying.");
      {
        char payload[1];
        payload[0] = (char)END_CIRC_REASON_REQUESTED;
        relay_send_command_from_edge(0, circ, RELAY_COMMAND_TRUNCATED,
                                     payload, sizeof(payload), NULL);
      }
      return 0;
    case RELAY_COMMAND_TRUNCATED:
      if (!layer_hint) {
        log_fn(LOG_PROTOCOL_WARN, LD_EXIT,
               "'truncated' unsupported at non-origin. Dropping.");
        return 0;
      }
      circuit_truncated(TO_ORIGIN_CIRCUIT(circ), layer_hint);
      return 0;
    case RELAY_COMMAND_CONNECTED:
      if (conn) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "'connected' unsupported while open. Closing circ.");
        return -END_CIRC_REASON_TORPROTOCOL;
      }
      log_info(domain,
               "'connected' received, no conn attached anymore. Ignoring.");
      return 0;
    case RELAY_COMMAND_SENDME:
      if (!rh.stream_id) {
        if (layer_hint) {
          if (layer_hint->package_window + CIRCWINDOW_INCREMENT >
                CIRCWINDOW_START_MAX) {
            log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
                   "Bug/attack: unexpected sendme cell from exit relay. "
                   "Closing circ.");
            return -END_CIRC_REASON_TORPROTOCOL;
          }
          layer_hint->package_window += CIRCWINDOW_INCREMENT;
          log_debug(LD_APP,"circ-level sendme at origin, packagewindow %d.",
                    layer_hint->package_window);
          circuit_resume_edge_reading(circ, layer_hint);
        } else {
          if (circ->package_window + CIRCWINDOW_INCREMENT >
                CIRCWINDOW_START_MAX) {
            log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
                   "Bug/attack: unexpected sendme cell from client. "
                   "Closing circ.");
            return -END_CIRC_REASON_TORPROTOCOL;
          }
          circ->package_window += CIRCWINDOW_INCREMENT;
          log_debug(LD_APP,
                    "circ-level sendme at non-origin, packagewindow %d.",
                    circ->package_window);
          circuit_resume_edge_reading(circ, layer_hint);
        }
        return 0;
      }
      if (!conn) {
        log_info(domain,"sendme cell dropped, unknown stream (streamid %d).",
                 rh.stream_id);
        return 0;
      }
      conn->package_window += STREAMWINDOW_INCREMENT;
      log_debug(domain,"stream-level sendme, packagewindow now %d.",
                conn->package_window);
      if (circuit_queue_streams_are_blocked(circ)) {
        /* Still waiting for queue to flush; don't touch conn */
        return 0;
      }
      connection_start_reading(TO_CONN(conn));
      /* handle whatever might still be on the inbuf */
      if (connection_edge_package_raw_inbuf(conn, 1, NULL) < 0) {
        /* (We already sent an end cell if possible) */
        connection_mark_for_close(TO_CONN(conn));
        return 0;
      }
      return 0;
    case RELAY_COMMAND_RESOLVE:
      if (layer_hint) {
        log_fn(LOG_PROTOCOL_WARN, LD_APP,
               "resolve request unsupported at AP; dropping.");
        return 0;
      } else if (conn) {
        log_fn(LOG_PROTOCOL_WARN, domain,
               "resolve request for known stream; dropping.");
        return 0;
      } else if (circ->purpose != CIRCUIT_PURPOSE_OR) {
        log_fn(LOG_PROTOCOL_WARN, domain,
               "resolve request on circ with purpose %d; dropping",
               circ->purpose);
        return 0;
      }
      connection_exit_begin_resolve(cell, TO_OR_CIRCUIT(circ));
      return 0;
    case RELAY_COMMAND_RESOLVED:
      if (conn) {
        log_fn(LOG_PROTOCOL_WARN, domain,
               "'resolved' unsupported while open. Closing circ.");
        return -END_CIRC_REASON_TORPROTOCOL;
      }
      log_info(domain,
               "'resolved' received, no conn attached anymore. Ignoring.");
      return 0;
    case RELAY_COMMAND_ESTABLISH_INTRO:
    case RELAY_COMMAND_ESTABLISH_RENDEZVOUS:
    case RELAY_COMMAND_INTRODUCE1:
    case RELAY_COMMAND_INTRODUCE2:
    case RELAY_COMMAND_INTRODUCE_ACK:
    case RELAY_COMMAND_RENDEZVOUS1:
    case RELAY_COMMAND_RENDEZVOUS2:
    case RELAY_COMMAND_INTRO_ESTABLISHED:
    case RELAY_COMMAND_RENDEZVOUS_ESTABLISHED:
      rend_process_relay_cell(circ, layer_hint,
                              rh.command, rh.length,
                              cell->payload+RELAY_HEADER_SIZE);
      return 0;
  }
  log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
         "Received unknown relay command %d. Perhaps the other side is using "
         "a newer version of Tor? Dropping.",
         rh.command);
  return 0; /* for forward compatibility, don't kill the circuit */
}

/** How many relay_data cells have we built, ever? */
uint64_t stats_n_data_cells_packaged = 0;
/** How many bytes of data have we put in relay_data cells have we built,
 * ever? This would be RELAY_PAYLOAD_SIZE*stats_n_data_cells_packaged if
 * every relay cell we ever sent were completely full of data. */
uint64_t stats_n_data_bytes_packaged = 0;
/** How many relay_data cells have we received, ever? */
uint64_t stats_n_data_cells_received = 0;
/** How many bytes of data have we received relay_data cells, ever? This would
 * be RELAY_PAYLOAD_SIZE*stats_n_data_cells_packaged if every relay cell we
 * ever received were completely full of data. */
uint64_t stats_n_data_bytes_received = 0;

/** If <b>conn</b> has an entire relay payload of bytes on its inbuf (or
 * <b>package_partial</b> is true), and the appropriate package windows aren't
 * empty, grab a cell and send it down the circuit.
 *
 * If *<b>max_cells</b> is given, package no more than max_cells.  Decrement
 * *<b>max_cells</b> by the number of cells packaged.
 *
 * Return -1 (and send a RELAY_COMMAND_END cell if necessary) if conn should
 * be marked for close, else return 0.
 */
int
connection_edge_package_raw_inbuf(edge_connection_t *conn, int package_partial,
                                  int *max_cells)
{
  size_t bytes_to_process, length;
  char payload[CELL_PAYLOAD_SIZE];
  circuit_t *circ;
  const unsigned domain = conn->_base.type == CONN_TYPE_AP ? LD_APP : LD_EXIT;
  int sending_from_optimistic = 0;
  const int sending_optimistically =
    conn->_base.type == CONN_TYPE_AP &&
    conn->_base.state != AP_CONN_STATE_OPEN;
  entry_connection_t *entry_conn =
    conn->_base.type == CONN_TYPE_AP ? EDGE_TO_ENTRY_CONN(conn) : NULL;
  crypt_path_t *cpath_layer = conn->cpath_layer;

  tor_assert(conn);

  if (conn->_base.marked_for_close) {
    log_warn(LD_BUG,
             "called on conn that's already marked for close at %s:%d.",
             conn->_base.marked_for_close_file, conn->_base.marked_for_close);
    return 0;
  }

  if (max_cells && *max_cells <= 0)
    return 0;

 repeat_connection_edge_package_raw_inbuf:

  circ = circuit_get_by_edge_conn(conn);
  if (!circ) {
    log_info(domain,"conn has no circuit! Closing.");
    conn->end_reason = END_STREAM_REASON_CANT_ATTACH;
    return -1;
  }

  if (circuit_consider_stop_edge_reading(circ, cpath_layer))
    return 0;

  if (conn->package_window <= 0) {
    log_info(domain,"called with package_window %d. Skipping.",
             conn->package_window);
    connection_stop_reading(TO_CONN(conn));
    return 0;
  }

  sending_from_optimistic = entry_conn &&
    entry_conn->sending_optimistic_data != NULL;

  if (PREDICT_UNLIKELY(sending_from_optimistic)) {
    bytes_to_process = generic_buffer_len(entry_conn->sending_optimistic_data);
    if (PREDICT_UNLIKELY(!bytes_to_process)) {
      log_warn(LD_BUG, "sending_optimistic_data was non-NULL but empty");
      bytes_to_process = connection_get_inbuf_len(TO_CONN(conn));
      sending_from_optimistic = 0;
    }
  } else {
    bytes_to_process = connection_get_inbuf_len(TO_CONN(conn));
  }

  if (!bytes_to_process)
    return 0;

  if (!package_partial && bytes_to_process < RELAY_PAYLOAD_SIZE)
    return 0;

  if (bytes_to_process > RELAY_PAYLOAD_SIZE) {
    length = RELAY_PAYLOAD_SIZE;
  } else {
    length = bytes_to_process;
  }
  stats_n_data_bytes_packaged += length;
  stats_n_data_cells_packaged += 1;

  if (PREDICT_UNLIKELY(sending_from_optimistic)) {
    /* XXXX We could be more efficient here by sometimes packing
     * previously-sent optimistic data in the same cell with data
     * from the inbuf. */
    generic_buffer_get(entry_conn->sending_optimistic_data, payload, length);
    if (!generic_buffer_len(entry_conn->sending_optimistic_data)) {
        generic_buffer_free(entry_conn->sending_optimistic_data);
        entry_conn->sending_optimistic_data = NULL;
    }
  } else {
    connection_fetch_from_buf(payload, length, TO_CONN(conn));
  }

  log_debug(domain,"(%d) Packaging %d bytes (%d waiting).", conn->_base.s,
            (int)length, (int)connection_get_inbuf_len(TO_CONN(conn)));

  if (sending_optimistically && !sending_from_optimistic) {
    /* This is new optimistic data; remember it in case we need to detach and
       retry */
    if (!entry_conn->pending_optimistic_data)
      entry_conn->pending_optimistic_data = generic_buffer_new();
    generic_buffer_add(entry_conn->pending_optimistic_data, payload, length);
  }

  if (connection_edge_send_command(conn, RELAY_COMMAND_DATA,
                                   payload, length) < 0 )
    /* circuit got marked for close, don't continue, don't need to mark conn */
    return 0;

  if (!cpath_layer) { /* non-rendezvous exit */
    tor_assert(circ->package_window > 0);
    circ->package_window--;
  } else { /* we're an AP, or an exit on a rendezvous circ */
    tor_assert(cpath_layer->package_window > 0);
    cpath_layer->package_window--;
  }

  if (--conn->package_window <= 0) { /* is it 0 after decrement? */
    connection_stop_reading(TO_CONN(conn));
    log_debug(domain,"conn->package_window reached 0.");
    circuit_consider_stop_edge_reading(circ, cpath_layer);
    return 0; /* don't process the inbuf any more */
  }
  log_debug(domain,"conn->package_window is now %d",conn->package_window);

  if (max_cells) {
    *max_cells -= 1;
    if (*max_cells <= 0)
      return 0;
  }

  /* handle more if there's more, or return 0 if there isn't */
  goto repeat_connection_edge_package_raw_inbuf;
}

/** Called when we've just received a relay data cell, when
 * we've just finished flushing all bytes to stream <b>conn</b>,
 * or when we've flushed *some* bytes to the stream <b>conn</b>.
 *
 * If conn->outbuf is not too full, and our deliver window is
 * low, send back a suitable number of stream-level sendme cells.
 */
void
connection_edge_consider_sending_sendme(edge_connection_t *conn)
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
    log_debug(conn->_base.type == CONN_TYPE_AP ?LD_APP:LD_EXIT,
              "Outbuf %d, Queuing stream sendme.",
              (int)conn->_base.outbuf_flushlen);
    conn->deliver_window += STREAMWINDOW_INCREMENT;
    if (connection_edge_send_command(conn, RELAY_COMMAND_SENDME,
                                     NULL, 0) < 0) {
      log_warn(LD_APP,"connection_edge_send_command failed. Skipping.");
      return; /* the circuit's closed, don't continue */
    }
  }
}

/** The circuit <b>circ</b> has received a circuit-level sendme
 * (on hop <b>layer_hint</b>, if we're the OP). Go through all the
 * attached streams and let them resume reading and packaging, if
 * their stream windows allow it.
 */
static void
circuit_resume_edge_reading(circuit_t *circ, crypt_path_t *layer_hint)
{
  if (circuit_queue_streams_are_blocked(circ)) {
    log_debug(layer_hint?LD_APP:LD_EXIT,"Too big queue, no resuming");
    return;
  }
  log_debug(layer_hint?LD_APP:LD_EXIT,"resuming");

  if (CIRCUIT_IS_ORIGIN(circ))
    circuit_resume_edge_reading_helper(TO_ORIGIN_CIRCUIT(circ)->p_streams,
                                       circ, layer_hint);
  else
    circuit_resume_edge_reading_helper(TO_OR_CIRCUIT(circ)->n_streams,
                                       circ, layer_hint);
}

/** A helper function for circuit_resume_edge_reading() above.
 * The arguments are the same, except that <b>conn</b> is the head
 * of a linked list of edge streams that should each be considered.
 */
static int
circuit_resume_edge_reading_helper(edge_connection_t *first_conn,
                                   circuit_t *circ,
                                   crypt_path_t *layer_hint)
{
  edge_connection_t *conn;
  int n_packaging_streams, n_streams_left;
  int packaged_this_round;
  int cells_on_queue;
  int cells_per_conn;
  edge_connection_t *chosen_stream = NULL;

  /* How many cells do we have space for?  It will be the minimum of
   * the number needed to exhaust the package window, and the minimum
   * needed to fill the cell queue. */
  int max_to_package = circ->package_window;
  if (CIRCUIT_IS_ORIGIN(circ)) {
    cells_on_queue = circ->n_conn_cells.n;
  } else {
    or_circuit_t *or_circ = TO_OR_CIRCUIT(circ);
    cells_on_queue = or_circ->p_conn_cells.n;
  }
  if (CELL_QUEUE_HIGHWATER_SIZE - cells_on_queue < max_to_package)
    max_to_package = CELL_QUEUE_HIGHWATER_SIZE - cells_on_queue;

  /* Once we used to start listening on the streams in the order they
   * appeared in the linked list.  That leads to starvation on the
   * streams that appeared later on the list, since the first streams
   * would always get to read first.  Instead, we just pick a random
   * stream on the list, and enable reading for streams starting at that
   * point (and wrapping around as if the list were circular).  It would
   * probably be better to actually remember which streams we've
   * serviced in the past, but this is simple and effective. */

  /* Select a stream uniformly at random from the linked list.  We
   * don't need cryptographic randomness here. */
  {
    int num_streams = 0;
    for (conn = first_conn; conn; conn = conn->next_stream) {
      num_streams++;
      if ((tor_weak_random() % num_streams)==0)
        chosen_stream = conn;
      /* Invariant: chosen_stream has been chosen uniformly at random from
       * among the first num_streams streams on first_conn. */
    }
  }

  /* Count how many non-marked streams there are that have anything on
   * their inbuf, and enable reading on all of the connections. */
  n_packaging_streams = 0;
  /* Activate reading starting from the chosen stream */
  for (conn=chosen_stream; conn; conn = conn->next_stream) {
    /* Start reading for the streams starting from here */
    if (conn->_base.marked_for_close || conn->package_window <= 0)
      continue;
    if (!layer_hint || conn->cpath_layer == layer_hint) {
      connection_start_reading(TO_CONN(conn));

      if (connection_get_inbuf_len(TO_CONN(conn)) > 0)
        ++n_packaging_streams;
    }
  }
  /* Go back and do the ones we skipped, circular-style */
  for (conn = first_conn; conn != chosen_stream; conn = conn->next_stream) {
    if (conn->_base.marked_for_close || conn->package_window <= 0)
      continue;
    if (!layer_hint || conn->cpath_layer == layer_hint) {
      connection_start_reading(TO_CONN(conn));

      if (connection_get_inbuf_len(TO_CONN(conn)) > 0)
        ++n_packaging_streams;
    }
  }

  if (n_packaging_streams == 0) /* avoid divide-by-zero */
    return 0;

 again:

  cells_per_conn = CEIL_DIV(max_to_package, n_packaging_streams);

  packaged_this_round = 0;
  n_streams_left = 0;

  /* Iterate over all connections.  Package up to cells_per_conn cells on
   * each.  Update packaged_this_round with the total number of cells
   * packaged, and n_streams_left with the number that still have data to
   * package.
   */
  for (conn=first_conn; conn; conn=conn->next_stream) {
    if (conn->_base.marked_for_close || conn->package_window <= 0)
      continue;
    if (!layer_hint || conn->cpath_layer == layer_hint) {
      int n = cells_per_conn, r;
      /* handle whatever might still be on the inbuf */
      r = connection_edge_package_raw_inbuf(conn, 1, &n);

      /* Note how many we packaged */
      packaged_this_round += (cells_per_conn-n);

      if (r<0) {
        /* Problem while packaging. (We already sent an end cell if
         * possible) */
        connection_mark_for_close(TO_CONN(conn));
        continue;
      }

      /* If there's still data to read, we'll be coming back to this stream. */
      if (connection_get_inbuf_len(TO_CONN(conn)))
          ++n_streams_left;

      /* If the circuit won't accept any more data, return without looking
       * at any more of the streams. Any connections that should be stopped
       * have already been stopped by connection_edge_package_raw_inbuf. */
      if (circuit_consider_stop_edge_reading(circ, layer_hint))
        return -1;
      /* XXXX should we also stop immediately if we fill up the cell queue?
       * Probably. */
    }
  }

  /* If we made progress, and we are willing to package more, and there are
   * any streams left that want to package stuff... try again!
   */
  if (packaged_this_round && packaged_this_round < max_to_package &&
      n_streams_left) {
    max_to_package -= packaged_this_round;
    n_packaging_streams = n_streams_left;
    goto again;
  }

  return 0;
}

/** Check if the package window for <b>circ</b> is empty (at
 * hop <b>layer_hint</b> if it's defined).
 *
 * If yes, tell edge streams to stop reading and return 1.
 * Else return 0.
 */
static int
circuit_consider_stop_edge_reading(circuit_t *circ, crypt_path_t *layer_hint)
{
  edge_connection_t *conn = NULL;
  unsigned domain = layer_hint ? LD_APP : LD_EXIT;

  if (!layer_hint) {
    or_circuit_t *or_circ = TO_OR_CIRCUIT(circ);
    log_debug(domain,"considering circ->package_window %d",
              circ->package_window);
    if (circ->package_window <= 0) {
      log_debug(domain,"yes, not-at-origin. stopped.");
      for (conn = or_circ->n_streams; conn; conn=conn->next_stream)
        connection_stop_reading(TO_CONN(conn));
      return 1;
    }
    return 0;
  }
  /* else, layer hint is defined, use it */
  log_debug(domain,"considering layer_hint->package_window %d",
            layer_hint->package_window);
  if (layer_hint->package_window <= 0) {
    log_debug(domain,"yes, at-origin. stopped.");
    for (conn = TO_ORIGIN_CIRCUIT(circ)->p_streams; conn;
         conn=conn->next_stream) {
      if (conn->cpath_layer == layer_hint)
        connection_stop_reading(TO_CONN(conn));
    }
    return 1;
  }
  return 0;
}

/** Check if the deliver_window for circuit <b>circ</b> (at hop
 * <b>layer_hint</b> if it's defined) is low enough that we should
 * send a circuit-level sendme back down the circuit. If so, send
 * enough sendmes that the window would be overfull if we sent any
 * more.
 */
static void
circuit_consider_sending_sendme(circuit_t *circ, crypt_path_t *layer_hint)
{
//  log_fn(LOG_INFO,"Considering: layer_hint is %s",
//         layer_hint ? "defined" : "null");
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

#ifdef ACTIVE_CIRCUITS_PARANOIA
#define assert_active_circuits_ok_paranoid(conn) \
     assert_active_circuits_ok(conn)
#else
#define assert_active_circuits_ok_paranoid(conn)
#endif

/** The total number of cells we have allocated from the memory pool. */
static size_t total_cells_allocated = 0;

/** A memory pool to allocate packed_cell_t objects. */
static mp_pool_t *cell_pool = NULL;

/** Memory pool to allocate insertion_time_elem_t objects used for cell
 * statistics. */
static mp_pool_t *it_pool = NULL;

/** Allocate structures to hold cells. */
void
init_cell_pool(void)
{
  tor_assert(!cell_pool);
  cell_pool = mp_pool_new(sizeof(packed_cell_t), 128*1024);
}

/** Free all storage used to hold cells (and insertion times if we measure
 * cell statistics). */
void
free_cell_pool(void)
{
  /* Maybe we haven't called init_cell_pool yet; need to check for it. */
  if (cell_pool) {
    mp_pool_destroy(cell_pool);
    cell_pool = NULL;
  }
  if (it_pool) {
    mp_pool_destroy(it_pool);
    it_pool = NULL;
  }
}

/** Free excess storage in cell pool. */
void
clean_cell_pool(void)
{
  tor_assert(cell_pool);
  mp_pool_clean(cell_pool, 0, 1);
}

/** Release storage held by <b>cell</b>. */
static INLINE void
packed_cell_free_unchecked(packed_cell_t *cell)
{
  --total_cells_allocated;
  mp_pool_release(cell);
}

/** Allocate and return a new packed_cell_t. */
static INLINE packed_cell_t *
packed_cell_alloc(void)
{
  ++total_cells_allocated;
  return mp_pool_get(cell_pool);
}

/** Log current statistics for cell pool allocation at log level
 * <b>severity</b>. */
void
dump_cell_pool_usage(int severity)
{
  circuit_t *c;
  int n_circs = 0;
  int n_cells = 0;
  for (c = _circuit_get_global_list(); c; c = c->next) {
    n_cells += c->n_conn_cells.n;
    if (!CIRCUIT_IS_ORIGIN(c))
      n_cells += TO_OR_CIRCUIT(c)->p_conn_cells.n;
    ++n_circs;
  }
  log(severity, LD_MM, "%d cells allocated on %d circuits. %d cells leaked.",
      n_cells, n_circs, (int)total_cells_allocated - n_cells);
  mp_pool_log_status(cell_pool, severity);
}

/** Allocate a new copy of packed <b>cell</b>. */
static INLINE packed_cell_t *
packed_cell_copy(const cell_t *cell)
{
  packed_cell_t *c = packed_cell_alloc();
  cell_pack(c, cell);
  c->next = NULL;
  return c;
}

/** Append <b>cell</b> to the end of <b>queue</b>. */
void
cell_queue_append(cell_queue_t *queue, packed_cell_t *cell)
{
  if (queue->tail) {
    tor_assert(!queue->tail->next);
    queue->tail->next = cell;
  } else {
    queue->head = cell;
  }
  queue->tail = cell;
  cell->next = NULL;
  ++queue->n;
}

/** Append a newly allocated copy of <b>cell</b> to the end of <b>queue</b> */
void
cell_queue_append_packed_copy(cell_queue_t *queue, const cell_t *cell)
{
  struct timeval now;
  packed_cell_t *copy = packed_cell_copy(cell);
  tor_gettimeofday_cached(&now);
  copy->inserted_time = (uint32_t)tv_to_msec(&now);

  /* Remember the time when this cell was put in the queue. */
  /*XXXX This may be obsoleted by inserted_time */
  if (get_options()->CellStatistics) {
    uint32_t added;
    insertion_time_queue_t *it_queue = queue->insertion_times;
    if (!it_pool)
      it_pool = mp_pool_new(sizeof(insertion_time_elem_t), 1024);

#define SECONDS_IN_A_DAY 86400L
    added = (uint32_t)(((now.tv_sec % SECONDS_IN_A_DAY) * 100L)
            + ((uint32_t)now.tv_usec / (uint32_t)10000L));
    if (!it_queue) {
      it_queue = tor_malloc_zero(sizeof(insertion_time_queue_t));
      queue->insertion_times = it_queue;
    }
    if (it_queue->last && it_queue->last->insertion_time == added) {
      it_queue->last->counter++;
    } else {
      insertion_time_elem_t *elem = mp_pool_get(it_pool);
      elem->next = NULL;
      elem->insertion_time = added;
      elem->counter = 1;
      if (it_queue->last) {
        it_queue->last->next = elem;
        it_queue->last = elem;
      } else {
        it_queue->first = it_queue->last = elem;
      }
    }
  }
  cell_queue_append(queue, copy);
}

/** Remove and free every cell in <b>queue</b>. */
void
cell_queue_clear(cell_queue_t *queue)
{
  packed_cell_t *cell, *next;
  cell = queue->head;
  while (cell) {
    next = cell->next;
    packed_cell_free_unchecked(cell);
    cell = next;
  }
  queue->head = queue->tail = NULL;
  queue->n = 0;
  if (queue->insertion_times) {
    while (queue->insertion_times->first) {
      insertion_time_elem_t *elem = queue->insertion_times->first;
      queue->insertion_times->first = elem->next;
      mp_pool_release(elem);
    }
    tor_free(queue->insertion_times);
  }
}

/** Extract and return the cell at the head of <b>queue</b>; return NULL if
 * <b>queue</b> is empty. */
static INLINE packed_cell_t *
cell_queue_pop(cell_queue_t *queue)
{
  packed_cell_t *cell = queue->head;
  if (!cell)
    return NULL;
  queue->head = cell->next;
  if (cell == queue->tail) {
    tor_assert(!queue->head);
    queue->tail = NULL;
  }
  --queue->n;
  return cell;
}

/** Return the total number of bytes used for each packed_cell in a queue.
 * Approximate. */
size_t
packed_cell_mem_cost(void)
{
  return sizeof(packed_cell_t) + MP_POOL_ITEM_OVERHEAD +
    get_options()->CellStatistics ?
    (sizeof(insertion_time_elem_t)+MP_POOL_ITEM_OVERHEAD) : 0;
}

/** Check whether we've got too much space used for cells.  If so,
 * call the OOM handler and return 1.  Otherwise, return 0. */
static int
cell_queues_check_size(void)
{
  size_t alloc = total_cells_allocated * packed_cell_mem_cost();
  if (alloc >= get_options()->MaxMemInCellQueues) {
    circuits_handle_oom(alloc);
    return 1;
  }
  return 0;
}

/** Return a pointer to the "next_active_on_{n,p}_conn" pointer of <b>circ</b>,
 * depending on whether <b>conn</b> matches n_conn or p_conn. */
static INLINE circuit_t **
next_circ_on_conn_p(circuit_t *circ, or_connection_t *conn)
{
  tor_assert(circ);
  tor_assert(conn);
  if (conn == circ->n_conn) {
    return &circ->next_active_on_n_conn;
  } else {
    or_circuit_t *orcirc = TO_OR_CIRCUIT(circ);
    tor_assert(conn == orcirc->p_conn);
    return &orcirc->next_active_on_p_conn;
  }
}

/** Return a pointer to the "prev_active_on_{n,p}_conn" pointer of <b>circ</b>,
 * depending on whether <b>conn</b> matches n_conn or p_conn. */
static INLINE circuit_t **
prev_circ_on_conn_p(circuit_t *circ, or_connection_t *conn)
{
  tor_assert(circ);
  tor_assert(conn);
  if (conn == circ->n_conn) {
    return &circ->prev_active_on_n_conn;
  } else {
    or_circuit_t *orcirc = TO_OR_CIRCUIT(circ);
    tor_assert(conn == orcirc->p_conn);
    return &orcirc->prev_active_on_p_conn;
  }
}

/** Helper for sorting cell_ewma_t values in their priority queue. */
static int
compare_cell_ewma_counts(const void *p1, const void *p2)
{
  const cell_ewma_t *e1=p1, *e2=p2;
  if (e1->cell_count < e2->cell_count)
    return -1;
  else if (e1->cell_count > e2->cell_count)
    return 1;
  else
    return 0;
}

/** Given a cell_ewma_t, return a pointer to the circuit containing it. */
static circuit_t *
cell_ewma_to_circuit(cell_ewma_t *ewma)
{
  if (ewma->is_for_p_conn) {
    /* This is an or_circuit_t's p_cell_ewma. */
    or_circuit_t *orcirc = SUBTYPE_P(ewma, or_circuit_t, p_cell_ewma);
    return TO_CIRCUIT(orcirc);
  } else {
    /* This is some circuit's n_cell_ewma. */
    return SUBTYPE_P(ewma, circuit_t, n_cell_ewma);
  }
}

/* ==== Functions for scaling cell_ewma_t ====

   When choosing which cells to relay first, we favor circuits that have been
   quiet recently.  This gives better latency on connections that aren't
   pushing lots of data, and makes the network feel more interactive.

   Conceptually, we take an exponentially weighted mean average of the number
   of cells a circuit has sent, and allow active circuits (those with cells to
   relay) to send cells in reverse order of their exponentially-weighted mean
   average (EWMA) cell count.  [That is, a cell sent N seconds ago 'counts'
   F^N times as much as a cell sent now, for 0<F<1.0, and we favor the
   circuit that has sent the fewest cells]

   If 'double' had infinite precision, we could do this simply by counting a
   cell sent at startup as having weight 1.0, and a cell sent N seconds later
   as having weight F^-N.  This way, we would never need to re-scale
   any already-sent cells.

   To prevent double from overflowing, we could count a cell sent now as
   having weight 1.0 and a cell sent N seconds ago as having weight F^N.
   This, however, would mean we'd need to re-scale *ALL* old circuits every
   time we wanted to send a cell.

   So as a compromise, we divide time into 'ticks' (currently, 10-second
   increments) and say that a cell sent at the start of a current tick is
   worth 1.0, a cell sent N seconds before the start of the current tick is
   worth F^N, and a cell sent N seconds after the start of the current tick is
   worth F^-N.  This way we don't overflow, and we don't need to constantly
   rescale.
 */

/** How long does a tick last (seconds)? */
#define EWMA_TICK_LEN 10

/** The default per-tick scale factor, if it hasn't been overridden by a
 * consensus or a configuration setting.  zero means "disabled". */
#define EWMA_DEFAULT_HALFLIFE 0.0

/** Given a timeval <b>now</b>, compute the cell_ewma tick in which it occurs
 * and the fraction of the tick that has elapsed between the start of the tick
 * and <b>now</b>.  Return the former and store the latter in
 * *<b>remainder_out</b>.
 *
 * These tick values are not meant to be shared between Tor instances, or used
 * for other purposes. */
static unsigned
cell_ewma_tick_from_timeval(const struct timeval *now,
                            double *remainder_out)
{
  unsigned res = (unsigned) (now->tv_sec / EWMA_TICK_LEN);
  /* rem */
  double rem = (now->tv_sec % EWMA_TICK_LEN) +
    ((double)(now->tv_usec)) / 1.0e6;
  *remainder_out = rem / EWMA_TICK_LEN;
  return res;
}

/** Compute and return the current cell_ewma tick. */
unsigned
cell_ewma_get_tick(void)
{
  return ((unsigned)approx_time() / EWMA_TICK_LEN);
}

/** The per-tick scale factor to be used when computing cell-count EWMA
 * values.  (A cell sent N ticks before the start of the current tick
 * has value ewma_scale_factor ** N.)
 */
static double ewma_scale_factor = 0.1;
/* DOCDOC ewma_enabled */
static int ewma_enabled = 0;

/*DOCDOC*/
#define EPSILON 0.00001
/*DOCDOC*/
#define LOG_ONEHALF -0.69314718055994529

/** Adjust the global cell scale factor based on <b>options</b> */
void
cell_ewma_set_scale_factor(const or_options_t *options,
                           const networkstatus_t *consensus)
{
  int32_t halflife_ms;
  double halflife;
  const char *source;
  if (options && options->CircuitPriorityHalflife >= -EPSILON) {
    halflife = options->CircuitPriorityHalflife;
    source = "CircuitPriorityHalflife in configuration";
  } else if (consensus && (halflife_ms = networkstatus_get_param(
                 consensus, "CircuitPriorityHalflifeMsec",
                 -1, -1, INT32_MAX)) >= 0) {
    halflife = ((double)halflife_ms)/1000.0;
    source = "CircuitPriorityHalflifeMsec in consensus";
  } else {
    halflife = EWMA_DEFAULT_HALFLIFE;
    source = "Default value";
  }

  if (halflife <= EPSILON) {
    /* The cell EWMA algorithm is disabled. */
    ewma_scale_factor = 0.1;
    ewma_enabled = 0;
    log_info(LD_OR,
             "Disabled cell_ewma algorithm because of value in %s",
             source);
  } else {
    /* convert halflife into halflife-per-tick. */
    halflife /= EWMA_TICK_LEN;
    /* compute per-tick scale factor. */
    ewma_scale_factor = exp( LOG_ONEHALF / halflife );
    ewma_enabled = 1;
    log_info(LD_OR,
             "Enabled cell_ewma algorithm because of value in %s; "
             "scale factor is %f per %d seconds",
             source, ewma_scale_factor, EWMA_TICK_LEN);
  }
}

/** Return the multiplier necessary to convert the value of a cell sent in
 * 'from_tick' to one sent in 'to_tick'. */
static INLINE double
get_scale_factor(unsigned from_tick, unsigned to_tick)
{
  /* This math can wrap around, but that's okay: unsigned overflow is
     well-defined */
  int diff = (int)(to_tick - from_tick);
  return pow(ewma_scale_factor, diff);
}

/** Adjust the cell count of <b>ewma</b> so that it is scaled with respect to
 * <b>cur_tick</b> */
static void
scale_single_cell_ewma(cell_ewma_t *ewma, unsigned cur_tick)
{
  double factor = get_scale_factor(ewma->last_adjusted_tick, cur_tick);
  ewma->cell_count *= factor;
  ewma->last_adjusted_tick = cur_tick;
}

/** Adjust the cell count of every active circuit on <b>conn</b> so
 * that they are scaled with respect to <b>cur_tick</b> */
static void
scale_active_circuits(or_connection_t *conn, unsigned cur_tick)
{

  double factor = get_scale_factor(
              conn->active_circuit_pqueue_last_recalibrated,
              cur_tick);
  /** Ordinarily it isn't okay to change the value of an element in a heap,
   * but it's okay here, since we are preserving the order. */
  SMARTLIST_FOREACH(conn->active_circuit_pqueue, cell_ewma_t *, e, {
      tor_assert(e->last_adjusted_tick ==
                 conn->active_circuit_pqueue_last_recalibrated);
      e->cell_count *= factor;
      e->last_adjusted_tick = cur_tick;
  });
  conn->active_circuit_pqueue_last_recalibrated = cur_tick;
}

/** Rescale <b>ewma</b> to the same scale as <b>conn</b>, and add it to
 * <b>conn</b>'s priority queue of active circuits */
static void
add_cell_ewma_to_conn(or_connection_t *conn, cell_ewma_t *ewma)
{
  tor_assert(ewma->heap_index == -1);
  scale_single_cell_ewma(ewma,
                         conn->active_circuit_pqueue_last_recalibrated);

  smartlist_pqueue_add(conn->active_circuit_pqueue,
                       compare_cell_ewma_counts,
                       STRUCT_OFFSET(cell_ewma_t, heap_index),
                       ewma);
}

/** Remove <b>ewma</b> from <b>conn</b>'s priority queue of active circuits */
static void
remove_cell_ewma_from_conn(or_connection_t *conn, cell_ewma_t *ewma)
{
  tor_assert(ewma->heap_index != -1);
  smartlist_pqueue_remove(conn->active_circuit_pqueue,
                          compare_cell_ewma_counts,
                          STRUCT_OFFSET(cell_ewma_t, heap_index),
                          ewma);
}

/** Remove and return the first cell_ewma_t from conn's priority queue of
 * active circuits.  Requires that the priority queue is nonempty. */
static cell_ewma_t *
pop_first_cell_ewma_from_conn(or_connection_t *conn)
{
  return smartlist_pqueue_pop(conn->active_circuit_pqueue,
                              compare_cell_ewma_counts,
                              STRUCT_OFFSET(cell_ewma_t, heap_index));
}

/** Add <b>circ</b> to the list of circuits with pending cells on
 * <b>conn</b>.  No effect if <b>circ</b> is already linked. */
void
make_circuit_active_on_conn(circuit_t *circ, or_connection_t *conn)
{
  circuit_t **nextp = next_circ_on_conn_p(circ, conn);
  circuit_t **prevp = prev_circ_on_conn_p(circ, conn);

  if (*nextp && *prevp) {
    /* Already active. */
    return;
  }

  assert_active_circuits_ok_paranoid(conn);

  if (! conn->active_circuits) {
    conn->active_circuits = circ;
    *prevp = *nextp = circ;
  } else {
    circuit_t *head = conn->active_circuits;
    circuit_t *old_tail = *prev_circ_on_conn_p(head, conn);
    *next_circ_on_conn_p(old_tail, conn) = circ;
    *nextp = head;
    *prev_circ_on_conn_p(head, conn) = circ;
    *prevp = old_tail;
  }

  if (circ->n_conn == conn) {
    add_cell_ewma_to_conn(conn, &circ->n_cell_ewma);
  } else {
    or_circuit_t *orcirc = TO_OR_CIRCUIT(circ);
    tor_assert(conn == orcirc->p_conn);
    add_cell_ewma_to_conn(conn, &orcirc->p_cell_ewma);
  }

  assert_active_circuits_ok_paranoid(conn);
}

/** Remove <b>circ</b> from the list of circuits with pending cells on
 * <b>conn</b>.  No effect if <b>circ</b> is already unlinked. */
void
make_circuit_inactive_on_conn(circuit_t *circ, or_connection_t *conn)
{
  circuit_t **nextp = next_circ_on_conn_p(circ, conn);
  circuit_t **prevp = prev_circ_on_conn_p(circ, conn);
  circuit_t *next = *nextp, *prev = *prevp;

  if (!next && !prev) {
    /* Already inactive. */
    return;
  }

  assert_active_circuits_ok_paranoid(conn);

  tor_assert(next && prev);
  tor_assert(*prev_circ_on_conn_p(next, conn) == circ);
  tor_assert(*next_circ_on_conn_p(prev, conn) == circ);

  if (next == circ) {
    conn->active_circuits = NULL;
  } else {
    *prev_circ_on_conn_p(next, conn) = prev;
    *next_circ_on_conn_p(prev, conn) = next;
    if (conn->active_circuits == circ)
      conn->active_circuits = next;
  }
  *prevp = *nextp = NULL;

  if (circ->n_conn == conn) {
    remove_cell_ewma_from_conn(conn, &circ->n_cell_ewma);
  } else {
    or_circuit_t *orcirc = TO_OR_CIRCUIT(circ);
    tor_assert(conn == orcirc->p_conn);
    remove_cell_ewma_from_conn(conn, &orcirc->p_cell_ewma);
  }

  assert_active_circuits_ok_paranoid(conn);
}

/** Remove all circuits from the list of circuits with pending cells on
 * <b>conn</b>. */
void
connection_or_unlink_all_active_circs(or_connection_t *orconn)
{
  circuit_t *head = orconn->active_circuits;
  circuit_t *cur = head;
  if (! head)
    return;
  do {
    circuit_t *next = *next_circ_on_conn_p(cur, orconn);
    *prev_circ_on_conn_p(cur, orconn) = NULL;
    *next_circ_on_conn_p(cur, orconn) = NULL;
    cur = next;
  } while (cur != head);
  orconn->active_circuits = NULL;

  SMARTLIST_FOREACH(orconn->active_circuit_pqueue, cell_ewma_t *, e,
                    e->heap_index = -1);
  smartlist_clear(orconn->active_circuit_pqueue);
}

/** Block (if <b>block</b> is true) or unblock (if <b>block</b> is false)
 * every edge connection that is using <b>circ</b> to write to <b>orconn</b>,
 * and start or stop reading as appropriate.
 *
 * If <b>stream_id</b> is nonzero, block only the edge connection whose
 * stream_id matches it.
 *
 * Returns the number of streams whose status we changed.
 */
static int
set_streams_blocked_on_circ(circuit_t *circ, or_connection_t *orconn,
                            int block, streamid_t stream_id)
{
  edge_connection_t *edge = NULL;
  int n = 0;
  if (circ->n_conn == orconn) {
    circ->streams_blocked_on_n_conn = block;
    if (CIRCUIT_IS_ORIGIN(circ))
      edge = TO_ORIGIN_CIRCUIT(circ)->p_streams;
  } else {
    circ->streams_blocked_on_p_conn = block;
    tor_assert(!CIRCUIT_IS_ORIGIN(circ));
    edge = TO_OR_CIRCUIT(circ)->n_streams;
  }

  for (; edge; edge = edge->next_stream) {
    connection_t *conn = TO_CONN(edge);
    if (stream_id && edge->stream_id != stream_id)
      continue;

    if (edge->edge_blocked_on_circ != block) {
      ++n;
      edge->edge_blocked_on_circ = block;
    }

    if (!conn->read_event && !HAS_BUFFEREVENT(conn)) {
      /* This connection is a placeholder for something; probably a DNS
       * request.  It can't actually stop or start reading.*/
      continue;
    }

    if (block) {
      if (connection_is_reading(conn))
        connection_stop_reading(conn);
    } else {
      /* Is this right? */
      if (!connection_is_reading(conn))
        connection_start_reading(conn);
    }
  }

  return n;
}

/** Pull as many cells as possible (but no more than <b>max</b>) from the
 * queue of the first active circuit on <b>conn</b>, and write them to
 * <b>conn</b>-&gt;outbuf.  Return the number of cells written.  Advance
 * the active circuit pointer to the next active circuit in the ring. */
int
connection_or_flush_from_first_active_circuit(or_connection_t *conn, int max,
                                              time_t now)
{
  int n_flushed;
  cell_queue_t *queue;
  circuit_t *circ;
  int streams_blocked;

  /* The current (hi-res) time */
  struct timeval now_hires;

  /* The EWMA cell counter for the circuit we're flushing. */
  cell_ewma_t *cell_ewma = NULL;
  double ewma_increment = -1;

  circ = conn->active_circuits;
  if (!circ) return 0;
  assert_active_circuits_ok_paranoid(conn);

  /* See if we're doing the ewma circuit selection algorithm. */
  if (ewma_enabled) {
    unsigned tick;
    double fractional_tick;
    tor_gettimeofday_cached(&now_hires);
    tick = cell_ewma_tick_from_timeval(&now_hires, &fractional_tick);

    if (tick != conn->active_circuit_pqueue_last_recalibrated) {
      scale_active_circuits(conn, tick);
    }

    ewma_increment = pow(ewma_scale_factor, -fractional_tick);

    cell_ewma = smartlist_get(conn->active_circuit_pqueue, 0);
    circ = cell_ewma_to_circuit(cell_ewma);
  }

  if (circ->n_conn == conn) {
    queue = &circ->n_conn_cells;
    streams_blocked = circ->streams_blocked_on_n_conn;
  } else {
    queue = &TO_OR_CIRCUIT(circ)->p_conn_cells;
    streams_blocked = circ->streams_blocked_on_p_conn;
  }
  tor_assert(*next_circ_on_conn_p(circ,conn));

  for (n_flushed = 0; n_flushed < max && queue->head; ) {
    packed_cell_t *cell = cell_queue_pop(queue);
    tor_assert(*next_circ_on_conn_p(circ,conn));

    /* Calculate the exact time that this cell has spent in the queue. */
    if (get_options()->CellStatistics && !CIRCUIT_IS_ORIGIN(circ)) {
      struct timeval tvnow;
      uint32_t flushed;
      uint32_t cell_waiting_time;
      insertion_time_queue_t *it_queue = queue->insertion_times;
      tor_gettimeofday_cached(&tvnow);
      flushed = (uint32_t)((tvnow.tv_sec % SECONDS_IN_A_DAY) * 100L +
                 (uint32_t)tvnow.tv_usec / (uint32_t)10000L);
      if (!it_queue || !it_queue->first) {
        log_info(LD_GENERAL, "Cannot determine insertion time of cell. "
                             "Looks like the CellStatistics option was "
                             "recently enabled.");
      } else {
        or_circuit_t *orcirc = TO_OR_CIRCUIT(circ);
        insertion_time_elem_t *elem = it_queue->first;
        cell_waiting_time =
            (uint32_t)((flushed * 10L + SECONDS_IN_A_DAY * 1000L -
                        elem->insertion_time * 10L) %
                       (SECONDS_IN_A_DAY * 1000L));
#undef SECONDS_IN_A_DAY
        elem->counter--;
        if (elem->counter < 1) {
          it_queue->first = elem->next;
          if (elem == it_queue->last)
            it_queue->last = NULL;
          mp_pool_release(elem);
        }
        orcirc->total_cell_waiting_time += cell_waiting_time;
        orcirc->processed_cells++;
      }
    }

    /* If we just flushed our queue and this circuit is used for a
     * tunneled directory request, possibly advance its state. */
    if (queue->n == 0 && TO_CONN(conn)->dirreq_id)
      geoip_change_dirreq_state(TO_CONN(conn)->dirreq_id,
                                DIRREQ_TUNNELED,
                                DIRREQ_CIRC_QUEUE_FLUSHED);

    connection_write_to_buf(cell->body, CELL_NETWORK_SIZE, TO_CONN(conn));

    packed_cell_free_unchecked(cell);
    ++n_flushed;
    if (cell_ewma) {
      cell_ewma_t *tmp;
      cell_ewma->cell_count += ewma_increment;
      /* We pop and re-add the cell_ewma_t here, not above, since we need to
       * re-add it immediately to keep the priority queue consistent with
       * the linked-list implementation */
      tmp = pop_first_cell_ewma_from_conn(conn);
      tor_assert(tmp == cell_ewma);
      add_cell_ewma_to_conn(conn, cell_ewma);
    }
    if (!ewma_enabled && circ != conn->active_circuits) {
      /* If this happens, the current circuit just got made inactive by
       * a call in connection_write_to_buf().  That's nothing to worry about:
       * circuit_make_inactive_on_conn() already advanced conn->active_circuits
       * for us.
       */
      assert_active_circuits_ok_paranoid(conn);
      goto done;
    }
  }
  tor_assert(*next_circ_on_conn_p(circ,conn));
  assert_active_circuits_ok_paranoid(conn);
  conn->active_circuits = *next_circ_on_conn_p(circ, conn);

  /* Is the cell queue low enough to unblock all the streams that are waiting
   * to write to this circuit? */
  if (streams_blocked && queue->n <= CELL_QUEUE_LOWWATER_SIZE)
    set_streams_blocked_on_circ(circ, conn, 0, 0); /* unblock streams */

  /* Did we just run out of cells on this circuit's queue? */
  if (queue->n == 0) {
    log_debug(LD_GENERAL, "Made a circuit inactive.");
    make_circuit_inactive_on_conn(circ, conn);
  }
 done:
  if (n_flushed)
    conn->timestamp_last_added_nonpadding = now;
  return n_flushed;
}

/** Add <b>cell</b> to the queue of <b>circ</b> writing to <b>orconn</b>
 * transmitting in <b>direction</b>. */
void
append_cell_to_circuit_queue(circuit_t *circ, or_connection_t *orconn,
                             cell_t *cell, cell_direction_t direction,
                             streamid_t fromstream)
{
  or_circuit_t *orcirc = NULL;
  cell_queue_t *queue;
  int streams_blocked;

  if (circ->marked_for_close)
    return;

  if (direction == CELL_DIRECTION_OUT) {
    queue = &circ->n_conn_cells;
    streams_blocked = circ->streams_blocked_on_n_conn;
  } else {
    orcirc = TO_OR_CIRCUIT(circ);
    queue = &orcirc->p_conn_cells;
    streams_blocked = circ->streams_blocked_on_p_conn;
  }

  /*
   * Disabling this for now because of a possible guard discovery attack
   */
#if 0
  /* Are we a middle circuit about to exceed ORCIRC_MAX_MIDDLE_CELLS? */
  if ((circ->n_conn != NULL) && CIRCUIT_IS_ORCIRC(circ)) {
    orcirc = TO_OR_CIRCUIT(circ);
    if (orcirc->p_conn) {
      if (queue->n + 1 >= ORCIRC_MAX_MIDDLE_CELLS) {
        /* Queueing this cell would put queue over the cap */
        log_warn(LD_CIRC,
                 "Got a cell exceeding the cap of %u in the %s direction "
                 "on middle circ ID %u; killing the circuit.",
                 ORCIRC_MAX_MIDDLE_CELLS,
                 (direction == CELL_DIRECTION_OUT) ? "n" : "p",
                 (direction == CELL_DIRECTION_OUT) ?
                    circ->n_circ_id : orcirc->p_circ_id);
        circuit_mark_for_close(circ, END_CIRC_REASON_RESOURCELIMIT);
        return;
      }
    }
  }
#endif

  cell_queue_append_packed_copy(queue, cell);

  if (PREDICT_UNLIKELY(cell_queues_check_size())) {
    /* We ran the OOM handler */
    if (circ->marked_for_close)
      return;
  }

  /* If we have too many cells on the circuit, we should stop reading from
   * the edge streams for a while. */
  if (!streams_blocked && queue->n >= CELL_QUEUE_HIGHWATER_SIZE)
    set_streams_blocked_on_circ(circ, orconn, 1, 0); /* block streams */

  if (streams_blocked && fromstream) {
    /* This edge connection is apparently not blocked; block it. */
    set_streams_blocked_on_circ(circ, orconn, 1, fromstream);
  }

  if (queue->n == 1) {
    /* This was the first cell added to the queue.  We need to make this
     * circuit active. */
    log_debug(LD_GENERAL, "Made a circuit active.");
    make_circuit_active_on_conn(circ, orconn);
  }

  if (! connection_get_outbuf_len(TO_CONN(orconn))) {
    /* There is no data at all waiting to be sent on the outbuf.  Add a
     * cell, so that we can notice when it gets flushed, flushed_some can
     * get called, and we can start putting more data onto the buffer then.
     */
    log_debug(LD_GENERAL, "Primed a buffer.");
    connection_or_flush_from_first_active_circuit(orconn, 1, approx_time());
  }
}

/** Append an encoded value of <b>addr</b> to <b>payload_out</b>, which must
 * have at least 18 bytes of free space.  The encoding is, as specified in
 * tor-spec.txt:
 *   RESOLVED_TYPE_IPV4 or RESOLVED_TYPE_IPV6  [1 byte]
 *   LENGTH                                    [1 byte]
 *   ADDRESS                                   [length bytes]
 * Return the number of bytes added, or -1 on error */
int
append_address_to_payload(uint8_t *payload_out, const tor_addr_t *addr)
{
  uint32_t a;
  switch (tor_addr_family(addr)) {
  case AF_INET:
    payload_out[0] = RESOLVED_TYPE_IPV4;
    payload_out[1] = 4;
    a = tor_addr_to_ipv4n(addr);
    memcpy(payload_out+2, &a, 4);
    return 6;
  case AF_INET6:
    payload_out[0] = RESOLVED_TYPE_IPV6;
    payload_out[1] = 16;
    memcpy(payload_out+2, tor_addr_to_in6_addr8(addr), 16);
    return 18;
  case AF_UNSPEC:
  default:
    return -1;
  }
}

/** Given <b>payload_len</b> bytes at <b>payload</b>, starting with an address
 * encoded as by append_address_to_payload(), try to decode the address into
 * *<b>addr_out</b>.  Return the next byte in the payload after the address on
 * success, or NULL on failure. */
const uint8_t *
decode_address_from_payload(tor_addr_t *addr_out, const uint8_t *payload,
                            int payload_len)
{
  if (payload_len < 2)
    return NULL;
  if (payload_len < 2+payload[1])
    return NULL;

  switch (payload[0]) {
  case RESOLVED_TYPE_IPV4:
    if (payload[1] != 4)
      return NULL;
    tor_addr_from_ipv4n(addr_out, get_uint32(payload+2));
    break;
  case RESOLVED_TYPE_IPV6:
    if (payload[1] != 16)
      return NULL;
    tor_addr_from_ipv6_bytes(addr_out, (char*)(payload+2));
    break;
  default:
    tor_addr_make_unspec(addr_out);
    break;
  }
  return payload + 2 + payload[1];
}

/** Remove all the cells queued on <b>circ</b> for <b>orconn</b>. */
void
circuit_clear_cell_queue(circuit_t *circ, or_connection_t *orconn)
{
  cell_queue_t *queue;
  if (circ->n_conn == orconn) {
    queue = &circ->n_conn_cells;
  } else {
    or_circuit_t *orcirc = TO_OR_CIRCUIT(circ);
    tor_assert(orcirc->p_conn == orconn);
    queue = &orcirc->p_conn_cells;
  }

  if (queue->n)
    make_circuit_inactive_on_conn(circ,orconn);

  cell_queue_clear(queue);
}

/** Fail with an assert if the active circuits ring on <b>orconn</b> is
 * corrupt.  */
void
assert_active_circuits_ok(or_connection_t *orconn)
{
  circuit_t *head = orconn->active_circuits;
  circuit_t *cur = head;
  int n = 0;
  if (! head)
    return;
  do {
    circuit_t *next = *next_circ_on_conn_p(cur, orconn);
    circuit_t *prev = *prev_circ_on_conn_p(cur, orconn);
    cell_ewma_t *ewma;
    tor_assert(next);
    tor_assert(prev);
    tor_assert(*next_circ_on_conn_p(prev, orconn) == cur);
    tor_assert(*prev_circ_on_conn_p(next, orconn) == cur);
    if (orconn == cur->n_conn) {
      ewma = &cur->n_cell_ewma;
      tor_assert(!ewma->is_for_p_conn);
    } else {
      ewma = &TO_OR_CIRCUIT(cur)->p_cell_ewma;
      tor_assert(ewma->is_for_p_conn);
    }
    tor_assert(ewma->heap_index != -1);
    tor_assert(ewma == smartlist_get(orconn->active_circuit_pqueue,
                                     ewma->heap_index));
    n++;
    cur = next;
  } while (cur != head);

  tor_assert(n == smartlist_len(orconn->active_circuit_pqueue));
}

/** Return 1 if we shouldn't restart reading on this circuit, even if
 * we get a SENDME.  Else return 0.
*/
static int
circuit_queue_streams_are_blocked(circuit_t *circ)
{
  if (CIRCUIT_IS_ORIGIN(circ)) {
    return circ->streams_blocked_on_n_conn;
  } else {
    return circ->streams_blocked_on_p_conn;
  }
}

