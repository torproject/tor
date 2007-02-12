/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2007, Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char relay_c_id[] =
  "$Id$";

/**
 * \file relay.c
 * \brief Handle relay cell encryption/decryption, plus packaging and
 * receiving from circuits.
 **/

#include "or.h"

static int relay_crypt(circuit_t *circ, cell_t *cell, int cell_direction,
                crypt_path_t **layer_hint, char *recognized);
static edge_connection_t *relay_lookup_conn(circuit_t *circ, cell_t *cell,
                                       int cell_direction);

static int
connection_edge_process_relay_cell(cell_t *cell, circuit_t *circ,
                                   edge_connection_t *conn,
                                   crypt_path_t *layer_hint);
static void
circuit_consider_sending_sendme(circuit_t *circ, crypt_path_t *layer_hint);
static void
circuit_resume_edge_reading(circuit_t *circ, crypt_path_t *layer_hint);
static int
circuit_resume_edge_reading_helper(edge_connection_t *conn,
                                   circuit_t *circ,
                                   crypt_path_t *layer_hint);
static int
circuit_consider_stop_edge_reading(circuit_t *circ, crypt_path_t *layer_hint);

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
relay_set_digest(crypto_digest_env_t *digest, cell_t *cell)
{
  char integrity[4];
  relay_header_t rh;

  crypto_digest_add_bytes(digest, cell->payload, CELL_PAYLOAD_SIZE);
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
relay_digest_matches(crypto_digest_env_t *digest, cell_t *cell)
{
  char received_integrity[4], calculated_integrity[4];
  relay_header_t rh;
  crypto_digest_env_t *backup_digest=NULL;

  backup_digest = crypto_digest_dup(digest);

  relay_header_unpack(&rh, cell->payload);
  memcpy(received_integrity, rh.integrity, 4);
  memset(rh.integrity, 0, 4);
  relay_header_pack(cell->payload, &rh);

//  log_fn(LOG_DEBUG,"Reading digest of %u %u %u %u from relay cell.",
//    received_integrity[0], received_integrity[1],
//    received_integrity[2], received_integrity[3]);

  crypto_digest_add_bytes(digest, cell->payload, CELL_PAYLOAD_SIZE);
  crypto_digest_get_digest(digest, calculated_integrity, 4);

  if (memcmp(received_integrity, calculated_integrity, 4)) {
//    log_fn(LOG_INFO,"Recognized=0 but bad digest. Not recognizing.");
// (%d vs %d).", received_integrity, calculated_integrity);
    /* restore digest to its old form */
    crypto_digest_assign(digest, backup_digest);
    /* restore the relay header */
    memcpy(rh.integrity, received_integrity, 4);
    relay_header_pack(cell->payload, &rh);
    crypto_free_digest_env(backup_digest);
    return 0;
  }
  crypto_free_digest_env(backup_digest);
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
relay_crypt_one_payload(crypto_cipher_env_t *cipher, char *in,
                        int encrypt_mode)
{
  char out[CELL_PAYLOAD_SIZE]; /* 'in' must be this size too */
  int r;

  if (encrypt_mode)
    r = crypto_cipher_encrypt(cipher, out, in, CELL_PAYLOAD_SIZE);
  else
    r = crypto_cipher_decrypt(cipher, out, in, CELL_PAYLOAD_SIZE);

  if (r) {
    log_warn(LD_BUG,"Error during relay encryption");
    return -1;
  }
  memcpy(in,out,CELL_PAYLOAD_SIZE);
  return 0;
}

/** Receive a relay cell:
 *  - Crypt it (encrypt APward, decrypt at AP, decrypt exitward).
 *  - Check if recognized (if exitward).
 *  - If recognized and the digest checks out, then find if there's
 *    a conn that the cell is intended for, and deliver it to
 *    connection_edge.
 *  - Else connection_or_write_cell_to_buf to the conn on the other
 *    side of the circuit.
 *
 * Return -reason on failure.
 */
int
circuit_receive_relay_cell(cell_t *cell, circuit_t *circ, int cell_direction)
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
    edge_connection_t *conn = relay_lookup_conn(circ, cell, cell_direction);
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
  ++stats_n_relay_cells_relayed;
  connection_or_write_cell_to_buf(cell, or_conn);
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
static int
relay_crypt(circuit_t *circ, cell_t *cell, int cell_direction,
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
 *  - connection_or_write_cell_to_buf to the right conn
 */
static int
circuit_package_relay_cell(cell_t *cell, circuit_t *circ,
                           int cell_direction,
                           crypt_path_t *layer_hint)
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
      /* XXXX RD This is a bug, right? */
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
  connection_or_write_cell_to_buf(cell, conn);
  return 0;
}

/** If cell's stream_id matches the stream_id of any conn that's
 * attached to circ, return that conn, else return NULL.
 */
static edge_connection_t *
relay_lookup_conn(circuit_t *circ, cell_t *cell, int cell_direction)
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
          !tmpconn->_base.marked_for_close) {
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
relay_header_pack(char *dest, const relay_header_t *src)
{
  *(uint8_t*)(dest) = src->command;

  set_uint16(dest+1, htons(src->recognized));
  set_uint16(dest+3, htons(src->stream_id));
  memcpy(dest+5, src->integrity, 4);
  set_uint16(dest+9, htons(src->length));
}

/** Unpack the network-order buffer <b>src</b> into a host-order
 * relay_header_t structure <b>dest</b>.
 */
void
relay_header_unpack(relay_header_t *dest, const char *src)
{
  dest->command = *(uint8_t*)(src);

  dest->recognized = ntohs(get_uint16(src+1));
  dest->stream_id = ntohs(get_uint16(src+3));
  memcpy(dest->integrity, src+5, 4);
  dest->length = ntohs(get_uint16(src+9));
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
relay_send_command_from_edge(uint16_t stream_id, circuit_t *circ,
                             int relay_command, const char *payload,
                             size_t payload_len, crypt_path_t *cpath_layer)
{
  cell_t cell;
  relay_header_t rh;
  int cell_direction;
  /* XXXX NM Split this function into a separate versions per circuit type? */

  tor_assert(circ);

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
  if (payload_len) {
    tor_assert(payload_len <= RELAY_PAYLOAD_SIZE);
    memcpy(cell.payload+RELAY_HEADER_SIZE, payload, payload_len);
  }

  log_debug(LD_OR,"delivering %d cell %s.", relay_command,
            cell_direction == CELL_DIRECTION_OUT ? "forward" : "backward");

  if (circuit_package_relay_cell(&cell, circ, cell_direction, cpath_layer)
      < 0) {
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
connection_edge_send_command(edge_connection_t *fromconn, circuit_t *circ,
                             int relay_command, const char *payload,
                             size_t payload_len, crypt_path_t *cpath_layer)
{
  /* XXXX NM Split this function into a separate versions per circuit type? */

  if (fromconn && fromconn->_base.marked_for_close) {
    log_warn(LD_BUG,
             "Bug: called on conn that's already marked for close at %s:%d.",
             fromconn->_base.marked_for_close_file,
             fromconn->_base.marked_for_close);
    return 0;
  }

  if (!circ) {
    tor_assert(fromconn);
    if (fromconn->_base.type == CONN_TYPE_AP) {
      log_info(LD_APP,"no circ. Closing conn.");
      connection_mark_unattached_ap(fromconn, END_STREAM_REASON_INTERNAL);
    } else {
      log_info(LD_EXIT,"no circ. Closing conn.");
      fromconn->_base.edge_has_sent_end = 1; /* no circ to send to */
      fromconn->end_reason = END_STREAM_REASON_INTERNAL;
      connection_mark_for_close(TO_CONN(fromconn));
    }
    return -1;
  }

  return relay_send_command_from_edge(fromconn ? fromconn->stream_id : 0,
                                      circ, relay_command, payload,
                                      payload_len, cpath_layer);
}

/** Translate <b>reason</b>, which came from a relay 'end' cell,
 * into a static const string describing why the stream is closing.
 * <b>reason</b> is -1 if no reason was provided.
 */
static const char *
connection_edge_end_reason_str(int reason)
{
  switch (reason) {
    case -1:
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
             "End cell arrived with length 0. Should be at least 1.");
      return "MALFORMED";
    case END_STREAM_REASON_MISC:           return "misc error";
    case END_STREAM_REASON_RESOLVEFAILED:  return "resolve failed";
    case END_STREAM_REASON_CONNECTREFUSED: return "connection refused";
    case END_STREAM_REASON_EXITPOLICY:     return "exit policy failed";
    case END_STREAM_REASON_DESTROY:        return "destroyed";
    case END_STREAM_REASON_DONE:           return "closed normally";
    case END_STREAM_REASON_TIMEOUT:        return "gave up (timeout)";
    case END_STREAM_REASON_HIBERNATING:    return "server is hibernating";
    case END_STREAM_REASON_INTERNAL:       return "internal error at server";
    case END_STREAM_REASON_RESOURCELIMIT:  return "server out of resources";
    case END_STREAM_REASON_CONNRESET:      return "connection reset";
    case END_STREAM_REASON_TORPROTOCOL:    return "Tor protocol error";
    case END_STREAM_REASON_NOTDIRECTORY:   return "not a directory";
    default:
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
             "Reason for ending (%d) not recognized.",reason);
      return "unknown";
  }
}

/** Translate <b>reason</b> (as from a relay 'end' cell) into an
 * appropriate SOCKS5 reply code.
 * DODCDOC 0
 */
socks5_reply_status_t
connection_edge_end_reason_socks5_response(int reason)
{
  switch (reason & END_STREAM_REASON_MASK) {
    case 0:
      return SOCKS5_SUCCEEDED;
    case END_STREAM_REASON_MISC:
      return SOCKS5_GENERAL_ERROR;
    case END_STREAM_REASON_RESOLVEFAILED:
      return SOCKS5_HOST_UNREACHABLE;
    case END_STREAM_REASON_CONNECTREFUSED:
      return SOCKS5_CONNECTION_REFUSED;
    case END_STREAM_REASON_EXITPOLICY:
      return SOCKS5_NOT_ALLOWED;
    case END_STREAM_REASON_DESTROY:
      return SOCKS5_GENERAL_ERROR;
    case END_STREAM_REASON_DONE:
      return SOCKS5_SUCCEEDED;
    case END_STREAM_REASON_TIMEOUT:
      return SOCKS5_TTL_EXPIRED;
    case END_STREAM_REASON_RESOURCELIMIT:
      return SOCKS5_GENERAL_ERROR;
    case END_STREAM_REASON_HIBERNATING:
      return SOCKS5_GENERAL_ERROR;
    case END_STREAM_REASON_INTERNAL:
      return SOCKS5_GENERAL_ERROR;
    case END_STREAM_REASON_CONNRESET:
      return SOCKS5_CONNECTION_REFUSED;
    case END_STREAM_REASON_TORPROTOCOL:
      return SOCKS5_GENERAL_ERROR;

    case END_STREAM_REASON_CANT_ATTACH:
      return SOCKS5_GENERAL_ERROR;
    case END_STREAM_REASON_NET_UNREACHABLE:
      return SOCKS5_NET_UNREACHABLE;
    case END_STREAM_REASON_SOCKSPROTOCOL:
      return SOCKS5_GENERAL_ERROR;
    default:
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
             "Reason for ending (%d) not recognized; "
             "sending generic socks error.", reason);
      return SOCKS5_GENERAL_ERROR;
  }
}

/* We need to use a few macros to deal with the fact that Windows
 * decided that their sockets interface should be a permakludge.
 * E_CASE is for errors where windows has both a EFOO and a WSAEFOO
 * version, and S_CASE is for errors where windows has only a WSAEFOO
 * version.  (The E is for 'error', the S is for 'socket'). */
#ifdef MS_WINDOWS
#define E_CASE(s) case s: case WSA ## s
#define S_CASE(s) case WSA ## s
#else
#define E_CASE(s) case s
#define S_CASE(s) case s
#endif

/** Given an errno from a failed exit connection, return a reason code
 * appropriate for use in a RELAY END cell.
 */
int
errno_to_end_reason(int e)
{
  switch (e) {
    case EPIPE:
      return END_STREAM_REASON_DONE;
    E_CASE(EBADF):
    E_CASE(EFAULT):
    E_CASE(EINVAL):
    S_CASE(EISCONN):
    S_CASE(ENOTSOCK):
    S_CASE(EPROTONOSUPPORT):
    S_CASE(EAFNOSUPPORT):
    E_CASE(EACCES):
    S_CASE(ENOTCONN):
    S_CASE(ENETUNREACH):
      return END_STREAM_REASON_INTERNAL;
    S_CASE(ECONNREFUSED):
      return END_STREAM_REASON_CONNECTREFUSED;
    S_CASE(ECONNRESET):
      return END_STREAM_REASON_CONNRESET;
    S_CASE(ETIMEDOUT):
      return END_STREAM_REASON_TIMEOUT;
    S_CASE(ENOBUFS):
    case ENOMEM:
    case ENFILE:
    E_CASE(EMFILE):
      return END_STREAM_REASON_RESOURCELIMIT;
    default:
      log_info(LD_EXIT, "Didn't recognize errno %d (%s); telling the client "
               "that we are ending a stream for 'misc' reason.",
               e, tor_socket_strerror(e));
      return END_STREAM_REASON_MISC;
  }
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
         reason == END_STREAM_REASON_MISC;
}

/** Called when we receive an END cell on a stream that isn't open yet.
 * Arguments are as for connection_edge_process_relay_cell().
 */
static int
connection_edge_process_end_not_open(
    relay_header_t *rh, cell_t *cell, origin_circuit_t *circ,
    edge_connection_t *conn, crypt_path_t *layer_hint)
{
  struct in_addr in;
  routerinfo_t *exitrouter;
  int reason = *(cell->payload+RELAY_HEADER_SIZE);
  int control_reason = reason | END_STREAM_REASON_FLAG_REMOTE;
  (void) layer_hint; /* unused */

  if (rh->length > 0 && edge_reason_is_retriable(reason) &&
      conn->_base.type == CONN_TYPE_AP) {
    log_info(LD_APP,"Address '%s' refused due to '%s'. Considering retrying.",
             safe_str(conn->socks_request->address),
             connection_edge_end_reason_str(reason));
    exitrouter =
      router_get_by_digest(circ->build_state->chosen_exit->identity_digest);
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
          client_dns_set_addressmap(conn->socks_request->address, addr,
                                    conn->chosen_exit_name, ttl);
        }
        /* check if he *ought* to have allowed it */
        if (exitrouter &&
            (rh->length < 5 ||
             (tor_inet_aton(conn->socks_request->address, &in) &&
              !conn->chosen_exit_name))) {
          log_notice(LD_APP,
                 "Exitrouter '%s' seems to be more restrictive than its exit "
                 "policy. Not using this router as exit for now.",
                 exitrouter->nickname);
          addr_policy_free(exitrouter->exit_policy);
          exitrouter->exit_policy =
            router_parse_addr_policy_from_string("reject *:*", -1);
        }
        /* rewrite it to an IP if we learned one. */
        if (addressmap_rewrite(conn->socks_request->address,
                               sizeof(conn->socks_request->address))) {
          control_event_stream_status(conn, STREAM_EVENT_REMAP, 0);
        }
        if (conn->_base.chosen_exit_optional) {
          /* stop wanting a specific exit */
          conn->_base.chosen_exit_optional = 0;
          tor_free(conn->chosen_exit_name); /* clears it */
        }
        if (connection_ap_detach_retriable(conn, circ, control_reason) >= 0)
          return 0;
        /* else, conn will get closed below */
        break;
      case END_STREAM_REASON_CONNECTREFUSED:
        if (!conn->_base.chosen_exit_optional)
          break; /* break means it'll close, below */
        /* Else fall through: expire this circuit, clear the
         * chosen_exit_name field, and try again. */
      case END_STREAM_REASON_RESOLVEFAILED:
      case END_STREAM_REASON_TIMEOUT:
      case END_STREAM_REASON_MISC:
        if (client_dns_incr_failures(conn->socks_request->address)
            < MAX_RESOLVE_FAILURES) {
          /* We haven't retried too many times; reattach the connection. */
          circuit_log_path(LOG_INFO,LD_APP,circ);
          tor_assert(circ->_base.timestamp_dirty);
          circ->_base.timestamp_dirty -= get_options()->MaxCircuitDirtiness;

          if (conn->_base.chosen_exit_optional) {
            /* stop wanting a specific exit */
            conn->_base.chosen_exit_optional = 0;
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
          addr_policy_free(exitrouter->exit_policy);
          exitrouter->exit_policy =
            router_parse_addr_policy_from_string("reject *:*", -1);
        }
        if (conn->_base.chosen_exit_optional) {
          /* stop wanting a specific exit */
          conn->_base.chosen_exit_optional = 0;
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
       connection_edge_end_reason_str(rh->length > 0 ? reason : -1));
  if (conn->_base.type == CONN_TYPE_AP) {
    circuit_log_path(LOG_INFO,LD_APP,circ);
    connection_mark_unattached_ap(conn, control_reason);
  } else {
    /* we just got an 'end', don't need to send one */
    conn->_base.edge_has_sent_end = 1;
    conn->end_reason = control_reason;
    connection_mark_for_close(TO_CONN(conn));
  }
  return 0;
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
    if (CIRCUIT_IS_ORIGIN(circ))
      return connection_edge_process_end_not_open(rh, cell,
                                                 TO_ORIGIN_CIRCUIT(circ), conn,
                                                 layer_hint);
    else
      return 0;
  }

  if (conn->_base.type == CONN_TYPE_AP &&
      rh->command == RELAY_COMMAND_CONNECTED) {
    tor_assert(CIRCUIT_IS_ORIGIN(circ));
    if (conn->_base.state != AP_CONN_STATE_CONNECT_WAIT) {
      log_fn(LOG_PROTOCOL_WARN, LD_APP,
             "Got 'connected' while not in state connect_wait. Dropping.");
      return 0;
    }
//    log_fn(LOG_INFO,"Connected! Notifying application.");
    conn->_base.state = AP_CONN_STATE_OPEN;
    log_info(LD_APP,"'connected' received after %d seconds.",
             (int)(time(NULL) - conn->_base.timestamp_lastread));
    if (rh->length >= 4) {
      uint32_t addr = ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE));
      int ttl;
      if (!addr) {
        log_info(LD_APP,
                 "...but it claims the IP address was 0.0.0.0. Closing.");
        connection_edge_end(conn, END_STREAM_REASON_TORPROTOCOL,
                            conn->cpath_layer);
        connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
        return 0;
      }
      if (rh->length >= 8)
        ttl = (int)ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE+4));
      else
        ttl = -1;
      client_dns_set_addressmap(conn->socks_request->address, addr,
                                conn->chosen_exit_name, ttl);
    }
    circuit_log_path(LOG_INFO,LD_APP,TO_ORIGIN_CIRCUIT(circ));
    /* don't send a socks reply to transparent conns */
    if (!conn->socks_request->has_finished)
      connection_ap_handshake_socks_reply(conn, NULL, 0, 0);
    /* handle anything that might have queued */
    if (connection_edge_package_raw_inbuf(conn, 1) < 0) {
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
    if (conn->_base.state != AP_CONN_STATE_RESOLVE_WAIT) {
      log_fn(LOG_PROTOCOL_WARN, LD_APP, "Got a 'resolved' cell while "
             "not in state resolve_wait. Dropping.");
      return 0;
    }
    tor_assert(SOCKS_COMMAND_IS_RESOLVE(conn->socks_request->command));
    answer_len = cell->payload[RELAY_HEADER_SIZE+1];
    if (rh->length < 2 || answer_len+2>rh->length) {
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
             "Dropping malformed 'resolved' cell");
      connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
      return 0;
    }
    if (rh->length >= answer_len+6)
      ttl = (int)ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE+
                                  2+answer_len));
    else
      ttl = -1;
    connection_ap_handshake_socks_resolved(conn,
                   cell->payload[RELAY_HEADER_SIZE], /*answer_type*/
                   cell->payload[RELAY_HEADER_SIZE+1], /*answer_len*/
                   cell->payload+RELAY_HEADER_SIZE+2, /*answer*/
                   ttl);
    connection_mark_unattached_ap(conn,
                              END_STREAM_REASON_DONE |
                              END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
    return 0;
  }

  log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
         "Got an unexpected relay command %d, in state %d (%s). Dropping.",
         rh->command, conn->_base.state,
         conn_state_to_string(conn->_base.type, conn->_base.state));
  return 0; /* for forward compatibility, don't kill the circuit */
//  connection_edge_end(conn, END_STREAM_REASON_TORPROTOCOL,
//                      conn->cpath_layer);
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

  tor_assert(cell);
  tor_assert(circ);

  relay_header_unpack(&rh, cell->payload);
//  log_fn(LOG_DEBUG,"command %d stream %d", rh.command, rh.stream_id);
  num_seen++;
  log_debug(domain, "Now seen %d relay cells here.", num_seen);

  if (rh.length > RELAY_PAYLOAD_SIZE) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Relay cell length field too long. Closing circuit.");
    return - END_CIRC_REASON_TORPROTOCOL;
  }

  /* either conn is NULL, in which case we've got a control cell, or else
   * conn points to the recognized stream. */

  if (conn && !connection_state_is_open(TO_CONN(conn)))
    return connection_edge_process_relay_cell_not_open(
             &rh, cell, circ, conn, layer_hint);

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
      if (conn) {
        log_fn(LOG_PROTOCOL_WARN, domain,
               "Begin cell for known stream. Dropping.");
        return 0;
      }
      return connection_exit_begin_conn(cell, circ);
    case RELAY_COMMAND_DATA:
      ++stats_n_data_cells_received;
      if (( layer_hint && --layer_hint->deliver_window < 0) ||
          (!layer_hint && --circ->deliver_window < 0)) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "(relay data) circ deliver_window below 0. Killing.");
        connection_edge_end(conn, END_STREAM_REASON_TORPROTOCOL,
                            conn->cpath_layer);
        connection_mark_for_close(TO_CONN(conn));
        return -END_CIRC_REASON_TORPROTOCOL;
      }
      log_debug(domain,"circ deliver_window now %d.", layer_hint ?
                layer_hint->deliver_window : circ->deliver_window);

      circuit_consider_sending_sendme(circ, layer_hint);

      if (!conn) {
        log_info(domain,"data cell dropped, unknown stream.");
        return 0;
      }

      if (--conn->deliver_window < 0) { /* is it below 0 after decrement? */
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "(relay data) conn deliver_window below 0. Killing.");
        return -END_CIRC_REASON_TORPROTOCOL;
      }

      stats_n_data_bytes_received += rh.length;
      connection_write_to_buf(cell->payload + RELAY_HEADER_SIZE,
                              rh.length, TO_CONN(conn));
      connection_edge_consider_sending_sendme(conn);
      return 0;
    case RELAY_COMMAND_END:
      reason = rh.length > 0 ?
        *(uint8_t *)(cell->payload+RELAY_HEADER_SIZE) : END_STREAM_REASON_MISC;
      if (!conn) {
        log_info(domain,"end cell (%s) dropped, unknown stream.",
                 connection_edge_end_reason_str(reason));
        return 0;
      }
/* XXX add to this log_fn the exit node's nickname? */
      log_info(domain,"%d: end cell (%s) for stream %d. Removing stream.",
               conn->_base.s,
               connection_edge_end_reason_str(reason),
               conn->stream_id);
      if (conn->socks_request && !conn->socks_request->has_finished)
        log_warn(LD_BUG,
                 "Bug: open stream hasn't sent socks answer yet? Closing.");
      /* We just *got* an end; no reason to send one. */
      conn->_base.edge_has_sent_end = 1;
      if (!conn->end_reason)
        conn->end_reason = reason | END_STREAM_REASON_FLAG_REMOTE;
      if (!conn->_base.marked_for_close) {
        /* only mark it if not already marked. it's possible to
         * get the 'end' right around when the client hangs up on us. */
        connection_mark_for_close(TO_CONN(conn));
        conn->_base.hold_open_until_flushed = 1;
      }
      return 0;
    case RELAY_COMMAND_EXTEND:
      if (conn) {
        log_fn(LOG_PROTOCOL_WARN, domain,
               "'extend' cell received for non-zero stream. Dropping.");
        return 0;
      }
      return circuit_extend(cell, circ);
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
        uint8_t reason = *(uint8_t*)(cell->payload + RELAY_HEADER_SIZE);
        connection_or_send_destroy(circ->n_circ_id, circ->n_conn, reason);
        circuit_set_n_circid_orconn(circ, 0, NULL);
      }
      log_debug(LD_EXIT, "Processed 'truncate', replying.");
      {
        char payload[1];
        payload[0] = (char)END_CIRC_REASON_REQUESTED;
        connection_edge_send_command(NULL, circ, RELAY_COMMAND_TRUNCATED,
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
      if (!conn) {
        if (layer_hint) {
          layer_hint->package_window += CIRCWINDOW_INCREMENT;
          log_debug(LD_APP,"circ-level sendme at origin, packagewindow %d.",
                    layer_hint->package_window);
          circuit_resume_edge_reading(circ, layer_hint);
        } else {
          circ->package_window += CIRCWINDOW_INCREMENT;
          log_debug(LD_APP,
                    "circ-level sendme at non-origin, packagewindow %d.",
                    circ->package_window);
          circuit_resume_edge_reading(circ, layer_hint);
        }
        return 0;
      }
      conn->package_window += STREAMWINDOW_INCREMENT;
      log_debug(domain,"stream-level sendme, packagewindow now %d.",
                conn->package_window);
      connection_start_reading(TO_CONN(conn));
      /* handle whatever might still be on the inbuf */
      if (connection_edge_package_raw_inbuf(conn, 1) < 0) {
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
      rend_process_relay_cell(circ, rh.command, rh.length,
                              cell->payload+RELAY_HEADER_SIZE);
      return 0;
  }
  log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
         "Received unknown relay command %d. Perhaps the other side is using "
         "a newer version of Tor? Dropping.",
         rh.command);
  return 0; /* for forward compatibility, don't kill the circuit */
}

uint64_t stats_n_data_cells_packaged = 0;
uint64_t stats_n_data_bytes_packaged = 0;
uint64_t stats_n_data_cells_received = 0;
uint64_t stats_n_data_bytes_received = 0;

/** While conn->inbuf has an entire relay payload of bytes on it,
 * and the appropriate package windows aren't empty, grab a cell
 * and send it down the circuit.
 *
 * Return -1 (and send a RELAY_END cell if necessary) if conn should
 * be marked for close, else return 0.
 */
int
connection_edge_package_raw_inbuf(edge_connection_t *conn, int package_partial)
{
  size_t amount_to_process, length;
  char payload[CELL_PAYLOAD_SIZE];
  circuit_t *circ;
  unsigned domain = conn->cpath_layer ? LD_APP : LD_EXIT;

  tor_assert(conn);

  if (conn->_base.marked_for_close) {
    log_warn(LD_BUG,
             "Bug: called on conn that's already marked for close at %s:%d.",
             conn->_base.marked_for_close_file, conn->_base.marked_for_close);
    return 0;
  }

repeat_connection_edge_package_raw_inbuf:

  circ = circuit_get_by_edge_conn(conn);
  if (!circ) {
    log_info(domain,"conn has no circuit! Closing.");
    conn->end_reason = END_STREAM_REASON_CANT_ATTACH;
    return -1;
  }

  if (circuit_consider_stop_edge_reading(circ, conn->cpath_layer))
    return 0;

  if (conn->package_window <= 0) {
    log_info(domain,"called with package_window %d. Skipping.",
             conn->package_window);
    connection_stop_reading(TO_CONN(conn));
    return 0;
  }

  amount_to_process = buf_datalen(conn->_base.inbuf);

  if (!amount_to_process)
    return 0;

  if (!package_partial && amount_to_process < RELAY_PAYLOAD_SIZE)
    return 0;

  if (amount_to_process > RELAY_PAYLOAD_SIZE) {
    length = RELAY_PAYLOAD_SIZE;
  } else {
    length = amount_to_process;
  }
  stats_n_data_bytes_packaged += length;
  stats_n_data_cells_packaged += 1;

  connection_fetch_from_buf(payload, length, TO_CONN(conn));

  log_debug(domain,"(%d) Packaging %d bytes (%d waiting).", conn->_base.s,
            (int)length, (int)buf_datalen(conn->_base.inbuf));

  if (connection_edge_send_command(conn, circ, RELAY_COMMAND_DATA,
                                   payload, length, conn->cpath_layer) < 0)
    /* circuit got marked for close, don't continue, don't need to mark conn */
    return 0;

  if (!conn->cpath_layer) { /* non-rendezvous exit */
    tor_assert(circ->package_window > 0);
    circ->package_window--;
  } else { /* we're an AP, or an exit on a rendezvous circ */
    tor_assert(conn->cpath_layer->package_window > 0);
    conn->cpath_layer->package_window--;
  }

  if (--conn->package_window <= 0) { /* is it 0 after decrement? */
    connection_stop_reading(TO_CONN(conn));
    log_debug(domain,"conn->package_window reached 0.");
    circuit_consider_stop_edge_reading(circ, conn->cpath_layer);
    return 0; /* don't process the inbuf any more */
  }
  log_debug(domain,"conn->package_window is now %d",conn->package_window);

  /* handle more if there's more, or return 0 if there isn't */
  goto repeat_connection_edge_package_raw_inbuf;
}

/** Called when we've just received a relay data cell, or when
 * we've just finished flushing all bytes to stream <b>conn</b>.
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

  while (conn->deliver_window < STREAMWINDOW_START - STREAMWINDOW_INCREMENT) {
    log_debug(conn->cpath_layer?LD_APP:LD_EXIT,
              "Outbuf %d, Queueing stream sendme.",
              (int)conn->_base.outbuf_flushlen);
    conn->deliver_window += STREAMWINDOW_INCREMENT;
    if (connection_edge_send_command(conn, circ, RELAY_COMMAND_SENDME,
                                     NULL, 0, conn->cpath_layer) < 0) {
      log_warn(LD_APP,"connection_edge_send_command failed. Returning.");
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
circuit_resume_edge_reading_helper(edge_connection_t *conn,
                                   circuit_t *circ,
                                   crypt_path_t *layer_hint)
{
  for ( ; conn; conn=conn->next_stream) {
    if (conn->_base.marked_for_close)
      continue;
    if ((!layer_hint && conn->package_window > 0) ||
        (layer_hint && conn->package_window > 0 &&
         conn->cpath_layer == layer_hint)) {
      connection_start_reading(TO_CONN(conn));
      /* handle whatever might still be on the inbuf */
      if (connection_edge_package_raw_inbuf(conn, 1)<0) {
        /* (We already sent an end cell if possible) */
        connection_mark_for_close(TO_CONN(conn));
        continue;
      }

      /* If the circuit won't accept any more data, return without looking
       * at any more of the streams. Any connections that should be stopped
       * have already been stopped by connection_edge_package_raw_inbuf. */
      if (circuit_consider_stop_edge_reading(circ, layer_hint))
        return -1;
    }
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
         conn=conn->next_stream)
      if (conn->cpath_layer == layer_hint)
        connection_stop_reading(TO_CONN(conn));
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
  while ((layer_hint ? layer_hint->deliver_window : circ->deliver_window) <
          CIRCWINDOW_START - CIRCWINDOW_INCREMENT) {
    log_debug(LD_CIRC,"Queueing circuit sendme.");
    if (layer_hint)
      layer_hint->deliver_window += CIRCWINDOW_INCREMENT;
    else
      circ->deliver_window += CIRCWINDOW_INCREMENT;
    if (connection_edge_send_command(NULL, circ, RELAY_COMMAND_SENDME,
                                     NULL, 0, layer_hint) < 0) {
      log_warn(LD_CIRC,
               "connection_edge_send_command failed. Circuit's closed.");
      return; /* the circuit's closed, don't continue */
    }
  }
}

