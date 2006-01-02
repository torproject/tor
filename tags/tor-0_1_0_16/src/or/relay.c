/* Copyright 2001 Matej Pfajfar.
 * Copyright 2001-2004 Roger Dingledine.
 * Copyright 2004-2005 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char relay_c_id[] = "$Id$";

/**
 * \file relay.c
 * \brief Handle relay cell encryption/decryption, plus packaging and
 * receiving from circuits.
 **/

#include "or.h"

static int relay_crypt(circuit_t *circ, cell_t *cell, int cell_direction,
                crypt_path_t **layer_hint, char *recognized);
static connection_t *relay_lookup_conn(circuit_t *circ, cell_t *cell, int cell_direction);

static int
connection_edge_process_relay_cell(cell_t *cell, circuit_t *circ,
                                   connection_t *conn,
                                   crypt_path_t *layer_hint);
static void
circuit_consider_sending_sendme(circuit_t *circ, crypt_path_t *layer_hint);
static void
circuit_resume_edge_reading(circuit_t *circ, crypt_path_t *layer_hint);
static int
circuit_resume_edge_reading_helper(connection_t *conn,
                                   circuit_t *circ,
                                   crypt_path_t *layer_hint);
static int
circuit_consider_stop_edge_reading(circuit_t *circ, crypt_path_t *layer_hint);

/** Stats: how many relay cells have originated at this hop, or have
 * been relayed onward (not recognized at this hop)?
 */
unsigned long stats_n_relay_cells_relayed = 0;
/** Stats: how many relay cells have been delivered to streams at this
 * hop?
 */
unsigned long stats_n_relay_cells_delivered = 0;

/** Update digest from the payload of cell. Assign integrity part to
 * cell.
 */
static void relay_set_digest(crypto_digest_env_t *digest, cell_t *cell) {
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
static int relay_digest_matches(crypto_digest_env_t *digest, cell_t *cell) {
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
static int relay_crypt_one_payload(crypto_cipher_env_t *cipher, char *in,
                                   int encrypt_mode) {
  char out[CELL_PAYLOAD_SIZE]; /* 'in' must be this size too */

  if (( encrypt_mode && crypto_cipher_encrypt(cipher, out, in, CELL_PAYLOAD_SIZE)) ||
      (!encrypt_mode && crypto_cipher_decrypt(cipher, out, in, CELL_PAYLOAD_SIZE))) {
    log_fn(LOG_WARN,"Error during relay encryption");
    return -1;
  }
  memcpy(in,out,CELL_PAYLOAD_SIZE);
  return 0;
}

/** Receive a relay cell:
 *  - Crypt it (encrypt APward, decrypt at AP, decrypt exitward).
 *  - Check if recognized (if exitward).
 *  - If recognized and the digest checks out, then find if there's
 *    a conn that the cell is intended for, and deliver it to·
 *    connection_edge.
 *  - Else connection_or_write_cell_to_buf to the conn on the other
 *    side of the circuit.
 */
int circuit_receive_relay_cell(cell_t *cell, circuit_t *circ,
                               int cell_direction) {
  connection_t *conn=NULL;
  crypt_path_t *layer_hint=NULL;
  char recognized=0;

  tor_assert(cell);
  tor_assert(circ);
  tor_assert(cell_direction == CELL_DIRECTION_OUT ||
             cell_direction == CELL_DIRECTION_IN);
  if (circ->marked_for_close)
    return 0;

  if (relay_crypt(circ, cell, cell_direction, &layer_hint, &recognized) < 0) {
    log_fn(LOG_WARN,"relay crypt failed. Dropping connection.");
    return -1;
  }

  if (recognized) {
    conn = relay_lookup_conn(circ, cell, cell_direction);
    if (cell_direction == CELL_DIRECTION_OUT) {
      ++stats_n_relay_cells_delivered;
      log_fn(LOG_DEBUG,"Sending away from origin.");
      if (connection_edge_process_relay_cell(cell, circ, conn, NULL) < 0) {
        log_fn(LOG_WARN,"connection_edge_process_relay_cell (away from origin) failed.");
        return -1;
      }
    }
    if (cell_direction == CELL_DIRECTION_IN) {
      ++stats_n_relay_cells_delivered;
      log_fn(LOG_DEBUG,"Sending to origin.");
      if (connection_edge_process_relay_cell(cell, circ, conn, layer_hint) < 0) {
        log_fn(LOG_WARN,"connection_edge_process_relay_cell (at origin) failed.");
        return -1;
      }
    }
    return 0;
  }

  /* not recognized. pass it on. */
  if (cell_direction == CELL_DIRECTION_OUT) {
    cell->circ_id = circ->n_circ_id; /* switch it */
    conn = circ->n_conn;
  } else {
    cell->circ_id = circ->p_circ_id; /* switch it */
    conn = circ->p_conn;
  }

  if (!conn) {
    if (circ->rend_splice && cell_direction == CELL_DIRECTION_OUT) {
      tor_assert(circ->purpose == CIRCUIT_PURPOSE_REND_ESTABLISHED);
      tor_assert(circ->rend_splice->purpose == CIRCUIT_PURPOSE_REND_ESTABLISHED);
      cell->circ_id = circ->rend_splice->p_circ_id;
      if (circuit_receive_relay_cell(cell, circ->rend_splice, CELL_DIRECTION_IN)<0) {
        log_fn(LOG_WARN, "Error relaying cell across rendezvous; closing circuits");
        circuit_mark_for_close(circ); /* XXXX Do this here, or just return -1? */
        return -1;
      }
      return 0;
    }
    log_fn(LOG_WARN,"Didn't recognize cell, but circ stops here! Closing circ.");
    return -1;
  }

  log_fn(LOG_DEBUG,"Passing on unrecognized cell.");
  ++stats_n_relay_cells_relayed;
  connection_or_write_cell_to_buf(cell, conn);
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
/* wrap this into receive_relay_cell one day */
static int relay_crypt(circuit_t *circ, cell_t *cell, int cell_direction,
                       crypt_path_t **layer_hint, char *recognized) {
  crypt_path_t *thishop;
  relay_header_t rh;

  tor_assert(circ);
  tor_assert(cell);
  tor_assert(recognized);
  tor_assert(cell_direction == CELL_DIRECTION_IN ||
             cell_direction == CELL_DIRECTION_OUT);

  if (cell_direction == CELL_DIRECTION_IN) {
    if (CIRCUIT_IS_ORIGIN(circ)) { /* We're at the beginning of the circuit.
                                     We'll want to do layered decrypts. */
      tor_assert(circ->cpath);
      thishop = circ->cpath;
      if (thishop->state != CPATH_STATE_OPEN) {
        log_fn(LOG_WARN,"Relay cell before first created cell? Closing.");
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
      } while (thishop != circ->cpath && thishop->state == CPATH_STATE_OPEN);
      log_fn(LOG_WARN,"in-cell at OP not recognized. Closing.");
      return -1;
    } else { /* we're in the middle. Just one crypt. */
      if (relay_crypt_one_payload(circ->p_crypto, cell->payload, 1) < 0)
        return -1;
//      log_fn(LOG_DEBUG,"Skipping recognized check, because we're not the OP.");
    }
  } else /* cell_direction == CELL_DIRECTION_OUT */ {
    /* we're in the middle. Just one crypt. */

    if (relay_crypt_one_payload(circ->n_crypto, cell->payload, 0) < 0)
      return -1;

    relay_header_unpack(&rh, cell->payload);
    if (rh.recognized == 0) {
      /* it's possibly recognized. have to check digest to be sure. */
      if (relay_digest_matches(circ->n_digest, cell)) {
        *recognized = 1;
        return 0;
      }
    }
  }
  return 0;
}

/** Package a relay cell:
 *  - Encrypt it to the right layer
 *  - connection_or_write_cell_to_buf to the right conn
 */
static int
circuit_package_relay_cell(cell_t *cell, circuit_t *circ,
                           int cell_direction,
                           crypt_path_t *layer_hint)
{
  connection_t *conn; /* where to send the cell */
  crypt_path_t *thishop; /* counter for repeated crypts */

  if (cell_direction == CELL_DIRECTION_OUT) {
    conn = circ->n_conn;
    if (!conn) {
      log_fn(LOG_WARN,"outgoing relay cell has n_conn==NULL. Dropping.");
      return 0; /* just drop it */
    }
    relay_set_digest(layer_hint->f_digest, cell);

    thishop = layer_hint;
    /* moving from farthest to nearest hop */
    do {
      tor_assert(thishop);

      log_fn(LOG_DEBUG,"crypting a layer of the relay cell.");
      if (relay_crypt_one_payload(thishop->f_crypto, cell->payload, 1) < 0) {
        return -1;
      }

      thishop = thishop->prev;
    } while (thishop != circ->cpath->prev);

  } else { /* incoming cell */
    conn = circ->p_conn;
    if (!conn) {
      log_fn(LOG_WARN,"incoming relay cell has p_conn==NULL. Dropping.");
      return 0; /* just drop it */
    }
    relay_set_digest(circ->p_digest, cell);
    if (relay_crypt_one_payload(circ->p_crypto, cell->payload, 1) < 0)
      return -1;
  }
  ++stats_n_relay_cells_relayed;
  connection_or_write_cell_to_buf(cell, conn);
  return 0;
}

/** If cell's stream_id matches the stream_id of any conn that's
 * attached to circ, return that conn, else return NULL.
 */
static connection_t *
relay_lookup_conn(circuit_t *circ, cell_t *cell, int cell_direction)
{
  connection_t *tmpconn;
  relay_header_t rh;

  relay_header_unpack(&rh, cell->payload);

  if (!rh.stream_id)
    return NULL;

  /* IN or OUT cells could have come from either direction, now
   * that we allow rendezvous *to* an OP.
   */

  for (tmpconn = circ->n_streams; tmpconn; tmpconn=tmpconn->next_stream) {
    if (rh.stream_id == tmpconn->stream_id && !tmpconn->marked_for_close) {
      log_fn(LOG_DEBUG,"found conn for stream %d.", rh.stream_id);
      if (cell_direction == CELL_DIRECTION_OUT ||
          connection_edge_is_rendezvous_stream(tmpconn))
        return tmpconn;
    }
  }
  for (tmpconn = circ->p_streams; tmpconn; tmpconn=tmpconn->next_stream) {
    if (rh.stream_id == tmpconn->stream_id && !tmpconn->marked_for_close) {
      log_fn(LOG_DEBUG,"found conn for stream %d.", rh.stream_id);
      return tmpconn;
    }
  }
  for (tmpconn = circ->resolving_streams; tmpconn; tmpconn=tmpconn->next_stream) {
    if (rh.stream_id == tmpconn->stream_id && !tmpconn->marked_for_close) {
      log_fn(LOG_DEBUG,"found conn for stream %d.", rh.stream_id);
      return tmpconn;
    }
  }
  return NULL; /* probably a begin relay cell */
}

/** Pack the relay_header_t host-order structure <b>src</b> into
 * network-order in the buffer <b>dest</b>. See tor-spec.txt for details
 * about the wire format.
 */
void relay_header_pack(char *dest, const relay_header_t *src) {
  *(uint8_t*)(dest) = src->command;

  set_uint16(dest+1, htons(src->recognized));
  set_uint16(dest+3, htons(src->stream_id));
  memcpy(dest+5, src->integrity, 4);
  set_uint16(dest+9, htons(src->length));
}

/** Unpack the network-order buffer <b>src</b> into a host-order
 * relay_header_t structure <b>dest</b>.
 */
void relay_header_unpack(relay_header_t *dest, const char *src) {
  dest->command = *(uint8_t*)(src);

  dest->recognized = ntohs(get_uint16(src+1));
  dest->stream_id = ntohs(get_uint16(src+3));
  memcpy(dest->integrity, src+5, 4);
  dest->length = ntohs(get_uint16(src+9));
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
int connection_edge_send_command(connection_t *fromconn, circuit_t *circ,
                                 int relay_command, const char *payload,
                                 size_t payload_len, crypt_path_t *cpath_layer) {
  cell_t cell;
  relay_header_t rh;
  int cell_direction;

  if (fromconn && fromconn->marked_for_close) {
    log_fn(LOG_WARN,"Bug: called on conn that's already marked for close at %s:%d.",
           fromconn->marked_for_close_file, fromconn->marked_for_close);
    return 0;
  }

  if (!circ) {
    log_fn(LOG_INFO,"no circ. Closing conn.");
    tor_assert(fromconn);
    if (fromconn->type == CONN_TYPE_AP) {
      connection_mark_unattached_ap(fromconn, END_STREAM_REASON_INTERNAL);
    } else {
      fromconn->has_sent_end = 1; /* no circ to send to */
      connection_mark_for_close(fromconn);
    }
    return -1;
  }

  memset(&cell, 0, sizeof(cell_t));
  cell.command = CELL_RELAY;
  if (cpath_layer) {
    cell.circ_id = circ->n_circ_id;
    cell_direction = CELL_DIRECTION_OUT;
  } else {
    cell.circ_id = circ->p_circ_id;
    cell_direction = CELL_DIRECTION_IN;
  }

  memset(&rh, 0, sizeof(rh));
  rh.command = relay_command;
  if (fromconn)
    rh.stream_id = fromconn->stream_id; /* else it's 0 */
  rh.length = payload_len;
  relay_header_pack(cell.payload, &rh);
  if (payload_len) {
    tor_assert(payload_len <= RELAY_PAYLOAD_SIZE);
    memcpy(cell.payload+RELAY_HEADER_SIZE, payload, payload_len);
  }

  log_fn(LOG_DEBUG,"delivering %d cell %s.", relay_command,
         cell_direction == CELL_DIRECTION_OUT ? "forward" : "backward");

  if (circuit_package_relay_cell(&cell, circ, cell_direction, cpath_layer) < 0) {
    log_fn(LOG_WARN,"circuit_package_relay_cell failed. Closing.");
    circuit_mark_for_close(circ);
    return -1;
  }
  return 0;
}

/** Translate <b>reason</b>, which came from a relay 'end' cell,
 * into a static const string describing why the stream is closing.
 * <b>reason</b> is -1 if no reason was provided.
 */
static const char *
connection_edge_end_reason_str(int reason) {
  switch (reason) {
    case -1:
      log_fn(LOG_WARN,"End cell arrived with length 0. Should be at least 1.");
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
    default:
      log_fn(LOG_WARN,"Reason for ending (%d) not recognized.",reason);
      return "unknown";
  }
}

/** Translate <b>reason</b> (as from a relay 'end' cell) into an
 * appropriate SOCKS5 reply code.
 */
socks5_reply_status_t
connection_edge_end_reason_socks5_response(int reason)
{
  switch (reason) {
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

    case END_STREAM_REASON_ALREADY_SOCKS_REPLIED:
      return SOCKS5_SUCCEEDED; /* never used */
    case END_STREAM_REASON_CANT_ATTACH:
      return SOCKS5_GENERAL_ERROR;
    case END_STREAM_REASON_NET_UNREACHABLE:
      return SOCKS5_NET_UNREACHABLE;
    default:
      log_fn(LOG_WARN,"Reason for ending (%d) not recognized.",reason);
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
      log_fn(LOG_INFO, "Didn't recognize errno %d (%s); telling the OP that we are ending a stream for 'misc' reason.",
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
edge_reason_is_retriable(int reason) {
  return reason == END_STREAM_REASON_HIBERNATING ||
         reason == END_STREAM_REASON_RESOURCELIMIT ||
         reason == END_STREAM_REASON_EXITPOLICY ||
         reason == END_STREAM_REASON_RESOLVEFAILED ||
         reason == END_STREAM_REASON_MISC;
}

static int
connection_edge_process_end_not_open(
    relay_header_t *rh, cell_t *cell, circuit_t *circ,
    connection_t *conn, crypt_path_t *layer_hint) {
  struct in_addr in;
  routerinfo_t *exitrouter;
  int reason = *(cell->payload+RELAY_HEADER_SIZE);

  if (rh->length > 0 && edge_reason_is_retriable(reason)) {
    if (conn->type != CONN_TYPE_AP) {
      log_fn(LOG_WARN,"Got an end because of %s, but we're not an AP. Closing.",
             connection_edge_end_reason_str(reason));
      return -1;
    }
    log_fn(LOG_INFO,"Address '%s' refused due to '%s'. Considering retrying.",
           safe_str(conn->socks_request->address),
           connection_edge_end_reason_str(reason));
    exitrouter = router_get_by_digest(circ->build_state->chosen_exit_digest);
    if (!exitrouter) {
      log_fn(LOG_INFO,"Skipping broken circ (exit router vanished)");
      return 0; /* this circuit is screwed and doesn't know it yet */
    }
    switch (reason) {
      case END_STREAM_REASON_EXITPOLICY:
        if (rh->length >= 5) {
          uint32_t addr = ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE+1));
          if (!addr) {
            log_fn(LOG_INFO,"Address '%s' resolved to 0.0.0.0. Closing,",
                   safe_str(conn->socks_request->address));
            connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
            return 0;
          }
          client_dns_set_addressmap(conn->socks_request->address, addr,
                                    conn->chosen_exit_name);
        }
        /* check if he *ought* to have allowed it */
        if (rh->length < 5 ||
            (tor_inet_aton(conn->socks_request->address, &in) &&
             !conn->chosen_exit_name)) {
          log_fn(LOG_NOTICE,"Exitrouter '%s' seems to be more restrictive than its exit policy. Not using this router as exit for now.", exitrouter->nickname);
          addr_policy_free(exitrouter->exit_policy);
          exitrouter->exit_policy =
            router_parse_addr_policy_from_string("reject *:*");
        }
        /* rewrite it to an IP if we learned one. */
        addressmap_rewrite(conn->socks_request->address,
                           sizeof(conn->socks_request->address));

        if (connection_ap_detach_retriable(conn, circ) >= 0)
          return 0;
        /* else, conn will get closed below */
        break;
      case END_STREAM_REASON_RESOLVEFAILED:
      case END_STREAM_REASON_MISC:
        if (client_dns_incr_failures(conn->socks_request->address)
            < MAX_RESOLVE_FAILURES) {
          /* We haven't retried too many times; reattach the connection. */
          circuit_log_path(LOG_INFO,circ);
          tor_assert(circ->timestamp_dirty);
          circ->timestamp_dirty -= get_options()->MaxCircuitDirtiness;

          if (connection_ap_detach_retriable(conn, circ) >= 0)
            return 0;
          /* else, conn will get closed below */
        } else {
          log_fn(LOG_NOTICE,"Have tried resolving or connecting to address '%s' at %d different places. Giving up.",
                 safe_str(conn->socks_request->address), MAX_RESOLVE_FAILURES);
          /* clear the failures, so it will have a full try next time */
          client_dns_clear_failures(conn->socks_request->address);
        }
        break;
      case END_STREAM_REASON_HIBERNATING:
      case END_STREAM_REASON_RESOURCELIMIT:
        addr_policy_free(exitrouter->exit_policy);
        exitrouter->exit_policy =
          router_parse_addr_policy_from_string("reject *:*");

        if (connection_ap_detach_retriable(conn, circ) >= 0)
          return 0;
        /* else, will close below */
        break;
    } /* end switch */
    log_fn(LOG_INFO,"Giving up on retrying; conn can't be handled.");
  }

  log_fn(LOG_INFO,"Edge got end (%s) before we're connected. Marking for close.",
         connection_edge_end_reason_str(rh->length > 0 ? reason : -1));
  if (conn->type == CONN_TYPE_AP) {
    circuit_log_path(LOG_INFO,circ);
    connection_mark_unattached_ap(conn, reason);
  } else {
    conn->has_sent_end = 1; /* we just got an 'end', don't need to send one */
    connection_mark_for_close(conn);
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
    connection_t *conn, crypt_path_t *layer_hint) {

  if (rh->command == RELAY_COMMAND_END)
    return connection_edge_process_end_not_open(rh, cell, circ, conn, layer_hint);

  if (conn->type == CONN_TYPE_AP && rh->command == RELAY_COMMAND_CONNECTED) {
    if (conn->state != AP_CONN_STATE_CONNECT_WAIT) {
      log_fn(LOG_WARN,"Got 'connected' while not in state connect_wait. Dropping.");
      return 0;
    }
//    log_fn(LOG_INFO,"Connected! Notifying application.");
    conn->state = AP_CONN_STATE_OPEN;
    log_fn(LOG_INFO,"'connected' received after %d seconds.",
           (int)(time(NULL) - conn->timestamp_lastread));
    if (rh->length >= 4) {
      uint32_t addr = ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE));
      if (!addr) {
        log_fn(LOG_INFO,"...but it claims the IP address was 0.0.0.0. Closing.");
        connection_edge_end(conn, END_STREAM_REASON_TORPROTOCOL, conn->cpath_layer);
        connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
        return 0;
      }
      client_dns_set_addressmap(conn->socks_request->address, addr,
                                conn->chosen_exit_name);
    }
    circuit_log_path(LOG_INFO,circ);
    connection_ap_handshake_socks_reply(conn, NULL, 0, SOCKS5_SUCCEEDED);
    /* handle anything that might have queued */
    if (connection_edge_package_raw_inbuf(conn, 1) < 0) {
      /* (We already sent an end cell if possible) */
      connection_mark_for_close(conn);
      return 0;
    }
    return 0;
  }
  if (conn->type == CONN_TYPE_AP && rh->command == RELAY_COMMAND_RESOLVED) {
    if (conn->state != AP_CONN_STATE_RESOLVE_WAIT) {
      log_fn(LOG_WARN,"Got a 'resolved' cell while not in state resolve_wait. Dropping.");
      return 0;
    }
    tor_assert(conn->socks_request->command == SOCKS_COMMAND_RESOLVE);
    if (rh->length < 2 || cell->payload[RELAY_HEADER_SIZE+1]+2>rh->length) {
      log_fn(LOG_WARN, "Dropping malformed 'resolved' cell");
      connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
      return 0;
    }
    connection_ap_handshake_socks_resolved(conn,
                   cell->payload[RELAY_HEADER_SIZE], /*answer_type*/
                   cell->payload[RELAY_HEADER_SIZE+1], /*answer_len*/
                   cell->payload+RELAY_HEADER_SIZE+2); /* answer */
    connection_mark_unattached_ap(conn, END_STREAM_REASON_ALREADY_SOCKS_REPLIED);
    return 0;
  }

  log_fn(LOG_WARN,"Got an unexpected relay command %d, in state %d (%s). Closing.",
         rh->command, conn->state, conn_state_to_string(conn->type, conn->state));
  connection_edge_end(conn, END_STREAM_REASON_TORPROTOCOL, conn->cpath_layer);
  connection_mark_for_close(conn);
  return -1;
}

/** An incoming relay cell has arrived on circuit <b>circ</b>. If
 * <b>conn</b> is NULL this is a control cell, else <b>cell</b> is
 * destined for <b>conn</b>.
 *
 * If <b>layer_hint</b> is defined, then we're the origin of the
 * circuit, and it specifies the hop that packaged <b>cell</b>.
 *
 * Return -1 if you want to tear down the circuit, else 0.
 */
static int
connection_edge_process_relay_cell(cell_t *cell, circuit_t *circ,
                                   connection_t *conn,
                                   crypt_path_t *layer_hint)
{
  static int num_seen=0;
  relay_header_t rh;

  tor_assert(cell);
  tor_assert(circ);

  relay_header_unpack(&rh, cell->payload);
//  log_fn(LOG_DEBUG,"command %d stream %d", rh.command, rh.stream_id);
  num_seen++;
  log_fn(LOG_DEBUG,"Now seen %d relay cells here.", num_seen);

  if (rh.length > RELAY_PAYLOAD_SIZE) {
    log_fn(LOG_WARN, "Relay cell length field too long. Closing circuit.");
    return -1;
  }

  /* either conn is NULL, in which case we've got a control cell, or else
   * conn points to the recognized stream. */

  if (conn && !connection_state_is_open(conn))
    return connection_edge_process_relay_cell_not_open(
             &rh, cell, circ, conn, layer_hint);

  switch (rh.command) {
    case RELAY_COMMAND_DROP:
      log_fn(LOG_INFO,"Got a relay-level padding cell. Dropping.");
      return 0;
    case RELAY_COMMAND_BEGIN:
      if (layer_hint &&
          circ->purpose != CIRCUIT_PURPOSE_S_REND_JOINED) {
        log_fn(LOG_WARN,"relay begin request unsupported at AP. Dropping.");
        return 0;
      }
      if (conn) {
        log_fn(LOG_WARN,"begin cell for known stream. Dropping.");
        return 0;
      }
      connection_exit_begin_conn(cell, circ);
      return 0;
    case RELAY_COMMAND_DATA:
      ++stats_n_data_cells_received;
      if (( layer_hint && --layer_hint->deliver_window < 0) ||
          (!layer_hint && --circ->deliver_window < 0)) {
        log_fn(LOG_WARN,"(relay data) circ deliver_window below 0. Killing.");
        connection_edge_end(conn, END_STREAM_REASON_TORPROTOCOL, conn->cpath_layer);
        connection_mark_for_close(conn);
        return -1;
      }
      log_fn(LOG_DEBUG,"circ deliver_window now %d.", layer_hint ?
             layer_hint->deliver_window : circ->deliver_window);

      circuit_consider_sending_sendme(circ, layer_hint);

      if (!conn) {
        log_fn(LOG_INFO,"data cell dropped, unknown stream.");
        return 0;
      }

      if (--conn->deliver_window < 0) { /* is it below 0 after decrement? */
        log_fn(LOG_WARN,"(relay data) conn deliver_window below 0. Killing.");
        return -1; /* somebody's breaking protocol. kill the whole circuit. */
      }

      stats_n_data_bytes_received += rh.length;
      connection_write_to_buf(cell->payload + RELAY_HEADER_SIZE,
                              rh.length, conn);
      connection_edge_consider_sending_sendme(conn);
      return 0;
    case RELAY_COMMAND_END:
      if (!conn) {
        log_fn(LOG_INFO,"end cell (%s) dropped, unknown stream.",
               connection_edge_end_reason_str(rh.length > 0 ?
                 *(char *)(cell->payload+RELAY_HEADER_SIZE) : -1));
        return 0;
      }
/* XXX add to this log_fn the exit node's nickname? */
      log_fn(LOG_INFO,"%d: end cell (%s) for stream %d. Removing stream.",
             conn->s,
             connection_edge_end_reason_str(rh.length > 0 ?
               *(char *)(cell->payload+RELAY_HEADER_SIZE) : -1),
             conn->stream_id);
      if (conn->socks_request && !conn->socks_request->has_finished)
        log_fn(LOG_WARN,"Bug: open stream hasn't sent socks answer yet? Closing.");
#ifdef HALF_OPEN
      conn->done_sending = 1;
      shutdown(conn->s, 1); /* XXX check return; refactor NM */
      if (conn->done_receiving) {
        /* We just *got* an end; no reason to send one. */
        conn->has_sent_end = 1;
        connection_mark_for_close(conn);
        conn->hold_open_until_flushed = 1;
      }
#else
      /* We just *got* an end; no reason to send one. */
      conn->has_sent_end = 1;
      if (!conn->marked_for_close) {
        /* only mark it if not already marked. it's possible to
         * get the 'end' right around when the client hangs up on us. */
        connection_mark_for_close(conn);
        conn->hold_open_until_flushed = 1;
      }
#endif
      return 0;
    case RELAY_COMMAND_EXTEND:
      if (conn) {
        log_fn(LOG_WARN,"'extend' for non-zero stream. Dropping.");
        return 0;
      }
      return circuit_extend(cell, circ);
    case RELAY_COMMAND_EXTENDED:
      if (!layer_hint) {
        log_fn(LOG_WARN,"'extended' unsupported at non-origin. Dropping.");
        return 0;
      }
      log_fn(LOG_DEBUG,"Got an extended cell! Yay.");
      if (circuit_finish_handshake(circ, CELL_CREATED,
                                   cell->payload+RELAY_HEADER_SIZE) < 0) {
        log_fn(LOG_WARN,"circuit_finish_handshake failed.");
        return -1;
      }
      if (circuit_send_next_onion_skin(circ)<0) {
        log_fn(LOG_INFO,"circuit_send_next_onion_skin() failed.");
        return -1;
      }
      return 0;
    case RELAY_COMMAND_TRUNCATE:
      if (layer_hint) {
        log_fn(LOG_WARN,"'truncate' unsupported at origin. Dropping.");
        return 0;
      }
      if (circ->n_conn) {
        connection_send_destroy(circ->n_circ_id, circ->n_conn);
        circuit_set_circid_orconn(circ, 0, NULL, N_CONN_CHANGED);
      }
      log_fn(LOG_DEBUG, "Processed 'truncate', replying.");
      connection_edge_send_command(NULL, circ, RELAY_COMMAND_TRUNCATED,
                                   NULL, 0, NULL);
      return 0;
    case RELAY_COMMAND_TRUNCATED:
      if (!layer_hint) {
        log_fn(LOG_WARN,"'truncated' unsupported at non-origin. Dropping.");
        return 0;
      }
      circuit_truncated(circ, layer_hint);
      return 0;
    case RELAY_COMMAND_CONNECTED:
      if (conn) {
        log_fn(LOG_WARN,"'connected' unsupported while open. Closing circ.");
        return -1;
      }
      log_fn(LOG_INFO,"'connected' received, no conn attached anymore. Ignoring.");
      return 0;
    case RELAY_COMMAND_SENDME:
      if (!conn) {
        if (layer_hint) {
          layer_hint->package_window += CIRCWINDOW_INCREMENT;
          log_fn(LOG_DEBUG,"circ-level sendme at origin, packagewindow %d.",
                 layer_hint->package_window);
          circuit_resume_edge_reading(circ, layer_hint);
        } else {
          circ->package_window += CIRCWINDOW_INCREMENT;
          log_fn(LOG_DEBUG,"circ-level sendme at non-origin, packagewindow %d.",
                 circ->package_window);
          circuit_resume_edge_reading(circ, layer_hint);
        }
        return 0;
      }
      conn->package_window += STREAMWINDOW_INCREMENT;
      log_fn(LOG_DEBUG,"stream-level sendme, packagewindow now %d.", conn->package_window);
      connection_start_reading(conn);
      /* handle whatever might still be on the inbuf */
      if (connection_edge_package_raw_inbuf(conn, 1) < 0) {
        /* (We already sent an end cell if possible) */
        connection_mark_for_close(conn);
        return 0;
      }
      return 0;
    case RELAY_COMMAND_RESOLVE:
      if (layer_hint) {
        log_fn(LOG_WARN,"resolve request unsupported at AP; dropping.");
        return 0;
      } else if (conn) {
        log_fn(LOG_WARN, "resolve request for known stream; dropping.");
        return 0;
      } else if (circ->purpose != CIRCUIT_PURPOSE_OR) {
        log_fn(LOG_WARN, "resolve request on circ with purpose %d; dropping",
               circ->purpose);
        return 0;
      }
      connection_exit_begin_resolve(cell, circ);
      return 0;
    case RELAY_COMMAND_RESOLVED:
      if (conn) {
        log_fn(LOG_WARN,"'resolved' unsupported while open. Closing circ.");
        return -1;
      }
      log_fn(LOG_INFO,"'resolved' received, no conn attached anymore. Ignoring.");
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
  log_fn(LOG_WARN,"unknown relay command %d.",rh.command);
  return -1;
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
int connection_edge_package_raw_inbuf(connection_t *conn, int package_partial) {
  size_t amount_to_process, length;
  char payload[CELL_PAYLOAD_SIZE];
  circuit_t *circ;

  tor_assert(conn);
  tor_assert(!connection_speaks_cells(conn));
  if (conn->marked_for_close) {
    log_fn(LOG_WARN,"Bug: called on conn that's already marked for close at %s:%d.",
           conn->marked_for_close_file, conn->marked_for_close);
    return 0;
  }

repeat_connection_edge_package_raw_inbuf:

  circ = circuit_get_by_edge_conn(conn);
  if (!circ) {
    log_fn(LOG_INFO,"conn has no circuit! Closing.");
    return -1;
  }

  if (circuit_consider_stop_edge_reading(circ, conn->cpath_layer))
    return 0;

  if (conn->package_window <= 0) {
    log_fn(LOG_INFO,"called with package_window %d. Skipping.", conn->package_window);
    connection_stop_reading(conn);
    return 0;
  }

  amount_to_process = buf_datalen(conn->inbuf);

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

  connection_fetch_from_buf(payload, length, conn);

  log_fn(LOG_DEBUG,"(%d) Packaging %d bytes (%d waiting).", conn->s,
         (int)length, (int)buf_datalen(conn->inbuf));

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
    connection_stop_reading(conn);
    log_fn(LOG_DEBUG,"conn->package_window reached 0.");
    circuit_consider_stop_edge_reading(circ, conn->cpath_layer);
    return 0; /* don't process the inbuf any more */
  }
  log_fn(LOG_DEBUG,"conn->package_window is now %d",conn->package_window);

  /* handle more if there's more, or return 0 if there isn't */
  goto repeat_connection_edge_package_raw_inbuf;
}

/** Called when we've just received a relay data cell, or when
 * we've just finished flushing all bytes to stream <b>conn</b>.
 *
 * If conn->outbuf is not too full, and our deliver window is
 * low, send back a suitable number of stream-level sendme cells.
 */
void connection_edge_consider_sending_sendme(connection_t *conn) {
  circuit_t *circ;

  if (connection_outbuf_too_full(conn))
    return;

  circ = circuit_get_by_edge_conn(conn);
  if (!circ) {
    /* this can legitimately happen if the destroy has already
     * arrived and torn down the circuit */
    log_fn(LOG_INFO,"No circuit associated with conn. Skipping.");
    return;
  }

  while (conn->deliver_window < STREAMWINDOW_START - STREAMWINDOW_INCREMENT) {
    log_fn(LOG_DEBUG,"Outbuf %d, Queueing stream sendme.", (int)conn->outbuf_flushlen);
    conn->deliver_window += STREAMWINDOW_INCREMENT;
    if (connection_edge_send_command(conn, circ, RELAY_COMMAND_SENDME,
                                     NULL, 0, conn->cpath_layer) < 0) {
      log_fn(LOG_WARN,"connection_edge_send_command failed. Returning.");
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

  log_fn(LOG_DEBUG,"resuming");

  /* have to check both n_streams and p_streams, to handle rendezvous */
  if (circuit_resume_edge_reading_helper(circ->n_streams, circ, layer_hint) >= 0)
    circuit_resume_edge_reading_helper(circ->p_streams, circ, layer_hint);
}

/** A helper function for circuit_resume_edge_reading() above.
 * The arguments are the same, except that <b>conn</b> is the head
 * of a linked list of edge streams that should each be considered.
 */
static int
circuit_resume_edge_reading_helper(connection_t *conn,
                                   circuit_t *circ,
                                   crypt_path_t *layer_hint) {

  for ( ; conn; conn=conn->next_stream) {
    if (conn->marked_for_close)
      continue;
    if ((!layer_hint && conn->package_window > 0) ||
        (layer_hint && conn->package_window > 0 && conn->cpath_layer == layer_hint)) {
      connection_start_reading(conn);
      /* handle whatever might still be on the inbuf */
      if (connection_edge_package_raw_inbuf(conn, 1)<0) {
        /* (We already sent an end cell if possible) */
        connection_mark_for_close(conn);
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
  connection_t *conn = NULL;

  if (!layer_hint) {
    log_fn(LOG_DEBUG,"considering circ->package_window %d", circ->package_window);
    if (circ->package_window <= 0) {
      log_fn(LOG_DEBUG,"yes, not-at-origin. stopped.");
      for (conn = circ->n_streams; conn; conn=conn->next_stream)
        connection_stop_reading(conn);
      return 1;
    }
    return 0;
  }
  /* else, layer hint is defined, use it */
  log_fn(LOG_DEBUG,"considering layer_hint->package_window %d", layer_hint->package_window);
  if (layer_hint->package_window <= 0) {
    log_fn(LOG_DEBUG,"yes, at-origin. stopped.");
    for (conn = circ->n_streams; conn; conn=conn->next_stream)
      if (conn->cpath_layer == layer_hint)
        connection_stop_reading(conn);
    for (conn = circ->p_streams; conn; conn=conn->next_stream)
      if (conn->cpath_layer == layer_hint)
        connection_stop_reading(conn);
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
    log_fn(LOG_DEBUG,"Queueing circuit sendme.");
    if (layer_hint)
      layer_hint->deliver_window += CIRCWINDOW_INCREMENT;
    else
      circ->deliver_window += CIRCWINDOW_INCREMENT;
    if (connection_edge_send_command(NULL, circ, RELAY_COMMAND_SENDME,
                                     NULL, 0, layer_hint) < 0) {
      log_fn(LOG_WARN,"connection_edge_send_command failed. Circuit's closed.");
      return; /* the circuit's closed, don't continue */
    }
  }
}

