/* Copyright 2001 Matej Pfajfar, 2001-2004 Roger Dingledine. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file relay.c
 * \brief Handle relay cell encryption/decryption.
 **/

#include "or.h"

static int relay_crypt(circuit_t *circ, cell_t *cell, int cell_direction,
                crypt_path_t **layer_hint, char *recognized);
static connection_t *relay_lookup_conn(circuit_t *circ, cell_t *cell, int cell_direction)
;

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

  if(memcmp(received_integrity, calculated_integrity, 4)) {
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
  relay_header_t rh;

  relay_header_unpack(&rh, in);
//  log_fn(LOG_DEBUG,"before crypt: %d",rh.recognized);
  if(( encrypt_mode && crypto_cipher_encrypt(cipher, in, CELL_PAYLOAD_SIZE, out)) ||
     (!encrypt_mode && crypto_cipher_decrypt(cipher, in, CELL_PAYLOAD_SIZE, out))) {
    log_fn(LOG_WARN,"Error during relay encryption");
    return -1;
  }
  memcpy(in,out,CELL_PAYLOAD_SIZE);
  relay_header_unpack(&rh, in);
//  log_fn(LOG_DEBUG,"after crypt: %d",rh.recognized);
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

  tor_assert(cell && circ);
  tor_assert(cell_direction == CELL_DIRECTION_OUT || cell_direction == CELL_DIRECTION_IN);
  if (circ->marked_for_close)
    return 0;

  if(relay_crypt(circ, cell, cell_direction, &layer_hint, &recognized) < 0) {
    log_fn(LOG_WARN,"relay crypt failed. Dropping connection.");
    return -1;
  }

  if(recognized) {
    conn = relay_lookup_conn(circ, cell, cell_direction);
    if(cell_direction == CELL_DIRECTION_OUT) {
      ++stats_n_relay_cells_delivered;
      log_fn(LOG_DEBUG,"Sending away from origin.");
      if (connection_edge_process_relay_cell(cell, circ, conn, NULL) < 0) {
        log_fn(LOG_WARN,"connection_edge_process_relay_cell (away from origin) failed.");
        return -1;
      }
    }
    if(cell_direction == CELL_DIRECTION_IN) {
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
  if(cell_direction == CELL_DIRECTION_OUT) {
    cell->circ_id = circ->n_circ_id; /* switch it */
    conn = circ->n_conn;
  } else {
    cell->circ_id = circ->p_circ_id; /* switch it */
    conn = circ->p_conn;
  }

  if(!conn) {
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

  tor_assert(circ && cell && recognized);
  tor_assert(cell_direction == CELL_DIRECTION_IN || cell_direction == CELL_DIRECTION_OUT); 

  if(cell_direction == CELL_DIRECTION_IN) {
    if(CIRCUIT_IS_ORIGIN(circ)) { /* We're at the beginning of the circuit.
                                     We'll want to do layered decrypts. */
      tor_assert(circ->cpath);
      thishop = circ->cpath;
      if(thishop->state != CPATH_STATE_OPEN) {
        log_fn(LOG_WARN,"Relay cell before first created cell? Closing.");
        return -1;
      }
      do { /* Remember: cpath is in forward order, that is, first hop first. */
        tor_assert(thishop);

        if(relay_crypt_one_payload(thishop->b_crypto, cell->payload, 0) < 0)
          return -1;

        relay_header_unpack(&rh, cell->payload);
        if(rh.recognized == 0) {
          /* it's possibly recognized. have to check digest to be sure. */
          if(relay_digest_matches(thishop->b_digest, cell)) {
            *recognized = 1;
            *layer_hint = thishop;
            return 0;
          }
        }

        thishop = thishop->next;
      } while(thishop != circ->cpath && thishop->state == CPATH_STATE_OPEN);
      log_fn(LOG_WARN,"in-cell at OP not recognized. Closing.");
      return -1;
    } else { /* we're in the middle. Just one crypt. */
      if(relay_crypt_one_payload(circ->p_crypto, cell->payload, 1) < 0)
        return -1;
//      log_fn(LOG_DEBUG,"Skipping recognized check, because we're not the OP.");
    }
  } else /* cell_direction == CELL_DIRECTION_OUT */ {
    /* we're in the middle. Just one crypt. */

    if(relay_crypt_one_payload(circ->n_crypto, cell->payload, 0) < 0)
      return -1;

    relay_header_unpack(&rh, cell->payload);
    if (rh.recognized == 0) {
      /* it's possibly recognized. have to check digest to be sure. */
      if(relay_digest_matches(circ->n_digest, cell)) {
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
int
circuit_package_relay_cell(cell_t *cell, circuit_t *circ,
                           int cell_direction,
                           crypt_path_t *layer_hint)
{ 
  connection_t *conn; /* where to send the cell */
  crypt_path_t *thishop; /* counter for repeated crypts */

  if(cell_direction == CELL_DIRECTION_OUT) {
    conn = circ->n_conn;
    if(!conn) {
      log_fn(LOG_WARN,"outgoing relay cell has n_conn==NULL. Dropping.");
      return 0; /* just drop it */
    }
    relay_set_digest(layer_hint->f_digest, cell);

    thishop = layer_hint;
    /* moving from farthest to nearest hop */
    do {
      tor_assert(thishop);

      log_fn(LOG_DEBUG,"crypting a layer of the relay cell.");
      if(relay_crypt_one_payload(thishop->f_crypto, cell->payload, 1) < 0) {
        return -1;
      }

      thishop = thishop->prev;
    } while (thishop != circ->cpath->prev);

  } else { /* incoming cell */
    conn = circ->p_conn;
    if(!conn) {
      log_fn(LOG_WARN,"incoming relay cell has p_conn==NULL. Dropping.");
      return 0; /* just drop it */
    }
    relay_set_digest(circ->p_digest, cell);
    if(relay_crypt_one_payload(circ->p_crypto, cell->payload, 1) < 0)
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

  if(!rh.stream_id)
    return NULL;

  /* IN or OUT cells could have come from either direction, now
   * that we allow rendezvous *to* an OP.
   */

  for(tmpconn = circ->n_streams; tmpconn; tmpconn=tmpconn->next_stream) {
    if(rh.stream_id == tmpconn->stream_id) {
      log_fn(LOG_DEBUG,"found conn for stream %d.", rh.stream_id);
      if(cell_direction == CELL_DIRECTION_OUT ||
         connection_edge_is_rendezvous_stream(tmpconn))
        return tmpconn;
    }
  }
  for(tmpconn = circ->p_streams; tmpconn; tmpconn=tmpconn->next_stream) {
    if(rh.stream_id == tmpconn->stream_id) {
      log_fn(LOG_DEBUG,"found conn for stream %d.", rh.stream_id);
      return tmpconn;
    }
  }
  for(tmpconn = circ->resolving_streams; tmpconn; tmpconn=tmpconn->next_stream) {
    if(rh.stream_id == tmpconn->stream_id) {
      log_fn(LOG_DEBUG,"found conn for stream %d.", rh.stream_id);
      return tmpconn;
    }
  }
  return NULL; /* probably a begin relay cell */
}

