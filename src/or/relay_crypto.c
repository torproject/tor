/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#include "config.h"
#include "relay_crypto.h"
#include "relay.h"

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
  uint32_t received_integrity, calculated_integrity;
  relay_header_t rh;
  crypto_digest_checkpoint_t backup_digest;

  crypto_digest_checkpoint(&backup_digest, digest);

  relay_header_unpack(&rh, cell->payload);
  memcpy(&received_integrity, rh.integrity, 4);
  memset(rh.integrity, 0, 4);
  relay_header_pack(cell->payload, &rh);

//  log_fn(LOG_DEBUG,"Reading digest of %u %u %u %u from relay cell.",
//    received_integrity[0], received_integrity[1],
//    received_integrity[2], received_integrity[3]);

  crypto_digest_add_bytes(digest, (char*) cell->payload, CELL_PAYLOAD_SIZE);
  crypto_digest_get_digest(digest, (char*) &calculated_integrity, 4);

  int rv = 1;

  if (calculated_integrity != received_integrity) {
//    log_fn(LOG_INFO,"Recognized=0 but bad digest. Not recognizing.");
// (%d vs %d).", received_integrity, calculated_integrity);
    /* restore digest to its old form */
    crypto_digest_restore(digest, &backup_digest);
    /* restore the relay header */
    memcpy(rh.integrity, &received_integrity, 4);
    relay_header_pack(cell->payload, &rh);
    rv = 0;
  }

  memwipe(&backup_digest, 0, sizeof(backup_digest));
  return rv;
}

/** Apply <b>cipher</b> to CELL_PAYLOAD_SIZE bytes of <b>in</b>
 * (in place).
 *
 * Note that we use the same operation for encrypting and for decrypting.
 */
static void
relay_crypt_one_payload(crypto_cipher_t *cipher, uint8_t *in)
{
  crypto_cipher_crypt_inplace(cipher, (char*) in, CELL_PAYLOAD_SIZE);
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
relay_decrypt_cell(circuit_t *circ, cell_t *cell,
                   cell_direction_t cell_direction,
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

        /* decrypt one layer */
        relay_crypt_one_payload(thishop->b_crypto, cell->payload);

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
    } else {
      /* We're in the middle. Encrypt one layer. */
      relay_crypt_one_payload(TO_OR_CIRCUIT(circ)->p_crypto, cell->payload);
    }
  } else /* cell_direction == CELL_DIRECTION_OUT */ {
    /* We're in the middle. Decrypt one layer. */

    relay_crypt_one_payload(TO_OR_CIRCUIT(circ)->n_crypto, cell->payload);

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

/**
 * Encrypt a cell <b>cell</b> that we are creating, and sending outbound on
 * <b>circ</b> until the hop corresponding to <b>layer_hint</b>.
 */
void
relay_encrypt_cell_outbound(cell_t *cell,
                            origin_circuit_t *circ,
                            crypt_path_t *layer_hint)
{
  crypt_path_t *thishop; /* counter for repeated crypts */
  relay_set_digest(layer_hint->f_digest, cell);

  thishop = layer_hint;
  /* moving from farthest to nearest hop */
  do {
    tor_assert(thishop);
    log_debug(LD_OR,"encrypting a layer of the relay cell.");
    relay_crypt_one_payload(thishop->f_crypto, cell->payload);

    thishop = thishop->prev;
  } while (thishop != circ->cpath->prev);
}

/**
 * Encrypt a cell <b>cell</b> that we are creating, and sending on
 * <b>circuit</b> to the origin.
 */
void
relay_encrypt_cell_inbound(cell_t *cell,
                           or_circuit_t *or_circ)
{
  relay_set_digest(or_circ->p_digest, cell);
  /* encrypt one layer */
  relay_crypt_one_payload(or_circ->p_crypto, cell->payload);
}

