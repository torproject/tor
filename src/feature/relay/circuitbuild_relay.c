/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file circuitbuild_relay.c
 * @brief Implements the details of exteding circuits (by relaying extend
 * cells as create cells, and answering create cells).
 *
 * On the server side, this module handles the logic of responding to
 * RELAY_EXTEND requests, using circuit_extend() and onionskin_answer().
 *
 * The shared client and server code is in core/or/circuitbuild.c.
 **/

#include "orconfig.h"
#include "feature/relay/circuitbuild_relay.h"

#include "core/or/or.h"
#include "app/config/config.h"

#include "core/crypto/relay_crypto.h"

#include "core/or/cell_st.h"
#include "core/or/circuit_st.h"
#include "core/or/extend_info_st.h"
#include "core/or/or_circuit_st.h"

#include "core/or/channel.h"
#include "core/or/circuitbuild.h"
#include "core/or/circuitlist.h"
#include "core/or/onion.h"
#include "core/or/relay.h"

#include "feature/nodelist/nodelist.h"

#include "feature/relay/routermode.h"
#include "feature/relay/selftest.h"

/* Before replying to an extend cell, check the state of the circuit
 * <b>circ</b>, and the configured tor mode.
 *
 * Return -1 if we want to warn and tear down the circuit, else return 0.
 */
int
circuit_extend(struct cell_t *cell, struct circuit_t *circ)
{
  channel_t *n_chan;
  relay_header_t rh;
  extend_cell_t ec;
  const char *msg = NULL;
  int should_launch = 0;

  if (!server_mode(get_options())) {
    circuitbuild_warn_client_extend();
    return -1;
  }

  if (circ->n_chan) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "n_chan already set. Bug/attack. Closing.");
    return -1;
  }
  if (circ->n_hop) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "conn to next hop already launched. Bug/attack. Closing.");
    return -1;
  }

  relay_header_unpack(&rh, cell->payload);

  if (extend_cell_parse(&ec, rh.command,
                        cell->payload+RELAY_HEADER_SIZE,
                        rh.length) < 0) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Can't parse extend cell. Closing circuit.");
    return -1;
  }

  if (!ec.orport_ipv4.port || tor_addr_is_null(&ec.orport_ipv4.addr)) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Client asked me to extend to zero destination port or addr.");
    return -1;
  }

  if (tor_addr_is_internal(&ec.orport_ipv4.addr, 0) &&
      !get_options()->ExtendAllowPrivateAddresses) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Client asked me to extend to a private address");
    return -1;
  }

  /* Check if they asked us for 0000..0000. We support using
   * an empty fingerprint for the first hop (e.g. for a bridge relay),
   * but we don't want to let clients send us extend cells for empty
   * fingerprints -- a) because it opens the user up to a mitm attack,
   * and b) because it lets an attacker force the relay to hold open a
   * new TLS connection for each extend request. */
  if (tor_digest_is_zero((const char*)ec.node_id)) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Client asked me to extend without specifying an id_digest.");
    return -1;
  }

  /* Fill in ed_pubkey if it was not provided and we can infer it from
   * our networkstatus */
  if (ed25519_public_key_is_zero(&ec.ed_pubkey)) {
    const node_t *node = node_get_by_id((const char*)ec.node_id);
    const ed25519_public_key_t *node_ed_id = NULL;
    if (node &&
        node_supports_ed25519_link_authentication(node, 1) &&
        (node_ed_id = node_get_ed25519_id(node))) {
      ed25519_pubkey_copy(&ec.ed_pubkey, node_ed_id);
    }
  }

  /* Next, check if we're being asked to connect to the hop that the
   * extend cell came from. There isn't any reason for that, and it can
   * assist circular-path attacks. */
  if (tor_memeq(ec.node_id,
                TO_OR_CIRCUIT(circ)->p_chan->identity_digest,
                DIGEST_LEN)) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Client asked me to extend back to the previous hop.");
    return -1;
  }

  /* Check the previous hop Ed25519 ID too */
  if (! ed25519_public_key_is_zero(&ec.ed_pubkey) &&
      ed25519_pubkey_eq(&ec.ed_pubkey,
                        &TO_OR_CIRCUIT(circ)->p_chan->ed25519_identity)) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Client asked me to extend back to the previous hop "
           "(by Ed25519 ID).");
    return -1;
  }

  n_chan = channel_get_for_extend((const char*)ec.node_id,
                                  &ec.ed_pubkey,
                                  &ec.orport_ipv4.addr,
                                  &msg,
                                  &should_launch);

  if (!n_chan) {
    log_debug(LD_CIRC|LD_OR,"Next router (%s): %s",
              fmt_addrport(&ec.orport_ipv4.addr,ec.orport_ipv4.port),
              msg?msg:"????");

    circ->n_hop = extend_info_new(NULL /*nickname*/,
                                  (const char*)ec.node_id,
                                  &ec.ed_pubkey,
                                  NULL, /*onion_key*/
                                  NULL, /*curve25519_key*/
                                  &ec.orport_ipv4.addr,
                                  ec.orport_ipv4.port);

    circ->n_chan_create_cell = tor_memdup(&ec.create_cell,
                                          sizeof(ec.create_cell));

    circuit_set_state(circ, CIRCUIT_STATE_CHAN_WAIT);

    if (should_launch) {
      /* we should try to open a connection */
      n_chan = channel_connect_for_circuit(&ec.orport_ipv4.addr,
                                           ec.orport_ipv4.port,
                                           (const char*)ec.node_id,
                                           &ec.ed_pubkey);
      if (!n_chan) {
        log_info(LD_CIRC,"Launching n_chan failed. Closing circuit.");
        circuit_mark_for_close(circ, END_CIRC_REASON_CONNECTFAILED);
        return 0;
      }
      log_debug(LD_CIRC,"connecting in progress (or finished). Good.");
    }
    /* return success. The onion/circuit/etc will be taken care of
     * automatically (may already have been) whenever n_chan reaches
     * OR_CONN_STATE_OPEN.
     */
    return 0;
  }

  tor_assert(!circ->n_hop); /* Connection is already established. */
  circ->n_chan = n_chan;
  log_debug(LD_CIRC,
            "n_chan is %s",
            channel_get_canonical_remote_descr(n_chan));

  if (circuit_deliver_create_cell(circ, &ec.create_cell, 1) < 0)
    return -1;

  return 0;
}

/** Given a response payload and keys, initialize, then send a created
 * cell back.
 */
int
onionskin_answer(struct or_circuit_t *circ,
                 const created_cell_t *created_cell,
                 const char *keys, size_t keys_len,
                 const uint8_t *rend_circ_nonce)
{
  cell_t cell;

  tor_assert(keys_len == CPATH_KEY_MATERIAL_LEN);

  if (created_cell_format(&cell, created_cell) < 0) {
    log_warn(LD_BUG,"couldn't format created cell (type=%d, len=%d)",
             (int)created_cell->cell_type, (int)created_cell->handshake_len);
    return -1;
  }
  cell.circ_id = circ->p_circ_id;

  circuit_set_state(TO_CIRCUIT(circ), CIRCUIT_STATE_OPEN);

  log_debug(LD_CIRC,"init digest forward 0x%.8x, backward 0x%.8x.",
            (unsigned int)get_uint32(keys),
            (unsigned int)get_uint32(keys+20));
  if (relay_crypto_init(&circ->crypto, keys, keys_len, 0, 0)<0) {
    log_warn(LD_BUG,"Circuit initialization failed");
    return -1;
  }

  memcpy(circ->rend_circ_nonce, rend_circ_nonce, DIGEST_LEN);

  int used_create_fast = (created_cell->cell_type == CELL_CREATED_FAST);

  append_cell_to_circuit_queue(TO_CIRCUIT(circ),
                               circ->p_chan, &cell, CELL_DIRECTION_IN, 0);
  log_debug(LD_CIRC,"Finished sending '%s' cell.",
            used_create_fast ? "created_fast" : "created");

  /* Ignore the local bit when ExtendAllowPrivateAddresses is set:
   * it violates the assumption that private addresses are local.
   * Also, many test networks run on local addresses, and
   * TestingTorNetwork sets ExtendAllowPrivateAddresses. */
  if ((!channel_is_local(circ->p_chan)
       || get_options()->ExtendAllowPrivateAddresses)
      && !channel_is_outgoing(circ->p_chan)) {
    /* record that we could process create cells from a non-local conn
     * that we didn't initiate; presumably this means that create cells
     * can reach us too. */
    router_orport_found_reachable();
  }

  return 0;
}
