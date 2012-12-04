/* Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_ONION_NTOR_H
#define TOR_ONION_NTOR_H

#include "torint.h"
#include "crypto_curve25519.h"
#include "di_ops.h"

/** State to be maintained by a client between sending an ntor onionskin
 * and receiving a reply. */
typedef struct ntor_handshake_state_t ntor_handshake_state_t;

/** Length of an ntor onionskin, as sent from the client to server. */
#define NTOR_ONIONSKIN_LEN 84
/** Length of an ntor reply, as sent from server to client. */
#define NTOR_REPLY_LEN 64

/** A paired public and private key for curve25519.
 * XXXX024 move this structure somewhere smarter.
 **/
typedef struct curve25519_keypair_t {
  curve25519_public_key_t pubkey;
  curve25519_secret_key_t seckey;
} curve25519_keypair_t;

void ntor_handshake_state_free(ntor_handshake_state_t *state);

int onion_skin_ntor_create(const uint8_t *router_id,
                           const curve25519_public_key_t *router_key,
                           ntor_handshake_state_t **handshake_state_out,
                           uint8_t *onion_skin_out);

int onion_skin_ntor_server_handshake(const uint8_t *onion_skin,
                                 const di_digest256_map_t *private_keys,
                                 const uint8_t *my_node_id,
                                 uint8_t *handshake_reply_out,
                                 uint8_t *key_out,
                                 size_t key_out_len);

int onion_skin_ntor_client_handshake(
                             const ntor_handshake_state_t *handshake_state,
                             const uint8_t *handshake_reply,
                             uint8_t *key_out,
                             size_t key_out_len);

#endif

