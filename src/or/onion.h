/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file onion.h
 * \brief Header file for onion.c.
 **/

#ifndef TOR_ONION_H
#define TOR_ONION_H

int onion_pending_add(or_circuit_t *circ, char *onionskin);
or_circuit_t *onion_next_task(char **onionskin_out);
void onion_pending_remove(or_circuit_t *circ);
void clear_pending_onions(void);

typedef struct server_onion_keys_t {
  uint8_t my_identity[DIGEST_LEN];
  crypto_pk_t *onion_key;
  crypto_pk_t *last_onion_key;
#ifdef CURVE25519_ENABLED
  di_digest256_map_t *curve25519_key_map;
#endif
} server_onion_keys_t;

#define MAX_ONIONSKIN_CHALLENGE_LEN 255
#define MAX_ONIONSKIN_REPLY_LEN 255

void setup_server_onion_keys(server_onion_keys_t *keys);
void release_server_onion_keys(server_onion_keys_t *keys);

void onion_handshake_state_release(onion_handshake_state_t *state);

int onion_skin_create(int type,
                      const extend_info_t *node,
                      onion_handshake_state_t *state_out,
                      uint8_t *onion_skin_out);
int onion_skin_server_handshake(int type,
                      const uint8_t *onion_skin,
                      const server_onion_keys_t *keys,
                      uint8_t *reply_out,
                      uint8_t *keys_out, size_t key_out_len);
//                      uint8_t *rend_authenticator_out);
int onion_skin_client_handshake(int type,
                      const onion_handshake_state_t *handshake_state,
                      const uint8_t *reply,
                      uint8_t *keys_out, size_t key_out_len,
                      uint8_t *rend_authenticator_out);

#endif

