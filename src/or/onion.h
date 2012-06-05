/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file onion.h
 * \brief Header file for onion.c.
 **/

#ifndef _TOR_ONION_H
#define _TOR_ONION_H

int onion_pending_add(or_circuit_t *circ, char *onionskin);
or_circuit_t *onion_next_task(char **onionskin_out);
void onion_pending_remove(or_circuit_t *circ);

int onion_skin_create(crypto_pk_t *router_key,
                      crypto_dh_t **handshake_state_out,
                      char *onion_skin_out);

int onion_skin_server_handshake(const char *onion_skin,
                                crypto_pk_t *private_key,
                                crypto_pk_t *prev_private_key,
                                char *handshake_reply_out,
                                char *key_out,
                                size_t key_out_len);

int onion_skin_client_handshake(crypto_dh_t *handshake_state,
                                const char *handshake_reply,
                                char *key_out,
                                size_t key_out_len);

int fast_server_handshake(const uint8_t *key_in,
                          uint8_t *handshake_reply_out,
                          uint8_t *key_out,
                          size_t key_out_len);

int fast_client_handshake(const uint8_t *handshake_state,
                          const uint8_t *handshake_reply_out,
                          uint8_t *key_out,
                          size_t key_out_len);

void clear_pending_onions(void);

#endif

