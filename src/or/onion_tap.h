/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file onion_tap.h
 * \brief Header file for onion_tap.c.
 **/

#ifndef TOR_ONION_TAP_H
#define TOR_ONION_TAP_H

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

#endif

