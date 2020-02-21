/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file clientkey.h
 * @brief Header for feature/relay/clientkey.c
 **/

#ifndef TOR_FEATURE_RELAY_CLIENTKEY_H
#define TOR_FEATURE_RELAY_CLIENTKEY_H

int router_initialize_tls_context(void);
int init_keys_client(void);
void set_client_identity_key(crypto_pk_t *k);
crypto_pk_t *get_tlsclient_identity_key(void);
int client_identity_key_is_set(void);

void clientkey_free_all(void);

#endif /* !defined(TOR_FEATURE_RELAY_CLIENTKEY_H) */
