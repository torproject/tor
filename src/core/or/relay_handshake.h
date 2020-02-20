/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file relay_handshake.h
 * @brief Header for core/or/relay_handshake.c
 **/

#ifndef TOR_CORE_OR_RELAY_HANDSHAKE_H
#define TOR_CORE_OR_RELAY_HANDSHAKE_H

struct ed25519_keypair_t;

int connection_or_send_certs_cell(or_connection_t *conn);
int connection_or_send_auth_challenge_cell(or_connection_t *conn);

var_cell_t *connection_or_compute_authenticate_cell_body(
                              or_connection_t *conn,
                              const int authtype,
                              crypto_pk_t *signing_key,
                              const struct ed25519_keypair_t *ed_signing_key,
                              int server);

int authchallenge_type_is_supported(uint16_t challenge_type);
int authchallenge_type_is_better(uint16_t challenge_type_a,
                                 uint16_t challenge_type_b);

MOCK_DECL(int,connection_or_send_authenticate_cell,
          (or_connection_t *conn, int type));

#ifdef TOR_UNIT_TESTS
extern int certs_cell_ed25519_disabled_for_testing;
#endif

#endif /* !defined(TOR_CORE_OR_RELAY_HANDSHAKE_H) */
