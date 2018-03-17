/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relay.h
 * \brief Header file for relay.c.
 **/

#ifndef TOR_RELAY_CRYPTO_H
#define TOR_RELAY_CRYPTO_H

int relay_decrypt_cell(circuit_t *circ, cell_t *cell,
                       cell_direction_t cell_direction,
                       crypt_path_t **layer_hint, char *recognized);
void relay_encrypt_cell_outbound(cell_t *cell, origin_circuit_t *or_circ,
                            crypt_path_t *layer_hint);
void relay_encrypt_cell_inbound(cell_t *cell, or_circuit_t *or_circ);

#endif /* !defined(TOR_RELAY_CRYPTO_H) */

