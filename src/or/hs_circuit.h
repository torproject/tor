/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_circuit.h
 * \brief Header file containing circuit data for the whole HS subsytem.
 **/

#ifndef TOR_HS_CIRCUIT_H
#define TOR_HS_CIRCUIT_H

#include "or.h"

/* e2e circuit API. */

int hs_circuit_setup_e2e_rend_circ(origin_circuit_t *circ,
                                   const uint8_t *ntor_key_seed,
                                   int is_service_side);
int hs_circuit_setup_e2e_rend_circ_legacy_client(origin_circuit_t *circ,
                                          const uint8_t *rend_cell_body);

#endif /* TOR_HS_CIRCUIT_H */

