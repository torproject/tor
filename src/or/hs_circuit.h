/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_circuit.h
 * \brief Header file containing circuit data for the whole HS subsytem.
 **/

#ifndef TOR_HS_CIRCUIT_H
#define TOR_HS_CIRCUIT_H

#include "or.h"
#include "crypto.h"
#include "crypto_ed25519.h"

#include "hs_service.h"

/* Circuit API. */
int hs_circ_service_intro_has_opened(hs_service_t *service,
                                     hs_service_intro_point_t *ip,
                                     const hs_service_descriptor_t *desc,
                                     origin_circuit_t *circ);
int hs_circ_launch_intro_point(hs_service_t *service,
                               const hs_service_intro_point_t *ip,
                               extend_info_t *ei, time_t now);

/* Cell API. */
void hs_circ_send_establish_intro(const hs_service_t *service,
                                  hs_service_intro_point_t *ip,
                                  origin_circuit_t *circ);

/* e2e circuit API. */

int hs_circuit_setup_e2e_rend_circ(origin_circuit_t *circ,
                                   const uint8_t *ntor_key_seed,
                                   size_t seed_len,
                                   int is_service_side);
int hs_circuit_setup_e2e_rend_circ_legacy_client(origin_circuit_t *circ,
                                          const uint8_t *rend_cell_body);

#endif /* TOR_HS_CIRCUIT_H */

