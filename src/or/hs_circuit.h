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
void hs_circ_service_rp_has_opened(const hs_service_t *service,
                                   origin_circuit_t *circ);
int hs_circ_launch_intro_point(hs_service_t *service,
                               const hs_service_intro_point_t *ip,
                               extend_info_t *ei, time_t now);
int hs_circ_launch_rendezvous_point(const hs_service_t *service,
                                    const curve25519_public_key_t *onion_key,
                                    const uint8_t *rendezvous_cookie);

/* Cell API. */
int hs_circ_handle_intro_established(const hs_service_t *service,
                                     const hs_service_intro_point_t *ip,
                                     origin_circuit_t *circ,
                                     const uint8_t *payload,
                                     size_t payload_len);
int hs_circ_handle_introduce2(const hs_service_t *service,
                              const origin_circuit_t *circ,
                              hs_service_intro_point_t *ip,
                              const uint8_t *subcredential,
                              const uint8_t *payload, size_t payload_len);

/* e2e circuit API. */

int hs_circuit_setup_e2e_rend_circ(origin_circuit_t *circ,
                                   const uint8_t *ntor_key_seed,
                                   size_t seed_len,
                                   int is_service_side);
int hs_circuit_setup_e2e_rend_circ_legacy_client(origin_circuit_t *circ,
                                          const uint8_t *rend_cell_body);

#endif /* TOR_HS_CIRCUIT_H */

