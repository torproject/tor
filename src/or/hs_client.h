/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_client.h
 * \brief Header file containing client data for the HS subsytem.
 **/

#ifndef TOR_HS_CLIENT_H
#define TOR_HS_CLIENT_H

#include "crypto_ed25519.h"
#include "hs_descriptor.h"
#include "hs_ident.h"

void hs_client_note_connection_attempt_succeeded(
                                       const edge_connection_t *conn);

int hs_client_decode_descriptor(
                     const char *desc_str,
                     const ed25519_public_key_t *service_identity_pk,
                     hs_descriptor_t **desc);
int hs_client_any_intro_points_usable(const ed25519_public_key_t *service_pk,
                                      const hs_descriptor_t *desc);
int hs_client_refetch_hsdesc(const ed25519_public_key_t *identity_pk);

int hs_client_send_introduce1(origin_circuit_t *intro_circ,
                              origin_circuit_t *rend_circ);

void hs_client_circuit_has_opened(origin_circuit_t *circ);

int hs_client_receive_rendezvous_acked(origin_circuit_t *circ,
                                       const uint8_t *payload,
                                       size_t payload_len);
int hs_client_receive_introduce_ack(origin_circuit_t *circ,
                                    const uint8_t *payload,
                                    size_t payload_len);
int hs_client_receive_rendezvous2(origin_circuit_t *circ,
                                  const uint8_t *payload,
                                  size_t payload_len);

void hs_client_desc_has_arrived(const hs_ident_dir_conn_t *ident);

extend_info_t *hs_client_get_random_intro_from_edge(
                                          const edge_connection_t *edge_conn);

int hs_client_reextend_intro_circuit(origin_circuit_t *circ);

void hs_client_purge_state(void);

void hs_client_free_all(void);

#ifdef HS_CLIENT_PRIVATE

STATIC routerstatus_t *
pick_hsdir_v3(const ed25519_public_key_t *onion_identity_pk);

#endif

#endif /* TOR_HS_CLIENT_H */

