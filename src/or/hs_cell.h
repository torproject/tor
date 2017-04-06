/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_cell.h
 * \brief Header file containing cell data for the whole HS subsytem.
 **/

#ifndef TOR_HS_CELL_H
#define TOR_HS_CELL_H

#include "or.h"
#include "hs_service.h"

/* Onion key type found in the INTRODUCE1 cell. */
typedef enum {
  HS_CELL_ONION_KEY_TYPE_NTOR = 1,
} hs_cell_onion_key_type_t;

/* This data structure contains data that we need to parse an INTRODUCE2 cell
 * which is used by the INTRODUCE2 cell parsing function. On a successful
 * parsing, the onion_pk and rendezvous_cookie will be populated with the
 * computed key material from the cell data. */
typedef struct hs_cell_introduce2_data_t {
  /*** Immutable Section. ***/

  /* Introduction point authentication public key. */
  const ed25519_public_key_t *auth_pk;
  /* Introduction point encryption keypair for the ntor handshake. */
  const curve25519_keypair_t *enc_kp;
  /* Subcredentials of the service. */
  const uint8_t *subcredential;
  /* Payload of the received encoded cell. */
  const uint8_t *payload;
  /* Size of the payload of the received encoded cell. */
  size_t payload_len;
  /* Is this a legacy introduction point? */
  unsigned int is_legacy : 1;

  /*** Muttable Section. ***/

  /* Onion public key computed using the INTRODUCE2 encrypted section. */
  curve25519_public_key_t onion_pk;
  /* Rendezvous cookie taken from the INTRODUCE2 encrypted section. */
  uint8_t rendezvous_cookie[REND_COOKIE_LEN];
  /* Client public key from the INTRODUCE2 encrypted section. */
  curve25519_public_key_t client_pk;
  /* Link specifiers of the rendezvous point. Contains link_specifier_t. */
  smartlist_t *link_specifiers;
  /* Replay cache of the introduction point. */
  replaycache_t *replay_cache;
} hs_cell_introduce2_data_t;

/* Build cell API. */
ssize_t hs_cell_build_establish_intro(const char *circ_nonce,
                                      const hs_service_intro_point_t *ip,
                                      uint8_t *cell_out);
ssize_t hs_cell_build_rendezvous1(const uint8_t *rendezvous_cookie,
                                  size_t rendezvous_cookie_len,
                                  const uint8_t *rendezvous_handshake_info,
                                  size_t rendezvous_handshake_info_len,
                                  uint8_t *cell_out);

/* Parse cell API. */
ssize_t hs_cell_parse_intro_established(const uint8_t *payload,
                                        size_t payload_len);
ssize_t hs_cell_parse_introduce2(hs_cell_introduce2_data_t *data,
                                 const origin_circuit_t *circ,
                                 const hs_service_t *service);

#endif /* TOR_HS_CELL_H */

