/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_intropoint.h
 * \brief Header file for hs_intropoint.c.
 **/

#ifndef TOR_HS_INTRO_H
#define TOR_HS_INTRO_H

/* Authentication key type in an ESTABLISH_INTRO cell. */
enum hs_intro_auth_key_type {
  HS_INTRO_AUTH_KEY_TYPE_LEGACY0 = 0x00,
  HS_INTRO_AUTH_KEY_TYPE_LEGACY1 = 0x01,
  HS_INTRO_AUTH_KEY_TYPE_ED25519 = 0x02,
};

int hs_intro_received_establish_intro(or_circuit_t *circ, const uint8_t *request,
                                size_t request_len);

MOCK_DECL(int, hs_intro_send_intro_established_cell,(or_circuit_t *circ));

/* also used by rendservice.c */
int hs_intro_circuit_is_suitable(const or_circuit_t *circ);

#ifdef HS_INTROPOINT_PRIVATE

STATIC int
verify_establish_intro_cell(const hs_cell_establish_intro_t *out,
                            const uint8_t *circuit_key_material,
                            size_t circuit_key_material_len);

STATIC void
get_auth_key_from_establish_intro_cell(ed25519_public_key_t *auth_key_out,
                                       const hs_cell_establish_intro_t *cell);

#endif /* HS_INTROPOINT_PRIVATE */

#endif /* TOR_HS_INTRO_H */
