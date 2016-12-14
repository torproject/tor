/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_circuitmap.h
 * \brief Header file for hs_circuitmap.c.
 **/

#ifndef TOR_HS_CIRCUITMAP_H
#define TOR_HS_CIRCUITMAP_H

typedef HT_HEAD(hs_circuitmap_ht, or_circuit_t) hs_circuitmap_ht;

typedef struct hs_token_s hs_token_t;
struct or_circuit_t;

/** Public HS circuitmap API: */

struct or_circuit_t *hs_circuitmap_get_rend_circ(const uint8_t *cookie);
struct or_circuit_t *hs_circuitmap_get_intro_circ_v3(
                                        const ed25519_public_key_t *auth_key);
struct or_circuit_t *hs_circuitmap_get_intro_circ_v2(const uint8_t *digest);

void hs_circuitmap_register_rend_circ(struct or_circuit_t *circ,
                                      const uint8_t *cookie);
void hs_circuitmap_register_intro_circ_v2(struct or_circuit_t *circ,
                                          const uint8_t *digest);
void hs_circuitmap_register_intro_circ_v3(struct or_circuit_t *circ,
                                         const ed25519_public_key_t *auth_key);

void hs_circuitmap_remove_circuit(struct or_circuit_t *circ);

void hs_circuitmap_init(void);
void hs_circuitmap_free_all(void);

#ifdef HS_CIRCUITMAP_PRIVATE

/** Represents the type of HS token. */
typedef enum {
  /** A rendezvous cookie (128bit)*/
  HS_TOKEN_REND,
  /** A v2 introduction point pubkey (160bit) */
  HS_TOKEN_INTRO_V2,
  /** A v3 introduction point pubkey (256bit) */
  HS_TOKEN_INTRO_V3,
} hs_token_type_t;

/** Represents a token used in the HS protocol. Each such token maps to a
 *  specific introduction or rendezvous circuit. */
struct hs_token_s {
  /* Type of HS token. */
  hs_token_type_t type;

  /* The size of the token (depends on the type). */
  size_t token_len;

  /* The token itself. Memory allocated at runtime. */
  uint8_t *token;
};

#endif /* HS_CIRCUITMAP_PRIVATE */

#ifdef TOR_UNIT_TESTS

hs_circuitmap_ht *get_hs_circuitmap(void);

#endif /* TOR_UNIT_TESTS */

#endif /* TOR_HS_CIRCUITMAP_H */

