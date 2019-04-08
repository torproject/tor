/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef CRYPT_PATH_ST_H
#define CRYPT_PATH_ST_H

#include "core/or/relay_crypto_st.h"
struct crypto_dh_t;

#define CRYPT_PATH_MAGIC 0x70127012u

struct fast_handshake_state_t;
struct ntor_handshake_state_t;
struct crypto_dh_t;
struct onion_handshake_state_t {
  uint16_t tag;
  union {
    struct fast_handshake_state_t *fast;
    struct crypto_dh_t *tap;
    struct ntor_handshake_state_t *ntor;
  } u;
};

#ifdef CRYPT_PATH_PRIVATE

/* The private parts of crypt path that don't need to be exposed to all the
 * modules. */
struct crypt_path_private_t {
  /** Cryptographic state used for encrypting and authenticating relay
   * cells to and from this hop. */
  relay_crypto_t crypto;
};

#endif

/** Holds accounting information for a single step in the layered encryption
 * performed by a circuit.  Used only at the client edge of a circuit. */
struct crypt_path_t {
  uint32_t magic;

  /** Current state of the handshake as performed with the OR at this
   * step. */
  onion_handshake_state_t handshake_state;
  /** Diffie-hellman handshake state for performing an introduction
   * operations */
  struct crypto_dh_t *rend_dh_handshake_state;

  /** Negotiated key material shared with the OR at this step. */
  char rend_circ_nonce[DIGEST_LEN];/* KH in tor-spec.txt */

  /** Information to extend to the OR at this step. */
  extend_info_t *extend_info;

  /** Is the circuit built to this step?  Must be one of:
   *    - CPATH_STATE_CLOSED (The circuit has not been extended to this step)
   *    - CPATH_STATE_AWAITING_KEYS (We have sent an EXTEND/CREATE to this step
   *      and not received an EXTENDED/CREATED)
   *    - CPATH_STATE_OPEN (The circuit has been extended to this step) */
  uint8_t state;
#define CPATH_STATE_CLOSED 0
#define CPATH_STATE_AWAITING_KEYS 1
#define CPATH_STATE_OPEN 2
  struct crypt_path_t *next; /**< Link to next crypt_path_t in the circuit.
                              * (The list is circular, so the last node
                              * links to the first.) */
  struct crypt_path_t *prev; /**< Link to previous crypt_path_t in the
                              * circuit. */

  int package_window; /**< How many cells are we allowed to originate ending
                       * at this step? */
  int deliver_window; /**< How many cells are we willing to deliver originating
                       * at this step? */

  /* Private parts of the crypt_path. Eventually everything should be
   * private. */
  struct crypt_path_private_t *private;
};

#endif
