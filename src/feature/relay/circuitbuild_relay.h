/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file circuitbuild_relay.h
 * @brief Header for feature/relay/circuitbuild_relay.c
 **/

#ifndef TOR_FEATURE_RELAY_CIRCUITBUILD_RELAY_H
#define TOR_FEATURE_RELAY_CIRCUITBUILD_RELAY_H

#include "lib/cc/torint.h"

struct cell_t;
struct created_cell_t;

struct circuit_t;
struct or_circuit_t;

#ifdef HAVE_MODULE_RELAY

int circuit_extend(struct cell_t *cell, struct circuit_t *circ);

int onionskin_answer(struct or_circuit_t *circ,
                     const struct created_cell_t *created_cell,
                     const char *keys, size_t keys_len,
                     const uint8_t *rend_circ_nonce);

#else

static inline int
circuit_extend(struct cell_t *cell, struct circuit_t *circ)
{
  (void)cell;
  (void)circ;
  tor_assert_nonfatal_unreached();
  return -1;
}

static inline int
onionskin_answer(struct or_circuit_t *circ,
                 const struct created_cell_t *created_cell,
                 const char *keys, size_t keys_len,
                 const uint8_t *rend_circ_nonce)
{
  (void)circ;
  (void)created_cell;
  (void)keys;
  (void)keys_len;
  (void)rend_circ_nonce;
  tor_assert_nonfatal_unreached();
  return -1;
}

#endif

#endif /* !defined(TOR_FEATURE_RELAY_CIRCUITBUILD_RELAY_H) */
