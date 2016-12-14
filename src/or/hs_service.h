/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_service.h
 * \brief Header file for hs_service.c.
 **/

#ifndef TOR_HS_SERVICE_H
#define TOR_HS_SERVICE_H

#include "or.h"
#include "hs/cell_establish_intro.h"

#ifdef HS_SERVICE_PRIVATE

#ifdef TOR_UNIT_TESTS

STATIC hs_cell_establish_intro_t *
generate_establish_intro_cell(const uint8_t *circuit_key_material,
                              size_t circuit_key_material_len);

STATIC ssize_t
get_establish_intro_payload(uint8_t *buf, size_t buf_len,
                            const hs_cell_establish_intro_t *cell);

#endif /* TOR_UNIT_TESTS */

#endif /* HS_SERVICE_PRIVATE */

#endif /* TOR_HS_SERVICE_H */
