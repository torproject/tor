/* Copyright (c) 2016-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_service.h
 * \brief Header file for hs_service.c.
 **/

#ifndef TOR_HS_SERVICE_H
#define TOR_HS_SERVICE_H

#include "or.h"
#include "hs/cell_establish_intro.h"

/* These functions are only used by unit tests and we need to expose them else
 * hs_service.o ends up with no symbols in libor.a which makes clang throw a
 * warning at compile time. See #21825. */

trn_cell_establish_intro_t *
generate_establish_intro_cell(const uint8_t *circuit_key_material,
                              size_t circuit_key_material_len);
ssize_t
get_establish_intro_payload(uint8_t *buf, size_t buf_len,
                            const trn_cell_establish_intro_t *cell);

#endif /* TOR_HS_SERVICE_H */

