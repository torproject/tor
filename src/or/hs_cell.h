/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_cell.h
 * \brief Header file containing cell data for the whole HS subsytem.
 **/

#ifndef TOR_HS_CELL_H
#define TOR_HS_CELL_H

#include "hs_service.h"

ssize_t hs_cell_build_establish_intro(const char *circ_nonce,
                                      const hs_service_intro_point_t *ip,
                                      uint8_t *cell_out);

ssize_t hs_cell_parse_intro_established(const uint8_t *payload,
                                        size_t payload_len);

#endif /* TOR_HS_CELL_H */

