/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_common.h
 * \brief Header file containing common data for the whole HS subsytem.
 **/

#ifndef TOR_HS_COMMON_H
#define TOR_HS_COMMON_H

#include "or.h"

/* Protocol version 2. Use this instead of hardcoding "2" in the code base,
 * this adds a clearer semantic to the value when used. */
#define HS_VERSION_TWO 2
/* Version 3 of the protocol (prop224). */
#define HS_VERSION_THREE 3

void rend_data_free(rend_data_t *data);
rend_data_t *rend_data_dup(const rend_data_t *data);
rend_data_t *rend_data_client_create(const char *onion_address,
                                     const char *desc_id,
                                     const char *cookie,
                                     rend_auth_type_t auth_type);
rend_data_t *rend_data_service_create(const char *onion_address,
                                      const char *pk_digest,
                                      const uint8_t *cookie,
                                      rend_auth_type_t auth_type);
const char *rend_data_get_address(const rend_data_t *rend_data);
const char *rend_data_get_desc_id(const rend_data_t *rend_data,
                                  uint8_t replica, size_t *len_out);
const uint8_t *rend_data_get_pk_digest(const rend_data_t *rend_data,
                                       size_t *len_out);

int hs_v3_protocol_is_enabled(void);

#endif /* TOR_HS_COMMON_H */

