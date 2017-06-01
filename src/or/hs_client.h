/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_client.h
 * \brief Header file containing client data for the HS subsytem.
 **/

#ifndef TOR_HS_CLIENT_H
#define TOR_HS_CLIENT_H

#include "hs_descriptor.h"

void hs_client_note_connection_attempt_succeeded(
                                       const edge_connection_t *conn);

int hs_client_decode_descriptor(
                     const char *desc_str,
                     const ed25519_public_key_t *service_identity_pk,
                     hs_descriptor_t **desc);

#endif /* TOR_HS_CLIENT_H */

