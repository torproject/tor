/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_client.h
 * \brief Header file containing client data for the HS subsytem.
 **/

#ifndef TOR_HS_CLIENT_H
#define TOR_HS_CLIENT_H

void hs_client_note_connection_attempt_succeeded(
                                       const edge_connection_t *conn);

#endif /* TOR_HS_CLIENT_H */

