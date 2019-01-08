/* Copyright (c) 2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file sendme.h
 * \brief Header file for sendme.c.
 **/

#ifndef TOR_SENDME_H
#define TOR_SENDME_H

#include "core/or/edge_connection_st.h"
#include "core/or/crypt_path_st.h"
#include "core/or/circuit_st.h"

void sendme_connection_edge_consider_sending(edge_connection_t *edge_conn);
void sendme_circuit_consider_sending(circuit_t *circ,
                                     crypt_path_t *layer_hint);

int sendme_process_circuit_level(crypt_path_t *layer_hint,
                                 circuit_t *circ, uint16_t cell_body_len);
int sendme_process_stream_level(edge_connection_t *conn, circuit_t *circ,
                                uint16_t cell_body_len);

#endif /* !defined(TOR_SENDME_H) */
