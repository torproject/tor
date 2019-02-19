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

/* Sending SENDME cell. */
void sendme_connection_edge_consider_sending(edge_connection_t *edge_conn);
void sendme_circuit_consider_sending(circuit_t *circ,
                                     crypt_path_t *layer_hint);

/* Processing SENDME cell. */
int sendme_process_circuit_level(crypt_path_t *layer_hint,
                                 circuit_t *circ, const uint8_t *cell_payload,
                                 uint16_t cell_payload_len);
int sendme_process_stream_level(edge_connection_t *conn, circuit_t *circ,
                                uint16_t cell_body_len);

/* Update deliver window functions. */
int sendme_stream_data_received(edge_connection_t *conn);
int sendme_circuit_data_received(circuit_t *circ, crypt_path_t *layer_hint);

/* Update package window functions. */
int sendme_circuit_data_packaged(circuit_t *circ, crypt_path_t *layer_hint);
int sendme_stream_data_packaged(edge_connection_t *conn);

/* Track cell digest. */
void sendme_note_cell_digest(circuit_t *circ);

/* Private section starts. */
#ifdef SENDME_PRIVATE

/*
 * Unit tests declaractions.
 */
#ifdef TOR_UNIT_TESTS

STATIC int get_emit_min_version(void);
STATIC int get_accept_min_version(void);

STATIC bool cell_version_is_valid(uint8_t cell_version);

STATIC ssize_t build_cell_payload_v1(crypto_digest_t *cell_digest,
                                     uint8_t *payload);
STATIC bool sendme_is_valid(const circuit_t *circ,
                            const uint8_t *cell_payload,
                            size_t cell_payload_len);

#endif /* TOR_UNIT_TESTS */

#endif /* SENDME_PRIVATE */

#endif /* !defined(TOR_SENDME_H) */
