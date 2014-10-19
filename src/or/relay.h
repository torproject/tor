/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relay.h
 * \brief Header file for relay.c.
 **/

#ifndef _TOR_RELAY_H
#define _TOR_RELAY_H

extern uint64_t stats_n_relay_cells_relayed;
extern uint64_t stats_n_relay_cells_delivered;

int circuit_receive_relay_cell(cell_t *cell, circuit_t *circ,
                               cell_direction_t cell_direction);

void relay_header_pack(uint8_t *dest, const relay_header_t *src);
void relay_header_unpack(relay_header_t *dest, const uint8_t *src);
int relay_send_command_from_edge(streamid_t stream_id, circuit_t *circ,
                               uint8_t relay_command, const char *payload,
                               size_t payload_len, crypt_path_t *cpath_layer);
int connection_edge_send_command(edge_connection_t *fromconn,
                                 uint8_t relay_command, const char *payload,
                                 size_t payload_len);
int connection_edge_package_raw_inbuf(edge_connection_t *conn,
                                      int package_partial,
                                      int *max_cells);
void connection_edge_consider_sending_sendme(edge_connection_t *conn);

extern uint64_t stats_n_data_cells_packaged;
extern uint64_t stats_n_data_bytes_packaged;
extern uint64_t stats_n_data_cells_received;
extern uint64_t stats_n_data_bytes_received;

void init_cell_pool(void);
void free_cell_pool(void);
void clean_cell_pool(void);
void dump_cell_pool_usage(int severity);
size_t packed_cell_mem_cost(void);

void cell_queue_clear(cell_queue_t *queue);
void cell_queue_append(cell_queue_t *queue, packed_cell_t *cell);
void cell_queue_append_packed_copy(cell_queue_t *queue, const cell_t *cell);

void append_cell_to_circuit_queue(circuit_t *circ, or_connection_t *orconn,
                                  cell_t *cell, cell_direction_t direction,
                                  streamid_t fromstream);
void connection_or_unlink_all_active_circs(or_connection_t *conn);
int connection_or_flush_from_first_active_circuit(or_connection_t *conn,
                                                  int max, time_t now);
void assert_active_circuits_ok(or_connection_t *orconn);
void make_circuit_inactive_on_conn(circuit_t *circ, or_connection_t *conn);
void make_circuit_active_on_conn(circuit_t *circ, or_connection_t *conn);

int append_address_to_payload(uint8_t *payload_out, const tor_addr_t *addr);
const uint8_t *decode_address_from_payload(tor_addr_t *addr_out,
                                        const uint8_t *payload,
                                        int payload_len);
unsigned cell_ewma_get_tick(void);
void cell_ewma_set_scale_factor(const or_options_t *options,
                                const networkstatus_t *consensus);
void circuit_clear_cell_queue(circuit_t *circ, or_connection_t *orconn);

#ifdef RELAY_PRIVATE
int relay_crypt(circuit_t *circ, cell_t *cell, cell_direction_t cell_direction,
                crypt_path_t **layer_hint, char *recognized);
#endif

#endif

