/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitbuild.h
 * \brief Header file for circuitbuild.c.
 **/

#ifndef TOR_CIRCUITBUILD_H
#define TOR_CIRCUITBUILD_H

char *circuit_list_path(origin_circuit_t *circ, int verbose);
char *circuit_list_path_for_controller(origin_circuit_t *circ);
void circuit_log_path(int severity, unsigned int domain,
                      origin_circuit_t *circ);
void circuit_rep_hist_note_result(origin_circuit_t *circ);
origin_circuit_t *origin_circuit_init(uint8_t purpose, int flags);
origin_circuit_t *circuit_establish_circuit(uint8_t purpose,
                                            extend_info_t *exit,
                                            int flags);
int circuit_handle_first_hop(origin_circuit_t *circ);
void circuit_n_chan_done(channel_t *chan, int status);
int inform_testing_reachability(void);
int circuit_timeout_want_to_count_circ(origin_circuit_t *circ);
int circuit_send_next_onion_skin(origin_circuit_t *circ);
void circuit_note_clock_jumped(int seconds_elapsed);
int circuit_extend(cell_t *cell, circuit_t *circ);
int circuit_init_cpath_crypto(crypt_path_t *cpath, const char *key_data,
                              int reverse);
int circuit_finish_handshake(origin_circuit_t *circ, uint8_t cell_type,
                             const uint8_t *reply);
int circuit_truncated(origin_circuit_t *circ, crypt_path_t *layer,
                      int reason);
int onionskin_answer(or_circuit_t *circ, uint8_t cell_type,
                     const char *payload, size_t payload_len,
                     const char *keys);
int circuit_all_predicted_ports_handled(time_t now, int *need_uptime,
                                        int *need_capacity);

int circuit_append_new_exit(origin_circuit_t *circ, extend_info_t *info);
int circuit_extend_to_new_exit(origin_circuit_t *circ, extend_info_t *info);
void onion_append_to_cpath(crypt_path_t **head_ptr, crypt_path_t *new_hop);
extend_info_t *extend_info_new(const char *nickname, const char *digest,
                                 crypto_pk_t *onion_key,
                                 const tor_addr_t *addr, uint16_t port);
extend_info_t *extend_info_from_node(const node_t *r, int for_direct_connect);
extend_info_t *extend_info_dup(extend_info_t *info);
void extend_info_free(extend_info_t *info);
const node_t *build_state_get_exit_node(cpath_build_state_t *state);
const char *build_state_get_exit_nickname(cpath_build_state_t *state);

const node_t *choose_good_entry_server(uint8_t purpose,
                                       cpath_build_state_t *state);
double pathbias_get_disable_rate(const or_options_t *options);

#endif

