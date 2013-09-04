/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitbuild.h
 * \brief Header file for circuitbuild.c.
 **/

#ifndef _TOR_CIRCUITBUILD_H
#define _TOR_CIRCUITBUILD_H

/** Represents a pluggable transport proxy used by a bridge. */
typedef struct {
  /** SOCKS version: One of PROXY_SOCKS4, PROXY_SOCKS5. */
  int socks_version;
  /** Name of pluggable transport protocol */
  char *name;
  /** Address of proxy */
  tor_addr_t addr;
  /** Port of proxy */
  uint16_t port;
  /** Boolean: We are re-parsing our transport list, and we are going to remove
   * this one if we don't find it in the list of configured transports. */
  unsigned marked_for_removal : 1;
} transport_t;

char *circuit_list_path(origin_circuit_t *circ, int verbose);
char *circuit_list_path_for_controller(origin_circuit_t *circ);
void circuit_log_path(int severity, unsigned int domain,
                      origin_circuit_t *circ);
void circuit_rep_hist_note_result(origin_circuit_t *circ);
int circuit_build_times_disabled(void);
origin_circuit_t *origin_circuit_init(uint8_t purpose, int flags);
origin_circuit_t *circuit_establish_circuit(uint8_t purpose,
                                            extend_info_t *exit,
                                            int flags);
int circuit_handle_first_hop(origin_circuit_t *circ);
void circuit_n_conn_done(or_connection_t *or_conn, int status);
int inform_testing_reachability(void);
int circuit_timeout_want_to_count_circ(origin_circuit_t *circ);
int circuit_send_next_onion_skin(origin_circuit_t *circ);
void circuit_note_clock_jumped(int seconds_elapsed);
int circuit_extend(cell_t *cell, circuit_t *circ);
int circuit_init_cpath_crypto(crypt_path_t *cpath, const char *key_data,
                              int reverse);
int circuit_finish_handshake(origin_circuit_t *circ, uint8_t cell_type,
                             const uint8_t *reply);
int circuit_truncated(origin_circuit_t *circ, crypt_path_t *layer);
int onionskin_answer(or_circuit_t *circ, uint8_t cell_type,
                     const char *payload, const char *keys);
int circuit_all_predicted_ports_handled(time_t now, int *need_uptime,
                                        int *need_capacity);

int circuit_append_new_exit(origin_circuit_t *circ, extend_info_t *info);
int circuit_extend_to_new_exit(origin_circuit_t *circ, extend_info_t *info);
void onion_append_to_cpath(crypt_path_t **head_ptr, crypt_path_t *new_hop);
extend_info_t *extend_info_alloc(const char *nickname, const char *digest,
                                 crypto_pk_t *onion_key,
                                 const tor_addr_t *addr, uint16_t port);
extend_info_t *extend_info_from_router(const routerinfo_t *r,
                                       int for_direct_connect);
extend_info_t *extend_info_from_node(const node_t *node,
                                     int for_direct_connect);
extend_info_t *extend_info_dup(extend_info_t *info);
void extend_info_free(extend_info_t *info);
const node_t *build_state_get_exit_node(cpath_build_state_t *state);
const char *build_state_get_exit_nickname(cpath_build_state_t *state);

void entry_guards_compute_status(const or_options_t *options, time_t now);
int entry_guard_register_connect_status(const char *digest, int succeeded,
                                        int mark_relay_status, time_t now);
void entry_nodes_should_be_added(void);
int entry_list_is_constrained(const or_options_t *options);
const node_t *choose_random_entry(cpath_build_state_t *state);
int entry_guards_parse_state(or_state_t *state, int set, char **msg);
void entry_guards_update_state(or_state_t *state);
int getinfo_helper_entry_guards(control_connection_t *conn,
                                const char *question, char **answer,
                                const char **errmsg);

void mark_bridge_list(void);
void sweep_bridge_list(void);
void mark_transport_list(void);
void sweep_transport_list(void);

int routerinfo_is_a_configured_bridge(const routerinfo_t *ri);
int node_is_a_configured_bridge(const node_t *node);
void learned_router_identity(const tor_addr_t *addr, uint16_t port,
                             const char *digest);
void bridge_add_from_config(const tor_addr_t *addr, uint16_t port,
                            const char *digest,
                            const char *transport_name);
void retry_bridge_descriptor_fetch_directly(const char *digest);
void fetch_bridge_descriptors(const or_options_t *options, time_t now);
void learned_bridge_descriptor(routerinfo_t *ri, int from_cache);
int any_bridge_descriptors_known(void);
int any_pending_bridge_descriptor_fetches(void);
int entries_known_but_down(const or_options_t *options);
void entries_retry_all(const or_options_t *options);

int any_bridges_dont_support_microdescriptors(void);

void entry_guards_free_all(void);

extern circuit_build_times_t circ_times;
int circuit_build_times_enough_to_compute(circuit_build_times_t *cbt);
void circuit_build_times_update_state(circuit_build_times_t *cbt,
                                      or_state_t *state);
int circuit_build_times_parse_state(circuit_build_times_t *cbt,
                                    or_state_t *state);
void circuit_build_times_count_timeout(circuit_build_times_t *cbt,
                                       int did_onehop);
int circuit_build_times_count_close(circuit_build_times_t *cbt,
                                    int did_onehop, time_t start_time);
void circuit_build_times_set_timeout(circuit_build_times_t *cbt);
int circuit_build_times_add_time(circuit_build_times_t *cbt,
                                 build_time_t time);
int circuit_build_times_needs_circuits(circuit_build_times_t *cbt);

int circuit_build_times_needs_circuits_now(circuit_build_times_t *cbt);
void circuit_build_times_init(circuit_build_times_t *cbt);
void circuit_build_times_free_timeouts(circuit_build_times_t *cbt);
void circuit_build_times_new_consensus_params(circuit_build_times_t *cbt,
                                              networkstatus_t *ns);
double circuit_build_times_timeout_rate(const circuit_build_times_t *cbt);
double circuit_build_times_close_rate(const circuit_build_times_t *cbt);

#ifdef CIRCUIT_PRIVATE
double circuit_build_times_calculate_timeout(circuit_build_times_t *cbt,
                                             double quantile);
build_time_t circuit_build_times_generate_sample(circuit_build_times_t *cbt,
                                                 double q_lo, double q_hi);
void circuit_build_times_initial_alpha(circuit_build_times_t *cbt,
                                       double quantile, double time_ms);
int circuit_build_times_update_alpha(circuit_build_times_t *cbt);
double circuit_build_times_cdf(circuit_build_times_t *cbt, double x);
void circuitbuild_running_unit_tests(void);
void circuit_build_times_reset(circuit_build_times_t *cbt);

/* Network liveness functions */
int circuit_build_times_network_check_changed(circuit_build_times_t *cbt);
#endif

/* Network liveness functions */
void circuit_build_times_network_is_live(circuit_build_times_t *cbt);
int circuit_build_times_network_check_live(circuit_build_times_t *cbt);
void circuit_build_times_network_circ_success(circuit_build_times_t *cbt);

/* DOCDOC circuit_build_times_get_bw_scale */
int circuit_build_times_get_bw_scale(networkstatus_t *ns);

void clear_transport_list(void);
int transport_add_from_config(const tor_addr_t *addr, uint16_t port,
                               const char *name, int socks_ver);
int transport_add(transport_t *t);
void transport_free(transport_t *transport);
transport_t *transport_new(const tor_addr_t *addr, uint16_t port,
                                      const char *name, int socks_ver);

/* DOCDOC find_transport_name_by_bridge_addrport */
const char *find_transport_name_by_bridge_addrport(const tor_addr_t *addr,
                                                   uint16_t port);

int find_transport_by_bridge_addrport(const tor_addr_t *addr, uint16_t port,
                                      const transport_t **transport);
transport_t *transport_get_by_name(const char *name);

#endif

