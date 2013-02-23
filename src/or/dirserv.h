/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file dirserv.h
 * \brief Header file for dirserv.c.
 **/

#ifndef TOR_DIRSERV_H
#define TOR_DIRSERV_H

/** What fraction (1 over this number) of the relay ID space do we
 * (as a directory authority) launch connections to at each reachability
 * test? */
#define REACHABILITY_MODULO_PER_TEST 128

/** How often (in seconds) do we launch reachability tests? */
#define REACHABILITY_TEST_INTERVAL 10

/** How many seconds apart are the reachability tests for a given relay? */
#define REACHABILITY_TEST_CYCLE_PERIOD \
  (REACHABILITY_TEST_INTERVAL*REACHABILITY_MODULO_PER_TEST)

/** Maximum length of an exit policy summary. */
#define MAX_EXITPOLICY_SUMMARY_LEN 1000

/** Maximum allowable length of a version line in a networkstatus. */
#define MAX_V_LINE_LEN 128
/** Length of "r Authority BadDirectory BadExit Exit Fast Guard HSDir Named
 * Running Stable Unnamed V2Dir Valid\n". */
#define MAX_FLAG_LINE_LEN 96
/** Length of "w" line for weighting.  Currently at most
 * "w Bandwidth=<uint32t> Measured=<uint32t>\n" */
#define MAX_WEIGHT_LINE_LEN (12+10+10+10+1)
/** Maximum length of an exit policy summary line. */
#define MAX_POLICY_LINE_LEN (3+MAX_EXITPOLICY_SUMMARY_LEN)

int connection_dirserv_flushed_some(dir_connection_t *conn);

int dirserv_add_own_fingerprint(const char *nickname, crypto_pk_t *pk);
int dirserv_load_fingerprint_file(void);
void dirserv_free_fingerprint_list(void);
const char *dirserv_get_nickname_by_digest(const char *digest);
enum was_router_added_t dirserv_add_multiple_descriptors(
                                     const char *desc, uint8_t purpose,
                                     const char *source,
                                     const char **msg);
enum was_router_added_t dirserv_add_descriptor(routerinfo_t *ri,
                                               const char **msg,
                                               const char *source);
void dirserv_set_router_is_running(routerinfo_t *router, time_t now);
int list_server_status_v1(smartlist_t *routers, char **router_status_out,
                          int for_controller);
int dirserv_dump_directory_to_string(char **dir_out,
                                     crypto_pk_t *private_key);
char *dirserv_get_flag_thresholds_line(void);

int directory_fetches_from_authorities(const or_options_t *options);
int directory_fetches_dir_info_early(const or_options_t *options);
int directory_fetches_dir_info_later(const or_options_t *options);
int directory_caches_v2_dir_info(const or_options_t *options);
#define directory_caches_v1_dir_info(o) directory_caches_v2_dir_info(o)
int directory_caches_unknown_auth_certs(const or_options_t *options);
int directory_caches_dir_info(const or_options_t *options);
int directory_permits_begindir_requests(const or_options_t *options);
int directory_permits_controller_requests(const or_options_t *options);
int directory_too_idle_to_fetch_descriptors(const or_options_t *options,
                                            time_t now);

void directory_set_dirty(void);
cached_dir_t *dirserv_get_directory(void);
cached_dir_t *dirserv_get_runningrouters(void);
cached_dir_t *dirserv_get_consensus(const char *flavor_name);
void dirserv_set_cached_networkstatus_v2(const char *directory,
                                         const char *identity,
                                         time_t published);
void dirserv_set_cached_consensus_networkstatus(const char *consensus,
                                                const char *flavor_name,
                                                const digests_t *digests,
                                                time_t published);
void dirserv_clear_old_networkstatuses(time_t cutoff);
void dirserv_clear_old_v1_info(time_t now);
void dirserv_get_networkstatus_v2(smartlist_t *result, const char *key);
void dirserv_get_networkstatus_v2_fingerprints(smartlist_t *result,
                                               const char *key);
int dirserv_get_routerdesc_fingerprints(smartlist_t *fps_out, const char *key,
                                        const char **msg,
                                        int for_unencrypted_conn,
                                        int is_extrainfo);
int dirserv_get_routerdescs(smartlist_t *descs_out, const char *key,
                            const char **msg);
void dirserv_orconn_tls_done(const tor_addr_t *addr,
                             uint16_t or_port,
                             const char *digest_rcvd);
int dirserv_should_launch_reachability_test(const routerinfo_t *ri,
                                            const routerinfo_t *ri_old);
void dirserv_single_reachability_test(time_t now, routerinfo_t *router);
void dirserv_test_reachability(time_t now);
int authdir_wants_to_reject_router(routerinfo_t *ri, const char **msg,
                                   int complain,
                                   int *valid_out);
uint32_t dirserv_router_get_status(const routerinfo_t *router,
                                   const char **msg);
void dirserv_set_node_flags_from_authoritative_status(node_t *node,
                                                      uint32_t authstatus);

int dirserv_would_reject_router(const routerstatus_t *rs);
int dirserv_remove_old_statuses(smartlist_t *fps, time_t cutoff);
int dirserv_have_any_serverdesc(smartlist_t *fps, int spool_src);
int dirserv_have_any_microdesc(const smartlist_t *fps);
size_t dirserv_estimate_data_size(smartlist_t *fps, int is_serverdescs,
                                  int compressed);
size_t dirserv_estimate_microdesc_size(const smartlist_t *fps, int compressed);

char *routerstatus_format_entry(
                              const routerstatus_t *rs, const char *platform,
                              routerstatus_format_type_t format,
                              const vote_routerstatus_t *vrs);
void dirserv_free_all(void);
void cached_dir_decref(cached_dir_t *d);
cached_dir_t *new_cached_dir(char *s, time_t published);

#ifdef DIRSERV_PRIVATE
int measured_bw_line_parse(measured_bw_line_t *out, const char *line);

int measured_bw_line_apply(measured_bw_line_t *parsed_line,
                           smartlist_t *routerstatuses);
#endif

int dirserv_read_measured_bandwidths(const char *from_file,
                                     smartlist_t *routerstatuses);

#endif

