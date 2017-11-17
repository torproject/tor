/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file directory.h
 * \brief Header file for directory.c.
 **/

#ifndef TOR_DIRECTORY_H
#define TOR_DIRECTORY_H

#include "hs_ident.h"

int directories_have_accepted_server_descriptor(void);
void directory_post_to_dirservers(uint8_t dir_purpose, uint8_t router_purpose,
                                  dirinfo_type_t type, const char *payload,
                                  size_t payload_len, size_t extrainfo_len);
MOCK_DECL(void, directory_get_from_dirserver, (
                          uint8_t dir_purpose,
                          uint8_t router_purpose,
                          const char *resource,
                          int pds_flags,
                          download_want_authority_t want_authority));
void directory_get_from_all_authorities(uint8_t dir_purpose,
                                        uint8_t router_purpose,
                                        const char *resource);

/** Enumeration of ways to connect to a directory server */
typedef enum {
  /** Default: connect over a one-hop Tor circuit. Relays fall back to direct
   * DirPort connections, clients, onion services, and bridges do not */
  DIRIND_ONEHOP=0,
  /** Connect over a multi-hop anonymizing Tor circuit */
  DIRIND_ANONYMOUS=1,
  /** Connect to the DirPort directly */
  DIRIND_DIRECT_CONN,
  /** Connect over a multi-hop anonymizing Tor circuit to our dirport */
  DIRIND_ANON_DIRPORT,
} dir_indirection_t;

int directory_must_use_begindir(const or_options_t *options);

/**
 * A directory_request_t describes the information about a directory request
 * at the client side.  It describes what we're going to ask for, which
 * directory we're going to ask for it, how we're going to contact that
 * directory, and (in some cases) what to do with it when we're done.
 */
typedef struct directory_request_t directory_request_t;
directory_request_t *directory_request_new(uint8_t dir_purpose);
void directory_request_free(directory_request_t *req);
void directory_request_set_or_addr_port(directory_request_t *req,
                                        const tor_addr_port_t *p);
void directory_request_set_dir_addr_port(directory_request_t *req,
                                         const tor_addr_port_t *p);
void directory_request_set_directory_id_digest(directory_request_t *req,
                                               const char *digest);
void directory_request_set_guard_state(directory_request_t *req,
                                       struct circuit_guard_state_t *state);
void directory_request_set_router_purpose(directory_request_t *req,
                                          uint8_t router_purpose);
void directory_request_set_indirection(directory_request_t *req,
                                       dir_indirection_t indirection);
void directory_request_set_resource(directory_request_t *req,
                                    const char *resource);
void directory_request_set_payload(directory_request_t *req,
                                   const char *payload,
                                   size_t payload_len);
void directory_request_set_if_modified_since(directory_request_t *req,
                                             time_t if_modified_since);
void directory_request_set_rend_query(directory_request_t *req,
                                      const rend_data_t *query);
void directory_request_upload_set_hs_ident(directory_request_t *req,
                                           const hs_ident_dir_conn_t *ident);
void directory_request_fetch_set_hs_ident(directory_request_t *req,
                                          const hs_ident_dir_conn_t *ident);

void directory_request_set_routerstatus(directory_request_t *req,
                                        const routerstatus_t *rs);
void directory_request_add_header(directory_request_t *req,
                                  const char *key,
                                  const char *val);
MOCK_DECL(void, directory_initiate_request, (directory_request_t *request));

int parse_http_response(const char *headers, int *code, time_t *date,
                        compress_method_t *compression, char **response);
int parse_http_command(const char *headers,
                       char **command_out, char **url_out);
char *http_get_header(const char *headers, const char *which);

int connection_dir_is_encrypted(const dir_connection_t *conn);
int connection_dir_reached_eof(dir_connection_t *conn);
int connection_dir_process_inbuf(dir_connection_t *conn);
int connection_dir_finished_flushing(dir_connection_t *conn);
int connection_dir_finished_connecting(dir_connection_t *conn);
void connection_dir_about_to_close(dir_connection_t *dir_conn);

#define DSR_HEX       (1<<0)
#define DSR_BASE64    (1<<1)
#define DSR_DIGEST256 (1<<2)
#define DSR_SORT_UNIQ (1<<3)
int dir_split_resource_into_fingerprints(const char *resource,
                                     smartlist_t *fp_out, int *compressed_out,
                                     int flags);
enum dir_spool_source_t;
int dir_split_resource_into_spoolable(const char *resource,
                                      enum dir_spool_source_t source,
                                      smartlist_t *spool_out,
                                      int *compressed_out,
                                      int flags);
int dir_split_resource_into_fingerprint_pairs(const char *res,
                                              smartlist_t *pairs_out);
char *directory_dump_request_log(void);
void note_request(const char *key, size_t bytes);
int router_supports_extrainfo(const char *identity_digest, int is_authority);

time_t download_status_increment_failure(download_status_t *dls,
                                         int status_code, const char *item,
                                         int server, time_t now);
time_t download_status_increment_attempt(download_status_t *dls,
                                         const char *item,  time_t now);
/** Increment the failure count of the download_status_t <b>dls</b>, with
 * the optional status code <b>sc</b>. */
#define download_status_failed(dls, sc)                                 \
  download_status_increment_failure((dls), (sc), NULL,                  \
                                    dir_server_mode(get_options()), \
                                    time(NULL))

void download_status_reset(download_status_t *dls);
static int download_status_is_ready(download_status_t *dls, time_t now,
                                    int max_failures);
time_t download_status_get_next_attempt_at(const download_status_t *dls);

/** Return true iff, as of <b>now</b>, the resource tracked by <b>dls</b> is
 * ready to get its download reattempted. */
static inline int
download_status_is_ready(download_status_t *dls, time_t now,
                         int max_failures)
{
  /* dls wasn't reset before it was used */
  if (dls->next_attempt_at == 0) {
    download_status_reset(dls);
  }

  if (dls->backoff == DL_SCHED_DETERMINISTIC) {
    /* Deterministic schedules can hit an endpoint; exponential backoff
     * schedules just wait longer and longer. */
    int under_failure_limit = (dls->n_download_failures <= max_failures
                               && dls->n_download_attempts <= max_failures);
    if (!under_failure_limit)
      return 0;
  }
  return download_status_get_next_attempt_at(dls) <= now;
}

static void download_status_mark_impossible(download_status_t *dl);
/** Mark <b>dl</b> as never downloadable. */
static inline void
download_status_mark_impossible(download_status_t *dl)
{
  dl->n_download_failures = IMPOSSIBLE_TO_DOWNLOAD;
  dl->n_download_attempts = IMPOSSIBLE_TO_DOWNLOAD;
}

int download_status_get_n_failures(const download_status_t *dls);
int download_status_get_n_attempts(const download_status_t *dls);

int purpose_needs_anonymity(uint8_t dir_purpose, uint8_t router_purpose,
                            const char *resource);

#ifdef DIRECTORY_PRIVATE

/** A structure to hold arguments passed into each directory response
 * handler */
typedef struct response_handler_args_t {
  int status_code;
  const char *reason;
  const char *body;
  size_t body_len;
  const char *headers;
} response_handler_args_t;

struct directory_request_t {
  /**
   * These fields specify which directory we're contacting.  Routerstatus,
   * if present, overrides the other fields.
   *
   * @{ */
  tor_addr_port_t or_addr_port;
  tor_addr_port_t dir_addr_port;
  char digest[DIGEST_LEN];

  const routerstatus_t *routerstatus;
  /** @} */
  /** One of DIR_PURPOSE_* other than DIR_PURPOSE_SERVER. Describes what
   * kind of operation we'll be doing (upload/download), and of what kind
   * of document. */
  uint8_t dir_purpose;
  /** One of ROUTER_PURPOSE_*; used for uploads and downloads of routerinfo
   * and extrainfo docs.  */
  uint8_t router_purpose;
  /** Enum: determines whether to anonymize, and whether to use dirport or
   * orport. */
  dir_indirection_t indirection;
  /** Alias to the variable part of the URL for this request */
  const char *resource;
  /** Alias to the payload to upload (if any) */
  const char *payload;
  /** Number of bytes to upload from payload</b> */
  size_t payload_len;
  /** Value to send in an if-modified-since header, or 0 for none. */
  time_t if_modified_since;
  /** Hidden-service-specific information v2. */
  const rend_data_t *rend_query;
  /** Extra headers to append to the request */
  config_line_t *additional_headers;
  /** Hidden-service-specific information for v3+. */
  const hs_ident_dir_conn_t *hs_ident;
  /** Used internally to directory.c: gets informed when the attempt to
   * connect to the directory succeeds or fails, if that attempt bears on the
   * directory's usability as a directory guard. */
  struct circuit_guard_state_t *guard_state;
};

struct get_handler_args_t;
STATIC int handle_get_hs_descriptor_v3(dir_connection_t *conn,
                                       const struct get_handler_args_t *args);
STATIC int directory_handle_command(dir_connection_t *conn);
STATIC char *accept_encoding_header(void);
STATIC int allowed_anonymous_connection_compression_method(compress_method_t);
STATIC void warn_disallowed_anonymous_compression_method(compress_method_t);

STATIC int handle_response_fetch_hsdesc_v3(dir_connection_t *conn,
                                          const response_handler_args_t *args);
STATIC int handle_response_fetch_microdesc(dir_connection_t *conn,
                                 const response_handler_args_t *args);

#endif /* defined(DIRECTORY_PRIVATE) */

#ifdef TOR_UNIT_TESTS
/* Used only by test_dir.c and test_hs_cache.c */

STATIC int parse_http_url(const char *headers, char **url);
STATIC dirinfo_type_t dir_fetch_type(int dir_purpose, int router_purpose,
                                     const char *resource);
MOCK_DECL(STATIC int, directory_handle_command_get,(dir_connection_t *conn,
                                                    const char *headers,
                                                    const char *req_body,
                                                    size_t req_body_len));
MOCK_DECL(STATIC int, directory_handle_command_post,(dir_connection_t *conn,
                                                     const char *headers,
                                                     const char *body,
                                                     size_t body_len));
STATIC int download_status_schedule_get_delay(download_status_t *dls,
                                              const smartlist_t *schedule,
                                              int min_delay, int max_delay,
                                              time_t now);

STATIC int handle_post_hs_descriptor(const char *url, const char *body);

STATIC char* authdir_type_to_string(dirinfo_type_t auth);
STATIC const char * dir_conn_purpose_to_string(int purpose);
STATIC int should_use_directory_guards(const or_options_t *options);
STATIC compression_level_t choose_compression_level(ssize_t n_bytes);
STATIC const smartlist_t *find_dl_schedule(const download_status_t *dls,
                                           const or_options_t *options);
STATIC void find_dl_min_and_max_delay(download_status_t *dls,
                                      const or_options_t *options,
                                      int *min, int *max);

STATIC int next_random_exponential_delay(int delay,
                                         int base_delay,
                                         int max_delay);

STATIC void next_random_exponential_delay_range(int *low_bound_out,
                                                int *high_bound_out,
                                                int delay,
                                                int base_delay);

STATIC int parse_hs_version_from_post(const char *url, const char *prefix,
                                      const char **end_pos);

STATIC unsigned parse_accept_encoding_header(const char *h);
#endif /* defined(TOR_UNIT_TESTS) */

#if defined(TOR_UNIT_TESTS) || defined(DIRECTORY_PRIVATE)
/* Used only by directory.c and test_dir.c */

/* no more than quadruple the previous delay (multiplier + 1) */
#define DIR_DEFAULT_RANDOM_MULTIPLIER (3)
/* no more than triple the previous delay */
#define DIR_TEST_NET_RANDOM_MULTIPLIER (2)

#endif /* defined(TOR_UNIT_TESTS) || defined(DIRECTORY_PRIVATE) */

#endif /* !defined(TOR_DIRECTORY_H) */

