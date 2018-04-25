/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file dirvote.h
 * \brief Header file for dirvote.c.
 **/

#ifndef TOR_DIRVOTE_H
#define TOR_DIRVOTE_H

/*
 * Ideally, assuming synced clocks, we should only need 1 second for each of:
 *  - Vote
 *  - Distribute
 *  - Consensus Publication
 * As we can gather descriptors continuously.
 * (Could we even go as far as publishing the previous consensus,
 *  in the same second that we vote for the next one?)
 * But we're not there yet: these are the lowest working values at this time.
 */

/** Lowest allowable value for VoteSeconds. */
#define MIN_VOTE_SECONDS 2
/** Lowest allowable value for VoteSeconds when TestingTorNetwork is 1 */
#define MIN_VOTE_SECONDS_TESTING 2

/** Lowest allowable value for DistSeconds. */
#define MIN_DIST_SECONDS 2
/** Lowest allowable value for DistSeconds when TestingTorNetwork is 1 */
#define MIN_DIST_SECONDS_TESTING 2

/** Lowest allowable voting interval. */
#define MIN_VOTE_INTERVAL 300
/** Lowest allowable voting interval when TestingTorNetwork is 1:
 * Voting Interval can be:
 *   10, 12, 15, 18, 20, 24, 25, 30, 36, 40, 45, 50, 60, ...
 * Testing Initial Voting Interval can be:
 *    5,  6,  8,  9, or any of the possible values for Voting Interval,
 * as they both need to evenly divide 30 minutes.
 * If clock desynchronisation is an issue, use an interval of at least:
 *   18 * drift in seconds, to allow for a clock slop factor */
#define MIN_VOTE_INTERVAL_TESTING \
                (((MIN_VOTE_SECONDS_TESTING)+(MIN_DIST_SECONDS_TESTING)+1)*2)

#define MIN_VOTE_INTERVAL_TESTING_INITIAL \
                ((MIN_VOTE_SECONDS_TESTING)+(MIN_DIST_SECONDS_TESTING)+1)

/* A placeholder for routerstatus_format_entry() when the consensus method
 * argument is not applicable. */
#define ROUTERSTATUS_FORMAT_NO_CONSENSUS_METHOD 0

/** The lowest consensus method that we currently support. */
#define MIN_SUPPORTED_CONSENSUS_METHOD 25

/** The highest consensus method that we currently support. */
#define MAX_SUPPORTED_CONSENSUS_METHOD 28

/** Lowest consensus method where authorities vote on required/recommended
 * protocols. */
#define MIN_METHOD_FOR_RECOMMENDED_PROTOCOLS 25

/** Lowest consensus method where authorities add protocols to routerstatus
 * entries. */
#define MIN_METHOD_FOR_RS_PROTOCOLS 25

/** Lowest consensus method where authorities initialize bandwidth weights to 1
 * instead of 0. See #14881 */
#define MIN_METHOD_FOR_INIT_BW_WEIGHTS_ONE 26

/** Lowest consensus method where the microdesc consensus contains relay IPv6
 * addresses. See #23826 and #20916. */
#define MIN_METHOD_FOR_A_LINES_IN_MICRODESC_CONSENSUS 27

/** Lowest consensus method where microdescriptors do not contain relay IPv6
 * addresses. See #23828 and #20916. */
#define MIN_METHOD_FOR_NO_A_LINES_IN_MICRODESC 28

/** Default bandwidth to clip unmeasured bandwidths to using method >=
 * MIN_METHOD_TO_CLIP_UNMEASURED_BW.  (This is not a consensus method; do not
 * get confused with the above macros.) */
#define DEFAULT_MAX_UNMEASURED_BW_KB 20

/* Directory Get Vote (DGV) flags for dirvote_get_vote(). */
#define DGV_BY_ID 1
#define DGV_INCLUDE_PENDING 2
#define DGV_INCLUDE_PREVIOUS 4

/*
 * Public API. Used outside of the dirauth subsystem.
 */

void dirvote_free_all(void);

/* Vote manipulation */
void ns_detached_signatures_free_(ns_detached_signatures_t *s);
#define ns_detached_signatures_free(s) \
  FREE_AND_NULL(ns_detached_signatures_t, ns_detached_signatures_free_, (s))

void dirvote_recalculate_timing(const or_options_t *options, time_t now);
void dirvote_act(const or_options_t *options, time_t now);
/* Invoked on timers and by outside triggers. */
struct pending_vote_t * dirvote_add_vote(const char *vote_body,
                                         const char **msg_out,
                                         int *status_out);
int dirvote_add_signatures(const char *detached_signatures_body,
                           const char *source,
                           const char **msg_out);
/* Item access */
MOCK_DECL(const char*, dirvote_get_pending_consensus,
          (consensus_flavor_t flav));
MOCK_DECL(const char*, dirvote_get_pending_detached_signatures, (void));
const cached_dir_t *dirvote_get_vote(const char *fp, int flags);
document_signature_t *voter_get_sig_by_algorithm(
                           const networkstatus_voter_info_t *voter,
                           digest_algorithm_t alg);

/*
 * API used _only_ by the dirauth subsystem.
 */

/* Cert manipulation */
authority_cert_t *authority_cert_dup(authority_cert_t *cert);

void dirvote_get_preferred_voting_intervals(vote_timing_t *timing_out);
time_t dirvote_get_start_of_next_interval(time_t now,
                                          int interval,
                                          int offset);
time_t dirvote_get_next_valid_after_time(void);

void set_routerstatus_from_routerinfo(routerstatus_t *rs,
                                      node_t *node,
                                      routerinfo_t *ri, time_t now,
                                      int listbadexits);
networkstatus_t *
dirserv_generate_networkstatus_vote_obj(crypto_pk_t *private_key,
                                        authority_cert_t *cert);

vote_microdesc_hash_t *dirvote_format_all_microdesc_vote_lines(
                                        const routerinfo_t *ri,
                                        time_t now,
                                        smartlist_t *microdescriptors_out);

/*
 * Exposed functions for unit tests.
 */
#ifdef DIRVOTE_PRIVATE

STATIC int32_t dirvote_get_intermediate_param_value(
                                   const smartlist_t *param_list,
                                   const char *keyword,
                                   int32_t default_val);
STATIC char *format_networkstatus_vote(crypto_pk_t *private_key,
                                 networkstatus_t *v3_ns);
STATIC smartlist_t *dirvote_compute_params(smartlist_t *votes, int method,
                             int total_authorities);
STATIC char *compute_consensus_package_lines(smartlist_t *votes);
STATIC char *make_consensus_method_list(int low, int high, const char *sep);
STATIC int
networkstatus_compute_bw_weights_v10(smartlist_t *chunks, int64_t G,
                                     int64_t M, int64_t E, int64_t D,
                                     int64_t T, int64_t weight_scale);
STATIC
char *networkstatus_compute_consensus(smartlist_t *votes,
                                      int total_authorities,
                                      crypto_pk_t *identity_key,
                                      crypto_pk_t *signing_key,
                                      const char *legacy_identity_key_digest,
                                      crypto_pk_t *legacy_signing_key,
                                      consensus_flavor_t flavor);
STATIC
int networkstatus_add_detached_signatures(networkstatus_t *target,
                                          ns_detached_signatures_t *sigs,
                                          const char *source,
                                          int severity,
                                          const char **msg_out);
STATIC
char *networkstatus_get_detached_signatures(smartlist_t *consensuses);
STATIC microdesc_t *dirvote_create_microdescriptor(const routerinfo_t *ri,
                                                   int consensus_method);

#endif /* defined(DIRVOTE_PRIVATE) */

#endif /* !defined(TOR_DIRVOTE_H) */

