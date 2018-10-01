/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file routerparse.h
 * \brief Header file for routerparse.c.
 **/

#ifndef TOR_ROUTERPARSE_H
#define TOR_ROUTERPARSE_H

#include "core/or/versions.h"

enum networkstatus_type_t;

int router_get_router_hash(const char *s, size_t s_len, char *digest);
int router_get_networkstatus_v3_hashes(const char *s,
                                       common_digests_t *digests);
int router_get_networkstatus_v3_signed_boundaries(const char *s,
                                                  const char **start_out,
                                                  const char **end_out);
int router_get_networkstatus_v3_sha3_as_signed(uint8_t *digest_out,
                                               const char *s);
int router_get_extrainfo_hash(const char *s, size_t s_len, char *digest);

int router_parse_list_from_string(const char **s, const char *eos,
                                  smartlist_t *dest,
                                  saved_location_t saved_location,
                                  int is_extrainfo,
                                  int allow_annotations,
                                  const char *prepend_annotations,
                                  smartlist_t *invalid_digests_out);

routerinfo_t *router_parse_entry_from_string(const char *s, const char *end,
                                             int cache_copy,
                                             int allow_annotations,
                                             const char *prepend_annotations,
                                             int *can_dl_again_out);
struct digest_ri_map_t;
extrainfo_t *extrainfo_parse_entry_from_string(const char *s, const char *end,
                             int cache_copy, struct digest_ri_map_t *routermap,
                             int *can_dl_again_out);
MOCK_DECL(addr_policy_t *, router_parse_addr_policy_item_from_string,
         (const char *s, int assume_action, int *malformed_list));

void assert_addr_policy_ok(smartlist_t *t);

int compare_vote_routerstatus_entries(const void **_a, const void **_b);
int networkstatus_verify_bw_weights(networkstatus_t *ns, int);
networkstatus_t *networkstatus_parse_vote_from_string(const char *s,
                                           const char **eos_out,
                                           enum networkstatus_type_t ns_type);
ns_detached_signatures_t *networkstatus_parse_detached_signatures(
                                          const char *s, const char *eos);

smartlist_t *microdescs_parse_from_string(const char *s, const char *eos,
                                          int allow_annotations,
                                          saved_location_t where,
                                          smartlist_t *invalid_digests_out);

void routerparse_init(void);
void routerparse_free_all(void);

#ifdef ROUTERPARSE_PRIVATE
STATIC int routerstatus_parse_guardfraction(const char *guardfraction_str,
                                            networkstatus_t *vote,
                                            vote_routerstatus_t *vote_rs,
                                            routerstatus_t *rs);
struct memarea_t;
STATIC routerstatus_t *routerstatus_parse_entry_from_string(
                                     struct memarea_t *area,
                                     const char **s, smartlist_t *tokens,
                                     networkstatus_t *vote,
                                     vote_routerstatus_t *vote_rs,
                                     int consensus_method,
                                     consensus_flavor_t flav);
STATIC void summarize_protover_flags(protover_summary_flags_t *out,
                                     const char *protocols,
                                     const char *version);
#endif /* defined(ROUTERPARSE_PRIVATE) */

#define ED_DESC_SIGNATURE_PREFIX "Tor router descriptor signature v1"

#endif /* !defined(TOR_ROUTERPARSE_H) */
