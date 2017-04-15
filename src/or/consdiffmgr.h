/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_CONSDIFFMGR_H
#define TOR_CONSDIFFMGR_H

/**
 * Possible outcomes from trying to look up a given consensus diff.
 */
typedef enum consdiff_status_t {
  CONSDIFF_AVAILABLE,
  CONSDIFF_NOT_FOUND,
  CONSDIFF_IN_PROGRESS,
} consdiff_status_t;

typedef struct consdiff_cfg_t {
  uint32_t cache_max_age_hours;
  uint32_t cache_max_num;
} consdiff_cfg_t;

struct consensus_cache_entry_t; // from conscache.h

int consdiffmgr_add_consensus(const char *consensus,
                              const networkstatus_t *as_parsed);

consdiff_status_t consdiffmgr_find_diff_from(
                           struct consensus_cache_entry_t **entry_out,
                           consensus_flavor_t flavor,
                           int digest_type,
                           const uint8_t *digest,
                           size_t digestlen);
void consdiffmgr_rescan(void);
int consdiffmgr_cleanup(void);
void consdiffmgr_configure(const consdiff_cfg_t *cfg);
void consdiffmgr_free_all(void);

#ifdef CONSDIFFMGR_PRIVATE
STATIC consensus_cache_t *cdm_cache_get(void);
STATIC consensus_cache_entry_t *cdm_cache_lookup_consensus(
                          consensus_flavor_t flavor, time_t valid_after);
#endif

#endif

