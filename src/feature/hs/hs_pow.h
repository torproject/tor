/* Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_pow.h
 * \brief Header file containing PoW denial of service defenses for the HS
 *        subsystem for all versions.
 **/

#ifndef TOR_HS_POW_H
#define TOR_HS_POW_H

typedef unsigned __int128 uint128_t;

#include "ext/equix/include/equix.h"

#include "lib/evloop/compat_libevent.h"
#include "lib/smartlist_core/smartlist_core.h"

#define HS_POW_SUGGESTED_EFFORT_DEFAULT 100 // HRPR TODO 5000
/* Service updates the suggested effort every HS_UPDATE_PERIOD seconds. */
#define HS_UPDATE_PERIOD 300 // HRPR TODO Should be consensus

/** Length of random nonce (N) used in the PoW scheme. */
#define HS_POW_NONCE_LEN 16
/** Length of an E-quiX solution (S) in bytes. */
#define HS_POW_EQX_SOL_LEN 16
/** Length of blake2b hash result (R) used in the PoW scheme. */
#define HS_POW_HASH_LEN 4
/** Length of random seed used in the PoW scheme. */
#define HS_POW_SEED_LEN 32
/** Length of an effort value */
#define HS_POW_EFFORT_LEN sizeof(uint32_t)
/** Length of a PoW challenge. Construction as per prop327 is:
 *    (C || N || INT_32(E))
 */
#define HS_POW_CHALLENGE_LEN \
  (HS_POW_SEED_LEN + HS_POW_NONCE_LEN + HS_POW_EFFORT_LEN)

/** Type of PoW in the descriptor. */
typedef enum {
  HS_POW_DESC_V1 = 1,
} hs_pow_desc_type_t;

/** Proof-of-Work parameters for DoS defense located in a descriptor. */
typedef struct hs_pow_desc_params_t {
  /** Type of PoW system being used. */
  hs_pow_desc_type_t type;

  /** Random 32-byte seed used as input the the PoW hash function. Decoded? */
  uint8_t seed[HS_POW_SEED_LEN];

  /** Specifies effort value that clients should aim for when contacting the
   * service. */
  uint32_t suggested_effort;

  /** Timestamp after which the above seed expires. */
  time_t expiration_time;
} hs_pow_desc_params_t;

/** State and parameters of PoW defenses, stored in the service state. */
typedef struct hs_pow_service_state_t {
  /* If PoW defenses are enabled this is a priority queue containing acceptable
   * requests that are awaiting rendezvous circuits to built, where priority is
   * based on the amount of effort that was exerted in the PoW. */
  smartlist_t *rend_request_pqueue;

  /* HRPR TODO Is this cursed? Including compat_libevent for this. feb 24 */
  /* When PoW defenses are enabled, this event pops rendezvous requests from
   * the service's priority queue; higher effort is higher priority. */
  mainloop_event_t *pop_pqueue_ev;

  /* The current seed being used in the PoW defenses. */
  uint8_t seed_current[HS_POW_SEED_LEN];

  /* The previous seed that was used in the PoW defenses. We accept solutions
   * for both the current and previous seed.  */
  uint8_t seed_previous[HS_POW_SEED_LEN];

  /* The time at which the current seed expires and rotates for a new one. */
  time_t expiration_time;

  /* The minimum effort required for a valid solution. */
  uint32_t min_effort;

  /* The suggested effort that clients should use in order for their request to
   * be serviced in a timely manner. */
  uint32_t suggested_effort;

  /* The following values are used when calculating and updating the suggested
   * effort every HS_UPDATE_PERIOD seconds. */

  /* Number of intro requests the service can handle per second. */
  uint32_t svc_bottom_capacity;
  /* The next time at which to update the suggested effort. */
  time_t next_effort_update;
  /* Sum of effort of all valid requests received since the last update. */
  uint64_t total_effort;
} hs_pow_service_state_t;

/* Struct to store a solution to the PoW challenge. */
typedef struct hs_pow_solution_t {
  /** HRPR TODO are we best off storing this as a byte array, as trunnel doesnt
   * support uint128 (?) */
  /* The 16 byte nonce used in the solution. */
  uint128_t nonce;

  /* The effort used in the solution. */
  uint32_t effort;

  /* The first four bytes of the seed used in the solution. */
  uint32_t seed_head;

  /* The Equi-X solution used in the solution. */
  equix_solution equix_solution;
} hs_pow_solution_t;

/* API */
int hs_pow_solve(const hs_pow_desc_params_t *pow_params,
                 hs_pow_solution_t *pow_solution_out);

int hs_pow_verify(const hs_pow_service_state_t *pow_state,
                  const hs_pow_solution_t *pow_solution);

void hs_pow_remove_seed_from_cache(uint32_t seed);
void hs_pow_free_service_state(hs_pow_service_state_t *state);

#endif /* !defined(TOR_HS_POW_H) */
