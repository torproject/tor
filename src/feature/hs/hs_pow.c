/* Copyright (c) 2017-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_pow.c
 * \brief Contains code to handle proof-of-work computations
 * when a hidden service is defending against DoS attacks.
 **/

typedef unsigned __int128 uint128_t;

#include <blake2.h>
#include <stdio.h>

#include "ext/ht.h"
#include "feature/hs/hs_descriptor.h"
#include "feature/hs/hs_pow.h"
#include "lib/crypt_ops/crypto_rand.h"

/** Replay cache set up */
/** Cache entry for (nonce, seed) replay protection. */
typedef struct nonce_cache_entry_t {
  HT_ENTRY(nonce_cache_entry_t) node;
  uint128_t nonce;
  uint32_t seed_head;
} nonce_cache_entry_t;

/** Return true if the two (nonce, seed) replay cache entries are the same */
static inline int
nonce_cache_entries_eq_(const struct nonce_cache_entry_t *entry1,
                        const struct nonce_cache_entry_t *entry2)
{
  return entry1->nonce == entry2->nonce &&
         entry1->seed_head == entry2->seed_head;
}

/** Hash function to hash the (nonce, seed) tuple entry. */
static inline unsigned
nonce_cache_entry_hash_(const struct nonce_cache_entry_t *ent)
{
  return (unsigned)siphash24g(&ent->nonce, HS_POW_NONCE_LEN) + ent->seed_head;
}

static HT_HEAD(nonce_cache_table_ht, nonce_cache_entry_t)
  nonce_cache_table = HT_INITIALIZER();

HT_PROTOTYPE(nonce_cache_table_ht, nonce_cache_entry_t, node,
             nonce_cache_entry_hash_, nonce_cache_entries_eq_);

HT_GENERATE2(nonce_cache_table_ht, nonce_cache_entry_t, node,
             nonce_cache_entry_hash_, nonce_cache_entries_eq_, 0.6,
             tor_reallocarray_, tor_free_);

/** We use this to check if an entry in the replay cache is for a particular
 * seed head, so we know to remove it once the seed is no longer in use. */
static int
nonce_cache_entry_has_seed(nonce_cache_entry_t *ent, void *data)
{
  /* Returning nonzero makes HT_FOREACH_FN remove the element from the HT */
  return ent->seed_head == *(uint32_t *)data;
}

/** Helper: Increment a given nonce and set it in the challenge at the right
 * offset. Use by the solve function. */
static inline void
increment_and_set_nonce(uint128_t *nonce, uint8_t *challenge)
{
  (*nonce)++;
  memcpy(challenge + HS_POW_SEED_LEN, nonce, HS_POW_NONCE_LEN);
}

/* Helper: Build EquiX challenge (C || N || INT_32(E)) and return a newly
 * allocated buffer containing it. */
static uint8_t *
build_equix_challenge(const uint8_t *seed, const uint128_t nonce,
                      const uint32_t effort)
{
  /* Build EquiX challenge (C || N || INT_32(E)). */
  size_t offset = 0;
  uint8_t *challenge = tor_malloc_zero(HS_POW_CHALLENGE_LEN);

  memcpy(challenge, seed, HS_POW_SEED_LEN);
  offset += HS_POW_SEED_LEN;
  memcpy(challenge + offset, &nonce, HS_POW_NONCE_LEN);
  offset += HS_POW_NONCE_LEN;
  set_uint32(challenge + offset, tor_htonl(effort));
  offset += HS_POW_EFFORT_LEN;
  tor_assert(HS_POW_CHALLENGE_LEN == offset);

  return challenge;
}

/** Helper: Return true iff the given challenge and solution for the given
 * effort do validate as in: R * E <= UINT32_MAX. */
static bool
validate_equix_challenge(const uint8_t *challenge, const equix_solution *sol,
                         const uint32_t effort)
{
  /* Fail if R * E > UINT32_MAX. */
  uint8_t hash_result[HS_POW_HASH_LEN];
  blake2b_state b2_state;

  if (BUG(blake2b_init(&b2_state, HS_POW_HASH_LEN) < 0)) {
    return false;
  }

  /* Construct: blake2b(C || N || E || S) */
  blake2b_update(&b2_state, challenge, HS_POW_CHALLENGE_LEN);
  blake2b_update(&b2_state, (const uint8_t *) sol, HS_POW_EQX_SOL_LEN);
  blake2b_final(&b2_state, hash_result, HS_POW_HASH_LEN);

  /* Scale to 64 bit so we can avoid 32 bit overflow. */
  uint64_t RE = tor_htonl(get_uint32(hash_result)) * (uint64_t) effort;

  return RE <= UINT32_MAX;
}

/** Solve the EquiX/blake2b PoW scheme using the parameters in pow_params, and
 * store the solution in pow_solution_out. Returns 0 on success and -1
 * otherwise. Called by a client. */
int
hs_pow_solve(const hs_pow_desc_params_t *pow_params,
             hs_pow_solution_t *pow_solution_out)
{
  int ret = -1;
  uint128_t nonce;
  uint8_t *challenge = NULL;
  equix_ctx *ctx = NULL;

  tor_assert(pow_params);
  tor_assert(pow_solution_out);

  /* Select E (just using suggested for now) */
  uint32_t effort = pow_params->suggested_effort;

  /* Generate a random nonce N. */
  crypto_rand((char *)&nonce, sizeof(uint128_t));

  /* Build EquiX challenge (C || N || INT_32(E)). */
  challenge = build_equix_challenge(pow_params->seed, nonce, effort);

  ctx = equix_alloc(EQUIX_CTX_SOLVE);
  equix_solution solution[EQUIX_MAX_SOLS];

  /* We'll do a maximum of the nonce size iterations here which is the maximum
   * number of nonce we can try in an attempt to find a valid solution. */
  log_notice(LD_REND, "Solving proof of work");
  for (uint64_t i = 0; i < UINT64_MAX; i++) {
    /* Calculate S = equix_solve(C || N || E) */
    if (!equix_solve(ctx, challenge, HS_POW_CHALLENGE_LEN, solution)) {
      ret = -1;
      goto end;
    }
    const equix_solution *sol = &solution[0];

    equix_result result = equix_verify(ctx, challenge,
                                       HS_POW_CHALLENGE_LEN, sol);
    if (result != EQUIX_OK) {
      /* Go again with a new nonce. */
      increment_and_set_nonce(&nonce, challenge);
      continue;
    }

    /* Validate the challenge against the solution. */
    if (validate_equix_challenge(challenge, sol, effort)) {
      /* Store the nonce N. */
      pow_solution_out->nonce = nonce;
      /* Store the effort E. */
      pow_solution_out->effort = effort;
      /* We only store the first 4 bytes of the seed C. */
      pow_solution_out->seed_head = get_uint32(pow_params->seed);
      /* Store the solution S */
      memcpy(&pow_solution_out->equix_solution, sol,
             sizeof(pow_solution_out->equix_solution));

      /* Indicate success and we are done. */
      ret = 0;
      break;
    }

    /* Did not pass the R * E <= UINT32_MAX check. Increment the nonce and
     * try again. */
    increment_and_set_nonce(&nonce, challenge);
  }

 end:
  tor_free(challenge);
  equix_free(ctx);
  return ret;
}

/** Verify the solution in pow_solution using the service's current PoW
 * parameters found in pow_state. Returns 0 on success and -1 otherwise. Called
 * by the service. */
int
hs_pow_verify(const hs_pow_service_state_t *pow_state,
              const hs_pow_solution_t *pow_solution)
{
  int ret = -1;
  uint8_t *challenge = NULL;
  nonce_cache_entry_t search, *entry = NULL;
  equix_ctx *ctx = NULL;
  const uint8_t *seed = NULL;

  tor_assert(pow_state);
  tor_assert(pow_solution);

  /* Notice, but don't fail, if E = POW_EFFORT is lower than the minimum
   * effort. We will take whatever valid cells arrive, put them into the
   * pqueue, and get to whichever ones we get to. */
  if (pow_solution->effort < pow_state->min_effort) {
    log_info(LD_REND, "Effort %d used in solution is less than the minimum "
                      "effort %d required by the service. That's ok.",
                       pow_solution->effort, pow_state->min_effort);
  }

  /* Find a valid seed C that starts with the seed head. Fail if no such seed
   * exists. */
  if (get_uint32(pow_state->seed_current) == pow_solution->seed_head) {
    seed = pow_state->seed_current;
  } else if (get_uint32(pow_state->seed_previous) == pow_solution->seed_head) {
    seed = pow_state->seed_previous;
  } else {
    log_warn(LD_REND, "Seed head didn't match either seed.");
    goto done;
  }

  /* Fail if N = POW_NONCE is present in the replay cache. */
  search.nonce = pow_solution->nonce;
  search.seed_head = pow_solution->seed_head;
  entry = HT_FIND(nonce_cache_table_ht, &nonce_cache_table, &search);
  if (entry) {
    log_warn(LD_REND, "Found (nonce, seed) tuple in the replay cache.");
    goto done;
  }

  /* Build the challenge with the param we have. */
  challenge = build_equix_challenge(seed, pow_solution->nonce,
                                    pow_solution->effort);

  if (!validate_equix_challenge(challenge, &pow_solution->equix_solution,
                                pow_solution->effort)) {
    log_warn(LD_REND, "Equi-X solution and effort was too large.");
    goto done;
  }

  /* Fail if equix_verify(C || N || E, S) != EQUIX_OK */
  ctx = equix_alloc(EQUIX_CTX_SOLVE);

  equix_result result = equix_verify(ctx, challenge, HS_POW_CHALLENGE_LEN,
                                     &pow_solution->equix_solution);
  if (result != EQUIX_OK) {
    log_warn(LD_REND, "Verification of EquiX solution in PoW failed.");
    goto done;
  }

  /* PoW verified successfully. */
  ret = 0;

  /* Add the (nonce, seed) tuple to the replay cache. */
  entry = tor_malloc_zero(sizeof(nonce_cache_entry_t));
  entry->nonce = pow_solution->nonce;
  entry->seed_head = pow_solution->seed_head;
  HT_INSERT(nonce_cache_table_ht, &nonce_cache_table, entry);

 done:
  tor_free(challenge);
  equix_free(ctx);
  return ret;
}

/** Remove entries from the (nonce, seed) replay cache which are for the seed
 * beginning with seed_head. */
void
hs_pow_remove_seed_from_cache(uint32_t seed)
{
  /* If nonce_cache_entry_has_seed returns 1, the entry is removed. */
  HT_FOREACH_FN(nonce_cache_table_ht, &nonce_cache_table,
                nonce_cache_entry_has_seed, &seed);
}

/** Free a given PoW service state. */
void
hs_pow_free_service_state(hs_pow_service_state_t *state)
{
  if (state == NULL) {
    return;
  }
  smartlist_free(state->rend_request_pqueue);
  mainloop_event_free(state->pop_pqueue_ev);
  tor_free(state);
}
