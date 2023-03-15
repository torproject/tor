/* Copyright (c) 2017-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_pow.c
 * \brief Contains code to handle proof-of-work computations
 * when a hidden service is defending against DoS attacks.
 **/

#include <stdio.h>

#include "ext/ht.h"
#include "ext/compat_blake2.h"
#include "core/or/circuitlist.h"
#include "core/or/origin_circuit_st.h"
#include "ext/equix/include/equix.h"
#include "feature/hs/hs_cache.h"
#include "feature/hs/hs_descriptor.h"
#include "feature/hs/hs_client.h"
#include "feature/hs/hs_pow.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/arch/bytes.h"
#include "lib/cc/ctassert.h"
#include "core/mainloop/cpuworker.h"
#include "lib/evloop/workqueue.h"

/** Replay cache set up */
/** Cache entry for (nonce, seed) replay protection. */
typedef struct nonce_cache_entry_t {
  HT_ENTRY(nonce_cache_entry_t) node;
  struct {
    uint8_t nonce[HS_POW_NONCE_LEN];
    uint8_t seed_head[HS_POW_SEED_HEAD_LEN];
  } bytes;
} nonce_cache_entry_t;

/** Return true if the two (nonce, seed) replay cache entries are the same */
static inline int
nonce_cache_entries_eq_(const struct nonce_cache_entry_t *entry1,
                        const struct nonce_cache_entry_t *entry2)
{
  return fast_memeq(&entry1->bytes, &entry2->bytes, sizeof entry1->bytes);
}

/** Hash function to hash the (nonce, seed) tuple entry. */
static inline unsigned
nonce_cache_entry_hash_(const struct nonce_cache_entry_t *ent)
{
  return (unsigned)siphash24g(&ent->bytes, sizeof ent->bytes);
}

static HT_HEAD(nonce_cache_table_ht, nonce_cache_entry_t)
  nonce_cache_table = HT_INITIALIZER();

HT_PROTOTYPE(nonce_cache_table_ht, nonce_cache_entry_t, node,
             nonce_cache_entry_hash_, nonce_cache_entries_eq_);

HT_GENERATE2(nonce_cache_table_ht, nonce_cache_entry_t, node,
             nonce_cache_entry_hash_, nonce_cache_entries_eq_, 0.6,
             tor_reallocarray_, tor_free_);

/** This is a callback used to check replay cache entries against a provided
 * seed head, or NULL to operate on the entire cache. Matching entries return
 * 1 and their internal cache entry is freed, non-matching entries return 0. */
static int
nonce_cache_entry_match_seed_and_free(nonce_cache_entry_t *ent, void *data)
{
  if (data == NULL ||
      fast_memeq(ent->bytes.seed_head, data, HS_POW_SEED_HEAD_LEN)) {
    tor_free(ent);
    return 1;
  }
  return 0;
}

/** Helper: Increment a given nonce and set it in the challenge at the right
 * offset. Use by the solve function. */
static inline void
increment_and_set_nonce(uint8_t *nonce, uint8_t *challenge)
{
  for (unsigned i = 0; i < HS_POW_NONCE_LEN; i++) {
    uint8_t prev = nonce[i];
    if (++nonce[i] > prev) {
      break;
    }
  }
  memcpy(challenge + HS_POW_SEED_LEN, nonce, HS_POW_NONCE_LEN);
}

/* Helper: Allocate an EquiX context, using the much faster compiled
 * implementation of hashx if it's available on this architecture. */
static equix_ctx *
build_equix_ctx(equix_ctx_flags flags)
{
  equix_ctx *ctx = equix_alloc(flags | EQUIX_CTX_COMPILE);
  if (ctx == EQUIX_NOTSUPP) {
    ctx = equix_alloc(flags);
  }
  tor_assert_nonfatal(ctx != EQUIX_NOTSUPP);
  tor_assert_nonfatal(ctx != NULL);
  if (ctx == EQUIX_NOTSUPP) {
    ctx = NULL;
  }
  return ctx;
}

/* Helper: Build EquiX challenge (C || N || INT_32(E)) and return a newly
 * allocated buffer containing it. */
static uint8_t *
build_equix_challenge(const uint8_t *seed, const uint8_t *nonce,
                      const uint32_t effort)
{
  /* Build EquiX challenge (C || N || INT_32(E)). */
  size_t offset = 0;
  uint8_t *challenge = tor_malloc_zero(HS_POW_CHALLENGE_LEN);

  memcpy(challenge, seed, HS_POW_SEED_LEN);
  offset += HS_POW_SEED_LEN;
  memcpy(challenge + offset, nonce, HS_POW_NONCE_LEN);
  offset += HS_POW_NONCE_LEN;
  set_uint32(challenge + offset, tor_htonl(effort));
  offset += HS_POW_EFFORT_LEN;
  tor_assert(HS_POW_CHALLENGE_LEN == offset);

  return challenge;
}

/** Helper: Return true iff the given challenge and solution for the given
 * effort do validate as in: R * E <= UINT32_MAX. */
static bool
validate_equix_challenge(const uint8_t *challenge,
                         const uint8_t *solution_bytes,
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
  blake2b_update(&b2_state, solution_bytes, HS_POW_EQX_SOL_LEN);
  blake2b_final(&b2_state, hash_result, HS_POW_HASH_LEN);

  /* Scale to 64 bit so we can avoid 32 bit overflow. */
  uint64_t RE = tor_htonl(get_uint32(hash_result)) * (uint64_t) effort;

  return RE <= UINT32_MAX;
}

/** Helper: Convert equix_solution to a byte array in little-endian order */
static void
pack_equix_solution(const equix_solution *sol_in,
                    uint8_t *bytes_out)
{
  for (unsigned i = 0; i < EQUIX_NUM_IDX; i++) {
    bytes_out[i*2+0] = (uint8_t)sol_in->idx[i];
    bytes_out[i*2+1] = (uint8_t)(sol_in->idx[i] >> 8);
  }
}

/** Helper: Build an equix_solution from its corresponding byte array. */
static void
unpack_equix_solution(const uint8_t *bytes_in,
                      equix_solution *sol_out)
{
  for (unsigned i = 0; i < EQUIX_NUM_IDX; i++) {
    sol_out->idx[i] = (uint16_t)bytes_in[i*2+0] |
                      (uint16_t)bytes_in[i*2+1] << 8;
  }
}

/** Solve the EquiX/blake2b PoW scheme using the parameters in pow_params, and
 * store the solution in pow_solution_out. Returns 0 on success and -1
 * otherwise. Called by a client. */
int
hs_pow_solve(const hs_pow_desc_params_t *pow_params,
             hs_pow_solution_t *pow_solution_out)
{
  int ret = -1;
  uint8_t nonce[HS_POW_NONCE_LEN];
  uint8_t *challenge = NULL;
  equix_ctx *ctx = NULL;

  tor_assert(pow_params);
  tor_assert(pow_solution_out);

  /* Select E (just using suggested for now) */
  uint32_t effort = pow_params->suggested_effort;

  /* Generate a random nonce N. */
  crypto_rand((char *)nonce, sizeof nonce);

  /* Build EquiX challenge (C || N || INT_32(E)). */
  challenge = build_equix_challenge(pow_params->seed, nonce, effort);

  ctx = build_equix_ctx(EQUIX_CTX_SOLVE);
  if (!ctx) {
    goto end;
  }
  equix_solution solutions[EQUIX_MAX_SOLS];
  uint8_t sol_bytes[HS_POW_EQX_SOL_LEN];

  log_notice(LD_REND, "Solving proof of work (effort %u)", effort);
  for (;;) {
    /* Calculate solutions to S = equix_solve(C || N || E),  */
    int count = equix_solve(ctx, challenge, HS_POW_CHALLENGE_LEN, solutions);
    for (int i = 0; i < count; i++) {
      pack_equix_solution(&solutions[i], sol_bytes);

      /* Check an Equi-X solution against the effort threshold */
      if (validate_equix_challenge(challenge, sol_bytes, effort)) {
        /* Store the nonce N. */
        memcpy(pow_solution_out->nonce, nonce, HS_POW_NONCE_LEN);
        /* Store the effort E. */
        pow_solution_out->effort = effort;
        /* We only store the first 4 bytes of the seed C. */
        memcpy(pow_solution_out->seed_head, pow_params->seed,
               sizeof(pow_solution_out->seed_head));
        /* Store the solution S */
        memcpy(&pow_solution_out->equix_solution, sol_bytes, sizeof sol_bytes);

        /* Indicate success and we are done. */
        ret = 0;
        goto end;
      }
    }

    /* No solutions for this nonce and/or none that passed the effort
     * threshold, increment and try again. */
    increment_and_set_nonce(nonce, challenge);
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
  if (fast_memeq(pow_state->seed_current, pow_solution->seed_head,
                 HS_POW_SEED_HEAD_LEN)) {
    seed = pow_state->seed_current;
  } else if (fast_memeq(pow_state->seed_previous, pow_solution->seed_head,
                        HS_POW_SEED_HEAD_LEN)) {
    seed = pow_state->seed_previous;
  } else {
    log_warn(LD_REND, "Seed head didn't match either seed.");
    goto done;
  }

  /* Fail if N = POW_NONCE is present in the replay cache. */
  memcpy(search.bytes.nonce, pow_solution->nonce, HS_POW_NONCE_LEN);
  memcpy(search.bytes.seed_head, pow_solution->seed_head,
         HS_POW_SEED_HEAD_LEN);
  entry = HT_FIND(nonce_cache_table_ht, &nonce_cache_table, &search);
  if (entry) {
    log_warn(LD_REND, "Found (nonce, seed) tuple in the replay cache.");
    goto done;
  }

  /* Build the challenge with the param we have. */
  challenge = build_equix_challenge(seed, pow_solution->nonce,
                                    pow_solution->effort);

  if (!validate_equix_challenge(challenge, pow_solution->equix_solution,
                                pow_solution->effort)) {
    log_warn(LD_REND, "Equi-X solution and effort was too large.");
    goto done;
  }

  ctx = build_equix_ctx(EQUIX_CTX_VERIFY);
  if (!ctx) {
    goto done;
  }

  /* Fail if equix_verify(C || N || E, S) != EQUIX_OK */
  equix_solution equix_sol;
  unpack_equix_solution(pow_solution->equix_solution, &equix_sol);
  equix_result result = equix_verify(ctx, challenge, HS_POW_CHALLENGE_LEN,
                                     &equix_sol);
  if (result != EQUIX_OK) {
    log_warn(LD_REND, "Verification of EquiX solution in PoW failed.");
    goto done;
  }

  /* PoW verified successfully. */
  ret = 0;

  /* Add the (nonce, seed) tuple to the replay cache. */
  entry = tor_malloc_zero(sizeof(nonce_cache_entry_t));
  memcpy(entry->bytes.nonce, pow_solution->nonce, HS_POW_NONCE_LEN);
  memcpy(entry->bytes.seed_head, pow_solution->seed_head,
         HS_POW_SEED_HEAD_LEN);
  HT_INSERT(nonce_cache_table_ht, &nonce_cache_table, entry);

 done:
  tor_free(challenge);
  equix_free(ctx);
  return ret;
}

/** Remove entries from the (nonce, seed) replay cache which are for the seed
 * beginning with seed_head. If seed_head is NULL, remove all cache entries. */
void
hs_pow_remove_seed_from_cache(const uint8_t *seed_head)
{
  /* If nonce_cache_entry_has_seed returns 1, the entry is removed. */
  HT_FOREACH_FN(nonce_cache_table_ht, &nonce_cache_table,
                nonce_cache_entry_match_seed_and_free, (void*)seed_head);
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

/* =====
   Thread workers
   =====*/

/**
 * An object passed to a worker thread that will try to solve the pow.
 */
typedef struct pow_worker_job_t {

  /** Input: The pow challenge we need to solve. */
  hs_pow_desc_params_t *pow_params;

  /** State: we'll look these up to figure out how to proceed after. */
  uint32_t intro_circ_identifier;
  uint32_t rend_circ_identifier;

  /** Output: The worker thread will malloc and write its answer here,
   * or set it to NULL if it produced no useful answer. */
  hs_pow_solution_t *pow_solution_out;

} pow_worker_job_t;

/**
 * Worker function. This function runs inside a worker thread and receives
 * a pow_worker_job_t as its input.
 */
static workqueue_reply_t
pow_worker_threadfn(void *state_, void *work_)
{
  (void)state_;
  pow_worker_job_t *job = work_;
  job->pow_solution_out = tor_malloc_zero(sizeof(hs_pow_solution_t));

  if (hs_pow_solve(job->pow_params, job->pow_solution_out)) {
    log_info(LD_REND, "Haven't solved the PoW yet. Returning.");
    tor_free(job->pow_solution_out);
    job->pow_solution_out = NULL; /* how we signal that we came up empty */
    return WQ_RPL_REPLY;
  }

  /* we have a winner! */
  log_info(LD_REND, "cpuworker pow: we have a winner!");
  return WQ_RPL_REPLY;
}

/**
 * Helper: release all storage held in <b>job</b>.
 */
static void
pow_worker_job_free(pow_worker_job_t *job)
{
  if (!job)
    return;
  tor_free(job->pow_params);
  tor_free(job->pow_solution_out);
  tor_free(job);
}

/**
 * Worker function: This function runs in the main thread, and receives
 * a pow_worker_job_t that the worker thread has already processed.
 */
static void
pow_worker_replyfn(void *work_)
{
  tor_assert(in_main_thread());
  tor_assert(work_);

  pow_worker_job_t *job = work_;

  // look up the circuits that we're going to use this pow in
  origin_circuit_t *intro_circ =
    circuit_get_by_global_id(job->intro_circ_identifier);
  origin_circuit_t *rend_circ =
    circuit_get_by_global_id(job->rend_circ_identifier);

  /* try to re-create desc and ip */
  const ed25519_public_key_t *service_identity_pk = NULL;
  const hs_descriptor_t *desc = NULL;
  const hs_desc_intro_point_t *ip = NULL;
  if (intro_circ)
    service_identity_pk = &intro_circ->hs_ident->identity_pk;
  if (service_identity_pk)
    desc = hs_cache_lookup_as_client(service_identity_pk);
  if (desc)
    ip = find_desc_intro_point_by_ident(intro_circ->hs_ident, desc);

  if (intro_circ && rend_circ && service_identity_pk && desc && ip &&
      job->pow_solution_out) { /* successful pow solve, and circs still here */

    log_notice(LD_REND, "Got a PoW solution we like! Shipping it!");
    /* Set flag to reflect that the HS we are attempting to rendezvous has PoW
     * defenses enabled, and as such we will need to be more lenient with
     * timing out while waiting for the service-side circuit to be built. */
    rend_circ->hs_with_pow_circ = 1;

    // and then send that intro cell
    if (send_introduce1(intro_circ, rend_circ,
                        desc, job->pow_solution_out, ip) < 0) {
      /* if it failed, mark the intro point as ready to start over */
      intro_circ->hs_currently_solving_pow = 0;
    }

  } else { /* unsuccessful pow solve. put it back on the queue. */
    log_notice(LD_REND,
               "PoW cpuworker returned with no solution. Will retry soon.");
    if (intro_circ) {
      intro_circ->hs_currently_solving_pow = 0;
    }
    /* We could imagine immediately re-launching a follow-up worker
     * here too, but for now just let the main intro loop find the
     * not-being-serviced request and it can start everything again. For
     * the sake of complexity, maybe that's the best long-term solution
     * too, and we can tune the cpuworker job to try for longer if we want
     * to improve efficiency. */
  }

  pow_worker_job_free(job);
}

/**
 * Queue the job of solving the pow in a worker thread.
 */
int
hs_pow_queue_work(uint32_t intro_circ_identifier,
                  uint32_t rend_circ_identifier,
                  const hs_pow_desc_params_t *pow_params)
{
  tor_assert(in_main_thread());

  pow_worker_job_t *job = tor_malloc_zero(sizeof(*job));
  job->intro_circ_identifier = intro_circ_identifier;
  job->rend_circ_identifier = rend_circ_identifier;
  job->pow_params = tor_memdup(pow_params, sizeof(hs_pow_desc_params_t));

  workqueue_entry_t *work;
  work = cpuworker_queue_work(WQ_PRI_LOW,
                              pow_worker_threadfn,
                              pow_worker_replyfn,
                              job);
  if (!work) {
    pow_worker_job_free(job);
    return -1;
  }
  return 0;
}
