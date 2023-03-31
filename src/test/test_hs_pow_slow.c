/* Copyright (c) 2020-2023, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_pow_slow.c
 * \brief Slower (solve + verify) tests for service proof-of-work defenses.
 */

#define HS_SERVICE_PRIVATE

#include "lib/cc/compat_compiler.h"
#include "lib/cc/torint.h"

#include "test/test.h"
#include "test/test_helpers.h"
#include "test/log_test_helpers.h"
#include "test/rng_test_helpers.h"

#include "app/config/config.h"
#include "feature/hs/hs_pow.h"

static int
testing_one_hs_pow_solution(const hs_pow_solution_t *ref_solution,
                            const uint8_t *seed)
{
  int retval = -1;
  hs_pow_solution_t sol_buffer;
  hs_pow_service_state_t *s = tor_malloc_zero(sizeof(hs_pow_service_state_t));
  s->rend_request_pqueue = smartlist_new();

  memcpy(s->seed_previous, seed, HS_POW_SEED_LEN);

  const unsigned num_variants = 10;
  const unsigned num_attempts = 3;

  for (unsigned variant = 0; variant < num_variants; variant++) {
    hs_pow_remove_seed_from_cache(seed);

    for (unsigned attempt = 0; attempt < num_attempts; attempt++) {
      int expected = -1;
      memcpy(&sol_buffer, ref_solution, sizeof sol_buffer);

      /* One positive test, and a few negative tests of corrupted solutions */
      if (variant == 0) {
        if (attempt == 0) {
          /* Only the first attempt should succeed (nonce replay) */
          expected = 0;
        }
      } else if (variant & 1) {
        sol_buffer.nonce[variant / 2 % HS_POW_NONCE_LEN]++;
      } else {
        sol_buffer.equix_solution[variant / 2 % HS_POW_EQX_SOL_LEN]++;
      }

      tt_int_op(expected, OP_EQ, hs_pow_verify(s, &sol_buffer));
    }
  }

  retval = 0;
done:
  hs_pow_free_service_state(s);
  return retval;
}

static void
test_hs_pow_vectors(void *arg)
{
  (void)arg;

  /* All test vectors include a solve, verify, and fail-verify phase
   * as well as a test of the nonce replay cache. The initial nonce for the
   * solution search is set via the solver's RNG data. The amount of solve
   * time during test execution can be tuned based on how far away from the
   * winning nonce our solve_rng value is set.
   */
  static const struct {
    uint32_t effort;
    const char *solve_rng_hex;
    const char *seed_hex;
    const char *nonce_hex;
    const char *sol_hex;
  } vectors[] = {
    {
      0, "55555555555555555555555555555555",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "55555555555555555555555555555555", "fd57d7676238c0ad1d5473aa2d0cbff5"
    },
    {
      1, "55555555555555555555555555555555",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "55555555555555555555555555555555", "703d8bc75492e8f90d836dd21bde61fc"
    },
    {
      2, "55555555555555555555555555555555",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "56555555555555555555555555555555", "c2374478d35040b53e4eb9aa9f16e9ec"
    },
    {
      10, "55555555555555555555555555555555",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "5c555555555555555555555555555555", "b167af85e25a0c961928eff53672c1f8"
    },
    {
      10, "ffffffffffffffffffffffffffffffff",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "02000000000000000000000000000000", "954e4464715842d391712bb3b2289ff8"
    },
    {
      1337, "7fffffffffffffffffffffffffffffff",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "eaffffffffffffffffffffffffffffff", "dbab3eb9045f85f8162c482d43f7d6fc"
    },
    {
      31337, "00410000000000000000000000000000",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "23410000000000000000000000000000", "545ddd60e33bfa73ec75aada68608ee8"
    },
    {
      100, "6b555555555555555555555555555555",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "6b555555555555555555555555555555", "7e14e98fed2f35a1b293b39d56b260e9"
    },
    {
      1000, "0e565555555555555555555555555555",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "0e565555555555555555555555555555", "514963616e0b986afb1414afa88b85ff"
    },
    {
      10000, "80835555555555555555555555555555",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "89835555555555555555555555555555", "7a5164905f8aaec152126258a2462ae6"
    },
    {
      100000, "fd995655555555555555555555555555",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "fd995655555555555555555555555555", "8b27f2664340bc88dd5335821a68f5ff"
    },
    {
      1000000, "15505855555555555555555555555555",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "16505855555555555555555555555555", "bf2c2d345e5773b5c32ec5596244bdbc"
    },
    {
      1, "d0aec1669384bfe5ed39cd724d6c7954",
      "c52be1f8a5e6cc3b8fb71cfdbe272cbc91d4d035400f2f94fb0d0074794e0a07",
      "d0aec1669384bfe5ed39cd724d6c7954", "9e062190e23b34a80562818b14cf4ae5"
    },
    {
      1, "b4d0e611e6935750fcf9406aae131f62",
      "86fb0acf4932cda44dbb451282f415479462dd10cb97ff5e7e8e2a53c3767a7f",
      "b4d0e611e6935750fcf9406aae131f62", "a01cf4457a016488df4fa45f0864b6fb"
    },
    {
      1, "b4d0e611e6935750fcf9406aae131f62",
      "9dfbd06d86fed8e12de3ab214e1a63ea61f46253fe08346a20378da70c4a327d",
      "b5d0e611e6935750fcf9406aae131f62", "5944a260423392780f10b25b7e2502d3"
    },
    {
      1, "40559fdbc34326d9d2f18ed277469c63",
      "86fb0acf4932cda44dbb451282f415479462dd10cb97ff5e7e8e2a53c3767a7f",
      "40559fdbc34326d9d2f18ed277469c63", "31139564ca5262a4f82b9385b2832fce"
    },
    {
      10000, "70559fdbc34326d9d2f18ed277469c63",
      "86fb0acf4932cda44dbb451282f415479462dd10cb97ff5e7e8e2a53c3767a7f",
      "72559fdbc34326d9d2f18ed277469c63", "262c6c82025c53b69b0bf255606ca3e2"
    },
    {
      100000, "c0d49fdbc34326d9d2f18ed277469c63",
      "86fb0acf4932cda44dbb451282f415479462dd10cb97ff5e7e8e2a53c3767a7f",
      "cdd49fdbc34326d9d2f18ed277469c63", "7f153437c58620d3ea4717746093dde6"
    },
    {
      1000000, "40fdb1dbc34326d9d2f18ed277469c63",
      "86fb0acf4932cda44dbb451282f415479462dd10cb97ff5e7e8e2a53c3767a7f",
      "4cfdb1dbc34326d9d2f18ed277469c63", "b31bbb45340e17a14c2156c0b66780e7"
    },
  };

  const unsigned num_vectors = sizeof vectors / sizeof vectors[0];
  for (unsigned vec_i = 0; vec_i < num_vectors; vec_i++) {
    const char *seed_hex = vectors[vec_i].seed_hex;
    const char *solve_rng_hex = vectors[vec_i].solve_rng_hex;
    const char *nonce_hex = vectors[vec_i].nonce_hex;
    const char *sol_hex = vectors[vec_i].sol_hex;

    uint8_t rng_bytes[HS_POW_NONCE_LEN];
    hs_pow_solution_t output;
    hs_pow_solution_t solution = { 0 };
    hs_pow_solver_inputs_t input = {
      .effort = vectors[vec_i].effort,
    };

    tt_int_op(strlen(seed_hex), OP_EQ, 2 * sizeof input.seed);
    tt_int_op(strlen(solve_rng_hex), OP_EQ, 2 * sizeof rng_bytes);
    tt_int_op(strlen(nonce_hex), OP_EQ, 2 * sizeof solution.nonce);
    tt_int_op(strlen(sol_hex), OP_EQ, 2 * sizeof solution.equix_solution);

    tt_int_op(base16_decode((char*)input.seed, HS_POW_SEED_LEN,
                            seed_hex, 2 * HS_POW_SEED_LEN),
                            OP_EQ, HS_POW_SEED_LEN);
    tt_int_op(base16_decode((char*)rng_bytes, sizeof rng_bytes,
                            solve_rng_hex, 2 * sizeof rng_bytes),
                            OP_EQ, HS_POW_NONCE_LEN);
    tt_int_op(base16_decode((char*)&solution.nonce, sizeof solution.nonce,
                            nonce_hex, 2 * sizeof solution.nonce),
                            OP_EQ, HS_POW_NONCE_LEN);
    tt_int_op(base16_decode((char*)&solution.equix_solution,
                            sizeof solution.equix_solution,
                            sol_hex, 2 * sizeof solution.equix_solution),
                            OP_EQ, HS_POW_EQX_SOL_LEN);
    memcpy(solution.seed_head, input.seed, HS_POW_SEED_HEAD_LEN);

    memset(&output, 0xaa, sizeof output);
    testing_enable_prefilled_rng(rng_bytes, HS_POW_NONCE_LEN);
    tt_int_op(0, OP_EQ, hs_pow_solve(&input, &output));
    testing_disable_prefilled_rng();

    tt_mem_op(solution.seed_head, OP_EQ, output.seed_head,
              sizeof output.seed_head);
    tt_mem_op(solution.nonce, OP_EQ, output.nonce,
              sizeof output.nonce);
    tt_mem_op(&solution.equix_solution, OP_EQ, &output.equix_solution,
              sizeof output.equix_solution);

    tt_int_op(testing_one_hs_pow_solution(&output, input.seed), OP_EQ, 0);
  }

 done:
  testing_disable_prefilled_rng();
  hs_pow_remove_seed_from_cache(NULL);
}

struct testcase_t slow_hs_pow_tests[] = {
  { "vectors", test_hs_pow_vectors, 0, NULL, NULL },
  END_OF_TESTCASES
};
