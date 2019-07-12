/* Copyright (c) 2017-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_circ.c
 * \brief Test hidden service circuit functionality.
 */

#define CIRCUITLIST_PRIVATE

#include "test/test.h"
#include "test/test_helpers.h"
#include "test/log_test_helpers.h"

#include "core/or/circuitbuild.h"
#include "core/or/circuitlist.h"
#include "core/or/circuituse.h"
#include "core/or/origin_circuit_st.h"

#include "feature/hs/hs_circuit.h"
#include "feature/hs/hs_circuitmap.h"

static void
test_circuit_repurpose(void *arg)
{
  origin_circuit_t *intro_circ = NULL;
  const origin_circuit_t *search;
  ed25519_keypair_t kp;

  (void) arg;

  hs_init();

  intro_circ = origin_circuit_init(CIRCUIT_PURPOSE_S_ESTABLISH_INTRO, 0);
  tt_assert(intro_circ);
  ed25519_keypair_generate(&kp, 0);

  /* Register circuit in global map and make sure it is actually there. */
  hs_circuitmap_register_intro_circ_v3_service_side(intro_circ,
                                                    &kp.pubkey);
  tt_assert(TO_CIRCUIT(intro_circ)->hs_token);
  search = hs_circuitmap_get_intro_circ_v3_service_side(&kp.pubkey);
  tt_mem_op(search, OP_EQ, intro_circ, sizeof(origin_circuit_t));

  /* Setup circuit HS ident. We don't care about the service pubkey. */
  intro_circ->hs_ident = hs_ident_circuit_new(&kp.pubkey,
                                              HS_IDENT_CIRCUIT_INTRO);
  tt_assert(intro_circ->hs_ident);

  /* Trigger a repurpose. State should be cleaned up. */
  hs_circ_repurpose(TO_CIRCUIT(intro_circ));

  /* Removed from map. */
  search = hs_circuitmap_get_intro_circ_v3_service_side(&kp.pubkey);
  tt_assert(!search);
  /* HS identifier has been removed. */
  tt_assert(!intro_circ->hs_ident);

 done:
  circuit_free_(TO_CIRCUIT(intro_circ));
  hs_free_all();
}

struct testcase_t hs_circ_tests[] = {
  { "repurpose", test_circuit_repurpose, TT_FORK,
    NULL, NULL },

  END_OF_TESTCASES
};

