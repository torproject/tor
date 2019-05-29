/* Copyright (c) 2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_dos.c
 **/

#define HS_DOS_PRIVATE

#include "core/or/circuitlist.h"

#include "hs_dos.h"

/*
 * Public API.
 */

/* Return true iff an INTRODUCE2 cell can be sent on the given service
 * introduction circuit. */
bool
hs_dos_can_send_intro2(or_circuit_t *s_intro_circ)
{
  tor_assert(s_intro_circ);

  /* Should not happen but if so, scream loudly. */
  if (BUG(TO_CIRCUIT(s_intro_circ)->purpose != CIRCUIT_PURPOSE_INTRO_POINT)) {
    return false;
  }

  /* This is called just after we got a valid and parsed INTRODUCE1 cell. The
   * service has been found and we have its introduction circuit.
   *
   * First, the INTRODUCE2 bucket will be refilled (if any). Then, decremented
   * because we are about to send or not the cell we just got. Finally,
   * evaluate if we can send it based on our token bucket state. */

  /* Refill INTRODUCE2 bucket. */
  token_bucket_ctr_refill(&s_intro_circ->introduce2_bucket,
                          (uint32_t) approx_time());

  /* Decrement the bucket for this valid INTRODUCE1 cell we just got. Don't
   * underflow else we end up with a too big of a bucket. */
  if (token_bucket_ctr_get(&s_intro_circ->introduce2_bucket) > 0) {
    token_bucket_ctr_dec(&s_intro_circ->introduce2_bucket, 1);
  }

  /* Finally, we can send a new INTRODUCE2 if there are still tokens. */
  return token_bucket_ctr_get(&s_intro_circ->introduce2_bucket) > 0;
}
