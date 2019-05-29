/* Copyright (c) 2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_dos.h
 * \brief Header file containing denial of service defenses for the HS
 *        subsystem for all versions.
 **/

#ifndef TOR_HS_DOS_H
#define TOR_HS_DOS_H

#include "core/or/or_circuit_st.h"

#include "lib/evloop/token_bucket.h"

#define HS_DOS_INTRODUCE_CELL_RATE_PER_SEC 25
#define HS_DOS_INTRODUCE_CELL_BURST_PER_SEC 200

bool hs_dos_can_send_intro2(or_circuit_t *s_intro_circ);

/* Return the INTRODUCE2 cell rate per second. */
static inline
uint32_t hs_dos_get_intro2_rate(void)
{
  return HS_DOS_INTRODUCE_CELL_RATE_PER_SEC;
}

/* Return the INTRODUCE2 cell burst per second. */
static inline
uint32_t hs_dos_get_intro2_burst(void)
{
  return HS_DOS_INTRODUCE_CELL_BURST_PER_SEC;
}

#ifdef HS_DOS_PRIVATE

#ifdef TOR_UNIT_TESTS

#endif /* define(TOR_UNIT_TESTS) */

#endif /* defined(HS_DOS_PRIVATE) */

#endif /* !defined(TOR_HS_DOS_H) */
