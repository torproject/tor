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

#include "feature/nodelist/networkstatus_st.h"

/* Init */
void hs_dos_init(void);

/* Consensus. */
void hs_dos_consensus_has_changed(const networkstatus_t *ns);

bool hs_dos_can_send_intro2(or_circuit_t *s_intro_circ);

/* Getters. */
uint32_t hs_dos_get_intro2_rate(void);
uint32_t hs_dos_get_intro2_burst(void);

#ifdef HS_DOS_PRIVATE

#ifdef TOR_UNIT_TESTS

#endif /* define(TOR_UNIT_TESTS) */

#endif /* defined(HS_DOS_PRIVATE) */

#endif /* !defined(TOR_HS_DOS_H) */
