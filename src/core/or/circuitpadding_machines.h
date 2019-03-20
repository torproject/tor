/* Copyright (c) 2018 The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitpadding_machines.h
 * \brief Header file for circuitpadding_machines.c.
 **/

#ifndef TOR_CIRCUITPADDING_MACHINES_H
#define TOR_CIRCUITPADDING_MACHINES_H

void circpad_machine_relay_hide_intro_circuits(smartlist_t *machines_sl);
void circpad_machine_client_hide_intro_circuits(smartlist_t *machines_sl);
void circpad_machine_relay_hide_rend_circuits(smartlist_t *machines_sl);
void circpad_machine_client_hide_rend_circuits(smartlist_t *machines_sl);

#ifdef CIRCUITPADDING_MACHINES_PRIVATE

/** Minimum number of padding cells to be sent by this machine per state. */
#define HS_MACHINE_STATE_PADDING_MINIMUM 4
/** Maximum number of padding cells to be sent by this machine per state.
 *  The actual value will be sampled between the min and max.*/
#define HS_MACHINE_STATE_PADDING_MAXIMUM 30

#endif

#endif
