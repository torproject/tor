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

/** Constants defining the amount of padding that a machine will send to hide
 *  HS circuits. The actual value is sampled uniformly random between the
 *  min/max values.
 *
 *  We want the numbers for the client-side to be bigger than the service-side
 *  to dispel the common fingerprint of HS tickets where the service sends more
 *  cells than the client.
 */

/** Minimum number of padding cells to be sent by a client-side machine for
 *  hiding HS circuits */
#define HS_MACHINE_PADDING_MINIMUM_CLIENT 10
/** Maximum number of padding cells to be sent by a client-side machine for
 *  hiding HS circuits */
#define HS_MACHINE_PADDING_MAXIMUM_CLIENT 30

/** Minimum number of padding cells to be sent by this machine per state. */
#define HS_MACHINE_PADDING_MINIMUM_SERVICE 5
/** Maximum number of padding cells to be sent by this machine per state.
 *  The actual value will be sampled between the min and max.*/
#define HS_MACHINE_PADDING_MAXIMUM_SERVICE 15

#endif

#endif
