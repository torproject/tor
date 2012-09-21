/* * Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitmux.h
 * \brief Header file for circuitmux.c
 **/

#ifndef _TOR_CIRCUITMUX_H
#define _TOR_CIRCUITMUX_H

#include "or.h"

/* Consistency check */
void circuitmux_assert_okay(circuitmux_t *cmux);

/* Create/destroy */
circuitmux_t * circuitmux_alloc(void);
void circuitmux_detach_all_circuits(circuitmux_t *cmux);
void circuitmux_free(circuitmux_t *cmux);

/* Status inquiries */
cell_direction_t circuitmux_attached_circuit_direction(
    circuitmux_t *cmux,
    circuit_t *circ);
int circuitmux_is_circuit_attached(circuitmux_t *cmux, circuit_t *circ);
int circuitmux_is_circuit_active(circuitmux_t *cmux, circuit_t *circ);
unsigned int circuitmux_num_cells_for_circuit(circuitmux_t *cmux,
                                              circuit_t *circ);
unsigned int circuitmux_num_cells(circuitmux_t *cmux);
unsigned int circuitmux_num_circuits(circuitmux_t *cmux);
unsigned int circuitmux_num_active_circuits(circuitmux_t *cmux);

/* Channel interface */
circuit_t * circuitmux_get_first_active_circuit(circuitmux_t *cmux);
void circuitmux_notify_xmit_cells(circuitmux_t *cmux, circuit_t *circ,
                                  unsigned int n_cells);

/* Circuit interface */
void circuitmux_attach_circuit(circuitmux_t *cmux, circuit_t *circ,
                               cell_direction_t direction);
void circuitmux_detach_circuit(circuitmux_t *cmux, circuit_t *circ);
void circuitmux_clear_num_cells(circuitmux_t *cmux, circuit_t *circ);
void circuitmux_add_to_num_cells(circuitmux_t *cmux, circuit_t *circ,
                                 unsigned int n_cells);
void circuitmux_set_num_cells(circuitmux_t *cmux, circuit_t *circ,
                              unsigned int n_cells);

#endif /* _TOR_CIRCUITMUX_H */

