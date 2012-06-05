/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file command.h
 * \brief Header file for command.c.
 **/

#ifndef _TOR_COMMAND_H
#define _TOR_COMMAND_H

void command_process_cell(cell_t *cell, or_connection_t *conn);
void command_process_var_cell(var_cell_t *cell, or_connection_t *conn);

extern uint64_t stats_n_padding_cells_processed;
extern uint64_t stats_n_create_cells_processed;
extern uint64_t stats_n_created_cells_processed;
extern uint64_t stats_n_relay_cells_processed;
extern uint64_t stats_n_destroy_cells_processed;

#endif

