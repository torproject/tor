/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file onion.h
 * \brief Header file for onion.c.
 **/

#ifndef TOR_ONION_H
#define TOR_ONION_H

int onion_pending_add(or_circuit_t *circ, char *onionskin);
or_circuit_t *onion_next_task(char **onionskin_out);
void onion_pending_remove(or_circuit_t *circ);
void clear_pending_onions(void);

#endif

