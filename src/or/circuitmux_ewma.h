/* * Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitmux_ewma.h
 * \brief Header file for circuitmux_ewma.c
 **/

#ifndef _TOR_CIRCUITMUX_EWMA_H
#define _TOR_CIRCUITMUX_EWMA_H

#include "or.h"
#include "circuitmux.h"

/* Everything but circuitmux_ewma.c should see this extern */
#ifndef _TOR_CIRCUITMUX_EWMA_C

extern circuitmux_policy_t ewma_policy;

#endif /* !(_TOR_CIRCUITMUX_EWMA_C) */

/* Externally visible EWMA functions */
unsigned int cell_ewma_get_tick(void);
void cell_ewma_set_scale_factor(const or_options_t *options,
                                const networkstatus_t *consensus);

#endif /* _TOR_CIRCUITMUX_EWMA_H */

