/* * Copyright (c) 2012-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitmux_ewma.h
 * \brief Header file for circuitmux_ewma.c
 **/

#ifndef TOR_CIRCUITMUX_EWMA_H
#define TOR_CIRCUITMUX_EWMA_H

#include "or.h"
#include "circuitmux.h"

/* The public EWMA policy callbacks object. */
extern circuitmux_policy_t ewma_policy;

/* Externally visible EWMA functions */
void cmux_ewma_set_options(const or_options_t *options,
                           const networkstatus_t *consensus);

#endif /* !defined(TOR_CIRCUITMUX_EWMA_H) */

