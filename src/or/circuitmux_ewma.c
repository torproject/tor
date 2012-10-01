/* * Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitmux_ewma.c
 * \brief EWMA circuit selection as a circuitmux_t policy
 **/

#include "or.h"
#include "circuitmux.h"
#include "circuitmux_ewma.h"

