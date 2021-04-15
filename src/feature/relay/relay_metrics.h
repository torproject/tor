/* Copyright (c) 2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file relay_metrics.h
 * @brief Header for feature/relay/relay_metrics.c
 **/

#ifndef TOR_FEATURE_RELAY_RELAY_METRICS_H
#define TOR_FEATURE_RELAY_RELAY_METRICS_H

#include "lib/container/smartlist.h"

/* Init. */
void relay_metrics_init(void);
void relay_metrics_free(void);

/* Accessors. */
const smartlist_t *relay_metrics_get_stores(void);

#endif /* !defined(TOR_FEATURE_RELAY_RELAY_METRICS_H) */
