/* Copyright (c) 2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file metrics.h
 * @brief Header for feature/metrics/metrics.c
 **/

#ifndef TOR_FEATURE_METRICS_METRICS_H
#define TOR_FEATURE_METRICS_METRICS_H

#include "lib/metrics/metrics_common.h"

/* Initializer / Cleanup. */
void metrics_init(void);
void metrics_cleanup(void);

/* Accessors. */
char *metrics_get_output(const metrics_format_t fmt);

#endif /* !defined(TOR_FEATURE_METRICS_METRICS_H) */
