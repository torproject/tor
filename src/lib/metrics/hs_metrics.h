/* Copyright (c) 2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file hs_metrics.h
 * @brief Header for lib/metrics/hs_metrics.c
 **/

#ifndef TOR_LIB_METRICS_HS_METRICS_H
#define TOR_LIB_METRICS_HS_METRICS_H

#include "lib/metrics/metrics_common.h"

/**
 * Data model for per onion address metrics that is metrics that can only
 * apply to an onion service and not a specific port of the service.
 */
extern const metrics_entry_model_t hs_addr_metrics_model[];
extern const size_t hs_addr_metrics_model_size;

/**
 * Data model for per onion address and service port metrics that is metrics
 * that can only apply to an onion service and specific to a service port.
 */
extern const metrics_entry_model_t hs_addr_port_metrics_model[];
extern const size_t hs_addr_port_metrics_model_size;

#endif /* !defined(TOR_LIB_METRICS_HS_METRICS_H) */
