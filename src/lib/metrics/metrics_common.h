/* Copyright (c) 2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file metrics_common.h
 * @brief Header for lib/metrics/metrics_common.c
 **/

#ifndef TOR_LIB_METRICS_METRICS_COMMON_H
#define TOR_LIB_METRICS_METRICS_COMMON_H

#include "lib/cc/torint.h"

/** Metric type. */
typedef enum {
  /* Increment only. */
  METRICS_TYPE_COUNTER,
  /* Can go up or down. */
  METRICS_TYPE_GAUGE,
} metrics_type_t;

/** Metric counter object (METRICS_TYPE_COUNTER). */
typedef struct metrics_counter_t {
  uint64_t value;
} metrics_counter_t;

/** Metric gauge object (METRICS_TYPE_GAUGE). */
typedef struct metrics_gauge_t {
  uint64_t value;
} metrics_gauge_t;

typedef struct metrics_entry_model_t {
  /* Metric key. */
  int key;
  /* Metric type. */
  const metrics_type_t type;
  /* Metric output name. */
  const char *name;
  /* Help comment (#HELP). */
  const char *help;
} metrics_entry_model_t;

const char *metrics_type_to_str(const metrics_type_t type);

#endif /* !defined(TOR_LIB_METRICS_METRICS_COMMON_H) */
