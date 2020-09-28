/* Copyright (c) 2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file metrics_store_entry.h
 * @brief Header for lib/metrics/metrics_store_entry.c
 **/

#ifndef TOR_LIB_METRICS_METRICS_STORE_ENTRY_H
#define TOR_LIB_METRICS_METRICS_STORE_ENTRY_H

#include "lib/cc/torint.h"

#include "lib/metrics/metrics_common.h"

#ifdef METRICS_STORE_ENTRY_PRIVATE

typedef struct metrics_store_entry_t {
  /** Metrics key. */
  unsigned int key;

  /** Type of entry. */
  metrics_type_t type;

  /** Name. */
  const char *name;

  /** Help comment string. */
  const char *help;

  /* Actual data. */
  union {
    metrics_counter_t counter;
    metrics_gauge_t gauge;
  } u;
} metrics_store_entry_t;

#endif /* METRICS_STORE_ENTRY_PRIVATE */

typedef struct metrics_store_entry_t metrics_store_entry_t;

/* Allocators. */
metrics_store_entry_t *metrics_store_entry_new(
                                     const metrics_entry_model_t *model);
void metrics_store_entry_free_(metrics_store_entry_t *entry);
#define metrics_store_entry_free(entry) \
  FREE_AND_NULL(metrics_store_entry_t, metrics_store_entry_free_, (entry));

/* Accessors. */
uint64_t metrics_store_entry_get_value(const metrics_store_entry_t *entry);
char *metrics_store_entry_get_output(const metrics_store_entry_t *entry,
                                     const char *label);

/* Modifiers. */
void metrics_store_entry_update(metrics_store_entry_t *entry,
                                const int64_t value);

#endif /* !defined(TOR_LIB_METRICS_METRICS_STORE_ENTRY_H) */
