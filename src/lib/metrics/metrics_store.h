/* Copyright (c) 2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file metrics_store.h
 * @brief Header for lib/metrics/metrics_store.c
 **/

#ifndef TOR_LIB_METRICS_METRICS_STORE_H
#define TOR_LIB_METRICS_METRICS_STORE_H

/* Stub. */
typedef struct metrics_store_t metrics_store_t;

typedef enum {
  /* Store for an address. */
  METRICS_STORE_TYPE_HS_ADDR,
  /* Store for an address and port. */
  METRICS_STORE_TYPE_HS_ADDR_PORT,
} metrics_store_type_t;

/* Allocators. */
void metrics_store_free_(metrics_store_t *store);
#define metrics_store_free(store) \
  FREE_AND_NULL(metrics_store_t, metrics_store_free_, (store))
metrics_store_t *metrics_store_new(const metrics_store_type_t type,
                                   const char *label);

/* Accessors. */
char *metrics_store_get_output(const metrics_store_t *store);

/* Modifiers. */
void metrics_store_update(metrics_store_t *store, const unsigned int key,
                          const int64_t n);

#ifdef METRICS_METRICS_STORE_PRIVATE

#endif /* METRICS_METRICS_STORE_PRIVATE. */

#endif /* !defined(TOR_LIB_METRICS_METRICS_STORE_H) */
