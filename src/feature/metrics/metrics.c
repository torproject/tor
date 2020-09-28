/* Copyright (c) 2007-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file metrics.c
 * @brief Metrics subsystem.
 **/

#include <stddef.h>

#include "orconfig.h"

#include "lib/container/map.h"
#include "lib/log/util_bug.h"
#include "lib/metrics/metrics_store.h"
#include "lib/metrics/metrics_store_entry.h"

#include "feature/metrics/metrics.h"

/** Onion service metrics store. Indexed by onion address located in the
 * hs_service_t object. */
static strmap_t *onion_service_store = NULL;

static void
free_metrics_store_(void *store)
{
  metrics_store_free_(store);
}

void
metrics_init(void)
{
  if (!onion_service_store) {
    onion_service_store = strmap_new();
  }
}

void
metrics_cleanup(void)
{
  strmap_free(onion_service_store, free_metrics_store_);
}

void
metrics_new_onion_service(const char *address)
{
  metrics_store_t *store = metrics_store_new(METRICS_STORE_TYPE_HS);

  strmap_set(onion_service_store, address, store);
}

/*
 * Metrics counting.
 */

#define UPDATE(hs_addr, n, fn)                                         \
  do {                                                                 \
    metrics_store_t *store = strmap_get(onion_service_store, hs_addr); \
    if (BUG(store == NULL)) {                                          \
      return;                                                          \
    }                                                                  \
    fn(store, n);                                                      \
  } while (0)

void
metrics_hs_service_write_bytes(const char *address, uint64_t n)
{
  UPDATE(address, n, metrics_store_hs_servive_write);
}
