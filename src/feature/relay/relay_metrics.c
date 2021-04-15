/* Copyright (c) 2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file relay_metrics.c
 * @brief Relay metrics exposed through the MetricsPort
 **/

#define RELAY_METRICS_ENTRY_PRIVATE

#include "orconfig.h"

#include "lib/malloc/malloc.h"
#include "lib/container/smartlist.h"
#include "lib/metrics/metrics_store.h"
#include "lib/log/util_bug.h"

#include "feature/relay/relay_metrics.h"

/** The base metrics that is a static array of metrics added to the metrics
 * store.
 *
 * The key member MUST be also the index of the entry in the array. */
static const relay_metrics_entry_t base_metrics[] = {};
static const size_t num_base_metrics = ARRAY_LENGTH(base_metrics);

/** The only and single store of all the relay metrics. */
static metrics_store_t *the_store;

/** Return a list of all the relay metrics stores. This is the
 * function attached to the .get_metrics() member of the subsys_t. */
const smartlist_t *
relay_metrics_get_stores(void)
{
  /* We can't have the caller to free the returned list so keep it static,
   * simply update it. */
  static smartlist_t *stores_list = NULL;

  if (!stores_list) {
    stores_list = smartlist_new();
    smartlist_add(stores_list, the_store);
  }

  return stores_list;
}

/** Initialize the relay metrics. */
void
relay_metrics_init(void)
{
  if (BUG(the_store)) {
    return;
  }
  the_store = metrics_store_new();
}

/** Free the relay metrics. */
void
relay_metrics_free(void)
{
  if (!the_store) {
    return;
  }
  /* NULL is set with this call. */
  metrics_store_free(the_store);
}
