/* Copyright (c) 2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file relay_metrics.c
 * @brief Relay metrics exposed through the MetricsPort
 **/

#define RELAY_METRICS_ENTRY_PRIVATE

#include "orconfig.h"

#include "core/or/or.h"
#include "core/or/relay.h"

#include "lib/malloc/malloc.h"
#include "lib/container/smartlist.h"
#include "lib/metrics/metrics_store.h"
#include "lib/log/util_bug.h"

#include "feature/relay/relay_metrics.h"

/** Declarations of each fill function for metrics defined in base_metrics. */
static void fill_oom_values(void);

/** The base metrics that is a static array of metrics added to the metrics
 * store.
 *
 * The key member MUST be also the index of the entry in the array. */
static const relay_metrics_entry_t base_metrics[] =
{
  {
    .key = RELAY_METRICS_NUM_OOM_BYTES,
    .type = METRICS_TYPE_COUNTER,
    .name = METRICS_NAME(relay_load_oom_bytes_total),
    .help = "Total number of bytes the OOM has freed by subsystem",
    .fill_fn = fill_oom_values,
  },
};
static const size_t num_base_metrics = ARRAY_LENGTH(base_metrics);

/** The only and single store of all the relay metrics. */
static metrics_store_t *the_store;

/** Fill function for the RELAY_METRICS_NUM_OOM_BYTES metrics. */
static void
fill_oom_values(void)
{
  metrics_store_entry_t *sentry;
  const relay_metrics_entry_t *rentry =
    &base_metrics[RELAY_METRICS_NUM_OOM_BYTES];

  sentry = metrics_store_add(the_store, rentry->type, rentry->name,
                             rentry->help);
  metrics_store_entry_add_label(sentry, "subsys=cell");
  metrics_store_entry_update(sentry, oom_stats_n_bytes_removed_cell);

  sentry = metrics_store_add(the_store, rentry->type, rentry->name,
                             rentry->help);
  metrics_store_entry_add_label(sentry, "subsys=dns");
  metrics_store_entry_update(sentry, oom_stats_n_bytes_removed_dns);

  sentry = metrics_store_add(the_store, rentry->type, rentry->name,
                             rentry->help);
  metrics_store_entry_add_label(sentry, "subsys=geoip");
  metrics_store_entry_update(sentry, oom_stats_n_bytes_removed_geoip);

  sentry = metrics_store_add(the_store, rentry->type, rentry->name,
                             rentry->help);
  metrics_store_entry_add_label(sentry, "subsys=hsdir");
  metrics_store_entry_update(sentry, oom_stats_n_bytes_removed_hsdir);
}

/** Reset the global store and fill it with all the metrics from base_metrics
 * and their associated values.
 *
 * To pull this off, every metrics has a "fill" function that is called and in
 * charge of adding the metrics to the store, appropriate labels and finally
 * updating the value to report. */
static void
fill_store(void)
{
  /* Reset the current store, we are about to fill it with all the things. */
  metrics_store_reset(the_store);

  /* Call the fill function for each metrics. */
  for (size_t i = 0; i < num_base_metrics; i++) {
    if (BUG(!base_metrics[i].fill_fn)) {
      continue;
    }
    base_metrics[i].fill_fn();
  }
}

/** Return a list of all the relay metrics stores. This is the
 * function attached to the .get_metrics() member of the subsys_t. */
const smartlist_t *
relay_metrics_get_stores(void)
{
  /* We can't have the caller to free the returned list so keep it static,
   * simply update it. */
  static smartlist_t *stores_list = NULL;

  /* We dynamically fill the store with all the metrics upon a request. The
   * reason for this is because the exposed metrics of a relay are often
   * internal counters in the fast path and thus we fetch the value when a
   * metrics port request arrives instead of keeping a local metrics store of
   * those values. */
  fill_store();

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
