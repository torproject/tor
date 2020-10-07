/* Copyright (c) 2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file metrics_store.c
 * @brief Metrics interface to store them based on specific store type and get
 *        their MetricsPort output.
 **/

#define METRICS_STORE_ENTRY_PRIVATE

#include "orconfig.h"

#include "lib/log/util_bug.h"
#include "lib/malloc/malloc.h"
#include "lib/container/smartlist.h"
#include "lib/string/printf.h"

#include "lib/metrics/metrics_store.h"
#include "lib/metrics/metrics_store_entry.h"

#include "lib/metrics/hs_metrics.h"

/** Onion service metric store. */
typedef struct metrics_store_t {
  /** Type of store. */
  metrics_store_type_t type;

  /** Entries indexed by statistics type. */
  metrics_store_entry_t **entries;

  /** Number of entries in that store. */
  size_t num_entries;

  /** Label added to the output for this tore. */
  char *label;
} metrics_store_t;

/** Helper: Initialize a new onion service store by allocating a counter for
 * each store key. */
static void
init_store(metrics_store_t *store, const char *label,
           const metrics_entry_model_t *model, const size_t model_size)
{
  tor_assert(store);

  store->num_entries = model_size;
  store->label = tor_strdup(label);
  store->entries =
    tor_malloc_zero(sizeof(metrics_store_entry_t) * store->num_entries);

  for (size_t i = 0; i < model_size; ++i) {
    store->entries[i] = metrics_store_entry_new(&model[i]);
  }
}

/** Return a newly allocated string containing the data output of the given
 * store. There is NO newline at the end of this string. */
static char *
get_store_output(const metrics_store_t *store)
{
  char *data = NULL;
  smartlist_t *lines = smartlist_new();

  for (size_t i = 0; i < store->num_entries; ++i) {
    smartlist_add(lines, metrics_store_entry_get_output(store->entries[i],
                                                        store->label));
  }

  data = smartlist_join_strings(lines, "\n", 0, NULL);

  SMARTLIST_FOREACH(lines, char *, l, tor_free(l));
  smartlist_free(lines);

  return data;
}

/** Return a newly allocated and initialized store of the given type. */
metrics_store_t *
metrics_store_new(const metrics_store_type_t type, const char *label)
{
  const metrics_entry_model_t *model;
  size_t model_size;
  metrics_store_t *store = tor_malloc_zero(sizeof(*store));

  switch (type) {
  case METRICS_STORE_TYPE_HS_ADDR:
    model = hs_addr_metrics_model;
    model_size = hs_addr_metrics_model_size;
    break;
  case METRICS_STORE_TYPE_HS_ADDR_PORT:
    model = hs_addr_port_metrics_model;
    model_size = hs_addr_port_metrics_model_size;
    break;
  default:
    /* This means internal code flow problem. Should never happen, these
     * stores allocation are never controlled by an untrusted source. */
    tor_assert_unreached();
  }

  init_store(store, label, model, model_size);

  return store;
}

/** Free the given store including all its entries. */
void
metrics_store_free_(metrics_store_t *store)
{
  if (store == NULL) {
    return;
  }

  for (size_t i = 0; i < store->num_entries; ++i) {
    metrics_store_entry_free(store->entries[i]);
  }

  tor_free(store->entries);
  tor_free(store->label);
  tor_free(store);
}

/** Return a newly allocated string containing the store output. There is NO
 * newline at the end of the string. */
char *
metrics_store_get_output(const metrics_store_t *store)
{
  tor_assert(store);

  return get_store_output(store);
}

/** Update metric key within the given store with value n. */
void
metrics_store_update(metrics_store_t *store, const unsigned int key,
                     const int64_t n)
{
  tor_assert(store);

  /* Safeguard. */
  if (BUG(key > store->num_entries)) {
    return;
  }

  /* Safety. This should always be true. */
  tor_assert(store->entries[key]->key == key);
  metrics_store_entry_update(store->entries[key], n);
}

/** Reset metrics for the given key in the given store. This basically sets
 * its metrics data to 0 as for example set a counter to 0. */
void
metrics_store_reset(metrics_store_t *store, const unsigned int key)
{
  tor_assert(store);

  /* Safeguard. */
  if (BUG(key > store->num_entries)) {
    return;
  }

  /* Safety. This should always be true. */
  tor_assert(store->entries[key]->key == key);
  metrics_store_entry_reset(store->entries[key]);
}
