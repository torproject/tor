/* Copyright (c) 2007-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file metrics.c
 * @brief Metrics subsystem.
 **/

#include <stddef.h>
#include <string.h>

#include "orconfig.h"

#include "lib/container/map.h"
#include "lib/log/util_bug.h"
#include "lib/metrics/metrics_store.h"
#include "lib/string/printf.h"

#include "feature/hs/hs_common.h"
#include "feature/metrics/metrics.h"

/** Onion service specific metric store. It is used in
 * store_list_per_hs_addr_port which tracks metrics that are per address +
 * port. */
typedef struct hs_metrics_store_t {
  /* Virtual port of the service. */
  uint16_t port;
  /* Metrics store. */
  metrics_store_t *store;
} hs_metrics_store_t;

/** Onion service metrics store. Indexed by service identity key. */
static digest256map_t *store_per_hs_addr = NULL;

/** List of onion service stores. The list is indexed by service identity key
 * and then each store in the list is for a specific port. */
static digest256map_t *store_list_per_hs_addr_port = NULL;

/** Helper: Free store_t object. */
static void
free_metrics_store(hs_metrics_store_t *store)
{
  metrics_store_free(store->store);
  tor_free(store);
}

/** Helper: Free the store objects in the given list. */
static void
free_list_metrics_store(smartlist_t *list)
{
  /* Per address + port output. */
  SMARTLIST_FOREACH_BEGIN(list, hs_metrics_store_t *, s) {
    free_metrics_store(s);
  } SMARTLIST_FOREACH_END(s);
  smartlist_free(list);
}

/** Helper: Use to free the store object within a map */
static void
free_metrics_store_(void *store)
{
  free_metrics_store(store);
}

/** Helper: Use to free a list of store object within a map */
static void
free_list_metrics_store_(void *list)
{
  free_list_metrics_store(list);
}

/** Return a pointer to a static buffer containing a formatted label
 * contanining the given address and port.
 *
 * A subsequent call will invalidate the content of the previous one. */
static const char *
hs_build_label(const char *address, const uint16_t port)
{
  static char label[128];

  memset(label, 0, sizeof(label));
  tor_snprintf(label, sizeof(label), "onion=\"%s\"", address);
  if (port != 0) {
    tor_snprintf(label + strlen(label), sizeof(label) - strlen(label),
                 ",port=\"%u\"", port);
  }
  return label;
}

/** Return newly allocated string containing the output of _all_ onion service
 * metric stores (per address and per address + port). */
static char *
hs_metrics_get_output(void)
{
  char *data = NULL;
  smartlist_t *chunks = smartlist_new();

  /* Per address output. */
  DIGEST256MAP_FOREACH(store_per_hs_addr, k, const hs_metrics_store_t *, s) {
    smartlist_add(chunks, metrics_store_get_output(s->store));
  } DIGEST256MAP_FOREACH_END;

  /* Per address + port output. */
  DIGEST256MAP_FOREACH(store_list_per_hs_addr_port, k,
                       const smartlist_t *, list) {
    SMARTLIST_FOREACH_BEGIN(list, const hs_metrics_store_t *, s) {
      smartlist_add(chunks, metrics_store_get_output(s->store));
    } SMARTLIST_FOREACH_END(s);
  } DIGEST256MAP_FOREACH_END;

  data = smartlist_join_strings(chunks, "\n", 0, NULL);

  SMARTLIST_FOREACH(chunks, char *, c, tor_free(c));
  smartlist_free(chunks);

  return data;
}

/** Initialize the subsystem. */
void
metrics_init(void)
{
  if (!store_per_hs_addr) {
    store_per_hs_addr = digest256map_new();
  }
  if (!store_list_per_hs_addr_port) {
    store_list_per_hs_addr_port = digest256map_new();
  }
}

/** Cleanup and free any global memory of this subsystem. */
void
metrics_cleanup(void)
{
  digest256map_free(store_per_hs_addr, free_metrics_store_);
  digest256map_free(store_list_per_hs_addr_port, free_list_metrics_store_);
}

/** Return newly allocated string containing the output of all stores tracked
 * by this module.
 *
 * This is used to output the content on the MetricsPort. */
char *
metrics_get_output(void)
{
  /* We only have an onion service store for now. */
  return hs_metrics_get_output();
}

/** Add a new onion service to the onion service metric store. */
void
metrics_hs_new(const ed25519_public_key_t *key, const char *address,
               const smartlist_t *ports)
{
  smartlist_t *per_addr_port_stores;
  hs_metrics_store_t *store = tor_malloc_zero(sizeof(*store));

  /* This is possible with unit testing. */
  if (!store_per_hs_addr || !store_list_per_hs_addr_port) {
    metrics_init();
  }

  /* Per address only store. */
  store->store = metrics_store_new(METRICS_STORE_TYPE_HS_ADDR,
                                   hs_build_label(address, 0));
  digest256map_set(store_per_hs_addr, key->pubkey, store);

  if (ports && smartlist_len(ports) > 0) {
    per_addr_port_stores = smartlist_new();

    /* Per address + port only store. */
    SMARTLIST_FOREACH_BEGIN(ports, const rend_service_port_config_t *, p) {
      hs_metrics_store_t *p_store= tor_malloc_zero(sizeof(*store));
      p_store->store =
        metrics_store_new(METRICS_STORE_TYPE_HS_ADDR_PORT,
                          hs_build_label(address, p->virtual_port));
      p_store->port = p->virtual_port;
      smartlist_add(per_addr_port_stores, p_store);
    } SMARTLIST_FOREACH_END(p);

    digest256map_set(store_list_per_hs_addr_port, key->pubkey,
                     per_addr_port_stores);
  }
}

/** Remove onion service from the store. Free everything. */
void
metrics_hs_remove(const ed25519_public_key_t *key)
{
  hs_metrics_store_t *store =
    digest256map_remove(store_per_hs_addr, key->pubkey);
  if (store == NULL) {
    return;
  }
  free_metrics_store(store);

  smartlist_t *per_addr_port_stores =
    digest256map_remove(store_list_per_hs_addr_port, key->pubkey);
  if (per_addr_port_stores == NULL) {
    return;
  }

  SMARTLIST_FOREACH(per_addr_port_stores, hs_metrics_store_t *, s,
                    free_metrics_store(s));
  smartlist_free(per_addr_port_stores);
}

/** Update the onion service metric key for the store indexed at the given
 * identity key. */
void
metrics_hs_update(const ed25519_public_key_t *ident_key,
                  const unsigned int key, const uint16_t port,
                  const int64_t n)
{
  hs_metrics_store_t *store = NULL;

  if (port != 0) {
    smartlist_t *list =
      digest256map_get(store_list_per_hs_addr_port, ident_key->pubkey);
    SMARTLIST_FOREACH_BEGIN(list, hs_metrics_store_t *, s) {
      if (s->port == port) {
        store = s;
        break;
      }
    } SMARTLIST_FOREACH_END(s);
  } else {
    store = digest256map_get(store_per_hs_addr, ident_key->pubkey);
  }

  if (store == NULL) {
    return;
  }
  metrics_store_update(store->store, key, n);
}

/** Reset the onion service metric key data for the store indexed at the given
 * identity key and possibly port. */
void
metrics_hs_reset(const ed25519_public_key_t *ident_key,
                 const unsigned int key, const uint16_t port)
{
  hs_metrics_store_t *store = NULL;

  if (port != 0) {
    smartlist_t *list =
      digest256map_get(store_list_per_hs_addr_port, ident_key->pubkey);
    SMARTLIST_FOREACH_BEGIN(list, hs_metrics_store_t *, s) {
      if (s->port == port) {
        store = s;
        break;
      }
    } SMARTLIST_FOREACH_END(s);
  } else {
    store = digest256map_get(store_per_hs_addr, ident_key->pubkey);
  }

  if (store == NULL) {
    return;
  }
  metrics_store_reset(store->store, key);
}
