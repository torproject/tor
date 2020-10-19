/* Copyright (c) 2007-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file metrics.c
 * @brief Metrics subsystem.
 **/

#include "orconfig.h"

#include "lib/container/smartlist.h"
#include "lib/log/util_bug.h"
#include "lib/malloc/malloc.h"
#include "lib/metrics/metrics_store.h"
#include "lib/string/printf.h"

#include "feature/metrics/metrics.h"

#include "app/main/subsysmgr.h"

/** Return newly allocated string containing the output of all subsystems
 * having metrics.
 *
 * This is used to output the content on the MetricsPort. */
char *
metrics_get_output(const metrics_format_t fmt)
{
  char *data;
  smartlist_t *chunks = smartlist_new();

  /* Go over all subsystems that exposes a metrics store. */
  for (unsigned i = 0; i < n_tor_subsystems; ++i) {
    const smartlist_t *stores;
    const subsys_fns_t *sys = tor_subsystems[i];

    /* Skip unsupported subsystems. */
    if (!sys->supported) {
      continue;
    }

    if (sys->get_metrics && (stores = sys->get_metrics())) {
      SMARTLIST_FOREACH_BEGIN(stores, const metrics_store_t *, store) {
        smartlist_add(chunks, metrics_store_get_output(fmt, store));
      } SMARTLIST_FOREACH_END(store);
    }
  }

  data = smartlist_join_strings(chunks, "\n", 0, NULL);

  SMARTLIST_FOREACH(chunks, char *, c, tor_free(c));
  smartlist_free(chunks);

  return data;
}

/** Initialize the subsystem. */
void
metrics_init(void)
{
}

/** Cleanup and free any global memory of this subsystem. */
void
metrics_cleanup(void)
{
}
