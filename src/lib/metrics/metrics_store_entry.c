/* Copyright (c) 2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file metrics_store_entry.c
 * @brief Metrics store entry which contains the gathered data.
 **/

#define METRICS_STORE_ENTRY_PRIVATE

#include <string.h>

#include "orconfig.h"

#include "lib/container/smartlist.h"
#include "lib/log/util_bug.h"
#include "lib/malloc/malloc.h"
#include "lib/metrics/metrics_store_entry.h"
#include "lib/string/printf.h"

/*
 * Public API.
 */

/** Return newly allocated store entry of type COUNTER. */
metrics_store_entry_t *
metrics_store_entry_new(const metrics_entry_model_t *model)
{
  metrics_store_entry_t *entry = tor_malloc_zero(sizeof(*entry));

  tor_assert(model);

  entry->key = model->key;
  entry->type = model->type;
  entry->name = model->name;
  entry->help = model->help;

  return entry;
}

/** Free a store entry. */
void
metrics_store_entry_free_(metrics_store_entry_t *entry)
{
  if (!entry) {
    return;
  }
  tor_free(entry);
}

/** Update a store entry with value. */
void
metrics_store_entry_update(metrics_store_entry_t *entry, const int64_t value)
{
  tor_assert(entry);

  switch (entry->type) {
  case METRICS_TYPE_COUNTER:
    /* Counter type always increment. */
    entry->u.counter.value += value;
    break;
  case METRICS_TYPE_GAUGE:
    /* Guage might go down or not. */
    entry->u.gauge.value += value;
    break;
  }
}

/** Reset a store entry that is set its metric data to 0. */
void
metrics_store_entry_reset(metrics_store_entry_t *entry)
{
  tor_assert(entry);
  /* Everything back to 0. */
  memset(&entry->u, 0, sizeof(entry->u));
}

/** Return newly allocated string containing the ouput of the given entry.
 *
 * If label is not NULL, it is added to the output. */
char *
metrics_store_entry_get_output(const metrics_store_entry_t *entry,
                               const char *label)
{
  uint64_t value;
  char *label_formatted, *output = NULL;
  smartlist_t *lines = smartlist_new();

  tor_assert(entry);

  value = metrics_store_entry_get_value(entry);

  if (label) {
    tor_asprintf(&label_formatted, "{%s}", label);
  } else {
    label_formatted = tor_strdup("");
  }

  smartlist_add_asprintf(lines, "# HELP %s %s", entry->name, entry->help);
  smartlist_add_asprintf(lines, "# TYPE %s %s", entry->name,
                         metrics_type_to_str(entry->type));
  smartlist_add_asprintf(lines, "%s%s %" PRIu64, entry->name, label_formatted,
                         value);

  output = smartlist_join_strings(lines, "\n", 0, NULL);

  SMARTLIST_FOREACH(lines, char *, l, tor_free(l));
  smartlist_free(lines);
  tor_free(label_formatted);

  return output;
}

/** Return store entry value. */
uint64_t
metrics_store_entry_get_value(const metrics_store_entry_t *entry)
{
  tor_assert(entry);

  switch (entry->type) {
  case METRICS_TYPE_COUNTER:
    return entry->u.counter.value;
  case METRICS_TYPE_GAUGE:
    return entry->u.gauge.value;
  }

  // LCOV_EXCL_START
  tor_assert_unreached();
  // LCOV_EXCL_STOP
}
