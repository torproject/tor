/* Copyright (c) 2020-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file hs_metrics_entry.c
 * @brief Defines the metrics entry that are collected by an onion service.
 **/

#define HS_METRICS_ENTRY_PRIVATE

#include "orconfig.h"

#include "lib/cc/compat_compiler.h"

#include "feature/hs/hs_metrics_entry.h"

/** The base metrics that is a static array of metrics that are added to every
 * single new stores.
 *
 * The key member MUST be also the index of the entry in the array. */
const hs_metrics_entry_t base_metrics[] =
{
  {
    .key = HS_METRICS_NUM_INTRODUCTIONS,
    .type = METRICS_TYPE_COUNTER,
    .name = METRICS_NAME(hs_intro_num_total),
    .help = "Total number of introduction received",
    .port_as_label = false,
  },
  {
    .key = HS_METRICS_APP_WRITE_BYTES,
    .type = METRICS_TYPE_COUNTER,
    .name = METRICS_NAME(hs_app_write_bytes_total),
    .help = "Total number of bytes written to the application",
    .port_as_label = true,
  },
  {
    .key = HS_METRICS_APP_READ_BYTES,
    .type = METRICS_TYPE_COUNTER,
    .name = METRICS_NAME(hs_app_read_bytes_total),
    .help = "Total number of bytes read from the application",
    .port_as_label = true,
  },
  {
    .key = HS_METRICS_NUM_ESTABLISHED_RDV,
    .type = METRICS_TYPE_GAUGE,
    .name = METRICS_NAME(hs_rdv_established_count),
    .help = "Total number of established rendezvous circuits",
  },
  {
    .key = HS_METRICS_NUM_RDV,
    .type = METRICS_TYPE_COUNTER,
    .name = METRICS_NAME(hs_rdv_num_total),
    .help = "Total number of rendezvous circuits created",
  },
  {
    .key = HS_METRICS_NUM_FAILED_RDV,
    .type = METRICS_TYPE_COUNTER,
    .name = METRICS_NAME(hs_rdv_error_count),
    .help = "Total number of rendezvous circuit errors",
  },
  {
    .key = HS_METRICS_NUM_ESTABLISHED_INTRO,
    .type = METRICS_TYPE_GAUGE,
    .name = METRICS_NAME(hs_intro_established_count),
    .help = "Total number of established introduction circuit",
  },
  {
    .key = HS_METRICS_NUM_REJECTED_INTRO_REQ,
    .type = METRICS_TYPE_COUNTER,
    .name = METRICS_NAME(hs_intro_rejected_intro_req_count),
    .help = "Total number of rejected introduction circuits",
  },
};

/** Size of base_metrics array that is number of entries. */
const size_t base_metrics_size = ARRAY_LENGTH(base_metrics);
