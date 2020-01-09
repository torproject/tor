/* Copyright (c) 2018-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file log_sys.c
 * \brief Setup and tear down the tracing module.
 **/

#include "lib/subsys/subsys.h"

#include "lib/trace/trace.h"
#include "lib/trace/trace_sys.h"

static int
subsys_tracing_initialize(void)
{
  tor_trace_init();
  return 0;
}

static void
subsys_tracing_shutdown(void)
{
  tor_trace_free_all();
}

const subsys_fns_t sys_tracing = {
  .name = "tracing",
  .supported = true,
  .level = -100,
  .initialize = subsys_tracing_initialize,
  .shutdown = subsys_tracing_shutdown,
};
