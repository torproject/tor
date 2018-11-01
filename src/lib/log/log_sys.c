/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file log_sys.c
 * \brief Setup and tear down the logging module.
 **/

#include "orconfig.h"
#include "lib/subsys/subsys.h"
#include "lib/log/escape.h"
#include "lib/log/log.h"
#include "lib/log/log_sys.h"

static int
init_logging_subsys(void)
{
  init_logging(0);
  return 0;
}

static void
shutdown_logging_subsys(void)
{
  logs_free_all();
  escaped(NULL);
}

const subsys_fns_t sys_logging = {
  .name = "log",
  .supported = true,
  .level = -90,
  .initialize = init_logging_subsys,
  .shutdown = shutdown_logging_subsys,
};
