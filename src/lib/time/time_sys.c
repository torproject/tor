/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file time_sys.c
 * \brief Subsystem object for monotime setup.
 **/

#include "orconfig.h"
#include "lib/subsys/subsys.h"
#include "lib/time/time_sys.h"
#include "lib/time/compat_time.h"

static int
init_time_sys(void)
{
  monotime_init();
  return 0;
}

const subsys_fns_t sys_time = {
  .name = "time",
  .level = -90,
  .supported = true,
  .initialize = init_time_sys,
};
