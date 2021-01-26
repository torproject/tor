/* Copyright (c) 2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file dos_sys.c
 * @brief Subsystem definitions for DOS module.
 **/

#include "lib/subsys/subsys.h"

#include "core/or/dos.h"
#include "core/or/dos_sys.h"

static int
subsys_dos_initialize(void)
{
  return 0;
}

static void
subsys_dos_shutdown(void)
{
}

const struct subsys_fns_t sys_dos = {
  SUBSYS_DECLARE_LOCATION(),

  .name = "dos",
  .supported = true,
  .level = DOS_SUBSYS_LEVEL,

  .initialize = subsys_dos_initialize,
  .shutdown = subsys_dos_shutdown,
};
