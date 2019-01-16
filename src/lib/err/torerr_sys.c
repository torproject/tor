/* Copyright (c) 2018-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file torerr_sys.c
 * \brief Subsystem object for the error handling subsystem.
 **/

#include "orconfig.h"
#include "lib/err/backtrace.h"
#include "lib/err/torerr.h"
#include "lib/err/torerr_sys.h"
#include "lib/subsys/subsys.h"
#include "lib/version/torversion.h"

#include <stddef.h>

static int
subsys_torerr_initialize(void)
{
  if (configure_backtrace_handler(get_version()) < 0)
    return -1;
  tor_log_reset_sigsafe_err_fds();

  return 0;
}
static void
subsys_torerr_shutdown(void)
{
  tor_log_reset_sigsafe_err_fds();
  clean_up_backtrace_handler();
}

const subsys_fns_t sys_torerr = {
  .name = "err",
  .level = -100,
  .supported = true,
  .initialize = subsys_torerr_initialize,
  .shutdown = subsys_torerr_shutdown
};
