/* Copyright (c) 2018, The Tor Project, Inc. */
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
torerr_subsys_init(void)
{
  configure_backtrace_handler(get_version());
  tor_log_reset_sigsafe_err_fds();

  return 0;
}
static void
torerr_subsys_shutdown(void)
{
  tor_log_reset_sigsafe_err_fds();
  clean_up_backtrace_handler();
}

const subsys_fns_t sys_torerr = {
  .name = "err",
  .level = -100,
  .supported = true,
  .initialize = torerr_subsys_init,
  .shutdown = torerr_subsys_shutdown
};
