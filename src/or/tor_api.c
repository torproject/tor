/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file tor_api.c
 **/

#include "tor_api.h"
#include "tor_api_internal.h"

// Include this after the above headers, to insure that they don't
// depend on anything else.
#include "orconfig.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// We don't want to use tor_malloc and tor_free here, since this needs
// to run before anything is initialized at all, and ought to run when
// we're not linked to anything at all.

#define raw_malloc malloc
#define raw_free free

tor_main_configuration_t *
tor_main_configuration_new(void)
{
  static const char *fake_argv[] = { "tor" };
  tor_main_configuration_t *cfg = raw_malloc(sizeof(*cfg));
  if (cfg == NULL)
    return NULL;

  memset(cfg, 0, sizeof(*cfg));

  cfg->argc = 1;
  cfg->argv = (char **) fake_argv;

  return cfg;
}

int
tor_main_configuration_set_command_line(tor_main_configuration_t *cfg,
                                        int argc, char *argv[])
{
  if (cfg == NULL)
    return -1;
  cfg->argc = argc;
  cfg->argv = argv;
  return 0;
}

void
tor_main_configuration_free(tor_main_configuration_t *cfg)
{
  if (cfg == NULL)
    return;
  raw_free(cfg);
}

/* Main entry point for the Tor process.  Called from main().
 *
 * This function is distinct from main() only so we can link main.c into
 * the unittest binary without conflicting with the unittests' main.
 *
 * Some embedders have historically called this function; but that usage is
 * deprecated: they should use tor_run_main() instead.
 */
int
tor_main(int argc, char *argv[])
{
  tor_main_configuration_t *cfg = tor_main_configuration_new();
  if (!cfg) {
    puts("INTERNAL ERROR: Allocation failure. Cannot proceed");
    return 1;
  }
  if (tor_main_configuration_set_command_line(cfg, argc, argv) < 0) {
    puts("INTERNAL ERROR: Can't set command line. Cannot proceed.");
    return 1;
  }
  int rv = tor_run_main(cfg);
  tor_main_configuration_free(cfg);
  return rv;
}

