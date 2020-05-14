/* Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file btrack.c
 * \brief Bootstrap trackers
 *
 * Initializes and shuts down the specific bootstrap trackers.  These
 * trackers help the reporting of bootstrap progress by maintaining
 * state information about various subsystems within tor.  When the
 * correct state changes happen, these trackers emit controller
 * events.
 *
 * These trackers avoid referring directly to the internals of state
 * objects of other subsystems.
 *
 * btrack_circuit.c contains the tracker for origin circuits.
 *
 * btrack_orconn.c contains the tracker for OR connections.
 *
 * Eventually there will be a tracker for directory downloads as well.
 **/

#include "feature/control/btrack_circuit.h"
#include "feature/control/btrack_orconn.h"
#include "feature/control/btrack_sys.h"
#include "lib/subsys/subsys.h"

static int
btrack_init(void)
{
  if (btrack_orconn_init())
    return -1;
  if (btrack_circ_init())
    return -1;

  return 0;
}

static void
btrack_fini(void)
{
  btrack_orconn_fini();
  btrack_circ_fini();
}

const subsys_fns_t sys_btrack = {
  .name = "btrack",
  .supported = true,
  .level = -30,
  .initialize = btrack_init,
  .shutdown = btrack_fini,
};
