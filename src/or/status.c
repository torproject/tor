/* Copyright (c) 2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file status.c
 * \brief Keep status information and log the heartbeat messages.
 **/

#include "or.h"


/****************************************************************************/



#define BEAT(x) log_fn(LOG_NOTICE, LD_HEARTBEAT, (x) )

void
log_heartbeat(time_t now) {
  or_options_t *opt = get_options();

  (void) now;
  log_fn(LOG_NOTICE, LD_HEARTBEAT, "This is the Tor heartbeat message.");
  if (!server_mode(opt))
    BEAT("you are a client, hahaha");

}
