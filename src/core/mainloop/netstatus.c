/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "core/or/or.h"
#include "core/mainloop/netstatus.h"
#include "core/mainloop/mainloop.h"
#include "app/config/config.h"
#include "feature/hibernate/hibernate.h"

/** Return true iff our network is in some sense disabled or shutting down:
 * either we're hibernating, entering hibernation, or the network is turned
 * off with DisableNetwork. */
int
net_is_disabled(void)
{
  return get_options()->DisableNetwork || we_are_hibernating();
}

/** Return true iff our network is in some sense "completely disabled" either
 * we're fully hibernating or the network is turned off with
 * DisableNetwork. */
int
net_is_completely_disabled(void)
{
  return get_options()->DisableNetwork || we_are_fully_hibernating();
}

/**
 * The time at which we've last seen "user activity" -- that is, any activity
 * that should keep us as a participant on the network.
 */
static time_t last_user_activity_seen = 0;

/**
 * True iff we are currently a "network participant" -- that is, we
 * are building circuits, fetching directory information, and so on.
 **/
static bool participating_on_network = false;

/**
 * Record the fact that we have seen "user activity" at the time now.  Move
 * "last activity seen" time forwards, but never backwards.
 *
 * If we were previously not participating on the network, set our
 * participation status to true, and launch periodic events as appropriate.
 **/
void
note_user_activity(time_t now)
{
  last_user_activity_seen = MAX(now, last_user_activity_seen);

  if (! participating_on_network) {
    log_notice(LD_GENERAL, "Tor is no longer dormant.");
    set_network_participation(true);
    schedule_rescan_periodic_events();
  }
}

/**
 * Change the time at which "user activitiy" was last seen to <b>now</b>.
 *
 * Unlike note_user_actity, this function sets the time without checking
 * whether it is in the past, and without causing any rescan of periodic events
 * or change in participation status.
 */
void
reset_user_activity(time_t now)
{
  last_user_activity_seen = now;
}

/**
 * Return the most recent time at which we recorded "user activity".
 **/
time_t
get_last_user_activity_time(void)
{
  return last_user_activity_seen;
}

/**
 * Set the field that remembers whether we are currently participating on the
 * network.  Does not schedule or un-schedule periodic events.
 **/
void
set_network_participation(bool participation)
{
  participating_on_network = participation;
}

/**
 * Return true iff we are currently participating on the network.
 **/
bool
is_participating_on_network(void)
{
  return participating_on_network;
}
