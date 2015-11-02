/* Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#include "config.h"
#include "periodic.h"

static const int MAX_INTERVAL = 10 * 365 * 86400;

/** DOCDOC */
static void
periodic_event_set_interval(periodic_event_item_t *event,
                            time_t next_interval)
{
  /** update the interval time if it's changed */
  if (next_interval != event->interval) {
    tor_assert(next_interval < MAX_INTERVAL);
    struct timeval tv;
    tv.tv_sec = next_interval;
    tv.tv_usec = 0;
    event->interval = (int)next_interval;
    periodic_timer_update_interval(event->timer, &tv);
  }
}

/** Wraps dispatches for periodic events, <b>data</b> will be a pointer to the
 * event that needs to be called */
static void
periodic_event_dispatch(periodic_timer_t *timer, void *data)
{
  periodic_event_item_t *event = data;
  tor_assert(timer == event->timer);

  time_t now = time(NULL);
  const or_options_t *options = get_options();
  int r = event->fn(now, options);
  int next_interval = 0;

  /* update the last run time if action was taken */
  if (r==0) {
    log_err(LD_BUG, "Invalid return value for periodic event from %s.",
                      event->name);
    tor_assert(r != 0);
  } else if (r > 0) {
    event->last_action_time = now;
    /* If the event is meant to happen after ten years, that's likely
     * a bug, and somebody gave an absolute time rather than an interval.
     */
    tor_assert(r < MAX_INTERVAL);
    next_interval = r;
  } else {
    /* no action was taken, it is likely a precondition failed,
     * we should reschedule for next second incase the precondition
     * passes then */
    next_interval = 1;
  }

  periodic_event_set_interval(event, next_interval);

  log_info(LD_GENERAL, "Dispatching %s", event->name);
}

/** DOCDOC */
void
periodic_event_reschedule(periodic_event_item_t *event)
{
  periodic_event_set_interval(event, 1);
}

/** Handles initial dispatch for periodic events. It should happen 1 second
 * after the events are created to mimic behaviour before #3199's refactor */
void
periodic_event_launch(periodic_event_item_t *event)
{
  if (event->timer) { /** Already setup? This is a bug */
    log_err(LD_BUG, "Initial dispatch should only be done once.");
    tor_assert(0);
  }

  struct timeval interval;
  interval.tv_sec = event->interval;
  interval.tv_usec = 0;

  periodic_timer_t *timer = periodic_timer_new(tor_libevent_get_base(),
                                               &interval,
                                               periodic_event_dispatch,
                                               event);
  tor_assert(timer);
  event->timer = timer;

  // Initial dispatch
  periodic_event_dispatch(timer, event);
}

/** DOCDOC */
void
periodic_event_destroy(periodic_event_item_t *event)
{
  if (!event)
    return;
  periodic_timer_free(event->timer);
  event->timer = 0;
  event->interval = 0;
  event->last_action_time = 0;
}

