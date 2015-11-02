/* Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_PERIODIC_H
#define TOR_PERIODIC_H

/** Callback function for a periodic event to take action.
* The return value influences the next time the function will get called.
* Return -1 to not update <b>last_action_time</b> and be polled again in
* the next second. If a positive value is returned it will update the
* interval time. If the returned value is larger than <b>now</b> then it
* is assumed to be a future time to poll again. */
typedef int (*periodic_event_helper_t)(time_t now,
                                      const or_options_t *options);


/** A single item for the periodic-events-function table. */
typedef struct periodic_event_item_t {
  periodic_event_helper_t fn; /**< The function to run the event */
  int interval; /**< The interval for running the function (In seconds). */
  time_t last_action_time; /**< The last time the function did something */
  periodic_timer_t *timer; /**< Timer object for this event */
  const char *name; /**< Name of the function -- for debug */
} periodic_event_item_t;

/** events will get their interval from first execution */
#define PERIODIC_EVENT(fn) { fn##_callback, 0, 0, NULL, #fn }

#if 0
/** Refactor test, check the last_action_time was now or (now - delta - 1)
* It returns an incremented <b>now</b> value and accounts for the current
* implementation's off by one error in it's comparisons. */
#define INCREMENT_DELTA_AND_TEST(id, now, delta) \
  (now+delta);                                   \
  STMT_BEGIN \
    periodic_event_item_t *ev = &periodic_events[id]; \
    if (ev->last_action_time != now - delta - 1 && \
        ev->last_action_time != now) { \
      log_err(LD_BUG, "[Refactor Bug] Missed an interval " \
        "for %s, Got %lu, wanted %lu or %lu.", ev->name, \
        ev->last_action_time, now, now-delta); \
      tor_assert(0); \
    } \
    STMT_END
#endif

void periodic_event_assert_in_range(periodic_event_item_t *event,
                                    time_t start, time_t end);
void periodic_event_launch(periodic_event_item_t *event);
void periodic_event_destroy(periodic_event_item_t *event);
void periodic_event_reschedule(periodic_event_item_t *event);

#endif

