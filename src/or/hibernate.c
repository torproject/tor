/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file hibernate.c
 * \brief Functions to close listeners, stop allowing new circuits,
 * etc in preparation for closing down or going dormant.
 **/

/*
hibernating, phase 1:
  - send destroy in response to create cells
  - send end (policy failed) in response to begin cells
  - close an OR conn when it has no circuits

hibernating, phase 2:
  (entered when bandwidth hard limit reached)
  - close all OR/AP/exit conns)
*/

#include "or.h"

#define HIBERNATE_STATE_LIVE 1
#define HIBERNATE_STATE_EXITING 2
#define HIBERNATE_STATE_LOWBANDWIDTH 3
#define HIBERNATE_STATE_DORMANT 4

#define SHUTDOWN_WAIT_LENGTH 30 /* seconds */

int hibernate_state = HIBERNATE_STATE_LIVE;
time_t hibernate_timeout = 0;

/** Returns 1 if the bandwidth soft limit has been reached, else 0. */
static int hibernate_soft_limit_reached(void) {
  return accounting_soft_limit_reached();
}

/** Returns 1 if the bandwidth hard limit has been reached, else 0. */
static int hibernate_hard_limit_reached(void) {
  return accounting_hard_limit_reached();
}

/** Return the time when we should stop being dormant. */
static time_t hibernate_calc_wakeup_time(void) {
  return accounting_get_wakeup_time();
}

/** Called when we get a SIGINT, or when bandwidth soft limit
 * is reached. */
static void hibernate_begin(int new_state) {
  connection_t *conn;

  if(hibernate_state == HIBERNATE_STATE_EXITING) {
    /* we've been called twice now. close immediately. */
    log(LOG_NOTICE,"Second sigint received; exiting now.");
    tor_cleanup();
    exit(0);
  }

  tor_assert(hibernate_state == HIBERNATE_STATE_LIVE);

  /* close listeners */
  while((conn = connection_get_by_type(CONN_TYPE_OR_LISTENER)) ||
        (conn = connection_get_by_type(CONN_TYPE_AP_LISTENER)) ||
        (conn = connection_get_by_type(CONN_TYPE_DIR_LISTENER))) {
    log_fn(LOG_INFO,"Closing listener type %d", conn->type);
    connection_mark_for_close(conn);
  }

  /* XXX kill intro point circs */
  /* XXX upload rendezvous service descriptors with no intro points */

  if(new_state == HIBERNATE_STATE_EXITING) {
    log(LOG_NOTICE,"Interrupt: will shut down in %d seconds. Interrupt again to exit now.", SHUTDOWN_WAIT_LENGTH);
    hibernate_timeout = time(NULL) + SHUTDOWN_WAIT_LENGTH;
  } else { /* soft limit reached */
    log_fn(LOG_NOTICE,"Bandwidth limit reached; beginning hibernation.");
    hibernate_timeout = hibernate_calc_wakeup_time();
  }

  hibernate_state = new_state;
}

/** Called when we've been hibernating and our timeout is reached. */
static void hibernate_end(int new_state) {

  tor_assert(hibernate_state == HIBERNATE_STATE_LOWBANDWIDTH ||
             hibernate_state == HIBERNATE_STATE_DORMANT);

  /* listeners will be relaunched in run_scheduled_events() in main.c */
  log_fn(LOG_NOTICE,"Hibernation period ended. Resuming normal activity.");

  hibernate_state = new_state;
  hibernate_timeout = 0; /* no longer hibernating */
}

/** A wrapper around hibernate_begin, for when we get SIGINT. */
void hibernate_begin_shutdown(void) {
  hibernate_begin(HIBERNATE_STATE_EXITING);
}

/** A wrapper to expose whether we're hibernating. */
int we_are_hibernating(void) {
  return hibernate_state != HIBERNATE_STATE_LIVE;
}

/** The big function. Consider our environment and decide if it's
 * time to start/stop hibernating.
 */
void consider_hibernation(time_t now) {
  connection_t *conn;

  if (hibernate_state != HIBERNATE_STATE_LIVE)
    tor_assert(hibernate_timeout);

  if (hibernate_state == HIBERNATE_STATE_EXITING) {
    if(hibernate_timeout <= now) {
      log(LOG_NOTICE,"Clean shutdown finished. Exiting.");
      tor_cleanup();
      exit(0);
    }
    return; /* if exiting soon, don't worry about bandwidth limits */
  }

  if(hibernate_timeout && hibernate_timeout <= now) {
    /* we've been hibernating; time to wake up. */
    hibernate_end(HIBERNATE_STATE_LIVE);
    return;
  }

  /* else, see if it's time to start hibernating */

  if (hibernate_state == HIBERNATE_STATE_LIVE &&
      hibernate_soft_limit_reached()) {
    log_fn(LOG_NOTICE,"Bandwidth soft limit reached; commencing hibernation.");
    hibernate_begin(HIBERNATE_STATE_LOWBANDWIDTH);
  }

  if (hibernate_state == HIBERNATE_STATE_LOWBANDWIDTH &&
      hibernate_hard_limit_reached()) {
    hibernate_state = HIBERNATE_STATE_DORMANT;
    log_fn(LOG_NOTICE,"Going dormant. Blowing away remaining connections.");

    /* Close all OR/AP/exit conns. Leave dir conns. */
    while((conn = connection_get_by_type(CONN_TYPE_OR)) ||
          (conn = connection_get_by_type(CONN_TYPE_AP)) ||
          (conn = connection_get_by_type(CONN_TYPE_EXIT))) {
      log_fn(LOG_INFO,"Closing conn type %d", conn->type);
      connection_mark_for_close(conn);
    }
  }
}

