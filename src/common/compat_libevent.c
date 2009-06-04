/* Copyright (c) 2009, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file compat_libevent.c
 * \brief Wrappers to handle porting between different versions of libevent.
 *
 * In an ideal world, we'd just use Libevent 2.0 from now on.  But as of June
 * 2009, Libevent 2.0 is still in alpha, and we will have old versions of
 * Libevent for the forseeable future.
 **/

#include "orconfig.h"
#include "compat_libevent.h"

#include "compat.h"
#include "util.h"
#include "log.h"

#ifdef HAVE_EVENT2_EVENT_H
#include <event2/event.h>
#else
#include <event.h>
#endif

#ifdef HAVE_EVENT_SET_LOG_CALLBACK
/** A string which, if it appears in a libevent log, should be ignored. */
static const char *suppress_msg = NULL;
/** Callback function passed to event_set_log() so we can intercept
 * log messages from libevent. */
static void
libevent_logging_callback(int severity, const char *msg)
{
  char buf[1024];
  size_t n;
  if (suppress_msg && strstr(msg, suppress_msg))
    return;
  n = strlcpy(buf, msg, sizeof(buf));
  if (n && n < sizeof(buf) && buf[n-1] == '\n') {
    buf[n-1] = '\0';
  }
  switch (severity) {
    case _EVENT_LOG_DEBUG:
      log(LOG_DEBUG, LD_NET, "Message from libevent: %s", buf);
      break;
    case _EVENT_LOG_MSG:
      log(LOG_INFO, LD_NET, "Message from libevent: %s", buf);
      break;
    case _EVENT_LOG_WARN:
      log(LOG_WARN, LD_GENERAL, "Warning from libevent: %s", buf);
      break;
    case _EVENT_LOG_ERR:
      log(LOG_ERR, LD_GENERAL, "Error from libevent: %s", buf);
      break;
    default:
      log(LOG_WARN, LD_GENERAL, "Message [%d] from libevent: %s",
          severity, buf);
      break;
  }
}
/** Set hook to intercept log messages from libevent. */
void
configure_libevent_logging(void)
{
  event_set_log_callback(libevent_logging_callback);
}
/** Ignore any libevent log message that contains <b>msg</b>. */
void
suppress_libevent_log_msg(const char *msg)
{
  suppress_msg = msg;
}
#else
void
configure_libevent_logging(void)
{
}
void
suppress_libevent_log_msg(const char *msg)
{
  (void)msg;
}
#endif

#ifndef HAVE_EVENT2_EVENT_H
/** Work-alike replacement for event_new() on pre-Libevent-2.0 systems. */
struct event *
tor_event_new(struct event_base *base, int sock, short what,
              void (*cb)(int, short, void *), void *arg)
{
  struct event *e = tor_malloc_zero(sizeof(struct event));
  event_set(e, sock, what, cb, arg);
  event_base_set(base, e);
  return e;
}
/** Work-alike replacement for evtimer_new() on pre-Libevent-2.0 systems. */
struct event *
tor_evtimer_new(struct event_base *base,
                void (*cb)(int, short, void *), void *arg)
{
  return tor_event_new(base, -1, 0, cb, arg);
}
/** Work-alike replacement for evsignal_new() on pre-Libevent-2.0 systems. */
struct event *
tor_evsignal_new(struct event_base * base, int sig,
                 void (*cb)(int, short, void *), void *arg)
{
  return tor_event_new(base, sig, EV_SIGNAL, cb, arg);
}
/** Work-alike replacement for event_free() on pre-Libevent-2.0 systems. */
void
tor_event_free(struct event *ev)
{
  event_del(ev);
  tor_free(ev);
}
#endif

/** Global event base for use by the main thread. */
struct event_base *the_event_base = NULL;

/** Initialize the Libevent library and set up the event base. */
void
tor_libevent_initialize(void)
{
  tor_assert(the_event_base == NULL);
#ifdef HAVE_EVENT2_EVENT_H
  the_event_base = event_base_new();
#else
  the_event_base = event_init();
#endif
}

/** Return the current Libevent event base that we're set up to use. */
struct event_base *
tor_libevent_get_base(void)
{
  return the_event_base;
}

/** Return the name of the Libevent backend we're using. */
const char *
tor_libevent_get_method(void)
{
#ifdef HAVE_EVENT2_EVENT_H
  return event_base_get_method(the_event_base);
#elif defined(HAVE_EVENT_GET_METHOD)
  return event_get_method();
#else
  return "<unknown>";
#endif
}

