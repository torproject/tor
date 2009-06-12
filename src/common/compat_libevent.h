/* Copyright (c) 2009, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef _TOR_COMPAT_LIBEVENT_H
#define _TOR_COMPAT_LIBEVENT_H

#include "orconfig.h"

struct event;
struct event_base;

#ifdef HAVE_EVENT2_EVENT_H
#include <event2/util.h>
#else
#define evutil_socket_t int
#endif

void configure_libevent_logging(void);
void suppress_libevent_log_msg(const char *msg);

#ifdef HAVE_EVENT2_EVENT_H
#define tor_event_new     event_new
#define tor_evtimer_new   evtimer_new
#define tor_evsignal_new  evsignal_new
#define tor_event_free    event_free
#else
struct event *tor_event_new(struct event_base * base, evutil_socket_t sock,
           short what, void (*cb)(evutil_socket_t, short, void *), void *arg);
struct event *tor_evtimer_new(struct event_base * base,
            void (*cb)(evutil_socket_t, short, void *), void *arg);
struct event *tor_evsignal_new(struct event_base * base, int sig,
            void (*cb)(evutil_socket_t, short, void *), void *arg);
void tor_event_free(struct event *ev);
#endif

/* XXXX022 If we can drop support for Libevent before 1.1, we can
 * do without this wrapper. */
#ifdef HAVE_EVENT_BASE_LOOPEXIT
#define tor_event_base_loopexit event_base_loopexit
#else
struct timeval;
int tor_event_base_loopexit(struct event_base *base, struct timeval *tv);
#endif

void tor_libevent_initialize(void);
struct event_base *tor_libevent_get_base(void);
const char *tor_libevent_get_method(void);
void tor_check_libevent_version(const char *m, int server,
                                const char **badness_out);
void tor_check_libevent_header_compatibility(void);
const char *tor_libevent_get_version_str(void);

#endif

