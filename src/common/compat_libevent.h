/* Copyright (c) 2009-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_COMPAT_LIBEVENT_H
#define TOR_COMPAT_LIBEVENT_H

#include "orconfig.h"
#include "testsupport.h"

struct event;
struct event_base;
#ifdef USE_BUFFEREVENTS
struct bufferevent;
struct ev_token_bucket_cfg;
struct bufferevent_rate_limit_group;
#endif

#include <event2/util.h>

void configure_libevent_logging(void);
void suppress_libevent_log_msg(const char *msg);

#define tor_event_new     event_new
#define tor_evtimer_new   evtimer_new
#define tor_evsignal_new  evsignal_new
#define tor_evdns_add_server_port(sock, tcp, cb, data) \
  evdns_add_server_port_with_base(tor_libevent_get_base(), \
  (sock),(tcp),(cb),(data));

void tor_event_free(struct event *ev);

typedef struct periodic_timer_t periodic_timer_t;

periodic_timer_t *periodic_timer_new(struct event_base *base,
             const struct timeval *tv,
             void (*cb)(periodic_timer_t *timer, void *data),
             void *data);
void periodic_timer_free(periodic_timer_t *);

#define tor_event_base_loopexit event_base_loopexit

/** Defines a configuration for using libevent with Tor: passed as an argument
 * to tor_libevent_initialize() to describe how we want to set up. */
typedef struct tor_libevent_cfg {
  /** Flag: if true, disable IOCP (assuming that it could be enabled). */
  int disable_iocp;
  /** How many CPUs should we use (relevant only with IOCP). */
  int num_cpus;
  /** How many milliseconds should we allow between updating bandwidth limits?
   * (relevant only with bufferevents). */
  int msec_per_tick;
} tor_libevent_cfg;

void tor_libevent_initialize(tor_libevent_cfg *cfg);
MOCK_DECL(struct event_base *, tor_libevent_get_base, (void));
const char *tor_libevent_get_method(void);
void tor_check_libevent_header_compatibility(void);
const char *tor_libevent_get_version_str(void);
const char *tor_libevent_get_header_version_str(void);

#ifdef USE_BUFFEREVENTS
const struct timeval *tor_libevent_get_one_tick_timeout(void);
int tor_libevent_using_iocp_bufferevents(void);
int tor_set_bufferevent_rate_limit(struct bufferevent *bev,
                                   struct ev_token_bucket_cfg *cfg);
int tor_add_bufferevent_to_rate_limit_group(struct bufferevent *bev,
                                   struct bufferevent_rate_limit_group *g);
#endif

int tor_init_libevent_rng(void);

void tor_gettimeofday_cached(struct timeval *tv);
void tor_gettimeofday_cache_clear(void);
#ifdef TOR_UNIT_TESTS
void tor_gettimeofday_cache_set(const struct timeval *tv);
#endif
void tor_gettimeofday_cached_monotonic(struct timeval *tv);

#ifdef COMPAT_LIBEVENT_PRIVATE
/** A number representing a version of Libevent.

    This is a 4-byte number, with the first three bytes representing the
    major, minor, and patchlevel respectively of the library.  The fourth
    byte is unused.

    This is equivalent to the format of LIBEVENT_VERSION_NUMBER on Libevent
    2.0.1 or later.
*/
typedef uint32_t le_version_t;

/** @{ */
/** Macros: returns the number of a libevent version as a le_version_t */
#define V(major, minor, patch) \
  (((major) << 24) | ((minor) << 16) | ((patch) << 8))
/** @} */

STATIC void
libevent_logging_callback(int severity, const char *msg);
#endif

#endif

