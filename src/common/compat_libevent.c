/* Copyright (c) 2009-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file compat_libevent.c
 * \brief Wrappers to handle porting between different versions of libevent.
 *
 * In an ideal world, we'd just use Libevent 2.0 from now on.  But as of June
 * 2012, Libevent 1.4 is still all over, and some poor souls are stuck on
 * Libevent 1.3e. */

#include "orconfig.h"
#include "compat.h"
#define COMPAT_LIBEVENT_PRIVATE
#include "compat_libevent.h"

#include "crypto.h"

#include "util.h"
#include "torlog.h"

#include <event2/event.h>
#include <event2/thread.h>
#ifdef USE_BUFFEREVENTS
#include <event2/bufferevent.h>
#endif

/** A string which, if it appears in a libevent log, should be ignored. */
static const char *suppress_msg = NULL;
/** Callback function passed to event_set_log() so we can intercept
 * log messages from libevent. */
STATIC void
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
      log_debug(LD_NOCB|LD_NET, "Message from libevent: %s", buf);
      break;
    case _EVENT_LOG_MSG:
      log_info(LD_NOCB|LD_NET, "Message from libevent: %s", buf);
      break;
    case _EVENT_LOG_WARN:
      log_warn(LD_NOCB|LD_GENERAL, "Warning from libevent: %s", buf);
      break;
    case _EVENT_LOG_ERR:
      log_err(LD_NOCB|LD_GENERAL, "Error from libevent: %s", buf);
      break;
    default:
      log_warn(LD_NOCB|LD_GENERAL, "Message [%d] from libevent: %s",
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

/* Wrapper for event_free() that tolerates tor_event_free(NULL) */
void
tor_event_free(struct event *ev)
{
  if (ev == NULL)
    return;
  event_free(ev);
}

/** Global event base for use by the main thread. */
static struct event_base *the_event_base = NULL;

/* This is what passes for version detection on OSX.  We set
 * MACOSX_KQUEUE_IS_BROKEN to true iff we're on a version of OSX before
 * 10.4.0 (aka 1040). */
#ifdef __APPLE__
#ifdef __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__
#define MACOSX_KQUEUE_IS_BROKEN \
  (__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ < 1040)
#else
#define MACOSX_KQUEUE_IS_BROKEN 0
#endif
#endif

#ifdef USE_BUFFEREVENTS
static int using_iocp_bufferevents = 0;
static void tor_libevent_set_tick_timeout(int msec_per_tick);

int
tor_libevent_using_iocp_bufferevents(void)
{
  return using_iocp_bufferevents;
}
#endif

/** Initialize the Libevent library and set up the event base. */
void
tor_libevent_initialize(tor_libevent_cfg *torcfg)
{
  tor_assert(the_event_base == NULL);
  /* some paths below don't use torcfg, so avoid unused variable warnings */
  (void)torcfg;

  {
    int attempts = 0;
    int using_threads;
    struct event_config *cfg;

  retry:
    ++attempts;
    using_threads = 0;
    cfg = event_config_new();
    tor_assert(cfg);

#if defined(_WIN32) && defined(USE_BUFFEREVENTS)
    if (! torcfg->disable_iocp) {
      evthread_use_windows_threads();
      event_config_set_flag(cfg, EVENT_BASE_FLAG_STARTUP_IOCP);
      using_iocp_bufferevents = 1;
      using_threads = 1;
    } else {
      using_iocp_bufferevents = 0;
    }
#elif defined(__COVERITY__)
    /* Avoid a 'dead code' warning below. */
    using_threads = ! torcfg->disable_iocp;
#endif

    if (!using_threads) {
      /* Telling Libevent not to try to turn locking on can avoid a needless
       * socketpair() attempt. */
      event_config_set_flag(cfg, EVENT_BASE_FLAG_NOLOCK);
    }

    if (torcfg->num_cpus > 0)
      event_config_set_num_cpus_hint(cfg, torcfg->num_cpus);

    /* We can enable changelist support with epoll, since we don't give
     * Libevent any dup'd fds.  This lets us avoid some syscalls. */
    event_config_set_flag(cfg, EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST);

    the_event_base = event_base_new_with_config(cfg);

    event_config_free(cfg);

    if (using_threads && the_event_base == NULL && attempts < 2) {
      /* This could be a socketpair() failure, which can happen sometimes on
       * windows boxes with obnoxious firewall rules.  Downgrade and try
       * again. */
#if defined(_WIN32) && defined(USE_BUFFEREVENTS)
      if (torcfg->disable_iocp == 0) {
        log_warn(LD_GENERAL, "Unable to initialize Libevent. Trying again "
                 "with IOCP disabled.");
      } else
#endif
      {
          log_warn(LD_GENERAL, "Unable to initialize Libevent. Trying again.");
      }

      torcfg->disable_iocp = 1;
      goto retry;
    }
  }

  if (!the_event_base) {
    /* LCOV_EXCL_START */
    log_err(LD_GENERAL, "Unable to initialize Libevent: cannot continue.");
    exit(1);
    /* LCOV_EXCL_STOP */
  }

  log_info(LD_GENERAL,
      "Initialized libevent version %s using method %s. Good.",
      event_get_version(), tor_libevent_get_method());

#ifdef USE_BUFFEREVENTS
  tor_libevent_set_tick_timeout(torcfg->msec_per_tick);
#endif
}

/** Return the current Libevent event base that we're set up to use. */
MOCK_IMPL(struct event_base *,
tor_libevent_get_base, (void))
{
  tor_assert(the_event_base != NULL);
  return the_event_base;
}

/** Return the name of the Libevent backend we're using. */
const char *
tor_libevent_get_method(void)
{
  return event_base_get_method(the_event_base);
}

/** Return a string representation of the version of the currently running
 * version of Libevent. */
const char *
tor_libevent_get_version_str(void)
{
  return event_get_version();
}

/** Return a string representation of the version of Libevent that was used
* at compilation time. */
const char *
tor_libevent_get_header_version_str(void)
{
  return LIBEVENT_VERSION;
}

/** Represents a timer that's run every N microseconds by Libevent. */
struct periodic_timer_t {
  /** Underlying event used to implement this periodic event. */
  struct event *ev;
  /** The callback we'll be invoking whenever the event triggers */
  void (*cb)(struct periodic_timer_t *, void *);
  /** User-supplied data for the callback */
  void *data;
};

/** Libevent callback to implement a periodic event. */
static void
periodic_timer_cb(evutil_socket_t fd, short what, void *arg)
{
  periodic_timer_t *timer = arg;
  (void) what;
  (void) fd;
  timer->cb(timer, timer->data);
}

/** Create and schedule a new timer that will run every <b>tv</b> in
 * the event loop of <b>base</b>.  When the timer fires, it will
 * run the timer in <b>cb</b> with the user-supplied data in <b>data</b>. */
periodic_timer_t *
periodic_timer_new(struct event_base *base,
                   const struct timeval *tv,
                   void (*cb)(periodic_timer_t *timer, void *data),
                   void *data)
{
  periodic_timer_t *timer;
  tor_assert(base);
  tor_assert(tv);
  tor_assert(cb);
  timer = tor_malloc_zero(sizeof(periodic_timer_t));
  if (!(timer->ev = tor_event_new(base, -1, EV_PERSIST,
                                  periodic_timer_cb, timer))) {
    tor_free(timer);
    return NULL;
  }
  timer->cb = cb;
  timer->data = data;
  event_add(timer->ev, (struct timeval *)tv); /*drop const for old libevent*/
  return timer;
}

/** Stop and free a periodic timer */
void
periodic_timer_free(periodic_timer_t *timer)
{
  if (!timer)
    return;
  tor_event_free(timer->ev);
  tor_free(timer);
}

#ifdef USE_BUFFEREVENTS
static const struct timeval *one_tick = NULL;
/**
 * Return a special timeout to be passed whenever libevent's O(1) timeout
 * implementation should be used. Only use this when the timer is supposed
 * to fire after msec_per_tick ticks have elapsed.
*/
const struct timeval *
tor_libevent_get_one_tick_timeout(void)
{
  tor_assert(one_tick);
  return one_tick;
}

/** Initialize the common timeout that we'll use to refill the buckets every
 * time a tick elapses. */
static void
tor_libevent_set_tick_timeout(int msec_per_tick)
{
  struct event_base *base = tor_libevent_get_base();
  struct timeval tv;

  tor_assert(! one_tick);
  tv.tv_sec = msec_per_tick / 1000;
  tv.tv_usec = (msec_per_tick % 1000) * 1000;
  one_tick = event_base_init_common_timeout(base, &tv);
}

static struct bufferevent *
tor_get_root_bufferevent(struct bufferevent *bev)
{
  struct bufferevent *u;
  while ((u = bufferevent_get_underlying(bev)) != NULL)
    bev = u;
  return bev;
}

int
tor_set_bufferevent_rate_limit(struct bufferevent *bev,
                               struct ev_token_bucket_cfg *cfg)
{
  return bufferevent_set_rate_limit(tor_get_root_bufferevent(bev), cfg);
}

int
tor_add_bufferevent_to_rate_limit_group(struct bufferevent *bev,
                                        struct bufferevent_rate_limit_group *g)
{
  return bufferevent_add_to_rate_limit_group(tor_get_root_bufferevent(bev), g);
}
#endif

int
tor_init_libevent_rng(void)
{
  int rv = 0;
  char buf[256];
  if (evutil_secure_rng_init() < 0) {
    rv = -1;
  }
  crypto_rand(buf, 32);
  evutil_secure_rng_add_bytes(buf, 32);
  evutil_secure_rng_get_bytes(buf, sizeof(buf));
  return rv;
}

#if defined(LIBEVENT_VERSION_NUMBER) && LIBEVENT_VERSION_NUMBER >= V(2,1,1) \
  && !defined(TOR_UNIT_TESTS)
void
tor_gettimeofday_cached(struct timeval *tv)
{
  event_base_gettimeofday_cached(the_event_base, tv);
}
void
tor_gettimeofday_cache_clear(void)
{
  event_base_update_cache_time(the_event_base);
}
#else
/** Cache the current hi-res time; the cache gets reset when libevent
 * calls us. */
static struct timeval cached_time_hires = {0, 0};

/** Return a fairly recent view of the current time. */
void
tor_gettimeofday_cached(struct timeval *tv)
{
  if (cached_time_hires.tv_sec == 0) {
    tor_gettimeofday(&cached_time_hires);
  }
  *tv = cached_time_hires;
}

/** Reset the cached view of the current time, so that the next time we try
 * to learn it, we will get an up-to-date value. */
void
tor_gettimeofday_cache_clear(void)
{
  cached_time_hires.tv_sec = 0;
}

#ifdef TOR_UNIT_TESTS
/** For testing: force-update the cached time to a given value. */
void
tor_gettimeofday_cache_set(const struct timeval *tv)
{
  tor_assert(tv);
  memcpy(&cached_time_hires, tv, sizeof(*tv));
}
#endif
#endif

/**
 * As tor_gettimeofday_cached, but can never move backwards in time.
 *
 * The returned value may diverge from wall-clock time, since wall-clock time
 * can trivially be adjusted backwards, and this can't.  Don't mix wall-clock
 * time with these values in the same calculation.
 *
 * Depending on implementation, this function may or may not "smooth out" huge
 * jumps forward in wall-clock time.  It may or may not keep its results
 * advancing forward (as opposed to stalling) if the wall-clock time goes
 * backwards.  The current implementation does neither of of these.
 *
 * This function is not thread-safe; do not call it outside the main thread.
 *
 * In future versions of Tor, this may return a time does not have its
 * origin at the Unix epoch.
 */
void
tor_gettimeofday_cached_monotonic(struct timeval *tv)
{
  struct timeval last_tv = { 0, 0 };

  tor_gettimeofday_cached(tv);
  if (timercmp(tv, &last_tv, OP_LT)) {
    memcpy(tv, &last_tv, sizeof(struct timeval));
  } else {
    memcpy(&last_tv, tv, sizeof(struct timeval));
  }
}

