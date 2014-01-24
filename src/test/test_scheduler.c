/* Copyright (c) 2014, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include <math.h>

#include "orconfig.h"

/* Libevent stuff */
#ifdef HAVE_EVENT2_EVENT_H
#include <event2/event.h>
#else
#include <event.h>
#endif

#define TOR_CHANNEL_INTERNAL_
#include "or.h"
#include "compat_libevent.h"
#include "scheduler.h"

/* Test suite stuff */
#include "test.h"

/* Statics in scheduler.c exposed to the test suite */
extern smartlist_t *channels_pending;
extern struct event *run_sched_ev;
extern uint64_t queue_heuristic;
extern time_t queue_heuristic_timestamp;

/* Event base for scheduelr tests */
static struct event_base *mock_event_base = NULL;

/* Setup for mock event stuff */
static void mock_event_free_all(void);
static void mock_event_init(void);

/* Mocks used by scheduler tests */
static struct event_base * tor_libevent_get_base_mock(void);

/* Scheduler test cases */
static void test_scheduler_initfree(void *arg);

/* Mock event init/free */

/* Shamelessly stolen from compat_libevent.c */
#define V(major, minor, patch) \
  (((major) << 24) | ((minor) << 16) | ((patch) << 8))

static void
mock_event_free_all(void)
{
  test_assert(mock_event_base != NULL);

  if (mock_event_base) {
    event_base_free(mock_event_base);
    mock_event_base = NULL;
  }

  test_eq(mock_event_base, NULL);

 done:
  return;
}

static void
mock_event_init(void)
{
#ifdef HAVE_EVENT2_EVENT_H
  struct event_config *cfg = NULL;
#endif

  test_eq(mock_event_base, NULL);

  /*
   * Really cut down from tor_libevent_initialize of
   * src/common/compat_libevent.c to kill config dependencies
   */

  if (!mock_event_base) {
#ifdef HAVE_EVENT2_EVENT_H
    cfg = event_config_new();
#if LIBEVENT_VERSION_NUMBER >= V(2,0,9)
    /* We can enable changelist support with epoll, since we don't give
     * Libevent any dup'd fds.  This lets us avoid some syscalls. */
    event_config_set_flag(cfg, EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST);
#endif
    mock_event_base = event_base_new_with_config(cfg);
    event_config_free(cfg);
#else
    mock_event_base = event_init();
#endif
  }

  test_assert(mock_event_base != NULL);

 done:
  return;
}

/* Mocks */

static struct event_base *
tor_libevent_get_base_mock(void)
{
  return mock_event_base;
}

/* Test cases */

static void
test_scheduler_initfree(void *arg)
{
  (void)arg;

  test_eq(channels_pending, NULL);
  test_eq(run_sched_ev, NULL);

  mock_event_init();
  MOCK(tor_libevent_get_base, tor_libevent_get_base_mock);

  scheduler_init();

  test_assert(channels_pending != NULL);
  test_assert(run_sched_ev != NULL);

  scheduler_free_all();

  UNMOCK(tor_libevent_get_base);
  mock_event_free_all();

  test_eq(channels_pending, NULL);
  test_eq(run_sched_ev, NULL);

 done:
  return;
}

struct testcase_t scheduler_tests[] = {
  { "initfree", test_scheduler_initfree, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};

