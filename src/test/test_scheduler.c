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
#define CHANNEL_PRIVATE_
#include "or.h"
#include "compat_libevent.h"
#include "channel.h"
#define SCHEDULER_PRIVATE_
#include "scheduler.h"

/* Test suite stuff */
#include "test.h"
#include "fakechans.h"

/* Statics in scheduler.c exposed to the test suite */
extern smartlist_t *channels_pending;
extern struct event *run_sched_ev;
extern uint64_t queue_heuristic;
extern time_t queue_heuristic_timestamp;

/* Event base for scheduelr tests */
static struct event_base *mock_event_base = NULL;

/* Statics controlling mocks */
static circuitmux_t *mock_ccm_tgt_1 = NULL;
static circuitmux_t *mock_ccm_tgt_2 = NULL;

static circuitmux_t *mock_cgp_tgt_1 = NULL;
static const circuitmux_policy_t *mock_cgp_val_1 = NULL;
static circuitmux_t *mock_cgp_tgt_2 = NULL;
static const circuitmux_policy_t *mock_cgp_val_2 = NULL;

/* Setup for mock event stuff */
static void mock_event_free_all(void);
static void mock_event_init(void);

/* Mocks used by scheduler tests */
static int circuitmux_compare_muxes_mock(circuitmux_t *cmux_1,
                                         circuitmux_t *cmux_2);
static const circuitmux_policy_t * circuitmux_get_policy_mock(
    circuitmux_t *cmux);
static struct event_base * tor_libevent_get_base_mock(void);

/* Scheduler test cases */
static void test_scheduler_compare_channels(void *arg);
static void test_scheduler_initfree(void *arg);
static void test_scheduler_queue_heuristic(void *arg);

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

static int
circuitmux_compare_muxes_mock(circuitmux_t *cmux_1,
                              circuitmux_t *cmux_2)
{
  int result = 0;

  test_assert(cmux_1 != NULL);
  test_assert(cmux_2 != NULL);

  if (cmux_1 != cmux_2) {
    if (cmux_1 == mock_ccm_tgt_1 && cmux_2 == mock_ccm_tgt_2) result = -1;
    else if (cmux_1 == mock_ccm_tgt_2 && cmux_2 == mock_ccm_tgt_1) {
      result = 1;
    }
    else {
      if (cmux_1 == mock_ccm_tgt_1 || cmux_1 == mock_ccm_tgt_1) result = -1;
      else if (cmux_2 == mock_ccm_tgt_1 || cmux_2 == mock_ccm_tgt_2) {
        result = 1;
      } else {
        result = circuitmux_compare_muxes__real(cmux_1, cmux_2);
      }
    }
  }
  /* else result = 0 always */

 done:
  return result;
}

static const circuitmux_policy_t *
circuitmux_get_policy_mock(circuitmux_t *cmux)
{
  const circuitmux_policy_t *result = NULL;

  test_assert(cmux != NULL);
  if (cmux) {
    if (cmux == mock_cgp_tgt_1) result = mock_cgp_val_1;
    else if (cmux == mock_cgp_tgt_2) result = mock_cgp_val_2;
    else result = circuitmux_get_policy__real(cmux);
  }

 done:
  return result;
}

static struct event_base *
tor_libevent_get_base_mock(void)
{
  return mock_event_base;
}

/* Test cases */

static void
test_scheduler_compare_channels(void *arg)
{
  /* We don't actually need whole fake channels... */
  channel_t c1, c2;
  /* ...and some dummy circuitmuxes too */
  circuitmux_t *cm1 = NULL, *cm2 = NULL;
  int result;

  (void)arg;

  /* We can't actually see sizeof(circuitmux_t) from here */
  cm1 = tor_malloc_zero(sizeof(void *));
  cm2 = tor_malloc_zero(sizeof(void *));

  c1.cmux = cm1;
  c2.cmux = cm2;

  /* Configure circuitmux_get_policy() mock */
  mock_cgp_tgt_1 = cm1;
  /*
   * This is to test the different-policies case, which uses the policy
   * cast to an intptr_t as an arbitrary but definite thing to compare.
   */
  mock_cgp_val_1 = (const circuitmux_policy_t *)(1);
  mock_cgp_tgt_2 = cm2;
  mock_cgp_val_2 = (const circuitmux_policy_t *)(2);

  MOCK(circuitmux_get_policy, circuitmux_get_policy_mock);

  /* Now set up circuitmux_compare_muxes() mock using cm1/cm2 */
  mock_ccm_tgt_1 = cm1;
  mock_ccm_tgt_2 = cm2;
  MOCK(circuitmux_compare_muxes, circuitmux_compare_muxes_mock);

  /* Equal-channel case */
  result = scheduler_compare_channels(&c1, &c1);
  test_eq(result, 0);
  
  /* Distinct channels, distinct policies */
  result = scheduler_compare_channels(&c1, &c2);
  test_eq(result, -1);
  result = scheduler_compare_channels(&c2, &c1);
  test_eq(result, 1);

  /* Distinct channels, same policy */
  mock_cgp_val_2 = mock_cgp_val_1;
  result = scheduler_compare_channels(&c1, &c2);
  test_eq(result, -1);
  result = scheduler_compare_channels(&c2, &c1);
  test_eq(result, 1);

 done:

  UNMOCK(circuitmux_compare_muxes);
  mock_ccm_tgt_1 = NULL;
  mock_ccm_tgt_2 = NULL;

  UNMOCK(circuitmux_get_policy);
  mock_cgp_tgt_1 = NULL;
  mock_cgp_val_1 = NULL;
  mock_cgp_tgt_2 = NULL;
  mock_cgp_val_2 = NULL;

  tor_free(cm1);
  tor_free(cm2);

  return;
}

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

static void
test_scheduler_queue_heuristic(void *arg)
{
  time_t now = approx_time();
  uint64_t qh;

  (void)arg;

  queue_heuristic = 0;
  queue_heuristic_timestamp = 0;

  /* Not yet inited case */
  scheduler_update_queue_heuristic(now - 180);
  test_eq(queue_heuristic, 0);
  test_eq(queue_heuristic_timestamp, now - 180);

  queue_heuristic = 1000000000L;
  queue_heuristic_timestamp = now - 120;

  scheduler_update_queue_heuristic(now - 119);
  test_eq(queue_heuristic, 500000000L);
  test_eq(queue_heuristic_timestamp, now - 119);

  scheduler_update_queue_heuristic(now - 116);
  test_eq(queue_heuristic, 62500000L);
  test_eq(queue_heuristic_timestamp, now - 116);

  qh = scheduler_get_queue_heuristic();
  test_eq(qh, 0);

 done:
  return;
}

struct testcase_t scheduler_tests[] = {
  { "compare_channels", test_scheduler_compare_channels,
    TT_FORK, NULL, NULL },
  { "initfree", test_scheduler_initfree, TT_FORK, NULL, NULL },
  { "queue_heuristic", test_scheduler_queue_heuristic,
    TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};

