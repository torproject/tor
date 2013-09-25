/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include "or.h"
#include "compat_threads.h"
#include "test.h"

/** mutex for thread test to stop the threads hitting data at the same time. */
static tor_mutex_t *thread_test_mutex_ = NULL;
/** mutexes for the thread test to make sure that the threads have to
 * interleave somewhat. */
static tor_mutex_t *thread_test_start1_ = NULL,
                   *thread_test_start2_ = NULL;
/** Shared strmap for the thread test. */
static strmap_t *thread_test_strmap_ = NULL;
/** The name of thread1 for the thread test */
static char *thread1_name_ = NULL;
/** The name of thread2 for the thread test */
static char *thread2_name_ = NULL;

static void thread_test_func_(void* _s) ATTR_NORETURN;

/** How many iterations have the threads in the unit test run? */
static int t1_count = 0, t2_count = 0;

/** Helper function for threading unit tests: This function runs in a
 * subthread. It grabs its own mutex (start1 or start2) to make sure that it
 * should start, then it repeatedly alters _test_thread_strmap protected by
 * thread_test_mutex_. */
static void
thread_test_func_(void* _s)
{
  char *s = _s;
  int i, *count;
  tor_mutex_t *m;
  char buf[64];
  char **cp;
  if (!strcmp(s, "thread 1")) {
    m = thread_test_start1_;
    cp = &thread1_name_;
    count = &t1_count;
  } else {
    m = thread_test_start2_;
    cp = &thread2_name_;
    count = &t2_count;
  }

  tor_snprintf(buf, sizeof(buf), "%lu", tor_get_thread_id());
  *cp = tor_strdup(buf);

  tor_mutex_acquire(m);

  for (i=0; i<10000; ++i) {
    tor_mutex_acquire(thread_test_mutex_);
    strmap_set(thread_test_strmap_, "last to run", *cp);
    ++*count;
    tor_mutex_release(thread_test_mutex_);
  }
  tor_mutex_acquire(thread_test_mutex_);
  strmap_set(thread_test_strmap_, s, *cp);
  tor_mutex_release(thread_test_mutex_);

  tor_mutex_release(m);

  spawn_exit();
}

/** Run unit tests for threading logic. */
static void
test_threads_basic(void *arg)
{
  char *s1 = NULL, *s2 = NULL;
  int done = 0, timedout = 0;
  time_t started;
#ifndef _WIN32
  struct timeval tv;
  tv.tv_sec=0;
  tv.tv_usec=100*1000;
#endif
  (void)arg;
  thread_test_mutex_ = tor_mutex_new();
  thread_test_start1_ = tor_mutex_new();
  thread_test_start2_ = tor_mutex_new();
  thread_test_strmap_ = strmap_new();
  s1 = tor_strdup("thread 1");
  s2 = tor_strdup("thread 2");
  tor_mutex_acquire(thread_test_start1_);
  tor_mutex_acquire(thread_test_start2_);
  spawn_func(thread_test_func_, s1);
  spawn_func(thread_test_func_, s2);
  tor_mutex_release(thread_test_start2_);
  tor_mutex_release(thread_test_start1_);
  started = time(NULL);
  while (!done) {
    tor_mutex_acquire(thread_test_mutex_);
    strmap_assert_ok(thread_test_strmap_);
    if (strmap_get(thread_test_strmap_, "thread 1") &&
        strmap_get(thread_test_strmap_, "thread 2")) {
      done = 1;
    } else if (time(NULL) > started + 150) {
      timedout = done = 1;
    }
    tor_mutex_release(thread_test_mutex_);
#ifndef _WIN32
    /* Prevent the main thread from starving the worker threads. */
    select(0, NULL, NULL, NULL, &tv);
#endif
  }
  tor_mutex_acquire(thread_test_start1_);
  tor_mutex_release(thread_test_start1_);
  tor_mutex_acquire(thread_test_start2_);
  tor_mutex_release(thread_test_start2_);

  tor_mutex_free(thread_test_mutex_);

  if (timedout) {
    printf("\nTimed out: %d %d", t1_count, t2_count);
    tt_assert(strmap_get(thread_test_strmap_, "thread 1"));
    tt_assert(strmap_get(thread_test_strmap_, "thread 2"));
    tt_assert(!timedout);
  }

  /* different thread IDs. */
  tt_assert(strcmp(strmap_get(thread_test_strmap_, "thread 1"),
                     strmap_get(thread_test_strmap_, "thread 2")));
  tt_assert(!strcmp(strmap_get(thread_test_strmap_, "thread 1"),
                      strmap_get(thread_test_strmap_, "last to run")) ||
              !strcmp(strmap_get(thread_test_strmap_, "thread 2"),
                      strmap_get(thread_test_strmap_, "last to run")));

 done:
  tor_free(s1);
  tor_free(s2);
  tor_free(thread1_name_);
  tor_free(thread2_name_);
  if (thread_test_strmap_)
    strmap_free(thread_test_strmap_, NULL);
  if (thread_test_start1_)
    tor_mutex_free(thread_test_start1_);
  if (thread_test_start2_)
    tor_mutex_free(thread_test_start2_);
}

#define THREAD_TEST(name) \
  { #name, test_threads_##name, TT_FORK, NULL, NULL }

struct testcase_t thread_tests[] = {
  THREAD_TEST(basic),
  END_OF_TESTCASES
};

