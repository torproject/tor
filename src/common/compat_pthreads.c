/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include <pthread.h>

#include "compat.h"
#include "torlog.h"
#include "util.h"

/** Wraps a void (*)(void*) function and its argument so we can
 * invoke them in a way pthreads would expect.
 */
typedef struct tor_pthread_data_t {
  void (*func)(void *);
  void *data;
} tor_pthread_data_t;
/** Given a tor_pthread_data_t <b>_data</b>, call _data-&gt;func(d-&gt;data)
 * and free _data.  Used to make sure we can call functions the way pthread
 * expects. */
static void *
tor_pthread_helper_fn(void *_data)
{
  tor_pthread_data_t *data = _data;
  void (*func)(void*);
  void *arg;
  /* mask signals to worker threads to avoid SIGPIPE, etc */
  sigset_t sigs;
  /* We're in a subthread; don't handle any signals here. */
  sigfillset(&sigs);
  pthread_sigmask(SIG_SETMASK, &sigs, NULL);

  func = data->func;
  arg = data->data;
  tor_free(_data);
  func(arg);
  return NULL;
}
/**
 * A pthread attribute to make threads start detached.
 */
static pthread_attr_t attr_detached;
/** True iff we've called tor_threads_init() */
static int threads_initialized = 0;


/** Minimalist interface to run a void function in the background.  On
 * Unix calls fork, on win32 calls beginthread.  Returns -1 on failure.
 * func should not return, but rather should call spawn_exit.
 *
 * NOTE: if <b>data</b> is used, it should not be allocated on the stack,
 * since in a multithreaded environment, there is no way to be sure that
 * the caller's stack will still be around when the called function is
 * running.
 */
int
spawn_func(void (*func)(void *), void *data)
{
  pthread_t thread;
  tor_pthread_data_t *d;
  if (PREDICT_UNLIKELY(!threads_initialized))
    tor_threads_init();
  d = tor_malloc(sizeof(tor_pthread_data_t));
  d->data = data;
  d->func = func;
  if (pthread_create(&thread,&attr_detached,tor_pthread_helper_fn,d))
    return -1;
  return 0;
}

/** End the current thread/process.
 */
void
spawn_exit(void)
{
  pthread_exit(NULL);
}

/** A mutex attribute that we're going to use to tell pthreads that we want
 * "reentrant" mutexes (i.e., once we can re-lock if we're already holding
 * them.) */
static pthread_mutexattr_t attr_reentrant;
/** Initialize <b>mutex</b> so it can be locked.  Every mutex must be set
 * up with tor_mutex_init() or tor_mutex_new(); not both. */
void
tor_mutex_init(tor_mutex_t *mutex)
{
  int err;
  if (PREDICT_UNLIKELY(!threads_initialized))
    tor_threads_init();
  err = pthread_mutex_init(&mutex->mutex, &attr_reentrant);
  if (PREDICT_UNLIKELY(err)) {
    log_err(LD_GENERAL, "Error %d creating a mutex.", err);
    tor_fragile_assert();
  }
}

/** As tor_mutex_init, but initialize a mutex suitable that may be
 * non-reentrant, if the OS supports that. */
void
tor_mutex_init_nonreentrant(tor_mutex_t *mutex)
{
  int err;
  if (PREDICT_UNLIKELY(!threads_initialized))
    tor_threads_init();
  err = pthread_mutex_init(&mutex->mutex, NULL);
  if (PREDICT_UNLIKELY(err)) {
    log_err(LD_GENERAL, "Error %d creating a mutex.", err);
    tor_fragile_assert();
  }
}

/** Wait until <b>m</b> is free, then acquire it. */
void
tor_mutex_acquire(tor_mutex_t *m)
{
  int err;
  tor_assert(m);
  err = pthread_mutex_lock(&m->mutex);
  if (PREDICT_UNLIKELY(err)) {
    log_err(LD_GENERAL, "Error %d locking a mutex.", err);
    tor_fragile_assert();
  }
}
/** Release the lock <b>m</b> so another thread can have it. */
void
tor_mutex_release(tor_mutex_t *m)
{
  int err;
  tor_assert(m);
  err = pthread_mutex_unlock(&m->mutex);
  if (PREDICT_UNLIKELY(err)) {
    log_err(LD_GENERAL, "Error %d unlocking a mutex.", err);
    tor_fragile_assert();
  }
}
/** Clean up the mutex <b>m</b> so that it no longer uses any system
 * resources.  Does not free <b>m</b>.  This function must only be called on
 * mutexes from tor_mutex_init(). */
void
tor_mutex_uninit(tor_mutex_t *m)
{
  int err;
  tor_assert(m);
  err = pthread_mutex_destroy(&m->mutex);
  if (PREDICT_UNLIKELY(err)) {
    log_err(LD_GENERAL, "Error %d destroying a mutex.", err);
    tor_fragile_assert();
  }
}
/** Return an integer representing this thread. */
unsigned long
tor_get_thread_id(void)
{
  union {
    pthread_t thr;
    unsigned long id;
  } r;
  r.thr = pthread_self();
  return r.id;
}

/* Conditions. */

/** Initialize an already-allocated condition variable. */
int
tor_cond_init(tor_cond_t *cond)
{
  memset(cond, 0, sizeof(tor_cond_t));
  if (pthread_cond_init(&cond->cond, NULL)) {
    return -1;
  }
  return 0;
}

/** Release all resources held by <b>cond</b>, but do not free <b>cond</b>
 * itself. */
void
tor_cond_uninit(tor_cond_t *cond)
{
  if (pthread_cond_destroy(&cond->cond)) {
    log_warn(LD_GENERAL,"Error freeing condition: %s", strerror(errno));
    return;
  }
}
/** Wait until one of the tor_cond_signal functions is called on <b>cond</b>.
 * (If <b>tv</b> is set, and that amount of time passes with no signal to
 * <b>cond</b>, return anyway.  All waiters on the condition must wait holding
 * the same <b>mutex</b>.  All signallers should hold that mutex.  The mutex
 * needs to have been allocated with tor_mutex_init_for_cond().
 *
 * Returns 0 on success, -1 on failure, 1 on timeout. */
int
tor_cond_wait(tor_cond_t *cond, tor_mutex_t *mutex, const struct timeval *tv)
{
  if (tv == NULL) {
    return pthread_cond_wait(&cond->cond, &mutex->mutex) ? -1 : 0;
  } else {
    struct timespec ts;
    int r;
    ts.tv_sec = tv->tv_sec;
    ts.tv_nsec = tv->tv_usec * 1000;
    r = pthread_cond_timedwait(&cond->cond, &mutex->mutex, &ts);
    if (r == 0)
      return 0;
    else if (r == ETIMEDOUT)
      return 1;
    else
      return -1;
  }
}
/** Wake up one of the waiters on <b>cond</b>. */
void
tor_cond_signal_one(tor_cond_t *cond)
{
  pthread_cond_signal(&cond->cond);
}
/** Wake up all of the waiters on <b>cond</b>. */
void
tor_cond_signal_all(tor_cond_t *cond)
{
  pthread_cond_broadcast(&cond->cond);
}

/** Set up common structures for use by threading. */
void
tor_threads_init(void)
{
  if (!threads_initialized) {
    pthread_mutexattr_init(&attr_reentrant);
    pthread_mutexattr_settype(&attr_reentrant, PTHREAD_MUTEX_RECURSIVE);
    tor_assert(0==pthread_attr_init(&attr_detached));
    tor_assert(0==pthread_attr_setdetachstate(&attr_detached, 1));
    threads_initialized = 1;
    set_main_thread();
  }
}
