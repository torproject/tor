/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "compat.h"
#include <windows.h>
#include <process.h>
#include "util.h"
#include "container.h"
#include "torlog.h"

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
  int rv;
  rv = (int)_beginthread(func, 0, data);
  if (rv == (int)-1)
    return -1;
  return 0;
}


/** End the current thread/process.
 */
void
spawn_exit(void)
{
  _endthread();
  //we should never get here. my compiler thinks that _endthread returns, this
  //is an attempt to fool it.
  tor_assert(0);
  _exit(0);
}


void
tor_mutex_init(tor_mutex_t *m)
{
  InitializeCriticalSection(&m->mutex);
}
void
tor_mutex_uninit(tor_mutex_t *m)
{
  DeleteCriticalSection(&m->mutex);
}
void
tor_mutex_acquire(tor_mutex_t *m)
{
  tor_assert(m);
  EnterCriticalSection(&m->mutex);
}
void
tor_mutex_release(tor_mutex_t *m)
{
  LeaveCriticalSection(&m->mutex);
}
unsigned long
tor_get_thread_id(void)
{
  return (unsigned long)GetCurrentThreadId();
}

static DWORD cond_event_tls_index;
struct tor_cond_t {
  CRITICAL_SECTION mutex;
  smartlist_t *events;
};
tor_cond_t *
tor_cond_new(void)
{
  tor_cond_t *cond = tor_malloc_zero(sizeof(tor_cond_t));
  InitializeCriticalSection(&cond->mutex);
  cond->events = smartlist_new();
  return cond;
}
void
tor_cond_free(tor_cond_t *cond)
{
  if (!cond)
    return;
  DeleteCriticalSection(&cond->mutex);
  /* XXXX notify? */
  smartlist_free(cond->events);
  tor_free(cond);
}
int
tor_cond_wait(tor_cond_t *cond, tor_mutex_t *mutex)
{
  HANDLE event;
  int r;
  tor_assert(cond);
  tor_assert(mutex);
  event = TlsGetValue(cond_event_tls_index);
  if (!event) {
    event = CreateEvent(0, FALSE, FALSE, NULL);
    TlsSetValue(cond_event_tls_index, event);
  }
  EnterCriticalSection(&cond->mutex);

  tor_assert(WaitForSingleObject(event, 0) == WAIT_TIMEOUT);
  tor_assert(!smartlist_contains(cond->events, event));
  smartlist_add(cond->events, event);

  LeaveCriticalSection(&cond->mutex);

  tor_mutex_release(mutex);
  r = WaitForSingleObject(event, INFINITE);
  tor_mutex_acquire(mutex);

  switch (r) {
    case WAIT_OBJECT_0: /* we got the mutex normally. */
      break;
    case WAIT_ABANDONED: /* holding thread exited. */
    case WAIT_TIMEOUT: /* Should never happen. */
      tor_assert(0);
      break;
    case WAIT_FAILED:
      log_warn(LD_GENERAL, "Failed to acquire mutex: %d",(int) GetLastError());
  }
  return 0;
}
void
tor_cond_signal_one(tor_cond_t *cond)
{
  HANDLE event;
  tor_assert(cond);

  EnterCriticalSection(&cond->mutex);

  if ((event = smartlist_pop_last(cond->events)))
    SetEvent(event);

  LeaveCriticalSection(&cond->mutex);
}
void
tor_cond_signal_all(tor_cond_t *cond)
{
  tor_assert(cond);

  EnterCriticalSection(&cond->mutex);
  SMARTLIST_FOREACH(cond->events, HANDLE, event, SetEvent(event));
  smartlist_clear(cond->events);
  LeaveCriticalSection(&cond->mutex);
}

void
tor_threads_init(void)
{
  cond_event_tls_index = TlsAlloc();
  set_main_thread();
}
