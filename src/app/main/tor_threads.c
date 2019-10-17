/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "app/main/tor_threads.h"

#include "lib/thread/threads.h"
#include "app/main/subsysmgr.h"

/** Wraps a void (*)(void*) function and its argument so we can
 * invoke them with proper subsystem thread management.
 */
typedef struct tor_thread_helper_info_t {
  void (*func)(void *);
  void *data;
} tor_thread_helper_info_t;

static void tor_thread_helper(void *_info) ATTR_NORETURN;

static void
tor_thread_helper(void *_info)
{
  tor_thread_helper_info_t *info = _info;
  void (*func)(void*) = info->func;
  void *data = info->data;
  tor_free(_info);

  subsystems_thread_init();
  func(data);
  subsystems_thread_cleanup();
  spawn_exit();
}

int
start_tor_thread(void (*func)(void *), void *data)
{
  tor_thread_helper_info_t *d = tor_malloc(sizeof(tor_thread_helper_info_t));
  d->func = func;
  d->data = data;

  return spawn_func(tor_thread_helper, d);
}
