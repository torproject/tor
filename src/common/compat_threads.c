/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "compat.h"
#include "util.h"

/** Return a newly allocated, ready-for-use mutex. */
tor_mutex_t *
tor_mutex_new(void)
{
  tor_mutex_t *m = tor_malloc_zero(sizeof(tor_mutex_t));
  tor_mutex_init(m);
  return m;
}
/** Release all storage and system resources held by <b>m</b>. */
void
tor_mutex_free(tor_mutex_t *m)
{
  if (!m)
    return;
  tor_mutex_uninit(m);
  tor_free(m);
}

/** Identity of the "main" thread */
static unsigned long main_thread_id = -1;

/** Start considering the current thread to be the 'main thread'.  This has
 * no effect on anything besides in_main_thread(). */
void
set_main_thread(void)
{
  main_thread_id = tor_get_thread_id();
}
/** Return true iff called from the main thread. */
int
in_main_thread(void)
{
  return main_thread_id == tor_get_thread_id();
}
