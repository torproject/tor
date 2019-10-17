/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_APP_THREADS_H
#define TOR_APP_THREADS_H

int start_tor_thread(void (*func)(void *), void *data);

#endif /* !defined(TOR_APP_THREADS_H) */
