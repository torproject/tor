/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file subprocess.h
 * \brief Header for subprocess.c
 **/

#ifndef TOR_SUBPROCESS_H
#define TOR_SUBPROCESS_H

void tor_disable_spawning_background_processes(void);

#ifndef _WIN32
char *tor_join_win_cmdline(const char *argv[]);
#endif

#endif
