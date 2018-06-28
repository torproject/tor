/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file waitpid.h
 * \brief Headers for waitpid.c
 **/

#ifndef TOR_RESTRICT_H
#define TOR_RESTRICT_H

int tor_disable_debugger_attach(void);
int tor_mlockall(void);

#endif /* !defined(TOR_RESTRICT_H) */
