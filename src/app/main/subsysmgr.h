/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_SUBSYSMGR_T
#define TOR_SUBSYSMGR_T

#include "lib/subsys/subsys.h"

extern const struct subsys_fns_t *tor_subsystems[];
extern const unsigned n_tor_subsystems;

int subsystems_init(void);
int subsystems_init_upto(int level);

void subsystems_shutdown(void);
void subsystems_shutdown_downto(int level);

void subsystems_prefork(void);
void subsystems_postfork(void);
void subsystems_thread_cleanup(void);

#endif
