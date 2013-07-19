/* Copyright (c) 2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_BACKTRACE_H
#define TOR_BACKTRACE_H

void dump_backtrace(const char *msg);
int configure_backtrace_handler(const char *filename, const char *tor_version);
void clean_up_backtrace_handler(void);

#endif

