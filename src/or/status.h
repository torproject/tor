/* Copyright (c) 2010-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_STATUS_H
#define TOR_STATUS_H

int log_heartbeat(time_t now);
void log_accounting(const time_t now, const or_options_t *options);

#endif

