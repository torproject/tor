/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file control_trace.h
 * @brief Header for lib/err/control_trace.c
 **/

#ifndef TOR_LIB_ERR_CONTROL_TRACE_H
#define TOR_LIB_ERR_CONTROL_TRACE_H

void tor_log_debug_control_safe(const char *m, ...);
int tor_log_get_control_safe_debug_fds(const int **out);
void tor_log_set_control_safe_debug_fds(const int *fds, int n);
void tor_log_reset_control_safe_debug_fds(void);

#endif /* !defined(TOR_LIB_ERR_CONTROL_TRACE_H) */
