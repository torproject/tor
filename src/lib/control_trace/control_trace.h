/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file control_trace.h
 * @brief Header for lib/control_trace/control_trace.c
 **/

#ifndef TOR_LIB_ERR_CONTROL_TRACE_H
#define TOR_LIB_ERR_CONTROL_TRACE_H

#include "lib/testsupport/testsupport.h"

/* Using this feature struct is technically a layering violation.
 * But we never use the actual definition of the struct, just the pointer
 * value. */
typedef struct control_connection_t control_connection_t;

/* Use one of the typed functions/macros, rather than using this function
 * directly. */
void tor_log_debug_control_safe_message(const control_connection_t *conn,
                                        const char *type, const char *msg);

/* Control trace log typed functions/macros. */
void tor_log_debug_control_safe_command(const control_connection_t *conn,
                                        const char *cmd, const char *args);
#define tor_log_debug_control_safe_reply_write(conn, msg) \
    tor_log_debug_control_safe_message(conn, "Reply Write", msg)
#define tor_log_debug_control_safe_reply_printf(conn, msg) \
    tor_log_debug_control_safe_message(conn, "Reply Printf", msg)
#define tor_log_debug_control_safe_reply_data(conn, msg) \
    tor_log_debug_control_safe_message(conn, "Reply Data", msg)
#define tor_log_debug_control_safe_event(conn, msg) \
    tor_log_debug_control_safe_message(conn, "Event", msg)
#define tor_log_debug_control_safe_getconf_reply(conn, msg) \
    tor_log_debug_control_safe_message(conn, "GETCONF Reply", msg)
#define tor_log_debug_control_safe_mapaddress_reply(conn, msg) \
    tor_log_debug_control_safe_message(conn, "MAPADDRESS Reply", msg)
#define tor_log_debug_control_safe_protocol_error(conn, msg) \
    tor_log_debug_control_safe_message(conn, "Control Protocol Error", msg)

/* Raw logging setup functions. */
int tor_log_get_control_safe_debug_fds(const int **out);
void tor_log_set_control_safe_debug_fds(const int *fds, int n);
void tor_log_reset_control_safe_debug_fds(void);

#if defined(CONTROL_TRACE_PRIVATE) || defined(TOR_UNIT_TESTS)
/* Do not use this function with unvalidated inputs: it outputs its arguments
 * without escaping. */
STATIC void tor_log_debug_control_safe(const char *m, ...);
#endif

#endif /* !defined(TOR_LIB_ERR_CONTROL_TRACE_H) */
