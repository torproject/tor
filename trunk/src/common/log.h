/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar.
 * Copyright 2004-2005 Roger Dingledine, Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file log.h
 *
 * \brief Headers for logging functions.
 **/

#ifndef __LOG_H
#define LOG_H_ID "$Id$"

#include "../common/compat.h"

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#define LOG_WARN LOG_WARNING
#if LOG_DEBUG < LOG_ERR
#error "Your syslog.h thinks high numbers are more important.  We aren't prepared to deal with that."
#endif
#else
/* XXXX Note: The code was originally written to refer to severities,
 * with 0 being the least severe; while syslog's logging code refers to
 * priorities, with 0 being the most important.  Thus, all our comparisons
 * needed to be reversed when we added syslog support.
 *
 * The upshot of this is that comments about log levels may be messed
 * up: for "maximum severity" read "most severe" and "numerically
 * *lowest* severity".
 */

/** Debug-level severity: for hyper-verbose messages of no interest to
 * anybody but developers. */
#define LOG_DEBUG   7
/** Info-level severity: for messages that appear frequently during normal
 * operation. */
#define LOG_INFO    6
/** Notice-level severity: for messages that appear infrequently
 * during normal operation; that the user will probably care about;
 * and that are not errors.
 */
#define LOG_NOTICE  5
/** Warn-level severity: for messages that only appear when something has gone
 * wrong. */
#define LOG_WARN    4
/** Error-level severity: for messages that only appear when something has gone
 * very wrong, and the Tor process can no longer proceed. */
#define LOG_ERR     3
#endif

typedef void (*log_callback)(int severity, const char *msg);

int parse_log_level(const char *level);
const char *log_level_to_string(int level);
void add_stream_log(int severityMin, int severityMax, const char *name, FILE *stream);
int add_file_log(int severityMin, int severityMax, const char *filename);
#ifdef HAVE_SYSLOG_H
int add_syslog_log(int loglevelMin, int loglevelMax);
#endif
int add_callback_log(int loglevelMin, int loglevelMax, log_callback cb);
int get_min_log_level(void);
void switch_logs_debug(void);
void close_logs(void);
void reset_logs(void);
void add_temp_log(void);
void close_temp_logs(void);
void mark_logs_temp(void);
void configure_libevent_logging(void);
void suppress_libevent_log_msg(const char *msg);
void change_callback_log_severity(int loglevelMin, int loglevelMax,
                                  log_callback cb);

/* Outputs a message to stdout */
void _log(int severity, const char *format, ...) CHECK_PRINTF(2,3);

#ifdef __GNUC__
void _log_fn(int severity, const char *funcname, const char *format, ...)
     CHECK_PRINTF(3,4);
/** Log a message at level <b>severity</b>, using a pretty-printed version
 * of the current function name. */
#define log_fn(severity, args...) \
  _log_fn(severity, __PRETTY_FUNCTION__, args)
#elif defined(_MSC_VER) && _MSC_VER < 1300
/* MSVC 6 and earlier don't have __FUNCTION__, or even __LINE__. */
#define log_fn _log
#else
/* We don't have GCC's varargs macros, so use a global variable to pass the
 * function name to log_fn */
extern const char *_log_fn_function_name;
void _log_fn(int severity, const char *format, ...);
/* We abuse the comma operator here, since we can't use the standard
 * do {...} while (0) trick to wrap this macro, since the macro can't take
 * arguments. */
#define log_fn (_log_fn_function_name=__FUNCTION__),_log_fn
#endif
#define log _log /* hack it so we don't conflict with log() as much */

# define __LOG_H
#endif

