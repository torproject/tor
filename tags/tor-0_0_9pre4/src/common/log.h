/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * /file log.h
 *
 * /brief Headers for logging functions.
 **/

#ifndef __LOG_H

/**
 * \file log.h
 * \brief Headers for log.c
 */

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#define LOG_WARN LOG_WARNING
#else
/** Debug-level severity: for hyper-verbose messages of no interest to
 * anybody but developers. */
#define LOG_DEBUG   0
/** Info-level severity: for messages that appear frequently during normal
 * operation. */
#define LOG_INFO    1
/** Notice-level severity: for messages that appear infrequently
 * during normal operation; that the user will probably care about;
 * and that are not errors.
 */
#define LOG_NOTICE  2
/** Warn-level severity: for messages that only appear when something has gone
 * wrong. */
#define LOG_WARN    3
/** Error-level severity: for messages that only appear when something has gone
 * very wrong, and the Tor process can no longer proceed. */
#define LOG_ERR     4
#endif

/* magic to make GCC check for proper format strings. */
#ifdef __GNUC__
#define CHECK_PRINTF(formatIdx, firstArg) \
   __attribute__ ((format (printf, formatIdx, firstArg)))
#else
#define CHECK_PRINTF(formatIdx, firstArg)
#endif

int parse_log_level(const char *level);
void add_stream_log(int severityMin, int severityMax, const char *name, FILE *stream);
int add_file_log(int severityMin, int severityMax, const char *filename);
int get_min_log_level(void);
void close_logs();
void reset_logs();
void add_temp_log(void);
void close_temp_logs(void);
void mark_logs_temp(void);

/* Outputs a message to stdout */
void _log(int severity, const char *format, ...) CHECK_PRINTF(2,3);

#ifdef __GNUC__
void _log_fn(int severity, const char *funcname, const char *format, ...)
     CHECK_PRINTF(3,4);
/** Log a message at level <b>severity</b>, using a pretty-printed version
 * of the current function name. */
#define log_fn(severity, args...) \
  _log_fn(severity, __PRETTY_FUNCTION__, args)
#else
#define log_fn _log
#endif
#define log _log /* hack it so we don't conflict with log() as much */

# define __LOG_H
#endif

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
