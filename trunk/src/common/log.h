/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef __LOG_H

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#define LOG_WARN LOG_WARNING
#else
#define LOG_DEBUG   0
#define LOG_INFO    1
#define LOG_NOTICE  2
#define LOG_WARN    3
#define LOG_ERR     4
#endif

/* magic to make GCC check for proper format strings. */
#ifdef __GNUC__
#define CHECK_PRINTF(formatIdx, firstArg) \
   __attribute__ ((format (printf, formatIdx, firstArg)))
#else
#define CHECK_PRINTF(formatIdx, firstArg)
#endif

void add_stream_log(int loglevel, const char *name, FILE *stream);
int add_file_log(int severity, const char *filename);
void close_logs();
void reset_logs();

/* Outputs a message to stdout */
void _log(int severity, const char *format, ...) CHECK_PRINTF(2,3);

#ifdef __GNUC__
void _log_fn(int severity, const char *funcname, const char *format, ...)
     CHECK_PRINTF(3,4);
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
