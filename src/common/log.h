/*
 * log.h
 * Logging facilities.
 * 
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

#ifndef __LOG_H

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#else
#define LOG_DEBUG   0
#define LOG_INFO    1
#define LOG_NOTICE  2
#define LOG_WARNING 3
#define LOG_ERR     4
#define LOG_CRIT    5
#define LOG_ALERT   6
#define LOG_EMERG   7
#endif

/* magic to make GCC check for proper format strings. */ 
#ifdef __GNUC__
#define CHECK_PRINTF(formatIdx, firstArg) \
   __attribute__ ((format (printf, formatIdx, firstArg)))
#else
#define CHECK_PRINTF(formatIdx, firstArg) 
#endif 

void log_set_severity(int severity);

/* Outputs a message to stdout */
void log(int severity, const char *format, ...) CHECK_PRINTF(2,3);

#ifdef __GNUC__
void _log_fn(int severity, const char *funcname, const char *format, ...)
     CHECK_PRINTF(3,4);
#define log_fn(severity, args...) \
  _log_fn(severity, __PRETTY_FUNCTION__, args)
#else
#define log_fn log
#endif

# define __LOG_H
#endif
