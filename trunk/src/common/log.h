/*
 * log.h
 * Logging facilities.
 * 
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

#ifndef __LOG_H

#include <syslog.h>

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
