/*
 * log.h
 * Logging facilities.
 * 
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

#ifndef __LOG_H

#include <syslog.h>

/* Outputs a message to stdout and also logs the same message using syslog. */
void log(int severity, const char *format, ...);

#ifdef __GNUC__
void _log_fn(int severity, const char *funcname, const char *format, ...);
#define log_fn(severity, args...) \
  _log_fn(severity, __PRETTY_FUNCTION__, args)
#else
#define log_fn log
#endif

# define __LOG_H
#endif
