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
#define log_fn(severity, format, args...) \
  log((severity), "%s(): " format , __PRETTY_FUNCTION__ ,  ##args)
#else
#define log_fn log
#endif

# define __LOG_H
#endif
