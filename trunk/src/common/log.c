/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "../or/or.h"

static const char *sev_to_string(int severity) {
  switch(severity) {
    case LOG_DEBUG:   return "debug";
    case LOG_INFO:    return "info";
    case LOG_NOTICE:  return "notice";
    case LOG_WARNING: return "warn";
    case LOG_ERR:     return "err";
    case LOG_CRIT:    return "crit";
    case LOG_ALERT:   return "alert";
    case LOG_EMERG:   return "emerg";
    default:          return "UNKNOWN";
  }
}

static int loglevel = LOG_DEBUG;

static void 
logv(int severity, const char *funcname, const char *format, va_list ap)
{
  char buf[201];
  time_t t;
  struct timeval now;
  
  assert(format);
  if (severity > loglevel)
    return;
  if (gettimeofday(&now,NULL) < 0)
    return;

  t = time(NULL);
  strftime(buf, 200, "%b %d %H:%M:%S", localtime(&t));
  printf("%s.%.3ld [%s] ", buf, (long)now.tv_usec / 1000, sev_to_string(severity));
  if (funcname)
    printf("%s(): ", funcname);
  vprintf(format,ap);
  printf("\n");
}

void 
log_set_severity(int severity)
{
  loglevel = severity;
}

/* Outputs a message to stdout */
void log(int severity, const char *format, ...)
{
  va_list ap;
  va_start(ap,format);
  logv(severity, NULL, format, ap);
  va_end(ap);
}

void _log_fn(int severity, const char *fn, const char *format, ...)
{
  va_list ap;
  va_start(ap,format);
  logv(severity, fn, format, ap);
  va_end(ap);
}


