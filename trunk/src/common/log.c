/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "../or/or.h"
#include "log.h"

/* FIXME this whole thing is hacked together. feel free to make it clean. */
size_t sev_to_string(char *buf, int max, int severity) {
  assert(max > 20);

  switch(severity) {
    case LOG_DEBUG:
      strcpy(buf,"debug");  
      break;
    case LOG_INFO:
      strcpy(buf,"info");
      break;
    case LOG_NOTICE:
      strcpy(buf,"notice");
      break;
    case LOG_WARNING:
      strcpy(buf,"warn");
      break;
    case LOG_ERR:
      strcpy(buf,"err");
      break;
    case LOG_CRIT:
      strcpy(buf,"crit");
      break;
    case LOG_ALERT:
      strcpy(buf,"alert");
      break;
    case LOG_EMERG: 
      strcpy(buf,"emerg");
      break;
    default:
      strcpy(buf,"UNKNOWN");
      break;
  }

  return strlen(buf)+1;
}

static void 
logv(int severity, const char *funcname, const char *format, va_list ap)
{
  static int loglevel = LOG_DEBUG;
  char buf[201];
  time_t t;
  struct timeval now;
  
  if (format) {

    if (severity > loglevel)
      return;
    if (gettimeofday(&now,NULL) < 0)
      return;

    t = time(NULL);
    strftime(buf, 200, "%b %d %H:%M:%S", localtime(&t));
    printf("%s.%.3ld ", buf, (long)now.tv_usec / 1000);
    sev_to_string(buf, 200, severity);
    printf("[%s] ", buf);
    if (funcname)
      printf("%s(): ", funcname);
    vprintf(format,ap);
    printf("\n");
  } else
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


