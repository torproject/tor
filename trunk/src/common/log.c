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

/* Outputs a message to stdout */
void log(int severity, const char *format, ...)
{
  static int loglevel = LOG_DEBUG;
  char buf[201];
  time_t t;
  va_list ap;
  struct timeval now;

  if (format) {

    if(gettimeofday(&now,NULL) < 0)
      return;

    va_start(ap,format);
  
    if (severity <= loglevel)
    {
      t = time(NULL);
      strftime(buf, 200, "%b %d %H:%M:%S", localtime(&t));
      printf("%s.%.3ld ", buf, (long)now.tv_usec / 1000);
      sev_to_string(buf, 200, severity);
      printf("[%s] ", buf);
      vprintf(format,ap);
      printf("\n");
    }
    
    va_end(ap);
  }
  else
    loglevel = severity;
}

