/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "../or/or.h"
#include "util.h"

struct logfile_t;

typedef struct logfile_t {
  struct logfile_t *next;
  const char *filename;
  FILE *file;
  int needs_close;
  int loglevel;
  int max_loglevel;
} logfile_t;

static INLINE const char *sev_to_string(int severity) {
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
static logfile_t *logfiles = NULL;

/* Format a log message into a fixed-sized buffer. (This is factored out
 * of 'logv' so that we never format a message more than once.
 */
static INLINE void format_msg(char *buf, size_t buf_len,
			      int severity, const char *funcname, 
			      const char *format, va_list ap) 
{
  time_t t;
  struct timeval now;
  int n;

  buf_len -= 2; /* subtract 2 characters so we have room for \n\0 */
  
  my_gettimeofday(&now);
  t = (time_t)now.tv_sec;
  
  n  = strftime(buf, buf_len, "%b %d %H:%M:%S", localtime(&t));
  n += snprintf(buf+n, buf_len-n,
		".%.3ld [%s] ", 
		(long)now.tv_usec / 1000, sev_to_string(severity));
  if (funcname)
    n += snprintf(buf+n, buf_len-n, "%s(): ", funcname);

  n += vsnprintf(buf+n,buf_len-n,format,ap);
  buf[n]='\n';
  buf[n+1]='\0';
}

static void 
logv(int severity, const char *funcname, const char *format, va_list ap)
{
  char buf[1024];
  int formatted = 0;
  logfile_t *lf;
  
  assert(format);
  if (severity < loglevel)
    return;
  if (!logfiles) {
    /* XXX This is a temporary measure until we get configuration support
       for logfiles. */
    add_stream_log(loglevel, "<stdout>", stdout);
  }
  for (lf = logfiles; lf; lf = lf->next) {
    if (severity < lf->loglevel || severity > lf->max_loglevel)
      continue;
    if (!lf->file)
      continue;

    if (!formatted) {
      format_msg(buf, 1024, severity, funcname, format, ap);
      formatted = 1;
    }
    fputs(buf, lf->file);
  }
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

void close_logs()
{
  logfile_t *next, *lf;
  for (lf = logfiles; lf; lf = lf->next) {
    if (lf->needs_close)
      fclose(lf->file);
    next = lf->next;
    free(lf);
  }
  logfiles = NULL;
}

void reset_logs()
{
  logfile_t *lf;
  for (lf = logfiles; lf; lf = lf->next) {
    if (lf->needs_close) {
      fclose(lf->file);
      lf->file = fopen(lf->filename, "a");
    }
  }
}

void add_stream_log(int loglevel, const char *name, FILE *stream)
{
  logfile_t *lf;
  lf = tor_malloc(sizeof(logfile_t));
  lf->filename = name;
  lf->needs_close = 0;
  lf->loglevel = loglevel;
  lf->max_loglevel = LOG_EMERG;
  lf->file = stream;
  lf->next = logfiles;
  logfiles = lf;
}

void add_file_log(int loglevel, const char *filename) 
{
  FILE *f;
  f = fopen(filename, "a");
  if (!f) return;
  add_stream_log(loglevel, filename, f);
  logfiles->needs_close = 1;
}
