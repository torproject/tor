/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "../or/or.h"
#ifdef MS_WINDOWS
#define vsnprintf _vsnprintf
#endif

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
    case LOG_WARN:    return "warn";
    case LOG_ERR:     return "err";
    default:          assert(0); return "UNKNOWN";
  }
}

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
  size_t n;

  buf_len -= 2; /* subtract 2 characters so we have room for \n\0 */

  tor_gettimeofday(&now);
  t = (time_t)now.tv_sec;

  n = strftime(buf, buf_len, "%b %d %H:%M:%S", localtime(&t));
  n += snprintf(buf+n, buf_len-n,
                ".%.3ld [%s] ",
                (long)now.tv_usec / 1000, sev_to_string(severity));
  if(n > buf_len)
    n = buf_len-1; /* the *nprintf funcs return how many bytes they
                    * _would_ print, if the output is truncated.
                    * Subtract one because the count doesn't include the \0 */

  if (funcname) {
    n += snprintf(buf+n, buf_len-n, "%s(): ", funcname);
    if(n > buf_len)
      n = buf_len-1;
  }

  n += vsnprintf(buf+n,buf_len-n,format,ap);
  if(n > buf_len)
    n = buf_len-1;
  buf[n]='\n';
  buf[n+1]='\0';
}

static void
logv(int severity, const char *funcname, const char *format, va_list ap)
{
  char buf[10024];
  int formatted = 0;
  logfile_t *lf;

  assert(format);
  for (lf = logfiles; lf; lf = lf->next) {
    if (severity < lf->loglevel || severity > lf->max_loglevel)
      continue;
    if (!lf->file)
      continue;

    if (!formatted) {
      format_msg(buf, 10024, severity, funcname, format, ap);
      formatted = 1;
    }
    if(fputs(buf, lf->file) == EOF) { /* error */
      assert(0); /* XXX */
    }
    if(fflush(lf->file) == EOF) { /* error */
      /* don't log the error! */
      assert(0); /* XXX fail for now. what's better to do? */
    }
  }
}

/* Outputs a message to stdout */
void _log(int severity, const char *format, ...)
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
  logfile_t *victim;
  while(logfiles) {
    victim = logfiles;
    logfiles = logfiles->next;
    if (victim->needs_close)
      fclose(victim->file);
    free(victim);
  }
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
  lf->max_loglevel = LOG_ERR;
  lf->file = stream;
  lf->next = logfiles;
  logfiles = lf;
}

/*
 * If opening the logfile fails, -1 is returned and
 * errno is set appropriately (by fopen)
 */
int add_file_log(int loglevel, const char *filename)
{
  FILE *f;
  f = fopen(filename, "a");
  if (!f) return -1;
  add_stream_log(loglevel, filename, f);
  logfiles->needs_close = 1;
  return 0;
}

