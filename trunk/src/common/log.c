/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file log.c
 *
 * \brief Functions to send messages to log files or the console.
 */

#include <stdarg.h>
#include <assert.h>
#include <stdlib.h>
#include "orconfig.h"
#include "./util.h"
#include "./log.h"


#ifdef MS_WINDOWS
#define vsnprintf _vsnprintf
#define snprintf _snprintf
#endif

/** Information for a single logfile; only used in log.c */
typedef struct logfile_t {
  struct logfile_t *next; /**< Next logfile_t in the linked list */
  const char *filename; /**< Filename to open */
  FILE *file; /**< Stream to receive log messages */
  int needs_close; /**< Boolean: true if the stream gets closed on shutdown. */
  int loglevel; /**< Lowest severity level to send to this stream. */
  int max_loglevel; /**< Highest severity level to send to this stream. */
} logfile_t;

/** Helper: map a log severity to descriptive string */
static INLINE const char *sev_to_string(int severity) {
  switch(severity) {
    case LOG_DEBUG:   return "debug";
    case LOG_INFO:    return "info";
    case LOG_NOTICE:  return "notice";
    case LOG_WARN:    return "warn";
    case LOG_ERR:     return "err";
    default:          assert(0); return "UNKNOWN";
  }
}

/** Linked list of logfile_t */
static logfile_t *logfiles = NULL;

/** Helper: Format a log message into a fixed-sized buffer. (This is
 * factored out of <b>logv</b> so that we never format a message more
 * than once.)
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

/** Helper: sends a message to the appropriate logfiles, at loglevel
 * <b>severity</b>.  If provided, <b>funcname</b> is prepended to the
 * message.  The actual message is derived as from vsprintf(format,ap).
 */
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

/** Output a message to the log. */
void _log(int severity, const char *format, ...)
{
  va_list ap;
  va_start(ap,format);
  logv(severity, NULL, format, ap);
  va_end(ap);
}

/** Output a message to the log, prefixed with a function name <b>fn</b> */
void _log_fn(int severity, const char *fn, const char *format, ...)
{
  va_list ap;
  va_start(ap,format);
  logv(severity, fn, format, ap);
  va_end(ap);
}

/** Close all open log files */
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

/** Close and re-open all log files; used to rotate logs on SIGHUP. */
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

/** Add a log handler to send all messages of severity <b>loglevel</b>
 * or higher to <b>stream</b>. */
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

/**
 * Add a log handler to send messages to <b>filename</b>. If opening
 * the logfile fails, -1 is returned and errno is set appropriately
 * (by fopen)
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

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
