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
#include <string.h>
#include "orconfig.h"
#include "./util.h"
#include "./log.h"


#ifdef MS_WINDOWS
#define vsnprintf _vsnprintf
#define snprintf _snprintf
#endif

#define TRUNCATED_STR "[...truncated]"
#define TRUNCATED_STR_LEN 14

/** Information for a single logfile; only used in log.c */
typedef struct logfile_t {
  struct logfile_t *next; /**< Next logfile_t in the linked list. */
  char *filename; /**< Filename to open. */
  FILE *file; /**< Stream to receive log messages. */
  int needs_close; /**< Boolean: true if the stream gets closed on shutdown. */
  int loglevel; /**< Lowest severity level to send to this stream. */
  int max_loglevel; /**< Highest severity level to send to this stream. */
  int is_temporary; /**< Boolean: close after initializing logging subsystem.*/
} logfile_t;

/** Helper: map a log severity to descriptive string. */
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

/** Linked list of logfile_t. */
static logfile_t *logfiles = NULL;

static void delete_log(logfile_t *victim);

static INLINE size_t
_log_prefix(char *buf, size_t buf_len, int severity)
{
  time_t t;
  struct timeval now;
  size_t n;

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
  return n;
}

/** If lf refers to an actual file that we have just opened, and the file
 * contains no data, log an "opening new logfile" message at the top. **/
static void log_tor_version(logfile_t *lf, int reset)
{
  char buf[256];
  size_t n;
  int is_new;

  if (!lf->needs_close)
    /* If it doesn't get closed, it isn't really a file. */
    return;
  if (lf->is_temporary)
    /* If it's temporary, it isn't really a file. */
    return;
  is_new = (ftell(lf->file) == 0);
  if (reset && !is_new)
    /* We are resetting, but we aren't at the start of the file; no
     * need to log again. */
    return;
  n = _log_prefix(buf, 250, LOG_NOTICE);
  n += snprintf(buf+n, 250-n, "Tor %s opening %slog file.\n", VERSION,
                is_new?"new ":"");
  if (n>250)
    n = 250;
  buf[n+1]='\0';
  fputs(buf, lf->file);
}

/** Helper: Format a log message into a fixed-sized buffer. (This is
 * factored out of <b>logv</b> so that we never format a message more
 * than once.)
 */
static INLINE void format_msg(char *buf, size_t buf_len,
                              int severity, const char *funcname,
                              const char *format, va_list ap)
{
  size_t n;
  buf_len -= 2; /* subtract 2 characters so we have room for \n\0 */

  n = _log_prefix(buf, buf_len, severity);

  if (funcname) {
    n += snprintf(buf+n, buf_len-n, "%s(): ", funcname);
    if(n > buf_len)
      n = buf_len-1;
  }

  n += vsnprintf(buf+n,buf_len-n,format,ap);
  if(n > buf_len) {
    n = buf_len-1;
    strcpy(buf+n-TRUNCATED_STR_LEN, TRUNCATED_STR);
  }
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
  lf = logfiles;
  while(lf) {
    if (severity < lf->loglevel || severity > lf->max_loglevel) {
      lf = lf->next;
      continue;
    }
    if (!lf->file) {
      lf = lf->next;
      continue;
    }

    if (!formatted) {
      format_msg(buf, sizeof(buf), severity, funcname, format, ap);
      formatted = 1;
    }
    if(fputs(buf, lf->file) == EOF ||
       fflush(lf->file) == EOF) { /* error */
      /* don't log the error! Blow away this log entry and continue. */
      logfile_t *victim = lf;
      lf = victim->next;
      delete_log(victim);
    } else {
      lf = lf->next;
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

/** Output a message to the log, prefixed with a function name <b>fn</b>. */
void _log_fn(int severity, const char *fn, const char *format, ...)
{
  va_list ap;
  va_start(ap,format);
  logv(severity, fn, format, ap);
  va_end(ap);
}

/** Close all open log files. */
void close_logs()
{
  logfile_t *victim;
  while(logfiles) {
    victim = logfiles;
    logfiles = logfiles->next;
    if (victim->needs_close)
      fclose(victim->file);
    tor_free(victim->filename);
    tor_free(victim);
  }
}

/** Close and re-open all log files; used to rotate logs on SIGHUP. */
void reset_logs()
{
  logfile_t *lf = logfiles;
  while(lf) {
    if (lf->needs_close) {
      if(fclose(lf->file)==EOF ||
        !(lf->file = fopen(lf->filename, "a"))) {
        /* error. don't log it. delete the log entry and continue. */
        logfile_t *victim = lf;
        lf = victim->next;
        delete_log(victim);
        continue;
      } else {
        log_tor_version(lf, 1);
      }
    }
    lf = lf->next;
  }
}

/** Remove and free the log entry <b>victim</b> from the linked-list
 * logfiles (it must be present in the list when this function is
 * called). After this function is called, the caller shouldn't refer
 * to <b>victim</b> anymore.
 */
static void delete_log(logfile_t *victim) {
  logfile_t *tmpl;
  if(victim == logfiles)
    logfiles = victim->next;
  else {
    for(tmpl = logfiles; tmpl && tmpl->next != victim; tmpl=tmpl->next) ;
    tor_assert(tmpl && tmpl->next == victim);
    tmpl->next = victim->next;
  }
  tor_free(victim->filename);
  tor_free(victim);
}

/** Add a log handler to send all messages of severity <b>loglevel</b>
 * or higher to <b>stream</b>. */
void add_stream_log(int loglevelMin, int loglevelMax, const char *name, FILE *stream)
{
  logfile_t *lf;
  lf = tor_malloc(sizeof(logfile_t));
  lf->filename = tor_strdup(name);
  lf->needs_close = 0;
  lf->loglevel = loglevelMin;
  lf->max_loglevel = loglevelMax;
  lf->file = stream;
  lf->next = logfiles;
  lf->is_temporary = 0;
  logfiles = lf;
}

/** Add a log handler to receive messages during startup (before the real
 * logs are initialized).
 */
void add_temp_log(void)
{
  add_stream_log(LOG_INFO, LOG_ERR, "<temp>", stdout);
  logfiles->is_temporary = 1;
}

void close_temp_logs(void)
{
  logfile_t *lf, **p;
  for (p = &logfiles; *p; ) {
    if ((*p)->is_temporary) {
      lf = *p;
      *p = (*p)->next;
      if (lf->needs_close)
        fclose(lf->file);
      tor_free(lf->filename);
      tor_free(lf);
    } else {
      p = &((*p)->next);
    }
  }
}

void mark_logs_temp(void)
{
  logfile_t *lf;
  for (lf = logfiles; lf; lf = lf->next)
    lf->is_temporary = 1;
}

/**
 * Add a log handler to send messages to <b>filename</b>. If opening
 * the logfile fails, -1 is returned and errno is set appropriately
 * (by fopen).
 */
int add_file_log(int loglevelMin, int loglevelMax, const char *filename)
{
  FILE *f;
  f = fopen(filename, "a");
  if (!f) return -1;
  add_stream_log(loglevelMin, loglevelMax, filename, f);
  logfiles->needs_close = 1;
  log_tor_version(logfiles, 0);
  return 0;
}

/** If <b>level</b> is a valid log severity, return the corresponding
 * numeric value.  Otherwise, return -1. */
int parse_log_level(const char *level) {
  if (!strcasecmp(level, "err"))
    return LOG_ERR;
  if (!strcasecmp(level, "warn"))
    return LOG_WARN;
  if (!strcasecmp(level, "notice"))
    return LOG_NOTICE;
  if (!strcasecmp(level, "info"))
    return LOG_INFO;
  if (!strcasecmp(level, "debug"))
    return LOG_DEBUG;
  return -1;
}

int get_min_log_level(void)
{
  logfile_t *lf;
  int min = LOG_ERR;
  for (lf = logfiles; lf; lf = lf->next) {
    if (lf->loglevel < min)
      min = lf->loglevel;
  }
  return min;
}


/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
