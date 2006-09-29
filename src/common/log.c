/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char log_c_id[] = "$Id$";

/**
 * \file log.c
 * \brief Functions to send messages to log files or the console.
 **/

#include "orconfig.h"
#include <stdarg.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include "./util.h"
#include "./log.h"

#ifdef HAVE_EVENT_H
#include <event.h>
#else
#error "Tor requires libevent to build."
#endif

#define TRUNCATED_STR "[...truncated]"
#define TRUNCATED_STR_LEN 14

/** Information for a single logfile; only used in log.c */
typedef struct logfile_t {
  struct logfile_t *next; /**< Next logfile_t in the linked list. */
  char *filename; /**< Filename to open. */
  FILE *file; /**< Stream to receive log messages. */
  int needs_close; /**< Boolean: true if the stream gets closed on shutdown. */
  int min_loglevel; /**< Lowest severity level to send to this stream. */
  int max_loglevel; /**< Highest severity level to send to this stream. */
  int is_temporary; /**< Boolean: close after initializing logging subsystem.*/
  int is_syslog; /**< Boolean: send messages to syslog. */
  log_callback callback; /**< If not NULL, send messages to this function. */
} logfile_t;

/** Helper: map a log severity to descriptive string. */
static INLINE const char *
sev_to_string(int severity)
{
  switch (severity) {
    case LOG_DEBUG:   return "debug";
    case LOG_INFO:    return "info";
    case LOG_NOTICE:  return "notice";
    case LOG_WARN:    return "warn";
    case LOG_ERR:     return "err";
    default:          assert(0); return "UNKNOWN";
  }
}

/** Helper: decide whether to include the function name in the log message. */
static INLINE int
should_log_function_name(uint32_t domain, int severity)
{
  switch (severity) {
    case LOG_DEBUG:
    case LOG_INFO:
      /* All debugging messages occur in interesting places. */
      return 1;
    case LOG_NOTICE:
    case LOG_WARN:
    case LOG_ERR:
      /* We care about places where bugs occur. */
      return (domain == LD_BUG);
    default:
      assert(0); return 0;
  }
}

/** Linked list of logfile_t. */
static logfile_t *logfiles = NULL;
#ifdef HAVE_SYSLOG_H
static int syslog_count = 0;
#endif

static void delete_log(logfile_t *victim);
static void close_log(logfile_t *victim);

/** Helper: Write the standard prefix for log lines to a
 * <b>buf_len</b> character buffer in <b>buf</b>.
 */
static INLINE size_t
_log_prefix(char *buf, size_t buf_len, int severity)
{
  time_t t;
  struct timeval now;
  struct tm tm;
  size_t n;
  int r;

  tor_gettimeofday(&now);
  t = (time_t)now.tv_sec;

  n = strftime(buf, buf_len, "%b %d %H:%M:%S", tor_localtime_r(&t, &tm));
  r = tor_snprintf(buf+n, buf_len-n,
                ".%.3ld [%s] ",
                (long)now.tv_usec / 1000, sev_to_string(severity));
  if (r<0)
    return buf_len-1;
  else
    return n+r;
}

/** If lf refers to an actual file that we have just opened, and the file
 * contains no data, log an "opening new logfile" message at the top.
 *
 * Return -1 if the log is broken and needs to be deleted, else return 0.
 */
static int
log_tor_version(logfile_t *lf, int reset)
{
  char buf[256];
  size_t n;
  int is_new;

  if (!lf->needs_close)
    /* If it doesn't get closed, it isn't really a file. */
    return 0;
  if (lf->is_temporary)
    /* If it's temporary, it isn't really a file. */
    return 0;
#ifdef HAVE_FTELLO
  is_new = (ftello(lf->file) == 0);
#else
  is_new = (ftell(lf->file) == 0);
#endif
  if (reset && !is_new)
    /* We are resetting, but we aren't at the start of the file; no
     * need to log again. */
    return 0;
  n = _log_prefix(buf, sizeof(buf), LOG_NOTICE);
  tor_snprintf(buf+n, sizeof(buf)-n,
               "Tor %s opening %slog file.\n", VERSION, is_new?"new ":"");
  if (fputs(buf, lf->file) == EOF ||
      fflush(lf->file) == EOF) /* error */
    return -1; /* failed */
  return 0;
}

/** Helper: Format a log message into a fixed-sized buffer. (This is
 * factored out of <b>logv</b> so that we never format a message more
 * than once.)  Return a pointer to the first character of the message
 * portion of the formatted string.
 */
static INLINE char *
format_msg(char *buf, size_t buf_len,
           uint32_t domain, int severity, const char *funcname,
           const char *format, va_list ap)
{
  size_t n;
  int r;
  char *end_of_prefix;

  tor_assert(buf_len >= 2); /* prevent integer underflow */
  buf_len -= 2; /* subtract 2 characters so we have room for \n\0 */

  n = _log_prefix(buf, buf_len, severity);
  end_of_prefix = buf+n;

  if (funcname && should_log_function_name(domain, severity)) {
    r = tor_snprintf(buf+n, buf_len-n, "%s(): ", funcname);
    if (r<0)
      n = strlen(buf);
    else
      n += r;
  }

  r = tor_vsnprintf(buf+n,buf_len-n,format,ap);
  if (r < 0) {
    /* The message was too long; overwrite the end of the buffer with
     * "[...truncated]" */
    if (buf_len >= TRUNCATED_STR_LEN) {
      int offset = buf_len-TRUNCATED_STR_LEN;
      /* We have an extra 2 characters after buf_len to hold the \n\0,
       * so it's safe to add 1 to the size here. */
      strlcpy(buf+offset, TRUNCATED_STR, buf_len-offset+1);
    }
    /* Set 'n' to the end of the buffer, where we'll be writing \n\0.
     * Since we already subtracted 2 from buf_len, this is safe.*/
    n = buf_len;
  } else {
    n += r;
  }
  buf[n]='\n';
  buf[n+1]='\0';
  return end_of_prefix;
}

/** Helper: sends a message to the appropriate logfiles, at loglevel
 * <b>severity</b>.  If provided, <b>funcname</b> is prepended to the
 * message.  The actual message is derived as from tor_snprintf(format,ap).
 */
static void
logv(int severity, uint32_t domain, const char *funcname, const char *format,
     va_list ap)
{
  char buf[10024];
  int formatted = 0;
  logfile_t *lf;
  char *end_of_prefix=NULL;

  assert(format);
  lf = logfiles;
  while (lf) {
    if (severity > lf->min_loglevel || severity < lf->max_loglevel) {
      lf = lf->next;
      continue;
    }
    if (! (lf->file || lf->is_syslog || lf->callback)) {
      lf = lf->next;
      continue;
    }

    if (!formatted) {
      end_of_prefix =
        format_msg(buf, sizeof(buf), domain, severity, funcname, format, ap);
      formatted = 1;
    }
    if (lf->is_syslog) {
#ifdef HAVE_SYSLOG_H
      syslog(severity, "%s", end_of_prefix);
#endif
      lf = lf->next;
      continue;
    } else if (lf->callback) {
      lf->callback(severity, domain, end_of_prefix);
      lf = lf->next;
      continue;
    }
    if (fputs(buf, lf->file) == EOF ||
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
void
_log(int severity, uint32_t domain, const char *format, ...)
{
  va_list ap;
  va_start(ap,format);
  logv(severity, domain, NULL, format, ap);
  va_end(ap);
}

/** Output a message to the log, prefixed with a function name <b>fn</b>. */
#ifdef __GNUC__
void
_log_fn(int severity, uint32_t domain, const char *fn, const char *format, ...)
{
  va_list ap;
  va_start(ap,format);
  logv(severity, domain, fn, format, ap);
  va_end(ap);
}
#else
const char *_log_fn_function_name=NULL;
void
_log_fn(int severity, uint32_t domain, const char *format, ...)
{
  va_list ap;
  va_start(ap,format);
  logv(severity, domain, _log_fn_function_name, format, ap);
  va_end(ap);
  _log_fn_function_name = NULL;
}
void
_log_debug(uint32_t domain, const char *format, ...)
{
  va_list ap;
  va_start(ap,format);
  logv(LOG_DEBUG, domain, _log_fn_function_name, format, ap);
  va_end(ap);
  _log_fn_function_name = NULL;
}
void
_log_info(uint32_t domain, const char *format, ...)
{
  va_list ap;
  va_start(ap,format);
  logv(LOG_INFO, domain, _log_fn_function_name, format, ap);
  va_end(ap);
  _log_fn_function_name = NULL;
}
void
_log_notice(uint32_t domain, const char *format, ...)
{
  va_list ap;
  va_start(ap,format);
  logv(LOG_NOTICE, domain, _log_fn_function_name, format, ap);
  va_end(ap);
  _log_fn_function_name = NULL;
}
void
_log_warn(uint32_t domain, const char *format, ...)
{
  va_list ap;
  va_start(ap,format);
  logv(LOG_WARN, domain, _log_fn_function_name, format, ap);
  va_end(ap);
  _log_fn_function_name = NULL;
}
void
_log_err(uint32_t domain, const char *format, ...)
{
  va_list ap;
  va_start(ap,format);
  logv(LOG_ERR, domain, _log_fn_function_name, format, ap);
  va_end(ap);
  _log_fn_function_name = NULL;
}
#endif

/** Close all open log files. */
void
close_logs(void)
{
  logfile_t *victim, *next;
  next = logfiles;
  logfiles = NULL;
  while (next) {
    victim = next;
    next = next->next;
    close_log(victim);
    tor_free(victim->filename);
    tor_free(victim);
  }
}

/** Remove and free the log entry <b>victim</b> from the linked-list
 * logfiles (it is probably present, but it might not be due to thread
 * racing issues). After this function is called, the caller shouldn't
 * refer to <b>victim</b> anymore.
 *
 * Long-term, we need to do something about races in the log subsystem
 * in general. See bug 222 for more details.
 */
static void
delete_log(logfile_t *victim)
{
  logfile_t *tmpl;
  if (victim == logfiles)
    logfiles = victim->next;
  else {
    for (tmpl = logfiles; tmpl && tmpl->next != victim; tmpl=tmpl->next) ;
//    tor_assert(tmpl);
//    tor_assert(tmpl->next == victim);
    if (!tmpl)
      return;
    tmpl->next = victim->next;
  }
  tor_free(victim->filename);
  tor_free(victim);
}

/** Helper: release system resources (but not memory) held by a single
 * logfile_t. */
static void
close_log(logfile_t *victim)
{
  if (victim->needs_close && victim->file) {
    fclose(victim->file);
  } else if (victim->is_syslog) {
#ifdef HAVE_SYSLOG_H
    if (--syslog_count == 0) {
      /* There are no other syslogs; close the logging facility. */
      closelog();
    }
#endif
  }
}

/** Add a log handler to send all messages of severity <b>loglevel</b>
 * or higher to <b>stream</b>. */
void
add_stream_log(int loglevelMin, int loglevelMax,
               const char *name, FILE *stream)
{
  logfile_t *lf;
  lf = tor_malloc_zero(sizeof(logfile_t));
  lf->filename = tor_strdup(name);
  lf->min_loglevel = loglevelMin;
  lf->max_loglevel = loglevelMax;
  lf->file = stream;
  lf->next = logfiles;
  logfiles = lf;
}

/** Add a log handler to receive messages during startup (before the real
 * logs are initialized).
 */
void
add_temp_log(void)
{
  add_stream_log(LOG_NOTICE, LOG_ERR, "<temp>", stdout);
  logfiles->is_temporary = 1;
}

/**
 * Add a log handler to send messages of severity between
 * <b>logLevelmin</b> and <b>logLevelMax</b> to the function
 * <b>cb</b>.
 */
int
add_callback_log(int loglevelMin, int loglevelMax, log_callback cb)
{
  logfile_t *lf;
  lf = tor_malloc_zero(sizeof(logfile_t));
  lf->min_loglevel = loglevelMin;
  lf->max_loglevel = loglevelMax;
  lf->filename = tor_strdup("<callback>");
  lf->callback = cb;
  lf->next = logfiles;
  logfiles = lf;
  return 0;
}

/** Adjust the configured severity of any logs whose callback function is
 * <b>cb</b>. */
void
change_callback_log_severity(int loglevelMin, int loglevelMax,
                             log_callback cb)
{
  logfile_t *lf;
  for (lf = logfiles; lf; lf = lf->next) {
    if (lf->callback == cb) {
      lf->min_loglevel = loglevelMin;
      lf->max_loglevel = loglevelMax;
    }
  }
}

/** Close any log handlers added by add_temp_log or marked by mark_logs_temp */
void
close_temp_logs(void)
{
  logfile_t *lf, **p;
  for (p = &logfiles; *p; ) {
    if ((*p)->is_temporary) {
      lf = *p;
      /* we use *p here to handle the edge case of the head of the list */
      *p = (*p)->next;
      close_log(lf);
      tor_free(lf->filename);
      tor_free(lf);
    } else {
      p = &((*p)->next);
    }
  }
}

/** Make all currently temporary logs (set to be closed by close_temp_logs)
 * live again, and close all non-temporary logs. */
void
rollback_log_changes(void)
{
  logfile_t *lf;
  for (lf = logfiles; lf; lf = lf->next)
    lf->is_temporary = ! lf->is_temporary;
  close_temp_logs();
}

/** Configure all log handles to be closed by close_temp_logs */
void
mark_logs_temp(void)
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
int
add_file_log(int loglevelMin, int loglevelMax, const char *filename)
{
  FILE *f;
  f = fopen(filename, "a");
  if (!f) return -1;
  add_stream_log(loglevelMin, loglevelMax, filename, f);
  logfiles->needs_close = 1;
  if (log_tor_version(logfiles, 0) < 0) {
    delete_log(logfiles);
  }
  return 0;
}

#ifdef HAVE_SYSLOG_H
/**
 * Add a log handler to send messages to they system log facility.
 */
int
add_syslog_log(int loglevelMin, int loglevelMax)
{
  logfile_t *lf;
  if (syslog_count++ == 0)
    /* This is the first syslog. */
    openlog("Tor", LOG_PID | LOG_NDELAY, LOGFACILITY);

  lf = tor_malloc_zero(sizeof(logfile_t));
  lf->min_loglevel = loglevelMin;
  lf->filename = tor_strdup("<syslog>");
  lf->max_loglevel = loglevelMax;
  lf->is_syslog = 1;
  lf->next = logfiles;
  logfiles = lf;
  return 0;
}
#endif

/** If <b>level</b> is a valid log severity, return the corresponding
 * numeric value.  Otherwise, return -1. */
int
parse_log_level(const char *level)
{
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

/** Return the string equivalent of a given log level. */
const char *
log_level_to_string(int level)
{
  return sev_to_string(level);
}

/** Return the least severe log level that any current log is interested in. */
int
get_min_log_level(void)
{
  logfile_t *lf;
  int min = LOG_ERR;
  for (lf = logfiles; lf; lf = lf->next) {
    if (lf->min_loglevel > min)
      min = lf->min_loglevel;
  }
  return min;
}

/** Switch all logs to output at most verbose level. */
void
switch_logs_debug(void)
{
  logfile_t *lf;
  for (lf = logfiles; lf; lf=lf->next) {
    lf->min_loglevel = LOG_DEBUG;
  }
}

#ifdef HAVE_EVENT_SET_LOG_CALLBACK
/** A string which, if it appears in a libevent log, should be ignored. */
static const char *suppress_msg = NULL;
/** Callback function passed to event_set_log() so we can intercept
 * log messages from libevent. */
static void
libevent_logging_callback(int severity, const char *msg)
{
  char buf[1024];
  size_t n;
  if (suppress_msg && strstr(msg, suppress_msg))
    return;
  n = strlcpy(buf, msg, sizeof(buf));
  if (n && n < sizeof(buf) && buf[n-1] == '\n') {
    buf[n-1] = '\0';
  }
  switch (severity) {
    case _EVENT_LOG_DEBUG:
      log(LOG_DEBUG, LD_NET, "Message from libevent: %s", buf);
      break;
    case _EVENT_LOG_MSG:
      log(LOG_INFO, LD_NET, "Message from libevent: %s", buf);
      break;
    case _EVENT_LOG_WARN:
      log(LOG_WARN, LD_GENERAL, "Warning from libevent: %s", buf);
      break;
    case _EVENT_LOG_ERR:
      log(LOG_ERR, LD_GENERAL, "Error from libevent: %s", buf);
      break;
    default:
      log(LOG_WARN, LD_GENERAL, "Message [%d] from libevent: %s",
          severity, buf);
      break;
  }
}
/** Set hook to intercept log messages from libevent. */
void
configure_libevent_logging(void)
{
  event_set_log_callback(libevent_logging_callback);
}
/** Ignore any libevent log message that contains <b>msg</b> */
void
suppress_libevent_log_msg(const char *msg)
{
  suppress_msg = msg;
}
#else
void
configure_libevent_logging(void)
{
}
void
suppress_libevent_log_msg(const char *msg)
{
}
#endif

#if 0
static void
dump_log_info(logfile_t *lf)
{
  const char *tp;

  if (lf->filename) {
    printf("=== log into \"%s\" (%s-%s) (%stemporary)\n", lf->filename,
           sev_to_string(lf->min_loglevel),
           sev_to_string(lf->max_loglevel),
           lf->is_temporary?"":"not ");
  } else if (lf->is_syslog) {
    printf("=== syslog (%s-%s) (%stemporary)\n",
           sev_to_string(lf->min_loglevel),
           sev_to_string(lf->max_loglevel),
           lf->is_temporary?"":"not ");
  } else {
    printf("=== log (%s-%s) (%stemporary)\n",
           sev_to_string(lf->min_loglevel),
           sev_to_string(lf->max_loglevel),
           lf->is_temporary?"":"not ");
  }
}

void
describe_logs(void)
{
  logfile_t *lf;
  printf("==== BEGIN LOGS ====\n");
  for (lf = logfiles; lf; lf = lf->next)
    dump_log_info(lf);
  printf("==== END LOGS ====\n");
}
#endif

