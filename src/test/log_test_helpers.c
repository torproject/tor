/* Copyright (c) 2015-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */
#define LOG_PRIVATE
#include "torlog.h"
#include "log_test_helpers.h"

static smartlist_t *saved_logs = NULL;

static int echo_to_real_logs = 1;

int
setup_full_capture_of_logs(int new_level)
{
  int result = setup_capture_of_logs(new_level);
  echo_to_real_logs = 0;
  return result;
}

int
setup_capture_of_logs(int new_level)
{
  int previous_log = log_global_min_severity_;
  log_global_min_severity_ = new_level;
  mock_clean_saved_logs();
  saved_logs = smartlist_new();
  MOCK(logv, mock_saving_logv);
  echo_to_real_logs = 1;
  return previous_log;
}

void
teardown_capture_of_logs(int prev)
{
  UNMOCK(logv);
  log_global_min_severity_ = prev;
  mock_clean_saved_logs();
}

void
mock_clean_saved_logs(void)
{
  if (!saved_logs)
    return;
  SMARTLIST_FOREACH(saved_logs, mock_saved_log_entry_t *, m,
                    { tor_free(m->generated_msg); tor_free(m); });
  smartlist_free(saved_logs);
  saved_logs = NULL;
}

const smartlist_t *
mock_saved_logs(void)
{
  return saved_logs;
}

int
mock_saved_log_has_message(const char *msg)
{
  int has_msg = 0;
  if (saved_logs) {
    SMARTLIST_FOREACH(saved_logs, mock_saved_log_entry_t *, m,
                      {
                        if (msg && m->generated_msg &&
                            !strcmp(msg, m->generated_msg)) {
                          has_msg = 1;
                        }
                      });
  }

  return has_msg;
}

int
mock_saved_log_has_message_containing(const char *msg)
{
  if (saved_logs) {
    SMARTLIST_FOREACH(saved_logs, mock_saved_log_entry_t *, m,
                      {
                        if (msg && m->generated_msg &&
                            strstr(m->generated_msg, msg)) {
                          return 1;
                        }
                      });
  }

  return 0;
}


/* Do the saved logs have any messages with severity? */
int
mock_saved_log_has_severity(int severity)
{
  int has_sev = 0;
  if (saved_logs) {
    SMARTLIST_FOREACH(saved_logs, mock_saved_log_entry_t *, m,
                      {
                        if (m->severity == severity) {
                          has_sev = 1;
                        }
                      });
  }

  return has_sev;
}

/* Do the saved logs have any messages? */
int
mock_saved_log_has_entry(void)
{
  if (saved_logs) {
    return smartlist_len(saved_logs) > 0;
  }
  return 0;
}

void
mock_saving_logv(int severity, log_domain_mask_t domain,
                 const char *funcname, const char *suffix,
                 const char *format, va_list ap)
{
  char *buf = tor_malloc_zero(10240);
  int n;
  n = tor_vsnprintf(buf,10240,format,ap);
  tor_assert(n < 10240-1);
  buf[n]='\n';
  buf[n+1]='\0';

  mock_saved_log_entry_t *e = tor_malloc_zero(sizeof(mock_saved_log_entry_t));
  e->severity = severity;
  e->funcname = funcname;
  e->suffix = suffix;
  e->format = format;
  e->generated_msg = tor_strdup(buf);
  tor_free(buf);

  if (!saved_logs)
    saved_logs = smartlist_new();
  smartlist_add(saved_logs, e);

  if (echo_to_real_logs) {
    tor_log(severity, domain|LD_NO_MOCK, "%s", e->generated_msg);
  }
}

