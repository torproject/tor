#define LOG_PRIVATE
#include "torlog.h"
#include "log_test_helpers.h"

static smartlist_t *saved_logs = NULL;

int
setup_capture_of_logs(int new_level)
{
  int previous_log = log_global_min_severity_;
  log_global_min_severity_ = new_level;
  mock_clean_saved_logs();
  MOCK(logv, mock_saving_logv);
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

static mock_saved_log_entry_t *
mock_get_log_entry(int ix)
{
  int saved_log_count = mock_saved_log_number();
  if(ix < 0) {
    ix = saved_log_count + ix;
  }

  if (saved_log_count <= ix)
    return NULL;

  return smartlist_get(saved_logs, ix);
}

const char *
mock_saved_log_at(int ix)
{
  mock_saved_log_entry_t *ent = mock_get_log_entry(ix);
  if (ent)
    return ent->generated_msg;
  else
    return "";
}

int
mock_saved_severity_at(int ix)
{
  mock_saved_log_entry_t *ent = mock_get_log_entry(ix);
  if (ent)
    return ent->severity;
  else
    return -1;
}

int
mock_saved_log_number(void)
{
  if (!saved_logs)
    return 0;
  return smartlist_len(saved_logs);
}

const smartlist_t *
mock_saved_logs(void)
{
  return saved_logs;
}

void
mock_saving_logv(int severity, log_domain_mask_t domain,
                 const char *funcname, const char *suffix,
                 const char *format, va_list ap)
{
  (void)domain;
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
}
