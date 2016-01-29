/* Copyright (c) 2014-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"

#ifndef TOR_LOG_TEST_HELPERS_H
#define TOR_LOG_TEST_HELPERS_H

typedef struct mock_saved_log_entry_t {
  int severity;
  const char *funcname;
  const char *suffix;
  const char *format;
  char *generated_msg;
  struct mock_saved_log_entry_t *next;
} mock_saved_log_entry_t;

void mock_saving_logv(int severity, log_domain_mask_t domain,
                      const char *funcname, const char *suffix,
                      const char *format, va_list ap)
  CHECK_PRINTF(5, 0);
void mock_clean_saved_logs(void);
const smartlist_t *mock_saved_logs(void);
int setup_capture_of_logs(int new_level);
void teardown_capture_of_logs(int prev);
const char *mock_saved_log_at(int ix);
int mock_saved_severity_at(int ix);
int mock_saved_log_number(void);
int mock_saved_log_has_message(const char *msg);

#endif

