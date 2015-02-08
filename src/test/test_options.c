/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define CONFIG_PRIVATE
#include "or.h"
#include "confparse.h"
#include "config.h"
#include "test.h"

typedef struct {
  int severity;
  uint32_t domain;
  char *msg;
} logmsg_t;

static smartlist_t *messages = NULL;

static void
log_cback(int severity, uint32_t domain, const char *msg)
{
  logmsg_t *x = tor_malloc(sizeof(*x));
  x->severity = severity;
  x->domain = domain;
  x->msg = tor_strdup(msg);
  if (!messages)
    messages = smartlist_new();
  smartlist_add(messages, x);
}

static void
setup_log_callback(void)
{
  log_severity_list_t lst;
  memset(&lst, 0, sizeof(lst));
  lst.masks[LOG_ERR - LOG_ERR] = ~0;
  lst.masks[LOG_WARN - LOG_ERR] = ~0;
  lst.masks[LOG_NOTICE - LOG_ERR] = ~0;
  add_callback_log(&lst, log_cback);
}

static char *
dump_logs(void)
{
  smartlist_t *msgs;
  char *out;
  if (! messages)
    return tor_strdup("");
  msgs = smartlist_new();
  SMARTLIST_FOREACH_BEGIN(messages, logmsg_t *, x) {
    smartlist_add_asprintf(msgs, "[%s] %s",
                           log_level_to_string(x->severity), x->msg);
  } SMARTLIST_FOREACH_END(x);
  out = smartlist_join_strings(msgs, "", 0, NULL);
  SMARTLIST_FOREACH(msgs, char *, cp, tor_free(cp));
  smartlist_free(msgs);
  return out;
}

static void
clear_log_messages(void)
{
  if (!messages)
    return;
  SMARTLIST_FOREACH(messages, logmsg_t *, m,
                    { tor_free(m->msg); tor_free(m); });
  smartlist_free(messages);
  messages = NULL;
}

#define setup_options(opt,dflt)              \
  do {                                       \
    opt = options_new();                     \
    opt->command = CMD_RUN_TOR;              \
    options_init(opt);                       \
                                             \
    dflt = config_dup(&options_format, opt); \
    clear_log_messages();                    \
  } while (0)

static void
test_options_validate_impl(const char *configuration,
                           const char *expect_errmsg,
                           int expect_log_severity,
                           const char *expect_log)
{
  or_options_t *opt=NULL;
  or_options_t *dflt;
  config_line_t *cl=NULL;
  char *msg=NULL;
  int r;

  setup_options(opt, dflt);

  r = config_get_lines(configuration, &cl, 1);
  tt_int_op(r, OP_EQ, 0);

  r = config_assign(&options_format, opt, cl, 0, 0, &msg);
  tt_int_op(r, OP_EQ, 0);

  r = options_validate(NULL, opt, dflt, 0, &msg);
  if (expect_errmsg && !msg) {
    TT_DIE(("Expected error message <%s> from <%s>, but got none.",
            expect_errmsg, configuration));
  } else if (expect_errmsg && !strstr(msg, expect_errmsg)) {
    TT_DIE(("Expected error message <%s> from <%s>, but got <%s>.",
            expect_errmsg, configuration, msg));
  } else if (!expect_errmsg && msg) {
    TT_DIE(("Expected no error message from <%s> but got <%s>.",
            configuration, msg));
  }
  tt_int_op((r == 0), OP_EQ, (msg == NULL));

  if (expect_log) {
    int found = 0;
    if (messages) {
      SMARTLIST_FOREACH_BEGIN(messages, logmsg_t *, m) {
        if (m->severity == expect_log_severity &&
            strstr(m->msg, expect_log)) {
          found = 1;
          break;
        }
      } SMARTLIST_FOREACH_END(m);
    }
    if (!found) {
      tor_free(msg);
      msg = dump_logs();
      TT_DIE(("Expected log message [%s] %s from <%s>, but got <%s>.",
              log_level_to_string(expect_log_severity), expect_log,
              configuration, msg));
    }
  }

 done:
  config_free_lines(cl);
  or_options_free(opt);
  or_options_free(dflt);
  tor_free(msg);
  clear_log_messages();
}

#define WANT_ERR(config, msg)                           \
  test_options_validate_impl((config), (msg), 0, NULL)
#define WANT_LOG(config, severity, msg)                         \
  test_options_validate_impl((config), NULL, (severity), (msg))
#define WANT_ERR_LOG(config, msg, severity, logmsg)                     \
  test_options_validate_impl((config), (msg), (severity), (logmsg))
#define OK(config)                                      \
  test_options_validate_impl((config), NULL, 0, NULL)

static void
test_options_validate(void *arg)
{
  (void)arg;
  setup_log_callback();

  WANT_ERR("ExtORPort 500000", "Invalid ExtORPort");

  WANT_ERR_LOG("ServerTransportOptions trebuchet",
               "ServerTransportOptions did not parse",
               LOG_WARN, "Too few arguments");
  OK("ServerTransportOptions trebuchet sling=snappy");
  OK("ServerTransportOptions trebuchet sling=");
  WANT_ERR_LOG("ServerTransportOptions trebuchet slingsnappy",
               "ServerTransportOptions did not parse",
               LOG_WARN, "\"slingsnappy\" is not a k=v");

  WANT_ERR("DirPort 8080\nDirCache 0",
           "DirPort configured but DirCache disabled.");
  WANT_ERR("BridgeRelay 1\nDirCache 0",
           "We're a bridge but DirCache is disabled.");

  clear_log_messages();
  return;
}

#define MEGABYTEIFY(mb) (U64_LITERAL(mb) << 20)
static void
test_have_enough_mem_for_dircache(void *arg)
{
  (void)arg;
  or_options_t *opt=NULL;
  or_options_t *dflt;
  config_line_t *cl=NULL;
  char *msg=NULL;;
  int r;
  const char *configuration = "ORPort 8080\nDirCache 1", *expect_errmsg;

  setup_options(opt, dflt);
  setup_log_callback();
  (void)dflt;

  r = config_get_lines(configuration, &cl, 1);
  tt_int_op(r, OP_EQ, 0);

  r = config_assign(&options_format, opt, cl, 0, 0, &msg);
  tt_int_op(r, OP_EQ, 0);

  /* 300 MB RAM available, DirCache enabled */
  r = have_enough_mem_for_dircache(opt, MEGABYTEIFY(300), &msg);
  tt_int_op(r, OP_EQ, 0);
  tt_assert(!msg);

  /* 200 MB RAM available, DirCache enabled */
  r = have_enough_mem_for_dircache(opt, MEGABYTEIFY(200), &msg);
  tt_int_op(r, OP_EQ, -1);
  expect_errmsg = "Being a directory cache (default) with less than ";
  if (!strstr(msg, expect_errmsg)) {
    TT_DIE(("Expected error message <%s> from <%s>, but got <%s>.",
            expect_errmsg, configuration, msg));
  }
  tor_free(msg);

  configuration = "ORPort 8080\nDirCache 1\nBridgeRelay 1";
  r = config_get_lines(configuration, &cl, 1);
  tt_int_op(r, OP_EQ, 0);

  r = config_assign(&options_format, opt, cl, 0, 0, &msg);
  tt_int_op(r, OP_EQ, 0);

  /* 300 MB RAM available, DirCache enabled, Bridge */
  r = have_enough_mem_for_dircache(opt, MEGABYTEIFY(300), &msg);
  tt_int_op(r, OP_EQ, 0);
  tt_assert(!msg);

  /* 200 MB RAM available, DirCache enabled, Bridge */
  r = have_enough_mem_for_dircache(opt, MEGABYTEIFY(200), &msg);
  tt_int_op(r, OP_EQ, -1);
  expect_errmsg = "Running a Bridge with less than ";
  if (!strstr(msg, expect_errmsg)) {
    TT_DIE(("Expected error message <%s> from <%s>, but got <%s>.",
            expect_errmsg, configuration, msg));
  }
  tor_free(msg);

  configuration = "ORPort 8080\nDirCache 0";
  r = config_get_lines(configuration, &cl, 1);
  tt_int_op(r, OP_EQ, 0);

  r = config_assign(&options_format, opt, cl, 0, 0, &msg);
  tt_int_op(r, OP_EQ, 0);

  /* 200 MB RAM available, DirCache disabled */
  r = have_enough_mem_for_dircache(opt, MEGABYTEIFY(200), &msg);
  tt_int_op(r, OP_EQ, 0);
  tt_assert(!msg);

  /* 300 MB RAM available, DirCache disabled */
  r = have_enough_mem_for_dircache(opt, MEGABYTEIFY(300), &msg);
  tt_int_op(r, OP_EQ, -1);
  expect_errmsg = "DirCache is disabled and we are configured as a ";
  if (!strstr(msg, expect_errmsg)) {
    TT_DIE(("Expected error message <%s> from <%s>, but got <%s>.",
            expect_errmsg, configuration, msg));
  }
  tor_free(msg);

  clear_log_messages();

 done:
  if (msg)
    tor_free(msg);
  tor_free(dflt);
  tor_free(opt);
  tor_free(cl);
  return;
}

struct testcase_t options_tests[] = {
  { "validate", test_options_validate, TT_FORK, NULL, NULL },
  { "mem_dircache", test_have_enough_mem_for_dircache, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};

