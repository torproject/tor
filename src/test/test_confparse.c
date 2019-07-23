/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/*
 * Tests for confparse.c module that we use to parse various
 * configuration/state file types.
 */

#define CONFPARSE_PRIVATE
#include "orconfig.h"

#include "core/or/or.h"
#include "lib/encoding/confline.h"
#include "feature/nodelist/routerset.h"
#include "app/config/confparse.h"
#include "test/test.h"
#include "test/log_test_helpers.h"

#include "lib/confmgt/unitparse.h"

typedef struct test_struct_t {
  uint32_t magic;
  char *s;
  char *fn;
  int pos;
  int i;
  int deprecated_int;
  uint64_t u64;
  int interval;
  int msec_interval;
  uint64_t mem;
  double dbl;
  int boolean;
  int autobool;
  time_t time;
  smartlist_t *csv;
  int csv_interval;
  config_line_t *lines;
  config_line_t *mixed_lines;
  routerset_t *routerset;
  int hidden_int;
  config_line_t *mixed_hidden_lines;

  config_line_t *extra_lines;
} test_struct_t;

static test_struct_t test_struct_t_dummy;

#define VAR(name,conftype,member,initvalue)                             \
  { name, CONFIG_TYPE_##conftype, offsetof(test_struct_t, member),      \
      initvalue CONF_TEST_MEMBERS(test_struct_t, conftype, member) }

#define V(name,conftype,initvalue)                                      \
  VAR( #name, conftype, name, initvalue )

#define OBSOLETE(name)                          \
  { name, CONFIG_TYPE_OBSOLETE, 0, NULL, {.INT=NULL} }

static config_var_t test_vars[] = {
  V(s, STRING, "hello"),
  V(fn, FILENAME, NULL),
  V(pos, POSINT, NULL),
  V(i, INT, "-10"),
  V(deprecated_int, INT, "3"),
  V(u64, UINT64, NULL),
  V(interval, INTERVAL, "10 seconds"),
  V(msec_interval, MSEC_INTERVAL, "150 msec"),
  V(mem, MEMUNIT, "10 MB"),
  V(dbl, DOUBLE, NULL),
  V(boolean, BOOL, "0"),
  V(autobool, AUTOBOOL, "auto"),
  V(time, ISOTIME, NULL),
  V(csv, CSV, NULL),
  V(csv_interval, CSV_INTERVAL, "5 seconds"),
  V(lines, LINELIST, NULL),
  VAR("MixedLines", LINELIST_V, mixed_lines, NULL),
  VAR("LineTypeA", LINELIST_S, mixed_lines, NULL),
  VAR("LineTypeB", LINELIST_S, mixed_lines, NULL),
  OBSOLETE("obsolete"),
  V(routerset, ROUTERSET, NULL),
  VAR("__HiddenInt", POSINT, hidden_int, "0"),
  VAR("MixedHiddenLines", LINELIST_V, mixed_hidden_lines, NULL),
  VAR("__HiddenLineA", LINELIST_S, mixed_hidden_lines, NULL),
  VAR("VisibleLineB", LINELIST_S, mixed_hidden_lines, NULL),

  END_OF_CONFIG_VARS,
};

static config_abbrev_t test_abbrevs[] = {
  { "uint", "pos", 0, 0 },
  { "float", "dbl", 0, 1 },
  { NULL, NULL, 0, 0 }
};

static config_deprecation_t test_deprecation_notes[] = {
  { "deprecated_int", "This integer is deprecated." },
  { NULL, NULL }
};

static int
test_validate_cb(void *old_options, void *options, void *default_options,
                 int from_setconf, char **msg)
{
  (void)old_options;
  (void)default_options;
  (void)from_setconf;
  (void)msg;
  test_struct_t *ts = options;

  if (ts->i == 0xbad) {
    *msg = tor_strdup("bad value for i");
    return -1;
  }
  return 0;
}

static void test_free_cb(void *options);

#define TEST_MAGIC 0x1337

static config_format_t test_fmt = {
  sizeof(test_struct_t),
  TEST_MAGIC,
  offsetof(test_struct_t, magic),
  test_abbrevs,
  test_deprecation_notes,
  test_vars,
  test_validate_cb,
  test_free_cb,
  NULL,
};

static void
test_free_cb(void *options)
{
  if (!options)
    return;

  config_free(&test_fmt, options);
}

/* Make sure that config_init sets everything to the right defaults. */
static void
test_confparse_init(void *arg)
{
  (void)arg;
  test_struct_t *tst = config_new(&test_fmt);
  config_init(&test_fmt, tst);

  // Make sure that options are initialized right. */
  tt_uint_op(tst->magic, OP_EQ, TEST_MAGIC);
  tt_str_op(tst->s, OP_EQ, "hello");
  tt_ptr_op(tst->fn, OP_EQ, NULL);
  tt_int_op(tst->pos, OP_EQ, 0);
  tt_int_op(tst->i, OP_EQ, -10);
  tt_int_op(tst->deprecated_int, OP_EQ, 3);
  tt_u64_op(tst->u64, OP_EQ, 0);
  tt_int_op(tst->interval, OP_EQ, 10);
  tt_int_op(tst->msec_interval, OP_EQ, 150);
  tt_u64_op(tst->mem, OP_EQ, 10 * 1024 * 1024);
  tt_double_op(tst->dbl, OP_LT, .0000000001);
  tt_double_op(tst->dbl, OP_GT, -0.0000000001);
  tt_int_op(tst->boolean, OP_EQ, 0);
  tt_int_op(tst->autobool, OP_EQ, -1);
  tt_i64_op(tst->time, OP_EQ, 0);
  tt_ptr_op(tst->csv, OP_EQ, NULL);
  tt_int_op(tst->csv_interval, OP_EQ, 5);
  tt_ptr_op(tst->lines, OP_EQ, NULL);
  tt_ptr_op(tst->mixed_lines, OP_EQ, NULL);
  tt_int_op(tst->hidden_int, OP_EQ, 0);

 done:
  config_free(&test_fmt, tst);
}

static const char simple_settings[] =
      "s this is a \n"
      "fn /simple/test of the\n"
      "uint 77\n" // this is an abbrev
      "i 3\n"
      "u64   1000000000000  \n"
      "interval 5 minutes \n"
      "msec_interval 5 minutes \n"
      "mem 10\n"
      "dbl 6.060842\n"
      "BOOLEAN 1\n"
      "aUtObOOl 0\n"
      "time 2019-06-14 13:58:51\n"
      "csv configuration, parsing  , system  \n"
      "csv_interval 10 seconds, 5 seconds, 10 hours\n"
      "lines hello\n"
      "LINES world\n"
      "linetypea i d\n"
      "linetypeb i c\n"
      "routerset $FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\n"
      "__hiddenint 11\n"
      "__hiddenlineA XYZ\n"
      "visiblelineB ABC\n";

/* Return a configuration object set up from simple_settings above. */
static test_struct_t *
get_simple_config(void)
{
  test_struct_t *result = NULL;
  test_struct_t *tst = config_new(&test_fmt);
  config_line_t *lines = NULL;
  char *msg = NULL;

  config_init(&test_fmt, tst);

  int r = config_get_lines(simple_settings, &lines, 0);
  tt_int_op(r, OP_EQ, 0);
  r = config_assign(&test_fmt, tst, lines, 0, &msg);
  tt_int_op(r, OP_EQ, 0);
  tt_ptr_op(msg, OP_EQ, NULL);

  result = tst;
  tst = NULL; // prevent free
 done:
  tor_free(msg);
  config_free_lines(lines);
  config_free(&test_fmt, tst);
  return result;
}

/* Make sure that config_assign can parse things. */
static void
test_confparse_assign_simple(void *arg)
{
  (void)arg;
  test_struct_t *tst = get_simple_config();

  tt_str_op(tst->s, OP_EQ, "this is a");
  tt_str_op(tst->fn, OP_EQ, "/simple/test of the");
  tt_int_op(tst->pos, OP_EQ, 77);
  tt_int_op(tst->i, OP_EQ, 3);
  tt_int_op(tst->deprecated_int, OP_EQ, 3);
  tt_u64_op(tst->u64, OP_EQ, UINT64_C(1000000000000));
  tt_int_op(tst->interval, OP_EQ, 5 * 60);
  tt_int_op(tst->msec_interval, OP_EQ, 5 * 60 * 1000);
  tt_u64_op(tst->mem, OP_EQ, 10);
  tt_double_op(tst->dbl, OP_LT, 6.060843);
  tt_double_op(tst->dbl, OP_GT, 6.060841);
  tt_int_op(tst->boolean, OP_EQ, 1);
  tt_int_op(tst->autobool, OP_EQ, 0);
  tt_i64_op(tst->time, OP_EQ, 1560520731);
  tt_ptr_op(tst->csv, OP_NE, NULL);
  tt_int_op(smartlist_len(tst->csv), OP_EQ, 3);
  tt_str_op(smartlist_get(tst->csv, 0), OP_EQ, "configuration");
  tt_str_op(smartlist_get(tst->csv, 1), OP_EQ, "parsing");
  tt_str_op(smartlist_get(tst->csv, 2), OP_EQ, "system");
  tt_int_op(tst->csv_interval, OP_EQ, 10);
  tt_int_op(tst->hidden_int, OP_EQ, 11);

  tt_assert(tst->lines);
  tt_str_op(tst->lines->key, OP_EQ, "lines");
  tt_str_op(tst->lines->value, OP_EQ, "hello");
  tt_assert(tst->lines->next);
  tt_str_op(tst->lines->next->key, OP_EQ, "lines");
  tt_str_op(tst->lines->next->value, OP_EQ, "world");
  tt_assert(!tst->lines->next->next);

  tt_assert(tst->mixed_lines);
  tt_str_op(tst->mixed_lines->key, OP_EQ, "LineTypeA");
  tt_str_op(tst->mixed_lines->value, OP_EQ, "i d");
  tt_assert(tst->mixed_lines->next);
  tt_str_op(tst->mixed_lines->next->key, OP_EQ, "LineTypeB");
  tt_str_op(tst->mixed_lines->next->value, OP_EQ, "i c");
  tt_assert(!tst->mixed_lines->next->next);

  tt_assert(tst->mixed_hidden_lines);
  tt_str_op(tst->mixed_hidden_lines->key, OP_EQ, "__HiddenLineA");
  tt_str_op(tst->mixed_hidden_lines->value, OP_EQ, "XYZ");
  tt_assert(tst->mixed_hidden_lines->next);
  tt_str_op(tst->mixed_hidden_lines->next->key, OP_EQ, "VisibleLineB");
  tt_str_op(tst->mixed_hidden_lines->next->value, OP_EQ, "ABC");
  tt_assert(!tst->mixed_hidden_lines->next->next);

 done:
  config_free(&test_fmt, tst);
}

/* Try to assign to an obsolete option, and make sure we get a warning. */
static void
test_confparse_assign_obsolete(void *arg)
{
  (void)arg;
  test_struct_t *tst = config_new(&test_fmt);
  config_line_t *lines = NULL;
  char *msg = NULL;

  config_init(&test_fmt, tst);

  int r = config_get_lines("obsolete option here",
                           &lines, 0);
  tt_int_op(r, OP_EQ, 0);
  setup_capture_of_logs(LOG_WARN);
  r = config_assign(&test_fmt, tst, lines, 0, &msg);
  tt_int_op(r, OP_EQ, 0);
  tt_ptr_op(msg, OP_EQ, NULL);
  expect_single_log_msg_containing("Skipping obsolete configuration option");

 done:
  teardown_capture_of_logs();
  config_free(&test_fmt, tst);
  config_free_lines(lines);
  tor_free(msg);
}

/* Try to assign to an deprecated option, and make sure we get a warning
 * but the assignment works anyway. */
static void
test_confparse_assign_deprecated(void *arg)
{
  (void)arg;
  test_struct_t *tst = config_new(&test_fmt);
  config_line_t *lines = NULL;
  char *msg = NULL;

  config_init(&test_fmt, tst);

  int r = config_get_lines("deprecated_int 7",
                           &lines, 0);
  tt_int_op(r, OP_EQ, 0);
  setup_capture_of_logs(LOG_WARN);
  r = config_assign(&test_fmt, tst, lines, CAL_WARN_DEPRECATIONS, &msg);
  tt_int_op(r, OP_EQ, 0);
  tt_ptr_op(msg, OP_EQ, NULL);
  expect_single_log_msg_containing("This integer is deprecated.");

  tt_int_op(tst->deprecated_int, OP_EQ, 7);

 done:
  teardown_capture_of_logs();
  config_free(&test_fmt, tst);
  config_free_lines(lines);
  tor_free(msg);
}

/* Try to re-assign an option name that has been depreacted in favor of
 * another. */
static void
test_confparse_assign_replaced(void *arg)
{
  (void)arg;
  test_struct_t *tst = config_new(&test_fmt);
  config_line_t *lines = NULL;
  char *msg = NULL;

  config_init(&test_fmt, tst);

  int r = config_get_lines("float 1000\n", &lines, 0);
  tt_int_op(r, OP_EQ, 0);
  setup_capture_of_logs(LOG_WARN);
  r = config_assign(&test_fmt, tst, lines, CAL_WARN_DEPRECATIONS, &msg);
  tt_int_op(r, OP_EQ, 0);
  tt_ptr_op(msg, OP_EQ, NULL);
  expect_single_log_msg_containing("use 'dbl' instead.");

  tt_double_op(tst->dbl, OP_GT, 999.999);
  tt_double_op(tst->dbl, OP_LT, 1000.001);

 done:
  teardown_capture_of_logs();
  config_free(&test_fmt, tst);
  config_free_lines(lines);
  tor_free(msg);
}

/* Try to set a linelist value with no option. */
static void
test_confparse_assign_emptystring(void *arg)
{
  (void)arg;
  test_struct_t *tst = config_new(&test_fmt);
  config_line_t *lines = NULL;
  char *msg = NULL;

  config_init(&test_fmt, tst);

  int r = config_get_lines("lines\n", &lines, 0);
  tt_int_op(r, OP_EQ, 0);
  setup_capture_of_logs(LOG_WARN);
  r = config_assign(&test_fmt, tst, lines, 0, &msg);
  tt_int_op(r, OP_EQ, 0);
  tt_ptr_op(msg, OP_EQ, NULL);
  expect_single_log_msg_containing("has no value");

 done:
  teardown_capture_of_logs();
  config_free(&test_fmt, tst);
  config_free_lines(lines);
  tor_free(msg);
}

/* Try to set a the same option twice; make sure we get a warning. */
static void
test_confparse_assign_twice(void *arg)
{
  (void)arg;
  test_struct_t *tst = config_new(&test_fmt);
  config_line_t *lines = NULL;
  char *msg = NULL;

  config_init(&test_fmt, tst);

  int r = config_get_lines("pos 10\n"
                           "pos 99\n", &lines, 0);
  tt_int_op(r, OP_EQ, 0);
  setup_capture_of_logs(LOG_WARN);
  r = config_assign(&test_fmt, tst, lines, 0, &msg);
  tt_int_op(r, OP_EQ, 0);
  tt_ptr_op(msg, OP_EQ, NULL);
  expect_single_log_msg_containing("used more than once");

 done:
  teardown_capture_of_logs();
  config_free(&test_fmt, tst);
  config_free_lines(lines);
  tor_free(msg);
}

typedef struct badval_test_t {
  const char *cfg;
  const char *expect_msg;
} badval_test_t;

/* Try to set an option and make sure that we get a failure and an expected
 * warning. */
static void
test_confparse_assign_badval(void *arg)
{
  const badval_test_t *bt = arg;
  test_struct_t *tst = config_new(&test_fmt);
  config_line_t *lines = NULL;
  char *msg = NULL;

  config_init(&test_fmt, tst);

  int r = config_get_lines(bt->cfg, &lines, 0);
  tt_int_op(r, OP_EQ, 0);
  setup_capture_of_logs(LOG_WARN);
  r = config_assign(&test_fmt, tst, lines, 0, &msg);
  tt_int_op(r, OP_LT, 0);
  tt_ptr_op(msg, OP_NE, NULL);
  if (! strstr(msg, bt->expect_msg)) {
    TT_DIE(("'%s' did not contain '%s'" , msg, bt->expect_msg));
  }

 done:
  teardown_capture_of_logs();
  config_free(&test_fmt, tst);
  config_free_lines(lines);
  tor_free(msg);
}

/* Various arguments for badval test.
 *
 * Note that the expected warnings here are _very_ truncated, since we
 * are writing these tests before a refactoring that we expect will
 * change them.
 */
static const badval_test_t bv_notint = { "pos X\n", "malformed" };
static const badval_test_t bv_negint = { "pos -10\n", "out of bounds" };
static const badval_test_t bv_badu64 = { "u64 u64\n", "malformed" };
static const badval_test_t bv_badcsvi1 =
  { "csv_interval 10 wl\n", "malformed" };
static const badval_test_t bv_badcsvi2 =
  { "csv_interval cl,10\n", "malformed" };
static const badval_test_t bv_nonoption = { "fnord 10\n", "Unknown option" };
static const badval_test_t bv_badmem = { "mem 3 trits\n", "malformed" };
static const badval_test_t bv_badbool = { "boolean 7\n", "Unrecognized value"};
static const badval_test_t bv_badabool =
  { "autobool 7\n", "Unrecognized value" };
static const badval_test_t bv_badtime = { "time lunchtime\n", "Invalid time" };
static const badval_test_t bv_virt = { "MixedLines 7\n", "virtual option" };
static const badval_test_t bv_rs = { "Routerset 2.2.2.2.2\n", "Invalid" };

/* Try config_dump(), and make sure it behaves correctly */
static void
test_confparse_dump(void *arg)
{
  (void)arg;
  test_struct_t *tst = get_simple_config();
  char *dumped = NULL;

  /* Minimal version. */
  dumped = config_dump(&test_fmt, NULL, tst, 1, 0);
  tt_str_op(dumped, OP_EQ,
            "s this is a\n"
            "fn /simple/test of the\n"
            "pos 77\n"
            "i 3\n"
            "u64 1000000000000\n"
            "interval 300\n"
            "msec_interval 300000\n"
            "mem 10\n"
            "dbl 6.060842\n"
            "boolean 1\n"
            "autobool 0\n"
            "time 2019-06-14 13:58:51\n"
            "csv configuration,parsing,system\n"
            "csv_interval 10\n"
            "lines hello\n"
            "lines world\n"
            "LineTypeA i d\n"
            "LineTypeB i c\n"
            "routerset $FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\n"
            "VisibleLineB ABC\n");

  /* Maximal */
  tor_free(dumped);
  dumped = config_dump(&test_fmt, NULL, tst, 0, 0);
  tt_str_op(dumped, OP_EQ,
            "s this is a\n"
            "fn /simple/test of the\n"
            "pos 77\n"
            "i 3\n"
            "deprecated_int 3\n"
            "u64 1000000000000\n"
            "interval 300\n"
            "msec_interval 300000\n"
            "mem 10\n"
            "dbl 6.060842\n"
            "boolean 1\n"
            "autobool 0\n"
            "time 2019-06-14 13:58:51\n"
            "csv configuration,parsing,system\n"
            "csv_interval 10\n"
            "lines hello\n"
            "lines world\n"
            "LineTypeA i d\n"
            "LineTypeB i c\n"
            "routerset $FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\n"
            "VisibleLineB ABC\n");

  /* commented */
  tor_free(dumped);
  dumped = config_dump(&test_fmt, NULL, tst, 0, 1);
  tt_str_op(dumped, OP_EQ,
            "s this is a\n"
            "fn /simple/test of the\n"
            "pos 77\n"
            "i 3\n"
            "# deprecated_int 3\n"
            "u64 1000000000000\n"
            "interval 300\n"
            "msec_interval 300000\n"
            "mem 10\n"
            "dbl 6.060842\n"
            "boolean 1\n"
            "autobool 0\n"
            "time 2019-06-14 13:58:51\n"
            "csv configuration,parsing,system\n"
            "csv_interval 10\n"
            "lines hello\n"
            "lines world\n"
            "LineTypeA i d\n"
            "LineTypeB i c\n"
            "routerset $FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\n"
                        "VisibleLineB ABC\n");

 done:
  config_free(&test_fmt, tst);
  tor_free(dumped);
}

/* Try confparse_reset_line(), and make sure it behaves correctly */
static void
test_confparse_reset(void *arg)
{
  (void)arg;
  test_struct_t *tst = get_simple_config();

  config_reset_line(&test_fmt, tst, "interval", 0);
  tt_int_op(tst->interval, OP_EQ, 0);

  config_reset_line(&test_fmt, tst, "interval", 1);
  tt_int_op(tst->interval, OP_EQ, 10);

 done:
  config_free(&test_fmt, tst);
}

/* Try setting options a second time on a config object, and make sure
 * it behaves correctly. */
static void
test_confparse_reassign(void *arg)
{
  (void)arg;
  test_struct_t *tst = get_simple_config();
  config_line_t *lines = NULL;
  char *msg = NULL, *rs = NULL;

  int r = config_get_lines(
         "s eleven\n"
         "i 12\n"
         "lines 13\n"
         "csv 14,15\n"
         "routerset 127.0.0.1\n",
         &lines, 0);
  r = config_assign(&test_fmt, tst,lines, 0, &msg);
  tt_int_op(r, OP_EQ, 0);
  tt_ptr_op(msg, OP_EQ, NULL);

  tt_str_op(tst->s, OP_EQ, "eleven");
  tt_str_op(tst->fn, OP_EQ, "/simple/test of the"); // unchanged
  tt_int_op(tst->pos, OP_EQ, 77); // unchanged
  tt_int_op(tst->i, OP_EQ, 12);
  tt_ptr_op(tst->lines, OP_NE, NULL);
  tt_str_op(tst->lines->key, OP_EQ, "lines");
  tt_str_op(tst->lines->value, OP_EQ, "13");
  tt_ptr_op(tst->lines->next, OP_EQ, NULL);
  tt_int_op(smartlist_len(tst->csv), OP_EQ, 2);
  tt_str_op(smartlist_get(tst->csv, 0), OP_EQ, "14");
  tt_str_op(smartlist_get(tst->csv, 1), OP_EQ, "15");

  rs = routerset_to_string(tst->routerset);
  tt_str_op(rs, OP_EQ, "127.0.0.1");

  // Try again with the CLEAR_FIRST and USE_DEFAULTS flags
  r = config_assign(&test_fmt, tst, lines,
                    CAL_CLEAR_FIRST|CAL_USE_DEFAULTS, &msg);
  tt_int_op(r, OP_EQ, 0);

  tt_ptr_op(msg, OP_EQ, NULL);
  tt_str_op(tst->s, OP_EQ, "eleven");
  // tt_ptr_op(tst->fn, OP_EQ, NULL); //XXXX why is this not cleared?
  // tt_int_op(tst->pos, OP_EQ, 0); //XXXX why is this not cleared?
  tt_int_op(tst->i, OP_EQ, 12);

 done:
  config_free(&test_fmt, tst);
  config_free_lines(lines);
  tor_free(msg);
  tor_free(rs);
}

/* Try setting options a second time on a config object, using the +foo
 * linelist-extending syntax. */
static void
test_confparse_reassign_extend(void *arg)
{
  (void)arg;
  test_struct_t *tst = get_simple_config();
  config_line_t *lines = NULL;
  char *msg = NULL;

  int r = config_get_lines(
         "+lines 13\n",
         &lines, 1); // allow extended format.
  tt_int_op(r, OP_EQ, 0);
  r = config_assign(&test_fmt, tst,lines, 0, &msg);
  tt_int_op(r, OP_EQ, 0);
  tt_ptr_op(msg, OP_EQ, NULL);

  tt_assert(tst->lines);
  tt_str_op(tst->lines->key, OP_EQ, "lines");
  tt_str_op(tst->lines->value, OP_EQ, "hello");
  tt_assert(tst->lines->next);
  tt_str_op(tst->lines->next->key, OP_EQ, "lines");
  tt_str_op(tst->lines->next->value, OP_EQ, "world");
  tt_assert(tst->lines->next->next);
  tt_str_op(tst->lines->next->next->key, OP_EQ, "lines");
  tt_str_op(tst->lines->next->next->value, OP_EQ, "13");
  tt_assert(tst->lines->next->next->next == NULL);
  config_free_lines(lines);

  r = config_get_lines(
         "/lines\n",
         &lines, 1); // allow extended format.
  tt_int_op(r, OP_EQ, 0);
  r = config_assign(&test_fmt, tst, lines, 0, &msg);
  tt_int_op(r, OP_EQ, 0);
  tt_ptr_op(msg, OP_EQ, NULL);
  tt_assert(tst->lines == NULL);
  config_free_lines(lines);

  config_free(&test_fmt, tst);
  tst = get_simple_config();
  r = config_get_lines(
         "/lines away!\n",
         &lines, 1); // allow extended format.
  tt_int_op(r, OP_EQ, 0);
  r = config_assign(&test_fmt, tst, lines, 0, &msg);
  tt_int_op(r, OP_EQ, 0);
  tt_ptr_op(msg, OP_EQ, NULL);
  tt_assert(tst->lines == NULL);

 done:
  config_free(&test_fmt, tst);
  config_free_lines(lines);
  tor_free(msg);
}

/* Test out confparse_get_assigned(). */
static void
test_confparse_get_assigned(void *arg)
{
  (void)arg;
  test_struct_t *tst = get_simple_config();
  config_line_t *lines = NULL;

  lines = config_get_assigned_option(&test_fmt, tst, "I", 1);
  tt_assert(lines);
  tt_str_op(lines->key, OP_EQ, "i");
  tt_str_op(lines->value, OP_EQ, "3");
  tt_assert(lines->next == NULL);
  config_free_lines(lines);

  lines = config_get_assigned_option(&test_fmt, tst, "s", 1);
  tt_assert(lines);
  tt_str_op(lines->key, OP_EQ, "s");
  tt_str_op(lines->value, OP_EQ, "this is a");
  tt_assert(lines->next == NULL);
  config_free_lines(lines);

  lines = config_get_assigned_option(&test_fmt, tst, "obsolete", 1);
  tt_assert(!lines);

  lines = config_get_assigned_option(&test_fmt, tst, "nonesuch", 1);
  tt_assert(!lines);

  lines = config_get_assigned_option(&test_fmt, tst, "mixedlines", 1);
  tt_assert(lines);
  tt_str_op(lines->key, OP_EQ, "LineTypeA");
  tt_str_op(lines->value, OP_EQ, "i d");
  tt_assert(lines->next);
  tt_str_op(lines->next->key, OP_EQ, "LineTypeB");
  tt_str_op(lines->next->value, OP_EQ, "i c");
  tt_assert(lines->next->next == NULL);
  config_free_lines(lines);

  lines = config_get_assigned_option(&test_fmt, tst, "linetypeb", 1);
  tt_assert(lines);
  tt_str_op(lines->key, OP_EQ, "LineTypeB");
  tt_str_op(lines->value, OP_EQ, "i c");
  tt_assert(lines->next == NULL);
  config_free_lines(lines);

  tor_free(tst->s);
  tst->s = tor_strdup("Hello\nWorld");
  lines = config_get_assigned_option(&test_fmt, tst, "s", 1);
  tt_assert(lines);
  tt_str_op(lines->key, OP_EQ, "s");
  tt_str_op(lines->value, OP_EQ, "\"Hello\\nWorld\"");
  tt_assert(lines->next == NULL);
  config_free_lines(lines);

 done:
  config_free(&test_fmt, tst);
  config_free_lines(lines);
}

/* Another variant, which accepts and stores unrecognized lines.*/
#define ETEST_MAGIC 13371337

static config_var_t extra = VAR("__extra", LINELIST, extra_lines, NULL);

static config_format_t etest_fmt = {
  sizeof(test_struct_t),
  ETEST_MAGIC,
  offsetof(test_struct_t, magic),
  test_abbrevs,
  test_deprecation_notes,
  test_vars,
  test_validate_cb,
  test_free_cb,
  &extra,
};

/* Try out the feature where we can store unrecognized lines and dump them
 * again.  (State files use this.) */
static void
test_confparse_extra_lines(void *arg)
{
  (void)arg;
  test_struct_t *tst = config_new(&etest_fmt);
  config_line_t *lines = NULL;
  char *msg = NULL, *dump = NULL;

  config_init(&etest_fmt, tst);

  int r = config_get_lines(
      "unknotty addita\n"
      "pos 99\n"
      "wombat knish\n", &lines, 0);
  tt_int_op(r, OP_EQ, 0);
  r = config_assign(&etest_fmt, tst, lines, 0, &msg);
  tt_int_op(r, OP_EQ, 0);
  tt_ptr_op(msg, OP_EQ, NULL);

  tt_assert(tst->extra_lines);

  dump = config_dump(&etest_fmt, NULL, tst, 1, 0);
  tt_str_op(dump, OP_EQ,
      "pos 99\n"
      "unknotty addita\n"
      "wombat knish\n");

 done:
  tor_free(msg);
  tor_free(dump);
  config_free_lines(lines);
  config_free(&etest_fmt, tst);
}

static void
test_confparse_unitparse(void *args)
{
  (void)args;
  /* spot-check a few memunit values. */
  int ok = 3;
  tt_u64_op(config_parse_memunit("100 MB", &ok), OP_EQ, 100<<20);
  tt_assert(ok);
  tt_u64_op(config_parse_memunit("100 TB", &ok), OP_EQ, UINT64_C(100)<<40);
  tt_assert(ok);
  // This is a floating-point value, but note that 1.5 can be represented
  // precisely.
  tt_u64_op(config_parse_memunit("1.5 MB", &ok), OP_EQ, 3<<19);
  tt_assert(ok);

  /* Try some good intervals and msec intervals */
  tt_int_op(config_parse_interval("2 days", &ok), OP_EQ, 48*3600);
  tt_assert(ok);
  tt_int_op(config_parse_interval("1.5 hour", &ok), OP_EQ, 5400);
  tt_assert(ok);
  tt_u64_op(config_parse_interval("1 minute", &ok), OP_EQ, 60);
  tt_assert(ok);
  tt_int_op(config_parse_msec_interval("2 days", &ok), OP_EQ, 48*3600*1000);
  tt_assert(ok);
  tt_int_op(config_parse_msec_interval("10 msec", &ok), OP_EQ, 10);
  tt_assert(ok);

  /* Try a couple of unitless values. */
  tt_int_op(config_parse_interval("10", &ok), OP_EQ, 10);
  tt_assert(ok);
  tt_u64_op(config_parse_interval("15.0", &ok), OP_EQ, 15);
  tt_assert(ok);

  /* u64 overflow */
  /* XXXX our implementation does not currently detect this. See bug 30920. */
  /*
  tt_u64_op(config_parse_memunit("20000000 TB", &ok), OP_EQ, 0);
  tt_assert(!ok);
  */

  /* i32 overflow */
  tt_int_op(config_parse_interval("1000 months", &ok), OP_EQ, -1);
  tt_assert(!ok);
  tt_int_op(config_parse_msec_interval("4 weeks", &ok), OP_EQ, -1);
  tt_assert(!ok);

  /* bad units */
  tt_u64_op(config_parse_memunit("7 nybbles", &ok), OP_EQ, 0);
  tt_assert(!ok);
  // XXXX these next two should return -1 according to the documentation.
  tt_int_op(config_parse_interval("7 cowznofski", &ok), OP_EQ, 0);
  tt_assert(!ok);
  tt_int_op(config_parse_msec_interval("1 kalpa", &ok), OP_EQ, 0);
  tt_assert(!ok);

 done:
  ;
}

#define CONFPARSE_TEST(name, flags)                          \
  { #name, test_confparse_ ## name, flags, NULL, NULL }

#define BADVAL_TEST(name)                               \
  { "badval_" #name, test_confparse_assign_badval, 0,   \
      &passthrough_setup, (void*)&bv_ ## name }

struct testcase_t confparse_tests[] = {
  CONFPARSE_TEST(init, 0),
  CONFPARSE_TEST(assign_simple, 0),
  CONFPARSE_TEST(assign_obsolete, 0),
  CONFPARSE_TEST(assign_deprecated, 0),
  CONFPARSE_TEST(assign_replaced, 0),
  CONFPARSE_TEST(assign_emptystring, 0),
  CONFPARSE_TEST(assign_twice, 0),
  BADVAL_TEST(notint),
  BADVAL_TEST(negint),
  BADVAL_TEST(badu64),
  BADVAL_TEST(badcsvi1),
  BADVAL_TEST(badcsvi2),
  BADVAL_TEST(nonoption),
  BADVAL_TEST(badmem),
  BADVAL_TEST(badbool),
  BADVAL_TEST(badabool),
  BADVAL_TEST(badtime),
  BADVAL_TEST(virt),
  BADVAL_TEST(rs),
  CONFPARSE_TEST(dump, 0),
  CONFPARSE_TEST(reset, 0),
  CONFPARSE_TEST(reassign, 0),
  CONFPARSE_TEST(reassign_extend, 0),
  CONFPARSE_TEST(get_assigned, 0),
  CONFPARSE_TEST(extra_lines, 0),
  CONFPARSE_TEST(unitparse, 0),
  END_OF_TESTCASES
};
