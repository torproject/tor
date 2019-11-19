/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define CONFIG_PRIVATE
#include "core/or/or.h"
#include "app/config/config.h"

#include "test/test.h"
#include "test/log_test_helpers.h"
#include "test/test_helpers.h"

#ifndef _WIN32
#include <sys/stat.h>

/**
 * Check whether fname is readable. On success set
 * *<b>is_group_readable_out</b> to as appropriate and return 0. On failure
 * return -1.
 */
static int
get_file_mode(const char *fname, unsigned *permissions_out)
{
  struct stat st;
  int r = stat(fname, &st);
  if (r < 0)
    return -1;
  *permissions_out = (unsigned) st.st_mode;
  return 0;
}
#define assert_mode(fn,mask,expected) STMT_BEGIN                 \
  unsigned mode_;                                                \
  int tmp_ = get_file_mode((fn), &mode_);                        \
  if (tmp_ < 0) {                                                \
    TT_DIE(("Couldn't stat %s: %s", (fn), strerror(errno)));     \
  }                                                              \
  if ((mode_ & (mask)) != (expected)) {                          \
    TT_DIE(("Bad mode %o on %s", mode_, (fn)));                  \
  }                                                              \
  STMT_END
#else
/* "group-readable" isn't meaningful on windows */
#define assert_mode(fn,mask,expected) STMT_NIL
#endif

static or_options_t *mock_opts;
static const or_options_t *
mock_get_options(void)
{
  return mock_opts;
}

static void
test_options_act_create_dirs(void *arg)
{
  (void)arg;
  MOCK(get_options, mock_get_options);
  char *msg = NULL;
  or_options_t *opts = mock_opts = options_new();

  /* We're testing options_create_directories(), which assumes that
     validate_data_directories() has already been called, and all of
     KeyDirectory, DataDirectory, and CacheDirectory are set. */

  /* Success case 1: all directories are the default */
  char *fn;
  fn = tor_strdup(get_fname_rnd("ddir"));
  opts->DataDirectory = tor_strdup(fn);
  opts->CacheDirectory = tor_strdup(fn);
  tor_asprintf(&opts->KeyDirectory, "%s/keys", fn);
  opts->DataDirectoryGroupReadable = 1;
  opts->CacheDirectoryGroupReadable = -1; /* default. */
  int r = options_create_directories(&msg);
  tt_int_op(r, OP_EQ, 0);
  tt_ptr_op(msg, OP_EQ, NULL);
  tt_int_op(FN_DIR, OP_EQ, file_status(opts->DataDirectory));
  tt_int_op(FN_DIR, OP_EQ, file_status(opts->CacheDirectory));
  tt_int_op(FN_DIR, OP_EQ, file_status(opts->KeyDirectory));
  assert_mode(opts->DataDirectory, 0777, 0750);
  assert_mode(opts->KeyDirectory, 0777, 0700);
  tor_free(fn);
  tor_free(opts->KeyDirectory);
  or_options_free(opts);

  /* Success case 2: all directories are different. */
  opts = mock_opts = options_new();
  opts->DataDirectory = tor_strdup(get_fname_rnd("ddir"));
  opts->CacheDirectory = tor_strdup(get_fname_rnd("cdir"));
  opts->KeyDirectory = tor_strdup(get_fname_rnd("kdir"));
  opts->CacheDirectoryGroupReadable = 1; // cache directory group readable
  r = options_create_directories(&msg);
  tt_int_op(r, OP_EQ, 0);
  tt_ptr_op(msg, OP_EQ, NULL);
  tt_int_op(FN_DIR, OP_EQ, file_status(opts->DataDirectory));
  tt_int_op(FN_DIR, OP_EQ, file_status(opts->CacheDirectory));
  tt_int_op(FN_DIR, OP_EQ, file_status(opts->KeyDirectory));
  assert_mode(opts->DataDirectory, 0777, 0700);
  assert_mode(opts->KeyDirectory, 0777, 0700);
  assert_mode(opts->CacheDirectory, 0777, 0750);
  tor_free(fn);
  or_options_free(opts);

  /* Success case 3: all directories are the same. */
  opts = mock_opts = options_new();
  fn = tor_strdup(get_fname_rnd("ddir"));
  opts->DataDirectory = tor_strdup(fn);
  opts->CacheDirectory = tor_strdup(fn);
  opts->KeyDirectory = tor_strdup(fn);
  opts->DataDirectoryGroupReadable = 1;
  opts->CacheDirectoryGroupReadable = -1; /* default. */
  opts->KeyDirectoryGroupReadable = -1; /* default */
  r = options_create_directories(&msg);
  tt_int_op(r, OP_EQ, 0);
  tt_ptr_op(msg, OP_EQ, NULL);
  tt_int_op(FN_DIR, OP_EQ, file_status(opts->DataDirectory));
  tt_int_op(FN_DIR, OP_EQ, file_status(opts->CacheDirectory));
  tt_int_op(FN_DIR, OP_EQ, file_status(opts->KeyDirectory));
  assert_mode(opts->DataDirectory, 0777, 0750);
  assert_mode(opts->KeyDirectory, 0777, 0750);
  assert_mode(opts->CacheDirectory, 0777, 0750);
  tor_free(fn);
  or_options_free(opts);

  /* Failure case 1: Can't make datadir. */
  opts = mock_opts = options_new();
  opts->DataDirectory = tor_strdup(get_fname_rnd("ddir"));
  opts->CacheDirectory = tor_strdup(get_fname_rnd("cdir"));
  opts->KeyDirectory = tor_strdup(get_fname_rnd("kdir"));
  write_str_to_file(opts->DataDirectory, "foo", 0);
  r = options_create_directories(&msg);
  tt_int_op(r, OP_LT, 0);
  tt_assert(!strcmpstart(msg, "Couldn't create private data directory"));
  or_options_free(opts);
  tor_free(msg);

  /* Failure case 2: Can't make keydir. */
  opts = mock_opts = options_new();
  opts->DataDirectory = tor_strdup(get_fname_rnd("ddir"));
  opts->CacheDirectory = tor_strdup(get_fname_rnd("cdir"));
  opts->KeyDirectory = tor_strdup(get_fname_rnd("kdir"));
  write_str_to_file(opts->KeyDirectory, "foo", 0);
  r = options_create_directories(&msg);
  tt_int_op(r, OP_LT, 0);
  tt_assert(!strcmpstart(msg, "Couldn't create private data directory"));
  or_options_free(opts);
  tor_free(msg);

  /* Failure case 3: Can't make cachedir. */
  opts = mock_opts = options_new();
  opts->DataDirectory = tor_strdup(get_fname_rnd("ddir"));
  opts->CacheDirectory = tor_strdup(get_fname_rnd("cdir"));
  opts->KeyDirectory = tor_strdup(get_fname_rnd("kdir"));
  write_str_to_file(opts->CacheDirectory, "foo", 0);
  r = options_create_directories(&msg);
  tt_int_op(r, OP_LT, 0);
  tt_assert(!strcmpstart(msg, "Couldn't create private data directory"));
  tor_free(fn);
  or_options_free(opts);
  tor_free(msg);

 done:
  UNMOCK(get_options);
  or_options_free(opts);
  mock_opts = NULL;
  tor_free(fn);
  tor_free(msg);
}

#ifndef COCCI
#define T(name) { #name, test_options_act_##name, TT_FORK, NULL, NULL }
#endif

struct testcase_t options_act_tests[] = {
  T(create_dirs),
  END_OF_TESTCASES
};
