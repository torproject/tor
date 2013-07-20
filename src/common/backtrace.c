/* Copyright (c) 2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include "backtrace.h"
#include "compat.h"
#include "util.h"
#include "torlog.h"

#ifdef HAVE_EXECINFO_H
#include <execinfo.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#if defined(HAVE_EXECINFO_H) && defined(HAVE_BACKTRACE) && \
  defined(HAVE_BACKTRACE_SYMBOLS_FD) && defined(HAVE_SIGACTION)
#define USE_BACKTRACE
#endif

#if !defined(USE_BACKTRACE)
#define NO_BACKTRACE_IMPL
#endif

static char *bt_version = NULL;

#ifdef USE_BACKTRACE
#define MAX_DEPTH 256
static void *cb_buf[MAX_DEPTH];

/**DOCDOC*/
void
dump_backtrace(const char *msg)
{
  int depth;
  const int *fds;
  int n_fds;
  int i;

  if (!msg) msg = "unspecified crash";

  depth = backtrace(cb_buf, MAX_DEPTH);

  tor_log_err_sigsafe(bt_version, " died: ", msg, "\n",
                      NULL);
  n_fds = tor_log_get_sigsafe_err_fds(&fds);
  for (i=0; i < n_fds; ++i)
    backtrace_symbols_fd(cb_buf, depth, fds[i]);
}

/**DOCDOC*/
static int
install_bt_handler(void)
{
  /*XXXX add signal handlers */
  /*XXXX make this idempotent */
  return 0;
}
/**DOCDOC*/
static void
remove_bt_handler(void)
{
}
#endif

#ifdef NO_BACKTRACE_IMPL
/**DOCDOC*/
void
dump_backtrace(const char *msg)
{
  tor_log_err_sigsafe(bt_version, " died: ", msg, "\n", NULL);
}

/**DOCDOC*/
static int
install_bt_handler(void)
{
  return 0;
}

/**DOCDOC*/
static void
remove_bt_handler(void)
{
}
#endif

/**DOCDOC*/
int
configure_backtrace_handler(const char *tor_version)
{
  tor_free(bt_version);
  if (!tor_version)
    tor_version = "Tor";
  bt_version = tor_strdup(tor_version);

  return install_bt_handler();
}

/**DOCDOC*/
void
clean_up_backtrace_handler(void)
{
  remove_bt_handler();

  tor_free(bt_version);
}

