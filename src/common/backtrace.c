/* Copyright (c) 2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include "backtrace.h"
#include "compat.h"
#include "util.h"

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

static char *bt_filename = NULL;
static char *bt_version = NULL;

#ifndef NO_BACKTRACE_IMPL
/**DOCDOC*/
static int
open_bt_target(void)
{
  int fd = -1;
  if (bt_filename)
    fd = open(bt_filename, O_WRONLY|O_CREAT|O_APPEND, 0700);
  return fd;
}
#endif

/**DOCDOC*/
static void
bt_write(int fd, const char *s, ssize_t n)
{
  int r;
  if (n < 0) n = strlen(s);

  r = write(STDERR_FILENO, s, n);
  if (fd >= 0)
    r = write(fd, s, n);
  (void)r; 
}

#ifdef USE_BACKTRACE
#define MAX_DEPTH 256
static void *cb_buf[MAX_DEPTH];

/**DOCDOC*/
void
dump_backtrace(const char *msg)
{
  char timebuf[32];
  time_t t = time(NULL);
  int timebuf_len;
  int depth;
  int fd;
  if (!msg) msg = "unspecified crash";

  depth = backtrace(cb_buf, MAX_DEPTH);

  t /= 900; t *= 900; /* Round to the previous 15 minutes */
  timebuf[0] = '\0';
  timebuf_len = format_dec_number_sigsafe(t, timebuf, sizeof(timebuf));

  fd = open_bt_target();
  bt_write(fd, "========================================"
               "====================================\n", -1);
  bt_write(fd, bt_version, -1);
  bt_write(fd, " died around T=", -1);
  bt_write(fd, timebuf, timebuf_len);
  bt_write(fd, ": ", 2);
  bt_write(fd, msg, -1);
  bt_write(fd, "\n", 1);
  backtrace_symbols_fd(cb_buf, depth, STDERR_FILENO);
  if (fd >= 0)
    backtrace_symbols_fd(cb_buf, depth, fd);

  close(fd);
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
  bt_write(-1, bt_version, -1);
  bt_write(-1, " died: ", -1);
  bt_write(-1, msg, -1);
  bt_write(-1, "\n", -1);
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
configure_backtrace_handler(const char *filename, const char *tor_version)
{
  tor_free(bt_filename);
  if (filename)
    bt_filename = tor_strdup(filename);
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

  tor_free(bt_filename);
  tor_free(bt_version);
}

