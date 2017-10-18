/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "tor_api.h"
#include "tor_api_internal.h"

#include "orconfig.h"
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <stdlib.h>
#include <string.h>

#ifndef __GNUC__
#define __attribute__(x)
#endif

static void child(const tor_main_configuration_t *cfg)
  __attribute__((noreturn));

int
tor_run_main(const tor_main_configuration_t *cfg)
{
  pid_t pid = fork();
  if (pid == 0) {
    child(cfg);
    exit(0); /* Unreachable */
  }

  pid_t stopped_pid;
  int status = 0;
  do {
    stopped_pid = waitpid(pid, &status, 0);
  } while (stopped_pid == -1);

  /* Note: these return values are not documented.  No return value is
   * documented! */

  if (stopped_pid != pid) {
    return -99999;
  }
  if (WIFSTOPPED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    return -WTERMSIG(status);
  }

  return -999988;
}

static void
child(const tor_main_configuration_t *cfg)
{
  /* XXXX Close unused file descriptors. */

  char **args = calloc(cfg->argc+1, sizeof(char *));
  memcpy(args, cfg->argv, cfg->argc * sizeof(char *));
  args[cfg->argc] = NULL;

  int rv = execv(BINDIR "/tor", args);

  if (rv < 0) {
    exit(254);
  } else {
    abort(); /* Unreachable */
  }
}

