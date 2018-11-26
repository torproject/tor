/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file subprocess.c
 * \brief Launch and monitor other processes.
 **/

#define SUBPROCESS_PRIVATE
#include "lib/process/subprocess.h"

#include "lib/container/smartlist.h"
#include "lib/err/torerr.h"
#include "lib/log/log.h"
#include "lib/log/util_bug.h"
#include "lib/log/win32err.h"
#include "lib/malloc/malloc.h"
#include "lib/process/env.h"
#include "lib/process/waitpid.h"
#include "lib/string/compat_ctype.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#include <errno.h>
#include <string.h>

/** Format a single argument for being put on a Windows command line.
 * Returns a newly allocated string */
static char *
format_win_cmdline_argument(const char *arg)
{
  char *formatted_arg;
  char need_quotes;
  const char *c;
  int i;
  int bs_counter = 0;
  /* Backslash we can point to when one is inserted into the string */
  const char backslash = '\\';

  /* Smartlist of *char */
  smartlist_t *arg_chars;
  arg_chars = smartlist_new();

  /* Quote string if it contains whitespace or is empty */
  need_quotes = (strchr(arg, ' ') || strchr(arg, '\t') || '\0' == arg[0]);

  /* Build up smartlist of *chars */
  for (c=arg; *c != '\0'; c++) {
    if ('"' == *c) {
      /* Double up backslashes preceding a quote */
      for (i=0; i<(bs_counter*2); i++)
        smartlist_add(arg_chars, (void*)&backslash);
      bs_counter = 0;
      /* Escape the quote */
      smartlist_add(arg_chars, (void*)&backslash);
      smartlist_add(arg_chars, (void*)c);
    } else if ('\\' == *c) {
      /* Count backslashes until we know whether to double up */
      bs_counter++;
    } else {
      /* Don't double up slashes preceding a non-quote */
      for (i=0; i<bs_counter; i++)
        smartlist_add(arg_chars, (void*)&backslash);
      bs_counter = 0;
      smartlist_add(arg_chars, (void*)c);
    }
  }
  /* Don't double up trailing backslashes */
  for (i=0; i<bs_counter; i++)
    smartlist_add(arg_chars, (void*)&backslash);

  /* Allocate space for argument, quotes (if needed), and terminator */
  const size_t formatted_arg_len = smartlist_len(arg_chars) +
    (need_quotes ? 2 : 0) + 1;
  formatted_arg = tor_malloc_zero(formatted_arg_len);

  /* Add leading quote */
  i=0;
  if (need_quotes)
    formatted_arg[i++] = '"';

  /* Add characters */
  SMARTLIST_FOREACH(arg_chars, char*, ch,
  {
    formatted_arg[i++] = *ch;
  });

  /* Add trailing quote */
  if (need_quotes)
    formatted_arg[i++] = '"';
  formatted_arg[i] = '\0';

  smartlist_free(arg_chars);
  return formatted_arg;
}

/** Format a command line for use on Windows, which takes the command as a
 * string rather than string array. Follows the rules from "Parsing C++
 * Command-Line Arguments" in MSDN. Algorithm based on list2cmdline in the
 * Python subprocess module. Returns a newly allocated string */
char *
tor_join_win_cmdline(const char *argv[])
{
  smartlist_t *argv_list;
  char *joined_argv;
  int i;

  /* Format each argument and put the result in a smartlist */
  argv_list = smartlist_new();
  for (i=0; argv[i] != NULL; i++) {
    smartlist_add(argv_list, (void *)format_win_cmdline_argument(argv[i]));
  }

  /* Join the arguments with whitespace */
  joined_argv = smartlist_join_strings(argv_list, " ", 0, NULL);

  /* Free the newly allocated arguments, and the smartlist */
  SMARTLIST_FOREACH(argv_list, char *, arg,
  {
    tor_free(arg);
  });
  smartlist_free(argv_list);

  return joined_argv;
}

/**
 * Boolean.  If true, then Tor may call execve or CreateProcess via
 * tor_spawn_background.
 **/
static int may_spawn_background_process = 1;
/**
 * Turn off may_spawn_background_process, so that all future calls to
 * tor_spawn_background are guaranteed to fail.
 **/
void
tor_disable_spawning_background_processes(void)
{
  may_spawn_background_process = 0;
}
