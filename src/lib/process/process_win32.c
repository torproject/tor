/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file process_win32.c
 * \brief Module for working with Unix processes.
 **/

#ifdef _WIN32

#define PROCESS_WIN32_PRIVATE
#include "lib/intmath/cmp.h"
#include "lib/container/buffers.h"
#include "lib/net/buffers_net.h"
#include "lib/container/smartlist.h"
#include "lib/log/log.h"
#include "lib/log/util_bug.h"
#include "lib/process/process.h"
#include "lib/process/process_win32.h"

struct process_win32_t {
};

process_win32_t *
process_win32_new(void)
{
  process_win32_t *win32_process;
  win32_process = tor_malloc_zero(sizeof(process_win32_t));

  return win32_process;
}

void
process_win32_free_(process_win32_t *win32_process)
{
  if (! win32_process)
    return;

  tor_free(win32_process);
}

process_status_t
process_win32_exec(process_t *process)
{
  tor_assert(process);

  return PROCESS_STATUS_ERROR;
}

int
process_win32_write(struct process_t *process, buf_t *buffer)
{
  tor_assert(process);
  tor_assert(buffer);

  return 0;
}

int
process_win32_read_stdout(struct process_t *process, buf_t *buffer)
{
  tor_assert(process);
  tor_assert(buffer);

  return 0;
}

int
process_win32_read_stderr(struct process_t *process, buf_t *buffer)
{
  tor_assert(process);
  tor_assert(buffer);

  return 0;
}

#endif /* ! defined(_WIN32). */
