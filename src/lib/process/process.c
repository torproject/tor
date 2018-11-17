/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file process.c
 * \brief Module for working with other processes.
 **/

#define PROCESS_PRIVATE
#include "lib/container/buffers.h"
#include "lib/net/buffers_net.h"
#include "lib/container/smartlist.h"
#include "lib/log/log.h"
#include "lib/log/util_bug.h"
#include "lib/process/process.h"
#include "lib/process/process_unix.h"
#include "lib/process/process_win32.h"

#include <stddef.h>

static smartlist_t *processes;

struct process_t {
  /** Which type is this process? */
  process_type_t type;

  /** Which protocol is the process using? */
  process_protocol_t protocol;

  /** Which function to call when we have data to read on stdout? */
  process_read_callback_t stdout_read_callback;

  /** Which function to call when we have data to read on stderr? */
  process_read_callback_t stderr_read_callback;

  /** Name of the process we want to execute (for example: /bin/ls). */
  char *process_name;

  /** The arguments used for the new process. */
  smartlist_t *arguments;

  /** The environment used for the new process. */
  smartlist_t *environment;

  /** Buffer to store data from stdout when it is read. */
  buf_t *stdout_buffer;

  /** Buffer to store data from stderr when it is read. */
  buf_t *stderr_buffer;

  /** Buffer to store data to stdin before it is written. */
  buf_t *stdin_buffer;

  /** Do we need to store some custom data with the process? */
  void *data;

#ifndef _WIN32
  /** Our Unix process handle. */
  process_unix_t *unix_process;
#else
  /** Our Win32 process handle. */
  process_win32_t *win32_process;
#endif
};

/** Convert a given process status in <b>status</b> to its string
 * representation. */
const char *
process_status_to_string(process_status_t status)
{
  switch (status) {
  case PROCESS_STATUS_NOT_RUNNING:
    return "not running";
  case PROCESS_STATUS_RUNNING:
    return "running";
  case PROCESS_STATUS_ERROR:
    return "error";
  }

  /* LCOV_EXCL_START */
  tor_assert_unreached();
  return NULL;
  /* LCOV_EXCL_STOP */
}

/** Convert a given process type in <b>type</b> to its string representation.
 * */
const char *
process_type_to_string(process_type_t type)
{
  switch (type) {
  case PROCESS_TYPE_UNKNOWN:
    return "Unknown Process";
  }

  /* LCOV_EXCL_START */
  tor_assert_unreached();
  return NULL;
  /* LCOV_EXCL_STOP */
}

/** Convert a given process protocol in <b>protocol</b> to its string
 * representation. */
const char *
process_protocol_to_string(process_protocol_t protocol)
{
  switch (protocol) {
  case PROCESS_PROTOCOL_LINE:
    return "Line";
  case PROCESS_PROTOCOL_RAW:
    return "Raw";
  }

  /* LCOV_EXCL_START */
  tor_assert_unreached();
  return NULL;
  /* LCOV_EXCL_STOP */
}

/** Initialize the Process subsystem.  This function initializes the Process
 * subsystem's global state. For cleaning up, <b>process_free_all()</b> should
 * be called. */
void
process_init(void)
{
  processes = smartlist_new();

#ifdef _WIN32
  process_win32_init();
#endif
}

/** Free up all resources that is handled by the Process subsystem. Note that
 * this call does not terminate already running processes. */
void
process_free_all(void)
{
#ifdef _WIN32
  process_win32_deinit();
#endif

  SMARTLIST_FOREACH(processes, process_t *, x, process_free(x));
  smartlist_free(processes);
}

/** Get a list of all processes.  This function returns a smartlist of
 * <b>process_t</b> containing all the currently allocated processes. */
smartlist_t *
process_get_all_processes(void)
{
  return processes;
}

/** Allocate and initialize a new process.  This function returns a newly
 * allocated and initialized process data-structure, which can be used to
 * configure and later run a subprocess of Tor. */
process_t *
process_new(process_type_t type)
{
  process_t *process;
  process = tor_malloc_zero(sizeof(process_t));

  /* Set default values here. */
  process->type = type;

  /* Prepare process environment. */
  process->arguments = smartlist_new();
  process->environment = smartlist_new();

  /* Prepare the buffers. */
  process->stdout_buffer = buf_new();
  process->stderr_buffer = buf_new();
  process->stdin_buffer = buf_new();

#ifndef _WIN32
  /* Prepare our Unix process handle. */
  process->unix_process = process_unix_new();
#else
  /* Prepare our Win32 process handle. */
  process->win32_process = process_win32_new();
#endif

  smartlist_add(processes, process);

  return process;
}

/** Deallocate the given process in <b>process</b>. */
void
process_free_(process_t *process)
{
  if (! process)
    return;

  /* Cleanup parameters. */
  tor_free(process->process_name);

  /* Cleanup arguments and environment. */
  smartlist_free(process->arguments);
  smartlist_free(process->environment);

  /* Cleanup the buffers. */
  buf_free(process->stdout_buffer);
  buf_free(process->stderr_buffer);
  buf_free(process->stdin_buffer);

#ifndef _WIN32
  /* Cleanup our Unix process handle. */
  process_unix_free(process->unix_process);
#else
  /* Cleanup our Win32 process handle. */
  process_win32_free(process->win32_process);
#endif

  smartlist_remove(processes, process);

  tor_free(process);
}

process_status_t
process_exec(process_t *process)
{
  tor_assert(process);

  log_info(LD_PROCESS, "Starting new process: \"%s\" (%s)",
           process->process_name,
           process_type_to_string(process->type));

#ifndef _WIN32
  return process_unix_exec(process);
#else
  return process_win32_exec(process);
#endif
}

void
process_set_stdout_read_callback(process_t *process,
                                 process_read_callback_t callback)
{
  tor_assert(process);
  process->stdout_read_callback = callback;
}

void
process_set_stderr_read_callback(process_t *process,
                                 process_read_callback_t callback)
{
  tor_assert(process);
  process->stderr_read_callback = callback;
}

void
process_set_name(process_t *process, const char *process_name)
{
  tor_assert(process);
  tor_assert(process_name);

  if (process->process_name != NULL)
    tor_free(process->process_name);

  process->process_name = tor_strdup(process_name);
}

char *
process_get_name(const process_t *process)
{
  tor_assert(process);
  return process->process_name;
}

process_type_t
process_get_type(const process_t *process)
{
  tor_assert(process);
  return process->type;
}

void
process_set_protocol(process_t *process, process_protocol_t protocol)
{
  tor_assert(process);
  process->protocol = protocol;
}

process_protocol_t
process_get_protocol(const process_t *process)
{
  tor_assert(process);
  return process->protocol;
}

void
process_set_data(process_t *process, void *data)
{
  tor_assert(process);
  process->data = data;
}

void *
process_get_data(const process_t *process)
{
  tor_assert(process);
  return process->data;
}

smartlist_t *
process_get_arguments(const process_t *process)
{
  tor_assert(process);
  return process->arguments;
}

smartlist_t *
process_get_environment(const process_t *process)
{
  tor_assert(process);
  return process->environment;
}

#ifndef _WIN32
process_unix_t *
process_get_unix_process(const process_t *process)
{
  tor_assert(process);
  tor_assert(process->unix_process);
  return process->unix_process;
}
#else
process_win32_t *
process_get_win32_process(const process_t *process)
{
  tor_assert(process);
  tor_assert(process->win32_process);
  return process->win32_process;
}
#endif

void
process_write(process_t *process,
              const uint8_t *data, size_t size)
{
  tor_assert(process);
  tor_assert(data);

  buf_add(process->stdin_buffer, (char *)data, size);
  process_write_stdin(process, process->stdin_buffer);
}

void
process_vprintf(process_t *process,
                const char *format, va_list args)
{
  tor_assert(process);
  tor_assert(format);

  int size;
  char *data;

  size = tor_vasprintf(&data, format, args);
  process_write(process, (uint8_t *)data, size);
  tor_free(data);
}

void
process_printf(process_t *process,
               const char *format, ...)
{
  tor_assert(process);
  tor_assert(format);

  va_list ap;
  va_start(ap, format);
  process_vprintf(process, format, ap);
  va_end(ap);
}

void
process_notify_event_stdout(process_t *process)
{
  tor_assert(process);

  int ret;

  ret = process_read_stdout(process, process->stdout_buffer);

  if (ret > 0) {
    if (process->protocol == PROCESS_PROTOCOL_RAW)
      process_read_buffer(process,
                          process->stdout_buffer,
                          process->stdout_read_callback);

    if (process->protocol == PROCESS_PROTOCOL_LINE)
      process_read_lines(process,
                         process->stdout_buffer,
                         process->stdout_read_callback);
  }
}

void
process_notify_event_stderr(process_t *process)
{
  tor_assert(process);

  int ret;

  ret = process_read_stderr(process, process->stderr_buffer);

  if (ret > 0) {
    if (process->protocol == PROCESS_PROTOCOL_RAW)
      process_read_buffer(process,
                          process->stderr_buffer,
                          process->stderr_read_callback);

    if (process->protocol == PROCESS_PROTOCOL_LINE)
      process_read_lines(process,
                         process->stderr_buffer,
                         process->stderr_read_callback);
  }
}

void
process_notify_event_stdin(process_t *process)
{
  tor_assert(process);

  process_write_stdin(process, process->stdin_buffer);
}

MOCK_IMPL(STATIC int, process_read_stdout, (process_t *process, buf_t *buffer))
{
  tor_assert(process);
  tor_assert(buffer);

#ifndef _WIN32
  return process_unix_read_stdout(process, buffer);
#else
  return process_win32_read_stdout(process, buffer);
#endif
}

MOCK_IMPL(STATIC int, process_read_stderr, (process_t *process, buf_t *buffer))
{
  tor_assert(process);
  tor_assert(buffer);

#ifndef _WIN32
  return process_unix_read_stderr(process, buffer);
#else
  return process_win32_read_stderr(process, buffer);
#endif
}

MOCK_IMPL(STATIC void, process_write_stdin,
          (process_t *process, buf_t *buffer))
{
  tor_assert(process);
  tor_assert(buffer);

#ifndef _WIN32
  process_unix_write(process, buffer);
#else
  process_win32_write(process, buffer);
#endif
}

STATIC void
process_read_buffer(process_t *process,
                    buf_t *buffer,
                    process_read_callback_t callback)
{
  tor_assert(process);
  tor_assert(buffer);

  if (callback == NULL)
    return;

  const size_t size = buf_datalen(buffer);

  /* We allocate an extra byte for the zero byte in the end. */
  char *data = tor_malloc_zero(size + 1);

  buf_get_bytes(buffer, data, size);
  log_info(LD_PROCESS, "Read data from process: \"%s\"", data);
  callback(process, data, size);

  tor_free(data);
}

STATIC void
process_read_lines(process_t *process,
                   buf_t *buffer,
                   process_read_callback_t callback)
{
  tor_assert(process);
  tor_assert(buffer);

  if (callback == NULL)
    return;

  const size_t size = buf_datalen(buffer) + 1;
  size_t line_size = 0;
  char *data = tor_malloc_zero(size);
  int ret;

  while (true) {
    line_size = size;
    ret = buf_get_line(buffer, data, &line_size);

    // A complete line should always be smaller than the size of our
    // buffer.
    tor_assert(ret != -1);

    if (ret == 1) {
      log_info(LD_PROCESS, "Read line from process: \"%s\"", data);
      callback(process, data, line_size);
      // We have read a whole line, let's see if there is more lines to
      // read.
      continue;
    }

    // No complete line for us to read. We are done.
    tor_assert(ret == 0);
    break;
  }

  tor_free(data);
}
