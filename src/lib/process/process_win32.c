/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file process_win32.c
 * \brief Module for working with Windows processes.
 **/

#ifdef _WIN32

#define PROCESS_WIN32_PRIVATE
#include "lib/intmath/cmp.h"
#include "lib/container/buffers.h"
#include "lib/net/buffers_net.h"
#include "lib/container/smartlist.h"
#include "lib/log/log.h"
#include "lib/log/util_bug.h"
#include "lib/log/win32err.h"
#include "lib/process/process.h"
#include "lib/process/process_win32.h"
#include "lib/process/subprocess.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <stdio.h>

/** The size of our I/O Completion Port buffers. */
#define IO_BUFFER_SIZE (1024)

static periodic_timer_t *periodic_timer;
static HANDLE completion_port = INVALID_HANDLE_VALUE;

struct process_win32_t {
  /** Standard in pipe handle. */
  HANDLE stdin_pipe;

  /** Overlapped structure for standard in. */
  OVERLAPPED stdin_overlapped;

  /** Dynamically allocated buffer for WriteFileEx(). */
  char *stdin_buffer;

  /** Standard out pipe handle. */
  HANDLE stdout_pipe;

  /** Standard out buffer. */
  char stdout_buffer[IO_BUFFER_SIZE];

  /** True iff we have reached EOF from standard out. */
  bool stdout_reached_eof;

  /** How much data is available in stdout_buffer. */
  size_t stdout_data_available;

  /** Overlapped structure for standard out. */
  OVERLAPPED stdout_overlapped;

  /** Standard error pipe handle. */
  HANDLE stderr_pipe;

  /** Standard error buffer. */
  char stderr_buffer[IO_BUFFER_SIZE];

  /** True iff we have reached EOF from stdandard out. */
  bool stderr_reached_eof;

  /** How much data is available in stderr_buffer. */
  size_t stderr_data_available;

  /** Overlapped structure for standard out. */
  OVERLAPPED stderr_overlapped;

  /** Process Information. */
  PROCESS_INFORMATION pid;
};

process_win32_t *
process_win32_new(void)
{
  process_win32_t *win32_process;
  win32_process = tor_malloc_zero(sizeof(process_win32_t));

  win32_process->stdin_pipe = INVALID_HANDLE_VALUE;
  win32_process->stdout_pipe = INVALID_HANDLE_VALUE;
  win32_process->stderr_pipe = INVALID_HANDLE_VALUE;

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

  process_win32_t *win32_process = process_get_win32_process(process);

  HANDLE stdout_pipe_read = NULL;
  HANDLE stdout_pipe_write = NULL;
  HANDLE stderr_pipe_read = NULL;
  HANDLE stderr_pipe_write = NULL;
  HANDLE stdin_pipe_read = NULL;
  HANDLE stdin_pipe_write = NULL;
  process_status_t status = PROCESS_STATUS_ERROR;
  STARTUPINFOA siStartInfo;
  BOOL retval = FALSE;
  char *joined_argv;
  const char *filename = process_get_name(process);

  SECURITY_ATTRIBUTES saAttr;

  saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
  saAttr.bInheritHandle = TRUE;
  /* TODO: should we set explicit security attributes? (#2046, comment 5) */
  saAttr.lpSecurityDescriptor = NULL;

  /* Set up pipe for stdout */
  if (! process_win32_create_pipe(&stdout_pipe_read,
                                  &stdout_pipe_write,
                                  &saAttr,
                                  4096,
                                  FILE_FLAG_OVERLAPPED,
                                  0)) {
    log_warn(LD_GENERAL,
      "Failed to create pipe for stdout communication with child process: %s",
      format_win32_error(GetLastError()));
    return status;
  }
  if (!SetHandleInformation(stdout_pipe_read, HANDLE_FLAG_INHERIT, 0)) {
    log_warn(LD_GENERAL,
      "Failed to configure pipe for stdout communication with child "
      "process: %s", format_win32_error(GetLastError()));
    return status;
  }

  /* Set up pipe for stderr */
  if (! process_win32_create_pipe(&stderr_pipe_read,
                                  &stderr_pipe_write,
                                  &saAttr,
                                  4096,
                                  FILE_FLAG_OVERLAPPED,
                                  0)) {
    log_warn(LD_GENERAL,
      "Failed to create pipe for stderr communication with child process: %s",
      format_win32_error(GetLastError()));
    return status;
  }
  if (!SetHandleInformation(stderr_pipe_read, HANDLE_FLAG_INHERIT, 0)) {
    log_warn(LD_GENERAL,
      "Failed to configure pipe for stderr communication with child "
      "process: %s", format_win32_error(GetLastError()));
    return status;
  }

  /* Set up pipe for stdin */
  if (! process_win32_create_pipe(&stdin_pipe_read,
                                  &stdin_pipe_write,
                                  &saAttr,
                                  4096,
                                  0,
                                  FILE_FLAG_OVERLAPPED)) {
    log_warn(LD_GENERAL,
      "Failed to create pipe for stdin communication with child process: %s",
      format_win32_error(GetLastError()));
    return status;
  }
  if (!SetHandleInformation(stdin_pipe_write, HANDLE_FLAG_INHERIT, 0)) {
    log_warn(LD_GENERAL,
      "Failed to configure pipe for stdin communication with child "
      "process: %s", format_win32_error(GetLastError()));
    return status;
  }

  /* Create the child process */
  ZeroMemory(&(win32_process->pid), sizeof(PROCESS_INFORMATION));
  ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
  siStartInfo.cb = sizeof(STARTUPINFO);
  siStartInfo.hStdError = stderr_pipe_write;
  siStartInfo.hStdOutput = stdout_pipe_write;
  siStartInfo.hStdInput = stdin_pipe_read;
  siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

  /* Create argv. We allocate an extra sizeof(char *) for the process_name in
   * the beginning and an extra sizeof(char *) for the NULL pointer at the
   * end. */
  smartlist_t *arguments = process_get_arguments(process);
  const char **argv;

  argv = tor_malloc_zero(sizeof(char *) * (smartlist_len(arguments) + 2));
  argv[0] = filename;

  SMARTLIST_FOREACH_BEGIN(arguments, char *, arg_val) {
    tor_assert(arg_val != NULL);

    argv[arg_val_sl_idx + 1] = arg_val;
  } SMARTLIST_FOREACH_END(arg_val);

  /* Windows expects argv to be a whitespace delimited string, so join argv up
   */
  joined_argv = tor_join_win_cmdline(argv);

  /* Create the child process */

  retval = CreateProcessA(filename,      // module name
                 joined_argv,   // command line
  /* TODO: should we set explicit security attributes? (#2046, comment 5) */
                 NULL,          // process security attributes
                 NULL,          // primary thread security attributes
                 TRUE,          // handles are inherited
  /*(TODO: set CREATE_NEW CONSOLE/PROCESS_GROUP to make GetExitCodeProcess()
   * work?) */
                 CREATE_NO_WINDOW,             // creation flags
                 NULL,          // FIXME(ahf): Fix environment.
                 NULL,          // use parent's current directory
                 &siStartInfo,  // STARTUPINFO pointer
                 &(win32_process->pid));  // receives PROCESS_INFORMATION

  tor_free(argv);
  tor_free(joined_argv);

  if (! retval) {
    log_warn(LD_GENERAL,
      "Failed to create child process %s: %s", filename,
      format_win32_error(GetLastError()));
    return status;
  } else  {
    /* TODO: Close hProcess and hThread in process_handle->pid? */
    win32_process->stdout_pipe = stdout_pipe_read;
    win32_process->stderr_pipe = stderr_pipe_read;
    win32_process->stdin_pipe = stdin_pipe_write;

    /* Used by the I/O Completion Port callback functions such that we can
     * figure out which process_t that was responsible for the event.
     *
     * Warning: Here be dragons:
     *   MSDN says that the hEvent member of the overlapped structure is unused
     *   for ReadFileEx() and WriteFileEx, which allows us to store the state
     *   there.
     */
    win32_process->stdout_overlapped.hEvent = (HANDLE)process;
    win32_process->stderr_overlapped.hEvent = (HANDLE)process;
    win32_process->stdin_overlapped.hEvent = (HANDLE)process;

    if (! process_win32_timer_running())
      process_win32_timer_start();

    /* I/O Completeion Ports reports when an event is completed, so we start a
     * ReadFileEx() right away.
     */
    process_notify_event_stdout(process);
    process_notify_event_stderr(process);
  }

  /* TODO: Close pipes on exit */
  return status;
}

void
process_win32_init(void)
{
  tor_assert(completion_port == INVALID_HANDLE_VALUE);

  completion_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE,
                                           NULL,
                                           0,
                                           0);

  if (completion_port == INVALID_HANDLE_VALUE) {
    log_warn(LD_PROCESS, "Unable to create I/O Completion Port: %s",
             format_win32_error(GetLastError()));
  }
}

void
process_win32_deinit(void)
{
  process_win32_timer_stop();

  if (completion_port != INVALID_HANDLE_VALUE) {
    CloseHandle(completion_port);
    completion_port = INVALID_HANDLE_VALUE;
  }
}

int
process_win32_write(struct process_t *process, buf_t *buffer)
{
  tor_assert(process);
  tor_assert(buffer);

  process_win32_t *win32_process = process_get_win32_process(process);
  BOOL ret;
  const size_t buffer_size = buf_datalen(buffer);

  /* Windows is still writing our buffer. */
  if (win32_process->stdin_buffer != NULL)
    return 0;

  /* Nothing for us to do right now. */
  if (buffer_size == 0)
    return 0;

  tor_assert(win32_process->stdin_buffer == NULL);
  win32_process->stdin_buffer = tor_malloc_zero(buffer_size);
  buf_get_bytes(buffer, win32_process->stdin_buffer, buffer_size);

  ret = WriteFileEx(win32_process->stdin_pipe,
                    win32_process->stdin_buffer,
                    buffer_size,
                    &win32_process->stdin_overlapped,
                    process_win32_stdin_write_done);

  if (! ret) {
    log_warn(LD_PROCESS, "Unable to write data to standard in: %s",
             format_win32_error(GetLastError()));
    return 0;
  }

  return (int)buffer_size;
}

int
process_win32_read_stdout(struct process_t *process, buf_t *buffer)
{
  tor_assert(process);
  tor_assert(buffer);

  process_win32_t *win32_process = process_get_win32_process(process);
  BOOL ret;
  int bytes_available = 0;

  /* The cast here should be safe, since our buffer can be maximum up to
   * IO_BUFFER_SIZE big. */
  bytes_available = (int)win32_process->stdout_data_available;

  if (win32_process->stdout_data_available > 0) {
    buf_add(buffer,
            win32_process->stdout_buffer,
            win32_process->stdout_data_available);

    /* Clear our flags. */
    win32_process->stdout_data_available = 0;
    memset(win32_process->stdout_buffer, 0,
           sizeof(win32_process->stdout_buffer));
  }

  ret = ReadFileEx(win32_process->stdout_pipe,
                   win32_process->stdout_buffer,
                   sizeof(win32_process->stdout_buffer),
                   &win32_process->stdout_overlapped,
                   process_win32_stdout_read_done);

  if (! ret) {
    log_warn(LD_PROCESS, "Unable to read data from standard out: %s",
             format_win32_error(GetLastError()));
    return bytes_available;
  }

  return bytes_available;
}

int
process_win32_read_stderr(struct process_t *process, buf_t *buffer)
{
  tor_assert(process);
  tor_assert(buffer);

  process_win32_t *win32_process = process_get_win32_process(process);
  BOOL ret;
  int bytes_available = 0;

  /* The cast here should be safe, since our buffer can be maximum up to
   * IO_BUFFER_SIZE big. */
  bytes_available = (int)win32_process->stderr_data_available;

  if (win32_process->stderr_data_available > 0) {
    buf_add(buffer,
            win32_process->stderr_buffer,
            win32_process->stderr_data_available);

    /* Clear our flags. */
    win32_process->stderr_data_available = 0;
    memset(win32_process->stderr_buffer, 0,
           sizeof(win32_process->stderr_buffer));
  }

  ret = ReadFileEx(win32_process->stderr_pipe,
                   win32_process->stderr_buffer,
                   sizeof(win32_process->stderr_buffer),
                   &win32_process->stderr_overlapped,
                   process_win32_stderr_read_done);

  if (! ret) {
    log_warn(LD_PROCESS, "Unable to read data from standard error: %s",
             format_win32_error(GetLastError()));
    return bytes_available;
  }

  return bytes_available;
}

STATIC void
process_win32_timer_start(void)
{
  if (BUG(process_win32_timer_running()))
    return;

  /* Wake up once a second. */
  static const struct timeval interval = {1, 0};

  log_info(LD_PROCESS, "Starting Windows I/O Control Port timer");
  periodic_timer = periodic_timer_new(tor_libevent_get_base(),
                                      &interval,
                                      process_win32_timer_callback,
                                      NULL);
}

STATIC void
process_win32_timer_stop(void)
{
  if (periodic_timer == NULL)
    return;

  log_warn(LD_PROCESS, "Stopping Windows process timer");
  periodic_timer_free(periodic_timer);
}

STATIC bool
process_win32_timer_running(void)
{
  return periodic_timer != NULL;
}

STATIC void
process_win32_timer_callback(periodic_timer_t *timer, void *data)
{
  tor_assert(timer == periodic_timer);
  tor_assert(data == NULL);

  log_debug(LD_PROCESS, "I/O Control Port timer ticked");
  smartlist_t *processes = process_get_all_processes();

  SMARTLIST_FOREACH(processes, process_t *, p,
                    process_win32_timer_test_process(p));

  /* FIXME(ahf): Question for Nick here: Could we remove this timer that runs
   * every second  and move the call to SleepEx() to whenever libevent returns
   * from a single step of the main loop? */
  SleepEx(0, TRUE);
}

STATIC void
process_win32_timer_test_process(process_t *process)
{
  process_win32_t *win32_process = process_get_win32_process(process);
  BOOL ret = FALSE;
  DWORD exit_code = 0;

  /* We start by testing whether our process is still running. */
  ret = GetExitCodeProcess(win32_process->pid.hProcess, &exit_code);

  if (! ret) {
    log_warn(LD_PROCESS, "Failed to get exit code from process: %s",
             format_win32_error(GetLastError()));
    return;
  }

  if (exit_code != STILL_ACTIVE) {
    log_warn(LD_PROCESS, "  Process no longer running :-(");
    return;
  }
}

STATIC bool
process_win32_create_pipe(HANDLE *read_pipe,
                          HANDLE *write_pipe,
                          SECURITY_ATTRIBUTES *attributes,
                          size_t size,
                          DWORD read_mode,
                          DWORD write_mode)
{
  tor_assert(read_pipe);
  tor_assert(write_pipe);
  tor_assert(attributes);
  tor_assert(size > 0);

  /* Generate the unique pipe name. */
  char pipe_name[MAX_PATH];
  static DWORD process_id = 0;
  static DWORD counter = 0;

  if (process_id == 0)
    process_id = GetCurrentProcessId();

  tor_snprintf(pipe_name, sizeof(pipe_name),
               "\\\\.\\Pipe\\Tor-Process-Pipe-%lu-%lu",
               process_id, counter++);

  /* Validate flags. */
  if ((read_mode | write_mode) & (~FILE_FLAG_OVERLAPPED))
    return false;

  /* Setup our read and write handles. */
  HANDLE read_handle;
  HANDLE write_handle;

  read_handle = CreateNamedPipeA(pipe_name,
                                 (PIPE_ACCESS_INBOUND|read_mode),
                                 (PIPE_TYPE_BYTE|PIPE_WAIT),
                                 1,
                                 size,
                                 size,
                                 1000,
                                 attributes);

  if (! read_handle)
    return false;

  write_handle = CreateFileA(pipe_name,
                             GENERIC_WRITE,
                             0,
                             attributes,
                             OPEN_EXISTING,
                             (FILE_ATTRIBUTE_NORMAL|write_mode),
                             NULL);

  if (write_handle == INVALID_HANDLE_VALUE)
    return false;

  *read_pipe = read_handle;
  *write_pipe = write_handle;

  return true;
}

STATIC VOID WINAPI
process_win32_stdout_read_done(DWORD error_code,
                               DWORD byte_count,
                               LPOVERLAPPED overlapped)
{
  tor_assert(overlapped);
  tor_assert(overlapped->hEvent);

  process_t *process = (process_t *)overlapped->hEvent;
  process_win32_t *win32_process = process_get_win32_process(process);

  if (error_code != 0) {
    log_warn(LD_PROCESS,
             "Error from I/O completeion routine for standard out: %s",
             format_win32_error(error_code));

    /* FIXME(ahf): I have never seen this happen :-/ */
  }

  win32_process->stdout_data_available = (size_t)byte_count;

  /* Schedule next read. */
  process_notify_event_stdout(process);
}

STATIC VOID WINAPI
process_win32_stderr_read_done(DWORD error_code,
                               DWORD byte_count,
                               LPOVERLAPPED overlapped)
{
  tor_assert(overlapped);
  tor_assert(overlapped->hEvent);

  process_t *process = (process_t *)overlapped->hEvent;
  process_win32_t *win32_process = process_get_win32_process(process);

  if (error_code != 0) {
    log_warn(LD_PROCESS,
             "Error from I/O completeion routine for standard error: %s",
             format_win32_error(error_code));

    /* FIXME(ahf): I have never seen this happen :-/ */
  }

  win32_process->stderr_data_available = (size_t)byte_count;

  /* Schedule next read. */
  process_notify_event_stderr(process);
}

STATIC VOID WINAPI
process_win32_stdin_write_done(DWORD error_code,
                               DWORD byte_count,
                               LPOVERLAPPED overlapped)
{
  tor_assert(overlapped);
  tor_assert(overlapped->hEvent);

  (void)byte_count;

  process_t *process = (process_t *)overlapped->hEvent;
  process_win32_t *win32_process = process_get_win32_process(process);

  if (error_code != 0) {
    log_warn(LD_PROCESS,
             "Error from I/O completeion routine for standard error: %s",
             format_win32_error(error_code));

    /* FIXME(ahf): I have never seen this happen :-/ */
  }

  /* Our data have been written. Clear our state for the next
   * write. */
  tor_assert(win32_process->stdin_buffer != NULL);
  tor_free(win32_process->stdin_buffer);

  /* Schedule next write. */
  process_notify_event_stdin(process);
}

#endif /* ! defined(_WIN32). */
