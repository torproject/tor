/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file process_unix.c
 * \brief Module for working with Unix processes.
 **/

#ifndef _WIN32

#define PROCESS_UNIX_PRIVATE
#include "lib/intmath/cmp.h"
#include "lib/container/buffers.h"
#include "lib/net/buffers_net.h"
#include "lib/container/smartlist.h"
#include "lib/evloop/compat_libevent.h"
#include "lib/log/log.h"
#include "lib/log/util_bug.h"
#include "lib/process/process.h"
#include "lib/process/process_unix.h"

#include <string.h>

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#if defined(HAVE_SYS_PRCTL_H) && defined(__linux__)
#include <sys/prctl.h>
#endif

#if HAVE_SIGNAL_H
#include <signal.h>
#endif

/* Maximum number of file descriptors, if we cannot get it via sysconf() */
#define DEFAULT_MAX_FD 256

struct process_unix_t {
  /** Standard in pipe. */
  int stdin_pipe;

  /** Standard out pipe. */
  int stdout_pipe;

  /** Standard error pipe. */
  int stderr_pipe;

  /** The process identifier of our process. */
  pid_t pid;

  /** True iff we have reached EOF from stdout. */
  bool stdout_reached_eof;

  /** True iff we have reached EOF from stderr. */
  bool stderr_reached_eof;

  /** True iff we are already writing. */
  bool stdin_is_writing;

  /** Event for reading from the process' standard out. */
  struct event *stdout_read_event;

  /** Event for reading from the process' stadard error. */
  struct event *stderr_read_event;

  /** Event for writing to the process' standard in. */
  struct event *stdin_write_event;
};

process_unix_t *
process_unix_new(void)
{
  process_unix_t *unix_process;
  unix_process = tor_malloc_zero(sizeof(process_unix_t));

  unix_process->stdin_pipe = -1;
  unix_process->stderr_pipe = -1;
  unix_process->stdout_pipe = -1;

  return unix_process;
}

void
process_unix_free_(process_unix_t *unix_process)
{
  if (! unix_process)
    return;

  /* Cleanup our events. */
  if (! unix_process->stdout_reached_eof)
    stop_reading_stdout(unix_process);

  if (! unix_process->stderr_reached_eof)
    stop_reading_stderr(unix_process);

  stop_writing_stdin(unix_process);

  tor_event_free(unix_process->stdout_read_event);
  tor_event_free(unix_process->stderr_read_event);
  tor_event_free(unix_process->stdin_write_event);

  tor_free(unix_process);
}

process_status_t
process_unix_exec(process_t *process)
{
  static int max_fd = -1;

  process_unix_t *unix_process;
  pid_t pid;
  process_status_t status;
  int stdin_pipe[2];
  int stdout_pipe[2];
  int stderr_pipe[2];
  int retval, fd;
  char **argv, **env;

  status = PROCESS_STATUS_ERROR;
  unix_process = process_get_unix_process(process);

  tor_assert(unix_process);

  /* Create standard in pipe. */
  retval = pipe(stdin_pipe);

  if (-1 == retval) {
    log_warn(LD_PROCESS,
             "Unable to create pipe for stdin "
             "communication with process: %s",
             strerror(errno));

    return status;
  }

  /* Create standard out pipe. */
  retval = pipe(stdout_pipe);

  if (-1 == retval) {
    log_warn(LD_PROCESS,
             "Unable to create pipe for stdout "
             "communication with process: %s",
             strerror(errno));

    /** Cleanup standard in pipe. */
    close(stdin_pipe[0]);
    close(stdin_pipe[1]);

    return status;
  }

  /* Create standard error pipe. */
  retval = pipe(stderr_pipe);

  if (-1 == retval) {
    log_warn(LD_PROCESS,
             "Unable to create pipe for stderr "
             "communication with process: %s",
             strerror(errno));

    /** Cleanup standard in pipe. */
    close(stdin_pipe[0]);
    close(stdin_pipe[1]);

    /** Cleanup standard out pipe. */
    close(stdin_pipe[0]);
    close(stdin_pipe[1]);

    return status;
  }

#ifdef _SC_OPEN_MAX
  if (-1 == max_fd) {
    max_fd = (int)sysconf(_SC_OPEN_MAX);

    if (max_fd == -1) {
      max_fd = DEFAULT_MAX_FD;
      log_warn(LD_PROCESS,
               "Cannot find maximum file descriptor, assuming: %d", max_fd);
    }
  }
#else /* !(defined(_SC_OPEN_MAX)) */
  max_fd = DEFAULT_MAX_FD;
#endif /* defined(_SC_OPEN_MAX) */

  pid = fork();

  if (0 == pid) {
    /* We are in the child process. */

#if defined(HAVE_SYS_PRCTL_H) && defined(__linux__)
    /* Attempt to have the kernel issue a SIGTERM if the parent
     * goes away. Certain attributes of the binary being execve()ed
     * will clear this during the execve() call, but it's better
     * than nothing.
     */
    prctl(PR_SET_PDEATHSIG, SIGTERM);
#endif /* defined(HAVE_SYS_PRCTL_H) && defined(__linux__) */

    /* Link process stdout to the write end of the pipe. */
    retval = dup2(stdout_pipe[1], STDOUT_FILENO);
    if (-1 == retval)
      goto error;

    /* Link process stderr to the write end of the pipe. */
    retval = dup2(stderr_pipe[1], STDERR_FILENO);
    if (-1 == retval)
      goto error;

    /* Link process stdin to the read end of the pipe */
    retval = dup2(stdin_pipe[0], STDIN_FILENO);
    if (-1 == retval)
      goto error;

    /* Close our pipes now after they have been dup2()'ed. */
    close(stderr_pipe[0]);
    close(stderr_pipe[1]);
    close(stdout_pipe[0]);
    close(stdout_pipe[1]);
    close(stdin_pipe[0]);
    close(stdin_pipe[1]);

    /* Close all other fds, including the read end of the pipe.
     * XXX: We should now be doing enough FD_CLOEXEC setting to make
     * this needless.
     */
    for (fd = STDERR_FILENO + 1; fd < max_fd; fd++) {
      close(fd);
    }

    /* Create argv. We allocate an extra sizeof(char *) for the process_name in
     * the beginning and an extra sizeof(char *) for the NULL pointer at the
     * end. */
    smartlist_t *arguments = process_get_arguments(process);

    argv = tor_malloc_zero(sizeof(char *) * (smartlist_len(arguments) + 2));
    argv[0] = process_get_name(process);

    SMARTLIST_FOREACH_BEGIN(arguments, char *, arg_val) {
      tor_assert(arg_val != NULL);

      argv[arg_val_sl_idx + 1] = arg_val;
    } SMARTLIST_FOREACH_END(arg_val);

    /* Create env. We allocate an an extra sizeof(char *) for the NULL pointer
     * at the end. */
    smartlist_t *environment = process_get_environment(process);

    env = tor_malloc_zero(sizeof(char *) * (smartlist_len(environment) + 1));

    SMARTLIST_FOREACH_BEGIN(environment, char *, env_val) {
      tor_assert(env_val != NULL);

      env[env_val_sl_idx] = env_val;
    } SMARTLIST_FOREACH_END(env_val);

    /* Call the requested program. */
    execve(argv[0], argv, env);

    /* If we got here, the exec or open("/dev/null") failed. */
    tor_free(argv);
    tor_free(env);

    tor_assert_unreached();

 error:
    {
      // FIXME(ahf): ...
    }

    /* LCOV_EXCL_START */
    tor_assert_unreached();
    return status;
    /* LCOV_EXCL_STOP */
  }

  /* We are in the parent process. */
  if (-1 == pid) {
    log_warn(LD_PROCESS,
             "Failed to create child process: %s", strerror(errno));

    /** Cleanup standard in pipe. */
    close(stdin_pipe[0]);
    close(stdin_pipe[1]);

    /** Cleanup standard out pipe. */
    close(stdin_pipe[0]);
    close(stdin_pipe[1]);

    /** Cleanup standard error pipe. */
    close(stderr_pipe[0]);
    close(stderr_pipe[1]);

    return status;
  }

  unix_process->pid = pid;

  /* Handle standard out. */
  unix_process->stdout_pipe = stdout_pipe[0];
  retval = close(stdout_pipe[1]);

  if (-1 == retval) {
    log_warn(LD_PROCESS, "Failed to close write end of standard out pipe: %s",
             strerror(errno));
  }

  /* Handle standard error. */
  unix_process->stderr_pipe = stderr_pipe[0];
  retval = close(stderr_pipe[1]);

  if (-1 == retval) {
    log_warn(LD_PROCESS,
             "Failed to close write end of standard error pipe: %s",
             strerror(errno));
  }

  /* Handle standard in. */
  unix_process->stdin_pipe = stdin_pipe[1];
  retval = close(stdin_pipe[0]);

  if (-1 == retval) {
    log_warn(LD_PROCESS, "Failed to close read end of standard in pipe: %s",
             strerror(errno));
  }

  /* The process is now running. */
  status = PROCESS_STATUS_RUNNING;

  /* Set standard in, out, and error to be non-blocking. */
  if (fcntl(unix_process->stdout_pipe, F_SETFL, O_NONBLOCK) < 0 ||
      fcntl(unix_process->stderr_pipe, F_SETFL, O_NONBLOCK) < 0 ||
      fcntl(unix_process->stdin_pipe, F_SETFL, O_NONBLOCK) < 0) {
    log_warn(LD_PROCESS,
             "Unable to set standard in, out, and error pipes nonblocking: %s",
             strerror(errno));
  }

  /* Register standard out read events. */
  unix_process->stdout_read_event = tor_event_new(tor_libevent_get_base(),
                                                  unix_process->stdout_pipe,
                                                  EV_READ|EV_PERSIST,
                                                  stdout_read_callback,
                                                  process);

  /* Register standard error read events. */
  unix_process->stderr_read_event = tor_event_new(tor_libevent_get_base(),
                                                  unix_process->stderr_pipe,
                                                  EV_READ|EV_PERSIST,
                                                  stderr_read_callback,
                                                  process);

  /* Register standard in write events. */
  unix_process->stdin_write_event = tor_event_new(tor_libevent_get_base(),
                                                  unix_process->stdin_pipe,
                                                  EV_WRITE|EV_PERSIST,
                                                  stdin_write_callback,
                                                  process);

  start_reading_stdout(unix_process);
  start_reading_stderr(unix_process);

  return status;
}

int
process_unix_write(struct process_t *process, buf_t *buffer)
{
  tor_assert(process);
  tor_assert(buffer);

  process_unix_t *unix_process = process_get_unix_process(process);

  size_t buffer_flush_len = buf_datalen(buffer);
  const size_t max_to_write = MIN(PROCESS_MAX_WRITE, buffer_flush_len);

  if (buffer_flush_len > 0 && ! unix_process->stdin_is_writing) {
    start_writing_stdin(unix_process);
    return 0;
  }

  if (buffer_flush_len == 0 && unix_process->stdin_is_writing) {
    stop_writing_stdin(unix_process);
    return 0;
  }

  return buf_flush_to_pipe(buffer,
                           process_get_unix_process(process)->stdin_pipe,
                           max_to_write, &buffer_flush_len);
}

int
process_unix_read_stdout(struct process_t *process, buf_t *buffer)
{
  tor_assert(process);
  tor_assert(buffer);

  process_unix_t *unix_process = process_get_unix_process(process);

  int ret = 0;
  int eof = 0;
  int error = 0;

  ret = buf_read_from_pipe(buffer,
                           unix_process->stdout_pipe,
                           PROCESS_MAX_READ,
                           &eof,
                           &error);

  if (error)
    log_warn(LD_PROCESS,
             "Unable to read data from stdout: %s",
             strerror(error));

  if (eof) {
    unix_process->stdout_reached_eof = true;
    stop_reading_stdout(unix_process);
  }

  return ret;
}

int
process_unix_read_stderr(struct process_t *process, buf_t *buffer)
{
  tor_assert(process);
  tor_assert(buffer);

  process_unix_t *unix_process = process_get_unix_process(process);

  int ret = 0;
  int eof = 0;
  int error = 0;

  ret = buf_read_from_pipe(buffer,
                           unix_process->stderr_pipe,
                           PROCESS_MAX_READ,
                           &eof,
                           &error);

  if (error)
    log_warn(LD_PROCESS,
             "Unable to read data from stderr: %s",
             strerror(error));

  if (eof) {
    unix_process->stderr_reached_eof = true;
    stop_reading_stderr(unix_process);
  }

  return ret;
}

STATIC void
stdout_read_callback(evutil_socket_t fd, short event, void *data)
{
  (void)fd;
  (void)event;

  process_t *process = data;
  tor_assert(process);

  process_notify_event_stdout(process);
}

STATIC void
stderr_read_callback(evutil_socket_t fd, short event, void *data)
{
  (void)fd;
  (void)event;

  process_t *process = data;
  tor_assert(process);

  process_notify_event_stderr(process);
}

STATIC void
stdin_write_callback(evutil_socket_t fd, short event, void *data)
{
  (void)fd;
  (void)event;

  process_t *process = data;
  tor_assert(process);

  process_notify_event_stdin(process);
}

STATIC void
start_reading_stdout(process_unix_t *process)
{
  tor_assert(process);
  tor_assert(process->stdout_read_event);

  if (event_add(process->stdout_read_event, NULL))
    log_warn(LD_PROCESS,
             "Unable to add libevent event for standard out in process.");
}

STATIC void
stop_reading_stdout(process_unix_t *process)
{
  tor_assert(process);

  if (process->stdout_read_event == NULL)
    return;

  if (event_del(process->stdout_read_event))
    log_warn(LD_PROCESS,
             "Unable to delete libevent event for standard out in process.");
}

STATIC void
start_reading_stderr(process_unix_t *process)
{
  tor_assert(process);
  tor_assert(process->stderr_read_event);

  if (event_add(process->stderr_read_event, NULL))
    log_warn(LD_PROCESS,
             "Unable to add libevent event for standard error in process.");
}

STATIC void
stop_reading_stderr(process_unix_t *process)
{
  tor_assert(process);

  if (process->stderr_read_event == NULL)
    return;

  if (event_del(process->stderr_read_event))
    log_warn(LD_PROCESS,
             "Unable to delete libevent event for standard error in process.");
}

STATIC void
start_writing_stdin(process_unix_t *process)
{
  tor_assert(process);

  if (event_add(process->stdin_write_event, NULL))
    log_warn(LD_PROCESS,
             "Unable to add libevent event for standard in for process.");

  process->stdin_is_writing = true;
}

STATIC void
stop_writing_stdin(process_unix_t *process)
{
  tor_assert(process);

  if (process->stdin_write_event == NULL)
    return;

  if (event_del(process->stdin_write_event))
    log_warn(LD_PROCESS,
             "Unable to delete libevent event for standard in for process.");

  process->stdin_is_writing = false;
}

#endif /* defined(_WIN32). */
