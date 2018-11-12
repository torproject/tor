/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file process_unix.h
 * \brief Header for process_unix.c
 **/

#ifndef TOR_PROCESS_UNIX_H
#define TOR_PROCESS_UNIX_H

#ifndef _WIN32

#include "orconfig.h"
#include "lib/malloc/malloc.h"

#include <event2/event.h>

struct process_t;

struct process_unix_t;
typedef struct process_unix_t process_unix_t;

process_unix_t *process_unix_new(void);
void process_unix_free_(process_unix_t *unix_process);
#define process_unix_free(s) \
  FREE_AND_NULL(process_unix_t, process_unix_free_, (s))

process_status_t process_unix_exec(struct process_t *process);

int process_unix_write(struct process_t *process, buf_t *buffer);
int process_unix_read_stdout(struct process_t *process, buf_t *buffer);
int process_unix_read_stderr(struct process_t *process, buf_t *buffer);

#ifdef PROCESS_UNIX_PRIVATE
STATIC void stdout_read_callback(evutil_socket_t fd, short event, void *data);
STATIC void stderr_read_callback(evutil_socket_t fd, short event, void *data);
STATIC void stdin_write_callback(evutil_socket_t fd, short event, void *data);

STATIC void start_reading_stdout(struct process_unix_t *process);
STATIC void stop_reading_stdout(struct process_unix_t *process);

STATIC void start_reading_stderr(struct process_unix_t *process);
STATIC void stop_reading_stderr(struct process_unix_t *process);

STATIC void start_writing_stdin(struct process_unix_t *process);
STATIC void stop_writing_stdin(struct process_unix_t *process);
#endif /* defined(PROCESS_UNIX_PRIVATE). */

#endif /* defined(_WIN32). */

#endif /* defined(TOR_PROCESS_UNIX_H). */
