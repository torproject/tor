/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file process_win32.h
 * \brief Header for process_win32.c
 **/

#ifndef TOR_PROCESS_WIN32_H
#define TOR_PROCESS_WIN32_H

#ifdef _WIN32

#include "orconfig.h"
#include "lib/malloc/malloc.h"
#include "lib/evloop/compat_libevent.h"

#include <windows.h>

struct process_t;

struct process_win32_t;
typedef struct process_win32_t process_win32_t;

process_win32_t *process_win32_new(void);
void process_win32_free_(process_win32_t *win32_process);
#define process_win32_free(s) \
  FREE_AND_NULL(process_win32_t, process_win32_free_, (s))

process_status_t process_win32_exec(struct process_t *process);

void process_win32_init(void);
void process_win32_deinit(void);

int process_win32_write(struct process_t *process, buf_t *buffer);
int process_win32_read_stdout(struct process_t *process, buf_t *buffer);
int process_win32_read_stderr(struct process_t *process, buf_t *buffer);

#ifdef PROCESS_WIN32_PRIVATE
STATIC void process_win32_timer_start(void);
STATIC void process_win32_timer_stop(void);
STATIC bool process_win32_timer_running(void);
STATIC void process_win32_timer_callback(periodic_timer_t *, void *);
STATIC void process_win32_timer_test_process(process_t *process);

STATIC bool process_win32_create_pipe(HANDLE *read_pipe,
                                      HANDLE *write_pipe,
                                      SECURITY_ATTRIBUTES *attributes,
                                      size_t size,
                                      DWORD read_mode,
                                      DWORD write_mode);
STATIC VOID WINAPI process_win32_stdout_read_done(DWORD error_code,
                                                  DWORD byte_count,
                                                  LPOVERLAPPED overlapped);
STATIC VOID WINAPI process_win32_stderr_read_done(DWORD error_code,
                                                  DWORD byte_count,
                                                  LPOVERLAPPED overlapped);
STATIC VOID WINAPI process_win32_stdin_write_done(DWORD error_code,
                                                  DWORD byte_count,
                                                  LPOVERLAPPED overlapped);
#endif /* defined(PROCESS_WIN32_PRIVATE). */

#endif /* ! defined(_WIN32). */

#endif /* defined(TOR_PROCESS_WIN32_H). */
