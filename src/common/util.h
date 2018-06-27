/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file util.h
 * \brief Headers for util.c
 **/

#ifndef TOR_UTIL_H
#define TOR_UTIL_H

#include "orconfig.h"
#include "lib/cc/torint.h"
#include "common/compat.h"
#include "lib/ctime/di_ops.h"
#include "lib/testsupport/testsupport.h"
#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
/* for the correct alias to struct stat */
#include <sys/stat.h>
#endif
#include "lib/err/torerr.h"
#include "lib/malloc/util_malloc.h"
#include "lib/wallclock/approx_time.h"
#include "lib/string/util_string.h"
#include "lib/string/parse_int.h"
#include "lib/string/scanf.h"
#include "lib/intmath/bits.h"
#include "lib/intmath/addsub.h"
#include "lib/intmath/muldiv.h"
#include "lib/intmath/cmp.h"
#include "lib/log/ratelim.h"
#include "lib/log/util_bug.h"
#include "lib/log/escape.h"
#include "lib/fs/dir.h"
#include "lib/fs/files.h"
#include "lib/fs/path.h"

void tor_log_mallinfo(int severity);

/** Macro: yield a pointer to an enclosing structure given a pointer to
 * a substructure at offset <b>off</b>. Example:
 * <pre>
 *   struct base { ... };
 *   struct subtype { int x; struct base b; } x;
 *   struct base *bp = &x.base;
 *   struct *sp = SUBTYPE_P(bp, struct subtype, b);
 * </pre>
 */
#define SUBTYPE_P(p, subtype, basemember) \
  ((void*) ( ((char*)(p)) - offsetof(subtype, basemember) ))

/* Logic */
/** Macro: true if two values have the same boolean value. */
#define bool_eq(a,b) (!(a)==!(b))
/** Macro: true if two values have different boolean values. */
#define bool_neq(a,b) (!(a)!=!(b))

/* Math functions */
double tor_mathlog(double d) ATTR_CONST;
long tor_lround(double d) ATTR_CONST;
int64_t tor_llround(double d) ATTR_CONST;
int64_t sample_laplace_distribution(double mu, double b, double p);
int64_t add_laplace_noise(int64_t signal, double random, double delta_f,
                          double epsilon);
int64_t clamp_double_to_int64(double number);

/* String manipulation */

const char *hex_str(const char *from, size_t fromlen) ATTR_NONNULL((1));

int string_is_key_value(int severity, const char *string);

char *tor_escape_str_for_pt_args(const char *string,
                                 const char *chars_to_escape);

/* Time helpers */
long tv_udiff(const struct timeval *start, const struct timeval *end);
long tv_mdiff(const struct timeval *start, const struct timeval *end);
int64_t tv_to_msec(const struct timeval *tv);
int tor_timegm(const struct tm *tm, time_t *time_out);
#define RFC1123_TIME_LEN 29
void format_rfc1123_time(char *buf, time_t t);
int parse_rfc1123_time(const char *buf, time_t *t);
#define ISO_TIME_LEN 19
#define ISO_TIME_USEC_LEN (ISO_TIME_LEN+7)
void format_local_iso_time(char *buf, time_t t);
void format_iso_time(char *buf, time_t t);
void format_local_iso_time_nospace(char *buf, time_t t);
void format_iso_time_nospace(char *buf, time_t t);
void format_iso_time_nospace_usec(char *buf, const struct timeval *tv);
int parse_iso_time_(const char *cp, time_t *t, int strict, int nospace);
int parse_iso_time(const char *buf, time_t *t);
int parse_iso_time_nospace(const char *cp, time_t *t);
int parse_http_time(const char *buf, struct tm *tm);
int format_time_interval(char *out, size_t out_len, long interval);

/* File helpers */

#define write_all(fd, buf, count, isSock) \
  ((isSock) ? write_all_to_socket((fd), (buf), (count)) \
            : write_all_to_fd((int)(fd), (buf), (count)))
#define read_all(fd, buf, count, isSock) \
  ((isSock) ? read_all_from_socket((fd), (buf), (count)) \
            : read_all_from_fd((int)(fd), (buf), (count)))

/** Status of an I/O stream. */
enum stream_status {
  IO_STREAM_OKAY,
  IO_STREAM_EAGAIN,
  IO_STREAM_TERM,
  IO_STREAM_CLOSED
};

const char *stream_status_to_string(enum stream_status stream_status);

enum stream_status get_string_from_pipe(int fd, char *buf, size_t count);

const char *unescape_string(const char *s, char **result, size_t *size_out);

/* Process helpers */
void start_daemon(void);
void finish_daemon(const char *desired_cwd);
int write_pidfile(const char *filename);

void tor_disable_spawning_background_processes(void);

typedef struct process_handle_t process_handle_t;
typedef struct process_environment_t process_environment_t;
int tor_spawn_background(const char *const filename, const char **argv,
                         process_environment_t *env,
                         process_handle_t **process_handle_out);

#define SPAWN_ERROR_MESSAGE "ERR: Failed to spawn background process - code "

#ifdef _WIN32
HANDLE load_windows_system_library(const TCHAR *library_name);
#endif

int environment_variable_names_equal(const char *s1, const char *s2);

/* DOCDOC process_environment_t */
struct process_environment_t {
  /** A pointer to a sorted empty-string-terminated sequence of
   * NUL-terminated strings of the form "NAME=VALUE". */
  char *windows_environment_block;
  /** A pointer to a NULL-terminated array of pointers to
   * NUL-terminated strings of the form "NAME=VALUE". */
  char **unixoid_environment_block;
};

process_environment_t *process_environment_make(struct smartlist_t *env_vars);
void process_environment_free_(process_environment_t *env);
#define process_environment_free(env) \
  FREE_AND_NULL(process_environment_t, process_environment_free_, (env))

struct smartlist_t *get_current_process_environment_variables(void);

void set_environment_variable_in_smartlist(struct smartlist_t *env_vars,
                                           const char *new_var,
                                           void (*free_old)(void*),
                                           int free_p);

/* Values of process_handle_t.status. */
#define PROCESS_STATUS_NOTRUNNING 0
#define PROCESS_STATUS_RUNNING 1
#define PROCESS_STATUS_ERROR -1

#ifdef UTIL_PRIVATE
struct waitpid_callback_t;
/** Structure to represent the state of a process with which Tor is
 * communicating. The contents of this structure are private to util.c */
struct process_handle_t {
  /** One of the PROCESS_STATUS_* values */
  int status;
#ifdef _WIN32
  HANDLE stdin_pipe;
  HANDLE stdout_pipe;
  HANDLE stderr_pipe;
  PROCESS_INFORMATION pid;
#else /* !(defined(_WIN32)) */
  int stdin_pipe;
  int stdout_pipe;
  int stderr_pipe;
  pid_t pid;
  /** If the process has not given us a SIGCHLD yet, this has the
   * waitpid_callback_t that gets invoked once it has. Otherwise this
   * contains NULL. */
  struct waitpid_callback_t *waitpid_cb;
  /** The exit status reported by waitpid. */
  int waitpid_exit_status;
#endif /* defined(_WIN32) */
};
#endif /* defined(UTIL_PRIVATE) */

/* Return values of tor_get_exit_code() */
#define PROCESS_EXIT_RUNNING 1
#define PROCESS_EXIT_EXITED 0
#define PROCESS_EXIT_ERROR -1
int tor_get_exit_code(process_handle_t *process_handle,
                      int block, int *exit_code);
int tor_split_lines(struct smartlist_t *sl, char *buf, int len);
#ifdef _WIN32
ssize_t tor_read_all_handle(HANDLE h, char *buf, size_t count,
                            const process_handle_t *process);
#else
ssize_t tor_read_all_handle(int fd, char *buf, size_t count,
                            const process_handle_t *process,
                            int *eof);
#endif /* defined(_WIN32) */
ssize_t tor_read_all_from_process_stdout(
    const process_handle_t *process_handle, char *buf, size_t count);
ssize_t tor_read_all_from_process_stderr(
    const process_handle_t *process_handle, char *buf, size_t count);
char *tor_join_win_cmdline(const char *argv[]);

int tor_process_get_pid(process_handle_t *process_handle);
#ifdef _WIN32
HANDLE tor_process_get_stdout_pipe(process_handle_t *process_handle);
#else
int tor_process_get_stdout_pipe(process_handle_t *process_handle);
#endif

#ifdef _WIN32
MOCK_DECL(struct smartlist_t *,
tor_get_lines_from_handle,(HANDLE *handle,
                           enum stream_status *stream_status));
#else
MOCK_DECL(struct smartlist_t *,
tor_get_lines_from_handle,(int fd,
                           enum stream_status *stream_status));
#endif /* defined(_WIN32) */

int
tor_terminate_process(process_handle_t *process_handle);

MOCK_DECL(void,
tor_process_handle_destroy,(process_handle_t *process_handle,
                            int also_terminate_process));

/* ===== Insecure rng */
typedef struct tor_weak_rng_t {
  uint32_t state;
} tor_weak_rng_t;

#define TOR_WEAK_RNG_INIT {383745623}
#define TOR_WEAK_RANDOM_MAX (INT_MAX)
void tor_init_weak_random(tor_weak_rng_t *weak_rng, unsigned seed);
int32_t tor_weak_random(tor_weak_rng_t *weak_rng);
int32_t tor_weak_random_range(tor_weak_rng_t *rng, int32_t top);
/** Randomly return true according to <b>rng</b> with probability 1 in
 * <b>n</b> */
#define tor_weak_random_one_in_n(rng, n) (0==tor_weak_random_range((rng),(n)))

#ifdef UTIL_PRIVATE
/* Prototypes for private functions only used by util.c (and unit tests) */

#ifndef _WIN32
STATIC int format_helper_exit_status(unsigned char child_state,
                              int saved_errno, char *hex_errno);

/* Space for hex values of child state, a slash, saved_errno (with
   leading minus) and newline (no null) */
#define HEX_ERRNO_SIZE (sizeof(char) * 2 + 1 + \
                        1 + sizeof(int) * 2 + 1)
#endif /* !defined(_WIN32) */

#endif /* defined(UTIL_PRIVATE) */

#endif /* !defined(TOR_UTIL_H) */
