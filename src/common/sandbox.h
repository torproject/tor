/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file sandbox.h
 * \brief Header file for sandbox.c.
 **/

#ifndef SANDBOX_H_
#define SANDBOX_H_

#ifndef SYS_SECCOMP

/**
 * Used by SIGSYS signal handler to check if the signal was issued due to a
 * seccomp2 filter violation.
 */
#define SYS_SECCOMP 1

#endif

#include "torint.h"

/**
 * Linux definitions
 */
#ifdef __linux__

#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <sys/ucontext.h>
#include <seccomp.h>
#include <netdb.h>

#define PARAM_PTR 0
#define PARAM_NUM 1

/**
 * Structure used to manage a sandbox configuration.
 *
 * It is implemented as a linked list of parameters. Currently only controls
 * parameters for open, openat, execve, stat64.
 */
struct pfd_elem {
  /** syscall associated with parameter. */
  int syscall;

  /** parameter index. */
  int pindex;
  /** parameter value. */
  intptr_t param;

  /**  parameter flag (0 = not protected, 1 = protected). */
  int prot;

  struct pfd_elem *next;
};
/** Typedef to structure used to manage a sandbox configuration. */
typedef struct pfd_elem sandbox_cfg_t;

/** Function pointer defining the prototype of a filter function.*/
typedef int (*sandbox_filter_func_t)(scmp_filter_ctx ctx,
    sandbox_cfg_t *filter);

/** Type that will be used in step 3 in order to manage multiple sandboxes.*/
typedef struct {
  /** function pointers associated with the filter */
  sandbox_filter_func_t *filter_func;

  /** filter function pointer parameters */
  sandbox_cfg_t *filter_dynamic;
} sandbox_t;

/**
 * Linux 32 bit definitions
 */
#if defined(__i386__)

#define REG_SYSCALL REG_EAX

/**
 * Linux 64 bit definitions
 */
#elif defined(__x86_64__)

#define REG_SYSCALL REG_RAX

#endif

#endif // __linux__

/** Replacement for getaddrinfo(), using pre-recorded results. */
int sandbox_getaddrinfo(const char *name, struct addrinfo **res);

/** Use <b>fd</b> to log non-survivable sandbox violations. */
void sandbox_set_debugging_fd(int fd);

/** Returns a registered protected string used with the sandbox, given that
 * it matches the parameter.
 */
const char* sandbox_intern_string(const char *param);

/** Creates an empty sandbox configuration file.*/
sandbox_cfg_t * sandbox_cfg_new(void);

/**
 * Function used to add a open allowed filename to a supplied configuration.
 * The (char*) specifies the path to the allowed file, fr = 1 tells the
 * function that the char* needs to be free-ed, 0 means the pointer does not
 * need to be free-ed.
 */
int sandbox_cfg_allow_open_filename(sandbox_cfg_t **cfg, char *file,
    int fr);

/** Function used to add a series of open allowed filenames to a supplied
 * configuration.
 *  @param cfg  sandbox configuration.
 *  @param num  number of files.
 *  @param ... all future parameters are specified as pairs of <(char*), 1 / 0>
 *    the char* specifies the path to the allowed file, 1 tells the function
 *    that the char* needs to be free-ed, 0 means the pointer does not need to
 *    be free-ed.
 */
int sandbox_cfg_allow_open_filename_array(sandbox_cfg_t **cfg, int num, ...);

/**
 * Function used to add a openat allowed filename to a supplied configuration.
 * The (char*) specifies the path to the allowed file, fr = 1 tells the
 * function that the char* needs to be free-ed, 0 means the pointer does not
 * need to be free-ed.
 */
int sandbox_cfg_allow_openat_filename(sandbox_cfg_t **cfg, char *file,
    int fr);

/** Function used to add a series of openat allowed filenames to a supplied
 * configuration.
 *  @param cfg  sandbox configuration.
 *  @param num  number of files.
 *  @param ... all future parameters are specified as pairs of <(char*), 1 / 0>
 *    the char* specifies the path to the allowed file, 1 tells the function
 *    that the char* needs to be free-ed, 0 means the pointer does not need to
 *    be free-ed.
 */
int sandbox_cfg_allow_openat_filename_array(sandbox_cfg_t **cfg, int num, ...);

/**
 * Function used to add a execve allowed filename to a supplied configuration.
 * The (char*) specifies the path to the allowed file, fr = 1 tells the
 * function that the char* needs to be free-ed, 0 means the pointer does not
 * need to be free-ed.
 */
int sandbox_cfg_allow_execve(sandbox_cfg_t **cfg, char *com);

/** Function used to add a series of execve allowed filenames to a supplied
 * configuration.
 *  @param cfg  sandbox configuration.
 *  @param num  number of files.
 *  @param ... all future parameters are specified as pairs of <(char*), 1 / 0>
 *    the char* specifies the path to the allowed file, 1 tells the function
 *    that the char* needs to be free-ed, 0 means the pointer does not need to
 *    be free-ed.
 */
int sandbox_cfg_allow_execve_array(sandbox_cfg_t **cfg, int num, ...);

/**
 * Function used to add a stat64 allowed filename to a supplied configuration.
 * The (char*) specifies the path to the allowed file, fr = 1 tells the
 * function that the char* needs to be free-ed, 0 means the pointer does not
 * need to be free-ed.
 */
int sandbox_cfg_allow_stat64_filename(sandbox_cfg_t **cfg, char *file,
    int fr);

/** Function used to add a series of stat64 allowed filenames to a supplied
 * configuration.
 *  @param cfg  sandbox configuration.
 *  @param num  number of files.
 *  @param ... all future parameters are specified as pairs of <(char*), 1 / 0>
 *    the char* specifies the path to the allowed file, 1 tells the function
 *    that the char* needs to be free-ed, 0 means the pointer does not need to
 *    be free-ed.
 */
int sandbox_cfg_allow_stat64_filename_array(sandbox_cfg_t **cfg,
    int num, ...);

/** Function used to initialise a sandbox configuration.*/
int sandbox_init(sandbox_cfg_t* cfg);

#endif /* SANDBOX_H_ */

