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

#include "orconfig.h"
#include "torint.h"

#ifndef SYS_SECCOMP

/**
 * Used by SIGSYS signal handler to check if the signal was issued due to a
 * seccomp2 filter violation.
 */
#define SYS_SECCOMP 1

#endif

#if defined(HAVE_SECCOMP_H) && defined(__linux__)
#define USE_LIBSECCOMP
#endif

/**
 * Linux definitions
 */
#ifdef USE_LIBSECCOMP

#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <sys/ucontext.h>
#include <seccomp.h>
#include <netdb.h>

#define PARAM_PTR 0
#define PARAM_NUM 1

/**
 * Enum used to manage the type of the implementation for general purpose.
 */
typedef enum {
  /** Libseccomp implementation based on seccomp2*/
  LIBSECCOMP2 = 0
} SB_IMPL;

/**
 *  Configuration parameter structure associated with the LIBSECCOMP2
 *  implementation.
 */
typedef struct smp_param {
  /** syscall associated with parameter. */
  int syscall;

  /** parameter index. */
  int pindex;
  /** parameter value. */
  intptr_t value;

  /**  parameter flag (0 = not protected, 1 = protected). */
  int prot;
} smp_param_t;

/**
 * Structure used to manage a sandbox configuration.
 *
 * It is implemented as a linked list of parameters. Currently only controls
 * parameters for open, openat, execve, stat64.
 */
struct sandbox_cfg_elem {
  /** Sandbox implementation which dictates the parameter type. */
  SB_IMPL implem;

  /** Configuration parameter. */
  void *param;

  /** Next element of the configuration*/
  struct sandbox_cfg_elem *next;
};
/** Typedef to structure used to manage a sandbox configuration. */
typedef struct sandbox_cfg_elem sandbox_cfg_t;

/**
 * Structure used for keeping a linked list of getaddrinfo pre-recorded
 * results.
 */
struct sb_addr_info_el {
  /** Name of the address info result. */
  char *name;
  /** Pre-recorded getaddrinfo result. */
  struct addrinfo *info;
  /** Next element in the list. */
  struct sb_addr_info_el *next;
};
/** Typedef to structure used to manage an addrinfo list. */
typedef struct sb_addr_info_el sb_addr_info_t;

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

#endif // USE_LIBSECCOMP

#ifdef USE_LIBSECCOMP
/** Pre-calls getaddrinfo in order to pre-record result. */
int sandbox_add_addrinfo(const char *addr);

struct addrinfo;
/** Replacement for getaddrinfo(), using pre-recorded results. */
int sandbox_getaddrinfo(const char *name, const char *servname,
                        const struct addrinfo *hints,
                        struct addrinfo **res);
#else
#define sandbox_getaddrinfo(name, servname, hints, res)  \
  getaddrinfo((name),(servname), (hints),(res))
#define sandbox_add_addrinfo(name) \
  ((void)(name))
#endif

/** Use <b>fd</b> to log non-survivable sandbox violations. */
void sandbox_set_debugging_fd(int fd);

#ifdef USE_LIBSECCOMP
/** Returns a registered protected string used with the sandbox, given that
 * it matches the parameter.
 */
const char* sandbox_intern_string(const char *param);
#else
#define sandbox_intern_string(s) (s)
#endif

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
 *  @param ... all future parameters are specified as pairs of <(char*), 1 / 0>
 *    the char* specifies the path to the allowed file, 1 tells the function
 *    that the char* needs to be free-ed, 0 means the pointer does not need to
 *    be free-ed; the final parameter needs to be <NULL, 0>.
 */
int sandbox_cfg_allow_open_filename_array(sandbox_cfg_t **cfg, ...);

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
 *  @param ... all future parameters are specified as pairs of <(char*), 1 / 0>
 *    the char* specifies the path to the allowed file, 1 tells the function
 *    that the char* needs to be free-ed, 0 means the pointer does not need to
 *    be free-ed; the final parameter needs to be <NULL, 0>.
 */
int sandbox_cfg_allow_openat_filename_array(sandbox_cfg_t **cfg, ...);

/**
 * Function used to add a execve allowed filename to a supplied configuration.
 * The (char*) specifies the path to the allowed file, fr = 1 tells the
 * function that the char* needs to be free-ed, 0 means the pointer does not
 * need to be free-ed.
 */
int sandbox_cfg_allow_execve(sandbox_cfg_t **cfg, const char *com);

/** Function used to add a series of execve allowed filenames to a supplied
 * configuration.
 *  @param cfg  sandbox configuration.
 *  @param ... all future parameters are specified as pairs of <(char*), 1 / 0>
 *    the char* specifies the path to the allowed file, 1 tells the function
 *    that the char* needs to be free-ed, 0 means the pointer does not need to
 *    be free-ed; the final parameter needs to be <NULL, 0>.
 */
int sandbox_cfg_allow_execve_array(sandbox_cfg_t **cfg, ...);

/**
 * Function used to add a stat/stat64 allowed filename to a configuration.
 * The (char*) specifies the path to the allowed file, fr = 1 tells the
 * function that the char* needs to be free-ed, 0 means the pointer does not
 * need to be free-ed.
 */
int sandbox_cfg_allow_stat_filename(sandbox_cfg_t **cfg, char *file,
    int fr);

/** Function used to add a series of stat64 allowed filenames to a supplied
 * configuration.
 *  @param cfg  sandbox configuration.
 *  @param ... all future parameters are specified as pairs of <(char*), 1 / 0>
 *    the char* specifies the path to the allowed file, 1 tells the function
 *    that the char* needs to be free-ed, 0 means the pointer does not need to
 *    be free-ed; the final parameter needs to be <NULL, 0>.
 */
int sandbox_cfg_allow_stat_filename_array(sandbox_cfg_t **cfg, ...);

/** Function used to initialise a sandbox configuration.*/
int sandbox_init(sandbox_cfg_t* cfg);

#endif /* SANDBOX_H_ */

