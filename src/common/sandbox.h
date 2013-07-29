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

#define __USE_GNU
#include <sys/ucontext.h>

#define MAX_PARAM_LEN 64

#define PARAM_PTR 0
#define PARAM_NUM 1

typedef struct {
  int syscall;

  char ptype;
  char pindex;
  intptr_t param;

  char prot;
} sandbox_static_cfg_t;

struct pfd_elem {
  int syscall;

  char ptype;
  char pindex;
  intptr_t param;

  char prot;

  struct pfd_elem *next;
};
typedef struct pfd_elem sandbox_cfg_t;

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

void sandbox_set_debugging_fd(int fd);
int tor_global_sandbox(void);
const char* sandbox_intern_string(char *param);

sandbox_cfg_t * sandbox_cfg_new();
int sandbox_cfg_allow_open_filename(sandbox_cfg_t **cfg, char *file);
int sandbox_init(sandbox_cfg_t* cfg);

#endif /* SANDBOX_H_ */

