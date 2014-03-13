/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file sandbox.c
 * \brief Code to enable sandboxing.
 **/

#include "orconfig.h"

#ifndef _LARGEFILE64_SOURCE
/**
 * Temporarily required for O_LARGEFILE flag. Needs to be removed
 * with the libevent fix.
 */
#define _LARGEFILE64_SOURCE
#endif

/** Malloc mprotect limit in bytes. */
#define MALLOC_MP_LIM 1048576

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sandbox.h"
#include "torlog.h"
#include "torint.h"
#include "util.h"
#include "tor_queue.h"

#define DEBUGGING_CLOSE

#if defined(USE_LIBSECCOMP)

#define _GNU_SOURCE

#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <linux/futex.h>
#include <bits/signum.h>
#include <event2/event.h>

#include <stdarg.h>
#include <seccomp.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>

/**Determines if at least one sandbox is active.*/
static int sandbox_active = 0;
/** Holds the parameter list configuration for the sandbox.*/
static sandbox_cfg_t *filter_dynamic = NULL;
/** Holds a list of pre-recorded results from getaddrinfo().*/
static sb_addr_info_t *sb_addr_info = NULL;

#undef SCMP_CMP
#define SCMP_CMP(a,b,c) ((struct scmp_arg_cmp){(a),(b),(c),0})

/** Variable used for storing all syscall numbers that will be allowed with the
 * stage 1 general Tor sandbox.
 */
static int filter_nopar_gen[] = {
    SCMP_SYS(access),
    SCMP_SYS(brk),
    SCMP_SYS(clock_gettime),
    SCMP_SYS(close),
    SCMP_SYS(clone),
    SCMP_SYS(epoll_create),
    SCMP_SYS(epoll_wait),
    SCMP_SYS(fcntl),
    SCMP_SYS(fstat),
#ifdef __NR_fstat64
    SCMP_SYS(fstat64),
#endif
    SCMP_SYS(getdents64),
    SCMP_SYS(getegid),
#ifdef __NR_getegid32
    SCMP_SYS(getegid32),
#endif
    SCMP_SYS(geteuid),
#ifdef __NR_geteuid32
    SCMP_SYS(geteuid32),
#endif
    SCMP_SYS(getgid),
#ifdef __NR_getgid32
    SCMP_SYS(getgid32),
#endif
    SCMP_SYS(getrlimit),
    SCMP_SYS(gettimeofday),
    SCMP_SYS(getuid),
#ifdef __NR_getuid32
    SCMP_SYS(getuid32),
#endif
    SCMP_SYS(lseek),
#ifdef __NR__llseek
    SCMP_SYS(_llseek),
#endif
    SCMP_SYS(mkdir),
    SCMP_SYS(mlockall),
    SCMP_SYS(mmap),
    SCMP_SYS(munmap),
    SCMP_SYS(read),
    SCMP_SYS(rename),
    SCMP_SYS(rt_sigreturn),
    SCMP_SYS(set_robust_list),
#ifdef __NR_sigreturn
    SCMP_SYS(sigreturn),
#endif
    SCMP_SYS(stat),
    SCMP_SYS(uname),
    SCMP_SYS(write),
    SCMP_SYS(exit_group),
    SCMP_SYS(exit),

    SCMP_SYS(madvise),
#ifdef __NR_stat64
    // getaddrinfo uses this..
    SCMP_SYS(stat64),
#endif

    /*
     * These socket syscalls are not required on x86_64 and not supported with
     * some libseccomp versions (eg: 1.0.1)
     */
#if defined(__i386)
    SCMP_SYS(recv),
    SCMP_SYS(send),
#endif

    // socket syscalls
    SCMP_SYS(bind),
    SCMP_SYS(connect),
    SCMP_SYS(getsockname),
    SCMP_SYS(recvmsg),
    SCMP_SYS(recvfrom),
    SCMP_SYS(sendto),
    SCMP_SYS(unlink)
};

/**
 * Function responsible for setting up the rt_sigaction syscall for
 * the seccomp filter sandbox.
 */
static int
sb_rt_sigaction(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  unsigned i;
  int rc;
  int param[] = { SIGINT, SIGTERM, SIGPIPE, SIGUSR1, SIGUSR2, SIGHUP, SIGCHLD,
#ifdef SIGXFSZ
      SIGXFSZ
#endif
      };
  (void) filter;

  for (i = 0; i < ARRAY_LENGTH(param); i++) {
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 1,
        SCMP_CMP(0, SCMP_CMP_EQ, param[i]));
    if (rc)
      break;
  }

  return rc;
}

/**
 * Function responsible for setting up the execve syscall for
 * the seccomp filter sandbox.
 */
static int
sb_execve(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  int rc;
  sandbox_cfg_t *elem = NULL;

  // for each dynamic parameter filters
  for (elem = filter; elem != NULL; elem = elem->next) {
    smp_param_t *param = (smp_param_t*) elem->param;

    if (param != NULL && param->prot == 1 && param->syscall
        == SCMP_SYS(execve)) {
      rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 1,
          SCMP_CMP(0, SCMP_CMP_EQ, param->value));
      if (rc != 0) {
        log_err(LD_BUG,"(Sandbox) failed to add execve syscall, received "
            "libseccomp error %d", rc);
        return rc;
      }
    }
  }

  return 0;
}

/**
 * Function responsible for setting up the time syscall for
 * the seccomp filter sandbox.
 */
static int
sb_time(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  (void) filter;
  return seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(time), 1,
       SCMP_CMP(0, SCMP_CMP_EQ, 0));
}

/**
 * Function responsible for setting up the accept4 syscall for
 * the seccomp filter sandbox.
 */
static int
sb_accept4(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  int rc = 0;
  (void)filter;

#ifdef __i386__
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socketcall), 1,
      SCMP_CMP(0, SCMP_CMP_EQ, 18));
  if (rc) {
    return rc;
  }
#endif

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept4), 1,
      SCMP_CMP(3, SCMP_CMP_EQ, SOCK_CLOEXEC));
  if (rc) {
    return rc;
  }

  return 0;
}

#ifdef __NR_mmap2
/**
 * Function responsible for setting up the mmap2 syscall for
 * the seccomp filter sandbox.
 */
static int
sb_mmap2(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  int rc = 0;
  (void)filter;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap2), 2,
       SCMP_CMP(2, SCMP_CMP_EQ, PROT_READ),
       SCMP_CMP(3, SCMP_CMP_EQ, MAP_PRIVATE));
  if (rc) {
    return rc;
  }

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap2), 2,
       SCMP_CMP(2, SCMP_CMP_EQ, PROT_NONE),
       SCMP_CMP(3, SCMP_CMP_EQ, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE));
  if (rc) {
    return rc;
  }

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap2), 2,
       SCMP_CMP(2, SCMP_CMP_EQ, PROT_READ|PROT_WRITE),
       SCMP_CMP(3, SCMP_CMP_EQ, MAP_PRIVATE|MAP_ANONYMOUS));
  if (rc) {
    return rc;
  }

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap2), 2,
       SCMP_CMP(2, SCMP_CMP_EQ, PROT_READ|PROT_WRITE),
       SCMP_CMP(3, SCMP_CMP_EQ,MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK));
  if (rc) {
    return rc;
  }

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap2), 2,
      SCMP_CMP(2, SCMP_CMP_EQ, PROT_READ|PROT_WRITE),
      SCMP_CMP(3, SCMP_CMP_EQ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE));
  if (rc) {
    return rc;
  }

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap2), 2,
      SCMP_CMP(2, SCMP_CMP_EQ, PROT_READ|PROT_WRITE),
      SCMP_CMP(3, SCMP_CMP_EQ, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS));
  if (rc) {
    return rc;
  }

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap2), 2,
      SCMP_CMP(2, SCMP_CMP_EQ, PROT_READ|PROT_EXEC),
      SCMP_CMP(3, SCMP_CMP_EQ, MAP_PRIVATE|MAP_DENYWRITE));
  if (rc) {
    return rc;
  }

  return 0;
}
#endif

/**
 * Function responsible for setting up the open syscall for
 * the seccomp filter sandbox.
 */
static int
sb_open(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  int rc;
  sandbox_cfg_t *elem = NULL;

  // for each dynamic parameter filters
  for (elem = filter; elem != NULL; elem = elem->next) {
    smp_param_t *param = elem->param;

    if (param != NULL && param->prot == 1 && param->syscall
        == SCMP_SYS(open)) {
      rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
            SCMP_CMP(0, SCMP_CMP_EQ, param->value));
      if (rc != 0) {
        log_err(LD_BUG,"(Sandbox) failed to add open syscall, received "
            "libseccomp error %d", rc);
        return rc;
      }
    }
  }

  rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(-1), SCMP_SYS(open), 1,
        SCMP_CMP(1, SCMP_CMP_EQ, O_RDONLY|O_CLOEXEC));
  if (rc != 0) {
    log_err(LD_BUG,"(Sandbox) failed to add open syscall, received libseccomp "
        "error %d", rc);
    return rc;
  }

  return 0;
}

/**
 * Function responsible for setting up the openat syscall for
 * the seccomp filter sandbox.
 */
static int
sb_openat(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  int rc;
  sandbox_cfg_t *elem = NULL;

  // for each dynamic parameter filters
  for (elem = filter; elem != NULL; elem = elem->next) {
    smp_param_t *param = elem->param;

    if (param != NULL && param->prot == 1 && param->syscall
        == SCMP_SYS(openat)) {
      rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 1,
          SCMP_CMP(0, SCMP_CMP_EQ, AT_FDCWD),
          SCMP_CMP(1, SCMP_CMP_EQ, param->value),
          SCMP_CMP(2, SCMP_CMP_EQ, O_RDONLY|O_NONBLOCK|O_LARGEFILE|O_DIRECTORY|
              O_CLOEXEC));
      if (rc != 0) {
        log_err(LD_BUG,"(Sandbox) failed to add openat syscall, received "
            "libseccomp error %d", rc);
        return rc;
      }
    }
  }

  return 0;
}

/**
 * Function responsible for setting up the socket syscall for
 * the seccomp filter sandbox.
 */
static int
sb_socket(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  int rc = 0;
  (void) filter;

#ifdef __i386__
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
  if (rc)
    return rc;
#endif

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 3,
      SCMP_CMP(0, SCMP_CMP_EQ, PF_FILE),
      SCMP_CMP(1, SCMP_CMP_EQ, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK),
      SCMP_CMP(2, SCMP_CMP_EQ, IPPROTO_IP));
  if (rc)
    return rc;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 3,
      SCMP_CMP(0, SCMP_CMP_EQ, PF_INET),
      SCMP_CMP(1, SCMP_CMP_EQ, SOCK_STREAM|SOCK_CLOEXEC),
      SCMP_CMP(2, SCMP_CMP_EQ, IPPROTO_TCP));
  if (rc)
    return rc;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 3,
      SCMP_CMP(0, SCMP_CMP_EQ, PF_INET),
      SCMP_CMP(1, SCMP_CMP_EQ, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK),
      SCMP_CMP(2, SCMP_CMP_EQ, IPPROTO_TCP));
  if (rc)
    return rc;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 3,
      SCMP_CMP(0, SCMP_CMP_EQ, PF_INET),
      SCMP_CMP(1, SCMP_CMP_EQ, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK),
      SCMP_CMP(2, SCMP_CMP_EQ, IPPROTO_IP));
  if (rc)
    return rc;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 3,
      SCMP_CMP(0, SCMP_CMP_EQ, PF_NETLINK),
      SCMP_CMP(1, SCMP_CMP_EQ, SOCK_RAW),
      SCMP_CMP(2, SCMP_CMP_EQ, 0));
  if (rc)
    return rc;

  return 0;
}

/**
 * Function responsible for setting up the socketpair syscall for
 * the seccomp filter sandbox.
 */
static int
sb_socketpair(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  int rc = 0;
  (void) filter;

#ifdef __i386__
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socketpair), 0);
  if (rc)
    return rc;
#endif

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socketpair), 2,
      SCMP_CMP(0, SCMP_CMP_EQ, PF_FILE),
      SCMP_CMP(1, SCMP_CMP_EQ, SOCK_STREAM|SOCK_CLOEXEC));
  if (rc)
    return rc;

  return 0;
}

/**
 * Function responsible for setting up the setsockopt syscall for
 * the seccomp filter sandbox.
 */
static int
sb_setsockopt(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  int rc = 0;
  (void) filter;

#ifdef __i386__
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 0);
  if (rc)
    return rc;
#endif

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 2,
      SCMP_CMP(1, SCMP_CMP_EQ, SOL_SOCKET),
      SCMP_CMP(2, SCMP_CMP_EQ, SO_REUSEADDR));
  if (rc)
    return rc;

#ifdef IP_TRANSPARENT
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 2,
      SCMP_CMP(1, SCMP_CMP_EQ, SOL_IP),
      SCMP_CMP(2, SCMP_CMP_EQ, IP_TRANSPARENT));
  if (rc)
    return rc;
#endif

  return 0;
}

/**
 * Function responsible for setting up the getsockopt syscall for
 * the seccomp filter sandbox.
 */
static int
sb_getsockopt(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  int rc = 0;
  (void) filter;

#ifdef __i386__
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 0);
  if (rc)
    return rc;
#endif

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 2,
      SCMP_CMP(1, SCMP_CMP_EQ, SOL_SOCKET),
      SCMP_CMP(2, SCMP_CMP_EQ, SO_ERROR));
  if (rc)
    return rc;

  return 0;
}

#ifdef __NR_fcntl64
/**
 * Function responsible for setting up the fcntl64 syscall for
 * the seccomp filter sandbox.
 */
static int
sb_fcntl64(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  int rc = 0;
  (void) filter;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl64), 1,
      SCMP_CMP(1, SCMP_CMP_EQ, F_GETFL));
  if (rc)
    return rc;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl64), 2,
      SCMP_CMP(1, SCMP_CMP_EQ, F_SETFL),
      SCMP_CMP(2, SCMP_CMP_EQ, O_RDWR|O_NONBLOCK));
  if (rc)
    return rc;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl64), 1,
      SCMP_CMP(1, SCMP_CMP_EQ, F_GETFD));
  if (rc)
    return rc;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl64), 2,
      SCMP_CMP(1, SCMP_CMP_EQ, F_SETFD),
      SCMP_CMP(2, SCMP_CMP_EQ, FD_CLOEXEC));
  if (rc)
    return rc;

  return 0;
}
#endif

/**
 * Function responsible for setting up the epoll_ctl syscall for
 * the seccomp filter sandbox.
 *
 *  Note: basically allows everything but will keep for now..
 */
static int
sb_epoll_ctl(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  int rc = 0;
  (void) filter;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 1,
      SCMP_CMP(1, SCMP_CMP_EQ, EPOLL_CTL_ADD));
  if (rc)
    return rc;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 1,
      SCMP_CMP(1, SCMP_CMP_EQ, EPOLL_CTL_MOD));
  if (rc)
    return rc;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 1,
      SCMP_CMP(1, SCMP_CMP_EQ, EPOLL_CTL_DEL));
  if (rc)
    return rc;

  return 0;
}

/**
 * Function responsible for setting up the fcntl64 syscall for
 * the seccomp filter sandbox.
 *
 * NOTE: if multiple filters need to be added, the PR_SECCOMP parameter needs
 * to be whitelisted in this function.
 */
static int
sb_prctl(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  int rc = 0;
  (void) filter;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 1,
      SCMP_CMP(0, SCMP_CMP_EQ, PR_SET_DUMPABLE));
  if (rc)
    return rc;

  return 0;
}

/**
 * Function responsible for setting up the fcntl64 syscall for
 * the seccomp filter sandbox.
 *
 * NOTE: does not NEED to be here.. currently only occurs before filter; will
 * keep just in case for the future.
 */
static int
sb_mprotect(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  int rc = 0;
  (void) filter;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 1,
      SCMP_CMP(2, SCMP_CMP_EQ, PROT_READ));
  if (rc)
    return rc;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 1,
      SCMP_CMP(2, SCMP_CMP_EQ, PROT_NONE));
  if (rc)
    return rc;

  return 0;
}

/**
 * Function responsible for setting up the rt_sigprocmask syscall for
 * the seccomp filter sandbox.
 */
static int
sb_rt_sigprocmask(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  int rc = 0;
  (void) filter;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 1,
      SCMP_CMP(0, SCMP_CMP_EQ, SIG_UNBLOCK));
  if (rc)
    return rc;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 1,
      SCMP_CMP(0, SCMP_CMP_EQ, SIG_SETMASK));
  if (rc)
    return rc;

  return 0;
}

/**
 * Function responsible for setting up the flock syscall for
 * the seccomp filter sandbox.
 *
 *  NOTE: does not need to be here, occurs before filter is applied.
 */
static int
sb_flock(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  int rc = 0;
  (void) filter;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(flock), 1,
      SCMP_CMP(1, SCMP_CMP_EQ, LOCK_EX|LOCK_NB));
  if (rc)
    return rc;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(flock), 1,
      SCMP_CMP(1, SCMP_CMP_EQ, LOCK_UN));
  if (rc)
    return rc;

  return 0;
}

/**
 * Function responsible for setting up the futex syscall for
 * the seccomp filter sandbox.
 */
static int
sb_futex(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  int rc = 0;
  (void) filter;

  // can remove
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 1,
      SCMP_CMP(1, SCMP_CMP_EQ,
          FUTEX_WAIT_BITSET_PRIVATE|FUTEX_CLOCK_REALTIME));
  if (rc)
    return rc;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 1,
      SCMP_CMP(1, SCMP_CMP_EQ, FUTEX_WAKE_PRIVATE));
  if (rc)
    return rc;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 1,
      SCMP_CMP(1, SCMP_CMP_EQ, FUTEX_WAIT_PRIVATE));
  if (rc)
    return rc;

  return 0;
}

/**
 * Function responsible for setting up the mremap syscall for
 * the seccomp filter sandbox.
 *
 *  NOTE: so far only occurs before filter is applied.
 */
static int
sb_mremap(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  int rc = 0;
  (void) filter;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mremap), 1,
      SCMP_CMP(3, SCMP_CMP_EQ, MREMAP_MAYMOVE));
  if (rc)
    return rc;

  return 0;
}

/**
 * Function responsible for setting up the poll syscall for
 * the seccomp filter sandbox.
 */
static int
sb_poll(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  int rc = 0;
  (void) filter;

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 2,
      SCMP_CMP(1, SCMP_CMP_EQ, 1),
      SCMP_CMP(2, SCMP_CMP_EQ, 10));
  if (rc)
    return rc;

  return 0;
}

#ifdef __NR_stat64
/**
 * Function responsible for setting up the stat64 syscall for
 * the seccomp filter sandbox.
 */
static int
sb_stat64(scmp_filter_ctx ctx, sandbox_cfg_t *filter)
{
  int rc = 0;
  sandbox_cfg_t *elem = NULL;

  // for each dynamic parameter filters
  for (elem = filter; elem != NULL; elem = elem->next) {
    smp_param_t *param = elem->param;

    if (param != NULL && param->prot == 1 && (param->syscall == SCMP_SYS(open)
        || param->syscall == SCMP_SYS(stat64))) {
      rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat64), 1,
          SCMP_CMP(0, SCMP_CMP_EQ, param->value));
      if (rc != 0) {
        log_err(LD_BUG,"(Sandbox) failed to add open syscall, received "
            "libseccomp  error %d", rc);
        return rc;
      }
    }
  }

  return 0;
}
#endif

/**
 * Array of function pointers responsible for filtering different syscalls at
 * a parameter level.
 */
static sandbox_filter_func_t filter_func[] = {
    sb_rt_sigaction,
    sb_rt_sigprocmask,
    sb_execve,
    sb_time,
    sb_accept4,
#ifdef __NR_mmap2
    sb_mmap2,
#endif
    sb_open,
    sb_openat,
#ifdef __NR_fcntl64
    sb_fcntl64,
#endif
    sb_epoll_ctl,
    sb_prctl,
    sb_mprotect,
    sb_flock,
    sb_futex,
    sb_mremap,
    sb_poll,
#ifdef __NR_stat64
    sb_stat64,
#endif

    sb_socket,
    sb_setsockopt,
    sb_getsockopt,
    sb_socketpair
};

const char*
sandbox_intern_string(const char *str)
{
  sandbox_cfg_t *elem;

  if (str == NULL)
    return NULL;

  for (elem = filter_dynamic; elem != NULL; elem = elem->next) {
    smp_param_t *param = elem->param;

    if (param->prot && !strcmp(str, (char*)(param->value))) {
      return (char*)(param->value);
    }
  }

  log_info(LD_GENERAL, "(Sandbox) Parameter %s not found", str);
  return str;
}

/**
 * Protects all the strings in the sandbox's parameter list configuration. It
 * works by calculating the total amount of memory required by the parameter
 * list, allocating the memory using mmap, and protecting it from writes with
 * mprotect().
 */
static int
prot_strings(scmp_filter_ctx ctx, sandbox_cfg_t* cfg)
{
  int ret = 0;
  size_t pr_mem_size = 0, pr_mem_left = 0;
  char *pr_mem_next = NULL, *pr_mem_base;
  sandbox_cfg_t *el = NULL;

  // get total number of bytes required to mmap
  for (el = cfg; el != NULL; el = el->next) {
    pr_mem_size += strlen((char*) ((smp_param_t*)el->param)->value) + 1;
  }

  // allocate protected memory with MALLOC_MP_LIM canary
  pr_mem_base = (char*) mmap(NULL, MALLOC_MP_LIM + pr_mem_size,
      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  if (pr_mem_base == MAP_FAILED) {
    log_err(LD_BUG,"(Sandbox) failed allocate protected memory! mmap: %s",
        strerror(errno));
    ret = -1;
    goto out;
  }

  pr_mem_next = pr_mem_base + MALLOC_MP_LIM;
  pr_mem_left = pr_mem_size;

  // change el value pointer to protected
  for (el = cfg; el != NULL; el = el->next) {
    char *param_val = (char*)((smp_param_t *)el->param)->value;
    size_t param_size = strlen(param_val) + 1;

    if (pr_mem_left >= param_size) {
      // copy to protected
      memcpy(pr_mem_next, param_val, param_size);

      // re-point el parameter to protected
      {
        void *old_val = (void *) ((smp_param_t*)el->param)->value;
        tor_free(old_val);
      }
      ((smp_param_t*)el->param)->value = (intptr_t) pr_mem_next;
      ((smp_param_t*)el->param)->prot = 1;

      // move next available protected memory
      pr_mem_next += param_size;
      pr_mem_left -= param_size;
    } else {
      log_err(LD_BUG,"(Sandbox) insufficient protected memory!");
      ret = -2;
      goto out;
    }
  }

  // protecting from writes
  if (mprotect(pr_mem_base, MALLOC_MP_LIM + pr_mem_size, PROT_READ)) {
    log_err(LD_BUG,"(Sandbox) failed to protect memory! mprotect: %s",
        strerror(errno));
    ret = -3;
    goto out;
  }

  /*
   * Setting sandbox restrictions so the string memory cannot be tampered with
   */
  // no mremap of the protected base address
  ret = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(mremap), 1,
      SCMP_CMP(0, SCMP_CMP_EQ, (intptr_t) pr_mem_base));
  if (ret) {
    log_err(LD_BUG,"(Sandbox) mremap protected memory filter fail!");
    return ret;
  }

  // no munmap of the protected base address
  ret = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(munmap), 1,
        SCMP_CMP(0, SCMP_CMP_EQ, (intptr_t) pr_mem_base));
  if (ret) {
    log_err(LD_BUG,"(Sandbox) munmap protected memory filter fail!");
    return ret;
  }

  /*
   * Allow mprotect with PROT_READ|PROT_WRITE because openssl uses it, but
   * never over the memory region used by the protected strings.
   *
   * PROT_READ|PROT_WRITE was originally fully allowed in sb_mprotect(), but
   * had to be removed due to limitation of libseccomp regarding intervals.
   *
   * There is a restriction on how much you can mprotect with R|W up to the
   * size of the canary.
   */
  ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 2,
      SCMP_CMP(0, SCMP_CMP_LT, (intptr_t) pr_mem_base),
      SCMP_CMP(1, SCMP_CMP_LE, MALLOC_MP_LIM),
      SCMP_CMP(2, SCMP_CMP_EQ, PROT_READ|PROT_WRITE));
  if (ret) {
    log_err(LD_BUG,"(Sandbox) mprotect protected memory filter fail (LT)!");
    return ret;
  }

  ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 2,
      SCMP_CMP(0, SCMP_CMP_GT, (intptr_t) pr_mem_base + pr_mem_size +
          MALLOC_MP_LIM),
      SCMP_CMP(1, SCMP_CMP_LE, MALLOC_MP_LIM),
      SCMP_CMP(2, SCMP_CMP_EQ, PROT_READ|PROT_WRITE));
  if (ret) {
    log_err(LD_BUG,"(Sandbox) mprotect protected memory filter fail (GT)!");
    return ret;
  }

 out:
   return ret;
}

/**
 * Auxiliary function used in order to allocate a sandbox_cfg_t element and set
 * it's values according the the parameter list. All elements are initialised
 * with the 'prot' field set to false, as the pointer is not protected at this
 * point.
 */
static sandbox_cfg_t*
new_element(int syscall, int index, intptr_t value)
{
  smp_param_t *param = NULL;

  sandbox_cfg_t *elem = tor_malloc(sizeof(sandbox_cfg_t));
  elem->param = tor_malloc(sizeof(smp_param_t));

  param = elem->param;
  param->syscall = syscall;
  param->pindex = index;
  param->value = value;
  param->prot = 0;

  return elem;
}

#ifdef __NR_stat64
#define SCMP_stat SCMP_SYS(stat64)
#else
#define SCMP_stat SCMP_SYS(stat)
#endif

int
sandbox_cfg_allow_stat_filename(sandbox_cfg_t **cfg, char *file, int fr)
{
  sandbox_cfg_t *elem = NULL;

  elem = new_element(SCMP_stat, 0, (intptr_t)(void*) tor_strdup(file));
  if (!elem) {
    log_err(LD_BUG,"(Sandbox) failed to register parameter!");
    return -1;
  }

  elem->next = *cfg;
  *cfg = elem;

  if (fr) tor_free(file);
  return 0;
}

int
sandbox_cfg_allow_stat_filename_array(sandbox_cfg_t **cfg, ...)
{
  int rc = 0;
  char *fn = NULL;

  va_list ap;
  va_start(ap, cfg);

  while ((fn = va_arg(ap, char*)) != NULL) {
    int fr = va_arg(ap, int);

    rc = sandbox_cfg_allow_stat_filename(cfg, fn, fr);
    if (rc) {
      log_err(LD_BUG,"(Sandbox) sandbox_cfg_allow_stat_filename_array fail");
      goto end;
    }
  }

 end:
  va_end(ap);
  return 0;
}

int
sandbox_cfg_allow_open_filename(sandbox_cfg_t **cfg, char *file, int fr)
{
  sandbox_cfg_t *elem = NULL;

  elem = new_element(SCMP_SYS(open), 0, (intptr_t)(void *)tor_strdup(file));
  if (!elem) {
    log_err(LD_BUG,"(Sandbox) failed to register parameter!");
    return -1;
  }

  elem->next = *cfg;
  *cfg = elem;

  if (fr) tor_free(file);

  return 0;
}

int
sandbox_cfg_allow_open_filename_array(sandbox_cfg_t **cfg, ...)
{
  int rc = 0;
  char *fn = NULL;

  va_list ap;
  va_start(ap, cfg);

  while ((fn = va_arg(ap, char*)) != NULL) {
    int fr = va_arg(ap, int);

    rc = sandbox_cfg_allow_open_filename(cfg, fn, fr);
    if (rc) {
      log_err(LD_BUG,"(Sandbox) sandbox_cfg_allow_open_filename_array fail");
      goto end;
    }
  }

 end:
  va_end(ap);
  return 0;
}

int
sandbox_cfg_allow_openat_filename(sandbox_cfg_t **cfg, char *file, int fr)
{
  sandbox_cfg_t *elem = NULL;

  elem = new_element(SCMP_SYS(openat), 1, (intptr_t)(void *)tor_strdup(file));
  if (!elem) {
    log_err(LD_BUG,"(Sandbox) failed to register parameter!");
    return -1;
  }

  elem->next = *cfg;
  *cfg = elem;

  if (fr) tor_free(file);

  return 0;
}

int
sandbox_cfg_allow_openat_filename_array(sandbox_cfg_t **cfg, ...)
{
  int rc = 0;
  char *fn = NULL;

  va_list ap;
  va_start(ap, cfg);

  while ((fn = va_arg(ap, char*)) != NULL) {
    int fr = va_arg(ap, int);

    rc = sandbox_cfg_allow_openat_filename(cfg, fn, fr);
    if (rc) {
      log_err(LD_BUG,"(Sandbox) sandbox_cfg_allow_openat_filename_array fail");
      goto end;
    }
  }

 end:
  va_end(ap);
  return 0;
}

int
sandbox_cfg_allow_execve(sandbox_cfg_t **cfg, const char *com)
{
  sandbox_cfg_t *elem = NULL;

  elem = new_element(SCMP_SYS(execve), 1, (intptr_t)(void *)tor_strdup(com));
  if (!elem) {
    log_err(LD_BUG,"(Sandbox) failed to register parameter!");
    return -1;
  }

  elem->next = *cfg;
  *cfg = elem;

  return 0;
}

int
sandbox_cfg_allow_execve_array(sandbox_cfg_t **cfg, ...)
{
  int rc = 0;
  char *fn = NULL;

  va_list ap;
  va_start(ap, cfg);

  while ((fn = va_arg(ap, char*)) != NULL) {

    rc = sandbox_cfg_allow_execve(cfg, fn);
    if (rc) {
      log_err(LD_BUG,"(Sandbox) sandbox_cfg_allow_execve_array failed");
      goto end;
    }
  }

 end:
  va_end(ap);
  return 0;
}

int
sandbox_getaddrinfo(const char *name, const char *servname,
                    const struct addrinfo *hints,
                    struct addrinfo **res)
{
  sb_addr_info_t *el;

  if (servname != NULL)
    return -1;

  *res = NULL;

  for (el = sb_addr_info; el; el = el->next) {
    if (!strcmp(el->name, name)) {
      *res = tor_malloc(sizeof(struct addrinfo));

      memcpy(*res, el->info, sizeof(struct addrinfo));
      /* XXXX What if there are multiple items in the list? */
      return 0;
    }
  }

  if (!sandbox_active) {
    if (getaddrinfo(name, NULL, hints, res)) {
      log_err(LD_BUG,"(Sandbox) getaddrinfo failed!");
      return -1;
    }

    return 0;
  }

  // getting here means something went wrong
  log_err(LD_BUG,"(Sandbox) failed to get address %s!", name);
  if (*res) {
    tor_free(*res);
    res = NULL;
  }
  return -1;
}

int
sandbox_add_addrinfo(const char* name)
{
  int ret;
  struct addrinfo hints;
  sb_addr_info_t *el = NULL;

  el = tor_malloc(sizeof(sb_addr_info_t));

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  ret = getaddrinfo(name, NULL, &hints, &(el->info));
  if (ret) {
    log_err(LD_BUG,"(Sandbox) failed to getaddrinfo");
    ret = -2;
    tor_free(el);
    goto out;
  }

  el->name = tor_strdup(name);
  el->next = sb_addr_info;
  sb_addr_info = el;

 out:
  return ret;
}

/**
 * Function responsible for going through the parameter syscall filters and
 * call each function pointer in the list.
 */
static int
add_param_filter(scmp_filter_ctx ctx, sandbox_cfg_t* cfg)
{
  unsigned i;
  int rc = 0;

  // function pointer
  for (i = 0; i < ARRAY_LENGTH(filter_func); i++) {
    if ((filter_func[i])(ctx, cfg)) {
      log_err(LD_BUG,"(Sandbox) failed to add syscall %d, received libseccomp "
          "error %d", i, rc);
      return rc;
    }
  }

  return 0;
}

/**
 * Function responsible of loading the libseccomp syscall filters which do not
 * have parameter filtering.
 */
static int
add_noparam_filter(scmp_filter_ctx ctx)
{
  unsigned i;
  int rc = 0;

  // add general filters
  for (i = 0; i < ARRAY_LENGTH(filter_nopar_gen); i++) {
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, filter_nopar_gen[i], 0);
    if (rc != 0) {
      log_err(LD_BUG,"(Sandbox) failed to add syscall index %d (NR=%d), "
          "received libseccomp error %d", i, filter_nopar_gen[i], rc);
      return rc;
    }
  }

  return 0;
}

/**
 * Function responsible for setting up and enabling a global syscall filter.
 * The function is a prototype developed for stage 1 of sandboxing Tor.
 * Returns 0 on success.
 */
static int
install_syscall_filter(sandbox_cfg_t* cfg)
{
  int rc = 0;
  scmp_filter_ctx ctx;

  ctx = seccomp_init(SCMP_ACT_TRAP);
  if (ctx == NULL) {
    log_err(LD_BUG,"(Sandbox) failed to initialise libseccomp context");
    rc = -1;
    goto end;
  }

  // protectign sandbox parameter strings
  if ((rc = prot_strings(ctx, cfg))) {
    goto end;
  }

  // add parameter filters
  if ((rc = add_param_filter(ctx, cfg))) {
    log_err(LD_BUG, "(Sandbox) failed to add param filters!");
    goto end;
  }

  // adding filters with no parameters
  if ((rc = add_noparam_filter(ctx))) {
    log_err(LD_BUG, "(Sandbox) failed to add param filters!");
    goto end;
  }

  // loading the seccomp2 filter
  if ((rc = seccomp_load(ctx))) {
    log_err(LD_BUG, "(Sandbox) failed to load!");
    goto end;
  }

  // marking the sandbox as active
  sandbox_active = 1;

 end:
  seccomp_release(ctx);
  return (rc < 0 ? -rc : rc);
}

/**
 * Function called when a SIGSYS is caught by the application. It notifies the
 * user that an error has occurred and either terminates or allows the
 * application to continue execution, based on the DEBUGGING_CLOSE symbol.
 */
static void
sigsys_debugging(int nr, siginfo_t *info, void *void_context)
{
  ucontext_t *ctx = (ucontext_t *) (void_context);
  char number[32];
  int syscall;
  (void) nr;

  if (info->si_code != SYS_SECCOMP)
    return;

  if (!ctx)
    return;

  syscall = (int) ctx->uc_mcontext.gregs[REG_SYSCALL];

  format_dec_number_sigsafe(syscall, number, sizeof(number));
  tor_log_err_sigsafe("(Sandbox) Caught a bad syscall attempt (syscall ",
                      number,
                      ")\n",
                      NULL);

#if defined(DEBUGGING_CLOSE)
  _exit(1);
#endif // DEBUGGING_CLOSE
}

/**
 * Function that adds a handler for SIGSYS, which is the signal thrown
 * when the application is issuing a syscall which is not allowed. The
 * main purpose of this function is to help with debugging by identifying
 * filtered syscalls.
 */
static int
install_sigsys_debugging(void)
{
  struct sigaction act;
  sigset_t mask;

  memset(&act, 0, sizeof(act));
  sigemptyset(&mask);
  sigaddset(&mask, SIGSYS);

  act.sa_sigaction = &sigsys_debugging;
  act.sa_flags = SA_SIGINFO;
  if (sigaction(SIGSYS, &act, NULL) < 0) {
    log_err(LD_BUG,"(Sandbox) Failed to register SIGSYS signal handler");
    return -1;
  }

  if (sigprocmask(SIG_UNBLOCK, &mask, NULL)) {
    log_err(LD_BUG,"(Sandbox) Failed call to sigprocmask()");
    return -2;
  }

  return 0;
}

/**
 * Function responsible of registering the sandbox_cfg_t list of parameter
 * syscall filters to the existing parameter list. This is used for incipient
 * multiple-sandbox support.
 */
static int
register_cfg(sandbox_cfg_t* cfg)
{
  sandbox_cfg_t *elem = NULL;

  if (filter_dynamic == NULL) {
    filter_dynamic = cfg;
    return 0;
  }

  for (elem = filter_dynamic; elem->next != NULL; elem = elem->next);

  elem->next = cfg;

  return 0;
}

#endif // USE_LIBSECCOMP

#ifdef USE_LIBSECCOMP
/**
 * Initialises the syscall sandbox filter for any linux architecture, taking
 * into account various available features for different linux flavours.
 */
static int
initialise_libseccomp_sandbox(sandbox_cfg_t* cfg)
{
  if (install_sigsys_debugging())
    return -1;

  if (install_syscall_filter(cfg))
    return -2;

  if (register_cfg(cfg))
    return -3;

  return 0;
}

#endif // USE_LIBSECCOMP

sandbox_cfg_t*
sandbox_cfg_new(void)
{
  return NULL;
}

int
sandbox_init(sandbox_cfg_t *cfg)
{
#if defined(USE_LIBSECCOMP)
  return initialise_libseccomp_sandbox(cfg);

#elif defined(_WIN32)
  (void)cfg;
  log_warn(LD_BUG,"Windows sandboxing is not implemented. The feature is "
      "currently disabled.");
  return 0;

#elif defined(TARGET_OS_MAC)
  (void)cfg;
  log_warn(LD_BUG,"Mac OSX sandboxing is not implemented. The feature is "
      "currently disabled");
  return 0;
#else
  (void)cfg;
  log_warn(LD_BUG,"Sandboxing is not implemented for your platform. The "
      "feature is currently disabled");
  return 0;
#endif
}

#ifndef USE_LIBSECCOMP
int
sandbox_cfg_allow_open_filename(sandbox_cfg_t **cfg, char *file,
                                int fr)
{
  (void)cfg; (void)file; (void)fr;
  return 0;
}

int
sandbox_cfg_allow_open_filename_array(sandbox_cfg_t **cfg, ...)
{
  (void)cfg;
  return 0;
}

int
sandbox_cfg_allow_openat_filename(sandbox_cfg_t **cfg, char *file,
                                  int fr)
{
  (void)cfg; (void)file; (void)fr;
  return 0;
}

int
sandbox_cfg_allow_openat_filename_array(sandbox_cfg_t **cfg, ...)
{
  (void)cfg;
  return 0;
}

int
sandbox_cfg_allow_execve(sandbox_cfg_t **cfg, const char *com)
{
  (void)cfg; (void)com;
  return 0;
}

int
sandbox_cfg_allow_execve_array(sandbox_cfg_t **cfg, ...)
{
  (void)cfg;
  return 0;
}

int
sandbox_cfg_allow_stat_filename(sandbox_cfg_t **cfg, char *file,
                                int fr)
{
  (void)cfg; (void)file; (void)fr;
  return 0;
}

int
sandbox_cfg_allow_stat_filename_array(sandbox_cfg_t **cfg, ...)
{
  (void)cfg;
  return 0;
}
#endif

