/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file sandbox.c
 * \brief Code to enable sandboxing.
 **/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "orconfig.h"
#include "sandbox.h"
#include "torlog.h"
#include "util.h"

#if defined(HAVE_SECCOMP_H) && defined(__linux__)
#define USE_LIBSECCOMP
#endif

#define DEBUGGING_CLOSE

#if defined(USE_LIBSECCOMP)

#include <sys/syscall.h>
#include <seccomp.h>
#include <signal.h>
#include <unistd.h>

/** Variable used for storing all syscall numbers that will be allowed with the
 * stage 1 general Tor sandbox.
 */
static int general_filter[] = {
    SCMP_SYS(access),
    SCMP_SYS(brk),
    SCMP_SYS(clock_gettime),
    SCMP_SYS(close),
    SCMP_SYS(clone),
    SCMP_SYS(epoll_create),
    SCMP_SYS(epoll_ctl),
    SCMP_SYS(epoll_wait),
    SCMP_SYS(execve),
    SCMP_SYS(fcntl),
#ifdef __NR_fcntl64
    /* Older libseccomp versions don't define PNR entries for all of these,
     * so we need to ifdef them here.*/
    SCMP_SYS(fcntl64),
#endif
    SCMP_SYS(flock),
    SCMP_SYS(fstat),
#ifdef __NR_fstat64
    SCMP_SYS(fstat64),
#endif
    SCMP_SYS(futex),
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
#ifdef __NR_mmap2
    SCMP_SYS(mmap2),
#endif
    SCMP_SYS(mprotect),
    SCMP_SYS(mremap),
    SCMP_SYS(munmap),
    SCMP_SYS(open),
    SCMP_SYS(openat),
    SCMP_SYS(poll),
    SCMP_SYS(prctl),
    SCMP_SYS(read),
    SCMP_SYS(rename),
    SCMP_SYS(rt_sigaction),
    SCMP_SYS(rt_sigprocmask),
    SCMP_SYS(rt_sigreturn),
#ifdef __NR_sigreturn
    SCMP_SYS(sigreturn),
#endif
    SCMP_SYS(set_robust_list),
    SCMP_SYS(set_thread_area),
    SCMP_SYS(set_tid_address),
    SCMP_SYS(stat),
#ifdef __NR_stat64
    SCMP_SYS(stat64),
#endif
    SCMP_SYS(time),
    SCMP_SYS(uname),
    SCMP_SYS(write),
    SCMP_SYS(exit_group),
    SCMP_SYS(exit),

    // socket syscalls
    SCMP_SYS(accept4),
    SCMP_SYS(bind),
    SCMP_SYS(connect),
    SCMP_SYS(getsockname),
    SCMP_SYS(getsockopt),
    SCMP_SYS(listen),
#if __NR_recv >= 0
    /* This is a kludge; It's necessary on 64-bit with libseccomp 1.0.0; I
     * don't know if other 64-bit or other versions require it. */
    SCMP_SYS(recv),
#endif
    SCMP_SYS(recvmsg),
#if __NR_send >= 0
    SCMP_SYS(send),
#endif
    SCMP_SYS(sendto),
    SCMP_SYS(setsockopt),
    SCMP_SYS(socket),
    SCMP_SYS(socketpair),

    // TODO: remove when accept4 is fixed
#ifdef __NR_socketcall
    SCMP_SYS(socketcall),
#endif

    SCMP_SYS(recvfrom),
    SCMP_SYS(unlink)
};

/**
 * Function responsible for setting up and enabling a global syscall filter.
 * The function is a prototype developed for stage 1 of sandboxing Tor.
 * Returns 0 on success.
 */
static int
install_glob_syscall_filter(void)
{
  int rc = 0, i, filter_size;
  scmp_filter_ctx ctx;

  ctx = seccomp_init(SCMP_ACT_TRAP);
  if (ctx == NULL) {
    log_err(LD_BUG,"(Sandbox) failed to initialise libseccomp context");
    rc = -1;
    goto end;
  }

  if (general_filter != NULL) {
    filter_size = sizeof(general_filter) / sizeof(general_filter[0]);
  } else {
    filter_size = 0;
  }

  // add general filters
  for (i = 0; i < filter_size; i++) {
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, general_filter[i], 0);
    if (rc != 0) {
      log_err(LD_BUG,"(Sandbox) failed to add syscall index %d, "
          "received libseccomp error %d", i, rc);
      goto end;
    }
  }

  rc = seccomp_load(ctx);

 end:
  seccomp_release(ctx);
  return (rc < 0 ? -rc : rc);
}

/** Additional file descriptor to use when logging seccomp2 failures */
static int sigsys_debugging_fd = -1;

/** Use the file descriptor <b>fd</b> to log seccomp2 failures. */
static void
sigsys_set_debugging_fd(int fd)
{
  sigsys_debugging_fd = fd;
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
  char message[256];
  int rv = 0, syscall, length, err;
  (void) nr;

  if (info->si_code != SYS_SECCOMP)
    return;

  if (!ctx)
    return;

  syscall = ctx->uc_mcontext.gregs[REG_SYSCALL];

  strlcpy(message, "\n\n(Sandbox) Caught a bad syscall attempt (syscall 0x",
          sizeof(message));
  (void) format_hex_number_sigsafe(syscall, message+strlen(message),
                                   sizeof(message)-strlen(message));
  strlcat(message, ")\n", sizeof(message));
  length = strlen(message);

  err = 0;
  if (sigsys_debugging_fd >= 0) {
    rv = write(sigsys_debugging_fd, message, length);
    err += rv != length;
  }

  rv = write(STDOUT_FILENO, message, length);
  err += rv != length;

  if (err)
    _exit(2);

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
#endif // USE_LIBSECCOMP

#ifdef USE_LIBSECCOMP
/**
 * Initialises the syscall sandbox filter for any linux architecture, taking
 * into account various available features for different linux flavours.
 */
static int
initialise_libseccomp_sandbox(void)
{
  if (install_sigsys_debugging())
    return -1;

  if (install_glob_syscall_filter())
    return -2;

  return 0;
}

#endif // USE_LIBSECCOMP

/**
 * Enables the stage 1 general sandbox. It applies a syscall filter which does
 * not restrict any Tor features. The filter is representative for the whole
 * application.
 */
int
tor_global_sandbox(void)
{

#if defined(USE_LIBSECCOMP)
  return initialise_libseccomp_sandbox();

#elif defined(_WIN32)
  log_warn(LD_BUG,"Windows sandboxing is not implemented. The feature is "
      "currently disabled.");
  return 0;

#elif defined(TARGET_OS_MAC)
  log_warn(LD_BUG,"Mac OSX sandboxing is not implemented. The feature is "
      "currently disabled");
  return 0;
#else
  log_warn(LD_BUG,"Sandboxing is not implemented for your platform. The "
      "feature is currently disabled");
  return 0;
#endif
}

/** Use <b>fd</b> to log non-survivable sandbox violations. */
void
sandbox_set_debugging_fd(int fd)
{
#ifdef USE_LIBSECCOMP
  sigsys_set_debugging_fd(fd);
#else
  (void)fd;
#endif
}

