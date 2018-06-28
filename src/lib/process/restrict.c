/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include "lib/process/restrict.h"
#include "lib/log/torlog.h"

/* We only use the linux prctl for now. There is no Win32 support; this may
 * also work on various BSD systems and Mac OS X - send testing feedback!
 *
 * On recent Gnu/Linux kernels it is possible to create a system-wide policy
 * that will prevent non-root processes from attaching to other processes
 * unless they are the parent process; thus gdb can attach to programs that
 * they execute but they cannot attach to other processes running as the same
 * user. The system wide policy may be set with the sysctl
 * kernel.yama.ptrace_scope or by inspecting
 * /proc/sys/kernel/yama/ptrace_scope and it is 1 by default on Ubuntu 11.04.
 *
 * This ptrace scope will be ignored on Gnu/Linux for users with
 * CAP_SYS_PTRACE and so it is very likely that root will still be able to
 * attach to the Tor process.
 */
/** Attempt to disable debugger attachment: return 1 on success, -1 on
 * failure, and 0 if we don't know how to try on this platform. */
int
tor_disable_debugger_attach(void)
{
  int r = -1;
  log_debug(LD_CONFIG,
            "Attemping to disable debugger attachment to Tor for "
            "unprivileged users.");
#if defined(__linux__) && defined(HAVE_SYS_PRCTL_H) \
  && defined(HAVE_PRCTL) && defined(PR_SET_DUMPABLE)
#define TRIED_TO_DISABLE
  r = prctl(PR_SET_DUMPABLE, 0);
#elif defined(__APPLE__) && defined(PT_DENY_ATTACH)
#define TRIED_TO_ATTACH
  r = ptrace(PT_DENY_ATTACH, 0, 0, 0);
#endif /* defined(__linux__) && defined(HAVE_SYS_PRCTL_H) ... || ... */

  // XXX: TODO - Mac OS X has dtrace and this may be disabled.
  // XXX: TODO - Windows probably has something similar
#ifdef TRIED_TO_DISABLE
  if (r == 0) {
    log_debug(LD_CONFIG,"Debugger attachment disabled for "
              "unprivileged users.");
    return 1;
  } else {
    log_warn(LD_CONFIG, "Unable to disable debugger attaching: %s",
             strerror(errno));
  }
#endif /* defined(TRIED_TO_DISABLE) */
#undef TRIED_TO_DISABLE
  return r;
}

#if defined(HAVE_MLOCKALL) && HAVE_DECL_MLOCKALL && defined(RLIMIT_MEMLOCK)
#define HAVE_UNIX_MLOCKALL
#endif

#ifdef HAVE_UNIX_MLOCKALL
/** Attempt to raise the current and max rlimit to infinity for our process.
 * This only needs to be done once and can probably only be done when we have
 * not already dropped privileges.
 */
static int
tor_set_max_memlock(void)
{
  /* Future consideration for Windows is probably SetProcessWorkingSetSize
   * This is similar to setting the memory rlimit of RLIMIT_MEMLOCK
   * http://msdn.microsoft.com/en-us/library/ms686234(VS.85).aspx
   */

  struct rlimit limit;

  /* RLIM_INFINITY is -1 on some platforms. */
  limit.rlim_cur = RLIM_INFINITY;
  limit.rlim_max = RLIM_INFINITY;

  if (setrlimit(RLIMIT_MEMLOCK, &limit) == -1) {
    if (errno == EPERM) {
      log_warn(LD_GENERAL, "You appear to lack permissions to change memory "
                           "limits. Are you root?");
    }
    log_warn(LD_GENERAL, "Unable to raise RLIMIT_MEMLOCK: %s",
             strerror(errno));
    return -1;
  }

  return 0;
}
#endif /* defined(HAVE_UNIX_MLOCKALL) */

/** Attempt to lock all current and all future memory pages.
 * This should only be called once and while we're privileged.
 * Like mlockall() we return 0 when we're successful and -1 when we're not.
 * Unlike mlockall() we return 1 if we've already attempted to lock memory.
 */
int
tor_mlockall(void)
{
  static int memory_lock_attempted = 0;

  if (memory_lock_attempted) {
    return 1;
  }

  memory_lock_attempted = 1;

  /*
   * Future consideration for Windows may be VirtualLock
   * VirtualLock appears to implement mlock() but not mlockall()
   *
   * http://msdn.microsoft.com/en-us/library/aa366895(VS.85).aspx
   */

#ifdef HAVE_UNIX_MLOCKALL
  if (tor_set_max_memlock() == 0) {
    log_debug(LD_GENERAL, "RLIMIT_MEMLOCK is now set to RLIM_INFINITY.");
  }

  if (mlockall(MCL_CURRENT|MCL_FUTURE) == 0) {
    log_info(LD_GENERAL, "Insecure OS paging is effectively disabled.");
    return 0;
  } else {
    if (errno == ENOSYS) {
      /* Apple - it's 2009! I'm looking at you. Grrr. */
      log_notice(LD_GENERAL, "It appears that mlockall() is not available on "
                             "your platform.");
    } else if (errno == EPERM) {
      log_notice(LD_GENERAL, "It appears that you lack the permissions to "
                             "lock memory. Are you root?");
    }
    log_notice(LD_GENERAL, "Unable to lock all current and future memory "
                           "pages: %s", strerror(errno));
    return -1;
  }
#else /* !(defined(HAVE_UNIX_MLOCKALL)) */
  log_warn(LD_GENERAL, "Unable to lock memory pages. mlockall() unsupported?");
  return -1;
#endif /* defined(HAVE_UNIX_MLOCKALL) */
}
