/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file compat.c
 * \brief Wrappers to make calls more portable.  This code defines
 * functions such as tor_snprintf, get/set various data types,
 * renaming, setting socket options, switching user IDs.  It is basically
 * where the non-portable items are conditionally included depending on
 * the platform.
 **/

#define COMPAT_PRIVATE
#include "common/compat.h"

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <sys/locking.h>
#endif

#ifdef HAVE_UNAME
#include <sys/utsname.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_UTIME_H
#include <utime.h>
#endif
#ifdef HAVE_SYS_UTIME_H
#include <sys/utime.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_FCNTL_H
#include <sys/fcntl.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif
#ifdef HAVE_SYS_CAPABILITY_H
#include <sys/capability.h>
#endif

#ifdef _WIN32
#include <conio.h>
#include <wchar.h>
/* Some mingw headers lack these. :p */
#if defined(HAVE_DECL__GETWCH) && !HAVE_DECL__GETWCH
wint_t _getwch(void);
#endif
#ifndef WEOF
#define WEOF (wchar_t)(0xFFFF)
#endif
#if defined(HAVE_DECL_SECUREZEROMEMORY) && !HAVE_DECL_SECUREZEROMEMORY
static inline void
SecureZeroMemory(PVOID ptr, SIZE_T cnt)
{
  volatile char *vcptr = (volatile char*)ptr;
  while (cnt--)
    *vcptr++ = 0;
}
#endif /* defined(HAVE_DECL_SECUREZEROMEMORY) && !HAVE_DECL_SECUREZEROMEMORY */
#elif defined(HAVE_READPASSPHRASE_H)
#include <readpassphrase.h>
#else
#include "tor_readpassphrase.h"
#endif /* defined(_WIN32) || ... */

/* Includes for the process attaching prevention */
#if defined(HAVE_SYS_PRCTL_H) && defined(__linux__)
/* Only use the linux prctl;  the IRIX prctl is totally different */
#include <sys/prctl.h>
#elif defined(__APPLE__)
#include <sys/ptrace.h>
#endif /* defined(HAVE_SYS_PRCTL_H) && defined(__linux__) || ... */

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h> /* FreeBSD needs this to know what version it is */
#endif
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif
#ifdef HAVE_SYS_SYSLIMITS_H
#include <sys/syslimits.h>
#endif
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#include "lib/log/torlog.h"
#include "common/util.h"
#include "lib/container/smartlist.h"
#include "lib/wallclock/tm_cvt.h"
#include "lib/net/address.h"
#include "lib/sandbox/sandbox.h"

/** Hold the result of our call to <b>uname</b>. */
static char uname_result[256];
/** True iff uname_result is set. */
static int uname_result_is_set = 0;

/** Return a pointer to a description of our platform.
 */
MOCK_IMPL(const char *,
get_uname,(void))
{
#ifdef HAVE_UNAME
  struct utsname u;
#endif
  if (!uname_result_is_set) {
#ifdef HAVE_UNAME
    if (uname(&u) != -1) {
      /* (Linux says 0 is success, Solaris says 1 is success) */
      strlcpy(uname_result, u.sysname, sizeof(uname_result));
    } else
#endif /* defined(HAVE_UNAME) */
      {
#ifdef _WIN32
        OSVERSIONINFOEX info;
        int i;
        const char *plat = NULL;
        static struct {
          unsigned major; unsigned minor; const char *version;
        } win_version_table[] = {
          { 6, 2, "Windows 8" },
          { 6, 1, "Windows 7" },
          { 6, 0, "Windows Vista" },
          { 5, 2, "Windows Server 2003" },
          { 5, 1, "Windows XP" },
          { 5, 0, "Windows 2000" },
          /* { 4, 0, "Windows NT 4.0" }, */
          { 4, 90, "Windows Me" },
          { 4, 10, "Windows 98" },
          /* { 4, 0, "Windows 95" } */
          { 3, 51, "Windows NT 3.51" },
          { 0, 0, NULL }
        };
        memset(&info, 0, sizeof(info));
        info.dwOSVersionInfoSize = sizeof(info);
        if (! GetVersionEx((LPOSVERSIONINFO)&info)) {
          strlcpy(uname_result, "Bizarre version of Windows where GetVersionEx"
                  " doesn't work.", sizeof(uname_result));
          uname_result_is_set = 1;
          return uname_result;
        }
        if (info.dwMajorVersion == 4 && info.dwMinorVersion == 0) {
          if (info.dwPlatformId == VER_PLATFORM_WIN32_NT)
            plat = "Windows NT 4.0";
          else
            plat = "Windows 95";
        } else {
          for (i=0; win_version_table[i].major>0; ++i) {
            if (win_version_table[i].major == info.dwMajorVersion &&
                win_version_table[i].minor == info.dwMinorVersion) {
              plat = win_version_table[i].version;
              break;
            }
          }
        }
        if (plat) {
          strlcpy(uname_result, plat, sizeof(uname_result));
        } else {
          if (info.dwMajorVersion > 6 ||
              (info.dwMajorVersion==6 && info.dwMinorVersion>2))
            tor_snprintf(uname_result, sizeof(uname_result),
                         "Very recent version of Windows [major=%d,minor=%d]",
                         (int)info.dwMajorVersion,(int)info.dwMinorVersion);
          else
            tor_snprintf(uname_result, sizeof(uname_result),
                         "Unrecognized version of Windows [major=%d,minor=%d]",
                         (int)info.dwMajorVersion,(int)info.dwMinorVersion);
        }
#ifdef VER_NT_SERVER
      if (info.wProductType == VER_NT_SERVER ||
          info.wProductType == VER_NT_DOMAIN_CONTROLLER) {
        strlcat(uname_result, " [server]", sizeof(uname_result));
      }
#endif /* defined(VER_NT_SERVER) */
#else /* !(defined(_WIN32)) */
        /* LCOV_EXCL_START -- can't provoke uname failure */
        strlcpy(uname_result, "Unknown platform", sizeof(uname_result));
        /* LCOV_EXCL_STOP */
#endif /* defined(_WIN32) */
      }
    uname_result_is_set = 1;
  }
  return uname_result;
}

/*
 *   Process control
 */

/** Emit the password prompt <b>prompt</b>, then read up to <b>buflen</b>
 * bytes of passphrase into <b>output</b>. Return the number of bytes in
 * the passphrase, excluding terminating NUL.
 */
ssize_t
tor_getpass(const char *prompt, char *output, size_t buflen)
{
  tor_assert(buflen <= SSIZE_MAX);
  tor_assert(buflen >= 1);
#if defined(HAVE_READPASSPHRASE)
  char *pwd = readpassphrase(prompt, output, buflen, RPP_ECHO_OFF);
  if (pwd == NULL)
    return -1;
  return strlen(pwd);
#elif defined(_WIN32)
  int r = -1;
  while (*prompt) {
    _putch(*prompt++);
  }

  tor_assert(buflen <= INT_MAX);
  wchar_t *buf = tor_calloc(buflen, sizeof(wchar_t));

  wchar_t *ptr = buf, *lastch = buf + buflen - 1;
  while (ptr < lastch) {
    wint_t ch = _getwch();
    switch (ch) {
      case '\r':
      case '\n':
      case WEOF:
        goto done_reading;
      case 3:
        goto done; /* Can't actually read ctrl-c this way. */
      case '\b':
        if (ptr > buf)
          --ptr;
        continue;
      case 0:
      case 0xe0:
        ch = _getwch(); /* Ignore; this is a function or arrow key */
        break;
      default:
        *ptr++ = ch;
        break;
    }
  }
 done_reading:
  ;

#ifndef WC_ERR_INVALID_CHARS
#define WC_ERR_INVALID_CHARS 0x80
#endif

  /* Now convert it to UTF-8 */
  r = WideCharToMultiByte(CP_UTF8,
                          WC_NO_BEST_FIT_CHARS|WC_ERR_INVALID_CHARS,
                          buf, (int)(ptr-buf),
                          output, (int)(buflen-1),
                          NULL, NULL);
  if (r <= 0) {
    r = -1;
    goto done;
  }

  tor_assert(r < (int)buflen);

  output[r] = 0;

 done:
  SecureZeroMemory(buf, sizeof(wchar_t)*buflen);
  tor_free(buf);
  return r;
#else
#error "No implementation for tor_getpass found!"
#endif /* defined(HAVE_READPASSPHRASE) || ... */
}
