/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include "lib/osinfo/uname.h"

#include "lib/string/compat_string.h"
#include "lib/string/printf.h"

#ifdef HAVE_UNAME
#include <sys/utsname.h>
#endif
#ifdef _WIN32
#include <windows.h>
#endif
#include <string.h>

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
