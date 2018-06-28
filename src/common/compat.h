/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_COMPAT_H
#define TOR_COMPAT_H

#include "orconfig.h"
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#ifndef SIO_IDEAL_SEND_BACKLOG_QUERY
#define SIO_IDEAL_SEND_BACKLOG_QUERY 0x4004747b
#endif
#endif
#include "lib/cc/torint.h"
#include "lib/testsupport/testsupport.h"
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdarg.h>
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET6_IN6_H
#include <netinet6/in6.h>
#endif

#include "lib/cc/compat_compiler.h"
#include "lib/arch/bytes.h"
#include "common/compat_time.h"
#include "lib/string/compat_ctype.h"
#include "lib/string/compat_string.h"
#include "lib/string/printf.h"
#include "lib/log/win32err.h"
#include "lib/net/socket.h"
#include "lib/net/ipv4.h"
#include "lib/net/ipv6.h"
#include "lib/net/resolve.h"
#include "lib/fs/files.h"
#include "lib/fs/mmap.h"
#include "lib/fs/userdb.h"

#include <stdio.h>
#include <errno.h>

/* ===== Time compatibility */

#ifndef timeradd
/** Replacement for timeradd on platforms that do not have it: sets tvout to
 * the sum of tv1 and tv2. */
#define timeradd(tv1,tv2,tvout) \
  do {                                                  \
    (tvout)->tv_sec = (tv1)->tv_sec + (tv2)->tv_sec;    \
    (tvout)->tv_usec = (tv1)->tv_usec + (tv2)->tv_usec; \
    if ((tvout)->tv_usec >= 1000000) {                  \
      (tvout)->tv_usec -= 1000000;                      \
      (tvout)->tv_sec++;                                \
    }                                                   \
  } while (0)
#endif /* !defined(timeradd) */

#ifndef timersub
/** Replacement for timersub on platforms that do not have it: sets tvout to
 * tv1 minus tv2. */
#define timersub(tv1,tv2,tvout) \
  do {                                                  \
    (tvout)->tv_sec = (tv1)->tv_sec - (tv2)->tv_sec;    \
    (tvout)->tv_usec = (tv1)->tv_usec - (tv2)->tv_usec; \
    if ((tvout)->tv_usec < 0) {                         \
      (tvout)->tv_usec += 1000000;                      \
      (tvout)->tv_sec--;                                \
    }                                                   \
  } while (0)
#endif /* !defined(timersub) */

#ifndef timercmp
/** Replacement for timercmp on platforms that do not have it: returns true
 * iff the relational operator "op" makes the expression tv1 op tv2 true.
 *
 * Note that while this definition should work for all boolean operators, some
 * platforms' native timercmp definitions do not support >=, <=, or ==.  So
 * don't use those.
 */
#define timercmp(tv1,tv2,op)                    \
  (((tv1)->tv_sec == (tv2)->tv_sec) ?           \
   ((tv1)->tv_usec op (tv2)->tv_usec) :         \
   ((tv1)->tv_sec op (tv2)->tv_sec))
#endif /* !defined(timercmp) */

/* ===== File compatibility */
typedef struct tor_lockfile_t tor_lockfile_t;
tor_lockfile_t *tor_lockfile_lock(const char *filename, int blocking,
                                  int *locked_out);
void tor_lockfile_unlock(tor_lockfile_t *lockfile);

/* ===== Net compatibility */

MOCK_DECL(int,tor_gethostname,(char *name, size_t namelen));

/** Specified SOCKS5 status codes. */
typedef enum {
  SOCKS5_SUCCEEDED                  = 0x00,
  SOCKS5_GENERAL_ERROR              = 0x01,
  SOCKS5_NOT_ALLOWED                = 0x02,
  SOCKS5_NET_UNREACHABLE            = 0x03,
  SOCKS5_HOST_UNREACHABLE           = 0x04,
  SOCKS5_CONNECTION_REFUSED         = 0x05,
  SOCKS5_TTL_EXPIRED                = 0x06,
  SOCKS5_COMMAND_NOT_SUPPORTED      = 0x07,
  SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED = 0x08,
} socks5_reply_status_t;

/* ===== OS compatibility */
MOCK_DECL(const char *, get_uname, (void));

#if !defined(HAVE_RLIM_T)
typedef unsigned long rlim_t;
#endif
int set_max_file_descriptors(rlim_t limit, int *max);
MOCK_DECL(int, get_total_system_memory, (size_t *mem_out));

int compute_num_cpus(void);

/** Macros for MIN/MAX.  Never use these when the arguments could have
 * side-effects.
 * {With GCC extensions we could probably define a safer MIN/MAX.  But
 * depending on that safety would be dangerous, since not every platform
 * has it.}
 **/
#ifndef MAX
#define MAX(a,b) ( ((a)<(b)) ? (b) : (a) )
#endif
#ifndef MIN
#define MIN(a,b) ( ((a)>(b)) ? (b) : (a) )
#endif

/*for some reason my compiler doesn't have these version flags defined
  a nice homework assignment for someone one day is to define the rest*/
//these are the values as given on MSDN
#ifdef _WIN32

#ifndef VER_SUITE_EMBEDDEDNT
#define VER_SUITE_EMBEDDEDNT 0x00000040
#endif

#ifndef VER_SUITE_SINGLEUSERTS
#define VER_SUITE_SINGLEUSERTS 0x00000100
#endif

#endif /* defined(_WIN32) */

ssize_t tor_getpass(const char *prompt, char *output, size_t buflen);

/* This needs some of the declarations above so we include it here. */
#include "lib/thread/threads.h"

#endif /* !defined(TOR_COMPAT_H) */
