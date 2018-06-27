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
#include "common/compat_time.h"
#include "lib/string/compat_ctype.h"
#include "lib/string/compat_string.h"
#include "lib/string/printf.h"
#include "lib/log/win32err.h"
#include "lib/net/socket.h"
#include "lib/net/ipv4.h"
#include "lib/net/ipv6.h"
#include "lib/net/resolve.h"

#include <stdio.h>
#include <errno.h>

/* ===== Compiler compatibility */

/** Represents an mmaped file. Allocated via tor_mmap_file; freed with
 * tor_munmap_file. */
typedef struct tor_mmap_t {
  const char *data; /**< Mapping of the file's contents. */
  size_t size; /**< Size of the file. */

  /* None of the fields below should be accessed from outside compat.c */
#ifdef HAVE_MMAP
  size_t mapping_size; /**< Size of the actual mapping. (This is this file
                        * size, rounded up to the nearest page.) */
#elif defined _WIN32
  HANDLE mmap_handle;
#endif /* defined(HAVE_MMAP) || ... */

} tor_mmap_t;

tor_mmap_t *tor_mmap_file(const char *filename) ATTR_NONNULL((1));
int tor_munmap_file(tor_mmap_t *handle) ATTR_NONNULL((1));

const void *tor_memmem(const void *haystack, size_t hlen, const void *needle,
                       size_t nlen) ATTR_NONNULL((1,3));
static const void *tor_memstr(const void *haystack, size_t hlen,
                           const char *needle) ATTR_NONNULL((1,3));
static inline const void *
tor_memstr(const void *haystack, size_t hlen, const char *needle)
{
  return tor_memmem(haystack, hlen, needle, strlen(needle));
}

char *tor_strtok_r_impl(char *str, const char *sep, char **lasts);
#ifdef HAVE_STRTOK_R
#define tor_strtok_r(str, sep, lasts) strtok_r(str, sep, lasts)
#else
#define tor_strtok_r(str, sep, lasts) tor_strtok_r_impl(str, sep, lasts)
#endif

/* ===== Time compatibility */

struct tm *tor_localtime_r(const time_t *timep, struct tm *result);
struct tm *tor_gmtime_r(const time_t *timep, struct tm *result);

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
int tor_open_cloexec(const char *path, int flags, unsigned mode);
FILE *tor_fopen_cloexec(const char *path, const char *mode);
int tor_rename(const char *path_old, const char *path_new);

int replace_file(const char *from, const char *to);
int touch_file(const char *fname);

typedef struct tor_lockfile_t tor_lockfile_t;
tor_lockfile_t *tor_lockfile_lock(const char *filename, int blocking,
                                  int *locked_out);
void tor_lockfile_unlock(tor_lockfile_t *lockfile);

int64_t tor_get_avail_disk_space(const char *path);

#ifdef _WIN32
#define PATH_SEPARATOR "\\"
#else
#define PATH_SEPARATOR "/"
#endif

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

uint16_t get_uint16(const void *cp) ATTR_NONNULL((1));
uint32_t get_uint32(const void *cp) ATTR_NONNULL((1));
uint64_t get_uint64(const void *cp) ATTR_NONNULL((1));
void set_uint16(void *cp, uint16_t v) ATTR_NONNULL((1));
void set_uint32(void *cp, uint32_t v) ATTR_NONNULL((1));
void set_uint64(void *cp, uint64_t v) ATTR_NONNULL((1));

/* These uint8 variants are defined to make the code more uniform. */
#define get_uint8(cp) (*(const uint8_t*)(cp))
static void set_uint8(void *cp, uint8_t v);
static inline void
set_uint8(void *cp, uint8_t v)
{
  *(uint8_t*)cp = v;
}

#if !defined(HAVE_RLIM_T)
typedef unsigned long rlim_t;
#endif
int set_max_file_descriptors(rlim_t limit, int *max);
int tor_disable_debugger_attach(void);

#if defined(HAVE_SYS_CAPABILITY_H) && defined(HAVE_CAP_SET_PROC)
#define HAVE_LINUX_CAPABILITIES
#endif

int have_capability_support(void);

/** Flag for switch_id; see switch_id() for documentation */
#define SWITCH_ID_KEEP_BINDLOW    (1<<0)
/** Flag for switch_id; see switch_id() for documentation */
#define SWITCH_ID_WARN_IF_NO_CAPS (1<<1)
int switch_id(const char *user, unsigned flags);
#ifdef HAVE_PWD_H
char *get_user_homedir(const char *username);
#endif

#ifndef _WIN32
const struct passwd *tor_getpwnam(const char *username);
const struct passwd *tor_getpwuid(uid_t uid);
#endif

int get_parent_directory(char *fname);
char *make_path_absolute(char *fname);

char **get_environment(void);

MOCK_DECL(int, get_total_system_memory, (size_t *mem_out));

int compute_num_cpus(void);

int tor_mlockall(void);

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
#include "common/compat_threads.h"

#endif /* !defined(TOR_COMPAT_H) */
