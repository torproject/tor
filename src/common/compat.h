/* Copyright 2003-2004 Roger Dingledinex
 * Copyright 2004-2005 Roger Dingledine, Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef __COMPAT_H
#define __COMPAT_H
#define COMPAT_H_ID "$Id$"

#include "orconfig.h"
#include "torint.h"
#ifdef MS_WINDOWS
#define WIN32_WINNT 0x400
#define _WIN32_WINNT 0x400
#define WIN32_LEAN_AND_MEAN
#if (_MSC_VER <= 1300)
#include <winsock.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
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
#include <stdarg.h>

#ifndef NULL_REP_IS_ZERO_BYTES
#error "It seems your platform does not represent NULL as zero. We can't cope."
#endif

/* ===== Compiler compatibility */

/* GCC can check printf types on arbitrary functions. */
#ifdef __GNUC__
#define CHECK_PRINTF(formatIdx, firstArg) \
   __attribute__ ((format(printf, formatIdx, firstArg)))
#else
#define CHECK_PRINTF(formatIdx, firstArg)
#endif

/* inline is __inline on windows. */
#ifdef MS_WINDOWS
#define INLINE __inline
#else
#define INLINE inline
#endif

/* Windows compilers before VC7 don't have __FUNCTION__. */
#if defined(_MSC_VER) && _MSC_VER < 1300
#define __FUNCTION__ "???"
#endif

#if defined(__sgi) && !defined(__GNUC__) && defined(__c99)
#define __FUNCTION__ __func__
#endif

/* ===== String compatibility */
#ifdef MS_WINDOWS
/* Windows names string functions differently from most other platforms. */
#define strncasecmp strnicmp
#define strcasecmp stricmp
#endif
#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

#ifdef MS_WINDOWS
#define U64_PRINTF_ARG(a) (a)
#define U64_SCANF_ARG(a) (a)
#define U64_FORMAT "%I64u"
#define U64_LITERAL(n) (n ## ui64)
#else
#define U64_PRINTF_ARG(a) ((long long unsigned int)(a))
#define U64_SCANF_ARG(a) ((long long unsigned int*)(a))
#define U64_FORMAT "%llu"
#define U64_LITERAL(n) (n ## llu)
#endif

int tor_snprintf(char *str, size_t size, const char *format, ...)
     CHECK_PRINTF(3,4);
int tor_vsnprintf(char *str, size_t size, const char *format, va_list args);

const void *tor_memmem(const void *haystack, size_t hlen, const void *needle,
                       size_t nlen);

#define TOR_ISALPHA(c)   isalpha((int)(unsigned char)(c))
#define TOR_ISALNUM(c)   isalnum((int)(unsigned char)(c))
#define TOR_ISSPACE(c)   isspace((int)(unsigned char)(c))
#define TOR_ISXDIGIT(c) isxdigit((int)(unsigned char)(c))
#define TOR_ISDIGIT(c)   isdigit((int)(unsigned char)(c))
#define TOR_ISPRINT(c)   isprint((int)(unsigned char)(c))

#ifdef MS_WINDOWS
#define _SHORT_FILE_ (tor_fix_source_file(__FILE__))
const char *tor_fix_source_file(const char *fname);
#else
#define _SHORT_FILE_ (__FILE__)
#define tor_fix_source_file(s) (s)
#endif

/* ===== Time compatibility */
#if !defined(HAVE_GETTIMEOFDAY) && !defined(HAVE_STRUCT_TIMEVAL_TV_SEC)
struct timeval {
  time_t tv_sec;
  unsigned int tv_usec;
};
#endif

void tor_gettimeofday(struct timeval *timeval);

#ifdef HAVE_LOCALTIME_R
#define tor_localtime_r localtime_r
#else
struct tm *tor_localtime_r(const time_t *timep, struct tm *result);
#endif

#ifdef HAVE_GMTIME_R
#define tor_gmtime_r gmtime_r
#else
struct tm *tor_gmtime_r(const time_t *timep, struct tm *result);
#endif

/* ===== File compatibility */
int replace_file(const char *from, const char *to);
int touch_file(const char *fname);

#ifdef MS_WINDOWS
#define PATH_SEPARATOR "\\"
#else
#define PATH_SEPARATOR "/"
#endif

/* ===== Net compatibility */
#ifdef MS_WINDOWS
/** On windows, you have to call close() on fds returned by open(),
 * and closesocket() on fds returned by socket().  On Unix, everything
 * gets close()'d.  We abstract this difference by always using
 * tor_close_socket to close sockets, and always using close() on
 * files.
 */
#define tor_close_socket(s) closesocket(s)
#else
#define tor_close_socket(s) close(s)
#endif

#if (SIZEOF_SOCKLEN_T == 0)
typedef int socklen_t;
#endif

/* Now that we use libevent, all real sockets are safe for polling ... or
 * if they aren't, libevent will help us. */
#define SOCKET_IS_POLLABLE(fd) ((fd)>=0)

struct in_addr;
int tor_inet_aton(const char *cp, struct in_addr *addr);
int tor_lookup_hostname(const char *name, uint32_t *addr);
void set_socket_nonblocking(int socket);
int tor_socketpair(int family, int type, int protocol, int fd[2]);
int network_init(void);
/* For stupid historical reasons, windows sockets have an independent
 * set of errnos, and an independent way to get them.  Also, you can't
 * always believe WSAEWOULDBLOCK.  Use the macros below to compare
 * errnos against expected values, and use tor_socket_errno to find
 * the actual errno after a socket operation fails.
 */
#ifdef MS_WINDOWS
/** Return true if e is EAGAIN or the local equivalent. */
#define ERRNO_IS_EAGAIN(e)           ((e) == EAGAIN || (e) == WSAEWOULDBLOCK)
/** Return true if e is EINPROGRESS or the local equivalent. */
#define ERRNO_IS_EINPROGRESS(e)      ((e) == WSAEINPROGRESS)
/** Return true if e is EINPROGRESS or the local equivalent as returned by
 * a call to connect(). */
#define ERRNO_IS_CONN_EINPROGRESS(e) \
  ((e) == WSAEINPROGRESS || (e)== WSAEINVAL || (e) == WSAEWOULDBLOCK)
/** Return true if e is EAGAIN or another error indicating that a call to
 * accept() has no pending connections to return. */
#define ERRNO_IS_ACCEPT_EAGAIN(e)    ERRNO_IS_EAGAIN(e)
/** Return true if e is EMFILE or another error indicating that a call to
 * accept() has failed because we're out of fds or something. */
#define ERRNO_IS_ACCEPT_RESOURCE_LIMIT(e) \
  ((e) == WSAEMFILE || (e) == WSAENOBUFS)
/** Return true if e is EADDRINUSE or the local equivalent. */
#define ERRNO_IS_EADDRINUSE(e)      ((e) == WSAEADDRINUSE)
int tor_socket_errno(int sock);
const char *tor_socket_strerror(int e);
#else
#define ERRNO_IS_EAGAIN(e)           ((e) == EAGAIN)
#define ERRNO_IS_EINPROGRESS(e)      ((e) == EINPROGRESS)
#define ERRNO_IS_CONN_EINPROGRESS(e) ((e) == EINPROGRESS)
#define ERRNO_IS_ACCEPT_EAGAIN(e)    ((e) == EAGAIN || (e) == ECONNABORTED)
#define ERRNO_IS_ACCEPT_RESOURCE_LIMIT(e) \
  ((e) == EMFILE || (e) == ENFILE || (e) == ENOBUFS || (e) == ENOMEM)
#define ERRNO_IS_EADDRINUSE(e)       ((e) == EADDRINUSE)
#define tor_socket_errno(sock)       (errno)
#define tor_socket_strerror(e)       strerror(e)
#endif

/* ===== OS compatibility */
const char *get_uname(void);

/* Some platforms segfault when you try to access a multi-byte type
 * that isn't aligned to a word boundary.  The macros and/or functions
 * below can be used to access unaligned data on any platform.
 */
#ifdef UNALIGNED_INT_ACCESS_OK
#define get_uint16(cp) (*(uint16_t*)(cp))
#define get_uint32(cp) (*(uint32_t*)(cp))
#define set_uint16(cp,v) do { *(uint16_t*)(cp) = (v); } while (0)
#define set_uint32(cp,v) do { *(uint32_t*)(cp) = (v); } while (0)
#else
uint16_t get_uint16(const char *cp);
uint32_t get_uint32(const char *cp);
void set_uint16(char *cp, uint16_t v);
void set_uint32(char *cp, uint32_t v);
#endif

int set_max_file_descriptors(unsigned long limit, unsigned long cap);
int switch_id(char *user, char *group);
#ifdef HAVE_PWD_H
char *get_user_homedir(const char *username);
#endif

int spawn_func(int (*func)(void *), void *data);
void spawn_exit(void);

#if defined(ENABLE_THREADS) && defined(MS_WINDOWS)
#define USE_WIN32_THREADS
#define TOR_IS_MULTITHREADED 1
#elif (defined(ENABLE_THREADS) && defined(HAVE_PTHREAD_H) && \
       defined(HAVE_PTHREAD_CREATE))
#define USE_PTHREADS
#define TOR_IS_MULTITHREADED 1
#else
#undef TOR_IS_MULTITHREADED
#endif

/* Because we use threads instead of processes on Windows, we need locking on
 * Windows.  On Unixy platforms, these functions are no-ops. */

typedef struct tor_mutex_t tor_mutex_t;
#ifdef TOR_IS_MULTITHREADED
tor_mutex_t *tor_mutex_new(void);
void tor_mutex_acquire(tor_mutex_t *m);
void tor_mutex_release(tor_mutex_t *m);
void tor_mutex_free(tor_mutex_t *m);
unsigned long tor_get_thread_id(void);
#else
#define tor_mutex_new() ((tor_mutex_t*)tor_malloc(sizeof(int)))
#define tor_mutex_acquire(m) do { } while (0)
#define tor_mutex_release(m) do { } while (0)
#define tor_mutex_free(m) do { tor_free(m); } while (0)
#define tor_get_thread_id() (1UL)
#endif

#endif

