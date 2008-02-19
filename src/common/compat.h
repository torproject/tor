/* Copyright (c) 2003-2004, Roger Dingledinex
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2008, The Tor Project, Inc. */
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
#if defined(_MSC_VER) && (_MSC_VER < 1300)
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
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#include <stdarg.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET6_IN6_H
#include <netinet6/in6.h>
#endif

#ifndef NULL_REP_IS_ZERO_BYTES
#error "It seems your platform does not represent NULL as zero. We can't cope."
#endif

#if 'a'!=97 || 'z'!=122 || 'A'!=65 || ' '!=32
#error "It seems that you encode characters in something other than ASCII."
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

/* Try to get a reasonable __func__ substitute in place. */
#if defined(_MSC_VER)
/* MSVC compilers before VC7 don't have __func__ at all; later ones call it
 * __FUNCTION__. */
#if _MSC_VER < 1300
#define __func__ "???"
#else
#define __func__ __FUNCTION__
#endif

#else
/* For platforms where autoconf works, make sure __func__ is defined
 * sanely. */
#ifndef HAVE_MACRO__func__
#ifdef HAVE_MACRO__FUNCTION__
#define __func__ __FUNCTION__
#elif HAVE_MACRO__FUNC__
#define __func__ __FUNC__
#else
#define __func__ "???"
#endif
#endif /* ifndef MAVE_MACRO__func__ */
#endif /* if not windows */

#if defined(_MSC_VER) && (_MSC_VER < 1300)
/* MSVC versions before 7 apparently don't believe that you can cast uint64_t
 * to double and really mean it. */
extern INLINE double U64_TO_DBL(uint64_t x) {
  int64_t i = (int64_t) x;
  return (i < 0) ? ((double) INT64_MAX) : (double) i;
}
#define DBL_TO_U64(x) ((uint64_t)(int64_t) (x))
#else
#define U64_TO_DBL(x) ((double) (x))
#define DBL_TO_U64(x) ((uint64_t) (x))
#endif

/* GCC has several useful attributes. */
#if defined(__GNUC__) && __GNUC__ >= 3
#define ATTR_NORETURN __attribute__((noreturn))
#define ATTR_PURE __attribute__((pure))
#define ATTR_CONST __attribute__((const))
#define ATTR_MALLOC __attribute__((malloc))
#define ATTR_NORETURN __attribute__((noreturn))
#define ATTR_NONNULL(x) __attribute__((nonnull x))
/** Macro: Evaluates to <b>exp</b> and hints the compiler that the value
 * of <b>exp</b> will probably be true. */
#define PREDICT_LIKELY(exp) __builtin_expect((exp), 1)
/** Macro: Evaluates to <b>exp</b> and hints the compiler that the value
 * of <b>exp</b> will probably be false. */
#define PREDICT_UNLIKELY(exp) __builtin_expect((exp), 0)
#else
#define ATTR_NORETURN
#define ATTR_PURE
#define ATTR_CONST
#define ATTR_MALLOC
#define ATTR_NORETURN
#define ATTR_NONNULL(x)
#define PREDICT_LIKELY(exp) (exp)
#define PREDICT_UNLIKELY(exp) (exp)
#endif

/* Ways to declare macros. */
#define STMT_NIL (void)0
#ifdef __GNUC__
#define STMT_BEGIN (void) ({
#define STMT_END })
#elif defined(sun) || defined(__sun__)
#define STMT_BEGIN if (1) {
#define STMT_END } else STMT_NIL
#else
#define STMT_BEGIN do {
#define STMT_END } while (0)
#endif

/* ===== String compatibility */
#ifdef MS_WINDOWS
/* Windows names string functions differently from most other platforms. */
#define strncasecmp strnicmp
#define strcasecmp stricmp
#endif
#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz) ATTR_NONNULL((1,2));
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz) ATTR_NONNULL((1,2));
#endif

#ifdef _MSC_VER
#define U64_PRINTF_ARG(a) (a)
#define U64_SCANF_ARG(a) (a)
#define U64_LITERAL(n) (n ## ui64)
#else
#define U64_PRINTF_ARG(a) ((long long unsigned int)(a))
#define U64_SCANF_ARG(a) ((long long unsigned int*)(a))
#define U64_LITERAL(n) (n ## llu)
#endif

#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
#define U64_FORMAT "%I64u"
#else
#define U64_FORMAT "%llu"
#endif

/** Represents an mmaped file. Allocated via tor_mmap_file; freed with
 * tor_munmap_file. */
typedef struct tor_mmap_t {
  const char *data; /**< Mapping of the file's contents. */
  size_t size; /**< Size of the file. */
} tor_mmap_t;

tor_mmap_t *tor_mmap_file(const char *filename) ATTR_NONNULL((1));
void tor_munmap_file(tor_mmap_t *handle) ATTR_NONNULL((1));

int tor_snprintf(char *str, size_t size, const char *format, ...)
  CHECK_PRINTF(3,4) ATTR_NONNULL((1,3));
int tor_vsnprintf(char *str, size_t size, const char *format, va_list args)
  ATTR_NONNULL((1,3));

const void *tor_memmem(const void *haystack, size_t hlen, const void *needle,
                       size_t nlen)  ATTR_PURE ATTR_NONNULL((1,3));
static const void *tor_memstr(const void *haystack, size_t hlen,
                           const char *needle) ATTR_PURE ATTR_NONNULL((1,3));
static INLINE const void *
tor_memstr(const void *haystack, size_t hlen, const char *needle)
{
  return tor_memmem(haystack, hlen, needle, strlen(needle));
}

#define TOR_ISALPHA(c)   isalpha((int)(unsigned char)(c))
#define TOR_ISALNUM(c)   isalnum((int)(unsigned char)(c))
#define TOR_ISSPACE(c)   isspace((int)(unsigned char)(c))
#define TOR_ISXDIGIT(c) isxdigit((int)(unsigned char)(c))
#define TOR_ISDIGIT(c)   isdigit((int)(unsigned char)(c))
#define TOR_ISPRINT(c)   isprint((int)(unsigned char)(c))
#define TOR_ISLOWER(c)   islower((int)(unsigned char)(c))
#define TOR_ISUPPER(c)   isupper((int)(unsigned char)(c))

#define TOR_TOLOWER(c)   ((char)tolower((int)(unsigned char)(c)))
#define TOR_TOUPPER(c)   ((char)toupper((int)(unsigned char)(c)))

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

int tor_close_socket(int s);
int tor_open_socket(int domain, int type, int protocol);
int tor_accept_socket(int sockfd, struct sockaddr *addr, socklen_t *len);
int get_n_open_sockets(void);

#ifdef USE_BSOCKETS
#define tor_socket_send(s, buf, len, flags) bsend(s, buf, len, flags)
#define tor_socket_recv(s, buf, len, flags) brecv(s, buf, len, flags)
#else
#define tor_socket_send(s, buf, len, flags) send(s, buf, len, flags)
#define tor_socket_recv(s, buf, len, flags) recv(s, buf, len, flags)
#endif

#if (SIZEOF_SOCKLEN_T == 0)
typedef int socklen_t;
#endif

/* Define struct in6_addr on platforms that do not have it.  Generally,
 * these platforms are ones without IPv6 support, but we want to have
 * a working in6_addr there anyway, so we can use it to parse IPv6
 * addresses. */
#if !defined(HAVE_STRUCT_IN6_ADDR)
struct in6_addr
{
  union {
    uint8_t u6_addr8[16];
    uint16_t u6_addr16[8];
    uint32_t u6_addr32[4];
  } in6_u;
#define s6_addr   in6_u.u6_addr8
#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32
};
#endif

#if defined(__APPLE__) || defined(__darwin__) || defined(__FreeBSD__) \
    || defined(__NetBSD__) || defined(__OpenBSD__)
/* Many BSD variants seem not to define these. */
#ifndef s6_addr16
#define s6_addr16 __u6_addr.__u6_addr16
#endif
#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif
#endif

#ifndef HAVE_SA_FAMILY_T
typedef uint16_t sa_family_t;
#endif

/* Apparently, MS and Solaris don't define s6_addr16 or s6_addr32. */
#ifdef HAVE_STRUCT_IN6_ADDR_S6_ADDR32
#define S6_ADDR32(x) ((uint32_t*)(x).s6_addr32)
#else
#define S6_ADDR32(x) ((uint32_t*)((char*)&(x).s6_addr))
#endif
#ifdef HAVE_STRUCT_IN6_ADDR_S6_ADDR16
#define S6_ADDR16(x) ((uint16_t*)(x).s6_addr16)
#else
#define S6_ADDR16(x) ((uint16_t*)((char*)&(x).s6_addr))
#endif

/* Define struct sockaddr_in6 on platforms that do not have it. See notes
 * on struct in6_addr. */
#if !defined(HAVE_STRUCT_SOCKADDR_IN6)
struct sockaddr_in6 {
  sa_family_t sin6_family;
  uint16_t sin6_port;
  // uint32_t sin6_flowinfo;
  struct in6_addr sin6_addr;
  // uint32_t sin6_scope_id;
};
#endif

typedef uint8_t maskbits_t;
struct in_addr;
/** DOCDOC */
typedef struct tor_addr_t
{
  sa_family_t family;
  union {
    struct in_addr in_addr;
    struct in6_addr in6_addr;
  } addr;
} tor_addr_t;

/* XXXX021 rename these. */
static INLINE uint32_t IPV4IP(const tor_addr_t *a);
static INLINE uint32_t IPV4IPh(const tor_addr_t *a);
static INLINE uint32_t IPV4MAPh(const tor_addr_t *a);
static INLINE uint16_t IN_FAMILY(const tor_addr_t *a);
static INLINE const struct in_addr *IN4_ADDRESS(const tor_addr_t *a);
static INLINE const struct in6_addr *IN6_ADDRESS(const tor_addr_t *a);

static INLINE const struct in6_addr *
IN6_ADDRESS(const tor_addr_t *a)
{
  return &a->addr.in6_addr;
}

#define IN6_ADDRESS16(x) S6_ADDR16(*IN6_ADDRESS(x))
#define IN6_ADDRESS32(x) S6_ADDR32(*IN6_ADDRESS(x))

static INLINE uint32_t
IPV4IP(const tor_addr_t *a)
{
  return a->addr.in_addr.s_addr;
}
static INLINE uint32_t IPV4IPh(const tor_addr_t *a)
{
  return ntohl(IPV4IP(a));
}
static INLINE uint32_t
IPV4MAPh(const tor_addr_t *a)
{
  return ntohl(IN6_ADDRESS32(a)[3]);
}
static INLINE uint16_t
IN_FAMILY(const tor_addr_t *a)
{
  return a->family;
}
static INLINE const struct in_addr *
IN4_ADDRESS(const tor_addr_t *a)
{
  return &a->addr.in_addr;
}

#define INET_NTOA_BUF_LEN 16 /* 255.255.255.255 */
#define TOR_ADDR_BUF_LEN 46 /* ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255 */

int tor_inet_aton(const char *cp, struct in_addr *addr) ATTR_NONNULL((1,2));
const char *tor_inet_ntop(int af, const void *src, char *dst, size_t len);
int tor_inet_pton(int af, const char *src, void *dst);
int tor_lookup_hostname(const char *name, uint32_t *addr) ATTR_NONNULL((1,2));
void set_socket_nonblocking(int socket);
int tor_socketpair(int family, int type, int protocol, int fd[2]);
int network_init(void);

int tor_addr_lookup(const char *name, uint16_t family, tor_addr_t *addr_out);

/* For stupid historical reasons, windows sockets have an independent
 * set of errnos, and an independent way to get them.  Also, you can't
 * always believe WSAEWOULDBLOCK.  Use the macros below to compare
 * errnos against expected values, and use tor_socket_errno to find
 * the actual errno after a socket operation fails.
 */
#if defined(MS_WINDOWS) && !defined(USE_BSOCKETS)
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

uint16_t get_uint16(const char *cp) ATTR_PURE ATTR_NONNULL((1));
uint32_t get_uint32(const char *cp) ATTR_PURE ATTR_NONNULL((1));
void set_uint16(char *cp, uint16_t v) ATTR_NONNULL((1));
void set_uint32(char *cp, uint32_t v) ATTR_NONNULL((1));

int set_max_file_descriptors(unsigned long limit, unsigned long cap);
int switch_id(const char *user, const char *group);
#ifdef HAVE_PWD_H
char *get_user_homedir(const char *username);
#endif

int spawn_func(void (*func)(void *), void *data);
void spawn_exit(void) ATTR_NORETURN;

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

/* Because we use threads instead of processes on most platforms (Windows,
 * Linux, etc), we need locking for them.  On platforms with poor thread
 * support or broken gethostbyname_r, these functions are no-ops. */

typedef struct tor_mutex_t tor_mutex_t;
#ifdef TOR_IS_MULTITHREADED
tor_mutex_t *tor_mutex_new(void);
void tor_mutex_acquire(tor_mutex_t *m);
void tor_mutex_release(tor_mutex_t *m);
void tor_mutex_free(tor_mutex_t *m);
unsigned long tor_get_thread_id(void);
void tor_threads_init(void);
#else
#define tor_mutex_new() ((tor_mutex_t*)tor_malloc(sizeof(int)))
#define tor_mutex_acquire(m) STMT_NIL
#define tor_mutex_release(m) STMT_NIL
#define tor_mutex_free(m) STMT_BEGIN tor_free(m); STMT_END
#define tor_get_thread_id() (1UL)
#define tor_threads_init() STMT_NIL
#endif

#ifdef TOR_IS_MULTITHREADED
#if 0
typedef struct tor_cond_t tor_cond_t;
tor_cond_t *tor_cond_new(void);
void tor_cond_free(tor_cond_t *cond);
int tor_cond_wait(tor_cond_t *cond, tor_mutex_t *mutex);
void tor_cond_signal_one(tor_cond_t *cond);
void tor_cond_signal_all(tor_cond_t *cond);
#endif
#endif

/* Platform-specific helpers. */
#ifdef MS_WINDOWS
char *format_win32_error(DWORD err);
#endif

/*for some reason my compiler doesn't have these version flags defined
  a nice homework assignment for someone one day is to define the rest*/
//these are the values as given on MSDN
#ifdef MS_WINDOWS

#ifndef VER_SUITE_EMBEDDEDNT
#define VER_SUITE_EMBEDDEDNT 0x00000040
#endif

#ifndef VER_SUITE_SINGLEUSERTS
#define VER_SUITE_SINGLEUSERTS 0x00000100
#endif

#endif

#endif

