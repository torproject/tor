/* Copyright 2003 Roger Dingledine */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef __UTIL_H
#define __UTIL_H

#include "orconfig.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#if _MSC_VER > 1300
#include <winsock2.h>
#include <ws2tcpip.h>
#elif defined(_MSC_VER)
#include <winsock.h>
#endif
#include <errno.h>
#ifndef HAVE_GETTIMEOFDAY
#ifdef HAVE_FTIME
#define USING_FAKE_TIMEVAL
#include <sys/timeb.h>
#define timeval timeb
#define tv_sec time
#define tv_usec millitm
#endif
#endif

#ifdef MS_WINDOWS
/* Windows names string functions funnily. */
#define strncasecmp strnicmp
#define strcasecmp stricmp
#define INLINE __inline
#else
#define INLINE inline
#endif

void *tor_malloc(size_t size);

/* Same as gettimeofday, but no need to check exit value. */
void my_gettimeofday(struct timeval *timeval);
/* Returns the number of microseconds between start and end.  Requires that
 * end >= start, and that the number of microseconds < LONG_MAX. */
long tv_udiff(struct timeval *start, struct timeval *end);

void tv_addms(struct timeval *a, long ms);
void tv_add(struct timeval *a, struct timeval *b);
int tv_cmp(struct timeval *a, struct timeval *b);

int write_all(int fd, const void *buf, size_t count);
int read_all(int fd, void *buf, size_t count);

void set_socket_nonblocking(int socket);

/* Minimalist interface to run a void function in the background.  On
   unix calls fork, on win32 calls beginthread.  Returns -1 on failure.
   func should not return, but rather should call spawn_exit.
*/
int spawn_func(int (*func)(void *), void *data);
void spawn_exit();

int tor_socketpair(int family, int type, int protocol, int fd[2]);

/* For stupid historical reasons, windows sockets have an independent set of 
 * errnos which they use as the fancy strikes them.
 */
#ifdef MS_WINDOWS
#define ERRNO_EAGAIN(e)           ((e) == EAGAIN || (e) == WSAEWOULDBLOCK)
#define ERRNO_EINPROGRESS(e)      ((e) == WSAEINPROGRESS)
#define ERRNO_CONN_EINPROGRESS(e) ((e) == WSAEINPROGRESS || (e) == WSAEINVAL)
int correct_socket_errno(int s);
#else
#define ERRNO_EAGAIN(e)           ((e) == EAGAIN)
#define ERRNO_EINPROGRESS(e)      ((e) == EINPROGRESS)
#define ERRNO_CONN_EINPROGRESS(e) ((e) == EINPROGRESS)
#define correct_socket_errno(s)   (errno)
#endif


#endif
