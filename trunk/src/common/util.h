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
#ifndef HAVE_GETTIMEOFDAY
#ifdef HAVE_FTIME
#define USING_FAKE_TIMEVAL
#include <sys/timeb.h>
#define timeval timeb
#define tv_sec time
#define tv_usec millitm
#endif
#endif

#ifdef _MSC_VER
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

void set_socket_nonblocking(int socket);

/* Minimalist interface to run a void function in the background.  On
   unix calls fork, on win32 calls beginthread.  Returns -1 on failure.
   func should not return, but rather should call spawn_exit.
*/
int spawn_func(int (*func)(void *), void *data);
void spawn_exit();

int tor_socketpair(int family, int type, int protocol, int fd[2]);

#endif
