/* Copyright 2003 Roger Dingledine */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef __UTIL_H
#define __UTIL_H

#include "../or/or.h"

#if _MSC_VER > 1300
#include <winsock2.h>
#include <ws2tcpip.h>
#elif defined(_MSC_VER)
#include <winsock.h>
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

#ifdef MS_WINDOWS
/* Windows names string functions funnily. */
#define strncasecmp strnicmp
#define strcasecmp stricmp
#define INLINE __inline
#else
#define INLINE inline
#endif

#define xfree(p) do {if(p) {free(p); (p)=NULL;}} while(0) /* XXX use everywhere? */
void *tor_malloc(size_t size);
void *tor_realloc(void *ptr, size_t size);
char *tor_strdup(const char *s);
void tor_gettimeofday(struct timeval *timeval);

long tv_udiff(struct timeval *start, struct timeval *end);

void tv_addms(struct timeval *a, long ms);
void tv_add(struct timeval *a, struct timeval *b);
int tv_cmp(struct timeval *a, struct timeval *b);

time_t tor_timegm (struct tm *tm);

int write_all(int fd, const char *buf, size_t count);
int read_all(int fd, char *buf, size_t count);

void set_socket_nonblocking(int socket);

typedef enum { FN_ERROR, FN_NOENT, FN_FILE, FN_DIR} file_status_t;

file_status_t file_status(const char *filename);
int check_private_dir(const char *dirname, int create);
int write_str_to_file(const char *fname, const char *str);
char *read_file_to_str(const char *filename);
int parse_line_from_file(char *line, int maxlen, FILE *f, char **key_out, char **value_out);

int spawn_func(int (*func)(void *), void *data);
void spawn_exit();

int tor_socketpair(int family, int type, int protocol, int fd[2]);

const char *get_uname(void);

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
