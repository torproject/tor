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

void *tor_malloc(size_t size);
void *tor_malloc_zero(size_t size);
void *tor_realloc(void *ptr, size_t size);
char *tor_strdup(const char *s);
char *tor_strndup(const char *s, size_t n);
#define tor_free(p) do {if(p) {free(p); (p)=NULL;}} while(0)

typedef struct {
  void **list;
  int num_used;
  int max;
} smartlist_t;

smartlist_t *smartlist_create(int max_elements);
void smartlist_free(smartlist_t *sl);
void smartlist_add(smartlist_t *sl, void *element);
void smartlist_remove(smartlist_t *sl, void *element);
int smartlist_isin(smartlist_t *sl, void *element);
int smartlist_overlap(smartlist_t *sl1, smartlist_t *sl2);
void smartlist_intersect(smartlist_t *sl1, smartlist_t *sl2);
void smartlist_subtract(smartlist_t *sl1, smartlist_t *sl2);
void *smartlist_choose(smartlist_t *sl);

const char *eat_whitespace(const char *s);
const char *eat_whitespace_no_nl(const char *s);
const char *find_whitespace(const char *s);

void tor_gettimeofday(struct timeval *timeval);
long tv_udiff(struct timeval *start, struct timeval *end);
void tv_addms(struct timeval *a, long ms);
void tv_add(struct timeval *a, struct timeval *b);
int tv_cmp(struct timeval *a, struct timeval *b);
time_t tor_timegm (struct tm *tm);

int write_all(int fd, const char *buf, size_t count, int isSocket);
int read_all(int fd, char *buf, size_t count, int isSocket);

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

int is_internal_IP(uint32_t ip);

const char *get_uname(void);

/* Start putting the process into daemon mode: fork and drop all resources
 * except standard fds.  The parent process never returns, but stays around
 * until finish_daemon is called.  (Note: it's safe to call this more
 * than once: calls after the first are ignored.)
 */
void start_daemon(char *desired_cwd);
/* Finish putting the process into daemon mode: drop standard fds, and tell
 * the parent process to exit.  (Note: it's safe to call this more than once:
 * calls after the first are ignored.  Calls start_daemon first if it hasn't
 * been called already.)
 */
void finish_daemon(void);

void write_pidfile(char *filename);
int switch_id(char *user, char *group);

struct in_addr;
int tor_inet_aton(const char *cp, struct in_addr *addr);

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
