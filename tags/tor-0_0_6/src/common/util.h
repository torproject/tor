/* Copyright 2003 Roger Dingledine */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef __UTIL_H
#define __UTIL_H

#include "orconfig.h"
#include "torint.h"
#include <stdio.h>
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
/* Windows names string functions differently from most other platforms. */
#define strncasecmp strnicmp
#define strcasecmp stricmp
/* "inline" is __inline on windows. " */
#define INLINE __inline
/* Windows compilers before VC7 don't have __FUNCTION__. */
#if _MSC_VER < 1300
#define __FUNCTION__ "???"
#endif
#else
#define INLINE inline
#endif

/* Replace assert() with a variant that sends failures to the log before
 * calling assert() normally.
 */
#ifdef NDEBUG
#define tor_assert(expr) do {} while(0)
#else
#define tor_assert(expr) do {                                 \
 if (!(expr)) {                                               \
   log(LOG_ERR, "%s:%d: %s: Assertion %s failed; aborting.",  \
       __FILE__, __LINE__, __FUNCTION__, #expr);              \
   assert(expr); /* write to console too. */                  \
   abort();  /* unreached */                                  \
 } } while (0)
#endif

/* On windows, you have to call close() on fds returned by open(), and
 * closesocket() on fds returned by socket().  On Unix, everything
 * gets close()'d.  We abstract this difference by always using the
 * following macro to close sockets, and always using close() on
 * files.
 */
#ifdef MS_WINDOWS
#define tor_close_socket(s) closesocket(s)
#else
#define tor_close_socket(s) close(s)
#endif

/* legal characters in a filename */
/* XXXX This isn't so on windows. */
#define CONFIG_LEGAL_FILENAME_CHARACTERS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_/"

size_t strlcat(char *dst, const char *src, size_t siz);
size_t strlcpy(char *dst, const char *src, size_t siz);

void *tor_malloc(size_t size);
void *tor_malloc_zero(size_t size);
void *tor_realloc(void *ptr, size_t size);
char *tor_strdup(const char *s);
char *tor_strndup(const char *s, size_t n);
#define tor_free(p) do {if(p) {free(p); (p)=NULL;}} while(0)
void tor_strlower(char *s);

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
#if 1
uint16_t get_uint16(const char *cp);
uint32_t get_uint32(const char *cp);
void set_uint16(char *cp, uint16_t v);
void set_uint32(char *cp, uint32_t v);
#else
#define get_uint16(cp)                          \
  ( ((*(((uint8_t*)(cp))+0))<<8) +              \
    ((*(((uint8_t*)(cp))+1))   ) )
#define get_uint32(cp)                          \
  ( ((*(((uint8_t*)(cp))+0))<<24) +             \
    ((*(((uint8_t*)(cp))+1))<<16) +             \
    ((*(((uint8_t*)(cp))+2))<<8 ) +             \
    ((*(((uint8_t*)(cp))+3))    ) )
#define set_uint16(cp,v)                        \
  do {                                          \
    uint16_t u16v = (v);                        \
    *(((uint8_t*)(cp))+0) = (v >> 8)&0xff;      \
    *(((uint8_t*)(cp))+1) = (v >> 0)&0xff;      \
  } while (0)
#define set_uint32(cp,val)                      \
  do {                                          \
    uint32_t u32v = (v);                        \
    *(((uint8_t*)(cp))+0) = s32 >> 24)&0xff;    \
    *(((uint8_t*)(cp))+1) = s32 >> 16)&0xff;    \
    *(((uint8_t*)(cp))+2) = s32 >> 8)&0xff;     \
    *(((uint8_t*)(cp))+3) = s32 >> 0)&0xff;     \
  } while (0)
#endif
#endif

void hex_encode(const char *from, int fromlen, char *to);
const char *hex_str(const char *from, int fromlen);

/* Resizeable array. */
typedef struct smartlist_t smartlist_t;

smartlist_t *smartlist_create();
void smartlist_free(smartlist_t *sl);
void smartlist_set_capacity(smartlist_t *sl, int n);
void smartlist_clear(smartlist_t *sl);
void smartlist_truncate(smartlist_t *sl, int n);
void smartlist_add(smartlist_t *sl, void *element);
void smartlist_add_all(smartlist_t *sl, const smartlist_t *s2);
void smartlist_remove(smartlist_t *sl, void *element);
int smartlist_isin(const smartlist_t *sl, void *element);
int smartlist_overlap(const smartlist_t *sl1, const smartlist_t *sl2);
void smartlist_intersect(smartlist_t *sl1, const smartlist_t *sl2);
void smartlist_subtract(smartlist_t *sl1, const smartlist_t *sl2);
void *smartlist_choose(const smartlist_t *sl);
void *smartlist_get(const smartlist_t *sl, int idx);
void *smartlist_set(smartlist_t *sl, int idx, void *val);
void *smartlist_del(smartlist_t *sl, int idx);
void *smartlist_del_keeporder(smartlist_t *sl, int idx);
void smartlist_insert(smartlist_t *sl, int idx, void *val);
int smartlist_len(const smartlist_t *sl);
#define SMARTLIST_FOREACH(sl, type, var, cmd)                   \
  do {                                                          \
    int sl_idx, sl_len=smartlist_len(sl);                       \
    type var;                                                   \
    for(sl_idx = 0; sl_idx < sl_len; ++sl_idx) {                \
      var = smartlist_get((sl),sl_idx);                         \
      do {cmd;} while(0);                                       \
    } } while (0)

/* Map from const char * to void*. Implemented with a splay tree. */
typedef struct strmap_t strmap_t;
typedef struct strmap_entry_t strmap_entry_t;
typedef struct strmap_entry_t strmap_iter_t;
strmap_t* strmap_new(void);
void* strmap_set(strmap_t *map, const char *key, void *val);
void* strmap_get(strmap_t *map, const char *key);
void* strmap_remove(strmap_t *map, const char *key);
void* strmap_set_lc(strmap_t *map, const char *key, void *val);
void* strmap_get_lc(strmap_t *map, const char *key);
void* strmap_remove_lc(strmap_t *map, const char *key);
typedef void* (*strmap_foreach_fn)(const char *key, void *val, void *data);
void strmap_foreach(strmap_t *map, strmap_foreach_fn fn, void *data);
void strmap_free(strmap_t *map, void (*free_val)(void*));

strmap_iter_t *strmap_iter_init(strmap_t *map);
strmap_iter_t *strmap_iter_next(strmap_t *map, strmap_iter_t *iter);
strmap_iter_t *strmap_iter_next_rmv(strmap_t *map, strmap_iter_t *iter);
void strmap_iter_get(strmap_iter_t *iter, const char **keyp, void **valp);

int strmap_iter_done(strmap_iter_t *iter);

/* String manipulation */
const char *eat_whitespace(const char *s);
const char *eat_whitespace_no_nl(const char *s);
const char *find_whitespace(const char *s);

/* Time helpers */
void tor_gettimeofday(struct timeval *timeval);
long tv_udiff(struct timeval *start, struct timeval *end);
void tv_addms(struct timeval *a, long ms);
void tv_add(struct timeval *a, struct timeval *b);
int tv_cmp(struct timeval *a, struct timeval *b);
time_t tor_timegm(struct tm *tm);

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
int tor_lookup_hostname(const char *name, uint32_t *addr);

/* For stupid historical reasons, windows sockets have an independent
 * set of errnos, and an independent way to get them.  Also, you can't
 * always believe WSAEWOULDBLOCK.  Use the macros below to compare
 * errnos against expected values, and use tor_socket_errno to find
 * the actual errno after a socket operation fails.
 */
#ifdef MS_WINDOWS
#define ERRNO_IS_EAGAIN(e)           ((e) == EAGAIN || (e) == WSAEWOULDBLOCK)
#define ERRNO_IS_EINPROGRESS(e)      ((e) == WSAEINPROGRESS)
#define ERRNO_IS_CONN_EINPROGRESS(e) ((e) == WSAEINPROGRESS || (e)== WSAEINVAL)
int tor_socket_errno(int sock);
#else
#define ERRNO_IS_EAGAIN(e)           ((e) == EAGAIN)
#define ERRNO_IS_EINPROGRESS(e)      ((e) == EINPROGRESS)
#define ERRNO_IS_CONN_EINPROGRESS(e) ((e) == EINPROGRESS)
#define tor_socket_errno(sock)       (errno)
#endif

#endif

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
