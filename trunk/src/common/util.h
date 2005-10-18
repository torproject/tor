/* Copyright 2003-2004 Roger Dingledine
 * Copyright 2004-2005 Roger Dingledine, Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file util.h
 * \brief Headers for util.c
 **/

#ifndef __UTIL_H
#define __UTIL_H
#define UTIL_H_ID "$Id$"

#include "orconfig.h"
#include "torint.h"
#include "compat.h"
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif

/* Replace assert() with a variant that sends failures to the log before
 * calling assert() normally.
 */
#ifdef NDEBUG
/* Nobody should ever want to build with NDEBUG set.  99% of your asserts will
 * be outside the critical path anyway, so it's silly to disable bugchecking
 * throughout the entire program just because a few asserts are slowing you
 * down.  Profile, optimize the critical path, and keep debugging on.
 *
 * And I'm not just saying that because some of our asserts check
 * security-critical properties.
 */
#error "Sorry; we don't support building with NDEBUG."
#else
#ifdef OLD_LOG_INTERFACE
#define tor_assert(expr) do {                                            \
 if (!(expr)) {                                                          \
   log(LOG_ERR, "%s:%d: %s: Assertion %s failed; aborting.",            \
       _SHORT_FILE_, __LINE__, __FUNCTION__, #expr);                     \
   fprintf(stderr,"%s:%d %s: Assertion %s failed; aborting.\n",          \
       _SHORT_FILE_, __LINE__, __FUNCTION__, #expr);                     \
   abort();  /* unreached */                                             \
 } } while (0)
#else
#define tor_assert(expr) do {                                            \
 if (!(expr)) {                                                          \
   log(LOG_ERR, LD_GENERAL, "%s:%d: %s: Assertion %s failed; aborting.", \
       _SHORT_FILE_, __LINE__, __FUNCTION__, #expr);                     \
   fprintf(stderr,"%s:%d %s: Assertion %s failed; aborting.\n",          \
       _SHORT_FILE_, __LINE__, __FUNCTION__, #expr);                     \
   abort();  /* unreached */                                             \
 } } while (0)
#endif
#endif

#ifdef USE_DMALLOC
#define DMALLOC_PARAMS , const char *file, const int line
#define DMALLOC_ARGS , _SHORT_FILE_, __LINE__
#else
#define DMALLOC_PARAMS
#define DMALLOC_ARGS
#endif

/** Define this if you want Tor to crash when any problem comes up,
 * so you can get a coredump and track things down. */
// #define tor_fragile_assert() tor_assert(0)
#define tor_fragile_assert()

/* Memory management */
void *_tor_malloc(size_t size DMALLOC_PARAMS);
void *_tor_malloc_zero(size_t size DMALLOC_PARAMS);
void *_tor_realloc(void *ptr, size_t size DMALLOC_PARAMS);
char *_tor_strdup(const char *s DMALLOC_PARAMS);
char *_tor_strndup(const char *s, size_t n DMALLOC_PARAMS);
#ifdef USE_DMALLOC
extern int dmalloc_free(const char *file, const int line, void *pnt,
                        const int func_id);
#define tor_free(p) do { \
    if (p) {                                        \
      dmalloc_free(_SHORT_FILE_, __LINE__, (p), 0); \
      (p)=NULL;                                     \
    }                                               \
  } while (0)
#else
#define tor_free(p) do { if (p) {free(p); (p)=NULL;} } while (0)
#endif

#define tor_malloc(size)       _tor_malloc(size DMALLOC_ARGS)
#define tor_malloc_zero(size)  _tor_malloc_zero(size DMALLOC_ARGS)
#define tor_realloc(ptr, size) _tor_realloc(ptr, size DMALLOC_ARGS)
#define tor_strdup(s)          _tor_strdup(s DMALLOC_ARGS)
#define tor_strndup(s, n)      _tor_strndup(s, n DMALLOC_ARGS)

/* String manipulation */
#define HEX_CHARACTERS "0123456789ABCDEFabcdef"
void tor_strlower(char *s);
void tor_strupper(char *s);
int strcmpstart(const char *s1, const char *s2);
int strcasecmpstart(const char *s1, const char *s2);
int strcmpend(const char *s1, const char *s2);
int strcasecmpend(const char *s1, const char *s2);
int tor_strstrip(char *s, const char *strip);
typedef enum {
  ALWAYS_TERMINATE, NEVER_TERMINATE, TERMINATE_IF_EVEN
} part_finish_rule_t;
int tor_strpartition(char *dest, size_t dest_len,
                     const char *s, const char *insert, size_t n,
                     part_finish_rule_t rule);
long tor_parse_long(const char *s, int base, long min,
                    long max, int *ok, char **next);
unsigned long tor_parse_ulong(const char *s, int base, unsigned long min,
                              unsigned long max, int *ok, char **next);
uint64_t tor_parse_uint64(const char *s, int base, uint64_t min,
                         uint64_t max, int *ok, char **next);
const char *hex_str(const char *from, size_t fromlen);
const char *eat_whitespace(const char *s);
const char *eat_whitespace_no_nl(const char *s);
const char *find_whitespace(const char *s);

void base16_encode(char *dest, size_t destlen, const char *src, size_t srclen);
int base16_decode(char *dest, size_t destlen, const char *src, size_t srclen);

/* Time helpers */
long tv_udiff(struct timeval *start, struct timeval *end);
void tv_addms(struct timeval *a, long ms);
void tv_add(struct timeval *a, struct timeval *b);
int tv_cmp(struct timeval *a, struct timeval *b);
time_t tor_timegm(struct tm *tm);
#define RFC1123_TIME_LEN 29
void format_rfc1123_time(char *buf, time_t t);
int parse_rfc1123_time(const char *buf, time_t *t);
#define ISO_TIME_LEN 19
void format_local_iso_time(char *buf, time_t t);
void format_iso_time(char *buf, time_t t);
int parse_iso_time(const char *buf, time_t *t);

/* File helpers */
int write_all(int fd, const char *buf, size_t count, int isSocket);
int read_all(int fd, char *buf, size_t count, int isSocket);

typedef enum { FN_ERROR, FN_NOENT, FN_FILE, FN_DIR} file_status_t;
file_status_t file_status(const char *filename);

typedef enum { CPD_NONE, CPD_CREATE, CPD_CHECK } cpd_check_t;
int check_private_dir(const char *dirname, cpd_check_t check);
int write_str_to_file(const char *fname, const char *str, int bin);
int write_bytes_to_file(const char *fname, const char *str, size_t len,
                        int bin);
/** An ad-hoc type to hold a string of characters and a count; used by
 * write_chunks_to_file. */
typedef struct sized_chunk_t {
  const char *bytes;
  size_t len;
} sized_chunk_t;
struct smartlist_t;
int write_chunks_to_file(const char *fname, const struct smartlist_t *chunks,
                         int bin);
int append_bytes_to_file(const char *fname, const char *str, size_t len,
                         int bin);

char *read_file_to_str(const char *filename, int bin);
char *parse_line_from_str(char *line, char **key_out, char **value_out);
char *expand_filename(const char *filename);
struct smartlist_t *tor_listdir(const char *dirname);

/* Net helpers */
int is_internal_IP(uint32_t ip);
int is_local_IP(uint32_t ip);
int parse_addr_port(const char *addrport, char **address, uint32_t *addr,
                    uint16_t *port);
int parse_addr_and_port_range(const char *s, uint32_t *addr_out,
                              uint32_t *mask_out, uint16_t *port_min_out,
                              uint16_t *port_max_out);
#define INET_NTOA_BUF_LEN 16
int tor_inet_ntoa(struct in_addr *in, char *buf, size_t buf_len);
char *tor_dup_addr(uint32_t addr);
int is_plausible_address(const char *name);
int get_interface_address(uint32_t *addr);

/* Process helpers */
void start_daemon(void);
void finish_daemon(const char *desired_cwd);
void write_pidfile(char *filename);

#endif

