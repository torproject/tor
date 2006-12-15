/* Copyright 2003-2004 Roger Dingledine
 * Copyright 2004-2006 Roger Dingledine, Nick Mathewson */
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
/* Nobody should ever want to build with NDEBUG set.  99% of our asserts will
 * be outside the critical path anyway, so it's silly to disable bugchecking
 * throughout the entire program just because a few asserts are slowing you
 * down.  Profile, optimize the critical path, and keep debugging on.
 *
 * And I'm not just saying that because some of our asserts check
 * security-critical properties.
 */
#error "Sorry; we don't support building with NDEBUG."
#else
#ifdef __GNUC__
#define PREDICT_FALSE(x) PREDICT((x) == ((typeof(x)) 0), 0)
#else
#define PREDICT_FALSE(x) !(x)
#endif
#define tor_assert(expr) do {                                           \
    if (PREDICT_FALSE(expr)) {                                          \
      log(LOG_ERR, LD_BUG, "%s:%d: %s: Assertion %s failed; aborting.", \
          _SHORT_FILE_, __LINE__, __func__, #expr);                     \
      fprintf(stderr,"%s:%d %s: Assertion %s failed; aborting.\n",      \
              _SHORT_FILE_, __LINE__, __func__, #expr);                 \
      abort();                                                          \
    } } while (0)
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
void *_tor_malloc(size_t size DMALLOC_PARAMS) ATTR_MALLOC;
void *_tor_malloc_zero(size_t size DMALLOC_PARAMS) ATTR_MALLOC;
void *_tor_realloc(void *ptr, size_t size DMALLOC_PARAMS);
char *_tor_strdup(const char *s DMALLOC_PARAMS) ATTR_MALLOC ATTR_NONNULL((1));
char *_tor_strndup(const char *s, size_t n DMALLOC_PARAMS)
  ATTR_MALLOC ATTR_NONNULL((1));
void *_tor_memdup(const void *mem, size_t len DMALLOC_PARAMS)
  ATTR_MALLOC ATTR_NONNULL((1));
void _tor_free(void *mem);
#ifdef USE_DMALLOC
extern int dmalloc_free(const char *file, const int line, void *pnt,
                        const int func_id);
#define tor_free(p) do { \
    if (PREDICT((p)!=NULL, 1)) {                     \
      dmalloc_free(_SHORT_FILE_, __LINE__, (p), 0); \
      (p)=NULL;                                     \
    }                                               \
  } while (0)
#else
#define tor_free(p) do { if (PREDICT((p)!=NULL,1)) { free(p); (p)=NULL;} } \
  while (0)
#endif

#define tor_malloc(size)       _tor_malloc(size DMALLOC_ARGS)
#define tor_malloc_zero(size)  _tor_malloc_zero(size DMALLOC_ARGS)
#define tor_realloc(ptr, size) _tor_realloc(ptr, size DMALLOC_ARGS)
#define tor_strdup(s)          _tor_strdup(s DMALLOC_ARGS)
#define tor_strndup(s, n)      _tor_strndup(s, n DMALLOC_ARGS)
#define tor_memdup(s, n)       _tor_memdup(s, n DMALLOC_ARGS)

/** Return the offset of <b>member</b> within the type <b>tp</b>, in bytes */
#if defined(__GNUC__) && __GNUC__ > 3
#define STRUCT_OFFSET(tp, member) __builtin_offsetof(tp, member)
#else
 #define STRUCT_OFFSET(tp, member) \
   ((off_t) (((char*)&((tp*)0)->member)-(char*)0))
#endif

/* String manipulation */
#define HEX_CHARACTERS "0123456789ABCDEFabcdef"
void tor_strlower(char *s) ATTR_NONNULL((1));
void tor_strupper(char *s) ATTR_NONNULL((1));
int tor_strisprint(const char *s) ATTR_PURE ATTR_NONNULL((1));
int tor_strisnonupper(const char *s) ATTR_PURE ATTR_NONNULL((1));
int strcmpstart(const char *s1, const char *s2) ATTR_PURE ATTR_NONNULL((1,2));
int strcasecmpstart(const char *s1, const char *s2)
  ATTR_PURE ATTR_NONNULL((1,2));
int strcmpend(const char *s1, const char *s2) ATTR_PURE ATTR_NONNULL((1,2));
int strcasecmpend(const char *s1, const char *s2)
  ATTR_PURE ATTR_NONNULL((1,2));
int tor_strstrip(char *s, const char *strip) ATTR_NONNULL((1,2));
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
const char *hex_str(const char *from, size_t fromlen) ATTR_NONNULL((1));
const char *eat_whitespace(const char *s) ATTR_PURE;
const char *eat_whitespace_no_nl(const char *s) ATTR_PURE;
const char *find_whitespace(const char *s) ATTR_PURE;
int tor_mem_is_zero(const char *mem, size_t len) ATTR_PURE;
int tor_digest_is_zero(const char *digest) ATTR_PURE;
char *esc_for_log(const char *string) ATTR_MALLOC;
const char *escaped(const char *string);
struct smartlist_t;
void wrap_string(struct smartlist_t *out, const char *string, size_t width,
                 const char *prefix0, const char *prefixRest);

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
int write_chunks_to_file(const char *fname, const struct smartlist_t *chunks,
                         int bin);
int append_bytes_to_file(const char *fname, const char *str, size_t len,
                         int bin);

char *read_file_to_str(const char *filename, int bin, size_t *size_out)
  ATTR_MALLOC;
char *parse_line_from_str(char *line, char **key_out, char **value_out);
char *expand_filename(const char *filename);
struct smartlist_t *tor_listdir(const char *dirname);
int path_is_relative(const char *filename) ATTR_PURE;

/* Net helpers */
int is_internal_IP(uint32_t ip, int for_listening) ATTR_PURE;
int parse_addr_port(int severity, const char *addrport, char **address,
                    uint32_t *addr, uint16_t *port_out);
int parse_port_range(const char *port, uint16_t *port_min_out,
                     uint16_t *port_max_out);
int parse_addr_and_port_range(const char *s, uint32_t *addr_out,
                              uint32_t *mask_out, uint16_t *port_min_out,
                              uint16_t *port_max_out);
int addr_mask_get_bits(uint32_t mask);
#define INET_NTOA_BUF_LEN 16
int tor_inet_ntoa(struct in_addr *in, char *buf, size_t buf_len);
char *tor_dup_addr(uint32_t addr) ATTR_MALLOC;
int is_plausible_address(const char *name);
int get_interface_address(int severity, uint32_t *addr);

/* Process helpers */
void start_daemon(void);
void finish_daemon(const char *desired_cwd);
void write_pidfile(char *filename);

#endif

