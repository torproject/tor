/* Copyright 2003-2004 Roger Dingledine; Copyright 2004 Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file util.h
 * \brief Headers for util.c
 **/

#ifndef __UTIL_H
#define __UTIL_H

#include "orconfig.h"
#include "torint.h"
#include <stdio.h>
#include <assert.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif

/** Replace assert() with a variant that sends failures to the log before
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

/* Memory management */
void *tor_malloc(size_t size);
void *tor_malloc_zero(size_t size);
void *tor_realloc(void *ptr, size_t size);
char *tor_strdup(const char *s);
char *tor_strndup(const char *s, size_t n);
#define tor_free(p) do {if(p) {free(p); (p)=NULL;}} while(0)

/* String manipulation */
#define HEX_CHARACTERS "0123456789ABCDEFabcdef"
size_t strlcat(char *dst, const char *src, size_t siz);
size_t strlcpy(char *dst, const char *src, size_t siz);

void tor_strlower(char *s);
int strcmpstart(const char *s1, const char *s2);
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
const char *hex_str(const char *from, size_t fromlen);
const char *eat_whitespace(const char *s);
const char *eat_whitespace_no_nl(const char *s);
const char *find_whitespace(const char *s);


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
void format_iso_time(char *buf, time_t t);
int parse_iso_time(const char *buf, time_t *t);

/* File helpers */
int write_all(int fd, const char *buf, size_t count, int isSocket);
int read_all(int fd, char *buf, size_t count, int isSocket);

typedef enum { FN_ERROR, FN_NOENT, FN_FILE, FN_DIR} file_status_t;
file_status_t file_status(const char *filename);

int check_private_dir(const char *dirname, int create);
int write_str_to_file(const char *fname, const char *str, int bin);
char *read_file_to_str(const char *filename, int bin);
int parse_line_from_file(char *line, size_t maxlen, FILE *f, char **key_out, char **value_out);
char *expand_filename(const char *filename);

/* Net helpers */
int is_internal_IP(uint32_t ip);
int is_local_IP(uint32_t ip);
int tor_lookup_hostname(const char *name, uint32_t *addr);
int parse_addr_port(const char *addrport, char **address, uint32_t *addr,
                    uint16_t *port);
int parse_addr_and_port_range(const char *s, uint32_t *addr_out,
                              uint32_t *mask_out, uint16_t *port_min_out,
                              uint16_t *port_max_out);

/* Process helpers */
void start_daemon(const char *desired_cwd);
void finish_daemon(void);
void write_pidfile(char *filename);

#endif
/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
