/* Copyright 2003 Roger Dingledine
 * Copyright 2004-2006 Roger Dingledine, Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id$ */
const char util_c_id[] = "$Id$";

/**
 * \file util.c
 * \brief Common functions for strings, IO, network, data structures,
 * process control.
 **/

/* This is required on rh7 to make strptime not complain.
 */
#define _GNU_SOURCE

#include "orconfig.h"
#include "util.h"
#include "log.h"
#include "crypto.h"
#include "torint.h"
#include "container.h"

#ifdef MS_WINDOWS
#include <io.h>
#include <direct.h>
#else
#include <dirent.h>
#include <pwd.h>
#endif

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_FCNTL_H
#include <sys/fcntl.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif
#ifndef O_TEXT
#define O_TEXT 0
#endif

/* =====
 * Memory management
 * ===== */
#ifdef USE_DMALLOC
 #include <dmalloc.h>
 #define DMALLOC_FN_ARGS , file, line
#else
 #define dmalloc_strdup(file, line, string, xalloc_b) strdup(string)

 #define dmalloc_malloc(file, line, size, func_id, alignment, xalloc_b) \
     malloc(size)
 #define DMALLOC_FUNC_MALLOC 0

 #define dmalloc_realloc(file, line, old_pnt, new_size, func_id, xalloc_b) \
     realloc((old_pnt), (new_size))
 #define DMALLOC_FUNC_REALLOC 0
 #define DMALLOC_FN_ARGS
#endif

/** Allocate a chunk of <b>size</b> bytes of memory, and return a pointer to
 * result.  On error, log and terminate the process.  (Same as malloc(size),
 * but never returns NULL.)
 *
 * <b>file</b> and <b>line</b> are used if dmalloc is enabled, and
 * ignored otherwise.
 */
void *
_tor_malloc(size_t size DMALLOC_PARAMS)
{
  void *result;

#ifndef MALLOC_ZERO_WORKS
  /* Some libcs don't do the right thing on size==0. Override them. */
  if (size==0) {
    size=1;
  }
#endif
  result = dmalloc_malloc(file, line, size, DMALLOC_FUNC_MALLOC, 0, 0);

  if (PREDICT(result == NULL, 0)) {
    log_err(LD_MM,"Out of memory. Dying.");
    /* If these functions die within a worker process, they won't call
     * spawn_exit, but that's ok, since the parent will run out of memory soon
     * anyway. */
    exit(1);
  }
  return result;
}

/* Allocate a chunk of <b>size</b> bytes of memory, fill the memory with
 * zero bytes, and return a pointer to the result.  Log and terminate
 * the process on error.  (Same as calloc(size,1), but never returns NULL.)
 */
void *
_tor_malloc_zero(size_t size DMALLOC_PARAMS)
{
  void *result = _tor_malloc(size DMALLOC_FN_ARGS);
  memset(result, 0, size);
  return result;
}

/** Change the size of the memory block pointed to by <b>ptr</b> to <b>size</b>
 * bytes long; return the new memory block.  On error, log and
 * terminate. (Like realloc(ptr,size), but never returns NULL.)
 */
void *
_tor_realloc(void *ptr, size_t size DMALLOC_PARAMS)
{
  void *result;

  result = dmalloc_realloc(file, line, ptr, size, DMALLOC_FUNC_REALLOC, 0);
  if (PREDICT(result == NULL, 0)) {
    log_err(LD_MM,"Out of memory. Dying.");
    exit(1);
  }
  return result;
}

/** Return a newly allocated copy of the NUL-terminated string s. On
 * error, log and terminate.  (Like strdup(s), but never returns
 * NULL.)
 */
char *
_tor_strdup(const char *s DMALLOC_PARAMS)
{
  char *dup;
  tor_assert(s);

  dup = dmalloc_strdup(file, line, s, 0);
  if (PREDICT(dup == NULL, 0)) {
    log_err(LD_MM,"Out of memory. Dying.");
    exit(1);
  }
  return dup;
}

/** Allocate and return a new string containing the first <b>n</b>
 * characters of <b>s</b>.  If <b>s</b> is longer than <b>n</b>
 * characters, only the first <b>n</b> are copied.  The result is
 * always NUL-terminated.  (Like strndup(s,n), but never returns
 * NULL.)
 */
char *
_tor_strndup(const char *s, size_t n DMALLOC_PARAMS)
{
  char *dup;
  tor_assert(s);
  dup = _tor_malloc((n+1) DMALLOC_FN_ARGS);
  /* Performance note: Ordinarily we prefer strlcpy to strncpy.  But
   * this function gets called a whole lot, and platform strncpy is
   * much faster than strlcpy when strlen(s) is much longer than n.
   */
  strncpy(dup, s, n);
  dup[n]='\0';
  return dup;
}

/** Allocate a chunk of <b>len</b> bytes, with the same contents starting at
 * <b>mem</b>. */
void *
_tor_memdup(const void *mem, size_t len DMALLOC_PARAMS)
{
  char *dup;
  tor_assert(mem);
  dup = _tor_malloc(len DMALLOC_FN_ARGS);
  memcpy(dup, mem, len);
  return dup;
}

/* =====
 * String manipulation
 * ===== */

/** Remove from the string <b>s</b> every character which appears in
 * <b>strip</b>.  Return the number of characters removed. */
int
tor_strstrip(char *s, const char *strip)
{
  char *read = s;
  while (*read) {
    if (strchr(strip, *read)) {
      ++read;
    } else {
      *s++ = *read++;
    }
  }
  *s = '\0';
  return read-s;
}

/** Set the <b>dest_len</b>-byte buffer <b>buf</b> to contain the
 * string <b>s</b>, with the string <b>insert</b> inserted after every
 * <b>n</b> characters.  Return 0 on success, -1 on failure.
 *
 * If <b>rule</b> is ALWAYS_TERMINATE, then always end the string with
 * <b>insert</b>, even if its length is not a multiple of <b>n</b>.  If
 * <b>rule</b> is NEVER_TERMINATE, then never end the string with
 * <b>insert</b>, even if its length <i>is</i> a multiple of <b>n</b>.
 * If <b>rule</b> is TERMINATE_IF_EVEN, then end the string with <b>insert</b>
 * exactly when its length <i>is</i> a multiple of <b>n</b>.
 */
int
tor_strpartition(char *dest, size_t dest_len,
                 const char *s, const char *insert, size_t n,
                 part_finish_rule_t rule)
{
  char *destp;
  size_t len_in, len_out, len_ins;
  int is_even, remaining;
  tor_assert(s);
  tor_assert(insert);
  tor_assert(n > 0);
  tor_assert(n < SIZE_T_CEILING);
  tor_assert(dest_len < SIZE_T_CEILING);
  len_in = strlen(s);
  len_ins = strlen(insert);
  tor_assert(len_in < SIZE_T_CEILING);
  tor_assert(len_in/n < SIZE_T_CEILING/len_ins); /* avoid overflow */
  len_out = len_in + (len_in/n)*len_ins;
  is_even = (len_in%n) == 0;
  switch (rule)
    {
    case ALWAYS_TERMINATE:
      if (!is_even) len_out += len_ins;
      break;
    case NEVER_TERMINATE:
      if (is_even && len_in) len_out -= len_ins;
      break;
    case TERMINATE_IF_EVEN:
      break;
    }
  if (dest_len < len_out+1)
    return -1;
  destp = dest;
  remaining = len_in;
  while (remaining) {
    strncpy(destp, s, n);
    remaining -= n;
    if (remaining < 0) {
      if (rule == ALWAYS_TERMINATE)
        strcpy(destp+n+remaining,insert);
      break;
    } else if (remaining == 0 && rule == NEVER_TERMINATE) {
      *(destp+n) = '\0';
      break;
    }
    strcpy(destp+n, insert);
    s += n;
    destp += n+len_ins;
  }
  tor_assert(len_out == strlen(dest));
  return 0;
}

/** Return a pointer to a NUL-terminated hexadecimal string encoding
 * the first <b>fromlen</b> bytes of <b>from</b>. (fromlen must be \<= 32.) The
 * result does not need to be deallocated, but repeated calls to
 * hex_str will trash old results.
 */
const char *
hex_str(const char *from, size_t fromlen)
{
  static char buf[65];
  if (fromlen>(sizeof(buf)-1)/2)
    fromlen = (sizeof(buf)-1)/2;
  base16_encode(buf,sizeof(buf),from,fromlen);
  return buf;
}

/** Convert all alphabetic characters in the nul-terminated string <b>s</b> to
 * lowercase. */
void
tor_strlower(char *s)
{
  while (*s) {
    *s = TOR_TOLOWER(*s);
    ++s;
  }
}

/** Convert all alphabetic characters in the nul-terminated string <b>s</b> to
 * lowercase. */
void
tor_strupper(char *s)
{
  while (*s) {
    *s = TOR_TOUPPER(*s);
    ++s;
  }
}

/** Return 1 if every character in <b>s</b> is printable, else return 0.
 */
int
tor_strisprint(const char *s)
{
  while (*s) {
    if (!TOR_ISPRINT(*s))
      return 0;
    s++;
  }
  return 1;
}

/** Return 1 if no character in <b>s</b> is uppercase, else return 0.
 */
int
tor_strisnonupper(const char *s)
{
  while (*s) {
    if (TOR_ISUPPER(*s))
      return 0;
    s++;
  }
  return 1;
}

/* Compares the first strlen(s2) characters of s1 with s2.  Returns as for
 * strcmp.
 */
int
strcmpstart(const char *s1, const char *s2)
{
  size_t n = strlen(s2);
  return strncmp(s1, s2, n);
}

/* Compares the first strlen(s2) characters of s1 with s2.  Returns as for
 * strcasecmp.
 */
int
strcasecmpstart(const char *s1, const char *s2)
{
  size_t n = strlen(s2);
  return strncasecmp(s1, s2, n);
}

/* Compares the last strlen(s2) characters of s1 with s2.  Returns as for
 * strcmp.
 */
int
strcmpend(const char *s1, const char *s2)
{
  size_t n1 = strlen(s1), n2 = strlen(s2);
  if (n2>n1)
    return strcmp(s1,s2);
  else
    return strncmp(s1+(n1-n2), s2, n2);
}

/* Compares the last strlen(s2) characters of s1 with s2.  Returns as for
 * strcasecmp.
 */
int
strcasecmpend(const char *s1, const char *s2)
{
  size_t n1 = strlen(s1), n2 = strlen(s2);
  if (n2>n1) /* then they can't be the same; figure out which is bigger */
    return strcasecmp(s1,s2);
  else
    return strncasecmp(s1+(n1-n2), s2, n2);
}

/** Return a pointer to the first char of s that is not whitespace and
 * not a comment, or to the terminating NUL if no such character exists.
 */
const char *
eat_whitespace(const char *s)
{
  tor_assert(s);

  while (TOR_ISSPACE(*s) || *s == '#') {
    while (TOR_ISSPACE(*s))
      s++;
    if (*s == '#') { /* read to a \n or \0 */
      while (*s && *s != '\n')
        s++;
      if (!*s)
        return s;
    }
  }
  return s;
}

/** Return a pointer to the first char of s that is not a space or a tab,
 * or to the terminating NUL if no such character exists. */
const char *
eat_whitespace_no_nl(const char *s)
{
  while (*s == ' ' || *s == '\t')
    ++s;
  return s;
}

/** Return a pointer to the first char of s that is whitespace or <b>#</b>,
 * or to the terminating NUL if no such character exists.
 */
const char *
find_whitespace(const char *s)
{
  /* tor_assert(s); */
  while (1) {
    switch (*s)
    {
    case '\0':
    case '#':
    case ' ':
    case '\r':
    case '\n':
    case '\t':
      return s;
    default:
      ++s;
    }
  }
}

/** Return true iff the 'len' bytes at 'mem' are all zero. */
int
tor_mem_is_zero(const char *mem, size_t len)
{
  static const char ZERO[] = {
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
  };
  while (len >= sizeof(ZERO)) {
    if (memcmp(mem, ZERO, sizeof(ZERO)))
      return 0;
    len -= sizeof(ZERO);
    mem += sizeof(ZERO);
  }
  /* Deal with leftover bytes. */
  if (len)
    return ! memcmp(mem, ZERO, len);

  return 1;
}

/** Return true iff the DIGEST_LEN bytes in digest are all zero. */
int
tor_digest_is_zero(const char *digest)
{
  return tor_mem_is_zero(digest, DIGEST_LEN);
}

#define CHECK_STRTOX_RESULT()                           \
  /* Was at least one character converted? */           \
  if (endptr == s)                                      \
    goto err;                                           \
  /* Were there unexpected unconverted characters? */   \
  if (!next && *endptr)                                 \
    goto err;                                           \
  /* Is r within limits? */                             \
  if (r < min || r > max)                               \
    goto err;                                           \
  if (ok) *ok = 1;                                      \
  if (next) *next = endptr;                             \
  return r;                                             \
 err:                                                   \
  if (ok) *ok = 0;                                      \
  if (next) *next = endptr;                             \
  return 0

/** Extract a long from the start of s, in the given numeric base.  If
 * there is unconverted data and next is provided, set *next to the
 * first unconverted character.  An error has occurred if no characters
 * are converted; or if there are unconverted characters and next is NULL; or
 * if the parsed value is not between min and max.  When no error occurs,
 * return the parsed value and set *ok (if provided) to 1.  When an error
 * occurs, return 0 and set *ok (if provided) to 0.
 */
long
tor_parse_long(const char *s, int base, long min, long max,
               int *ok, char **next)
{
  char *endptr;
  long r;

  r = strtol(s, &endptr, base);
  CHECK_STRTOX_RESULT();
}

unsigned long
tor_parse_ulong(const char *s, int base, unsigned long min,
                unsigned long max, int *ok, char **next)
{
  char *endptr;
  unsigned long r;

  r = strtoul(s, &endptr, base);
  CHECK_STRTOX_RESULT();
}

/** Only base 10 is guaranteed to work for now. */
uint64_t
tor_parse_uint64(const char *s, int base, uint64_t min,
                 uint64_t max, int *ok, char **next)
{
  char *endptr;
  uint64_t r;

#ifdef HAVE_STRTOULL
  r = (uint64_t)strtoull(s, &endptr, base);
#elif defined(MS_WINDOWS)
#if _MSC_VER < 1300
  tor_assert(base <= 10);
  r = (uint64_t)_atoi64(s);
  endptr = (char*)s;
  while (TOR_ISSPACE(*endptr)) endptr++;
  while (TOR_ISDIGIT(*endptr)) endptr++;
#else
  r = (uint64_t)_strtoui64(s, &endptr, base);
#endif
#elif SIZEOF_LONG == 8
  r = (uint64_t)strtoul(s, &endptr, base);
#else
#error "I don't know how to parse 64-bit numbers."
#endif

  CHECK_STRTOX_RESULT();
}

void
base16_encode(char *dest, size_t destlen, const char *src, size_t srclen)
{
  const char *end;
  char *cp;

  tor_assert(destlen >= srclen*2+1);
  tor_assert(destlen < SIZE_T_CEILING);

  cp = dest;
  end = src+srclen;
  while (src<end) {
    sprintf(cp,"%02X",*(const uint8_t*)src);
    ++src;
    cp += 2;
  }
  *cp = '\0';
}

static const char HEX_DIGITS[] = "0123456789ABCDEFabcdef";

static INLINE int
hex_decode_digit(char c)
{
  const char *cp;
  int n;
  cp = strchr(HEX_DIGITS, c);
  if (!cp)
    return -1;
  n = cp-HEX_DIGITS;
  if (n<=15)
    return n; /* digit or uppercase */
  else
    return n-6; /* lowercase */
}

int
base16_decode(char *dest, size_t destlen, const char *src, size_t srclen)
{
  const char *end;
  int v1,v2;
  if ((srclen % 2) != 0)
    return -1;
  if (destlen < srclen/2 || destlen > SIZE_T_CEILING)
    return -1;
  end = src+srclen;
  while (src<end) {
    v1 = hex_decode_digit(*src);
    v2 = hex_decode_digit(*(src+1));
    if (v1<0||v2<0)
      return -1;
    *(uint8_t*)dest = (v1<<4)|v2;
    ++dest;
    src+=2;
  }
  return 0;
}

/** Allocate and return a new string representing the contents of <b>s</b>,
 * surrounded by quotes and using standard C escapes.
 *
 * Generally, we use this for logging values that come in over the network
 * to keep them from tricking users.
 *
 * We trust values from the resolver, OS, configuration file, and command line
 * to not be maliciously ill-formed.  We validate incoming routerdescs and
 * SOCKS requests and addresses from BEGIN cells as they're parsed;
 * afterwards, we trust them as non-malicious.
 */
char *
esc_for_log(const char *s)
{
  const char *cp;
  char *result, *outp;
  size_t len = 3;
  if (!s) {
    return tor_strdup("");
  }

  for (cp = s; *cp; ++cp) {
    switch (*cp) {
      case '\\':
      case '\"':
      case '\'':
        len += 2;
        break;
      default:
        if (TOR_ISPRINT(*cp) && ((uint8_t)*cp)<127)
          ++len;
        else
          len += 4;
        break;
    }
  }

  result = outp = tor_malloc(len);
  *outp++ = '\"';
  for (cp = s; *cp; ++cp) {
    switch (*cp) {
      case '\\':
      case '\"':
      case '\'':
        *outp++ = '\\';
        *outp++ = *cp;
        break;
      case '\n':
        *outp++ = '\\';
        *outp++ = 'n';
        break;
      case '\t':
        *outp++ = '\\';
        *outp++ = 't';
        break;
      case '\r':
        *outp++ = '\\';
        *outp++ = 'r';
        break;
      default:
        if (TOR_ISPRINT(*cp) && ((uint8_t)*cp)<127) {
          *outp++ = *cp;
        } else {
          tor_snprintf(outp, 5, "\\%03o", (int)(uint8_t) *cp);
          outp += 4;
        }
        break;
    }
  }

  *outp++ = '\"';
  *outp++ = 0;

  return result;
}

/** Allocate and return a new string representing the contents of <b>s</b>,
 * surrounded by quotes and using standard C escapes.
 *
 * THIS FUNCTION IS NOT REENTRANT.  Don't call it from outside the main
 * thread.  Also, each call invalidates the last-returned value, so don't
 * try log_warn(LD_GENERAL, "%s %s", escaped(a), escaped(b));
 */
const char *
escaped(const char *s)
{
  static char *_escaped_val = NULL;
  if (_escaped_val)
    tor_free(_escaped_val);

  if (s)
    _escaped_val = esc_for_log(s);
  else
    _escaped_val = NULL;

  return _escaped_val;
}

/* =====
 * Time
 * ===== */

/** Return the number of microseconds elapsed between *start and *end.
 */
long
tv_udiff(struct timeval *start, struct timeval *end)
{
  long udiff;
  long secdiff = end->tv_sec - start->tv_sec;

  if (labs(secdiff+1) > LONG_MAX/1000000) {
    log_warn(LD_GENERAL, "comparing times too far apart.");
    return LONG_MAX;
  }

  udiff = secdiff*1000000L + (end->tv_usec - start->tv_usec);
  return udiff;
}

/** Return -1 if *a \< *b, 0 if *a==*b, and 1 if *a \> *b.
 */
int
tv_cmp(struct timeval *a, struct timeval *b)
{
  if (a->tv_sec > b->tv_sec)
    return 1;
  if (a->tv_sec < b->tv_sec)
    return -1;
  if (a->tv_usec > b->tv_usec)
    return 1;
  if (a->tv_usec < b->tv_usec)
    return -1;
  return 0;
}

/** Increment *a by the number of seconds and microseconds in *b.
 */
void
tv_add(struct timeval *a, struct timeval *b)
{
  a->tv_usec += b->tv_usec;
  a->tv_sec += b->tv_sec + (a->tv_usec / 1000000);
  a->tv_usec %= 1000000;
}

/** Increment *a by <b>ms</b> milliseconds.
 */
void
tv_addms(struct timeval *a, long ms)
{
  a->tv_usec += (ms * 1000) % 1000000;
  a->tv_sec += ((ms * 1000) / 1000000) + (a->tv_usec / 1000000);
  a->tv_usec %= 1000000;
}

#define IS_LEAPYEAR(y) (!(y % 4) && ((y % 100) || !(y % 400)))
static int
n_leapdays(int y1, int y2)
{
  --y1;
  --y2;
  return (y2/4 - y1/4) - (y2/100 - y1/100) + (y2/400 - y1/400);
}
/** Number of days per month in non-leap year; used by tor_timegm. */
static const int days_per_month[] =
  { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

/** Return a time_t given a struct tm.  The result is given in GMT, and
 * does not account for leap seconds.
 */
time_t
tor_timegm(struct tm *tm)
{
  /* This is a pretty ironclad timegm implementation, snarfed from Python2.2.
   * It's way more brute-force than fiddling with tzset().
   */
  time_t ret;
  unsigned long year, days, hours, minutes;
  int i;
  year = tm->tm_year + 1900;
  if (year < 1970 || tm->tm_mon < 0 || tm->tm_mon > 11) {
    log_warn(LD_BUG, "Out-of-range argument to tor_timegm");
    return -1;
  }
  days = 365 * (year-1970) + n_leapdays(1970,year);
  for (i = 0; i < tm->tm_mon; ++i)
    days += days_per_month[i];
  if (tm->tm_mon > 1 && IS_LEAPYEAR(year))
    ++days;
  days += tm->tm_mday - 1;
  hours = days*24 + tm->tm_hour;

  minutes = hours*60 + tm->tm_min;
  ret = minutes*60 + tm->tm_sec;
  return ret;
}

/* strftime is locale-specific, so we need to replace those parts */
static const char *WEEKDAY_NAMES[] =
  { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static const char *MONTH_NAMES[] =
  { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

void
format_rfc1123_time(char *buf, time_t t)
{
  struct tm tm;

  tor_gmtime_r(&t, &tm);

  strftime(buf, RFC1123_TIME_LEN+1, "___, %d ___ %Y %H:%M:%S GMT", &tm);
  tor_assert(tm.tm_wday >= 0);
  tor_assert(tm.tm_wday <= 6);
  memcpy(buf, WEEKDAY_NAMES[tm.tm_wday], 3);
  tor_assert(tm.tm_wday >= 0);
  tor_assert(tm.tm_mon <= 11);
  memcpy(buf+8, MONTH_NAMES[tm.tm_mon], 3);
}

int
parse_rfc1123_time(const char *buf, time_t *t)
{
  struct tm tm;
  char month[4];
  char weekday[4];
  int i, m;

  if (strlen(buf) != RFC1123_TIME_LEN)
    return -1;
  memset(&tm, 0, sizeof(tm));
  if (sscanf(buf, "%3s, %d %3s %d %d:%d:%d GMT", weekday,
             &tm.tm_mday, month, &tm.tm_year, &tm.tm_hour,
             &tm.tm_min, &tm.tm_sec) < 7) {
    char *esc = esc_for_log(buf);
    log_warn(LD_GENERAL, "Got invalid RFC1123 time %s", esc);
    tor_free(esc);
    return -1;
  }

  m = -1;
  for (i = 0; i < 12; ++i) {
    if (!strcmp(month, MONTH_NAMES[i])) {
      m = i;
      break;
    }
  }
  if (m<0) {
    char *esc = esc_for_log(buf);
    log_warn(LD_GENERAL, "Got invalid RFC1123 time %s", esc);
    tor_free(esc);
    return -1;
  }
  tm.tm_mon = m;

  if (tm.tm_year < 1970) {
    char *esc = esc_for_log(buf);
    log_warn(LD_GENERAL,
             "Got invalid RFC1123 time %s. (Before 1970)", esc);
    tor_free(esc);
    return -1;
  }
  tm.tm_year -= 1900;

  *t = tor_timegm(&tm);
  return 0;
}

void
format_local_iso_time(char *buf, time_t t)
{
  struct tm tm;
  strftime(buf, ISO_TIME_LEN+1, "%Y-%m-%d %H:%M:%S", tor_localtime_r(&t, &tm));
}

void
format_iso_time(char *buf, time_t t)
{
  struct tm tm;
  strftime(buf, ISO_TIME_LEN+1, "%Y-%m-%d %H:%M:%S", tor_gmtime_r(&t, &tm));
}

int
parse_iso_time(const char *cp, time_t *t)
{
  struct tm st_tm;
#ifdef HAVE_STRPTIME
  if (!strptime(cp, "%Y-%m-%d %H:%M:%S", &st_tm)) {
    log_warn(LD_GENERAL, "Published time was unparseable"); return -1;
  }
#else
  unsigned int year=0, month=0, day=0, hour=100, minute=100, second=100;
  if (sscanf(cp, "%u-%u-%u %u:%u:%u", &year, &month,
                &day, &hour, &minute, &second) < 6) {
    log_warn(LD_GENERAL, "Published time was unparseable"); return -1;
  }
  if (year < 1970 || month < 1 || month > 12 || day < 1 || day > 31 ||
          hour > 23 || minute > 59 || second > 61) {
    log_warn(LD_GENERAL, "Published time was nonsensical"); return -1;
  }
  st_tm.tm_year = year-1900;
  st_tm.tm_mon = month-1;
  st_tm.tm_mday = day;
  st_tm.tm_hour = hour;
  st_tm.tm_min = minute;
  st_tm.tm_sec = second;
#endif
  if (st_tm.tm_year < 70) {
    char *esc = esc_for_log(cp);
    log_warn(LD_GENERAL, "Got invalid ISO time %s. (Before 1970)", esc);
    tor_free(esc);
    return -1;
  }
  *t = tor_timegm(&st_tm);
  return 0;
}

/* =====
 * File helpers
 * ===== */

/** Write <b>count</b> bytes from <b>buf</b> to <b>fd</b>.  <b>isSocket</b>
 * must be 1 if fd was returned by socket() or accept(), and 0 if fd
 * was returned by open().  Return the number of bytes written, or -1
 * on error.  Only use if fd is a blocking fd.  */
int
write_all(int fd, const char *buf, size_t count, int isSocket)
{
  size_t written = 0;
  int result;

  while (written != count) {
    if (isSocket)
      result = tor_socket_send(fd, buf+written, count-written, 0);
    else
      result = write(fd, buf+written, count-written);
    if (result<0)
      return -1;
    written += result;
  }
  return count;
}

/** Read from <b>fd</b> to <b>buf</b>, until we get <b>count</b> bytes
 * or reach the end of the file. <b>isSocket</b> must be 1 if fd
 * was returned by socket() or accept(), and 0 if fd was returned by
 * open().  Return the number of bytes read, or -1 on error. Only use
 * if fd is a blocking fd. */
int
read_all(int fd, char *buf, size_t count, int isSocket)
{
  size_t numread = 0;
  int result;

  if (count > SIZE_T_CEILING)
    return -1;

  while (numread != count) {
    if (isSocket)
      result = tor_socket_recv(fd, buf+numread, count-numread, 0);
    else
      result = read(fd, buf+numread, count-numread);
    if (result<0)
      return -1;
    else if (result == 0)
      break;
    numread += result;
  }
  return numread;
}

/*
 *    Filesystem operations.
 */

/** Clean up <b>name</b> so that we can use it in a call to "stat".  On Unix,
 * we do nothing.  On Windows, we remove a trailing slash, unless the path is
 * the root of a disk. */
static void
clean_name_for_stat(char *name)
{
#ifdef MS_WINDOWS
  size_t len = strlen(name);
  if (!len)
    return;
  if (name[len-1]=='\\' || name[len-1]=='/') {
    if (len == 1 || (len==3 && name[1]==':'))
      return;
    name[len-1]='\0';
  }
#else
  (void)name;
#endif
}

/** Return FN_ERROR if filename can't be read, FN_NOENT if it doesn't
 * exist, FN_FILE if it is a regular file, or FN_DIR if it's a
 * directory. */
file_status_t
file_status(const char *fname)
{
  struct stat st;
  char *f;
  int r;
  f = tor_strdup(fname);
  clean_name_for_stat(f);
  r = stat(f, &st);
  tor_free(f);
  if (r) {
    if (errno == ENOENT) {
      return FN_NOENT;
    }
    return FN_ERROR;
  }
  if (st.st_mode & S_IFDIR)
    return FN_DIR;
  else if (st.st_mode & S_IFREG)
    return FN_FILE;
  else
    return FN_ERROR;
}

/** Check whether dirname exists and is private.  If yes return 0.  If
 * it does not exist, and check==CPD_CREATE is set, try to create it
 * and return 0 on success. If it does not exist, and
 * check==CPD_CHECK, and we think we can create it, return 0.  Else
 * return -1. */
int
check_private_dir(const char *dirname, cpd_check_t check)
{
  int r;
  struct stat st;
  char *f;
  tor_assert(dirname);
  f = tor_strdup(dirname);
  clean_name_for_stat(f);
  r = stat(f, &st);
  tor_free(f);
  if (r) {
    if (errno != ENOENT) {
      log(LOG_WARN, LD_FS, "Directory %s cannot be read: %s", dirname,
          strerror(errno));
      return -1;
    }
    if (check == CPD_NONE) {
      log(LOG_WARN, LD_FS, "Directory %s does not exist.", dirname);
      return -1;
    } else if (check == CPD_CREATE) {
      log_info(LD_GENERAL, "Creating directory %s", dirname);
#ifdef MS_WINDOWS
      r = mkdir(dirname);
#else
      r = mkdir(dirname, 0700);
#endif
      if (r) {
        log(LOG_WARN, LD_FS, "Error creating directory %s: %s", dirname,
            strerror(errno));
        return -1;
      }
    }
    /* XXXX In the case where check==CPD_CHECK, we should look at the
     * parent directory a little harder. */
    return 0;
  }
  if (!(st.st_mode & S_IFDIR)) {
    log(LOG_WARN, LD_FS, "%s is not a directory", dirname);
    return -1;
  }
#ifndef MS_WINDOWS
  if (st.st_uid != getuid()) {
    struct passwd *pw = NULL;
    char *process_ownername = NULL;

    pw = getpwuid(getuid());
    process_ownername = pw ? tor_strdup(pw->pw_name) : tor_strdup("<unknown>");

    pw = getpwuid(st.st_uid);

    log(LOG_WARN, LD_FS, "%s is not owned by this user (%s, %d) but by "
        "%s (%d). Perhaps you are running Tor as the wrong user?",
                         dirname, process_ownername, (int)getuid(),
                         pw ? pw->pw_name : "<unknown>", (int)st.st_uid);

    tor_free(process_ownername);
    return -1;
  }
  if (st.st_mode & 0077) {
    log(LOG_WARN, LD_FS, "Fixing permissions on directory %s", dirname);
    if (chmod(dirname, 0700)) {
      log(LOG_WARN, LD_FS, "Could not chmod directory %s: %s", dirname,
          strerror(errno));
      return -1;
    } else {
      return 0;
    }
  }
#endif
  return 0;
}

/** Create a file named <b>fname</b> with the contents <b>str</b>.  Overwrite
 * the previous <b>fname</b> if possible.  Return 0 on success, -1 on failure.
 *
 * This function replaces the old file atomically, if possible.
 */
int
write_str_to_file(const char *fname, const char *str, int bin)
{
#ifdef MS_WINDOWS
  if (!bin && strchr(str, '\r')) {
    log_warn(LD_BUG,
             "Bug: we're writing a text string that already contains a CR.");
  }
#endif
  return write_bytes_to_file(fname, str, strlen(str), bin);
}

/* DOCDOC */
static int
write_chunks_to_file_impl(const char *fname, const smartlist_t *chunks,
                          int open_flags)
{
  size_t tempname_len;
  char *tempname;
  int fd;
  int result;
  tempname_len = strlen(fname)+16;
  tor_assert(tempname_len > strlen(fname)); /*check for overflow*/
  tempname = tor_malloc(tempname_len);
  if (open_flags & O_APPEND) {
    strlcpy(tempname, fname, tempname_len);
  } else {
    if (tor_snprintf(tempname, tempname_len, "%s.tmp", fname)<0) {
      log(LOG_WARN, LD_GENERAL, "Failed to generate filename");
      goto err;
    }
  }
  if ((fd = open(tempname, open_flags, 0600))
      < 0) {
    log(LOG_WARN, LD_FS, "Couldn't open \"%s\" for writing: %s", tempname,
        strerror(errno));
    goto err;
  }
  SMARTLIST_FOREACH(chunks, sized_chunk_t *, chunk,
  {
    result = write_all(fd, chunk->bytes, chunk->len, 0);
    if (result < 0 || (size_t)result != chunk->len) {
      log(LOG_WARN, LD_FS, "Error writing to \"%s\": %s", tempname,
          strerror(errno));
      close(fd);
      goto err;
    }
  });
  if (close(fd)) {
    log(LOG_WARN, LD_FS, "Error flushing to \"%s\": %s", tempname,
        strerror(errno));
    goto err;
  }
  if (!(open_flags & O_APPEND)) {
    if (replace_file(tempname, fname)) {
      log(LOG_WARN, LD_FS, "Error replacing \"%s\": %s", fname,
          strerror(errno));
      goto err;
    }
  }
  tor_free(tempname);
  return 0;
 err:
  tor_free(tempname);
  return -1;
}

/* DOCDOC */
int
write_chunks_to_file(const char *fname, const smartlist_t *chunks, int bin)
{
  int flags = O_WRONLY|O_CREAT|O_TRUNC|(bin?O_BINARY:O_TEXT);
  return write_chunks_to_file_impl(fname, chunks, flags);
}

/** As write_str_to_file, but does not assume a NUL-terminated *
 * string. Instead, we write <b>len</b> bytes, starting at <b>str</b>. */
int
write_bytes_to_file(const char *fname, const char *str, size_t len,
                    int bin)
{
  int flags = O_WRONLY|O_CREAT|O_TRUNC|(bin?O_BINARY:O_TEXT);
  int r;
  sized_chunk_t c = { str, len };
  smartlist_t *chunks = smartlist_create();
  smartlist_add(chunks, &c);
  r = write_chunks_to_file_impl(fname, chunks, flags);
  smartlist_free(chunks);
  return r;
}

/* DOCDOC */
int
append_bytes_to_file(const char *fname, const char *str, size_t len,
                     int bin)
{
  int flags = O_WRONLY|O_CREAT|O_APPEND|(bin?O_BINARY:O_TEXT);
  int r;
  sized_chunk_t c = { str, len };
  smartlist_t *chunks = smartlist_create();
  smartlist_add(chunks, &c);
  r = write_chunks_to_file_impl(fname, chunks, flags);
  smartlist_free(chunks);
  return r;
}

/** Read the contents of <b>filename</b> into a newly allocated
 * string; return the string on success or NULL on failure.
 */
/*
 * This function <em>may</em> return an erroneous result if the file
 * is modified while it is running, but must not crash or overflow.
 * Right now, the error case occurs when the file length grows between
 * the call to stat and the call to read_all: the resulting string will
 * be truncated.
 */
char *
read_file_to_str(const char *filename, int bin)
{
  int fd; /* router file */
  struct stat statbuf;
  char *string, *f;
  int r;

  tor_assert(filename);

  f = tor_strdup(filename);
  clean_name_for_stat(f);
  r = stat(f, &statbuf);
  tor_free(f);
  if (r < 0) {
    log_info(LD_FS,"Could not stat \"%s\".",filename);
    return NULL;
  }

  fd = open(filename,O_RDONLY|(bin?O_BINARY:O_TEXT),0);
  if (fd<0) {
    log_warn(LD_FS,"Could not open \"%s\".",filename);
    return NULL;
  }

  string = tor_malloc(statbuf.st_size+1);

  r = read_all(fd,string,statbuf.st_size,0);
  if (r<0) {
    log_warn(LD_FS,"Error reading from file \"%s\": %s", filename,
             strerror(errno));
    tor_free(string);
    close(fd);
    return NULL;
  }
  string[r] = '\0'; /* NUL-terminate the result. */

  if (bin && r != statbuf.st_size) {
    /* If we're in binary mode, then we'd better have an exact match for
     * size.  Otherwise, win32 encoding may throw us off, and that's okay. */
    log_warn(LD_FS,"Could read only %d of %ld bytes of file \"%s\".",
             r, (long)statbuf.st_size,filename);
    tor_free(string);
    close(fd);
    return NULL;
  }
#ifdef MS_WINDOWS
  if (!bin && strchr(string, '\r')) {
    log_debug(LD_FS, "We didn't convert CRLF to LF as well as we hoped "
              "when reading %s. Coping.",
              filename);
    tor_strstrip(string, "\r");
  }
#endif
  close(fd);

  return string;
}

/** Given a string containing part of a configuration file or similar format,
 * advance past comments and whitespace and try to parse a single line.  If we
 * parse a line successfully, set *<b>key_out</b> to the key portion and
 * *<b>value_out</b> to the value portion of the line, and return a pointer to
 * the start of the next line.  If we run out of data, return a pointer to the
 * end of the string.  If we encounter an error, return NULL.
 *
 * NOTE: We modify <b>line</b> as we parse it, by inserting NULs to terminate
 * the key and value.
 */
char *
parse_line_from_str(char *line, char **key_out, char **value_out)
{
  char *key, *val, *cp;

  tor_assert(key_out);
  tor_assert(value_out);

  *key_out = *value_out = key = val = NULL;
  /* Skip until the first keyword. */
  while (1) {
    while (TOR_ISSPACE(*line))
      ++line;
    if (*line == '#') {
      while (*line && *line != '\n')
        ++line;
    } else {
      break;
    }
  }

  if (!*line) { /* End of string? */
    *key_out = *value_out = NULL;
    return line;
  }

  /* Skip until the next space. */
  key = line;
  while (*line && !TOR_ISSPACE(*line) && *line != '#')
    ++line;

  /* Skip until the value */
  while (*line == ' ' || *line == '\t')
    *line++ = '\0';
  val = line;

  /* Find the end of the line. */
  while (*line && *line != '\n' && *line != '#')
    ++line;
  if (*line == '\n')
    cp = line++;
  else {
    cp = line-1;
  }
  while (cp>=val && TOR_ISSPACE(*cp))
    *cp-- = '\0';

  if (*line == '#') {
    do {
      *line++ = '\0';
    } while (*line && *line != '\n');
    if (*line == '\n')
      ++line;
  }

  *key_out = key;
  *value_out = val;

  return line;
}

/** Expand any homedir prefix on 'filename'; return a newly allocated
 * string. */
char *
expand_filename(const char *filename)
{
  tor_assert(filename);
  if (*filename == '~') {
    size_t len;
    char *home, *result;
    const char *rest;

    if (filename[1] == '/' || filename[1] == '\0') {
      home = getenv("HOME");
      if (!home) {
        log_warn(LD_CONFIG, "Couldn't find $HOME environment variable while "
                 "expanding \"%s\"", filename);
        return NULL;
      }
      home = tor_strdup(home);
      rest = strlen(filename)>=2?(filename+2):NULL;
    } else {
#ifdef HAVE_PWD_H
      char *username, *slash;
      slash = strchr(filename, '/');
      if (slash)
        username = tor_strndup(filename+1,slash-filename-1);
      else
        username = tor_strdup(filename+1);
      if (!(home = get_user_homedir(username))) {
        log_warn(LD_CONFIG,"Couldn't get homedir for \"%s\"",username);
        tor_free(username);
        return NULL;
      }
      tor_free(username);
      rest = slash ? (slash+1) : NULL;
#else
      log_warn(LD_CONFIG, "Couldn't expend homedir on system without pwd.h");
      return tor_strdup(filename);
#endif
    }
    tor_assert(home);
    /* Remove trailing slash. */
    if (strlen(home)>1 && !strcmpend(home,"/")) {
      home[strlen(home)-1] = '\0';
    }
    /* Plus one for /, plus one for NUL.
     * Round up to 16 in case we can't do math. */
    len = strlen(home)+strlen(rest)+16;
    result = tor_malloc(len);
    tor_snprintf(result,len,"%s/%s",home,rest?rest:"");
    tor_free(home);
    return result;
  } else {
    return tor_strdup(filename);
  }
}

/** Return a new list containing the filenames in the directory <b>dirname</b>.
 * Return NULL on error or if <b>dirname</b> is not a directory.
 */
smartlist_t *
tor_listdir(const char *dirname)
{
  smartlist_t *result;
#ifdef MS_WINDOWS
  char *pattern;
  HANDLE handle;
  WIN32_FIND_DATA findData;
  size_t pattern_len = strlen(dirname)+16;
  pattern = tor_malloc(pattern_len);
  tor_snprintf(pattern, pattern_len, "%s\\*", dirname);
  if (!(handle = FindFirstFile(pattern, &findData))) {
    tor_free(pattern);
    return NULL;
  }
  result = smartlist_create();
  while (1) {
    if (strcmp(findData.cFileName, ".") &&
        strcmp(findData.cFileName, "..")) {
      smartlist_add(result, tor_strdup(findData.cFileName));
    }
    if (!FindNextFile(handle, &findData)) {
      if (GetLastError() != ERROR_NO_MORE_FILES) {
        log_warn(LD_FS, "Error reading directory.");
      }
      break;
    }
  }
  FindClose(handle);
  tor_free(pattern);
#else
  DIR *d;
  struct dirent *de;
  if (!(d = opendir(dirname)))
    return NULL;

  result = smartlist_create();
  while ((de = readdir(d))) {
    if (!strcmp(de->d_name, ".") ||
        !strcmp(de->d_name, ".."))
      continue;
    smartlist_add(result, tor_strdup(de->d_name));
  }
  closedir(d);
#endif
  return result;
}

/** Return true iff <b>filename</b> is a relative path.  (XXXX doesn't work on
 * windows.) */
int
path_is_relative(const char *filename)
{
  if (filename && filename[0] == '/')
    return 0;
  else
    return 1;
}

/* =====
 * Net helpers
 * ===== */

/** Return true iff <b>ip</b> (in host order) is an IP reserved to localhost,
 * or reserved for local networks by RFC 1918.
 */
int
is_internal_IP(uint32_t ip, int for_listening)
{
  if (for_listening && !ip) /* special case for binding to 0.0.0.0 */
    return 0;
  if (((ip & 0xff000000) == 0x0a000000) || /*       10/8 */
      ((ip & 0xff000000) == 0x00000000) || /*        0/8 */
      ((ip & 0xff000000) == 0x7f000000) || /*      127/8 */
      ((ip & 0xffff0000) == 0xa9fe0000) || /* 169.254/16 */
      ((ip & 0xfff00000) == 0xac100000) || /*  172.16/12 */
      ((ip & 0xffff0000) == 0xc0a80000))   /* 192.168/16 */
    return 1;
  return 0;
}

/** Return true iff <b>ip</b> (in host order) is judged to be on the
 * same network as us. For now, check if it's an internal IP.
 *
 * XXX Also check if it's on the same class C network as our public IP.
 */
int
is_local_IP(uint32_t ip)
{
  return is_internal_IP(ip, 0);
}

/** Parse a string of the form "host[:port]" from <b>addrport</b>.  If
 * <b>address</b> is provided, set *<b>address</b> to a copy of the
 * host portion of the string.  If <b>addr</b> is provided, try to
 * resolve the host portion of the string and store it into
 * *<b>addr</b> (in host byte order).  If <b>port_out</b> is provided,
 * store the port number into *<b>port_out</b>, or 0 if no port is given.
 * If <b>port_out</b> is NULL, then there must be no port number in
 * <b>addrport</b>.
 * Return 0 on success, -1 on failure.
 */
int
parse_addr_port(int severity, const char *addrport, char **address,
                uint32_t *addr, uint16_t *port_out)
{
  const char *colon;
  char *_address = NULL;
  int _port;
  int ok = 1;

  tor_assert(addrport);

  colon = strchr(addrport, ':');
  if (colon) {
    _address = tor_strndup(addrport, colon-addrport);
    _port = (int) tor_parse_long(colon+1,10,1,65535,NULL,NULL);
    if (!_port) {
      log_fn(severity, LD_GENERAL, "Port %s out of range", escaped(colon+1));
      ok = 0;
    }
    if (!port_out) {
      char *esc_addrport = esc_for_log(addrport);
      log_fn(severity, LD_GENERAL,
             "Port %s given on %s when not required",
             escaped(colon+1), esc_addrport);
      tor_free(esc_addrport);
      ok = 0;
    }
  } else {
    _address = tor_strdup(addrport);
    _port = 0;
  }

  if (addr) {
    /* There's an addr pointer, so we need to resolve the hostname. */
    if (tor_lookup_hostname(_address,addr)) {
      log_fn(severity, LD_NET, "Couldn't look up %s", escaped(_address));
      ok = 0;
      *addr = 0;
    }
    *addr = ntohl(*addr);
  }

  if (address && ok) {
    *address = _address;
  } else {
    if (address)
      *address = NULL;
    tor_free(_address);
  }
  if (port_out)
    *port_out = ok ? ((uint16_t) _port) : 0;

  return ok ? 0 : -1;
}

/** If <b>mask</b> is an address mask for a bit-prefix, return the number of
 * bits.  Otherwise, return -1. */
int
addr_mask_get_bits(uint32_t mask)
{
  int i;
  if (mask == 0)
    return 0;
  if (mask == 0xFFFFFFFFu)
    return 32;
  for (i=0; i<=32; ++i) {
    if (mask == (uint32_t) ~((1u<<(32-i))-1)) {
      return i;
    }
  }
  return -1;
}

/** Parse a string <b>s</b> in the format of (*|port(-maxport)?)?, setting the
 * various *out pointers as appropriate.  Return 0 on success, -1 on failure.
 */
int
parse_port_range(const char *port, uint16_t *port_min_out,
                 uint16_t *port_max_out)
{
  tor_assert(port_min_out);
  tor_assert(port_max_out);

  if (!port || *port == '\0' || strcmp(port, "*") == 0) {
    *port_min_out = 1;
    *port_max_out = 65535;
  } else {
    char *endptr = NULL;
    *port_min_out = (uint16_t) tor_parse_long(port, 10, 1, 65535,
                                              NULL, &endptr);
    if (*endptr == '-') {
      port = endptr+1;
      endptr = NULL;
      *port_max_out = (uint16_t) tor_parse_long(port, 10, 1, 65535, NULL,
                                                &endptr);
      if (*endptr || !*port_max_out) {
        log_warn(LD_GENERAL,
                 "Malformed port %s on address range rejecting.",
                 escaped(port));
      }
    } else if (*endptr || !*port_min_out) {
      log_warn(LD_GENERAL,
               "Malformed port %s on address range; rejecting.",
               escaped(port));
      return -1;
    } else {
      *port_max_out = *port_min_out;
    }
    if (*port_min_out > *port_max_out) {
      log_warn(LD_GENERAL, "Insane port range on address policy; rejecting.");
      return -1;
    }
  }

  return 0;
}

/** Parse a string <b>s</b> in the format of
 * (IP(/mask|/mask-bits)?|*)(:*|port(-maxport)?)?, setting the various
 * *out pointers as appropriate.  Return 0 on success, -1 on failure.
 */
int
parse_addr_and_port_range(const char *s, uint32_t *addr_out,
                          uint32_t *mask_out, uint16_t *port_min_out,
                          uint16_t *port_max_out)
{
  char *address;
  char *mask, *port, *endptr;
  struct in_addr in;
  int bits;

  tor_assert(s);
  tor_assert(addr_out);
  tor_assert(mask_out);
  tor_assert(port_min_out);
  tor_assert(port_max_out);

  address = tor_strdup(s);
  /* Break 'address' into separate strings.
   */
  mask = strchr(address,'/');
  port = strchr(mask?mask:address,':');
  if (mask)
    *mask++ = '\0';
  if (port)
    *port++ = '\0';
  /* Now "address" is the IP|'*' part...
   *     "mask" is the Mask|Maskbits part...
   * and "port" is the *|port|min-max part.
   */

  if (strcmp(address,"*")==0) {
    *addr_out = 0;
  } else if (tor_inet_aton(address, &in) != 0) {
    *addr_out = ntohl(in.s_addr);
  } else {
    log_warn(LD_GENERAL, "Malformed IP %s in address pattern; rejecting.",
             escaped(address));
    goto err;
  }

  if (!mask) {
    if (strcmp(address,"*")==0)
      *mask_out = 0;
    else
      *mask_out = 0xFFFFFFFFu;
  } else {
    endptr = NULL;
    bits = (int) strtol(mask, &endptr, 10);
    if (!*endptr) {
      /* strtol handled the whole mask. */
      if (bits < 0 || bits > 32) {
        log_warn(LD_GENERAL,
                 "Bad number of mask bits on address range; rejecting.");
        goto err;
      }
      *mask_out = ~((1u<<(32-bits))-1);
    } else if (tor_inet_aton(mask, &in) != 0) {
      *mask_out = ntohl(in.s_addr);
    } else {
      log_warn(LD_GENERAL,
               "Malformed mask %s on address range; rejecting.",
               escaped(mask));
      goto err;
    }
  }

  if (parse_port_range(port, port_min_out, port_max_out)<0)
    goto err;

  tor_free(address);
  return 0;
 err:
  tor_free(address);
  return -1;
}

/** Given an IPv4 address <b>in</b> (in network order, as usual),
 * write it as a string into the <b>buf_len</b>-byte buffer in
 * <b>buf</b>.
 */
int
tor_inet_ntoa(struct in_addr *in, char *buf, size_t buf_len)
{
  uint32_t a = ntohl(in->s_addr);
  return tor_snprintf(buf, buf_len, "%d.%d.%d.%d",
                      (int)(uint8_t)((a>>24)&0xff),
                      (int)(uint8_t)((a>>16)&0xff),
                      (int)(uint8_t)((a>>8 )&0xff),
                      (int)(uint8_t)((a    )&0xff));
}

/** Given a host-order <b>addr</b>, call tor_inet_ntoa() on it
 * and return a strdup of the resulting address.
 */
char *
tor_dup_addr(uint32_t addr)
{
  char buf[INET_NTOA_BUF_LEN];
  struct in_addr in;

  in.s_addr = htonl(addr);
  tor_inet_ntoa(&in, buf, sizeof(buf));
  return tor_strdup(buf);
}

/* Return true iff <b>name</b> looks like it might be a hostname,
 * nickname, key, or IP address of some kind, suitable for the
 * controller's "mapaddress" command. */
int
is_plausible_address(const char *name)
{
//  const char *cp;
  tor_assert(name);
  /* We could check better here. */
  if (!*name)
    return 0;
#if 0
  for (cp=name; *cp; cp++) {
    if (*cp != '.' && *cp != '-' && !TOR_ISALNUM(*cp))
      return 0;
  }
#endif

  return 1;
}

/**
 * Set *<b>addr</b> to the host-order IPv4 address (if any) of whatever
 * interface connects to the internet.  This address should only be used in
 * checking whether our address has changed.  Return 0 on success, -1 on
 * failure.
 */
int
get_interface_address(int severity, uint32_t *addr)
{
  int sock=-1, r=-1;
  struct sockaddr_in target_addr, my_addr;
  socklen_t my_addr_len = sizeof(my_addr);

  tor_assert(addr);
  *addr = 0;

  sock = socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP);
  if (sock < 0) {
    int e = tor_socket_errno(-1);
    log_fn(severity, LD_NET, "unable to create socket: %s",
           tor_socket_strerror(e));
    goto err;
  }

  memset(&target_addr, 0, sizeof(target_addr));
  target_addr.sin_family = AF_INET;
  /* discard port */
  target_addr.sin_port = 9;
  /* 18.0.0.1 (Don't worry: no packets are sent. We just need a real address
   * on the internet.) */
  target_addr.sin_addr.s_addr = htonl(0x12000001);

  if (connect(sock,(struct sockaddr *)&target_addr,sizeof(target_addr))<0) {
    int e = tor_socket_errno(sock);
    log_fn(severity, LD_NET, "connect() failed: %s", tor_socket_strerror(e));
    goto err;
  }

  /* XXXX Can this be right on IPv6 clients? */
  if (getsockname(sock, (struct sockaddr*)&my_addr, &my_addr_len)) {
    int e = tor_socket_errno(sock);
    log_fn(severity, LD_NET, "getsockname() failed: %s",
           tor_socket_strerror(e));
    goto err;
  }

  *addr = ntohl(my_addr.sin_addr.s_addr);

  r=0;
 err:
  if (sock >= 0)
    tor_close_socket(sock);
  return r;
}

/* =====
 * Process helpers
 * ===== */

#ifndef MS_WINDOWS
/* Based on code contributed by christian grothoff */
static int start_daemon_called = 0;
static int finish_daemon_called = 0;
static int daemon_filedes[2];
/** Start putting the process into daemon mode: fork and drop all resources
 * except standard fds.  The parent process never returns, but stays around
 * until finish_daemon is called.  (Note: it's safe to call this more
 * than once: calls after the first are ignored.)
 */
void
start_daemon(void)
{
  pid_t pid;

  if (start_daemon_called)
    return;
  start_daemon_called = 1;

  pipe(daemon_filedes);
  pid = fork();
  if (pid < 0) {
    log_err(LD_GENERAL,"fork failed. Exiting.");
    exit(1);
  }
  if (pid) {  /* Parent */
    int ok;
    char c;

    close(daemon_filedes[1]); /* we only read */
    ok = -1;
    while (0 < read(daemon_filedes[0], &c, sizeof(char))) {
      if (c == '.')
        ok = 1;
    }
    fflush(stdout);
    if (ok == 1)
      exit(0);
    else
      exit(1); /* child reported error */
  } else { /* Child */
    close(daemon_filedes[0]); /* we only write */

    pid = setsid(); /* Detach from controlling terminal */
    /*
     * Fork one more time, so the parent (the session group leader) can exit.
     * This means that we, as a non-session group leader, can never regain a
     * controlling terminal.   This part is recommended by Stevens's
     * _Advanced Programming in the Unix Environment_.
     */
    if (fork() != 0) {
      exit(0);
    }
    return;
  }
}

/** Finish putting the process into daemon mode: drop standard fds, and tell
 * the parent process to exit.  (Note: it's safe to call this more than once:
 * calls after the first are ignored.  Calls start_daemon first if it hasn't
 * been called already.)
 */
void
finish_daemon(const char *desired_cwd)
{
  int nullfd;
  char c = '.';
  if (finish_daemon_called)
    return;
  if (!start_daemon_called)
    start_daemon();
  finish_daemon_called = 1;

  if (!desired_cwd)
    desired_cwd = "/";
   /* Don't hold the wrong FS mounted */
  if (chdir(desired_cwd) < 0) {
    log_err(LD_GENERAL,"chdir to \"%s\" failed. Exiting.",desired_cwd);
    exit(1);
  }

  nullfd = open("/dev/null",
                O_CREAT | O_RDWR | O_APPEND);
  if (nullfd < 0) {
    log_err(LD_GENERAL,"/dev/null can't be opened. Exiting.");
    exit(1);
  }
  /* close fds linking to invoking terminal, but
   * close usual incoming fds, but redirect them somewhere
   * useful so the fds don't get reallocated elsewhere.
   */
  if (dup2(nullfd,0) < 0 ||
      dup2(nullfd,1) < 0 ||
      dup2(nullfd,2) < 0) {
    log_err(LD_GENERAL,"dup2 failed. Exiting.");
    exit(1);
  }
  if (nullfd > 2)
    close(nullfd);
  write(daemon_filedes[1], &c, sizeof(char)); /* signal success */
  close(daemon_filedes[1]);
}
#else
/* defined(MS_WINDOWS) */
void
start_daemon(void)
{
}
void
finish_daemon(const char *cp)
{
}
#endif

/** Write the current process ID, followed by NL, into <b>filename</b>.
 */
void
write_pidfile(char *filename)
{
#ifndef MS_WINDOWS
  FILE *pidfile;

  if ((pidfile = fopen(filename, "w")) == NULL) {
    log_warn(LD_FS, "Unable to open \"%s\" for writing: %s", filename,
             strerror(errno));
  } else {
    fprintf(pidfile, "%d\n", (int)getpid());
    fclose(pidfile);
  }
#endif
}

