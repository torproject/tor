/* Copyright 2003 Roger Dingledine
 * Copyright 2004-2007 Roger Dingledine, Nick Mathewson */
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
#include <process.h>
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

  if (PREDICT_UNLIKELY(result == NULL)) {
    log_err(LD_MM,"Out of memory on malloc(). Dying.");
    /* If these functions die within a worker process, they won't call
     * spawn_exit, but that's ok, since the parent will run out of memory soon
     * anyway. */
    exit(1);
  }
  return result;
}

/** Allocate a chunk of <b>size</b> bytes of memory, fill the memory with
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
  if (PREDICT_UNLIKELY(result == NULL)) {
    log_err(LD_MM,"Out of memory on realloc(). Dying.");
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
  if (PREDICT_UNLIKELY(dup == NULL)) {
    log_err(LD_MM,"Out of memory on strdup(). Dying.");
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

/** Helper for places that need to take a function pointer to the right
 * spelling of "free()". */
void
_tor_free(void *mem)
{
  tor_free(mem);
}

/* =====
 * Math
 * ===== */

/** Returns floor(log2(u64)).  If u64 is 0, (incorrectly) returns 0. */
int
tor_log2(uint64_t u64)
{
  int r = 0;
  if (u64 >= (U64_LITERAL(1)<<32)) {
    u64 >>= 32;
    r = 32;
  }
  if (u64 >= (U64_LITERAL(1)<<16)) {
    u64 >>= 16;
    r += 16;
  }
  if (u64 >= (U64_LITERAL(1)<<8)) {
    u64 >>= 8;
    r += 8;
  }
  if (u64 >= (U64_LITERAL(1)<<4)) {
    u64 >>= 4;
    r += 4;
  }
  if (u64 >= (U64_LITERAL(1)<<2)) {
    u64 >>= 2;
    r += 2;
  }
  if (u64 >= (U64_LITERAL(1)<<1)) {
    u64 >>= 1;
    r += 1;
  }
  return r;
}

/** Return the power of 2 closest to <b>u64</b>. */
uint64_t
round_to_power_of_2(uint64_t u64)
{
  int lg2 = tor_log2(u64);
  uint64_t low = U64_LITERAL(1) << lg2, high = U64_LITERAL(1) << (lg2+1);
  if (high - u64 < u64 - low)
    return high;
  else
    return low;
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
 * Never end the string with <b>insert</b>, even if its length <i>is</i> a
 * multiple of <b>n</b>.
 */
int
tor_strpartition(char *dest, size_t dest_len,
                 const char *s, const char *insert, size_t n)
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
  if (is_even && len_in)
    len_out -= len_ins;
  if (dest_len < len_out+1)
    return -1;
  destp = dest;
  remaining = len_in;
  while (remaining) {
    strncpy(destp, s, n);
    remaining -= n;
    if (remaining < 0) {
      break;
    } else if (remaining == 0) {
      *(destp+n) = '\0';
      break;
    }
    strncpy(destp+n, insert, len_ins+1);
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

/** Compares the first strlen(s2) characters of s1 with s2.  Returns as for
 * strcmp.
 */
int
strcmpstart(const char *s1, const char *s2)
{
  size_t n = strlen(s2);
  return strncmp(s1, s2, n);
}

/** Compare the s1_len-byte string <b>s1</b> with <b>s2</b>,
 * without depending on a terminating nul in s1.  Sorting order is first by
 * length, then lexically; return values are as for strcmp.
 */
int
strcmp_len(const char *s1, const char *s2, size_t s1_len)
{
  size_t s2_len = strlen(s2);
  if (s1_len < s2_len)
    return -1;
  if (s1_len > s2_len)
    return 1;
  return memcmp(s1, s2, s2_len);
}

/** Compares the first strlen(s2) characters of s1 with s2.  Returns as for
 * strcasecmp.
 */
int
strcasecmpstart(const char *s1, const char *s2)
{
  size_t n = strlen(s2);
  return strncasecmp(s1, s2, n);
}

/** Compares the last strlen(s2) characters of s1 with s2.  Returns as for
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

/** Compares the last strlen(s2) characters of s1 with s2.  Returns as for
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

  while (1) {
    switch (*s) {
    case '\0':
    default:
      return s;
    case ' ':
    case '\t':
    case '\n':
    case '\r':
      ++s;
      break;
    case '#':
      ++s;
      while (*s && *s != '\n')
        ++s;
    }
  }
}

/** Return a pointer to the first char of s that is not whitespace and
 * not a comment, or to the terminating NUL if no such character exists.
 */
const char *
eat_whitespace_eos(const char *s, const char *eos)
{
  tor_assert(s);
  tor_assert(eos && s <= eos);

  while (s < eos) {
    switch (*s) {
    case '\0':
    default:
      return s;
    case ' ':
    case '\t':
    case '\n':
    case '\r':
      ++s;
      break;
    case '#':
      ++s;
      while (s < eos && *s && *s != '\n')
        ++s;
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

/** As eat_whitespace_no_nl, but stop at <b>eos</b> whether we have
 * found a non-whitespace character or not. */
const char *
eat_whitespace_eos_no_nl(const char *s, const char *eos)
{
  while (s < eos && (*s == ' ' || *s == '\t'))
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

/** As find_whitespace, but stop at <b>eos</b> whether we have found a
 * whitespace or not. */
const char *
find_whitespace_eos(const char *s, const char *eos)
{
  /* tor_assert(s); */
  while (s < eos) {
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
  return s;
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

/* Helper: common code to check whether the result of a strtol or strtoul or
 * strtoll is correct. */
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

/** As tor_parse_long, but return an unsigned long. */
unsigned long
tor_parse_ulong(const char *s, int base, unsigned long min,
                unsigned long max, int *ok, char **next)
{
  char *endptr;
  unsigned long r;

  r = strtoul(s, &endptr, base);
  CHECK_STRTOX_RESULT();
}

/** As tor_parse_log, but return a unit64_t.  Only base 10 is guaranteed to
 * work for now. */
uint64_t
tor_parse_uint64(const char *s, int base, uint64_t min,
                 uint64_t max, int *ok, char **next)
{
  char *endptr;
  uint64_t r;

#ifdef HAVE_STRTOULL
  r = (uint64_t)strtoull(s, &endptr, base);
#elif defined(MS_WINDOWS)
#if defined(_MSC_VER) && _MSC_VER < 1300
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

/** Encode the <b>srclen</b> bytes at <b>src</b> in a NUL-terminated,
 * uppercase hexadecimal string; store it in the <b>destlen</b>-byte buffer
 * <b>dest</b>.
 */
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
    *cp++ = "0123456789ABCDEF"[ (*(const uint8_t*)src) >> 4 ];
    *cp++ = "0123456789ABCDEF"[ (*(const uint8_t*)src) & 0xf ];
    ++src;
  }
  *cp = '\0';
}

/** Helper: given a hex digit, return its value, or -1 if it isn't hex. */
static INLINE int
hex_decode_digit(char c)
{
  switch (c) {
    case '0': return 0;
    case '1': return 1;
    case '2': return 2;
    case '3': return 3;
    case '4': return 4;
    case '5': return 5;
    case '6': return 6;
    case '7': return 7;
    case '8': return 8;
    case '9': return 9;
    case 'A': case 'a': return 10;
    case 'B': case 'b': return 11;
    case 'C': case 'c': return 12;
    case 'D': case 'd': return 13;
    case 'E': case 'e': return 14;
    case 'F': case 'f': return 15;
    default:
      return -1;
  }
}

/** Given a hexadecimal string of <b>srclen</b> bytes in <b>src</b>, decode it
 * and store the result in the <b>destlen</b>-byte buffer at <b>dest</b>.
 * Return 0 on success, -1 on failure. */
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
 * Generally, we use this for logging values that come in over the network to
 * keep them from tricking users, and for sending certain values to the
 * controller.
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

/** Rudimentary string wrapping code: given a un-wrapped <b>string</b> (no
 * newlines!), break the string into newline-terminated lines of no more than
 * <b>width</b> characters long (not counting newline) and insert them into
 * <b>out</b> in order.  Precede the first line with prefix0, and subsequent
 * lines with prefixRest.
 */
/* This uses a stupid greedy wrapping algorithm right now:
 *  - For each line:
 *    - Try to fit as much stuff as possible, but break on a space.
 *    - If the first "word" of the line will extend beyond the allowable
 *      width, break the word at the end of the width.
 */
void
wrap_string(smartlist_t *out, const char *string, size_t width,
            const char *prefix0, const char *prefixRest)
{
  size_t p0Len, pRestLen, pCurLen;
  const char *eos, *prefixCur;
  tor_assert(out);
  tor_assert(string);
  tor_assert(width);
  if (!prefix0)
    prefix0 = "";
  if (!prefixRest)
    prefixRest = "";

  p0Len = strlen(prefix0);
  pRestLen = strlen(prefixRest);
  tor_assert(width > p0Len && width > pRestLen);
  eos = strchr(string, '\0');
  tor_assert(eos);
  pCurLen = p0Len;
  prefixCur = prefix0;

  while ((eos-string)+pCurLen > width) {
    const char *eol = string + width - pCurLen;
    while (eol > string && *eol != ' ')
      --eol;
    /* eol is now the last space that can fit, or the start of the string. */
    if (eol > string) {
      size_t line_len = (eol-string) + pCurLen + 2;
      char *line = tor_malloc(line_len);
      memcpy(line, prefixCur, pCurLen);
      memcpy(line+pCurLen, string, eol-string);
      line[line_len-2] = '\n';
      line[line_len-1] = '\0';
      smartlist_add(out, line);
      string = eol + 1;
    } else {
      size_t line_len = width + 2;
      char *line = tor_malloc(line_len);
      memcpy(line, prefixCur, pCurLen);
      memcpy(line+pCurLen, string, width - pCurLen);
      line[line_len-2] = '\n';
      line[line_len-1] = '\0';
      smartlist_add(out, line);
      string += width-pCurLen;
    }
    prefixCur = prefixRest;
    pCurLen = pRestLen;
  }

  if (string < eos) {
    size_t line_len = (eos-string) + pCurLen + 2;
    char *line = tor_malloc(line_len);
    memcpy(line, prefixCur, pCurLen);
    memcpy(line+pCurLen, string, eos-string);
    line[line_len-2] = '\n';
    line[line_len-1] = '\0';
    smartlist_add(out, line);
  }
}

/* =====
 * Time
 * ===== */

/** Return the number of microseconds elapsed between *start and *end.
 */
long
tv_udiff(const struct timeval *start, const struct timeval *end)
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
tv_cmp(const struct timeval *a, const struct timeval *b)
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
tv_add(struct timeval *a, const struct timeval *b)
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
  uint64_t us = ms * 1000;
  a->tv_usec += us % 1000000;
  a->tv_sec += (us / 1000000) + (a->tv_usec / 1000000);
  a->tv_usec %= 1000000;
}

/** Yield true iff <b>y</b> is a leap-year. */
#define IS_LEAPYEAR(y) (!(y % 4) && ((y % 100) || !(y % 400)))
/** Helper: Return the number of leap-days between Jan 1, y1 and Jan 1, y2. */
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

/** Set <b>buf</b> to the RFC1123 encoding of the GMT value of <b>t</b>.
 * The buffer must be at least RFC1123_TIME_LEN+1 bytes long.
 *
 * (RFC1123 format is Fri, 29 Sep 2006 15:54:20 GMT)
 */
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

/** Parse the the RFC1123 encoding of some time (in GMT) from <b>buf</b>,
 * and store the result in *<b>t</b>.
 *
 * Return 0 on succcess, -1 on failure.
*/
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
    log_warn(LD_GENERAL, "Got invalid RFC1123 time %s: No such month", esc);
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

/** Set <b>buf</b> to the ISO8601 encoding of the local value of <b>t</b>.
 * The buffer must be at least ISO_TIME_LEN+1 bytes long.
 *
 * (ISO8601 format is 2006-10-29 10:57:20)
 */
void
format_local_iso_time(char *buf, time_t t)
{
  struct tm tm;
  strftime(buf, ISO_TIME_LEN+1, "%Y-%m-%d %H:%M:%S", tor_localtime_r(&t, &tm));
}

/** Set <b>buf</b> to the ISO8601 encoding of the GMT value of <b>t</b>.
 * The buffer must be at least ISO_TIME_LEN+1 bytes long.
 */
void
format_iso_time(char *buf, time_t t)
{
  struct tm tm;
  strftime(buf, ISO_TIME_LEN+1, "%Y-%m-%d %H:%M:%S", tor_gmtime_r(&t, &tm));
}

/** Given an ISO-formatted UTC time value (after the epoch) in <b>cp</b>,
 * parse it and store its value in *<b>t</b>.  Return 0 on success, -1 on
 * failure.  Ignore extraneous stuff in <b>cp</b> separated by whitespace from
 * the end of the time string. */
int
parse_iso_time(const char *cp, time_t *t)
{
  struct tm st_tm;
#ifdef HAVE_STRPTIME
  if (!strptime(cp, "%Y-%m-%d %H:%M:%S", &st_tm)) {
    log_warn(LD_GENERAL, "ISO time was unparseable by strptime"); return -1;
  }
#else
  unsigned int year=0, month=0, day=0, hour=100, minute=100, second=100;
  if (sscanf(cp, "%u-%u-%u %u:%u:%u", &year, &month,
                &day, &hour, &minute, &second) < 6) {
    log_warn(LD_GENERAL, "ISO time was unparseable"); return -1;
  }
  if (year < 1970 || month < 1 || month > 12 || day < 1 || day > 31 ||
          hour > 23 || minute > 59 || second > 61) {
    log_warn(LD_GENERAL, "ISO time was nonsensical"); return -1;
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

/** Given a <b>date</b> in one of the three formats allowed by HTTP (ugh),
 * parse it into <b>tm</b>.  Return 0 on success, negative on failure. */
int
parse_http_time(const char *date, struct tm *tm)
{
  const char *cp;
  char month[4];
  char wkday[4];
  int i;

  tor_assert(tm);
  memset(tm, 0, sizeof(*tm));

  /* First, try RFC1123 or RFC850 format: skip the weekday.  */
  if ((cp = strchr(date, ','))) {
    ++cp;
    if (sscanf(date, "%2d %3s %4d %2d:%2d:%2d GMT",
               &tm->tm_mday, month, &tm->tm_year,
               &tm->tm_hour, &tm->tm_min, &tm->tm_sec) == 6) {
      /* rfc1123-date */
      tm->tm_year -= 1900;
    } else if (sscanf(date, "%2d-%3s-%2d %2d:%2d:%2d GMT",
                      &tm->tm_mday, month, &tm->tm_year,
                      &tm->tm_hour, &tm->tm_min, &tm->tm_sec) == 6) {
      /* rfc850-date */
    } else {
      return -1;
    }
  } else {
    /* No comma; possibly asctime() format. */
    if (sscanf(date, "%3s %3s %2d %2d:%2d:%2d %4d",
               wkday, month, &tm->tm_mday,
               &tm->tm_hour, &tm->tm_min, &tm->tm_sec, &tm->tm_year) == 7) {
      tm->tm_year -= 1900;
    } else {
      return -1;
    }
  }

  month[4] = '\0';
  /* Okay, now decode the month. */
  for (i = 0; i < 12; ++i) {
    if (!strcasecmp(MONTH_NAMES[i], month)) {
      tm->tm_mon = i+1;
    }
  }

  if (tm->tm_year < 0 ||
      tm->tm_mon < 1  || tm->tm_mon > 12 ||
      tm->tm_mday < 0 || tm->tm_mday > 31 ||
      tm->tm_hour < 0 || tm->tm_hour > 23 ||
      tm->tm_min < 0  || tm->tm_min > 59 ||
      tm->tm_sec < 0  || tm->tm_sec > 61)
    return -1; /* Out of range, or bad month. */

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
 * This function replaces the old file atomically, if possible.  This
 * function, and all other functions in util.c that create files, create them
 * with mode 0600.
 */
int
write_str_to_file(const char *fname, const char *str, int bin)
{
#ifdef MS_WINDOWS
  if (!bin && strchr(str, '\r')) {
    log_warn(LD_BUG,
             "We're writing a text string that already contains a CR.");
  }
#endif
  return write_bytes_to_file(fname, str, strlen(str), bin);
}

/** Helper: given a set of flags as passed to open(2), open the file
 * <b>fname</b> and write all the sized_chunk_t structs in <b>chunks</b> to
 * the file.  Do so as atomically as possible e.g. by opening temp files and
 * renaming. */
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

/** Given a smartlist of sized_chunk_t, write them atomically to a file
 * <b>fname</b>, overwriting or creating the file as necessary. */
int
write_chunks_to_file(const char *fname, const smartlist_t *chunks, int bin)
{
  int flags = O_WRONLY|O_CREAT|O_TRUNC|(bin?O_BINARY:O_TEXT);
  return write_chunks_to_file_impl(fname, chunks, flags);
}

/** As write_str_to_file, but does not assume a NUL-terminated
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

/** As write_bytes_to_file, but if the file already exists, append the bytes
 * to the end of the file instead of overwriting it. */
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
 *
 * If <b>stat_out</b> is provided, store the result of stat()ing the
 * file into <b>stat_out</b>.
 *
 * If <b>flags</b> &amp; RFTS_BIN, open the file in binary mode.
 * If <b>flags</b> &amp; RFTS_IGNORE_MISSING, don't warn if the file
 * doesn't exist.
 */
/*
 * This function <em>may</em> return an erroneous result if the file
 * is modified while it is running, but must not crash or overflow.
 * Right now, the error case occurs when the file length grows between
 * the call to stat and the call to read_all: the resulting string will
 * be truncated.
 */
char *
read_file_to_str(const char *filename, int flags, struct stat *stat_out)
{
  int fd; /* router file */
  struct stat statbuf;
  char *string;
  int r;
  int bin = flags & RFTS_BIN;

  tor_assert(filename);

  fd = open(filename,O_RDONLY|(bin?O_BINARY:O_TEXT),0);
  if (fd<0) {
    int severity = LOG_WARN;
    if (errno == ENOENT && (flags & RFTS_IGNORE_MISSING))
      severity = LOG_INFO;
    log_fn(severity, LD_FS,"Could not open \"%s\": %s ",filename,
           strerror(errno));
    return NULL;
  }

  if (fstat(fd, &statbuf)<0) {
    close(fd);
    log_warn(LD_FS,"Could not fstat \"%s\".",filename);
    return NULL;
  }

  if ((uint64_t)(statbuf.st_size)+1 > SIZE_T_MAX)
    return NULL;

  string = tor_malloc((size_t)(statbuf.st_size+1));

  r = read_all(fd,string,(size_t)statbuf.st_size,0);
  if (r<0) {
    log_warn(LD_FS,"Error reading from file \"%s\": %s", filename,
             strerror(errno));
    tor_free(string);
    close(fd);
    return NULL;
  }
  string[r] = '\0'; /* NUL-terminate the result. */

#ifdef MS_WINDOWS
  if (!bin && strchr(string, '\r')) {
    log_debug(LD_FS, "We didn't convert CRLF to LF as well as we hoped "
              "when reading %s. Coping.",
              filename);
    tor_strstrip(string, "\r");
    r = strlen(string);
  }
  if (!bin) {
    statbuf.st_size = (size_t) r;
  } else
#endif
    if (r != statbuf.st_size) {
      /* Unless we're using text mode on win32, we'd better have an exact
       * match for size. */
      log_warn(LD_FS,"Could read only %d of %ld bytes of file \"%s\".",
               r, (long)statbuf.st_size,filename);
      tor_free(string);
      close(fd);
      return NULL;
    }
  close(fd);
  if (stat_out) {
    memcpy(stat_out, &statbuf, sizeof(struct stat));
  }

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

/** Expand any homedir prefix on <b>filename</b>; return a newly allocated
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
    if (strlen(home)>1 && !strcmpend(home,PATH_SEPARATOR)) {
      home[strlen(home)-1] = '\0';
    }
    /* Plus one for /, plus one for NUL.
     * Round up to 16 in case we can't do math. */
    len = strlen(home)+strlen(rest)+16;
    result = tor_malloc(len);
    tor_snprintf(result,len,"%s"PATH_SEPARATOR"%s",home,rest?rest:"");
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

/** Return true iff <b>filename</b> is a relative path. */
int
path_is_relative(const char *filename)
{
  if (filename && filename[0] == '/')
    return 0;
#ifdef MS_WINDOWS
  else if (filename && filename[0] == '\\')
    return 0;
  else if (filename && strlen(filename)>3 && TOR_ISALPHA(filename[0]) &&
           filename[1] == ':' && filename[2] == '\\')
    return 0;
#endif
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
  tor_addr_t myaddr;
  myaddr.sa.sin_family = AF_INET;
  myaddr.sa.sin_addr.s_addr = htonl(ip);

  return tor_addr_is_internal(&myaddr, for_listening);
}

/** Return true iff <b>ip</b> is an IP reserved to localhost or local networks
 * in RFC1918 or RFC4193 or RFC4291. (fec0::/10, deprecated by RFC3879, is
 * also treated as internal for now.)
 */
int
tor_addr_is_internal(const tor_addr_t *addr, int for_listening)
{
  uint32_t iph4 = 0;
  uint32_t iph6[4];
  sa_family_t v_family;
  v_family = IN_FAMILY(addr);

  if (v_family == AF_INET) {
    iph4 = IPV4IPh(addr);
  } else if (v_family == AF_INET6) {
    if (tor_addr_is_v4(addr)) { /* v4-mapped */
      v_family = AF_INET;
      iph4 = ntohl(IN6_ADDR(addr)->s6_addr32[3]);
    }
  }

  if (v_family == AF_INET6) {
    iph6[0] = ntohl(IN6_ADDR(addr)->s6_addr32[0]);
    iph6[1] = ntohl(IN6_ADDR(addr)->s6_addr32[1]);
    iph6[2] = ntohl(IN6_ADDR(addr)->s6_addr32[2]);
    iph6[3] = ntohl(IN6_ADDR(addr)->s6_addr32[3]);
    if (for_listening && !iph6[0] && !iph6[1] && !iph6[2] && !iph6[3]) /* :: */
      return 0;

    if (((iph6[0] & 0xfe000000) == 0xfc000000) || /* fc00/7  - RFC4193 */
        ((iph6[0] & 0xffc00000) == 0xfe800000) || /* fe80/10 - RFC4291 */
        ((iph6[0] & 0xffc00000) == 0xfec00000))   /* fec0/10 D- RFC3879 */
      return 1;

    if (!iph6[0] && !iph6[1] && !iph6[2] &&
        ((iph6[3] & 0xfffffffe) == 0x00000000))  /* ::/127 */
      return 1;

    return 0;
  } else if (v_family == AF_INET) {
    if (for_listening && !iph4) /* special case for binding to 0.0.0.0 */
      return 0;
    if (((iph4 & 0xff000000) == 0x0a000000) || /*       10/8 */
        ((iph4 & 0xff000000) == 0x00000000) || /*        0/8 */
        ((iph4 & 0xff000000) == 0x7f000000) || /*      127/8 */
        ((iph4 & 0xffff0000) == 0xa9fe0000) || /* 169.254/16 */
        ((iph4 & 0xfff00000) == 0xac100000) || /*  172.16/12 */
        ((iph4 & 0xffff0000) == 0xc0a80000))   /* 192.168/16 */
      return 1;
    return 0;
  }

  /* unknown address family... assume it's not safe for external use */
  /* rather than tor_assert(0) */
  log_warn(LD_BUG, "tor_addr_is_internal() called with a non-IP address.");
  return 1;
}

#if 0
/** Convert a tor_addr_t <b>addr</b> into a string, and store it in
 *  <b>dest</b> of size <b>len</b>.  Returns a pointer to dest on success,
 *  or NULL on failure.
 */
void
tor_addr_to_str(char *dest, const tor_addr_t *addr, int len)
{
  const char *ptr;
  tor_assert(addr && dest);

  switch (IN_FAMILY(addr)) {
    case AF_INET:
      ptr = tor_inet_ntop(AF_INET, &addr->sa.sin_addr, dest, len);
      break;
    case AF_INET6:
      ptr = tor_inet_ntop(AF_INET6, &addr->sa6.sin6_addr, dest, len);
      break;
    default:
      return NULL;
  }
  return ptr;
}
#endif

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

/** Compare two addresses <b>a1</b> and <b>a2</b> for equality under a
 *  etmask of <b>mbits</b> bits.  Return -1, 0, or 1.
 *
 * XXXX020Temporary function to allow masks as bitcounts everywhere.  This
 * will be replaced with an IPv6-aware version as soon as 32-bit addresses are
 * no longer passed around.
 */
int
addr_mask_cmp_bits(uint32_t a1, uint32_t a2, maskbits_t bits)
{
  if (bits > 32)
    bits = 32;
  else if (bits == 0)
    return 0;

  a1 >>= (32-bits);
  a2 >>= (32-bits);

  if (a1 < a2)
    return -1;
  else if (a1 > a2)
    return 1;
  else
    return 0;
}

/** Parse a string <b>s</b> in the format of (*|port(-maxport)?)?, setting the
 * various *out pointers as appropriate.  Return 0 on success, -1 on failure.
 */
int
parse_port_range(const char *port, uint16_t *port_min_out,
                 uint16_t *port_max_out)
{
  int port_min, port_max, ok;
  tor_assert(port_min_out);
  tor_assert(port_max_out);

  if (!port || *port == '\0' || strcmp(port, "*") == 0) {
    port_min = 1;
    port_max = 65535;
  } else {
    char *endptr = NULL;
    port_min = tor_parse_long(port, 10, 0, 65535, &ok, &endptr);
    if (!ok) {
      log_warn(LD_GENERAL,
               "Malformed port %s on address range; rejecting.",
               escaped(port));
      return -1;
    } else if (endptr && *endptr == '-') {
      port = endptr+1;
      endptr = NULL;
      port_max = tor_parse_long(port, 10, 1, 65536, &ok, &endptr);
      if (!ok) {
        log_warn(LD_GENERAL,
                 "Malformed port %s on address range; rejecting.",
                 escaped(port));
        return -1;
      }
    } else {
      port_max = port_min;
    }
    if (port_min > port_max) {
      log_warn(LD_GENERAL, "Insane port range on address policy; rejecting.");
      return -1;
    }
  }

  if (port_min < 1)
    port_min = 1;
  if (port_max > 65535)
    port_max = 65535;

  *port_min_out = (uint16_t) port_min;
  *port_max_out = (uint16_t) port_max;

  return 0;
}

/** Parse a string <b>s</b> in the format of
 * (IP(/mask|/mask-bits)?|*)(:*|port(-maxport)?)?, setting the various
 * *out pointers as appropriate.  Return 0 on success, -1 on failure.
 */
int
parse_addr_and_port_range(const char *s, uint32_t *addr_out,
                          maskbits_t *maskbits_out, uint16_t *port_min_out,
                          uint16_t *port_max_out)
{
  char *address;
  char *mask, *port, *endptr;
  struct in_addr in;
  int bits;

  tor_assert(s);
  tor_assert(addr_out);
  tor_assert(maskbits_out);
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
      *maskbits_out = 0;
    else
      *maskbits_out = 32;
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
      *maskbits_out = bits;
    } else if (tor_inet_aton(mask, &in) != 0) {
      bits = addr_mask_get_bits(ntohl(in.s_addr));
      if (bits < 0) {
        log_warn(LD_GENERAL,
                 "Mask %s on address range isn't a prefix; dropping",
                 escaped(mask));
        goto err;
      }
      *maskbits_out = bits;
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

/** Parse a string <b>s</b> containing an IPv4/IPv6 address, and possibly
 *  a mask and port or port range.  Store the parsed address in
 *  <b>addr_out</b>, a mask (if any) in <b>mask_out</b>, and port(s) (if any)
 *  in <b>port_min_out</b> and <b>port_max_out</b>.
 *
 * DOCDOC exact syntax.
 *
 *  - If mask, minport, or maxport are NULL, avoid storing those elements.
 *  - If the string has no mask, the mask is set to /32 (IPv4) or /128 (IPv6).
 *  - If the string has one port, it is placed in both min and max port
 *    variables.
 *  - If the string has no port(s), port_(min|max)_out are set to 1 and 65535.
 *
 *  Return an address family on success, or -1 if an invalid address string is
 *  provided.
 */
int
tor_addr_parse_mask_ports(const char *s, tor_addr_t *addr_out,
                          maskbits_t *maskbits_out,
                          uint16_t *port_min_out, uint16_t *port_max_out)
{
  char *base = NULL, *address, *mask = NULL, *port = NULL, *rbracket = NULL;
  char *endptr;
  int any_flag=0, v4map=0;

  tor_assert(s);
  tor_assert(addr_out);

  /* IP, [], /mask, ports */
#define MAX_ADDRESS_LENGTH (TOR_ADDR_BUF_LEN+2+(1+INET_NTOA_BUF_LEN)+12+1)

  if (strlen(s) > MAX_ADDRESS_LENGTH) {
    log_warn(LD_GENERAL, "Impossibly long IP %s; rejecting", escaped(s));
    goto err;
  }
  base = tor_strdup(s);

  /* Break 'base' into separate strings. */
  address = base;
  if (*address == '[') {  /* Probably IPv6 */
    address++;
    rbracket = strchr(address, ']');
    if (!rbracket) {
      log_warn(LD_GENERAL,
               "No closing IPv6 bracket in address pattern; rejecting.");
      goto err;
    }
  }
  mask = strchr((rbracket?rbracket:address),'/');
  port = strchr((mask?mask:(rbracket?rbracket:address)), ':');
  if (port)
    *port++ = '\0';
  if (mask)
    *mask++ = '\0';
  if (rbracket)
    *rbracket = '\0';
  if (port && mask)
    tor_assert(port > mask);
  if (mask && rbracket)
    tor_assert(mask > rbracket);

  /* Now "address" is the a.b.c.d|'*'|abcd::1 part...
   *     "mask" is the Mask|Maskbits part...
   * and "port" is the *|port|min-max part.
   */

  /* Process the address portion */
  memset(addr_out, 0, sizeof(tor_addr_t));

  if (!strcmp(address, "*")) {
    addr_out->sa.sin_family = AF_INET; /* AF_UNSPEC ???? XXXXX020 */
    any_flag = 1;
  } else if (tor_inet_pton(AF_INET6, address, &addr_out->sa6.sin6_addr) > 0) {
    addr_out->sa6.sin6_family = AF_INET6;
  } else if (tor_inet_pton(AF_INET, address, &addr_out->sa.sin_addr) > 0) {
    addr_out->sa.sin_family = AF_INET;
  } else {
    log_warn(LD_GENERAL, "Malformed IP %s in address pattern; rejecting.",
             escaped(address));
    goto err;
  }

  v4map = tor_addr_is_v4(addr_out);

/*
#ifdef ALWAYS_V6_MAP
  if (v_family == AF_INET) {
    v_family = AF_INET6;
    IN_ADDR6(addr_out).s6_addr32[3] = IN6_ADDR(addr_out).s_addr;
    memset(&IN6_ADDR(addr_out), 0, 10);
    IN_ADDR6(addr_out).s6_addr16[5] = 0xffff;
  }
#else
  if (v_family == AF_INET6 && v4map) {
    v_family = AF_INET;
    IN_ADDR(addr_out).s_addr = IN6_ADDR(addr_out).s6_addr32[3];
  }
#endif
*/

  /* Parse mask */
  if (maskbits_out) {
    int bits = 0;
    struct in_addr v4mask;

    if (mask) {  /* the caller (tried to) specify a mask */
      bits = (int) strtol(mask, &endptr, 10);
      if (!*endptr) {  /* strtol converted everything, so it was an integer */
        if ((bits<0 || bits>128) ||
            ((IN_FAMILY(addr_out) == AF_INET) && bits > 32)) {
          log_warn(LD_GENERAL,
                   "Bad number of mask bits (%d) on address range; rejecting.",
                   bits);
          goto err;
        }
      } else {  /* mask might still be an address-style mask */
        if (tor_inet_pton(AF_INET, mask, &v4mask) > 0) {
          bits = addr_mask_get_bits(ntohl(v4mask.s_addr));
          if (bits < 0) {
            log_warn(LD_GENERAL,
                     "IPv4-style mask %s is not a prefix address; rejecting.",
                     escaped(mask));
            goto err;
          }
        } else { /* Not IPv4; we don't do address-style IPv6 masks. */
          log_warn(LD_GENERAL,
                   "Malformed mask on address range %s; rejecting.",
                   escaped(s));
          goto err;
        }
      }
      if (IN_FAMILY(addr_out) == AF_INET6 && v4map) {
        if (bits > 32 && bits < 96) { /* Crazy */
          log_warn(LD_GENERAL,
                   "Bad mask bits %i for V4-mapped V6 address; rejecting.",
                   bits);
          goto err;
        }
        /* XXXX020 is this really what we want? */
        bits = 96 + bits%32; /* map v4-mapped masks onto 96-128 bits */
      }
    } else { /* pick an appropriate mask, as none was given */
      if (any_flag)
        bits = 0;  /* This is okay whether it's V6 or V4 (FIX V4-mapped V6!) */
      else if (IN_FAMILY(addr_out) == AF_INET)
        bits = 32;
      else if (IN_FAMILY(addr_out) == AF_INET6)
        bits = 128;
    }
    *maskbits_out = (maskbits_t) bits;
  } else {
    if (mask) {
      log_warn(LD_GENERAL,
               "Unexpected mask in addrss %s; rejecting", escaped(s));
      goto err;
    }
  }

  /* Parse port(s) */
  if (port_min_out) {
    uint16_t port2;
    if (!port_max_out) /* caller specified one port; fake the second one */
      port_max_out = &port2;

    if (parse_port_range(port, port_min_out, port_max_out) < 0) {
      goto err;
    } else if ((*port_min_out != *port_max_out) && port_max_out == &port2) {
      log_warn(LD_GENERAL,
               "Wanted one port from address range, but there are two.");

      port_max_out = NULL;  /* caller specified one port, so set this back */
      goto err;
    }
  } else {
    if (port) {
      log_warn(LD_GENERAL,
               "Unexpected ports in addrss %s; rejecting", escaped(s));
      goto err;
    }
  }

  tor_free(base);
  return IN_FAMILY(addr_out);
 err:
  tor_free(base);
  return -1;
}

/** Determine whether an address is IPv4, either native or ipv4-mapped ipv6.
 * Note that this is about representation only, as any decent stack will
 * reject ipv4-mapped addresses received on the wire (and won't use them
 * on the wire either).
 */
int
tor_addr_is_v4(const tor_addr_t *addr)
{
  tor_assert(addr);

  if (IN_FAMILY(addr) == AF_INET)
    return 1;

  if (IN_FAMILY(addr) == AF_INET6) { /* First two don't need to be ordered */
    if ((IN6_ADDR(addr)->s6_addr32[0] == 0) &&
        (IN6_ADDR(addr)->s6_addr32[1] == 0) &&
        (ntohl(IN6_ADDR(addr)->s6_addr32[2]) == 0x0000ffffu))
      return 1;
  }

  return 0; /* Not IPv4 - unknown family or a full-blood IPv6 address */
}

/** Determine whether an address <b>addr</b> is null, either all zeroes or
 *  belonging to family AF_UNSPEC.
 */
int
tor_addr_is_null(const tor_addr_t *addr)
{
  tor_assert(addr);

  switch (IN_FAMILY(addr)) {
    case AF_INET6:
      if (!IN6_ADDR(addr)->s6_addr32[0] && !IN6_ADDR(addr)->s6_addr32[1] &&
          !IN6_ADDR(addr)->s6_addr32[2] && !IN6_ADDR(addr)->s6_addr32[3])
        return 1;
      return 0;
    case AF_INET:
      if (!IN_ADDR(addr)->s_addr)
        return 1;
      return 0;
    default:
      return 1;
  }
  //return 1;
}

/** Given an IPv4 in_addr struct *<b>in</b> (in network order, as usual),
 *  write it as a string into the <b>buf_len</b>-byte buffer in
 *  <b>buf</b>.
 */
int
tor_inet_ntoa(const struct in_addr *in, char *buf, size_t buf_len)
{
  uint32_t a = ntohl(in->s_addr);
  return tor_snprintf(buf, buf_len, "%d.%d.%d.%d",
                      (int)(uint8_t)((a>>24)&0xff),
                      (int)(uint8_t)((a>>16)&0xff),
                      (int)(uint8_t)((a>>8 )&0xff),
                      (int)(uint8_t)((a    )&0xff));
}

/** Take a 32-bit host-order ipv4 address <b>v4addr</b> and store it in the
 *  tor_addr *<b>dest</b>.
 *
 *  XXXX020 Temporary, for use while 32-bit int addresses are still being
 *  passed around.
 */
void
tor_addr_from_ipv4(tor_addr_t *dest, uint32_t v4addr)
{
  tor_assert(dest);
  memset(dest, 0, sizeof(dest));
  dest->sa.sin_family = AF_INET;
  dest->sa.sin_addr.s_addr = htonl(v4addr);
}

/** Copy a tor_addr_t from <b>src</b> to <b>dest</b>.
 */
void
tor_addr_copy(tor_addr_t *dest, const tor_addr_t *src)
{
  tor_assert(src && dest);
  memcpy(dest, src, sizeof(tor_addr_t));
}

/** DOCDOC */
int
tor_addr_compare(const tor_addr_t *addr1, const tor_addr_t *addr2)
{
  return tor_addr_compare_masked(addr1, addr2, 128);
}

/** Given two addresses <b>addr1</b> and <b>addr2</b>, return 0 if the two
 * addresses are equivalent under the mask mbits, or nonzero if not.
 *
 * Different address families (IPv4 vs IPv6) are always considered unequal.
 *
 * Reduce over-specific masks (>128 for ipv6, >32 for ipv4) to 128 or 32.
 */
int
tor_addr_compare_masked(const tor_addr_t *addr1, const tor_addr_t *addr2,
                        maskbits_t mbits)
{
  uint32_t ip4a=0, ip4b=0;
  sa_family_t v_family[2];
  int idx;
  uint32_t masked_a, masked_b;

  tor_assert(addr1 && addr2);

  v_family[0] = IN_FAMILY(addr1);
  v_family[1] = IN_FAMILY(addr2);

  if (v_family[0] == AF_INET) { /* If this is native IPv4, note the address */
    ip4a = IPV4IPh(addr1); /* Later we risk overwriting a v4-mapped address */
  } else if ((v_family[0] == AF_INET6) && tor_addr_is_v4(addr1)) {
    v_family[0] = AF_INET;
    ip4a = IPV4MAPh(addr1);
  }

  if (v_family[1] == AF_INET) { /* If this is native IPv4, note the address */
    ip4b = IPV4IPh(addr2); /* Later we risk overwriting a v4-mapped address */
  } else if ((v_family[1] == AF_INET6) && tor_addr_is_v4(addr2)) {
    v_family[1] = AF_INET;
    ip4b = IPV4MAPh(addr2);
  }

  if (v_family[0] > v_family[1]) /* Comparison of virtual families */
    return 1;
  else if (v_family[0] < v_family[1])
    return -1;

  if (mbits == 0)  /* Under a complete wildcard mask, consider them equal */
    return 0;

  if (v_family[0] == AF_INET) { /* Real or mapped IPv4 */
    if (mbits >= 32) {
      masked_a = ip4a;
      masked_b = ip4b;
    } else if (mbits == 0) {
      return 0;
    } else {
      masked_a = ip4a >> (32-mbits);
      masked_b = ip4b >> (32-mbits);
    }
    if (masked_a < masked_b)
      return -1;
    else if (masked_a > masked_b)
      return 1;
    return 0;
  } else if (v_family[0] == AF_INET6) { /* Real IPv6 */
    const uint32_t *a1 = IN6_ADDR(addr1)->s6_addr32;
    const uint32_t *a2 = IN6_ADDR(addr2)->s6_addr32;
    for (idx = 0; idx < 4; ++idx) {
      uint32_t masked_a = ntohl(a1[idx]);
      uint32_t masked_b = ntohl(a2[idx]);
      if (!mbits) {
        return 0; /* Mask covers both addresses from here on */
      } else if (mbits < 32) {
        masked_a >>= (32-mbits);
        masked_b >>= (32-mbits);
      }

      if (masked_a > masked_b)
        return 1;
      else if (masked_a < masked_b)
        return -1;

      if (mbits < 32)
        return 0;
      mbits -= 32;
    }
    return 0;
  }

  tor_assert(0);  /* Unknown address family */
  return -1; /* unknown address family, return unequal? */
}

/** Given a host-order <b>addr</b>, call tor_inet_ntop() on it
 *  and return a strdup of the resulting address.
 */
char *
tor_dup_addr(uint32_t addr)
{
  char buf[TOR_ADDR_BUF_LEN];
  struct in_addr in;

  in.s_addr = htonl(addr);
  tor_inet_ntop(AF_INET, &in, buf, sizeof(buf));
  return tor_strdup(buf);
}

/** Convert the tor_addr_t *<b>addr</b> into string form and store it in
 * <b>dest</b> (no more than <b>len</b> bytes). DOCDOC return value.
 */
const char *
tor_addr_to_str(char *dest, const tor_addr_t *addr, int len)
{
  tor_assert(addr && dest);

  if (IN_FAMILY(addr) == AF_INET) {
    return tor_inet_ntop(AF_INET, IN_ADDR(addr), dest, len);
  } else if (IN_FAMILY(addr) == AF_INET6) {
    return tor_inet_ntop(AF_INET6, IN6_ADDR(addr), dest, len);
  } else {
    return NULL;
  }
}

/** Convert the string in <b>src</b> to a tor_addr_t <b>addr</b>.
 */
int
tor_addr_from_str(tor_addr_t *addr, const char *src)
{
  tor_assert(addr && src);
  return tor_addr_parse_mask_ports(src, addr, NULL, NULL, NULL);
}

/** Set *<b>addr</b> to the IP address (if any) of whatever interface
 * connects to the internet.  This address should only be used in checking
 * whether our address has changed.  Return 0 on success, -1 on failure.
 */
int
get_interface_address6(int severity, sa_family_t family, tor_addr_t *addr)
{
  int sock=-1, r=-1;
  struct sockaddr_storage my_addr, target_addr;
  socklen_t my_addr_len;

  tor_assert(addr);

  memset(addr, 0, sizeof(tor_addr_t));
  memset(&target_addr, 0, sizeof(target_addr));
  my_addr_len = sizeof(my_addr);
  ((struct sockaddr_in*)&target_addr)->sin_port = 9;  /* DISGARD port */
  /* Don't worry: no packets are sent. We just need to use a real address
   * on the actual internet. */
  if (family == AF_INET6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&target_addr;
    sock = tor_open_socket(PF_INET6,SOCK_DGRAM,IPPROTO_UDP);
    my_addr_len = sizeof(struct sockaddr_in6);
    sin6->sin6_family = AF_INET6;
    sin6->sin6_addr.s6_addr16[0] = htons(0x2002); /* 2002:: */
  } else if (family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in*)&target_addr;
    sock = tor_open_socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP);
    my_addr_len = sizeof(struct sockaddr_in);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(0x12000001); /* 18.0.0.1 */
  } else {
    return -1;
  }
  if (sock < 0) {
    int e = tor_socket_errno(-1);
    log_fn(severity, LD_NET, "unable to create socket: %s",
           tor_socket_strerror(e));
    goto err;
  }

  if (connect(sock,(struct sockaddr *)&target_addr,sizeof(target_addr))<0) {
    int e = tor_socket_errno(sock);
    log_fn(severity, LD_NET, "connect() failed: %s", tor_socket_strerror(e));
    goto err;
  }

  if (getsockname(sock,(struct sockaddr*)&my_addr, &my_addr_len)) {
    int e = tor_socket_errno(sock);
    log_fn(severity, LD_NET, "getsockname() to determine interface failed: %s",
           tor_socket_strerror(e));
    goto err;
  }

  memcpy(addr, &my_addr, sizeof(tor_addr_t));
  r=0;
 err:
  if (sock >= 0)
    tor_close_socket(sock);
  return r;
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
  tor_addr_t local_addr;
  int r;

  r = get_interface_address6(severity, AF_INET, &local_addr);
  if (r>=0)
    *addr = IPV4IPh(&local_addr);
  return r;
}

/* =====
 * Process helpers
 * ===== */

#ifndef MS_WINDOWS
/* Based on code contributed by christian grothoff */
/** True iff we've called start_daemon(). */
static int start_daemon_called = 0;
/** True iff we've called finish_daemon(). */
static int finish_daemon_called = 0;
/** Socketpair used to communicate between parent and child process while
 * daemonizing. */
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
  (void)cp;
}
#endif

/** Write the current process ID, followed by NL, into <b>filename</b>.
 */
void
write_pidfile(char *filename)
{
  FILE *pidfile;

  if ((pidfile = fopen(filename, "w")) == NULL) {
    log_warn(LD_FS, "Unable to open \"%s\" for writing: %s", filename,
             strerror(errno));
  } else {
#ifdef MS_WINDOWS
    fprintf(pidfile, "%d\n", (int)_getpid());
#else
    fprintf(pidfile, "%d\n", (int)getpid());
#endif
    fclose(pidfile);
  }
}

