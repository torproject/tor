/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "lib/string/util_string.h"
#include "lib/string/compat_ctype.h"
#include "lib/err/torerr.h"
#include "lib/ctime/di_ops.h"

#include <string.h>
#include <stdlib.h>

/** Remove from the string <b>s</b> every character which appears in
 * <b>strip</b>. */
void
tor_strstrip(char *s, const char *strip)
{
  char *readp = s;
  while (*readp) {
    if (strchr(strip, *readp)) {
      ++readp;
    } else {
      *s++ = *readp++;
    }
  }
  *s = '\0';
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

/** Return true iff every character in <b>s</b> is whitespace space; else
 * return false. */
int
tor_strisspace(const char *s)
{
  while (*s) {
    if (!TOR_ISSPACE(*s))
      return 0;
    s++;
  }
  return 1;
}

/** As strcmp, except that either string may be NULL.  The NULL string is
 * considered to be before any non-NULL string. */
int
strcmp_opt(const char *s1, const char *s2)
{
  if (!s1) {
    if (!s2)
      return 0;
    else
      return -1;
  } else if (!s2) {
    return 1;
  } else {
    return strcmp(s1, s2);
  }
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
  return fast_memcmp(s1, s2, s2_len);
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
  raw_assert(s);

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
  raw_assert(s);
  raw_assert(eos && s <= eos);

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

/** Return a pointer to the first char of s that is not a space or a tab
 * or a \\r, or to the terminating NUL if no such character exists. */
const char *
eat_whitespace_no_nl(const char *s)
{
  while (*s == ' ' || *s == '\t' || *s == '\r')
    ++s;
  return s;
}

/** As eat_whitespace_no_nl, but stop at <b>eos</b> whether we have
 * found a non-whitespace character or not. */
const char *
eat_whitespace_eos_no_nl(const char *s, const char *eos)
{
  while (s < eos && (*s == ' ' || *s == '\t' || *s == '\r'))
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

/** Return the first occurrence of <b>needle</b> in <b>haystack</b> that
 * occurs at the start of a line (that is, at the beginning of <b>haystack</b>
 * or immediately after a newline).  Return NULL if no such string is found.
 */
const char *
find_str_at_start_of_line(const char *haystack, const char *needle)
{
  size_t needle_len = strlen(needle);

  do {
    if (!strncmp(haystack, needle, needle_len))
      return haystack;

    haystack = strchr(haystack, '\n');
    if (!haystack)
      return NULL;
    else
      ++haystack;
  } while (*haystack);

  return NULL;
}

/** Returns true if <b>string</b> could be a C identifier.
    A C identifier must begin with a letter or an underscore and the
    rest of its characters can be letters, numbers or underscores. No
    length limit is imposed. */
int
string_is_C_identifier(const char *string)
{
  size_t iter;
  size_t length = strlen(string);
  if (!length)
    return 0;

  for (iter = 0; iter < length ; iter++) {
    if (iter == 0) {
      if (!(TOR_ISALPHA(string[iter]) ||
            string[iter] == '_'))
        return 0;
    } else {
      if (!(TOR_ISALPHA(string[iter]) ||
            TOR_ISDIGIT(string[iter]) ||
            string[iter] == '_'))
        return 0;
    }
  }

  return 1;
}
