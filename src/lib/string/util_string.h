/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_UTIL_STRING_H
#define TOR_UTIL_STRING_H

#include "orconfig.h"
#include "lib/cc/compat_compiler.h"

#include <stddef.h>

/** Allowable characters in a hexadecimal string. */
#define HEX_CHARACTERS "0123456789ABCDEFabcdef"
void tor_strlower(char *s) ATTR_NONNULL((1));
void tor_strupper(char *s) ATTR_NONNULL((1));
int tor_strisprint(const char *s) ATTR_NONNULL((1));
int tor_strisnonupper(const char *s) ATTR_NONNULL((1));
int tor_strisspace(const char *s);
int strcmp_opt(const char *s1, const char *s2);
int strcmpstart(const char *s1, const char *s2) ATTR_NONNULL((1,2));
int strcmp_len(const char *s1, const char *s2, size_t len) ATTR_NONNULL((1,2));
int strcasecmpstart(const char *s1, const char *s2) ATTR_NONNULL((1,2));
int strcmpend(const char *s1, const char *s2) ATTR_NONNULL((1,2));
int strcasecmpend(const char *s1, const char *s2) ATTR_NONNULL((1,2));
int fast_memcmpstart(const void *mem, size_t memlen, const char *prefix);

void tor_strstrip(char *s, const char *strip) ATTR_NONNULL((1,2));

const char *eat_whitespace(const char *s);
const char *eat_whitespace_eos(const char *s, const char *eos);
const char *eat_whitespace_no_nl(const char *s);
const char *eat_whitespace_eos_no_nl(const char *s, const char *eos);
const char *find_whitespace(const char *s);
const char *find_whitespace_eos(const char *s, const char *eos);
const char *find_str_at_start_of_line(const char *haystack,
                                      const char *needle);

int string_is_C_identifier(const char *string);

#endif /* !defined(TOR_UTIL_STRING_H) */
