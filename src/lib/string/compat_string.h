/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_COMPAT_STRING_H
#define TOR_COMPAT_STRING_H

#include "orconfig.h"
#include "lib/cc/compat_compiler.h"

#include <stddef.h>

/* ===== String compatibility */
#ifdef _WIN32
/* Windows names string functions differently from most other platforms. */
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#endif

#if defined __APPLE__
/* On OSX 10.9 and later, the overlap-checking code for strlcat would
 * appear to have a severe bug that can sometimes cause aborts in Tor.
 * Instead, use the non-checking variants.  This is sad.
 *
 * See https://trac.torproject.org/projects/tor/ticket/15205
 */
#undef strlcat
#undef strlcpy
#endif /* defined __APPLE__ */

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz) ATTR_NONNULL((1,2));
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz) ATTR_NONNULL((1,2));
#endif

char *tor_strtok_r_impl(char *str, const char *sep, char **lasts);
#ifdef HAVE_STRTOK_R
#define tor_strtok_r(str, sep, lasts) strtok_r(str, sep, lasts)
#else
#define tor_strtok_r(str, sep, lasts) tor_strtok_r_impl(str, sep, lasts)
#endif

#endif
