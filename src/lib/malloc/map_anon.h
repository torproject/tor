/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file map_anon.h
 * \brief Headers for map_anon.c
 **/

#ifndef TOR_MAP_ANON_H
#define TOR_MAP_ANON_H

#include "lib/malloc/malloc.h"
#include <stddef.h>

/**
 * When this flag is specified, try to prevent the mapping from being
 * swapped or dumped.
 *
 * In some operating systems, this flag is not implemented.
 */
#define ANONMAP_PRIVATE   (1u<<0)
/**
 * When this flag is specified, try to prevent the mapping from being
 * inherited after a fork().  In some operating systems, trying to access it
 * afterwards will cause its contents to be zero.  In others, trying to access
 * it afterwards will cause a crash.
 *
 * In some operating systems, this flag is not implemented at all.
 */
#define ANONMAP_NOINHERIT (1u<<1)

/** Possible value for inherit_result_out: the memory will be kept
 * by any child process. */
#define INHERIT_KEEP 0
/** Possible value for inherit_result_out: the memory will be dropped in
 * the child process. Attempting to access it will likely cause a segfault. */
#define INHERIT_DROP 1
/** Possible value for inherit_result_out: the memory will be cleared in
 * the child process. */
#define INHERIT_ZERO 2

void *tor_mmap_anonymous(size_t sz, unsigned flags,
                         unsigned *inherit_result_out);
void tor_munmap_anonymous(void *mapping, size_t sz);

#endif /* !defined(TOR_MAP_ANON_H) */
