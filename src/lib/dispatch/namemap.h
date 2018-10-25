/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_NAMEMAP_H
#define TOR_NAMEMAP_H

/**
 * \file namemap.h
 *
 * \brief Header for namemap.c
 *
 * (This is only for use inside the dispatch module; if we need it elsewhere,
 * we should refactor it.)
 **/

#ifdef DISPATCH_PRIVATE
#include "lib/cc/compat_compiler.h"
#include "ht.h"

/** Longest allowed name that's allowed in a namemap_t. */
#define MAX_NAMEMAP_NAME_LEN 128

/** An entry inside a namemap_t. Maps a string to a numeric identifier. */
typedef struct mapped_name_t {
  HT_ENTRY(mapped_name_t) node;
  unsigned intval;
  char name[FLEXIBLE_ARRAY_MEMBER];
} mapped_name_t;

/** A structure that allocates small numeric identifiers for names and maps
 * back and forth between them.  */
typedef struct namemap_t {
  HT_HEAD(namemap_ht, mapped_name_t) ht;
  struct smartlist_t *names;
} namemap_t;

/** Returned in place of an identifier when an error occurs. */
#define NAMEMAP_ERR UINT_MAX

void namemap_init(namemap_t *map);
const char *namemap_get_name(const namemap_t *map, unsigned id);
unsigned namemap_get_id(const namemap_t *map,
                        const char *name);
unsigned namemap_get_or_create_id(namemap_t *map,
                                  const char *name);
void namemap_clear(namemap_t *map);
#endif

#endif /* !defined(TOR_NAMEMAP_H) */
