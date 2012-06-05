/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file di_ops.h
 * \brief Headers for di_ops.c
 **/

#ifndef TOR_DI_OPS_H
#define TOR_DI_OPS_H

#include "orconfig.h"
#include "torint.h"

int tor_memcmp(const void *a, const void *b, size_t sz);
int tor_memeq(const void *a, const void *b, size_t sz);
#define tor_memneq(a,b,sz) (!tor_memeq((a),(b),(sz)))

/** Alias for the platform's memcmp() function.  This function is
 * <em>not</em> data-independent: we define this alias so that we can
 * mark cases where we are deliberately using a data-dependent memcmp()
 * implementation.
 */
#define fast_memcmp(a,b,c) (memcmp((a),(b),(c)))
#define fast_memeq(a,b,c)  (0==memcmp((a),(b),(c)))
#define fast_memneq(a,b,c) (0!=memcmp((a),(b),(c)))

#endif

