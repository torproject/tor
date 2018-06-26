/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_BLOOMFILT_H
#define TOR_BLOOMFILT_H

#include "orconfig.h"
#include "lib/cc/torint.h"
#include "lib/container/bitarray.h"
#include "siphash.h"

/** A set of digests, implemented as a Bloom filter. */
typedef struct {
  int mask; /**< One less than the number of bits in <b>ba</b>; always one less
             * than a power of two. */
  bitarray_t *ba; /**< A bit array to implement the Bloom filter. */
} digestset_t;

#define BIT(n) ((n) & set->mask)
/** Add the digest <b>digest</b> to <b>set</b>. */
static inline void
digestset_add(digestset_t *set, const char *digest)
{
  const uint64_t x = siphash24g(digest, 20);
  const uint32_t d1 = (uint32_t) x;
  const uint32_t d2 = (uint32_t)( (x>>16) + x);
  const uint32_t d3 = (uint32_t)( (x>>32) + x);
  const uint32_t d4 = (uint32_t)( (x>>48) + x);
  bitarray_set(set->ba, BIT(d1));
  bitarray_set(set->ba, BIT(d2));
  bitarray_set(set->ba, BIT(d3));
  bitarray_set(set->ba, BIT(d4));
}

/** If <b>digest</b> is in <b>set</b>, return nonzero.  Otherwise,
 * <em>probably</em> return zero. */
static inline int
digestset_contains(const digestset_t *set, const char *digest)
{
  const uint64_t x = siphash24g(digest, 20);
  const uint32_t d1 = (uint32_t) x;
  const uint32_t d2 = (uint32_t)( (x>>16) + x);
  const uint32_t d3 = (uint32_t)( (x>>32) + x);
  const uint32_t d4 = (uint32_t)( (x>>48) + x);
  return bitarray_is_set(set->ba, BIT(d1)) &&
         bitarray_is_set(set->ba, BIT(d2)) &&
         bitarray_is_set(set->ba, BIT(d3)) &&
         bitarray_is_set(set->ba, BIT(d4));
}
#undef BIT

digestset_t *digestset_new(int max_elements);
void digestset_free_(digestset_t* set);
#define digestset_free(set) FREE_AND_NULL(digestset_t, digestset_free_, (set))

#endif /* !defined(TOR_CONTAINER_H) */
