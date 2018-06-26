/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file container.c
 * \brief Implements a smartlist (a resizable array) along
 * with helper functions to use smartlists.  Also includes
 * hash table implementations of a string-to-void* map, and of
 * a digest-to-void* map.
 **/

#include <stdlib.h>
#include "lib/malloc/util_malloc.h"
#include "lib/container/bloomfilt.h"
#include "lib/intmath/bits.h"

/** Return a newly allocated digestset_t, optimized to hold a total of
 * <b>max_elements</b> digests with a reasonably low false positive weight. */
digestset_t *
digestset_new(int max_elements)
{
  /* The probability of false positives is about P=(1 - exp(-kn/m))^k, where k
   * is the number of hash functions per entry, m is the bits in the array,
   * and n is the number of elements inserted.  For us, k==4, n<=max_elements,
   * and m==n_bits= approximately max_elements*32.  This gives
   *   P<(1-exp(-4*n/(32*n)))^4 == (1-exp(1/-8))^4 == .00019
   *
   * It would be more optimal in space vs false positives to get this false
   * positive rate by going for k==13, and m==18.5n, but we also want to
   * conserve CPU, and k==13 is pretty big.
   */
  int n_bits = 1u << (tor_log2(max_elements)+5);
  digestset_t *r = tor_malloc(sizeof(digestset_t));
  r->mask = n_bits - 1;
  r->ba = bitarray_init_zero(n_bits);
  return r;
}

/** Free all storage held in <b>set</b>. */
void
digestset_free_(digestset_t *set)
{
  if (!set)
    return;
  bitarray_free(set->ba);
  tor_free(set);
}
