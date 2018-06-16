/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file address_set.c
 * \brief Implementation for a set of addresses.
 *
 * This module was first written on a semi-emergency basis to improve the
 * robustness of the anti-DoS module.  As such, it's written in a pretty
 * conservative way, and should be susceptible to improvement later on.
 **/

#include "orconfig.h"
#include "address_set.h"
#include "address.h"
#include "compat.h"
#include "container.h"
#include "crypto_rand.h"
#include "util.h"
#include "siphash.h"

/** How many 64-bit siphash values to extract per address */
#define N_HASHES 2
/** How many bloom-filter bits we set per address. This is twice the N_HASHES
 * value, since we split the siphash output into two 32-bit values. */
#define N_BITS_PER_ITEM (N_HASHES * 2)

/* XXXX This code is largely duplicated with digestset_t.  We should merge
 * them together into a common bloom-filter implementation.  I'm keeping
 * them separate for now, though, since this module needs to be backported
 * all the way to 0.2.9.
 *
 * The main difference between digestset_t and this code is that we use
 * independent siphashes rather than messing around with bit-shifts.  The
 * approach here is probably more sound, and we should prefer it if&when we
 * unify the implementations.
 */

struct address_set_t {
  /** siphash keys to make N_HASHES independent hashes for each address. */
  struct sipkey key[N_HASHES];
  int mask; /**< One less than the number of bits in <b>ba</b>; always one less
             * than a power of two. */
  bitarray_t *ba; /**< A bit array to implement the Bloom filter. */
};

/**
 * Allocate and return an address_set, suitable for holding up to
 * <b>max_address_guess</b> distinct values.
 */
address_set_t *
address_set_new(int max_addresses_guess)
{
  /* See digestset_new() for rationale on this equation. */
  int n_bits = 1u << (tor_log2(max_addresses_guess)+5);

  address_set_t *set = tor_malloc_zero(sizeof(address_set_t));
  set->mask = n_bits - 1;
  set->ba = bitarray_init_zero(n_bits);
  crypto_rand((char*) set->key, sizeof(set->key));

  return set;
}

/**
 * Release all storage associated with <b>set</b>.
 */
void
address_set_free(address_set_t *set)
{
  if (! set)
    return;

  bitarray_free(set->ba);
  tor_free(set);
}

/** Yield the bit index corresponding to 'val' for set. */
#define BIT(set, val) ((val) & (set)->mask)

/**
 * Add <b>addr</b> to <b>set</b>.
 *
 * All future queries for <b>addr</b> in set will return true. Removing
 * items is not possible.
 */
void
address_set_add(address_set_t *set, const struct tor_addr_t *addr)
{
  int i;
  for (i = 0; i < N_HASHES; ++i) {
    uint64_t h = tor_addr_keyed_hash(&set->key[i], addr);
    uint32_t high_bits = (uint32_t)(h >> 32);
    uint32_t low_bits = (uint32_t)(h);
    bitarray_set(set->ba, BIT(set, high_bits));
    bitarray_set(set->ba, BIT(set, low_bits));
  }
}

/** As address_set_add(), but take an ipv4 address in host order. */
void
address_set_add_ipv4h(address_set_t *set, uint32_t addr)
{
  tor_addr_t a;
  tor_addr_from_ipv4h(&a, addr);
  address_set_add(set, &a);
}

/**
 * Return true if <b>addr</b> is a member of <b>set</b>.  (And probably,
 * return false if <b>addr</b> is not a member of set.)
 */
int
address_set_probably_contains(address_set_t *set,
                              const struct tor_addr_t *addr)
{
  int i, matches = 0;
  for (i = 0; i < N_HASHES; ++i) {
    uint64_t h = tor_addr_keyed_hash(&set->key[i], addr);
    uint32_t high_bits = (uint32_t)(h >> 32);
    uint32_t low_bits = (uint32_t)(h);
    // Note that !! is necessary here, since bitarray_is_set does not
    // necessarily return 1 on true.
    matches += !! bitarray_is_set(set->ba, BIT(set, high_bits));
    matches += !! bitarray_is_set(set->ba, BIT(set, low_bits));
  }
  return matches == N_BITS_PER_ITEM;
}

