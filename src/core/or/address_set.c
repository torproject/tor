/* Copyright (c) 2018-2020, The Tor Project, Inc. */
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
#include "core/or/address_set.h"
#include "lib/net/address.h"
#include "lib/container/bloomfilt.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "siphash.h"

/** Wrap our hash function to have the signature that the bloom filter
 * needs. */
static uint64_t
bloomfilt_addr_hash(const struct sipkey *key,
                    const void *item)
{
  return tor_addr_keyed_hash(key, item);
}

/**
 * Allocate and return an address_set, suitable for holding up to
 * <b>max_address_guess</b> distinct values.
 */
address_set_t *
address_set_new(int max_addresses_guess)
{
  uint8_t k[BLOOMFILT_KEY_LEN];
  crypto_rand((void*)k, sizeof(k));
  return bloomfilt_new(max_addresses_guess, bloomfilt_addr_hash, k);
}

/**
 * Add <b>addr</b> to <b>set</b>.
 *
 * All future queries for <b>addr</b> in set will return true. Removing
 * items is not possible.
 */
void
address_set_add(address_set_t *set, const struct tor_addr_t *addr)
{
  bloomfilt_add(set, addr);
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
address_set_probably_contains(const address_set_t *set,
                              const struct tor_addr_t *addr)
{
  return bloomfilt_probably_contains(set, addr);
}

/* Length of the item is an address (IPv4 or IPv6) and a 2 byte port. We use
 * 16 bytes for the address here (IPv6) since we do not know which family
 * the given address in the item thus in the case of IPv4, the extra bytes
 * are simply zeroes to accomodate. */
#define BLOOMFILT_ADDR_PORT_ITEM_LEN (16 + sizeof(uint16_t))

/** Build an item for the bloomfilter consisting of an address and port pair.
 *
 * If the given address is _not_ AF_INET or AF_INET6, then the item is an
 * array of 0s.
 *
 * Return a pointer to a static buffer containing the item. Next call to this
 * function invalidates its previous content. */
static const uint8_t *
build_addr_port_item(const tor_addr_t *addr, const uint16_t port)
{
  static uint8_t data[BLOOMFILT_ADDR_PORT_ITEM_LEN];

  memset(data, 0, sizeof(data));
  switch (tor_addr_family(addr)) {
  case AF_INET:
    memcpy(data, &addr->addr.in_addr.s_addr, 4);
    break;
  case AF_INET6:
    memcpy(data, &addr->addr.in6_addr.s6_addr, 16);
    break;
  case AF_UNSPEC:
    /* Leave the 0. */
    break;
  default:
    /* LCOV_EXCL_START */
    tor_fragile_assert();
    /* LCOV_EXCL_STOP */
  }

  memcpy(data + 16, &port, sizeof(port));
  return data;
}

/** Return a hash value for the given item that the bloomfilter will use. */
static uint64_t
bloomfilt_addr_port_hash(const struct sipkey *key,
                         const void *item)
{
  return siphash24(item, BLOOMFILT_ADDR_PORT_ITEM_LEN, key);
}

/** Allocate and return an addr_port_set_t, suitable for holding up to
 * max_address_guess distinct values. */
addr_port_set_t *
addr_port_set_new(int max_addresses_guess)
{
  uint8_t k[BLOOMFILT_KEY_LEN];
  crypto_rand((void*)k, sizeof(k));
  return bloomfilt_new(max_addresses_guess, bloomfilt_addr_port_hash, k);
}

/** Add an address and port pair to the given set. */
void
addr_port_set_add(addr_port_set_t *set, const tor_addr_t *addr, uint16_t port)
{
  bloomfilt_add(set, build_addr_port_item(addr, port));
}

/** Return true if the given address and port pair are in the set. Of course,
 * this is a bloomfilter and thus in rare occasion, a false positive happens
 * thus the "probably". */
bool
addr_port_set_probably_contains(const addr_port_set_t *set,
                                const tor_addr_t *addr, uint16_t port)
{
  return !!bloomfilt_probably_contains(set, build_addr_port_item(addr, port));
}
