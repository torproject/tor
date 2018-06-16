/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file address_set.h
 * \brief Types to handle sets of addresses.
 *
 * This module was first written on a semi-emergency basis to improve the
 * robustness of the anti-DoS module.  As such, it's written in a pretty
 * conservative way, and should be susceptible to improvement later on.
 **/

#ifndef TOR_ADDRESS_SET_H
#define TOR_ADDRESS_SET_H

#include "orconfig.h"
#include "torint.h"

/**
 * An address_set_t represents a set of tor_addr_t values. The implementation
 * is probabilistic: false negatives cannot occur but false positives are
 * possible.
 */
typedef struct address_set_t address_set_t;
struct tor_addr_t;

address_set_t *address_set_new(int max_addresses_guess);
void address_set_free(address_set_t *set);
void address_set_add(address_set_t *set, const struct tor_addr_t *addr);
void address_set_add_ipv4h(address_set_t *set, uint32_t addr);
int address_set_probably_contains(address_set_t *set,
                                  const struct tor_addr_t *addr);

#endif

