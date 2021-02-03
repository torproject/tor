/* Copyright (c) 2018-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file address_set.h
 * \brief Types to handle sets of addresses.
 **/

#ifndef TOR_ADDRESS_SET_H
#define TOR_ADDRESS_SET_H

#include "orconfig.h"
#include "lib/cc/torint.h"
#include "lib/container/bloomfilt.h"

struct tor_addr_t;

/**
 * An address_set_t represents a set of tor_addr_t values. The implementation
 * is probabilistic: false negatives cannot occur but false positives are
 * possible.
 */
typedef struct bloomfilt_t address_set_t;

address_set_t *address_set_new(int max_addresses_guess);
#define address_set_free(set) bloomfilt_free(set)
void address_set_add(address_set_t *set, const struct tor_addr_t *addr);
void address_set_add_ipv4h(address_set_t *set, uint32_t addr);
int address_set_probably_contains(const address_set_t *set,
                                  const struct tor_addr_t *addr);

/**
 * An addr_port_set_t represents a set of tor_addr_t values with a uint16_t
 * port value. The implementation is probabilistic: false negatives cannot
 * occur but false positives are possible.
 */
typedef struct bloomfilt_t addr_port_set_t;

addr_port_set_t *addr_port_set_new(int max_addresses_guess);
#define addr_port_set_free(s) bloomfilt_free(s)
void addr_port_set_add(addr_port_set_t *set,
                       const struct tor_addr_t *addr, uint16_t port);
bool addr_port_set_probably_contains(const addr_port_set_t *set,
                                     const struct tor_addr_t *addr,
                                     uint16_t port);

#endif /* !defined(TOR_ADDRESS_SET_H) */
