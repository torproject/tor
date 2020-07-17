/* Copyright (c) 2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relay_find_addr.h
 * \brief Header file for relay_find_addr.c.
 **/

#ifndef TOR_RELAY_FIND_ADDR_H
#define TOR_RELAY_FIND_ADDR_H

void relay_address_new_suggestion(const tor_addr_t *suggested_addr,
                                  const tor_addr_t *peer_addr,
                                  const char *identity_digest);

MOCK_DECL(bool, relay_find_addr_to_publish,
          (const or_options_t *options, int family, bool cache_only,
           tor_addr_t *addr_out));

bool relay_has_address_set(int family);

#ifdef RELAY_FIND_ADDR_PRIVATE

#endif /* RELAY_FIND_ADDR_PRIVATE */

#endif /* TOR_RELAY_FIND_ADDR_H */

