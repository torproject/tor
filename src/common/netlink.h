/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file netlink.h
 * \brief Headers for netlink.h
 **/

#ifndef TOR_NETLINK_H
#define TOR_NETLINK_H

#include "orconfig.h"
#include "address.h"

MOCK_DECL(int, get_interface_address_netlink, (int severity,
                                               sa_family_t family,
                                               tor_addr_t *addr));

#endif /* TOR_NETLINK_H */

