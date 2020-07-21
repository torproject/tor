/* Copyright (c) 2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file resolve_addr.h
 * \brief Header file for resolve_addr.c.
 **/

#ifndef TOR_CONFIG_RESOLVE_ADDR_H
#define TOR_CONFIG_RESOLVE_ADDR_H

#include "app/config/config.h"
#include "core/mainloop/connection.h"

#include "app/config/or_options_st.h"

#define get_orport_addr(family) \
  (portconf_get_first_advertised_addr(CONN_TYPE_OR_LISTENER, family))

bool find_my_address(const or_options_t *options, int family,
                     int warn_severity, tor_addr_t *addr_out,
                     const char **method_out, char **hostname_out);

void resolved_addr_get_last(int family, tor_addr_t *addr_out);
void resolved_addr_reset_last(int family);
void resolved_addr_set_last(const tor_addr_t *addr, const char *method_used,
                            const char *hostname_used);

void resolved_addr_get_suggested(int family, tor_addr_t *addr_out);
void resolved_addr_set_suggested(const tor_addr_t *addr);

MOCK_DECL(bool, is_local_to_resolve_addr, (const tor_addr_t *addr));

#ifdef RESOLVE_ADDR_PRIVATE

#ifdef TOR_UNIT_TESTS

void resolve_addr_reset_suggested(int family);

#endif /* TOR_UNIT_TESTS */

#endif /* RESOLVE_ADDR_PRIVATE */

#endif /* TOR_CONFIG_RESOLVE_ADDR_H */

