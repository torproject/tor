/* Copyright (c) 2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file resolve_addr.h
 * \brief Header file for resolve_addr.c.
 **/

#ifndef TOR_CONFIG_RESOLVE_ADDR_H
#define TOR_CONFIG_RESOLVE_ADDR_H

#include "app/config/or_options_st.h"

int resolve_my_address(int warn_severity, const or_options_t *options,
                       uint32_t *addr_out,
                       const char **method_out, char **hostname_out);

uint32_t get_last_resolved_addr(void);
void reset_last_resolved_addr(void);

MOCK_DECL(int, is_local_addr, (const tor_addr_t *addr));

#ifdef RESOLVE_ADDR_PRIVATE

#endif /* RESOLVE_ADDR_PRIVATE */

#endif /* TOR_CONFIG_RESOLVE_ADDR_H */

