/* Copyright (c) 2010, Jacob Appelbaum, Steven J. Murdoch.
 * Copyright (c) 2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef _TOR_FW_HELPER_NATPMP_H
#define _TOR_FW_HELPER_NATPMP_H

#include <natpmp.h>

#define NATPMP_DEFAULT_LEASE 3600
#define NATPMP_SUCCESS 0

int tor_natpmp_add_tcp_mapping(tor_fw_options_t *tor_fw_options);

int tor_natpmp_fetch_public_ip(tor_fw_options_t *tor_fw_options);

#endif

