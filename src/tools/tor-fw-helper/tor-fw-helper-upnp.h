/* Copyright (c) 2010, Jacob Appelbaum, Steven J. Murdoch.
 * Copyright (c) 2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef _TOR_FW_HELPER_UPNP_H
#define _TOR_FW_HELPER_UPNP_H

#include <miniupnpc/miniwget.h>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>

#define UPNP_LANADDR_SZ 64

typedef struct miniupnpc_state_t {
  struct UPNPUrls urls;
  struct IGDdatas data;
  char lanaddr[UPNP_LANADDR_SZ];
  int init;
} miniupnpc_state_t;

int tor_upnp_init(miniupnpc_state_t *state);

int tor_upnp_cleanup(miniupnpc_state_t *state);

int tor_upnp_fetch_public_ip(miniupnpc_state_t *state);

int tor_upnp_add_tcp_mapping(miniupnpc_state_t *state,
    uint16_t internal_port, uint16_t external_port);

#endif

