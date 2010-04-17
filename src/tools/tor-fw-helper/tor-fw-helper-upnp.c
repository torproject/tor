/* Copyright (c) 2010, Jacob Appelbaum, Steven J. Murdoch.
 * Copyright (c) 2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "tor-fw-helper.h"
#include "tor-fw-helper-upnp.h"

#define UPNP_DISCOVER_TIMEOUT 2000
/* Description of the port mapping in the UPnP table */
#define UPNP_DESC "Tor relay"

#define UPNP_ERR_SUCCESS 0
#define UPNP_ERR_NODEVICESFOUND 1
#define UPNP_ERR_NOIGDFOUND 2
#define UPNP_ERR_ADDPORTMAPPING 3
#define UPNP_ERR_GETPORTMAPPING 4
#define UPNP_ERR_DELPORTMAPPING 5
#define UPNP_ERR_GETEXTERNALIP 6
#define UPNP_ERR_INVAL 7
#define UPNP_ERR_OTHER 8
#define UPNP_SUCCESS 1

int
tor_upnp_init(miniupnpc_state_t *state)
{
  struct UPNPDev *devlist;
  int r;

  memset(&(state->urls), 0, sizeof(struct UPNPUrls));
  memset(&(state->data), 0, sizeof(struct IGDdatas));

  devlist = upnpDiscover(UPNP_DISCOVER_TIMEOUT, NULL, NULL, 0);
  if (NULL == devlist) {
    fprintf(stderr, "E: upnpDiscover returned: NULL\n");
    return UPNP_ERR_NODEVICESFOUND;
  }

  r = UPNP_GetValidIGD(devlist, &(state->urls), &(state->data),
                       state->lanaddr, UPNP_LANADDR_SZ);
  fprintf(stdout, "tor-fw-helper: UPnP GetValidIGD returned: %d (%s)\n", r,
          r==UPNP_SUCCESS?"SUCCESS":"FAILED");

  freeUPNPDevlist(devlist);

  if (r != 1 && r != 2)
    return UPNP_ERR_NOIGDFOUND;

  state->init = 1;
  return UPNP_ERR_SUCCESS;
}

int
tor_upnp_cleanup(miniupnpc_state_t *state)
{
  if (state->init)
    FreeUPNPUrls(&(state->urls));
  state->init = 0;

  return UPNP_ERR_SUCCESS;
}

int
tor_upnp_fetch_public_ip(miniupnpc_state_t *state)
{
  int r;
  char externalIPAddress[16];

  if (!state->init) {
    r = tor_upnp_init(state);
    if (r != UPNP_ERR_SUCCESS)
      return r;
  }

  r = UPNP_GetExternalIPAddress(state->urls.controlURL,
                                state->data.first.servicetype,
                                externalIPAddress);

  if (r != UPNPCOMMAND_SUCCESS)
    goto err;

  if (externalIPAddress[0]) {
    fprintf(stdout, "tor-fw-helper: ExternalIPAddress = %s\n",
            externalIPAddress); tor_upnp_cleanup(state);
    return UPNP_ERR_SUCCESS;
  } else
    goto err;

  err:
    tor_upnp_cleanup(state);
    return UPNP_ERR_GETEXTERNALIP;
}

int
tor_upnp_add_tcp_mapping(miniupnpc_state_t *state,
    uint16_t internal_port, uint16_t external_port)
{
  int r;
  char internal_port_str[6];
  char external_port_str[6];

  if (!state->init) {
    r = tor_upnp_init(state);
    if (r != UPNP_ERR_SUCCESS)
      return r;
  }

  snprintf(internal_port_str, sizeof(internal_port_str),
           "%d", internal_port);
  snprintf(external_port_str, sizeof(external_port_str),
           "%d", external_port);

  r = UPNP_AddPortMapping(state->urls.controlURL,
                          state->data.first.servicetype,
                          external_port_str, internal_port_str,
                          state->lanaddr, UPNP_DESC, "TCP", 0);
  if (r != UPNPCOMMAND_SUCCESS)
    return UPNP_ERR_ADDPORTMAPPING;

  return UPNP_ERR_SUCCESS;
}

