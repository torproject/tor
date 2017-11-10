/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_control.c
 * \brief Contains control port event related code.
 **/

#include "or.h"
#include "control.h"
#include "hs_common.h"
#include "hs_control.h"
#include "nodelist.h"

/* Send on the control port the "HS_DESC REQUESTED [...]" event.
 *
 * The onion_pk is the onion service public key, base64_blinded_pk is the
 * base64 encoded blinded key for the service and hsdir_rs is the routerstatus
 * object of the HSDir that this request is for. */
void
hs_control_desc_event_requested(const ed25519_public_key_t *onion_pk,
                                const char *base64_blinded_pk,
                                const routerstatus_t *hsdir_rs)
{
  char onion_address[HS_SERVICE_ADDR_LEN_BASE32 + 1];
  const uint8_t *hsdir_index;
  const node_t *hsdir_node;

  tor_assert(onion_pk);
  tor_assert(base64_blinded_pk);
  tor_assert(hsdir_rs);

  hs_build_address(onion_pk, HS_VERSION_THREE, onion_address);

  /* Get the node from the routerstatus object to get the HSDir index used for
   * this request. We can't have a routerstatus entry without a node and we
   * can't pick a node without an hsdir_index. */
  hsdir_node = node_get_by_id(hsdir_rs->identity_digest);
  tor_assert(hsdir_node);
  tor_assert(hsdir_node->hsdir_index);
  /* This is a fetch event. */
  hsdir_index = hsdir_node->hsdir_index->fetch;

  /* Trigger the event. */
  control_event_hs_descriptor_requested(onion_address, REND_NO_AUTH,
                                        hsdir_rs->identity_digest,
                                        base64_blinded_pk,
                                        hex_str((const char *) hsdir_index,
                                                DIGEST256_LEN));
  memwipe(onion_address, 0, sizeof(onion_address));
}

