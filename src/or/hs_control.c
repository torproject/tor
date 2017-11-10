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

/* Send on the control port the "HS_DESC FAILED [...]" event.
 *
 * Using a directory connection identifier, the HSDir identity digest and a
 * reason for the failure. None can be NULL. */
void
hs_control_desc_event_failed(const hs_ident_dir_conn_t *ident,
                             const char *hsdir_id_digest,
                             const char *reason)
{
  char onion_address[HS_SERVICE_ADDR_LEN_BASE32 + 1];
  char base64_blinded_pk[ED25519_BASE64_LEN + 1];

  tor_assert(ident);
  tor_assert(hsdir_id_digest);
  tor_assert(reason);

  /* Build onion address and encoded blinded key. */
  IF_BUG_ONCE(ed25519_public_to_base64(base64_blinded_pk,
                                       &ident->blinded_pk) < 0) {
    return;
  }
  hs_build_address(&ident->identity_pk, HS_VERSION_THREE, onion_address);

  control_event_hsv3_descriptor_failed(onion_address, base64_blinded_pk,
                                       hsdir_id_digest, reason);
}

/* Send on the control port the "HS_DESC RECEIVED [...]" event.
 *
 * Using a directory connection identifier and the HSDir identity digest.
 * None can be NULL. */
void
hs_control_desc_event_received(const hs_ident_dir_conn_t *ident,
                               const char *hsdir_id_digest)
{
  char onion_address[HS_SERVICE_ADDR_LEN_BASE32 + 1];
  char base64_blinded_pk[ED25519_BASE64_LEN + 1];

  tor_assert(ident);
  tor_assert(hsdir_id_digest);

  /* Build onion address and encoded blinded key. */
  IF_BUG_ONCE(ed25519_public_to_base64(base64_blinded_pk,
                                       &ident->blinded_pk) < 0) {
    return;
  }
  hs_build_address(&ident->identity_pk, HS_VERSION_THREE, onion_address);

  control_event_hsv3_descriptor_received(onion_address, base64_blinded_pk,
                                         hsdir_id_digest);
}

/* Send on the control port the "HS_DESC CREATED [...]" event.
 *
 * Using the onion address of the descriptor's service and the blinded public
 * key of the descriptor as a descriptor ID. None can be NULL. */
void
hs_control_desc_event_created(const char *onion_address,
                              const ed25519_public_key_t *blinded_pk)
{
  char base64_blinded_pk[ED25519_BASE64_LEN + 1];

  tor_assert(onion_address);
  tor_assert(blinded_pk);

  /* Build base64 encoded blinded key. */
  IF_BUG_ONCE(ed25519_public_to_base64(base64_blinded_pk, blinded_pk) < 0) {
    return;
  }

  /* Version 3 doesn't use the replica number in its descriptor ID computation
   * so we pass negative value so the control port subsystem can ignore it. */
  control_event_hs_descriptor_created(onion_address, base64_blinded_pk, -1);
}

/* Send on the control port the "HS_DESC UPLOAD [...]" event.
 *
 * Using the onion address of the descriptor's service, the HSDir identity
 * digest, the blinded public key of the descriptor as a descriptor ID and the
 * HSDir index for this particular request. None can be NULL. */
void
hs_control_desc_event_upload(const char *onion_address,
                             const char *hsdir_id_digest,
                             const ed25519_public_key_t *blinded_pk,
                             const uint8_t *hsdir_index)
{
  char base64_blinded_pk[ED25519_BASE64_LEN + 1];

  tor_assert(onion_address);
  tor_assert(hsdir_id_digest);
  tor_assert(blinded_pk);
  tor_assert(hsdir_index);

  /* Build base64 encoded blinded key. */
  IF_BUG_ONCE(ed25519_public_to_base64(base64_blinded_pk, blinded_pk) < 0) {
    return;
  }

  control_event_hs_descriptor_upload(onion_address, hsdir_id_digest,
                                     base64_blinded_pk,
                                     hex_str((const char *) hsdir_index,
                                             DIGEST256_LEN));
}

