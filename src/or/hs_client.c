/* Copyright (c) 2016-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_service.c
 * \brief Implement next generation hidden service client functionality
 **/

#include "or.h"
#include "hs_circuit.h"
#include "hs_ident.h"
#include "connection_edge.h"
#include "rendclient.h"

#include "hs_client.h"

/** A prop224 v3 HS circuit successfully connected to the hidden
 *  service. Update the stream state at <b>hs_conn_ident</b> appropriately. */
static void
hs_client_attempt_succeeded(const hs_ident_edge_conn_t *hs_conn_ident)
{
  (void) hs_conn_ident;

  /* TODO: When implementing client side */
  return;
}

/** A circuit just finished connecting to a hidden service that the stream
 *  <b>conn</b> has been waiting for. Let the HS subsystem know about this. */
void
hs_client_note_connection_attempt_succeeded(const edge_connection_t *conn)
{
  tor_assert(connection_edge_is_rendezvous_stream(conn));

  if (BUG(conn->rend_data && conn->hs_ident)) {
    log_warn(LD_BUG, "Stream had both rend_data and hs_ident..."
             "Prioritizing hs_ident");
  }

  if (conn->hs_ident) { /* It's v3: pass it to the prop224 handler */
    hs_client_attempt_succeeded(conn->hs_ident);
    return;
  } else if (conn->rend_data) { /* It's v2: pass it to the legacy handler */
    rend_client_note_connection_attempt_ended(conn->rend_data);
    return;
  }
}

/* With the given encoded descriptor in desc_str and the service key in
 * service_identity_pk, decode the descriptor and set the desc pointer with a
 * newly allocated descriptor object.
 *
 * Return 0 on success else a negative value and desc is set to NULL. */
int
hs_client_decode_descriptor(const char *desc_str,
                            const ed25519_public_key_t *service_identity_pk,
                            hs_descriptor_t **desc)
{
  int ret;
  uint8_t subcredential[DIGEST256_LEN];

  tor_assert(desc_str);
  tor_assert(service_identity_pk);
  tor_assert(desc);

  /* Create subcredential for this HS so that we can decrypt */
  {
    ed25519_public_key_t blinded_pubkey;
    uint64_t current_time_period = hs_get_time_period_num(approx_time());
    hs_build_blinded_pubkey(service_identity_pk, NULL, 0, current_time_period,
                            &blinded_pubkey);
    hs_get_subcredential(service_identity_pk, &blinded_pubkey, subcredential);
  }

  /* Parse descriptor */
  ret = hs_desc_decode_descriptor(desc_str, subcredential, desc);
  memwipe(subcredential, 0, sizeof(subcredential));
  if (ret < 0) {
    log_warn(LD_GENERAL, "Could not parse received descriptor as client");
    goto err;
  }

  return 0;
 err:
  return -1;
}

