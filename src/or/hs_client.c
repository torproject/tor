/* Copyright (c) 2016-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_client.c
 * \brief Implement next generation hidden service client functionality
 **/

#include "or.h"
#include "hs_circuit.h"
#include "hs_ident.h"
#include "connection_edge.h"
#include "rendclient.h"
#include "hs_descriptor.h"
#include "hs_cache.h"
#include "config.h"
#include "directory.h"
#include "hs_client.h"
#include "router.h"

/* A v3 HS circuit successfully connected to the hidden service. Update the
 * stream state at <b>hs_conn_ident</b> appropriately. */
static void
note_connection_attempt_succeeded(const hs_ident_edge_conn_t *hs_conn_ident)
{
  (void) hs_conn_ident;

  /* TODO: When implementing client side */
  return;
}

/* Given the pubkey of a hidden service in <b>onion_identity_pk</b>, fetch its
 * descriptor by launching a dir connection to <b>hsdir</b>. Return 1 on
 * success or -1 on error. */
static int
directory_launch_v3_desc_fetch(const ed25519_public_key_t *onion_identity_pk,
                               const routerstatus_t *hsdir)
{
  uint64_t current_time_period = hs_get_time_period_num(approx_time());
  ed25519_public_key_t blinded_pubkey;
  char base64_blinded_pubkey[ED25519_BASE64_LEN + 1];
  hs_ident_dir_conn_t hs_conn_dir_ident;
  int retval;

  tor_assert(hsdir);
  tor_assert(onion_identity_pk);

  /* Get blinded pubkey */
  hs_build_blinded_pubkey(onion_identity_pk, NULL, 0,
                          current_time_period, &blinded_pubkey);
  /* ...and base64 it. */
  retval = ed25519_public_to_base64(base64_blinded_pubkey, &blinded_pubkey);
  if (BUG(retval < 0)) {
    return -1;
  }

  /* Copy onion pk to a dir_ident so that we attach it to the dir conn */
  ed25519_pubkey_copy(&hs_conn_dir_ident.identity_pk, onion_identity_pk);

  /* Setup directory request */
  directory_request_t *req =
    directory_request_new(DIR_PURPOSE_FETCH_HSDESC);
  directory_request_set_routerstatus(req, hsdir);
  directory_request_set_indirection(req, DIRIND_ANONYMOUS);
  directory_request_set_resource(req, base64_blinded_pubkey);
  directory_request_upload_set_hs_ident(req, &hs_conn_dir_ident);
  directory_initiate_request(req);
  directory_request_free(req);

  log_info(LD_REND, "Descriptor fetch request for service %s with blinded "
                    "key %s to directory %s",
           safe_str_client(ed25519_fmt(onion_identity_pk)),
           safe_str_client(base64_blinded_pubkey),
           safe_str_client(routerstatus_describe(hsdir)));

  /* Cleanup memory. */
  memwipe(&blinded_pubkey, 0, sizeof(blinded_pubkey));
  memwipe(base64_blinded_pubkey, 0, sizeof(base64_blinded_pubkey));
  memwipe(&hs_conn_dir_ident, 0, sizeof(hs_conn_dir_ident));

  return 1;
}

/** Return the HSDir we should use to fetch the descriptor of the hidden
 *  service with identity key <b>onion_identity_pk</b>. */
static routerstatus_t *
pick_hsdir_v3(const ed25519_public_key_t *onion_identity_pk)
{
  int retval;
  char base64_blinded_pubkey[ED25519_BASE64_LEN + 1];
  uint64_t current_time_period = hs_get_time_period_num(approx_time());
  smartlist_t *responsible_hsdirs;
  ed25519_public_key_t blinded_pubkey;
  routerstatus_t *hsdir_rs = NULL;

  tor_assert(onion_identity_pk);

  responsible_hsdirs = smartlist_new();

  /* Get blinded pubkey of hidden service */
  hs_build_blinded_pubkey(onion_identity_pk, NULL, 0,
                          current_time_period, &blinded_pubkey);
  /* ...and base64 it. */
  retval = ed25519_public_to_base64(base64_blinded_pubkey, &blinded_pubkey);
  if (BUG(retval < 0)) {
    return NULL;
  }

  /* Get responsible hsdirs of service for this time period */
  hs_get_responsible_hsdirs(&blinded_pubkey, current_time_period, 0, 1,
                            responsible_hsdirs);

  log_debug(LD_REND, "Found %d responsible HSDirs and about to pick one.",
           smartlist_len(responsible_hsdirs));

  /* Pick an HSDir from the responsible ones. The ownership of
   * responsible_hsdirs is given to this function so no need to free it. */
  hsdir_rs = hs_pick_hsdir(responsible_hsdirs, base64_blinded_pubkey);

  return hsdir_rs;
}

/** Fetch a v3 descriptor using the given <b>onion_identity_pk</b>.
 *
 * On success, 1 is returned. If no hidden service is left to ask, return 0.
 * On error, -1 is returned. */
static int
fetch_v3_desc(const ed25519_public_key_t *onion_identity_pk)
{
  routerstatus_t *hsdir_rs =NULL;

  tor_assert(onion_identity_pk);

  hsdir_rs = pick_hsdir_v3(onion_identity_pk);
  if (!hsdir_rs) {
    log_info(LD_REND, "Couldn't pick a v3 hsdir.");
    return 0;
  }

  return directory_launch_v3_desc_fetch(onion_identity_pk, hsdir_rs);
}

#if 0
/* Make sure that the given origin circuit circ is a valid correct
 * introduction circuit. This asserts on validation failure. */
static void
assert_intro_circ(const origin_circuit_t *circ)
{
  tor_assert(circ);
  tor_assert(circ->base_.purpose == CIRCUIT_PURPOSE_C_INTRODUCING);
  tor_assert(circ->hs_ident);
  tor_assert(hs_ident_intro_circ_is_valid(circ->hs_ident));
  assert_circ_anonymity_ok(circ, get_options());
}
#endif

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
    note_connection_attempt_succeeded(conn->hs_ident);
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

/** Return true if there are any usable intro points in the v3 HS descriptor
 *  <b>desc</b>. */
int
hs_client_any_intro_points_usable(const hs_descriptor_t *desc)
{
  /* XXX stub waiting for more client-side work:
     equivalent to v2 rend_client_any_intro_points_usable() */
  tor_assert(desc);
  return 1;
}

/** Launch a connection to a hidden service directory to fetch a hidden
 * service descriptor using <b>identity_pk</b> to get the necessary keys.
 *
 * On success, 1 is returned. If no hidden service is left to ask, return 0.
 * On error, -1 is returned. (retval is only used by unittests right now) */
int
hs_client_refetch_hsdesc(const ed25519_public_key_t *identity_pk)
{
  tor_assert(identity_pk);

  /* Are we configured to fetch descriptors? */
  if (!get_options()->FetchHidServDescriptors) {
    log_warn(LD_REND, "We received an onion address for a hidden service "
                      "descriptor but we are configured to not fetch.");
    return 0;
  }

  /* Check if fetching a desc for this HS is useful to us right now */
  {
    const hs_descriptor_t *cached_desc = NULL;
    cached_desc = hs_cache_lookup_as_client(identity_pk);
    if (cached_desc && hs_client_any_intro_points_usable(cached_desc)) {
      log_warn(LD_GENERAL, "We would fetch a v3 hidden service descriptor "
                            "but we already have a useable descriprot.");
      return 0;
    }
  }

  return fetch_v3_desc(identity_pk);
}

