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
#include "container.h"
#include "rendclient.h"
#include "hs_descriptor.h"
#include "hs_cache.h"
#include "hs_cell.h"
#include "hs_ident.h"
#include "config.h"
#include "directory.h"
#include "hs_client.h"
#include "router.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "connection.h"
#include "circpathbias.h"

/* Get all connections that are waiting on a circuit and flag them back to
 * waiting for a hidden service descriptor for the given service key
 * service_identity_pk. */
static void
flag_all_conn_wait_desc(const ed25519_public_key_t *service_identity_pk)
{
  tor_assert(service_identity_pk);

  smartlist_t *conns =
    connection_list_by_type_state(CONN_TYPE_AP, AP_CONN_STATE_CIRCUIT_WAIT);

  SMARTLIST_FOREACH_BEGIN(conns, connection_t *, conn) {
    edge_connection_t *edge_conn;
    if (BUG(!CONN_IS_EDGE(conn))) {
      continue;
    }
    edge_conn = TO_EDGE_CONN(conn);
    if (edge_conn->hs_ident &&
        ed25519_pubkey_eq(&edge_conn->hs_ident->identity_pk,
                          service_identity_pk)) {
      connection_ap_mark_as_non_pending_circuit(TO_ENTRY_CONN(conn));
      conn->state = AP_CONN_STATE_RENDDESC_WAIT;
    }
  } SMARTLIST_FOREACH_END(conn);

  smartlist_free(conns);
}

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

/* Make sure that the given origin circuit circ is a valid correct
 * introduction circuit. This asserts on validation failure. */
static void
assert_intro_circ_ok(const origin_circuit_t *circ)
{
  tor_assert(circ);
  tor_assert(circ->base_.purpose == CIRCUIT_PURPOSE_C_INTRODUCING);
  tor_assert(circ->hs_ident);
  tor_assert(hs_ident_intro_circ_is_valid(circ->hs_ident));
  assert_circ_anonymity_ok(circ, get_options());
}

/* Find a descriptor intro point object that matches the given ident in the
 * given descriptor desc. Return NULL if not found. */
static const hs_desc_intro_point_t *
find_desc_intro_point_by_ident(const hs_ident_circuit_t *ident,
                               const hs_descriptor_t *desc)
{
  const hs_desc_intro_point_t *intro_point = NULL;

  tor_assert(ident);
  tor_assert(desc);

  SMARTLIST_FOREACH_BEGIN(desc->encrypted_data.intro_points,
                          const hs_desc_intro_point_t *, ip) {
    if (ed25519_pubkey_eq(&ident->intro_auth_pk,
                          &ip->auth_key_cert->signed_key)) {
      intro_point = ip;
      break;
    }
  } SMARTLIST_FOREACH_END(ip);

  return intro_point;
}

/* Send an INTRODUCE1 cell along the intro circuit and populate the rend
 * circuit identifier with the needed key material for the e2e encryption.
 * Return 0 on success, -1 if there is a transient error such that an action
 * has been taken to recover and -2 if there is a permanent error indicating
 * that both circuits were closed. */
static int
send_introduce1(origin_circuit_t *intro_circ,
                origin_circuit_t *rend_circ)
{
  int status;
  char onion_address[HS_SERVICE_ADDR_LEN_BASE32 + 1];
  const ed25519_public_key_t *service_identity_pk = NULL;
  const hs_desc_intro_point_t *ip;

  assert_intro_circ_ok(intro_circ);
  tor_assert(rend_circ);

  service_identity_pk = &intro_circ->hs_ident->identity_pk;
  /* For logging purposes. There will be a time where the hs_ident will have a
   * version number but for now there is none because it's all v3. */
  hs_build_address(service_identity_pk, HS_VERSION_THREE, onion_address);

  log_info(LD_REND, "Sending INTRODUCE1 cell to service %s on circuit %u",
           safe_str_client(onion_address), TO_CIRCUIT(intro_circ)->n_circ_id);

  /* 1) Get descriptor from our cache. */
  const hs_descriptor_t *desc =
    hs_cache_lookup_as_client(service_identity_pk);
  if (desc == NULL || !hs_client_any_intro_points_usable(desc)) {
    log_info(LD_REND, "Request to %s %s. Trying to fetch a new descriptor.",
             safe_str_client(onion_address),
             (desc) ? "didn't have usable intro points" :
             "didn't have a descriptor");
    hs_client_refetch_hsdesc(service_identity_pk);
    /* We just triggered a refetch, make sure every connections are back
     * waiting for that descriptor. */
    flag_all_conn_wait_desc(service_identity_pk);
    /* We just asked for a refetch so this is a transient error. */
    goto tran_err;
  }

  /* We need to find which intro point in the descriptor we are connected to
   * on intro_circ. */
  ip = find_desc_intro_point_by_ident(intro_circ->hs_ident, desc);
  if (BUG(ip == NULL)) {
    /* If we can find a descriptor from this introduction circuit ident, we
     * must have a valid intro point object. Permanent error. */
    goto perm_err;
  }

  /* Send the INTRODUCE1 cell. */
  if (hs_circ_send_introduce1(intro_circ, rend_circ, ip,
                              desc->subcredential) < 0) {
    /* Unable to send the cell, the intro circuit has been marked for close so
     * this is a permanent error. */
    tor_assert_nonfatal(TO_CIRCUIT(intro_circ)->marked_for_close);
    goto perm_err;
  }

  /* Cell has been sent successfully. Copy the introduction point
   * authentication and encryption key in the rendezvous circuit identifier so
   * we can compute the ntor keys when we receive the RENDEZVOUS2 cell. */
  memcpy(&rend_circ->hs_ident->intro_enc_pk, &ip->enc_key,
         sizeof(rend_circ->hs_ident->intro_enc_pk));
  ed25519_pubkey_copy(&rend_circ->hs_ident->intro_auth_pk,
                      &intro_circ->hs_ident->intro_auth_pk);

  /* Now, we wait for an ACK or NAK on this circuit. */
  circuit_change_purpose(TO_CIRCUIT(intro_circ),
                         CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT);
  /* Set timestamp_dirty, because circuit_expire_building expects it to
   * specify when a circuit entered the _C_INTRODUCE_ACK_WAIT state. */
  TO_CIRCUIT(intro_circ)->timestamp_dirty = time(NULL);
  pathbias_count_use_attempt(intro_circ);

  /* Success. */
  status = 0;
  goto end;

 perm_err:
  /* Permanent error: it is possible that the intro circuit was closed prior
   * because we weren't able to send the cell. Make sure we don't double close
   * it which would result in a warning. */
  if (!TO_CIRCUIT(intro_circ)->marked_for_close) {
    circuit_mark_for_close(TO_CIRCUIT(intro_circ), END_CIRC_REASON_INTERNAL);
  }
  circuit_mark_for_close(TO_CIRCUIT(rend_circ), END_CIRC_REASON_INTERNAL);
  status = -2;
  goto end;

 tran_err:
  status = -1;

 end:
  memwipe(onion_address, 0, sizeof(onion_address));
  return status;
}

/* ========== */
/* Public API */
/* ========== */

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

/* This is called when we are trying to attach an AP connection to these
 * hidden service circuits from connection_ap_handshake_attach_circuit().
 * Return 0 on success, -1 for a transient error that is actions were
 * triggered to recover or -2 for a permenent error where both circuits will
 * marked for close.
 *
 * The following supports every hidden service version. */
int
hs_client_send_introduce1(origin_circuit_t *intro_circ,
                          origin_circuit_t *rend_circ)
{
  return (intro_circ->hs_ident) ? send_introduce1(intro_circ, rend_circ) :
                                  rend_client_send_introduction(intro_circ,
                                                                rend_circ);
}

