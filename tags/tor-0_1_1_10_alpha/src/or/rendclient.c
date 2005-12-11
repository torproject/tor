/* Copyright 2004-2005 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char rendclient_c_id[] = "$Id$";

/**
 * \file rendclient.c
 * \brief Client code to access location-hidden services.
 **/

#include "or.h"

/** Called when we've established a circuit to an introduction point:
 * send the introduction request. */
void
rend_client_introcirc_has_opened(circuit_t *circ)
{
  tor_assert(circ->purpose == CIRCUIT_PURPOSE_C_INTRODUCING);
  tor_assert(CIRCUIT_IS_ORIGIN(circ));
  tor_assert(circ->cpath);

  info(LD_REND,"introcirc is open");
  connection_ap_attach_pending();
}

/** Send the establish-rendezvous cell along a rendezvous circuit. if
 * it fails, mark the circ for close and return -1. else return 0.
 */
static int
rend_client_send_establish_rendezvous(circuit_t *circ)
{
  tor_assert(circ->purpose == CIRCUIT_PURPOSE_C_ESTABLISH_REND);
  info(LD_REND, "Sending an ESTABLISH_RENDEZVOUS cell");

  if (crypto_rand(circ->rend_cookie, REND_COOKIE_LEN) < 0) {
    warn(LD_BUG, "Internal error: Couldn't produce random cookie.");
    circuit_mark_for_close(circ);
    return -1;
  }
  if (connection_edge_send_command(NULL,circ,
                                   RELAY_COMMAND_ESTABLISH_RENDEZVOUS,
                                   circ->rend_cookie, REND_COOKIE_LEN,
                                   circ->cpath->prev)<0) {
    /* circ is already marked for close */
    warn(LD_GENERAL, "Couldn't send ESTABLISH_RENDEZVOUS cell");
    return -1;
  }

  return 0;
}

/** Called when we're trying to connect an ap conn; sends an INTRODUCE1 cell
 * down introcirc if possible.
 */
int
rend_client_send_introduction(circuit_t *introcirc, circuit_t *rendcirc)
{
  size_t payload_len;
  int r;
  char payload[RELAY_PAYLOAD_SIZE];
  char tmp[RELAY_PAYLOAD_SIZE];
  rend_cache_entry_t *entry;
  crypt_path_t *cpath;
  off_t dh_offset;

  tor_assert(introcirc->purpose == CIRCUIT_PURPOSE_C_INTRODUCING);
  tor_assert(rendcirc->purpose == CIRCUIT_PURPOSE_C_REND_READY);
  tor_assert(!rend_cmp_service_ids(introcirc->rend_query, rendcirc->rend_query));

  if (rend_cache_lookup_entry(introcirc->rend_query, -1, &entry) < 1) {
    warn(LD_REND,"query '%s' didn't have valid rend desc in cache. Failing.",
         safe_str(introcirc->rend_query));
    goto err;
  }

  /* first 20 bytes of payload are the hash of bob's pk */
  if (crypto_pk_get_digest(entry->parsed->pk, payload)<0) {
    warn(LD_BUG, "Internal error: couldn't hash public key.");
    goto err;
  }

  /* Initialize the pending_final_cpath and start the DH handshake. */
  cpath = rendcirc->build_state->pending_final_cpath;
  if (!cpath) {
    cpath = rendcirc->build_state->pending_final_cpath =
      tor_malloc_zero(sizeof(crypt_path_t));
    cpath->magic = CRYPT_PATH_MAGIC;
    if (!(cpath->dh_handshake_state = crypto_dh_new())) {
      warn(LD_BUG, "Internal error: couldn't allocate DH.");
      goto err;
    }
    if (crypto_dh_generate_public(cpath->dh_handshake_state)<0) {
      warn(LD_BUG, "Internal error: couldn't generate g^x.");
      goto err;
    }
  }

  /* write the remaining items into tmp */
  if (entry->parsed->protocols & (1<<2)) {
    /* version 2 format */
    extend_info_t *extend_info = rendcirc->build_state->chosen_exit;
    int klen;
    tmp[0] = 2; /* version 2 of the cell format */
    /* nul pads */
    set_uint32(tmp+1, htonl(extend_info->addr));
    set_uint16(tmp+5, htons(extend_info->port));
    memcpy(tmp+7, extend_info->identity_digest, DIGEST_LEN);
    klen = crypto_pk_asn1_encode(extend_info->onion_key, tmp+7+DIGEST_LEN+2,
                                 sizeof(tmp)-(7+DIGEST_LEN+2));
    set_uint16(tmp+7+DIGEST_LEN, htons(klen));
    memcpy(tmp+7+DIGEST_LEN+2+klen, rendcirc->rend_cookie, REND_COOKIE_LEN);
    dh_offset = 7+DIGEST_LEN+2+klen+REND_COOKIE_LEN;
  } else {
    /* Version 0. */
    strncpy(tmp, rendcirc->build_state->chosen_exit->nickname, (MAX_NICKNAME_LEN+1)); /* nul pads */
    memcpy(tmp+MAX_NICKNAME_LEN+1, rendcirc->rend_cookie, REND_COOKIE_LEN);
    dh_offset = MAX_NICKNAME_LEN+1+REND_COOKIE_LEN;
  }

  if (crypto_dh_get_public(cpath->dh_handshake_state, tmp+dh_offset,
                           DH_KEY_LEN)<0) {
    warn(LD_BUG, "Internal error: couldn't extract g^x.");
    goto err;
  }

  /*XXX maybe give crypto_pk_public_hybrid_encrypt a max_len arg,
   * to avoid buffer overflows? */
  r = crypto_pk_public_hybrid_encrypt(entry->parsed->pk, payload+DIGEST_LEN, tmp,
                                      dh_offset+DH_KEY_LEN,
                                      PK_PKCS1_OAEP_PADDING, 0);
  if (r<0) {
    warn(LD_BUG,"Internal error: hybrid pk encrypt failed.");
    goto err;
  }

  tor_assert(DIGEST_LEN + r <= RELAY_PAYLOAD_SIZE); /* we overran something */
  payload_len = DIGEST_LEN + r;

  if (connection_edge_send_command(NULL, introcirc,
                                   RELAY_COMMAND_INTRODUCE1,
                                   payload, payload_len,
                                   introcirc->cpath->prev)<0) {
    /* introcirc is already marked for close. leave rendcirc alone. */
    warn(LD_BUG, "Couldn't send INTRODUCE1 cell");
    return -1;
  }

  /* Now, we wait for an ACK or NAK on this circuit. */
  introcirc->purpose = CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT;

  return 0;
err:
  circuit_mark_for_close(introcirc);
  circuit_mark_for_close(rendcirc);
  return -1;
}

/** Called when a rendezvous circuit is open; sends a establish
 * rendezvous circuit as appropriate. */
void
rend_client_rendcirc_has_opened(circuit_t *circ)
{
  tor_assert(circ->purpose == CIRCUIT_PURPOSE_C_ESTABLISH_REND);
  tor_assert(CIRCUIT_IS_ORIGIN(circ));

  info(LD_REND,"rendcirc is open");

  /* generate a rendezvous cookie, store it in circ */
  if (rend_client_send_establish_rendezvous(circ) < 0) {
    return;
  }
}

/** Called when get an ACK or a NAK for a REND_INTRODUCE1 cell.
 */
int
rend_client_introduction_acked(circuit_t *circ,
                               const char *request, size_t request_len)
{
  circuit_t *rendcirc;

  if (circ->purpose != CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT) {
    warn(LD_PROTOCOL, "Received REND_INTRODUCE_ACK on unexpected circuit %d.",
         circ->n_circ_id);
    circuit_mark_for_close(circ);
    return -1;
  }

  tor_assert(circ->build_state->chosen_exit);
  tor_assert(circ->build_state->chosen_exit->nickname);

  if (request_len == 0) {
    /* It's an ACK; the introduction point relayed our introduction request. */
    /* Locate the rend circ which is waiting to hear about this ack,
     * and tell it.
     */
    info(LD_REND,"Received ack. Telling rend circ...");
    rendcirc = circuit_get_by_rend_query_and_purpose(
               circ->rend_query, CIRCUIT_PURPOSE_C_REND_READY);
    if (rendcirc) { /* remember the ack */
      rendcirc->purpose = CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED;
    } else {
      info(LD_REND,"...Found no rend circ. Dropping on the floor.");
    }
    /* close the circuit: we won't need it anymore. */
    circ->purpose = CIRCUIT_PURPOSE_C_INTRODUCE_ACKED;
    circuit_mark_for_close(circ);
  } else {
    /* It's a NAK; the introduction point didn't relay our request. */
    circ->purpose = CIRCUIT_PURPOSE_C_INTRODUCING;
    /* Remove this intro point from the set of viable introduction
     * points. If any remain, extend to a new one and try again.
     * If none remain, refetch the service descriptor.
     */
    if (rend_client_remove_intro_point(circ->build_state->chosen_exit,
                                       circ->rend_query) > 0) {
      /* There are introduction points left. Re-extend the circuit to
       * another intro point and try again. */
      extend_info_t *extend_info;
      int result;
      extend_info = rend_client_get_random_intro(circ->rend_query);
      if (!extend_info) {
        warn(LD_REND, "No introduction points left for %s. Closing.",
             safe_str(circ->rend_query));
        circuit_mark_for_close(circ);
        return -1;
      }
      info(LD_REND,
           "Got nack for %s from %s. Re-extending circ %d, this time to %s.",
           safe_str(circ->rend_query),
           circ->build_state->chosen_exit->nickname, circ->n_circ_id,
           extend_info->nickname);
      result = circuit_extend_to_new_exit(circ, extend_info);
      extend_info_free(extend_info);
      return result;
    }
  }
  return 0;
}

/** If we are not currently fetching a rendezvous service descriptor
 * for the service ID <b>query</b>, start a directory connection to fetch a
 * new one.
 */
void
rend_client_refetch_renddesc(const char *query)
{
  if (connection_get_by_type_state_rendquery(CONN_TYPE_DIR, 0, query)) {
    info(LD_REND,"Would fetch a new renddesc here (for %s), but one is already in progress.", safe_str(query));
  } else {
    /* not one already; initiate a dir rend desc lookup */
    directory_get_from_dirserver(DIR_PURPOSE_FETCH_RENDDESC, query, 1);
  }
}

/** remove failed_intro from ent. if ent now has no intro points, or
 * service is unrecognized, then launch a new renddesc fetch.
 *
 * Return -1 if error, 0 if no intro points remain or service
 * unrecognized, 1 if recognized and some intro points remain.
 */
int
rend_client_remove_intro_point(extend_info_t *failed_intro, const char *query)
{
  int i, r;
  rend_cache_entry_t *ent;
  connection_t *conn;

  r = rend_cache_lookup_entry(query, -1, &ent);
  if (r<0) {
    warn(LD_BUG, "Bug: malformed service ID '%s'.", safe_str(query));
    return -1;
  }
  if (r==0) {
    info(LD_REND, "Unknown service %s. Re-fetching descriptor.",
         safe_str(query));
    rend_client_refetch_renddesc(query);
    return 0;
  }

  if (ent->parsed->intro_point_extend_info) {
    for (i=0; i < ent->parsed->n_intro_points; ++i) {
      if (!memcmp(failed_intro->identity_digest,
                  ent->parsed->intro_point_extend_info[i]->identity_digest,
                  DIGEST_LEN)) {
        tor_assert(!strcmp(ent->parsed->intro_points[i],
                           ent->parsed->intro_point_extend_info[i]->nickname));
        tor_free(ent->parsed->intro_points[i]);
        extend_info_free(ent->parsed->intro_point_extend_info[i]);
        --ent->parsed->n_intro_points;
        ent->parsed->intro_points[i] =
          ent->parsed->intro_points[ent->parsed->n_intro_points];
        ent->parsed->intro_point_extend_info[i] =
          ent->parsed->intro_point_extend_info[ent->parsed->n_intro_points];
        break;
      }
    }
  } else {
    for (i=0; i < ent->parsed->n_intro_points; ++i) {
      if (!strcasecmp(ent->parsed->intro_points[i], failed_intro->nickname)) {
        tor_free(ent->parsed->intro_points[i]);
        ent->parsed->intro_points[i] =
          ent->parsed->intro_points[--ent->parsed->n_intro_points];
        break;
      }
    }
  }

  if (!ent->parsed->n_intro_points) {
    info(LD_REND,"No more intro points remain for %s. Re-fetching descriptor.",
         safe_str(query));
    rend_client_refetch_renddesc(query);

    /* move all pending streams back to renddesc_wait */
    while ((conn = connection_get_by_type_state_rendquery(CONN_TYPE_AP,
                                   AP_CONN_STATE_CIRCUIT_WAIT, query))) {
      conn->state = AP_CONN_STATE_RENDDESC_WAIT;
    }

    return 0;
  }
  info(LD_REND,"%d options left for %s.",
       ent->parsed->n_intro_points, safe_str(query));
  return 1;
}

/** Called when we receive a RENDEZVOUS_ESTABLISHED cell; changes the state of
 * the circuit to C_REND_READY.
 */
int
rend_client_rendezvous_acked(circuit_t *circ, const char *request, size_t request_len)
{
  /* we just got an ack for our establish-rendezvous. switch purposes. */
  if (circ->purpose != CIRCUIT_PURPOSE_C_ESTABLISH_REND) {
    warn(LD_PROTOCOL,"Got a rendezvous ack when we weren't expecting one. Closing circ.");
    circuit_mark_for_close(circ);
    return -1;
  }
  info(LD_REND,"Got rendezvous ack. This circuit is now ready for rendezvous.");
  circ->purpose = CIRCUIT_PURPOSE_C_REND_READY;
  return 0;
}

/** Bob sent us a rendezvous cell; join the circuits. */
int
rend_client_receive_rendezvous(circuit_t *circ, const char *request, size_t request_len)
{
  crypt_path_t *hop;
  char keys[DIGEST_LEN+CPATH_KEY_MATERIAL_LEN];

  if ((circ->purpose != CIRCUIT_PURPOSE_C_REND_READY &&
       circ->purpose != CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED)
      || !circ->build_state->pending_final_cpath) {
    warn(LD_PROTOCOL,"Got rendezvous2 cell from hidden service, but not expecting it. Closing.");
    circuit_mark_for_close(circ);
    return -1;
  }

  if (request_len != DH_KEY_LEN+DIGEST_LEN) {
    warn(LD_PROTOCOL,"Incorrect length (%d) on RENDEZVOUS2 cell.",(int)request_len);
    goto err;
  }

  /* first DH_KEY_LEN bytes are g^y from bob. Finish the dh handshake...*/
  tor_assert(circ->build_state);
  tor_assert(circ->build_state->pending_final_cpath);
  hop = circ->build_state->pending_final_cpath;
  tor_assert(hop->dh_handshake_state);
  if (crypto_dh_compute_secret(hop->dh_handshake_state, request, DH_KEY_LEN,
                               keys, DIGEST_LEN+CPATH_KEY_MATERIAL_LEN)<0) {
    warn(LD_GENERAL, "Couldn't complete DH handshake.");
    goto err;
  }
  /* ... and set up cpath. */
  if (circuit_init_cpath_crypto(hop, keys+DIGEST_LEN, 0)<0)
    goto err;

  /* Check whether the digest is right... */
  if (memcmp(keys, request+DH_KEY_LEN, DIGEST_LEN)) {
    warn(LD_PROTOCOL, "Incorrect digest of key material.");
    goto err;
  }

  crypto_dh_free(hop->dh_handshake_state);
  hop->dh_handshake_state = NULL;

  /* All is well. Extend the circuit. */
  circ->purpose = CIRCUIT_PURPOSE_C_REND_JOINED;
  hop->state = CPATH_STATE_OPEN;
  /* set the windows to default. these are the windows
   * that alice thinks bob has.
   */
  hop->package_window = CIRCWINDOW_START;
  hop->deliver_window = CIRCWINDOW_START;

  onion_append_to_cpath(&circ->cpath, hop);
  circ->build_state->pending_final_cpath = NULL; /* prevent double-free */
  return 0;
 err:
  circuit_mark_for_close(circ);
  return -1;
}

/** Find all the apconns in state AP_CONN_STATE_RENDDESC_WAIT that
 * are waiting on query. If there's a working cache entry here
 * with at least one intro point, move them to the next state;
 * else fail them.
 */
void
rend_client_desc_here(const char *query)
{
  connection_t *conn;
  rend_cache_entry_t *entry;
  time_t now = time(NULL);

  while ((conn = connection_get_by_type_state_rendquery(CONN_TYPE_AP,
                                 AP_CONN_STATE_RENDDESC_WAIT, query))) {
    if (rend_cache_lookup_entry(conn->rend_query, -1, &entry) == 1 &&
        entry->parsed->n_intro_points > 0) {
      /* either this fetch worked, or it failed but there was a
       * valid entry from before which we should reuse */
      info(LD_REND,"Rend desc is usable. Launching circuits.");
      conn->state = AP_CONN_STATE_CIRCUIT_WAIT;

      /* restart their timeout values, so they get a fair shake at
       * connecting to the hidden service. */
      conn->timestamp_created = now;
      conn->timestamp_lastread = now;
      conn->timestamp_lastwritten = now;

      if (connection_ap_handshake_attach_circuit(conn) < 0) {
        /* it will never work */
        warn(LD_REND,"Rendezvous attempt failed. Closing.");
        connection_mark_unattached_ap(conn, END_STREAM_REASON_CANT_ATTACH);
      }
      tor_assert(conn->state != AP_CONN_STATE_RENDDESC_WAIT); /* avoid loop */
    } else { /* 404, or fetch didn't get that far */
      notice(LD_REND,"Closing stream for '%s.onion': hidden service is unavailable (try again later).", safe_str(query));
      connection_mark_unattached_ap(conn, END_STREAM_REASON_TIMEOUT);
    }
  }
}

/** Return a newly allocated extend_info_t* for a randomly chosen introduction
 * point for the named hidden service.  Return NULL if all introduction points
 * have been tried and failed.
 */
extend_info_t *
rend_client_get_random_intro(const char *query)
{
  int i;
  rend_cache_entry_t *entry;

  if (rend_cache_lookup_entry(query, -1, &entry) < 1) {
    warn(LD_REND,"Query '%s' didn't have valid rend desc in cache. Failing.",
         safe_str(query));
    return NULL;
  }

 again:
  if (!entry->parsed->n_intro_points)
    return NULL;

  i = crypto_rand_int(entry->parsed->n_intro_points);

  if (entry->parsed->intro_point_extend_info) {
    return extend_info_dup(entry->parsed->intro_point_extend_info[i]);
  } else {
    /* add the intro point nicknames */
    char *choice = entry->parsed->intro_points[i];
    routerinfo_t *router = router_get_by_nickname(choice, 0);
    if (!router) {
      info(LD_REND, "Unknown router with nickname '%s'; trying another.",choice);
      tor_free(choice);
      entry->parsed->intro_points[i] =
        entry->parsed->intro_points[--entry->parsed->n_intro_points];
      goto again;
    }
    return extend_info_from_router(router);
  }
}

