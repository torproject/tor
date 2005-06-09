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

  log_fn(LOG_INFO,"introcirc is open");
  connection_ap_attach_pending();
}

/** Send the establish-rendezvous cell along a rendezvous circuit. if
 * it fails, mark the circ for close and return -1. else return 0.
 */
static int
rend_client_send_establish_rendezvous(circuit_t *circ)
{
  tor_assert(circ->purpose == CIRCUIT_PURPOSE_C_ESTABLISH_REND);
  log_fn(LOG_INFO, "Sending an ESTABLISH_RENDEZVOUS cell");

  if (crypto_rand(circ->rend_cookie, REND_COOKIE_LEN) < 0) {
    log_fn(LOG_WARN, "Couldn't get random cookie");
    circuit_mark_for_close(circ);
    return -1;
  }
  if (connection_edge_send_command(NULL,circ,
                                   RELAY_COMMAND_ESTABLISH_RENDEZVOUS,
                                   circ->rend_cookie, REND_COOKIE_LEN,
                                   circ->cpath->prev)<0) {
    /* circ is already marked for close */
    log_fn(LOG_WARN, "Couldn't send ESTABLISH_RENDEZVOUS cell");
    return -1;
  }

  return 0;
}

/** Called when we're trying to connect an ap conn; sends an INTRODUCE1 cell
 * down introcirc if possible.
 */
int
rend_client_send_introduction(circuit_t *introcirc, circuit_t *rendcirc) {
  size_t payload_len;
  int r;
  char payload[RELAY_PAYLOAD_SIZE];
  char tmp[1+(MAX_HEX_NICKNAME_LEN+1)+REND_COOKIE_LEN+DH_KEY_LEN];
  rend_cache_entry_t *entry;
  crypt_path_t *cpath;

  tor_assert(introcirc->purpose == CIRCUIT_PURPOSE_C_INTRODUCING);
  tor_assert(rendcirc->purpose == CIRCUIT_PURPOSE_C_REND_READY);
  tor_assert(!rend_cmp_service_ids(introcirc->rend_query, rendcirc->rend_query));

  if (rend_cache_lookup_entry(introcirc->rend_query, &entry) < 1) {
    log_fn(LOG_WARN,"query '%s' didn't have valid rend desc in cache. Failing.",
           safe_str(introcirc->rend_query));
    goto err;
  }

  /* first 20 bytes of payload are the hash of bob's pk */
  if (crypto_pk_get_digest(entry->parsed->pk, payload)<0) {
    log_fn(LOG_WARN, "Couldn't hash public key.");
    goto err;
  }

  /* Initialize the pending_final_cpath and start the DH handshake. */
  cpath = rendcirc->build_state->pending_final_cpath;
  if (!cpath) {
    cpath = rendcirc->build_state->pending_final_cpath =
      tor_malloc_zero(sizeof(crypt_path_t));
    cpath->magic = CRYPT_PATH_MAGIC;
    if (!(cpath->dh_handshake_state = crypto_dh_new())) {
      log_fn(LOG_WARN, "Couldn't allocate DH");
      goto err;
    }
    if (crypto_dh_generate_public(cpath->dh_handshake_state)<0) {
      log_fn(LOG_WARN, "Couldn't generate g^x");
      goto err;
    }
  }

  /* write the remaining items into tmp */
#if 0
  tmp[0] = 1; /* version 1 of the cell format */
  /* nul pads */
  strncpy(tmp+1, rendcirc->build_state->chosen_exit_name, (MAX_HEX_NICKNAME_LEN+1));
  memcpy(tmp+1+MAX_HEX_NICKNAME_LEN+1, rendcirc->rend_cookie, REND_COOKIE_LEN);
#else
  strncpy(tmp, rendcirc->build_state->chosen_exit_name, (MAX_NICKNAME_LEN+1)); /* nul pads */
  memcpy(tmp+MAX_NICKNAME_LEN+1, rendcirc->rend_cookie, REND_COOKIE_LEN);
#endif
  if (crypto_dh_get_public(cpath->dh_handshake_state,
#if 0
                           tmp+1+MAX_HEX_NICKNAME_LEN+1+REND_COOKIE_LEN,
#else
                           tmp+MAX_NICKNAME_LEN+1+REND_COOKIE_LEN,
#endif

                           DH_KEY_LEN)<0) {
    log_fn(LOG_WARN, "Couldn't extract g^x");
    goto err;
  }

  /*XXX maybe give crypto_pk_public_hybrid_encrypt a max_len arg,
   * to avoid buffer overflows? */
  r = crypto_pk_public_hybrid_encrypt(entry->parsed->pk, payload+DIGEST_LEN, tmp,
#if 0
                           1+MAX_HEX_NICKNAME_LEN+1+REND_COOKIE_LEN+DH_KEY_LEN,
#else
                           MAX_NICKNAME_LEN+1+REND_COOKIE_LEN+DH_KEY_LEN,
#endif
                                      PK_PKCS1_OAEP_PADDING, 0);
  if (r<0) {
    log_fn(LOG_WARN,"hybrid pk encrypt failed.");
    goto err;
  }

  tor_assert(DIGEST_LEN + r <= RELAY_PAYLOAD_SIZE); /* we overran something */
  payload_len = DIGEST_LEN + r;

  if (connection_edge_send_command(NULL, introcirc,
                                   RELAY_COMMAND_INTRODUCE1,
                                   payload, payload_len,
                                   introcirc->cpath->prev)<0) {
    /* introcirc is already marked for close. leave rendcirc alone. */
    log_fn(LOG_WARN, "Couldn't send INTRODUCE1 cell");
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

  log_fn(LOG_INFO,"rendcirc is open");

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
  char *nickname;
  circuit_t *rendcirc;

  if (circ->purpose != CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT) {
    log_fn(LOG_WARN, "Received REND_INTRODUCE_ACK on unexpected circuit %d",
           circ->n_circ_id);
    circuit_mark_for_close(circ);
    return -1;
  }

  tor_assert(circ->build_state->chosen_exit_name);

  if (request_len == 0) {
    /* It's an ACK; the introduction point relayed our introduction request. */
    /* Locate the rend circ which is waiting to hear about this ack,
     * and tell it.
     */
    log_fn(LOG_INFO,"Received ack. Telling rend circ...");
    rendcirc = circuit_get_by_rend_query_and_purpose(
               circ->rend_query, CIRCUIT_PURPOSE_C_REND_READY);
    if (rendcirc) { /* remember the ack */
      rendcirc->purpose = CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED;
    } else {
      log_fn(LOG_INFO,"...Found no rend circ. Dropping on the floor.");
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
    if (rend_client_remove_intro_point(circ->build_state->chosen_exit_name,
                                       circ->rend_query) > 0) {
      /* There are introduction points left. re-extend the circuit to
       * another intro point and try again. */
      routerinfo_t *r;
      nickname = rend_client_get_random_intro(circ->rend_query);
      tor_assert(nickname);
      log_fn(LOG_INFO,"Got nack for %s from %s, extending to %s.",
             safe_str(circ->rend_query),
             circ->build_state->chosen_exit_name, nickname);
      if (!(r = router_get_by_nickname(nickname))) {
        log_fn(LOG_WARN, "Advertised intro point '%s' for %s is not known. Closing.",
               nickname, safe_str(circ->rend_query));
        tor_free(nickname);
        circuit_mark_for_close(circ);
        return -1;
      }
      log_fn(LOG_INFO, "Chose new intro point %s for %s (circ %d)",
             nickname, safe_str(circ->rend_query), circ->n_circ_id);
      tor_free(nickname);
      return circuit_extend_to_new_exit(circ, r);
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
    log_fn(LOG_INFO,"Would fetch a new renddesc here (for %s), but one is already in progress.", safe_str(query));
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
rend_client_remove_intro_point(char *failed_intro, const char *query)
{
  int i, r;
  rend_cache_entry_t *ent;
  connection_t *conn;

  r = rend_cache_lookup_entry(query, &ent);
  if (r<0) {
    log_fn(LOG_WARN, "Malformed service ID '%s'", safe_str(query));
    return -1;
  }
  if (r==0) {
    log_fn(LOG_INFO, "Unknown service %s. Re-fetching descriptor.",
           safe_str(query));
    rend_client_refetch_renddesc(query);
    return 0;
  }

  for (i=0; i < ent->parsed->n_intro_points; ++i) {
    if (!strcasecmp(ent->parsed->intro_points[i], failed_intro)) {
      tor_free(ent->parsed->intro_points[i]);
      ent->parsed->intro_points[i] =
        ent->parsed->intro_points[--ent->parsed->n_intro_points];
      break;
    }
  }

  if (!ent->parsed->n_intro_points) {
    log_fn(LOG_INFO,"No more intro points remain for %s. Re-fetching descriptor.",
           safe_str(query));
    rend_client_refetch_renddesc(query);

    /* move all pending streams back to renddesc_wait */
    while ((conn = connection_get_by_type_state_rendquery(CONN_TYPE_AP,
                                   AP_CONN_STATE_CIRCUIT_WAIT, query))) {
      conn->state = AP_CONN_STATE_RENDDESC_WAIT;
    }

    return 0;
  }
  log_fn(LOG_INFO,"%d options left for %s.",
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
    log_fn(LOG_WARN,"Got a rendezvous ack when we weren't expecting one. Closing circ.");
    circuit_mark_for_close(circ);
    return -1;
  }
  log_fn(LOG_INFO,"Got rendezvous ack. This circuit is now ready for rendezvous.");
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
    log_fn(LOG_WARN,"Got rendezvous2 cell from Bob, but not expecting it. Closing.");
    circuit_mark_for_close(circ);
    return -1;
  }

  if (request_len != DH_KEY_LEN+DIGEST_LEN) {
    log_fn(LOG_WARN,"Incorrect length (%d) on RENDEZVOUS2 cell.",(int)request_len);
    goto err;
  }

  /* first DH_KEY_LEN bytes are g^y from bob. Finish the dh handshake...*/
  tor_assert(circ->build_state);
  tor_assert(circ->build_state->pending_final_cpath);
  hop = circ->build_state->pending_final_cpath;
  tor_assert(hop->dh_handshake_state);
  if (crypto_dh_compute_secret(hop->dh_handshake_state, request, DH_KEY_LEN,
                               keys, DIGEST_LEN+CPATH_KEY_MATERIAL_LEN)<0) {
    log_fn(LOG_WARN, "Couldn't complete DH handshake");
    goto err;
  }
  /* ... and set up cpath. */
  if (circuit_init_cpath_crypto(hop, keys+DIGEST_LEN, 0)<0)
    goto err;

  /* Check whether the digest is right... */
  if (memcmp(keys, request+DH_KEY_LEN, DIGEST_LEN)) {
    log_fn(LOG_WARN, "Incorrect digest of key material");
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
void rend_client_desc_here(char *query) {
  connection_t *conn;
  rend_cache_entry_t *entry;
  time_t now = time(NULL);

  while ((conn = connection_get_by_type_state_rendquery(CONN_TYPE_AP,
                                 AP_CONN_STATE_RENDDESC_WAIT, query))) {
    if (rend_cache_lookup_entry(conn->rend_query, &entry) == 1 &&
        entry->parsed->n_intro_points > 0) {
      /* either this fetch worked, or it failed but there was a
       * valid entry from before which we should reuse */
      log_fn(LOG_INFO,"Rend desc is usable. Launching circuits.");
      conn->state = AP_CONN_STATE_CIRCUIT_WAIT;

      /* restart their timeout values, so they get a fair shake at
       * connecting to the hidden service. */
      conn->timestamp_created = now;
      conn->timestamp_lastread = now;
      conn->timestamp_lastwritten = now;

      if (connection_ap_handshake_attach_circuit(conn) < 0) {
        /* it will never work */
        log_fn(LOG_WARN,"attaching to a rend circ failed. Closing conn.");
        connection_mark_unattached_ap(conn, END_STREAM_REASON_CANT_ATTACH);
      }
      tor_assert(conn->state != AP_CONN_STATE_RENDDESC_WAIT); /* avoid loop */
    } else { /* 404, or fetch didn't get that far */
      log_fn(LOG_NOTICE,"Closing stream for '%s.onion': hidden service is unavailable (try again later).", safe_str(query));
      connection_mark_unattached_ap(conn, END_STREAM_REASON_TIMEOUT);
    }
  }
}

/** strdup a nickname for a random introduction
 * point of query. return NULL if error.
 */
char *rend_client_get_random_intro(char *query) {
  int i;
  smartlist_t *sl;
  char *choice;
  char *nickname;
  rend_cache_entry_t *entry;

  if (rend_cache_lookup_entry(query, &entry) < 1) {
    log_fn(LOG_WARN,"query '%s' didn't have valid rend desc in cache. Failing.",
           safe_str(query));
    return NULL;
  }

  sl = smartlist_create();

  /* add the intro point nicknames */
  for (i=0;i<entry->parsed->n_intro_points;i++)
    smartlist_add(sl,entry->parsed->intro_points[i]);

  choice = smartlist_choose(sl);
  if (!choice) {
    smartlist_free(sl);
    return NULL;
  }
  nickname = tor_strdup(choice);
  smartlist_free(sl);
  return nickname;
}

