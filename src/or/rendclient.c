/* Copyright 2004 Roger Dingledine */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/* send the introduce cell */
void
rend_client_introcirc_is_open(circuit_t *circ)
{
  assert(circ->purpose == CIRCUIT_PURPOSE_C_INTRODUCING);
  assert(circ->cpath);

  log_fn(LOG_INFO,"introcirc is open");
  connection_ap_attach_pending();
}

/* send the establish-rendezvous cell. if it fails, mark
 * the circ for close and return -1. else return 0.
 */
int
rend_client_send_establish_rendezvous(circuit_t *circ)
{
  assert(circ->purpose == CIRCUIT_PURPOSE_C_ESTABLISH_REND);
  log_fn(LOG_INFO, "Sending an ESTABLISH_RENDEZVOUS cell");

  if (crypto_rand(REND_COOKIE_LEN, circ->rend_cookie)<0) {
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

int
rend_client_send_introduction(circuit_t *introcirc, circuit_t *rendcirc) {
  const char *descp;
  int desc_len, payload_len, r;
  char payload[RELAY_PAYLOAD_SIZE];
  char tmp[20+20+128];
  rend_service_descriptor_t *parsed=NULL;
  crypt_path_t *cpath;

  assert(introcirc->purpose == CIRCUIT_PURPOSE_C_INTRODUCING);
  assert(rendcirc->purpose == CIRCUIT_PURPOSE_C_REND_READY);
  assert(!rend_cmp_service_ids(introcirc->rend_query, rendcirc->rend_query));

  if(rend_cache_lookup(introcirc->rend_query, &descp, &desc_len) < 1) {
    log_fn(LOG_WARN,"query '%s' didn't have valid rend desc in cache. Failing.",
           introcirc->rend_query);
    goto err;
  }

  parsed = rend_parse_service_descriptor(descp,desc_len);
  if (!parsed) {
    log_fn(LOG_WARN,"Couldn't parse service descriptor");
    goto err;
  }

  /* first 20 bytes of payload are the hash of bob's pk */
  if (crypto_pk_get_digest(parsed->pk, payload)<0) {
    log_fn(LOG_WARN, "Couldn't hash public key.");
    goto err;
  }

  /* Initialize the pending_final_cpath and start the DH handshake. */
  cpath = rendcirc->build_state->pending_final_cpath =
    tor_malloc_zero(sizeof(crypt_path_t));
  if (!(cpath->handshake_state = crypto_dh_new())) {
    log_fn(LOG_WARN, "Couldn't allocate DH");
    goto err;
  }
  if (crypto_dh_generate_public(cpath->handshake_state)<0) {
    log_fn(LOG_WARN, "Couldn't generate g^x");
    goto err;
  }

  /* write the remaining items into tmp */
  strncpy(tmp, rendcirc->build_state->chosen_exit, 20); /* nul pads */
  memcpy(tmp+20, rendcirc->rend_cookie, 20);
  if (crypto_dh_get_public(cpath->handshake_state, tmp+40, 128)<0) {
    log_fn(LOG_WARN, "Couldn't extract g^x");
    goto err;
  }

  r = crypto_pk_public_hybrid_encrypt(parsed->pk, tmp,
                                      20+20+128, payload+20,
                                      PK_PKCS1_OAEP_PADDING);
  if (r<0) {
    log_fn(LOG_WARN,"hybrid pk encrypt failed.");
    goto err;
  }

  payload_len = 20 + r;

  rend_service_descriptor_free(parsed);

  if (connection_edge_send_command(NULL, introcirc,
                                   RELAY_COMMAND_INTRODUCE1,
                                   payload, payload_len,
                                   introcirc->cpath->prev)<0) {
    /* introcirc is already marked for close. leave rendcirc alone. */
    log_fn(LOG_WARN, "Couldn't send INTRODUCE1 cell");
    return -1;
  }

  /* we don't need it anymore, plus it's been used. send the destroy. */
  circuit_mark_for_close(introcirc);

  return 0;
err:
  if(parsed)
    rend_service_descriptor_free(parsed);
  circuit_mark_for_close(introcirc);
  circuit_mark_for_close(rendcirc);
  return -1;
}

/* send the rendezvous cell */
void
rend_client_rendcirc_is_open(circuit_t *circ)
{
  assert(circ->purpose == CIRCUIT_PURPOSE_C_ESTABLISH_REND);
  assert(circ->cpath);

  log_fn(LOG_INFO,"rendcirc is open");

  /* generate a rendezvous cookie, store it in circ */
  if (rend_client_send_establish_rendezvous(circ) < 0) {
    return;
  }

  connection_ap_attach_pending();
}

int
rend_client_rendezvous_acked(circuit_t *circ, const char *request, int request_len)
{
  /* we just got an ack for our establish-rendezvous. switch purposes. */
  if(circ->purpose != CIRCUIT_PURPOSE_C_ESTABLISH_REND) {
    log_fn(LOG_WARN,"Got a rendezvous ack when we weren't expecting one. Closing circ.");
    circuit_mark_for_close(circ);
    return -1;
  }
  log_fn(LOG_INFO,"Got rendezvous ack. This circuit is now ready for rendezvous.");
  circ->purpose = CIRCUIT_PURPOSE_C_REND_READY;
  return 0;
}

/* bob sent us a rendezvous cell, join the circs. */
int
rend_client_receive_rendezvous(circuit_t *circ, const char *request, int request_len)
{
  connection_t *apconn;
  crypt_path_t *hop;
  char keys[DIGEST_LEN+CPATH_KEY_MATERIAL_LEN];

  if(circ->purpose != CIRCUIT_PURPOSE_C_REND_READY ||
     !circ->build_state->pending_final_cpath) {
    log_fn(LOG_WARN,"Got rendezvous2 cell from Bob, but not expecting it. Closing.");
    circuit_mark_for_close(circ);
    return -1;
  }

  if (request_len != DH_KEY_LEN+DIGEST_LEN) {
    log_fn(LOG_WARN,"Incorrect length (%d) on RENDEZVOUS2 cell.",request_len);
    goto err;
  }

  /* first DH_KEY_LEN bytes are g^y from bob. Finish the dh handshake...*/
  assert(circ->build_state && circ->build_state->pending_final_cpath);
  hop = circ->build_state->pending_final_cpath;
  assert(hop->handshake_state);
  if (crypto_dh_compute_secret(hop->handshake_state, request, DH_KEY_LEN,
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

  /* All is well. Extend the circuit. */
  circ->purpose = CIRCUIT_PURPOSE_C_REND_JOINED;
  hop->state = CPATH_STATE_OPEN;
  onion_append_to_cpath(&circ->cpath, hop);
  circ->build_state->pending_final_cpath = NULL; /* prevent double-free */

  for(apconn = circ->p_streams; apconn; apconn = apconn->next_stream) {
    apconn->cpath_layer = circ->cpath->prev;
    /* now the last hop is different. be sure to send all the way. */
    if(connection_ap_handshake_send_begin(apconn, circ) < 0)
      return -1;
  }
  return 0;
 err:
  circuit_mark_for_close(circ);
  return -1;
}

/* Find all the apconns in state AP_CONN_STATE_RENDDESC_WAIT that
 * are waiting on query. If success==1, move them to the next state.
 * If success==0, fail them.
 */
void rend_client_desc_fetched(char *query, int success) {
  connection_t **carray;
  connection_t *conn;
  int n, i;

  get_connection_array(&carray, &n);

  for (i = 0; i < n; ++i) {
    conn = carray[i];
    if (conn->type != CONN_TYPE_AP ||
        conn->state != AP_CONN_STATE_RENDDESC_WAIT)
      continue;
    if (rend_cmp_service_ids(conn->rend_query, query))
      continue;
    /* great, this guy was waiting */
    if(success) {
      log_fn(LOG_INFO,"Rend desc retrieved. Launching circuits.");
      conn->state = AP_CONN_STATE_CIRCUIT_WAIT;
      if (connection_ap_handshake_attach_circuit(conn) < 0) {
        /* it will never work */
        log_fn(LOG_WARN,"attaching to a rend circ failed. Closing conn.");
        connection_mark_for_close(conn,0);
      }
    } else { /* 404 */
      log_fn(LOG_WARN,"service id '%s' not found. Closing conn.", query);
      connection_mark_for_close(conn,0);
    }
  }
}

int rend_cmp_service_ids(char *one, char *two) {
  return strcasecmp(one,two);
}

/* strdup a nickname for a random introduction
 * point of query. return NULL if error.
 */
char *rend_client_get_random_intro(char *query) {
  const char *descp;
  int desc_len;
  int i;
  smartlist_t *sl;
  rend_service_descriptor_t *parsed;
  char *choice;
  char *nickname;

  if(rend_cache_lookup(query, &descp, &desc_len) < 1) {
    log_fn(LOG_WARN,"query '%s' didn't have valid rend desc in cache. Failing.", query);
    return NULL;
  }

  parsed = rend_parse_service_descriptor(descp,desc_len);
  if (!parsed) {
    log_fn(LOG_WARN,"Couldn't parse service descriptor");
    return NULL;
  }

  sl = smartlist_create();

  /* add the intro point nicknames */
  for(i=0;i<parsed->n_intro_points;i++)
    smartlist_add(sl,parsed->intro_points[i]);

  choice = smartlist_choose(sl);
  nickname = tor_strdup(choice);
  smartlist_free(sl);
  rend_service_descriptor_free(parsed);
  return nickname;
}

/* If address is of the form "y.onion" with a well-formed handle y,
 * then put a '\0' after y, lower-case it, and return 0.
 * Else return -1 and change nothing.
 */
int rend_parse_rendezvous_address(char *address) {
  char *s;
  char query[REND_SERVICE_ID_LEN+1];

  s = strrchr(address,'.');
  if(!s) return -1; /* no dot */
  if (strcasecmp(s+1,"onion"))
    return -1; /* not .onion */

  *s = 0; /* null terminate it */
  if(strlcpy(query, address, REND_SERVICE_ID_LEN+1) >= REND_SERVICE_ID_LEN+1)
    goto failed;
  tor_strlower(query);
  if(rend_valid_service_id(query)) {
    tor_strlower(address);
    return 0; /* success */
  }
failed:
  /* otherwise, return to previous state and return -1 */
  *s = '.';
  return -1;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
