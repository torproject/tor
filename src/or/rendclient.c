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

int
rend_client_send_establish_rendezvous(circuit_t *circ)
{
  assert(circ->purpose == CIRCUIT_PURPOSE_C_ESTABLISH_REND);
  log_fn(LOG_INFO, "Sending an ESTABLISH_RENDEZVOUS cell");

  if (crypto_rand(REND_COOKIE_LEN, circ->rend_cookie)<0) {
    log_fn(LOG_WARN, "Couldn't get random cookie");
    return -1;
  }
  if (connection_edge_send_command(NULL,circ,
                                   RELAY_COMMAND_ESTABLISH_RENDEZVOUS,
                                   circ->rend_cookie, REND_COOKIE_LEN,
                                   circ->cpath->prev)<0) {
    log_fn(LOG_WARN, "Couldn't send ESTABLISH_RENDEZVOUS cell");
    return -1;
  }

  return 0;
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
    circuit_mark_for_close(circ);
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
  circ->purpose = CIRCUIT_PURPOSE_C_REND_READY;
  return 0;
}

/* bob sent us a rendezvous cell, join the circs. */
void
rend_client_rendezvous(connection_t *apconn, circuit_t *circ)
{


}




/* Find all the apconns in purpose AP_PURPOSE_RENDDESC_WAIT that
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

/* return a pointer to a nickname for a random introduction
 * point of query. return NULL if error.
 */
char *rend_get_random_intro(char *query) {
  const char *descp;
  int desc_len;
  int i;
  smartlist_t *sl;
  rend_service_descriptor_t *parsed;
  char *choice;

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
  smartlist_free(sl);
  rend_service_descriptor_free(parsed);
  return choice;
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
