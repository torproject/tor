/* Copyright 2004 Roger Dingledine */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/* send the introduce cell */
void
rend_client_introcirc_is_ready(connection_t *apconn, circuit_t *circ)
{

  log_fn(LOG_WARN,"introcirc is ready");
}

/* send the rendezvous cell */
void
rend_client_rendcirc_is_ready(connection_t *apconn, circuit_t *circ)
{


  log_fn(LOG_WARN,"rendcirc is ready");
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
        conn->state != AP_CONN_STATE_CIRCUIT_WAIT)
      continue;
    if (conn->purpose != AP_PURPOSE_RENDDESC_WAIT)
      continue;
    if (rend_cmp_service_ids(conn->rend_query, query))
      continue;
    /* great, this guy was waiting */
    if(success) {
      conn->purpose = AP_PURPOSE_RENDPOINT_WAIT;
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

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
