/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

extern or_options_t options; /* command-line and config-file options */

static int connection_tls_finish_handshake(connection_t *conn);
static int connection_or_process_cells_from_inbuf(connection_t *conn);

/**************************************************************/

static void cell_pack(char *dest, const cell_t *src) {
  *(uint16_t*)dest     = htons(src->circ_id);
  *(uint8_t*)(dest+2)  = src->command;
  memcpy(dest+3, src->payload, CELL_PAYLOAD_SIZE);
}

static void cell_unpack(cell_t *dest, const char *src) {
  dest->circ_id = ntohs(*(uint16_t*)(src));
  dest->command = *(uint8_t*)(src+2);
  memcpy(dest->payload, src+3, CELL_PAYLOAD_SIZE);
}

/**************************************************************/

int connection_or_process_inbuf(connection_t *conn) {

  assert(conn && conn->type == CONN_TYPE_OR);

  if(conn->inbuf_reached_eof) {
    log_fn(LOG_INFO,"OR connection reached EOF. Closing.");
    connection_mark_for_close(conn,0);
    return 0;
  }

  if(conn->state != OR_CONN_STATE_OPEN)
    return 0; /* don't do anything */
  return connection_or_process_cells_from_inbuf(conn);
}

int connection_or_finished_flushing(connection_t *conn) {
  int e, len=sizeof(e);

  assert(conn && conn->type == CONN_TYPE_OR);
  assert_connection_ok(conn,0);

  switch(conn->state) {
    case OR_CONN_STATE_CONNECTING:
      if (getsockopt(conn->s, SOL_SOCKET, SO_ERROR, (void*)&e, &len) < 0)  { /* not yet */
        if(!ERRNO_CONN_EINPROGRESS(errno)){
          log_fn(LOG_DEBUG,"in-progress connect failed. Removing.");
          connection_mark_for_close(conn,0);
          return -1;
        } else {
          return 0; /* no change, see if next time is better */
        }
      }
      /* the connect has finished. */

      log_fn(LOG_INFO,"OR connect() to router %s:%u finished.",
          conn->address,conn->port);

      if(connection_tls_start_handshake(conn, 0) < 0) {
        /* TLS handhaking error of some kind. */
        connection_mark_for_close(conn,0);
        return -1;
      }
      return 0;
    case OR_CONN_STATE_OPEN:
      connection_stop_writing(conn);
      return 0;
    default:
      log_fn(LOG_WARN,"BUG: called in unexpected state %d",conn->state);
      return 0;
  }
}

/*********************/

void connection_or_init_conn_from_router(connection_t *conn, routerinfo_t *router) {
  conn->addr = router->addr;
  conn->port = router->or_port;
  conn->receiver_bucket = conn->bandwidth = router->bandwidthburst;
  conn->onion_pkey = crypto_pk_dup_key(router->onion_pkey);
  conn->identity_pkey = crypto_pk_dup_key(router->identity_pkey);
  conn->nickname = tor_strdup(router->nickname);
  tor_free(conn->address);
  conn->address = tor_strdup(router->address);
}

connection_t *connection_or_connect(routerinfo_t *router) {
  connection_t *conn;

  assert(router);

  if(router_is_me(router)) {
    log_fn(LOG_WARN,"You asked me to connect to myself! Failing.");
    return NULL;
  }

  /* this function should never be called if we're already connected to router, but */
  /* check first to be sure */
  conn = connection_exact_get_by_addr_port(router->addr,router->or_port);
  if(conn)
    return conn;

  conn = connection_new(CONN_TYPE_OR);

  /* set up conn so it's got all the data we need to remember */
  connection_or_init_conn_from_router(conn, router);
  conn->state = OR_CONN_STATE_CONNECTING;

  if(connection_add(conn) < 0) { /* no space, forget it */
    connection_free(conn);
    return NULL;
  }

  switch(connection_connect(conn, router->address, router->addr, router->or_port)) {
    case -1:
      connection_mark_for_close(conn, 0);
      return NULL;
    case 0:
      connection_set_poll_socket(conn);
      connection_watch_events(conn, POLLIN | POLLOUT | POLLERR);
      /* writable indicates finish, readable indicates broken link,
         error indicates broken link on windows */
      return conn;
    /* case 1: fall through */
  }

  connection_set_poll_socket(conn);

  if(connection_tls_start_handshake(conn, 0) >= 0)
    return conn;

  /* failure */
  connection_mark_for_close(conn, 0);
  return NULL;
}

/* ********************************** */

int connection_tls_start_handshake(connection_t *conn, int receiving) {
  conn->state = OR_CONN_STATE_HANDSHAKING;
  conn->tls = tor_tls_new(conn->s, receiving);
  if(!conn->tls) {
    log_fn(LOG_WARN,"tor_tls_new failed. Closing.");
    return -1;
  }
  connection_start_reading(conn);
  log_fn(LOG_DEBUG,"starting the handshake");
  if(connection_tls_continue_handshake(conn) < 0) {
    return -1;
  }
  return 0;
}

int connection_tls_continue_handshake(connection_t *conn) {
  switch(tor_tls_handshake(conn->tls)) {
    case TOR_TLS_ERROR:
    case TOR_TLS_CLOSE:
      log_fn(LOG_INFO,"tls error. breaking.");
      return -1;
    case TOR_TLS_DONE:
     return connection_tls_finish_handshake(conn);
    case TOR_TLS_WANTWRITE:
      connection_start_writing(conn);
      log_fn(LOG_DEBUG,"wanted write");
      return 0;
    case TOR_TLS_WANTREAD: /* handshaking conns are *always* reading */
      log_fn(LOG_DEBUG,"wanted read");
      return 0;
  }
  return 0;
}

static int connection_tls_finish_handshake(connection_t *conn) {
  routerinfo_t *router;
  char nickname[MAX_NICKNAME_LEN+1];
  connection_t *c;

  conn->state = OR_CONN_STATE_OPEN;
  directory_set_dirty();
  connection_watch_events(conn, POLLIN);
  log_fn(LOG_DEBUG,"tls handshake done. verifying.");
  if (! tor_tls_peer_has_cert(conn->tls)) { /* It's an OP. */
    if (options.ORPort) { /* I'm an OR; good. */
      conn->receiver_bucket = conn->bandwidth = DEFAULT_BANDWIDTH_OP;
      return 0;
    } else { /* Neither side sent a certificate: ouch. */
      log_fn(LOG_WARN,"Neither peer sent a cert! Closing.");
      return -1;
    }
  }
  /* Okay; the other side is an OR. */
  if (tor_tls_get_peer_cert_nickname(conn->tls, nickname, MAX_NICKNAME_LEN)) {
    log_fn(LOG_WARN,"Other side (%s:%d) has a cert without a valid nickname. Closing.",
           conn->address, conn->port);
    return -1;
  }
  log_fn(LOG_DEBUG, "Other side claims to be '%s'", nickname);
  router = router_get_by_nickname(nickname);
  if (!router) {
    log_fn(LOG_INFO, "Unrecognized router with nickname '%s'", nickname);
    return -1;
  }
  if(tor_tls_verify(conn->tls, router->identity_pkey)<0) {
    log_fn(LOG_WARN,"Other side '%s' (%s:%d) has a cert but it's invalid. Closing.",
           nickname, conn->address, conn->port);
    return -1;
  }
  log_fn(LOG_DEBUG,"The router's cert is valid.");

  if((c=connection_exact_get_by_addr_port(router->addr,router->or_port))) {
    log_fn(LOG_INFO,"Router %s is already connected on fd %d. Dropping fd %d.", router->nickname, c->s, conn->s);
    return -1;
  }
  if (conn->nickname && strcmp(conn->nickname, nickname)) {
    log_fn(options.DirPort ? LOG_WARN : LOG_INFO,
           "Other side is '%s', but we tried to connect to '%s'",
           nickname, conn->nickname);
    return -1;
  }
  connection_or_init_conn_from_router(conn,router);

  if (!options.ORPort) { /* If I'm an OP... */
    conn->receiver_bucket = conn->bandwidth = DEFAULT_BANDWIDTH_OP;
  }
  circuit_n_conn_open(conn); /* send the pending creates, if any. */
  /* Note the success */
  rep_hist_note_connect_succeeded(nickname, time(NULL));
  return 0;
}

/* ********************************** */

void connection_or_write_cell_to_buf(const cell_t *cell, connection_t *conn) {
  char networkcell[CELL_NETWORK_SIZE];
  char *n = networkcell;

  assert(cell && conn);
  assert(connection_speaks_cells(conn));

  cell_pack(n, cell);

  connection_write_to_buf(n, CELL_NETWORK_SIZE, conn);
}

/* if there's a whole cell there, pull it off and process it. */
static int connection_or_process_cells_from_inbuf(connection_t *conn) {
  char buf[CELL_NETWORK_SIZE];
  cell_t cell;

loop:
  log_fn(LOG_DEBUG,"%d: starting, inbuf_datalen %d (%d pending in tls object).",
         conn->s,(int)buf_datalen(conn->inbuf),tor_tls_get_pending_bytes(conn->tls));
  if(buf_datalen(conn->inbuf) < CELL_NETWORK_SIZE) /* entire response available? */
    return 0; /* not yet */

  connection_fetch_from_buf(buf, CELL_NETWORK_SIZE, conn);

  /* retrieve cell info from buf (create the host-order struct from the
   * network-order string) */
  cell_unpack(&cell, buf);

  command_process_cell(&cell, conn);

  goto loop; /* process the remainder of the buffer */
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
