/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file connection_or.c
 * \brief Functions to handle OR connections, TLS handshaking, and
 * cells on the network.
 **/

#include "or.h"

extern or_options_t options; /**< command-line and config-file options */

static int connection_tls_finish_handshake(connection_t *conn);
static int connection_or_process_cells_from_inbuf(connection_t *conn);

/**************************************************************/

/** Pack the cell_t host-order structure <b>src</b> into network-order
 * in the buffer <b>dest</b>. See tor-spec.txt for details about the
 * wire format.
 */
static void cell_pack(char *dest, const cell_t *src) {
  *(uint16_t*)dest     = htons(src->circ_id);
  *(uint8_t*)(dest+2)  = src->command;
  memcpy(dest+3, src->payload, CELL_PAYLOAD_SIZE);
}

/** Unpack the network-order buffer <b>src</b> into a host-order
 * cell_t structure <b>dest</b>.
 */
static void cell_unpack(cell_t *dest, const char *src) {
  dest->circ_id = ntohs(*(uint16_t*)(src));
  dest->command = *(uint8_t*)(src+2);
  memcpy(dest->payload, src+3, CELL_PAYLOAD_SIZE);
}

/** Handle any new bytes that have come in on connection <b>conn</b>.
 * If conn is in 'open' state, hand it to
 * connection_or_process_cells_from_inbuf()
 * (else do nothing).
 */
int connection_or_process_inbuf(connection_t *conn) {

  tor_assert(conn && conn->type == CONN_TYPE_OR);

  if(conn->inbuf_reached_eof) {
    log_fn(LOG_INFO,"OR connection reached EOF. Closing.");
    connection_mark_for_close(conn,0);
    return 0;
  }

  if(conn->state != OR_CONN_STATE_OPEN)
    return 0; /* don't do anything */
  return connection_or_process_cells_from_inbuf(conn);
}

/** Connection <b>conn</b> has finished writing and has no bytes left on
 * its outbuf.
 *
 * If it's in state "connecting", then take a look at the socket, and
 * begin the tls handshake if the connect succeeded.
 *
 * Otherwise it's in state "open": stop writing and return.
 *
 * If <b>conn</b> is broken, mark it for close and return -1, else
 * return 0.
 */
int connection_or_finished_flushing(connection_t *conn) {
  int e, len=sizeof(e);

  tor_assert(conn && conn->type == CONN_TYPE_OR);
  assert_connection_ok(conn,0);

  switch(conn->state) {
    case OR_CONN_STATE_CONNECTING:
      if (getsockopt(conn->s, SOL_SOCKET, SO_ERROR, (void*)&e, &len) < 0) {
        /* not yet */
        if(!ERRNO_IS_CONN_EINPROGRESS(tor_socket_errno(conn->s))) {
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

/** Initialize <b>conn</b> to include all the relevant data from <b>router</b>.
 * This function is called either from connection_or_connect(), if
 * we initiated the connect, or from connection_tls_finish_handshake()
 * if the other side initiated it.
 */
static void
connection_or_init_conn_from_router(connection_t *conn, routerinfo_t *router) {
  conn->addr = router->addr;
  conn->port = router->or_port;
  conn->receiver_bucket = conn->bandwidth = router->bandwidthburst;
  conn->identity_pkey = crypto_pk_dup_key(router->identity_pkey);
  conn->nickname = tor_strdup(router->nickname);
  tor_free(conn->address);
  conn->address = tor_strdup(router->address);
}

/** Launch a new OR connection to <b>router</b>.
 *
 * If <b>router</b> is me, do nothing. If we're already connected to <b>router</b>,
 * return that connection. If the connect is in progress, set conn's
 * state to 'connecting' and return. If connect to <b>router</b> succeeds, call
 * connection_tls_start_handshake() on it.
 *
 * This function is called from router_retry_connections(), for
 * ORs connecting to ORs, and circuit_establish_circuit(), for
 * OPs connecting to ORs.
 *
 * Return the launched conn, or NULL if it failed.
 */
connection_t *connection_or_connect(routerinfo_t *router) {
  connection_t *conn;

  tor_assert(router);

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

  switch(connection_connect(conn, router->address, router->addr, router->or_port)) {
    case -1:
      connection_free(conn);
      return NULL;
    case 0:
      connection_watch_events(conn, POLLIN | POLLOUT | POLLERR);
      /* writable indicates finish, readable indicates broken link,
         error indicates broken link on windows */
      return conn;
    /* case 1: fall through */
  }

  if(connection_tls_start_handshake(conn, 0) >= 0)
    return conn;

  /* failure */
  connection_mark_for_close(conn, 0);
  return NULL;
}

/** Begin the tls handshake with <b>conn</b>. <b>receiving</b> is 0 if
 * we initiated the connection, else it's 1.
 *
 * Assign a new tls object to conn->tls, begin reading on <b>conn</b>, and pass
 * <b>conn</b> to connection_tls_continue_handshake().
 *
 * Return -1 if <b>conn</b> is broken, else return 0.
 */
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

/** Move forward with the tls handshake. If it finishes, hand
 * <b>conn</b> to connection_tls_finish_handshake().
 *
 * Return -1 if <b>conn</b> is broken, else return 0.
 */
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

/** The tls handshake is finished.
 *
 * Make sure we are happy with the person we just handshaked with:
 * If it's an OP (that is, it has no certificate), make sure I'm an OR.
 * If it's an OR (it has a certificate), make sure it has a recognized
 * nickname, and its cert is signed by the identity key of that nickname.
 * If I initiated the connection, make sure it's the right guy; and if
 * he initiated the connection, make sure he's not already connected.
 *
 * If he initiated the conn, also initialize conn from the information
 * in router.
 *
 * If either of us is an OP, set bandwidth to the default OP bandwidth.
 *
 * If all is successful and he's an OR, then call circuit_n_conn_open()
 * to handle events that have been pending on the tls handshake
 * completion, and set the directory to be dirty (only matters if I'm
 * a dirserver).
 */
static int
connection_tls_finish_handshake(connection_t *conn) {
  routerinfo_t *router;
  char nickname[MAX_NICKNAME_LEN+1];
  connection_t *c;

  conn->state = OR_CONN_STATE_OPEN;
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
  log_fn(LOG_DEBUG, "Other side (%s:%d) claims to be '%s'", conn->address,
         conn->port, nickname);
  router = router_get_by_nickname(nickname);
  if (!router) {
    log_fn(LOG_INFO, "Unrecognized router with nickname '%s' at %s:%d",
           nickname, conn->address, conn->port);
    return -1;
  }
  if(tor_tls_verify(conn->tls, router->identity_pkey)<0) {
    log_fn(LOG_WARN,"Other side '%s' (%s:%d) has a cert but it's invalid. Closing.",
           nickname, conn->address, conn->port);
    return -1;
  }
  log_fn(LOG_DEBUG,"The router's cert is valid.");

  if (conn->nickname) {
    /* I initiated this connection. */
    if (strcasecmp(conn->nickname, nickname)) {
      log_fn(options.DirPort ? LOG_WARN : LOG_INFO,
             "Other side (%s:%d) is '%s', but we tried to connect to '%s'",
             conn->address, conn->port, nickname, conn->nickname);
      return -1;
    }
  } else {
    if((c=connection_exact_get_by_addr_port(router->addr,router->or_port))) {
      log_fn(LOG_INFO,"Router %s is already connected on fd %d. Dropping fd %d.", router->nickname, c->s, conn->s);
      return -1;
    }
    connection_or_init_conn_from_router(conn,router);
  }

  if (!options.ORPort) { /* If I'm an OP... */
    conn->receiver_bucket = conn->bandwidth = DEFAULT_BANDWIDTH_OP;
  }
  directory_set_dirty();
  circuit_n_conn_open(conn); /* send the pending creates, if any. */
  /* Note the success */
  rep_hist_note_connect_succeeded(nickname, time(NULL));
  return 0;
}

/** Pack <b>cell</b> into wire-format, and write it onto <b>conn</b>'s outbuf. */
void connection_or_write_cell_to_buf(const cell_t *cell, connection_t *conn) {
  char networkcell[CELL_NETWORK_SIZE];
  char *n = networkcell;

  tor_assert(cell && conn);
  tor_assert(connection_speaks_cells(conn));

  cell_pack(n, cell);

  connection_write_to_buf(n, CELL_NETWORK_SIZE, conn);
}

/** Process cells from <b>conn</b>'s inbuf.
 *
 * Loop: while inbuf contains a cell, pull it off the inbuf, unpack it,
 * and hand it to command_process_cell().
 *
 * Always return 0.
 */
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
