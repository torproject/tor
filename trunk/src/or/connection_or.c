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
    connection_mark_for_close(conn);
    return 0;
  }

  if(conn->state != OR_CONN_STATE_OPEN)
    return 0; /* don't do anything */
  return connection_or_process_cells_from_inbuf(conn);
}

/** Connection <b>conn</b> has finished writing and has no bytes left on
 * its outbuf.
 *
 * Otherwise it's in state "open": stop writing and return.
 *
 * If <b>conn</b> is broken, mark it for close and return -1, else
 * return 0.
 */
int connection_or_finished_flushing(connection_t *conn) {
  tor_assert(conn && conn->type == CONN_TYPE_OR);

  assert_connection_ok(conn,0);

  if (conn->state != OR_CONN_STATE_OPEN) {
    log_fn(LOG_WARN,"BUG: called in unexpected state %d",conn->state);
    return -1;
  }

  connection_stop_writing(conn);
  return 0;
}

/** Connected handler for OR connections: begin the TLS handshake.
 */
int connection_or_finished_connecting(connection_t *conn)
{
  tor_assert(conn && conn->type == CONN_TYPE_OR);
  tor_assert(conn->state == OR_CONN_STATE_CONNECTING);

  log_fn(LOG_INFO,"OR connect() to router %s:%u finished.",
         conn->address,conn->port);

  if(connection_tls_start_handshake(conn, 0) < 0) {
    /* TLS handshaking error of some kind. */
    connection_mark_for_close(conn);
    return -1;
  }
  return 0;
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
  crypto_pk_get_digest(conn->identity_pkey, conn->identity_digest);
  conn->nickname = tor_strdup(router->nickname);
  tor_free(conn->address);
  conn->address = tor_strdup(router->address);
}

static void
connection_or_init_conn_from_address(connection_t *conn,
                                     uint32_t addr, uint16_t port,
                                     const char *id_digest)
{
  routerinfo_t *r;
  struct in_addr in;
  r = router_get_by_digest(id_digest);
  if (r) {
    connection_or_init_conn_from_router(conn,r);
    return;
  }
  conn->addr = addr;
  conn->port = port;
  /* This next part isn't really right, but it's good enough for now. */
  conn->receiver_bucket = conn->bandwidth = options.BandwidthBurst;
  memcpy(conn->identity_digest, id_digest, DIGEST_LEN);
  conn->nickname = tor_malloc(HEX_DIGEST_LEN+1);
  base16_encode(conn->nickname, HEX_DIGEST_LEN+1,
                conn->identity_digest, DIGEST_LEN);
  tor_free(conn->address);
  in.s_addr = htonl(addr);
  conn->address = tor_strdup(inet_ntoa(in));
}

/** Launch a new OR connection to <b>addr</b>:<b>port</b> and expect to
 * handshake with an OR with identity digest <b>id_digest</b>.
 *
 * If <b>id_digest</b> is me, do nothing. If we're already connected to it,
 * return that connection. If the connect() is in progress, set the
 * new conn's state to 'connecting' and return it. If connect() succeeds,
 * call * connection_tls_start_handshake() on it.
 *
 * This function is called from router_retry_connections(), for
 * ORs connecting to ORs, and circuit_establish_circuit(), for
 * OPs connecting to ORs.
 *
 * Return the launched conn, or NULL if it failed.
 */
connection_t *connection_or_connect(uint32_t addr, uint16_t port,
                                    const char *id_digest) {
  connection_t *conn;
  routerinfo_t *me;

  tor_assert(id_digest);

  if(server_mode() && (me=router_get_my_routerinfo()) &&
     !memcmp(me->identity_digest, id_digest,DIGEST_LEN)) {
    log_fn(LOG_WARN,"Request to connect to myself! Failing.");
    return NULL;
  }

  /* this function should never be called if we're already connected to
   * id_digest, but check first to be sure */
/*XXX008 this is getting called, at least by dirservers. */
  conn = connection_get_by_identity_digest(id_digest, CONN_TYPE_OR);
  if(conn) {
    tor_assert(conn->nickname);
    log_fn(LOG_WARN,"Asked me to connect to %s, but there's already a connection.", conn->nickname);
    return conn;
  }

  conn = connection_new(CONN_TYPE_OR);

  /* set up conn so it's got all the data we need to remember */
  connection_or_init_conn_from_address(conn, addr, port, id_digest);
  conn->state = OR_CONN_STATE_CONNECTING;

  switch(connection_connect(conn, conn->address, addr, port)) {
    case -1:
      router_mark_as_down(conn->identity_digest);
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
  connection_mark_for_close(conn);
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
  int use_no_cert=0;
  conn->state = OR_CONN_STATE_HANDSHAKING;
  if(receiving) { /* check if he's 0.0.7 and I'm unverified */
    routerinfo_t *him, *me;
    him = router_get_by_digest(conn->identity_digest);
    me = router_get_my_routerinfo();

    if(him && !strcmpstart(him->platform, "Tor 0.0.7") &&
       (!me || !me->is_verified)) {
      log_fn(LOG_INFO,"He's running 0.0.7, and I'm unverified. Acting like OP.");
      use_no_cert = 1;
    }
  }
  conn->tls = tor_tls_new(conn->s, receiving, use_no_cert);
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

static int digest_is_zero(const char *id) {
  char ZERO_DIGEST[DIGEST_LEN];
  memset(ZERO_DIGEST, 0, DIGEST_LEN);
  return !memcmp(ZERO_DIGEST, id, DIGEST_LEN);
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
 * If all is successful and he's an OR, then call circuit_n_conn_done()
 * to handle events that have been pending on the tls handshake
 * completion, and set the directory to be dirty (only matters if I'm
 * an authdirserver).
 */
static int
connection_tls_finish_handshake(connection_t *conn) {
  routerinfo_t *router;
  char nickname[MAX_NICKNAME_LEN+1];
  connection_t *c;
  crypto_pk_env_t *identity_rcvd=NULL;
  char digest_rcvd[DIGEST_LEN];

  conn->state = OR_CONN_STATE_OPEN;
  connection_watch_events(conn, POLLIN);
  log_fn(LOG_DEBUG,"tls handshake done. verifying.");
  if (! tor_tls_peer_has_cert(conn->tls)) { /* It's an OP. */
    if (server_mode()) { /* I'm an OR; good. */
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

  if(tor_tls_verify(conn->tls, &identity_rcvd) < 0) {
    log_fn(LOG_WARN,"Other side '%s' (%s:%d) has a cert but it's invalid. Closing.",
           nickname, conn->address, conn->port);
    return -1;
  }
  log_fn(LOG_DEBUG,"The router's cert is valid.");
  crypto_pk_get_digest(identity_rcvd, digest_rcvd);
  crypto_free_pk_env(identity_rcvd);

  router = router_get_by_nickname(nickname);
  if(router && /* we know this nickname */
     router->is_verified && /* make sure it's the right guy */
     memcmp(digest_rcvd, router->identity_digest, DIGEST_LEN) != 0) {
    log_fn(LOG_WARN, "Identity key not as expected for %s", nickname);
    return -1;
  }

  if (!digest_is_zero(conn->identity_digest)) {
    /* I initiated this connection. */
    if (strcasecmp(conn->nickname, nickname)) {
      log_fn(options.DirPort ? LOG_WARN : LOG_INFO,
             "Other side (%s:%d) is '%s', but we tried to connect to '%s'",
             conn->address, conn->port, nickname, conn->nickname);
      return -1;
    }
  } else {
    if((c=connection_get_by_identity_digest(digest_rcvd, CONN_TYPE_OR))) {
      log_fn(LOG_INFO,"Router %s is already connected on fd %d. Dropping fd %d.", nickname, c->s, conn->s);
      return -1;
    }
    connection_or_init_conn_from_address(conn,conn->addr,conn->port,digest_rcvd);
  }

  if (!server_mode()) { /* If I'm an OP... */
    conn->receiver_bucket = conn->bandwidth = DEFAULT_BANDWIDTH_OP;
  }
  directory_set_dirty();
  circuit_n_conn_done(conn, 1); /* send the pending creates, if any. */
  /* Note the success */
  rep_hist_note_connect_succeeded(conn->identity_digest, time(NULL));
  return 0;
}

/** Pack <b>cell</b> into wire-format, and write it onto <b>conn</b>'s
 * outbuf.
 *
 * (Commented out) If it's an OR conn, and an entire TLS record is
 * ready, then try to flush the record now.
 */
void connection_or_write_cell_to_buf(const cell_t *cell, connection_t *conn) {
  char networkcell[CELL_NETWORK_SIZE];
  char *n = networkcell;

  tor_assert(cell && conn);
  tor_assert(connection_speaks_cells(conn));

  cell_pack(n, cell);

  connection_write_to_buf(n, CELL_NETWORK_SIZE, conn);

#if 0 /* commented out -- can we get away with not doing this,
       * because we're already round-robining in handle_read?
       */
#define MIN_TLS_FLUSHLEN 15872
/* openssl tls record size is 16383, this is close. The goal here is to
 * push data out as soon as we know there's enough for a tls record, so
 * during periods of high load we won't read the entire megabyte from
 * input before pushing any data out. */
  if(conn->outbuf_flushlen-CELL_NETWORK_SIZE < MIN_TLS_FLUSHLEN &&
     conn->outbuf_flushlen >= MIN_TLS_FLUSHLEN) {
    int extra = conn->outbuf_flushlen - MIN_TLS_FLUSHLEN;
    conn->outbuf_flushlen = MIN_TLS_FLUSHLEN;
    if(connection_handle_write(conn) < 0) {
      log_fn(LOG_WARN,"flushing failed.");
      return;
    }
    if(extra) {
      conn->outbuf_flushlen += extra;
      connection_start_writing(conn);
    }
  }
#endif

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
