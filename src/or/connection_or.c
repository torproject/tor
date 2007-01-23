/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char connection_or_c_id[] =
  "$Id$";

/**
 * \file connection_or.c
 * \brief Functions to handle OR connections, TLS handshaking, and
 * cells on the network.
 **/

#include "or.h"

/** How much clock skew do we tolerate when checking certificates for
 * known routers? (sec) */

#define TIGHT_CERT_ALLOW_SKEW (90*60)

static int connection_tls_finish_handshake(or_connection_t *conn);
static int connection_or_process_cells_from_inbuf(or_connection_t *conn);

/**************************************************************/

/** Map from identity digest of connected OR or desired OR to a connection_t
 * with that identity digest.  If there is more than one such connection_t,
 * they form a linked list, with next_with_same_id as the next pointer. */
static digestmap_t *orconn_identity_map = NULL;

/** If conn is listed in orconn_identity_map, remove it, and clear
 * conn->identity_digest. */
void
connection_or_remove_from_identity_map(or_connection_t *conn)
{
  or_connection_t *tmp;
  tor_assert(conn);
  if (!orconn_identity_map)
    return;
  tmp = digestmap_get(orconn_identity_map, conn->identity_digest);
  if (!tmp)
    return;
  if (conn == tmp) {
    if (conn->next_with_same_id)
      digestmap_set(orconn_identity_map, conn->identity_digest,
                    conn->next_with_same_id);
    else
      digestmap_remove(orconn_identity_map, conn->identity_digest);
  } else {
    while (tmp->next_with_same_id) {
      if (tmp->next_with_same_id == conn) {
        tmp->next_with_same_id = conn->next_with_same_id;
        break;
      }
      tmp = tmp->next_with_same_id;
    }
  }
  memset(conn->identity_digest, 0, DIGEST_LEN);
  conn->next_with_same_id = NULL;
}

/** Remove all entries from the identity-to-orconn map, and clear
 * all identities in OR conns.*/
void
connection_or_clear_identity_map(void)
{
  int i, n;
  connection_t **carray;

  get_connection_array(&carray,&n);
  for (i = 0; i < n; ++i) {
    connection_t* conn = carray[i];
    if (conn->type == CONN_TYPE_OR) {
      or_connection_t *or_conn = TO_OR_CONN(conn);
      memset(or_conn->identity_digest, 0, DIGEST_LEN);
      or_conn->next_with_same_id = NULL;
    }
  }

  if (orconn_identity_map) {
    digestmap_free(orconn_identity_map, NULL);
    orconn_identity_map = NULL;
  }
}

/** Change conn->identity_digest to digest, and add conn into
 * orconn_digest_map. */
static void
connection_or_set_identity_digest(or_connection_t *conn, const char *digest)
{
  or_connection_t *tmp;
  tor_assert(conn);
  tor_assert(digest);

  if (!orconn_identity_map)
    orconn_identity_map = digestmap_new();
  if (!memcmp(conn->identity_digest, digest, DIGEST_LEN))
    return;
  if (tor_digest_is_zero(conn->identity_digest))
    connection_or_remove_from_identity_map(conn);

  memcpy(conn->identity_digest, digest, DIGEST_LEN);
  tmp = digestmap_set(orconn_identity_map, digest, conn);
  conn->next_with_same_id = tmp;

#if 0
  /* Testing code to check for bugs in representation. */
  for (; tmp; tmp = tmp->next_with_same_id) {
    tor_assert(!memcmp(tmp->identity_digest, digest, DIGEST_LEN));
    tor_assert(tmp != conn);
  }
#endif
}

/** Pack the cell_t host-order structure <b>src</b> into network-order
 * in the buffer <b>dest</b>. See tor-spec.txt for details about the
 * wire format.
 */
static void
cell_pack(char *dest, const cell_t *src)
{
  *(uint16_t*)dest    = htons(src->circ_id);
  *(uint8_t*)(dest+2) = src->command;
  memcpy(dest+3, src->payload, CELL_PAYLOAD_SIZE);
}

/** Unpack the network-order buffer <b>src</b> into a host-order
 * cell_t structure <b>dest</b>.
 */
static void
cell_unpack(cell_t *dest, const char *src)
{
  dest->circ_id = ntohs(*(uint16_t*)(src));
  dest->command = *(uint8_t*)(src+2);
  memcpy(dest->payload, src+3, CELL_PAYLOAD_SIZE);
}

int
connection_or_reached_eof(or_connection_t *conn)
{
  log_info(LD_OR,"OR connection reached EOF. Closing.");
  connection_mark_for_close(TO_CONN(conn));
  return 0;
}

/** Read conn's inbuf. If the http response from the proxy is all
 * here, make sure it's good news, and begin the tls handshake. If
 * it's bad news, close the connection and return -1. Else return 0
 * and hope for better luck next time.
 */
static int
connection_or_read_proxy_response(or_connection_t *or_conn)
{
  char *headers;
  char *reason=NULL;
  int status_code;
  time_t date_header;
  connection_t *conn = TO_CONN(or_conn);

  switch (fetch_from_buf_http(conn->inbuf,
                              &headers, MAX_HEADERS_SIZE,
                              NULL, NULL, 10000, 0)) {
    case -1: /* overflow */
      log_warn(LD_PROTOCOL,
               "Your https proxy sent back an oversized response. Closing.");
      return -1;
    case 0:
      log_info(LD_OR,"https proxy response not all here yet. Waiting.");
      return 0;
    /* case 1, fall through */
  }

  if (parse_http_response(headers, &status_code, &date_header,
                          NULL, &reason) < 0) {
    log_warn(LD_OR,
             "Unparseable headers from proxy (connecting to '%s'). Closing.",
             conn->address);
    tor_free(headers);
    return -1;
  }
  if (!reason) reason = tor_strdup("[no reason given]");

  if (status_code == 200) {
    log_info(LD_OR,
             "HTTPS connect to '%s' successful! (200 %s) Starting TLS.",
             conn->address, escaped(reason));
    tor_free(reason);
    if (connection_tls_start_handshake(or_conn, 0) < 0) {
      /* TLS handshaking error of some kind. */
      connection_mark_for_close(conn);

      return -1;
    }
    return 0;
  }
  /* else, bad news on the status code */
  log_warn(LD_OR,
           "The https proxy sent back an unexpected status code %d (%s). "
           "Closing.",
           status_code, escaped(reason));
  tor_free(reason);
  connection_mark_for_close(conn);
  return -1;
}

/** Handle any new bytes that have come in on connection <b>conn</b>.
 * If conn is in 'open' state, hand it to
 * connection_or_process_cells_from_inbuf()
 * (else do nothing).
 */
int
connection_or_process_inbuf(or_connection_t *conn)
{
  tor_assert(conn);

  switch (conn->_base.state) {
    case OR_CONN_STATE_PROXY_READING:
      return connection_or_read_proxy_response(conn);
    case OR_CONN_STATE_OPEN:
      return connection_or_process_cells_from_inbuf(conn);
    default:
      return 0; /* don't do anything */
  }
}

/** Connection <b>conn</b> has finished writing and has no bytes left on
 * its outbuf.
 *
 * Otherwise it's in state "open": stop writing and return.
 *
 * If <b>conn</b> is broken, mark it for close and return -1, else
 * return 0.
 */
int
connection_or_finished_flushing(or_connection_t *conn)
{
  tor_assert(conn);
  assert_connection_ok(TO_CONN(conn),0);

  switch (conn->_base.state) {
    case OR_CONN_STATE_PROXY_FLUSHING:
      log_debug(LD_OR,"finished sending CONNECT to proxy.");
      conn->_base.state = OR_CONN_STATE_PROXY_READING;
      connection_stop_writing(TO_CONN(conn));
      break;
    case OR_CONN_STATE_OPEN:
      connection_stop_writing(TO_CONN(conn));
      break;
    default:
      log_err(LD_BUG,"BUG: called in unexpected state %d.", conn->_base.state);
      tor_fragile_assert();
      return -1;
  }
  return 0;
}

/** Connected handler for OR connections: begin the TLS handshake.
 */
int
connection_or_finished_connecting(or_connection_t *or_conn)
{
  connection_t *conn;
  tor_assert(or_conn);
  conn = TO_CONN(or_conn);
  tor_assert(conn->state == OR_CONN_STATE_CONNECTING);

  log_debug(LD_OR,"OR connect() to router at %s:%u finished.",
            conn->address,conn->port);

  if (get_options()->HttpsProxy) {
    char buf[1024];
    char addrbuf[INET_NTOA_BUF_LEN];
    struct in_addr in;
    char *base64_authenticator=NULL;
    const char *authenticator = get_options()->HttpsProxyAuthenticator;

    in.s_addr = htonl(conn->addr);
    tor_inet_ntoa(&in, addrbuf, sizeof(addrbuf));

    if (authenticator) {
      base64_authenticator = alloc_http_authenticator(authenticator);
      if (!base64_authenticator)
        log_warn(LD_OR, "Encoding https authenticator failed");
    }
    if (base64_authenticator) {
      tor_snprintf(buf, sizeof(buf), "CONNECT %s:%d HTTP/1.1\r\n"
                   "Proxy-Authorization: Basic %s\r\n\r\n", addrbuf,
                   conn->port, base64_authenticator);
      tor_free(base64_authenticator);
    } else {
      tor_snprintf(buf, sizeof(buf), "CONNECT %s:%d HTTP/1.0\r\n\r\n",
                   addrbuf, conn->port);
    }
    connection_write_to_buf(buf, strlen(buf), conn);
    conn->state = OR_CONN_STATE_PROXY_FLUSHING;
    return 0;
  }

  if (connection_tls_start_handshake(or_conn, 0) < 0) {
    /* TLS handshaking error of some kind. */
    connection_mark_for_close(conn);
    return -1;
  }
  return 0;
}

/** If we don't necessarily know the router we're connecting to, but we
 * have an addr/port/id_digest, then fill in as much as we can. Start
 * by checking to see if this describes a router we know. */
static void
connection_or_init_conn_from_address(or_connection_t *conn,
                                     uint32_t addr, uint16_t port,
                                     const char *id_digest,
                                     int started_here)
{
  or_options_t *options = get_options();
  routerinfo_t *r = router_get_by_digest(id_digest);
  conn->bandwidthrate = (int)options->BandwidthRate;
  conn->read_bucket = conn->bandwidthburst = (int)options->BandwidthBurst;
  connection_or_set_identity_digest(conn, id_digest);
  conn->_base.addr = addr;
  conn->_base.port = port;
  if (r) {
    if (!started_here) {
      /* Override the addr/port, so our log messages will make sense.
       * This is dangerous, since if we ever try looking up a conn by
       * its actual addr/port, we won't remember. Careful! */
      conn->_base.addr = r->addr;
      conn->_base.port = r->or_port;
    }
    conn->nickname = tor_strdup(r->nickname);
    tor_free(conn->_base.address);
    conn->_base.address = tor_strdup(r->address);
  } else {
    const char *n;
    /* If we're an authoritative directory server, we may know a
     * nickname for this router. */
    n = dirserv_get_nickname_by_digest(id_digest);
    if (n) {
      conn->nickname = tor_strdup(n);
    } else {
      conn->nickname = tor_malloc(HEX_DIGEST_LEN+2);
      conn->nickname[0] = '$';
      base16_encode(conn->nickname+1, HEX_DIGEST_LEN+1,
                    conn->identity_digest, DIGEST_LEN);
    }
    tor_free(conn->_base.address);
    conn->_base.address = tor_dup_addr(addr);
  }
}

/** Return the best connection of type OR with the
 * digest <b>digest</b> that we have, or NULL if we have none.
 *
 * 1) Don't return it if it's marked for close.
 * 2) If there are any open conns, ignore non-open conns.
 * 3) If there are any non-obsolete conns, ignore obsolete conns.
 * 4) Then if there are any non-empty conns, ignore empty conns.
 * 5) Of the remaining conns, prefer newer conns.
 */
or_connection_t *
connection_or_get_by_identity_digest(const char *digest)
{
  int newer;
  or_connection_t *conn, *best=NULL;

  if (!orconn_identity_map)
    return NULL;

  conn = digestmap_get(orconn_identity_map, digest);

  for (; conn; conn = conn->next_with_same_id) {
    tor_assert(conn->_base.magic == OR_CONNECTION_MAGIC);
    tor_assert(conn->_base.type == CONN_TYPE_OR);
    tor_assert(!memcmp(conn->identity_digest, digest, DIGEST_LEN));
    if (conn->_base.marked_for_close)
      continue;
    if (!best) {
      best = conn; /* whatever it is, it's better than nothing. */
      continue;
    }
    if (best->_base.state == OR_CONN_STATE_OPEN &&
        conn->_base.state != OR_CONN_STATE_OPEN)
      continue; /* avoid non-open conns if we can */
    newer = best->_base.timestamp_created < conn->_base.timestamp_created;

    if (!best->_base.or_is_obsolete && conn->_base.or_is_obsolete)
      continue; /* We never prefer obsolete over non-obsolete connections. */

    if (
      /* We prefer non-obsolete connections: */
        (best->_base.or_is_obsolete && !conn->_base.or_is_obsolete) ||
      /* If both have circuits we prefer the newer: */
        (best->n_circuits && conn->n_circuits && newer) ||
      /* If neither has circuits we prefer the newer: */
        (!best->n_circuits && !conn->n_circuits && newer) ||
      /* We prefer connections with circuits: */
        (!best->n_circuits && conn->n_circuits)) {
      best = conn;
    };
  }
  return best;
}

/** Launch a new OR connection to <b>addr</b>:<b>port</b> and expect to
 * handshake with an OR with identity digest <b>id_digest</b>.
 *
 * If <b>id_digest</b> is me, do nothing. If we're already connected to it,
 * return that connection. If the connect() is in progress, set the
 * new conn's state to 'connecting' and return it. If connect() succeeds,
 * call connection_tls_start_handshake() on it.
 *
 * This function is called from router_retry_connections(), for
 * ORs connecting to ORs, and circuit_establish_circuit(), for
 * OPs connecting to ORs.
 *
 * Return the launched conn, or NULL if it failed.
 */
or_connection_t *
connection_or_connect(uint32_t addr, uint16_t port, const char *id_digest)
{
  or_connection_t *conn;
  or_options_t *options = get_options();

  tor_assert(id_digest);

  if (server_mode(options) && router_digest_is_me(id_digest)) {
    log_info(LD_PROTOCOL,"Client asked me to connect to myself. Refusing.");
    return NULL;
  }

  conn = TO_OR_CONN(connection_new(CONN_TYPE_OR));

  /* set up conn so it's got all the data we need to remember */
  connection_or_init_conn_from_address(conn, addr, port, id_digest, 1);
  conn->_base.state = OR_CONN_STATE_CONNECTING;
  control_event_or_conn_status(conn, OR_CONN_EVENT_LAUNCHED, 0);

  if (options->HttpsProxy) {
    /* we shouldn't connect directly. use the https proxy instead. */
    addr = options->HttpsProxyAddr;
    port = options->HttpsProxyPort;
  }

  switch (connection_connect(TO_CONN(conn), conn->_base.address, addr, port)) {
    case -1:
      /* If the connection failed immediately, and we're using
       * an https proxy, our https proxy is down. Don't blame the
       * Tor server. */
      if (!options->HttpsProxy) {
        entry_guard_register_connect_status(conn->identity_digest, 0,
                                            time(NULL));
        router_set_status(conn->identity_digest, 0);
      }
      control_event_or_conn_status(conn, OR_CONN_EVENT_FAILED,
              END_OR_CONN_REASON_TCP_REFUSED);
      connection_free(TO_CONN(conn));
      return NULL;
    case 0:
      connection_watch_events(TO_CONN(conn), EV_READ | EV_WRITE);
      /* writable indicates finish, readable indicates broken link,
         error indicates broken link on windows */
      return conn;
    /* case 1: fall through */
  }

  if (connection_or_finished_connecting(conn) < 0) {
    /* already marked for close */
    return NULL;
  }
  return conn;
}

/** Begin the tls handshake with <b>conn</b>. <b>receiving</b> is 0 if
 * we initiated the connection, else it's 1.
 *
 * Assign a new tls object to conn->tls, begin reading on <b>conn</b>, and
 * pass <b>conn</b> to connection_tls_continue_handshake().
 *
 * Return -1 if <b>conn</b> is broken, else return 0.
 */
int
connection_tls_start_handshake(or_connection_t *conn, int receiving)
{
  conn->_base.state = OR_CONN_STATE_HANDSHAKING;
  conn->tls = tor_tls_new(conn->_base.s, receiving);
  if (!conn->tls) {
    log_warn(LD_BUG,"tor_tls_new failed. Closing.");
    return -1;
  }
  connection_start_reading(TO_CONN(conn));
  log_debug(LD_OR,"starting TLS handshake on fd %d", conn->_base.s);
  note_crypto_pk_op(receiving ? TLS_HANDSHAKE_S : TLS_HANDSHAKE_C);

  if (connection_tls_continue_handshake(conn) < 0) {
    return -1;
  }
  return 0;
}

/** Move forward with the tls handshake. If it finishes, hand
 * <b>conn</b> to connection_tls_finish_handshake().
 *
 * Return -1 if <b>conn</b> is broken, else return 0.
 */
int
connection_tls_continue_handshake(or_connection_t *conn)
{
  check_no_tls_errors();
  switch (tor_tls_handshake(conn->tls)) {
    CASE_TOR_TLS_ERROR_ANY:
      log_info(LD_OR,"tls error. breaking connection.");
      return -1;
    case TOR_TLS_DONE:
      return connection_tls_finish_handshake(conn);
    case TOR_TLS_WANTWRITE:
      connection_start_writing(TO_CONN(conn));
      log_debug(LD_OR,"wanted write");
      return 0;
    case TOR_TLS_WANTREAD: /* handshaking conns are *always* reading */
      log_debug(LD_OR,"wanted read");
      return 0;
    case TOR_TLS_CLOSE:
      log_info(LD_OR,"tls closed. breaking connection.");
      return -1;
  }
  return 0;
}

/** Return 1 if we initiated this connection, or 0 if it started
 * out as an incoming connection.
 *
 * This is implemented for now by checking to see if
 * conn-\>identity_digest is set or not. Perhaps we should add a flag
 * one day so we're clearer.
 */
int
connection_or_nonopen_was_started_here(or_connection_t *conn)
{
  tor_assert(conn->_base.type == CONN_TYPE_OR);
  if (!conn->tls)
    return 1; /* it's still in proxy states or something */
  return !tor_tls_is_server(conn->tls);
}

/** Conn just completed its handshake. Return 0 if all is well, and
 * return -1 if he is lying, broken, or otherwise something is wrong.
 *
 * Make sure he sent a correctly formed certificate. If it has a
 * recognized ("named") nickname, make sure his identity key matches
 * it. If I initiated the connection, make sure it's the right guy.
 *
 * If we return 0, write a hash of the identity key into digest_rcvd,
 * which must have DIGEST_LEN space in it. (If we return -1 this
 * buffer is undefined.)
 *
 * As side effects,
 * 1) Set conn->circ_id_type according to tor-spec.txt.
 * 2) If we're an authdirserver and we initiated the connection: drop all
 *    descriptors that claim to be on that IP/port but that aren't
 *    this guy; and note that this guy is reachable.
 */
static int
connection_or_check_valid_handshake(or_connection_t *conn, char *digest_rcvd)
{
  routerinfo_t *router;
  crypto_pk_env_t *identity_rcvd=NULL;
  char nickname[MAX_NICKNAME_LEN+1];
  or_options_t *options = get_options();
  int severity = server_mode(options) ? LOG_PROTOCOL_WARN : LOG_WARN;
  int started_here = connection_or_nonopen_was_started_here(conn);
  const char *safe_address =
    started_here ? conn->_base.address : safe_str(conn->_base.address);
  const char *peer_type = started_here ? "Router" : "Client or router";

  check_no_tls_errors();
  if (! tor_tls_peer_has_cert(conn->tls)) {
    log_info(LD_PROTOCOL,"%s (%s:%d) didn't send a cert! Closing.",
             peer_type, safe_address, conn->_base.port);
    return -1;
  }
  check_no_tls_errors();
  if (tor_tls_get_peer_cert_nickname(severity, conn->tls, nickname,
                                     sizeof(nickname))) {
    log_fn(severity,LD_PROTOCOL,"%s (%s:%d) has a cert without a "
           "valid nickname. Closing.",
           peer_type, safe_address, conn->_base.port);
    return -1;
  }
  check_no_tls_errors();
  log_debug(LD_OR, "%s (%s:%d) claims to be router '%s'",
            peer_type, safe_address, conn->_base.port, nickname);

  if (tor_tls_verify(severity, conn->tls, &identity_rcvd) < 0) {
    log_fn(severity,LD_OR,"%s which claims to be router '%s' (%s:%d),"
           " has a cert but it's invalid. Closing.",
           peer_type, nickname, safe_address, conn->_base.port);
    return -1;
  }
  check_no_tls_errors();
  log_debug(LD_OR,"The router's cert is valid.");
  crypto_pk_get_digest(identity_rcvd, digest_rcvd);

  if (crypto_pk_cmp_keys(get_identity_key(), identity_rcvd)<0) {
    conn->circ_id_type = CIRC_ID_TYPE_LOWER;
  } else {
    conn->circ_id_type = CIRC_ID_TYPE_HIGHER;
  }
  crypto_free_pk_env(identity_rcvd);

  router = router_get_by_nickname(nickname, 0);
  if (router && /* we know this nickname */
      router->is_named && /* make sure it's the right guy */
      memcmp(digest_rcvd, router->cache_info.identity_digest,DIGEST_LEN) !=0) {
    log_fn(severity, LD_OR,
           "Identity key not as expected for peer claiming to be "
           "'%s' (%s:%d)",
           nickname, safe_address, conn->_base.port);
    return -1;
  }

  if (started_here) {
    int as_advertised = 1;
    if (memcmp(digest_rcvd, conn->identity_digest, DIGEST_LEN)) {
      /* I was aiming for a particular digest. I didn't get it! */
      char seen[HEX_DIGEST_LEN+1];
      char expected[HEX_DIGEST_LEN+1];
      base16_encode(seen, sizeof(seen), digest_rcvd, DIGEST_LEN);
      base16_encode(expected, sizeof(expected), conn->identity_digest,
                    DIGEST_LEN);
      log_fn(severity, LD_OR,
             "Identity key not as expected for router at %s:%d: wanted %s "
             "but got %s",
             conn->_base.address, conn->_base.port, expected, seen);
      entry_guard_register_connect_status(conn->identity_digest,0,time(NULL));
      router_set_status(conn->identity_digest, 0);
      control_event_or_conn_status(conn, OR_CONN_EVENT_FAILED,
              END_OR_CONN_REASON_OR_IDENTITY);
      as_advertised = 0;
    }
    if (authdir_mode(options)) {
      /* We initiated this connection to address:port.  Drop all routers
       * with the same address:port and a different key or nickname.
       */
      dirserv_orconn_tls_done(conn->_base.address, conn->_base.port,
                              digest_rcvd, nickname, as_advertised);
    }
    if (!as_advertised)
      return -1;
  }
  return 0;
}

/** The tls handshake is finished.
 *
 * Make sure we are happy with the person we just handshaked with.
 *
 * If he initiated the connection, make sure he's not already connected,
 * then initialize conn from the information in router.
 *
 * If all is successful, call circuit_n_conn_done() to handle events
 * that have been pending on the <tls handshake completion. Also set the
 * directory to be dirty (only matters if I'm an authdirserver).
 */
static int
connection_tls_finish_handshake(or_connection_t *conn)
{
  char digest_rcvd[DIGEST_LEN];
  int started_here = connection_or_nonopen_was_started_here(conn);

  log_debug(LD_OR,"tls handshake done. verifying.");
  if (connection_or_check_valid_handshake(conn, digest_rcvd) < 0)
    return -1;

  if (!started_here) {
    connection_or_init_conn_from_address(conn,conn->_base.addr,
                                         conn->_base.port, digest_rcvd, 0);
  }

  directory_set_dirty();
  conn->_base.state = OR_CONN_STATE_OPEN;
  control_event_or_conn_status(conn, OR_CONN_EVENT_CONNECTED, 0);
  if (started_here) {
    rep_hist_note_connect_succeeded(conn->identity_digest, time(NULL));
    if (entry_guard_register_connect_status(conn->identity_digest, 1,
                                            time(NULL)) < 0) {
      /* pending circs get closed in circuit_about_to_close_connection() */
      return -1;
    }
    router_set_status(conn->identity_digest, 1);
  }
  connection_watch_events(TO_CONN(conn), EV_READ);
  circuit_n_conn_done(conn, 1); /* send the pending creates, if any. */
  return 0;
}

/** Pack <b>cell</b> into wire-format, and write it onto <b>conn</b>'s
 * outbuf.
 */
void
connection_or_write_cell_to_buf(const cell_t *cell, or_connection_t *conn)
{
  char networkcell[CELL_NETWORK_SIZE];
  char *n = networkcell;

  tor_assert(cell);
  tor_assert(conn);

  cell_pack(n, cell);

  connection_write_to_buf(n, CELL_NETWORK_SIZE, TO_CONN(conn));
}

/** Process cells from <b>conn</b>'s inbuf.
 *
 * Loop: while inbuf contains a cell, pull it off the inbuf, unpack it,
 * and hand it to command_process_cell().
 *
 * Always return 0.
 */
static int
connection_or_process_cells_from_inbuf(or_connection_t *conn)
{
  char buf[CELL_NETWORK_SIZE];
  cell_t cell;

loop:
  log_debug(LD_OR,
            "%d: starting, inbuf_datalen %d (%d pending in tls object).",
            conn->_base.s,(int)buf_datalen(conn->_base.inbuf),
            tor_tls_get_pending_bytes(conn->tls));
  if (buf_datalen(conn->_base.inbuf) < CELL_NETWORK_SIZE) /* whole response
                                                             available? */
    return 0; /* not yet */

  connection_fetch_from_buf(buf, CELL_NETWORK_SIZE, TO_CONN(conn));

  /* retrieve cell info from buf (create the host-order struct from the
   * network-order string) */
  cell_unpack(&cell, buf);

  command_process_cell(&cell, conn);

  goto loop; /* process the remainder of the buffer */
}

/** Write a destroy cell with circ ID <b>circ_id</b> and reason <b>reason</b>
 * onto OR connection <b>conn</b>.  Don't perform range-checking on reason:
 * we may want to propagate reasons from other cells.
 *
 * Return 0.
 */
int
connection_or_send_destroy(uint16_t circ_id, or_connection_t *conn, int reason)
{
  cell_t cell;

  tor_assert(conn);

  memset(&cell, 0, sizeof(cell_t));
  cell.circ_id = circ_id;
  cell.command = CELL_DESTROY;
  cell.payload[0] = (uint8_t) reason;
  log_debug(LD_OR,"Sending destroy (circID %d).", circ_id);
  connection_or_write_cell_to_buf(&cell, conn);
  return 0;
}

/* XXXX012 This global is getting _too_ global. -NM */
extern smartlist_t *circuits_pending_or_conns;

/** Count number of pending circs on an or_conn */
int
connection_or_count_pending_circs(or_connection_t *or_conn)
{
  int cnt = 0;

  if (!circuits_pending_or_conns)
    return 0;

  tor_assert(or_conn);

  SMARTLIST_FOREACH(circuits_pending_or_conns, circuit_t *, circ,
  {
    if (circ->marked_for_close)
      continue;
    tor_assert(circ->state == CIRCUIT_STATE_OR_WAIT);
    if (!circ->n_conn &&
        !memcmp(or_conn->identity_digest, circ->n_conn_id_digest,
                DIGEST_LEN)) {
      cnt++;
    }
  });

  log_debug(LD_CIRC,"or_conn to %s, %d pending circs",
            or_conn->nickname ? or_conn->nickname : "NULL", cnt);
  return cnt;
}

