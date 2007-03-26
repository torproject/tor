/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2007, Roger Dingledine, Nick Mathewson. */
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

static int connection_tls_finish_handshake(or_connection_t *conn);
static int connection_or_process_cells_from_inbuf(or_connection_t *conn);
static int connection_or_empty_enough_for_dirserv_data(or_connection_t *conn);

/**************************************************************/

/** Map from identity digest of connected OR or desired OR to a connection_t
 * with that identity digest.  If there is more than one such connection_t,
 * they form a linked list, with next_with_same_id as the next pointer. */
static digestmap_t *orconn_identity_map = NULL;

/** If conn is listed in orconn_identity_map, remove it, and clear
 * conn->identity_digest.  Otherwise do nothing. */
void
connection_or_remove_from_identity_map(or_connection_t *conn)
{
  or_connection_t *tmp;
  tor_assert(conn);
  if (!orconn_identity_map)
    return;
  tmp = digestmap_get(orconn_identity_map, conn->identity_digest);
  if (!tmp) {
    if (!tor_digest_is_zero(conn->identity_digest)) {
      log_warn(LD_BUG, "Didn't find connection on identity map when "
               "trying to remove it.");
    }
    return;
  }
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

  /* If the identity was set previously, remove the old mapping. */
  if (! tor_digest_is_zero(conn->identity_digest))
    connection_or_remove_from_identity_map(conn);

  memcpy(conn->identity_digest, digest, DIGEST_LEN);

  /* If we're setting the ID to zero, don't add a mapping. */
  if (tor_digest_is_zero(digest))
    return;

  tmp = digestmap_set(orconn_identity_map, digest, conn);
  conn->next_with_same_id = tmp;

#if 1
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

/** Called whenever we have flushed some data on an or_conn: add more data
 * from active circuits. */
int
connection_or_flushed_some(or_connection_t *conn)
{
  if (conn->blocked_dir_connections &&
      connection_or_empty_enough_for_dirserv_data(conn)) {
    connection_dirserv_stop_blocking_all_on_or_conn(conn);
  }
  if (buf_datalen(conn->_base.outbuf) < 16*1024) {
    int n = (32*1024 - buf_datalen(conn->_base.outbuf)) / CELL_NETWORK_SIZE;
    while (conn->active_circuits && n > 0) {
      int flushed;
      log_info(LD_GENERAL, "Loop, n==%d",n);
      flushed = connection_or_flush_from_first_active_circuit(conn, 1);
      n -= flushed;
    }
  }
  return 0;
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
      log_err(LD_BUG,"Called in unexpected state %d.", conn->_base.state);
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
 */
int
connection_or_nonopen_was_started_here(or_connection_t *conn)
{
  tor_assert(conn->_base.type == CONN_TYPE_OR);
  if (!conn->tls)
    return 1; /* it's still in proxy states or something */
  return !tor_tls_is_server(conn->tls);
}

/** <b>Conn</b> just completed its handshake. Return 0 if all is well, and
 * return -1 if he is lying, broken, or otherwise something is wrong.
 *
 * If we initiated this connection (<b>started_here</b> is true), make sure
 * the other side sent sent a correctly formed certificate. If I initiated the
 * connection, make sure it's the right guy.
 *
 * Otherwise (if we _didn't_ initiate this connection), it's okay for
 * the certificate to be weird or absent.
 *
 * If we return 0, and the certificate is as expected, write a hash of the
 * identity key into digest_rcvd, which must have DIGEST_LEN space in it. (If
 * we return -1 this buffer is undefined.)  If the certificate is invalid
 * or missing on an incoming connection, we return 0 and set digest_rcvd to
 * DIGEST_LEN 0 bytes.
 *
 * As side effects,
 * 1) Set conn->circ_id_type according to tor-spec.txt.
 * 2) If we're an authdirserver and we initiated the connection: drop all
 *    descriptors that claim to be on that IP/port but that aren't
 *    this guy; and note that this guy is reachable.
 */
static int
connection_or_check_valid_handshake(or_connection_t *conn, int started_here,
                                    char *digest_rcvd)
{
  crypto_pk_env_t *identity_rcvd=NULL;
  or_options_t *options = get_options();
  int severity = server_mode(options) ? LOG_PROTOCOL_WARN : LOG_WARN;
  const char *safe_address =
    started_here ? conn->_base.address : safe_str(conn->_base.address);
  const char *conn_type = started_here ? "outgoing" : "incoming";
  int has_cert = 0, has_identity = 0;

  check_no_tls_errors();
  has_cert = tor_tls_peer_has_cert(conn->tls);
  if (started_here && !has_cert) {
    log_info(LD_PROTOCOL,"Tried connecting to router at %s:%d, but it didn't "
             "send a cert! Closing.",
             safe_address, conn->_base.port);
    return -1;
  } else if (!has_cert) {
    log_debug(LD_PROTOCOL,"Got incoming connection with no certificate. "
              "That's ok.");
  }
  check_no_tls_errors();

  if (has_cert) {
    int v = tor_tls_verify(started_here?severity:LOG_INFO,
                           conn->tls, &identity_rcvd);
    if (started_here && v<0) {
      log_fn(severity,LD_OR,"Tried connecting to router at %s:%d: It"
             " has a cert but it's invalid. Closing.",
             safe_address, conn->_base.port);
      return -1;
    } else if (v<0) {
      log_info(LD_PROTOCOL,"Incoming connection gave us an invalid cert "
               "chain; ignoring.");
    } else {
      log_debug(LD_OR,"The certificate seems to be valid on %s connection "
                "with %s:%d", conn_type, safe_address, conn->_base.port);
    }
    check_no_tls_errors();
  }

  if (identity_rcvd) {
    has_identity=1;
    crypto_pk_get_digest(identity_rcvd, digest_rcvd);

    if (crypto_pk_cmp_keys(get_identity_key(), identity_rcvd)<0) {
      conn->circ_id_type = CIRC_ID_TYPE_LOWER;
    } else {
      conn->circ_id_type = CIRC_ID_TYPE_HIGHER;
    }
    crypto_free_pk_env(identity_rcvd);
  } else {
    memset(digest_rcvd, 0, DIGEST_LEN);
    conn->circ_id_type = CIRC_ID_TYPE_NEITHER;
  }

  if (started_here) {
    int as_advertised = 1;
    tor_assert(has_cert);
    tor_assert(has_identity);
    if (memcmp(digest_rcvd, conn->identity_digest, DIGEST_LEN)) {
      /* I was aiming for a particular digest. I didn't get it! */
      char seen[HEX_DIGEST_LEN+1];
      char expected[HEX_DIGEST_LEN+1];
      base16_encode(seen, sizeof(seen), digest_rcvd, DIGEST_LEN);
      base16_encode(expected, sizeof(expected), conn->identity_digest,
                    DIGEST_LEN);
      log_fn(severity, LD_OR,
             "Tried connecting to router at %s:%d, but identity key was not "
             "as expected: wanted %s but got %s.",
             conn->_base.address, conn->_base.port, expected, seen);
      entry_guard_register_connect_status(conn->identity_digest,0,time(NULL));
      router_set_status(conn->identity_digest, 0);
      control_event_or_conn_status(conn, OR_CONN_EVENT_FAILED,
              END_OR_CONN_REASON_OR_IDENTITY);
      as_advertised = 0;
    }
    if (authdir_mode(options)) {
      /* We initiated this connection to address:port.  Drop all routers
       * with the same address:port and a different key.
       */
      dirserv_orconn_tls_done(conn->_base.address, conn->_base.port,
                              digest_rcvd, as_advertised);
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
  if (connection_or_check_valid_handshake(conn, started_here, digest_rcvd) < 0)
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
  /* XXXX clear the rest of the cell queue on the circuit. {cells} */
  connection_or_write_cell_to_buf(&cell, conn);
  return 0;
}

/** A high waterlevel for whether to refill this OR connection
 * with more directory information, if any is pending. */
#define DIR_BUF_FULLNESS_THRESHOLD (128*1024)
/** A bottom waterlevel for whether to refill this OR connection
 * with more directory information, if any is pending. We don't want
 * to make this too low, since we already run the risk of starving
 * the pending dir connections if the OR conn is frequently busy with
 * other things. */
#define DIR_BUF_EMPTINESS_THRESHOLD (96*1024)

/** Return true iff there is so much data waiting to be flushed on <b>conn</b>
 * that we should stop writing directory data to it. */
int
connection_or_too_full_for_dirserv_data(or_connection_t *conn)
{
  return buf_datalen(conn->_base.outbuf) > DIR_BUF_FULLNESS_THRESHOLD;
}

/** Return true iff there is no longer so much data waiting to be flushed on
 * <b>conn</b> that we should not write directory data to it. */
static int
connection_or_empty_enough_for_dirserv_data(or_connection_t *conn)
{
  /* Note that the threshold to stop writing is a bit higher than the
   * threshold to start again: this should (with any luck) keep us from
   * flapping about indefinitely. */
  return buf_datalen(conn->_base.outbuf) < DIR_BUF_EMPTINESS_THRESHOLD;
}

