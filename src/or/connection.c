/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char connection_c_id[] =
  "$Id$";

/**
 * \file connection.c
 * \brief General high-level functions to handle reading and writing
 * on connections.
 **/

#include "or.h"

static connection_t *connection_create_listener(const char *listenaddress,
                                                uint16_t listenport, int type);
static int connection_init_accepted_conn(connection_t *conn,
                                         uint8_t listener_type);
static int connection_handle_listener_read(connection_t *conn, int new_type);
static int connection_read_bucket_should_increase(or_connection_t *conn);
static int connection_finished_flushing(connection_t *conn);
static int connection_flushed_some(connection_t *conn);
static int connection_finished_connecting(connection_t *conn);
static int connection_reached_eof(connection_t *conn);
static int connection_read_to_buf(connection_t *conn, int *max_to_read);
static int connection_process_inbuf(connection_t *conn, int package_partial);
static void client_check_address_changed(int sock);

static uint32_t last_interface_ip = 0;
static smartlist_t *outgoing_addrs = NULL;

/**************************************************************/

/**
 * Return the human-readable name for the connection type <b>type</b>
 */
const char *
conn_type_to_string(int type)
{
  static char buf[64];
  switch (type) {
    case CONN_TYPE_OR_LISTENER: return "OR listener";
    case CONN_TYPE_OR: return "OR";
    case CONN_TYPE_EXIT: return "Exit";
    case CONN_TYPE_AP_LISTENER: return "Socks listener";
    case CONN_TYPE_AP_TRANS_LISTENER:
      return "Transparent pf/netfilter listener";
    case CONN_TYPE_AP_NATD_LISTENER: return "Transparent natd listener";
    case CONN_TYPE_AP: return "Socks";
    case CONN_TYPE_DIR_LISTENER: return "Directory listener";
    case CONN_TYPE_DIR: return "Directory";
    case CONN_TYPE_DNSWORKER: return "DNS worker";
    case CONN_TYPE_CPUWORKER: return "CPU worker";
    case CONN_TYPE_CONTROL_LISTENER: return "Control listener";
    case CONN_TYPE_CONTROL: return "Control";
    default:
      log_warn(LD_BUG, "Bug: unknown connection type %d", type);
      tor_snprintf(buf, sizeof(buf), "unknown [%d]", type);
      return buf;
  }
}

/**
 * Return the human-readable name for the connection state <b>state</b>
 * for the connection type <b>type</b>
 */
const char *
conn_state_to_string(int type, int state)
{
  static char buf[96];
  switch (type) {
    case CONN_TYPE_OR_LISTENER:
    case CONN_TYPE_AP_LISTENER:
    case CONN_TYPE_AP_TRANS_LISTENER:
    case CONN_TYPE_AP_NATD_LISTENER:
    case CONN_TYPE_DIR_LISTENER:
    case CONN_TYPE_CONTROL_LISTENER:
      if (state == LISTENER_STATE_READY)
        return "ready";
      break;
    case CONN_TYPE_OR:
      switch (state) {
        case OR_CONN_STATE_CONNECTING: return "connect()ing";
        case OR_CONN_STATE_PROXY_FLUSHING: return "proxy flushing";
        case OR_CONN_STATE_PROXY_READING: return "proxy reading";
        case OR_CONN_STATE_HANDSHAKING: return "handshaking";
        case OR_CONN_STATE_OPEN: return "open";
      }
      break;
    case CONN_TYPE_EXIT:
      switch (state) {
        case EXIT_CONN_STATE_RESOLVING: return "waiting for dest info";
        case EXIT_CONN_STATE_CONNECTING: return "connecting";
        case EXIT_CONN_STATE_OPEN: return "open";
        case EXIT_CONN_STATE_RESOLVEFAILED: return "resolve failed";
      }
      break;
    case CONN_TYPE_AP:
      switch (state) {
        case AP_CONN_STATE_SOCKS_WAIT: return "waiting for dest info";
        case AP_CONN_STATE_NATD_WAIT: return "waiting for natd dest info";
        case AP_CONN_STATE_RENDDESC_WAIT: return "waiting for rendezvous desc";
        case AP_CONN_STATE_CONTROLLER_WAIT: return "waiting for controller";
        case AP_CONN_STATE_CIRCUIT_WAIT: return "waiting for safe circuit";
        case AP_CONN_STATE_CONNECT_WAIT: return "waiting for connect";
        case AP_CONN_STATE_RESOLVE_WAIT: return "waiting for resolve";
        case AP_CONN_STATE_OPEN: return "open";
      }
      break;
    case CONN_TYPE_DIR:
      switch (state) {
        case DIR_CONN_STATE_CONNECTING: return "connecting";
        case DIR_CONN_STATE_CLIENT_SENDING: return "client sending";
        case DIR_CONN_STATE_CLIENT_READING: return "client reading";
        case DIR_CONN_STATE_SERVER_COMMAND_WAIT: return "waiting for command";
        case DIR_CONN_STATE_SERVER_WRITING: return "writing";
      }
      break;
    case CONN_TYPE_DNSWORKER:
      switch (state) {
        case DNSWORKER_STATE_IDLE: return "idle";
        case DNSWORKER_STATE_BUSY: return "busy";
      }
      break;
    case CONN_TYPE_CPUWORKER:
      switch (state) {
        case CPUWORKER_STATE_IDLE: return "idle";
        case CPUWORKER_STATE_BUSY_ONION: return "busy with onion";
      }
      break;
    case CONN_TYPE_CONTROL:
      switch (state) {
        case CONTROL_CONN_STATE_OPEN_V0: return "open (protocol v0)";
        case CONTROL_CONN_STATE_OPEN_V1: return "open (protocol v1)";
        case CONTROL_CONN_STATE_NEEDAUTH_V0:
          return "waiting for authentication (protocol unknown)";
        case CONTROL_CONN_STATE_NEEDAUTH_V1:
          return "waiting for authentication (protocol v1)";
      }
      break;
  }

  log_warn(LD_BUG, "Bug: unknown connection state %d (type %d)", state, type);
  tor_snprintf(buf, sizeof(buf),
               "unknown state [%d] on unknown [%s] connection",
               state, conn_type_to_string(type));
  return buf;
}

/** Allocate space for a new connection_t. This function just initializes
 * conn; you must call connection_add() to link it into the main array.
 *
 * Set conn-\>type to <b>type</b>. Set conn-\>s and conn-\>conn_array_index to
 * -1 to signify they are not yet assigned.
 *
 * If conn is not a listener type, allocate buffers for it. If it's
 * an AP type, allocate space to store the socks_request.
 *
 * Assign a pseudorandom next_circ_id between 0 and 2**15.
 *
 * Initialize conn's timestamps to now.
 */
connection_t *
connection_new(int type)
{
  static uint32_t n_connections_allocated = 1;
  connection_t *conn;
  time_t now = time(NULL);
  size_t length;
  uint32_t magic;

  switch (type) {
    case CONN_TYPE_OR:
      length = sizeof(or_connection_t);
      magic = OR_CONNECTION_MAGIC;
      break;
    case CONN_TYPE_EXIT:
    case CONN_TYPE_AP:
      length = sizeof(edge_connection_t);
      magic = EDGE_CONNECTION_MAGIC;
      break;
    case CONN_TYPE_DIR:
      length = sizeof(dir_connection_t);
      magic = DIR_CONNECTION_MAGIC;
      break;
    case CONN_TYPE_CONTROL:
      length = sizeof(control_connection_t);
      magic = CONTROL_CONNECTION_MAGIC;
      break;
    default:
      length = sizeof(connection_t);
      magic = BASE_CONNECTION_MAGIC;
      break;
  }

  conn = tor_malloc_zero(length);
  conn->magic = magic;
  conn->s = -1; /* give it a default of 'not used' */
  conn->conn_array_index = -1; /* also default to 'not used' */

  conn->type = type;
  if (!connection_is_listener(conn)) { /* listeners never use their buf */
    conn->inbuf = buf_new();
    conn->outbuf = buf_new();
  }
  if (type == CONN_TYPE_AP) {
    TO_EDGE_CONN(conn)->socks_request =
      tor_malloc_zero(sizeof(socks_request_t));
  }
  if (CONN_IS_EDGE(conn)) {
    TO_EDGE_CONN(conn)->global_identifier = n_connections_allocated++;
  }
  if (type == CONN_TYPE_OR)
    TO_OR_CONN(conn)->next_circ_id = crypto_rand_int(1<<15);

  conn->timestamp_created = now;
  conn->timestamp_lastread = now;
  conn->timestamp_lastwritten = now;

  return conn;
}

/** Tell libevent that we don't care about <b>conn</b> any more. */
void
connection_unregister(connection_t *conn)
{
  if (conn->read_event) {
    if (event_del(conn->read_event))
      log_warn(LD_BUG, "Error removing read event for %d", conn->s);
    tor_free(conn->read_event);
  }
  if (conn->write_event) {
    if (event_del(conn->write_event))
      log_warn(LD_BUG, "Error removing write event for %d", conn->s);
    tor_free(conn->write_event);
  }
}

/** Deallocate memory used by <b>conn</b>. Deallocate its buffers if
 * necessary, close its socket if necessary, and mark the directory as dirty
 * if <b>conn</b> is an OR or OP connection.
 */
static void
_connection_free(connection_t *conn)
{
  void *mem;
  switch (conn->type) {
    case CONN_TYPE_OR:
      tor_assert(conn->magic == OR_CONNECTION_MAGIC);
      mem = TO_OR_CONN(conn);
      break;
    case CONN_TYPE_AP:
    case CONN_TYPE_EXIT:
      tor_assert(conn->magic == EDGE_CONNECTION_MAGIC);
      mem = TO_EDGE_CONN(conn);
      break;
    case CONN_TYPE_DIR:
      tor_assert(conn->magic == DIR_CONNECTION_MAGIC);
      mem = TO_DIR_CONN(conn);
      break;
    case CONN_TYPE_CONTROL:
      tor_assert(conn->magic == CONTROL_CONNECTION_MAGIC);
      mem = TO_CONTROL_CONN(conn);
      break;
    default:
      tor_assert(conn->magic == BASE_CONNECTION_MAGIC);
      mem = conn;
      break;
  }

  if (!connection_is_listener(conn)) {
    buf_free(conn->inbuf);
    buf_free(conn->outbuf);
  }

  tor_free(conn->address);

  if (connection_speaks_cells(conn)) {
    or_connection_t *or_conn = TO_OR_CONN(conn);
    if (or_conn->tls) {
      tor_tls_free(or_conn->tls);
      or_conn->tls = NULL;
    }

    tor_free(or_conn->nickname);
  }
  if (CONN_IS_EDGE(conn)) {
    edge_connection_t *edge_conn = TO_EDGE_CONN(conn);
    tor_free(edge_conn->chosen_exit_name);
    tor_free(edge_conn->socks_request);
  }
  if (conn->type == CONN_TYPE_CONTROL) {
    control_connection_t *control_conn = TO_CONTROL_CONN(conn);
    tor_free(control_conn->incoming_cmd);
  }

  tor_free(conn->read_event); /* Probably already freed by connection_free. */
  tor_free(conn->write_event); /* Probably already freed by connection_free. */

  if (conn->type == CONN_TYPE_DIR) {
    dir_connection_t *dir_conn = TO_DIR_CONN(conn);
    tor_free(dir_conn->requested_resource);
    if (dir_conn->zlib_state)
      tor_zlib_free(dir_conn->zlib_state);
    if (dir_conn->fingerprint_stack) {
      SMARTLIST_FOREACH(dir_conn->fingerprint_stack, char *, cp, tor_free(cp));
      smartlist_free(dir_conn->fingerprint_stack);
    }
    if (dir_conn->cached_dir)
      cached_dir_decref(dir_conn->cached_dir);
  }

  if (conn->s >= 0) {
    log_debug(LD_NET,"closing fd %d.",conn->s);
    tor_close_socket(conn->s);
  }

  if (conn->type == CONN_TYPE_OR &&
      !tor_digest_is_zero(TO_OR_CONN(conn)->identity_digest)) {
    log_warn(LD_BUG, "called on OR conn with non-zeroed identity_digest");
    connection_or_remove_from_identity_map(TO_OR_CONN(conn));
  }

  memset(conn, 0xAA, sizeof(connection_t)); /* poison memory */
  tor_free(mem);
}

/** Make sure <b>conn</b> isn't in any of the global conn lists; then free it.
 */
void
connection_free(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(!connection_is_on_closeable_list(conn));
  tor_assert(!connection_in_array(conn));
  if (connection_speaks_cells(conn)) {
    if (conn->state == OR_CONN_STATE_OPEN)
      directory_set_dirty();
    if (!tor_digest_is_zero(TO_OR_CONN(conn)->identity_digest)) {
      connection_or_remove_from_identity_map(TO_OR_CONN(conn));
    }
  }
  if (conn->type == CONN_TYPE_CONTROL) {
    TO_CONTROL_CONN(conn)->event_mask = 0;
    control_update_global_event_mask();
  }
  connection_unregister(conn);
  _connection_free(conn);
}

/** Call _connection_free() on every connection in our array, and release all
 * storage helpd by connection.c. This is used by cpuworkers and dnsworkers
 * when they fork, so they don't keep resources held open (especially
 * sockets).
 *
 * Don't do the checks in connection_free(), because they will
 * fail.
 */
void
connection_free_all(void)
{
  int i, n;
  connection_t **carray;

  get_connection_array(&carray,&n);

  /* We don't want to log any messages to controllers. */
  for (i=0;i<n;i++)
    if (carray[i]->type == CONN_TYPE_CONTROL)
      TO_CONTROL_CONN(carray[i])->event_mask = 0;
  control_update_global_event_mask();

  /* Unlink everything from the identity map. */
  connection_or_clear_identity_map();

  for (i=0;i<n;i++)
    _connection_free(carray[i]);

  if (outgoing_addrs) {
    SMARTLIST_FOREACH(outgoing_addrs, void*, addr, tor_free(addr));
    smartlist_free(outgoing_addrs);
    outgoing_addrs = NULL;
  }
}

/** Do any cleanup needed:
 *   - Directory conns that failed to fetch a rendezvous descriptor
 *     need to inform pending rendezvous streams.
 *   - OR conns need to call rep_hist_note_*() to record status.
 *   - AP conns need to send a socks reject if necessary.
 *   - Exit conns need to call connection_dns_remove() if necessary.
 *   - AP and Exit conns need to send an end cell if they can.
 *   - DNS conns need to fail any resolves that are pending on them.
 *   - OR and edge connections need to be unlinked from circuits.
 */
void
connection_about_to_close_connection(connection_t *conn)
{
  circuit_t *circ;
  dir_connection_t *dir_conn;
  or_connection_t *or_conn;
  edge_connection_t *edge_conn;
  time_t now = time(NULL);

  assert(conn->marked_for_close);

  if (CONN_IS_EDGE(conn)) {
    if (!conn->edge_has_sent_end) {
      log_warn(LD_BUG, "Harmless bug: Edge connection (marked at %s:%d) "
               "hasn't sent end yet?",
               conn->marked_for_close_file, conn->marked_for_close);
      tor_fragile_assert();
    }
  }

  switch (conn->type) {
    case CONN_TYPE_DIR:
      dir_conn = TO_DIR_CONN(conn);
      if (conn->state < DIR_CONN_STATE_CLIENT_FINISHED) {
        /* It's a directory connection and connecting or fetching
         * failed: forget about this router, and maybe try again. */
        connection_dir_request_failed(dir_conn);
        // XXX if it's rend desc we may want to retry -RD
      }
      if (conn->purpose == DIR_PURPOSE_FETCH_RENDDESC)
        rend_client_desc_here(dir_conn->rend_query); /* give it a try */
      break;
    case CONN_TYPE_OR:
      or_conn = TO_OR_CONN(conn);
      /* Remember why we're closing this connection. */
      if (conn->state != OR_CONN_STATE_OPEN) {
        if (connection_or_nonopen_was_started_here(or_conn)) {
          rep_hist_note_connect_failed(or_conn->identity_digest, now);
          entry_guard_register_connect_status(or_conn->identity_digest,0,now);
          router_set_status(or_conn->identity_digest, 0);
          control_event_or_conn_status(or_conn, OR_CONN_EVENT_FAILED, 
                  control_tls_error_to_reason(or_conn->tls_error));
        }
        /* Inform any pending (not attached) circs that they should
         * give up. */
        circuit_n_conn_done(TO_OR_CONN(conn), 0);
      } else if (conn->hold_open_until_flushed) {
        /* We only set hold_open_until_flushed when we're intentionally
         * closing a connection. */
        rep_hist_note_disconnect(or_conn->identity_digest, now);
        control_event_or_conn_status(or_conn, OR_CONN_EVENT_CLOSED,
                control_tls_error_to_reason(or_conn->tls_error));
      } else if (or_conn->identity_digest) {
        rep_hist_note_connection_died(or_conn->identity_digest, now);
        control_event_or_conn_status(or_conn, OR_CONN_EVENT_CLOSED,
                control_tls_error_to_reason(or_conn->tls_error));
      }
      /* Now close all the attached circuits on it. */
      circuit_unlink_all_from_or_conn(TO_OR_CONN(conn),
                                      END_CIRC_REASON_OR_CONN_CLOSED);
      break;
    case CONN_TYPE_AP:
      edge_conn = TO_EDGE_CONN(conn);
      if (edge_conn->socks_request->has_finished == 0) {
        /* since conn gets removed right after this function finishes,
         * there's no point trying to send back a reply at this point. */
        log_warn(LD_BUG,"Bug: Closing stream (marked at %s:%d) without sending"
                 " back a socks reply.",
                 conn->marked_for_close_file, conn->marked_for_close);
      }
      if (!edge_conn->end_reason) {
        // XXXX012 Disable this before 0.1.2.x-final ships.
        log_warn(LD_BUG,"Bug: Closing stream (marked at %s:%d) without having"
                 " set end_reason. Please tell Nick.",
                 conn->marked_for_close_file, conn->marked_for_close);
      }
      control_event_stream_status(edge_conn, STREAM_EVENT_CLOSED,
                                  edge_conn->end_reason);
      circ = circuit_get_by_edge_conn(edge_conn);
      if (circ)
        circuit_detach_stream(circ, edge_conn);
      break;
    case CONN_TYPE_EXIT:
      edge_conn = TO_EDGE_CONN(conn);
      circ = circuit_get_by_edge_conn(edge_conn);
      if (circ)
        circuit_detach_stream(circ, edge_conn);
      if (conn->state == EXIT_CONN_STATE_RESOLVING) {
        connection_dns_remove(edge_conn);
      }
      break;
    case CONN_TYPE_DNSWORKER:
      if (conn->state == DNSWORKER_STATE_BUSY) {
        dns_cancel_pending_resolve(conn->address);
      }
      break;
  }
}

/** Close the underlying socket for <b>conn</b>, so we don't try to
 * flush it. Must be used in conjunction with (right before)
 * connection_mark_for_close().
 */
void
connection_close_immediate(connection_t *conn)
{
  assert_connection_ok(conn,0);
  if (conn->s < 0) {
    log_err(LD_BUG,"Bug: Attempt to close already-closed connection.");
    tor_fragile_assert();
    return;
  }
  if (conn->outbuf_flushlen) {
    log_info(LD_NET,"fd %d, type %s, state %s, %d bytes on outbuf.",
             conn->s, conn_type_to_string(conn->type),
             conn_state_to_string(conn->type, conn->state),
             (int)conn->outbuf_flushlen);
  }

  connection_unregister(conn);

  tor_close_socket(conn->s);
  conn->s = -1;
  if (!connection_is_listener(conn)) {
    buf_clear(conn->outbuf);
    conn->outbuf_flushlen = 0;
  }
}

/** Mark <b>conn</b> to be closed next time we loop through
 * conn_close_if_marked() in main.c. */
void
_connection_mark_for_close(connection_t *conn, int line, const char *file)
{
  assert_connection_ok(conn,0);
  tor_assert(line);
  tor_assert(file);

  if (conn->marked_for_close) {
    log(LOG_WARN,LD_BUG,"Duplicate call to connection_mark_for_close at %s:%d"
        " (first at %s:%d)", file, line, conn->marked_for_close_file,
        conn->marked_for_close);
    tor_fragile_assert();
    return;
  }

  conn->marked_for_close = line;
  conn->marked_for_close_file = file;
  add_connection_to_closeable_list(conn);

  /* in case we're going to be held-open-til-flushed, reset
   * the number of seconds since last successful write, so
   * we get our whole 15 seconds */
  conn->timestamp_lastwritten = time(NULL);
}

/** Find each connection that has hold_open_until_flushed set to
 * 1 but hasn't written in the past 15 seconds, and set
 * hold_open_until_flushed to 0. This means it will get cleaned
 * up in the next loop through close_if_marked() in main.c.
 */
void
connection_expire_held_open(void)
{
  connection_t **carray, *conn;
  int n, i;
  time_t now;

  now = time(NULL);

  get_connection_array(&carray, &n);
  for (i = 0; i < n; ++i) {
    conn = carray[i];
    /* If we've been holding the connection open, but we haven't written
     * for 15 seconds...
     */
    if (conn->hold_open_until_flushed) {
      tor_assert(conn->marked_for_close);
      if (now - conn->timestamp_lastwritten >= 15) {
        int severity;
        if (conn->type == CONN_TYPE_EXIT ||
            (conn->type == CONN_TYPE_DIR &&
             conn->purpose == DIR_PURPOSE_SERVER))
          severity = LOG_INFO;
        else
          severity = LOG_NOTICE;
        log_fn(severity, LD_NET,
               "Giving up on marked_for_close conn that's been flushing "
               "for 15s (fd %d, type %s, state %s).",
               conn->s, conn_type_to_string(conn->type),
               conn_state_to_string(conn->type, conn->state));
        conn->hold_open_until_flushed = 0;
      }
    }
  }
}

/** Bind a new non-blocking socket listening to
 * <b>listenaddress</b>:<b>listenport</b>, and add this new connection
 * (of type <b>type</b>) to the connection array.
 *
 * If <b>listenaddress</b> includes a port, we bind on that port;
 * otherwise, we use listenport.
 */
static connection_t *
connection_create_listener(const char *listenaddress, uint16_t listenport,
                           int type)
{
  struct sockaddr_in listenaddr; /* where to bind */
  char *address = NULL;
  connection_t *conn;
  uint16_t usePort;
  uint32_t addr;
  int s; /* the socket we're going to make */
#ifndef MS_WINDOWS
  int one=1;
#endif

  memset(&listenaddr,0,sizeof(struct sockaddr_in));
  if (parse_addr_port(LOG_WARN, listenaddress, &address, &addr, &usePort)<0) {
    log_warn(LD_CONFIG,
             "Error parsing/resolving ListenAddress %s", listenaddress);
    return NULL;
  }

  if (usePort==0)
    usePort = listenport;
  listenaddr.sin_addr.s_addr = htonl(addr);
  listenaddr.sin_family = AF_INET;
  listenaddr.sin_port = htons((uint16_t) usePort);

  log_notice(LD_NET, "Opening %s on %s:%d",
             conn_type_to_string(type), address, usePort);

  s = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
  if (s < 0) {
    log_warn(LD_NET,"Socket creation failed.");
    goto err;
  }

#ifndef MS_WINDOWS
  /* REUSEADDR on normal places means you can rebind to the port
   * right after somebody else has let it go. But REUSEADDR on win32
   * means you can bind to the port _even when somebody else
   * already has it bound_. So, don't do that on Win32. */
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void*) &one, sizeof(one));
#endif

  if (bind(s,(struct sockaddr *)&listenaddr,sizeof(listenaddr)) < 0) {
    const char *helpfulhint = "";
    int e = tor_socket_errno(s);
    if (ERRNO_IS_EADDRINUSE(e))
      helpfulhint = ". Is Tor already running?";
    log_warn(LD_NET, "Could not bind to %s:%u: %s%s", address, usePort,
             tor_socket_strerror(e), helpfulhint);
    tor_close_socket(s);
    goto err;
  }

  if (listen(s,SOMAXCONN) < 0) {
    log_warn(LD_NET, "Could not listen on %s:%u: %s", address, usePort,
             tor_socket_strerror(tor_socket_errno(s)));
    tor_close_socket(s);
    goto err;
  }

  set_socket_nonblocking(s);

  conn = connection_new(type);
  conn->s = s;
  conn->address = address;
  address = NULL;
  conn->port = usePort;

  if (connection_add(conn) < 0) { /* no space, forget it */
    log_warn(LD_NET,"connection_add for listener failed. Giving up.");
    connection_free(conn);
    goto err;
  }

  log_debug(LD_NET,"%s listening on port %u.",
            conn_type_to_string(type), usePort);

  conn->state = LISTENER_STATE_READY;
  connection_start_reading(conn);

  return conn;

 err:
  tor_free(address);
  return NULL;
}

/** Do basic sanity checking on a newly received socket. Return 0
 * if it looks ok, else return -1. */
static int
check_sockaddr_in(struct sockaddr *sa, int len, int level)
{
  int ok = 1;
  struct sockaddr_in *sin=(struct sockaddr_in*)sa;

  if (len != sizeof(struct sockaddr_in)) {
    log_fn(level, LD_NET, "Length of address not as expected: %d vs %d",
           len,(int)sizeof(struct sockaddr_in));
    ok = 0;
  }
  if (sa->sa_family != AF_INET) {
    log_fn(level, LD_NET, "Family of address not as expected: %d vs %d",
           sa->sa_family, AF_INET);
    ok = 0;
  }
  if (sin->sin_addr.s_addr == 0 || sin->sin_port == 0) {
    log_fn(level, LD_NET,
           "Address for new connection has address/port equal to zero.");
    ok = 0;
  }
  return ok ? 0 : -1;
}

/** The listener connection <b>conn</b> told poll() it wanted to read.
 * Call accept() on conn-\>s, and add the new connection if necessary.
 */
static int
connection_handle_listener_read(connection_t *conn, int new_type)
{
  int news; /* the new socket */
  connection_t *newconn;
  /* information about the remote peer when connecting to other routers */
  struct sockaddr_in remote;
  char addrbuf[256];
  /* length of the remote address. Must be whatever accept() needs. */
  socklen_t remotelen = 256;
  char tmpbuf[INET_NTOA_BUF_LEN];
  tor_assert((size_t)remotelen >= sizeof(struct sockaddr_in));
  memset(addrbuf, 0, sizeof(addrbuf));

  news = accept(conn->s,(struct sockaddr *)&addrbuf,&remotelen);
  if (news < 0) { /* accept() error */
    int e = tor_socket_errno(conn->s);
    if (ERRNO_IS_ACCEPT_EAGAIN(e)) {
      return 0; /* he hung up before we could accept(). that's fine. */
    } else if (ERRNO_IS_ACCEPT_RESOURCE_LIMIT(e)) {
      log_notice(LD_NET,"accept failed: %s. Dropping incoming connection.",
                 tor_socket_strerror(e));
      return 0;
    }
    /* else there was a real error. */
    log_warn(LD_NET,"accept() failed: %s. Closing listener.",
             tor_socket_strerror(e));
    connection_mark_for_close(conn);
    return -1;
  }
  log_debug(LD_NET,
            "Connection accepted on socket %d (child of fd %d).",
            news,conn->s);

  set_socket_nonblocking(news);

  if (check_sockaddr_in((struct sockaddr*)addrbuf, remotelen, LOG_INFO)<0) {
    log_info(LD_NET,
             "accept() returned a strange address; trying getsockname().");
    remotelen=256;
    memset(addrbuf, 0, sizeof(addrbuf));
    if (getsockname(news, (struct sockaddr*)addrbuf, &remotelen)<0) {
      int e = tor_socket_errno(news);
      log_warn(LD_NET, "getsockname() for new connection failed: %s",
               tor_socket_strerror(e));
    } else {
      if (check_sockaddr_in((struct sockaddr*)addrbuf, remotelen,
                            LOG_WARN) < 0) {
        log_warn(LD_NET,"Something's wrong with this conn. Closing it.");
        tor_close_socket(news);
        return 0;
      }
    }
  }
  memcpy(&remote, addrbuf, sizeof(struct sockaddr_in));

  /* process entrance policies here, before we even create the connection */
  if (new_type == CONN_TYPE_AP) {
    /* check sockspolicy to see if we should accept it */
    if (socks_policy_permits_address(ntohl(remote.sin_addr.s_addr)) == 0) {
      tor_inet_ntoa(&remote.sin_addr, tmpbuf, sizeof(tmpbuf));
      log_notice(LD_APP,"Denying socks connection from untrusted address %s.",
                 tmpbuf);
      tor_close_socket(news);
      return 0;
    }
  }
  if (new_type == CONN_TYPE_DIR) {
    /* check dirpolicy to see if we should accept it */
    if (dir_policy_permits_address(ntohl(remote.sin_addr.s_addr)) == 0) {
      tor_inet_ntoa(&remote.sin_addr, tmpbuf, sizeof(tmpbuf));
      log_notice(LD_DIRSERV,"Denying dir connection from address %s.",
                 tmpbuf);
      tor_close_socket(news);
      return 0;
    }
  }

  newconn = connection_new(new_type);
  newconn->s = news;

  /* remember the remote address */
  newconn->addr = ntohl(remote.sin_addr.s_addr);
  newconn->port = ntohs(remote.sin_port);
  newconn->address = tor_dup_addr(newconn->addr);

  if (connection_add(newconn) < 0) { /* no space, forget it */
    connection_free(newconn);
    return 0; /* no need to tear down the parent */
  }

  if (connection_init_accepted_conn(newconn, conn->type) < 0) {
    connection_mark_for_close(newconn);
    return 0;
  }
  return 0;
}

/** Initialize states for newly accepted connection <b>conn</b>.
 * If conn is an OR, start the tls handshake.
 * If conn is a transparent AP, get its original destination
 * and place it in circuit_wait.
 */
static int
connection_init_accepted_conn(connection_t *conn, uint8_t listener_type)
{
  connection_start_reading(conn);

  switch (conn->type) {
    case CONN_TYPE_OR:
      control_event_or_conn_status(TO_OR_CONN(conn), OR_CONN_EVENT_NEW, 0);
      return connection_tls_start_handshake(TO_OR_CONN(conn), 1);
    case CONN_TYPE_AP:
      switch (listener_type) {
        case CONN_TYPE_AP_LISTENER:
          conn->state = AP_CONN_STATE_SOCKS_WAIT;
          break;
        case CONN_TYPE_AP_TRANS_LISTENER:
          conn->state = AP_CONN_STATE_CIRCUIT_WAIT;
          return connection_ap_process_transparent(TO_EDGE_CONN(conn));
        case CONN_TYPE_AP_NATD_LISTENER:
          conn->state = AP_CONN_STATE_NATD_WAIT;
          break;
      }
      break;
    case CONN_TYPE_DIR:
      conn->purpose = DIR_PURPOSE_SERVER;
      conn->state = DIR_CONN_STATE_SERVER_COMMAND_WAIT;
      break;
    case CONN_TYPE_CONTROL:
      conn->state = CONTROL_CONN_STATE_NEEDAUTH_V0;
      break;
  }
  return 0;
}

/** Take conn, make a nonblocking socket; try to connect to
 * addr:port (they arrive in *host order*). If fail, return -1. Else
 * assign s to conn-\>s: if connected return 1, if EAGAIN return 0.
 *
 * address is used to make the logs useful.
 *
 * On success, add conn to the list of polled connections.
 */
int
connection_connect(connection_t *conn, char *address,
                   uint32_t addr, uint16_t port)
{
  int s, inprogress = 0;
  struct sockaddr_in dest_addr;
  or_options_t *options = get_options();

  s = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
  if (s < 0) {
    log_warn(LD_NET,"Error creating network socket: %s",
             tor_socket_strerror(tor_socket_errno(-1)));
    return -1;
  }

  if (options->OutboundBindAddress) {
    struct sockaddr_in ext_addr;

    memset(&ext_addr, 0, sizeof(ext_addr));
    ext_addr.sin_family = AF_INET;
    ext_addr.sin_port = 0;
    if (!tor_inet_aton(options->OutboundBindAddress, &ext_addr.sin_addr)) {
      log_warn(LD_CONFIG,"Outbound bind address '%s' didn't parse. Ignoring.",
               options->OutboundBindAddress);
    } else {
      if (bind(s, (struct sockaddr*)&ext_addr, sizeof(ext_addr)) < 0) {
        log_warn(LD_NET,"Error binding network socket: %s",
                 tor_socket_strerror(tor_socket_errno(s)));
        tor_close_socket(s);
        return -1;
      }
    }
  }

  set_socket_nonblocking(s);

  memset(&dest_addr,0,sizeof(dest_addr));
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(port);
  dest_addr.sin_addr.s_addr = htonl(addr);

  log_debug(LD_NET,"Connecting to %s:%u.",escaped_safe_str(address),port);

  if (connect(s,(struct sockaddr *)&dest_addr,sizeof(dest_addr)) < 0) {
    int e = tor_socket_errno(s);
    if (!ERRNO_IS_CONN_EINPROGRESS(e)) {
      /* yuck. kill it. */
      log_info(LD_NET,
               "connect() to %s:%u failed: %s",escaped_safe_str(address),
               port, tor_socket_strerror(e));
      tor_close_socket(s);
      return -1;
    } else {
      inprogress = 1;
    }
  }

  if (!server_mode(options))
    client_check_address_changed(s);

  /* it succeeded. we're connected. */
  log_fn(inprogress?LOG_DEBUG:LOG_INFO, LD_NET,
         "Connection to %s:%u %s (sock %d).",escaped_safe_str(address),
         port, inprogress?"in progress":"established", s);
  conn->s = s;
  if (connection_add(conn) < 0) /* no space, forget it */
    return -1;
  return inprogress ? 0 : 1;
}

/**
 * Launch any configured listener connections of type <b>type</b>.  (A
 * listener is configured if <b>port_option</b> is non-zero.  If any
 * ListenAddress configuration options are given in <b>cfg</b>, create a
 * connection binding to each one.  Otherwise, create a single
 * connection binding to the address <b>default_addr</b>.)
 *
 * If <b>force</b> is true, close and re-open all listener connections.
 * Otherwise, only relaunch the listeners of this type if the number of
 * existing connections is not as configured (e.g., because one died),
 * or if the existing connections do not match those configured.
 *
 * Add all old conns that should be closed to <b>replaced_conns</b>.
 * Add all new connections to <b>new_conns</b>.
 */
static int
retry_listeners(int type, config_line_t *cfg,
                int port_option, const char *default_addr, int force,
                smartlist_t *replaced_conns,
                smartlist_t *new_conns,
                int never_open_conns)
{
  smartlist_t *launch = smartlist_create();
  int free_launch_elts = 1;
  config_line_t *c;
  int n_conn, i;
  connection_t *conn;
  connection_t **carray;
  config_line_t *line;

  if (cfg && port_option) {
    for (c = cfg; c; c = c->next) {
      smartlist_add(launch, c);
    }
    free_launch_elts = 0;
  } else if (port_option) {
    line = tor_malloc_zero(sizeof(config_line_t));
    line->key = tor_strdup("");
    line->value = tor_strdup(default_addr);
    smartlist_add(launch, line);
  }

  /*
  SMARTLIST_FOREACH(launch, config_line_t *, l,
                    log_fn(LOG_NOTICE, "#%s#%s", l->key, l->value));
  */

  get_connection_array(&carray,&n_conn);
  for (i=0; i < n_conn; ++i) {
    conn = carray[i];
    if (conn->type != type || conn->marked_for_close)
      continue;
    if (force) {
      /* It's a listener, and we're relaunching all listeners of this
       * type. Close this one. */
      log_notice(LD_NET, "Force-closing listener %s on %s:%d",
             conn_type_to_string(type), conn->address, conn->port);
      connection_close_immediate(conn);
      connection_mark_for_close(conn);
      continue;
    }
    /* Okay, so this is a listener.  Is it configured? */
    line = NULL;
    SMARTLIST_FOREACH(launch, config_line_t *, wanted,
      {
        char *address=NULL;
        uint16_t port;
        if (!parse_addr_port(LOG_WARN, wanted->value, &address, NULL, &port)) {
          int addr_matches = !strcasecmp(address, conn->address);
          tor_free(address);
          if (! port)
            port = port_option;
          if (port == conn->port && addr_matches) {
            line = wanted;
            break;
          }
        }
      });
    if (! line) {
      /* This one isn't configured. Close it. */
      log_notice(LD_NET, "Closing no-longer-configured %s on %s:%d",
                 conn_type_to_string(type), conn->address, conn->port);
      if (replaced_conns) {
        smartlist_add(replaced_conns, conn);
      } else {
        connection_close_immediate(conn);
        connection_mark_for_close(conn);
      }
    } else {
      /* It's configured; we don't need to launch it. */
//      log_debug(LD_NET, "Already have %s on %s:%d",
//                conn_type_to_string(type), conn->address, conn->port);
      smartlist_remove(launch, line);
      if (free_launch_elts)
        config_free_lines(line);
    }
  }

  /* Now open all the listeners that are configured but not opened. */
  i = 0;
  if (!never_open_conns) {
    SMARTLIST_FOREACH(launch, config_line_t *, cfg,
      {
        conn = connection_create_listener(cfg->value, (uint16_t) port_option,
                                          type);
        if (!conn) {
          i = -1;
        } else {
          if (new_conns)
            smartlist_add(new_conns, conn);
        }
    });
  }

  if (free_launch_elts) {
    SMARTLIST_FOREACH(launch, config_line_t *, cfg,
                      config_free_lines(cfg));
  }
  smartlist_free(launch);

  return i;
}

/** (Re)launch listeners for each port you should have open.  If
 * <b>force</b> is true, close and relaunch all listeners. If <b>force</b>
 * is false, then only relaunch listeners when we have the wrong number of
 * connections for a given type.
 *
 * Add all old conns that should be closed to <b>replaced_conns</b>.
 * Add all new connections to <b>new_conns</b>.
 */
int
retry_all_listeners(int force, smartlist_t *replaced_conns,
                    smartlist_t *new_conns)
{
  or_options_t *options = get_options();

  if (retry_listeners(CONN_TYPE_OR_LISTENER, options->ORListenAddress,
                      options->ORPort, "0.0.0.0", force,
                      replaced_conns, new_conns, options->ClientOnly)<0)
    return -1;
  if (retry_listeners(CONN_TYPE_DIR_LISTENER, options->DirListenAddress,
                      options->DirPort, "0.0.0.0", force,
                      replaced_conns, new_conns, 0)<0)
    return -1;
  if (retry_listeners(CONN_TYPE_AP_LISTENER, options->SocksListenAddress,
                      options->SocksPort, "127.0.0.1", force,
                      replaced_conns, new_conns, 0)<0)
    return -1;
  if (retry_listeners(CONN_TYPE_AP_TRANS_LISTENER, options->TransListenAddress,
                      options->TransPort, "127.0.0.1", force,
                      replaced_conns, new_conns, 0)<0)
    return -1;
  if (retry_listeners(CONN_TYPE_AP_NATD_LISTENER, options->NatdListenAddress,
                      options->NatdPort, "127.0.0.1", force,
                      replaced_conns, new_conns, 0)<0)
    return -1;
  if (retry_listeners(CONN_TYPE_CONTROL_LISTENER,
                      options->ControlListenAddress,
                      options->ControlPort, "127.0.0.1", force,
                      replaced_conns, new_conns, 0)<0)
    return -1;

  return 0;
}

extern int global_read_bucket, global_write_bucket;

static int
connection_bucket_round_robin(int base, int priority,
                              int global_bucket, int conn_bucket)
{
  int at_most;
  int num_bytes_high = (priority ? 32 : 16) * base;
  int num_bytes_low = (priority ? 4 : 2) * base;

  /* Do a rudimentary round-robin so one circuit can't hog a connection.
   * Pick at most 32 cells, at least 4 cells if possible, and if we're in
   * the middle pick 1/8 of the available bandwidth. */
  at_most = global_bucket / 8;
  at_most -= (at_most % base); /* round down */
  if (at_most > num_bytes_high) /* 16 KB, or 8 KB for low-priority */
    at_most = num_bytes_high;
  else if (at_most < num_bytes_low) /* 2 KB, or 1 KB for low-priority */
    at_most = num_bytes_low;

  if (at_most > global_bucket)
    at_most = global_bucket;

  if (conn_bucket >= 0 && at_most > conn_bucket)
    at_most = conn_bucket;

  if (at_most < 0)
    return 0;
  return at_most;
}

/** How many bytes at most can we read onto this connection? */
static int
connection_bucket_read_limit(connection_t *conn)
{
  int base = connection_speaks_cells(conn) ?
               CELL_NETWORK_SIZE : RELAY_PAYLOAD_SIZE;
  int priority = conn->type != CONN_TYPE_DIR;
  int conn_bucket = -1;
  if (connection_speaks_cells(conn) && conn->state == OR_CONN_STATE_OPEN) {
    or_connection_t *or_conn = TO_OR_CONN(conn);
    conn_bucket = or_conn->read_bucket;
  }
  return connection_bucket_round_robin(base, priority,
                                       global_read_bucket, conn_bucket);
}

/** How many bytes at most can we write onto this connection? */
int
connection_bucket_write_limit(connection_t *conn)
{
  int base = connection_speaks_cells(conn) ?
               CELL_NETWORK_SIZE : RELAY_PAYLOAD_SIZE;
  int priority = conn->type != CONN_TYPE_DIR;

  return connection_bucket_round_robin(base, priority, global_write_bucket,
                                       conn->outbuf_flushlen);
}

/** Return 1 if the global write bucket is low enough that we shouldn't
 * send <b>attempt</b> bytes of low-priority directory stuff out.
 * Else return 0.

 * Priority is 1 for v1 requests (directories and running-routers),
 * and 2 for v2 requests (statuses and descriptors). But see FFFF in
 * directory_handle_command_get() for why we don't use priority 2 yet.
 *
 * There are a lot of parameters we could use here:
 * - global_write_bucket. Low is bad.
 * - bandwidthrate. Low is bad.
 * - bandwidthburst. Not a big factor?
 * - attempt. High is bad.
 * - total bytes queued on outbufs. High is bad. But I'm wary of
 *   using this, since a few slow-flushing queues will pump up the
 *   number without meaning what we meant to mean. What we really
 *   mean is "total directory bytes added to outbufs recently", but
 *   that's harder to quantify and harder to keep track of.
 */
int
global_write_bucket_low(size_t attempt, int priority)
{
  if (authdir_mode(get_options()) && priority>1)
    return 0; /* there's always room to answer v2 if we're an auth dir */

  if (global_write_bucket < (int)attempt)
    return 1; /* not enough space no matter the priority */

  if (priority == 1) { /* old-style v1 query */
    /* Could we handle *two* of these requests within the next two seconds? */
    int64_t can_write = (int64_t)global_write_bucket
      + 2*get_options()->BandwidthRate;
    if (can_write < 2*(int64_t)attempt)
      return 1;
  } else { /* v2 query */
    /* no further constraints yet */
  }
  return 0;
}

/** We just read num_read onto conn. Decrement buckets appropriately. */
static void
connection_read_bucket_decrement(connection_t *conn, int num_read)
{
  global_read_bucket -= num_read;
  if (connection_speaks_cells(conn) && conn->state == OR_CONN_STATE_OPEN) {
    TO_OR_CONN(conn)->read_bucket -= num_read;
  }
}

/** If we have exhausted our global buckets, or the buckets for conn,
 * stop reading. */
static void
connection_consider_empty_read_buckets(connection_t *conn)
{
  if (global_read_bucket <= 0) {
    LOG_FN_CONN(conn, (LOG_DEBUG,LD_NET,
                       "global read bucket exhausted. Pausing."));
    conn->wants_to_read = 1;
    connection_stop_reading(conn);
    return;
  }
  if (connection_speaks_cells(conn) &&
      conn->state == OR_CONN_STATE_OPEN &&
      TO_OR_CONN(conn)->read_bucket <= 0) {
    LOG_FN_CONN(conn,
                (LOG_DEBUG,LD_NET,"read bucket exhausted. Pausing."));
    conn->wants_to_read = 1;
    connection_stop_reading(conn);
  }
}

/** If we have exhausted our global buckets, or the buckets for conn,
 * stop writing. */
static void
connection_consider_empty_write_buckets(connection_t *conn)
{
  if (global_write_bucket <= 0) {
    LOG_FN_CONN(conn, (LOG_DEBUG,LD_NET,
                       "global write bucket exhausted. Pausing."));
    conn->wants_to_write = 1;
    connection_stop_writing(conn);
    return;
  }
#if 0
  if (connection_speaks_cells(conn) &&
      conn->state == OR_CONN_STATE_OPEN &&
      TO_OR_CONN(conn)->write_bucket <= 0) {
    LOG_FN_CONN(conn,
                (LOG_DEBUG,LD_NET,"write bucket exhausted. Pausing."));
    conn->wants_to_write = 1;
    connection_stop_writing(conn);
  }
#endif
}

/** Initialize the global read bucket to options->BandwidthBurst. */
void
connection_bucket_init(void)
{
  or_options_t *options = get_options();
  /* start it at max traffic */
  global_read_bucket = (int)options->BandwidthBurst;
  global_write_bucket = (int)options->BandwidthBurst;
}

/** A second has rolled over; increment buckets appropriately. */
void
connection_bucket_refill(int seconds_elapsed)
{
  int i, n;
  connection_t *conn;
  connection_t **carray;
  or_options_t *options = get_options();

  /* refill the global buckets */
  if (global_read_bucket < (int)options->BandwidthBurst) {
    global_read_bucket += (int)options->BandwidthRate*seconds_elapsed;
    if (global_read_bucket > (int)options->BandwidthBurst)
      global_read_bucket = (int)options->BandwidthBurst;
    log(LOG_DEBUG, LD_NET,"global_read_bucket now %d.", global_read_bucket);
  }
  if (global_write_bucket < (int)options->BandwidthBurst) {
    global_write_bucket += (int)options->BandwidthRate*seconds_elapsed;
    if (global_write_bucket > (int)options->BandwidthBurst)
      global_write_bucket = (int)options->BandwidthBurst;
    log(LOG_DEBUG, LD_NET,"global_write_bucket now %d.", global_write_bucket);
  }

  /* refill the per-connection buckets */
  get_connection_array(&carray,&n);
  for (i=0;i<n;i++) {
    conn = carray[i];

    if (connection_speaks_cells(conn)) {
      or_connection_t *or_conn = TO_OR_CONN(conn);
      if (connection_read_bucket_should_increase(or_conn)) {
        or_conn->read_bucket += or_conn->bandwidthrate*seconds_elapsed;
        if (or_conn->read_bucket > or_conn->bandwidthburst)
          or_conn->read_bucket = or_conn->bandwidthburst;
        //log_fn(LOG_DEBUG,"Receiver bucket %d now %d.", i,
        //       conn->read_bucket);
      }
    }

    if (conn->wants_to_read == 1 /* it's marked to turn reading back on now */
        && global_read_bucket > 0 /* and we're allowed to read */
        && (!connection_speaks_cells(conn) ||
            conn->state != OR_CONN_STATE_OPEN ||
            TO_OR_CONN(conn)->read_bucket > 0)) {
        /* and either a non-cell conn or a cell conn with non-empty bucket */
      LOG_FN_CONN(conn, (LOG_DEBUG,LD_NET,
                         "waking up conn (fd %d) for read",conn->s));
      conn->wants_to_read = 0;
      connection_start_reading(conn);
    }
    if (conn->wants_to_write == 1 &&
        global_write_bucket > 0) { /* and we're allowed to write */
      LOG_FN_CONN(conn, (LOG_DEBUG,LD_NET,
                         "waking up conn (fd %d) for write",conn->s));
      conn->wants_to_write = 0;
      connection_start_writing(conn);
    }
  }
}

/** Is the receiver bucket for connection <b>conn</b> low enough that we
 * should add another pile of tokens to it?
 */
static int
connection_read_bucket_should_increase(or_connection_t *conn)
{
  tor_assert(conn);

  if (conn->_base.state != OR_CONN_STATE_OPEN)
    return 0; /* only open connections play the rate limiting game */
  if (conn->read_bucket >= conn->bandwidthburst)
    return 0;

  return 1;
}

/** Read bytes from conn-\>s and process them.
 *
 * This function gets called from conn_read() in main.c, either
 * when poll() has declared that conn wants to read, or (for OR conns)
 * when there are pending TLS bytes.
 *
 * It calls connection_read_to_buf() to bring in any new bytes,
 * and then calls connection_process_inbuf() to process them.
 *
 * Mark the connection and return -1 if you want to close it, else
 * return 0.
 */
int
connection_handle_read(connection_t *conn)
{
  int max_to_read=-1, try_to_read;

  if (conn->marked_for_close)
    return 0; /* do nothing */

  conn->timestamp_lastread = time(NULL);

  switch (conn->type) {
    case CONN_TYPE_OR_LISTENER:
      return connection_handle_listener_read(conn, CONN_TYPE_OR);
    case CONN_TYPE_AP_LISTENER:
    case CONN_TYPE_AP_TRANS_LISTENER:
    case CONN_TYPE_AP_NATD_LISTENER:
      return connection_handle_listener_read(conn, CONN_TYPE_AP);
    case CONN_TYPE_DIR_LISTENER:
      return connection_handle_listener_read(conn, CONN_TYPE_DIR);
    case CONN_TYPE_CONTROL_LISTENER:
      return connection_handle_listener_read(conn, CONN_TYPE_CONTROL);
  }

loop_again:
  try_to_read = max_to_read;
  tor_assert(!conn->marked_for_close);
  if (connection_read_to_buf(conn, &max_to_read) < 0) {
    /* There's a read error; kill the connection.*/
    connection_close_immediate(conn); /* Don't flush; connection is dead. */
    if (CONN_IS_EDGE(conn)) {
      edge_connection_t *edge_conn = TO_EDGE_CONN(conn);
      connection_edge_end_errno(edge_conn, edge_conn->cpath_layer);
      if (edge_conn->socks_request) /* broken, don't send a socks reply back */
        edge_conn->socks_request->has_finished = 1;
    }
    connection_mark_for_close(conn);
    return -1;
  }
  if (CONN_IS_EDGE(conn) && try_to_read != max_to_read) {
    /* instruct it not to try to package partial cells. */
    if (connection_process_inbuf(conn, 0) < 0) {
      return -1;
    }
    if (!conn->marked_for_close &&
        connection_is_reading(conn) &&
        !conn->inbuf_reached_eof &&
        max_to_read > 0)
      goto loop_again; /* try reading again, in case more is here now */
  }
  /* one last try, packaging partial cells and all. */
  if (!conn->marked_for_close &&
      connection_process_inbuf(conn, 1) < 0) {
    return -1;
  }
  if (!conn->marked_for_close &&
      conn->inbuf_reached_eof &&
      connection_reached_eof(conn) < 0) {
    return -1;
  }
  return 0;
}

/** Pull in new bytes from conn-\>s onto conn-\>inbuf, either
 * directly or via TLS. Reduce the token buckets by the number of
 * bytes read.
 *
 * If *max_to_read is -1, then decide it ourselves, else go with the
 * value passed to us. When returning, if it's changed, subtract the
 * number of bytes we read from *max_to_read.
 *
 * Return -1 if we want to break conn, else return 0.
 */
static int
connection_read_to_buf(connection_t *conn, int *max_to_read)
{
  int result, at_most = *max_to_read;
  size_t bytes_in_buf, more_to_read;
  size_t n_read = 0, n_written = 0;

  if (at_most == -1) { /* we need to initialize it */
    /* how many bytes are we allowed to read? */
    at_most = connection_bucket_read_limit(conn);
  }

  bytes_in_buf = buf_capacity(conn->inbuf) - buf_datalen(conn->inbuf);
 again:
  if ((size_t)at_most > bytes_in_buf && bytes_in_buf >= 1024) {
    more_to_read = at_most - bytes_in_buf;
    at_most = bytes_in_buf;
  } else {
    more_to_read = 0;
  }

  if (connection_speaks_cells(conn) &&
      conn->state > OR_CONN_STATE_PROXY_READING) {
    int pending;
    or_connection_t *or_conn = TO_OR_CONN(conn);
    if (conn->state == OR_CONN_STATE_HANDSHAKING) {
      /* continue handshaking even if global token bucket is empty */
      return connection_tls_continue_handshake(or_conn);
    }

    log_debug(LD_NET,
              "%d: starting, inbuf_datalen %d (%d pending in tls object)."
              " at_most %d.",
              conn->s,(int)buf_datalen(conn->inbuf),
              tor_tls_get_pending_bytes(or_conn->tls), at_most);

    /* else open, or closing */
    result = read_to_buf_tls(or_conn->tls, at_most, conn->inbuf);
    or_conn->tls_error = result;

    switch (result) {
      case TOR_TLS_CLOSE:
        log_info(LD_NET,"TLS connection closed on read. Closing. "
                 "(Nickname %s, address %s",
                 or_conn->nickname ? or_conn->nickname : "not set",
                 conn->address);
        return result;
      case TOR_TLS_ERROR_IO:
      case TOR_TLS_ERROR_CONNREFUSED:
      case TOR_TLS_ERROR_CONNRESET:
      case TOR_TLS_ERROR_NO_ROUTE:
      case TOR_TLS_ERROR_TIMEOUT:
      case TOR_TLS_ERROR_MISC:
        log_info(LD_NET,"tls error. breaking (nickname %s, address %s).",
                 or_conn->nickname ? or_conn->nickname : "not set",
                 conn->address);
        return result;
      case TOR_TLS_WANTWRITE:
        connection_start_writing(conn);
        return 0;
      case TOR_TLS_WANTREAD: /* we're already reading */
      case TOR_TLS_DONE: /* no data read, so nothing to process */
        result = 0;
        break; /* so we call bucket_decrement below */
      default:
        break;
    }
    pending = tor_tls_get_pending_bytes(or_conn->tls);
    if (pending) {
      /* If we have any pending bytes, we read them now.  This *can*
       * take us over our read allotment, but really we shouldn't be
       * believing that SSL bytes are the same as TCP bytes anyway. */
      int r2 = read_to_buf_tls(or_conn->tls, pending, conn->inbuf);
      if (r2<0) {
        log_warn(LD_BUG, "Bug: apparently, reading pending bytes can fail.");
        return -1;
      } else {
        result += r2;
      }
    }

    tor_tls_get_n_raw_bytes(or_conn->tls, &n_read, &n_written);
    log_debug(LD_GENERAL, "After TLS read of %d: %ld read, %ld written",
              result, (long)n_read, (long)n_written);
  } else {
    int reached_eof = 0;
    CONN_LOG_PROTECT(conn,
        result = read_to_buf(conn->s, at_most, conn->inbuf, &reached_eof));
    if (reached_eof)
      conn->inbuf_reached_eof = 1;

//  log_fn(LOG_DEBUG,"read_to_buf returned %d.",read_result);

    if (result < 0)
      return -1;
    n_read = (size_t) result;
  }

  if (n_read > 0) { /* change *max_to_read */
    *max_to_read = at_most - n_read;
  }

  if (!is_internal_IP(conn->addr, 0)) {
    /* For non-local IPs, remember if we flushed any bytes over the wire. */
    time_t now = time(NULL);
    if (n_read > 0) {
      rep_hist_note_bytes_read(n_read, now);
      connection_read_bucket_decrement(conn, n_read);
    }
    if (n_written > 0) {
      rep_hist_note_bytes_written(n_written, now);
      global_write_bucket -= n_written;
    }
  }

  if (more_to_read && result == at_most) {
    bytes_in_buf = buf_capacity(conn->inbuf) - buf_datalen(conn->inbuf);
    tor_assert(bytes_in_buf < 1024);
    at_most = more_to_read;
    goto again;
  }

  /* Call even if result is 0, since the global read bucket may
   * have reached 0 on a different conn, and this guy needs to
   * know to stop reading. */
  connection_consider_empty_read_buckets(conn);
  if (n_written > 0 && connection_is_writing(conn))
    connection_consider_empty_write_buckets(conn);

  return 0;
}

/** A pass-through to fetch_from_buf. */
int
connection_fetch_from_buf(char *string, size_t len, connection_t *conn)
{
  return fetch_from_buf(string, len, conn->inbuf);
}

/** Return conn-\>outbuf_flushlen: how many bytes conn wants to flush
 * from its outbuf. */
int
connection_wants_to_flush(connection_t *conn)
{
  return conn->outbuf_flushlen;
}

/** Are there too many bytes on edge connection <b>conn</b>'s outbuf to
 * send back a relay-level sendme yet? Return 1 if so, 0 if not. Used by
 * connection_edge_consider_sending_sendme().
 */
int
connection_outbuf_too_full(connection_t *conn)
{
  return (conn->outbuf_flushlen > 10*CELL_PAYLOAD_SIZE);
}

/** Try to flush more bytes onto conn-\>s.
 *
 * This function gets called either from conn_write() in main.c
 * when poll() has declared that conn wants to write, or below
 * from connection_write_to_buf() when an entire TLS record is ready.
 *
 * Update conn-\>timestamp_lastwritten to now, and call flush_buf
 * or flush_buf_tls appropriately. If it succeeds and there no more
 * more bytes on conn->outbuf, then call connection_finished_flushing
 * on it too.
 *
 * If <b>force</b>, then write as many bytes as possible, ignoring bandwidth
 * limits.  (Used for flushing messages to controller connections on fatal
 * errors.)
 *
 * Mark the connection and return -1 if you want to close it, else
 * return 0.
 */
int
connection_handle_write(connection_t *conn, int force)
{
  int e;
  socklen_t len=sizeof(e);
  int result;
  int max_to_write;
  time_t now = time(NULL);
  size_t n_read = 0, n_written = 0;

  tor_assert(!connection_is_listener(conn));

  if (conn->marked_for_close || conn->s < 0)
    return 0; /* do nothing */

  conn->timestamp_lastwritten = now;

  /* Sometimes, "writable" means "connected". */
  if (connection_state_is_connecting(conn)) {
    if (getsockopt(conn->s, SOL_SOCKET, SO_ERROR, (void*)&e, &len) < 0) {
      log_warn(LD_BUG,
               "getsockopt() syscall failed?! Please report to tor-ops.");
      if (CONN_IS_EDGE(conn))
        connection_edge_end_errno(TO_EDGE_CONN(conn),
                                  TO_EDGE_CONN(conn)->cpath_layer);
      connection_mark_for_close(conn);
      return -1;
    }
    if (e) {
      /* some sort of error, but maybe just inprogress still */
      if (!ERRNO_IS_CONN_EINPROGRESS(e)) {
        log_info(LD_NET,"in-progress connect failed. Removing.");
        if (CONN_IS_EDGE(conn))
          connection_edge_end_errno(TO_EDGE_CONN(conn),
                                    TO_EDGE_CONN(conn)->cpath_layer);

        connection_close_immediate(conn);
        connection_mark_for_close(conn);
        /* it's safe to pass OPs to router_set_status(), since it just
         * ignores unrecognized routers
         */
        if (conn->type == CONN_TYPE_OR && !get_options()->HttpsProxy)
          router_set_status(TO_OR_CONN(conn)->identity_digest, 0);
        return -1;
      } else {
        return 0; /* no change, see if next time is better */
      }
    }
    /* The connection is successful. */
    if (connection_finished_connecting(conn)<0)
      return -1;
  }

  max_to_write = force ? (int)conn->outbuf_flushlen
    : connection_bucket_write_limit(conn);

  if (connection_speaks_cells(conn) &&
      conn->state > OR_CONN_STATE_PROXY_READING) {
    or_connection_t *or_conn = TO_OR_CONN(conn);
    if (conn->state == OR_CONN_STATE_HANDSHAKING) {
      connection_stop_writing(conn);
      if (connection_tls_continue_handshake(or_conn) < 0) {
        /* Don't flush; connection is dead. */
        connection_close_immediate(conn);
        connection_mark_for_close(conn);
        return -1;
      }
      return 0;
    }

    /* else open, or closing */
    result = flush_buf_tls(or_conn->tls, conn->outbuf,
                           max_to_write, &conn->outbuf_flushlen);
    switch (result) {
      case TOR_TLS_ERROR_IO:
      case TOR_TLS_ERROR_CONNREFUSED:
      case TOR_TLS_ERROR_CONNRESET:
      case TOR_TLS_ERROR_NO_ROUTE:
      case TOR_TLS_ERROR_TIMEOUT:
      case TOR_TLS_ERROR_MISC:
      case TOR_TLS_CLOSE:
        log_info(LD_NET,result!=TOR_TLS_CLOSE?
                 "tls error. breaking.":"TLS connection closed on flush");
        /* Don't flush; connection is dead. */
        connection_close_immediate(conn);
        connection_mark_for_close(conn);
        return -1;
      case TOR_TLS_WANTWRITE:
        log_debug(LD_NET,"wanted write.");
        /* we're already writing */
        return 0;
      case TOR_TLS_WANTREAD:
        /* Make sure to avoid a loop if the receive buckets are empty. */
        log_debug(LD_NET,"wanted read.");
        if (!connection_is_reading(conn)) {
          connection_stop_writing(conn);
          conn->wants_to_write = 1;
          /* we'll start reading again when the next second arrives,
           * and then also start writing again.
           */
        }
        /* else no problem, we're already reading */
        return 0;
      /* case TOR_TLS_DONE:
       * for TOR_TLS_DONE, fall through to check if the flushlen
       * is empty, so we can stop writing.
       */
    }

    tor_tls_get_n_raw_bytes(or_conn->tls, &n_read, &n_written);
    log_debug(LD_GENERAL, "After TLS write of %d: %ld read, %ld written",
              result, (long)n_read, (long)n_written);
  } else {
    CONN_LOG_PROTECT(conn,
             result = flush_buf(conn->s, conn->outbuf,
                                max_to_write, &conn->outbuf_flushlen));
    if (result < 0) {
      if (CONN_IS_EDGE(conn))
        connection_edge_end_errno(TO_EDGE_CONN(conn),
                                  TO_EDGE_CONN(conn)->cpath_layer);

      connection_close_immediate(conn); /* Don't flush; connection is dead. */
      connection_mark_for_close(conn);
      return -1;
    }
    n_written = (size_t) result;
  }

  if (!is_internal_IP(conn->addr, 0)) {
    /* For non-local IPs, remember if we flushed any bytes over the wire. */
    time_t now = time(NULL);
    if (n_written > 0) {
      rep_hist_note_bytes_written(n_written, now);
      global_write_bucket -= n_written;
    }
    if (n_read > 0) {
      rep_hist_note_bytes_read(n_read, now);
      connection_read_bucket_decrement(conn, n_read);
    }
  }

  if (result > 0) {
    /* If we wrote any bytes from our buffer, then call the appropriate
     * functions. */
    if (connection_flushed_some(conn) < 0)
      connection_mark_for_close(conn);
  }

  if (!connection_wants_to_flush(conn)) { /* it's done flushing */
    if (connection_finished_flushing(conn) < 0) {
      /* already marked */
      return -1;
    }
    return 0;
  }

  /* Call even if result is 0, since the global write bucket may
   * have reached 0 on a different conn, and this guy needs to
   * know to stop writing. */
  connection_consider_empty_write_buckets(conn);
  if (n_read > 0 && connection_is_reading(conn))
    connection_consider_empty_read_buckets(conn);

  return 0;
}

/** Append <b>len</b> bytes of <b>string</b> onto <b>conn</b>'s
 * outbuf, and ask it to start writing.
 *
 * If <b>zlib</b> is nonzero, this is a directory connection that should get
 * its contents compressed or decompressed as they're written.  If zlib is
 * negative, this is the last data to be compressed, and the connection's zlib
 * state should be flushed.
 */
void
_connection_write_to_buf_impl(const char *string, size_t len,
                              connection_t *conn, int zlib)
{
  int r;
  size_t old_datalen;
  if (!len)
    return;
  /* if it's marked for close, only allow write if we mean to flush it */
  if (conn->marked_for_close && !conn->hold_open_until_flushed)
    return;

  old_datalen = buf_datalen(conn->outbuf);
  if (zlib) {
    dir_connection_t *dir_conn = TO_DIR_CONN(conn);
    int done = zlib < 0;
    if (!dir_conn) return;
    CONN_LOG_PROTECT(conn, r = write_to_buf_zlib(conn->outbuf,
                                                 dir_conn->zlib_state,
                                                 string, len, done));
  } else {
    CONN_LOG_PROTECT(conn, r = write_to_buf(string, len, conn->outbuf));
  }
  if (r < 0) {
    if (CONN_IS_EDGE(conn)) {
      /* if it failed, it means we have our package/delivery windows set
         wrong compared to our max outbuf size. close the whole circuit. */
      log_warn(LD_NET,
               "write_to_buf failed. Closing circuit (fd %d).", conn->s);
      circuit_mark_for_close(circuit_get_by_edge_conn(TO_EDGE_CONN(conn)),
                             END_CIRC_REASON_INTERNAL);
    } else {
      log_warn(LD_NET,
               "write_to_buf failed. Closing connection (fd %d).", conn->s);
      connection_mark_for_close(conn);
    }
    return;
  }

  connection_start_writing(conn);
  if (zlib)
    conn->outbuf_flushlen += buf_datalen(conn->outbuf) - old_datalen;
  else
    conn->outbuf_flushlen += len;
}

/** Return the conn to addr/port that has the most recent
 * timestamp_created, or NULL if no such conn exists. */
or_connection_t *
connection_or_exact_get_by_addr_port(uint32_t addr, uint16_t port)
{
  int i, n;
  connection_t *conn;
  or_connection_t *best=NULL;
  connection_t **carray;

  get_connection_array(&carray,&n);
  for (i=0;i<n;i++) {
    conn = carray[i];
    if (conn->type == CONN_TYPE_OR &&
        conn->addr == addr &&
        conn->port == port &&
        !conn->marked_for_close &&
        (!best || best->_base.timestamp_created < conn->timestamp_created))
      best = TO_OR_CONN(conn);
  }
  return best;
}

/** Return a connection with given type, address, port, and purpose;
 * or NULL if no such connection exists. */
connection_t *
connection_get_by_type_addr_port_purpose(int type,
                                         uint32_t addr, uint16_t port,
                                         int purpose)
{
  int i, n;
  connection_t *conn;
  connection_t **carray;

  get_connection_array(&carray,&n);
  for (i=0;i<n;i++) {
    conn = carray[i];
    if (conn->type == type &&
        conn->addr == addr &&
        conn->port == port &&
        conn->purpose == purpose &&
        !conn->marked_for_close)
      return conn;
  }
  return NULL;
}

/** Return the connection with id <b>id</b> if it is not already marked for
 * close.
 */
edge_connection_t *
connection_get_by_global_id(uint32_t id)
{
  int i, n;
  connection_t *conn;
  connection_t **carray;

  get_connection_array(&carray,&n);
  for (i=0;i<n;i++) {
    conn = carray[i];
    if (CONN_IS_EDGE(conn) && TO_EDGE_CONN(conn)->global_identifier == id) {
      if (!conn->marked_for_close)
        return TO_EDGE_CONN(conn);
      else
        return NULL;
    }
  }
  return NULL;
}

/** Return a connection of type <b>type</b> that is not marked for close.
 */
connection_t *
connection_get_by_type(int type)
{
  int i, n;
  connection_t *conn;
  connection_t **carray;

  get_connection_array(&carray,&n);
  for (i=0;i<n;i++) {
    conn = carray[i];
    if (conn->type == type && !conn->marked_for_close)
      return conn;
  }
  return NULL;
}

/** Return a connection of type <b>type</b> that is in state <b>state</b>,
 * and that is not marked for close.
 */
connection_t *
connection_get_by_type_state(int type, int state)
{
  int i, n;
  connection_t *conn;
  connection_t **carray;

  get_connection_array(&carray,&n);
  for (i=0;i<n;i++) {
    conn = carray[i];
    if (conn->type == type && conn->state == state && !conn->marked_for_close)
      return conn;
  }
  return NULL;
}

/** Return the connection of type <b>type</b> that is in state
 * <b>state</b>, that was written to least recently, and that is not
 * marked for close.
 */
connection_t *
connection_get_by_type_state_lastwritten(int type, int state)
{
  int i, n;
  connection_t *conn, *best=NULL;
  connection_t **carray;

  get_connection_array(&carray,&n);
  for (i=0;i<n;i++) {
    conn = carray[i];
    if (conn->type == type && conn->state == state && !conn->marked_for_close)
      if (!best || conn->timestamp_lastwritten < best->timestamp_lastwritten)
        best = conn;
  }
  return best;
}

/** Return a connection of type <b>type</b> that has rendquery equal
 * to <b>rendquery</b>, and that is not marked for close. If state
 * is non-zero, conn must be of that state too.
 */
connection_t *
connection_get_by_type_state_rendquery(int type, int state,
                                       const char *rendquery)
{
  int i, n;
  connection_t *conn;
  connection_t **carray;

  tor_assert(type == CONN_TYPE_DIR ||
             type == CONN_TYPE_AP || type == CONN_TYPE_EXIT);

  get_connection_array(&carray,&n);
  for (i=0;i<n;i++) {
    conn = carray[i];
    if (conn->type == type &&
        !conn->marked_for_close &&
        (!state || state == conn->state)) {
      if (type == CONN_TYPE_DIR &&
          rend_cmp_service_ids(rendquery, TO_DIR_CONN(conn)->rend_query))
        return conn;
      else if (CONN_IS_EDGE(conn) &&
               rend_cmp_service_ids(rendquery, TO_EDGE_CONN(conn)->rend_query))
        return conn;
    }
  }
  return NULL;
}

/** Return an open, non-marked connection of a given type and purpose, or NULL
 * if no such connection exists. */
connection_t *
connection_get_by_type_purpose(int type, int purpose)
{
  int i, n;
  connection_t *conn;
  connection_t **carray;

  get_connection_array(&carray,&n);
  for (i=0;i<n;i++) {
    conn = carray[i];
    if (conn->type == type &&
        !conn->marked_for_close &&
        (purpose == conn->purpose))
      return conn;
  }
  return NULL;
}

/** Return 1 if <b>conn</b> is a listener conn, else return 0. */
int
connection_is_listener(connection_t *conn)
{
  if (conn->type == CONN_TYPE_OR_LISTENER ||
      conn->type == CONN_TYPE_AP_LISTENER ||
      conn->type == CONN_TYPE_AP_TRANS_LISTENER ||
      conn->type == CONN_TYPE_AP_NATD_LISTENER ||
      conn->type == CONN_TYPE_DIR_LISTENER ||
      conn->type == CONN_TYPE_CONTROL_LISTENER)
    return 1;
  return 0;
}

/** Return 1 if <b>conn</b> is in state "open" and is not marked
 * for close, else return 0.
 */
int
connection_state_is_open(connection_t *conn)
{
  tor_assert(conn);

  if (conn->marked_for_close)
    return 0;

  if ((conn->type == CONN_TYPE_OR && conn->state == OR_CONN_STATE_OPEN) ||
      (conn->type == CONN_TYPE_AP && conn->state == AP_CONN_STATE_OPEN) ||
      (conn->type == CONN_TYPE_EXIT && conn->state == EXIT_CONN_STATE_OPEN) ||
      (conn->type == CONN_TYPE_CONTROL &&
       (conn->state == CONTROL_CONN_STATE_OPEN_V0 ||
        conn->state == CONTROL_CONN_STATE_OPEN_V1)))
    return 1;

  return 0;
}

/** Return 1 if conn is in 'connecting' state, else return 0. */
int
connection_state_is_connecting(connection_t *conn)
{
  tor_assert(conn);

  if (conn->marked_for_close)
    return 0;
  switch (conn->type)
    {
    case CONN_TYPE_OR:
      return conn->state == OR_CONN_STATE_CONNECTING;
    case CONN_TYPE_EXIT:
      return conn->state == EXIT_CONN_STATE_CONNECTING;
    case CONN_TYPE_DIR:
      return conn->state == DIR_CONN_STATE_CONNECTING;
    }

  return 0;
}

/** Allocates a base64'ed authenticator for use in http or https
 * auth, based on the input string <b>authenticator</b>. Returns it
 * if success, else returns NULL. */
char *
alloc_http_authenticator(const char *authenticator)
{
  /* an authenticator in Basic authentication
   * is just the string "username:password" */
  const int authenticator_length = strlen(authenticator);
  /* The base64_encode function needs a minimum buffer length
   * of 66 bytes. */
  const int base64_authenticator_length = (authenticator_length/48+1)*66;
  char *base64_authenticator = tor_malloc(base64_authenticator_length);
  if (base64_encode(base64_authenticator, base64_authenticator_length,
                    authenticator, authenticator_length) < 0) {
    tor_free(base64_authenticator); /* free and set to null */
  } else {
    /* remove extra \n at end of encoding */
    base64_authenticator[strlen(base64_authenticator) - 1] = 0;
  }
  return base64_authenticator;
}

/** Given a socket handle, check whether the local address (sockname) of the
 * socket is one that we've connected from before.  If so, double-check
 * whether our address has changed and we need to generate keys.  If we do,
 * call init_keys().
 */
static void
client_check_address_changed(int sock)
{
  uint32_t iface_ip, ip_out;
  struct sockaddr_in out_addr;
  socklen_t out_addr_len = sizeof(out_addr);
  uint32_t *ip;

  if (!last_interface_ip)
    get_interface_address(LOG_INFO, &last_interface_ip);
  if (!outgoing_addrs)
    outgoing_addrs = smartlist_create();

  if (getsockname(sock, (struct sockaddr*)&out_addr, &out_addr_len)<0) {
    int e = tor_socket_errno(sock);
    log_warn(LD_NET, "getsockname() to check for address change failed: %s",
             tor_socket_strerror(e));
    return;
  }

  /* Okay.  If we've used this address previously, we're okay. */
  ip_out = ntohl(out_addr.sin_addr.s_addr);
  SMARTLIST_FOREACH(outgoing_addrs, uint32_t*, ip,
                    if (*ip == ip_out) return;
                    );

  /* Uh-oh.  We haven't connected from this address before. Has the interface
   * address changed? */
  if (get_interface_address(LOG_INFO, &iface_ip)<0)
    return;
  ip = tor_malloc(sizeof(uint32_t));
  *ip = ip_out;

  if (iface_ip == last_interface_ip) {
    /* Nope, it hasn't changed.  Add this address to the list. */
    smartlist_add(outgoing_addrs, ip);
  } else {
    /* The interface changed.  We're a client, so we need to regenerate our
     * keys.  First, reset the state. */
    log(LOG_NOTICE, LD_NET, "Our IP has changed.  Rotating keys...");
    last_interface_ip = iface_ip;
    SMARTLIST_FOREACH(outgoing_addrs, void*, ip, tor_free(ip));
    smartlist_clear(outgoing_addrs);
    smartlist_add(outgoing_addrs, ip);
    /* Okay, now change our keys. */
    ip_address_changed(1);
  }
}

/** Process new bytes that have arrived on conn-\>inbuf.
 *
 * This function just passes conn to the connection-specific
 * connection_*_process_inbuf() function. It also passes in
 * package_partial if wanted.
 */
static int
connection_process_inbuf(connection_t *conn, int package_partial)
{
  tor_assert(conn);

  switch (conn->type) {
    case CONN_TYPE_OR:
      return connection_or_process_inbuf(TO_OR_CONN(conn));
    case CONN_TYPE_EXIT:
    case CONN_TYPE_AP:
      return connection_edge_process_inbuf(TO_EDGE_CONN(conn),
                                           package_partial);
    case CONN_TYPE_DIR:
      return connection_dir_process_inbuf(TO_DIR_CONN(conn));
    case CONN_TYPE_DNSWORKER:
      return connection_dns_process_inbuf(conn);
    case CONN_TYPE_CPUWORKER:
      return connection_cpu_process_inbuf(conn);
    case CONN_TYPE_CONTROL:
      return connection_control_process_inbuf(TO_CONTROL_CONN(conn));
    default:
      log_err(LD_BUG,"Bug: got unexpected conn type %d.", conn->type);
      tor_fragile_assert();
      return -1;
  }
}

/** Called whenever we've written data on a connection. */
static int
connection_flushed_some(connection_t *conn)
{
  if (conn->type == CONN_TYPE_DIR &&
      conn->state == DIR_CONN_STATE_SERVER_WRITING)
    return connection_dirserv_flushed_some(TO_DIR_CONN(conn));
  else
    return 0;
}

/** We just finished flushing bytes from conn-\>outbuf, and there
 * are no more bytes remaining.
 *
 * This function just passes conn to the connection-specific
 * connection_*_finished_flushing() function.
 */
static int
connection_finished_flushing(connection_t *conn)
{
  tor_assert(conn);

//  log_fn(LOG_DEBUG,"entered. Socket %u.", conn->s);

  switch (conn->type) {
    case CONN_TYPE_OR:
      return connection_or_finished_flushing(TO_OR_CONN(conn));
    case CONN_TYPE_AP:
    case CONN_TYPE_EXIT:
      return connection_edge_finished_flushing(TO_EDGE_CONN(conn));
    case CONN_TYPE_DIR:
      return connection_dir_finished_flushing(TO_DIR_CONN(conn));
    case CONN_TYPE_DNSWORKER:
      return connection_dns_finished_flushing(conn);
    case CONN_TYPE_CPUWORKER:
      return connection_cpu_finished_flushing(conn);
    case CONN_TYPE_CONTROL:
      return connection_control_finished_flushing(TO_CONTROL_CONN(conn));
    default:
      log_err(LD_BUG,"Bug: got unexpected conn type %d.", conn->type);
      tor_fragile_assert();
      return -1;
  }
}

/** Called when our attempt to connect() to another server has just
 * succeeded.
 *
 * This function just passes conn to the connection-specific
 * connection_*_finished_connecting() function.
 */
static int
connection_finished_connecting(connection_t *conn)
{
  tor_assert(conn);
  switch (conn->type)
    {
    case CONN_TYPE_OR:
      return connection_or_finished_connecting(TO_OR_CONN(conn));
    case CONN_TYPE_EXIT:
      return connection_edge_finished_connecting(TO_EDGE_CONN(conn));
    case CONN_TYPE_DIR:
      return connection_dir_finished_connecting(TO_DIR_CONN(conn));
    default:
      log_err(LD_BUG,"Bug: got unexpected conn type %d.", conn->type);
      tor_fragile_assert();
      return -1;
  }
}

/** Callback: invoked when a connection reaches an EOF event. */
static int
connection_reached_eof(connection_t *conn)
{
  switch (conn->type) {
    case CONN_TYPE_OR:
      return connection_or_reached_eof(TO_OR_CONN(conn));
    case CONN_TYPE_AP:
    case CONN_TYPE_EXIT:
      return connection_edge_reached_eof(TO_EDGE_CONN(conn));
    case CONN_TYPE_DIR:
      return connection_dir_reached_eof(TO_DIR_CONN(conn));
    case CONN_TYPE_DNSWORKER:
      return connection_dns_reached_eof(conn);
    case CONN_TYPE_CPUWORKER:
      return connection_cpu_reached_eof(conn);
    case CONN_TYPE_CONTROL:
      return connection_control_reached_eof(TO_CONTROL_CONN(conn));
    default:
      log_err(LD_BUG,"Bug: got unexpected conn type %d.", conn->type);
      tor_fragile_assert();
      return -1;
  }
}

/** Verify that connection <b>conn</b> has all of its invariants
 * correct. Trigger an assert if anything is invalid.
 */
void
assert_connection_ok(connection_t *conn, time_t now)
{
  (void) now; /* XXXX unused. */
  tor_assert(conn);
  tor_assert(conn->type >= _CONN_TYPE_MIN);
  tor_assert(conn->type <= _CONN_TYPE_MAX);
  switch (conn->type) {
    case CONN_TYPE_OR:
      tor_assert(conn->magic == OR_CONNECTION_MAGIC);
      break;
    case CONN_TYPE_AP:
    case CONN_TYPE_EXIT:
      tor_assert(conn->magic == EDGE_CONNECTION_MAGIC);
      break;
    case CONN_TYPE_DIR:
      tor_assert(conn->magic == DIR_CONNECTION_MAGIC);
      break;
    case CONN_TYPE_CONTROL:
      tor_assert(conn->magic == CONTROL_CONNECTION_MAGIC);
      break;
    default:
      tor_assert(conn->magic == BASE_CONNECTION_MAGIC);
      break;
  }

  if (conn->outbuf_flushlen > 0) {
    tor_assert(connection_is_writing(conn) || conn->wants_to_write);
  }

  if (conn->hold_open_until_flushed)
    tor_assert(conn->marked_for_close);

  /* XXXX012 check: wants_to_read, wants_to_write, s, conn_array_index,
   * marked_for_close. */

  /* buffers */
  if (!connection_is_listener(conn)) {
    assert_buf_ok(conn->inbuf);
    assert_buf_ok(conn->outbuf);
  }

  /* XXXX012 Fix this; no longer so.*/
#if 0
  if (conn->type != CONN_TYPE_OR && conn->type != CONN_TYPE_DIR)
    tor_assert(!conn->pkey);
  /* pkey is set if we're a dir client, or if we're an OR in state OPEN
   * connected to another OR.
   */
#endif

  if (conn->chosen_exit_optional) {
    tor_assert(conn->type == CONN_TYPE_AP);
    tor_assert((TO_EDGE_CONN(conn))->chosen_exit_name);
  }

  if (conn->type == CONN_TYPE_OR) {
    or_connection_t *or_conn = TO_OR_CONN(conn);
    if (conn->state == OR_CONN_STATE_OPEN) {
      /* tor_assert(conn->bandwidth > 0); */
      /* the above isn't necessarily true: if we just did a TLS
       * handshake but we didn't recognize the other peer, or it
       * gave a bad cert/etc, then we won't have assigned bandwidth,
       * yet it will be open. -RD
       */
//      tor_assert(conn->read_bucket >= 0);
    }
//    tor_assert(conn->addr && conn->port);
    tor_assert(conn->address);
    if (conn->state > OR_CONN_STATE_PROXY_READING)
      tor_assert(or_conn->tls);
  }

  if (CONN_IS_EDGE(conn)) {
    edge_connection_t *edge_conn = TO_EDGE_CONN(conn);
    /* XXX unchecked: package window, deliver window. */
    if (conn->type == CONN_TYPE_AP) {

      tor_assert(edge_conn->socks_request);
      if (conn->state == AP_CONN_STATE_OPEN) {
        tor_assert(edge_conn->socks_request->has_finished);
        if (!conn->marked_for_close) {
          tor_assert(edge_conn->cpath_layer);
          assert_cpath_layer_ok(edge_conn->cpath_layer);
        }
      }
    }
    if (conn->type == CONN_TYPE_EXIT) {
      tor_assert(conn->purpose == EXIT_PURPOSE_CONNECT ||
                 conn->purpose == EXIT_PURPOSE_RESOLVE);
    }
  } else if (conn->type != CONN_TYPE_DIR) {
    /* Purpose is only used for dir and exit types currently */
    tor_assert(!conn->purpose);
  }

  switch (conn->type)
    {
    case CONN_TYPE_OR_LISTENER:
    case CONN_TYPE_AP_LISTENER:
    case CONN_TYPE_AP_TRANS_LISTENER:
    case CONN_TYPE_AP_NATD_LISTENER:
    case CONN_TYPE_DIR_LISTENER:
    case CONN_TYPE_CONTROL_LISTENER:
      tor_assert(conn->state == LISTENER_STATE_READY);
      break;
    case CONN_TYPE_OR:
      tor_assert(conn->state >= _OR_CONN_STATE_MIN);
      tor_assert(conn->state <= _OR_CONN_STATE_MAX);
      tor_assert(TO_OR_CONN(conn)->n_circuits >= 0);
      break;
    case CONN_TYPE_EXIT:
      tor_assert(conn->state >= _EXIT_CONN_STATE_MIN);
      tor_assert(conn->state <= _EXIT_CONN_STATE_MAX);
      tor_assert(conn->purpose >= _EXIT_PURPOSE_MIN);
      tor_assert(conn->purpose <= _EXIT_PURPOSE_MAX);
      break;
    case CONN_TYPE_AP:
      tor_assert(conn->state >= _AP_CONN_STATE_MIN);
      tor_assert(conn->state <= _AP_CONN_STATE_MAX);
      tor_assert(TO_EDGE_CONN(conn)->socks_request);
      break;
    case CONN_TYPE_DIR:
      tor_assert(conn->state >= _DIR_CONN_STATE_MIN);
      tor_assert(conn->state <= _DIR_CONN_STATE_MAX);
      tor_assert(conn->purpose >= _DIR_PURPOSE_MIN);
      tor_assert(conn->purpose <= _DIR_PURPOSE_MAX);
      break;
    case CONN_TYPE_DNSWORKER:
      tor_assert(conn->state >= _DNSWORKER_STATE_MIN);
      tor_assert(conn->state <= _DNSWORKER_STATE_MAX);
      break;
    case CONN_TYPE_CPUWORKER:
      tor_assert(conn->state >= _CPUWORKER_STATE_MIN);
      tor_assert(conn->state <= _CPUWORKER_STATE_MAX);
      break;
    case CONN_TYPE_CONTROL:
      tor_assert(conn->state >= _CONTROL_CONN_STATE_MIN);
      tor_assert(conn->state <= _CONTROL_CONN_STATE_MAX);
      break;
    default:
      tor_assert(0);
  }
}

