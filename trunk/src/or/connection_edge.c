/* Copyright 2001 Matej Pfajfar, 2001-2004 Roger Dingledine. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file connection_edge.c
 * \brief Handle edge streams.
 **/

#include "or.h"
#include "tree.h"

extern or_options_t options; /* command-line and config-file options */
extern char *conn_state_to_string[][_CONN_TYPE_MAX+1]; /* from connection.c */

static struct exit_policy_t *socks_policy = NULL;

static int connection_ap_handshake_process_socks(connection_t *conn);
static void parse_socks_policy(void);

/** Handle new bytes on conn->inbuf, or notification of eof.
 *
 * If there was an EOF, then send an end and mark the connection
 * for close.
 *
 * Otherwise handle it based on state:
 *   - If it's waiting for socks info, try to read another step of the
 *     socks handshake out of conn->inbuf.
 *   - If it's open, then package more relay cells from the stream.
 *   - Else, leave the bytes on inbuf alone for now.
 *
 * Mark and return -1 if there was an unexpected error with the conn,
 * else return 0.
 */
int connection_edge_process_inbuf(connection_t *conn) {

  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_AP || conn->type == CONN_TYPE_EXIT);

  if(conn->inbuf_reached_eof) {
#ifdef HALF_OPEN
    /* eof reached; we're done reading, but we might want to write more. */
    conn->done_receiving = 1;
    shutdown(conn->s, 0); /* XXX check return, refactor NM */
    if (conn->done_sending) {
      connection_edge_end(conn, END_STREAM_REASON_DONE, conn->cpath_layer);
      connection_mark_for_close(conn);
    } else {
      connection_edge_send_command(conn, circuit_get_by_conn(conn), RELAY_COMMAND_END,
                                   NULL, 0, conn->cpath_layer);
    }
    return 0;
#else
    /* eof reached, kill it. */
    log_fn(LOG_INFO,"conn (fd %d) reached eof. Closing.", conn->s);
    connection_edge_end(conn, END_STREAM_REASON_DONE, conn->cpath_layer);
    connection_mark_for_close(conn);
    conn->hold_open_until_flushed = 1; /* just because we shouldn't read
                                          doesn't mean we shouldn't write */
    return 0;
#endif
  }

  switch(conn->state) {
    case AP_CONN_STATE_SOCKS_WAIT:
      if(connection_ap_handshake_process_socks(conn) < 0) {
        conn->has_sent_end = 1; /* no circ yet */
        connection_mark_for_close(conn);
        conn->hold_open_until_flushed = 1;
        return -1;
      }
      return 0;
    case AP_CONN_STATE_OPEN:
    case EXIT_CONN_STATE_OPEN:
      if(conn->package_window <= 0) {
        /* XXX this is still getting called rarely :( */
        log_fn(LOG_WARN,"called with package_window %d. Tell Roger.", conn->package_window);
        return 0;
      }
      if(connection_edge_package_raw_inbuf(conn) < 0) {
        connection_edge_end(conn, END_STREAM_REASON_MISC, conn->cpath_layer);
        connection_mark_for_close(conn);
        return -1;
      }
      return 0;
    case EXIT_CONN_STATE_CONNECTING:
    case AP_CONN_STATE_RENDDESC_WAIT:
    case AP_CONN_STATE_CIRCUIT_WAIT:
    case AP_CONN_STATE_CONNECT_WAIT:
      log_fn(LOG_INFO,"data from edge while in '%s' state. Leaving it on buffer.",
                      conn_state_to_string[conn->type][conn->state]);
      return 0;
  }
  log_fn(LOG_WARN,"Got unexpected state %d. Closing.",conn->state);
  connection_edge_end(conn, END_STREAM_REASON_MISC, conn->cpath_layer);
  connection_mark_for_close(conn);
  return -1;
}

/** This edge needs to be closed, because its circuit has closed.
 * Mark it for close and return 0.
 */
int connection_edge_destroy(uint16_t circ_id, connection_t *conn) {
  tor_assert(conn->type == CONN_TYPE_AP || conn->type == CONN_TYPE_EXIT);

  if(conn->marked_for_close)
    return 0; /* already marked; probably got an 'end' */
  log_fn(LOG_INFO,"CircID %d: At an edge. Marking connection for close.",
         circ_id);
  conn->has_sent_end = 1; /* we're closing the circuit, nothing to send to */
  connection_mark_for_close(conn);
  conn->hold_open_until_flushed = 1;
  return 0;
}

/** Send a relay end cell from stream <b>conn</b> to conn's circuit,
 * with a destination of cpath_layer. (If cpath_layer is NULL, the
 * destination is the circuit's origin.) Mark the relay end cell as
 * closing because of <b>reason</b>.
 *
 * Return -1 if this function has already been called on this conn,
 * else return 0.
 */
int
connection_edge_end(connection_t *conn, char reason, crypt_path_t *cpath_layer)
{
  char payload[5];
  int payload_len=1;
  circuit_t *circ;

  if(conn->has_sent_end) {
    log_fn(LOG_WARN,"It appears I've already sent the end. Are you calling me twice?");
    return -1;
  }

  payload[0] = reason;
  if(reason == END_STREAM_REASON_EXITPOLICY) {
    /* this is safe even for rend circs, because they never fail
     * because of exitpolicy */
    set_uint32(payload+1, htonl(conn->addr));
    payload_len += 4;
  }

  circ = circuit_get_by_conn(conn);
  if(circ && !circ->marked_for_close) {
    log_fn(LOG_DEBUG,"Marking conn (fd %d) and sending end.",conn->s);
    connection_edge_send_command(conn, circ, RELAY_COMMAND_END,
                                 payload, payload_len, cpath_layer);
  } else {
    log_fn(LOG_DEBUG,"Marking conn (fd %d); no circ to send end.",conn->s);
  }

  conn->has_sent_end = 1;
  return 0;
}

/** Connection <b>conn</b> has finished writing and has no bytes left on
 * its outbuf.
 *
 * If it's in state 'open', stop writing, consider responding with a
 * sendme, and return.
 * Otherwise, stop writing and return.
 *
 * If <b>conn</b> is broken, mark it for close and return -1, else
 * return 0.
 */
int connection_edge_finished_flushing(connection_t *conn) {
  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_AP || conn->type == CONN_TYPE_EXIT);

  switch(conn->state) {
    case AP_CONN_STATE_OPEN:
    case EXIT_CONN_STATE_OPEN:
      connection_stop_writing(conn);
      connection_edge_consider_sending_sendme(conn);
      return 0;
    case AP_CONN_STATE_SOCKS_WAIT:
    case AP_CONN_STATE_RENDDESC_WAIT:
    case AP_CONN_STATE_CIRCUIT_WAIT:
    case AP_CONN_STATE_CONNECT_WAIT:
      connection_stop_writing(conn);
      return 0;
    default:
      log_fn(LOG_WARN,"BUG: called in unexpected state %d.", conn->state);
      return -1;
  }
  return 0;
}

/** Connected handler for exit connections: start writing pending
 * data, deliver 'CONNECTED' relay cells as appropriate, and check
 * any pending data that may have been received. */
int connection_edge_finished_connecting(connection_t *conn)
{
  unsigned char connected_payload[4];

  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_EXIT);
  tor_assert(conn->state == EXIT_CONN_STATE_CONNECTING);


  log_fn(LOG_INFO,"Exit connection to %s:%u established.",
         conn->address,conn->port);

  conn->state = EXIT_CONN_STATE_OPEN;
  connection_watch_events(conn, POLLIN); /* stop writing, continue reading */
  if(connection_wants_to_flush(conn)) /* in case there are any queued relay cells */
    connection_start_writing(conn);
  /* deliver a 'connected' relay cell back through the circuit. */
  if(connection_edge_is_rendezvous_stream(conn)) {
    if(connection_edge_send_command(conn, circuit_get_by_conn(conn),
                                    RELAY_COMMAND_CONNECTED, NULL, 0, conn->cpath_layer) < 0)
      return 0; /* circuit is closed, don't continue */
  } else {
    *(uint32_t*)connected_payload = htonl(conn->addr);
    if(connection_edge_send_command(conn, circuit_get_by_conn(conn),
         RELAY_COMMAND_CONNECTED, connected_payload, 4, conn->cpath_layer) < 0)
      return 0; /* circuit is closed, don't continue */
  }
  tor_assert(conn->package_window > 0);
  return connection_edge_process_inbuf(conn); /* in case the server has written anything */
}

/** How many times do we retry a general-purpose stream (detach it from
 * one circuit and try another, after we wait a while with no 'connected'
 * cell) before giving up?
 */
#define MAX_STREAM_RETRIES 4

/** Find all general-purpose AP streams in state connect_wait that sent
 * their begin cell >=15 seconds ago. Detach from their current circuit,
 * and mark their current circuit as unsuitable for new streams. Then call
 * connection_ap_handshake_attach_circuit() to attach to a new circuit (if
 * available) or launch a new one.
 *
 * For rendezvous streams, simply give up after 45 seconds (with no
 * retry attempt).
 */
void connection_ap_expire_beginning(void) {
  connection_t **carray;
  connection_t *conn;
  circuit_t *circ;
  int n, i;
  time_t now = time(NULL);

  get_connection_array(&carray, &n);

  for (i = 0; i < n; ++i) {
    conn = carray[i];
    if (conn->type != CONN_TYPE_AP ||
        conn->state != AP_CONN_STATE_CONNECT_WAIT)
      continue;
    if (now - conn->timestamp_lastread < 15)
      continue;
    conn->num_retries++;
    circ = circuit_get_by_conn(conn);
    if(!circ) { /* it's vanished? */
      log_fn(LOG_INFO,"Conn is in connect-wait, but lost its circ.");
      connection_mark_for_close(conn);
      continue;
    }
    if(circ->purpose == CIRCUIT_PURPOSE_C_REND_JOINED) {
      if (now - conn->timestamp_lastread > 45) {
        log_fn(LOG_WARN,"Rend stream is %d seconds late. Giving up.",
               (int)(now - conn->timestamp_lastread));
        connection_edge_end(conn, END_STREAM_REASON_TIMEOUT, conn->cpath_layer);
        connection_mark_for_close(conn);
      }
      continue;
    }
    tor_assert(circ->purpose == CIRCUIT_PURPOSE_C_GENERAL);
    if(conn->num_retries >= MAX_STREAM_RETRIES) {
      log_fn(LOG_WARN,"Stream is %d seconds late. Giving up.",
             15*conn->num_retries);
      circuit_log_path(LOG_WARN, circ);
      connection_edge_end(conn, END_STREAM_REASON_TIMEOUT, conn->cpath_layer);
      connection_mark_for_close(conn);
    } else {
      log_fn(LOG_WARN,"Stream is %d seconds late. Retrying.",
             (int)(now - conn->timestamp_lastread));
      circuit_log_path(LOG_WARN, circ);
      /* send an end down the circuit */
      connection_edge_end(conn, END_STREAM_REASON_TIMEOUT, conn->cpath_layer);
      /* un-mark it as ending, since we're going to reuse it */
      conn->has_sent_end = 0;
      /* move it back into 'pending' state. */
      conn->state = AP_CONN_STATE_CIRCUIT_WAIT;
      circuit_detach_stream(circ, conn);
      /* kludge to make us not try this circuit again, yet to allow
       * current streams on it to survive if they can: make it
       * unattractive to use for new streams */
      tor_assert(circ->timestamp_dirty);
      circ->timestamp_dirty -= options.NewCircuitPeriod;
      /* give our stream another 15 seconds to try */
      conn->timestamp_lastread += 15;
      /* attaching to a dirty circuit is fine */
      if(connection_ap_handshake_attach_circuit(conn)<0) {
        /* it will never work */
        /* Don't need to send end -- we're not connected */
        conn->has_sent_end = 1;
        connection_mark_for_close(conn);
      }
    } /* end if max_retries */
  } /* end for */
}

/** Tell any AP streamss that are waiting for a new circuit that one is
 * available.
 */
void connection_ap_attach_pending(void)
{
  connection_t **carray;
  connection_t *conn;
  int n, i;

  get_connection_array(&carray, &n);

  for (i = 0; i < n; ++i) {
    conn = carray[i];
    if (conn->marked_for_close ||
        conn->type != CONN_TYPE_AP ||
        conn->state != AP_CONN_STATE_CIRCUIT_WAIT)
      continue;
    if(connection_ap_handshake_attach_circuit(conn) < 0) {
      /* -1 means it will never work */
      /* Don't send end; there is no 'other side' yet */
      conn->has_sent_end = 1;
      connection_mark_for_close(conn);
    }
  }
}

/** connection_edge_process_inbuf() found a conn in state
 * socks_wait. See if conn->inbuf has the right bytes to proceed with
 * the socks handshake.
 *
 * If the handshake is complete, and it's for a general circuit, then
 * try to attach it to a circuit (or launch one as needed). If it's for
 * a rendezvous circuit, then fetch a rendezvous descriptor first (or
 * attach/launch a circuit if the rendezvous descriptor is already here
 * and fresh enough).
 *
 * Return -1 if an unexpected error with conn (and it should be marked
 * for close), else return 0.
 */
static int connection_ap_handshake_process_socks(connection_t *conn) {
  socks_request_t *socks;
  int sockshere;

  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_AP);
  tor_assert(conn->state == AP_CONN_STATE_SOCKS_WAIT);
  tor_assert(conn->socks_request);
  socks = conn->socks_request;

  log_fn(LOG_DEBUG,"entered.");

  sockshere = fetch_from_buf_socks(conn->inbuf, socks);
  if(sockshere == -1 || sockshere == 0) {
    if(socks->replylen) { /* we should send reply back */
      log_fn(LOG_DEBUG,"reply is already set for us. Using it.");
      connection_ap_handshake_socks_reply(conn, socks->reply, socks->replylen, 0);
    } else if(sockshere == -1) { /* send normal reject */
      log_fn(LOG_WARN,"Fetching socks handshake failed. Closing.");
      connection_ap_handshake_socks_reply(conn, NULL, 0, 0);
    } else {
      log_fn(LOG_DEBUG,"socks handshake not all here yet.");
    }
    if (sockshere == -1)
      conn->socks_request->has_finished = 1;
    return sockshere;
  } /* else socks handshake is done, continue processing */

  /* this call _modifies_ socks->address iff it's a hidden-service request */
  if (rend_parse_rendezvous_address(socks->address) < 0) {
    /* normal request */
    conn->state = AP_CONN_STATE_CIRCUIT_WAIT;
    return connection_ap_handshake_attach_circuit(conn);
  } else {
    /* it's a hidden-service request */
    rend_cache_entry_t *entry;
    int r;

    strcpy(conn->rend_query, socks->address); /* this strcpy is safe -RD */
    log_fn(LOG_INFO,"Got a hidden service request for ID '%s'", conn->rend_query);
    /* see if we already have it cached */
    r = rend_cache_lookup_entry(conn->rend_query, &entry);
    if(r<0) {
      log_fn(LOG_WARN,"Invalid service descriptor %s", conn->rend_query);
      return -1;
    }
    if(r==0) {
      conn->state = AP_CONN_STATE_RENDDESC_WAIT;
      log_fn(LOG_INFO, "Unknown descriptor %s. Fetching.", conn->rend_query);
      rend_client_refetch_renddesc(conn->rend_query);
      return 0;
    }
    if(r>0) {
#define NUM_SECONDS_BEFORE_REFETCH (60*15)
      if(time(NULL) - entry->received < NUM_SECONDS_BEFORE_REFETCH) {
        conn->state = AP_CONN_STATE_CIRCUIT_WAIT;
        log_fn(LOG_INFO, "Descriptor is here and fresh enough. Great.");
        return connection_ap_handshake_attach_circuit(conn);
      } else {
        conn->state = AP_CONN_STATE_RENDDESC_WAIT;
        log_fn(LOG_INFO, "Stale descriptor %s. Refetching.", conn->rend_query);
        rend_client_refetch_renddesc(conn->rend_query);
        return 0;
      }
    }
  }
  return 0;
}

/** Iterate over the two bytes of stream_id until we get one that is not
 * already in use; return it. Return 0 if can't get a unique stream_id.
 */
static uint16_t get_unique_stream_id_by_circ(circuit_t *circ) {
  connection_t *tmpconn;
  uint16_t test_stream_id;
  uint32_t attempts=0;

again:
  test_stream_id = circ->next_stream_id++;
  if(++attempts > 1<<16) {
    /* Make sure we don't loop forever if all stream_id's are used. */
    log_fn(LOG_WARN,"No unused stream IDs. Failing.");
    return 0;
  }
  if (test_stream_id == 0)
    goto again;
  for(tmpconn = circ->p_streams; tmpconn; tmpconn=tmpconn->next_stream)
    if(tmpconn->stream_id == test_stream_id)
      goto again;
  return test_stream_id;
}

/** Write a relay begin cell, using destaddr and destport from ap_conn's
 * socks_request field, and send it down circ.
 *
 * If ap_conn is broken, mark it for close and return -1. Else return 0.
 */
int connection_ap_handshake_send_begin(connection_t *ap_conn, circuit_t *circ)
{
  char payload[CELL_PAYLOAD_SIZE];
  int payload_len;
  struct in_addr in;
  const char *string_addr;

  tor_assert(ap_conn->type == CONN_TYPE_AP);
  tor_assert(ap_conn->state == AP_CONN_STATE_CIRCUIT_WAIT);
  tor_assert(ap_conn->socks_request);

  ap_conn->stream_id = get_unique_stream_id_by_circ(circ);
  if (ap_conn->stream_id==0) {
    /* Don't send end: there is no 'other side' yet */
    ap_conn->has_sent_end = 1;
    connection_mark_for_close(ap_conn);
    circuit_mark_for_close(circ);
    return -1;
  }

  if(circ->purpose == CIRCUIT_PURPOSE_C_GENERAL) {
    in.s_addr = htonl(client_dns_lookup_entry(ap_conn->socks_request->address));
    string_addr = in.s_addr ? inet_ntoa(in) : NULL;

    snprintf(payload,RELAY_PAYLOAD_SIZE,
             "%s:%d",
             string_addr ? string_addr : ap_conn->socks_request->address,
             ap_conn->socks_request->port);
  } else {
    snprintf(payload,RELAY_PAYLOAD_SIZE,
             ":%d", ap_conn->socks_request->port);
  }
  payload_len = strlen(payload)+1;

  log_fn(LOG_DEBUG,"Sending relay cell to begin stream %d.",ap_conn->stream_id);

  if(connection_edge_send_command(ap_conn, circ, RELAY_COMMAND_BEGIN,
                               payload, payload_len, ap_conn->cpath_layer) < 0)
    return -1; /* circuit is closed, don't continue */

  ap_conn->package_window = STREAMWINDOW_START;
  ap_conn->deliver_window = STREAMWINDOW_START;
  ap_conn->state = AP_CONN_STATE_CONNECT_WAIT;
  log_fn(LOG_INFO,"Address/port sent, ap socket %d, n_circ_id %d",ap_conn->s,circ->n_circ_id);
  return 0;
}

/** Make an AP connection_t, do a socketpair and attach one side
 * to the conn, connection_add it, initialize it to circuit_wait,
 * and call connection_ap_handshake_attach_circuit(conn) on it.
 *
 * Return the other end of the socketpair, or -1 if error.
 */
int connection_ap_make_bridge(char *address, uint16_t port) {
  int fd[2];
  connection_t *conn;

  log_fn(LOG_INFO,"Making AP bridge to %s:%d ...",address,port);

  if(tor_socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
    log(LOG_WARN,"Couldn't construct socketpair (%s). Network down? Delaying.",
        tor_socket_strerror(tor_socket_errno(-1)));
    return -1;
  }

  set_socket_nonblocking(fd[0]);
  set_socket_nonblocking(fd[1]);

  conn = connection_new(CONN_TYPE_AP);
  conn->s = fd[0];

  /* populate conn->socks_request */

  /* leave version at zero, so the socks_reply is empty */
  conn->socks_request->socks_version = 0;
  conn->socks_request->has_finished = 0; /* waiting for 'connected' */
  strcpy(conn->socks_request->address, address);
  conn->socks_request->port = port;

  conn->address = tor_strdup("(local bridge)");
  conn->addr = ntohs(0);
  conn->port = 0;

  if(connection_add(conn) < 0) { /* no space, forget it */
    connection_free(conn); /* this closes fd[0] */
    tor_close_socket(fd[1]);
    return -1;
  }

  conn->state = AP_CONN_STATE_CIRCUIT_WAIT;
  connection_start_reading(conn);

  /* attaching to a dirty circuit is fine */
  if (connection_ap_handshake_attach_circuit(conn) < 0) {
    conn->has_sent_end = 1; /* no circ to send to */
    connection_mark_for_close(conn);
    tor_close_socket(fd[1]);
    return -1;
  }

  log_fn(LOG_INFO,"... AP bridge created and connected.");
  return fd[1];
}

/** Send a socks reply to stream <b>conn</b>, using the appropriate
 * socks version, etc.
 *
 * If <b>reply</b> is defined, then write <b>replylen</b> bytes of it
 * to conn and return.
 *
 * Otherwise, send back a reply based on whether <b>success</b> is 1 or 0.
 */
void connection_ap_handshake_socks_reply(connection_t *conn, char *reply,
                                         int replylen, char success) {
  char buf[256];

  if(replylen) { /* we already have a reply in mind */
    connection_write_to_buf(reply, replylen, conn);
    return;
  }
  tor_assert(conn->socks_request);
  if(conn->socks_request->socks_version == 4) {
    memset(buf,0,SOCKS4_NETWORK_LEN);
#define SOCKS4_GRANTED          90
#define SOCKS4_REJECT           91
    buf[1] = (success ? SOCKS4_GRANTED : SOCKS4_REJECT);
    /* leave version, destport, destip zero */
    connection_write_to_buf(buf, SOCKS4_NETWORK_LEN, conn);
  }
  if(conn->socks_request->socks_version == 5) {
    buf[0] = 5; /* version 5 */
#define SOCKS5_SUCCESS          0
#define SOCKS5_GENERIC_ERROR    1
    buf[1] = success ? SOCKS5_SUCCESS : SOCKS5_GENERIC_ERROR;
    buf[2] = 0;
    buf[3] = 1; /* ipv4 addr */
    memset(buf+4,0,6); /* Set external addr/port to 0.
                          The spec doesn't seem to say what to do here. -RD */
    connection_write_to_buf(buf,10,conn);
  }
  /* If socks_version isn't 4 or 5, don't send anything.
   * This can happen in the case of AP bridges. */
  return;
}

/** A relay 'begin' cell has arrived, and either we are an exit hop
 * for the circuit, or we are the origin and it is a rendezvous begin.
 *
 * Launch a new exit connection and initialize things appropriately.
 *
 * If it's a rendezvous stream, call connection_exit_connect() on
 * it.
 *
 * For general streams, call dns_resolve() on it first, and only call
 * connection_exit_connect() if the dns answer is already known.
 *
 * Note that we don't call connection_add() on the new stream! We wait
 * for connection_exit_connect() to do that.
 *
 * Return -1 if we want to tear down <b>circ</b>. Else return 0.
 */
int connection_exit_begin_conn(cell_t *cell, circuit_t *circ) {
  connection_t *n_stream;
  relay_header_t rh;
  char *colon;

  assert_circuit_ok(circ);
  relay_header_unpack(&rh, cell->payload);

  /* XXX currently we don't send an end cell back if we drop the
   * begin because it's malformed.
   */

  if(!memchr(cell->payload+RELAY_HEADER_SIZE, 0, rh.length)) {
    log_fn(LOG_WARN,"relay begin cell has no \\0. Dropping.");
    return 0;
  }
  colon = strchr(cell->payload+RELAY_HEADER_SIZE, ':');
  if(!colon) {
    log_fn(LOG_WARN,"relay begin cell has no colon. Dropping.");
    return 0;
  }
  *colon = 0;

  if(!atoi(colon+1)) { /* bad port */
    log_fn(LOG_WARN,"relay begin cell has invalid port. Dropping.");
    return 0;
  }

  log_fn(LOG_DEBUG,"Creating new exit connection.");
  n_stream = connection_new(CONN_TYPE_EXIT);

  n_stream->stream_id = rh.stream_id;
  n_stream->port = atoi(colon+1);
  /* leave n_stream->s at -1, because it's not yet valid */
  n_stream->package_window = STREAMWINDOW_START;
  n_stream->deliver_window = STREAMWINDOW_START;

  if(circ->purpose == CIRCUIT_PURPOSE_S_REND_JOINED) {
    log_fn(LOG_DEBUG,"begin is for rendezvous. configuring stream.");
    n_stream->address = tor_strdup("(rendezvous)");
    n_stream->state = EXIT_CONN_STATE_CONNECTING;
    strcpy(n_stream->rend_query, circ->rend_query);
    tor_assert(n_stream->rend_query[0]);
    assert_circuit_ok(circ);
    if(rend_service_set_connection_addr_port(n_stream, circ) < 0) {
      log_fn(LOG_INFO,"Didn't find rendezvous service (port %d)",n_stream->port);
      connection_edge_end(n_stream, END_STREAM_REASON_EXITPOLICY, n_stream->cpath_layer);
      connection_free(n_stream);
      circuit_mark_for_close(circ); /* knock the whole thing down, somebody screwed up */
      return 0;
    }
    assert_circuit_ok(circ);
    log_fn(LOG_DEBUG,"Finished assigning addr/port");
    n_stream->cpath_layer = circ->cpath->prev; /* link it */

    /* add it into the linked list of n_streams on this circuit */
    n_stream->next_stream = circ->n_streams;
    circ->n_streams = n_stream;
    assert_circuit_ok(circ);

    connection_exit_connect(n_stream);
    return 0;
  }
  n_stream->address = tor_strdup(cell->payload + RELAY_HEADER_SIZE);
  n_stream->state = EXIT_CONN_STATE_RESOLVEFAILED;
  /* default to failed, change in dns_resolve if it turns out not to fail */

  /* send it off to the gethostbyname farm */
  switch(dns_resolve(n_stream)) {
    case 1: /* resolve worked */

      /* add it into the linked list of n_streams on this circuit */
      n_stream->next_stream = circ->n_streams;
      circ->n_streams = n_stream;
      assert_circuit_ok(circ);

      connection_exit_connect(n_stream);
      return 0;
    case -1: /* resolve failed */
      log_fn(LOG_INFO,"Resolve failed (%s).", n_stream->address);
      connection_edge_end(n_stream, END_STREAM_REASON_RESOLVEFAILED, n_stream->cpath_layer);
      connection_free(n_stream);
      break;
    case 0: /* resolve added to pending list */
      /* add it into the linked list of resolving_streams on this circuit */
      n_stream->next_stream = circ->resolving_streams;
      circ->resolving_streams = n_stream;
      assert_circuit_ok(circ);
      ;
  }
  return 0;
}

/** Connect to conn's specified addr and port. If it worked, conn
 * has now been added to the connection_array.
 *
 * Send back a connected cell. Include the resolved IP of the destination
 * address, but <em>only</em> if it's a general exit stream. (Rendezvous
 * streams must not reveal what IP they connected to.)
 */
void connection_exit_connect(connection_t *conn) {
  unsigned char connected_payload[4];

  if (!connection_edge_is_rendezvous_stream(conn) &&
      router_compare_to_my_exit_policy(conn) == ADDR_POLICY_REJECTED) {
    log_fn(LOG_INFO,"%s:%d failed exit policy. Closing.", conn->address, conn->port);
    connection_edge_end(conn, END_STREAM_REASON_EXITPOLICY, conn->cpath_layer);
    circuit_detach_stream(circuit_get_by_conn(conn), conn);
    connection_free(conn);
    return;
  }

  log_fn(LOG_DEBUG,"about to try connecting");
  switch(connection_connect(conn, conn->address, conn->addr, conn->port)) {
    case -1:
      connection_edge_end(conn, END_STREAM_REASON_CONNECTFAILED, conn->cpath_layer);
      circuit_detach_stream(circuit_get_by_conn(conn), conn);
      connection_free(conn);
      return;
    case 0:
      conn->state = EXIT_CONN_STATE_CONNECTING;

      connection_watch_events(conn, POLLOUT | POLLIN | POLLERR);
      /* writable indicates finish, readable indicates broken link,
         error indicates broken link in windowsland. */
      return;
    /* case 1: fall through */
  }

  conn->state = EXIT_CONN_STATE_OPEN;
  if(connection_wants_to_flush(conn)) { /* in case there are any queued data cells */
    log_fn(LOG_WARN,"tell roger: newly connected conn had data waiting!");
//    connection_start_writing(conn);
  }
//   connection_process_inbuf(conn);
  connection_watch_events(conn, POLLIN);

  /* also, deliver a 'connected' cell back through the circuit. */
  if(connection_edge_is_rendezvous_stream(conn)) { /* rendezvous stream */
    /* don't send an address back! */
    connection_edge_send_command(conn, circuit_get_by_conn(conn), RELAY_COMMAND_CONNECTED,
                                 NULL, 0, conn->cpath_layer);
  } else { /* normal stream */
    *(uint32_t*)connected_payload = htonl(conn->addr);
    connection_edge_send_command(conn, circuit_get_by_conn(conn), RELAY_COMMAND_CONNECTED,
                                 connected_payload, 4, conn->cpath_layer);
  }
}

/** Return 1 if <b>conn</b> is a rendezvous stream, or 0 if
 * it is a general stream.
 */
int connection_edge_is_rendezvous_stream(connection_t *conn) {
  tor_assert(conn);
  if(*conn->rend_query) /* XXX */
    return 1;
  return 0;
}

/** Return 1 if router <b>exit</b> might allow stream <b>conn</b>
 * to exit from it, or 0 if it definitely will not allow it.
 * (We might be uncertain if conn's destination address has not yet been
 * resolved.)
 */
int connection_ap_can_use_exit(connection_t *conn, routerinfo_t *exit)
{
  uint32_t addr;

  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_AP);
  tor_assert(conn->socks_request);

  log_fn(LOG_DEBUG,"considering nickname %s, for address %s / port %d:",
         exit->nickname, conn->socks_request->address,
         conn->socks_request->port);
  addr = client_dns_lookup_entry(conn->socks_request->address);
  return router_compare_addr_to_exit_policy(addr,
           conn->socks_request->port, exit->exit_policy);
}

/** A helper function for socks_policy_permits_address() below.
 *
 * Parse options.SocksPolicy in the same way that the exit policy
 * is parsed, and put the processed version in &socks_policy.
 * Ignore port specifiers.
 */
static void parse_socks_policy(void)
{
  struct exit_policy_t *n;
  if (socks_policy) {
    exit_policy_free(socks_policy);
    socks_policy = NULL;
  }
  config_parse_exit_policy(options.SocksPolicy, &socks_policy);
  /* ports aren't used. */
  for (n=socks_policy; n; n = n->next) {
    n->prt_min = 1;
    n->prt_max = 65535;
  }
}

/** Return 1 if <b>addr</b> is permitted to connect to our socks port,
 * based on <b>socks_policy</b>. Else return 0.
 */
int socks_policy_permits_address(uint32_t addr)
{
  int a;
  if (options.SocksPolicy && !socks_policy)
    parse_socks_policy();

  a = router_compare_addr_to_exit_policy(addr, 1, socks_policy);
  if (a==-1)
    return 0;
  else if (a==0)
    return 1;
  tor_assert(a==1);
  log_fn(LOG_WARN, "Got unexpected 'maybe' answer from socks policy");
  return 0;
}

/* ***** Client DNS code ***** */

/* XXX Perhaps this should get merged with the dns.c code somehow. */
/* XXX But we can't just merge them, because then nodes that act as
 *     both OR and OP could be attacked: people could rig the dns cache
 *     by answering funny things to stream begin requests, and later
 *     other clients would reuse those funny addr's. Hm.
 */

/** A client-side struct to remember the resolved IP (addr) for
 * a given address. These structs make up a tree, with client_dns_map
 * below as its root.
 */
struct client_dns_entry {
  uint32_t addr; /**< The resolved IP of this entry. */
  time_t expires; /**< At what second does addr expire? */
  int n_failures; /**< How many times has this entry failed to resolve so far? */
};

/** How many elements are in the client dns cache currently? */
static int client_dns_size = 0;
/** The tree of client-side cached DNS resolves. */
static strmap_t *client_dns_map = NULL;

/** Initialize client_dns_map and client_dns_size. */
void client_dns_init(void) {
  client_dns_map = strmap_new();
  client_dns_size = 0;
}

/** Return the client_dns_entry that corresponds to <b>address</b>.
 * If it's not there, allocate and return a new entry for <b>address</b>.
 */
static struct client_dns_entry *
_get_or_create_ent(const char *address)
{
  struct client_dns_entry *ent;
  ent = strmap_get_lc(client_dns_map,address);
  if (!ent) {
    ent = tor_malloc_zero(sizeof(struct client_dns_entry));
    ent->expires = time(NULL)+MAX_DNS_ENTRY_AGE;
    strmap_set_lc(client_dns_map,address,ent);
    ++client_dns_size;
  }
  return ent;
}

/** Return the IP associated with <b>address</b>, if we know it
 * and it's still fresh enough. Otherwise return 0.
 */
uint32_t client_dns_lookup_entry(const char *address)
{
  struct client_dns_entry *ent;
  struct in_addr in;
  time_t now;

  tor_assert(address);

  if (tor_inet_aton(address, &in)) {
    log_fn(LOG_DEBUG, "Using static address %s (%08lX)", address,
           (unsigned long)ntohl(in.s_addr));
    return ntohl(in.s_addr);
  }
  ent = strmap_get_lc(client_dns_map,address);
  if (!ent || !ent->addr) {
    log_fn(LOG_DEBUG, "No entry found for address %s", address);
    return 0;
  } else {
    now = time(NULL);
    if (ent->expires < now) {
      log_fn(LOG_DEBUG, "Expired entry found for address %s", address);
      strmap_remove_lc(client_dns_map,address);
      tor_free(ent);
      --client_dns_size;
      return 0;
    }
    in.s_addr = htonl(ent->addr);
    log_fn(LOG_DEBUG, "Found cached entry for address %s: %s", address,
           inet_ntoa(in));
    return ent->addr;
  }
}

/** An attempt to resolve <b>address</b> failed at some OR.
 * Increment the number of resolve failures we have on record
 * for it, and then return that number.
 */
int client_dns_incr_failures(const char *address)
{
  struct client_dns_entry *ent;
  ent = _get_or_create_ent(address);
  ++ent->n_failures;
  log_fn(LOG_DEBUG,"Address %s now has %d resolve failures.",
         address, ent->n_failures);
  return ent->n_failures;
}

/** Record the fact that <b>address</b> resolved to <b>val</b>.
 * We can now use this in subsequent streams in client_dns_lookup_entry(),
 * so we can more correctly choose a router that will allow <b>address</b>
 * to exit from him.
 */
void client_dns_set_entry(const char *address, uint32_t val)
{
  struct client_dns_entry *ent;
  struct in_addr in;
  time_t now;

  tor_assert(address);
  tor_assert(val);

  if (tor_inet_aton(address, &in))
    return;
  now = time(NULL);
  ent = _get_or_create_ent(address);
  in.s_addr = htonl(val);
  log_fn(LOG_DEBUG, "Updating entry for address %s: %s", address,
         inet_ntoa(in));
  ent->addr = val;
  ent->expires = now+MAX_DNS_ENTRY_AGE;
  ent->n_failures = 0;
}

/** A helper function for client_dns_clean() below. If ent is too old,
 * then remove it from the tree and return NULL, else return ent.
 */
static void* _remove_if_expired(const char *addr,
                                struct client_dns_entry *ent,
                                time_t *nowp)
{
  if (ent->expires < *nowp) {
    --client_dns_size;
    tor_free(ent);
    return NULL;
  } else {
    return ent;
  }
}

/** Clean out entries from the client-side DNS cache that were
 * resolved long enough ago that they are no longer valid.
 */
void client_dns_clean(void)
{
  time_t now;

  if(!client_dns_size)
    return;
  now = time(NULL);
  strmap_foreach(client_dns_map, (strmap_foreach_fn)_remove_if_expired, &now);
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
