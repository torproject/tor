/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file connection_edge.c
 * \brief Handle edge streams.
 **/

#include "or.h"
#include "buffers.h"
#include "channel.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "config.h"
#include "connection.h"
#include "connection_edge.h"
#include "connection_or.h"
#include "control.h"
#include "dns.h"
#include "dnsserv.h"
#include "dirserv.h"
#include "hibernate.h"
#include "main.h"
#include "nodelist.h"
#include "policies.h"
#include "reasons.h"
#include "relay.h"
#include "rendclient.h"
#include "rendcommon.h"
#include "rendservice.h"
#include "rephist.h"
#include "router.h"
#include "routerlist.h"
#include "routerset.h"

#ifdef HAVE_LINUX_TYPES_H
#include <linux/types.h>
#endif
#ifdef HAVE_LINUX_NETFILTER_IPV4_H
#include <linux/netfilter_ipv4.h>
#define TRANS_NETFILTER
#endif

#if defined(HAVE_NET_IF_H) && defined(HAVE_NET_PFVAR_H)
#include <net/if.h>
#include <net/pfvar.h>
#define TRANS_PF
#endif

#define SOCKS4_GRANTED          90
#define SOCKS4_REJECT           91

static int connection_ap_handshake_process_socks(entry_connection_t *conn);
static int connection_ap_process_natd(entry_connection_t *conn);
static int connection_exit_connect_dir(edge_connection_t *exitconn);
static int address_is_in_virtual_range(const char *addr);
static int consider_plaintext_ports(entry_connection_t *conn, uint16_t port);
static void clear_trackexithost_mappings(const char *exitname);
static int connection_ap_supports_optimistic_data(const entry_connection_t *);

/** An AP stream has failed/finished. If it hasn't already sent back
 * a socks reply, send one now (based on endreason). Also set
 * has_sent_end to 1, and mark the conn.
 */
void
connection_mark_unattached_ap_(entry_connection_t *conn, int endreason,
                               int line, const char *file)
{
  connection_t *base_conn = ENTRY_TO_CONN(conn);
  edge_connection_t *edge_conn = ENTRY_TO_EDGE_CONN(conn);
  tor_assert(base_conn->type == CONN_TYPE_AP);
  ENTRY_TO_EDGE_CONN(conn)->edge_has_sent_end = 1; /* no circ yet */

  /* If this is a rendezvous stream and it is failing without ever
   * being attached to a circuit, assume that an attempt to connect to
   * the destination hidden service has just ended.
   *
   * XXXX This condition doesn't limit to only streams failing
   * without ever being attached.  That sloppiness should be harmless,
   * but we should fix it someday anyway. */
  if ((edge_conn->on_circuit != NULL || edge_conn->edge_has_sent_end) &&
      connection_edge_is_rendezvous_stream(edge_conn)) {
    rend_client_note_connection_attempt_ended(
                                    edge_conn->rend_data->onion_address);
  }

  if (base_conn->marked_for_close) {
    /* This call will warn as appropriate. */
    connection_mark_for_close_(base_conn, line, file);
    return;
  }

  if (!conn->socks_request->has_finished) {
    if (endreason & END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED)
      log_warn(LD_BUG,
               "stream (marked at %s:%d) sending two socks replies?",
               file, line);

    if (SOCKS_COMMAND_IS_CONNECT(conn->socks_request->command))
      connection_ap_handshake_socks_reply(conn, NULL, 0, endreason);
    else if (SOCKS_COMMAND_IS_RESOLVE(conn->socks_request->command))
      connection_ap_handshake_socks_resolved(conn,
                                             RESOLVED_TYPE_ERROR_TRANSIENT,
                                             0, NULL, -1, -1);
    else /* unknown or no handshake at all. send no response. */
      conn->socks_request->has_finished = 1;
  }

  connection_mark_and_flush_(base_conn, line, file);

  ENTRY_TO_EDGE_CONN(conn)->end_reason = endreason;
}

/** There was an EOF. Send an end and mark the connection for close.
 */
int
connection_edge_reached_eof(edge_connection_t *conn)
{
  if (connection_get_inbuf_len(TO_CONN(conn)) &&
      connection_state_is_open(TO_CONN(conn))) {
    /* it still has stuff to process. don't let it die yet. */
    return 0;
  }
  log_info(LD_EDGE,"conn (fd %d) reached eof. Closing.", conn->base_.s);
  if (!conn->base_.marked_for_close) {
    /* only mark it if not already marked. it's possible to
     * get the 'end' right around when the client hangs up on us. */
    connection_edge_end(conn, END_STREAM_REASON_DONE);
    if (conn->base_.type == CONN_TYPE_AP) {
      /* eof, so don't send a socks reply back */
      if (EDGE_TO_ENTRY_CONN(conn)->socks_request)
        EDGE_TO_ENTRY_CONN(conn)->socks_request->has_finished = 1;
    }
    connection_mark_for_close(TO_CONN(conn));
  }
  return 0;
}

/** Handle new bytes on conn->inbuf based on state:
 *   - If it's waiting for socks info, try to read another step of the
 *     socks handshake out of conn->inbuf.
 *   - If it's waiting for the original destination, fetch it.
 *   - If it's open, then package more relay cells from the stream.
 *   - Else, leave the bytes on inbuf alone for now.
 *
 * Mark and return -1 if there was an unexpected error with the conn,
 * else return 0.
 */
int
connection_edge_process_inbuf(edge_connection_t *conn, int package_partial)
{
  tor_assert(conn);

  switch (conn->base_.state) {
    case AP_CONN_STATE_SOCKS_WAIT:
      if (connection_ap_handshake_process_socks(EDGE_TO_ENTRY_CONN(conn)) <0) {
        /* already marked */
        return -1;
      }
      return 0;
    case AP_CONN_STATE_NATD_WAIT:
      if (connection_ap_process_natd(EDGE_TO_ENTRY_CONN(conn)) < 0) {
        /* already marked */
        return -1;
      }
      return 0;
    case AP_CONN_STATE_OPEN:
    case EXIT_CONN_STATE_OPEN:
      if (connection_edge_package_raw_inbuf(conn, package_partial, NULL) < 0) {
        /* (We already sent an end cell if possible) */
        connection_mark_for_close(TO_CONN(conn));
        return -1;
      }
      return 0;
    case AP_CONN_STATE_CONNECT_WAIT:
      if (connection_ap_supports_optimistic_data(EDGE_TO_ENTRY_CONN(conn))) {
        log_info(LD_EDGE,
                 "data from edge while in '%s' state. Sending it anyway. "
                 "package_partial=%d, buflen=%ld",
                 conn_state_to_string(conn->base_.type, conn->base_.state),
                 package_partial,
                 (long)connection_get_inbuf_len(TO_CONN(conn)));
        if (connection_edge_package_raw_inbuf(conn, package_partial, NULL)<0) {
          /* (We already sent an end cell if possible) */
          connection_mark_for_close(TO_CONN(conn));
          return -1;
        }
        return 0;
      }
      /* Fall through if the connection is on a circuit without optimistic
       * data support. */
    case EXIT_CONN_STATE_CONNECTING:
    case AP_CONN_STATE_RENDDESC_WAIT:
    case AP_CONN_STATE_CIRCUIT_WAIT:
    case AP_CONN_STATE_RESOLVE_WAIT:
    case AP_CONN_STATE_CONTROLLER_WAIT:
      log_info(LD_EDGE,
               "data from edge while in '%s' state. Leaving it on buffer.",
               conn_state_to_string(conn->base_.type, conn->base_.state));
      return 0;
  }
  log_warn(LD_BUG,"Got unexpected state %d. Closing.",conn->base_.state);
  tor_fragile_assert();
  connection_edge_end(conn, END_STREAM_REASON_INTERNAL);
  connection_mark_for_close(TO_CONN(conn));
  return -1;
}

/** This edge needs to be closed, because its circuit has closed.
 * Mark it for close and return 0.
 */
int
connection_edge_destroy(circid_t circ_id, edge_connection_t *conn)
{
  if (!conn->base_.marked_for_close) {
    log_info(LD_EDGE,
             "CircID %d: At an edge. Marking connection for close.", circ_id);
    if (conn->base_.type == CONN_TYPE_AP) {
      entry_connection_t *entry_conn = EDGE_TO_ENTRY_CONN(conn);
      connection_mark_unattached_ap(entry_conn, END_STREAM_REASON_DESTROY);
      control_event_stream_bandwidth(conn);
      control_event_stream_status(entry_conn, STREAM_EVENT_CLOSED,
                                  END_STREAM_REASON_DESTROY);
      conn->end_reason |= END_STREAM_REASON_FLAG_ALREADY_SENT_CLOSED;
    } else {
      /* closing the circuit, nothing to send an END to */
      conn->edge_has_sent_end = 1;
      conn->end_reason = END_STREAM_REASON_DESTROY;
      conn->end_reason |= END_STREAM_REASON_FLAG_ALREADY_SENT_CLOSED;
      connection_mark_and_flush(TO_CONN(conn));
    }
  }
  conn->cpath_layer = NULL;
  conn->on_circuit = NULL;
  return 0;
}

/** Send a raw end cell to the stream with ID <b>stream_id</b> out over the
 * <b>circ</b> towards the hop identified with <b>cpath_layer</b>. If this
 * is not a client connection, set the relay end cell's reason for closing
 * as <b>reason</b> */
static int
relay_send_end_cell_from_edge(streamid_t stream_id, circuit_t *circ,
                              uint8_t reason, crypt_path_t *cpath_layer)
{
  char payload[1];

  if (CIRCUIT_PURPOSE_IS_CLIENT(circ->purpose)) {
    /* Never send the server an informative reason code; it doesn't need to
     * know why the client stream is failing. */
    reason = END_STREAM_REASON_MISC;
  }

  payload[0] = (char) reason;

  return relay_send_command_from_edge(stream_id, circ, RELAY_COMMAND_END,
                                      payload, 1, cpath_layer);
}

/** Send a relay end cell from stream <b>conn</b> down conn's circuit, and
 * remember that we've done so.  If this is not a client connection, set the
 * relay end cell's reason for closing as <b>reason</b>.
 *
 * Return -1 if this function has already been called on this conn,
 * else return 0.
 */
int
connection_edge_end(edge_connection_t *conn, uint8_t reason)
{
  char payload[RELAY_PAYLOAD_SIZE];
  size_t payload_len=1;
  circuit_t *circ;
  uint8_t control_reason = reason;

  if (conn->edge_has_sent_end) {
    log_warn(LD_BUG,"(Harmless.) Calling connection_edge_end (reason %d) "
             "on an already ended stream?", reason);
    tor_fragile_assert();
    return -1;
  }

  if (conn->base_.marked_for_close) {
    log_warn(LD_BUG,
             "called on conn that's already marked for close at %s:%d.",
             conn->base_.marked_for_close_file, conn->base_.marked_for_close);
    return 0;
  }

  circ = circuit_get_by_edge_conn(conn);
  if (circ && CIRCUIT_PURPOSE_IS_CLIENT(circ->purpose)) {
    /* If this is a client circuit, don't send the server an informative
     * reason code; it doesn't need to know why the client stream is
     * failing. */
    reason = END_STREAM_REASON_MISC;
  }

  payload[0] = (char)reason;
  if (reason == END_STREAM_REASON_EXITPOLICY &&
      !connection_edge_is_rendezvous_stream(conn)) {
    int addrlen;
    if (tor_addr_family(&conn->base_.addr) == AF_INET) {
      set_uint32(payload+1, tor_addr_to_ipv4n(&conn->base_.addr));
      addrlen = 4;
    } else {
      memcpy(payload+1, tor_addr_to_in6_addr8(&conn->base_.addr), 16);
      addrlen = 16;
    }
    set_uint32(payload+1+addrlen, htonl(dns_clip_ttl(conn->address_ttl)));
    payload_len += 4+addrlen;
  }

  if (circ && !circ->marked_for_close) {
    log_debug(LD_EDGE,"Sending end on conn (fd %d).",conn->base_.s);
    connection_edge_send_command(conn, RELAY_COMMAND_END,
                                 payload, payload_len);
  } else {
    log_debug(LD_EDGE,"No circ to send end on conn (fd %d).",
              conn->base_.s);
  }

  conn->edge_has_sent_end = 1;
  conn->end_reason = control_reason;
  return 0;
}

/** An error has just occurred on an operation on an edge connection
 * <b>conn</b>.  Extract the errno; convert it to an end reason, and send an
 * appropriate relay end cell to the other end of the connection's circuit.
 **/
int
connection_edge_end_errno(edge_connection_t *conn)
{
  uint8_t reason;
  tor_assert(conn);
  reason = errno_to_stream_end_reason(tor_socket_errno(conn->base_.s));
  return connection_edge_end(conn, reason);
}

/** We just wrote some data to <b>conn</b>; act appropriately.
 *
 * (That is, if it's open, consider sending a stream-level sendme cell if we
 * have just flushed enough.)
 */
int
connection_edge_flushed_some(edge_connection_t *conn)
{
  switch (conn->base_.state) {
    case AP_CONN_STATE_OPEN:
    case EXIT_CONN_STATE_OPEN:
      connection_edge_consider_sending_sendme(conn);
      break;
  }
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
int
connection_edge_finished_flushing(edge_connection_t *conn)
{
  tor_assert(conn);

  switch (conn->base_.state) {
    case AP_CONN_STATE_OPEN:
    case EXIT_CONN_STATE_OPEN:
      connection_edge_consider_sending_sendme(conn);
      return 0;
    case AP_CONN_STATE_SOCKS_WAIT:
    case AP_CONN_STATE_NATD_WAIT:
    case AP_CONN_STATE_RENDDESC_WAIT:
    case AP_CONN_STATE_CIRCUIT_WAIT:
    case AP_CONN_STATE_CONNECT_WAIT:
    case AP_CONN_STATE_CONTROLLER_WAIT:
    case AP_CONN_STATE_RESOLVE_WAIT:
      return 0;
    default:
      log_warn(LD_BUG, "Called in unexpected state %d.",conn->base_.state);
      tor_fragile_assert();
      return -1;
  }
  return 0;
}

/** Connected handler for exit connections: start writing pending
 * data, deliver 'CONNECTED' relay cells as appropriate, and check
 * any pending data that may have been received. */
int
connection_edge_finished_connecting(edge_connection_t *edge_conn)
{
  connection_t *conn;

  tor_assert(edge_conn);
  tor_assert(edge_conn->base_.type == CONN_TYPE_EXIT);
  conn = TO_CONN(edge_conn);
  tor_assert(conn->state == EXIT_CONN_STATE_CONNECTING);

  log_info(LD_EXIT,"Exit connection to %s:%u (%s) established.",
           escaped_safe_str(conn->address), conn->port,
           safe_str(fmt_and_decorate_addr(&conn->addr)));

  rep_hist_note_exit_stream_opened(conn->port);

  conn->state = EXIT_CONN_STATE_OPEN;
  IF_HAS_NO_BUFFEREVENT(conn)
    connection_watch_events(conn, READ_EVENT); /* stop writing, keep reading */
  if (connection_get_outbuf_len(conn)) /* in case there are any queued relay
                                        * cells */
    connection_start_writing(conn);
  /* deliver a 'connected' relay cell back through the circuit. */
  if (connection_edge_is_rendezvous_stream(edge_conn)) {
    if (connection_edge_send_command(edge_conn,
                                     RELAY_COMMAND_CONNECTED, NULL, 0) < 0)
      return 0; /* circuit is closed, don't continue */
  } else {
    char connected_payload[20];
    int connected_payload_len;
    if (tor_addr_family(&conn->addr) == AF_INET) {
      set_uint32(connected_payload, tor_addr_to_ipv4n(&conn->addr));
      set_uint32(connected_payload+4,
                 htonl(dns_clip_ttl(edge_conn->address_ttl)));
      connected_payload_len = 8;
    } else {
      memcpy(connected_payload, tor_addr_to_in6_addr8(&conn->addr), 16);
      set_uint32(connected_payload+16,
                 htonl(dns_clip_ttl(edge_conn->address_ttl)));
      connected_payload_len = 20;
    }
    if (connection_edge_send_command(edge_conn,
                                 RELAY_COMMAND_CONNECTED,
                                 connected_payload, connected_payload_len) < 0)
      return 0; /* circuit is closed, don't continue */
  }
  tor_assert(edge_conn->package_window > 0);
  /* in case the server has written anything */
  return connection_edge_process_inbuf(edge_conn, 1);
}

/** Common code to connection_(ap|exit)_about_to_close. */
static void
connection_edge_about_to_close(edge_connection_t *edge_conn)
{
  if (!edge_conn->edge_has_sent_end) {
    connection_t *conn = TO_CONN(edge_conn);
    log_warn(LD_BUG, "(Harmless.) Edge connection (marked at %s:%d) "
             "hasn't sent end yet?",
             conn->marked_for_close_file, conn->marked_for_close);
    tor_fragile_assert();
  }
}

/** Called when we're about to finally unlink and free an AP (client)
 * connection: perform necessary accounting and cleanup */
void
connection_ap_about_to_close(entry_connection_t *entry_conn)
{
  circuit_t *circ;
  edge_connection_t *edge_conn = ENTRY_TO_EDGE_CONN(entry_conn);
  connection_t *conn = ENTRY_TO_CONN(entry_conn);

  if (entry_conn->socks_request->has_finished == 0) {
    /* since conn gets removed right after this function finishes,
     * there's no point trying to send back a reply at this point. */
    log_warn(LD_BUG,"Closing stream (marked at %s:%d) without sending"
             " back a socks reply.",
             conn->marked_for_close_file, conn->marked_for_close);
  }
  if (!edge_conn->end_reason) {
    log_warn(LD_BUG,"Closing stream (marked at %s:%d) without having"
             " set end_reason.",
             conn->marked_for_close_file, conn->marked_for_close);
  }
  if (entry_conn->dns_server_request) {
    log_warn(LD_BUG,"Closing stream (marked at %s:%d) without having"
             " replied to DNS request.",
             conn->marked_for_close_file, conn->marked_for_close);
    dnsserv_reject_request(entry_conn);
  }
  control_event_stream_bandwidth(edge_conn);
  control_event_stream_status(entry_conn, STREAM_EVENT_CLOSED,
                              edge_conn->end_reason);
  circ = circuit_get_by_edge_conn(edge_conn);
  if (circ)
    circuit_detach_stream(circ, edge_conn);
}

/** Called when we're about to finally unlink and free an exit
 * connection: perform necessary accounting and cleanup */
void
connection_exit_about_to_close(edge_connection_t *edge_conn)
{
  circuit_t *circ;
  connection_t *conn = TO_CONN(edge_conn);

  connection_edge_about_to_close(edge_conn);

  circ = circuit_get_by_edge_conn(edge_conn);
  if (circ)
    circuit_detach_stream(circ, edge_conn);
  if (conn->state == EXIT_CONN_STATE_RESOLVING) {
    connection_dns_remove(edge_conn);
  }
}

/** Define a schedule for how long to wait between retrying
 * application connections. Rather than waiting a fixed amount of
 * time between each retry, we wait 10 seconds each for the first
 * two tries, and 15 seconds for each retry after
 * that. Hopefully this will improve the expected user experience. */
static int
compute_retry_timeout(entry_connection_t *conn)
{
  int timeout = get_options()->CircuitStreamTimeout;
  if (timeout) /* if our config options override the default, use them */
    return timeout;
  if (conn->num_socks_retries < 2) /* try 0 and try 1 */
    return 10;
  return 15;
}

/** Find all general-purpose AP streams waiting for a response that sent their
 * begin/resolve cell too long ago. Detach from their current circuit, and
 * mark their current circuit as unsuitable for new streams. Then call
 * connection_ap_handshake_attach_circuit() to attach to a new circuit (if
 * available) or launch a new one.
 *
 * For rendezvous streams, simply give up after SocksTimeout seconds (with no
 * retry attempt).
 */
void
connection_ap_expire_beginning(void)
{
  edge_connection_t *conn;
  entry_connection_t *entry_conn;
  circuit_t *circ;
  time_t now = time(NULL);
  const or_options_t *options = get_options();
  int severity;
  int cutoff;
  int seconds_idle, seconds_since_born;
  smartlist_t *conns = get_connection_array();

  SMARTLIST_FOREACH_BEGIN(conns, connection_t *, base_conn) {
    if (base_conn->type != CONN_TYPE_AP || base_conn->marked_for_close)
      continue;
    entry_conn = TO_ENTRY_CONN(base_conn);
    conn = ENTRY_TO_EDGE_CONN(entry_conn);
    /* if it's an internal linked connection, don't yell its status. */
    severity = (tor_addr_is_null(&base_conn->addr) && !base_conn->port)
      ? LOG_INFO : LOG_NOTICE;
    seconds_idle = (int)( now - base_conn->timestamp_lastread );
    seconds_since_born = (int)( now - base_conn->timestamp_created );

    if (base_conn->state == AP_CONN_STATE_OPEN)
      continue;

    /* We already consider SocksTimeout in
     * connection_ap_handshake_attach_circuit(), but we need to consider
     * it here too because controllers that put streams in controller_wait
     * state never ask Tor to attach the circuit. */
    if (AP_CONN_STATE_IS_UNATTACHED(base_conn->state)) {
      if (seconds_since_born >= options->SocksTimeout) {
        log_fn(severity, LD_APP,
            "Tried for %d seconds to get a connection to %s:%d. "
            "Giving up. (%s)",
            seconds_since_born,
            safe_str_client(entry_conn->socks_request->address),
            entry_conn->socks_request->port,
            conn_state_to_string(CONN_TYPE_AP, base_conn->state));
        connection_mark_unattached_ap(entry_conn, END_STREAM_REASON_TIMEOUT);
      }
      continue;
    }

    /* We're in state connect_wait or resolve_wait now -- waiting for a
     * reply to our relay cell. See if we want to retry/give up. */

    cutoff = compute_retry_timeout(entry_conn);
    if (seconds_idle < cutoff)
      continue;
    circ = circuit_get_by_edge_conn(conn);
    if (!circ) { /* it's vanished? */
      log_info(LD_APP,"Conn is waiting (address %s), but lost its circ.",
               safe_str_client(entry_conn->socks_request->address));
      connection_mark_unattached_ap(entry_conn, END_STREAM_REASON_TIMEOUT);
      continue;
    }
    if (circ->purpose == CIRCUIT_PURPOSE_C_REND_JOINED) {
      if (seconds_idle >= options->SocksTimeout) {
        log_fn(severity, LD_REND,
               "Rend stream is %d seconds late. Giving up on address"
               " '%s.onion'.",
               seconds_idle,
               safe_str_client(entry_conn->socks_request->address));
        connection_edge_end(conn, END_STREAM_REASON_TIMEOUT);
        connection_mark_unattached_ap(entry_conn, END_STREAM_REASON_TIMEOUT);
      }
      continue;
    }
    tor_assert(circ->purpose == CIRCUIT_PURPOSE_C_GENERAL);
    log_fn(cutoff < 15 ? LOG_INFO : severity, LD_APP,
           "We tried for %d seconds to connect to '%s' using exit %s."
           " Retrying on a new circuit.",
           seconds_idle,
           safe_str_client(entry_conn->socks_request->address),
           conn->cpath_layer ?
             extend_info_describe(conn->cpath_layer->extend_info):
             "*unnamed*");
    /* send an end down the circuit */
    connection_edge_end(conn, END_STREAM_REASON_TIMEOUT);
    /* un-mark it as ending, since we're going to reuse it */
    conn->edge_has_sent_end = 0;
    conn->end_reason = 0;
    /* kludge to make us not try this circuit again, yet to allow
     * current streams on it to survive if they can: make it
     * unattractive to use for new streams */
    /* XXXX024 this is a kludgy way to do this. */
    tor_assert(circ->timestamp_dirty);
    circ->timestamp_dirty -= options->MaxCircuitDirtiness;
    /* give our stream another 'cutoff' seconds to try */
    conn->base_.timestamp_lastread += cutoff;
    if (entry_conn->num_socks_retries < 250) /* avoid overflow */
      entry_conn->num_socks_retries++;
    /* move it back into 'pending' state, and try to attach. */
    if (connection_ap_detach_retriable(entry_conn, TO_ORIGIN_CIRCUIT(circ),
                                       END_STREAM_REASON_TIMEOUT)<0) {
      if (!base_conn->marked_for_close)
        connection_mark_unattached_ap(entry_conn,
                                      END_STREAM_REASON_CANT_ATTACH);
    }
  } SMARTLIST_FOREACH_END(base_conn);
}

/** Tell any AP streams that are waiting for a new circuit to try again,
 * either attaching to an available circ or launching a new one.
 */
void
connection_ap_attach_pending(void)
{
  entry_connection_t *entry_conn;
  smartlist_t *conns = get_connection_array();
  SMARTLIST_FOREACH_BEGIN(conns, connection_t *, conn) {
    if (conn->marked_for_close ||
        conn->type != CONN_TYPE_AP ||
        conn->state != AP_CONN_STATE_CIRCUIT_WAIT)
      continue;
    entry_conn = TO_ENTRY_CONN(conn);
    if (connection_ap_handshake_attach_circuit(entry_conn) < 0) {
      if (!conn->marked_for_close)
        connection_mark_unattached_ap(entry_conn,
                                      END_STREAM_REASON_CANT_ATTACH);
    }
  } SMARTLIST_FOREACH_END(conn);
}

/** Tell any AP streams that are waiting for a one-hop tunnel to
 * <b>failed_digest</b> that they are going to fail. */
/* XXX024 We should get rid of this function, and instead attach
 * one-hop streams to circ->p_streams so they get marked in
 * circuit_mark_for_close like normal p_streams. */
void
connection_ap_fail_onehop(const char *failed_digest,
                          cpath_build_state_t *build_state)
{
  entry_connection_t *entry_conn;
  char digest[DIGEST_LEN];
  smartlist_t *conns = get_connection_array();
  SMARTLIST_FOREACH_BEGIN(conns, connection_t *, conn) {
    if (conn->marked_for_close ||
        conn->type != CONN_TYPE_AP ||
        conn->state != AP_CONN_STATE_CIRCUIT_WAIT)
      continue;
    entry_conn = TO_ENTRY_CONN(conn);
    if (!entry_conn->want_onehop)
      continue;
    if (hexdigest_to_digest(entry_conn->chosen_exit_name, digest) < 0 ||
        tor_memneq(digest, failed_digest, DIGEST_LEN))
      continue;
    if (tor_digest_is_zero(digest)) {
      /* we don't know the digest; have to compare addr:port */
      tor_addr_t addr;
      if (!build_state || !build_state->chosen_exit ||
          !entry_conn->socks_request || !entry_conn->socks_request->address)
        continue;
      if (tor_addr_parse(&addr, entry_conn->socks_request->address)<0 ||
          !tor_addr_eq(&build_state->chosen_exit->addr, &addr) ||
          build_state->chosen_exit->port != entry_conn->socks_request->port)
        continue;
    }
    log_info(LD_APP, "Closing one-hop stream to '%s/%s' because the OR conn "
                     "just failed.", entry_conn->chosen_exit_name,
                     entry_conn->socks_request->address);
    connection_mark_unattached_ap(entry_conn, END_STREAM_REASON_TIMEOUT);
  } SMARTLIST_FOREACH_END(conn);
}

/** A circuit failed to finish on its last hop <b>info</b>. If there
 * are any streams waiting with this exit node in mind, but they
 * don't absolutely require it, make them give up on it.
 */
void
circuit_discard_optional_exit_enclaves(extend_info_t *info)
{
  entry_connection_t *entry_conn;
  const node_t *r1, *r2;

  smartlist_t *conns = get_connection_array();
  SMARTLIST_FOREACH_BEGIN(conns, connection_t *, conn) {
    if (conn->marked_for_close ||
        conn->type != CONN_TYPE_AP ||
        conn->state != AP_CONN_STATE_CIRCUIT_WAIT)
      continue;
    entry_conn = TO_ENTRY_CONN(conn);
    if (!entry_conn->chosen_exit_optional &&
        !entry_conn->chosen_exit_retries)
      continue;
    r1 = node_get_by_nickname(entry_conn->chosen_exit_name, 0);
    r2 = node_get_by_id(info->identity_digest);
    if (!r1 || !r2 || r1 != r2)
      continue;
    tor_assert(entry_conn->socks_request);
    if (entry_conn->chosen_exit_optional) {
      log_info(LD_APP, "Giving up on enclave exit '%s' for destination %s.",
               safe_str_client(entry_conn->chosen_exit_name),
               escaped_safe_str_client(entry_conn->socks_request->address));
      entry_conn->chosen_exit_optional = 0;
      tor_free(entry_conn->chosen_exit_name); /* clears it */
      /* if this port is dangerous, warn or reject it now that we don't
       * think it'll be using an enclave. */
      consider_plaintext_ports(entry_conn, entry_conn->socks_request->port);
    }
    if (entry_conn->chosen_exit_retries) {
      if (--entry_conn->chosen_exit_retries == 0) { /* give up! */
        clear_trackexithost_mappings(entry_conn->chosen_exit_name);
        tor_free(entry_conn->chosen_exit_name); /* clears it */
        /* if this port is dangerous, warn or reject it now that we don't
         * think it'll be using an enclave. */
        consider_plaintext_ports(entry_conn, entry_conn->socks_request->port);
      }
    }
  } SMARTLIST_FOREACH_END(conn);
}

/** The AP connection <b>conn</b> has just failed while attaching or
 * sending a BEGIN or resolving on <b>circ</b>, but another circuit
 * might work. Detach the circuit, and either reattach it, launch a
 * new circuit, tell the controller, or give up as a appropriate.
 *
 * Returns -1 on err, 1 on success, 0 on not-yet-sure.
 */
int
connection_ap_detach_retriable(entry_connection_t *conn,
                               origin_circuit_t *circ,
                               int reason)
{
  control_event_stream_status(conn, STREAM_EVENT_FAILED_RETRIABLE, reason);
  ENTRY_TO_CONN(conn)->timestamp_lastread = time(NULL);

  if (conn->pending_optimistic_data) {
    generic_buffer_set_to_copy(&conn->sending_optimistic_data,
                               conn->pending_optimistic_data);
  }

  if (!get_options()->LeaveStreamsUnattached || conn->use_begindir) {
    /* If we're attaching streams ourself, or if this connection is
     * a tunneled directory connection, then just attach it. */
    ENTRY_TO_CONN(conn)->state = AP_CONN_STATE_CIRCUIT_WAIT;
    circuit_detach_stream(TO_CIRCUIT(circ),ENTRY_TO_EDGE_CONN(conn));
    return connection_ap_handshake_attach_circuit(conn);
  } else {
    ENTRY_TO_CONN(conn)->state = AP_CONN_STATE_CONTROLLER_WAIT;
    circuit_detach_stream(TO_CIRCUIT(circ),ENTRY_TO_EDGE_CONN(conn));
    return 0;
  }
}

/** A client-side struct to remember requests to rewrite addresses
 * to new addresses. These structs are stored in the hash table
 * "addressmap" below.
 *
 * There are 5 ways to set an address mapping:
 * - A MapAddress command from the controller [permanent]
 * - An AddressMap directive in the torrc [permanent]
 * - When a TrackHostExits torrc directive is triggered [temporary]
 * - When a DNS resolve succeeds [temporary]
 * - When a DNS resolve fails [temporary]
 *
 * When an addressmap request is made but one is already registered,
 * the new one is replaced only if the currently registered one has
 * no "new_address" (that is, it's in the process of DNS resolve),
 * or if the new one is permanent (expires==0 or 1).
 *
 * (We overload the 'expires' field, using "0" for mappings set via
 * the configuration file, "1" for mappings set from the control
 * interface, and other values for DNS and TrackHostExit mappings that can
 * expire.)
 *
 * A mapping may be 'wildcarded'.  If "src_wildcard" is true, then
 * any address that ends with a . followed by the key for this entry will
 * get remapped by it.  If "dst_wildcard" is also true, then only the
 * matching suffix of such addresses will get replaced by new_address.
 */
typedef struct {
  char *new_address;
  time_t expires;
  addressmap_entry_source_t source:3;
  unsigned src_wildcard:1;
  unsigned dst_wildcard:1;
  short num_resolve_failures;
} addressmap_entry_t;

/** Entry for mapping addresses to which virtual address we mapped them to. */
typedef struct {
  char *ipv4_address;
  char *hostname_address;
} virtaddress_entry_t;

/** A hash table to store client-side address rewrite instructions. */
static strmap_t *addressmap=NULL;
/**
 * Table mapping addresses to which virtual address, if any, we
 * assigned them to.
 *
 * We maintain the following invariant: if [A,B] is in
 * virtaddress_reversemap, then B must be a virtual address, and [A,B]
 * must be in addressmap.  We do not require that the converse hold:
 * if it fails, then we could end up mapping two virtual addresses to
 * the same address, which is no disaster.
 **/
static strmap_t *virtaddress_reversemap=NULL;

/** Initialize addressmap. */
void
addressmap_init(void)
{
  addressmap = strmap_new();
  virtaddress_reversemap = strmap_new();
}

/** Free the memory associated with the addressmap entry <b>_ent</b>. */
static void
addressmap_ent_free(void *_ent)
{
  addressmap_entry_t *ent;
  if (!_ent)
    return;

  ent = _ent;
  tor_free(ent->new_address);
  tor_free(ent);
}

/** Free storage held by a virtaddress_entry_t* entry in <b>ent</b>. */
static void
addressmap_virtaddress_ent_free(void *_ent)
{
  virtaddress_entry_t *ent;
  if (!_ent)
    return;

  ent = _ent;
  tor_free(ent->ipv4_address);
  tor_free(ent->hostname_address);
  tor_free(ent);
}

/** Free storage held by a virtaddress_entry_t* entry in <b>ent</b>. */
static void
addressmap_virtaddress_remove(const char *address, addressmap_entry_t *ent)
{
  if (ent && ent->new_address &&
      address_is_in_virtual_range(ent->new_address)) {
    virtaddress_entry_t *ve =
      strmap_get(virtaddress_reversemap, ent->new_address);
    /*log_fn(LOG_NOTICE,"remove reverse mapping for %s",ent->new_address);*/
    if (ve) {
      if (!strcmp(address, ve->ipv4_address))
        tor_free(ve->ipv4_address);
      if (!strcmp(address, ve->hostname_address))
        tor_free(ve->hostname_address);
      if (!ve->ipv4_address && !ve->hostname_address) {
        tor_free(ve);
        strmap_remove(virtaddress_reversemap, ent->new_address);
      }
    }
  }
}

/** Remove <b>ent</b> (which must be mapped to by <b>address</b>) from the
 * client address maps. */
static void
addressmap_ent_remove(const char *address, addressmap_entry_t *ent)
{
  addressmap_virtaddress_remove(address, ent);
  addressmap_ent_free(ent);
}

/** Unregister all TrackHostExits mappings from any address to
 * *.exitname.exit. */
static void
clear_trackexithost_mappings(const char *exitname)
{
  char *suffix = NULL;
  if (!addressmap || !exitname)
    return;
  tor_asprintf(&suffix, ".%s.exit", exitname);
  tor_strlower(suffix);

  STRMAP_FOREACH_MODIFY(addressmap, address, addressmap_entry_t *, ent) {
    if (ent->source == ADDRMAPSRC_TRACKEXIT &&
        !strcmpend(ent->new_address, suffix)) {
      addressmap_ent_remove(address, ent);
      MAP_DEL_CURRENT(address);
    }
  } STRMAP_FOREACH_END;

  tor_free(suffix);
}

/** Remove all TRACKEXIT mappings from the addressmap for which the target
 * host is unknown or no longer allowed, or for which the source address
 * is no longer in trackexithosts. */
void
addressmap_clear_excluded_trackexithosts(const or_options_t *options)
{
  const routerset_t *allow_nodes = options->ExitNodes;
  const routerset_t *exclude_nodes = options->ExcludeExitNodesUnion_;

  if (!addressmap)
    return;
  if (routerset_is_empty(allow_nodes))
    allow_nodes = NULL;
  if (allow_nodes == NULL && routerset_is_empty(exclude_nodes))
    return;

  STRMAP_FOREACH_MODIFY(addressmap, address, addressmap_entry_t *, ent) {
    size_t len;
    const char *target = ent->new_address, *dot;
    char *nodename;
    const node_t *node;

    if (!target) {
      /* DNS resolving in progress */
      continue;
    } else if (strcmpend(target, ".exit")) {
      /* Not a .exit mapping */
      continue;
    } else if (ent->source != ADDRMAPSRC_TRACKEXIT) {
      /* Not a trackexit mapping. */
      continue;
    }
    len = strlen(target);
    if (len < 6)
      continue; /* malformed. */
    dot = target + len - 6; /* dot now points to just before .exit */
    while (dot > target && *dot != '.')
      dot--;
    if (*dot == '.') dot++;
    nodename = tor_strndup(dot, len-5-(dot-target));;
    node = node_get_by_nickname(nodename, 0);
    tor_free(nodename);
    if (!node ||
        (allow_nodes && !routerset_contains_node(allow_nodes, node)) ||
        routerset_contains_node(exclude_nodes, node) ||
        !hostname_in_track_host_exits(options, address)) {
      /* We don't know this one, or we want to be rid of it. */
      addressmap_ent_remove(address, ent);
      MAP_DEL_CURRENT(address);
    }
  } STRMAP_FOREACH_END;
}

/** Remove all AUTOMAP mappings from the addressmap for which the
 * source address no longer matches AutomapHostsSuffixes, which is
 * no longer allowed by AutomapHostsOnResolve, or for which the
 * target address is no longer in the virtual network. */
void
addressmap_clear_invalid_automaps(const or_options_t *options)
{
  int clear_all = !options->AutomapHostsOnResolve;
  const smartlist_t *suffixes = options->AutomapHostsSuffixes;

  if (!addressmap)
    return;

  if (!suffixes)
    clear_all = 1; /* This should be impossible, but let's be sure. */

  STRMAP_FOREACH_MODIFY(addressmap, src_address, addressmap_entry_t *, ent) {
    int remove = clear_all;
    if (ent->source != ADDRMAPSRC_AUTOMAP)
      continue; /* not an automap mapping. */

    if (!remove) {
      int suffix_found = 0;
      SMARTLIST_FOREACH(suffixes, const char *, suffix, {
          if (!strcasecmpend(src_address, suffix)) {
            suffix_found = 1;
            break;
          }
      });
      if (!suffix_found)
        remove = 1;
    }

    if (!remove && ! address_is_in_virtual_range(ent->new_address))
      remove = 1;

    if (remove) {
      addressmap_ent_remove(src_address, ent);
      MAP_DEL_CURRENT(src_address);
    }
  } STRMAP_FOREACH_END;
}

/** Remove all entries from the addressmap that were set via the
 * configuration file or the command line. */
void
addressmap_clear_configured(void)
{
  addressmap_get_mappings(NULL, 0, 0, 0);
}

/** Remove all entries from the addressmap that are set to expire, ever. */
void
addressmap_clear_transient(void)
{
  addressmap_get_mappings(NULL, 2, TIME_MAX, 0);
}

/** Clean out entries from the addressmap cache that were
 * added long enough ago that they are no longer valid.
 */
void
addressmap_clean(time_t now)
{
  addressmap_get_mappings(NULL, 2, now, 0);
}

/** Free all the elements in the addressmap, and free the addressmap
 * itself. */
void
addressmap_free_all(void)
{
  strmap_free(addressmap, addressmap_ent_free);
  addressmap = NULL;

  strmap_free(virtaddress_reversemap, addressmap_virtaddress_ent_free);
  virtaddress_reversemap = NULL;
}

/** Try to find a match for AddressMap expressions that use
 *  wildcard notation such as '*.c.d *.e.f' (so 'a.c.d' will map to 'a.e.f') or
 *  '*.c.d a.b.c' (so 'a.c.d' will map to a.b.c).
 *  Return the matching entry in AddressMap or NULL if no match is found.
 *  For expressions such as '*.c.d *.e.f', truncate <b>address</b> 'a.c.d'
 *  to 'a' before we return the matching AddressMap entry.
 *
 * This function does not handle the case where a pattern of the form "*.c.d"
 * matches the address c.d -- that's done by the main addressmap_rewrite
 * function.
 */
static addressmap_entry_t *
addressmap_match_superdomains(char *address)
{
  addressmap_entry_t *val;
  char *cp;

  cp = address;
  while ((cp = strchr(cp, '.'))) {
    /* cp now points to a suffix of address that begins with a . */
    val = strmap_get_lc(addressmap, cp+1);
    if (val && val->src_wildcard) {
      if (val->dst_wildcard)
        *cp = '\0';
      return val;
    }
    ++cp;
  }
  return NULL;
}

/** Look at address, and rewrite it until it doesn't want any
 * more rewrites; but don't get into an infinite loop.
 * Don't write more than maxlen chars into address.  Return true if the
 * address changed; false otherwise.  Set *<b>expires_out</b> to the
 * expiry time of the result, or to <b>time_max</b> if the result does
 * not expire.
 *
 * If <b>exit_source_out</b> is non-null, we set it as follows.  If we the
 * address starts out as a non-exit address, and we remap it to an .exit
 * address at any point, then set *<b>exit_source_out</b> to the
 * address_entry_source_t of the first such rule.  Set *<b>exit_source_out</b>
 * to ADDRMAPSRC_NONE if there is no such rewrite, or if the original address
 * was a .exit.
 */
int
addressmap_rewrite(char *address, size_t maxlen, time_t *expires_out,
                   addressmap_entry_source_t *exit_source_out)
{
  addressmap_entry_t *ent;
  int rewrites;
  time_t expires = TIME_MAX;
  addressmap_entry_source_t exit_source = ADDRMAPSRC_NONE;
  char *addr_orig = tor_strdup(address);
  char *log_addr_orig = NULL;

  for (rewrites = 0; rewrites < 16; rewrites++) {
    int exact_match = 0;
    log_addr_orig = tor_strdup(escaped_safe_str_client(address));

    ent = strmap_get(addressmap, address);

    if (!ent || !ent->new_address) {
      ent = addressmap_match_superdomains(address);
    } else {
      if (ent->src_wildcard && !ent->dst_wildcard &&
          !strcasecmp(address, ent->new_address)) {
        /* This is a rule like *.example.com example.com, and we just got
         * "example.com" */
        goto done;
      }

      exact_match = 1;
    }

    if (!ent || !ent->new_address) {
      goto done;
    }

    if (ent->dst_wildcard && !exact_match) {
      strlcat(address, ".", maxlen);
      strlcat(address, ent->new_address, maxlen);
    } else {
      strlcpy(address, ent->new_address, maxlen);
    }

    if (!strcmpend(address, ".exit") &&
        strcmpend(addr_orig, ".exit") &&
        exit_source == ADDRMAPSRC_NONE) {
      exit_source = ent->source;
    }

    log_info(LD_APP, "Addressmap: rewriting %s to %s",
             log_addr_orig, escaped_safe_str_client(address));
    if (ent->expires > 1 && ent->expires < expires)
      expires = ent->expires;

    tor_free(log_addr_orig);
  }
  log_warn(LD_CONFIG,
           "Loop detected: we've rewritten %s 16 times! Using it as-is.",
           escaped_safe_str_client(address));
  /* it's fine to rewrite a rewrite, but don't loop forever */

 done:
  tor_free(addr_orig);
  tor_free(log_addr_orig);
  if (exit_source_out)
    *exit_source_out = exit_source;
  if (expires_out)
    *expires_out = TIME_MAX;
  return (rewrites > 0);
}

/** If we have a cached reverse DNS entry for the address stored in the
 * <b>maxlen</b>-byte buffer <b>address</b> (typically, a dotted quad) then
 * rewrite to the cached value and return 1.  Otherwise return 0.  Set
 * *<b>expires_out</b> to the expiry time of the result, or to <b>time_max</b>
 * if the result does not expire. */
static int
addressmap_rewrite_reverse(char *address, size_t maxlen, time_t *expires_out)
{
  char *s, *cp;
  addressmap_entry_t *ent;
  int r = 0;
  tor_asprintf(&s, "REVERSE[%s]", address);
  ent = strmap_get(addressmap, s);
  if (ent) {
    cp = tor_strdup(escaped_safe_str_client(ent->new_address));
    log_info(LD_APP, "Rewrote reverse lookup %s -> %s",
             escaped_safe_str_client(s), cp);
    tor_free(cp);
    strlcpy(address, ent->new_address, maxlen);
    r = 1;
  }

  if (expires_out)
    *expires_out = (ent && ent->expires > 1) ? ent->expires : TIME_MAX;

  tor_free(s);
  return r;
}

/** Return 1 if <b>address</b> is already registered, else return 0. If address
 * is already registered, and <b>update_expires</b> is non-zero, then update
 * the expiry time on the mapping with update_expires if it is a
 * mapping created by TrackHostExits. */
int
addressmap_have_mapping(const char *address, int update_expiry)
{
  addressmap_entry_t *ent;
  if (!(ent=strmap_get_lc(addressmap, address)))
    return 0;
  if (update_expiry && ent->source==ADDRMAPSRC_TRACKEXIT)
    ent->expires=time(NULL) + update_expiry;
  return 1;
}

/** Register a request to map <b>address</b> to <b>new_address</b>,
 * which will expire on <b>expires</b> (or 0 if never expires from
 * config file, 1 if never expires from controller, 2 if never expires
 * (virtual address mapping) from the controller.)
 *
 * <b>new_address</b> should be a newly dup'ed string, which we'll use or
 * free as appropriate. We will leave address alone.
 *
 * If <b>wildcard_addr</b> is true, then the mapping will match any address
 * equal to <b>address</b>, or any address ending with a period followed by
 * <b>address</b>.  If <b>wildcard_addr</b> and <b>wildcard_new_addr</b> are
 * both true, the mapping will rewrite addresses that end with
 * ".<b>address</b>" into ones that end with ".<b>new_address</b>."
 *
 * If <b>new_address</b> is NULL, or <b>new_address</b> is equal to
 * <b>address</b> and <b>wildcard_addr</b> is equal to
 * <b>wildcard_new_addr</b>, remove any mappings that exist from
 * <b>address</b>.
 *
 *
 * It is an error to set <b>wildcard_new_addr</b> if <b>wildcard_addr</b> is
 * not set. */
void
addressmap_register(const char *address, char *new_address, time_t expires,
                    addressmap_entry_source_t source,
                    const int wildcard_addr,
                    const int wildcard_new_addr)
{
  addressmap_entry_t *ent;

  if (wildcard_new_addr)
    tor_assert(wildcard_addr);

  ent = strmap_get(addressmap, address);
  if (!new_address || (!strcasecmp(address,new_address) &&
                       wildcard_addr == wildcard_new_addr)) {
    /* Remove the mapping, if any. */
    tor_free(new_address);
    if (ent) {
      addressmap_ent_remove(address,ent);
      strmap_remove(addressmap, address);
    }
    return;
  }
  if (!ent) { /* make a new one and register it */
    ent = tor_malloc_zero(sizeof(addressmap_entry_t));
    strmap_set(addressmap, address, ent);
  } else if (ent->new_address) { /* we need to clean up the old mapping. */
    if (expires > 1) {
      log_info(LD_APP,"Temporary addressmap ('%s' to '%s') not performed, "
               "since it's already mapped to '%s'",
      safe_str_client(address),
      safe_str_client(new_address),
      safe_str_client(ent->new_address));
      tor_free(new_address);
      return;
    }
    if (address_is_in_virtual_range(ent->new_address) &&
        expires != 2) {
      /* XXX This isn't the perfect test; we want to avoid removing
       * mappings set from the control interface _as virtual mapping */
      addressmap_virtaddress_remove(address, ent);
    }
    tor_free(ent->new_address);
  } /* else { we have an in-progress resolve with no mapping. } */

  ent->new_address = new_address;
  ent->expires = expires==2 ? 1 : expires;
  ent->num_resolve_failures = 0;
  ent->source = source;
  ent->src_wildcard = wildcard_addr ? 1 : 0;
  ent->dst_wildcard = wildcard_new_addr ? 1 : 0;

  log_info(LD_CONFIG, "Addressmap: (re)mapped '%s' to '%s'",
           safe_str_client(address),
           safe_str_client(ent->new_address));
  control_event_address_mapped(address, ent->new_address, expires, NULL);
}

/** An attempt to resolve <b>address</b> failed at some OR.
 * Increment the number of resolve failures we have on record
 * for it, and then return that number.
 */
int
client_dns_incr_failures(const char *address)
{
  addressmap_entry_t *ent = strmap_get(addressmap, address);
  if (!ent) {
    ent = tor_malloc_zero(sizeof(addressmap_entry_t));
    ent->expires = time(NULL) + MAX_DNS_ENTRY_AGE;
    strmap_set(addressmap,address,ent);
  }
  if (ent->num_resolve_failures < SHORT_MAX)
    ++ent->num_resolve_failures; /* don't overflow */
  log_info(LD_APP, "Address %s now has %d resolve failures.",
           safe_str_client(address),
           ent->num_resolve_failures);
  return ent->num_resolve_failures;
}

/** If <b>address</b> is in the client DNS addressmap, reset
 * the number of resolve failures we have on record for it.
 * This is used when we fail a stream because it won't resolve:
 * otherwise future attempts on that address will only try once.
 */
void
client_dns_clear_failures(const char *address)
{
  addressmap_entry_t *ent = strmap_get(addressmap, address);
  if (ent)
    ent->num_resolve_failures = 0;
}

/** Record the fact that <b>address</b> resolved to <b>name</b>.
 * We can now use this in subsequent streams via addressmap_rewrite()
 * so we can more correctly choose an exit that will allow <b>address</b>.
 *
 * If <b>exitname</b> is defined, then append the addresses with
 * ".exitname.exit" before registering the mapping.
 *
 * If <b>ttl</b> is nonnegative, the mapping will be valid for
 * <b>ttl</b>seconds; otherwise, we use the default.
 */
static void
client_dns_set_addressmap_impl(const char *address, const char *name,
                               const char *exitname,
                               int ttl)
{
  /* <address>.<hex or nickname>.exit\0  or just  <address>\0 */
  char extendedaddress[MAX_SOCKS_ADDR_LEN+MAX_VERBOSE_NICKNAME_LEN+10];
  /* 123.123.123.123.<hex or nickname>.exit\0  or just  123.123.123.123\0 */
  char extendedval[INET_NTOA_BUF_LEN+MAX_VERBOSE_NICKNAME_LEN+10];

  tor_assert(address);
  tor_assert(name);

  if (ttl<0)
    ttl = DEFAULT_DNS_TTL;
  else
    ttl = dns_clip_ttl(ttl);

  if (exitname) {
    /* XXXX fails to ever get attempts to get an exit address of
     * google.com.digest[=~]nickname.exit; we need a syntax for this that
     * won't make strict RFC952-compliant applications (like us) barf. */
    tor_snprintf(extendedaddress, sizeof(extendedaddress),
                 "%s.%s.exit", address, exitname);
    tor_snprintf(extendedval, sizeof(extendedval),
                 "%s.%s.exit", name, exitname);
  } else {
    tor_snprintf(extendedaddress, sizeof(extendedaddress),
                 "%s", address);
    tor_snprintf(extendedval, sizeof(extendedval),
                 "%s", name);
  }
  addressmap_register(extendedaddress, tor_strdup(extendedval),
                      time(NULL) + ttl, ADDRMAPSRC_DNS, 0, 0);
}

/** Record the fact that <b>address</b> resolved to <b>val</b>.
 * We can now use this in subsequent streams via addressmap_rewrite()
 * so we can more correctly choose an exit that will allow <b>address</b>.
 *
 * If <b>exitname</b> is defined, then append the addresses with
 * ".exitname.exit" before registering the mapping.
 *
 * If <b>ttl</b> is nonnegative, the mapping will be valid for
 * <b>ttl</b>seconds; otherwise, we use the default.
 */
void
client_dns_set_addressmap(const char *address, uint32_t val,
                          const char *exitname,
                          int ttl)
{
  struct in_addr in;
  char valbuf[INET_NTOA_BUF_LEN];

  tor_assert(address);

  if (tor_inet_aton(address, &in))
    return; /* If address was an IP address already, don't add a mapping. */
  in.s_addr = htonl(val);
  tor_inet_ntoa(&in,valbuf,sizeof(valbuf));

  client_dns_set_addressmap_impl(address, valbuf, exitname, ttl);
}

/** Add a cache entry noting that <b>address</b> (ordinarily a dotted quad)
 * resolved via a RESOLVE_PTR request to the hostname <b>v</b>.
 *
 * If <b>exitname</b> is defined, then append the addresses with
 * ".exitname.exit" before registering the mapping.
 *
 * If <b>ttl</b> is nonnegative, the mapping will be valid for
 * <b>ttl</b>seconds; otherwise, we use the default.
 */
static void
client_dns_set_reverse_addressmap(const char *address, const char *v,
                                  const char *exitname,
                                  int ttl)
{
  char *s = NULL;
  tor_asprintf(&s, "REVERSE[%s]", address);
  client_dns_set_addressmap_impl(s, v, exitname, ttl);
  tor_free(s);
}

/* By default, we hand out 127.192.0.1 through 127.254.254.254.
 * These addresses should map to localhost, so even if the
 * application accidentally tried to connect to them directly (not
 * via Tor), it wouldn't get too far astray.
 *
 * These options are configured by parse_virtual_addr_network().
 */
/** Which network should we use for virtual IPv4 addresses?  Only the first
 * bits of this value are fixed. */
static uint32_t virtual_addr_network = 0x7fc00000u;
/** How many bits of <b>virtual_addr_network</b> are fixed? */
static maskbits_t virtual_addr_netmask_bits = 10;
/** What's the next virtual address we will hand out? */
static uint32_t next_virtual_addr    = 0x7fc00000u;

/** Read a netmask of the form 127.192.0.0/10 from "val", and check whether
 * it's a valid set of virtual addresses to hand out in response to MAPADDRESS
 * requests.  Return 0 on success; set *msg (if provided) to a newly allocated
 * string and return -1 on failure.  If validate_only is false, sets the
 * actual virtual address range to the parsed value. */
int
parse_virtual_addr_network(const char *val, int validate_only,
                           char **msg)
{
  uint32_t addr;
  uint16_t port_min, port_max;
  maskbits_t bits;

  if (parse_addr_and_port_range(val, &addr, &bits, &port_min, &port_max)) {
    if (msg) *msg = tor_strdup("Error parsing VirtualAddressNetwork");
    return -1;
  }

  if (port_min != 1 || port_max != 65535) {
    if (msg) *msg = tor_strdup("Can't specify ports on VirtualAddressNetwork");
    return -1;
  }

  if (bits > 16) {
    if (msg) *msg = tor_strdup("VirtualAddressNetwork expects a /16 "
                               "network or larger");
    return -1;
  }

  if (validate_only)
    return 0;

  virtual_addr_network = (uint32_t)( addr & (0xfffffffful << (32-bits)) );
  virtual_addr_netmask_bits = bits;

  if (addr_mask_cmp_bits(next_virtual_addr, addr, bits))
    next_virtual_addr = addr;

  return 0;
}

/**
 * Return true iff <b>addr</b> is likely to have been returned by
 * client_dns_get_unused_address.
 **/
static int
address_is_in_virtual_range(const char *address)
{
  struct in_addr in;
  tor_assert(address);
  if (!strcasecmpend(address, ".virtual")) {
    return 1;
  } else if (tor_inet_aton(address, &in)) {
    uint32_t addr = ntohl(in.s_addr);
    if (!addr_mask_cmp_bits(addr, virtual_addr_network,
                            virtual_addr_netmask_bits))
      return 1;
  }
  return 0;
}

/** Increment the value of next_virtual_addr; reset it to the start of the
 * virtual address range if it wraps around.
 */
static INLINE void
increment_virtual_addr(void)
{
  ++next_virtual_addr;
  if (addr_mask_cmp_bits(next_virtual_addr, virtual_addr_network,
                         virtual_addr_netmask_bits))
    next_virtual_addr = virtual_addr_network;
}

/** Return a newly allocated string holding an address of <b>type</b>
 * (one of RESOLVED_TYPE_{IPV4|HOSTNAME}) that has not yet been mapped,
 * and that is very unlikely to be the address of any real host.
 *
 * May return NULL if we have run out of virtual addresses.
 */
static char *
addressmap_get_virtual_address(int type)
{
  char buf[64];
  tor_assert(addressmap);

  if (type == RESOLVED_TYPE_HOSTNAME) {
    char rand[10];
    do {
      crypto_rand(rand, sizeof(rand));
      base32_encode(buf,sizeof(buf),rand,sizeof(rand));
      strlcat(buf, ".virtual", sizeof(buf));
    } while (strmap_get(addressmap, buf));
    return tor_strdup(buf);
  } else if (type == RESOLVED_TYPE_IPV4) {
    // This is an imperfect estimate of how many addresses are available, but
    // that's ok.
    struct in_addr in;
    uint32_t available = 1u << (32-virtual_addr_netmask_bits);
    while (available) {
      /* Don't hand out any .0 or .255 address. */
      while ((next_virtual_addr & 0xff) == 0 ||
             (next_virtual_addr & 0xff) == 0xff) {
        increment_virtual_addr();
        if (! --available) {
          log_warn(LD_CONFIG, "Ran out of virtual addresses!");
          return NULL;
        }
      }
      in.s_addr = htonl(next_virtual_addr);
      tor_inet_ntoa(&in, buf, sizeof(buf));
      if (!strmap_get(addressmap, buf)) {
        increment_virtual_addr();
        break;
      }

      increment_virtual_addr();
      --available;
      // log_info(LD_CONFIG, "%d addrs available", (int)available);
      if (! available) {
        log_warn(LD_CONFIG, "Ran out of virtual addresses!");
        return NULL;
      }
    }
    return tor_strdup(buf);
  } else {
    log_warn(LD_BUG, "Called with unsupported address type (%d)", type);
    return NULL;
  }
}

/** A controller has requested that we map some address of type
 * <b>type</b> to the address <b>new_address</b>.  Choose an address
 * that is unlikely to be used, and map it, and return it in a newly
 * allocated string.  If another address of the same type is already
 * mapped to <b>new_address</b>, try to return a copy of that address.
 *
 * The string in <b>new_address</b> may be freed or inserted into a map
 * as appropriate.  May return NULL if are out of virtual addresses.
 **/
const char *
addressmap_register_virtual_address(int type, char *new_address)
{
  char **addrp;
  virtaddress_entry_t *vent;
  int vent_needs_to_be_added = 0;

  tor_assert(new_address);
  tor_assert(addressmap);
  tor_assert(virtaddress_reversemap);

  vent = strmap_get(virtaddress_reversemap, new_address);
  if (!vent) {
    vent = tor_malloc_zero(sizeof(virtaddress_entry_t));
    vent_needs_to_be_added = 1;
  }

  addrp = (type == RESOLVED_TYPE_IPV4) ?
    &vent->ipv4_address : &vent->hostname_address;
  if (*addrp) {
    addressmap_entry_t *ent = strmap_get(addressmap, *addrp);
    if (ent && ent->new_address &&
        !strcasecmp(new_address, ent->new_address)) {
      tor_free(new_address);
      tor_assert(!vent_needs_to_be_added);
      return tor_strdup(*addrp);
    } else
      log_warn(LD_BUG,
               "Internal confusion: I thought that '%s' was mapped to by "
               "'%s', but '%s' really maps to '%s'. This is a harmless bug.",
               safe_str_client(new_address),
               safe_str_client(*addrp),
               safe_str_client(*addrp),
               ent?safe_str_client(ent->new_address):"(nothing)");
  }

  tor_free(*addrp);
  *addrp = addressmap_get_virtual_address(type);
  if (!*addrp) {
    tor_free(vent);
    tor_free(new_address);
    return NULL;
  }
  log_info(LD_APP, "Registering map from %s to %s", *addrp, new_address);
  if (vent_needs_to_be_added)
    strmap_set(virtaddress_reversemap, new_address, vent);
  addressmap_register(*addrp, new_address, 2, ADDRMAPSRC_AUTOMAP, 0, 0);

#if 0
  {
    /* Try to catch possible bugs */
    addressmap_entry_t *ent;
    ent = strmap_get(addressmap, *addrp);
    tor_assert(ent);
    tor_assert(!strcasecmp(ent->new_address,new_address));
    vent = strmap_get(virtaddress_reversemap, new_address);
    tor_assert(vent);
    tor_assert(!strcasecmp(*addrp,
                           (type == RESOLVED_TYPE_IPV4) ?
                           vent->ipv4_address : vent->hostname_address));
    log_info(LD_APP, "Map from %s to %s okay.",
             safe_str_client(*addrp),
             safe_str_client(new_address));
  }
#endif

  return *addrp;
}

/** Return 1 if <b>address</b> has funny characters in it like colons. Return
 * 0 if it's fine, or if we're configured to allow it anyway.  <b>client</b>
 * should be true if we're using this address as a client; false if we're
 * using it as a server.
 */
int
address_is_invalid_destination(const char *address, int client)
{
  if (client) {
    if (get_options()->AllowNonRFC953Hostnames)
      return 0;
  } else {
    if (get_options()->ServerDNSAllowNonRFC953Hostnames)
      return 0;
  }

  while (*address) {
    if (TOR_ISALNUM(*address) ||
        *address == '-' ||
        *address == '.' ||
        *address == '_') /* Underscore is not allowed, but Windows does it
                          * sometimes, just to thumb its nose at the IETF. */
      ++address;
    else
      return 1;
  }
  return 0;
}

/** Iterate over all address mappings which have expiry times between
 * min_expires and max_expires, inclusive.  If sl is provided, add an
 * "old-addr new-addr expiry" string to sl for each mapping, omitting
 * the expiry time if want_expiry is false. If sl is NULL, remove the
 * mappings.
 */
void
addressmap_get_mappings(smartlist_t *sl, time_t min_expires,
                        time_t max_expires, int want_expiry)
{
   strmap_iter_t *iter;
   const char *key;
   void *val_;
   addressmap_entry_t *val;

   if (!addressmap)
     addressmap_init();

   for (iter = strmap_iter_init(addressmap); !strmap_iter_done(iter); ) {
     strmap_iter_get(iter, &key, &val_);
     val = val_;
     if (val->expires >= min_expires && val->expires <= max_expires) {
       if (!sl) {
         iter = strmap_iter_next_rmv(addressmap,iter);
         addressmap_ent_remove(key, val);
         continue;
       } else if (val->new_address) {
         const char *src_wc = val->src_wildcard ? "*." : "";
         const char *dst_wc = val->dst_wildcard ? "*." : "";
         if (want_expiry) {
           if (val->expires < 3 || val->expires == TIME_MAX)
             smartlist_add_asprintf(sl, "%s%s %s%s NEVER",
                                    src_wc, key, dst_wc, val->new_address);
           else {
             char time[ISO_TIME_LEN+1];
             format_iso_time(time, val->expires);
             smartlist_add_asprintf(sl, "%s%s %s%s \"%s\"",
                                    src_wc, key, dst_wc, val->new_address,
                                    time);
           }
         } else {
           smartlist_add_asprintf(sl, "%s%s %s%s",
                                  src_wc, key, dst_wc, val->new_address);
         }
       }
     }
     iter = strmap_iter_next(addressmap,iter);
   }
}

/** Check if <b>conn</b> is using a dangerous port. Then warn and/or
 * reject depending on our config options. */
static int
consider_plaintext_ports(entry_connection_t *conn, uint16_t port)
{
  const or_options_t *options = get_options();
  int reject = smartlist_string_num_isin(options->RejectPlaintextPorts, port);

  if (smartlist_string_num_isin(options->WarnPlaintextPorts, port)) {
    log_warn(LD_APP, "Application request to port %d: this port is "
             "commonly used for unencrypted protocols. Please make sure "
             "you don't send anything you would mind the rest of the "
             "Internet reading!%s", port, reject ? " Closing." : "");
    control_event_client_status(LOG_WARN, "DANGEROUS_PORT PORT=%d RESULT=%s",
                                port, reject ? "REJECT" : "WARN");
  }

  if (reject) {
    log_info(LD_APP, "Port %d listed in RejectPlaintextPorts. Closing.", port);
    connection_mark_unattached_ap(conn, END_STREAM_REASON_ENTRYPOLICY);
    return -1;
  }

  return 0;
}

/** How many times do we try connecting with an exit configured via
 * TrackHostExits before concluding that it won't work any more and trying a
 * different one? */
#define TRACKHOSTEXITS_RETRIES 5

/** Call connection_ap_handshake_rewrite_and_attach() unless a controller
 *  asked us to leave streams unattached. Return 0 in that case.
 *
 *  See connection_ap_handshake_rewrite_and_attach()'s
 *  documentation for arguments and return value.
 */
int
connection_ap_rewrite_and_attach_if_allowed(entry_connection_t *conn,
                                            origin_circuit_t *circ,
                                            crypt_path_t *cpath)
{
  const or_options_t *options = get_options();

  if (options->LeaveStreamsUnattached) {
    ENTRY_TO_CONN(conn)->state = AP_CONN_STATE_CONTROLLER_WAIT;
    return 0;
  }
  return connection_ap_handshake_rewrite_and_attach(conn, circ, cpath);
}

/** Connection <b>conn</b> just finished its socks handshake, or the
 * controller asked us to take care of it. If <b>circ</b> is defined,
 * then that's where we'll want to attach it. Otherwise we have to
 * figure it out ourselves.
 *
 * First, parse whether it's a .exit address, remap it, and so on. Then
 * if it's for a general circuit, try to attach it to a circuit (or launch
 * one as needed), else if it's for a rendezvous circuit, fetch a
 * rendezvous descriptor first (or attach/launch a circuit if the
 * rendezvous descriptor is already here and fresh enough).
 *
 * The stream will exit from the hop
 * indicated by <b>cpath</b>, or from the last hop in circ's cpath if
 * <b>cpath</b> is NULL.
 */
int
connection_ap_handshake_rewrite_and_attach(entry_connection_t *conn,
                                           origin_circuit_t *circ,
                                           crypt_path_t *cpath)
{
  socks_request_t *socks = conn->socks_request;
  hostname_type_t addresstype;
  const or_options_t *options = get_options();
  struct in_addr addr_tmp;
  /* We set this to true if this is an address we should automatically
   * remap to a local address in VirtualAddrNetwork */
  int automap = 0;
  char orig_address[MAX_SOCKS_ADDR_LEN];
  time_t map_expires = TIME_MAX;
  time_t now = time(NULL);
  connection_t *base_conn = ENTRY_TO_CONN(conn);
  addressmap_entry_source_t exit_source = ADDRMAPSRC_NONE;

  tor_strlower(socks->address); /* normalize it */
  strlcpy(orig_address, socks->address, sizeof(orig_address));
  log_debug(LD_APP,"Client asked for %s:%d",
            safe_str_client(socks->address),
            socks->port);

  if (!strcmpend(socks->address, ".exit") && !options->AllowDotExit) {
    log_warn(LD_APP, "The  \".exit\" notation is disabled in Tor due to "
             "security risks. Set AllowDotExit in your torrc to enable "
             "it (at your own risk).");
    control_event_client_status(LOG_WARN, "SOCKS_BAD_HOSTNAME HOSTNAME=%s",
                                escaped(socks->address));
    connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
    return -1;
  }

  if (! conn->original_dest_address)
    conn->original_dest_address = tor_strdup(conn->socks_request->address);

  if (socks->command == SOCKS_COMMAND_RESOLVE &&
      !tor_inet_aton(socks->address, &addr_tmp) &&
      options->AutomapHostsOnResolve && options->AutomapHostsSuffixes) {
    SMARTLIST_FOREACH(options->AutomapHostsSuffixes, const char *, cp,
                      if (!strcasecmpend(socks->address, cp)) {
                        automap = 1;
                        break;
                      });
    if (automap) {
      const char *new_addr;
      new_addr = addressmap_register_virtual_address(
                              RESOLVED_TYPE_IPV4, tor_strdup(socks->address));
      if (! new_addr) {
        log_warn(LD_APP, "Unable to automap address %s",
                 escaped_safe_str(socks->address));
        connection_mark_unattached_ap(conn, END_STREAM_REASON_INTERNAL);
        return -1;
      }
      log_info(LD_APP, "Automapping %s to %s",
               escaped_safe_str_client(socks->address),
               safe_str_client(new_addr));
      strlcpy(socks->address, new_addr, sizeof(socks->address));
    }
  }

  if (socks->command == SOCKS_COMMAND_RESOLVE_PTR) {
    if (addressmap_rewrite_reverse(socks->address, sizeof(socks->address),
                                   &map_expires)) {
      char *result = tor_strdup(socks->address);
      /* remember _what_ is supposed to have been resolved. */
      tor_snprintf(socks->address, sizeof(socks->address), "REVERSE[%s]",
                  orig_address);
      connection_ap_handshake_socks_resolved(conn, RESOLVED_TYPE_HOSTNAME,
                                             strlen(result), (uint8_t*)result,
                                             -1,
                                             map_expires);
      connection_mark_unattached_ap(conn,
                                END_STREAM_REASON_DONE |
                                END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
      return 0;
    }
    if (options->ClientDNSRejectInternalAddresses) {
      /* Don't let people try to do a reverse lookup on 10.0.0.1. */
      tor_addr_t addr;
      int ok;
      ok = tor_addr_parse_PTR_name(
                               &addr, socks->address, AF_UNSPEC, 1);
      if (ok == 1 && tor_addr_is_internal(&addr, 0)) {
        connection_ap_handshake_socks_resolved(conn, RESOLVED_TYPE_ERROR,
                                               0, NULL, -1, TIME_MAX);
        connection_mark_unattached_ap(conn,
                                 END_STREAM_REASON_SOCKSPROTOCOL |
                                 END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
        return -1;
      }
    }
  } else if (!automap) {
    /* For address map controls, remap the address. */
    if (addressmap_rewrite(socks->address, sizeof(socks->address),
                           &map_expires, &exit_source)) {
      control_event_stream_status(conn, STREAM_EVENT_REMAP,
                                  REMAP_STREAM_SOURCE_CACHE);
    }
  }

  if (!automap && address_is_in_virtual_range(socks->address)) {
    /* This address was probably handed out by client_dns_get_unmapped_address,
     * but the mapping was discarded for some reason.  We *don't* want to send
     * the address through Tor; that's likely to fail, and may leak
     * information.
     */
    log_warn(LD_APP,"Missing mapping for virtual address '%s'. Refusing.",
             safe_str_client(socks->address));
    connection_mark_unattached_ap(conn, END_STREAM_REASON_INTERNAL);
    return -1;
  }

  /* Parse the address provided by SOCKS.  Modify it in-place if it
   * specifies a hidden-service (.onion) or particular exit node (.exit).
   */
  addresstype = parse_extended_hostname(socks->address);

  if (addresstype == BAD_HOSTNAME) {
    control_event_client_status(LOG_WARN, "SOCKS_BAD_HOSTNAME HOSTNAME=%s",
                                escaped(socks->address));
    connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
    return -1;
  }

  if (addresstype == EXIT_HOSTNAME) {
    /* foo.exit -- modify conn->chosen_exit_node to specify the exit
     * node, and conn->address to hold only the address portion. */
    char *s = strrchr(socks->address,'.');

    /* If StrictNodes is not set, then .exit overrides ExcludeNodes. */
    routerset_t *excludeset = options->StrictNodes ?
      options->ExcludeExitNodesUnion_ : options->ExcludeExitNodes;
    const node_t *node;

    if (exit_source == ADDRMAPSRC_AUTOMAP && !options->AllowDotExit) {
      /* Whoops; this one is stale.  It must have gotten added earlier,
       * when AllowDotExit was on. */
      log_warn(LD_APP,"Stale automapped address for '%s.exit', with "
               "AllowDotExit disabled. Refusing.",
               safe_str_client(socks->address));
      control_event_client_status(LOG_WARN, "SOCKS_BAD_HOSTNAME HOSTNAME=%s",
                                  escaped(socks->address));
      connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
      return -1;
    }

    if (exit_source == ADDRMAPSRC_DNS ||
        (exit_source == ADDRMAPSRC_NONE && !options->AllowDotExit)) {
      /* It shouldn't be possible to get a .exit address from any of these
       * sources. */
      log_warn(LD_BUG,"Address '%s.exit', with impossible source for the "
               ".exit part. Refusing.",
               safe_str_client(socks->address));
      control_event_client_status(LOG_WARN, "SOCKS_BAD_HOSTNAME HOSTNAME=%s",
                                  escaped(socks->address));
      connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
      return -1;
    }

    tor_assert(!automap);
    if (s) {
      /* The address was of the form "(stuff).(name).exit */
      if (s[1] != '\0') {
        conn->chosen_exit_name = tor_strdup(s+1);
        node = node_get_by_nickname(conn->chosen_exit_name, 1);

        if (exit_source == ADDRMAPSRC_TRACKEXIT) {
          /* We 5 tries before it expires the addressmap */
          conn->chosen_exit_retries = TRACKHOSTEXITS_RETRIES;
        }
        *s = 0;
      } else {
        /* Oops, the address was (stuff)..exit.  That's not okay. */
        log_warn(LD_APP,"Malformed exit address '%s.exit'. Refusing.",
                 safe_str_client(socks->address));
        control_event_client_status(LOG_WARN, "SOCKS_BAD_HOSTNAME HOSTNAME=%s",
                                    escaped(socks->address));
        connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
        return -1;
      }
    } else {
      /* It looks like they just asked for "foo.exit". */

      conn->chosen_exit_name = tor_strdup(socks->address);
      node = node_get_by_nickname(conn->chosen_exit_name, 1);
      if (node) {
        *socks->address = 0;
        node_get_address_string(node, socks->address, sizeof(socks->address));
      }
    }
    /* Now make sure that the chosen exit exists... */
    if (!node) {
      log_warn(LD_APP,
               "Unrecognized relay in exit address '%s.exit'. Refusing.",
               safe_str_client(socks->address));
      connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
      return -1;
    }
    /* ...and make sure that it isn't excluded. */
    if (routerset_contains_node(excludeset, node)) {
      log_warn(LD_APP,
               "Excluded relay in exit address '%s.exit'. Refusing.",
               safe_str_client(socks->address));
      connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
      return -1;
    }
    /* XXXX024-1090 Should we also allow foo.bar.exit if ExitNodes is set and
       Bar is not listed in it?  I say yes, but our revised manpage branch
       implies no. */
  }

  if (addresstype != ONION_HOSTNAME) {
    /* not a hidden-service request (i.e. normal or .exit) */
    if (address_is_invalid_destination(socks->address, 1)) {
      control_event_client_status(LOG_WARN, "SOCKS_BAD_HOSTNAME HOSTNAME=%s",
                                  escaped(socks->address));
      log_warn(LD_APP,
               "Destination '%s' seems to be an invalid hostname. Failing.",
               safe_str_client(socks->address));
      connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
      return -1;
    }

    if (options->Tor2webMode) {
      log_warn(LD_APP, "Refusing to connect to non-hidden-service hostname %s "
               "because tor2web mode is enabled.",
               safe_str_client(socks->address));
      connection_mark_unattached_ap(conn, END_STREAM_REASON_ENTRYPOLICY);
      return -1;
    }

    if (socks->command == SOCKS_COMMAND_RESOLVE) {
      uint32_t answer;
      struct in_addr in;
      /* Reply to resolves immediately if we can. */
      if (tor_inet_aton(socks->address, &in)) { /* see if it's an IP already */
        /* leave it in network order */
        answer = in.s_addr;
        /* remember _what_ is supposed to have been resolved. */
        strlcpy(socks->address, orig_address, sizeof(socks->address));
        connection_ap_handshake_socks_resolved(conn,RESOLVED_TYPE_IPV4,4,
                                               (uint8_t*)&answer,
                                               -1,map_expires);
        connection_mark_unattached_ap(conn,
                                END_STREAM_REASON_DONE |
                                END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
        return 0;
      }
      tor_assert(!automap);
      rep_hist_note_used_resolve(now); /* help predict this next time */
    } else if (socks->command == SOCKS_COMMAND_CONNECT) {
      tor_assert(!automap);
      if (socks->port == 0) {
        log_notice(LD_APP,"Application asked to connect to port 0. Refusing.");
        connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
        return -1;
      }
      if (options->ClientRejectInternalAddresses &&
          !conn->use_begindir && !conn->chosen_exit_name && !circ) {
        tor_addr_t addr;
        if (tor_addr_hostname_is_local(socks->address) ||
            (tor_addr_parse(&addr, socks->address) >= 0 &&
             tor_addr_is_internal(&addr, 0))) {
          /* If this is an explicit private address with no chosen exit node,
           * then we really don't want to try to connect to it.  That's
           * probably an error. */
          if (conn->is_transparent_ap) {
#define WARN_INTRVL_LOOP 300
            static ratelim_t loop_warn_limit = RATELIM_INIT(WARN_INTRVL_LOOP);
            char *m;
            if ((m = rate_limit_log(&loop_warn_limit, approx_time()))) {
              log_warn(LD_NET,
                       "Rejecting request for anonymous connection to private "
                       "address %s on a TransPort or NATDPort.  Possible loop "
                       "in your NAT rules?%s", safe_str_client(socks->address),
                       m);
              tor_free(m);
            }
          } else {
#define WARN_INTRVL_PRIV 300
            static ratelim_t priv_warn_limit = RATELIM_INIT(WARN_INTRVL_PRIV);
            char *m;
            if ((m = rate_limit_log(&priv_warn_limit, approx_time()))) {
              log_warn(LD_NET,
                       "Rejecting SOCKS request for anonymous connection to "
                       "private address %s.%s",
                       safe_str_client(socks->address),m);
              tor_free(m);
            }
          }
          connection_mark_unattached_ap(conn, END_STREAM_REASON_PRIVATE_ADDR);
          return -1;
        }
      }

      if (!conn->use_begindir && !conn->chosen_exit_name && !circ) {
        /* see if we can find a suitable enclave exit */
        const node_t *r =
          router_find_exact_exit_enclave(socks->address, socks->port);
        if (r) {
          log_info(LD_APP,
                   "Redirecting address %s to exit at enclave router %s",
                   safe_str_client(socks->address), node_describe(r));
          /* use the hex digest, not nickname, in case there are two
             routers with this nickname */
          conn->chosen_exit_name =
            tor_strdup(hex_str(r->identity, DIGEST_LEN));
          conn->chosen_exit_optional = 1;
        }
      }

      /* warn or reject if it's using a dangerous port */
      if (!conn->use_begindir && !conn->chosen_exit_name && !circ)
        if (consider_plaintext_ports(conn, socks->port) < 0)
          return -1;

      if (!conn->use_begindir) {
        /* help predict this next time */
        rep_hist_note_used_port(now, socks->port);
      }
    } else if (socks->command == SOCKS_COMMAND_RESOLVE_PTR) {
      rep_hist_note_used_resolve(now); /* help predict this next time */
      /* no extra processing needed */
    } else {
      tor_fragile_assert();
    }
    base_conn->state = AP_CONN_STATE_CIRCUIT_WAIT;
    if ((circ && connection_ap_handshake_attach_chosen_circuit(
                   conn, circ, cpath) < 0) ||
        (!circ &&
         connection_ap_handshake_attach_circuit(conn) < 0)) {
      if (!base_conn->marked_for_close)
        connection_mark_unattached_ap(conn, END_STREAM_REASON_CANT_ATTACH);
      return -1;
    }
    return 0;
  } else {
    /* it's a hidden-service request */
    rend_cache_entry_t *entry;
    int r;
    rend_service_authorization_t *client_auth;
    rend_data_t *rend_data;
    tor_assert(!automap);
    if (SOCKS_COMMAND_IS_RESOLVE(socks->command)) {
      /* if it's a resolve request, fail it right now, rather than
       * building all the circuits and then realizing it won't work. */
      log_warn(LD_APP,
               "Resolve requests to hidden services not allowed. Failing.");
      connection_ap_handshake_socks_resolved(conn,RESOLVED_TYPE_ERROR,
                                             0,NULL,-1,TIME_MAX);
      connection_mark_unattached_ap(conn,
                                END_STREAM_REASON_SOCKSPROTOCOL |
                                END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
      return -1;
    }

    if (circ) {
      log_warn(LD_CONTROL, "Attachstream to a circuit is not "
               "supported for .onion addresses currently. Failing.");
      connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
      return -1;
    }

    ENTRY_TO_EDGE_CONN(conn)->rend_data = rend_data =
      tor_malloc_zero(sizeof(rend_data_t));
    strlcpy(rend_data->onion_address, socks->address,
            sizeof(rend_data->onion_address));
    log_info(LD_REND,"Got a hidden service request for ID '%s'",
             safe_str_client(rend_data->onion_address));
    /* see if we already have it cached */
    r = rend_cache_lookup_entry(rend_data->onion_address, -1, &entry);
    if (r<0) {
      log_warn(LD_BUG,"Invalid service name '%s'",
               safe_str_client(rend_data->onion_address));
      connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
      return -1;
    }

    /* Help predict this next time. We're not sure if it will need
     * a stable circuit yet, but we know we'll need *something*. */
    rep_hist_note_used_internal(now, 0, 1);

    /* Look up if we have client authorization for it. */
    client_auth = rend_client_lookup_service_authorization(
                                          rend_data->onion_address);
    if (client_auth) {
      log_info(LD_REND, "Using previously configured client authorization "
                        "for hidden service request.");
      memcpy(rend_data->descriptor_cookie,
             client_auth->descriptor_cookie, REND_DESC_COOKIE_LEN);
      rend_data->auth_type = client_auth->auth_type;
    }
    if (r==0) {
      base_conn->state = AP_CONN_STATE_RENDDESC_WAIT;
      log_info(LD_REND, "Unknown descriptor %s. Fetching.",
               safe_str_client(rend_data->onion_address));
      rend_client_refetch_v2_renddesc(rend_data);
    } else { /* r > 0 */
      base_conn->state = AP_CONN_STATE_CIRCUIT_WAIT;
      log_info(LD_REND, "Descriptor is here. Great.");
      if (connection_ap_handshake_attach_circuit(conn) < 0) {
        if (!base_conn->marked_for_close)
          connection_mark_unattached_ap(conn, END_STREAM_REASON_CANT_ATTACH);
        return -1;
      }
    }
    return 0;
  }
  return 0; /* unreached but keeps the compiler happy */
}

#ifdef TRANS_PF
static int pf_socket = -1;
int
get_pf_socket(void)
{
  int pf;
  /*  This should be opened before dropping privileges. */
  if (pf_socket >= 0)
    return pf_socket;

#ifdef OPENBSD
  /* only works on OpenBSD */
  pf = tor_open_cloexec("/dev/pf", O_RDONLY, 0);
#else
  /* works on NetBSD and FreeBSD */
  pf = tor_open_cloexec("/dev/pf", O_RDWR, 0);
#endif

  if (pf < 0) {
    log_warn(LD_NET, "open(\"/dev/pf\") failed: %s", strerror(errno));
    return -1;
  }

  pf_socket = pf;
  return pf_socket;
}
#endif

/** Fetch the original destination address and port from a
 * system-specific interface and put them into a
 * socks_request_t as if they came from a socks request.
 *
 * Return -1 if an error prevents fetching the destination,
 * else return 0.
 */
static int
connection_ap_get_original_destination(entry_connection_t *conn,
                                       socks_request_t *req)
{
#ifdef TRANS_NETFILTER
  /* Linux 2.4+ */
  struct sockaddr_storage orig_dst;
  socklen_t orig_dst_len = sizeof(orig_dst);
  tor_addr_t addr;

  if (getsockopt(ENTRY_TO_CONN(conn)->s, SOL_IP, SO_ORIGINAL_DST,
                 (struct sockaddr*)&orig_dst, &orig_dst_len) < 0) {
    int e = tor_socket_errno(ENTRY_TO_CONN(conn)->s);
    log_warn(LD_NET, "getsockopt() failed: %s", tor_socket_strerror(e));
    return -1;
  }

  tor_addr_from_sockaddr(&addr, (struct sockaddr*)&orig_dst, &req->port);
  tor_addr_to_str(req->address, &addr, sizeof(req->address), 0);

  return 0;
#elif defined(TRANS_PF)
  struct sockaddr_storage proxy_addr;
  socklen_t proxy_addr_len = sizeof(proxy_addr);
  struct sockaddr *proxy_sa = (struct sockaddr*) &proxy_addr;
  struct pfioc_natlook pnl;
  tor_addr_t addr;
  int pf = -1;

  if (getsockname(ENTRY_TO_CONN(conn)->s, (struct sockaddr*)&proxy_addr,
                  &proxy_addr_len) < 0) {
    int e = tor_socket_errno(ENTRY_TO_CONN(conn)->s);
    log_warn(LD_NET, "getsockname() to determine transocks destination "
             "failed: %s", tor_socket_strerror(e));
    return -1;
  }

  memset(&pnl, 0, sizeof(pnl));
  pnl.proto           = IPPROTO_TCP;
  pnl.direction       = PF_OUT;
  if (proxy_sa->sa_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)proxy_sa;
    pnl.af              = AF_INET;
    pnl.saddr.v4.s_addr = tor_addr_to_ipv4n(&ENTRY_TO_CONN(conn)->addr);
    pnl.sport           = htons(ENTRY_TO_CONN(conn)->port);
    pnl.daddr.v4.s_addr = sin->sin_addr.s_addr;
    pnl.dport           = sin->sin_port;
  } else if (proxy_sa->sa_family == AF_INET6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)proxy_sa;
    pnl.af = AF_INET6;
    memcpy(&pnl.saddr.v6, tor_addr_to_in6(&ENTRY_TO_CONN(conn)->addr),
           sizeof(struct in6_addr));
    pnl.sport = htons(ENTRY_TO_CONN(conn)->port);
    memcpy(&pnl.daddr.v6, &sin6->sin6_addr, sizeof(struct in6_addr));
    pnl.dport = sin6->sin6_port;
  } else {
    log_warn(LD_NET, "getsockname() gave an unexpected address family (%d)",
             (int)proxy_sa->sa_family);
    return -1;
  }

  pf = get_pf_socket();
  if (pf<0)
    return -1;

  if (ioctl(pf, DIOCNATLOOK, &pnl) < 0) {
    log_warn(LD_NET, "ioctl(DIOCNATLOOK) failed: %s", strerror(errno));
    return -1;
  }

  if (pnl.af == AF_INET) {
    tor_addr_from_ipv4n(&addr, pnl.rdaddr.v4.s_addr);
  } else if (pnl.af == AF_INET6) {
    tor_addr_from_in6(&addr, &pnl.rdaddr.v6);
  } else {
    tor_fragile_assert();
    return -1;
  }

  tor_addr_to_str(req->address, &addr, sizeof(req->address), 0);
  req->port = ntohs(pnl.rdport);

  return 0;
#else
  (void)conn;
  (void)req;
  log_warn(LD_BUG, "Called connection_ap_get_original_destination, but no "
           "transparent proxy method was configured.");
  return -1;
#endif
}

/** connection_edge_process_inbuf() found a conn in state
 * socks_wait. See if conn->inbuf has the right bytes to proceed with
 * the socks handshake.
 *
 * If the handshake is complete, send it to
 * connection_ap_handshake_rewrite_and_attach().
 *
 * Return -1 if an unexpected error with conn occurs (and mark it for close),
 * else return 0.
 */
static int
connection_ap_handshake_process_socks(entry_connection_t *conn)
{
  socks_request_t *socks;
  int sockshere;
  const or_options_t *options = get_options();
  int had_reply = 0;
  connection_t *base_conn = ENTRY_TO_CONN(conn);

  tor_assert(conn);
  tor_assert(base_conn->type == CONN_TYPE_AP);
  tor_assert(base_conn->state == AP_CONN_STATE_SOCKS_WAIT);
  tor_assert(conn->socks_request);
  socks = conn->socks_request;

  log_debug(LD_APP,"entered.");

  IF_HAS_BUFFEREVENT(base_conn, {
    struct evbuffer *input = bufferevent_get_input(base_conn->bufev);
    sockshere = fetch_from_evbuffer_socks(input, socks,
                                     options->TestSocks, options->SafeSocks);
  }) ELSE_IF_NO_BUFFEREVENT {
    sockshere = fetch_from_buf_socks(base_conn->inbuf, socks,
                                     options->TestSocks, options->SafeSocks);
  };

  if (socks->replylen) {
    had_reply = 1;
    connection_write_to_buf((const char*)socks->reply, socks->replylen,
                            base_conn);
    socks->replylen = 0;
    if (sockshere == -1) {
      /* An invalid request just got a reply, no additional
       * one is necessary. */
      socks->has_finished = 1;
    }
  }

  if (sockshere == 0) {
    log_debug(LD_APP,"socks handshake not all here yet.");
    return 0;
  } else if (sockshere == -1) {
    if (!had_reply) {
      log_warn(LD_APP,"Fetching socks handshake failed. Closing.");
      connection_ap_handshake_socks_reply(conn, NULL, 0,
                                          END_STREAM_REASON_SOCKSPROTOCOL);
    }
    connection_mark_unattached_ap(conn,
                              END_STREAM_REASON_SOCKSPROTOCOL |
                              END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
    return -1;
  } /* else socks handshake is done, continue processing */

  if (SOCKS_COMMAND_IS_CONNECT(socks->command))
    control_event_stream_status(conn, STREAM_EVENT_NEW, 0);
  else
    control_event_stream_status(conn, STREAM_EVENT_NEW_RESOLVE, 0);

  return connection_ap_rewrite_and_attach_if_allowed(conn, NULL, NULL);
}

/** connection_init_accepted_conn() found a new trans AP conn.
 * Get the original destination and send it to
 * connection_ap_handshake_rewrite_and_attach().
 *
 * Return -1 if an unexpected error with conn (and it should be marked
 * for close), else return 0.
 */
int
connection_ap_process_transparent(entry_connection_t *conn)
{
  socks_request_t *socks;

  tor_assert(conn);
  tor_assert(conn->socks_request);
  socks = conn->socks_request;

  /* pretend that a socks handshake completed so we don't try to
   * send a socks reply down a transparent conn */
  socks->command = SOCKS_COMMAND_CONNECT;
  socks->has_finished = 1;

  log_debug(LD_APP,"entered.");

  if (connection_ap_get_original_destination(conn, socks) < 0) {
    log_warn(LD_APP,"Fetching original destination failed. Closing.");
    connection_mark_unattached_ap(conn,
                               END_STREAM_REASON_CANT_FETCH_ORIG_DEST);
    return -1;
  }
  /* we have the original destination */

  control_event_stream_status(conn, STREAM_EVENT_NEW, 0);

  return connection_ap_rewrite_and_attach_if_allowed(conn, NULL, NULL);
}

/** connection_edge_process_inbuf() found a conn in state natd_wait. See if
 * conn-\>inbuf has the right bytes to proceed.  See FreeBSD's libalias(3) and
 * ProxyEncodeTcpStream() in src/lib/libalias/alias_proxy.c for the encoding
 * form of the original destination.
 *
 * If the original destination is complete, send it to
 * connection_ap_handshake_rewrite_and_attach().
 *
 * Return -1 if an unexpected error with conn (and it should be marked
 * for close), else return 0.
 */
static int
connection_ap_process_natd(entry_connection_t *conn)
{
  char tmp_buf[36], *tbuf, *daddr;
  size_t tlen = 30;
  int err, port_ok;
  socks_request_t *socks;

  tor_assert(conn);
  tor_assert(ENTRY_TO_CONN(conn)->state == AP_CONN_STATE_NATD_WAIT);
  tor_assert(conn->socks_request);
  socks = conn->socks_request;

  log_debug(LD_APP,"entered.");

  /* look for LF-terminated "[DEST ip_addr port]"
   * where ip_addr is a dotted-quad and port is in string form */
  err = connection_fetch_from_buf_line(ENTRY_TO_CONN(conn), tmp_buf, &tlen);
  if (err == 0)
    return 0;
  if (err < 0) {
    log_warn(LD_APP,"NATD handshake failed (DEST too long). Closing");
    connection_mark_unattached_ap(conn, END_STREAM_REASON_INVALID_NATD_DEST);
    return -1;
  }

  if (strcmpstart(tmp_buf, "[DEST ")) {
    log_warn(LD_APP,"NATD handshake was ill-formed; closing. The client "
             "said: %s",
             escaped(tmp_buf));
    connection_mark_unattached_ap(conn, END_STREAM_REASON_INVALID_NATD_DEST);
    return -1;
  }

  daddr = tbuf = &tmp_buf[0] + 6; /* after end of "[DEST " */
  if (!(tbuf = strchr(tbuf, ' '))) {
    log_warn(LD_APP,"NATD handshake was ill-formed; closing. The client "
             "said: %s",
             escaped(tmp_buf));
    connection_mark_unattached_ap(conn, END_STREAM_REASON_INVALID_NATD_DEST);
    return -1;
  }
  *tbuf++ = '\0';

  /* pretend that a socks handshake completed so we don't try to
   * send a socks reply down a natd conn */
  strlcpy(socks->address, daddr, sizeof(socks->address));
  socks->port = (uint16_t)
    tor_parse_long(tbuf, 10, 1, 65535, &port_ok, &daddr);
  if (!port_ok) {
    log_warn(LD_APP,"NATD handshake failed; port %s is ill-formed or out "
             "of range.", escaped(tbuf));
    connection_mark_unattached_ap(conn, END_STREAM_REASON_INVALID_NATD_DEST);
    return -1;
  }

  socks->command = SOCKS_COMMAND_CONNECT;
  socks->has_finished = 1;

  control_event_stream_status(conn, STREAM_EVENT_NEW, 0);

  ENTRY_TO_CONN(conn)->state = AP_CONN_STATE_CIRCUIT_WAIT;

  return connection_ap_rewrite_and_attach_if_allowed(conn, NULL, NULL);
}

/** Iterate over the two bytes of stream_id until we get one that is not
 * already in use; return it. Return 0 if can't get a unique stream_id.
 */
static streamid_t
get_unique_stream_id_by_circ(origin_circuit_t *circ)
{
  edge_connection_t *tmpconn;
  streamid_t test_stream_id;
  uint32_t attempts=0;

 again:
  test_stream_id = circ->next_stream_id++;
  if (++attempts > 1<<16) {
    /* Make sure we don't loop forever if all stream_id's are used. */
    log_warn(LD_APP,"No unused stream IDs. Failing.");
    return 0;
  }
  if (test_stream_id == 0)
    goto again;
  for (tmpconn = circ->p_streams; tmpconn; tmpconn=tmpconn->next_stream)
    if (tmpconn->stream_id == test_stream_id)
      goto again;
  return test_stream_id;
}

/** Return true iff <b>conn</b> is linked to a circuit and configured to use
 * an exit that supports optimistic data. */
static int
connection_ap_supports_optimistic_data(const entry_connection_t *conn)
{
  const edge_connection_t *edge_conn = ENTRY_TO_EDGE_CONN(conn);
  /* We can only send optimistic data if we're connected to an open
     general circuit. */
  if (edge_conn->on_circuit == NULL ||
      edge_conn->on_circuit->state != CIRCUIT_STATE_OPEN ||
      edge_conn->on_circuit->purpose != CIRCUIT_PURPOSE_C_GENERAL)
    return 0;

  return conn->may_use_optimistic_data;
}

/** Write a relay begin cell, using destaddr and destport from ap_conn's
 * socks_request field, and send it down circ.
 *
 * If ap_conn is broken, mark it for close and return -1. Else return 0.
 */
int
connection_ap_handshake_send_begin(entry_connection_t *ap_conn)
{
  char payload[CELL_PAYLOAD_SIZE];
  int payload_len;
  int begin_type;
  origin_circuit_t *circ;
  edge_connection_t *edge_conn = ENTRY_TO_EDGE_CONN(ap_conn);
  connection_t *base_conn = TO_CONN(edge_conn);
  tor_assert(edge_conn->on_circuit);
  circ = TO_ORIGIN_CIRCUIT(edge_conn->on_circuit);

  tor_assert(base_conn->type == CONN_TYPE_AP);
  tor_assert(base_conn->state == AP_CONN_STATE_CIRCUIT_WAIT);
  tor_assert(ap_conn->socks_request);
  tor_assert(SOCKS_COMMAND_IS_CONNECT(ap_conn->socks_request->command));

  edge_conn->stream_id = get_unique_stream_id_by_circ(circ);
  if (edge_conn->stream_id==0) {
    /* XXXX024 Instead of closing this stream, we should make it get
     * retried on another circuit. */
    connection_mark_unattached_ap(ap_conn, END_STREAM_REASON_INTERNAL);

    /* Mark this circuit "unusable for new streams". */
    /* XXXX024 this is a kludgy way to do this. */
    tor_assert(circ->base_.timestamp_dirty);
    circ->base_.timestamp_dirty -= get_options()->MaxCircuitDirtiness;
    return -1;
  }

  tor_snprintf(payload,RELAY_PAYLOAD_SIZE, "%s:%d",
               (circ->base_.purpose == CIRCUIT_PURPOSE_C_GENERAL) ?
                 ap_conn->socks_request->address : "",
               ap_conn->socks_request->port);
  payload_len = (int)strlen(payload)+1;

  log_info(LD_APP,
           "Sending relay cell %d to begin stream %d.",
           (int)ap_conn->use_begindir,
           edge_conn->stream_id);

  begin_type = ap_conn->use_begindir ?
                 RELAY_COMMAND_BEGIN_DIR : RELAY_COMMAND_BEGIN;
  if (begin_type == RELAY_COMMAND_BEGIN) {
#ifndef NON_ANONYMOUS_MODE_ENABLED
    tor_assert(circ->build_state->onehop_tunnel == 0);
#endif
  }

  if (connection_edge_send_command(edge_conn, begin_type,
                  begin_type == RELAY_COMMAND_BEGIN ? payload : NULL,
                  begin_type == RELAY_COMMAND_BEGIN ? payload_len : 0) < 0)
    return -1; /* circuit is closed, don't continue */

  edge_conn->package_window = STREAMWINDOW_START;
  edge_conn->deliver_window = STREAMWINDOW_START;
  base_conn->state = AP_CONN_STATE_CONNECT_WAIT;
  log_info(LD_APP,"Address/port sent, ap socket %d, n_circ_id %d",
           base_conn->s, circ->base_.n_circ_id);
  control_event_stream_status(ap_conn, STREAM_EVENT_SENT_CONNECT, 0);

  /* If there's queued-up data, send it now */
  if ((connection_get_inbuf_len(base_conn) ||
       ap_conn->sending_optimistic_data) &&
      connection_ap_supports_optimistic_data(ap_conn)) {
    log_info(LD_APP, "Sending up to %ld + %ld bytes of queued-up data",
             (long)connection_get_inbuf_len(base_conn),
             ap_conn->sending_optimistic_data ?
             (long)generic_buffer_len(ap_conn->sending_optimistic_data) : 0);
    if (connection_edge_package_raw_inbuf(edge_conn, 1, NULL) < 0) {
      connection_mark_for_close(base_conn);
    }
  }

  return 0;
}

/** Write a relay resolve cell, using destaddr and destport from ap_conn's
 * socks_request field, and send it down circ.
 *
 * If ap_conn is broken, mark it for close and return -1. Else return 0.
 */
int
connection_ap_handshake_send_resolve(entry_connection_t *ap_conn)
{
  int payload_len, command;
  const char *string_addr;
  char inaddr_buf[REVERSE_LOOKUP_NAME_BUF_LEN];
  origin_circuit_t *circ;
  edge_connection_t *edge_conn = ENTRY_TO_EDGE_CONN(ap_conn);
  connection_t *base_conn = TO_CONN(edge_conn);
  tor_assert(edge_conn->on_circuit);
  circ = TO_ORIGIN_CIRCUIT(edge_conn->on_circuit);

  tor_assert(base_conn->type == CONN_TYPE_AP);
  tor_assert(base_conn->state == AP_CONN_STATE_CIRCUIT_WAIT);
  tor_assert(ap_conn->socks_request);
  tor_assert(circ->base_.purpose == CIRCUIT_PURPOSE_C_GENERAL);

  command = ap_conn->socks_request->command;
  tor_assert(SOCKS_COMMAND_IS_RESOLVE(command));

  edge_conn->stream_id = get_unique_stream_id_by_circ(circ);
  if (edge_conn->stream_id==0) {
    /* XXXX024 Instead of closing this stream, we should make it get
     * retried on another circuit. */
    connection_mark_unattached_ap(ap_conn, END_STREAM_REASON_INTERNAL);

    /* Mark this circuit "unusable for new streams". */
    /* XXXX024 this is a kludgy way to do this. */
    tor_assert(circ->base_.timestamp_dirty);
    circ->base_.timestamp_dirty -= get_options()->MaxCircuitDirtiness;
    return -1;
  }

  if (command == SOCKS_COMMAND_RESOLVE) {
    string_addr = ap_conn->socks_request->address;
    payload_len = (int)strlen(string_addr)+1;
  } else {
    /* command == SOCKS_COMMAND_RESOLVE_PTR */
    const char *a = ap_conn->socks_request->address;
    tor_addr_t addr;
    int r;

    /* We're doing a reverse lookup.  The input could be an IP address, or
     * could be an .in-addr.arpa or .ip6.arpa address */
    r = tor_addr_parse_PTR_name(&addr, a, AF_INET, 1);
    if (r <= 0) {
      log_warn(LD_APP, "Rejecting ill-formed reverse lookup of %s",
               safe_str_client(a));
      connection_mark_unattached_ap(ap_conn, END_STREAM_REASON_INTERNAL);
      return -1;
    }

    r = tor_addr_to_PTR_name(inaddr_buf, sizeof(inaddr_buf), &addr);
    if (r < 0) {
      log_warn(LD_BUG, "Couldn't generate reverse lookup hostname of %s",
               safe_str_client(a));
      connection_mark_unattached_ap(ap_conn, END_STREAM_REASON_INTERNAL);
      return -1;
    }

    string_addr = inaddr_buf;
    payload_len = (int)strlen(inaddr_buf)+1;
    tor_assert(payload_len <= (int)sizeof(inaddr_buf));
  }

  log_debug(LD_APP,
            "Sending relay cell to begin stream %d.", edge_conn->stream_id);

  if (connection_edge_send_command(edge_conn,
                           RELAY_COMMAND_RESOLVE,
                           string_addr, payload_len) < 0)
    return -1; /* circuit is closed, don't continue */

  tor_free(base_conn->address); /* Maybe already set by dnsserv. */
  base_conn->address = tor_strdup("(Tor_internal)");
  base_conn->state = AP_CONN_STATE_RESOLVE_WAIT;
  log_info(LD_APP,"Address sent for resolve, ap socket %d, n_circ_id %d",
           base_conn->s, circ->base_.n_circ_id);
  control_event_stream_status(ap_conn, STREAM_EVENT_NEW, 0);
  control_event_stream_status(ap_conn, STREAM_EVENT_SENT_RESOLVE, 0);
  return 0;
}

/** Make an AP connection_t linked to the connection_t <b>partner</b>. make a
 * new linked connection pair, and attach one side to the conn, connection_add
 * it, initialize it to circuit_wait, and call
 * connection_ap_handshake_attach_circuit(conn) on it.
 *
 * Return the newly created end of the linked connection pair, or -1 if error.
 */
entry_connection_t *
connection_ap_make_link(connection_t *partner,
                        char *address, uint16_t port,
                        const char *digest,
                        int session_group, int isolation_flags,
                        int use_begindir, int want_onehop)
{
  entry_connection_t *conn;
  connection_t *base_conn;

  log_info(LD_APP,"Making internal %s tunnel to %s:%d ...",
           want_onehop ? "direct" : "anonymized",
           safe_str_client(address), port);

  conn = entry_connection_new(CONN_TYPE_AP, tor_addr_family(&partner->addr));
  base_conn = ENTRY_TO_CONN(conn);
  base_conn->linked = 1; /* so that we can add it safely below. */

  /* populate conn->socks_request */

  /* leave version at zero, so the socks_reply is empty */
  conn->socks_request->socks_version = 0;
  conn->socks_request->has_finished = 0; /* waiting for 'connected' */
  strlcpy(conn->socks_request->address, address,
          sizeof(conn->socks_request->address));
  conn->socks_request->port = port;
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;
  conn->want_onehop = want_onehop;
  conn->use_begindir = use_begindir;
  if (use_begindir) {
    conn->chosen_exit_name = tor_malloc(HEX_DIGEST_LEN+2);
    conn->chosen_exit_name[0] = '$';
    tor_assert(digest);
    base16_encode(conn->chosen_exit_name+1,HEX_DIGEST_LEN+1,
                  digest, DIGEST_LEN);
  }

  /* Populate isolation fields. */
  conn->socks_request->listener_type = CONN_TYPE_DIR_LISTENER;
  conn->original_dest_address = tor_strdup(address);
  conn->session_group = session_group;
  conn->isolation_flags = isolation_flags;

  base_conn->address = tor_strdup("(Tor_internal)");
  tor_addr_make_unspec(&base_conn->addr);
  base_conn->port = 0;

  connection_link_connections(partner, base_conn);

  if (connection_add(base_conn) < 0) { /* no space, forget it */
    connection_free(base_conn);
    return NULL;
  }

  base_conn->state = AP_CONN_STATE_CIRCUIT_WAIT;

  control_event_stream_status(conn, STREAM_EVENT_NEW, 0);

  /* attaching to a dirty circuit is fine */
  if (connection_ap_handshake_attach_circuit(conn) < 0) {
    if (!base_conn->marked_for_close)
      connection_mark_unattached_ap(conn, END_STREAM_REASON_CANT_ATTACH);
    return NULL;
  }

  log_info(LD_APP,"... application connection created and linked.");
  return conn;
}

/** Notify any interested controller connections about a new hostname resolve
 * or resolve error.  Takes the same arguments as does
 * connection_ap_handshake_socks_resolved(). */
static void
tell_controller_about_resolved_result(entry_connection_t *conn,
                                      int answer_type,
                                      size_t answer_len,
                                      const char *answer,
                                      int ttl,
                                      time_t expires)
{

  if (ttl >= 0 && (answer_type == RESOLVED_TYPE_IPV4 ||
                   answer_type == RESOLVED_TYPE_HOSTNAME)) {
    return; /* we already told the controller. */
  } else if (answer_type == RESOLVED_TYPE_IPV4 && answer_len >= 4) {
    char *cp = tor_dup_ip(ntohl(get_uint32(answer)));
    control_event_address_mapped(conn->socks_request->address,
                                 cp, expires, NULL);
    tor_free(cp);
  } else if (answer_type == RESOLVED_TYPE_HOSTNAME && answer_len < 256) {
    char *cp = tor_strndup(answer, answer_len);
    control_event_address_mapped(conn->socks_request->address,
                                 cp, expires, NULL);
    tor_free(cp);
  } else {
    control_event_address_mapped(conn->socks_request->address,
                                 "<error>",
                                 time(NULL)+ttl,
                                 "error=yes");
  }
}

/** Send an answer to an AP connection that has requested a DNS lookup via
 * SOCKS.  The type should be one of RESOLVED_TYPE_(IPV4|IPV6|HOSTNAME) or -1
 * for unreachable; the answer should be in the format specified in the socks
 * extensions document.  <b>ttl</b> is the ttl for the answer, or -1 on
 * certain errors or for values that didn't come via DNS.  <b>expires</b> is
 * a time when the answer expires, or -1 or TIME_MAX if there's a good TTL.
 **/
/* XXXX the use of the ttl and expires fields is nutty.  Let's make this
 * interface and those that use it less ugly. */
void
connection_ap_handshake_socks_resolved(entry_connection_t *conn,
                                       int answer_type,
                                       size_t answer_len,
                                       const uint8_t *answer,
                                       int ttl,
                                       time_t expires)
{
  char buf[384];
  size_t replylen;

  if (ttl >= 0) {
    if (answer_type == RESOLVED_TYPE_IPV4 && answer_len == 4) {
      uint32_t a = ntohl(get_uint32(answer));
      if (a)
        client_dns_set_addressmap(conn->socks_request->address, a,
                                  conn->chosen_exit_name, ttl);
    } else if (answer_type == RESOLVED_TYPE_HOSTNAME && answer_len < 256) {
      char *cp = tor_strndup((char*)answer, answer_len);
      client_dns_set_reverse_addressmap(conn->socks_request->address,
                                        cp,
                                        conn->chosen_exit_name, ttl);
      tor_free(cp);
    }
  }

  if (ENTRY_TO_EDGE_CONN(conn)->is_dns_request) {
    if (conn->dns_server_request) {
      /* We had a request on our DNS port: answer it. */
      dnsserv_resolved(conn, answer_type, answer_len, (char*)answer, ttl);
      conn->socks_request->has_finished = 1;
      return;
    } else {
      /* This must be a request from the controller. We already sent
       * a mapaddress if there's a ttl. */
      tell_controller_about_resolved_result(conn, answer_type, answer_len,
                                            (char*)answer, ttl, expires);
      conn->socks_request->has_finished = 1;
      return;
    }
    /* We shouldn't need to free conn here; it gets marked by the caller. */
  }

  if (conn->socks_request->socks_version == 4) {
    buf[0] = 0x00; /* version */
    if (answer_type == RESOLVED_TYPE_IPV4 && answer_len == 4) {
      buf[1] = SOCKS4_GRANTED;
      set_uint16(buf+2, 0);
      memcpy(buf+4, answer, 4); /* address */
      replylen = SOCKS4_NETWORK_LEN;
    } else { /* "error" */
      buf[1] = SOCKS4_REJECT;
      memset(buf+2, 0, 6);
      replylen = SOCKS4_NETWORK_LEN;
    }
  } else if (conn->socks_request->socks_version == 5) {
    /* SOCKS5 */
    buf[0] = 0x05; /* version */
    if (answer_type == RESOLVED_TYPE_IPV4 && answer_len == 4) {
      buf[1] = SOCKS5_SUCCEEDED;
      buf[2] = 0; /* reserved */
      buf[3] = 0x01; /* IPv4 address type */
      memcpy(buf+4, answer, 4); /* address */
      set_uint16(buf+8, 0); /* port == 0. */
      replylen = 10;
    } else if (answer_type == RESOLVED_TYPE_IPV6 && answer_len == 16) {
      buf[1] = SOCKS5_SUCCEEDED;
      buf[2] = 0; /* reserved */
      buf[3] = 0x04; /* IPv6 address type */
      memcpy(buf+4, answer, 16); /* address */
      set_uint16(buf+20, 0); /* port == 0. */
      replylen = 22;
    } else if (answer_type == RESOLVED_TYPE_HOSTNAME && answer_len < 256) {
      buf[1] = SOCKS5_SUCCEEDED;
      buf[2] = 0; /* reserved */
      buf[3] = 0x03; /* Domainname address type */
      buf[4] = (char)answer_len;
      memcpy(buf+5, answer, answer_len); /* address */
      set_uint16(buf+5+answer_len, 0); /* port == 0. */
      replylen = 5+answer_len+2;
    } else {
      buf[1] = SOCKS5_HOST_UNREACHABLE;
      memset(buf+2, 0, 8);
      replylen = 10;
    }
  } else {
    /* no socks version info; don't send anything back */
    return;
  }
  connection_ap_handshake_socks_reply(conn, buf, replylen,
          (answer_type == RESOLVED_TYPE_IPV4 ||
           answer_type == RESOLVED_TYPE_IPV6 ||
           answer_type == RESOLVED_TYPE_HOSTNAME) ?
                                      0 : END_STREAM_REASON_RESOLVEFAILED);
}

/** Send a socks reply to stream <b>conn</b>, using the appropriate
 * socks version, etc, and mark <b>conn</b> as completed with SOCKS
 * handshaking.
 *
 * If <b>reply</b> is defined, then write <b>replylen</b> bytes of it to conn
 * and return, else reply based on <b>endreason</b> (one of
 * END_STREAM_REASON_*). If <b>reply</b> is undefined, <b>endreason</b> can't
 * be 0 or REASON_DONE.  Send endreason to the controller, if appropriate.
 */
void
connection_ap_handshake_socks_reply(entry_connection_t *conn, char *reply,
                                    size_t replylen, int endreason)
{
  char buf[256];
  socks5_reply_status_t status =
    stream_end_reason_to_socks5_response(endreason);

  tor_assert(conn->socks_request); /* make sure it's an AP stream */

  control_event_stream_status(conn,
     status==SOCKS5_SUCCEEDED ? STREAM_EVENT_SUCCEEDED : STREAM_EVENT_FAILED,
                              endreason);

  if (conn->socks_request->has_finished) {
    log_warn(LD_BUG, "(Harmless.) duplicate calls to "
             "connection_ap_handshake_socks_reply.");
    return;
  }
  if (replylen) { /* we already have a reply in mind */
    connection_write_to_buf(reply, replylen, ENTRY_TO_CONN(conn));
    conn->socks_request->has_finished = 1;
    return;
  }
  if (conn->socks_request->socks_version == 4) {
    memset(buf,0,SOCKS4_NETWORK_LEN);
    buf[1] = (status==SOCKS5_SUCCEEDED ? SOCKS4_GRANTED : SOCKS4_REJECT);
    /* leave version, destport, destip zero */
    connection_write_to_buf(buf, SOCKS4_NETWORK_LEN, ENTRY_TO_CONN(conn));
  } else if (conn->socks_request->socks_version == 5) {
    buf[0] = 5; /* version 5 */
    buf[1] = (char)status;
    buf[2] = 0;
    buf[3] = 1; /* ipv4 addr */
    memset(buf+4,0,6); /* Set external addr/port to 0.
                          The spec doesn't seem to say what to do here. -RD */
    connection_write_to_buf(buf,10,ENTRY_TO_CONN(conn));
  }
  /* If socks_version isn't 4 or 5, don't send anything.
   * This can happen in the case of AP bridges. */
  conn->socks_request->has_finished = 1;
  return;
}

/** A relay 'begin' or 'begin_dir' cell has arrived, and either we are
 * an exit hop for the circuit, or we are the origin and it is a
 * rendezvous begin.
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
 * Return -(some circuit end reason) if we want to tear down <b>circ</b>.
 * Else return 0.
 */
int
connection_exit_begin_conn(cell_t *cell, circuit_t *circ)
{
  edge_connection_t *n_stream;
  relay_header_t rh;
  char *address=NULL;
  uint16_t port;
  or_circuit_t *or_circ = NULL;
  const or_options_t *options = get_options();

  assert_circuit_ok(circ);
  if (!CIRCUIT_IS_ORIGIN(circ))
    or_circ = TO_OR_CIRCUIT(circ);

  relay_header_unpack(&rh, cell->payload);
  if (rh.length > RELAY_PAYLOAD_SIZE)
    return -1;

  /* Note: we have to use relay_send_command_from_edge here, not
   * connection_edge_end or connection_edge_send_command, since those require
   * that we have a stream connected to a circuit, and we don't connect to a
   * circuit until we have a pending/successful resolve. */

  if (!server_mode(options) &&
      circ->purpose != CIRCUIT_PURPOSE_S_REND_JOINED) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Relay begin cell at non-server. Closing.");
    relay_send_end_cell_from_edge(rh.stream_id, circ,
                                  END_STREAM_REASON_EXITPOLICY, NULL);
    return 0;
  }

  if (rh.command == RELAY_COMMAND_BEGIN) {
    if (!memchr(cell->payload+RELAY_HEADER_SIZE, 0, rh.length)) {
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
             "Relay begin cell has no \\0. Closing.");
      relay_send_end_cell_from_edge(rh.stream_id, circ,
                                    END_STREAM_REASON_TORPROTOCOL, NULL);
      return 0;
    }
    if (tor_addr_port_split(LOG_PROTOCOL_WARN,
                            (char*)(cell->payload+RELAY_HEADER_SIZE),
                            &address,&port)<0) {
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
             "Unable to parse addr:port in relay begin cell. Closing.");
      relay_send_end_cell_from_edge(rh.stream_id, circ,
                                    END_STREAM_REASON_TORPROTOCOL, NULL);
      return 0;
    }
    if (port==0) {
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
             "Missing port in relay begin cell. Closing.");
      relay_send_end_cell_from_edge(rh.stream_id, circ,
                                    END_STREAM_REASON_TORPROTOCOL, NULL);
      tor_free(address);
      return 0;
    }
    if (or_circ && or_circ->p_chan) {
      if (!options->AllowSingleHopExits &&
           (or_circ->is_first_hop ||
            (!connection_or_digest_is_known_relay(
                or_circ->p_chan->identity_digest) &&
          should_refuse_unknown_exits(options)))) {
        /* Don't let clients use us as a single-hop proxy, unless the user
         * has explicitly allowed that in the config. It attracts attackers
         * and users who'd be better off with, well, single-hop proxies.
         */
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "Attempt by %s to open a stream %s. Closing.",
               safe_str(channel_get_canonical_remote_descr(or_circ->p_chan)),
               or_circ->is_first_hop ? "on first hop of circuit" :
                                       "from unknown relay");
        relay_send_end_cell_from_edge(rh.stream_id, circ,
                                      or_circ->is_first_hop ?
                                        END_STREAM_REASON_TORPROTOCOL :
                                        END_STREAM_REASON_MISC,
                                      NULL);
        tor_free(address);
        return 0;
      }
    }
  } else if (rh.command == RELAY_COMMAND_BEGIN_DIR) {
    if (!directory_permits_begindir_requests(options) ||
        circ->purpose != CIRCUIT_PURPOSE_OR) {
      relay_send_end_cell_from_edge(rh.stream_id, circ,
                                    END_STREAM_REASON_NOTDIRECTORY, NULL);
      return 0;
    }
    /* Make sure to get the 'real' address of the previous hop: the
     * caller might want to know whether his IP address has changed, and
     * we might already have corrected base_.addr[ess] for the relay's
     * canonical IP address. */
    if (or_circ && or_circ->p_chan)
      address = tor_strdup(channel_get_actual_remote_address(or_circ->p_chan));
    else
      address = tor_strdup("127.0.0.1");
    port = 1; /* XXXX This value is never actually used anywhere, and there
               * isn't "really" a connection here.  But we
               * need to set it to something nonzero. */
  } else {
    log_warn(LD_BUG, "Got an unexpected command %d", (int)rh.command);
    relay_send_end_cell_from_edge(rh.stream_id, circ,
                                  END_STREAM_REASON_INTERNAL, NULL);
    return 0;
  }

  log_debug(LD_EXIT,"Creating new exit connection.");
  n_stream = edge_connection_new(CONN_TYPE_EXIT, AF_INET);

  /* Remember the tunneled request ID in the new edge connection, so that
   * we can measure download times. */
  n_stream->dirreq_id = circ->dirreq_id;

  n_stream->base_.purpose = EXIT_PURPOSE_CONNECT;

  n_stream->stream_id = rh.stream_id;
  n_stream->base_.port = port;
  /* leave n_stream->s at -1, because it's not yet valid */
  n_stream->package_window = STREAMWINDOW_START;
  n_stream->deliver_window = STREAMWINDOW_START;

  if (circ->purpose == CIRCUIT_PURPOSE_S_REND_JOINED) {
    origin_circuit_t *origin_circ = TO_ORIGIN_CIRCUIT(circ);
    log_info(LD_REND,"begin is for rendezvous. configuring stream.");
    n_stream->base_.address = tor_strdup("(rendezvous)");
    n_stream->base_.state = EXIT_CONN_STATE_CONNECTING;
    n_stream->rend_data = rend_data_dup(origin_circ->rend_data);
    tor_assert(connection_edge_is_rendezvous_stream(n_stream));
    assert_circuit_ok(circ);
    if (rend_service_set_connection_addr_port(n_stream, origin_circ) < 0) {
      log_info(LD_REND,"Didn't find rendezvous service (port %d)",
               n_stream->base_.port);
      relay_send_end_cell_from_edge(rh.stream_id, circ,
                                    END_STREAM_REASON_EXITPOLICY,
                                    origin_circ->cpath->prev);
      connection_free(TO_CONN(n_stream));
      tor_free(address);
      return 0;
    }
    assert_circuit_ok(circ);
    log_debug(LD_REND,"Finished assigning addr/port");
    n_stream->cpath_layer = origin_circ->cpath->prev; /* link it */

    /* add it into the linked list of p_streams on this circuit */
    n_stream->next_stream = origin_circ->p_streams;
    n_stream->on_circuit = circ;
    origin_circ->p_streams = n_stream;
    assert_circuit_ok(circ);

    connection_exit_connect(n_stream);
    tor_free(address);
    return 0;
  }
  tor_strlower(address);
  n_stream->base_.address = address;
  n_stream->base_.state = EXIT_CONN_STATE_RESOLVEFAILED;
  /* default to failed, change in dns_resolve if it turns out not to fail */

  if (we_are_hibernating()) {
    relay_send_end_cell_from_edge(rh.stream_id, circ,
                                  END_STREAM_REASON_HIBERNATING, NULL);
    connection_free(TO_CONN(n_stream));
    return 0;
  }

  n_stream->on_circuit = circ;

  if (rh.command == RELAY_COMMAND_BEGIN_DIR) {
    tor_addr_t tmp_addr;
    tor_assert(or_circ);
    if (or_circ->p_chan &&
        channel_get_addr_if_possible(or_circ->p_chan, &tmp_addr)) {
      tor_addr_copy(&n_stream->base_.addr, &tmp_addr);
    }
    return connection_exit_connect_dir(n_stream);
  }

  log_debug(LD_EXIT,"about to start the dns_resolve().");

  /* send it off to the gethostbyname farm */
  switch (dns_resolve(n_stream)) {
    case 1: /* resolve worked; now n_stream is attached to circ. */
      assert_circuit_ok(circ);
      log_debug(LD_EXIT,"about to call connection_exit_connect().");
      connection_exit_connect(n_stream);
      return 0;
    case -1: /* resolve failed */
      relay_send_end_cell_from_edge(rh.stream_id, circ,
                                    END_STREAM_REASON_RESOLVEFAILED, NULL);
      /* n_stream got freed. don't touch it. */
      break;
    case 0: /* resolve added to pending list */
      assert_circuit_ok(circ);
      break;
  }
  return 0;
}

/**
 * Called when we receive a RELAY_COMMAND_RESOLVE cell 'cell' along the
 * circuit <b>circ</b>;
 * begin resolving the hostname, and (eventually) reply with a RESOLVED cell.
 */
int
connection_exit_begin_resolve(cell_t *cell, or_circuit_t *circ)
{
  edge_connection_t *dummy_conn;
  relay_header_t rh;

  assert_circuit_ok(TO_CIRCUIT(circ));
  relay_header_unpack(&rh, cell->payload);
  if (rh.length > RELAY_PAYLOAD_SIZE)
    return -1;

  /* This 'dummy_conn' only exists to remember the stream ID
   * associated with the resolve request; and to make the
   * implementation of dns.c more uniform.  (We really only need to
   * remember the circuit, the stream ID, and the hostname to be
   * resolved; but if we didn't store them in a connection like this,
   * the housekeeping in dns.c would get way more complicated.)
   */
  dummy_conn = edge_connection_new(CONN_TYPE_EXIT, AF_INET);
  dummy_conn->stream_id = rh.stream_id;
  dummy_conn->base_.address = tor_strndup(
                                       (char*)cell->payload+RELAY_HEADER_SIZE,
                                       rh.length);
  dummy_conn->base_.port = 0;
  dummy_conn->base_.state = EXIT_CONN_STATE_RESOLVEFAILED;
  dummy_conn->base_.purpose = EXIT_PURPOSE_RESOLVE;

  dummy_conn->on_circuit = TO_CIRCUIT(circ);

  /* send it off to the gethostbyname farm */
  switch (dns_resolve(dummy_conn)) {
    case -1: /* Impossible to resolve; a resolved cell was sent. */
      /* Connection freed; don't touch it. */
      return 0;
    case 1: /* The result was cached; a resolved cell was sent. */
      if (!dummy_conn->base_.marked_for_close)
        connection_free(TO_CONN(dummy_conn));
      return 0;
    case 0: /* resolve added to pending list */
      assert_circuit_ok(TO_CIRCUIT(circ));
      break;
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
void
connection_exit_connect(edge_connection_t *edge_conn)
{
  const tor_addr_t *addr;
  uint16_t port;
  connection_t *conn = TO_CONN(edge_conn);
  int socket_error = 0;

  if (!connection_edge_is_rendezvous_stream(edge_conn) &&
      router_compare_to_my_exit_policy(edge_conn)) {
    log_info(LD_EXIT,"%s:%d failed exit policy. Closing.",
             escaped_safe_str_client(conn->address), conn->port);
    connection_edge_end(edge_conn, END_STREAM_REASON_EXITPOLICY);
    circuit_detach_stream(circuit_get_by_edge_conn(edge_conn), edge_conn);
    connection_free(conn);
    return;
  }

  addr = &conn->addr;
  port = conn->port;

  log_debug(LD_EXIT,"about to try connecting");
  switch (connection_connect(conn, conn->address, addr, port, &socket_error)) {
    case -1: {
      int reason = errno_to_stream_end_reason(socket_error);
      connection_edge_end(edge_conn, reason);
      circuit_detach_stream(circuit_get_by_edge_conn(edge_conn), edge_conn);
      connection_free(conn);
      return;
    }
    case 0:
      conn->state = EXIT_CONN_STATE_CONNECTING;

      connection_watch_events(conn, READ_EVENT | WRITE_EVENT);
      /* writable indicates finish;
       * readable/error indicates broken link in windows-land. */
      return;
    /* case 1: fall through */
  }

  conn->state = EXIT_CONN_STATE_OPEN;
  if (connection_get_outbuf_len(conn)) {
    /* in case there are any queued data cells */
    log_warn(LD_BUG,"newly connected conn had data waiting!");
//    connection_start_writing(conn);
  }
  IF_HAS_NO_BUFFEREVENT(conn)
    connection_watch_events(conn, READ_EVENT);

  /* also, deliver a 'connected' cell back through the circuit. */
  if (connection_edge_is_rendezvous_stream(edge_conn)) {
    /* rendezvous stream */
    /* don't send an address back! */
    connection_edge_send_command(edge_conn,
                                 RELAY_COMMAND_CONNECTED,
                                 NULL, 0);
  } else { /* normal stream */
    char connected_payload[20];
    int connected_payload_len;
    if (tor_addr_family(&conn->addr) == AF_INET) {
      set_uint32(connected_payload, tor_addr_to_ipv4n(&conn->addr));
      connected_payload_len = 4;
    } else {
      memcpy(connected_payload, tor_addr_to_in6_addr8(&conn->addr), 16);
      connected_payload_len = 16;
    }
    set_uint32(connected_payload+connected_payload_len,
               htonl(dns_clip_ttl(edge_conn->address_ttl)));
    connected_payload_len += 4;
    connection_edge_send_command(edge_conn,
                                 RELAY_COMMAND_CONNECTED,
                                 connected_payload, connected_payload_len);
  }
}

/** Given an exit conn that should attach to us as a directory server, open a
 * bridge connection with a linked connection pair, create a new directory
 * conn, and join them together.  Return 0 on success (or if there was an
 * error we could send back an end cell for).  Return -(some circuit end
 * reason) if the circuit needs to be torn down.  Either connects
 * <b>exitconn</b>, frees it, or marks it, as appropriate.
 */
static int
connection_exit_connect_dir(edge_connection_t *exitconn)
{
  dir_connection_t *dirconn = NULL;
  or_circuit_t *circ = TO_OR_CIRCUIT(exitconn->on_circuit);

  log_info(LD_EXIT, "Opening local connection for anonymized directory exit");

  exitconn->base_.state = EXIT_CONN_STATE_OPEN;

  dirconn = dir_connection_new(tor_addr_family(&exitconn->base_.addr));

  tor_addr_copy(&dirconn->base_.addr, &exitconn->base_.addr);
  dirconn->base_.port = 0;
  dirconn->base_.address = tor_strdup(exitconn->base_.address);
  dirconn->base_.type = CONN_TYPE_DIR;
  dirconn->base_.purpose = DIR_PURPOSE_SERVER;
  dirconn->base_.state = DIR_CONN_STATE_SERVER_COMMAND_WAIT;

  /* Note that the new dir conn belongs to the same tunneled request as
   * the edge conn, so that we can measure download times. */
  dirconn->dirreq_id = exitconn->dirreq_id;

  connection_link_connections(TO_CONN(dirconn), TO_CONN(exitconn));

  if (connection_add(TO_CONN(exitconn))<0) {
    connection_edge_end(exitconn, END_STREAM_REASON_RESOURCELIMIT);
    connection_free(TO_CONN(exitconn));
    connection_free(TO_CONN(dirconn));
    return 0;
  }

  /* link exitconn to circ, now that we know we can use it. */
  exitconn->next_stream = circ->n_streams;
  circ->n_streams = exitconn;

  if (connection_add(TO_CONN(dirconn))<0) {
    connection_edge_end(exitconn, END_STREAM_REASON_RESOURCELIMIT);
    connection_close_immediate(TO_CONN(exitconn));
    connection_mark_for_close(TO_CONN(exitconn));
    connection_free(TO_CONN(dirconn));
    return 0;
  }

  connection_start_reading(TO_CONN(dirconn));
  connection_start_reading(TO_CONN(exitconn));

  if (connection_edge_send_command(exitconn,
                                   RELAY_COMMAND_CONNECTED, NULL, 0) < 0) {
    connection_mark_for_close(TO_CONN(exitconn));
    connection_mark_for_close(TO_CONN(dirconn));
    return 0;
  }

  return 0;
}

/** Return 1 if <b>conn</b> is a rendezvous stream, or 0 if
 * it is a general stream.
 */
int
connection_edge_is_rendezvous_stream(edge_connection_t *conn)
{
  tor_assert(conn);
  if (conn->rend_data)
    return 1;
  return 0;
}

/** Return 1 if router <b>exit</b> is likely to allow stream <b>conn</b>
 * to exit from it, or 0 if it probably will not allow it.
 * (We might be uncertain if conn's destination address has not yet been
 * resolved.)
 */
int
connection_ap_can_use_exit(const entry_connection_t *conn, const node_t *exit)
{
  const or_options_t *options = get_options();

  tor_assert(conn);
  tor_assert(conn->socks_request);
  tor_assert(exit);

  /* If a particular exit node has been requested for the new connection,
   * make sure the exit node of the existing circuit matches exactly.
   */
  if (conn->chosen_exit_name) {
    const node_t *chosen_exit =
      node_get_by_nickname(conn->chosen_exit_name, 1);
    if (!chosen_exit || tor_memneq(chosen_exit->identity,
                               exit->identity, DIGEST_LEN)) {
      /* doesn't match */
//      log_debug(LD_APP,"Requested node '%s', considering node '%s'. No.",
//                conn->chosen_exit_name, exit->nickname);
      return 0;
    }
  }

  if (conn->use_begindir) {
    /* Internal directory fetches do not count as exiting. */
    return 1;
  }

  if (conn->socks_request->command == SOCKS_COMMAND_CONNECT) {
    struct in_addr in;
    tor_addr_t addr, *addrp = NULL;
    addr_policy_result_t r;
    if (tor_inet_aton(conn->socks_request->address, &in)) {
      tor_addr_from_in(&addr, &in);
      addrp = &addr;
    }
    r = compare_tor_addr_to_node_policy(addrp, conn->socks_request->port,exit);
    if (r == ADDR_POLICY_REJECTED)
      return 0; /* We know the address, and the exit policy rejects it. */
    if (r == ADDR_POLICY_PROBABLY_REJECTED && !conn->chosen_exit_name)
      return 0; /* We don't know the addr, but the exit policy rejects most
                 * addresses with this port. Since the user didn't ask for
                 * this node, err on the side of caution. */
  } else if (SOCKS_COMMAND_IS_RESOLVE(conn->socks_request->command)) {
    /* Don't send DNS requests to non-exit servers by default. */
    if (!conn->chosen_exit_name && node_exit_policy_rejects_all(exit))
      return 0;
  }
  if (routerset_contains_node(options->ExcludeExitNodesUnion_, exit)) {
    /* Not a suitable exit. Refuse it. */
    return 0;
  }

  return 1;
}

/** If address is of the form "y.onion" with a well-formed handle y:
 *     Put a NUL after y, lower-case it, and return ONION_HOSTNAME.
 *
 * If address is of the form "y.onion" with a badly-formed handle y:
 *     Return BAD_HOSTNAME and log a message.
 *
 * If address is of the form "y.exit":
 *     Put a NUL after y and return EXIT_HOSTNAME.
 *
 * Otherwise:
 *     Return NORMAL_HOSTNAME and change nothing.
 */
hostname_type_t
parse_extended_hostname(char *address)
{
    char *s;
    char query[REND_SERVICE_ID_LEN_BASE32+1];

    s = strrchr(address,'.');
    if (!s)
      return NORMAL_HOSTNAME; /* no dot, thus normal */
    if (!strcmp(s+1,"exit")) {
      *s = 0; /* NUL-terminate it */
      return EXIT_HOSTNAME; /* .exit */
    }
    if (strcmp(s+1,"onion"))
      return NORMAL_HOSTNAME; /* neither .exit nor .onion, thus normal */

    /* so it is .onion */
    *s = 0; /* NUL-terminate it */
    if (strlcpy(query, address, REND_SERVICE_ID_LEN_BASE32+1) >=
        REND_SERVICE_ID_LEN_BASE32+1)
      goto failed;
    if (rend_valid_service_id(query)) {
      return ONION_HOSTNAME; /* success */
    }
 failed:
    /* otherwise, return to previous state and return 0 */
    *s = '.';
    log_warn(LD_APP, "Invalid onion hostname %s; rejecting",
             safe_str_client(address));
    return BAD_HOSTNAME;
}

/** Return true iff the (possibly NULL) <b>alen</b>-byte chunk of memory at
 * <b>a</b> is equal to the (possibly NULL) <b>blen</b>-byte chunk of memory
 * at <b>b</b>. */
static int
memeq_opt(const char *a, size_t alen, const char *b, size_t blen)
{
  if (a == NULL) {
    return (b == NULL);
  } else if (b == NULL) {
    return 0;
  } else if (alen != blen) {
    return 0;
  } else {
    return tor_memeq(a, b, alen);
  }
}

/**
 * Return true iff none of the isolation flags and fields in <b>conn</b>
 * should prevent it from being attached to <b>circ</b>.
 */
int
connection_edge_compatible_with_circuit(const entry_connection_t *conn,
                                        const origin_circuit_t *circ)
{
  const uint8_t iso = conn->isolation_flags;
  const socks_request_t *sr = conn->socks_request;

  /* If circ has never been used for an isolated connection, we can
   * totally use it for this one. */
  if (!circ->isolation_values_set)
    return 1;

  /* If circ has been used for connections having more than one value
   * for some field f, it will have the corresponding bit set in
   * isolation_flags_mixed.  If isolation_flags_mixed has any bits
   * in common with iso, then conn must be isolated from at least
   * one stream that has been attached to circ. */
  if ((iso & circ->isolation_flags_mixed) != 0) {
    /* For at least one field where conn is isolated, the circuit
     * already has mixed streams. */
    return 0;
  }

  if (! conn->original_dest_address) {
    log_warn(LD_BUG, "Reached connection_edge_compatible_with_circuit without "
             "having set conn->original_dest_address");
    ((entry_connection_t*)conn)->original_dest_address =
      tor_strdup(conn->socks_request->address);
  }

  if ((iso & ISO_STREAM) &&
      (circ->associated_isolated_stream_global_id !=
       ENTRY_TO_CONN(conn)->global_identifier))
    return 0;

  if ((iso & ISO_DESTPORT) && conn->socks_request->port != circ->dest_port)
    return 0;
  if ((iso & ISO_DESTADDR) &&
      strcasecmp(conn->original_dest_address, circ->dest_address))
    return 0;
  if ((iso & ISO_SOCKSAUTH) &&
      (! memeq_opt(sr->username, sr->usernamelen,
                   circ->socks_username, circ->socks_username_len) ||
       ! memeq_opt(sr->password, sr->passwordlen,
                   circ->socks_password, circ->socks_password_len)))
    return 0;
  if ((iso & ISO_CLIENTPROTO) &&
      (conn->socks_request->listener_type != circ->client_proto_type ||
       conn->socks_request->socks_version != circ->client_proto_socksver))
    return 0;
  if ((iso & ISO_CLIENTADDR) &&
      !tor_addr_eq(&ENTRY_TO_CONN(conn)->addr, &circ->client_addr))
    return 0;
  if ((iso & ISO_SESSIONGRP) && conn->session_group != circ->session_group)
    return 0;
  if ((iso & ISO_NYM_EPOCH) && conn->nym_epoch != circ->nym_epoch)
    return 0;

  return 1;
}

/**
 * If <b>dry_run</b> is false, update <b>circ</b>'s isolation flags and fields
 * to reflect having had <b>conn</b> attached to it, and return 0.  Otherwise,
 * if <b>dry_run</b> is true, then make no changes to <b>circ</b>, and return
 * a bitfield of isolation flags that we would have to set in
 * isolation_flags_mixed to add <b>conn</b> to <b>circ</b>, or -1 if
 * <b>circ</b> has had no streams attached to it.
 */
int
connection_edge_update_circuit_isolation(const entry_connection_t *conn,
                                         origin_circuit_t *circ,
                                         int dry_run)
{
  const socks_request_t *sr = conn->socks_request;
  if (! conn->original_dest_address) {
    log_warn(LD_BUG, "Reached connection_update_circuit_isolation without "
             "having set conn->original_dest_address");
    ((entry_connection_t*)conn)->original_dest_address =
      tor_strdup(conn->socks_request->address);
  }

  if (!circ->isolation_values_set) {
    if (dry_run)
      return -1;
    circ->associated_isolated_stream_global_id =
      ENTRY_TO_CONN(conn)->global_identifier;
    circ->dest_port = conn->socks_request->port;
    circ->dest_address = tor_strdup(conn->original_dest_address);
    circ->client_proto_type = conn->socks_request->listener_type;
    circ->client_proto_socksver = conn->socks_request->socks_version;
    tor_addr_copy(&circ->client_addr, &ENTRY_TO_CONN(conn)->addr);
    circ->session_group = conn->session_group;
    circ->nym_epoch = conn->nym_epoch;
    circ->socks_username = sr->username ?
      tor_memdup(sr->username, sr->usernamelen) : NULL;
    circ->socks_password = sr->password ?
      tor_memdup(sr->password, sr->passwordlen) : NULL;
    circ->socks_username_len = sr->usernamelen;
    circ->socks_password_len = sr->passwordlen;

    circ->isolation_values_set = 1;
    return 0;
  } else {
    uint8_t mixed = 0;
    if (conn->socks_request->port != circ->dest_port)
      mixed |= ISO_DESTPORT;
    if (strcasecmp(conn->original_dest_address, circ->dest_address))
      mixed |= ISO_DESTADDR;
    if (!memeq_opt(sr->username, sr->usernamelen,
                   circ->socks_username, circ->socks_username_len) ||
        !memeq_opt(sr->password, sr->passwordlen,
                   circ->socks_password, circ->socks_password_len))
      mixed |= ISO_SOCKSAUTH;
    if ((conn->socks_request->listener_type != circ->client_proto_type ||
         conn->socks_request->socks_version != circ->client_proto_socksver))
      mixed |= ISO_CLIENTPROTO;
    if (!tor_addr_eq(&ENTRY_TO_CONN(conn)->addr, &circ->client_addr))
      mixed |= ISO_CLIENTADDR;
    if (conn->session_group != circ->session_group)
      mixed |= ISO_SESSIONGRP;
    if (conn->nym_epoch != circ->nym_epoch)
      mixed |= ISO_NYM_EPOCH;

    if (dry_run)
      return mixed;

    if ((mixed & conn->isolation_flags) != 0) {
      log_warn(LD_BUG, "Updating a circuit with seemingly incompatible "
               "isolation flags.");
    }
    circ->isolation_flags_mixed |= mixed;
    return 0;
  }
}

/**
 * Clear the isolation settings on <b>circ</b>.
 *
 * This only works on an open circuit that has never had a stream attached to
 * it, and whose isolation settings are hypothetical.  (We set hypothetical
 * isolation settings on circuits as we're launching them, so that we
 * know whether they can handle more streams or whether we need to launch
 * even more circuits.  Once the circuit is open, if it turns out that
 * we no longer have any streams to attach to it, we clear the isolation flags
 * and data so that other streams can have a chance.)
 */
void
circuit_clear_isolation(origin_circuit_t *circ)
{
  if (circ->isolation_any_streams_attached) {
    log_warn(LD_BUG, "Tried to clear the isolation status of a dirty circuit");
    return;
  }
  if (TO_CIRCUIT(circ)->state != CIRCUIT_STATE_OPEN) {
    log_warn(LD_BUG, "Tried to clear the isolation status of a non-open "
             "circuit");
    return;
  }

  circ->isolation_values_set = 0;
  circ->isolation_flags_mixed = 0;
  circ->associated_isolated_stream_global_id = 0;
  circ->client_proto_type = 0;
  circ->client_proto_socksver = 0;
  circ->dest_port = 0;
  tor_addr_make_unspec(&circ->client_addr);
  tor_free(circ->dest_address);
  circ->session_group = -1;
  circ->nym_epoch = 0;
  if (circ->socks_username) {
    memwipe(circ->socks_username, 0x11, circ->socks_username_len);
    tor_free(circ->socks_username);
  }
  if (circ->socks_password) {
    memwipe(circ->socks_password, 0x05, circ->socks_password_len);
    tor_free(circ->socks_password);
  }
  circ->socks_username_len = circ->socks_password_len = 0;
}

