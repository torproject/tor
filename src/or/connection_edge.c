/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2007, Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char connection_edge_c_id[] =
  "$Id$";

/**
 * \file connection_edge.c
 * \brief Handle edge streams.
 **/

#include "or.h"

#ifdef HAVE_LINUX_NETFILTER_IPV4_H
#include <linux/netfilter_ipv4.h>
#define TRANS_NETFILTER
#endif

#if defined(HAVE_NET_IF_H) && defined(HAVE_NET_PFVAR_H)
#include <net/if.h>
#include <net/pfvar.h>
#define TRANS_PF
#endif

/** List of exit_redirect_t for every configured RedirectExit. */
static smartlist_t *redirect_exit_list = NULL;

static int connection_ap_handshake_process_socks(edge_connection_t *conn);
static int connection_ap_process_natd(edge_connection_t *conn);
static int connection_exit_connect_dir(edge_connection_t *exit_conn);
static int hostname_is_noconnect_address(const char *address);

/** An AP stream has failed/finished. If it hasn't already sent back
 * a socks reply, send one now (based on endreason). Also set
 * has_sent_end to 1, and mark the conn.
 */
void
_connection_mark_unattached_ap(edge_connection_t *conn, int endreason,
                               int line, const char *file)
{
  tor_assert(conn->_base.type == CONN_TYPE_AP);
  conn->_base.edge_has_sent_end = 1; /* no circ yet */

  if (conn->_base.marked_for_close) {
    /* This call will warn as appropriate. */
    _connection_mark_for_close(TO_CONN(conn), line, file);
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
      connection_ap_handshake_socks_resolved(conn, RESOLVED_TYPE_ERROR,
                                             0, NULL, -1);
    else /* unknown or no handshake at all. send no response. */
      conn->socks_request->has_finished = 1;
  }

  _connection_mark_for_close(TO_CONN(conn), line, file);
  conn->_base.hold_open_until_flushed = 1;
  conn->end_reason = endreason;
}

/** There was an EOF. Send an end and mark the connection for close.
 */
int
connection_edge_reached_eof(edge_connection_t *conn)
{
  if (buf_datalen(conn->_base.inbuf) &&
      connection_state_is_open(TO_CONN(conn))) {
    /* it still has stuff to process. don't let it die yet. */
    return 0;
  }
  log_info(LD_EDGE,"conn (fd %d) reached eof. Closing.", conn->_base.s);
  if (!conn->_base.marked_for_close) {
    /* only mark it if not already marked. it's possible to
     * get the 'end' right around when the client hangs up on us. */
    connection_edge_end(conn, END_STREAM_REASON_DONE);
    if (conn->socks_request) /* eof, so don't send a socks reply back */
      conn->socks_request->has_finished = 1;
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

  switch (conn->_base.state) {
    case AP_CONN_STATE_SOCKS_WAIT:
      if (connection_ap_handshake_process_socks(conn) < 0) {
        /* already marked */
        return -1;
      }
      return 0;
    case AP_CONN_STATE_NATD_WAIT:
      if (connection_ap_process_natd(conn) < 0) {
        /* already marked */
        return -1;
      }
      return 0;
    case AP_CONN_STATE_OPEN:
    case EXIT_CONN_STATE_OPEN:
      if (connection_edge_package_raw_inbuf(conn, package_partial) < 0) {
        /* (We already sent an end cell if possible) */
        connection_mark_for_close(TO_CONN(conn));
        return -1;
      }
      return 0;
    case EXIT_CONN_STATE_CONNECTING:
    case AP_CONN_STATE_RENDDESC_WAIT:
    case AP_CONN_STATE_CIRCUIT_WAIT:
    case AP_CONN_STATE_CONNECT_WAIT:
    case AP_CONN_STATE_RESOLVE_WAIT:
    case AP_CONN_STATE_CONTROLLER_WAIT:
      log_info(LD_EDGE,
               "data from edge while in '%s' state. Leaving it on buffer.",
               conn_state_to_string(conn->_base.type, conn->_base.state));
      return 0;
  }
  log_warn(LD_BUG,"Got unexpected state %d. Closing.",conn->_base.state);
  tor_fragile_assert();
  connection_edge_end(conn, END_STREAM_REASON_INTERNAL);
  connection_mark_for_close(TO_CONN(conn));
  return -1;
}

/** This edge needs to be closed, because its circuit has closed.
 * Mark it for close and return 0.
 */
int
connection_edge_destroy(uint16_t circ_id, edge_connection_t *conn)
{
  if (!conn->_base.marked_for_close) {
    log_info(LD_EDGE,
             "CircID %d: At an edge. Marking connection for close.", circ_id);
    if (conn->_base.type == CONN_TYPE_AP) {
      connection_mark_unattached_ap(conn, END_STREAM_REASON_DESTROY);
    } else {
      /* closing the circuit, nothing to send an END to */
      conn->_base.edge_has_sent_end = 1;
      conn->end_reason = END_STREAM_REASON_DESTROY;
      conn->end_reason |= END_STREAM_REASON_FLAG_ALREADY_SENT_CLOSED;
      if (conn->_base.type == CONN_TYPE_AP)
        control_event_stream_status(conn, STREAM_EVENT_CLOSED,
                                    END_STREAM_REASON_DESTROY);
      connection_mark_for_close(TO_CONN(conn));
      conn->_base.hold_open_until_flushed = 1;
    }
  }
  conn->cpath_layer = NULL;
  conn->on_circuit = NULL;
  return 0;
}

/** Send a relay end cell from stream <b>conn</b> down conn's circuit.  Set
 * the relay end cell's reason for closing as <b>reason</b>.
 *
 * Return -1 if this function has already been called on this conn,
 * else return 0.
 */
int
connection_edge_end(edge_connection_t *conn, char reason)
{
  char payload[RELAY_PAYLOAD_SIZE];
  size_t payload_len=1;
  circuit_t *circ;

  if (conn->_base.edge_has_sent_end) {
    log_warn(LD_BUG,"(Harmless.) Calling connection_edge_end (reason %d) "
             "on an already ended stream?", reason);
    tor_fragile_assert();
    return -1;
  }

  if (conn->_base.marked_for_close) {
    log_warn(LD_BUG,
             "called on conn that's already marked for close at %s:%d.",
             conn->_base.marked_for_close_file, conn->_base.marked_for_close);
    return 0;
  }

  payload[0] = reason;
  if (reason == END_STREAM_REASON_EXITPOLICY &&
      !connection_edge_is_rendezvous_stream(conn)) {
    set_uint32(payload+1, htonl(conn->_base.addr));
    set_uint32(payload+5, htonl(dns_clip_ttl(conn->address_ttl)));
    payload_len += 8;
  }

  circ = circuit_get_by_edge_conn(conn);
  if (circ && !circ->marked_for_close) {
    log_debug(LD_EDGE,"Sending end on conn (fd %d).",conn->_base.s);
    connection_edge_send_command(conn, RELAY_COMMAND_END,
                                 payload, payload_len);
  } else {
    log_debug(LD_EDGE,"No circ to send end on conn (fd %d).",
              conn->_base.s);
  }

  conn->_base.edge_has_sent_end = 1;
  conn->end_reason = reason;
  return 0;
}

/** An error has just occured on an operation on an edge connection
 * <b>conn</b>.  Extract the errno; convert it to an end reason, and send an
 * appropriate relay end cell to the other end of the connection's circuit.
 **/
int
connection_edge_end_errno(edge_connection_t *conn)
{
  uint8_t reason;
  tor_assert(conn);
  reason = (uint8_t)errno_to_end_reason(tor_socket_errno(conn->_base.s));
  return connection_edge_end(conn, reason);
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

  switch (conn->_base.state) {
    case AP_CONN_STATE_OPEN:
    case EXIT_CONN_STATE_OPEN:
      connection_stop_writing(TO_CONN(conn));
      connection_edge_consider_sending_sendme(conn);
      return 0;
    case AP_CONN_STATE_SOCKS_WAIT:
    case AP_CONN_STATE_NATD_WAIT:
    case AP_CONN_STATE_RENDDESC_WAIT:
    case AP_CONN_STATE_CIRCUIT_WAIT:
    case AP_CONN_STATE_CONNECT_WAIT:
    case AP_CONN_STATE_CONTROLLER_WAIT:
      connection_stop_writing(TO_CONN(conn));
      return 0;
    default:
      log_warn(LD_BUG, "Called in unexpected state %d.",conn->_base.state);
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
  char valbuf[INET_NTOA_BUF_LEN];
  connection_t *conn;
  struct in_addr in;

  tor_assert(edge_conn);
  tor_assert(edge_conn->_base.type == CONN_TYPE_EXIT);
  conn = TO_CONN(edge_conn);
  tor_assert(conn->state == EXIT_CONN_STATE_CONNECTING);

  in.s_addr = htonl(conn->addr);
  tor_inet_ntoa(&in,valbuf,sizeof(valbuf));
  log_info(LD_EXIT,"Exit connection to %s:%u (%s) established.",
           escaped_safe_str(conn->address),conn->port,safe_str(valbuf));

  conn->state = EXIT_CONN_STATE_OPEN;
  connection_watch_events(conn, EV_READ); /* stop writing, continue reading */
  if (connection_wants_to_flush(conn)) /* in case there are any queued relay
                                        * cells */
    connection_start_writing(conn);
  /* deliver a 'connected' relay cell back through the circuit. */
  if (connection_edge_is_rendezvous_stream(edge_conn)) {
    if (connection_edge_send_command(edge_conn,
                                     RELAY_COMMAND_CONNECTED, NULL, 0) < 0)
      return 0; /* circuit is closed, don't continue */
  } else {
    char connected_payload[8];
    set_uint32(connected_payload, htonl(conn->addr));
    set_uint32(connected_payload+4,
               htonl(dns_clip_ttl(edge_conn->address_ttl)));
    if (connection_edge_send_command(edge_conn,
                                     RELAY_COMMAND_CONNECTED,
                                     connected_payload, 8) < 0)
      return 0; /* circuit is closed, don't continue */
  }
  tor_assert(edge_conn->package_window > 0);
  /* in case the server has written anything */
  return connection_edge_process_inbuf(edge_conn, 1);
}

/** Define a schedule for how long to wait between retrying
 * application connections. Rather than waiting a fixed amount of
 * time between each retry, we wait 10 seconds each for the first
 * two tries, and 15 seconds for each retry after
 * that. Hopefully this will improve the expected user experience. */
static int
compute_retry_timeout(edge_connection_t *conn)
{
  if (conn->num_socks_retries < 2) /* try 0 and try 1 */
    return 10;
  return 15;
}

/** Find all general-purpose AP streams waiting for a response that sent their
 * begin/resolve cell >=15 seconds ago. Detach from their current circuit, and
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
  connection_t **carray;
  edge_connection_t *conn;
  circuit_t *circ;
  const char *nickname;
  int n, i;
  time_t now = time(NULL);
  or_options_t *options = get_options();
  int severity;
  int cutoff;
  int seconds_idle;

  get_connection_array(&carray, &n);

  for (i = 0; i < n; ++i) {
    if (carray[i]->type != CONN_TYPE_AP)
      continue;
    conn = TO_EDGE_CONN(carray[i]);
    /* if it's an internal bridge connection, don't yell its status. */
    severity = (!conn->_base.addr && !conn->_base.port)
      ? LOG_INFO : LOG_NOTICE;
    seconds_idle = now - conn->_base.timestamp_lastread;

    if (AP_CONN_STATE_IS_UNATTACHED(conn->_base.state)) {
      if (seconds_idle >= options->SocksTimeout) {
        log_fn(severity, LD_APP,
            "Tried for %d seconds to get a connection to %s:%d. "
            "Giving up. (%s)",
            seconds_idle, safe_str(conn->socks_request->address),
            conn->socks_request->port,
            conn_state_to_string(CONN_TYPE_AP, conn->_base.state));
        connection_mark_unattached_ap(conn, END_STREAM_REASON_TIMEOUT);
      }
      continue;
    }

    if (conn->_base.state == AP_CONN_STATE_OPEN)
      continue;

    /* We're in state connect_wait or resolve_wait now -- waiting for a
     * reply to our relay cell. See if we want to retry/give up. */

    cutoff = compute_retry_timeout(conn);
    if (seconds_idle < cutoff)
      continue;
    circ = circuit_get_by_edge_conn(conn);
    if (!circ) { /* it's vanished? */
      log_info(LD_APP,"Conn is waiting (address %s), but lost its circ.",
               safe_str(conn->socks_request->address));
      connection_mark_unattached_ap(conn, END_STREAM_REASON_TIMEOUT);
      continue;
    }
    if (circ->purpose == CIRCUIT_PURPOSE_C_REND_JOINED) {
      if (seconds_idle >= options->SocksTimeout) {
        log_fn(severity, LD_REND,
               "Rend stream is %d seconds late. Giving up on address"
               " '%s.onion'.",
               seconds_idle,
               safe_str(conn->socks_request->address));
        connection_edge_end(conn, END_STREAM_REASON_TIMEOUT);
        connection_mark_unattached_ap(conn, END_STREAM_REASON_TIMEOUT);
      }
      continue;
    }
    tor_assert(circ->purpose == CIRCUIT_PURPOSE_C_GENERAL);
    nickname = build_state_get_exit_nickname(
                                        TO_ORIGIN_CIRCUIT(circ)->build_state);
    log_fn(cutoff < 15 ? LOG_INFO : severity, LD_APP,
           "We tried for %d seconds to connect to '%s' using exit '%s'."
           " Retrying on a new circuit.",
           seconds_idle, safe_str(conn->socks_request->address),
           nickname ? nickname : "*unnamed*");
    /* send an end down the circuit */
    connection_edge_end(conn, END_STREAM_REASON_TIMEOUT);
    /* un-mark it as ending, since we're going to reuse it */
    conn->_base.edge_has_sent_end = 0;
    conn->end_reason = 0;
    /* kludge to make us not try this circuit again, yet to allow
     * current streams on it to survive if they can: make it
     * unattractive to use for new streams */
    tor_assert(circ->timestamp_dirty);
    circ->timestamp_dirty -= options->MaxCircuitDirtiness;
    /* give our stream another 'cutoff' seconds to try */
    conn->_base.timestamp_lastread += cutoff;
    if (conn->num_socks_retries < 250) /* avoid overflow */
      conn->num_socks_retries++;
    /* move it back into 'pending' state, and try to attach. */
    if (connection_ap_detach_retriable(conn, TO_ORIGIN_CIRCUIT(circ),
                                       END_STREAM_REASON_TIMEOUT)<0) {
      connection_mark_unattached_ap(conn, END_STREAM_REASON_CANT_ATTACH);
    }
  } /* end for */
}

/** Tell any AP streams that are waiting for a new circuit to try again,
 * either attaching to an available circ or launching a new one.
 */
void
connection_ap_attach_pending(void)
{
  connection_t **carray;
  connection_t *conn;
  edge_connection_t *edge_conn;
  int n, i;

  get_connection_array(&carray, &n);

  for (i = 0; i < n; ++i) {
    conn = carray[i];
    if (conn->marked_for_close ||
        conn->type != CONN_TYPE_AP ||
        conn->state != AP_CONN_STATE_CIRCUIT_WAIT)
      continue;
    edge_conn = TO_EDGE_CONN(conn);
    if (connection_ap_handshake_attach_circuit(edge_conn) < 0) {
      connection_mark_unattached_ap(edge_conn, END_STREAM_REASON_CANT_ATTACH);
    }
  }
}

/** A circuit failed to finish on its last hop <b>info</b>. If there
 * are any streams waiting with this exit node in mind, but they
 * don't absolutely require it, make them give up on it.
 */
void
circuit_discard_optional_exit_enclaves(extend_info_t *info)
{
  connection_t **carray;
  connection_t *conn;
  edge_connection_t *edge_conn;
  routerinfo_t *r1, *r2;
  int n, i;

  get_connection_array(&carray, &n);

  for (i = 0; i < n; ++i) {
    conn = carray[i];
    if (conn->marked_for_close ||
        conn->type != CONN_TYPE_AP ||
        !conn->chosen_exit_optional)
      continue;
    edge_conn = TO_EDGE_CONN(conn);
    r1 = router_get_by_nickname(edge_conn->chosen_exit_name, 0);
    r2 = router_get_by_nickname(info->nickname, 0);
    if (r1 && r2 && r1==r2) {
      tor_assert(edge_conn->socks_request);
      log_info(LD_APP, "Giving up on enclave exit '%s' for destination %s.",
               safe_str(edge_conn->chosen_exit_name),
               escaped_safe_str(edge_conn->socks_request->address));
      conn->chosen_exit_optional = 0;
      tor_free(edge_conn->chosen_exit_name); /* clears it */
    }
  }
}

/** The AP connection <b>conn</b> has just failed while attaching or
 * sending a BEGIN or resolving on <b>circ</b>, but another circuit
 * might work. Detach the circuit, and either reattach it, launch a
 * new circuit, tell the controller, or give up as a appropriate.
 *
 * Returns -1 on err, 1 on success, 0 on not-yet-sure.
 */
int
connection_ap_detach_retriable(edge_connection_t *conn, origin_circuit_t *circ,
                               int reason)
{
  control_event_stream_status(conn, STREAM_EVENT_FAILED_RETRIABLE, reason);
  conn->_base.timestamp_lastread = time(NULL);
  if (! get_options()->LeaveStreamsUnattached) {
    conn->_base.state = AP_CONN_STATE_CIRCUIT_WAIT;
    circuit_detach_stream(TO_CIRCUIT(circ),conn);
    return connection_ap_handshake_attach_circuit(conn);
  } else {
    conn->_base.state = AP_CONN_STATE_CONTROLLER_WAIT;
    circuit_detach_stream(TO_CIRCUIT(circ),conn);
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
 * - When a dns resolve succeeds [temporary]
 * - When a dns resolve fails [temporary]
 *
 * When an addressmap request is made but one is already registered,
 * the new one is replaced only if the currently registered one has
 * no "new_address" (that is, it's in the process of dns resolve),
 * or if the new one is permanent (expires==0 or 1).
 *
 * (We overload the 'expires' field, using "0" for mappings set via
 * the configuration file, "1" for mappings set from the control
 * interface, and other values for DNS mappings that can expire.)
 */
typedef struct {
  char *new_address;
  time_t expires;
  int num_resolve_failures;
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
  addressmap_entry_t *ent = _ent;
  tor_free(ent->new_address);
  tor_free(ent);
}

/** Free storage held by a virtaddress_entry_t* entry in <b>ent</b> */
static void
addressmap_virtaddress_ent_free(void *_ent)
{
  virtaddress_entry_t *ent = _ent;
  tor_free(ent->ipv4_address);
  tor_free(ent->hostname_address);
  tor_free(ent);
}

/** Free storage held by a virtaddress_entry_t* entry in <b>ent</b> */
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

/** Remove all entries from the addressmap that were set via the
 * configuration file or the command line. */
void
addressmap_clear_configured(void)
{
  addressmap_get_mappings(NULL, 0, 0);
}

/** Remove all entries from the addressmap that are set to expire, ever. */
void
addressmap_clear_transient(void)
{
  addressmap_get_mappings(NULL, 2, TIME_MAX);
}

/** Clean out entries from the addressmap cache that were
 * added long enough ago that they are no longer valid.
 */
void
addressmap_clean(time_t now)
{
  addressmap_get_mappings(NULL, 2, now);
}

/** Free all the elements in the addressmap, and free the addressmap
 * itself. */
void
addressmap_free_all(void)
{
  if (addressmap) {
    strmap_free(addressmap, addressmap_ent_free);
    addressmap = NULL;
  }
  if (virtaddress_reversemap) {
    strmap_free(virtaddress_reversemap, addressmap_virtaddress_ent_free);
    virtaddress_reversemap = NULL;
  }
}

/** Look at address, and rewrite it until it doesn't want any
 * more rewrites; but don't get into an infinite loop.
 * Don't write more than maxlen chars into address.  Return true if the
 * address changed; false otherwise.
 */
int
addressmap_rewrite(char *address, size_t maxlen)
{
  addressmap_entry_t *ent;
  int rewrites;
  char *cp;

  for (rewrites = 0; rewrites < 16; rewrites++) {
    ent = strmap_get(addressmap, address);

    if (!ent || !ent->new_address)
      return (rewrites > 0); /* done, no rewrite needed */

    cp = tor_strdup(escaped_safe_str(ent->new_address));
    log_info(LD_APP, "Addressmap: rewriting %s to %s",
             escaped_safe_str(address), cp);
    tor_free(cp);
    strlcpy(address, ent->new_address, maxlen);
  }
  log_warn(LD_CONFIG,
           "Loop detected: we've rewritten %s 16 times! Using it as-is.",
           escaped_safe_str(address));
  /* it's fine to rewrite a rewrite, but don't loop forever */
  return 1;
}

/** If we have a cached reverse DNS entry for the address stored in the
 * <b>maxlen</b>-byte buffer <b>address</b> (typically, a dotted quad) then
 * rewrite to the cached value and return 1.  Otherwise return 0. */
static int
addressmap_rewrite_reverse(char *address, size_t maxlen)
{
  size_t len = maxlen + 16;
  char *s = tor_malloc(len), *cp;
  addressmap_entry_t *ent;
  int r = 0;
  tor_snprintf(s, len, "REVERSE[%s]", address);
  ent = strmap_get(addressmap, s);
  if (ent) {
    cp = tor_strdup(escaped_safe_str(ent->new_address));
    log_info(LD_APP, "Rewrote reverse lookup %s -> %s",
             escaped_safe_str(s), cp);
    tor_free(cp);
    strlcpy(address, ent->new_address, maxlen);
    r = 1;
  }
  tor_free(s);
  return r;
}

/** Return 1 if <b>address</b> is already registered, else return 0 */
int
addressmap_have_mapping(const char *address)
{
  return strmap_get_lc(addressmap, address) ? 1 : 0;
}

/** Register a request to map <b>address</b> to <b>new_address</b>,
 * which will expire on <b>expires</b> (or 0 if never expires from
 * config file, 1 if never expires from controller, 2 if never expires
 * (virtual address mapping) from the controller.)
 *
 * <b>new_address</b> should be a newly dup'ed string, which we'll use or
 * free as appropriate. We will leave address alone.
 *
 * If <b>new_address</b> is NULL, or equal to <b>address</b>, remove
 * any mappings that exist from <b>address</b>.
 */
void
addressmap_register(const char *address, char *new_address, time_t expires)
{
  addressmap_entry_t *ent;

  ent = strmap_get(addressmap, address);
  if (!new_address || !strcasecmp(address,new_address)) {
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
      safe_str(address), safe_str(new_address), safe_str(ent->new_address));
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

  log_info(LD_CONFIG, "Addressmap: (re)mapped '%s' to '%s'",
           safe_str(address), safe_str(ent->new_address));
  control_event_address_mapped(address, ent->new_address, expires);
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
  ++ent->num_resolve_failures;
  log_info(LD_APP, "Address %s now has %d resolve failures.",
           safe_str(address), ent->num_resolve_failures);
  return ent->num_resolve_failures;
}

/** If <b>address</b> is in the client dns addressmap, reset
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
                      time(NULL) + ttl);
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
  size_t len = strlen(address) + 16;
  char *s = tor_malloc(len);
  tor_snprintf(s, len, "REVERSE[%s]", address);
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
static uint32_t virtual_addr_network = 0x7fc00000u;
static uint32_t virtual_addr_netmask = 0xffc00000u;
static int virtual_addr_netmask_bits = 10;
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
  uint32_t addr, mask;
  uint16_t port_min, port_max;
  int bits;

  if (parse_addr_and_port_range(val, &addr, &mask, &port_min, &port_max)) {
    if (msg) *msg = tor_strdup("Error parsing VirtualAddressNetwork");
    return -1;
  }

  if (port_min != 1 || port_max != 65535) {
    if (msg) *msg = tor_strdup("Can't specify ports on VirtualAddressNetwork");
    return -1;
  }

  bits = addr_mask_get_bits(mask);
  if (bits < 0) {
    if (msg) *msg = tor_strdup("VirtualAddressNetwork must have a mask that "
                               "can be expressed as a prefix");
    return -1;
  }

  if (bits > 16) {
    if (msg) *msg = tor_strdup("VirtualAddressNetwork expects a /16 "
                               "network or larger");
    return -1;
  }

  if (validate_only)
    return 0;

  virtual_addr_network = addr & mask;
  virtual_addr_netmask = mask;
  virtual_addr_netmask_bits = bits;

  if ((next_virtual_addr & mask) != addr)
    next_virtual_addr = addr;

  return 0;
}

/**
 * Return true iff <b>addr</b> is likely to have been returned by
 * client_dns_get_unused_address.
 **/
int
address_is_in_virtual_range(const char *address)
{
  struct in_addr in;
  tor_assert(address);
  if (!strcasecmpend(address, ".virtual")) {
    return 1;
  } else if (tor_inet_aton(address, &in)) {
    uint32_t addr = ntohl(in.s_addr);
    if ((addr & virtual_addr_netmask) == virtual_addr_network)
      return 1;
  }
  return 0;
}

/** Return a newly allocated string holding an address of <b>type</b>
 * (one of RESOLVED_TYPE_{IPV4|HOSTNAME}) that has not yet been mapped,
 * and that is very unlikely to be the address of any real host.
 */
static char *
addressmap_get_virtual_address(int type)
{
  char buf[64];
  struct in_addr in;

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
    uint32_t available = 1u << (32-virtual_addr_netmask_bits);
    while (available) {
      /* Don't hand out any .0 or .255 address. */
      while ((next_virtual_addr & 0xff) == 0 ||
             (next_virtual_addr & 0xff) == 0xff) {
        ++next_virtual_addr;
      }
      in.s_addr = htonl(next_virtual_addr);
      tor_inet_ntoa(&in, buf, sizeof(buf));
      if (!strmap_get(addressmap, buf))
        break;

      ++next_virtual_addr;
      --available;
      log_notice(LD_CONFIG, "%d addrs available", (int)available);
      if (! --available) {
        log_warn(LD_CONFIG, "Ran out of virtual addresses!");
        return NULL;
      }
      if ((next_virtual_addr & virtual_addr_netmask) != virtual_addr_network)
        next_virtual_addr = virtual_addr_network;
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
 * The string in <b>new_address</b> may be freed, or inserted into a map
 * as appropriate.
 **/
const char *
addressmap_register_virtual_address(int type, char *new_address)
{
  char **addrp;
  virtaddress_entry_t *vent;

  tor_assert(new_address);
  tor_assert(addressmap);
  tor_assert(virtaddress_reversemap);

  vent = strmap_get(virtaddress_reversemap, new_address);
  if (!vent) {
    vent = tor_malloc_zero(sizeof(virtaddress_entry_t));
    strmap_set(virtaddress_reversemap, new_address, vent);
  }

  addrp = (type == RESOLVED_TYPE_IPV4) ?
    &vent->ipv4_address : &vent->hostname_address;
  if (*addrp) {
    addressmap_entry_t *ent = strmap_get(addressmap, *addrp);
    if (ent && ent->new_address &&
        !strcasecmp(new_address, ent->new_address)) {
      tor_free(new_address);
      return tor_strdup(*addrp);
    } else
      log_warn(LD_BUG,
               "Internal confusion: I thought that '%s' was mapped to by "
               "'%s', but '%s' really maps to '%s'. This is a harmless bug.",
               safe_str(new_address), safe_str(*addrp), safe_str(*addrp),
               ent?safe_str(ent->new_address):"(nothing)");
  }

  tor_free(*addrp);
  *addrp = addressmap_get_virtual_address(type);
  addressmap_register(*addrp, new_address, 2);

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
    log_fn(LOG_INFO, "Map from %s to %s okay.",
           safe_str(*addrp),safe_str(new_address));
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
 * "old-addr new-addr" string to sl for each mapping.  If sl is NULL,
 * remove the mappings.
 */
void
addressmap_get_mappings(smartlist_t *sl, time_t min_expires,
                        time_t max_expires)
{
   strmap_iter_t *iter;
   const char *key;
   void *_val;
   addressmap_entry_t *val;

   if (!addressmap)
     addressmap_init();

   for (iter = strmap_iter_init(addressmap); !strmap_iter_done(iter); ) {
     strmap_iter_get(iter, &key, &_val);
     val = _val;
     if (val->expires >= min_expires && val->expires <= max_expires) {
       if (!sl) {
         iter = strmap_iter_next_rmv(addressmap,iter);
         addressmap_ent_remove(key, val);
         continue;
       } else if (val->new_address) {
         size_t len = strlen(key)+strlen(val->new_address)+2;
         char *line = tor_malloc(len);
         tor_snprintf(line, len, "%s %s", key, val->new_address);
         smartlist_add(sl, line);
       }
     }
     iter = strmap_iter_next(addressmap,iter);
   }
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
 */
int
connection_ap_handshake_rewrite_and_attach(edge_connection_t *conn,
                                           origin_circuit_t *circ)
{
  socks_request_t *socks = conn->socks_request;
  hostname_type_t addresstype;

  tor_strlower(socks->address); /* normalize it */
  log_debug(LD_APP,"Client asked for %s:%d",
            safe_str(socks->address),
            socks->port);

  if (socks->command == SOCKS_COMMAND_RESOLVE_PTR) {
    if (addressmap_rewrite_reverse(socks->address, sizeof(socks->address))) {
      connection_ap_handshake_socks_resolved(conn, RESOLVED_TYPE_HOSTNAME,
                                             strlen(socks->address),
                                             socks->address, -1);
      connection_mark_unattached_ap(conn,
                                 END_STREAM_REASON_DONE |
                                 END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
      return 0;
    }
  } else {
    /* For address map controls, remap the address */
    if (addressmap_rewrite(socks->address, sizeof(socks->address))) {
      control_event_stream_status(conn, STREAM_EVENT_REMAP,
                                  REMAP_STREAM_SOURCE_CACHE);
    }
  }

  if (address_is_in_virtual_range(socks->address)) {
    /* This address was probably handed out by client_dns_get_unmapped_address,
     * but the mapping was discarded for some reason.  We *don't* want to send
     * the address through Tor; that's likely to fail, and may leak
     * information.
     */
    log_warn(LD_APP,"Missing mapping for virtual address '%s'. Refusing.",
             socks->address); /* don't safe_str() this yet. */
    connection_mark_unattached_ap(conn, END_STREAM_REASON_INTERNAL);
    return -1;
  }

  /* Parse the address provided by SOCKS.  Modify it in-place if it
   * specifies a hidden-service (.onion) or particular exit node (.exit).
   */
  addresstype = parse_extended_hostname(socks->address);

  if (addresstype == BAD_HOSTNAME) {
    log_warn(LD_APP, "Invalid hostname %s; rejecting", socks->address);
    control_event_client_status(LOG_WARN, "SOCKS_BAD_HOSTNAME HOSTNAME=%s",
                                escaped(socks->address));
    connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
    return -1;
  }

  if (addresstype == EXIT_HOSTNAME) {
    /* foo.exit -- modify conn->chosen_exit_node to specify the exit
     * node, and conn->address to hold only the address portion.*/
    char *s = strrchr(socks->address,'.');
    if (s) {
      if (s[1] != '\0') {
        conn->chosen_exit_name = tor_strdup(s+1);
        *s = 0;
      } else {
        log_warn(LD_APP,"Malformed exit address '%s.exit'. Refusing.",
                 safe_str(socks->address));
        control_event_client_status(LOG_WARN, "SOCKS_BAD_HOSTNAME HOSTNAME=%s",
                                    escaped(socks->address));
        connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
        return -1;
      }
    } else {
      routerinfo_t *r;
      conn->chosen_exit_name = tor_strdup(socks->address);
      r = router_get_by_nickname(conn->chosen_exit_name, 1);
      *socks->address = 0;
      if (r) {
        strlcpy(socks->address, r->address, sizeof(socks->address));
      } else {
        log_warn(LD_APP,
                 "Unrecognized server in exit address '%s.exit'. Refusing.",
                 safe_str(socks->address));
        connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
        return -1;
      }
    }
  }

  if (addresstype != ONION_HOSTNAME) {
    /* not a hidden-service request (i.e. normal or .exit) */
    if (address_is_invalid_destination(socks->address, 1)) {
      control_event_client_status(LOG_WARN, "SOCKS_BAD_HOSTNAME HOSTNAME=%s",
                                  escaped(socks->address));
      log_warn(LD_APP,
               "Destination '%s' seems to be an invalid hostname. Failing.",
               safe_str(socks->address));
      connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
      return -1;
    }

    if (socks->command == SOCKS_COMMAND_RESOLVE) {
      uint32_t answer;
      struct in_addr in;
      /* Reply to resolves immediately if we can. */
      if (strlen(socks->address) > RELAY_PAYLOAD_SIZE) {
        log_warn(LD_APP,"Address to be resolved is too large. Failing.");
        control_event_client_status(LOG_WARN, "SOCKS_BAD_HOSTNAME HOSTNAME=%s",
                                    escaped(socks->address));
        connection_ap_handshake_socks_resolved(conn,RESOLVED_TYPE_ERROR,
                                               0,NULL,-1);
        connection_mark_unattached_ap(conn,
                                END_STREAM_REASON_SOCKSPROTOCOL |
                                END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
        return -1;
      }
      if (tor_inet_aton(socks->address, &in)) { /* see if it's an IP already */
        answer = in.s_addr; /* leave it in network order */
        connection_ap_handshake_socks_resolved(conn,RESOLVED_TYPE_IPV4,4,
                                               (char*)&answer,-1);
        connection_mark_unattached_ap(conn,
                                END_STREAM_REASON_DONE |
                                END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
        return 0;
      }
      rep_hist_note_used_resolve(time(NULL)); /* help predict this next time */
    } else if (socks->command == SOCKS_COMMAND_CONNECT) {
      if (socks->port == 0) {
        log_notice(LD_APP,"Application asked to connect to port 0. Refusing.");
        connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
        return -1;
      }

      if (!conn->chosen_exit_name && !circ) {
        /* see if we can find a suitable enclave exit */
        routerinfo_t *r =
          router_find_exact_exit_enclave(socks->address, socks->port);
        if (r) {
          log_info(LD_APP,
                   "Redirecting address %s to exit at enclave router %s",
                   safe_str(socks->address), r->nickname);
          /* use the hex digest, not nickname, in case there are two
             routers with this nickname */
          conn->chosen_exit_name =
            tor_strdup(hex_str(r->cache_info.identity_digest, DIGEST_LEN));
          conn->_base.chosen_exit_optional = 1;
        }
      }

      /* help predict this next time */
      rep_hist_note_used_port(socks->port, time(NULL));
    } else if (socks->command == SOCKS_COMMAND_RESOLVE_PTR) {
      rep_hist_note_used_resolve(time(NULL)); /* help predict this next time */
    } else if (socks->command == SOCKS_COMMAND_CONNECT_DIR) {
      ; /* nothing */
    } else {
      tor_fragile_assert();
    }
    conn->_base.state = AP_CONN_STATE_CIRCUIT_WAIT;
    if ((circ &&
         connection_ap_handshake_attach_chosen_circuit(conn, circ) < 0) ||
        (!circ &&
         connection_ap_handshake_attach_circuit(conn) < 0)) {
      connection_mark_unattached_ap(conn, END_STREAM_REASON_CANT_ATTACH);
      return -1;
    }
    return 0;
  } else {
    /* it's a hidden-service request */
    rend_cache_entry_t *entry;
    int r;

    if (SOCKS_COMMAND_IS_RESOLVE(socks->command)) {
      /* if it's a resolve request, fail it right now, rather than
       * building all the circuits and then realizing it won't work. */
      log_warn(LD_APP,
               "Resolve requests to hidden services not allowed. Failing.");
      connection_ap_handshake_socks_resolved(conn,RESOLVED_TYPE_ERROR,
                                             0,NULL,-1);
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

    strlcpy(conn->rend_query, socks->address, sizeof(conn->rend_query));
    log_info(LD_REND,"Got a hidden service request for ID '%s'",
             safe_str(conn->rend_query));
    /* see if we already have it cached */
    r = rend_cache_lookup_entry(conn->rend_query, -1, &entry);
    if (r<0) {
      log_warn(LD_BUG,"Invalid service name '%s'",
               safe_str(conn->rend_query));
      connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
      return -1;
    }
    if (r==0) {
      conn->_base.state = AP_CONN_STATE_RENDDESC_WAIT;
      log_info(LD_REND, "Unknown descriptor %s. Fetching.",
               safe_str(conn->rend_query));
      rend_client_refetch_renddesc(conn->rend_query);
    } else { /* r > 0 */
/** How long after we receive a hidden service descriptor do we consider
 * it valid? */
#define NUM_SECONDS_BEFORE_HS_REFETCH (60*15)
      if (time(NULL) - entry->received < NUM_SECONDS_BEFORE_HS_REFETCH) {
        conn->_base.state = AP_CONN_STATE_CIRCUIT_WAIT;
        log_info(LD_REND, "Descriptor is here and fresh enough. Great.");
        if (connection_ap_handshake_attach_circuit(conn) < 0) {
          connection_mark_unattached_ap(conn, END_STREAM_REASON_CANT_ATTACH);
          return -1;
        }
      } else {
        conn->_base.state = AP_CONN_STATE_RENDDESC_WAIT;
        log_info(LD_REND, "Stale descriptor %s. Refetching.",
                 safe_str(conn->rend_query));
        rend_client_refetch_renddesc(conn->rend_query);
      }
    }
    return 0;
  }
  return 0; /* unreached but keeps the compiler happy */
}

#ifdef TRANS_PF
static int pf_socket = -1;
static int
get_pf_socket(void)
{
  int pf;
  /*  Ideally, this should be opened before dropping privs. */
  if (pf_socket >= 0)
    return pf_socket;

#ifdef OPENBSD
  /* only works on OpenBSD */
  pf = open("/dev/pf", O_RDONLY);
#else
  /* works on NetBSD and FreeBSD */
  pf = open("/dev/pf", O_RDWR);
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
connection_ap_get_original_destination(edge_connection_t *conn,
                                       socks_request_t *req)
{
#ifdef TRANS_NETFILTER
  /* Linux 2.4+ */
  struct sockaddr_in orig_dst;
  socklen_t orig_dst_len = sizeof(orig_dst);
  char tmpbuf[INET_NTOA_BUF_LEN];

  if (getsockopt(conn->_base.s, SOL_IP, SO_ORIGINAL_DST,
                 (struct sockaddr*)&orig_dst, &orig_dst_len) < 0) {
    int e = tor_socket_errno(conn->_base.s);
    log_warn(LD_NET, "getsockopt() failed: %s", tor_socket_strerror(e));
    return -1;
  }

  tor_inet_ntoa(&orig_dst.sin_addr, tmpbuf, sizeof(tmpbuf));
  strlcpy(req->address, tmpbuf, sizeof(req->address));
  req->port = ntohs(orig_dst.sin_port);

  return 0;
#elif defined(TRANS_PF)
  struct sockaddr_in proxy_addr;
  socklen_t proxy_addr_len = sizeof(proxy_addr);
  char tmpbuf[INET_NTOA_BUF_LEN];
  struct pfioc_natlook pnl;
  int pf = -1;

  if (getsockname(conn->_base.s, (struct sockaddr*)&proxy_addr,
                  &proxy_addr_len) < 0) {
    int e = tor_socket_errno(conn->_base.s);
    log_warn(LD_NET, "getsockname() to determine transocks destination "
             "failed: %s", tor_socket_strerror(e));
    return -1;
  }

  memset(&pnl, 0, sizeof(pnl));
  pnl.af              = AF_INET;
  pnl.proto           = IPPROTO_TCP;
  pnl.direction       = PF_OUT;
  pnl.saddr.v4.s_addr = htonl(conn->_base.addr);
  pnl.sport           = htons(conn->_base.port);
  pnl.daddr.v4.s_addr = proxy_addr.sin_addr.s_addr;
  pnl.dport           = proxy_addr.sin_port;

  pf = get_pf_socket();
  if (pf<0)
    return -1;

  if (ioctl(pf, DIOCNATLOOK, &pnl) < 0) {
    log_warn(LD_NET, "ioctl(DIOCNATLOOK) failed: %s", strerror(errno));
    return -1;
  }

  tor_inet_ntoa(&pnl.rdaddr.v4, tmpbuf, sizeof(tmpbuf));
  strlcpy(req->address, tmpbuf, sizeof(req->address));
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
connection_ap_handshake_process_socks(edge_connection_t *conn)
{
  socks_request_t *socks;
  int sockshere;
  or_options_t *options = get_options();

  tor_assert(conn);
  tor_assert(conn->_base.type == CONN_TYPE_AP);
  tor_assert(conn->_base.state == AP_CONN_STATE_SOCKS_WAIT);
  tor_assert(conn->socks_request);
  socks = conn->socks_request;

  log_debug(LD_APP,"entered.");

  sockshere = fetch_from_buf_socks(conn->_base.inbuf, socks,
                                   options->TestSocks, options->SafeSocks);
  if (sockshere == 0) {
    if (socks->replylen) {
      connection_write_to_buf(socks->reply, socks->replylen, TO_CONN(conn));
      /* zero it out so we can do another round of negotiation */
      socks->replylen = 0;
    } else {
      log_debug(LD_APP,"socks handshake not all here yet.");
    }
    return 0;
  } else if (sockshere == -1) {
    if (socks->replylen) { /* we should send reply back */
      log_debug(LD_APP,"reply is already set for us. Using it.");
      connection_ap_handshake_socks_reply(conn, socks->reply, socks->replylen,
                                          END_STREAM_REASON_SOCKSPROTOCOL);

    } else {
      log_warn(LD_APP,"Fetching socks handshake failed. Closing.");
      connection_ap_handshake_socks_reply(conn, NULL, 0,
                                          END_STREAM_REASON_SOCKSPROTOCOL);
    }
    connection_mark_unattached_ap(conn,
                              END_STREAM_REASON_SOCKSPROTOCOL |
                              END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
    return -1;
  } /* else socks handshake is done, continue processing */

  if (hostname_is_noconnect_address(socks->address))
  {
    control_event_stream_status(conn, STREAM_EVENT_NEW, 0);
    control_event_stream_status(conn, STREAM_EVENT_CLOSED, 0);
    connection_mark_unattached_ap(conn, END_STREAM_REASON_DONE);
    return -1;
  }

  if (SOCKS_COMMAND_IS_CONNECT(socks->command))
    control_event_stream_status(conn, STREAM_EVENT_NEW, 0);
  else
    control_event_stream_status(conn, STREAM_EVENT_NEW_RESOLVE, 0);

  if (options->LeaveStreamsUnattached) {
    conn->_base.state = AP_CONN_STATE_CONTROLLER_WAIT;
    return 0;
  }
  return connection_ap_handshake_rewrite_and_attach(conn, NULL);
}

/** connection_init_accepted_conn() found a new trans AP conn.
 * Get the original destination and send it to
 * connection_ap_handshake_rewrite_and_attach().
 *
 * Return -1 if an unexpected error with conn (and it should be marked
 * for close), else return 0.
 */
int
connection_ap_process_transparent(edge_connection_t *conn)
{
  socks_request_t *socks;
  or_options_t *options = get_options();

  tor_assert(conn);
  tor_assert(conn->_base.type == CONN_TYPE_AP);
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

  if (options->LeaveStreamsUnattached) {
    conn->_base.state = AP_CONN_STATE_CONTROLLER_WAIT;
    return 0;
  }
  return connection_ap_handshake_rewrite_and_attach(conn, NULL);
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
connection_ap_process_natd(edge_connection_t *conn)
{
  char tmp_buf[36], *tbuf, *daddr;
  size_t tlen = 30;
  int err, port_ok;
  socks_request_t *socks;
  or_options_t *options = get_options();

  tor_assert(conn);
  tor_assert(conn->_base.type == CONN_TYPE_AP);
  tor_assert(conn->_base.state == AP_CONN_STATE_NATD_WAIT);
  tor_assert(conn->socks_request);
  socks = conn->socks_request;

  log_debug(LD_APP,"entered.");

  /* look for LF-terminated "[DEST ip_addr port]"
   * where ip_addr is a dotted-quad and port is in string form */
  err = fetch_from_buf_line_lf(conn->_base.inbuf, tmp_buf, &tlen);
  if (err == 0)
    return 0;
  if (err < 0) {
    log_warn(LD_APP,"Natd handshake failed (DEST too long). Closing");
    connection_mark_unattached_ap(conn, END_STREAM_REASON_INVALID_NATD_DEST);
    return -1;
  }

  if (strcmpstart(tmp_buf, "[DEST ")) {
    log_warn(LD_APP,"Natd handshake was ill-formed; closing. The client "
             "said: %s",
             escaped(tmp_buf));
    connection_mark_unattached_ap(conn, END_STREAM_REASON_INVALID_NATD_DEST);
    return -1;
  }

  daddr = tbuf = &tmp_buf[0] + 6; /* after end of "[DEST " */
  while (*tbuf != '\0' && *tbuf != ' ')
    tbuf++;
  *tbuf = '\0';
  tbuf++;

  /* pretend that a socks handshake completed so we don't try to
   * send a socks reply down a natd conn */
  strlcpy(socks->address, daddr, sizeof(socks->address));
  socks->port = (uint16_t)
    tor_parse_long(tbuf, 10, 1, 65535, &port_ok, &daddr);
  if (!port_ok) {
    log_warn(LD_APP,"Natd handshake failed; port %s is ill-formed or out "
             "of range.", escaped(tbuf));
    connection_mark_unattached_ap(conn, END_STREAM_REASON_INVALID_NATD_DEST);
    return -1;
  }

  socks->command = SOCKS_COMMAND_CONNECT;
  socks->has_finished = 1;

  control_event_stream_status(conn, STREAM_EVENT_NEW, 0);

  if (options->LeaveStreamsUnattached) {
    conn->_base.state = AP_CONN_STATE_CONTROLLER_WAIT;
    return 0;
  }
  conn->_base.state = AP_CONN_STATE_CIRCUIT_WAIT;

  return connection_ap_handshake_rewrite_and_attach(conn, NULL);
}

/** Iterate over the two bytes of stream_id until we get one that is not
 * already in use; return it. Return 0 if can't get a unique stream_id.
 */
static uint16_t
get_unique_stream_id_by_circ(origin_circuit_t *circ)
{
  edge_connection_t *tmpconn;
  uint16_t test_stream_id;
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

/** Write a relay begin cell, using destaddr and destport from ap_conn's
 * socks_request field, and send it down circ.
 *
 * If ap_conn is broken, mark it for close and return -1. Else return 0.
 */
int
connection_ap_handshake_send_begin(edge_connection_t *ap_conn)
{
  char payload[CELL_PAYLOAD_SIZE];
  int payload_len;
  int begin_type;
  origin_circuit_t *circ;
  tor_assert(ap_conn->on_circuit);
  circ = TO_ORIGIN_CIRCUIT(ap_conn->on_circuit);

  tor_assert(ap_conn->_base.type == CONN_TYPE_AP);
  tor_assert(ap_conn->_base.state == AP_CONN_STATE_CIRCUIT_WAIT);
  tor_assert(ap_conn->socks_request);
  tor_assert(SOCKS_COMMAND_IS_CONNECT(ap_conn->socks_request->command));

  ap_conn->stream_id = get_unique_stream_id_by_circ(circ);
  if (ap_conn->stream_id==0) {
    connection_mark_unattached_ap(ap_conn, END_STREAM_REASON_INTERNAL);
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_RESOURCELIMIT);
    return -1;
  }

  tor_snprintf(payload,RELAY_PAYLOAD_SIZE, "%s:%d",
               (circ->_base.purpose == CIRCUIT_PURPOSE_C_GENERAL) ?
                 ap_conn->socks_request->address : "",
               ap_conn->socks_request->port);
  payload_len = strlen(payload)+1;

  log_debug(LD_APP,
            "Sending relay cell to begin stream %d.", ap_conn->stream_id);

  begin_type = ap_conn->socks_request->command == SOCKS_COMMAND_CONNECT ?
                 RELAY_COMMAND_BEGIN : RELAY_COMMAND_BEGIN_DIR;
  if (begin_type == RELAY_COMMAND_BEGIN) {
    tor_assert(circ->build_state->onehop_tunnel == 0);
  }

  if (connection_edge_send_command(ap_conn, begin_type,
                  begin_type == RELAY_COMMAND_BEGIN ? payload : NULL,
                  begin_type == RELAY_COMMAND_BEGIN ? payload_len : 0) < 0)
    return -1; /* circuit is closed, don't continue */

  ap_conn->package_window = STREAMWINDOW_START;
  ap_conn->deliver_window = STREAMWINDOW_START;
  ap_conn->_base.state = AP_CONN_STATE_CONNECT_WAIT;
  log_info(LD_APP,"Address/port sent, ap socket %d, n_circ_id %d",
           ap_conn->_base.s, circ->_base.n_circ_id);
  control_event_stream_status(ap_conn, STREAM_EVENT_SENT_CONNECT, 0);
  return 0;
}

/** Write a relay resolve cell, using destaddr and destport from ap_conn's
 * socks_request field, and send it down circ.
 *
 * If ap_conn is broken, mark it for close and return -1. Else return 0.
 */
int
connection_ap_handshake_send_resolve(edge_connection_t *ap_conn)
{
  int payload_len, command;
  const char *string_addr;
  char inaddr_buf[32];
  origin_circuit_t *circ;
  tor_assert(ap_conn->on_circuit);
  circ = TO_ORIGIN_CIRCUIT(ap_conn->on_circuit);

  tor_assert(ap_conn->_base.type == CONN_TYPE_AP);
  tor_assert(ap_conn->_base.state == AP_CONN_STATE_CIRCUIT_WAIT);
  tor_assert(ap_conn->socks_request);
  tor_assert(circ->_base.purpose == CIRCUIT_PURPOSE_C_GENERAL);

  command = ap_conn->socks_request->command;
  tor_assert(SOCKS_COMMAND_IS_RESOLVE(command));

  ap_conn->stream_id = get_unique_stream_id_by_circ(circ);
  if (ap_conn->stream_id==0) {
    connection_mark_unattached_ap(ap_conn, END_STREAM_REASON_INTERNAL);
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_RESOURCELIMIT);
    return -1;
  }

  if (command == SOCKS_COMMAND_RESOLVE) {
    string_addr = ap_conn->socks_request->address;
    payload_len = strlen(string_addr)+1;
    tor_assert(payload_len <= RELAY_PAYLOAD_SIZE);
  } else {
    struct in_addr in;
    uint32_t a;
    if (tor_inet_aton(ap_conn->socks_request->address, &in) == 0) {
      connection_mark_unattached_ap(ap_conn, END_STREAM_REASON_INTERNAL);
      return -1;
    }
    a = ntohl(in.s_addr);
    tor_snprintf(inaddr_buf, sizeof(inaddr_buf), "%d.%d.%d.%d.in-addr.arpa",
                 (int)(uint8_t)((a    )&0xff),
                 (int)(uint8_t)((a>>8 )&0xff),
                 (int)(uint8_t)((a>>16)&0xff),
                 (int)(uint8_t)((a>>24)&0xff));
    string_addr = inaddr_buf;
    payload_len = strlen(inaddr_buf)+1;
    tor_assert(payload_len <= RELAY_PAYLOAD_SIZE);
  }

  log_debug(LD_APP,
            "Sending relay cell to begin stream %d.", ap_conn->stream_id);

  if (connection_edge_send_command(ap_conn,
                           RELAY_COMMAND_RESOLVE,
                           string_addr, payload_len) < 0)
    return -1; /* circuit is closed, don't continue */

  ap_conn->_base.state = AP_CONN_STATE_RESOLVE_WAIT;
  log_info(LD_APP,"Address sent for resolve, ap socket %d, n_circ_id %d",
           ap_conn->_base.s, circ->_base.n_circ_id);
  control_event_stream_status(ap_conn, STREAM_EVENT_SENT_RESOLVE, 0);
  return 0;
}

/** Make an AP connection_t, do a socketpair and attach one side
 * to the conn, connection_add it, initialize it to circuit_wait,
 * and call connection_ap_handshake_attach_circuit(conn) on it.
 *
 * Return the other end of the socketpair, or -1 if error.
 */
int
connection_ap_make_bridge(char *address, uint16_t port,
                          const char *digest, int command)
{
  int fd[2];
  edge_connection_t *conn;
  int err;

  log_info(LD_APP,"Making AP bridge to %s:%d ...",safe_str(address),port);

  if ((err = tor_socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) < 0) {
    log_warn(LD_NET,
             "Couldn't construct socketpair (%s). Network down? Delaying.",
             tor_socket_strerror(-err));
    return -1;
  }

  tor_assert(fd[0] >= 0);
  tor_assert(fd[1] >= 0);

  set_socket_nonblocking(fd[0]);
  set_socket_nonblocking(fd[1]);

  conn = TO_EDGE_CONN(connection_new(CONN_TYPE_AP));
  conn->_base.s = fd[0];

  /* populate conn->socks_request */

  /* leave version at zero, so the socks_reply is empty */
  conn->socks_request->socks_version = 0;
  conn->socks_request->has_finished = 0; /* waiting for 'connected' */
  strlcpy(conn->socks_request->address, address,
          sizeof(conn->socks_request->address));
  conn->socks_request->port = port;
  conn->socks_request->command = command;
  if (command == SOCKS_COMMAND_CONNECT_DIR) {
    conn->chosen_exit_name = tor_malloc(HEX_DIGEST_LEN+2);
    conn->chosen_exit_name[0] = '$';
    base16_encode(conn->chosen_exit_name+1,HEX_DIGEST_LEN+1,
                  digest, DIGEST_LEN);
  }

  conn->_base.address = tor_strdup("(local bridge)");
  conn->_base.addr = 0;
  conn->_base.port = 0;

  if (connection_add(TO_CONN(conn)) < 0) { /* no space, forget it */
    connection_free(TO_CONN(conn)); /* this closes fd[0] */
    tor_close_socket(fd[1]);
    return -1;
  }

  conn->_base.state = AP_CONN_STATE_CIRCUIT_WAIT;
  connection_start_reading(TO_CONN(conn));

  /* attaching to a dirty circuit is fine */
  if (connection_ap_handshake_attach_circuit(conn) < 0) {
    connection_mark_unattached_ap(conn, END_STREAM_REASON_CANT_ATTACH);
    tor_close_socket(fd[1]);
    return -1;
  }

  log_info(LD_APP,"... AP bridge created and connected.");
  return fd[1];
}

/** Send an answer to an AP connection that has requested a DNS lookup
 * via SOCKS.  The type should be one of RESOLVED_TYPE_(IPV4|IPV6|HOSTNAME) or
 * -1 for unreachable; the answer should be in the format specified
 * in the socks extensions document.
 **/
void
connection_ap_handshake_socks_resolved(edge_connection_t *conn,
                                       int answer_type,
                                       size_t answer_len,
                                       const char *answer,
                                       int ttl)
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
      char *cp = tor_strndup(answer, answer_len);
      client_dns_set_reverse_addressmap(conn->socks_request->address,
                                        cp,
                                        conn->chosen_exit_name, ttl);
      tor_free(cp);
    }
  }

  if (conn->socks_request->socks_version == 4) {
    buf[0] = 0x00; /* version */
    if (answer_type == RESOLVED_TYPE_IPV4 && answer_len == 4) {
      buf[1] = 90; /* "Granted" */
      set_uint16(buf+2, 0);
      memcpy(buf+4, answer, 4); /* address */
      replylen = SOCKS4_NETWORK_LEN;
    } else {
      buf[1] = 91; /* "error" */
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
           answer_type == RESOLVED_TYPE_IPV6) ?
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
connection_ap_handshake_socks_reply(edge_connection_t *conn, char *reply,
                                    size_t replylen, int endreason)
{
  char buf[256];
  socks5_reply_status_t status =
    connection_edge_end_reason_socks5_response(endreason);

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
    connection_write_to_buf(reply, replylen, TO_CONN(conn));
    conn->socks_request->has_finished = 1;
    return;
  }
  if (conn->socks_request->socks_version == 4) {
    memset(buf,0,SOCKS4_NETWORK_LEN);
#define SOCKS4_GRANTED          90
#define SOCKS4_REJECT           91
    buf[1] = (status==SOCKS5_SUCCEEDED ? SOCKS4_GRANTED : SOCKS4_REJECT);
    /* leave version, destport, destip zero */
    connection_write_to_buf(buf, SOCKS4_NETWORK_LEN, TO_CONN(conn));
  } else if (conn->socks_request->socks_version == 5) {
    buf[0] = 5; /* version 5 */
    buf[1] = (char)status;
    buf[2] = 0;
    buf[3] = 1; /* ipv4 addr */
    memset(buf+4,0,6); /* Set external addr/port to 0.
                          The spec doesn't seem to say what to do here. -RD */
    connection_write_to_buf(buf,10,TO_CONN(conn));
  }
  /* If socks_version isn't 4 or 5, don't send anything.
   * This can happen in the case of AP bridges. */
  conn->socks_request->has_finished = 1;
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
  char end_payload[1];
  or_circuit_t *or_circ = NULL;

  assert_circuit_ok(circ);
  if (!CIRCUIT_IS_ORIGIN(circ))
    or_circ = TO_OR_CIRCUIT(circ);

  relay_header_unpack(&rh, cell->payload);

  /* Note: we have to use relay_send_command_from_edge here, not
   * connection_edge_end or connection_edge_send_command, since those require
   * that we have a stream connected to a circuit, and we don't connect to a
   * circuit until we have a pending/successful resolve. */

  if (!server_mode(get_options()) &&
      circ->purpose != CIRCUIT_PURPOSE_S_REND_JOINED) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Relay begin cell at non-server. Closing.");
    end_payload[0] = END_STREAM_REASON_EXITPOLICY;
    relay_send_command_from_edge(rh.stream_id, circ, RELAY_COMMAND_END,
                                 end_payload, 1, NULL);
    return 0;
  }

  if (rh.command == RELAY_COMMAND_BEGIN) {
    if (!memchr(cell->payload+RELAY_HEADER_SIZE, 0, rh.length)) {
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
             "Relay begin cell has no \\0. Closing.");
      end_payload[0] = END_STREAM_REASON_TORPROTOCOL;
      relay_send_command_from_edge(rh.stream_id, circ, RELAY_COMMAND_END,
                                   end_payload, 1, NULL);
      return 0;
    }
    if (parse_addr_port(LOG_PROTOCOL_WARN, cell->payload+RELAY_HEADER_SIZE,
                        &address,NULL,&port)<0) {
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
             "Unable to parse addr:port in relay begin cell. Closing.");
      end_payload[0] = END_STREAM_REASON_TORPROTOCOL;
      relay_send_command_from_edge(rh.stream_id, circ, RELAY_COMMAND_END,
                                   end_payload, 1, NULL);
      return 0;
    }
    if (port==0) {
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
             "Missing port in relay begin cell. Closing.");
      end_payload[0] = END_STREAM_REASON_TORPROTOCOL;
      relay_send_command_from_edge(rh.stream_id, circ, RELAY_COMMAND_END,
                                   end_payload, 1, NULL);
      tor_free(address);
      return 0;
    }
    if (or_circ && or_circ->is_first_hop) {
      /* Don't let clients use us as a single-hop proxy; it attracts attackers
       * and users who'd be better off with, well, single-hop proxies.
       */
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
             "Attempt to open a stream on first hop of circuit. Closing.");
      end_payload[0] = END_STREAM_REASON_TORPROTOCOL;
      relay_send_command_from_edge(rh.stream_id, circ, RELAY_COMMAND_END,
                                   end_payload, 1, NULL);
      tor_free(address);
      return 0;
    }
  } else if (rh.command == RELAY_COMMAND_BEGIN_DIR) {
    or_options_t *options = get_options();
    port = options->DirPort; /* not actually used to open a connection */
    if (!port || circ->purpose != CIRCUIT_PURPOSE_OR) {
      end_payload[0] = END_STREAM_REASON_NOTDIRECTORY;
      relay_send_command_from_edge(rh.stream_id, circ, RELAY_COMMAND_END,
                                   end_payload, 1, NULL);
      return 0;
    }
    if (or_circ && or_circ->p_conn && or_circ->p_conn->_base.address)
      address = tor_strdup(or_circ->p_conn->_base.address);
    else
      address = tor_strdup("127.0.0.1");
  } else {
    log_warn(LD_BUG, "Got an unexpected command %d", (int)rh.command);
    end_payload[0] = END_STREAM_REASON_INTERNAL;
    relay_send_command_from_edge(rh.stream_id, circ, RELAY_COMMAND_END,
                                 end_payload, 1, NULL);
    return 0;
  }

  log_debug(LD_EXIT,"Creating new exit connection.");
  n_stream = TO_EDGE_CONN(connection_new(CONN_TYPE_EXIT));
  n_stream->_base.purpose = EXIT_PURPOSE_CONNECT;

  n_stream->stream_id = rh.stream_id;
  n_stream->_base.port = port;
  /* leave n_stream->s at -1, because it's not yet valid */
  n_stream->package_window = STREAMWINDOW_START;
  n_stream->deliver_window = STREAMWINDOW_START;

  if (circ->purpose == CIRCUIT_PURPOSE_S_REND_JOINED) {
    origin_circuit_t *origin_circ = TO_ORIGIN_CIRCUIT(circ);
    log_debug(LD_REND,"begin is for rendezvous. configuring stream.");
    n_stream->_base.address = tor_strdup("(rendezvous)");
    n_stream->_base.state = EXIT_CONN_STATE_CONNECTING;
    strlcpy(n_stream->rend_query, origin_circ->rend_query,
            sizeof(n_stream->rend_query));
    tor_assert(connection_edge_is_rendezvous_stream(n_stream));
    assert_circuit_ok(circ);
    if (rend_service_set_connection_addr_port(n_stream, origin_circ) < 0) {
      log_info(LD_REND,"Didn't find rendezvous service (port %d)",
               n_stream->_base.port);
      end_payload[0] = END_STREAM_REASON_EXITPOLICY;
      relay_send_command_from_edge(rh.stream_id, circ, RELAY_COMMAND_END,
                                   end_payload, 1, NULL);
      connection_free(TO_CONN(n_stream));
      /* knock the whole thing down, somebody screwed up */
      circuit_mark_for_close(circ, END_CIRC_REASON_CONNECTFAILED);
      tor_free(address);
      return 0;
    }
    assert_circuit_ok(circ);
    log_debug(LD_REND,"Finished assigning addr/port");
    n_stream->cpath_layer = origin_circ->cpath->prev; /* link it */

    /* add it into the linked list of n_streams on this circuit */
    n_stream->next_stream = origin_circ->p_streams;
    n_stream->on_circuit = circ;
    origin_circ->p_streams = n_stream;
    assert_circuit_ok(circ);

    connection_exit_connect(n_stream);
    tor_free(address);
    return 0;
  }
  tor_strlower(address);
  n_stream->_base.address = address;
  n_stream->_base.state = EXIT_CONN_STATE_RESOLVEFAILED;
  /* default to failed, change in dns_resolve if it turns out not to fail */

  if (we_are_hibernating()) {
    end_payload[0] = END_STREAM_REASON_HIBERNATING;
    relay_send_command_from_edge(rh.stream_id, circ, RELAY_COMMAND_END,
                                 end_payload, 1, NULL);
    connection_free(TO_CONN(n_stream));
    return 0;
  }
  log_debug(LD_EXIT,"about to start the dns_resolve().");

  if (rh.command == RELAY_COMMAND_BEGIN_DIR) {
    if (or_circ && or_circ->p_conn && or_circ->p_conn->_base.addr)
      n_stream->_base.addr = or_circ->p_conn->_base.addr;
    n_stream->next_stream = TO_OR_CIRCUIT(circ)->n_streams;
    n_stream->on_circuit = circ;
    TO_OR_CIRCUIT(circ)->n_streams = n_stream;
    return connection_exit_connect_dir(n_stream);
  }

  n_stream->on_circuit = circ;

  /* send it off to the gethostbyname farm */
  switch (dns_resolve(n_stream)) {
    case 1: /* resolve worked */

      /* add it into the linked list of n_streams on this circuit */
      n_stream->next_stream = TO_OR_CIRCUIT(circ)->n_streams;
      TO_OR_CIRCUIT(circ)->n_streams = n_stream;
      assert_circuit_ok(circ);

      log_debug(LD_EXIT,"about to call connection_exit_connect().");
      connection_exit_connect(n_stream);
      return 0;
    case -1: /* resolve failed */
      end_payload[0] = END_STREAM_REASON_RESOLVEFAILED;
      relay_send_command_from_edge(rh.stream_id, circ, RELAY_COMMAND_END,
                                   end_payload, 1, NULL);
      /* n_stream got detached and freed. don't touch it. */
      break;
    case 0: /* resolve added to pending list */
      /* add it into the linked list of resolving_streams on this circuit */
      n_stream->next_stream = TO_OR_CIRCUIT(circ)->resolving_streams;
      TO_OR_CIRCUIT(circ)->resolving_streams = n_stream;
      assert_circuit_ok(circ);
      ;
  }
  return 0;
}

/**
 * Called when we receive a RELAY_RESOLVE cell 'cell' along the circuit 'circ';
 * begin resolving the hostname, and (eventually) reply with a RESOLVED cell.
 */
int
connection_exit_begin_resolve(cell_t *cell, or_circuit_t *circ)
{
  edge_connection_t *dummy_conn;
  relay_header_t rh;

  assert_circuit_ok(TO_CIRCUIT(circ));
  relay_header_unpack(&rh, cell->payload);

  /* This 'dummy_conn' only exists to remember the stream ID
   * associated with the resolve request; and to make the
   * implementation of dns.c more uniform.  (We really only need to
   * remember the circuit, the stream ID, and the hostname to be
   * resolved; but if we didn't store them in a connection like this,
   * the housekeeping in dns.c would get way more complicated.)
   */
  dummy_conn = TO_EDGE_CONN(connection_new(CONN_TYPE_EXIT));
  dummy_conn->stream_id = rh.stream_id;
  dummy_conn->_base.address = tor_strndup(cell->payload+RELAY_HEADER_SIZE,
                                          rh.length);
  dummy_conn->_base.port = 0;
  dummy_conn->_base.state = EXIT_CONN_STATE_RESOLVEFAILED;
  dummy_conn->_base.purpose = EXIT_PURPOSE_RESOLVE;

  dummy_conn->on_circuit = TO_CIRCUIT(circ);

  /* send it off to the gethostbyname farm */
  switch (dns_resolve(dummy_conn)) {
    case -1: /* Impossible to resolve; a resolved cell was sent. */
      /* Connection freed; don't touch it. */
      return 0;
    case 1: /* The result was cached; a resolved cell was sent. */
      if (!dummy_conn->_base.marked_for_close)
        connection_free(TO_CONN(dummy_conn));
      return 0;
    case 0: /* resolve added to pending list */
      dummy_conn->next_stream = circ->resolving_streams;
      circ->resolving_streams = dummy_conn;
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
  uint32_t addr;
  uint16_t port;
  connection_t *conn = TO_CONN(edge_conn);

  if (!connection_edge_is_rendezvous_stream(edge_conn) &&
      router_compare_to_my_exit_policy(edge_conn)) {
    log_info(LD_EXIT,"%s:%d failed exit policy. Closing.",
             escaped_safe_str(conn->address), conn->port);
    connection_edge_end(edge_conn, END_STREAM_REASON_EXITPOLICY);
    circuit_detach_stream(circuit_get_by_edge_conn(edge_conn), edge_conn);
    connection_free(conn);
    return;
  }

  addr = conn->addr;
  port = conn->port;
  if (redirect_exit_list) {
    SMARTLIST_FOREACH(redirect_exit_list, exit_redirect_t *, r,
    {
      if ((addr&r->mask)==(r->addr&r->mask) &&
          (r->port_min <= port) && (port <= r->port_max)) {
        struct in_addr in;
        if (r->is_redirect) {
          char tmpbuf[INET_NTOA_BUF_LEN];
          addr = r->addr_dest;
          port = r->port_dest;
          in.s_addr = htonl(addr);
          tor_inet_ntoa(&in, tmpbuf, sizeof(tmpbuf));
          log_debug(LD_EXIT, "Redirecting connection from %s:%d to %s:%d",
                    escaped_safe_str(conn->address), conn->port,
                    safe_str(tmpbuf), port);
        }
        break;
      }
    });
  }

  log_debug(LD_EXIT,"about to try connecting");
  switch (connection_connect(conn, conn->address, addr, port)) {
    case -1:
      connection_edge_end_errno(edge_conn);
      circuit_detach_stream(circuit_get_by_edge_conn(edge_conn), edge_conn);
      connection_free(conn);
      return;
    case 0:
      conn->state = EXIT_CONN_STATE_CONNECTING;

      connection_watch_events(conn, EV_WRITE | EV_READ);
      /* writable indicates finish;
       * readable/error indicates broken link in windowsland. */
      return;
    /* case 1: fall through */
  }

  conn->state = EXIT_CONN_STATE_OPEN;
  if (connection_wants_to_flush(conn)) {
    /* in case there are any queued data cells */
    log_warn(LD_BUG,"newly connected conn had data waiting!");
//    connection_start_writing(conn);
  }
  connection_watch_events(conn, EV_READ);

  /* also, deliver a 'connected' cell back through the circuit. */
  if (connection_edge_is_rendezvous_stream(edge_conn)) {
    /* rendezvous stream */
    /* don't send an address back! */
    connection_edge_send_command(edge_conn,
                                 RELAY_COMMAND_CONNECTED,
                                 NULL, 0);
  } else { /* normal stream */
    /* This must be the original address, not the redirected address. */
    char connected_payload[8];
    set_uint32(connected_payload, htonl(conn->addr));
    set_uint32(connected_payload+4,
               htonl(dns_clip_ttl(edge_conn->address_ttl)));
    connection_edge_send_command(edge_conn,
                                 RELAY_COMMAND_CONNECTED,
                                 connected_payload, 8);
  }
}

/** Given an exit conn that should attach to us as a directory server, open a
 * bridge connection with a socketpair, create a new directory conn, and join
 * them together.  Return 0 on success (or if there was an error we could send
 * back an end cell for).  Return -(some circuit end reason) if the circuit
 * needs to be torn down.  Either connects exit_conn, frees it, or marks it,
 * as appropriate.
 */
static int
connection_exit_connect_dir(edge_connection_t *exit_conn)
{
  int fd[2];
  int err;
  dir_connection_t *dir_conn = NULL;

  log_info(LD_EXIT, "Opening dir bridge");

  if ((err = tor_socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) < 0) {
    log_warn(LD_NET,
             "Couldn't construct socketpair (%s). "
             "Network down? Out of sockets?",
             tor_socket_strerror(-err));
    connection_edge_end(exit_conn, END_STREAM_REASON_RESOURCELIMIT);
    connection_free(TO_CONN(exit_conn));
    return 0;
  }

  tor_assert(fd[0] >= 0);
  tor_assert(fd[1] >= 0);

  set_socket_nonblocking(fd[0]);
  set_socket_nonblocking(fd[1]);

  exit_conn->_base.s = fd[0];
  exit_conn->_base.state = EXIT_CONN_STATE_OPEN;

  dir_conn = TO_DIR_CONN(connection_new(CONN_TYPE_DIR));
  dir_conn->_base.s = fd[1];

  dir_conn->_base.addr = 0x7f000001;
  dir_conn->_base.port = 0;
  dir_conn->_base.address = tor_strdup("Tor network");
  dir_conn->_base.type = CONN_TYPE_DIR;
  dir_conn->_base.purpose = DIR_PURPOSE_SERVER;
  dir_conn->_base.state = DIR_CONN_STATE_SERVER_COMMAND_WAIT;

  if (connection_add(TO_CONN(exit_conn))<0) {
    connection_edge_end(exit_conn, END_STREAM_REASON_RESOURCELIMIT);
    connection_free(TO_CONN(exit_conn));
    connection_free(TO_CONN(dir_conn));
    return 0;
  }

  if (connection_add(TO_CONN(dir_conn))<0) {
    connection_edge_end(exit_conn, END_STREAM_REASON_RESOURCELIMIT);
    connection_close_immediate(TO_CONN(exit_conn));
    connection_mark_for_close(TO_CONN(exit_conn));
    connection_free(TO_CONN(dir_conn));
    return 0;
  }

  connection_start_reading(TO_CONN(dir_conn));
  connection_start_reading(TO_CONN(exit_conn));

  if (connection_edge_send_command(exit_conn,
                                   RELAY_COMMAND_CONNECTED, NULL, 0) < 0) {
    connection_mark_for_close(TO_CONN(exit_conn));
    connection_mark_for_close(TO_CONN(dir_conn));
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
  if (*conn->rend_query) /* XXX */
    return 1;
  return 0;
}

/** Return 1 if router <b>exit</b> is likely to allow stream <b>conn</b>
 * to exit from it, or 0 if it probably will not allow it.
 * (We might be uncertain if conn's destination address has not yet been
 * resolved.)
 */
int
connection_ap_can_use_exit(edge_connection_t *conn, routerinfo_t *exit)
{
  tor_assert(conn);
  tor_assert(conn->_base.type == CONN_TYPE_AP);
  tor_assert(conn->socks_request);
  tor_assert(exit);

  /* If a particular exit node has been requested for the new connection,
   * make sure the exit node of the existing circuit matches exactly.
   */
  if (conn->chosen_exit_name) {
    if (router_get_by_nickname(conn->chosen_exit_name, 1) != exit) {
      /* doesn't match */
//      log_debug(LD_APP,"Requested node '%s', considering node '%s'. No.",
//                conn->chosen_exit_name, exit->nickname);
      return 0;
    }
  }

  if (conn->socks_request->command == SOCKS_COMMAND_CONNECT) {
    struct in_addr in;
    uint32_t addr = 0;
    addr_policy_result_t r;
    if (tor_inet_aton(conn->socks_request->address, &in))
      addr = ntohl(in.s_addr);
    r = compare_addr_to_addr_policy(addr, conn->socks_request->port,
                                    exit->exit_policy);
    if (r == ADDR_POLICY_REJECTED || r == ADDR_POLICY_PROBABLY_REJECTED)
      return 0;
  } else if (SOCKS_COMMAND_IS_RESOLVE(conn->socks_request->command)) {
    /* Can't support reverse lookups without eventdns. */
    if (conn->socks_request->command == SOCKS_COMMAND_RESOLVE_PTR &&
        exit->has_old_dnsworkers)
      return 0;

    /* Don't send DNS requests to non-exit servers by default. */
    if (!conn->chosen_exit_name && policy_is_reject_star(exit->exit_policy))
      return 0;
  }
  return 1;
}

/** Make connection redirection follow the provided list of
 * exit_redirect_t */
void
set_exit_redirects(smartlist_t *lst)
{
  if (redirect_exit_list) {
    SMARTLIST_FOREACH(redirect_exit_list, exit_redirect_t *, p, tor_free(p));
    smartlist_free(redirect_exit_list);
  }
  redirect_exit_list = lst;
}

/** If address is of the form "y.onion" with a well-formed handle y:
 *     Put a NUL after y, lower-case it, and return ONION_HOSTNAME.
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
    char query[REND_SERVICE_ID_LEN+1];

    s = strrchr(address,'.');
    if (!s)
      return NORMAL_HOSTNAME; /* no dot, thus normal */
    if (!strcmp(s+1,"exit")) {
      *s = 0; /* nul-terminate it */
      return EXIT_HOSTNAME; /* .exit */
    }
    if (strcmp(s+1,"onion"))
      return NORMAL_HOSTNAME; /* neither .exit nor .onion, thus normal */

    /* so it is .onion */
    *s = 0; /* nul-terminate it */
    if (strlcpy(query, address, REND_SERVICE_ID_LEN+1) >=
        REND_SERVICE_ID_LEN+1)
      goto failed;
    if (rend_valid_service_id(query)) {
      return ONION_HOSTNAME; /* success */
    }
failed:
    /* otherwise, return to previous state and return 0 */
    *s = '.';
    return BAD_HOSTNAME;
}

/** Check if the address is of the form "y.noconnect"
 */
static int
hostname_is_noconnect_address(const char *address)
{
  return ! strcasecmpend(address, ".noconnect");
}

