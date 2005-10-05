/* Copyright 2001 Matej Pfajfar.
 * Copyright 2001-2004 Roger Dingledine.
 * Copyright 2004-2005 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char connection_edge_c_id[] = "$Id$";

/**
 * \file connection_edge.c
 * \brief Handle edge streams.
 **/

#include "or.h"
#include "tree.h"

static addr_policy_t *socks_policy = NULL;
/* List of exit_redirect_t */
static smartlist_t *redirect_exit_list = NULL;

static int connection_ap_handshake_process_socks(connection_t *conn);

/** An AP stream has failed/finished. If it hasn't already sent back
 * a socks reply, send one now (based on endreason). Also set
 * has_sent_end to 1, and mark the conn.
 */
void
_connection_mark_unattached_ap(connection_t *conn, int endreason,
                               int line, const char *file)
{
  tor_assert(conn->type == CONN_TYPE_AP);
  conn->has_sent_end = 1; /* no circ yet */

  if (conn->marked_for_close) {
    /* This call will warn as appropriate. */
    _connection_mark_for_close(conn, line, file);
    return;
  }

  if (!conn->socks_request->has_finished) {
    socks5_reply_status_t socksreason =
      connection_edge_end_reason_socks5_response(endreason);

    if (endreason == END_STREAM_REASON_ALREADY_SOCKS_REPLIED)
      log_fn(LOG_WARN,"Bug: stream (marked at %s:%d) sending two socks replies?",
             file, line);

    if (conn->socks_request->command == SOCKS_COMMAND_CONNECT)
      connection_ap_handshake_socks_reply(conn, NULL, 0, socksreason);
    else
      connection_ap_handshake_socks_resolved(conn,RESOLVED_TYPE_ERROR,0,NULL,-1);
  }

  _connection_mark_for_close(conn, line, file);
  conn->hold_open_until_flushed = 1;
}

/** There was an EOF. Send an end and mark the connection for close.
 */
int
connection_edge_reached_eof(connection_t *conn)
{
#ifdef HALF_OPEN
  /* eof reached; we're done reading, but we might want to write more. */
  conn->done_receiving = 1;
  shutdown(conn->s, 0); /* XXX check return, refactor NM */
  if (conn->done_sending) {
    connection_edge_end(conn, END_STREAM_REASON_DONE, conn->cpath_layer);
    connection_mark_for_close(conn);
  } else {
    connection_edge_send_command(conn, circuit_get_by_edge_conn(conn),
                                 RELAY_COMMAND_END,
                                 NULL, 0, conn->cpath_layer);
  }
  return 0;
#else
  if (buf_datalen(conn->inbuf) && connection_state_is_open(conn)) {
    /* it still has stuff to process. don't let it die yet. */
    return 0;
  }
  log_fn(LOG_INFO,"conn (fd %d) reached eof. Closing.", conn->s);
  if (!conn->marked_for_close) {
    /* only mark it if not already marked. it's possible to
     * get the 'end' right around when the client hangs up on us. */
    connection_edge_end(conn, END_STREAM_REASON_DONE, conn->cpath_layer);
    if (conn->socks_request) /* eof, so don't send a socks reply back */
      conn->socks_request->has_finished = 1;
    connection_mark_for_close(conn);
  }
  return 0;
#endif
}

/** Handle new bytes on conn->inbuf based on state:
 *   - If it's waiting for socks info, try to read another step of the
 *     socks handshake out of conn->inbuf.
 *   - If it's open, then package more relay cells from the stream.
 *   - Else, leave the bytes on inbuf alone for now.
 *
 * Mark and return -1 if there was an unexpected error with the conn,
 * else return 0.
 */
int
connection_edge_process_inbuf(connection_t *conn, int package_partial)
{
  tor_assert(conn);
  tor_assert(CONN_IS_EDGE(conn));

  switch (conn->state) {
    case AP_CONN_STATE_SOCKS_WAIT:
      if (connection_ap_handshake_process_socks(conn) < 0) {
        /* already marked */
        return -1;
      }
      return 0;
    case AP_CONN_STATE_OPEN:
    case EXIT_CONN_STATE_OPEN:
      if (connection_edge_package_raw_inbuf(conn, package_partial) < 0) {
        /* (We already sent an end cell if possible) */
        connection_mark_for_close(conn);
        return -1;
      }
      return 0;
    case EXIT_CONN_STATE_CONNECTING:
    case AP_CONN_STATE_RENDDESC_WAIT:
    case AP_CONN_STATE_CIRCUIT_WAIT:
    case AP_CONN_STATE_CONNECT_WAIT:
    case AP_CONN_STATE_RESOLVE_WAIT:
    case AP_CONN_STATE_CONTROLLER_WAIT:
      log_fn(LOG_INFO,"data from edge while in '%s' state. Leaving it on buffer.",
             conn_state_to_string(conn->type, conn->state));
      return 0;
  }
  log_fn(LOG_WARN,"Bug: Got unexpected state %d. Closing.",conn->state);
  tor_fragile_assert();
  connection_edge_end(conn, END_STREAM_REASON_INTERNAL, conn->cpath_layer);
  connection_mark_for_close(conn);
  return -1;
}

/** This edge needs to be closed, because its circuit has closed.
 * Mark it for close and return 0.
 */
int
connection_edge_destroy(uint16_t circ_id, connection_t *conn)
{
  tor_assert(CONN_IS_EDGE(conn));

  if (!conn->marked_for_close) {
    log_fn(LOG_INFO,"CircID %d: At an edge. Marking connection for close.",
           circ_id);
    if (conn->type == CONN_TYPE_AP) {
      connection_mark_unattached_ap(conn, END_STREAM_REASON_DESTROY);
    } else {
      conn->has_sent_end = 1; /* we're closing the circuit, nothing to send to */
      connection_mark_for_close(conn);
      conn->hold_open_until_flushed = 1;
    }
  }
  conn->cpath_layer = NULL;
  conn->on_circuit = NULL;
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
  char payload[RELAY_PAYLOAD_SIZE];
  size_t payload_len=1;
  circuit_t *circ;

  if (conn->has_sent_end) {
    log_fn(LOG_WARN,"Harmless bug: Calling connection_edge_end (reason %d) on an already ended stream?", reason);
    tor_fragile_assert();
    return -1;
  }

  if (conn->marked_for_close) {
    log_fn(LOG_WARN,"Bug: called on conn that's already marked for close at %s:%d.",
           conn->marked_for_close_file, conn->marked_for_close);
    return 0;
  }

  payload[0] = reason;
  if (reason == END_STREAM_REASON_EXITPOLICY &&
      !connection_edge_is_rendezvous_stream(conn)) {
    set_uint32(payload+1, htonl(conn->addr));
    set_uint32(payload+5, htonl(MAX_DNS_ENTRY_AGE)); /* XXXXfill with a real TTL*/
    payload_len += 8;
  }

  circ = circuit_get_by_edge_conn(conn);
  if (circ && !circ->marked_for_close) {
    log_fn(LOG_DEBUG,"Marking conn (fd %d) and sending end.",conn->s);
    connection_edge_send_command(conn, circ, RELAY_COMMAND_END,
                                 payload, payload_len, cpath_layer);
  } else {
    log_fn(LOG_DEBUG,"Marking conn (fd %d); no circ to send end.",conn->s);
  }

  conn->has_sent_end = 1;
  return 0;
}

/** An error has just occured on an operation on an edge connection
 * <b>conn</b>.  Extract the errno; convert it to an end reason, and send
 * an appropriate relay end cell to <b>cpath_layer</b>.
 **/
int
connection_edge_end_errno(connection_t *conn, crypt_path_t *cpath_layer)
{
  uint8_t reason;
  tor_assert(conn);
  reason = (uint8_t)errno_to_end_reason(tor_socket_errno(conn->s));
  return connection_edge_end(conn, reason, cpath_layer);
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
connection_edge_finished_flushing(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(CONN_IS_EDGE(conn));

  switch (conn->state) {
    case AP_CONN_STATE_OPEN:
    case EXIT_CONN_STATE_OPEN:
      connection_stop_writing(conn);
      connection_edge_consider_sending_sendme(conn);
      return 0;
    case AP_CONN_STATE_SOCKS_WAIT:
    case AP_CONN_STATE_RENDDESC_WAIT:
    case AP_CONN_STATE_CIRCUIT_WAIT:
    case AP_CONN_STATE_CONNECT_WAIT:
    case AP_CONN_STATE_CONTROLLER_WAIT:
      connection_stop_writing(conn);
      return 0;
    default:
      log_fn(LOG_WARN,"BUG: called in unexpected state %d.", conn->state);
      tor_fragile_assert();
      return -1;
  }
  return 0;
}

/** Connected handler for exit connections: start writing pending
 * data, deliver 'CONNECTED' relay cells as appropriate, and check
 * any pending data that may have been received. */
int
connection_edge_finished_connecting(connection_t *conn)
{
  char valbuf[INET_NTOA_BUF_LEN];
  struct in_addr in;

  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_EXIT);
  tor_assert(conn->state == EXIT_CONN_STATE_CONNECTING);

  in.s_addr = htonl(conn->addr);
  tor_inet_ntoa(&in,valbuf,sizeof(valbuf));
  log_fn(LOG_INFO,"Exit connection to %s:%u (%s) established.",
         safe_str(conn->address),conn->port,safe_str(valbuf));

  conn->state = EXIT_CONN_STATE_OPEN;
  connection_watch_events(conn, EV_READ); /* stop writing, continue reading */
  if (connection_wants_to_flush(conn)) /* in case there are any queued relay cells */
    connection_start_writing(conn);
  /* deliver a 'connected' relay cell back through the circuit. */
  if (connection_edge_is_rendezvous_stream(conn)) {
    if (connection_edge_send_command(conn, circuit_get_by_edge_conn(conn),
                                     RELAY_COMMAND_CONNECTED, NULL, 0, conn->cpath_layer) < 0)
      return 0; /* circuit is closed, don't continue */
  } else {
    char connected_payload[8];
    set_uint32(connected_payload, htonl(conn->addr));
    set_uint32(connected_payload+4,
               htonl(MAX_DNS_ENTRY_AGE)); /* XXXX fill with a real TTL */
    if (connection_edge_send_command(conn, circuit_get_by_edge_conn(conn),
        RELAY_COMMAND_CONNECTED, connected_payload, 8, conn->cpath_layer) < 0)
      return 0; /* circuit is closed, don't continue */
  }
  tor_assert(conn->package_window > 0);
  /* in case the server has written anything */
  return connection_edge_process_inbuf(conn, 1);
}

/** Find all general-purpose AP streams waiting for a response that sent
 * their begin/resolve cell >=15 seconds ago. Detach from their current circuit,
 * and mark their current circuit as unsuitable for new streams. Then call
 * connection_ap_handshake_attach_circuit() to attach to a new circuit (if
 * available) or launch a new one.
 *
 * For rendezvous streams, simply give up after 45 seconds (with no
 * retry attempt).
 */
void
connection_ap_expire_beginning(void)
{
  connection_t **carray;
  connection_t *conn;
  circuit_t *circ;
  int n, i;
  time_t now = time(NULL);
  or_options_t *options = get_options();

  get_connection_array(&carray, &n);

  for (i = 0; i < n; ++i) {
    conn = carray[i];
    if (conn->type != CONN_TYPE_AP)
      continue;
    if (conn->state == AP_CONN_STATE_CONTROLLER_WAIT) {
      if (now - conn->timestamp_lastread >= 120) {
        log_fn(LOG_NOTICE, "Closing unattached stream.");
        connection_mark_unattached_ap(conn, END_STREAM_REASON_TIMEOUT);
      }
      continue;
    }

    else if (conn->state != AP_CONN_STATE_RESOLVE_WAIT &&
        conn->state != AP_CONN_STATE_CONNECT_WAIT)
      continue;
    if (now - conn->timestamp_lastread < 15)
      continue;
    circ = circuit_get_by_edge_conn(conn);
    if (!circ) { /* it's vanished? */
      log_fn(LOG_INFO,"Conn is waiting (address %s), but lost its circ.",
             safe_str(conn->socks_request->address));
      connection_mark_unattached_ap(conn, END_STREAM_REASON_TIMEOUT);
      continue;
    }
    if (circ->purpose == CIRCUIT_PURPOSE_C_REND_JOINED) {
      if (now - conn->timestamp_lastread > 45) {
        log_fn(LOG_NOTICE,"Rend stream is %d seconds late. Giving up on address '%s'.",
               (int)(now - conn->timestamp_lastread),
               safe_str(conn->socks_request->address));
        connection_edge_end(conn, END_STREAM_REASON_TIMEOUT, conn->cpath_layer);
        connection_mark_unattached_ap(conn, END_STREAM_REASON_TIMEOUT);
      }
      continue;
    }
    tor_assert(circ->purpose == CIRCUIT_PURPOSE_C_GENERAL);
    log_fn(LOG_NOTICE,"Stream is %d seconds late on address '%s'. Retrying.",
           (int)(now - conn->timestamp_lastread),
           safe_str(conn->socks_request->address));
    circuit_log_path(LOG_NOTICE, circ);
    /* send an end down the circuit */
    connection_edge_end(conn, END_STREAM_REASON_TIMEOUT, conn->cpath_layer);
    /* un-mark it as ending, since we're going to reuse it */
    conn->has_sent_end = 0;
    /* kludge to make us not try this circuit again, yet to allow
     * current streams on it to survive if they can: make it
     * unattractive to use for new streams */
    tor_assert(circ->timestamp_dirty);
    circ->timestamp_dirty -= options->MaxCircuitDirtiness;
    /* give our stream another 15 seconds to try */
    conn->timestamp_lastread += 15;
    /* move it back into 'pending' state, and try to attach. */
    if (connection_ap_detach_retriable(conn, circ)<0) {
      connection_mark_unattached_ap(conn, END_STREAM_REASON_CANT_ATTACH);
    }
  } /* end for */
}

/** Tell any AP streams that are waiting for a new circuit that one is
 * available.
 */
void
connection_ap_attach_pending(void)
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
    if (connection_ap_handshake_attach_circuit(conn) < 0) {
      connection_mark_unattached_ap(conn, END_STREAM_REASON_CANT_ATTACH);
    }
  }
}

/** The AP connection <b>conn</b> has just failed while attaching or
 * sending a BEGIN or resolving on <b>circ</b>, but another circuit
 * might work.  Detach the circuit, and either reattach it, launch a
 * new circuit, tell the controller, or give up as a appropriate.
 *
 * Returns -1 on err, 1 on success, 0 on not-yet-sure.
 */
int
connection_ap_detach_retriable(connection_t *conn, circuit_t *circ)
{
  control_event_stream_status(conn, STREAM_EVENT_FAILED_RETRIABLE);
  conn->timestamp_lastread = time(NULL);
  if (! get_options()->LeaveStreamsUnattached) {
    conn->state = AP_CONN_STATE_CIRCUIT_WAIT;
    circuit_detach_stream(circ,conn);
    return connection_ap_handshake_attach_circuit(conn);
  } else {
    conn->state = AP_CONN_STATE_CONTROLLER_WAIT;
    circuit_detach_stream(circ,conn);
    return 0;
  }
}

/** A client-side struct to remember requests to rewrite addresses
 * to new addresses. These structs make up a tree, with addressmap
 * below as its root.
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

typedef struct {
  char *ipv4_address;
  char *hostname_address;
} virtaddress_entry_t;

/** The tree of client-side address rewrite instructions. */
static strmap_t *addressmap=NULL;
/**
 * Tree mapping addresses to which virtual address, if any, we
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
  if (ent && ent->new_address && address_is_in_virtual_range(ent->new_address)) {
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

/* DOCDOC */
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
  strmap_free(addressmap, addressmap_ent_free);
  addressmap = NULL;
  strmap_free(virtaddress_reversemap, addressmap_virtaddress_ent_free);
}

/** Look at address, and rewrite it until it doesn't want any
 * more rewrites; but don't get into an infinite loop.
 * Don't write more than maxlen chars into address.
 */
void
addressmap_rewrite(char *address, size_t maxlen)
{
  addressmap_entry_t *ent;
  int rewrites;

  for (rewrites = 0; rewrites < 16; rewrites++) {
    ent = strmap_get(addressmap, address);

    if (!ent || !ent->new_address)
      return; /* done, no rewrite needed */

    log_fn(LOG_INFO, "Addressmap: rewriting '%s' to '%s'",
           safe_str(address), safe_str(ent->new_address));
    strlcpy(address, ent->new_address, maxlen);
  }
  log_fn(LOG_WARN,"Loop detected: we've rewritten '%s' 16 times! Using it as-is.",
         safe_str(address));
  /* it's fine to rewrite a rewrite, but don't loop forever */
}

/** Return 1 if <b>address</b> is already registered, else return 0 */
int
addressmap_already_mapped(const char *address)
{
  return strmap_get(addressmap, address) ? 1 : 0;
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
      log_fn(LOG_INFO,"Temporary addressmap ('%s' to '%s') not performed, since it's already mapped to '%s'",
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

  log_fn(LOG_INFO, "Addressmap: (re)mapped '%s' to '%s'",
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
    ent->expires = time(NULL)+MAX_DNS_ENTRY_AGE;
    strmap_set(addressmap,address,ent);
  }
  ++ent->num_resolve_failures;
  log_fn(LOG_INFO,"Address %s now has %d resolve failures.",
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

/** Record the fact that <b>address</b> resolved to <b>val</b>.
 * We can now use this in subsequent streams via addressmap_rewrite()
 * so we can more correctly choose an exit that will allow <b>address</b>.
 *
 * If <b>exitname</b> is defined, then append the addresses with
 * ".exitname.exit" before registering the mapping.
 *
 * If <b>ttl</b> is nonnegative, the mapping will be valid for
 * <b>ttl</b>seconds.
 */
void
client_dns_set_addressmap(const char *address, uint32_t val, const char *exitname,
                          int ttl)
{
  struct in_addr in;
  char extendedaddress[MAX_SOCKS_ADDR_LEN+MAX_HEX_NICKNAME_LEN+10];
  char valbuf[INET_NTOA_BUF_LEN];
  char extendedval[INET_NTOA_BUF_LEN+MAX_HEX_NICKNAME_LEN+10];

  tor_assert(address); tor_assert(val);

  if (ttl<0 || ttl>MAX_DNS_ENTRY_AGE)
    ttl = MAX_DNS_ENTRY_AGE;

  if (tor_inet_aton(address, &in))
    return; /* If address was an IP address already, don't add a mapping. */
  in.s_addr = htonl(val);
  tor_inet_ntoa(&in,valbuf,sizeof(valbuf));
  if (exitname) {
    tor_snprintf(extendedaddress, sizeof(extendedaddress),
                 "%s.%s.exit", address, exitname);
    tor_snprintf(extendedval, sizeof(extendedval),
                 "%s.%s.exit", valbuf, exitname);
  } else {
    tor_snprintf(extendedaddress, sizeof(extendedaddress),
                 "%s", address);
    tor_snprintf(extendedval, sizeof(extendedval),
                 "%s", valbuf);
  }
  addressmap_register(extendedaddress, tor_strdup(extendedval), time(NULL) + ttl);
}

/* Currently, we hand out 127.192.0.1 through 127.254.254.254.
 * These addresses should map to localhost, so even if the
 * application accidentally tried to connect to them directly (not
 * via Tor), it wouldn't get too far astray.
 *
 * Eventually, we should probably make this configurable.
 */
#define MIN_UNUSED_IPV4 0x7fc00001u
#define MAX_UNUSED_IPV4 0x7ffefefeu

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
    if (addr >= MIN_UNUSED_IPV4 && addr <= MAX_UNUSED_IPV4)
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
  static uint32_t next_ipv4 = MIN_UNUSED_IPV4;
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
    while (1) {
      /* Don't hand out any .0 or .255 address. */
      while ((next_ipv4 & 0xff) == 0 ||
             (next_ipv4 & 0xff) == 0xff)
        ++next_ipv4;
      in.s_addr = htonl(next_ipv4);
      tor_inet_ntoa(&in, buf, sizeof(buf));
      if (!strmap_get(addressmap, buf))
        break;

      ++next_ipv4;
      if (next_ipv4 > MAX_UNUSED_IPV4)
        next_ipv4 = MIN_UNUSED_IPV4;
    }
    return tor_strdup(buf);
  } else {
    log_fn(LOG_WARN, "Called with unsupported address type (%d)",
           type);
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
    if (ent && ent->new_address && !strcasecmp(new_address, ent->new_address)) {
      tor_free(new_address);
      return tor_strdup(*addrp);
    } else
      log_fn(LOG_WARN, "Internal confusion: I thought that '%s' was mapped to by '%s', but '%s' really maps to '%s'. This is a harmless bug.",
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

/** Return 1 if <b>address</b> has funny characters in it like
 * colons. Return 0 if it's fine.
 */
static int
address_is_invalid_destination(const char *address)
{
  /* FFFF should flesh this out */
  if (strchr(address,':'))
    return 1;
  return 0;
}

/** Iterate over all address mapings which have expiry times between
 * min_expires and max_expires, inclusive.  If sl is provided, add an
 * "old-addr new-addr" string to sl for each mapping.  If sl is NULL,
 * remove the mappings.
 */
void
addressmap_get_mappings(smartlist_t *sl, time_t min_expires, time_t max_expires)
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
         addressmap_ent_remove(key, val);
         iter = strmap_iter_next_rmv(addressmap,iter);
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
static int
connection_ap_handshake_process_socks(connection_t *conn)
{
  socks_request_t *socks;
  int sockshere;
  hostname_type_t addresstype;

  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_AP);
  tor_assert(conn->state == AP_CONN_STATE_SOCKS_WAIT);
  tor_assert(conn->socks_request);
  socks = conn->socks_request;

  log_fn(LOG_DEBUG,"entered.");

  sockshere = fetch_from_buf_socks(conn->inbuf, socks);
  if (sockshere == 0) {
    if (socks->replylen) {
      connection_write_to_buf(socks->reply, socks->replylen, conn);
      socks->replylen = 0; /* zero it out so we can do another round of negotiation */
    } else {
      log_fn(LOG_DEBUG,"socks handshake not all here yet.");
    }
    return 0;
  } else if (sockshere == -1) {
    if (socks->replylen) { /* we should send reply back */
      log_fn(LOG_DEBUG,"reply is already set for us. Using it.");
      connection_ap_handshake_socks_reply(conn, socks->reply, socks->replylen,
                                          SOCKS5_GENERAL_ERROR);
    } else {
      log_fn(LOG_WARN,"Fetching socks handshake failed. Closing.");
      connection_ap_handshake_socks_reply(conn, NULL, 0, SOCKS5_GENERAL_ERROR);
    }
    connection_mark_unattached_ap(conn, END_STREAM_REASON_ALREADY_SOCKS_REPLIED);
    return -1;
  } /* else socks handshake is done, continue processing */

  tor_strlower(socks->address); /* normalize it */
  log_fn(LOG_DEBUG,"Client asked for %s:%d", safe_str(socks->address),
         socks->port);

  /* For address map controls, remap the address */
  addressmap_rewrite(socks->address, sizeof(socks->address));

  if (address_is_in_virtual_range(socks->address)) {
    /* This address was probably handed out by client_dns_get_unmapped_address,
     * but the mapping was discarded for some reason.  We *don't* want to send
     * the address through tor; that's likely to fail, and may leak
     * information.
     */
    log_fn(LOG_WARN,"Missing mapping for virtual address '%s'. Refusing.",
           socks->address); /* don't safe_str() this yet. */
    connection_mark_unattached_ap(conn, END_STREAM_REASON_INTERNAL);
    return -1;
  }

  /* Parse the address provided by SOCKS.  Modify it in-place if it
   * specifies a hidden-service (.onion) or particular exit node (.exit).
   */
  addresstype = parse_extended_hostname(socks->address);

  if (addresstype == BAD_HOSTNAME) {
    log_fn(LOG_WARN, "Invalid hostname %s; rejecting", socks->address);
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
        log_fn(LOG_WARN,"Malformed exit address '%s.exit'. Refusing.",
               safe_str(socks->address));
        connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
        return -1;
      }
    } else {
      struct in_addr in;
      routerinfo_t *r = router_get_by_nickname(socks->address, 1);
      if (r) {
        conn->chosen_exit_name = tor_strdup(socks->address);
        /* XXXX Should this use server->address instead? */
        in.s_addr = htonl(r->addr);
        strlcpy(socks->address, inet_ntoa(in), sizeof(socks->address));
      } else {
        log_fn(LOG_WARN,
               "Unrecognized server in exit address '%s.exit'. Refusing.",
               safe_str(socks->address));
        connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
        return -1;
      }
    }
  }

  if (addresstype != ONION_HOSTNAME) {
    /* not a hidden-service request (i.e. normal or .exit) */

    if (address_is_invalid_destination(socks->address)) {
      log_fn(LOG_WARN,"Destination '%s' seems to be an invalid hostname. Failing.",
             safe_str(socks->address));
      connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
      return -1;
    }

    if (socks->command == SOCKS_COMMAND_RESOLVE) {
      uint32_t answer;
      struct in_addr in;
      /* Reply to resolves immediately if we can. */
      if (strlen(socks->address) > RELAY_PAYLOAD_SIZE) {
        log_fn(LOG_WARN,"Address to be resolved is too large. Failing.");
        connection_ap_handshake_socks_resolved(conn,RESOLVED_TYPE_ERROR,0,NULL,-1);
        connection_mark_unattached_ap(conn, END_STREAM_REASON_ALREADY_SOCKS_REPLIED);
        return -1;
      }
      if (tor_inet_aton(socks->address, &in)) { /* see if it's an IP already */
        answer = in.s_addr; /* leave it in network order */
        connection_ap_handshake_socks_resolved(conn,RESOLVED_TYPE_IPV4,4,
                                               (char*)&answer,-1);
        connection_mark_unattached_ap(conn, END_STREAM_REASON_ALREADY_SOCKS_REPLIED);
        return 0;
      }
      rep_hist_note_used_resolve(time(NULL)); /* help predict this next time */
      control_event_stream_status(conn, STREAM_EVENT_NEW_RESOLVE);
    } else { /* socks->command == SOCKS_COMMAND_CONNECT */
      if (socks->port == 0) {
        log_fn(LOG_NOTICE,"Application asked to connect to port 0. Refusing.");
        connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
        return -1;
      }

      if (!conn->chosen_exit_name) {
        /* see if we can find a suitable enclave exit */
        routerinfo_t *r =
          router_find_exact_exit_enclave(socks->address, socks->port);
        if (r) {
          log_fn(LOG_INFO,"Redirecting address %s to exit at enclave router %s",
                 safe_str(socks->address), r->nickname);
          /* use the hex digest, not nickname, in case there are two
             routers with this nickname */
          conn->chosen_exit_name =
            tor_strdup(hex_str(r->identity_digest, DIGEST_LEN));
        }
      }

      rep_hist_note_used_port(socks->port, time(NULL)); /* help predict this next time */
      control_event_stream_status(conn, STREAM_EVENT_NEW);
    }
    if (get_options()->LeaveStreamsUnattached) {
      conn->state = AP_CONN_STATE_CONTROLLER_WAIT;
    } else {
      conn->state = AP_CONN_STATE_CIRCUIT_WAIT;
      if (connection_ap_handshake_attach_circuit(conn) < 0) {
        connection_mark_unattached_ap(conn, END_STREAM_REASON_CANT_ATTACH);
        return -1;
      }
    }
    return 0;
  } else {
    /* it's a hidden-service request */
    rend_cache_entry_t *entry;
    int r;

    if (socks->command == SOCKS_COMMAND_RESOLVE) {
      /* if it's a resolve request, fail it right now, rather than
       * building all the circuits and then realizing it won't work. */
      log_fn(LOG_WARN,"Resolve requests to hidden services not allowed. Failing.");
      connection_ap_handshake_socks_resolved(conn,RESOLVED_TYPE_ERROR,0,NULL,-1);
      connection_mark_unattached_ap(conn, END_STREAM_REASON_ALREADY_SOCKS_REPLIED);
      return -1;
    }

    strlcpy(conn->rend_query, socks->address, sizeof(conn->rend_query));
    log_fn(LOG_INFO,"Got a hidden service request for ID '%s'",
           safe_str(conn->rend_query));
    /* see if we already have it cached */
    r = rend_cache_lookup_entry(conn->rend_query, -1, &entry);
    if (r<0) {
      log_fn(LOG_WARN,"Invalid service descriptor %s",
             safe_str(conn->rend_query));
      connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
      return -1;
    }
    if (r==0) {
      conn->state = AP_CONN_STATE_RENDDESC_WAIT;
      log_fn(LOG_INFO, "Unknown descriptor %s. Fetching.",
             safe_str(conn->rend_query));
      rend_client_refetch_renddesc(conn->rend_query);
      return 0;
    }
    if (r>0) {
#define NUM_SECONDS_BEFORE_REFETCH (60*15)
      if (time(NULL) - entry->received < NUM_SECONDS_BEFORE_REFETCH) {
        conn->state = AP_CONN_STATE_CIRCUIT_WAIT;
        log_fn(LOG_INFO, "Descriptor is here and fresh enough. Great.");
        if (connection_ap_handshake_attach_circuit(conn) < 0) {
          connection_mark_unattached_ap(conn, END_STREAM_REASON_CANT_ATTACH);
          return -1;
        }
        return 0;
      } else {
        conn->state = AP_CONN_STATE_RENDDESC_WAIT;
        log_fn(LOG_INFO, "Stale descriptor %s. Refetching.",
               safe_str(conn->rend_query));
        rend_client_refetch_renddesc(conn->rend_query);
        return 0;
      }
    }
  }
  return 0; /* unreached but keeps the compiler happy */
}

/** Iterate over the two bytes of stream_id until we get one that is not
 * already in use; return it. Return 0 if can't get a unique stream_id.
 */
static uint16_t
get_unique_stream_id_by_circ(circuit_t *circ)
{
  connection_t *tmpconn;
  uint16_t test_stream_id;
  uint32_t attempts=0;

again:
  test_stream_id = circ->next_stream_id++;
  if (++attempts > 1<<16) {
    /* Make sure we don't loop forever if all stream_id's are used. */
    log_fn(LOG_WARN,"No unused stream IDs. Failing.");
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
connection_ap_handshake_send_begin(connection_t *ap_conn, circuit_t *circ)
{
  char payload[CELL_PAYLOAD_SIZE];
  int payload_len;

  tor_assert(ap_conn->type == CONN_TYPE_AP);
  tor_assert(ap_conn->state == AP_CONN_STATE_CIRCUIT_WAIT);
  tor_assert(ap_conn->socks_request);

  ap_conn->stream_id = get_unique_stream_id_by_circ(circ);
  if (ap_conn->stream_id==0) {
    connection_mark_unattached_ap(ap_conn, END_STREAM_REASON_INTERNAL);
    circuit_mark_for_close(circ);
    return -1;
  }

  tor_snprintf(payload,RELAY_PAYLOAD_SIZE, "%s:%d",
               (circ->purpose == CIRCUIT_PURPOSE_C_GENERAL) ?
                 ap_conn->socks_request->address : "",
               ap_conn->socks_request->port);
  payload_len = strlen(payload)+1;

  log_fn(LOG_DEBUG,"Sending relay cell to begin stream %d.",ap_conn->stream_id);

  if (connection_edge_send_command(ap_conn, circ, RELAY_COMMAND_BEGIN,
                                   payload, payload_len, ap_conn->cpath_layer) < 0)
    return -1; /* circuit is closed, don't continue */

  ap_conn->package_window = STREAMWINDOW_START;
  ap_conn->deliver_window = STREAMWINDOW_START;
  ap_conn->state = AP_CONN_STATE_CONNECT_WAIT;
  log_fn(LOG_INFO,"Address/port sent, ap socket %d, n_circ_id %d",
         ap_conn->s, circ->n_circ_id);
  control_event_stream_status(ap_conn, STREAM_EVENT_SENT_CONNECT);
  return 0;
}

/** Write a relay resolve cell, using destaddr and destport from ap_conn's
 * socks_request field, and send it down circ.
 *
 * If ap_conn is broken, mark it for close and return -1. Else return 0.
 */
int
connection_ap_handshake_send_resolve(connection_t *ap_conn, circuit_t *circ)
{
  int payload_len;
  const char *string_addr;

  tor_assert(ap_conn->type == CONN_TYPE_AP);
  tor_assert(ap_conn->state == AP_CONN_STATE_CIRCUIT_WAIT);
  tor_assert(ap_conn->socks_request);
  tor_assert(ap_conn->socks_request->command == SOCKS_COMMAND_RESOLVE);
  tor_assert(circ->purpose == CIRCUIT_PURPOSE_C_GENERAL);

  ap_conn->stream_id = get_unique_stream_id_by_circ(circ);
  if (ap_conn->stream_id==0) {
    connection_mark_unattached_ap(ap_conn, END_STREAM_REASON_INTERNAL);
    circuit_mark_for_close(circ);
    return -1;
  }

  string_addr = ap_conn->socks_request->address;
  payload_len = strlen(string_addr)+1;
  tor_assert(payload_len <= RELAY_PAYLOAD_SIZE);

  log_fn(LOG_DEBUG,"Sending relay cell to begin stream %d.",ap_conn->stream_id);

  if (connection_edge_send_command(ap_conn, circ, RELAY_COMMAND_RESOLVE,
                           string_addr, payload_len, ap_conn->cpath_layer) < 0)
    return -1; /* circuit is closed, don't continue */

  ap_conn->state = AP_CONN_STATE_RESOLVE_WAIT;
  log_fn(LOG_INFO,"Address sent for resolve, ap socket %d, n_circ_id %d",
         ap_conn->s, circ->n_circ_id);
  control_event_stream_status(ap_conn, STREAM_EVENT_SENT_RESOLVE);
  return 0;
}

/** Make an AP connection_t, do a socketpair and attach one side
 * to the conn, connection_add it, initialize it to circuit_wait,
 * and call connection_ap_handshake_attach_circuit(conn) on it.
 *
 * Return the other end of the socketpair, or -1 if error.
 */
int
connection_ap_make_bridge(char *address, uint16_t port)
{
  int fd[2];
  connection_t *conn;
  int err;

  log_fn(LOG_INFO,"Making AP bridge to %s:%d ...",safe_str(address),port);

  if ((err = tor_socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) < 0) {
    log(LOG_WARN,"Couldn't construct socketpair (%s). Network down? Delaying.",
        tor_socket_strerror(-err));
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
  strlcpy(conn->socks_request->address, address,
          sizeof(conn->socks_request->address));
  conn->socks_request->port = port;
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;

  conn->address = tor_strdup("(local bridge)");
  conn->addr = 0;
  conn->port = 0;

  if (connection_add(conn) < 0) { /* no space, forget it */
    connection_free(conn); /* this closes fd[0] */
    tor_close_socket(fd[1]);
    return -1;
  }

  conn->state = AP_CONN_STATE_CIRCUIT_WAIT;
  connection_start_reading(conn);

  /* attaching to a dirty circuit is fine */
  if (connection_ap_handshake_attach_circuit(conn) < 0) {
    connection_mark_unattached_ap(conn, END_STREAM_REASON_CANT_ATTACH);
    tor_close_socket(fd[1]);
    return -1;
  }

  log_fn(LOG_INFO,"... AP bridge created and connected.");
  return fd[1];
}

/** Send an answer to an AP connection that has requested a DNS lookup
 * via SOCKS.  The type should be one of RESOLVED_TYPE_(IPV4|IPV6) or
 * -1 for unreachable; the answer should be in the format specified
 * in the socks extensions document.
 **/
void
connection_ap_handshake_socks_resolved(connection_t *conn,
                                       int answer_type,
                                       size_t answer_len,
                                       const char *answer,
                                       int ttl)
{
  char buf[256];
  size_t replylen;

  if (answer_type == RESOLVED_TYPE_IPV4) {
    uint32_t a = ntohl(get_uint32(answer));
    if (a)
      client_dns_set_addressmap(conn->socks_request->address, a,
                                conn->chosen_exit_name, ttl);
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
  } else {
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
    } else {
      buf[1] = SOCKS5_HOST_UNREACHABLE;
      memset(buf+2, 0, 8);
      replylen = 10;
    }
  }
  connection_ap_handshake_socks_reply(conn, buf, replylen,
          (answer_type == RESOLVED_TYPE_IPV4 ||
           answer_type == RESOLVED_TYPE_IPV6) ?
                               SOCKS5_SUCCEEDED : SOCKS5_HOST_UNREACHABLE);
}

/** Send a socks reply to stream <b>conn</b>, using the appropriate
 * socks version, etc, and mark <b>conn</b> as completed with SOCKS
 * handshaking.
 *
 * If <b>reply</b> is defined, then write <b>replylen</b> bytes of it
 * to conn and return, else reply based on <b>status</b>.
 *
 * If <b>reply</b> is undefined, <b>status</b> can't be 0.
 */
void
connection_ap_handshake_socks_reply(connection_t *conn, char *reply,
                                    size_t replylen,
                                    socks5_reply_status_t status) {
  char buf[256];
  tor_assert(conn->socks_request); /* make sure it's an AP stream */

  control_event_stream_status(conn,
     status==SOCKS5_SUCCEEDED ? STREAM_EVENT_SUCCEEDED : STREAM_EVENT_FAILED);

  if (conn->socks_request->has_finished) {
    log_fn(LOG_WARN, "Harmless bug: duplicate calls to connection_ap_handshake_socks_reply.");
    return;
  }
  if (replylen) { /* we already have a reply in mind */
    connection_write_to_buf(reply, replylen, conn);
    conn->socks_request->has_finished = 1;
    return;
  }
  if (conn->socks_request->socks_version == 4) {
    memset(buf,0,SOCKS4_NETWORK_LEN);
#define SOCKS4_GRANTED          90
#define SOCKS4_REJECT           91
    buf[1] = (status==SOCKS5_SUCCEEDED ? SOCKS4_GRANTED : SOCKS4_REJECT);
    /* leave version, destport, destip zero */
    connection_write_to_buf(buf, SOCKS4_NETWORK_LEN, conn);
  } else if (conn->socks_request->socks_version == 5) {
    buf[0] = 5; /* version 5 */
    buf[1] = (char)status;
    buf[2] = 0;
    buf[3] = 1; /* ipv4 addr */
    memset(buf+4,0,6); /* Set external addr/port to 0.
                          The spec doesn't seem to say what to do here. -RD */
    connection_write_to_buf(buf,10,conn);
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
 * Return -1 if we want to tear down <b>circ</b>. Else return 0.
 */
int
connection_exit_begin_conn(cell_t *cell, circuit_t *circ)
{
  connection_t *n_stream;
  relay_header_t rh;
  char *address=NULL;
  uint16_t port;

  assert_circuit_ok(circ);
  relay_header_unpack(&rh, cell->payload);

  /* XXX currently we don't send an end cell back if we drop the
   * begin because it's malformed.
   */

  if (!memchr(cell->payload+RELAY_HEADER_SIZE, 0, rh.length)) {
    log_fn(LOG_WARN,"relay begin cell has no \\0. Dropping.");
    return 0;
  }
  if (parse_addr_port(cell->payload+RELAY_HEADER_SIZE,&address,NULL,&port)<0) {
    log_fn(LOG_WARN,"Unable to parse addr:port in relay begin cell. Dropping.");
    return 0;
  }
  if (port==0) {
    log_fn(LOG_WARN,"Missing port in relay begin cell. Dropping.");
    tor_free(address);
    return 0;
  }

  log_fn(LOG_DEBUG,"Creating new exit connection.");
  n_stream = connection_new(CONN_TYPE_EXIT);
  n_stream->purpose = EXIT_PURPOSE_CONNECT;

  n_stream->stream_id = rh.stream_id;
  n_stream->port = port;
  /* leave n_stream->s at -1, because it's not yet valid */
  n_stream->package_window = STREAMWINDOW_START;
  n_stream->deliver_window = STREAMWINDOW_START;

  if (circ->purpose == CIRCUIT_PURPOSE_S_REND_JOINED) {
    log_fn(LOG_DEBUG,"begin is for rendezvous. configuring stream.");
    n_stream->address = tor_strdup("(rendezvous)");
    n_stream->state = EXIT_CONN_STATE_CONNECTING;
    strlcpy(n_stream->rend_query, circ->rend_query,
            sizeof(n_stream->rend_query));
    tor_assert(connection_edge_is_rendezvous_stream(n_stream));
    assert_circuit_ok(circ);
    if (rend_service_set_connection_addr_port(n_stream, circ) < 0) {
      log_fn(LOG_INFO,"Didn't find rendezvous service (port %d)",n_stream->port);
      connection_edge_end(n_stream, END_STREAM_REASON_EXITPOLICY, n_stream->cpath_layer);
      connection_free(n_stream);
      circuit_mark_for_close(circ); /* knock the whole thing down, somebody screwed up */
      tor_free(address);
      return 0;
    }
    assert_circuit_ok(circ);
    log_fn(LOG_DEBUG,"Finished assigning addr/port");
    n_stream->cpath_layer = circ->cpath->prev; /* link it */

    /* add it into the linked list of n_streams on this circuit */
    n_stream->next_stream = circ->n_streams;
    n_stream->on_circuit = circ;
    circ->n_streams = n_stream;
    assert_circuit_ok(circ);

    connection_exit_connect(n_stream);
    tor_free(address);
    return 0;
  }
  tor_strlower(address);
  n_stream->address = address;
  n_stream->state = EXIT_CONN_STATE_RESOLVEFAILED;
  /* default to failed, change in dns_resolve if it turns out not to fail */

  if (we_are_hibernating()) {
    connection_edge_end(n_stream, END_STREAM_REASON_HIBERNATING, n_stream->cpath_layer);
    connection_free(n_stream);
    return 0;
  }

  /* send it off to the gethostbyname farm */
  switch (dns_resolve(n_stream)) {
    case 1: /* resolve worked */

      /* add it into the linked list of n_streams on this circuit */
      n_stream->next_stream = circ->n_streams;
      n_stream->on_circuit = circ;
      circ->n_streams = n_stream;
      assert_circuit_ok(circ);

      connection_exit_connect(n_stream);
      return 0;
    case -1: /* resolve failed */
      /* n_stream got freed. don't touch it. */
      break;
    case 0: /* resolve added to pending list */
      /* add it into the linked list of resolving_streams on this circuit */
      n_stream->next_stream = circ->resolving_streams;
      n_stream->on_circuit = circ;
      circ->resolving_streams = n_stream;
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
connection_exit_begin_resolve(cell_t *cell, circuit_t *circ)
{
  connection_t *dummy_conn;
  relay_header_t rh;

  assert_circuit_ok(circ);
  relay_header_unpack(&rh, cell->payload);

  /* This 'dummy_conn' only exists to remember the stream ID
   * associated with the resolve request; and to make the
   * implementation of dns.c more uniform.  (We really only need to
   * remember the circuit, the stream ID, and the hostname to be
   * resolved; but if we didn't store them in a connection like this,
   * the housekeeping in dns.c would get way more complicated.)
   */
  dummy_conn = connection_new(CONN_TYPE_EXIT);
  dummy_conn->stream_id = rh.stream_id;
  dummy_conn->address = tor_strndup(cell->payload+RELAY_HEADER_SIZE,
                                    rh.length);
  dummy_conn->port = 0;
  dummy_conn->state = EXIT_CONN_STATE_RESOLVEFAILED;
  dummy_conn->purpose = EXIT_PURPOSE_RESOLVE;

  /* send it off to the gethostbyname farm */
  switch (dns_resolve(dummy_conn)) {
    case -1: /* Impossible to resolve; a resolved cell was sent. */
      /* Connection freed; don't touch it. */
      return 0;
    case 1: /* The result was cached; a resolved cell was sent. */
      if (!dummy_conn->marked_for_close)
        connection_free(dummy_conn);
      return 0;
    case 0: /* resolve added to pending list */
      dummy_conn->next_stream = circ->resolving_streams;
      dummy_conn->on_circuit = circ;
      circ->resolving_streams = dummy_conn;
      assert_circuit_ok(circ);
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
connection_exit_connect(connection_t *conn)
{
  uint32_t addr;
  uint16_t port;

  if (!connection_edge_is_rendezvous_stream(conn) &&
      router_compare_to_my_exit_policy(conn)) {
    log_fn(LOG_INFO,"%s:%d failed exit policy. Closing.",
           safe_str(conn->address), conn->port);
    connection_edge_end(conn, END_STREAM_REASON_EXITPOLICY, conn->cpath_layer);
    circuit_detach_stream(circuit_get_by_edge_conn(conn), conn);
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
          log_fn(LOG_DEBUG, "Redirecting connection from %s:%d to %s:%d",
                 safe_str(conn->address), conn->port, safe_str(tmpbuf), port);
        }
        break;
      }
    });
  }

  log_fn(LOG_DEBUG,"about to try connecting");
  switch (connection_connect(conn, conn->address, addr, port)) {
    case -1:
      connection_edge_end_errno(conn, conn->cpath_layer);
      circuit_detach_stream(circuit_get_by_edge_conn(conn), conn);
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
  if (connection_wants_to_flush(conn)) { /* in case there are any queued data cells */
    log_fn(LOG_WARN,"Bug: newly connected conn had data waiting!");
//    connection_start_writing(conn);
  }
  connection_watch_events(conn, EV_READ);

  /* also, deliver a 'connected' cell back through the circuit. */
  if (connection_edge_is_rendezvous_stream(conn)) { /* rendezvous stream */
    /* don't send an address back! */
    connection_edge_send_command(conn, circuit_get_by_edge_conn(conn),
                                 RELAY_COMMAND_CONNECTED,
                                 NULL, 0, conn->cpath_layer);
  } else { /* normal stream */
    /* This must be the original address, not the redirected address. */
    char connected_payload[8];
    set_uint32(connected_payload, htonl(conn->addr));
    set_uint32(connected_payload+4,
               htonl(MAX_DNS_ENTRY_AGE)); /* XXXX fill with a real TTL */
    connection_edge_send_command(conn, circuit_get_by_edge_conn(conn),
                                 RELAY_COMMAND_CONNECTED,
                                 connected_payload, 8, conn->cpath_layer);
  }
}

/** Return 1 if <b>conn</b> is a rendezvous stream, or 0 if
 * it is a general stream.
 */
int
connection_edge_is_rendezvous_stream(connection_t *conn)
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
connection_ap_can_use_exit(connection_t *conn, routerinfo_t *exit)
{
  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_AP);
  tor_assert(conn->socks_request);
  tor_assert(exit);

#if 0
  log_fn(LOG_DEBUG,"considering nickname %s, for address %s / port %d:",
         exit->nickname, safe_str(conn->socks_request->address),
         conn->socks_request->port);
#endif

  /* If a particular exit node has been requested for the new connection,
   * make sure the exit node of the existing circuit matches exactly.
   */
  if (conn->chosen_exit_name) {
    if (router_get_by_nickname(conn->chosen_exit_name, 1) != exit) {
      /* doesn't match */
      log_fn(LOG_DEBUG,"Requested node '%s', considering node '%s'. No.",
             conn->chosen_exit_name, exit->nickname);
      return 0;
    }
  }

  if (conn->socks_request->command != SOCKS_COMMAND_RESOLVE) {
    struct in_addr in;
    uint32_t addr = 0;
    addr_policy_result_t r;
    if (tor_inet_aton(conn->socks_request->address, &in))
      addr = ntohl(in.s_addr);
    r = router_compare_addr_to_addr_policy(addr, conn->socks_request->port,
                                           exit->exit_policy);
    if (r == ADDR_POLICY_REJECTED || r == ADDR_POLICY_PROBABLY_REJECTED)
      return 0;
  }
  return 1;
}

/** A helper function for socks_policy_permits_address() below.
 *
 * Parse options->SocksPolicy in the same way that the exit policy
 * is parsed, and put the processed version in &socks_policy.
 * Ignore port specifiers.
 */
void
parse_socks_policy(void)
{
  addr_policy_t *n;
  if (socks_policy) {
    addr_policy_free(socks_policy);
    socks_policy = NULL;
  }
  config_parse_addr_policy(get_options()->SocksPolicy, &socks_policy, -1);
  /* ports aren't used. */
  for (n=socks_policy; n; n = n->next) {
    n->prt_min = 1;
    n->prt_max = 65535;
  }
}

/** Free all storage held by our SOCKS allow policy
 */
void
free_socks_policy(void)
{
  addr_policy_free(socks_policy);
  socks_policy = NULL;
}

/** Return 1 if <b>addr</b> is permitted to connect to our socks port,
 * based on <b>socks_policy</b>. Else return 0.
 */
int
socks_policy_permits_address(uint32_t addr)
{
  int a;

  if (!socks_policy) /* 'no socks policy' means 'accept' */
    return 1;
  a = router_compare_addr_to_addr_policy(addr, 1, socks_policy);
  if (a==ADDR_POLICY_REJECTED)
    return 0;
  else if (a==ADDR_POLICY_ACCEPTED)
    return 1;
  log_fn(LOG_WARN, "Bug: Got unexpected 'maybe' answer from socks policy");
  return 0;
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
 *     Put a \code{'\0'} after y, lower-case it, and return ONION_HOSTNAME.
 *
 * If address is of the form "y.exit":
 *     Put a \code{'\0'} after y and return EXIT_HOSTNAME.
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
    if (!s) return 0; /* no dot, thus normal */
    if (!strcmp(s+1,"exit")) {
      *s = 0; /* null-terminate it */
      return EXIT_HOSTNAME; /* .exit */
    }
    if (strcmp(s+1,"onion"))
      return NORMAL_HOSTNAME; /* neither .exit nor .onion, thus normal */

    /* so it is .onion */
    *s = 0; /* null-terminate it */
    if (strlcpy(query, address, REND_SERVICE_ID_LEN+1) >= REND_SERVICE_ID_LEN+1)
      goto failed;
    if (rend_valid_service_id(query)) {
      return ONION_HOSTNAME; /* success */
    }
failed:
    /* otherwise, return to previous state and return 0 */
    *s = '.';
    return BAD_HOSTNAME;
}

