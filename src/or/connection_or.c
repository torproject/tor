/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file connection_or.c
 * \brief Functions to handle OR connections, TLS handshaking, and
 * cells on the network.
 **/

#include "or.h"
#include "buffers.h"
#include "circuitbuild.h"
#include "command.h"
#include "config.h"
#include "connection.h"
#include "connection_or.h"
#include "control.h"
#include "dirserv.h"
#include "geoip.h"
#include "main.h"
#include "networkstatus.h"
#include "reasons.h"
#include "relay.h"
#include "rephist.h"
#include "router.h"
#include "routerlist.h"

static int connection_tls_finish_handshake(or_connection_t *conn);
static int connection_or_process_cells_from_inbuf(or_connection_t *conn);
static int connection_or_send_versions(or_connection_t *conn);
static int connection_init_or_handshake_state(or_connection_t *conn,
                                              int started_here);
static int connection_or_check_valid_tls_handshake(or_connection_t *conn,
                                                   int started_here,
                                                   char *digest_rcvd_out);

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
      log_warn(LD_BUG, "Didn't find connection '%s' on identity map when "
               "trying to remove it.",
               conn->nickname ? conn->nickname : "NULL");
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
  smartlist_t *conns = get_connection_array();
  SMARTLIST_FOREACH(conns, connection_t *, conn,
  {
    if (conn->type == CONN_TYPE_OR) {
      or_connection_t *or_conn = TO_OR_CONN(conn);
      memset(or_conn->identity_digest, 0, DIGEST_LEN);
      or_conn->next_with_same_id = NULL;
    }
  });

  digestmap_free(orconn_identity_map, NULL);
  orconn_identity_map = NULL;
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
 *
 * Note that this function doesn't touch <b>dst</b>-\>next: the caller
 * should set it or clear it as appropriate.
 */
void
cell_pack(packed_cell_t *dst, const cell_t *src)
{
  char *dest = dst->body;
  set_uint16(dest, htons(src->circ_id));
  *(uint8_t*)(dest+2) = src->command;
  memcpy(dest+3, src->payload, CELL_PAYLOAD_SIZE);
}

/** Unpack the network-order buffer <b>src</b> into a host-order
 * cell_t structure <b>dest</b>.
 */
static void
cell_unpack(cell_t *dest, const char *src)
{
  dest->circ_id = ntohs(get_uint16(src));
  dest->command = *(uint8_t*)(src+2);
  memcpy(dest->payload, src+3, CELL_PAYLOAD_SIZE);
}

/** Write the header of <b>cell</b> into the first VAR_CELL_HEADER_SIZE
 * bytes of <b>hdr_out</b>. */
void
var_cell_pack_header(const var_cell_t *cell, char *hdr_out)
{
  set_uint16(hdr_out, htons(cell->circ_id));
  set_uint8(hdr_out+2, cell->command);
  set_uint16(hdr_out+3, htons(cell->payload_len));
}

/** Allocate and return a new var_cell_t with <b>payload_len</b> bytes of
 * payload space. */
var_cell_t *
var_cell_new(uint16_t payload_len)
{
  var_cell_t *cell = tor_malloc(sizeof(var_cell_t)+payload_len-1);
  cell->payload_len = payload_len;
  cell->command = 0;
  cell->circ_id = 0;
  return cell;
}

/** Release all space held by <b>cell</b>. */
void
var_cell_free(var_cell_t *cell)
{
  tor_free(cell);
}

/** We've received an EOF from <b>conn</b>. Mark it for close and return. */
int
connection_or_reached_eof(or_connection_t *conn)
{
  log_info(LD_OR,"OR connection reached EOF. Closing.");
  connection_mark_for_close(TO_CONN(conn));
  return 0;
}

/** Handle any new bytes that have come in on connection <b>conn</b>.
 * If conn is in 'open' state, hand it to
 * connection_or_process_cells_from_inbuf()
 * (else do nothing).
 */
int
connection_or_process_inbuf(or_connection_t *conn)
{
  int ret;
  tor_assert(conn);

  switch (conn->_base.state) {
    case OR_CONN_STATE_PROXY_HANDSHAKING:
      ret = connection_read_proxy_handshake(TO_CONN(conn));

      /* start TLS after handshake completion, or deal with error */
      if (ret == 1) {
        tor_assert(TO_CONN(conn)->proxy_state == PROXY_CONNECTED);
        if (connection_tls_start_handshake(conn, 0) < 0)
          ret = -1;
      }
      if (ret < 0) {
        connection_mark_for_close(TO_CONN(conn));
      }

      return ret;
    case OR_CONN_STATE_OPEN:
    case OR_CONN_STATE_OR_HANDSHAKING:
      return connection_or_process_cells_from_inbuf(conn);
    default:
      return 0; /* don't do anything */
  }
}

/** When adding cells to an OR connection's outbuf, keep adding until the
 * outbuf is at least this long, or we run out of cells. */
#define OR_CONN_HIGHWATER (32*1024)

/** Add cells to an OR connection's outbuf whenever the outbuf's data length
 * drops below this size. */
#define OR_CONN_LOWWATER (16*1024)

/** Called whenever we have flushed some data on an or_conn: add more data
 * from active circuits. */
int
connection_or_flushed_some(or_connection_t *conn)
{
  size_t datalen = buf_datalen(conn->_base.outbuf);
  /* If we're under the low water mark, add cells until we're just over the
   * high water mark. */
  if (datalen < OR_CONN_LOWWATER) {
    ssize_t n = CEIL_DIV(OR_CONN_HIGHWATER - datalen, CELL_NETWORK_SIZE);
    time_t now = approx_time();
    while (conn->active_circuits && n > 0) {
      int flushed;
      flushed = connection_or_flush_from_first_active_circuit(conn, 1, now);
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
    case OR_CONN_STATE_PROXY_HANDSHAKING:
    case OR_CONN_STATE_OPEN:
    case OR_CONN_STATE_OR_HANDSHAKING:
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
  int proxy_type;
  connection_t *conn;
  tor_assert(or_conn);
  conn = TO_CONN(or_conn);
  tor_assert(conn->state == OR_CONN_STATE_CONNECTING);

  log_debug(LD_HANDSHAKE,"OR connect() to router at %s:%u finished.",
            conn->address,conn->port);
  control_event_bootstrap(BOOTSTRAP_STATUS_HANDSHAKE, 0);

  proxy_type = PROXY_NONE;

  if (get_options()->HTTPSProxy)
    proxy_type = PROXY_CONNECT;
  else if (get_options()->Socks4Proxy)
    proxy_type = PROXY_SOCKS4;
  else if (get_options()->Socks5Proxy)
    proxy_type = PROXY_SOCKS5;

  if (proxy_type != PROXY_NONE) {
    /* start proxy handshake */
    if (connection_proxy_connect(conn, proxy_type) < 0) {
      connection_mark_for_close(conn);
      return -1;
    }

    connection_start_reading(conn);
    conn->state = OR_CONN_STATE_PROXY_HANDSHAKING;
    return 0;
  }

  if (connection_tls_start_handshake(or_conn, 0) < 0) {
    /* TLS handshaking error of some kind. */
    connection_mark_for_close(conn);
    return -1;
  }
  return 0;
}

/** Return 1 if identity digest <b>id_digest</b> is known to be a
 * currently or recently running relay. Otherwise return 0. */
int
connection_or_digest_is_known_relay(const char *id_digest)
{
  if (router_get_consensus_status_by_id(id_digest))
    return 1; /* It's in the consensus: "yes" */
  if (router_get_by_digest(id_digest))
    return 1; /* Not in the consensus, but we have a descriptor for
               * it. Probably it was in a recent consensus. "Yes". */
  return 0;
}

/** Set the per-conn read and write limits for <b>conn</b>. If it's a known
 * relay, we will rely on the global read and write buckets, so give it
 * per-conn limits that are big enough they'll never matter. But if it's
 * not a known relay, first check if we set PerConnBwRate/Burst, then
 * check if the consensus sets them, else default to 'big enough'.
 */
static void
connection_or_update_token_buckets_helper(or_connection_t *conn, int reset,
                                          or_options_t *options)
{
  int rate, burst; /* per-connection rate limiting params */
  if (connection_or_digest_is_known_relay(conn->identity_digest)) {
    /* It's in the consensus, or we have a descriptor for it meaning it
     * was probably in a recent consensus. It's a recognized relay:
     * give it full bandwidth. */
    rate = (int)options->BandwidthRate;
    burst = (int)options->BandwidthBurst;
  } else {
    /* Not a recognized relay. Squeeze it down based on the suggested
     * bandwidth parameters in the consensus, but allow local config
     * options to override. */
    rate = options->PerConnBWRate ? (int)options->PerConnBWRate :
        (int)networkstatus_get_param(NULL, "perconnbwrate",
                                     (int)options->BandwidthRate);
    burst = options->PerConnBWBurst ? (int)options->PerConnBWBurst :
        (int)networkstatus_get_param(NULL, "perconnbwburst",
                                     (int)options->BandwidthBurst);
  }

  conn->bandwidthrate = rate;
  conn->bandwidthburst = burst;
  if (reset) { /* set up the token buckets to be full */
    conn->read_bucket = conn->write_bucket = burst;
    return;
  }
  /* If the new token bucket is smaller, take out the extra tokens.
   * (If it's larger, don't -- the buckets can grow to reach the cap.) */
  if (conn->read_bucket > burst)
    conn->read_bucket = burst;
  if (conn->write_bucket > burst)
    conn->write_bucket = burst;
}

/** Either our set of relays or our per-conn rate limits have changed.
 * Go through all the OR connections and update their token buckets. */
void
connection_or_update_token_buckets(smartlist_t *conns, or_options_t *options)
{
  SMARTLIST_FOREACH(conns, connection_t *, conn,
  {
    if (connection_speaks_cells(conn))
      connection_or_update_token_buckets_helper(TO_OR_CONN(conn), 0, options);
  });
}

/** If we don't necessarily know the router we're connecting to, but we
 * have an addr/port/id_digest, then fill in as much as we can. Start
 * by checking to see if this describes a router we know. */
static void
connection_or_init_conn_from_address(or_connection_t *conn,
                                     const tor_addr_t *addr, uint16_t port,
                                     const char *id_digest,
                                     int started_here)
{
  routerinfo_t *r = router_get_by_digest(id_digest);
  connection_or_set_identity_digest(conn, id_digest);
  connection_or_update_token_buckets_helper(conn, 1, get_options());

  conn->_base.port = port;
  tor_addr_copy(&conn->_base.addr, addr);
  tor_addr_copy(&conn->real_addr, addr);
  if (r) {
    /* XXXX proposal 118 will make this more complex. */
    if (tor_addr_eq_ipv4h(&conn->_base.addr, r->addr))
      conn->is_canonical = 1;
    if (!started_here) {
      /* Override the addr/port, so our log messages will make sense.
       * This is dangerous, since if we ever try looking up a conn by
       * its actual addr/port, we won't remember. Careful! */
      /* XXXX arma: this is stupid, and it's the reason we need real_addr
       * to track is_canonical properly.  What requires it? */
      /* XXXX <arma> i believe the reason we did this, originally, is because
       * we wanted to log what OR a connection was to, and if we logged the
       * right IP address and port 56244, that wouldn't be as helpful. now we
       * log the "right" port too, so we know if it's moria1 or moria2.
       */
      tor_addr_from_ipv4h(&conn->_base.addr, r->addr);
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

/** Return true iff <b>a</b> is "better" than <b>b</b> for new circuits.
 *
 * A more canonical connection is always better than a less canonical
 * connection.  That aside, a connection is better if it has circuits and the
 * other does not, or if it was created more recently.
 *
 * Requires that both input connections are open; not is_bad_for_new_circs,
 * and not impossibly non-canonical.
 *
 * If </b>forgive_new_connections</b> is true, then we do not call
 * <b>a</b>better than <b>b</b> simply because b has no circuits,
 * unless b is also relatively old.
 */
static int
connection_or_is_better(time_t now,
                        const or_connection_t *a,
                        const or_connection_t *b,
                        int forgive_new_connections)
{
  int newer;
/** Do not definitively deprecate a new connection with no circuits on it
 * until this much time has passed. */
#define NEW_CONN_GRACE_PERIOD (15*60)

  if (b->is_canonical && !a->is_canonical)
    return 0; /* A canonical connection is better than a non-canonical
               * one, no matter how new it is or which has circuits. */

  newer = b->_base.timestamp_created < a->_base.timestamp_created;

  if (
      /* We prefer canonical connections regardless of newness. */
      (!b->is_canonical && a->is_canonical) ||
      /* If both have circuits we prefer the newer: */
      (b->n_circuits && a->n_circuits && newer) ||
      /* If neither has circuits we prefer the newer: */
      (!b->n_circuits && !a->n_circuits && newer))
    return 1;

  /* If one has no circuits and the other does... */
  if (!b->n_circuits && a->n_circuits) {
    /* Then it's bad, unless it's in its grace period and we're forgiving. */
    if (forgive_new_connections &&
        now < b->_base.timestamp_created + NEW_CONN_GRACE_PERIOD)
      return 0;
    else
      return 1;
  }

  return 0;
}

/** Return the OR connection we should use to extend a circuit to the router
 * whose identity is <b>digest</b>, and whose address we believe (or have been
 * told in an extend cell) is <b>target_addr</b>.  If there is no good
 * connection, set *<b>msg_out</b> to a message describing the connection's
 * state and our next action, and set <b>launch_out</b> to a boolean for
 * whether we should launch a new connection or not.
 */
or_connection_t *
connection_or_get_for_extend(const char *digest,
                             const tor_addr_t *target_addr,
                             const char **msg_out,
                             int *launch_out)
{
  or_connection_t *conn, *best=NULL;
  int n_inprogress_goodaddr = 0, n_old = 0, n_noncanonical = 0, n_possible = 0;
  time_t now = approx_time();

  tor_assert(msg_out);
  tor_assert(launch_out);

  if (!orconn_identity_map) {
    *msg_out = "Router not connected (nothing is).  Connecting.";
    *launch_out = 1;
    return NULL;
  }

  conn = digestmap_get(orconn_identity_map, digest);

  for (; conn; conn = conn->next_with_same_id) {
    tor_assert(conn->_base.magic == OR_CONNECTION_MAGIC);
    tor_assert(conn->_base.type == CONN_TYPE_OR);
    tor_assert(!memcmp(conn->identity_digest, digest, DIGEST_LEN));
    if (conn->_base.marked_for_close)
      continue;
    /* Never return a non-open connection. */
    if (conn->_base.state != OR_CONN_STATE_OPEN) {
      /* If the address matches, don't launch a new connection for this
       * circuit. */
      if (!tor_addr_compare(&conn->real_addr, target_addr, CMP_EXACT))
        ++n_inprogress_goodaddr;
      continue;
    }
    /* Never return a connection that shouldn't be used for circs. */
    if (conn->is_bad_for_new_circs) {
      ++n_old;
      continue;
    }
    /* Never return a non-canonical connection using a recent link protocol
     * if the address is not what we wanted.
     *
     * (For old link protocols, we can't rely on is_canonical getting
     * set properly if we're talking to the right address, since we might
     * have an out-of-date descriptor, and we will get no NETINFO cell to
     * tell us about the right address.) */
    if (!conn->is_canonical && conn->link_proto >= 2 &&
        tor_addr_compare(&conn->real_addr, target_addr, CMP_EXACT)) {
      ++n_noncanonical;
      continue;
    }

    ++n_possible;

    if (!best) {
      best = conn; /* If we have no 'best' so far, this one is good enough. */
      continue;
    }

    if (connection_or_is_better(now, conn, best, 0))
      best = conn;
  }

  if (best) {
    *msg_out = "Connection is fine; using it.";
    *launch_out = 0;
    return best;
  } else if (n_inprogress_goodaddr) {
    *msg_out = "Connection in progress; waiting.";
    *launch_out = 0;
    return NULL;
  } else if (n_old || n_noncanonical) {
    *msg_out = "Connections all too old, or too non-canonical. "
      " Launching a new one.";
    *launch_out = 1;
    return NULL;
  } else {
    *msg_out = "Not connected. Connecting.";
    *launch_out = 1;
    return NULL;
  }
}

/** How old do we let a connection to an OR get before deciding it's
 * too old for new circuits? */
#define TIME_BEFORE_OR_CONN_IS_TOO_OLD (60*60*24*7)

/** Given the head of the linked list for all the or_connections with a given
 * identity, set elements of that list as is_bad_for_new_circs as
 * appropriate. Helper for connection_or_set_bad_connections().
 *
 * Specifically, we set the is_bad_for_new_circs flag on:
 *    - all connections if <b>force</b> is true.
 *    - all connections that are too old.
 *    - all open non-canonical connections for which a canonical connection
 *      exists to the same router.
 *    - all open canonical connections for which a 'better' canonical
 *      connection exists to the same router.
 *    - all open non-canonical connections for which a 'better' non-canonical
 *      connection exists to the same router at the same address.
 *
 * See connection_or_is_better() for our idea of what makes one OR connection
 * better than another.
 */
static void
connection_or_group_set_badness(or_connection_t *head, int force)
{
  or_connection_t *or_conn = NULL, *best = NULL;
  int n_old = 0, n_inprogress = 0, n_canonical = 0, n_other = 0;
  time_t now = time(NULL);

  /* Pass 1: expire everything that's old, and see what the status of
   * everything else is. */
  for (or_conn = head; or_conn; or_conn = or_conn->next_with_same_id) {
    if (or_conn->_base.marked_for_close ||
        or_conn->is_bad_for_new_circs)
      continue;
    if (force ||
        or_conn->_base.timestamp_created + TIME_BEFORE_OR_CONN_IS_TOO_OLD
          < now) {
      log_info(LD_OR,
               "Marking OR conn to %s:%d as too old for new circuits "
               "(fd %d, %d secs old).",
               or_conn->_base.address, or_conn->_base.port, or_conn->_base.s,
               (int)(now - or_conn->_base.timestamp_created));
      or_conn->is_bad_for_new_circs = 1;
    }

    if (or_conn->is_bad_for_new_circs) {
      ++n_old;
    } else if (or_conn->_base.state != OR_CONN_STATE_OPEN) {
      ++n_inprogress;
    } else if (or_conn->is_canonical) {
      ++n_canonical;
    } else {
      ++n_other;
    }
  }

  /* Pass 2: We know how about how good the best connection is.
   * expire everything that's worse, and find the very best if we can. */
  for (or_conn = head; or_conn; or_conn = or_conn->next_with_same_id) {
    if (or_conn->_base.marked_for_close ||
        or_conn->is_bad_for_new_circs)
      continue; /* This one doesn't need to be marked bad. */
    if (or_conn->_base.state != OR_CONN_STATE_OPEN)
      continue; /* Don't mark anything bad until we have seen what happens
                 * when the connection finishes. */
    if (n_canonical && !or_conn->is_canonical) {
      /* We have at least one open canonical connection to this router,
       * and this one is open but not canonical.  Mark it bad. */
      log_info(LD_OR,
               "Marking OR conn to %s:%d as unsuitable for new circuits: "
               "(fd %d, %d secs old).  It is not canonical, and we have "
               "another connection to that OR that is.",
               or_conn->_base.address, or_conn->_base.port, or_conn->_base.s,
               (int)(now - or_conn->_base.timestamp_created));
      or_conn->is_bad_for_new_circs = 1;
      continue;
    }

    if (!best || connection_or_is_better(now, or_conn, best, 0))
      best = or_conn;
  }

  if (!best)
    return;

  /* Pass 3: One connection to OR is best.  If it's canonical, mark as bad
   * every other open connection.  If it's non-canonical, mark as bad
   * every other open connection to the same address.
   *
   * XXXX This isn't optimal; if we have connections to an OR at multiple
   *   addresses, we'd like to pick the best _for each address_, and mark as
   *   bad every open connection that isn't best for its address.  But this
   *   can only occur in cases where the other OR is old (so we have no
   *   canonical connection to it), or where all the connections to the OR are
   *   at noncanonical addresses and we have no good direct connection (which
   *   means we aren't at risk of attaching circuits to it anyway).  As
   *   0.1.2.x dies out, the first case will go away, and the second one is
   *   "mostly harmless", so a fix can wait until somebody is bored.
   */
  for (or_conn = head; or_conn; or_conn = or_conn->next_with_same_id) {
    if (or_conn->_base.marked_for_close ||
        or_conn->is_bad_for_new_circs ||
        or_conn->_base.state != OR_CONN_STATE_OPEN)
      continue;
    if (or_conn != best && connection_or_is_better(now, best, or_conn, 1)) {
      /* This isn't the best conn, _and_ the best conn is better than it,
         even when we're being forgiving. */
      if (best->is_canonical) {
        log_info(LD_OR,
                 "Marking OR conn to %s:%d as unsuitable for new circuits: "
                 "(fd %d, %d secs old).  We have a better canonical one "
                 "(fd %d; %d secs old).",
                 or_conn->_base.address, or_conn->_base.port, or_conn->_base.s,
                 (int)(now - or_conn->_base.timestamp_created),
                 best->_base.s, (int)(now - best->_base.timestamp_created));
        or_conn->is_bad_for_new_circs = 1;
      } else if (!tor_addr_compare(&or_conn->real_addr,
                                   &best->real_addr, CMP_EXACT)) {
        log_info(LD_OR,
                 "Marking OR conn to %s:%d as unsuitable for new circuits: "
                 "(fd %d, %d secs old).  We have a better one with the "
                 "same address (fd %d; %d secs old).",
                 or_conn->_base.address, or_conn->_base.port, or_conn->_base.s,
                 (int)(now - or_conn->_base.timestamp_created),
                 best->_base.s, (int)(now - best->_base.timestamp_created));
        or_conn->is_bad_for_new_circs = 1;
      }
    }
  }
}

/** Go through all the OR connections (or if <b>digest</b> is non-NULL, just
 * the OR connections with that digest), and set the is_bad_for_new_circs
 * flag based on the rules in connection_or_group_set_badness() (or just
 * always set it if <b>force</b> is true).
 */
void
connection_or_set_bad_connections(const char *digest, int force)
{
  if (!orconn_identity_map)
    return;

  DIGESTMAP_FOREACH(orconn_identity_map, identity, or_connection_t *, conn) {
    if (!digest || !memcmp(digest, conn->identity_digest, DIGEST_LEN))
      connection_or_group_set_badness(conn, force);
  } DIGESTMAP_FOREACH_END;
}

/** <b>conn</b> is in the 'connecting' state, and it failed to complete
 * a TCP connection. Send notifications appropriately.
 *
 * <b>reason</b> specifies the or_conn_end_reason for the failure;
 * <b>msg</b> specifies the strerror-style error message.
 */
void
connection_or_connect_failed(or_connection_t *conn,
                             int reason, const char *msg)
{
  control_event_or_conn_status(conn, OR_CONN_EVENT_FAILED, reason);
  if (!authdir_mode_tests_reachability(get_options()))
    control_event_bootstrap_problem(msg, reason);
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
connection_or_connect(const tor_addr_t *_addr, uint16_t port,
                      const char *id_digest)
{
  or_connection_t *conn;
  or_options_t *options = get_options();
  int socket_error = 0;
  int using_proxy = 0;
  tor_addr_t addr;

  tor_assert(_addr);
  tor_assert(id_digest);
  tor_addr_copy(&addr, _addr);

  if (server_mode(options) && router_digest_is_me(id_digest)) {
    log_info(LD_PROTOCOL,"Client asked me to connect to myself. Refusing.");
    return NULL;
  }

  conn = or_connection_new(AF_INET);

  /* set up conn so it's got all the data we need to remember */
  connection_or_init_conn_from_address(conn, &addr, port, id_digest, 1);
  conn->_base.state = OR_CONN_STATE_CONNECTING;
  control_event_or_conn_status(conn, OR_CONN_EVENT_LAUNCHED, 0);

  /* use a proxy server if available */
  if (options->HTTPSProxy) {
    using_proxy = 1;
    tor_addr_copy(&addr, &options->HTTPSProxyAddr);
    port = options->HTTPSProxyPort;
  } else if (options->Socks4Proxy) {
    using_proxy = 1;
    tor_addr_copy(&addr, &options->Socks4ProxyAddr);
    port = options->Socks4ProxyPort;
  } else if (options->Socks5Proxy) {
    using_proxy = 1;
    tor_addr_copy(&addr, &options->Socks5ProxyAddr);
    port = options->Socks5ProxyPort;
  }

  switch (connection_connect(TO_CONN(conn), conn->_base.address,
                             &addr, port, &socket_error)) {
    case -1:
      /* If the connection failed immediately, and we're using
       * a proxy, our proxy is down. Don't blame the Tor server. */
      if (!using_proxy)
        entry_guard_register_connect_status(conn->identity_digest,
                                            0, 1, time(NULL));
      connection_or_connect_failed(conn,
                                   errno_to_orconn_end_reason(socket_error),
                                   tor_socket_strerror(socket_error));
      connection_free(TO_CONN(conn));
      return NULL;
    case 0:
      connection_watch_events(TO_CONN(conn), READ_EVENT | WRITE_EVENT);
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
  conn->_base.state = OR_CONN_STATE_TLS_HANDSHAKING;
  conn->tls = tor_tls_new(conn->_base.s, receiving);
  tor_tls_set_logged_address(conn->tls, // XXX client and relay?
      escaped_safe_str(conn->_base.address));
  if (!conn->tls) {
    log_warn(LD_BUG,"tor_tls_new failed. Closing.");
    return -1;
  }
  connection_start_reading(TO_CONN(conn));
  log_debug(LD_HANDSHAKE,"starting TLS handshake on fd %d", conn->_base.s);
  note_crypto_pk_op(receiving ? TLS_HANDSHAKE_S : TLS_HANDSHAKE_C);

  if (connection_tls_continue_handshake(conn) < 0) {
    return -1;
  }
  return 0;
}

/** Invoked on the server side from inside tor_tls_read() when the server
 * gets a successful TLS renegotiation from the client. */
static void
connection_or_tls_renegotiated_cb(tor_tls_t *tls, void *_conn)
{
  or_connection_t *conn = _conn;
  (void)tls;

  /* Don't invoke this again. */
  tor_tls_set_renegotiate_callback(tls, NULL, NULL);
  tor_tls_block_renegotiation(tls);

  if (connection_tls_finish_handshake(conn) < 0) {
    /* XXXX_TLS double-check that it's ok to do this from inside read. */
    /* XXXX_TLS double-check that this verifies certificates. */
    connection_mark_for_close(TO_CONN(conn));
  }
}

/** Move forward with the tls handshake. If it finishes, hand
 * <b>conn</b> to connection_tls_finish_handshake().
 *
 * Return -1 if <b>conn</b> is broken, else return 0.
 */
int
connection_tls_continue_handshake(or_connection_t *conn)
{
  int result;
  check_no_tls_errors();
 again:
  if (conn->_base.state == OR_CONN_STATE_TLS_CLIENT_RENEGOTIATING) {
    // log_notice(LD_OR, "Renegotiate with %p", conn->tls);
    result = tor_tls_renegotiate(conn->tls);
    // log_notice(LD_OR, "Result: %d", result);
  } else {
    tor_assert(conn->_base.state == OR_CONN_STATE_TLS_HANDSHAKING);
    // log_notice(LD_OR, "Continue handshake with %p", conn->tls);
    result = tor_tls_handshake(conn->tls);
    // log_notice(LD_OR, "Result: %d", result);
  }
  switch (result) {
    CASE_TOR_TLS_ERROR_ANY:
    log_info(LD_OR,"tls error [%s]. breaking connection.",
             tor_tls_err_to_string(result));
      return -1;
    case TOR_TLS_DONE:
      if (! tor_tls_used_v1_handshake(conn->tls)) {
        if (!tor_tls_is_server(conn->tls)) {
          if (conn->_base.state == OR_CONN_STATE_TLS_HANDSHAKING) {
            // log_notice(LD_OR,"Done. state was TLS_HANDSHAKING.");
            conn->_base.state = OR_CONN_STATE_TLS_CLIENT_RENEGOTIATING;
            goto again;
          }
          // log_notice(LD_OR,"Done. state was %d.", conn->_base.state);
        } else {
          /* improved handshake, but not a client. */
          tor_tls_set_renegotiate_callback(conn->tls,
                                           connection_or_tls_renegotiated_cb,
                                           conn);
          conn->_base.state = OR_CONN_STATE_TLS_SERVER_RENEGOTIATING;
          connection_stop_writing(TO_CONN(conn));
          connection_start_reading(TO_CONN(conn));
          return 0;
        }
      }
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
  if (conn->handshake_state)
    return conn->handshake_state->started_here;
  return !tor_tls_is_server(conn->tls);
}

/** <b>Conn</b> just completed its handshake. Return 0 if all is well, and
 * return -1 if he is lying, broken, or otherwise something is wrong.
 *
 * If we initiated this connection (<b>started_here</b> is true), make sure
 * the other side sent a correctly formed certificate. If I initiated the
 * connection, make sure it's the right guy.
 *
 * Otherwise (if we _didn't_ initiate this connection), it's okay for
 * the certificate to be weird or absent.
 *
 * If we return 0, and the certificate is as expected, write a hash of the
 * identity key into <b>digest_rcvd_out</b>, which must have DIGEST_LEN
 * space in it.
 * If the certificate is invalid or missing on an incoming connection,
 * we return 0 and set <b>digest_rcvd_out</b> to DIGEST_LEN NUL bytes.
 * (If we return -1, the contents of this buffer are undefined.)
 *
 * As side effects,
 * 1) Set conn->circ_id_type according to tor-spec.txt.
 * 2) If we're an authdirserver and we initiated the connection: drop all
 *    descriptors that claim to be on that IP/port but that aren't
 *    this guy; and note that this guy is reachable.
 * 3) If this is a bridge and we didn't configure its identity
 *    fingerprint, remember the keyid we just learned.
 */
static int
connection_or_check_valid_tls_handshake(or_connection_t *conn,
                                        int started_here,
                                        char *digest_rcvd_out)
{
  crypto_pk_env_t *identity_rcvd=NULL;
  or_options_t *options = get_options();
  int severity = server_mode(options) ? LOG_PROTOCOL_WARN : LOG_WARN;
  const char *safe_address =
    started_here ? conn->_base.address :
                   safe_str_client(conn->_base.address);
  const char *conn_type = started_here ? "outgoing" : "incoming";
  crypto_pk_env_t *our_identity =
    started_here ? get_tlsclient_identity_key() :
                   get_server_identity_key();
  int has_cert = 0, has_identity=0;

  check_no_tls_errors();
  has_cert = tor_tls_peer_has_cert(conn->tls);
  if (started_here && !has_cert) {
    log_info(LD_HANDSHAKE,"Tried connecting to router at %s:%d, but it didn't "
             "send a cert! Closing.",
             safe_address, conn->_base.port);
    return -1;
  } else if (!has_cert) {
    log_debug(LD_HANDSHAKE,"Got incoming connection with no certificate. "
              "That's ok.");
  }
  check_no_tls_errors();

  if (has_cert) {
    int v = tor_tls_verify(started_here?severity:LOG_INFO,
                           conn->tls, &identity_rcvd);
    if (started_here && v<0) {
      log_fn(severity,LD_HANDSHAKE,"Tried connecting to router at %s:%d: It"
             " has a cert but it's invalid. Closing.",
             safe_address, conn->_base.port);
        return -1;
    } else if (v<0) {
      log_info(LD_HANDSHAKE,"Incoming connection gave us an invalid cert "
               "chain; ignoring.");
    } else {
      log_debug(LD_HANDSHAKE,
                "The certificate seems to be valid on %s connection "
                "with %s:%d", conn_type, safe_address, conn->_base.port);
    }
    check_no_tls_errors();
  }

  if (identity_rcvd) {
    has_identity = 1;
    crypto_pk_get_digest(identity_rcvd, digest_rcvd_out);
    if (crypto_pk_cmp_keys(our_identity, identity_rcvd)<0) {
      conn->circ_id_type = CIRC_ID_TYPE_LOWER;
    } else {
      conn->circ_id_type = CIRC_ID_TYPE_HIGHER;
    }
    crypto_free_pk_env(identity_rcvd);
  } else {
    memset(digest_rcvd_out, 0, DIGEST_LEN);
    conn->circ_id_type = CIRC_ID_TYPE_NEITHER;
  }

  if (started_here && tor_digest_is_zero(conn->identity_digest)) {
    connection_or_set_identity_digest(conn, digest_rcvd_out);
    tor_free(conn->nickname);
    conn->nickname = tor_malloc(HEX_DIGEST_LEN+2);
    conn->nickname[0] = '$';
    base16_encode(conn->nickname+1, HEX_DIGEST_LEN+1,
                  conn->identity_digest, DIGEST_LEN);
    log_info(LD_HANDSHAKE, "Connected to router %s at %s:%d without knowing "
                    "its key. Hoping for the best.",
                    conn->nickname, conn->_base.address, conn->_base.port);
    /* if it's a bridge and we didn't know its identity fingerprint, now
     * we do -- remember it for future attempts. */
    learned_router_identity(&conn->_base.addr, conn->_base.port,
                            digest_rcvd_out);
  }

  if (started_here) {
    int as_advertised = 1;
    tor_assert(has_cert);
    tor_assert(has_identity);
    if (memcmp(digest_rcvd_out, conn->identity_digest, DIGEST_LEN)) {
      /* I was aiming for a particular digest. I didn't get it! */
      char seen[HEX_DIGEST_LEN+1];
      char expected[HEX_DIGEST_LEN+1];
      base16_encode(seen, sizeof(seen), digest_rcvd_out, DIGEST_LEN);
      base16_encode(expected, sizeof(expected), conn->identity_digest,
                    DIGEST_LEN);
      log_fn(severity, LD_HANDSHAKE,
             "Tried connecting to router at %s:%d, but identity key was not "
             "as expected: wanted %s but got %s.",
             conn->_base.address, conn->_base.port, expected, seen);
      entry_guard_register_connect_status(conn->identity_digest, 0, 1,
                                          time(NULL));
      control_event_or_conn_status(conn, OR_CONN_EVENT_FAILED,
              END_OR_CONN_REASON_OR_IDENTITY);
      if (!authdir_mode_tests_reachability(options))
        control_event_bootstrap_problem("foo", END_OR_CONN_REASON_OR_IDENTITY);
      as_advertised = 0;
    }
    if (authdir_mode_tests_reachability(options)) {
      /* We initiated this connection to address:port.  Drop all routers
       * with the same address:port and a different key.
       */
      dirserv_orconn_tls_done(conn->_base.address, conn->_base.port,
                              digest_rcvd_out, as_advertised);
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

  log_debug(LD_HANDSHAKE,"tls handshake with %s done. verifying.",
            safe_str_client(conn->_base.address));

  directory_set_dirty();

  if (connection_or_check_valid_tls_handshake(conn, started_here,
                                              digest_rcvd) < 0)
    return -1;

  circuit_build_times_network_is_live(&circ_times);

  if (tor_tls_used_v1_handshake(conn->tls)) {
    conn->link_proto = 1;
    if (!started_here) {
      connection_or_init_conn_from_address(conn, &conn->_base.addr,
                                           conn->_base.port, digest_rcvd, 0);
    }
    tor_tls_block_renegotiation(conn->tls);
    return connection_or_set_state_open(conn);
  } else {
    conn->_base.state = OR_CONN_STATE_OR_HANDSHAKING;
    if (connection_init_or_handshake_state(conn, started_here) < 0)
      return -1;
    if (!started_here) {
      connection_or_init_conn_from_address(conn, &conn->_base.addr,
                                           conn->_base.port, digest_rcvd, 0);
    }
    return connection_or_send_versions(conn);
  }
}

/** Allocate a new connection handshake state for the connection
 * <b>conn</b>.  Return 0 on success, -1 on failure. */
static int
connection_init_or_handshake_state(or_connection_t *conn, int started_here)
{
  or_handshake_state_t *s;
  s = conn->handshake_state = tor_malloc_zero(sizeof(or_handshake_state_t));
  s->started_here = started_here ? 1 : 0;
  return 0;
}

/** Free all storage held by <b>state</b>. */
void
or_handshake_state_free(or_handshake_state_t *state)
{
  if (!state)
    return;
  memset(state, 0xBE, sizeof(or_handshake_state_t));
  tor_free(state);
}

/** Set <b>conn</b>'s state to OR_CONN_STATE_OPEN, and tell other subsystems
 * as appropriate.  Called when we are done with all TLS and OR handshaking.
 */
int
connection_or_set_state_open(or_connection_t *conn)
{
  int started_here = connection_or_nonopen_was_started_here(conn);
  time_t now = time(NULL);
  conn->_base.state = OR_CONN_STATE_OPEN;
  control_event_or_conn_status(conn, OR_CONN_EVENT_CONNECTED, 0);

  if (started_here) {
    circuit_build_times_network_is_live(&circ_times);
    rep_hist_note_connect_succeeded(conn->identity_digest, now);
    if (entry_guard_register_connect_status(conn->identity_digest,
                                            1, 0, now) < 0) {
      /* Close any circuits pending on this conn. We leave it in state
       * 'open' though, because it didn't actually *fail* -- we just
       * chose not to use it. (Otherwise
       * connection_about_to_close_connection() will call a big pile of
       * functions to indicate we shouldn't try it again.) */
      log_debug(LD_OR, "New entry guard was reachable, but closing this "
                "connection so we can retry the earlier entry guards.");
      circuit_n_conn_done(conn, 0);
      return -1;
    }
    router_set_status(conn->identity_digest, 1);
  } else {
    /* only report it to the geoip module if it's not a known router */
    if (!router_get_by_digest(conn->identity_digest)) {
      if (tor_addr_family(&TO_CONN(conn)->addr) == AF_INET) {
        /*XXXX IP6 support ipv6 geoip.*/
        uint32_t a = tor_addr_to_ipv4h(&TO_CONN(conn)->addr);
        geoip_note_client_seen(GEOIP_CLIENT_CONNECT, a, now);
      }
    }
  }

  or_handshake_state_free(conn->handshake_state);
  conn->handshake_state = NULL;

  connection_start_reading(TO_CONN(conn));
  circuit_n_conn_done(conn, 1); /* send the pending creates, if any. */

  return 0;
}

/** Pack <b>cell</b> into wire-format, and write it onto <b>conn</b>'s outbuf.
 * For cells that use or affect a circuit, this should only be called by
 * connection_or_flush_from_first_active_circuit().
 */
void
connection_or_write_cell_to_buf(const cell_t *cell, or_connection_t *conn)
{
  packed_cell_t networkcell;

  tor_assert(cell);
  tor_assert(conn);

  cell_pack(&networkcell, cell);

  connection_write_to_buf(networkcell.body, CELL_NETWORK_SIZE, TO_CONN(conn));

  if (cell->command != CELL_PADDING)
    conn->timestamp_last_added_nonpadding = approx_time();
}

/** Pack a variable-length <b>cell</b> into wire-format, and write it onto
 * <b>conn</b>'s outbuf.  Right now, this <em>DOES NOT</em> support cells that
 * affect a circuit.
 */
void
connection_or_write_var_cell_to_buf(const var_cell_t *cell,
                                    or_connection_t *conn)
{
  char hdr[VAR_CELL_HEADER_SIZE];
  tor_assert(cell);
  tor_assert(conn);
  var_cell_pack_header(cell, hdr);
  connection_write_to_buf(hdr, sizeof(hdr), TO_CONN(conn));
  connection_write_to_buf(cell->payload, cell->payload_len, TO_CONN(conn));
  if (cell->command != CELL_PADDING)
    conn->timestamp_last_added_nonpadding = approx_time();
}

/** See whether there's a variable-length cell waiting on <b>conn</b>'s
 * inbuf.  Return values as for fetch_var_cell_from_buf(). */
static int
connection_fetch_var_cell_from_buf(or_connection_t *conn, var_cell_t **out)
{
  return fetch_var_cell_from_buf(conn->_base.inbuf, out, conn->link_proto);
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
  var_cell_t *var_cell;

  while (1) {
    log_debug(LD_OR,
              "%d: starting, inbuf_datalen %d (%d pending in tls object).",
              conn->_base.s,(int)buf_datalen(conn->_base.inbuf),
              tor_tls_get_pending_bytes(conn->tls));
    if (connection_fetch_var_cell_from_buf(conn, &var_cell)) {
      if (!var_cell)
        return 0; /* not yet. */
      circuit_build_times_network_is_live(&circ_times);
      command_process_var_cell(var_cell, conn);
      var_cell_free(var_cell);
    } else {
      char buf[CELL_NETWORK_SIZE];
      cell_t cell;
      if (buf_datalen(conn->_base.inbuf) < CELL_NETWORK_SIZE) /* whole response
                                                                 available? */
        return 0; /* not yet */

      circuit_build_times_network_is_live(&circ_times);
      connection_fetch_from_buf(buf, CELL_NETWORK_SIZE, TO_CONN(conn));

      /* retrieve cell info from buf (create the host-order struct from the
       * network-order string) */
      cell_unpack(&cell, buf);

      command_process_cell(&cell, conn);
    }
  }
}

/** Write a destroy cell with circ ID <b>circ_id</b> and reason <b>reason</b>
 * onto OR connection <b>conn</b>.  Don't perform range-checking on reason:
 * we may want to propagate reasons from other cells.
 *
 * Return 0.
 */
int
connection_or_send_destroy(circid_t circ_id, or_connection_t *conn, int reason)
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

/** Array of recognized link protocol versions. */
static const uint16_t or_protocol_versions[] = { 1, 2 };
/** Number of versions in <b>or_protocol_versions</b>. */
static const int n_or_protocol_versions =
  (int)( sizeof(or_protocol_versions)/sizeof(uint16_t) );

/** Return true iff <b>v</b> is a link protocol version that this Tor
 * implementation believes it can support. */
int
is_or_protocol_version_known(uint16_t v)
{
  int i;
  for (i = 0; i < n_or_protocol_versions; ++i) {
    if (or_protocol_versions[i] == v)
      return 1;
  }
  return 0;
}

/** Send a VERSIONS cell on <b>conn</b>, telling the other host about the
 * link protocol versions that this Tor can support. */
static int
connection_or_send_versions(or_connection_t *conn)
{
  var_cell_t *cell;
  int i;
  tor_assert(conn->handshake_state &&
             !conn->handshake_state->sent_versions_at);
  cell = var_cell_new(n_or_protocol_versions * 2);
  cell->command = CELL_VERSIONS;
  for (i = 0; i < n_or_protocol_versions; ++i) {
    uint16_t v = or_protocol_versions[i];
    set_uint16(cell->payload+(2*i), htons(v));
  }

  connection_or_write_var_cell_to_buf(cell, conn);
  conn->handshake_state->sent_versions_at = time(NULL);

  var_cell_free(cell);
  return 0;
}

/** Send a NETINFO cell on <b>conn</b>, telling the other server what we know
 * about their address, our address, and the current time. */
int
connection_or_send_netinfo(or_connection_t *conn)
{
  cell_t cell;
  time_t now = time(NULL);
  routerinfo_t *me;
  int len;
  char *out;

  memset(&cell, 0, sizeof(cell_t));
  cell.command = CELL_NETINFO;

  /* Timestamp. */
  set_uint32(cell.payload, htonl((uint32_t)now));

  /* Their address. */
  out = cell.payload + 4;
  len = append_address_to_payload(out, &conn->_base.addr);
  if (len<0)
    return -1;
  out += len;

  /* My address. */
  if ((me = router_get_my_routerinfo())) {
    tor_addr_t my_addr;
    *out++ = 1; /* only one address is supported. */

    tor_addr_from_ipv4h(&my_addr, me->addr);
    len = append_address_to_payload(out, &my_addr);
    if (len < 0)
      return -1;
    out += len;
  } else {
    *out++ = 0;
  }

  connection_or_write_cell_to_buf(&cell, conn);

  return 0;
}

