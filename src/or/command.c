/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file command.c
 * \brief Functions for processing incoming cells.
 **/

/* In-points to command.c:
 *
 * - command_process_cell(), called from
 *   connection_or_process_cells_from_inbuf() in connection_or.c
 */

#include "or.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "command.h"
#include "connection.h"
#include "connection_or.h"
#include "config.h"
#include "control.h"
#include "cpuworker.h"
#include "hibernate.h"
#include "nodelist.h"
#include "onion.h"
#include "relay.h"
#include "router.h"
#include "routerlist.h"

/** How many CELL_PADDING cells have we received, ever? */
uint64_t stats_n_padding_cells_processed = 0;
/** How many CELL_CREATE cells have we received, ever? */
uint64_t stats_n_create_cells_processed = 0;
/** How many CELL_CREATED cells have we received, ever? */
uint64_t stats_n_created_cells_processed = 0;
/** How many CELL_RELAY cells have we received, ever? */
uint64_t stats_n_relay_cells_processed = 0;
/** How many CELL_DESTROY cells have we received, ever? */
uint64_t stats_n_destroy_cells_processed = 0;
/** How many CELL_VERSIONS cells have we received, ever? */
uint64_t stats_n_versions_cells_processed = 0;
/** How many CELL_NETINFO cells have we received, ever? */
uint64_t stats_n_netinfo_cells_processed = 0;

/* These are the main functions for processing cells */
static void command_process_create_cell(cell_t *cell, or_connection_t *conn);
static void command_process_created_cell(cell_t *cell, or_connection_t *conn);
static void command_process_relay_cell(cell_t *cell, or_connection_t *conn);
static void command_process_destroy_cell(cell_t *cell, or_connection_t *conn);
static void command_process_versions_cell(var_cell_t *cell,
                                          or_connection_t *conn);
static void command_process_netinfo_cell(cell_t *cell, or_connection_t *conn);

#ifdef KEEP_TIMING_STATS
/** This is a wrapper function around the actual function that processes the
 * <b>cell</b> that just arrived on <b>conn</b>. Increment <b>*time</b>
 * by the number of microseconds used by the call to <b>*func(cell, conn)</b>.
 */
static void
command_time_process_cell(cell_t *cell, or_connection_t *conn, int *time,
                               void (*func)(cell_t *, or_connection_t *))
{
  struct timeval start, end;
  long time_passed;

  tor_gettimeofday(&start);

  (*func)(cell, conn);

  tor_gettimeofday(&end);
  time_passed = tv_udiff(&start, &end) ;

  if (time_passed > 10000) { /* more than 10ms */
    log_debug(LD_OR,"That call just took %ld ms.",time_passed/1000);
  }
  if (time_passed < 0) {
    log_info(LD_GENERAL,"That call took us back in time!");
    time_passed = 0;
  }
  *time += time_passed;
}
#endif

/** Process a <b>cell</b> that was just received on <b>conn</b>. Keep internal
 * statistics about how many of each cell we've processed so far
 * this second, and the total number of microseconds it took to
 * process each type of cell.
 */
void
command_process_cell(cell_t *cell, or_connection_t *conn)
{
  int handshaking = (conn->_base.state == OR_CONN_STATE_OR_HANDSHAKING);
#ifdef KEEP_TIMING_STATS
  /* how many of each cell have we seen so far this second? needs better
   * name. */
  static int num_create=0, num_created=0, num_relay=0, num_destroy=0;
  /* how long has it taken to process each type of cell? */
  static int create_time=0, created_time=0, relay_time=0, destroy_time=0;
  static time_t current_second = 0; /* from previous calls to time */

  time_t now = time(NULL);

  if (now > current_second) { /* the second has rolled over */
    /* print stats */
    log_info(LD_OR,
         "At end of second: %d creates (%d ms), %d createds (%d ms), "
         "%d relays (%d ms), %d destroys (%d ms)",
         num_create, create_time/1000,
         num_created, created_time/1000,
         num_relay, relay_time/1000,
         num_destroy, destroy_time/1000);

    /* zero out stats */
    num_create = num_created = num_relay = num_destroy = 0;
    create_time = created_time = relay_time = destroy_time = 0;

    /* remember which second it is, for next time */
    current_second = now;
  }
#endif

#ifdef KEEP_TIMING_STATS
#define PROCESS_CELL(tp, cl, cn) STMT_BEGIN {                   \
    ++num ## tp;                                                \
    command_time_process_cell(cl, cn, & tp ## time ,            \
                              command_process_ ## tp ## _cell);  \
  } STMT_END
#else
#define PROCESS_CELL(tp, cl, cn) command_process_ ## tp ## _cell(cl, cn)
#endif

  /* Reject all but VERSIONS and NETINFO when handshaking. */
  if (handshaking && cell->command != CELL_VERSIONS &&
      cell->command != CELL_NETINFO)
    return;

  switch (cell->command) {
    case CELL_PADDING:
      ++stats_n_padding_cells_processed;
      /* do nothing */
      break;
    case CELL_CREATE:
    case CELL_CREATE_FAST:
      ++stats_n_create_cells_processed;
      PROCESS_CELL(create, cell, conn);
      break;
    case CELL_CREATED:
    case CELL_CREATED_FAST:
      ++stats_n_created_cells_processed;
      PROCESS_CELL(created, cell, conn);
      break;
    case CELL_RELAY:
    case CELL_RELAY_EARLY:
      ++stats_n_relay_cells_processed;
      PROCESS_CELL(relay, cell, conn);
      break;
    case CELL_DESTROY:
      ++stats_n_destroy_cells_processed;
      PROCESS_CELL(destroy, cell, conn);
      break;
    case CELL_VERSIONS:
      tor_fragile_assert();
      break;
    case CELL_NETINFO:
      ++stats_n_netinfo_cells_processed;
      PROCESS_CELL(netinfo, cell, conn);
      break;
    default:
      log_fn(LOG_INFO, LD_PROTOCOL,
             "Cell of unknown type (%d) received. Dropping.", cell->command);
      break;
  }
}

/** Process a <b>cell</b> that was just received on <b>conn</b>. Keep internal
 * statistics about how many of each cell we've processed so far
 * this second, and the total number of microseconds it took to
 * process each type of cell.
 */
void
command_process_var_cell(var_cell_t *cell, or_connection_t *conn)
{
#ifdef KEEP_TIMING_STATS
  /* how many of each cell have we seen so far this second? needs better
   * name. */
  static int num_versions=0, num_cert=0;

  time_t now = time(NULL);

  if (now > current_second) { /* the second has rolled over */
    /* print stats */
    log_info(LD_OR,
             "At end of second: %d versions (%d ms), %d cert (%d ms)",
             num_versions, versions_time/1000,
             cert, cert_time/1000);

    num_versions = num_cert = 0;
    versions_time = cert_time = 0;

    /* remember which second it is, for next time */
    current_second = now;
  }
#endif

  /* reject all when not handshaking. */
  if (conn->_base.state != OR_CONN_STATE_OR_HANDSHAKING)
    return;

  switch (cell->command) {
    case CELL_VERSIONS:
      ++stats_n_versions_cells_processed;
      PROCESS_CELL(versions, cell, conn);
      break;
    default:
      log_warn(LD_BUG,
               "Variable-length cell of unknown type (%d) received.",
               cell->command);
      tor_fragile_assert();
      break;
  }
}

/** Process a 'create' <b>cell</b> that just arrived from <b>conn</b>. Make a
 * new circuit with the p_circ_id specified in cell. Put the circuit in state
 * onionskin_pending, and pass the onionskin to the cpuworker. Circ will get
 * picked up again when the cpuworker finishes decrypting it.
 */
static void
command_process_create_cell(cell_t *cell, or_connection_t *conn)
{
  or_circuit_t *circ;
  int id_is_high;

  if (we_are_hibernating()) {
    log_info(LD_OR,
             "Received create cell but we're shutting down. Sending back "
             "destroy.");
    connection_or_send_destroy(cell->circ_id, conn,
                               END_CIRC_REASON_HIBERNATING);
    return;
  }

  if (!server_mode(get_options())) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Received create cell (type %d) from %s:%d, but we're a client. "
           "Sending back a destroy.",
           (int)cell->command, conn->_base.address, conn->_base.port);
    connection_or_send_destroy(cell->circ_id, conn,
                               END_CIRC_REASON_TORPROTOCOL);
    return;
  }

  /* If the high bit of the circuit ID is not as expected, close the
   * circ. */
  id_is_high = cell->circ_id & (1<<15);
  if ((id_is_high && conn->circ_id_type == CIRC_ID_TYPE_HIGHER) ||
      (!id_is_high && conn->circ_id_type == CIRC_ID_TYPE_LOWER)) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Received create cell with unexpected circ_id %d. Closing.",
           cell->circ_id);
    connection_or_send_destroy(cell->circ_id, conn,
                               END_CIRC_REASON_TORPROTOCOL);
    return;
  }

  if (circuit_id_in_use_on_orconn(cell->circ_id, conn)) {
    const node_t *node = node_get_by_id(conn->identity_digest);
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Received CREATE cell (circID %d) for known circ. "
           "Dropping (age %d).",
           cell->circ_id, (int)(time(NULL) - conn->_base.timestamp_created));
    if (node) {
      char *p = esc_for_log(node_get_platform(node));
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
             "Details: router %s, platform %s.",
             node_describe(node), p);
      tor_free(p);
    }
    return;
  }

  circ = or_circuit_new(cell->circ_id, conn);
  circ->_base.purpose = CIRCUIT_PURPOSE_OR;
  circuit_set_state(TO_CIRCUIT(circ), CIRCUIT_STATE_ONIONSKIN_PENDING);
  if (cell->command == CELL_CREATE) {
    char *onionskin = tor_malloc(ONIONSKIN_CHALLENGE_LEN);
    memcpy(onionskin, cell->payload, ONIONSKIN_CHALLENGE_LEN);

    /* hand it off to the cpuworkers, and then return. */
    if (assign_onionskin_to_cpuworker(NULL, circ, onionskin) < 0) {
#define WARN_HANDOFF_FAILURE_INTERVAL (6*60*60)
      static ratelim_t handoff_warning =
        RATELIM_INIT(WARN_HANDOFF_FAILURE_INTERVAL);
      char *m;
      if ((m = rate_limit_log(&handoff_warning, approx_time()))) {
        log_warn(LD_GENERAL,"Failed to hand off onionskin. Closing.%s",m);
        tor_free(m);
      }
      circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_INTERNAL);
      return;
    }
    log_debug(LD_OR,"success: handed off onionskin.");
  } else {
    /* This is a CREATE_FAST cell; we can handle it immediately without using
     * a CPU worker. */
    char keys[CPATH_KEY_MATERIAL_LEN];
    char reply[DIGEST_LEN*2];
    tor_assert(cell->command == CELL_CREATE_FAST);
    if (fast_server_handshake(cell->payload, (uint8_t*)reply,
                              (uint8_t*)keys, sizeof(keys))<0) {
      log_warn(LD_OR,"Failed to generate key material. Closing.");
      circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_INTERNAL);
      return;
    }
    if (onionskin_answer(circ, CELL_CREATED_FAST, reply, keys)<0) {
      log_warn(LD_OR,"Failed to reply to CREATE_FAST cell. Closing.");
      circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_INTERNAL);
      return;
    }
  }
}

/** Process a 'created' <b>cell</b> that just arrived from <b>conn</b>.
 * Find the circuit
 * that it's intended for. If we're not the origin of the circuit, package
 * the 'created' cell in an 'extended' relay cell and pass it back. If we
 * are the origin of the circuit, send it to circuit_finish_handshake() to
 * finish processing keys, and then call circuit_send_next_onion_skin() to
 * extend to the next hop in the circuit if necessary.
 */
static void
command_process_created_cell(cell_t *cell, or_connection_t *conn)
{
  circuit_t *circ;

  circ = circuit_get_by_circid_orconn(cell->circ_id, conn);

  if (!circ) {
    log_info(LD_OR,
             "(circID %d) unknown circ (probably got a destroy earlier). "
             "Dropping.", cell->circ_id);
    return;
  }

  if (circ->n_circ_id != cell->circ_id) {
    log_fn(LOG_PROTOCOL_WARN,LD_PROTOCOL,
           "got created cell from Tor client? Closing.");
    circuit_mark_for_close(circ, END_CIRC_REASON_TORPROTOCOL);
    return;
  }

  if (CIRCUIT_IS_ORIGIN(circ)) { /* we're the OP. Handshake this. */
    origin_circuit_t *origin_circ = TO_ORIGIN_CIRCUIT(circ);
    int err_reason = 0;
    log_debug(LD_OR,"at OP. Finishing handshake.");
    if ((err_reason = circuit_finish_handshake(origin_circ, cell->command,
                                               cell->payload)) < 0) {
      log_warn(LD_OR,"circuit_finish_handshake failed.");
      circuit_mark_for_close(circ, -err_reason);
      return;
    }
    log_debug(LD_OR,"Moving to next skin.");
    if ((err_reason = circuit_send_next_onion_skin(origin_circ)) < 0) {
      log_info(LD_OR,"circuit_send_next_onion_skin failed.");
      /* XXX push this circuit_close lower */
      circuit_mark_for_close(circ, -err_reason);
      return;
    }
  } else { /* pack it into an extended relay cell, and send it. */
    log_debug(LD_OR,
              "Converting created cell to extended relay cell, sending.");
    relay_send_command_from_edge(0, circ, RELAY_COMMAND_EXTENDED,
                                 (char*)cell->payload, ONIONSKIN_REPLY_LEN,
                                 NULL);
  }
}

/** Process a 'relay' or 'relay_early' <b>cell</b> that just arrived from
 * <b>conn</b>. Make sure it came in with a recognized circ_id. Pass it on to
 * circuit_receive_relay_cell() for actual processing.
 */
static void
command_process_relay_cell(cell_t *cell, or_connection_t *conn)
{
  circuit_t *circ;
  int reason, direction;

  circ = circuit_get_by_circid_orconn(cell->circ_id, conn);

  if (!circ) {
    log_debug(LD_OR,
              "unknown circuit %d on connection from %s:%d. Dropping.",
              cell->circ_id, conn->_base.address, conn->_base.port);
    return;
  }

  if (circ->state == CIRCUIT_STATE_ONIONSKIN_PENDING) {
    log_fn(LOG_PROTOCOL_WARN,LD_PROTOCOL,"circuit in create_wait. Closing.");
    circuit_mark_for_close(circ, END_CIRC_REASON_TORPROTOCOL);
    return;
  }

  if (CIRCUIT_IS_ORIGIN(circ)) {
    /* if we're a relay and treating connections with recent local
     * traffic better, then this is one of them. */
    conn->client_used = time(NULL);
  }

  if (!CIRCUIT_IS_ORIGIN(circ) &&
      cell->circ_id == TO_OR_CIRCUIT(circ)->p_circ_id)
    direction = CELL_DIRECTION_OUT;
  else
    direction = CELL_DIRECTION_IN;

  /* If we have a relay_early cell, make sure that it's outbound, and we've
   * gotten no more than MAX_RELAY_EARLY_CELLS_PER_CIRCUIT of them. */
  if (cell->command == CELL_RELAY_EARLY) {
    if (direction == CELL_DIRECTION_IN) {
      /* Allow an unlimited number of inbound relay_early cells,
       * for hidden service compatibility. There isn't any way to make
       * a long circuit through inbound relay_early cells anyway. See
       * bug 1038. -RD */
    } else {
      or_circuit_t *or_circ = TO_OR_CIRCUIT(circ);
      if (or_circ->remaining_relay_early_cells == 0) {
        log_fn(LOG_PROTOCOL_WARN, LD_OR,
               "Received too many RELAY_EARLY cells on circ %d from %s:%d."
               "  Closing circuit.",
               cell->circ_id, safe_str(conn->_base.address),
               conn->_base.port);
        circuit_mark_for_close(circ, END_CIRC_REASON_TORPROTOCOL);
        return;
      }
      --or_circ->remaining_relay_early_cells;
    }
  }

  if ((reason = circuit_receive_relay_cell(cell, circ, direction)) < 0) {
    log_fn(LOG_PROTOCOL_WARN,LD_PROTOCOL,"circuit_receive_relay_cell "
           "(%s) failed. Closing.",
           direction==CELL_DIRECTION_OUT?"forward":"backward");
    circuit_mark_for_close(circ, -reason);
  }
}

/** Process a 'destroy' <b>cell</b> that just arrived from
 * <b>conn</b>. Find the circ that it refers to (if any).
 *
 * If the circ is in state
 * onionskin_pending, then call onion_pending_remove() to remove it
 * from the pending onion list (note that if it's already being
 * processed by the cpuworker, it won't be in the list anymore; but
 * when the cpuworker returns it, the circuit will be gone, and the
 * cpuworker response will be dropped).
 *
 * Then mark the circuit for close (which marks all edges for close,
 * and passes the destroy cell onward if necessary).
 */
static void
command_process_destroy_cell(cell_t *cell, or_connection_t *conn)
{
  circuit_t *circ;
  int reason;

  circ = circuit_get_by_circid_orconn(cell->circ_id, conn);
  reason = (uint8_t)cell->payload[0];
  if (!circ) {
    log_info(LD_OR,"unknown circuit %d on connection from %s:%d. Dropping.",
             cell->circ_id, conn->_base.address, conn->_base.port);
    return;
  }
  log_debug(LD_OR,"Received for circID %d.",cell->circ_id);

  if (!CIRCUIT_IS_ORIGIN(circ) &&
      cell->circ_id == TO_OR_CIRCUIT(circ)->p_circ_id) {
    /* the destroy came from behind */
    circuit_set_p_circid_orconn(TO_OR_CIRCUIT(circ), 0, NULL);
    circuit_mark_for_close(circ, reason|END_CIRC_REASON_FLAG_REMOTE);
  } else { /* the destroy came from ahead */
    circuit_set_n_circid_orconn(circ, 0, NULL);
    if (CIRCUIT_IS_ORIGIN(circ)) {
      circuit_mark_for_close(circ, reason|END_CIRC_REASON_FLAG_REMOTE);
    } else {
      char payload[1];
      log_debug(LD_OR, "Delivering 'truncated' back.");
      payload[0] = (char)reason;
      relay_send_command_from_edge(0, circ, RELAY_COMMAND_TRUNCATED,
                                   payload, sizeof(payload), NULL);
    }
  }
}

/** Process a 'versions' cell.  The current link protocol version must be 0
 * to indicate that no version has yet been negotiated.  We compare the
 * versions in the cell to the list of versions we support, pick the
 * highest version we have in common, and continue the negotiation from
 * there.
 */
static void
command_process_versions_cell(var_cell_t *cell, or_connection_t *conn)
{
  int highest_supported_version = 0;
  const uint8_t *cp, *end;
  if (conn->link_proto != 0 ||
      conn->_base.state != OR_CONN_STATE_OR_HANDSHAKING ||
      (conn->handshake_state && conn->handshake_state->received_versions)) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Received a VERSIONS cell on a connection with its version "
           "already set to %d; dropping", (int) conn->link_proto);
    return;
  }
  tor_assert(conn->handshake_state);
  end = cell->payload + cell->payload_len;
  for (cp = cell->payload; cp+1 < end; ++cp) {
    uint16_t v = ntohs(get_uint16(cp));
    if (is_or_protocol_version_known(v) && v > highest_supported_version)
      highest_supported_version = v;
  }
  if (!highest_supported_version) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Couldn't find a version in common between my version list and the "
           "list in the VERSIONS cell; closing connection.");
    connection_mark_for_close(TO_CONN(conn));
    return;
  } else if (highest_supported_version == 1) {
    /* Negotiating version 1 makes no sense, since version 1 has no VERSIONS
     * cells. */
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Used version negotiation protocol to negotiate a v1 connection. "
           "That's crazily non-compliant. Closing connection.");
    connection_mark_for_close(TO_CONN(conn));
    return;
  }
  conn->link_proto = highest_supported_version;
  conn->handshake_state->received_versions = 1;

  log_info(LD_OR, "Negotiated version %d with %s:%d; sending NETINFO.",
           highest_supported_version,
           safe_str_client(conn->_base.address),
           conn->_base.port);
  tor_assert(conn->link_proto >= 2);

  if (connection_or_send_netinfo(conn) < 0) {
    connection_mark_for_close(TO_CONN(conn));
    return;
  }
}

/** Process a 'netinfo' cell: read and act on its contents, and set the
 * connection state to "open". */
static void
command_process_netinfo_cell(cell_t *cell, or_connection_t *conn)
{
  time_t timestamp;
  uint8_t my_addr_type;
  uint8_t my_addr_len;
  const uint8_t *my_addr_ptr;
  const uint8_t *cp, *end;
  uint8_t n_other_addrs;
  time_t now = time(NULL);

  long apparent_skew = 0;
  uint32_t my_apparent_addr = 0;

  if (conn->link_proto < 2) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Received a NETINFO cell on %s connection; dropping.",
           conn->link_proto == 0 ? "non-versioned" : "a v1");
    return;
  }
  if (conn->_base.state != OR_CONN_STATE_OR_HANDSHAKING) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Received a NETINFO cell on non-handshaking connection; dropping.");
    return;
  }
  tor_assert(conn->handshake_state &&
             conn->handshake_state->received_versions);
  /* Decode the cell. */
  timestamp = ntohl(get_uint32(cell->payload));
  if (labs(now - conn->handshake_state->sent_versions_at) < 180) {
    apparent_skew = now - timestamp;
  }

  my_addr_type = (uint8_t) cell->payload[4];
  my_addr_len = (uint8_t) cell->payload[5];
  my_addr_ptr = (uint8_t*) cell->payload + 6;
  end = cell->payload + CELL_PAYLOAD_SIZE;
  cp = cell->payload + 6 + my_addr_len;
  if (cp >= end) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Addresses too long in netinfo cell; closing connection.");
    connection_mark_for_close(TO_CONN(conn));
    return;
  } else if (my_addr_type == RESOLVED_TYPE_IPV4 && my_addr_len == 4) {
    my_apparent_addr = ntohl(get_uint32(my_addr_ptr));
  }

  n_other_addrs = (uint8_t) *cp++;
  while (n_other_addrs && cp < end-2) {
    /* Consider all the other addresses; if any matches, this connection is
     * "canonical." */
    tor_addr_t addr;
    const uint8_t *next =
      decode_address_from_payload(&addr, cp, (int)(end-cp));
    if (next == NULL) {
      log_fn(LOG_PROTOCOL_WARN,  LD_OR,
             "Bad address in netinfo cell; closing connection.");
      connection_mark_for_close(TO_CONN(conn));
      return;
    }
    if (tor_addr_eq(&addr, &conn->real_addr)) {
      conn->is_canonical = 1;
      break;
    }
    cp = next;
    --n_other_addrs;
  }

  /* Act on apparent skew. */
  /** Warn when we get a netinfo skew with at least this value. */
#define NETINFO_NOTICE_SKEW 3600
  if (labs(apparent_skew) > NETINFO_NOTICE_SKEW &&
      router_get_by_id_digest(conn->identity_digest)) {
    char dbuf[64];
    int severity;
    /*XXXX be smarter about when everybody says we are skewed. */
    if (router_digest_is_trusted_dir(conn->identity_digest))
      severity = LOG_WARN;
    else
      severity = LOG_INFO;
    format_time_interval(dbuf, sizeof(dbuf), apparent_skew);
    log_fn(severity, LD_GENERAL, "Received NETINFO cell with skewed time from "
           "server at %s:%d.  It seems that our clock is %s by %s, or "
           "that theirs is %s. Tor requires an accurate clock to work: "
           "please check your time and date settings.",
           conn->_base.address, (int)conn->_base.port,
           apparent_skew>0 ? "ahead" : "behind", dbuf,
           apparent_skew>0 ? "behind" : "ahead");
    if (severity == LOG_WARN) /* only tell the controller if an authority */
      control_event_general_status(LOG_WARN,
                          "CLOCK_SKEW SKEW=%ld SOURCE=OR:%s:%d",
                          apparent_skew,
                          conn->_base.address, conn->_base.port);
  }

  /* XXX maybe act on my_apparent_addr, if the source is sufficiently
   * trustworthy. */
  (void)my_apparent_addr;

  if (connection_or_set_state_open(conn)<0)
    connection_mark_for_close(TO_CONN(conn));
  else
    log_info(LD_OR, "Got good NETINFO cell from %s:%d; OR connection is now "
             "open, using protocol version %d",
             safe_str_client(conn->_base.address),
             conn->_base.port, (int)conn->link_proto);
  assert_connection_ok(TO_CONN(conn),time(NULL));
}

