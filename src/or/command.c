/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
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

/** How many CELL_VPADDING cells have we received, ever? */
uint64_t stats_n_vpadding_cells_processed = 0;
/** How many CELL_CERTS cells have we received, ever? */
uint64_t stats_n_certs_cells_processed = 0;
/** How many CELL_AUTH_CHALLENGE cells have we received, ever? */
uint64_t stats_n_auth_challenge_cells_processed = 0;
/** How many CELL_AUTHENTICATE cells have we received, ever? */
uint64_t stats_n_authenticate_cells_processed = 0;
/** How many CELL_AUTHORIZE cells have we received, ever? */
uint64_t stats_n_authorize_cells_processed = 0;

/* These are the main functions for processing cells */
static void command_process_create_cell(cell_t *cell, or_connection_t *conn);
static void command_process_created_cell(cell_t *cell, or_connection_t *conn);
static void command_process_relay_cell(cell_t *cell, or_connection_t *conn);
static void command_process_destroy_cell(cell_t *cell, or_connection_t *conn);
static void command_process_versions_cell(var_cell_t *cell,
                                          or_connection_t *conn);
static void command_process_netinfo_cell(cell_t *cell, or_connection_t *conn);
static void command_process_certs_cell(var_cell_t *cell,
                                      or_connection_t *conn);
static void command_process_auth_challenge_cell(var_cell_t *cell,
                                          or_connection_t *conn);
static void command_process_authenticate_cell(var_cell_t *cell,
                                          or_connection_t *conn);
static int enter_v3_handshake_with_cell(var_cell_t *cell,
                                        or_connection_t *conn);

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
  int handshaking = (conn->_base.state != OR_CONN_STATE_OPEN);
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

  if (conn->_base.marked_for_close)
    return;

  /* Reject all but VERSIONS and NETINFO when handshaking. */
  /* (VERSIONS should actually be impossible; it's variable-length.) */
  if (handshaking && cell->command != CELL_VERSIONS &&
      cell->command != CELL_NETINFO) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Received unexpected cell command %d in state %s; closing the "
           "connection.",
           (int)cell->command,
           conn_state_to_string(CONN_TYPE_OR,conn->_base.state));
    connection_mark_for_close(TO_CONN(conn));
    return;
  }

  if (conn->_base.state == OR_CONN_STATE_OR_HANDSHAKING_V3)
    or_handshake_state_record_cell(conn->handshake_state, cell, 1);

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

/** Return true if <b>command</b> is a cell command that's allowed to start a
 * V3 handshake. */
static int
command_allowed_before_handshake(uint8_t command)
{
  switch (command) {
    case CELL_VERSIONS:
    case CELL_VPADDING:
    case CELL_AUTHORIZE:
      return 1;
    default:
      return 0;
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
  static int num_versions=0, num_certs=0;

  time_t now = time(NULL);

  if (now > current_second) { /* the second has rolled over */
    /* print stats */
    log_info(LD_OR,
             "At end of second: %d versions (%d ms), %d certs (%d ms)",
             num_versions, versions_time/1000,
             num_certs, certs_time/1000);

    num_versions = num_certs = 0;
    versions_time = certs_time = 0;

    /* remember which second it is, for next time */
    current_second = now;
  }
#endif

  if (conn->_base.marked_for_close)
    return;

  switch (conn->_base.state)
  {
    case OR_CONN_STATE_OR_HANDSHAKING_V2:
      if (cell->command != CELL_VERSIONS) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "Received a cell with command %d in state %s; "
               "closing the connection.",
               (int)cell->command,
               conn_state_to_string(CONN_TYPE_OR,conn->_base.state));
        connection_mark_for_close(TO_CONN(conn));
        return;
      }
      break;
    case OR_CONN_STATE_TLS_HANDSHAKING:
      /* If we're using bufferevents, it's entirely possible for us to
       * notice "hey, data arrived!" before we notice "hey, the handshake
       * finished!" And we need to be accepting both at once to handle both
       * the v2 and v3 handshakes. */

      /* fall through */
    case OR_CONN_STATE_TLS_SERVER_RENEGOTIATING:
      if (! command_allowed_before_handshake(cell->command)) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "Received a cell with command %d in state %s; "
               "closing the connection.",
               (int)cell->command,
               conn_state_to_string(CONN_TYPE_OR,conn->_base.state));
        connection_mark_for_close(TO_CONN(conn));
        return;
      } else {
        if (enter_v3_handshake_with_cell(cell, conn)<0)
          return;
      }
      break;
    case OR_CONN_STATE_OR_HANDSHAKING_V3:
      if (cell->command != CELL_AUTHENTICATE)
        or_handshake_state_record_var_cell(conn->handshake_state, cell, 1);
      break; /* Everything is allowed */
    case OR_CONN_STATE_OPEN:
      if (conn->link_proto < 3) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "Received a variable-length cell with command %d in state %s "
               "with link protocol %d; ignoring it.",
               (int)cell->command,
               conn_state_to_string(CONN_TYPE_OR,conn->_base.state),
               (int)conn->link_proto);
        return;
      }
      break;
    default:
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
             "Received var-length cell with command %d in unexpected state "
             "%s [%d]; ignoring it.",
             (int)cell->command,
             conn_state_to_string(CONN_TYPE_OR,conn->_base.state),
             (int)conn->_base.state);
      return;
  }

  switch (cell->command) {
    case CELL_VERSIONS:
      ++stats_n_versions_cells_processed;
      PROCESS_CELL(versions, cell, conn);
      break;
    case CELL_VPADDING:
      ++stats_n_vpadding_cells_processed;
      /* Do nothing */
      break;
    case CELL_CERTS:
      ++stats_n_certs_cells_processed;
      PROCESS_CELL(certs, cell, conn);
      break;
    case CELL_AUTH_CHALLENGE:
      ++stats_n_auth_challenge_cells_processed;
      PROCESS_CELL(auth_challenge, cell, conn);
      break;
    case CELL_AUTHENTICATE:
      ++stats_n_authenticate_cells_processed;
      PROCESS_CELL(authenticate, cell, conn);
      break;
    case CELL_AUTHORIZE:
      ++stats_n_authorize_cells_processed;
      /* Ignored so far. */
      break;
    default:
      log_fn(LOG_INFO, LD_PROTOCOL,
               "Variable-length cell of unknown type (%d) received.",
               cell->command);
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
  const or_options_t *options = get_options();
  int id_is_high;

  if (we_are_hibernating()) {
    log_info(LD_OR,
             "Received create cell but we're shutting down. Sending back "
             "destroy.");
    connection_or_send_destroy(cell->circ_id, conn,
                               END_CIRC_REASON_HIBERNATING);
    return;
  }

  if (!server_mode(options) ||
      (!public_server_mode(options) && conn->is_outgoing)) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Received create cell (type %d) from %s:%d, but we're connected "
           "to it as a client. "
           "Sending back a destroy.",
           (int)cell->command, conn->_base.address, conn->_base.port);
    connection_or_send_destroy(cell->circ_id, conn,
                               END_CIRC_REASON_TORPROTOCOL);
    return;
  }

  if (cell->circ_id == 0) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Received a create cell (type %d) from %s:%d with zero circID; "
           " ignoring.", (int)cell->command, conn->_base.address,
           conn->_base.port);
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
      circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_RESOURCELIMIT);
      return;
    }
    log_debug(LD_OR,"success: handed off onionskin.");
  } else {
    /* This is a CREATE_FAST cell; we can handle it immediately without using
     * a CPU worker. */
    char keys[CPATH_KEY_MATERIAL_LEN];
    char reply[DIGEST_LEN*2];

    tor_assert(cell->command == CELL_CREATE_FAST);

    /* Make sure we never try to use the OR connection on which we
     * received this cell to satisfy an EXTEND request,  */
    conn->is_connection_with_client = 1;

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
  if (!circ) {
    log_info(LD_OR,"unknown circuit %d on connection from %s:%d. Dropping.",
             cell->circ_id, conn->_base.address, conn->_base.port);
    return;
  }
  log_debug(LD_OR,"Received for circID %d.",cell->circ_id);

  reason = (uint8_t)cell->payload[0];

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

/** Called when we as a server receive an appropriate cell while waiting
 * either for a cell or a TLS handshake.  Set the connection's state to
 * "handshaking_v3', initializes the or_handshake_state field as needed,
 * and add the cell to the hash of incoming cells.)
 *
 * Return 0 on success; return -1 and mark the connection on failure.
 */
static int
enter_v3_handshake_with_cell(var_cell_t *cell, or_connection_t *conn)
{
  const int started_here = connection_or_nonopen_was_started_here(conn);

  tor_assert(conn->_base.state == OR_CONN_STATE_TLS_HANDSHAKING ||
             conn->_base.state == OR_CONN_STATE_TLS_SERVER_RENEGOTIATING);

  if (started_here) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Received a cell while TLS-handshaking, not in "
           "OR_HANDSHAKING_V3, on a connection we originated.");
  }
  connection_or_block_renegotiation(conn);
  conn->_base.state = OR_CONN_STATE_OR_HANDSHAKING_V3;
  if (connection_init_or_handshake_state(conn, started_here) < 0) {
    connection_mark_for_close(TO_CONN(conn));
    return -1;
  }
  or_handshake_state_record_var_cell(conn->handshake_state, cell, 1);
  return 0;
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
  const int started_here = connection_or_nonopen_was_started_here(conn);
  if (conn->link_proto != 0 ||
      (conn->handshake_state && conn->handshake_state->received_versions)) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Received a VERSIONS cell on a connection with its version "
           "already set to %d; dropping", (int) conn->link_proto);
    return;
  }
  switch (conn->_base.state)
    {
    case OR_CONN_STATE_OR_HANDSHAKING_V2:
    case OR_CONN_STATE_OR_HANDSHAKING_V3:
      break;
    case OR_CONN_STATE_TLS_HANDSHAKING:
    case OR_CONN_STATE_TLS_SERVER_RENEGOTIATING:
    default:
      log_fn(LOG_PROTOCOL_WARN, LD_OR,
             "VERSIONS cell while in unexpected state");
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
  } else if (highest_supported_version < 3 &&
             conn->_base.state ==  OR_CONN_STATE_OR_HANDSHAKING_V3) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Negotiated link protocol 2 or lower after doing a v3 TLS "
           "handshake. Closing connection.");
    connection_mark_for_close(TO_CONN(conn));
    return;
  } else if (highest_supported_version != 2 &&
             conn->_base.state == OR_CONN_STATE_OR_HANDSHAKING_V2) {
    /* XXXX This should eventually be a log_protocol_warn */
    log_fn(LOG_WARN, LD_OR,
           "Negotiated link with non-2 protocol after doing a v2 TLS "
           "handshake with %s. Closing connection.",
           fmt_addr(&conn->_base.addr));
    connection_mark_for_close(TO_CONN(conn));
    return;
  }

  conn->link_proto = highest_supported_version;
  conn->handshake_state->received_versions = 1;

  if (conn->link_proto == 2) {
    log_info(LD_OR, "Negotiated version %d with %s:%d; sending NETINFO.",
             highest_supported_version,
             safe_str_client(conn->_base.address),
             conn->_base.port);

    if (connection_or_send_netinfo(conn) < 0) {
      connection_mark_for_close(TO_CONN(conn));
      return;
    }
  } else {
    const int send_versions = !started_here;
    /* If we want to authenticate, send a CERTS cell */
    const int send_certs = !started_here || public_server_mode(get_options());
    /* If we're a host that got a connection, ask for authentication. */
    const int send_chall = !started_here;
    /* If our certs cell will authenticate us, we can send a netinfo cell
     * right now. */
    const int send_netinfo = !started_here;
    const int send_any =
      send_versions || send_certs || send_chall || send_netinfo;
    tor_assert(conn->link_proto >= 3);

    log_info(LD_OR, "Negotiated version %d with %s:%d; %s%s%s%s%s",
             highest_supported_version,
             safe_str_client(conn->_base.address),
             conn->_base.port,
             send_any ? "Sending cells:" : "Waiting for CERTS cell",
             send_versions ? " VERSIONS" : "",
             send_certs ? " CERTS" : "",
             send_chall ? " AUTH_CHALLENGE" : "",
             send_netinfo ? " NETINFO" : "");

#ifdef DISABLE_V3_LINKPROTO_SERVERSIDE
    if (1) {
      connection_mark_for_close(TO_CONN(conn));
      return;
    }
#endif

    if (send_versions) {
      if (connection_or_send_versions(conn, 1) < 0) {
        log_warn(LD_OR, "Couldn't send versions cell");
        connection_mark_for_close(TO_CONN(conn));
        return;
      }
    }
    if (send_certs) {
      if (connection_or_send_certs_cell(conn) < 0) {
        log_warn(LD_OR, "Couldn't send certs cell");
        connection_mark_for_close(TO_CONN(conn));
        return;
      }
    }
    if (send_chall) {
      if (connection_or_send_auth_challenge_cell(conn) < 0) {
        log_warn(LD_OR, "Couldn't send auth_challenge cell");
        connection_mark_for_close(TO_CONN(conn));
        return;
      }
    }
    if (send_netinfo) {
      if (connection_or_send_netinfo(conn) < 0) {
        log_warn(LD_OR, "Couldn't send netinfo cell");
        connection_mark_for_close(TO_CONN(conn));
        return;
      }
    }
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
  if (conn->_base.state != OR_CONN_STATE_OR_HANDSHAKING_V2 &&
      conn->_base.state != OR_CONN_STATE_OR_HANDSHAKING_V3) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Received a NETINFO cell on non-handshaking connection; dropping.");
    return;
  }
  tor_assert(conn->handshake_state &&
             conn->handshake_state->received_versions);

  if (conn->_base.state == OR_CONN_STATE_OR_HANDSHAKING_V3) {
    tor_assert(conn->link_proto >= 3);
    if (conn->handshake_state->started_here) {
      if (!conn->handshake_state->authenticated) {
        log_fn(LOG_PROTOCOL_WARN, LD_OR, "Got a NETINFO cell from server, "
               "but no authentication.  Closing the connection.");
        connection_mark_for_close(TO_CONN(conn));
        return;
      }
    } else {
      /* we're the server.  If the client never authenticated, we have
         some housekeeping to do.*/
      if (!conn->handshake_state->authenticated) {
        tor_assert(tor_digest_is_zero(
                  (const char*)conn->handshake_state->authenticated_peer_id));
        connection_or_set_circid_type(conn, NULL);

        connection_or_init_conn_from_address(conn,
                  &conn->_base.addr,
                  conn->_base.port,
                  (const char*)conn->handshake_state->authenticated_peer_id,
                  0);
      }
    }
  }

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

  if (! conn->handshake_state->sent_netinfo) {
    /* If we were prepared to authenticate, but we never got an AUTH_CHALLENGE
     * cell, then we would not previously have sent a NETINFO cell. Do so
     * now. */
    if (connection_or_send_netinfo(conn) < 0) {
      connection_mark_for_close(TO_CONN(conn));
      return;
    }
  }

  if (connection_or_set_state_open(conn)<0) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR, "Got good NETINFO cell from %s:%d; but "
           "was unable to make the OR connection become open.",
           safe_str_client(conn->_base.address),
           conn->_base.port);
    connection_mark_for_close(TO_CONN(conn));
  } else {
    log_info(LD_OR, "Got good NETINFO cell from %s:%d; OR connection is now "
             "open, using protocol version %d. Its ID digest is %s",
             safe_str_client(conn->_base.address),
             conn->_base.port, (int)conn->link_proto,
             hex_str(conn->identity_digest, DIGEST_LEN));
  }
  assert_connection_ok(TO_CONN(conn),time(NULL));
}

/** Process a CERTS cell from an OR connection.
 *
 * If the other side should not have sent us a CERTS cell, or the cell is
 * malformed, or it is supposed to authenticate the TLS key but it doesn't,
 * then mark the connection.
 *
 * If the cell has a good cert chain and we're doing a v3 handshake, then
 * store the certificates in or_handshake_state.  If this is the client side
 * of the connection, we then authenticate the server or mark the connection.
 * If it's the server side, wait for an AUTHENTICATE cell.
 */
static void
command_process_certs_cell(var_cell_t *cell, or_connection_t *conn)
{
#define ERR(s)                                                  \
  do {                                                          \
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,                      \
           "Received a bad CERTS cell from %s:%d: %s",          \
           safe_str(conn->_base.address), conn->_base.port, (s)); \
    connection_mark_for_close(TO_CONN(conn));                   \
    goto err;                                                   \
  } while (0)

  tor_cert_t *link_cert = NULL;
  tor_cert_t *id_cert = NULL;
  tor_cert_t *auth_cert = NULL;

  uint8_t *ptr;
  int n_certs, i;
  int send_netinfo = 0;

  if (conn->_base.state != OR_CONN_STATE_OR_HANDSHAKING_V3)
    ERR("We're not doing a v3 handshake!");
  if (conn->link_proto < 3)
    ERR("We're not using link protocol >= 3");
  if (conn->handshake_state->received_certs_cell)
    ERR("We already got one");
  if (conn->handshake_state->authenticated) {
    /* Should be unreachable, but let's make sure. */
    ERR("We're already authenticated!");
  }
  if (cell->payload_len < 1)
    ERR("It had no body");
  if (cell->circ_id)
    ERR("It had a nonzero circuit ID");

  n_certs = cell->payload[0];
  ptr = cell->payload + 1;
  for (i = 0; i < n_certs; ++i) {
    uint8_t cert_type;
    uint16_t cert_len;
    if (ptr + 3 > cell->payload + cell->payload_len) {
      goto truncated;
    }
    cert_type = *ptr;
    cert_len = ntohs(get_uint16(ptr+1));
    if (ptr + 3 + cert_len > cell->payload + cell->payload_len) {
      goto truncated;
    }
    if (cert_type == OR_CERT_TYPE_TLS_LINK ||
        cert_type == OR_CERT_TYPE_ID_1024 ||
        cert_type == OR_CERT_TYPE_AUTH_1024) {
      tor_cert_t *cert = tor_cert_decode(ptr + 3, cert_len);
      if (!cert) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "Received undecodable certificate in CERTS cell from %s:%d",
               safe_str(conn->_base.address), conn->_base.port);
      } else {
        if (cert_type == OR_CERT_TYPE_TLS_LINK) {
          if (link_cert) {
            tor_cert_free(cert);
            ERR("Too many TLS_LINK certificates");
          }
          link_cert = cert;
        } else if (cert_type == OR_CERT_TYPE_ID_1024) {
          if (id_cert) {
            tor_cert_free(cert);
            ERR("Too many ID_1024 certificates");
          }
          id_cert = cert;
        } else if (cert_type == OR_CERT_TYPE_AUTH_1024) {
          if (auth_cert) {
            tor_cert_free(cert);
            ERR("Too many AUTH_1024 certificates");
          }
          auth_cert = cert;
        } else {
          tor_cert_free(cert);
        }
      }
    }
    ptr += 3 + cert_len;
    continue;

  truncated:
    ERR("It ends in the middle of a certificate");
  }

  if (conn->handshake_state->started_here) {
    int severity;
    if (! (id_cert && link_cert))
      ERR("The certs we wanted were missing");
    /* Okay. We should be able to check the certificates now. */
    if (! tor_tls_cert_matches_key(conn->tls, link_cert)) {
      ERR("The link certificate didn't match the TLS public key");
    }
    /* Note that this warns more loudly about time and validity if we were
    * _trying_ to connect to an authority, not necessarily if we _did_ connect
    * to one. */
    if (router_digest_is_trusted_dir(conn->identity_digest))
      severity = LOG_WARN;
    else
      severity = LOG_PROTOCOL_WARN;

    if (! tor_tls_cert_is_valid(severity, link_cert, id_cert, 0))
      ERR("The link certificate was not valid");
    if (! tor_tls_cert_is_valid(severity, id_cert, id_cert, 1))
      ERR("The ID certificate was not valid");

    conn->handshake_state->authenticated = 1;
    {
      const digests_t *id_digests = tor_cert_get_id_digests(id_cert);
      crypto_pk_t *identity_rcvd;
      if (!id_digests)
        ERR("Couldn't compute digests for key in ID cert");

      identity_rcvd = tor_tls_cert_get_key(id_cert);
      if (!identity_rcvd)
        ERR("Internal error: Couldn't get RSA key from ID cert.");
      memcpy(conn->handshake_state->authenticated_peer_id,
             id_digests->d[DIGEST_SHA1], DIGEST_LEN);
      connection_or_set_circid_type(conn, identity_rcvd);
      crypto_pk_free(identity_rcvd);
    }

    if (connection_or_client_learned_peer_id(conn,
                      conn->handshake_state->authenticated_peer_id) < 0)
      ERR("Problem setting or checking peer id");

    log_info(LD_OR, "Got some good certificates from %s:%d: Authenticated it.",
             safe_str(conn->_base.address), conn->_base.port);

    conn->handshake_state->id_cert = id_cert;
    id_cert = NULL;

    if (!public_server_mode(get_options())) {
      /* If we initiated the connection and we are not a public server, we
       * aren't planning to authenticate at all.  At this point we know who we
       * are talking to, so we can just send a netinfo now. */
      send_netinfo = 1;
    }
  } else {
    if (! (id_cert && auth_cert))
      ERR("The certs we wanted were missing");

    /* Remember these certificates so we can check an AUTHENTICATE cell */
    if (! tor_tls_cert_is_valid(LOG_PROTOCOL_WARN, auth_cert, id_cert, 1))
      ERR("The authentication certificate was not valid");
    if (! tor_tls_cert_is_valid(LOG_PROTOCOL_WARN, id_cert, id_cert, 1))
      ERR("The ID certificate was not valid");

    log_info(LD_OR, "Got some good certificates from %s:%d: "
             "Waiting for AUTHENTICATE.",
             safe_str(conn->_base.address), conn->_base.port);
    /* XXXX check more stuff? */

    conn->handshake_state->id_cert = id_cert;
    conn->handshake_state->auth_cert = auth_cert;
    id_cert = auth_cert = NULL;
  }

  conn->handshake_state->received_certs_cell = 1;

  if (send_netinfo) {
    if (connection_or_send_netinfo(conn) < 0) {
      log_warn(LD_OR, "Couldn't send netinfo cell");
      connection_mark_for_close(TO_CONN(conn));
      goto err;
    }
  }

 err:
  tor_cert_free(id_cert);
  tor_cert_free(link_cert);
  tor_cert_free(auth_cert);
#undef ERR
}

/** Process an AUTH_CHALLENGE cell from an OR connection.
 *
 * If we weren't supposed to get one (for example, because we're not the
 * originator of the connection), or it's ill-formed, or we aren't doing a v3
 * handshake, mark the connection.  If the cell is well-formed but we don't
 * want to authenticate, just drop it.  If the cell is well-formed *and* we
 * want to authenticate, send an AUTHENTICATE cell and then a NETINFO cell. */
static void
command_process_auth_challenge_cell(var_cell_t *cell, or_connection_t *conn)
{
  int n_types, i, use_type = -1;
  uint8_t *cp;

#define ERR(s)                                                  \
  do {                                                          \
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,                      \
           "Received a bad AUTH_CHALLENGE cell from %s:%d: %s", \
           safe_str(conn->_base.address), conn->_base.port, (s));       \
    connection_mark_for_close(TO_CONN(conn));                   \
    return;                                                     \
  } while (0)

  if (conn->_base.state != OR_CONN_STATE_OR_HANDSHAKING_V3)
    ERR("We're not currently doing a v3 handshake");
  if (conn->link_proto < 3)
    ERR("We're not using link protocol >= 3");
  if (! conn->handshake_state->started_here)
    ERR("We didn't originate this connection");
  if (conn->handshake_state->received_auth_challenge)
    ERR("We already received one");
  if (! conn->handshake_state->received_certs_cell)
    ERR("We haven't gotten a CERTS cell yet");
  if (cell->payload_len < OR_AUTH_CHALLENGE_LEN + 2)
    ERR("It was too short");
  if (cell->circ_id)
    ERR("It had a nonzero circuit ID");

  n_types = ntohs(get_uint16(cell->payload + OR_AUTH_CHALLENGE_LEN));
  if (cell->payload_len < OR_AUTH_CHALLENGE_LEN + 2 + 2*n_types)
    ERR("It looks truncated");

  /* Now see if there is an authentication type we can use */
  cp=cell->payload+OR_AUTH_CHALLENGE_LEN+2;
  for (i=0; i < n_types; ++i, cp += 2) {
    uint16_t authtype = ntohs(get_uint16(cp));
    if (authtype == AUTHTYPE_RSA_SHA256_TLSSECRET)
      use_type = authtype;
  }

  conn->handshake_state->received_auth_challenge = 1;

  if (! public_server_mode(get_options())) {
    /* If we're not a public server then we don't want to authenticate on a
       connection we originated, and we already sent a NETINFO cell when we
       got the CERTS cell. We have nothing more to do. */
    return;
  }

  if (use_type >= 0) {
    log_info(LD_OR, "Got an AUTH_CHALLENGE cell from %s:%d: Sending "
             "authentication",
             safe_str(conn->_base.address), conn->_base.port);

    if (connection_or_send_authenticate_cell(conn, use_type) < 0) {
      log_warn(LD_OR, "Couldn't send authenticate cell");
      connection_mark_for_close(TO_CONN(conn));
      return;
    }
  } else {
    log_info(LD_OR, "Got an AUTH_CHALLENGE cell from %s:%d, but we don't "
             "know any of its authentication types. Not authenticating.",
             safe_str(conn->_base.address), conn->_base.port);
  }

  if (connection_or_send_netinfo(conn) < 0) {
    log_warn(LD_OR, "Couldn't send netinfo cell");
    connection_mark_for_close(TO_CONN(conn));
    return;
  }

#undef ERR
}

/** Process an AUTHENTICATE cell from an OR connection.
 *
 * If it's ill-formed or we weren't supposed to get one or we're not doing a
 * v3 handshake, then mark the connection.  If it does not authenticate the
 * other side of the connection successfully (because it isn't signed right,
 * we didn't get a CERTS cell, etc) mark the connection.  Otherwise, accept
 * the identity of the router on the other side of the connection.
 */
static void
command_process_authenticate_cell(var_cell_t *cell, or_connection_t *conn)
{
  uint8_t expected[V3_AUTH_FIXED_PART_LEN];
  const uint8_t *auth;
  int authlen;

#define ERR(s)                                                  \
  do {                                                          \
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,                      \
           "Received a bad AUTHENTICATE cell from %s:%d: %s",   \
           safe_str(conn->_base.address), conn->_base.port, (s));       \
    connection_mark_for_close(TO_CONN(conn));                   \
    return;                                                     \
  } while (0)

  if (conn->_base.state != OR_CONN_STATE_OR_HANDSHAKING_V3)
    ERR("We're not doing a v3 handshake");
  if (conn->link_proto < 3)
    ERR("We're not using link protocol >= 3");
  if (conn->handshake_state->started_here)
    ERR("We originated this connection");
  if (conn->handshake_state->received_authenticate)
    ERR("We already got one!");
  if (conn->handshake_state->authenticated) {
    /* Should be impossible given other checks */
    ERR("The peer is already authenticated");
  }
  if (! conn->handshake_state->received_certs_cell)
    ERR("We never got a certs cell");
  if (conn->handshake_state->auth_cert == NULL)
    ERR("We never got an authentication certificate");
  if (conn->handshake_state->id_cert == NULL)
    ERR("We never got an identity certificate");
  if (cell->payload_len < 4)
    ERR("Cell was way too short");

  auth = cell->payload;
  {
    uint16_t type = ntohs(get_uint16(auth));
    uint16_t len = ntohs(get_uint16(auth+2));
    if (4 + len > cell->payload_len)
      ERR("Authenticator was truncated");

    if (type != AUTHTYPE_RSA_SHA256_TLSSECRET)
      ERR("Authenticator type was not recognized");

    auth += 4;
    authlen = len;
  }

  if (authlen < V3_AUTH_BODY_LEN + 1)
    ERR("Authenticator was too short");

  if (connection_or_compute_authenticate_cell_body(
                        conn, expected, sizeof(expected), NULL, 1) < 0)
    ERR("Couldn't compute expected AUTHENTICATE cell body");

  if (tor_memneq(expected, auth, sizeof(expected)))
    ERR("Some field in the AUTHENTICATE cell body was not as expected");

  {
    crypto_pk_t *pk = tor_tls_cert_get_key(
                                   conn->handshake_state->auth_cert);
    char d[DIGEST256_LEN];
    char *signed_data;
    size_t keysize;
    int signed_len;

    if (!pk)
      ERR("Internal error: couldn't get RSA key from AUTH cert.");
    crypto_digest256(d, (char*)auth, V3_AUTH_BODY_LEN, DIGEST_SHA256);

    keysize = crypto_pk_keysize(pk);
    signed_data = tor_malloc(keysize);
    signed_len = crypto_pk_public_checksig(pk, signed_data, keysize,
                                           (char*)auth + V3_AUTH_BODY_LEN,
                                           authlen - V3_AUTH_BODY_LEN);
    crypto_pk_free(pk);
    if (signed_len < 0) {
      tor_free(signed_data);
      ERR("Signature wasn't valid");
    }
    if (signed_len < DIGEST256_LEN) {
      tor_free(signed_data);
      ERR("Not enough data was signed");
    }
    /* Note that we deliberately allow *more* than DIGEST256_LEN bytes here,
     * in case they're later used to hold a SHA3 digest or something. */
    if (tor_memneq(signed_data, d, DIGEST256_LEN)) {
      tor_free(signed_data);
      ERR("Signature did not match data to be signed.");
    }
    tor_free(signed_data);
  }

  /* Okay, we are authenticated. */
  conn->handshake_state->received_authenticate = 1;
  conn->handshake_state->authenticated = 1;
  conn->handshake_state->digest_received_data = 0;
  {
    crypto_pk_t *identity_rcvd =
      tor_tls_cert_get_key(conn->handshake_state->id_cert);
    const digests_t *id_digests =
      tor_cert_get_id_digests(conn->handshake_state->id_cert);

    /* This must exist; we checked key type when reading the cert. */
    tor_assert(id_digests);

    memcpy(conn->handshake_state->authenticated_peer_id,
           id_digests->d[DIGEST_SHA1], DIGEST_LEN);

    connection_or_set_circid_type(conn, identity_rcvd);
    crypto_pk_free(identity_rcvd);

    connection_or_init_conn_from_address(conn,
                  &conn->_base.addr,
                  conn->_base.port,
                  (const char*)conn->handshake_state->authenticated_peer_id,
                  0);

    log_info(LD_OR, "Got an AUTHENTICATE cell from %s:%d: Looks good.",
             safe_str(conn->_base.address), conn->_base.port);
  }

#undef ERR
}

