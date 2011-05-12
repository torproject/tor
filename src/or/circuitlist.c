/* Copyright 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitlist.c
 * \brief Manage the global circuit list.
 **/

#include "or.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "connection.h"
#include "config.h"
#include "connection_edge.h"
#include "connection_or.h"
#include "control.h"
#include "networkstatus.h"
#include "onion.h"
#include "relay.h"
#include "rendclient.h"
#include "rendcommon.h"
#include "rephist.h"
#include "routerlist.h"
#include "ht.h"

/********* START VARIABLES **********/

/** A global list of all circuits at this hop. */
circuit_t *global_circuitlist=NULL;

/** A list of all the circuits in CIRCUIT_STATE_OR_WAIT. */
static smartlist_t *circuits_pending_or_conns=NULL;

static void circuit_free(circuit_t *circ);
static void circuit_free_cpath(crypt_path_t *cpath);
static void circuit_free_cpath_node(crypt_path_t *victim);

/********* END VARIABLES ************/

/** A map from OR connection and circuit ID to circuit.  (Lookup performance is
 * very important here, since we need to do it every time a cell arrives.) */
typedef struct orconn_circid_circuit_map_t {
  HT_ENTRY(orconn_circid_circuit_map_t) node;
  or_connection_t *or_conn;
  circid_t circ_id;
  circuit_t *circuit;
} orconn_circid_circuit_map_t;

/** Helper for hash tables: compare the OR connection and circuit ID for a and
 * b, and return less than, equal to, or greater than zero appropriately.
 */
static INLINE int
_orconn_circid_entries_eq(orconn_circid_circuit_map_t *a,
                          orconn_circid_circuit_map_t *b)
{
  return a->or_conn == b->or_conn && a->circ_id == b->circ_id;
}

/** Helper: return a hash based on circuit ID and the pointer value of
 * or_conn in <b>a</b>. */
static INLINE unsigned int
_orconn_circid_entry_hash(orconn_circid_circuit_map_t *a)
{
  return (((unsigned)a->circ_id)<<8) ^ (unsigned)(uintptr_t)(a->or_conn);
}

/** Map from [orconn,circid] to circuit. */
static HT_HEAD(orconn_circid_map, orconn_circid_circuit_map_t)
     orconn_circid_circuit_map = HT_INITIALIZER();
HT_PROTOTYPE(orconn_circid_map, orconn_circid_circuit_map_t, node,
             _orconn_circid_entry_hash, _orconn_circid_entries_eq)
HT_GENERATE(orconn_circid_map, orconn_circid_circuit_map_t, node,
            _orconn_circid_entry_hash, _orconn_circid_entries_eq, 0.6,
            malloc, realloc, free)

/** The most recently returned entry from circuit_get_by_circid_orconn;
 * used to improve performance when many cells arrive in a row from the
 * same circuit.
 */
orconn_circid_circuit_map_t *_last_circid_orconn_ent = NULL;

/** Implementation helper for circuit_set_{p,n}_circid_orconn: A circuit ID
 * and/or or_connection for circ has just changed from <b>old_conn, old_id</b>
 * to <b>conn, id</b>.  Adjust the conn,circid map as appropriate, removing
 * the old entry (if any) and adding a new one.  If <b>active</b> is true,
 * remove the circuit from the list of active circuits on old_conn and add it
 * to the list of active circuits on conn.
 * XXX "active" isn't an arg anymore */
static void
circuit_set_circid_orconn_helper(circuit_t *circ, int direction,
                                 circid_t id,
                                 or_connection_t *conn)
{
  orconn_circid_circuit_map_t search;
  orconn_circid_circuit_map_t *found;
  or_connection_t *old_conn, **conn_ptr;
  circid_t old_id, *circid_ptr;
  int was_active, make_active;

  if (direction == CELL_DIRECTION_OUT) {
    conn_ptr = &circ->n_conn;
    circid_ptr = &circ->n_circ_id;
    was_active = circ->next_active_on_n_conn != NULL;
    make_active = circ->n_conn_cells.n > 0;
  } else {
    or_circuit_t *c = TO_OR_CIRCUIT(circ);
    conn_ptr = &c->p_conn;
    circid_ptr = &c->p_circ_id;
    was_active = c->next_active_on_p_conn != NULL;
    make_active = c->p_conn_cells.n > 0;
  }
  old_conn = *conn_ptr;
  old_id = *circid_ptr;

  if (id == old_id && conn == old_conn)
    return;

  if (_last_circid_orconn_ent &&
      ((old_id == _last_circid_orconn_ent->circ_id &&
        old_conn == _last_circid_orconn_ent->or_conn) ||
       (id == _last_circid_orconn_ent->circ_id &&
        conn == _last_circid_orconn_ent->or_conn))) {
    _last_circid_orconn_ent = NULL;
  }

  if (old_conn) { /* we may need to remove it from the conn-circid map */
    tor_assert(old_conn->_base.magic == OR_CONNECTION_MAGIC);
    search.circ_id = old_id;
    search.or_conn = old_conn;
    found = HT_REMOVE(orconn_circid_map, &orconn_circid_circuit_map, &search);
    if (found) {
      tor_free(found);
      --old_conn->n_circuits;
    }
    if (was_active && old_conn != conn)
      make_circuit_inactive_on_conn(circ,old_conn);
  }

  /* Change the values only after we have possibly made the circuit inactive
   * on the previous conn. */
  *conn_ptr = conn;
  *circid_ptr = id;

  if (conn == NULL)
    return;

  /* now add the new one to the conn-circid map */
  search.circ_id = id;
  search.or_conn = conn;
  found = HT_FIND(orconn_circid_map, &orconn_circid_circuit_map, &search);
  if (found) {
    found->circuit = circ;
  } else {
    found = tor_malloc_zero(sizeof(orconn_circid_circuit_map_t));
    found->circ_id = id;
    found->or_conn = conn;
    found->circuit = circ;
    HT_INSERT(orconn_circid_map, &orconn_circid_circuit_map, found);
  }
  if (make_active && old_conn != conn)
    make_circuit_active_on_conn(circ,conn);

  ++conn->n_circuits;
}

/** Set the p_conn field of a circuit <b>circ</b>, along
 * with the corresponding circuit ID, and add the circuit as appropriate
 * to the (orconn,id)-\>circuit map. */
void
circuit_set_p_circid_orconn(or_circuit_t *circ, circid_t id,
                            or_connection_t *conn)
{
  circuit_set_circid_orconn_helper(TO_CIRCUIT(circ), CELL_DIRECTION_IN,
                                   id, conn);

  if (conn)
    tor_assert(bool_eq(circ->p_conn_cells.n, circ->next_active_on_p_conn));
}

/** Set the n_conn field of a circuit <b>circ</b>, along
 * with the corresponding circuit ID, and add the circuit as appropriate
 * to the (orconn,id)-\>circuit map. */
void
circuit_set_n_circid_orconn(circuit_t *circ, circid_t id,
                            or_connection_t *conn)
{
  circuit_set_circid_orconn_helper(circ, CELL_DIRECTION_OUT, id, conn);

  if (conn)
    tor_assert(bool_eq(circ->n_conn_cells.n, circ->next_active_on_n_conn));
}

/** Change the state of <b>circ</b> to <b>state</b>, adding it to or removing
 * it from lists as appropriate. */
void
circuit_set_state(circuit_t *circ, uint8_t state)
{
  tor_assert(circ);
  if (state == circ->state)
    return;
  if (!circuits_pending_or_conns)
    circuits_pending_or_conns = smartlist_create();
  if (circ->state == CIRCUIT_STATE_OR_WAIT) {
    /* remove from waiting-circuit list. */
    smartlist_remove(circuits_pending_or_conns, circ);
  }
  if (state == CIRCUIT_STATE_OR_WAIT) {
    /* add to waiting-circuit list. */
    smartlist_add(circuits_pending_or_conns, circ);
  }
  if (state == CIRCUIT_STATE_OPEN)
    tor_assert(!circ->n_conn_onionskin);
  circ->state = state;
}

/** Add <b>circ</b> to the global list of circuits. This is called only from
 * within circuit_new.
 */
static void
circuit_add(circuit_t *circ)
{
  if (!global_circuitlist) { /* first one */
    global_circuitlist = circ;
    circ->next = NULL;
  } else {
    circ->next = global_circuitlist;
    global_circuitlist = circ;
  }
}

/** Append to <b>out</b> all circuits in state OR_WAIT waiting for
 * the given connection. */
void
circuit_get_all_pending_on_or_conn(smartlist_t *out, or_connection_t *or_conn)
{
  tor_assert(out);
  tor_assert(or_conn);

  if (!circuits_pending_or_conns)
    return;

  SMARTLIST_FOREACH_BEGIN(circuits_pending_or_conns, circuit_t *, circ) {
    if (circ->marked_for_close)
      continue;
    if (!circ->n_hop)
      continue;
    tor_assert(circ->state == CIRCUIT_STATE_OR_WAIT);
    if (tor_digest_is_zero(circ->n_hop->identity_digest)) {
      /* Look at addr/port. This is an unkeyed connection. */
      if (!tor_addr_eq(&circ->n_hop->addr, &or_conn->_base.addr) ||
          circ->n_hop->port != or_conn->_base.port)
        continue;
    } else {
      /* We expected a key. See if it's the right one. */
      if (tor_memneq(or_conn->identity_digest,
                 circ->n_hop->identity_digest, DIGEST_LEN))
        continue;
    }
    smartlist_add(out, circ);
  } SMARTLIST_FOREACH_END(circ);
}

/** Return the number of circuits in state OR_WAIT, waiting for the given
 * connection. */
int
circuit_count_pending_on_or_conn(or_connection_t *or_conn)
{
  int cnt;
  smartlist_t *sl = smartlist_create();
  circuit_get_all_pending_on_or_conn(sl, or_conn);
  cnt = smartlist_len(sl);
  smartlist_free(sl);
  log_debug(LD_CIRC,"or_conn to %s, %d pending circs",
            or_conn->nickname ? or_conn->nickname : "NULL", cnt);
  return cnt;
}

/** Detach from the global circuit list, and deallocate, all
 * circuits that have been marked for close.
 */
void
circuit_close_all_marked(void)
{
  circuit_t *tmp,*m;

  while (global_circuitlist && global_circuitlist->marked_for_close) {
    tmp = global_circuitlist->next;
    circuit_free(global_circuitlist);
    global_circuitlist = tmp;
  }

  tmp = global_circuitlist;
  while (tmp && tmp->next) {
    if (tmp->next->marked_for_close) {
      m = tmp->next->next;
      circuit_free(tmp->next);
      tmp->next = m;
      /* Need to check new tmp->next; don't advance tmp. */
    } else {
      /* Advance tmp. */
      tmp = tmp->next;
    }
  }
}

/** Return the head of the global linked list of circuits. */
circuit_t *
_circuit_get_global_list(void)
{
  return global_circuitlist;
}

/** Function to make circ-\>state human-readable */
const char *
circuit_state_to_string(int state)
{
  static char buf[64];
  switch (state) {
    case CIRCUIT_STATE_BUILDING: return "doing handshakes";
    case CIRCUIT_STATE_ONIONSKIN_PENDING: return "processing the onion";
    case CIRCUIT_STATE_OR_WAIT: return "connecting to server";
    case CIRCUIT_STATE_OPEN: return "open";
    default:
      log_warn(LD_BUG, "Unknown circuit state %d", state);
      tor_snprintf(buf, sizeof(buf), "unknown state [%d]", state);
      return buf;
  }
}

/** Map a circuit purpose to a string suitable to be displayed to a
 * controller. */
const char *
circuit_purpose_to_controller_string(uint8_t purpose)
{
  static char buf[32];
  switch (purpose) {
    case CIRCUIT_PURPOSE_OR:
    case CIRCUIT_PURPOSE_INTRO_POINT:
    case CIRCUIT_PURPOSE_REND_POINT_WAITING:
    case CIRCUIT_PURPOSE_REND_ESTABLISHED:
      return "SERVER"; /* A controller should never see these, actually. */

    case CIRCUIT_PURPOSE_C_GENERAL:
      return "GENERAL";
    case CIRCUIT_PURPOSE_C_INTRODUCING:
    case CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT:
    case CIRCUIT_PURPOSE_C_INTRODUCE_ACKED:
      return "HS_CLIENT_INTRO";

    case CIRCUIT_PURPOSE_C_ESTABLISH_REND:
    case CIRCUIT_PURPOSE_C_REND_READY:
    case CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED:
    case CIRCUIT_PURPOSE_C_REND_JOINED:
      return "HS_CLIENT_REND";

    case CIRCUIT_PURPOSE_S_ESTABLISH_INTRO:
    case CIRCUIT_PURPOSE_S_INTRO:
      return "HS_SERVICE_INTRO";

    case CIRCUIT_PURPOSE_S_CONNECT_REND:
    case CIRCUIT_PURPOSE_S_REND_JOINED:
      return "HS_SERVICE_REND";

    case CIRCUIT_PURPOSE_TESTING:
      return "TESTING";
    case CIRCUIT_PURPOSE_C_MEASURE_TIMEOUT:
      return "MEASURE_TIMEOUT";
    case CIRCUIT_PURPOSE_CONTROLLER:
      return "CONTROLLER";

    default:
      tor_snprintf(buf, sizeof(buf), "UNKNOWN_%d", (int)purpose);
      return buf;
  }
}

/** Return a human-readable string for the circuit purpose <b>purpose</b>. */
const char *
circuit_purpose_to_string(uint8_t purpose)
{
  static char buf[32];

  switch (purpose)
    {
    case CIRCUIT_PURPOSE_OR:
      return "Circuit at relay";
    case CIRCUIT_PURPOSE_INTRO_POINT:
      return "Acting as intro point";
    case CIRCUIT_PURPOSE_REND_POINT_WAITING:
      return "Acting as rendevous (pending)";
    case CIRCUIT_PURPOSE_REND_ESTABLISHED:
      return "Acting as rendevous (established)";
    case CIRCUIT_PURPOSE_C_GENERAL:
      return "General-purpose client";
    case CIRCUIT_PURPOSE_C_INTRODUCING:
      return "Hidden service client: Connecting to intro point";
    case CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT:
      return "Hidden service client: Waiting for ack from intro point";
    case CIRCUIT_PURPOSE_C_INTRODUCE_ACKED:
      return "Hidden service client: Received ack from intro point";
    case CIRCUIT_PURPOSE_C_ESTABLISH_REND:
      return "Hidden service client: Establishing rendezvous point";
    case CIRCUIT_PURPOSE_C_REND_READY:
      return "Hidden service client: Pending rendezvous point";
    case CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED:
      return "Hidden service client: Pending rendezvous point (ack received)";
    case CIRCUIT_PURPOSE_C_REND_JOINED:
      return "Hidden service client: Active rendezvous point";
    case CIRCUIT_PURPOSE_C_MEASURE_TIMEOUT:
      return "Measuring circuit timeout";

    case CIRCUIT_PURPOSE_S_ESTABLISH_INTRO:
      return "Hidden service: Establishing introduction point";
    case CIRCUIT_PURPOSE_S_INTRO:
      return "Hidden service: Introduction point";
    case CIRCUIT_PURPOSE_S_CONNECT_REND:
      return "Hidden service: Connecting to rendezvous point";
    case CIRCUIT_PURPOSE_S_REND_JOINED:
      return "Hidden service: Active rendezvous point";

    case CIRCUIT_PURPOSE_TESTING:
      return "Testing circuit";

    case CIRCUIT_PURPOSE_CONTROLLER:
      return "Circuit made by controller";

    default:
      tor_snprintf(buf, sizeof(buf), "UNKNOWN_%d", (int)purpose);
      return buf;
  }
}

/** Pick a reasonable package_window to start out for our circuits.
 * Originally this was hard-coded at 1000, but now the consensus votes
 * on the answer. See proposal 168. */
int32_t
circuit_initial_package_window(void)
{
  int32_t num = networkstatus_get_param(NULL, "circwindow", CIRCWINDOW_START,
                                        CIRCWINDOW_START_MIN,
                                        CIRCWINDOW_START_MAX);
  /* If the consensus tells us a negative number, we'd assert. */
  if (num < 0)
    num = CIRCWINDOW_START;
  return num;
}

/** Initialize the common elements in a circuit_t, and add it to the global
 * list. */
static void
init_circuit_base(circuit_t *circ)
{
  tor_gettimeofday(&circ->timestamp_created);

  circ->package_window = circuit_initial_package_window();
  circ->deliver_window = CIRCWINDOW_START;

  /* Initialize the cell_ewma_t structure */
  circ->n_cell_ewma.last_adjusted_tick = cell_ewma_get_tick();
  circ->n_cell_ewma.cell_count = 0.0;
  circ->n_cell_ewma.heap_index = -1;
  circ->n_cell_ewma.is_for_p_conn = 0;

  circuit_add(circ);
}

/** Allocate space for a new circuit, initializing with <b>p_circ_id</b>
 * and <b>p_conn</b>. Add it to the global circuit list.
 */
origin_circuit_t *
origin_circuit_new(void)
{
  origin_circuit_t *circ;
  /* never zero, since a global ID of 0 is treated specially by the
   * controller */
  static uint32_t n_circuits_allocated = 1;

  circ = tor_malloc_zero(sizeof(origin_circuit_t));
  circ->_base.magic = ORIGIN_CIRCUIT_MAGIC;

  circ->next_stream_id = crypto_rand_int(1<<16);
  circ->global_identifier = n_circuits_allocated++;
  circ->remaining_relay_early_cells = MAX_RELAY_EARLY_CELLS_PER_CIRCUIT;
  circ->remaining_relay_early_cells -= crypto_rand_int(2);

  init_circuit_base(TO_CIRCUIT(circ));

  circ_times.last_circ_at = approx_time();

  return circ;
}

/** Allocate a new or_circuit_t, connected to <b>p_conn</b> as
 * <b>p_circ_id</b>.  If <b>p_conn</b> is NULL, the circuit is unattached. */
or_circuit_t *
or_circuit_new(circid_t p_circ_id, or_connection_t *p_conn)
{
  /* CircIDs */
  or_circuit_t *circ;

  circ = tor_malloc_zero(sizeof(or_circuit_t));
  circ->_base.magic = OR_CIRCUIT_MAGIC;

  if (p_conn)
    circuit_set_p_circid_orconn(circ, p_circ_id, p_conn);

  circ->remaining_relay_early_cells = MAX_RELAY_EARLY_CELLS_PER_CIRCUIT;

  init_circuit_base(TO_CIRCUIT(circ));

  /* Initialize the cell_ewma_t structure */

  /* Initialize the cell counts to 0 */
  circ->p_cell_ewma.cell_count = 0.0;
  circ->p_cell_ewma.last_adjusted_tick = cell_ewma_get_tick();
  circ->p_cell_ewma.is_for_p_conn = 1;

  /* It's not in any heap yet. */
  circ->p_cell_ewma.heap_index = -1;

  return circ;
}

/** Deallocate space associated with circ.
 */
static void
circuit_free(circuit_t *circ)
{
  void *mem;
  size_t memlen;
  if (!circ)
    return;

  if (CIRCUIT_IS_ORIGIN(circ)) {
    origin_circuit_t *ocirc = TO_ORIGIN_CIRCUIT(circ);
    mem = ocirc;
    memlen = sizeof(origin_circuit_t);
    tor_assert(circ->magic == ORIGIN_CIRCUIT_MAGIC);
    if (ocirc->build_state) {
        extend_info_free(ocirc->build_state->chosen_exit);
        circuit_free_cpath_node(ocirc->build_state->pending_final_cpath);
    }
    tor_free(ocirc->build_state);

    circuit_free_cpath(ocirc->cpath);

    crypto_free_pk_env(ocirc->intro_key);
    rend_data_free(ocirc->rend_data);
  } else {
    or_circuit_t *ocirc = TO_OR_CIRCUIT(circ);
    /* Remember cell statistics for this circuit before deallocating. */
    if (get_options()->CellStatistics)
      rep_hist_buffer_stats_add_circ(circ, time(NULL));
    mem = ocirc;
    memlen = sizeof(or_circuit_t);
    tor_assert(circ->magic == OR_CIRCUIT_MAGIC);

    crypto_free_cipher_env(ocirc->p_crypto);
    crypto_free_digest_env(ocirc->p_digest);
    crypto_free_cipher_env(ocirc->n_crypto);
    crypto_free_digest_env(ocirc->n_digest);

    if (ocirc->rend_splice) {
      or_circuit_t *other = ocirc->rend_splice;
      tor_assert(other->_base.magic == OR_CIRCUIT_MAGIC);
      other->rend_splice = NULL;
    }

    /* remove from map. */
    circuit_set_p_circid_orconn(ocirc, 0, NULL);

    /* Clear cell queue _after_ removing it from the map.  Otherwise our
     * "active" checks will be violated. */
    cell_queue_clear(&ocirc->p_conn_cells);
  }

  extend_info_free(circ->n_hop);
  tor_free(circ->n_conn_onionskin);

  /* Remove from map. */
  circuit_set_n_circid_orconn(circ, 0, NULL);

  /* Clear cell queue _after_ removing it from the map.  Otherwise our
   * "active" checks will be violated. */
  cell_queue_clear(&circ->n_conn_cells);

  memset(mem, 0xAA, memlen); /* poison memory */
  tor_free(mem);
}

/** Deallocate space associated with the linked list <b>cpath</b>. */
static void
circuit_free_cpath(crypt_path_t *cpath)
{
  crypt_path_t *victim, *head=cpath;

  if (!cpath)
    return;

  /* it's a doubly linked list, so we have to notice when we've
   * gone through it once. */
  while (cpath->next && cpath->next != head) {
    victim = cpath;
    cpath = victim->next;
    circuit_free_cpath_node(victim);
  }

  circuit_free_cpath_node(cpath);
}

/** Release all storage held by circuits. */
void
circuit_free_all(void)
{
  circuit_t *next;
  while (global_circuitlist) {
    next = global_circuitlist->next;
    if (! CIRCUIT_IS_ORIGIN(global_circuitlist)) {
      or_circuit_t *or_circ = TO_OR_CIRCUIT(global_circuitlist);
      while (or_circ->resolving_streams) {
        edge_connection_t *next_conn;
        next_conn = or_circ->resolving_streams->next_stream;
        connection_free(TO_CONN(or_circ->resolving_streams));
        or_circ->resolving_streams = next_conn;
      }
    }
    circuit_free(global_circuitlist);
    global_circuitlist = next;
  }

  smartlist_free(circuits_pending_or_conns);
  circuits_pending_or_conns = NULL;

  HT_CLEAR(orconn_circid_map, &orconn_circid_circuit_map);
}

/** Deallocate space associated with the cpath node <b>victim</b>. */
static void
circuit_free_cpath_node(crypt_path_t *victim)
{
  if (!victim)
    return;

  crypto_free_cipher_env(victim->f_crypto);
  crypto_free_cipher_env(victim->b_crypto);
  crypto_free_digest_env(victim->f_digest);
  crypto_free_digest_env(victim->b_digest);
  crypto_dh_free(victim->dh_handshake_state);
  extend_info_free(victim->extend_info);

  memset(victim, 0xBB, sizeof(crypt_path_t)); /* poison memory */
  tor_free(victim);
}

/** A helper function for circuit_dump_by_conn() below. Log a bunch
 * of information about circuit <b>circ</b>.
 */
static void
circuit_dump_details(int severity, circuit_t *circ, int conn_array_index,
                     const char *type, int this_circid, int other_circid)
{
  log(severity, LD_CIRC, "Conn %d has %s circuit: circID %d (other side %d), "
      "state %d (%s), born %ld:",
      conn_array_index, type, this_circid, other_circid, circ->state,
      circuit_state_to_string(circ->state),
      (long)circ->timestamp_created.tv_sec);
  if (CIRCUIT_IS_ORIGIN(circ)) { /* circ starts at this node */
    circuit_log_path(severity, LD_CIRC, TO_ORIGIN_CIRCUIT(circ));
  }
}

/** Log, at severity <b>severity</b>, information about each circuit
 * that is connected to <b>conn</b>.
 */
void
circuit_dump_by_conn(connection_t *conn, int severity)
{
  circuit_t *circ;
  edge_connection_t *tmpconn;

  for (circ=global_circuitlist;circ;circ = circ->next) {
    circid_t n_circ_id = circ->n_circ_id, p_circ_id = 0;
    if (circ->marked_for_close)
      continue;

    if (! CIRCUIT_IS_ORIGIN(circ))
      p_circ_id = TO_OR_CIRCUIT(circ)->p_circ_id;

    if (! CIRCUIT_IS_ORIGIN(circ) && TO_OR_CIRCUIT(circ)->p_conn &&
        TO_CONN(TO_OR_CIRCUIT(circ)->p_conn) == conn)
      circuit_dump_details(severity, circ, conn->conn_array_index, "App-ward",
                           p_circ_id, n_circ_id);
    if (CIRCUIT_IS_ORIGIN(circ)) {
      for (tmpconn=TO_ORIGIN_CIRCUIT(circ)->p_streams; tmpconn;
           tmpconn=tmpconn->next_stream) {
        if (TO_CONN(tmpconn) == conn) {
          circuit_dump_details(severity, circ, conn->conn_array_index,
                               "App-ward", p_circ_id, n_circ_id);
        }
      }
    }
    if (circ->n_conn && TO_CONN(circ->n_conn) == conn)
      circuit_dump_details(severity, circ, conn->conn_array_index, "Exit-ward",
                           n_circ_id, p_circ_id);
    if (! CIRCUIT_IS_ORIGIN(circ)) {
      for (tmpconn=TO_OR_CIRCUIT(circ)->n_streams; tmpconn;
           tmpconn=tmpconn->next_stream) {
        if (TO_CONN(tmpconn) == conn) {
          circuit_dump_details(severity, circ, conn->conn_array_index,
                               "Exit-ward", n_circ_id, p_circ_id);
        }
      }
    }
    if (!circ->n_conn && circ->n_hop &&
        tor_addr_eq(&circ->n_hop->addr, &conn->addr) &&
        circ->n_hop->port == conn->port &&
        conn->type == CONN_TYPE_OR &&
        tor_memeq(TO_OR_CONN(conn)->identity_digest,
                circ->n_hop->identity_digest, DIGEST_LEN)) {
      circuit_dump_details(severity, circ, conn->conn_array_index,
                           (circ->state == CIRCUIT_STATE_OPEN &&
                            !CIRCUIT_IS_ORIGIN(circ)) ?
                             "Endpoint" : "Pending",
                           n_circ_id, p_circ_id);
    }
  }
}

/** Return the circuit whose global ID is <b>id</b>, or NULL if no
 * such circuit exists. */
origin_circuit_t *
circuit_get_by_global_id(uint32_t id)
{
  circuit_t *circ;
  for (circ=global_circuitlist;circ;circ = circ->next) {
    if (CIRCUIT_IS_ORIGIN(circ) &&
        TO_ORIGIN_CIRCUIT(circ)->global_identifier == id) {
      if (circ->marked_for_close)
        return NULL;
      else
        return TO_ORIGIN_CIRCUIT(circ);
    }
  }
  return NULL;
}

/** Return a circ such that:
 *  - circ-\>n_circ_id or circ-\>p_circ_id is equal to <b>circ_id</b>, and
 *  - circ is attached to <b>conn</b>, either as p_conn or n_conn.
 * Return NULL if no such circuit exists.
 */
static INLINE circuit_t *
circuit_get_by_circid_orconn_impl(circid_t circ_id, or_connection_t *conn)
{
  orconn_circid_circuit_map_t search;
  orconn_circid_circuit_map_t *found;

  if (_last_circid_orconn_ent &&
      circ_id == _last_circid_orconn_ent->circ_id &&
      conn == _last_circid_orconn_ent->or_conn) {
    found = _last_circid_orconn_ent;
  } else {
    search.circ_id = circ_id;
    search.or_conn = conn;
    found = HT_FIND(orconn_circid_map, &orconn_circid_circuit_map, &search);
    _last_circid_orconn_ent = found;
  }
  if (found && found->circuit)
    return found->circuit;

  return NULL;

  /* The rest of this checks for bugs. Disabled by default. */
  {
    circuit_t *circ;
    for (circ=global_circuitlist;circ;circ = circ->next) {
      if (! CIRCUIT_IS_ORIGIN(circ)) {
        or_circuit_t *or_circ = TO_OR_CIRCUIT(circ);
        if (or_circ->p_conn == conn && or_circ->p_circ_id == circ_id) {
          log_warn(LD_BUG,
                   "circuit matches p_conn, but not in hash table (Bug!)");
          return circ;
        }
      }
      if (circ->n_conn == conn && circ->n_circ_id == circ_id) {
        log_warn(LD_BUG,
                 "circuit matches n_conn, but not in hash table (Bug!)");
        return circ;
      }
    }
    return NULL;
  }
}

/** Return a circ such that:
 *  - circ-\>n_circ_id or circ-\>p_circ_id is equal to <b>circ_id</b>, and
 *  - circ is attached to <b>conn</b>, either as p_conn or n_conn.
 *  - circ is not marked for close.
 * Return NULL if no such circuit exists.
 */
circuit_t *
circuit_get_by_circid_orconn(circid_t circ_id, or_connection_t *conn)
{
  circuit_t *circ = circuit_get_by_circid_orconn_impl(circ_id, conn);
  if (!circ || circ->marked_for_close)
    return NULL;
  else
    return circ;
}

/** Return true iff the circuit ID <b>circ_id</b> is currently used by a
 * circuit, marked or not, on <b>conn</b>. */
int
circuit_id_in_use_on_orconn(circid_t circ_id, or_connection_t *conn)
{
  return circuit_get_by_circid_orconn_impl(circ_id, conn) != NULL;
}

/** Return the circuit that a given edge connection is using. */
circuit_t *
circuit_get_by_edge_conn(edge_connection_t *conn)
{
  circuit_t *circ;

  circ = conn->on_circuit;
  tor_assert(!circ ||
             (CIRCUIT_IS_ORIGIN(circ) ? circ->magic == ORIGIN_CIRCUIT_MAGIC
                                      : circ->magic == OR_CIRCUIT_MAGIC));

  return circ;
}

/** For each circuit that has <b>conn</b> as n_conn or p_conn, unlink the
 * circuit from the orconn,circid map, and mark it for close if it hasn't
 * been marked already.
 */
void
circuit_unlink_all_from_or_conn(or_connection_t *conn, int reason)
{
  circuit_t *circ;

  connection_or_unlink_all_active_circs(conn);

  for (circ = global_circuitlist; circ; circ = circ->next) {
    int mark = 0;
    if (circ->n_conn == conn) {
        circuit_set_n_circid_orconn(circ, 0, NULL);
        mark = 1;
    }
    if (! CIRCUIT_IS_ORIGIN(circ)) {
      or_circuit_t *or_circ = TO_OR_CIRCUIT(circ);
      if (or_circ->p_conn == conn) {
        circuit_set_p_circid_orconn(or_circ, 0, NULL);
        mark = 1;
      }
    }
    if (mark && !circ->marked_for_close)
      circuit_mark_for_close(circ, reason);
  }
}

/** Return a circ such that:
 *  - circ-\>rend_data-\>query is equal to <b>rend_query</b>, and
 *  - circ-\>purpose is equal to <b>purpose</b>.
 *
 * Return NULL if no such circuit exists.
 */
origin_circuit_t *
circuit_get_by_rend_query_and_purpose(const char *rend_query, uint8_t purpose)
{
  circuit_t *circ;

  tor_assert(CIRCUIT_PURPOSE_IS_ORIGIN(purpose));

  for (circ = global_circuitlist; circ; circ = circ->next) {
    if (!circ->marked_for_close &&
        circ->purpose == purpose) {
      origin_circuit_t *ocirc = TO_ORIGIN_CIRCUIT(circ);
      if (ocirc->rend_data &&
          !rend_cmp_service_ids(rend_query,
                                ocirc->rend_data->onion_address))
        return ocirc;
    }
  }
  return NULL;
}

/** Return the first circuit originating here in global_circuitlist after
 * <b>start</b> whose purpose is <b>purpose</b>, and where
 * <b>digest</b> (if set) matches the rend_pk_digest field. Return NULL if no
 * circuit is found.  If <b>start</b> is NULL, begin at the start of the list.
 */
origin_circuit_t *
circuit_get_next_by_pk_and_purpose(origin_circuit_t *start,
                                   const char *digest, uint8_t purpose)
{
  circuit_t *circ;
  tor_assert(CIRCUIT_PURPOSE_IS_ORIGIN(purpose));
  if (start == NULL)
    circ = global_circuitlist;
  else
    circ = TO_CIRCUIT(start)->next;

  for ( ; circ; circ = circ->next) {
    if (circ->marked_for_close)
      continue;
    if (circ->purpose != purpose)
      continue;
    if (!digest)
      return TO_ORIGIN_CIRCUIT(circ);
    else if (TO_ORIGIN_CIRCUIT(circ)->rend_data &&
             tor_memeq(TO_ORIGIN_CIRCUIT(circ)->rend_data->rend_pk_digest,
                     digest, DIGEST_LEN))
      return TO_ORIGIN_CIRCUIT(circ);
  }
  return NULL;
}

/** Return the first OR circuit in the global list whose purpose is
 * <b>purpose</b>, and whose rend_token is the <b>len</b>-byte
 * <b>token</b>. */
static or_circuit_t *
circuit_get_by_rend_token_and_purpose(uint8_t purpose, const char *token,
                                      size_t len)
{
  circuit_t *circ;
  for (circ = global_circuitlist; circ; circ = circ->next) {
    if (! circ->marked_for_close &&
        circ->purpose == purpose &&
        tor_memeq(TO_OR_CIRCUIT(circ)->rend_token, token, len))
      return TO_OR_CIRCUIT(circ);
  }
  return NULL;
}

/** Return the circuit waiting for a rendezvous with the provided cookie.
 * Return NULL if no such circuit is found.
 */
or_circuit_t *
circuit_get_rendezvous(const char *cookie)
{
  return circuit_get_by_rend_token_and_purpose(
                                     CIRCUIT_PURPOSE_REND_POINT_WAITING,
                                     cookie, REND_COOKIE_LEN);
}

/** Return the circuit waiting for intro cells of the given digest.
 * Return NULL if no such circuit is found.
 */
or_circuit_t *
circuit_get_intro_point(const char *digest)
{
  return circuit_get_by_rend_token_and_purpose(
                                     CIRCUIT_PURPOSE_INTRO_POINT, digest,
                                     DIGEST_LEN);
}

/** Return a circuit that is open, is CIRCUIT_PURPOSE_C_GENERAL,
 * has a timestamp_dirty value of 0, has flags matching the CIRCLAUNCH_*
 * flags in <b>flags</b>, and if info is defined, does not already use info
 * as any of its hops; or NULL if no circuit fits this description.
 *
 * The <b>purpose</b> argument (currently ignored) refers to the purpose of
 * the circuit we want to create, not the purpose of the circuit we want to
 * cannibalize.
 *
 * If !CIRCLAUNCH_NEED_UPTIME, prefer returning non-uptime circuits.
 */
origin_circuit_t *
circuit_find_to_cannibalize(uint8_t purpose, extend_info_t *info,
                            int flags)
{
  circuit_t *_circ;
  origin_circuit_t *best=NULL;
  int need_uptime = (flags & CIRCLAUNCH_NEED_UPTIME) != 0;
  int need_capacity = (flags & CIRCLAUNCH_NEED_CAPACITY) != 0;
  int internal = (flags & CIRCLAUNCH_IS_INTERNAL) != 0;
  or_options_t *options = get_options();

  /* Make sure we're not trying to create a onehop circ by
   * cannibalization. */
  tor_assert(!(flags & CIRCLAUNCH_ONEHOP_TUNNEL));

  log_debug(LD_CIRC,
            "Hunting for a circ to cannibalize: purpose %d, uptime %d, "
            "capacity %d, internal %d",
            purpose, need_uptime, need_capacity, internal);

  for (_circ=global_circuitlist; _circ; _circ = _circ->next) {
    if (CIRCUIT_IS_ORIGIN(_circ) &&
        _circ->state == CIRCUIT_STATE_OPEN &&
        !_circ->marked_for_close &&
        _circ->purpose == CIRCUIT_PURPOSE_C_GENERAL &&
        !_circ->timestamp_dirty) {
      origin_circuit_t *circ = TO_ORIGIN_CIRCUIT(_circ);
      if ((!need_uptime || circ->build_state->need_uptime) &&
          (!need_capacity || circ->build_state->need_capacity) &&
          (internal == circ->build_state->is_internal) &&
          circ->remaining_relay_early_cells &&
          !circ->build_state->onehop_tunnel) {
        if (info) {
          /* need to make sure we don't duplicate hops */
          crypt_path_t *hop = circ->cpath;
          routerinfo_t *ri1 = router_get_by_digest(info->identity_digest);
          do {
            routerinfo_t *ri2;
            if (tor_memeq(hop->extend_info->identity_digest,
                        info->identity_digest, DIGEST_LEN))
              goto next;
            if (ri1 &&
                (ri2 = router_get_by_digest(hop->extend_info->identity_digest))
                && routers_in_same_family(ri1, ri2))
              goto next;
            hop=hop->next;
          } while (hop!=circ->cpath);
        }
        if (options->ExcludeNodes) {
          /* Make sure no existing nodes in the circuit are excluded for
           * general use.  (This may be possible if StrictNodes is 0, and we
           * thought we needed to use an otherwise excluded node for, say, a
           * directory operation.) */
          crypt_path_t *hop = circ->cpath;
          do {
            if (routerset_contains_extendinfo(options->ExcludeNodes,
                                              hop->extend_info))
              goto next;
            hop = hop->next;
          } while (hop != circ->cpath);
        }
        if (!best || (best->build_state->need_uptime && !need_uptime))
          best = circ;
      next: ;
      }
    }
  }
  return best;
}

/** Return the number of hops in circuit's path. */
int
circuit_get_cpath_len(origin_circuit_t *circ)
{
  int n = 0;
  if (circ && circ->cpath) {
    crypt_path_t *cpath, *cpath_next = NULL;
    for (cpath = circ->cpath; cpath_next != circ->cpath; cpath = cpath_next) {
      cpath_next = cpath->next;
      ++n;
    }
  }
  return n;
}

/** Return the <b>hopnum</b>th hop in <b>circ</b>->cpath, or NULL if there
 * aren't that many hops in the list. */
crypt_path_t *
circuit_get_cpath_hop(origin_circuit_t *circ, int hopnum)
{
  if (circ && circ->cpath && hopnum > 0) {
    crypt_path_t *cpath, *cpath_next = NULL;
    for (cpath = circ->cpath; cpath_next != circ->cpath; cpath = cpath_next) {
      cpath_next = cpath->next;
      if (--hopnum <= 0)
        return cpath;
    }
  }
  return NULL;
}

/** Go through the circuitlist; mark-for-close each circuit that starts
 *  at us but has not yet been used. */
void
circuit_mark_all_unused_circs(void)
{
  circuit_t *circ;

  for (circ=global_circuitlist; circ; circ = circ->next) {
    if (CIRCUIT_IS_ORIGIN(circ) &&
        !circ->marked_for_close &&
        !circ->timestamp_dirty)
      circuit_mark_for_close(circ, END_CIRC_REASON_FINISHED);
  }
}

/** Go through the circuitlist; for each circuit that starts at us
 * and is dirty, frob its timestamp_dirty so we won't use it for any
 * new streams.
 *
 * This is useful for letting the user change pseudonyms, so new
 * streams will not be linkable to old streams.
 */
/* XXX023 this is a bad name for what this function does */
void
circuit_expire_all_dirty_circs(void)
{
  circuit_t *circ;
  or_options_t *options = get_options();

  for (circ=global_circuitlist; circ; circ = circ->next) {
    if (CIRCUIT_IS_ORIGIN(circ) &&
        !circ->marked_for_close &&
        circ->timestamp_dirty)
      /* XXXX023 This is a screwed-up way to say "This is too dirty
       * for new circuits. */
      circ->timestamp_dirty -= options->MaxCircuitDirtiness;
  }
}

/** Mark <b>circ</b> to be closed next time we call
 * circuit_close_all_marked(). Do any cleanup needed:
 *   - If state is onionskin_pending, remove circ from the onion_pending
 *     list.
 *   - If circ isn't open yet: call circuit_build_failed() if we're
 *     the origin, and in either case call circuit_rep_hist_note_result()
 *     to note stats.
 *   - If purpose is C_INTRODUCE_ACK_WAIT, remove the intro point we
 *     just tried from our list of intro points for that service
 *     descriptor.
 *   - Send appropriate destroys and edge_destroys for conns and
 *     streams attached to circ.
 *   - If circ->rend_splice is set (we are the midpoint of a joined
 *     rendezvous stream), then mark the other circuit to close as well.
 */
void
_circuit_mark_for_close(circuit_t *circ, int reason, int line,
                        const char *file)
{
  int orig_reason = reason; /* Passed to the controller */
  assert_circuit_ok(circ);
  tor_assert(line);
  tor_assert(file);

  if (circ->marked_for_close) {
    log(LOG_WARN,LD_BUG,
        "Duplicate call to circuit_mark_for_close at %s:%d"
        " (first at %s:%d)", file, line,
        circ->marked_for_close_file, circ->marked_for_close);
    return;
  }
  if (reason == END_CIRC_AT_ORIGIN) {
    if (!CIRCUIT_IS_ORIGIN(circ)) {
      log_warn(LD_BUG, "Specified 'at-origin' non-reason for ending circuit, "
               "but circuit was not at origin. (called %s:%d, purpose=%d)",
               file, line, circ->purpose);
    }
    reason = END_CIRC_REASON_NONE;
  }
  if (CIRCUIT_IS_ORIGIN(circ)) {
    /* We don't send reasons when closing circuits at the origin. */
    reason = END_CIRC_REASON_NONE;
  }

  if (reason & END_CIRC_REASON_FLAG_REMOTE)
    reason &= ~END_CIRC_REASON_FLAG_REMOTE;

  if (reason < _END_CIRC_REASON_MIN || reason > _END_CIRC_REASON_MAX) {
    if (!(orig_reason & END_CIRC_REASON_FLAG_REMOTE))
      log_warn(LD_BUG, "Reason %d out of range at %s:%d", reason, file, line);
    reason = END_CIRC_REASON_NONE;
  }

  if (circ->state == CIRCUIT_STATE_ONIONSKIN_PENDING) {
    onion_pending_remove(TO_OR_CIRCUIT(circ));
  }
  /* If the circuit ever became OPEN, we sent it to the reputation history
   * module then.  If it isn't OPEN, we send it there now to remember which
   * links worked and which didn't.
   */
  if (circ->state != CIRCUIT_STATE_OPEN) {
    if (CIRCUIT_IS_ORIGIN(circ)) {
      origin_circuit_t *ocirc = TO_ORIGIN_CIRCUIT(circ);
      circuit_build_failed(ocirc); /* take actions if necessary */
      circuit_rep_hist_note_result(ocirc);
    }
  }
  if (circ->state == CIRCUIT_STATE_OR_WAIT) {
    if (circuits_pending_or_conns)
      smartlist_remove(circuits_pending_or_conns, circ);
  }
  if (CIRCUIT_IS_ORIGIN(circ)) {
    control_event_circuit_status(TO_ORIGIN_CIRCUIT(circ),
     (circ->state == CIRCUIT_STATE_OPEN)?CIRC_EVENT_CLOSED:CIRC_EVENT_FAILED,
     orig_reason);
  }
  if (circ->purpose == CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT) {
    origin_circuit_t *ocirc = TO_ORIGIN_CIRCUIT(circ);
    tor_assert(circ->state == CIRCUIT_STATE_OPEN);
    tor_assert(ocirc->build_state->chosen_exit);
    tor_assert(ocirc->rend_data);
    /* treat this like getting a nack from it */
    log_info(LD_REND, "Failed intro circ %s to %s (awaiting ack). "
           "Removing from descriptor.",
           safe_str_client(ocirc->rend_data->onion_address),
           safe_str_client(build_state_get_exit_nickname(ocirc->build_state)));
    rend_client_remove_intro_point(ocirc->build_state->chosen_exit,
                                   ocirc->rend_data);
  }
  if (circ->n_conn) {
    circuit_clear_cell_queue(circ, circ->n_conn);
    connection_or_send_destroy(circ->n_circ_id, circ->n_conn, reason);
  }

  if (! CIRCUIT_IS_ORIGIN(circ)) {
    or_circuit_t *or_circ = TO_OR_CIRCUIT(circ);
    edge_connection_t *conn;
    for (conn=or_circ->n_streams; conn; conn=conn->next_stream)
      connection_edge_destroy(or_circ->p_circ_id, conn);
    or_circ->n_streams = NULL;

    while (or_circ->resolving_streams) {
      conn = or_circ->resolving_streams;
      or_circ->resolving_streams = conn->next_stream;
      if (!conn->_base.marked_for_close) {
        /* The client will see a DESTROY, and infer that the connections
         * are closing because the circuit is getting torn down.  No need
         * to send an end cell. */
        conn->edge_has_sent_end = 1;
        conn->end_reason = END_STREAM_REASON_DESTROY;
        conn->end_reason |= END_STREAM_REASON_FLAG_ALREADY_SENT_CLOSED;
        connection_mark_for_close(TO_CONN(conn));
      }
      conn->on_circuit = NULL;
    }

    if (or_circ->p_conn) {
      circuit_clear_cell_queue(circ, or_circ->p_conn);
      connection_or_send_destroy(or_circ->p_circ_id, or_circ->p_conn, reason);
    }
  } else {
    origin_circuit_t *ocirc = TO_ORIGIN_CIRCUIT(circ);
    edge_connection_t *conn;
    for (conn=ocirc->p_streams; conn; conn=conn->next_stream)
      connection_edge_destroy(circ->n_circ_id, conn);
    ocirc->p_streams = NULL;
  }

  circ->marked_for_close = line;
  circ->marked_for_close_file = file;

  if (!CIRCUIT_IS_ORIGIN(circ)) {
    or_circuit_t *or_circ = TO_OR_CIRCUIT(circ);
    if (or_circ->rend_splice) {
      if (!or_circ->rend_splice->_base.marked_for_close) {
        /* do this after marking this circuit, to avoid infinite recursion. */
        circuit_mark_for_close(TO_CIRCUIT(or_circ->rend_splice), reason);
      }
      or_circ->rend_splice = NULL;
    }
  }
}

/** Verify that cpath layer <b>cp</b> has all of its invariants
 * correct. Trigger an assert if anything is invalid.
 */
void
assert_cpath_layer_ok(const crypt_path_t *cp)
{
//  tor_assert(cp->addr); /* these are zero for rendezvous extra-hops */
//  tor_assert(cp->port);
  tor_assert(cp);
  tor_assert(cp->magic == CRYPT_PATH_MAGIC);
  switch (cp->state)
    {
    case CPATH_STATE_OPEN:
      tor_assert(cp->f_crypto);
      tor_assert(cp->b_crypto);
      /* fall through */
    case CPATH_STATE_CLOSED:
      tor_assert(!cp->dh_handshake_state);
      break;
    case CPATH_STATE_AWAITING_KEYS:
      /* tor_assert(cp->dh_handshake_state); */
      break;
    default:
      log_fn(LOG_ERR, LD_BUG, "Unexpected state %d", cp->state);
      tor_assert(0);
    }
  tor_assert(cp->package_window >= 0);
  tor_assert(cp->deliver_window >= 0);
}

/** Verify that cpath <b>cp</b> has all of its invariants
 * correct. Trigger an assert if anything is invalid.
 */
static void
assert_cpath_ok(const crypt_path_t *cp)
{
  const crypt_path_t *start = cp;

  do {
    assert_cpath_layer_ok(cp);
    /* layers must be in sequence of: "open* awaiting? closed*" */
    if (cp != start) {
      if (cp->state == CPATH_STATE_AWAITING_KEYS) {
        tor_assert(cp->prev->state == CPATH_STATE_OPEN);
      } else if (cp->state == CPATH_STATE_OPEN) {
        tor_assert(cp->prev->state == CPATH_STATE_OPEN);
      }
    }
    cp = cp->next;
    tor_assert(cp);
  } while (cp != start);
}

/** Verify that circuit <b>c</b> has all of its invariants
 * correct. Trigger an assert if anything is invalid.
 */
void
assert_circuit_ok(const circuit_t *c)
{
  edge_connection_t *conn;
  const or_circuit_t *or_circ = NULL;
  const origin_circuit_t *origin_circ = NULL;

  tor_assert(c);
  tor_assert(c->magic == ORIGIN_CIRCUIT_MAGIC || c->magic == OR_CIRCUIT_MAGIC);
  tor_assert(c->purpose >= _CIRCUIT_PURPOSE_MIN &&
             c->purpose <= _CIRCUIT_PURPOSE_MAX);

  {
    /* Having a separate variable for this pleases GCC 4.2 in ways I hope I
     * never understand. -NM. */
    circuit_t *nonconst_circ = (circuit_t*) c;
    if (CIRCUIT_IS_ORIGIN(c))
      origin_circ = TO_ORIGIN_CIRCUIT(nonconst_circ);
    else
      or_circ = TO_OR_CIRCUIT(nonconst_circ);
  }

  if (c->n_conn) {
    tor_assert(!c->n_hop);

    if (c->n_circ_id) {
      /* We use the _impl variant here to make sure we don't fail on marked
       * circuits, which would not be returned by the regular function. */
      circuit_t *c2 = circuit_get_by_circid_orconn_impl(c->n_circ_id,
                                                        c->n_conn);
      tor_assert(c == c2);
    }
  }
  if (or_circ && or_circ->p_conn) {
    if (or_circ->p_circ_id) {
      /* ibid */
      circuit_t *c2 = circuit_get_by_circid_orconn_impl(or_circ->p_circ_id,
                                                        or_circ->p_conn);
      tor_assert(c == c2);
    }
  }
  if (or_circ)
    for (conn = or_circ->n_streams; conn; conn = conn->next_stream)
      tor_assert(conn->_base.type == CONN_TYPE_EXIT);

  tor_assert(c->deliver_window >= 0);
  tor_assert(c->package_window >= 0);
  if (c->state == CIRCUIT_STATE_OPEN) {
    tor_assert(!c->n_conn_onionskin);
    if (or_circ) {
      tor_assert(or_circ->n_crypto);
      tor_assert(or_circ->p_crypto);
      tor_assert(or_circ->n_digest);
      tor_assert(or_circ->p_digest);
    }
  }
  if (c->state == CIRCUIT_STATE_OR_WAIT && !c->marked_for_close) {
    tor_assert(circuits_pending_or_conns &&
               smartlist_isin(circuits_pending_or_conns, c));
  } else {
    tor_assert(!circuits_pending_or_conns ||
               !smartlist_isin(circuits_pending_or_conns, c));
  }
  if (origin_circ && origin_circ->cpath) {
    assert_cpath_ok(origin_circ->cpath);
  }
  if (c->purpose == CIRCUIT_PURPOSE_REND_ESTABLISHED) {
    tor_assert(or_circ);
    if (!c->marked_for_close) {
      tor_assert(or_circ->rend_splice);
      tor_assert(or_circ->rend_splice->rend_splice == or_circ);
    }
    tor_assert(or_circ->rend_splice != or_circ);
  } else {
    tor_assert(!or_circ || !or_circ->rend_splice);
  }
}

