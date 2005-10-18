/* Copyright 2001 Matej Pfajfar.
 * Copyright 2001-2004 Roger Dingledine.
 * Copyright 2004-2005 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char circuitlist_c_id[] = "$Id$";

/**
 * \file circuitlist.c
 * \brief Manage the global circuit list.
 **/

#include "or.h"

/* Define RB_AUGMENT to avoid warnings about if statements with emtpy bodies.
 */
#define RB_AUGMENT(x) do{}while(0)
#include "tree.h"

/********* START VARIABLES **********/

/** A global list of all circuits at this hop. */
circuit_t *global_circuitlist=NULL;

static void circuit_free(circuit_t *circ);
static void circuit_free_cpath(crypt_path_t *cpath);
static void circuit_free_cpath_node(crypt_path_t *victim);

/********* END VARIABLES ************/

/** A map from OR connection and circuit ID to circuit.  (Lookup performance is
 * very important here, since we need to do it every time a cell arrives.) */
typedef struct orconn_circid_circuit_map_t {
  RB_ENTRY(orconn_circid_circuit_map_t) node;
  connection_t *or_conn;
  uint16_t circ_id;
  circuit_t *circuit;
} orconn_circid_circuit_map_t;

/** Helper for RB tree: compare the OR connection and circuit ID for a and b,
 * and return less than, equal to, or greater than zero appropriately.
 */
static INLINE int
compare_orconn_circid_entries(orconn_circid_circuit_map_t *a,
                              orconn_circid_circuit_map_t *b)
{
  if (a->or_conn < b->or_conn)
    return -1;
  else if (a->or_conn > b->or_conn)
    return 1;
  else
    return ((int)b->circ_id) - ((int)a->circ_id);
};

static RB_HEAD(orconn_circid_tree, orconn_circid_circuit_map_t) orconn_circid_circuit_map = RB_INITIALIZER(orconn_circid_circuit_map);
RB_PROTOTYPE(orconn_circid_tree, orconn_circid_circuit_map_t, node, compare_orconn_circid_entries);
RB_GENERATE(orconn_circid_tree, orconn_circid_circuit_map_t, node, compare_orconn_circid_entries);

/** The most recently returned entry from circuit_get_by_circid_orconn;
 * used to improve performance when many cells arrive in a row from the
 * same circuit.
 */
/* (We tried using splay trees, but round-robin turned out to make them
 * suck.) */
orconn_circid_circuit_map_t *_last_circid_orconn_ent = NULL;

/** Set the p_conn or n_conn field of a circuit <b>circ</b>, along
 * with the corresponding circuit ID, and add the circuit as appropriate
 * to the (orconn,id)-\>circuit map. */
void
circuit_set_circid_orconn(circuit_t *circ, uint16_t id,
                          connection_t *conn,
                          enum which_conn_changed_t which)
{
  uint16_t old_id;
  connection_t *old_conn;
  orconn_circid_circuit_map_t search;
  orconn_circid_circuit_map_t *found;

  tor_assert(!conn || conn->type == CONN_TYPE_OR);

  if (which == P_CONN_CHANGED) {
    old_id = circ->p_circ_id;
    old_conn = circ->p_conn;
    circ->p_circ_id = id;
    circ->p_conn = conn;
  } else {
    old_id = circ->n_circ_id;
    old_conn = circ->n_conn;
    circ->n_circ_id = id;
    circ->n_conn = conn;
  }

  if (_last_circid_orconn_ent &&
      ((old_id == _last_circid_orconn_ent->circ_id &&
        old_conn == _last_circid_orconn_ent->or_conn) ||
       (id == _last_circid_orconn_ent->circ_id &&
        conn == _last_circid_orconn_ent->or_conn))) {
    _last_circid_orconn_ent = NULL;
  }

  if (old_conn) {
    search.circ_id = old_id;
    search.or_conn = old_conn;
    found = RB_FIND(orconn_circid_tree, &orconn_circid_circuit_map, &search);
    if (found) {
      RB_REMOVE(orconn_circid_tree, &orconn_circid_circuit_map, found);
    }
    tor_free(found);
  }

  if (conn == NULL)
    return;

  search.circ_id = id;
  search.or_conn = conn;
  found = RB_FIND(orconn_circid_tree, &orconn_circid_circuit_map, &search);
  if (found) {
    found->circuit = circ;
  } else {
    found = tor_malloc_zero(sizeof(orconn_circid_circuit_map_t));
    found->circ_id = id;
    found->or_conn = conn;
    found->circuit = circ;
    RB_INSERT(orconn_circid_tree, &orconn_circid_circuit_map, found);
  }
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

/** Return the head of the global linked list of circuits. **/
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
    case CIRCUIT_STATE_OR_WAIT: return "connecting to firsthop";
    case CIRCUIT_STATE_OPEN: return "open";
    default:
      log_fn(LOG_WARN, "Bug: unknown circuit state %d", state);
      tor_snprintf(buf, sizeof(buf), "unknown state [%d]", state);
      return buf;
  }
}

/** Allocate space for a new circuit, initializing with <b>p_circ_id</b>
 * and <b>p_conn</b>. Add it to the global circuit list.
 */
circuit_t *
circuit_new(uint16_t p_circ_id, connection_t *p_conn)
{
  circuit_t *circ;
  static uint32_t n_circuits_allocated = 1;
  /* never zero, since a global ID of 0 is treated specially by the
   * controller */

  circ = tor_malloc_zero(sizeof(circuit_t));
  circ->magic = CIRCUIT_MAGIC;

  circ->timestamp_created = time(NULL);

  circ->state = CIRCUIT_STATE_ONIONSKIN_PENDING;

  /* CircIDs */
  if (p_conn) {
    circuit_set_circid_orconn(circ, p_circ_id, p_conn, P_CONN_CHANGED);
  }
  /* circ->n_circ_id remains 0 because we haven't identified the next hop yet */

  circ->package_window = CIRCWINDOW_START;
  circ->deliver_window = CIRCWINDOW_START;

  circ->next_stream_id = crypto_rand_int(1<<16);
  circ->global_identifier = n_circuits_allocated++;

  circuit_add(circ);

  return circ;
}

/** Deallocate space associated with circ.
 */
static void
circuit_free(circuit_t *circ)
{
  tor_assert(circ);
  tor_assert(circ->magic == CIRCUIT_MAGIC);
  if (circ->n_crypto)
    crypto_free_cipher_env(circ->n_crypto);
  if (circ->p_crypto)
    crypto_free_cipher_env(circ->p_crypto);
  if (circ->n_digest)
    crypto_free_digest_env(circ->n_digest);
  if (circ->p_digest)
    crypto_free_digest_env(circ->p_digest);
  if (circ->build_state) {
    if (circ->build_state->chosen_exit)
      extend_info_free(circ->build_state->chosen_exit);
    if (circ->build_state->pending_final_cpath)
      circuit_free_cpath_node(circ->build_state->pending_final_cpath);
  }
  tor_free(circ->build_state);
  circuit_free_cpath(circ->cpath);
  if (circ->rend_splice) {
    circ->rend_splice->rend_splice = NULL;
  }
  /* Remove from map. */
  circuit_set_circid_orconn(circ, 0, NULL, P_CONN_CHANGED);
  circuit_set_circid_orconn(circ, 0, NULL, N_CONN_CHANGED);

  memset(circ, 0xAA, sizeof(circuit_t)); /* poison memory */
  tor_free(circ);
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
    while (global_circuitlist->resolving_streams) {
      connection_t *next;
      next = global_circuitlist->resolving_streams->next_stream;
      connection_free(global_circuitlist->resolving_streams);
      global_circuitlist->resolving_streams = next;
    }
    circuit_free(global_circuitlist);
    global_circuitlist = next;
  }
}

/** Deallocate space associated with the cpath node <b>victim</b>. */
static void
circuit_free_cpath_node(crypt_path_t *victim)
{
  if (victim->f_crypto)
    crypto_free_cipher_env(victim->f_crypto);
  if (victim->b_crypto)
    crypto_free_cipher_env(victim->b_crypto);
  if (victim->f_digest)
    crypto_free_digest_env(victim->f_digest);
  if (victim->b_digest)
    crypto_free_digest_env(victim->b_digest);
  if (victim->dh_handshake_state)
    crypto_dh_free(victim->dh_handshake_state);
  if (victim->extend_info)
    extend_info_free(victim->extend_info);

  victim->magic = 0xDEADBEEFu;
  tor_free(victim);
}

/** Return the circuit whose global ID is <b>id</b>, or NULL if no
 * such circuit exists. */
circuit_t *
circuit_get_by_global_id(uint32_t id)
{
  circuit_t *circ;
  for (circ=global_circuitlist;circ;circ = circ->next) {
    if (circ->global_identifier == id) {
      if (circ->marked_for_close)
        return NULL;
      else
        return circ;
    }
  }
  return NULL;
}

/** Return a circ such that:
 *  - circ-\>n_circ_id or circ-\>p_circ_id is equal to <b>circ_id</b>, and
 *  - circ is attached to <b>conn</b>, either as p_conn or n_conn.
 * Return NULL if no such circuit exists.
 */
circuit_t *
circuit_get_by_circid_orconn(uint16_t circ_id, connection_t *conn)
{
  orconn_circid_circuit_map_t search;
  orconn_circid_circuit_map_t *found;

  tor_assert(conn->type == CONN_TYPE_OR);

  if (_last_circid_orconn_ent &&
      circ_id == _last_circid_orconn_ent->circ_id &&
      conn == _last_circid_orconn_ent->or_conn) {
    found = _last_circid_orconn_ent;
  } else {
    search.circ_id = circ_id;
    search.or_conn = conn;
    found = RB_FIND(orconn_circid_tree, &orconn_circid_circuit_map, &search);
    _last_circid_orconn_ent = found;
  }
  if (found && found->circuit && !found->circuit->marked_for_close)
    return found->circuit;

  /* The rest of this can be replaced with
     "return NULL;" once we believe the code works. */

  {
    circuit_t *circ;
    for (circ=global_circuitlist;circ;circ = circ->next) {
      if (circ->marked_for_close)
        continue;

      if (circ->p_conn == conn && circ->p_circ_id == circ_id) {
        log_fn(LOG_WARN, "circuit matches p_conn, but not in tree (Bug!)");
        return circ;
      }
      if (circ->n_conn == conn && circ->n_circ_id == circ_id) {
        log_fn(LOG_WARN, "circuit matches n_conn, but not in tree (Bug!)");
        return circ;
      }
    }
    return NULL;
  }

}

/** Return the circuit that a given edge connection is using. */
circuit_t *
circuit_get_by_edge_conn(connection_t *conn)
{
  circuit_t *circ;
#if 0
  connection_t *tmpconn;
#endif
  tor_assert(CONN_IS_EDGE(conn));

  if (! conn->on_circuit) {
    /* return NULL; */
    circ = circuit_get_by_conn(conn);
    if (circ) {
      log_fn(LOG_WARN, "BUG: conn->on_circuit==NULL, but there was in fact a circuit there.");
    }
    return circ;
  }

  circ = conn->on_circuit;
  tor_assert(circ->magic == CIRCUIT_MAGIC);
#if 0
  /* All this stuff here is sanity-checking. */
  for (tmpconn = circ->p_streams; tmpconn; tmpconn=tmpconn->next_stream)
    if (tmpconn == conn)
      return circ;
  for (tmpconn = circ->n_streams; tmpconn; tmpconn=tmpconn->next_stream)
    if (tmpconn == conn)
      return circ;
  for (tmpconn = circ->resolving_streams; tmpconn; tmpconn=tmpconn->next_stream)
    if (tmpconn == conn)
      return circ;

  tor_assert(0);
#endif
  return circ;
}

/** Return a circ such that circ is attached to <b>conn</b>, either as
 * p_conn, n_conn, or in p_streams or n_streams or resolving_streams.
 *
 * Return NULL if no such circuit exists.
 */
circuit_t *
circuit_get_by_conn(connection_t *conn)
{
  circuit_t *circ;
  connection_t *tmpconn;

  for (circ=global_circuitlist;circ;circ = circ->next) {
    if (circ->marked_for_close)
      continue;

    if (circ->p_conn == conn)
      return circ;
    if (circ->n_conn == conn)
      return circ;
    for (tmpconn = circ->p_streams; tmpconn; tmpconn=tmpconn->next_stream)
      if (tmpconn == conn)
        return circ;
    for (tmpconn = circ->n_streams; tmpconn; tmpconn=tmpconn->next_stream)
      if (tmpconn == conn)
        return circ;
    for (tmpconn = circ->resolving_streams; tmpconn; tmpconn=tmpconn->next_stream)
      if (tmpconn == conn)
        return circ;
  }
  return NULL;
}

/** Return a circ such that:
 *  - circ-\>rend_query is equal to <b>rend_query</b>, and
 *  - circ-\>purpose is equal to <b>purpose</b>.
 *
 * Return NULL if no such circuit exists.
 */
circuit_t *
circuit_get_by_rend_query_and_purpose(const char *rend_query, uint8_t purpose)
{
  circuit_t *circ;

  for (circ = global_circuitlist; circ; circ = circ->next) {
    if (!circ->marked_for_close &&
        circ->purpose == purpose &&
        !rend_cmp_service_ids(rend_query, circ->rend_query))
      return circ;
  }
  return NULL;
}

/** Return the first circuit in global_circuitlist after <b>start</b>
 * whose rend_pk_digest field is <b>digest</b> and whose purpose is
 * <b>purpose</b>. Returns NULL if no circuit is found.
 * If <b>start</b> is NULL, begin at the start of the list.
 */
circuit_t *
circuit_get_next_by_pk_and_purpose(circuit_t *start,
                                   const char *digest, uint8_t purpose)
{
  circuit_t *circ;
  if (start == NULL)
    circ = global_circuitlist;
  else
    circ = start->next;

  for ( ; circ; circ = circ->next) {
    if (circ->marked_for_close)
      continue;
    if (circ->purpose != purpose)
      continue;
    if (!memcmp(circ->rend_pk_digest, digest, DIGEST_LEN))
      return circ;
  }
  return NULL;
}

/** Return the circuit waiting for a rendezvous with the provided cookie.
 * Return NULL if no such circuit is found.
 */
circuit_t *
circuit_get_rendezvous(const char *cookie)
{
  circuit_t *circ;
  for (circ = global_circuitlist; circ; circ = circ->next) {
    if (! circ->marked_for_close &&
        circ->purpose == CIRCUIT_PURPOSE_REND_POINT_WAITING &&
        ! memcmp(circ->rend_cookie, cookie, REND_COOKIE_LEN) )
      return circ;
  }
  return NULL;
}

/** Return a circuit that is open, has specified <b>purpose</b>,
 * has a timestamp_dirty value of 0, and is uptime/capacity/internal
 * if required; or NULL if no circuit fits this description.
 *
 * Avoid returning need_uptime circuits if not necessary.
 * FFFF As a more important goal, not yet implemented, avoid returning
 * internal circuits if not necessary.
 */
circuit_t *
circuit_get_clean_open(uint8_t purpose, int need_uptime,
                       int need_capacity, int internal)
{
  circuit_t *circ;
  circuit_t *best=NULL;

  log_fn(LOG_DEBUG,"Hunting for a circ to cannibalize: purpose %d, uptime %d, capacity %d, internal %d", purpose, need_uptime, need_capacity, internal);

  for (circ=global_circuitlist; circ; circ = circ->next) {
    if (CIRCUIT_IS_ORIGIN(circ) &&
        circ->state == CIRCUIT_STATE_OPEN &&
        !circ->marked_for_close &&
        circ->purpose == purpose &&
        !circ->timestamp_dirty &&
        (!need_uptime || circ->build_state->need_uptime) &&
        (!need_capacity || circ->build_state->need_capacity) &&
        (!internal || circ->build_state->is_internal)) {
      if (!best || (best->build_state->need_uptime && !need_uptime))
        best = circ;
    }
  }
  return best;
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
      circuit_mark_for_close(circ);
  }
}

/** Go through the circuitlist; for each circuit that starts at us
 * and is dirty, frob its timestamp_dirty so we won't use it for any
 * new streams.
 *
 * This is useful for letting the user change pseudonyms, so new
 * streams will not be linkable to old streams.
 */
void
circuit_expire_all_dirty_circs(void)
{
  circuit_t *circ;
  or_options_t *options = get_options();

  for (circ=global_circuitlist; circ; circ = circ->next) {
    if (CIRCUIT_IS_ORIGIN(circ) &&
        !circ->marked_for_close &&
        circ->timestamp_dirty)
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
_circuit_mark_for_close(circuit_t *circ, int line, const char *file)
{
  connection_t *conn;

  assert_circuit_ok(circ);
  tor_assert(line);
  tor_assert(file);

  if (circ->marked_for_close) {
    log(LOG_WARN,"Duplicate call to circuit_mark_for_close at %s:%d"
        " (first at %s:%d)", file, line,
        circ->marked_for_close_file, circ->marked_for_close);
    return;
  }

  if (circ->state == CIRCUIT_STATE_ONIONSKIN_PENDING) {
    onion_pending_remove(circ);
  }
  /* If the circuit ever became OPEN, we sent it to the reputation history
   * module then.  If it isn't OPEN, we send it there now to remember which
   * links worked and which didn't.
   */
  if (circ->state != CIRCUIT_STATE_OPEN) {
    if (CIRCUIT_IS_ORIGIN(circ)) {
      circuit_build_failed(circ); /* take actions if necessary */
    }
    circuit_rep_hist_note_result(circ);
  }
  if (CIRCUIT_IS_ORIGIN(circ)) {
    control_event_circuit_status(circ,
     (circ->state == CIRCUIT_STATE_OPEN)?CIRC_EVENT_CLOSED:CIRC_EVENT_FAILED);
  }
  if (circ->purpose == CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT) {
    tor_assert(circ->state == CIRCUIT_STATE_OPEN);
    tor_assert(circ->build_state->chosen_exit);
    /* treat this like getting a nack from it */
    log_fn(LOG_INFO,"Failed intro circ %s to %s (awaiting ack). Removing from descriptor.",
           safe_str(circ->rend_query),
           safe_str(build_state_get_exit_nickname(circ->build_state)));
    rend_client_remove_intro_point(circ->build_state->chosen_exit,
                                   circ->rend_query);
  }

  if (circ->n_conn)
    connection_send_destroy(circ->n_circ_id, circ->n_conn);
  for (conn=circ->n_streams; conn; conn=conn->next_stream)
    connection_edge_destroy(circ->n_circ_id, conn);
  while (circ->resolving_streams) {
    conn = circ->resolving_streams;
    circ->resolving_streams = conn->next_stream;
    if (!conn->marked_for_close) {
      /* The other side will see a DESTROY, and infer that the connections
       * are closing because the circuit is getting torn down.  No need
       * to send an end cell*/
      conn->has_sent_end = 1; /* we're closing the circuit, nothing to send to */
      connection_mark_for_close(conn);
    }
    conn->on_circuit = NULL;
  }
  if (circ->p_conn)
    connection_send_destroy(circ->p_circ_id, circ->p_conn);
  for (conn=circ->p_streams; conn; conn=conn->next_stream)
    connection_edge_destroy(circ->p_circ_id, conn);

  circ->marked_for_close = line;
  circ->marked_for_close_file = file;

  if (circ->rend_splice && !circ->rend_splice->marked_for_close) {
    /* do this after marking this circuit, to avoid infinite recursion. */
    circuit_mark_for_close(circ->rend_splice);
    circ->rend_splice = NULL;
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
      log_fn(LOG_ERR,"Unexpected state %d",cp->state);
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
  connection_t *conn;

  tor_assert(c);
  tor_assert(c->magic == CIRCUIT_MAGIC);
  tor_assert(c->purpose >= _CIRCUIT_PURPOSE_MIN &&
             c->purpose <= _CIRCUIT_PURPOSE_MAX);

  if (c->n_conn) {
    tor_assert(c->n_conn->type == CONN_TYPE_OR);
    tor_assert(!memcmp(c->n_conn->identity_digest, c->n_conn_id_digest, DIGEST_LEN));
    if (c->n_circ_id)
      tor_assert(c == circuit_get_by_circid_orconn(c->n_circ_id, c->n_conn));
  }
  if (c->p_conn) {
    tor_assert(c->p_conn->type == CONN_TYPE_OR);
    if (c->p_circ_id)
      tor_assert(c == circuit_get_by_circid_orconn(c->p_circ_id, c->p_conn));
  }
  for (conn = c->p_streams; conn; conn = conn->next_stream)
    tor_assert(conn->type == CONN_TYPE_AP);
  for (conn = c->n_streams; conn; conn = conn->next_stream)
    tor_assert(conn->type == CONN_TYPE_EXIT);

  tor_assert(c->deliver_window >= 0);
  tor_assert(c->package_window >= 0);
  if (c->state == CIRCUIT_STATE_OPEN) {
    if (c->cpath) {
      tor_assert(CIRCUIT_IS_ORIGIN(c));
      tor_assert(!c->n_crypto);
      tor_assert(!c->p_crypto);
      tor_assert(!c->n_digest);
      tor_assert(!c->p_digest);
    } else {
      tor_assert(!CIRCUIT_IS_ORIGIN(c));
      tor_assert(c->n_crypto);
      tor_assert(c->p_crypto);
      tor_assert(c->n_digest);
      tor_assert(c->p_digest);
    }
  }
  if (c->cpath) {
    assert_cpath_ok(c->cpath);
  }
  if (c->purpose == CIRCUIT_PURPOSE_REND_ESTABLISHED) {
    if (!c->marked_for_close) {
      tor_assert(c->rend_splice);
      tor_assert(c->rend_splice->rend_splice == c);
    }
    tor_assert(c->rend_splice != c);
  } else {
    tor_assert(!c->rend_splice);
  }
}

