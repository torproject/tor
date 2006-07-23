/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char circuitbuild_c_id[] =
  "$Id$";

/**
 * \file circuitbuild.c
 * \brief The actual details of building circuits.
 **/

#include "or.h"

/********* START VARIABLES **********/

/** A global list of all circuits at this hop. */
extern circuit_t *global_circuitlist;

/** An entry_guard_t represents our information about a chosen long-term
 * first hop, known as a "helper" node in the literature. We can't just
 * use a routerinfo_t, since we want to remember these even when we
 * don't have a directory. */
typedef struct {
  char nickname[MAX_NICKNAME_LEN+1];
  char identity[DIGEST_LEN];
  uint8_t made_contact; /**< 0 if we have never connected to this router,
                         * 1 if we have. */
  time_t down_since; /**< 0 if this router is currently up, or the time at
                      * which it was observed to go down. */
  time_t unlisted_since; /**< 0 if this router is currently listed, or the
                          * time at which it became unlisted */
} entry_guard_t;

/** A list of our chosen entry guards. */
static smartlist_t *entry_guards = NULL;
/** A value of 1 means that the entry_guards list has changed
 * and those changes need to be flushed to disk. */
static int entry_guards_dirty = 0;

/********* END VARIABLES ************/

static int circuit_deliver_create_cell(circuit_t *circ,
                                       uint8_t cell_type, char *payload);
static int onion_pick_cpath_exit(origin_circuit_t *circ, extend_info_t *exit);
static crypt_path_t *onion_next_hop_in_cpath(crypt_path_t *cpath);
static int onion_extend_cpath(uint8_t purpose, crypt_path_t **head_ptr,
                              cpath_build_state_t *state);
static int count_acceptable_routers(smartlist_t *routers);
static int onion_append_hop(crypt_path_t **head_ptr, extend_info_t *choice);

static routerinfo_t *choose_random_entry(cpath_build_state_t *state);
static void entry_guards_changed(void);

/** Iterate over values of circ_id, starting from conn-\>next_circ_id,
 * and with the high bit specified by conn-\>circ_id_type, until we get
 * a circ_id that is not in use by any other circuit on that conn.
 *
 * Return it, or 0 if can't get a unique circ_id.
 */
static uint16_t
get_unique_circ_id_by_conn(connection_t *conn)
{
  uint16_t test_circ_id;
  uint16_t attempts=0;
  uint16_t high_bit;

  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_OR);
  high_bit = (conn->circ_id_type == CIRC_ID_TYPE_HIGHER) ? 1<<15 : 0;
  do {
    /* Sequentially iterate over test_circ_id=1...1<<15-1 until we find a
     * circID such that (high_bit|test_circ_id) is not already used. */
    test_circ_id = conn->next_circ_id++;
    if (test_circ_id == 0 || test_circ_id >= 1<<15) {
      test_circ_id = 1;
      conn->next_circ_id = 2;
    }
    if (++attempts > 1<<15) {
      /* Make sure we don't loop forever if all circ_id's are used. This
       * matters because it's an external DoS opportunity.
       */
      log_warn(LD_CIRC,"No unused circ IDs. Failing.");
      return 0;
    }
    test_circ_id |= high_bit;
  } while (circuit_id_used_on_conn(test_circ_id, conn));
  return test_circ_id;
}

/** If <b>verbose</b> is false, allocate and return a comma-separated
 * list of the currently built elements of circuit_t.  If
 * <b>verbose</b> is true, also list information about link status in
 * a more verbose format using spaces.
 */
char *
circuit_list_path(origin_circuit_t *circ, int verbose)
{
  crypt_path_t *hop;
  smartlist_t *elements;
  const char *states[] = {"closed", "waiting for keys", "open"};
  char buf[128];
  char *s;

  elements = smartlist_create();

  if (verbose) {
    const char *nickname = build_state_get_exit_nickname(circ->build_state);
    tor_snprintf(buf, sizeof(buf), "%s%s circ (length %d%s%s):",
                 circ->build_state->is_internal ? "internal" : "exit",
                 circ->build_state->need_uptime ? " (high-uptime)" : "",
                 circ->build_state->desired_path_len,
                 circ->_base.state == CIRCUIT_STATE_OPEN ? "" : ", exit ",
                 circ->_base.state == CIRCUIT_STATE_OPEN ? "" :
                   (nickname?nickname:"*unnamed*"));
    smartlist_add(elements, tor_strdup(buf));
  }

  hop = circ->cpath;
  do {
    const char *elt;
    if (!hop)
      break;
    if (!verbose && hop->state != CPATH_STATE_OPEN)
      break;
    if (!hop->extend_info)
      break;
    elt = hop->extend_info->nickname;
    tor_assert(elt);
    if (verbose) {
      size_t len = strlen(elt)+2+strlen(states[hop->state])+1;
      char *v = tor_malloc(len);
      tor_assert(hop->state <= 2);
      tor_snprintf(v,len,"%s(%s)",elt,states[hop->state]);
      smartlist_add(elements, v);
    } else {
      smartlist_add(elements, tor_strdup(elt));
    }
    hop = hop->next;
  } while (hop != circ->cpath);

  s = smartlist_join_strings(elements, verbose?" ":",", 0, NULL);
  SMARTLIST_FOREACH(elements, char*, cp, tor_free(cp));
  smartlist_free(elements);
  return s;
}

/** Log, at severity <b>severity</b>, the nicknames of each router in
 * circ's cpath. Also log the length of the cpath, and the intended
 * exit point.
 */
void
circuit_log_path(int severity, unsigned int domain, origin_circuit_t *circ)
{
  char *s = circuit_list_path(circ,1);
  log(severity,domain,"%s",s);
  tor_free(s);
}

/** Tell the rep(utation)hist(ory) module about the status of the links
 * in circ.  Hops that have become OPEN are marked as successfully
 * extended; the _first_ hop that isn't open (if any) is marked as
 * unable to extend.
 */
void
circuit_rep_hist_note_result(origin_circuit_t *circ)
{
  crypt_path_t *hop;
  char *prev_digest = NULL;
  routerinfo_t *router;
  hop = circ->cpath;
  if (!hop) {
    /* XXX
     * if !hop, then we're not the beginning of this circuit.
     * for now, just forget about it. later, we should remember when
     * extends-through-us failed, too.
     */
    return;
  }
  if (server_mode(get_options())) {
    routerinfo_t *me = router_get_my_routerinfo();
    if (!me)
      return;
    prev_digest = me->cache_info.identity_digest;
  }
  do {
    router = router_get_by_digest(hop->extend_info->identity_digest);
    if (router) {
      if (prev_digest) {
        if (hop->state == CPATH_STATE_OPEN)
          rep_hist_note_extend_succeeded(prev_digest,
                                         router->cache_info.identity_digest);
        else {
          rep_hist_note_extend_failed(prev_digest,
                                      router->cache_info.identity_digest);
          break;
        }
      }
      prev_digest = router->cache_info.identity_digest;
    } else {
      prev_digest = NULL;
    }
    hop=hop->next;
  } while (hop!=circ->cpath);
}

/** Pick all the entries in our cpath. Stop and return 0 when we're
 * happy, or return -1 if an error occurs. */
static int
onion_populate_cpath(origin_circuit_t *circ)
{
  int r;
again:
  r = onion_extend_cpath(circ->_base.purpose, &circ->cpath, circ->build_state);
  if (r < 0) {
    log_info(LD_CIRC,"Generating cpath hop failed.");
    return -1;
  }
  if (r == 0)
    goto again;
  return 0; /* if r == 1 */
}

/** Create and return a new origin circuit. Initialize its purpose and
 * build-state based on our arguments. */
origin_circuit_t *
origin_circuit_init(uint8_t purpose, int need_uptime, int need_capacity,
                    int internal)
{
  /* sets circ->p_circ_id and circ->p_conn */
  origin_circuit_t *circ = origin_circuit_new();
  circuit_set_state(TO_CIRCUIT(circ), CIRCUIT_STATE_OR_WAIT);
  circ->build_state = tor_malloc_zero(sizeof(cpath_build_state_t));
  circ->build_state->need_uptime = need_uptime;
  circ->build_state->need_capacity = need_capacity;
  circ->build_state->is_internal = internal;
  circ->_base.purpose = purpose;
  return circ;
}

/** Build a new circuit for <b>purpose</b>. If <b>info/b>
 * is defined, then use that as your exit router, else choose a suitable
 * exit node.
 *
 * Also launch a connection to the first OR in the chosen path, if
 * it's not open already.
 */
origin_circuit_t *
circuit_establish_circuit(uint8_t purpose, extend_info_t *info,
                          int need_uptime, int need_capacity, int internal)
{
  origin_circuit_t *circ;

  circ = origin_circuit_init(purpose, need_uptime, need_capacity, internal);

  if (onion_pick_cpath_exit(circ, info) < 0 ||
      onion_populate_cpath(circ) < 0) {
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_AT_ORIGIN);
    return NULL;
  }

  control_event_circuit_status(circ, CIRC_EVENT_LAUNCHED);

  if (circuit_handle_first_hop(circ) < 0) {
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_AT_ORIGIN);
    return NULL;
  }
  return circ;
}

/** Start establishing the first hop of our circuit. Figure out what
 * OR we should connect to, and if necessary start the connection to
 * it. If we're already connected, then send the 'create' cell.
 * Return 0 for ok, -1 if circ should be marked-for-close. */
int
circuit_handle_first_hop(origin_circuit_t *circ)
{
  crypt_path_t *firsthop;
  connection_t *n_conn;
  char tmpbuf[INET_NTOA_BUF_LEN];
  struct in_addr in;

  firsthop = onion_next_hop_in_cpath(circ->cpath);
  tor_assert(firsthop);
  tor_assert(firsthop->extend_info);

  /* now see if we're already connected to the first OR in 'route' */
  in.s_addr = htonl(firsthop->extend_info->addr);
  tor_inet_ntoa(&in, tmpbuf, sizeof(tmpbuf));
  log_debug(LD_CIRC,"Looking for firsthop '%s:%u'",tmpbuf,
            firsthop->extend_info->port);
  /* imprint the circuit with its future n_conn->id */
  memcpy(circ->_base.n_conn_id_digest, firsthop->extend_info->identity_digest,
         DIGEST_LEN);
  n_conn = connection_or_get_by_identity_digest(
         firsthop->extend_info->identity_digest);
  /* If we don't have an open conn, or the conn we have is obsolete
   * (i.e. old or broken) and the other side will let us make a second
   * connection without dropping it immediately... */
  if (!n_conn || n_conn->state != OR_CONN_STATE_OPEN ||
      (n_conn->is_obsolete &&
       router_digest_version_as_new_as(firsthop->extend_info->identity_digest,
                                       "0.1.1.9-alpha-cvs"))) {
    /* not currently connected */
    circ->_base.n_addr = firsthop->extend_info->addr;
    circ->_base.n_port = firsthop->extend_info->port;

    if (!n_conn || n_conn->is_obsolete) { /* launch the connection */
      n_conn = connection_or_connect(firsthop->extend_info->addr,
                                     firsthop->extend_info->port,
                                     firsthop->extend_info->identity_digest);
      if (!n_conn) { /* connect failed, forget the whole thing */
        log_info(LD_CIRC,"connect to firsthop failed. Closing.");
        return -1;
      }
    }

    log_debug(LD_CIRC,"connecting in progress (or finished). Good.");
    /* return success. The onion/circuit/etc will be taken care of
     * automatically (may already have been) whenever n_conn reaches
     * OR_CONN_STATE_OPEN.
     */
    return 0;
  } else { /* it's already open. use it. */
    circ->_base.n_addr = n_conn->addr;
    circ->_base.n_port = n_conn->port;
    circ->_base.n_conn = n_conn;
    log_debug(LD_CIRC,"Conn open. Delivering first onion skin.");
    if (circuit_send_next_onion_skin(circ) < 0) {
      log_info(LD_CIRC,"circuit_send_next_onion_skin failed.");
      return -1;
    }
  }
  return 0;
}

/** Find any circuits that are waiting on <b>or_conn</b> to become
 * open and get them to send their create cells forward.
 *
 * Status is 1 if connect succeeded, or 0 if connect failed.
 */
void
circuit_n_conn_done(connection_t *or_conn, int status)
{
  extern smartlist_t *circuits_pending_or_conns;
  smartlist_t *changed_circs;

  log_debug(LD_CIRC,"or_conn to %s, status=%d",
            or_conn->nickname ? or_conn->nickname : "NULL", status);

  if (!circuits_pending_or_conns)
    return;

  changed_circs = smartlist_create();

  SMARTLIST_FOREACH(circuits_pending_or_conns, circuit_t *, circ,
  {
    if (circ->marked_for_close)
      continue;
    tor_assert(circ->state == CIRCUIT_STATE_OR_WAIT);
    if (!circ->n_conn &&
        !memcmp(or_conn->identity_digest, circ->n_conn_id_digest,
                DIGEST_LEN)) {
      if (!status) { /* or_conn failed; close circ */
        log_info(LD_CIRC,"or_conn failed. Closing circ.");
        circuit_mark_for_close(circ, END_CIRC_REASON_OR_CONN_CLOSED);
        continue;
      }
      log_debug(LD_CIRC, "Found circ, sending create cell.");
      /* circuit_deliver_create_cell will set n_circ_id and add us to
       * orconn_circuid_circuit_map, so we don't need to call
       * set_circid_orconn here. */
      circ->n_conn = or_conn;
      if (CIRCUIT_IS_ORIGIN(circ)) {
        if (circuit_send_next_onion_skin(TO_ORIGIN_CIRCUIT(circ)) < 0) {
          log_info(LD_CIRC,
                   "send_next_onion_skin failed; circuit marked for closing.");
          circuit_mark_for_close(circ, END_CIRC_AT_ORIGIN);
          continue;
          /* XXX could this be bad, eg if next_onion_skin failed because conn
           *     died? */
        }
      } else {
        /* pull the create cell out of circ->onionskin, and send it */
        tor_assert(circ->onionskin);
        if (circuit_deliver_create_cell(circ,CELL_CREATE,circ->onionskin)<0) {
          circuit_mark_for_close(circ, END_CIRC_REASON_RESOURCELIMIT);
          continue;
        }
        tor_free(circ->onionskin);
        /* We don't want to change circ's state here, since the act
         * of doing that modifies the circuits_pending_or_conns list
         * that we're looping through right now. So collect a list of
         * circs to change their state when we're done. */
        smartlist_add(changed_circs, circ);
      }
    }
  });

  SMARTLIST_FOREACH(changed_circs, circuit_t *, circ,
    circuit_set_state(circ, CIRCUIT_STATE_OPEN));
  smartlist_free(changed_circs);
}

/** Find a new circid that isn't currently in use on the circ->n_conn
 * for the outgoing
 * circuit <b>circ</b>, and deliver a cell of type <b>cell_type</b>
 * (either CELL_CREATE or CELL_CREATE_FAST) with payload <b>payload</b>
 * to this circuit.
 * Return -1 if we failed to find a suitable circid, else return 0.
 */
static int
circuit_deliver_create_cell(circuit_t *circ, uint8_t cell_type,
                            char *payload)
{
  cell_t cell;
  uint16_t id;

  tor_assert(circ);
  tor_assert(circ->n_conn);
  tor_assert(circ->n_conn->type == CONN_TYPE_OR);
  tor_assert(payload);
  tor_assert(cell_type == CELL_CREATE || cell_type == CELL_CREATE_FAST);

  id = get_unique_circ_id_by_conn(circ->n_conn);
  if (!id) {
    log_warn(LD_CIRC,"failed to get unique circID.");
    return -1;
  }
  log_debug(LD_CIRC,"Chosen circID %u.", id);
  circuit_set_n_circid_orconn(circ, id, circ->n_conn);

  memset(&cell, 0, sizeof(cell_t));
  cell.command = cell_type;
  cell.circ_id = circ->n_circ_id;

  memcpy(cell.payload, payload, ONIONSKIN_CHALLENGE_LEN);
  connection_or_write_cell_to_buf(&cell, circ->n_conn);
  return 0;
}

/** We've decided to start our reachability testing. If all
 * is set, log this to the user. Return 1 if we did, or 0 if
 * we chose not to log anything. */
int
inform_testing_reachability(void)
{
  char dirbuf[128];
  routerinfo_t *me = router_get_my_routerinfo();
  if (!me)
    return 0;
  if (me->dir_port)
    tor_snprintf(dirbuf, sizeof(dirbuf), " and DirPort %s:%d",
                 me->address, me->dir_port);
  log(LOG_NOTICE, LD_OR, "Now checking whether ORPort %s:%d%s %s reachable... "
                         "(this may take up to %d minutes -- look for log "
                         "messages indicating success)",
      me->address, me->or_port,
      me->dir_port ? dirbuf : "",
      me->dir_port ? "are" : "is",
      TIMEOUT_UNTIL_UNREACHABILITY_COMPLAINT/60);
  return 1;
}

/** Return true iff we should send a create_fast cell to build a circuit
 * starting at <b>router</b>.  (If <b>router</b> is NULL, we don't have
 * information on the router, so return false.) */
static INLINE int
should_use_create_fast_for_router(routerinfo_t *router)
{
  or_options_t *options = get_options();

  if (!options->FastFirstHopPK || server_mode(options))
    return 0;
  else if (!router || !router->platform ||
           !tor_version_as_new_as(router->platform, "0.1.0.6-rc"))
    return 0;
  else
    return 1;
}

extern int has_completed_circuit;

/** This is the backbone function for building circuits.
 *
 * If circ's first hop is closed, then we need to build a create
 * cell and send it forward.
 *
 * Otherwise, we need to build a relay extend cell and send it
 * forward.
 *
 * Return -reason if we want to tear down circ, else return 0.
 */
int
circuit_send_next_onion_skin(origin_circuit_t *circ)
{
  crypt_path_t *hop;
  routerinfo_t *router;
  char payload[2+4+DIGEST_LEN+ONIONSKIN_CHALLENGE_LEN];
  char *onionskin;
  size_t payload_len;

  tor_assert(circ);

  if (circ->cpath->state == CPATH_STATE_CLOSED) {
    int fast;
    uint8_t cell_type;
    log_debug(LD_CIRC,"First skin; sending create cell.");

    router = router_get_by_digest(circ->_base.n_conn->identity_digest);
    fast = should_use_create_fast_for_router(router);
    if (! fast) {
      /* We are an OR, or we are connecting to an old Tor: we should
       * send an old slow create cell.
       */
      cell_type = CELL_CREATE;
      if (onion_skin_create(circ->cpath->extend_info->onion_key,
                            &(circ->cpath->dh_handshake_state),
                            payload) < 0) {
        log_warn(LD_CIRC,"onion_skin_create (first hop) failed.");
        return - END_CIRC_REASON_INTERNAL;
      }
    } else {
      /* We are not an OR, and we're building the first hop of a circuit to a
       * new OR: we can be speedy and use CREATE_FAST to save an RSA operation
       * and a DH operation. */
      cell_type = CELL_CREATE_FAST;
      memset(payload, 0, sizeof(payload));
      crypto_rand(circ->cpath->fast_handshake_state,
                  sizeof(circ->cpath->fast_handshake_state));
      memcpy(payload, circ->cpath->fast_handshake_state,
             sizeof(circ->cpath->fast_handshake_state));
    }

    if (circuit_deliver_create_cell(TO_CIRCUIT(circ), cell_type, payload) < 0)
      return - END_CIRC_REASON_RESOURCELIMIT;

    circ->cpath->state = CPATH_STATE_AWAITING_KEYS;
    circuit_set_state(TO_CIRCUIT(circ), CIRCUIT_STATE_BUILDING);
    log_info(LD_CIRC,"First hop: finished sending %s cell to '%s'",
             fast ? "CREATE_FAST" : "CREATE",
             router ? router->nickname : "<unnamed>");
  } else {
    tor_assert(circ->cpath->state == CPATH_STATE_OPEN);
    tor_assert(circ->_base.state == CIRCUIT_STATE_BUILDING);
    log_debug(LD_CIRC,"starting to send subsequent skin.");
    hop = onion_next_hop_in_cpath(circ->cpath);
    if (!hop) {
      /* done building the circuit. whew. */
      circuit_set_state(TO_CIRCUIT(circ), CIRCUIT_STATE_OPEN);
      log_info(LD_CIRC,"circuit built!");
      circuit_reset_failure_count(0);
      if (!has_completed_circuit) {
        or_options_t *options = get_options();
        has_completed_circuit=1;
        /* FFFF Log a count of known routers here */
        log(LOG_NOTICE, LD_GENERAL,
            "Tor has successfully opened a circuit. "
            "Looks like client functionality is working.");
        if (server_mode(options) && !check_whether_orport_reachable()) {
          inform_testing_reachability();
          consider_testing_reachability();
        }
      }
      circuit_rep_hist_note_result(circ);
      circuit_has_opened(circ); /* do other actions as necessary */
      return 0;
    }

    *(uint32_t*)payload = htonl(hop->extend_info->addr);
    *(uint16_t*)(payload+4) = htons(hop->extend_info->port);

    onionskin = payload+2+4;
    memcpy(payload+2+4+ONIONSKIN_CHALLENGE_LEN,
           hop->extend_info->identity_digest, DIGEST_LEN);
    payload_len = 2+4+ONIONSKIN_CHALLENGE_LEN+DIGEST_LEN;

    if (onion_skin_create(hop->extend_info->onion_key,
                          &(hop->dh_handshake_state), onionskin) < 0) {
      log_warn(LD_CIRC,"onion_skin_create failed.");
      return - END_CIRC_REASON_INTERNAL;
    }

    log_debug(LD_CIRC,"Sending extend relay cell.");
    /* send it to hop->prev, because it will transfer
     * it to a create cell and then send to hop */
    if (connection_edge_send_command(NULL, TO_CIRCUIT(circ),
                                     RELAY_COMMAND_EXTEND,
                                     payload, payload_len, hop->prev) < 0)
      return 0; /* circuit is closed */

    hop->state = CPATH_STATE_AWAITING_KEYS;
  }
  return 0;
}

/** Our clock just jumped forward by <b>seconds_elapsed</b>. Assume
 * something has also gone wrong with our network: notify the user,
 * and abandon all not-yet-used circuits. */
void
circuit_note_clock_jumped(int seconds_elapsed)
{
  if (server_mode(get_options()))
    log(LOG_WARN, LD_GENERAL,
        "Please report: your clock just jumped %d seconds forward; "
        "assuming established circuits no longer work.", seconds_elapsed);
  else
    log(LOG_NOTICE, LD_GENERAL, "Your clock just jumped %d seconds forward; "
        "assuming established circuits no longer work.", seconds_elapsed);
  has_completed_circuit=0; /* so it'll log when it works again */
  circuit_mark_all_unused_circs();
  circuit_expire_all_dirty_circs();
}

/** Take the 'extend' cell, pull out addr/port plus the onion skin. Make
 * sure we're connected to the next hop, and pass it the onion skin using
 * a create cell. Return -1 if we want to warn and tear down the circuit,
 * else return 0.
 */
int
circuit_extend(cell_t *cell, circuit_t *circ)
{
  connection_t *n_conn;
  relay_header_t rh;
  char *onionskin;
  char *id_digest=NULL;

  if (circ->n_conn) {
    log_fn(LOG_PROTOCOL_WARN,LD_PROTOCOL,
           "n_conn already set. Bug/attack. Closing.");
    return -1;
  }

  relay_header_unpack(&rh, cell->payload);

  if (rh.length < 4+2+ONIONSKIN_CHALLENGE_LEN+DIGEST_LEN) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Wrong length %d on extend cell. Closing circuit.",
           rh.length);
    return -1;
  }

  circ->n_addr = ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE));
  circ->n_port = ntohs(get_uint16(cell->payload+RELAY_HEADER_SIZE+4));

  onionskin = cell->payload+RELAY_HEADER_SIZE+4+2;
  id_digest = cell->payload+RELAY_HEADER_SIZE+4+2+ONIONSKIN_CHALLENGE_LEN;
  n_conn = connection_or_get_by_identity_digest(id_digest);

  /* If we don't have an open conn, or the conn we have is obsolete
   * (i.e. old or broken) and the other side will let us make a second
   * connection without dropping it immediately... */
  if (!n_conn || n_conn->state != OR_CONN_STATE_OPEN ||
    (n_conn->is_obsolete &&
     router_digest_version_as_new_as(id_digest,"0.1.1.9-alpha-cvs"))) {
    struct in_addr in;
    char tmpbuf[INET_NTOA_BUF_LEN];
    in.s_addr = htonl(circ->n_addr);
    tor_inet_ntoa(&in,tmpbuf,sizeof(tmpbuf));
    log_info(LD_CIRC|LD_OR,"Next router (%s:%d) not connected. Connecting.",
             tmpbuf, circ->n_port);

    circ->onionskin = tor_malloc(ONIONSKIN_CHALLENGE_LEN);
    memcpy(circ->onionskin, onionskin, ONIONSKIN_CHALLENGE_LEN);
    circuit_set_state(circ, CIRCUIT_STATE_OR_WAIT);

    /* imprint the circuit with its future n_conn->id */
    memcpy(circ->n_conn_id_digest, id_digest, DIGEST_LEN);

    if (n_conn && !n_conn->is_obsolete) {
      circ->n_addr = n_conn->addr;
      circ->n_port = n_conn->port;
    } else {
     /* we should try to open a connection */
      n_conn = connection_or_connect(circ->n_addr, circ->n_port, id_digest);
      if (!n_conn) {
        log_info(LD_CIRC,"Launching n_conn failed. Closing circuit.");
        circuit_mark_for_close(circ, END_CIRC_REASON_CONNECTFAILED);
        return 0;
      }
      log_debug(LD_CIRC,"connecting in progress (or finished). Good.");
    }
    /* return success. The onion/circuit/etc will be taken care of
     * automatically (may already have been) whenever n_conn reaches
     * OR_CONN_STATE_OPEN.
     */
    return 0;
  }

  /* these may be different if the router connected to us from elsewhere */
  circ->n_addr = n_conn->addr;
  circ->n_port = n_conn->port;

  circ->n_conn = n_conn;
  memcpy(circ->n_conn_id_digest, n_conn->identity_digest, DIGEST_LEN);
  log_debug(LD_CIRC,"n_conn is %s:%u",n_conn->address,n_conn->port);

  if (circuit_deliver_create_cell(circ, CELL_CREATE, onionskin) < 0)
    return -1;
  return 0;
}

/** Initialize cpath-\>{f|b}_{crypto|digest} from the key material in
 * key_data.  key_data must contain CPATH_KEY_MATERIAL bytes, which are
 * used as follows:
 *   - 20 to initialize f_digest
 *   - 20 to initialize b_digest
 *   - 16 to key f_crypto
 *   - 16 to key b_crypto
 *
 * (If 'reverse' is true, then f_XX and b_XX are swapped.)
 */
int
circuit_init_cpath_crypto(crypt_path_t *cpath, char *key_data, int reverse)
{
  crypto_digest_env_t *tmp_digest;
  crypto_cipher_env_t *tmp_crypto;

  tor_assert(cpath);
  tor_assert(key_data);
  tor_assert(!(cpath->f_crypto || cpath->b_crypto ||
             cpath->f_digest || cpath->b_digest));

  cpath->f_digest = crypto_new_digest_env();
  crypto_digest_add_bytes(cpath->f_digest, key_data, DIGEST_LEN);
  cpath->b_digest = crypto_new_digest_env();
  crypto_digest_add_bytes(cpath->b_digest, key_data+DIGEST_LEN, DIGEST_LEN);

  if (!(cpath->f_crypto =
        crypto_create_init_cipher(key_data+(2*DIGEST_LEN),1))) {
    log_warn(LD_BUG,"Bug: forward cipher initialization failed.");
    return -1;
  }
  if (!(cpath->b_crypto =
        crypto_create_init_cipher(key_data+(2*DIGEST_LEN)+CIPHER_KEY_LEN,0))) {
    log_warn(LD_BUG,"Bug: backward cipher initialization failed.");
    return -1;
  }

  if (reverse) {
    tmp_digest = cpath->f_digest;
    cpath->f_digest = cpath->b_digest;
    cpath->b_digest = tmp_digest;
    tmp_crypto = cpath->f_crypto;
    cpath->f_crypto = cpath->b_crypto;
    cpath->b_crypto = tmp_crypto;
  }

  return 0;
}

/** A created or extended cell came back to us on the circuit, and it included
 * <b>reply</b> as its body.  (If <b>reply_type</b> is CELL_CREATED, the body
 * contains (the second DH key, plus KH).  If <b>reply_type</b> is
 * CELL_CREATED_FAST, the body contains a secret y and a hash H(x|y).)
 *
 * Calculate the appropriate keys and digests, make sure KH is
 * correct, and initialize this hop of the cpath.
 *
 * Return - reason if we want to mark circ for close, else return 0.
 */
int
circuit_finish_handshake(origin_circuit_t *circ, uint8_t reply_type,
                         char *reply)
{
  char keys[CPATH_KEY_MATERIAL_LEN];
  crypt_path_t *hop;

  if (circ->cpath->state == CPATH_STATE_AWAITING_KEYS)
    hop = circ->cpath;
  else {
    hop = onion_next_hop_in_cpath(circ->cpath);
    if (!hop) { /* got an extended when we're all done? */
      log_warn(LD_PROTOCOL,"got extended when circ already built? Closing.");
      return - END_CIRC_REASON_TORPROTOCOL;
    }
  }
  tor_assert(hop->state == CPATH_STATE_AWAITING_KEYS);

  if (reply_type == CELL_CREATED && hop->dh_handshake_state) {
    if (onion_skin_client_handshake(hop->dh_handshake_state, reply, keys,
                                    DIGEST_LEN*2+CIPHER_KEY_LEN*2) < 0) {
      log_warn(LD_CIRC,"onion_skin_client_handshake failed.");
      return -END_CIRC_REASON_TORPROTOCOL;
    }
    /* Remember hash of g^xy */
    memcpy(hop->handshake_digest, reply+DH_KEY_LEN, DIGEST_LEN);
  } else if (reply_type == CELL_CREATED_FAST && !hop->dh_handshake_state) {
    if (fast_client_handshake(hop->fast_handshake_state, reply, keys,
                              DIGEST_LEN*2+CIPHER_KEY_LEN*2) < 0) {
      log_warn(LD_CIRC,"fast_client_handshake failed.");
      return -END_CIRC_REASON_TORPROTOCOL;
    }
    memcpy(hop->handshake_digest, reply+DIGEST_LEN, DIGEST_LEN);
  } else {
    log_warn(LD_PROTOCOL,"CREATED cell type did not match CREATE cell type.");
    return -END_CIRC_REASON_TORPROTOCOL;
  }

  if (hop->dh_handshake_state) {
    crypto_dh_free(hop->dh_handshake_state); /* don't need it anymore */
    hop->dh_handshake_state = NULL;
  }
  memset(hop->fast_handshake_state, 0, sizeof(hop->fast_handshake_state));

  if (circuit_init_cpath_crypto(hop, keys, 0)<0) {
    return -END_CIRC_REASON_TORPROTOCOL;
  }

  hop->state = CPATH_STATE_OPEN;
  log_info(LD_CIRC,"Finished building %scircuit hop:",
           (reply_type == CELL_CREATED_FAST) ? "fast " : "");
  circuit_log_path(LOG_INFO,LD_CIRC,circ);
  control_event_circuit_status(circ, CIRC_EVENT_EXTENDED);

  return 0;
}

/** We received a relay truncated cell on circ.
 *
 * Since we don't ask for truncates currently, getting a truncated
 * means that a connection broke or an extend failed. For now,
 * just give up: for circ to close, and return 0.
 */
int
circuit_truncated(origin_circuit_t *circ, crypt_path_t *layer)
{
//  crypt_path_t *victim;
//  connection_t *stream;

  tor_assert(circ);
  tor_assert(layer);

  /* XXX Since we don't ask for truncates currently, getting a truncated
   *     means that a connection broke or an extend failed. For now,
   *     just give up.
   */
  circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_AT_ORIGIN);
  return 0;

#if 0
  while (layer->next != circ->cpath) {
    /* we need to clear out layer->next */
    victim = layer->next;
    log_debug(LD_CIRC, "Killing a layer of the cpath.");

    for (stream = circ->p_streams; stream; stream=stream->next_stream) {
      if (stream->cpath_layer == victim) {
        /* XXXX NM LD_CIRC? */
        log_info(LD_APP, "Marking stream %d for close.", stream->stream_id);
        /* no need to send 'end' relay cells,
         * because the other side's already dead
         */
        connection_mark_unattached_ap(stream, END_STREAM_REASON_DESTROY);
      }
    }

    layer->next = victim->next;
    circuit_free_cpath_node(victim);
  }

  log_info(LD_CIRC, "finished");
  return 0;
#endif
}

/** Given a response payload and keys, initialize, then send a created
 * cell back.
 */
int
onionskin_answer(or_circuit_t *circ, uint8_t cell_type, char *payload,
                 char *keys)
{
  cell_t cell;
  crypt_path_t *tmp_cpath;

  tmp_cpath = tor_malloc_zero(sizeof(crypt_path_t));
  tmp_cpath->magic = CRYPT_PATH_MAGIC;

  memset(&cell, 0, sizeof(cell_t));
  cell.command = cell_type;
  cell.circ_id = circ->p_circ_id;

  circuit_set_state(TO_CIRCUIT(circ), CIRCUIT_STATE_OPEN);

  memcpy(cell.payload, payload,
         cell_type == CELL_CREATED ? ONIONSKIN_REPLY_LEN : DIGEST_LEN*2);

  log_debug(LD_CIRC,"init digest forward 0x%.8x, backward 0x%.8x.",
            (unsigned int)*(uint32_t*)(keys),
            (unsigned int)*(uint32_t*)(keys+20));
  if (circuit_init_cpath_crypto(tmp_cpath, keys, 0)<0) {
    log_warn(LD_BUG,"Circuit initialization failed");
    tor_free(tmp_cpath);
    return -1;
  }
  circ->n_digest = tmp_cpath->f_digest;
  circ->n_crypto = tmp_cpath->f_crypto;
  circ->p_digest = tmp_cpath->b_digest;
  circ->p_crypto = tmp_cpath->b_crypto;
  tmp_cpath->magic = 0;
  tor_free(tmp_cpath);

  if (cell_type == CELL_CREATED)
    memcpy(circ->handshake_digest, cell.payload+DH_KEY_LEN, DIGEST_LEN);
  else
    memcpy(circ->handshake_digest, cell.payload+DIGEST_LEN, DIGEST_LEN);

  connection_or_write_cell_to_buf(&cell, circ->p_conn);
  log_debug(LD_CIRC,"Finished sending 'created' cell.");

  if (!is_local_IP(circ->p_conn->addr) &&
      !connection_or_nonopen_was_started_here(circ->p_conn)) {
    /* record that we could process create cells from a non-local conn
     * that we didn't initiate; presumably this means that create cells
     * can reach us too. */
    router_orport_found_reachable();
  }

  return 0;
}

/** Choose a length for a circuit of purpose <b>purpose</b>.
 * Default length is 3 + the number of endpoints that would give something
 * away. If the routerlist <b>routers</b> doesn't have enough routers
 * to handle the desired path length, return as large a path length as
 * is feasible, except if it's less than 2, in which case return -1.
 */
static int
new_route_len(double cw, uint8_t purpose, extend_info_t *exit,
              smartlist_t *routers)
{
  int num_acceptable_routers;
  int routelen;

  tor_assert(cw >= 0.);
  tor_assert(cw < 1.);
  tor_assert(routers);

#ifdef TOR_PERF
  routelen = 2;
#else
  routelen = 3;
  if (exit &&
      purpose != CIRCUIT_PURPOSE_TESTING &&
      purpose != CIRCUIT_PURPOSE_S_ESTABLISH_INTRO)
    routelen++;
#endif
  log_debug(LD_CIRC,"Chosen route length %d (%d routers available).",
            routelen, smartlist_len(routers));

  num_acceptable_routers = count_acceptable_routers(routers);

  if (num_acceptable_routers < 2) {
    log_info(LD_CIRC,
             "Not enough acceptable routers (%d). Discarding this circuit.",
             num_acceptable_routers);
    return -1;
  }

  if (num_acceptable_routers < routelen) {
    log_info(LD_CIRC,"Not enough routers: cutting routelen from %d to %d.",
             routelen, num_acceptable_routers);
    routelen = num_acceptable_routers;
  }

  return routelen;
}

/** Fetch the list of predicted ports, dup it into a smartlist of
 * uint16_t's, remove the ones that are already handled by an
 * existing circuit, and return it.
 */
static smartlist_t *
circuit_get_unhandled_ports(time_t now)
{
  smartlist_t *source = rep_hist_get_predicted_ports(now);
  smartlist_t *dest = smartlist_create();
  uint16_t *tmp;
  int i;

  for (i = 0; i < smartlist_len(source); ++i) {
    tmp = tor_malloc(sizeof(uint16_t));
    memcpy(tmp, smartlist_get(source, i), sizeof(uint16_t));
    smartlist_add(dest, tmp);
  }

  circuit_remove_handled_ports(dest);
  return dest;
}

/** Return 1 if we already have circuits present or on the way for
 * all anticipated ports. Return 0 if we should make more.
 *
 * If we're returning 0, set need_uptime and need_capacity to
 * indicate any requirements that the unhandled ports have.
 */
int
circuit_all_predicted_ports_handled(time_t now, int *need_uptime,
                                    int *need_capacity)
{
  int i, enough;
  uint16_t *port;
  smartlist_t *sl = circuit_get_unhandled_ports(now);
  smartlist_t *LongLivedServices = get_options()->LongLivedPorts;
  tor_assert(need_uptime);
  tor_assert(need_capacity);
  enough = (smartlist_len(sl) == 0);
  for (i = 0; i < smartlist_len(sl); ++i) {
    port = smartlist_get(sl, i);
    if (smartlist_string_num_isin(LongLivedServices, *port))
      *need_uptime = 1;
    tor_free(port);
  }
  smartlist_free(sl);
  return enough;
}

/** Return 1 if <b>router</b> can handle one or more of the ports in
 * <b>needed_ports</b>, else return 0.
 */
static int
router_handles_some_port(routerinfo_t *router, smartlist_t *needed_ports)
{
  int i;
  uint16_t port;

  for (i = 0; i < smartlist_len(needed_ports); ++i) {
    addr_policy_result_t r;
    port = *(uint16_t *)smartlist_get(needed_ports, i);
    tor_assert(port);
    r = compare_addr_to_addr_policy(0, port, router->exit_policy);
    if (r != ADDR_POLICY_REJECTED && r != ADDR_POLICY_PROBABLY_REJECTED)
      return 1;
  }
  return 0;
}

/** How many circuits do we want simultaneously in-progress to handle
 * a given stream?
 */
#define MIN_CIRCUITS_HANDLING_STREAM 2

static int
ap_stream_wants_exit_attention(connection_t *conn)
{
  if (conn->type == CONN_TYPE_AP &&
      conn->state == AP_CONN_STATE_CIRCUIT_WAIT &&
      !conn->marked_for_close &&
      !connection_edge_is_rendezvous_stream(conn) &&
      !circuit_stream_is_being_handled(conn, 0, MIN_CIRCUITS_HANDLING_STREAM))
    return 1;
  return 0;
}

/** Return a pointer to a suitable router to be the exit node for the
 * general-purpose circuit we're about to build.
 *
 * Look through the connection array, and choose a router that maximizes
 * the number of pending streams that can exit from this router.
 *
 * Return NULL if we can't find any suitable routers.
 */
static routerinfo_t *
choose_good_exit_server_general(routerlist_t *dir, int need_uptime,
                                int need_capacity)
{
  int *n_supported;
  int i, j;
  int n_pending_connections = 0;
  connection_t **carray;
  int n_connections;
  int best_support = -1;
  int n_best_support=0;
  smartlist_t *sl, *preferredexits, *excludedexits;
  routerinfo_t *router;
  or_options_t *options = get_options();

  get_connection_array(&carray, &n_connections);

  /* Count how many connections are waiting for a circuit to be built.
   * We use this for log messages now, but in the future we may depend on it.
   */
  for (i = 0; i < n_connections; ++i) {
    if (ap_stream_wants_exit_attention(carray[i]))
      ++n_pending_connections;
  }
//  log_fn(LOG_DEBUG, "Choosing exit node; %d connections are pending",
//         n_pending_connections);
  /* Now we count, for each of the routers in the directory, how many
   * of the pending connections could possibly exit from that
   * router (n_supported[i]). (We can't be sure about cases where we
   * don't know the IP address of the pending connection.)
   */
  n_supported = tor_malloc(sizeof(int)*smartlist_len(dir->routers));
  for (i = 0; i < smartlist_len(dir->routers); ++i) {/* iterate over routers */
    router = smartlist_get(dir->routers, i);
    if (router_is_me(router)) {
      n_supported[i] = -1;
//      log_fn(LOG_DEBUG,"Skipping node %s -- it's me.", router->nickname);
      /* XXX there's probably a reverse predecessor attack here, but
       * it's slow. should we take this out? -RD
       */
      continue;
    }
    if (!router->is_running) {
      n_supported[i] = -1;
//      log_fn(LOG_DEBUG,
//           "Skipping node %s (index %d) -- directory says it's not running.",
//           router->nickname, i);
      continue; /* skip routers that are known to be down */
    }
    if (router_is_unreliable(router, need_uptime, need_capacity, 0)) {
      n_supported[i] = -1;
      continue; /* skip routers that are not suitable */
    }
    if (!router->is_valid &&
        (!(options->_AllowInvalid & ALLOW_INVALID_EXIT) ||
         router_is_unreliable(router, 1, 1, 0))) {
      /* if it's invalid, and either we don't want it or it's unsuitable */
      n_supported[i] = -1;
//      log_fn(LOG_DEBUG,"Skipping node %s (index %d) -- invalid router.",
//             router->nickname, i);
      continue; /* skip invalid routers */
    }
    if (router_exit_policy_rejects_all(router)) {
      n_supported[i] = -1;
//      log_fn(LOG_DEBUG,"Skipping node %s (index %d) -- it rejects all.",
//             router->nickname, i);
      continue; /* skip routers that reject all */
    }
    n_supported[i] = 0;
    for (j = 0; j < n_connections; ++j) { /* iterate over connections */
      if (!ap_stream_wants_exit_attention(carray[j]))
        continue; /* Skip everything but APs in CIRCUIT_WAIT */
      if (connection_ap_can_use_exit(carray[j], router)) {
        ++n_supported[i];
//        log_fn(LOG_DEBUG,"%s is supported. n_supported[%d] now %d.",
//               router->nickname, i, n_supported[i]);
      } else {
//        log_fn(LOG_DEBUG,"%s (index %d) would reject this stream.",
//               router->nickname, i);
      }
    } /* End looping over connections. */
    if (n_supported[i] > best_support) {
      /* If this router is better than previous ones, remember its index
       * and goodness, and start counting how many routers are this good. */
      best_support = n_supported[i]; n_best_support=1;
//      log_fn(LOG_DEBUG,"%s is new best supported option so far.",
//             router->nickname);
    } else if (n_supported[i] == best_support) {
      /* If this router is _as good_ as the best one, just increment the
       * count of equally good routers.*/
      ++n_best_support;
    }
  }
  log_info(LD_CIRC,
           "Found %d servers that might support %d/%d pending connections.",
           n_best_support, best_support >= 0 ? best_support : 0,
           n_pending_connections);

  preferredexits = smartlist_create();
  add_nickname_list_to_smartlist(preferredexits,options->ExitNodes,1,1,1);

  excludedexits = smartlist_create();
  add_nickname_list_to_smartlist(excludedexits,options->ExcludeNodes,0,0,1);

  sl = smartlist_create();

  /* If any routers definitely support any pending connections, choose one
   * at random. */
  if (best_support > 0) {
    for (i = 0; i < smartlist_len(dir->routers); i++)
      if (n_supported[i] == best_support)
        smartlist_add(sl, smartlist_get(dir->routers, i));

    smartlist_subtract(sl,excludedexits);
    if (options->StrictExitNodes || smartlist_overlap(sl,preferredexits))
      smartlist_intersect(sl,preferredexits);
    router = routerlist_sl_choose_by_bandwidth(sl);
  } else {
    /* Either there are no pending connections, or no routers even seem to
     * possibly support any of them.  Choose a router at random that satisfies
     * at least one predicted exit port. */

    int try;
    smartlist_t *needed_ports = circuit_get_unhandled_ports(time(NULL));

    if (best_support == -1) {
      if (need_uptime || need_capacity) {
        log_info(LD_CIRC,
                 "We couldn't find any live%s%s routers; falling back "
                 "to list of all routers.",
                 need_capacity?", fast":"",
                 need_uptime?", stable":"");
        return choose_good_exit_server_general(dir, 0, 0);
      }
      log_notice(LD_CIRC, "All routers are down or won't exit -- choosing a "
                 "doomed exit at random.");
    }
    for (try = 0; try < 2; try++) {
      /* try once to pick only from routers that satisfy a needed port,
       * then if there are none, pick from any that support exiting. */
      for (i = 0; i < smartlist_len(dir->routers); i++) {
        router = smartlist_get(dir->routers, i);
        if (n_supported[i] != -1 &&
            (try || router_handles_some_port(router, needed_ports))) {
//          log_fn(LOG_DEBUG,"Try %d: '%s' is a possibility.",
//                 try, router->nickname);
          smartlist_add(sl, router);
        }
      }

      smartlist_subtract(sl,excludedexits);
      if (options->StrictExitNodes || smartlist_overlap(sl,preferredexits))
        smartlist_intersect(sl,preferredexits);
        /* XXX sometimes the above results in null, when the requested
         * exit node is down. we should pick it anyway. */
      router = routerlist_sl_choose_by_bandwidth(sl);
      if (router)
        break;
    }
    SMARTLIST_FOREACH(needed_ports, uint16_t *, cp, tor_free(cp));
    smartlist_free(needed_ports);
  }

  smartlist_free(preferredexits);
  smartlist_free(excludedexits);
  smartlist_free(sl);
  tor_free(n_supported);
  if (router) {
    log_info(LD_CIRC, "Chose exit server '%s'", router->nickname);
    return router;
  }
  if (options->StrictExitNodes) {
    log_warn(LD_CIRC,
             "No specified exit routers seem to be running, and "
             "StrictExitNodes is set: can't choose an exit.");
  }
  return NULL;
}

/** Return a pointer to a suitable router to be the exit node for the
 * circuit of purpose <b>purpose</b> that we're about to build (or NULL
 * if no router is suitable).
 *
 * For general-purpose circuits, pass it off to
 * choose_good_exit_server_general()
 *
 * For client-side rendezvous circuits, choose a random node, weighted
 * toward the preferences in 'options'.
 */
static routerinfo_t *
choose_good_exit_server(uint8_t purpose, routerlist_t *dir,
                        int need_uptime, int need_capacity, int is_internal)
{
  or_options_t *options = get_options();
  switch (purpose) {
    case CIRCUIT_PURPOSE_C_GENERAL:
      if (is_internal) /* pick it like a middle hop */
        return router_choose_random_node(NULL, get_options()->ExcludeNodes,
               NULL, need_uptime, need_capacity, 0,
               get_options()->_AllowInvalid & ALLOW_INVALID_MIDDLE, 0);
      else
        return choose_good_exit_server_general(dir,need_uptime,need_capacity);
    case CIRCUIT_PURPOSE_C_ESTABLISH_REND:
      return router_choose_random_node(
               options->RendNodes, options->RendExcludeNodes,
               NULL, need_uptime, need_capacity, 0,
               options->_AllowInvalid & ALLOW_INVALID_RENDEZVOUS, 0);
  }
  log_warn(LD_BUG,"Bug: unhandled purpose %d", purpose);
  tor_fragile_assert();
  return NULL;
}

/** Decide a suitable length for circ's cpath, and pick an exit
 * router (or use <b>exit</b> if provided). Store these in the
 * cpath. Return 0 if ok, -1 if circuit should be closed. */
static int
onion_pick_cpath_exit(origin_circuit_t *circ, extend_info_t *exit)
{
  cpath_build_state_t *state = circ->build_state;
  routerlist_t *rl = router_get_routerlist();
  int r;

  r = new_route_len(get_options()->PathlenCoinWeight, circ->_base.purpose,
                    exit, rl->routers);
  if (r < 1) /* must be at least 1 */
    return -1;
  state->desired_path_len = r;

  if (exit) { /* the circuit-builder pre-requested one */
    log_info(LD_CIRC,"Using requested exit node '%s'", exit->nickname);
    exit = extend_info_dup(exit);
  } else { /* we have to decide one */
    routerinfo_t *router =
      choose_good_exit_server(circ->_base.purpose, rl, state->need_uptime,
                              state->need_capacity, state->is_internal);
    if (!router) {
      log_warn(LD_CIRC,"failed to choose an exit server");
      return -1;
    }
    exit = extend_info_from_router(router);
  }
  state->chosen_exit = exit;
  return 0;
}

/** Give <b>circ</b> a new exit destination to <b>exit</b>, and add a
 * hop to the cpath reflecting this. Don't send the next extend cell --
 * the caller will do this if it wants to.
 */
int
circuit_append_new_exit(origin_circuit_t *circ, extend_info_t *info)
{
  cpath_build_state_t *state;
  tor_assert(info);
  tor_assert(circ);

  state = circ->build_state;
  tor_assert(state);
  if (state->chosen_exit)
    extend_info_free(state->chosen_exit);
  state->chosen_exit = extend_info_dup(info);

  ++circ->build_state->desired_path_len;
  onion_append_hop(&circ->cpath, info);
  return 0;
}

/** Take an open <b>circ</b>, and add a new hop at the end, based on
 * <b>info</b>. Set its state back to CIRCUIT_STATE_BUILDING, and then
 * send the next extend cell to begin connecting to that hop.
 */
int
circuit_extend_to_new_exit(origin_circuit_t *circ, extend_info_t *info)
{
  circuit_append_new_exit(circ, info);
  circuit_set_state(TO_CIRCUIT(circ), CIRCUIT_STATE_BUILDING);
  if (circuit_send_next_onion_skin(circ)<0) {
    log_warn(LD_CIRC, "Couldn't extend circuit to new point '%s'.",
             info->nickname);
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_AT_ORIGIN);
    return -1;
  }
  return 0;
}

/** Return the number of routers in <b>routers</b> that are currently up
 * and available for building circuits through.
 */
static int
count_acceptable_routers(smartlist_t *routers)
{
  int i, n;
  int num=0;
  routerinfo_t *r;

  n = smartlist_len(routers);
  for (i=0;i<n;i++) {
    r = smartlist_get(routers, i);
//    log_debug(LD_CIRC,
//              "Contemplating whether router %d (%s) is a new option.",
//              i, r->nickname);
    if (r->is_running == 0) {
//      log_debug(LD_CIRC,"Nope, the directory says %d is not running.",i);
      goto next_i_loop;
    }
    if (r->is_valid == 0) {
//      log_debug(LD_CIRC,"Nope, the directory says %d is not valid.",i);
      goto next_i_loop;
      /* XXX This clause makes us count incorrectly: if AllowInvalidRouters
       * allows this node in some places, then we're getting an inaccurate
       * count. For now, be conservative and don't count it. But later we
       * should try to be smarter. */
    }
    num++;
//    log_debug(LD_CIRC,"I like %d. num_acceptable_routers now %d.",i, num);
    next_i_loop:
      ; /* C requires an explicit statement after the label */
  }

  return num;
}

/** Add <b>new_hop</b> to the end of the doubly-linked-list <b>head_ptr</b>.
 * This function is used to extend cpath by another hop.
 */
void
onion_append_to_cpath(crypt_path_t **head_ptr, crypt_path_t *new_hop)
{
  if (*head_ptr) {
    new_hop->next = (*head_ptr);
    new_hop->prev = (*head_ptr)->prev;
    (*head_ptr)->prev->next = new_hop;
    (*head_ptr)->prev = new_hop;
  } else {
    *head_ptr = new_hop;
    new_hop->prev = new_hop->next = new_hop;
  }
}

/** Pick a random server digest that's running a Tor version that
 * doesn't have the reachability bug. These are versions 0.1.1.21-cvs+
 * and 0.1.2.1-alpha+. Avoid picking authorities, since we're
 * probably already connected to them.
 *
 * We only return one, so this doesn't become stupid when the
 * whole network has upgraded. */
static char *
compute_preferred_testing_list(const char *answer)
{
  smartlist_t *choices;
  routerlist_t *rl = router_get_routerlist();
  routerinfo_t *router;
  char *s;

  if (answer) /* they have one in mind -- easy */
    return tor_strdup(answer);

  choices = smartlist_create();
  /* now count up our choices */
  SMARTLIST_FOREACH(rl->routers, routerinfo_t *, r,
    if (r->is_running && r->is_valid &&
        ((tor_version_as_new_as(r->platform,"0.1.1.21-cvs") &&
          !tor_version_as_new_as(r->platform,"0.1.2.0-alpha-cvs")) ||
         tor_version_as_new_as(r->platform,"0.1.2.1-alpha")) &&
        !router_get_trusteddirserver_by_digest(r->cache_info.identity_digest))
      smartlist_add(choices, r));
  router = smartlist_choose(choices);
  smartlist_free(choices);
  if (!router) {
    log_info(LD_CIRC, "Looking for middle server that doesn't have the "
             "reachability bug, but didn't find one. Oh well.");
    return NULL;
  }
  log_info(LD_CIRC, "Looking for middle server that doesn't have the "
             "reachability bug, and chose '%s'. Great.", router->nickname);
  s = tor_malloc(HEX_DIGEST_LEN+2);
  s[0] = '$';
  base16_encode(s+1, HEX_DIGEST_LEN+1,
                router->cache_info.identity_digest, DIGEST_LEN);
  return s;
}

/** A helper function used by onion_extend_cpath(). Use <b>purpose</b>
 * and <b>state</b> and the cpath <b>head</b> (currently populated only
 * to length <b>cur_len</b> to decide a suitable middle hop for a
 * circuit. In particular, make sure we don't pick the exit node or its
 * family, and make sure we don't duplicate any previous nodes or their
 * families. */
static routerinfo_t *
choose_good_middle_server(uint8_t purpose,
                          cpath_build_state_t *state,
                          crypt_path_t *head,
                          int cur_len)
{
  int i;
  routerinfo_t *r, *choice;
  crypt_path_t *cpath;
  smartlist_t *excluded;
  or_options_t *options = get_options();
  char *preferred = NULL;
  tor_assert(_CIRCUIT_PURPOSE_MIN <= purpose &&
             purpose <= _CIRCUIT_PURPOSE_MAX);

  log_debug(LD_CIRC, "Contemplating intermediate hop: random choice.");
  excluded = smartlist_create();
  if ((r = build_state_get_exit_router(state))) {
    smartlist_add(excluded, r);
    routerlist_add_family(excluded, r);
  }
  if ((r = routerlist_find_my_routerinfo())) {
    smartlist_add(excluded, r);
    routerlist_add_family(excluded, r);
  }
  for (i = 0, cpath = head; i < cur_len; ++i, cpath=cpath->next) {
    if ((r = router_get_by_digest(cpath->extend_info->identity_digest))) {
      smartlist_add(excluded, r);
      routerlist_add_family(excluded, r);
    }
  }
  if (purpose == CIRCUIT_PURPOSE_TESTING)
    preferred = compute_preferred_testing_list(options->TestVia);
  choice = router_choose_random_node(preferred,
           options->ExcludeNodes, excluded,
           state->need_uptime, state->need_capacity, 0,
           options->_AllowInvalid & ALLOW_INVALID_MIDDLE, 0);
  if (preferred)
    tor_free(preferred);
  smartlist_free(excluded);
  return choice;
}

/** Pick a good entry server for the circuit to be built according to
 * <b>state</b>.  Don't reuse a chosen exit (if any), don't use this
 * router (if we're an OR), and respect firewall settings; if we're
 * using entry_guards, return one.
 *
 * If <b>state</b> is NULL, we're choosing routers to serve as entry
 * nodes, not for any particular circuit.
 */
static routerinfo_t *
choose_good_entry_server(uint8_t purpose, cpath_build_state_t *state)
{
  routerinfo_t *r, *choice;
  smartlist_t *excluded;
  or_options_t *options = get_options();
  (void)purpose; /* not used yet. */

  if (state && options->UseEntryGuards) {
    return choose_random_entry(state);
  }

  excluded = smartlist_create();

  if (state && (r = build_state_get_exit_router(state))) {
    smartlist_add(excluded, r);
    routerlist_add_family(excluded, r);
  }
  if ((r = routerlist_find_my_routerinfo())) {
    smartlist_add(excluded, r);
    routerlist_add_family(excluded, r);
  }
  if (firewall_is_fascist_or()) {
    /* exclude all ORs that listen on the wrong port */
    routerlist_t *rl = router_get_routerlist();
    int i;

    for (i=0; i < smartlist_len(rl->routers); i++) {
      r = smartlist_get(rl->routers, i);
      if (!fascist_firewall_allows_address_or(r->addr,r->or_port))
        smartlist_add(excluded, r);
    }
  }
  /* and exclude current entry guards, if applicable */
  if (options->UseEntryGuards && entry_guards) {
    SMARTLIST_FOREACH(entry_guards, entry_guard_t *, entry,
      {
        if ((r = router_get_by_digest(entry->identity)))
          smartlist_add(excluded, r);
      });
  }
  // XXX we should exclude busy exit nodes here, too,
  // but only if there are enough other nodes available.
  choice = router_choose_random_node(
           NULL, options->ExcludeNodes,
           excluded, state ? state->need_uptime : 0,
           state ? state->need_capacity : 0,
           state ? 0 : 1,
           options->_AllowInvalid & ALLOW_INVALID_ENTRY, 0);
  smartlist_free(excluded);
  return choice;
}

/** Return the first non-open hop in cpath, or return NULL if all
 * hops are open. */
static crypt_path_t *
onion_next_hop_in_cpath(crypt_path_t *cpath)
{
  crypt_path_t *hop = cpath;
  do {
    if (hop->state != CPATH_STATE_OPEN)
      return hop;
    hop = hop->next;
  } while (hop != cpath);
  return NULL;
}

/** Choose a suitable next hop in the cpath <b>head_ptr</b>,
 * based on <b>state</b>. Append the hop info to head_ptr.
 */
static int
onion_extend_cpath(uint8_t purpose, crypt_path_t **head_ptr,
                   cpath_build_state_t *state)
{
  int cur_len;
  crypt_path_t *cpath;
  extend_info_t *info = NULL;

  tor_assert(head_ptr);

  if (!*head_ptr) {
    cur_len = 0;
  } else {
    cur_len = 1;
    for (cpath = *head_ptr; cpath->next != *head_ptr; cpath = cpath->next) {
      ++cur_len;
    }
  }

  if (cur_len >= state->desired_path_len) {
    log_debug(LD_CIRC, "Path is complete: %d steps long",
              state->desired_path_len);
    return 1;
  }

  log_debug(LD_CIRC, "Path is %d long; we want %d", cur_len,
            state->desired_path_len);

  if (cur_len == state->desired_path_len - 1) { /* Picking last node */
    info = extend_info_dup(state->chosen_exit);
  } else if (cur_len == 0) { /* picking first node */
    routerinfo_t *r = choose_good_entry_server(purpose, state);
    if (r)
      info = extend_info_from_router(r);
  } else {
    routerinfo_t *r =
      choose_good_middle_server(purpose, state, *head_ptr, cur_len);
    if (r)
      info = extend_info_from_router(r);
  }

  if (!info) {
    log_warn(LD_CIRC,"Failed to find node for hop %d of our path. Discarding "
             "this circuit.", cur_len);
    return -1;
  }

  log_debug(LD_CIRC,"Chose router %s for hop %d (exit is %s)",
            info->nickname, cur_len+1, build_state_get_exit_nickname(state));

  onion_append_hop(head_ptr, info);
  extend_info_free(info);
  return 0;
}

/** Create a new hop, annotate it with information about its
 * corresponding router <b>choice</b>, and append it to the
 * end of the cpath <b>head_ptr</b>. */
static int
onion_append_hop(crypt_path_t **head_ptr, extend_info_t *choice)
{
  crypt_path_t *hop = tor_malloc_zero(sizeof(crypt_path_t));

  /* link hop into the cpath, at the end. */
  onion_append_to_cpath(head_ptr, hop);

  hop->magic = CRYPT_PATH_MAGIC;
  hop->state = CPATH_STATE_CLOSED;

  hop->extend_info = extend_info_dup(choice);

  hop->package_window = CIRCWINDOW_START;
  hop->deliver_window = CIRCWINDOW_START;

  return 0;
}

/** Allocate and return a new extend_info_t that can be used to build a
 * circuit to or through the router <b>r</b>. */
extend_info_t *
extend_info_from_router(routerinfo_t *r)
{
  extend_info_t *info;
  tor_assert(r);
  info = tor_malloc_zero(sizeof(extend_info_t));
  strlcpy(info->nickname, r->nickname, sizeof(info->nickname));
  memcpy(info->identity_digest, r->cache_info.identity_digest, DIGEST_LEN);
  info->onion_key = crypto_pk_dup_key(r->onion_pkey);
  info->addr = r->addr;
  info->port = r->or_port;
  return info;
}

/** Release storage held by an extend_info_t struct. */
void
extend_info_free(extend_info_t *info)
{
  tor_assert(info);
  crypto_free_pk_env(info->onion_key);
  tor_free(info);
}

/** Allocate and return a new extend_info_t with the same contents as
 * <b>info</b>. */
extend_info_t *
extend_info_dup(extend_info_t *info)
{
  extend_info_t *newinfo;
  tor_assert(info);
  newinfo = tor_malloc(sizeof(extend_info_t));
  memcpy(newinfo, info, sizeof(extend_info_t));
  newinfo->onion_key = crypto_pk_dup_key(info->onion_key);
  return newinfo;
}

/** Return the routerinfo_t for the chosen exit router in <b>state</b>.
 * If there is no chosen exit, or if we don't know the routerinfo_t for
 * the chosen exit, return NULL.
 */
routerinfo_t *
build_state_get_exit_router(cpath_build_state_t *state)
{
  if (!state || !state->chosen_exit)
    return NULL;
  return router_get_by_digest(state->chosen_exit->identity_digest);
}

/** Return the nickname for the chosen exit router in <b>state</b>. If
 * there is no chosen exit, or if we don't know the routerinfo_t for the
 * chosen exit, return NULL.
 */
const char *
build_state_get_exit_nickname(cpath_build_state_t *state)
{
  if (!state || !state->chosen_exit)
    return NULL;
  return state->chosen_exit->nickname;
}

/** Return the router corresponding to <b>e</b>, if <b>e</b> is
 * working well enough that we are willing to use it as an entry
 * right now. (Else return NULL.) In particular, it must be
 * - Listed as either up or never yet contacted;
 * - Present in the routerlist;
 * - Listed as 'stable' or 'fast' by the current dirserver concensus,
 *   if demanded by <b>need_uptime</b> or <b>need_capacity</b>; and
 * - Allowed by our current ReachableAddresses config option.
 */
static INLINE routerinfo_t *
entry_is_live(entry_guard_t *e, int need_uptime, int need_capacity)
{
  routerinfo_t *r;
  if (e->down_since && e->made_contact)
    return NULL;
  r = router_get_by_digest(e->identity);
  if (!r)
    return NULL;
  if (router_is_unreliable(r, need_uptime, need_capacity, 0))
    return NULL;
  if (firewall_is_fascist_or() &&
      !fascist_firewall_allows_address_or(r->addr,r->or_port))
    return NULL;
  return r;
}

/** Return the number of entry guards that we think are usable. */
static int
num_live_entry_guards(void)
{
  int n = 0;
  if (! entry_guards)
    return 0;
  SMARTLIST_FOREACH(entry_guards, entry_guard_t *, entry,
    {
      if (entry_is_live(entry, 0, 1))
        ++n;
    });
  return n;
}

/** Return 1 if <b>digest</b> matches the identity of any node
 * in the entry_guards list. Else return 0. */
static INLINE int
is_an_entry_guard(char *digest)
{
  SMARTLIST_FOREACH(entry_guards, entry_guard_t *, entry,
                    if (!memcmp(digest, entry->identity, DIGEST_LEN))
                      return 1;
                   );
  return 0;
}

static void
log_entry_guards(int severity)
{
  smartlist_t *elements = smartlist_create();
  char buf[1024];
  char *s;

  SMARTLIST_FOREACH(entry_guards, entry_guard_t *, e,
    {
      tor_snprintf(buf, sizeof(buf), "%s (%s%s%s)",
                   e->nickname,
                   (e->down_since || e->unlisted_since) ? "down " : "up ",
                   e->unlisted_since ? "unlisted " : "listed ",
                   e->made_contact ? "made-contact" : "never-contacted");
      smartlist_add(elements, tor_strdup(buf));
    });

  s = smartlist_join_strings(elements, ",", 0, NULL);
  SMARTLIST_FOREACH(elements, char*, cp, tor_free(cp));
  smartlist_free(elements);
  log_fn(severity,LD_CIRC,"%s",s);
  tor_free(s);
}

#define NUM_ENTRY_PICK_TRIES 100

/** Add a new (preferably stable and fast) router to our
 * entry_guards list. Return a pointer to the router if we succeed,
 * or NULL if we can't find any more suitable entries.
 *
 * If <b>chosen</b> is defined, use that one, and if it's not
 * already in our entry_guards list, put it at the *beginning*.
 * Else, put the one we pick at the end of the list. */
static routerinfo_t *
add_an_entry_guard(routerinfo_t *chosen)
{
  routerinfo_t *router;
  entry_guard_t *entry;

  if (chosen) {
    router = chosen;
    if (is_an_entry_guard(router->cache_info.identity_digest))
      return NULL;
  } else {
    router = choose_good_entry_server(CIRCUIT_PURPOSE_C_GENERAL, NULL);
    if (!router)
      return NULL;
  }
  entry = tor_malloc_zero(sizeof(entry_guard_t));
  log_info(LD_CIRC, "Chose '%s' as new entry guard.", router->nickname);
  strlcpy(entry->nickname, router->nickname, sizeof(entry->nickname));
  memcpy(entry->identity, router->cache_info.identity_digest, DIGEST_LEN);
  if (chosen) /* prepend */
    smartlist_insert(entry_guards, 0, entry);
  else /* append */
    smartlist_add(entry_guards, entry);
  log_entry_guards(LOG_INFO);
  return router;
}

/** If the use of entry guards is configured, choose more entry guards
 * until we have enough in the list. */
static void
pick_entry_guards(void)
{
  or_options_t *options = get_options();
  int changed = 0;

  tor_assert(entry_guards);

  while (num_live_entry_guards() < options->NumEntryGuards) {
    if (!add_an_entry_guard(NULL))
      break;
    changed = 1;
  }
  if (changed)
    entry_guards_changed();
}

/** Release all storage held by the list of entry guards. */
void
entry_guards_free_all(void)
{
  if (entry_guards) {
    SMARTLIST_FOREACH(entry_guards, entry_guard_t *, e, tor_free(e));
    smartlist_free(entry_guards);
    entry_guards = NULL;
  }
}

/** How long (in seconds) do we allow an entry guard to be nonfunctional
 * before we give up on it? */
#define ENTRY_ALLOW_DOWNTIME (30*24*60*60)
/** How long (in seconds) do we allow an entry guard to be unlisted in the
 * directory before we give up on it? */
#define ENTRY_ALLOW_UNLISTED (30*24*60*60)

/** Remove all entry guards that have been down or unlisted for so
 * long that we don't think they'll come up again. Return 1 if we
 * removed any, or 0 if we did nothing. */
static int
remove_dead_entries(void)
{
  char dbuf[HEX_DIGEST_LEN+1];
  char tbuf[ISO_TIME_LEN+1];
  time_t now = time(NULL);
  int i;
  int changed = 0;

  for (i = 0; i < smartlist_len(entry_guards); ) {
    entry_guard_t *entry = smartlist_get(entry_guards, i);
    const char *why = NULL;
    time_t since = 0;
    if (entry->unlisted_since &&
        entry->unlisted_since + ENTRY_ALLOW_UNLISTED < now) {
      why = "unlisted";
      since = entry->unlisted_since;
    } else if (entry->down_since &&
               entry->down_since + ENTRY_ALLOW_DOWNTIME < now) {
      why = "down";
      since = entry->down_since;
    }
    if (why) {
      base16_encode(dbuf, sizeof(dbuf), entry->identity, DIGEST_LEN);
      format_local_iso_time(tbuf, since);
      log_info(LD_CIRC,
               "Entry guard '%s' (%s) has been %s since %s; removing.",
               entry->nickname, dbuf, why, tbuf);
      tor_free(entry);
      smartlist_del_keeporder(entry_guards, i);
      log_entry_guards(LOG_INFO);
      changed = 1;
    } else
      ++i;
  }
  return changed ? 1 : 0;
}

/** A new directory or router-status has arrived; update the down/listed
 * status of the entry guards.
 *
 * An entry is 'down' if the directory lists it as nonrunning.
 * An entry is 'unlisted' if the directory doesn't include it.
 */
void
entry_guards_set_status_from_directory(void)
{
  /* Don't call this on startup; only on a fresh download.  Otherwise we'll
   * think that things are unlisted. */
  routerlist_t *routers;
  time_t now;
  int changed = 0;
  int severity = LOG_INFO;
  if (! entry_guards)
    return;

  routers = router_get_routerlist();

  now = time(NULL);

  SMARTLIST_FOREACH(entry_guards, entry_guard_t *, entry,
    {
      routerinfo_t *r = router_get_by_digest(entry->identity);
      if (! r) {
        if (! entry->unlisted_since) {
          entry->unlisted_since = time(NULL);
          changed = 1;
          log_info(LD_CIRC,"Entry guard '%s' is not listed by directories.",
                   entry->nickname);
          severity = LOG_INFO;
        }
      } else {
        if (entry->unlisted_since) {
          log_info(LD_CIRC,"Entry guard '%s' is listed again by directories.",
                   entry->nickname);
          changed = 1;
          severity = LOG_INFO;
        }
        entry->unlisted_since = 0;
        if (! r->is_running) {
          if (! entry->down_since) {
            entry->down_since = now;
            log_info(LD_CIRC, "Entry guard '%s' is now down.",
                     entry->nickname);
            changed = 1;
            severity = LOG_INFO;
          }
        } else {
          if (entry->down_since) {
            log_info(LD_CIRC,"Entry guard '%s' is up in latest directories.",
                     entry->nickname);
            changed = 1;
          }
          entry->down_since = 0;
        }
      }
      log_info(LD_CIRC, "Summary: Entry '%s' is %s, %s, and %s.",
               entry->nickname,
               (entry->down_since || entry->unlisted_since) ? "down" : "up",
               entry->unlisted_since ? "unlisted" : "listed",
               entry_is_live(entry, 0, 1) ? "live" : "not live");
    });

  if (remove_dead_entries())
    changed = 1;

  if (changed) {
    log_fn(severity, LD_CIRC, "    (%d/%d entry guards are usable/new)",
           num_live_entry_guards(), smartlist_len(entry_guards));
    log_entry_guards(LOG_INFO);
    entry_guards_changed();
  }
}

/** Called when a connection to an OR with the identity digest <b>digest</b>
 * is established (<b>succeeded</b>==1) or has failed (<b>succeeded</b>==0).
 * If the OR is an entry, change that entry's up/down status.
 * Return 0 normally, or -1 if we want to tear down the new connection.
 */
int
entry_guard_set_status(const char *digest, int succeeded)
{
  int changed = 0;
  int refuse_conn = 0;

  if (! entry_guards)
    return 0;

  SMARTLIST_FOREACH(entry_guards, entry_guard_t *, entry,
    {
      if (!memcmp(entry->identity, digest, DIGEST_LEN)) {
        if (succeeded) {
          if (!entry->made_contact) {
            /* We've just added a new long-term entry guard. Perhaps
             * the network just came back? We should give our earlier
             * entries another try too, and close this connection so
             * we don't use it before we've given the others a shot. */
            entry->made_contact = 1;
            SMARTLIST_FOREACH(entry_guards, entry_guard_t *, e,
              {
                routerinfo_t *r;
                if (e == entry)
                  break;
                if (e->made_contact) {
                  e->down_since = 0;
                  r = entry_is_live(e, 0, 1);
                  if (r) {
                    refuse_conn = 1;
                    r->is_running = 1;
                  }
                }
              });
            log_info(LD_CIRC,
                     "Connected to new entry guard '%s'. Marking earlier "
                     "entry guards up. %d/%d entry guards usable/new.",
                     entry->nickname,
                     num_live_entry_guards(), smartlist_len(entry_guards));
            log_entry_guards(LOG_INFO);
            changed = 1;
          }
          if (entry->down_since) {
            entry->down_since = 0;
            log_info(LD_CIRC,
                  "Connection to formerly down entry guard '%s' succeeded. "
                  "%d/%d entry guards usable/new.", entry->nickname,
                  num_live_entry_guards(), smartlist_len(entry_guards));
            log_entry_guards(LOG_INFO);
            changed = 1;
          }
        } else {
          if (!entry->made_contact) { /* dump him */
            log_info(LD_CIRC,
                   "Connection to never-contacted entry guard '%s' failed. "
                   "Removing from the list. %d/%d entry guards usable/new.",
                   entry->nickname,
                   num_live_entry_guards()-1, smartlist_len(entry_guards)-1);
            tor_free(entry);
            smartlist_del_keeporder(entry_guards, entry_sl_idx);
            log_entry_guards(LOG_INFO);
            changed = 1;
          } else if (!entry->down_since) {
            entry->down_since = time(NULL);
            log_info(LD_CIRC, "Connection to entry guard '%s' failed. "
                     "%d/%d entry guards usable/new.",
                     entry->nickname,
                     num_live_entry_guards(), smartlist_len(entry_guards));
            log_entry_guards(LOG_INFO);
            changed = 1;
          }
        }
      }
    });

  if (changed)
    entry_guards_changed();
  return refuse_conn ? -1 : 0;
}

/** When we try to choose an entry guard, should we parse and add
 * config's EntryNodes first? */
static int should_add_entry_nodes = 0;

void
entry_nodes_should_be_added(void)
{
  log_info(LD_CIRC, "New EntryNodes config option detected. Will use.");
  should_add_entry_nodes = 1;
}

void
entry_guards_prepend_from_config(void)
{
  int missed_some = 0;
  int idx;
  or_options_t *options = get_options();
  smartlist_t *routers = smartlist_create();
  smartlist_t *tmp = smartlist_create();

  tor_assert(entry_guards);
  tor_assert(options->EntryNodes);

  if (options->StrictEntryNodes) {
    log_info(LD_CIRC,"Clearing old entry guards");
    SMARTLIST_FOREACH(entry_guards, entry_guard_t *, e, tor_free(e));
    smartlist_clear(entry_guards);
    entry_guards_changed();
  }

  add_nickname_list_to_smartlist(routers, options->EntryNodes,
                                 0, 1, 1);

  /* take a moment first to notice whether we got them all */
  log_info(LD_CIRC,"Adding configured EntryNodes '%s'.",
           options->EntryNodes);
  smartlist_split_string(tmp, options->EntryNodes, ",",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  missed_some = smartlist_len(routers) != smartlist_len(tmp);
  SMARTLIST_FOREACH(tmp, char *, nick, tor_free(nick));
  smartlist_free(tmp);

  for (idx = smartlist_len(routers)-1 ; idx >= 0; idx--) {
    /* pick off the last one, turn it into a router, prepend it
     * to our entry_guards list. If we can't find it, set missed_some
     * to 1. */
    routerinfo_t *r = smartlist_get(routers, idx);
    add_an_entry_guard(r);
  }

  if (!missed_some)
    should_add_entry_nodes = 0; /* whew, we're done */

  smartlist_free(routers);
}

/** Pick a live (up and listed) entry guard from entry_guards, and
 * make sure not to pick this circuit's exit. */
static routerinfo_t *
choose_random_entry(cpath_build_state_t *state)
{
  or_options_t *options = get_options();
  smartlist_t *live_entry_guards = smartlist_create();
  routerinfo_t *chosen_exit = build_state_get_exit_router(state);
  routerinfo_t *r = NULL;
  int need_uptime = state->need_uptime;
  int need_capacity = state->need_capacity;

  if (!entry_guards)
    entry_guards = smartlist_create();

  if (should_add_entry_nodes)
    entry_guards_prepend_from_config();

  if (!options->StrictEntryNodes &&
      (! entry_guards ||
       smartlist_len(entry_guards) < options->NumEntryGuards))
    pick_entry_guards();

 retry:
  smartlist_clear(live_entry_guards);
  SMARTLIST_FOREACH(entry_guards, entry_guard_t *, entry,
    {
      r = entry_is_live(entry, need_uptime, need_capacity);
      if (r && r != chosen_exit) {
        smartlist_add(live_entry_guards, r);
        if (smartlist_len(live_entry_guards) >= options->NumEntryGuards)
          break; /* we have enough */
      }
    });

  /* Try to have at least 2 choices available. This way we don't
   * get stuck with a single live-but-crummy entry and just keep
   * using him.
   * (We might get 2 live-but-crummy entry guards, but so be it.) */
  if (smartlist_len(live_entry_guards) < 2) {
    if (need_uptime) {
      need_uptime = 0; /* try without that requirement */
      goto retry;
    }
    if (!options->StrictEntryNodes) {
      /* still no? try adding a new entry then */
      r = add_an_entry_guard(NULL);
      if (r) {
        smartlist_add(live_entry_guards, r);
        entry_guards_changed();
      }
    }
    if (!r && need_capacity) {
        /* still no? last attempt, try without requiring capacity */
        need_capacity = 0;
        goto retry;
    }
    /* live_entry_guards will be empty below. Oh well, we tried. */
  }

  r = smartlist_choose(live_entry_guards);
  smartlist_free(live_entry_guards);
  return r;
}

/** Parse <b>state</b> and learn about the entry guards it describes.
 * If <b>set</b> is true, and there are no errors, replace the global
 * entry_list with what we find.
 * On success, return 0. On failure, alloc into *<b>msg</b> a string
 * describing the error, and return -1.
 */
int
entry_guards_parse_state(or_state_t *state, int set, char **msg)
{
  entry_guard_t *node = NULL;
  smartlist_t *new_entry_guards = smartlist_create();
  config_line_t *line;

  *msg = NULL;
  for (line = state->EntryGuards; line; line = line->next) {
    if (!strcasecmp(line->key, "EntryGuard")) {
      smartlist_t *args = smartlist_create();
      node = tor_malloc_zero(sizeof(entry_guard_t));
      /* all entry guards on disk have been contacted */
      node->made_contact = 1;
      smartlist_add(new_entry_guards, node);
      smartlist_split_string(args, line->value, " ",
                             SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
      if (smartlist_len(args)<2) {
        *msg = tor_strdup("Unable to parse entry nodes: "
                          "Too few arguments to EntryGuard");
      } else if (!is_legal_nickname(smartlist_get(args,0))) {
        *msg = tor_strdup("Unable to parse entry nodes: "
                          "Bad nickname for EntryGuard");
      } else {
        strlcpy(node->nickname, smartlist_get(args,0), MAX_NICKNAME_LEN+1);
        if (base16_decode(node->identity, DIGEST_LEN, smartlist_get(args,1),
                          strlen(smartlist_get(args,1)))<0) {
          *msg = tor_strdup("Unable to parse entry nodes: "
                            "Bad hex digest for EntryGuard");
        }
      }
      SMARTLIST_FOREACH(args, char*, cp, tor_free(cp));
      smartlist_free(args);
      if (*msg)
        break;
    } else {
      time_t when;
      if (!node) {
        *msg = tor_strdup("Unable to parse entry nodes: "
               "EntryGuardDownSince/UnlistedSince without EntryGuard");
        break;
      }
      if (parse_iso_time(line->value, &when)<0) {
        *msg = tor_strdup("Unable to parse entry nodes: "
                          "Bad time in EntryGuardDownSince/UnlistedSince");
        break;
      }
      if (!strcasecmp(line->key, "EntryGuardDownSince"))
        node->down_since = when;
      else
        node->unlisted_since = when;
    }
  }

  if (*msg || !set) {
    SMARTLIST_FOREACH(new_entry_guards, entry_guard_t *, e, tor_free(e));
    smartlist_free(new_entry_guards);
  } else { /* !*err && set */
    if (entry_guards) {
      SMARTLIST_FOREACH(entry_guards, entry_guard_t *, e, tor_free(e));
      smartlist_free(entry_guards);
    }
    entry_guards = new_entry_guards;
    entry_guards_dirty = 0;
  }
  return *msg ? -1 : 0;
}

/** Our list of entry guards has changed, or some element of one
 * of our entry guards has changed. Write the changes to disk. */
static void
entry_guards_changed(void)
{
  entry_guards_dirty = 1;

  or_state_save();
}

/** If the entry guard info has not changed, do nothing and return.
 * Otherwise, free the EntryGuards piece of <b>state</b> and create
 * a new one out of the global entry_guards list, and then mark
 * <b>state</b> dirty so it will get saved to disk.
 */
void
entry_guards_update_state(or_state_t *state)
{
  config_line_t **next, *line;
  if (! entry_guards_dirty)
    return;

  config_free_lines(state->EntryGuards);
  next = &state->EntryGuards;
  *next = NULL;
  if (!entry_guards)
    entry_guards = smartlist_create();
  SMARTLIST_FOREACH(entry_guards, entry_guard_t *, e,
    {
      char dbuf[HEX_DIGEST_LEN+1];
      if (!e->made_contact)
        continue; /* don't write this one to disk */
      *next = line = tor_malloc_zero(sizeof(config_line_t));
      line->key = tor_strdup("EntryGuard");
      line->value = tor_malloc(HEX_DIGEST_LEN+MAX_NICKNAME_LEN+2);
      base16_encode(dbuf, sizeof(dbuf), e->identity, DIGEST_LEN);
      tor_snprintf(line->value,HEX_DIGEST_LEN+MAX_NICKNAME_LEN+2,
                   "%s %s", e->nickname, dbuf);
      next = &(line->next);
      if (e->down_since) {
        *next = line = tor_malloc_zero(sizeof(config_line_t));
        line->key = tor_strdup("EntryGuardDownSince");
        line->value = tor_malloc(ISO_TIME_LEN+1);
        format_iso_time(line->value, e->down_since);
        next = &(line->next);
      }
      if (e->unlisted_since) {
        *next = line = tor_malloc_zero(sizeof(config_line_t));
        line->key = tor_strdup("EntryGuardUnlistedSince");
        line->value = tor_malloc(ISO_TIME_LEN+1);
        format_iso_time(line->value, e->unlisted_since);
        next = &(line->next);
      }
    });
  state->dirty = 1;
  entry_guards_dirty = 0;
}

/** If <b>question</b> is the string "entry-guards", then dump
 * to *<b>answer</b> a newly allocated string describing all of
 * the nodes in the global entry_guards list. See control-spec.txt
 * for details.
 * For backward compatibility, we also handle the string "helper-nodes".
 * */
int
entry_guards_getinfo(const char *question, char **answer)
{
  if (!strcmp(question,"entry-guards") ||
      !strcmp(question,"helper-nodes")) {
    smartlist_t *sl = smartlist_create();
    char tbuf[ISO_TIME_LEN+1];
    char dbuf[HEX_DIGEST_LEN+1];
    if (!entry_guards)
      entry_guards = smartlist_create();
    SMARTLIST_FOREACH(entry_guards, entry_guard_t *, e,
      {
        size_t len = HEX_DIGEST_LEN+ISO_TIME_LEN+32;
        char *c = tor_malloc(len);
        const char *status = NULL;
        time_t when = 0;
        if (!e->made_contact) {
          status = "never-connected";
        } else if (e->unlisted_since) {
          when = e->unlisted_since;
          status = "unlisted";
        } else if (e->down_since) {
          when = e->down_since;
          status = "down";
        } else {
          status = "up";
        }
        base16_encode(dbuf, sizeof(dbuf), e->identity, DIGEST_LEN);
        if (when) {
          format_iso_time(tbuf, when);
          tor_snprintf(c, len, "$%s %s %s\n", dbuf, status, tbuf);
        } else {
          tor_snprintf(c, len, "$%s %s\n", dbuf, status);
        }
        smartlist_add(sl, c);
      });
    *answer = smartlist_join_strings(sl, "", 0, NULL);
    SMARTLIST_FOREACH(sl, char *, c, tor_free(c));
    smartlist_free(sl);
  }
  return 0;
}

