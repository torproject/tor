/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2007, Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char circuituse_c_id[] =
  "$Id$";

/**
 * \file circuituse.c
 * \brief Launch the right sort of circuits and attach streams to them.
 **/

#include "or.h"

/********* START VARIABLES **********/

extern circuit_t *global_circuitlist; /* from circuitlist.c */

/********* END VARIABLES ************/

static void circuit_expire_old_circuits(time_t now);
static void circuit_increment_failure_count(void);

/** Return 1 if <b>circ</b> could be returned by circuit_get_best().
 * Else return 0.
 */
static int
circuit_is_acceptable(circuit_t *circ, edge_connection_t *conn,
                      int must_be_open, uint8_t purpose,
                      int need_uptime, int need_internal,
                      time_t now)
{
  routerinfo_t *exitrouter;
  cpath_build_state_t *build_state;
  tor_assert(circ);
  tor_assert(conn);
  tor_assert(conn->socks_request);

  if (!CIRCUIT_IS_ORIGIN(circ))
    return 0; /* this circ doesn't start at us */
  if (must_be_open && (circ->state != CIRCUIT_STATE_OPEN || !circ->n_conn))
    return 0; /* ignore non-open circs */
  if (circ->marked_for_close)
    return 0;

  /* if this circ isn't our purpose, skip. */
  if (purpose == CIRCUIT_PURPOSE_C_REND_JOINED && !must_be_open) {
    if (circ->purpose != CIRCUIT_PURPOSE_C_ESTABLISH_REND &&
        circ->purpose != CIRCUIT_PURPOSE_C_REND_READY &&
        circ->purpose != CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED &&
        circ->purpose != CIRCUIT_PURPOSE_C_REND_JOINED)
      return 0;
  } else if (purpose == CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT &&
             !must_be_open) {
    if (circ->purpose != CIRCUIT_PURPOSE_C_INTRODUCING &&
        circ->purpose != CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT)
      return 0;
  } else {
    if (purpose != circ->purpose)
      return 0;
  }

  if (purpose == CIRCUIT_PURPOSE_C_GENERAL)
    if (circ->timestamp_dirty &&
       circ->timestamp_dirty+get_options()->MaxCircuitDirtiness <= now)
      return 0;

  /* decide if this circ is suitable for this conn */

  /* for rend circs, circ->cpath->prev is not the last router in the
   * circuit, it's the magical extra bob hop. so just check the nickname
   * of the one we meant to finish at.
   */
  build_state = TO_ORIGIN_CIRCUIT(circ)->build_state;
  exitrouter = build_state_get_exit_router(build_state);

  if (need_uptime && !build_state->need_uptime)
    return 0;
  if (need_internal != build_state->is_internal)
    return 0;

  if (purpose == CIRCUIT_PURPOSE_C_GENERAL) {
    if (!exitrouter) {
      log_debug(LD_CIRC,"Not considering circuit with unknown router.");
      return 0; /* this circuit is screwed and doesn't know it yet,
                 * or is a rendezvous circuit. */
    }
    if (build_state->onehop_tunnel) {
      if (conn->socks_request->command != SOCKS_COMMAND_CONNECT_DIR) {
        log_debug(LD_CIRC,"Skipping one-hop circuit.");
        return 0;
      }
    } else {
      if (conn->socks_request->command == SOCKS_COMMAND_CONNECT_DIR) {
        /* don't use three-hop circuits -- that could hurt our anonymity. */
        log_debug(LD_CIRC,"Skipping multi-hop circuit for CONNECT_DIR.");
        return 0;
      }
    }
    if (!connection_ap_can_use_exit(conn, exitrouter)) {
      /* can't exit from this router */
      return 0;
    }
  } else { /* not general */
    if (rend_cmp_service_ids(conn->rend_query,
                             TO_ORIGIN_CIRCUIT(circ)->rend_query)) {
      /* this circ is not for this conn */
      return 0;
    }
  }
  return 1;
}

/** Return 1 if circuit <b>a</b> is better than circuit <b>b</b> for
 * <b>purpose</b>, and return 0 otherwise. Used by circuit_get_best.
 */
static int
circuit_is_better(circuit_t *a, circuit_t *b, uint8_t purpose)
{
  switch (purpose) {
    case CIRCUIT_PURPOSE_C_GENERAL:
      /* if it's used but less dirty it's best;
       * else if it's more recently created it's best
       */
      if (b->timestamp_dirty) {
        if (a->timestamp_dirty &&
            a->timestamp_dirty > b->timestamp_dirty)
          return 1;
      } else {
        if (a->timestamp_dirty ||
            a->timestamp_created > b->timestamp_created)
          return 1;
        if (CIRCUIT_IS_ORIGIN(b) &&
            TO_ORIGIN_CIRCUIT(b)->build_state->is_internal)
          return 1;
      }
      break;
    case CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT:
      /* the closer it is to ack_wait the better it is */
      if (a->purpose > b->purpose)
        return 1;
      break;
    case CIRCUIT_PURPOSE_C_REND_JOINED:
      /* the closer it is to rend_joined the better it is */
      if (a->purpose > b->purpose)
        return 1;
      break;
  }
  return 0;
}

/** Find the best circ that conn can use, preferably one which is
 * dirty. Circ must not be too old.
 *
 * Conn must be defined.
 *
 * If must_be_open, ignore circs not in CIRCUIT_STATE_OPEN.
 *
 * circ_purpose specifies what sort of circuit we must have.
 * It can be C_GENERAL, C_INTRODUCE_ACK_WAIT, or C_REND_JOINED.
 *
 * If it's REND_JOINED and must_be_open==0, then return the closest
 * rendezvous-purposed circuit that you can find.
 *
 * If it's INTRODUCE_ACK_WAIT and must_be_open==0, then return the
 * closest introduce-purposed circuit that you can find.
 */
static origin_circuit_t *
circuit_get_best(edge_connection_t *conn, int must_be_open, uint8_t purpose,
                 int need_uptime, int need_internal)
{
  circuit_t *circ, *best=NULL;
  time_t now = time(NULL);

  tor_assert(conn);

  tor_assert(purpose == CIRCUIT_PURPOSE_C_GENERAL ||
             purpose == CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT ||
             purpose == CIRCUIT_PURPOSE_C_REND_JOINED);

  for (circ=global_circuitlist;circ;circ = circ->next) {
    if (!circuit_is_acceptable(circ,conn,must_be_open,purpose,
                               need_uptime,need_internal,now))
      continue;

    /* now this is an acceptable circ to hand back. but that doesn't
     * mean it's the *best* circ to hand back. try to decide.
     */
    if (!best || circuit_is_better(circ,best,purpose))
      best = circ;
  }

  return best ? TO_ORIGIN_CIRCUIT(best) : NULL;
}

/** Close all circuits that start at us, aren't open, and were born
 * at least CircuitBuildTimeout seconds ago.
 */
void
circuit_expire_building(time_t now)
{
  circuit_t *victim, *circ = global_circuitlist;
  time_t cutoff = now - get_options()->CircuitBuildTimeout;

  while (circ) {
    victim = circ;
    circ = circ->next;
    if (!CIRCUIT_IS_ORIGIN(victim) || /* didn't originate here */
        victim->timestamp_created > cutoff || /* Not old enough to expire */
        victim->marked_for_close) /* don't mess with marked circs */
      continue;

#if 0
    /* some debug logs, to help track bugs */
    if (victim->purpose >= CIRCUIT_PURPOSE_C_INTRODUCING &&
        victim->purpose <= CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED) {
      if (!victim->timestamp_dirty)
        log_fn(LOG_DEBUG,"Considering %sopen purp %d to %s (circid %d)."
               "(clean).",
               victim->state == CIRCUIT_STATE_OPEN ? "" : "non",
               victim->purpose, victim->build_state->chosen_exit_name,
               victim->n_circ_id);
      else
        log_fn(LOG_DEBUG,"Considering %sopen purp %d to %s (circid %d). "
               "%d secs since dirty.",
               victim->state == CIRCUIT_STATE_OPEN ? "" : "non",
               victim->purpose, victim->build_state->chosen_exit_name,
               victim->n_circ_id,
               (int)(now - victim->timestamp_dirty));
    }
#endif

    /* if circ is !open, or if it's open but purpose is a non-finished
     * intro or rend, then mark it for close */
    if (victim->state == CIRCUIT_STATE_OPEN) {
      switch (victim->purpose) {
        default: /* most open circuits can be left alone. */
          continue; /* yes, continue inside a switch refers to the nearest
                     * enclosing loop. C is smart. */
        case CIRCUIT_PURPOSE_C_ESTABLISH_REND:
        case CIRCUIT_PURPOSE_C_INTRODUCING:
        case CIRCUIT_PURPOSE_S_ESTABLISH_INTRO:
          break; /* too old, need to die */
        case CIRCUIT_PURPOSE_C_REND_READY:
          /* it's a rend_ready circ -- has it already picked a query? */
          /* c_rend_ready circs measure age since timestamp_dirty,
           * because that's set when they switch purposes
           */
          if (TO_ORIGIN_CIRCUIT(victim)->rend_query[0] ||
              victim->timestamp_dirty > cutoff)
            continue;
          break;
        case CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED:
        case CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT:
          /* rend and intro circs become dirty each time they
           * make an introduction attempt. so timestamp_dirty
           * will reflect the time since the last attempt.
           */
          if (victim->timestamp_dirty > cutoff)
            continue;
          break;
      }
    }

    if (victim->n_conn)
      log_info(LD_CIRC,"Abandoning circ %s:%d:%d (state %d:%s, purpose %d)",
               victim->n_conn->_base.address, victim->n_port,
               victim->n_circ_id,
               victim->state, circuit_state_to_string(victim->state),
               victim->purpose);
    else
      log_info(LD_CIRC,"Abandoning circ %d (state %d:%s, purpose %d)",
               victim->n_circ_id, victim->state,
               circuit_state_to_string(victim->state), victim->purpose);

    circuit_log_path(LOG_INFO,LD_CIRC,TO_ORIGIN_CIRCUIT(victim));
    circuit_mark_for_close(victim, END_CIRC_REASON_TIMEOUT);
  }
}

/** Remove any elements in <b>needed_ports</b> that are handled by an
 * open or in-progress circuit.
 */
void
circuit_remove_handled_ports(smartlist_t *needed_ports)
{
  int i;
  uint16_t *port;

  for (i = 0; i < smartlist_len(needed_ports); ++i) {
    port = smartlist_get(needed_ports, i);
    tor_assert(*port);
    if (circuit_stream_is_being_handled(NULL, *port,
                                        MIN_CIRCUITS_HANDLING_STREAM)) {
//      log_debug(LD_CIRC,"Port %d is already being handled; removing.", port);
      smartlist_del(needed_ports, i--);
      tor_free(port);
    } else {
      log_debug(LD_CIRC,"Port %d is not handled.", *port);
    }
  }
}

/** Return 1 if at least <b>min</b> general-purpose non-internal circuits
 * will have an acceptable exit node for exit stream <b>conn</b> if it
 * is defined, else for "*:port".
 * Else return 0.
 */
int
circuit_stream_is_being_handled(edge_connection_t *conn,
                                uint16_t port, int min)
{
  circuit_t *circ;
  routerinfo_t *exitrouter;
  int num=0;
  time_t now = time(NULL);
  int need_uptime = smartlist_string_num_isin(get_options()->LongLivedPorts,
                                   conn ? conn->socks_request->port : port);

  for (circ=global_circuitlist;circ;circ = circ->next) {
    if (CIRCUIT_IS_ORIGIN(circ) &&
        !circ->marked_for_close &&
        circ->purpose == CIRCUIT_PURPOSE_C_GENERAL &&
        (!circ->timestamp_dirty ||
         circ->timestamp_dirty + get_options()->MaxCircuitDirtiness > now)) {
      cpath_build_state_t *build_state = TO_ORIGIN_CIRCUIT(circ)->build_state;
      if (build_state->is_internal || build_state->onehop_tunnel)
        continue;

      exitrouter = build_state_get_exit_router(build_state);
      if (exitrouter && (!need_uptime || build_state->need_uptime)) {
        int ok;
        if (conn) {
          ok = connection_ap_can_use_exit(conn, exitrouter);
        } else {
          addr_policy_result_t r = compare_addr_to_addr_policy(
              0, port, exitrouter->exit_policy);
          ok = r != ADDR_POLICY_REJECTED && r != ADDR_POLICY_PROBABLY_REJECTED;
        }
        if (ok) {
          if (++num >= min)
            return 1;
        }
      }
    }
  }
  return 0;
}

/** Don't keep more than this many unused open circuits around. */
#define MAX_UNUSED_OPEN_CIRCUITS 12

/** Figure out how many circuits we have open that are clean. Make
 * sure it's enough for all the upcoming behaviors we predict we'll have.
 * But if we have too many, close the not-so-useful ones.
 */
static void
circuit_predict_and_launch_new(void)
{
  circuit_t *circ;
  int num=0, num_internal=0, num_uptime_internal=0;
  int hidserv_needs_uptime=0, hidserv_needs_capacity=1;
  int port_needs_uptime=0, port_needs_capacity=1;
  time_t now = time(NULL);

  /* First, count how many of each type of circuit we have already. */
  for (circ=global_circuitlist;circ;circ = circ->next) {
    cpath_build_state_t *build_state;
    if (!CIRCUIT_IS_ORIGIN(circ))
      continue;
    if (circ->marked_for_close)
      continue; /* don't mess with marked circs */
    if (circ->timestamp_dirty)
      continue; /* only count clean circs */
    if (circ->purpose != CIRCUIT_PURPOSE_C_GENERAL)
      continue; /* only pay attention to general-purpose circs */
    build_state = TO_ORIGIN_CIRCUIT(circ)->build_state;
    if (build_state->onehop_tunnel)
      continue;
    num++;
    if (build_state->is_internal)
      num_internal++;
    if (build_state->need_uptime && build_state->is_internal)
      num_uptime_internal++;
  }

  /* If that's enough, then stop now. */
  if (num >= MAX_UNUSED_OPEN_CIRCUITS)
    return; /* we already have many, making more probably will hurt */

  /* Second, see if we need any more exit circuits. */
  /* check if we know of a port that's been requested recently
   * and no circuit is currently available that can handle it. */
  if (!circuit_all_predicted_ports_handled(now, &port_needs_uptime,
                                           &port_needs_capacity)) {
    log_info(LD_CIRC,
             "Have %d clean circs (%d internal), need another exit circ.",
             num, num_internal);
    circuit_launch_by_router(CIRCUIT_PURPOSE_C_GENERAL, 0, NULL,
                             port_needs_uptime, port_needs_capacity, 0);
    return;
  }

  /* Third, see if we need any more hidden service (server) circuits. */
  if (num_rend_services() && num_uptime_internal < 3) {
    log_info(LD_CIRC,
             "Have %d clean circs (%d internal), need another internal "
             "circ for my hidden service.",
             num, num_internal);
    circuit_launch_by_router(CIRCUIT_PURPOSE_C_GENERAL, 0, NULL,
                             1, 1, 1);
    return;
  }

  /* Fourth, see if we need any more hidden service (client) circuits. */
  if (rep_hist_get_predicted_internal(now, &hidserv_needs_uptime,
                                      &hidserv_needs_capacity) &&
      ((num_uptime_internal<2 && hidserv_needs_uptime) ||
        num_internal<2)) {
    log_info(LD_CIRC,
             "Have %d clean circs (%d uptime-internal, %d internal), need"
             " another hidserv circ.",
             num, num_uptime_internal, num_internal);
    circuit_launch_by_router(CIRCUIT_PURPOSE_C_GENERAL, 0, NULL,
                             hidserv_needs_uptime, hidserv_needs_capacity, 1);
    return;
  }
}

/** Build a new test circuit every 5 minutes */
#define TESTING_CIRCUIT_INTERVAL 300

/** This function is called once a second. Its job is to make sure
 * all services we offer have enough circuits available. Some
 * services just want enough circuits for current tasks, whereas
 * others want a minimum set of idle circuits hanging around.
 */
void
circuit_build_needed_circs(time_t now)
{
  static long time_to_new_circuit = 0;

  /* launch a new circ for any pending streams that need one */
  connection_ap_attach_pending();

  /* make sure any hidden services have enough intro points */
  /* XXXX012 circuit_build_needed_circs is only called at all if
   *         router_have_minimum_dir_info is true; this check is redundant,
   *         and it appears to show up on some people's profiles. */
  if (1 || router_have_minimum_dir_info())
    rend_services_introduce();

  if (time_to_new_circuit < now) {
    circuit_reset_failure_count(1);
    time_to_new_circuit = now + get_options()->NewCircuitPeriod;
    if (proxy_mode(get_options()))
      addressmap_clean(now);
    circuit_expire_old_circuits(now);

#if 0 /* disable for now, until predict-and-launch-new can cull leftovers */
    circ = circuit_get_youngest_clean_open(CIRCUIT_PURPOSE_C_GENERAL);
    if (get_options()->RunTesting &&
        circ &&
        circ->timestamp_created + TESTING_CIRCUIT_INTERVAL < now) {
      log_fn(LOG_INFO,"Creating a new testing circuit.");
      circuit_launch_by_router(CIRCUIT_PURPOSE_C_GENERAL, 0, NULL, 0, 0, 0);
    }
#endif
  }
  circuit_predict_and_launch_new();
}

/** If the stream <b>conn</b> is a member of any of the linked
 * lists of <b>circ</b>, then remove it from the list.
 */
void
circuit_detach_stream(circuit_t *circ, edge_connection_t *conn)
{
  edge_connection_t *prevconn;

  tor_assert(circ);
  tor_assert(conn);

  conn->cpath_layer = NULL; /* make sure we don't keep a stale pointer */
  conn->on_circuit = NULL;

  if (CIRCUIT_IS_ORIGIN(circ)) {
    origin_circuit_t *origin_circ = TO_ORIGIN_CIRCUIT(circ);
    if (conn == origin_circ->p_streams) {
      origin_circ->p_streams = conn->next_stream;
      return;
    }

    for (prevconn = origin_circ->p_streams;
         prevconn && prevconn->next_stream && prevconn->next_stream != conn;
         prevconn = prevconn->next_stream)
      ;
    if (prevconn && prevconn->next_stream) {
      prevconn->next_stream = conn->next_stream;
      return;
    }
  } else {
    or_circuit_t *or_circ = TO_OR_CIRCUIT(circ);
    if (conn == or_circ->n_streams) {
      or_circ->n_streams = conn->next_stream;
      return;
    }
    if (conn == or_circ->resolving_streams) {
      or_circ->resolving_streams = conn->next_stream;
      return;
    }

    for (prevconn = or_circ->n_streams;
         prevconn && prevconn->next_stream && prevconn->next_stream != conn;
         prevconn = prevconn->next_stream)
      ;
    if (prevconn && prevconn->next_stream) {
      prevconn->next_stream = conn->next_stream;
      return;
    }

    for (prevconn = or_circ->resolving_streams;
         prevconn && prevconn->next_stream && prevconn->next_stream != conn;
         prevconn = prevconn->next_stream)
      ;
    if (prevconn && prevconn->next_stream) {
      prevconn->next_stream = conn->next_stream;
      return;
    }
  }

  log_err(LD_BUG,"edge conn not in circuit's list?");
  tor_assert(0); /* should never get here */
}

/** Find each circuit that has been unused for too long, or dirty
 * for too long and has no streams on it: mark it for close.
 */
static void
circuit_expire_old_circuits(time_t now)
{
  circuit_t *circ;
  time_t cutoff = now - get_options()->CircuitIdleTimeout;

  for (circ = global_circuitlist; circ; circ = circ->next) {
    if (circ->marked_for_close || ! CIRCUIT_IS_ORIGIN(circ))
      continue;
    /* If the circuit has been dirty for too long, and there are no streams
     * on it, mark it for close.
     */
    if (circ->timestamp_dirty &&
        circ->timestamp_dirty + get_options()->MaxCircuitDirtiness < now &&
        !TO_ORIGIN_CIRCUIT(circ)->p_streams /* nothing attached */ ) {
      log_debug(LD_CIRC, "Closing n_circ_id %d (dirty %d secs ago, purp %d)",
                circ->n_circ_id, (int)(now - circ->timestamp_dirty),
                circ->purpose);
      circuit_mark_for_close(circ, END_CIRC_REASON_FINISHED);
    } else if (!circ->timestamp_dirty &&
               circ->state == CIRCUIT_STATE_OPEN &&
               circ->purpose == CIRCUIT_PURPOSE_C_GENERAL) {
      if (circ->timestamp_created < cutoff) {
        log_debug(LD_CIRC,
                  "Closing circuit that has been unused for %d seconds.",
                  (int)(now - circ->timestamp_created));
        circuit_mark_for_close(circ, END_CIRC_REASON_FINISHED);
      }
    }
  }
}

/** Number of circuits to open at once when testing our bandwidth. */
#define NUM_PARALLEL_TESTING_CIRCS 4

/** True iff we've ever opened enough testing circuits to test our
 * bandwidth. */
static int have_performed_bandwidth_test = 0;

/** Reset have_performed_bandwidth_test, so we'll start building
 * testing circuits again so we can exercise our bandwidth. */
void
reset_bandwidth_test(void)
{
  have_performed_bandwidth_test = 0;
}

/** Return 1 if we've already exercised our bandwidth, or if we
 * have fewer than NUM_PARALLEL_TESTING_CIRCS testing circuits
 * established or on the way. Else return 0.
 */
int
circuit_enough_testing_circs(void)
{
  circuit_t *circ;
  int num = 0;

  if (have_performed_bandwidth_test)
    return 1;

  for (circ = global_circuitlist; circ; circ = circ->next) {
    if (!circ->marked_for_close && CIRCUIT_IS_ORIGIN(circ) &&
        circ->purpose == CIRCUIT_PURPOSE_TESTING &&
        circ->state == CIRCUIT_STATE_OPEN)
      num++;
  }
  return num >= NUM_PARALLEL_TESTING_CIRCS;
}

/** A testing circuit has completed. Take whatever stats we want.
 * Noticing reachability is taken care of in onionskin_answer(),
 * so there's no need to record anything here. But if we still want
 * to do the bandwidth test, and we now have enough testing circuits
 * open, do it.
 */
static void
circuit_testing_opened(origin_circuit_t *circ)
{
  if (have_performed_bandwidth_test) {
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_AT_ORIGIN);
  } else if (circuit_enough_testing_circs()) {
    router_perform_bandwidth_test(NUM_PARALLEL_TESTING_CIRCS, time(NULL));
    have_performed_bandwidth_test = 1;
  } else
    consider_testing_reachability(1, 0);
}

/** A testing circuit has failed to build. Take whatever stats we want. */
static void
circuit_testing_failed(origin_circuit_t *circ, int at_last_hop)
{
  routerinfo_t *me = router_get_my_routerinfo();
  if (server_mode(get_options()) && check_whether_orport_reachable())
    return;
  if (!me)
    return;

  log_info(LD_GENERAL,
           "Our testing circuit (to see if your ORPort is reachable) "
           "has failed. I'll try again later.");
  control_event_server_status(LOG_WARN, "REACHABILITY_FAILED ORADDRESS=%s:%d",
                             me->address, me->or_port);

  /* These aren't used yet. */
  (void)circ;
  (void)at_last_hop;
}

/** The circuit <b>circ</b> has just become open. Take the next
 * step: for rendezvous circuits, we pass circ to the appropriate
 * function in rendclient or rendservice. For general circuits, we
 * call connection_ap_attach_pending, which looks for pending streams
 * that could use circ.
 */
void
circuit_has_opened(origin_circuit_t *circ)
{
  control_event_circuit_status(circ, CIRC_EVENT_BUILT, 0);

  switch (TO_CIRCUIT(circ)->purpose) {
    case CIRCUIT_PURPOSE_C_ESTABLISH_REND:
      rend_client_rendcirc_has_opened(circ);
      connection_ap_attach_pending();
      break;
    case CIRCUIT_PURPOSE_C_INTRODUCING:
      rend_client_introcirc_has_opened(circ);
      break;
    case CIRCUIT_PURPOSE_C_GENERAL:
      /* Tell any AP connections that have been waiting for a new
       * circuit that one is ready. */
      connection_ap_attach_pending();
      break;
    case CIRCUIT_PURPOSE_S_ESTABLISH_INTRO:
      /* at Bob, waiting for introductions */
      rend_service_intro_has_opened(circ);
      break;
    case CIRCUIT_PURPOSE_S_CONNECT_REND:
      /* at Bob, connecting to rend point */
      rend_service_rendezvous_has_opened(circ);
      break;
    case CIRCUIT_PURPOSE_TESTING:
      circuit_testing_opened(circ);
      break;
    /* default:
     * This won't happen in normal operation, but might happen if the
     * controller did it. Just let it slide. */
  }
}

/** Called whenever a circuit could not be successfully built.
 */
void
circuit_build_failed(origin_circuit_t *circ)
{
  /* we should examine circ and see if it failed because of
   * the last hop or an earlier hop. then use this info below.
   */
  int failed_at_last_hop = 0;
  /* If the last hop isn't open, and the second-to-last is, we failed
   * at the last hop. */
  if (circ->cpath &&
      circ->cpath->prev->state != CPATH_STATE_OPEN &&
      circ->cpath->prev->prev->state == CPATH_STATE_OPEN) {
    failed_at_last_hop = 1;
  }
  if (circ->cpath &&
      circ->cpath->state != CPATH_STATE_OPEN) {
    /* We failed at the first hop. If there's an OR connection
       to blame, blame it. */
    or_connection_t *n_conn = NULL;
    if (circ->_base.n_conn) {
      n_conn = circ->_base.n_conn;
    } else if (circ->_base.state == CIRCUIT_STATE_OR_WAIT) {
      /* we have to hunt for it */
      n_conn = connection_or_get_by_identity_digest(
                                               circ->_base.n_conn_id_digest);
    }
    if (n_conn) {
      log_info(LD_OR,
               "Our circuit failed to get a response from the first hop "
               "(%s:%d). I'm going to try to rotate to a better connection.",
               n_conn->_base.address, n_conn->_base.port);
      n_conn->_base.or_is_obsolete = 1;
      entry_guard_register_connect_status(n_conn->identity_digest, 0,
                                          time(NULL));
    }
  }

  switch (circ->_base.purpose) {
    case CIRCUIT_PURPOSE_C_GENERAL:
      /* If we never built the circuit, note it as a failure. */
      circuit_increment_failure_count();
      if (failed_at_last_hop) {
        /* Make sure any streams that demand our last hop as their exit
         * know that it's unlikely to happen. */
        circuit_discard_optional_exit_enclaves(circ->cpath->prev->extend_info);
      }
      break;
    case CIRCUIT_PURPOSE_TESTING:
      circuit_testing_failed(circ, failed_at_last_hop);
      break;
    case CIRCUIT_PURPOSE_S_ESTABLISH_INTRO:
      /* at Bob, waiting for introductions */
      if (circ->_base.state != CIRCUIT_STATE_OPEN) {
        circuit_increment_failure_count();
      }
      /* no need to care here, because bob will rebuild intro
       * points periodically. */
      break;
    case CIRCUIT_PURPOSE_C_INTRODUCING:
      /* at Alice, connecting to intro point */
      /* Don't increment failure count, since Bob may have picked
       * the introduction point maliciously */
      /* Alice will pick a new intro point when this one dies, if
       * the stream in question still cares. No need to act here. */
      break;
    case CIRCUIT_PURPOSE_C_ESTABLISH_REND:
      /* at Alice, waiting for Bob */
      circuit_increment_failure_count();
      /* Alice will pick a new rend point when this one dies, if
       * the stream in question still cares. No need to act here. */
      break;
    case CIRCUIT_PURPOSE_S_CONNECT_REND:
      /* at Bob, connecting to rend point */
      /* Don't increment failure count, since Alice may have picked
       * the rendezvous point maliciously */
      log_info(LD_REND,
               "Couldn't connect to Alice's chosen rend point %s "
               "(%s hop failed).",
               escaped(build_state_get_exit_nickname(circ->build_state)),
               failed_at_last_hop?"last":"non-last");
      rend_service_relaunch_rendezvous(circ);
      break;
    /* default:
     * This won't happen in normal operation, but might happen if the
     * controller did it. Just let it slide. */
  }
}

/** Number of consecutive failures so far; should only be touched by
 * circuit_launch_new and circuit_*_failure_count.
 */
static int n_circuit_failures = 0;
/** Before the last time we called circuit_reset_failure_count(), were
 * there a lot of failures? */
static int did_circs_fail_last_period = 0;

/** Don't retry launching a new circuit if we try this many times with no
 * success. */
#define MAX_CIRCUIT_FAILURES 5

/** Launch a new circuit; see circuit_launch_by_extend_info() for
 * details on arguments. */
origin_circuit_t *
circuit_launch_by_router(uint8_t purpose, int onehop_tunnel,
                         routerinfo_t *exit, int need_uptime,
                         int need_capacity, int internal)
{
  origin_circuit_t *circ;
  extend_info_t *info = NULL;
  if (exit)
    info = extend_info_from_router(exit);
  circ = circuit_launch_by_extend_info(
    purpose, onehop_tunnel, info, need_uptime, need_capacity, internal);
  if (info)
    extend_info_free(info);
  return circ;
}

/** Launch a new circuit with purpose <b>purpose</b> and exit node <b>info</b>
 * (or NULL to select a random exit node).  If <b>need_uptime</b> is true,
 * choose among routers with high uptime.  If <b>need_capacity</b> is true,
 * choose among routers with high bandwidth.  If <b>internal</b> is true, the
 * last hop need not be an exit node. Return the newly allocated circuit on
 * success, or NULL on failure. */
origin_circuit_t *
circuit_launch_by_extend_info(uint8_t purpose, int onehop_tunnel,
                              extend_info_t *extend_info, int need_uptime,
                              int need_capacity, int internal)
{
  origin_circuit_t *circ;

  if (!onehop_tunnel && !router_have_minimum_dir_info()) {
    log_debug(LD_CIRC,"Haven't fetched enough directory info yet; canceling "
              "circuit launch.");
    return NULL;
  }

  if ((extend_info || purpose != CIRCUIT_PURPOSE_C_GENERAL) &&
      purpose != CIRCUIT_PURPOSE_TESTING && !onehop_tunnel) {
    /* see if there are appropriate circs available to cannibalize. */
    circ = circuit_find_to_cannibalize(CIRCUIT_PURPOSE_C_GENERAL, extend_info,
                                       need_uptime, need_capacity, internal);
    if (circ) {
      log_info(LD_CIRC,"Cannibalizing circ '%s' for purpose %d",
               build_state_get_exit_nickname(circ->build_state), purpose);
      circ->_base.purpose = purpose;
      /* reset the birth date of this circ, else expire_building
       * will see it and think it's been trying to build since it
       * began. */
      circ->_base.timestamp_created = time(NULL);
      switch (purpose) {
        case CIRCUIT_PURPOSE_C_ESTABLISH_REND:
        case CIRCUIT_PURPOSE_S_ESTABLISH_INTRO:
          /* it's ready right now */
          break;
        case CIRCUIT_PURPOSE_C_INTRODUCING:
        case CIRCUIT_PURPOSE_S_CONNECT_REND:
        case CIRCUIT_PURPOSE_C_GENERAL:
          /* need to add a new hop */
          tor_assert(extend_info);
          if (circuit_extend_to_new_exit(circ, extend_info) < 0)
            return NULL;
          break;
        default:
          log_warn(LD_BUG,
                   "Bug: unexpected purpose %d when cannibalizing a circ.",
                   purpose);
          tor_fragile_assert();
          return NULL;
      }
      return circ;
    }
  }

  if (did_circs_fail_last_period &&
      n_circuit_failures > MAX_CIRCUIT_FAILURES) {
    /* too many failed circs in a row. don't try. */
//    log_fn(LOG_INFO,"%d failures so far, not trying.",n_circuit_failures);
    return NULL;
  }

  /* try a circ. if it fails, circuit_mark_for_close will increment
   * n_circuit_failures */
  return circuit_establish_circuit(purpose, onehop_tunnel, extend_info,
                                   need_uptime, need_capacity, internal);
}

/** Launch a new circuit; see circuit_launch_by_extend_info() for
 * details on arguments. */
origin_circuit_t *
circuit_launch_by_nickname(uint8_t purpose, int onehop_tunnel,
                           const char *exit_nickname,
                           int need_uptime, int need_capacity, int internal)
{
  routerinfo_t *router = NULL;

  if (exit_nickname) {
    router = router_get_by_nickname(exit_nickname, 1);
    if (!router) {
      log_warn(LD_GENERAL, "Trying to launch circ by nickname, but "
               "no such OR as '%s'", exit_nickname);
      return NULL;
    }
  }
  return circuit_launch_by_router(purpose, onehop_tunnel, router,
                                  need_uptime, need_capacity, internal);
}

/** Record another failure at opening a general circuit. When we have
 * too many, we'll stop trying for the remainder of this minute.
 */
static void
circuit_increment_failure_count(void)
{
  ++n_circuit_failures;
  log_debug(LD_CIRC,"n_circuit_failures now %d.",n_circuit_failures);
}

/** Reset the failure count for opening general circuits. This means
 * we will try MAX_CIRCUIT_FAILURES times more (if necessary) before
 * stopping again.
 */
void
circuit_reset_failure_count(int timeout)
{
  if (timeout && n_circuit_failures > MAX_CIRCUIT_FAILURES)
    did_circs_fail_last_period = 1;
  else
    did_circs_fail_last_period = 0;
  n_circuit_failures = 0;
}

/** Find an open circ that we're happy to use for <b>conn</b> and return 1. If
 * there isn't one, and there isn't one on the way, launch one and return
 * 0. If it will never work, return -1.
 *
 * Write the found or in-progress or launched circ into *circp.
 */
static int
circuit_get_open_circ_or_launch(edge_connection_t *conn,
                                uint8_t desired_circuit_purpose,
                                origin_circuit_t **circp)
{
  origin_circuit_t *circ;
  int check_exit_policy;
  int need_uptime, need_internal;
  int want_onehop;

  tor_assert(conn);
  tor_assert(circp);
  tor_assert(conn->_base.state == AP_CONN_STATE_CIRCUIT_WAIT);
  check_exit_policy =
      (conn->socks_request->command == SOCKS_COMMAND_CONNECT) &&
      !connection_edge_is_rendezvous_stream(conn);
  want_onehop = conn->socks_request->command == SOCKS_COMMAND_CONNECT_DIR;

  need_uptime = (conn->socks_request->command == SOCKS_COMMAND_CONNECT) &&
                smartlist_string_num_isin(get_options()->LongLivedPorts,
                                          conn->socks_request->port);
  need_internal = desired_circuit_purpose != CIRCUIT_PURPOSE_C_GENERAL;

  circ = circuit_get_best(conn, 1, desired_circuit_purpose,
                          need_uptime, need_internal);

  if (circ) {
    *circp = circ;
    return 1; /* we're happy */
  }

  if (!want_onehop && !router_have_minimum_dir_info()) {
    if (!connection_get_by_type(CONN_TYPE_DIR)) {
      log_notice(LD_APP|LD_DIR,
                 "Application request when we're believed to be "
                 "offline. Optimistically trying directory fetches again.");
      router_reset_status_download_failures();
      router_reset_descriptor_download_failures();
      update_networkstatus_downloads(time(NULL));
      update_router_descriptor_downloads(time(NULL));
    }
    /* the stream will be dealt with when router_have_minimum_dir_info becomes
     * 1, or when all directory attempts fail and directory_all_unreachable()
     * kills it.
     */
    return 0;
  }

  /* Do we need to check exit policy? */
  if (check_exit_policy) {
    struct in_addr in;
    uint32_t addr = 0;
    if (tor_inet_aton(conn->socks_request->address, &in))
      addr = ntohl(in.s_addr);
    if (router_exit_policy_all_routers_reject(addr, conn->socks_request->port,
                                              need_uptime)) {
      log_notice(LD_APP,
                 "No Tor server exists that allows exit to %s:%d. Rejecting.",
                 safe_str(conn->socks_request->address),
                 conn->socks_request->port);
      return -1;
    }
  }

  /* is one already on the way? */
  circ = circuit_get_best(conn, 0, desired_circuit_purpose,
                          need_uptime, need_internal);
  if (!circ) {
    extend_info_t *extend_info=NULL;
    uint8_t new_circ_purpose;

    if (desired_circuit_purpose == CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT) {
      /* need to pick an intro point */
      extend_info = rend_client_get_random_intro(conn->rend_query);
      if (!extend_info) {
        log_info(LD_REND,
                 "No intro points for '%s': refetching service descriptor.",
                 safe_str(conn->rend_query));
        rend_client_refetch_renddesc(conn->rend_query);
        conn->_base.state = AP_CONN_STATE_RENDDESC_WAIT;
        return 0;
      }
      log_info(LD_REND,"Chose '%s' as intro point for '%s'.",
               extend_info->nickname, safe_str(conn->rend_query));
    }

    /* If we have specified a particular exit node for our
     * connection, then be sure to open a circuit to that exit node.
     */
    if (desired_circuit_purpose == CIRCUIT_PURPOSE_C_GENERAL) {
      if (conn->chosen_exit_name) {
        routerinfo_t *r;
        int opt = conn->_base.chosen_exit_optional;
        r = router_get_by_nickname(conn->chosen_exit_name, 1);
        if (r) {
          extend_info = extend_info_from_router(r);
        } else {
          if (want_onehop && conn->chosen_exit_name[0] == '$') {
            /* We're asking for a one-hop circuit to a router that
             * we don't have a routerinfo about. Hope we have a
             * routerstatus or equivalent. */
            routerstatus_t *s =
              routerstatus_get_by_hexdigest(conn->chosen_exit_name+1);
            if (s) {
              extend_info = extend_info_from_routerstatus(s);
            } else {
              log_warn(LD_APP,
                       "Requested router '%s' is not known. Closing.",
                       conn->chosen_exit_name);
              return -1;
            }
          } else {
            /* We will need an onion key for the router, and we
             * don't have one. Refuse or relax requirements. */
            log_fn(opt ? LOG_INFO : LOG_WARN, LD_APP,
                   "Requested exit point '%s' is not known. %s.",
                   conn->chosen_exit_name, opt ? "Trying others" : "Closing");
            if (opt) {
              conn->_base.chosen_exit_optional = 0;
              tor_free(conn->chosen_exit_name);
              return 0;
            }
            return -1;
          }
        }
      }
    }

    if (desired_circuit_purpose == CIRCUIT_PURPOSE_C_REND_JOINED)
      new_circ_purpose = CIRCUIT_PURPOSE_C_ESTABLISH_REND;
    else if (desired_circuit_purpose == CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT)
      new_circ_purpose = CIRCUIT_PURPOSE_C_INTRODUCING;
    else
      new_circ_purpose = desired_circuit_purpose;

    circ = circuit_launch_by_extend_info(
              new_circ_purpose, want_onehop, extend_info,
              need_uptime, 1, need_internal);
    if (extend_info)
      extend_info_free(extend_info);

    if (desired_circuit_purpose != CIRCUIT_PURPOSE_C_GENERAL) {
      /* help predict this next time */
      rep_hist_note_used_internal(time(NULL), need_uptime, 1);
      if (circ) {
        /* write the service_id into circ */
        strlcpy(circ->rend_query, conn->rend_query, sizeof(circ->rend_query));
        if (circ->_base.purpose == CIRCUIT_PURPOSE_C_ESTABLISH_REND &&
            circ->_base.state == CIRCUIT_STATE_OPEN)
          rend_client_rendcirc_has_opened(circ);
      }
    }
  }
  if (!circ)
    log_info(LD_APP,
             "No safe circuit (purpose %d) ready for edge "
             "connection; delaying.",
             desired_circuit_purpose);
  *circp = circ;
  return 0;
}

/** Attach the AP stream <b>apconn</b> to circ's linked list of
 * p_streams. Also set apconn's cpath_layer to the last hop in
 * circ's cpath.
 */
static void
link_apconn_to_circ(edge_connection_t *apconn, origin_circuit_t *circ)
{
  /* add it into the linked list of streams on this circuit */
  log_debug(LD_APP|LD_CIRC, "attaching new conn to circ. n_circ_id %d.",
            circ->_base.n_circ_id);
  /* reset it, so we can measure circ timeouts */
  apconn->_base.timestamp_lastread = time(NULL);
  apconn->next_stream = circ->p_streams;
  apconn->on_circuit = TO_CIRCUIT(circ);
  /* assert_connection_ok(conn, time(NULL)); */
  circ->p_streams = apconn;

  tor_assert(circ->cpath);
  tor_assert(circ->cpath->prev);
  tor_assert(circ->cpath->prev->state == CPATH_STATE_OPEN);
  apconn->cpath_layer = circ->cpath->prev;
}

/** If an exit wasn't specifically chosen, save the history for future
 * use. */
static void
consider_recording_trackhost(edge_connection_t *conn, origin_circuit_t *circ)
{
  int found_needle = 0;
  or_options_t *options = get_options();
  size_t len;
  char *new_address;
  char fp[HEX_DIGEST_LEN+1];

  /* Search the addressmap for this conn's destination. */
  /* If he's not in the address map.. */
  if (!options->TrackHostExits ||
      addressmap_have_mapping(conn->socks_request->address))
    return; /* nothing to track, or already mapped */

  SMARTLIST_FOREACH(options->TrackHostExits, const char *, cp, {
    if (cp[0] == '.') { /* match end */
      if (!strcasecmpend(conn->socks_request->address, cp) ||
          !strcasecmp(conn->socks_request->address, &cp[1]))
          found_needle = 1;
    } else if (strcasecmp(cp, conn->socks_request->address) == 0) {
      found_needle = 1;
    }
  });

  if (!found_needle || !circ->build_state->chosen_exit)
    return;

  /* write down the fingerprint of the chosen exit, not the nickname,
   * because the chosen exit might not be named. */
  base16_encode(fp, sizeof(fp),
                circ->build_state->chosen_exit->identity_digest, DIGEST_LEN);

  /* Add this exit/hostname pair to the addressmap. */
  len = strlen(conn->socks_request->address) + 1 /* '.' */ +
        strlen(fp) + 1 /* '.' */ +
        strlen("exit") + 1 /* '\0' */;
  new_address = tor_malloc(len);

  tor_snprintf(new_address, len, "%s.%s.exit",
               conn->socks_request->address, fp);

  addressmap_register(conn->socks_request->address, new_address,
                      time(NULL) + options->TrackHostExitsExpire);
}

/** Attempt to attach the connection <b>conn</b> to <b>circ</b>, and
 * send a begin or resolve cell as appropriate.  Return values are as
 * for connection_ap_handshake_attach_circuit. */
int
connection_ap_handshake_attach_chosen_circuit(edge_connection_t *conn,
                                              origin_circuit_t *circ)
{
  tor_assert(conn);
  tor_assert(conn->_base.state == AP_CONN_STATE_CIRCUIT_WAIT ||
             conn->_base.state == AP_CONN_STATE_CONTROLLER_WAIT);
  tor_assert(conn->socks_request);
  tor_assert(circ);
  tor_assert(circ->_base.state == CIRCUIT_STATE_OPEN);

  conn->_base.state = AP_CONN_STATE_CIRCUIT_WAIT;

  if (!circ->_base.timestamp_dirty)
    circ->_base.timestamp_dirty = time(NULL);

  link_apconn_to_circ(conn, circ);
  tor_assert(conn->socks_request);
  switch (conn->socks_request->command) {
    case SOCKS_COMMAND_CONNECT:
      consider_recording_trackhost(conn, circ);
      /* fall through */
    case SOCKS_COMMAND_CONNECT_DIR:
      if (connection_ap_handshake_send_begin(conn, circ)<0)
        return -1;
      break;
    default:
      if (connection_ap_handshake_send_resolve(conn, circ)<0)
        return -1;
  }

  return 1;
}

/** Try to find a safe live circuit for CONN_TYPE_AP connection conn. If
 * we don't find one: if conn cannot be handled by any known nodes,
 * warn and return -1 (conn needs to die);
 * else launch new circuit (if necessary) and return 0.
 * Otherwise, associate conn with a safe live circuit, do the
 * right next step, and return 1.
 */
int
connection_ap_handshake_attach_circuit(edge_connection_t *conn)
{
  int retval;
  int conn_age;

  tor_assert(conn);
  tor_assert(conn->_base.state == AP_CONN_STATE_CIRCUIT_WAIT);
  tor_assert(conn->socks_request);

  conn_age = time(NULL) - conn->_base.timestamp_created;

  if (!connection_edge_is_rendezvous_stream(conn)) { /* we're a general conn */
    origin_circuit_t *circ=NULL;

    if (conn->chosen_exit_name) {
      routerinfo_t *router = router_get_by_nickname(conn->chosen_exit_name, 1);
      int opt = conn->_base.chosen_exit_optional;
      if (!router) {
        log_fn(opt ? LOG_INFO : LOG_WARN, LD_APP,
               "Requested exit point '%s' is not known. %s.",
               conn->chosen_exit_name, opt ? "Trying others" : "Closing");
        if (opt) {
          conn->_base.chosen_exit_optional = 0;
          tor_free(conn->chosen_exit_name);
          return 0;
        }
        return -1;
      }
      if (!connection_ap_can_use_exit(conn, router)) {
        log_fn(opt ? LOG_INFO : LOG_WARN, LD_APP,
               "Requested exit point '%s' would refuse request. %s.",
               conn->chosen_exit_name, opt ? "Trying others" : "Closing");
        if (opt) {
          conn->_base.chosen_exit_optional = 0;
          tor_free(conn->chosen_exit_name);
          return 0;
        }
        return -1;
      }
    }

    /* find the circuit that we should use, if there is one. */
    retval = circuit_get_open_circ_or_launch(
        conn, CIRCUIT_PURPOSE_C_GENERAL, &circ);
    if (retval < 1)
      return retval;

    log_debug(LD_APP|LD_CIRC,
              "Attaching apconn to circ %d (stream %d sec old).",
              circ->_base.n_circ_id, conn_age);
    /* here, print the circ's path. so people can figure out which circs are
     * sucking. */
    circuit_log_path(LOG_INFO,LD_APP|LD_CIRC,circ);

    /* We have found a suitable circuit for our conn. Hurray. */
    return connection_ap_handshake_attach_chosen_circuit(conn, circ);

  } else { /* we're a rendezvous conn */
    origin_circuit_t *rendcirc=NULL, *introcirc=NULL;

    tor_assert(!conn->cpath_layer);

    /* start by finding a rendezvous circuit for us */

    retval = circuit_get_open_circ_or_launch(
       conn, CIRCUIT_PURPOSE_C_REND_JOINED, &rendcirc);
    if (retval < 0) return -1; /* failed */

    if (retval > 0) {
      tor_assert(rendcirc);
      /* one is already established, attach */
      log_info(LD_REND,
               "rend joined circ %d already here. attaching. "
               "(stream %d sec old)",
               rendcirc->_base.n_circ_id, conn_age);
      /* Mark rendezvous circuits as 'newly dirty' every time you use
       * them, since the process of rebuilding a rendezvous circ is so
       * expensive. There is a tradeoffs between linkability and
       * feasibility, at this point.
       */
      rendcirc->_base.timestamp_dirty = time(NULL);
      link_apconn_to_circ(conn, rendcirc);
      if (connection_ap_handshake_send_begin(conn, rendcirc) < 0)
        return 0; /* already marked, let them fade away */
      return 1;
    }

    if (rendcirc && (rendcirc->_base.purpose ==
                     CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED)) {
      log_info(LD_REND,
               "pending-join circ %d already here, with intro ack. "
               "Stalling. (stream %d sec old)",
                rendcirc->_base.n_circ_id, conn_age);
      return 0;
    }

    /* it's on its way. find an intro circ. */
    retval = circuit_get_open_circ_or_launch(
      conn, CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT, &introcirc);
    if (retval < 0) return -1; /* failed */

    if (retval > 0) {
      /* one has already sent the intro. keep waiting. */
      tor_assert(introcirc);
      log_info(LD_REND, "Intro circ %d present and awaiting ack (rend %d). "
               "Stalling. (stream %d sec old)",
               introcirc->_base.n_circ_id,
               rendcirc ? rendcirc->_base.n_circ_id : 0,
               conn_age);
      return 0;
    }

    /* now rendcirc and introcirc are each either undefined or not finished */

    if (rendcirc && introcirc &&
        rendcirc->_base.purpose == CIRCUIT_PURPOSE_C_REND_READY) {
      log_info(LD_REND,
               "ready rend circ %d already here (no intro-ack yet on "
               "intro %d). (stream %d sec old)",
               rendcirc->_base.n_circ_id,
               introcirc->_base.n_circ_id, conn_age);

      tor_assert(introcirc->_base.purpose == CIRCUIT_PURPOSE_C_INTRODUCING);
      if (introcirc->_base.state == CIRCUIT_STATE_OPEN) {
        log_info(LD_REND,"found open intro circ %d (rend %d); sending "
                 "introduction. (stream %d sec old)",
                 introcirc->_base.n_circ_id, rendcirc->_base.n_circ_id,
                 conn_age);
        if (rend_client_send_introduction(introcirc, rendcirc) < 0) {
          return -1;
        }
        rendcirc->_base.timestamp_dirty = time(NULL);
        introcirc->_base.timestamp_dirty = time(NULL);
        assert_circuit_ok(TO_CIRCUIT(rendcirc));
        assert_circuit_ok(TO_CIRCUIT(introcirc));
        return 0;
      }
    }

    log_info(LD_REND, "Intro (%d) and rend (%d) circs are not both ready. "
             "Stalling conn. (%d sec old)",
             introcirc ? introcirc->_base.n_circ_id : 0,
             rendcirc ? rendcirc->_base.n_circ_id : 0, conn_age);
    return 0;
  }
}

