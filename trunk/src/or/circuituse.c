/* Copyright 2001 Matej Pfajfar, 2001-2004 Roger Dingledine. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file circuituse.c
 * \brief Launch the right sort of circuits, attach streams to them.
 **/

#include "or.h"

extern or_options_t options; /* command-line and config-file options */

/********* START VARIABLES **********/

extern circuit_t *global_circuitlist; /* from circuitlist.c */
extern int has_fetched_directory; /* from main.c */

/********* END VARIABLES ************/

static void circuit_expire_old_circuits(void);
static void circuit_increment_failure_count(void);

/* Return 1 if <b>circ</b> could be returned by circuit_get_best().
 * Else return 0.
 */
static int circuit_is_acceptable(circuit_t *circ,
                                 connection_t *conn,
                                 int must_be_open,
                                 uint8_t purpose,
                                 time_t now)
{
  routerinfo_t *exitrouter;

  if (!CIRCUIT_IS_ORIGIN(circ))
    return 0; /* this circ doesn't start at us */
  if (must_be_open && (circ->state != CIRCUIT_STATE_OPEN || !circ->n_conn))
    return 0; /* ignore non-open circs */
  if (circ->marked_for_close)
    return 0;

  /* if this circ isn't our purpose, skip. */
  if(purpose == CIRCUIT_PURPOSE_C_REND_JOINED && !must_be_open) {
    if(circ->purpose != CIRCUIT_PURPOSE_C_ESTABLISH_REND &&
       circ->purpose != CIRCUIT_PURPOSE_C_REND_READY &&
       circ->purpose != CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED &&
       circ->purpose != CIRCUIT_PURPOSE_C_REND_JOINED)
      return 0;
  } else if (purpose == CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT && !must_be_open) {
    if (circ->purpose != CIRCUIT_PURPOSE_C_INTRODUCING &&
        circ->purpose != CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT)
      return 0;
  } else {
    if(purpose != circ->purpose)
      return 0;
  }

  if(purpose == CIRCUIT_PURPOSE_C_GENERAL)
    if(circ->timestamp_dirty &&
       circ->timestamp_dirty+options.NewCircuitPeriod <= now)
      return 0;

  if(conn) {
    /* decide if this circ is suitable for this conn */

    /* for rend circs, circ->cpath->prev is not the last router in the
     * circuit, it's the magical extra bob hop. so just check the nickname
     * of the one we meant to finish at.
     */
    exitrouter = router_get_by_digest(circ->build_state->chosen_exit_digest);

    if(!exitrouter) {
      log_fn(LOG_INFO,"Skipping broken circ (exit router vanished)");
      return 0; /* this circuit is screwed and doesn't know it yet */
    }

    if (conn->socks_request &&
        conn->socks_request->command == SOCKS_COMMAND_RESOLVE) {
      /* 0.0.7 servers and earlier don't support DNS resolution.  0.0.8 servers
       * have buggy resolve support. */
      if (!tor_version_as_new_as(exitrouter->platform, "0.0.9pre1"))
        return 0;
    } else if(purpose == CIRCUIT_PURPOSE_C_GENERAL) {
      if(!connection_ap_can_use_exit(conn, exitrouter)) {
        /* can't exit from this router */
        return 0;
      }
    } else { /* not general */
      if(rend_cmp_service_ids(conn->rend_query, circ->rend_query) &&
         (circ->rend_query[0] || purpose != CIRCUIT_PURPOSE_C_REND_JOINED)) {
        /* this circ is not for this conn, and it's not suitable
         * for cannibalizing either */
        return 0;
      }
    }
  }
  return 1;
}

/* Return 1 if circuit <b>a</b> is better than circuit <b>b</b> for
 * <b>purpose</b>, and return 0 otherwise. Used by circuit_get_best.
 */
static int circuit_is_better(circuit_t *a, circuit_t *b, uint8_t purpose)
{
  switch(purpose) {
    case CIRCUIT_PURPOSE_C_GENERAL:
      /* if it's used but less dirty it's best;
       * else if it's more recently created it's best
       */
      if(b->timestamp_dirty) {
        if(a->timestamp_dirty &&
           a->timestamp_dirty > b->timestamp_dirty)
          return 1;
      } else {
        if(a->timestamp_dirty ||
           a->timestamp_created > b->timestamp_created)
          return 1;
      }
      break;
    case CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT:
      /* the closer it is to ack_wait the better it is */
      if(a->purpose > b->purpose)
        return 1;
      break;
    case CIRCUIT_PURPOSE_C_REND_JOINED:
      /* the closer it is to rend_joined the better it is */
      if(a->purpose > b->purpose)
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
static circuit_t *
circuit_get_best(connection_t *conn, int must_be_open, uint8_t purpose)
{
  circuit_t *circ, *best=NULL;
  time_t now = time(NULL);

  tor_assert(conn);

  tor_assert(purpose == CIRCUIT_PURPOSE_C_GENERAL ||
             purpose == CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT ||
             purpose == CIRCUIT_PURPOSE_C_REND_JOINED);

  for (circ=global_circuitlist;circ;circ = circ->next) {
    if (!circuit_is_acceptable(circ,conn,must_be_open,purpose,now))
      continue;

    /* now this is an acceptable circ to hand back. but that doesn't
     * mean it's the *best* circ to hand back. try to decide.
     */
    if(!best || circuit_is_better(circ,best,purpose))
      best = circ;
  }

  return best;
}

/** Circuits that were born at the end of their second might be expired
 * after 30.1 seconds; circuits born at the beginning might be expired
 * after closer to 31 seconds.
 */
#define MIN_SECONDS_BEFORE_EXPIRING_CIRC 30

/** Close all circuits that start at us, aren't open, and were born
 * at least MIN_SECONDS_BEFORE_EXPIRING_CIRC seconds ago.
 */
void circuit_expire_building(time_t now) {
  circuit_t *victim, *circ = global_circuitlist;

  while(circ) {
    victim = circ;
    circ = circ->next;
    if(!CIRCUIT_IS_ORIGIN(victim))
      continue; /* didn't originate here */
    if(victim->marked_for_close)
      continue; /* don't mess with marked circs */
    if(victim->timestamp_created + MIN_SECONDS_BEFORE_EXPIRING_CIRC > now)
      continue; /* it's young still, don't mess with it */

    /* some debug logs, to help track bugs */
    if(victim->purpose >= CIRCUIT_PURPOSE_C_INTRODUCING &&
       victim->purpose <= CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED) {
      if(!victim->timestamp_dirty)
        log_fn(LOG_DEBUG,"Considering %sopen purp %d to %s (circid %d). (clean).",
               victim->state == CIRCUIT_STATE_OPEN ? "" : "non",
               victim->purpose, victim->build_state->chosen_exit_name,
               victim->n_circ_id);
      else
        log_fn(LOG_DEBUG,"Considering %sopen purp %d to %s (circid %d). %d secs since dirty.",
               victim->state == CIRCUIT_STATE_OPEN ? "" : "non",
               victim->purpose, victim->build_state->chosen_exit_name,
               victim->n_circ_id,
               (int)(now - victim->timestamp_dirty));
    }

    /* if circ is !open, or if it's open but purpose is a non-finished
     * intro or rend, then mark it for close */
    if(victim->state != CIRCUIT_STATE_OPEN ||
       victim->purpose == CIRCUIT_PURPOSE_C_ESTABLISH_REND ||
       victim->purpose == CIRCUIT_PURPOSE_C_INTRODUCING ||
       victim->purpose == CIRCUIT_PURPOSE_S_ESTABLISH_INTRO ||

       /* it's a rend_ready circ, but it's already picked a query */
       (victim->purpose == CIRCUIT_PURPOSE_C_REND_READY &&
        victim->rend_query[0]) ||

       /* c_rend_ready circs measure age since timestamp_dirty,
        * because that's set when they switch purposes
        */
       /* rend and intro circs become dirty each time they
        * make an introduction attempt. so timestamp_dirty
        * will reflect the time since the last attempt.
        */
       ((victim->purpose == CIRCUIT_PURPOSE_C_REND_READY ||
         victim->purpose == CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED ||
         victim->purpose == CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT) &&
        victim->timestamp_dirty + MIN_SECONDS_BEFORE_EXPIRING_CIRC > now)) {
      if(victim->n_conn)
        log_fn(LOG_INFO,"Abandoning circ %s:%d:%d (state %d:%s, purpose %d)",
               victim->n_conn->address, victim->n_port, victim->n_circ_id,
               victim->state, circuit_state_to_string[victim->state], victim->purpose);
      else
        log_fn(LOG_INFO,"Abandoning circ %d (state %d:%s, purpose %d)", victim->n_circ_id,
               victim->state, circuit_state_to_string[victim->state], victim->purpose);
      circuit_log_path(LOG_INFO,victim);
      circuit_mark_for_close(victim);
    }
  }
}

/** How many circuits do we want simultaneously in-progress to handle
 * a given stream?
 */
#define MIN_CIRCUITS_HANDLING_STREAM 2

/** Return 1 if at least MIN_CIRCUITS_HANDLING_STREAM non-open
 * general-purpose circuits will have an acceptable exit node for
 * conn. Else return 0.
 */
int circuit_stream_is_being_handled(connection_t *conn) {
  circuit_t *circ;
  routerinfo_t *exitrouter;
  int num=0;
  time_t now = time(NULL);

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if(CIRCUIT_IS_ORIGIN(circ) && circ->state != CIRCUIT_STATE_OPEN &&
       !circ->marked_for_close && circ->purpose == CIRCUIT_PURPOSE_C_GENERAL &&
       (!circ->timestamp_dirty ||
        circ->timestamp_dirty + options.NewCircuitPeriod < now)) {
      exitrouter = router_get_by_digest(circ->build_state->chosen_exit_digest);
      if(exitrouter && connection_ap_can_use_exit(conn, exitrouter))
        if(++num >= MIN_CIRCUITS_HANDLING_STREAM)
          return 1;
    }
  }
  return 0;
}

/** Build a new test circuit every 5 minutes */
#define TESTING_CIRCUIT_INTERVAL 300

/** This function is called once a second. Its job is to make sure
 * all services we offer have enough circuits available. Some
 * services just want enough circuits for current tasks, whereas
 * others want a minimum set of idle circuits hanging around.
 */
void circuit_build_needed_circs(time_t now) {
  static long time_to_new_circuit = 0;
  circuit_t *circ;

  /* launch a new circ for any pending streams that need one */
  connection_ap_attach_pending();

  /* make sure any hidden services have enough intro points */
  if(has_fetched_directory)
    rend_services_introduce();

  circ = circuit_get_youngest_clean_open(CIRCUIT_PURPOSE_C_GENERAL);

  if(time_to_new_circuit < now) {
    circuit_reset_failure_count(1);
    time_to_new_circuit = now + options.NewCircuitPeriod;
    if(proxy_mode())
      client_dns_clean();
    circuit_expire_old_circuits();

    if(options.RunTesting && circ &&
               circ->timestamp_created + TESTING_CIRCUIT_INTERVAL < now) {
      log_fn(LOG_INFO,"Creating a new testing circuit.");
      circuit_launch_by_identity(CIRCUIT_PURPOSE_C_GENERAL, NULL);
    }
  }

/** How many simultaneous in-progress general-purpose circuits do we
 * want to be building at once, if there are no open general-purpose
 * circuits?
 */
#define CIRCUIT_MIN_BUILDING_GENERAL 5
  /* if there's no open circ, and less than 5 are on the way,
   * go ahead and try another. */
  if(!circ && circuit_count_building(CIRCUIT_PURPOSE_C_GENERAL)
              < CIRCUIT_MIN_BUILDING_GENERAL) {
    circuit_launch_by_identity(CIRCUIT_PURPOSE_C_GENERAL, NULL);
  }

  /* XXX count idle rendezvous circs and build more */
}

/** If the stream <b>conn</b> is a member of any of the linked
 * lists of <b>circ</b>, then remove it from the list.
 */
void circuit_detach_stream(circuit_t *circ, connection_t *conn) {
  connection_t *prevconn;

  tor_assert(circ && conn);

  conn->cpath_layer = NULL; /* make sure we don't keep a stale pointer */

  if(conn == circ->p_streams) {
    circ->p_streams = conn->next_stream;
    return;
  }
  if(conn == circ->n_streams) {
    circ->n_streams = conn->next_stream;
    return;
  }
  if(conn == circ->resolving_streams) {
    circ->resolving_streams = conn->next_stream;
    return;
  }

  for(prevconn = circ->p_streams;
      prevconn && prevconn->next_stream && prevconn->next_stream != conn;
      prevconn = prevconn->next_stream)
    ;
  if(prevconn && prevconn->next_stream) {
    prevconn->next_stream = conn->next_stream;
    return;
  }

  for(prevconn = circ->n_streams;
      prevconn && prevconn->next_stream && prevconn->next_stream != conn;
      prevconn = prevconn->next_stream)
    ;
  if(prevconn && prevconn->next_stream) {
    prevconn->next_stream = conn->next_stream;
    return;
  }

  for(prevconn = circ->resolving_streams;
      prevconn && prevconn->next_stream && prevconn->next_stream != conn;
      prevconn = prevconn->next_stream)
    ;
  if(prevconn && prevconn->next_stream) {
    prevconn->next_stream = conn->next_stream;
    return;
  }

  log_fn(LOG_ERR,"edge conn not in circuit's list?");
  tor_assert(0); /* should never get here */
}

/** Notify the global circuit list that <b>conn</b> is about to be
 * removed and then freed.
 *
 * If it's an OR conn, then mark-for-close all the circuits that use
 * that conn.
 *
 * If it's an edge conn, then detach it from its circ, so we don't
 * try to reference it later.
 */
void circuit_about_to_close_connection(connection_t *conn) {
  /* currently, we assume it's too late to flush conn's buf here.
   * down the road, maybe we'll consider that eof doesn't mean can't-write
   */
  circuit_t *circ;

  switch(conn->type) {
    case CONN_TYPE_OR:
      if(conn->state != OR_CONN_STATE_OPEN) {
        /* Inform any pending (not attached) circs that they should give up. */
        circuit_n_conn_done(conn, 0);
      }
      /* Now close all the attached circuits on it. */
      while((circ = circuit_get_by_conn(conn))) {
        if(circ->n_conn == conn) /* it's closing in front of us */
          circ->n_conn = NULL;
        if(circ->p_conn == conn) /* it's closing behind us */
          circ->p_conn = NULL;
        circuit_mark_for_close(circ);
      }
      return;
    case CONN_TYPE_AP:
    case CONN_TYPE_EXIT:

      /* It's an edge conn. Need to remove it from the linked list of
       * conn's for this circuit. Confirm that 'end' relay command has
       * been sent. But don't kill the circuit.
       */

      circ = circuit_get_by_conn(conn);
      if(!circ)
        return;

      circuit_detach_stream(circ, conn);

  } /* end switch */
}

/** Don't keep more than 10 unused open circuits around. */
#define MAX_UNUSED_OPEN_CIRCUITS 10

/** Find each circuit that has been dirty for too long, and has
 * no streams on it: mark it for close.
 *
 * Also, if there are more than MAX_UNUSED_OPEN_CIRCUITS open and
 * unused circuits, then mark the excess circs for close.
 */
static void
circuit_expire_old_circuits(void)
{
  circuit_t *circ;
  time_t now = time(NULL);
  smartlist_t *unused_open_circs;
  int i;

  unused_open_circs = smartlist_create();

  for (circ = global_circuitlist; circ; circ = circ->next) {
    if (circ->marked_for_close)
      continue;
    /* If the circuit has been dirty for too long, and there are no streams
     * on it, mark it for close.
     */
    if (circ->timestamp_dirty &&
        circ->timestamp_dirty + options.NewCircuitPeriod < now &&
        !circ->p_conn && /* we're the origin */
        !circ->p_streams /* nothing attached */ ) {
      log_fn(LOG_DEBUG,"Closing n_circ_id %d (dirty %d secs ago, purp %d)",circ->n_circ_id,
             (int)(now - circ->timestamp_dirty), circ->purpose);
      /* (only general and purpose_c circs can get dirty) */
      tor_assert(!circ->n_streams);
      tor_assert(circ->purpose <= CIRCUIT_PURPOSE_C_REND_JOINED);
      circuit_mark_for_close(circ);
    } else if (!circ->timestamp_dirty && CIRCUIT_IS_ORIGIN(circ) &&
               circ->state == CIRCUIT_STATE_OPEN &&
               circ->purpose == CIRCUIT_PURPOSE_C_GENERAL) {
      /* Also, gather a list of open unused general circuits that we created.
       * Because we add elements to the front of global_circuitlist,
       * the last elements of unused_open_circs will be the oldest
       * ones.
       */
      smartlist_add(unused_open_circs, circ);
    }
  }
  for (i = MAX_UNUSED_OPEN_CIRCUITS; i < smartlist_len(unused_open_circs); ++i) {
    circuit_t *circ = smartlist_get(unused_open_circs, i);
    log_fn(LOG_DEBUG,"Expiring excess clean circ (n_circ_id %d, purp %d)",
           circ->n_circ_id, circ->purpose);
    circuit_mark_for_close(circ);
  }
  smartlist_free(unused_open_circs);
}

/** The circuit <b>circ</b> has just become open. Take the next
 * step: for rendezvous circuits, we pass circ to the appropriate
 * function in rendclient or rendservice. For general circuits, we
 * call connection_ap_attach_pending, which looks for pending streams
 * that could use circ.
 */
void circuit_has_opened(circuit_t *circ) {

  switch(circ->purpose) {
    case CIRCUIT_PURPOSE_C_ESTABLISH_REND:
      rend_client_rendcirc_has_opened(circ);
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
    default:
      log_fn(LOG_ERR,"unhandled purpose %d",circ->purpose);
      tor_assert(0);
  }
}

/*~ Called whenever a circuit could not be successfully built.
 */
void circuit_build_failed(circuit_t *circ) {

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

  switch(circ->purpose) {
    case CIRCUIT_PURPOSE_C_GENERAL:
      if (circ->state != CIRCUIT_STATE_OPEN) {
        /* If we never built the circuit, note it as a failure. */
        /* Note that we can't just check circ->cpath here, because if
         * circuit-building failed immediately, it won't be set yet. */
        circuit_increment_failure_count();
      }
      break;
    case CIRCUIT_PURPOSE_S_ESTABLISH_INTRO:
      /* at Bob, waiting for introductions */
      if (circ->state != CIRCUIT_STATE_OPEN) {
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
      if (circ->state != CIRCUIT_STATE_OPEN) {
        circuit_increment_failure_count();
      }
      /* Alice will pick a new rend point when this one dies, if
       * the stream in question still cares. No need to act here. */
      break;
    case CIRCUIT_PURPOSE_S_CONNECT_REND:
      /* at Bob, connecting to rend point */
      /* Don't increment failure count, since Alice may have picked
       * the rendezvous point maliciously */
      if (failed_at_last_hop) {
        log_fn(LOG_INFO,"Couldn't connect to Alice's chosen rend point %s. Sucks to be Alice.", circ->build_state->chosen_exit_name);
      } else {
        log_fn(LOG_INFO,"Couldn't connect to Alice's chosen rend point %s, because an earlier node failed.",
               circ->build_state->chosen_exit_name);
        rend_service_relaunch_rendezvous(circ);
      }
      break;
    default:
      /* Other cases are impossible, since this function is only called with
       * unbuilt circuits. */
      tor_assert(0);
  }
}

/** Number of consecutive failures so far; should only be touched by
 * circuit_launch_new and circuit_*_failure_count.
 */
static int n_circuit_failures = 0;
static int did_circs_fail_last_period = 0;

/** Don't retry launching a new circuit if we try this many times with no
 * success. */
#define MAX_CIRCUIT_FAILURES 5

circuit_t *circuit_launch_by_identity(uint8_t purpose, const char *exit_digest)
{
  if (!has_fetched_directory) {
    log_fn(LOG_DEBUG,"Haven't fetched directory yet; cancelling circuit launch.");
    return NULL;
  }

  if (did_circs_fail_last_period &&
      n_circuit_failures > MAX_CIRCUIT_FAILURES) {
    /* too many failed circs in a row. don't try. */
//    log_fn(LOG_INFO,"%d failures so far, not trying.",n_circuit_failures);
    return NULL;
  }

  /* try a circ. if it fails, circuit_mark_for_close will increment n_circuit_failures */
  return circuit_establish_circuit(purpose, exit_digest);
}

/** Launch a new circuit and return a pointer to it. Return NULL if you failed. */
circuit_t *circuit_launch_by_nickname(uint8_t purpose, const char *exit_nickname)
{
  const char *digest = NULL;

  if (exit_nickname) {
    routerinfo_t *r = router_get_by_nickname(exit_nickname);
    if (!r) {
      log_fn(LOG_WARN, "No such OR as '%s'", exit_nickname);
      return NULL;
    }
    digest = r->identity_digest;
  }
  return circuit_launch_by_identity(purpose, digest);
}

/** Record another failure at opening a general circuit. When we have
 * too many, we'll stop trying for the remainder of this minute.
 */
static void circuit_increment_failure_count(void) {
  ++n_circuit_failures;
  log_fn(LOG_DEBUG,"n_circuit_failures now %d.",n_circuit_failures);
}

/** Reset the failure count for opening general circuits. This means
 * we will try MAX_CIRCUIT_FAILURES times more (if necessary) before
 * stopping again.
 */
void circuit_reset_failure_count(int timeout) {
  if(timeout && n_circuit_failures > MAX_CIRCUIT_FAILURES)
    did_circs_fail_last_period = 1;
  else
    did_circs_fail_last_period = 0;
  n_circuit_failures = 0;
}

/** Find an open circ that we're happy with: return 1. If there isn't
 * one, and there isn't one on the way, launch one and return 0. If it
 * will never work, return -1.
 *
 * Write the found or in-progress or launched circ into *circp.
 */
static int
circuit_get_open_circ_or_launch(connection_t *conn,
                                uint8_t desired_circuit_purpose,
                                circuit_t **circp) {
  circuit_t *circ;
  uint32_t addr;
  int is_resolve;

  tor_assert(conn);
  tor_assert(circp);
  tor_assert(conn->state == AP_CONN_STATE_CIRCUIT_WAIT);
  is_resolve = conn->socks_request->command == SOCKS_COMMAND_RESOLVE;

  circ = circuit_get_best(conn, 1, desired_circuit_purpose);

  if(circ) {
    *circp = circ;
    return 1; /* we're happy */
  }

  /* Do we need to check exit policy? */
  if(!is_resolve && !connection_edge_is_rendezvous_stream(conn)) {
    addr = client_dns_lookup_entry(conn->socks_request->address);
    if(router_exit_policy_all_routers_reject(addr, conn->socks_request->port)) {
      log_fn(LOG_WARN,"No Tor server exists that allows exit to %s:%d. Rejecting.",
             conn->socks_request->address, conn->socks_request->port);
      return -1;
    }
  }

  /* is one already on the way? */
  circ = circuit_get_best(conn, 0, desired_circuit_purpose);
  if(!circ) {
    char *exitname=NULL;
    uint8_t new_circ_purpose;

    if(desired_circuit_purpose == CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT) {
      /* need to pick an intro point */
      exitname = rend_client_get_random_intro(conn->rend_query);
      if(!exitname) {
        log_fn(LOG_WARN,"Couldn't get an intro point for '%s'. Closing conn.",
               conn->rend_query);
        return -1;
      }
      if(!router_get_by_nickname(exitname)) {
        log_fn(LOG_WARN,"Advertised intro point '%s' is not known. Closing.", exitname);
        return -1;
      }
      /* XXX if we failed, then refetch the descriptor */
      log_fn(LOG_INFO,"Chose %s as intro point for %s.", exitname, conn->rend_query);
    }

    if(desired_circuit_purpose == CIRCUIT_PURPOSE_C_REND_JOINED)
      new_circ_purpose = CIRCUIT_PURPOSE_C_ESTABLISH_REND;
    else if(desired_circuit_purpose == CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT)
      new_circ_purpose = CIRCUIT_PURPOSE_C_INTRODUCING;
    else
      new_circ_purpose = desired_circuit_purpose;

    circ = circuit_launch_by_nickname(new_circ_purpose, exitname);
    tor_free(exitname);

    if(circ &&
       (desired_circuit_purpose != CIRCUIT_PURPOSE_C_GENERAL)) {
      /* then write the service_id into circ */
      strcpy(circ->rend_query, conn->rend_query);
    }
  }
  if(!circ)
    log_fn(LOG_INFO,"No safe circuit (purpose %d) ready for edge connection; delaying.",
           desired_circuit_purpose);
  *circp = circ;
  return 0;
}

/** Attach the AP stream <b>apconn</b> to circ's linked list of
 * p_streams. Also set apconn's cpath_layer to the last hop in
 * circ's cpath.
 */
static void link_apconn_to_circ(connection_t *apconn, circuit_t *circ) {
  /* add it into the linked list of streams on this circuit */
  log_fn(LOG_DEBUG,"attaching new conn to circ. n_circ_id %d.", circ->n_circ_id);
  apconn->next_stream = circ->p_streams;
  /* assert_connection_ok(conn, time(NULL)); */
  circ->p_streams = apconn;

  tor_assert(CIRCUIT_IS_ORIGIN(circ) && circ->cpath && circ->cpath->prev);
  tor_assert(circ->cpath->prev->state == CPATH_STATE_OPEN);
  apconn->cpath_layer = circ->cpath->prev;
}

/** Try to find a safe live circuit for CONN_TYPE_AP connection conn. If
 * we don't find one: if conn cannot be handled by any known nodes,
 * warn and return -1 (conn needs to die);
 * else launch new circuit (if necessary) and return 0.
 * Otherwise, associate conn with a safe live circuit, do the
 * right next step, and return 1.
 */
int connection_ap_handshake_attach_circuit(connection_t *conn) {
  int retval;
  int conn_age;

  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_AP);
  tor_assert(conn->state == AP_CONN_STATE_CIRCUIT_WAIT);
  tor_assert(conn->socks_request);

  conn_age = time(NULL) - conn->timestamp_created;
  if(conn_age > 60) {
    /* XXX make this cleaner than '60' */
    log_fn(LOG_WARN,"Giving up on unattached conn (%d sec old).", conn_age);
    return -1;
  }

  if(!connection_edge_is_rendezvous_stream(conn)) { /* we're a general conn */
    circuit_t *circ=NULL;

    /* find the circuit that we should use, if there is one. */
    retval = circuit_get_open_circ_or_launch(conn, CIRCUIT_PURPOSE_C_GENERAL, &circ);
    if(retval < 1)
      return retval;

    /* We have found a suitable circuit for our conn. Hurray. */

    log_fn(LOG_DEBUG,"Attaching apconn to general circ %d (stream %d sec old).",
           circ->n_circ_id, conn_age);
    /* here, print the circ's path. so people can figure out which circs are sucking. */
    circuit_log_path(LOG_INFO,circ);

    if(!circ->timestamp_dirty)
      circ->timestamp_dirty = time(NULL);

    link_apconn_to_circ(conn, circ);
    tor_assert(conn->socks_request);
    if (conn->socks_request->command == SOCKS_COMMAND_CONNECT)
      connection_ap_handshake_send_begin(conn, circ);
    else
      connection_ap_handshake_send_resolve(conn, circ);

    return 1;
  } else { /* we're a rendezvous conn */
    circuit_t *rendcirc=NULL, *introcirc=NULL;

    tor_assert(!conn->cpath_layer);

    /* start by finding a rendezvous circuit for us */

    retval = circuit_get_open_circ_or_launch(conn, CIRCUIT_PURPOSE_C_REND_JOINED, &rendcirc);
    if(retval < 0) return -1; /* failed */
    tor_assert(rendcirc);

    if(retval > 0) {
      /* one is already established, attach */
      log_fn(LOG_INFO,"rend joined circ %d already here. attaching. (stream %d sec old)",
             rendcirc->n_circ_id, conn_age);
      link_apconn_to_circ(conn, rendcirc);
      if(connection_ap_handshake_send_begin(conn, rendcirc) < 0)
        return 0; /* already marked, let them fade away */
      return 1;
    }

    if(rendcirc->purpose == CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED) {
      log_fn(LOG_INFO,"pending-join circ %d already here, with intro ack. Stalling. (stream %d sec old)", rendcirc->n_circ_id, conn_age);
      return 0;
    }

    /* it's on its way. find an intro circ. */
    retval = circuit_get_open_circ_or_launch(conn, CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT, &introcirc);
    if(retval < 0) return -1; /* failed */
    tor_assert(introcirc);

    if(retval > 0) {
      /* one has already sent the intro. keep waiting. */
      log_fn(LOG_INFO,"Intro circ %d present and awaiting ack (rend %d). Stalling. (stream %d sec old)",
             introcirc->n_circ_id, rendcirc->n_circ_id, conn_age);
      return 0;
    }

    /* now both rendcirc and introcirc are defined, and neither is finished */

    if(rendcirc->purpose == CIRCUIT_PURPOSE_C_REND_READY) {
      log_fn(LOG_INFO,"ready rend circ %d already here (no intro-ack yet on intro %d). (stream %d sec old)",
             rendcirc->n_circ_id, introcirc->n_circ_id, conn_age);
      /* look around for any new intro circs that should introduce */

      tor_assert(introcirc->purpose == CIRCUIT_PURPOSE_C_INTRODUCING);
      if(introcirc->state == CIRCUIT_STATE_OPEN) {
        log_fn(LOG_INFO,"found open intro circ %d (rend %d); sending introduction. (stream %d sec old)",
               introcirc->n_circ_id, rendcirc->n_circ_id, conn_age);
        /* XXX here we should cannibalize the rend circ if it's a zero service id */
        if(rend_client_send_introduction(introcirc, rendcirc) < 0) {
          return -1;
        }
        rendcirc->timestamp_dirty = time(NULL);
        introcirc->timestamp_dirty = time(NULL);
        assert_circuit_ok(rendcirc);
        assert_circuit_ok(introcirc);
        return 0;
      }
    }

    log_fn(LOG_INFO,"Intro (%d) and rend (%d) circs are not both ready. Stalling conn. (%d sec old)", introcirc->n_circ_id, rendcirc->n_circ_id, conn_age);
    return 0;
  }
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
