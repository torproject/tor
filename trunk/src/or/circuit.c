/* Copyright 2001 Matej Pfajfar, 2001-2004 Roger Dingledine. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file circuit.c
 * \brief Manage circuits and the global circuit list.
 **/

#include "or.h"

extern or_options_t options; /* command-line and config-file options */

static int circuit_resume_edge_reading_helper(connection_t *conn,
                                              circuit_t *circ,
                                              crypt_path_t *layer_hint);
static void circuit_free_cpath_node(crypt_path_t *victim);
static uint16_t get_unique_circ_id_by_conn(connection_t *conn, int circ_id_type);
static void circuit_rep_hist_note_result(circuit_t *circ);

void circuit_expire_old_circuits(void);
static void circuit_is_open(circuit_t *circ);
static void circuit_build_failed(circuit_t *circ);
static circuit_t *circuit_establish_circuit(uint8_t purpose, const char *exit_nickname);

/********* START VARIABLES **********/

/** A global (within this file) list of all circuits at this hop. */
static circuit_t *global_circuitlist=NULL;
/** How many entries are in global_circuitlist? */
static int circuitlist_len=0;
/** Array of strings to make circ-\>state human-readable */
char *circuit_state_to_string[] = {
  "doing handshakes",        /* 0 */
  "processing the onion",    /* 1 */
  "connecting to firsthop",  /* 2 */
  "open"                     /* 3 */
};

/********* END VARIABLES ************/

/** Add <b>circ</b> to the global list of circuits. This is called only from
 * within circuit_new.
 */
static void circuit_add(circuit_t *circ) {
  if(!global_circuitlist) { /* first one */
    global_circuitlist = circ;
    circ->next = NULL;
  } else {
    circ->next = global_circuitlist;
    global_circuitlist = circ;
  }
  ++circuitlist_len;
}

/** Detach from the global circuit list, and deallocate, all
 * circuits that have been marked for close.
 */
void circuit_close_all_marked()
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

/** Allocate space for a new circuit, initializing with <b>p_circ_id</b>
 * and <b>p_conn</b>. Add it to the global circuit list.
 */
circuit_t *circuit_new(uint16_t p_circ_id, connection_t *p_conn) {
  circuit_t *circ;

  circ = tor_malloc_zero(sizeof(circuit_t));
  circ->magic = CIRCUIT_MAGIC;

  circ->timestamp_created = time(NULL);

  circ->p_circ_id = p_circ_id;
  circ->p_conn = p_conn;

  circ->state = CIRCUIT_STATE_ONIONSKIN_PENDING;

  /* CircIDs */
  circ->p_circ_id = p_circ_id;
  /* circ->n_circ_id remains 0 because we haven't identified the next hop yet */

  circ->package_window = CIRCWINDOW_START;
  circ->deliver_window = CIRCWINDOW_START;

  circ->next_stream_id = crypto_pseudo_rand_int(1<<16);

  circuit_add(circ);

  return circ;
}

/** Deallocate space associated with circ.
 */
void circuit_free(circuit_t *circ) {
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
  if(circ->build_state) {
    tor_free(circ->build_state->chosen_exit);
    if (circ->build_state->pending_final_cpath)
      circuit_free_cpath_node(circ->build_state->pending_final_cpath);
  }
  tor_free(circ->build_state);
  circuit_free_cpath(circ->cpath);
  if (circ->rend_splice) {
    circ->rend_splice->rend_splice = NULL;
  }

  memset(circ, 0xAA, sizeof(circuit_t)); /* poison memory */
  free(circ);
}

/** Deallocate space associated with the linked list <b>cpath</b>. */
void circuit_free_cpath(crypt_path_t *cpath) {
  crypt_path_t *victim, *head=cpath;

  if(!cpath)
    return;

  /* it's a doubly linked list, so we have to notice when we've
   * gone through it once. */
  while(cpath->next && cpath->next != head) {
    victim = cpath;
    cpath = victim->next;
    circuit_free_cpath_node(victim);
  }

  circuit_free_cpath_node(cpath);
}

/** Deallocate space associated with the cpath node <b>victim</b>. */
static void circuit_free_cpath_node(crypt_path_t *victim) {
  if(victim->f_crypto)
    crypto_free_cipher_env(victim->f_crypto);
  if(victim->b_crypto)
    crypto_free_cipher_env(victim->b_crypto);
  if(victim->f_digest)
    crypto_free_digest_env(victim->f_digest);
  if(victim->b_digest)
    crypto_free_digest_env(victim->b_digest);
  if(victim->handshake_state)
    crypto_dh_free(victim->handshake_state);
  free(victim);
}

/** Iterate over values of circ_id, starting from conn-\>next_circ_id,
 * and with the high bit specified by circ_id_type (see
 * decide_circ_id_type()), until we get a circ_id that is not in use
 * by any other circuit on that conn.
 *
 * Return it, or 0 if can't get a unique circ_id.
 */
static uint16_t get_unique_circ_id_by_conn(connection_t *conn, int circ_id_type) {
  uint16_t test_circ_id;
  int attempts=0;
  uint16_t high_bit;

  tor_assert(conn && conn->type == CONN_TYPE_OR);
  high_bit = (circ_id_type == CIRC_ID_TYPE_HIGHER) ? 1<<15 : 0;
  do {
    /* Sequentially iterate over test_circ_id=1...1<<15-1 until we find a
     * circID such that (high_bit|test_circ_id) is not already used. */
    test_circ_id = conn->next_circ_id++;
    if (test_circ_id == 0 || test_circ_id >= 1<<15) {
      test_circ_id = 1;
      conn->next_circ_id = 2;
    }
    if(++attempts > 1<<15) {
      /* Make sure we don't loop forever if all circ_id's are used. This
       * matters because it's an external DoS vulnerability.
       */
      log_fn(LOG_WARN,"No unused circ IDs. Failing.");
      return 0;
    }
    test_circ_id |= high_bit;
  } while(circuit_get_by_circ_id_conn(test_circ_id, conn));
  return test_circ_id;
}

/** Return a circ such that:
 *  - circ-\>n_circ_id or circ-\>p_circ_id is equal to <b>circ_id</b>, and
 *  - circ is attached to <b>conn</b>, either as p_conn, n-conn, or
 *    in p_streams or n_streams.
 * Return NULL if no such circuit exists.
 */
circuit_t *circuit_get_by_circ_id_conn(uint16_t circ_id, connection_t *conn) {
  circuit_t *circ;
  connection_t *tmpconn;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if (circ->marked_for_close)
      continue;

    if(circ->p_circ_id == circ_id) {
      if(circ->p_conn == conn)
        return circ;
      for(tmpconn = circ->p_streams; tmpconn; tmpconn = tmpconn->next_stream) {
        if(tmpconn == conn)
          return circ;
      }
    }
    if(circ->n_circ_id == circ_id) {
      if(circ->n_conn == conn)
        return circ;
      for(tmpconn = circ->n_streams; tmpconn; tmpconn = tmpconn->next_stream) {
        if(tmpconn == conn)
          return circ;
      }
      for(tmpconn = circ->resolving_streams; tmpconn; tmpconn = tmpconn->next_stream) {
        if(tmpconn == conn)
          return circ;
      }
    }
  }
  return NULL;
}

/** Return a circ such that circ is attached to <b>conn</b>, either as
 * p_conn, n-conn, or in p_streams or n_streams.
 *
 * Return NULL if no such circuit exists.
 */
circuit_t *circuit_get_by_conn(connection_t *conn) {
  circuit_t *circ;
  connection_t *tmpconn;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if (circ->marked_for_close)
      continue;

    if(circ->p_conn == conn)
      return circ;
    if(circ->n_conn == conn)
      return circ;
    for(tmpconn = circ->p_streams; tmpconn; tmpconn=tmpconn->next_stream)
      if(tmpconn == conn)
        return circ;
    for(tmpconn = circ->n_streams; tmpconn; tmpconn=tmpconn->next_stream)
      if(tmpconn == conn)
        return circ;
    for(tmpconn = circ->resolving_streams; tmpconn; tmpconn=tmpconn->next_stream)
      if(tmpconn == conn)
        return circ;
  }
  return NULL;
}

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
       circ->timestamp_dirty+options.NewCircuitPeriod < now)
      return 0;

  if(conn) {
    /* decide if this circ is suitable for this conn */

    /* for rend circs, circ->cpath->prev is not the last router in the
     * circuit, it's the magical extra bob hop. so just check the nickname
     * of the one we meant to finish at.
     */
    exitrouter = router_get_by_nickname(circ->build_state->chosen_exit);

    if(!exitrouter) {
      log_fn(LOG_INFO,"Skipping broken circ (exit router vanished)");
      return 0; /* this circuit is screwed and doesn't know it yet */
    }

    if(purpose == CIRCUIT_PURPOSE_C_GENERAL) {
      if(connection_ap_can_use_exit(conn, exitrouter) == ADDR_POLICY_REJECTED) {
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
circuit_t *circuit_get_best(connection_t *conn,
                            int must_be_open, uint8_t purpose) {
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

/** Return a circ such that:
 *  - circ-\>rend_query is equal to <b>rend_query</b>, and
 *  - circ-\>purpose is equal to <b>purpose</b>.
 *
 * Return NULL if no such circuit exists.
 */
circuit_t *circuit_get_by_rend_query_and_purpose(const char *rend_query, uint8_t purpose) {
  circuit_t *circ;

  for (circ = global_circuitlist; circ; circ = circ->next) {
    if (!circ->marked_for_close &&
        circ->purpose == purpose &&
        !rend_cmp_service_ids(rend_query, circ->rend_query))
      return circ;
  }
  return NULL;
}

/** Return the first circuit in global_circuitlist after <b>start</b> whose
 * rend_pk_digest field is <b>digest</b> and whose purpose is <b>purpose</b>. Returns
 * NULL if no circuit is found.  If <b>start</b> is NULL, begin at the start of
 * the list.
 */
circuit_t *circuit_get_next_by_pk_and_purpose(circuit_t *start,
                                         const char *digest, uint8_t purpose)
{
  circuit_t *circ;
  if (start == NULL)
    circ = global_circuitlist;
  else
    circ = start->next;

  for( ; circ; circ = circ->next) {
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
circuit_t *circuit_get_rendezvous(const char *cookie)
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
               victim->purpose, victim->build_state->chosen_exit,
               victim->n_circ_id);
      else
        log_fn(LOG_DEBUG,"Considering %sopen purp %d to %s (circid %d). %d secs since dirty.",
               victim->state == CIRCUIT_STATE_OPEN ? "" : "non",
               victim->purpose, victim->build_state->chosen_exit,
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

/** Count the number of circs originating here that aren't open, and
 * that have the specified <b>purpose</b>. */
int circuit_count_building(uint8_t purpose) {
  circuit_t *circ;
  int num=0;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if(CIRCUIT_IS_ORIGIN(circ) &&
       circ->state != CIRCUIT_STATE_OPEN &&
       circ->purpose == purpose &&
       !circ->marked_for_close)
      num++;
  }
  return num;
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
      exitrouter = router_get_by_nickname(circ->build_state->chosen_exit);
      if(exitrouter && connection_ap_can_use_exit(conn, exitrouter) != ADDR_POLICY_REJECTED)
        if(++num >= MIN_CIRCUITS_HANDLING_STREAM)
          return 1;
    }
  }
  return 0;
}

/** Return the circuit that is open, has specified <b>purpose</b>,
 * has a timestamp_dirty value of 0, and was created most recently,
 * or NULL if no circuit fits this description.
 */
static circuit_t *
circuit_get_youngest_clean_open(uint8_t purpose) {
  circuit_t *circ;
  circuit_t *youngest=NULL;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if(CIRCUIT_IS_ORIGIN(circ) && circ->state == CIRCUIT_STATE_OPEN &&
       !circ->marked_for_close && circ->purpose == purpose &&
       !circ->timestamp_dirty &&
       (!youngest || youngest->timestamp_created < circ->timestamp_created))
      youngest = circ;
  }
  return youngest;
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
  rend_services_introduce();

  circ = circuit_get_youngest_clean_open(CIRCUIT_PURPOSE_C_GENERAL);

  if(time_to_new_circuit < now) {
    circuit_reset_failure_count();
    time_to_new_circuit = now + options.NewCircuitPeriod;
    if(options.SocksPort)
      client_dns_clean();
    circuit_expire_old_circuits();

    if(options.RunTesting && circ &&
               circ->timestamp_created + TESTING_CIRCUIT_INTERVAL < now) {
      log_fn(LOG_INFO,"Creating a new testing circuit.");
      circuit_launch_new(CIRCUIT_PURPOSE_C_GENERAL, NULL);
    }
  }

/** How many simultaneous in-progress general-purpose circuits do we
 * want to be building at once, if there are no open general-purpose
 * circuits?
 */
#define CIRCUIT_MIN_BUILDING_GENERAL 3
  /* if there's no open circ, and less than 3 are on the way,
   * go ahead and try another. */
  if(!circ && circuit_count_building(CIRCUIT_PURPOSE_C_GENERAL)
              < CIRCUIT_MIN_BUILDING_GENERAL) {
    circuit_launch_new(CIRCUIT_PURPOSE_C_GENERAL, NULL);
  }

  /* XXX count idle rendezvous circs and build more */
}

/** The circuit <b>circ</b> has received a circuit-level sendme
 * (on hop <b>layer_hint</b>, if we're the OP). Go through all the
 * attached streams and let them resume reading and packaging, if
 * their stream windows allow it.
 */
void circuit_resume_edge_reading(circuit_t *circ, crypt_path_t *layer_hint) {

  log_fn(LOG_DEBUG,"resuming");

  /* have to check both n_streams and p_streams, to handle rendezvous */
  if(circuit_resume_edge_reading_helper(circ->n_streams, circ, layer_hint) >= 0)
    circuit_resume_edge_reading_helper(circ->p_streams, circ, layer_hint);
}

/** A helper function for circuit_resume_edge_reading() above.
 * The arguments are the same, except that <b>conn</b> is the head
 * of a linked list of edge streams that should each be considered.
 */
static int
circuit_resume_edge_reading_helper(connection_t *conn,
                                   circuit_t *circ,
                                   crypt_path_t *layer_hint) {

  for( ; conn; conn=conn->next_stream) {
    if((!layer_hint && conn->package_window > 0) ||
       (layer_hint && conn->package_window > 0 && conn->cpath_layer == layer_hint)) {
      connection_start_reading(conn);
      /* handle whatever might still be on the inbuf */
      connection_edge_package_raw_inbuf(conn);

      /* If the circuit won't accept any more data, return without looking
       * at any more of the streams. Any connections that should be stopped
       * have already been stopped by connection_edge_package_raw_inbuf. */
      if(circuit_consider_stop_edge_reading(circ, layer_hint))
        return -1;
    }
  }
  return 0;
}

/** Check if the package window for <b>circ</b> is empty (at
 * hop <b>layer_hint</b> if it's defined).
 *
 * If yes, tell edge streams to stop reading and return -1.
 * Else return 0.
 */
int circuit_consider_stop_edge_reading(circuit_t *circ, crypt_path_t *layer_hint) {
  connection_t *conn = NULL;

  log_fn(LOG_DEBUG,"considering");
  if(!layer_hint && circ->package_window <= 0) {
    log_fn(LOG_DEBUG,"yes, not-at-origin. stopped.");
    for(conn = circ->n_streams; conn; conn=conn->next_stream)
      connection_stop_reading(conn);
    return -1;
  } else if(layer_hint && layer_hint->package_window <= 0) {
    log_fn(LOG_DEBUG,"yes, at-origin. stopped.");
    for(conn = circ->n_streams; conn; conn=conn->next_stream)
      if(conn->cpath_layer == layer_hint)
        connection_stop_reading(conn);
    for(conn = circ->p_streams; conn; conn=conn->next_stream)
      if(conn->cpath_layer == layer_hint)
        connection_stop_reading(conn);
    return -1;
  }
  return 0;
}

/** Check if the deliver_window for circuit <b>circ</b> (at hop
 * <b>layer_hint</b> if it's defined) is low enough that we should
 * send a circuit-level sendme back down the circuit. If so, send
 * enough sendmes that the window would be overfull if we sent any
 * more.
 */
void circuit_consider_sending_sendme(circuit_t *circ, crypt_path_t *layer_hint) {
//  log_fn(LOG_INFO,"Considering: layer_hint is %s",
//         layer_hint ? "defined" : "null");
  while((layer_hint ? layer_hint->deliver_window : circ->deliver_window) <
         CIRCWINDOW_START - CIRCWINDOW_INCREMENT) {
    log_fn(LOG_DEBUG,"Queueing circuit sendme.");
    if(layer_hint)
      layer_hint->deliver_window += CIRCWINDOW_INCREMENT;
    else
      circ->deliver_window += CIRCWINDOW_INCREMENT;
    if(connection_edge_send_command(NULL, circ, RELAY_COMMAND_SENDME,
                                    NULL, 0, layer_hint) < 0) {
      log_fn(LOG_WARN,"connection_edge_send_command failed. Circuit's closed.");
      return; /* the circuit's closed, don't continue */
    }
  }
}

/** Mark <b>circ</b> to be closed next time we call
 * circuit_close_all_marked(). Do any cleanup needed:
 *   - If state is onionskin_pending, remove circ from the onion_pending
 *     list.
 *   - If circ isn't open yet, call circuit_build_failed() if we're
 *     the origin, and in case call circuit_rep_hist_note_result()
 *     to note stats.
 *   - If purpose is C_INTRODUCE_ACK_WAIT, remove the intro point we
 *     just tried from our list of intro points for that service
 *     descriptor.
 *   - Send appropriate destroys and edge_destroys for conns and
 *     streams attached to circ.
 *   - If circ->rend_splice is set (we are the midpoint of a joined
 *     rendezvous stream), then mark the other circuit to close as well.
 */
int _circuit_mark_for_close(circuit_t *circ) {
  connection_t *conn;

  assert_circuit_ok(circ);
  if (circ->marked_for_close)
    return -1;

  if(circ->state == CIRCUIT_STATE_ONIONSKIN_PENDING) {
    onion_pending_remove(circ);
  }
  /* If the circuit ever became OPEN, we sent it to the reputation history
   * module then.  If it isn't OPEN, we send it there now to remember which
   * links worked and which didn't.
   */
  if (circ->state != CIRCUIT_STATE_OPEN) {
    if(CIRCUIT_IS_ORIGIN(circ))
      circuit_build_failed(circ); /* take actions if necessary */
    circuit_rep_hist_note_result(circ);
  }
  if (circ->purpose == CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT) {
    tor_assert(circ->state == CIRCUIT_STATE_OPEN);
    /* treat this like getting a nack from it */
    log_fn(LOG_INFO,"Failed intro circ %s to %s (awaiting ack). Removing from descriptor.",
           circ->rend_query, circ->build_state->chosen_exit);
    rend_client_remove_intro_point(circ->build_state->chosen_exit, circ->rend_query);
  }

  if(circ->n_conn)
    connection_send_destroy(circ->n_circ_id, circ->n_conn);
  for(conn=circ->n_streams; conn; conn=conn->next_stream)
    connection_edge_destroy(circ->n_circ_id, conn);
  while(circ->resolving_streams) {
    conn = circ->resolving_streams;
    circ->resolving_streams = conn->next_stream;
    log_fn(LOG_INFO,"Freeing resolving-conn.");
    connection_free(conn);
  }
  if(circ->p_conn)
    connection_send_destroy(circ->p_circ_id, circ->p_conn);
  for(conn=circ->p_streams; conn; conn=conn->next_stream)
    connection_edge_destroy(circ->p_circ_id, conn);

  circ->marked_for_close = 1;

  if (circ->rend_splice && !circ->rend_splice->marked_for_close) {
    /* do this after marking this circuit, to avoid infinite recursion. */
    circuit_mark_for_close(circ->rend_splice);
    circ->rend_splice = NULL;
  }
  return 0;
}

/** If the stream <b>conn</b> is a member of any of the linked
 * lists of <b>circ</b>, then remove it from the list.
 */
void circuit_detach_stream(circuit_t *circ, connection_t *conn) {
  connection_t *prevconn;

  tor_assert(circ && conn);

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
      /* We must close all the circuits on it. */
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

      if(!conn->has_sent_end) {
        log_fn(LOG_WARN,"Edge connection hasn't sent end yet? Bug.");
        connection_mark_for_close(conn, END_STREAM_REASON_MISC);
      }

      circuit_detach_stream(circ, conn);

  } /* end switch */
}

/** Log, at severity <b>severity</b>, the nicknames of each router in
 * circ's cpath. Also log the length of the cpath, and the intended
 * exit point.
 */
void circuit_log_path(int severity, circuit_t *circ) {
  char buf[1024];
  char *s = buf;
  struct crypt_path_t *hop;
  char *states[] = {"closed", "waiting for keys", "open"};
  routerinfo_t *router;
  tor_assert(CIRCUIT_IS_ORIGIN(circ) && circ->cpath);

  snprintf(s, sizeof(buf)-1, "circ (length %d, exit %s): ",
          circ->build_state->desired_path_len, circ->build_state->chosen_exit);
  hop=circ->cpath;
  do {
    s = buf + strlen(buf);
    router = router_get_by_addr_port(hop->addr,hop->port);
    if(router) {
      snprintf(s, sizeof(buf) - (s - buf), "%s(%s) ",
               router->nickname, states[hop->state]);
    } else {
      if(circ->purpose == CIRCUIT_PURPOSE_C_REND_JOINED) {
        snprintf(s, sizeof(buf) - (s - buf), "(rendjoin hop)");
      } else {
        snprintf(s, sizeof(buf) - (s - buf), "UNKNOWN ");
      }
    }
    hop=hop->next;
  } while(hop!=circ->cpath);
  log_fn(severity,"%s",buf);
}

/** Tell the rep(utation)hist(ory) module about the status of the links
 * in circ.  Hops that have become OPEN are marked as successfully
 * extended; the _first_ hop that isn't open (if any) is marked as
 * unable to extend.
 */
static void
circuit_rep_hist_note_result(circuit_t *circ)
{
  struct crypt_path_t *hop;
  char *prev_nickname = NULL;
  routerinfo_t *router;
  hop = circ->cpath;
  if(!hop) {
    /* XXX
     * if !hop, then we're not the beginning of this circuit.
     * for now, just forget about it. later, we should remember when
     * extends-through-us failed, too.
     */
    return;
  }
  if (options.ORPort) {
    prev_nickname = options.Nickname;
  }
  do {
    router = router_get_by_addr_port(hop->addr,hop->port);
    if (router) {
      if (prev_nickname) {
        if (hop->state == CPATH_STATE_OPEN)
          rep_hist_note_extend_succeeded(prev_nickname, router->nickname);
        else {
          rep_hist_note_extend_failed(prev_nickname, router->nickname);
          break;
        }
      }
      prev_nickname = router->nickname;
    } else {
      prev_nickname = NULL;
    }
    hop=hop->next;
  } while (hop!=circ->cpath);
}

/** A helper function for circuit_dump_by_conn() below. Log a bunch
 * of information about circuit <b>circ</b>.
 */
static void
circuit_dump_details(int severity, circuit_t *circ, int poll_index,
                     char *type, int this_circid, int other_circid) {
  struct crypt_path_t *hop;
  log(severity,"Conn %d has %s circuit: circID %d (other side %d), state %d (%s), born %d",
      poll_index, type, this_circid, other_circid, circ->state,
      circuit_state_to_string[circ->state], (int)circ->timestamp_created);
  if(CIRCUIT_IS_ORIGIN(circ)) { /* circ starts at this node */
    if(circ->state == CIRCUIT_STATE_BUILDING)
      log(severity,"Building: desired len %d, planned exit node %s.",
          circ->build_state->desired_path_len, circ->build_state->chosen_exit);
    for(hop=circ->cpath;hop->next != circ->cpath; hop=hop->next)
      log(severity,"hop: state %d, addr 0x%.8x, port %d", hop->state,
          (unsigned int)hop->addr,
          (int)hop->port);
  }
}

/** Log, at severity <b>severity</b>, information about each circuit
 * that is connected to <b>conn</b>.
 */
void circuit_dump_by_conn(connection_t *conn, int severity) {
  circuit_t *circ;
  connection_t *tmpconn;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if(circ->p_conn == conn)
      circuit_dump_details(severity, circ, conn->poll_index, "App-ward",
                           circ->p_circ_id, circ->n_circ_id);
    for(tmpconn=circ->p_streams; tmpconn; tmpconn=tmpconn->next_stream) {
      if(tmpconn == conn) {
        circuit_dump_details(severity, circ, conn->poll_index, "App-ward",
                             circ->p_circ_id, circ->n_circ_id);
      }
    }
    if(circ->n_conn == conn)
      circuit_dump_details(severity, circ, conn->poll_index, "Exit-ward",
                           circ->n_circ_id, circ->p_circ_id);
    for(tmpconn=circ->n_streams; tmpconn; tmpconn=tmpconn->next_stream) {
      if(tmpconn == conn) {
        circuit_dump_details(severity, circ, conn->poll_index, "Exit-ward",
                             circ->n_circ_id, circ->p_circ_id);
      }
    }
  }
}

/** Don't keep more than 10 unused open circuits around. */
#define MAX_UNUSED_OPEN_CIRCUITS 10

/** Find each circuit that has been dirty for too long, and has
 * no streams on it: mark it for close.
 *
 * Also, if there are more than MAX_UNUSED_OPEN_CIRCUITS open and
 * unused circuits, then mark the excess circs for close.
 */
void circuit_expire_old_circuits(void) {
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
static void circuit_is_open(circuit_t *circ) {

  switch(circ->purpose) {
    case CIRCUIT_PURPOSE_C_ESTABLISH_REND:
      rend_client_rendcirc_is_open(circ);
      break;
    case CIRCUIT_PURPOSE_C_INTRODUCING:
      rend_client_introcirc_is_open(circ);
      break;
    case CIRCUIT_PURPOSE_C_GENERAL:
      /* Tell any AP connections that have been waiting for a new
       * circuit that one is ready. */
      connection_ap_attach_pending();
      break;
    case CIRCUIT_PURPOSE_S_ESTABLISH_INTRO:
      /* at Bob, waiting for introductions */
      rend_service_intro_is_ready(circ);
      break;
    case CIRCUIT_PURPOSE_S_CONNECT_REND:
      /* at Bob, connecting to rend point */
      rend_service_rendezvous_is_ready(circ);
      break;
    default:
      log_fn(LOG_ERR,"unhandled purpose %d",circ->purpose);
      tor_assert(0);
  }
}

/*~ Called whenever a circuit could not be successfully built.
 */
static void circuit_build_failed(circuit_t *circ) {

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
        log_fn(LOG_INFO,"Couldn't connect to Alice's chosen rend point %s. Sucks to be Alice.", circ->build_state->chosen_exit);
      } else {
        log_fn(LOG_INFO,"Couldn't connect to Alice's chosen rend point %s, because an earlier node failed.",
               circ->build_state->chosen_exit);
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

/** Don't retry launching a new circuit if we try this many times with no
 * success. */
#define MAX_CIRCUIT_FAILURES 5

/** Launch a new circuit and return a pointer to it. Return NULL if you failed. */
circuit_t *circuit_launch_new(uint8_t purpose, const char *exit_nickname) {

  if (n_circuit_failures > MAX_CIRCUIT_FAILURES) {
    /* too many failed circs in a row. don't try. */
//    log_fn(LOG_INFO,"%d failures so far, not trying.",n_circuit_failures);
    return NULL;
  }

  /* try a circ. if it fails, circuit_mark_for_close will increment n_circuit_failures */
  return circuit_establish_circuit(purpose, exit_nickname);
}

/** Record another failure at opening a general circuit. When we have
 * too many, we'll stop trying for the remainder of this minute.
 */
void circuit_increment_failure_count(void) {
  ++n_circuit_failures;
  log_fn(LOG_DEBUG,"n_circuit_failures now %d.",n_circuit_failures);
}

/** Reset the failure count for opening general circuits. This means
 * we will try MAX_CIRCUIT_FAILURES times more (if necessary) before
 * stopping again.
 */
void circuit_reset_failure_count(void) {
  n_circuit_failures = 0;
}

/** Build a new circuit for <b>purpose</b>. If <b>exit_nickname</b>
 * is defined, then use that as your exit router, else choose a suitable
 * exit node.
 *
 * Also launch a connection to the first OR in the chosen path, if
 * it's not open already.
 */
static circuit_t *circuit_establish_circuit(uint8_t purpose,
                                            const char *exit_nickname) {
  routerinfo_t *firsthop;
  connection_t *n_conn;
  circuit_t *circ;

  circ = circuit_new(0, NULL); /* sets circ->p_circ_id and circ->p_conn */
  circ->state = CIRCUIT_STATE_OR_WAIT;
  circ->build_state = onion_new_cpath_build_state(purpose, exit_nickname);
  circ->purpose = purpose;

  if (! circ->build_state) {
    log_fn(LOG_INFO,"Generating cpath failed.");
    circuit_mark_for_close(circ);
    return NULL;
  }

  onion_extend_cpath(&circ->cpath, circ->build_state, &firsthop);
  if(!CIRCUIT_IS_ORIGIN(circ)) {
    log_fn(LOG_INFO,"Generating first cpath hop failed.");
    circuit_mark_for_close(circ);
    return NULL;
  }

  /* now see if we're already connected to the first OR in 'route' */

  log_fn(LOG_DEBUG,"Looking for firsthop '%s:%u'",
      firsthop->address,firsthop->or_port);
  n_conn = connection_twin_get_by_addr_port(firsthop->addr,firsthop->or_port);
  if(!n_conn || n_conn->state != OR_CONN_STATE_OPEN) { /* not currently connected */
    circ->n_addr = firsthop->addr;
    circ->n_port = firsthop->or_port;

    if(!n_conn) { /* launch the connection */
      n_conn = connection_or_connect(firsthop);
      if(!n_conn) { /* connect failed, forget the whole thing */
        log_fn(LOG_INFO,"connect to firsthop failed. Closing.");
        circuit_mark_for_close(circ);
        return NULL;
      }
    }

    log_fn(LOG_DEBUG,"connecting in progress (or finished). Good.");
    /* return success. The onion/circuit/etc will be taken care of automatically
     * (may already have been) whenever n_conn reaches OR_CONN_STATE_OPEN.
     */
    return circ;
  } else { /* it (or a twin) is already open. use it. */
    circ->n_addr = n_conn->addr;
    circ->n_port = n_conn->port;
    circ->n_conn = n_conn;
    log_fn(LOG_DEBUG,"Conn open. Delivering first onion skin.");
    if(circuit_send_next_onion_skin(circ) < 0) {
      log_fn(LOG_INFO,"circuit_send_next_onion_skin failed.");
      circuit_mark_for_close(circ);
      return NULL;
    }
  }
  return circ;
}

/** Find circuits that are waiting on <b>or_conn</b> to become open,
 * if any, and get them to send their create cells forward.
 */
void circuit_n_conn_open(connection_t *or_conn) {
  circuit_t *circ;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if (circ->marked_for_close)
      continue;
    if(CIRCUIT_IS_ORIGIN(circ) && circ->n_addr == or_conn->addr && circ->n_port == or_conn->port) {
      tor_assert(circ->state == CIRCUIT_STATE_OR_WAIT);
      log_fn(LOG_DEBUG,"Found circ %d, sending onion skin.", circ->n_circ_id);
      circ->n_conn = or_conn;
      if(circuit_send_next_onion_skin(circ) < 0) {
        log_fn(LOG_INFO,"send_next_onion_skin failed; circuit marked for closing.");
        circuit_mark_for_close(circ);
        continue;
        /* XXX could this be bad, eg if next_onion_skin failed because conn died? */
      }
    }
  }
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
 * Return -1 if we want to tear down circ, else return 0.
 */
int circuit_send_next_onion_skin(circuit_t *circ) {
  cell_t cell;
  crypt_path_t *hop;
  routerinfo_t *router;
  int r;
  int circ_id_type;
  char payload[2+4+ONIONSKIN_CHALLENGE_LEN];

  tor_assert(circ && CIRCUIT_IS_ORIGIN(circ));

  if(circ->cpath->state == CPATH_STATE_CLOSED) {
    tor_assert(circ->n_conn && circ->n_conn->type == CONN_TYPE_OR);

    log_fn(LOG_DEBUG,"First skin; sending create cell.");
    circ_id_type = decide_circ_id_type(options.Nickname,
                                       circ->n_conn->nickname);
    circ->n_circ_id = get_unique_circ_id_by_conn(circ->n_conn, circ_id_type);

    memset(&cell, 0, sizeof(cell_t));
    cell.command = CELL_CREATE;
    cell.circ_id = circ->n_circ_id;

    router = router_get_by_nickname(circ->n_conn->nickname);
    if (!router) {
      log_fn(LOG_WARN,"Couldn't find routerinfo for %s",
             circ->n_conn->nickname);
      return -1;
    }

    if(onion_skin_create(router->onion_pkey,
                         &(circ->cpath->handshake_state),
                         cell.payload) < 0) {
      log_fn(LOG_WARN,"onion_skin_create (first hop) failed.");
      return -1;
    }

    connection_or_write_cell_to_buf(&cell, circ->n_conn);

    circ->cpath->state = CPATH_STATE_AWAITING_KEYS;
    circ->state = CIRCUIT_STATE_BUILDING;
    log_fn(LOG_DEBUG,"first skin; finished sending create cell.");
  } else {
    tor_assert(circ->cpath->state == CPATH_STATE_OPEN);
    tor_assert(circ->state == CIRCUIT_STATE_BUILDING);
    log_fn(LOG_DEBUG,"starting to send subsequent skin.");
    r = onion_extend_cpath(&circ->cpath, circ->build_state, &router);
    if (r==1) {
      /* done building the circuit. whew. */
      circ->state = CIRCUIT_STATE_OPEN;
      log_fn(LOG_INFO,"circuit built!");
      circuit_reset_failure_count();
      if(!has_completed_circuit) {
        has_completed_circuit=1;
        log_fn(LOG_NOTICE,"Tor has successfully opened a circuit. Looks like it's working.");
      }
      circuit_rep_hist_note_result(circ);
      circuit_is_open(circ); /* do other actions as necessary */
      return 0;
    } else if (r<0) {
      log_fn(LOG_INFO,"Unable to extend circuit path.");
      return -1;
    }
    hop = circ->cpath->prev;

    *(uint32_t*)payload = htonl(hop->addr);
    *(uint16_t*)(payload+4) = htons(hop->port);
    if(onion_skin_create(router->onion_pkey, &(hop->handshake_state), payload+6) < 0) {
      log_fn(LOG_WARN,"onion_skin_create failed.");
      return -1;
    }

    log_fn(LOG_DEBUG,"Sending extend relay cell.");
    /* send it to hop->prev, because it will transfer
     * it to a create cell and then send to hop */
    if(connection_edge_send_command(NULL, circ, RELAY_COMMAND_EXTEND,
                               payload, sizeof(payload), hop->prev) < 0)
      return 0; /* circuit is closed */

    hop->state = CPATH_STATE_AWAITING_KEYS;
  }
  return 0;
}

/** Take the 'extend' cell, pull out addr/port plus the onion skin. Make
 * sure we're connected to the next hop, and pass it the onion skin in
 * a create cell.
 */
int circuit_extend(cell_t *cell, circuit_t *circ) {
  connection_t *n_conn;
  int circ_id_type;
  cell_t newcell;

  if(circ->n_conn) {
    log_fn(LOG_WARN,"n_conn already set. Bug/attack. Closing.");
    return -1;
  }

  circ->n_addr = ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE));
  circ->n_port = ntohs(get_uint16(cell->payload+RELAY_HEADER_SIZE+4));

  n_conn = connection_twin_get_by_addr_port(circ->n_addr,circ->n_port);
  if(!n_conn || n_conn->type != CONN_TYPE_OR) {
    /* I've disabled making connections through OPs, but it's definitely
     * possible here. I'm not sure if it would be a bug or a feature.
     *
     * Note also that this will close circuits where the onion has the same
     * router twice in a row in the path. I think that's ok.
     */
    struct in_addr in;
    in.s_addr = htonl(circ->n_addr);
    log_fn(LOG_INFO,"Next router (%s:%d) not connected. Closing.", inet_ntoa(in), circ->n_port);
#if 0 /* if we do truncateds, no need to kill circ */
    connection_edge_send_command(NULL, circ, RELAY_COMMAND_TRUNCATED,
                                 NULL, 0, NULL);
    return 0;
#endif
    circuit_mark_for_close(circ);
    return 0;
  }

  circ->n_addr = n_conn->addr; /* these are different if we found a twin instead */
  circ->n_port = n_conn->port;

  circ->n_conn = n_conn;
  log_fn(LOG_DEBUG,"n_conn is %s:%u",n_conn->address,n_conn->port);

  circ_id_type = decide_circ_id_type(options.Nickname, n_conn->nickname);

//  log_fn(LOG_DEBUG,"circ_id_type = %u.",circ_id_type);
  circ->n_circ_id = get_unique_circ_id_by_conn(circ->n_conn, circ_id_type);
  if(!circ->n_circ_id) {
    log_fn(LOG_WARN,"failed to get unique circID.");
    return -1;
  }
  log_fn(LOG_DEBUG,"Chosen circID %u.",circ->n_circ_id);

  memset(&newcell, 0, sizeof(cell_t));
  newcell.command = CELL_CREATE;
  newcell.circ_id = circ->n_circ_id;

  memcpy(newcell.payload, cell->payload+RELAY_HEADER_SIZE+2+4,
         ONIONSKIN_CHALLENGE_LEN);

  connection_or_write_cell_to_buf(&newcell, circ->n_conn);
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
int circuit_init_cpath_crypto(crypt_path_t *cpath, char *key_data, int reverse)
{
  crypto_digest_env_t *tmp_digest;
  crypto_cipher_env_t *tmp_crypto;

  tor_assert(cpath && key_data);
  tor_assert(!(cpath->f_crypto || cpath->b_crypto ||
             cpath->f_digest || cpath->b_digest));

  log_fn(LOG_DEBUG,"hop init digest forward 0x%.8x, backward 0x%.8x.",
         (unsigned int)*(uint32_t*)key_data, (unsigned int)*(uint32_t*)(key_data+20));
  cpath->f_digest = crypto_new_digest_env();
  crypto_digest_add_bytes(cpath->f_digest, key_data, DIGEST_LEN);
  cpath->b_digest = crypto_new_digest_env();
  crypto_digest_add_bytes(cpath->b_digest, key_data+DIGEST_LEN, DIGEST_LEN);

  log_fn(LOG_DEBUG,"hop init cipher forward 0x%.8x, backward 0x%.8x.",
         (unsigned int)*(uint32_t*)(key_data+40), (unsigned int)*(uint32_t*)(key_data+40+16));
  if (!(cpath->f_crypto =
        crypto_create_init_cipher(key_data+(2*DIGEST_LEN),1))) {
    log(LOG_WARN,"forward cipher initialization failed.");
    return -1;
  }
  if (!(cpath->b_crypto =
     crypto_create_init_cipher(key_data+(2*DIGEST_LEN)+CIPHER_KEY_LEN,0))) {
    log(LOG_WARN,"backward cipher initialization failed.");
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

/** A created or extended cell came back to us on the circuit,
 * and it included <b>reply</b> (the second DH key, plus KH).
 *
 * Calculate the appropriate keys and digests, make sure KH is
 * correct, and initialize this hop of the cpath.
 *
 * Return -1 if we want to mark circ for close, else return 0.
 */
int circuit_finish_handshake(circuit_t *circ, char *reply) {
  unsigned char keys[CPATH_KEY_MATERIAL_LEN];
  crypt_path_t *hop;

  tor_assert(CIRCUIT_IS_ORIGIN(circ));
  if(circ->cpath->state == CPATH_STATE_AWAITING_KEYS)
    hop = circ->cpath;
  else {
    for(hop=circ->cpath->next;
        hop != circ->cpath && hop->state == CPATH_STATE_OPEN;
        hop=hop->next) ;
    if(hop == circ->cpath) { /* got an extended when we're all done? */
      log_fn(LOG_WARN,"got extended when circ already built? Closing.");
      return -1;
    }
  }
  tor_assert(hop->state == CPATH_STATE_AWAITING_KEYS);

  if(onion_skin_client_handshake(hop->handshake_state, reply, keys,
                                 DIGEST_LEN*2+CIPHER_KEY_LEN*2) < 0) {
    log_fn(LOG_WARN,"onion_skin_client_handshake failed.");
    return -1;
  }

  crypto_dh_free(hop->handshake_state); /* don't need it anymore */
  hop->handshake_state = NULL;
  /* Remember hash of g^xy */
  memcpy(hop->handshake_digest, reply+DH_KEY_LEN, DIGEST_LEN);

  if (circuit_init_cpath_crypto(hop, keys, 0)<0) {
    return -1;
  }

  hop->state = CPATH_STATE_OPEN;
  log_fn(LOG_INFO,"finished");
  circuit_log_path(LOG_INFO,circ);
  return 0;
}

/** We received a relay truncated cell on circ.
 *
 * Since we don't ask for truncates currently, getting a truncated
 * means that a connection broke or an extend failed. For now,
 * just give up: for circ to close, and return 0.
 */
int circuit_truncated(circuit_t *circ, crypt_path_t *layer) {
  crypt_path_t *victim;
  connection_t *stream;

  tor_assert(circ && CIRCUIT_IS_ORIGIN(circ));
  tor_assert(layer);

  /* XXX Since we don't ask for truncates currently, getting a truncated
   *     means that a connection broke or an extend failed. For now,
   *     just give up.
   */
  circuit_mark_for_close(circ);
  return 0;

  while(layer->next != circ->cpath) {
    /* we need to clear out layer->next */
    victim = layer->next;
    log_fn(LOG_DEBUG, "Killing a layer of the cpath.");

    for(stream = circ->p_streams; stream; stream=stream->next_stream) {
      if(stream->cpath_layer == victim) {
        log_fn(LOG_INFO, "Marking stream %d for close.", stream->stream_id);
        /* no need to send 'end' relay cells,
         * because the other side's already dead
         */
        connection_mark_for_close(stream,0);
      }
    }

    layer->next = victim->next;
    circuit_free_cpath_node(victim);
  }

  log_fn(LOG_INFO, "finished");
  return 0;
}

/** Verify that cpath layer <b>cp</b> has all of its invariants
 * correct. Trigger an assert if anything is invalid.
 */
void assert_cpath_layer_ok(const crypt_path_t *cp)
{
  tor_assert(cp->f_crypto);
  tor_assert(cp->b_crypto);
//  tor_assert(cp->addr); /* these are zero for rendezvous extra-hops */
//  tor_assert(cp->port);
  switch(cp->state)
    {
    case CPATH_STATE_CLOSED:
    case CPATH_STATE_OPEN:
      tor_assert(!cp->handshake_state);
      break;
    case CPATH_STATE_AWAITING_KEYS:
      tor_assert(cp->handshake_state);
      break;
    default:
      tor_assert(0);
    }
  tor_assert(cp->package_window >= 0);
  tor_assert(cp->deliver_window >= 0);
}

/** Verify that cpath <b>cp</b> has all of its invariants
 * correct. Trigger an assert if anything is invalid.
 */
void assert_cpath_ok(const crypt_path_t *cp)
{
  while(cp->prev)
    cp = cp->prev;

  while(cp->next) {
    assert_cpath_layer_ok(cp);
    /* layers must be in sequence of: "open* awaiting? closed*" */
    if (cp->prev) {
      if (cp->prev->state == CPATH_STATE_OPEN) {
        tor_assert(cp->state == CPATH_STATE_CLOSED ||
                   cp->state == CPATH_STATE_AWAITING_KEYS);
      } else {
        tor_assert(cp->state == CPATH_STATE_CLOSED);
      }
    }
    cp = cp->next;
  }
}

/** Verify that circuit <b>c</b> has all of its invariants
 * correct. Trigger an assert if anything is invalid.
 */
void assert_circuit_ok(const circuit_t *c)
{
  connection_t *conn;

  tor_assert(c);
  tor_assert(c->magic == CIRCUIT_MAGIC);
  tor_assert(c->purpose >= _CIRCUIT_PURPOSE_MIN &&
             c->purpose <= _CIRCUIT_PURPOSE_MAX);

  if (c->n_conn)
    tor_assert(c->n_conn->type == CONN_TYPE_OR);
  if (c->p_conn)
    tor_assert(c->p_conn->type == CONN_TYPE_OR);
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
//XXX    assert_cpath_ok(c->cpath);
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

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
