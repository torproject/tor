/* Copyright 2001 Matej Pfajfar.
 * Copyright 2001-2004 Roger Dingledine.
 * Copyright 2004-2005 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char circuitbuild_c_id[] = "$Id$";

/**
 * \file circuitbuild.c
 * \brief The actual details of building circuits.
 **/

#include "or.h"

/********* START VARIABLES **********/

/** A global list of all circuits at this hop. */
extern circuit_t *global_circuitlist;

/********* END VARIABLES ************/

static int circuit_deliver_create_cell(circuit_t *circ,
                                       uint8_t cell_type, char *payload);
static int onion_pick_cpath_exit(circuit_t *circ, routerinfo_t *exit);
static crypt_path_t *onion_next_hop_in_cpath(crypt_path_t *cpath);
static int onion_next_router_in_cpath(circuit_t *circ, routerinfo_t **router);
static int onion_extend_cpath(uint8_t purpose, crypt_path_t **head_ptr,
                              cpath_build_state_t *state);
static int count_acceptable_routers(smartlist_t *routers);
static int onion_append_hop(crypt_path_t **head_ptr, routerinfo_t *choice);

/** Iterate over values of circ_id, starting from conn-\>next_circ_id,
 * and with the high bit specified by circ_id_type (see
 * decide_circ_id_type()), until we get a circ_id that is not in use
 * by any other circuit on that conn.
 *
 * Return it, or 0 if can't get a unique circ_id.
 */
static uint16_t get_unique_circ_id_by_conn(connection_t *conn) {
  uint16_t test_circ_id;
  int attempts=0;
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
       * matters because it's an external DoS vulnerability.
       */
      log_fn(LOG_WARN,"No unused circ IDs. Failing.");
      return 0;
    }
    test_circ_id |= high_bit;
  } while (circuit_get_by_circid_orconn(test_circ_id, conn));
  return test_circ_id;
}

/** If <b>verbose</b> is false, allocate and return a comma-separated
 * list of the currently built elements of circuit_t.  If
 * <b>verbose</b> is true, also list information about link status in
 * a more verbose format using spaces.
 */
char *
circuit_list_path(circuit_t *circ, int verbose)
{
  struct crypt_path_t *hop;
  smartlist_t *elements;
  const char *states[] = {"closed", "waiting for keys", "open"};
  char buf[128];
  char *s;
  tor_assert(CIRCUIT_IS_ORIGIN(circ));
  tor_assert(circ->cpath);

  elements = smartlist_create();

  if (verbose) {
    tor_snprintf(buf, sizeof(buf)-1, "%s%s circ (length %d, exit %s):",
                 circ->build_state->is_internal ? "internal" : "exit",
                 circ->build_state->need_uptime ? " (high-uptime)" : "",
                 circ->build_state->desired_path_len,
                 circ->build_state->chosen_exit_name);
    smartlist_add(elements, tor_strdup(buf));
  }

  hop = circ->cpath;
  do {
    const char *elt;
    routerinfo_t *r;
    if (!hop)
      break;
    if (!verbose && hop->state != CPATH_STATE_OPEN)
      break;
    if ((r = router_get_by_digest(hop->identity_digest))) {
      elt = r->nickname;
    } else if (circ->purpose == CIRCUIT_PURPOSE_C_REND_JOINED) {
      elt = "<rendezvous splice>";
    } else {
      buf[0]='$';
      base16_encode(buf+1,sizeof(buf)-1,hop->identity_digest,DIGEST_LEN);
      elt = buf;
    }
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
void circuit_log_path(int severity, circuit_t *circ) {
  char *s = circuit_list_path(circ,1);
  log_fn(severity,"%s",s);
  tor_free(s);
}

/** Tell the rep(utation)hist(ory) module about the status of the links
 * in circ.  Hops that have become OPEN are marked as successfully
 * extended; the _first_ hop that isn't open (if any) is marked as
 * unable to extend.
 */
void circuit_rep_hist_note_result(circuit_t *circ) {
  struct crypt_path_t *hop;
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
    tor_assert(me);
    prev_digest = me->identity_digest;
  }
  do {
    router = router_get_by_digest(hop->identity_digest);
    if (router) {
      if (prev_digest) {
        if (hop->state == CPATH_STATE_OPEN)
          rep_hist_note_extend_succeeded(prev_digest, router->identity_digest);
        else {
          rep_hist_note_extend_failed(prev_digest, router->identity_digest);
          break;
        }
      }
      prev_digest = router->identity_digest;
    } else {
      prev_digest = NULL;
    }
    hop=hop->next;
  } while (hop!=circ->cpath);
}

/** A helper function for circuit_dump_by_conn() below. Log a bunch
 * of information about circuit <b>circ</b>.
 */
static void
circuit_dump_details(int severity, circuit_t *circ, int poll_index,
                     const char *type, int this_circid, int other_circid) {
  log(severity,"Conn %d has %s circuit: circID %d (other side %d), state %d (%s), born %d:",
      poll_index, type, this_circid, other_circid, circ->state,
      circuit_state_to_string(circ->state), (int)circ->timestamp_created);
  if (CIRCUIT_IS_ORIGIN(circ)) { /* circ starts at this node */
    circuit_log_path(severity, circ);
  }
}

/** Log, at severity <b>severity</b>, information about each circuit
 * that is connected to <b>conn</b>.
 */
void circuit_dump_by_conn(connection_t *conn, int severity) {
  circuit_t *circ;
  connection_t *tmpconn;

  for (circ=global_circuitlist;circ;circ = circ->next) {
    if (circ->marked_for_close)
      continue;
    if (circ->p_conn == conn)
      circuit_dump_details(severity, circ, conn->poll_index, "App-ward",
                           circ->p_circ_id, circ->n_circ_id);
    for (tmpconn=circ->p_streams; tmpconn; tmpconn=tmpconn->next_stream) {
      if (tmpconn == conn) {
        circuit_dump_details(severity, circ, conn->poll_index, "App-ward",
                             circ->p_circ_id, circ->n_circ_id);
      }
    }
    if (circ->n_conn == conn)
      circuit_dump_details(severity, circ, conn->poll_index, "Exit-ward",
                           circ->n_circ_id, circ->p_circ_id);
    for (tmpconn=circ->n_streams; tmpconn; tmpconn=tmpconn->next_stream) {
      if (tmpconn == conn) {
        circuit_dump_details(severity, circ, conn->poll_index, "Exit-ward",
                             circ->n_circ_id, circ->p_circ_id);
      }
    }
    if (!circ->n_conn && circ->n_addr && circ->n_port &&
        circ->n_addr == conn->addr &&
        circ->n_port == conn->port &&
        !memcmp(conn->identity_digest, circ->n_conn_id_digest, DIGEST_LEN)) {
      circuit_dump_details(severity, circ, conn->poll_index, "Pending",
                           circ->n_circ_id, circ->p_circ_id);
    }
  }
}

/** Pick all the entries in our cpath. Stop and return 0 when we're
 * happy, or return -1 if an error occurs. */
static int
onion_populate_cpath(circuit_t *circ) {
  int r;
again:
  r = onion_extend_cpath(circ->purpose, &circ->cpath, circ->build_state);
//    || !CIRCUIT_IS_ORIGIN(circ)) { // wtf? -rd
  if (r < 0) {
    log_fn(LOG_INFO,"Generating cpath hop failed.");
    return -1;
  }
  if (r == 0)
    goto again;
  return 0; /* if r == 1 */
}

/** Create and return a new circuit. Initialize its purpose and
 * build-state based on our arguments. */
circuit_t *
circuit_init(uint8_t purpose, int need_uptime, int need_capacity, int internal) {
  circuit_t *circ = circuit_new(0, NULL); /* sets circ->p_circ_id and circ->p_conn */
  circ->state = CIRCUIT_STATE_OR_WAIT;
  circ->build_state = tor_malloc_zero(sizeof(cpath_build_state_t));
  circ->build_state->need_uptime = need_uptime;
  circ->build_state->need_capacity = need_capacity;
  circ->build_state->is_internal = internal;
  circ->purpose = purpose;
  return circ;
}

/** Build a new circuit for <b>purpose</b>. If <b>exit</b>
 * is defined, then use that as your exit router, else choose a suitable
 * exit node.
 *
 * Also launch a connection to the first OR in the chosen path, if
 * it's not open already.
 */
circuit_t *
circuit_establish_circuit(uint8_t purpose, routerinfo_t *exit,
                          int need_uptime, int need_capacity, int internal) {
  circuit_t *circ;

  circ = circuit_init(purpose, need_uptime, need_capacity, internal);

  if (onion_pick_cpath_exit(circ, exit) < 0 ||
      onion_populate_cpath(circ) < 0) {
    circuit_mark_for_close(circ);
    return NULL;
  }

  control_event_circuit_status(circ, CIRC_EVENT_LAUNCHED);

  if (circuit_handle_first_hop(circ) < 0) {
    circuit_mark_for_close(circ);
    return NULL;
  }
  return circ;
}

/** Start establishing the first hop of our circuit. Figure out what
 * OR we should connect to, and if necessary start the connection to
 * it. If we're already connected, then send the 'create' cell.
 * Return 0 for ok, -1 if circ should be marked-for-close. */
int circuit_handle_first_hop(circuit_t *circ) {
  routerinfo_t *firsthop;
  connection_t *n_conn;

  onion_next_router_in_cpath(circ, &firsthop);
  tor_assert(firsthop);

  /* now see if we're already connected to the first OR in 'route' */
  log_fn(LOG_DEBUG,"Looking for firsthop '%s:%u'",
      firsthop->address,firsthop->or_port);
  /* imprint the circuit with its future n_conn->id */
  memcpy(circ->n_conn_id_digest, firsthop->identity_digest, DIGEST_LEN);
  n_conn = connection_get_by_identity_digest(firsthop->identity_digest,
                                             CONN_TYPE_OR);
  if (!n_conn || n_conn->state != OR_CONN_STATE_OPEN) { /* not currently connected */
    circ->n_addr = firsthop->addr;
    circ->n_port = firsthop->or_port;

    if (!n_conn) { /* launch the connection */
      n_conn = connection_or_connect(firsthop->addr, firsthop->or_port,
                                     firsthop->identity_digest);
      if (!n_conn) { /* connect failed, forget the whole thing */
        log_fn(LOG_INFO,"connect to firsthop failed. Closing.");
        return -1;
      }
    }

    log_fn(LOG_DEBUG,"connecting in progress (or finished). Good.");
    /* return success. The onion/circuit/etc will be taken care of automatically
     * (may already have been) whenever n_conn reaches OR_CONN_STATE_OPEN.
     */
    return 0;
  } else { /* it's already open. use it. */
    circ->n_addr = n_conn->addr;
    circ->n_port = n_conn->port;
    circ->n_conn = n_conn;
    log_fn(LOG_DEBUG,"Conn open. Delivering first onion skin.");
    if (circuit_send_next_onion_skin(circ) < 0) {
      log_fn(LOG_INFO,"circuit_send_next_onion_skin failed.");
      return -1;
    }
  }
  return 0;
}

/** Find circuits that are waiting on <b>or_conn</b> to become open,
 * if any, and get them to send their create cells forward.
 *
 * Status is 1 if connect succeeded, or 0 if connect failed.
 */
void circuit_n_conn_done(connection_t *or_conn, int status) {
  circuit_t *circ;

  log_fn(LOG_DEBUG,"or_conn to %s, status=%d",
         or_conn->nickname ? or_conn->nickname : "NULL", status);

  for (circ=global_circuitlist;circ;circ = circ->next) {
    if (circ->marked_for_close)
      continue;
    if (circ->state == CIRCUIT_STATE_OR_WAIT &&
        !circ->n_conn &&
        circ->n_addr == or_conn->addr &&
        circ->n_port == or_conn->port &&
        !memcmp(or_conn->identity_digest, circ->n_conn_id_digest, DIGEST_LEN)) {
      if (!status) { /* or_conn failed; close circ */
        log_fn(LOG_INFO,"or_conn failed. Closing circ.");
        circuit_mark_for_close(circ);
        continue;
      }
      log_fn(LOG_DEBUG,"Found circ %d, sending create cell.", circ->n_circ_id);
      circ->n_conn = or_conn;
      memcpy(circ->n_conn_id_digest, or_conn->identity_digest, DIGEST_LEN);
      if (CIRCUIT_IS_ORIGIN(circ)) {
        if (circuit_send_next_onion_skin(circ) < 0) {
          log_fn(LOG_INFO,"send_next_onion_skin failed; circuit marked for closing.");
          circuit_mark_for_close(circ);
          continue;
          /* XXX could this be bad, eg if next_onion_skin failed because conn died? */
        }
      } else {
        /* pull the create cell out of circ->onionskin, and send it */
        if (circuit_deliver_create_cell(circ,CELL_CREATE,circ->onionskin) < 0) {
          circuit_mark_for_close(circ);
          continue;
        }
      }
    }
  }
}

static int
circuit_deliver_create_cell(circuit_t *circ, uint8_t cell_type, char *payload) {
  cell_t cell;
  uint16_t id;

  tor_assert(circ);
  tor_assert(circ->n_conn);
  tor_assert(circ->n_conn->type == CONN_TYPE_OR);
  tor_assert(payload);
  tor_assert(cell_type == CELL_CREATE || cell_type == CELL_CREATE_FAST);

  id = get_unique_circ_id_by_conn(circ->n_conn);
  if (!id) {
    log_fn(LOG_WARN,"failed to get unique circID.");
    return -1;
  }
  log_fn(LOG_DEBUG,"Chosen circID %u.", id);
  circuit_set_circid_orconn(circ, id, circ->n_conn, N_CONN_CHANGED);

  memset(&cell, 0, sizeof(cell_t));
  cell.command = cell_type;
  cell.circ_id = circ->n_circ_id;

  memcpy(cell.payload, payload, ONIONSKIN_CHALLENGE_LEN);
  connection_or_write_cell_to_buf(&cell, circ->n_conn);
  return 0;
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
  crypt_path_t *hop;
  routerinfo_t *router;
  int r;
  char payload[2+4+DIGEST_LEN+ONIONSKIN_CHALLENGE_LEN];
  char *onionskin;
  size_t payload_len;

  tor_assert(circ);
  tor_assert(CIRCUIT_IS_ORIGIN(circ));

  if (circ->cpath->state == CPATH_STATE_CLOSED) {
    uint8_t cell_type;
    log_fn(LOG_DEBUG,"First skin; sending create cell.");

    router = router_get_by_digest(circ->n_conn->identity_digest);
    if (!router) {
      log_fn(LOG_WARN,"Couldn't find routerinfo for %s",
             circ->n_conn->nickname);
      return -1;
    }

    if (1 || /* Disable this '1' once we believe CREATE_FAST works. XXXX */
        (get_options()->ORPort || !router->platform ||
         !tor_version_as_new_as(router->platform, "0.1.0.6-rc"))) {
      /* We are an OR, or we are connecting to an old Tor: we should
       * send an old slow create cell.
       */
      cell_type = CELL_CREATE;
      if (onion_skin_create(router->onion_pkey,
                            &(circ->cpath->dh_handshake_state),
                            payload) < 0) {
        log_fn(LOG_WARN,"onion_skin_create (first hop) failed.");
        return -1;
      }
    } else {
      /* We are not an OR, and we building the first hop of a circuit to
       * a new OR: we can be speedy. */
      cell_type = CELL_CREATE_FAST;
      memset(payload, 0, sizeof(payload));
      crypto_rand(circ->cpath->fast_handshake_state,
                  sizeof(circ->cpath->fast_handshake_state));
      memcpy(payload, circ->cpath->fast_handshake_state,
             sizeof(circ->cpath->fast_handshake_state));
    }

    if (circuit_deliver_create_cell(circ, cell_type, payload) < 0)
      return -1;

    circ->cpath->state = CPATH_STATE_AWAITING_KEYS;
    circ->state = CIRCUIT_STATE_BUILDING;
    log_fn(LOG_DEBUG,"first skin; finished sending create cell.");
  } else {
    tor_assert(circ->cpath->state == CPATH_STATE_OPEN);
    tor_assert(circ->state == CIRCUIT_STATE_BUILDING);
    log_fn(LOG_DEBUG,"starting to send subsequent skin.");
    r = onion_next_router_in_cpath(circ, &router);
    if (r > 0) {
      /* done building the circuit. whew. */
      circ->state = CIRCUIT_STATE_OPEN;
      log_fn(LOG_INFO,"circuit built!");
      circuit_reset_failure_count(0);
      if (!has_completed_circuit) {
        or_options_t *options = get_options();
        has_completed_circuit=1;
        log(LOG_NOTICE,"Tor has successfully opened a circuit. Looks like it's working.");
        /* XXX009 Log a count of known routers here */
        if (server_mode(options) && !check_whether_orport_reachable())
          log(LOG_NOTICE,"Now checking whether ORPort %s%s reachable... (this may take up to %d minutes -- look for log messages indicating success)",
                 options->DirPort ? "and DirPort " : "",
                 options->DirPort ? "are" : "is",
                 TIMEOUT_UNTIL_UNREACHABILITY_COMPLAINT/60);
      }
      circuit_rep_hist_note_result(circ);
      circuit_has_opened(circ); /* do other actions as necessary */
      return 0;
    } else if (r < 0) {
      return -1;
    }
    hop = onion_next_hop_in_cpath(circ->cpath);

    *(uint32_t*)payload = htonl(hop->addr);
    *(uint16_t*)(payload+4) = htons(hop->port);

    onionskin = payload+2+4;
    memcpy(payload+2+4+ONIONSKIN_CHALLENGE_LEN, hop->identity_digest, DIGEST_LEN);
    payload_len = 2+4+ONIONSKIN_CHALLENGE_LEN+DIGEST_LEN;

    if (onion_skin_create(router->onion_pkey, &(hop->dh_handshake_state), onionskin) < 0) {
      log_fn(LOG_WARN,"onion_skin_create failed.");
      return -1;
    }

    log_fn(LOG_DEBUG,"Sending extend relay cell.");
    /* send it to hop->prev, because it will transfer
     * it to a create cell and then send to hop */
    if (connection_edge_send_command(NULL, circ, RELAY_COMMAND_EXTEND,
                                     payload, payload_len, hop->prev) < 0)
      return 0; /* circuit is closed */

    hop->state = CPATH_STATE_AWAITING_KEYS;
  }
  return 0;
}

/** Our clock just jumped forward by <b>seconds_elapsed</b>. Assume
 * something has also gone wrong with our network: notify the user,
 * and abandon all not-yet-used circuits. */
void circuit_note_clock_jumped(int seconds_elapsed) {
  log(LOG_NOTICE,"Your clock just jumped %d seconds forward; assuming established circuits no longer work.", seconds_elapsed);
  has_completed_circuit=0; /* so it'll log when it works again */
  circuit_mark_all_unused_circs();
}

/** Take the 'extend' cell, pull out addr/port plus the onion skin. Make
 * sure we're connected to the next hop, and pass it the onion skin in
 * a create cell.
 */
int circuit_extend(cell_t *cell, circuit_t *circ) {
  connection_t *n_conn;
  relay_header_t rh;
  char *onionskin;
  char *id_digest=NULL;

  if (circ->n_conn) {
    log_fn(LOG_WARN,"n_conn already set. Bug/attack. Closing.");
    return -1;
  }

  relay_header_unpack(&rh, cell->payload);

  if (rh.length < 4+2+ONIONSKIN_CHALLENGE_LEN+DIGEST_LEN) {
    log_fn(LOG_WARN, "Wrong length %d on extend cell. Closing circuit.", rh.length);
    return -1;
  }

  circ->n_addr = ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE));
  circ->n_port = ntohs(get_uint16(cell->payload+RELAY_HEADER_SIZE+4));

  onionskin = cell->payload+RELAY_HEADER_SIZE+4+2;
  id_digest = cell->payload+RELAY_HEADER_SIZE+4+2+ONIONSKIN_CHALLENGE_LEN;
  n_conn = connection_get_by_identity_digest(id_digest, CONN_TYPE_OR);

  if (!n_conn || n_conn->state != OR_CONN_STATE_OPEN) {
     /* Note that this will close circuits where the onion has the same
     * router twice in a row in the path. I think that's ok.
     */
    struct in_addr in;
    char tmpbuf[INET_NTOA_BUF_LEN];
    in.s_addr = htonl(circ->n_addr);
    tor_inet_ntoa(&in,tmpbuf,sizeof(tmpbuf));
    log_fn(LOG_INFO,"Next router (%s:%d) not connected. Connecting.",
           tmpbuf, circ->n_port);

    memcpy(circ->onionskin, onionskin, ONIONSKIN_CHALLENGE_LEN);
    circ->state = CIRCUIT_STATE_OR_WAIT;

    /* imprint the circuit with its future n_conn->id */
    memcpy(circ->n_conn_id_digest, id_digest, DIGEST_LEN);

    if (n_conn) {
      circ->n_addr = n_conn->addr;
      circ->n_port = n_conn->port;
    } else {
     /* we should try to open a connection */
      n_conn = connection_or_connect(circ->n_addr, circ->n_port, id_digest);
      if (!n_conn) {
        log_fn(LOG_INFO,"Launching n_conn failed. Closing.");
        return -1;
      }
      log_fn(LOG_DEBUG,"connecting in progress (or finished). Good.");
    }
    /* return success. The onion/circuit/etc will be taken care of automatically
     * (may already have been) whenever n_conn reaches OR_CONN_STATE_OPEN.
     */
    return 0;
  }

  /* these may be different if the router connected to us from elsewhere */
  circ->n_addr = n_conn->addr;
  circ->n_port = n_conn->port;

  circ->n_conn = n_conn;
  memcpy(circ->n_conn_id_digest, n_conn->identity_digest, DIGEST_LEN);
  log_fn(LOG_DEBUG,"n_conn is %s:%u",n_conn->address,n_conn->port);

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
int circuit_init_cpath_crypto(crypt_path_t *cpath, char *key_data, int reverse)
{
  crypto_digest_env_t *tmp_digest;
  crypto_cipher_env_t *tmp_crypto;

  tor_assert(cpath);
  tor_assert(key_data);
  tor_assert(!(cpath->f_crypto || cpath->b_crypto ||
             cpath->f_digest || cpath->b_digest));

//  log_fn(LOG_DEBUG,"hop init digest forward 0x%.8x, backward 0x%.8x.",
//         (unsigned int)*(uint32_t*)key_data, (unsigned int)*(uint32_t*)(key_data+20));
  cpath->f_digest = crypto_new_digest_env();
  crypto_digest_add_bytes(cpath->f_digest, key_data, DIGEST_LEN);
  cpath->b_digest = crypto_new_digest_env();
  crypto_digest_add_bytes(cpath->b_digest, key_data+DIGEST_LEN, DIGEST_LEN);

//  log_fn(LOG_DEBUG,"hop init cipher forward 0x%.8x, backward 0x%.8x.",
//         (unsigned int)*(uint32_t*)(key_data+40), (unsigned int)*(uint32_t*)(key_data+40+16));
  if (!(cpath->f_crypto =
        crypto_create_init_cipher(key_data+(2*DIGEST_LEN),1))) {
    log(LOG_WARN,"Bug: forward cipher initialization failed.");
    return -1;
  }
  if (!(cpath->b_crypto =
        crypto_create_init_cipher(key_data+(2*DIGEST_LEN)+CIPHER_KEY_LEN,0))) {
    log(LOG_WARN,"Bug: backward cipher initialization failed.");
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
 * DOCDOC reply_type.
 *
 * Calculate the appropriate keys and digests, make sure KH is
 * correct, and initialize this hop of the cpath.
 *
 * Return -1 if we want to mark circ for close, else return 0.
 */
int circuit_finish_handshake(circuit_t *circ, uint8_t reply_type, char *reply) {
  char keys[CPATH_KEY_MATERIAL_LEN];
  crypt_path_t *hop;

  tor_assert(CIRCUIT_IS_ORIGIN(circ));
  if (circ->cpath->state == CPATH_STATE_AWAITING_KEYS)
    hop = circ->cpath;
  else {
    hop = onion_next_hop_in_cpath(circ->cpath);
    if (!hop) { /* got an extended when we're all done? */
      log_fn(LOG_WARN,"got extended when circ already built? Closing.");
      return -1;
    }
  }
  tor_assert(hop->state == CPATH_STATE_AWAITING_KEYS);

  if (reply_type == CELL_CREATED && hop->dh_handshake_state) {
    if (onion_skin_client_handshake(hop->dh_handshake_state, reply, keys,
                                    DIGEST_LEN*2+CIPHER_KEY_LEN*2) < 0) {
      log_fn(LOG_WARN,"onion_skin_client_handshake failed.");
      return -1;
    }
    /* Remember hash of g^xy */
    memcpy(hop->handshake_digest, reply+DH_KEY_LEN, DIGEST_LEN);
  } else if (reply_type == CELL_CREATED_FAST && !hop->dh_handshake_state) {
    if (fast_client_handshake(hop->fast_handshake_state, reply, keys,
                              DIGEST_LEN*2+CIPHER_KEY_LEN*2) < 0) {
      log_fn(LOG_WARN,"fast_client_handshake failed.");
      return -1;
    }
    memcpy(hop->handshake_digest, reply+DIGEST_LEN, DIGEST_LEN);
  } else {
    log_fn(LOG_WARN,"CREATED cell type did not match CREATE cell type.");
    return -1;
  }

  if (hop->dh_handshake_state) {
    crypto_dh_free(hop->dh_handshake_state); /* don't need it anymore */
    hop->dh_handshake_state = NULL;
  }
  memset(hop->fast_handshake_state, 0, sizeof(hop->fast_handshake_state));

  if (circuit_init_cpath_crypto(hop, keys, 0)<0) {
    return -1;
  }

  hop->state = CPATH_STATE_OPEN;
  log_fn(LOG_INFO,"Finished building circuit hop:");
  circuit_log_path(LOG_INFO,circ);
  control_event_circuit_status(circ, CIRC_EVENT_EXTENDED);

  return 0;
}

/** We received a relay truncated cell on circ.
 *
 * Since we don't ask for truncates currently, getting a truncated
 * means that a connection broke or an extend failed. For now,
 * just give up: for circ to close, and return 0.
 */
int circuit_truncated(circuit_t *circ, crypt_path_t *layer) {
//  crypt_path_t *victim;
//  connection_t *stream;

  tor_assert(circ);
  tor_assert(CIRCUIT_IS_ORIGIN(circ));
  tor_assert(layer);

  /* XXX Since we don't ask for truncates currently, getting a truncated
   *     means that a connection broke or an extend failed. For now,
   *     just give up.
   */
  circuit_mark_for_close(circ);
  return 0;

#if 0
  while (layer->next != circ->cpath) {
    /* we need to clear out layer->next */
    victim = layer->next;
    log_fn(LOG_DEBUG, "Killing a layer of the cpath.");

    for (stream = circ->p_streams; stream; stream=stream->next_stream) {
      if (stream->cpath_layer == victim) {
        log_fn(LOG_INFO, "Marking stream %d for close.", stream->stream_id);
        /* no need to send 'end' relay cells,
         * because the other side's already dead
         */
        connection_mark_unattached_ap(stream, END_STREAM_REASON_DESTROY);
      }
    }

    layer->next = victim->next;
    circuit_free_cpath_node(victim);
  }

  log_fn(LOG_INFO, "finished");
  return 0;
#endif
}

/** Given a response payload and keys, initialize, then send a created
 * cell back.
 */
int onionskin_answer(circuit_t *circ, uint8_t cell_type, char *payload, char *keys) {
  cell_t cell;
  crypt_path_t *tmp_cpath;

  tmp_cpath = tor_malloc_zero(sizeof(crypt_path_t));
  tmp_cpath->magic = CRYPT_PATH_MAGIC;

  memset(&cell, 0, sizeof(cell_t));
  cell.command = cell_type;
  cell.circ_id = circ->p_circ_id;

  circ->state = CIRCUIT_STATE_OPEN;

  memcpy(cell.payload, payload,
         cell_type == CELL_CREATED ? ONIONSKIN_REPLY_LEN : DIGEST_LEN*2);

  log_fn(LOG_INFO,"init digest forward 0x%.8x, backward 0x%.8x.",
         (unsigned int)*(uint32_t*)(keys), (unsigned int)*(uint32_t*)(keys+20));
  if (circuit_init_cpath_crypto(tmp_cpath, keys, 0)<0) {
    log_fn(LOG_WARN,"Circuit initialization failed");
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
  log_fn(LOG_DEBUG,"Finished sending 'created' cell.");

  if (!is_local_IP(circ->p_conn->addr) &&
      tor_tls_is_server(circ->p_conn->tls)) {
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
static int new_route_len(double cw, uint8_t purpose, smartlist_t *routers) {
  int num_acceptable_routers;
  int routelen;

  tor_assert(cw >= 0.);
  tor_assert(cw < 1.);
  tor_assert(routers);

#ifdef TOR_PERF
  routelen = 2;
#else
  if (purpose == CIRCUIT_PURPOSE_C_GENERAL)
    routelen = 3;
  else if (purpose == CIRCUIT_PURPOSE_TESTING)
    routelen = 3;
  else if (purpose == CIRCUIT_PURPOSE_C_INTRODUCING)
    routelen = 4;
  else if (purpose == CIRCUIT_PURPOSE_C_ESTABLISH_REND)
    routelen = 3;
  else if (purpose == CIRCUIT_PURPOSE_S_ESTABLISH_INTRO)
    routelen = 3;
  else if (purpose == CIRCUIT_PURPOSE_S_CONNECT_REND)
    routelen = 4;
  else {
    log_fn(LOG_WARN,"Bug: unhandled purpose %d", purpose);
    tor_fragile_assert();
    return -1;
  }
#endif
#if 0
  for (routelen = 3; ; routelen++) { /* 3, increment until coinflip says we're done */
    if (crypto_pseudo_rand_int(255) >= cw*255) /* don't extend */
      break;
  }
#endif
  log_fn(LOG_DEBUG,"Chosen route length %d (%d routers available).",routelen,
         smartlist_len(routers));

  num_acceptable_routers = count_acceptable_routers(routers);

  if (num_acceptable_routers < 2) {
    log_fn(LOG_INFO,"Not enough acceptable routers (%d). Discarding this circuit.",
           num_acceptable_routers);
    return -1;
  }

  if (num_acceptable_routers < routelen) {
    log_fn(LOG_INFO,"Not enough routers: cutting routelen from %d to %d.",
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
circuit_get_unhandled_ports(time_t now) {
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
                                    int *need_capacity) {
  int i, enough;
  uint16_t *port;
  smartlist_t *sl = circuit_get_unhandled_ports(now);
  smartlist_t *LongLivedServices = get_options()->LongLivedPorts;
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
router_handles_some_port(routerinfo_t *router, smartlist_t *needed_ports) {
  int i;
  uint16_t port;

  for (i = 0; i < smartlist_len(needed_ports); ++i) {
    addr_policy_result_t r;
    port = *(uint16_t *)smartlist_get(needed_ports, i);
    tor_assert(port);
    r = router_compare_addr_to_addr_policy(0, port, router->exit_policy);
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
ap_stream_wants_exit_attention(connection_t *conn) {
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
  smartlist_t *sl, *preferredexits, *preferredentries, *excludedexits;
  routerinfo_t *router;
  or_options_t *options = get_options();

  preferredentries = smartlist_create();
  add_nickname_list_to_smartlist(preferredentries,options->EntryNodes,1);

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
  for (i = 0; i < smartlist_len(dir->routers); ++i) { /* iterate over routers */
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
//      log_fn(LOG_DEBUG,"Skipping node %s (index %d) -- directory says it's not running.",
//             router->nickname, i);
      continue; /* skip routers that are known to be down */
    }
    if (router_is_unreliable(router, need_uptime, need_capacity)) {
      n_supported[i] = -1;
      continue; /* skip routers that are not suitable */
    }
    if (!router->is_verified &&
        (!(options->_AllowUnverified & ALLOW_UNVERIFIED_EXIT) ||
         router_is_unreliable(router, 1, 1))) {
      /* if it's unverified, and either we don't want it or it's unsuitable */
      n_supported[i] = -1;
//      log_fn(LOG_DEBUG,"Skipping node %s (index %d) -- unverified router.",
//             router->nickname, i);
      continue; /* skip unverified routers */
    }
    if (router_exit_policy_rejects_all(router)) {
      n_supported[i] = -1;
//      log_fn(LOG_DEBUG,"Skipping node %s (index %d) -- it rejects all.",
//             router->nickname, i);
      continue; /* skip routers that reject all */
    }
    if (smartlist_len(preferredentries)==1 &&
        router == (routerinfo_t*)smartlist_get(preferredentries, 0)) {
      n_supported[i] = -1;
//      log_fn(LOG_DEBUG,"Skipping node %s (index %d) -- it's our only preferred entry node.", router->nickname, i);
      continue;
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
  log_fn(LOG_INFO, "Found %d servers that might support %d/%d pending connections.",
         n_best_support, best_support, n_pending_connections);

  preferredexits = smartlist_create();
  add_nickname_list_to_smartlist(preferredexits,options->ExitNodes,1);

  excludedexits = smartlist_create();
  add_nickname_list_to_smartlist(excludedexits,options->ExcludeNodes,0);

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
      log(LOG_NOTICE, "All routers are down or middleman -- choosing a doomed exit at random.");
    }
    for (try = 0; try < 2; try++) {
      /* try once to pick only from routers that satisfy a needed port,
       * then if there are none, pick from any that support exiting. */
      for (i = 0; i < smartlist_len(dir->routers); i++) {
        router = smartlist_get(dir->routers, i);
        if (n_supported[i] != -1 &&
            (try || router_handles_some_port(router, needed_ports))) {
          log_fn(LOG_DEBUG,"Try %d: '%s' is a possibility.", try, router->nickname);
          smartlist_add(sl, router);
        }
      }

      smartlist_subtract(sl,excludedexits);
      if (options->StrictExitNodes || smartlist_overlap(sl,preferredexits))
        smartlist_intersect(sl,preferredexits);
      router = routerlist_sl_choose_by_bandwidth(sl);
      if (router)
        break;
    }
    SMARTLIST_FOREACH(needed_ports, uint16_t *, cp, tor_free(cp));
    smartlist_free(needed_ports);
  }

  smartlist_free(preferredexits);
  smartlist_free(preferredentries);
  smartlist_free(excludedexits);
  smartlist_free(sl);
  tor_free(n_supported);
  if (router) {
    log_fn(LOG_INFO, "Chose exit server '%s'", router->nickname);
    return router;
  }
  if (options->StrictExitNodes)
    log_fn(LOG_WARN, "No exit routers seem to be running; can't choose an exit.");

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
                        int need_uptime, int need_capacity)
{
  routerinfo_t *r;
  or_options_t *options = get_options();
  switch (purpose) {
    case CIRCUIT_PURPOSE_C_GENERAL:
      return choose_good_exit_server_general(dir, need_uptime, need_capacity);
    case CIRCUIT_PURPOSE_C_ESTABLISH_REND:
      r = router_choose_random_node(options->RendNodes, options->RendExcludeNodes,
          NULL, need_uptime, need_capacity,
          options->_AllowUnverified & ALLOW_UNVERIFIED_RENDEZVOUS, 0);
      return r;
  }
  log_fn(LOG_WARN,"Bug: unhandled purpose %d", purpose);
  tor_fragile_assert();
  return NULL;
}

/** Decide a suitable length for circ's cpath, and pick an exit
 * router (or use <b>exit</b> if provided). Store these in the
 * cpath. Return 0 if ok, -1 if circuit should be closed. */
static int
onion_pick_cpath_exit(circuit_t *circ, routerinfo_t *exit) {
  cpath_build_state_t *state = circ->build_state;

  routerlist_t *rl;
  int r;

  router_get_routerlist(&rl);
  if (!rl) {
    log_fn(LOG_WARN,"router_get_routerlist returned empty list; closing circ.");
    return -1;
  }
  r = new_route_len(get_options()->PathlenCoinWeight, circ->purpose, rl->routers);
  if (r < 1) /* must be at least 1 */
    return -1;
  state->desired_path_len = r;

  if (exit) { /* the circuit-builder pre-requested one */
    log_fn(LOG_INFO,"Using requested exit node '%s'", exit->nickname);
  } else { /* we have to decide one */
    exit = choose_good_exit_server(circ->purpose, rl,
                                   state->need_uptime, state->need_capacity);
    if (!exit) {
      log_fn(LOG_WARN,"failed to choose an exit server");
      return -1;
    }
  }
  memcpy(state->chosen_exit_digest, exit->identity_digest, DIGEST_LEN);
  state->chosen_exit_name = tor_strdup(exit->nickname);
  return 0;
}

/** Give <b>circ</b> a new exit destination to <b>exit</b>, and add a
 * hop to the cpath reflecting this. Don't send the next extend cell --
 * the caller will do this if it wants to.
 */
int
circuit_append_new_exit(circuit_t *circ, routerinfo_t *exit) {
  tor_assert(exit);
  tor_assert(circ && CIRCUIT_IS_ORIGIN(circ));
  tor_free(circ->build_state->chosen_exit_name);
  circ->build_state->chosen_exit_name = tor_strdup(exit->nickname);
  memcpy(circ->build_state->chosen_exit_digest, exit->identity_digest, DIGEST_LEN);
  ++circ->build_state->desired_path_len;
  onion_append_hop(&circ->cpath, exit);
  return 0;
}

/** Take the open circ originating here, give it a new exit destination
 * to <b>exit</b>, and get it to send the next extend cell. If you can't
 * send the extend cell, mark the circuit for close and return -1, else
 * return 0. */
int circuit_extend_to_new_exit(circuit_t *circ, routerinfo_t *exit) {
  circuit_append_new_exit(circ, exit);
  circ->state = CIRCUIT_STATE_BUILDING;
  if (circuit_send_next_onion_skin(circ)<0) {
    log_fn(LOG_WARN, "Couldn't extend circuit to new point '%s'.",
           circ->build_state->chosen_exit_name);
    circuit_mark_for_close(circ);
    return -1;
  }
  return 0;
}

/** Return the number of routers in <b>routers</b> that are currently up
 * and available for building circuits through.
 */
static int count_acceptable_routers(smartlist_t *routers) {
  int i, n;
  int num=0;
  routerinfo_t *r;

  n = smartlist_len(routers);
  for (i=0;i<n;i++) {
    r = smartlist_get(routers, i);
//    log_fn(LOG_DEBUG,"Contemplating whether router %d (%s) is a new option...",
//           i, r->nickname);
    if (r->is_running == 0) {
//      log_fn(LOG_DEBUG,"Nope, the directory says %d is not running.",i);
      goto next_i_loop;
    }
    if (r->is_verified == 0) {
//      log_fn(LOG_DEBUG,"Nope, the directory says %d is not verified.",i);
      /* XXXX009 But unverified routers *are* sometimes acceptable. */
      goto next_i_loop;
    }
    num++;
//    log_fn(LOG_DEBUG,"I like %d. num_acceptable_routers now %d.",i, num);
    next_i_loop:
      ; /* C requires an explicit statement after the label */
  }

  return num;
}

/** Add <b>new_hop</b> to the end of the doubly-linked-list <b>head_ptr</b>.
 *
 * This function is used to extend cpath by another hop.
 */
void onion_append_to_cpath(crypt_path_t **head_ptr, crypt_path_t *new_hop)
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

static routerinfo_t *choose_good_middle_server(uint8_t purpose,
                                               cpath_build_state_t *state,
                                               crypt_path_t *head,
                                               int cur_len)
{
  int i;
  routerinfo_t *r, *choice;
  crypt_path_t *cpath;
  smartlist_t *excluded;

  log_fn(LOG_DEBUG, "Contemplating intermediate hop: random choice.");
  excluded = smartlist_create();
  if ((r = router_get_by_digest(state->chosen_exit_digest))) {
    smartlist_add(excluded, r);
    routerlist_add_family(excluded, r);
  }
  if ((r = routerlist_find_my_routerinfo())) {
    smartlist_add(excluded, r);
    routerlist_add_family(excluded, r);
  }
  for (i = 0, cpath = head; i < cur_len; ++i, cpath=cpath->next) {
    if ((r = router_get_by_digest(cpath->identity_digest))) {
      smartlist_add(excluded, r);
      routerlist_add_family(excluded, r);
    }
  }
  choice = router_choose_random_node(NULL, get_options()->ExcludeNodes, excluded,
           state->need_uptime, state->need_capacity,
           get_options()->_AllowUnverified & ALLOW_UNVERIFIED_MIDDLE, 0);
  smartlist_free(excluded);
  return choice;
}

static routerinfo_t *choose_good_entry_server(cpath_build_state_t *state)
{
  routerinfo_t *r, *choice;
  smartlist_t *excluded = smartlist_create();
  or_options_t *options = get_options();

  if ((r = router_get_by_digest(state->chosen_exit_digest))) {
    smartlist_add(excluded, r);
    routerlist_add_family(excluded, r);
  }
  if ((r = routerlist_find_my_routerinfo())) {
    smartlist_add(excluded, r);
    routerlist_add_family(excluded, r);
  }
  if (options->FascistFirewall) {
    /* exclude all ORs that listen on the wrong port */
    routerlist_t *rl;
    int i;

    router_get_routerlist(&rl);
    if (!rl)
      return NULL;

    for (i=0; i < smartlist_len(rl->routers); i++) {
      r = smartlist_get(rl->routers, i);
      if (!smartlist_string_num_isin(options->FirewallPorts, r->or_port))
         smartlist_add(excluded, r);
    }
  }
  choice = router_choose_random_node(options->EntryNodes, options->ExcludeNodes,
           excluded, state->need_uptime, state->need_capacity,
           options->_AllowUnverified & ALLOW_UNVERIFIED_ENTRY,
           options->StrictEntryNodes);
  smartlist_free(excluded);
  return choice;
}

/** Return the first non-open hop in cpath, or return NULL if all
 * hops are open. */
static crypt_path_t *
onion_next_hop_in_cpath(crypt_path_t *cpath) {
  crypt_path_t *hop = cpath;
  do {
    if (hop->state != CPATH_STATE_OPEN)
      return hop;
    hop = hop->next;
  } while (hop != cpath);
  return NULL;
}

/** Find the router corresponding to the first non-open hop in
 * circ->cpath. Make sure it's state closed. Return 1 if all
 * hops are open (the circuit is complete), 0 if we find a router
 * (and set it to *router), and -1 if we fail to lookup the router.
 */
static int
onion_next_router_in_cpath(circuit_t *circ, routerinfo_t **router) {
  routerinfo_t *r;
  crypt_path_t *hop = onion_next_hop_in_cpath(circ->cpath);
  if (!hop) /* all hops are open */
    return 1;
  tor_assert(hop->state == CPATH_STATE_CLOSED);
  r = router_get_by_digest(hop->identity_digest);
  if (!r) {
    log_fn(LOG_WARN,"Circuit intended to extend to a hop whose routerinfo we've lost. Cancelling circuit.");
    return -1;
  }
  *router = r;
  return 0;
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
  routerinfo_t *choice;
  smartlist_t *excludednodes;

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
    log_fn(LOG_DEBUG, "Path is complete: %d steps long",
           state->desired_path_len);
    return 1;
  }

  log_fn(LOG_DEBUG, "Path is %d long; we want %d", cur_len,
         state->desired_path_len);

  excludednodes = smartlist_create();
  add_nickname_list_to_smartlist(excludednodes,get_options()->ExcludeNodes,0);

  if (cur_len == state->desired_path_len - 1) { /* Picking last node */
    choice = router_get_by_digest(state->chosen_exit_digest);
  } else if (cur_len == 0) { /* picking first node */
    choice = choose_good_entry_server(state);
  } else {
    choice = choose_good_middle_server(purpose, state, *head_ptr, cur_len);
  }

  smartlist_free(excludednodes);
  if (!choice) {
    log_fn(LOG_WARN,"Failed to find node for hop %d of our path. Discarding this circuit.", cur_len);
    return -1;
  }

  log_fn(LOG_DEBUG,"Chose router %s for hop %d (exit is %s)",
         choice->nickname, cur_len+1, state->chosen_exit_name);

  onion_append_hop(head_ptr, choice);
  return 0;
}

/** Create a new hop, annotate it with information about its
 * corresponding router <b>choice</b>, and append it to the
 * end of the cpath <b>head_ptr</b>. */
static int
onion_append_hop(crypt_path_t **head_ptr, routerinfo_t *choice) {
  crypt_path_t *hop = tor_malloc_zero(sizeof(crypt_path_t));

  /* link hop into the cpath, at the end. */
  onion_append_to_cpath(head_ptr, hop);

  hop->magic = CRYPT_PATH_MAGIC;
  hop->state = CPATH_STATE_CLOSED;

  hop->port = choice->or_port;
  hop->addr = choice->addr;
  memcpy(hop->identity_digest, choice->identity_digest, DIGEST_LEN);

  hop->package_window = CIRCWINDOW_START;
  hop->deliver_window = CIRCWINDOW_START;

  return 0;
}

