/* Copyright 2001 Matej Pfajfar, 2001-2004 Roger Dingledine. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file circuitbuild.c
 * \brief The actual details of building circuits.
 **/

#include "or.h"

extern or_options_t options; /* command-line and config-file options */

/********* START VARIABLES **********/

/** A global list of all circuits at this hop. */
extern circuit_t *global_circuitlist;

/********* END VARIABLES ************/

static int
circuit_deliver_create_cell(circuit_t *circ, char *payload);
static cpath_build_state_t *
onion_new_cpath_build_state(uint8_t purpose, const char *exit_digest);
static int
onion_extend_cpath(crypt_path_t **head_ptr, cpath_build_state_t
                   *state, routerinfo_t **router_out);
static int decide_circ_id_type(char *local_nick, char *remote_nick);
static int count_acceptable_routers(smartlist_t *routers);

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
          circ->build_state->desired_path_len, circ->build_state->chosen_exit_name);
  hop=circ->cpath;
  do {
    s = buf + strlen(buf);
    router = router_get_by_digest(hop->identity_digest);
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
void circuit_rep_hist_note_result(circuit_t *circ) {
  struct crypt_path_t *hop;
  char *prev_digest = NULL;
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
  if (server_mode()) {
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
                     char *type, int this_circid, int other_circid) {
  struct crypt_path_t *hop;
  log(severity,"Conn %d has %s circuit: circID %d (other side %d), state %d (%s), born %d",
      poll_index, type, this_circid, other_circid, circ->state,
      circuit_state_to_string[circ->state], (int)circ->timestamp_created);
  if(CIRCUIT_IS_ORIGIN(circ)) { /* circ starts at this node */
    if(circ->state == CIRCUIT_STATE_BUILDING)
      log(severity,"Building: desired len %d, planned exit node %s.",
          circ->build_state->desired_path_len, circ->build_state->chosen_exit_name);
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

/** Build a new circuit for <b>purpose</b>. If <b>exit_digest</b>
 * is defined, then use that as your exit router, else choose a suitable
 * exit node.
 *
 * Also launch a connection to the first OR in the chosen path, if
 * it's not open already.
 */
circuit_t *circuit_establish_circuit(uint8_t purpose,
                                     const char *exit_digest) {
  routerinfo_t *firsthop;
  connection_t *n_conn;
  circuit_t *circ;

  circ = circuit_new(0, NULL); /* sets circ->p_circ_id and circ->p_conn */
  circ->state = CIRCUIT_STATE_OR_WAIT;
  circ->build_state = onion_new_cpath_build_state(purpose, exit_digest);
  circ->purpose = purpose;

  if (! circ->build_state) {
    log_fn(LOG_INFO,"Generating cpath failed.");
    circuit_mark_for_close(circ);
    return NULL;
  }

  if(onion_extend_cpath(&circ->cpath, circ->build_state, &firsthop)<0 ||
     !CIRCUIT_IS_ORIGIN(circ)) {
    log_fn(LOG_INFO,"Generating first cpath hop failed.");
    circuit_mark_for_close(circ);
    return NULL;
  }

  /* now see if we're already connected to the first OR in 'route' */

  tor_assert(firsthop);
  log_fn(LOG_DEBUG,"Looking for firsthop '%s:%u'",
      firsthop->address,firsthop->or_port);
  /* imprint the circuit with its future n_conn->id */
  memcpy(circ->n_conn_id_digest, firsthop->identity_digest, DIGEST_LEN);
  n_conn = connection_get_by_identity_digest(firsthop->identity_digest,
                                             CONN_TYPE_OR);
  if(!n_conn || n_conn->state != OR_CONN_STATE_OPEN) { /* not currently connected */
    circ->n_addr = firsthop->addr;
    circ->n_port = firsthop->or_port;

    if(!n_conn) { /* launch the connection */
      n_conn = connection_or_connect(firsthop->addr, firsthop->or_port,
                                     firsthop->identity_digest);
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
void circuit_n_conn_done(connection_t *or_conn, int success) {
  circuit_t *circ;

  log_fn(LOG_DEBUG,"or_conn to %s, success=%d", or_conn->nickname, success);

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if (circ->marked_for_close)
      continue;
    if(!circ->n_conn &&
       circ->n_addr == or_conn->addr &&
       circ->n_port == or_conn->port &&
       !memcmp(or_conn->identity_digest, circ->n_conn_id_digest, DIGEST_LEN)) {
      tor_assert(circ->state == CIRCUIT_STATE_OR_WAIT);
      if(!success) { /* or_conn failed; close circ */
        log_fn(LOG_INFO,"or_conn failed. Closing circ.");
        circuit_mark_for_close(circ);
        continue;
      }
      log_fn(LOG_DEBUG,"Found circ %d, sending create cell.", circ->n_circ_id);
      circ->n_conn = or_conn;
      memcpy(circ->n_conn_id_digest, or_conn->identity_digest, DIGEST_LEN);
      if(CIRCUIT_IS_ORIGIN(circ)) {
        if(circuit_send_next_onion_skin(circ) < 0) {
          log_fn(LOG_INFO,"send_next_onion_skin failed; circuit marked for closing.");
          circuit_mark_for_close(circ);
          continue;
          /* XXX could this be bad, eg if next_onion_skin failed because conn died? */
        }
      } else {
        /* pull the create cell out of circ->onionskin, and send it */
        if(circuit_deliver_create_cell(circ, circ->onionskin) < 0) {
          circuit_mark_for_close(circ);
          continue;
        }
      }
    }
  }
}

static int
circuit_deliver_create_cell(circuit_t *circ, char *payload) {
  int circ_id_type;
  cell_t cell;

  tor_assert(circ && circ->n_conn && circ->n_conn->type == CONN_TYPE_OR);
  tor_assert(payload);

  /* XXXX008 How can we keep a good upgrade path here?  We should
   * compare keys, not nicknames...but older servers will compare nicknames.
   * Should we check server version from the most recent directory? Hm.
   */
  circ_id_type = decide_circ_id_type(options.Nickname,
                                     circ->n_conn->nickname);
  circ->n_circ_id = get_unique_circ_id_by_conn(circ->n_conn, circ_id_type);
  if(!circ->n_circ_id) {
    log_fn(LOG_WARN,"failed to get unique circID.");
    return -1;
  }
  log_fn(LOG_DEBUG,"Chosen circID %u.",circ->n_circ_id);

  memset(&cell, 0, sizeof(cell_t));
  cell.command = CELL_CREATE;
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
  int payload_len;

  tor_assert(circ && CIRCUIT_IS_ORIGIN(circ));

  if(circ->cpath->state == CPATH_STATE_CLOSED) {
    log_fn(LOG_DEBUG,"First skin; sending create cell.");

    router = router_get_by_digest(circ->n_conn->identity_digest);
    if (!router) {
      log_fn(LOG_WARN,"Couldn't find routerinfo for %s",
             circ->n_conn->nickname);
      return -1;
    }

    if(onion_skin_create(router->onion_pkey,
                         &(circ->cpath->handshake_state),
                         payload) < 0) {
      log_fn(LOG_WARN,"onion_skin_create (first hop) failed.");
      return -1;
    }

    if(circuit_deliver_create_cell(circ, payload) < 0)
      return -1;

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
      circuit_reset_failure_count(0);
      if(!has_completed_circuit) {
        has_completed_circuit=1;
        log_fn(LOG_NOTICE,"Tor has successfully opened a circuit. Looks like it's working.");
// XXX008 put a count of known routers here
      }
      circuit_rep_hist_note_result(circ);
      circuit_has_opened(circ); /* do other actions as necessary */
      return 0;
    } else if (r<0) {
      log_fn(LOG_INFO,"Unable to extend circuit path.");
      return -1;
    }
    hop = circ->cpath->prev;

    *(uint32_t*)payload = htonl(hop->addr);
    *(uint16_t*)(payload+4) = htons(hop->port);

    onionskin = payload+2+4;
    memcpy(payload+2+4+ONIONSKIN_CHALLENGE_LEN, hop->identity_digest, DIGEST_LEN);
    payload_len = 2+4+ONIONSKIN_CHALLENGE_LEN+DIGEST_LEN;

    if(onion_skin_create(router->onion_pkey, &(hop->handshake_state), onionskin) < 0) {
      log_fn(LOG_WARN,"onion_skin_create failed.");
      return -1;
    }

    log_fn(LOG_DEBUG,"Sending extend relay cell.");
    /* send it to hop->prev, because it will transfer
     * it to a create cell and then send to hop */
    if(connection_edge_send_command(NULL, circ, RELAY_COMMAND_EXTEND,
                               payload, payload_len, hop->prev) < 0)
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
  relay_header_t rh;
  int old_format;
  char *onionskin;
  char *id_digest=NULL;

  if(circ->n_conn) {
    log_fn(LOG_WARN,"n_conn already set. Bug/attack. Closing.");
    return -1;
  }

  relay_header_unpack(&rh, cell->payload);

  if (rh.length == 4+2+ONIONSKIN_CHALLENGE_LEN) {
    old_format = 1;
  } else if (rh.length == 4+2+ONIONSKIN_CHALLENGE_LEN+DIGEST_LEN) {
    old_format = 0;
  } else {
    log_fn(LOG_WARN, "Wrong length %d on extend cell. Closing circuit.", rh.length);
    return -1;
  }

  circ->n_addr = ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE));
  circ->n_port = ntohs(get_uint16(cell->payload+RELAY_HEADER_SIZE+4));

  if (old_format) {
    n_conn = connection_exact_get_by_addr_port(circ->n_addr,circ->n_port);
    onionskin = cell->payload+RELAY_HEADER_SIZE+4+2;
  } else {
    onionskin = cell->payload+RELAY_HEADER_SIZE+4+2;
    id_digest = cell->payload+RELAY_HEADER_SIZE+4+2+ONIONSKIN_CHALLENGE_LEN;
    n_conn = connection_get_by_identity_digest(id_digest, CONN_TYPE_OR);
  }

  if(!n_conn || n_conn->state != OR_CONN_STATE_OPEN) {
     /* Note that this will close circuits where the onion has the same
     * router twice in a row in the path. I think that's ok.
     */
    routerinfo_t *router;
    struct in_addr in;
    in.s_addr = htonl(circ->n_addr);
    log_fn(LOG_INFO,"Next router (%s:%d) not connected. Connecting.",
           inet_ntoa(in), circ->n_port);

    if (old_format) {
      router = router_get_by_addr_port(circ->n_addr, circ->n_port);
      if(!router) {
        log_fn(LOG_WARN,"Next hop is an unknown router. Closing.");
        return -1;
      }
      id_digest = router->identity_digest;
    } else { /* new format */
      router = router_get_by_digest(id_digest);
    }
    tor_assert(id_digest);

    memcpy(circ->onionskin, onionskin, ONIONSKIN_CHALLENGE_LEN);
    circ->state = CIRCUIT_STATE_OR_WAIT;

    /* imprint the circuit with its future n_conn->id */
    memcpy(circ->n_conn_id_digest, id_digest, DIGEST_LEN);

    if(n_conn) {
      circ->n_addr = n_conn->addr;
      circ->n_port = n_conn->port;
    } else {
     /* we should try to open a connection */
      n_conn = connection_or_connect(circ->n_addr, circ->n_port, id_digest);
      if(!n_conn) {
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

  if(circuit_deliver_create_cell(circ, onionskin) < 0)
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
        stream->has_sent_end = 1;
        connection_mark_for_close(stream);
      }
    }

    layer->next = victim->next;
    circuit_free_cpath_node(victim);
  }

  log_fn(LOG_INFO, "finished");
  return 0;
}

/** Decide whether the first bit of the circuit ID will be
 * 0 or 1, to avoid conflicts where each side randomly chooses
 * the same circuit ID.
 *
 * Return CIRC_ID_TYPE_LOWER if local_nick is NULL, or if
 * local_nick is lexographically smaller than remote_nick.
 * Else return CIRC_ID_TYPE_HIGHER.
 */
static int decide_circ_id_type(char *local_nick, char *remote_nick) {
  int result;

  tor_assert(remote_nick);
  if(!local_nick)
    return CIRC_ID_TYPE_LOWER;
  result = strcasecmp(local_nick, remote_nick);
  tor_assert(result);
  if(result < 0)
    return CIRC_ID_TYPE_LOWER;
  return CIRC_ID_TYPE_HIGHER;
}

/** Given a response payload and keys, initialize, then send a created
 * cell back.
 */
int onionskin_answer(circuit_t *circ, unsigned char *payload, unsigned char *keys) {
  cell_t cell;
  crypt_path_t *tmp_cpath;

  tmp_cpath = tor_malloc_zero(sizeof(crypt_path_t));

  memset(&cell, 0, sizeof(cell_t));
  cell.command = CELL_CREATED;
  cell.circ_id = circ->p_circ_id;

  circ->state = CIRCUIT_STATE_OPEN;

  log_fn(LOG_DEBUG,"Entering.");

  memcpy(cell.payload, payload, ONIONSKIN_REPLY_LEN);

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
  tor_free(tmp_cpath);

  memcpy(circ->handshake_digest, cell.payload+DH_KEY_LEN, DIGEST_LEN);

  connection_or_write_cell_to_buf(&cell, circ->p_conn);
  log_fn(LOG_DEBUG,"Finished sending 'created' cell.");

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

  tor_assert((cw >= 0) && (cw < 1) && routers); /* valid parameters */

#ifdef TOR_PERF
  routelen = 2;
#else
  if(purpose == CIRCUIT_PURPOSE_C_GENERAL)
    routelen = 3;
  else if(purpose == CIRCUIT_PURPOSE_C_INTRODUCING)
    routelen = 4;
  else if(purpose == CIRCUIT_PURPOSE_C_ESTABLISH_REND)
    routelen = 3;
  else if(purpose == CIRCUIT_PURPOSE_S_ESTABLISH_INTRO)
    routelen = 3;
  else if(purpose == CIRCUIT_PURPOSE_S_CONNECT_REND)
    routelen = 4;
  else {
    log_fn(LOG_WARN,"Unhandled purpose %d", purpose);
    return -1;
  }
#endif
#if 0
  for(routelen = 3; ; routelen++) { /* 3, increment until coinflip says we're done */
    if (crypto_pseudo_rand_int(255) >= cw*255) /* don't extend */
      break;
  }
#endif
  log_fn(LOG_DEBUG,"Chosen route length %d (%d routers available).",routelen,
         smartlist_len(routers));

  num_acceptable_routers = count_acceptable_routers(routers);

  if(num_acceptable_routers < 2) {
    log_fn(LOG_INFO,"Not enough acceptable routers (%d). Discarding this circuit.",
           num_acceptable_routers);
    return -1;
  }

  if(num_acceptable_routers < routelen) {
    log_fn(LOG_INFO,"Not enough routers: cutting routelen from %d to %d.",
           routelen, num_acceptable_routers);
    routelen = num_acceptable_routers;
  }

  return routelen;
}

/** Return a pointer to a suitable router to be the exit node for the
 * general-purpose circuit we're about to build.
 *
 * Look through the connection array, and choose a router that maximizes
 * the number of pending streams that can exit from this router.
 *
 * Return NULL if we can't find any suitable routers.
 */
static routerinfo_t *choose_good_exit_server_general(routerlist_t *dir)
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

  preferredentries = smartlist_create();
  add_nickname_list_to_smartlist(preferredentries,options.EntryNodes);

  get_connection_array(&carray, &n_connections);

  /* Count how many connections are waiting for a circuit to be built.
   * We use this for log messages now, but in the future we may depend on it.
   */
  for (i = 0; i < n_connections; ++i) {
    if (carray[i]->type == CONN_TYPE_AP &&
        carray[i]->state == AP_CONN_STATE_CIRCUIT_WAIT &&
        !carray[i]->marked_for_close &&
        !circuit_stream_is_being_handled(carray[i]))
      ++n_pending_connections;
  }
  log_fn(LOG_DEBUG, "Choosing exit node; %d connections are pending",
         n_pending_connections);
  /* Now we count, for each of the routers in the directory, how many
   * of the pending connections could possibly exit from that
   * router (n_supported[i]). (We can't be sure about cases where we
   * don't know the IP address of the pending connection.)
   */
  n_supported = tor_malloc(sizeof(int)*smartlist_len(dir->routers));
  for (i = 0; i < smartlist_len(dir->routers); ++i) { /* iterate over routers */
    router = smartlist_get(dir->routers, i);
    if(router_is_me(router)) {
      n_supported[i] = -1;
      log_fn(LOG_DEBUG,"Skipping node %s -- it's me.", router->nickname);
      /* XXX there's probably a reverse predecessor attack here, but
       * it's slow. should we take this out? -RD
       */
      continue;
    }
    if(!router->is_running) {
      n_supported[i] = -1;
      log_fn(LOG_DEBUG,"Skipping node %s (index %d) -- directory says it's not running.",
             router->nickname, i);
      continue; /* skip routers that are known to be down */
    }
    if(!router->is_verified &&
       !(options._AllowUnverified & ALLOW_UNVERIFIED_EXIT)) {
      n_supported[i] = -1;
      log_fn(LOG_DEBUG,"Skipping node %s (index %d) -- unverified router.",
             router->nickname, i);
      continue; /* skip unverified routers */
    }
    if(router_exit_policy_rejects_all(router)) {
      n_supported[i] = -1;
      log_fn(LOG_DEBUG,"Skipping node %s (index %d) -- it rejects all.",
             router->nickname, i);
      continue; /* skip routers that reject all */
    }
    if(smartlist_len(preferredentries)==1 &&
       router == (routerinfo_t*)smartlist_get(preferredentries, 0)) {
      n_supported[i] = -1;
      log_fn(LOG_DEBUG,"Skipping node %s (index %d) -- it's our only preferred entry node.", router->nickname, i);
      continue;
    }
    n_supported[i] = 0;
    for (j = 0; j < n_connections; ++j) { /* iterate over connections */
      if (carray[j]->type != CONN_TYPE_AP ||
          carray[j]->state != AP_CONN_STATE_CIRCUIT_WAIT ||
          carray[j]->marked_for_close ||
          circuit_stream_is_being_handled(carray[j]))
        continue; /* Skip everything but APs in CIRCUIT_WAIT */
      if(connection_ap_can_use_exit(carray[j], router)) {
        ++n_supported[i];
        log_fn(LOG_DEBUG,"%s is supported. n_supported[%d] now %d.",
               router->nickname, i, n_supported[i]);
      } else {
        log_fn(LOG_DEBUG,"%s (index %d) would reject this stream.",
               router->nickname, i);
      }
    } /* End looping over connections. */
    if (n_supported[i] > best_support) {
      /* If this router is better than previous ones, remember its index
       * and goodness, and start counting how many routers are this good. */
      best_support = n_supported[i]; n_best_support=1;
      log_fn(LOG_DEBUG,"%s is new best supported option so far.",
             router->nickname);
    } else if (n_supported[i] == best_support) {
      /* If this router is _as good_ as the best one, just increment the
       * count of equally good routers.*/
      ++n_best_support;
    }
  }
  log_fn(LOG_INFO, "Found %d servers that might support %d/%d pending connections.",
         n_best_support, best_support, n_pending_connections);

  preferredexits = smartlist_create();
  add_nickname_list_to_smartlist(preferredexits,options.ExitNodes);

  excludedexits = smartlist_create();
  add_nickname_list_to_smartlist(excludedexits,options.ExcludeNodes);

  sl = smartlist_create();

  /* If any routers definitely support any pending connections, choose one
   * at random. */
  if (best_support > 0) {
    for (i = 0; i < smartlist_len(dir->routers); i++)
      if (n_supported[i] == best_support)
        smartlist_add(sl, smartlist_get(dir->routers, i));

    smartlist_subtract(sl,excludedexits);
    if (options.StrictExitNodes || smartlist_overlap(sl,preferredexits))
      smartlist_intersect(sl,preferredexits);
    router = routerlist_sl_choose_by_bandwidth(sl);
  } else {
    /* Either there are no pending connections, or no routers even seem to
     * possibly support any of them.  Choose a router at random. */
    if (best_support == -1) {
      log(LOG_WARN, "All routers are down or middleman -- choosing a doomed exit at random.");
    }
    for(i = 0; i < smartlist_len(dir->routers); i++)
      if(n_supported[i] != -1)
        smartlist_add(sl, smartlist_get(dir->routers, i));

    smartlist_subtract(sl,excludedexits);
    if (options.StrictExitNodes || smartlist_overlap(sl,preferredexits))
      smartlist_intersect(sl,preferredexits);
    router = routerlist_sl_choose_by_bandwidth(sl);
  }

  smartlist_free(preferredexits);
  smartlist_free(preferredentries);
  smartlist_free(excludedexits);
  smartlist_free(sl);
  tor_free(n_supported);
  if(router) {
    log_fn(LOG_INFO, "Chose exit server '%s'", router->nickname);
    return router;
  }
  if (options.StrictExitNodes)
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
static routerinfo_t *choose_good_exit_server(uint8_t purpose, routerlist_t *dir)
{
  routerinfo_t *r;
  switch(purpose) {
    case CIRCUIT_PURPOSE_C_GENERAL:
      return choose_good_exit_server_general(dir);
    case CIRCUIT_PURPOSE_C_ESTABLISH_REND:
      r = router_choose_random_node(options.RendNodes, options.RendExcludeNodes,
          NULL, 0, 1, options._AllowUnverified & ALLOW_UNVERIFIED_RENDEZVOUS, 0);
      return r;
    default:
      log_fn(LOG_WARN,"unhandled purpose %d", purpose);
      tor_assert(0);
  }
  return NULL; /* never reached */
}

/** Allocate a cpath_build_state_t, populate it based on
 * <b>purpose</b> and <b>exit_digest</b> (if specified), and
 * return it.
 */
static cpath_build_state_t *
onion_new_cpath_build_state(uint8_t purpose, const char *exit_digest)
{
  routerlist_t *rl;
  int r;
  cpath_build_state_t *info;
  routerinfo_t *exit;
  router_get_routerlist(&rl);
  r = new_route_len(options.PathlenCoinWeight, purpose, rl->routers);
  if (r < 1) /* must be at least 1 */
    return NULL;
  info = tor_malloc_zero(sizeof(cpath_build_state_t));
  info->desired_path_len = r;
  if(exit_digest) { /* the circuit-builder pre-requested one */
    memcpy(info->chosen_exit_digest, exit_digest, DIGEST_LEN);
    exit = router_get_by_digest(exit_digest);
    if (exit) {
      info->chosen_exit_name = tor_strdup(exit->nickname);
    } else {
      info->chosen_exit_name = tor_malloc(HEX_DIGEST_LEN+1);
      base16_encode(info->chosen_exit_name, HEX_DIGEST_LEN+1,
                    exit_digest, DIGEST_LEN);
    }
    log_fn(LOG_INFO,"Using requested exit node '%s'", info->chosen_exit_name);
  } else { /* we have to decide one */
    exit = choose_good_exit_server(purpose, rl);
    if(!exit) {
      log_fn(LOG_WARN,"failed to choose an exit server");
      tor_free(info);
      return NULL;
    }
    memcpy(info->chosen_exit_digest, exit->identity_digest, DIGEST_LEN);
    info->chosen_exit_name = tor_strdup(exit->nickname);
  }
  return info;
}

/** Return the number of routers in <b>routers</b> that are currently up
 * and available for building circuits through. Count sets of twins only
 * once.
 */
static int count_acceptable_routers(smartlist_t *routers) {
  int i, j, n;
  int num=0;
  connection_t *conn;
  routerinfo_t *r, *r2;

  n = smartlist_len(routers);
  for(i=0;i<n;i++) {
    r = smartlist_get(routers, i);
    log_fn(LOG_DEBUG,"Contemplating whether router %d (%s) is a new option...",
           i, r->nickname);
    if(r->is_running == 0) {
      log_fn(LOG_DEBUG,"Nope, the directory says %d is not running.",i);
      goto next_i_loop;
    }
    if(r->is_verified == 0) {
      log_fn(LOG_DEBUG,"Nope, the directory says %d is not verified.",i);
      goto next_i_loop; /* XXX008 */
    }
    if(clique_mode()) {
      conn = connection_get_by_identity_digest(r->identity_digest,
                                               CONN_TYPE_OR);
      if(!conn || conn->state != OR_CONN_STATE_OPEN) {
        log_fn(LOG_DEBUG,"Nope, %d is not connected.",i);
        goto next_i_loop;
      }
    }
    for(j=0;j<i;j++) {
      r2 = smartlist_get(routers, j);
      if(!crypto_pk_cmp_keys(r->onion_pkey, r2->onion_pkey)) {
        /* these guys are twins. so we've already counted him. */
        log_fn(LOG_DEBUG,"Nope, %d is a twin of %d.",i,j);
        goto next_i_loop;
      }
    }
    num++;
    log_fn(LOG_DEBUG,"I like %d. num_acceptable_routers now %d.",i, num);
    next_i_loop:
      ; /* C requires an explicit statement after the label */
  }

  return num;
}

#if 0
/** Go through smartlist <b>sl</b> of routers, and remove all elements that
 * have the same onion key as twin.
 */
static void remove_twins_from_smartlist(smartlist_t *sl, routerinfo_t *twin) {
  int i;
  routerinfo_t *r;

  if(twin == NULL)
    return;

  for(i=0; i < smartlist_len(sl); i++) {
    r = smartlist_get(sl,i);
    if (!crypto_pk_cmp_keys(r->onion_pkey, twin->onion_pkey)) {
      smartlist_del(sl,i--);
    }
  }
}
#endif

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

static routerinfo_t *choose_good_middle_server(cpath_build_state_t *state,
                                               crypt_path_t *head,
                                               int cur_len)
{
  int i;
  routerinfo_t *r, *choice;
  crypt_path_t *cpath;
  smartlist_t *excluded = smartlist_create();

  log_fn(LOG_DEBUG, "Contemplating intermediate hop: random choice.");
  excluded = smartlist_create();
  if((r = router_get_by_digest(state->chosen_exit_digest)))
    smartlist_add(excluded, r);
  if((r = router_get_my_routerinfo()))
    smartlist_add(excluded, r);
  for (i = 0, cpath = head; i < cur_len; ++i, cpath=cpath->next) {
    r = router_get_by_digest(cpath->identity_digest);
    tor_assert(r);
    smartlist_add(excluded, r);
  }
  choice = router_choose_random_node("", options.ExcludeNodes, excluded,
           0, 1, options._AllowUnverified & ALLOW_UNVERIFIED_MIDDLE, 0);
  smartlist_free(excluded);
  return choice;
}

static routerinfo_t *choose_good_entry_server(cpath_build_state_t *state)
{
  routerinfo_t *r, *choice;
  smartlist_t *excluded = smartlist_create();
  char buf[16];

  if((r = router_get_by_digest(state->chosen_exit_digest)))
    smartlist_add(excluded, r);
  if((r = router_get_my_routerinfo()))
    smartlist_add(excluded, r);
  if(options.FascistFirewall) {
    /* exclude all ORs that listen on the wrong port */
    routerlist_t *rl;
    int i;

    router_get_routerlist(&rl);
    if(!rl)
      return NULL;

    for(i=0; i < smartlist_len(rl->routers); i++) {
      r = smartlist_get(rl->routers, i);
      sprintf(buf, "%d", r->or_port);
      if(!smartlist_string_isin(options.FirewallPorts, buf))
         smartlist_add(excluded, r);
    }
  }
  choice = router_choose_random_node(options.EntryNodes, options.ExcludeNodes,
           excluded, 0, 1, options._AllowUnverified & ALLOW_UNVERIFIED_ENTRY,
           options.StrictEntryNodes);
  smartlist_free(excluded);
  return choice;
}

/** Choose a suitable next hop in the cpath <b>head_ptr</b>,
 * based on <b>state</b>. Add the hop info to head_ptr, and return a
 * pointer to the chosen router in <b>router_out</b>.
 */
static int
onion_extend_cpath(crypt_path_t **head_ptr, cpath_build_state_t
                   *state, routerinfo_t **router_out)
{
  int cur_len;
  crypt_path_t *cpath, *hop;
  routerinfo_t *choice;
  smartlist_t *excludednodes;

  tor_assert(head_ptr);
  tor_assert(router_out);

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
  add_nickname_list_to_smartlist(excludednodes,options.ExcludeNodes);

  if(cur_len == state->desired_path_len - 1) { /* Picking last node */
    choice = router_get_by_digest(state->chosen_exit_digest);
  } else if(cur_len == 0) { /* picking first node */
    choice = choose_good_entry_server(state);
  } else {
    choice = choose_good_middle_server(state, *head_ptr, cur_len);
  }

  smartlist_free(excludednodes);
  if(!choice) {
    log_fn(LOG_WARN,"Failed to find node for hop %d of our path. Discarding this circuit.", cur_len);
    return -1;
  }

  log_fn(LOG_DEBUG,"Chose router %s for hop %d (exit is %s)",
         choice->nickname, cur_len, state->chosen_exit_name);

  hop = tor_malloc_zero(sizeof(crypt_path_t));

  /* link hop into the cpath, at the end. */
  onion_append_to_cpath(head_ptr, hop);

  hop->state = CPATH_STATE_CLOSED;

  hop->port = choice->or_port;
  hop->addr = choice->addr;
  memcpy(hop->identity_digest, choice->identity_digest, DIGEST_LEN);

  hop->package_window = CIRCWINDOW_START;
  hop->deliver_window = CIRCWINDOW_START;

  log_fn(LOG_DEBUG, "Extended circuit path with %s for hop %d",
         choice->nickname, cur_len);

  *router_out = choice;
  return 0;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
