/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

extern or_options_t options; /* command-line and config-file options */

static int relay_crypt(circuit_t *circ, cell_t *cell, int cell_direction,
                crypt_path_t **layer_hint, char *recognized);
static connection_t *relay_lookup_conn(circuit_t *circ, cell_t *cell, int cell_direction);
static void circuit_free_cpath_node(crypt_path_t *victim);
static uint16_t get_unique_circ_id_by_conn(connection_t *conn, int circ_id_type);
static void circuit_rep_hist_note_result(circuit_t *circ);

static void circuit_is_open(circuit_t *circ);
static void circuit_failed(circuit_t *circ);
static circuit_t *circuit_establish_circuit(uint8_t purpose, const char *exit_nickname);

unsigned long stats_n_relay_cells_relayed = 0;
unsigned long stats_n_relay_cells_delivered = 0;

/********* START VARIABLES **********/

static int circuitlist_len=0;
static circuit_t *global_circuitlist=NULL;
char *circuit_state_to_string[] = {
  "doing handshakes",        /* 0 */
  "processing the onion",    /* 1 */
  "connecting to firsthop",  /* 2 */
  "open"                     /* 3 */
};

/********* END VARIABLES ************/

void circuit_add(circuit_t *circ) {
  if(!global_circuitlist) { /* first one */
    global_circuitlist = circ;
    circ->next = NULL;
  } else {
    circ->next = global_circuitlist;
    global_circuitlist = circ;
  }
  ++circuitlist_len;
}

void circuit_remove(circuit_t *circ) {
  circuit_t *tmpcirc;

  assert(circ && global_circuitlist);

  if(global_circuitlist == circ) {
    global_circuitlist = global_circuitlist->next;
    --circuitlist_len;
    return;
  }

  for(tmpcirc = global_circuitlist;tmpcirc->next;tmpcirc = tmpcirc->next) {
    if(tmpcirc->next == circ) {
      tmpcirc->next = circ->next;
      --circuitlist_len;
      return;
    }
  }
}

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

void circuit_free(circuit_t *circ) {
  assert(circ);
  assert(circ->magic == CIRCUIT_MAGIC);
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

/* return 0 if can't get a unique circ_id. */
static uint16_t get_unique_circ_id_by_conn(connection_t *conn, int circ_id_type) {
  uint16_t test_circ_id;
  int attempts=0;
  uint16_t high_bit;

  assert(conn && conn->type == CONN_TYPE_OR);
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
    }
  }
  return NULL;
}

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
  }
  return NULL;
}

/* Dear god this function needs refactoring. */
/* Find the best circ that conn can use, preferably one which is
 * dirty. Circ must not be too old.
 * If !conn, return newest.
 *
 * If must_be_open, ignore circs not in CIRCUIT_STATE_OPEN.
 *
 * circ_purpose specifies what sort of circuit we must have.
 * It can be C_GENERAL, C_INTRODUCING, or C_REND_JOINED.
 *
 * If it's REND_JOINED and must_be_open==0, then return the closest
 * rendezvous-purposed circuit that you can find.
 *
 * If circ_purpose is not GENERAL, then conn must be defined.
 */
circuit_t *circuit_get_best(connection_t *conn,
                            int must_be_open, uint8_t purpose) {
  circuit_t *circ, *best=NULL;
  routerinfo_t *exitrouter;
  time_t now = time(NULL);

  assert(purpose == CIRCUIT_PURPOSE_C_GENERAL ||
         purpose == CIRCUIT_PURPOSE_C_INTRODUCING ||
         purpose == CIRCUIT_PURPOSE_C_REND_JOINED);

  for (circ=global_circuitlist;circ;circ = circ->next) {
    if (!circ->cpath)
      continue; /* this circ doesn't start at us */
    if (must_be_open && (circ->state != CIRCUIT_STATE_OPEN || !circ->n_conn))
      continue; /* ignore non-open circs */
    if (circ->marked_for_close)
      continue;

    /* if this circ isn't our purpose, skip. */
    if(purpose == CIRCUIT_PURPOSE_C_REND_JOINED) {
      if(must_be_open && purpose != circ->purpose)
        continue;
      if(circ->purpose != CIRCUIT_PURPOSE_C_ESTABLISH_REND &&
         circ->purpose != CIRCUIT_PURPOSE_C_REND_READY &&
         circ->purpose != CIRCUIT_PURPOSE_C_REND_JOINED)
        continue;
    } else {
      if(purpose != circ->purpose)
        continue;
    }

    if(purpose == CIRCUIT_PURPOSE_C_GENERAL)
      if(circ->timestamp_dirty &&
         circ->timestamp_dirty+options.NewCircuitPeriod < now)
        continue; /* too old */

    if(conn) {
      /* decide if this circ is suitable for this conn */

      if(circ->state == CIRCUIT_STATE_OPEN && circ->n_conn) /* open */
        exitrouter = router_get_by_addr_port(circ->cpath->prev->addr,
                                             circ->cpath->prev->port);
      else /* not open */
        exitrouter = router_get_by_nickname(circ->build_state->chosen_exit);

      if(!exitrouter) {
        log_fn(LOG_INFO,"Skipping broken circ (exit router vanished)");
        continue; /* this circuit is screwed and doesn't know it yet */
      }

      if(purpose == CIRCUIT_PURPOSE_C_GENERAL) {
        if(connection_ap_can_use_exit(conn, exitrouter) == ADDR_POLICY_REJECTED) {
          /* can't exit from this router */
          continue;
        }
      } else { /* not general */
        if(rend_cmp_service_ids(conn->rend_query, circ->rend_query)) {
          /* this circ is not for this conn */
          continue;
        }
      }
    }

    /* now this is an acceptable circ to hand back. but that doesn't
     * mean it's the *best* circ to hand back. try to decide.
     */
    if(!best)
      best = circ;
    switch(purpose) {
      case CIRCUIT_PURPOSE_C_GENERAL:
        /* if it's used but less dirty it's best;
         * else if it's more recently created it's best
         */
        if(best->timestamp_dirty) {
          if(circ->timestamp_dirty &&
             circ->timestamp_dirty > best->timestamp_dirty)
            best = circ;
        } else {
          if(circ->timestamp_dirty ||
             circ->timestamp_created > best->timestamp_created)
            best = circ;
        }
        break;
      case CIRCUIT_PURPOSE_C_INTRODUCING:
        /* more recently created is best */
        if(circ->timestamp_created > best->timestamp_created)
          best = circ;
        break;
      case CIRCUIT_PURPOSE_C_REND_JOINED:
        /* the closer it is to rend_joined the better it is */
        if(circ->purpose > best->purpose)
          best = circ;
        break;
    }
  }

  return best;
}

/* Return the first circuit in global_circuitlist after 'start' whose
 * rend_pk_digest field is 'digest' and whose purpose is purpose. Returns
 * NULL if no circuit is found.  If 'start' is null, begin at the start of
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

/* Return the circuit waiting for a rendezvous with the provided cookie.
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

#define MIN_SECONDS_BEFORE_EXPIRING_CIRC 10
/* circuits that were born at the end of their second might be expired
 * after 10.1 seconds; circuits born at the beginning might be expired
 * after closer to 11 seconds.
 */

/* close all circuits that start at us, aren't open, and were born
 * at least MIN_SECONDS_BEFORE_EXPIRING_CIRC seconds ago */
void circuit_expire_building(void) {
  int now = time(NULL);
  circuit_t *victim, *circ = global_circuitlist;

  while(circ) {
    victim = circ;
    circ = circ->next;
    if(victim->cpath &&
       victim->state != CIRCUIT_STATE_OPEN &&
       victim->timestamp_created + MIN_SECONDS_BEFORE_EXPIRING_CIRC+1 < now &&
       !victim->marked_for_close) {
      if(victim->n_conn)
        log_fn(LOG_INFO,"Abandoning circ %s:%d:%d (state %d:%s)",
               victim->n_conn->address, victim->n_port, victim->n_circ_id,
               victim->state, circuit_state_to_string[victim->state]);
      else
        log_fn(LOG_INFO,"Abandoning circ %d (state %d:%s)", victim->n_circ_id,
               victim->state, circuit_state_to_string[victim->state]);
      circuit_log_path(LOG_INFO,victim);
      circuit_mark_for_close(victim);
    }
  }
}

/* count the number of circs starting at us that aren't open */
int circuit_count_building(void) {
  circuit_t *circ;
  int num=0;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if(circ->cpath
       && circ->state != CIRCUIT_STATE_OPEN
       && !circ->marked_for_close)
      num++;
  }
  return num;
}

#define MIN_CIRCUITS_HANDLING_STREAM 2
/* return 1 if at least MIN_CIRCUITS_HANDLING_STREAM non-open
 * general-purpose circuits will have an acceptable exit node for
 * conn. Else return 0.
 */
int circuit_stream_is_being_handled(connection_t *conn) {
  circuit_t *circ;
  routerinfo_t *exitrouter;
  int num=0;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if(circ->cpath && circ->state != CIRCUIT_STATE_OPEN &&
       !circ->marked_for_close && circ->purpose == CIRCUIT_PURPOSE_C_GENERAL) {
      exitrouter = router_get_by_nickname(circ->build_state->chosen_exit);
      if(exitrouter && connection_ap_can_use_exit(conn, exitrouter) != ADDR_POLICY_REJECTED)
        if(++num >= MIN_CIRCUITS_HANDLING_STREAM)
          return 1;
    }
  }
  return 0;
}

/* update digest from the payload of cell. assign integrity part to cell. */
static void relay_set_digest(crypto_digest_env_t *digest, cell_t *cell) {
  char integrity[4];
  relay_header_t rh;

  crypto_digest_add_bytes(digest, cell->payload, CELL_PAYLOAD_SIZE);
  crypto_digest_get_digest(digest, integrity, 4);
//  log_fn(LOG_DEBUG,"Putting digest of %u %u %u %u into relay cell.",
//    integrity[0], integrity[1], integrity[2], integrity[3]);
  relay_header_unpack(&rh, cell->payload);
  memcpy(rh.integrity, integrity, 4);
  relay_header_pack(cell->payload, &rh);
}

/* update digest from the payload of cell (with the integrity part set
 * to 0). If the integrity part is valid return 1, else restore digest
 * and cell to their original state and return 0.
 */
static int relay_digest_matches(crypto_digest_env_t *digest, cell_t *cell) {
  char received_integrity[4], calculated_integrity[4];
  relay_header_t rh;
  crypto_digest_env_t *backup_digest=NULL;

  backup_digest = crypto_digest_dup(digest);

  relay_header_unpack(&rh, cell->payload);
  memcpy(received_integrity, rh.integrity, 4);
  memset(rh.integrity, 0, 4);
  relay_header_pack(cell->payload, &rh);

//  log_fn(LOG_DEBUG,"Reading digest of %u %u %u %u from relay cell.",
//    received_integrity[0], received_integrity[1],
//    received_integrity[2], received_integrity[3]);

  crypto_digest_add_bytes(digest, cell->payload, CELL_PAYLOAD_SIZE);
  crypto_digest_get_digest(digest, calculated_integrity, 4);

  if(memcmp(received_integrity, calculated_integrity, 4)) {
//    log_fn(LOG_INFO,"Recognized=0 but bad digest. Not recognizing.");
// (%d vs %d).", received_integrity, calculated_integrity);
    /* restore digest to its old form */
    crypto_digest_assign(digest, backup_digest);
    /* restore the relay header */
    memcpy(rh.integrity, received_integrity, 4);
    relay_header_pack(cell->payload, &rh);
    crypto_free_digest_env(backup_digest);
    return 0;
  }
  crypto_free_digest_env(backup_digest);
  return 1;
}

static int relay_crypt_one_payload(crypto_cipher_env_t *cipher, char *in,
                                   int encrypt_mode) {
  char out[CELL_PAYLOAD_SIZE]; /* 'in' must be this size too */
  relay_header_t rh;

  relay_header_unpack(&rh, in);
//  log_fn(LOG_DEBUG,"before crypt: %d",rh.recognized);
  if(( encrypt_mode && crypto_cipher_encrypt(cipher, in, CELL_PAYLOAD_SIZE, out)) ||
     (!encrypt_mode && crypto_cipher_decrypt(cipher, in, CELL_PAYLOAD_SIZE, out))) {
    log_fn(LOG_WARN,"Error during crypt: %s", crypto_perror());
    return -1;
  }
  memcpy(in,out,CELL_PAYLOAD_SIZE);
  relay_header_unpack(&rh, in);
//  log_fn(LOG_DEBUG,"after crypt: %d",rh.recognized);
  return 0;
}

/*
receive a relay cell:
  - crypt it (encrypt APward, decrypt at AP, decrypt exitward)
  - check if recognized (if exitward)
  - if recognized, check digest, find right conn, deliver to edge.
  - else connection_or_write_cell_to_buf to the right conn
*/
int circuit_receive_relay_cell(cell_t *cell, circuit_t *circ,
                               int cell_direction) {
  connection_t *conn=NULL;
  crypt_path_t *layer_hint=NULL;
  char recognized=0;

  assert(cell && circ);
  assert(cell_direction == CELL_DIRECTION_OUT || cell_direction == CELL_DIRECTION_IN);
  if (circ->marked_for_close)
    return 0;

  if(relay_crypt(circ, cell, cell_direction, &layer_hint, &recognized) < 0) {
    log_fn(LOG_WARN,"relay crypt failed. Dropping connection.");
    return -1;
  }

  if(recognized) {
    conn = relay_lookup_conn(circ, cell, cell_direction);
    if(cell_direction == CELL_DIRECTION_OUT) {
      ++stats_n_relay_cells_delivered;
      log_fn(LOG_DEBUG,"Sending to exit.");
      if (connection_edge_process_relay_cell(cell, circ, conn, EDGE_EXIT, NULL) < 0) {
        log_fn(LOG_WARN,"connection_edge_process_relay_cell (at exit) failed.");
        return -1;
      }
    }
    if(cell_direction == CELL_DIRECTION_IN) {
      ++stats_n_relay_cells_delivered;
      log_fn(LOG_DEBUG,"Sending to AP.");
      if (connection_edge_process_relay_cell(cell, circ, conn, EDGE_AP, layer_hint) < 0) {
        log_fn(LOG_WARN,"connection_edge_process_relay_cell (at AP) failed.");
        return -1;
      }
    }
    return 0;
  }

  /* not recognized. pass it on. */
  if(cell_direction == CELL_DIRECTION_OUT) {
    cell->circ_id = circ->n_circ_id; /* switch it */
    conn = circ->n_conn;
  } else {
    cell->circ_id = circ->p_circ_id; /* switch it */
    conn = circ->p_conn;
  }

  if(!conn) {
    if (circ->rend_splice && cell_direction == CELL_DIRECTION_OUT) {
      assert(circ->purpose == CIRCUIT_PURPOSE_REND_ESTABLISHED);
      assert(circ->rend_splice->purpose == CIRCUIT_PURPOSE_REND_ESTABLISHED);
      cell->circ_id = circ->rend_splice->p_circ_id;
      if (circuit_receive_relay_cell(cell, circ->rend_splice, CELL_DIRECTION_IN)<0) {
        log_fn(LOG_WARN, "Error relaying cell across rendezvous; closing circuits");
        circuit_mark_for_close(circ); /* XXXX Do this here, or just return -1? */
        return -1;
      }
      return 0;
    }
    log_fn(LOG_WARN,"Didn't recognize cell, but circ stops here! Closing circ.");
    return -1;
  }

  log_fn(LOG_DEBUG,"Passing on unrecognized cell.");
  ++stats_n_relay_cells_relayed;
  connection_or_write_cell_to_buf(cell, conn);
  return 0;
}

/* wrap this into receive_relay_cell one day */
static int relay_crypt(circuit_t *circ, cell_t *cell, int cell_direction,
                       crypt_path_t **layer_hint, char *recognized) {
  crypt_path_t *thishop;
  relay_header_t rh;

  assert(circ && cell && recognized);
  assert(cell_direction == CELL_DIRECTION_IN || cell_direction == CELL_DIRECTION_OUT);

  if(cell_direction == CELL_DIRECTION_IN) {
    if(circ->cpath) { /* we're at the beginning of the circuit.
                         We'll want to do layered crypts. */
      thishop = circ->cpath;
      if(thishop->state != CPATH_STATE_OPEN) {
        log_fn(LOG_WARN,"Relay cell before first created cell? Closing.");
        return -1;
      }
      do { /* Remember: cpath is in forward order, that is, first hop first. */
        assert(thishop);

        if(relay_crypt_one_payload(thishop->b_crypto, cell->payload, 0) < 0)
          return -1;

        relay_header_unpack(&rh, cell->payload);
        if(rh.recognized == 0) {
          /* it's possibly recognized. have to check digest to be sure. */
          if(relay_digest_matches(thishop->b_digest, cell)) {
            *recognized = 1;
            *layer_hint = thishop;
            return 0;
          }
        }

        thishop = thishop->next;
      } while(thishop != circ->cpath && thishop->state == CPATH_STATE_OPEN);
      log_fn(LOG_WARN,"in-cell at OP not recognized. Closing.");
      return -1;
    } else { /* we're in the middle. Just one crypt. */
      if(relay_crypt_one_payload(circ->p_crypto, cell->payload, 1) < 0)
        return -1;
//      log_fn(LOG_DEBUG,"Skipping recognized check, because we're not the OP.");
    }
  } else /* cell_direction == CELL_DIRECTION_OUT */ {
    /* we're in the middle. Just one crypt. */

    if(relay_crypt_one_payload(circ->n_crypto, cell->payload, 0) < 0)
      return -1;

    relay_header_unpack(&rh, cell->payload);
    if (rh.recognized == 0) {
      /* it's possibly recognized. have to check digest to be sure. */
      if(relay_digest_matches(circ->n_digest, cell)) {
        *recognized = 1;
        return 0;
      }
    }
  }
  return 0;
}

/*
package a relay cell:
 1) encrypt it to the right conn
 2) connection_or_write_cell_to_buf to the right conn
*/
int
circuit_package_relay_cell(cell_t *cell, circuit_t *circ,
                           int cell_direction,
                           crypt_path_t *layer_hint)
{
  connection_t *conn; /* where to send the cell */
  crypt_path_t *thishop; /* counter for repeated crypts */

  if(cell_direction == CELL_DIRECTION_OUT) {
    conn = circ->n_conn;
    if(!conn) {
      log_fn(LOG_WARN,"outgoing relay cell has n_conn==NULL. Dropping.");
      return 0; /* just drop it */
    }
    relay_set_digest(layer_hint->f_digest, cell);

    thishop = layer_hint;
    /* moving from farthest to nearest hop */
    do {
      assert(thishop);

      log_fn(LOG_DEBUG,"crypting a layer of the relay cell.");
      if(relay_crypt_one_payload(thishop->f_crypto, cell->payload, 1) < 0) {
        return -1;
      }

      thishop = thishop->prev;
    } while (thishop != circ->cpath->prev);

  } else { /* incoming cell */
    conn = circ->p_conn;
    if(!conn) {
      log_fn(LOG_WARN,"incoming relay cell has p_conn==NULL. Dropping.");
      return 0; /* just drop it */
    }
    relay_set_digest(circ->p_digest, cell);
    if(relay_crypt_one_payload(circ->p_crypto, cell->payload, 1) < 0)
      return -1;
  }
  ++stats_n_relay_cells_relayed;
  connection_or_write_cell_to_buf(cell, conn);
  return 0;
}

static connection_t *
relay_lookup_conn(circuit_t *circ, cell_t *cell, int cell_direction)
{
  connection_t *tmpconn;
  relay_header_t rh;

  relay_header_unpack(&rh, cell->payload);

  if(!rh.stream_id)
    return NULL;

  /* IN or OUT cells could have come from either direction, now
   * that we allow rendezvous *to* an OP.
   */

  for(tmpconn = circ->n_streams; tmpconn; tmpconn=tmpconn->next_stream) {
    if(rh.stream_id == tmpconn->stream_id) {
      log_fn(LOG_DEBUG,"found conn for stream %d.", rh.stream_id);
      if(cell_direction == CELL_DIRECTION_OUT ||
         connection_edge_is_rendezvous_stream(tmpconn))
        return tmpconn;
    }
  }
  for(tmpconn = circ->p_streams; tmpconn; tmpconn=tmpconn->next_stream) {
    if(rh.stream_id == tmpconn->stream_id) {
      log_fn(LOG_DEBUG,"found conn for stream %d.", rh.stream_id);
      return tmpconn;
    }
  }
  return NULL; /* probably a begin relay cell */
}

void circuit_resume_edge_reading(circuit_t *circ, int edge_type, crypt_path_t *layer_hint) {
  connection_t *conn;

  assert(edge_type == EDGE_EXIT || edge_type == EDGE_AP);

  log_fn(LOG_DEBUG,"resuming");

  if(edge_type == EDGE_EXIT)
    conn = circ->n_streams;
  else
    conn = circ->p_streams;

  for( ; conn; conn=conn->next_stream) {
    if((edge_type == EDGE_EXIT && conn->package_window > 0) ||
       (edge_type == EDGE_AP   && conn->package_window > 0 && conn->cpath_layer == layer_hint)) {
      connection_start_reading(conn);
      connection_edge_package_raw_inbuf(conn); /* handle whatever might still be on the inbuf */

      /* If the circuit won't accept any more data, return without looking
       * at any more of the streams. Any connections that should be stopped
       * have already been stopped by connection_edge_package_raw_inbuf. */
      if(circuit_consider_stop_edge_reading(circ, edge_type, layer_hint))
        return;
    }
  }
}

/* returns 1 if the window is empty, else 0. If it's empty, tell edge conns to stop reading. */
int circuit_consider_stop_edge_reading(circuit_t *circ, int edge_type, crypt_path_t *layer_hint) {
  connection_t *conn = NULL;

  assert(edge_type == EDGE_EXIT || edge_type == EDGE_AP);
  assert(edge_type == EDGE_EXIT || layer_hint);

  log_fn(LOG_DEBUG,"considering");
  if(edge_type == EDGE_EXIT && circ->package_window <= 0)
    conn = circ->n_streams;
  else if(edge_type == EDGE_AP && layer_hint->package_window <= 0)
    conn = circ->p_streams;
  else
    return 0;

  for( ; conn; conn=conn->next_stream)
    if(!layer_hint || conn->cpath_layer == layer_hint)
      connection_stop_reading(conn);

  log_fn(LOG_DEBUG,"yes. stopped.");
  return 1;
}

void circuit_consider_sending_sendme(circuit_t *circ, int edge_type, crypt_path_t *layer_hint) {
  while((edge_type == EDGE_AP ? layer_hint->deliver_window : circ->deliver_window) <
         CIRCWINDOW_START - CIRCWINDOW_INCREMENT) {
    log_fn(LOG_DEBUG,"Queueing circuit sendme.");
    if(edge_type == EDGE_AP)
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

int _circuit_mark_for_close(circuit_t *circ) {
  connection_t *conn;

  assert_circuit_ok(circ);
  if (circ->marked_for_close < 0)
    return -1;

  if(circ->state == CIRCUIT_STATE_ONIONSKIN_PENDING) {
    onion_pending_remove(circ);
  }
  /* If the circuit ever became OPEN, we sent it to the reputation history
   * module then.  If it isn't OPEN, we send it there now to remember which
   * links worked and which didn't.
   */
  if (circ->state != CIRCUIT_STATE_OPEN) {
    circuit_failed(circ); /* take actions if necessary */
    circuit_rep_hist_note_result(circ);
  }

  if(circ->n_conn)
    connection_send_destroy(circ->n_circ_id, circ->n_conn);
  for(conn=circ->n_streams; conn; conn=conn->next_stream) {
    connection_edge_destroy(circ->n_circ_id, conn);
  }
  if(circ->p_conn)
    connection_send_destroy(circ->n_circ_id, circ->p_conn);
  for(conn=circ->p_streams; conn; conn=conn->next_stream) {
    connection_edge_destroy(circ->p_circ_id, conn);
  }

  circ->marked_for_close = 1;

  if (circ->rend_splice && !circ->rend_splice->marked_for_close) {
    /* do this after marking this circuit, to avoid infinite recursion. */
    circuit_mark_for_close(circ->rend_splice);
    circ->rend_splice = NULL;
  }
  return 0;
}

void circuit_detach_stream(circuit_t *circ, connection_t *conn) {
  connection_t *prevconn;

  assert(circ);
  assert(conn);

  if(conn == circ->p_streams) {
    circ->p_streams = conn->next_stream;
    return;
  }
  if(conn == circ->n_streams) {
    circ->n_streams = conn->next_stream;
    return;
  }
  for(prevconn = circ->p_streams; prevconn && prevconn->next_stream && prevconn->next_stream != conn; prevconn = prevconn->next_stream) ;
  if(prevconn && prevconn->next_stream) {
    prevconn->next_stream = conn->next_stream;
    return;
  }
  for(prevconn = circ->n_streams; prevconn && prevconn->next_stream && prevconn->next_stream != conn; prevconn = prevconn->next_stream) ;
  if(prevconn && prevconn->next_stream) {
    prevconn->next_stream = conn->next_stream;
    return;
  }
  log_fn(LOG_ERR,"edge conn not in circuit's list?");
  assert(0); /* should never get here */
}

void circuit_about_to_close_connection(connection_t *conn) {
  /* send destroys for all circuits using conn */
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

void circuit_log_path(int severity, circuit_t *circ) {
  char buf[1024];
  char *s = buf;
  struct crypt_path_t *hop;
  char *states[] = {"closed", "waiting for keys", "open"};
  routerinfo_t *router;
  assert(circ->cpath);

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

/* Tell the rep(utation)hist(ory) module about the status of the links
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

static void
circuit_dump_details(int severity, circuit_t *circ, int poll_index,
                     char *type, int this_circid, int other_circid) {
  struct crypt_path_t *hop;
  log(severity,"Conn %d has %s circuit: circID %d (other side %d), state %d (%s), born %d",
      poll_index, type, this_circid, other_circid, circ->state,
      circuit_state_to_string[circ->state], (int)circ->timestamp_created);
  if(circ->cpath) { /* circ starts at this node */
    if(circ->state == CIRCUIT_STATE_BUILDING)
      log(severity,"Building: desired len %d, planned exit node %s.",
          circ->build_state->desired_path_len, circ->build_state->chosen_exit);
    for(hop=circ->cpath;hop->next != circ->cpath; hop=hop->next)
      log(severity,"hop: state %d, addr 0x%.8x, port %d", hop->state,
          (unsigned int)hop->addr,
          (int)hop->port);
  }
}

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

/* Don't keep more than 10 unused open circuits around. */
#define MAX_UNUSED_OPEN_CIRCUITS 10

void circuit_expire_unused_circuits(void) {
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
        !circ->p_conn &&
        !circ->p_streams) {
      log_fn(LOG_DEBUG,"Closing n_circ_id %d",circ->n_circ_id);
      circuit_mark_for_close(circ);
    } else if (!circ->timestamp_dirty && circ->cpath &&
               circ->state == CIRCUIT_STATE_OPEN) {
      /* Also, gather a list of open unused circuits that we created.
       * Because we add elements to the front of global_circuitlist,
       * the last elements of unused_open_circs will be the oldest
       * ones.
       */
      smartlist_add(unused_open_circs, circ);
    }
  }
  for (i = MAX_UNUSED_OPEN_CIRCUITS; i < smartlist_len(unused_open_circs); ++i) {
    circuit_t *circ = smartlist_get(unused_open_circs, i);
    circuit_mark_for_close(circ);
  }
  smartlist_free(unused_open_circs);
}

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
      assert(0);
  }
}

static void circuit_failed(circuit_t *circ) {

  /* we should examine circ and see if it failed because of
   * the last hop or an earlier hop. then use this info below.
   */
  //int failed_at_last_hop;

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
      // remember this somewhere?
      break;
    case CIRCUIT_PURPOSE_C_INTRODUCING:
      /* at Alice, connecting to intro point */
      // alice needs to try another intro point
      break;
    case CIRCUIT_PURPOSE_C_ESTABLISH_REND:
      /* at Alice, waiting for Bob */
      // alice needs to pick a new rend point
      break;
    case CIRCUIT_PURPOSE_S_CONNECT_REND:
      /* at Bob, connecting to rend point */
      // 
      break;
  }
}

/* Number of consecutive failures so far; should only be touched by
 * circuit_launch_new and circuit_*_failure_count.
 */
static int n_circuit_failures = 0;

/* Don't retry launching a new circuit if we try this many times with no
 * success. */
#define MAX_CIRCUIT_FAILURES 5

/* Launch a new circuit and return a pointer to it. Return NULL if you failed. */
circuit_t *circuit_launch_new(uint8_t purpose, const char *exit_nickname) {

  if (n_circuit_failures > MAX_CIRCUIT_FAILURES) {
    /* too many failed circs in a row. don't try. */
//    log_fn(LOG_INFO,"%d failures so far, not trying.",n_circuit_failures);
    return NULL;
  }

  /* try a circ. if it fails, circuit_mark_for_close will increment n_circuit_failures */
  return circuit_establish_circuit(purpose, exit_nickname);
}

void circuit_increment_failure_count(void) {
  ++n_circuit_failures;
  log_fn(LOG_DEBUG,"n_circuit_failures now %d.",n_circuit_failures);
}

void circuit_reset_failure_count(void) {
  n_circuit_failures = 0;
}

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
  if(!circ->cpath) {
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
    if(options.ORPort) { /* we would be connected if he were up. and he's not. */
      log_fn(LOG_INFO,"Route's firsthop isn't connected.");
      circuit_mark_for_close(circ);
      return NULL;
    }

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

/* find circuits that are waiting on me, if any, and get them to send the onion */
void circuit_n_conn_open(connection_t *or_conn) {
  circuit_t *circ;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if (circ->marked_for_close)
      continue;
    if(circ->cpath && circ->n_addr == or_conn->addr && circ->n_port == or_conn->port) {
      assert(circ->state == CIRCUIT_STATE_OR_WAIT);
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

int circuit_send_next_onion_skin(circuit_t *circ) {
  cell_t cell;
  crypt_path_t *hop;
  routerinfo_t *router;
  int r;
  int circ_id_type;
  char payload[2+4+ONIONSKIN_CHALLENGE_LEN];

  assert(circ && circ->cpath);

  if(circ->cpath->state == CPATH_STATE_CLOSED) {
    assert(circ->n_conn && circ->n_conn->type == CONN_TYPE_OR);

    log_fn(LOG_DEBUG,"First skin; sending create cell.");
    circ_id_type = decide_circ_id_type(options.Nickname,
                                       circ->n_conn->nickname);
    circ->n_circ_id = get_unique_circ_id_by_conn(circ->n_conn, circ_id_type);

    memset(&cell, 0, sizeof(cell_t));
    cell.command = CELL_CREATE;
    cell.circ_id = circ->n_circ_id;

    if(onion_skin_create(circ->n_conn->onion_pkey,
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
    assert(circ->cpath->state == CPATH_STATE_OPEN);
    assert(circ->state == CIRCUIT_STATE_BUILDING);
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

/* take the 'extend' cell, pull out addr/port plus the onion skin. Make
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
    connection_edge_send_command(NULL, circ, RELAY_COMMAND_TRUNCATED,
                                 NULL, 0, NULL);
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

/* Initialize cpath->{f|b}_{crypto|digest} from the key material in
 * key_data.  key_data must contain CPATH_KEY_MATERIAL bytes, which are
 * used as follows:
 *       20 to initialize f_digest
 *       20 to initialize b_digest
 *       16 to key f_crypto
 *       16 to key b_crypto
 *
 * (If 'reverse' is true, then f_XX and b_XX are swapped.)
 */
int circuit_init_cpath_crypto(crypt_path_t *cpath, char *key_data, int reverse)
{
  unsigned char iv[CIPHER_IV_LEN];
  crypto_digest_env_t *tmp_digest;
  crypto_cipher_env_t *tmp_crypto;

  assert(cpath && key_data);
  assert(!(cpath->f_crypto || cpath->b_crypto ||
           cpath->f_digest || cpath->b_digest));

  memset(iv, 0, CIPHER_IV_LEN);

  log_fn(LOG_DEBUG,"hop init digest forward 0x%.8x, backward 0x%.8x.",
         (unsigned int)*(uint32_t*)key_data, (unsigned int)*(uint32_t*)(key_data+20));
  cpath->f_digest = crypto_new_digest_env();
  crypto_digest_add_bytes(cpath->f_digest, key_data, DIGEST_LEN);
  cpath->b_digest = crypto_new_digest_env();
  crypto_digest_add_bytes(cpath->b_digest, key_data+DIGEST_LEN, DIGEST_LEN);

  log_fn(LOG_DEBUG,"hop init cipher forward 0x%.8x, backward 0x%.8x.",
         (unsigned int)*(uint32_t*)(key_data+40), (unsigned int)*(uint32_t*)(key_data+40+16));
  if (!(cpath->f_crypto =
        crypto_create_init_cipher(key_data+(2*DIGEST_LEN),iv,1))) {
    log(LOG_WARN,"forward cipher initialization failed.");
    return -1;
  }
  if (!(cpath->b_crypto =
     crypto_create_init_cipher(key_data+(2*DIGEST_LEN)+CIPHER_KEY_LEN,iv,0))) {
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

int circuit_finish_handshake(circuit_t *circ, char *reply) {
  unsigned char keys[CPATH_KEY_MATERIAL_LEN];
  crypt_path_t *hop;

  assert(circ->cpath);
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
  assert(hop->state == CPATH_STATE_AWAITING_KEYS);

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

int circuit_truncated(circuit_t *circ, crypt_path_t *layer) {
  crypt_path_t *victim;
  connection_t *stream;

  assert(circ);
  assert(layer);

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

void assert_cpath_layer_ok(const crypt_path_t *cp)
{
  assert(cp->f_crypto);
  assert(cp->b_crypto);
//  assert(cp->addr); /* these are zero for rendezvous extra-hops */
//  assert(cp->port);
  switch(cp->state)
    {
    case CPATH_STATE_CLOSED:
    case CPATH_STATE_OPEN:
      assert(!cp->handshake_state);
      break;
    case CPATH_STATE_AWAITING_KEYS:
      assert(cp->handshake_state);
      break;
    default:
      assert(0);
    }
  assert(cp->package_window >= 0);
  assert(cp->deliver_window >= 0);
}

void assert_cpath_ok(const crypt_path_t *cp)
{
  while(cp->prev)
    cp = cp->prev;

  while(cp->next) {
    assert_cpath_layer_ok(cp);
    /* layers must be in sequence of: "open* awaiting? closed*" */
    if (cp->prev) {
      if (cp->prev->state == CPATH_STATE_OPEN) {
        assert(cp->state == CPATH_STATE_CLOSED ||
               cp->state == CPATH_STATE_AWAITING_KEYS);
      } else {
        assert(cp->state == CPATH_STATE_CLOSED);
      }
    }
    cp = cp->next;
  }
}

void assert_circuit_ok(const circuit_t *c)
{
  connection_t *conn;

  assert(c);
  assert(c->magic == CIRCUIT_MAGIC);
  assert(c->purpose >= _CIRCUIT_PURPOSE_MIN &&
         c->purpose <= _CIRCUIT_PURPOSE_MAX);

  if (c->n_conn)
    assert(c->n_conn->type == CONN_TYPE_OR);
  if (c->p_conn)
    assert(c->p_conn->type == CONN_TYPE_OR);
  for (conn = c->p_streams; conn; conn = conn->next_stream)
    assert(conn->type == CONN_TYPE_AP);
  for (conn = c->n_streams; conn; conn = conn->next_stream)
    assert(conn->type == CONN_TYPE_EXIT);

  assert(c->deliver_window >= 0);
  assert(c->package_window >= 0);
  if (c->state == CIRCUIT_STATE_OPEN) {
    if (c->cpath) {
      assert(!c->n_crypto);
      assert(!c->p_crypto);
      assert(!c->n_digest);
      assert(!c->p_digest);
    } else {
      assert(c->n_crypto);
      assert(c->p_crypto);
      assert(c->n_digest);
      assert(c->p_digest);
    }
  }
  if (c->cpath) {
//XXX    assert_cpath_ok(c->cpath);
  }
  if (c->purpose == CIRCUIT_PURPOSE_REND_ESTABLISHED) {
    if (!c->marked_for_close) {
      assert(c->rend_splice);
      assert(c->rend_splice->rend_splice == c);
    }
    assert(c->rend_splice != c);
  } else {
    assert(!c->rend_splice);
  }
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
