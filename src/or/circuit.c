/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

extern or_options_t options; /* command-line and config-file options */

static void circuit_free_cpath_node(crypt_path_t *victim);
static circ_id_t get_unique_circ_id_by_conn(connection_t *conn, int circ_id_type);  

unsigned long stats_n_relay_cells_relayed = 0;
unsigned long stats_n_relay_cells_delivered = 0;

/********* START VARIABLES **********/

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

}

void circuit_remove(circuit_t *circ) {
  circuit_t *tmpcirc;

  assert(circ && global_circuitlist);

  if(global_circuitlist == circ) {
    global_circuitlist = global_circuitlist->next;
    return;
  }

  for(tmpcirc = global_circuitlist;tmpcirc->next;tmpcirc = tmpcirc->next) {
    if(tmpcirc->next == circ) {
      tmpcirc->next = circ->next;
      return;
    }
  }
}

circuit_t *circuit_new(circ_id_t p_circ_id, connection_t *p_conn) {
  circuit_t *circ; 

  circ = tor_malloc_zero(sizeof(circuit_t));

  circ->timestamp_created = time(NULL);

  circ->p_circ_id = p_circ_id;
  circ->p_conn = p_conn;

  circ->state = CIRCUIT_STATE_ONIONSKIN_PENDING;

  /* CircIDs */
  circ->p_circ_id = p_circ_id;
  /* circ->n_circ_id remains 0 because we haven't identified the next hop yet */

  circ->package_window = CIRCWINDOW_START;
  circ->deliver_window = CIRCWINDOW_START;

  circuit_add(circ);

  return circ;
}

void circuit_free(circuit_t *circ) {
  assert(circ);
  if (circ->n_crypto)
    crypto_free_cipher_env(circ->n_crypto);
  if (circ->p_crypto)
    crypto_free_cipher_env(circ->p_crypto);
  if(circ->build_state)
    tor_free(circ->build_state->chosen_exit);
  tor_free(circ->build_state);
  circuit_free_cpath(circ->cpath);
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
  if(victim->handshake_state)
    crypto_dh_free(victim->handshake_state);
  free(victim);
}

/* return 0 if can't get a unique circ_id. */
static circ_id_t get_unique_circ_id_by_conn(connection_t *conn, int circ_id_type) {
  circ_id_t test_circ_id;
  uint16_t high_bit;
  assert(conn && conn->type == CONN_TYPE_OR);

  high_bit = (circ_id_type == CIRC_ID_TYPE_HIGHER) ? 1<<15 : 0;
  do {
    /* Sequentially iterate over test_circ_id=1...1<<15-1 until we find an
     * circID such that (high_bit|test_circ_id) is not already used. */
    /* XXX Will loop forever if all circ_id's in our range are used.
     * This matters because it's an external DoS vulnerability. */
    test_circ_id = conn->next_circ_id++;
    if (test_circ_id == 0 || test_circ_id >= 1<<15) {
      test_circ_id = 1;
      conn->next_circ_id = 2;
    }
    test_circ_id |= high_bit;
  } while(circuit_get_by_circ_id_conn(test_circ_id, conn));
  return test_circ_id;
}

circuit_t *circuit_get_by_circ_id_conn(circ_id_t circ_id, connection_t *conn) {
  circuit_t *circ;
  connection_t *tmpconn;

  for(circ=global_circuitlist;circ;circ = circ->next) {
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

/* Find the newest circ that conn can use, preferably one which is
 * dirty and not too old.
 * If !conn, return newest.
 *
 * If must_be_open, ignore circs not in CIRCUIT_STATE_OPEN.
 */
circuit_t *circuit_get_newest(connection_t *conn, int must_be_open) {
  circuit_t *circ, *newest=NULL, *leastdirty=NULL;
  routerinfo_t *exitrouter;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if(!circ->cpath)
      continue; /* this circ doesn't start at us */
    if(must_be_open && (circ->state != CIRCUIT_STATE_OPEN || !circ->n_conn))
      continue; /* ignore non-open circs */
    if(conn) {
      if(circ->state == CIRCUIT_STATE_OPEN && circ->n_conn) /* open */
        exitrouter = router_get_by_addr_port(circ->cpath->prev->addr, circ->cpath->prev->port);
      else /* not open */
        exitrouter = router_get_by_nickname(circ->build_state->chosen_exit);
      if(!exitrouter || connection_ap_can_use_exit(conn, exitrouter) < 0) {
        /* can't exit from this router */
        continue;
      }
    }
    if(!newest || newest->timestamp_created < circ->timestamp_created) {
      assert(circ->n_circ_id);
      newest = circ;
    }
    if(conn && circ->timestamp_dirty &&
       (!leastdirty || leastdirty->timestamp_dirty < circ->timestamp_dirty)) {
      assert(circ->n_circ_id);
      leastdirty = circ;
    }
  }

  if(leastdirty &&
     leastdirty->timestamp_dirty+options.NewCircuitPeriod > time(NULL)) {
/*    log_fn(LOG_DEBUG,"Choosing in-use circuit %s:%d:%d.",
           leastdirty->n_conn->address, leastdirty->n_port, leastdirty->n_circ_id); */
    return leastdirty;
  }
  if(newest) {
/*    log_fn(LOG_DEBUG,"Choosing circuit %s:%d:%d.",
           newest->n_conn->address, newest->n_port, newest->n_circ_id); */
    return newest;
  }
  return NULL;
}

#define MIN_SECONDS_BEFORE_EXPIRING_CIRC 3
/* circuits that were born at the end of their second might be expired
 * after 3.1 seconds; circuits born at the beginning might be expired
 * after closer to 4 seconds.
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
       victim->timestamp_created + MIN_SECONDS_BEFORE_EXPIRING_CIRC+1 < now) {
      if(victim->n_conn)
        log_fn(LOG_INFO,"Abandoning circ %s:%d:%d (state %d:%s)",
               victim->n_conn->address, victim->n_port, victim->n_circ_id,
               victim->state, circuit_state_to_string[victim->state]);
      else
        log_fn(LOG_INFO,"Abandoning circ %d (state %d:%s)", victim->n_circ_id,
               victim->state, circuit_state_to_string[victim->state]);
      circuit_close(victim);
    }
  }
}

/* count the number of circs starting at us that aren't open */
int circuit_count_building(void) {
  circuit_t *circ;
  int num=0;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if(circ->cpath && circ->state != CIRCUIT_STATE_OPEN)
      num++;
  }
  return num;
}

int circuit_deliver_relay_cell(cell_t *cell, circuit_t *circ,
                               int cell_direction, crypt_path_t *layer_hint) {
  connection_t *conn=NULL;
  char recognized=0;
  char buf[1+CELL_PAYLOAD_SIZE];

  assert(cell && circ);
  assert(cell_direction == CELL_DIRECTION_OUT || cell_direction == CELL_DIRECTION_IN); 

  buf[0] = cell->length;
  memcpy(buf+1, cell->payload, CELL_PAYLOAD_SIZE);

  log_fn(LOG_DEBUG,"direction %d, streamid %d before crypt.", cell_direction, *(int*)(cell->payload+1));

  if(relay_crypt(circ, buf, 1+CELL_PAYLOAD_SIZE, cell_direction, &layer_hint, &recognized, &conn) < 0) {
    log_fn(LOG_WARN,"relay crypt failed. Dropping connection.");
    return -1;
  }

  cell->length = buf[0];
  memcpy(cell->payload, buf+1, CELL_PAYLOAD_SIZE);

  if(recognized) {
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
  if(cell_direction == CELL_DIRECTION_OUT)
    conn = circ->n_conn;
  else
    conn = circ->p_conn;

  if(!conn) {
    log_fn(LOG_INFO,"Didn't recognize cell (%d), but circ stops here! Dropping.",
           *(int *)(cell->payload+1));
    return 0;
  }

  log_fn(LOG_DEBUG,"Passing on unrecognized cell.");
  ++stats_n_relay_cells_relayed;
  connection_or_write_cell_to_buf(cell, conn);
  return 0;
}

int relay_crypt(circuit_t *circ, char *in, int inlen, char cell_direction,
                crypt_path_t **layer_hint, char *recognized, connection_t **conn) {
  crypt_path_t *thishop;
  char out[256];

  assert(circ && in && recognized && conn);

  assert(inlen < 256);

  if(cell_direction == CELL_DIRECTION_IN) { 
    if(circ->cpath) { /* we're at the beginning of the circuit. We'll want to do layered crypts. */
      thishop = circ->cpath;
      if(thishop->state != CPATH_STATE_OPEN) {
        log_fn(LOG_WARN,"Relay cell before first created cell?");
        return -1;
      }
      do { /* Remember: cpath is in forward order, that is, first hop first. */
        assert(thishop);

        log_fn(LOG_DEBUG,"before decrypt: %d",*(int*)(in+2));
        /* decrypt */
        if(crypto_cipher_decrypt(thishop->b_crypto, in, inlen, out)) {
          log_fn(LOG_WARN,"Error performing onion decryption: %s", crypto_perror());
          return -1;
        }
        memcpy(in,out,inlen);
        log_fn(LOG_DEBUG,"after decrypt: %d",*(int*)(in+2));

        if( (*recognized = relay_check_recognized(circ, cell_direction, in+2, conn))) {
          *layer_hint = thishop;
          return 0;
        }

        thishop = thishop->next;
      } while(thishop != circ->cpath && thishop->state == CPATH_STATE_OPEN);
      log_fn(LOG_INFO,"in-cell at OP not recognized. Dropping.");
      return 0;
    } else { /* we're in the middle. Just one crypt. */

      log_fn(LOG_DEBUG,"before encrypt: %d",*(int*)(in+2));
      if(crypto_cipher_encrypt(circ->p_crypto, in, inlen, out)) {
        log_fn(LOG_WARN,"Onion encryption failed for circID %u: %s",
               circ->p_circ_id, crypto_perror());
        return -1;
      }
      memcpy(in,out,inlen);
      log_fn(LOG_DEBUG,"after encrypt: %d",*(int*)(in+2));

      log_fn(LOG_DEBUG,"Skipping recognized check, because we're not the OP.");
      /* don't check for recognized. only the OP can recognize a stream on the way back. */

    }
  } else if(cell_direction == CELL_DIRECTION_OUT) { 
    if(circ->cpath) { /* we're at the beginning of the circuit. We'll want to do layered crypts. */

      thishop = *layer_hint; /* we already know which layer, from when we package_raw_inbuf'ed */
      /* moving from last to first hop */
      do {
        assert(thishop);

        log_fn(LOG_DEBUG,"before encrypt: %d",*(int*)(in+2));
        if(crypto_cipher_encrypt(thishop->f_crypto, in, inlen, out)) {
          log_fn(LOG_WARN,"Error performing encryption: %s", crypto_perror());
          return -1;
        }
        memcpy(in,out,inlen);
        log_fn(LOG_DEBUG,"after encrypt: %d",*(int*)(in+2));

        thishop = thishop->prev;
      } while(thishop != circ->cpath->prev);
    } else { /* we're in the middle. Just one crypt. */

      if(crypto_cipher_decrypt(circ->n_crypto,in, inlen, out)) {
        log_fn(LOG_WARN,"Decryption failed for circID %u: %s",
               circ->n_circ_id, crypto_perror());
        return -1;
      }
      memcpy(in,out,inlen);

      if( (*recognized = relay_check_recognized(circ, cell_direction, in+2, conn)))
        return 0;

    }
  } else {
    log_fn(LOG_ERR,"unknown cell direction %d.", cell_direction);
    assert(0);
  }

  return 0;
}

int relay_check_recognized(circuit_t *circ, int cell_direction, char *stream, connection_t **conn) {
/* FIXME can optimize by passing thishop in */
  connection_t *tmpconn;

  if(!memcmp(stream,ZERO_STREAM,STREAM_ID_SIZE)) {
    log_fn(LOG_DEBUG,"It's the zero stream. Recognized.");
    return 1; /* the zero stream is always recognized */
  }
  log_fn(LOG_DEBUG,"not the zero stream.");

  if(cell_direction == CELL_DIRECTION_OUT)
    tmpconn = circ->n_streams;
  else
    tmpconn = circ->p_streams;

  if(!tmpconn) {
    log_fn(LOG_DEBUG,"No conns. Not recognized.");
    return 0;
  }

  for( ; tmpconn; tmpconn=tmpconn->next_stream) {
    if(!memcmp(stream,tmpconn->stream_id, STREAM_ID_SIZE)) {
      log_fn(LOG_DEBUG,"recognized stream %d.", *(int*)stream);
      *conn = tmpconn;
      return 1;
    }
    log_fn(LOG_DEBUG,"considered stream %d, not it.",*(int*)tmpconn->stream_id);
  }

  log_fn(LOG_DEBUG,"Didn't recognize on this iteration of decryption.");
  return 0;

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

int circuit_consider_sending_sendme(circuit_t *circ, int edge_type, crypt_path_t *layer_hint) {
  cell_t cell;

  assert(circ);

  memset(&cell, 0, sizeof(cell_t));
  cell.command = CELL_RELAY;
  SET_CELL_RELAY_COMMAND(cell, RELAY_COMMAND_SENDME);
  SET_CELL_STREAM_ID(cell, ZERO_STREAM);

  cell.length = RELAY_HEADER_SIZE;
  if(edge_type == EDGE_AP) { /* i'm the AP */
    cell.circ_id = circ->n_circ_id;
    while(layer_hint->deliver_window < CIRCWINDOW_START-CIRCWINDOW_INCREMENT) {
      log_fn(LOG_DEBUG,"deliver_window %d, Queueing sendme forward.", layer_hint->deliver_window);
      layer_hint->deliver_window += CIRCWINDOW_INCREMENT;
      if(circuit_deliver_relay_cell(&cell, circ, CELL_DIRECTION_OUT, layer_hint) < 0) {
        log_fn(LOG_WARN,"At AP: circuit_deliver_relay_cell failed.");
        return -1;
      }
    }
  } else if(edge_type == EDGE_EXIT) { /* i'm the exit */
    cell.circ_id = circ->p_circ_id;
    while(circ->deliver_window < CIRCWINDOW_START-CIRCWINDOW_INCREMENT) {
      log_fn(LOG_DEBUG,"deliver_window %d, Queueing sendme back.", circ->deliver_window);
      circ->deliver_window += CIRCWINDOW_INCREMENT;
      if(circuit_deliver_relay_cell(&cell, circ, CELL_DIRECTION_IN, layer_hint) < 0) {
        log_fn(LOG_WARN,"At exit: circuit_deliver_relay_cell failed.");
        return -1;
      }
    }
  }
  return 0;
}

void circuit_close(circuit_t *circ) {
  connection_t *conn;

  assert(circ);
  circuit_remove(circ);
  if(circ->state == CIRCUIT_STATE_ONIONSKIN_PENDING) {
    onion_pending_remove(circ);
  }

  if(circ->n_conn)
    connection_send_destroy(circ->n_circ_id, circ->n_conn);
  for(conn=circ->n_streams; conn; conn=conn->next_stream) {
    connection_send_destroy(circ->n_circ_id, conn); 
  }
  if(circ->p_conn)
    connection_send_destroy(circ->n_circ_id, circ->p_conn);
  for(conn=circ->p_streams; conn; conn=conn->next_stream) {
    connection_send_destroy(circ->p_circ_id, conn); 
  }
  if (circ->state != CIRCUIT_STATE_OPEN && circ->cpath) {
    /* If we never built the circuit, note it as a failure. */
    circuit_increment_failure_count();
  }
  circuit_free(circ);
}

void circuit_about_to_close_connection(connection_t *conn) {
  /* send destroys for all circuits using conn */
  /* currently, we assume it's too late to flush conn's buf here.
   * down the road, maybe we'll consider that eof doesn't mean can't-write
   */
  circuit_t *circ;
  connection_t *prevconn;

  switch(conn->type) {
    case CONN_TYPE_OR:
      /* We must close all the circuits on it. */
      while((circ = circuit_get_by_conn(conn))) {
        if(circ->n_conn == conn) /* it's closing in front of us */
          circ->n_conn = NULL;
        if(circ->p_conn == conn) /* it's closing behind us */
          circ->p_conn = NULL;
        circuit_close(circ);
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
        log_fn(LOG_INFO,"Edge connection hasn't sent end yet? Bug.");
        connection_edge_end(conn, END_STREAM_REASON_MISC, conn->cpath_layer);
      }

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
  } /* end switch */
}

void circuit_dump_details(int severity, circuit_t *circ, int poll_index,
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
      log(severity,"hop: state %d, addr %d, port %d", hop->state, hop->addr, hop->port);
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

void circuit_expire_unused_circuits(void) {
  circuit_t *circ, *tmpcirc;
  time_t now = time(NULL);

  circ = global_circuitlist;
  while(circ) {
    tmpcirc = circ;
    circ = circ->next;
    if(tmpcirc->timestamp_dirty &&
       tmpcirc->timestamp_dirty + options.NewCircuitPeriod < now &&
       !tmpcirc->p_conn && !tmpcirc->p_streams) {
      log_fn(LOG_DEBUG,"Closing n_circ_id %d",tmpcirc->n_circ_id);
      circuit_close(tmpcirc);
    }
  }
}

/* Number of consecutive failures so far; should only be touched by
 * circuit_launch_new and circuit_*_failure_count.
 */
static int n_circuit_failures = 0; 

/* Return -1 if you aren't going to try to make a circuit, 0 if you did try. */
int circuit_launch_new(void) {

  if(!options.SocksPort) /* we're not an application proxy. no need for circuits. */
    return -1;

  if(n_circuit_failures > 5) /* too many failed circs in a row. don't try. */
    return -1;

  /* try a circ. if it fails, circuit_close will increment n_circuit_failures */
  circuit_establish_circuit();

  return 0;
}

void circuit_increment_failure_count(void) {
  ++n_circuit_failures;
}

void circuit_reset_failure_count(void) {
  n_circuit_failures = 0;
}

int circuit_establish_circuit(void) {
  routerinfo_t *firsthop;
  connection_t *n_conn;
  circuit_t *circ;

  circ = circuit_new(0, NULL); /* sets circ->p_circ_id and circ->p_conn */
  circ->state = CIRCUIT_STATE_OR_WAIT;
  circ->build_state = onion_new_cpath_build_state();

  if (! circ->build_state) {
    log_fn(LOG_INFO,"Generating cpath length failed.");
    circuit_close(circ);
    return -1;
  }

  onion_extend_cpath(&circ->cpath, circ->build_state, &firsthop);
  if(!circ->cpath) {
    log_fn(LOG_INFO,"Generating first cpath hop failed.");
    circuit_close(circ);
    return -1;
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
      circuit_close(circ);
      return -1;
    }

    if(!n_conn) { /* launch the connection */
      n_conn = connection_or_connect(firsthop);
      if(!n_conn) { /* connect failed, forget the whole thing */
        log_fn(LOG_INFO,"connect to firsthop failed. Closing.");
        circuit_close(circ);
        return -1;
      }
    }

    log_fn(LOG_DEBUG,"connecting in progress (or finished). Good.");
    return 0; /* return success. The onion/circuit/etc will be taken care of automatically
               * (may already have been) whenever n_conn reaches OR_CONN_STATE_OPEN.
               */ 
  } else { /* it (or a twin) is already open. use it. */
    circ->n_addr = n_conn->addr;
    circ->n_port = n_conn->port;
    circ->n_conn = n_conn;
    log_fn(LOG_DEBUG,"Conn open. Delivering first onion skin.");
    if(circuit_send_next_onion_skin(circ) < 0) {
      log_fn(LOG_INFO,"circuit_send_next_onion_skin failed.");
      circuit_close(circ);
      return -1;
    }
  }
  return 0;
}

/* find circuits that are waiting on me, if any, and get them to send the onion */
void circuit_n_conn_open(connection_t *or_conn) {
  circuit_t *circ;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if(circ->cpath && circ->n_addr == or_conn->addr && circ->n_port == or_conn->port) {
      assert(circ->state == CIRCUIT_STATE_OR_WAIT);
      log_fn(LOG_DEBUG,"Found circ %d, sending onion skin.", circ->n_circ_id);
      circ->n_conn = or_conn;
      if(circuit_send_next_onion_skin(circ) < 0) {
        log_fn(LOG_INFO,"send_next_onion_skin failed; circuit marked for closing.");
        circuit_close(circ);
        continue;
          /* XXX could this be bad, eg if next_onion_skin failed because conn died? */
      }
    }
  }
}

int circuit_send_next_onion_skin(circuit_t *circ) {
  cell_t cell;
  crypt_path_t *hop;
  routerinfo_t *router;
  int r;
  int circ_id_type;

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
    cell.length = DH_ONIONSKIN_LEN;

    if(onion_skin_create(circ->n_conn->onion_pkey, &(circ->cpath->handshake_state), cell.payload) < 0) {
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
      /* Tell any AP connections that have been waiting for a new
       * circuit that one is ready. */
      connection_ap_attach_pending();
      return 0;
    } else if (r<0) {
      log_fn(LOG_INFO,"Unable to extend circuit path.");
      return -1;
    }
    hop = circ->cpath->prev;

    memset(&cell, 0, sizeof(cell_t));
    cell.command = CELL_RELAY; 
    cell.circ_id = circ->n_circ_id;
    SET_CELL_RELAY_COMMAND(cell, RELAY_COMMAND_EXTEND);
    SET_CELL_STREAM_ID(cell, ZERO_STREAM);

    cell.length = RELAY_HEADER_SIZE + 6 + DH_ONIONSKIN_LEN;
    *(uint32_t*)(cell.payload+RELAY_HEADER_SIZE) = htonl(hop->addr);
    *(uint16_t*)(cell.payload+RELAY_HEADER_SIZE+4) = htons(hop->port);
    if(onion_skin_create(router->onion_pkey, &(hop->handshake_state), cell.payload+RELAY_HEADER_SIZE+6) < 0) {
      log_fn(LOG_WARN,"onion_skin_create failed.");
      return -1;
    }

    log_fn(LOG_DEBUG,"Sending extend relay cell.");
    /* send it to hop->prev, because it will transfer it to a create cell and then send to hop */
    if(circuit_deliver_relay_cell(&cell, circ, CELL_DIRECTION_OUT, hop->prev) < 0) {
      log_fn(LOG_WARN,"failed to deliver extend cell. Closing.");
      return -1;
    }
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

  circ->n_addr = ntohl(*(uint32_t*)(cell->payload+RELAY_HEADER_SIZE));
  circ->n_port = ntohs(*(uint16_t*)(cell->payload+RELAY_HEADER_SIZE+4));

  n_conn = connection_twin_get_by_addr_port(circ->n_addr,circ->n_port);
  if(!n_conn || n_conn->type != CONN_TYPE_OR) {
    /* i've disabled making connections through OPs, but it's definitely
     * possible here. I'm not sure if it would be a bug or a feature. -RD
     */
    /* note also that this will close circuits where the onion has the same
     * router twice in a row in the path. i think that's ok. -RD
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

  log_fn(LOG_DEBUG,"circ_id_type = %u.",circ_id_type);
  circ->n_circ_id = get_unique_circ_id_by_conn(circ->n_conn, circ_id_type);
  if(!circ->n_circ_id) {
    log_fn(LOG_WARN,"failed to get unique circID.");
    return -1;
  }
  log_fn(LOG_DEBUG,"Chosen circID %u.",circ->n_circ_id);

  memset(&newcell, 0, sizeof(cell_t));
  newcell.command = CELL_CREATE;
  newcell.circ_id = circ->n_circ_id;
  newcell.length = DH_ONIONSKIN_LEN;

  memcpy(newcell.payload, cell->payload+RELAY_HEADER_SIZE+6, DH_ONIONSKIN_LEN);

  connection_or_write_cell_to_buf(&newcell, circ->n_conn);
  return 0;
}

int circuit_finish_handshake(circuit_t *circ, char *reply) {
  unsigned char iv[16];
  unsigned char keys[32];
  crypt_path_t *hop;

  memset(iv, 0, 16);

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

  if(onion_skin_client_handshake(hop->handshake_state, reply, keys, 32) < 0) {
    log_fn(LOG_WARN,"onion_skin_client_handshake failed.");
    return -1;
  }

  crypto_dh_free(hop->handshake_state); /* don't need it anymore */
  hop->handshake_state = NULL;

  log_fn(LOG_DEBUG,"hop %d init cipher forward %d, backward %d.", (uint32_t)hop, *(uint32_t*)keys, *(uint32_t*)(keys+16));
  if (!(hop->f_crypto =
        crypto_create_init_cipher(CIRCUIT_CIPHER,keys,iv,1))) {
    log(LOG_WARN,"forward cipher initialization failed.");
    return -1;
  }

  if (!(hop->b_crypto =
        crypto_create_init_cipher(CIRCUIT_CIPHER,keys+16,iv,0))) {
    log(LOG_WARN,"backward cipher initialization failed.");
    return -1;
  }

  hop->state = CPATH_STATE_OPEN;
  log_fn(LOG_INFO,"finished");
  return 0;
}

int circuit_truncated(circuit_t *circ, crypt_path_t *layer) {
  crypt_path_t *victim;
  connection_t *stream;

  assert(circ);
  assert(layer);

  while(layer->next != circ->cpath) {
    /* we need to clear out layer->next */
    victim = layer->next;
    log_fn(LOG_DEBUG, "Killing a layer of the cpath.");

    for(stream = circ->p_streams; stream; stream=stream->next_stream) {
      if(stream->cpath_layer == victim) {
        log_fn(LOG_INFO, "Marking stream %d for close.", *(int*)stream->stream_id);
        /* no need to send 'end' relay cells,
         * because the other side's already dead
         */
        stream->marked_for_close = 1;
        stream->has_sent_end = 1;
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
  assert(cp->addr);
  assert(cp->port);
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

  assert(c->n_addr);
  assert(c->n_port);
  assert(c->n_conn);
  assert(c->n_conn->type == CONN_TYPE_OR);
  if (c->p_conn)
    assert(c->p_conn->type == CONN_TYPE_OR);
  for (conn = c->p_streams; conn; conn = conn->next_stream)
    assert(c->p_conn->type == CONN_TYPE_EXIT);
  for (conn = c->n_streams; conn; conn = conn->next_stream)
    assert(conn->type == CONN_TYPE_EXIT);

  assert(c->deliver_window >= 0);
  assert(c->package_window >= 0);
  if (c->state == CIRCUIT_STATE_OPEN) {
    if (c->cpath) {
      assert(!c->n_crypto);
      assert(!c->p_crypto);
    } else {
      assert(c->n_crypto);
      assert(c->p_crypto);
    }
  }
  if (c->cpath) {
    assert_cpath_ok(c->cpath);
  }
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
