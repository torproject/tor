/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

extern or_options_t options; /* command-line and config-file options */

/********* START VARIABLES **********/

static circuit_t *global_circuitlist=NULL;

char *circuit_state_to_string[] = {
  "receiving the onion",    /* 0 */
  "waiting to process create", /* 1 */
  "connecting to firsthop", /* 2 */
  "open"                    /* 3 */
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

circuit_t *circuit_new(aci_t p_aci, connection_t *p_conn) {
  circuit_t *circ; 
  struct timeval now;

  my_gettimeofday(&now);

  circ = (circuit_t *)tor_malloc(sizeof(circuit_t));
  memset(circ,0,sizeof(circuit_t)); /* zero it out */

  circ->timestamp_created = now.tv_sec;

  circ->p_aci = p_aci;
  circ->p_conn = p_conn;

  circ->state = CIRCUIT_STATE_ONIONSKIN_PENDING;

  /* ACIs */
  circ->p_aci = p_aci;
  /* circ->n_aci remains 0 because we haven't identified the next hop yet */

  circ->package_window = CIRCWINDOW_START;
  circ->deliver_window = CIRCWINDOW_START;

  circuit_add(circ);

  return circ;
}

void circuit_free(circuit_t *circ) {
  struct relay_queue_t *tmpd;
  
  if (circ->n_crypto)
    crypto_free_cipher_env(circ->n_crypto);
  if (circ->p_crypto)
    crypto_free_cipher_env(circ->p_crypto);

  circuit_free_cpath(circ->cpath);
  while(circ->relay_queue) {
    tmpd = circ->relay_queue;
    circ->relay_queue = tmpd->next;
    free(tmpd->cell);
    free(tmpd);
  }

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

void circuit_free_cpath_node(crypt_path_t *victim) {
  if(victim->f_crypto)
    crypto_free_cipher_env(victim->f_crypto);
  if(victim->b_crypto)
    crypto_free_cipher_env(victim->b_crypto);
  if(victim->handshake_state)
    crypto_dh_free(victim->handshake_state);
  free(victim);
}

/* return 0 if can't get a unique aci. */
aci_t get_unique_aci_by_addr_port(uint32_t addr, uint16_t port, int aci_type) {
  aci_t test_aci;
  connection_t *conn;

try_again:
  log(LOG_DEBUG,"get_unique_aci_by_addr_port() trying to get a unique aci");

  if (CRYPTO_PSEUDO_RAND_INT(test_aci))
    return -1;

  if(aci_type == ACI_TYPE_LOWER && test_aci >= (1<<15))
    test_aci -= (1<<15);
  if(aci_type == ACI_TYPE_HIGHER && test_aci < (1<<15))
    test_aci += (1<<15);
  /* if aci_type == ACI_BOTH, don't filter any of it */

  if(test_aci == 0)
    goto try_again;

  conn = connection_exact_get_by_addr_port(addr,port);
  if(!conn) /* there can't be a conflict -- no connection of that sort yet */
    return test_aci;

  if(circuit_get_by_aci_conn(test_aci, conn))
    goto try_again;

  return test_aci;
}

circuit_t *circuit_enumerate_by_naddr_nport(circuit_t *circ, uint32_t naddr, uint16_t nport) {

  if(!circ) /* use circ if it's defined, else start from the beginning */
    circ = global_circuitlist; 
  else
    circ = circ->next;

  for( ; circ; circ = circ->next) {
    if(circ->n_addr == naddr && circ->n_port == nport)
       return circ;
  }
  return NULL;
}

circuit_t *circuit_get_by_aci_conn(aci_t aci, connection_t *conn) {
  circuit_t *circ;
  connection_t *tmpconn;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if(circ->p_aci == aci) {
      if(circ->p_conn == conn)
        return circ;
      for(tmpconn = circ->p_streams; tmpconn; tmpconn = tmpconn->next_stream) {
        if(tmpconn == conn)
          return circ;
      }
    }
    if(circ->n_aci == aci) {
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

circuit_t *circuit_get_newest_ap(void) {
  circuit_t *circ, *bestcirc=NULL;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if(circ->cpath && circ->state == CIRCUIT_STATE_OPEN && (!bestcirc ||
      bestcirc->timestamp_created < circ->timestamp_created)) {
      log(LOG_DEBUG,"circuit_get_newest_ap(): Choosing n_aci %d.", circ->n_aci);
      assert(circ->n_aci);
      bestcirc = circ;
    }
  }
  return bestcirc;
}

int circuit_deliver_relay_cell_from_edge(cell_t *cell, circuit_t *circ,
                                         char edge_type, crypt_path_t *layer_hint) {
  int cell_direction;
  static int numsent_ap=0, numsent_exit=0;

  log(LOG_DEBUG,"circuit_deliver_relay_cell_from_edge(): called, edge_type %d.", edge_type);

  if(edge_type == EDGE_AP) { /* i'm the AP */
    cell_direction = CELL_DIRECTION_OUT;
    numsent_ap++;
    log(LOG_DEBUG,"circuit_deliver_relay_cell_from_edge(): now sent %d relay cells from ap", numsent_ap);
  } else { /* i'm the exit */
    cell_direction = CELL_DIRECTION_IN;
    numsent_exit++;
    log(LOG_DEBUG,"circuit_deliver_relay_cell_from_edge(): now sent %d relay cells from exit", numsent_exit);
  }

  if(circuit_deliver_relay_cell(cell, circ, cell_direction, layer_hint) < 0) {
    return -1;
  }

  return 0;
}

int circuit_deliver_relay_cell(cell_t *cell, circuit_t *circ,
                               int cell_direction, crypt_path_t *layer_hint) {
  connection_t *conn=NULL;
  char recognized=0;
  char buf[256];

  assert(cell && circ);
  assert(cell_direction == CELL_DIRECTION_OUT || cell_direction == CELL_DIRECTION_IN); 

  buf[0] = cell->length;
  memcpy(buf+1, cell->payload, CELL_PAYLOAD_SIZE);

  log(LOG_DEBUG,"circuit_deliver_relay_cell(): direction %d, streamid %d before crypt.", cell_direction, *(int*)(cell->payload+1));

  if(relay_crypt(circ, buf, 1+CELL_PAYLOAD_SIZE, cell_direction, &layer_hint, &recognized, &conn) < 0) {
    log(LOG_DEBUG,"circuit_deliver_relay_cell(): relay crypt failed. Dropping connection.");
    return -1;
  }

  cell->length = buf[0];
  memcpy(cell->payload, buf+1, CELL_PAYLOAD_SIZE);

  if(recognized) {
    if(cell_direction == CELL_DIRECTION_OUT) {
      log(LOG_DEBUG,"circuit_deliver_relay_cell(): Sending to exit.");
      return connection_edge_process_relay_cell(cell, circ, conn, EDGE_EXIT, NULL);
    }
    if(cell_direction == CELL_DIRECTION_IN) {
      log(LOG_DEBUG,"circuit_deliver_relay_cell(): Sending to AP.");
      return connection_edge_process_relay_cell(cell, circ, conn, EDGE_AP, layer_hint);
    }
  }

  /* not recognized. pass it on. */
  if(cell_direction == CELL_DIRECTION_OUT)
    conn = circ->n_conn;
  else
    conn = circ->p_conn;

  if(!conn) { //|| !connection_speaks_cells(conn)) {
    log(LOG_INFO,"circuit_deliver_relay_cell(): Didn't recognize cell (%d), but circ stops here! Dropping.", *(int *)(cell->payload+1));
    return 0;
  }

  log(LOG_DEBUG,"circuit_deliver_relay_cell(): Passing on unrecognized cell.");
  return connection_write_cell_to_buf(cell, conn);
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
        log(LOG_INFO,"relay_crypt(): Relay cell before first created cell?");
        return -1;
      }
      do { /* Remember: cpath is in forward order, that is, first hop first. */
        assert(thishop);

        log(LOG_DEBUG,"relay_crypt(): before decrypt: %d",*(int*)(in+2));
        /* decrypt */
        if(crypto_cipher_decrypt(thishop->b_crypto, in, inlen, out)) {
          log(LOG_ERR,"Error performing decryption:%s",crypto_perror());
          return -1;
        }
        memcpy(in,out,inlen);
        log(LOG_DEBUG,"relay_crypt(): after decrypt: %d",*(int*)(in+2));

        if( (*recognized = relay_check_recognized(circ, cell_direction, in+2, conn))) {
          *layer_hint = thishop;
          return 0;
        }

        thishop = thishop->next;
      } while(thishop != circ->cpath && thishop->state == CPATH_STATE_OPEN);
      log(LOG_INFO,"relay_crypt(): in-cell at OP not recognized. Dropping.");
      return 0;
    } else { /* we're in the middle. Just one crypt. */

      log(LOG_DEBUG,"relay_crypt(): before encrypt: %d",*(int*)(in+2));
      if(crypto_cipher_encrypt(circ->p_crypto, in, inlen, out)) {
        log(LOG_ERR,"circuit_encrypt(): Encryption failed for ACI : %u (%s).",
            circ->p_aci, crypto_perror());
        return -1;
      }
      memcpy(in,out,inlen);
      log(LOG_DEBUG,"relay_crypt(): after encrypt: %d",*(int*)(in+2));

      log(LOG_DEBUG,"circuit_encrypt(): Skipping recognized check, because we're not the OP.");
      /* don't check for recognized. only the OP can recognize a stream on the way back. */

    }
  } else if(cell_direction == CELL_DIRECTION_OUT) { 
    if(circ->cpath) { /* we're at the beginning of the circuit. We'll want to do layered crypts. */

      thishop = *layer_hint; /* we already know which layer, from when we package_raw_inbuf'ed */
      /* moving from last to first hop */
      do {
        assert(thishop);

        log(LOG_DEBUG,"relay_crypt(): before encrypt: %d",*(int*)(in+2));
        if(crypto_cipher_encrypt(thishop->f_crypto, in, inlen, out)) {
          log(LOG_ERR,"Error performing encryption:%s",crypto_perror());
          return -1;
        }
        memcpy(in,out,inlen);
        log(LOG_DEBUG,"relay_crypt(): after encrypt: %d",*(int*)(in+2));

        thishop = thishop->prev;
      } while(thishop != circ->cpath->prev);
    } else { /* we're in the middle. Just one crypt. */

      if(crypto_cipher_decrypt(circ->n_crypto,in, inlen, out)) {
        log(LOG_ERR,"circuit_crypt(): Decryption failed for ACI : %u (%s).",
            circ->n_aci, crypto_perror());
        return -1;
      }
      memcpy(in,out,inlen);

      if( (*recognized = relay_check_recognized(circ, cell_direction, in+2, conn)))
        return 0;

    }
  } else {
    log(LOG_ERR,"circuit_crypt(): unknown cell direction %d.", cell_direction);
    assert(0);
  }

  return 0;
}

int relay_check_recognized(circuit_t *circ, int cell_direction, char *stream, connection_t **conn) {
/* FIXME can optimize by passing thishop in */
  connection_t *tmpconn;

  if(!memcmp(stream,ZERO_STREAM,STREAM_ID_SIZE)) {
    log(LOG_DEBUG,"relay_check_recognized(): It's the zero stream. Recognized.");
    return 1; /* the zero stream is always recognized */
  }
  log(LOG_DEBUG,"relay_check_recognized(): not the zero stream.");

  if(cell_direction == CELL_DIRECTION_OUT)
    tmpconn = circ->n_streams;
  else
    tmpconn = circ->p_streams;

  if(!tmpconn) {
    log(LOG_DEBUG,"relay_check_recognized(): No conns. Not recognized.");
    return 0;
  }

  for( ; tmpconn; tmpconn=tmpconn->next_stream) {
    if(!memcmp(stream,tmpconn->stream_id, STREAM_ID_SIZE)) {
      log(LOG_DEBUG,"relay_check_recognized(): recognized stream %d.", *(int*)stream);
      *conn = tmpconn;
      return 1;
    }
    log(LOG_DEBUG,"relay_check_recognized(): considered stream %d, not it.",*(int*)tmpconn->stream_id);
  }

  log(LOG_DEBUG,"relay_check_recognized(): Didn't recognize. Giving up.");
  return 0;

}

void circuit_resume_edge_reading(circuit_t *circ, int edge_type, crypt_path_t *layer_hint) {
  connection_t *conn;

  assert(edge_type == EDGE_EXIT || edge_type == EDGE_AP);

  log(LOG_DEBUG,"circuit_resume_edge_reading(): resuming");

  if(edge_type == EDGE_EXIT)
    conn = circ->n_streams;
  else
    conn = circ->p_streams;

  for( ; conn; conn=conn->next_stream) {
    if((edge_type == EDGE_EXIT && conn->package_window > 0) ||
       (edge_type == EDGE_AP   && conn->package_window > 0 && conn->cpath_layer == layer_hint)) {
      connection_start_reading(conn);
      connection_package_raw_inbuf(conn); /* handle whatever might still be on the inbuf */
    }
  }
  circuit_consider_stop_edge_reading(circ, edge_type, layer_hint);
}

/* returns 1 if the window is empty, else 0. If it's empty, tell edge conns to stop reading. */
int circuit_consider_stop_edge_reading(circuit_t *circ, int edge_type, crypt_path_t *layer_hint) {
  connection_t *conn = NULL;

  assert(edge_type == EDGE_EXIT || edge_type == EDGE_AP);
  assert(edge_type == EDGE_EXIT || layer_hint);

  log(LOG_DEBUG,"circuit_consider_stop_edge_reading(): considering");
  if(edge_type == EDGE_EXIT && circ->package_window <= 0)
    conn = circ->n_streams;
  else if(edge_type == EDGE_AP && layer_hint->package_window <= 0)
    conn = circ->p_streams;
  else
    return 0;

  for( ; conn; conn=conn->next_stream)
    if(!layer_hint || conn->cpath_layer == layer_hint)
      connection_stop_reading(conn);

  log(LOG_DEBUG,"circuit_consider_stop_edge_reading(): yes. stopped.");
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
    cell.aci = circ->n_aci;
    while(layer_hint->deliver_window < CIRCWINDOW_START-CIRCWINDOW_INCREMENT) {
      log(LOG_DEBUG,"circuit_consider_sending_sendme(): deliver_window %d, Queueing sendme forward.", layer_hint->deliver_window);
      layer_hint->deliver_window += CIRCWINDOW_INCREMENT;
      if(circuit_deliver_relay_cell_from_edge(&cell, circ, edge_type, layer_hint) < 0) {
        return -1;
      }
    }
  } else if(edge_type == EDGE_EXIT) { /* i'm the exit */
    cell.aci = circ->p_aci;
    while(circ->deliver_window < CIRCWINDOW_START-CIRCWINDOW_INCREMENT) {
      log(LOG_DEBUG,"circuit_consider_sending_sendme(): deliver_window %d, Queueing sendme back.", circ->deliver_window);
      circ->deliver_window += CIRCWINDOW_INCREMENT;
      if(circuit_deliver_relay_cell_from_edge(&cell, circ, edge_type, layer_hint) < 0) {
        return -1;
      }
    }
  }
  return 0;
}

void circuit_close(circuit_t *circ) {
  connection_t *conn;
  circuit_t *youngest=NULL;

  assert(circ);
  if(options.APPort) {
    youngest = circuit_get_newest_ap();
    log(LOG_DEBUG,"circuit_close(): youngest %d, circ %d.",youngest,circ);
  }
  circuit_remove(circ);
  if(circ->n_conn)
    connection_send_destroy(circ->n_aci, circ->n_conn);
  for(conn=circ->n_streams; conn; conn=conn->next_stream) {
    connection_send_destroy(circ->n_aci, conn); 
  }
  if(circ->p_conn)
    connection_send_destroy(circ->n_aci, circ->p_conn);
  for(conn=circ->p_streams; conn; conn=conn->next_stream) {
    connection_send_destroy(circ->p_aci, conn); 
  }
  if(options.APPort && youngest == circ) { /* check this after we've sent the destroys, to reduce races */
    /* our current circuit just died. Launch another one pronto. */
    log(LOG_INFO,"circuit_close(): Youngest circuit dying. Launching a replacement.");
    circuit_launch_new(1);
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

  if(!connection_speaks_cells(conn)) {
    /* it's an edge conn. need to remove it from the linked list of
     * conn's for this circuit. Send an 'end' relay command.
     * But don't kill the circuit.
     */

    circ = circuit_get_by_conn(conn);
    if(!circ)
      return;

    if(conn == circ->p_streams) {
      circ->p_streams = conn->next_stream;
      goto send_end;
    }
    if(conn == circ->n_streams) {
      circ->n_streams = conn->next_stream;
      goto send_end;
    }
    for(prevconn = circ->p_streams; prevconn && prevconn->next_stream && prevconn->next_stream != conn; prevconn = prevconn->next_stream) ;
    if(prevconn && prevconn->next_stream) {
      prevconn->next_stream = conn->next_stream;
      goto send_end;
    }
    for(prevconn = circ->n_streams; prevconn && prevconn->next_stream && prevconn->next_stream != conn; prevconn = prevconn->next_stream) ;
    if(prevconn && prevconn->next_stream) {
      prevconn->next_stream = conn->next_stream;
      goto send_end;
    }
    log(LOG_ERR,"circuit_about_to_close_connection(): edge conn not in circuit's list?");
    assert(0); /* should never get here */
send_end:
    if(connection_edge_send_command(conn, circ, RELAY_COMMAND_END) < 0) {
      log(LOG_DEBUG,"circuit_about_to_close_connection(): sending end failed. Closing.");
      circuit_close(circ);
    }
    return;
  }

  /* this connection speaks cells. We must close all the circuits on it. */
  while((circ = circuit_get_by_conn(conn))) {
    if(circ->n_conn == conn) /* it's closing in front of us */
      circ->n_conn = NULL;
    if(circ->p_conn == conn) /* it's closing behind us */
      circ->p_conn = NULL;
    circuit_close(circ);
  }  
}

/* FIXME this now leaves some out */
void circuit_dump_by_conn(connection_t *conn) {
  circuit_t *circ;
  connection_t *tmpconn;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if(circ->p_conn == conn)
      printf("Conn %d has App-ward circuit:  aci %d (other side %d), state %d (%s)\n",
        conn->poll_index, circ->p_aci, circ->n_aci, circ->state, circuit_state_to_string[circ->state]);
    for(tmpconn=circ->p_streams; tmpconn; tmpconn=tmpconn->next_stream) {
      if(tmpconn == conn) {
        printf("Conn %d has App-ward circuit:  aci %d (other side %d), state %d (%s)\n",
          conn->poll_index, circ->p_aci, circ->n_aci, circ->state, circuit_state_to_string[circ->state]);
      }
    }
    if(circ->n_conn == conn)
      printf("Conn %d has Exit-ward circuit: aci %d (other side %d), state %d (%s)\n",
        conn->poll_index, circ->n_aci, circ->p_aci, circ->state, circuit_state_to_string[circ->state]);
    for(tmpconn=circ->n_streams; tmpconn; tmpconn=tmpconn->next_stream) {
      if(tmpconn == conn) {
        printf("Conn %d has Exit-ward circuit: aci %d (other side %d), state %d (%s)\n",
          conn->poll_index, circ->n_aci, circ->p_aci, circ->state, circuit_state_to_string[circ->state]);
      }
    }
  }
}

void circuit_expire_unused_circuits(void) {
  circuit_t *circ, *tmpcirc;
  circuit_t *youngest;

  youngest = circuit_get_newest_ap();

  circ = global_circuitlist;
  while(circ) {
    tmpcirc = circ;
    circ = circ->next;
    if(tmpcirc != youngest && !tmpcirc->p_conn && !tmpcirc->p_streams) {
      log(LOG_DEBUG,"circuit_expire_unused_circuits(): Closing n_aci %d",tmpcirc->n_aci);
      circuit_close(tmpcirc);
    }
  }
}

/* failure_status code: negative means reset failures to 0. Other values mean
 * add that value to the current number of failures, then if we don't have too
 * many failures on record, try to make a new circuit.
 */
void circuit_launch_new(int failure_status) {
  static int failures=0;

  if(!options.APPort) /* we're not an application proxy. no need for circuits. */
    return;

  if(failure_status == -1) { /* I was called because a circuit succeeded */
    failures = 0;
    return;
  }

  failures += failure_status;

retry_circuit:

  if(failures > 5) {
    log(LOG_INFO,"circuit_launch_new(): Giving up, %d failures.", failures);
    return;
  }

  if(circuit_establish_circuit() < 0) {
    failures++;
    goto retry_circuit;
  }

  failures = 0;
  return;
}

int circuit_establish_circuit(void) {
  routerinfo_t *firsthop;
  connection_t *n_conn;
  circuit_t *circ;

  circ = circuit_new(0, NULL); /* sets circ->p_aci and circ->p_conn */
  circ->state = CIRCUIT_STATE_OR_WAIT;
  circ->cpath = onion_generate_cpath(&firsthop);
  if(!circ->cpath) {
    log(LOG_DEBUG,"circuit_establish_circuit(): Generating cpath failed.");
    circuit_close(circ);
    return -1;
  }

  /* now see if we're already connected to the first OR in 'route' */

  log(LOG_DEBUG,"circuit_establish_circuit(): Looking for firsthop '%s:%u'",
      firsthop->address,firsthop->or_port);
  n_conn = connection_twin_get_by_addr_port(firsthop->addr,firsthop->or_port);
  if(!n_conn || n_conn->state != OR_CONN_STATE_OPEN) { /* not currently connected */
    circ->n_addr = firsthop->addr;
    circ->n_port = firsthop->or_port;
    if(options.OnionRouter) { /* we would be connected if he were up. but he's not. */
      log(LOG_DEBUG,"circuit_establish_circuit(): Route's firsthop isn't connected.");
      circuit_close(circ); 
      return -1;
    }

    if(!n_conn) { /* launch the connection */
      n_conn = connection_or_connect(firsthop);
      if(!n_conn) { /* connect failed, forget the whole thing */
        log(LOG_DEBUG,"circuit_establish_circuit(): connect to firsthop failed. Closing.");
        circuit_close(circ);
        return -1;
      }
    }

    log(LOG_DEBUG,"circuit_establish_circuit(): connecting in progress (or finished). Good.");
    return 0; /* return success. The onion/circuit/etc will be taken care of automatically
               * (may already have been) whenever n_conn reaches OR_CONN_STATE_OPEN.
               */ 
  } else { /* it (or a twin) is already open. use it. */
    circ->n_addr = n_conn->addr;
    circ->n_port = n_conn->port;
    circ->n_conn = n_conn;
    log(LOG_DEBUG,"circuit_establish_circuit(): Conn open. Delivering first onion skin.");
    if(circuit_send_next_onion_skin(circ) < 0) {
      log(LOG_DEBUG,"circuit_establish_circuit(): circuit_send_next_onion_skin failed.");
      circuit_close(circ);
      return -1;
    }
  }
  return 0;
}

/* find circuits that are waiting on me, if any, and get them to send the onion */
void circuit_n_conn_open(connection_t *or_conn) {
  circuit_t *circ;

  log(LOG_DEBUG,"circuit_n_conn_open(): Starting.");
  circ = circuit_enumerate_by_naddr_nport(NULL, or_conn->addr, or_conn->port);
  for(;;) {
    if(!circ)
      return;

    log(LOG_DEBUG,"circuit_n_conn_open(): Found circ, sending onion skin.");
    circ->n_conn = or_conn;
    if(circuit_send_next_onion_skin(circ) < 0) {
      log(LOG_DEBUG,"circuit_n_conn_open(): circuit marked for closing.");
      circuit_close(circ);
      return; /* FIXME will want to try the other circuits too? */
    }
    circ = circuit_enumerate_by_naddr_nport(circ, or_conn->addr, or_conn->port);
  }
}

int circuit_send_next_onion_skin(circuit_t *circ) {
  cell_t cell;
  crypt_path_t *hop;
  routerinfo_t *router;

  assert(circ && circ->cpath);

  if(circ->cpath->state == CPATH_STATE_CLOSED) {

    log(LOG_DEBUG,"circuit_send_next_onion_skin(): First skin; sending create cell.");
    circ->n_aci = get_unique_aci_by_addr_port(circ->n_addr, circ->n_port, ACI_TYPE_BOTH);

    memset(&cell, 0, sizeof(cell_t));
    cell.command = CELL_CREATE;
    cell.aci = circ->n_aci;
    cell.length = DH_ONIONSKIN_LEN;

    if(onion_skin_create(circ->n_conn->pkey, &(circ->cpath->handshake_state), cell.payload) < 0) {
      log(LOG_INFO,"circuit_send_next_onion_skin(): onion_skin_create (first hop) failed.");
      return -1;
    }

    if(connection_write_cell_to_buf(&cell, circ->n_conn) < 0) {
      return -1;
    }

    circ->cpath->state = CPATH_STATE_AWAITING_KEYS;
    circ->state = CIRCUIT_STATE_BUILDING;
    log(LOG_DEBUG,"circuit_send_next_onion_skin(): first skin; finished sending create cell.");
  } else {
    assert(circ->cpath->state == CPATH_STATE_OPEN);
    assert(circ->state == CIRCUIT_STATE_BUILDING);
    log(LOG_DEBUG,"circuit_send_next_onion_skin(): starting to send subsequent skin.");
    for(hop=circ->cpath->next;
        hop != circ->cpath && hop->state == CPATH_STATE_OPEN;
        hop=hop->next) ;
    if(hop == circ->cpath) { /* done building the circuit. whew. */
      circ->state = CIRCUIT_STATE_OPEN;
      log(LOG_DEBUG,"circuit_send_next_onion_skin(): circuit built!");
      return 0;
    }

    router = router_get_by_addr_port(hop->addr,hop->port);
    if(!router) {
      log(LOG_INFO,"circuit_send_next_onion_skin(): couldn't lookup router %d:%d",hop->addr,hop->port);
      return -1;
    }

    memset(&cell, 0, sizeof(cell_t));
    cell.command = CELL_RELAY; 
    cell.aci = circ->n_aci;
    SET_CELL_RELAY_COMMAND(cell, RELAY_COMMAND_EXTEND);
    SET_CELL_STREAM_ID(cell, ZERO_STREAM);

    cell.length = RELAY_HEADER_SIZE + 6 + DH_ONIONSKIN_LEN;
    *(uint32_t*)(cell.payload+RELAY_HEADER_SIZE) = htonl(hop->addr);
    *(uint32_t*)(cell.payload+RELAY_HEADER_SIZE+4) = htons(hop->port);
    if(onion_skin_create(router->pkey, &(hop->handshake_state), cell.payload+RELAY_HEADER_SIZE+6) < 0) {
      log(LOG_INFO,"circuit_send_next_onion_skin(): onion_skin_create failed.");
      return -1;
    }

    log(LOG_DEBUG,"circuit_send_next_onion_skin(): Sending extend relay cell.");
    /* send it to hop->prev, because it will transfer it to a create cell and then send to hop */
    if(circuit_deliver_relay_cell_from_edge(&cell, circ, EDGE_AP, hop->prev) < 0) {
      log(LOG_DEBUG,"circuit_send_next_onion_skin(): failed to deliver extend cell. Closing.");
      return -1;
    }
    hop->state = CPATH_STATE_AWAITING_KEYS;
  }
  return 0;
}

/* take the 'extend' cell, pull out addr/port plus the onion skin. Connect
 * to the next hop, and pass it the onion skin in a create cell.
 */
int circuit_extend(cell_t *cell, circuit_t *circ) {
  connection_t *n_conn;
  aci_t aci_type;
  struct sockaddr_in me; /* my router identity */
  cell_t newcell;

  if(circ->n_conn) {
    log(LOG_WARNING,"circuit_extend(): n_conn already set. Bug/attack. Closing.");
    return -1;
  }

  circ->n_addr = ntohl(*(uint32_t*)(cell->payload+RELAY_HEADER_SIZE));
  circ->n_port = ntohs(*(uint16_t*)(cell->payload+RELAY_HEADER_SIZE+4));

  if(learn_my_address(&me) < 0)
    return -1;

  n_conn = connection_twin_get_by_addr_port(circ->n_addr,circ->n_port);
  if(!n_conn || n_conn->type != CONN_TYPE_OR) {
    /* i've disabled making connections through OPs, but it's definitely
     * possible here. I'm not sure if it would be a bug or a feature. -RD
     */
    /* note also that this will close circuits where the onion has the same
     * router twice in a row in the path. i think that's ok. -RD
     */
    log(LOG_DEBUG,"circuit_extend(): Next router not connected. Closing.");
    /* XXX later we should fail more gracefully here, like with a 'truncated' */
    return -1;
  }

  circ->n_addr = n_conn->addr; /* these are different if we found a twin instead */
  circ->n_port = n_conn->port;

  circ->n_conn = n_conn;
  log(LOG_DEBUG,"circuit_extend(): n_conn is %s:%u",n_conn->address,n_conn->port);

  aci_type = decide_aci_type(ntohl(me.sin_addr.s_addr), ntohs(me.sin_port),
                             circ->n_addr, circ->n_port);

  log(LOG_DEBUG,"circuit_extend(): aci_type = %u.",aci_type);
  circ->n_aci = get_unique_aci_by_addr_port(circ->n_addr, circ->n_port, aci_type);
  if(!circ->n_aci) {
    log(LOG_ERR,"circuit_extend(): failed to get unique aci.");
    return -1;
  }
  log(LOG_DEBUG,"circuit_extend(): Chosen ACI %u.",circ->n_aci);

  memset(&newcell, 0, sizeof(cell_t));
  newcell.command = CELL_CREATE;
  newcell.aci = circ->n_aci;
  newcell.length = DH_ONIONSKIN_LEN;

  memcpy(newcell.payload, cell->payload+RELAY_HEADER_SIZE+6, DH_ONIONSKIN_LEN);

  if(connection_write_cell_to_buf(&newcell, circ->n_conn) < 0) {
    return -1;
  }

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
      log(LOG_INFO,"circuit_finish_handshake(): got extended when circ already built? Weird.");
      return 0;
    }
  }
  assert(hop->state == CPATH_STATE_AWAITING_KEYS);

  if(onion_skin_client_handshake(hop->handshake_state, reply, keys, 32) < 0) {
    log(LOG_ERR,"circuit_finish_handshake(): onion_skin_client_handshake failed.");
    return -1;
  }

  crypto_dh_free(hop->handshake_state); /* don't need it anymore */
  hop->handshake_state = NULL;

  log(LOG_DEBUG,"circuit_finish_handshake(): hop %d init cipher forward %d, backward %d.", hop, *(int*)keys, *(int*)(keys+16));
  if (!(hop->f_crypto =
        crypto_create_init_cipher(DEFAULT_CIPHER,keys,iv,1))) {
    log(LOG_ERR,"Cipher initialization failed.");
    return -1;
  }

  if (!(hop->b_crypto =
        crypto_create_init_cipher(DEFAULT_CIPHER,keys+16,iv,0))) {
    log(LOG_ERR,"Cipher initialization failed.");
    return -1;
  }

  hop->state = CPATH_STATE_OPEN;
  log(LOG_DEBUG,"circuit_finish_handshake(): Completed.");
  return 0;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
