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

  circ = (circuit_t *)malloc(sizeof(circuit_t));
  if(!circ)
    return NULL;
  memset(circ,0,sizeof(circuit_t)); /* zero it out */

  circ->timestamp_created = now.tv_sec;

  circ->p_aci = p_aci;
  circ->p_conn = p_conn;

  circ->state = CIRCUIT_STATE_ONION_WAIT;

  /* ACIs */
  circ->p_aci = p_aci;
  /* circ->n_aci remains 0 because we haven't identified the next hop yet */

  circ->n_receive_circwindow = CIRCWINDOW_START;
  circ->p_receive_circwindow = CIRCWINDOW_START;

  circuit_add(circ);

  return circ;
}

void circuit_free(circuit_t *circ) {
  struct relay_queue_t *tmpd;
  
  if (circ->n_crypto)
    crypto_free_cipher_env(circ->n_crypto);
  if (circ->p_crypto)
    crypto_free_cipher_env(circ->p_crypto);

  if(circ->onion)
    free(circ->onion);
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

int circuit_init(circuit_t *circ, int aci_type, onion_layer_t *layer) {
  unsigned char iv[16];
  unsigned char digest1[20];
  unsigned char digest2[20];
  struct timeval start, end;
  long time_passed;

  assert(circ && circ->onion);

  log(LOG_DEBUG,"circuit_init(): starting");
  circ->n_port = layer->port;
  log(LOG_DEBUG,"circuit_init(): Set port to %u.",circ->n_port);
  circ->n_addr = layer->addr;
  circ->state = CIRCUIT_STATE_OPEN;

  log(LOG_DEBUG,"circuit_init(): aci_type = %u.",aci_type);

  my_gettimeofday(&start);

  circ->n_aci = get_unique_aci_by_addr_port(circ->n_addr, circ->n_port, aci_type);
  if(!circ->n_aci) {
    log(LOG_ERR,"circuit_init(): failed to get unique aci.");
    return -1;
  }

  my_gettimeofday(&end);

  time_passed = tv_udiff(&start, &end);
  if (time_passed > 1000) {/* more than 1ms */
    log(LOG_NOTICE,"circuit_init(): get_unique_aci just took %d us!",time_passed);
  }

  log(LOG_DEBUG,"circuit_init(): Chosen ACI %u.",circ->n_aci);

  /* keys */
  memset(iv, 0, 16);
  crypto_SHA_digest(layer->keyseed,16,digest1);
  crypto_SHA_digest(digest1,20,digest2);
  crypto_SHA_digest(digest2,20,digest1);
  log(LOG_DEBUG,"circuit_init(): Computed keys.");

  if (!(circ->p_crypto = 
        crypto_create_init_cipher(DEFAULT_CIPHER,digest2,iv,1))) {
    log(LOG_ERR,"Cipher initialization failed (ACI %u).",circ->n_aci);
    return -1;
  }
  
  if (!(circ->n_crypto = 
        crypto_create_init_cipher(DEFAULT_CIPHER,digest1,iv,0))) {
    log(LOG_ERR,"Cipher initialization failed (ACI %u).",circ->n_aci);
    return -1;
  }

  log(LOG_DEBUG,"circuit_init(): Cipher initialization complete.");

  circ->expire = layer->expire;

  return 0;
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
      for(tmpconn = circ->p_conn; tmpconn; tmpconn = tmpconn->next_stream) {
        if(tmpconn == conn)
          return circ;
      }
    }
    if(circ->n_aci == aci) {
      for(tmpconn = circ->n_conn; tmpconn; tmpconn = tmpconn->next_stream) {
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
    for(tmpconn = circ->p_conn; tmpconn; tmpconn=tmpconn->next_stream)
      if(tmpconn == conn)
        return circ;
    for(tmpconn = circ->n_conn; tmpconn; tmpconn=tmpconn->next_stream)
      if(tmpconn == conn)
        return circ;
  }
  return NULL;
}

circuit_t *circuit_get_newest_ap(void) {
  circuit_t *circ, *bestcirc=NULL;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if(!circ->p_conn || circ->p_conn->type == CONN_TYPE_AP) {
      if(circ->state == CIRCUIT_STATE_OPEN && (!bestcirc ||
        bestcirc->timestamp_created < circ->timestamp_created)) {
        log(LOG_DEBUG,"circuit_get_newest_ap(): Choosing n_aci %d.", circ->n_aci);
        assert(circ->n_aci);
        bestcirc = circ;
      }
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
    if(circ->p_receive_circwindow <= 0) {
      log(LOG_DEBUG,"circuit_deliver_relay_cell_from_edge(): pwindow 0, queueing for later.");
      circ->relay_queue = relay_queue_add(circ->relay_queue, cell, layer_hint);
      return 0;
    }
    circ->p_receive_circwindow--;
//    log(LOG_INFO,"circuit_deliver_relay_cell_from_edge(): p_receive_circwindow now %d.",circ->p_receive_circwindow);
  } else { /* i'm the exit */
    cell_direction = CELL_DIRECTION_IN;
    numsent_exit++;
    log(LOG_DEBUG,"circuit_deliver_relay_cell_from_edge(): now sent %d relay cells from exit", numsent_exit);
    if(circ->n_receive_circwindow <= 0) {
      log(LOG_DEBUG,"circuit_deliver_relay_cell_from_edge(): nwindow 0, queueing for later.");
      circ->relay_queue = relay_queue_add(circ->relay_queue, cell, layer_hint);
      return 0;
    }
    circ->n_receive_circwindow--;
  }

  if(circuit_deliver_relay_cell(cell, circ, cell_direction, layer_hint) < 0) {
    return -1;
  }

  circuit_consider_stop_edge_reading(circ, edge_type); /* has window reached 0? */
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

  log(LOG_DEBUG,"circuit_deliver_relay_cell(): streamid %d before crypt.", *(int*)(cell->payload+1));

  if(relay_crypt(circ, buf, 1+CELL_PAYLOAD_SIZE, cell_direction, layer_hint, &recognized, &conn) < 0) {
    log(LOG_DEBUG,"circuit_deliver_relay_cell(): relay crypt failed. Dropping connection.");
    return -1;
  }

  cell->length = buf[0];
  memcpy(cell->payload, buf+1, CELL_PAYLOAD_SIZE);

  if(recognized) {
    if(cell_direction == CELL_DIRECTION_OUT) {
      log(LOG_DEBUG,"circuit_deliver_relay_cell(): Sending to exit.");
      return connection_edge_process_relay_cell(cell, circ, conn, EDGE_EXIT);
    }
    if(cell_direction == CELL_DIRECTION_IN) {
      log(LOG_DEBUG,"circuit_deliver_relay_cell(): Sending to AP.");
      return connection_edge_process_relay_cell(cell, circ, conn, EDGE_AP);
    }
  }

  /* not recognized. pass it on. */
  if(cell_direction == CELL_DIRECTION_OUT)
    conn = circ->n_conn;
  else
    conn = circ->p_conn;

  if(!conn || !connection_speaks_cells(conn)) {
    log(LOG_INFO,"circuit_deliver_relay_cell(): Didn't recognize cell (%d), but circ stops here! Dropping.", *(int *)(cell->payload+1));
    return 0;
  }

  return connection_write_cell_to_buf(cell, conn);
}

int relay_crypt(circuit_t *circ, char *in, int inlen, char cell_direction,
                crypt_path_t *layer_hint, char *recognized, connection_t **conn) {
  crypt_path_t *thishop;
  char out[256];

  assert(circ && in && recognized && conn);

  assert(inlen < 256);

  if(cell_direction == CELL_DIRECTION_IN) { 
    if(circ->cpath) { /* we're at the beginning of the circuit. We'll want to do layered crypts. */
      thishop = circ->cpath;
      do { /* Remember: cpath is in forward order, that is, first hop first. */
        assert(thishop);

        /* decrypt */
        if(crypto_cipher_decrypt(thishop->b_crypto, in, inlen, out)) {
          log(LOG_ERR,"Error performing decryption:%s",crypto_perror());
          return -1;
        }
        memcpy(in,out,inlen);

        if( (*recognized = relay_check_recognized(circ, cell_direction, in+2, conn)))
          return 0;

        thishop = thishop->next;
      } while(thishop != circ->cpath);
      log(LOG_INFO,"relay_crypt(): in-cell at OP not recognized. Killing circuit.");
      return -1;
    } else { /* we're in the middle. Just one crypt. */

      if(crypto_cipher_encrypt(circ->p_crypto, in, inlen, out)) {
        log(LOG_ERR,"circuit_encrypt(): Encryption failed for ACI : %u (%s).",
            circ->p_aci, crypto_perror());
        return -1;
      }
      memcpy(in,out,inlen);

      /* don't check for recognized. only the OP can recognize a stream on the way back. */

    }
  } else if(cell_direction == CELL_DIRECTION_OUT) { 
    if(circ->cpath) { /* we're at the beginning of the circuit. We'll want to do layered crypts. */

      thishop = layer_hint; /* we already know which layer, from when we package_raw_inbuf'ed */
      /* moving from last to first hop */
      do {
        assert(thishop);

        /* encrypt */
        if(crypto_cipher_encrypt(thishop->f_crypto, in, inlen, out)) {
          log(LOG_ERR,"Error performing encryption:%s",crypto_perror());
          return -1;
        }
        memcpy(in,out,inlen);

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

  log(LOG_DEBUG,"relay_check_recognized(): entering");
  if(!memcmp(stream,ZERO_STREAM,STREAM_ID_SIZE))
    return 1; /* the zero stream is always recognized */

  if(cell_direction == CELL_DIRECTION_OUT)
    tmpconn = circ->n_conn;
  else
    tmpconn = circ->p_conn;

  log(LOG_DEBUG,"relay_check_recognized(): not the zero stream.");
  if(!tmpconn)
    return 0; /* no conns? don't recognize it */

  while(tmpconn && tmpconn->type == CONN_TYPE_OR) {
    log(LOG_DEBUG,"relay_check_recognized(): skipping over an OR conn");
    tmpconn = tmpconn->next_stream;
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

void circuit_resume_edge_reading(circuit_t *circ, int edge_type) {
  connection_t *conn;
  struct relay_queue_t *tmpd;

  assert(edge_type == EDGE_EXIT || edge_type == EDGE_AP);

  /* first, send the queue waiting at circ onto the circuit */
  while(circ->relay_queue) {
    assert(circ->relay_queue->cell);
    if(edge_type == EDGE_EXIT) {
      circ->n_receive_circwindow--;
      assert(circ->n_receive_circwindow >= 0);

      if(circuit_deliver_relay_cell(circ->relay_queue->cell, circ, CELL_DIRECTION_IN, circ->relay_queue->layer_hint) < 0) {
        circuit_close(circ);
        return;
      }
    } else { /* ap */
      circ->p_receive_circwindow--;
      assert(circ->p_receive_circwindow >= 0);

      if(circuit_deliver_relay_cell(circ->relay_queue->cell, circ, CELL_DIRECTION_OUT, circ->relay_queue->layer_hint) < 0) {
        circuit_close(circ);
        return;
      }
    }
    tmpd = circ->relay_queue;
    circ->relay_queue = tmpd->next;
    free(tmpd->cell);
    free(tmpd);

    if(circuit_consider_stop_edge_reading(circ, edge_type))
      return;
  }

  if(edge_type == EDGE_EXIT)
    conn = circ->n_conn;
  else
    conn = circ->p_conn;

  for( ; conn; conn=conn->next_stream) {
    if((edge_type == EDGE_EXIT && conn->n_receive_streamwindow > 0) ||
       (edge_type == EDGE_AP   && conn->p_receive_streamwindow > 0)) {
      connection_start_reading(conn);
      connection_package_raw_inbuf(conn); /* handle whatever might still be on the inbuf */
    }
  }
  circuit_consider_stop_edge_reading(circ, edge_type);
}

/* returns 1 if the window is empty, else 0. If it's empty, tell edge conns to stop reading. */
int circuit_consider_stop_edge_reading(circuit_t *circ, int edge_type) {
  connection_t *conn = NULL;

  assert(edge_type == EDGE_EXIT || edge_type == EDGE_AP);

  if(edge_type == EDGE_EXIT && circ->n_receive_circwindow <= 0)
    conn = circ->n_conn;
  else if(edge_type == EDGE_AP && circ->p_receive_circwindow <= 0)
    conn = circ->p_conn;
  else
    return 0;

  for( ; conn; conn=conn->next_stream)
    connection_stop_reading(conn);

  return 1;
}

int circuit_consider_sending_sendme(circuit_t *circ, int edge_type) {
  cell_t sendme;

  assert(circ);

  memset(&sendme, 0, sizeof(cell_t));
  sendme.command = CELL_SENDME;
  sendme.length = CIRCWINDOW_INCREMENT;

  if(edge_type == EDGE_AP) { /* i'm the AP */
    while(circ->n_receive_circwindow < CIRCWINDOW_START-CIRCWINDOW_INCREMENT) {
      log(LOG_DEBUG,"circuit_consider_sending_sendme(): n_receive_circwindow %d, Queueing sendme forward.", circ->n_receive_circwindow);
      circ->n_receive_circwindow += CIRCWINDOW_INCREMENT;
      sendme.aci = circ->n_aci;
      if(connection_write_cell_to_buf(&sendme, circ->n_conn) < 0) {
        return -1;
      }
    }
  } else if(edge_type == EDGE_EXIT) { /* i'm the exit */
    while(circ->p_receive_circwindow < CIRCWINDOW_START-CIRCWINDOW_INCREMENT) {
      log(LOG_DEBUG,"circuit_consider_sending_sendme(): p_receive_circwindow %d, Queueing sendme back.", circ->p_receive_circwindow);
      circ->p_receive_circwindow += CIRCWINDOW_INCREMENT;
      sendme.aci = circ->p_aci;
      if(connection_write_cell_to_buf(&sendme, circ->p_conn) < 0) {
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
  for(conn=circ->n_conn; conn; conn=conn->next_stream) {
    connection_send_destroy(circ->n_aci, circ->n_conn); 
  }
  for(conn=circ->p_conn; conn; conn=conn->next_stream) {
    connection_send_destroy(circ->p_aci, circ->p_conn); 
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

    if(conn == circ->p_conn) {
      circ->p_conn = conn->next_stream;
      goto send_end;
    }
    if(conn == circ->n_conn) {
      circ->n_conn = conn->next_stream;
      goto send_end;
    }
    for(prevconn = circ->p_conn; prevconn->next_stream && prevconn->next_stream != conn; prevconn = prevconn->next_stream) ;
    if(prevconn->next_stream) {
      prevconn->next_stream = conn->next_stream;
      goto send_end;
    }
    for(prevconn = circ->n_conn; prevconn->next_stream && prevconn->next_stream != conn; prevconn = prevconn->next_stream) ;
    if(prevconn->next_stream) {
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
    for(tmpconn=circ->p_conn; tmpconn; tmpconn=tmpconn->next_stream) {
      if(tmpconn == conn) {
        printf("Conn %d has App-ward circuit:  aci %d (other side %d), state %d (%s)\n",
          conn->poll_index, circ->p_aci, circ->n_aci, circ->state, circuit_state_to_string[circ->state]);
      }
    }
    for(tmpconn=circ->n_conn; tmpconn; tmpconn=tmpconn->next_stream) {
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
    if(tmpcirc != youngest && !tmpcirc->p_conn) {
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

  if(circuit_create_onion() < 0) {
    failures++;
    goto retry_circuit;
  }

  failures = 0;
  return;
}

int circuit_create_onion(void) {
  int routelen; /* length of the route */
  unsigned int *route; /* hops in the route as an array of indexes into rarray */
  unsigned char *onion; /* holds the onion */
  int onionlen; /* onion length in host order */
  crypt_path_t *cpath; /* defines the crypt operations that need to be performed on incoming/outgoing data */

  /* choose a route */
  route = (unsigned int *)router_new_route(&routelen);
  if (!route) { 
    log(LOG_ERR,"circuit_create_onion(): Error choosing a route through the OR network.");
    return -1;
  }
  log(LOG_DEBUG,"circuit_create_onion(): Chosen a route of length %u : ",routelen);

  /* create an onion and calculate crypto keys */
  onion = router_create_onion(route,routelen,&onionlen, &cpath);
  if (!onion) {
    log(LOG_ERR,"circuit_create_onion(): Error creating an onion.");
    free(route);
    return -1;
  }
  log(LOG_DEBUG,"circuit_create_onion(): Created an onion of size %u bytes.",onionlen);
//  log(LOG_DEBUG,"circuit_create_onion(): Crypt path :");

  return circuit_establish_circuit(route, routelen, onion, onionlen, cpath);
}

int circuit_establish_circuit(unsigned int *route, int routelen, char *onion,
                                   int onionlen, crypt_path_t *cpath) {
  routerinfo_t *firsthop;
  connection_t *n_conn;
  circuit_t *circ;

  /* now see if we're already connected to the first OR in 'route' */
  firsthop = router_get_first_in_route(route, routelen);
  assert(firsthop); /* should always be defined */
  free(route); /* we don't need it anymore */

  circ = circuit_new(0, NULL); /* sets circ->p_aci and circ->p_conn */
  circ->state = CIRCUIT_STATE_OR_WAIT;
  circ->onion = onion;
  circ->onionlen = onionlen;
  circ->cpath = cpath;

  log(LOG_DEBUG,"circuit_establish_circuit(): Looking for firsthop '%s:%u'",
      firsthop->address,firsthop->or_port);
  n_conn = connection_twin_get_by_addr_port(firsthop->addr,firsthop->or_port);
  if(!n_conn || n_conn->state != OR_CONN_STATE_OPEN) { /* not currently connected */
    circ->n_addr = firsthop->addr;
    circ->n_port = firsthop->or_port;
    if(options.ORPort) { /* we would be connected if he were up. but he's not. */
      log(LOG_DEBUG,"circuit_establish_circuit(): Route's firsthop isn't connected.");
      circuit_close(circ); 
      return -1;
    }

    if(!n_conn) { /* launch the connection */
      n_conn = connection_or_connect_as_op(firsthop);
      if(!n_conn) { /* connect failed, forget the whole thing */
        log(LOG_DEBUG,"circuit_establish_circuit(): connect to firsthop failed. Closing.");
        circuit_close(circ);
        return -1;
      }
    }

    return 0; /* return success. The onion/circuit/etc will be taken care of automatically
               * (may already have been) whenever n_conn reaches OR_CONN_STATE_OPEN.
               */ 
  } else { /* it (or a twin) is already open. use it. */
    circ->n_addr = n_conn->addr;
    circ->n_port = n_conn->port;
    return circuit_send_onion(n_conn, circ);
  }
}

/* find circuits that are waiting on me, if any, and get them to send the onion */
void circuit_n_conn_open(connection_t *or_conn) {
  circuit_t *circ;

  log(LOG_DEBUG,"circuit_n_conn_open(): Starting.");
  circ = circuit_enumerate_by_naddr_nport(NULL, or_conn->addr, or_conn->port);
  for(;;) {
    if(!circ)
      return;

    log(LOG_DEBUG,"circuit_n_conn_open(): Found circ, sending onion.");
    if(circuit_send_onion(or_conn, circ) < 0) {
      log(LOG_DEBUG,"circuit_n_conn_open(): circuit marked for closing.");
      circuit_close(circ);
      return; /* FIXME will want to try the other circuits too? */
    }
    circ = circuit_enumerate_by_naddr_nport(circ, or_conn->addr, or_conn->port);
  }
}

int circuit_send_onion(connection_t *n_conn, circuit_t *circ) {
  cell_t cell;
  int tmpbuflen, dataleft;
  char *tmpbuf;

  circ->n_aci = get_unique_aci_by_addr_port(circ->n_addr, circ->n_port, ACI_TYPE_BOTH);
  circ->n_conn = n_conn;
  log(LOG_DEBUG,"circuit_send_onion(): n_conn is %s:%u",n_conn->address,n_conn->port);

  /* deliver the onion as one or more create cells */
  cell.command = CELL_CREATE;
  cell.aci = circ->n_aci;

  tmpbuflen = circ->onionlen+4;
  tmpbuf = malloc(tmpbuflen);
  if(!tmpbuf)
    return -1;
  *(uint32_t*)tmpbuf = htonl(circ->onionlen);
  memcpy(tmpbuf+4, circ->onion, circ->onionlen);

  dataleft = tmpbuflen;
  while(dataleft) {
    cell.command = CELL_CREATE;
    cell.aci = circ->n_aci;
    log(LOG_DEBUG,"circuit_send_onion(): Sending a create cell for the onion...");
    if(dataleft >= CELL_PAYLOAD_SIZE) {
      cell.length = CELL_PAYLOAD_SIZE;
      memcpy(cell.payload, tmpbuf + tmpbuflen - dataleft, CELL_PAYLOAD_SIZE);
      connection_write_cell_to_buf(&cell, n_conn);
      dataleft -= CELL_PAYLOAD_SIZE;
    } else { /* last cell */
      cell.length = dataleft;
      memcpy(cell.payload, tmpbuf + tmpbuflen - dataleft, dataleft);
      /* fill extra space with 0 bytes */
      memset(cell.payload + dataleft, 0, CELL_PAYLOAD_SIZE - dataleft);
      connection_write_cell_to_buf(&cell, n_conn);
      dataleft = 0;
    }
  }
  free(tmpbuf);

  circ->state = CIRCUIT_STATE_OPEN;
  /* FIXME should set circ->expire to something here */

  return 0;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
