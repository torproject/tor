/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

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

  circ = (circuit_t *)malloc(sizeof(circuit_t));
  if(!circ)
    return NULL;
  memset(circ,0,sizeof(circuit_t)); /* zero it out */

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
  struct data_queue_t *tmpd;
  
  if (circ->n_crypto)
    crypto_free_cipher_env(circ->n_crypto);
  if (circ->p_crypto)
    crypto_free_cipher_env(circ->p_crypto);

  if(circ->onion)
    free(circ->onion);
  if(circ->cpath)
    circuit_free_cpath(circ->cpath, circ->cpathlen);
  while(circ->data_queue) {
    tmpd = circ->data_queue;
    circ->data_queue = tmpd->next;
    free(tmpd->cell);
    free(tmpd);
  }

  free(circ);
}

void circuit_free_cpath(crypt_path_t **cpath, int cpathlen) {
  int i;

  for(i=0;i<cpathlen;i++)
    free(cpath[i]);

  free(cpath);
}

/* return 0 if can't get a unique aci. */
aci_t get_unique_aci_by_addr_port(uint32_t addr, uint16_t port, int aci_type) {
  aci_t test_aci;
  connection_t *conn;

try_again:
  log(LOG_DEBUG,"get_unique_aci_by_addr_port() trying to get a unique aci");

  crypto_pseudo_rand(2, (unsigned char *)&test_aci);

  if(aci_type == ACI_TYPE_LOWER && test_aci >= (2<<15))
    test_aci -= (2<<15);
  if(aci_type == ACI_TYPE_HIGHER && test_aci < (2<<15))
    test_aci += (2<<15);
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

int circuit_init(circuit_t *circ, int aci_type) {
  unsigned char iv[16];
  unsigned char digest1[20];
  unsigned char digest2[20];
  struct timeval start, end;
  int time_passed; 

  assert(circ && circ->onion);

  log(LOG_DEBUG,"circuit_init(): starting");
  circ->n_port = ntohs(*(uint16_t *)(circ->onion+2));
  log(LOG_DEBUG,"circuit_init(): Set port to %u.",circ->n_port);
  circ->n_addr = ntohl(*(uint32_t *)(circ->onion+4));
  circ->p_f = *(circ->onion+1) >> 4; /* backf */
  log(LOG_DEBUG,"circuit_init(): Set BACKF to %u.",circ->p_f);
  circ->n_f = *(circ->onion+1) & 0x0f; /* forwf */
  log(LOG_DEBUG,"circuit_init(): Set FORWF to %u.",circ->n_f);
  circ->state = CIRCUIT_STATE_OPEN;

  log(LOG_DEBUG,"circuit_init(): aci_type = %u.",aci_type);



  gettimeofday(&start,NULL);

  circ->n_aci = get_unique_aci_by_addr_port(circ->n_addr, circ->n_port, aci_type);
  if(!circ->n_aci) {
    log(LOG_ERR,"circuit_init(): failed to get unique aci.");
    return -1;
  }

  gettimeofday(&end,NULL);

  if(end.tv_usec < start.tv_usec) {
    end.tv_sec--;
    end.tv_usec += 1000000;
  }
  time_passed = ((end.tv_sec - start.tv_sec)*1000000) + (end.tv_usec - start.tv_usec);
  if(time_passed > 1000) { /* more than 1ms */
    log(LOG_NOTICE,"circuit_init(): get_unique_aci just took %d us!",time_passed);
  }



  log(LOG_DEBUG,"circuit_init(): Chosen ACI %u.",circ->n_aci);

  /* keys */
  memset(iv, 0, 16);
  crypto_SHA_digest(circ->onion+12,16,digest1);
  crypto_SHA_digest(digest1,20,digest2);
  crypto_SHA_digest(digest2,20,digest1);
  log(LOG_DEBUG,"circuit_init(): Computed keys.");

  if (!(circ->p_crypto = create_onion_cipher(circ->p_f,digest2,iv,1))) {
    log(LOG_ERR,"Cipher initialization failed (ACI %u).",circ->n_aci);
    return -1;
  }
  
  if (!(circ->n_crypto = create_onion_cipher(circ->n_f, digest1, iv, 0))) {
    log(LOG_ERR,"Cipher initialization failed (ACI %u).",circ->n_aci);
    return -1;
  }

  log(LOG_DEBUG,"circuit_init(): Cipher initialization complete.");

  circ->expire = ntohl(*(uint32_t *)(circ->onion+8));

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
      for(tmpconn = circ->p_conn; tmpconn; tmpconn = tmpconn->next_topic) {
        if(tmpconn == conn)
          return circ;
      }
    }
    if(circ->n_aci == aci) {
      for(tmpconn = circ->n_conn; tmpconn; tmpconn = tmpconn->next_topic) {
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
    for(tmpconn = circ->p_conn; tmpconn; tmpconn=tmpconn->next_topic)
      if(tmpconn == conn)
        return circ;
    for(tmpconn = circ->n_conn; tmpconn; tmpconn=tmpconn->next_topic)
      if(tmpconn == conn)
        return circ;
  }
  return NULL;
}

int circuit_deliver_data_cell_from_edge(cell_t *cell, circuit_t *circ, char edge_type) {
  int cell_direction;

  log(LOG_DEBUG,"circuit_deliver_data_cell_from_edge(): called, edge_type %d.", edge_type);

  if(edge_type == EDGE_AP) { /* i'm the AP */
    cell_direction = CELL_DIRECTION_OUT;
    if(circ->p_receive_circwindow <= 0) {
      log(LOG_DEBUG,"circuit_deliver_data_cell_from_edge(): window 0, queueing for later.");
      circ->data_queue = data_queue_add(circ->data_queue, cell);
      return 0;
    }
    circ->p_receive_circwindow--;
  } else { /* i'm the exit */
    cell_direction = CELL_DIRECTION_IN;
    if(circ->n_receive_circwindow <= 0) {
      log(LOG_DEBUG,"circuit_deliver_data_cell_from_edge(): window 0, queueing for later.");
      circ->data_queue = data_queue_add(circ->data_queue, cell);
      return 0;
    }
    circ->n_receive_circwindow--;
  }

  if(circuit_deliver_data_cell(cell, circ, cell_direction) < 0) {
    return -1;
  }
    
  circuit_consider_stop_edge_reading(circ, edge_type); /* has window reached 0? */
  return 0;
}

int circuit_deliver_data_cell(cell_t *cell, circuit_t *circ, int cell_direction) {
  connection_t *conn;

  assert(cell && circ);
  assert(cell_direction == CELL_DIRECTION_OUT || cell_direction == CELL_DIRECTION_IN); 
  if(cell_direction == CELL_DIRECTION_OUT)
    conn = circ->n_conn;
  else
    conn = circ->p_conn;

  /* first crypt cell->length */
  if(circuit_crypt(circ, &(cell->length), 1, cell_direction) < 0) {
    log(LOG_DEBUG,"circuit_deliver_data_cell(): length crypt failed. Dropping connection.");
    return -1;
  }

  /* then crypt the payload */
  if(circuit_crypt(circ, (char *)&(cell->payload), CELL_PAYLOAD_SIZE, cell_direction) < 0) {
    log(LOG_DEBUG,"circuit_deliver_data_cell(): payload crypt failed. Dropping connection.");
    return -1;
  }

  if((!conn && cell_direction == CELL_DIRECTION_OUT) || (conn && conn->type == CONN_TYPE_EXIT)) {
    log(LOG_DEBUG,"circuit_deliver_data_cell(): Sending to exit.");
    return connection_exit_process_data_cell(cell, circ);
  }
  if((!conn && cell_direction == CELL_DIRECTION_IN) || (conn && conn->type == CONN_TYPE_AP)) {
    log(LOG_DEBUG,"circuit_deliver_data_cell(): Sending to AP.");
    return connection_ap_process_data_cell(cell, circ);
  }
  /* else send it as a cell */
  assert(conn);
  //log(LOG_DEBUG,"circuit_deliver_data_cell(): Sending to connection.");
  return connection_write_cell_to_buf(cell, conn);
}

int circuit_crypt(circuit_t *circ, char *in, int inlen, char cell_direction) {
  char *out;
  int i;
  crypt_path_t *thishop;

  assert(circ && in);

  out = (char *)malloc(inlen);
  if(!out)
    return -1;

  if(cell_direction == CELL_DIRECTION_IN) { //crypt_type == 'e') {
    if(circ->cpath) { /* we're at the beginning of the circuit. We'll want to do layered crypts. */
      for (i=circ->cpathlen-1; i >= 0; i--) /* moving from first to last hop 
                                       * Remember : cpath is in reverse order, i.e. last hop first
                                       */
      { 
        thishop = circ->cpath[i];

        /* decrypt */
        if(crypto_cipher_decrypt(thishop->b_crypto, in, inlen, out)) {
          log(LOG_ERR,"Error performing decryption:%s",crypto_perror());
          free(out);
          return -1;
        }

        /* copy ciphertext back to buf */
        memcpy(in,out,inlen);
      }
    } else { /* we're in the middle. Just one crypt. */
      if(crypto_cipher_encrypt(circ->p_crypto,in, inlen, out)) {
        log(LOG_ERR,"circuit_encrypt(): Encryption failed for ACI : %u (%s).",
            circ->p_aci, crypto_perror());
        free(out);
        return -1;
      }
      memcpy(in,out,inlen);
    }
  } else if(cell_direction == CELL_DIRECTION_OUT) { //crypt_type == 'd') {
    if(circ->cpath) { /* we're at the beginning of the circuit. We'll want to do layered crypts. */
      for (i=0; i < circ->cpathlen; i++) /* moving from last to first hop 
                                          * Remember : cpath is in reverse order, i.e. last hop first
                                          */
      { 
        thishop = circ->cpath[i];
    
        /* encrypt */
        if(crypto_cipher_encrypt(thishop->f_crypto, in, inlen, (unsigned char *)out)) {
          log(LOG_ERR,"Error performing encryption:%s",crypto_perror());
          free(out);
          return -1;
        }

        /* copy ciphertext back to buf */
        memcpy(in,out,inlen);
      }
    } else { /* we're in the middle. Just one crypt. */
      if(crypto_cipher_decrypt(circ->n_crypto,in, inlen, out)) {
        log(LOG_ERR,"circuit_crypt(): Decryption failed for ACI : %u (%s).",
            circ->n_aci, crypto_perror());
        free(out);
        return -1;
      }
      memcpy(in,out,inlen);
    }
  } else {
    log(LOG_ERR,"circuit_crypt(): unknown cell direction %d.", cell_direction);
    assert(0);
  }

  free(out);
  return 0;
}

void circuit_resume_edge_reading(circuit_t *circ, int edge_type) {
  connection_t *conn;
  struct data_queue_t *tmpd;

  assert(edge_type == EDGE_EXIT || edge_type == EDGE_AP);

  if(edge_type == EDGE_EXIT)
    conn = circ->n_conn;
  else
    conn = circ->p_conn;

  /* first, send the queue waiting at circ onto the circuit */
  while(circ->data_queue) {
    assert(circ->data_queue->cell);
    if(edge_type == EDGE_EXIT) {   
      circ->p_receive_circwindow--;
      assert(circ->p_receive_circwindow >= 0);
      
      if(circuit_deliver_data_cell(circ->data_queue->cell, circ, CELL_DIRECTION_IN) < 0) {
        circuit_close(circ);
        return;
      }
    } else { /* ap */
      circ->p_receive_circwindow--;
      assert(circ->p_receive_circwindow >= 0);
      
      if(circuit_deliver_data_cell(circ->data_queue->cell, circ, CELL_DIRECTION_IN) < 0) {
        circuit_close(circ);
        return;
      }
    }
    tmpd = circ->data_queue;
    circ->data_queue = tmpd->next;
    free(tmpd->cell);
    free(tmpd);

    if(circuit_consider_stop_edge_reading(circ, edge_type))
      return;
  }

  for( ; conn; conn=conn->next_topic) {
    if((edge_type == EDGE_EXIT && conn->n_receive_topicwindow > 0) ||
       (edge_type == EDGE_AP   && conn->p_receive_topicwindow > 0)) {
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

  if(edge_type == EDGE_EXIT && circ->p_receive_circwindow <= 0)
    conn = circ->n_conn;      
  else if(edge_type == EDGE_AP && circ->n_receive_circwindow <= 0)
    conn = circ->p_conn;      
  else
    return 0;

  for( ; conn; conn=conn->next_topic)
    connection_stop_reading(conn);

  return 1;
}

int circuit_consider_sending_sendme(circuit_t *circ, int edge_type) {
  cell_t sendme;

  assert(circ);

  sendme.command = CELL_SENDME;
  sendme.length = CIRCWINDOW_INCREMENT;

  if(edge_type == EDGE_AP) { /* i'm the AP */
    if(circ->n_receive_circwindow < CIRCWINDOW_START-CIRCWINDOW_INCREMENT) {
      log(LOG_DEBUG,"circuit_consider_sending_sendme(): Queueing sendme forward.");
      circ->n_receive_circwindow += CIRCWINDOW_INCREMENT;
      sendme.aci = circ->n_aci;
      return connection_write_cell_to_buf(&sendme, circ->n_conn); /* (clobbers sendme) */
    }
  } else if(edge_type == EDGE_EXIT) { /* i'm the exit */
    if(circ->p_receive_circwindow < CIRCWINDOW_START-CIRCWINDOW_INCREMENT) {
      log(LOG_DEBUG,"circuit_consider_sending_sendme(): Queueing sendme back.");
      circ->p_receive_circwindow += CIRCWINDOW_INCREMENT;
      sendme.aci = circ->p_aci;
      return connection_write_cell_to_buf(&sendme, circ->p_conn); /* (clobbers sendme) */
    }
  }
  return 0;
}

void circuit_close(circuit_t *circ) {
  connection_t *conn;

  circuit_remove(circ);
  for(conn=circ->n_conn; conn; conn=conn->next_topic) {
    connection_send_destroy(circ->n_aci, circ->n_conn); 
  }
  for(conn=circ->p_conn; conn; conn=conn->next_topic) {
    connection_send_destroy(circ->p_aci, circ->p_conn); 
  }
  circuit_free(circ);
}

void circuit_about_to_close_connection(connection_t *conn) {
  /* send destroys for all circuits using conn */
  /* currently, we assume it's too late to flush conn's buf here.
   * down the road, maybe we'll consider that eof doesn't mean can't-write
   */
  circuit_t *circ;
  connection_t *prevconn, *tmpconn;
  cell_t cell;
  int edge_type;

  if(!connection_speaks_cells(conn)) {
    /* it's an edge conn. need to remove it from the linked list of
     * conn's for this circuit. Send an 'end' data topic.
     * But don't kill the circuit.
     */

    circ = circuit_get_by_conn(conn);
    if(!circ)
      return;

    memset(&cell, 0, sizeof(cell_t));
    cell.command = CELL_DATA;
    cell.length = TOPIC_HEADER_SIZE;
    *(uint32_t *)cell.payload = conn->topic_id;
    *cell.payload = TOPIC_COMMAND_END;
   
    if(conn == circ->p_conn) {
      circ->p_conn = conn->next_topic;
      edge_type = EDGE_AP;
      goto send_end;
    }
    if(conn == circ->n_conn) {
      circ->n_conn = conn->next_topic;
      edge_type = EDGE_EXIT;
      goto send_end;
    }
    for(prevconn = circ->p_conn; prevconn->next_topic && prevconn->next_topic != conn; prevconn = prevconn->next_topic) ;
    if(prevconn->next_topic) {
      prevconn->next_topic = conn->next_topic;
      edge_type = EDGE_AP;
      goto send_end;
    }
    for(prevconn = circ->n_conn; prevconn->next_topic && prevconn->next_topic != conn; prevconn = prevconn->next_topic) ;
    if(prevconn->next_topic) {
      prevconn->next_topic = conn->next_topic;
      edge_type = EDGE_EXIT;
      goto send_end;
    }
    log(LOG_ERR,"circuit_about_to_close_connection(): edge conn not in circuit's list?");
    assert(0); /* should never get here */
send_end:
    if(edge_type == EDGE_AP) { /* send to circ->n_conn */
      log(LOG_INFO,"circuit_about_to_close_connection(): send data end forward (aci %d).",circ->n_aci);
      cell.aci = circ->n_aci;
    } else { /* send to circ->p_conn */
      assert(edge_type == EDGE_EXIT);
      log(LOG_INFO,"circuit_about_to_close_connection(): send data end backward (aci %d).",circ->p_aci);
      cell.aci = circ->p_aci;
    }

    if(circuit_deliver_data_cell_from_edge(&cell, circ, edge_type) < 0) {
      log(LOG_DEBUG,"circuit_about_to_close_connection(): circuit_deliver_data_cell_from_edge (%d) failed. Closing.", edge_type);
      circuit_close(circ);
    }
    return;
  }

  while((circ = circuit_get_by_conn(conn))) {
    circuit_remove(circ);
    if(circ->n_conn == conn) /* it's closing in front of us */
      for(tmpconn=circ->p_conn; tmpconn; tmpconn=tmpconn->next_topic) {
        connection_send_destroy(circ->p_aci, tmpconn); 
      }
    if(circ->p_conn == conn) /* it's closing behind us */
      for(tmpconn=circ->n_conn; tmpconn; tmpconn=tmpconn->next_topic) {
        connection_send_destroy(circ->n_aci, tmpconn); 
      }
    circuit_free(circ);
  }  
}

/* FIXME this now leaves some out */
void circuit_dump_by_conn(connection_t *conn) {
  circuit_t *circ;
  connection_t *tmpconn;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    for(tmpconn=circ->p_conn; tmpconn; tmpconn=tmpconn->next_topic) {
      if(tmpconn == conn) {
        printf("Conn %d has App-ward circuit:  aci %d (other side %d), state %d (%s)\n",
          conn->poll_index, circ->p_aci, circ->n_aci, circ->state, circuit_state_to_string[circ->state]);
      }
    }
    for(tmpconn=circ->n_conn; tmpconn; tmpconn=tmpconn->next_topic) {
      if(tmpconn == conn) {
        printf("Conn %d has Exit-ward circuit: aci %d (other side %d), state %d (%s)\n",
          conn->poll_index, circ->n_aci, circ->p_aci, circ->state, circuit_state_to_string[circ->state]);
      }
    }
  }
}

