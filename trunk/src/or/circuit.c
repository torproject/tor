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

  circ->n_receive_window = RECEIVE_WINDOW_START;
  circ->p_receive_window = RECEIVE_WINDOW_START;

  circuit_add(circ);

  return circ;
}

void circuit_free(circuit_t *circ) {
  
  if (circ->n_crypto)
    crypto_free_cipher_env(circ->n_crypto);
  if (circ->p_crypto)
    crypto_free_cipher_env(circ->p_crypto);

  if(circ->onion)
    free(circ->onion);
  if(circ->cpath)
    circuit_free_cpath(circ->cpath, circ->cpathlen);

  free(circ);
}

void circuit_free_cpath(crypt_path_t **cpath, int cpathlen) {
  int i;

  for(i=0;i<cpathlen;i++)
    free(cpath[i]);

  free(cpath);
}

aci_t get_unique_aci_by_addr_port(uint32_t addr, uint16_t port, int aci_type) {
  aci_t test_aci;
  connection_t *conn;

  log(LOG_DEBUG,"get_unique_aci_by_addr_port() trying to get a unique aci");

  crypto_pseudo_rand(2, (unsigned char *)&test_aci);

  if(aci_type == ACI_TYPE_LOWER)
    test_aci &= htons(0x00FF);
  if(aci_type == ACI_TYPE_HIGHER)
    test_aci &= htons(0xFF00);
  /* if aci_type == ACI_BOTH, don't filter any of it */

  if(test_aci == 0)
    return get_unique_aci_by_addr_port(addr, port, aci_type); /* try again */ 

  conn = connection_exact_get_by_addr_port(addr,port);
  if(!conn) /* there can't be a conflict -- no connection of that sort yet */
    return test_aci;

  if(circuit_get_by_aci_conn(test_aci, conn))
    return get_unique_aci_by_addr_port(addr, port, aci_type); /* try again */

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

  for( ;circ;circ = circ->next) {
    if(circ->n_addr == naddr && circ->n_port == nport)
       return circ;
  }
  return NULL;
}

circuit_t *circuit_get_by_aci_conn(aci_t aci, connection_t *conn) {
  circuit_t *circ;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if(circ->p_conn == conn && circ->p_aci == aci)
       return circ;
    if(circ->n_conn == conn && circ->n_aci == aci)
       return circ;
  }
  return NULL;
}

circuit_t *circuit_get_by_conn(connection_t *conn) {
  circuit_t *circ;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if(circ->p_conn == conn)
       return circ;
    if(circ->n_conn == conn)
       return circ;
  }
  return NULL;
}

int circuit_deliver_data_cell(cell_t *cell, circuit_t *circ, connection_t *conn, int crypt_type) {

  /* first decrypt cell->length */
  if(circuit_crypt(circ, &(cell->length), 1, crypt_type) < 0) {
    log(LOG_DEBUG,"circuit_deliver_data_cell(): length decryption failed. Dropping connection.");
    return -1;
  }

  /* then decrypt the payload */
  if(circuit_crypt(circ, (char *)&(cell->payload), CELL_PAYLOAD_SIZE, crypt_type) < 0) {
    log(LOG_DEBUG,"circuit_deliver_data_cell(): payload decryption failed. Dropping connection.");
    return -1;
  }

  if(conn->type == CONN_TYPE_EXIT) { /* send payload directly */
//    log(LOG_DEBUG,"circuit_deliver_data_cell(): Sending to exit.");
    return connection_exit_process_data_cell(cell, conn);
  }
  if(conn->type == CONN_TYPE_AP) { /* send payload directly */
//    log(LOG_DEBUG,"circuit_deliver_data_cell(): Sending to AP.");
    return connection_ap_process_data_cell(cell, conn);
  }
  /* else send it as a cell */
//  log(LOG_DEBUG,"circuit_deliver_data_cell(): Sending to connection.");
  return connection_write_cell_to_buf(cell, conn);
}

int circuit_crypt(circuit_t *circ, char *in, int inlen, char crypt_type) {
  char *out;
  int i;
  crypt_path_t *thishop;

  assert(circ && in);

  out = (char *)malloc(inlen);
  if(!out)
    return -1;

  if(crypt_type == 'e') {
//    log(LOG_DEBUG,"circuit_crypt(): Encrypting %d bytes.",inlen);
    if(circ->cpath) { /* we're at the beginning of the circuit. We'll want to do layered crypts. */
      /* 'e' means we're preparing to send it out. */
      for (i=0; i < circ->cpathlen; i++) /* moving from last to first hop 
                                          * Remember : cpath is in reverse order, i.e. last hop first
                                          */
      { 
//        log(LOG_DEBUG,"circuit_crypt() : Encrypting via cpath: Processing hop %u",circ->cpathlen-i);
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
      if(crypto_cipher_encrypt(circ->p_crypto,in, inlen, out)) {
        log(LOG_ERR,"circuit_encrypt(): Encryption failed for ACI : %u (%s).",
            circ->p_aci, crypto_perror());
        free(out);
        return -1;
      }
      memcpy(in,out,inlen);
    }
  } else if(crypt_type == 'd') {
//    log(LOG_DEBUG,"circuit_crypt(): Decrypting %d bytes.",inlen);
    if(circ->cpath) { /* we're at the beginning of the circuit. We'll want to do layered crypts. */
      for (i=circ->cpathlen-1; i >= 0; i--) /* moving from first to last hop 
                                       * Remember : cpath is in reverse order, i.e. last hop first
                                       */
      { 
//        log(LOG_DEBUG,"circuit_crypt() : Decrypting via cpath: Processing hop %u",circ->cpathlen-i);
        thishop = circ->cpath[i];

        /* encrypt */
        if(crypto_cipher_decrypt(thishop->b_crypto, in, inlen, out)) {
          log(LOG_ERR,"Error performing decryption:%s",crypto_perror());
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
  }

  free(out);

  return 0;
}

void circuit_close(circuit_t *circ) {
  circuit_remove(circ);
  if(circ->n_conn)
    connection_send_destroy(circ->n_aci, circ->n_conn); 
  if(circ->p_conn)
    connection_send_destroy(circ->p_aci, circ->p_conn); 
  circuit_free(circ);
}

void circuit_about_to_close_connection(connection_t *conn) {
  /* send destroys for all circuits using conn */
  /* currently, we assume it's too late to flush conn's buf here.
   * down the road, maybe we'll consider that eof doesn't mean can't-write
   */
  circuit_t *circ;

  while((circ = circuit_get_by_conn(conn))) {
    circuit_remove(circ);
    if(circ->n_conn == conn) /* it's closing in front of us */
      /* circ->p_conn should always be set */
      connection_send_destroy(circ->p_aci, circ->p_conn);
    if(circ->p_conn == conn) /* it's closing behind us */
      if(circ->n_conn)
        connection_send_destroy(circ->n_aci, circ->n_conn);
    circuit_free(circ);
  }  
}

void circuit_dump_by_conn(connection_t *conn) {
  circuit_t *circ;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if(circ->p_conn == conn) {
      printf("Conn %d has App-ward circuit:  aci %d (other side %d), state %d (%s)\n",
        conn->poll_index, circ->p_aci, circ->n_aci, circ->state, circuit_state_to_string[circ->state]);
    }
    if(circ->n_conn == conn) {
      printf("Conn %d has Exit-ward circuit: aci %d (other side %d), state %d (%s)\n",
        conn->poll_index, circ->n_aci, circ->p_aci, circ->state, circuit_state_to_string[circ->state]);
    }
  }
}

