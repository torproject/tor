/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/********* START VARIABLES **********/

extern or_options_t options; /* command-line and config-file options */

#if 0
/* these are now out of date :( -RD */
char *conn_type_to_string[] = {
  "OP listener", /* 0 */
  "OP",          /* 1 */
  "OR listener", /* 2 */
  "OR",          /* 3 */
  "App"          /* 4 */
};

char *conn_state_to_string[][10] = {
  { "ready" }, /* op listener, 0 */
  { "awaiting keys", /* op, 0 */
    "open",              /* 1 */
    "close",             /* 2 */
    "close_wait" },      /* 3 */
  { "ready" }, /* or listener, 0 */
  { "connecting (as client)",   /* or, 0 */
    "sending auth (as client)",     /* 1 */
    "waiting for auth (as client)", /* 2 */
    "sending nonce (as client)",    /* 3 */
    "waiting for auth (as server)", /* 4 */
    "sending auth (as server)",     /* 5 */
    "waiting for nonce (as server)",/* 6 */
    "open" },                       /* 7 */
  { "connecting",                /* exit, 0 */
    "open",                            /* 1 */
    "waiting for dest info",           /* 2 */
    "flushing buffer, then will close",/* 3 */
    "close_wait" }                     /* 4 */
};
#endif

/********* END VARIABLES ************/

/**************************************************************/

int tv_cmp(struct timeval *a, struct timeval *b) {
        if (a->tv_sec > b->tv_sec)
                return 1;
        if (a->tv_sec < b->tv_sec)
                return -1;
        if (a->tv_usec > b->tv_usec)
                return 1;
        if (a->tv_usec < b->tv_usec)
                return -1;
        return 0;
}

void tv_add(struct timeval *a, struct timeval *b) {
        a->tv_usec += b->tv_usec;
        a->tv_sec += b->tv_sec + (a->tv_usec / 1000000);
        a->tv_usec %= 1000000;
}

void tv_addms(struct timeval *a, long ms) {
        a->tv_usec += (ms * 1000) % 1000000;
        a->tv_sec += ((ms * 1000) / 1000000) + (a->tv_usec / 1000000);
        a->tv_usec %= 1000000;
}

/**************************************************************/

connection_t *connection_new(int type) {
  connection_t *conn;

  conn = (connection_t *)malloc(sizeof(connection_t));
  if(!conn)
    return NULL;
  memset(conn,0,sizeof(connection_t)); /* zero it out to start */

  conn->type = type;
  if(buf_new(&conn->inbuf, &conn->inbuflen, &conn->inbuf_datalen) < 0 ||
     buf_new(&conn->outbuf, &conn->outbuflen, &conn->outbuf_datalen) < 0)
    return NULL;

  conn->receiver_bucket = 10240; /* should be enough to do the handshake */
  conn->bandwidth = conn->receiver_bucket / 10; /* give it a default */
  return conn;
}

void connection_free(connection_t *conn) {
  assert(conn);

  buf_free(conn->inbuf);
  buf_free(conn->outbuf);
  if(conn->address)
    free(conn->address);
  if(conn->dest_addr)
    free(conn->dest_addr);
  if(conn->dest_port)
    free(conn->dest_port);

  if(connection_speaks_cells(conn)) {
    EVP_CIPHER_CTX_cleanup(&conn->f_ctx);
    EVP_CIPHER_CTX_cleanup(&conn->b_ctx);
  }

  if(conn->s > 0)
    close(conn->s);
  free(conn);
}

int connection_create_listener(RSA *prkey, struct sockaddr_in *local, int type) {
  connection_t *conn;
  int s;
  int one=1;

  s = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
  if (s < 0)
  { 
    log(LOG_ERR,"connection_create_listener(): Socket creation failed.");
    return -1;
  }

  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  if(bind(s,(struct sockaddr *)local,sizeof(*local)) < 0) {
    perror("bind ");
    log(LOG_ERR,"Could not bind to local port %u.",ntohs(local->sin_port));
    return -1;
  }

  /* start local server */
  if(listen(s,SOMAXCONN) < 0) {
    log(LOG_ERR,"Could not listen on local port %u.",ntohs(local->sin_port));
    return -1;
  }

  fcntl(s, F_SETFL, O_NONBLOCK); /* set s to non-blocking */

  conn = connection_new(type);
  if(!conn)
    return -1;
  conn->s = s;

  if(connection_add(conn) < 0) { /* no space, forget it */
    connection_free(conn);
    return -1;
  }

  /* remember things so you can tell the baby sockets */
  memcpy(&conn->local,local,sizeof(struct sockaddr_in));
  conn->prkey = prkey;

  log(LOG_DEBUG,"connection_create_listener(): Listening on local port %u.",ntohs(local->sin_port));

  conn->state = LISTENER_STATE_READY;
  connection_start_reading(conn);

  return 0;
}

int connection_handle_listener_read(connection_t *conn, int new_type, int new_state) {

  int news; /* the new socket */
  connection_t *newconn;
  struct sockaddr_in remote; /* information about the remote peer when connecting to other routers */
  int remotelen = sizeof(struct sockaddr_in); /* length of the remote address */

  news = accept(conn->s,(struct sockaddr *)&remote,&remotelen);
  if (news == -1) { /* accept() error */
    if(errno==EAGAIN)
      return 0; /* he hung up before we could accept(). that's fine. */
    /* else there was a real error. */
    log(LOG_ERR,"connection_handle_listener_read(): accept() failed. Closing.");
    return -1;
  }
  log(LOG_DEBUG,"Connection accepted on socket %d.",news);

  fcntl(news, F_SETFL, O_NONBLOCK); /* set s to non-blocking */

  newconn = connection_new(new_type);
  newconn->s = news;

  if(!connection_speaks_cells(newconn)) {
    newconn->receiver_bucket = -1;
    newconn->bandwidth = -1;
  }

  /* learn things from parent, so we can perform auth */
  memcpy(&newconn->local,&conn->local,sizeof(struct sockaddr_in));
  newconn->prkey = conn->prkey;
//  newconn->address = strdup(get_string_from_remote()) FIXME ;

  if(connection_add(newconn) < 0) { /* no space, forget it */
    connection_free(newconn);
    return -1;
  }

  log(LOG_DEBUG,"connection_handle_listener_read(): socket %d entered state %d.",newconn->s, new_state);
  newconn->state = new_state;
  connection_start_reading(newconn);

  return 0;
}

/* private function, to create the 'local' variable used below */
static int learn_local(struct sockaddr_in *local) {
  /* local host information */
  char localhostname[512];
  struct hostent *localhost;

  /* obtain local host information */
  if(gethostname(localhostname,512) < 0) {
    log(LOG_ERR,"Error obtaining local hostname.");
    return -1;
  }
  localhost = gethostbyname(localhostname);
  if (!localhost) {
    log(LOG_ERR,"Error obtaining local host info.");
    return -1;
  }
  memset((void *)local,0,sizeof(struct sockaddr_in));
  local->sin_family = AF_INET;
  local->sin_addr.s_addr = INADDR_ANY;
  memcpy((void *)&local->sin_addr,(void *)localhost->h_addr,sizeof(struct in_addr));

  return 0;
}

int retry_all_connections(int role, routerinfo_t **router_array, int rarray_len,
  RSA *prkey, uint16_t or_listenport, uint16_t op_listenport, uint16_t ap_listenport) {

  /* start all connections that should be up but aren't */

  routerinfo_t *router;
  int i;
  struct sockaddr_in local; /* local address */

  if(learn_local(&local) < 0)
    return -1;

  local.sin_port = htons(or_listenport);
  if(role & ROLE_OR_CONNECT_ALL) {
    for (i=0;i<rarray_len;i++) {
      router = router_array[i];
      if(!connection_exact_get_by_addr_port(router->addr,router->or_port)) { /* not in the list */
        log(LOG_DEBUG,"retry_all_connections(): connecting to OR %s:%u.",router->address,ntohs(router->or_port));
        connection_or_connect_as_or(router, prkey, &local);
      }
    }
  }

  if(role & ROLE_OR_LISTEN) {
    if(!connection_get_by_type(CONN_TYPE_OR_LISTENER)) {
      connection_or_create_listener(prkey, &local);
    }
  }
      
  if(role & ROLE_OP_LISTEN) {
    local.sin_port = htons(op_listenport);
    if(!connection_get_by_type(CONN_TYPE_OP_LISTENER)) {
      connection_op_create_listener(prkey, &local);
    }
  }

  if(role & ROLE_AP_LISTEN) {
    local.sin_port = htons(ap_listenport);
    if(!connection_get_by_type(CONN_TYPE_AP_LISTENER)) {
      connection_ap_create_listener(NULL, &local); /* no need to tell it the private key. */
    }
  }
 
  return 0;
}

connection_t *connection_connect_to_router_as_op(routerinfo_t *router, RSA *prkey, uint16_t local_or_port) {
  struct sockaddr_in local; /* local address */

  if(learn_local(&local) < 0)
    return NULL;
  local.sin_port = htons(local_or_port);
  return connection_or_connect_as_op(router, prkey, &local);
}

int connection_read_to_buf(connection_t *conn) {
  int read_result;

  if(connection_speaks_cells(conn)) {
    assert(conn->receiver_bucket >= 0);
  }
  if(!connection_speaks_cells(conn)) {
    assert(conn->receiver_bucket < 0);
  }
  read_result = read_to_buf(conn->s, conn->receiver_bucket, &conn->inbuf, &conn->inbuflen,
                            &conn->inbuf_datalen, &conn->inbuf_reached_eof);
//  log(LOG_DEBUG,"connection_read_to_buf(): read_to_buf returned %d.",read_result);
  if(read_result >= 0 && connection_speaks_cells(conn)) {
    conn->receiver_bucket -= read_result;
    if(conn->receiver_bucket <= 0) {

//      log(LOG_DEBUG,"connection_read_to_buf() stopping reading, receiver bucket full.");
      connection_stop_reading(conn);

      /* If we're not in 'open' state here, then we're never going to finish the
       * handshake, because we'll never increment the receiver_bucket. But we
       * can't check for that here, because the buf we just read might have enough
       * on it to finish the handshake. So we check for that in check_conn_read().
       */
    }
  }

  return read_result;
}

int connection_fetch_from_buf(char *string, int len, connection_t *conn) {
  return fetch_from_buf(string, len, &conn->inbuf, &conn->inbuflen, &conn->inbuf_datalen);
}

int connection_wants_to_flush(connection_t *conn) {
  return conn->outbuf_flushlen;
}

int connection_outbuf_too_full(connection_t *conn) {
  return (conn->outbuf_flushlen > 10*CELL_PAYLOAD_SIZE);
}

int connection_flush_buf(connection_t *conn) {
  return flush_buf(conn->s, &conn->outbuf, &conn->outbuflen, &conn->outbuf_flushlen, &conn->outbuf_datalen);
}

int connection_write_to_buf(char *string, int len, connection_t *conn) {
  if(!len)
    return 0;

  if( (conn->type != CONN_TYPE_OR && conn->type != CONN_TYPE_OR) ||
      (!connection_state_is_open(conn)) ||
      (options.LinkPadding == 0) ) {
    /* connection types other than or and op, or or/op not in 'open' state, should flush immediately */
    /* also flush immediately if we're not doing LinkPadding, since otherwise it will never flush */
    connection_start_writing(conn);
    conn->outbuf_flushlen += len;
  }

  return write_to_buf(string, len, &conn->outbuf, &conn->outbuflen, &conn->outbuf_datalen);
}

int connection_receiver_bucket_should_increase(connection_t *conn) {
  assert(conn);

  if(!connection_speaks_cells(conn))
    return 0; /* edge connections don't use receiver_buckets */

  if(conn->receiver_bucket > 10*conn->bandwidth)
    return 0;

  return 1;
}

void connection_increment_receiver_bucket (connection_t *conn) {
  assert(conn);

  if(connection_receiver_bucket_should_increase(conn)) {
    /* yes, the receiver_bucket can become overfull here. But not by much. */
    conn->receiver_bucket += conn->bandwidth*1.1;
    if(connection_state_is_open(conn)) {
      /* if we're in state 'open', then start reading again */
      connection_start_reading(conn);
    }
  }
}

int connection_speaks_cells(connection_t *conn) {
  assert(conn);

  if(conn->type == CONN_TYPE_OR || conn->type == CONN_TYPE_OP)
    return 1;

  return 0;
}

int connection_state_is_open(connection_t *conn) {
  assert(conn);

  if((conn->type == CONN_TYPE_OR && conn->state == OR_CONN_STATE_OPEN) ||
     (conn->type == CONN_TYPE_OP && conn->state == OP_CONN_STATE_OPEN) ||
     (conn->type == CONN_TYPE_AP && conn->state == AP_CONN_STATE_OPEN) ||
     (conn->type == CONN_TYPE_EXIT && conn->state == EXIT_CONN_STATE_OPEN))
    return 1;

  return 0;
}

void connection_send_cell(connection_t *conn) {
  cell_t cell;
  int bytes_in_full_flushlen;

  /* this function only gets called if options.LinkPadding is 1 */
  assert(options.LinkPadding == 1);

  assert(conn);

  if(!connection_speaks_cells(conn)) {
    /* this conn doesn't speak cells. do nothing. */
    return;
  }

  if(!connection_state_is_open(conn)) {
    /* it's not in 'open' state, all data should already be waiting to be flushed */
    assert(conn->outbuf_datalen == conn->outbuf_flushlen);
    return;
  }

#if 0 /* use to send evenly spaced cells, but not padding */
  if(conn->outbuf_datalen - conn->outbuf_flushlen >= sizeof(cell_t)) {
    conn->outbuf_flushlen += sizeof(cell_t); /* instruct it to send a cell */
    connection_start_writing(conn);
  }
#endif

  connection_increment_send_timeval(conn); /* update when we'll send the next cell */

  bytes_in_full_flushlen = conn->bandwidth / 100; /* 10ms worth */
  if(bytes_in_full_flushlen < 10*sizeof(cell_t))
    bytes_in_full_flushlen = 10*sizeof(cell_t); /* but at least 10 cells worth */

  if(conn->outbuf_flushlen > bytes_in_full_flushlen - sizeof(cell_t)) {
    /* if we would exceed bytes_in_full_flushlen by adding a new cell */
    return;
  }

  if(conn->outbuf_datalen - conn->outbuf_flushlen < sizeof(cell_t)) {
    /* we need to queue a padding cell first */
    memset(&cell,0,sizeof(cell_t));
    cell.command = CELL_PADDING;
    connection_write_cell_to_buf(&cell, conn);
  }

  conn->outbuf_flushlen += sizeof(cell_t); /* instruct it to send a cell */
  connection_start_writing(conn);

}

void connection_increment_send_timeval(connection_t *conn) {
  /* add "1000000 * sizeof(cell_t) / conn->bandwidth" microseconds to conn->send_timeval */
  /* FIXME should perhaps use ceil() of this. For now I simply add 1. */

  tv_addms(&conn->send_timeval, 1+1000 * sizeof(cell_t) / conn->bandwidth);
}

void connection_init_timeval(connection_t *conn) {

  assert(conn);

  if(gettimeofday(&conn->send_timeval,NULL) < 0)
    return;

  connection_increment_send_timeval(conn);
}

int connection_send_destroy(aci_t aci, connection_t *conn) {
  cell_t cell;

  assert(conn);

  if(!connection_speaks_cells(conn)) {
     log(LOG_DEBUG,"connection_send_destroy(): At an edge. Marking connection for close.");
     conn->marked_for_close = 1;
     return 0;
  }

  cell.aci = aci;
  cell.command = CELL_DESTROY;
  log(LOG_DEBUG,"connection_send_destroy(): Sending destroy (aci %d).",aci);
  return connection_write_cell_to_buf(&cell, conn);

}

int connection_write_cell_to_buf(cell_t *cellp, connection_t *conn) {
 
  if(connection_encrypt_cell_header(cellp,conn)<0) {
    return -1;
  }

  return connection_write_to_buf((char *)cellp, sizeof(cell_t), conn);
}

int connection_encrypt_cell_header(cell_t *cellp, connection_t *conn) {
  char newheader[8];
  int newsize;
#if 0
  int x;
  char *px;

  printf("Sending: Cell header plaintext: ");
  px = (char *)cellp;
  for(x=0;x<8;x++) {
    printf("%u ",px[x]);
  } 
  printf("\n");
#endif

  if(!EVP_EncryptUpdate(&conn->f_ctx, newheader, &newsize, (char *)cellp, 8)) {
    log(LOG_ERR,"Could not encrypt data for connection %s:%u.",conn->address,ntohs(conn->port));
    return -1;
  }
#if 0
  printf("Sending: Cell header crypttext: ");
  for(x=0;x<8;x++) {
    printf("%u ",newheader[x]);
  }
  printf("\n");
#endif

  memcpy(cellp,newheader,8);
  return 0;
}

int connection_process_inbuf(connection_t *conn) {

  assert(conn);

  switch(conn->type) {
    case CONN_TYPE_OP:
      return connection_op_process_inbuf(conn);
    case CONN_TYPE_OR:
      return connection_or_process_inbuf(conn);
    case CONN_TYPE_EXIT:
      return connection_exit_process_inbuf(conn);
    case CONN_TYPE_AP:
      return connection_ap_process_inbuf(conn);
    default:
      log(LOG_DEBUG,"connection_process_inbuf() got unexpected conn->type.");
      return -1;
  }
}

int connection_package_raw_inbuf(connection_t *conn) {
  int amount_to_process;
  cell_t cell;
  circuit_t *circ;

  assert(conn);
  assert(!connection_speaks_cells(conn));
  /* this function should never get called if the receiver_window is 0 */

  amount_to_process = conn->inbuf_datalen;

  if(!amount_to_process)
    return 0;

  if(amount_to_process > CELL_PAYLOAD_SIZE) {
    cell.length = CELL_PAYLOAD_SIZE;
  } else {
    cell.length = amount_to_process;
  }

  if(connection_fetch_from_buf(cell.payload, cell.length, conn) < 0)
    return -1;

  circ = circuit_get_by_conn(conn);
  if(!circ) {
    log(LOG_DEBUG,"connection_raw_package_inbuf(): conn has no circuits!");
    return -1;
  }

  log(LOG_DEBUG,"connection_raw_package_inbuf(): Packaging %d bytes.",cell.length);
  if(circ->n_conn == conn) { /* send it backward. we're an exit. */
    cell.aci = circ->p_aci;
    cell.command = CELL_DATA;
    if(circuit_deliver_data_cell(&cell, circ, circ->p_conn, 'e') < 0) {
      log(LOG_DEBUG,"connection_raw_package_inbuf(): circuit_deliver_data_cell (backward) failed. Closing.");
      circuit_close(circ);
      return 0;
    }
    assert(circ->n_receive_window > 0);
    if(--circ->n_receive_window <= 0) { /* is it 0 after decrement? */
      connection_stop_reading(circ->n_conn);
      log(LOG_DEBUG,"connection_raw_package_inbuf(): receive_window at exit reached 0.");
      return 0; /* don't process the inbuf any more */
    }
    log(LOG_DEBUG,"connection_raw_package_inbuf(): receive_window at exit is %d",circ->n_receive_window);
  } else { /* send it forward. we're an AP */
    cell.aci = circ->n_aci;
    cell.command = CELL_DATA;
    if(circuit_deliver_data_cell(&cell, circ, circ->n_conn, 'e') < 0) {
      /* yes, we use 'e' here, because the AP connection must *encrypt* its input. */
      log(LOG_DEBUG,"connection_raw_package_inbuf(): circuit_deliver_data_cell (forward) failed. Closing.");
      circuit_close(circ);
      return 0;
    }
    assert(circ->p_receive_window > 0);
    if(--circ->p_receive_window <= 0) { /* is it 0 after decrement? */
      connection_stop_reading(circ->p_conn);
      log(LOG_DEBUG,"connection_raw_package_inbuf(): receive_window at AP reached 0.");
      return 0; /* don't process the inbuf any more */
    }
    log(LOG_DEBUG,"connection_raw_package_inbuf(): receive_window at AP is %d",circ->p_receive_window);
  }
  if(amount_to_process > CELL_PAYLOAD_SIZE)
    log(LOG_DEBUG,"connection_raw_package_inbuf(): recursing.");
    return connection_package_raw_inbuf(conn);
  return 0;
}

int connection_consider_sending_sendme(connection_t *conn) {
  circuit_t *circ;
  cell_t sendme;

  if(connection_outbuf_too_full(conn))
    return 0;

  circ = circuit_get_by_conn(conn);
  if(!circ) {
    log(LOG_DEBUG,"connection_consider_sending_sendme(): Bug: no circuit associated with conn. Closing.");
    return -1;
  }
  sendme.command = CELL_SENDME;
  sendme.length = RECEIVE_WINDOW_INCREMENT;

  if(circ->n_conn == conn) { /* we're at an exit */
    if(circ->p_receive_window < RECEIVE_WINDOW_START-RECEIVE_WINDOW_INCREMENT) {
      log(LOG_DEBUG,"connection_consider_sending_sendme(): Outbuf %d, Queueing sendme back.", conn->outbuf_flushlen);
      circ->p_receive_window += RECEIVE_WINDOW_INCREMENT;
      sendme.aci = circ->p_aci;
      return connection_write_cell_to_buf(&sendme, circ->p_conn); /* (clobbers sendme) */
    }
  } else { /* we're at an AP */
    if(circ->n_receive_window < RECEIVE_WINDOW_START-RECEIVE_WINDOW_INCREMENT) {
      log(LOG_DEBUG,"connection_consider_sending_sendme(): Outbuf %d, Queueing sendme forward.", conn->outbuf_flushlen);
      circ->n_receive_window += RECEIVE_WINDOW_INCREMENT;
      sendme.aci = circ->n_aci;
      return connection_write_cell_to_buf(&sendme, circ->n_conn); /* (clobbers sendme) */
    }
  }
  return 0;
} 

int connection_finished_flushing(connection_t *conn) {

  assert(conn);

//  log(LOG_DEBUG,"connection_finished_flushing() entered. Socket %u.", conn->s);

  switch(conn->type) {
    case CONN_TYPE_AP:
      return connection_ap_finished_flushing(conn);
    case CONN_TYPE_OP:
      return connection_op_finished_flushing(conn);
    case CONN_TYPE_OR:
      return connection_or_finished_flushing(conn);
    case CONN_TYPE_EXIT:
      return connection_exit_finished_flushing(conn);
    default:
      log(LOG_DEBUG,"connection_finished_flushing() got unexpected conn->type.");
      return -1;
  }
}

int connection_process_cell_from_inbuf(connection_t *conn) {
  /* check if there's a whole cell there.
   * if yes, pull it off, decrypt it, and process it.
   */
  char crypted[128];
  char outbuf[1024];
  int outlen;
//  int x;
  cell_t *cellp;

  if(conn->inbuf_datalen < 128) /* entire response available? */
    return 0; /* not yet */

  if(connection_fetch_from_buf(crypted,128,conn) < 0) {
    return -1;
  }

#if 0
  printf("Cell header crypttext: ");
  for(x=0;x<8;x++) {
    printf("%u ",crypted[x]);
  }
  printf("\n");
#endif
  /* decrypt */
  if(!EVP_DecryptUpdate(&conn->b_ctx,(unsigned char *)outbuf,&outlen,crypted,8)) {
    log(LOG_ERR,"connection_process_cell_from_inbuf(): Decryption failed, dropping.");
    return connection_process_inbuf(conn); /* process the remainder of the buffer */
  }
//  log(LOG_DEBUG,"connection_process_cell_from_inbuf(): Cell decrypted (%d bytes).",outlen);
#if 0
  printf("Cell header plaintext: ");
  for(x=0;x<8;x++) {
    printf("%u ",outbuf[x]);
  }
  printf("\n");
#endif

  /* copy the rest of the cell */
  memcpy((char *)outbuf+8, (char *)crypted+8, sizeof(cell_t)-8);
  cellp = (cell_t *)outbuf;
//  log(LOG_DEBUG,"connection_process_cell_from_inbuf(): Decrypted cell is of type %u (ACI %u).",cellp->command,cellp->aci);
  command_process_cell(cellp, conn);

  return connection_process_inbuf(conn); /* process the remainder of the buffer */
}

