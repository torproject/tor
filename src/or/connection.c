/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/********* START VARIABLES **********/

extern or_options_t options; /* command-line and config-file options */

extern int global_read_bucket;

char *conn_type_to_string[] = {
  "",            /* 0 */
  "OP listener", /* 1 */
  "OP",          /* 2 */
  "OR listener", /* 3 */
  "OR",          /* 4 */
  "Exit",        /* 5 */
  "App listener",/* 6 */
  "App",         /* 7 */
  "Dir listener",/* 8 */
  "Dir",         /* 9 */
  "DNS worker",  /* 10 */
  "CPU worker",  /* 11 */
};

char *conn_state_to_string[][15] = {
	{ NULL },         /* no type associated with 0 */
  { "ready" }, /* op listener, 0 */
  { "awaiting keys", /* op, 0 */
    "open",              /* 1 */
    "close",             /* 2 */
    "close_wait" },      /* 3 */
  { "ready" }, /* or listener, 0 */
  { "connecting (as OP)",       /* or, 0 */
    "sending keys (as OP)",         /* 1 */
    "connecting (as client)",       /* 2 */
    "sending auth (as client)",     /* 3 */
    "waiting for auth (as client)", /* 4 */
    "sending nonce (as client)",    /* 5 */
    "waiting for auth (as server)", /* 6 */
    "sending auth (as server)",     /* 7 */
    "waiting for nonce (as server)",/* 8 */
    "open" },                       /* 9 */
  { "waiting for dest info",     /* exit, 0 */
    "connecting",                      /* 1 */
    "open" },                          /* 2 */
  { "ready" }, /* app listener, 0 */
  { "", /* 0 */
    "", /* 1 */
    "", /* 2 */
    "awaiting dest info",         /* app, 3 */
    "waiting for OR connection",       /* 4 */
    "open" },                          /* 5 */
  { "ready" }, /* dir listener, 0 */
  { "connecting",                      /* 0 */
    "sending command",                 /* 1 */
    "reading",                         /* 2 */
    "awaiting command",                /* 3 */
    "writing" },                       /* 4 */
  { "idle",                /* dns worker, 0 */
    "busy" },                          /* 1 */
  { "idle",                /* cpu worker, 0 */
    "busy with onion",                 /* 1 */
    "busy with handshake" },           /* 2 */
};

/********* END VARIABLES ************/

static int connection_init_accepted_conn(connection_t *conn);
static int connection_tls_continue_handshake(connection_t *conn);
static int connection_tls_finish_handshake(connection_t *conn);

/**************************************************************/

connection_t *connection_new(int type) {
  connection_t *conn;
  struct timeval now;

  my_gettimeofday(&now);

  conn = (connection_t *)tor_malloc(sizeof(connection_t));
  memset(conn,0,sizeof(connection_t)); /* zero it out to start */

  conn->type = type;
  if(buf_new(&conn->inbuf, &conn->inbuflen, &conn->inbuf_datalen) < 0 ||
     buf_new(&conn->outbuf, &conn->outbuflen, &conn->outbuf_datalen) < 0)
    return NULL;

  conn->receiver_bucket = 10240; /* should be enough to do the handshake */
  conn->bandwidth = conn->receiver_bucket / 10; /* give it a default */

  conn->timestamp_created = now.tv_sec;
  conn->timestamp_lastread = now.tv_sec;
  conn->timestamp_lastwritten = now.tv_sec;

#ifndef USE_TLS
  if (connection_speaks_cells(conn)) {
    conn->f_crypto = crypto_new_cipher_env(CONNECTION_CIPHER);
    if (!conn->f_crypto) {
      free((void *)conn);
      return NULL;
    }
    conn->b_crypto = crypto_new_cipher_env(CONNECTION_CIPHER);
    if (!conn->b_crypto) {
      crypto_free_cipher_env(conn->f_crypto);
      free((void *)conn);
      return NULL;
    }
  }
#endif
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

  if(connection_speaks_cells(conn)) {
    directory_set_dirty();
#ifdef USE_TLS
    if (conn->tls)
      tor_tls_free(conn->tls);
#else
    if (conn->f_crypto)
      crypto_free_cipher_env(conn->f_crypto);
    if (conn->b_crypto)
      crypto_free_cipher_env(conn->b_crypto);
#endif
  }

  if (conn->pkey)
    crypto_free_pk_env(conn->pkey);

  if(conn->s > 0) {
    log_fn(LOG_INFO,"closing fd %d.",conn->s);
    close(conn->s);
  }
  free(conn);
}

int connection_create_listener(struct sockaddr_in *bindaddr, int type) {
  connection_t *conn;
  int s;
  int one=1;

  s = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
  if (s < 0)
  { 
    log_fn(LOG_ERR,"Socket creation failed.");
    return -1;
  }

  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void*)&one, sizeof(one));

  if(bind(s,(struct sockaddr *)bindaddr,sizeof(*bindaddr)) < 0) {
    perror("bind ");
    log(LOG_ERR,"Could not bind to port %u.",ntohs(bindaddr->sin_port));
    return -1;
  }

  if(listen(s,SOMAXCONN) < 0) {
    log(LOG_ERR,"Could not listen on port %u.",ntohs(bindaddr->sin_port));
    return -1;
  }

  set_socket_nonblocking(s);

  conn = connection_new(type);
  if(!conn) {
    log_fn(LOG_DEBUG,"connection_new failed. Giving up.");
    return -1;
  }
  conn->s = s;

  if(connection_add(conn) < 0) { /* no space, forget it */
    log_fn(LOG_DEBUG,"connection_add failed. Giving up.");
    connection_free(conn);
    return -1;
  }

  log_fn(LOG_DEBUG,"%s listening on port %u.",conn_type_to_string[type], ntohs(bindaddr->sin_port));

  conn->state = LISTENER_STATE_READY;
  connection_start_reading(conn);

  return 0;
}

int connection_handle_listener_read(connection_t *conn, int new_type) {

  int news; /* the new socket */
  connection_t *newconn;
  struct sockaddr_in remote; /* information about the remote peer when connecting to other routers */
  int remotelen = sizeof(struct sockaddr_in); /* length of the remote address */
#ifdef MS_WINDOWS
  int e;
#endif

  news = accept(conn->s,(struct sockaddr *)&remote,&remotelen);
  if (news == -1) { /* accept() error */
    if(ERRNO_EAGAIN(errno)) {
#ifdef MS_WINDOWS
      e = correct_socket_errno(conn->s);
      if (ERRNO_EAGAIN(e))
        return 0;
#else
      return 0; /* he hung up before we could accept(). that's fine. */
#endif
    }
    /* else there was a real error. */
    log_fn(LOG_ERR,"accept() failed. Closing.");
    return -1;
  }
  log(LOG_INFO,"Connection accepted on socket %d (child of fd %d).",news, conn->s);

  set_socket_nonblocking(news);

  newconn = connection_new(new_type);
  newconn->s = news;

  if(!connection_speaks_cells(newconn)) {
    newconn->receiver_bucket = -1;
    newconn->bandwidth = -1;
  }

  newconn->address = strdup(inet_ntoa(remote.sin_addr)); /* remember the remote address */
  newconn->addr = ntohl(remote.sin_addr.s_addr);
  newconn->port = ntohs(remote.sin_port);

  if(connection_add(newconn) < 0) { /* no space, forget it */
    connection_free(newconn);
    return 0; /* no need to tear down the parent */
  }

  if(connection_init_accepted_conn(newconn) < 0) {
    connection_free(newconn);
    return 0;
  }
  return 0;
}

static int connection_init_accepted_conn(connection_t *conn) {

  connection_start_reading(conn);

  switch(conn->type) {
    case CONN_TYPE_OR:
#ifdef USE_TLS
      if(connection_tls_start_handshake(conn) < 0)
        return -1;
#else
      conn->state = OR_CONN_STATE_SERVER_AUTH_WAIT;
#endif
      break;
    case CONN_TYPE_AP:
      conn->state = AP_CONN_STATE_SOCKS_WAIT;
      break;
    case CONN_TYPE_DIR:
      conn->state = DIR_CONN_STATE_COMMAND_WAIT;
      break;
  }
  return 0;
}

#ifdef USE_TLS
int connection_tls_start_handshake(connection_t *conn) {
  conn->state = OR_CONN_STATE_HANDSHAKING;
  conn->tls = tor_tls_new(conn->s, options.OnionRouter);
  if(!conn->tls) {
    log_fn(LOG_ERR,"tor_tls_new failed. Closing.");
    return -1;
  }
  connection_start_reading(conn);
  if(connection_tls_continue_handshake(conn) < 0)
    return -1;
  return 0;
}

static int connection_tls_continue_handshake(connection_t *conn) {
  switch(tor_tls_handshake(conn->tls)) {
    case TOR_TLS_ERROR:
    case TOR_TLS_CLOSE:
      log_fn(LOG_DEBUG,"tls error. breaking.");
      return -1;
    case TOR_TLS_DONE:
     return connection_tls_finish_handshake(conn);
    case TOR_TLS_WANTWRITE:
      connection_start_writing(conn);
      return 0;
    case TOR_TLS_WANTREAD: /* handshaking conns are *always* reading */
      return 0;
  }
  return 0;
}

static int connection_tls_finish_handshake(connection_t *conn) {
  crypto_pk_env_t *pk;
  routerinfo_t *router;

  conn->state = OR_CONN_STATE_OPEN;
  directory_set_dirty();
  connection_watch_events(conn, POLLIN);
  if(options.OnionRouter) { /* I'm an OR */
    if(tor_tls_peer_has_cert(conn->tls)) { /* it's another OR */
      pk = tor_tls_verify(conn->tls);
      if(!pk) {
        log_fn(LOG_INFO,"Other side has a cert but it's bad. Closing.");
        return -1;
      }
      router = look up which router I just connected to. /* XXX */
      conn->bandwidth = router->bandwidth;
      conn->addr = router->addr, conn->port = router->or_port;
      conn->pkey = crypto_pk_dup_key(router->pkey);
      if(conn->address)
        free(conn->address);
      conn->address = strdup(router->address);
    } else { /* it's an OP */
      conn->bandwidth = DEFAULT_BANDWIDTH_OP;
    }
  } else { /* I'm a client */
    conn->bandwidth = DEFAULT_BANDWIDTH_OP;
    circuit_n_conn_open(conn); /* send the pending create */
  }
  log_fn(LOG_DEBUG,"tls handshake done, now open.");
  return 0;
}
#endif

/* start all connections that should be up but aren't */
int retry_all_connections(uint16_t or_listenport, uint16_t ap_listenport, uint16_t dir_listenport) {
  struct sockaddr_in bindaddr; /* where to bind */

  if(or_listenport) {
    router_retry_connections();
  }

  memset(&bindaddr,0,sizeof(struct sockaddr_in));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = htonl(INADDR_ANY); /* anyone can connect */

  if(or_listenport) {
    bindaddr.sin_port = htons(or_listenport);
    if(!connection_get_by_type(CONN_TYPE_OR_LISTENER)) {
      connection_create_listener(&bindaddr, CONN_TYPE_OR_LISTENER);
    }
  }

  if(dir_listenport) {
    bindaddr.sin_port = htons(dir_listenport);
    if(!connection_get_by_type(CONN_TYPE_DIR_LISTENER)) {
      connection_create_listener(&bindaddr, CONN_TYPE_DIR_LISTENER);
    }
  }
 
  if(ap_listenport) {
    bindaddr.sin_port = htons(ap_listenport);
    bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* the AP listens only on localhost! */
    if(!connection_get_by_type(CONN_TYPE_AP_LISTENER)) {
      connection_create_listener(&bindaddr, CONN_TYPE_AP_LISTENER);
    }
  }

  return 0;
}

int connection_handle_read(connection_t *conn) {
  struct timeval now;

  my_gettimeofday(&now);
  conn->timestamp_lastread = now.tv_sec;

  switch(conn->type) {
    case CONN_TYPE_OR_LISTENER:
      return connection_handle_listener_read(conn, CONN_TYPE_OR);
    case CONN_TYPE_AP_LISTENER:
      return connection_handle_listener_read(conn, CONN_TYPE_AP);
    case CONN_TYPE_DIR_LISTENER:
      return connection_handle_listener_read(conn, CONN_TYPE_DIR);
  }

  if(connection_read_to_buf(conn) < 0) {
    if(conn->type == CONN_TYPE_DIR && conn->state == DIR_CONN_STATE_CONNECTING) {
       /* it's a directory server and connecting failed: forget about this router */
       /* XXX I suspect pollerr may make Windows not get to this point. :( */
       router_forget_router(conn->addr,conn->port); 
         /* FIXME i don't think router_forget_router works. */
    }
    return -1;
  }
  if(connection_process_inbuf(conn) < 0) {
    //log_fn(LOG_DEBUG,"connection_process_inbuf returned %d.",retval);
    return -1;
  }
  if(!connection_state_is_open(conn) && conn->receiver_bucket == 0) {
    log_fn(LOG_DEBUG,"receiver bucket reached 0 before handshake finished. Closing.");
    return -1;
  }
  return 0;
}

/* return -1 if we want to break conn, else return 0 */
int connection_read_to_buf(connection_t *conn) {
  int result;
  int at_most;

  assert((connection_speaks_cells(conn) && conn->receiver_bucket >= 0) ||
         (!connection_speaks_cells(conn) && conn->receiver_bucket < 0));

  if(options.LinkPadding) {
    at_most = global_read_bucket;
  } else {
    /* do a rudimentary round-robin so one connection can't hog a thickpipe */
    if(connection_speaks_cells(conn)) {
      at_most = 10*(CELL_NETWORK_SIZE);
    } else {
      at_most = 10*(CELL_PAYLOAD_SIZE - RELAY_HEADER_SIZE);
    }

    if(at_most > global_read_bucket)
      at_most = global_read_bucket;
  }

  if(conn->receiver_bucket >= 0 && at_most > conn->receiver_bucket)
    at_most = conn->receiver_bucket;

#ifdef USE_TLS
  if(connection_speaks_cells(conn) && conn->state != OR_CONN_STATE_CONNECTING) {
    if(conn->state == OR_CONN_STATE_HANDSHAKING)
      return connection_tls_continue_handshake(conn);

    /* else open, or closing */
    result = read_to_buf_tls(conn->tls, at_most, &conn->inbuf,
                             &conn->inbuflen, &conn->inbuf_datalen);

    switch(result) {
      case TOR_TLS_ERROR:
      case TOR_TLS_CLOSE:
        log_fn(LOG_DEBUG,"tls error. breaking.");
        return -1; /* XXX deal with close better */
      case TOR_TLS_WANTWRITE:
        connection_start_writing(conn);
        return 0;
      case TOR_TLS_WANTREAD: /* we're already reading */
      case TOR_TLS_DONE: /* no data read, so nothing to process */
        return 0;
    }
  } else
#endif
  {
    result = read_to_buf(conn->s, at_most, &conn->inbuf, &conn->inbuflen,
                         &conn->inbuf_datalen, &conn->inbuf_reached_eof);
//  log(LOG_DEBUG,"connection_read_to_buf(): read_to_buf returned %d.",read_result);

    if(result < 0)
      return -1;
  }

  global_read_bucket -= result; assert(global_read_bucket >= 0);
  if(connection_speaks_cells(conn))
    conn->receiver_bucket -= result;
  if(conn->receiver_bucket == 0 || global_read_bucket == 0) {
    log_fn(LOG_DEBUG,"buckets (%d, %d) exhausted. Pausing.", global_read_bucket, conn->receiver_bucket);
    conn->wants_to_read = 1;
    connection_stop_reading(conn);
  }
  return 0;
}

int connection_fetch_from_buf(char *string, int len, connection_t *conn) {
  return fetch_from_buf(string, len, &conn->inbuf, &conn->inbuflen, &conn->inbuf_datalen);
}

int connection_find_on_inbuf(char *string, int len, connection_t *conn) {
  return find_on_inbuf(string, len, conn->inbuf, conn->inbuf_datalen);
}

int connection_wants_to_flush(connection_t *conn) {
  return conn->outbuf_flushlen;
}

int connection_outbuf_too_full(connection_t *conn) {
  return (conn->outbuf_flushlen > 10*CELL_PAYLOAD_SIZE);
}

int connection_flush_buf(connection_t *conn) {
  return flush_buf(conn->s, &conn->outbuf, &conn->outbuflen,
                   &conn->outbuf_flushlen, &conn->outbuf_datalen);
}

/* return -1 if you want to break the conn, else return 0 */
int connection_handle_write(connection_t *conn) {
  struct timeval now;

  if(connection_is_listener(conn)) {
    log_fn(LOG_DEBUG,"Got a listener socket. Can't happen!");
    return -1;
  }

  my_gettimeofday(&now);
  conn->timestamp_lastwritten = now.tv_sec;

#ifdef USE_TLS
  if(connection_speaks_cells(conn) && conn->state != OR_CONN_STATE_CONNECTING) {
    if(conn->state == OR_CONN_STATE_HANDSHAKING) {
      connection_stop_writing(conn);
      return connection_tls_continue_handshake(conn);
    }

    /* else open, or closing */
    switch(flush_buf_tls(conn->tls, &conn->outbuf, &conn->outbuflen,
                         &conn->outbuf_flushlen, &conn->outbuf_datalen)) {
      case TOR_TLS_ERROR:
      case TOR_TLS_CLOSE:
        log_fn(LOG_DEBUG,"tls error. breaking.");
        return -1; /* XXX deal with close better */
      case TOR_TLS_WANTWRITE:
        /* we're already writing */
        return 0;
      case TOR_TLS_WANTREAD:
        /* Make sure to avoid a loop if the receive buckets are empty. */
        if(!connection_is_reading(conn)) {
          connection_stop_writing(conn);
          conn->wants_to_write = 1;
          /* we'll start reading again when the next second arrives,
           * and then also start writing again.
           */
        }
        /* else no problem, we're already reading */
        return 0;
      case TOR_TLS_DONE:
      /* for TOR_TLS_DONE, fall through to check if the flushlen
       * is empty, so we can stop writing.
       */  
    }
  } else
#endif
  {
    if(flush_buf(conn->s, &conn->outbuf, &conn->outbuflen,
                 &conn->outbuf_flushlen, &conn->outbuf_datalen) < 0)
      return -1;
      /* conns in CONNECTING state will fall through... */
  }

  if(!connection_wants_to_flush(conn)) /* it's done flushing */
    if(connection_finished_flushing(conn) < 0) /* ...and get handled here. */
      return -1;

  return 0;
}

int connection_write_to_buf(char *string, int len, connection_t *conn) {

  if(!len)
    return 0;

  if(conn->marked_for_close)
    return 0;

  if( (!connection_speaks_cells(conn)) ||
      (!connection_state_is_open(conn)) ||
      (options.LinkPadding == 0) ) {
    /* connection types other than or, or or not in 'open' state, should flush immediately */
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

  if(conn->receiver_bucket > 9*conn->bandwidth)
    return 0;

  return 1;
}

int connection_is_listener(connection_t *conn) {
  if(conn->type == CONN_TYPE_OR_LISTENER ||
     conn->type == CONN_TYPE_AP_LISTENER ||
     conn->type == CONN_TYPE_DIR_LISTENER)
    return 1;
  return 0;
}

int connection_state_is_open(connection_t *conn) {
  assert(conn);

  if((conn->type == CONN_TYPE_OR && conn->state == OR_CONN_STATE_OPEN) ||
     (conn->type == CONN_TYPE_AP && conn->state == AP_CONN_STATE_OPEN) ||
     (conn->type == CONN_TYPE_EXIT && conn->state == EXIT_CONN_STATE_OPEN))
    return 1;

  return 0;
}

int connection_send_destroy(aci_t aci, connection_t *conn) {
  cell_t cell;

  assert(conn);

  if(!connection_speaks_cells(conn)) {
     log_fn(LOG_INFO,"Aci %d: At an edge. Marking connection for close.", aci);
     conn->marked_for_close = 1;
     return 0;
  }

  memset(&cell, 0, sizeof(cell_t));
  cell.aci = aci;
  cell.command = CELL_DESTROY;
  log_fn(LOG_INFO,"Sending destroy (aci %d).",aci);
  return connection_write_cell_to_buf(&cell, conn);
}

int connection_write_cell_to_buf(const cell_t *cellp, connection_t *conn) {
  char networkcell[CELL_NETWORK_SIZE];
  char *n = networkcell;
 
  cell_pack(n, cellp);

#ifndef USE_TLS
  if(connection_encrypt_cell(n,conn)<0) {
    return -1;
  }
#endif

  return connection_write_to_buf(n, CELL_NETWORK_SIZE, conn);
}

#ifndef USE_TLS
int connection_encrypt_cell(char *cellp, connection_t *conn) {
  char cryptcell[CELL_NETWORK_SIZE];
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

  assert(conn);

  if(crypto_cipher_encrypt(conn->f_crypto, cellp, CELL_NETWORK_SIZE, cryptcell)) {
    log(LOG_ERR,"Could not encrypt cell for connection %s:%u.",conn->address,conn->port);
    return -1;
  }
#if 0
  printf("Sending: Cell header crypttext: ");
  px = (char *)&newcell;
  for(x=0;x<8;x++) {
    printf("%u ",px[x]);
  }
  printf("\n");
#endif

  memcpy(cellp,cryptcell,CELL_NETWORK_SIZE);
  return 0;
}
#endif

int connection_process_inbuf(connection_t *conn) {

  assert(conn);

  switch(conn->type) {
    case CONN_TYPE_OR:
      return connection_or_process_inbuf(conn);
    case CONN_TYPE_EXIT:
    case CONN_TYPE_AP:
      return connection_edge_process_inbuf(conn);
    case CONN_TYPE_DIR:
      return connection_dir_process_inbuf(conn);
    case CONN_TYPE_DNSWORKER:
      return connection_dns_process_inbuf(conn); 
    case CONN_TYPE_CPUWORKER:
      return connection_cpu_process_inbuf(conn); 
    default:
      log_fn(LOG_DEBUG,"got unexpected conn->type.");
      return -1;
  }
}

int connection_package_raw_inbuf(connection_t *conn) {
  int amount_to_process;
  cell_t cell;
  circuit_t *circ;

  assert(conn);
  assert(!connection_speaks_cells(conn));

repeat_connection_package_raw_inbuf:

  circ = circuit_get_by_conn(conn);
  if(!circ) {
    log_fn(LOG_DEBUG,"conn has no circuits!");
    return -1;
  }

  if(circuit_consider_stop_edge_reading(circ, conn->type, conn->cpath_layer))
    return 0;

  if(conn->package_window <= 0) {
    log_fn(LOG_ERR,"called with package_window 0. Tell Roger.");
    connection_stop_reading(conn);
    return 0;
  }

  amount_to_process = conn->inbuf_datalen;

  if(!amount_to_process)
    return 0;

  /* Initialize the cell with 0's */
  memset(&cell, 0, sizeof(cell_t));

  if(amount_to_process > CELL_PAYLOAD_SIZE - RELAY_HEADER_SIZE) {
    cell.length = CELL_PAYLOAD_SIZE - RELAY_HEADER_SIZE;
  } else {
    cell.length = amount_to_process;
  }

  connection_fetch_from_buf(cell.payload+RELAY_HEADER_SIZE, cell.length, conn);

  log_fn(LOG_DEBUG,"(%d) Packaging %d bytes (%d waiting).",conn->s,cell.length, conn->inbuf_datalen);


  cell.command = CELL_RELAY;
  SET_CELL_RELAY_COMMAND(cell, RELAY_COMMAND_DATA);
  SET_CELL_STREAM_ID(cell, conn->stream_id);
  cell.length += RELAY_HEADER_SIZE;

  if(conn->type == CONN_TYPE_EXIT) {
    cell.aci = circ->p_aci;
    if(circuit_deliver_relay_cell(&cell, circ, CELL_DIRECTION_IN, NULL) < 0) {
      log_fn(LOG_DEBUG,"circuit_deliver_relay_cell (backward) failed. Closing.");
      circuit_close(circ);
      return 0;
    }
    assert(circ->package_window > 0);
    circ->package_window--;
  } else { /* send it forward. we're an AP */
    assert(conn->type == CONN_TYPE_AP);
    cell.aci = circ->n_aci;
    if(circuit_deliver_relay_cell(&cell, circ, CELL_DIRECTION_OUT, conn->cpath_layer) < 0) {
      log_fn(LOG_DEBUG,"circuit_deliver_relay_cell (forward) failed. Closing.");
      circuit_close(circ);
      return 0;
    }
    assert(conn->cpath_layer->package_window > 0);
    conn->cpath_layer->package_window--;
  }

  assert(conn->package_window > 0);
  if(--conn->package_window <= 0) { /* is it 0 after decrement? */
    connection_stop_reading(conn);
    log_fn(LOG_DEBUG,"conn->package_window reached 0.");
    circuit_consider_stop_edge_reading(circ, conn->type, conn->cpath_layer);
    return 0; /* don't process the inbuf any more */
  }
  log_fn(LOG_DEBUG,"conn->package_window is now %d",conn->package_window);

  /* handle more if there's more, or return 0 if there isn't */
  goto repeat_connection_package_raw_inbuf;
}

int connection_consider_sending_sendme(connection_t *conn, int edge_type) {
  circuit_t *circ;
  cell_t cell;

  if(connection_outbuf_too_full(conn))
    return 0;

  circ = circuit_get_by_conn(conn);
  if(!circ) {
    /* this can legitimately happen if the destroy has already arrived and torn down the circuit */
    log_fn(LOG_DEBUG,"No circuit associated with conn. Skipping.");
    return 0;
  }

  memset(&cell, 0, sizeof(cell_t));
  cell.command = CELL_RELAY;
  SET_CELL_RELAY_COMMAND(cell, RELAY_COMMAND_SENDME);
  SET_CELL_STREAM_ID(cell, conn->stream_id);
  cell.length += RELAY_HEADER_SIZE;

  if(edge_type == EDGE_EXIT)
    cell.aci = circ->p_aci;
  else
    cell.aci = circ->n_aci;

  while(conn->deliver_window < STREAMWINDOW_START - STREAMWINDOW_INCREMENT) {
    log_fn(LOG_DEBUG,"Outbuf %d, Queueing stream sendme.", conn->outbuf_flushlen);
    conn->deliver_window += STREAMWINDOW_INCREMENT;
    if(circuit_deliver_relay_cell(&cell, circ, CELL_DIRECTION(edge_type), conn->cpath_layer) < 0) {
      log_fn(LOG_DEBUG,"circuit_deliver_relay_cell failed. Closing.");
      circuit_close(circ);
      return 0;
    }
  }

  return 0;
}

int connection_finished_flushing(connection_t *conn) {

  assert(conn);

//  log_fn(LOG_DEBUG,"entered. Socket %u.", conn->s);

  switch(conn->type) {
    case CONN_TYPE_OR:
      return connection_or_finished_flushing(conn);
    case CONN_TYPE_AP:
    case CONN_TYPE_EXIT:
      return connection_edge_finished_flushing(conn);
    case CONN_TYPE_DIR:
      return connection_dir_finished_flushing(conn);
    case CONN_TYPE_DNSWORKER:
      return connection_dns_finished_flushing(conn);
    case CONN_TYPE_CPUWORKER:
      return connection_cpu_finished_flushing(conn);
    default:
      log_fn(LOG_DEBUG,"got unexpected conn->type.");
      return -1;
  }
}

int connection_process_cell_from_inbuf(connection_t *conn) {
  /* check if there's a whole cell there.
   * if yes, pull it off, decrypt it if we're not doing TLS, and process it.
   */
#ifndef USE_TLS
  char networkcell[CELL_NETWORK_SIZE];
#endif
  char buf[CELL_NETWORK_SIZE];
//  int x;
  cell_t cell;

  if(conn->inbuf_datalen < CELL_NETWORK_SIZE) /* entire response available? */
    return 0; /* not yet */

#ifdef USE_TLS
  connection_fetch_from_buf(buf, CELL_NETWORK_SIZE, conn);
#else
  connection_fetch_from_buf(networkcell, CELL_NETWORK_SIZE, conn);
#if 0
  printf("Cell header crypttext: ");
  for(x=0;x<8;x++) {
    printf("%u ",crypted[x]);
  }
  printf("\n");
#endif
  /* decrypt */
  if(crypto_cipher_decrypt(conn->b_crypto, networkcell, CELL_NETWORK_SIZE, buf)) {
    log_fn(LOG_ERR,"Decryption failed, dropping.");
    return connection_process_inbuf(conn); /* process the remainder of the buffer */
  }
//  log_fn(LOG_DEBUG,"Cell decrypted (%d bytes).",outlen);
#if 0
  printf("Cell header plaintext: ");
  for(x=0;x<8;x++) {
    printf("%u ",outbuf[x]);
  }
  printf("\n");
#endif
#endif

  /* retrieve cell info from buf (create the host-order struct from the network-order string) */
  cell_unpack(&cell, buf);

//  log_fn(LOG_DEBUG,"Decrypted cell is of type %u (ACI %u).",cellp->command,cellp->aci);
  command_process_cell(&cell, conn);

  return connection_process_inbuf(conn); /* process the remainder of the buffer */
}

void
cell_pack(char *dest, const cell_t *src)
{
  *(uint16_t*)dest     = htons(src->aci);
  *(uint8_t*)(dest+2)  = src->command;
  *(uint8_t*)(dest+3)  = src->length;
  *(uint32_t*)(dest+4) = 0; /* Reserved */
  memcpy(dest+8, src->payload, CELL_PAYLOAD_SIZE);
}

void
cell_unpack(cell_t *dest, const char *src)
{
  dest->aci     = ntohs(*(uint16_t*)(src));
  dest->command = *(uint8_t*)(src+2);
  dest->length  = *(uint8_t*)(src+3);
  dest->seq     = ntohl(*(uint32_t*)(src+4));
  memcpy(dest->payload, src+8, CELL_PAYLOAD_SIZE);
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
