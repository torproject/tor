
#include "or.h"

/********* START VARIABLES **********/

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

 /* FIXME should we do these for all connections, or just ORs, or what */
  if(conn->type == CONN_TYPE_OR ||
     conn->type == CONN_TYPE_OP) {
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
  connection_watch_events(conn, POLLIN);

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

  newconn = connection_new(new_type);
  newconn->s = news;

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
  connection_watch_events(newconn, POLLIN);

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
      if(!connection_get_by_addr_port(router->addr,router->or_port)) { /* not in the list */
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
  return read_to_buf(conn->s, &conn->inbuf, &conn->inbuflen, &conn->inbuf_datalen, &conn->inbuf_reached_eof);
}

int connection_fetch_from_buf(char *string, int len, connection_t *conn) {
  return fetch_from_buf(string, len, &conn->inbuf, &conn->inbuflen, &conn->inbuf_datalen);
}

int connection_flush_buf(connection_t *conn) {
  return flush_buf(conn->s, &conn->outbuf, &conn->outbuflen, &conn->outbuf_datalen);
}

int connection_write_to_buf(char *string, int len, connection_t *conn) {
  if(!len)
    return 0;
  connection_watch_events(conn, POLLOUT | POLLIN);
  return write_to_buf(string, len, &conn->outbuf, &conn->outbuflen, &conn->outbuf_datalen);
}

int connection_send_destroy(aci_t aci, connection_t *conn) {
  cell_t cell;

  assert(conn);

  if(conn->type == CONN_TYPE_OP ||
     conn->type == CONN_TYPE_AP ||
     conn->type == CONN_TYPE_EXIT) {
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
  /* FIXME in the future, we should modify windows, etc, here */
 
  if(connection_encrypt_cell_header(cellp,conn)<0) {
    return -1;
  }

  return connection_write_to_buf((char *)cellp, sizeof(cell_t), conn);

}

int connection_encrypt_cell_header(cell_t *cellp, connection_t *conn) {
  char newheader[8];
  int newsize;
  int x;
  char *px;

  printf("Sending: Cell header plaintext: ");
  px = (char *)cellp;
  for(x=0;x<8;x++) {
    printf("%u ",px[x]);
  } 
  printf("\n");

  if(!EVP_EncryptUpdate(&conn->f_ctx, newheader, &newsize, (char *)cellp, 8)) {
    log(LOG_ERR,"Could not encrypt data for connection %s:%u.",conn->address,ntohs(conn->port));
    return -1;
  }
  printf("Sending: Cell header crypttext: ");
  for(x=0;x<8;x++) {
    printf("%u ",newheader[x]);
  }
  printf("\n");

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
  assert(conn->type == CONN_TYPE_EXIT || conn->type == CONN_TYPE_AP);

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
  } else { /* send it forward. we're an AP */
    cell.aci = circ->n_aci;
    cell.command = CELL_DATA;
    if(circuit_deliver_data_cell(&cell, circ, circ->n_conn, 'e') < 0) {
      /* yes, we use 'e' here, because the AP connection must *encrypt* its input. */
      log(LOG_DEBUG,"connection_raw_package_inbuf(): circuit_deliver_data_cell (forward) failed. Closing.");
      circuit_close(circ);
      return 0;
    }
  }
  if(amount_to_process > CELL_PAYLOAD_SIZE)
    return connection_package_raw_inbuf(conn);
  return 0;
}

int connection_finished_flushing(connection_t *conn) {

  assert(conn);

  log(LOG_DEBUG,"connection_finished_flushing() entered. Socket %u.", conn->s);

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
  int x;
  cell_t *cellp;

  if(conn->inbuf_datalen < 128) /* entire response available? */
    return 0; /* not yet */

  if(connection_fetch_from_buf(crypted,128,conn) < 0) {
    return -1;
  }

  printf("Cell header crypttext: ");
  for(x=0;x<8;x++) {
    printf("%u ",crypted[x]);
  }
  printf("\n");
  /* decrypt */
  if(!EVP_DecryptUpdate(&conn->b_ctx,(unsigned char *)outbuf,&outlen,crypted,8)) {
    log(LOG_ERR,"connection_process_cell_from_inbuf(): Decryption failed, dropping.");
    return connection_process_inbuf(conn); /* process the remainder of the buffer */
  }
  log(LOG_DEBUG,"connection_process_cell_from_inbuf(): Cell decrypted (%d bytes).",outlen);
  printf("Cell header plaintext: ");
  for(x=0;x<8;x++) {
    printf("%u ",outbuf[x]);
  }
  printf("\n");

  /* copy the rest of the cell */
  memcpy((char *)outbuf+8, (char *)crypted+8, sizeof(cell_t)-8);
  cellp = (cell_t *)outbuf;
  log(LOG_DEBUG,"connection_process_cell_from_inbuf(): Decrypted cell is of type %u (ACI %u).",cellp->command,cellp->aci);
  command_process_cell(cellp, conn);

  return connection_process_inbuf(conn); /* process the remainder of the buffer */
}

