/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

extern int global_role; /* from main.c */

int connection_ap_process_inbuf(connection_t *conn) {

  assert(conn && conn->type == CONN_TYPE_AP);

  if(conn->inbuf_reached_eof) {
    /* eof reached, kill it. */
    log(LOG_DEBUG,"connection_ap_process_inbuf(): conn reached eof. Closing.");
    return -1;
  }

  log(LOG_DEBUG,"connection_ap_process_inbuf(): state %d.",conn->state);

  switch(conn->state) {
    case AP_CONN_STATE_SS_WAIT:
      return ap_handshake_process_ss(conn);
    case AP_CONN_STATE_OPEN:
      return connection_package_raw_inbuf(conn);
    default:
      log(LOG_DEBUG,"connection_ap_process_inbuf() called in state where I'm waiting. Ignoring buf for now.");
  }

  return 0;
}

int ap_handshake_process_ss(connection_t *conn) {
  uint16_t len;

  assert(conn);

  log(LOG_DEBUG,"ap_handshake_process_ss() entered.");

  if(!conn->ss_received) { /* try to pull it in */

    if(conn->inbuf_datalen < sizeof(ss_t)) /* entire ss available? */
      return 0; /* not yet */

    if(connection_fetch_from_buf((char *)&conn->ss,sizeof(ss_t),conn) < 0)
      return -1;

    conn->ss_received = sizeof(ss_t);
    log(LOG_DEBUG,"ap_handshake_process_ss(): Successfully read ss.");

    if ((conn->ss.version == 0) || (conn->ss.version != VERSION)) { /* unsupported version */
      log(LOG_DEBUG,"ap_handshake_process_ss(): ss: Unsupported version.");
      return -1;
    }
    if (conn->ss.addr_fmt != SS_ADDR_FMT_ASCII_HOST_PORT) { /* unrecognized address format */
      log(LOG_DEBUG,"ap_handshake_process_ss(): ss: Unrecognized address format.");
      return -1;
    }
  }

  if(!conn->dest_addr) { /* no dest_addr found yet */

    if(conn->inbuf_datalen < sizeof(uint16_t))
      return 0; /* not yet */

    if(connection_fetch_from_buf((char *)&len,sizeof(uint16_t),conn) < 0)
      return -1;

    len = ntohs(len);
    if(len > 512) {
      log(LOG_DEBUG,"ap_handshake_process_ss(): Addr length %d too high.",len);
      return -1;
    }

    conn->dest_addr = malloc(len+1);
    if(!conn->dest_addr) {
      log(LOG_DEBUG,"ap_handshake_process_ss(): Addr malloc failed");
      return -1;
    }

    conn->dest_addr[len] = 0; /* null terminate it */
    conn->dest_addr_len = len;
    log(LOG_DEBUG,"Preparing a dest_addr of %d+1 bytes.",len);
  }
  if(conn->dest_addr_len != conn->dest_addr_received) { /* try to fetch it all in */

    if(conn->inbuf_datalen < conn->dest_addr_len)
      return 0; /* not yet */

    if(connection_fetch_from_buf(conn->dest_addr,conn->dest_addr_len,conn) < 0)
      return -1;
    log(LOG_DEBUG,"ap_handshake_process_ss(): Read dest_addr '%s'.",conn->dest_addr);

    conn->dest_addr_received = conn->dest_addr_len;
  }
  /* now do the same thing for port */
  if(!conn->dest_port) { /* no dest_port found yet */

    if(conn->inbuf_datalen < sizeof(uint16_t))
      return 0; /* not yet */

    if(connection_fetch_from_buf((char *)&len,sizeof(uint16_t),conn) < 0)
      return -1;

    len = ntohs(len);
    if(len > 10) {
      log(LOG_DEBUG,"ap_handshake_process_ss(): Port length %d too high.",len);
      return -1;
    }

    conn->dest_port = malloc(len+1);
    if(!conn->dest_port) {
      log(LOG_DEBUG,"ap_handshake_process_ss(): Port malloc failed");
      return -1;
    }

    conn->dest_port[len] = 0; /* null terminate it */
    conn->dest_port_len = len;
    log(LOG_DEBUG,"Preparing a dest_port of %d+1 bytes.",len);
  }
  if(conn->dest_port_len != conn->dest_port_received) { /* try to fetch it all in */

    if(conn->inbuf_datalen < conn->dest_port_len)
      return 0; /* not yet */

    if(connection_fetch_from_buf(conn->dest_port,conn->dest_port_len,conn) < 0)
      return -1;
    log(LOG_DEBUG,"ap_handshake_process_ss(): Read dest_port (network order) '%s'.",conn->dest_port);

    conn->dest_port_received = conn->dest_port_len;
  }

  /* now we're all ready to make an onion, etc */
  return ap_handshake_create_onion(conn);
}

int ap_handshake_create_onion(connection_t *conn) {
  int i;
  int routelen = 0; /* length of the route */
  unsigned int *route = NULL; /* hops in the route as an array of indexes into rarray */
  unsigned char *onion = NULL; /* holds the onion */
  int onionlen = 0; /* onion length in host order */
  crypt_path_t **cpath = NULL; /* defines the crypt operations that need to be performed on incoming/outgoing data */

  assert(conn);

  /* choose a route */
  route = (unsigned int *)router_new_route(&routelen);
  if (!route) { 
    log(LOG_ERR,"ap_handshake_create_onion(): Error choosing a route through the OR network.");
    return -1;
  }
  log(LOG_DEBUG,"ap_handshake_create_onion(): Chosen a route of length %u : ",routelen);
#if 0
  for (i=routelen-1;i>=0;i--)
  { 
    log(LOG_DEBUG,"ap_handshake_process_ss() : %u : %s:%u, %u",routelen-i,(routerarray[route[i]])->address,ntohs((routerarray[route[i]])->port),RSA_size((routerarray[route[i]])->pkey));
  }
#endif

  /* allocate memory for the crypt path */
  cpath = malloc(routelen * sizeof(crypt_path_t *));
  if (!cpath) { 
    log(LOG_ERR,"ap_handshake_create_onion(): Error allocating memory for cpath.");
    free(route);
    return -1;
  }

  /* create an onion and calculate crypto keys */
  onion = router_create_onion(route,routelen,&onionlen,cpath);
  if (!onion) {
    log(LOG_ERR,"ap_handshake_create_onion(): Error creating an onion.");
    free(route);
    free(cpath); /* it's got nothing in it, since !onion */
    return -1;
  }
  log(LOG_DEBUG,"ap_handshake_create_onion(): Created an onion of size %u bytes.",onionlen);
  log(LOG_DEBUG,"ap_handshake_create_onion(): Crypt path :");
  for (i=0;i<routelen;i++) {
    log(LOG_DEBUG,"ap_handshake_create_onion() : %u/%u",(cpath[i])->forwf, (cpath[i])->backf);
  }

  return ap_handshake_establish_circuit(conn, route, routelen, onion, onionlen, cpath);
}

int ap_handshake_establish_circuit(connection_t *conn, unsigned int *route, int routelen, char *onion,
                                   int onionlen, crypt_path_t **cpath) {
  routerinfo_t *firsthop;
  connection_t *n_conn;
  circuit_t *circ;

  /* now see if we're already connected to the first OR in 'route' */
  firsthop = router_get_first_in_route(route, routelen);
  assert(firsthop); /* should always be defined */
  free(route); /* we don't need it anymore */

  circ = circuit_new(0, conn); /* sets circ->p_aci and circ->p_conn */
  circ->state = CIRCUIT_STATE_OR_WAIT;
  circ->onion = onion;
  circ->onionlen = onionlen;
  circ->cpath = cpath;
  circ->cpathlen = routelen;

  log(LOG_DEBUG,"ap_handshake_establish_circuit(): Looking for firsthop '%s:%u'",
      firsthop->address,ntohs(firsthop->or_port));
  n_conn = connection_twin_get_by_addr_port(firsthop->addr,firsthop->or_port);
  if(!n_conn) { /* not currently connected */
    circ->n_addr = firsthop->addr;
    circ->n_port = firsthop->or_port;
    if(global_role & ROLE_OR_CONNECT_ALL) { /* we would be connected if he were up. but he's not. */
      log(LOG_DEBUG,"ap_handshake_establish_circuit(): Route's firsthop isn't connected.");
      circuit_close(circ); 
      return -1;
    }
    
    /* ok, launch the connection */
    n_conn = connect_to_router_as_op(firsthop);
    if(!n_conn) { /* connect failed, forget the whole thing */
      log(LOG_DEBUG,"ap_handshake_establish_circuit(): connect to firsthop failed. Closing.");
      circuit_close(circ);
      return -1;
    }   
    conn->state = AP_CONN_STATE_OR_WAIT;
    connection_stop_reading(conn); /* Stop listening for input from the AP! */
    return 0; /* return success. The onion/circuit/etc will be taken care of automatically
               * (may already have been) whenever n_conn reaches OR_CONN_STATE_OPEN.
               */ 
  } else { /* it (or a twin) is already open. use it. */
    circ->n_addr = n_conn->addr;
    circ->n_port = n_conn->port;
    return ap_handshake_send_onion(conn, n_conn, circ);
  }
}

/* find the circ that's waiting on me, if any, and get it to send its onion */
int ap_handshake_n_conn_open(connection_t *or_conn) {
  circuit_t *circ;

  log(LOG_DEBUG,"ap_handshake_n_conn_open(): Starting.");
  circ = circuit_get_by_naddr_nport(or_conn->addr, or_conn->port);
  if(!circ)
    return 0; /* i'm ok with that. no need to close the connection or anything. */

  if(circ->p_conn->state != AP_CONN_STATE_OR_WAIT) {
    log(LOG_DEBUG,"Bug: ap_handshake_n_conn_open() got an ap_conn not in OR_WAIT state.");
  }
  connection_start_reading(circ->p_conn); /* resume listening for reads */
  log(LOG_DEBUG,"ap_handshake_n_conn_open(): Found circ, sending onion.");
  return ap_handshake_send_onion(circ->p_conn, or_conn, circ);
}

int ap_handshake_send_onion(connection_t *ap_conn, connection_t *n_conn, circuit_t *circ) {
  cell_t cell;
  int tmpbuflen, dataleft;
  char *tmpbuf;
  char zero=0;

  circ->n_aci = get_unique_aci_by_addr_port(circ->n_addr, circ->n_port, ACI_TYPE_BOTH);
  circ->n_conn = n_conn;
  log(LOG_DEBUG,"ap_handshake_send_onion(): n_conn is %s:%u",n_conn->address,ntohs(n_conn->port));

  /* deliver the onion as one or more create cells */
  cell.command = CELL_CREATE;
  cell.aci = circ->n_aci;

  tmpbuflen = circ->onionlen+4;
  tmpbuf = malloc(tmpbuflen);
  if(!tmpbuf)
    return -1;
  circ->onionlen = htonl(circ->onionlen);
  memcpy(tmpbuf,&circ->onionlen,4);
  circ->onionlen = ntohl(circ->onionlen);
  memcpy(tmpbuf+4, circ->onion, circ->onionlen);

  dataleft = tmpbuflen;
  while(dataleft) {
    cell.command = CELL_CREATE;
    cell.aci = circ->n_aci;
    log(LOG_DEBUG,"ap_handshake_send_onion(): Sending a create cell for the onion...");
    if(dataleft >= CELL_PAYLOAD_SIZE) {
      cell.length = CELL_PAYLOAD_SIZE;
      memcpy(cell.payload, tmpbuf + tmpbuflen - dataleft, CELL_PAYLOAD_SIZE);
      connection_write_cell_to_buf(&cell, n_conn); /* clobbers cell */
      dataleft -= CELL_PAYLOAD_SIZE;
    } else { /* last cell */
      cell.length = dataleft;
      memcpy(cell.payload, tmpbuf + tmpbuflen - dataleft, dataleft);
      connection_write_cell_to_buf(&cell, n_conn); /* clobbers cell */
      dataleft = 0;
    }
  }
  free(tmpbuf);

  /* deliver the ss in a data cell */
  cell.command = CELL_DATA;
  cell.aci = circ->n_aci;
  cell.length = sizeof(ss_t);
  memcpy(cell.payload, &ap_conn->ss, sizeof(ss_t));
  log(LOG_DEBUG,"ap_handshake_send_onion(): Sending a data cell for ss...");
  if(circuit_deliver_data_cell(&cell, circ, circ->n_conn, 'e') < 0) {
    log(LOG_DEBUG,"ap_handshake_send_onion(): failed to deliver ss cell. Closing.");
    circuit_close(circ);
    return -1;
  }

  /* deliver the dest_addr in a data cell */
  cell.command = CELL_DATA;
  cell.aci = circ->n_aci;
  cell.length = ap_conn->dest_addr_len+1;
  strncpy(cell.payload, ap_conn->dest_addr, ap_conn->dest_addr_len+1);
  log(LOG_DEBUG,"ap_handshake_send_onion(): Sending a data cell for addr...");
  if(circuit_deliver_data_cell(&cell, circ, circ->n_conn, 'e') < 0) {
    log(LOG_DEBUG,"ap_handshake_send_onion(): failed to deliver addr cell. Closing.");
    circuit_close(circ);
    return -1;
  }

  /* deliver the dest_port in a data cell */
  cell.command = CELL_DATA;
  cell.aci = circ->n_aci;
  cell.length = ap_conn->dest_port_len+1;
  strncpy(cell.payload, ap_conn->dest_port, ap_conn->dest_port_len+1);
  log(LOG_DEBUG,"ap_handshake_send_onion(): Sending a data cell for port...");
  if(circuit_deliver_data_cell(&cell, circ, circ->n_conn, 'e') < 0) {
    log(LOG_DEBUG,"ap_handshake_send_onion(): failed to deliver port cell. Closing.");
    circuit_close(circ);
    return -1;
  }

  circ->state = CIRCUIT_STATE_OPEN;
  ap_conn->state = AP_CONN_STATE_OPEN;

  /* FIXME should set circ->expire to something here */

  /* now we want to give the AP a "0" byte, because it wants to hear
   * back from us */
  connection_write_to_buf(&zero, 1, ap_conn); /* this does connection_start_writing() too */

  return 0;
}

int connection_ap_process_data_cell(cell_t *cell, connection_t *conn) {

  /* an incoming data cell has arrived */

  assert(conn && conn->type == CONN_TYPE_AP);

  if(conn->state != AP_CONN_STATE_OPEN) {
    /* we should not have gotten this cell */
    log(LOG_DEBUG,"connection_ap_process_data_cell(): Got a data cell when not in 'open' state. Closing.");
    return -1;
  }

  log(LOG_DEBUG,"connection_ap_process_data_cell(): In state 'open', writing to buf.");

  if(connection_write_to_buf(cell->payload, cell->length, conn) < 0)
    return -1;
  return connection_consider_sending_sendme(conn);
}     

int connection_ap_finished_flushing(connection_t *conn) {

  assert(conn && conn->type == CONN_TYPE_AP);

  switch(conn->state) {
    case AP_CONN_STATE_OPEN:
      /* FIXME down the road, we'll clear out circuits that are pending to close */
      connection_stop_writing(conn);
      connection_consider_sending_sendme(conn);
      return 0;
    default:
      log(LOG_DEBUG,"Bug: connection_ap_finished_flushing() called in unexpected state.");
      return 0;
  }

  return 0;

}

int connection_ap_create_listener(RSA *prkey, struct sockaddr_in *local) {
  log(LOG_DEBUG,"connection_create_ap_listener starting");
  return connection_create_listener(prkey, local, CONN_TYPE_AP_LISTENER);
}

int connection_ap_handle_listener_read(connection_t *conn) {
  log(LOG_NOTICE,"AP: Received a connection request. Waiting for SS.");
  return connection_handle_listener_read(conn, CONN_TYPE_AP, AP_CONN_STATE_SS_WAIT);
} 

