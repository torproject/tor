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

//  log(LOG_DEBUG,"connection_ap_process_inbuf(): state %d.",conn->state);

  switch(conn->state) {
    case AP_CONN_STATE_SOCKS_WAIT:
      return ap_handshake_process_socks(conn);
    case AP_CONN_STATE_OPEN:
      return connection_package_raw_inbuf(conn);
    default:
      log(LOG_DEBUG,"connection_ap_process_inbuf() called in state where I'm waiting. Ignoring buf for now.");
  }

  return 0;
}

int ap_handshake_process_socks(connection_t *conn) {
  char c;
  socks4_t socks4_info; 

  assert(conn);

  log(LOG_DEBUG,"ap_handshake_process_socks() entered.");

  if(!conn->socks_version) { /* try to pull it in */

    if(conn->inbuf_datalen < sizeof(socks4_t)) /* basic info available? */
      return 0; /* not yet */

    if(connection_fetch_from_buf((char *)&socks4_info,sizeof(socks4_t),conn) < 0)
      return -1;

    log(LOG_DEBUG,"ap_handshake_process_socks(): Successfully read socks info.");

    if(socks4_info.version != 4) {
      log(LOG_NOTICE,"ap_handshake_process_socks(): Unrecognized version %d.",socks4_info.version);
      ap_handshake_socks_reply(conn, SOCKS4_REQUEST_REJECT);
      return -1;
    }
    conn->socks_version = socks4_info.version;

    if(socks4_info.command != 1) { /* not a connect? we don't support it. */
      log(LOG_NOTICE,"ap_handshake_process_socks(): command %d not '1'.",socks4_info.command);
      ap_handshake_socks_reply(conn, SOCKS4_REQUEST_REJECT);
      return -1;
    }

    conn->dest_port = ntohs(*(uint16_t*)&socks4_info.destport);
    if(!conn->dest_port) {
      log(LOG_NOTICE,"ap_handshake_process_socks(): Port is zero.");
      ap_handshake_socks_reply(conn, SOCKS4_REQUEST_REJECT);
      return -1;
    }
    log(LOG_NOTICE,"ap_handshake_process_socks(): Dest port is %d.",conn->dest_port);

    if(socks4_info.destip[0] || 
       socks4_info.destip[1] ||
       socks4_info.destip[2] ||
       !socks4_info.destip[3]) { /* must be in form 0.0.0.x, at least for now */
      log(LOG_NOTICE,"ap_handshake_process_socks(): destip not in form 0.0.0.x.");
      ap_handshake_socks_reply(conn, SOCKS4_REQUEST_REJECT);
      return -1;
    }
    log(LOG_DEBUG,"ap_handshake_process_socks(): Successfully read destip (0.0.0.x.)");

  }

  if(!conn->read_username) { /* the socks spec says we've got to read stuff until we get a null */
    for(;;) {
      if(!conn->inbuf_datalen)
        return 0; /* maybe next time */
      if(connection_fetch_from_buf((char *)&c,1,conn) < 0)
        return -1;
      if(!c) {
        conn->read_username = 1;
        log(LOG_DEBUG,"ap_handshake_process_socks(): Successfully read username.");
        break;
      }
    }
  }

  if(!conn->dest_addr) { /* no dest_addr found yet */

    for(;;) {
      if(!conn->inbuf_datalen)
        return 0; /* maybe next time */
      if(connection_fetch_from_buf((char *)&c,1,conn) < 0)
        return -1;
      conn->dest_tmp[conn->dest_tmplen++] = c;
      if(conn->dest_tmplen > 500) {
        log(LOG_NOTICE,"ap_handshake_process_socks(): dest_addr too long!");
        ap_handshake_socks_reply(conn, SOCKS4_REQUEST_REJECT);
        return -1;
      }
      if(!c) { /* we found the null; we're done */
        conn->dest_addr = strdup(conn->dest_tmp);
        log(LOG_NOTICE,"ap_handshake_process_socks(): successfully read dest addr '%s'",
          conn->dest_addr);
        break;
      }
    }
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
      firsthop->address,firsthop->or_port);
  n_conn = connection_twin_get_by_addr_port(firsthop->addr,firsthop->or_port);
  if(!n_conn || n_conn->state != OR_CONN_STATE_OPEN) { /* not currently connected */
    circ->n_addr = firsthop->addr;
    circ->n_port = firsthop->or_port;
    if(global_role & ROLE_OR_CONNECT_ALL) { /* we would be connected if he were up. but he's not. */
      log(LOG_DEBUG,"ap_handshake_establish_circuit(): Route's firsthop isn't connected.");
      circuit_close(circ); 
      return -1;
    }

    conn->state = AP_CONN_STATE_OR_WAIT;
    connection_stop_reading(conn); /* Stop listening for input from the AP! */

    if(!n_conn) { /* launch the connection */
      n_conn = connect_to_router_as_op(firsthop);
      if(!n_conn) { /* connect failed, forget the whole thing */
        log(LOG_DEBUG,"ap_handshake_establish_circuit(): connect to firsthop failed. Closing.");
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
    return ap_handshake_send_onion(conn, n_conn, circ);
  }
}

/* find circuits that are waiting on me, if any, and get them to send the onion */
void ap_handshake_n_conn_open(connection_t *or_conn) {
  circuit_t *circ;
  connection_t *p_conn;

  log(LOG_DEBUG,"ap_handshake_n_conn_open(): Starting.");
  circ = circuit_enumerate_by_naddr_nport(NULL, or_conn->addr, or_conn->port);
  for(;;) {
    if(!circ)
      return;

    p_conn = circ->p_conn;
    if(p_conn->state != AP_CONN_STATE_OR_WAIT) {
      log(LOG_WARNING,"Bug: ap_handshake_n_conn_open() got an ap_conn not in OR_WAIT state.");
    }
    connection_start_reading(p_conn); /* resume listening for reads */
    log(LOG_DEBUG,"ap_handshake_n_conn_open(): Found circ, sending onion.");
    if(ap_handshake_send_onion(p_conn, or_conn, circ)<0) {
      log(LOG_DEBUG,"ap_handshake_n_conn_open(): circuit marked for closing.");
      p_conn->marked_for_close = 1;
      return; /* XXX will want to try the rest too */
    } else {
      circ = circuit_enumerate_by_naddr_nport(circ, or_conn->addr, or_conn->port);
    }
  }
}

int ap_handshake_send_onion(connection_t *ap_conn, connection_t *n_conn, circuit_t *circ) {
  cell_t cell;
  int tmpbuflen, dataleft;
  char *tmpbuf;

  circ->n_aci = get_unique_aci_by_addr_port(circ->n_addr, circ->n_port, ACI_TYPE_BOTH);
  circ->n_conn = n_conn;
  log(LOG_DEBUG,"ap_handshake_send_onion(): n_conn is %s:%u",n_conn->address,n_conn->port);

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

#if 0
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
#endif

  /* deliver the dest_addr in a data cell */
  cell.command = CELL_DATA;
  cell.aci = circ->n_aci;
  strncpy(cell.payload, ap_conn->dest_addr, CELL_PAYLOAD_SIZE);
  cell.length = strlen(cell.payload)+1;
  log(LOG_DEBUG,"ap_handshake_send_onion(): Sending a data cell for addr...");
  if(circuit_deliver_data_cell(&cell, circ, circ->n_conn, 'e') < 0) {
    log(LOG_DEBUG,"ap_handshake_send_onion(): failed to deliver addr cell. Closing.");
    circuit_close(circ);
    return -1;
  }

  /* deliver the dest_port in a data cell */
  cell.command = CELL_DATA;
  cell.aci = circ->n_aci;
  snprintf(cell.payload, CELL_PAYLOAD_SIZE, "%d", ap_conn->dest_port);
  cell.length = strlen(cell.payload)+1;
  log(LOG_DEBUG,"ap_handshake_send_onion(): Sending a data cell for port...");
  if(circuit_deliver_data_cell(&cell, circ, circ->n_conn, 'e') < 0) {
    log(LOG_DEBUG,"ap_handshake_send_onion(): failed to deliver port cell. Closing.");
    circuit_close(circ);
    return -1;
  }

  circ->state = CIRCUIT_STATE_OPEN;
  ap_conn->state = AP_CONN_STATE_OPEN;
  log(LOG_INFO,"ap_handshake_send_onion(): Address/port sent, ap socket %d, n_aci %d",ap_conn->s,circ->n_aci);

  /* FIXME should set circ->expire to something here */

  return 0;
}

int ap_handshake_socks_reply(connection_t *conn, char result) {
  socks4_t socks4_info; 

  assert(conn);

  socks4_info.version = 4;
  socks4_info.command = result;
  socks4_info.destport[0] = socks4_info.destport[1] = 0;
  socks4_info.destip[0] = socks4_info.destip[1] = socks4_info.destip[2] = socks4_info.destip[3] = 0;

  connection_write_to_buf((char *)&socks4_info, sizeof(socks4_t), conn); 
  return connection_flush_buf(conn); /* try to flush it, in case we're about to close the conn */
}

int connection_ap_send_connected(connection_t *conn) {
  assert(conn);

  return ap_handshake_socks_reply(conn, SOCKS4_REQUEST_GRANTED);
}

int connection_ap_process_data_cell(cell_t *cell, connection_t *conn) {

  /* an incoming data cell has arrived */

  assert(conn && conn->type == CONN_TYPE_AP);

  if(conn->state != AP_CONN_STATE_OPEN) {
    /* we should not have gotten this cell */
    log(LOG_DEBUG,"connection_ap_process_data_cell(): Got a data cell when not in 'open' state. Closing.");
    return -1;
  }

//  log(LOG_DEBUG,"connection_ap_process_data_cell(): In state 'open', writing to buf.");

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
      return connection_consider_sending_sendme(conn);
    default:
      log(LOG_DEBUG,"Bug: connection_ap_finished_flushing() called in unexpected state.");
      return 0;
  }

  return 0;

}

int connection_ap_create_listener(crypto_pk_env_t *prkey, struct sockaddr_in *local) {
  log(LOG_DEBUG,"connection_create_ap_listener starting");
  return connection_create_listener(prkey, local, CONN_TYPE_AP_LISTENER);
}

int connection_ap_handle_listener_read(connection_t *conn) {
  log(LOG_NOTICE,"AP: Received a connection request. Waiting for socksinfo.");
  return connection_handle_listener_read(conn, CONN_TYPE_AP, AP_CONN_STATE_SOCKS_WAIT);
} 

