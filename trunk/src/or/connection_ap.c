/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

extern or_options_t options; /* command-line and config-file options */

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
      if(connection_package_raw_inbuf(conn) < 0)
        return -1;
      circuit_consider_stop_edge_reading(circuit_get_by_conn(conn), EDGE_AP);
      return 0;
    default:
      log(LOG_DEBUG,"connection_ap_process_inbuf() called in state where I'm waiting. Ignoring buf for now.");
  }

  return 0;
}

int ap_handshake_process_socks(connection_t *conn) {
  char c;
  socks4_t socks4_info; 
  circuit_t *circ;

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
       !socks4_info.destip[3]) { /* not 0.0.0.x */
      log(LOG_NOTICE,"ap_handshake_process_socks(): destip not in form 0.0.0.x.");
      sprintf(conn->dest_tmp, "%d.%d.%d.%d", socks4_info.destip[0],
        socks4_info.destip[1], socks4_info.destip[2], socks4_info.destip[3]);
      conn->dest_addr = strdup(conn->dest_tmp);
      log(LOG_DEBUG,"ap_handshake_process_socks(): Successfully read destip (%s)", conn->dest_addr);
    }

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

  /* find the circuit that we should use, if there is one. */
  circ = circuit_get_by_edge_type(EDGE_AP);

  /* now we're all ready to make an onion or send a begin */

  if(circ && circ->state == CIRCUIT_STATE_OPEN) {
    /* FIXME if circ not yet open, figure out how to queue this begin? */
    /* add it into the linked list of topics on this circuit */
    log(LOG_DEBUG,"ap_handshake_process_socks(): attaching new conn to circ. n_aci %d.", circ->n_aci);
    conn->next_topic = circ->p_conn;
    circ->p_conn = conn;

    if(ap_handshake_send_begin(conn, circ) < 0) {
      circuit_close(circ);
      return -1;
    }
  } else {
    if(ap_handshake_create_onion(conn) < 0) {
      if(circ)
        circuit_close(circ);
      return -1;
    }
  }
  return 0;
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
    if(options.ORPort) { /* we would be connected if he were up. but he's not. */
      log(LOG_DEBUG,"ap_handshake_establish_circuit(): Route's firsthop isn't connected.");
      circuit_close(circ); 
      return -1;
    }

    conn->state = AP_CONN_STATE_OR_WAIT;
    connection_stop_reading(conn); /* Stop listening for input from the AP! */

    if(!n_conn) { /* launch the connection */
      n_conn = connection_or_connect_as_op(firsthop);
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
    if(ap_handshake_send_onion(p_conn, or_conn, circ) < 0) {
      log(LOG_DEBUG,"ap_handshake_n_conn_open(): circuit marked for closing.");
      circuit_close(circ);
      return; /* FIXME will want to try the other circuits too? */
    }
    for(p_conn = p_conn->next_topic; p_conn; p_conn = p_conn->next_topic) { /* start up any other pending topics */
      if(ap_handshake_send_begin(p_conn, circ) < 0) {
        circuit_close(circ);
        return;
      }
    }
    circ = circuit_enumerate_by_naddr_nport(circ, or_conn->addr, or_conn->port);
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

  if(ap_handshake_send_begin(ap_conn, circ) < 0) {
    return -1;
  }

  circ->state = CIRCUIT_STATE_OPEN;
  /* FIXME should set circ->expire to something here */

  return 0;
}

int ap_handshake_send_begin(connection_t *ap_conn, circuit_t *circ) {
  cell_t cell;

  memset(&cell, 0, sizeof(cell_t));
  /* deliver the dest_addr in a data cell */
  cell.command = CELL_DATA;
  cell.aci = circ->n_aci;
  crypto_pseudo_rand(2, cell.payload+2); /* bytes 0-1 is blank, bytes 2-3 are random */
  /* FIXME check for collisions */
  ap_conn->topic_id = ntohs(*(uint16_t *)(cell.payload+2));
  cell.payload[0] = TOPIC_COMMAND_BEGIN;
  snprintf(cell.payload+4, CELL_PAYLOAD_SIZE-4, "%s,%d", ap_conn->dest_addr, ap_conn->dest_port);
  cell.length = strlen(cell.payload+TOPIC_HEADER_SIZE)+1+TOPIC_HEADER_SIZE;
  log(LOG_DEBUG,"ap_handshake_send_begin(): Sending data cell to begin topic %d.", ap_conn->topic_id);
  if(circuit_deliver_data_cell_from_edge(&cell, circ, EDGE_AP) < 0) {
    log(LOG_DEBUG,"ap_handshake_send_begin(): failed to deliver begin cell. Closing.");
    return -1;
  }
  ap_conn->n_receive_topicwindow = TOPICWINDOW_START;
  ap_conn->p_receive_topicwindow = TOPICWINDOW_START;
  ap_conn->state = AP_CONN_STATE_OPEN;
  log(LOG_INFO,"ap_handshake_send_begin(): Address/port sent, ap socket %d, n_aci %d",ap_conn->s,circ->n_aci);
  return 0;
}

int ap_handshake_socks_reply(connection_t *conn, char result) {
  socks4_t socks4_info; 

  assert(conn);

  socks4_info.version = 0;
  socks4_info.command = result;
  socks4_info.destport[0] = socks4_info.destport[1] = 0;
  socks4_info.destip[0] = socks4_info.destip[1] = socks4_info.destip[2] = socks4_info.destip[3] = 0;

  if(connection_write_to_buf((char *)&socks4_info, sizeof(socks4_t), conn) < 0)
    return -1;
  return connection_flush_buf(conn); /* try to flush it, in case we're about to close the conn */
}

int connection_ap_process_data_cell(cell_t *cell, circuit_t *circ) {
  connection_t *conn;
  int topic_command;
  int topic_id;
  static int num_seen=0;

  /* an incoming data cell has arrived */

  assert(cell && circ);

  topic_command = *cell->payload;
  topic_id = ntohs(*(uint16_t *)(cell->payload+2));
  log(LOG_DEBUG,"connection_ap_process_data_cell(): command %d topic %d", topic_command, topic_id);
  num_seen++;
  log(LOG_DEBUG,"connection_ap_process_data_cell(): Now seen %d data cells here.", num_seen);


  circuit_consider_sending_sendme(circ, EDGE_AP);

  for(conn = circ->p_conn; conn && conn->topic_id != topic_id; conn = conn->next_topic) ;

  /* now conn is either NULL, in which case we don't recognize the topic_id, or
   * it is set, in which case cell is talking about this conn.
   */

  if(conn && conn->state != AP_CONN_STATE_OPEN) {
    /* we should not have gotten this cell */
    log(LOG_DEBUG,"connection_ap_process_data_cell(): Got a data cell when not in 'open' state. Dropping.");
    return 0;
  }

  switch(topic_command) {
    case TOPIC_COMMAND_BEGIN:
      log(LOG_INFO,"connection_ap_process_data_cell(): topic begin request unsupported. Dropping.");
      break;
    case TOPIC_COMMAND_DATA:
      if(!conn) {
        log(LOG_DEBUG,"connection_ap_process_data_cell(): data cell dropped, unknown topic %d.",topic_id);
        return 0;
      }
      if(--conn->n_receive_topicwindow < 0) { /* is it below 0 after decrement? */
        log(LOG_DEBUG,"connection_ap_process_data_cell(): receive_topicwindow at exit below 0. Killing.");
        return -1; /* exit node breaking protocol. kill the whole circuit. */
      }
      log(LOG_DEBUG,"connection_ap_process_data_cell(): willing to receive %d more cells from circ",conn->n_receive_topicwindow);

#ifdef USE_ZLIB
      if(connection_decompress_to_buf(cell->payload + TOPIC_HEADER_SIZE,
				      cell->length - TOPIC_HEADER_SIZE, 
				      conn, Z_SYNC_FLUSH) < 0) {
        log(LOG_INFO,"connection_exit_process_data_cell(): write to buf failed. Marking for close.");
        conn->marked_for_close = 1;
        return 0;
      }
#else
      if(connection_write_to_buf(cell->payload + TOPIC_HEADER_SIZE,
                                 cell->length - TOPIC_HEADER_SIZE, conn) < 0) {
        conn->marked_for_close = 1;
        return 0;
      }
#endif
      if(connection_consider_sending_sendme(conn, EDGE_AP) < 0)
        conn->marked_for_close = 1;
      return 0;
    case TOPIC_COMMAND_END:
      if(!conn) {
        log(LOG_DEBUG,"connection_ap_process_data_cell(): end cell dropped, unknown topic %d.",topic_id);
        return 0;
      }
      log(LOG_DEBUG,"connection_ap_process_data_cell(): end cell for topic %d. Removing topic.",topic_id);

      /* go through and identify who points to conn. remove conn from the list. */
#if 0
      if(conn == circ->p_conn) {
        circ->p_conn = conn->next_topic;
      }
      for(prevconn = circ->p_conn; prevconn->next_topic != conn; prevconn = prevconn->next_topic) ;
      prevconn->next_topic = conn->next_topic;
#endif
#if 0
      conn->done_sending = 1;
      shutdown(conn->s, 1); /* XXX check return; refactor NM */
      if (conn->done_receiving)
	conn->marked_for_close = 1;
#endif
      conn->marked_for_close = 1;
      break;
    case TOPIC_COMMAND_CONNECTED:
      if(!conn) {
        log(LOG_DEBUG,"connection_ap_process_data_cell(): connected cell dropped, unknown topic %d.",topic_id);
        break;
      }
      log(LOG_DEBUG,"connection_ap_process_data_cell(): Connected! Notifying application.");
      if(ap_handshake_socks_reply(conn, SOCKS4_REQUEST_GRANTED) < 0) {
        conn->marked_for_close = 1;
      }
      break;
    case TOPIC_COMMAND_SENDME:
      if(!conn) {
        log(LOG_DEBUG,"connection_ap_process_data_cell(): sendme cell dropped, unknown topic %d.",topic_id);
        return 0;
      }
      conn->p_receive_topicwindow += TOPICWINDOW_INCREMENT;
      connection_start_reading(conn);
      connection_package_raw_inbuf(conn); /* handle whatever might still be on the inbuf */
      circuit_consider_stop_edge_reading(circ, EDGE_AP);
      break;
    default:
      log(LOG_DEBUG,"connection_ap_process_data_cell(): unknown topic command %d.",topic_command);
  }
  return 0;
}

int connection_ap_finished_flushing(connection_t *conn) {

  assert(conn && conn->type == CONN_TYPE_AP);

  switch(conn->state) {
    case AP_CONN_STATE_OPEN:
      /* FIXME down the road, we'll clear out circuits that are pending to close */
      connection_stop_writing(conn);
      return connection_consider_sending_sendme(conn, EDGE_AP);
    default:
      log(LOG_DEBUG,"Bug: connection_ap_finished_flushing() called in unexpected state.");
      return 0;
  }

  return 0;
}

int connection_ap_create_listener(struct sockaddr_in *bindaddr) {
  log(LOG_DEBUG,"connection_create_ap_listener starting");
  return connection_create_listener(bindaddr, CONN_TYPE_AP_LISTENER);
}

int connection_ap_handle_listener_read(connection_t *conn) {
  log(LOG_NOTICE,"AP: Received a connection request. Waiting for socksinfo.");
  return connection_handle_listener_read(conn, CONN_TYPE_AP, AP_CONN_STATE_SOCKS_WAIT);
} 

