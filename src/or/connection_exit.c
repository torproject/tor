/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

int connection_exit_process_inbuf(connection_t *conn) {

  assert(conn && conn->type == CONN_TYPE_EXIT);

  if(conn->inbuf_reached_eof) {
    /* eof reached, kill it. */
    log(LOG_DEBUG,"connection_exit_process_inbuf(): conn reached eof. Closing.");
    return -1;
  }

  log(LOG_DEBUG,"connection_exit_process_inbuf(): state %d.",conn->state);

  switch(conn->state) {
    case EXIT_CONN_STATE_CONNECTING:
      log(LOG_DEBUG,"connection_exit_process_inbuf(): text from server while in 'connecting' state. Leaving it on buffer.");
      return 0;
    case EXIT_CONN_STATE_OPEN:
      if(connection_package_raw_inbuf(conn) < 0)
        return -1;
      circuit_consider_stop_edge_reading(circuit_get_by_conn(conn), EDGE_EXIT);
      return 0;
  }
  return 0;
}

int connection_exit_finished_flushing(connection_t *conn) {
  int e, len=sizeof(e);

  assert(conn && conn->type == CONN_TYPE_EXIT);

  switch(conn->state) {
    case EXIT_CONN_STATE_CONNECTING:
      if (getsockopt(conn->s, SOL_SOCKET, SO_ERROR, &e, &len) < 0)  { /* not yet */
        if(errno != EINPROGRESS){
          /* yuck. kill it. */
          log(LOG_DEBUG,"connection_exit_finished_flushing(): in-progress connect failed. Removing.");
          return -1;
        } else {
          log(LOG_DEBUG,"connection_exit_finished_flushing(): in-progress connect still waiting.");
          return 0; /* no change, see if next time is better */
        }
      }
      /* the connect has finished. */

      log(LOG_DEBUG,"connection_exit_finished_flushing(): Connection to %s:%u established.",
          conn->address,conn->port);
      
      conn->state = EXIT_CONN_STATE_OPEN;
      connection_watch_events(conn, POLLIN); /* stop writing, continue reading */
      if(connection_wants_to_flush(conn)) /* in case there are any queued data cells */
        connection_start_writing(conn);
      return
        connection_exit_send_connected(conn) || /* deliver a 'connected' data cell back through the circuit. */
        connection_process_inbuf(conn); /* in case the server has written anything */
    case EXIT_CONN_STATE_OPEN:
      /* FIXME down the road, we'll clear out circuits that are pending to close */
      log(LOG_DEBUG,"connection_exit_finished_flushing(): finished flushing.");
      connection_stop_writing(conn);
      connection_consider_sending_sendme(conn, EDGE_EXIT);
      return 0;
    default:
      log(LOG_DEBUG,"Bug: connection_exit_finished_flushing() called in unexpected state.");
      return 0;
  }

  return 0;
}

int connection_exit_send_connected(connection_t *conn) {
  circuit_t *circ;
  cell_t cell;

  assert(conn);

  circ = circuit_get_by_conn(conn);

  if(!circ) {
    log(LOG_DEBUG,"connection_exit_send_connected(): client-side sent destroy just as we completed server connection. Closing.");
    return -1;
  }

  memset(&cell, 0, sizeof(cell_t));
  cell.aci = circ->p_aci;
  cell.command = CELL_DATA;
  *(uint16_t *)(cell.payload+2) = htons(conn->topic_id);
  *cell.payload = TOPIC_COMMAND_CONNECTED;
  cell.length = TOPIC_HEADER_SIZE;
  log(LOG_INFO,"connection_exit_send_connected(): passing back cell (aci %d).",circ->p_aci);

  if(circuit_deliver_data_cell_from_edge(&cell, circ, EDGE_EXIT) < 0) {
    log(LOG_DEBUG,"connection_exit_send_connected(): circuit_deliver_data_cell (backward) failed. Closing.");
    circuit_close(circ);
    return 0;
  }
  return 0;
}

int connection_exit_begin_conn(cell_t *cell, circuit_t *circ) {
  connection_t *n_conn;
  char *comma;

  if(!memchr(cell->payload + TOPIC_HEADER_SIZE,0,cell->length - TOPIC_HEADER_SIZE)) {
    log(LOG_WARNING,"connection_exit_begin_conn(): topic begin cell has no \\0. Dropping.");
    return 0;
  }
  comma = strchr(cell->payload + TOPIC_HEADER_SIZE, ',');
  if(!comma) {
    log(LOG_WARNING,"connection_exit_begin_conn(): topic begin cell has no comma. Dropping.");
    return 0;
  }
  *comma = 0;

  if(!atoi(comma+1)) { /* bad port */
    log(LOG_DEBUG,"connection_exit_begin_conn(): topic begin cell has invalid port. Dropping.");
    return 0;
  }

  log(LOG_DEBUG,"connection_exit_begin_conn(): Creating new exit connection.");
  n_conn = connection_new(CONN_TYPE_EXIT);
  if(!n_conn) {
    log(LOG_DEBUG,"connection_exit_begin_conn(): connection_new failed. Closing.");
    return -1;
  }

  cell->payload[0] = 0;
  n_conn->topic_id = ntohs(*(uint16_t *)(cell->payload+2));

  n_conn->address = strdup(cell->payload + TOPIC_HEADER_SIZE);
  n_conn->port = atoi(comma+1);
  n_conn->state = EXIT_CONN_STATE_RESOLVING;
  n_conn->receiver_bucket = -1; /* edge connections don't do receiver buckets */
  n_conn->bandwidth = -1;
  n_conn->s = -1; /* not yet valid */
  n_conn->n_receive_topicwindow = TOPICWINDOW_START;
  n_conn->p_receive_topicwindow = TOPICWINDOW_START;
  if(connection_add(n_conn) < 0) { /* no space, forget it */
    log(LOG_DEBUG,"connection_exit_begin_conn(): connection_add failed. Closing.");
    connection_free(n_conn);
    return -1;
  }

  /* add it into the linked list of topics on this circuit */
  n_conn->next_topic = circ->n_conn;
  circ->n_conn = n_conn;

  /* send it off to the gethostbyname farm */
  if(dns_resolve(n_conn) < 0) {
    log(LOG_DEBUG,"connection_exit_begin_conn(): Couldn't queue resolve request.");
    connection_remove(n_conn);
    connection_free(n_conn);
    return 0;
  }

  return 0;
}

int connection_exit_process_data_cell(cell_t *cell, circuit_t *circ) {
  connection_t *conn;
  int topic_command;
  int topic_id;
  static int num_seen=0;

  /* an outgoing data cell has arrived */

  assert(cell && circ);

  topic_command = *cell->payload;
  topic_id = ntohs(*(uint16_t *)(cell->payload+2));
  log(LOG_DEBUG,"connection_exit_process_data_cell(): command %d topic %d", topic_command, topic_id);
  num_seen++;
  log(LOG_DEBUG,"connection_exit_process_data_cell(): Now seen %d data cells here.", num_seen);

  circuit_consider_sending_sendme(circ, EDGE_EXIT);

  for(conn = circ->n_conn; conn && conn->topic_id != topic_id; conn = conn->next_topic) ;

  /* now conn is either NULL, in which case we don't recognize the topic_id, or
   * it is set, in which case cell is talking about this conn.
   */

  if(conn && conn->state != EXIT_CONN_STATE_OPEN) {
    if(topic_command == TOPIC_COMMAND_END) {
      log(LOG_ERR,"connection_exit_process_data_cell(): Got an end before we're connected. Marking for close.");
      conn->marked_for_close = 1;
      return 0;
    } else {
      log(LOG_INFO,"connection_exit_process_data_cell(): Got a non-end data cell when not in 'open' state. Dropping.");
      return 0;
    }
  }

  switch(topic_command) {
    case TOPIC_COMMAND_BEGIN:
      if(conn) {
        log(LOG_INFO,"connection_exit_process_data_cell(): begin cell for known topic. Dropping.");
        return 0;
      }
      return connection_exit_begin_conn(cell, circ);
    case TOPIC_COMMAND_DATA:
      if(!conn) {
        log(LOG_INFO,"connection_exit_process_data_cell(): data cell for unknown topic. Dropping.");
        return 0;
      }
      if(--conn->p_receive_topicwindow < 0) { /* is it below 0 after decrement? */
        log(LOG_DEBUG,"connection_exit_process_data_cell(): receive_topicwindow at exit below 0. Killing.");
        return -1; /* AP breaking protocol. kill the whole circuit. */
      }
      log(LOG_DEBUG,"connection_exit_process_data_cell(): willing to receive %d more cells from circ",conn->p_receive_topicwindow);

      if(conn->state != EXIT_CONN_STATE_OPEN) {
        log(LOG_DEBUG,"connection_exit_process_data_cell(): data received while resolving/connecting. Queueing.");
      }
      log(LOG_DEBUG,"connection_exit_process_data_cell(): put %d bytes on outbuf.",cell->length - TOPIC_HEADER_SIZE);
      if(connection_write_to_buf(cell->payload + TOPIC_HEADER_SIZE,
                                 cell->length - TOPIC_HEADER_SIZE, conn) < 0) {
        log(LOG_INFO,"connection_exit_process_data_cell(): write to buf failed. Marking for close.");
        conn->marked_for_close = 1;
        return 0;
      }
      if(connection_consider_sending_sendme(conn, EDGE_EXIT) < 0)
        conn->marked_for_close = 1;
      return 0;
    case TOPIC_COMMAND_END:
      if(!conn) {
        log(LOG_DEBUG,"connection_exit_process_data_cell(): end cell dropped, unknown topic %d.",topic_id);
        return 0;
      }
      log(LOG_DEBUG,"connection_exit_process_data_cell(): end cell for topic %d. Removing topic.",topic_id);

#if 0
      /* go through and identify who points to conn. remove conn from the list. */
      if(conn == circ->n_conn) {
        circ->n_conn = conn->next_topic;
      }
      for(prevconn = circ->n_conn; prevconn->next_topic != conn; prevconn = prevconn->next_topic) ;
      prevconn->next_topic = conn->next_topic;
#endif
      conn->marked_for_close = 1;
      break;
    case TOPIC_COMMAND_CONNECTED:
      log(LOG_INFO,"connection_exit_process_data_cell(): topic connected request unsupported. Dropping.");
      break;
    case TOPIC_COMMAND_SENDME:
      if(!conn) {
        log(LOG_DEBUG,"connection_exit_process_data_cell(): sendme cell dropped, unknown topic %d.",topic_id);
        return 0;
      }
      conn->n_receive_topicwindow += TOPICWINDOW_INCREMENT;
      connection_start_reading(conn);
      connection_package_raw_inbuf(conn); /* handle whatever might still be on the inbuf */
      circuit_consider_stop_edge_reading(circ, EDGE_EXIT);
      break;
    default:
      log(LOG_DEBUG,"connection_exit_process_data_cell(): unknown topic command %d.",topic_command);
  }
  return 0;
}

#if 0
static uint32_t address_to_addr(char *address) {
  struct hostent *rent;
  uint32_t addr;
  char *caddr;

  rent = gethostbyname(address);
  if (!rent) { 
    log(LOG_ERR,"address_to_addr(): Could not resolve dest addr %s.",address);
    return 0;
  }
  memcpy(&addr, rent->h_addr,rent->h_length); 
  addr = ntohl(addr); /* get it back to host order */
  caddr = (char *)&addr;
  log(LOG_DEBUG,"address_to_addr(): addr is %d %d %d %d",
    caddr[0], caddr[1], caddr[2], caddr[3]);
  return addr;
}
#endif

int connection_exit_connect(connection_t *conn) {
  int s; /* for the new socket */
  struct sockaddr_in dest_addr;

  /* all the necessary info is here. Start the connect() */
  s=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
  if (s < 0) {
    log(LOG_ERR,"connection_exit_connect(): Error creating network socket.");
    return -1;
  }
  fcntl(s, F_SETFL, O_NONBLOCK); /* set s to non-blocking */

  memset((void *)&dest_addr,0,sizeof(dest_addr));
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(conn->port);
  dest_addr.sin_addr.s_addr = htonl(conn->addr);

  log(LOG_DEBUG,"connection_exit_connect(): Connecting to %s:%u.",conn->address,conn->port); 

  if(connect(s,(struct sockaddr *)&dest_addr,sizeof(dest_addr)) < 0) {
    if(errno != EINPROGRESS){
      /* yuck. kill it. */
      perror("connect");
      log(LOG_DEBUG,"connection_exit_connect(): Connect failed.");
      return -1;
    } else {
      /* it's in progress. set state appropriately and return. */
      conn->s = s;
      connection_set_poll_socket(conn);
      conn->state = EXIT_CONN_STATE_CONNECTING;

      log(LOG_DEBUG,"connection_exit_connect(): connect in progress, socket %d.",s);
      connection_watch_events(conn, POLLOUT | POLLIN);
      return 0;
    }
  }

  /* it succeeded. we're connected. */
  log(LOG_DEBUG,"connection_exit_connect(): Connection to %s:%u established.",conn->address,conn->port);

  conn->s = s;
  connection_set_poll_socket(conn);
  conn->state = EXIT_CONN_STATE_OPEN;
  if(connection_wants_to_flush(conn)) { /* in case there are any queued data cells */
    log(LOG_ERR,"connection_exit_connect(): tell roger: newly connected conn had data waiting!");
//    connection_start_writing(conn);
  }
//   connection_process_inbuf(conn);
  connection_watch_events(conn, POLLIN);

  /* also, deliver a 'connected' cell back through the circuit. */
  return connection_exit_send_connected(conn);
}

