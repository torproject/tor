/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

int connection_exit_begin_conn(cell_t *cell, circuit_t *circ) {
  connection_t *n_conn;
  char *colon;

  if(!memchr(cell->payload + TOPIC_HEADER_SIZE,0,cell->length - TOPIC_HEADER_SIZE)) {
    log(LOG_WARNING,"connection_exit_begin_conn(): topic begin cell has no \\0. Dropping.");
    return 0;
  }
  colon = strchr(cell->payload + TOPIC_HEADER_SIZE, ':');
  if(!colon) {
    log(LOG_WARNING,"connection_exit_begin_conn(): topic begin cell has no colon. Dropping.");
    return 0;
  }
  *colon = 0;

  if(!atoi(colon+1)) { /* bad port */
    log(LOG_DEBUG,"connection_exit_begin_conn(): topic begin cell has invalid port. Dropping.");
    return 0;
  }

  log(LOG_DEBUG,"connection_exit_begin_conn(): Creating new exit connection.");
  n_conn = connection_new(CONN_TYPE_EXIT);
  if(!n_conn) {
    log(LOG_DEBUG,"connection_exit_begin_conn(): connection_new failed. Dropping.");
    return 0;
  }

  cell->payload[0] = 0;
  n_conn->topic_id = ntohs(*(uint16_t *)(cell->payload+2));

  n_conn->address = strdup(cell->payload + TOPIC_HEADER_SIZE);
  n_conn->port = atoi(colon+1);
  n_conn->state = EXIT_CONN_STATE_RESOLVING;
  n_conn->receiver_bucket = -1; /* edge connections don't do receiver buckets */
  n_conn->bandwidth = -1;
  n_conn->s = -1; /* not yet valid */
  n_conn->n_receive_topicwindow = TOPICWINDOW_START;
  n_conn->p_receive_topicwindow = TOPICWINDOW_START;
  if(connection_add(n_conn) < 0) { /* no space, forget it */
    log(LOG_DEBUG,"connection_exit_begin_conn(): connection_add failed. Dropping.");
    connection_free(n_conn);
    return 0;
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

int connection_exit_connect(connection_t *conn) {
  int s; /* for the new socket */
  struct sockaddr_in dest_addr;

  if(router_compare_to_exit_policy(conn) < 0) {
    log(LOG_INFO,"connection_exit_connect(): %s:%d failed exit policy. Closing.", conn->address, conn->port);
    return -1;
  }

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
  return connection_edge_send_command(conn, circuit_get_by_conn(conn), TOPIC_COMMAND_CONNECTED);
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
