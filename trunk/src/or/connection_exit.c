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
      return connection_package_raw_inbuf(conn);
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

      log(LOG_DEBUG,"connection_exit_finished_flushing() : Connection to %s:%u established.",
          conn->address,ntohs(conn->port));
      
      conn->state = EXIT_CONN_STATE_OPEN;
      if(connection_wants_to_flush(conn)) /* in case there are any queued data cells */
        connection_start_writing(conn);
      connection_start_reading(conn);
      return 0;
    case EXIT_CONN_STATE_OPEN:
      /* FIXME down the road, we'll clear out circuits that are pending to close */
      connection_stop_writing(conn);
      connection_consider_sending_sendme(conn);
      return 0;
    default:
      log(LOG_DEBUG,"Bug: connection_exit_finished_flushing() called in unexpected state.");
      return 0;
  }

  return 0;
}

int connection_exit_process_data_cell(cell_t *cell, connection_t *conn) {
  struct hostent *rent;
  struct sockaddr_in dest_addr;
  int s; /* for the new socket, if we're on connecting_wait */

  /* an outgoing data cell has arrived */

  assert(conn && conn->type == CONN_TYPE_EXIT);

  switch(conn->state) {
    case EXIT_CONN_STATE_CONNECTING_WAIT:
      log(LOG_DEBUG,"connection_exit_process_data_cell(): state is connecting_wait. cell length %d.", cell->length);
      if(!conn->ss_received) { /* this cell contains the ss */
        if(cell->length != sizeof(ss_t)) {
          log(LOG_DEBUG,"connection_exit_process_data_cell(): Supposed to contain SS but wrong size. Closing.");
          return -1;
        }
        memcpy(&conn->ss, cell->payload, cell->length);
        if(conn->ss.addr_fmt != SS_ADDR_FMT_ASCII_HOST_PORT) { /* unrecognized address format */
          log(LOG_DEBUG,"connection_exit_process_data_cell(): SS has unrecognized address format. Closing.");
          return -1;
        }
        conn->ss_received = 1;
	log(LOG_DEBUG,"connection_exit_process_data_cell(): SS received.");
      } else if (!conn->addr) { /* this cell contains the dest addr */
        if(!memchr(cell->payload,0,cell->length)) {
          log(LOG_DEBUG,"connection_exit_process_data_cell(): dest_addr cell has no \\0. Closing.");
          return -1;
        }
        conn->address = strdup(cell->payload);
        rent = gethostbyname(cell->payload);
        if (!rent) { 
          log(LOG_ERR,"connection_exit_process_data_cell(): Could not resolve dest addr %s.",cell->payload);
          return -1;
        }
        memcpy(&conn->addr, rent->h_addr,rent->h_length); 
	log(LOG_DEBUG,"connection_exit_process_data_cell(): addr is %s.",cell->payload);
      } else if (!conn->port) { /* this cell contains the dest port */
        if(!memchr(cell->payload,'\0',cell->length)) {
          log(LOG_DEBUG,"connection_exit_process_data_cell(): dest_port cell has no \\0. Closing.");
          return -1;
        }
        conn->port = atoi(cell->payload);
        if(!conn->port) { /* bad port */
          log(LOG_DEBUG,"connection_exit_process_data_cell(): dest_port cell isn't a valid number. Closing.");
          return -1;
        }
        /* all the necessary info is here. Start the connect() */
        s=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
        if (s < 0)
        {
          log(LOG_ERR,"connection_exit_process_data_cell(): Error creating network socket.");
          return -1;
        }
        fcntl(s, F_SETFL, O_NONBLOCK); /* set s to non-blocking */
      
        memset((void *)&dest_addr,0,sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = conn->port;
        memcpy((void *)&dest_addr.sin_addr, &conn->addr, sizeof(uint32_t));
      
        log(LOG_DEBUG,"connection_exit_process_data_cell(): Connecting to %s:%u.",conn->address,ntohs(conn->port)); 

        if(connect(s,(struct sockaddr *)&dest_addr,sizeof(dest_addr)) < 0){
          if(errno != EINPROGRESS){
            /* yuck. kill it. */
            log(LOG_DEBUG,"connection_exit_process_data_cell(): Connect failed.");
            return -1;
          } else {
            /* it's in progress. set state appropriately and return. */
            conn->s = s;
            connection_set_poll_socket(conn);
            conn->state = EXIT_CONN_STATE_CONNECTING;
      
            log(LOG_DEBUG,"connection_exit_process_data_cell(): connect in progress, socket %d.",s);
            connection_watch_events(conn, POLLOUT | POLLIN);
            return 0;
          }
        }

        /* it succeeded. we're connected. */
        log(LOG_DEBUG,"connection_exit_process_data_cell(): Connection to %s:%u established.",conn->address,ntohs(conn->port));

        conn->s = s;
        connection_set_poll_socket(conn);
        conn->state = EXIT_CONN_STATE_OPEN;
        connection_watch_events(conn, POLLIN);
	return 0;
      } else {
	log(LOG_DEBUG,"connection_exit_process_data_cell(): in connecting_wait, but I've already received everything. Closing.");
	return -1;
      }
      return 0;
    case EXIT_CONN_STATE_CONNECTING:
      log(LOG_DEBUG,"connection_exit_process_data_cell(): Data receiving while connecting. Queueing.");
      /* we stay listening for writable, so connect() can finish */
      /* fall through to the next state -- write the cell and consider sending back a sendme */
    case EXIT_CONN_STATE_OPEN:
      if(connection_write_to_buf(cell->payload, cell->length, conn) < 0)
        return -1;
      return connection_consider_sending_sendme(conn);
  }

  return 0;
}

