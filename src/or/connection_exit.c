
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
          return 0; /* no change, see if next time is better */
        }
      }
      /* the connect has finished. */

      log(LOG_DEBUG,"connection_exit_finished_flushing() : Connection to %s:%u established.",
          conn->address,ntohs(conn->port));
      
      conn->state = EXIT_CONN_STATE_OPEN;
      connection_watch_events(conn, POLLIN);
      return 0;
    case EXIT_CONN_STATE_OPEN:
      /* FIXME down the road, we'll clear out circuits that are pending to close */
      connection_watch_events(conn, POLLIN);
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
  int retval;
  int s; /* for the new socket, if we're on connecting_wait */

  /* an outgoing data cell has arrived */

  assert(conn && conn->type == CONN_TYPE_EXIT);

  switch(conn->state) {
    case EXIT_CONN_STATE_CONNECTING_WAIT:
      log(LOG_DEBUG,"connection_exit_process_cell(): state is connecting_wait. cell length %d.", cell->length);
      if(!conn->ss_received) { /* this cell contains the ss */
        if(cell->length != sizeof(ss_t)) {
          log(LOG_DEBUG,"connection_exit_process_cell(): Supposed to contain SS but wrong size. Closing.");
          return -1;
        }
        memcpy(&conn->ss, cell->payload, cell->length);
        if(conn->ss.addr_fmt != SS_ADDR_FMT_ASCII_HOST_PORT) { /* unrecognized address format */
          log(LOG_DEBUG,"connection_exit_process_cell(): SS has unrecognized address format. Closing.");
          return -1;
        }
        conn->ss_received = 1;
	log(LOG_DEBUG,"connection_exit_process_cell(): SS received.");
      } else if (!conn->addr) { /* this cell contains the dest addr */
        if(!memchr(cell->payload,0,cell->length)) {
          log(LOG_DEBUG,"connection_exit_process_cell(): dest_addr cell has no \\0. Closing.");
          return -1;
        }
        conn->address = strdup(cell->payload);
        rent = gethostbyname(cell->payload);
        if (!rent) { 
          log(LOG_ERR,"connection_exit_process_cell(): Could not resolve dest addr %s.",cell->payload);
          return -1;
        }
        memcpy(&conn->addr, rent->h_addr,rent->h_length); 
	log(LOG_DEBUG,"connection_exit_process_cell(): addr %s resolves to %d.",cell->payload,conn->addr);
      } else if (!conn->port) { /* this cell contains the dest port */
        if(!memchr(cell->payload,'\0',cell->length)) {
          log(LOG_DEBUG,"connection_exit_process_cell(): dest_port cell has no \\0. Closing.");
          return -1;
        }
        conn->port = atoi(cell->payload);
        if(!conn->port) { /* bad port */
          log(LOG_DEBUG,"connection_exit_process_cell(): dest_port cell isn't a valid number. Closing.");
          return -1;
        }
        /* all the necessary info is here. Start the connect() */
        s=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
        if (s < 0)
        {
          log(LOG_ERR,"connection_exit_process_cell(): Error creating network socket.");
          return -1;
        }
        fcntl(s, F_SETFL, O_NONBLOCK); /* set s to non-blocking */
      
        memset((void *)&dest_addr,0,sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = conn->port;
        memcpy((void *)&dest_addr.sin_addr, &conn->addr, sizeof(uint32_t));
      
        log(LOG_DEBUG,"connection_exit_process_cell(): Connecting to %s:%u.",conn->address,ntohs(conn->port)); 

        if(connect(s,(struct sockaddr *)&dest_addr,sizeof(dest_addr)) < 0){
          if(errno != EINPROGRESS){
            /* yuck. kill it. */
            log(LOG_DEBUG,"connection_exit_process_cell(): Connect failed.");
            return -1;
          } else {
            /* it's in progress. set state appropriately and return. */
            conn->s = s;
            connection_set_poll_socket(conn);
            conn->state = EXIT_CONN_STATE_CONNECTING;
      
            /* i think only pollout is needed, but i'm curious if pollin ever gets caught -RD */
            log(LOG_DEBUG,"connection_exit_process_cell(): connect in progress, socket %d.",s);
            connection_watch_events(conn, POLLOUT | POLLIN);
            return 0;
          }
        }

        /* it succeeded. we're connected. */
        log(LOG_DEBUG,"connection_exit_process_cell(): Connection to %s:%u established.",conn->address,ntohs(conn->port));

        conn->s = s;
        connection_set_poll_socket(conn);
        conn->state = EXIT_CONN_STATE_OPEN;
        connection_watch_events(conn, POLLIN);
	return 0;
      }
      else {
	log(LOG_DEBUG,"connection_exit_process_cell(): in connecting_wait, but I've already received everything. Closing.");
	return -1;
      }
    case EXIT_CONN_STATE_CONNECTING:
      log(LOG_DEBUG,"connection_exit_process_cell(): Data receiving while connecting. Queueing.");
      retval = connection_write_to_buf(cell->payload, cell->length, conn);
      connection_watch_events(conn, POLLIN); /* make it stop trying to write */
      return retval; 
    case EXIT_CONN_STATE_OPEN:
      return connection_write_to_buf(cell->payload, cell->length, conn);
  }

  return 0;
}

