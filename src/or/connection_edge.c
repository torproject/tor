/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

extern or_options_t options; /* command-line and config-file options */

int connection_edge_process_inbuf(connection_t *conn) {

  assert(conn);
  assert(conn->type == CONN_TYPE_AP || conn->type == CONN_TYPE_EXIT);

  if(conn->inbuf_reached_eof) {
#ifdef HALF_OPEN
    /* eof reached; we're done reading, but we might want to write more. */ 
    conn->done_receiving = 1;
    shutdown(conn->s, 0); /* XXX check return, refactor NM */
    if (conn->done_sending)
      conn->marked_for_close = 1;

    /* XXX Factor out common logic here and in circuit_about_to_close NM */
    circ = circuit_get_by_conn(conn);
    if (!circ)
      return -1;
    
    memset(&cell, 0, sizeof(cell_t));
    cell.command = CELL_DATA;
    cell.length = TOPIC_HEADER_SIZE;
    cell.topic_command = TOPIC_COMMAND_END;
    cell.topic_id = conn->topic_id;
    cell.aci = circ->n_aci;

    if (circuit_deliver_data_cell_from_edge(&cell, circ, conn->type) < 0) {
      log(LOG_DEBUG,"connection_edge_process_inbuf: circuit_deliver_data_cell_from_edge failed.  Closing");
      circuit_close(circ);
    }
    return 0;
#else 
    /* eof reached, kill it. */
    log(LOG_DEBUG,"connection_edge_process_inbuf(): conn reached eof. Closing.");
    return -1;
#endif
  }

  switch(conn->state) {
    case AP_CONN_STATE_SOCKS_WAIT:
      return ap_handshake_process_socks(conn);
    case AP_CONN_STATE_OPEN:
    case EXIT_CONN_STATE_OPEN:
      if(connection_package_raw_inbuf(conn) < 0)
        return -1;
      circuit_consider_stop_edge_reading(circuit_get_by_conn(conn), EDGE_AP);
      return 0;
    case EXIT_CONN_STATE_CONNECTING:
      log(LOG_DEBUG,"connection_edge_process_inbuf(): text from server while in 'connecting' state at exit. Leaving it on buffer.");
      return 0;
  }

  return 0;
}

int connection_edge_send_command(connection_t *conn, circuit_t *circ, int topic_command) {
  cell_t cell;

  assert(conn);

  if(!circ) {
    log(LOG_DEBUG,"connection_edge_send_command(): conn has no circ. Closing.");
    return -1;
  }

  memset(&cell, 0, sizeof(cell_t));
  if(conn->type == CONN_TYPE_AP)
    cell.aci = circ->n_aci;
  else
    cell.aci = circ->p_aci;
  cell.command = CELL_DATA;
  cell.topic_command = topic_command;
  cell.topic_id = conn->topic_id;

  cell.length = TOPIC_HEADER_SIZE;
  log(LOG_INFO,"connection_edge_send_command(): delivering %d cell %s.", topic_command, conn->type == CONN_TYPE_AP ? "forward" : "backward");

  if(circuit_deliver_data_cell_from_edge(&cell, circ, conn->type) < 0) {
    log(LOG_DEBUG,"connection_edge_send_command(): circuit_deliver_data_cell failed. Closing.");
    circuit_close(circ);
    return 0;
  }
  return 0;
}

int connection_edge_process_data_cell(cell_t *cell, circuit_t *circ, int edge_type) {
  connection_t *conn;
  int topic_command;
  int topic_id;
  static int num_seen=0;

  /* an incoming data cell has arrived */

  assert(cell && circ);

  topic_command = cell->topic_command;
  topic_id = cell->topic_id;
  log(LOG_DEBUG,"connection_edge_process_data_cell(): command %d topic %d", topic_command, topic_id);
  num_seen++;
  log(LOG_DEBUG,"connection_edge_process_data_cell(): Now seen %d data cells here.", num_seen);

  circuit_consider_sending_sendme(circ, edge_type);

  if(edge_type == EDGE_AP)
    conn = circ->p_conn;
  else
    conn = circ->n_conn;

  for( ; conn && conn->topic_id != topic_id; conn = conn->next_topic) ;

  /* now conn is either NULL, in which case we don't recognize the topic_id, or
   * it is set, in which case cell is talking about this conn.
   */

  if(conn && conn->state != AP_CONN_STATE_OPEN && conn->state != EXIT_CONN_STATE_OPEN) {
    if(conn->type == CONN_TYPE_EXIT && topic_command == TOPIC_COMMAND_END) {
      log(LOG_INFO,"connection_edge_process_data_cell(): Exit got end before we're connected. Marking for close.");
      conn->marked_for_close = 1;
    } else {
      log(LOG_DEBUG,"connection_edge_process_data_cell(): Got an unexpected data cell, not in 'open' state. Dropping.");
    }
    return 0;
  }

  switch(topic_command) {
    case TOPIC_COMMAND_BEGIN:
      if(edge_type == EDGE_AP) {
        log(LOG_INFO,"connection_edge_process_data_cell(): topic begin request unsupported. Dropping.");
        return 0;
      } else {
        if(conn) {
          log(LOG_INFO,"connection_edge_process_data_cell(): begin cell for known topic. Dropping.");
          return 0;
        }
        return connection_exit_begin_conn(cell, circ);
      }
    case TOPIC_COMMAND_DATA:
      if(!conn) {
        log(LOG_DEBUG,"connection_edge_process_data_cell(): data cell dropped, unknown topic %d.",topic_id);
        return 0;
      }
      if((edge_type == EDGE_AP && --conn->n_receive_topicwindow < 0) ||
         (edge_type == EDGE_EXIT && --conn->p_receive_topicwindow < 0)) { /* is it below 0 after decrement? */
        log(LOG_DEBUG,"connection_edge_process_data_cell(): receive_topicwindow below 0. Killing.");
        return -1; /* somebody's breaking protocol. kill the whole circuit. */
      }

#ifdef USE_ZLIB
      if(connection_decompress_to_buf(cell->payload,
                                      cell->length - TOPIC_HEADER_SIZE, 
                                      conn, Z_SYNC_FLUSH) < 0) {
        log(LOG_INFO,"connection_edge_process_data_cell(): write to buf failed. Marking for close.");
        conn->marked_for_close = 1;
        return 0;
      }
#else
      if(connection_write_to_buf(cell->payload,
                                 cell->length - TOPIC_HEADER_SIZE, conn) < 0) {
        conn->marked_for_close = 1;
        return 0;
      }
#endif
      if(connection_consider_sending_sendme(conn, edge_type) < 0)
        conn->marked_for_close = 1;
      return 0;
    case TOPIC_COMMAND_END:
      if(!conn) {
        log(LOG_DEBUG,"connection_edge_process_data_cell(): end cell dropped, unknown topic %d.",topic_id);
        return 0;
      }
      log(LOG_DEBUG,"connection_edge_process_data_cell(): end cell for topic %d. Removing topic.",topic_id);

      /* go through and identify who points to conn. remove conn from the list. */
#if 0
      if(conn == circ->p_conn) {
        circ->p_conn = conn->next_topic;
      }
      for(prevconn = circ->p_conn; prevconn->next_topic != conn; prevconn = prevconn->next_topic) ;
      prevconn->next_topic = conn->next_topic;
#endif
#ifdef HALF_OPEN
      conn->done_sending = 1;
      shutdown(conn->s, 1); /* XXX check return; refactor NM */
      if (conn->done_receiving)
        conn->marked_for_close = 1;
#endif
      conn->marked_for_close = 1;
      break;
    case TOPIC_COMMAND_CONNECTED:
      if(edge_type == EDGE_EXIT) {
        log(LOG_INFO,"connection_edge_process_data_cell(): 'connected' unsupported at exit. Dropping.");
        return 0;
      }
      if(!conn) {
        log(LOG_DEBUG,"connection_edge_process_data_cell(): connected cell dropped, unknown topic %d.",topic_id);
        break;
      }
      log(LOG_DEBUG,"connection_edge_process_data_cell(): Connected! Notifying application.");
      if(ap_handshake_socks_reply(conn, SOCKS4_REQUEST_GRANTED) < 0) {
        conn->marked_for_close = 1;
      }
      break;
    case TOPIC_COMMAND_SENDME:
      if(!conn) {
        log(LOG_DEBUG,"connection_edge_process_data_cell(): sendme cell dropped, unknown topic %d.",topic_id);
        return 0;
      }
      if(edge_type == EDGE_AP)
        conn->p_receive_topicwindow += TOPICWINDOW_INCREMENT;
      else
        conn->n_receive_topicwindow += TOPICWINDOW_INCREMENT;
      connection_start_reading(conn);
      connection_package_raw_inbuf(conn); /* handle whatever might still be on the inbuf */
      circuit_consider_stop_edge_reading(circ, edge_type);
      break;
    default:
      log(LOG_DEBUG,"connection_edge_process_data_cell(): unknown topic command %d.",topic_command);
  }
  return 0;
}

int connection_edge_finished_flushing(connection_t *conn) {
  int e, len=sizeof(e);

  assert(conn);
  assert(conn->type == CONN_TYPE_AP || conn->type == CONN_TYPE_EXIT);

  switch(conn->state) {
    case EXIT_CONN_STATE_CONNECTING:
      if (getsockopt(conn->s, SOL_SOCKET, SO_ERROR, &e, &len) < 0)  { /* not yet */
        if(errno != EINPROGRESS){
          /* yuck. kill it. */
          log(LOG_DEBUG,"connection_edge_finished_flushing(): in-progress exit connect failed. Removing.");
          return -1;
        } else {
          log(LOG_DEBUG,"connection_edge_finished_flushing(): in-progress exit connect still waiting.");
          return 0; /* no change, see if next time is better */
        }
      }
      /* the connect has finished. */

      log(LOG_DEBUG,"connection_edge_finished_flushing(): Exit connection to %s:%u established.",
          conn->address,conn->port);

      conn->state = EXIT_CONN_STATE_OPEN;
      connection_watch_events(conn, POLLIN); /* stop writing, continue reading */
      if(connection_wants_to_flush(conn)) /* in case there are any queued data cells */
        connection_start_writing(conn);
      return
        connection_edge_send_command(conn, circuit_get_by_conn(conn), TOPIC_COMMAND_CONNECTED) || /* deliver a 'connected' data cell back through the circuit. */
        connection_process_inbuf(conn); /* in case the server has written anything */
    case AP_CONN_STATE_OPEN:
    case EXIT_CONN_STATE_OPEN:
      connection_stop_writing(conn);
#ifdef USE_ZLIB
      if (connection_decompress_to_buf(NULL, 0, conn, Z_SYNC_FLUSH) < 0)
        return 0;
#endif
      return connection_consider_sending_sendme(conn, conn->type);
    default:
      log(LOG_DEBUG,"Bug: connection_edge_finished_flushing() called in unexpected state.");
      return 0;
  }

  return 0;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
