/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"
#include "tree.h"

extern or_options_t options; /* command-line and config-file options */
extern char *conn_state_to_string[][_CONN_TYPE_MAX+1];

static int connection_ap_handshake_process_socks(connection_t *conn);
static int connection_ap_handshake_attach_circuit(connection_t *conn);
static void connection_ap_handshake_send_begin(connection_t *ap_conn, circuit_t *circ);

static int connection_exit_begin_conn(cell_t *cell, circuit_t *circ);
static void connection_edge_consider_sending_sendme(connection_t *conn);

static uint32_t client_dns_lookup_entry(const char *address);
static void client_dns_set_entry(const char *address, uint32_t val);

void relay_header_pack(char *dest, const relay_header_t *src) {
  uint16_t tmp;

  /* we have to do slow memcpy's here, because we screwed up
   * and made our cell payload not word-aligned. we should fix
   * this someday.
   */

  *(uint8_t*)(dest) = src->command;

  tmp = htons(src->recognized);
  memcpy(dest+1, &tmp, 2);

  tmp = htons(src->stream_id);
  memcpy(dest+3, &tmp, 2);

  memcpy(dest+5, src->integrity, 4);

  tmp = htons(src->length);
  memcpy(dest+9, &tmp, 2);

#if 0
  *(uint8_t*)(dest)    = src->command;
  *(uint16_t*)(dest+1) = htons(src->recognized);
  *(uint16_t*)(dest+3) = htons(src->stream_id);
  memcpy(dest+5, src->integrity, 4);
  *(uint16_t*)(dest+9) = htons(src->length);
#endif
}

void relay_header_unpack(relay_header_t *dest, const char *src) {
  dest->command = *(uint8_t*)(src);

  memcpy(&dest->recognized, src+1, 2);
  dest->recognized = ntohs(dest->recognized);

  memcpy(&dest->stream_id, src+3, 2);
  dest->stream_id = ntohs(dest->stream_id);

  memcpy(dest->integrity, src+5, 4);

  memcpy(&dest->length, src+9, 2);
  dest->length = ntohs(dest->length);

#if 0
  dest->command    = *(uint8_t*)(src);
  dest->recognized = ntohs(*(uint16_t*)(src+1));
  dest->stream_id  = ntohs(*(uint16_t*)(src+3));
  memcpy(dest->integrity, src+5, 4);
  dest->length     = ntohs(*(uint16_t*)(src+9));
#endif
}

/* mark and return -1 if there was an unexpected error with the conn,
 * else return 0.
 */
int connection_edge_process_inbuf(connection_t *conn) {

  assert(conn);
  assert(conn->type == CONN_TYPE_AP || conn->type == CONN_TYPE_EXIT);

  if(conn->inbuf_reached_eof) {
#ifdef HALF_OPEN
    /* eof reached; we're done reading, but we might want to write more. */
    conn->done_receiving = 1;
    shutdown(conn->s, 0); /* XXX check return, refactor NM */
    if (conn->done_sending) {
      connection_mark_for_close(conn, END_STREAM_REASON_DONE);
    } else {
      connection_edge_send_command(conn, circuit_get_by_conn(conn), RELAY_COMMAND_END,
                                   NULL, 0, conn->cpath_layer);
    }
    return 0;
#else
    /* eof reached, kill it. */
    log_fn(LOG_INFO,"conn (fd %d) reached eof. Closing.", conn->s);
    connection_mark_for_close(conn, END_STREAM_REASON_DONE);
    conn->hold_open_until_flushed = 1; /* just because we shouldn't read
                                          doesn't mean we shouldn't write */
    return 0;
#endif
  }

  switch(conn->state) {
    case AP_CONN_STATE_SOCKS_WAIT:
      if(connection_ap_handshake_process_socks(conn) < 0) {
        connection_mark_for_close(conn, END_STREAM_REASON_MISC);
        conn->hold_open_until_flushed = 1;
        return -1;
      }
      return 0;
    case AP_CONN_STATE_OPEN:
    case EXIT_CONN_STATE_OPEN:
      if(conn->package_window <= 0) {
        log_fn(LOG_WARN,"called with package_window %d. Tell Roger.", conn->package_window);
        return 0;
      }
      if(connection_edge_package_raw_inbuf(conn) < 0) {
        connection_mark_for_close(conn, END_STREAM_REASON_MISC);
        return -1;
      }
      return 0;
    case EXIT_CONN_STATE_CONNECTING:
    case AP_CONN_STATE_CIRCUIT_WAIT:
    case AP_CONN_STATE_CONNECT_WAIT:
      log_fn(LOG_INFO,"data from edge while in '%s' state. Leaving it on buffer.",
                      conn_state_to_string[conn->type][conn->state]);
      return 0;
  }
  log_fn(LOG_WARN,"Got unexpected state %d. Closing.",conn->state);
  connection_mark_for_close(conn, END_STREAM_REASON_MISC);
  return -1;
}

int connection_edge_destroy(uint16_t circ_id, connection_t *conn) {
  assert(conn->type == CONN_TYPE_AP || conn->type == CONN_TYPE_EXIT);

  if(conn->marked_for_close)
    return 0; /* already marked; probably got an 'end' */
  log_fn(LOG_INFO,"CircID %d: At an edge. Marking connection for close.",
         circ_id);
  conn->has_sent_end = 1; /* we're closing the circuit, nothing to send to */
  connection_mark_for_close(conn, END_STREAM_REASON_DESTROY);
  conn->hold_open_until_flushed = 1;
  return 0;
}

static char *connection_edge_end_reason(char *payload, uint16_t length) {
  if(length < 1) {
    log_fn(LOG_WARN,"End cell arrived with length 0. Should be at least 1.");
    return "MALFORMED";
  }
  if(*payload < _MIN_END_STREAM_REASON || *payload > _MAX_END_STREAM_REASON) {
    log_fn(LOG_WARN,"Reason for ending (%d) not recognized.",*payload);
    return "MALFORMED";
  }
  switch(*payload) {
    case END_STREAM_REASON_MISC:           return "misc error";
    case END_STREAM_REASON_RESOLVEFAILED:  return "resolve failed";
    case END_STREAM_REASON_CONNECTFAILED:  return "connect failed";
    case END_STREAM_REASON_EXITPOLICY:     return "exit policy failed";
    case END_STREAM_REASON_DESTROY:        return "destroyed";
    case END_STREAM_REASON_DONE:           return "closed normally";
    case END_STREAM_REASON_TIMEOUT:        return "gave up (timeout)";
  }
  assert(0);
  return "";
}

int connection_edge_end(connection_t *conn, char reason, crypt_path_t *cpath_layer) {
  char payload[5];
  int payload_len=1;
  circuit_t *circ;

  if(conn->has_sent_end) {
    log_fn(LOG_WARN,"It appears I've already sent the end. Are you calling me twice?");
    return -1;
  }

  payload[0] = reason;
  if(reason == END_STREAM_REASON_EXITPOLICY) {
    uint32_t tmp = htonl(conn->addr);
    memcpy(payload+1, &tmp, 4);
//    *(uint32_t *)(payload+1) = htonl(conn->addr);
    payload_len += 4;
  }

  circ = circuit_get_by_conn(conn);
  if(circ && !circ->marked_for_close) {
    log_fn(LOG_DEBUG,"Marking conn (fd %d) and sending end.",conn->s);
    connection_edge_send_command(conn, circ, RELAY_COMMAND_END,
                                 payload, payload_len, cpath_layer);
  } else {
    log_fn(LOG_DEBUG,"Marking conn (fd %d); no circ to send end.",conn->s);
  }

  conn->has_sent_end = 1;
  return 0;
}

/* Make a relay cell out of 'relay_command' and 'payload', and
 * send it onto the open circuit 'circ'. If it's a control cell,
 * set fromconn to NULL, else it's the stream that's sending the
 * relay cell. Use cpath_layer NULL if you're responding to the OP;
 * If it's an outgoing cell it must specify the destination hop.
 *
 * If you can't send the cell, mark the circuit for close and
 * return -1. Else return 0.
 */
int connection_edge_send_command(connection_t *fromconn, circuit_t *circ,
                                 int relay_command, void *payload,
                                 int payload_len, crypt_path_t *cpath_layer) {
  cell_t cell;
  relay_header_t rh;
  int cell_direction;

  if(!circ) {
    log_fn(LOG_WARN,"no circ. Closing conn.");
    assert(fromconn);
    connection_mark_for_close(fromconn, 0);
    return -1;
  }

  memset(&cell, 0, sizeof(cell_t));
  cell.command = CELL_RELAY;
  if(cpath_layer) {
    cell.circ_id = circ->n_circ_id;
    cell_direction = CELL_DIRECTION_OUT;
  } else {
    cell.circ_id = circ->p_circ_id;
    cell_direction = CELL_DIRECTION_IN;
  }

  memset(&rh, 0, sizeof(rh));
  rh.command = relay_command;
  if(fromconn)
    rh.stream_id = fromconn->stream_id; /* else it's 0 */
  rh.length = payload_len;
  relay_header_pack(cell.payload, &rh);
  if(payload_len)
    memcpy(cell.payload+RELAY_HEADER_SIZE, payload, payload_len);

  log_fn(LOG_DEBUG,"delivering %d cell %s.", relay_command,
         cell_direction == CELL_DIRECTION_OUT ? "forward" : "backward");

  if(circuit_package_relay_cell(&cell, circ, cell_direction, cpath_layer) < 0) {
    log_fn(LOG_WARN,"circuit_package_relay_cell failed. Closing.");
    circuit_mark_for_close(circ);
    return -1;
  }
  return 0;
}

/* an incoming relay cell has arrived. return -1 if you want to tear down the
 * circuit, else 0. */
int connection_edge_process_relay_cell(cell_t *cell, circuit_t *circ,
                                       connection_t *conn, int edge_type,
                                       crypt_path_t *layer_hint) {
  static int num_seen=0;
  uint32_t addr;
  relay_header_t rh;

  assert(cell && circ);

  relay_header_unpack(&rh, cell->payload);
//  log_fn(LOG_DEBUG,"command %d stream %d", rh.command, rh.stream_id);
  num_seen++;
  log_fn(LOG_DEBUG,"Now seen %d relay cells here.", num_seen);

  /* either conn is NULL, in which case we've got a control cell, or else
   * conn points to the recognized stream. */

  if(conn && conn->state != AP_CONN_STATE_OPEN && conn->state != EXIT_CONN_STATE_OPEN) {
    if(rh.command == RELAY_COMMAND_END) {
      log_fn(LOG_INFO,"Edge got end (%s) before we're connected. Marking for close.",
        connection_edge_end_reason(cell->payload+RELAY_HEADER_SIZE, rh.length));
      conn->has_sent_end = 1; /* we just got an 'end', don't need to send one */
      connection_mark_for_close(conn, 0);
      /* XXX This is where we should check if reason is EXITPOLICY, and reattach */
      /* XXX here we should send a socks reject back if necessary, and hold
       * open til flushed */
      return 0;
    }
    if(conn->type == CONN_TYPE_AP && rh.command == RELAY_COMMAND_CONNECTED) {
      if(conn->state != AP_CONN_STATE_CONNECT_WAIT) {
        log_fn(LOG_WARN,"Got 'connected' while not in state connect_wait. Dropping.");
        return 0;
      }
//      log_fn(LOG_INFO,"Connected! Notifying application.");
      conn->state = AP_CONN_STATE_OPEN;
      if (rh.length >= 4) {
        memcpy(&addr, cell->payload + RELAY_HEADER_SIZE, 4);
        addr = ntohl(addr);
        client_dns_set_entry(conn->socks_request->address, addr);
      }
      log_fn(LOG_INFO,"'connected' received after %d seconds.",
             (int)(time(NULL) - conn->timestamp_lastread));
      circuit_log_path(LOG_INFO,circ);
      connection_ap_handshake_socks_reply(conn, NULL, 0, 1);
      conn->socks_request->has_finished = 1;
      /* handle anything that might have queued */
      if (connection_edge_package_raw_inbuf(conn) < 0) {
        connection_mark_for_close(conn, END_STREAM_REASON_MISC);
        return 0;
      }
      return 0;
    } else {
      log_fn(LOG_WARN,"Got an unexpected relay command %d, in state %d (%s). Closing.",
             rh.command, conn->state, conn_state_to_string[conn->type][conn->state]);
      connection_mark_for_close(conn, END_STREAM_REASON_MISC);
      return -1;
    }
  }

  switch(rh.command) {
    case RELAY_COMMAND_DROP:
      log_fn(LOG_INFO,"Got a relay-level padding cell. Dropping.");
      return 0;
    case RELAY_COMMAND_BEGIN:
      if(edge_type == EDGE_AP) {
        log_fn(LOG_WARN,"relay begin request unsupported at AP. Dropping.");
        return 0;
      }
      if(conn) {
        log_fn(LOG_WARN,"begin cell for known stream. Dropping.");
        return 0;
      }
      connection_exit_begin_conn(cell, circ);
      return 0;
    case RELAY_COMMAND_DATA:
      ++stats_n_data_cells_received;
      if((edge_type == EDGE_AP && --layer_hint->deliver_window < 0) ||
         (edge_type == EDGE_EXIT && --circ->deliver_window < 0)) {
        log_fn(LOG_WARN,"(relay data) circ deliver_window below 0. Killing.");
        connection_mark_for_close(conn, END_STREAM_REASON_MISC);
        return -1;
      }
      log_fn(LOG_DEBUG,"circ deliver_window now %d.", edge_type == EDGE_AP ?
             layer_hint->deliver_window : circ->deliver_window);

      circuit_consider_sending_sendme(circ, edge_type, layer_hint);

      if(!conn) {
        log_fn(LOG_INFO,"data cell dropped, unknown stream.");
        return 0;
      }

      if(--conn->deliver_window < 0) { /* is it below 0 after decrement? */
        log_fn(LOG_WARN,"(relay data) conn deliver_window below 0. Killing.");
        return -1; /* somebody's breaking protocol. kill the whole circuit. */
      }

      stats_n_data_bytes_received += rh.length;
      connection_write_to_buf(cell->payload + RELAY_HEADER_SIZE,
                              rh.length, conn);
      connection_edge_consider_sending_sendme(conn);
      return 0;
    case RELAY_COMMAND_END:
      if(!conn) {
        log_fn(LOG_INFO,"end cell (%s) dropped, unknown stream.",
          connection_edge_end_reason(cell->payload+RELAY_HEADER_SIZE, rh.length));
        return 0;
      }
      if(rh.length >= 5 &&
         *(cell->payload+RELAY_HEADER_SIZE) == END_STREAM_REASON_EXITPOLICY) {

        /* XXX this will never be reached, since we're in 'connect_wait' state
         * but this is only reached when we're in 'open' state. Put it higher. */

        /* No need to close the connection. We'll hold it open while
         * we try a new exit node.
         * cell->payload+RELAY_HEADER_SIZE+1 holds the destination addr.
         */
        memcpy(&addr, cell->payload+RELAY_HEADER_SIZE+1, 4);
        addr = ntohl(addr);
        client_dns_set_entry(conn->socks_request->address, addr);
        /* conn->purpose is still set to general */
        conn->state = AP_CONN_STATE_CIRCUIT_WAIT;
        /* attaching to a dirty circuit is fine */
        if(connection_ap_handshake_attach_circuit(conn) >= 0)
          return 0;
        /* else, conn will get closed below */
      }
/* XXX add to this log_fn the exit node's nickname? */
      log_fn(LOG_INFO,"end cell (%s) for stream %d. Removing stream.",
        connection_edge_end_reason(cell->payload+RELAY_HEADER_SIZE, rh.length),
        conn->stream_id);

#ifdef HALF_OPEN
      conn->done_sending = 1;
      shutdown(conn->s, 1); /* XXX check return; refactor NM */
      if (conn->done_receiving) {
        /* We just *got* an end; no reason to send one. */
        conn->has_sent_end = 1;
        connection_mark_for_close(conn, 0);
        conn->hold_open_until_flushed = 1;
      }
#else
      /* We just *got* an end; no reason to send one. */
      conn->has_sent_end = 1;
      connection_mark_for_close(conn, 0);
      conn->hold_open_until_flushed = 1;
#endif
      return 0;
    case RELAY_COMMAND_EXTEND:
      if(conn) {
        log_fn(LOG_WARN,"'extend' for non-zero stream. Dropping.");
        return 0;
      }
      return circuit_extend(cell, circ);
    case RELAY_COMMAND_EXTENDED:
      if(edge_type == EDGE_EXIT) {
        log_fn(LOG_WARN,"'extended' unsupported at exit. Dropping.");
        return 0;
      }
      log_fn(LOG_DEBUG,"Got an extended cell! Yay.");
      if(circuit_finish_handshake(circ, cell->payload+RELAY_HEADER_SIZE) < 0) {
        log_fn(LOG_WARN,"circuit_finish_handshake failed.");
        return -1;
      }
      if (circuit_send_next_onion_skin(circ)<0) {
        log_fn(LOG_INFO,"circuit_send_next_onion_skin() failed.");
        return -1;
      }
      return 0;
    case RELAY_COMMAND_TRUNCATE:
      if(edge_type == EDGE_AP) {
        log_fn(LOG_WARN,"'truncate' unsupported at AP. Dropping.");
        return 0;
      }
      if(circ->n_conn) {
        connection_send_destroy(circ->n_circ_id, circ->n_conn);
        circ->n_conn = NULL;
      }
      log_fn(LOG_DEBUG, "Processed 'truncate', replying.");
      connection_edge_send_command(NULL, circ, RELAY_COMMAND_TRUNCATED,
                                   NULL, 0, NULL);
      return 0;
    case RELAY_COMMAND_TRUNCATED:
      if(edge_type == EDGE_EXIT) {
        log_fn(LOG_WARN,"'truncated' unsupported at exit. Dropping.");
        return 0;
      }
      circuit_truncated(circ, layer_hint);
      return 0;
    case RELAY_COMMAND_CONNECTED:
      if(conn) {
        log_fn(LOG_WARN,"'connected' unsupported while open. Closing conn.");
        return -1;
      }
      log_fn(LOG_INFO,"'connected' received, no conn attached anymore. Ignoring.");
      return 0;
    case RELAY_COMMAND_SENDME:
      if(!conn) {
        if(edge_type == EDGE_AP) {
          assert(layer_hint);
          layer_hint->package_window += CIRCWINDOW_INCREMENT;
          log_fn(LOG_DEBUG,"circ-level sendme at AP, packagewindow %d.",
                 layer_hint->package_window);
          circuit_resume_edge_reading(circ, EDGE_AP, layer_hint);
        } else {
          assert(!layer_hint);
          circ->package_window += CIRCWINDOW_INCREMENT;
          log_fn(LOG_DEBUG,"circ-level sendme at exit, packagewindow %d.",
                 circ->package_window);
          circuit_resume_edge_reading(circ, EDGE_EXIT, layer_hint);
        }
        return 0;
      }
      conn->package_window += STREAMWINDOW_INCREMENT;
      log_fn(LOG_DEBUG,"stream-level sendme, packagewindow now %d.", conn->package_window);
      connection_start_reading(conn);
      connection_edge_package_raw_inbuf(conn); /* handle whatever might still be on the inbuf */
      return 0;
  }
  log_fn(LOG_WARN,"unknown relay command %d.",rh.command);
  return -1;
}

int connection_edge_finished_flushing(connection_t *conn) {
  unsigned char connected_payload[4];
  int e, len=sizeof(e);

  assert(conn);
  assert(conn->type == CONN_TYPE_AP || conn->type == CONN_TYPE_EXIT);

  switch(conn->state) {
    case EXIT_CONN_STATE_CONNECTING:
      if (getsockopt(conn->s, SOL_SOCKET, SO_ERROR, (void*)&e, &len) < 0)  { /* not yet */
        if(!ERRNO_CONN_EINPROGRESS(errno)) {
          /* yuck. kill it. */
          log_fn(LOG_DEBUG,"in-progress exit connect failed. Removing.");
          connection_mark_for_close(conn, END_STREAM_REASON_CONNECTFAILED);
          return -1;
        } else {
          log_fn(LOG_DEBUG,"in-progress exit connect still waiting.");
          return 0; /* no change, see if next time is better */
        }
      }
      /* the connect has finished. */

      log_fn(LOG_INFO,"Exit connection to %s:%u established.",
          conn->address,conn->port);

      conn->state = EXIT_CONN_STATE_OPEN;
      connection_watch_events(conn, POLLIN); /* stop writing, continue reading */
      if(connection_wants_to_flush(conn)) /* in case there are any queued relay cells */
        connection_start_writing(conn);
      /* deliver a 'connected' relay cell back through the circuit. */
      *(uint32_t*)connected_payload = htonl(conn->addr);
      if(connection_edge_send_command(conn, circuit_get_by_conn(conn),
         RELAY_COMMAND_CONNECTED, connected_payload, 4, NULL) < 0)
        return 0; /* circuit is closed, don't continue */
      assert(conn->package_window > 0);
      return connection_edge_process_inbuf(conn); /* in case the server has written anything */
    case AP_CONN_STATE_OPEN:
    case EXIT_CONN_STATE_OPEN:
      connection_stop_writing(conn);
      connection_edge_consider_sending_sendme(conn);
      return 0;
    case AP_CONN_STATE_SOCKS_WAIT:
    case AP_CONN_STATE_CIRCUIT_WAIT:
    case AP_CONN_STATE_CONNECT_WAIT:
      connection_stop_writing(conn);
      return 0;
    default:
      log_fn(LOG_WARN,"BUG: called in unexpected state %d.", conn->state);
      return -1;
  }
  return 0;
}

uint64_t stats_n_data_cells_packaged = 0;
uint64_t stats_n_data_bytes_packaged = 0;
uint64_t stats_n_data_cells_received = 0;
uint64_t stats_n_data_bytes_received = 0;

int connection_edge_package_raw_inbuf(connection_t *conn) {
  int amount_to_process, length;
  char payload[CELL_PAYLOAD_SIZE];
  circuit_t *circ;

  assert(conn);
  assert(!connection_speaks_cells(conn));

repeat_connection_edge_package_raw_inbuf:

  circ = circuit_get_by_conn(conn);
  if(!circ) {
    log_fn(LOG_INFO,"conn has no circuits! Closing.");
    return -1;
  }

  if(circuit_consider_stop_edge_reading(circ, conn->type, conn->cpath_layer))
    return 0;

  if(conn->package_window <= 0) {
    log_fn(LOG_WARN,"called with package_window %d. Tell Roger.", conn->package_window);
    connection_stop_reading(conn);
    return 0;
  }

  amount_to_process = buf_datalen(conn->inbuf);

  if(!amount_to_process)
    return 0;

  if(amount_to_process > RELAY_PAYLOAD_SIZE) {
    length = RELAY_PAYLOAD_SIZE;
  } else {
    length = amount_to_process;
  }
  stats_n_data_bytes_packaged += length;
  stats_n_data_cells_packaged += 1;

  connection_fetch_from_buf(payload, length, conn);

  log_fn(LOG_DEBUG,"(%d) Packaging %d bytes (%d waiting).", conn->s, length,
         (int)buf_datalen(conn->inbuf));

  if(connection_edge_send_command(conn, circ, RELAY_COMMAND_DATA,
                               payload, length, conn->cpath_layer) < 0)
    return 0; /* circuit is closed, don't continue */

  if(conn->type == CONN_TYPE_EXIT) {
    assert(circ->package_window > 0);
    circ->package_window--;
  } else { /* we're an AP */
    assert(conn->type == CONN_TYPE_AP);
    assert(conn->cpath_layer->package_window > 0);
    conn->cpath_layer->package_window--;
  }

  if(--conn->package_window <= 0) { /* is it 0 after decrement? */
    connection_stop_reading(conn);
    log_fn(LOG_DEBUG,"conn->package_window reached 0.");
    circuit_consider_stop_edge_reading(circ, conn->type, conn->cpath_layer);
    return 0; /* don't process the inbuf any more */
  }
  log_fn(LOG_DEBUG,"conn->package_window is now %d",conn->package_window);

  /* handle more if there's more, or return 0 if there isn't */
  goto repeat_connection_edge_package_raw_inbuf;
}

#define MAX_STREAM_RETRIES 4
void connection_ap_expire_beginning(void) {
  connection_t **carray;
  connection_t *conn;
  circuit_t *circ;
  int n, i;
  time_t now = time(NULL);

  get_connection_array(&carray, &n);

  for (i = 0; i < n; ++i) {
    conn = carray[i];
    if (conn->type != CONN_TYPE_AP ||
        conn->state != AP_CONN_STATE_CONNECT_WAIT)
      continue;
    if (now - conn->timestamp_lastread < 15)
      continue;
    conn->num_retries++;
    circ = circuit_get_by_conn(conn);
    if(conn->num_retries >= MAX_STREAM_RETRIES) {
      log_fn(LOG_WARN,"Stream is %d seconds late. Giving up.",
             15*conn->num_retries);
      circuit_log_path(LOG_WARN, circ);
      connection_mark_for_close(conn,END_STREAM_REASON_TIMEOUT);
    } else {
      log_fn(LOG_WARN,"Stream is %d seconds late. Retrying.",
             (int)(now - conn->timestamp_lastread));
      circuit_log_path(LOG_WARN, circ);
      /* send an end down the circuit */
      connection_edge_end(conn, END_STREAM_REASON_TIMEOUT, conn->cpath_layer);
      /* un-mark it as ending, since we're going to reuse it */
      conn->has_sent_end = 0;
      /* move it back into 'pending' state. */
      conn->state = AP_CONN_STATE_CIRCUIT_WAIT;
      /* conn->purpose is still set to general */
      circuit_detach_stream(circ, conn);
      /* kludge to make us not try this circuit again, yet to allow
       * current streams on it to survive if they can: make it
       * unattractive to use for new streams */
      assert(circ->timestamp_dirty);
      circ->timestamp_dirty -= options.NewCircuitPeriod;
      /* give our stream another 15 seconds to try */
      conn->timestamp_lastread += 15;
      /* attaching to a dirty circuit is fine */
      if(connection_ap_handshake_attach_circuit(conn)<0) {
        /* it will never work */
        /* Don't need to send end -- we're not connected */
        connection_mark_for_close(conn, 0);
      }
    } /* end if max_retries */
  } /* end for */
}

/* Tell any APs that are waiting for a new circuit that one is available */
void connection_ap_attach_pending(void)
{
  connection_t **carray;
  connection_t *conn;
  int n, i;

  get_connection_array(&carray, &n);

  for (i = 0; i < n; ++i) {
    conn = carray[i];
    if (conn->type != CONN_TYPE_AP ||
        conn->state != AP_CONN_STATE_CIRCUIT_WAIT)
      continue;
    /* attaching to a dirty circuit is fine */
    if(connection_ap_handshake_attach_circuit(conn) < 0) {
      /* -1 means it will never work */
      /* Don't send end; there is no 'other side' yet */
      connection_mark_for_close(conn,0);
    }
  }
}

static void connection_edge_consider_sending_sendme(connection_t *conn) {
  circuit_t *circ;

  if(connection_outbuf_too_full(conn))
    return;

  circ = circuit_get_by_conn(conn);
  if(!circ) {
    /* this can legitimately happen if the destroy has already
     * arrived and torn down the circuit */
    log_fn(LOG_INFO,"No circuit associated with conn. Skipping.");
    return;
  }

  while(conn->deliver_window < STREAMWINDOW_START - STREAMWINDOW_INCREMENT) {
    log_fn(LOG_DEBUG,"Outbuf %d, Queueing stream sendme.", conn->outbuf_flushlen);
    conn->deliver_window += STREAMWINDOW_INCREMENT;
    if(connection_edge_send_command(conn, circ, RELAY_COMMAND_SENDME,
                                    NULL, 0, conn->cpath_layer) < 0) {
      log_fn(LOG_WARN,"connection_edge_send_command failed. Returning.");
      return; /* the circuit's closed, don't continue */
    }
  }
}

/* return -1 if an unexpected error with conn, else 0. */
static int connection_ap_handshake_process_socks(connection_t *conn) {
  socks_request_t *socks;
  int sockshere;

  assert(conn);
  assert(conn->type == CONN_TYPE_AP);
  assert(conn->state == AP_CONN_STATE_SOCKS_WAIT);
  assert(conn->socks_request);
  socks = conn->socks_request;

  log_fn(LOG_DEBUG,"entered.");

  sockshere = fetch_from_buf_socks(conn->inbuf, socks);
  if(sockshere == -1 || sockshere == 0) {
    if(socks->replylen) { /* we should send reply back */
      log_fn(LOG_DEBUG,"reply is already set for us. Using it.");
      connection_ap_handshake_socks_reply(conn, socks->reply, socks->replylen, 0);
    } else if(sockshere == -1) { /* send normal reject */
      log_fn(LOG_WARN,"Fetching socks handshake failed. Closing.");
      connection_ap_handshake_socks_reply(conn, NULL, 0, 0);
    } else {
      log_fn(LOG_DEBUG,"socks handshake not all here yet.");
    }
    if (sockshere == -1)
      conn->socks_request->has_finished = 1;
    return sockshere;
  } /* else socks handshake is done, continue processing */

  /* this call _modifies_ socks->address iff it's a hidden-service request */
  if (rend_parse_rendezvous_address(socks->address) < 0) {
    /* normal request */
    conn->state = AP_CONN_STATE_CIRCUIT_WAIT;
    conn->purpose = AP_PURPOSE_GENERAL;
    /* attaching to a dirty circuit is fine */
    return connection_ap_handshake_attach_circuit(conn);
  } else {
    /* it's a hidden-service request */
    const char *descp;
    int desc_len;

    /* see if we already have it cached */
    if (rend_cache_lookup(socks->address, &descp, &desc_len) == 1) {
      conn->purpose = AP_PURPOSE_RENDPOINT_WAIT;
      return connection_ap_handshake_attach_circuit(conn);
      //circuit_launch_new(CIRCUIT_PURPOSE_C_ESTABLISH_REND, NULL);
    } else {
      conn->purpose = AP_PURPOSE_RENDDESC_WAIT;
      /* initiate a dir hidserv desc lookup */
      directory_initiate_command(router_pick_directory_server(),
                                 DIR_PURPOSE_FETCH_RENDDESC,
                                 socks->address, strlen(socks->address));
      return 0;
    }
  }
  return 0;
}

/* Try to find a safe live circuit for CONN_TYPE_AP connection conn. If
 * we don't find one: if conn cannot be handled by any known nodes,
 * warn and return -1 (conn needs to die);
 * else launch new circuit and return 0.
 * Otherwise, associate conn with a safe live circuit, do the
 * right next step, and return 1.
 */
static int connection_ap_handshake_attach_circuit(connection_t *conn) {
  circuit_t *circ;
  uint32_t addr;
  int must_be_clean;
  uint8_t desired_circuit_purpose;

  assert(conn);
  assert(conn->type == CONN_TYPE_AP);
  assert(conn->state == AP_CONN_STATE_CIRCUIT_WAIT);
  assert(conn->socks_request);

  switch(conn->purpose) {
    case AP_PURPOSE_GENERAL:
    case AP_PURPOSE_RENDDESC_WAIT:
      desired_circuit_purpose = CIRCUIT_PURPOSE_C_GENERAL;
      break;
    case AP_PURPOSE_RENDPOINT_WAIT:
      desired_circuit_purpose = CIRCUIT_PURPOSE_C_ESTABLISH_REND;
      break;
    case AP_PURPOSE_INTROPOINT_WAIT:
      desired_circuit_purpose = CIRCUIT_PURPOSE_C_INTRODUCING;
      break;
    default:
      assert(0); /* never reached */
  }

  /* find the circuit that we should use, if there is one. */
  circ = circuit_get_newest(conn, 1, desired_circuit_purpose);

  if(!circ) {
//XXX
    log_fn(LOG_INFO,"No safe circuit ready for edge connection; delaying.");
    addr = client_dns_lookup_entry(conn->socks_request->address);
    if(router_exit_policy_all_routers_reject(addr, conn->socks_request->port)) {
      log_fn(LOG_WARN,"No Tor server exists that allows exit to %s:%d. Rejecting.",
             conn->socks_request->address, conn->socks_request->port);
      return -1;
    }
    if(!circuit_get_newest(conn, 0, desired_circuit_purpose)) {
      /* is one already on the way? */
      circuit_launch_new(desired_circuit_purpose, NULL);
    }
    return 0;
  }

  /* here, print the circ's path. so people can figure out which circs are sucking. */
  circuit_log_path(LOG_INFO,circ);

  if(!circ->timestamp_dirty)
    circ->timestamp_dirty = time(NULL);

  switch(conn->purpose) {
    case AP_PURPOSE_GENERAL:
    case AP_PURPOSE_RENDDESC_WAIT:
      /* add it into the linked list of streams on this circuit */
      log_fn(LOG_DEBUG,"attaching new conn to circ. n_circ_id %d.", circ->n_circ_id);
      conn->next_stream = circ->p_streams;
      /* assert_connection_ok(conn, time(NULL)); */
      circ->p_streams = conn;

      assert(circ->cpath && circ->cpath->prev);
      assert(circ->cpath->prev->state == CPATH_STATE_OPEN);
      conn->cpath_layer = circ->cpath->prev;

      connection_ap_handshake_send_begin(conn, circ);
      break;
    case AP_PURPOSE_RENDPOINT_WAIT:
    case AP_PURPOSE_INTROPOINT_WAIT:
  }

  return 1;
}

/* Iterate over the two bytes of stream_id until we get one that is not
 * already in use. Return 0 if can't get a unique stream_id.
 */
static uint16_t get_unique_stream_id_by_circ(circuit_t *circ) {
  connection_t *tmpconn;
  uint16_t test_stream_id;
  uint32_t attempts=0;

again:
  test_stream_id = circ->next_stream_id++;
  if(++attempts > 1<<16) {
    /* Make sure we don't loop forever if all stream_id's are used. */
    log_fn(LOG_WARN,"No unused stream IDs. Failing.");
    return 0;
  }
  if (test_stream_id == 0)
    goto again;
  for(tmpconn = circ->p_streams; tmpconn; tmpconn=tmpconn->next_stream)
    if(tmpconn->stream_id == test_stream_id)
      goto again;
  return test_stream_id;
}

/* deliver the destaddr:destport in a relay cell */
static void connection_ap_handshake_send_begin(connection_t *ap_conn, circuit_t *circ)
{
  char payload[CELL_PAYLOAD_SIZE];
  int payload_len;
  struct in_addr in;
  const char *string_addr;

  assert(ap_conn->type == CONN_TYPE_AP);
  assert(ap_conn->state == AP_CONN_STATE_CIRCUIT_WAIT);
  assert(ap_conn->socks_request);

  ap_conn->stream_id = get_unique_stream_id_by_circ(circ);
  if (ap_conn->stream_id==0) {
    /* Don't send end: there is no 'other side' yet */
    connection_mark_for_close(ap_conn, 0);
    return;
  }

  in.s_addr = htonl(client_dns_lookup_entry(ap_conn->socks_request->address));
  string_addr = in.s_addr ? inet_ntoa(in) : NULL;

  snprintf(payload,RELAY_PAYLOAD_SIZE,
           "%s:%d",
           string_addr ? string_addr : ap_conn->socks_request->address,
           ap_conn->socks_request->port);
  payload_len = strlen(payload)+1;

  log_fn(LOG_DEBUG,"Sending relay cell to begin stream %d.",ap_conn->stream_id);

  if(connection_edge_send_command(ap_conn, circ, RELAY_COMMAND_BEGIN,
                               payload, payload_len, ap_conn->cpath_layer) < 0)
    return; /* circuit is closed, don't continue */

  ap_conn->package_window = STREAMWINDOW_START;
  ap_conn->deliver_window = STREAMWINDOW_START;
  ap_conn->state = AP_CONN_STATE_CONNECT_WAIT;
  log_fn(LOG_INFO,"Address/port sent, ap socket %d, n_circ_id %d",ap_conn->s,circ->n_circ_id);
  return;
}

/* make an ap connection_t, do a socketpair and attach one side
 * to the conn, connection_add it, initialize it to circuit_wait,
 * and call connection_ap_handshake_attach_circuit(conn) on it.
 * Return the other end of the socketpair, or -1 if error.
 */
int connection_ap_make_bridge(char *address, uint16_t port) {
  int fd[2];
  connection_t *conn;

  log_fn(LOG_INFO,"Making AP bridge to %s:%d ...",address,port);

  if(tor_socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
    log(LOG_ERR, "Couldn't construct socketpair: %s", strerror(errno));
    exit(1);
  }

  set_socket_nonblocking(fd[0]);
  set_socket_nonblocking(fd[1]);

  conn = connection_new(CONN_TYPE_AP);
  conn->s = fd[0];

  /* populate conn->socks_request */

  /* leave version at zero, so the socks_reply is empty */
  conn->socks_request->socks_version = 0;
  conn->socks_request->has_finished = 0; /* waiting for 'connected' */
  strcpy(conn->socks_request->address, address);
  conn->socks_request->port = port;

  conn->address = tor_strdup("(local bridge)");
  conn->addr = ntohs(0);
  conn->port = 0;

  if(connection_add(conn) < 0) { /* no space, forget it */
    connection_free(conn); /* this closes fd[0] */
    close(fd[1]);
    return -1;
  }

  conn->state = AP_CONN_STATE_CIRCUIT_WAIT;
  connection_start_reading(conn);

  /* attaching to a dirty circuit is fine */
  if (connection_ap_handshake_attach_circuit(conn) < 0) {
    connection_mark_for_close(conn, 0);
    close(fd[1]);
    return -1;
  }

  log_fn(LOG_INFO,"... AP bridge created and connected.");
  return fd[1];
}

void connection_ap_handshake_socks_reply(connection_t *conn, char *reply,
                                         int replylen, char success) {
  char buf[256];

  if(replylen) { /* we already have a reply in mind */
    connection_write_to_buf(reply, replylen, conn);
    return;
  }
  assert(conn->socks_request);
  if(conn->socks_request->socks_version == 4) {
    memset(buf,0,SOCKS4_NETWORK_LEN);
#define SOCKS4_GRANTED          90
#define SOCKS4_REJECT           91
    buf[1] = (success ? SOCKS4_GRANTED : SOCKS4_REJECT);
    /* leave version, destport, destip zero */
    connection_write_to_buf(buf, SOCKS4_NETWORK_LEN, conn);
  }
  if(conn->socks_request->socks_version == 5) {
    buf[0] = 5; /* version 5 */
#define SOCKS5_SUCCESS          0
#define SOCKS5_GENERIC_ERROR    1
    buf[1] = success ? SOCKS5_SUCCESS : SOCKS5_GENERIC_ERROR;
    buf[2] = 0;
    buf[3] = 1; /* ipv4 addr */
    memset(buf+4,0,6); /* Set external addr/port to 0.
                          The spec doesn't seem to say what to do here. -RD */
    connection_write_to_buf(buf,10,conn);
  }
  /* If socks_version isn't 4 or 5, don't send anything.
   * This can happen in the case of AP bridges. */
  return;
}

static int connection_exit_begin_conn(cell_t *cell, circuit_t *circ) {
  connection_t *n_stream;
  relay_header_t rh;
  char *colon;

  relay_header_unpack(&rh, cell->payload);

  /* XXX currently we don't send an end cell back if we drop the
   * begin because it's malformed.
   */

  if(!memchr(cell->payload+RELAY_HEADER_SIZE, 0, rh.length)) {
    log_fn(LOG_WARN,"relay begin cell has no \\0. Dropping.");
    return 0;
  }
  colon = strchr(cell->payload+RELAY_HEADER_SIZE, ':');
  if(!colon) {
    log_fn(LOG_WARN,"relay begin cell has no colon. Dropping.");
    return 0;
  }
  *colon = 0;

  if(!atoi(colon+1)) { /* bad port */
    log_fn(LOG_WARN,"relay begin cell has invalid port. Dropping.");
    return 0;
  }

  log_fn(LOG_DEBUG,"Creating new exit connection.");
  n_stream = connection_new(CONN_TYPE_EXIT);

  n_stream->stream_id = rh.stream_id;
  n_stream->address = tor_strdup(cell->payload + RELAY_HEADER_SIZE);
  n_stream->port = atoi(colon+1);
  n_stream->state = EXIT_CONN_STATE_RESOLVING;
  /* leave n_stream->s at -1, because it's not yet valid */
  n_stream->package_window = STREAMWINDOW_START;
  n_stream->deliver_window = STREAMWINDOW_START;
  if(connection_add(n_stream) < 0) { /* no space, forget it */
    log_fn(LOG_WARN,"connection_add failed. Dropping.");
    connection_free(n_stream);
    return 0;
  }

  /* add it into the linked list of streams on this circuit */
  n_stream->next_stream = circ->n_streams;
  circ->n_streams = n_stream;

  /* send it off to the gethostbyname farm */
  switch(dns_resolve(n_stream)) {
    case 1: /* resolve worked */
      connection_exit_connect(n_stream);
      return 0;
    case -1: /* resolve failed */
      log_fn(LOG_INFO,"Resolve failed (%s).", n_stream->address);
      /* Set the state so that we don't try to remove n_stream from a DNS
       * pending list. */
      n_stream->state = EXIT_CONN_STATE_RESOLVEFAILED; 
      connection_mark_for_close(n_stream, END_STREAM_REASON_RESOLVEFAILED);
      break;
    case 0: /* resolve added to pending list */
      ;
  }
  return 0;
}

void connection_exit_connect(connection_t *conn) {
  unsigned char connected_payload[4];

  if(router_compare_to_my_exit_policy(conn) == ADDR_POLICY_REJECTED) {
    log_fn(LOG_INFO,"%s:%d failed exit policy. Closing.", conn->address, conn->port);
    connection_mark_for_close(conn, END_STREAM_REASON_EXITPOLICY);
    return;
  }

  switch(connection_connect(conn, conn->address, conn->addr, conn->port)) {
    case -1:
      connection_mark_for_close(conn, END_STREAM_REASON_CONNECTFAILED);
      return;
    case 0:
      connection_set_poll_socket(conn);
      conn->state = EXIT_CONN_STATE_CONNECTING;

      connection_watch_events(conn, POLLOUT | POLLIN | POLLERR);
      /* writable indicates finish, readable indicates broken link,
         error indicates broken link in windowsland. */
      return;
    /* case 1: fall through */
  }

  connection_set_poll_socket(conn);
  conn->state = EXIT_CONN_STATE_OPEN;
  if(connection_wants_to_flush(conn)) { /* in case there are any queued data cells */
    log_fn(LOG_WARN,"tell roger: newly connected conn had data waiting!");
//    connection_start_writing(conn);
  }
//   connection_process_inbuf(conn);
  connection_watch_events(conn, POLLIN);

  /* also, deliver a 'connected' cell back through the circuit. */
  *(uint32_t*)connected_payload = htonl(conn->addr);
  connection_edge_send_command(conn, circuit_get_by_conn(conn), RELAY_COMMAND_CONNECTED,
                               connected_payload, 4, NULL);
}

int connection_ap_can_use_exit(connection_t *conn, routerinfo_t *exit)
{
  uint32_t addr;

  assert(conn);
  assert(conn->type == CONN_TYPE_AP);
  assert(conn->socks_request);

  log_fn(LOG_DEBUG,"considering nickname %s, for address %s / port %d:",
         exit->nickname, conn->socks_request->address,
         conn->socks_request->port);
  addr = client_dns_lookup_entry(conn->socks_request->address);
  return router_compare_addr_to_exit_policy(addr,
           conn->socks_request->port, exit->exit_policy);
}

/* ***** Client DNS code ***** */

/* XXX Perhaps this should get merged with the dns.c code somehow. */
/* XXX But we can't just merge them, because then nodes that act as
 *     both OR and OP could be attacked: people could rig the dns cache
 *     by answering funny things to stream begin requests, and later
 *     other clients would reuse those funny addr's. Hm.
 */
struct client_dns_entry {
  uint32_t addr;
  time_t expires;
};
static int client_dns_size = 0;
static strmap_t *client_dns_map = NULL;

void client_dns_init(void) {
  client_dns_map = strmap_new();
  client_dns_size = 0;
}

static uint32_t client_dns_lookup_entry(const char *address)
{
  struct client_dns_entry *ent;
  struct in_addr in;
  time_t now;

  assert(address);

  if (tor_inet_aton(address, &in)) {
    log_fn(LOG_DEBUG, "Using static address %s (%08lX)", address,
           (unsigned long)ntohl(in.s_addr));
    return ntohl(in.s_addr);
  }
  ent = strmap_get_lc(client_dns_map,address);
  if (!ent) {
    log_fn(LOG_DEBUG, "No entry found for address %s", address);
    return 0;
  } else {
    now = time(NULL);
    if (ent->expires < now) {
      log_fn(LOG_DEBUG, "Expired entry found for address %s", address);
      strmap_remove_lc(client_dns_map,address);
      tor_free(ent);
      --client_dns_size;
      return 0;
    }
    in.s_addr = htonl(ent->addr);
    log_fn(LOG_DEBUG, "Found cached entry for address %s: %s", address,
           inet_ntoa(in));
    return ent->addr;
  }
}

static void client_dns_set_entry(const char *address, uint32_t val)
{
  struct client_dns_entry *ent;
  struct in_addr in;
  time_t now;

  assert(address);
  assert(val);

  if (tor_inet_aton(address, &in))
    return;
  now = time(NULL);
  ent = strmap_get_lc(client_dns_map, address);
  if (ent) {
    in.s_addr = htonl(val);
    log_fn(LOG_DEBUG, "Updating entry for address %s: %s", address,
           inet_ntoa(in));
    ent->addr = val;
    ent->expires = now+MAX_DNS_ENTRY_AGE;
  } else {
    in.s_addr = htonl(val);
    log_fn(LOG_DEBUG, "Caching result for address %s: %s", address,
           inet_ntoa(in));
    ent = tor_malloc(sizeof(struct client_dns_entry));
    ent->addr = val;
    ent->expires = now+MAX_DNS_ENTRY_AGE;
    strmap_set_lc(client_dns_map, address, ent);
    ++client_dns_size;
  }
}

static void* _remove_if_expired(const char *addr,
                                struct client_dns_entry *ent,
                                time_t *nowp)
{
  if (ent->expires < *nowp) {
    --client_dns_size;
    tor_free(ent);
    return NULL;
  } else {
    return ent;
  }
}

void client_dns_clean(void)
{
  time_t now;

  if(!client_dns_size)
    return;
  now = time(NULL);
  strmap_foreach(client_dns_map, (strmap_foreach_fn)_remove_if_expired, &now);
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
