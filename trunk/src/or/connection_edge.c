/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"
#include "tree.h"

extern or_options_t options; /* command-line and config-file options */
extern char *conn_state_to_string[][_CONN_TYPE_MAX+1];

static int connection_ap_handshake_process_socks(connection_t *conn);

static int connection_exit_begin_conn(cell_t *cell, circuit_t *circ);
static void connection_edge_consider_sending_sendme(connection_t *conn);

static uint32_t client_dns_lookup_entry(const char *address);
static void client_dns_set_entry(const char *address, uint32_t val);
static int client_dns_incr_failures(const char *address);

void relay_header_pack(char *dest, const relay_header_t *src) {
  *(uint8_t*)(dest) = src->command;

  set_uint16(dest+1, htons(src->recognized));
  set_uint16(dest+3, htons(src->stream_id));
  memcpy(dest+5, src->integrity, 4);
  set_uint16(dest+9, htons(src->length));
}

void relay_header_unpack(relay_header_t *dest, const char *src) {
  dest->command = *(uint8_t*)(src);

  dest->recognized = ntohs(get_uint16(src+1));
  dest->stream_id = ntohs(get_uint16(src+3));
  memcpy(dest->integrity, src+5, 4);
  dest->length = ntohs(get_uint16(src+9));
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
        /* XXX this is still getting called rarely :( */
        log_fn(LOG_WARN,"called with package_window %d. Tell Roger.", conn->package_window);
        return 0;
      }
      if(connection_edge_package_raw_inbuf(conn) < 0) {
        connection_mark_for_close(conn, END_STREAM_REASON_MISC);
        return -1;
      }
      return 0;
    case EXIT_CONN_STATE_CONNECTING:
    case AP_CONN_STATE_RENDDESC_WAIT:
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
    /* this is safe even for rend circs, because they never fail
     * because of exitpolicy */
    set_uint32(payload+1, htonl(conn->addr));
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
                                 int relay_command, const char *payload,
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

#define MAX_RESOLVE_FAILURES 3

int connection_edge_process_relay_cell_not_open(
    relay_header_t *rh, cell_t *cell, circuit_t *circ,
    connection_t *conn, crypt_path_t *layer_hint) {
  uint32_t addr;
  int reason;

  if(rh->command == RELAY_COMMAND_END) {
    reason = *(cell->payload+RELAY_HEADER_SIZE);
    /* We have to check this here, since we aren't connected yet. */
    if (rh->length >= 5 && reason == END_STREAM_REASON_EXITPOLICY) {
      addr = ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE+1));
      client_dns_set_entry(conn->socks_request->address, addr);
      conn->state = AP_CONN_STATE_CIRCUIT_WAIT;
      circuit_detach_stream(circ,conn);
      if(connection_ap_handshake_attach_circuit(conn) >= 0)
        return 0;
      /* else, conn will get closed below */
    } else if (rh->length && reason == END_STREAM_REASON_RESOLVEFAILED) {
      if (client_dns_incr_failures(conn->socks_request->address)
          < MAX_RESOLVE_FAILURES) {
        /* We haven't retried too many times; reattach the connection. */
        conn->state = AP_CONN_STATE_CIRCUIT_WAIT;
        circuit_detach_stream(circ,conn);
        if(connection_ap_handshake_attach_circuit(conn) >= 0)
          return 0;
        /* else, conn will get closed below */
      }
    }
    log_fn(LOG_INFO,"Edge got end (%s) before we're connected. Marking for close.",
      connection_edge_end_reason(cell->payload+RELAY_HEADER_SIZE, rh->length));
    if(CIRCUIT_IS_ORIGIN(circ))
      circuit_log_path(LOG_INFO,circ);
    conn->has_sent_end = 1; /* we just got an 'end', don't need to send one */
    connection_mark_for_close(conn, 0);
    /* XXX here we should send a socks reject back if necessary, and hold
     * open til flushed */
    return 0;
  }

  if(conn->type == CONN_TYPE_AP && rh->command == RELAY_COMMAND_CONNECTED) {
    if(conn->state != AP_CONN_STATE_CONNECT_WAIT) {
      log_fn(LOG_WARN,"Got 'connected' while not in state connect_wait. Dropping.");
      return 0;
    }
//    log_fn(LOG_INFO,"Connected! Notifying application.");
    conn->state = AP_CONN_STATE_OPEN;
    if (rh->length >= 4) {
      addr = ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE));
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
           rh->command, conn->state, conn_state_to_string[conn->type][conn->state]);
    connection_mark_for_close(conn, END_STREAM_REASON_MISC);
    return -1;
  }
}

/* an incoming relay cell has arrived. return -1 if you want to tear down the
 * circuit, else 0. */
int connection_edge_process_relay_cell(cell_t *cell, circuit_t *circ,
                                       connection_t *conn,
                                       crypt_path_t *layer_hint) {
  static int num_seen=0;
  relay_header_t rh;

  assert(cell && circ);

  relay_header_unpack(&rh, cell->payload);
//  log_fn(LOG_DEBUG,"command %d stream %d", rh.command, rh.stream_id);
  num_seen++;
  log_fn(LOG_DEBUG,"Now seen %d relay cells here.", num_seen);

  /* either conn is NULL, in which case we've got a control cell, or else
   * conn points to the recognized stream. */

  if(conn &&
     conn->state != AP_CONN_STATE_OPEN &&
     conn->state != EXIT_CONN_STATE_OPEN) {
    return connection_edge_process_relay_cell_not_open(
             &rh, cell, circ, conn, layer_hint);
  }

  switch(rh.command) {
    case RELAY_COMMAND_DROP:
      log_fn(LOG_INFO,"Got a relay-level padding cell. Dropping.");
      return 0;
    case RELAY_COMMAND_BEGIN:
      if (layer_hint &&
          circ->purpose != CIRCUIT_PURPOSE_S_REND_JOINED) {
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
      if((layer_hint && --layer_hint->deliver_window < 0) ||
         (!layer_hint && --circ->deliver_window < 0)) {
        log_fn(LOG_WARN,"(relay data) circ deliver_window below 0. Killing.");
        connection_mark_for_close(conn, END_STREAM_REASON_MISC);
        return -1;
      }
      log_fn(LOG_DEBUG,"circ deliver_window now %d.", layer_hint ?
             layer_hint->deliver_window : circ->deliver_window);

      circuit_consider_sending_sendme(circ, layer_hint);

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
      if(!layer_hint) {
        log_fn(LOG_WARN,"'extended' unsupported at non-origin. Dropping.");
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
      if(layer_hint) {
        log_fn(LOG_WARN,"'truncate' unsupported at origin. Dropping.");
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
      if(!layer_hint) {
        log_fn(LOG_WARN,"'truncated' unsupported at non-origin. Dropping.");
        return 0;
      }
      circuit_truncated(circ, layer_hint);
      return 0;
    case RELAY_COMMAND_CONNECTED:
      if(conn) {
        log_fn(LOG_WARN,"'connected' unsupported while open. Closing circ.");
        return -1;
      }
      log_fn(LOG_INFO,"'connected' received, no conn attached anymore. Ignoring.");
      return 0;
    case RELAY_COMMAND_SENDME:
      if(!conn) {
        if(layer_hint) {
          layer_hint->package_window += CIRCWINDOW_INCREMENT;
          log_fn(LOG_DEBUG,"circ-level sendme at origin, packagewindow %d.",
                 layer_hint->package_window);
          circuit_resume_edge_reading(circ, layer_hint);
        } else {
          circ->package_window += CIRCWINDOW_INCREMENT;
          log_fn(LOG_DEBUG,"circ-level sendme at non-origin, packagewindow %d.",
                 circ->package_window);
          circuit_resume_edge_reading(circ, layer_hint);
        }
        return 0;
      }
      conn->package_window += STREAMWINDOW_INCREMENT;
      log_fn(LOG_DEBUG,"stream-level sendme, packagewindow now %d.", conn->package_window);
      connection_start_reading(conn);
      connection_edge_package_raw_inbuf(conn); /* handle whatever might still be on the inbuf */
      return 0;
    case RELAY_COMMAND_ESTABLISH_INTRO:
    case RELAY_COMMAND_ESTABLISH_RENDEZVOUS:
    case RELAY_COMMAND_INTRODUCE1:
    case RELAY_COMMAND_INTRODUCE2:
    case RELAY_COMMAND_INTRODUCE_ACK:
    case RELAY_COMMAND_RENDEZVOUS1:
    case RELAY_COMMAND_RENDEZVOUS2:
    case RELAY_COMMAND_INTRO_ESTABLISHED:
    case RELAY_COMMAND_RENDEZVOUS_ESTABLISHED:
      rend_process_relay_cell(circ, rh.command, rh.length,
                              cell->payload+RELAY_HEADER_SIZE);
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
      if(connection_edge_is_rendezvous_stream(conn)) {
        if(connection_edge_send_command(conn, circuit_get_by_conn(conn),
           RELAY_COMMAND_CONNECTED, NULL, 0, conn->cpath_layer) < 0)
          return 0; /* circuit is closed, don't continue */
      } else {
        *(uint32_t*)connected_payload = htonl(conn->addr);
        if(connection_edge_send_command(conn, circuit_get_by_conn(conn),
           RELAY_COMMAND_CONNECTED, connected_payload, 4, conn->cpath_layer) < 0)
          return 0; /* circuit is closed, don't continue */
      }
      assert(conn->package_window > 0);
      return connection_edge_process_inbuf(conn); /* in case the server has written anything */
    case AP_CONN_STATE_OPEN:
    case EXIT_CONN_STATE_OPEN:
      connection_stop_writing(conn);
      connection_edge_consider_sending_sendme(conn);
      return 0;
    case AP_CONN_STATE_SOCKS_WAIT:
    case AP_CONN_STATE_RENDDESC_WAIT:
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

  if(circuit_consider_stop_edge_reading(circ, conn->cpath_layer))
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

  if(!conn->cpath_layer) { /* non-rendezvous exit */
    assert(circ->package_window > 0);
    circ->package_window--;
  } else { /* we're an AP, or an exit on a rendezvous circ */
    assert(conn->cpath_layer->package_window > 0);
    conn->cpath_layer->package_window--;
  }

  if(--conn->package_window <= 0) { /* is it 0 after decrement? */
    connection_stop_reading(conn);
    log_fn(LOG_DEBUG,"conn->package_window reached 0.");
    circuit_consider_stop_edge_reading(circ, conn->cpath_layer);
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
    if(circ->purpose == CIRCUIT_PURPOSE_C_REND_JOINED) {
      if (now - conn->timestamp_lastread > 45) {
        log_fn(LOG_WARN,"Rend stream is %d seconds late. Giving up.",
               (int)(now - conn->timestamp_lastread));
        connection_mark_for_close(conn,END_STREAM_REASON_TIMEOUT);
      }
      continue;
    }
    assert(circ->purpose == CIRCUIT_PURPOSE_C_GENERAL);
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
    return connection_ap_handshake_attach_circuit(conn);
  } else {
    /* it's a hidden-service request */
    rend_cache_entry_t *entry;

    strcpy(conn->rend_query, socks->address); /* this strcpy is safe -RD */
    log_fn(LOG_INFO,"Got a hidden service request for ID '%s'", conn->rend_query);
    /* see if we already have it cached */
    if (rend_cache_lookup_entry(conn->rend_query, &entry) == 1 &&
#define NUM_SECONDS_BEFORE_REFETCH (60*15)
      entry->received + NUM_SECONDS_BEFORE_REFETCH < time(NULL)) {
      conn->state = AP_CONN_STATE_CIRCUIT_WAIT;
      return connection_ap_handshake_attach_circuit(conn);
    } else {
      conn->state = AP_CONN_STATE_RENDDESC_WAIT;
      if(!connection_get_by_type_rendquery(CONN_TYPE_DIR, conn->rend_query)) {
        /* not one already; initiate a dir rend desc lookup */
        directory_initiate_command(router_pick_directory_server(),
                                   DIR_PURPOSE_FETCH_RENDDESC,
                                   conn->rend_query, strlen(conn->rend_query));
      }
      return 0;
    }
  }
  return 0;
}

/* Find an open circ that we're happy with: return 1. if there isn't
 * one, and there isn't one on the way, launch one and return 0. if it
 * will never work, return -1.
 * write the found or in-progress or launched circ into *circp.
 */
static int
circuit_get_open_circ_or_launch(connection_t *conn,
                                uint8_t desired_circuit_purpose,
                                circuit_t **circp) {
  circuit_t *circ;
  uint32_t addr;

  assert(conn);
  assert(circp);
  assert(conn->state == AP_CONN_STATE_CIRCUIT_WAIT);

  circ = circuit_get_best(conn, 1, desired_circuit_purpose);

  if(circ) {
    *circp = circ;
    return 1; /* we're happy */
  }

  if(!connection_edge_is_rendezvous_stream(conn)) { /* general purpose circ */
    addr = client_dns_lookup_entry(conn->socks_request->address);
    if(router_exit_policy_all_routers_reject(addr, conn->socks_request->port)) {
      log_fn(LOG_WARN,"No Tor server exists that allows exit to %s:%d. Rejecting.",
             conn->socks_request->address, conn->socks_request->port);
      return -1;
    }
  }

  /* is one already on the way? */
  circ = circuit_get_best(conn, 0, desired_circuit_purpose);
  if(!circ) {
    char *exitname=NULL;
    uint8_t new_circ_purpose;

    if(desired_circuit_purpose == CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT) {
      /* need to pick an intro point */
      exitname = rend_client_get_random_intro(conn->rend_query);
      if(!exitname) {
        log_fn(LOG_WARN,"Couldn't get an intro point for '%s'. Closing conn.",
               conn->rend_query);
        return -1;
      }
      if(!router_get_by_nickname(exitname)) {
        log_fn(LOG_WARN,"Advertised intro point '%s' is not known. Closing.", exitname);
        return -1;
      }
      log_fn(LOG_INFO,"Chose %s as intro point for %s.", exitname, conn->rend_query);
    }

    if(desired_circuit_purpose == CIRCUIT_PURPOSE_C_REND_JOINED)
      new_circ_purpose = CIRCUIT_PURPOSE_C_ESTABLISH_REND;
    else if(desired_circuit_purpose == CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT)
      new_circ_purpose = CIRCUIT_PURPOSE_C_INTRODUCING;
    else
      new_circ_purpose = desired_circuit_purpose;

    circ = circuit_launch_new(new_circ_purpose, exitname);
    tor_free(exitname);

    if(circ &&
       (desired_circuit_purpose != CIRCUIT_PURPOSE_C_GENERAL)) {
      /* then write the service_id into circ */
      strcpy(circ->rend_query, conn->rend_query);
    }
  }
  if(!circ)
    log_fn(LOG_INFO,"No safe circuit (purpose %d) ready for edge connection; delaying.",
           desired_circuit_purpose);
  *circp = circ;
  return 0;
}

void link_apconn_to_circ(connection_t *apconn, circuit_t *circ) {
  /* add it into the linked list of streams on this circuit */
  log_fn(LOG_DEBUG,"attaching new conn to circ. n_circ_id %d.", circ->n_circ_id);
  apconn->next_stream = circ->p_streams;
  /* assert_connection_ok(conn, time(NULL)); */
  circ->p_streams = apconn;

  assert(CIRCUIT_IS_ORIGIN(circ) && circ->cpath && circ->cpath->prev);
  assert(circ->cpath->prev->state == CPATH_STATE_OPEN);
  apconn->cpath_layer = circ->cpath->prev;
}

/* Try to find a safe live circuit for CONN_TYPE_AP connection conn. If
 * we don't find one: if conn cannot be handled by any known nodes,
 * warn and return -1 (conn needs to die);
 * else launch new circuit (if necessary) and return 0.
 * Otherwise, associate conn with a safe live circuit, do the
 * right next step, and return 1.
 */
int connection_ap_handshake_attach_circuit(connection_t *conn) {
  int retval;

  assert(conn);
  assert(conn->type == CONN_TYPE_AP);
  assert(conn->state == AP_CONN_STATE_CIRCUIT_WAIT);
  assert(conn->socks_request);

  if(conn->timestamp_created < time(NULL)-60) {
    /* XXX make this cleaner than '60' */
    log_fn(LOG_WARN,"Giving up on attached circ (60s late).");
    connection_mark_for_close(conn, 0);
  }

  if(!connection_edge_is_rendezvous_stream(conn)) { /* we're a general conn */
    circuit_t *circ=NULL;

    /* find the circuit that we should use, if there is one. */
    retval = circuit_get_open_circ_or_launch(conn, CIRCUIT_PURPOSE_C_GENERAL, &circ);
    if(retval < 1)
      return retval;

    /* We have found a suitable circuit for our conn. Hurray. */

    /* here, print the circ's path. so people can figure out which circs are sucking. */
    circuit_log_path(LOG_INFO,circ);

    if(!circ->timestamp_dirty)
      circ->timestamp_dirty = time(NULL);

    link_apconn_to_circ(conn, circ);
    connection_ap_handshake_send_begin(conn, circ);

    return 1;

  } else { /* we're a rendezvous conn */
    circuit_t *rendcirc=NULL, *introcirc=NULL;

    assert(!conn->cpath_layer);

    /* start by finding a rendezvous circuit for us */

    retval = circuit_get_open_circ_or_launch(conn, CIRCUIT_PURPOSE_C_REND_JOINED, &rendcirc);
    if(retval < 0) return -1; /* failed */
    assert(rendcirc);

    if(retval > 0) {
      /* one is already established, attach */
      log_fn(LOG_INFO,"rend joined circ already here. attaching.");
      link_apconn_to_circ(conn, rendcirc);
      if(connection_ap_handshake_send_begin(conn, rendcirc) < 0)
        return 0; /* already marked, let them fade away */
      return 1;
    }

    if(rendcirc->purpose == CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED) {
      log_fn(LOG_INFO,"pending-join circ already here, with intro ack. Stalling.");
      return 0;
    }

    /* it's on its way. find an intro circ. */
    retval = circuit_get_open_circ_or_launch(conn, CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT, &introcirc);
    if(retval < 0) return -1; /* failed */
    assert(introcirc);

    if(retval > 0) {
      /* one has already sent the intro. keep waiting. */
      log_fn(LOG_INFO,"Intro circ present and awaiting ack. Stalling.");
      return 0;
    }

    /* now both rendcirc and introcirc are defined, and neither is finished */

    if(rendcirc->purpose == CIRCUIT_PURPOSE_C_REND_READY) {
      log_fn(LOG_INFO,"ready rend circ already here (no intro-ack yet).");
      /* look around for any new intro circs that should introduce */

      assert(introcirc->purpose == CIRCUIT_PURPOSE_C_INTRODUCING);
      if(introcirc->state == CIRCUIT_STATE_OPEN) {
        log_fn(LOG_INFO,"found open intro circ; sending introduction.");
        /* XXX here we should cannibalize the rend circ if it's a zero service id */
        if(rend_client_send_introduction(introcirc, rendcirc) < 0) {
          return -1;
        }
        rendcirc->timestamp_dirty = time(NULL);
        introcirc->timestamp_dirty = time(NULL);
        assert_circuit_ok(rendcirc);
        assert_circuit_ok(introcirc);
        return 0;
      }
    }

    log_fn(LOG_INFO,"Intro and rend circs are not both ready. Stalling conn.");
    return 0;
  }
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
int connection_ap_handshake_send_begin(connection_t *ap_conn, circuit_t *circ)
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
    circuit_mark_for_close(circ);
    return -1;
  }

  if(circ->purpose == CIRCUIT_PURPOSE_C_GENERAL) {
    in.s_addr = htonl(client_dns_lookup_entry(ap_conn->socks_request->address));
    string_addr = in.s_addr ? inet_ntoa(in) : NULL;

    snprintf(payload,RELAY_PAYLOAD_SIZE,
             "%s:%d",
             string_addr ? string_addr : ap_conn->socks_request->address,
             ap_conn->socks_request->port);
  } else {
    snprintf(payload,RELAY_PAYLOAD_SIZE,
             ":%d", ap_conn->socks_request->port);
  }
  payload_len = strlen(payload)+1;

  log_fn(LOG_DEBUG,"Sending relay cell to begin stream %d.",ap_conn->stream_id);

  if(connection_edge_send_command(ap_conn, circ, RELAY_COMMAND_BEGIN,
                               payload, payload_len, ap_conn->cpath_layer) < 0)
    return -1; /* circuit is closed, don't continue */

  ap_conn->package_window = STREAMWINDOW_START;
  ap_conn->deliver_window = STREAMWINDOW_START;
  ap_conn->state = AP_CONN_STATE_CONNECT_WAIT;
  log_fn(LOG_INFO,"Address/port sent, ap socket %d, n_circ_id %d",ap_conn->s,circ->n_circ_id);
  return 0;
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

  assert_circuit_ok(circ);
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
  n_stream->port = atoi(colon+1);
  /* leave n_stream->s at -1, because it's not yet valid */
  n_stream->package_window = STREAMWINDOW_START;
  n_stream->deliver_window = STREAMWINDOW_START;
  if(connection_add(n_stream) < 0) { /* no space, forget it */
    log_fn(LOG_WARN,"connection_add failed. Dropping.");
    connection_free(n_stream);
    return 0;
  }

  log_fn(LOG_DEBUG,"finished adding conn");

  /* add it into the linked list of streams on this circuit */
  n_stream->next_stream = circ->n_streams;
  circ->n_streams = n_stream;
  assert_circuit_ok(circ);

  if(circ->purpose == CIRCUIT_PURPOSE_S_REND_JOINED) {
    log_fn(LOG_DEBUG,"begin is for rendezvous. configuring stream.");
    n_stream->address = tor_strdup("(rendezvous)");
    n_stream->state = EXIT_CONN_STATE_CONNECTING;
    strcpy(n_stream->rend_query, circ->rend_query);
    assert(n_stream->rend_query[0]);
    assert_circuit_ok(circ);
    if(rend_service_set_connection_addr_port(n_stream, circ) < 0) {
      log_fn(LOG_WARN,"Didn't find rendezvous service (port %d)",n_stream->port);
      connection_mark_for_close(n_stream,0 /* XXX */);
      return 0;
    }
    assert_circuit_ok(circ);
    log_fn(LOG_DEBUG,"Finished assigning addr/port");
    n_stream->cpath_layer = circ->cpath->prev; /* link it */
    connection_exit_connect(n_stream);
    return 0;
  }
  n_stream->address = tor_strdup(cell->payload + RELAY_HEADER_SIZE);
  n_stream->state = EXIT_CONN_STATE_RESOLVEFAILED;
  /* default to failed, change in dns_resolve if it turns out not to fail */

  /* send it off to the gethostbyname farm */
  switch(dns_resolve(n_stream)) {
    case 1: /* resolve worked */
      connection_exit_connect(n_stream);
      return 0;
    case -1: /* resolve failed */
      log_fn(LOG_INFO,"Resolve failed (%s).", n_stream->address);
      connection_mark_for_close(n_stream, END_STREAM_REASON_RESOLVEFAILED);
      break;
    case 0: /* resolve added to pending list */
      ;
  }
  return 0;
}

void connection_exit_connect(connection_t *conn) {
  unsigned char connected_payload[4];

  if (!connection_edge_is_rendezvous_stream(conn) &&
      router_compare_to_my_exit_policy(conn) == ADDR_POLICY_REJECTED) {
    log_fn(LOG_INFO,"%s:%d failed exit policy. Closing.", conn->address, conn->port);
    connection_mark_for_close(conn, END_STREAM_REASON_EXITPOLICY);
    return;
  }

  log_fn(LOG_DEBUG,"about to try connecting");
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
  if(connection_edge_is_rendezvous_stream(conn)) { /* rendezvous stream */
    /* don't send an address back! */
    connection_edge_send_command(conn, circuit_get_by_conn(conn), RELAY_COMMAND_CONNECTED,
                                 NULL, 0, conn->cpath_layer);
  } else { /* normal stream */
    *(uint32_t*)connected_payload = htonl(conn->addr);
    connection_edge_send_command(conn, circuit_get_by_conn(conn), RELAY_COMMAND_CONNECTED,
                                 connected_payload, 4, conn->cpath_layer);
  }
}

int connection_edge_is_rendezvous_stream(connection_t *conn) {
  assert(conn);
  if(*conn->rend_query) /* XXX */
    return 1;
  return 0;
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
  int n_failures;
};
static int client_dns_size = 0;
static strmap_t *client_dns_map = NULL;

void client_dns_init(void) {
  client_dns_map = strmap_new();
  client_dns_size = 0;
}

static struct client_dns_entry *
_get_or_create_ent(const char *address)
{
  struct client_dns_entry *ent;
  ent = strmap_get_lc(client_dns_map,address);
  if (!ent) {
    ent = tor_malloc_zero(sizeof(struct client_dns_entry));
    ent->expires = time(NULL)+MAX_DNS_ENTRY_AGE;
    strmap_set_lc(client_dns_map,address,ent);
    ++client_dns_size;
  }
  return ent;
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
  if (!ent || !ent->addr) {
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

static int client_dns_incr_failures(const char *address)
{
  struct client_dns_entry *ent;
  ent = _get_or_create_ent(address);
  return ++ent->n_failures;
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
  ent = _get_or_create_ent(address);
  in.s_addr = htonl(val);
  log_fn(LOG_DEBUG, "Updating entry for address %s: %s", address,
         inet_ntoa(in));
  ent->addr = val;
  ent->expires = now+MAX_DNS_ENTRY_AGE;
  ent->n_failures = 0;
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
