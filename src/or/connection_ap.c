/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

int ap_handshake_process_socks(connection_t *conn) {
  socks4_t socks4_info; 
  circuit_t *circ;
  char tmpbuf[512];
  int amt;

  assert(conn);

  log_fn(LOG_DEBUG,"entered.");

  if(!conn->socks_version) { /* try to pull it in */

    if(conn->inbuf_datalen < sizeof(socks4_t)) /* basic info available? */
      return 0; /* not yet */

    if(connection_fetch_from_buf((char *)&socks4_info,sizeof(socks4_t),conn) < 0)
      return -1;

    log_fn(LOG_DEBUG,"Successfully read socks info.");

    if(socks4_info.version != 4) {
      log_fn(LOG_NOTICE,"Unrecognized version %d.",socks4_info.version);
      ap_handshake_socks_reply(conn, SOCKS4_REQUEST_REJECT);
      return -1;
    }
    conn->socks_version = socks4_info.version;

    if(socks4_info.command != 1) { /* not a connect? we don't support it. */
      log_fn(LOG_NOTICE,"command %d not '1'.",socks4_info.command);
      ap_handshake_socks_reply(conn, SOCKS4_REQUEST_REJECT);
      return -1;
    }

    conn->dest_port = ntohs(*(uint16_t*)&socks4_info.destport);
    if(!conn->dest_port) {
      log_fn(LOG_NOTICE,"Port is zero.");
      ap_handshake_socks_reply(conn, SOCKS4_REQUEST_REJECT);
      return -1;
    }
    log_fn(LOG_NOTICE,"Dest port is %d.",conn->dest_port);

    if(socks4_info.destip[0] || 
       socks4_info.destip[1] ||
       socks4_info.destip[2] ||
       !socks4_info.destip[3]) { /* not 0.0.0.x */
      log_fn(LOG_NOTICE,"destip not in form 0.0.0.x.");
      sprintf(tmpbuf, "%d.%d.%d.%d", socks4_info.destip[0],
        socks4_info.destip[1], socks4_info.destip[2], socks4_info.destip[3]);
      conn->dest_addr = strdup(tmpbuf);
      log_fn(LOG_DEBUG,"Successfully read destip (%s)", conn->dest_addr);
    }

  }

  if(!conn->read_username) { /* the socks spec says we've got to read stuff until we get a null */
    amt = connection_find_on_inbuf("\0", 1, conn);
    if(amt < 0) /* not there yet */
      return 0;
    if(amt > 500) {
      log_fn(LOG_NOTICE,"username too long.");    
      ap_handshake_socks_reply(conn, SOCKS4_REQUEST_REJECT);
      return -1;
    }
    if(connection_fetch_from_buf(tmpbuf,amt,conn) < 0)
      return -1;
    conn->read_username = 1;
    log_fn(LOG_DEBUG,"Successfully read username.");
  }

  if(!conn->dest_addr) { /* no dest_addr found yet */
    amt = connection_find_on_inbuf("\0", 1, conn);
    if(amt < 0) /* not there yet */
      return 0;
    if(amt > 500) {
      log_fn(LOG_NOTICE,"dest_addr too long.");    
      ap_handshake_socks_reply(conn, SOCKS4_REQUEST_REJECT);
      return -1;
    }
    if(connection_fetch_from_buf(tmpbuf,amt,conn) < 0)
      return -1;

    conn->dest_addr = strdup(tmpbuf);
    log_fn(LOG_NOTICE,"successfully read dest addr '%s'",
      conn->dest_addr);
  }

  /* find the circuit that we should use, if there is one. */
  circ = circuit_get_newest_ap();

  if(!circ) {
    log_fn(LOG_INFO,"No circuit ready. Closing.");
    return -1;
  }

  circ->dirty = 1;

  /* add it into the linked list of streams on this circuit */
  log_fn(LOG_DEBUG,"attaching new conn to circ. n_aci %d.", circ->n_aci);
  conn->next_stream = circ->p_streams;
  circ->p_streams = conn;

  assert(circ->cpath && circ->cpath->prev);
  assert(circ->cpath->prev->state == CPATH_STATE_OPEN);
  conn->cpath_layer = circ->cpath->prev;

  if(ap_handshake_send_begin(conn, circ) < 0) {
    circuit_close(circ);
    return -1;
  }

  return 0;
}

int ap_handshake_send_begin(connection_t *ap_conn, circuit_t *circ) {
  cell_t cell;

  memset(&cell, 0, sizeof(cell_t));
  /* deliver the dest_addr in a relay cell */
  cell.command = CELL_RELAY;
  cell.aci = circ->n_aci;
  SET_CELL_RELAY_COMMAND(cell, RELAY_COMMAND_BEGIN);
  if(crypto_pseudo_rand(STREAM_ID_SIZE, ap_conn->stream_id) < 0)
    return -1;
  /* FIXME check for collisions */
  SET_CELL_STREAM_ID(cell, ZERO_STREAM);

  memcpy(cell.payload+RELAY_HEADER_SIZE, ap_conn->stream_id, STREAM_ID_SIZE);
  cell.length = 
    snprintf(cell.payload+RELAY_HEADER_SIZE+STREAM_ID_SIZE, CELL_PAYLOAD_SIZE-RELAY_HEADER_SIZE-STREAM_ID_SIZE,
             "%s:%d", ap_conn->dest_addr, ap_conn->dest_port) + 
    1 + STREAM_ID_SIZE + RELAY_HEADER_SIZE;
  log_fn(LOG_DEBUG,"Sending relay cell (id %d) to begin stream %d.", *(int *)(cell.payload+1),*(int *)ap_conn->stream_id);
  if(circuit_deliver_relay_cell(&cell, circ, CELL_DIRECTION_OUT, ap_conn->cpath_layer) < 0) {
    log_fn(LOG_DEBUG,"failed to deliver begin cell. Closing.");
    return -1;
  }
  ap_conn->package_window = STREAMWINDOW_START;
  ap_conn->deliver_window = STREAMWINDOW_START;
  ap_conn->state = AP_CONN_STATE_OPEN;
  log_fn(LOG_INFO,"Address/port sent, ap socket %d, n_aci %d",ap_conn->s,circ->n_aci);
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

int connection_ap_create_listener(struct sockaddr_in *bindaddr) {
  log_fn(LOG_DEBUG,"starting");
  return connection_create_listener(bindaddr, CONN_TYPE_AP_LISTENER);
}

int connection_ap_handle_listener_read(connection_t *conn) {
  log(LOG_NOTICE,"AP: Received a connection request. Waiting for socksinfo.");
  return connection_handle_listener_read(conn, CONN_TYPE_AP, AP_CONN_STATE_SOCKS_WAIT);
} 

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
