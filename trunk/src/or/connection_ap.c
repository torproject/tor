/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

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
  circ = circuit_get_newest_by_edge_type(EDGE_AP);

  if(!circ) {
    log(LOG_INFO,"ap_handshake_process_socks(): No circuit ready. Closing.");
    return -1;
  }

  circ->dirty = 1;

  /* add it into the linked list of topics on this circuit */
  log(LOG_DEBUG,"ap_handshake_process_socks(): attaching new conn to circ. n_aci %d.", circ->n_aci);
  conn->next_topic = circ->p_conn;
  circ->p_conn = conn;

  if(ap_handshake_send_begin(conn, circ) < 0) {
    circuit_close(circ);
    return -1;
  }

  return 0;
}

int ap_handshake_send_begin(connection_t *ap_conn, circuit_t *circ) {
  cell_t cell;
  uint16_t topic_id;

  memset(&cell, 0, sizeof(cell_t));
  /* deliver the dest_addr in a data cell */
  cell.command = CELL_DATA;
  cell.aci = circ->n_aci;
  SET_CELL_TOPIC_COMMAND(cell, TOPIC_COMMAND_BEGIN);
  if (CRYPTO_PSEUDO_RAND_INT(topic_id))
    return -1;
  SET_CELL_TOPIC_ID(cell, topic_id);
  /* FIXME check for collisions */
  ap_conn->topic_id = topic_id;

  snprintf(cell.payload+4, CELL_PAYLOAD_SIZE-4, "%s:%d", ap_conn->dest_addr, ap_conn->dest_port);
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

int connection_ap_create_listener(struct sockaddr_in *bindaddr) {
  log(LOG_DEBUG,"connection_create_ap_listener starting");
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
