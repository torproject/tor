/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

extern or_options_t options; /* command-line and config-file options */

void command_time_process_cell(cell_t *cell, connection_t *conn,
                               int *num, int *time,
                               void (*func)(cell_t *, connection_t *)) {
  struct timeval start, end;
  long time_passed; 

  *num += 1;

  my_gettimeofday(&start);

  (*func)(cell, conn);

  my_gettimeofday(&end);
  time_passed = tv_udiff(&start, &end) ;

  if (time_passed > 5000) { /* more than 5ms */
    log(LOG_INFO,"command_time_process_cell(): That call just took %d ms.",time_passed/1000);
  }
  *time += time_passed;
}

void command_process_cell(cell_t *cell, connection_t *conn) {
  static int num_create=0, num_created=0, num_relay=0, num_destroy=0, num_sendme=0;
  static int create_time=0, created_time=0, relay_time=0, destroy_time=0, sendme_time=0;
  static long current_second = 0; /* from previous calls to gettimeofday */
  struct timeval now;

  my_gettimeofday(&now);

  if(now.tv_sec > current_second) { /* the second has rolled over */
    /* print stats */
    log(LOG_INFO,"At end of second:"); 
    log(LOG_INFO,"Create:    %d (%d ms)", num_create, create_time/1000);
    log(LOG_INFO,"Created:   %d (%d ms)", num_created, created_time/1000);
    log(LOG_INFO,"Relay:     %d (%d ms)", num_relay, relay_time/1000);
    log(LOG_INFO,"Destroy:   %d (%d ms)", num_destroy, destroy_time/1000);
    log(LOG_INFO,"Sendme:    %d (%d ms)", num_sendme, sendme_time/1000);

    /* zero out stats */
    num_create = num_created = num_relay = num_destroy = num_sendme = 0;
    create_time = created_time = relay_time = destroy_time = sendme_time = 0;

    /* remember which second it is, for next time */
    current_second = now.tv_sec; 
  }

  log(LOG_DEBUG,"command_process_cell(): Examining cell type %d.", cell->command);
  switch(cell->command) {
    case CELL_PADDING:
      /* do nothing */
      break;
    case CELL_CREATE:
      command_time_process_cell(cell, conn, &num_create, &create_time,
                                command_process_create_cell);
      break;
    case CELL_CREATED:
      command_time_process_cell(cell, conn, &num_created, &created_time,
                                command_process_created_cell);
      break;
    case CELL_RELAY:
      command_time_process_cell(cell, conn, &num_relay, &relay_time,
                                command_process_relay_cell);
      break;
    case CELL_DESTROY:
      command_time_process_cell(cell, conn, &num_destroy, &destroy_time,
                                command_process_destroy_cell);
      break;
    case CELL_SENDME:
      command_time_process_cell(cell, conn, &num_sendme, &sendme_time,
                                command_process_sendme_cell);
      break;
    default:
      log(LOG_DEBUG,"Cell of unknown type (%d) received. Dropping.", cell->command);
      break;
  }
}

void command_process_create_cell(cell_t *cell, connection_t *conn) {
  circuit_t *circ;

  circ = circuit_get_by_aci_conn(cell->aci, conn);

  if(circ) {
    log(LOG_DEBUG,"command_process_create_cell(): received CREATE cell for known circ. Dropping.");
    return;
  }

  circ = circuit_new(cell->aci, conn);
  circ->state = CIRCUIT_STATE_ONIONSKIN_PENDING;
  if(cell->length != 208) {
    log(LOG_DEBUG,"command_process_create_cell(): Bad cell length %d. Dropping.", cell->length);
    circuit_close(circ);
    return;
  }

  memcpy(circ->onionskin,cell->payload,cell->length);

  /* add it to the pending onions queue, and then return */
  if(onion_pending_add(circ) < 0) {
    log(LOG_DEBUG,"command_process_create_cell(): Failed to queue onionskin. Closing.");
    circuit_close(circ);
  }
  log(LOG_DEBUG,"command_process_create_cell(): success: queued onionskin.");
  return;
}

void command_process_created_cell(cell_t *cell, connection_t *conn) {
  circuit_t *circ;
  cell_t newcell;

  circ = circuit_get_by_aci_conn(cell->aci, conn);

  if(!circ) {
    log(LOG_DEBUG,"command_process_created_cell(): received CREATED cell for unknown circ. Dropping.");
    return;
  }

  if(circ->n_aci != cell->aci) {
    log(LOG_DEBUG,"command_process_created_cell(): got created cell from OPward? Dropping.");
    return;
  }
  assert(cell->length == 192);

  if(circ->cpath) { /* we're the OP. Handshake this. */
    log(LOG_DEBUG,"command_process_created_cell(): at OP. Finishing handshake.");
    if(circuit_finish_handshake(circ, cell->payload) < 0) {
      log(LOG_INFO,"command_process_created_cell(): circuit_finish_handshake failed.");
      circuit_close(circ);
      return;
    }
    log(LOG_DEBUG,"command_process_created_cell(): Moving to next skin.");
    if(circuit_send_next_onion_skin(circ) < 0) {
      log(LOG_INFO,"command_process_created_cell(): circuit_send_next_onion_skin failed.");
      circuit_close(circ);
      return;
    }
  } else { /* pack it into an extended relay cell, and send it. */
    memset(&newcell, 0, sizeof(cell_t));
    newcell.command = CELL_RELAY;
    newcell.aci = circ->p_aci;
    SET_CELL_RELAY_COMMAND(newcell, RELAY_COMMAND_EXTENDED);
    SET_CELL_STREAM_ID(newcell, ZERO_STREAM);

    newcell.length = RELAY_HEADER_SIZE + cell->length;
    memcpy(newcell.payload+RELAY_HEADER_SIZE, cell->payload, 192);

    log(LOG_DEBUG,"command_process_created_cell(): Sending extended relay cell.");
    if(circuit_deliver_relay_cell_from_edge(&newcell, circ, EDGE_EXIT, NULL) < 0) {
      log(LOG_DEBUG,"command_process_created_cell(): failed to deliver extended cell. Closing.");
      circuit_close(circ);
      return;
    }
  }
  return;
}

void command_process_sendme_cell(cell_t *cell, connection_t *conn) {
  circuit_t *circ;

  circ = circuit_get_by_aci_conn(cell->aci, conn);

  if(!circ) {
    log(LOG_DEBUG,"command_process_sendme_cell(): unknown circuit %d. Dropping.", cell->aci);
    return;
  }

#if 0
  if(circ->state == CIRCUIT_STATE_ONION_WAIT) {
    log(LOG_DEBUG,"command_process_sendme_cell(): circuit in onion_wait. Dropping.");
    return;
  }
  if(circ->state == CIRCUIT_STATE_OR_WAIT) {
    log(LOG_DEBUG,"command_process_sendme_cell(): circuit in or_wait. Dropping.");
    return;
  }
#endif

  /* at this point both circ->n_conn and circ->p_conn are guaranteed to be set */

  if(cell->length != CIRCWINDOW_INCREMENT) {
    log(LOG_WARNING,"command_process_sendme_cell(): non-standard sendme value %d.",cell->length);
  }

  if(cell->aci == circ->p_aci) { /* it's an outgoing cell */
    circ->n_receive_circwindow += cell->length;
    assert(circ->n_receive_circwindow <= CIRCWINDOW_START);
    log(LOG_DEBUG,"command_process_sendme_cell(): n_receive_circwindow for aci %d is %d.",circ->n_aci,circ->n_receive_circwindow);
    if(!circ->n_conn || circ->n_conn->type == CONN_TYPE_EXIT) {
      circuit_resume_edge_reading(circ, EDGE_EXIT);
    } else {
      cell->aci = circ->n_aci; /* switch it */
      if(connection_write_cell_to_buf(cell, circ->n_conn) < 0) {
        circuit_close(circ);
        return;
      }
    }
  } else { /* it's an ingoing cell */
    assert(cell->aci == circ->n_aci);
    circ->p_receive_circwindow += cell->length;
    log(LOG_DEBUG,"command_process_sendme_cell(): p_receive_circwindow for aci %d is %d.",circ->p_aci,circ->p_receive_circwindow);
    assert(circ->p_receive_circwindow <= CIRCWINDOW_START);
    if(!circ->p_conn || circ->p_conn->type == CONN_TYPE_AP) {
      circuit_resume_edge_reading(circ, EDGE_AP);
    } else {
      cell->aci = circ->p_aci; /* switch it */
      if(connection_write_cell_to_buf(cell, circ->p_conn) < 0) {
        circuit_close(circ);
        return;
      }
    }
  } 
}

void command_process_relay_cell(cell_t *cell, connection_t *conn) {
  circuit_t *circ;

  circ = circuit_get_by_aci_conn(cell->aci, conn);

  if(!circ) {
    log(LOG_DEBUG,"command_process_relay_cell(): unknown circuit %d. Dropping.", cell->aci);
    return;
  }

  if(circ->state == CIRCUIT_STATE_ONIONSKIN_PENDING) {
    log(LOG_DEBUG,"command_process_relay_cell(): circuit in create_wait. Queueing relay cell.");
    onion_pending_relay_add(circ, cell);
    return;
  }

  if(cell->aci == circ->p_aci) { /* it's an outgoing cell */
    if(--circ->p_receive_circwindow < 0) { /* is it less than 0 after decrement? */
      log(LOG_INFO,"command_process_relay_cell(): Too many relay cells for out circuit (aci %d). Closing.", circ->p_aci);
      circuit_close(circ);
      return;
    }
    log(LOG_DEBUG,"command_process_relay_cell(): p_receive_circwindow for aci %d is %d.",circ->p_aci,circ->p_receive_circwindow);
  }

  if(cell->aci == circ->n_aci) { /* it's an ingoing cell */
    if(--circ->n_receive_circwindow < 0) { /* is it less than 0 after decrement? */
      log(LOG_INFO,"command_process_relay_cell(): Too many relay cells for in circuit (aci %d). Closing.", circ->n_aci);
      circuit_close(circ);
      return;
    }
    log(LOG_DEBUG,"command_process_relay_cell(): n_receive_circwindow for aci %d is %d.",circ->n_aci,circ->n_receive_circwindow);
  }

#if 0
  if(circ->state == CIRCUIT_STATE_ONION_WAIT) {
    log(LOG_WARNING,"command_process_relay_cell(): circuit in onion_wait. Dropping relay cell.");
    return;
  }
  if(circ->state == CIRCUIT_STATE_OR_WAIT) {
    log(LOG_WARNING,"command_process_relay_cell(): circuit in or_wait. Dropping relay cell.");
    return;
  }
#endif
  /* circ->p_conn and n_conn are only null if we're at an edge point with no connections yet */

  if(cell->aci == circ->p_aci) { /* it's an outgoing cell */
    cell->aci = circ->n_aci; /* switch it */
    if(circuit_deliver_relay_cell(cell, circ, CELL_DIRECTION_OUT, conn->cpath_layer) < 0) {
      log(LOG_INFO,"command_process_relay_cell(): circuit_deliver_relay_cell (forward) failed. Closing.");
      circuit_close(circ);
      return;
    }
  } else { /* it's an ingoing cell */
    cell->aci = circ->p_aci; /* switch it */
    if(circuit_deliver_relay_cell(cell, circ, CELL_DIRECTION_IN, NULL) < 0) {
      log(LOG_DEBUG,"command_process_relay_cell(): circuit_deliver_relay_cell (backward) failed. Closing.");
      circuit_close(circ);
      return;
    }
  }
}

void command_process_destroy_cell(cell_t *cell, connection_t *conn) {
  circuit_t *circ;

  circ = circuit_get_by_aci_conn(cell->aci, conn);

  if(!circ) {
    log(LOG_DEBUG,"command_process_destroy_cell(): unknown circuit %d. Dropping.", cell->aci);
    return;
  }

  log(LOG_DEBUG,"command_process_destroy_cell(): Received for aci %d.",cell->aci);
  if(circ->state == CIRCUIT_STATE_ONIONSKIN_PENDING) {
    onion_pending_remove(circ);
  }

  if(cell->aci == circ->p_aci) /* the destroy came from behind */
    circ->p_conn = NULL;
  if(cell->aci == circ->n_aci) /* the destroy came from ahead */
    circ->n_conn = NULL;
  circuit_close(circ);
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
