
#include "or.h"

void command_process_cell(cell_t *cell, connection_t *conn) {

  if(check_sane_cell(cell) < 0)
    return;

  switch(cell->command) {
    case CELL_PADDING:
      /* do nothing */
      break;
    case CELL_CREATE:
      command_process_create_cell(cell, conn);
      break;
    case CELL_DATA:
      command_process_data_cell(cell, conn);
      break;
    case CELL_DESTROY:
      command_process_destroy_cell(cell, conn);
      break;
  }
}

void command_process_create_cell(cell_t *cell, connection_t *conn) {
  circuit_t *circ;
  connection_t *n_conn;
  unsigned char *cellbuf; /* array of cells */
  int cellbuflen; /* size of cellbuf in bytes */
  cell_t *tmpcell; /* pointer to an arbitrary cell */
  int retval, i;

  circ = circuit_get_by_aci_conn(cell->aci, conn);

  if(circ && circ->state != CIRCUIT_STATE_OPEN_WAIT) {
    log(LOG_DEBUG,"command_process_create_cell(): received CREATE cell, not in open_wait. Dropping.");
    return;
  }

  if(!circ) { /* if it's not there, create it */
    circ = circuit_new(cell->aci, conn);
    circ->state = CIRCUIT_STATE_OPEN_WAIT;
    memcpy((void *)&circ->onionlen,(void *)cell->payload, 4);
    circ->onionlen = ntohl(circ->onionlen);
    log(LOG_DEBUG,"command_process_create_cell():  Onion length is %u.",circ->onionlen);
    if(circ->onionlen > 50000) { /* too big */
      log(LOG_DEBUG,"That's ludicrous. Closing.");
      circuit_close(circ);
      return;
    }
    circ->onion = (unsigned char *)malloc(circ->onionlen);
    if(!circ->onion) { 
      log(LOG_DEBUG,"command_process_create_cell(): Out of memory. Closing.");
      circuit_close(circ);
      return;
    }
    if(circ->onionlen < cell->length-4) { /* protect from buffer overflow */
      log(LOG_DEBUG,"command_process_create_cell(): Onion too small. Closing.");
      circuit_close(circ);
      return;
    }
    memcpy((void *)circ->onion,(void *)(cell->payload+4),cell->length-4);
    circ->recvlen = cell->length-4;
    log(LOG_DEBUG,"command_process_create_cell(): Primary create cell handled, have received %d of %d onion bytes.",
        circ->recvlen,circ->onionlen);

  } else { /* pull over as much of the onion as we can */
    if(cell->length + circ->recvlen > circ->onionlen) { /* protect from buffer overflow */
      log(LOG_DEBUG,"command_process_create_cell(): payload too big for onion. Closing.");
      circuit_close(circ);
      return;
    }
    memcpy((void *)(circ->onion+circ->recvlen),(void *)cell->payload,cell->length);
    circ->recvlen += cell->length;
    log(LOG_DEBUG,"command_process_create_cell(): Secondary create cell handled, have received %d of %d onion bytes.",
        circ->recvlen,circ->onionlen);
  }

  if(circ->recvlen != circ->onionlen) {
    log(LOG_DEBUG,"command_process_create_cell(): Onion not all here yet. Ok.");
    return;
  }

  /* we're all ready to go now. */ 
  circ->state = CIRCUIT_STATE_OPEN;

  if(process_onion(circ, conn) < 0) {
    log(LOG_DEBUG,"command_process_create_cell(): Onion processing failed. Closing.");
    circuit_close(circ);
    return;
  }

  if(circ->n_addr && circ->n_port) { /* must send create cells to the next router */
    n_conn = connection_get_by_addr_port(circ->n_addr,circ->n_port);
    if(!n_conn || n_conn->type != CONN_TYPE_OR) {
      /* i've disabled making connections through OPs, but it's definitely
       * possible here. I'm not sure if it would be a bug or a feature. -RD
       */
      log(LOG_DEBUG,"command_process_create_cell(): Next router not connected. Closing.");
      circuit_close(circ);
    }
    circ->n_conn = n_conn;
    log(LOG_DEBUG,"command_process_create_cell(): n_conn is %s:%u",n_conn->address,ntohs(n_conn->port));

    /* send the CREATE cells on to the next hop  */
    pad_onion(circ->onion,circ->onionlen, sizeof(onion_layer_t));
    log(LOG_DEBUG,"command_process_create_cell(): Padded the onion with random data.");

    retval = pack_create(circ->n_aci, circ->onion, circ->onionlen, &cellbuf, &cellbuflen);
    free((void *)circ->onion);
    circ->onion = NULL;
    if (retval == -1) /* pack_create() error */
    {
      log(LOG_DEBUG,"command_process_create_cell(): Could not pack the onion into CREATE cells. Closing the connection.");
      circuit_close(circ);
      return;
    }
    log(LOG_DEBUG,"command_process_create_cell(): Onion packed into CREATE cells. Buffering the cells.");
    /* queue the create cells for transmission to the next hop */
    tmpcell = (cell_t *)cellbuf;
    for (i=0;i<cellbuflen/sizeof(cell_t);i++)
    {
      retval = connection_write_cell_to_buf(tmpcell, n_conn);
      if (retval == -1) /* buffering failed, drop the connection */
      {
        log(LOG_DEBUG,"command_process_create_cell(): Could not buffer new create cells. Closing.");
        circuit_close(circ);
        return;
      }
      tmpcell++;
    }
    free((void *)cellbuf);
    return;

  } else { /* this is destined for an app */
    log(LOG_DEBUG,"command_process_create_cell(): Creating new application connection.");
    n_conn = connection_new(CONN_TYPE_APP);
    if(!n_conn) {
      log(LOG_DEBUG,"command_process_create_cell(): connection_new failed. Closing.");
      circuit_close(circ);
      return;
    }
    n_conn->state = APP_CONN_STATE_CONNECTING_WAIT;
    n_conn->s = -1; /* not yet valid */
    if(connection_add(n_conn) < 0) { /* no space, forget it */
      log(LOG_DEBUG,"command_process_create_cell(): connection_add failed. Closing.");
      connection_free(n_conn);
      circuit_close(circ);
      return;
    }
    circ->n_conn = n_conn;
    return;
  }

}

void command_process_data_cell(cell_t *cell, connection_t *conn) {
  circuit_t *circ;

  /* FIXME do something with 'close' state, here */

  circ = circuit_get_by_aci_conn(cell->aci, conn);

  if(!circ) {
    log(LOG_DEBUG,"command_process_data_cell(): received DATA cell for unknown circuit. Dropping.");
    return;
  }

  if(circ->state == CIRCUIT_STATE_OPEN_WAIT) {
    log(LOG_DEBUG,"command_process_data_cell(): circuit in open_wait. Dropping data cell.");
    return;
  }

  /* at this point both circ->n_conn and circ->p_conn are guaranteed to be set */

  if(cell->aci == circ->p_aci) { /* it's an outgoing cell */
    cell->aci = circ->n_aci; /* switch it */
    if(circuit_deliver_data_cell(cell, circ, circ->n_conn, 'd') < 0) {
      log(LOG_DEBUG,"command_process_data_cell(): circuit_deliver_data_cell (forward) failed. Closing.");
      circuit_close(circ);
      return;
    }
  } else { /* it's an ingoing cell */
    cell->aci = circ->p_aci; /* switch it */
    if(circuit_deliver_data_cell(cell, circ, circ->p_conn, 'e') < 0) {
      log(LOG_DEBUG,"command_process_data_cell(): circuit_deliver_data_cell (backward) failed. Closing.");
      circuit_close(circ);
      return;
    }
  }
}

void command_process_destroy_cell(cell_t *cell, connection_t *conn) {
  circuit_t *circ;

  circ = circuit_get_by_aci_conn(cell->aci, conn);

  if(!circ) {
    log(LOG_DEBUG,"command_process_destroy_cell(): received DESTROY cell for unknown circuit. Dropping.");
    return;
  }

  log(LOG_DEBUG,"command_process_destroy_cell(): Received for aci %d.",cell->aci);
  circuit_remove(circ);
  if(cell->aci == circ->p_aci) /* the destroy came from behind */
    connection_send_destroy(circ->n_aci, circ->n_conn);
  if(cell->aci == circ->n_aci) /* the destroy came from ahead */
    connection_send_destroy(circ->p_aci, circ->p_conn);
  circuit_free(circ);

}

