/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

extern or_options_t options; /* command-line and config-file options */

unsigned long stats_n_padding_cells_processed = 0;
unsigned long stats_n_create_cells_processed = 0;
unsigned long stats_n_created_cells_processed = 0;
unsigned long stats_n_relay_cells_processed = 0;
unsigned long stats_n_destroy_cells_processed = 0;

static void command_process_create_cell(cell_t *cell, connection_t *conn);
static void command_process_created_cell(cell_t *cell, connection_t *conn);
static void command_process_relay_cell(cell_t *cell, connection_t *conn);
static void command_process_destroy_cell(cell_t *cell, connection_t *conn);

static void command_time_process_cell(cell_t *cell, connection_t *conn,
                               int *num, int *time,
                               void (*func)(cell_t *, connection_t *)) {
  struct timeval start, end;
  long time_passed; 

  *num += 1;

  tor_gettimeofday(&start);

  (*func)(cell, conn);

  tor_gettimeofday(&end);
  time_passed = tv_udiff(&start, &end) ;

  if (time_passed > 5000) { /* more than 5ms */
    log_fn(LOG_INFO,"That call just took %ld ms.",time_passed/1000);
  }
  *time += time_passed;
}

void command_process_cell(cell_t *cell, connection_t *conn) {
  static int num_create=0, num_created=0, num_relay=0, num_destroy=0;
  static int create_time=0, created_time=0, relay_time=0, destroy_time=0;
  static time_t current_second = 0; /* from previous calls to time */
  time_t now = time(NULL);

  if(now > current_second) { /* the second has rolled over */
    /* print stats */
    log(LOG_INFO,"At end of second:"); 
    log(LOG_INFO,"Create:    %d (%d ms)", num_create, create_time/1000);
    log(LOG_INFO,"Created:   %d (%d ms)", num_created, created_time/1000);
    log(LOG_INFO,"Relay:     %d (%d ms)", num_relay, relay_time/1000);
    log(LOG_INFO,"Destroy:   %d (%d ms)", num_destroy, destroy_time/1000);

    /* zero out stats */
    num_create = num_created = num_relay = num_destroy = 0;
    create_time = created_time = relay_time = destroy_time = 0;

    /* remember which second it is, for next time */
    current_second = now;
  }

  switch(cell->command) {
    case CELL_PADDING:
      ++stats_n_padding_cells_processed;
      /* do nothing */
      break;
    case CELL_CREATE:
      ++stats_n_create_cells_processed;
      command_time_process_cell(cell, conn, &num_create, &create_time,
                                command_process_create_cell);
      break;
    case CELL_CREATED:
      ++stats_n_created_cells_processed;
      command_time_process_cell(cell, conn, &num_created, &created_time,
                                command_process_created_cell);
      break;
    case CELL_RELAY:
      ++stats_n_relay_cells_processed;
      command_time_process_cell(cell, conn, &num_relay, &relay_time,
                                command_process_relay_cell);
      break;
    case CELL_DESTROY:
      ++stats_n_destroy_cells_processed;
      command_time_process_cell(cell, conn, &num_destroy, &destroy_time,
                                command_process_destroy_cell);
      break;
    default:
      log_fn(LOG_WARNING,"Cell of unknown type (%d) received. Dropping.", cell->command);
      break;
  }
}

static void command_process_create_cell(cell_t *cell, connection_t *conn) {
  circuit_t *circ;

  circ = circuit_get_by_aci_conn(cell->aci, conn);

  if(circ) {
    log_fn(LOG_WARNING,"received CREATE cell (aci %d) for known circ. Dropping.", cell->aci);
    return;
  }

  circ = circuit_new(cell->aci, conn);
  circ->state = CIRCUIT_STATE_ONIONSKIN_PENDING;
  if(cell->length != DH_ONIONSKIN_LEN) {
    log_fn(LOG_WARNING,"Bad cell length %d. Dropping.", cell->length);
    circuit_close(circ);
    return;
  }

  memcpy(circ->onionskin,cell->payload,cell->length);

  /* hand it off to the cpuworkers, and then return */
  if(assign_to_cpuworker(NULL, CPUWORKER_TASK_ONION, circ) < 0) {
    log_fn(LOG_WARNING,"Failed to hand off onionskin. Closing.");
    circuit_close(circ);
    return;
  }
  log_fn(LOG_INFO,"success: handed off onionskin.");
}

static void command_process_created_cell(cell_t *cell, connection_t *conn) {
  circuit_t *circ;

  circ = circuit_get_by_aci_conn(cell->aci, conn);

  if(!circ) {
    log_fn(LOG_INFO,"(aci %d) unknown circ (probably got a destroy earlier). Dropping.", cell->aci);
    return;
  }

  if(circ->n_aci != cell->aci) {
    log_fn(LOG_WARNING,"got created cell from OPward? Closing.");
    circuit_close(circ);
    return;
  }
  assert(cell->length == DH_KEY_LEN);

  if(circ->cpath) { /* we're the OP. Handshake this. */
    log_fn(LOG_DEBUG,"at OP. Finishing handshake.");
    if(circuit_finish_handshake(circ, cell->payload) < 0) {
      log_fn(LOG_WARNING,"circuit_finish_handshake failed.");
      circuit_close(circ);
      return;
    }
    log_fn(LOG_DEBUG,"Moving to next skin.");
    if(circuit_send_next_onion_skin(circ) < 0) {
      log_fn(LOG_WARNING,"circuit_send_next_onion_skin failed.");
      circuit_close(circ);
      return;
    }
  } else { /* pack it into an extended relay cell, and send it. */
    log_fn(LOG_INFO,"Converting created cell to extended relay cell, sending.");
    connection_edge_send_command(NULL, circ, RELAY_COMMAND_EXTENDED,
                                 cell->payload, DH_KEY_LEN, NULL);
  }
}

static void command_process_relay_cell(cell_t *cell, connection_t *conn) {
  circuit_t *circ;

  circ = circuit_get_by_aci_conn(cell->aci, conn);

  if(!circ) {
    log_fn(LOG_INFO,"unknown circuit %d. Dropping.", cell->aci);
    return;
  }

  if(circ->state == CIRCUIT_STATE_ONIONSKIN_PENDING) {
    log_fn(LOG_WARNING,"circuit in create_wait. Closing.");
    circuit_close(circ);
    return;
  }

  if(cell->aci == circ->p_aci) { /* it's an outgoing cell */
    cell->aci = circ->n_aci; /* switch it */
    if(circuit_deliver_relay_cell(cell, circ, CELL_DIRECTION_OUT, conn->cpath_layer) < 0) {
      log_fn(LOG_WARNING,"circuit_deliver_relay_cell (forward) failed. Closing.");
      circuit_close(circ);
      return;
    }
  } else { /* it's an ingoing cell */
    cell->aci = circ->p_aci; /* switch it */
    if(circuit_deliver_relay_cell(cell, circ, CELL_DIRECTION_IN, NULL) < 0) {
      log_fn(LOG_WARNING,"circuit_deliver_relay_cell (backward) failed. Closing.");
      circuit_close(circ);
      return;
    }
  }
}

static void command_process_destroy_cell(cell_t *cell, connection_t *conn) {
  circuit_t *circ;

  circ = circuit_get_by_aci_conn(cell->aci, conn);

  if(!circ) {
    log_fn(LOG_INFO,"unknown circuit %d. Dropping.", cell->aci);
    return;
  }

  log_fn(LOG_DEBUG,"Received for aci %d.",cell->aci);
  if(circ->state == CIRCUIT_STATE_ONIONSKIN_PENDING) {
    onion_pending_remove(circ);
  }

  if(cell->aci == circ->p_aci || circ->cpath) {
    /* either the destroy came from behind, or we're the AP */
    circ->p_conn = NULL;
    circuit_close(circ);
  } else { /* the destroy came from ahead */
    circ->n_conn = NULL;
    log_fn(LOG_DEBUG, "Delivering 'truncated' back.");
    connection_edge_send_command(NULL, circ, RELAY_COMMAND_TRUNCATED,
                                 NULL, 0, NULL);
  }
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
