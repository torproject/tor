/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

extern or_options_t options; /* command-line and config-file options */

/**************************************************************/

static void cell_pack(char *dest, const cell_t *src) {
  *(uint16_t*)dest     = htons(src->aci);
  *(uint8_t*)(dest+2)  = src->command;
  *(uint8_t*)(dest+3)  = src->length;
  *(uint32_t*)(dest+4) = 0; /* Reserved */
  memcpy(dest+8, src->payload, CELL_PAYLOAD_SIZE);
}

static void cell_unpack(cell_t *dest, const char *src) {
  dest->aci     = ntohs(*(uint16_t*)(src));
  dest->command = *(uint8_t*)(src+2);
  dest->length  = *(uint8_t*)(src+3);
  dest->seq     = ntohl(*(uint32_t*)(src+4));
  memcpy(dest->payload, src+8, CELL_PAYLOAD_SIZE);
}

/**************************************************************/

int connection_or_process_inbuf(connection_t *conn) {

  assert(conn && conn->type == CONN_TYPE_OR);

  if(conn->inbuf_reached_eof) {
    log_fn(LOG_INFO,"conn reached eof. Closing.");
    return -1;
  }

  if(conn->state != OR_CONN_STATE_OPEN)
    return 0; /* don't do anything */
  return connection_process_cell_from_inbuf(conn);
}

int connection_or_finished_flushing(connection_t *conn) {
  int e, len=sizeof(e);

  assert(conn && conn->type == CONN_TYPE_OR);

  switch(conn->state) {
    case OR_CONN_STATE_CONNECTING:
      if (getsockopt(conn->s, SOL_SOCKET, SO_ERROR, (void*)&e, &len) < 0)  { /* not yet */
        if(!ERRNO_CONN_EINPROGRESS(errno)){
          log_fn(LOG_DEBUG,"in-progress connect failed. Removing.");
          return -1;
        } else {
          return 0; /* no change, see if next time is better */
        }
      }
      /* the connect has finished. */

      log_fn(LOG_INFO,"OR connect() to router %s:%u finished.",
          conn->address,conn->port);

      if(connection_tls_start_handshake(conn, 0) < 0)
        return -1;
      return 0;
    case OR_CONN_STATE_OPEN:
      connection_stop_writing(conn);
      return 0;
    default:
      log_fn(LOG_WARNING,"BUG: called in unexpected state.");
      return 0;
  }
}

/*********************/

void connection_or_init_conn_from_router(connection_t *conn, routerinfo_t *router) {
  conn->addr = router->addr;
  conn->port = router->or_port;
  conn->receiver_bucket = conn->bandwidth = router->bandwidth;
  conn->onion_pkey = crypto_pk_dup_key(router->onion_pkey);
  conn->link_pkey = crypto_pk_dup_key(router->link_pkey);
  conn->identity_pkey = crypto_pk_dup_key(router->identity_pkey);
  conn->nickname = strdup(router->nickname);
  if(conn->address)
    free(conn->address);
  conn->address = strdup(router->address);
}

connection_t *connection_or_connect(routerinfo_t *router) {
  connection_t *conn;

  assert(router);

  if(router_is_me(router->addr, router->or_port)) {
    /* this is me! don't connect to me. XXX use nickname/key */
    log(LOG_DEBUG,"connection_or_connect(): This is me. Skipping.");
    return NULL;
  }

  /* this function should never be called if we're already connected to router, but */
  /* check first to be sure */
  conn = connection_exact_get_by_addr_port(router->addr,router->or_port);
  if(conn)
    return conn;

  conn = connection_new(CONN_TYPE_OR);

  /* set up conn so it's got all the data we need to remember */
  connection_or_init_conn_from_router(conn, router);

  if(connection_add(conn) < 0) { /* no space, forget it */
    connection_free(conn);
    return NULL;
  }

  switch(connection_connect(conn, router->address, router->addr, router->or_port)) {
    case -1:
      connection_remove(conn);
      connection_free(conn);
      return NULL;
    case 0:
      connection_set_poll_socket(conn);
      connection_watch_events(conn, POLLIN | POLLOUT | POLLERR); 
      /* writable indicates finish, readable indicates broken link,
         error indicates broken link on windows */
      conn->state = OR_CONN_STATE_CONNECTING;
      return conn;
    /* case 1: fall through */
  }

  connection_set_poll_socket(conn);

  if(connection_tls_start_handshake(conn, 0) >= 0)
    return conn;

  /* failure */
  connection_remove(conn);
  connection_free(conn);
  return NULL;
}

/* ********************************** */

int connection_write_cell_to_buf(const cell_t *cellp, connection_t *conn) {
  char networkcell[CELL_NETWORK_SIZE];
  char *n = networkcell;

  cell_pack(n, cellp);
 
  return connection_write_to_buf(n, CELL_NETWORK_SIZE, conn);
}

/* if there's a whole cell there, pull it off and process it. */
int connection_process_cell_from_inbuf(connection_t *conn) {
  char buf[CELL_NETWORK_SIZE];
  cell_t cell;

  log_fn(LOG_DEBUG,"%d: starting, inbuf_datalen %d.",conn->s,buf_datalen(conn->inbuf));
  if(buf_datalen(conn->inbuf) < CELL_NETWORK_SIZE) /* entire response available? */
    return 0; /* not yet */
 
  connection_fetch_from_buf(buf, CELL_NETWORK_SIZE, conn);
 
  /* retrieve cell info from buf (create the host-order struct from the network-order string) */
  cell_unpack(&cell, buf);
 
  command_process_cell(&cell, conn);
 
  return connection_process_inbuf(conn); /* process the remainder of the buffer */
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
