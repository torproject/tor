/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/********* START VARIABLES **********/

extern or_options_t options; /* command-line and config-file options */

extern int global_read_bucket;

char *conn_type_to_string[] = {
  "",            /* 0 */
  "OP listener", /* 1 */
  "OP",          /* 2 */
  "OR listener", /* 3 */
  "OR",          /* 4 */
  "Exit",        /* 5 */
  "App listener",/* 6 */
  "App",         /* 7 */
  "Dir listener",/* 8 */
  "Dir",         /* 9 */
  "DNS worker",  /* 10 */
  "CPU worker",  /* 11 */
};

char *conn_state_to_string[][_CONN_TYPE_MAX+1] = {
  { NULL }, /* no type associated with 0 */
  { NULL }, /* op listener, obsolete */
  { NULL }, /* op, obsolete */
  { "ready" }, /* or listener, 0 */
  { "",                         /* OR, 0 */
    "connect()ing",                 /* 1 */
    "handshaking",                  /* 2 */
    "open" },                       /* 3 */
  { "",                          /* exit, 0 */
    "waiting for dest info",           /* 1 */
    "connecting",                      /* 2 */
    "open"                             /* 3 */
    "resolve failed" },                /* 4 */
  { "ready" }, /* app listener, 0 */
  { "", /* 0 */
    "", /* 1 */
    "", /* 2 */
    "", /* 3 */
    "", /* 4 */
    "awaiting dest info",         /* app, 5 */
    "waiting for safe circuit",        /* 6 */
    "waiting for connected",           /* 7 */
    "open" },                          /* 8 */
  { "ready" }, /* dir listener, 0 */
  { "",                           /* dir, 0 */
    "connecting (fetch)",              /* 1 */
    "connecting (upload)",             /* 2 */
    "client sending fetch",            /* 3 */
    "client sending upload",           /* 4 */
    "client reading fetch",            /* 5 */
    "client reading upload",           /* 6 */
    "awaiting command",                /* 7 */
    "writing" },                       /* 8 */
  { "",                    /* dns worker, 0 */
    "idle",                            /* 1 */
    "busy" },                          /* 2 */
  { "",                    /* cpu worker, 0 */
    "idle",                            /* 1 */
    "busy with onion",                 /* 2 */
    "busy with handshake" },           /* 3 */
};

/********* END VARIABLES ************/

static int connection_init_accepted_conn(connection_t *conn);
static int connection_handle_listener_read(connection_t *conn, int new_type);

/**************************************************************/

connection_t *connection_new(int type) {
  connection_t *conn;
  time_t now = time(NULL);

  conn = tor_malloc_zero(sizeof(connection_t));
  conn->magic = CONNECTION_MAGIC;
  conn->s = -1; /* give it a default of 'not used' */

  conn->type = type;
  if(!connection_is_listener(conn)) { /* listeners never use their buf */
    conn->inbuf = buf_new();
    conn->outbuf = buf_new();
  }
  if (type == CONN_TYPE_AP) {
    conn->socks_request = tor_malloc_zero(sizeof(socks_request_t));
  }

  conn->next_circ_id = crypto_pseudo_rand_int(1<<15);

  conn->timestamp_created = now;
  conn->timestamp_lastread = now;
  conn->timestamp_lastwritten = now;

  return conn;
}

void connection_free(connection_t *conn) {
  assert(conn);
  assert(conn->magic == CONNECTION_MAGIC);

  if(!connection_is_listener(conn)) {
    buf_free(conn->inbuf);
    buf_free(conn->outbuf);
  }
  tor_free(conn->address);

  if(connection_speaks_cells(conn)) {
    directory_set_dirty();
    if (conn->tls)
      tor_tls_free(conn->tls);
  }

  if (conn->onion_pkey)
    crypto_free_pk_env(conn->onion_pkey);
  if (conn->link_pkey)
    crypto_free_pk_env(conn->link_pkey);
  if (conn->identity_pkey)
    crypto_free_pk_env(conn->identity_pkey);
  tor_free(conn->nickname);
  tor_free(conn->socks_request);

  if(conn->s >= 0) {
    log_fn(LOG_INFO,"closing fd %d.",conn->s);
    close(conn->s);
  }
  memset(conn, 0xAA, sizeof(connection_t)); /* poison memory */
  free(conn);
}

void connection_free_all(void) {
  int i, n;
  connection_t **carray;

  get_connection_array(&carray,&n);
  for(i=0;i<n;i++)
    connection_free(carray[i]);
}

/* Close the underlying socket for conn, so we don't try to flush it.
 * Must be used in conjunction with connection_mark_for_close
 */
void connection_close_immediate(connection_t *conn)
{
  assert_connection_ok(conn,0);
  if (conn->s < 0) {
    log_fn(LOG_WARN,"Attempt to close already-closed connection.");
    return;
  }
  close(conn->s);
  conn->s = -1;
  if(!connection_is_listener(conn)) {
    buf_clear(conn->outbuf);
    conn->outbuf_flushlen = 0;
  }
}

int
_connection_mark_for_close(connection_t *conn, char reason)
{
  int retval = 0;
  assert_connection_ok(conn,0);

  if (conn->marked_for_close) {
    log(LOG_WARN, "Double mark-for-close on connection.");
    return -1;
  }

  switch (conn->type)
    {
    case CONN_TYPE_OR_LISTENER:
    case CONN_TYPE_AP_LISTENER:
    case CONN_TYPE_DIR_LISTENER:
    case CONN_TYPE_CPUWORKER:
    case CONN_TYPE_DIR:
      /* No special processing needed. */
      break;
    case CONN_TYPE_OR:
      /* No special processing needed, I think. */
      break;
    case CONN_TYPE_EXIT:
    case CONN_TYPE_AP:
      if (conn->state == EXIT_CONN_STATE_RESOLVING)
        connection_dns_remove(conn);
      if (!conn->has_sent_end && reason &&
          connection_edge_end(conn, reason, conn->cpath_layer) < 0)
        retval = -1;
      break;
    case CONN_TYPE_DNSWORKER:
      if (conn->state == DNSWORKER_STATE_BUSY) {
        dns_cancel_pending_resolve(conn->address);
      }
      break;
    default:
      log(LOG_ERR, "Unknown connection type %d", conn->type);
      ;
    }
  conn->marked_for_close = 1;
  return retval;
}

int connection_create_listener(char *bindaddress, uint16_t bindport, int type) {
  struct sockaddr_in bindaddr; /* where to bind */
  struct hostent *rent;
  connection_t *conn;
  int s; /* the socket we're going to make */
  int one=1;

  memset(&bindaddr,0,sizeof(struct sockaddr_in));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_port = htons(bindport);
  rent = gethostbyname(bindaddress);
  if (!rent) {
    log_fn(LOG_WARN,"Can't resolve BindAddress %s",bindaddress);
    return -1;
  }
  if(rent->h_length != 4)
    return -1; /* XXX complain */
  memcpy(&(bindaddr.sin_addr.s_addr),rent->h_addr,rent->h_length);

  s = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
  if (s < 0) {
    log_fn(LOG_WARN,"Socket creation failed.");
    return -1;
  }

  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  if(bind(s,(struct sockaddr *)&bindaddr,sizeof(bindaddr)) < 0) {
    log_fn(LOG_WARN,"Could not bind to port %u: %s",bindport,strerror(errno));
    return -1;
  }

  if(listen(s,SOMAXCONN) < 0) {
    log_fn(LOG_WARN,"Could not listen on port %u: %s",bindport,strerror(errno));
    return -1;
  }

  set_socket_nonblocking(s);

  conn = connection_new(type);
  conn->s = s;

  if(connection_add(conn) < 0) { /* no space, forget it */
    log_fn(LOG_WARN,"connection_add failed. Giving up.");
    connection_free(conn);
    return -1;
  }

  log_fn(LOG_DEBUG,"%s listening on port %u.",conn_type_to_string[type], bindport);

  conn->state = LISTENER_STATE_READY;
  connection_start_reading(conn);

  return 0;
}

static int connection_handle_listener_read(connection_t *conn, int new_type) {
  int news; /* the new socket */
  connection_t *newconn;
  struct sockaddr_in remote; /* information about the remote peer when connecting to other routers */
  int remotelen = sizeof(struct sockaddr_in); /* length of the remote address */
#ifdef MS_WINDOWS
  int e;
#endif

  news = accept(conn->s,(struct sockaddr *)&remote,&remotelen);
  if (news == -1) { /* accept() error */
    if(ERRNO_EAGAIN(errno)) {
#ifdef MS_WINDOWS
      e = correct_socket_errno(conn->s);
      if (ERRNO_EAGAIN(e))
        return 0;
#else
      return 0; /* he hung up before we could accept(). that's fine. */
#endif
    }
    /* else there was a real error. */
    log_fn(LOG_WARN,"accept() failed. Closing listener.");
    connection_mark_for_close(conn,0);
    return -1;
  }
  log(LOG_INFO,"Connection accepted on socket %d (child of fd %d).",news, conn->s);

  set_socket_nonblocking(news);

  newconn = connection_new(new_type);
  newconn->s = news;

  newconn->address = tor_strdup(inet_ntoa(remote.sin_addr)); /* remember the remote address */
  newconn->addr = ntohl(remote.sin_addr.s_addr);
  newconn->port = ntohs(remote.sin_port);

  if(connection_add(newconn) < 0) { /* no space, forget it */
    connection_free(newconn);
    return 0; /* no need to tear down the parent */
  }

  if(connection_init_accepted_conn(newconn) < 0) {
    connection_mark_for_close(newconn,0);
    return 0;
  }
  return 0;
}

static int connection_init_accepted_conn(connection_t *conn) {

  connection_start_reading(conn);

  switch(conn->type) {
    case CONN_TYPE_OR:
      return connection_tls_start_handshake(conn, 1);
    case CONN_TYPE_AP:
      conn->state = AP_CONN_STATE_SOCKS_WAIT;
      break;
    case CONN_TYPE_DIR:
      conn->state = DIR_CONN_STATE_SERVER_COMMAND_WAIT;
      break;
  }
  return 0;
}

/* take conn, make a nonblocking socket; try to connect to
 * addr:port (they arrive in *host order*). If fail, return -1. Else
 * assign s to conn->s: if connected return 1, if eagain return 0.
 * address is used to make the logs useful.
 */
int connection_connect(connection_t *conn, char *address, uint32_t addr, uint16_t port) {
  int s;
  struct sockaddr_in dest_addr;

  s=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
  if (s < 0) {
    log_fn(LOG_WARN,"Error creating network socket.");
    return -1;
  }
  set_socket_nonblocking(s);

  memset(&dest_addr,0,sizeof(dest_addr));
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(port);
  dest_addr.sin_addr.s_addr = htonl(addr);

  log_fn(LOG_DEBUG,"Connecting to %s:%u.",address,port);

  if(connect(s,(struct sockaddr *)&dest_addr,sizeof(dest_addr)) < 0) {
    if(!ERRNO_CONN_EINPROGRESS(errno)) {
      /* yuck. kill it. */
      log_fn(LOG_INFO,"Connect() to %s:%u failed: %s",address,port,strerror(errno));
      close(s);
      return -1;
    } else {
      /* it's in progress. set state appropriately and return. */
      conn->s = s;
      log_fn(LOG_DEBUG,"connect in progress, socket %d.",s);
      return 0;
    }
  }

  /* it succeeded. we're connected. */
  log_fn(LOG_INFO,"Connection to %s:%u established.",address,port);
  conn->s = s;
  return 1;
}

static void listener_close_if_present(int type) {
  connection_t *conn;
  assert(type == CONN_TYPE_OR_LISTENER ||
         type == CONN_TYPE_AP_LISTENER ||
         type == CONN_TYPE_DIR_LISTENER);
  conn = connection_get_by_type(type);
  if (conn) {
    connection_close_immediate(conn);
    connection_mark_for_close(conn,0);
  }
}

/* start all connections that should be up but aren't */
int retry_all_connections(void) {

  if(options.ORPort) {
    router_retry_connections();
  }

  if(options.ORPort) {
    listener_close_if_present(CONN_TYPE_OR_LISTENER);
    if(connection_create_listener(options.ORBindAddress, options.ORPort,
                                  CONN_TYPE_OR_LISTENER) < 0)
      return -1;
  }

  if(options.DirPort) {
    listener_close_if_present(CONN_TYPE_DIR_LISTENER);
    if(connection_create_listener(options.DirBindAddress, options.DirPort,
                                  CONN_TYPE_DIR_LISTENER) < 0)
      return -1;
  }

  if(options.SocksPort) {
    listener_close_if_present(CONN_TYPE_AP_LISTENER);
    if(connection_create_listener(options.SocksBindAddress, options.SocksPort,
                                  CONN_TYPE_AP_LISTENER) < 0)
      return -1;
  }

  return 0;
}

int connection_handle_read(connection_t *conn) {

  conn->timestamp_lastread = time(NULL);

  switch(conn->type) {
    case CONN_TYPE_OR_LISTENER:
      return connection_handle_listener_read(conn, CONN_TYPE_OR);
    case CONN_TYPE_AP_LISTENER:
      return connection_handle_listener_read(conn, CONN_TYPE_AP);
    case CONN_TYPE_DIR_LISTENER:
      return connection_handle_listener_read(conn, CONN_TYPE_DIR);
  }

  if(connection_read_to_buf(conn) < 0) {
    if(conn->type == CONN_TYPE_DIR &&
       (conn->state == DIR_CONN_STATE_CONNECTING_FETCH ||
        conn->state == DIR_CONN_STATE_CONNECTING_UPLOAD)) {
       /* it's a directory server and connecting failed: forget about this router */
       /* XXX I suspect pollerr may make Windows not get to this point. :( */
       router_mark_as_down(conn->nickname);
    }
    /* There's a read error; kill the connection.*/
    connection_close_immediate(conn); /* Don't flush; connection is dead. */
    connection_mark_for_close(conn, END_STREAM_REASON_MISC);
    return -1;
  }
  if(connection_process_inbuf(conn) < 0) {
//    log_fn(LOG_DEBUG,"connection_process_inbuf returned -1.");
    return -1;
  }
  return 0;
}

/* return -1 if we want to break conn, else return 0 */
int connection_read_to_buf(connection_t *conn) {
  int result;
  int at_most;

  if(options.LinkPadding) {
    at_most = global_read_bucket;
  } else {
    /* do a rudimentary round-robin so one connection can't hog a thickpipe */
    if(connection_speaks_cells(conn)) {
      at_most = 32*(CELL_NETWORK_SIZE);
    } else {
      at_most = 32*(RELAY_PAYLOAD_SIZE);
    }

    if(at_most > global_read_bucket)
      at_most = global_read_bucket;
  }

  if(connection_speaks_cells(conn) && conn->state != OR_CONN_STATE_CONNECTING) {
    if(conn->state == OR_CONN_STATE_HANDSHAKING)
      return connection_tls_continue_handshake(conn);

    /* else open, or closing */
    if(at_most > conn->receiver_bucket)
      at_most = conn->receiver_bucket;
    result = read_to_buf_tls(conn->tls, at_most, conn->inbuf);

    switch(result) {
      case TOR_TLS_ERROR:
      case TOR_TLS_CLOSE:
        log_fn(LOG_INFO,"tls error. breaking.");
        return -1; /* XXX deal with close better */
      case TOR_TLS_WANTWRITE:
        connection_start_writing(conn);
        return 0;
      case TOR_TLS_WANTREAD: /* we're already reading */
      case TOR_TLS_DONE: /* no data read, so nothing to process */
        return 0;
    }
  } else {
    result = read_to_buf(conn->s, at_most, conn->inbuf,
                         &conn->inbuf_reached_eof);

//  log(LOG_DEBUG,"connection_read_to_buf(): read_to_buf returned %d.",read_result);

    if(result < 0)
      return -1;
  }

  global_read_bucket -= result; assert(global_read_bucket >= 0);
  if(global_read_bucket == 0) {
    log_fn(LOG_DEBUG,"global bucket exhausted. Pausing.");
    conn->wants_to_read = 1;
    connection_stop_reading(conn);
    return 0;
  }
  if(connection_speaks_cells(conn) && conn->state == OR_CONN_STATE_OPEN) {
    conn->receiver_bucket -= result; assert(conn->receiver_bucket >= 0);
    if(conn->receiver_bucket == 0) {
      log_fn(LOG_DEBUG,"receiver bucket exhausted. Pausing.");
      conn->wants_to_read = 1;
      connection_stop_reading(conn);
      return 0;
    }
  }
  return 0;
}

int connection_fetch_from_buf(char *string, int len, connection_t *conn) {
  return fetch_from_buf(string, len, conn->inbuf);
}

int connection_find_on_inbuf(char *string, int len, connection_t *conn) {
  return find_on_inbuf(string, len, conn->inbuf);
}

int connection_wants_to_flush(connection_t *conn) {
  return conn->outbuf_flushlen;
}

int connection_outbuf_too_full(connection_t *conn) {
  return (conn->outbuf_flushlen > 10*CELL_PAYLOAD_SIZE);
}

/* return -1 if you want to break the conn, else return 0 */
int connection_handle_write(connection_t *conn) {

  assert(!connection_is_listener(conn));

  conn->timestamp_lastwritten = time(NULL);

  if (connection_speaks_cells(conn) &&
      conn->state != OR_CONN_STATE_CONNECTING) {
    if (conn->state == OR_CONN_STATE_HANDSHAKING) {
      connection_stop_writing(conn);
      return connection_tls_continue_handshake(conn);
    }

    /* else open, or closing */
    switch(flush_buf_tls(conn->tls, conn->outbuf, &conn->outbuf_flushlen)) {
      case TOR_TLS_ERROR:
      case TOR_TLS_CLOSE:
        log_fn(LOG_INFO,"tls error. breaking.");
        connection_mark_for_close(conn, 0);
        return -1; /* XXX deal with close better */
      case TOR_TLS_WANTWRITE:
        log_fn(LOG_DEBUG,"wanted write.");
        /* we're already writing */
        return 0;
      case TOR_TLS_WANTREAD:
        /* Make sure to avoid a loop if the receive buckets are empty. */
        log_fn(LOG_DEBUG,"wanted read.");
        if(!connection_is_reading(conn)) {
          connection_stop_writing(conn);
          conn->wants_to_write = 1;
          /* we'll start reading again when the next second arrives,
           * and then also start writing again.
           */
        }
        /* else no problem, we're already reading */
        return 0;
      /* case TOR_TLS_DONE:
       * for TOR_TLS_DONE, fall through to check if the flushlen
       * is empty, so we can stop writing.
       */
    }
  } else {
    if (flush_buf(conn->s, conn->outbuf, &conn->outbuf_flushlen) < 0) {
      connection_mark_for_close(conn, END_STREAM_REASON_MISC);
      return -1;
    }
    /* conns in CONNECTING state will fall through... */
  }

  if(!connection_wants_to_flush(conn)) /* it's done flushing */
    if(connection_finished_flushing(conn) < 0) /* ...and get handled here. */
      return -1;

  return 0;
}

void connection_write_to_buf(const char *string, int len, connection_t *conn) {

  if(!len || conn->marked_for_close)
    return;

  if(write_to_buf(string, len, conn->outbuf) < 0) {
    log_fn(LOG_WARN,"write_to_buf failed. Closing connection (fd %d).", conn->s);
    connection_mark_for_close(conn,0);
    return;
  }

  connection_start_writing(conn);
#define MIN_TLS_FLUSHLEN 15872
/* openssl tls record size is 16383, this is close. The goal here is to
 * push data out as soon as we know there's enough for a tls record, so
 * during periods of high load we won't read the entire megabyte from
 * input before pushing any data out. */
  if(connection_speaks_cells(conn) &&
     conn->outbuf_flushlen < MIN_TLS_FLUSHLEN &&
     conn->outbuf_flushlen+len >= MIN_TLS_FLUSHLEN) {
    len -= (MIN_TLS_FLUSHLEN - conn->outbuf_flushlen);
    conn->outbuf_flushlen = MIN_TLS_FLUSHLEN;
    if(connection_handle_write(conn) < 0) {
      log_fn(LOG_WARN,"flushing failed.");
      connection_mark_for_close(conn,0);
    }
  }
  if(len > 0) { /* if there's any left over */
    conn->outbuf_flushlen += len;
    connection_start_writing(conn);
    /* because connection_handle_write() above might have stopped writing */
  }
}

connection_t *connection_exact_get_by_addr_port(uint32_t addr, uint16_t port) {
  int i, n;
  connection_t *conn;
  connection_t **carray;

  get_connection_array(&carray,&n);
  for(i=0;i<n;i++) {
    conn = carray[i];
    if(conn->addr == addr && conn->port == port && !conn->marked_for_close)
      return conn;
  }
  return NULL;
}

connection_t *connection_twin_get_by_addr_port(uint32_t addr, uint16_t port) {
  /* Find a connection to the router described by addr and port,
   *   or alternately any router which knows its key.
   * This connection *must* be in 'open' state.
   * If not, return NULL.
   */
  int i, n;
  connection_t *conn;
  routerinfo_t *router;
  connection_t **carray;

  /* first check if it's there exactly */
  conn = connection_exact_get_by_addr_port(addr,port);
  if(conn && connection_state_is_open(conn)) {
    log(LOG_DEBUG,"connection_twin_get_by_addr_port(): Found exact match.");
    return conn;
  }

  /* now check if any of the other open connections are a twin for this one */

  router = router_get_by_addr_port(addr,port);
  if(!router)
    return NULL;

  get_connection_array(&carray,&n);
  for(i=0;i<n;i++) {
    conn = carray[i];
    assert(conn);
    if(connection_state_is_open(conn) &&
       !crypto_pk_cmp_keys(conn->onion_pkey, router->onion_pkey)) {
      log(LOG_DEBUG,"connection_twin_get_by_addr_port(): Found twin (%s).",conn->address);
      return conn;
    }
  }
  return NULL;
}

connection_t *connection_get_by_type(int type) {
  int i, n;
  connection_t *conn;
  connection_t **carray;

  get_connection_array(&carray,&n);
  for(i=0;i<n;i++) {
    conn = carray[i];
    if(conn->type == type && !conn->marked_for_close)
      return conn;
  }
  return NULL;
}

connection_t *connection_get_by_type_state(int type, int state) {
  int i, n;
  connection_t *conn;
  connection_t **carray;

  get_connection_array(&carray,&n);
  for(i=0;i<n;i++) {
    conn = carray[i];
    if(conn->type == type && conn->state == state && !conn->marked_for_close)
      return conn;
  }
  return NULL;
}

connection_t *connection_get_by_type_state_lastwritten(int type, int state) {
  int i, n;
  connection_t *conn, *best=NULL;
  connection_t **carray;

  get_connection_array(&carray,&n);
  for(i=0;i<n;i++) {
    conn = carray[i];
    if(conn->type == type && conn->state == state && !conn->marked_for_close)
      if(!best || conn->timestamp_lastwritten < best->timestamp_lastwritten)
        best = conn;
  }
  return best;
}

int connection_receiver_bucket_should_increase(connection_t *conn) {
  assert(conn);

  if(!connection_speaks_cells(conn))
    return 0; /* edge connections don't use receiver_buckets */
  if(conn->state != OR_CONN_STATE_OPEN)
    return 0; /* only open connections play the rate limiting game */

  assert(conn->bandwidth > 0);
  if(conn->receiver_bucket > 9*conn->bandwidth)
    return 0;

  return 1;
}

int connection_is_listener(connection_t *conn) {
  if(conn->type == CONN_TYPE_OR_LISTENER ||
     conn->type == CONN_TYPE_AP_LISTENER ||
     conn->type == CONN_TYPE_DIR_LISTENER)
    return 1;
  return 0;
}

int connection_state_is_open(connection_t *conn) {
  assert(conn);

  if(conn->marked_for_close)
    return 0;

  if((conn->type == CONN_TYPE_OR && conn->state == OR_CONN_STATE_OPEN) ||
     (conn->type == CONN_TYPE_AP && conn->state == AP_CONN_STATE_OPEN) ||
     (conn->type == CONN_TYPE_EXIT && conn->state == EXIT_CONN_STATE_OPEN))
    return 1;

  return 0;
}

int connection_send_destroy(uint16_t circ_id, connection_t *conn) {
  cell_t cell;

  assert(conn);
  assert(connection_speaks_cells(conn));

  memset(&cell, 0, sizeof(cell_t));
  cell.circ_id = circ_id;
  cell.command = CELL_DESTROY;
  log_fn(LOG_INFO,"Sending destroy (circID %d).", circ_id);
  connection_or_write_cell_to_buf(&cell, conn);
  return 0;
}

int connection_process_inbuf(connection_t *conn) {

  assert(conn);

  switch(conn->type) {
    case CONN_TYPE_OR:
      return connection_or_process_inbuf(conn);
    case CONN_TYPE_EXIT:
    case CONN_TYPE_AP:
      return connection_edge_process_inbuf(conn);
    case CONN_TYPE_DIR:
      return connection_dir_process_inbuf(conn);
    case CONN_TYPE_DNSWORKER:
      return connection_dns_process_inbuf(conn);
    case CONN_TYPE_CPUWORKER:
      return connection_cpu_process_inbuf(conn);
    default:
      log_fn(LOG_WARN,"got unexpected conn->type %d.", conn->type);
      return -1;
  }
}

int connection_finished_flushing(connection_t *conn) {

  assert(conn);

//  log_fn(LOG_DEBUG,"entered. Socket %u.", conn->s);

  switch(conn->type) {
    case CONN_TYPE_OR:
      return connection_or_finished_flushing(conn);
    case CONN_TYPE_AP:
    case CONN_TYPE_EXIT:
      return connection_edge_finished_flushing(conn);
    case CONN_TYPE_DIR:
      return connection_dir_finished_flushing(conn);
    case CONN_TYPE_DNSWORKER:
      return connection_dns_finished_flushing(conn);
    case CONN_TYPE_CPUWORKER:
      return connection_cpu_finished_flushing(conn);
    default:
      log_fn(LOG_WARN,"got unexpected conn->type %d.", conn->type);
      return -1;
  }
}

void assert_connection_ok(connection_t *conn, time_t now)
{
  assert(conn);
  assert(conn->magic == CONNECTION_MAGIC);
  assert(conn->type >= _CONN_TYPE_MIN);
  assert(conn->type <= _CONN_TYPE_MAX);

  if(conn->outbuf_flushlen > 0) {
    assert(connection_is_writing(conn) || conn->wants_to_write);
  }

  /* XXX check: wants_to_read, wants_to_write, s, poll_index,
   * marked_for_close. */

  /* buffers */
  if (!connection_is_listener(conn)) {
    assert(conn->inbuf);
    assert(conn->outbuf);
  }

  assert(!now || conn->timestamp_lastread <= now);
  assert(!now || conn->timestamp_lastwritten <= now);
  assert(conn->timestamp_created <= conn->timestamp_lastread);
  assert(conn->timestamp_created <= conn->timestamp_lastwritten);

  /* XXX Fix this; no longer so.*/
#if 0
  if(conn->type != CONN_TYPE_OR && conn->type != CONN_TYPE_DIR)
    assert(!conn->pkey);
  /* pkey is set if we're a dir client, or if we're an OR in state OPEN
   * connected to another OR.
   */
#endif

  if (conn->type != CONN_TYPE_OR) {
    assert(!conn->tls);
  } else {
    if(conn->state == OR_CONN_STATE_OPEN) {
      /* assert(conn->bandwidth > 0); */
      /* the above isn't necessarily true: if we just did a TLS
       * handshake but we didn't recognize the other peer, or it
       * gave a bad cert/etc, then we won't have assigned bandwidth,
       * yet it will be open. -RD
       */
      assert(conn->receiver_bucket >= 0);
    }
    assert(conn->addr && conn->port);
    assert(conn->address);
    if (conn->state != OR_CONN_STATE_CONNECTING)
      assert(conn->tls);
  }

  if (conn->type != CONN_TYPE_EXIT && conn->type != CONN_TYPE_AP) {
    assert(!conn->stream_id);
    assert(!conn->next_stream);
    assert(!conn->cpath_layer);
    assert(!conn->package_window);
    assert(!conn->deliver_window);
    assert(!conn->done_sending);
    assert(!conn->done_receiving);
  } else {
    if(conn->type == CONN_TYPE_AP && conn->state == AP_CONN_STATE_OPEN)
      assert(conn->cpath_layer);
    if(conn->cpath_layer)
      assert_cpath_layer_ok(conn->cpath_layer);
    /* XXX unchecked: package window, deliver window. */
  }
  if (conn->type != CONN_TYPE_AP) {
    assert(!conn->socks_request);
  }

  switch(conn->type)
    {
    case CONN_TYPE_OR_LISTENER:
    case CONN_TYPE_AP_LISTENER:
    case CONN_TYPE_DIR_LISTENER:
      assert(conn->state == LISTENER_STATE_READY);
      break;
    case CONN_TYPE_OR:
      assert(conn->state >= _OR_CONN_STATE_MIN &&
             conn->state <= _OR_CONN_STATE_MAX);
      break;
    case CONN_TYPE_EXIT:
      assert(conn->state >= _EXIT_CONN_STATE_MIN &&
             conn->state <= _EXIT_CONN_STATE_MAX);
      break;
    case CONN_TYPE_AP:
      assert(conn->state >= _AP_CONN_STATE_MIN &&
             conn->state <= _AP_CONN_STATE_MAX);
      assert(conn->socks_request);
      break;
    case CONN_TYPE_DIR:
      assert(conn->state >= _DIR_CONN_STATE_MIN &&
             conn->state <= _DIR_CONN_STATE_MAX);
      break;
    case CONN_TYPE_DNSWORKER:
      assert(conn->state == DNSWORKER_STATE_IDLE ||
             conn->state == DNSWORKER_STATE_BUSY);
      break;
    case CONN_TYPE_CPUWORKER:
      assert(conn->state >= _CPUWORKER_STATE_MIN &&
             conn->state <= _CPUWORKER_STATE_MAX);
      break;
    default:
      assert(0);
  }
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
