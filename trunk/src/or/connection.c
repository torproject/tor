/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file connection.c
 * \brief General high-level functions to handle reading and writing
 * on connections.
 **/

#include "or.h"

/********* START VARIABLES **********/

extern or_options_t options; /* command-line and config-file options */
extern int shutting_down; /* whether we should refuse new connections */

/** Array of strings to make conn-\>type human-readable. */
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

/** Array of string arrays to make {conn-\>type,conn-\>state} human-readable. */
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
    "open",                            /* 3 */
    "resolve failed" },                /* 4 */
  { "ready" }, /* app listener, 0 */
  { "", /* 0 */
    "", /* 1 */
    "", /* 2 */
    "", /* 3 */
    "", /* 4 */
    "awaiting dest info",         /* app, 5 */
    "waiting for rendezvous desc",     /* 6 */
    "waiting for safe circuit",        /* 7 */
    "waiting for connected",           /* 8 */
    "open" },                          /* 9 */
  { "ready" }, /* dir listener, 0 */
  { "",                           /* dir, 0 */
    "connecting",                      /* 1 */
    "client sending",                  /* 2 */
    "client reading",                  /* 3 */
    "awaiting command",                /* 4 */
    "writing" },                       /* 5 */
  { "",                    /* dns worker, 0 */
    "idle",                            /* 1 */
    "busy" },                          /* 2 */
  { "",                    /* cpu worker, 0 */
    "idle",                            /* 1 */
    "busy with onion",                 /* 2 */
    "busy with handshake" },           /* 3 */
};

/********* END VARIABLES ************/

static int connection_create_listener(const char *bindaddress,
                                      uint16_t bindport, int type);
static int connection_init_accepted_conn(connection_t *conn);
static int connection_handle_listener_read(connection_t *conn, int new_type);
static int connection_receiver_bucket_should_increase(connection_t *conn);
static int connection_finished_flushing(connection_t *conn);
static int connection_finished_connecting(connection_t *conn);
static int connection_read_to_buf(connection_t *conn);
static int connection_process_inbuf(connection_t *conn);

/**************************************************************/

/** Allocate space for a new connection_t. This function just initializes
 * conn; you must call connection_add() to link it into the main array.
 *
 * Set conn-\>type to <b>type</b>. Set conn-\>s and conn-\>poll_index to
 * -1 to signify they are not yet assigned.
 *
 * If conn is not a listener type, allocate buffers for it. If it's
 * an AP type, allocate space to store the socks_request.
 *
 * Assign a pseudorandom next_circ_id between 0 and 2**15.
 *
 * Initialize conn's timestamps to now.
 */
connection_t *connection_new(int type) {
  connection_t *conn;
  time_t now = time(NULL);

  conn = tor_malloc_zero(sizeof(connection_t));
  conn->magic = CONNECTION_MAGIC;
  conn->s = -1; /* give it a default of 'not used' */
  conn->poll_index = -1; /* also default to 'not used' */

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

/** Deallocate memory used by <b>conn</b>. Deallocate its buffers if necessary,
 * close its socket if necessary, and mark the directory as dirty if <b>conn</b>
 * is an OR or OP connection.
 */
void connection_free(connection_t *conn) {
  tor_assert(conn);
  tor_assert(conn->magic == CONNECTION_MAGIC);

  if(!connection_is_listener(conn)) {
    buf_free(conn->inbuf);
    buf_free(conn->outbuf);
  }
  tor_free(conn->address);

  if(connection_speaks_cells(conn)) {
    directory_set_dirty(); /* XXX should only do this for an open OR conn */
    if (conn->tls)
      tor_tls_free(conn->tls);
  }

  if (conn->identity_pkey)
    crypto_free_pk_env(conn->identity_pkey);
  tor_free(conn->nickname);
  tor_free(conn->socks_request);

  if(conn->s >= 0) {
    log_fn(LOG_INFO,"closing fd %d.",conn->s);
    tor_close_socket(conn->s);
  }
  memset(conn, 0xAA, sizeof(connection_t)); /* poison memory */
  free(conn);
}

/** Call connection_free() on every connection in our array.
 * This is used by cpuworkers and dnsworkers when they fork,
 * so they don't keep resources held open (especially sockets).
 */
void connection_free_all(void) {
  int i, n;
  connection_t **carray;

  get_connection_array(&carray,&n);
  for(i=0;i<n;i++)
    connection_free(carray[i]);
}

void connection_about_to_close_connection(connection_t *conn)
{

  assert(conn->marked_for_close);

  if(conn->type == CONN_TYPE_AP || conn->type == CONN_TYPE_EXIT) {
    if(!conn->has_sent_end)
      log_fn(LOG_WARN,"Edge connection hasn't sent end yet? Bug.");
  }

  switch(conn->type) {
    case CONN_TYPE_DIR:
      if(conn->purpose == DIR_PURPOSE_FETCH_RENDDESC)
        rend_client_desc_fetched(conn->rend_query, 0);
      break;
    case CONN_TYPE_OR:
      /* Remember why we're closing this connection. */
      if (conn->state != OR_CONN_STATE_OPEN) {
        /* XXX Nick: this still isn't right, because it might be
         * dying even though we didn't initiate the connect. Can
         * you look at this more? -RD XXXX008 -NM*/
        if(conn->nickname)
          rep_hist_note_connect_failed(conn->identity_digest, time(NULL));
      } else if (0) { // XXX reason == CLOSE_REASON_UNUSED_OR_CONN) {
        rep_hist_note_disconnect(conn->identity_digest, time(NULL));
      } else {
        rep_hist_note_connection_died(conn->identity_digest, time(NULL));
      }
      break;
    case CONN_TYPE_AP:
      if (conn->socks_request->has_finished == 0) {
        log_fn(LOG_INFO,"Cleaning up AP -- sending socks reject.");
        connection_ap_handshake_socks_reply(conn, NULL, 0, 0);
        conn->socks_request->has_finished = 1;
        conn->hold_open_until_flushed = 1;
      }
      break;
    case CONN_TYPE_EXIT:
      if (conn->state == EXIT_CONN_STATE_RESOLVING) {
        circuit_detach_stream(circuit_get_by_conn(conn), conn);
        connection_dns_remove(conn);
      }
      break;
    case CONN_TYPE_DNSWORKER:
      if (conn->state == DNSWORKER_STATE_BUSY) {
        dns_cancel_pending_resolve(conn->address);
      }
      break;
  }
}

/** Close the underlying socket for <b>conn</b>, so we don't try to
 * flush it. Must be used in conjunction with (right before)
 * connection_mark_for_close().
 */
void connection_close_immediate(connection_t *conn)
{
  assert_connection_ok(conn,0);
  if (conn->s < 0) {
    log_fn(LOG_WARN,"Attempt to close already-closed connection.");
    return;
  }
  if (conn->outbuf_flushlen) {
    log_fn(LOG_INFO,"fd %d, type %s, state %d, %d bytes on outbuf.",
           conn->s, CONN_TYPE_TO_STRING(conn->type),
           conn->state, conn->outbuf_flushlen);
  }
  tor_close_socket(conn->s);
  conn->s = -1;
  if(!connection_is_listener(conn)) {
    buf_clear(conn->outbuf);
    conn->outbuf_flushlen = 0;
  }
}

/** Mark <b>conn</b> to be closed next time we loop through
 * conn_close_if_marked() in main.c. Do any cleanup needed:
 *   - Directory conns that fail to fetch a rendezvous descriptor need
 *     to inform pending rendezvous streams.
 *   - OR conns need to call rep_hist_note_*() to record status.
 *   - AP conns need to send a socks reject if necessary.
 *   - Exit conns need to call connection_dns_remove() if necessary.
 *   - AP and Exit conns need to send an end cell if they can.
 *   - DNS conns need to fail any resolves that are pending on them.
 */
int
_connection_mark_for_close(connection_t *conn)
{
  assert_connection_ok(conn,0);

  if (conn->marked_for_close) {
    log(LOG_WARN, "Double mark-for-close on connection.");
    return -1;
  }

  conn->marked_for_close = 1;

  /* in case we're going to be held-open-til-flushed, reset
   * the number of seconds since last successful write, so
   * we get our whole 15 seconds */
  conn->timestamp_lastwritten = time(NULL);

  return 0;
}

/** Find each connection that has hold_open_until_flushed set to
 * 1 but hasn't written in the past 15 seconds, and set
 * hold_open_until_flushed to 0. This means it will get cleaned
 * up in the next loop through close_if_marked() in main.c.
 */
void connection_expire_held_open(void)
{
  connection_t **carray, *conn;
  int n, i;
  time_t now;

  now = time(NULL);

  get_connection_array(&carray, &n);
  for (i = 0; i < n; ++i) {
    conn = carray[i];
    /* If we've been holding the connection open, but we haven't written
     * for 15 seconds...
     */
    if (conn->hold_open_until_flushed) {
      tor_assert(conn->marked_for_close);
      if (now - conn->timestamp_lastwritten >= 15) {
        log_fn(LOG_WARN,"Giving up on marked_for_close conn that's been flushing for 15s (fd %d, type %s, state %d).",
               conn->s, CONN_TYPE_TO_STRING(conn->type), conn->state);
        conn->hold_open_until_flushed = 0;
      }
    }
  }
}

/** Bind a new non-blocking socket listening to
 * <b>bindaddress</b>:<b>bindport</b>, and add this new connection
 * (of type <b>type</b>) to the connection array.
 *
 * If <b>bindaddress</b> includes a port, we bind on that port; otherwise, we
 * use bindport.
 */
static int connection_create_listener(const char *bindaddress, uint16_t bindport, int type) {
  struct sockaddr_in bindaddr; /* where to bind */
  connection_t *conn;
  char *hostname, *cp;
  int usePort;
  int s; /* the socket we're going to make */
  int one=1;


  cp = strchr(bindaddress, ':');
  if (cp) {
    hostname = tor_strndup(bindaddress, cp-bindaddress);
    usePort = atoi(cp+1);
  } else {
    hostname = tor_strdup(bindaddress);
    usePort = bindport;
  }

  memset(&bindaddr,0,sizeof(struct sockaddr_in));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_port = htons((uint16_t) usePort);
  if(tor_lookup_hostname(hostname, &(bindaddr.sin_addr.s_addr)) != 0) {
    log_fn(LOG_WARN,"Can't resolve BindAddress %s",hostname);
    tor_free(hostname);
    return -1;
  }
  tor_free(hostname);

  s = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
  if (s < 0) {
    log_fn(LOG_WARN,"Socket creation failed.");
    return -1;
  }

  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void*) &one, sizeof(one));

  if(bind(s,(struct sockaddr *)&bindaddr,sizeof(bindaddr)) < 0) {
    log_fn(LOG_WARN,"Could not bind to port %u: %s",usePort,
           tor_socket_strerror(tor_socket_errno(s)));
    return -1;
  }

  if(listen(s,SOMAXCONN) < 0) {
    log_fn(LOG_WARN,"Could not listen on port %u: %s",usePort,
           tor_socket_strerror(tor_socket_errno(s)));
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

  log_fn(LOG_DEBUG,"%s listening on port %u.",conn_type_to_string[type], usePort);

  conn->state = LISTENER_STATE_READY;
  connection_start_reading(conn);

  return 0;
}

/** The listener connection <b>conn</b> told poll() it wanted to read.
 * Call accept() on conn-\>s, and add the new connection if necessary.
 */
static int connection_handle_listener_read(connection_t *conn, int new_type) {
  int news; /* the new socket */
  connection_t *newconn;
  struct sockaddr_in remote; /* information about the remote peer when connecting to other routers */
  int remotelen = sizeof(struct sockaddr_in); /* length of the remote address */

  news = accept(conn->s,(struct sockaddr *)&remote,&remotelen);
  if (news == -1) { /* accept() error */
    if(ERRNO_IS_EAGAIN(tor_socket_errno(conn->s))) {
      return 0; /* he hung up before we could accept(). that's fine. */
    }
    /* else there was a real error. */
    log_fn(LOG_WARN,"accept() failed. Closing listener.");
    connection_mark_for_close(conn);
    return -1;
  }
  log(LOG_INFO,"Connection accepted on socket %d (child of fd %d).",news, conn->s);

  if(shutting_down && new_type != CONN_TYPE_DIR) {
    /* allow directory connections even while we're shutting down */
    log(LOG_INFO,"But we're shutting down, so closing (type %d).", new_type);
    tor_close_socket(news);
    return 0;
  }

  set_socket_nonblocking(news);

  /* process entrance policies here, before we even create the connection */
  if(new_type == CONN_TYPE_AP) {
    /* check sockspolicy to see if we should accept it */
    if(socks_policy_permits_address(ntohl(remote.sin_addr.s_addr)) == 0) {
      log_fn(LOG_WARN,"Denying socks connection from untrusted address %s.",
             inet_ntoa(remote.sin_addr));
      tor_close_socket(news);
      return 0;
    }
  }

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
    connection_mark_for_close(newconn);
    return 0;
  }
  return 0;
}

/** Initialize states for newly accepted connection <b>conn</b>.
 * If conn is an OR, start the tls handshake.
 */
static int connection_init_accepted_conn(connection_t *conn) {

  connection_start_reading(conn);

  switch(conn->type) {
    case CONN_TYPE_OR:
      return connection_tls_start_handshake(conn, 1);
    case CONN_TYPE_AP:
      conn->state = AP_CONN_STATE_SOCKS_WAIT;
      break;
    case CONN_TYPE_DIR:
      conn->purpose = DIR_PURPOSE_SERVER;
      conn->state = DIR_CONN_STATE_SERVER_COMMAND_WAIT;
      break;
  }
  return 0;
}

/** Take conn, make a nonblocking socket; try to connect to
 * addr:port (they arrive in *host order*). If fail, return -1. Else
 * assign s to conn->\s: if connected return 1, if EAGAIN return 0.
 *
 * address is used to make the logs useful.
 *
 * On success, add conn to the list of polled connections.
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
    if(!ERRNO_IS_CONN_EINPROGRESS(tor_socket_errno(s))) {
      /* yuck. kill it. */
      log_fn(LOG_INFO,"Connect() to %s:%u failed: %s",address,port,
             tor_socket_strerror(tor_socket_errno(s)));
      tor_close_socket(s);
      return -1;
    } else {
      /* it's in progress. set state appropriately and return. */
      conn->s = s;
      if(connection_add(conn) < 0) /* no space, forget it */
        return -1;
      log_fn(LOG_DEBUG,"connect in progress, socket %d.",s);
      return 0;
    }
  }

  /* it succeeded. we're connected. */
  log_fn(LOG_INFO,"Connection to %s:%u established.",address,port);
  conn->s = s;
  if(connection_add(conn) < 0) /* no space, forget it */
    return -1;
  return 1;
}

/** If there exist any listeners of type <b>type</b> in the connection
 * array, mark them for close.
 */
static void listener_close_if_present(int type) {
  connection_t *conn;
  connection_t **carray;
  int i,n;
  tor_assert(type == CONN_TYPE_OR_LISTENER ||
             type == CONN_TYPE_AP_LISTENER ||
             type == CONN_TYPE_DIR_LISTENER);
  get_connection_array(&carray,&n);
  for(i=0;i<n;i++) {
    conn = carray[i];
    if (conn->type == type && !conn->marked_for_close) {
      connection_close_immediate(conn);
      connection_mark_for_close(conn);
    }
  }
}

static int retry_listeners(int type, struct config_line_t *cfg,
                           int port_option, const char *default_addr)
{
  listener_close_if_present(type);
  if (port_option) {
    if (!cfg) {
      if (connection_create_listener(default_addr, (uint16_t) port_option,
                                     type)<0)
        return -1;
    } else {
      for ( ; cfg; cfg = cfg->next) {
        if (connection_create_listener(cfg->value, (uint16_t) port_option,
                                       type)<0)
          return -1;
      }
    }
  }
  return 0;
}

/** (Re)launch listeners for each port you should have open.
 */
int retry_all_listeners(void) {

  if (retry_listeners(CONN_TYPE_OR_LISTENER, options.ORBindAddress,
                      options.ORPort, "0.0.0.0")<0)
    return -1;
  if (retry_listeners(CONN_TYPE_DIR_LISTENER, options.DirBindAddress,
                      options.DirPort, "0.0.0.0")<0)
    return -1;
  if (retry_listeners(CONN_TYPE_AP_LISTENER, options.SocksBindAddress,
                      options.SocksPort, "127.0.0.1")<0)
    return -1;

  return 0;
}

extern int global_read_bucket;

/** How many bytes at most can we read onto this connection? */
int connection_bucket_read_limit(connection_t *conn) {
  int at_most;

  if(options.LinkPadding) {
    at_most = global_read_bucket;
  } else {
    /* do a rudimentary round-robin so one circuit can't hog a connection */
    if(connection_speaks_cells(conn)) {
      at_most = 32*(CELL_NETWORK_SIZE);
    } else {
      at_most = 32*(RELAY_PAYLOAD_SIZE);
    }

    if(at_most > global_read_bucket)
      at_most = global_read_bucket;
  }

  if(connection_speaks_cells(conn) && conn->state == OR_CONN_STATE_OPEN)
    if(at_most > conn->receiver_bucket)
      at_most = conn->receiver_bucket;

  return at_most;
}

/** We just read num_read onto conn. Decrement buckets appropriately. */
void connection_bucket_decrement(connection_t *conn, int num_read) {
  global_read_bucket -= num_read; tor_assert(global_read_bucket >= 0);
  if(connection_speaks_cells(conn) && conn->state == OR_CONN_STATE_OPEN) {
    conn->receiver_bucket -= num_read; tor_assert(conn->receiver_bucket >= 0);
  }
  if(global_read_bucket == 0) {
    log_fn(LOG_DEBUG,"global bucket exhausted. Pausing.");
    conn->wants_to_read = 1;
    connection_stop_reading(conn);
    return;
  }
  if(connection_speaks_cells(conn) &&
     conn->state == OR_CONN_STATE_OPEN &&
     conn->receiver_bucket == 0) {
      log_fn(LOG_DEBUG,"receiver bucket exhausted. Pausing.");
      conn->wants_to_read = 1;
      connection_stop_reading(conn);
  }
}

/** Keep a timeval to know when time has passed enough to refill buckets */
static struct timeval current_time;

/** Initiatialize the global read bucket to options.BandwidthBurst,
 * and current_time to the current time. */
void connection_bucket_init(void) {
  tor_gettimeofday(&current_time);
  global_read_bucket = options.BandwidthBurst; /* start it at max traffic */
}

/** Some time has passed; increment buckets appropriately. */
void connection_bucket_refill(struct timeval *now) {
  int i, n;
  connection_t *conn;
  connection_t **carray;

  if(now->tv_sec <= current_time.tv_sec)
    return; /* wait until the second has rolled over */

  current_time.tv_sec = now->tv_sec; /* update current_time */
  /* (ignore usecs for now) */

  /* refill the global bucket */
  if(global_read_bucket < options.BandwidthBurst) {
    global_read_bucket += options.BandwidthRate;
    log_fn(LOG_DEBUG,"global_read_bucket now %d.", global_read_bucket);
  }

  /* refill the per-connection buckets */
  get_connection_array(&carray,&n);
  for(i=0;i<n;i++) {
    conn = carray[i];

    if(connection_receiver_bucket_should_increase(conn)) {
      conn->receiver_bucket += conn->bandwidth;
      //log_fn(LOG_DEBUG,"Receiver bucket %d now %d.", i, conn->receiver_bucket);
    }

    if(conn->wants_to_read == 1 /* it's marked to turn reading back on now */
       && global_read_bucket > 0 /* and we're allowed to read */
       && (!connection_speaks_cells(conn) ||
           conn->state != OR_CONN_STATE_OPEN ||
           conn->receiver_bucket > 0)) {
      /* and either a non-cell conn or a cell conn with non-empty bucket */
      log_fn(LOG_DEBUG,"waking up conn (fd %d)",conn->s);
      conn->wants_to_read = 0;
      connection_start_reading(conn);
      if(conn->wants_to_write == 1) {
        conn->wants_to_write = 0;
        connection_start_writing(conn);
      }
    }
  }
}

/** Is the receiver bucket for connection <b>conn</b> low enough that we
 * should add another pile of tokens to it?
 */
static int connection_receiver_bucket_should_increase(connection_t *conn) {
  tor_assert(conn);

  if(!connection_speaks_cells(conn))
    return 0; /* edge connections don't use receiver_buckets */
  if(conn->state != OR_CONN_STATE_OPEN)
    return 0; /* only open connections play the rate limiting game */

  tor_assert(conn->bandwidth > 0);
  if(conn->receiver_bucket > 9*conn->bandwidth)
    return 0;

  return 1;
}

/** Read bytes from conn->\s and process them.
 *
 * This function gets called from conn_read() in main.c, either
 * when poll() has declared that conn wants to read, or (for OR conns)
 * when there are pending TLS bytes.
 *
 * It calls connection_read_to_buf() to bring in any new bytes,
 * and then calls connection_process_inbuf() to process them.
 *
 * Mark the connection and return -1 if you want to close it, else
 * return 0.
 */
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
    /* There's a read error; kill the connection.*/
    connection_close_immediate(conn); /* Don't flush; connection is dead. */
    conn->has_sent_end = 1; /* XXX have we already sent the end? really? */
    connection_mark_for_close(conn);
    if(conn->type == CONN_TYPE_DIR &&
       conn->state == DIR_CONN_STATE_CONNECTING) {
       /* it's a directory server and connecting failed: forget about this router */
       /* XXX I suspect pollerr may make Windows not get to this point. :( */
       router_mark_as_down(conn->identity_digest);
       if(conn->purpose == DIR_PURPOSE_FETCH_DIR && !all_directory_servers_down()) {
         log_fn(LOG_INFO,"Giving up on dirserver %s; trying another.", conn->nickname);
         directory_get_from_dirserver(DIR_PURPOSE_FETCH_DIR, NULL, 0);
       }
    }
    return -1;
  }
  if(connection_process_inbuf(conn) < 0) {
//    log_fn(LOG_DEBUG,"connection_process_inbuf returned -1.");
    return -1;
  }
  return 0;
}

/** Pull in new bytes from conn-\>s onto conn-\>inbuf, either
 * directly or via TLS. Reduce the token buckets by the number of
 * bytes read.
 *
 * Return -1 if we want to break conn, else return 0.
 */
static int connection_read_to_buf(connection_t *conn) {
  int result;
  int at_most;

  /* how many bytes are we allowed to read? */
  at_most = connection_bucket_read_limit(conn);

  if(connection_speaks_cells(conn) && conn->state != OR_CONN_STATE_CONNECTING) {
    if(conn->state == OR_CONN_STATE_HANDSHAKING) {
      /* continue handshaking even if global token bucket is empty */
      return connection_tls_continue_handshake(conn);
    }

    log_fn(LOG_DEBUG,"%d: starting, inbuf_datalen %d (%d pending in tls object). at_most %d.",
           conn->s,(int)buf_datalen(conn->inbuf),tor_tls_get_pending_bytes(conn->tls), at_most);

    /* else open, or closing */
    result = read_to_buf_tls(conn->tls, at_most, conn->inbuf);

    switch(result) {
      case TOR_TLS_ERROR:
      case TOR_TLS_CLOSE:
        log_fn(LOG_INFO,"tls error. breaking (nickname %s, address %s).",
               conn->nickname ? conn->nickname : "not set", conn->address);
        return -1; /* XXX deal with close better */
      case TOR_TLS_WANTWRITE:
        connection_start_writing(conn);
        return 0;
      case TOR_TLS_WANTREAD: /* we're already reading */
      case TOR_TLS_DONE: /* no data read, so nothing to process */
        result = 0;
        break; /* so we call bucket_decrement below */
    }
  } else {
    result = read_to_buf(conn->s, at_most, conn->inbuf,
                         &conn->inbuf_reached_eof);

//  log(LOG_DEBUG,"connection_read_to_buf(): read_to_buf returned %d.",read_result);

    if(result < 0)
      return -1;
  }

  if(result > 0 && !is_local_IP(conn->addr)) { /* remember it */
    rep_hist_note_bytes_read(result, time(NULL));
  }

  connection_bucket_decrement(conn, result);
  return 0;
}

/** A pass-through to fetch_from_buf. */
int connection_fetch_from_buf(char *string, int len, connection_t *conn) {
  return fetch_from_buf(string, len, conn->inbuf);
}

/** Return conn-\>outbuf_flushlen: how many bytes conn wants to flush
 * from its outbuf. */
int connection_wants_to_flush(connection_t *conn) {
  return conn->outbuf_flushlen;
}

/** Are there too many bytes on edge connection <b>conn</b>'s outbuf to
 * send back a relay-level sendme yet? Return 1 if so, 0 if not. Used by
 * connection_edge_consider_sending_sendme().
 */
int connection_outbuf_too_full(connection_t *conn) {
  return (conn->outbuf_flushlen > 10*CELL_PAYLOAD_SIZE);
}

/** Try to flush more bytes onto conn-\>s.
 *
 * This function gets called either from conn_write() in main.c
 * when poll() has declared that conn wants to write, or below
 * from connection_write_to_buf() when an entire TLS record is ready.
 *
 * Update conn-\>timestamp_lastwritten to now, and call flush_buf
 * or flush_buf_tls appropriately. If it succeeds and there no more
 * more bytes on conn->outbuf, then call connection_finished_flushing
 * on it too.
 *
 * Mark the connection and return -1 if you want to close it, else
 * return 0.
 */
int connection_handle_write(connection_t *conn) {
  int e, len=sizeof(e);
  int result;
  time_t now = time(NULL);

  tor_assert(!connection_is_listener(conn));

  conn->timestamp_lastwritten = now;

  /* Sometimes, "writeable" means "connected". */
  if (connection_state_is_connecting(conn)) {
    if (getsockopt(conn->s, SOL_SOCKET, SO_ERROR, (void*)&e, &len) < 0) {
      log_fn(LOG_WARN,"getsockopt() syscall failed?! Please report to tor-ops.");
      connection_close_immediate(conn);
      connection_mark_for_close(conn);
      return -1;
    }
    if(e) {
      /* some sort of error, but maybe just inprogress still */
      errno = e; /* XXX008 this is a kludge. maybe we should rearrange
                    our error-hunting functions? E.g. pass errno to
                    tor_socket_errno(). */
      if(!ERRNO_IS_CONN_EINPROGRESS(tor_socket_errno(conn->s))) {
        log_fn(LOG_INFO,"in-progress connect failed. Removing.");
        connection_close_immediate(conn);
        connection_mark_for_close(conn);
        /* it's safe to pass OPs to router_mark_as_down(), since it just
         * ignores unrecognized routers
         */
        if (conn->type == CONN_TYPE_OR)
          router_mark_as_down(conn->identity_digest);
        return -1;
      } else {
        return 0; /* no change, see if next time is better */
      }
    }
    /* The connection is successful. */
    return connection_finished_connecting(conn);
  }

  if (connection_speaks_cells(conn)) {
    if (conn->state == OR_CONN_STATE_HANDSHAKING) {
      connection_stop_writing(conn);
      if(connection_tls_continue_handshake(conn) < 0) {
        connection_close_immediate(conn); /* Don't flush; connection is dead. */
        connection_mark_for_close(conn);
        return -1;
      }
      return 0;
    }

    /* else open, or closing */
    result = flush_buf_tls(conn->tls, conn->outbuf, &conn->outbuf_flushlen);
    switch(result) {
      case TOR_TLS_ERROR:
      case TOR_TLS_CLOSE:
        log_fn(LOG_INFO,"tls error. breaking.");
        connection_close_immediate(conn); /* Don't flush; connection is dead. */
        connection_mark_for_close(conn);
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
    result = flush_buf(conn->s, conn->outbuf, &conn->outbuf_flushlen);
    if (result < 0) {
      connection_close_immediate(conn); /* Don't flush; connection is dead. */
      conn->has_sent_end = 1;
      connection_mark_for_close(conn);
      return -1;
    }
  }

  if(result > 0 && !is_local_IP(conn->addr)) { /* remember it */
    rep_hist_note_bytes_written(result, now);
  }

  if(!connection_wants_to_flush(conn)) { /* it's done flushing */
    if(connection_finished_flushing(conn) < 0) {
      /* already marked */
      return -1;
    }
  }

  return 0;
}

/** Append <b>len</b> bytes of <b>string</b> onto <b>conn</b>'s
 * outbuf, and ask it to start writing.
 */
void connection_write_to_buf(const char *string, int len, connection_t *conn) {

  if(!len || conn->marked_for_close)
    return;

  if(write_to_buf(string, len, conn->outbuf) < 0) {
    if(conn->type == CONN_TYPE_AP || conn->type == CONN_TYPE_EXIT) {
      /* if it failed, it means we have our package/delivery windows set
         wrong compared to our max outbuf size. close the whole circuit. */
      log_fn(LOG_WARN,"write_to_buf failed. Closing circuit (fd %d).", conn->s);
      circuit_mark_for_close(circuit_get_by_conn(conn));
    } else {
      log_fn(LOG_WARN,"write_to_buf failed. Closing connection (fd %d).", conn->s);
      connection_mark_for_close(conn);
    }
    return;
  }

  connection_start_writing(conn);
  conn->outbuf_flushlen += len;
}

/** Return the conn to addr/port that has the most recent
 * timestamp_created, or NULL if no such conn exists. */
connection_t *connection_exact_get_by_addr_port(uint32_t addr, uint16_t port) {
  int i, n;
  connection_t *conn, *best=NULL;
  connection_t **carray;

  get_connection_array(&carray,&n);
  for(i=0;i<n;i++) {
    conn = carray[i];
    if(conn->addr == addr && conn->port == port && !conn->marked_for_close &&
       (!best || best->timestamp_created < conn->timestamp_created))
      best = conn;
  }
  return best;
}

/** Find a connection to the router described by addr and port,
 * or alternately any router with the same identity key.
 * This connection <em>must</em> be in an "open" state.
 * If not, return NULL.
 */
/* XXX this twin thing is busted, now that we're rotating onion
 * keys. abandon/patch? */
connection_t *connection_twin_get_by_addr_port(uint32_t addr, uint16_t port) {
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
    tor_assert(conn);
    if(connection_state_is_open(conn) &&
       !crypto_pk_cmp_keys(conn->identity_pkey, router->identity_pkey)) {
      log(LOG_DEBUG,"connection_twin_get_by_addr_port(): Found twin (%s).",conn->address);
      return conn;
    }
  }
  return NULL;
}

connection_t *connection_get_by_identity_digest(const char *digest, int type)
{
  int i, n;
  connection_t *conn, *best=NULL;
  connection_t **carray;

  get_connection_array(&carray,&n);
  for(i=0;i<n;i++) {
    conn = carray[i];
    if (conn->type != type)
      continue;
    if (!memcmp(conn->identity_digest, digest, DIGEST_LEN)
        && !conn->marked_for_close
        && (!best || best->timestamp_created < conn->timestamp_created))
      best = conn;
  }
  return best;
}

/** Return a connection of type <b>type</b> that is not marked for
 * close.
 */
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

/** Return a connection of type <b>type</b> that is in state <b>state</b>,
 * and that is not marked for close.
 */
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

/** Return the connection of type <b>type</b> that is in state
 * <b>state</b>, that was written to least recently, and that is not
 * marked for close.
 */
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

/** Return a connection of type <b>type</b> that has rendquery equal
 * to <b>rendquery</b>, and that is not marked for close.
 */
connection_t *connection_get_by_type_rendquery(int type, const char *rendquery) {
  int i, n;
  connection_t *conn;
  connection_t **carray;

  get_connection_array(&carray,&n);
  for(i=0;i<n;i++) {
    conn = carray[i];
    if(conn->type == type &&
       !conn->marked_for_close &&
       !rend_cmp_service_ids(rendquery, conn->rend_query))
      return conn;
  }
  return NULL;
}

/** Return 1 if <b>conn</b> is a listener conn, else return 0. */
int connection_is_listener(connection_t *conn) {
  if(conn->type == CONN_TYPE_OR_LISTENER ||
     conn->type == CONN_TYPE_AP_LISTENER ||
     conn->type == CONN_TYPE_DIR_LISTENER)
    return 1;
  return 0;
}

/** Return 1 if <b>conn</b> is in state "open" and is not marked
 * for close, else return 0.
 */
int connection_state_is_open(connection_t *conn) {
  tor_assert(conn);

  if(conn->marked_for_close)
    return 0;

  if((conn->type == CONN_TYPE_OR && conn->state == OR_CONN_STATE_OPEN) ||
     (conn->type == CONN_TYPE_AP && conn->state == AP_CONN_STATE_OPEN) ||
     (conn->type == CONN_TYPE_EXIT && conn->state == EXIT_CONN_STATE_OPEN))
    return 1;

  return 0;
}

/** Return 1 if conn is in 'connecting' state, else return 0. */
int connection_state_is_connecting(connection_t *conn) {
  tor_assert(conn);

  if (conn->marked_for_close)
    return 0;
  switch (conn->type)
    {
    case CONN_TYPE_OR:
      return conn->state == OR_CONN_STATE_CONNECTING;
    case CONN_TYPE_EXIT:
      return conn->state == EXIT_CONN_STATE_CONNECTING;
    case CONN_TYPE_DIR:
      return conn->state == DIR_CONN_STATE_CONNECTING;
    }

  return 0;
}

/** Write a destroy cell with circ ID <b>circ_id</b> onto OR connection
 * <b>conn</b>.
 *
 * Return 0.
 */
int connection_send_destroy(uint16_t circ_id, connection_t *conn) {
  cell_t cell;

  tor_assert(conn);
  tor_assert(connection_speaks_cells(conn));

  memset(&cell, 0, sizeof(cell_t));
  cell.circ_id = circ_id;
  cell.command = CELL_DESTROY;
  log_fn(LOG_INFO,"Sending destroy (circID %d).", circ_id);
  connection_or_write_cell_to_buf(&cell, conn);
  return 0;
}

/** Process new bytes that have arrived on conn-\>inbuf.
 *
 * This function just passes conn to the connection-specific
 * connection_*_process_inbuf() function.
 */
static int connection_process_inbuf(connection_t *conn) {

  tor_assert(conn);

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

/** We just finished flushing bytes from conn-\>outbuf, and there
 * are no more bytes remaining.
 *
 * This function just passes conn to the connection-specific
 * connection_*_finished_flushing() function.
 */
static int connection_finished_flushing(connection_t *conn) {

  tor_assert(conn);

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

/** Called when our attempt to connect() to another server has just
 * succeeded.
 *
 * This function just passes conn to the connection-specific
 * connection_*_finished_connecting() function.
 */
static int connection_finished_connecting(connection_t *conn)
{
  tor_assert(conn);
  switch (conn->type)
    {
    case CONN_TYPE_OR:
      return connection_or_finished_connecting(conn);
    case CONN_TYPE_EXIT:
      return connection_edge_finished_connecting(conn);
    case CONN_TYPE_DIR:
      return connection_dir_finished_connecting(conn);
    default:
      tor_assert(0);
      return -1;
  }
}

/** Verify that connection <b>conn</b> has all of its invariants
 * correct. Trigger an assert if anything is invalid.
 */
void assert_connection_ok(connection_t *conn, time_t now)
{
  tor_assert(conn);
  tor_assert(conn->magic == CONNECTION_MAGIC);
  tor_assert(conn->type >= _CONN_TYPE_MIN);
  tor_assert(conn->type <= _CONN_TYPE_MAX);

  if(conn->outbuf_flushlen > 0) {
    tor_assert(connection_is_writing(conn) || conn->wants_to_write);
  }

  if(conn->hold_open_until_flushed)
    tor_assert(conn->marked_for_close);

  /* XXX check: wants_to_read, wants_to_write, s, poll_index,
   * marked_for_close. */

  /* buffers */
  if (!connection_is_listener(conn)) {
    assert_buf_ok(conn->inbuf);
    assert_buf_ok(conn->outbuf);
  }

#if 0 /* computers often go back in time; no way to know */
  tor_assert(!now || conn->timestamp_lastread <= now);
  tor_assert(!now || conn->timestamp_lastwritten <= now);
  tor_assert(conn->timestamp_created <= conn->timestamp_lastread);
  tor_assert(conn->timestamp_created <= conn->timestamp_lastwritten);
#endif

  /* XXX Fix this; no longer so.*/
#if 0
  if(conn->type != CONN_TYPE_OR && conn->type != CONN_TYPE_DIR)
    tor_assert(!conn->pkey);
  /* pkey is set if we're a dir client, or if we're an OR in state OPEN
   * connected to another OR.
   */
#endif

  if (conn->type != CONN_TYPE_OR) {
    tor_assert(!conn->tls);
  } else {
    if(conn->state == OR_CONN_STATE_OPEN) {
      /* tor_assert(conn->bandwidth > 0); */
      /* the above isn't necessarily true: if we just did a TLS
       * handshake but we didn't recognize the other peer, or it
       * gave a bad cert/etc, then we won't have assigned bandwidth,
       * yet it will be open. -RD
       */
      tor_assert(conn->receiver_bucket >= 0);
    }
    tor_assert(conn->addr && conn->port);
    tor_assert(conn->address);
    if (conn->state != OR_CONN_STATE_CONNECTING)
      tor_assert(conn->tls);
  }

  if (conn->type != CONN_TYPE_EXIT && conn->type != CONN_TYPE_AP) {
    tor_assert(!conn->stream_id);
    tor_assert(!conn->next_stream);
    tor_assert(!conn->cpath_layer);
    tor_assert(!conn->package_window);
    tor_assert(!conn->deliver_window);
    tor_assert(!conn->done_sending);
    tor_assert(!conn->done_receiving);
  } else {
    /* XXX unchecked: package window, deliver window. */
  }
  if (conn->type == CONN_TYPE_AP) {
    tor_assert(conn->socks_request);
    if (conn->state == AP_CONN_STATE_OPEN) {
      tor_assert(conn->socks_request->has_finished);
      tor_assert(conn->cpath_layer);
      assert_cpath_layer_ok(conn->cpath_layer);
    }
  } else {
    tor_assert(!conn->socks_request);
  }
  if (conn->type == CONN_TYPE_EXIT) {
    tor_assert(conn->purpose == EXIT_PURPOSE_CONNECT ||
               conn->purpose == EXIT_PURPOSE_RESOLVE);
  } else if(conn->type != CONN_TYPE_DIR) {
    tor_assert(!conn->purpose); /* only used for dir types currently */
  }

  switch(conn->type)
    {
    case CONN_TYPE_OR_LISTENER:
    case CONN_TYPE_AP_LISTENER:
    case CONN_TYPE_DIR_LISTENER:
      tor_assert(conn->state == LISTENER_STATE_READY);
      break;
    case CONN_TYPE_OR:
      tor_assert(conn->state >= _OR_CONN_STATE_MIN &&
                 conn->state <= _OR_CONN_STATE_MAX);
      break;
    case CONN_TYPE_EXIT:
      tor_assert(conn->state >= _EXIT_CONN_STATE_MIN &&
                 conn->state <= _EXIT_CONN_STATE_MAX);
      break;
    case CONN_TYPE_AP:
      tor_assert(conn->state >= _AP_CONN_STATE_MIN &&
                 conn->state <= _AP_CONN_STATE_MAX);
      tor_assert(conn->socks_request);
      break;
    case CONN_TYPE_DIR:
      tor_assert(conn->state >= _DIR_CONN_STATE_MIN &&
                 conn->state <= _DIR_CONN_STATE_MAX);
      tor_assert(conn->purpose >= _DIR_PURPOSE_MIN &&
                 conn->purpose <= _DIR_PURPOSE_MAX);
      break;
    case CONN_TYPE_DNSWORKER:
      tor_assert(conn->state == DNSWORKER_STATE_IDLE ||
                 conn->state == DNSWORKER_STATE_BUSY);
      break;
    case CONN_TYPE_CPUWORKER:
      tor_assert(conn->state >= _CPUWORKER_STATE_MIN &&
                 conn->state <= _CPUWORKER_STATE_MAX);
      break;
    default:
      tor_assert(0);
  }
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
