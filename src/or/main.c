/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/********* START VARIABLES **********/

or_options_t options; /* command-line and config-file options */
int global_role;

static connection_t *connection_array[MAXCONNECTIONS] =
        { NULL };

static struct pollfd poll_array[MAXCONNECTIONS];

static int nfds=0; /* number of connections currently active */

static int please_dumpstats=0; /* whether we should dump stats during the loop */
static int please_fetch_directory=0; /* whether we should fetch a new directory */

/* private key */
static crypto_pk_env_t *privatekey;

routerinfo_t *my_routerinfo=NULL;

/********* END VARIABLES ************/

void setprivatekey(crypto_pk_env_t *k) {
  privatekey = k;
}

crypto_pk_env_t *getprivatekey(void) {
  assert(privatekey);
  return privatekey;
}

/****************************************************************************
*
* This section contains accessors and other methods on the connection_array
* and poll_array variables (which are global within this file and unavailable
* outside it).
*
****************************************************************************/

int connection_add(connection_t *conn) {

  if(nfds >= options.MaxConn-1) {
    log(LOG_INFO,"connection_add(): failing because nfds is too high.");
    return -1;
  }

  conn->poll_index = nfds;
  connection_set_poll_socket(conn);
  connection_array[nfds] = conn;

  /* zero these out here, because otherwise we'll inherit values from the previously freed one */
  poll_array[nfds].events = 0;
  poll_array[nfds].revents = 0;

  nfds++;

  log(LOG_INFO,"connection_add(): new conn type %d, socket %d, nfds %d.",conn->type, conn->s, nfds);

  return 0;
}

void connection_set_poll_socket(connection_t *conn) {
  poll_array[conn->poll_index].fd = conn->s;
}

int connection_remove(connection_t *conn) {
  int current_index;

  assert(conn);
  assert(nfds>0);

  log(LOG_INFO,"connection_remove(): removing socket %d, nfds now %d",conn->s, nfds-1);
  circuit_about_to_close_connection(conn); /* flush and send destroys for all circuits on this conn */

  current_index = conn->poll_index;
  if(current_index == nfds-1) { /* this is the end */
    nfds--;
    return 0;
  } 

  /* we replace this one with the one at the end, then free it */
  nfds--;
  poll_array[current_index].fd = poll_array[nfds].fd; 
  poll_array[current_index].events = poll_array[nfds].events;
  poll_array[current_index].revents = poll_array[nfds].revents;
  connection_array[current_index] = connection_array[nfds];
  connection_array[current_index]->poll_index = current_index;

  return 0;  
}

connection_t *connection_twin_get_by_addr_port(uint32_t addr, uint16_t port) {
  /* Find a connection to the router described by addr and port,
   *   or alternately any router which knows its key.
   * This connection *must* be in 'open' state.
   * If not, return NULL.
   */
  int i;
  connection_t *conn;
  routerinfo_t *router;

  /* first check if it's there exactly */
  conn = connection_exact_get_by_addr_port(addr,port);
  if(conn && connection_state_is_open(conn)) {
    log(LOG_INFO,"connection_twin_get_by_addr_port(): Found exact match.");
    return conn;
  }

  /* now check if any of the other open connections are a twin for this one */

  router = router_get_by_addr_port(addr,port);
  if(!router)
    return NULL;

  for(i=0;i<nfds;i++) {
    conn = connection_array[i];
    assert(conn);
    if(connection_state_is_open(conn) && !crypto_pk_cmp_keys(conn->pkey, router->pkey)) {
      log(LOG_INFO,"connection_twin_get_by_addr_port(): Found twin (%s).",conn->address);
      return conn;
    }
  }

  /* guess not */
  return NULL;

}

connection_t *connection_exact_get_by_addr_port(uint32_t addr, uint16_t port) {
  int i;
  connection_t *conn;

  for(i=0;i<nfds;i++) {
    conn = connection_array[i];
    assert(conn);
    if(conn->addr == addr && conn->port == port)
       return conn;
  }

  return NULL;
}

connection_t *connection_get_by_type(int type) {
  int i;
  connection_t *conn;

  for(i=0;i<nfds;i++) {
    conn = connection_array[i];
    if(conn->type == type)
       return conn;
  }

  return NULL;
}




/* FIXME can we cut this function out? */
connection_t *connect_to_router_as_op(routerinfo_t *router) {
  return connection_connect_to_router_as_op(router, options.ORPort);
}

void connection_watch_events(connection_t *conn, short events) {

  assert(conn && conn->poll_index < nfds);

  poll_array[conn->poll_index].events = events;
}

void connection_stop_reading(connection_t *conn) {

  assert(conn && conn->poll_index < nfds);

  log(LOG_DEBUG,"connection_stop_reading() called.");
  if(poll_array[conn->poll_index].events & POLLIN)
    poll_array[conn->poll_index].events -= POLLIN;
}

void connection_start_reading(connection_t *conn) {

  assert(conn && conn->poll_index < nfds);

  poll_array[conn->poll_index].events |= POLLIN;
}

void connection_stop_writing(connection_t *conn) {

  assert(conn && conn->poll_index < nfds);

  if(poll_array[conn->poll_index].events & POLLOUT)
    poll_array[conn->poll_index].events -= POLLOUT;
}

void connection_start_writing(connection_t *conn) {

  assert(conn && conn->poll_index < nfds);

  poll_array[conn->poll_index].events |= POLLOUT;
}


void check_conn_read(int i) {
  int retval;
  connection_t *conn;

  if(poll_array[i].revents & POLLIN) { /* something to read */

    conn = connection_array[i];
    assert(conn);
//    log(LOG_DEBUG,"check_conn_read(): socket %d has something to read.",conn->s);

    if (conn->type == CONN_TYPE_OP_LISTENER) {
      retval = connection_op_handle_listener_read(conn);
    } else if (conn->type == CONN_TYPE_OR_LISTENER) {
      retval = connection_or_handle_listener_read(conn);
    } else if (conn->type == CONN_TYPE_AP_LISTENER) {
      retval = connection_ap_handle_listener_read(conn);
    } else if (conn->type == CONN_TYPE_DIR_LISTENER) {
      retval = connection_dir_handle_listener_read(conn);
    } else {
      retval = connection_read_to_buf(conn);
      if (retval < 0 && conn->type == CONN_TYPE_DIR) {
         /* as a special case: forget about this router */
         router_forget_router(conn->addr,conn->port);
      }
      if (retval >= 0) { /* all still well */
        retval = connection_process_inbuf(conn);
//      log(LOG_DEBUG,"check_conn_read(): connection_process_inbuf returned %d.",retval);
        if(retval >= 0 && !connection_state_is_open(conn) && conn->receiver_bucket == 0) {
          log(LOG_DEBUG,"check_conn_read(): receiver bucket reached 0 before handshake finished. Closing.");
          retval = -1;
        }
      }
    }

    if(retval < 0) { /* this connection is broken. remove it */
      log(LOG_INFO,"check_conn_read(): Connection broken, removing."); 
      connection_remove(conn);
      connection_free(conn);
      if(i<nfds) { /* we just replaced the one at i with a new one.
                      process it too. */
        check_conn_read(i);
      }
    }
  }
}

void check_conn_write(int i) {
  int retval;
  connection_t *conn;

  if(poll_array[i].revents & POLLOUT) { /* something to write */

    conn = connection_array[i];
//    log(LOG_DEBUG,"check_conn_write(): socket %d wants to write.",conn->s);

    if(connection_is_listener(conn)) {
      log(LOG_DEBUG,"check_conn_write(): Got a listener socket. Can't happen!");
      retval = -1;
    } else {
      /* else it's an OP, OR, or exit */
      retval = connection_flush_buf(conn); /* conns in CONNECTING state will fall through... */
      if(retval == 0) { /* it's done flushing */
        retval = connection_finished_flushing(conn); /* ...and get handled here. */
      }
    }

    if(retval < 0) { /* this connection is broken. remove it. */
      log(LOG_DEBUG,"check_conn_write(): Connection broken, removing.");
      connection_remove(conn);
      connection_free(conn);
      if(i<nfds) { /* we just replaced the one at i with a new one.
                      process it too. */
        check_conn_write(i);
      }
    }
  }
}

void check_conn_marked(int i) {
  connection_t *conn;

  conn = connection_array[i];
  assert(conn);
  if(conn->marked_for_close) {
    log(LOG_DEBUG,"check_conn_marked(): Cleaning up connection.");
    if(conn->s >= 0) { /* might be an incomplete exit connection */
      /* FIXME there's got to be a better way to check for this -- and make other checks? */
      connection_flush_buf(conn); /* flush it first */
    }
    connection_remove(conn);
    connection_free(conn);
    if(i<nfds) { /* we just replaced the one at i with a new one.
                    process it too. */
      check_conn_marked(i);
    }
  }
}

int prepare_for_poll(int *timeout) {
  int i;
  int need_to_refill_buckets = 0;
  connection_t *conn = NULL;
  connection_t *tmpconn;
  struct timeval now, soonest;
  static long current_second = 0; /* from previous calls to gettimeofday */
  static long time_to_rebuild_directory = 0;
  static long time_to_fetch_directory = 0;
  int ms_until_conn;
  cell_t cell;

  if(gettimeofday(&now,NULL) < 0)
    return -1;

  if(options.Role & ROLE_DIR_SERVER) {
    if(time_to_rebuild_directory < now.tv_sec) {
      /* it's time to rebuild our directory */
      if(time_to_rebuild_directory == 0) { 
        /* we just started up. if we build a directory now it will be meaningless. */
        log(LOG_DEBUG,"prepare_for_poll(): Delaying initial dir build for 15 seconds.");
        time_to_rebuild_directory = now.tv_sec + 15; /* try in 15 seconds */
      } else {
        directory_rebuild();
        time_to_rebuild_directory = now.tv_sec + options.DirRebuildPeriod;
      }
    }
    *timeout = 1000*(time_to_rebuild_directory - now.tv_sec) + (1000 - (now.tv_usec / 1000));
//    log(LOG_DEBUG,"prepare_for_poll(): DirBuild timeout is %d",*timeout);
  }

  if(!(options.Role & ROLE_DIR_SERVER)) {
    if(time_to_fetch_directory < now.tv_sec) {
      /* it's time to fetch a new directory */
      /* NOTE directory servers do not currently fetch directories.
       * Hope this doesn't bite us later.
       */
      directory_initiate_fetch(router_pick_directory_server());
      time_to_fetch_directory = now.tv_sec + options.DirFetchPeriod;
    }
    *timeout = 1000*(time_to_fetch_directory - now.tv_sec) + (1000 - (now.tv_usec / 1000));
  }

  /* check connections to see whether we should send a keepalive, expire, or wait */
  for(i=0;i<nfds;i++) {
    tmpconn = connection_array[i];
    if(!connection_speaks_cells(tmpconn))
      continue; /* this conn type doesn't send cells */
    if(!connection_state_is_open(tmpconn)) {
      continue; /* only conns in state 'open' need a keepalive */
      /* XXX should time-out unfinished connections someday too */
    }    
    if(now.tv_sec >= tmpconn->timestamp_lastwritten + options.KeepalivePeriod) {
      if(!(options.Role & ROLE_OR_CONNECT_ALL) && !circuit_get_by_conn(tmpconn)) {
        /* we're an onion proxy, with no circuits. kill it. */
        log(LOG_DEBUG,"prepare_for_poll(): Expiring connection to %d (%s:%d).",
            i,tmpconn->address, tmpconn->port);
        tmpconn->marked_for_close = 1;
      } else {
        /* either a full router, or we've got a circuit. send a padding cell. */
//        log(LOG_DEBUG,"prepare_for_poll(): Sending keepalive to (%s:%d)",
//            tmpconn->address, tmpconn->port);
        memset(&cell,0,sizeof(cell_t));
        cell.command = CELL_PADDING;
        connection_write_cell_to_buf(&cell, tmpconn);
      }
    }
    if(!tmpconn->marked_for_close &&
       *timeout > 1000*(tmpconn->timestamp_lastwritten + options.KeepalivePeriod - now.tv_sec)) {
      *timeout = 1000*(tmpconn->timestamp_lastwritten + options.KeepalivePeriod - now.tv_sec);
    }
  }
  assert(*timeout >= 0);
  /* blow away any connections that need to die. can't do this later
   * because we might open up a circuit and not realize it.
   */
  for(i=0;i<nfds;i++)
    check_conn_marked(i); 

  /* check if we need to refill buckets */
  for(i=0;i<nfds;i++) {
    if(connection_receiver_bucket_should_increase(connection_array[i])) {
      need_to_refill_buckets = 1;
      break;
    }
  }

  if(need_to_refill_buckets) {
    if(now.tv_sec > current_second) { /* the second has already rolled over! */
//      log(LOG_DEBUG,"prepare_for_poll(): The second has rolled over, immediately refilling.");
      for(i=0;i<nfds;i++)
        connection_increment_receiver_bucket(connection_array[i]);
      current_second = now.tv_sec; /* remember which second it is, for next time */
    }
    /* this timeout is definitely sooner than any of the above ones */
    *timeout = 1000 - (now.tv_usec / 1000); /* how many milliseconds til the next second? */
  }

  if(options.LinkPadding) {
    /* now check which conn wants to speak soonest */
    for(i=0;i<nfds;i++) {
      tmpconn = connection_array[i];
      if(!connection_speaks_cells(tmpconn))
        continue; /* this conn type doesn't send cells */
      if(!connection_state_is_open(tmpconn))
        continue; /* only conns in state 'open' have a valid send_timeval */ 
      while(tv_cmp(&tmpconn->send_timeval,&now) <= 0) { /* send_timeval has already passed, let it send a cell */
//        log(LOG_DEBUG,"prepare_for_poll(): doing backlogged connection_send_cell on socket %d (%d ms old)",tmpconn->s,
//         (now.tv_sec - tmpconn->send_timeval.tv_sec)*1000 +
//         (now.tv_usec - tmpconn->send_timeval.tv_usec)/1000
//        );
        connection_send_cell(tmpconn);
      }
      if(!conn || tv_cmp(&tmpconn->send_timeval, &soonest) < 0) { /* this is the best choice so far */
//        log(LOG_DEBUG,"prepare_for_poll(): chose socket %d as best connection so far",tmpconn->s);
        conn = tmpconn;
        soonest.tv_sec = conn->send_timeval.tv_sec;
        soonest.tv_usec = conn->send_timeval.tv_usec;
      }
    }

    if(conn) { /* we might want to set *timeout sooner */
      ms_until_conn = (soonest.tv_sec - now.tv_sec)*1000 +
                    (soonest.tv_usec - now.tv_usec)/1000;
//      log(LOG_DEBUG,"prepare_for_poll(): conn %d times out in %d ms.",conn->s, ms_until_conn);
      if(ms_until_conn < *timeout) { /* use the new one */
//        log(LOG_DEBUG,"prepare_for_poll(): conn %d soonest, in %d ms.",conn->s,ms_until_conn);
        *timeout = ms_until_conn;
      }
    }
  }

  return 0;
}

int do_main_loop(void) {
  int i;
  int timeout;
  int poll_result;
  crypto_pk_env_t *prkey;

  /* load the routers file */
  if(router_get_list_from_file(options.RouterFile, options.ORPort) < 0) {
    log(LOG_ERR,"Error loading router list.");
    return -1;
  }

  /* load the private key, if we're supposed to have one */
  if(ROLE_IS_OR(global_role)) {
    prkey = crypto_new_pk_env(CRYPTO_PK_RSA);
    if (!prkey) {
      log(LOG_ERR,"Error creating a crypto environment.");
      return -1;
    }
    if (crypto_pk_read_private_key_from_filename(prkey, options.PrivateKeyFile))
    {
      log(LOG_ERR,"Error loading private key.");
      return -1;
    }
    setprivatekey(prkey);
  }

  /* start-up the necessary connections based on global_role. This is where we
   * try to connect to all the other ORs, and start the listeners */
  retry_all_connections(options.Role, options.ORPort,
                        options.OPPort, options.APPort, options.DirPort);

  for(;;) {
    if(please_dumpstats) {
      dumpstats();
      please_dumpstats = 0;
    }
    if(please_fetch_directory) {
      if(options.Role & ROLE_DIR_SERVER) {
        if(router_get_list_from_file(options.RouterFile, options.ORPort) < 0) {
          log(LOG_ERR,"Error reloading router list. Continuing with old list.");
        }
      } else {
        directory_initiate_fetch(router_pick_directory_server());
      }
      please_fetch_directory = 0;
    }
    if(prepare_for_poll(&timeout) < 0) {
      log(LOG_DEBUG,"do_main_loop(): prepare_for_poll failed, exiting.");
      return -1;
    }
    /* now timeout is the value we'll hand to poll. It's either -1, meaning
     * don't timeout, else it indicates the soonest event (either the
     * one-second rollover for refilling receiver buckets, or the soonest
     * conn that needs to send a cell)
     */

    /* if the timeout is less than 10, set it to 10 */
    if(timeout >= 0 && timeout < 10)
      timeout = 10;

    /* poll until we have an event, or it's time to do something */
    poll_result = poll(poll_array, nfds, timeout);

#if 0 /* let catch() handle things like ^c, and otherwise don't worry about it */
    if(poll_result < 0) {
      log(LOG_ERR,"do_main_loop(): poll failed.");
      if(errno != EINTR) /* let the program survive things like ^z */
        return -1;
    }
#endif

    if(poll_result > 0) { /* we have at least one connection to deal with */
      /* do all the reads first, so we can detect closed sockets */
      for(i=0;i<nfds;i++)
        check_conn_read(i); /* this also blows away broken connections */

      /* then do the writes */
      for(i=0;i<nfds;i++)
        check_conn_write(i);

      /* any of the conns need to be closed now? */
      for(i=0;i<nfds;i++)
        check_conn_marked(i); 
    }
    /* refilling buckets and sending cells happens at the beginning of the
     * next iteration of the loop, inside prepare_for_poll()
     */
  }
}

static void catch(int the_signal) {

  switch(the_signal) {
    case SIGABRT:
    case SIGTERM:
    case SIGINT:
      log(LOG_NOTICE,"Catching signal %d, exiting cleanly.", the_signal);
      exit(0);
    case SIGHUP:
      please_fetch_directory = 1;
      break;
    case SIGUSR1:
      please_dumpstats = 1;
      break;
    default:
      log(LOG_ERR,"Caught signal that we can't handle??");
  }
}

void dumpstats (void) { /* dump stats to stdout */
  int i;
  connection_t *conn;
  struct timeval now;
  extern char *conn_type_to_string[];
  extern char *conn_state_to_string[][15];

  printf("Dumping stats:\n");
  if(gettimeofday(&now,NULL) < 0)
    return ;

  for(i=0;i<nfds;i++) {
    conn = connection_array[i];
    printf("Conn %d (socket %d) type %d (%s), state %d (%s), created %ld secs ago\n",
      i, conn->s, conn->type, conn_type_to_string[conn->type],
      conn->state, conn_state_to_string[conn->type][conn->state], now.tv_sec - conn->timestamp_created);
    if(!connection_is_listener(conn)) {
      printf("Conn %d is to '%s:%d'.\n",i,conn->address, conn->port);
      printf("Conn %d: %d bytes waiting on inbuf (last read %ld secs ago)\n",i,conn->inbuf_datalen,
        now.tv_sec - conn->timestamp_lastread);
      printf("Conn %d: %d bytes waiting on outbuf (last written %ld secs ago)\n",i,conn->outbuf_datalen, 
        now.tv_sec - conn->timestamp_lastwritten);
    }
    circuit_dump_by_conn(conn); /* dump info about all the circuits using this conn */
    printf("\n");
  }

}

int dump_router_to_string(char *s, int maxlen, routerinfo_t *router) {
  char *pkey;
  int pkeylen;
  int written;

  if(crypto_pk_write_public_key_to_string(router->pkey,&pkey,&pkeylen)<0) {
    log(LOG_ERR,"dump_directory_to_string(): write pkey to string failed!");
    return 0;
  }
  written = snprintf(s, maxlen, "%s %d %d %d %d %d\n%s\n",
    router->address,
    router->or_port,
    router->op_port,
    router->ap_port,
    router->dir_port,
    router->bandwidth,
    pkey);

  free(pkey);

  return written;
}

void dump_directory_to_string(char *s, int maxlen) {
  int i;
  connection_t *conn;
  routerinfo_t *router;
  int written;

  /* first write my own info */
  /* XXX should check for errors here too */
  written = dump_router_to_string(s, maxlen, my_routerinfo);
  maxlen -= written;
  s += written;

  /* now write info for other routers */
  for(i=0;i<nfds;i++) {
    conn = connection_array[i];

    if(conn->type != CONN_TYPE_OR)
      continue; /* we only want to list ORs */
    router = router_get_by_addr_port(conn->addr,conn->port);
    if(!router) {
      log(LOG_ERR,"dump_directory_to_string(): couldn't find router %d:%d!",conn->addr,conn->port);
      return;
    }

    written = dump_router_to_string(s, maxlen, router);

    if(written < 0 || written > maxlen) { 
      /* apparently different glibcs do different things on error.. so check both */
      log(LOG_ERR,"dump_directory_to_string(): tried to exceed string length.");
      s[maxlen-1] = 0; /* make sure it's null terminated */
      return;
    }
  
    maxlen -= written;
    s += written;
  }

}

int main(int argc, char *argv[]) {
  int retval = 0;

  signal (SIGINT, catch); /* catch kills so we can exit cleanly */
  signal (SIGABRT, catch);
  signal (SIGTERM, catch);
  signal (SIGUSR1, catch); /* to dump stats to stdout */
  signal (SIGHUP, catch); /* to reload directory */

  if ( getoptions(argc,argv,&options) ) exit(1);
  log(options.loglevel,NULL);         /* assign logging severity level from options */
  global_role = options.Role;   /* assign global_role from options. FIX: remove from global namespace later. */

  crypto_global_init();
  retval = do_main_loop();
  crypto_global_cleanup();

  return retval;
}

