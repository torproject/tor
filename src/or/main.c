/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/********* START VARIABLES **********/

or_options_t options; /* command-line and config-file options */
int global_role;

static connection_t *connection_array[MAXCONNECTIONS] =
        { NULL };

static struct pollfd poll_array[MAXCONNECTIONS] =
        { [0 ... MAXCONNECTIONS-1] = { -1, 0, 0 } };

static int nfds=0; /* number of connections currently active */

/* private key */
static RSA *prkey = NULL;

/* router array */
static routerinfo_t **router_array = NULL;
static int rarray_len = 0;

/********* END VARIABLES ************/

/****************************************************************************
*
* This section contains accessors and other methods on the connection_array
* and poll_array variables (which are global within this file and unavailable
* outside it).
*
****************************************************************************/

int connection_add(connection_t *conn) {

  if(nfds >= MAXCONNECTIONS-2) { /* 2, for some breathing room. should count the fenceposts. */
    /* FIXME should use the 'max connections' option */
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

  circuit_about_to_close_connection(conn); /* flush and send destroys for all circuits on this conn */

  current_index = conn->poll_index;
  if(current_index == nfds-1) { /* this is the end */
//    connection_free(conn);
    nfds--;
    log(LOG_INFO,"connection_remove(): nfds now %d.",nfds);  
    return 0;
  } 

  /* we replace this one with the one at the end, then free it */
  nfds--;
  poll_array[current_index].fd = poll_array[nfds].fd; 
  poll_array[current_index].events = poll_array[nfds].events;
  poll_array[current_index].revents = poll_array[nfds].revents;
  connection_array[current_index] = connection_array[nfds];
  connection_array[current_index]->poll_index = current_index;

  log(LOG_INFO,"connection_remove(): nfds now %d.",nfds);

  return 0;  
}

int pkey_cmp(RSA *a, RSA *b) {
  /* return 0 if a and b are "the same key". Return non-0 otherwise. */

  int result;

  if(!a || !b)
    return -1;

  assert(a->n && a->e && b->n && b->e);

  result = BN_cmp(a->n, b->n);
  if(result)
    return result;
  return BN_cmp(a->e, b->e);
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
    log(LOG_DEBUG,"connection_twin_get_by_addr_port(): Found exact match.");
    return conn;
  }

  /* now check if any of the other open connections are a twin for this one */

  router = router_get_by_addr_port(addr,port);
  if(!router)
    return NULL;

  for(i=0;i<nfds;i++) {
    conn = connection_array[i];
    assert(conn);
    if(connection_state_is_open(conn) && !pkey_cmp(conn->pkey, router->pkey)) {
      log(LOG_DEBUG,"connection_twin_get_by_addr_port(): Found twin (%s).",conn->address);
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




/* the next 4 functions should move to routers.c once we get it
 * cleaned up more. The router_array and rarray_len variables should
 * move there too.
 */

routerinfo_t *router_get_by_addr_port(uint32_t addr, uint16_t port) {
  int i;
  routerinfo_t *router;

  assert(router_array);

  for(i=0;i<rarray_len;i++) {
    router = router_array[i];
    if ((router->addr == addr) && (router->or_port == port))
      return router;
  }

  return NULL;
}

routerinfo_t *router_get_first_in_route(unsigned int *route, size_t routelen) {
  return router_array[route[routelen-1]];
}

/* a wrapper around new_route. put all these in routers.c perhaps? */
unsigned int *router_new_route(size_t *rlen) {
  return new_route(options.CoinWeight, router_array,rarray_len, rlen);
}

/* a wrapper around create_onion */
unsigned char *router_create_onion(unsigned int *route, size_t routelen, size_t *lenp, crypt_path_t **cpathp) {
  return create_onion(router_array,rarray_len,route,routelen,lenp,cpathp);
}





connection_t *connect_to_router_as_op(routerinfo_t *router) {
  return connection_connect_to_router_as_op(router, prkey, options.ORPort);
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
    } else {
      /* else it's an OP, OR, or exit */
      retval = connection_read_to_buf(conn);
      if (retval >= 0) { /* all still well */
        retval = connection_process_inbuf(conn);
//	log(LOG_DEBUG,"check_conn_read(): connection_process_inbuf returned %d.",retval);
        if(retval >= 0 && !connection_state_is_open(conn) && conn->receiver_bucket == 0) {
          log(LOG_DEBUG,"check_conn_read(): receiver bucket reached 0 before handshake finished. Closing.");
          retval = -1;
        }
      }
    }

    if(retval < 0) { /* this connection is broken. remove it */
      log(LOG_DEBUG,"check_conn_read(): Connection broken, removing."); 
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

    if(conn->type == CONN_TYPE_OP_LISTENER ||
       conn->type == CONN_TYPE_OR_LISTENER) {
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
  static int current_second = 0; /* from previous calls to gettimeofday */
  int ms_until_conn;

  *timeout = -1; /* set it to never timeout, possibly overridden below */
  
  /* first check if we need to refill buckets */
  for(i=0;i<nfds;i++) {
    if(connection_receiver_bucket_should_increase(connection_array[i])) {
      need_to_refill_buckets = 1;
      break;
    }
  }

  if(gettimeofday(&now,NULL) < 0)
    return -1;

  if(need_to_refill_buckets) {
    if(now.tv_sec > current_second) { /* the second has already rolled over! */
//      log(LOG_DEBUG,"prepare_for_poll(): The second has rolled over, immediately refilling.");
      for(i=0;i<nfds;i++)
        connection_increment_receiver_bucket(connection_array[i]);
      current_second = now.tv_sec; /* remember which second it is, for next time */
    }
    *timeout = 1000 - (now.tv_usec / 1000); /* how many milliseconds til the next second? */
//    log(LOG_DEBUG,"prepare_for_poll(): %d milliseconds til next second.",*timeout);
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
      if(*timeout == -1 || ms_until_conn < *timeout) { /* use the new one */
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

  /* load the routers file */
  router_array = getrouters(options.RouterFile,&rarray_len, options.ORPort);
  if (!router_array)
  {
    log(LOG_ERR,"Error loading router list.");
    return -1;
  }

  /* load the private key */
  prkey = load_prkey(options.PrivateKeyFile);
  if (!prkey)
  {
    log(LOG_ERR,"Error loading private key.");
    return -1;
  }
  log(LOG_DEBUG,"core : Loaded private key of size %u bytes.",RSA_size(prkey));

  /* start-up the necessary connections based on global_role. This is where we
   * try to connect to all the other ORs, and start the listeners */
  retry_all_connections(options.Role, router_array, rarray_len, prkey, 
		        options.ORPort, options.OPPort, options.APPort);

  for(;;) {
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

void catch () {
  errno = 0; /* netcat does this. it looks fun. */

  log(LOG_DEBUG,"Catching ^c, exiting cleanly.");
   
  exit(0);
}

int main(int argc, char *argv[]) {
  int retval = 0;

  signal (SIGINT, catch); /* to catch ^c so we can exit cleanly */

  if ( getoptions(argc,argv,&options) ) exit(1);
  log(options.loglevel,NULL);         /* assign logging severity level from options */
  global_role = options.Role;   /* assign global_role from options. FIX: remove from global namespace later. */

  ERR_load_crypto_strings();
  retval = do_main_loop();
  ERR_free_strings();

  return retval;
}

