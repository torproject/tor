
#include "or.h"

/********* START VARIABLES **********/

/* valid command-line options */
static char *args = "hf:e:n:l:";

int loglevel = LOG_DEBUG; /* global variable */

//int global_role = ROLE_AP_LISTEN;
int global_role = ROLE_OR_LISTEN | ROLE_OR_CONNECT_ALL | ROLE_OP_LISTEN | ROLE_AP_LISTEN;
/* FIXME defaulting to all roles for now. should make it a config option though */

/* valid config file options */
config_opt_t options[] =
{
  {"RouterFile", CONFIG_TYPE_STRING, {0}, 0},
  {"PrivateKeyFile", CONFIG_TYPE_STRING, {0}, 0},
  {"APPort", CONFIG_TYPE_INT, {0}, 0},
  {"OPPort", CONFIG_TYPE_INT, {0}, 0},
  {"ORPort", CONFIG_TYPE_INT, {0}, 0},
  {"CoinWeight", CONFIG_TYPE_DOUBLE, {0}, 0},
  {"MaxConn", CONFIG_TYPE_INT, {0}, 0},
  {"TrafficShaping", CONFIG_TYPE_INT, {0}, 0},
  {0}
};
enum opts {
  RouterFile=0, PrivateKeyFile, APPort, OPPort, ORPort, CoinWeight, MaxConn, TrafficShaping
};

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
    log(LOG_DEBUG,"connection_add(): failing because nfds is too high.");
    return -1;
  }

  conn->poll_index = nfds;
  connection_set_poll_socket(conn);
  connection_array[nfds] = conn;

  /* zero these out here, because otherwise we'll inherit values from the previously freed one */
  poll_array[nfds].events = 0;
  poll_array[nfds].revents = 0;

  nfds++;

  log(LOG_DEBUG,"connection_add(): new conn type %d, socket %d, nfds %d.",conn->type, conn->s, nfds);

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
    log(LOG_DEBUG,"connection_remove(): nfds now %d.",nfds);  
    return 0;
  } 

  /* we replace this one with the one at the end, then free it */
  nfds--;
  poll_array[current_index].fd = poll_array[nfds].fd; 
  poll_array[current_index].events = poll_array[nfds].events;
  poll_array[current_index].revents = poll_array[nfds].revents;
  connection_array[current_index] = connection_array[nfds];
  connection_array[current_index]->poll_index = current_index;

  log(LOG_DEBUG,"connection_remove(): nfds now %d.",nfds);

  return 0;  
}

connection_t *connection_twin_get_by_addr_port(uint32_t addr, uint16_t port) {
  int i;
  connection_t *conn;

  /* first check if it's there exactly */
  conn = connection_exact_get_by_addr_port(addr,port);
  if(conn)
    return conn;

  /* now check if any of the other open connections are a twin for this one */

  /* XXX */

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
  return new_route(options[CoinWeight].r.d, router_array,rarray_len, rlen);
}

/* a wrapper around create_onion */
unsigned char *router_create_onion(unsigned int *route, size_t routelen, size_t *lenp, crypt_path_t **cpathp) {
  return create_onion(router_array,rarray_len,route,routelen,lenp,cpathp);
}





connection_t *connect_to_router_as_op(routerinfo_t *router) {
  return connection_connect_to_router_as_op(router, prkey, options[ORPort].r.i);
}

void connection_watch_events(connection_t *conn, short events) {

  assert(conn && conn->poll_index < nfds);

  poll_array[conn->poll_index].events = events;
}

void check_conn_read(int i) {
  int retval;
  connection_t *conn;

  if(poll_array[i].revents & POLLIN) { /* something to read */

    conn = connection_array[i];
    assert(conn);
    log(LOG_DEBUG,"check_conn_read(): socket %d has something to read.",conn->s);

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
	log(LOG_DEBUG,"check_conn_read(): connection_process_inbuf returned %d.",retval);
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
    log(LOG_DEBUG,"check_conn_write(): socket %d wants to write.",conn->s);

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
        check_conn_read(i);
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

int do_main_loop(void) {
  int i;

  /* load the routers file */
  router_array = getrouters(options[RouterFile].r.str,&rarray_len, options[ORPort].r.i);
  if (!router_array)
  {
    log(LOG_ERR,"Error loading router list.");
    exit(1);
  }

  /* load the private key */
  prkey = load_prkey(options[PrivateKeyFile].r.str);
  if (!prkey)
  {
    log(LOG_ERR,"Error loading private key.");
    exit(1);
  }
  log(LOG_DEBUG,"core : Loaded private key of size %u bytes.",RSA_size(prkey));

  /* start-up the necessary connections based on global_role. This is where we
   * try to connect to all the other ORs, and start the listeners */
  retry_all_connections(global_role, router_array, rarray_len, prkey, 
		        options[ORPort].r.i,options[OPPort].r.i,
			options[APPort].r.i);

  for(;;) {
    poll(poll_array, nfds, -1); /* poll until we have an event */

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
}

void catch () {
  errno = 0; /* netcat does this. it looks fun. */

  log(LOG_DEBUG,"Catching ^c, exiting cleanly.");
   
  exit(0);
}

int main(int argc, char *argv[]) {
  int retval = 0;

  char *conf_filename = NULL; /* configuration file */
  signal (SIGINT, catch); /* to catch ^c so we can exit cleanly */

  /* get command-line arguments */
  retval = getargs(argc,argv,args,&conf_filename,&loglevel);
  if (retval == -1)
  {
    log(LOG_ERR,"Error processing command-line arguments.");
    exit(1);
  }

  /* load config file */
  retval = getconfig(conf_filename,options);
  if (retval == -1)
  {
    log(LOG_ERR,"Error loading configuration file.");
    exit(1);
  }
  else if (options[RouterFile].err != 1)
  { 
    log(LOG_ERR,"RouterFile option required, but not found.");
    exit(1);
  }
  else if (options[PrivateKeyFile].err != 1)
  { 
    log(LOG_ERR,"PrivateKeyFile option required but not found.");
    exit(1);
  }
  else if (options[CoinWeight].err != 1)
  {
    log(LOG_ERR,"Error reading the CoinWeight option.");
    exit(1);
  }
  else if (options[APPort].err != 1)
  { 
    log(LOG_ERR,"APPort option required but not found.");
    exit(1);
  }
  else if (options[OPPort].err != 1)
  { 
    log(LOG_ERR,"OPPort option required but not found.");
    exit(1);
  }
  else if (options[ORPort].err != 1)
  { 
    log(LOG_ERR,"ORPort option required but not found.");
    exit(1);
  }
  else if (options[MaxConn].err != 1)
  { 
    log(LOG_ERR,"MaxConn option required but not found.");
    exit(1);
  }

  ERR_load_crypto_strings();
  retval = do_main_loop();
  ERR_free_strings();

  return retval;
}

