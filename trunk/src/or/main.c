/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/********* START VARIABLES **********/

or_options_t options; /* command-line and config-file options */

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
  circuit_about_to_close_connection(conn); /* if it's an edge conn, remove it from the list
                                            * of conn's on this circuit. If it's not on an edge,
                                            * flush and send destroys for all circuits on this conn
                                            */

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
      if (retval < 0 && conn->type == CONN_TYPE_DIR && conn->state == DIR_CONN_STATE_CONNECTING) {
         /* it's a directory server and connecting failed: forget about this router */
         router_forget_router(conn->addr,conn->port); /* FIXME i don't think this function works. */
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
//  connection_t *conn = NULL;
  connection_t *tmpconn;
  struct timeval now; //soonest;
  static long current_second = 0; /* from previous calls to gettimeofday */
  static long time_to_fetch_directory = 0;
  static long time_to_new_circuit = 0;
//  int ms_until_conn;
  cell_t cell;
  circuit_t *circ;

  my_gettimeofday(&now);

  if(now.tv_sec > current_second) { /* the second has rolled over. check more stuff. */

    if(!options.DirPort) {
      if(time_to_fetch_directory < now.tv_sec) {
        /* it's time to fetch a new directory */
        /* NOTE directory servers do not currently fetch directories.
         * Hope this doesn't bite us later.
         */
        directory_initiate_fetch(router_pick_directory_server());
        time_to_fetch_directory = now.tv_sec + options.DirFetchPeriod;
      }
    }

    if(options.APPort && time_to_new_circuit < now.tv_sec) {
      circuit_expire_unused_circuits();
      circuit_launch_new(-1); /* tell it to forget about previous failures */
      circ = circuit_get_newest_ap();
      if(!circ || circ->dirty) {
        log(LOG_INFO,"prepare_for_poll(): Youngest circuit %s; launching replacement.", circ ? "dirty" : "missing");
        circuit_launch_new(0); /* make an onion and lay the circuit */
      }
      time_to_new_circuit = now.tv_sec + options.NewCircuitPeriod;
    }

    /* do housekeeping for each connection */
    for(i=0;i<nfds;i++) {
      tmpconn = connection_array[i];
      connection_increment_receiver_bucket(tmpconn);

      /* check connections to see whether we should send a keepalive, expire, or wait */
      if(!connection_speaks_cells(tmpconn))
        continue; /* this conn type doesn't send cells */
      if(now.tv_sec >= tmpconn->timestamp_lastwritten + options.KeepalivePeriod) {
        if((!options.ORPort && !circuit_get_by_conn(tmpconn)) ||
           (!connection_state_is_open(tmpconn))) {
          /* we're an onion proxy, with no circuits; or our handshake has expired. kill it. */
          log(LOG_DEBUG,"prepare_for_poll(): Expiring connection to %d (%s:%d).",
              i,tmpconn->address, tmpconn->port);
          tmpconn->marked_for_close = 1;
        } else {
          /* either a full router, or we've got a circuit. send a padding cell. */
//          log(LOG_DEBUG,"prepare_for_poll(): Sending keepalive to (%s:%d)",
//              tmpconn->address, tmpconn->port);
          memset(&cell,0,sizeof(cell_t));
          cell.command = CELL_PADDING;
          if(connection_write_cell_to_buf(&cell, tmpconn) < 0)
            tmpconn->marked_for_close = 1;
        }
      }
    }
    /* blow away any connections that need to die. can't do this later
     * because we might open up a circuit and not realize it we're about to cull it.
     */
    for(i=0;i<nfds;i++)
      check_conn_marked(i); 

    current_second = now.tv_sec; /* remember which second it is, for next time */
  }

  if(onion_pending_check()) {
    /* there's an onion pending. check for new things to do, but don't wait any time */
    *timeout = 0;
  } else {
    *timeout = 1000 - (now.tv_usec / 1000); /* how many milliseconds til the next second? */
  }

  return 0;
}



/* Link padding stuff left here for fun. Not used now. */
#if 0
  if(options.LinkPadding) {
    /* now check which conn wants to speak soonest */
    for(i=0;i<nfds;i++) {
      tmpconn = connection_array[i];
      if(!connection_speaks_cells(tmpconn))
        continue; /* this conn type doesn't send cells */
      if(!connection_state_is_open(tmpconn))
        continue; /* only conns in state 'open' have a valid send_timeval */ 
      while(tv_cmp(&tmpconn->send_timeval,&now) <= 0) { /* send_timeval has already passed, let it send a cell */
        connection_send_cell(tmpconn);
      }
      if(!conn || tv_cmp(&tmpconn->send_timeval, &soonest) < 0) { /* this is the best choice so far */
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
#endif

int do_main_loop(void) {
  int i;
  int timeout;
  int poll_result;
  crypto_pk_env_t *prkey;

  /* load the routers file */
  if(router_get_list_from_file(options.RouterFile) < 0) {
    log(LOG_ERR,"Error loading router list.");
    return -1;
  }

  /* load the private key, if we're supposed to have one */
  if(options.ORPort) {
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

  /* start up the necessary connections based on which ports are
   * non-zero. This is where we try to connect to all the other ORs,
   * and start the listeners
   */
  retry_all_connections(options.ORPort,
                        options.OPPort, options.APPort, options.DirPort);

  for(;;) {
    if(please_dumpstats) {
      dumpstats();
      please_dumpstats = 0;
    }
    if(please_fetch_directory) {
      if(options.DirPort) {
        if(router_get_list_from_file(options.RouterFile) < 0) {
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

    /* poll until we have an event, or it's time to do something */
    poll_result = poll(poll_array, nfds, timeout);

#if 0 /* let catch() handle things like ^c, and otherwise don't worry about it */
    if(poll_result < 0) {
      log(LOG_ERR,"do_main_loop(): poll failed.");
      if(errno != EINTR) /* let the program survive things like ^z */
        return -1;
    }
#endif

    if(poll_result == 0) { 
      /* poll timed out without anything to do. process a pending onion, if any. */
      onion_pending_process_one();
    }

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
//    case SIGABRT:
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

void dumpstats(void) { /* dump stats to stdout */
  int i;
  connection_t *conn;
  struct timeval now;
  extern char *conn_type_to_string[];
  extern char *conn_state_to_string[][15];

  printf("Dumping stats:\n");
  my_gettimeofday(&now);

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
  char *signing_pkey, *signing_pkey_tag;
  int pkeylen, signing_pkeylen;
  int written;
  int result=0;
  struct exit_policy_t *tmpe;

  if(crypto_pk_write_public_key_to_string(router->pkey,&pkey,&pkeylen)<0) {
    log(LOG_ERR,"dump_router_to_string(): write pkey to string failed!");
    return 0;
  }

  signing_pkey = "";
  signing_pkey_tag = "";
  if (router->signing_pkey) {
    if(crypto_pk_write_public_key_to_string(router->signing_pkey,
                                         &signing_pkey,&signing_pkeylen)<0) {
      log(LOG_ERR,"dump_router_to_string(): write signing_pkey to string failed!");
      return 0;
    }
    signing_pkey_tag = "signing-key\n";
  }
  
  result = snprintf(s, maxlen, "router %s %d %d %d %d %d\n%s%s%s",
    router->address,
    router->or_port,
    router->op_port,
    router->ap_port,
    router->dir_port,
    router->bandwidth,
    pkey,
    signing_pkey_tag, signing_pkey);

  free(pkey);
  if (*signing_pkey)
    free(signing_pkey);

  if(result < 0 || result > maxlen) {
    /* apparently different glibcs do different things on snprintf error.. so check both */
    return -1;
  }
  written = result;

  for(tmpe=router->exit_policy; tmpe; tmpe=tmpe->next) {
    result = snprintf(s+written, maxlen-written, "%s %s:%s\n", 
      tmpe->policy_type == EXIT_POLICY_ACCEPT ? "accept" : "reject",
      tmpe->address, tmpe->port);
    if(result < 0 || result+written > maxlen) {
      /* apparently different glibcs do different things on snprintf error.. so check both */
      return -1;
    }
    written += result;
  }

  if(written > maxlen-2) {
    return -1; /* not enough space for \n\0 */
  }
  /* XXX count fenceposts here. They're probably wrong. In general,
   * we need a better way to handle overruns in building the directory
   * string, and a better way to handle directory string size in general. */

  /* include a last '\n' */
  s[written] = '\n';
  s[written+1] = 0;
  return written+1;

}

void dump_directory_to_string(char *s, int maxlen) 
{
  directory_t dir;
  routerinfo_t **routers = NULL;;
  connection_t *conn;
  routerinfo_t *router;
  int i, n = 0;

  routers = (routerinfo_t**) malloc(sizeof(routerinfo_t*) * (nfds+1));
  if (!routers) {
    /* freak out XXX */
    return;
  }
  if (my_routerinfo) {
    routers[n++] = my_routerinfo;
  }
  for(i = 0; i<nfds; ++i) {
    conn = connection_array[i];

    if(conn->type != CONN_TYPE_OR)
      continue; /* we only want to list ORs */
    if(conn->state != OR_CONN_STATE_OPEN)
      continue; /* we only want to list ones that successfully handshaked */
    router = router_get_by_addr_port(conn->addr,conn->port);
    if(!router) {
      log(LOG_ERR,"dump_directory_to_string(): couldn't find router %d:%d!",conn->addr,conn->port);
      continue;
    }
    routers[n++] = router;
  }
  dir.routers = routers;
  dir.n_routers = n;

  dump_directory_to_string_impl(s, maxlen, &dir);
}

int
dump_signed_directory_to_string_impl(char *s, int maxlen, directory_t *dir,
                                     crypto_pk_env_t *private_key)
{
  char *cp;
  char digest[20];
  char signature[128];
  int i;
  strncpy(s, 
          "signed-directory\n"
          "client-software x y z\n" /* XXX make this real */
          "server-software a b c\n\n" /* XXX make this real */
          , maxlen);
  /* These multiple strlen calls are inefficient, but dwarfed by the RSA
     signature.
  */
  i = strlen(s); 

  dump_directory_to_string_impl(s+i, maxlen-i, dir);
  i = strlen(s);
  cp = s + i;
  
  if (crypto_SHA_digest(s, i, digest))
    return -1;
  if (crypto_pk_private_sign(private_key, digest, 20, signature))
    return -1;
  

  strncpy(cp, 
          "directory-signature\n-----BEGIN SIGNATURE-----\n", maxlen-i);
          
  i = strlen(s);
  cp = s+i;
  if (base64_encode(cp, maxlen-i, signature, 128) < 0)
    return -1;

  i = strlen(s);
  cp = s+i;
  strcat(cp, "-----END SIGNATURE-----\n");

  return 0;
}

void dump_directory_to_string_impl(char *s, int maxlen, directory_t *directory) {
  int i;
  routerinfo_t *router;
  int written;

  for (i = 0; i < directory->n_routers; ++i) {
    router = directory->routers[i];
    written = dump_router_to_string(s, maxlen, router);

    if(written < 0) { 
      log(LOG_ERR,"dump_directory_to_string(): tried to exceed string length.");
      s[maxlen-1] = 0; /* make sure it's null terminated */
      return;
    }

    maxlen -= written;
    s += written;
  }
}

void daemonize(void) {
  /* Fork; parent exits. */
  if (fork())
    exit(0);

  /* Create new session; make sure we never get a terminal */
  setsid();
  if (fork())
    exit(0);

  chdir("/");
  umask(000);

  fclose(stdin);
  fclose(stdout);
  fclose(stderr);
}

int tor_main(int argc, char *argv[]) {
  int retval = 0;

  if(getconfig(argc,argv,&options))
    exit(1);
  log(options.loglevel,NULL);         /* assign logging severity level from options */

  if (options.Daemon)
    daemonize();

  if(options.ORPort) { /* only spawn dns handlers if we're a router */
    if(dns_master_start() < 0) {
      log(LOG_ERR,"main(): We're running without a dns handler. Bad news.");
    }
  }

  init_cache_tree(); /* initialize the dns resolve tree */

  signal (SIGINT,  catch); /* catch kills so we can exit cleanly */
  signal (SIGTERM, catch);
  signal (SIGUSR1, catch); /* to dump stats to stdout */
  signal (SIGHUP,  catch); /* to reload directory */

  crypto_global_init();
  retval = do_main_loop();
  crypto_global_cleanup();

  return retval;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
