/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/********* START PROTOTYPES **********/

static void dumpstats(void); /* dump stats to stdout */

/********* START VARIABLES **********/

extern char *conn_type_to_string[];
extern char *conn_state_to_string[][_CONN_TYPE_MAX+1];

or_options_t options; /* command-line and config-file options */
int global_read_bucket; /* max number of bytes I can read this second */

static int stats_prev_global_read_bucket;
static uint64_t stats_n_bytes_read = 0;
static long stats_n_seconds_reading = 0;

static connection_t *connection_array[MAXCONNECTIONS] =
        { NULL };

static struct pollfd poll_array[MAXCONNECTIONS];

static int nfds=0; /* number of connections currently active */

#ifndef MS_WINDOWS /* do signal stuff only on unix */
static int please_dumpstats=0; /* whether we should dump stats during the loop */
static int please_reset =0; /* whether we just got a sighup */
static int please_reap_children=0; /* whether we should waitpid for exited children*/
#endif /* signal stuff */

/* private keys */
static crypto_pk_env_t *onionkey=NULL;
static crypto_pk_env_t *linkkey=NULL;
static crypto_pk_env_t *identitykey=NULL;

/********* END VARIABLES ************/

void set_onion_key(crypto_pk_env_t *k) {
  onionkey = k;
}

crypto_pk_env_t *get_onion_key(void) {
  assert(onionkey);
  return onionkey;
}

void set_link_key(crypto_pk_env_t *k)
{
  linkkey = k;
}

crypto_pk_env_t *get_link_key(void)
{
  assert(linkkey);
  return linkkey;
}

void set_identity_key(crypto_pk_env_t *k) {
  identitykey = k;
}

crypto_pk_env_t *get_identity_key(void) {
  assert(identitykey);
  return identitykey;
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
    log(LOG_WARNING,"connection_add(): failing because nfds is too high.");
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

void get_connection_array(connection_t ***array, int *n) {
  *array = connection_array;
  *n = nfds;
}

void connection_watch_events(connection_t *conn, short events) {

  assert(conn && conn->poll_index < nfds);

  poll_array[conn->poll_index].events = events;
}

int connection_is_reading(connection_t *conn) {
  return poll_array[conn->poll_index].events & POLLIN;
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

static void conn_read(int i) {
  connection_t *conn = connection_array[i];

  /* see http://www.greenend.org.uk/rjk/2001/06/poll.html for
   * discussion of POLLIN vs POLLHUP */
  if(!(poll_array[i].revents & (POLLIN|POLLHUP|POLLERR)))
    if(!connection_speaks_cells(conn) ||
       conn->state != OR_CONN_STATE_OPEN ||
       !connection_is_reading(conn) ||
       !tor_tls_get_pending_bytes(conn->tls)) 
      return; /* this conn should not read */

  log_fn(LOG_DEBUG,"socket %d wants to read.",conn->s);
 
  assert_connection_ok(conn, time(NULL));

  if(
      /* XXX does POLLHUP also mean it's definitely broken? */
#ifdef MS_WINDOWS
      (poll_array[i].revents & POLLERR) ||
#endif
    connection_handle_read(conn) < 0)
    {
      /* this connection is broken. remove it */
      log_fn(LOG_INFO,"%s connection broken, removing.", conn_type_to_string[conn->type]); 
      connection_remove(conn);
      connection_free(conn);
      if(i<nfds) { /* we just replaced the one at i with a new one. process it too. */
        conn_read(i);
      }
    } else assert_connection_ok(conn, time(NULL));
}

static void conn_write(int i) {
  connection_t *conn;

  if(!(poll_array[i].revents & POLLOUT))
    return; /* this conn doesn't want to write */

  conn = connection_array[i];
  log_fn(LOG_DEBUG,"socket %d wants to write.",conn->s);

  assert_connection_ok(conn, time(NULL));

  if(connection_handle_write(conn) < 0) { /* this connection is broken. remove it. */
    log_fn(LOG_INFO,"%s connection broken, removing.", conn_type_to_string[conn->type]);
    connection_remove(conn);
    connection_free(conn);
    if(i<nfds) { /* we just replaced the one at i with a new one. process it too. */
        conn_write(i);
    }
  } else assert_connection_ok(conn, time(NULL));
}

static void check_conn_marked(int i) {
  connection_t *conn;

  conn = connection_array[i];
  assert_connection_ok(conn, time(NULL));
  if(conn->marked_for_close) {
    log_fn(LOG_INFO,"Cleaning up connection (fd %d).",conn->s);
    if(conn->s >= 0) { /* might be an incomplete edge connection */
      /* FIXME there's got to be a better way to check for this -- and make other checks? */
      if(connection_speaks_cells(conn)) {
        if(conn->state == OR_CONN_STATE_OPEN)
          flush_buf_tls(conn->tls, conn->outbuf, &conn->outbuf_flushlen);
      } else {
        flush_buf(conn->s, conn->outbuf, &conn->outbuf_flushlen);
      }
      if(connection_wants_to_flush(conn)) /* not done flushing */
        log_fn(LOG_WARNING,"Conn (socket %d) still wants to flush. Losing %d bytes!",conn->s, (int)buf_datalen(conn->inbuf));
    }
    connection_remove(conn);
    connection_free(conn);
    if(i<nfds) { /* we just replaced the one at i with a new one.
                    process it too. */
      check_conn_marked(i);
    }
  }
}

static int prepare_for_poll(void) {
  int i;
  connection_t *conn;
  struct timeval now;
  static long current_second = 0; /* from previous calls to gettimeofday */
  static long time_to_fetch_directory = 0;
  static long time_to_new_circuit = 0;
  cell_t cell;
  circuit_t *circ;

  tor_gettimeofday(&now);

  if(now.tv_sec > current_second) { /* the second has rolled over. check more stuff. */

    ++stats_n_seconds_reading;

    if(time_to_fetch_directory < now.tv_sec) {
      /* it's time to fetch a new directory and/or post our descriptor */
      if(options.OnionRouter) {
        router_rebuild_descriptor();
        router_upload_desc_to_dirservers();
      }
      if(!options.DirPort) {
        /* NOTE directory servers do not currently fetch directories.
         * Hope this doesn't bite us later. */
        directory_initiate_command(router_pick_directory_server(),
                                   DIR_CONN_STATE_CONNECTING_FETCH);
      }
      time_to_fetch_directory = now.tv_sec + options.DirFetchPostPeriod;
    }

    if(options.APPort && time_to_new_circuit < now.tv_sec) {
      circuit_expire_unused_circuits();
      circuit_launch_new(-1); /* tell it to forget about previous failures */
      circ = circuit_get_newest_open();
      if(!circ || circ->dirty) {
        log_fn(LOG_INFO,"Youngest circuit %s; launching replacement.", circ ? "dirty" : "missing");
        circuit_launch_new(0); /* make an onion and lay the circuit */
      }
      time_to_new_circuit = now.tv_sec + options.NewCircuitPeriod;
    }

    stats_n_bytes_read += stats_prev_global_read_bucket-global_read_bucket;
    if(global_read_bucket < 9*options.TotalBandwidth) {
      global_read_bucket += options.TotalBandwidth;
      log_fn(LOG_DEBUG,"global_read_bucket now %d.", global_read_bucket);
    }
    stats_prev_global_read_bucket = global_read_bucket;

    /* do housekeeping for each connection */
    for(i=0;i<nfds;i++) {
      conn = connection_array[i];
      if(connection_receiver_bucket_should_increase(conn)) {
        conn->receiver_bucket += conn->bandwidth;
//        log_fn(LOG_DEBUG,"Receiver bucket %d now %d.", i, conn->receiver_bucket);
      }

      if(conn->wants_to_read == 1 /* it's marked to turn reading back on now */
         && global_read_bucket > 0 /* and we're allowed to read */
         && (!connection_speaks_cells(conn) || conn->receiver_bucket > 0)) {
         /* and either a non-cell conn or a cell conn with non-empty bucket */
        conn->wants_to_read = 0;
        connection_start_reading(conn);
	if(conn->wants_to_write == 1) {
          conn->wants_to_write = 0;
          connection_start_writing(conn);
        }
      }

      /* check connections to see whether we should send a keepalive, expire, or wait */
      if(!connection_speaks_cells(conn))
        continue; /* this conn type doesn't send cells */
      if(now.tv_sec >= conn->timestamp_lastwritten + options.KeepalivePeriod) {
        if((!options.OnionRouter && !circuit_get_by_conn(conn)) ||
           (!connection_state_is_open(conn))) {
          /* we're an onion proxy, with no circuits; or our handshake has expired. kill it. */
          log_fn(LOG_INFO,"Expiring connection to %d (%s:%d).",
              i,conn->address, conn->port);
          conn->marked_for_close = 1;
        } else {
          /* either a full router, or we've got a circuit. send a padding cell. */
          log_fn(LOG_DEBUG,"Sending keepalive to (%s:%d)",
              conn->address, conn->port);
          memset(&cell,0,sizeof(cell_t));
          cell.command = CELL_PADDING;
          connection_write_cell_to_buf(&cell, conn);
        }
      }
    }
    /* blow away any connections that need to die. can't do this later
     * because we might open up a circuit and not realize we're about to cull
     * the connection it's running over.
     */
    for(i=0;i<nfds;i++)
      check_conn_marked(i); 

    current_second = now.tv_sec; /* remember which second it is, for next time */
  }

  for(i=0;i<nfds;i++) {
    conn = connection_array[i];
    if(connection_speaks_cells(conn) &&
       connection_state_is_open(conn) &&
       tor_tls_get_pending_bytes(conn->tls)) {
      log_fn(LOG_DEBUG,"sock %d has pending bytes.",conn->s);
      return 0; /* has pending bytes to read; don't let poll wait. */
    }
  }

  return (1000 - (now.tv_usec / 1000)); /* how many milliseconds til the next second? */
}

static crypto_pk_env_t *init_key_from_file(const char *fname)
{
  crypto_pk_env_t *prkey = NULL;
  int fd = -1;
  FILE *file = NULL;

  if (!(prkey = crypto_new_pk_env(CRYPTO_PK_RSA))) {
    log(LOG_ERR, "Error creating crypto environment.");
    goto error;
  }

  switch(file_status(fname)) {
  case FN_DIR:
  case FN_ERROR:
    log(LOG_ERR, "Can't read key from %s", fname);
    goto error;
  case FN_NOENT:
    log(LOG_INFO, "No key found in %s; generating fresh key.", fname);
    if (crypto_pk_generate_key(prkey)) {
      log(LOG_ERR, "Error generating key: %s", crypto_perror());
      goto error;
    }
    if (crypto_pk_check_key(prkey) <= 0) {
      log(LOG_ERR, "Generated key seems invalid");
      goto error;
    }
    log(LOG_INFO, "Generated key seems valid");
    if (crypto_pk_write_private_key_to_filename(prkey, fname)) {
      log(LOG_ERR, "Couldn't write generated key to %s.", fname);
      goto error;
    }
    return prkey;
  case FN_FILE:
    if (crypto_pk_read_private_key_from_filename(prkey, fname)) {
      log(LOG_ERR, "Error loading private key.");
      goto error;
    }
    return prkey;
  default: 
    assert(0);
  }

 error:
  if (prkey)
    crypto_free_pk_env(prkey);
  if (fd >= 0 && !file)
    close(fd);
  if (file)
    fclose(file);
  return NULL;
}

static int init_keys(void)
{
  char keydir[512];
  char fingerprint[FINGERPRINT_LEN+MAX_NICKNAME_LEN+3]; 
  char *cp;
  const char *tmp, *mydesc;
  crypto_pk_env_t *prkey;

  /* OP's don't need keys.  Just initialize the TLS context.*/
  if (!options.OnionRouter) {
    assert(!options.DirPort);
    if (tor_tls_context_new(NULL, 0, NULL)<0) {
      log_fn(LOG_ERR, "Error creating TLS context for OP.");
      return -1;
    }
    return 0;
  }
  assert(options.DataDirectory);
  if (strlen(options.DataDirectory) > (512-128)) {
    log_fn(LOG_ERR, "DataDirectory is too long.");
    return -1;
  }
  if (check_private_dir(options.DataDirectory, 1)) {
    return -1;
  }
  sprintf(keydir,"%s/keys",options.DataDirectory);
  if (check_private_dir(keydir, 1)) {
    return -1;
  }
  cp = keydir + strlen(keydir); /* End of string. */
  
  /* 1. Read identity key. Make it if none is found. */
  strcpy(cp, "/identity.key");
  log_fn(LOG_INFO,"Reading/making identity key %s...",keydir);
  prkey = init_key_from_file(keydir);
  if (!prkey) return -1;
  set_identity_key(prkey);
  /* 2. Read onion key.  Make it if none is found. */
  strcpy(cp, "/onion.key");
  log_fn(LOG_INFO,"Reading/making onion key %s...",keydir);
  prkey = init_key_from_file(keydir);
  if (!prkey) return -1;
  set_onion_key(prkey);
  
  /* 3. Initialize link key and TLS context. */
  strcpy(cp, "/link.key");
  log_fn(LOG_INFO,"Reading/making link key %s...",keydir);
  prkey = init_key_from_file(keydir);
  if (!prkey) return -1;
  set_link_key(prkey);
  if (tor_tls_context_new(prkey, 1, options.Nickname) < 0) {
    log_fn(LOG_ERR, "Error initializing TLS context");
    return -1;
  }
  /* 4. Dump router descriptor to 'router.desc' */
  /* Must be called after keys are initialized. */
  if (!(router_get_my_descriptor())) {
    log_fn(LOG_ERR, "Error initializing descriptor.");
    return -1;
  }
  /* We need to add our own fingerprint so it gets recognized. */
  if (dirserv_add_own_fingerprint(options.Nickname, get_identity_key())) {
    log_fn(LOG_ERR, "Error adding own fingerprint to approved set");
    return -1;
  }
  tmp = mydesc = router_get_my_descriptor();
  if (dirserv_add_descriptor(&tmp)) {
    log(LOG_ERR, "Unable to add own descriptor to directory.");
    return -1;
  }
  sprintf(keydir,"%s/router.desc", options.DataDirectory);
  log_fn(LOG_INFO,"Dumping descriptor to %s...",keydir);
  if (write_str_to_file(keydir, mydesc)) {
    return -1;
  }
  /* 5. Dump fingerprint to 'fingerprint' */
  sprintf(keydir,"%s/fingerprint", options.DataDirectory);
  log_fn(LOG_INFO,"Dumping fingerprint to %s...",keydir);
  assert(strlen(options.Nickname) <= MAX_NICKNAME_LEN);
  strcpy(fingerprint, options.Nickname);
  strcat(fingerprint, " ");
  if (crypto_pk_get_fingerprint(get_identity_key(),
                                fingerprint+strlen(fingerprint))<0) {
    log_fn(LOG_ERR, "Error computing fingerprint");
    return -1;
  }
  strcat(fingerprint, "\n");
  if (write_str_to_file(keydir, fingerprint))
    return -1;
  if(!options.DirPort)
    return 0;
  /* 6. [dirserver only] load approved-routers file */
  sprintf(keydir,"%s/approved-routers", options.DataDirectory);
  log_fn(LOG_INFO,"Loading approved fingerprints from %s...",keydir);
  if(dirserv_parse_fingerprint_file(keydir) < 0) {
    log_fn(LOG_ERR, "Error loading fingerprints");
    return -1;
  }
  /* 7. [dirserver only] load old directory, if it's there */
  sprintf(keydir,"%s/cached-directory", options.DataDirectory);
  log_fn(LOG_INFO,"Loading cached directory from %s...",keydir);
  cp = read_file_to_str(keydir);
  if(!cp) {
    log_fn(LOG_INFO,"Cached directory %s not present. Ok.",keydir);
  } else {
    if(dirserv_init_from_directory_string(cp) < 0) {
      log_fn(LOG_ERR, "Cached directory %s is corrupt", keydir);
      free(cp);
      return -1;
    }
    free(cp);
  }
  /* success */
  return 0;
}

static int do_main_loop(void) {
  int i;
  int timeout;
  int poll_result;
  
  /* load the routers file */
  if(router_get_list_from_file(options.RouterFile) < 0) {
    log_fn(LOG_ERR,"Error loading router list.");
    return -1;
  }

  /* load the private keys, if we're supposed to have them, and set up the
   * TLS context. */
  if (init_keys() < 0) {
    log_fn(LOG_ERR,"Error initializing keys; exiting");
    return -1;
  }

  if(options.OnionRouter) {
    cpu_init(); /* launch cpuworkers. Need to do this *after* we've read the onion key. */
    router_upload_desc_to_dirservers(); /* upload our descriptor to all dirservers */
  }

  /* start up the necessary connections based on which ports are
   * non-zero. This is where we try to connect to all the other ORs,
   * and start the listeners.
   */
  retry_all_connections((uint16_t) options.ORPort,
                        (uint16_t) options.APPort,
                        (uint16_t) options.DirPort);

  for(;;) {
#ifndef MS_WIN32 /* do signal stuff only on unix */
    if(please_dumpstats) {
      dumpstats();
      please_dumpstats = 0;
    }
    if(please_reset) {
      /* fetch a new directory */
      if(options.DirPort) {
        if(router_get_list_from_file(options.RouterFile) < 0) {
          log(LOG_WARNING,"Error reloading router list. Continuing with old list.");
        }
      } else {
        directory_initiate_command(router_pick_directory_server(), DIR_CONN_STATE_CONNECTING_FETCH);
      }

      /* close and reopen the log files */
      reset_logs();

      please_reset = 0;
    }
    if(please_reap_children) {
      while(waitpid(-1,NULL,WNOHANG)) ; /* keep reaping until no more zombies */
      please_reap_children = 0;
    }
#endif /* signal stuff */

    timeout = prepare_for_poll();

    /* poll until we have an event, or the second ends */
    poll_result = poll(poll_array, nfds, timeout);

#if 0 /* let catch() handle things like ^c, and otherwise don't worry about it */
    if(poll_result < 0) {
      log(LOG_ERR,"do_main_loop(): poll failed.");
      if(errno != EINTR) /* let the program survive things like ^z */
        return -1;
    }
#endif

    /* do all the reads and errors first, so we can detect closed sockets */
    for(i=0;i<nfds;i++)
      conn_read(i); /* this also blows away broken connections */

    /* then do the writes */
    for(i=0;i<nfds;i++)
      conn_write(i);

    /* any of the conns need to be closed now? */
    for(i=0;i<nfds;i++)
      check_conn_marked(i); 

    /* refilling buckets and sending cells happens at the beginning of the
     * next iteration of the loop, inside prepare_for_poll()
     */
  }
}

static void catch(int the_signal) {

#ifndef MS_WIN32 /* do signal stuff only on unix */
  switch(the_signal) {
//    case SIGABRT:
    case SIGTERM:
    case SIGINT:
      log(LOG_ERR,"Catching signal %d, exiting cleanly.", the_signal);
      exit(0);
    case SIGHUP:
      please_reset = 1;
      break;
    case SIGUSR1:
      please_dumpstats = 1;
      break;
    case SIGCHLD:
      please_reap_children = 1;
      break;
    default:
      log(LOG_WARNING,"Caught signal %d that we can't handle??", the_signal);
  }
#endif /* signal stuff */
}

static void dumpstats(void) { /* dump stats to stdout */
  int i;
  connection_t *conn;
  time_t now = time(NULL);

  printf("Dumping stats:\n");

  for(i=0;i<nfds;i++) {
    conn = connection_array[i];
    printf("Conn %d (socket %d) type %d (%s), state %d (%s), created %ld secs ago\n",
      i, conn->s, conn->type, conn_type_to_string[conn->type],
      conn->state, conn_state_to_string[conn->type][conn->state], now - conn->timestamp_created);
    if(!connection_is_listener(conn)) {
      printf("Conn %d is to '%s:%d'.\n",i,conn->address, conn->port);
      printf("Conn %d: %d bytes waiting on inbuf (last read %ld secs ago)\n",i,
             (int)buf_datalen(conn->inbuf),
             now - conn->timestamp_lastread);
      printf("Conn %d: %d bytes waiting on outbuf (last written %ld secs ago)\n",i,
             (int)buf_datalen(conn->outbuf), now - conn->timestamp_lastwritten);
    }
    circuit_dump_by_conn(conn); /* dump info about all the circuits using this conn */
    printf("\n");
  }
  printf("Cells processed: %10lud padding\n"
         "                 %10lud create\n"
         "                 %10lud created\n"
         "                 %10lud relay\n"
         "                        (%10lud relayed)\n"
         "                        (%10lud delivered)\n"
         "                 %10lud destroy\n",
         stats_n_padding_cells_processed,
         stats_n_create_cells_processed,
         stats_n_created_cells_processed,
         stats_n_relay_cells_processed,
         stats_n_relay_cells_relayed,
         stats_n_relay_cells_delivered,
         stats_n_destroy_cells_processed);
  if (stats_n_data_cells_packaged)
    printf("Average outgoing cell fullness: %2.3f%%\n",
           100*(((double)stats_n_data_bytes_packaged) / 
                (stats_n_data_cells_packaged*(CELL_PAYLOAD_SIZE-RELAY_HEADER_SIZE))) );
  if (stats_n_data_cells_packaged)
    printf("Average incomoing cell fullness: %2.3f%%\n",
           100*(((double)stats_n_data_bytes_received) / 
                (stats_n_data_cells_received*(CELL_PAYLOAD_SIZE-RELAY_HEADER_SIZE))) );
  
  if (stats_n_seconds_reading)
    printf("Average bandwidth used: %d bytes/sec\n",
           (int) (stats_n_bytes_read/stats_n_seconds_reading));
}

void daemonize(void) {
#ifndef MS_WINDOWS
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
  fclose(stdout); /* XXX Nick: this closes our log, right? is it safe to leave this open? */
  fclose(stderr);
#endif
}

int tor_main(int argc, char *argv[]) {

  if(getconfig(argc,argv,&options)) {
    log_fn(LOG_ERR,"Reading config file failed. exiting.");
    return -1;
  }
  log_set_severity(options.loglevel);     /* assign logging severity level from options */
  global_read_bucket = options.TotalBandwidth; /* start it at 1 second of traffic */
  stats_prev_global_read_bucket = global_read_bucket;

  if(options.Daemon)
    daemonize();

  if(options.OnionRouter) { /* only spawn dns handlers if we're a router */
    dns_init(); /* initialize the dns resolve tree, and spawn workers */
  }

#ifndef MS_WINDOWS /* do signal stuff only on unix */
  signal (SIGINT,  catch); /* catch kills so we can exit cleanly */
  signal (SIGTERM, catch);
  signal (SIGUSR1, catch); /* to dump stats to stdout */
  signal (SIGHUP,  catch); /* to reload directory */
  signal (SIGCHLD, catch); /* for exiting dns/cpu workers */
#endif /* signal stuff */

  crypto_global_init();
  crypto_seed_rng();
  do_main_loop();
  crypto_global_cleanup();
  return -1;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
