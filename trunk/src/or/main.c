/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/********* START PROTOTYPES **********/

static void dumpstats(int severity); /* log stats */
static int init_from_config(int argc, char **argv);

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
static int please_reset=0; /* whether we just got a sighup */
static int please_reap_children=0; /* whether we should waitpid for exited children */
#endif /* signal stuff */

/********* END VARIABLES ************/

/****************************************************************************
*
* This section contains accessors and other methods on the connection_array
* and poll_array variables (which are global within this file and unavailable
* outside it).
*
****************************************************************************/

int connection_add(connection_t *conn) {

  if(nfds >= options.MaxConn-1) {
    log(LOG_WARN,"connection_add(): failing because nfds is too high.");
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

/* Remove the connection from the global list, and remove the
 * corresponding poll entry.  Calling this function will shift the last
 * connection (if any) into the position occupied by conn.
 */
int connection_remove(connection_t *conn) {
  int current_index;

  assert(conn);
  assert(nfds>0);

  log(LOG_INFO,"connection_remove(): removing socket %d, nfds now %d",conn->s, nfds-1);
  /* if it's an edge conn, remove it from the list
   * of conn's on this circuit. If it's not on an edge,
   * flush and send destroys for all circuits on this conn
   */
  circuit_about_to_close_connection(conn);

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
    if(!connection_is_reading(conn) ||
       !connection_has_pending_tls_data(conn))
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
      log_fn(LOG_INFO,"%s connection broken, removing.",
             conn_type_to_string[conn->type]);
      connection_remove(conn);
      connection_free(conn);
      if(i<nfds) {
        /* we just replaced the one at i with a new one. process it too. */
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

static void conn_close_if_marked(int i) {
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
      if(connection_wants_to_flush(conn) && buf_datalen(conn->outbuf)) {
        log_fn(LOG_WARN,"Conn (socket %d) still wants to flush. Losing %d bytes!",
               conn->s, (int)buf_datalen(conn->outbuf));
      }
    }
    connection_remove(conn);
    connection_free(conn);
    if(i<nfds) { /* we just replaced the one at i with a new one.
                    process it too. */
      conn_close_if_marked(i);
    }
  }
}

/* Perform regular maintenance tasks for a single connection.  This
 * function gets run once per second per connection by run_housekeeping.
 */
static void run_connection_housekeeping(int i, time_t now) {
  cell_t cell;
  connection_t *conn = connection_array[i];

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
    return;

  if(now >= conn->timestamp_lastwritten + options.KeepalivePeriod) {
    if((!options.ORPort && !circuit_get_by_conn(conn)) ||
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
      connection_or_write_cell_to_buf(&cell, conn);
    }
  }
}

/* Perform regular maintenance tasks.  This function gets run once per
 * second by prepare_for_poll.
 */
static void run_scheduled_events(time_t now) {
  static long time_to_fetch_directory = 0;
  static long time_to_new_circuit = 0;
  circuit_t *circ;
  int i;

  /* 1. Every DirFetchPostPeriod seconds, we get a new directory and upload
   *    our descriptor (if any). */
  if(time_to_fetch_directory < now) {
    /* it's time to fetch a new directory and/or post our descriptor */
    if(options.ORPort) {
      router_rebuild_descriptor();
      router_upload_desc_to_dirservers();
    }
    if(!options.DirPort) {
      /* NOTE directory servers do not currently fetch directories.
       * Hope this doesn't bite us later. */
      directory_initiate_command(router_pick_directory_server(),
                                 DIR_CONN_STATE_CONNECTING_FETCH);
    }
    time_to_fetch_directory = now + options.DirFetchPostPeriod;
  }

  /* 2. Every second, we examine pending circuits and prune the
   *    ones which have been pending for more than 3 seconds.
   *    We do this before step 3, so it can try building more if
   *    it's not comfortable with the number of available circuits.
   */
  circuit_expire_building();

  /* 2b. Also look at pending streams and prune the ones that 'began'
   *     a long time ago but haven't gotten a 'connected' yet.
   *     Do this before step 3, so we can put them back into pending
   *     state to be picked up by the new circuit.
   */
  connection_ap_expire_beginning();

  /* 3. Every second, we try a new circuit if there are no valid
   *    circuits. Every NewCircuitPeriod seconds, we expire circuits
   *    that became dirty more than NewCircuitPeriod seconds ago,
   *    and we make a new circ if there are no clean circuits.
   */
  if(options.SocksPort) {

    /* launch a new circ for any pending streams that need one */
    connection_ap_attach_pending();

    circ = circuit_get_newest(NULL, 1);
    if(time_to_new_circuit < now) {
      client_dns_clean();
      circuit_expire_unused_circuits();
      circuit_reset_failure_count();
      if(circ && circ->timestamp_dirty) {
        log_fn(LOG_INFO,"Youngest circuit dirty; launching replacement.");
        circuit_launch_new(); /* make a new circuit */
      }
      time_to_new_circuit = now + options.NewCircuitPeriod;
    }
#define CIRCUIT_MIN_BUILDING 2
    if(!circ && circuit_count_building() < CIRCUIT_MIN_BUILDING) {
      /* if there's no open circ, and less than 2 are on the way,
       * go ahead and try another.
       */
      circuit_launch_new();
    }
  }

  /* 4. Every second, we check how much bandwidth we've consumed and
   *    increment global_read_bucket.
   */
  stats_n_bytes_read += stats_prev_global_read_bucket-global_read_bucket;
  if(global_read_bucket < options.BandwidthBurst) {
    global_read_bucket += options.BandwidthRate;
    log_fn(LOG_DEBUG,"global_read_bucket now %d.", global_read_bucket);
  }
  stats_prev_global_read_bucket = global_read_bucket;

  /* 5. We do housekeeping for each connection... */
  for(i=0;i<nfds;i++) {
    run_connection_housekeeping(i, now);
  }

  /* 6. and blow away any connections that need to die. can't do this later
   * because we might open up a circuit and not realize we're about to cull
   * the connection it's running over.
   * XXX we can remove this step once we audit circuit-building to make sure
   *     it doesn't pick a marked-for-close conn. -RD
   */
  for(i=0;i<nfds;i++)
    conn_close_if_marked(i);
}

static int prepare_for_poll(void) {
  static long current_second = 0; /* from previous calls to gettimeofday */
  connection_t *conn;
  struct timeval now;
  int i;

  tor_gettimeofday(&now);

  if(now.tv_sec > current_second) { /* the second has rolled over. check more stuff. */

    ++stats_n_seconds_reading;
    run_scheduled_events(now.tv_sec);

    current_second = now.tv_sec; /* remember which second it is, for next time */
  }

  for(i=0;i<nfds;i++) {
    conn = connection_array[i];
    if(connection_has_pending_tls_data(conn)) {
      log_fn(LOG_DEBUG,"sock %d has pending bytes.",conn->s);
      return 0; /* has pending bytes to read; don't let poll wait. */
    }
  }

  return (1000 - (now.tv_usec / 1000)); /* how many milliseconds til the next second? */
}

static int init_from_config(int argc, char **argv) {
  if(getconfig(argc,argv,&options)) {
    log_fn(LOG_ERR,"Reading config failed. For usage, try -h.");
    return -1;
  }
  close_logs(); /* we'll close, then open with correct loglevel if necessary */
  if(!options.LogFile && !options.RunAsDaemon)
    add_stream_log(options.loglevel, "<stdout>", stdout);
  if(options.LogFile) {
    if (add_file_log(options.loglevel, options.LogFile) != 0) {
      /* opening the log file failed!  Use stderr and log a warning */
      add_stream_log(options.loglevel, "<stderr>", stderr);
      log_fn(LOG_WARN, "Cannot write to LogFile '%s': %s.", options.LogFile, strerror(errno));
    }
    log_fn(LOG_WARN, "Successfully opened LogFile '%s', redirecting output.",
           options.LogFile);
  }
  if(options.DebugLogFile) {
    if (add_file_log(LOG_DEBUG, options.DebugLogFile) != 0)
      log_fn(LOG_WARN, "Cannot write to DebugLogFile '%s': %s.", options.DebugLogFile, strerror(errno));
    log_fn(LOG_DEBUG, "Successfully opened DebugLogFile '%s'.", options.DebugLogFile);
  }

  global_read_bucket = options.BandwidthBurst; /* start it at max traffic */
  stats_prev_global_read_bucket = global_read_bucket;

  if(options.User || options.Group) {
    if(switch_id(options.User, options.Group) != 0) {
      return -1;
    }
  }

  if(options.RunAsDaemon) {
    /* XXXX Can we delay this any more? */
    finish_daemon();
  }

  /* write our pid to the pid file, if we do not have write permissions we will log a warning */
  if(options.PidFile)
    write_pidfile(options.PidFile);

  return 0;
}

static int do_main_loop(void) {
  int i;
  int timeout;
  int poll_result;

  /* load the routers file */
  if(router_set_routerlist_from_file(options.RouterFile) < 0) {
    log_fn(LOG_ERR,"Error loading router list.");
    return -1;
  }

  /* load the private keys, if we're supposed to have them, and set up the
   * TLS context. */
  if (init_keys() < 0) {
    log_fn(LOG_ERR,"Error initializing keys; exiting");
    return -1;
  }

  if(options.ORPort) {
    cpu_init(); /* launch cpuworkers. Need to do this *after* we've read the onion key. */
    router_upload_desc_to_dirservers(); /* upload our descriptor to all dirservers */
  }

  /* start up the necessary connections based on which ports are
   * non-zero. This is where we try to connect to all the other ORs,
   * and start the listeners.
   */
  if(retry_all_connections() < 0) {
    log_fn(LOG_ERR,"Failed to bind one of the listener ports.");
    return -1;
  }

  for(;;) {
#ifndef MS_WINDOWS /* do signal stuff only on unix */
    if(please_dumpstats) {
      /* prefer to log it at INFO, but make sure we always see it */
      dumpstats(options.loglevel>LOG_INFO ? options.loglevel : LOG_INFO);
      please_dumpstats = 0;
    }
    if(please_reset) {
      log_fn(LOG_WARN,"Received sighup. Reloading config.");
      /* first, reload config variables, in case they've changed */
      if (init_from_config(0, NULL) < 0) {
        /* no need to provide argc/v, they've been cached inside init_from_config */
        exit(1);
      }
      if(retry_all_connections() < 0) {
        log_fn(LOG_ERR,"Failed to bind one of the listener ports.");
        return -1;
      }
      if(options.DirPort) {
        /* reload the approved-routers file */
        char keydir[512];
        sprintf(keydir,"%s/approved-routers", options.DataDirectory);
        log_fn(LOG_INFO,"Reloading approved fingerprints from %s...",keydir);
        if(dirserv_parse_fingerprint_file(keydir) < 0) {
          log_fn(LOG_WARN, "Error reloading fingerprints. Continuing with old list.");
        }
      } else {
        /* fetch a new directory */
        directory_initiate_command(router_pick_directory_server(), DIR_CONN_STATE_CONNECTING_FETCH);
      }

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

    /* let catch() handle things like ^c, and otherwise don't worry about it */
    if(poll_result < 0) {
      if(errno != EINTR) { /* let the program survive things like ^z */
        log_fn(LOG_ERR,"poll failed.");
        return -1;
      } else {
        log_fn(LOG_DEBUG,"poll interrupted.");
      }
    }

    /* do all the reads and errors first, so we can detect closed sockets */
    for(i=0;i<nfds;i++)
      conn_read(i); /* this also blows away broken connections */

    /* then do the writes */
    for(i=0;i<nfds;i++)
      conn_write(i);

    /* any of the conns need to be closed now? */
    for(i=0;i<nfds;i++)
      conn_close_if_marked(i);

    /* refilling buckets and sending cells happens at the beginning of the
     * next iteration of the loop, inside prepare_for_poll()
     */
  }
}

static void catch(int the_signal) {

#ifndef MS_WINDOWS /* do signal stuff only on unix */
  switch(the_signal) {
//    case SIGABRT:
    case SIGTERM:
    case SIGINT:
      log(LOG_ERR,"Catching signal %d, exiting cleanly.", the_signal);
      /* we don't care if there was an error when we unlink, nothing
         we could do about it anyways */
      if(options.PidFile)
        unlink(options.PidFile);
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
      log(LOG_WARN,"Caught signal %d that we can't handle??", the_signal);
  }
#endif /* signal stuff */
}

static void dumpstats(int severity) {
  int i;
  connection_t *conn;
  time_t now = time(NULL);

  log(severity, "Dumping stats:");

  for(i=0;i<nfds;i++) {
    conn = connection_array[i];
    log(severity, "Conn %d (socket %d) type %d (%s), state %d (%s), created %ld secs ago",
      i, conn->s, conn->type, conn_type_to_string[conn->type],
      conn->state, conn_state_to_string[conn->type][conn->state], now - conn->timestamp_created);
    if(!connection_is_listener(conn)) {
      log(severity,"Conn %d is to '%s:%d'.",i,conn->address, conn->port);
      log(severity,"Conn %d: %d bytes waiting on inbuf (last read %ld secs ago)",i,
             (int)buf_datalen(conn->inbuf),
             now - conn->timestamp_lastread);
      log(severity,"Conn %d: %d bytes waiting on outbuf (last written %ld secs ago)",i,
             (int)buf_datalen(conn->outbuf), now - conn->timestamp_lastwritten);
    }
    circuit_dump_by_conn(conn, severity); /* dump info about all the circuits using this conn */
  }
  log(severity,
         "Cells processed: %10lu padding\n"
         "                 %10lu create\n"
         "                 %10lu created\n"
         "                 %10lu relay\n"
         "                        (%10lu relayed)\n"
         "                        (%10lu delivered)\n"
         "                 %10lu destroy",
         stats_n_padding_cells_processed,
         stats_n_create_cells_processed,
         stats_n_created_cells_processed,
         stats_n_relay_cells_processed,
         stats_n_relay_cells_relayed,
         stats_n_relay_cells_delivered,
         stats_n_destroy_cells_processed);
  if (stats_n_data_cells_packaged)
    log(severity,"Average packaged cell fullness: %2.3f%%",
           100*(((double)stats_n_data_bytes_packaged) /
                (stats_n_data_cells_packaged*RELAY_PAYLOAD_SIZE)) );
  if (stats_n_data_cells_received)
    log(severity,"Average delivered cell fullness: %2.3f%%",
           100*(((double)stats_n_data_bytes_received) /
                (stats_n_data_cells_received*RELAY_PAYLOAD_SIZE)) );

  if (stats_n_seconds_reading)
    log(severity,"Average bandwidth used: %d bytes/sec",
           (int) (stats_n_bytes_read/stats_n_seconds_reading));
}

int tor_main(int argc, char *argv[]) {

  /* give it somewhere to log to initially */
  add_stream_log(LOG_INFO, "<stdout>", stdout);
  log_fn(LOG_WARN,"Tor v%s. This is experimental software. Do not use it if you need anonymity.",VERSION);

  if (init_from_config(argc,argv) < 0)
    return -1;

#ifndef MS_WINDOWS
  if(geteuid()==0)
    log_fn(LOG_WARN,"You are running Tor as root. You don't need to, and you probably shouldn't.");
#endif

  if (options.RunAsDaemon) {
    start_daemon();
  }

  if(options.ORPort) { /* only spawn dns handlers if we're a router */
    dns_init(); /* initialize the dns resolve tree, and spawn workers */
  }
  if(options.SocksPort) {
    client_dns_init(); /* init the client dns cache */
  }

#ifndef MS_WINDOWS /* do signal stuff only on unix */
  signal (SIGINT,  catch); /* catch kills so we can exit cleanly */
  signal (SIGTERM, catch);
  signal (SIGUSR1, catch); /* to dump stats */
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
