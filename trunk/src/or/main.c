/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/********* PROTOTYPES **********/

static void dumpstats(int severity); /* log stats */
static int init_from_config(int argc, char **argv);

/********* START VARIABLES **********/

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

int has_fetched_directory=0;
/* we set this to 1 when we've fetched a dir, to know whether to complain
 * yet about unrecognized nicknames in entrynodes, exitnodes, etc.
 * Also, we don't try building circuits unless this is 1. */

int has_completed_circuit=0;
/* we set this to 1 when we've opened a circuit, so we can print a log
 * entry to inform the user that Tor is working. */

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
    log_fn(LOG_WARN,"failing because nfds is too high.");
    return -1;
  }

  conn->poll_index = nfds;
  connection_set_poll_socket(conn);
  connection_array[nfds] = conn;

  /* zero these out here, because otherwise we'll inherit values from the previously freed one */
  poll_array[nfds].events = 0;
  poll_array[nfds].revents = 0;

  nfds++;

  log_fn(LOG_INFO,"new conn type %s, socket %d, nfds %d.",
      CONN_TYPE_TO_STRING(conn->type), conn->s, nfds);

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

  log_fn(LOG_INFO,"removing socket %d (type %s), nfds now %d",
         conn->s, CONN_TYPE_TO_STRING(conn->type), nfds-1);
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

  /* replace this one with the one at the end */
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

int connection_is_writing(connection_t *conn) {
  return poll_array[conn->poll_index].events & POLLOUT;
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

  if (conn->marked_for_close)
    return;

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
      connection_handle_read(conn) < 0) {
      if (!conn->marked_for_close) {
        /* this connection is broken. remove it */
        /* XXX This shouldn't ever happen anymore. */
        /* XXX but it'll clearly happen on MS_WINDOWS from POLLERR, right? */
        log_fn(LOG_ERR,"Unhandled error on read for %s connection (fd %d); removing",
               CONN_TYPE_TO_STRING(conn->type), conn->s);
        connection_mark_for_close(conn,0);
      }
    }
    assert_connection_ok(conn, time(NULL));
}

static void conn_write(int i) {
  connection_t *conn;

  if(!(poll_array[i].revents & POLLOUT))
    return; /* this conn doesn't want to write */

  conn = connection_array[i];
  log_fn(LOG_DEBUG,"socket %d wants to write.",conn->s);
  if (conn->marked_for_close)
    return;

  assert_connection_ok(conn, time(NULL));

  if (connection_handle_write(conn) < 0) {
    if (!conn->marked_for_close) {
      /* this connection is broken. remove it. */
      log_fn(LOG_WARN,"Unhandled error on read for %s connection (fd %d); removing",
             CONN_TYPE_TO_STRING(conn->type), conn->s);
      conn->has_sent_end = 1; /* otherwise we cry wolf about duplicate close */
      connection_mark_for_close(conn,0);
    }
  }
  assert_connection_ok(conn, time(NULL));
}

static void conn_close_if_marked(int i) {
  connection_t *conn;
  int retval;

  conn = connection_array[i];
  assert_connection_ok(conn, time(NULL));
  if(!conn->marked_for_close)
    return; /* nothing to see here, move along */

  log_fn(LOG_INFO,"Cleaning up connection (fd %d).",conn->s);
  if(conn->s >= 0 && connection_wants_to_flush(conn)) {
    /* -1 means it's an incomplete edge connection, or that the socket
     * has already been closed as unflushable. */
    if(!conn->hold_open_until_flushed)
      log_fn(LOG_WARN,
        "Conn (fd %d, type %s, state %d) marked, but wants to flush %d bytes. "
        "(Marked at %s:%d)",
        conn->s, CONN_TYPE_TO_STRING(conn->type), conn->state,
        conn->outbuf_flushlen, conn->marked_for_close_file, conn->marked_for_close);
    if(connection_speaks_cells(conn)) {
      if(conn->state == OR_CONN_STATE_OPEN) {
        retval = flush_buf_tls(conn->tls, conn->outbuf, &conn->outbuf_flushlen);
        /* XXX actually, some non-zero results are maybe ok. which ones? */
      } else
        retval = -1; /* never flush non-open broken tls connections */
    } else {
      retval = flush_buf(conn->s, conn->outbuf, &conn->outbuf_flushlen);
    }
    if(retval >= 0 &&
       conn->hold_open_until_flushed && connection_wants_to_flush(conn)) {
      log_fn(LOG_INFO,"Holding conn (fd %d) open for more flushing.",conn->s);
      /* XXX should we reset timestamp_lastwritten here? */
      return;
    }
    if(connection_wants_to_flush(conn)) {
      log_fn(LOG_WARN,"Conn (fd %d, type %s, state %d) still wants to flush. Losing %d bytes! (Marked at %s:%d)",
             conn->s, CONN_TYPE_TO_STRING(conn->type), conn->state,
             (int)buf_datalen(conn->outbuf), conn->marked_for_close_file,
             conn->marked_for_close);
    }
  }
  connection_remove(conn);
  if(conn->type == CONN_TYPE_EXIT) {
    assert_connection_edge_not_dns_pending(conn);
  }
  connection_free(conn);
  if(i<nfds) { /* we just replaced the one at i with a new one.
                  process it too. */
    conn_close_if_marked(i);
  }
}

void directory_has_arrived(void) {

  log_fn(LOG_INFO, "We now have a directory.");

  /* just for testing */
  directory_initiate_command(router_pick_directory_server(),
                             DIR_PURPOSE_FETCH_HIDSERV, "foo", 3);

  rend_services_init(); /* get bob to initialize all his hidden services */

}

/* Perform regular maintenance tasks for a single connection.  This
 * function gets run once per second per connection by run_housekeeping.
 */
static void run_connection_housekeeping(int i, time_t now) {
  cell_t cell;
  connection_t *conn = connection_array[i];

  /* check connections to see whether we should send a keepalive, expire, or wait */
  if(!connection_speaks_cells(conn))
    return;

  if(now >= conn->timestamp_lastwritten + options.KeepalivePeriod) {
    if((!options.ORPort && !circuit_get_by_conn(conn)) ||
       (!connection_state_is_open(conn))) {
      /* we're an onion proxy, with no circuits; or our handshake has expired. kill it. */
      log_fn(LOG_INFO,"Expiring connection to %d (%s:%d).",
             i,conn->address, conn->port);
      /* flush anything waiting, e.g. a destroy for a just-expired circ */
      connection_mark_for_close(conn,CLOSE_REASON_UNUSED_OR_CONN);
      conn->hold_open_until_flushed = 1;
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
      router_upload_dir_desc_to_dirservers();
    }
    if(!options.DirPort) {
      /* NOTE directory servers do not currently fetch directories.
       * Hope this doesn't bite us later. */
      directory_initiate_command(router_pick_directory_server(),
                                 DIR_PURPOSE_FETCH_DIR, NULL, 0);
    } else {
      /* We're a directory; dump any old descriptors. */
      dirserv_remove_old_servers();
    }
    rend_cache_clean(); /* should this go elsewhere? */
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


  /* 2c. And expire connections that we've held open for too long.
   */
  connection_expire_held_open();

  /* 3. Every second, we try a new circuit if there are no valid
   *    circuits. Every NewCircuitPeriod seconds, we expire circuits
   *    that became dirty more than NewCircuitPeriod seconds ago,
   *    and we make a new circ if there are no clean circuits.
   */
  if(has_fetched_directory &&
     (options.SocksPort || options.RunTesting)) {

    if (options.SocksPort)
      /* launch a new circ for any pending streams that need one */
      connection_ap_attach_pending();

/* Build a new test circuit every 5 minutes */
#define TESTING_CIRCUIT_INTERVAL 300

    circ = circuit_get_newest(NULL, 1, 0);
    if(time_to_new_circuit < now) {
      client_dns_clean();
      circuit_expire_unused_circuits();
      circuit_reset_failure_count();
      if(circ && circ->timestamp_dirty) {
        log_fn(LOG_INFO,"Youngest circuit dirty; launching replacement.");
        /* make a new circuit */
        circuit_launch_new(CIRCUIT_PURPOSE_C_GENERAL, NULL);
      } else if (options.RunTesting && circ &&
                 circ->timestamp_created + TESTING_CIRCUIT_INTERVAL < now) {
        log_fn(LOG_INFO,"Creating a new testing circuit.");
        circuit_launch_new(CIRCUIT_PURPOSE_C_GENERAL, NULL);
      }
      time_to_new_circuit = now + options.NewCircuitPeriod;
    }
#define CIRCUIT_MIN_BUILDING 3
    if(!circ && circuit_count_building() < CIRCUIT_MIN_BUILDING) {
      /* if there's no open circ, and less than 3 are on the way,
       * go ahead and try another.
       */
      circuit_launch_new(CIRCUIT_PURPOSE_C_GENERAL, NULL);
    }
  }

  /* 5. We do housekeeping for each connection... */
  for(i=0;i<nfds;i++) {
    run_connection_housekeeping(i, now);
  }

  /* 6. And remove any marked circuits... */
  circuit_close_all_marked();

  /* 7. and blow away any connections that need to die. can't do this later
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

  /* Check how much bandwidth we've consumed,
   * and increment the token buckets. */
  stats_n_bytes_read += stats_prev_global_read_bucket-global_read_bucket;
  connection_bucket_refill(&now);
  stats_prev_global_read_bucket = global_read_bucket;

  if(now.tv_sec > current_second) { /* the second has rolled over. check more stuff. */

    ++stats_n_seconds_reading;
    run_scheduled_events(now.tv_sec);

    current_second = now.tv_sec; /* remember which second it is, for next time */
  }

  for(i=0;i<nfds;i++) {
    conn = connection_array[i];
    if(connection_has_pending_tls_data(conn) &&
       connection_is_reading(conn)) {
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

  if(options.User || options.Group) {
    if(switch_id(options.User, options.Group) != 0) {
      return -1;
    }
  }

  if (options.RunAsDaemon) {
    start_daemon(options.DataDirectory);
  }

  if(!options.LogFile && !options.RunAsDaemon)
    add_stream_log(options.loglevel, "<stdout>", stdout);
  if(options.LogFile) {
    if (add_file_log(options.loglevel, options.LogFile) != 0) {
      /* opening the log file failed!  Use stderr and log a warning */
      add_stream_log(options.loglevel, "<stderr>", stderr);
      log_fn(LOG_WARN, "Cannot write to LogFile '%s': %s.", options.LogFile, strerror(errno));
    }
    log_fn(LOG_NOTICE, "Successfully opened LogFile '%s', redirecting output.",
           options.LogFile);
  }
  if(options.DebugLogFile) {
    if (add_file_log(LOG_DEBUG, options.DebugLogFile) != 0)
      log_fn(LOG_WARN, "Cannot write to DebugLogFile '%s': %s.", options.DebugLogFile, strerror(errno));
    log_fn(LOG_DEBUG, "Successfully opened DebugLogFile '%s'.", options.DebugLogFile);
  }

  connection_bucket_init();
  stats_prev_global_read_bucket = global_read_bucket;

  if(options.RunAsDaemon) {
    /* XXXX Can we delay this any more? */
    finish_daemon();
  }

  /* write our pid to the pid file, if we do not have write permissions we will log a warning */
  if(options.PidFile)
    write_pidfile(options.PidFile);

  return 0;
}

static int do_hup(void) {
  char keydir[512];

  log_fn(LOG_NOTICE,"Received sighup. Reloading config.");
  has_completed_circuit=0;
  /* first, reload config variables, in case they've changed */
  /* no need to provide argc/v, they've been cached inside init_from_config */
  if (init_from_config(0, NULL) < 0) {
    exit(1);
  }
  if(retry_all_connections() < 0) {
    log_fn(LOG_ERR,"Failed to bind one of the listener ports.");
    return -1;
  }
  if(options.DirPort) {
    /* reload the approved-routers file */
    sprintf(keydir,"%s/approved-routers", options.DataDirectory);
    log_fn(LOG_INFO,"Reloading approved fingerprints from %s...",keydir);
    if(dirserv_parse_fingerprint_file(keydir) < 0) {
      log_fn(LOG_WARN, "Error reloading fingerprints. Continuing with old list.");
    }
  } else {
    /* fetch a new directory */
    directory_initiate_command(router_pick_directory_server(),
                               DIR_PURPOSE_FETCH_DIR, NULL, 0);
  }
  if(options.ORPort) {
    router_rebuild_descriptor();
    sprintf(keydir,"%s/router.desc", options.DataDirectory);
    log_fn(LOG_INFO,"Dumping descriptor to %s...",keydir);
    if (write_str_to_file(keydir, router_get_my_descriptor())) {
      return -1;
    }
  }
  return 0;
}

static int do_main_loop(void) {
  int i;
  int timeout;
  int poll_result;

  /* load the routers file */
  if(options.RouterFile &&
     router_set_routerlist_from_file(options.RouterFile) < 0) {
    log_fn(LOG_ERR,"Error loading router list.");
    return -1;
  }

  /* Initialize the history structures. */
  rep_hist_init();
  /* Intialize the service cache. */
  rend_cache_init();

  /* load the private keys, if we're supposed to have them, and set up the
   * TLS context. */
  if (init_keys() < 0 || rend_service_init_keys() < 0) {
    log_fn(LOG_ERR,"Error initializing keys; exiting");
    return -1;
  }

  if(options.DirPort) { /* the directory is already here, run startup things */
    has_fetched_directory = 1;
    directory_has_arrived();
  }

  if(options.ORPort) {
    cpu_init(); /* launch cpuworkers. Need to do this *after* we've read the onion key. */
    router_upload_dir_desc_to_dirservers(); /* upload our descriptor to all dirservers */
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
      do_hup();
      please_reset = 0;
    }
    if(please_reap_children) {
      while(waitpid(-1,NULL,WNOHANG)) ; /* keep reaping until no more zombies */
      please_reap_children = 0;
    }
#endif /* signal stuff */

    timeout = prepare_for_poll();

    /* poll until we have an event, or the second ends */
    poll_result = tor_poll(poll_array, nfds, timeout);

    /* let catch() handle things like ^c, and otherwise don't worry about it */
    if(poll_result < 0) {
      if(errno != EINTR) { /* let the program survive things like ^z */
        log_fn(LOG_ERR,"poll failed: %s",strerror(errno));
        return -1;
      } else {
        log_fn(LOG_DEBUG,"poll interrupted.");
      }
    }

    /* do all the reads and errors first, so we can detect closed sockets */
    for(i=0;i<nfds;i++)
      conn_read(i); /* this also marks broken connections */

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
    case SIGPIPE:
      log(LOG_WARN,"Bug: caught sigpipe. Ignoring.");
      break;
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
      i, conn->s, conn->type, CONN_TYPE_TO_STRING(conn->type),
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

  rep_hist_dump_stats(now,severity);
}

int network_init(void)
{
#ifdef MS_WINDOWS
  /* This silly exercise is necessary before windows will allow gethostbyname to work.
   */
  WSADATA WSAData;
  int r;
  r = WSAStartup(0x101,&WSAData);
  if (r) {
    log_fn(LOG_WARN,"Error initializing windows network layer: code was %d",r);
    return -1;
  }
  /* XXXX We should call WSACleanup on exit, I think. */
#endif
  return 0;
}

void exit_function(void)
{
#ifdef MS_WINDOWS
  WSACleanup();
#endif
}

int tor_main(int argc, char *argv[]) {

  /* give it somewhere to log to initially */
  add_stream_log(LOG_INFO, "<stdout>", stdout);
  log_fn(LOG_NOTICE,"Tor v%s. This is experimental software. Do not use it if you need anonymity.",VERSION);

  if (network_init()<0) {
    log_fn(LOG_ERR,"Error initializing network; exiting.");
    return 1;
  }
  atexit(exit_function);

  if (init_from_config(argc,argv) < 0)
    return -1;

#ifndef MS_WINDOWS
  if(geteuid()==0)
    log_fn(LOG_WARN,"You are running Tor as root. You don't need to, and you probably shouldn't.");
#endif

  if(options.ORPort) { /* only spawn dns handlers if we're a router */
    dns_init(); /* initialize the dns resolve tree, and spawn workers */
  }
  if(options.SocksPort) {
    client_dns_init(); /* init the client dns cache */
  }

#ifndef MS_WINDOWS /* do signal stuff only on unix */
{
  struct sigaction action;
  action.sa_flags = 0;
  sigemptyset(&action.sa_mask);

  action.sa_handler = catch;
  sigaction(SIGINT,  &action, NULL);
  sigaction(SIGTERM, &action, NULL);
  sigaction(SIGPIPE, &action, NULL);
  sigaction(SIGUSR1, &action, NULL);
  sigaction(SIGHUP,  &action, NULL); /* to reload config, retry conns, etc */
  sigaction(SIGCHLD, &action, NULL); /* handle dns/cpu workers that exit */
}
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
