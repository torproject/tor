/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file main.c
 * \brief Tor main loop and startup functions.
 **/

#include "or.h"

/********* PROTOTYPES **********/

static void dumpstats(int severity); /* log stats */
static int init_from_config(int argc, char **argv);

/********* START VARIABLES **********/

/* declared in connection.c */
extern char *conn_state_to_string[][_CONN_TYPE_MAX+1];

or_options_t options; /**< Command-line and config-file options. */
int global_read_bucket; /**< Max number of bytes I can read this second. */

/** What was the read bucket before the last call to prepare_for_pool?
 * (used to determine how many bytes we've read). */
static int stats_prev_global_read_bucket;
/** How many bytes have we read since we started the process? */
static uint64_t stats_n_bytes_read = 0;
/** How many seconds have we been running? */
long stats_n_seconds_uptime = 0;

/** Array of all open connections; each element corresponds to the element of
 * poll_array in the same position.  The first nfds elements are valid. */
static connection_t *connection_array[MAXCONNECTIONS] =
        { NULL };

/** Array of pollfd objects for calls to poll(). */
static struct pollfd poll_array[MAXCONNECTIONS];

static int nfds=0; /**< Number of connections currently active. */

#ifndef MS_WINDOWS /* do signal stuff only on unix */
static int please_dumpstats=0; /**< Whether we should dump stats during the loop. */
static int please_reset=0; /**< Whether we just got a sighup. */
static int please_reap_children=0; /**< Whether we should waitpid for exited children. */
static int please_shutdown=0; /**< Whether we should shut down Tor. */
#endif /* signal stuff */

/** We should exit if shutting_down != 0 and now <= shutting_down.
 * If it's non-zero, don't accept any new circuits or connections.
 * This gets assigned when we receive a sig_int, and if we receive a
 * second one we exit immediately. */
int shutting_down=0;
#define SHUTDOWN_WAIT_LENGTH 30 /* seconds */

/** We set this to 1 when we've fetched a dir, to know whether to complain
 * yet about unrecognized nicknames in entrynodes, exitnodes, etc.
 * Also, we don't try building circuits unless this is 1. */
int has_fetched_directory=0;

/** We set this to 1 when we've opened a circuit, so we can print a log
 * entry to inform the user that Tor is working. */
int has_completed_circuit=0;

#ifdef MS_WINDOWS
SERVICE_STATUS service_status;
SERVICE_STATUS_HANDLE hStatus;
#endif

/********* END VARIABLES ************/

/****************************************************************************
*
* This section contains accessors and other methods on the connection_array
* and poll_array variables (which are global within this file and unavailable
* outside it).
*
****************************************************************************/

/** Add <b>conn</b> to the array of connections that we can poll on.  The
 * connection's socket must be set; the connection starts out
 * non-reading and non-writing.
 */
int connection_add(connection_t *conn) {
  tor_assert(conn);
  tor_assert(conn->s >= 0);

  if(nfds >= options.MaxConn-1) {
    log_fn(LOG_WARN,"failing because nfds is too high.");
    return -1;
  }

  tor_assert(conn->poll_index == -1); /* can only connection_add once */
  conn->poll_index = nfds;
  connection_array[nfds] = conn;

  poll_array[nfds].fd = conn->s;

  /* zero these out here, because otherwise we'll inherit values from the previously freed one */
  poll_array[nfds].events = 0;
  poll_array[nfds].revents = 0;

  nfds++;

  log_fn(LOG_INFO,"new conn type %s, socket %d, nfds %d.",
      CONN_TYPE_TO_STRING(conn->type), conn->s, nfds);

  return 0;
}

/** Remove the connection from the global list, and remove the
 * corresponding poll entry.  Calling this function will shift the last
 * connection (if any) into the position occupied by conn.
 */
int connection_remove(connection_t *conn) {
  int current_index;

  tor_assert(conn);
  tor_assert(nfds>0);

  log_fn(LOG_INFO,"removing socket %d (type %s), nfds now %d",
         conn->s, CONN_TYPE_TO_STRING(conn->type), nfds-1);

  tor_assert(conn->poll_index >= 0);
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

/** Return true iff conn is in the current poll array. */
int connection_in_array(connection_t *conn) {
  int i;
  for (i=0; i<nfds; ++i) {
    if (conn==connection_array[i])
      return 1;
  }
  return 0;
}

/** Set <b>*array</b> to an array of all connections, and <b>*n</b>
 * to the length of the array. <b>*array</b> and <b>*n</b> must not
 * be modified.
 */
void get_connection_array(connection_t ***array, int *n) {
  *array = connection_array;
  *n = nfds;
}

/** Set the event mask on <b>conn</b> to <b>events</b>.  (The form of
* the event mask is as for poll().)
 */
void connection_watch_events(connection_t *conn, short events) {

  tor_assert(conn && conn->poll_index >= 0 && conn->poll_index < nfds);

  poll_array[conn->poll_index].events = events;
}

/** Return true iff <b>conn</b> is listening for read events. */
int connection_is_reading(connection_t *conn) {
  tor_assert(conn && conn->poll_index >= 0);
  return poll_array[conn->poll_index].events & POLLIN;
}

/** Tell the main loop to stop notifying <b>conn</b> of any read events. */
void connection_stop_reading(connection_t *conn) {
  tor_assert(conn && conn->poll_index >= 0 && conn->poll_index < nfds);

  log(LOG_DEBUG,"connection_stop_reading() called.");
  if(poll_array[conn->poll_index].events & POLLIN)
    poll_array[conn->poll_index].events -= POLLIN;
}

/** Tell the main loop to start notifying <b>conn</b> of any read events. */
void connection_start_reading(connection_t *conn) {
  tor_assert(conn && conn->poll_index >= 0 && conn->poll_index < nfds);
  poll_array[conn->poll_index].events |= POLLIN;
}

/** Return true iff <b>conn</b> is listening for write events. */
int connection_is_writing(connection_t *conn) {
  return poll_array[conn->poll_index].events & POLLOUT;
}

/** Tell the main loop to stop notifying <b>conn</b> of any write events. */
void connection_stop_writing(connection_t *conn) {
  tor_assert(conn && conn->poll_index >= 0 && conn->poll_index < nfds);
  if(poll_array[conn->poll_index].events & POLLOUT)
    poll_array[conn->poll_index].events -= POLLOUT;
}

/** Tell the main loop to start notifying <b>conn</b> of any write events. */
void connection_start_writing(connection_t *conn) {
  tor_assert(conn && conn->poll_index >= 0 && conn->poll_index < nfds);
  poll_array[conn->poll_index].events |= POLLOUT;
}

/** Called when the connection at connection_array[i] has a read event,
 * or it has pending tls data waiting to be read: checks for validity,
 * catches numerous errors, and dispatches to connection_handle_read.
 */
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
  assert_all_pending_dns_resolves_ok();

  if(
    /* XXX does POLLHUP also mean it's definitely broken? */
#ifdef MS_WINDOWS
    (poll_array[i].revents & POLLERR) ||
#endif
    connection_handle_read(conn) < 0) {
      if (!conn->marked_for_close) {
        /* this connection is broken. remove it */
        log_fn(LOG_WARN,"Unhandled error on read for %s connection (fd %d); removing",
               CONN_TYPE_TO_STRING(conn->type), conn->s);
        connection_mark_for_close(conn);
      }
  }
  assert_connection_ok(conn, time(NULL));
  assert_all_pending_dns_resolves_ok();
}

/** Called when the connection at connection_array[i] has a write event:
 * checks for validity, catches numerous errors, and dispatches to
 * connection_handle_write.
 */
static void conn_write(int i) {
  connection_t *conn;

  if(!(poll_array[i].revents & POLLOUT))
    return; /* this conn doesn't want to write */

  conn = connection_array[i];
  log_fn(LOG_DEBUG,"socket %d wants to write.",conn->s);
  if (conn->marked_for_close)
    return;

  assert_connection_ok(conn, time(NULL));
  assert_all_pending_dns_resolves_ok();

  if (connection_handle_write(conn) < 0) {
    if (!conn->marked_for_close) {
      /* this connection is broken. remove it. */
      log_fn(LOG_WARN,"Unhandled error on read for %s connection (fd %d); removing",
             CONN_TYPE_TO_STRING(conn->type), conn->s);
      conn->has_sent_end = 1; /* otherwise we cry wolf about duplicate close */
      /* XXX do we need a close-immediate here, so we don't try to flush? */
      connection_mark_for_close(conn);
    }
  }
  assert_connection_ok(conn, time(NULL));
  assert_all_pending_dns_resolves_ok();
}

/** If the connection at connection_array[i] is marked for close, then:
 *    - If it has data that it wants to flush, try to flush it.
 *    - If it _still_ has data to flush, and conn->hold_open_until_flushed is
 *      true, then leave the connection open and return.
 *    - Otherwise, remove the connection from connection_array and from
 *      all other lists, close it, and free it.
 * If we remove the connection, then call conn_closed_if_marked at the new
 * connection at position i.
 */
static void conn_close_if_marked(int i) {
  connection_t *conn;
  int retval;

  conn = connection_array[i];
  assert_connection_ok(conn, time(NULL));
  assert_all_pending_dns_resolves_ok();
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
  /* if it's an edge conn, remove it from the list
   * of conn's on this circuit. If it's not on an edge,
   * flush and send destroys for all circuits on this conn
   */
  circuit_about_to_close_connection(conn);
  connection_about_to_close_connection(conn);
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

/** This function is called whenever we successfully pull down a directory */
void directory_has_arrived(void) {

  log_fn(LOG_INFO, "A directory has arrived.");

  has_fetched_directory=1;

  if(clique_mode()) { /* connect to them all */
    router_retry_connections();
  }
}

/** Perform regular maintenance tasks for a single connection.  This
 * function gets run once per second per connection by run_housekeeping.
 */
static void run_connection_housekeeping(int i, time_t now) {
  cell_t cell;
  connection_t *conn = connection_array[i];

  /* Expire any directory connections that haven't sent anything for 5 min */
  if(conn->type == CONN_TYPE_DIR &&
     !conn->marked_for_close &&
     conn->timestamp_lastwritten + 5*60 < now) {
    log_fn(LOG_INFO,"Expiring wedged directory conn (fd %d, purpose %d)", conn->s, conn->purpose);
    connection_mark_for_close(conn);
    return;
  }

  /* If we haven't written to an OR connection for a while, then either nuke
     the connection or send a keepalive, depending. */
  if(connection_speaks_cells(conn) &&
     now >= conn->timestamp_lastwritten + options.KeepalivePeriod) {
    routerinfo_t *router = router_get_by_digest(conn->identity_digest);
    if((!connection_state_is_open(conn)) ||
       (!clique_mode() && !circuit_get_by_conn(conn) &&
       (!router || !server_mode() || !router_is_clique_mode(router)))) {
      /* our handshake has expired;
       * or we're not an authdirserver, we have no circuits, and
       *   either he's an OP, we're an OP, or we're both ORs and he's
       *   running 0.0.8 and he's not an authdirserver,
       * then kill it. */
      log_fn(LOG_INFO,"Expiring connection to %d (%s:%d).",
             i,conn->address, conn->port);
      /* flush anything waiting, e.g. a destroy for a just-expired circ */
      connection_mark_for_close(conn);
      conn->hold_open_until_flushed = 1;
    } else {
      /* either in clique mode, or we've got a circuit. send a padding cell. */
      log_fn(LOG_DEBUG,"Sending keepalive to (%s:%d)",
             conn->address, conn->port);
      memset(&cell,0,sizeof(cell_t));
      cell.command = CELL_PADDING;
      connection_or_write_cell_to_buf(&cell, conn);
    }
  }
}

#define MIN_BW_TO_PUBLISH_DESC 5000 /* 5000 bytes/s sustained */
#define MIN_UPTIME_TO_PUBLISH_DESC (30*60) /* half an hour */

/** Decide if we're a publishable server or just a client. We are a server if:
 * - We have the AuthoritativeDirectory option set.
 * or
 * - We don't have the ClientOnly option set; and
 * - We have ORPort set; and
 * - We have been up for at least MIN_UPTIME_TO_PUBLISH_DESC seconds; and
 * - We have processed some suitable minimum bandwidth recently; and
 * - We believe we are reachable from the outside.
 */
static int decide_if_publishable_server(time_t now) {
  int r;

  if(options.ClientOnly)
    return 0;
  if(!options.ORPort)
    return 0;


  /* XXX008 for now, you're only a server if you're a server */
  return server_mode();


  /* here, determine if we're reachable */
  if(0) { /* we've recently failed to reach our IP/ORPort from the outside */
    return 0;
  }

  r = rep_hist_bandwidth_assess(now);


//  set_advertised_bandwidth(r);

  if(r < MIN_BW_TO_PUBLISH_DESC)
    return 0;
  if(options.AuthoritativeDir)
    return 1;
  if(stats_n_seconds_uptime < MIN_UPTIME_TO_PUBLISH_DESC)
    return 0;

  return 1;
}

/** Return true iff we believe ourselves to be an authoritative
 * directory server.
 */
int authdir_mode(void) {
  return (options.AuthoritativeDir != 0);
}

/** Return true iff we try to stay connected to all ORs at once.
 */
int clique_mode(void) {
  return authdir_mode();
}

/** Return true iff we are trying to be a server.
 */
int server_mode(void) {
  return (options.ORPort != 0);
}

/** Return true iff we have published our descriptor lately.
 */
int advertised_server_mode(void) {
  return (options.ORPort != 0);
}

/** Return true iff we are trying to be a socks proxy. */
int proxy_mode(void) {
  return (options.SocksPort != 0);
}

/** Perform regular maintenance tasks.  This function gets run once per
 * second by prepare_for_poll.
 */
static void run_scheduled_events(time_t now) {
  static long time_to_fetch_directory = 0;
  static time_t last_uploaded_services = 0;
  static time_t last_rotated_certificate = 0;
  int i;

  /** 0. See if we've been asked to shut down and our timeout has
   * expired. If so, exit now.
   */
  if(shutting_down && shutting_down <= now) {
    log(LOG_NOTICE,"Clean shutdown finished. Exiting.");
    exit(0);
  }

  /** 1a. Every MIN_ONION_KEY_LIFETIME seconds, rotate the onion keys,
   *  shut down and restart all cpuworkers, and update the directory if
   *  necessary.
   */
  if (server_mode() && get_onion_key_set_at()+MIN_ONION_KEY_LIFETIME < now) {
    log_fn(LOG_INFO,"Rotating onion key.");
    rotate_onion_key();
    cpuworkers_rotate();
    if (router_rebuild_descriptor()<0) {
      log_fn(LOG_WARN, "Couldn't rebuild router descriptor");
    }
    /* XXX008 only if advertised_server_mode */
    router_upload_dir_desc_to_dirservers();
  }

  /** 1b. Every MAX_SSL_KEY_LIFETIME seconds, we change our TLS context. */
  if (!last_rotated_certificate)
    last_rotated_certificate = now;
  /*XXXX008 we should remove the server_mode() check once OPs also use
   * identity keys (which they can't do until the known-router check in
   * connection_or.c is removed. */
  if (server_mode() && last_rotated_certificate+MAX_SSL_KEY_LIFETIME < now) {
    log_fn(LOG_INFO,"Rotating tls context.");
    if (tor_tls_context_new(get_identity_key(), 1, options.Nickname,
                            MAX_SSL_KEY_LIFETIME) < 0) {
      log_fn(LOG_WARN, "Error reinitializing TLS context");
    }
    last_rotated_certificate = now;
    /* XXXX We should rotate TLS connections as well; this code doesn't change
     * XXXX them at all. */
  }

  /** 2. Every DirFetchPostPeriod seconds, we get a new directory and upload
   *    our descriptor (if we've passed our internal checks). */
  if(time_to_fetch_directory < now) {

    if(decide_if_publishable_server(now)) {
      router_rebuild_descriptor();
      router_upload_dir_desc_to_dirservers();
    }

    routerlist_remove_old_routers(); /* purge obsolete entries */

    if(authdir_mode()) {
      /* We're a directory; dump any old descriptors. */
      dirserv_remove_old_servers();
      /* dirservers try to reconnect, in case connections have failed */
      router_retry_connections();
    }

    directory_get_from_dirserver(DIR_PURPOSE_FETCH_DIR, NULL, 0);

    /* Force an upload of our rend descriptors every DirFetchPostPeriod seconds. */
    rend_services_upload(1);
    last_uploaded_services = now;
    rend_cache_clean(); /* should this go elsewhere? */

    time_to_fetch_directory = now + options.DirFetchPostPeriod;
  }

  /** 3a. Every second, we examine pending circuits and prune the
   *    ones which have been pending for more than a few seconds.
   *    We do this before step 3, so it can try building more if
   *    it's not comfortable with the number of available circuits.
   */
  circuit_expire_building(now);

  /** 3b. Also look at pending streams and prune the ones that 'began'
   *     a long time ago but haven't gotten a 'connected' yet.
   *     Do this before step 3, so we can put them back into pending
   *     state to be picked up by the new circuit.
   */
  connection_ap_expire_beginning();


  /** 3c. And expire connections that we've held open for too long.
   */
  connection_expire_held_open();

  /** 4. Every second, we try a new circuit if there are no valid
   *    circuits. Every NewCircuitPeriod seconds, we expire circuits
   *    that became dirty more than NewCircuitPeriod seconds ago,
   *    and we make a new circ if there are no clean circuits.
   */
  if(has_fetched_directory)
    circuit_build_needed_circs(now);

  /** 5. We do housekeeping for each connection... */
  for(i=0;i<nfds;i++) {
    run_connection_housekeeping(i, now);
  }

  /** 6. And remove any marked circuits... */
  circuit_close_all_marked();

  /** 7. And upload service descriptors for any services whose intro points
   *    have changed in the last second. */
  if (last_uploaded_services < now-5) {
    rend_services_upload(0);
    last_uploaded_services = now;
  }

  /** 8. and blow away any connections that need to die. have to do this now,
   * because if we marked a conn for close and left its socket -1, then
   * we'll pass it to poll/select and bad things will happen.
   */
  for(i=0;i<nfds;i++)
    conn_close_if_marked(i);
}

/** Called every time we're about to call tor_poll.  Increments statistics,
 * and adjusts token buckets.  Returns the number of milliseconds to use for
 * the poll() timeout.
 */
static int prepare_for_poll(void) {
  static long current_second = 0; /* from previous calls to gettimeofday */
  connection_t *conn;
  struct timeval now;
  int i;

  tor_gettimeofday(&now);

  /* Check how much bandwidth we've consumed, and increment the token
   * buckets. */
  stats_n_bytes_read += stats_prev_global_read_bucket - global_read_bucket;
  connection_bucket_refill(&now);
  stats_prev_global_read_bucket = global_read_bucket;

  if(now.tv_sec > current_second) { /* the second has rolled over. check more stuff. */

    if(current_second)
      stats_n_seconds_uptime += (now.tv_sec - current_second);
    assert_all_pending_dns_resolves_ok();
    run_scheduled_events(now.tv_sec);
    assert_all_pending_dns_resolves_ok();

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

/** Configure the Tor process from the command line arguments and from the
 * configuration file.
 */
static int init_from_config(int argc, char **argv) {
  /* read the configuration file. */
  if(getconfig(argc,argv,&options)) {
    log_fn(LOG_ERR,"Reading config failed. For usage, try -h.");
    return -1;
  }

  /* Setuid/setgid as appropriate */
  if(options.User || options.Group) {
    if(switch_id(options.User, options.Group) != 0) {
      return -1;
    }
  }

  /* Ensure data directory is private; create if possible. */
  if (check_private_dir(get_data_directory(&options), 1) != 0) {
    log_fn(LOG_ERR, "Couldn't access/create private data directory %s",
           get_data_directory(&options));
    return -1;
  }

  /* Start backgrounding the process, if requested. */
  if (options.RunAsDaemon) {
    start_daemon(get_data_directory(&options));
  }

  /* Configure the log(s) */
  if (config_init_logs(&options)<0)
    return -1;
  /* Close the temporary log we used while starting up, if it isn't already
   * gone. */
  close_temp_logs();

  /* Set up our buckets */
  connection_bucket_init();
  stats_prev_global_read_bucket = global_read_bucket;

  /* Finish backgrounding the process */
  if(options.RunAsDaemon) {
    /* XXXX Can we delay this any more? */
    finish_daemon();
  }

  /* Write our pid to the pid file. If we do not have write permissions we
   * will log a warning */
  if(options.PidFile)
    write_pidfile(options.PidFile);

  return 0;
}

/** Called when we get a SIGHUP: reload configuration files and keys,
 * retry all connections, re-upload all descriptors, and so on. */
static int do_hup(void) {
  char keydir[512];

  log_fn(LOG_NOTICE,"Received sighup. Reloading config.");
  has_completed_circuit=0;
  mark_logs_temp(); /* Close current logs once new logs are open. */
  /* first, reload config variables, in case they've changed */
  /* no need to provide argc/v, they've been cached inside init_from_config */
  if (init_from_config(0, NULL) < 0) {
    exit(1);
  }
  /* reload keys as needed for rendezvous services. */
  if (rend_service_load_keys()<0) {
    log_fn(LOG_ERR,"Error reloading rendezvous service keys");
    exit(1);
  }
  if(retry_all_listeners() < 0) {
    log_fn(LOG_ERR,"Failed to bind one of the listener ports.");
    return -1;
  }
  if(authdir_mode()) {
    /* reload the approved-routers file */
    sprintf(keydir,"%s/approved-routers", get_data_directory(&options));
    log_fn(LOG_INFO,"Reloading approved fingerprints from %s...",keydir);
    if(dirserv_parse_fingerprint_file(keydir) < 0) {
      log_fn(LOG_WARN, "Error reloading fingerprints. Continuing with old list.");
    }
    /* Since we aren't fetching a directory, we won't retry rendezvous points
     * when it gets in.  Try again now. */
    rend_services_introduce();
  }
  /* Fetch a new directory. Even authdirservers do this. */
  directory_get_from_dirserver(DIR_PURPOSE_FETCH_DIR, NULL, 0);
  if(server_mode()) {
    /* Restart cpuworker and dnsworker processes, so they get up-to-date
     * configuration options. */
    cpuworkers_rotate();
    if (server_mode())
      dnsworkers_rotate();
    /* Rebuild fresh descriptor as needed. */
    router_rebuild_descriptor();
    sprintf(keydir,"%s/router.desc", get_data_directory(&options));
    log_fn(LOG_INFO,"Dumping descriptor to %s...",keydir);
    if (write_str_to_file(keydir, router_get_my_descriptor())) {
      return -1;
    }
  }
  return 0;
}

/** Tor main loop. */
static int do_main_loop(void) {
  int i;
  int timeout;
  int poll_result;

  /* Initialize the history structures. */
  rep_hist_init();
  /* Intialize the service cache. */
  rend_cache_init();

  /* load the private keys, if we're supposed to have them, and set up the
   * TLS context. */
  if (init_keys() < 0 || rend_service_load_keys() < 0) {
    log_fn(LOG_ERR,"Error initializing keys; exiting");
    return -1;
  }

  /* load the routers file */
  if(options.RouterFile) {
    routerlist_clear_trusted_directories();
    if (router_load_routerlist_from_file(options.RouterFile, 1) < 0) {
      log_fn(LOG_ERR,"Error loading router list.");
      return -1;
    }
  }

  if(authdir_mode()) {
    /* the directory is already here, run startup things */
    directory_has_arrived();
  }

  if(server_mode()) {
    /* launch cpuworkers. Need to do this *after* we've read the onion key. */
    cpu_init();
  }

  /* start up the necessary listeners based on which ports are non-zero. */
  if(retry_all_listeners() < 0) {
    log_fn(LOG_ERR,"Failed to bind one of the listener ports.");
    return -1;
  }

  for(;;) {
#ifdef MS_WINDOWS /* Do service stuff only on windows. */
        if (service_status.dwCurrentState != SERVICE_RUNNING) {
      return 0;
    }
#else /* do signal stuff only on unix */
    if(please_shutdown) {
      if(shutting_down) { /* we've already been asked. do it now. */
        log(LOG_NOTICE,"Second sigint received; exiting now.");
        exit(0);
      } else {
        log(LOG_NOTICE,"Interrupt: will shut down in %d seconds. Interrupt again to exit now.", SHUTDOWN_WAIT_LENGTH);
        shutting_down = time(NULL) + SHUTDOWN_WAIT_LENGTH;
      }
      please_shutdown = 0;
    }
    if(please_dumpstats) {
      /* prefer to log it at INFO, but make sure we always see it */
      dumpstats(get_min_log_level()>LOG_INFO ? get_min_log_level() : LOG_INFO);
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
      /* let the program survive things like ^z */
      if(tor_socket_errno(-1) != EINTR) {
        log_fn(LOG_ERR,"poll failed: %s [%d]",
               tor_socket_strerror(tor_socket_errno(-1)),
               tor_socket_errno(-1));
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

/** Unix signal handler. */
static void catch(int the_signal) {

#ifndef MS_WINDOWS /* do signal stuff only on unix */
  switch(the_signal) {
//    case SIGABRT:
    case SIGTERM:
      log(LOG_ERR,"Catching signal %d, exiting cleanly.", the_signal);
      exit(0);
    case SIGINT:
      please_shutdown = 1;
      break;
    case SIGPIPE:
      log(LOG_NOTICE,"Caught sigpipe. Ignoring.");
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

/** Write all statistics to the log, with log level 'severity'.  Called
 * in response to a SIGUSR1. */
static void dumpstats(int severity) {
  int i;
  connection_t *conn;
  time_t now = time(NULL);

  log(severity, "Dumping stats:");

  for(i=0;i<nfds;i++) {
    conn = connection_array[i];
    log(severity, "Conn %d (socket %d) type %d (%s), state %d (%s), created %d secs ago",
      i, conn->s, conn->type, CONN_TYPE_TO_STRING(conn->type),
      conn->state, conn_state_to_string[conn->type][conn->state], (int)(now - conn->timestamp_created));
    if(!connection_is_listener(conn)) {
      log(severity,"Conn %d is to '%s:%d'.",i,conn->address, conn->port);
      log(severity,"Conn %d: %d bytes waiting on inbuf (last read %d secs ago)",i,
             (int)buf_datalen(conn->inbuf),
             (int)(now - conn->timestamp_lastread));
      log(severity,"Conn %d: %d bytes waiting on outbuf (last written %d secs ago)",i,
             (int)buf_datalen(conn->outbuf), (int)(now - conn->timestamp_lastwritten));
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

  if (stats_n_seconds_uptime)
    log(severity,"Average bandwidth used: %d bytes/sec",
           (int) (stats_n_bytes_read/stats_n_seconds_uptime));

  rep_hist_dump_stats(now,severity);
  rend_service_dump_stats(severity);
}

/** Called before we make any calls to network-related functions.
 * (Some operating systems require their network libraries to be
 * initialized.) */
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

/** Called by exit() as we shut down the process.
 */
void exit_function(void)
{
  /* Remove our pid file. We don't care if there was an error when we
   * unlink, nothing we could do about it anyways. */
  if(options.PidFile)
    unlink(options.PidFile);
#ifdef MS_WINDOWS
  WSACleanup();
#endif
}

/** Main entry point for the Tor command-line client.
 */
int tor_init(int argc, char *argv[]) {

  /* give it somewhere to log to initially */
  add_temp_log();
  log_fn(LOG_NOTICE,"Tor v%s. This is experimental software. Do not use it if you need anonymity.",VERSION);

  if (network_init()<0) {
    log_fn(LOG_ERR,"Error initializing network; exiting.");
    return -1;
  }
  atexit(exit_function);

  if (init_from_config(argc,argv) < 0)
    return -1;

#ifndef MS_WINDOWS
  if(geteuid()==0)
    log_fn(LOG_WARN,"You are running Tor as root. You don't need to, and you probably shouldn't.");
#endif

  if(server_mode()) { /* only spawn dns handlers if we're a router */
    dns_init(); /* initialize the dns resolve tree, and spawn workers */
  }
  if(proxy_mode()) {
    client_dns_init(); /* init the client dns cache */
  }

#ifndef MS_WINDOWS /* do signal stuff only on unix */
{
  struct sigaction action;
  action.sa_flags = 0;
  sigemptyset(&action.sa_mask);

  action.sa_handler = catch;
  sigaction(SIGINT,  &action, NULL); /* do a controlled slow shutdown */
  sigaction(SIGTERM, &action, NULL); /* to terminate now */
  sigaction(SIGPIPE, &action, NULL); /* otherwise sigpipe kills us */
  sigaction(SIGUSR1, &action, NULL); /* dump stats */
  sigaction(SIGHUP,  &action, NULL); /* to reload config, retry conns, etc */
  sigaction(SIGCHLD, &action, NULL); /* handle dns/cpu workers that exit */
}
#endif /* signal stuff */

  crypto_global_init();
  crypto_seed_rng();
  return 0;
}

void tor_cleanup(void) {
  crypto_global_cleanup();
}

#ifdef MS_WINDOWS
void nt_service_control(DWORD request)
{
  switch (request) {
    case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
          log(LOG_ERR, "Got stop/shutdown request; shutting down cleanly.");
      service_status.dwWin32ExitCode = 0;
          service_status.dwCurrentState = SERVICE_STOPPED;
          return;
  }
  SetServiceStatus(hStatus, &service_status);     
}

void nt_service_body(int argc, char **argv)
{
  int err;
  FILE *f;
  f = fopen("d:\\foo.txt", "w");
  fprintf(f, "POINT 1\n");
  fclose(f);
  service_status.dwServiceType = SERVICE_WIN32;
  service_status.dwCurrentState = SERVICE_START_PENDING;
  service_status.dwControlsAccepted = 
        SERVICE_ACCEPT_STOP |
                SERVICE_ACCEPT_SHUTDOWN;
  service_status.dwWin32ExitCode = 0;
  service_status.dwServiceSpecificExitCode = 0;
  service_status.dwCheckPoint = 0;
  service_status.dwWaitHint = 0;
  hStatus = RegisterServiceCtrlHandler("Tor", (LPHANDLER_FUNCTION) nt_service_control);
  if (hStatus == 0) {
        // failed;
        return;
  }
  err = tor_init(argc, argv); // refactor this part out of tor_main and do_main_loop
  if (err) {
        // failed.
        service_status.dwCurrentState = SERVICE_STOPPED;
        service_status.dwWin32ExitCode = -1;
    SetServiceStatus(hStatus, &service_status);
        return;
  }
  service_status.dwCurrentState = SERVICE_RUNNING;
  SetServiceStatus(hStatus, &service_status);
  do_main_loop();
  tor_cleanup();
  return;
}

void nt_service_main(void)
{
  SERVICE_TABLE_ENTRY table[2];
  table[0].lpServiceName = "Tor";
  table[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)nt_service_body;
  table[1].lpServiceName = NULL;
  table[1].lpServiceProc = NULL;
  if (!StartServiceCtrlDispatcher(table))
          printf("Error was %d\n",GetLastError());
}
#endif

int tor_main(int argc, char *argv[]) {
#ifdef MS_WINDOWS_SERVICE
  nt_service_main();
  return 0;
#else
  if (tor_init(argc, argv)<0)
    return -1;
  do_main_loop();
  tor_cleanup();
  return -1;
#endif
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
