/* Copyright 2001 Matej Pfajfar.
 * Copyright 2001-2004 Roger Dingledine.
 * Copyright 2004 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char main_c_id[] = "$Id$";

/**
 * \file main.c
 * \brief Tor main loop and startup functions.
 **/

#include "or.h"

/* These signals are defined to help control_signal_act work. */
#ifndef SIGHUP
#define SIGHUP 1
#endif
#ifndef SIGINT
#define SIGINT 2
#endif
#ifndef SIGUSR1
#define SIGUSR1 10
#endif
#ifndef SIGUSR2
#define SIGUSR2 12
#endif
#ifndef SIGTERM
#define SIGTERM 15
#endif

/********* PROTOTYPES **********/

static void dumpstats(int severity); /* log stats */
static void conn_read_callback(int fd, short event, void *_conn);
static void conn_write_callback(int fd, short event, void *_conn);
static void signal_callback(int fd, short events, void *arg);
static void second_elapsed_callback(int fd, short event, void *args);
static int conn_close_if_marked(int i);

/********* START VARIABLES **********/

int global_read_bucket; /**< Max number of bytes I can read this second. */
int global_write_bucket; /**< Max number of bytes I can write this second. */

/** What was the read bucket before the last call to prepare_for_pool?
 * (used to determine how many bytes we've read). */
static int stats_prev_global_read_bucket;
/** What was the write bucket before the last call to prepare_for_pool?
 * (used to determine how many bytes we've written). */
static int stats_prev_global_write_bucket;
/** How many bytes have we read/written since we started the process? */
static uint64_t stats_n_bytes_read = 0;
static uint64_t stats_n_bytes_written = 0;
/** What time did this process start up? */
long time_of_process_start = 0;
/** How many seconds have we been running? */
long stats_n_seconds_working = 0;
/** When do we next download a directory? */
static time_t time_to_fetch_directory = 0;
/** When do we next upload our descriptor? */
static time_t time_to_force_upload_descriptor = 0;
/** When do we next download a running-routers summary? */
static time_t time_to_fetch_running_routers = 0;

/** Array of all open connections; each element corresponds to the element of
 * poll_array in the same position.  The first nfds elements are valid. */
static connection_t *connection_array[MAXCONNECTIONS] =
        { NULL };
static smartlist_t *closeable_connection_lst = NULL;

static int nfds=0; /**< Number of connections currently active. */

/** We set this to 1 when we've fetched a dir, to know whether to complain
 * yet about unrecognized nicknames in entrynodes, exitnodes, etc.
 * Also, we don't try building circuits unless this is 1. */
int has_fetched_directory=0;

/** We set this to 1 when we've opened a circuit, so we can print a log
 * entry to inform the user that Tor is working. */
int has_completed_circuit=0;

/* #define MS_WINDOWS_SERVICE */
#ifdef MS_WINDOWS_SERVICE
#include <tchar.h>
#define GENSRV_SERVICENAME  TEXT("tor-"VERSION)
#define GENSRV_DISPLAYNAME  TEXT("Tor "VERSION" Win32 Service")
SERVICE_STATUS service_status;
SERVICE_STATUS_HANDLE hStatus;
static char **backup_argv;
static int backup_argc;
#endif

#define CHECK_DESCRIPTOR_INTERVAL 60

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

  if (nfds >= get_options()->MaxConn-1) {
    log_fn(LOG_WARN,"failing because nfds is too high.");
    return -1;
  }

  tor_assert(conn->poll_index == -1); /* can only connection_add once */
  conn->poll_index = nfds;
  connection_array[nfds] = conn;

  conn->read_event = tor_malloc_zero(sizeof(struct event));
  conn->write_event = tor_malloc_zero(sizeof(struct event));
  event_set(conn->read_event, conn->s, EV_READ|EV_PERSIST,
            conn_read_callback, conn);
  event_set(conn->write_event, conn->s, EV_WRITE|EV_PERSIST,
            conn_write_callback, conn);

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
  if (current_index == nfds-1) { /* this is the end */
    nfds--;
    return 0;
  }

  if (conn->read_event) {
    event_del(conn->read_event);
    tor_free(conn->read_event);
  }
  if (conn->write_event) {
    event_del(conn->write_event);
    tor_free(conn->write_event);
  }

  /* replace this one with the one at the end */
  nfds--;
  connection_array[current_index] = connection_array[nfds];
  connection_array[current_index]->poll_index = current_index;

  return 0;
}

/** DOCDOC **/
void
add_connection_to_closeable_list(connection_t *conn)
{
  tor_assert(!smartlist_isin(closeable_connection_lst, conn));
  tor_assert(conn->marked_for_close);

  smartlist_add(closeable_connection_lst, conn);
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
* the event mask is DOCDOC)
 */
void connection_watch_events(connection_t *conn, short events) {
  tor_assert(conn);
  tor_assert(conn->read_event);
  tor_assert(conn->write_event);

  if (events & EV_READ) {
    event_add(conn->read_event, NULL);
  } else {
    event_del(conn->read_event);
  }

  if (events & EV_WRITE) {
    event_add(conn->write_event, NULL);
  } else {
    event_del(conn->write_event);
  }
}

/** Return true iff <b>conn</b> is listening for read events. */
int connection_is_reading(connection_t *conn) {
  tor_assert(conn);

  /* This isn't 100% documented, but it should work. */
  return conn->read_event &&
    (conn->read_event->ev_flags & (EVLIST_INSERTED|EVLIST_ACTIVE));
}

/** Tell the main loop to stop notifying <b>conn</b> of any read events. */
void connection_stop_reading(connection_t *conn) {
  tor_assert(conn);
  tor_assert(conn->read_event);

  log(LOG_DEBUG,"connection_stop_reading() called.");
  event_del(conn->read_event);
}

/** Tell the main loop to start notifying <b>conn</b> of any read events. */
void connection_start_reading(connection_t *conn) {
  tor_assert(conn);
  tor_assert(conn->read_event);

  event_add(conn->read_event, NULL);
}

/** Return true iff <b>conn</b> is listening for write events. */
int connection_is_writing(connection_t *conn) {
  tor_assert(conn);

  /* This isn't 100% documented, but it should work. */
  return conn->write_event &&
    (conn->write_event->ev_flags & (EVLIST_INSERTED|EVLIST_ACTIVE));
}

/** Tell the main loop to stop notifying <b>conn</b> of any write events. */
void connection_stop_writing(connection_t *conn) {
  tor_assert(conn);
  tor_assert(conn->write_event);

  event_del(conn->write_event);
}

/** Tell the main loop to start notifying <b>conn</b> of any write events. */
void connection_start_writing(connection_t *conn) {
  tor_assert(conn);
  tor_assert(conn->write_event);

  event_add(conn->write_event, NULL);
}

/** DOCDOC */
static void
close_closeable_connections(void)
{
  int i;
  if (!smartlist_len(closeable_connection_lst))
    return;

  for (i = 0; i < smartlist_len(closeable_connection_lst); ) {
    connection_t *conn = smartlist_get(closeable_connection_lst, i);
    if (!conn_close_if_marked(conn->poll_index))
      ++i;
  }
}

/** DOCDOC */
static void
conn_read_callback(int fd, short event, void *_conn)
{
  connection_t *conn = _conn;
  if (conn->marked_for_close)
    return;

  log_fn(LOG_DEBUG,"socket %d wants to read.",conn->s);

  assert_connection_ok(conn, time(NULL));
  assert_all_pending_dns_resolves_ok();

  if (connection_handle_read(conn) < 0) {
    if (!conn->marked_for_close) {
#ifndef MS_WINDOWS
      log_fn(LOG_WARN,"Bug: unhandled error on read for %s connection (fd %d); removing",
             CONN_TYPE_TO_STRING(conn->type), conn->s);
#endif
      connection_mark_for_close(conn);
    }
  }
  assert_connection_ok(conn, time(NULL));
  assert_all_pending_dns_resolves_ok();

  if (smartlist_len(closeable_connection_lst))
    close_closeable_connections();
}

static void conn_write_callback(int fd, short events, void *_conn)
{
  connection_t *conn = _conn;

  log_fn(LOG_DEBUG,"socket %d wants to write.",conn->s);
  if (conn->marked_for_close)
    return;

  assert_connection_ok(conn, time(NULL));
  assert_all_pending_dns_resolves_ok();

  if (connection_handle_write(conn) < 0) {
    if (!conn->marked_for_close) {
      /* this connection is broken. remove it. */
      log_fn(LOG_WARN,"Bug: unhandled error on write for %s connection (fd %d); removing",
             CONN_TYPE_TO_STRING(conn->type), conn->s);
      conn->has_sent_end = 1; /* otherwise we cry wolf about duplicate close */
      /* XXX do we need a close-immediate here, so we don't try to flush? */
      connection_mark_for_close(conn);
    }
  }
  assert_connection_ok(conn, time(NULL));
  assert_all_pending_dns_resolves_ok();

  if (smartlist_len(closeable_connection_lst))
    close_closeable_connections();
}

#if 0
static void conn_read(int i) {
  connection_t *conn = connection_array[i];

  if (conn->marked_for_close)
    return;

  /* post 0.0.9, sometimes we get into loops like:
Jan 06 13:54:14.999 [debug] connection_consider_empty_buckets(): global bucket exhausted. Pausing.
Jan 06 13:54:14.999 [debug] connection_stop_reading() called.
Jan 06 13:54:14.999 [debug] conn_read(): socket 14 wants to read.
Jan 06 13:54:14.999 [debug] connection_consider_empty_buckets(): global bucket exhausted. Pausing.
...
  We finish the loop after a couple of seconds go by, but nothing seems
  to happen during the loop except tight looping over poll. Perhaps the
  tls buffer has pending bytes but we don't allow ourselves to read them?
  */

  /* see http://www.greenend.org.uk/rjk/2001/06/poll.html for
   * discussion of POLLIN vs POLLHUP */
  if (!(poll_array[i].revents & (POLLIN|POLLHUP|POLLERR)))
    /* Sometimes read events get triggered for things that didn't ask
     * for them (XXX due to unknown poll wonkiness) and sometime we
     * want to read even though there was no read event (due to
     * pending TLS data).
     */

    /* XXX Post 0.0.9, we should rewrite this whole if statement;
     * something sane may result.  Nick suspects that the || below
     * should be a &&.
     *
     * No, it should remain a ||. Here's why: when we reach the end
     * of a read bucket, we stop reading on a conn. We don't want to
     * read any more bytes on it, until we're allowed to resume reading.
     * So if !connection_is_reading, then return right then. Also, if
     * poll() said nothing (true because the if above), and there's
     * nothing pending, then also return because nothing to do.
     *
     * If poll *does* have something to say, even though
     * !connection_is_reading, then we want to handle it in connection.c
     * to make it stop reading for next time, else we loop.
     */
    if (!connection_is_reading(conn) ||
        !connection_has_pending_tls_data(conn))
      return; /* this conn should not read */

  log_fn(LOG_DEBUG,"socket %d wants to read.",conn->s);

  assert_connection_ok(conn, time(NULL));
  assert_all_pending_dns_resolves_ok();

  if (
    /* XXX does POLLHUP also mean it's definitely broken? */
#ifdef MS_WINDOWS
      (poll_array[i].revents & POLLERR) ||
#endif
      connection_handle_read(conn) < 0) {
    if (!conn->marked_for_close) {
      /* this connection is broken. remove it */
#ifndef MS_WINDOWS
      log_fn(LOG_WARN,"Bug: unhandled error on read for %s connection (fd %d); removing",
             CONN_TYPE_TO_STRING(conn->type), conn->s);
#endif
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

  if (!(poll_array[i].revents & POLLOUT))
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
      log_fn(LOG_WARN,"Bug: unhandled error on write for %s connection (fd %d); removing",
             CONN_TYPE_TO_STRING(conn->type), conn->s);
      conn->has_sent_end = 1; /* otherwise we cry wolf about duplicate close */
      /* XXX do we need a close-immediate here, so we don't try to flush? */
      connection_mark_for_close(conn);
    }
  }
  assert_connection_ok(conn, time(NULL));
  assert_all_pending_dns_resolves_ok();
}
#endif

/** If the connection at connection_array[i] is marked for close, then:
 *    - If it has data that it wants to flush, try to flush it.
 *    - If it _still_ has data to flush, and conn->hold_open_until_flushed is
 *      true, then leave the connection open and return.
 *    - Otherwise, remove the connection from connection_array and from
 *      all other lists, close it, and free it.
 * Returns 1 if the connection was closed, 0 otherwise.
 * DOCDOC closeable_list
 */
static int conn_close_if_marked(int i) {
  connection_t *conn;
  int retval;

  conn = connection_array[i];
  if (!conn->marked_for_close)
    return 0; /* nothing to see here, move along */
  assert_connection_ok(conn, time(NULL));
  assert_all_pending_dns_resolves_ok();

  log_fn(LOG_INFO,"Cleaning up connection (fd %d).",conn->s);
  if (conn->s >= 0 && connection_wants_to_flush(conn)) {
    /* -1 means it's an incomplete edge connection, or that the socket
     * has already been closed as unflushable. */
    if (!conn->hold_open_until_flushed)
      log_fn(LOG_INFO,
        "Conn (addr %s, fd %d, type %s, state %d) marked, but wants to flush %d bytes. "
        "(Marked at %s:%d)",
        conn->address, conn->s, CONN_TYPE_TO_STRING(conn->type), conn->state,
        (int)conn->outbuf_flushlen, conn->marked_for_close_file, conn->marked_for_close);
    if (connection_speaks_cells(conn)) {
      if (conn->state == OR_CONN_STATE_OPEN) {
        retval = flush_buf_tls(conn->tls, conn->outbuf, &conn->outbuf_flushlen);
      } else
        retval = -1; /* never flush non-open broken tls connections */
    } else {
      retval = flush_buf(conn->s, conn->outbuf, &conn->outbuf_flushlen);
    }
    if (retval >= 0 &&
       conn->hold_open_until_flushed && connection_wants_to_flush(conn)) {
      log_fn(LOG_INFO,"Holding conn (fd %d) open for more flushing.",conn->s);
      /* XXX should we reset timestamp_lastwritten here? */
      return 0;
    }
    if (connection_wants_to_flush(conn)) {
      log_fn(LOG_NOTICE,"Conn (addr %s, fd %d, type %s, state %d) is being closed, but there are still %d bytes we can't write. (Marked at %s:%d)",
             conn->address, conn->s, CONN_TYPE_TO_STRING(conn->type), conn->state,
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
  smartlist_remove(closeable_connection_lst, conn);
  if (conn->type == CONN_TYPE_EXIT) {
    assert_connection_edge_not_dns_pending(conn);
  }
  connection_free(conn);
  return 1;
}

/** We've just tried every dirserver we know about, and none of
 * them were reachable. Assume the network is down. Change state
 * so next time an application connection arrives we'll delay it
 * and try another directory fetch. Kill off all the circuit_wait
 * streams that are waiting now, since they will all timeout anyway.
 */
void directory_all_unreachable(time_t now) {
  connection_t *conn;

  has_fetched_directory=0;
  stats_n_seconds_working=0; /* reset it */

  while ((conn = connection_get_by_type_state(CONN_TYPE_AP,
                                              AP_CONN_STATE_CIRCUIT_WAIT))) {
    conn->has_sent_end = 1; /* it's not connected anywhere, so no need to end */
    log_fn(LOG_NOTICE,"Network down? Failing connection to '%s'.",
           conn->socks_request->address);
    connection_mark_for_close(conn);
  }
}

/** This function is called whenever we successfully pull down a directory */
void directory_has_arrived(time_t now) {
  or_options_t *options = get_options();

  log_fn(LOG_INFO, "A directory has arrived.");

  has_fetched_directory=1;
  /* Don't try to upload or download anything for a while
   * after the directory we had when we started.
   */
  if (!time_to_fetch_directory)
    time_to_fetch_directory = now + options->DirFetchPeriod;

  if (!time_to_force_upload_descriptor)
    time_to_force_upload_descriptor = now + options->DirPostPeriod;

  if (!time_to_fetch_running_routers)
    time_to_fetch_running_routers = now + options->StatusFetchPeriod;

  if (server_mode(options) &&
      !we_are_hibernating()) { /* connect to the appropriate routers */
    router_retry_connections();
  }
}

/** Perform regular maintenance tasks for a single connection.  This
 * function gets run once per second per connection by run_housekeeping.
 */
static void run_connection_housekeeping(int i, time_t now) {
  cell_t cell;
  connection_t *conn = connection_array[i];
  or_options_t *options = get_options();

  /* Expire any directory connections that haven't sent anything for 5 min */
  if (conn->type == CONN_TYPE_DIR &&
      !conn->marked_for_close &&
      conn->timestamp_lastwritten + 5*60 < now) {
    log_fn(LOG_INFO,"Expiring wedged directory conn (fd %d, purpose %d)", conn->s, conn->purpose);
    connection_mark_for_close(conn);
    return;
  }

  /* If we haven't written to an OR connection for a while, then either nuke
     the connection or send a keepalive, depending. */
  if (connection_speaks_cells(conn) &&
      now >= conn->timestamp_lastwritten + options->KeepalivePeriod) {
    routerinfo_t *router = router_get_by_digest(conn->identity_digest);
    if ((!connection_state_is_open(conn)) ||
        (we_are_hibernating() && !circuit_get_by_conn(conn)) ||
        (!clique_mode(options) && !circuit_get_by_conn(conn) &&
        (!router || !server_mode(options) || !router_is_clique_mode(router)))) {
      /* our handshake has expired; we're hibernating;
       * or we have no circuits and we're both either OPs or normal ORs,
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
  int bw;
  or_options_t *options = get_options();

  bw = rep_hist_bandwidth_assess();
  router_set_bandwidth_capacity(bw);

  if (options->ClientOnly)
    return 0;
  if (!options->ORPort)
    return 0;

  /* XXX for now, you're only a server if you're a server */
  return server_mode(options);

  /* here, determine if we're reachable */
  if (0) { /* we've recently failed to reach our IP/ORPort from the outside */
    return 0;
  }

  if (bw < MIN_BW_TO_PUBLISH_DESC)
    return 0;
  if (options->AuthoritativeDir)
    return 1;
  if (stats_n_seconds_working < MIN_UPTIME_TO_PUBLISH_DESC)
    return 0;

  return 1;
}

/** Return true iff we believe ourselves to be an authoritative
 * directory server.
 */
int authdir_mode(or_options_t *options) {
  return options->AuthoritativeDir != 0;
}

/** Return true iff we try to stay connected to all ORs at once.
 */
int clique_mode(or_options_t *options) {
  return authdir_mode(options);
}

/** Return true iff we are trying to be a server.
 */
int server_mode(or_options_t *options) {
  return (options->ORPort != 0 || options->ORBindAddress);
}

/** Remember if we've advertised ourselves to the dirservers. */
static int server_is_advertised=0;

/** Return true iff we have published our descriptor lately.
 */
int advertised_server_mode(void) {
  return server_is_advertised;
}

/** Return true iff we are trying to be a socks proxy. */
int proxy_mode(or_options_t *options) {
  return (options->SocksPort != 0 || options->SocksBindAddress);
}

/** Perform regular maintenance tasks.  This function gets run once per
 * second by prepare_for_poll.
 */
static void run_scheduled_events(time_t now) {
  static time_t last_rotated_certificate = 0;
  static time_t time_to_check_listeners = 0;
  static time_t time_to_check_descriptor = 0;
  or_options_t *options = get_options();
  int i;

  /** 0. See if we've been asked to shut down and our timeout has
   * expired; or if our bandwidth limits are exhausted and we
   * should hibernate; or if it's time to wake up from hibernation.
   */
  consider_hibernation(now);

  /** 1a. Every MIN_ONION_KEY_LIFETIME seconds, rotate the onion keys,
   *  shut down and restart all cpuworkers, and update the directory if
   *  necessary.
   */
  if (server_mode(options) &&
      get_onion_key_set_at()+MIN_ONION_KEY_LIFETIME < now) {
    log_fn(LOG_INFO,"Rotating onion key.");
    rotate_onion_key();
    cpuworkers_rotate();
    if (router_rebuild_descriptor(1)<0) {
      log_fn(LOG_WARN, "Couldn't rebuild router descriptor");
    }
    if (advertised_server_mode())
      router_upload_dir_desc_to_dirservers(0);
  }

  /** 1b. Every MAX_SSL_KEY_LIFETIME seconds, we change our TLS context. */
  if (!last_rotated_certificate)
    last_rotated_certificate = now;
  if (last_rotated_certificate+MAX_SSL_KEY_LIFETIME < now) {
    log_fn(LOG_INFO,"Rotating tls context.");
    if (tor_tls_context_new(get_identity_key(), 1, options->Nickname,
                            MAX_SSL_KEY_LIFETIME) < 0) {
      log_fn(LOG_WARN, "Error reinitializing TLS context");
      /* XXX is it a bug here, that we just keep going? */
    }
    last_rotated_certificate = now;
    /* XXXX We should rotate TLS connections as well; this code doesn't change
     *      them at all. */
  }

  /** 1c. If we have to change the accounting interval or record
   * bandwidth used in this accounting interval, do so. */
  if (accounting_is_enabled(options))
    accounting_run_housekeeping(now);

  /** 2. Periodically, we consider getting a new directory, getting a
   * new running-routers list, and/or force-uploading our descriptor
   * (if we've passed our internal checks). */
  if (time_to_fetch_directory < now) {
    /* purge obsolete entries */
    routerlist_remove_old_routers(ROUTER_MAX_AGE);

    if (authdir_mode(options)) {
      /* We're a directory; dump any old descriptors. */
      dirserv_remove_old_servers(ROUTER_MAX_AGE);
    }
    if (server_mode(options) && !we_are_hibernating()) {
      /* dirservers try to reconnect, in case connections have failed;
       * and normal servers try to reconnect to dirservers */
      router_retry_connections();
    }

    directory_get_from_dirserver(DIR_PURPOSE_FETCH_DIR, NULL, 1);
    time_to_fetch_directory = now + options->DirFetchPeriod;
    if (time_to_fetch_running_routers < now + options->StatusFetchPeriod) {
      time_to_fetch_running_routers = now + options->StatusFetchPeriod;
    }

    /* Also, take this chance to remove old information from rephist. */
    rep_history_clean(now-24*60*60);
  }

  if (time_to_fetch_running_routers < now) {
    if (!authdir_mode(options)) {
      directory_get_from_dirserver(DIR_PURPOSE_FETCH_RUNNING_LIST, NULL, 1);
    }
    time_to_fetch_running_routers = now + options->StatusFetchPeriod;
  }

  if (time_to_force_upload_descriptor < now) {
    if (decide_if_publishable_server(now)) {
      server_is_advertised = 1;
      router_rebuild_descriptor(1);
      router_upload_dir_desc_to_dirservers(1);
    } else {
      server_is_advertised = 0;
    }

    rend_cache_clean(); /* this should go elsewhere? */

    time_to_force_upload_descriptor = now + options->DirPostPeriod;
  }

  /* 2b. Once per minute, regenerate and upload the descriptor if the old
   * one is inaccurate. */
  if (time_to_check_descriptor < now) {
    time_to_check_descriptor = now + CHECK_DESCRIPTOR_INTERVAL;
    if (decide_if_publishable_server(now)) {
      server_is_advertised=1;
      router_rebuild_descriptor(0);
      router_upload_dir_desc_to_dirservers(0);
    } else {
      server_is_advertised=0;
    }
  }

  /** 3a. Every second, we examine pending circuits and prune the
   *    ones which have been pending for more than a few seconds.
   *    We do this before step 4, so it can try building more if
   *    it's not comfortable with the number of available circuits.
   */
  circuit_expire_building(now);

  /** 3b. Also look at pending streams and prune the ones that 'began'
   *     a long time ago but haven't gotten a 'connected' yet.
   *     Do this before step 4, so we can put them back into pending
   *     state to be picked up by the new circuit.
   */
  connection_ap_expire_beginning();

  /** 3c. And expire connections that we've held open for too long.
   */
  connection_expire_held_open();

  /** 3d. And every 60 seconds, we relaunch listeners if any died. */
  if (!we_are_hibernating() && time_to_check_listeners < now) {
    retry_all_listeners(0); /* 0 means "only if some died." */
    time_to_check_listeners = now+60;
  }

  /** 4. Every second, we try a new circuit if there are no valid
   *    circuits. Every NewCircuitPeriod seconds, we expire circuits
   *    that became dirty more than NewCircuitPeriod seconds ago,
   *    and we make a new circ if there are no clean circuits.
   */
  if (has_fetched_directory && !we_are_hibernating())
    circuit_build_needed_circs(now);

  /** 5. We do housekeeping for each connection... */
  for (i=0;i<nfds;i++) {
    run_connection_housekeeping(i, now);
  }

  /** 6. And remove any marked circuits... */
  circuit_close_all_marked();

  /** 7. And upload service descriptors if necessary. */
  if (!we_are_hibernating())
    rend_consider_services_upload(now);

  /** 8. and blow away any connections that need to die. have to do this now,
   * because if we marked a conn for close and left its socket -1, then
   * we'll pass it to poll/select and bad things will happen.
   */
  close_closeable_connections();
}

/** DOCDOC */
static void second_elapsed_callback(int fd, short event, void *args)
{
  static struct event *timeout_event = NULL;
  static struct timeval one_second;
  static long current_second = 0;
  struct timeval now;
  size_t bytes_written;
  size_t bytes_read;
  int seconds_elapsed;
  if (!timeout_event) {
    timeout_event = tor_malloc_zero(sizeof(struct event));
    evtimer_set(timeout_event, second_elapsed_callback, NULL);
    one_second.tv_sec = 1;
    one_second.tv_usec = 0;
  }

  /* log_fn(LOG_NOTICE, "Tick."); */
  tor_gettimeofday(&now);

  /* the second has rolled over. check more stuff. */
  bytes_written = stats_prev_global_write_bucket - global_write_bucket;
  bytes_read = stats_prev_global_read_bucket - global_read_bucket;
  seconds_elapsed = current_second ? (now.tv_sec - current_second) : 0;
  stats_n_bytes_read += bytes_read;
  stats_n_bytes_written += bytes_written;
  if (accounting_is_enabled(get_options()))
    accounting_add_bytes(bytes_read, bytes_written, seconds_elapsed);
  control_event_bandwidth_used((uint32_t)bytes_read,(uint32_t)bytes_written);

  connection_bucket_refill(&now);
  stats_prev_global_read_bucket = global_read_bucket;
  stats_prev_global_write_bucket = global_write_bucket;

  /* if more than 10s have elapsed, probably the clock jumped: doesn't count. */
  if (seconds_elapsed < 10)
    stats_n_seconds_working += seconds_elapsed;

  assert_all_pending_dns_resolves_ok();
  run_scheduled_events(now.tv_sec);
  assert_all_pending_dns_resolves_ok();

  current_second = now.tv_sec; /* remember which second it is, for next time */

#if 0
  for (i=0;i<nfds;i++) {
    conn = connection_array[i];
    if (connection_has_pending_tls_data(conn) &&
        connection_is_reading(conn)) {
      log_fn(LOG_DEBUG,"sock %d has pending bytes.",conn->s);
      return; /* has pending bytes to read; don't let poll wait. */
    }
  }
#endif

  evtimer_add(timeout_event, &one_second);
}

/** Called when we get a SIGHUP: reload configuration files and keys,
 * retry all connections, re-upload all descriptors, and so on. */
static int do_hup(void) {
  char keydir[512];
  or_options_t *options = get_options();

  log_fn(LOG_NOTICE,"Received sighup. Reloading config.");
  has_completed_circuit=0;
  if (accounting_is_enabled(options))
    accounting_record_bandwidth_usage(time(NULL));

  /* first, reload config variables, in case they've changed */
  /* no need to provide argc/v, they've been cached inside init_from_config */
  if (init_from_config(0, NULL) < 0) {
    log_fn(LOG_ERR,"Reading config failed--see warnings above. For usage, try -h.");
    return -1;
  }
  options = get_options(); /* they have changed now */
  if (authdir_mode(options)) {
    /* reload the approved-routers file */
    tor_snprintf(keydir,sizeof(keydir),"%s/approved-routers", options->DataDirectory);
    log_fn(LOG_INFO,"Reloading approved fingerprints from %s...",keydir);
    if (dirserv_parse_fingerprint_file(keydir) < 0) {
      log_fn(LOG_NOTICE, "Error reloading fingerprints. Continuing with old list.");
    }
  }
  /* Fetch a new directory. Even authdirservers do this. */
  directory_get_from_dirserver(DIR_PURPOSE_FETCH_DIR, NULL, 1);
  if (server_mode(options)) {
    /* Restart cpuworker and dnsworker processes, so they get up-to-date
     * configuration options. */
    cpuworkers_rotate();
    dnsworkers_rotate();
    /* Rebuild fresh descriptor. */
    router_rebuild_descriptor(1);
    tor_snprintf(keydir,sizeof(keydir),"%s/router.desc", options->DataDirectory);
    log_fn(LOG_INFO,"Saving descriptor to %s...",keydir);
    if (write_str_to_file(keydir, router_get_my_descriptor(), 0)) {
      return -1;
    }
  }
  return 0;
}

/** Tor main loop. */
static int do_main_loop(void) {
  int loop_result;

  /* load the private keys, if we're supposed to have them, and set up the
   * TLS context. */
  if (! identity_key_is_set()) {
    if (init_keys() < 0) {
      log_fn(LOG_ERR,"Error initializing keys; exiting");
      return -1;
    }
  }

  /* Set up our buckets */
  connection_bucket_init();
  stats_prev_global_read_bucket = global_read_bucket;
  stats_prev_global_write_bucket = global_write_bucket;

  /* load the routers file, or assign the defaults. */
  if (router_reload_router_list()) {
    return -1;
  }

  if (authdir_mode(get_options())) {
    /* the directory is already here, run startup things */
    router_retry_connections();
  }

  if (server_mode(get_options())) {
    /* launch cpuworkers. Need to do this *after* we've read the onion key. */
    cpu_init();
  }

  /* set up once-a-second callback. */
  second_elapsed_callback(0,0,NULL);

  for (;;) {
#ifdef MS_WINDOWS_SERVICE /* Do service stuff only on windows. */
    if (service_status.dwCurrentState == SERVICE_STOP_PENDING) {
      service_status.dwWin32ExitCode = 0;
      service_status.dwCurrentState = SERVICE_STOPPED;
      SetServiceStatus(hStatus, &service_status);
      return 0;
    }
#endif
    /* poll until we have an event, or the second ends */
    loop_result = event_dispatch();

    /* let catch() handle things like ^c, and otherwise don't worry about it */
    if (loop_result < 0) {
      int e = errno;
      /* let the program survive things like ^z */
      if (e != EINTR) {
        log_fn(LOG_ERR,"poll failed: %s [%d]",
               tor_socket_strerror(e), e);
        return -1;
      } else {
        log_fn(LOG_DEBUG,"poll interrupted.");
        /* You can't trust the results of this poll(). Go back to the
         * top of the big for loop. */
        continue;
      }
    }

    /* refilling buckets and sending cells happens at the beginning of the
     * next iteration of the loop, inside prepare_for_poll()
     * XXXX No longer so.
     */
  }
}

/** Used to implement the SIGNAL control command: if we accept
 * <b>the_signal</b> as a remote pseudo-signal, then act on it and
 * return 0.  Else return -1. */
/* We don't re-use catch() here because:
 *   1. We handle a different set of signals than those allowed in catch.
 *   2. Platforms without signal() are unlikely to define SIGfoo.
 *   3. The control spec is defined to use fixed numeric signal values
 *      which just happen to match the unix values.
 */
int
control_signal_act(int the_signal)
{
  switch(the_signal)
    {
    case 1:
      signal_callback(0,0,(void*)SIGHUP);
      break;
    case 2:
      signal_callback(0,0,(void*)SIGINT);
      break;
    case 10:
      signal_callback(0,0,(void*)SIGUSR1);
      break;
    case 12:
      signal_callback(0,0,(void*)SIGUSR2);
      break;
    case 15:
      signal_callback(0,0,(void*)SIGTERM);
      break;
    default:
      return -1;
    }
  return 0;
}

static void signal_callback(int fd, short events, void *arg)
{
  int sig = (int) arg;
  switch (sig)
    {
    case SIGTERM:
      log(LOG_ERR,"Catching signal TERM, exiting cleanly.");
      tor_cleanup();
      exit(0);
      break;
    case SIGINT:
      if (!server_mode(get_options())) { /* do it now */
        log(LOG_NOTICE,"Interrupt: exiting cleanly.");
        tor_cleanup();
        exit(0);
      }
      hibernate_begin_shutdown();
      break;
#ifdef SIGPIPE
    case SIGPIPE:
      log(LOG_NOTICE,"Caught sigpipe. Ignoring.");
      break;
#endif
    case SIGUSR1:
      /* prefer to log it at INFO, but make sure we always see it */
      dumpstats(get_min_log_level()<LOG_INFO ? get_min_log_level() : LOG_INFO);
      break;
    case SIGUSR2:
      switch_logs_debug();
      log(LOG_NOTICE,"Caught USR2. Going to loglevel debug.");
      break;
    case SIGHUP:
      if (do_hup() < 0) {
        log_fn(LOG_WARN,"Restart failed (config error?). Exiting.");
        tor_cleanup();
        exit(1);
      }
      break;
#ifdef SIGCHLD
    case SIGCHLD:
      while (waitpid(-1,NULL,WNOHANG) > 0) ; /* keep reaping until no more zombies */
      break;
    }
#endif
}

/** Write all statistics to the log, with log level 'severity'.  Called
 * in response to a SIGUSR1. */
static void dumpstats(int severity) {
  int i;
  connection_t *conn;
  time_t now = time(NULL);
  time_t elapsed;

  log(severity, "Dumping stats:");

  for (i=0;i<nfds;i++) {
    conn = connection_array[i];
    log(severity, "Conn %d (socket %d) type %d (%s), state %d (%s), created %d secs ago",
      i, conn->s, conn->type, CONN_TYPE_TO_STRING(conn->type),
      conn->state, conn_state_to_string[conn->type][conn->state], (int)(now - conn->timestamp_created));
    if (!connection_is_listener(conn)) {
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

  if (now - time_of_process_start >= 0)
    elapsed = now - time_of_process_start;
  else
    elapsed = 0;

  if (elapsed) {
    log(severity,
        "Average bandwidth: "U64_FORMAT"/%d = %d bytes/sec reading",
        U64_PRINTF_ARG(stats_n_bytes_read),
        (int)elapsed,
        (int) (stats_n_bytes_read/elapsed));
    log(severity,
        "Average bandwidth: "U64_FORMAT"/%d = %d bytes/sec writing",
        U64_PRINTF_ARG(stats_n_bytes_written),
        (int)elapsed,
        (int) (stats_n_bytes_written/elapsed));
  }

  rep_hist_dump_stats(now,severity);
  rend_service_dump_stats(severity);
}

/** Called by exit() as we shut down the process.
 */
static void exit_function(void)
{
  /* NOTE: If we ever daemonize, this gets called immediately.  That's
   * okay for now, because we only use this on Windows.  */
#ifdef MS_WINDOWS
  WSACleanup();
#endif
}

/** Set up the signal handlers for either parent or child. */
void handle_signals(int is_parent)
{
#ifndef MS_WINDOWS /* do signal stuff only on unix */
  int i;
  static int signals[] = {
    SIGINT,  /* do a controlled slow shutdown */
    SIGTERM, /* to terminate now */
    SIGPIPE, /* otherwise sigpipe kills us */
    SIGUSR1, /* dump stats */
    SIGUSR2, /* go to loglevel debug */
    SIGHUP,  /* to reload config, retry conns, etc */
#ifdef SIGXFSZ
    SIGXFSZ, /* handle file-too-big resource exhaustion */
#endif
    SIGCHLD, /* handle dns/cpu workers that exit */
    -1 };
  static struct event signal_events[16]; /* bigger than it has to be. */
  if (is_parent) {
    for (i = 0; signals[i] >= 0; ++i) {
      signal_set(&signal_events[i], signals[i], signal_callback,
                 (void*)signals[i]);
      signal_add(&signal_events[i], NULL);
    }
  } else {
    struct sigaction action;
    action.sa_flags = 0;
    sigemptyset(&action.sa_mask);
    action.sa_handler = SIG_IGN;
    sigaction(SIGINT,  &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGPIPE, &action, NULL);
    sigaction(SIGUSR1, &action, NULL);
    sigaction(SIGUSR2, &action, NULL);
    sigaction(SIGHUP,  &action, NULL);
#ifdef SIGXFSZ
    sigaction(SIGXFSZ, &action, NULL);
#endif
#endif /* signal stuff */
  }
}

/** Main entry point for the Tor command-line client.
 */
static int tor_init(int argc, char *argv[]) {
  time_of_process_start = time(NULL);
  closeable_connection_lst = smartlist_create();
  /* Initialize the history structures. */
  rep_hist_init();
  /* Initialize the service cache. */
  rend_cache_init();
  client_dns_init(); /* Init the client dns cache. Do it always, since it's cheap. */

  /* give it somewhere to log to initially */
  add_temp_log();
  log_fn(LOG_NOTICE,"Tor v%s. This is experimental software. Do not rely on it for strong anonymity.",VERSION);

  if (network_init()<0) {
    log_fn(LOG_ERR,"Error initializing network; exiting.");
    return -1;
  }
  atexit(exit_function);
  event_init(); /* This needs to happen before net stuff. Is it okay if this
                 * happens before daemonizing? */

  if (init_from_config(argc,argv) < 0) {
    log_fn(LOG_ERR,"Reading config failed--see warnings above. For usage, try -h.");
    return -1;
  }

#ifndef MS_WINDOWS
  if (geteuid()==0)
    log_fn(LOG_WARN,"You are running Tor as root. You don't need to, and you probably shouldn't.");
#endif

  /* only spawn dns handlers if we're a router */
  if (server_mode(get_options()) && get_options()->command == CMD_RUN_TOR) {
    dns_init(); /* initialize the dns resolve tree, and spawn workers */
    /* XXX really, this should get moved to do_main_loop */
  }

  handle_signals(1);

  crypto_global_init();
  crypto_seed_rng();
  return 0;
}

/** Do whatever cleanup is necessary before shutting Tor down. */
void tor_cleanup(void) {
  or_options_t *options = get_options();
  /* Remove our pid file. We don't care if there was an error when we
   * unlink, nothing we could do about it anyways. */
  if (options->PidFile && options->command == CMD_RUN_TOR)
    unlink(options->PidFile);
  crypto_global_cleanup();
  if (accounting_is_enabled(options))
    accounting_record_bandwidth_usage(time(NULL));
}

/** Read/create keys as needed, and echo our fingerprint to stdout. */
static void do_list_fingerprint(void)
{
  char buf[FINGERPRINT_LEN+1];
  crypto_pk_env_t *k;
  const char *nickname = get_options()->Nickname;
  if (!server_mode(get_options())) {
    printf("Clients don't have long-term identity keys. Exiting.\n");
    return;
  }
  tor_assert(nickname);
  if (init_keys() < 0) {
    log_fn(LOG_ERR,"Error initializing keys; exiting");
    return;
  }
  if (!(k = get_identity_key())) {
    log_fn(LOG_ERR,"Error: missing identity key.");
    return;
  }
  if (crypto_pk_get_fingerprint(k, buf, 1)<0) {
    log_fn(LOG_ERR, "Error computing fingerprint");
    return;
  }
  printf("%s %s\n", nickname, buf);
}

/** Entry point for password hashing: take the desired password from
 * the command line, and print its salted hash to stdout. **/
static void do_hash_password(void)
{

  char output[256];
  char key[S2K_SPECIFIER_LEN+DIGEST_LEN];

  crypto_rand(key, S2K_SPECIFIER_LEN-1);
  key[S2K_SPECIFIER_LEN-1] = (uint8_t)96; /* Hash 64 K of data. */
  secret_to_key(key+S2K_SPECIFIER_LEN, DIGEST_LEN,
                get_options()->command_arg, strlen(get_options()->command_arg),
                key);
  if (base64_encode(output, sizeof(output), key, sizeof(key))<0) {
    log_fn(LOG_ERR, "Unable to compute base64");
  } else {
    printf("%s",output);
  }
}

#ifdef MS_WINDOWS_SERVICE
void nt_service_control(DWORD request)
{
  switch (request) {
    case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
          log(LOG_ERR, "Got stop/shutdown request; shutting down cleanly.");
          service_status.dwCurrentState = SERVICE_STOP_PENDING;
          return;
  }
  SetServiceStatus(hStatus, &service_status);
}

void nt_service_body(int argc, char **argv)
{
  int err;
  FILE *f;
  service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  service_status.dwCurrentState = SERVICE_START_PENDING;
  service_status.dwControlsAccepted =
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  service_status.dwWin32ExitCode = 0;
  service_status.dwServiceSpecificExitCode = 0;
  service_status.dwCheckPoint = 0;
  service_status.dwWaitHint = 1000;
  hStatus = RegisterServiceCtrlHandler(GENSRV_SERVICENAME, (LPHANDLER_FUNCTION) nt_service_control);
  if (hStatus == 0) {
    // failed;
    return;
  }
  err = tor_init(backup_argc, backup_argv); // refactor this part out of tor_main and do_main_loop
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
  DWORD result = 0;
  table[0].lpServiceName = GENSRV_SERVICENAME;
  table[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)nt_service_body;
  table[1].lpServiceName = NULL;
  table[1].lpServiceProc = NULL;
  if (!StartServiceCtrlDispatcher(table)) {
    result = GetLastError();
    printf("Error was %d\n",result);
    if (result == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
      if (tor_init(backup_argc, backup_argv) < 0)
        return;
      switch (get_options()->command) {
      case CMD_RUN_TOR:
        do_main_loop();
        break;
      case CMD_LIST_FINGERPRINT:
        do_list_fingerprint();
        break;
      case CMD_HASH_PASSWORD:
        do_hash_password();
        break;
      default:
        log_fn(LOG_ERR, "Illegal command number %d: internal error.", get_options()->command);
      }
      tor_cleanup();
    }
  }
}

int nt_service_install()
{
  /* XXXX Problems with NT services:
   * 1. The configuration file needs to be in the same directory as the .exe
   * 2. The exe and the configuration file can't be on any directory path
   *    that contains a space.
   * 3. Ideally, there should be one EXE that can either run as a
   *    separate process (as now) or that can install and run itself
   *    as an NT service.  I have no idea how hard this is.
   *
   * Notes about developing NT services:
   *
   * 1. Don't count on your CWD. If an absolute path is not given, the
   *    fopen() function goes wrong.
   * 2. The parameters given to the nt_service_body() function differ
   *    from those given to main() function.
   */

  SC_HANDLE hSCManager = NULL;
  SC_HANDLE hService = NULL;
  TCHAR szPath[_MAX_PATH];
  TCHAR szDrive[_MAX_DRIVE];
  TCHAR szDir[_MAX_DIR];
  char cmd1[] = " -f ";
  char cmd2[] = "\\torrc";
  char *command;
  int len = 0;

  if (0 == GetModuleFileName(NULL, szPath, MAX_PATH))
    return 0;

  _tsplitpath(szPath, szDrive, szDir, NULL, NULL);
  len = _MAX_PATH + strlen(cmd1) + _MAX_DRIVE + _MAX_DIR + strlen(cmd2);
  command = tor_malloc(len);

  strlcpy(command, szPath, len);
  strlcat(command, " -f ", len);
  strlcat(command, szDrive, len);
  strlcat(command, szDir, len);
  strlcat(command, "\\torrc", len);

  if ((hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE)) == NULL) {
    printf("Failed: OpenSCManager()\n");
    free(command);
    return 0;
  }

  if ((hService = CreateService(hSCManager, GENSRV_SERVICENAME, GENSRV_DISPLAYNAME,
                                SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, command,
                                NULL, NULL, NULL, NULL, NULL)) == NULL) {
    printf("Failed: CreateService()\n");
    CloseServiceHandle(hSCManager);
    free(command);
    return 0;
  }

  CloseServiceHandle(hService);
  CloseServiceHandle(hSCManager);
  free(command);

  printf("Install service successfully\n");

  return 0;
}

int nt_service_remove()
{
  SC_HANDLE hSCManager = NULL;
  SC_HANDLE hService = NULL;
  SERVICE_STATUS service_status;
  BOOL result = FALSE;

  if ((hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE)) == NULL) {
    printf("Failed: OpenSCManager()\n");
    return 0;
  }

  if ((hService = OpenService(hSCManager, GENSRV_SERVICENAME, SERVICE_ALL_ACCESS)) == NULL) {
    printf("Failed: OpenService()\n");
    CloseServiceHandle(hSCManager);
  }

  result = ControlService(hService, SERVICE_CONTROL_STOP, &service_status);
  if (result) {
    while (QueryServiceStatus(hService, &service_status))
    {
      if (service_status.dwCurrentState == SERVICE_STOP_PENDING)
        Sleep(500);
      else
        break;
    }
    if (DeleteService(hService))
      printf("Remove service successfully\n");
    else
      printf("Failed: DeleteService()\n");
  } else {
    result = DeleteService(hService);
    if (result)
      printf("Remove service successfully\n");
    else
      printf("Failed: DeleteService()\n");
  }

  CloseServiceHandle(hService);
  CloseServiceHandle(hSCManager);

  return 0;
}
#endif

int tor_main(int argc, char *argv[]) {
#ifdef MS_WINDOWS_SERVICE
  backup_argv = argv;
  backup_argc = argc;
  if ((argc >= 2) && !strcmp(argv[1], "-install"))
    return nt_service_install();
  if ((argc >= 2) && !strcmp(argv[1], "-remove"))
    return nt_service_remove();
  nt_service_main();
  return 0;
#else
  if (tor_init(argc, argv)<0)
    return -1;
  switch (get_options()->command) {
  case CMD_RUN_TOR:
    do_main_loop();
    break;
  case CMD_LIST_FINGERPRINT:
    do_list_fingerprint();
    break;
  case CMD_HASH_PASSWORD:
    do_hash_password();
    break;
  default:
    log_fn(LOG_ERR, "Illegal command number %d: internal error.",
           get_options()->command);
  }
  tor_cleanup();
  return -1;
#endif
}

