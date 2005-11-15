/* Copyright 2001 Matej Pfajfar.
 * Copyright 2001-2004 Roger Dingledine.
 * Copyright 2004-2005 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char main_c_id[] = "$Id$";

/**
 * \file main.c
 * \brief Toplevel module. Handles signals, multiplexes between
 * connections, implements main loop, and drives scheduled events.
 **/

#include "or.h"
#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

/********* PROTOTYPES **********/

static void dumpmemusage(int severity);
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
/** When do we next download a running-routers summary? */
static time_t time_to_fetch_running_routers = 0;

/** Array of all open connections; each element corresponds to the element of
 * poll_array in the same position.  The first nfds elements are valid. */
static connection_t *connection_array[MAXCONNECTIONS+1] =
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

#ifdef MS_WINDOWS
#define MS_WINDOWS_SERVICE
#endif

#ifdef MS_WINDOWS_SERVICE
#include <tchar.h>
#define GENSRV_SERVICENAME  TEXT("tor")
#define GENSRV_DISPLAYNAME  TEXT("Tor Win32 Service")
#define GENSRV_DESCRIPTION  TEXT("Provides an anonymous Internet communication system")

// Cheating: using the pre-defined error codes, tricks Windows into displaying
//           a semi-related human-readable error message if startup fails as
//           opposed to simply scaring people with Error: 0xffffffff
#define NT_SERVICE_ERROR_NO_TORRC ERROR_FILE_NOT_FOUND
#define NT_SERVICE_ERROR_TORINIT_FAILED ERROR_EXCEPTION_IN_SERVICE

SERVICE_STATUS service_status;
SERVICE_STATUS_HANDLE hStatus;
static char **backup_argv;
static int backup_argc;
static int nt_service_is_stopped(void);
static char* nt_strerror(uint32_t errnum);
#else
#define nt_service_is_stopped() (0)
#endif

#define FORCE_REGENERATE_DESCRIPTOR_INTERVAL 18*60*60 /* 18 hours */
#define CHECK_DESCRIPTOR_INTERVAL 60 /* one minute */
#define CHECK_IPADDRESS_INTERVAL (5*60) /* five minutes */
#define BUF_SHRINK_INTERVAL 60 /* one minute */
#define DESCRIPTOR_RETRY_INTERVAL 10
#define DESCRIPTOR_FAILURE_RESET_INTERVAL 60*60
#define TIMEOUT_UNTIL_UNREACHABILITY_COMPLAINT (20*60) /* 20 minutes */
#define ENTROPY_INTERVAL 60*60

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
int
connection_add(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->s >= 0);

  if (nfds >= get_options()->_ConnLimit-1) {
    warn(LD_NET,"Failing because we have %d connections already. Please raise your ulimit -n.", nfds);
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

  debug(LD_NET,"new conn type %s, socket %d, nfds %d.",
      conn_type_to_string(conn->type), conn->s, nfds);

  return 0;
}

/** Remove the connection from the global list, and remove the
 * corresponding poll entry.  Calling this function will shift the last
 * connection (if any) into the position occupied by conn.
 */
int
connection_remove(connection_t *conn)
{
  int current_index;

  tor_assert(conn);
  tor_assert(nfds>0);

  debug(LD_NET,"removing socket %d (type %s), nfds now %d",
        conn->s, conn_type_to_string(conn->type), nfds-1);

  tor_assert(conn->poll_index >= 0);
  current_index = conn->poll_index;
  if (current_index == nfds-1) { /* this is the end */
    nfds--;
    return 0;
  }

  connection_unregister(conn);

  /* replace this one with the one at the end */
  nfds--;
  connection_array[current_index] = connection_array[nfds];
  connection_array[current_index]->poll_index = current_index;

  return 0;
}

/** If it's an edge conn, remove it from the list
 * of conn's on this circuit. If it's not on an edge,
 * flush and send destroys for all circuits on this conn.
 *
 * If <b>remove</b> is non-zero, then remove it from the
 * connection_array and closeable_connection_lst.
 *
 * Then free it.
 */
static void
connection_unlink(connection_t *conn, int remove)
{
  circuit_about_to_close_connection(conn);
  connection_about_to_close_connection(conn);
  if (remove) {
    connection_remove(conn);
  }
  smartlist_remove(closeable_connection_lst, conn);
  if (conn->type == CONN_TYPE_EXIT) {
    assert_connection_edge_not_dns_pending(conn);
  }
  connection_free(conn);
}

/** Schedule <b>conn</b> to be closed. **/
void
add_connection_to_closeable_list(connection_t *conn)
{
  tor_assert(!smartlist_isin(closeable_connection_lst, conn));
  tor_assert(conn->marked_for_close);
  assert_connection_ok(conn, time(NULL));
  smartlist_add(closeable_connection_lst, conn);
}

/** Return 1 if conn is on the closeable list, else return 0. */
int
connection_is_on_closeable_list(connection_t *conn)
{
  return smartlist_isin(closeable_connection_lst, conn);
}

/** Return true iff conn is in the current poll array. */
int
connection_in_array(connection_t *conn)
{
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
void
get_connection_array(connection_t ***array, int *n)
{
  *array = connection_array;
  *n = nfds;
}

/** Set the event mask on <b>conn</b> to <b>events</b>.  (The event
 * mask is a bitmask whose bits are EV_READ and EV_WRITE.)
 */
void
connection_watch_events(connection_t *conn, short events)
{
  int r;

  tor_assert(conn);
  tor_assert(conn->read_event);
  tor_assert(conn->write_event);

  if (events & EV_READ) {
    r = event_add(conn->read_event, NULL);
  } else {
    r = event_del(conn->read_event);
  }

  if (r<0)
    warn(LD_NET,
         "Error from libevent setting read event state for %d to %swatched.",
         conn->s, (events & EV_READ)?"":"un");

  if (events & EV_WRITE) {
    r = event_add(conn->write_event, NULL);
  } else {
    r = event_del(conn->write_event);
  }

  if (r<0)
    warn(LD_NET,
         "Error from libevent setting read event state for %d to %swatched.",
         conn->s, (events & EV_WRITE)?"":"un");
}

/** Return true iff <b>conn</b> is listening for read events. */
int
connection_is_reading(connection_t *conn)
{
  tor_assert(conn);

  return conn->read_event && event_pending(conn->read_event, EV_READ, NULL);
}

/** Tell the main loop to stop notifying <b>conn</b> of any read events. */
void
connection_stop_reading(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->read_event);

  debug(LD_NET,"connection_stop_reading() called.");
  if (event_del(conn->read_event))
    warn(LD_NET, "Error from libevent setting read event state for %d to unwatched.",
         conn->s);
}

/** Tell the main loop to start notifying <b>conn</b> of any read events. */
void
connection_start_reading(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->read_event);

  if (event_add(conn->read_event, NULL))
    warn(LD_NET, "Error from libevent setting read event state for %d to watched.",
         conn->s);
}

/** Return true iff <b>conn</b> is listening for write events. */
int
connection_is_writing(connection_t *conn)
{
  tor_assert(conn);

  return conn->write_event && event_pending(conn->write_event, EV_WRITE, NULL);
}

/** Tell the main loop to stop notifying <b>conn</b> of any write events. */
void
connection_stop_writing(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->write_event);

  if (event_del(conn->write_event))
    warn(LD_NET, "Error from libevent setting write event state for %d to unwatched.",
           conn->s);

}

/** Tell the main loop to start notifying <b>conn</b> of any write events. */
void
connection_start_writing(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->write_event);

  if (event_add(conn->write_event, NULL))
    warn(LD_NET, "Error from libevent setting write event state for %d to watched.",
           conn->s);
}

/** Close all connections that have been scheduled to get closed */
static void
close_closeable_connections(void)
{
  int i;
  for (i = 0; i < smartlist_len(closeable_connection_lst); ) {
    connection_t *conn = smartlist_get(closeable_connection_lst, i);
    if (conn->poll_index < 0) {
      connection_unlink(conn, 0); /* blow it away right now */
    } else {
      if (!conn_close_if_marked(conn->poll_index))
        ++i;
    }
  }
}

/** Libevent callback: this gets invoked when (connection_t*)<b>conn</b> has
 * some data to read. */
static void
conn_read_callback(int fd, short event, void *_conn)
{
  connection_t *conn = _conn;

  debug(LD_NET,"socket %d wants to read.",conn->s);

  assert_connection_ok(conn, time(NULL));

  if (connection_handle_read(conn) < 0) {
    if (!conn->marked_for_close) {
#ifndef MS_WINDOWS
      warn(LD_BUG,"Bug: unhandled error on read for %s connection (fd %d); removing",
             conn_type_to_string(conn->type), conn->s);
      tor_fragile_assert();
#endif
      if (CONN_IS_EDGE(conn))
        connection_edge_end_errno(conn, conn->cpath_layer);
      connection_mark_for_close(conn);
    }
  }
  assert_connection_ok(conn, time(NULL));

  if (smartlist_len(closeable_connection_lst))
    close_closeable_connections();
}

/** Libevent callback: this gets invoked when (connection_t*)<b>conn</b> has
 * some data to write. */
static void
conn_write_callback(int fd, short events, void *_conn)
{
  connection_t *conn = _conn;

  LOG_FN_CONN(conn, (LOG_DEBUG, LD_NET, "socket %d wants to write.",conn->s));

  assert_connection_ok(conn, time(NULL));

  if (connection_handle_write(conn) < 0) {
    if (!conn->marked_for_close) {
      /* this connection is broken. remove it. */
      log_fn(LOG_WARN,LD_BUG,"Bug: unhandled error on write for %s connection (fd %d); removing",
             conn_type_to_string(conn->type), conn->s);
      tor_fragile_assert();
      conn->has_sent_end = 1; /* otherwise we cry wolf about duplicate close */
      /* XXX do we need a close-immediate here, so we don't try to flush? */
      connection_mark_for_close(conn);
    }
  }
  assert_connection_ok(conn, time(NULL));

  if (smartlist_len(closeable_connection_lst))
    close_closeable_connections();
}

/** If the connection at connection_array[i] is marked for close, then:
 *    - If it has data that it wants to flush, try to flush it.
 *    - If it _still_ has data to flush, and conn->hold_open_until_flushed is
 *      true, then leave the connection open and return.
 *    - Otherwise, remove the connection from connection_array and from
 *      all other lists, close it, and free it.
 * Returns 1 if the connection was closed, 0 otherwise.
 */
static int
conn_close_if_marked(int i)
{
  connection_t *conn;
  int retval;

  conn = connection_array[i];
  if (!conn->marked_for_close)
    return 0; /* nothing to see here, move along */
  assert_connection_ok(conn, time(NULL));
  assert_all_pending_dns_resolves_ok();

  debug(LD_NET,"Cleaning up connection (fd %d).",conn->s);
  if (conn->s >= 0 && connection_wants_to_flush(conn)) {
    /* s == -1 means it's an incomplete edge connection, or that the socket
     * has already been closed as unflushable. */
    int sz = connection_bucket_write_limit(conn);
    if (!conn->hold_open_until_flushed)
      info(LD_NET,
        "Conn (addr %s, fd %d, type %s, state %d) marked, but wants to flush %d bytes. "
        "(Marked at %s:%d)",
        conn->address, conn->s, conn_type_to_string(conn->type), conn->state,
        (int)conn->outbuf_flushlen, conn->marked_for_close_file, conn->marked_for_close);
    if (connection_speaks_cells(conn)) {
      if (conn->state == OR_CONN_STATE_OPEN) {
        retval = flush_buf_tls(conn->tls, conn->outbuf, sz, &conn->outbuf_flushlen);
      } else
        retval = -1; /* never flush non-open broken tls connections */
    } else {
      retval = flush_buf(conn->s, conn->outbuf, sz, &conn->outbuf_flushlen);
    }
    if (retval >= 0 && /* Technically, we could survive things like
                          TLS_WANT_WRITE here. But don't bother for now. */
        conn->hold_open_until_flushed && connection_wants_to_flush(conn)) {
      LOG_FN_CONN(conn,
                  (LOG_INFO,LD_NET,"Holding conn (fd %d) open for more flushing.",conn->s));
      /* XXX should we reset timestamp_lastwritten here? */
      return 0;
    }
    if (connection_wants_to_flush(conn)) {
      int severity;
      if (conn->type == CONN_TYPE_EXIT ||
          (conn->type == CONN_TYPE_DIR && conn->purpose == DIR_PURPOSE_SERVER))
        severity = LOG_INFO;
      else
        severity = LOG_NOTICE;
      log_fn(severity, LD_NET, "Something wrong with your network connection? Conn (addr %s, fd %d, type %s, state %d) tried to write %d bytes but timed out. (Marked at %s:%d)",
             safe_str(conn->address), conn->s, conn_type_to_string(conn->type),
             conn->state,
             (int)buf_datalen(conn->outbuf), conn->marked_for_close_file,
             conn->marked_for_close);
    }
  }
  connection_unlink(conn, 1); /* unlink, remove, free */
  return 1;
}

/** We've just tried every dirserver we know about, and none of
 * them were reachable. Assume the network is down. Change state
 * so next time an application connection arrives we'll delay it
 * and try another directory fetch. Kill off all the circuit_wait
 * streams that are waiting now, since they will all timeout anyway.
 */
void
directory_all_unreachable(time_t now)
{
  connection_t *conn;
  /* XXXX011 NM Update this to reflect new directories? */

  has_fetched_directory=0;
  stats_n_seconds_working=0; /* reset it */

  while ((conn = connection_get_by_type_state(CONN_TYPE_AP,
                                              AP_CONN_STATE_CIRCUIT_WAIT))) {
    notice(LD_NET,"Network down? Failing connection to '%s:%d'.",
           safe_str(conn->socks_request->address), conn->socks_request->port);
    connection_mark_unattached_ap(conn, END_STREAM_REASON_NET_UNREACHABLE);
  }
}

/**
 * Return the interval to wait betweeen directory downloads, in seconds.
 */
static INLINE int
get_dir_fetch_period(or_options_t *options)
{
  if (options->DirFetchPeriod)
    /* Value from config file. */
    return options->DirFetchPeriod;
  else if (options->DirPort)
    /* Default for directory server */
    return 20*60;
  else
    /* Default for average user. */
    return 40*60;
}

/**
 * Return the interval to wait betweeen router status downloads, in seconds.
 */
static INLINE int
get_status_fetch_period(or_options_t *options)
{
  if (options->StatusFetchPeriod)
    /* Value from config file. */
    return options->StatusFetchPeriod;
  else if (options->DirPort)
    /* Default for directory server */
    return 15*60;
  else
    /* Default for average user. */
    return 30*60;
}

/** This function is called whenever we successfully pull down some new
 * network statuses or server descriptors. */
void
directory_info_has_arrived(time_t now, int from_cache)
{
  or_options_t *options = get_options();

  if (!router_have_minimum_dir_info()) {
    log(LOG_NOTICE, LD_DIR, "I learned some more directory information, but not enough to build a circuit.");
    return;
  }

  if (!has_fetched_directory) {
    log(LOG_NOTICE, LD_DIR, "We have enough directory information to build circuits.");
  }

  has_fetched_directory=1;

  if (server_mode(options) &&
      !we_are_hibernating()) { /* connect to the appropriate routers */
    if (!authdir_mode(options))
      router_retry_connections(0);
    if (!from_cache)
      consider_testing_reachability();
  }
}

/** Perform regular maintenance tasks for a single connection.  This
 * function gets run once per second per connection by run_scheduled_events.
 */
static void
run_connection_housekeeping(int i, time_t now)
{
  cell_t cell;
  connection_t *conn = connection_array[i];
  or_options_t *options = get_options();

  if (conn->outbuf && !buf_datalen(conn->outbuf))
    conn->timestamp_lastempty = now;

  /* Expire any directory connections that haven't sent anything for 5 min */
  if (conn->type == CONN_TYPE_DIR &&
      !conn->marked_for_close &&
      conn->timestamp_lastwritten + 5*60 < now) {
    info(LD_DIR,"Expiring wedged directory conn (fd %d, purpose %d)",
           conn->s, conn->purpose);
    /* This check is temporary; it's to let us know whether we should consider
     * parsing partial serverdesc responses. */
    if (conn->purpose == DIR_PURPOSE_FETCH_SERVERDESC &&
        buf_datalen(conn->inbuf)>=1024) {
      info(LD_DIR,"Trying to extract information from wedged server desc download.");
      connection_dir_reached_eof(conn);
    } else {
      connection_mark_for_close(conn);
    }
    return;
  }

  /* If we haven't written to an OR connection for a while, then either nuke
     the connection or send a keepalive, depending. */
  if (connection_speaks_cells(conn) &&
      now >= conn->timestamp_lastwritten + options->KeepalivePeriod) {
    routerinfo_t *router = router_get_by_digest(conn->identity_digest);
    if (!connection_state_is_open(conn)) {
      info(LD_OR,"Expiring non-open OR connection to fd %d (%s:%d).",
           conn->s,conn->address, conn->port);
      connection_mark_for_close(conn);
      conn->hold_open_until_flushed = 1;
    } else if (we_are_hibernating() && !circuit_get_by_conn(conn) &&
               !buf_datalen(conn->outbuf)) {
      info(LD_OR,"Expiring non-used OR connection to fd %d (%s:%d) [Hibernating or exiting].",
             conn->s,conn->address, conn->port);
      connection_mark_for_close(conn);
      conn->hold_open_until_flushed = 1;
    } else if (!clique_mode(options) && !circuit_get_by_conn(conn) &&
               (!router || !server_mode(options) || !router_is_clique_mode(router))) {
      info(LD_OR,"Expiring non-used OR connection to fd %d (%s:%d) [Not in clique mode].",
             conn->s,conn->address, conn->port);
      connection_mark_for_close(conn);
      conn->hold_open_until_flushed = 1;
    } else if (
         now >= conn->timestamp_lastempty + options->KeepalivePeriod*10 &&
         now >= conn->timestamp_lastwritten + options->KeepalivePeriod*10) {
      log_fn(LOG_PROTOCOL_WARN,LD_PROTOCOL,"Expiring stuck OR connection to fd %d (%s:%d). (%d bytes to flush; %d seconds since last write)",
             conn->s, conn->address, conn->port,
             (int)buf_datalen(conn->outbuf),
             (int)(now-conn->timestamp_lastwritten));
      connection_mark_for_close(conn);
    } else if (!buf_datalen(conn->outbuf)) {
      /* either in clique mode, or we've got a circuit. send a padding cell. */
      log_fn(LOG_DEBUG,LD_OR,"Sending keepalive to (%s:%d)",
             conn->address, conn->port);
      memset(&cell,0,sizeof(cell_t));
      cell.command = CELL_PADDING;
      connection_or_write_cell_to_buf(&cell, conn);
    }
  }
}

/** Perform regular maintenance tasks.  This function gets run once per
 * second by prepare_for_poll.
 */
static void
run_scheduled_events(time_t now)
{
  static time_t last_rotated_certificate = 0;
  static time_t time_to_check_listeners = 0;
  static time_t time_to_check_descriptor = 0;
  static time_t time_to_check_ipaddress = 0;
  static time_t time_to_shrink_buffers = 0;
  static time_t time_to_try_getting_descriptors = 0;
  static time_t time_to_reset_descriptor_failures = 0;
  static time_t time_to_add_entropy = 0;
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
    info(LD_GENERAL,"Rotating onion key.");
    rotate_onion_key();
    cpuworkers_rotate();
    if (router_rebuild_descriptor(1)<0) {
      warn(LD_BUG, "Couldn't rebuild router descriptor");
    }
    if (advertised_server_mode())
      router_upload_dir_desc_to_dirservers(0);
  }

  if (time_to_try_getting_descriptors < now) {
    update_router_descriptor_downloads(now);
    time_to_try_getting_descriptors = now + DESCRIPTOR_RETRY_INTERVAL;
  }

  if (time_to_reset_descriptor_failures < now) {
    router_reset_descriptor_download_failures();
    time_to_reset_descriptor_failures = now + DESCRIPTOR_FAILURE_RESET_INTERVAL;
  }

  /** 1b. Every MAX_SSL_KEY_LIFETIME seconds, we change our TLS context. */
  if (!last_rotated_certificate)
    last_rotated_certificate = now;
  if (last_rotated_certificate+MAX_SSL_KEY_LIFETIME < now) {
    info(LD_GENERAL,"Rotating tls context.");
    if (tor_tls_context_new(get_identity_key(), 1, options->Nickname,
                            MAX_SSL_KEY_LIFETIME) < 0) {
      warn(LD_BUG, "Error reinitializing TLS context");
      /* XXX is it a bug here, that we just keep going? */
    }
    last_rotated_certificate = now;
    /* XXXX We should rotate TLS connections as well; this code doesn't change
     *      them at all. */
  }

  if (time_to_add_entropy == 0)
    time_to_add_entropy = now + ENTROPY_INTERVAL;
  if (time_to_add_entropy < now) {
    /* We already seeded once, so don't die on failure. */
    crypto_seed_rng();
    time_to_add_entropy = now + ENTROPY_INTERVAL;
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
    routerlist_remove_old_routers();
    networkstatus_list_clean(now);

    if (authdir_mode(options)) {
      if (!we_are_hibernating()) { /* try to determine reachability */
        router_retry_connections(1);
      }
    }

    /* Only caches actually need to fetch directories now. */
    if (options->DirPort && !options->V1AuthoritativeDir) {
      directory_get_from_dirserver(DIR_PURPOSE_FETCH_DIR, NULL, 1);
    }

    time_to_fetch_directory = now + get_dir_fetch_period(options);

    /* Also, take this chance to remove old information from rephist
     * and the rend cache. */
    rep_history_clean(now - options->RephistTrackTime);
    rend_cache_clean();
  }

  /* Caches need to fetch running_routers; directory clients don't. */
  if (options->DirPort && time_to_fetch_running_routers < now) {
    if (!authdir_mode(options) || !options->V1AuthoritativeDir) {
      directory_get_from_dirserver(DIR_PURPOSE_FETCH_RUNNING_LIST, NULL, 1);
    }
    time_to_fetch_running_routers = now + get_status_fetch_period(options);
  }

  /* 2b. Once per minute, regenerate and upload the descriptor if the old
   * one is inaccurate. */
  if (time_to_check_descriptor < now) {
    time_to_check_descriptor = now + CHECK_DESCRIPTOR_INTERVAL;
    check_descriptor_bandwidth_changed(now);
    if (time_to_check_ipaddress < now) {
      time_to_check_ipaddress = now + CHECK_IPADDRESS_INTERVAL;
      check_descriptor_ipaddress_changed(now);
    }
    mark_my_descriptor_dirty_if_older_than(
                                    now - FORCE_REGENERATE_DESCRIPTOR_INTERVAL);
    consider_publishable_server(now, 0);
    /* also, check religiously for reachability, if it's within the first
     * 20 minutes of our uptime. */
    if (server_mode(options) &&
        stats_n_seconds_working < TIMEOUT_UNTIL_UNREACHABILITY_COMPLAINT &&
        !we_are_hibernating())
      consider_testing_reachability();

    /* If any networkstatus documents are no longer recent, we need to
     * update all the descriptors' running status. */
    networkstatus_list_update_recent(now);
    routers_update_all_from_networkstatus();

    /* Also, once per minute, check whether we want to download any
     * networkstatus documents.
     */
    update_networkstatus_downloads(now);
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
    /* 0 means "only launch the ones that died." */
    retry_all_listeners(0, NULL, NULL);
    time_to_check_listeners = now+60;
  }

  /** 4. Every second, we try a new circuit if there are no valid
   *    circuits. Every NewCircuitPeriod seconds, we expire circuits
   *    that became dirty more than MaxCircuitDirtiness seconds ago,
   *    and we make a new circ if there are no clean circuits.
   */
  if (has_fetched_directory && !we_are_hibernating())
    circuit_build_needed_circs(now);

  /** 5. We do housekeeping for each connection... */
  for (i=0;i<nfds;i++) {
    run_connection_housekeeping(i, now);
  }
  if (time_to_shrink_buffers < now) {
    for (i=0;i<nfds;i++) {
      connection_t *conn = connection_array[i];
      if (conn->outbuf)
        buf_shrink(conn->outbuf);
      if (conn->inbuf)
        buf_shrink(conn->inbuf);
    }
    time_to_shrink_buffers = now + BUF_SHRINK_INTERVAL;
  }

  /** 6. And remove any marked circuits... */
  circuit_close_all_marked();

  /** 7. And upload service descriptors if necessary. */
  if (has_fetched_directory && !we_are_hibernating())
    rend_consider_services_upload(now);

  /** 8. and blow away any connections that need to die. have to do this now,
   * because if we marked a conn for close and left its socket -1, then
   * we'll pass it to poll/select and bad things will happen.
   */
  close_closeable_connections();
}

static struct event *timeout_event = NULL;
static int n_libevent_errors = 0;

/** Libevent callback: invoked once every second. */
static void
second_elapsed_callback(int fd, short event, void *args)
{
  static struct timeval one_second;
  static long current_second = 0;
  struct timeval now;
  size_t bytes_written;
  size_t bytes_read;
  int seconds_elapsed;
  or_options_t *options = get_options();
  if (!timeout_event) {
    timeout_event = tor_malloc_zero(sizeof(struct event));
    evtimer_set(timeout_event, second_elapsed_callback, NULL);
    one_second.tv_sec = 1;
    one_second.tv_usec = 0;
  }

  n_libevent_errors = 0;

  /* log_fn(LOG_NOTICE, "Tick."); */
  tor_gettimeofday(&now);

  /* the second has rolled over. check more stuff. */
  bytes_written = stats_prev_global_write_bucket - global_write_bucket;
  bytes_read = stats_prev_global_read_bucket - global_read_bucket;
  /* XXX below we get suspicious if time jumps forward more than 10
   * seconds, but we never notice if it jumps *back* more than 10 seconds.
   * This could be useful for detecting that we just NTP'ed to three
   * weeks ago and it will be 3 weeks and 15 minutes until any of our
   * events trigger.
   */
  seconds_elapsed = current_second ? (now.tv_sec - current_second) : 0;
  stats_n_bytes_read += bytes_read;
  stats_n_bytes_written += bytes_written;
  if (accounting_is_enabled(options))
    accounting_add_bytes(bytes_read, bytes_written, seconds_elapsed);
  control_event_bandwidth_used((uint32_t)bytes_read,(uint32_t)bytes_written);

  connection_bucket_refill(&now);
  stats_prev_global_read_bucket = global_read_bucket;
  stats_prev_global_write_bucket = global_write_bucket;

  if (server_mode(options) &&
      !we_are_hibernating() &&
      stats_n_seconds_working / TIMEOUT_UNTIL_UNREACHABILITY_COMPLAINT !=
      (stats_n_seconds_working+seconds_elapsed) /
        TIMEOUT_UNTIL_UNREACHABILITY_COMPLAINT) {
    /* every 20 minutes, check and complain if necessary */
    routerinfo_t *me = router_get_my_routerinfo();
    if (me && !check_whether_orport_reachable())
      warn(LD_CONFIG,"Your server (%s:%d) has not managed to confirm that its ORPort is reachable. Please check your firewalls, ports, address, /etc/hosts file, etc.",
          me->address, me->or_port);
    if (me && !check_whether_dirport_reachable())
      warn(LD_CONFIG,"Your server (%s:%d) has not managed to confirm that its DirPort is reachable. Please check your firewalls, ports, address, /etc/hosts file, etc.",
          me->address, me->dir_port);
  }

  /* if more than 100s have elapsed, probably the clock jumped: doesn't count. */
  if (seconds_elapsed < 100)
    stats_n_seconds_working += seconds_elapsed;
  else
    circuit_note_clock_jumped(seconds_elapsed);

  run_scheduled_events(now.tv_sec);

  current_second = now.tv_sec; /* remember which second it is, for next time */

#if 0
  if (current_second % 300 == 0) {
    rep_history_clean(current_second - options->RephistTrackTime);
    dumpmemusage(get_min_log_level()<LOG_INFO ? get_min_log_level() : LOG_INFO);
  }
#endif

  if (evtimer_add(timeout_event, &one_second))
    err(LD_NET,
        "Error from libevent when setting one-second timeout event");
}

/** Called when a possibly ignorable libevent error occurs; ensures that we
 * don't get into an infinite loop by ignoring too many errors from
 * libevent. */
static int
got_libevent_error(void)
{
  if (++n_libevent_errors > 8) {
    err(LD_NET, "Too many libevent errors in one second; dying");
    return -1;
  }
  return 0;
}

/** Called when we get a SIGHUP: reload configuration files and keys,
 * retry all connections, re-upload all descriptors, and so on. */
static int
do_hup(void)
{
  char keydir[512];
  or_options_t *options = get_options();

  notice(LD_GENERAL,"Received sighup. Reloading config.");
  has_completed_circuit=0;
  if (accounting_is_enabled(options))
    accounting_record_bandwidth_usage(time(NULL));

  router_reset_warnings();
  routerlist_reset_warnings();
  addressmap_clear_transient();
  /* first, reload config variables, in case they've changed */
  /* no need to provide argc/v, they've been cached inside init_from_config */
  if (options_init_from_torrc(0, NULL) < 0) {
    err(LD_CONFIG,"Reading config failed--see warnings above. For usage, try -h.");
    return -1;
  }
  options = get_options(); /* they have changed now */
  if (authdir_mode(options)) {
    /* reload the approved-routers file */
    tor_snprintf(keydir,sizeof(keydir),"%s/approved-routers", options->DataDirectory);
    info(LD_GENERAL,"Reloading approved fingerprints from \"%s\"...",keydir);
    if (dirserv_parse_fingerprint_file(keydir) < 0) {
      info(LD_GENERAL, "Error reloading fingerprints. Continuing with old list.");
    }
  }

  /* Rotate away from the old dirty circuits. This has to be done
   * after we've read the new options, but before we start using
   * circuits for directory fetches. */
  circuit_expire_all_dirty_circs();

  /* retry appropriate downloads */
  router_reset_status_download_failures();
  router_reset_descriptor_download_failures();
  update_networkstatus_downloads(time(NULL));

  /* We'll retry routerstatus downloads in about 10 seconds; no need to
   * force a retry there. */

  if (server_mode(options)) {
    const char *descriptor;
    /* Restart cpuworker and dnsworker processes, so they get up-to-date
     * configuration options. */
    cpuworkers_rotate();
    dnsworkers_rotate();
    /* Write out a fresh descriptor, but leave old one on failure. */
    router_rebuild_descriptor(1);
    descriptor = router_get_my_descriptor();
    if (descriptor) {
      tor_snprintf(keydir,sizeof(keydir),"%s/router.desc",
                   options->DataDirectory);
      info(LD_OR,"Saving descriptor to \"%s\"...",keydir);
      if (write_str_to_file(keydir, descriptor, 0)) {
        return 0;
      }
    }
  }
  return 0;
}

/** Tor main loop. */
static int
do_main_loop(void)
{
  int loop_result;

  dns_init(); /* initialize dns resolve tree, spawn workers if needed */

  handle_signals(1);

  /* load the private keys, if we're supposed to have them, and set up the
   * TLS context. */
  if (! identity_key_is_set()) {
    if (init_keys() < 0) {
      err(LD_GENERAL,"Error initializing keys; exiting");
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
  /* load the networkstatuses. (This launches a download for new routers as
   * appropriate.)
   */
  if (router_reload_networkstatus()) {
    return -1;
  }
  directory_info_has_arrived(time(NULL),1);

  if (authdir_mode(get_options())) {
    /* the directory is already here, run startup things */
    router_retry_connections(1);
  }

  if (server_mode(get_options())) {
    /* launch cpuworkers. Need to do this *after* we've read the onion key. */
    cpu_init();
  }

  /* set up once-a-second callback. */
  second_elapsed_callback(0,0,NULL);

  for (;;) {
    if (nt_service_is_stopped())
      return 0;

#ifndef MS_WINDOWS
    /* Make it easier to tell whether libevent failure is our fault or not. */
    errno = 0;
#endif
    /* poll until we have an event, or the second ends */
    loop_result = event_dispatch();

    /* let catch() handle things like ^c, and otherwise don't worry about it */
    if (loop_result < 0) {
      int e = tor_socket_errno(-1);
      /* let the program survive things like ^z */
      if (e != EINTR && !ERRNO_IS_EINPROGRESS(e)) {
#ifdef HAVE_EVENT_GET_METHOD
        err(LD_NET,"libevent poll with %s failed: %s [%d]",
               event_get_method(), tor_socket_strerror(e), e);
#else
        err(LD_NET,"libevent poll failed: %s [%d]",
               tor_socket_strerror(e), e);
#endif
        return -1;
#ifndef MS_WINDOWS
      } else if (e == EINVAL) {
        warn(LD_NET, "EINVAL from libevent: should you upgrade libevent?");
        if (got_libevent_error())
          return -1;
#endif
      } else {
        if (ERRNO_IS_EINPROGRESS(e))
          warn(LD_BUG,"libevent poll returned EINPROGRESS? Please report.");
        debug(LD_NET,"event poll interrupted.");
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
  switch (the_signal)
    {
    case 1:
      signal_callback(0,0,(void*)(uintptr_t)SIGHUP);
      break;
    case 2:
      signal_callback(0,0,(void*)(uintptr_t)SIGINT);
      break;
    case 10:
      signal_callback(0,0,(void*)(uintptr_t)SIGUSR1);
      break;
    case 12:
      signal_callback(0,0,(void*)(uintptr_t)SIGUSR2);
      break;
    case 15:
      signal_callback(0,0,(void*)(uintptr_t)SIGTERM);
      break;
    default:
      return -1;
    }
  return 0;
}

/** Libevent callback: invoked when we get a signal.
 */
static void
signal_callback(int fd, short events, void *arg)
{
  uintptr_t sig = (uintptr_t)arg;
  switch (sig)
    {
    case SIGTERM:
      err(LD_GENERAL,"Catching signal TERM, exiting cleanly.");
      tor_cleanup();
      exit(0);
      break;
    case SIGINT:
      if (!server_mode(get_options())) { /* do it now */
        notice(LD_GENERAL,"Interrupt: exiting cleanly.");
        tor_cleanup();
        exit(0);
      }
      hibernate_begin_shutdown();
      break;
#ifdef SIGPIPE
    case SIGPIPE:
      debug(LD_GENERAL,"Caught sigpipe. Ignoring.");
      break;
#endif
    case SIGUSR1:
      /* prefer to log it at INFO, but make sure we always see it */
      dumpstats(get_min_log_level()<LOG_INFO ? get_min_log_level() : LOG_INFO);
      break;
    case SIGUSR2:
      switch_logs_debug();
      debug(LD_GENERAL,"Caught USR2, going to loglevel debug. Send HUP to change back.");
      break;
    case SIGHUP:
      if (do_hup() < 0) {
        warn(LD_CONFIG,"Restart failed (config error?). Exiting.");
        tor_cleanup();
        exit(1);
      }
      break;
#ifdef SIGCHLD
    case SIGCHLD:
      while (waitpid(-1,NULL,WNOHANG) > 0) ; /* keep reaping until no more zombies */
      break;
#endif
  }
}

/**
 * Write current memory uusage information to the log.
 */
static void
dumpmemusage(int severity)
{
  extern uint64_t buf_total_used;
  extern uint64_t buf_total_alloc;
  extern uint64_t rephist_total_alloc;
  extern uint32_t rephist_total_num;

  log(severity, LD_GENERAL, "In buffers: "U64_FORMAT" used/"U64_FORMAT" allocated (%d conns).",
      U64_PRINTF_ARG(buf_total_used), U64_PRINTF_ARG(buf_total_alloc),
      nfds);
  log(severity, LD_GENERAL, "In rephist: "U64_FORMAT" used by %d Tors.",
      U64_PRINTF_ARG(rephist_total_alloc), rephist_total_num);
}

/** Write all statistics to the log, with log level 'severity'.  Called
 * in response to a SIGUSR1. */
static void
dumpstats(int severity)
{
  int i;
  connection_t *conn;
  time_t now = time(NULL);
  time_t elapsed;

  log(severity, LD_GENERAL, "Dumping stats:");

  for (i=0;i<nfds;i++) {
    conn = connection_array[i];
    log(severity, LD_GENERAL, "Conn %d (socket %d) type %d (%s), state %d (%s), created %d secs ago",
      i, conn->s, conn->type, conn_type_to_string(conn->type),
        conn->state, conn_state_to_string(conn->type, conn->state), (int)(now - conn->timestamp_created));
    if (!connection_is_listener(conn)) {
      log(severity,LD_GENERAL,"Conn %d is to '%s:%d'.",i,safe_str(conn->address), conn->port);
      log(severity,LD_GENERAL, "Conn %d: %d bytes waiting on inbuf (len %d, last read %d secs ago)",i,
             (int)buf_datalen(conn->inbuf),
             (int)buf_capacity(conn->inbuf),
             (int)(now - conn->timestamp_lastread));
      log(severity,LD_GENERAL, "Conn %d: %d bytes waiting on outbuf (len %d, last written %d secs ago)",i,
             (int)buf_datalen(conn->outbuf),
             (int)buf_capacity(conn->outbuf),
             (int)(now - conn->timestamp_lastwritten));
    }
    circuit_dump_by_conn(conn, severity); /* dump info about all the circuits using this conn */
  }
  log(severity, LD_NET,
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
    log(severity,LD_NET,"Average packaged cell fullness: %2.3f%%",
           100*(((double)stats_n_data_bytes_packaged) /
                (stats_n_data_cells_packaged*RELAY_PAYLOAD_SIZE)) );
  if (stats_n_data_cells_received)
    log(severity,LD_NET,"Average delivered cell fullness: %2.3f%%",
           100*(((double)stats_n_data_bytes_received) /
                (stats_n_data_cells_received*RELAY_PAYLOAD_SIZE)) );

  if (now - time_of_process_start >= 0)
    elapsed = now - time_of_process_start;
  else
    elapsed = 0;

  if (elapsed) {
    log(severity, LD_NET,
        "Average bandwidth: "U64_FORMAT"/%d = %d bytes/sec reading",
        U64_PRINTF_ARG(stats_n_bytes_read),
        (int)elapsed,
        (int) (stats_n_bytes_read/elapsed));
    log(severity, LD_NET,
        "Average bandwidth: "U64_FORMAT"/%d = %d bytes/sec writing",
        U64_PRINTF_ARG(stats_n_bytes_written),
        (int)elapsed,
        (int) (stats_n_bytes_written/elapsed));
  }

  log(severity, LD_NET, "--------------- Dumping memory information:");
  dumpmemusage(severity);

  rep_hist_dump_stats(now,severity);
  rend_service_dump_stats(severity);
}

/** Called by exit() as we shut down the process.
 */
static void
exit_function(void)
{
  /* NOTE: If we ever daemonize, this gets called immediately.  That's
   * okay for now, because we only use this on Windows.  */
#ifdef MS_WINDOWS
  WSACleanup();
#endif
}

/** Set up the signal handlers for either parent or child. */
void
handle_signals(int is_parent)
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
                 (void*)(uintptr_t)signals[i]);
      if (signal_add(&signal_events[i], NULL))
        warn(LD_BUG, "Error from libevent when adding event for signal %d",
               signals[i]);
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
  }
#endif /* signal stuff */
}

/** Main entry point for the Tor command-line client.
 */
static int
tor_init(int argc, char *argv[])
{
  time_of_process_start = time(NULL);
  if (!closeable_connection_lst)
    closeable_connection_lst = smartlist_create();
  /* Initialize the history structures. */
  rep_hist_init();
  /* Initialize the service cache. */
  rend_cache_init();
  addressmap_init(); /* Init the client dns cache. Do it always, since it's cheap. */

  /* give it somewhere to log to initially */
  add_temp_log();

  log(LOG_NOTICE, LD_GENERAL, "Tor v%s. This is experimental software. Do not rely on it for strong anonymity.",VERSION);

  if (network_init()<0) {
    err(LD_NET,"Error initializing network; exiting.");
    return -1;
  }
  atexit(exit_function);

  if (options_init_from_torrc(argc,argv) < 0) {
    err(LD_CONFIG,"Reading config failed--see warnings above. For usage, try -h.");
    return -1;
  }

#ifndef MS_WINDOWS
  if (geteuid()==0)
    warn(LD_GENERAL,"You are running Tor as root. You don't need to, and you probably shouldn't.");
#endif

  crypto_global_init(get_options()->HardwareAccel);
  if (crypto_seed_rng()) {
    err(LD_BUG, "Unable to seed random number generator. Exiting.");
    return -1;
  }

  return 0;
}

/** Free all memory that we might have allocated somewhere.
 * Helps us find the real leaks with dmalloc and the like.
 *
 * Also valgrind should then report 0 reachable in its
 * leak report */
void
tor_free_all(int postfork)
{
  routerlist_free_all();
  addressmap_free_all();
  set_exit_redirects(NULL); /* free the registered exit redirects */
  free_socks_policy();
  free_dir_policy();
  dirserv_free_all();
  rend_service_free_all();
  rend_cache_free_all();
  rep_hist_free_all();
  dns_free_all();
  clear_pending_onions();
  circuit_free_all();
  helper_nodes_free_all();
  connection_free_all();
  if (!postfork) {
    config_free_all();
    router_free_all();
  }
  tor_tls_free_all();
  /* stuff in main.c */
  smartlist_free(closeable_connection_lst);
  tor_free(timeout_event);

  if (!postfork) {
    close_logs(); /* free log strings. do this last so logs keep working. */
  }
}

/** Do whatever cleanup is necessary before shutting Tor down. */
void
tor_cleanup(void)
{
  or_options_t *options = get_options();
  /* Remove our pid file. We don't care if there was an error when we
   * unlink, nothing we could do about it anyways. */
  if (options->PidFile && options->command == CMD_RUN_TOR)
    unlink(options->PidFile);
  if (accounting_is_enabled(options))
    accounting_record_bandwidth_usage(time(NULL));
  tor_free_all(0); /* move tor_free_all back into the ifdef below later. XXX*/
  crypto_global_cleanup();
#ifdef USE_DMALLOC
  dmalloc_log_unfreed();
  dmalloc_shutdown();
#endif
}

/** Read/create keys as needed, and echo our fingerprint to stdout. */
static void
do_list_fingerprint(void)
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
    err(LD_BUG,"Error initializing keys; exiting");
    return;
  }
  if (!(k = get_identity_key())) {
    err(LD_GENERAL,"Error: missing identity key.");
    return;
  }
  if (crypto_pk_get_fingerprint(k, buf, 1)<0) {
    warn(LD_BUG, "Error computing fingerprint");
    return;
  }
  printf("%s %s\n", nickname, buf);
}

/** Entry point for password hashing: take the desired password from
 * the command line, and print its salted hash to stdout. **/
static void
do_hash_password(void)
{

  char output[256];
  char key[S2K_SPECIFIER_LEN+DIGEST_LEN];

  crypto_rand(key, S2K_SPECIFIER_LEN-1);
  key[S2K_SPECIFIER_LEN-1] = (uint8_t)96; /* Hash 64 K of data. */
  secret_to_key(key+S2K_SPECIFIER_LEN, DIGEST_LEN,
                get_options()->command_arg, strlen(get_options()->command_arg),
                key);
  base16_encode(output, sizeof(output), key, sizeof(key));
  printf("16:%s\n",output);
}

#ifdef MS_WINDOWS_SERVICE
/** Checks if torrc is present in the same directory
 *  as the service executable.
 *  Return 1 if it is, 0 if it is not present. */
static int
nt_torrc_is_present()
{
  HANDLE hFile;
  TCHAR szPath[_MAX_PATH];
  TCHAR szDrive[_MAX_DRIVE];
  TCHAR szDir[_MAX_DIR];
  char torrc[] = "torrc";
  char *path_to_torrc;
  int len = 0;

  /* Get the service executable path */
  if (0 == GetModuleFileName(NULL, szPath, MAX_PATH))
    return 0;
  _tsplitpath(szPath, szDrive, szDir, NULL, NULL);

  /* Build the path to the torrc file */
  len = _MAX_PATH + _MAX_DRIVE + _MAX_DIR + strlen(torrc) + 1;
  path_to_torrc = tor_malloc(len);
  if (tor_snprintf(path_to_torrc, len, "%s%s%s", szDrive,  szDir, torrc)<0) {
    printf("Failed: tor_snprinf()\n");
    tor_free(path_to_torrc);
    return 0;
  }

  /* See if torrc is present */
  hFile = CreateFile(TEXT(path_to_torrc),
                     GENERIC_READ, FILE_SHARE_READ, NULL,
                     OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                     NULL);

  tor_free(path_to_torrc);

  if (hFile == INVALID_HANDLE_VALUE) {
    return 0;
  }
  CloseHandle(hFile);
  return 1;
}

/** If we're compile to run as an NT service, and the service has been
 * shut down, then change our current status and return 1.  Else
 * return 0.
 */
static int
nt_service_is_stopped(void)
{
  if (service_status.dwCurrentState == SERVICE_STOP_PENDING) {
    service_status.dwWin32ExitCode = 0;
    service_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(hStatus, &service_status);
    return 1;
  } else if (service_status.dwCurrentState == SERVICE_STOPPED) {
    return 1;
  }
  return 0;
}

/** DOCDOC */
void
nt_service_control(DWORD request)
{
  static struct timeval exit_now;
  exit_now.tv_sec  = 0;
  exit_now.tv_usec = 0;

  switch (request) {
    case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
          err(LD_GENERAL, "Got stop/shutdown request; shutting down cleanly.");
          service_status.dwCurrentState = SERVICE_STOP_PENDING;
          event_loopexit(&exit_now);
          return;
  }
  SetServiceStatus(hStatus, &service_status);
}

/** DOCDOC */
void
nt_service_body(int argc, char **argv)
{
  int r;
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

  // check for torrc
  if (nt_torrc_is_present()) {
    r = tor_init(backup_argc, backup_argv); // refactor this part out of tor_main and do_main_loop
    if (r) {
      r = NT_SERVICE_ERROR_TORINIT_FAILED;
    }
  }
  else {
    err(LD_CONFIG, "torrc is not in the current working directory. The Tor service will not start.");
    r = NT_SERVICE_ERROR_NO_TORRC;
  }

  if (r) {
    // failed.
    service_status.dwCurrentState = SERVICE_STOPPED;
    service_status.dwWin32ExitCode = r;
    service_status.dwServiceSpecificExitCode = r;
    SetServiceStatus(hStatus, &service_status);
    return;
  }
  service_status.dwCurrentState = SERVICE_RUNNING;
  SetServiceStatus(hStatus, &service_status);
  do_main_loop();
  tor_cleanup();
  return;
}

/** DOCDOC */
void
nt_service_main(void)
{
  SERVICE_TABLE_ENTRY table[2];
  DWORD result = 0;
  char *errmsg;
  table[0].lpServiceName = GENSRV_SERVICENAME;
  table[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)nt_service_body;
  table[1].lpServiceName = NULL;
  table[1].lpServiceProc = NULL;

  if (!StartServiceCtrlDispatcher(table)) {
    result = GetLastError();
    errmsg = nt_strerror(result);
    printf("Service error %d : %s\n", result, errmsg);
    LocalFree(errmsg);
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
      case CMD_VERIFY_CONFIG:
        printf("Configuration was valid\n");
        break;
      default:
        err(LD_CONFIG, "Illegal command number %d: internal error.", get_options()->command);
      }
      tor_cleanup();
    }
  }
}

/** DOCDOC */
SC_HANDLE
nt_service_open_scm(void)
{
  SC_HANDLE hSCManager;
  char *errmsg = NULL;

  if ((hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE)) == NULL) {
    errmsg = nt_strerror(GetLastError());
    printf("OpenSCManager() failed : %s\n", errmsg);
    LocalFree(errmsg);
  }
  return hSCManager;
}

/** DOCDOC */
SC_HANDLE
nt_service_open(SC_HANDLE hSCManager)
{
  SC_HANDLE hService;
  char *errmsg = NULL;

  if ((hService = OpenService(hSCManager, GENSRV_SERVICENAME, SERVICE_ALL_ACCESS)) == NULL) {
    errmsg = nt_strerror(GetLastError());
    printf("OpenService() failed : %s\n", errmsg);
    LocalFree(errmsg);
  }
  return hService;
}

/** DOCDOC */
int
nt_service_start(SC_HANDLE hService)
{
  char *errmsg = NULL;

  QueryServiceStatus(hService, &service_status);
  if (service_status.dwCurrentState == SERVICE_RUNNING) {
    printf("Service is already running\n");
    return 1;
  }

  if (StartService(hService, 0, NULL)) {
    /* Loop until the service has finished attempting to start */
    while (QueryServiceStatus(hService, &service_status)) {
      if (service_status.dwCurrentState == SERVICE_START_PENDING)
        Sleep(500);
      else
        break;
    }

    /* Check if it started successfully or not */
    if (service_status.dwCurrentState == SERVICE_RUNNING) {
      printf("Service started successfully\n");
      return 1;
    }
    else {
      errmsg = nt_strerror(service_status.dwWin32ExitCode);
      printf("Service failed to start : %s\n", errmsg);
      LocalFree(errmsg);
    }
  }
  else {
    errmsg = nt_strerror(GetLastError());
    printf("StartService() failed : %s\n", errmsg);
    LocalFree(errmsg);
  }
  return 0;
}

/** DOCDOC */
int
nt_service_stop(SC_HANDLE hService)
{
  char *errmsg = NULL;

  QueryServiceStatus(hService, &service_status);
  if (service_status.dwCurrentState == SERVICE_STOPPED) {
    printf("Service is already stopped\n");
    return 1;
  }

  if (ControlService(hService, SERVICE_CONTROL_STOP, &service_status)) {
    while (QueryServiceStatus(hService, &service_status)) {
      if (service_status.dwCurrentState == SERVICE_STOP_PENDING)
        Sleep(500);
      else
        break;
    }
    if (service_status.dwCurrentState == SERVICE_STOPPED) {
      printf("Service stopped successfully\n");
      return 1;
    }
    else {
      errmsg = nt_strerror(GetLastError());
      printf("Service failed to stop : %s\n");
      LocalFree(errmsg);
    }
  }
  else {
    errmsg = nt_strerror(GetLastError());
    printf("ControlService() failed : %s\n", errmsg);
    LocalFree(errmsg);
  }
  return 0;
}

/** DOCDOC */
int
nt_service_install(void)
{
  /* XXXX Problems with NT services:
   * 1. The configuration file needs to be in the same directory as the .exe
   *
   * 2. The exe and the configuration file can't be on any directory path
   *    that contains a space.
   *    mje - you can quote the string (i.e., "c:\program files")
   *
   * 3. Ideally, there should be one EXE that can either run as a
   *    separate process (as now) or that can install and run itself
   *    as an NT service.  I have no idea how hard this is.
   *    mje - should be done. It can install and run itself as a service
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
  SERVICE_DESCRIPTION sdBuff;
  TCHAR szPath[_MAX_PATH];
  TCHAR szDrive[_MAX_DRIVE];
  TCHAR szDir[_MAX_DIR];
  char cmd1[] = " -f ";
  char cmd2[] = "\\torrc";
  char *command;
  char *errmsg;
  int len = 0;

  if (0 == GetModuleFileName(NULL, szPath, MAX_PATH))
    return 0;

  _tsplitpath(szPath, szDrive, szDir, NULL, NULL);

  /* Account for the extra quotes */
  //len = _MAX_PATH + strlen(cmd1) + _MAX_DRIVE + _MAX_DIR + strlen(cmd2);
  len = _MAX_PATH + strlen(cmd1) + _MAX_DRIVE + _MAX_DIR + strlen(cmd2) + 64;
  command = tor_malloc(len);

  /* Create a quoted command line, like "c:\with spaces\tor.exe" -f
   * "c:\with spaces\tor.exe"
   */
  if (tor_snprintf(command, len, "\"%s\" --nt-service -f \"%s%storrc\"",
                   szPath,  szDrive, szDir)<0) {
    printf("Failed: tor_snprinf()\n");
    tor_free(command);
    return 0;
  }

  if ((hSCManager = nt_service_open_scm()) == NULL) {
    tor_free(command);
    return 0;
  }

  /* 1/26/2005 mje
   * - changed the service start type to auto
   * - and changed the lpPassword param to "" instead of NULL as per an
   *   MSDN article.
   */
  if ((hService = CreateService(hSCManager, GENSRV_SERVICENAME, GENSRV_DISPLAYNAME,
                                SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, command,
                                NULL, NULL, NULL, NULL, "")) == NULL) {
    errmsg = nt_strerror(GetLastError());
    printf("CreateService() failed : %s\n", errmsg);
    CloseServiceHandle(hSCManager);
    LocalFree(errmsg);
    tor_free(command);
    return 0;
  }

  /* Set the service's description */
  sdBuff.lpDescription = GENSRV_DESCRIPTION;
  ChangeServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, &sdBuff);
  printf("Service installed successfully\n");

  /* Start the service initially */
  nt_service_start(hService);

  CloseServiceHandle(hService);
  CloseServiceHandle(hSCManager);
  tor_free(command);

  return 0;
}

/** DOCDOC */
int
nt_service_remove(void)
{
  SC_HANDLE hSCManager = NULL;
  SC_HANDLE hService = NULL;
  BOOL result = FALSE;
  char *errmsg;

  if ((hSCManager = nt_service_open_scm()) == NULL) {
    return 0;
  }

  if ((hService = nt_service_open(hSCManager)) == NULL) {
    CloseServiceHandle(hSCManager);
    return 0;
  }

  if (nt_service_stop(hService)) {
    if (DeleteService(hService)) {
      printf("Removed service successfully\n");
    }
    else {
      errmsg = nt_strerror(GetLastError());
      printf("DeleteService() failed : %s\n", errmsg);
      LocalFree(errmsg);
    }
  }
  else {
    printf("Service could not be removed\n");
  }

  CloseServiceHandle(hService);
  CloseServiceHandle(hSCManager);

  return 0;
}

/** DOCDOC */
int
nt_service_cmd_start(void)
{
  SC_HANDLE hSCManager;
  SC_HANDLE hService;
  int start;

  if ((hSCManager = nt_service_open_scm()) == NULL)
    return -1;
  if ((hService = nt_service_open(hSCManager)) == NULL) {
    CloseHandle(hSCManager);
    return -1;
  }

  start = nt_service_start(hService);
  CloseHandle(hService);
  CloseHandle(hSCManager);

  return start;
}

/** DOCDOC */
int
nt_service_cmd_stop(void)
{
  SC_HANDLE hSCManager;
  SC_HANDLE hService;
  int stop;

  if ((hSCManager = nt_service_open_scm()) == NULL)
    return -1;
  if ((hService = nt_service_open(hSCManager)) == NULL) {
    CloseHandle(hSCManager);
    return -1;
  }

  stop = nt_service_stop(hService);
  CloseHandle(hService);
  CloseHandle(hSCManager);

  return stop;
}

/** Given a Win32 error code, this attempts to make Windows
 * return a human-readable error message. The char* returned
 * is allocated by Windows, but should be freed with LocalFree()
 * when finished with it. */
static char*
nt_strerror(uint32_t errnum)
{
   char *msgbuf;
   FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                 NULL, errnum, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                 (LPSTR)&msgbuf, 0, NULL);
   return msgbuf;
}
#endif

#ifdef USE_DMALLOC
#include <openssl/crypto.h>
static void
_tor_dmalloc_free(void *p)
{
  tor_free(p);
}
#endif

/** DOCDOC */
int
tor_main(int argc, char *argv[])
{
#ifdef USE_DMALLOC
    int r = CRYPTO_set_mem_ex_functions(_tor_malloc, _tor_realloc, _tor_dmalloc_free);
    notice(LD_CONFIG, "Set up damalloc; returned %d", r);
#endif
#ifdef MS_WINDOWS_SERVICE
  backup_argv = argv;
  backup_argc = argc;
  if ((argc >= 3) && (!strcmp(argv[1], "-service") || !strcmp(argv[1], "--service"))) {
    if (!strcmp(argv[2], "install"))
      return nt_service_install();
    if (!strcmp(argv[2], "remove"))
      return nt_service_remove();
    if (!strcmp(argv[2], "start"))
      return nt_service_cmd_start();
    if (!strcmp(argv[2], "stop"))
      return nt_service_cmd_stop();
    printf("Unrecognized service command '%s'\n", argv[2]);
    return -1;
  }
  // These are left so as not to confuse people who are used to these options
  if (argc >= 2) {
    if (!strcmp(argv[1], "-install") || !strcmp(argv[1], "--install"))
      return nt_service_install();
    if (!strcmp(argv[1], "-remove") || !strcmp(argv[1], "--remove"))
      return nt_service_remove();
    if (!strcmp(argv[1], "-nt-service") || !strcmp(argv[1], "--nt-service")) {
      nt_service_main();
      return 0;
    }
  }
#endif
  if (tor_init(argc, argv)<0)
    return -1;
  switch (get_options()->command) {
  case CMD_RUN_TOR:
#ifdef MS_WINDOWS_SERVICE
    service_status.dwCurrentState = SERVICE_RUNNING;
#endif
    do_main_loop();
    break;
  case CMD_LIST_FINGERPRINT:
    do_list_fingerprint();
    break;
  case CMD_HASH_PASSWORD:
    do_hash_password();
    break;
  case CMD_VERIFY_CONFIG:
    printf("Configuration was valid\n");
    break;
  default:
    warn(LD_BUG,"Illegal command number %d: internal error.",
         get_options()->command);
  }
  tor_cleanup();
  return -1;
}

