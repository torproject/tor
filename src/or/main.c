/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2007, Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char main_c_id[] =
  "$Id$";

/**
 * \file main.c
 * \brief Toplevel module. Handles signals, multiplexes between
 * connections, implements main loop, and drives scheduled events.
 **/

#include "or.h"
#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

void evdns_shutdown(int);

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
/** When do we next launch DNS wildcarding checks? */
static time_t time_to_check_for_correct_dns = 0;

/** How often will we honor SIGNEWNYM requests? */
#define MAX_SIGNEWNYM_RATE 10
/** When did we last process a SIGNEWNYM request? */
static time_t time_of_last_signewnym = 0;
/** Is there a signewnym request we're currently waiting to handle? */
static int signewnym_is_pending = 0;

/** Array of all open connections.  The first n_conns elements are valid. */
static connection_t *connection_array[MAXCONNECTIONS+1] =
        { NULL };
/** List of connections that have been marked for close and need to be freed
 * and removed from connection_array. */
static smartlist_t *closeable_connection_lst = NULL;

static int n_conns=0; /**< Number of connections currently active. */

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
#define GENSRV_DESCRIPTION  \
  TEXT("Provides an anonymous Internet communication system")
#define GENSRV_USERACCT TEXT("NT AUTHORITY\\LocalService")

// Cheating: using the pre-defined error codes, tricks Windows into displaying
//           a semi-related human-readable error message if startup fails as
//           opposed to simply scaring people with Error: 0xffffffff
#define NT_SERVICE_ERROR_TORINIT_FAILED ERROR_EXCEPTION_IN_SERVICE

SERVICE_STATUS service_status;
SERVICE_STATUS_HANDLE hStatus;
/* XXXX This 'backup argv' and 'backup argc' business is an ugly hack. This
 * is a job for arguments, not globals. */
static char **backup_argv;
static int backup_argc;
static int nt_service_is_stopping(void);
static char* nt_strerror(uint32_t errnum);
#else
#define nt_service_is_stopping() (0)
#endif

/** If our router descriptor ever goes this long without being regenerated
 * because something changed, we force an immediate regenerate-and-upload. */
#define FORCE_REGENERATE_DESCRIPTOR_INTERVAL (18*60*60)
/** How often do we check whether part of our router info has changed in a way
 * that would require an upload? */
#define CHECK_DESCRIPTOR_INTERVAL (60)
/** How often do we (as a router) check whether our IP address has changed? */
#define CHECK_IPADDRESS_INTERVAL (15*60)
/** How often do we check buffers for empty space that can be deallocated? */
#define BUF_SHRINK_INTERVAL (60)
/** How often do we check for router descriptors that we should download? */
#define DESCRIPTOR_RETRY_INTERVAL (10)
/** How often do we 'forgive' undownloadable router descriptors and attempt
 * to download them again? */
#define DESCRIPTOR_FAILURE_RESET_INTERVAL (60*60)
/** How often do we add more entropy to OpenSSL's RNG pool? */
#define ENTROPY_INTERVAL (60*60)
/** How long do we let a directory connection stall before expiring it? */
#define DIR_CONN_MAX_STALL (5*60)

/** How old do we let a connection to an OR get before deciding it's
 * obsolete? */
#define TIME_BEFORE_OR_CONN_IS_OBSOLETE (60*60*24*7)
/** How long do we let OR connections handshake before we decide that
 * they are obsolete? */
#define TLS_HANDSHAKE_TIMEOUT           (60)

/********* END VARIABLES ************/

/****************************************************************************
*
* This section contains accessors and other methods on the connection_array
* variables (which are global within this file and unavailable outside it).
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

  if (n_conns >= get_options()->_ConnLimit-1) {
    log_warn(LD_NET,"Failing because we have %d connections already. Please "
             "raise your ulimit -n.", n_conns);
    control_event_general_status(LOG_WARN, "TOO_MANY_CONNECTIONS CURRENT=%d",
                                 n_conns);
    return -1;
  }

  tor_assert(conn->conn_array_index == -1); /* can only connection_add once */
  conn->conn_array_index = n_conns;
  connection_array[n_conns] = conn;

  conn->read_event = tor_malloc_zero(sizeof(struct event));
  conn->write_event = tor_malloc_zero(sizeof(struct event));
  event_set(conn->read_event, conn->s, EV_READ|EV_PERSIST,
            conn_read_callback, conn);
  event_set(conn->write_event, conn->s, EV_WRITE|EV_PERSIST,
            conn_write_callback, conn);

  n_conns++;

  log_debug(LD_NET,"new conn type %s, socket %d, n_conns %d.",
            conn_type_to_string(conn->type), conn->s, n_conns);

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
  tor_assert(n_conns>0);

  log_debug(LD_NET,"removing socket %d (type %s), n_conns now %d",
            conn->s, conn_type_to_string(conn->type), n_conns-1);

  tor_assert(conn->conn_array_index >= 0);
  current_index = conn->conn_array_index;
  if (current_index == n_conns-1) { /* this is the end */
    n_conns--;
    return 0;
  }

  connection_unregister(conn);

  /* replace this one with the one at the end */
  n_conns--;
  connection_array[current_index] = connection_array[n_conns];
  connection_array[current_index]->conn_array_index = current_index;

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
  connection_about_to_close_connection(conn);
  if (remove) {
    connection_remove(conn);
  }
  smartlist_remove(closeable_connection_lst, conn);
  if (conn->type == CONN_TYPE_EXIT) {
    assert_connection_edge_not_dns_pending(TO_EDGE_CONN(conn));
  }
  if (conn->type == CONN_TYPE_OR) {
    if (!tor_digest_is_zero(TO_OR_CONN(conn)->identity_digest))
      connection_or_remove_from_identity_map(TO_OR_CONN(conn));
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
  for (i=0; i<n_conns; ++i) {
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
  *n = n_conns;
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
    log_warn(LD_NET,
             "Error from libevent setting read event state for %d to "
             "%swatched: %s",
             conn->s, (events & EV_READ)?"":"un",
             tor_socket_strerror(tor_socket_errno(conn->s)));

  if (events & EV_WRITE) {
    r = event_add(conn->write_event, NULL);
  } else {
    r = event_del(conn->write_event);
  }

  if (r<0)
    log_warn(LD_NET,
             "Error from libevent setting read event state for %d to "
             "%swatched: %s",
             conn->s, (events & EV_WRITE)?"":"un",
             tor_socket_strerror(tor_socket_errno(conn->s)));
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

  log_debug(LD_NET,"entering.");
  if (event_del(conn->read_event))
    log_warn(LD_NET, "Error from libevent setting read event state for %d "
             "to unwatched: %s",
             conn->s,
             tor_socket_strerror(tor_socket_errno(conn->s)));
}

/** Tell the main loop to start notifying <b>conn</b> of any read events. */
void
connection_start_reading(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->read_event);

  if (event_add(conn->read_event, NULL))
    log_warn(LD_NET, "Error from libevent setting read event state for %d "
             "to watched: %s",
             conn->s,
             tor_socket_strerror(tor_socket_errno(conn->s)));
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
    log_warn(LD_NET, "Error from libevent setting write event state for %d "
             "to unwatched: %s",
             conn->s,
             tor_socket_strerror(tor_socket_errno(conn->s)));
}

/** Tell the main loop to start notifying <b>conn</b> of any write events. */
void
connection_start_writing(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->write_event);

  if (event_add(conn->write_event, NULL))
    log_warn(LD_NET, "Error from libevent setting write event state for %d "
             "to watched: %s",
             conn->s,
             tor_socket_strerror(tor_socket_errno(conn->s)));
}

/** Close all connections that have been scheduled to get closed */
static void
close_closeable_connections(void)
{
  int i;
  for (i = 0; i < smartlist_len(closeable_connection_lst); ) {
    connection_t *conn = smartlist_get(closeable_connection_lst, i);
    if (conn->conn_array_index < 0) {
      connection_unlink(conn, 0); /* blow it away right now */
    } else {
      if (!conn_close_if_marked(conn->conn_array_index))
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
  (void)fd;
  (void)event;

  log_debug(LD_NET,"socket %d wants to read.",conn->s);

  assert_connection_ok(conn, time(NULL));

  if (connection_handle_read(conn) < 0) {
    if (!conn->marked_for_close) {
#ifndef MS_WINDOWS
      log_warn(LD_BUG,"Unhandled error on read for %s connection "
               "(fd %d); removing",
               conn_type_to_string(conn->type), conn->s);
      tor_fragile_assert();
#endif
      if (CONN_IS_EDGE(conn))
        connection_edge_end_errno(TO_EDGE_CONN(conn),
                                  TO_EDGE_CONN(conn)->cpath_layer);
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
  (void)fd;
  (void)events;

  LOG_FN_CONN(conn, (LOG_DEBUG, LD_NET, "socket %d wants to write.",conn->s));

  assert_connection_ok(conn, time(NULL));

  if (connection_handle_write(conn, 0) < 0) {
    if (!conn->marked_for_close) {
      /* this connection is broken. remove it. */
      log_fn(LOG_WARN,LD_BUG,
           "unhandled error on write for %s connection (fd %d); removing",
           conn_type_to_string(conn->type), conn->s);
      tor_fragile_assert();
      if (CONN_IS_EDGE(conn)) {
        /* otherwise we cry wolf about duplicate close */
        edge_connection_t *edge_conn = TO_EDGE_CONN(conn);
        if (!edge_conn->end_reason)
          edge_conn->end_reason = END_STREAM_REASON_INTERNAL;
        conn->edge_has_sent_end = 1;
      }
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

  log_debug(LD_NET,"Cleaning up connection (fd %d).",conn->s);
  if (conn->s >= 0 && connection_wants_to_flush(conn)) {
    /* s == -1 means it's an incomplete edge connection, or that the socket
     * has already been closed as unflushable. */
    int sz = connection_bucket_write_limit(conn);
    if (!conn->hold_open_until_flushed)
      log_info(LD_NET,
               "Conn (addr %s, fd %d, type %s, state %d) marked, but wants "
               "to flush %d bytes. (Marked at %s:%d)",
               escaped_safe_str(conn->address),
               conn->s, conn_type_to_string(conn->type), conn->state,
               (int)conn->outbuf_flushlen,
                conn->marked_for_close_file, conn->marked_for_close);
    if (connection_speaks_cells(conn)) {
      if (conn->state == OR_CONN_STATE_OPEN) {
        retval = flush_buf_tls(TO_OR_CONN(conn)->tls, conn->outbuf, sz,
                               &conn->outbuf_flushlen);
      } else
        retval = -1; /* never flush non-open broken tls connections */
    } else {
      retval = flush_buf(conn->s, conn->outbuf, sz, &conn->outbuf_flushlen);
    }
    if (retval >= 0 && /* Technically, we could survive things like
                          TLS_WANT_WRITE here. But don't bother for now. */
        conn->hold_open_until_flushed && connection_wants_to_flush(conn)) {
      if (retval > 0)
        LOG_FN_CONN(conn, (LOG_INFO,LD_NET,
                           "Holding conn (fd %d) open for more flushing.",
                           conn->s));
      /* XXX should we reset timestamp_lastwritten here? */
      return 0;
    }
    if (connection_wants_to_flush(conn)) {
      int severity;
      if (conn->type == CONN_TYPE_EXIT ||
          (conn->type == CONN_TYPE_OR && server_mode(get_options())) ||
          (conn->type == CONN_TYPE_DIR && conn->purpose == DIR_PURPOSE_SERVER))
        severity = LOG_INFO;
      else
        severity = LOG_NOTICE;
      /* XXXX Maybe allow this to happen a certain amount per hour; it usually
       * is meaningless. */
      log_fn(severity, LD_NET, "We stalled too much while trying to write %d "
             "bytes to addr %s.  If this happens a lot, either "
             "something is wrong with your network connection, or "
             "something is wrong with theirs. "
             "(fd %d, type %s, state %d, marked at %s:%d).",
             (int)buf_datalen(conn->outbuf),
             escaped_safe_str(conn->address), conn->s,
             conn_type_to_string(conn->type), conn->state,
             conn->marked_for_close_file,
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
  (void)now;

  stats_n_seconds_working=0; /* reset it */

  while ((conn = connection_get_by_type_state(CONN_TYPE_AP,
                                              AP_CONN_STATE_CIRCUIT_WAIT))) {
    edge_connection_t *edge_conn = TO_EDGE_CONN(conn);
    log_notice(LD_NET,
               "Is your network connection down? "
               "Failing connection to '%s:%d'.",
               safe_str(edge_conn->socks_request->address),
               edge_conn->socks_request->port);
    connection_mark_unattached_ap(edge_conn,
                                  END_STREAM_REASON_NET_UNREACHABLE);
  }
  control_event_general_status(LOG_ERR, "DIR_ALL_UNREACHABLE");
}

/** This function is called whenever we successfully pull down some new
 * network statuses or server descriptors. */
void
directory_info_has_arrived(time_t now, int from_cache)
{
  or_options_t *options = get_options();

  if (!router_have_minimum_dir_info()) {
    log(LOG_NOTICE, LD_DIR,
        "I learned some more directory information, but not enough to "
        "build a circuit.");
    update_router_descriptor_downloads(now);
    return;
  }

  if (server_mode(options) && !we_are_hibernating() && !from_cache &&
      (has_completed_circuit || !any_predicted_circuits(now)))
    consider_testing_reachability(1, 1);
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
  or_connection_t *or_conn;

  if (conn->outbuf && !buf_datalen(conn->outbuf) && conn->type == CONN_TYPE_OR)
    TO_OR_CONN(conn)->timestamp_lastempty = now;

  if (conn->marked_for_close) {
    /* nothing to do here */
    return;
  }

  /* Expire any directory connections that haven't been active (sent
   * if a server or received if a client) for 5 min */
  if (conn->type == CONN_TYPE_DIR &&
      ((DIR_CONN_IS_SERVER(conn) &&
        conn->timestamp_lastwritten + DIR_CONN_MAX_STALL < now) ||
       (!DIR_CONN_IS_SERVER(conn) &&
        conn->timestamp_lastread + DIR_CONN_MAX_STALL < now))) {
    log_info(LD_DIR,"Expiring wedged directory conn (fd %d, purpose %d)",
             conn->s, conn->purpose);
    /* This check is temporary; it's to let us know whether we should consider
     * parsing partial serverdesc responses. */
    if (conn->purpose == DIR_PURPOSE_FETCH_SERVERDESC &&
        buf_datalen(conn->inbuf)>=1024) {
      log_info(LD_DIR,"Trying to extract information from wedged server desc "
               "download.");
      connection_dir_reached_eof(TO_DIR_CONN(conn));
    } else {
      connection_mark_for_close(conn);
    }
    return;
  }

  if (!connection_speaks_cells(conn))
    return; /* we're all done here, the rest is just for OR conns */

  or_conn = TO_OR_CONN(conn);

  if (!conn->or_is_obsolete) {
    if (conn->timestamp_created + TIME_BEFORE_OR_CONN_IS_OBSOLETE < now) {
      log_info(LD_OR,
               "Marking OR conn to %s:%d obsolete (fd %d, %d secs old).",
               conn->address, conn->port, conn->s,
               (int)(now - conn->timestamp_created));
      conn->or_is_obsolete = 1;
    } else {
      or_connection_t *best =
        connection_or_get_by_identity_digest(or_conn->identity_digest);
      if (best && best != or_conn &&
          (conn->state == OR_CONN_STATE_OPEN ||
           now > conn->timestamp_created + TLS_HANDSHAKE_TIMEOUT)) {
          /* We only mark as obsolete connections that already are in
           * OR_CONN_STATE_OPEN, i.e. that have finished their TLS handshaking.
           * This is necessary because authorities judge whether a router is
           * reachable based on whether they were able to TLS handshake with it
           * recently.  Without this check we would expire connections too
           * early for router->last_reachable to be updated.
           */
        log_info(LD_OR,
                 "Marking duplicate conn to %s:%d obsolete "
                 "(fd %d, %d secs old).",
                 conn->address, conn->port, conn->s,
                 (int)(now - conn->timestamp_created));
        conn->or_is_obsolete = 1;
      }
    }
  }

  if (conn->or_is_obsolete && !or_conn->n_circuits) {
    /* no unmarked circs -- mark it now */
    log_info(LD_OR,
             "Expiring non-used OR connection to fd %d (%s:%d) [Obsolete].",
             conn->s, conn->address, conn->port);
    connection_mark_for_close(conn);
    conn->hold_open_until_flushed = 1;
    return;
  }

  /* If we haven't written to an OR connection for a while, then either nuke
     the connection or send a keepalive, depending. */
  if (now >= conn->timestamp_lastwritten + options->KeepalivePeriod) {
    routerinfo_t *router = router_get_by_digest(or_conn->identity_digest);
    if (!connection_state_is_open(conn)) {
      log_info(LD_OR,"Expiring non-open OR connection to fd %d (%s:%d).",
               conn->s,conn->address, conn->port);
      connection_mark_for_close(conn);
      conn->hold_open_until_flushed = 1;
    } else if (we_are_hibernating() && !or_conn->n_circuits &&
               !buf_datalen(conn->outbuf)) {
      log_info(LD_OR,"Expiring non-used OR connection to fd %d (%s:%d) "
               "[Hibernating or exiting].",
               conn->s,conn->address, conn->port);
      connection_mark_for_close(conn);
      conn->hold_open_until_flushed = 1;
    } else if (!clique_mode(options) && !or_conn->n_circuits &&
               (!router || !server_mode(options) ||
                !router_is_clique_mode(router))) {
      log_info(LD_OR,"Expiring non-used OR connection to fd %d (%s:%d) "
               "[Not in clique mode].",
               conn->s,conn->address, conn->port);
      connection_mark_for_close(conn);
      conn->hold_open_until_flushed = 1;
    } else if (
         now >= or_conn->timestamp_lastempty + options->KeepalivePeriod*10 &&
         now >= conn->timestamp_lastwritten + options->KeepalivePeriod*10) {
      log_fn(LOG_PROTOCOL_WARN,LD_PROTOCOL,
             "Expiring stuck OR connection to fd %d (%s:%d). (%d bytes to "
             "flush; %d seconds since last write)",
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
      connection_or_write_cell_to_buf(&cell, or_conn);
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
  int have_dir_info;

  /** 0. See if we've been asked to shut down and our timeout has
   * expired; or if our bandwidth limits are exhausted and we
   * should hibernate; or if it's time to wake up from hibernation.
   */
  consider_hibernation(now);

  /* 0b. If we've deferred a signewnym, make sure it gets handled
   * eventually */
  if (signewnym_is_pending &&
      time_of_last_signewnym + MAX_SIGNEWNYM_RATE <= now) {
    log(LOG_INFO, LD_CONTROL, "Honoring delayed NEWNYM request");
    circuit_expire_all_dirty_circs();
    addressmap_clear_transient();
    time_of_last_signewnym = now;
    signewnym_is_pending = 0;
  }

  /** 1a. Every MIN_ONION_KEY_LIFETIME seconds, rotate the onion keys,
   *  shut down and restart all cpuworkers, and update the directory if
   *  necessary.
   */
  if (server_mode(options) &&
      get_onion_key_set_at()+MIN_ONION_KEY_LIFETIME < now) {
    log_info(LD_GENERAL,"Rotating onion key.");
    rotate_onion_key();
    cpuworkers_rotate();
    if (router_rebuild_descriptor(1)<0) {
      log_info(LD_CONFIG, "Couldn't rebuild router descriptor");
    }
    if (advertised_server_mode())
      router_upload_dir_desc_to_dirservers(0);
  }

  if (time_to_try_getting_descriptors < now) {
    /* XXXX  Maybe we should do this every 10sec when not enough info,
     * and every 60sec when we have enough info -NM */
    update_router_descriptor_downloads(now);
    time_to_try_getting_descriptors = now + DESCRIPTOR_RETRY_INTERVAL;
  }

  if (time_to_reset_descriptor_failures < now) {
    router_reset_descriptor_download_failures();
    time_to_reset_descriptor_failures =
      now + DESCRIPTOR_FAILURE_RESET_INTERVAL;
  }

  /** 1b. Every MAX_SSL_KEY_LIFETIME seconds, we change our TLS context. */
  if (!last_rotated_certificate)
    last_rotated_certificate = now;
  if (last_rotated_certificate+MAX_SSL_KEY_LIFETIME < now) {
    log_info(LD_GENERAL,"Rotating tls context.");
    if (tor_tls_context_new(get_identity_key(), options->Nickname,
                            MAX_SSL_KEY_LIFETIME) < 0) {
      log_warn(LD_BUG, "Error reinitializing TLS context");
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

  if (now % 10 == 0 && authdir_mode(options) && !we_are_hibernating()) {
    /* try to determine reachability of the other Tor servers */
    dirserv_test_reachability(0);
  }

  /** 2. Periodically, we consider getting a new directory, getting a
   * new running-routers list, and/or force-uploading our descriptor
   * (if we've passed our internal checks). */
  if (time_to_fetch_directory < now) {
    /* Only caches actually need to fetch directories now. */
    if (options->DirPort && !options->V1AuthoritativeDir) {
      /* XXX actually, we should only do this if we want to advertise
       * our dirport. not simply if we configured one. -RD */
      if (any_trusted_dir_is_v1_authority())
        directory_get_from_dirserver(DIR_PURPOSE_FETCH_DIR, NULL, 1);
    }
/** How often do we (as a cache) fetch a new V1 directory? */
#define V1_DIR_FETCH_PERIOD (6*60*60)
    time_to_fetch_directory = now + V1_DIR_FETCH_PERIOD;
  }

  /* Caches need to fetch running_routers; directory clients don't. */
  if (options->DirPort && time_to_fetch_running_routers < now) {
    if (!authdir_mode(options) || !options->V1AuthoritativeDir) {
      directory_get_from_dirserver(DIR_PURPOSE_FETCH_RUNNING_LIST, NULL, 1);
    }
/** How often do we (as a cache) fetch a new V1 runningrouters document? */
#define V1_RUNNINGROUTERS_FETCH_PERIOD (30*60)
    time_to_fetch_running_routers = now + V1_RUNNINGROUTERS_FETCH_PERIOD;

     /* Also, take this chance to remove old information from rephist
     * and the rend cache. */
    rep_history_clean(now - options->RephistTrackTime);
    rend_cache_clean();
 }

  /* 2b. Once per minute, regenerate and upload the descriptor if the old
   * one is inaccurate. */
  if (time_to_check_descriptor < now) {
    static int dirport_reachability_count = 0;
    time_to_check_descriptor = now + CHECK_DESCRIPTOR_INTERVAL;
    check_descriptor_bandwidth_changed(now);
    if (time_to_check_ipaddress < now) {
      time_to_check_ipaddress = now + CHECK_IPADDRESS_INTERVAL;
      check_descriptor_ipaddress_changed(now);
    }
    mark_my_descriptor_dirty_if_older_than(
                                  now - FORCE_REGENERATE_DESCRIPTOR_INTERVAL);
    consider_publishable_server(0);
    /* also, check religiously for reachability, if it's within the first
     * 20 minutes of our uptime. */
    if (server_mode(options) &&
        (has_completed_circuit || !any_predicted_circuits(now)) &&
        stats_n_seconds_working < TIMEOUT_UNTIL_UNREACHABILITY_COMPLAINT &&
        !we_are_hibernating()) {
      consider_testing_reachability(1, dirport_reachability_count==0);
      if (++dirport_reachability_count > 5)
        dirport_reachability_count = 0;
    }

    /* If any networkstatus documents are no longer recent, we need to
     * update all the descriptors' running status. */
    /* purge obsolete entries */
    routerlist_remove_old_routers();
    networkstatus_list_clean(now);
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
  have_dir_info = router_have_minimum_dir_info();
  if (have_dir_info && !we_are_hibernating())
    circuit_build_needed_circs(now);

  /** 5. We do housekeeping for each connection... */
  for (i=0;i<n_conns;i++) {
    run_connection_housekeeping(i, now);
  }
  if (time_to_shrink_buffers < now) {
    for (i=0;i<n_conns;i++) {
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
  if (has_completed_circuit && !we_are_hibernating())
    rend_consider_services_upload(now);

  /** 8. and blow away any connections that need to die. have to do this now,
   * because if we marked a conn for close and left its socket -1, then
   * we'll pass it to poll/select and bad things will happen.
   */
  close_closeable_connections();

  /** 8b. And if anything in our state is ready to get flushed to disk, we
   * flush it. */
  or_state_save(now);

  /** 9. and if we're a server, check whether our DNS is telling stories to
   * us. */
  if (server_mode(options) && time_to_check_for_correct_dns < now) {
    if (!time_to_check_for_correct_dns) {
      time_to_check_for_correct_dns = now + 60 + crypto_rand_int(120);
    } else {
      dns_launch_correctness_checks();
      time_to_check_for_correct_dns = now + 12*3600 +
        crypto_rand_int(12*3600);
    }
  }
}

/** Libevent timer: used to invoke second_elapsed_callback() once per
 * second. */
static struct event *timeout_event = NULL;
/** Number of libevent errors in the last second: we die if we get too many. */
static int n_libevent_errors = 0;

/** Libevent callback: invoked once every second. */
static void
second_elapsed_callback(int fd, short event, void *args)
{
  /* XXXX This could be sensibly refactored into multiple callbacks, and we
   * could use libevent's timers for this rather than checking the current
   * time against a bunch of timeouts every second. */
  static struct timeval one_second;
  static long current_second = 0;
  struct timeval now;
  size_t bytes_written;
  size_t bytes_read;
  int seconds_elapsed;
  or_options_t *options = get_options();
  (void)fd;
  (void)event;
  (void)args;
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
  seconds_elapsed = current_second ? (now.tv_sec - current_second) : 0;
  stats_n_bytes_read += bytes_read;
  stats_n_bytes_written += bytes_written;
  if (accounting_is_enabled(options) && seconds_elapsed >= 0)
    accounting_add_bytes(bytes_read, bytes_written, seconds_elapsed);
  control_event_bandwidth_used((uint32_t)bytes_read,(uint32_t)bytes_written);
  control_event_stream_bandwidth_used();

  if (seconds_elapsed > 0)
    connection_bucket_refill(seconds_elapsed);
  stats_prev_global_read_bucket = global_read_bucket;
  stats_prev_global_write_bucket = global_write_bucket;

  if (server_mode(options) &&
      !we_are_hibernating() &&
      seconds_elapsed > 0 &&
      stats_n_seconds_working / TIMEOUT_UNTIL_UNREACHABILITY_COMPLAINT !=
      (stats_n_seconds_working+seconds_elapsed) /
        TIMEOUT_UNTIL_UNREACHABILITY_COMPLAINT) {
    /* every 20 minutes, check and complain if necessary */
    routerinfo_t *me = router_get_my_routerinfo();
    if (me && !check_whether_orport_reachable())
      log_warn(LD_CONFIG,"Your server (%s:%d) has not managed to confirm that "
               "its ORPort is reachable. Please check your firewalls, ports, "
               "address, /etc/hosts file, etc.",
               me->address, me->or_port);
    if (me && !check_whether_dirport_reachable())
      log_warn(LD_CONFIG,
               "Your server (%s:%d) has not managed to confirm that its "
               "DirPort is reachable. Please check your firewalls, ports, "
               "address, /etc/hosts file, etc.",
               me->address, me->dir_port);
  }

/** If more than this many seconds have elapsed, probably the clock
 * jumped: doesn't count. */
#define NUM_JUMPED_SECONDS_BEFORE_WARN 100
  if (seconds_elapsed < -NUM_JUMPED_SECONDS_BEFORE_WARN ||
      seconds_elapsed >= NUM_JUMPED_SECONDS_BEFORE_WARN) {
    circuit_note_clock_jumped(seconds_elapsed);
    /* XXX if the time jumps *back* many months, do our events in
     * run_scheduled_events() recover? I don't think they do. -RD */
  } else if (seconds_elapsed > 0)
    stats_n_seconds_working += seconds_elapsed;

  run_scheduled_events(now.tv_sec);

  current_second = now.tv_sec; /* remember which second it is, for next time */

#if 0
  if (current_second % 300 == 0) {
    rep_history_clean(current_second - options->RephistTrackTime);
    dumpmemusage(get_min_log_level()<LOG_INFO ?
                 get_min_log_level() : LOG_INFO);
  }
#endif

  if (evtimer_add(timeout_event, &one_second))
    log_err(LD_NET,
            "Error from libevent when setting one-second timeout event");
}

#ifndef MS_WINDOWS
/** Called when a possibly ignorable libevent error occurs; ensures that we
 * don't get into an infinite loop by ignoring too many errors from
 * libevent. */
static int
got_libevent_error(void)
{
  if (++n_libevent_errors > 8) {
    log_err(LD_NET, "Too many libevent errors in one second; dying");
    return -1;
  }
  return 0;
}
#endif

#define UPTIME_CUTOFF_FOR_NEW_BANDWIDTH_TEST (6*60*60)

/** Called when our IP address seems to have changed. <b>at_interface</b>
 * should be true if we detected a change in our interface, and false if we
 * detected a change in our published address. */
void
ip_address_changed(int at_interface)
{
  int server = server_mode(get_options());

  if (at_interface) {
    if (! server) {
      /* Okay, change our keys. */
      init_keys();
    }
  } else {
    if (server) {
      if (stats_n_seconds_working > UPTIME_CUTOFF_FOR_NEW_BANDWIDTH_TEST)
        reset_bandwidth_test();
      stats_n_seconds_working = 0;
      router_reset_reachability();
      mark_my_descriptor_dirty();
    }
  }

  dns_servers_relaunch_checks();
}

/** Forget what we've learned about the correctness of our DNS servers, and
 * start learning again. */
void
dns_servers_relaunch_checks(void)
{
  if (server_mode(get_options())) {
    dns_reset_correctness_checks();
    time_to_check_for_correct_dns = 0;
  }
}

/** Called when we get a SIGHUP: reload configuration files and keys,
 * retry all connections, re-upload all descriptors, and so on. */
static int
do_hup(void)
{
  or_options_t *options = get_options();

  log_notice(LD_GENERAL,"Received reload signal (hup). Reloading config.");
  if (accounting_is_enabled(options))
    accounting_record_bandwidth_usage(time(NULL), get_or_state());

  router_reset_warnings();
  routerlist_reset_warnings();
  addressmap_clear_transient();
  /* first, reload config variables, in case they've changed */
  /* no need to provide argc/v, they've been cached inside init_from_config */
  if (options_init_from_torrc(0, NULL) < 0) {
    log_err(LD_CONFIG,"Reading config failed--see warnings above. "
            "For usage, try -h.");
    return -1;
  }
  options = get_options(); /* they have changed now */
  if (authdir_mode(options)) {
    /* reload the approved-routers file */
    if (dirserv_load_fingerprint_file() < 0) {
      /* warnings are logged from dirserv_load_fingerprint_file() directly */
      log_info(LD_GENERAL, "Error reloading fingerprints. "
               "Continuing with old list.");
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
//    const char *descriptor;
    mark_my_descriptor_dirty();
    /* Restart cpuworker and dnsworker processes, so they get up-to-date
     * configuration options. */
    cpuworkers_rotate();
    dns_reset();
#if 0
    const char *descriptor;
    char keydir[512];
    /* Write out a fresh descriptor, but leave old one on failure. */
    router_rebuild_descriptor(1);
    descriptor = router_get_my_descriptor();
    if (descriptor) {
      tor_snprintf(keydir,sizeof(keydir),"%s/router.desc",
                   options->DataDirectory);
      log_info(LD_OR,"Saving descriptor to \"%s\"...",keydir);
      if (write_str_to_file(keydir, descriptor, 0)) {
        return 0;
      }
    }
#endif
  }
  return 0;
}

/** Tor main loop. */
static int
do_main_loop(void)
{
  int loop_result;

  /* initialize dns resolve map, spawn workers if needed */
  if (dns_init() < 0) {
    log_err(LD_GENERAL,"Error initializing dns subsystem; exiting");
    return -1;
  }

  handle_signals(1);

  /* load the private keys, if we're supposed to have them, and set up the
   * TLS context. */
  if (! identity_key_is_set()) {
    if (init_keys() < 0) {
      log_err(LD_BUG,"Error initializing keys; exiting");
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
    dirserv_test_reachability(1);
  }

  if (server_mode(get_options())) {
    /* launch cpuworkers. Need to do this *after* we've read the onion key. */
    cpu_init();
  }

  /* set up once-a-second callback. */
  second_elapsed_callback(0,0,NULL);

  for (;;) {
    if (nt_service_is_stopping())
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
        log_err(LD_NET,"libevent call with %s failed: %s [%d]",
                event_get_method(), tor_socket_strerror(e), e);
#else
        log_err(LD_NET,"libevent call failed: %s [%d]",
                tor_socket_strerror(e), e);
#endif
        return -1;
#ifndef MS_WINDOWS
      } else if (e == EINVAL) {
        log_warn(LD_NET, "EINVAL from libevent: should you upgrade libevent?");
        if (got_libevent_error())
          return -1;
#endif
      } else {
        if (ERRNO_IS_EINPROGRESS(e))
          log_warn(LD_BUG,
                   "libevent call returned EINPROGRESS? Please report.");
        log_debug(LD_NET,"libevent call interrupted.");
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
 * <b>the_signal</b> as a remote pseudo-signal, act on it. */
/* We don't re-use catch() here because:
 *   1. We handle a different set of signals than those allowed in catch.
 *   2. Platforms without signal() are unlikely to define SIGfoo.
 *   3. The control spec is defined to use fixed numeric signal values
 *      which just happen to match the unix values.
 */
void
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
    case SIGNEWNYM:
      signal_callback(0,0,(void*)(uintptr_t)SIGNEWNYM);
      break;
    case SIGCLEARDNSCACHE:
      signal_callback(0,0,(void*)(uintptr_t)SIGCLEARDNSCACHE);
      break;
    default:
      log_warn(LD_BUG, "Unrecognized signal number %d.", the_signal);
      break;
    }
}

/** Libevent callback: invoked when we get a signal.
 */
static void
signal_callback(int fd, short events, void *arg)
{
  uintptr_t sig = (uintptr_t)arg;
  (void)fd;
  (void)events;
  switch (sig)
    {
    case SIGTERM:
      log_err(LD_GENERAL,"Catching signal TERM, exiting cleanly.");
      tor_cleanup();
      exit(0);
      break;
    case SIGINT:
      if (!server_mode(get_options())) { /* do it now */
        log_notice(LD_GENERAL,"Interrupt: exiting cleanly.");
        tor_cleanup();
        exit(0);
      }
      hibernate_begin_shutdown();
      break;
#ifdef SIGPIPE
    case SIGPIPE:
      log_debug(LD_GENERAL,"Caught sigpipe. Ignoring.");
      break;
#endif
    case SIGUSR1:
      /* prefer to log it at INFO, but make sure we always see it */
      dumpstats(get_min_log_level()<LOG_INFO ? get_min_log_level() : LOG_INFO);
      break;
    case SIGUSR2:
      switch_logs_debug();
      log_debug(LD_GENERAL,"Caught USR2, going to loglevel debug. "
                "Send HUP to change back.");
      break;
    case SIGHUP:
      if (do_hup() < 0) {
        log_warn(LD_CONFIG,"Restart failed (config error?). Exiting.");
        tor_cleanup();
        exit(1);
      }
      break;
#ifdef SIGCHLD
    case SIGCHLD:
      while (waitpid(-1,NULL,WNOHANG) > 0) ; /* keep reaping until no more
                                                zombies */
      break;
#endif
    case SIGNEWNYM: {
      time_t now = time(NULL);
      if (time_of_last_signewnym + MAX_SIGNEWNYM_RATE > now) {
        signewnym_is_pending = 1;
        log(LOG_NOTICE, LD_CONTROL,
            "Rate limiting NEWNYM request: delaying by %d second(s)",
            (int)(MAX_SIGNEWNYM_RATE+time_of_last_signewnym-now));
      } else {
        /* XXX refactor someday: these two calls are in
         * run_scheduled_events() above too, and they should be in just
         * one place. */
        circuit_expire_all_dirty_circs();
        addressmap_clear_transient();
        time_of_last_signewnym = now;
      }
      break;
    }
    case SIGCLEARDNSCACHE:
      addressmap_clear_transient();
      break;
  }
}

extern uint64_t buf_total_used;
extern uint64_t buf_total_alloc;
extern uint64_t rephist_total_alloc;
extern uint32_t rephist_total_num;

/**
 * Write current memory usage information to the log.
 */
static void
dumpmemusage(int severity)
{
  log(severity, LD_GENERAL,
      "In buffers: "U64_FORMAT" used/"U64_FORMAT" allocated (%d conns).",
      U64_PRINTF_ARG(buf_total_used), U64_PRINTF_ARG(buf_total_alloc),
      n_conns);
  log(severity, LD_GENERAL, "In rephist: "U64_FORMAT" used by %d Tors.",
      U64_PRINTF_ARG(rephist_total_alloc), rephist_total_num);
  dump_routerlist_mem_usage(severity);
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

  for (i=0;i<n_conns;i++) {
    conn = connection_array[i];
    log(severity, LD_GENERAL,
        "Conn %d (socket %d) type %d (%s), state %d (%s), created %d secs ago",
        i, conn->s, conn->type, conn_type_to_string(conn->type),
        conn->state, conn_state_to_string(conn->type, conn->state),
        (int)(now - conn->timestamp_created));
    if (!connection_is_listener(conn)) {
      log(severity,LD_GENERAL,
          "Conn %d is to %s:%d.", i,
          safe_str(conn->address), conn->port);
      log(severity,LD_GENERAL,
          "Conn %d: %d bytes waiting on inbuf (len %d, last read %d secs ago)",
          i,
          (int)buf_datalen(conn->inbuf),
          (int)buf_capacity(conn->inbuf),
          (int)(now - conn->timestamp_lastread));
      log(severity,LD_GENERAL,
          "Conn %d: %d bytes waiting on outbuf "
          "(len %d, last written %d secs ago)",i,
          (int)buf_datalen(conn->outbuf),
          (int)buf_capacity(conn->outbuf),
          (int)(now - conn->timestamp_lastwritten));
    }
    circuit_dump_by_conn(conn, severity); /* dump info about all the circuits
                                           * using this conn */
  }
  log(severity, LD_NET,
      "Cells processed: "U64_FORMAT" padding\n"
      "                 "U64_FORMAT" create\n"
      "                 "U64_FORMAT" created\n"
      "                 "U64_FORMAT" relay\n"
      "                        ("U64_FORMAT" relayed)\n"
      "                        ("U64_FORMAT" delivered)\n"
      "                 "U64_FORMAT" destroy",
      U64_PRINTF_ARG(stats_n_padding_cells_processed),
      U64_PRINTF_ARG(stats_n_create_cells_processed),
      U64_PRINTF_ARG(stats_n_created_cells_processed),
      U64_PRINTF_ARG(stats_n_relay_cells_processed),
      U64_PRINTF_ARG(stats_n_relay_cells_relayed),
      U64_PRINTF_ARG(stats_n_relay_cells_delivered),
      U64_PRINTF_ARG(stats_n_destroy_cells_processed));
  if (stats_n_data_cells_packaged)
    log(severity,LD_NET,"Average packaged cell fullness: %2.3f%%",
        100*(U64_TO_DBL(stats_n_data_bytes_packaged) /
             U64_TO_DBL(stats_n_data_cells_packaged*RELAY_PAYLOAD_SIZE)) );
  if (stats_n_data_cells_received)
    log(severity,LD_NET,"Average delivered cell fullness: %2.3f%%",
        100*(U64_TO_DBL(stats_n_data_bytes_received) /
             U64_TO_DBL(stats_n_data_cells_received*RELAY_PAYLOAD_SIZE)) );

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
  dump_pk_ops(severity);
  dump_distinct_digest_count(severity);
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
        log_warn(LD_BUG, "Error from libevent when adding event for signal %d",
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
#else /* MS windows */
  (void)is_parent;
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
  addressmap_init(); /* Init the client dns cache. Do it always, since it's
                      * cheap. */

  /* give it somewhere to log to initially */
  add_temp_log();

  log(LOG_NOTICE, LD_GENERAL, "Tor v%s. This is experimental software. "
      "Do not rely on it for strong anonymity.",VERSION);

  if (network_init()<0) {
    log_err(LD_BUG,"Error initializing network; exiting.");
    return -1;
  }
  atexit(exit_function);

  if (options_init_from_torrc(argc,argv) < 0) {
    log_err(LD_CONFIG,"Reading config failed--see warnings above.");
    return -1;
  }

#ifndef MS_WINDOWS
  if (geteuid()==0)
    log_warn(LD_GENERAL,"You are running Tor as root. You don't need to, "
             "and you probably shouldn't.");
#endif

  crypto_global_init(get_options()->HardwareAccel);
  if (crypto_seed_rng()) {
    log_err(LD_BUG, "Unable to seed random number generator. Exiting.");
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
  if (!postfork) {
    evdns_shutdown(1);
  }
  routerlist_free_all();
  addressmap_free_all();
  set_exit_redirects(NULL); /* free the registered exit redirects */
  dirserv_free_all();
  rend_service_free_all();
  rend_cache_free_all();
  rep_hist_free_all();
  dns_free_all();
  clear_pending_onions();
  circuit_free_all();
  entry_guards_free_all();
  connection_free_all();
  policies_free_all();
  if (!postfork) {
    config_free_all();
    router_free_all();
  }
  tor_tls_free_all();
  /* stuff in main.c */
  smartlist_free(closeable_connection_lst);
  tor_free(timeout_event);
  /* Stuff in util.c */
  escaped(NULL);
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
  if (options->command == CMD_RUN_TOR) {
    if (options->PidFile)
      unlink(options->PidFile);
    if (accounting_is_enabled(options))
      accounting_record_bandwidth_usage(time(NULL), get_or_state());
    or_state_mark_dirty(get_or_state(), 0); /* force an immediate save. */
    or_state_save(time(NULL));
  }
  tor_free_all(0); /* move tor_free_all back into the ifdef below later. XXX*/
  crypto_global_cleanup();
#ifdef USE_DMALLOC
  dmalloc_log_unfreed();
  dmalloc_shutdown();
#endif
}

/** Read/create keys as needed, and echo our fingerprint to stdout. */
static int
do_list_fingerprint(void)
{
  char buf[FINGERPRINT_LEN+1];
  crypto_pk_env_t *k;
  const char *nickname = get_options()->Nickname;
  if (!server_mode(get_options())) {
    log_err(LD_GENERAL,
            "Clients don't have long-term identity keys. Exiting.\n");
    return -1;
  }
  tor_assert(nickname);
  if (init_keys() < 0) {
    log_err(LD_BUG,"Error initializing keys; can't display fingerprint");
    return -1;
  }
  if (!(k = get_identity_key())) {
    log_err(LD_GENERAL,"Error: missing identity key.");
    return -1;
  }
  if (crypto_pk_get_fingerprint(k, buf, 1)<0) {
    log_err(LD_BUG, "Error computing fingerprint");
    return -1;
  }
  printf("%s %s\n", nickname, buf);
  return 0;
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

/* XXXX can some/all these functions become static? without breaking NT
 * services? -NM */
/* XXXX I'd also like to move much of the NT service stuff into its own
 * file. -RD */
void nt_service_control(DWORD request);
void nt_service_body(int argc, char **argv);
void nt_service_main(void);
SC_HANDLE nt_service_open_scm(void);
SC_HANDLE nt_service_open(SC_HANDLE hSCManager);
int nt_service_start(SC_HANDLE hService);
int nt_service_stop(SC_HANDLE hService);
int nt_service_install(int argc, char **argv);
int nt_service_remove(void);
int nt_service_cmd_start(void);
int nt_service_cmd_stop(void);

struct service_fns {
  int loaded;

  BOOL (WINAPI *ChangeServiceConfig2A_fn)(
                             SC_HANDLE hService,
                             DWORD dwInfoLevel,
                             LPVOID lpInfo);

  BOOL (WINAPI *CloseServiceHandle_fn)(
                             SC_HANDLE hSCObject);

  BOOL (WINAPI *ControlService_fn)(
                             SC_HANDLE hService,
                             DWORD dwControl,
                             LPSERVICE_STATUS lpServiceStatus);

  SC_HANDLE (WINAPI *CreateServiceA_fn)(
                             SC_HANDLE hSCManager,
                             LPCTSTR lpServiceName,
                             LPCTSTR lpDisplayName,
                             DWORD dwDesiredAccess,
                             DWORD dwServiceType,
                             DWORD dwStartType,
                             DWORD dwErrorControl,
                             LPCTSTR lpBinaryPathName,
                             LPCTSTR lpLoadOrderGroup,
                             LPDWORD lpdwTagId,
                             LPCTSTR lpDependencies,
                             LPCTSTR lpServiceStartName,
                             LPCTSTR lpPassword);

  BOOL (WINAPI *DeleteService_fn)(
                             SC_HANDLE hService);

  SC_HANDLE (WINAPI *OpenSCManagerA_fn)(
                             LPCTSTR lpMachineName,
                             LPCTSTR lpDatabaseName,
                             DWORD dwDesiredAccess);

  SC_HANDLE (WINAPI *OpenServiceA_fn)(
                             SC_HANDLE hSCManager,
                             LPCTSTR lpServiceName,
                             DWORD dwDesiredAccess);

  BOOL (WINAPI *QueryServiceStatus_fn)(
                             SC_HANDLE hService,
                             LPSERVICE_STATUS lpServiceStatus);

  SERVICE_STATUS_HANDLE (WINAPI *RegisterServiceCtrlHandlerA_fn)(
                             LPCTSTR lpServiceName,
                             LPHANDLER_FUNCTION lpHandlerProc);

  BOOL (WINAPI *SetServiceStatus_fn)(SERVICE_STATUS_HANDLE,
                             LPSERVICE_STATUS);

  BOOL (WINAPI *StartServiceCtrlDispatcherA_fn)(
                             const SERVICE_TABLE_ENTRY* lpServiceTable);

  BOOL (WINAPI *StartServiceA_fn)(
                             SC_HANDLE hService,
                             DWORD dwNumServiceArgs,
                             LPCTSTR* lpServiceArgVectors);

  BOOL (WINAPI *LookupAccountNameA_fn)(
                             LPCTSTR lpSystemName,
                             LPCTSTR lpAccountName,
                             PSID Sid,
                             LPDWORD cbSid,
                             LPTSTR ReferencedDomainName,
                             LPDWORD cchReferencedDomainName,
                             PSID_NAME_USE peUse);
} service_fns = { 0,
                  NULL, NULL, NULL, NULL, NULL, NULL,
                  NULL, NULL, NULL, NULL, NULL, NULL,
                  NULL};

/** Loads functions used by NT services. Returns on success, or prints a
 * complaint to stdout and exits on error. */
static void
nt_service_loadlibrary(void)
{
  HMODULE library = 0;
  void *fn;

  if (service_fns.loaded)
    return;

  /* XXXX Possibly, we should hardcode the location of this DLL. */
  if (!(library = LoadLibrary("advapi32.dll"))) {
    log_err(LD_GENERAL, "Couldn't open advapi32.dll.  Are you trying to use "
            "NT services on Windows 98? That doesn't work.");
    goto err;
  }

#define LOAD(f) do {                                                    \
    if (!(fn = GetProcAddress(library, #f))) {                          \
      log_err(LD_BUG,                                                   \
              "Couldn't find %s in advapi32.dll! We probably got the "  \
              "name wrong.", #f);                                       \
      goto err;                                                         \
    } else {                                                            \
      service_fns.f ## _fn = fn;                                        \
    }                                                                   \
  } while (0)

  LOAD(ChangeServiceConfig2A);
  LOAD(CloseServiceHandle);
  LOAD(ControlService);
  LOAD(CreateServiceA);
  LOAD(DeleteService);
  LOAD(OpenSCManagerA);
  LOAD(OpenServiceA);
  LOAD(QueryServiceStatus);
  LOAD(RegisterServiceCtrlHandlerA);
  LOAD(SetServiceStatus);
  LOAD(StartServiceCtrlDispatcherA);
  LOAD(StartServiceA);
  LOAD(LookupAccountNameA);

  service_fns.loaded = 1;

  return;
 err:
  printf("Unable to load library support for NT services: exiting.\n");
  exit(1);
}

/** If we're compiled to run as an NT service, and the service wants to
 * shut down, then change our current status and return 1.  Else
 * return 0.
 */
static int
nt_service_is_stopping(void)
/* XXXX this function would probably _love_ to be inline, in 0.2.0. */
{
  /* If we haven't loaded the function pointers, we can't possibly be an NT
   * service trying to shut down. */
  if (!service_fns.loaded)
    return 0;

  if (service_status.dwCurrentState == SERVICE_STOP_PENDING) {
    service_status.dwWin32ExitCode = 0;
    service_status.dwCurrentState = SERVICE_STOPPED;
    service_fns.SetServiceStatus_fn(hStatus, &service_status);
    return 1;
  } else if (service_status.dwCurrentState == SERVICE_STOPPED) {
    return 1;
  }
  return 0;
}

/** Handles service control requests, such as stopping or starting the
 * Tor service. */
void
nt_service_control(DWORD request)
{
  static struct timeval exit_now;
  exit_now.tv_sec  = 0;
  exit_now.tv_usec = 0;

  nt_service_loadlibrary();

  switch (request) {
    case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
          log_err(LD_GENERAL,
                  "Got stop/shutdown request; shutting down cleanly.");
          service_status.dwCurrentState = SERVICE_STOP_PENDING;
          event_loopexit(&exit_now);
          return;
  }
  service_fns.SetServiceStatus_fn(hStatus, &service_status);
}

/** Called when the service is started via the system's service control
 * manager. This calls tor_init() and starts the main event loop. If
 * tor_init() fails, the service will be stopped and exit code set to
 * NT_SERVICE_ERROR_TORINIT_FAILED. */
void
nt_service_body(int argc, char **argv)
{
  int r;
  (void) argc; /* unused */
  (void) argv; /* unused */
  nt_service_loadlibrary();
  service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  service_status.dwCurrentState = SERVICE_START_PENDING;
  service_status.dwControlsAccepted =
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  service_status.dwWin32ExitCode = 0;
  service_status.dwServiceSpecificExitCode = 0;
  service_status.dwCheckPoint = 0;
  service_status.dwWaitHint = 1000;
  hStatus = service_fns.RegisterServiceCtrlHandlerA_fn(GENSRV_SERVICENAME,
                                   (LPHANDLER_FUNCTION) nt_service_control);

  if (hStatus == 0) {
    /* Failed to register the service control handler function */
    return;
  }

  r = tor_init(backup_argc, backup_argv);
  if (r) {
    /* Failed to start the Tor service */
    r = NT_SERVICE_ERROR_TORINIT_FAILED;
    service_status.dwCurrentState = SERVICE_STOPPED;
    service_status.dwWin32ExitCode = r;
    service_status.dwServiceSpecificExitCode = r;
    service_fns.SetServiceStatus_fn(hStatus, &service_status);
    return;
  }

  /* Set the service's status to SERVICE_RUNNING and start the main
   * event loop */
  service_status.dwCurrentState = SERVICE_RUNNING;
  service_fns.SetServiceStatus_fn(hStatus, &service_status);
  do_main_loop();
  tor_cleanup();
}

/** Main service entry point. Starts the service control dispatcher and waits
 * until the service status is set to SERVICE_STOPPED. */
void
nt_service_main(void)
{
  SERVICE_TABLE_ENTRY table[2];
  DWORD result = 0;
  char *errmsg;
  nt_service_loadlibrary();
  table[0].lpServiceName = (char*)GENSRV_SERVICENAME;
  table[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)nt_service_body;
  table[1].lpServiceName = NULL;
  table[1].lpServiceProc = NULL;

  if (!service_fns.StartServiceCtrlDispatcherA_fn(table)) {
    result = GetLastError();
    errmsg = nt_strerror(result);
    printf("Service error %d : %s\n", (int) result, errmsg);
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
      case CMD_RUN_UNITTESTS:
      default:
        log_err(LD_CONFIG, "Illegal command number %d: internal error.",
                get_options()->command);
      }
      tor_cleanup();
    }
  }
}

/** Return a handle to the service control manager on success, or NULL on
 * failure. */
SC_HANDLE
nt_service_open_scm(void)
{
  SC_HANDLE hSCManager;
  char *errmsg = NULL;

  nt_service_loadlibrary();
  if ((hSCManager = service_fns.OpenSCManagerA_fn(
                            NULL, NULL, SC_MANAGER_CREATE_SERVICE)) == NULL) {
    errmsg = nt_strerror(GetLastError());
    printf("OpenSCManager() failed : %s\n", errmsg);
    LocalFree(errmsg);
  }
  return hSCManager;
}

/** Open a handle to the Tor service using <b>hSCManager</b>. Return NULL
 * on failure. */
SC_HANDLE
nt_service_open(SC_HANDLE hSCManager)
{
  SC_HANDLE hService;
  char *errmsg = NULL;
  nt_service_loadlibrary();
  if ((hService = service_fns.OpenServiceA_fn(hSCManager, GENSRV_SERVICENAME,
                              SERVICE_ALL_ACCESS)) == NULL) {
    errmsg = nt_strerror(GetLastError());
    printf("OpenService() failed : %s\n", errmsg);
    LocalFree(errmsg);
  }
  return hService;
}

/** Start the Tor service. Return 0 if the service is started or was
 * previously running. Return -1 on error. */
int
nt_service_start(SC_HANDLE hService)
{
  char *errmsg = NULL;

  nt_service_loadlibrary();

  service_fns.QueryServiceStatus_fn(hService, &service_status);
  if (service_status.dwCurrentState == SERVICE_RUNNING) {
    printf("Service is already running\n");
    return 0;
  }

  if (service_fns.StartServiceA_fn(hService, 0, NULL)) {
    /* Loop until the service has finished attempting to start */
    while (service_fns.QueryServiceStatus_fn(hService, &service_status) &&
           (service_status.dwCurrentState == SERVICE_START_PENDING)) {
      Sleep(500);
    }

    /* Check if it started successfully or not */
    if (service_status.dwCurrentState == SERVICE_RUNNING) {
      printf("Service started successfully\n");
      return 0;
    } else {
      errmsg = nt_strerror(service_status.dwWin32ExitCode);
      printf("Service failed to start : %s\n", errmsg);
      LocalFree(errmsg);
    }
  } else {
    errmsg = nt_strerror(GetLastError());
    printf("StartService() failed : %s\n", errmsg);
    LocalFree(errmsg);
  }
  return -1;
}

/** Stop the Tor service. Return 0 if the service is stopped or was not
 * previously running. Return -1 on error. */
int
nt_service_stop(SC_HANDLE hService)
{
/** Wait at most 10 seconds for the service to stop. */
#define MAX_SERVICE_WAIT_TIME 10
  int wait_time;
  char *errmsg = NULL;
  nt_service_loadlibrary();

  service_fns.QueryServiceStatus_fn(hService, &service_status);
  if (service_status.dwCurrentState == SERVICE_STOPPED) {
    printf("Service is already stopped\n");
    return 0;
  }

  if (service_fns.ControlService_fn(hService, SERVICE_CONTROL_STOP,
                                    &service_status)) {
    wait_time = 0;
    while (service_fns.QueryServiceStatus_fn(hService, &service_status) &&
           (service_status.dwCurrentState != SERVICE_STOPPED) &&
           (wait_time < MAX_SERVICE_WAIT_TIME)) {
      Sleep(1000);
      wait_time++;
    }
    if (service_status.dwCurrentState == SERVICE_STOPPED) {
      printf("Service stopped successfully\n");
      return 0;
    } else if (wait_time == MAX_SERVICE_WAIT_TIME) {
      printf("Service did not stop within %d seconds.\n", wait_time);
    } else {
      errmsg = nt_strerror(GetLastError());
      printf("QueryServiceStatus() failed : %s\n",errmsg);
      LocalFree(errmsg);
    }
  } else {
    errmsg = nt_strerror(GetLastError());
    printf("ControlService() failed : %s\n", errmsg);
    LocalFree(errmsg);
  }
  return -1;
}

/** Build a formatted command line used for the NT service. Return a
 * pointer to the formatted string on success, or NULL on failure.  Set
 * *<b>using_default_torrc</b> to true if we're going to use the default
 * location to torrc, or 1 if an option was specified on the command line.
 */
static char *
nt_service_command_line(int *using_default_torrc)
{
  TCHAR tor_exe[MAX_PATH+1];
  char *command, *options=NULL;
  smartlist_t *sl;
  int i, cmdlen;
  *using_default_torrc = 1;

  /* Get the location of tor.exe */
  if (0 == GetModuleFileName(NULL, tor_exe, MAX_PATH))
    return NULL;

  /* Get the service arguments */
  sl = smartlist_create();
  for (i = 1; i < backup_argc; ++i) {
    if (!strcmp(backup_argv[i], "--options") ||
        !strcmp(backup_argv[i], "-options")) {
      while (++i < backup_argc) {
        if (!strcmp(backup_argv[i], "-f"))
          *using_default_torrc = 0;
        smartlist_add(sl, backup_argv[i]);
      }
    }
  }
  if (smartlist_len(sl))
    options = smartlist_join_strings(sl,"\" \"",0,NULL);
  smartlist_free(sl);

  /* Allocate a string for the NT service command line */
  cmdlen = strlen(tor_exe) + (options?strlen(options):0) + 32;
  command = tor_malloc(cmdlen);

  /* Format the service command */
  if (options) {
    if (tor_snprintf(command, cmdlen, "\"%s\" --nt-service \"%s\"",
                     tor_exe, options)<0) {
      tor_free(command); /* sets command to NULL. */
    }
  } else { /* ! options */
    if (tor_snprintf(command, cmdlen, "\"%s\" --nt-service", tor_exe)<0) {
      tor_free(command); /* sets command to NULL. */
    }
  }

  tor_free(options);
  return command;
}

/** Creates a Tor NT service, set to start on boot. The service will be
 * started if installation succeeds. Returns 0 on success, or -1 on
 * failure. */
int
nt_service_install(int argc, char **argv)
{
  /* Notes about developing NT services:
   *
   * 1. Don't count on your CWD. If an absolute path is not given, the
   *    fopen() function goes wrong.
   * 2. The parameters given to the nt_service_body() function differ
   *    from those given to main() function.
   */

  SC_HANDLE hSCManager = NULL;
  SC_HANDLE hService = NULL;
  SERVICE_DESCRIPTION sdBuff;
  char *command;
  char *errmsg;
  const char *user_acct = GENSRV_USERACCT;
  const char *password = "";
  int i;
  OSVERSIONINFOEX info;
  SID_NAME_USE sidUse;
  DWORD sidLen = 0, domainLen = 0;
  int is_win2k_or_worse = 0;
  int using_default_torrc = 0;

  nt_service_loadlibrary();

  /* Open the service control manager so we can create a new service */
  if ((hSCManager = nt_service_open_scm()) == NULL)
    return -1;
  /* Build the command line used for the service */
  if ((command = nt_service_command_line(&using_default_torrc)) == NULL) {
    printf("Unable to build service command line.\n");
    service_fns.CloseServiceHandle_fn(hSCManager);
    return -1;
  }

  for (i=1; i < argc; ++i) {
    if (!strcmp(argv[i], "--user") && i+1<argc) {
      user_acct = argv[i+1];
      ++i;
    }
    if (!strcmp(argv[i], "--password") && i+1<argc) {
      password = argv[i+1];
      ++i;
    }
  }

  /* Compute our version and see whether we're running win2k or earlier. */
  memset(&info, 0, sizeof(info));
  info.dwOSVersionInfoSize = sizeof(info);
  if (! GetVersionEx((LPOSVERSIONINFO)&info)) {
    printf("Call to GetVersionEx failed.\n");
    is_win2k_or_worse = 1;
  } else {
    if (info.dwMajorVersion < 5 ||
        (info.dwMajorVersion == 5 && info.dwMinorVersion == 0))
      is_win2k_or_worse = 1;
  }

  if (user_acct == GENSRV_USERACCT) {
    if (is_win2k_or_worse) {
      /* On Win2k, there is no LocalService account, so we actually need to
       * fall back on NULL (the system account). */
      printf("Running on Win2K or earlier, so the LocalService account "
             "doesn't exist.  Falling back to SYSTEM account.\n");
      user_acct = NULL;
    } else {
      /* Genericity is apparently _so_ last year in Redmond, where some
       * accounts are accounts that you can look up, and some accounts
       * are magic and undetectable via the security subsystem. See
       * http://msdn2.microsoft.com/en-us/library/ms684188.aspx
       */
      printf("Running on a Post-Win2K OS, so we'll assume that the "
             "LocalService account exists.\n");
    }
  } else if (0 && service_fns.LookupAccountNameA_fn(NULL, // On this system
                            user_acct,
                            NULL, &sidLen, // Don't care about the SID
                            NULL, &domainLen, // Don't care about the domain
                            &sidUse) == 0) {
    /* XXXX For some reason, the above test segfaults. Fix that. */
    printf("User \"%s\" doesn't seem to exist.\n", user_acct);
    return -1;
  } else {
    printf("Will try to install service as user \"%s\".\n", user_acct);
  }
  /* XXXX This warning could be better about explaining how to resolve the
   * situation. */
  if (using_default_torrc)
    printf("IMPORTANT NOTE:\n"
        "    The Tor service will run under the account \"%s\".  This means\n"
        "    that Tor will look for its configuration file under that\n"
        "    account's Application Data directory, which is probably not\n"
        "    the same as yours.\n", user_acct?user_acct:"<local system>");

  /* Create the Tor service, set to auto-start on boot */
  if ((hService = service_fns.CreateServiceA_fn(hSCManager, GENSRV_SERVICENAME,
                                GENSRV_DISPLAYNAME,
                                SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                SERVICE_AUTO_START, SERVICE_ERROR_IGNORE,
                                command, NULL, NULL, NULL,
                                user_acct, password)) == NULL) {
    errmsg = nt_strerror(GetLastError());
    printf("CreateService() failed : %s\n", errmsg);
    service_fns.CloseServiceHandle_fn(hSCManager);
    LocalFree(errmsg);
    tor_free(command);
    return -1;
  }
  printf("Done with CreateService.\n");

  /* Set the service's description */
  sdBuff.lpDescription = (char*)GENSRV_DESCRIPTION;
  service_fns.ChangeServiceConfig2A_fn(hService, SERVICE_CONFIG_DESCRIPTION,
                                       &sdBuff);
  printf("Service installed successfully\n");

  /* Start the service initially */
  nt_service_start(hService);

  service_fns.CloseServiceHandle_fn(hService);
  service_fns.CloseServiceHandle_fn(hSCManager);
  tor_free(command);

  return 0;
}

/** Removes the Tor NT service. Returns 0 if the service was successfully
 * removed, or -1 on error. */
int
nt_service_remove(void)
{
  SC_HANDLE hSCManager = NULL;
  SC_HANDLE hService = NULL;
  char *errmsg;

  nt_service_loadlibrary();
  if ((hSCManager = nt_service_open_scm()) == NULL)
    return -1;
  if ((hService = nt_service_open(hSCManager)) == NULL) {
    service_fns.CloseServiceHandle_fn(hSCManager);
    return -1;
  }

  nt_service_stop(hService);
  if (service_fns.DeleteService_fn(hService) == FALSE) {
    errmsg = nt_strerror(GetLastError());
    printf("DeleteService() failed : %s\n", errmsg);
    LocalFree(errmsg);
    service_fns.CloseServiceHandle_fn(hService);
    service_fns.CloseServiceHandle_fn(hSCManager);
    return -1;
  }

  service_fns.CloseServiceHandle_fn(hService);
  service_fns.CloseServiceHandle_fn(hSCManager);
  printf("Service removed successfully\n");

  return 0;
}

/** Starts the Tor service. Returns 0 on success, or -1 on error. */
int
nt_service_cmd_start(void)
{
  SC_HANDLE hSCManager;
  SC_HANDLE hService;
  int start;

  if ((hSCManager = nt_service_open_scm()) == NULL)
    return -1;
  if ((hService = nt_service_open(hSCManager)) == NULL) {
    service_fns.CloseServiceHandle_fn(hSCManager);
    return -1;
  }

  start = nt_service_start(hService);
  service_fns.CloseServiceHandle_fn(hService);
  service_fns.CloseServiceHandle_fn(hSCManager);

  return start;
}

/** Stops the Tor service. Returns 0 on success, or -1 on error. */
int
nt_service_cmd_stop(void)
{
  SC_HANDLE hSCManager;
  SC_HANDLE hService;
  int stop;

  if ((hSCManager = nt_service_open_scm()) == NULL)
    return -1;
  if ((hService = nt_service_open(hSCManager)) == NULL) {
    service_fns.CloseServiceHandle_fn(hSCManager);
    return -1;
  }

  stop = nt_service_stop(hService);
  service_fns.CloseServiceHandle_fn(hService);
  service_fns.CloseServiceHandle_fn(hSCManager);

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

/** Main entry point for the Tor process.  Called from main(). */
/* This function is distinct from main() only so we can link main.c into
 * the unittest binary without conflicting with the unittests' main. */
int
tor_main(int argc, char *argv[])
{
  int result = 0;
#ifdef USE_DMALLOC
  int r = CRYPTO_set_mem_ex_functions(_tor_malloc, _tor_realloc,
                                      _tor_dmalloc_free);
  log_notice(LD_CONFIG, "Set up dmalloc; returned %d", r);
#endif
#ifdef MS_WINDOWS_SERVICE
  backup_argv = argv;
  backup_argc = argc;
  if ((argc >= 3) &&
      (!strcmp(argv[1], "-service") || !strcmp(argv[1], "--service"))) {
    nt_service_loadlibrary();
    if (!strcmp(argv[2], "install"))
      return nt_service_install(argc, argv);
    if (!strcmp(argv[2], "remove"))
      return nt_service_remove();
    if (!strcmp(argv[2], "start"))
      return nt_service_cmd_start();
    if (!strcmp(argv[2], "stop"))
      return nt_service_cmd_stop();
    printf("Unrecognized service command '%s'\n", argv[2]);
    return -1;
  }
  if (argc >= 2) {
    if (!strcmp(argv[1], "-nt-service") || !strcmp(argv[1], "--nt-service")) {
      nt_service_loadlibrary();
      nt_service_main();
      return 0;
    }
    // These values have been deprecated since 0.1.1.2-alpha; we've warned
    // about them since 0.1.2.7-alpha.
    if (!strcmp(argv[1], "-install") || !strcmp(argv[1], "--install")) {
      nt_service_loadlibrary();
      fprintf(stderr,
            "The %s option is deprecated; use \"--service install\" instead.",
            argv[1]);
      return nt_service_install(argc, argv);
    }
    if (!strcmp(argv[1], "-remove") || !strcmp(argv[1], "--remove")) {
      nt_service_loadlibrary();
      fprintf(stderr,
            "The %s option is deprecated; use \"--service remove\" instead.",
            argv[1]);
      return nt_service_remove();
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
    result = do_main_loop();
    break;
  case CMD_LIST_FINGERPRINT:
    result = do_list_fingerprint();
    break;
  case CMD_HASH_PASSWORD:
    do_hash_password();
    result = 0;
    break;
  case CMD_VERIFY_CONFIG:
    printf("Configuration was valid\n");
    result = 0;
    break;
  case CMD_RUN_UNITTESTS: /* only set by test.c */
  default:
    log_warn(LD_BUG,"Illegal command number %d: internal error.",
             get_options()->command);
    result = -1;
  }
  tor_cleanup();
  return result;
}

