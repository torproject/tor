/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file main.h
 * \brief Header file for main.c.
 **/

#ifndef _TOR_MAIN_H
#define _TOR_MAIN_H

extern int can_complete_circuit;

int connection_add(connection_t *conn);
int connection_remove(connection_t *conn);
void connection_unregister_events(connection_t *conn);
int connection_in_array(connection_t *conn);
void add_connection_to_closeable_list(connection_t *conn);
int connection_is_on_closeable_list(connection_t *conn);

smartlist_t *get_connection_array(void);

/** Bitmask for events that we can turn on and off with
 * connection_watch_events. */
typedef enum watchable_events {
  READ_EVENT=0x02, /**< We want to know when a connection is readable */
  WRITE_EVENT=0x04 /**< We want to know when a connection is writable */
} watchable_events_t;
void connection_watch_events(connection_t *conn, watchable_events_t events);
int connection_is_reading(connection_t *conn);
void connection_stop_reading(connection_t *conn);
void connection_start_reading(connection_t *conn);

int connection_is_writing(connection_t *conn);
void connection_stop_writing(connection_t *conn);
void connection_start_writing(connection_t *conn);

void connection_stop_reading_from_linked_conn(connection_t *conn);

void directory_all_unreachable(time_t now);
void directory_info_has_arrived(time_t now, int from_cache);

void ip_address_changed(int at_interface);
void dns_servers_relaunch_checks(void);

void control_signal_act(int the_signal);
void handle_signals(int is_parent);

int try_locking(or_options_t *options, int err_if_locked);
int have_lockfile(void);
void release_lockfile(void);

void tor_cleanup(void);
void tor_free_all(int postfork);

int tor_main(int argc, char *argv[]);

#ifdef MAIN_PRIVATE
int do_main_loop(void);
int do_list_fingerprint(void);
void do_hash_password(void);
int tor_init(int argc, char **argv);
#endif

#endif

