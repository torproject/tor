/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file connection.h
 * \brief Header file for connection.c.
 **/

#ifndef _TOR_CONNECTION_H
#define _TOR_CONNECTION_H

/* XXXX For buf_datalen in inline function */
#include "buffers.h"

const char *conn_type_to_string(int type);
const char *conn_state_to_string(int type, int state);

dir_connection_t *dir_connection_new(int socket_family);
or_connection_t *or_connection_new(int socket_family);
edge_connection_t *edge_connection_new(int type, int socket_family);
control_connection_t *control_connection_new(int socket_family);
connection_t *connection_new(int type, int socket_family);

void connection_link_connections(connection_t *conn_a, connection_t *conn_b);
void connection_free(connection_t *conn);
void connection_free_all(void);
void connection_about_to_close_connection(connection_t *conn);
void connection_close_immediate(connection_t *conn);
void _connection_mark_for_close(connection_t *conn,int line, const char *file);

#define connection_mark_for_close(c) \
  _connection_mark_for_close((c), __LINE__, _SHORT_FILE_)

#define connection_mark_and_flush(c)                                    \
  do {                                                                  \
    connection_t *tmp_conn_ = (c);                                      \
    _connection_mark_for_close(tmp_conn_, __LINE__, _SHORT_FILE_);      \
    tmp_conn_->hold_open_until_flushed = 1;                             \
    IF_HAS_BUFFEREVENT(tmp_conn_,                                       \
                       connection_start_writing(tmp_conn_));            \
  } while (0)

void connection_expire_held_open(void);

int connection_connect(connection_t *conn, const char *address,
                       const tor_addr_t *addr,
                       uint16_t port, int *socket_error);

int connection_proxy_connect(connection_t *conn, int type);
int connection_read_proxy_handshake(connection_t *conn);

int retry_all_listeners(smartlist_t *replaced_conns,
                        smartlist_t *new_conns);

ssize_t connection_bucket_write_limit(connection_t *conn, time_t now);
int global_write_bucket_low(connection_t *conn, size_t attempt, int priority);
void connection_bucket_init(void);
void connection_bucket_refill(int seconds_elapsed, time_t now);

int connection_handle_read(connection_t *conn);

int connection_fetch_from_buf(char *string, size_t len, connection_t *conn);
int connection_fetch_from_buf_line(connection_t *conn, char *data,
                                   size_t *data_len);
int connection_fetch_from_buf_http(connection_t *conn,
                               char **headers_out, size_t max_headerlen,
                               char **body_out, size_t *body_used,
                               size_t max_bodylen, int force_complete);

int connection_wants_to_flush(connection_t *conn);
int connection_outbuf_too_full(connection_t *conn);
int connection_handle_write(connection_t *conn, int force);
void _connection_write_to_buf_impl(const char *string, size_t len,
                                   connection_t *conn, int zlib);
static void connection_write_to_buf(const char *string, size_t len,
                                    connection_t *conn);
static void connection_write_to_buf_zlib(const char *string, size_t len,
                                         dir_connection_t *conn, int done);
static INLINE void
connection_write_to_buf(const char *string, size_t len, connection_t *conn)
{
  _connection_write_to_buf_impl(string, len, conn, 0);
}
static INLINE void
connection_write_to_buf_zlib(const char *string, size_t len,
                             dir_connection_t *conn, int done)
{
  _connection_write_to_buf_impl(string, len, TO_CONN(conn), done ? -1 : 1);
}

static size_t connection_get_inbuf_len(connection_t *conn);
static size_t connection_get_outbuf_len(connection_t *conn);

static INLINE size_t
connection_get_inbuf_len(connection_t *conn)
{
  IF_HAS_BUFFEREVENT(conn, {
    return evbuffer_get_length(bufferevent_get_input(conn->bufev));
  }) ELSE_IF_NO_BUFFEREVENT {
    return buf_datalen(conn->inbuf);
  }
}

static INLINE size_t
connection_get_outbuf_len(connection_t *conn)
{
  IF_HAS_BUFFEREVENT(conn, {
    return evbuffer_get_length(bufferevent_get_output(conn->bufev));
  }) ELSE_IF_NO_BUFFEREVENT {
    return buf_datalen(conn->outbuf);
  }
}

connection_t *connection_get_by_global_id(uint64_t id);

connection_t *connection_get_by_type(int type);
connection_t *connection_get_by_type_purpose(int type, int purpose);
connection_t *connection_get_by_type_addr_port_purpose(int type,
                                                   const tor_addr_t *addr,
                                                   uint16_t port, int purpose);
connection_t *connection_get_by_type_state(int type, int state);
connection_t *connection_get_by_type_state_rendquery(int type, int state,
                                                     const char *rendquery);

#define connection_speaks_cells(conn) ((conn)->type == CONN_TYPE_OR)
int connection_is_listener(connection_t *conn);
int connection_state_is_open(connection_t *conn);
int connection_state_is_connecting(connection_t *conn);

char *alloc_http_authenticator(const char *authenticator);

void assert_connection_ok(connection_t *conn, time_t now);
int connection_or_nonopen_was_started_here(or_connection_t *conn);
void connection_dump_buffer_mem_stats(int severity);
void remove_file_if_very_old(const char *fname, time_t now);

#ifdef USE_BUFFEREVENTS
int connection_type_uses_bufferevent(connection_t *conn);
void connection_configure_bufferevent_callbacks(connection_t *conn);
#else
#define connection_type_uses_bufferevent(c) (0)
#endif

#endif

