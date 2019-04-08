/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file control_fmt.h
 * \brief Header file for control_fmt.c.
 **/

#ifndef TOR_CONTROL_FMT_H
#define TOR_CONTROL_FMT_H

void connection_write_str_to_buf(const char *s, control_connection_t *conn);
void connection_printf_to_buf(control_connection_t *conn,
                                     const char *format, ...)
  CHECK_PRINTF(2,3);

int write_stream_target_to_buf(entry_connection_t *conn, char *buf,
                               size_t len);
void orconn_target_get_name(char *buf, size_t len,
                            or_connection_t *conn);
char *circuit_describe_status_for_controller(origin_circuit_t *circ);

size_t write_escaped_data(const char *data, size_t len, char **out);
size_t read_escaped_data(const char *data, size_t len, char **out);
const char *decode_escaped_string(const char *start, size_t in_len_max,
                                  char **out, size_t *out_len);
void send_control_done(control_connection_t *conn);

MOCK_DECL(const char *, node_describe_longname_by_id,(const char *id_digest));

#endif /* !defined(TOR_CONTROL_FMT_H) */
