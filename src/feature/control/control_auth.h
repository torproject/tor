/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file control_auth.h
 * \brief Header file for control_auth.c.
 **/

#ifndef TOR_CONTROL_AUTH_H
#define TOR_CONTROL_AUTH_H

int init_control_cookie_authentication(int enabled);
char *get_controller_cookie_file_name(void);
struct config_line_t;
smartlist_t *decode_hashed_passwords(struct config_line_t *passwords);

int handle_control_authchallenge(control_connection_t *conn, uint32_t len,
                                 const char *body);
int handle_control_authenticate(control_connection_t *conn,
                           uint32_t cmd_data_len,
                           const char *args);
void control_auth_free_all(void);

#endif /* !defined(TOR_CONTROL_AUTH_H) */
