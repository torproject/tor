/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file control_hs.c
 *
 * \brief Header file for control_hs.c.
 **/

#ifndef TOR_CONTROL_HS_H
#define TOR_CONTROL_HS_H

struct control_cmd_syntax_t;

extern const struct control_cmd_syntax_t onion_client_auth_add_syntax;
extern const struct control_cmd_syntax_t onion_client_auth_remove_syntax;
extern const struct control_cmd_syntax_t onion_client_auth_view_syntax;

int
handle_control_onion_client_auth_add(control_connection_t *conn,
                                     const control_cmd_args_t *args);

int
handle_control_onion_client_auth_remove(control_connection_t *conn,
                                        const control_cmd_args_t *args);

int
handle_control_onion_client_auth_view(control_connection_t *conn,
                                      const control_cmd_args_t *args);

#endif

