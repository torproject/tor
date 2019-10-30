/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file transport_config.h
 * @brief Header for feature/relay/transport_config.c
 **/

#ifndef TOR_FEATURE_RELAY_TRANSPORT_CONFIG_H
#define TOR_FEATURE_RELAY_TRANSPORT_CONFIG_H

typedef struct or_options_t or_options_t;
typedef struct smartlist_t smartlist_t;

char *get_transport_bindaddr_from_config(const char *transport);
smartlist_t *get_options_from_transport_options_line(const char *line,
                                                     const char *transport);
smartlist_t *get_options_for_server_transport(const char *transport);

int options_validate_server_transport(const or_options_t *old_options,
                                      or_options_t *options,
                                      char **msg);

int options_act_server_transport(const or_options_t *old_options);

#endif /* !defined(TOR_FEATURE_RELAY_TRANSPORT_CONFIG_H) */
