/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file relay_config.h
 * @brief Header for feature/relay/relay_config.c
 **/

#ifndef TOR_FEATURE_RELAY_RELAY_CONFIG_H
#define TOR_FEATURE_RELAY_RELAY_CONFIG_H

typedef struct or_options_t or_options_t;
typedef struct smartlist_t smartlist_t;

int parse_ports_relay(or_options_t *options,
                      char **msg,
                      smartlist_t *ports_out,
                      int *have_low_ports_out);
void update_port_set_relay(or_options_t *options,
                           const smartlist_t *ports);

#endif /* !defined(TOR_FEATURE_RELAY_RELAY_CONFIG_H) */
