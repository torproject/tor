/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file pluggable_transpots.h
 * \brief Headers for pluggable_transpots.c
 **/

#ifndef TOR_PLUGGABLE_TRANSPORTS_H
#define TOR_PLUGGABLE_TRANSPORTS_H

int pt_managed_launch_proxy(const char *method,
                         char **proxy_argv, int is_server);

#define pt_managed_launch_client_proxy(m, pa)  \
  pt_managed_launch_proxy(m, pa, 0)
#define pt_managed_launch_server_proxy(m, pa) \
  pt_managed_launch_proxy(m, pa, 1)

void pt_configure_remaining_proxies(void);

int pt_proxies_configuration_pending(void);

void pt_free_all(void);

#ifdef PT_PRIVATE
/** State of the managed proxy configuration protocol. */
enum pt_proto_state {
  PT_PROTO_INFANT, /* was just born */
  PT_PROTO_ACCEPTING_METHODS, /* accepting methods */
  PT_PROTO_CONFIGURED, /* configured successfully */
  PT_PROTO_COMPLETED, /* configure and registered its transports */
  PT_PROTO_BROKEN
};

/** Structure containing information of a managed proxy. */
typedef struct {
  enum pt_proto_state conf_state; /* the current configuration state */
  int conf_protocol; /* the configuration protocol version used */

  FILE *stdout; /* a stream to its stdout
                   (closed in managed_proxy_destroy()) */

  smartlist_t *transports; /* list of transports this proxy spawns */
} managed_proxy_t;

int parse_cmethod_line(char *line, managed_proxy_t *mp);
int parse_smethod_line(char *line, managed_proxy_t *mp);

int parse_version(char *line, managed_proxy_t *mp);
void parse_env_error(char *line);
void handle_proxy_line(char *line, managed_proxy_t *mp);

#endif

#endif

