/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file transports.h
 * \brief Headers for transports.c
 **/

#ifndef TOR_TRANSPORTS_H
#define TOR_TRANSPORTS_H

void pt_kickstart_proxy(char *method, char **proxy_argv,
                        int is_server);

#define pt_kickstart_client_proxy(m, pa)  \
  pt_kickstart_proxy(m, pa, 0)
#define pt_kickstart_server_proxy(m, pa) \
  pt_kickstart_proxy(m, pa, 1)

void pt_configure_remaining_proxies(void);

int pt_proxies_configuration_pending(void);

void pt_free_all(void);

#ifdef PT_PRIVATE
/** State of the managed proxy configuration protocol. */
enum pt_proto_state {
  PT_PROTO_INFANT, /* was just born */
  PT_PROTO_LAUNCHED, /* was just launched */
  PT_PROTO_ACCEPTING_METHODS, /* accepting methods */
  PT_PROTO_CONFIGURED, /* configured successfully */
  PT_PROTO_COMPLETED, /* configure and registered its transports */
  PT_PROTO_BROKEN
};

/** Structure containing information of a managed proxy. */
typedef struct {
  enum pt_proto_state conf_state; /* the current configuration state */
  char **argv; /* the cli arguments of this proxy */
  int conf_protocol; /* the configuration protocol version used */

  int is_server; /* is it a server proxy? */

  FILE *stdout; /* a stream to its stdout
                   (closed in managed_proxy_destroy()) */

  smartlist_t *transports_to_launch; /* transports to-be-launched by this proxy */
  smartlist_t *transports; /* list of transport_t this proxy spawned */
} managed_proxy_t;

int parse_cmethod_line(char *line, managed_proxy_t *mp);
int parse_smethod_line(char *line, managed_proxy_t *mp);

int parse_version(char *line, managed_proxy_t *mp);
void parse_env_error(char *line);
void handle_proxy_line(char *line, managed_proxy_t *mp);

#endif

#endif

