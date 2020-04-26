/* Copyright (c) 2019 Christian Hofer.
 * Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef DNS_LOOKUP_ST_H
#define DNS_LOOKUP_ST_H

#include "core/or/or.h"
#include "lib/cc/torint.h"
#include "lib/container/dns_message_st.h"
#include "lib/wallclock/timeval.h"

typedef enum lookup_action_t {
  DNS_LOOKUP_ACTION_FORWARD,
  DNS_LOOKUP_ACTION_RESOLVE,
  DNS_LOOKUP_ACTION_VALIDATE
} lookup_action_t;

typedef struct nameserver_t {
  char *hostname;
  uint16_t port;
  smartlist_t *zones;
  uint16_t latency;
  uint16_t sleep;
  uint16_t backoff;
} nameserver_t;

typedef struct validation_t {
  uint8_t action;
  dns_message_t *message;
  uint8_t section;
  smartlist_t *completed;

  dns_name_t *active_zone;
  dns_name_t *active_child;

  smartlist_t *zones;
  smartlist_t *apex_dnskeys;
  smartlist_t *delegation_signers;
} validation_t;

/** State of a DNS lookup. */
struct dns_lookup_t {
  lookup_action_t action;

  dns_name_t *qname;
  uint16_t qtype;
  struct timeval start_time;

  nameserver_t *nameserver;
  validation_t *validation;

  struct evdns_server_request *server_request;
  entry_connection_t *ap_conn;
};

#endif
