/* Copyright (c) 2019 Christian Hofer.
 * Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file dns_resolver.c
 * \brief Implementation of a security aware DNS resolver.
 **/

#define DNS_RESOLVER_PRIVATE
#include "core/or/dns_resolver.h"

#include "core/or/or.h"
#include "app/config/config.h"
#include "core/mainloop/connection.h"
#include "core/mainloop/mainloop.h"
#include "core/or/connection_edge.h"
#include "core/or/dns_lookup_st.h"
#include "core/or/entry_connection_st.h"
#include "core/or/socks_request_st.h"
#include "feature/control/control_events.h"
#include "feature/hs/hs_cache.h"
#include "feature/hs/hs_client.h"
#include "feature/rend/rendcache.h"
#include "feature/rend/rendclient.h"
#include "lib/container/dns_message.h"
#include "lib/container/dns_message_st.h"
#include "lib/crypt_ops/crypto_dnssec.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/defs/dns_types.h"
#include "lib/encoding/dns_string.h"
#include "lib/encoding/dns_wireformat.h"
#include "lib/wallclock/timeval.h"
#include "lib/wallclock/tor_gettimeofday.h"

#include <event2/dns.h>
#include <event2/dns_struct.h>

#define MAX_BACKOFF_ATTEMPTS 90
#define MSEC_PER_SEC 1000
#define USEC_PER_MSEC 1000

/** A hash table to cache DNS messages. */
static strmap_t *dns_message_cache = NULL;

/** Index of the next nameserver to ping. */
static int ping_nameserver_index = 0;

/** Initialize DNS resolver. */
void
dns_resolver_init(void)
{
  dns_message_cache = strmap_new();
}

/** Free all DNS resolver resources. */
void
dns_resolver_free_all(void)
{
  if (!dns_message_cache) {
    return;
  }
  strmap_free(dns_message_cache, (void (*)(void *)) dns_message_free_);
}

/** Return a new dns_lookup_t. */
dns_lookup_t *
dns_lookup_new(void)
{
  dns_lookup_t *dl = tor_malloc_zero(sizeof(dns_lookup_t));
  dl->action = 0;
  dl->qname = NULL;
  dl->qtype = 0;
  dl->nameserver = NULL;
  dl->validation = NULL;
  dl->server_request = NULL;
  dl->ap_conn = NULL;
  return dl;
}

/** Free all storage held in the dns_lookup_t <b>dl</b>. */
void
dns_lookup_free_(dns_lookup_t *dl)
{
  if (!dl) {
    return;
  }
  dns_name_free(dl->qname);
  validation_free(dl->validation);
  tor_free(dl);
}

/** Create and register a new DNS lookup connection to resolve the qname given
 * in <b>req</b>. Return 0 on success, < 0 otherwise. */
int
dns_resolver_initiate_server_request_forward(struct evdns_server_request *req)
{
  // LCOV_EXCL_START
  tor_assert(req);
  // LCOV_EXCL_STOP

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();
  dns_lookup_t *lookup = dns_conn->dns_lookup;

  if (dns_resolver_lookup_setup_forward_query(lookup, req) < 0) {
    log_debug(LD_APP, "Couldn't setup lookup query.");
    connection_free_(ENTRY_TO_CONN(dns_conn));
    return -1;
  }

  log_debug(LD_APP, "Forward server request: %s/%d.",
            dns_name_str(lookup->qname), lookup->qtype);

  dns_message_t *cached_message = dns_resolver_cache_get_message(lookup->qname,
                                                                lookup->qtype);
  if (cached_message) {
    log_debug(LD_APP, "Using cached message.");
    connection_free_(ENTRY_TO_CONN(dns_conn));
    return dns_resolver_resolve_server_request(req, cached_message);
  }

  nameserver_t *nameserver = dns_resolver_choose_nameserver_for_lookup(lookup);
  if (!nameserver) {
    log_debug(LD_APP, "Couldn't find working nameserver.");
    connection_free_(ENTRY_TO_CONN(dns_conn));
    return -2;
  }
  dns_resolver_assign_nameserver(dns_conn, nameserver);

  if (dns_resolver_add_query(dns_conn) < 0) {
    log_debug(LD_APP, "Couldn't add query to DNS lookup connection.");
    connection_free_(ENTRY_TO_CONN(dns_conn));
    return -3;
  }

  log_debug(LD_APP, "Successfully prepared DNS lookup connection.");

  connection_add(ENTRY_TO_CONN(dns_conn));
  control_event_stream_status(dns_conn, STREAM_EVENT_NEW_RESOLVE, 0);
  return connection_ap_rewrite_and_attach_if_allowed(dns_conn, NULL, NULL);
}

/** Create and register a new DNS lookup connection to resolve the socks
 * address given in <b>ap_conn</b>. Return 0 on success, < 0 otherwise. */
int
dns_resolver_initiate_socks_address_resolution(entry_connection_t *ap_conn)
{
  // LCOV_EXCL_START
  tor_assert(ap_conn);
  // LCOV_EXCL_STOP

  connection_t *conn = ENTRY_TO_CONN(ap_conn);
  if (conn->read_event) {
    connection_stop_reading(conn);
  }

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();
  dns_lookup_t *lookup = dns_conn->dns_lookup;

  if (dns_resolver_lookup_setup_resolution_query(lookup, ap_conn) < 0) {
    log_debug(LD_APP, "Couldn't setup lookup query.");
    connection_free_(ENTRY_TO_CONN(dns_conn));
    return -1;
  }

  log_debug(LD_APP, "Resolve socks address: %s/%d.",
            dns_name_str(lookup->qname), lookup->qtype);

  dns_message_t *cached_message = dns_resolver_cache_get_message(lookup->qname,
                                                                lookup->qtype);
  if (cached_message) {
    log_debug(LD_APP, "Using cached message.");
    connection_free_(ENTRY_TO_CONN(dns_conn));
    return dns_resolver_resolve_socks_address(ap_conn, cached_message);
  }

  nameserver_t *nameserver = dns_resolver_choose_nameserver_for_lookup(lookup);
  if (!nameserver) {
    log_debug(LD_APP, "Couldn't find working nameserver.");
    connection_free_(ENTRY_TO_CONN(dns_conn));
    return -2;
  }
  dns_resolver_assign_nameserver(dns_conn, nameserver);

  if (dns_resolver_add_query(dns_conn) < 0) {
    log_debug(LD_APP, "Couldn't add query to DNS lookup connection.");
    connection_free_(ENTRY_TO_CONN(dns_conn));
    return -3;
  }

  log_debug(LD_APP, "Successfully prepared DNS lookup connection.");

  connection_add(ENTRY_TO_CONN(dns_conn));
  control_event_stream_status(dns_conn, STREAM_EVENT_NEW_RESOLVE, 0);
  return connection_ap_rewrite_and_attach_if_allowed(dns_conn, NULL, NULL);
}

/** Ping one of the configured nameservers in DNSResolverNameservers. */
void
dns_resolver_ping_nameserver(void)
{
  nameserver_t *nameserver = dns_resolver_choose_nameserver_to_ping();

  if (!nameserver) {
    log_debug(LD_APP, "Skipping... no nameserver available.");
    return;
  }

  log_debug(LD_APP, "Ping nameserver: %5u - %s:%d", nameserver->latency,
            nameserver->hostname, nameserver->port);

  dns_name_t *qname = dns_name_of(".");
  uint8_t qtype = DNS_TYPE_NS;

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();
  dns_resolver_lookup_set_query(dns_conn->dns_lookup,
                                DNS_LOOKUP_ACTION_RESOLVE, qname, qtype);
  dns_resolver_assign_nameserver(dns_conn, nameserver);

  if (dns_resolver_add_query(dns_conn) < 0) {
    // LCOV_EXCL_START
    log_debug(LD_APP, "Couldn't add query to DNS lookup connection.");

    connection_free_(ENTRY_TO_CONN(dns_conn));
    // LCOV_EXCL_STOP
  } else {
    log_debug(LD_APP, "Successfully prepared DNS lookup connection.");

    connection_add(ENTRY_TO_CONN(dns_conn));
    control_event_stream_status(dns_conn, STREAM_EVENT_NEW_RESOLVE, 0);
    connection_ap_rewrite_and_attach_if_allowed(dns_conn, NULL, NULL);
  }

  dns_name_free(qname);
}

/** Handle DNS reply and act accordingly. Decode message from connection
 * buffer, if it is valid forward it based on lookup action. */
int
dns_resolver_process_reply(entry_connection_t *dns_conn)
{
  // LCOV_EXCL_START
  tor_assert(dns_conn);
  tor_assert(dns_conn->dns_lookup);
  // LCOV_EXCL_STOP

  connection_t *conn = ENTRY_TO_CONN(dns_conn);
  dns_lookup_t *lookup = dns_conn->dns_lookup;

  dns_message_t *response = dns_message_new();

  if (dns_decode_message_tcp(response, conn->outbuf) < 0) {
    log_debug(LD_APP, "Failed decoding dns message.");
    dns_message_free(response);
    return -1;
  } else {
    log_debug(LD_APP, "Received response:\n%s", dns_message_str(response));
    int should_penalize = response->header->rcode == DNS_RCODE_REFUSED;
    dns_resolver_update_nameserver_latency(lookup, should_penalize);
  }

  if (response->header->qdcount == 0) {
    log_debug(LD_APP, "Skipping... got response without question.");
    dns_resolver_update_nameserver_latency(lookup, 2);
    dns_message_free(response);
    return -2;
  }

  switch (lookup->action)
  {
  case DNS_LOOKUP_ACTION_FORWARD:
    return dns_resolver_complete_server_request_forward(dns_conn, response);

  case DNS_LOOKUP_ACTION_RESOLVE:
    return dns_resolver_handle_resolution_reply(dns_conn, response);

  case DNS_LOOKUP_ACTION_VALIDATE:
    return dns_resolver_handle_validation_reply(dns_conn, response);

  default:
    log_info(LD_APP, "Invalid lookup action: %d", lookup->action);
    dns_message_free(response);
    return -3;
  }
}

/** Given the value that the user has set for DNSResolverDNSSECMode, return the
 * DNSSEC mode for the configured value in DNSResolverDNSSECMode. The fallback
 * for unrecognized modes is validate. Supported modes are:
 * off, process, trust, and validate. */
int
dns_resolver_config_revise_dnssec_mode(const char *mode)
{
  if (!mode) {
    return DNSSEC_MODE_VALIDATE;
  }

  if (strcasecmp(mode, "off") == 0) {
    return DNSSEC_MODE_OFF;
  }

  if (strcasecmp(mode, "process") == 0) {
    return DNSSEC_MODE_PROCESS;
  }

  if (strcasecmp(mode, "trust") == 0) {
    return DNSSEC_MODE_TRUST;
  }

  if (strcasecmp(mode, "validate") == 0) {
    return DNSSEC_MODE_VALIDATE;
  }

  return DNSSEC_MODE_VALIDATE;
}

/** Given the value that the user has set for DNSResolverNameservers, create an
 * updated nameserver list based on the configured nameservers and previously
 * used nameserver list in <b>old_options</b>. */
smartlist_t *
dns_resolver_config_revise_nameservers(const smartlist_t *nameservers,
                                       const or_options_t *old_options)
{
  // LCOV_EXCL_START
  tor_assert(nameservers);
  // LCOV_EXCL_STOP

  smartlist_t *old_nameservers = NULL;
  smartlist_t *updated_nameservers = NULL;

  if (old_options) {
    old_nameservers = old_options->DNSResolverNameservers;
  }
  updated_nameservers = dns_resolver_nameserver_create_list(nameservers,
                                                            old_nameservers);

  if (old_nameservers) {
    dns_resolver_nameserver_free_outdated(old_nameservers,
                                          updated_nameservers);
    smartlist_clear(old_nameservers);
  }

  return updated_nameservers;
}

/** Free all storage held in the DNSResolverNameservers. */
void
dns_resolver_config_free_nameservers(smartlist_t *nameservers)
{
  if (!nameservers) {
    return;
  }

  SMARTLIST_FOREACH_BEGIN(nameservers, nameserver_t *, nameserver) {
    nameserver_free(nameserver);
  } SMARTLIST_FOREACH_END(nameserver);

  smartlist_free(nameservers);
}

/** Create a new nameserver zone map for the given <b>nameservers</b>. */
strmap_t *
dns_resolver_config_revise_nameserver_zone_map(const smartlist_t *nameservers)
{
  // LCOV_EXCL_START
  tor_assert(nameservers);
  // LCOV_EXCL_STOP

  strmap_t *zone_map = strmap_new();

  SMARTLIST_FOREACH_BEGIN(nameservers, nameserver_t *, nameserver) {
    SMARTLIST_FOREACH_BEGIN(nameserver->zones, const dns_name_t *, zone) {

      smartlist_t *list = strmap_get_lc(zone_map, dns_name_str(zone));
      if (!list) {
        list = smartlist_new();
        strmap_set_lc(zone_map, dns_name_str(zone), list);
      }

      if (!smartlist_contains(list, nameserver)) {
        smartlist_add(list, nameserver);
      }

    } SMARTLIST_FOREACH_END(zone);
  } SMARTLIST_FOREACH_END(nameserver);

  return zone_map;
}

/** Free all storage held in the DNSResolverNameserverZoneMap. */
void
dns_resolver_config_free_nameserver_zone_map(strmap_t *zone_map)
{
  if (!zone_map) {
    return;
  }

  strmap_free(zone_map, (void (*)(void *)) smartlist_free_);
}

/** Given the value that the user has set for DNSResolverTrustAnchors, create
 * an updated trust anchor list based on the configured trust anchors and
 * previously used trust anchor list in <b>old_options</b>. */
smartlist_t *
dns_resolver_config_revise_trust_anchors(const smartlist_t *trust_anchors)
{
  // LCOV_EXCL_START
  tor_assert(trust_anchors);
  // LCOV_EXCL_STOP

  smartlist_t *updated_trust_anchors = smartlist_new();

  SMARTLIST_FOREACH_BEGIN(trust_anchors, char *, trust_anchor) {

    dns_rr_t *rr = dns_rr_value_of(trust_anchor);
    if (dns_type_is(rr->rrtype, DNS_TYPE_DS)) {
      rr->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
      smartlist_add(updated_trust_anchors, rr);
      log_debug(LD_APP, "Add trust anchor: %s", dns_rr_str(rr));
    } else {
      dns_rr_free(rr);
    }

  } SMARTLIST_FOREACH_END(trust_anchor);

  return updated_trust_anchors;
}

/** Free all storage held in the DNSResolverTrustAnchors. */
void
dns_resolver_config_free_trust_anchors(smartlist_t *trust_anchors)
{
  if (!trust_anchors) {
    return;
  }

  SMARTLIST_FOREACH_BEGIN(trust_anchors, dns_rr_t *, trust_anchor) {
    dns_rr_free(trust_anchor);
  } SMARTLIST_FOREACH_END(trust_anchor);

  smartlist_free(trust_anchors);
}

/** Allocate and return a new entry_connection_t, initialized to perform DNS
 * lookups. */
entry_connection_t *
dns_resolver_dns_connection_new(void)
{
  entry_connection_t *dns_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  connection_t *conn = ENTRY_TO_CONN(dns_conn);
  CONNECTION_AP_EXPECT_NONPENDING(dns_conn);
  conn->state = AP_CONN_STATE_SOCKS_WAIT;
  conn->port = 0;
  conn->address = tor_strdup("(DNS lookup)");

  dns_conn->dns_lookup = dns_lookup_new();

  dns_conn->entry_cfg.session_group = SESSION_GROUP_DNS_LOOKUP;
  dns_conn->entry_cfg.isolation_flags = ISO_DEFAULT;
  dns_conn->entry_cfg.ipv4_traffic = 1;
  dns_conn->entry_cfg.ipv6_traffic = 1;
  dns_conn->entry_cfg.dns_request = 0;
  dns_conn->entry_cfg.onion_traffic = 1;
  dns_conn->entry_cfg.use_cached_ipv4_answers = 0;
  dns_conn->entry_cfg.use_cached_ipv6_answers = 0;

  dns_conn->nym_epoch = get_signewnym_epoch();

  return dns_conn;
}

/** Return a new nameserver_t. */
nameserver_t *
nameserver_new(void)
{
  nameserver_t *nsrv = tor_malloc_zero(sizeof(nameserver_t));
  nsrv->hostname = NULL;
  nsrv->port = 0;
  nsrv->zones = smartlist_new();
  nsrv->latency = 0;
  nsrv->sleep = 0;
  nsrv->backoff = 0;
  return nsrv;
}

/** Free all storage held in the nameserver_t <b>nsrv</b>. */
void
nameserver_free_(nameserver_t *nsrv)
{
  if (!nsrv) {
    return;
  }
  tor_free(nsrv->hostname);
  SMARTLIST_FOREACH(nsrv->zones, dns_name_t *, zone, dns_name_free(zone));
  smartlist_free(nsrv->zones);
  tor_free(nsrv);
}

/** Return a new validation_t. */
validation_t *
validation_new(void)
{
  validation_t *val = tor_malloc_zero(sizeof(validation_t));
  val->action = 0;
  val->message = NULL;
  val->section = 0;
  val->completed = smartlist_new();
  val->active_zone = NULL;
  val->active_child = NULL;
  val->zones = NULL;
  val->apex_dnskeys = smartlist_new();
  val->delegation_signers = smartlist_new();
  return val;
}

/** Free all storage held in the validation_t <b>val</b>. */
void
validation_free_(validation_t *val)
{
  if (!val) {
    return;
  }
  dns_message_free(val->message);
  SMARTLIST_FOREACH(val->completed, dns_name_t *, zone, dns_name_free(zone));
  smartlist_free(val->completed);
  dns_name_free(val->active_zone);
  dns_name_free(val->active_child);
  if (val->zones) {
    SMARTLIST_FOREACH(val->zones, dns_name_t *, zone, dns_name_free(zone));
    smartlist_free(val->zones);
  }
  SMARTLIST_FOREACH(val->apex_dnskeys, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(val->apex_dnskeys);
  SMARTLIST_FOREACH(val->delegation_signers, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_free(val->delegation_signers);
  tor_free(val);
}

/** Handle resolution reply and act accordingly. Either initiate follow-up
 * operation or resolve socks address. */
int
dns_resolver_handle_resolution_reply(entry_connection_t *dns_conn,
                                     dns_message_t *resp)
{
  const or_options_t *options = get_options();

  // LCOV_EXCL_START
  tor_assert(dns_conn);
  tor_assert(dns_conn->dns_lookup);
  tor_assert(resp);
  // LCOV_EXCL_STOP

  switch (options->DNSResolverDNSSECMode)
  {
  case DNSSEC_MODE_OFF:
    log_debug(LD_APP, "DNSSEC mode is OFF.");
    return dns_resolver_complete_socks_address_resolution_closing(dns_conn,
                                                                  resp);

  case DNSSEC_MODE_TRUST:
    log_debug(LD_APP, "DNSSEC mode is TRUST.");
    return dns_resolver_complete_socks_address_resolution_closing(dns_conn,
                                                                  resp);

#ifdef ENABLE_OPENSSL

  case DNSSEC_MODE_PROCESS:
    log_debug(LD_APP, "DNSSEC mode is PROCESS.");
    if (dns_resolver_complete_socks_address_resolution(dns_conn,
                                                  dns_message_dup(resp)) < 0) {
      log_debug(LD_APP, "Unable to resolve socks address.");
    }
    return dns_resolver_validation_initiate(dns_conn, resp);

  case DNSSEC_MODE_VALIDATE:
    log_debug(LD_APP, "DNSSEC mode is VALIDATE.");
    return dns_resolver_validation_initiate(dns_conn, resp);

#else

  case DNSSEC_MODE_PROCESS:
  case DNSSEC_MODE_VALIDATE:
    log_warn(LD_APP, "Skipping DNSSEC validation... we require OpenSSL.");
    return dns_resolver_complete_socks_address_resolution_closing(dns_conn,
                                                                  resp);

#endif /* defined(ENABLE_OPENSSL) */

  default:
    log_info(LD_APP, "Got unknown DNSSEC mode %d.",
             options->DNSResolverDNSSECMode);
    log_debug(LD_APP, "Closing DNS lookup connection.");
    connection_mark_unattached_ap(dns_conn, END_STREAM_REASON_DESTROY);
    dns_message_free(resp);
    return -1;
  }
}

/** Handle validation reply and act accordingly. */
int
dns_resolver_handle_validation_reply(entry_connection_t *dns_conn,
                                     dns_message_t *resp)
{
  // LCOV_EXCL_START
  tor_assert(dns_conn);
  tor_assert(dns_conn->dns_lookup);
  tor_assert(dns_conn->dns_lookup->validation);
  // LCOV_EXCL_STOP

  dns_lookup_t *lookup = dns_conn->dns_lookup;

  switch (lookup->validation->action)
  {
  case VALIDATION_ACTION_APEX_KEYS:
    return dns_resolver_validation_apex_dnskeys_response(dns_conn, resp);

  case VALIDATION_ACTION_DELEGATION:
    return dns_resolver_validation_delegation_response(dns_conn, resp);

  case VALIDATION_ACTION_ZONE_CUT:
    return dns_resolver_validation_zone_cut_response(dns_conn, resp);

  default:
    log_info(LD_APP, "Got unknown validation action: %d.",
             lookup->validation->action);
    dns_message_free(resp);
    return -1;
  }
}

/** Initiate new trust chain validation. Return 0 on success, < 0 otherwise. */
int
dns_resolver_validation_initiate(entry_connection_t *dns_conn,
                                 dns_message_t *resp)
{
  // LCOV_EXCL_START
  tor_assert(dns_conn);
  tor_assert(dns_conn->dns_lookup);
  tor_assert(resp);
  // LCOV_EXCL_STOP

  dns_lookup_t *lookup = dns_conn->dns_lookup;
  lookup->action = DNS_LOOKUP_ACTION_VALIDATE;

  dns_question_t *question = dns_message_get_question(resp);
  if (!question) {
    log_debug(LD_APP, "Skip validation for message without question.");
    return -1;
  }
  log_debug(LD_APP, "Initiate validation for %s/%s",
            dns_name_str(question->qname), question->qtype->name);

  SMARTLIST_FOREACH_BEGIN(resp->answer_list, dns_rr_t *, rr) {
    rr->validation_state = DNSSEC_VALIDATION_STATE_INDETERMINATE;
  } SMARTLIST_FOREACH_END(rr);
  SMARTLIST_FOREACH_BEGIN(resp->name_server_list, dns_rr_t *, rr) {
    rr->validation_state = DNSSEC_VALIDATION_STATE_INDETERMINATE;
  } SMARTLIST_FOREACH_END(rr);

  validation_free(lookup->validation);
  lookup->validation = validation_new();
  lookup->validation->message = resp;
  lookup->validation->section = DNS_MESSAGE_SECTION_ANSWER;

  return dns_resolver_validation_initiate_next_chain(dns_conn);
}

/** Initiate validation of new trust chain. In case there are no trust chains
 * left, answer the initial resolve request. Return 0 on success, < 0
 * otherwise. */
int
dns_resolver_validation_initiate_next_chain(entry_connection_t *dns_conn)
{
  const or_options_t *options = get_options();

  // LCOV_EXCL_START
  tor_assert(dns_conn);
  tor_assert(dns_conn->dns_lookup);
  tor_assert(dns_conn->dns_lookup->validation);
  tor_assert(dns_conn->dns_lookup->validation->message);
  // LCOV_EXCL_STOP

  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;

  if (dns_resolver_validation_choose_next_zone_to_validate(validation) < 0) {

    log_debug(LD_APP, "All trust chains completed.");

    // LCOV_EXCL_START
    if (PREDICT_UNLIKELY(log_global_min_severity_ == LOG_DEBUG)) {
      SMARTLIST_FOREACH_BEGIN(validation->message->answer_list, dns_rr_t *,
                              rr) {
        log_notice(LD_APP, "%d - %s", rr->validation_state, dns_rr_str(rr));
      } SMARTLIST_FOREACH_END(rr);
      SMARTLIST_FOREACH_BEGIN(validation->message->name_server_list,
                              dns_rr_t *, rr) {
        log_notice(LD_APP, "%d - %s", rr->validation_state, dns_rr_str(rr));
      } SMARTLIST_FOREACH_END(rr);
    }
    // LCOV_EXCL_STOP

    if (dns_resolver_cache_add_message(validation->message) < 0) {
      log_debug(LD_APP, "Resolution response was not added to cache.");
    }

    return dns_resolver_complete_socks_address_resolution_closing(dns_conn,
                                         dns_message_dup(validation->message));

  } else {
    log_debug(LD_APP, "Initiate trust chain: %s",
              dns_name_str(validation->active_zone));

    if (!options->DNSResolverTrustAnchors ||
        smartlist_len(options->DNSResolverTrustAnchors) == 0) {

      log_debug(LD_APP, "Skipping... no trust anchors available.");
      return dns_resolver_validation_initiate_next_chain(dns_conn);
    }

    // Cleanup and set trust chain zones.
    if (validation->zones) {
      SMARTLIST_FOREACH(validation->zones, dns_name_t *, zone,
                        dns_name_free(zone));
      smartlist_free(validation->zones);
    }
    validation->zones = dns_resolver_get_zones_for_name(
                          validation->active_zone,
                          options->DNSResolverTrustAnchors);

    // Cleanup and set active child zone.
    dns_name_free(validation->active_child);
    validation->active_child = smartlist_pop_last(validation->zones);

    if (!validation->active_child) {
      log_debug(LD_APP, "Unable to find trust anchor for trust chain.");
      dns_resolver_validation_update_state(validation,
                                        DNSSEC_VALIDATION_STATE_INDETERMINATE);
      return dns_resolver_validation_initiate_next_chain(dns_conn);
    }

    // Cleanup and set delegation signers.
    SMARTLIST_FOREACH(validation->delegation_signers, dns_rr_t *, rr,
                      dns_rr_free(rr));
    smartlist_clear(validation->delegation_signers);

    SMARTLIST_FOREACH_BEGIN(options->DNSResolverTrustAnchors,
                            dns_rr_t *, rr) {
      if (dns_type_is(rr->rrtype, DNS_TYPE_DS)) {
        log_debug(LD_APP, "Add trust anchor: %s", dns_rr_str(rr));
        smartlist_add(validation->delegation_signers, dns_rr_dup(rr));
      }
    } SMARTLIST_FOREACH_END(rr);

    return dns_resolver_validation_apex_dnskeys_request(dns_conn);
  }
}

/** Conclude trust chain validation and initiate next trust chain validation.
 * Validate the message's resource records with the retrieved DNSKEYs. Return 0
 * on success, < 0 otherwise. */
int
dns_resolver_validation_conclude_chain(entry_connection_t *dns_conn)
{
  const or_options_t *options = get_options();

  // LCOV_EXCL_START
  tor_assert(dns_conn);
  tor_assert(dns_conn->dns_lookup);
  tor_assert(dns_conn->dns_lookup->validation);
  tor_assert(dns_conn->dns_lookup->validation->message);
  // LCOV_EXCL_STOP

  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;

  log_debug(LD_APP, "No more zones in chain %s Validate RRs in message.",
            dns_name_str(validation->active_zone));

  if (validation->section == DNS_MESSAGE_SECTION_ANSWER) {
    if (dnssec_authenticate_rrset(validation->message->answer_list,
                                  validation->apex_dnskeys) < 0) {
      log_debug(LD_APP, "Unable to authenticate answer records.");
      if (options->DNSResolverDNSSECMode == DNSSEC_MODE_VALIDATE) {
        log_notice(LD_APP, "%s validates as insecure.",
                   dns_name_str(validation->active_zone));
        validation->message->header->rcode = DNS_RCODE_SERVFAIL;
      }
    }
  }

  if (validation->section == DNS_MESSAGE_SECTION_AUTHORITY) {
    if (dnssec_authenticate_rrset(validation->message->name_server_list,
                                  validation->apex_dnskeys) < 0) {
      log_debug(LD_APP, "Unable to authenticate authority records.");
      if (options->DNSResolverDNSSECMode == DNSSEC_MODE_VALIDATE) {
        log_notice(LD_APP, "%s validates as insecure.",
                   dns_name_str(validation->active_zone));
        validation->message->header->rcode = DNS_RCODE_SERVFAIL;
      }
    }

    dns_question_t *question = dns_message_get_question(validation->message);
    if (question) {
      int rcode = dnssec_denial_of_existence(question->qname,
                    question->qtype->value,
                    validation->message->name_server_list);

      if (rcode == DNSSEC_DENIAL_OF_EXISTENCE_NXDOMAIN) {
        log_debug(LD_APP, "Name does not exist.");
        if (options->DNSResolverDNSSECMode == DNSSEC_MODE_VALIDATE) {
          validation->message->header->rcode = DNS_RCODE_NXDOMAIN;
        }
      }
    }
  }

  // LCOV_EXCL_START
  if (PREDICT_UNLIKELY(log_global_min_severity_ == LOG_DEBUG)) {
    SMARTLIST_FOREACH_BEGIN(validation->message->answer_list, dns_rr_t *, rr) {
      log_notice(LD_APP, "%d - %s", rr->validation_state, dns_rr_str(rr));
    } SMARTLIST_FOREACH_END(rr);
    SMARTLIST_FOREACH_BEGIN(validation->message->name_server_list, dns_rr_t *,
                            rr) {
      log_notice(LD_APP, "%d - %s", rr->validation_state, dns_rr_str(rr));
    } SMARTLIST_FOREACH_END(rr);
  }
  // LCOV_EXCL_STOP

  return dns_resolver_validation_initiate_next_chain(dns_conn);
}

/** Select and return the next zone to validate from <b>validation->message</b>
 * Return 0 on success, < 0 otherwise. */
int
dns_resolver_validation_choose_next_zone_to_validate(validation_t *validation)
{
  // LCOV_EXCL_START
  tor_assert(validation);
  tor_assert(validation->message);
  // LCOV_EXCL_STOP

  if (validation->active_zone) {
    smartlist_add(validation->completed,
                  dns_name_dup(validation->active_zone));
    dns_name_free(validation->active_zone);
  }

  log_debug(LD_APP, "Completed zone: ");
  // LCOV_EXCL_START
  if (PREDICT_UNLIKELY(log_global_min_severity_ == LOG_DEBUG)) {
    SMARTLIST_FOREACH_BEGIN(validation->completed, dns_name_t *, zone) {
      log_notice(LD_APP, "* %s", dns_name_str(zone));
    } SMARTLIST_FOREACH_END(zone);
  }
  // LCOV_EXCL_STOP

  if (validation->section == DNS_MESSAGE_SECTION_ANSWER) {
    SMARTLIST_FOREACH_BEGIN(validation->message->answer_list, dns_rr_t *, rr) {
      if (rr->validation_state == DNSSEC_VALIDATION_STATE_INDETERMINATE &&
          dns_type_is(rr->rrtype, DNS_TYPE_RRSIG) &&
          dns_name_present_in_smartlist(validation->completed,
                                        rr->rrsig->signer_name) == 0) {
        validation->active_zone = dns_name_dup(rr->rrsig->signer_name);
        return 0;
      }
    } SMARTLIST_FOREACH_END(rr);

    SMARTLIST_FOREACH_BEGIN(validation->message->answer_list, dns_rr_t *, rr) {
      if (rr->validation_state == DNSSEC_VALIDATION_STATE_INDETERMINATE &&
          !dns_type_is(rr->rrtype, DNS_TYPE_RRSIG) &&
          dns_name_present_in_smartlist(validation->completed,
                                        rr->name) == 0) {
        validation->active_zone = dns_name_dup(rr->name);
        return 0;
      }
    } SMARTLIST_FOREACH_END(rr);

    validation->section = DNS_MESSAGE_SECTION_AUTHORITY;
    SMARTLIST_FOREACH(validation->completed, dns_name_t *, zone,
                      dns_name_free(zone));
    smartlist_clear(validation->completed);
  }

  if (validation->section == DNS_MESSAGE_SECTION_AUTHORITY) {
    SMARTLIST_FOREACH_BEGIN(validation->message->name_server_list, dns_rr_t *,
                            rr) {
      if (rr->validation_state == DNSSEC_VALIDATION_STATE_INDETERMINATE &&
          dns_type_is(rr->rrtype, DNS_TYPE_RRSIG) &&
          dns_name_present_in_smartlist(validation->completed,
                                        rr->rrsig->signer_name) == 0) {
        validation->active_zone = dns_name_dup(rr->rrsig->signer_name);
        return 0;
      }
    } SMARTLIST_FOREACH_END(rr);
  }

  return -1;
}

/** Initiate apex dnskeys query. Return 0 on success, < 0 otherwise. */
int
dns_resolver_validation_apex_dnskeys_request(entry_connection_t *dns_conn)
{
  const or_options_t *options = get_options();

  // LCOV_EXCL_START
  tor_assert(dns_conn);
  tor_assert(dns_conn->dns_lookup);
  tor_assert(dns_conn->dns_lookup->validation);
  tor_assert(dns_conn->dns_lookup->validation->active_child);
  // LCOV_EXCL_STOP

  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;
  validation->action = VALIDATION_ACTION_APEX_KEYS;

  log_debug(LD_APP, "Request DNSKEY for zone: %s",
            dns_name_str(validation->active_child));

  dns_message_t *cached_message = dns_resolver_cache_get_message(
                                    validation->active_child, DNS_TYPE_DNSKEY);
  if (cached_message) {
    log_debug(LD_APP, "Using cached message.");
    return dns_resolver_validation_apex_dnskeys_response(dns_conn,
                                                         cached_message);
  }

  dns_resolver_lookup_set_query(dns_conn->dns_lookup, lookup->action,
                                validation->active_child, DNS_TYPE_DNSKEY);

  if (dns_resolver_add_query_processing(dns_conn) < 0) {
    log_info(LD_APP, "Couldn't process query for DNSKEY.");
    if (options->DNSResolverDNSSECMode == DNSSEC_MODE_VALIDATE) {
      validation->message->header->rcode = DNS_RCODE_SERVFAIL;
    }
    return dns_resolver_validation_initiate_next_chain(dns_conn);
  }

  return 0;
}

/** Process apex dnskeys response. Return 0 on success, < 0 otherwise. */
int
dns_resolver_validation_apex_dnskeys_response(entry_connection_t *dns_conn,
                                              dns_message_t *resp)
{
  const or_options_t *options = get_options();

  // LCOV_EXCL_START
  tor_assert(dns_conn);
  tor_assert(dns_conn->dns_lookup);
  tor_assert(dns_conn->dns_lookup->validation);
  tor_assert(dns_conn->dns_lookup->validation->active_child);
  tor_assert(resp);
  // LCOV_EXCL_STOP

  dns_question_t *question = dns_message_get_question(resp);
  if (!question || !dns_type_is(question->qtype, DNS_TYPE_DNSKEY)) {
    log_debug(LD_APP, "Want to process DNSKEY response, but question asked "
              "for different type.");
    return -1;
  }

  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;

  log_debug(LD_APP, "Process DNSKEY response: %s",
            dns_name_str(validation->active_child));

  SMARTLIST_FOREACH(validation->apex_dnskeys, dns_rr_t *, rr, dns_rr_free(rr));
  smartlist_clear(validation->apex_dnskeys);

  smartlist_t *authenticated_child_dnskey_rrset = smartlist_new();

  /* RFC 4035 section-5.2
  * * The Algorithm and Key Tag in the DS RR match the Algorithm field
  *   and the key tag of a DNSKEY RR in the child zone's apex DNSKEY
  *   RRset, and, when the DNSKEY RR's owner name and RDATA are hashed
  *   using the digest algorithm specified in the DS RR's Digest Type
  *   field, the resulting digest value matches the Digest field of the
  *   DS RR.
  * * The matching DNSKEY RR in the child zone has the Zone Flag bit
  *   set, the corresponding private key has signed the child zone's
  *   apex DNSKEY RRset.*/
  if (dnssec_authenticate_delegation_to_child_zone(
        authenticated_child_dnskey_rrset, resp->answer_list,
        validation->delegation_signers) < 0) {
    smartlist_free(authenticated_child_dnskey_rrset);
    dns_message_free(resp);

    log_debug(LD_APP, "Unable to authenticate delegation to the child zone.");
    if (options->DNSResolverDNSSECMode == DNSSEC_MODE_VALIDATE) {
      log_notice(LD_APP, "%s validates as bogus.",
                 dns_name_str(validation->active_zone));
      validation->message->header->rcode = DNS_RCODE_SERVFAIL;
    }
    dns_resolver_validation_update_state(validation,
                                         DNSSEC_VALIDATION_STATE_BOGUS);
    return dns_resolver_validation_initiate_next_chain(dns_conn);
  }

  /* RFC 4035 section-5.2
  * The resulting RRSIG RR authenticates the child zone's apex DNSKEY RRset. */
  if (dnssec_authenticate_rrset(resp->answer_list,
                                authenticated_child_dnskey_rrset) < 0) {
    log_debug(LD_APP, "Unable to authenticate the child apex DNSKEY RRset.");
    if (options->DNSResolverDNSSECMode == DNSSEC_MODE_VALIDATE) {
      log_notice(LD_APP, "%s validates as insecure.",
                 dns_name_str(validation->active_zone));
      validation->message->header->rcode = DNS_RCODE_SERVFAIL;
    }
    dns_resolver_validation_update_state(validation,
                                         DNSSEC_VALIDATION_STATE_INSECURE);
  }

  SMARTLIST_FOREACH_BEGIN(resp->answer_list, dns_rr_t *, rr) {
    if (dns_type_is(rr->rrtype, DNS_TYPE_DNSKEY) &&
        (rr->dnskey->flags & DNS_DNSKEY_FLAG_ZONE) &&
        rr->validation_state == DNSSEC_VALIDATION_STATE_SECURE) {
      smartlist_add(validation->apex_dnskeys, dns_rr_dup(rr));
    }
  } SMARTLIST_FOREACH_END(rr);

  if (dns_resolver_cache_add_message(resp) < 0) {
    log_debug(LD_APP, "DNSKEY response was not added to cache.");
  }

  smartlist_free(authenticated_child_dnskey_rrset);
  dns_message_free(resp);
  return dns_resolver_validation_zone_cut_request(dns_conn);
}

/** Initiate delegation query. */
int
dns_resolver_validation_delegation_request(entry_connection_t *dns_conn)
{
  const or_options_t *options = get_options();

  // LCOV_EXCL_START
  tor_assert(dns_conn);
  tor_assert(dns_conn->dns_lookup);
  tor_assert(dns_conn->dns_lookup->validation);
  tor_assert(dns_conn->dns_lookup->validation->active_child);
  // LCOV_EXCL_STOP

  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;
  validation->action = VALIDATION_ACTION_DELEGATION;

  log_debug(LD_APP, "Request DS for zone: %s",
            dns_name_str(validation->active_child));

  dns_message_t *cached_message = dns_resolver_cache_get_message(
                                    validation->active_child, DNS_TYPE_DS);
  if (cached_message) {
    log_debug(LD_APP, "Using cached message.");
    return dns_resolver_validation_delegation_response(dns_conn,
                                                       cached_message);
  }

  dns_resolver_lookup_set_query(dns_conn->dns_lookup, lookup->action,
                                validation->active_child, DNS_TYPE_DS);

  if (options->DNSResolverTrustAnchors) {
    SMARTLIST_FOREACH_BEGIN(options->DNSResolverTrustAnchors, dns_rr_t *, rr) {
      if (dns_type_is(rr->rrtype, DNS_TYPE_DS) &&
          dns_name_compare(validation->active_child, rr->name) == 0) {

        dns_message_t *trust_anchor =
          dns_resolver_build_dns_message(dns_conn->dns_lookup);
        smartlist_add(trust_anchor->answer_list, dns_rr_dup(rr));
        trust_anchor->header->ancount =
          smartlist_len(trust_anchor->answer_list);

        log_debug(LD_APP, "Using trust anchor.");
        return dns_resolver_validation_delegation_response(dns_conn,
                                                          trust_anchor);
      }
    } SMARTLIST_FOREACH_END(rr);
  }

  if (dns_resolver_add_query_processing(dns_conn) < 0) {
    log_info(LD_APP, "Couldn't process query for DS.");
    if (options->DNSResolverDNSSECMode == DNSSEC_MODE_VALIDATE) {
      validation->message->header->rcode = DNS_RCODE_SERVFAIL;
    }
    return dns_resolver_validation_initiate_next_chain(dns_conn);
  }

  return 0;
}

/** Process delegation response. Return 0 on success, < 0 otherwise. */
int
dns_resolver_validation_delegation_response(entry_connection_t *dns_conn,
                                            dns_message_t *resp)
{
  // LCOV_EXCL_START
  tor_assert(dns_conn);
  tor_assert(dns_conn->dns_lookup);
  tor_assert(dns_conn->dns_lookup->validation);
  tor_assert(dns_conn->dns_lookup->validation->active_child);
  tor_assert(resp);
  // LCOV_EXCL_STOP

  dns_question_t *question = dns_message_get_question(resp);
  if (!question || !dns_type_is(question->qtype, DNS_TYPE_DS)) {
    log_debug(LD_APP, "Want to process DS response, but question asked for "
              "different type.");
    return -1;
  }

  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;

  log_debug(LD_APP, "Process DS response: %s",
            dns_name_str(validation->active_child));

  SMARTLIST_FOREACH(validation->delegation_signers, dns_rr_t *, rr,
                    dns_rr_free(rr));
  smartlist_clear(validation->delegation_signers);

  if (smartlist_len(resp->answer_list) > 0) {
    if (dnssec_authenticate_rrset(resp->answer_list, validation->apex_dnskeys)
        < 0) {
      log_debug(LD_APP, "Unable to authenticate DS RRset.");
    }

    SMARTLIST_FOREACH_BEGIN(resp->answer_list, dns_rr_t *, rr) {
      if (dns_type_is(rr->rrtype, DNS_TYPE_DS) &&
          rr->validation_state == DNSSEC_VALIDATION_STATE_SECURE) {
        smartlist_add(validation->delegation_signers, dns_rr_dup(rr));
      }
    } SMARTLIST_FOREACH_END(rr);
  }

  /* RFC 4035 section-5.2
   * If the referral from the parent zone did not contain a DS RRset, the
   * response should have included a signed NSEC RRset proving that no DS
   * RRset exists for the delegated name (see Section 3.1.4). */
  if (smartlist_len(resp->name_server_list) > 0) {
    if (dnssec_authenticate_rrset(resp->name_server_list,
                                  validation->apex_dnskeys) < 0) {
      log_debug(LD_APP, "Unable to authenticate NSEC RRset.");
    }

    int rcode = dnssec_denial_of_existence(lookup->qname, lookup->qtype,
                                           resp->name_server_list);

    if (rcode == DNSSEC_DENIAL_OF_EXISTENCE_INSECURE ||
        rcode == DNSSEC_DENIAL_OF_EXISTENCE_NXDOMAIN) {
      dns_message_free(resp);

      log_debug(LD_APP, "Set RRset validation state to BOGUS.");
      dns_resolver_validation_update_state(validation,
                                           DNSSEC_VALIDATION_STATE_BOGUS);
      return dns_resolver_validation_initiate_next_chain(dns_conn);
    }

    if (rcode == DNSSEC_DENIAL_OF_EXISTENCE_NXQTYPE ||
        rcode == DNSSEC_DENIAL_OF_EXISTENCE_OPTOUT) {
      dns_message_free(resp);

      log_debug(LD_APP, "Set RRset validation state to INSECURE.");
      dns_resolver_validation_update_state(validation,
                                           DNSSEC_VALIDATION_STATE_INSECURE);
      return dns_resolver_validation_initiate_next_chain(dns_conn);
    }
  }

  if (dns_resolver_cache_add_message(resp) < 0) {
    log_debug(LD_APP, "DS response was not added to cache.");
  }

  dns_message_free(resp);
  return dns_resolver_validation_apex_dnskeys_request(dns_conn);
}

/** Initiate zone cut query. Return 0 on success, < 0 otherwise. */
int
dns_resolver_validation_zone_cut_request(entry_connection_t *dns_conn)
{
  const or_options_t *options = get_options();

  // LCOV_EXCL_START
  tor_assert(dns_conn);
  tor_assert(dns_conn->dns_lookup);
  tor_assert(dns_conn->dns_lookup->validation);
  // LCOV_EXCL_STOP

  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;
  validation->action = VALIDATION_ACTION_ZONE_CUT;

  if (validation->zones && smartlist_len(validation->zones) > 0) {
    dns_name_free(validation->active_child);
    validation->active_child = smartlist_pop_last(validation->zones);

    log_debug(LD_APP, "Request NS for child zone: %s",
              dns_name_str(validation->active_child));

    dns_message_t *cached_message = dns_resolver_cache_get_message(
                                      validation->active_child, DNS_TYPE_NS);
    if (cached_message) {
      log_debug(LD_APP, "Using cached message.");
      return dns_resolver_validation_zone_cut_response(dns_conn,
                                                       cached_message);
    }

    dns_resolver_lookup_set_query(dns_conn->dns_lookup, lookup->action,
                                  validation->active_child, DNS_TYPE_NS);

    if (dns_resolver_add_query_processing(dns_conn) < 0) {
      log_info(LD_APP, "Couldn't process query for NS.");
      if (options->DNSResolverDNSSECMode == DNSSEC_MODE_VALIDATE) {
        validation->message->header->rcode = DNS_RCODE_SERVFAIL;
      }
      return dns_resolver_validation_initiate_next_chain(dns_conn);
    }

    return 0;
  }

  return dns_resolver_validation_conclude_chain(dns_conn);
}

/** Process zone cut response. Return 0 on success, < 0 otherwise. */
int
dns_resolver_validation_zone_cut_response(entry_connection_t *dns_conn,
                                          dns_message_t *resp)
{
  // LCOV_EXCL_START
  tor_assert(dns_conn);
  tor_assert(dns_conn->dns_lookup);
  tor_assert(dns_conn->dns_lookup->validation);
  tor_assert(resp);
  // LCOV_EXCL_STOP

  dns_question_t *question = dns_message_get_question(resp);
  if (!question || !dns_type_is(question->qtype, DNS_TYPE_NS)) {
    log_debug(LD_APP, "Want to process NS response, but question asked for "
              "different type.");
    return -1;
  }

  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;

  log_debug(LD_APP, "Process NS response: %s",
            dns_name_str(validation->active_child));

  bool is_zone_cut = false;
  SMARTLIST_FOREACH_BEGIN(resp->answer_list, dns_rr_t *, rr) {
    if (!is_zone_cut && dns_type_is(rr->rrtype, DNS_TYPE_NS)) {
      is_zone_cut = true;
    }
  } SMARTLIST_FOREACH_END(rr);

  if (dns_resolver_cache_add_message(resp) < 0) {
    log_debug(LD_APP, "NS response was not added to cache.");
  }

  dns_message_free(resp);

  if (is_zone_cut) {
    log_debug(LD_APP, "Found zone cut.");
    return dns_resolver_validation_delegation_request(dns_conn);
  } else {
    dns_name_free(validation->active_child);
    return dns_resolver_validation_zone_cut_request(dns_conn);
  }
}

/** Update the validatoin state of all resource records for the active
 * validation to the given <b>state</b>. */
void
dns_resolver_validation_update_state(const validation_t *validation,
                                     const uint8_t state)
{
  // LCOV_EXCL_START
  tor_assert(validation);
  tor_assert(validation->message);
  // LCOV_EXCL_STOP

  if (!validation->active_zone) {
    return;
  }

  log_debug(LD_APP, "Update state for %s to %d",
            dns_name_str(validation->active_zone), state);

  dns_message_t *message = validation->message;

  SMARTLIST_FOREACH_BEGIN(message->answer_list, dns_rr_t *, rr) {
    if (dns_name_compare(validation->active_zone, rr->name) == 0) {
      rr->validation_state = state;
    }
  } SMARTLIST_FOREACH_END(rr);

  SMARTLIST_FOREACH_BEGIN(message->name_server_list, dns_rr_t *, rr) {
    if (dns_name_compare(validation->active_zone, rr->name) == 0) {
      rr->validation_state = state;
    }
  } SMARTLIST_FOREACH_END(rr);
}

/** Resolve server_request in <b>lookup</b>, if not resolved yet. */
int
dns_resolver_complete_server_request_forward(entry_connection_t *dns_conn,
                                             dns_message_t *resp)
{
  // LCOV_EXCL_START
  tor_assert(dns_conn);
  tor_assert(dns_conn->dns_lookup);
  tor_assert(resp);
  // LCOV_EXCL_STOP

  dns_lookup_t *lookup = dns_conn->dns_lookup;

  struct evdns_server_request *req = lookup->server_request;
  lookup->server_request = NULL;

  log_debug(LD_APP, "Closing DNS lookup connection.");
  connection_mark_unattached_ap(dns_conn,
                                END_STREAM_REASON_DONE |
                                END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);

  return dns_resolver_resolve_server_request(req, resp);
}

/** Resolve server request and respond to <b>req</b>. */
int
dns_resolver_resolve_server_request(struct evdns_server_request *req,
                                    dns_message_t *resp)
{
  // LCOV_EXCL_START
  tor_assert(resp);
  // LCOV_EXCL_STOP

  if (!req) {
    log_debug(LD_APP, "Server request is already resolved.");
    dns_message_free(resp);
    return -1;
  }

  if (resp->header->rcode != DNS_RCODE_SERVFAIL) {
    SMARTLIST_FOREACH_BEGIN(resp->answer_list, dns_rr_t *, rr) {
      dns_resolver_evdns_wrapper_add_reply(req, EVDNS_ANSWER_SECTION, rr);
    } SMARTLIST_FOREACH_END(rr);

    SMARTLIST_FOREACH_BEGIN(resp->name_server_list, dns_rr_t *, rr) {
      dns_resolver_evdns_wrapper_add_reply(req, EVDNS_AUTHORITY_SECTION, rr);
    } SMARTLIST_FOREACH_END(rr);
  }

  dns_resolver_evdns_wrapper_respond(req, resp);
  dns_message_free(resp);

  return 0;
}

// LCOV_EXCL_START
/** Wrapper for evdns_server_request_add_reply. */
MOCK_IMPL(void,
dns_resolver_evdns_wrapper_add_reply, (struct evdns_server_request *req,
                                       int section, dns_rr_t *rr))
{
  tor_assert(req);
  tor_assert(rr);

  evdns_server_request_add_reply(req, section, dns_name_str(rr->name),
                                 rr->rrtype->value, rr->rrclass, rr->ttl,
                                 rr->rdlength, 0, (const char *) rr->rdata);
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
/** Wrapper for evdns_server_request_respond. */
MOCK_IMPL(void,
dns_resolver_evdns_wrapper_respond, (struct evdns_server_request *req,
                                     dns_message_t *resp))
{
  tor_assert(req);
  tor_assert(resp);
  tor_assert(resp->header);

  evdns_server_request_respond(req, resp->header->rcode);
}
// LCOV_EXCL_STOP

/** Resolve ap_conn in <b>lookup</b>, if not resolved yet. */
int
dns_resolver_complete_socks_address_resolution_impl(
                                                  entry_connection_t *dns_conn,
                                                  dns_message_t *resp,
                                                  int is_closing)
{
  // LCOV_EXCL_START
  tor_assert(dns_conn);
  tor_assert(dns_conn->dns_lookup);
  tor_assert(resp);
  // LCOV_EXCL_STOP

  dns_lookup_t *lookup = dns_conn->dns_lookup;

  if (dns_resolver_resolution_should_fallback_to_ipv4(resp)) {
    dns_question_t *question = dns_message_get_question(resp);
    if (!question) {
      // LCOV_EXCL_START
      log_debug(LD_APP, "Unable to fallback to IPv4 without question.");
      return -1;
      // LCOV_EXCL_STOP
    }

    if (dns_resolver_cache_add_message(resp) < 0) {
      log_debug(LD_APP, "Resolution response was not added to cache.");
    }

    log_debug(LD_APP, "IPv6 fallback for %s", dns_name_str(question->qname));
    dns_resolver_lookup_set_query(lookup, DNS_LOOKUP_ACTION_RESOLVE,
                                  question->qname, DNS_TYPE_A);

    dns_message_free(resp);
    return dns_resolver_add_query_processing(dns_conn);
  }

  entry_connection_t *ap_conn = lookup->ap_conn;
  lookup->ap_conn = NULL;

  if (is_closing) {
    log_debug(LD_APP, "Closing DNS lookup connection.");
    connection_mark_unattached_ap(dns_conn,
                                 END_STREAM_REASON_DONE |
                                 END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
  }

  log_debug(LD_APP, "Resolved: %s/%d", dns_name_str(lookup->qname),
            lookup->qtype);

  return dns_resolver_resolve_socks_address(ap_conn, resp);
}

/** Resolve socks address and attach <b>ap_conn</b>. */
int
dns_resolver_resolve_socks_address(entry_connection_t *ap_conn,
                                   dns_message_t *resp)
{
  // LCOV_EXCL_START
  tor_assert(resp);
  // LCOV_EXCL_STOP

  if (!ap_conn) {
    log_debug(LD_APP, "Socks address is already resolved.");
    dns_message_free(resp);
    return -1;
  }

  if (ENTRY_TO_CONN(ap_conn)->magic != ENTRY_CONNECTION_MAGIC) {
    log_debug(LD_APP, "Invalid connection type.");
    dns_message_free(resp);
    return -2;
  }

  smartlist_t *answers = dns_resolver_resolve_socks_address_get_answers(resp);
  log_debug(LD_APP, "Got %d answers.", smartlist_len(answers));

  dns_rr_t *rr = smartlist_choose(answers);
  smartlist_free(answers);

  if (rr) {
    ap_conn->original_dest_address =
      tor_strdup(ap_conn->socks_request->address);

    if (dns_type_is(rr->rrtype, DNS_TYPE_A)) {
      strlcpy(ap_conn->socks_request->address, rr->a,
              sizeof(ap_conn->socks_request->address));
    }

    if (dns_type_is(rr->rrtype, DNS_TYPE_AAAA)) {
      char* target = NULL;
      tor_asprintf(&target, "[%s]", rr->aaaa);

      strlcpy(ap_conn->socks_request->address, target,
              sizeof(ap_conn->socks_request->address));
      tor_free(target);
    }

    if (dns_type_is(rr->rrtype, DNS_TYPE_KEY)) {
      int len = base64_encode(ap_conn->socks_request->address,
                              sizeof(ap_conn->socks_request->address),
                              (const char *) rr->key->public_key,
                              rr->key->public_key_len, 0);

      strlcpy(ap_conn->socks_request->address + len,
              ".onion", sizeof(ap_conn->socks_request->address));
    }

    log_debug(LD_APP, "Resolved %s to %s.", ap_conn->original_dest_address,
              ap_conn->socks_request->address);
  }

  dns_message_free(resp);

  connection_t *conn = ENTRY_TO_CONN(ap_conn);
  if (conn->read_event) {
    connection_start_reading(conn);
  }

  control_event_stream_status(ap_conn, STREAM_EVENT_NEW, 0);
  return connection_ap_rewrite_and_attach_if_allowed(ap_conn, NULL, NULL);
}

/** Collect all known and valid answers from response <b>resp</b>. */
smartlist_t *
dns_resolver_resolve_socks_address_get_answers(dns_message_t *resp)
{
  // LCOV_EXCL_START
  tor_assert(resp);
  // LCOV_EXCL_STOP

  if (resp->header->rcode != DNS_RCODE_NOERROR) {
    log_debug(LD_APP, "Got unsuccessful response.");
    return smartlist_new();
  }

  smartlist_t *answers = smartlist_new();
  smartlist_t *answers_in_cache = smartlist_new();

  SMARTLIST_FOREACH_BEGIN(resp->answer_list, dns_rr_t *, rr) {
    if (dns_type_is(rr->rrtype, DNS_TYPE_A) && rr->a &&
        string_is_valid_ipv4_address(rr->a)) {
      smartlist_add(answers, rr);
    }

    if (dns_type_is(rr->rrtype, DNS_TYPE_AAAA) && rr->aaaa &&
        string_is_valid_ipv6_address(rr->aaaa)) {
      smartlist_add(answers, rr);
    }

    if (dns_type_is(rr->rrtype, DNS_TYPE_KEY) && rr->key &&
        rr->key->public_key && rr->key->public_key_len > 0 &&
        rr->key->protocol == DNS_KEY_PROTO_ONION) {
      smartlist_add(answers, rr);

      char address[MAX_SOCKS_ADDR_LEN];
      int len = base64_encode(address, sizeof(address),
                              (const char *) rr->key->public_key,
                              rr->key->public_key_len, 0);

      if (rr->key->algorithm == DNS_KEY_ALG_HSV2 &&
          len == REND_SERVICE_ID_LEN_BASE32) {
        rend_cache_entry_t *entry = NULL;
        if (rend_cache_lookup_entry(address, -1, &entry) == 0 &&
            rend_client_any_intro_points_usable(entry) == 1) {
          log_debug(LD_APP, "Found address in cache (v2).");
          smartlist_add(answers_in_cache, rr);
        }
      }

      if (rr->key->algorithm == DNS_KEY_ALG_HSV3 &&
          len == HS_SERVICE_ADDR_LEN_BASE32) {
        hs_ident_edge_conn_t *hs_conn_ident =
          tor_malloc_zero(sizeof(hs_ident_edge_conn_t));

        if (hs_parse_address(address, &hs_conn_ident->identity_pk, NULL,
                              NULL) == 0) {
          const hs_descriptor_t *cached_desc =
            hs_cache_lookup_as_client(&hs_conn_ident->identity_pk);
          if (cached_desc &&
              hs_client_any_intro_points_usable(&hs_conn_ident->identity_pk,
                                                cached_desc) == 1) {
            log_debug(LD_APP, "Found address in cache (v3).");
            smartlist_add(answers_in_cache, rr);
          }
        }
        tor_free(hs_conn_ident);
      }
    }

  } SMARTLIST_FOREACH_END(rr);

  if (smartlist_len(answers_in_cache) > 0) {
    smartlist_free(answers);
    return answers_in_cache;
  }

  smartlist_free(answers_in_cache);
  return answers;
}

/** Choose next nameserver to ping. */
nameserver_t *
dns_resolver_choose_nameserver_to_ping(void)
{
  const or_options_t *options = get_options();

  if (!options->DNSResolverNameservers) {
    return NULL;
  }

  int nameservers = smartlist_len(options->DNSResolverNameservers);
  if (ping_nameserver_index >= nameservers) {
    ping_nameserver_index = 0;
  }

  nameserver_t *nameserver = NULL;
  while (nameservers-- > 0) {
    nameserver = smartlist_get(options->DNSResolverNameservers,
                               ping_nameserver_index);

    ping_nameserver_index++;
    if (ping_nameserver_index >=
        smartlist_len(options->DNSResolverNameservers)) {
      ping_nameserver_index = 0;
    }

    if (!dns_resolver_backoff_nameserver(nameserver)) {
      return nameserver;
    }
  }

  return NULL;
}

/** Determine whether the given <b>nameserver</b> is active.
 * Return True in case the nameserver is asleep, False otherwise.
 */
bool
dns_resolver_backoff_nameserver(nameserver_t *nameserver)
{
  // LCOV_EXCL_START
  tor_assert(nameserver);
  // LCOV_EXCL_STOP

  if (nameserver->sleep == 0) {
    if (nameserver->backoff == 1) {
      nameserver->latency = NAMESERVER_MAX_LATENCY_IN_MSEC;
    }
    nameserver->backoff = MIN(MAX_BACKOFF_ATTEMPTS, nameserver->backoff + 1);
    nameserver->sleep = crypto_rand_int_range(1, nameserver->backoff * 3);
    return false;
  } else {
    nameserver->sleep--;
    return true;
  }
}

/** Choose the best fitting nameserver for the given <b>qname</b>. Return NULL
 * in case there is none, otherwise the nameserver. */
nameserver_t *
dns_resolver_choose_nameserver_for_lookup(dns_lookup_t *lookup)
{
  const or_options_t *options = get_options();

  // LCOV_EXCL_START
  tor_assert(lookup);
  tor_assert(lookup->qname);
  // LCOV_EXCL_STOP

  if (!options->DNSResolverNameserverZoneMap) {
    log_debug(LD_APP, "Missing nameserver zone map.");
    return NULL;
  }

  smartlist_t *zone_nameservers = NULL;
  int max_labels = 0;

  STRMAP_FOREACH(options->DNSResolverNameserverZoneMap, zone, smartlist_t *,
                 nameservers) {
    dns_name_t *zone_name = dns_name_of(zone);
    int labels = dns_name_is_part_of(zone_name, lookup->qname);
    dns_name_free(zone_name);

    if (zone_nameservers == NULL) {
      zone_nameservers = nameservers;
      max_labels = labels;
    } else if (labels > max_labels) {
      zone_nameservers = nameservers;
      max_labels = labels;
    }

  } STRMAP_FOREACH_END;

  return dns_resolver_nameserver_find_best_by_latency(zone_nameservers);
}

/** Assign given <b>nameserver</b> to given <b>dns_conn</b> and use it for all
 * upcoming DNS queries. */
void
dns_resolver_assign_nameserver(entry_connection_t *dns_conn,
                               nameserver_t *nameserver)
{
  // LCOV_EXCL_START
  tor_assert(dns_conn);
  tor_assert(dns_conn->dns_lookup);
  tor_assert(dns_conn->socks_request);
  tor_assert(nameserver);
  // LCOV_EXCL_STOP

  log_debug(LD_APP, "Assign: %5u - %s:%d", nameserver->latency,
            nameserver->hostname, nameserver->port);

  dns_conn->dns_lookup->nameserver = nameserver;

  dns_conn->socks_request->command = SOCKS_COMMAND_CONNECT;
  strlcpy(dns_conn->socks_request->address, nameserver->hostname,
    sizeof(dns_conn->socks_request->address));
  dns_conn->socks_request->port = nameserver->port;
  dns_conn->socks_request->has_finished = 1;
}

/** Create nameserver list for given server lines in
 * <b>nameserver_lines</b>, which originates from
 * <b>DNSResolverNameservers</b>. */
smartlist_t *
dns_resolver_nameserver_create_list(const smartlist_t *nameserver_lines,
                                    const smartlist_t *old_nameservers)
{
  // LCOV_EXCL_START
  tor_assert(nameserver_lines);
  // LCOV_EXCL_STOP

  smartlist_t *nameservers = smartlist_new();

  SMARTLIST_FOREACH_BEGIN(nameserver_lines, const char *, line) {
    log_debug(LD_APP, "processing nameserver line: %s", line);

    char *server = NULL;
    smartlist_t *zones = smartlist_new();

    if (dns_resolver_extract_server_and_zones(&server, zones, line) == 0) {

      char *hostname = NULL;
      int port = 0;

      if (dns_resolver_extract_hostname_and_port(&hostname, &port, server) ==
                                                 0) {

        nameserver_t *nameserver = NULL;
        if (old_nameservers) {
          nameserver = dns_resolver_nameserver_find(old_nameservers, zones,
                                                    hostname, port);
        }

        if (!nameserver) {
          nameserver = nameserver_new();
          nameserver->hostname = tor_strdup(hostname);
          nameserver->port = port;
          SMARTLIST_FOREACH_BEGIN(zones, dns_name_t *, zone) {
            smartlist_add(nameserver->zones, dns_name_dup(zone));
          } SMARTLIST_FOREACH_END(zone);
        }

        smartlist_add(nameservers, nameserver);
      } else {
        log_warn(LD_APP, "Invalid nameserver configuration: %s", server);
      }

      tor_free(hostname);
    }

    tor_free(server);
    SMARTLIST_FOREACH(zones, dns_name_t *, zone, dns_name_free(zone));
    smartlist_free(zones);

  } SMARTLIST_FOREACH_END(line);

  return nameservers;
}

/** Find a nameserver in <b>nameservers</b> that matches the given criterions
 * in <b>zones</b>, <b>hostname</b>, and <b>port</b>.
 * Return the nameserver pointer if found, NULL otherwise. */
nameserver_t *
dns_resolver_nameserver_find(const smartlist_t *nameservers,
                             const smartlist_t *zones, const char *hostname,
                             const int port)
{
  // LCOV_EXCL_START
  tor_assert(nameservers);
  tor_assert(zones);
  tor_assert(hostname);
  // LCOV_EXCL_STOP

  // LCOV_EXCL_START
  if (PREDICT_UNLIKELY(log_global_min_severity_ == LOG_DEBUG)) {
    smartlist_t *zone_names = smartlist_new();

    SMARTLIST_FOREACH_BEGIN(zones, const dns_name_t *, zone) {
      smartlist_add(zone_names, (char *) dns_name_str(zone));
    } SMARTLIST_FOREACH_END(zone);

    char *zone_string = smartlist_join_strings(
                                         (smartlist_t *) zones, ", ", 0, NULL);
    log_notice(LD_APP, "Looking for namserver %s:%d with zones: %s", hostname,
               port, zone_string);
    smartlist_free(zone_names);
    tor_free(zone_string);
  }
  // LCOV_EXCL_STOP

  SMARTLIST_FOREACH_BEGIN(nameservers, nameserver_t *, nameserver) {
    bool zones_are_equal = true;
    SMARTLIST_FOREACH_BEGIN(nameserver->zones, dns_name_t *, zone) {
      zones_are_equal &= dns_name_present_in_smartlist(zones, zone) == 1;
    } SMARTLIST_FOREACH_END(zone);

    if (nameserver->port == port &&
        strcasecmp(nameserver->hostname, hostname) == 0 && zones_are_equal) {
      log_debug(LD_APP, "Found nameserver");
      return nameserver;
    }
  } SMARTLIST_FOREACH_END(nameserver);

  return NULL;
}

/** Find best nameserver in <b>nameservers</b> in terms of latency.
 * Return nameserver pointer if found, NULL otherwise. */
nameserver_t *
dns_resolver_nameserver_find_best_by_latency(const smartlist_t *nameservers)
{
  if (!nameservers) {
    return NULL;
  }

  nameserver_t *best_nameserver = NULL;

  smartlist_t *sorted = smartlist_new();
  SMARTLIST_FOREACH_BEGIN(nameservers, nameserver_t *, nameserver) {
    log_debug(LD_APP, "       %5u - %s:%d", nameserver->latency,
              nameserver->hostname, nameserver->port);
    smartlist_add(sorted, nameserver);
  } SMARTLIST_FOREACH_END(nameserver);

  smartlist_sort(sorted, dns_resolver_nameserver_sort_by_latency_asc);

  SMARTLIST_FOREACH_BEGIN(sorted, nameserver_t *, nameserver) {
    if (nameserver->latency > 0) {
      log_debug(LD_APP, "Found: %5u - %s:%d", nameserver->latency,
                nameserver->hostname, nameserver->port);
      best_nameserver = nameserver;
      goto cleanup;
    }
  } SMARTLIST_FOREACH_END(nameserver);

  log_debug(LD_APP, "Unable to find nameserver");

 cleanup:
  smartlist_free(sorted);
  return best_nameserver;
}

/** Free nameserver that are present in <b>old</b> list, but not in
 * <b>new</b> list. */
void
dns_resolver_nameserver_free_outdated(const smartlist_t *old,
                                      const smartlist_t *new)
{
  // LCOV_EXCL_START
  tor_assert(old);
  tor_assert(new);
  // LCOV_EXCL_STOP

  SMARTLIST_FOREACH_BEGIN(old, nameserver_t *, nameserver) {
    if (!dns_resolver_nameserver_find(new, nameserver->zones,
                                      nameserver->hostname,
                                      nameserver->port)) {

      // LCOV_EXCL_START
      if (PREDICT_UNLIKELY(log_global_min_severity_ == LOG_DEBUG)) {
        smartlist_t *zone_names = smartlist_new();

        SMARTLIST_FOREACH_BEGIN(nameserver->zones, const dns_name_t *, zone) {
          smartlist_add(zone_names, (char *) dns_name_str(zone));
        } SMARTLIST_FOREACH_END(zone);

        char *zone_string = smartlist_join_strings(zone_names, ", ", 0, NULL);
        log_notice(LD_APP, "Freeing namserver %s:%d with zones: %s",
                   nameserver->hostname, nameserver->port, zone_string);
        smartlist_free(zone_names);
        tor_free(zone_string);
      }
      // LCOV_EXCL_STOP

      nameserver_free(nameserver);
    }
  } SMARTLIST_FOREACH_END(nameserver);
}

/** Extract <b>server</b> and <b>zones</b> from <b>string</b>.
 * Expected format: [server] [zone1] [zone2].
 * Return 0 on success, < 0 otherwise. */
int
dns_resolver_extract_server_and_zones(char **server, smartlist_t *zones,
                                      const char *string)
{
  // LCOV_EXCL_START
  tor_assert(zones);
  tor_assert(string);
  // LCOV_EXCL_STOP

  int ret = 0;

  smartlist_t *parts = smartlist_new();
  smartlist_split_string(parts, string, " ", SPLIT_IGNORE_BLANK, 0);

  if (smartlist_len(parts) == 0) {
    log_debug(LD_APP, "Unable to extract server and zones from %s", string);
    ret = -1;
    goto cleanup;
  }

  tor_free(*server);
  SMARTLIST_FOREACH(zones, dns_name_t *, zone, dns_name_free(zone));
  smartlist_clear(zones);

  SMARTLIST_FOREACH_BEGIN(parts, char *, part) {
    if (*server == NULL) {
      *server = tor_strdup(part);
    } else {
      dns_name_t *normalized_zone = dns_name_of(part);
      dns_name_normalize(normalized_zone);
      smartlist_add(zones, normalized_zone);
      log_debug(LD_APP, "Add zone: %s", dns_name_str(normalized_zone));
    }
  } SMARTLIST_FOREACH_END(part);

  if (smartlist_len(zones) == 0) {
    smartlist_add(zones, dns_name_of("."));
  }

  // LCOV_EXCL_START
  if (PREDICT_UNLIKELY(log_global_min_severity_ == LOG_DEBUG)) {
    smartlist_t *zone_names = smartlist_new();

    SMARTLIST_FOREACH_BEGIN(zones, const dns_name_t *, zone) {
      smartlist_add(zone_names, (char *) dns_name_str(zone));
    } SMARTLIST_FOREACH_END(zone);

    char *zone_string = smartlist_join_strings(zone_names, ", ", 0, NULL);
    log_notice(LD_APP, "Got server: %s with zones: %s", *server, zone_string);
    smartlist_free(zone_names);
    tor_free(zone_string);
  }
  // LCOV_EXCL_STOP

 cleanup:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  return ret;
}

/** Extract <b>hostname</b> and <b>port</b> from <b>string</b>.
 * Expected format: [hostname]:[port].
 * Return 0 on success, < 0 otherwise. */
int
dns_resolver_extract_hostname_and_port(char **hostname, int *port,
                                       const char *string)
{
  // LCOV_EXCL_START
  tor_assert(string);
  // LCOV_EXCL_STOP

  if (tor_strisspace(string)) {
    return -1;
  }

  char *opening_square_bracket = strchr(string, '[');
  char *closing_square_bracket = strchr(string, ']');

  char *last_colon = strrchr(string, ':');

  // handle ipv6 addresses
  if (opening_square_bracket || closing_square_bracket) {
    if (!opening_square_bracket || !closing_square_bracket) {
      log_debug(LD_APP, "Invalid IPv6 address: %s", string);
      return -2;
    }

    tor_free(*hostname);
    *port = 0;

    *hostname = tor_strndup(string, (closing_square_bracket + 1) - string);
    if (last_colon && last_colon > closing_square_bracket) {
      *port = (int) strtol(last_colon + 1, NULL, 10);
    }
  } else {
    tor_free(*hostname);
    *port = 0;

    if (last_colon) {
      *hostname = tor_strndup(string, last_colon - string);
      *port = (int) strtol(last_colon + 1, NULL, 10);
    } else {
      *hostname = tor_strdup(string);
    }
  }

  if (*port == 0) {
    *port = 53;
  }

  log_debug(LD_APP, "Got hostname: %s, port: %d", *hostname, *port);

  return 0;
}

/** Setup lookup parameters to forward a DNS query received from DNS port. */
int
dns_resolver_lookup_setup_forward_query(dns_lookup_t *lookup,
                                        struct evdns_server_request *req)
{
  // LCOV_EXCL_START
  tor_assert(lookup);
  tor_assert(req);
  // LCOV_EXCL_STOP

  if (req->nquestions != 1) {
    log_debug(LD_APP, "Invalid number of questions.");
    return -1;
  }

  if (!req->questions) {
    log_debug(LD_APP, "Question is missing.");
    return -2;
  }

  lookup->action = DNS_LOOKUP_ACTION_FORWARD;
  dns_name_free(lookup->qname);
  lookup->qname = dns_name_of(req->questions[0]->name);
  lookup->qtype = req->questions[0]->type;
  lookup->server_request = req;

  return 0;
}

/** Setup lookup parameters to resolve a socks address from given
 * <b>ap_conn</b>. */
int
dns_resolver_lookup_setup_resolution_query(dns_lookup_t *lookup,
                                           entry_connection_t *ap_conn)
{
  const or_options_t *options = get_options();

  // LCOV_EXCL_START
  tor_assert(lookup);
  tor_assert(ap_conn);
  tor_assert(ap_conn->socks_request);
  // LCOV_EXCL_STOP

  lookup->action = DNS_LOOKUP_ACTION_RESOLVE;
  dns_name_free(lookup->qname);
  lookup->qname = dns_name_of(ap_conn->socks_request->address);

  if (options->DNSResolverHiddenServiceZones &&
      dns_resolver_zone_in_hidden_service_zone(lookup->qname,
        options->DNSResolverHiddenServiceZones)) {
    lookup->qtype = DNS_TYPE_KEY;
  } else if (options->DNSResolverIPv4 && options->DNSResolverIPv6) {
    dns_message_t *cached = dns_resolver_cache_get_message(lookup->qname,
                                                           DNS_TYPE_AAAA);

    if (cached && dns_resolver_resolution_should_fallback_to_ipv4(cached)) {
      lookup->qtype = DNS_TYPE_A;
    } else {
      lookup->qtype = DNS_TYPE_AAAA;
    }

    dns_message_free(cached);
  } else if (options->DNSResolverIPv6) {
    lookup->qtype = DNS_TYPE_AAAA;
  } else if (options->DNSResolverIPv4) {
    lookup->qtype = DNS_TYPE_A;
  } else {
    log_notice(LD_APP, "Unable to determine qtype in resolution mode.");
    return -1;
  }

  log_debug(LD_APP, "Resolve: %s/%d", dns_name_str(lookup->qname),
            lookup->qtype);

  lookup->ap_conn = ap_conn;
  return 0;
}

/** Set lookup parameters to perform a query with given values. */
void
dns_resolver_lookup_set_query(dns_lookup_t *lookup, const uint8_t action,
                              const dns_name_t *qname, const uint16_t qtype)
{
  // LCOV_EXCL_START
  tor_assert(lookup);
  tor_assert(qname);
  // LCOV_EXCL_STOP

  lookup->action = action;
  if (dns_name_compare(lookup->qname, qname) != 0) {
    dns_name_free(lookup->qname);
    lookup->qname = dns_name_dup(qname);
  }
  lookup->qtype = qtype;

  log_debug(LD_APP, "Query: %s/%d", dns_name_str(lookup->qname),
            lookup->qtype);
}

/** Check if <b>qname</b> is within hidden service zones. Return 1 if
 * <b>qname</b> is within <b>hidden_service_zones</b>, 0 otherwise. */
int
dns_resolver_zone_in_hidden_service_zone(const dns_name_t *qname,
                                       const smartlist_t *hidden_service_zones)
{
  if (!qname || !hidden_service_zones) {
    return 0;
  }

  SMARTLIST_FOREACH_BEGIN(hidden_service_zones, const char *, zone) {
    dns_name_t *zone_name = dns_name_of(zone);
    if (dns_name_is_part_of(zone_name, qname) >= 0) {
      dns_name_free(zone_name);
      return 1;
    }
    dns_name_free(zone_name);
  } SMARTLIST_FOREACH_END(zone);

  return 0;
}

/** Determine if we should fallback to IPv4, based on the response in
 * <b>resp</b> and the configuration options: DNSResolverIPv4 and
 * DNSResolverIPv6.
 * Return True when fallback is desirable, False otherwise. */
bool
dns_resolver_resolution_should_fallback_to_ipv4(dns_message_t *resp)
{
  const or_options_t *options = get_options();

  // LCOV_EXCL_START
  tor_assert(resp);
  // LCOV_EXCL_STOP

  dns_question_t *question = dns_message_get_question(resp);
  if (options->DNSResolverIPv4 && question &&
      dns_type_is(question->qtype, DNS_TYPE_AAAA)) {

    SMARTLIST_FOREACH_BEGIN(resp->answer_list, dns_rr_t *, rr) {
      if (dns_type_is(rr->rrtype, DNS_TYPE_AAAA)) {
        return false;
      }
    } SMARTLIST_FOREACH_END(rr);

    log_debug(LD_APP, "Couldn't find IPv6 answer, fallback to IPv4.");
    return true;
  }

  return false;
}

/** Create a list with all zones for given name starting from root zone
 * descending. E.g.: the name <b>www.example.com</b> results in:
 * www.example.com., example.com., com., . */
smartlist_t *
dns_resolver_get_zones_for_name(const dns_name_t *name,
                                const smartlist_t *trust_anchors)
{
  // LCOV_EXCL_START
  tor_assert(name);
  tor_assert(trust_anchors);
  // LCOV_EXCL_STOP

  dns_rr_t *trust_anchor = NULL;
  int max_labels = 0;

  log_debug(LD_APP, "Get zones for name: %s", dns_name_str(name));

  SMARTLIST_FOREACH_BEGIN(trust_anchors, dns_rr_t *, rr) {
    int labels = dns_name_is_part_of(rr->name, name);

    if (trust_anchor == NULL) {
      trust_anchor = rr;
      max_labels = labels;
    } else if (max_labels < labels) {
      trust_anchor = rr;
      max_labels = labels;
    }
  } SMARTLIST_FOREACH_END(rr);

  if (trust_anchor) {
    log_debug(LD_APP, "Found trust anchor <%s> for name: %s",
              dns_name_str(trust_anchor->name), dns_name_str(name));
  } else {
    log_debug(LD_APP, "Unable to find trust anchor for: %s",
              dns_name_str(name));
  }

  smartlist_t *rejected = smartlist_new();
  smartlist_t *accepted = smartlist_new();

  for (int i = name->length; i >= 0; i--) {
    dns_name_t *next = NULL;

    if (i == name->length) {
      next = dns_name_of(".");
    } else if (i ==0 || name->value[i - 1] == '.') {
      next = dns_name_new();
      next->length = name->length - i;
      next->value = tor_memdup(&name->value[i], next->length + 1);
    }

    if (next) {
      if (trust_anchor && dns_name_is_part_of(trust_anchor->name, next) >= 0) {
        log_debug(LD_APP, "Accepting zone: %s", dns_name_str(next));
        smartlist_add(accepted, next);
      } else {
        log_debug(LD_APP, "Rejecting zone: %s", dns_name_str(next));
        smartlist_add(rejected, next);
      }
    }
  }

  SMARTLIST_FOREACH(rejected, dns_name_t *, zone, dns_name_free(zone));
  smartlist_free(rejected);

  smartlist_reverse(accepted);

  return accepted;
}

/** Add new query to connection's inbuf and start to process the data in case
 * <b>is_processing</b> is set. */
int
dns_resolver_add_query_impl(entry_connection_t *dns_conn, int is_processing)
{
  // LCOV_EXCL_START
  tor_assert(dns_conn);
  tor_assert(dns_conn->dns_lookup);
  tor_assert(dns_conn->dns_lookup->qname);
  // LCOV_EXCL_STOP

  connection_t *conn = ENTRY_TO_CONN(dns_conn);

  int ret = 0;
  dns_message_t *request =
    dns_resolver_build_dns_message(dns_conn->dns_lookup);

  if (dns_encode_message_tcp(conn->inbuf, request) < 0) {
    log_debug(LD_NET, "Failed encoding DNS message.");
    ret = -1;
    goto cleanup;
  }

  if (is_processing) {
    ret = connection_edge_process_inbuf(ENTRY_TO_EDGE_CONN(dns_conn), 1);
  }

 cleanup:
  dns_message_free(request);
  tor_gettimeofday(&dns_conn->dns_lookup->start_time);
  return ret;
}

/** Build and return a new DNS message with the <b>qname</b> and <b>qtype</b>
 * defined in <b>lookup</b>. */
dns_message_t *
dns_resolver_build_dns_message(const dns_lookup_t *lookup)
{
  const or_options_t *options = get_options();

  // LCOV_EXCL_START
  tor_assert(lookup);
  tor_assert(lookup->qname);
  // LCOV_EXCL_STOP

  dns_message_t *message = dns_message_new();

  // add question
  dns_question_t *question = dns_question_new();
  question->qname = dns_name_dup(lookup->qname);
  question->qtype = dns_type_of(lookup->qtype);
  question->qclass = DNS_CLASS_IN;
  smartlist_add(message->question_list, question);

  // add EDNS DO flag
  if (lookup->action != DNS_LOOKUP_ACTION_FORWARD &&
      (options->DNSResolverDNSSECMode == DNSSEC_MODE_PROCESS ||
       options->DNSResolverDNSSECMode == DNSSEC_MODE_VALIDATE)) {

    log_debug(LD_APP, "Adding EDNS DO flag.");

    dns_rr_t *edns0 = dns_rr_new();
    edns0->rrtype = dns_type_of(DNS_TYPE_OPT);
    edns0->rrclass = 0;
    edns0->ttl = 0x8000;
    smartlist_add(message->additional_record_list, edns0);
  }

  // setup header
  message->header->opcode = DNS_OPCODE_QUERY;

  // set RD (Recursion Desired) flag
  message->header->rd = true;

  // set CD (Checking Disabled) flag
  if (lookup->action != DNS_LOOKUP_ACTION_FORWARD &&
      options->DNSResolverDNSSECMode == DNSSEC_MODE_TRUST) {
    message->header->cd = false;
  } else {
    message->header->cd = true;
  }

  message->header->qdcount = smartlist_len(message->question_list);
  message->header->arcount = smartlist_len(message->additional_record_list);

  if (options->DNSResolverRandomizeCase) {
    str_shuffle_case(question->qname->value);
  }

  return message;
}

/** Incorporate the DNS query time into the nameserver's average latency and
 * apply the given <b>penalty</b>.*/
void
dns_resolver_update_nameserver_latency(dns_lookup_t *lookup, int penalty)
{
  // LCOV_EXCL_START
  tor_assert(lookup);
  // LCOV_EXCL_STOP

  struct timeval end_time;
  struct timeval elapsed_time;

  tor_gettimeofday(&end_time);
  timersub(&end_time, &lookup->start_time, &elapsed_time);

  uint16_t elapsed_time_in_ms = (elapsed_time.tv_sec * MSEC_PER_SEC) +
                                (elapsed_time.tv_usec / USEC_PER_MSEC);
  log_debug(LD_APP, "Query %s/%d took: %d msec", dns_name_str(lookup->qname),
            lookup->qtype, elapsed_time_in_ms);

  if (lookup->nameserver) {
    if (lookup->nameserver->latency == 0) {
      lookup->nameserver->latency = 1;
    } else if (lookup->nameserver->latency == 1) {
      lookup->nameserver->latency = MIN(NAMESERVER_MAX_LATENCY_IN_MSEC,
                                        MAX(elapsed_time_in_ms, 1));
    } else {
      lookup->nameserver->latency = MIN(NAMESERVER_MAX_LATENCY_IN_MSEC,
                                        CEIL_DIV(lookup->nameserver->latency +
                                                 elapsed_time_in_ms, 2));
    }

    while (penalty-- > 0) {
      lookup->nameserver->latency = MIN(NAMESERVER_MAX_LATENCY_IN_MSEC,
                                        lookup->nameserver->latency * 2);
    }

    lookup->nameserver->sleep = 0;
    lookup->nameserver->backoff = 0;
  }
}

/** Sort a list of nameservers by latency in ascending order. */
STATIC int
dns_resolver_nameserver_sort_by_latency_asc(const void **a_, const void **b_)
{
  const nameserver_t *a = *a_,
                     *b = *b_;
  return a->latency - b->latency;
}

/** Add <b>message</b> to cache if applicable. Return 0 on success, < 0
 * otherwise. */
int
dns_resolver_cache_add_message(const dns_message_t *message)
{
  const or_options_t *options = get_options();

  // LCOV_EXCL_START
  tor_assert(message);
  // LCOV_EXCL_STOP

  if (!dns_resolver_cache_is_enabled(options)) {
    log_debug(LD_APP, "Skipping... cache is disabled.");
    return -1;
  }

  if (PREDICT_UNLIKELY(!dns_message_cache)) {
    dns_message_cache = strmap_new();
  }

  dns_question_t *question = dns_message_get_question(message);
  if (!question || !question->qname || !question->qtype) {
    log_debug(LD_APP, "Skipping... message without question.");
    return -2;
  }

  char *cache_key = dns_resolver_cache_get_key(question->qname,
                                               question->qtype->value);

  if (strmap_get(dns_message_cache, cache_key) == NULL) {
    dns_message_t *cache_entry = dns_message_dup(message);
    tor_gettimeofday(&cache_entry->cached_at);
    strmap_set(dns_message_cache, cache_key, cache_entry);
  }

  log_debug(LD_APP, "Cache entries: %d, max: %d",
            strmap_size(dns_message_cache),
            options->DNSResolverMaxCacheEntries);

  // if cache limit is reached remove soon to expire messages
  while (strmap_size(dns_message_cache) >
         options->DNSResolverMaxCacheEntries) {
    log_debug(LD_APP, "Remove message from cache.");
    uint32_t minimum_ttl = UINT32_MAX;
    char *to_be_removed_key = NULL;
    dns_message_t *to_be_removed_value = NULL;

    STRMAP_FOREACH(dns_message_cache, key, dns_message_t *, value) {

      uint32_t ttl = dns_resolver_cache_update_message_ttl(value);
      if (to_be_removed_key == NULL || ttl < minimum_ttl) {
        ttl = minimum_ttl;
        to_be_removed_key = (char *) key;
        to_be_removed_value = value;
      }

    } STRMAP_FOREACH_END;

    strmap_remove(dns_message_cache, to_be_removed_key);
    dns_message_free(to_be_removed_value);
  }

  tor_free(cache_key);

  return 0;
}

/** Return cached message for <b>qname</b> and <b>qtype</b> if availbale and
 * not expired, NULL otherwise. */
dns_message_t *
dns_resolver_cache_get_message(const dns_name_t *qname, const uint16_t qtype)
{
  // LCOV_EXCL_START
  tor_assert(qname);
  // LCOV_EXCL_STOP

  if (!dns_message_cache) {
    return NULL;
  }

  char *cache_key = dns_resolver_cache_get_key(qname, qtype);
  dns_message_t *message = strmap_get(dns_message_cache, cache_key);

  if (!message) {
    log_debug(LD_APP, "Unable to find cached message for: %s", cache_key);
    goto cleanup;
  }

  if (dns_resolver_cache_update_message_ttl(message) == 0) {
    log_debug(LD_APP, "Cache message expired");
    strmap_remove(dns_message_cache, cache_key);
    dns_message_free(message);
  }

 cleanup:
  tor_free(cache_key);
  if (!message) {
    return NULL;
  }
  return dns_message_dup(message);
}

/** Free all cached messages. Return the number of freed messages. */
int
dns_resolver_cache_free_all(void)
{
  if (!dns_message_cache) {
    return 0;
  }

  int freed = 0;
  STRMAP_FOREACH_MODIFY(dns_message_cache, key, dns_message_t *, value) {

    dns_message_free(value);
    MAP_DEL_CURRENT(key);
    freed++;

  } STRMAP_FOREACH_END;
  return freed;
}

/** Return True if DNS resolver cache is enabled, False otherwise. */
bool
dns_resolver_cache_is_enabled(const or_options_t *options)
{
  return options->DNSResolverMaxCacheTTL > 0 &&
         options->DNSResolverMaxCacheEntries > 0;
}

/** Return cache key for <b>qname</b> and <b>qtype</b>. */
char *
dns_resolver_cache_get_key(const dns_name_t *qname, const uint16_t qtype)
{
  // LCOV_EXCL_START
  tor_assert(qname);
  // LCOV_EXCL_STOP

  dns_name_t *normalized_qname = dns_name_dup(qname);
  dns_name_normalize(normalized_qname);

  char *key = NULL;
  tor_asprintf(&key, "%s%d", dns_name_str(normalized_qname), qtype);
  dns_name_free(normalized_qname);

  log_debug(LD_APP, "Cache key is %s", key);
  return key;
}

/** Update TTL for all resource records in <b>message</b> and return the
 * minimum TTL. */
uint32_t
dns_resolver_cache_update_message_ttl(dns_message_t *message)
{
  const or_options_t *options = get_options();

  // LCOV_EXCL_START
  tor_assert(message);
  // LCOV_EXCL_STOP

  uint32_t minimum_ttl = UINT32_MAX;

  struct timeval now;
  tor_gettimeofday(&now);

  struct timeval elapsed_time;
  timersub(&now, &message->cached_at, &elapsed_time);
  uint32_t elapsed_sec = (uint32_t) elapsed_time.tv_sec;

  if ((uint32_t) options->DNSResolverMaxCacheTTL < elapsed_sec) {
    return 0;
  }

  SMARTLIST_FOREACH_BEGIN(message->answer_list, dns_rr_t *, rr) {
    if (rr->ttl < elapsed_sec) {
      return 0;
    }
    rr->ttl -= elapsed_sec;
    minimum_ttl = MIN(rr->ttl, minimum_ttl);
  } SMARTLIST_FOREACH_END(rr);

  SMARTLIST_FOREACH_BEGIN(message->name_server_list, dns_rr_t *, rr) {
    if (rr->ttl < elapsed_sec) {
      return 0;
    }
    rr->ttl -= elapsed_sec;
    minimum_ttl = MIN(rr->ttl, minimum_ttl);
  } SMARTLIST_FOREACH_END(rr);

  return minimum_ttl;
}

