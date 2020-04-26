/* Copyright (c) 2019 Christian Hofer.
 * Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file dns_resolver.h
 * \brief Header file for dns_resolver.c.
 **/

#ifndef TOR_DNS_RESOLVER_H
#define TOR_DNS_RESOLVER_H

#include "core/or/dns_lookup_st.h"
#include "core/or/or.h"
#include "lib/cc/torint.h"
#include "lib/container/dns_message_st.h"
#include "lib/testsupport/testsupport.h"

void dns_resolver_init(void);
void dns_resolver_free_all(void);

struct dns_lookup_t *dns_lookup_new(void);
void dns_lookup_free_(struct dns_lookup_t *dl);
#define dns_lookup_free(dl) \
  FREE_AND_NULL(dns_lookup_t, dns_lookup_free_, (dl))

int dns_resolver_initiate_server_request_forward(
                                             struct evdns_server_request *req);
int dns_resolver_initiate_socks_address_resolution(
                                                  entry_connection_t *ap_conn);
void dns_resolver_ping_nameserver(void);
int dns_resolver_process_reply(entry_connection_t *dns_conn);

int dns_resolver_config_revise_dnssec_mode(const char *mode);
smartlist_t *dns_resolver_config_revise_nameservers(
                                              const smartlist_t *nameservers,
                                              const or_options_t *old_options);
void dns_resolver_config_free_nameservers(smartlist_t *nameservers);
strmap_t *dns_resolver_config_revise_nameserver_zone_map(
                                               const smartlist_t *nameservers);
void dns_resolver_config_free_nameserver_zone_map(strmap_t *zone_map);
smartlist_t *dns_resolver_config_revise_trust_anchors(
                                             const smartlist_t *trust_anchors);
void dns_resolver_config_free_trust_anchors(smartlist_t *trust_anchors);

#ifdef DNS_RESOLVER_PRIVATE

#define NAMESERVER_MAX_LATENCY_IN_MSEC  10000

#define VALIDATION_ACTION_APEX_KEYS   1  // Retrieve the apex DNSKEY RRset.
#define VALIDATION_ACTION_DELEGATION  2  // Retrieve the Delegation Signer
                                         // (DS) records.
#define VALIDATION_ACTION_ZONE_CUT    3  // Find the next zone cut.

#define DNS_MESSAGE_SECTION_ANSWER     1  // DNS message answer section.
#define DNS_MESSAGE_SECTION_AUTHORITY  2  // DNS message authority section.

entry_connection_t *dns_resolver_dns_connection_new(void);

nameserver_t *nameserver_new(void);
void nameserver_free_(nameserver_t *nsrv);
#define nameserver_free(nsrv) \
  FREE_AND_NULL(nameserver_t, nameserver_free_, (nsrv))

validation_t *validation_new(void);
void validation_free_(validation_t *val);
#define validation_free(val) \
  FREE_AND_NULL(validation_t, validation_free_, (val))

int dns_resolver_handle_resolution_reply(entry_connection_t *dns_conn,
                                         dns_message_t *resp);
int dns_resolver_handle_validation_reply(entry_connection_t *dns_conn,
                                         dns_message_t *resp);

int dns_resolver_validation_initiate(entry_connection_t *dns_conn,
                                     dns_message_t *resp);
int dns_resolver_validation_initiate_next_chain(entry_connection_t *dns_conn);
int dns_resolver_validation_conclude_chain(entry_connection_t *dns_conn);
int dns_resolver_validation_choose_next_zone_to_validate(
      validation_t *validation);

int dns_resolver_validation_apex_dnskeys_request(entry_connection_t *dns_conn);
int dns_resolver_validation_apex_dnskeys_response(
      entry_connection_t *dns_conn, dns_message_t *resp);

int dns_resolver_validation_delegation_request(entry_connection_t *dns_conn);
int dns_resolver_validation_delegation_response(entry_connection_t *dns_conn,
                                                dns_message_t *resp);

int dns_resolver_validation_zone_cut_request(entry_connection_t *dns_conn);
int dns_resolver_validation_zone_cut_response(entry_connection_t *dns_conn,
                                              dns_message_t *resp);

void dns_resolver_validation_update_state(const validation_t *validation,
                                          const uint8_t state);

int dns_resolver_complete_server_request_forward(entry_connection_t *dns_conn,
                                                 dns_message_t *resp);
int dns_resolver_resolve_server_request(struct evdns_server_request *req,
                                        dns_message_t *resp);
MOCK_DECL(void, dns_resolver_evdns_wrapper_add_reply,
          (struct evdns_server_request *req, int section, dns_rr_t *rr));
MOCK_DECL(void, dns_resolver_evdns_wrapper_respond,
          (struct evdns_server_request *req, dns_message_t *resp));

int dns_resolver_complete_socks_address_resolution_impl(
            entry_connection_t *dns_conn, dns_message_t *resp, int is_closing);
#define dns_resolver_complete_socks_address_resolution(dns_conn, resp) \
  dns_resolver_complete_socks_address_resolution_impl((dns_conn), (resp), 0)
#define dns_resolver_complete_socks_address_resolution_closing(dns_conn, \
                                                               resp)     \
  dns_resolver_complete_socks_address_resolution_impl((dns_conn), (resp), 1)
int dns_resolver_resolve_socks_address(entry_connection_t *ap_conn,
                                       dns_message_t *resp);
smartlist_t *dns_resolver_resolve_socks_address_get_answers(
                                                          dns_message_t *resp);

nameserver_t *dns_resolver_choose_nameserver_to_ping(void);
bool dns_resolver_backoff_nameserver(nameserver_t *nameserver);
nameserver_t *dns_resolver_choose_nameserver_for_lookup(dns_lookup_t *lookup);
void dns_resolver_assign_nameserver(entry_connection_t *dns_conn,
                                    nameserver_t *nameserver);

smartlist_t *dns_resolver_nameserver_create_list(
               const smartlist_t *nameserver_lines,
               const smartlist_t *old_nameservers);
nameserver_t *dns_resolver_nameserver_find(
                const smartlist_t *nameservers,
                const smartlist_t *zones, const char *hostname,
                const int port);
nameserver_t *dns_resolver_nameserver_find_best_by_latency(
                const smartlist_t *nameservers);
void dns_resolver_nameserver_free_outdated(const smartlist_t *old,
                                           const smartlist_t *new);

int dns_resolver_extract_server_and_zones(char **server, smartlist_t *zones,
                                          const char *string);
int dns_resolver_extract_hostname_and_port(char **hostname, int *port,
                                           const char *string);

int dns_resolver_lookup_setup_forward_query(dns_lookup_t *lookup,
                                            struct evdns_server_request *req);
int dns_resolver_lookup_setup_resolution_query(dns_lookup_t *lookup,
                                               entry_connection_t *ap_conn);
void dns_resolver_lookup_set_query(dns_lookup_t *lookup, const uint8_t action,
                                   const dns_name_t *qname,
                                   const uint16_t qtype);

int dns_resolver_zone_in_hidden_service_zone(const dns_name_t *qname,
                                      const smartlist_t *hidden_service_zones);
bool dns_resolver_resolution_should_fallback_to_ipv4(dns_message_t *resp);
smartlist_t *dns_resolver_get_zones_for_name(const dns_name_t *name,
                                             const smartlist_t *trust_anchors);

int dns_resolver_add_query_impl(entry_connection_t *dns_conn,
                                int is_processing);
#define dns_resolver_add_query(dns_conn) \
  dns_resolver_add_query_impl((dns_conn), 0)
#define dns_resolver_add_query_processing(dns_conn) \
  dns_resolver_add_query_impl((dns_conn), 1)

dns_message_t *dns_resolver_build_dns_message(const dns_lookup_t *lookup);

void dns_resolver_update_nameserver_latency(dns_lookup_t *lookup, int penalty);
STATIC int dns_resolver_nameserver_sort_by_latency_asc(const void **a_,
                                                       const void **b_);

int dns_resolver_cache_add_message(const dns_message_t *message);
dns_message_t *dns_resolver_cache_get_message(const dns_name_t *qname,
                                              const uint16_t qtype);
int dns_resolver_cache_free_all(void);
bool dns_resolver_cache_is_enabled(const or_options_t *options);
char *dns_resolver_cache_get_key(const dns_name_t *qname,
                                 const uint16_t qtype);
uint32_t dns_resolver_cache_update_message_ttl(dns_message_t *message);

#endif /* !defined(DNS_RESOLVER_PRIVATE) */

#endif /* !defined(TOR_DNS_RESOLVER_H) */
