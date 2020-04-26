/* Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/*
 * \file test_dns_resolver.c
 * \brief Tests for our DNS resolver.
 */

#define CONNECTION_PRIVATE
#define DNS_RESOLVER_PRIVATE

#include "test/test.h"
#include "test/hs_test_helpers.h"
#include "test/log_test_helpers.h"
#include "test/rend_test_helpers.h"

#include "app/config/config.h"
#include "core/mainloop/connection.h"
#include "core/or/connection_edge.h"
#include "core/or/dns_lookup_st.h"
#include "core/or/dns_resolver.h"
#include "core/or/entry_connection_st.h"
#include "core/or/or_connection_st.h"
#include "core/or/socks_request_st.h"
#include "lib/defs/dns_types.h"
#include "feature/hs/hs_cache.h"
#include "feature/nodelist/networkstatus.h"
#include "feature/nodelist/networkstatus_st.h"
#include "feature/rend/rendcache.h"
#include "feature/rend/rend_encoded_v2_service_descriptor_st.h"
#include "lib/container/dns_message.h"
#include "lib/container/dns_message_st.h"
#include "lib/crypt_ops/crypto_dnssec.h"
#include "lib/encoding/dns_string.h"
#include "lib/encoding/dns_wireformat.h"

#include <event2/dns.h>
#include <event2/dns_struct.h>

/** Mock replacement for get_options that returns <b>mock_options</b>. */
static or_options_t *mock_options = NULL;
static const or_options_t *
mock_get_options(void)
{
  return mock_options;
}

/** Mock replacement for connection_ap_rewrite_and_attach_if_allowed that
 * returns ok. */
static int
mock_connection_ap_rewrite_and_attach_if_allowed_ok(entry_connection_t *conn,
                                                    origin_circuit_t *circ,
                                                    crypt_path_t *cpath)
{
  (void) circ;
  (void) cpath;
  if (conn->dns_lookup) {
    connection_free_minimal(ENTRY_TO_CONN(conn));
  }
  return 0;
}

/** Mock replacement for mock_connection_mark_unattached_ap_. */
static void
mock_connection_mark_unattached_ap_ok(entry_connection_t *conn, int endreason,
                                      int line, const char *file)
{
  (void) conn;
  (void) endreason;
  (void) line;
  (void) file;
}

/** Mock replacement for connection_free_. */
static void
mock_connection_free_(connection_t *conn)
{
  connection_free_minimal(conn);
}

static networkstatus_t mock_ns;

/** Mock replacement for networkstatus_get_live_consensus. Required for hs
 * cache test. */
static networkstatus_t *
mock_networkstatus_get_live_consensus(time_t now)
{
  (void) now;
  return &mock_ns;
}

static uint8_t mock_evdns_answer_replies = 0;
static uint8_t mock_evdns_authority_replies = 0;

/** Mock replacement for dns_resolver_evdns_wrapper_add_reply. */
static void
mock_dns_resolver_evdns_wrapper_add_reply(struct evdns_server_request *req,
                                          int section, dns_rr_t *rr)
{
  (void) req;
  (void) rr;

  if (section == EVDNS_ANSWER_SECTION) {
    mock_evdns_answer_replies++;
  }
  if (section == EVDNS_AUTHORITY_SECTION) {
    mock_evdns_authority_replies++;
  }
}

static uint8_t mock_evdns_responds = 0;

/** Mock replacement for dns_resolver_evdns_wrapper_respond. */
static void
mock_dns_resolver_evdns_wrapper_respond(struct evdns_server_request *req,
                                        dns_message_t *resp)
{
  (void) req;
  (void) resp;
  mock_evdns_responds++;
}

#ifdef ENABLE_OPENSSL

/** Mock replacement for dnssec_authenticate_rrset that returns
 * authenticated. */
static int
mock_dnssec_authenticate_rrset_ok(const smartlist_t *unauthenticated_rrset,
                                 const smartlist_t *authenticated_dnskey_rrset)
{
  (void) unauthenticated_rrset;
  (void) authenticated_dnskey_rrset;
  return 0;
}

/** Mock replacement for dnssec_authenticate_rrset that returns
 * unauthenticated. */
static int
mock_dnssec_authenticate_rrset_fail(const smartlist_t *unauthenticated_rrset,
                                 const smartlist_t *authenticated_dnskey_rrset)
{
  (void) unauthenticated_rrset;
  (void) authenticated_dnskey_rrset;
  return -1;
}

/** Mock replacement for dnssec_authenticate_delegation_to_child_zone that
 * returns authenticated. */
static int
mock_dnssec_authenticate_delegation_to_child_zone_ok(
  smartlist_t *authenticated_dnskey_rrset,
  const smartlist_t *unauthenticated_rrset, const smartlist_t *ds_rrset)
{
  (void) authenticated_dnskey_rrset;
  (void) unauthenticated_rrset;
  (void) ds_rrset;
  return 0;
}

/** Mock replacement for dnssec_authenticate_delegation_to_child_zone that
 * returns unauthenticated. */
static int
mock_dnssec_authenticate_delegation_to_child_zone_fail(
  smartlist_t *authenticated_dnskey_rrset,
  const smartlist_t *unauthenticated_rrset, const smartlist_t *ds_rrset)
{
  (void) authenticated_dnskey_rrset;
  (void) unauthenticated_rrset;
  (void) ds_rrset;
  return -1;
}

/** Mock replacement for dnssec_denial_of_existence that returns NXDOMAIN. */
static denial_of_existence_t
mock_dnssec_denial_of_existence_nxdomain(const dns_name_t *qname,
                                         const uint16_t qtype,
                                         const smartlist_t *rrset)
{
  (void) qname;
  (void) qtype;
  (void) rrset;
  return DNSSEC_DENIAL_OF_EXISTENCE_NXDOMAIN;
}

/** Mock replacement for dnssec_denial_of_existence that returns OPTOUT. */
static denial_of_existence_t
mock_dnssec_denial_of_existence_optout(const dns_name_t *qname,
                                       const uint16_t qtype,
                                       const smartlist_t *rrset)
{
  (void) qname;
  (void) qtype;
  (void) rrset;
  return DNSSEC_DENIAL_OF_EXISTENCE_OPTOUT;
}

#endif /* defined(ENABLE_OPENSSL) */

static time_t mocked_timeofday;

/** Mock replacement for tor_gettimeofday. */
static void
mock_tor_gettimeofday(struct timeval *timeval)
{
  timeval->tv_sec = mocked_timeofday;
  timeval->tv_usec = 0;
}

#ifdef ENABLE_OPENSSL

static entry_connection_t *
setup_dns_connection(const char *active_child)
{
  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();
  ENTRY_TO_CONN(dns_conn)->state = AP_CONN_STATE_CIRCUIT_WAIT;
  dns_conn->dns_lookup->validation = validation_new();
  if (active_child) {
    dns_conn->dns_lookup->validation->active_child = dns_name_of(active_child);
  }
  return dns_conn;
}

#endif /* defined(ENABLE_OPENSSL) */

static void
test_dns_resolver_initiate_server_request_forward_succeeds(void *arg)
{
  (void) arg;

  const char *qname = "example.com";

  struct evdns_server_question *question =
    tor_malloc_zero(sizeof(struct evdns_server_question) + strlen(qname));
  memcpy(question->name, qname, strlen(qname) + 1);
  question->type = DNS_TYPE_A;

  struct evdns_server_request *req = tor_malloc_zero(
                                       sizeof(struct evdns_server_request));
  req->nquestions = 1;
  req->questions = &question;

  nameserver_t *nameserver = nameserver_new();
  nameserver->hostname = tor_strdup("127.0.0.1");
  nameserver->port = 53;
  nameserver->latency = 1;

  smartlist_t *nameservers = smartlist_new();
  smartlist_add(nameservers, nameserver);

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverNameserverZoneMap = strmap_new();
  strmap_set(mock_options->DNSResolverNameserverZoneMap, ".", nameservers);

  MOCK(get_options, mock_get_options);
  MOCK(connection_ap_rewrite_and_attach_if_allowed,
       mock_connection_ap_rewrite_and_attach_if_allowed_ok);
  tt_int_op(dns_resolver_initiate_server_request_forward(req), OP_EQ, 0);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_ap_rewrite_and_attach_if_allowed);

  tor_free(question);
  tor_free(req);
  nameserver_free(nameserver);
  strmap_free(mock_options->DNSResolverNameserverZoneMap,
              (void (*)(void *)) smartlist_free_);
  tor_free(mock_options);
}

static void
test_dns_resolver_initiate_server_request_forward_invalid_qname(void *arg)
{
  (void) arg;

  const char *qname = "abcd012345678901234567890123456789012345678901234567890"
                      "123456789.example.com.";

  struct evdns_server_question *question =
    tor_malloc_zero(sizeof(struct evdns_server_question) + strlen(qname));
  memcpy(question->name, qname, strlen(qname) + 1);
  question->type = DNS_TYPE_A;

  struct evdns_server_request *req = tor_malloc_zero(
                                       sizeof(struct evdns_server_request));
  req->nquestions = 1;
  req->questions = &question;

  nameserver_t *nameserver = nameserver_new();
  nameserver->hostname = tor_strdup("127.0.0.1");
  nameserver->port = 53;
  nameserver->latency = 1;

  smartlist_t *nameservers = smartlist_new();
  smartlist_add(nameservers, nameserver);

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverNameserverZoneMap = strmap_new();
  strmap_set(mock_options->DNSResolverNameserverZoneMap, ".", nameservers);

  MOCK(get_options, mock_get_options);
  MOCK(connection_free_, mock_connection_free_);
  tt_int_op(dns_resolver_initiate_server_request_forward(req), OP_EQ, -3);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_free_);

  tor_free(question);
  tor_free(req);
  nameserver_free(nameserver);
  strmap_free(mock_options->DNSResolverNameserverZoneMap,
              (void (*)(void *)) smartlist_free_);
  tor_free(mock_options);
}

static void
test_dns_resolver_initiate_server_request_forward_missing_nameserver(void *arg)
{
  (void) arg;

  const char *qname = "example.com";

  struct evdns_server_question *question =
    tor_malloc_zero(sizeof(struct evdns_server_question) + strlen(qname));
  memcpy(question->name, qname, strlen(qname) + 1);
  question->type = DNS_TYPE_A;

  struct evdns_server_request *req = tor_malloc_zero(
                                       sizeof(struct evdns_server_request));
  req->nquestions = 1;
  req->questions = &question;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverNameserverZoneMap = strmap_new();

  MOCK(get_options, mock_get_options);
  MOCK(connection_free_, mock_connection_free_);
  tt_int_op(dns_resolver_initiate_server_request_forward(req), OP_EQ, -2);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_free_);

  tor_free(question);
  tor_free(req);
  strmap_free(mock_options->DNSResolverNameserverZoneMap, NULL);
  tor_free(mock_options);
}

static void
test_dns_resolver_initiate_server_request_forward_invalid_server_request(
                                                                     void *arg)
{
  (void) arg;

  struct evdns_server_request *req = tor_malloc_zero(
                                       sizeof(struct evdns_server_request));

  MOCK(connection_free_, mock_connection_free_);
  tt_int_op(dns_resolver_initiate_server_request_forward(req), OP_EQ, -1);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(connection_free_);

  tor_free(req);
}

static void
test_dns_resolver_initiate_server_request_forward_is_cached(void *arg)
{
  (void) arg;

  const char *qname = "example.com";

  struct evdns_server_question *question =
    tor_malloc_zero(sizeof(struct evdns_server_question) + strlen(qname));
  memcpy(question->name, qname, strlen(qname) + 1);
  question->type = DNS_TYPE_A;

  struct evdns_server_request *req = tor_malloc_zero(
                                       sizeof(struct evdns_server_request));
  req->nquestions = 1;
  req->questions = &question;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverNameserverZoneMap = strmap_new();
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;

  dns_question_t *dq = dns_question_new();
  dq->qname = dns_name_of(qname);
  dq->qtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *message = dns_message_new();
  smartlist_add(message->question_list, dq);
  message->header->qdcount = smartlist_len(message->question_list);

  mock_evdns_responds = 0;

  MOCK(get_options, mock_get_options);
  MOCK(connection_free_, mock_connection_free_);
  MOCK(dns_resolver_evdns_wrapper_respond,
       mock_dns_resolver_evdns_wrapper_respond);

  tt_int_op(dns_resolver_cache_add_message(message), OP_EQ, 0);
  tt_int_op(dns_resolver_initiate_server_request_forward(req), OP_EQ, 0);
  tt_int_op(mock_evdns_responds, OP_EQ, 1);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_free_);
  UNMOCK(dns_resolver_evdns_wrapper_respond);

  tor_free(question);
  tor_free(req);
  strmap_free(mock_options->DNSResolverNameserverZoneMap, NULL);
  tor_free(mock_options);
  dns_message_free(message);
}

static void
test_dns_resolver_initiate_socks_address_resolution_succeeds(void *arg)
{
  (void) arg;

  const char *qname = "example.com";

  entry_connection_t *ap_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  strlcpy(ap_conn->socks_request->address, qname,
          sizeof(ap_conn->socks_request->address));

  nameserver_t *nameserver = nameserver_new();
  nameserver->hostname = tor_strdup("127.0.0.1");
  nameserver->port = 53;
  nameserver->latency = 1;

  smartlist_t *nameservers = smartlist_new();
  smartlist_add(nameservers, nameserver);

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverIPv4 = 1;
  mock_options->DNSResolverNameserverZoneMap = strmap_new();
  strmap_set(mock_options->DNSResolverNameserverZoneMap, ".", nameservers);

  MOCK(get_options, mock_get_options);
  MOCK(connection_ap_rewrite_and_attach_if_allowed,
       mock_connection_ap_rewrite_and_attach_if_allowed_ok);
  tt_int_op(dns_resolver_initiate_socks_address_resolution(ap_conn), OP_EQ, 0);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_ap_rewrite_and_attach_if_allowed);

  connection_free_minimal(ENTRY_TO_CONN(ap_conn));
  nameserver_free(nameserver);
  strmap_free(mock_options->DNSResolverNameserverZoneMap,
              (void (*)(void *)) smartlist_free_);
  tor_free(mock_options);
}

static void
test_dns_resolver_initiate_socks_address_resolution_invalid_qname(void *arg)
{
  (void) arg;

  const char *qname = "abcd012345678901234567890123456789012345678901234567890"
                      "123456789.example.com.";

  entry_connection_t *ap_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  strlcpy(ap_conn->socks_request->address, qname,
          sizeof(ap_conn->socks_request->address));

  nameserver_t *nameserver = nameserver_new();
  nameserver->hostname = tor_strdup("127.0.0.1");
  nameserver->port = 53;
  nameserver->latency = 1;

  smartlist_t *nameservers = smartlist_new();
  smartlist_add(nameservers, nameserver);

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverIPv4 = 1;
  mock_options->DNSResolverNameserverZoneMap = strmap_new();
  strmap_set(mock_options->DNSResolverNameserverZoneMap, ".", nameservers);

  MOCK(get_options, mock_get_options);
  MOCK(connection_free_, mock_connection_free_);
  tt_int_op(dns_resolver_initiate_socks_address_resolution(ap_conn), OP_EQ,
            -3);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_free_);

  connection_free_minimal(ENTRY_TO_CONN(ap_conn));
  nameserver_free(nameserver);
  strmap_free(mock_options->DNSResolverNameserverZoneMap,
              (void (*)(void *)) smartlist_free_);
  tor_free(mock_options);
}

static void
test_dns_resolver_initiate_socks_address_resolution_missing_nameserver(
                                                                     void *arg)
{
  (void) arg;

  const char *qname = "example.com";

  entry_connection_t *ap_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  strlcpy(ap_conn->socks_request->address, qname,
          sizeof(ap_conn->socks_request->address));

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverIPv4 = 1;
  mock_options->DNSResolverNameserverZoneMap = strmap_new();

  MOCK(get_options, mock_get_options);
  MOCK(connection_free_, mock_connection_free_);
  tt_int_op(dns_resolver_initiate_socks_address_resolution(ap_conn), OP_EQ,
            -2);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_free_);

  connection_free_minimal(ENTRY_TO_CONN(ap_conn));
  strmap_free(mock_options->DNSResolverNameserverZoneMap,
              (void (*)(void *)) smartlist_free_);
  tor_free(mock_options);
}

static void
test_dns_resolver_initiate_socks_address_resolution_invalid_config(void *arg)
{
  (void) arg;

  const char *qname = "example.com";

  entry_connection_t *ap_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  strlcpy(ap_conn->socks_request->address, qname,
          sizeof(ap_conn->socks_request->address));

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverNameserverZoneMap = strmap_new();

  MOCK(get_options, mock_get_options);
  MOCK(connection_free_, mock_connection_free_);
  tt_int_op(dns_resolver_initiate_socks_address_resolution(ap_conn), OP_EQ,
            -1);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_free_);

  connection_free_minimal(ENTRY_TO_CONN(ap_conn));
  strmap_free(mock_options->DNSResolverNameserverZoneMap,
              (void (*)(void *)) smartlist_free_);
  tor_free(mock_options);
}

static void
test_dns_resolver_initiate_socks_address_resolution_is_cached(void *arg)
{
  (void) arg;

  const char *qname = "example.com";

  entry_connection_t *ap_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  strlcpy(ap_conn->socks_request->address, qname,
          sizeof(ap_conn->socks_request->address));

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverIPv4 = 1;
  mock_options->DNSResolverNameserverZoneMap = strmap_new();
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;

  dns_question_t *dq = dns_question_new();
  dq->qname = dns_name_of(qname);
  dq->qtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *message = dns_message_new();
  smartlist_add(message->question_list, dq);
  message->header->qdcount = smartlist_len(message->question_list);

  MOCK(get_options, mock_get_options);
  MOCK(connection_free_, mock_connection_free_);
  MOCK(connection_ap_rewrite_and_attach_if_allowed,
       mock_connection_ap_rewrite_and_attach_if_allowed_ok);
  tt_int_op(dns_resolver_cache_add_message(message), OP_EQ, 0);
  tt_int_op(dns_resolver_initiate_socks_address_resolution(ap_conn), OP_EQ, 0);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_free_);
  UNMOCK(connection_ap_rewrite_and_attach_if_allowed);

  connection_free_minimal(ENTRY_TO_CONN(ap_conn));
  strmap_free(mock_options->DNSResolverNameserverZoneMap,
              (void (*)(void *)) smartlist_free_);
  tor_free(mock_options);
  dns_message_free(message);
}

static void
test_dns_resolver_ping_nameserver(void *arg)
{
  (void) arg;

  nameserver_t *nameserver = nameserver_new();
  nameserver->hostname = tor_strdup("127.0.0.1");
  nameserver->port = 53;
  nameserver->latency = 1;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverNameservers = smartlist_new();
  smartlist_add(mock_options->DNSResolverNameservers, nameserver);

  MOCK(get_options, mock_get_options);
  MOCK(connection_ap_rewrite_and_attach_if_allowed,
       mock_connection_ap_rewrite_and_attach_if_allowed_ok);
  dns_resolver_ping_nameserver();
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_ap_rewrite_and_attach_if_allowed);

  nameserver_free(nameserver);
  smartlist_free(mock_options->DNSResolverNameservers);
  tor_free(mock_options);
}

static void
test_dns_resolver_process_reply_forward(void *arg)
{
  (void) arg;

  struct evdns_server_request *req = tor_malloc_zero(
                                       sizeof(struct evdns_server_request));

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  lookup->action = DNS_LOOKUP_ACTION_FORWARD;
  lookup->server_request = req;

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of("example.com");
  question->qtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *response = dns_message_new();
  smartlist_add(response->question_list, question);
  response->header->qdcount = smartlist_len(response->question_list);

  dns_encode_message_tcp(ENTRY_TO_CONN(dns_conn)->outbuf, response);

  mock_evdns_responds = 0;

  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);
  MOCK(dns_resolver_evdns_wrapper_respond,
       mock_dns_resolver_evdns_wrapper_respond);

  tt_int_op(dns_resolver_process_reply(dns_conn), OP_EQ, 0);
  tt_int_op(mock_evdns_responds, OP_EQ, 1);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(connection_mark_unattached_ap_);
  UNMOCK(dns_resolver_evdns_wrapper_respond);

  tor_free(req);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
  dns_message_free(response);
}

static void
test_dns_resolver_process_reply_resolve(void *arg)
{
  (void) arg;

  entry_connection_t *ap_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  strlcpy(ap_conn->socks_request->address, "example.com",
          sizeof(ap_conn->socks_request->address));

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  lookup->action = DNS_LOOKUP_ACTION_RESOLVE;
  lookup->ap_conn = ap_conn;

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of("example.com");
  question->qtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *response = dns_message_new();
  smartlist_add(response->question_list, question);
  response->header->qdcount = smartlist_len(response->question_list);

  dns_encode_message_tcp(ENTRY_TO_CONN(dns_conn)->outbuf, response);

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverDNSSECMode = DNSSEC_MODE_OFF;
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;

  MOCK(get_options, mock_get_options);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);
  MOCK(connection_ap_rewrite_and_attach_if_allowed,
       mock_connection_ap_rewrite_and_attach_if_allowed_ok);

  tt_int_op(dns_resolver_process_reply(dns_conn), OP_EQ, 0);
  tt_ptr_op(lookup->ap_conn, OP_EQ, NULL);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_mark_unattached_ap_);
  UNMOCK(connection_ap_rewrite_and_attach_if_allowed);

  connection_free_minimal(ENTRY_TO_CONN(ap_conn));
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
  dns_message_free(response);
  tor_free(mock_options);
}

static void
test_dns_resolver_process_reply_validate(void *arg)
{
  (void) arg;

  entry_connection_t *ap_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  strlcpy(ap_conn->socks_request->address, "example.com",
          sizeof(ap_conn->socks_request->address));

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  lookup->action = DNS_LOOKUP_ACTION_VALIDATE;
  lookup->ap_conn = ap_conn;
  lookup->validation = validation_new();

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of("example.com");
  question->qtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *response = dns_message_new();
  smartlist_add(response->question_list, question);
  response->header->qdcount = smartlist_len(response->question_list);

  dns_encode_message_tcp(ENTRY_TO_CONN(dns_conn)->outbuf, response);

  MOCK(connection_ap_rewrite_and_attach_if_allowed,
       mock_connection_ap_rewrite_and_attach_if_allowed_ok);

  tt_int_op(dns_resolver_process_reply(dns_conn), OP_EQ, -1);
  tt_ptr_op(lookup->ap_conn, OP_NE, NULL);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(connection_ap_rewrite_and_attach_if_allowed);

  connection_free_minimal(ENTRY_TO_CONN(ap_conn));
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
  dns_message_free(response);
}

static void
test_dns_resolver_process_reply_unknown_action(void *arg)
{
  (void) arg;

  entry_connection_t *ap_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  strlcpy(ap_conn->socks_request->address, "example.com",
          sizeof(ap_conn->socks_request->address));

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  lookup->action = 255;
  lookup->ap_conn = ap_conn;

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of("example.com");
  question->qtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *response = dns_message_new();
  smartlist_add(response->question_list, question);
  response->header->qdcount = smartlist_len(response->question_list);

  dns_encode_message_tcp(ENTRY_TO_CONN(dns_conn)->outbuf, response);

  MOCK(connection_ap_rewrite_and_attach_if_allowed,
       mock_connection_ap_rewrite_and_attach_if_allowed_ok);

  tt_int_op(dns_resolver_process_reply(dns_conn), OP_EQ, -3);
  tt_ptr_op(lookup->ap_conn, OP_NE, NULL);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(connection_ap_rewrite_and_attach_if_allowed);

  connection_free_minimal(ENTRY_TO_CONN(ap_conn));
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
  dns_message_free(response);
}

static void
test_dns_resolver_process_reply_invalid_message(void *arg)
{
  (void) arg;

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  lookup->action = 255;

  dns_message_t *response = dns_message_new();

  dns_encode_message_tcp(ENTRY_TO_CONN(dns_conn)->outbuf, response);

  tt_int_op(dns_resolver_process_reply(dns_conn), OP_EQ, -2);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
  dns_message_free(response);
}

static void
test_dns_resolver_process_reply_partial_response(void *arg)
{
  (void) arg;

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  lookup->action = 255;

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of("example.com");
  question->qtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *response = dns_message_new();
  smartlist_add(response->question_list, question);
  response->header->qdcount = smartlist_len(response->question_list);

  buf_t *buf = buf_new();
  dns_encode_message_tcp(buf, response);

  size_t size = buf_datalen(buf) - 1;
  buf_move_to_buf(ENTRY_TO_CONN(dns_conn)->outbuf, buf, &size);

  tt_int_op(dns_resolver_process_reply(dns_conn), OP_EQ, -1);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
  dns_message_free(response);
  buf_free(buf);
}

static void
test_dns_resolver_process_reply_invalid_response(void *arg)
{
  (void) arg;

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  lookup->action = 255;

  size_t response_len = 12;
  uint8_t response_data[12] = {
    0x08, 0x4B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  };

  uint16_t bytes = htons((uint16_t) response_len);
  buf_add(ENTRY_TO_CONN(dns_conn)->outbuf, (const char *) &bytes, 2);
  buf_add(ENTRY_TO_CONN(dns_conn)->outbuf, (const char *) response_data,
          response_len);

  tt_int_op(dns_resolver_process_reply(dns_conn), OP_EQ, -1);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_config_revise_dnssec_mode(void *arg)
{
  (void) arg;

  tt_int_op(dns_resolver_config_revise_dnssec_mode(NULL), OP_EQ,
            DNSSEC_MODE_VALIDATE);
  tt_int_op(dns_resolver_config_revise_dnssec_mode("Off"), OP_EQ,
            DNSSEC_MODE_OFF);
  tt_int_op(dns_resolver_config_revise_dnssec_mode("Process"), OP_EQ,
            DNSSEC_MODE_PROCESS);
  tt_int_op(dns_resolver_config_revise_dnssec_mode("Trust"), OP_EQ,
            DNSSEC_MODE_TRUST);
  tt_int_op(dns_resolver_config_revise_dnssec_mode("Validate"), OP_EQ,
            DNSSEC_MODE_VALIDATE);
  tt_int_op(dns_resolver_config_revise_dnssec_mode("unknown"), OP_EQ,
            DNSSEC_MODE_VALIDATE);

 done:
  (void) 0;
}

static void
test_dns_resolver_config_revise_nameservers_initial(void *arg)
{
  (void) arg;

  smartlist_t *nameservers = smartlist_new();
  smartlist_add(nameservers, (char *) "1.2.3.4");
  smartlist_add(nameservers, (char *) "");

  or_options_t *old_options = tor_malloc_zero(sizeof(or_options_t));

  smartlist_t *updated = dns_resolver_config_revise_nameservers(nameservers,
                                                                old_options);

  tt_int_op(smartlist_len(updated), OP_EQ, 1);
  tt_str_op(((nameserver_t *) smartlist_get(updated, 0))->hostname, OP_EQ,
            "1.2.3.4");

 done:
  smartlist_free(nameservers);
  tor_free(old_options);
  dns_resolver_config_free_nameservers(updated);
}

static void
test_dns_resolver_config_revise_nameservers_update(void *arg)
{
  (void) arg;

  smartlist_t *nameservers = smartlist_new();
  smartlist_add(nameservers, (char *) "1.2.3.4");
  smartlist_add(nameservers, (char *) "");

  nameserver_t *ns1 = nameserver_new();
  ns1->hostname = tor_strdup("1.2.3.4");
  ns1->port = 53;
  smartlist_add(ns1->zones, dns_name_of("."));

  nameserver_t *ns2 = nameserver_new();
  ns2->hostname = tor_strdup("5.6.7.8");
  ns2->port = 53;
  smartlist_add(ns2->zones, dns_name_of("."));

  or_options_t *old_options = tor_malloc_zero(sizeof(or_options_t));
  old_options->DNSResolverNameservers = smartlist_new();
  smartlist_add(old_options->DNSResolverNameservers, ns1);
  smartlist_add(old_options->DNSResolverNameservers, ns2);

  smartlist_t *updated = dns_resolver_config_revise_nameservers(nameservers,
                                                                old_options);

  tt_int_op(smartlist_len(updated), OP_EQ, 1);
  tt_ptr_op(smartlist_get(updated, 0), OP_EQ, ns1);
  tt_int_op(smartlist_len(old_options->DNSResolverNameservers), OP_EQ, 0);

 done:
  smartlist_free(nameservers);
  dns_resolver_config_free_nameservers(old_options->DNSResolverNameservers);
  tor_free(old_options);
  dns_resolver_config_free_nameservers(updated);
}

static void
test_dns_resolver_config_revise_nameserver_zone_map(void *arg)
{
  (void) arg;

  nameserver_t *ns1 = nameserver_new();
  ns1->hostname = tor_strdup("1.2.3.4");
  ns1->port = 53;
  smartlist_add(ns1->zones, dns_name_of("."));
  smartlist_add(ns1->zones, dns_name_of("com."));
  smartlist_add(ns1->zones, dns_name_of("net."));

  nameserver_t *ns2 = nameserver_new();
  ns2->hostname = tor_strdup("4.5.6.7");
  ns2->port = 53;
  smartlist_add(ns2->zones, dns_name_of("."));
  smartlist_add(ns2->zones, dns_name_of("net."));

  smartlist_t *nameservers = smartlist_new();
  smartlist_add(nameservers, ns1);
  smartlist_add(nameservers, ns2);

  strmap_t *zone_map =
    dns_resolver_config_revise_nameserver_zone_map(nameservers);

  tt_int_op(strmap_size(zone_map), OP_EQ, 3);
  tt_ptr_op(strmap_get(zone_map, "."), OP_NE, NULL);
  tt_int_op(smartlist_len(strmap_get(zone_map, ".")), OP_EQ, 2);
  tt_ptr_op(strmap_get(zone_map, "com."), OP_NE, NULL);
  tt_int_op(smartlist_len(strmap_get(zone_map, "com.")), OP_EQ, 1);
  tt_ptr_op(strmap_get(zone_map, "net."), OP_NE, NULL);
  tt_int_op(smartlist_len(strmap_get(zone_map, "net.")), OP_EQ, 2);

 done:
  SMARTLIST_FOREACH(nameservers, nameserver_t *, nameserver,
                    nameserver_free(nameserver));
  smartlist_free(nameservers);
  dns_resolver_config_free_nameserver_zone_map(zone_map);
}

static void
test_dns_resolver_config_revise_trust_anchors(void *arg)
{
  (void) arg;

  smartlist_t *trust_anchors = smartlist_new();
  smartlist_add(trust_anchors, (char *) ". 3475 IN DS 20326 8 2 "
    "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d");
  smartlist_add(trust_anchors, (char *) "example. 3600 IN DNSKEY 256 3 5 "
    "AQOy1bZVvpPqhg4j7EJoM9rI3ZmyEx2OzDBVrZy/lvI5CQePxXHZS4i8dANH4DX3tbHol61ek"
    "8EFMcsGXxKciJFHyhl94C+NwILQdzsUlSFovBZsyl/NX6yEbtw/xN9ZNcrbYvgjjZ/UVPZIyS"
    "FNsgEYvh0z2542lzMKR4Dh8uZffQ==");
  smartlist_add(trust_anchors, (char *) "invalid");

  smartlist_t *updated = dns_resolver_config_revise_trust_anchors(
                           trust_anchors);

  tt_int_op(smartlist_len(updated), OP_EQ, 1);

 done:
  smartlist_free(trust_anchors);
  dns_resolver_config_free_trust_anchors(updated);
}

static void
test_dns_resolver_handle_resolution_reply_dnssec_off(void *arg)
{
  (void) arg;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverDNSSECMode = DNSSEC_MODE_OFF;

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of("example.com");
  question->qtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);

  MOCK(get_options, mock_get_options);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_handle_resolution_reply(dns_conn, resp), OP_EQ, -1);
  tt_ptr_op(dns_conn->dns_lookup->validation, OP_EQ, NULL);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_mark_unattached_ap_);

  tor_free(mock_options);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_handle_resolution_reply_dnssec_trust(void *arg)
{
  (void) arg;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverDNSSECMode = DNSSEC_MODE_TRUST;

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of("example.com");
  question->qtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);

  MOCK(get_options, mock_get_options);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_handle_resolution_reply(dns_conn, resp), OP_EQ, -1);
  tt_ptr_op(dns_conn->dns_lookup->validation, OP_EQ, NULL);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_mark_unattached_ap_);

  tor_free(mock_options);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_handle_resolution_reply_unknown_action(void *arg)
{
  (void) arg;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverDNSSECMode = 255;

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();

  dns_message_t *resp = dns_message_new();

  MOCK(get_options, mock_get_options);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_handle_resolution_reply(dns_conn, resp), OP_EQ, -1);
  tt_ptr_op(dns_conn->dns_lookup->validation, OP_EQ, NULL);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_mark_unattached_ap_);

  tor_free(mock_options);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

#ifdef ENABLE_OPENSSL

static void
test_dns_resolver_handle_resolution_reply_dnssec_process(void *arg)
{
  (void) arg;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverDNSSECMode = DNSSEC_MODE_PROCESS;

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of("example.com");
  question->qtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);

  MOCK(get_options, mock_get_options);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_handle_resolution_reply(dns_conn, resp), OP_EQ, -1);
  tt_ptr_op(dns_conn->dns_lookup->validation, OP_NE, NULL);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_mark_unattached_ap_);

  tor_free(mock_options);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_handle_resolution_reply_dnssec_validate(void *arg)
{
  (void) arg;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverDNSSECMode = DNSSEC_MODE_VALIDATE;

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of("example.com");
  question->qtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);

  MOCK(get_options, mock_get_options);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_handle_resolution_reply(dns_conn, resp), OP_EQ, -1);
  tt_ptr_op(dns_conn->dns_lookup->validation, OP_NE, NULL);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_mark_unattached_ap_);

  tor_free(mock_options);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_handle_validation_reply_apex_dnskeys_respond(void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  validation_t *validation = dns_conn->dns_lookup->validation;

  validation->action = VALIDATION_ACTION_APEX_KEYS;
  validation->message = dns_message_new();
  validation->active_zone = dns_name_of(zone);

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of("example.com");
  question->qtype = dns_type_of(DNS_TYPE_DNSKEY);

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);

  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_handle_validation_reply(dns_conn, resp), OP_EQ, -1);
  tt_uint_op(validation->action, OP_EQ, VALIDATION_ACTION_APEX_KEYS);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(connection_mark_unattached_ap_);

  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_handle_validation_reply_delegation_respond(void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  validation_t *validation = dns_conn->dns_lookup->validation;

  validation->action = VALIDATION_ACTION_DELEGATION;
  validation->message = dns_message_new();
  validation->active_zone = dns_name_of(zone);

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of("example.com");
  question->qtype = dns_type_of(DNS_TYPE_DS);

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);

  tt_int_op(dns_resolver_handle_validation_reply(dns_conn, resp), OP_EQ, 0);
  tt_uint_op(validation->action, OP_EQ, VALIDATION_ACTION_APEX_KEYS);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_handle_validation_reply_zone_cut_respond(void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  validation_t *validation = dns_conn->dns_lookup->validation;

  validation->action = VALIDATION_ACTION_ZONE_CUT;
  validation->message = dns_message_new();
  validation->active_zone = dns_name_of(zone);

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of("example.com");
  question->qtype = dns_type_of(DNS_TYPE_NS);

  dns_rr_t *rr = dns_rr_new();
  rr->rrtype = dns_type_of(DNS_TYPE_NS);

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);
  smartlist_add(resp->answer_list, rr);

  tt_int_op(dns_resolver_handle_validation_reply(dns_conn, resp), OP_EQ, 0);
  tt_uint_op(validation->action, OP_EQ, VALIDATION_ACTION_DELEGATION);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_handle_validation_reply_unknown_action(void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  validation_t *validation = dns_conn->dns_lookup->validation;

  validation->action = 255;
  validation->message = dns_message_new();
  validation->active_zone = dns_name_of(zone);

  dns_message_t *resp = dns_message_new();

  tt_int_op(dns_resolver_handle_validation_reply(dns_conn, resp), OP_EQ, -1);
  tt_uint_op(validation->action, OP_EQ, 255);

 done:
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_validation_initiate(void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  lookup->action = DNS_LOOKUP_ACTION_RESOLVE;
  validation_free(lookup->validation);

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of(zone);
  question->qtype = dns_type_of(DNS_TYPE_A);

  dns_rr_t *answer_rr = dns_rr_new();
  answer_rr->name = dns_name_of("hello.");
  dns_rr_t *authority_rr = dns_rr_new();
  authority_rr->name = dns_name_of("hello.");

  dns_message_t *message = dns_message_new();
  smartlist_add(message->question_list, question);
  message->header->qdcount = smartlist_len(message->question_list);
  smartlist_add(message->answer_list, answer_rr);
  smartlist_add(message->name_server_list, authority_rr);

  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_validation_initiate(dns_conn, message), OP_EQ, -1);
  tt_int_op(lookup->action, OP_EQ, DNS_LOOKUP_ACTION_VALIDATE);
  tt_ptr_op(lookup->validation, OP_NE, NULL);
  tt_ptr_op(lookup->validation->message, OP_EQ, message);
  tt_int_op(answer_rr->validation_state, OP_EQ,
            DNSSEC_VALIDATION_STATE_INDETERMINATE);
  tt_int_op(authority_rr->validation_state, OP_EQ,
            DNSSEC_VALIDATION_STATE_INDETERMINATE);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  UNMOCK(connection_mark_unattached_ap_);

  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_validation_initiate_encounters_invalid_message(void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  lookup->action = DNS_LOOKUP_ACTION_RESOLVE;
  validation_free(lookup->validation);

  dns_message_t *message = dns_message_new();

  tt_int_op(dns_resolver_validation_initiate(dns_conn, message), OP_EQ, -1);
  tt_int_op(lookup->action, OP_EQ, DNS_LOOKUP_ACTION_VALIDATE);
  tt_ptr_op(lookup->validation, OP_EQ, NULL);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  dns_message_free(message);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_validation_initiate_next_chain_initiate(void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  validation_t *validation = dns_conn->dns_lookup->validation;

  dns_rr_t *ta_rr = dns_rr_new();
  ta_rr->name = dns_name_of(".");
  ta_rr->rrtype = dns_type_of(DNS_TYPE_DS);

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;
  mock_options->DNSResolverTrustAnchors = smartlist_new();
  smartlist_add(mock_options->DNSResolverTrustAnchors, ta_rr);

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of(zone);
  question->qtype = dns_type_of(DNS_TYPE_A);

  dns_rr_t *a_rr = dns_rr_new();
  a_rr->name = dns_name_of(zone);
  a_rr->rrtype = dns_type_of(DNS_TYPE_A);
  a_rr->validation_state = DNSSEC_VALIDATION_STATE_INDETERMINATE;

  dns_message_t *message = dns_message_new();
  smartlist_add(message->question_list, question);
  message->header->qdcount = smartlist_len(message->question_list);
  smartlist_add(message->answer_list, a_rr);

  validation->message = message;
  validation->section = DNS_MESSAGE_SECTION_ANSWER;

  MOCK(get_options, mock_get_options);
  tt_int_op(dns_resolver_validation_initiate_next_chain(dns_conn), OP_EQ, 0);

  tt_str_op(dns_name_str(validation->active_child), OP_EQ, ".");
  tt_int_op(smartlist_len(validation->zones), OP_EQ, 2);
  tt_int_op(smartlist_len(validation->delegation_signers), OP_EQ, 1);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);

  SMARTLIST_FOREACH(mock_options->DNSResolverTrustAnchors, dns_rr_t *, rr,
                    dns_rr_free(rr));
  smartlist_free(mock_options->DNSResolverTrustAnchors);
  tor_free(mock_options);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_validation_initiate_next_chain_out_of_child_zones(void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  validation_t *validation = dns_conn->dns_lookup->validation;

  dns_rr_t *ta_rr = dns_rr_new();
  ta_rr->name = dns_name_of("org.");
  ta_rr->rrtype = dns_type_of(DNS_TYPE_DS);

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;
  mock_options->DNSResolverTrustAnchors = smartlist_new();
  smartlist_add(mock_options->DNSResolverTrustAnchors, ta_rr);

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of(zone);
  question->qtype = dns_type_of(DNS_TYPE_A);

  dns_rr_t *a_rr = dns_rr_new();
  a_rr->name = dns_name_of(zone);
  a_rr->rrtype = dns_type_of(DNS_TYPE_A);
  a_rr->validation_state = DNSSEC_VALIDATION_STATE_INDETERMINATE;

  dns_message_t *message = dns_message_new();
  smartlist_add(message->question_list, question);
  message->header->qdcount = smartlist_len(message->question_list);
  smartlist_add(message->answer_list, a_rr);

  validation->message = message;
  validation->section = DNS_MESSAGE_SECTION_ANSWER;
  validation->zones = smartlist_new();

  MOCK(get_options, mock_get_options);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_validation_initiate_next_chain(dns_conn), OP_EQ, -1);

  tt_ptr_op(validation->active_child, OP_EQ, NULL);
  tt_int_op(smartlist_len(validation->zones), OP_EQ, 0);
  tt_int_op(smartlist_len(validation->delegation_signers), OP_EQ, 0);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_mark_unattached_ap_);

  SMARTLIST_FOREACH(mock_options->DNSResolverTrustAnchors, dns_rr_t *, rr,
                    dns_rr_free(rr));
  smartlist_free(mock_options->DNSResolverTrustAnchors);
  tor_free(mock_options);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_validation_initiate_next_chain_misses_trust_anchor(void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  validation_t *validation = dns_conn->dns_lookup->validation;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;
  mock_options->DNSResolverTrustAnchors = smartlist_new();

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of(zone);
  question->qtype = dns_type_of(DNS_TYPE_A);

  dns_rr_t *a_rr = dns_rr_new();
  a_rr->name = dns_name_of(zone);
  a_rr->rrtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *message = dns_message_new();
  smartlist_add(message->question_list, question);
  message->header->qdcount = smartlist_len(message->question_list);
  smartlist_add(message->answer_list, a_rr);

  validation->message = message;

  MOCK(get_options, mock_get_options);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_validation_initiate_next_chain(dns_conn), OP_EQ, -1);

  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_ptr_op(validation->zones, OP_EQ, NULL);
  tt_int_op(smartlist_len(validation->delegation_signers), OP_EQ, 0);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_mark_unattached_ap_);

  smartlist_free(mock_options->DNSResolverTrustAnchors);
  tor_free(mock_options);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_validation_initiate_next_chain_resolve_request(void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  validation_t *validation = dns_conn->dns_lookup->validation;
  validation->active_zone = dns_name_of(zone);

  dns_rr_t *ta_rr = dns_rr_new();
  ta_rr->name = dns_name_of(".");
  ta_rr->rrtype = dns_type_of(DNS_TYPE_DS);

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;
  mock_options->DNSResolverTrustAnchors = smartlist_new();
  smartlist_add(mock_options->DNSResolverTrustAnchors, ta_rr);

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of(zone);
  question->qtype = dns_type_of(DNS_TYPE_A);

  dns_rr_t *a_rr = dns_rr_new();
  a_rr->name = dns_name_of(zone);
  a_rr->rrtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *message = dns_message_new();
  smartlist_add(message->question_list, question);
  message->header->qdcount = smartlist_len(message->question_list);
  smartlist_add(message->answer_list, a_rr);

  validation->message = message;

  MOCK(get_options, mock_get_options);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_validation_initiate_next_chain(dns_conn), OP_EQ, -1);

  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_ptr_op(validation->zones, OP_EQ, NULL);
  tt_int_op(smartlist_len(validation->delegation_signers), OP_EQ, 0);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_mark_unattached_ap_);

  SMARTLIST_FOREACH(mock_options->DNSResolverTrustAnchors, dns_rr_t *, rr,
                    dns_rr_free(rr));
  smartlist_free(mock_options->DNSResolverTrustAnchors);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
  tor_free(mock_options);
}

static void
test_dns_resolver_validation_conclude_chain_unauthenticated_answers(void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;

  smartlist_add(validation->completed, dns_name_of(zone));

  dns_rr_t *rr = dns_rr_new();
  rr->name = dns_name_of(zone);

  dns_message_t *message = dns_message_new();
  message->header->rcode = DNS_RCODE_NOERROR;
  smartlist_add(message->answer_list, rr);
  validation->message = message;
  validation->section = DNS_MESSAGE_SECTION_ANSWER;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverDNSSECMode = DNSSEC_MODE_VALIDATE;
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;

  MOCK(get_options, mock_get_options);
  MOCK(dnssec_authenticate_rrset, mock_dnssec_authenticate_rrset_fail);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_validation_conclude_chain(dns_conn), OP_EQ, -1);

  tt_int_op(validation->message->header->rcode, OP_EQ, DNS_RCODE_SERVFAIL);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);
  UNMOCK(dnssec_authenticate_rrset);
  UNMOCK(connection_mark_unattached_ap_);

  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
  tor_free(mock_options);
}

static void
test_dns_resolver_validation_conclude_chain_unauthenticated_authorities(
  void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;

  smartlist_add(validation->completed, dns_name_of(zone));

  dns_rr_t *rr = dns_rr_new();
  rr->name = dns_name_of(zone);

  dns_message_t *message = dns_message_new();
  message->header->rcode = DNS_RCODE_NOERROR;
  smartlist_add(message->name_server_list, rr);
  validation->message = message;
  validation->section = DNS_MESSAGE_SECTION_AUTHORITY;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverDNSSECMode = DNSSEC_MODE_VALIDATE;
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;

  MOCK(get_options, mock_get_options);
  MOCK(dnssec_authenticate_rrset, mock_dnssec_authenticate_rrset_fail);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_validation_conclude_chain(dns_conn), OP_EQ, -1);

  tt_int_op(validation->message->header->rcode, OP_EQ, DNS_RCODE_SERVFAIL);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);
  UNMOCK(dnssec_authenticate_rrset);
  UNMOCK(connection_mark_unattached_ap_);

  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
  tor_free(mock_options);
}

static void
test_dns_resolver_validation_conclude_chain_denial_of_existence(void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;

  smartlist_add(validation->completed, dns_name_of(zone));

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of(zone);
  question->qtype = dns_type_of(DNS_TYPE_A);

  dns_rr_t *rr = dns_rr_new();
  rr->name = dns_name_of(zone);

  dns_message_t *message = dns_message_new();
  smartlist_add(message->question_list, question);
  message->header->qdcount = smartlist_len(message->question_list);
  message->header->rcode = DNS_RCODE_NOERROR;
  smartlist_add(message->name_server_list, rr);
  validation->message = message;
  validation->section = DNS_MESSAGE_SECTION_AUTHORITY;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverDNSSECMode = DNSSEC_MODE_VALIDATE;
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;

  MOCK(get_options, mock_get_options);
  MOCK(dnssec_authenticate_rrset, mock_dnssec_authenticate_rrset_ok);
  MOCK(dnssec_denial_of_existence, mock_dnssec_denial_of_existence_nxdomain);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_validation_conclude_chain(dns_conn), OP_EQ, -1);

  tt_int_op(validation->message->header->rcode, OP_EQ, DNS_RCODE_NXDOMAIN);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  UNMOCK(get_options);
  UNMOCK(dnssec_authenticate_rrset);
  UNMOCK(dnssec_denial_of_existence);
  UNMOCK(connection_mark_unattached_ap_);

  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
  tor_free(mock_options);
}

static void
test_dns_resolver_validation_choose_next_zone_to_validate(void *arg)
{
  (void) arg;

  dns_rr_t *ans_rrsig = dns_rr_new();
  ans_rrsig->name = dns_name_of("answer.example.");
  ans_rrsig->rrtype = dns_type_of(DNS_TYPE_RRSIG);
  ans_rrsig->rrsig = dns_rrsig_new();
  ans_rrsig->rrsig->signer_name = dns_name_of("rrsig.answer.example.");
  ans_rrsig->validation_state = DNSSEC_VALIDATION_STATE_INDETERMINATE;

  dns_rr_t *auth_rrsig = dns_rr_new();
  auth_rrsig->name = dns_name_of("authority.example.");
  auth_rrsig->rrtype = dns_type_of(DNS_TYPE_RRSIG);
  auth_rrsig->rrsig = dns_rrsig_new();
  auth_rrsig->rrsig->signer_name = dns_name_of("rrsig.authority.example.");
  auth_rrsig->validation_state = DNSSEC_VALIDATION_STATE_INDETERMINATE;

  dns_rr_t *rr = dns_rr_new();
  rr->name = dns_name_of("cname.example.");
  rr->rrtype = dns_type_of(DNS_TYPE_CNAME);
  rr->validation_state = DNSSEC_VALIDATION_STATE_INDETERMINATE;

  dns_message_t *message = dns_message_new();
  smartlist_add(message->answer_list, ans_rrsig);
  smartlist_add(message->answer_list, rr);
  smartlist_add(message->name_server_list, auth_rrsig);

  validation_t *validation = validation_new();
  validation->message = message;
  validation->section = DNS_MESSAGE_SECTION_ANSWER;

  tt_int_op(dns_resolver_validation_choose_next_zone_to_validate(validation),
            OP_EQ, 0);
  tt_str_op(dns_name_str(validation->active_zone), OP_EQ,
            dns_name_str(ans_rrsig->rrsig->signer_name));

  smartlist_add(validation->completed, dns_name_dup(validation->active_zone));
  tt_int_op(dns_resolver_validation_choose_next_zone_to_validate(validation),
            OP_EQ, 0);
  tt_str_op(dns_name_str(validation->active_zone), OP_EQ,
            dns_name_str(rr->name));

  smartlist_add(validation->completed, dns_name_dup(validation->active_zone));
  tt_int_op(dns_resolver_validation_choose_next_zone_to_validate(validation),
            OP_EQ, 0);
  tt_str_op(dns_name_str(validation->active_zone), OP_EQ,
            dns_name_str(auth_rrsig->rrsig->signer_name));

  smartlist_add(validation->completed, dns_name_dup(validation->active_zone));
  tt_int_op(dns_resolver_validation_choose_next_zone_to_validate(validation),
            OP_EQ, -1);

 done:
  validation_free(validation);
}

static void
test_dns_resolver_validation_apex_dnskeys_request_send_query_succeeds(
                                                                     void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;

  validation->action = VALIDATION_ACTION_DELEGATION;
  validation->zones = smartlist_new();
  smartlist_add(validation->zones, dns_name_of(zone));

  tt_int_op(dns_resolver_validation_apex_dnskeys_request(dns_conn), OP_EQ, 0);

  tt_uint_op(validation->action, OP_EQ, VALIDATION_ACTION_APEX_KEYS);
  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_str_op(dns_name_str(lookup->qname), OP_EQ, zone);
  tt_uint_op(lookup->qtype, OP_EQ, DNS_TYPE_DNSKEY);
  tt_int_op(buf_datalen(ENTRY_TO_CONN(dns_conn)->inbuf), OP_EQ, 31);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_validation_apex_dnskeys_request_send_query_fails(void *arg)
{
  (void) arg;

  const char *zone = "abcd012345678901234567890123456789012345678901234567890"
                     "123456789.example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;

  validation->action = VALIDATION_ACTION_DELEGATION;
  validation->message = dns_message_new();
  validation->zones = smartlist_new();
  smartlist_add(validation->zones, dns_name_of(zone));

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverDNSSECMode = DNSSEC_MODE_VALIDATE;

  MOCK(get_options, mock_get_options);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_validation_apex_dnskeys_request(dns_conn), OP_EQ, -1);

  tt_uint_op(validation->action, OP_EQ, VALIDATION_ACTION_APEX_KEYS);
  tt_int_op(validation->message->header->rcode, OP_EQ, DNS_RCODE_SERVFAIL);
  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_str_op(dns_name_str(lookup->qname), OP_EQ, zone);
  tt_uint_op(lookup->qtype, OP_EQ, DNS_TYPE_DNSKEY);
  tt_int_op(buf_datalen(ENTRY_TO_CONN(dns_conn)->inbuf), OP_EQ, 0);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_mark_unattached_ap_);

  tor_free(mock_options);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_validation_apex_dnskeys_request_is_cached(void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;

  validation->action = VALIDATION_ACTION_DELEGATION;
  validation->active_zone = dns_name_of(zone);
  validation->zones = smartlist_new();
  smartlist_add(validation->zones, dns_name_of(zone));
  validation->message = dns_message_new();

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of(zone);
  question->qtype = dns_type_of(DNS_TYPE_DNSKEY);

  dns_message_t *message = dns_message_new();
  smartlist_add(message->question_list, question);
  message->header->qdcount = smartlist_len(message->question_list);

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;

  MOCK(get_options, mock_get_options);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  dns_resolver_cache_add_message(message);

  tt_int_op(dns_resolver_validation_apex_dnskeys_request(dns_conn), OP_EQ, -1);

  tt_uint_op(validation->action, OP_EQ, VALIDATION_ACTION_APEX_KEYS);
  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_str_op(dns_name_str(lookup->qname), OP_EQ, "");
  tt_uint_op(lookup->qtype, OP_EQ, 0);
  tt_int_op(buf_datalen(ENTRY_TO_CONN(dns_conn)->inbuf), OP_EQ, 0);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_mark_unattached_ap_);

  dns_message_free(validation->message);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
  dns_message_free(message);
  tor_free(mock_options);
}

static void
test_dns_resolver_validation_apex_dnskeys_response_is_valid(void *arg)
{
  (void) arg;

  const char *zone = "example.com";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  validation_t *validation = dns_conn->dns_lookup->validation;

  validation->action = VALIDATION_ACTION_APEX_KEYS;
  validation->message = dns_message_new();

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of(zone);
  question->qtype = dns_type_of(DNS_TYPE_DNSKEY);

  dns_rr_t *dnskey_rr = dns_rr_new();
  dnskey_rr->rrtype = dns_type_of(DNS_TYPE_DNSKEY);
  dnskey_rr->validation_state = DNSSEC_VALIDATION_STATE_SECURE;
  dnskey_rr->dnskey = dns_dnskey_new();
  dnskey_rr->dnskey->flags = DNS_DNSKEY_FLAG_ZONE;

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);
  smartlist_add(resp->answer_list, dnskey_rr);

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverDNSSECMode = DNSSEC_MODE_VALIDATE;
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;

  MOCK(get_options, mock_get_options);
  MOCK(dnssec_authenticate_delegation_to_child_zone,
       mock_dnssec_authenticate_delegation_to_child_zone_ok);
  MOCK(dnssec_authenticate_rrset, mock_dnssec_authenticate_rrset_ok);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_validation_apex_dnskeys_response(dns_conn, resp),
            OP_EQ, -1);

  tt_uint_op(validation->action, OP_EQ, VALIDATION_ACTION_ZONE_CUT);
  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_int_op(smartlist_len(validation->apex_dnskeys), OP_EQ, 1);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  UNMOCK(get_options);
  UNMOCK(dnssec_authenticate_delegation_to_child_zone);
  UNMOCK(dnssec_authenticate_rrset);
  UNMOCK(connection_mark_unattached_ap_);

  dns_message_free(validation->message);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
  tor_free(mock_options);
}

static void
test_dns_resolver_validation_apex_dnskeys_response_is_bogus(void *arg)
{
  (void) arg;

  const char *zone = "example.com";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  validation_t *validation = dns_conn->dns_lookup->validation;
  validation->action = VALIDATION_ACTION_APEX_KEYS;

  dns_rr_t *rr = dns_rr_new();
  rr->name = dns_name_of(zone);

  validation->active_zone = dns_name_of(zone);
  validation->message = dns_message_new();
  validation->message->header->rcode = DNS_RCODE_NOERROR;
  smartlist_add(validation->message->answer_list, rr);

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of(zone);
  question->qtype = dns_type_of(DNS_TYPE_DNSKEY);

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverDNSSECMode = DNSSEC_MODE_VALIDATE;
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;

  MOCK(get_options, mock_get_options);
  MOCK(dnssec_authenticate_delegation_to_child_zone,
       mock_dnssec_authenticate_delegation_to_child_zone_fail);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_validation_apex_dnskeys_response(dns_conn, resp),
            OP_EQ, -1);

  tt_uint_op(validation->action, OP_EQ, VALIDATION_ACTION_APEX_KEYS);
  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_int_op(smartlist_len(validation->apex_dnskeys), OP_EQ, 0);
  tt_int_op(validation->message->header->rcode, OP_EQ, DNS_RCODE_SERVFAIL);
  tt_int_op(rr->validation_state, OP_EQ, DNSSEC_VALIDATION_STATE_BOGUS);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);
  UNMOCK(dnssec_authenticate_delegation_to_child_zone);
  UNMOCK(connection_mark_unattached_ap_);

  tor_free(validation->active_zone);
  dns_message_free(validation->message);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
  tor_free(mock_options);
}

static void
test_dns_resolver_validation_apex_dnskeys_response_is_insecure(void *arg)
{
  (void) arg;

  const char *zone = "example.com";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  validation_t *validation = dns_conn->dns_lookup->validation;
  validation->action = VALIDATION_ACTION_APEX_KEYS;

  dns_rr_t *rr = dns_rr_new();
  rr->name = dns_name_of(zone);

  validation->active_zone = dns_name_of(zone);
  validation->message = dns_message_new();
  validation->message->header->rcode = DNS_RCODE_NOERROR;
  smartlist_add(validation->message->answer_list, rr);

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of(zone);
  question->qtype = dns_type_of(DNS_TYPE_DNSKEY);

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverDNSSECMode = DNSSEC_MODE_VALIDATE;
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;

  MOCK(get_options, mock_get_options);
  MOCK(dnssec_authenticate_delegation_to_child_zone,
       mock_dnssec_authenticate_delegation_to_child_zone_ok);
  MOCK(dnssec_authenticate_rrset, mock_dnssec_authenticate_rrset_fail);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_validation_apex_dnskeys_response(dns_conn, resp),
            OP_EQ, -1);

  tt_uint_op(validation->action, OP_EQ, VALIDATION_ACTION_ZONE_CUT);
  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_int_op(smartlist_len(validation->apex_dnskeys), OP_EQ, 0);
  tt_int_op(validation->message->header->rcode, OP_EQ, DNS_RCODE_SERVFAIL);
  tt_int_op(rr->validation_state, OP_EQ, DNSSEC_VALIDATION_STATE_INSECURE);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  UNMOCK(get_options);
  UNMOCK(dnssec_authenticate_delegation_to_child_zone);
  UNMOCK(dnssec_authenticate_rrset);
  UNMOCK(connection_mark_unattached_ap_);

  tor_free(validation->active_zone);
  dns_message_free(validation->message);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
  tor_free(mock_options);
}

static void
test_dns_resolver_validation_apex_dnskeys_response_has_invalid_type(void *arg)
{
  (void) arg;

  const char *zone = "example.com";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  validation_t *validation = dns_conn->dns_lookup->validation;

  validation->action = VALIDATION_ACTION_APEX_KEYS;
  validation->message = dns_message_new();

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of(zone);
  question->qtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverDNSSECMode = DNSSEC_MODE_VALIDATE;
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;

  MOCK(get_options, mock_get_options);
  MOCK(dnssec_authenticate_delegation_to_child_zone,
       mock_dnssec_authenticate_delegation_to_child_zone_ok);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_validation_apex_dnskeys_response(dns_conn, resp),
            OP_EQ, -1);

  tt_uint_op(validation->action, OP_EQ, VALIDATION_ACTION_APEX_KEYS);
  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_int_op(smartlist_len(validation->apex_dnskeys), OP_EQ, 0);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);
  UNMOCK(dnssec_authenticate_delegation_to_child_zone);
  UNMOCK(connection_mark_unattached_ap_);

  dns_message_free(validation->message);
  dns_message_free(resp);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
  tor_free(mock_options);
}

static void
test_dns_resolver_validation_delegation_request_send_query_succeedes(void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;

  validation->action = VALIDATION_ACTION_ZONE_CUT;
  validation->zones = smartlist_new();
  smartlist_add(validation->zones, dns_name_of(zone));

  tt_int_op(dns_resolver_validation_delegation_request(dns_conn), OP_EQ, 0);

  tt_uint_op(validation->action , OP_EQ, VALIDATION_ACTION_DELEGATION);
  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_str_op(dns_name_str(lookup->qname), OP_EQ, zone);
  tt_uint_op(lookup->qtype, OP_EQ, DNS_TYPE_DS);
  tt_int_op(buf_datalen(ENTRY_TO_CONN(dns_conn)->inbuf), OP_EQ, 31);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_validation_delegation_request_send_query_fails(void *arg)
{
  (void) arg;

  const char *zone = "abcd012345678901234567890123456789012345678901234567890"
                     "123456789.example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;

  validation->action = VALIDATION_ACTION_ZONE_CUT;
  validation->message = dns_message_new();
  validation->zones = smartlist_new();
  smartlist_add(validation->zones, dns_name_of(zone));

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverDNSSECMode = DNSSEC_MODE_VALIDATE;

  MOCK(get_options, mock_get_options);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_validation_delegation_request(dns_conn), OP_EQ, -1);

  tt_uint_op(validation->action , OP_EQ, VALIDATION_ACTION_DELEGATION);
  tt_int_op(validation->message->header->rcode, OP_EQ, DNS_RCODE_SERVFAIL);
  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_str_op(dns_name_str(lookup->qname), OP_EQ, zone);
  tt_uint_op(lookup->qtype, OP_EQ, DNS_TYPE_DS);
  tt_int_op(buf_datalen(ENTRY_TO_CONN(dns_conn)->inbuf), OP_EQ, 0);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_mark_unattached_ap_);

  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
  tor_free(mock_options);
}

static void
test_dns_resolver_validation_delegation_request_is_cached(void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;

  validation->action = VALIDATION_ACTION_ZONE_CUT;
  validation->zones = smartlist_new();
  smartlist_add(validation->zones, dns_name_of(zone));

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of(zone);
  question->qtype = dns_type_of(DNS_TYPE_DS);

  dns_message_t *message = dns_message_new();
  smartlist_add(message->question_list, question);
  message->header->qdcount = smartlist_len(message->question_list);

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;

  MOCK(get_options, mock_get_options);
  dns_resolver_cache_add_message(message);

  tt_int_op(dns_resolver_validation_delegation_request(dns_conn), OP_EQ, 0);

  tt_uint_op(validation->action , OP_EQ, VALIDATION_ACTION_APEX_KEYS);
  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_str_op(dns_name_str(lookup->qname), OP_EQ, zone);
  tt_uint_op(lookup->qtype, OP_EQ, DNS_TYPE_DNSKEY);
  tt_int_op(buf_datalen(ENTRY_TO_CONN(dns_conn)->inbuf), OP_EQ, 31);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  UNMOCK(get_options);

  tor_free(mock_options);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
  dns_message_free(message);
}

static void
test_dns_resolver_validation_delegation_request_is_trust_anchor(void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;

  validation->action = VALIDATION_ACTION_ZONE_CUT;
  validation->zones = smartlist_new();
  smartlist_add(validation->zones, dns_name_of(zone));

  dns_rr_t *trust_anchor = dns_rr_value_of("example.com. 3475 IN DS 20326 8 2 "
                                           "e06d44");

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverTrustAnchors = smartlist_new();
  smartlist_add(mock_options->DNSResolverTrustAnchors, trust_anchor);

  MOCK(get_options, mock_get_options);

  tt_int_op(dns_resolver_validation_delegation_request(dns_conn), OP_EQ, 0);

  tt_uint_op(validation->action , OP_EQ, VALIDATION_ACTION_APEX_KEYS);
  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_str_op(dns_name_str(lookup->qname), OP_EQ, zone);
  tt_uint_op(lookup->qtype, OP_EQ, DNS_TYPE_DNSKEY);
  tt_int_op(buf_datalen(ENTRY_TO_CONN(dns_conn)->inbuf), OP_EQ, 31);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);

  dns_rr_free(trust_anchor);
  smartlist_free(mock_options->DNSResolverTrustAnchors);
  tor_free(mock_options);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_validation_delegation_response_is_valid(void *arg)
{
  (void) arg;

  const char *zone = "example.com";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  validation_t *validation = dns_conn->dns_lookup->validation;
  validation->action = VALIDATION_ACTION_DELEGATION;

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of(zone);
  question->qtype = dns_type_of(DNS_TYPE_DS);

  dns_rr_t *ds_rr = dns_rr_new();
  ds_rr->rrtype = dns_type_of(DNS_TYPE_DS);
  ds_rr->validation_state = DNSSEC_VALIDATION_STATE_SECURE;

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);
  smartlist_add(resp->answer_list, ds_rr);

  MOCK(dnssec_authenticate_rrset, mock_dnssec_authenticate_rrset_ok);

  tt_int_op(dns_resolver_validation_delegation_response(dns_conn, resp),
            OP_EQ, 0);

  tt_uint_op(validation->action, OP_EQ, VALIDATION_ACTION_APEX_KEYS);
  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_int_op(smartlist_len(validation->delegation_signers), OP_EQ, 1);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  UNMOCK(dnssec_authenticate_rrset);

  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_validation_delegation_response_is_bogus(void *arg)
{
  (void) arg;

  const char *zone = "example.com";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  validation_t *validation = dns_conn->dns_lookup->validation;
  validation->action = VALIDATION_ACTION_DELEGATION;

  dns_rr_t *rr = dns_rr_new();
  rr->name = dns_name_of(zone);

  validation->active_zone = dns_name_of(zone);
  validation->message = dns_message_new();
  smartlist_add(validation->message->answer_list, rr);

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of(zone);
  question->qtype = dns_type_of(DNS_TYPE_DS);

  dns_rr_t *nsec_rr = dns_rr_new();
  nsec_rr->rrtype = dns_type_of(DNS_TYPE_NSEC);
  nsec_rr->validation_state = DNSSEC_VALIDATION_STATE_SECURE;

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);
  smartlist_add(resp->name_server_list, nsec_rr);

  MOCK(dnssec_authenticate_rrset, mock_dnssec_authenticate_rrset_ok);
  MOCK(dnssec_denial_of_existence, mock_dnssec_denial_of_existence_nxdomain);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_validation_delegation_response(dns_conn, resp),
            OP_EQ, -1);

  tt_uint_op(validation->action, OP_EQ, VALIDATION_ACTION_DELEGATION);
  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_int_op(smartlist_len(validation->delegation_signers), OP_EQ, 0);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);
  tt_int_op(rr->validation_state, OP_EQ, DNSSEC_VALIDATION_STATE_BOGUS);

 done:
  UNMOCK(dnssec_authenticate_rrset);
  UNMOCK(dnssec_denial_of_existence);
  UNMOCK(connection_mark_unattached_ap_);

  tor_free(validation->active_zone);
  dns_message_free(validation->message);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_validation_delegation_response_is_insecure(void *arg)
{
  (void) arg;

  const char *zone = "example.com";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  validation_t *validation = dns_conn->dns_lookup->validation;
  validation->action = VALIDATION_ACTION_DELEGATION;

  dns_rr_t *rr = dns_rr_new();
  rr->name = dns_name_of(zone);

  validation->active_zone = dns_name_of(zone);
  validation->message = dns_message_new();
  smartlist_add(validation->message->answer_list, rr);

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of(zone);
  question->qtype = dns_type_of(DNS_TYPE_DS);

  dns_rr_t *nsec_rr = dns_rr_new();
  nsec_rr->rrtype = dns_type_of(DNS_TYPE_NSEC);
  nsec_rr->validation_state = DNSSEC_VALIDATION_STATE_SECURE;

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);
  smartlist_add(resp->name_server_list, nsec_rr);

  MOCK(dnssec_authenticate_rrset, mock_dnssec_authenticate_rrset_ok);
  MOCK(dnssec_denial_of_existence, mock_dnssec_denial_of_existence_optout);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_validation_delegation_response(dns_conn, resp),
            OP_EQ, -1);

  tt_uint_op(validation->action, OP_EQ, VALIDATION_ACTION_DELEGATION);
  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_int_op(smartlist_len(validation->delegation_signers), OP_EQ, 0);
  tt_int_op(rr->validation_state, OP_EQ, DNSSEC_VALIDATION_STATE_INSECURE);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(dnssec_authenticate_rrset);
  UNMOCK(dnssec_denial_of_existence);
  UNMOCK(connection_mark_unattached_ap_);

  tor_free(validation->active_zone);
  dns_message_free(validation->message);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_validation_delegation_response_has_invalid_type(void *arg)
{
  (void) arg;

  const char *zone = "example.com";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  validation_t *validation = dns_conn->dns_lookup->validation;
  validation->action = VALIDATION_ACTION_DELEGATION;

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of(zone);
  question->qtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);

  MOCK(dnssec_authenticate_rrset, mock_dnssec_authenticate_rrset_ok);

  tt_int_op(dns_resolver_validation_delegation_response(dns_conn, resp),
            OP_EQ, -1);

  tt_uint_op(validation->action, OP_EQ, VALIDATION_ACTION_DELEGATION);
  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_int_op(smartlist_len(validation->delegation_signers), OP_EQ, 0);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(dnssec_authenticate_rrset);

  dns_message_free(resp);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_validation_zone_cut_request_send_query_succeedes(void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection("com.");
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;

  validation->action = VALIDATION_ACTION_APEX_KEYS;
  validation->zones = smartlist_new();
  smartlist_add(validation->zones, dns_name_of(zone));

  tt_int_op(dns_resolver_validation_zone_cut_request(dns_conn), OP_EQ, 0);

  tt_uint_op(validation->action , OP_EQ, VALIDATION_ACTION_ZONE_CUT);
  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_str_op(dns_name_str(lookup->qname), OP_EQ, zone);
  tt_uint_op(lookup->qtype, OP_EQ, DNS_TYPE_NS);
  tt_int_op(buf_datalen(ENTRY_TO_CONN(dns_conn)->inbuf), OP_EQ, 31);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_validation_zone_cut_request_send_query_fails(void *arg)
{
  (void) arg;

  const char *zone = "abcd012345678901234567890123456789012345678901234567890"
                     "123456789.example.com.";

  entry_connection_t *dns_conn = setup_dns_connection("com.");
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;

  validation->action = VALIDATION_ACTION_APEX_KEYS;
  validation->message = dns_message_new();
  validation->zones = smartlist_new();
  smartlist_add(validation->zones, dns_name_of(zone));

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverDNSSECMode = DNSSEC_MODE_VALIDATE;

  MOCK(get_options, mock_get_options);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_validation_zone_cut_request(dns_conn), OP_EQ, -1);

  tt_uint_op(validation->action , OP_EQ, VALIDATION_ACTION_ZONE_CUT);
  tt_int_op(validation->message->header->rcode, OP_EQ, DNS_RCODE_SERVFAIL);
  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_str_op(dns_name_str(lookup->qname), OP_EQ, zone);
  tt_uint_op(lookup->qtype, OP_EQ, DNS_TYPE_NS);
  tt_int_op(buf_datalen(ENTRY_TO_CONN(dns_conn)->inbuf), OP_EQ, 0);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_mark_unattached_ap_);

  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
  tor_free(mock_options);
}

static void
test_dns_resolver_validation_zone_cut_request_is_cached(void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection("com.");
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;

  validation->action = VALIDATION_ACTION_APEX_KEYS;
  validation->zones = smartlist_new();
  smartlist_add(validation->zones, dns_name_of(zone));
  validation->message = dns_message_new();

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of(zone);
  question->qtype = dns_type_of(DNS_TYPE_NS);

  dns_message_t *message = dns_message_new();
  smartlist_add(message->question_list, question);
  message->header->qdcount = smartlist_len(message->question_list);

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;

  MOCK(get_options, mock_get_options);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  dns_resolver_cache_add_message(message);

  tt_int_op(dns_resolver_validation_zone_cut_request(dns_conn), OP_EQ, -1);

  tt_uint_op(validation->action , OP_EQ, VALIDATION_ACTION_ZONE_CUT);
  tt_ptr_op(validation->active_child, OP_EQ, NULL);
  tt_ptr_op(lookup->qname, OP_EQ, NULL);
  tt_uint_op(lookup->qtype, OP_EQ, 0);
  tt_int_op(buf_datalen(ENTRY_TO_CONN(dns_conn)->inbuf), OP_EQ, 0);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  UNMOCK(get_options);
  UNMOCK(connection_mark_unattached_ap_);

  tor_free(mock_options);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
  dns_message_free(message);
}

static void
test_dns_resolver_validation_zone_cut_request_conclude_chain(void *arg)
{
  (void) arg;

  const char *zone = "example.com.";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  validation_t *validation = lookup->validation;

  validation->action = VALIDATION_ACTION_APEX_KEYS;
  validation->message = dns_message_new();
  smartlist_add(validation->completed, dns_name_of(zone));

  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_validation_zone_cut_request(dns_conn), OP_EQ, -1);

  tt_uint_op(validation->action , OP_EQ, VALIDATION_ACTION_ZONE_CUT);
  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_str_op(dns_name_str(lookup->qname), OP_EQ, "");
  tt_uint_op(lookup->qtype, OP_EQ, 0);
  tt_int_op(buf_datalen(ENTRY_TO_CONN(dns_conn)->inbuf), OP_EQ, 0);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(connection_mark_unattached_ap_);

  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_validation_zone_cut_response_indicates_zone_cut(void *arg)
{
  (void) arg;

  const char *zone = "example.com";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  validation_t *validation = dns_conn->dns_lookup->validation;
  validation->action = VALIDATION_ACTION_ZONE_CUT;

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of(zone);
  question->qtype = dns_type_of(DNS_TYPE_NS);

  dns_rr_t *rr = dns_rr_new();
  rr->rrtype = dns_type_of(DNS_TYPE_NS);

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);
  smartlist_add(resp->answer_list, rr);

  tt_int_op(dns_resolver_validation_zone_cut_response(dns_conn, resp),
            OP_EQ, 0);

  tt_uint_op(validation->action, OP_EQ, VALIDATION_ACTION_DELEGATION);
  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_validation_zone_cut_response_is_not_zone_cut(void *arg)
{
  (void) arg;

  const char *zone = "example.com";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  validation_t *validation = dns_conn->dns_lookup->validation;

  validation->action = VALIDATION_ACTION_ZONE_CUT;
  validation->message = dns_message_new();

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of(zone);
  question->qtype = dns_type_of(DNS_TYPE_NS);

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);

  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  tt_int_op(dns_resolver_validation_zone_cut_response(dns_conn, resp),
            OP_EQ, -1);

  tt_uint_op(validation->action, OP_EQ, VALIDATION_ACTION_ZONE_CUT);
  tt_ptr_op(validation->active_child, OP_EQ, NULL);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  UNMOCK(connection_mark_unattached_ap_);

  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_validation_zone_cut_response_has_invalid_type(void *arg)
{
  (void) arg;

  const char *zone = "example.com";

  entry_connection_t *dns_conn = setup_dns_connection(zone);
  validation_t *validation = dns_conn->dns_lookup->validation;
  validation->action = VALIDATION_ACTION_ZONE_CUT;

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of(zone);
  question->qtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);

  tt_int_op(dns_resolver_validation_zone_cut_response(dns_conn, resp),
            OP_EQ, -1);

  tt_uint_op(validation->action, OP_EQ, VALIDATION_ACTION_ZONE_CUT);
  tt_str_op(dns_name_str(validation->active_child), OP_EQ, zone);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  dns_message_free(resp);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

#endif /* defined(ENABLE_OPENSSL) */

static void
test_dns_resolver_validation_update_state(void *arg)
{
  (void) arg;

  const char *zone = "example.";

  dns_rr_t *an_rr = dns_rr_new();
  an_rr->name = dns_name_of(zone);
  an_rr->validation_state = DNSSEC_VALIDATION_STATE_INDETERMINATE;

  dns_rr_t *ns_rr = dns_rr_new();
  ns_rr->name = dns_name_of(zone);
  ns_rr->validation_state = DNSSEC_VALIDATION_STATE_INDETERMINATE;

  dns_message_t *message = dns_message_new();
  smartlist_add(message->answer_list, an_rr);
  smartlist_add(message->name_server_list, ns_rr);

  validation_t *validation = validation_new();
  validation->active_zone = dns_name_of(zone);
  validation->message = message;

  dns_resolver_validation_update_state(validation,
                                       DNSSEC_VALIDATION_STATE_BOGUS);

  tt_int_op(an_rr->validation_state, OP_EQ, DNSSEC_VALIDATION_STATE_BOGUS);
  tt_int_op(ns_rr->validation_state, OP_EQ, DNSSEC_VALIDATION_STATE_BOGUS);

  dns_name_free(validation->active_zone);
  validation->active_zone = dns_name_of("unknown.name.");

  dns_resolver_validation_update_state(validation,
                                       DNSSEC_VALIDATION_STATE_SECURE);

  tt_int_op(an_rr->validation_state, OP_EQ, DNSSEC_VALIDATION_STATE_BOGUS);
  tt_int_op(ns_rr->validation_state, OP_EQ, DNSSEC_VALIDATION_STATE_BOGUS);

 done:
  dns_name_free(validation->active_zone);
  validation_free(validation);
}

static void
test_dns_resolver_resolve_socks_address_ipv4(void *arg)
{
  (void) arg;

  entry_connection_t *ap_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  strlcpy(ap_conn->socks_request->address, "example.com",
          sizeof(ap_conn->socks_request->address));

  dns_rr_t *rr = dns_rr_new();
  rr->rrtype = dns_type_of(DNS_TYPE_A);
  rr->a = tor_strdup("1.2.3.4");

  dns_message_t *message = dns_message_new();
  smartlist_add(message->answer_list, rr);

  MOCK(connection_ap_rewrite_and_attach_if_allowed,
       mock_connection_ap_rewrite_and_attach_if_allowed_ok);

  tt_int_op(dns_resolver_resolve_socks_address(ap_conn, message), OP_EQ, 0);
  tt_str_op(ap_conn->original_dest_address, OP_EQ, "example.com");
  tt_str_op(ap_conn->socks_request->address, OP_EQ, "1.2.3.4");

 done:
  UNMOCK(connection_ap_rewrite_and_attach_if_allowed);

  connection_free_minimal(ENTRY_TO_CONN(ap_conn));
}

static void
test_dns_resolver_complete_server_request_forward(void *arg)
{
  (void) arg;

  struct evdns_server_request *req = tor_malloc_zero(
                                       sizeof(struct evdns_server_request));

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  lookup->server_request = req;

  mock_evdns_responds = 0;

  MOCK(dns_resolver_evdns_wrapper_add_reply,
       mock_dns_resolver_evdns_wrapper_add_reply);
  MOCK(dns_resolver_evdns_wrapper_respond,
       mock_dns_resolver_evdns_wrapper_respond);
  MOCK(connection_mark_unattached_ap_, mock_connection_mark_unattached_ap_ok);

  dns_message_t *resp1 = dns_message_new();
  tt_int_op(dns_resolver_complete_server_request_forward(dns_conn, resp1),
            OP_EQ, 0);
  tt_int_op(mock_evdns_responds, OP_EQ, 1);
  tt_ptr_op(lookup->server_request, OP_EQ, NULL);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

  dns_message_t *resp2 = dns_message_new();
  tt_int_op(dns_resolver_complete_server_request_forward(dns_conn, resp2),
            OP_EQ, -1);
  tt_int_op(mock_evdns_responds, OP_EQ, 1);
  tt_ptr_op(lookup->server_request, OP_EQ, NULL);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(dns_resolver_evdns_wrapper_add_reply);
  UNMOCK(dns_resolver_evdns_wrapper_respond);
  UNMOCK(connection_mark_unattached_ap_);

  tor_free(req);
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_resolve_server_request_successful_response(void *arg)
{
  (void) arg;

  struct evdns_server_request *req = tor_malloc_zero(
                                       sizeof(struct evdns_server_request));

  dns_message_t *message = dns_message_new();
  message->header->rcode = DNS_RCODE_NOERROR;
  smartlist_add(message->answer_list, dns_rr_new());
  smartlist_add(message->name_server_list, dns_rr_new());
  smartlist_add(message->additional_record_list, dns_rr_new());

  mock_evdns_answer_replies = 0;
  mock_evdns_authority_replies = 0;
  mock_evdns_responds = 0;

  MOCK(dns_resolver_evdns_wrapper_add_reply,
       mock_dns_resolver_evdns_wrapper_add_reply);
  MOCK(dns_resolver_evdns_wrapper_respond,
       mock_dns_resolver_evdns_wrapper_respond);

  tt_int_op(dns_resolver_resolve_server_request(req, message),
            OP_EQ, 0);
  tt_int_op(mock_evdns_answer_replies, OP_EQ, 1);
  tt_int_op(mock_evdns_authority_replies, OP_EQ, 1);
  tt_int_op(mock_evdns_responds, OP_EQ, 1);

 done:
  UNMOCK(dns_resolver_evdns_wrapper_add_reply);
  UNMOCK(dns_resolver_evdns_wrapper_respond);

  tor_free(req);
}

static void
test_dns_resolver_resolve_server_request_unsuccessful_response(void *arg)
{
  (void) arg;

  struct evdns_server_request *req = tor_malloc_zero(
                                       sizeof(struct evdns_server_request));

  dns_message_t *message = dns_message_new();
  message->header->rcode = DNS_RCODE_SERVFAIL;
  smartlist_add(message->answer_list, dns_rr_new());
  smartlist_add(message->name_server_list, dns_rr_new());
  smartlist_add(message->additional_record_list, dns_rr_new());

  mock_evdns_answer_replies = 0;
  mock_evdns_authority_replies = 0;
  mock_evdns_responds = 0;

  MOCK(dns_resolver_evdns_wrapper_add_reply,
       mock_dns_resolver_evdns_wrapper_add_reply);
  MOCK(dns_resolver_evdns_wrapper_respond,
       mock_dns_resolver_evdns_wrapper_respond);

  tt_int_op(dns_resolver_resolve_server_request(req, message),
            OP_EQ, 0);
  tt_int_op(mock_evdns_answer_replies, OP_EQ, 0);
  tt_int_op(mock_evdns_authority_replies, OP_EQ, 0);
  tt_int_op(mock_evdns_responds, OP_EQ, 1);

 done:
  UNMOCK(dns_resolver_evdns_wrapper_add_reply);
  UNMOCK(dns_resolver_evdns_wrapper_respond);

  tor_free(req);
}

static void
test_dns_resolver_resolve_server_request_already_resolved(void *arg)
{
  (void) arg;

  dns_message_t *message = dns_message_new();
  message->header->rcode = DNS_RCODE_NOERROR;
  smartlist_add(message->answer_list, dns_rr_new());
  smartlist_add(message->name_server_list, dns_rr_new());
  smartlist_add(message->additional_record_list, dns_rr_new());

  mock_evdns_answer_replies = 0;
  mock_evdns_authority_replies = 0;
  mock_evdns_responds = 0;

  MOCK(dns_resolver_evdns_wrapper_add_reply,
       mock_dns_resolver_evdns_wrapper_add_reply);
  MOCK(dns_resolver_evdns_wrapper_respond,
       mock_dns_resolver_evdns_wrapper_respond);

  tt_int_op(dns_resolver_resolve_server_request(NULL, message),
            OP_EQ, -1);
  tt_int_op(mock_evdns_answer_replies, OP_EQ, 0);
  tt_int_op(mock_evdns_authority_replies, OP_EQ, 0);
  tt_int_op(mock_evdns_responds, OP_EQ, 0);

 done:
  UNMOCK(dns_resolver_evdns_wrapper_add_reply);
  UNMOCK(dns_resolver_evdns_wrapper_respond);
}

static void
test_dns_resolver_complete_socks_address_resolution_fallback(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("example.com");

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverIPv4 = 1;
  mock_options->DNSResolverIPv6 = 1;
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;

  entry_connection_t *ap_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  lookup->action = DNS_LOOKUP_ACTION_VALIDATE;
  lookup->qname = dns_name_dup(qname);
  lookup->qtype = DNS_TYPE_AAAA;
  lookup->ap_conn = ap_conn;

  // Make sure that no action is performed within connection_edge_process_inbuf
  ENTRY_TO_CONN(dns_conn)->state = AP_CONN_STATE_CIRCUIT_WAIT;

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_dup(qname);
  question->qtype = dns_type_of(DNS_TYPE_AAAA);

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);

  MOCK(get_options, mock_get_options);

  tt_int_op(dns_resolver_complete_socks_address_resolution(dns_conn, resp),
            OP_EQ, 0);
  tt_uint_op(lookup->action, OP_EQ, DNS_LOOKUP_ACTION_RESOLVE);
  tt_uint_op(lookup->qtype, OP_EQ, DNS_TYPE_A);
  tt_ptr_op(lookup->validation, OP_EQ, NULL);
  tt_ptr_op(lookup->ap_conn, OP_NE, NULL);
  tt_int_op(buf_datalen(ENTRY_TO_CONN(dns_conn)->inbuf), OP_EQ, 31);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  UNMOCK(get_options);

  tor_free(mock_options);
  dns_name_free(qname);
  connection_free_minimal(ENTRY_TO_CONN(ap_conn));
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_complete_socks_address_resolution_resolve(void *arg)
{
  (void) arg;

  entry_connection_t *ap_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();
  dns_lookup_t *lookup = dns_conn->dns_lookup;
  lookup->ap_conn = ap_conn;

  MOCK(connection_ap_rewrite_and_attach_if_allowed,
       mock_connection_ap_rewrite_and_attach_if_allowed_ok);

  dns_message_t *resp1 = dns_message_new();
  tt_int_op(dns_resolver_complete_socks_address_resolution(dns_conn, resp1),
            OP_EQ, 0);
  tt_ptr_op(lookup->ap_conn, OP_EQ, NULL);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

  dns_message_t *resp2 = dns_message_new();
  tt_int_op(dns_resolver_complete_socks_address_resolution(dns_conn, resp2),
            OP_EQ, -1);
  tt_ptr_op(lookup->ap_conn, OP_EQ, NULL);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(connection_ap_rewrite_and_attach_if_allowed);

  connection_free_minimal(ENTRY_TO_CONN(ap_conn));
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_resolve_socks_address_ipv6(void *arg)
{
  (void) arg;

  entry_connection_t *ap_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  strlcpy(ap_conn->socks_request->address, "example.com",
          sizeof(ap_conn->socks_request->address));

  dns_rr_t *rr = dns_rr_new();
  rr->rrtype = dns_type_of(DNS_TYPE_AAAA);
  rr->aaaa = tor_strdup("2::3:0:0:4");

  dns_message_t *message = dns_message_new();
  smartlist_add(message->answer_list, rr);

  MOCK(connection_ap_rewrite_and_attach_if_allowed,
       mock_connection_ap_rewrite_and_attach_if_allowed_ok);

  tt_int_op(dns_resolver_resolve_socks_address(ap_conn, message), OP_EQ, 0);
  tt_str_op(ap_conn->original_dest_address, OP_EQ, "example.com");
  tt_str_op(ap_conn->socks_request->address, OP_EQ, "[2::3:0:0:4]");

 done:
  UNMOCK(connection_ap_rewrite_and_attach_if_allowed);

  connection_free_minimal(ENTRY_TO_CONN(ap_conn));
}

static void
test_dns_resolver_resolve_socks_address_onion(void *arg)
{
  (void) arg;

  const char *onion_address = "expyuzz4wqqyqhjn.onion";

  entry_connection_t *ap_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  strlcpy(ap_conn->socks_request->address, "example.com",
          sizeof(ap_conn->socks_request->address));

  dns_rr_t *rr = dns_rr_new();
  rr->rrtype = dns_type_of(DNS_TYPE_KEY);
  rr->key = dns_key_new();
  rr->key->protocol = DNS_KEY_PROTO_ONION;

  size_t onion_address_len = strlen(onion_address) - 6;
  rr->key->public_key = tor_malloc_zero(
                          base64_decode_maxsize(onion_address_len));
  rr->key->public_key_len = base64_decode_maxsize(onion_address_len);

  base64_decode((char *)rr->key->public_key, rr->key->public_key_len,
                onion_address, onion_address_len);

  dns_message_t *message = dns_message_new();
  smartlist_add(message->answer_list, rr);

  MOCK(connection_ap_rewrite_and_attach_if_allowed,
       mock_connection_ap_rewrite_and_attach_if_allowed_ok);

  tt_int_op(dns_resolver_resolve_socks_address(ap_conn, message), OP_EQ, 0);
  tt_str_op(ap_conn->original_dest_address, OP_EQ, "example.com");
  tt_str_op(ap_conn->socks_request->address, OP_EQ, onion_address);

 done:
  UNMOCK(connection_ap_rewrite_and_attach_if_allowed);

  connection_free_minimal(ENTRY_TO_CONN(ap_conn));
}

static void
test_dns_resolver_resolve_socks_address_invalid_connection_type(void *arg)
{
  (void) arg;

  or_connection_t *or_conn = or_connection_new(CONN_TYPE_OR, AF_INET);

  dns_message_t *message = dns_message_new();

  tt_int_op(dns_resolver_resolve_socks_address((entry_connection_t*) or_conn,
                                               message), OP_EQ, -2);

 done:
  connection_free_minimal(TO_CONN(or_conn));
}

static void
test_dns_resolver_resolve_socks_address_already_resolved(void *arg)
{
  (void) arg;

  dns_message_t *message = dns_message_new();

  tt_int_op(dns_resolver_resolve_socks_address(NULL, message), OP_EQ, -1);

 done:
  (void) 0;
}

static void
test_dns_resolver_resolve_socks_address_get_answers_ipv4(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();
  rr->rrtype = dns_type_of(DNS_TYPE_A);
  rr->a = tor_strdup("1.2.3.4");

  dns_message_t *message = dns_message_new();
  smartlist_add(message->answer_list, rr);

  smartlist_t *answers =
    dns_resolver_resolve_socks_address_get_answers(message);

  tt_int_op(smartlist_len(answers), OP_EQ, 1);

 done:
  dns_message_free(message);
  smartlist_free(answers);
}

static void
test_dns_resolver_resolve_socks_address_get_answers_ipv6(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();
  rr->rrtype = dns_type_of(DNS_TYPE_AAAA);
  rr->aaaa = tor_strdup("2::3:0:0:4");

  dns_message_t *message = dns_message_new();
  smartlist_add(message->answer_list, rr);

  smartlist_t *answers =
    dns_resolver_resolve_socks_address_get_answers(message);

  tt_int_op(smartlist_len(answers), OP_EQ, 1);

 done:
  dns_message_free(message);
  smartlist_free(answers);
}

static void
test_dns_resolver_resolve_socks_address_get_answers_onion(void *arg)
{
  (void) arg;

  uint8_t public_key[2] = {0x01, 0x02};

  dns_rr_t *rr = dns_rr_new();
  rr->rrtype = dns_type_of(DNS_TYPE_KEY);
  rr->key = dns_key_new();
  rr->key->protocol = DNS_KEY_PROTO_ONION;
  rr->key->public_key = tor_memdup(public_key, 2);
  rr->key->public_key_len = 2;

  dns_message_t *message = dns_message_new();
  smartlist_add(message->answer_list, rr);

  smartlist_t *answers =
    dns_resolver_resolve_socks_address_get_answers(message);

  tt_int_op(smartlist_len(answers), OP_EQ, 1);

 done:
  dns_message_free(message);
  smartlist_free(answers);
}

static void
test_dns_resolver_resolve_socks_address_get_answers_cached_v2(void *arg)
{
  (void) arg;

  rend_cache_init();

  rend_encoded_v2_service_descriptor_t *desc_holder = NULL;
  char *service_id = NULL;
  rend_data_t *rend_query = NULL;
  char desc_id_base32[REND_DESC_ID_V2_LEN_BASE32 + 1];

  generate_desc(-10, &desc_holder, &service_id, 2);

  rend_query = mock_rend_data(service_id);
  base32_encode(desc_id_base32, sizeof(desc_id_base32), desc_holder->desc_id,
                DIGEST_LEN);
  rend_cache_store_v2_desc_as_client(desc_holder->desc_str, desc_id_base32,
                                     rend_query, NULL);

  dns_rr_t *rr = dns_rr_new();
  rr->rrtype = dns_type_of(DNS_TYPE_KEY);
  rr->key = dns_key_new();
  rr->key->protocol = DNS_KEY_PROTO_ONION;

  dns_rr_t *cached_rr = dns_rr_new();
  cached_rr->rrtype = dns_type_of(DNS_TYPE_KEY);
  cached_rr->key = dns_key_new();
  cached_rr->key->protocol = DNS_KEY_PROTO_ONION;
  cached_rr->key->algorithm = DNS_KEY_ALG_HSV2;

  size_t service_id_len = strlen(service_id);
  cached_rr->key->public_key = tor_malloc_zero(
                                 base64_decode_maxsize(service_id_len));
  cached_rr->key->public_key_len = base64_decode_maxsize(service_id_len);

  base64_decode((char *)cached_rr->key->public_key,
                cached_rr->key->public_key_len, service_id, service_id_len);

  dns_message_t *message = dns_message_new();
  smartlist_add(message->answer_list, rr);
  smartlist_add(message->answer_list, cached_rr);

  smartlist_t *answers =
    dns_resolver_resolve_socks_address_get_answers(message);

  tt_int_op(smartlist_len(answers), OP_EQ, 1);

 done:
  rend_encoded_v2_service_descriptor_free(desc_holder);
  tor_free(service_id);
  rend_cache_free_all();
  rend_data_free(rend_query);

  dns_message_free(message);
  smartlist_free(answers);
}

static void
test_dns_resolver_resolve_socks_address_get_answers_cached_v3(void *arg)
{
  (void) arg;

  hs_cache_init();

  MOCK(networkstatus_get_live_consensus,
       mock_networkstatus_get_live_consensus);

  parse_rfc1123_time("Sat, 26 Oct 1985 13:00:00 UTC", &mock_ns.valid_after);
  parse_rfc1123_time("Sat, 26 Oct 1985 14:00:00 UTC", &mock_ns.fresh_until);
  parse_rfc1123_time("Sat, 26 Oct 1985 16:00:00 UTC", &mock_ns.valid_until);

  char service_id[HS_SERVICE_ADDR_LEN_BASE32 + 1];
  ed25519_keypair_t service_kp;
  hs_descriptor_t *desc = NULL;
  char *encoded = NULL;

  ed25519_keypair_generate(&service_kp, 0);
  desc = hs_helper_build_hs_desc_with_ip(&service_kp);

  hs_build_address(&service_kp.pubkey, HS_VERSION_THREE, service_id);
  hs_desc_encode_descriptor(desc, &service_kp, NULL, &encoded);
  hs_cache_store_as_client(encoded, &service_kp.pubkey);

  dns_rr_t *rr = dns_rr_new();
  rr->rrtype = dns_type_of(DNS_TYPE_KEY);
  rr->key = dns_key_new();
  rr->key->protocol = DNS_KEY_PROTO_ONION;

  dns_rr_t *cached_rr = dns_rr_new();
  cached_rr->rrtype = dns_type_of(DNS_TYPE_KEY);
  cached_rr->key = dns_key_new();
  cached_rr->key->protocol = DNS_KEY_PROTO_ONION;
  cached_rr->key->algorithm = DNS_KEY_ALG_HSV3;

  size_t service_id_len = strlen(service_id);
  cached_rr->key->public_key = tor_malloc_zero(
                                 base64_decode_maxsize(service_id_len));
  cached_rr->key->public_key_len = base64_decode_maxsize(service_id_len);

  base64_decode((char *)cached_rr->key->public_key,
                cached_rr->key->public_key_len, service_id, service_id_len);

  dns_message_t *message = dns_message_new();
  smartlist_add(message->answer_list, rr);
  smartlist_add(message->answer_list, cached_rr);

  smartlist_t *answers =
    dns_resolver_resolve_socks_address_get_answers(message);

  tt_int_op(smartlist_len(answers), OP_EQ, 1);

 done:
  UNMOCK(networkstatus_get_live_consensus);

  hs_cache_free_all();
  hs_descriptor_free(desc);
  tor_free(encoded);

  dns_message_free(message);
  smartlist_free(answers);
}

static void
test_dns_resolver_resolve_socks_address_get_answers_when_failure(void *arg)
{
  (void) arg;

  dns_rr_t *rr = dns_rr_new();
  rr->rrtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *message = dns_message_new();
  message->header->rcode = DNS_RCODE_NXDOMAIN;
  smartlist_add(message->answer_list, rr);

  smartlist_t *answers =
    dns_resolver_resolve_socks_address_get_answers(message);

  tt_int_op(smartlist_len(answers), OP_EQ, 0);

 done:
  dns_message_free(message);
  smartlist_free(answers);
}

static void
test_dns_resolver_choose_nameserver_to_ping(void *arg)
{
  (void) arg;

  nameserver_t *ns1 = nameserver_new();

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverNameservers = smartlist_new();

  MOCK(get_options, mock_get_options);

  tt_ptr_op(dns_resolver_choose_nameserver_to_ping(), OP_EQ, NULL);

  smartlist_add(mock_options->DNSResolverNameservers, ns1);
  tt_ptr_op(dns_resolver_choose_nameserver_to_ping(), OP_EQ, ns1);

 done:
  UNMOCK(get_options);

  nameserver_free(ns1);
  smartlist_free(mock_options->DNSResolverNameservers);
  tor_free(mock_options);
}

static void
test_dns_resolver_backoff_nameserver(void *arg)
{
  (void) arg;

  nameserver_t *nameserver = nameserver_new();

  tt_int_op(dns_resolver_backoff_nameserver(nameserver), OP_EQ, 0);
  tt_int_op(dns_resolver_backoff_nameserver(nameserver), OP_EQ, 1);

 done:
  nameserver_free(nameserver);
}

static void
test_dns_resolver_choose_nameserver_for_lookup(void *arg)
{
  (void) arg;

  smartlist_t *root_nameservers = smartlist_new();

  nameserver_t *ns1 = nameserver_new();
  ns1->latency = 2;

  nameserver_t *ns2 = nameserver_new();
  ns2->latency = 1;

  smartlist_t *com_nameservers = smartlist_new();
  smartlist_add(com_nameservers, ns1);
  smartlist_add(com_nameservers, ns2);

  smartlist_t *org_nameservers = smartlist_new();
  smartlist_add(org_nameservers, ns1);

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverNameserverZoneMap = strmap_new();

  dns_lookup_t *lookup = dns_lookup_new();
  lookup->qname = dns_name_of("example.com");

  MOCK(get_options, mock_get_options);

  nameserver_t *none_available = dns_resolver_choose_nameserver_for_lookup(
                                                                       lookup);

  strmap_set(mock_options->DNSResolverNameserverZoneMap, ".",
             root_nameservers);
  strmap_set(mock_options->DNSResolverNameserverZoneMap, "org.",
             org_nameservers);

  nameserver_t *none_in_zone = dns_resolver_choose_nameserver_for_lookup(
                                                                       lookup);

  strmap_set(mock_options->DNSResolverNameserverZoneMap, "com.",
             com_nameservers);

  nameserver_t *expect_ns2 = dns_resolver_choose_nameserver_for_lookup(lookup);

  tt_ptr_op(none_available, OP_EQ, NULL);
  tt_ptr_op(none_in_zone, OP_EQ, NULL);
  tt_ptr_op(expect_ns2, OP_EQ, ns2);

 done:
  UNMOCK(get_options);

  nameserver_free(ns1);
  nameserver_free(ns2);
  smartlist_free(root_nameservers);
  smartlist_free(com_nameservers);
  smartlist_free(org_nameservers);
  strmap_free(mock_options->DNSResolverNameserverZoneMap, NULL);
  tor_free(mock_options);
  dns_lookup_free(lookup);
}

static void
test_dns_resolver_assign_nameserver(void *arg)
{
  (void) arg;

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();

  nameserver_t *nameserver = nameserver_new();
  nameserver->hostname = tor_strdup("1.2.3.4");
  nameserver->port = 53;

  dns_resolver_assign_nameserver(dns_conn, nameserver);

  tt_ptr_op(dns_conn->dns_lookup->nameserver, OP_EQ, nameserver);
  tt_int_op(dns_conn->socks_request->command, OP_EQ, SOCKS_COMMAND_CONNECT);
  tt_str_op(dns_conn->socks_request->address, OP_EQ, "1.2.3.4");
  tt_int_op(dns_conn->socks_request->port, OP_EQ, 53);
  tt_int_op(dns_conn->socks_request->has_finished, OP_EQ, 1);

 done:
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
  nameserver_free(nameserver);
}

static const char *
nameserver_hostname(smartlist_t *list, int idx)
{
  tor_assert(list);
  tor_assert(smartlist_get(list, idx));
  return ((nameserver_t *) smartlist_get(list, idx))->hostname;
}

static uint16_t
nameserver_port(smartlist_t *list, int idx)
{
  tor_assert(list);
  tor_assert(smartlist_get(list, idx));
  return ((nameserver_t *) smartlist_get(list, idx))->port;
}

static int
nameserver_zone_len(smartlist_t *list, int idx)
{
  tor_assert(list);
  tor_assert(smartlist_get(list, idx));
  return smartlist_len(((nameserver_t *) smartlist_get(list, idx))->zones);
}

static void
test_dns_resolver_nameserver_create_list(void *arg)
{
  (void) arg;

  smartlist_t *nameserver_lines = smartlist_new();
  smartlist_add(nameserver_lines, (char *) "4.5.6.7");
  smartlist_add(nameserver_lines, (char *) "4.5.6.7:9053");
  smartlist_add(nameserver_lines, (char *) "1.2.3.4 . CoM nET.");
  smartlist_add(nameserver_lines, (char *) "1.2.3.4:9053 CoM nET.");
  smartlist_add(nameserver_lines, (char *) "[::1]:9053 com.");

  nameserver_t *ns1 = nameserver_new();
  ns1->hostname = tor_strdup("1.2.3.4");
  ns1->port = 53;
  smartlist_add(ns1->zones, dns_name_of("."));
  smartlist_add(ns1->zones, dns_name_of("com."));
  smartlist_add(ns1->zones, dns_name_of("net."));

  smartlist_t *nameservers = smartlist_new();
  smartlist_add(nameservers, ns1);

  smartlist_t *list = dns_resolver_nameserver_create_list(nameserver_lines,
                                                          nameservers);

  tt_int_op(smartlist_len(list), OP_EQ, 5);

  tt_str_op(nameserver_hostname(list, 0), OP_EQ, "4.5.6.7");
  tt_str_op(nameserver_hostname(list, 1), OP_EQ, "4.5.6.7");
  tt_str_op(nameserver_hostname(list, 2), OP_EQ, "1.2.3.4");
  tt_str_op(nameserver_hostname(list, 3), OP_EQ, "1.2.3.4");
  tt_str_op(nameserver_hostname(list, 4), OP_EQ, "[::1]");

  tt_int_op(nameserver_port(list, 0), OP_EQ, 53);
  tt_int_op(nameserver_port(list, 1), OP_EQ, 9053);
  tt_int_op(nameserver_port(list, 2), OP_EQ, 53);
  tt_int_op(nameserver_port(list, 3), OP_EQ, 9053);
  tt_int_op(nameserver_port(list, 4), OP_EQ, 9053);

  tt_int_op(nameserver_zone_len(list, 0), OP_EQ, 1);
  tt_int_op(nameserver_zone_len(list, 1), OP_EQ, 1);
  tt_int_op(nameserver_zone_len(list, 2), OP_EQ, 3);
  tt_int_op(nameserver_zone_len(list, 3), OP_EQ, 2);
  tt_int_op(nameserver_zone_len(list, 4), OP_EQ, 1);

  tt_ptr_op(smartlist_get(list, 0), OP_NE, ns1);
  tt_ptr_op(smartlist_get(list, 1), OP_NE, ns1);
  tt_ptr_op(smartlist_get(list, 2), OP_EQ, ns1);
  tt_ptr_op(smartlist_get(list, 3), OP_NE, ns1);
  tt_ptr_op(smartlist_get(list, 4), OP_NE, ns1);

 done:
  SMARTLIST_FOREACH(list, nameserver_t *, nameserver,
                    nameserver_free(nameserver));
  smartlist_free(list);
  smartlist_free(nameservers);
  smartlist_free(nameserver_lines);
}

static void
test_dns_resolver_nameserver_create_list_without_servers(void *arg)
{
  (void) arg;

  smartlist_t *nameserver_lines = smartlist_new();
  smartlist_t *nameservers = smartlist_new();

  smartlist_t *list = dns_resolver_nameserver_create_list(nameserver_lines,
                                                          nameservers);

  tt_int_op(smartlist_len(list), OP_EQ, 0);

 done:
  smartlist_free(list);
  smartlist_free(nameservers);
  smartlist_free(nameserver_lines);
}

static void
test_dns_resolver_nameserver_find(void *arg)
{
  (void) arg;

  smartlist_t *empty_zones = smartlist_new();

  nameserver_t *ns1 = nameserver_new();
  ns1->hostname = tor_strdup("1.2.3.4");
  ns1->port = 53;
  smartlist_add(ns1->zones, dns_name_of("."));
  smartlist_add(ns1->zones, dns_name_of("com."));
  smartlist_add(ns1->zones, dns_name_of("net."));

  nameserver_t *ns2 = nameserver_new();
  ns2->hostname = tor_strdup("ns1.example.com");
  ns2->port = 53;
  smartlist_add(ns2->zones, dns_name_of("."));
  smartlist_add(ns2->zones, dns_name_of("net."));

  smartlist_t *nameservers = smartlist_new();
  smartlist_add(nameservers, ns1);
  smartlist_add(nameservers, ns2);

  tt_ptr_op(dns_resolver_nameserver_find(nameservers, ns1->zones,
            ns1->hostname, ns1->port), OP_EQ, ns1);
  tt_ptr_op(dns_resolver_nameserver_find(nameservers, ns1->zones,
            ns1->hostname, 123), OP_EQ, NULL);
  tt_ptr_op(dns_resolver_nameserver_find(nameservers, ns2->zones,
            ns2->hostname, ns2->port), OP_EQ, ns2);
  tt_ptr_op(dns_resolver_nameserver_find(nameservers, ns2->zones,
            "ns1.eXaMPle.com", ns2->port), OP_EQ, ns2);
  tt_ptr_op(dns_resolver_nameserver_find(nameservers, ns2->zones,
            "1.2.3.4", ns2->port), OP_EQ, NULL);
  tt_ptr_op(dns_resolver_nameserver_find(nameservers, empty_zones,
            ns2->hostname, ns2->port), OP_EQ, NULL);

 done:
  SMARTLIST_FOREACH(nameservers, nameserver_t *, nameserver,
                    nameserver_free(nameserver));
  smartlist_free(nameservers);
  smartlist_free(empty_zones);
}

static void
test_dns_resolver_nameserver_find_best_by_latency(void *arg)
{
  (void) arg;

  nameserver_t *ns1 = nameserver_new();
  ns1->latency = 2;

  nameserver_t *ns2 = nameserver_new();
  ns2->latency = 1;

  smartlist_t *nameservers = smartlist_new();
  smartlist_add(nameservers, ns1);
  smartlist_add(nameservers, ns2);

  nameserver_t *best =
    dns_resolver_nameserver_find_best_by_latency(nameservers);
  tt_ptr_op(best, OP_EQ, ns2);

 done:
  SMARTLIST_FOREACH(nameservers, nameserver_t *, nameserver,
                    nameserver_free(nameserver));
  smartlist_free(nameservers);
}

static void
test_dns_resolver_nameserver_free_outdated(void *arg)
{
  (void) arg;

  nameserver_t *ns1 = nameserver_new();
  ns1->hostname = tor_strdup("1.2.3.4");
  ns1->port = 53;

  nameserver_t *ns2 = nameserver_new();
  ns2->hostname = tor_strdup("5.6.7.8");
  ns2->port = 53;

  smartlist_t *old = smartlist_new();
  smartlist_add(old, ns1);
  smartlist_add(old, ns2);

  smartlist_t *new = smartlist_new();
  smartlist_add(new, ns1);

  dns_resolver_nameserver_free_outdated(old, new);

  tt_str_op(ns1->hostname, OP_EQ, "1.2.3.4");

 done:
  smartlist_free(old);
  smartlist_free(new);
  nameserver_free(ns1);
}

static void
test_dns_resolver_extract_server_and_zones(void *arg)
{
  (void) arg;

  char *server = NULL;
  smartlist_t *zones = smartlist_new();

  tt_int_op(dns_resolver_extract_server_and_zones(&server, zones,
            (char *) "ns1.example.com:9053 . com."), OP_EQ, 0);
  tt_str_op(server, OP_EQ, "ns1.example.com:9053");
  tt_int_op(smartlist_len(zones), OP_EQ, 2);

  tt_int_op(dns_resolver_extract_server_and_zones(&server, zones,
            (char *) "ns2.example.com"), OP_EQ, 0);
  tt_str_op(server, OP_EQ, "ns2.example.com");
  tt_int_op(smartlist_len(zones), OP_EQ, 1);

  tt_int_op(dns_resolver_extract_server_and_zones(&server, zones,
            (char *) ""), OP_EQ, -1);
  tt_str_op(server, OP_EQ, "ns2.example.com");
  tt_int_op(smartlist_len(zones), OP_EQ, 1);

 done:
  tor_free(server);
  SMARTLIST_FOREACH(zones, dns_name_t *, zone, dns_name_free(zone));
  smartlist_free(zones);
}

static void
test_dns_resolver_extract_hostname_and_port(void *arg)
{
  (void) arg;

  char *hostname = NULL;
  int port = 0;

  tt_int_op(dns_resolver_extract_hostname_and_port(&hostname, &port,
            (char *) "ns1.example.com:9053"), OP_EQ, 0);
  tt_str_op(hostname, OP_EQ, "ns1.example.com");
  tt_int_op(port, OP_EQ, 9053);

  tt_int_op(dns_resolver_extract_hostname_and_port(&hostname, &port,
            (char *) "ns2.example.com"), OP_EQ, 0);
  tt_str_op(hostname, OP_EQ, "ns2.example.com");
  tt_int_op(port, OP_EQ, 53);

  tt_int_op(dns_resolver_extract_hostname_and_port(&hostname, &port,
            (char *) ""), OP_EQ, -1);
  tt_str_op(hostname, OP_EQ, "ns2.example.com");
  tt_int_op(port, OP_EQ, 53);

  tt_int_op(dns_resolver_extract_hostname_and_port(&hostname, &port,
            (char *) ":abc"), OP_EQ, 0);
  tt_str_op(hostname, OP_EQ, "");
  tt_int_op(port, OP_EQ, 53);

  tt_int_op(dns_resolver_extract_hostname_and_port(&hostname, &port,
            (char *) "1.2.3.4:abc"), OP_EQ, 0);
  tt_str_op(hostname, OP_EQ, "1.2.3.4");
  tt_int_op(port, OP_EQ, 53);

  tt_int_op(dns_resolver_extract_hostname_and_port(&hostname, &port,
            (char *) "[::1]"), OP_EQ, 0);
  tt_str_op(hostname, OP_EQ, "[::1]");
  tt_int_op(port, OP_EQ, 53);

  tt_int_op(dns_resolver_extract_hostname_and_port(&hostname, &port,
            (char *) "[::2]:9053"), OP_EQ, 0);
  tt_str_op(hostname, OP_EQ, "[::2]");
  tt_int_op(port, OP_EQ, 9053);

  tt_int_op(dns_resolver_extract_hostname_and_port(&hostname, &port,
            (char *) "::1]"), OP_EQ, -2);
  tt_str_op(hostname, OP_EQ, "[::2]");
  tt_int_op(port, OP_EQ, 9053);

 done:
  tor_free(hostname);
}

static void
test_dns_resolver_lookup_setup_forward_query_succeeds(void *arg)
{
  (void) arg;

  const char *qname = "example.com";

  struct evdns_server_question *question =
    tor_malloc_zero(sizeof(struct evdns_server_question) + strlen(qname));
  memcpy(question->name, qname, strlen(qname) + 1);
  question->type = DNS_TYPE_A;

  struct evdns_server_request *req = tor_malloc_zero(
                                       sizeof(struct evdns_server_request));
  req->nquestions = 1;
  req->questions = &question;

  dns_lookup_t *lookup = dns_lookup_new();
  lookup->qname = dns_name_of("invalid");

  tt_int_op(dns_resolver_lookup_setup_forward_query(lookup, req), OP_EQ, 0);

  tt_int_op(lookup->action, OP_EQ, DNS_LOOKUP_ACTION_FORWARD);
  tt_str_op(dns_name_str(lookup->qname), OP_EQ, qname);
  tt_int_op(lookup->qtype, OP_EQ, DNS_TYPE_A);
  tt_ptr_op(lookup->server_request, OP_EQ, req);

 done:
  tor_free(question);
  tor_free(req);
  dns_lookup_free(lookup);
}

static void
test_dns_resolver_lookup_setup_forward_query_number_of_question(void *arg)
{
  (void) arg;

  const char *qname = "example.com";

  struct evdns_server_question *question =
    tor_malloc_zero(sizeof(struct evdns_server_question) + strlen(qname));
  memcpy(question->name, qname, strlen(qname) + 1);
  question->type = DNS_TYPE_A;

  struct evdns_server_request *req = tor_malloc_zero(
                                       sizeof(struct evdns_server_request));
  req->nquestions = 0;
  req->questions = &question;

  dns_lookup_t *lookup = dns_lookup_new();

  tt_int_op(dns_resolver_lookup_setup_forward_query(lookup, req), OP_EQ, -1);

 done:
  tor_free(question);
  tor_free(req);
  dns_lookup_free(lookup);
}

static void
test_dns_resolver_lookup_setup_forward_query_missing_question(void *arg)
{
  (void) arg;

  struct evdns_server_request *req = tor_malloc_zero(
                                       sizeof(struct evdns_server_request));
  req->nquestions = 1;

  dns_lookup_t *lookup = dns_lookup_new();

  tt_int_op(dns_resolver_lookup_setup_forward_query(lookup, req), OP_EQ, -2);

 done:
  tor_free(req);
  dns_lookup_free(lookup);
}

static void
test_dns_resolver_lookup_setup_resolution_query_is_hidden_service(void *arg)
{
  (void) arg;

  const char *qname = "example.com";

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverHiddenServiceZones = smartlist_new();
  smartlist_add(mock_options->DNSResolverHiddenServiceZones, (void *) "com.");
  mock_options->DNSResolverIPv6 = 1;
  mock_options->DNSResolverIPv4 = 1;

  dns_lookup_t *lookup = dns_lookup_new();
  lookup->qname = dns_name_of("invalid");

  entry_connection_t *ap_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  strlcpy(ap_conn->socks_request->address, qname,
          sizeof(ap_conn->socks_request->address));

  MOCK(get_options, mock_get_options);
  tt_int_op(dns_resolver_lookup_setup_resolution_query(lookup, ap_conn), OP_EQ,
            0);

  tt_int_op(lookup->action, OP_EQ, DNS_LOOKUP_ACTION_RESOLVE);
  tt_str_op(dns_name_str(lookup->qname), OP_EQ, qname);
  tt_int_op(lookup->qtype, OP_EQ, DNS_TYPE_KEY);
  tt_ptr_op(lookup->ap_conn, OP_EQ, ap_conn);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);

  smartlist_free(mock_options->DNSResolverHiddenServiceZones);
  tor_free(mock_options);
  dns_lookup_free(lookup);
  connection_free_minimal(ENTRY_TO_CONN(ap_conn));
}

static void
test_dns_resolver_lookup_setup_resolution_query_is_ipv6(void *arg)
{
  (void) arg;

  const char *qname = "example.com";

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverIPv6 = 1;
  mock_options->DNSResolverIPv4 = 0;

  dns_lookup_t *lookup = dns_lookup_new();
  lookup->qname = dns_name_of("invalid");

  entry_connection_t *ap_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  strlcpy(ap_conn->socks_request->address, qname,
          sizeof(ap_conn->socks_request->address));

  MOCK(get_options, mock_get_options);
  tt_int_op(dns_resolver_lookup_setup_resolution_query(lookup, ap_conn), OP_EQ,
            0);

  tt_int_op(lookup->action, OP_EQ, DNS_LOOKUP_ACTION_RESOLVE);
  tt_str_op(dns_name_str(lookup->qname), OP_EQ, qname);
  tt_int_op(lookup->qtype, OP_EQ, DNS_TYPE_AAAA);
  tt_ptr_op(lookup->ap_conn, OP_EQ, ap_conn);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);

  tor_free(mock_options);
  dns_lookup_free(lookup);
  connection_free_minimal(ENTRY_TO_CONN(ap_conn));
}

static void
test_dns_resolver_lookup_setup_resolution_query_has_cached_ipv6(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("example.com");

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverIPv6 = 1;
  mock_options->DNSResolverIPv4 = 1;
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_dup(qname);
  question->qtype = dns_type_of(DNS_TYPE_AAAA);

  dns_message_t *message = dns_message_new();
  smartlist_add(message->question_list, question);
  message->header->qdcount = smartlist_len(message->question_list);

  dns_lookup_t *lookup = dns_lookup_new();
  lookup->qname = dns_name_of("invalid");

  entry_connection_t *ap_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  strlcpy(ap_conn->socks_request->address, dns_name_str(qname),
          sizeof(ap_conn->socks_request->address));

  MOCK(get_options, mock_get_options);
  tt_int_op(dns_resolver_cache_add_message(message), OP_EQ, 0);
  tt_int_op(dns_resolver_lookup_setup_resolution_query(lookup, ap_conn), OP_EQ,
            0);

  tt_int_op(lookup->action, OP_EQ, DNS_LOOKUP_ACTION_RESOLVE);
  tt_str_op(dns_name_str(lookup->qname), OP_EQ, dns_name_str(qname));
  tt_int_op(lookup->qtype, OP_EQ, DNS_TYPE_A);
  tt_ptr_op(lookup->ap_conn, OP_EQ, ap_conn);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  UNMOCK(get_options);

  dns_name_free(qname);
  tor_free(mock_options);
  dns_lookup_free(lookup);
  connection_free_minimal(ENTRY_TO_CONN(ap_conn));
  dns_message_free(message);
}

static void
test_dns_resolver_lookup_setup_resolution_query_is_ipv4_and_ipv6(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("example.com");

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverIPv6 = 1;
  mock_options->DNSResolverIPv4 = 1;

  dns_lookup_t *lookup = dns_lookup_new();
  lookup->qname = dns_name_of("invalid");

  entry_connection_t *ap_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  strlcpy(ap_conn->socks_request->address, dns_name_str(qname),
          sizeof(ap_conn->socks_request->address));

  MOCK(get_options, mock_get_options);
  tt_int_op(dns_resolver_lookup_setup_resolution_query(lookup, ap_conn), OP_EQ,
            0);

  tt_int_op(lookup->action, OP_EQ, DNS_LOOKUP_ACTION_RESOLVE);
  tt_str_op(dns_name_str(lookup->qname), OP_EQ, dns_name_str(qname));
  tt_int_op(lookup->qtype, OP_EQ, DNS_TYPE_AAAA);
  tt_ptr_op(lookup->ap_conn, OP_EQ, ap_conn);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);

  dns_name_free(qname);
  tor_free(mock_options);
  dns_lookup_free(lookup);
  connection_free_minimal(ENTRY_TO_CONN(ap_conn));
}

static void
test_dns_resolver_lookup_setup_resolution_query_is_ipv4(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("example.com");

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverIPv6 = 0;
  mock_options->DNSResolverIPv4 = 1;

  dns_lookup_t *lookup = dns_lookup_new();
  lookup->qname = dns_name_of("invalid");

  entry_connection_t *ap_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  strlcpy(ap_conn->socks_request->address, dns_name_str(qname),
          sizeof(ap_conn->socks_request->address));

  MOCK(get_options, mock_get_options);
  tt_int_op(dns_resolver_lookup_setup_resolution_query(lookup, ap_conn), OP_EQ,
            0);

  tt_int_op(lookup->action, OP_EQ, DNS_LOOKUP_ACTION_RESOLVE);
  tt_str_op(dns_name_str(lookup->qname), OP_EQ, dns_name_str(qname));
  tt_int_op(lookup->qtype, OP_EQ, DNS_TYPE_A);
  tt_ptr_op(lookup->ap_conn, OP_EQ, ap_conn);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);

  dns_name_free(qname);
  tor_free(mock_options);
  dns_lookup_free(lookup);
  connection_free_minimal(ENTRY_TO_CONN(ap_conn));
}

static void
test_dns_resolver_lookup_setup_resolution_query_is_undetermined(void *arg)
{
  (void) arg;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverIPv6 = 0;
  mock_options->DNSResolverIPv4 = 0;

  dns_lookup_t *lookup = dns_lookup_new();

  entry_connection_t *ap_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);

  MOCK(get_options, mock_get_options);
  tt_int_op(dns_resolver_lookup_setup_resolution_query(lookup, ap_conn), OP_EQ,
            -1);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 0);

 done:
  UNMOCK(get_options);

  tor_free(mock_options);
  dns_lookup_free(lookup);
  connection_free_minimal(ENTRY_TO_CONN(ap_conn));
}

static void
test_dns_resolver_lookup_set_query(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("example.com");

  dns_lookup_t *lookup = dns_lookup_new();
  lookup->qname = dns_name_of("invalid");

  dns_resolver_lookup_set_query(lookup, DNS_LOOKUP_ACTION_VALIDATE, qname,
                                DNS_TYPE_AAAA);

  tt_int_op(lookup->action, OP_EQ, DNS_LOOKUP_ACTION_VALIDATE);
  tt_str_op(dns_name_str(lookup->qname), OP_EQ, dns_name_str(qname));
  tt_int_op(lookup->qtype, OP_EQ, DNS_TYPE_AAAA);

 done:
  dns_name_free(qname);
  dns_lookup_free(lookup);
}

static void
test_dns_resolver_zone_in_hidden_service_zone(void *arg)
{
  (void) arg;

  dns_name_t *a1 = dns_name_of(".");
  dns_name_t *a2 = NULL;
  dns_name_t *a3 = dns_name_of(".");
  dns_name_t *a4 = dns_name_of("com");
  dns_name_t *a5 = dns_name_of("com.");
  dns_name_t *a6 = dns_name_of("net");
  dns_name_t *a7 = dns_name_of("net.");
  dns_name_t *a8 = dns_name_of("example.com");
  dns_name_t *a9 = dns_name_of("example.com.");
  dns_name_t *a10 = dns_name_of("eXamPLe.COm");
  dns_name_t *a11 = dns_name_of("example.net");
  dns_name_t *a12 = dns_name_of("example.net.");

  smartlist_t *zones = smartlist_new();
  smartlist_add(zones, (char *) "com.");

  tt_int_op(dns_resolver_zone_in_hidden_service_zone(a1, NULL), OP_EQ, 0);
  tt_int_op(dns_resolver_zone_in_hidden_service_zone(a2, zones), OP_EQ, 0);
  tt_int_op(dns_resolver_zone_in_hidden_service_zone(a3, zones), OP_EQ, 0);
  tt_int_op(dns_resolver_zone_in_hidden_service_zone(a4, zones), OP_EQ, 1);
  tt_int_op(dns_resolver_zone_in_hidden_service_zone(a5, zones), OP_EQ, 1);
  tt_int_op(dns_resolver_zone_in_hidden_service_zone(a6, zones), OP_EQ, 0);
  tt_int_op(dns_resolver_zone_in_hidden_service_zone(a7, zones), OP_EQ, 0);
  tt_int_op(dns_resolver_zone_in_hidden_service_zone(a8, zones), OP_EQ, 1);
  tt_int_op(dns_resolver_zone_in_hidden_service_zone(a9, zones), OP_EQ, 1);
  tt_int_op(dns_resolver_zone_in_hidden_service_zone(a10, zones), OP_EQ, 1);
  tt_int_op(dns_resolver_zone_in_hidden_service_zone(a11, zones), OP_EQ, 0);
  tt_int_op(dns_resolver_zone_in_hidden_service_zone(a12, zones), OP_EQ, 0);

 done:
  dns_name_free(a1);
  dns_name_free(a2);
  dns_name_free(a3);
  dns_name_free(a4);
  dns_name_free(a5);
  dns_name_free(a6);
  dns_name_free(a7);
  dns_name_free(a8);
  dns_name_free(a9);
  dns_name_free(a10);
  dns_name_free(a11);
  dns_name_free(a12);
  smartlist_free(zones);
}

static void
test_dns_resolver_resolution_should_fallback_to_ipv4_not_enabled(void *arg)
{
  (void) arg;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverIPv4 = 0;
  mock_options->DNSResolverIPv6 = 1;

  dns_question_t *question = dns_question_new();
  question->qtype = dns_type_of(DNS_TYPE_AAAA);

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);

  MOCK(get_options, mock_get_options);

  tt_int_op(dns_resolver_resolution_should_fallback_to_ipv4(resp), OP_EQ, 0);

 done:
  UNMOCK(get_options);

  tor_free(mock_options);
  dns_message_free(resp);
}

static void
test_dns_resolver_resolution_should_fallback_to_ipv4_invalid_qtype(void *arg)
{
  (void) arg;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverIPv4 = 1;
  mock_options->DNSResolverIPv6 = 1;

  dns_question_t *question = dns_question_new();
  question->qtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);

  MOCK(get_options, mock_get_options);

  tt_int_op(dns_resolver_resolution_should_fallback_to_ipv4(resp), OP_EQ, 0);

 done:
  UNMOCK(get_options);

  tor_free(mock_options);
  dns_message_free(resp);
}

static void
test_dns_resolver_resolution_should_fallback_to_ipv4_has_response(void *arg)
{
  (void) arg;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverIPv4 = 1;
  mock_options->DNSResolverIPv6 = 1;

  dns_question_t *question = dns_question_new();
  question->qtype = dns_type_of(DNS_TYPE_AAAA);

  dns_rr_t *rr = dns_rr_new();
  rr->rrtype = dns_type_of(DNS_TYPE_AAAA);

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);
  smartlist_add(resp->answer_list, rr);

  MOCK(get_options, mock_get_options);

  tt_int_op(dns_resolver_resolution_should_fallback_to_ipv4(resp), OP_EQ, 0);

 done:
  UNMOCK(get_options);

  tor_free(mock_options);
  dns_message_free(resp);
}

static void
test_dns_resolver_resolution_should_fallback_to_ipv4_fallback(void *arg)
{
  (void) arg;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverIPv4 = 1;
  mock_options->DNSResolverIPv6 = 1;

  dns_question_t *question = dns_question_new();
  question->qtype = dns_type_of(DNS_TYPE_AAAA);

  dns_message_t *resp = dns_message_new();
  smartlist_add(resp->question_list, question);
  resp->header->qdcount = smartlist_len(resp->question_list);

  MOCK(get_options, mock_get_options);

  tt_int_op(dns_resolver_resolution_should_fallback_to_ipv4(resp), OP_EQ, 1);

 done:
  UNMOCK(get_options);

  tor_free(mock_options);
  dns_message_free(resp);
}

static void
test_dns_resolver_get_zones_for_name_with_root_trust_anchor(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("a.c.x.w.example.");

  dns_rr_t *root_ta = dns_rr_new();
  root_ta->name = dns_name_of(".");

  smartlist_t *trust_anchors = smartlist_new();
  smartlist_add(trust_anchors, root_ta);

  smartlist_t *zones = dns_resolver_get_zones_for_name(qname, trust_anchors);

  tt_int_op(smartlist_len(zones), OP_EQ, 6);
  tt_str_op(dns_name_str(smartlist_get(zones, 0)), OP_EQ, "a.c.x.w.example.");
  tt_str_op(dns_name_str(smartlist_get(zones, 1)), OP_EQ, "c.x.w.example.");
  tt_str_op(dns_name_str(smartlist_get(zones, 2)), OP_EQ, "x.w.example.");
  tt_str_op(dns_name_str(smartlist_get(zones, 3)), OP_EQ, "w.example.");
  tt_str_op(dns_name_str(smartlist_get(zones, 4)), OP_EQ, "example.");
  tt_str_op(dns_name_str(smartlist_get(zones, 5)), OP_EQ, ".");

 done:
  dns_name_free(qname);
  SMARTLIST_FOREACH(zones, dns_name_t *, zone, dns_name_free(zone));
  smartlist_free(zones);
  SMARTLIST_FOREACH(trust_anchors, dns_rr_t *, anchor, dns_rr_free(anchor));
  smartlist_free(trust_anchors);
}

static void
test_dns_resolver_get_zones_for_name_with_intermediate_trust_anchor(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("a.c.x.w.example.");

  dns_rr_t *root_ta = dns_rr_new();
  root_ta->name = dns_name_of(".");

  dns_rr_t *intermediate_ta = dns_rr_new();
  intermediate_ta->name = dns_name_of("w.example.");

  smartlist_t *trust_anchors = smartlist_new();
  smartlist_add(trust_anchors, root_ta);
  smartlist_add(trust_anchors, intermediate_ta);

  smartlist_t *zones = dns_resolver_get_zones_for_name(qname, trust_anchors);

  tt_int_op(smartlist_len(zones), OP_EQ, 4);
  tt_str_op(dns_name_str(smartlist_get(zones, 0)), OP_EQ, "a.c.x.w.example.");
  tt_str_op(dns_name_str(smartlist_get(zones, 1)), OP_EQ, "c.x.w.example.");
  tt_str_op(dns_name_str(smartlist_get(zones, 2)), OP_EQ, "x.w.example.");
  tt_str_op(dns_name_str(smartlist_get(zones, 3)), OP_EQ, "w.example.");

 done:
  dns_name_free(qname);
  SMARTLIST_FOREACH(zones, dns_name_t *, zone, dns_name_free(zone));
  smartlist_free(zones);
  SMARTLIST_FOREACH(trust_anchors, dns_rr_t *, anchor, dns_rr_free(anchor));
  smartlist_free(trust_anchors);
}

static void
test_dns_resolver_get_zones_for_name_without_trust_anchor(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("a.c.x.w.example.");
  smartlist_t *trust_anchors = smartlist_new();
  smartlist_t *zones = dns_resolver_get_zones_for_name(qname, trust_anchors);

  tt_int_op(smartlist_len(zones), OP_EQ, 0);

 done:
  dns_name_free(qname);
  SMARTLIST_FOREACH(zones, dns_name_t *, zone, dns_name_free(zone));
  smartlist_free(zones);
  SMARTLIST_FOREACH(trust_anchors, dns_rr_t *, anchor, dns_rr_free(anchor));
  smartlist_free(trust_anchors);
}

static void
test_dns_resolver_add_query_succeeds(void *arg)
{
  (void) arg;

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();
  dns_conn->dns_lookup->qname = dns_name_of("example.com.");

  tt_int_op(buf_datalen(ENTRY_TO_CONN(dns_conn)->inbuf), OP_EQ, 0);
  tt_int_op(dns_resolver_add_query_impl(dns_conn, 0), OP_EQ, 0);
  tt_int_op(buf_datalen(ENTRY_TO_CONN(dns_conn)->inbuf), OP_EQ, 31);

 done:
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_add_query_with_invalid_qname(void *arg)
{
  (void) arg;

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();
  dns_conn->dns_lookup->qname = dns_name_of("abcd01234567890123456789012345678"
                                            "9012345678901234567890123456789.e"
                                            "xample.com.");

  tt_int_op(buf_datalen(ENTRY_TO_CONN(dns_conn)->inbuf), OP_EQ, 0);
  tt_int_op(dns_resolver_add_query_impl(dns_conn, 0), OP_EQ, -1);
  tt_int_op(buf_datalen(ENTRY_TO_CONN(dns_conn)->inbuf), OP_EQ, 0);

 done:
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_add_query_and_process(void *arg)
{
  (void) arg;

  entry_connection_t *dns_conn = dns_resolver_dns_connection_new();
  dns_conn->dns_lookup->qname = dns_name_of("example.com.");

  // Make sure that no action is performed within connection_edge_process_inbuf
  ENTRY_TO_CONN(dns_conn)->state = AP_CONN_STATE_CIRCUIT_WAIT;

  tt_int_op(buf_datalen(ENTRY_TO_CONN(dns_conn)->inbuf), OP_EQ, 0);
  tt_int_op(dns_resolver_add_query_impl(dns_conn, 1), OP_EQ, 0);
  tt_int_op(buf_datalen(ENTRY_TO_CONN(dns_conn)->inbuf), OP_EQ, 31);

 done:
  connection_free_minimal(ENTRY_TO_CONN(dns_conn));
}

static void
test_dns_resolver_build_dns_message_minimal(void *arg)
{
  (void) arg;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverDNSSECMode = DNSSEC_MODE_OFF;
  mock_options->DNSResolverRandomizeCase = 0;

  dns_lookup_t *lookup = dns_lookup_new();
  lookup->action = DNS_LOOKUP_ACTION_RESOLVE;
  lookup->qname = dns_name_of("example.com.");
  lookup->qtype = DNS_TYPE_AAAA;

  MOCK(get_options, mock_get_options);
  dns_message_t *message = dns_resolver_build_dns_message(lookup);

  tt_int_op(message->header->opcode, OP_EQ, DNS_OPCODE_QUERY);
  tt_int_op(message->header->rd, OP_EQ, 1);
  tt_int_op(message->header->cd, OP_EQ, 1);
  tt_int_op(message->header->qdcount, OP_EQ, 1);
  tt_int_op(message->header->ancount, OP_EQ, 0);
  tt_int_op(message->header->nscount, OP_EQ, 0);
  tt_int_op(message->header->arcount, OP_EQ, 0);

  dns_question_t *question = dns_message_get_question(message);
  const char *question_str = dns_question_str(question);
  tt_ptr_op(strstr(question_str, "example.com."), OP_NE, NULL);
  tt_ptr_op(strstr(question_str, "AAAA"), OP_NE, NULL);

 done:
  UNMOCK(get_options);

  tor_free(mock_options);
  dns_lookup_free(lookup);
  dns_message_free(message);
}

static void
test_dns_resolver_build_dns_message_trust_recursor(void *arg)
{
  (void) arg;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverDNSSECMode = DNSSEC_MODE_TRUST;
  mock_options->DNSResolverRandomizeCase = 0;

  dns_lookup_t *lookup = dns_lookup_new();
  lookup->action = DNS_LOOKUP_ACTION_RESOLVE;
  lookup->qname = dns_name_of("example.com.");
  lookup->qtype = DNS_TYPE_AAAA;

  MOCK(get_options, mock_get_options);
  dns_message_t *message = dns_resolver_build_dns_message(lookup);

  tt_int_op(message->header->opcode, OP_EQ, DNS_OPCODE_QUERY);
  tt_int_op(message->header->rd, OP_EQ, 1);
  tt_int_op(message->header->cd, OP_EQ, 0);
  tt_int_op(message->header->qdcount, OP_EQ, 1);
  tt_int_op(message->header->ancount, OP_EQ, 0);
  tt_int_op(message->header->nscount, OP_EQ, 0);
  tt_int_op(message->header->arcount, OP_EQ, 0);

  dns_question_t *question = dns_message_get_question(message);
  const char *question_str = dns_question_str(question);
  tt_ptr_op(strstr(question_str, "example.com."), OP_NE, NULL);
  tt_ptr_op(strstr(question_str, "AAAA"), OP_NE, NULL);

 done:
  UNMOCK(get_options);

  tor_free(mock_options);
  dns_lookup_free(lookup);
  dns_message_free(message);
}

static void
test_dns_resolver_build_dns_message_with_dnssec_flag(void *arg)
{
  (void) arg;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverDNSSECMode = DNSSEC_MODE_VALIDATE;
  mock_options->DNSResolverRandomizeCase = 0;

  dns_lookup_t *lookup = dns_lookup_new();
  lookup->action = DNS_LOOKUP_ACTION_RESOLVE;
  lookup->qname = dns_name_of("example.com.");
  lookup->qtype = DNS_TYPE_AAAA;

  MOCK(get_options, mock_get_options);
  dns_message_t *message = dns_resolver_build_dns_message(lookup);

  tt_int_op(message->header->opcode, OP_EQ, DNS_OPCODE_QUERY);
  tt_int_op(message->header->rd, OP_EQ, 1);
  tt_int_op(message->header->cd, OP_EQ, 1);
  tt_int_op(message->header->qdcount, OP_EQ, 1);
  tt_int_op(message->header->ancount, OP_EQ, 0);
  tt_int_op(message->header->nscount, OP_EQ, 0);
  tt_int_op(message->header->arcount, OP_EQ, 1);

  dns_question_t *question = dns_message_get_question(message);
  const char *question_str = dns_question_str(question);
  tt_ptr_op(strstr(question_str, "example.com."), OP_NE, NULL);
  tt_ptr_op(strstr(question_str, "AAAA"), OP_NE, NULL);

  const char *rr_str = dns_rr_str(
                         smartlist_get(message->additional_record_list, 0));
  tt_ptr_op(strstr(rr_str, "32768"), OP_NE, NULL);

 done:
  UNMOCK(get_options);

  tor_free(mock_options);
  dns_lookup_free(lookup);
  dns_message_free(message);
}

static void
test_dns_resolver_build_dns_message_randomize_case(void *arg)
{
  (void) arg;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverDNSSECMode = DNSSEC_MODE_OFF;
  mock_options->DNSResolverRandomizeCase = 1;

  dns_lookup_t *lookup = dns_lookup_new();
  lookup->action = DNS_LOOKUP_ACTION_RESOLVE;
  lookup->qname = dns_name_of("example.com.");
  lookup->qtype = DNS_TYPE_AAAA;

  MOCK(get_options, mock_get_options);
  dns_message_t *message = dns_resolver_build_dns_message(lookup);

  tt_int_op(message->header->opcode, OP_EQ, DNS_OPCODE_QUERY);
  tt_int_op(message->header->rd, OP_EQ, 1);
  tt_int_op(message->header->cd, OP_EQ, 1);
  tt_int_op(message->header->qdcount, OP_EQ, 1);
  tt_int_op(message->header->ancount, OP_EQ, 0);
  tt_int_op(message->header->nscount, OP_EQ, 0);
  tt_int_op(message->header->arcount, OP_EQ, 0);

  dns_question_t *question = dns_message_get_question(message);

  char *question_str = (char *) dns_question_str(question);
  tt_ptr_op(strstr(question_str, "example.com."), OP_EQ, NULL);
  tt_ptr_op(strstr(question_str, "AAAA"), OP_NE, NULL);

  tor_strlower(question->qname->value);
  question_str = (char *) dns_question_str(question);
  tt_ptr_op(strstr(question_str, "example.com."), OP_NE, NULL);
  tt_ptr_op(strstr(question_str, "AAAA"), OP_NE, NULL);

 done:
  UNMOCK(get_options);

  tor_free(mock_options);
  dns_lookup_free(lookup);
  dns_message_free(message);
}

static void
test_dns_resolver_update_nameserver_latency(void *arg)
{
  (void) arg;

  nameserver_t *nameserver = nameserver_new();
  nameserver->latency = 0;

  dns_lookup_t *lookup = dns_lookup_new();
  lookup->nameserver = nameserver;

  dns_resolver_update_nameserver_latency(lookup, 0);
  tt_int_op(nameserver->latency, OP_EQ, 1);

  tor_gettimeofday(&lookup->start_time);
  dns_resolver_update_nameserver_latency(lookup, 0);
  tt_int_op(nameserver->latency, OP_EQ, 1);

  tor_gettimeofday(&lookup->start_time);
  dns_resolver_update_nameserver_latency(lookup, 1);
  tt_int_op(nameserver->latency, OP_EQ, 2);

  tor_gettimeofday(&lookup->start_time);
  dns_resolver_update_nameserver_latency(lookup, 5);
  tt_int_op(nameserver->latency, OP_EQ, 32);

  tor_gettimeofday(&lookup->start_time);
  dns_resolver_update_nameserver_latency(lookup, 10);
  tt_int_op(nameserver->latency, OP_EQ, NAMESERVER_MAX_LATENCY_IN_MSEC);

 done:
  nameserver_free(nameserver);
  dns_lookup_free(lookup);
}

static void
test_dns_resolver_nameserver_sort_by_latency_asc(void *arg)
{
  (void) arg;

  nameserver_t *ns1 = nameserver_new();
  ns1->latency = 1;

  nameserver_t *ns2 = nameserver_new();
  ns2->latency = 3;

  tt_int_op(dns_resolver_nameserver_sort_by_latency_asc((void *) &ns1,
                                                        (void *) &ns2),
                                                        OP_EQ, -2);

  tt_int_op(dns_resolver_nameserver_sort_by_latency_asc((void *) &ns2,
                                                        (void *) &ns1),
                                                        OP_EQ, 2);

  tt_int_op(dns_resolver_nameserver_sort_by_latency_asc((void *) &ns2,
                                                        (void *) &ns2),
                                                        OP_EQ, 0);

 done:
  nameserver_free(ns1);
  nameserver_free(ns2);
}

static void
test_dns_resolver_cache_add_message_succeeds(void *arg)
{
  (void) arg;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_of("example.com.");
  question->qtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *message = dns_message_new();
  smartlist_add(message->question_list, question);
  message->header->qdcount = smartlist_len(message->question_list);

  MOCK(get_options, mock_get_options);
  tt_int_op(dns_resolver_cache_add_message(message), OP_EQ, 0);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  UNMOCK(get_options);

  tor_free(mock_options);
  dns_message_free(message);
}

static void
test_dns_resolver_cache_add_message_overflow(void *arg)
{
  (void) arg;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;

  dns_question_t *question1 = dns_question_new();
  question1->qname = dns_name_of("example.com.");
  question1->qtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *message1 = dns_message_new();
  smartlist_add(message1->question_list, question1);
  message1->header->qdcount = smartlist_len(message1->question_list);

  dns_question_t *question2 = dns_question_new();
  question2->qname = dns_name_of("example.org.");
  question2->qtype = dns_type_of(DNS_TYPE_A);

  dns_message_t *message2 = dns_message_new();
  smartlist_add(message2->question_list, question2);
  message2->header->qdcount = smartlist_len(message2->question_list);

  MOCK(get_options, mock_get_options);
  tt_int_op(dns_resolver_cache_add_message(message1), OP_EQ, 0);
  tt_int_op(dns_resolver_cache_add_message(message2), OP_EQ, 0);
  tt_int_op(dns_resolver_cache_free_all(), OP_EQ, 1);

 done:
  UNMOCK(get_options);

  tor_free(mock_options);
  dns_message_free(message1);
  dns_message_free(message2);
}

static void
test_dns_resolver_cache_add_message_when_disabled(void *arg)
{
  (void) arg;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 0;

  dns_message_t *message = dns_message_new();

  MOCK(get_options, mock_get_options);
  tt_int_op(dns_resolver_cache_add_message(message), OP_EQ, -1);

 done:
  UNMOCK(get_options);

  tor_free(mock_options);
  dns_message_free(message);
}

static void
test_dns_resolver_cache_add_message_when_invalid(void *arg)
{
  (void) arg;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;

  dns_message_t *message = dns_message_new();

  MOCK(get_options, mock_get_options);
  tt_int_op(dns_resolver_cache_add_message(message), OP_EQ, -2);

 done:
  UNMOCK(get_options);

  tor_free(mock_options);
  dns_message_free(message);
}

static void
test_dns_resolver_cache_get_message_when_present(void *arg)
{
  (void) arg;

  dns_message_t *cached_message = NULL;

  dns_name_t *qname = dns_name_of("example.com");
  uint16_t qtype = DNS_TYPE_A;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_dup(qname);
  question->qtype = dns_type_of(qtype);

  dns_message_t *message = dns_message_new();
  smartlist_add(message->question_list, question);
  message->header->qdcount = smartlist_len(message->question_list);

  MOCK(get_options, mock_get_options);
  tt_int_op(dns_resolver_cache_add_message(message), OP_EQ, 0);

  cached_message = dns_resolver_cache_get_message(qname, qtype);
  tt_ptr_op(cached_message, OP_NE, NULL);

 done:
  UNMOCK(get_options);

  dns_name_free(qname);
  tor_free(mock_options);
  dns_message_free(message);
  dns_message_free(cached_message);
  dns_resolver_cache_free_all();
}

static void
test_dns_resolver_cache_get_message_when_not_present(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("example.com");
  uint16_t qtype = DNS_TYPE_A;

  tt_ptr_op(dns_resolver_cache_get_message(qname, qtype), OP_EQ, NULL);

 done:
  dns_name_free(qname);
}

static void
test_dns_resolver_cache_get_message_when_expired(void *arg)
{
  (void) arg;

  dns_name_t *qname = dns_name_of("example.com");
  uint16_t qtype = DNS_TYPE_A;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverMaxCacheEntries = 1;
  mock_options->DNSResolverMaxCacheTTL = 10;

  dns_question_t *question = dns_question_new();
  question->qname = dns_name_dup(qname);
  question->qtype = dns_type_of(qtype);

  dns_rr_t *rr = dns_rr_new();
  rr->ttl = 60;

  dns_message_t *message = dns_message_new();
  smartlist_add(message->question_list, question);
  message->header->qdcount = smartlist_len(message->question_list);
  smartlist_add(message->answer_list, rr);

  MOCK(get_options, mock_get_options);
  tt_int_op(dns_resolver_cache_add_message(message), OP_EQ, 0);

  mocked_timeofday = 60;
  MOCK(tor_gettimeofday, mock_tor_gettimeofday);

  tt_ptr_op(dns_resolver_cache_get_message(qname, qtype), OP_EQ, NULL);

 done:
  UNMOCK(get_options);
  UNMOCK(tor_gettimeofday);

  dns_name_free(qname);
  tor_free(mock_options);
  dns_message_free(message);
  dns_resolver_cache_free_all();
}

static void
test_dns_resolver_cache_is_enabled(void *arg)
{
  (void) arg;

  or_options_t *options = tor_malloc_zero(sizeof(or_options_t));

  options->DNSResolverMaxCacheEntries = 1;
  options->DNSResolverMaxCacheTTL = 10;
  tt_int_op(dns_resolver_cache_is_enabled(options), OP_EQ, 1);

  options->DNSResolverMaxCacheEntries = 1;
  options->DNSResolverMaxCacheTTL = 0;
  tt_int_op(dns_resolver_cache_is_enabled(options), OP_EQ, 0);

  options->DNSResolverMaxCacheEntries = 0;
  options->DNSResolverMaxCacheTTL = 10;
  tt_int_op(dns_resolver_cache_is_enabled(options), OP_EQ, 0);

  options->DNSResolverMaxCacheEntries = 0;
  options->DNSResolverMaxCacheTTL = 0;
  tt_int_op(dns_resolver_cache_is_enabled(options), OP_EQ, 0);

 done:
  tor_free(options);
}

static void
test_dns_resolver_cache_get_key(void *arg)
{
  (void) arg;

  dns_name_t *name1 = dns_name_of("example.com");
  dns_name_t *name2 = dns_name_of("eXamPLe.com");
  dns_name_t *name3 = dns_name_of("");

  char *cache_key1 = dns_resolver_cache_get_key(name1, DNS_TYPE_A);
  char *cache_key2 = dns_resolver_cache_get_key(name2, DNS_TYPE_AAAA);
  char *cache_key3 = dns_resolver_cache_get_key(name3, DNS_TYPE_RRSIG);

  tt_str_op(cache_key1, OP_EQ, "example.com.1");
  tt_str_op(cache_key2, OP_EQ, "example.com.28");
  tt_str_op(cache_key3, OP_EQ, ".46");

 done:
  dns_name_free(name1);
  dns_name_free(name2);
  dns_name_free(name3);

  tor_free(cache_key1);
  tor_free(cache_key2);
  tor_free(cache_key3);
}

static void
test_dns_resolver_cache_update_message_ttl(void *arg)
{
  (void) arg;

  mock_options = tor_malloc_zero(sizeof(or_options_t));
  mock_options->DNSResolverMaxCacheTTL = 10;

  dns_rr_t *an_rr = dns_rr_new();
  an_rr->ttl = 60;

  dns_rr_t *ns_rr = dns_rr_new();
  ns_rr->ttl = 20;

  mocked_timeofday = 0;

  MOCK(get_options, mock_get_options);
  MOCK(tor_gettimeofday, mock_tor_gettimeofday);

  dns_message_t *message = dns_message_new();
  smartlist_add(message->answer_list, an_rr);
  uint32_t an_minimum_ttl = dns_resolver_cache_update_message_ttl(message);

  smartlist_add(message->name_server_list, ns_rr);
  uint32_t ns_minimum_ttl = dns_resolver_cache_update_message_ttl(message);

  mocked_timeofday = 11;
  uint32_t expired_max_ttl = dns_resolver_cache_update_message_ttl(message);

  mock_options->DNSResolverMaxCacheTTL = 120;
  mocked_timeofday = 21;
  uint32_t ns_expired = dns_resolver_cache_update_message_ttl(message);

  ns_rr->ttl += 60;
  mocked_timeofday = 61;
  uint32_t an_expired = dns_resolver_cache_update_message_ttl(message);

  tt_uint_op(an_minimum_ttl, OP_EQ, 60);
  tt_uint_op(ns_minimum_ttl, OP_EQ, 20);
  tt_uint_op(expired_max_ttl, OP_EQ, 0);
  tt_uint_op(ns_expired, OP_EQ, 0);
  tt_uint_op(an_expired, OP_EQ, 0);

 done:
  UNMOCK(get_options);
  UNMOCK(tor_gettimeofday);

  tor_free(mock_options);
  dns_message_free(message);
}

#define DNS_RESOLVER_TEST(name, flags)                          \
  { #name, test_dns_resolver_ ## name, flags, NULL, NULL }

struct testcase_t dns_resolver_tests[] = {

  DNS_RESOLVER_TEST(initiate_server_request_forward_succeeds, TT_FORK),
  DNS_RESOLVER_TEST(initiate_server_request_forward_invalid_qname, 0),
  DNS_RESOLVER_TEST(initiate_server_request_forward_missing_nameserver, 0),
  DNS_RESOLVER_TEST(initiate_server_request_forward_invalid_server_request, 0),
  DNS_RESOLVER_TEST(initiate_server_request_forward_is_cached, 0),

  DNS_RESOLVER_TEST(initiate_socks_address_resolution_succeeds, TT_FORK),
  DNS_RESOLVER_TEST(initiate_socks_address_resolution_invalid_qname, 0),
  DNS_RESOLVER_TEST(initiate_socks_address_resolution_missing_nameserver, 0),
  DNS_RESOLVER_TEST(initiate_socks_address_resolution_invalid_config, 0),
  DNS_RESOLVER_TEST(initiate_socks_address_resolution_is_cached, 0),

  DNS_RESOLVER_TEST(ping_nameserver, TT_FORK),

  DNS_RESOLVER_TEST(process_reply_forward, 0),
  DNS_RESOLVER_TEST(process_reply_resolve, 0),
  DNS_RESOLVER_TEST(process_reply_validate, 0),
  DNS_RESOLVER_TEST(process_reply_unknown_action, 0),
  DNS_RESOLVER_TEST(process_reply_invalid_message, 0),
  DNS_RESOLVER_TEST(process_reply_partial_response, 0),
  DNS_RESOLVER_TEST(process_reply_invalid_response, 0),

  DNS_RESOLVER_TEST(config_revise_dnssec_mode, 0),
  DNS_RESOLVER_TEST(config_revise_nameservers_initial, 0),
  DNS_RESOLVER_TEST(config_revise_nameservers_update, 0),
  DNS_RESOLVER_TEST(config_revise_nameserver_zone_map, 0),
  DNS_RESOLVER_TEST(config_revise_trust_anchors, 0),

  DNS_RESOLVER_TEST(handle_resolution_reply_dnssec_off, 0),
  DNS_RESOLVER_TEST(handle_resolution_reply_dnssec_trust, 0),
  DNS_RESOLVER_TEST(handle_resolution_reply_unknown_action, 0),

#ifdef ENABLE_OPENSSL

  DNS_RESOLVER_TEST(handle_resolution_reply_dnssec_process, 0),
  DNS_RESOLVER_TEST(handle_resolution_reply_dnssec_validate, 0),

  DNS_RESOLVER_TEST(handle_validation_reply_apex_dnskeys_respond, 0),
  DNS_RESOLVER_TEST(handle_validation_reply_delegation_respond, 0),
  DNS_RESOLVER_TEST(handle_validation_reply_zone_cut_respond, 0),
  DNS_RESOLVER_TEST(handle_validation_reply_unknown_action, 0),

  DNS_RESOLVER_TEST(validation_initiate, 0),
  DNS_RESOLVER_TEST(validation_initiate_encounters_invalid_message, 0),
  DNS_RESOLVER_TEST(validation_initiate_next_chain_initiate, 0),
  DNS_RESOLVER_TEST(validation_initiate_next_chain_out_of_child_zones, 0),
  DNS_RESOLVER_TEST(validation_initiate_next_chain_misses_trust_anchor, 0),
  DNS_RESOLVER_TEST(validation_initiate_next_chain_resolve_request, 0),

  DNS_RESOLVER_TEST(validation_conclude_chain_unauthenticated_answers, 0),
  DNS_RESOLVER_TEST(validation_conclude_chain_unauthenticated_authorities, 0),
  DNS_RESOLVER_TEST(validation_conclude_chain_denial_of_existence, 0),

  DNS_RESOLVER_TEST(validation_choose_next_zone_to_validate, 0),

  DNS_RESOLVER_TEST(validation_apex_dnskeys_request_send_query_succeeds, 0),
  DNS_RESOLVER_TEST(validation_apex_dnskeys_request_send_query_fails, 0),
  DNS_RESOLVER_TEST(validation_apex_dnskeys_request_is_cached, 0),
  DNS_RESOLVER_TEST(validation_apex_dnskeys_response_is_valid, 0),
  DNS_RESOLVER_TEST(validation_apex_dnskeys_response_is_bogus, 0),
  DNS_RESOLVER_TEST(validation_apex_dnskeys_response_is_insecure, 0),
  DNS_RESOLVER_TEST(validation_apex_dnskeys_response_has_invalid_type, 0),

  DNS_RESOLVER_TEST(validation_delegation_request_send_query_succeedes, 0),
  DNS_RESOLVER_TEST(validation_delegation_request_send_query_fails, 0),
  DNS_RESOLVER_TEST(validation_delegation_request_is_cached, 0),
  DNS_RESOLVER_TEST(validation_delegation_request_is_trust_anchor, 0),
  DNS_RESOLVER_TEST(validation_delegation_response_is_valid, 0),
  DNS_RESOLVER_TEST(validation_delegation_response_is_bogus, 0),
  DNS_RESOLVER_TEST(validation_delegation_response_is_insecure, 0),
  DNS_RESOLVER_TEST(validation_delegation_response_has_invalid_type, 0),

  DNS_RESOLVER_TEST(validation_zone_cut_request_send_query_succeedes, 0),
  DNS_RESOLVER_TEST(validation_zone_cut_request_send_query_fails, 0),
  DNS_RESOLVER_TEST(validation_zone_cut_request_is_cached, 0),
  DNS_RESOLVER_TEST(validation_zone_cut_request_conclude_chain, 0),
  DNS_RESOLVER_TEST(validation_zone_cut_response_indicates_zone_cut, 0),
  DNS_RESOLVER_TEST(validation_zone_cut_response_is_not_zone_cut, 0),
  DNS_RESOLVER_TEST(validation_zone_cut_response_has_invalid_type, 0),

#endif /* defined(ENABLE_OPENSSL) */

  DNS_RESOLVER_TEST(validation_update_state, 0),

  DNS_RESOLVER_TEST(complete_server_request_forward, 0),
  DNS_RESOLVER_TEST(resolve_server_request_successful_response, 0),
  DNS_RESOLVER_TEST(resolve_server_request_unsuccessful_response, 0),
  DNS_RESOLVER_TEST(resolve_server_request_already_resolved, 0),

  DNS_RESOLVER_TEST(complete_socks_address_resolution_fallback, 0),
  DNS_RESOLVER_TEST(complete_socks_address_resolution_resolve, 0),
  DNS_RESOLVER_TEST(resolve_socks_address_ipv4, 0),
  DNS_RESOLVER_TEST(resolve_socks_address_ipv6, 0),
  DNS_RESOLVER_TEST(resolve_socks_address_onion, 0),
  DNS_RESOLVER_TEST(resolve_socks_address_invalid_connection_type, 0),
  DNS_RESOLVER_TEST(resolve_socks_address_already_resolved, 0),

  DNS_RESOLVER_TEST(resolve_socks_address_get_answers_ipv4, 0),
  DNS_RESOLVER_TEST(resolve_socks_address_get_answers_ipv6, 0),
  DNS_RESOLVER_TEST(resolve_socks_address_get_answers_onion, 0),
  DNS_RESOLVER_TEST(resolve_socks_address_get_answers_cached_v2, TT_FORK),
  DNS_RESOLVER_TEST(resolve_socks_address_get_answers_cached_v3, TT_FORK),
  DNS_RESOLVER_TEST(resolve_socks_address_get_answers_when_failure, 0),

  DNS_RESOLVER_TEST(choose_nameserver_to_ping, 0),
  DNS_RESOLVER_TEST(backoff_nameserver, 0),
  DNS_RESOLVER_TEST(choose_nameserver_for_lookup, 0),
  DNS_RESOLVER_TEST(assign_nameserver, 0),

  DNS_RESOLVER_TEST(nameserver_create_list, 0),
  DNS_RESOLVER_TEST(nameserver_create_list_without_servers, 0),
  DNS_RESOLVER_TEST(nameserver_find, 0),
  DNS_RESOLVER_TEST(nameserver_find_best_by_latency, 0),
  DNS_RESOLVER_TEST(nameserver_free_outdated, 0),

  DNS_RESOLVER_TEST(extract_server_and_zones, 0),
  DNS_RESOLVER_TEST(extract_hostname_and_port, 0),

  DNS_RESOLVER_TEST(lookup_setup_forward_query_succeeds, 0),
  DNS_RESOLVER_TEST(lookup_setup_forward_query_number_of_question, 0),
  DNS_RESOLVER_TEST(lookup_setup_forward_query_missing_question, 0),

  DNS_RESOLVER_TEST(lookup_setup_resolution_query_is_hidden_service, 0),
  DNS_RESOLVER_TEST(lookup_setup_resolution_query_is_ipv6, 0),
  DNS_RESOLVER_TEST(lookup_setup_resolution_query_has_cached_ipv6, 0),
  DNS_RESOLVER_TEST(lookup_setup_resolution_query_is_ipv4_and_ipv6, 0),
  DNS_RESOLVER_TEST(lookup_setup_resolution_query_is_ipv4, 0),
  DNS_RESOLVER_TEST(lookup_setup_resolution_query_is_undetermined, 0),

  DNS_RESOLVER_TEST(lookup_set_query, 0),

  DNS_RESOLVER_TEST(zone_in_hidden_service_zone, 0),
  DNS_RESOLVER_TEST(resolution_should_fallback_to_ipv4_not_enabled, 0),
  DNS_RESOLVER_TEST(resolution_should_fallback_to_ipv4_invalid_qtype, 0),
  DNS_RESOLVER_TEST(resolution_should_fallback_to_ipv4_has_response, 0),
  DNS_RESOLVER_TEST(resolution_should_fallback_to_ipv4_fallback, 0),
  DNS_RESOLVER_TEST(get_zones_for_name_with_root_trust_anchor, 0),
  DNS_RESOLVER_TEST(get_zones_for_name_with_intermediate_trust_anchor, 0),
  DNS_RESOLVER_TEST(get_zones_for_name_without_trust_anchor, 0),

  DNS_RESOLVER_TEST(add_query_succeeds, 0),
  DNS_RESOLVER_TEST(add_query_with_invalid_qname, 0),
  DNS_RESOLVER_TEST(add_query_and_process, 0),

  DNS_RESOLVER_TEST(build_dns_message_minimal, 0),
  DNS_RESOLVER_TEST(build_dns_message_trust_recursor, 0),
  DNS_RESOLVER_TEST(build_dns_message_with_dnssec_flag, 0),
  DNS_RESOLVER_TEST(build_dns_message_randomize_case, 0),

  DNS_RESOLVER_TEST(update_nameserver_latency, 0),
  DNS_RESOLVER_TEST(nameserver_sort_by_latency_asc, 0),

  DNS_RESOLVER_TEST(cache_add_message_succeeds, 0),
  DNS_RESOLVER_TEST(cache_add_message_overflow, 0),
  DNS_RESOLVER_TEST(cache_add_message_when_disabled, 0),
  DNS_RESOLVER_TEST(cache_add_message_when_invalid, 0),
  DNS_RESOLVER_TEST(cache_get_message_when_present, 0),
  DNS_RESOLVER_TEST(cache_get_message_when_not_present, 0),
  DNS_RESOLVER_TEST(cache_get_message_when_expired, 0),
  DNS_RESOLVER_TEST(cache_is_enabled, 0),
  DNS_RESOLVER_TEST(cache_get_key, 0),
  DNS_RESOLVER_TEST(cache_update_message_ttl, 0),

  END_OF_TESTCASES
};
