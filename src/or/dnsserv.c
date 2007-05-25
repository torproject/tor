/* Copyright 2007 Roger Dingledine, Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id$ */
const char dnsserv_c_id[] =
  "$Id$";

/**
 * \file dnservs.c
 * \brief Implements client-side DNS proxy server code.
 **/

#include "or.h"
#include "eventdns.h"

static void
evdns_server_callback(struct evdns_server_request *req, void *_data)
{
  edge_connection_t *conn;
  int i = 0;
  struct evdns_server_question *q = NULL;
  struct sockaddr_storage addr;
  struct sockaddr *sa;
  int addrlen;
  uint32_t ipaddr;
  int err = DNS_ERR_NONE;

  tor_assert(req);
  tor_assert(_data == NULL);
  log_info(LD_APP, "Got a new DNS request!");

  if ((addrlen = evdns_server_request_get_requesting_addr(req,
                                (struct sockaddr*)&addr, sizeof(addr))) < 0) {
    log_warn(LD_APP, "Couldn't get requesting address.");
    evdns_server_request_respond(req, DNS_ERR_SERVERFAILED);
    return;
  }
  sa = (struct sockaddr*) &addr;
  if (sa->sa_family != AF_INET) {
    /* XXXX020 Handle IPV6 */
    log_warn(LD_APP, "Requesting address wasn't ipv4.");
    evdns_server_request_respond(req, DNS_ERR_SERVERFAILED);
    return;
  } else {
    struct sockaddr_in *sin = (struct sockaddr_in*)&addr;
    ipaddr = ntohl(sin->sin_addr.s_addr);
  }
  if (!socks_policy_permits_address(ipaddr)) {
    log_warn(LD_APP, "Rejecting DNS request from disallowed IP.");
    evdns_server_request_respond(req, DNS_ERR_REFUSED);
    return;
  }
  if (req->nquestions == 0) {
    log_info(LD_APP, "No questions in DNS request; sending back nil reply.");
    evdns_server_request_respond(req, 0);
    return;
  }
  if (req->nquestions > 1) {
    log_info(LD_APP, "Got a DNS request with more than one question; I only "
             "handle one question at a time for now.  Skipping the extras.");
  }
  for (i = 0; i < req->nquestions; ++i) {
    if (req->questions[i]->class != EVDNS_CLASS_INET)
      continue;
    switch (req->questions[i]->type) {
      case EVDNS_TYPE_A:
      case EVDNS_TYPE_PTR:
        q = req->questions[i];
      default:
        break;
      }
  }
  if (!q) {
    log_info(LD_APP, "None of the questions we got were ones we're willing "
             "to support. Sending error.");
    evdns_server_request_respond(req, DNS_ERR_NOTIMPL);
    return;
  }
  if (q->type == EVDNS_TYPE_A) {
    if (hostname_is_noconnect_address(q->name)) {
      err = DNS_ERR_REFUSED;
    }
  } else {
    tor_assert(q->type == EVDNS_TYPE_PTR);
  }
  if (err == DNS_ERR_NONE && strlen(q->name) > MAX_SOCKS_ADDR_LEN-1)
    err = DNS_ERR_FORMAT;

  if (err != DNS_ERR_NONE) {
    evdns_server_request_respond(req, err);
    return;
  }

  /* XXXX020 Send a stream event to the controller. */

  conn = TO_EDGE_CONN(connection_new(CONN_TYPE_AP));
  conn->_base.state = AP_CONN_STATE_RESOLVE_WAIT;
  if (q->type == EVDNS_TYPE_A)
    conn->socks_request->command = SOCKS_COMMAND_RESOLVE;
  else
    conn->socks_request->command = SOCKS_COMMAND_RESOLVE_PTR;

  strlcpy(conn->socks_request->address, q->name,
          sizeof(conn->socks_request->address));

  conn->dns_server_request = req;

  log_info(LD_APP, "Passing request for %s to rewrite_and_attach.", q->name);
  connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);
  /* Now the connection is marked if it was bad. */

  log_info(LD_APP, "Passed request for %s to rewrite_and_attach.", q->name);
}

void
dnsserv_reject_request(edge_connection_t *conn)
{
  evdns_server_request_respond(conn->dns_server_request, DNS_ERR_SERVERFAILED);
  conn->dns_server_request = NULL;
}

void
dnsserv_resolved(edge_connection_t *conn,
                 int answer_type,
                 size_t answer_len,
                 const char *answer,
                 int ttl)
{
  struct evdns_server_request *req = conn->dns_server_request;
  int err = DNS_ERR_NONE;
  if (!req)
    return;

  /* XXXX Re-do. */
  if (ttl < 60)
    ttl = 60;

  if (answer_type == RESOLVED_TYPE_IPV6) {
    log_info(LD_APP, "Got an IPv6 answer; that's not implemented.");
    err = DNS_ERR_NOTIMPL;
  } else if (answer_type == RESOLVED_TYPE_IPV4 && answer_len == 4 &&
             conn->socks_request->command == SOCKS_COMMAND_RESOLVE) {
    evdns_server_request_add_a_reply(req,
                                     conn->socks_request->address,
                                     1, (char*)answer, ttl);
  } else if (answer_type == RESOLVED_TYPE_HOSTNAME &&
             conn->socks_request->command == SOCKS_COMMAND_RESOLVE_PTR) {
    char *ans = tor_strndup(answer, answer_len);
    evdns_server_request_add_ptr_reply(req, NULL,
                                       conn->socks_request->address,
                                       (char*)answer, ttl);
    tor_free(ans);
  } else {
    err = DNS_ERR_SERVERFAILED;
  }

  evdns_server_request_respond(req, err);
  conn->dns_server_request = NULL;
}

void
dnsserv_configure_listener(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->s);

  evdns_add_server_port(conn->s, 0, evdns_server_callback, NULL);
}

void
dnsserv_close_listener(connection_t *conn)
{
  evdns_close_server_port(conn->dns_server_port);
  conn->dns_server_port = NULL;
}

