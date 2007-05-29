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

/* Helper function: called by evdns whenever the client sends a request to our
 * DNSPort.  We need to eventually answer the request <b>req</b>.
 */
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
  char *q_name;

  tor_assert(req);
  tor_assert(_data == NULL);
  log_info(LD_APP, "Got a new DNS request!");

  /* First, check whether the requesting address matches our SOCKSPolicy. */
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

  /* Now, let's find the first actual question of a type we can answer in this
   * DNS request.  It makes us a little noncompliant to act like this; we
   * should fix that eventually if it turns out to make a difference for
   * anybody. */
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
    /* Refuse any attempt to resolve a noconnect address, right now. */
    if (hostname_is_noconnect_address(q->name)) {
      err = DNS_ERR_REFUSED;
    }
  } else {
    tor_assert(q->type == EVDNS_TYPE_PTR);
  }

  /* Make sure the name isn't too long: This should be impossible, I think. */
  if (err == DNS_ERR_NONE && strlen(q->name) > MAX_SOCKS_ADDR_LEN-1)
    err = DNS_ERR_FORMAT;

  if (err != DNS_ERR_NONE) {
    /* We got an error?  Then send back an answer immediately; we're done. */
    evdns_server_request_respond(req, err);
    return;
  }

  /* XXXX020 Send a stream event to the controller. */

  /* Make a new dummy AP connection, and attach the request to it. */
  conn = TO_EDGE_CONN(connection_new(CONN_TYPE_AP));
  conn->_base.state = AP_CONN_STATE_RESOLVE_WAIT;
  if (q->type == EVDNS_TYPE_A)
    conn->socks_request->command = SOCKS_COMMAND_RESOLVE;
  else
    conn->socks_request->command = SOCKS_COMMAND_RESOLVE_PTR;

  strlcpy(conn->socks_request->address, q->name,
          sizeof(conn->socks_request->address));

  conn->dns_server_request = req;

  /* Now, throw the connection over to get rewritten (which will answer it
  * immediately if it's in the cache, or completely bogus, or automapped),
  * and then attached to a circuit. */
  log_info(LD_APP, "Passing request for %s to rewrite_and_attach.",
           escaped_safe_str(q->name));
  q_name = tor_strdup(q->name); /* q could be freed in rewrite_and_attach */
  connection_ap_handshake_rewrite_and_attach(conn, NULL, NULL);
  /* Now, the connection is marked if it was bad. */

  log_info(LD_APP, "Passed request for %s to rewrite_and_attach.",
           escaped_safe_str(q_name));
  tor_free(q_name);
}

/** If there is a pending request on <b>conn</b> that's waiting for an answer,
 * send back an error and free the request. */
void
dnsserv_reject_request(edge_connection_t *conn)
{
  if (conn->dns_server_request) {
    evdns_server_request_respond(conn->dns_server_request,
                                 DNS_ERR_SERVERFAILED);
    conn->dns_server_request = NULL;
  }
}

/** Tell the dns request waiting for an answer on <b>conn</b> that we have an
 * answer of type <b>answer_type</b> (RESOLVE_TYPE_IPV4/IPV6/ERR), of length
 * <b>answer_len</b>, in <b>answer</b>, with TTL <b>ttl</b>.  Doesn't do
 * any caching; that's handled elsewhere. */
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

  /* XXXX020 Re-do; this is dumb. */
  if (ttl < 60)
    ttl = 60;

  /* The evdns interface is: add a bunch of reply items (corresponding to one
   * or more of the questions in the request); then, call
   * evdns_server_request_respond. */
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
    err = DNS_ERR_SERVERFAILED; /* Really? Not noent? */
  }

  evdns_server_request_respond(req, err);
  conn->dns_server_request = NULL;
}

/* Set up the evdns server port for the UDP socket on <b>conn</b>, which
 * must be an AP_DNS_LISTENER */
void
dnsserv_configure_listener(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->s);
  tor_assert(conn->type == CONN_TYPE_AP_DNS_LISTENER);

  evdns_add_server_port(conn->s, 0, evdns_server_callback, NULL);
}

/** Free the evdns server port for <b>conn</b>, which must be an
 * AP_DNS_LISTENER. */
void
dnsserv_close_listener(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_AP_DNS_LISTENER);

  if (conn->dns_server_port) {
    evdns_close_server_port(conn->dns_server_port);
    conn->dns_server_port = NULL;
  }
}

