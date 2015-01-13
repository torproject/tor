/* Copyright (c) 2014-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"

#define CONNECTION_PRIVATE
#define CONNECTION_EDGE_PRIVATE

#include "or.h"
#include "test.h"

#include "addressmap.h"
#include "config.h"
#include "connection.h"
#include "connection_edge.h"

static void *
entryconn_rewrite_setup(const struct testcase_t *tc)
{
  (void)tc;
  entry_connection_t *ec = entry_connection_new(CONN_TYPE_AP, AF_INET);
  addressmap_init();
  return ec;
}

static int
entryconn_rewrite_teardown(const struct testcase_t *tc, void *arg)
{
  (void)tc;
  entry_connection_t *ec = arg;
  if (ec)
    connection_free_(ENTRY_TO_CONN(ec));
  addressmap_free_all();
  return 1;
}

static struct testcase_setup_t test_rewrite_setup = {
  entryconn_rewrite_setup, entryconn_rewrite_teardown
};

/* Simple rewrite: no changes needed */
static void
test_entryconn_rewrite_basic(void *arg)
{
  entry_connection_t *ec = arg;
  rewrite_result_t rr;

  tt_assert(ec->socks_request);
  strlcpy(ec->socks_request->address, "www.TORproject.org",
          sizeof(ec->socks_request->address));
  ec->socks_request->command = SOCKS_COMMAND_CONNECT;
  connection_ap_handshake_rewrite(ec, &rr);

  tt_int_op(rr.should_close, OP_EQ, 0);
  tt_int_op(rr.end_reason, OP_EQ, 0);
  tt_int_op(rr.automap, OP_EQ, 0);
  tt_i64_op(rr.map_expires, OP_EQ, TIME_MAX);
  tt_int_op(rr.exit_source, OP_EQ, ADDRMAPSRC_NONE);
  tt_str_op(rr.orig_address, OP_EQ, "www.torproject.org");
  tt_str_op(ec->socks_request->address, OP_EQ, "www.torproject.org");
  tt_str_op(ec->original_dest_address, OP_EQ, "www.torproject.org");

 done:
  ;
}

/* Rewrite but reject because of disallowed .exit */
static void
test_entryconn_rewrite_bad_dotexit(void *arg)
{
  entry_connection_t *ec = arg;
  rewrite_result_t rr;

  get_options_mutable()->AllowDotExit = 0;
  tt_assert(ec->socks_request);
  strlcpy(ec->socks_request->address, "www.TORproject.org.foo.exit",
          sizeof(ec->socks_request->address));
  ec->socks_request->command = SOCKS_COMMAND_CONNECT;
  connection_ap_handshake_rewrite(ec, &rr);

  tt_int_op(rr.should_close, OP_EQ, 1);
  tt_int_op(rr.end_reason, OP_EQ, END_STREAM_REASON_TORPROTOCOL);

 done:
  ;
}

/* Automap on resolve, connect to automapped address, resolve again and get
 * same answer. (IPv4) */
static void
test_entryconn_rewrite_automap_ipv4(void *arg)
{
  entry_connection_t *ec = arg;
  entry_connection_t *ec2=NULL, *ec3=NULL;
  rewrite_result_t rr;
  char *msg = NULL;

  ec2 = entry_connection_new(CONN_TYPE_AP, AF_INET);
  ec3 = entry_connection_new(CONN_TYPE_AP, AF_INET);

  get_options_mutable()->AutomapHostsOnResolve = 1;
  get_options_mutable()->AutomapHostsSuffixes = smartlist_new();
  smartlist_add(get_options_mutable()->AutomapHostsSuffixes, tor_strdup("."));
  parse_virtual_addr_network("127.202.0.0/16", AF_INET, 0, &msg);

  /* Automap this on resolve. */
  strlcpy(ec->socks_request->address, "WWW.MIT.EDU",
          sizeof(ec->socks_request->address));
  ec->socks_request->command = SOCKS_COMMAND_RESOLVE;
  connection_ap_handshake_rewrite(ec, &rr);

  tt_int_op(rr.automap, OP_EQ, 1);
  tt_int_op(rr.should_close, OP_EQ, 0);
  tt_int_op(rr.end_reason, OP_EQ, 0);
  tt_i64_op(rr.map_expires, OP_EQ, TIME_MAX);
  tt_int_op(rr.exit_source, OP_EQ, ADDRMAPSRC_NONE);
  tt_str_op(rr.orig_address, OP_EQ, "www.mit.edu");
  tt_str_op(ec->original_dest_address, OP_EQ, "www.mit.edu");

  tt_assert(!strcmpstart(ec->socks_request->address,"127.202."));

  /* Connect to it and make sure we get the original address back. */
  strlcpy(ec2->socks_request->address, ec->socks_request->address,
          sizeof(ec2->socks_request->address));

  ec2->socks_request->command = SOCKS_COMMAND_CONNECT;
  connection_ap_handshake_rewrite(ec2, &rr);

  tt_int_op(rr.automap, OP_EQ, 0);
  tt_int_op(rr.should_close, OP_EQ, 0);
  tt_int_op(rr.end_reason, OP_EQ, 0);
  tt_i64_op(rr.map_expires, OP_EQ, TIME_MAX);
  tt_int_op(rr.exit_source, OP_EQ, ADDRMAPSRC_NONE);
  tt_str_op(rr.orig_address, OP_EQ, ec->socks_request->address);
  tt_str_op(ec2->original_dest_address, OP_EQ, ec->socks_request->address);
  tt_str_op(ec2->socks_request->address, OP_EQ, "www.mit.edu");

  /* Resolve it again, make sure the answer is the same. */
  strlcpy(ec3->socks_request->address, "www.MIT.EDU",
          sizeof(ec3->socks_request->address));
  ec3->socks_request->command = SOCKS_COMMAND_RESOLVE;
  connection_ap_handshake_rewrite(ec3, &rr);

  tt_int_op(rr.automap, OP_EQ, 1);
  tt_int_op(rr.should_close, OP_EQ, 0);
  tt_int_op(rr.end_reason, OP_EQ, 0);
  tt_i64_op(rr.map_expires, OP_EQ, TIME_MAX);
  tt_int_op(rr.exit_source, OP_EQ, ADDRMAPSRC_NONE);
  tt_str_op(rr.orig_address, OP_EQ, "www.mit.edu");
  tt_str_op(ec3->original_dest_address, OP_EQ, "www.mit.edu");

  tt_str_op(ec3->socks_request->address, OP_EQ,
            ec->socks_request->address);

 done:
  connection_free_(ENTRY_TO_CONN(ec2));
  connection_free_(ENTRY_TO_CONN(ec3));
}

/* Automap on resolve, connect to automapped address, resolve again and get
 * same answer. (IPv6) */
static void
test_entryconn_rewrite_automap_ipv6(void *arg)
{
  entry_connection_t *ec = arg;
  entry_connection_t *ec2=NULL, *ec3=NULL;
  rewrite_result_t rr;
  char *msg = NULL;
  connection_free_(ENTRY_TO_CONN(ec));
  ec2 = entry_connection_new(CONN_TYPE_AP, AF_INET6);
  ec2 = entry_connection_new(CONN_TYPE_AP, AF_INET6);
  ec3 = entry_connection_new(CONN_TYPE_AP, AF_INET6);

  get_options_mutable()->AutomapHostsOnResolve = 1;
  get_options_mutable()->AutomapHostsSuffixes = smartlist_new();
  smartlist_add(get_options_mutable()->AutomapHostsSuffixes, tor_strdup("."));
  parse_virtual_addr_network("FE80::/32", AF_INET6, 0, &msg);

  /* Automap this on resolve. */
  strlcpy(ec->socks_request->address, "WWW.MIT.EDU",
          sizeof(ec->socks_request->address));
  ec->socks_request->command = SOCKS_COMMAND_RESOLVE;
  connection_ap_handshake_rewrite(ec, &rr);

  tt_int_op(rr.automap, OP_EQ, 1);
  tt_int_op(rr.should_close, OP_EQ, 0);
  tt_int_op(rr.end_reason, OP_EQ, 0);
  tt_i64_op(rr.map_expires, OP_EQ, TIME_MAX);
  tt_int_op(rr.exit_source, OP_EQ, ADDRMAPSRC_NONE);
  tt_str_op(rr.orig_address, OP_EQ, "www.mit.edu");
  tt_str_op(ec->original_dest_address, OP_EQ, "www.mit.edu");

  printf("<%s>\n", ec->socks_request->address);
  /* XXXX Should this [ be here? */
  tt_assert(!strcmpstart(ec->socks_request->address,"[fe80:"));

  /* Connect to it and make sure we get the original address back. */
  strlcpy(ec2->socks_request->address, ec->socks_request->address,
          sizeof(ec2->socks_request->address));

  ec2->socks_request->command = SOCKS_COMMAND_CONNECT;
  connection_ap_handshake_rewrite(ec2, &rr);

  tt_int_op(rr.automap, OP_EQ, 0);
  tt_int_op(rr.should_close, OP_EQ, 0);
  tt_int_op(rr.end_reason, OP_EQ, 0);
  tt_i64_op(rr.map_expires, OP_EQ, TIME_MAX);
  tt_int_op(rr.exit_source, OP_EQ, ADDRMAPSRC_NONE);
  tt_str_op(rr.orig_address, OP_EQ, ec->socks_request->address);
  tt_str_op(ec2->original_dest_address, OP_EQ, ec->socks_request->address);
  tt_str_op(ec2->socks_request->address, OP_EQ, "www.mit.edu");

  /* Resolve it again, make sure the answer is the same. */
  strlcpy(ec3->socks_request->address, "www.MIT.EDU",
          sizeof(ec3->socks_request->address));
  ec3->socks_request->command = SOCKS_COMMAND_RESOLVE;
  connection_ap_handshake_rewrite(ec3, &rr);

  tt_int_op(rr.automap, OP_EQ, 1);
  tt_int_op(rr.should_close, OP_EQ, 0);
  tt_int_op(rr.end_reason, OP_EQ, 0);
  tt_i64_op(rr.map_expires, OP_EQ, TIME_MAX);
  tt_int_op(rr.exit_source, OP_EQ, ADDRMAPSRC_NONE);
  tt_str_op(rr.orig_address, OP_EQ, "www.mit.edu");
  tt_str_op(ec3->original_dest_address, OP_EQ, "www.mit.edu");

  tt_str_op(ec3->socks_request->address, OP_EQ,
            ec->socks_request->address);

 done:
  connection_free_(ENTRY_TO_CONN(ec2));
  connection_free_(ENTRY_TO_CONN(ec3));
}

/* automap on resolve, reverse lookup. */

/* Rewrite because of cached DNS entry. */

/* Rewrite because of AddrmapRewrite option */

/* Rewrite because of control port */

/* Rewrite into .exit because of virtual address mapping */

/* Rewrite into .exit because of mapaddress */

/* Fail to connect to unmapped address in virtual range. */

/* Rewrite plus automap */

/* Map foo.onion to longthing.onion */



#define REWRITE(name)                           \
  { #name, test_entryconn_##name, TT_FORK, &test_rewrite_setup, NULL }

struct testcase_t entryconn_tests[] = {
  REWRITE(rewrite_basic),
  REWRITE(rewrite_bad_dotexit),
  REWRITE(rewrite_automap_ipv4),
  REWRITE(rewrite_automap_ipv6),
  END_OF_TESTCASES
};

