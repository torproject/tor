/* Copyright (c) 2014-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/** Some constants used by test_connection and helpers */
#define TEST_CONN_FAMILY        (AF_INET)
#define TEST_CONN_ADDRESS       "127.0.0.1"
#define TEST_CONN_PORT          (12345)
#define TEST_CONN_ADDRESS_PORT  "127.0.0.1:12345"
#define TEST_CONN_FD_INIT 50

void test_conn_lookup_addr_helper(const char *address,
                                  int family, tor_addr_t *addr);

