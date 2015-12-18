/* Copyright (c) 2014, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define ROUTERLIST_PRIVATE
#include "or.h"
#include "routerlist.h"
#include "directory.h"
#include "connection.h"
#include "test.h"

/* 4 digests + 3 sep + pre + post + NULL */
static char output[4*BASE64_DIGEST256_LEN+3+2+2+1];

static void
mock_get_from_dirserver(uint8_t dir_purpose, uint8_t router_purpose,
                        const char *resource, int pds_flags,
                        download_want_authority_t want_authority)
{
  (void)dir_purpose;
  (void)router_purpose;
  (void)pds_flags;
  (void)want_authority;
  tt_assert(resource);
  strlcpy(output, resource, sizeof(output));
 done:
  ;
}

static void
test_routerlist_initiate_descriptor_downloads(void *arg)
{
  const char *prose = "unhurried and wise, we perceive.";
  smartlist_t *digests = smartlist_new();
  (void)arg;

  for (int i = 0; i < 20; i++) {
    smartlist_add(digests, (char*)prose);
  }

  MOCK(directory_get_from_dirserver, mock_get_from_dirserver);
  initiate_descriptor_downloads(NULL, DIR_PURPOSE_FETCH_MICRODESC,
                                digests, 3, 7, 0);
  UNMOCK(directory_get_from_dirserver);

  tt_str_op(output, OP_EQ, "d/"
            "dW5odXJyaWVkIGFuZCB3aXNlLCB3ZSBwZXJjZWl2ZS4-"
            "dW5odXJyaWVkIGFuZCB3aXNlLCB3ZSBwZXJjZWl2ZS4-"
            "dW5odXJyaWVkIGFuZCB3aXNlLCB3ZSBwZXJjZWl2ZS4-"
            "dW5odXJyaWVkIGFuZCB3aXNlLCB3ZSBwZXJjZWl2ZS4"
            ".z");

 done:
  smartlist_free(digests);
}

static int count = 0;

static void
mock_initiate_descriptor_downloads(const routerstatus_t *source,
                                   int purpose, smartlist_t *digests,
                                   int lo, int hi, int pds_flags)
{
  (void)source;
  (void)purpose;
  (void)digests;
  (void)pds_flags;
  (void)hi;
  (void)lo;
  count += 1;
}

static void
test_routerlist_launch_descriptor_downloads(void *arg)
{
  smartlist_t *downloadable = smartlist_new();
  time_t now = time(NULL);
  char *cp;
  (void)arg;

  for (int i = 0; i < 100; i++) {
    cp = tor_malloc(DIGEST256_LEN);
    tt_assert(cp);
    crypto_rand(cp, DIGEST256_LEN);
    smartlist_add(downloadable, cp);
  }

  MOCK(initiate_descriptor_downloads, mock_initiate_descriptor_downloads);
  launch_descriptor_downloads(DIR_PURPOSE_FETCH_MICRODESC, downloadable,
                              NULL, now);
  tt_int_op(3, ==, count);
  UNMOCK(initiate_descriptor_downloads);

 done:
  SMARTLIST_FOREACH(downloadable, char *, cp1, tor_free(cp1));
  smartlist_free(downloadable);
}

connection_t *mocked_connection = NULL;

/* Mock connection_get_by_type_addr_port_purpose by returning
 * mocked_connection. */
static connection_t *
mock_connection_get_by_type_addr_port_purpose(int type,
                                              const tor_addr_t *addr,
                                              uint16_t port, int purpose)
{
  (void)type;
  (void)addr;
  (void)port;
  (void)purpose;

  return mocked_connection;
}

#define TEST_ADDR_STR "127.0.0.1"
#define TEST_DIR_PORT 12345

static void
test_routerlist_router_is_already_dir_fetching(void *arg)
{
  (void)arg;
  tor_addr_port_t test_ap, null_addr_ap, zero_port_ap;

  /* Setup */
  tor_addr_parse(&test_ap.addr, TEST_ADDR_STR);
  test_ap.port = TEST_DIR_PORT;
  tor_addr_make_null(&null_addr_ap.addr, AF_INET6);
  null_addr_ap.port = TEST_DIR_PORT;
  tor_addr_parse(&zero_port_ap.addr, TEST_ADDR_STR);
  zero_port_ap.port = 0;
  MOCK(connection_get_by_type_addr_port_purpose,
       mock_connection_get_by_type_addr_port_purpose);

  /* Test that we never get 1 from a NULL connection */
  mocked_connection = NULL;
  tt_assert(router_is_already_dir_fetching(&test_ap, 1, 1) == 0);
  tt_assert(router_is_already_dir_fetching(&test_ap, 1, 0) == 0);
  tt_assert(router_is_already_dir_fetching(&test_ap, 0, 1) == 0);
  /* We always expect 0 in these cases */
  tt_assert(router_is_already_dir_fetching(&test_ap, 0, 0) == 0);
  tt_assert(router_is_already_dir_fetching(NULL, 1, 1) == 0);
  tt_assert(router_is_already_dir_fetching(&null_addr_ap, 1, 1) == 0);
  tt_assert(router_is_already_dir_fetching(&zero_port_ap, 1, 1) == 0);

  /* Test that we get 1 with a connection in the appropriate circumstances */
  mocked_connection = connection_new(CONN_TYPE_DIR, AF_INET);
  tt_assert(router_is_already_dir_fetching(&test_ap, 1, 1) == 1);
  tt_assert(router_is_already_dir_fetching(&test_ap, 1, 0) == 1);
  tt_assert(router_is_already_dir_fetching(&test_ap, 0, 1) == 1);

  /* Test that we get 0 even with a connection in the appropriate
   * circumstances */
  tt_assert(router_is_already_dir_fetching(&test_ap, 0, 0) == 0);
  tt_assert(router_is_already_dir_fetching(NULL, 1, 1) == 0);
  tt_assert(router_is_already_dir_fetching(&null_addr_ap, 1, 1) == 0);
  tt_assert(router_is_already_dir_fetching(&zero_port_ap, 1, 1) == 0);

 done:
  /* If a connection is never set up, connection_free chokes on it. */
  buf_free(mocked_connection->inbuf);
  buf_free(mocked_connection->outbuf);
  tor_free(mocked_connection);
  UNMOCK(connection_get_by_type_addr_port_purpose);
}

#undef TEST_ADDR_STR
#undef TEST_DIR_PORT

#define NODE(name, flags) \
  { #name, test_routerlist_##name, (flags), NULL, NULL }

struct testcase_t routerlist_tests[] = {
  NODE(initiate_descriptor_downloads, 0),
  NODE(launch_descriptor_downloads, 0),
  NODE(router_is_already_dir_fetching, TT_FORK),
  END_OF_TESTCASES
};

