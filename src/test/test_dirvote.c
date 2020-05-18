/* Copyright (c) 2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_dirvote.c
 * \brief Unit tests for dirvote related functions
 */
#define DIRVOTE_PRIVATE

#include "tinytest.h"
#include "core/or/or.h"
#include "feature/dirauth/dirvote.h"
#include "feature/nodelist/dirlist.h"
#include "feature/nodelist/node_st.h"
#include "feature/nodelist/nodelist.h"
#include "feature/nodelist/routerinfo_st.h"
#include "feature/nodelist/signed_descriptor_st.h"
#include "tinytest_macros.h"

/**
 * This struct holds the various informations that are needed for router
 * comparison. Each router in the test function has one, and they are all
 * put in a global digestmap, router_properties
 */
typedef struct router_values {
  int is_running;
  int is_auth;
  int bw_kb;
  char digest[DIGEST_LEN];
} router_values;
/**
 * This typedef makes declaring digests easier and less verbose
 */
typedef char tor_digest[DIGEST_LEN];

// Use of global variable is justified because the functions that have to be
// mocked take as arguments objects we have no control over
digestmap_t *router_properties = NULL;
// Use of global variable is justified by its use in nodelist.c
// and is necessary to avoid memory leaks when mocking the
// function node_get_by_id
node_t *running_node;
node_t *non_running_node;

int mock_router_digest_is_trusted(const char *digest, dirinfo_type_t type);
int
mock_router_digest_is_trusted(const char *digest, dirinfo_type_t type)
{
  (void)type;
  router_values *status;
  status = digestmap_get(router_properties, digest);
  if (!status) {
    return -1;
  }
  return status->is_auth;
}

const node_t *mock_node_get_by_id(const char *identity_digest);
const node_t *
mock_node_get_by_id(const char *identity_digest)
{
  router_values *status;
  status = digestmap_get(router_properties, identity_digest);
  if (!status) {
    return NULL;
  }
  if (status->is_running)
    return running_node;
  else
    return non_running_node;
}

uint32_t mock_dirserv_get_bw(const routerinfo_t *ri);
uint32_t
mock_dirserv_get_bw(const routerinfo_t *ri)
{
  const char *digest = ri->cache_info.identity_digest;
  router_values *status;
  status = digestmap_get(router_properties, digest);
  if (!status) {
    return -1;
  }
  return status->bw_kb;
}

router_values *router_values_new(int running, int auth, int bw, char *digest);
/** Generate a pointer to a router_values struct with the arguments as
 * field values, and return it
 * The returned pointer has to be freed by the caller.
 */
router_values *
router_values_new(int running, int auth, int bw, char *digest)
{
  router_values *status = tor_malloc(sizeof(router_values));
  memcpy(status->digest, digest, sizeof(status->digest));
  status->is_running = running;
  status->bw_kb = bw;
  status->is_auth = auth;
  return status;
}

routerinfo_t *routerinfo_new(router_values *status, int family, int addr);
/** Given a router_values struct, generate a pointer to a routerinfo struct.
 * In the cache_info member, put the identity digest, and depending on
 * the family argument, fill the IPv4 or IPv6 address. Return the pointer.
 * The returned pointer has to be freed by the caller.
 */
routerinfo_t *
routerinfo_new(router_values *status, int family, int addr)
{
  routerinfo_t *ri = tor_malloc(sizeof(routerinfo_t));
  signed_descriptor_t cache_info;
  memcpy(cache_info.identity_digest, status->digest,
         sizeof(cache_info.identity_digest));
  ri->cache_info = cache_info;
  tor_addr_t ipv6;
  ipv6.family = family;
  if (family == AF_INET) {
    ri->addr = addr;
  } else {
    for (size_t i = 0; i < 16; i++) {
      ipv6.addr.in6_addr.s6_addr[i] = addr;
    }
  }
  ri->ipv6_addr = ipv6;
  return ri;
}

static void
test_dirvote_compare_routerinfo_usefulness(void *arg)
{
  (void)arg;
  MOCK(router_digest_is_trusted_dir_type, mock_router_digest_is_trusted);
  MOCK(node_get_by_id, mock_node_get_by_id);
  MOCK(dirserv_get_bandwidth_for_router_kb, mock_dirserv_get_bw);

  running_node = tor_malloc(sizeof(node_t));
  running_node->is_running = 1;
  non_running_node = tor_malloc(sizeof(node_t));
  non_running_node->is_running = 0;
  router_properties = digestmap_new();

  // Maybe can be cleaner using macros ?
  // The router one is the "least useful" router, every router is compared to
  // it
  tor_digest digest_one = "aaaa";
  router_values *status_one = router_values_new(0, 0, 0, digest_one);
  digestmap_set(router_properties, status_one->digest, status_one);
  tor_digest digest_two = "bbbb";
  router_values *status_two = router_values_new(0, 1, 0, digest_two);
  digestmap_set(router_properties, status_two->digest, status_two);
  tor_digest digest_three = "cccc";
  router_values *status_three = router_values_new(1, 0, 0, digest_three);
  digestmap_set(router_properties, status_three->digest, status_three);
  tor_digest digest_four = "dddd";
  router_values *status_four = router_values_new(0, 0, 128, digest_four);
  digestmap_set(router_properties, status_four->digest, status_four);
  tor_digest digest_five = "9999";
  router_values *status_five = router_values_new(0, 0, 0, digest_five);
  digestmap_set(router_properties, status_five->digest, status_five);

  // A router that has auth status is more useful than a non-auth one
  routerinfo_t *first = routerinfo_new(status_one, AF_INET, 0xf);
  routerinfo_t *second = routerinfo_new(status_two, AF_INET, 0xf);
  int a = compare_routerinfo_usefulness((const void **)&first,
                                        (const void **)&second);
  tt_assert(a == 1);

  // A running router is more useful than a non running one
  routerinfo_t *third = routerinfo_new(status_three, AF_INET, 0xf);
  a = compare_routerinfo_usefulness((const void **)&first,
                                    (const void **)&third);
  tt_assert(a == 1);

  // A higher bandwidth is more useful
  routerinfo_t *fourth = routerinfo_new(status_four, AF_INET, 0xf);
  a = compare_routerinfo_usefulness((const void **)&first,
                                    (const void **)&fourth);
  tt_assert(a == 1);

  // In case of tie, the digests are compared
  routerinfo_t *fifth = routerinfo_new(status_five, AF_INET, 0xf);
  a = compare_routerinfo_usefulness((const void **)&first,
                                    (const void **)&fifth);
  tt_assert(a > 0);

end:
  UNMOCK(router_digest_is_trusted_dir_type);
  UNMOCK(node_get_by_id);
  UNMOCK(dirserv_get_bandwidth_for_router_kb);
  tor_free(running_node);
  tor_free(non_running_node);
  tor_free(router_properties);
  tor_free(status_one);
  tor_free(status_two);
  tor_free(status_three);
  tor_free(status_four);
  tor_free(status_five);
  tor_free(first);
  tor_free(second);
  tor_free(third);
  tor_free(fourth);
  tor_free(fifth);
}

static void
test_dirvote_compare_routerinfo_by_ipv4(void *arg)
{
  (void)arg;
  MOCK(router_digest_is_trusted_dir_type, mock_router_digest_is_trusted);
  MOCK(node_get_by_id, mock_node_get_by_id);
  MOCK(dirserv_get_bandwidth_for_router_kb, mock_dirserv_get_bw);

  running_node = tor_malloc(sizeof(node_t));
  running_node->is_running = 1;
  non_running_node = tor_malloc(sizeof(node_t));
  non_running_node->is_running = 0;
  router_properties = digestmap_new();
  tor_digest digest_one = "aaaa";
  router_values *status_one = router_values_new(0, 0, 0, digest_one);
  digestmap_set(router_properties, status_one->digest, status_one);
  tor_digest digest_two = "bbbb";
  router_values *status_two = router_values_new(0, 1, 0, digest_two);
  digestmap_set(router_properties, status_two->digest, status_two);

  // Both routers have an IPv4 address
  routerinfo_t *first = routerinfo_new(status_one, AF_INET, 1);
  routerinfo_t *second = routerinfo_new(status_two, AF_INET, 0xf);

  // The first argument's address precedes the seconds' one
  int a = compare_routerinfo_by_ipv4((const void **)&first,
                                     (const void **)&second);
  tt_assert(a < 0);
  // The second argument's address precedes the first' one
  a = compare_routerinfo_by_ipv4((const void **)&second,
                                 (const void **)&first);
  tt_assert(a > 0);
  first->addr = second->addr;
  // The addresses are equal, they are compared by usefulness,
  // and first is less useful than second
  a = compare_routerinfo_by_ipv4((const void **)&first,
                                 (const void **)&second);
  tt_assert(a == 1);
end:
  UNMOCK(router_digest_is_trusted_dir_type);
  UNMOCK(node_get_by_id);
  UNMOCK(dirserv_get_bandwidth_for_router_kb);
  tor_free(running_node);
  tor_free(non_running_node);
  tor_free(router_properties);
  tor_free(status_one);
  tor_free(status_two);
  tor_free(first);
  tor_free(second);
};

static void
test_dirvote_compare_routerinfo_by_ipv6(void *arg)
{
  (void)arg;
  MOCK(router_digest_is_trusted_dir_type, mock_router_digest_is_trusted);
  MOCK(node_get_by_id, mock_node_get_by_id);
  MOCK(dirserv_get_bandwidth_for_router_kb, mock_dirserv_get_bw);

  running_node = tor_malloc(sizeof(node_t));
  running_node->is_running = 1;
  non_running_node = tor_malloc(sizeof(node_t));
  non_running_node->is_running = 0;
  router_properties = digestmap_new();
  char digest_one[DIGEST_LEN] = "aaaa";
  router_values *status_one = router_values_new(0, 0, 0, digest_one);
  digestmap_set(router_properties, status_one->digest, status_one);
  char digest_two[DIGEST_LEN] = "bbbb";
  router_values *status_two = router_values_new(0, 1, 0, digest_two);
  digestmap_set(router_properties, status_two->digest, status_two);

  // Both routers have an IPv6 address
  routerinfo_t *first = routerinfo_new(status_one, AF_INET6, 1);
  routerinfo_t *second = routerinfo_new(status_two, AF_INET6, 0xf);

  // The first argument's address precedes the seconds' one
  int a = compare_routerinfo_by_ipv6((const void **)&first,
                                     (const void **)&second);
  tt_assert(a < 0);
  // The second argument's address precedes the first' one
  a = compare_routerinfo_by_ipv6((const void **)&second,
                                 (const void **)&first);
  tt_assert(a > 0);
  tor_addr_copy(&(first->ipv6_addr), &(second->ipv6_addr));
  // The addresses are equal, they are compared by usefulness,
  // and first is less useful than second
  a = compare_routerinfo_by_ipv6((const void **)&first,
                                 (const void **)&second);
  tt_assert(a == 1);
end:
  UNMOCK(router_digest_is_trusted_dir_type);
  UNMOCK(node_get_by_id);
  UNMOCK(dirserv_get_bandwidth_for_router_kb);
  tor_free(running_node);
  tor_free(non_running_node);
  tor_free(router_properties);
  tor_free(status_one);
  tor_free(status_two);
  tor_free(first);
  tor_free(second);
};

/** Create routers values and routerinfos that always have the same
 * characteristics, and add them to the global digestmap. This macro is here to
 * avoid duplicated code fragments.
 */
#define CREATE_ROUTER(digest, name, addr, ip_version)                     \
  tor_digest name##_digest = digest;                                      \
  router_values *name##_val = router_values_new(1, 1, 1, name##_digest);  \
  digestmap_set(router_properties, name##_digest, name##_val);            \
  routerinfo_t *name##_ri = routerinfo_new(name##_val, ip_version, addr); \
  tor_free(name##_val);

/** Test to see if the returned routers are exactly the ones that should be
 * flagged as sybils : we test for inclusion then for number of elements
 */
#define TEST_SYBIL(true_sybil, possible_sybil)               \
  DIGESTMAP_FOREACH (true_sybil, sybil_id, void *, ignore) { \
    (void)ignore;                                            \
    tt_assert(digestmap_get(possible_sybil, sybil_id));      \
  }                                                          \
  DIGESTMAP_FOREACH_END;                                     \
  tt_assert(digestmap_size(true_sybil) == digestmap_size(possible_sybil));

static void
test_dirvote_get_sybil_by_ip_version_ipv4(void *arg)
{
  // It is assumed that global_dirauth_options.AuthDirMaxServersPerAddr == 2
  (void)arg;
  MOCK(router_digest_is_trusted_dir_type, mock_router_digest_is_trusted);
  MOCK(node_get_by_id, mock_node_get_by_id);
  MOCK(dirserv_get_bandwidth_for_router_kb, mock_dirserv_get_bw);
  running_node = tor_malloc(sizeof(node_t));
  running_node->is_running = 1;
  non_running_node = tor_malloc(sizeof(node_t));
  non_running_node->is_running = 0;
  router_properties = digestmap_new();
  smartlist_t *routers_ipv4;
  routers_ipv4 = smartlist_new();
  digestmap_t *true_sybil_routers = NULL;
  true_sybil_routers = digestmap_new();
  digestmap_t *omit_as_sybil;

  CREATE_ROUTER("aaaa", aaaa, 123, AF_INET);
  smartlist_add(routers_ipv4, aaaa_ri);
  CREATE_ROUTER("bbbb", bbbb, 123, AF_INET);
  smartlist_add(routers_ipv4, bbbb_ri);
  omit_as_sybil = get_sybil_list_by_ip_version(routers_ipv4, AF_INET);
  tt_assert(digestmap_isempty(omit_as_sybil) == 1);

  CREATE_ROUTER("cccc", cccc, 123, AF_INET);
  smartlist_add(routers_ipv4, cccc_ri);
  digestmap_set(true_sybil_routers, cccc_digest, cccc_digest);
  omit_as_sybil = get_sybil_list_by_ip_version(routers_ipv4, AF_INET);
  TEST_SYBIL(true_sybil_routers, omit_as_sybil);

  CREATE_ROUTER("dddd", dddd, 123, AF_INET);
  smartlist_add(routers_ipv4, dddd_ri);
  digestmap_set(true_sybil_routers, dddd_digest, dddd_digest);
  omit_as_sybil = get_sybil_list_by_ip_version(routers_ipv4, AF_INET);
  TEST_SYBIL(true_sybil_routers, omit_as_sybil);

  CREATE_ROUTER("eeee", eeee, 456, AF_INET);
  smartlist_add(routers_ipv4, eeee_ri);
  omit_as_sybil = get_sybil_list_by_ip_version(routers_ipv4, AF_INET);
  TEST_SYBIL(true_sybil_routers, omit_as_sybil);

  CREATE_ROUTER("ffff", ffff, 456, AF_INET);
  smartlist_add(routers_ipv4, ffff_ri);
  omit_as_sybil = get_sybil_list_by_ip_version(routers_ipv4, AF_INET);
  TEST_SYBIL(true_sybil_routers, omit_as_sybil);

  CREATE_ROUTER("gggg", gggg, 456, AF_INET);
  smartlist_add(routers_ipv4, gggg_ri);
  digestmap_set(true_sybil_routers, gggg_digest, gggg_digest);
  omit_as_sybil = get_sybil_list_by_ip_version(routers_ipv4, AF_INET);
  TEST_SYBIL(true_sybil_routers, omit_as_sybil);

  CREATE_ROUTER("hhhh", hhhh, 456, AF_INET);
  smartlist_add(routers_ipv4, hhhh_ri);
  digestmap_set(true_sybil_routers, hhhh_digest, hhhh_digest);
  omit_as_sybil = get_sybil_list_by_ip_version(routers_ipv4, AF_INET);
  TEST_SYBIL(true_sybil_routers, omit_as_sybil);

end:
  UNMOCK(router_digest_is_trusted_dir_type);
  UNMOCK(node_get_by_id);
  UNMOCK(dirserv_get_bandwidth_for_router_kb);
  tor_free(running_node);
  tor_free(non_running_node);
  tor_free(router_properties);
  tor_free(routers_ipv4);
  tor_free(omit_as_sybil);
  tor_free(true_sybil_routers);
}

static void
test_dirvote_get_sybil_by_ip_version_ipv6(void *arg)
{
  // It is assumed that global_dirauth_options.AuthDirMaxServersPerAddr == 2
  (void)arg;
  MOCK(router_digest_is_trusted_dir_type, mock_router_digest_is_trusted);
  MOCK(node_get_by_id, mock_node_get_by_id);
  MOCK(dirserv_get_bandwidth_for_router_kb, mock_dirserv_get_bw);
  running_node = tor_malloc(sizeof(node_t));
  running_node->is_running = 1;
  non_running_node = tor_malloc(sizeof(node_t));
  non_running_node->is_running = 0;
  router_properties = digestmap_new();
  smartlist_t *routers_ipv6;
  routers_ipv6 = smartlist_new();
  digestmap_t *true_sybil_routers = NULL;
  true_sybil_routers = digestmap_new();
  digestmap_t *omit_as_sybil;

  CREATE_ROUTER("aaaa", aaaa, 123, AF_INET6);
  smartlist_add(routers_ipv6, aaaa_ri);
  CREATE_ROUTER("bbbb", bbbb, 123, AF_INET6);
  smartlist_add(routers_ipv6, bbbb_ri);
  omit_as_sybil = get_sybil_list_by_ip_version(routers_ipv6, AF_INET6);
  TEST_SYBIL(true_sybil_routers, omit_as_sybil);

  CREATE_ROUTER("cccc", cccc, 123, AF_INET6);
  smartlist_add(routers_ipv6, cccc_ri);
  digestmap_set(true_sybil_routers, cccc_digest, cccc_digest);
  omit_as_sybil = get_sybil_list_by_ip_version(routers_ipv6, AF_INET6);
  TEST_SYBIL(true_sybil_routers, omit_as_sybil);

  CREATE_ROUTER("dddd", dddd, 123, AF_INET6);
  smartlist_add(routers_ipv6, dddd_ri);
  digestmap_set(true_sybil_routers, dddd_digest, dddd_digest);
  omit_as_sybil = get_sybil_list_by_ip_version(routers_ipv6, AF_INET6);
  TEST_SYBIL(true_sybil_routers, omit_as_sybil);

  CREATE_ROUTER("eeee", eeee, 456, AF_INET6);
  smartlist_add(routers_ipv6, eeee_ri);
  omit_as_sybil = get_sybil_list_by_ip_version(routers_ipv6, AF_INET6);
  TEST_SYBIL(true_sybil_routers, omit_as_sybil);

  CREATE_ROUTER("ffff", ffff, 456, AF_INET6);
  smartlist_add(routers_ipv6, ffff_ri);
  omit_as_sybil = get_sybil_list_by_ip_version(routers_ipv6, AF_INET6);
  TEST_SYBIL(true_sybil_routers, omit_as_sybil);

  CREATE_ROUTER("gggg", gggg, 456, AF_INET6);
  smartlist_add(routers_ipv6, gggg_ri);
  digestmap_set(true_sybil_routers, gggg_digest, gggg_digest);
  omit_as_sybil = get_sybil_list_by_ip_version(routers_ipv6, AF_INET6);
  TEST_SYBIL(true_sybil_routers, omit_as_sybil);

  CREATE_ROUTER("hhhh", hhhh, 456, AF_INET6);
  smartlist_add(routers_ipv6, hhhh_ri);
  digestmap_set(true_sybil_routers, hhhh_digest, hhhh_digest);
  omit_as_sybil = get_sybil_list_by_ip_version(routers_ipv6, AF_INET6);
  TEST_SYBIL(true_sybil_routers, omit_as_sybil);
end:
  UNMOCK(router_digest_is_trusted_dir_type);
  UNMOCK(node_get_by_id);
  UNMOCK(dirserv_get_bandwidth_for_router_kb);
  tor_free(true_sybil_routers);
  tor_free(running_node);
  tor_free(non_running_node);
  tor_free(router_properties);
  tor_free(routers_ipv6);
  tor_free(omit_as_sybil);
}

#define NODE(name, flags)                           \
  {                                                 \
#    name, test_dirvote_##name, (flags), NULL, NULL \
  }

struct testcase_t dirvote_tests[] = {
    NODE(compare_routerinfo_usefulness, TT_FORK),
    NODE(compare_routerinfo_by_ipv6, TT_FORK),
    NODE(compare_routerinfo_by_ipv4, TT_FORK),
    NODE(get_sybil_by_ip_version_ipv4, TT_FORK),
    NODE(get_sybil_by_ip_version_ipv6, TT_FORK),
    END_OF_TESTCASES};
