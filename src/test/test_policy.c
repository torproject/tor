/* Copyright (c) 2013-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#define CONFIG_PRIVATE
#include "config.h"
#include "router.h"
#include "routerparse.h"
#define POLICIES_PRIVATE
#include "policies.h"
#include "test.h"

/* Helper: assert that short_policy parses and writes back out as itself,
   or as <b>expected</b> if that's provided. */
static void
test_short_policy_parse(const char *input,
                        const char *expected)
{
  short_policy_t *short_policy = NULL;
  char *out = NULL;

  if (expected == NULL)
    expected = input;

  short_policy = parse_short_policy(input);
  tt_assert(short_policy);
  out = write_short_policy(short_policy);
  tt_str_op(out, OP_EQ, expected);

 done:
  tor_free(out);
  short_policy_free(short_policy);
}

/** Helper: Parse the exit policy string in <b>policy_str</b>, and make sure
 * that policies_summarize() produces the string <b>expected_summary</b> from
 * it. */
static void
test_policy_summary_helper(const char *policy_str,
                           const char *expected_summary)
{
  config_line_t line;
  smartlist_t *policy = smartlist_new();
  char *summary = NULL;
  char *summary_after = NULL;
  int r;
  short_policy_t *short_policy = NULL;

  line.key = (char*)"foo";
  line.value = (char *)policy_str;
  line.next = NULL;

  r = policies_parse_exit_policy(&line, &policy,
                                 EXIT_POLICY_IPV6_ENABLED |
                                 EXIT_POLICY_ADD_DEFAULT, NULL);
  tt_int_op(r,OP_EQ, 0);

  summary = policy_summarize(policy, AF_INET);

  tt_assert(summary != NULL);
  tt_str_op(summary,OP_EQ, expected_summary);

  short_policy = parse_short_policy(summary);
  tt_assert(short_policy);
  summary_after = write_short_policy(short_policy);
  tt_str_op(summary,OP_EQ, summary_after);

 done:
  tor_free(summary_after);
  tor_free(summary);
  if (policy)
    addr_policy_list_free(policy);
  short_policy_free(short_policy);
}

/** Run unit tests for generating summary lines of exit policies */
static void
test_policies_general(void *arg)
{
  int i;
  smartlist_t *policy = NULL, *policy2 = NULL, *policy3 = NULL,
              *policy4 = NULL, *policy5 = NULL, *policy6 = NULL,
              *policy7 = NULL, *policy8 = NULL, *policy9 = NULL,
              *policy10 = NULL, *policy11 = NULL, *policy12 = NULL;
  addr_policy_t *p;
  tor_addr_t tar, tar2;
  smartlist_t *addr_list = NULL;
  config_line_t line;
  smartlist_t *sm = NULL;
  char *policy_str = NULL;
  short_policy_t *short_parsed = NULL;
  int malformed_list = -1;
  (void)arg;

  policy = smartlist_new();

  p = router_parse_addr_policy_item_from_string("reject 192.168.0.0/16:*", -1,
                                                &malformed_list);
  tt_assert(p != NULL);
  tt_int_op(ADDR_POLICY_REJECT,OP_EQ, p->policy_type);
  tor_addr_from_ipv4h(&tar, 0xc0a80000u);
  tt_int_op(0,OP_EQ, tor_addr_compare(&p->addr, &tar, CMP_EXACT));
  tt_int_op(16,OP_EQ, p->maskbits);
  tt_int_op(1,OP_EQ, p->prt_min);
  tt_int_op(65535,OP_EQ, p->prt_max);

  smartlist_add(policy, p);

  tor_addr_from_ipv4h(&tar, 0x01020304u);
  tt_assert(ADDR_POLICY_ACCEPTED ==
          compare_tor_addr_to_addr_policy(&tar, 2, policy));
  tor_addr_make_unspec(&tar);
  tt_assert(ADDR_POLICY_PROBABLY_ACCEPTED ==
          compare_tor_addr_to_addr_policy(&tar, 2, policy));
  tor_addr_from_ipv4h(&tar, 0xc0a80102);
  tt_assert(ADDR_POLICY_REJECTED ==
          compare_tor_addr_to_addr_policy(&tar, 2, policy));

  tt_int_op(0, OP_EQ, policies_parse_exit_policy(NULL, &policy2,
                                              EXIT_POLICY_IPV6_ENABLED |
                                              EXIT_POLICY_REJECT_PRIVATE |
                                              EXIT_POLICY_ADD_DEFAULT, NULL));

  tt_assert(policy2);

  tor_addr_from_ipv4h(&tar, 0x0306090cu);
  tor_addr_parse(&tar2, "[2000::1234]");
  addr_list = smartlist_new();
  smartlist_add(addr_list, &tar);
  smartlist_add(addr_list, &tar2);
  tt_int_op(0, OP_EQ, policies_parse_exit_policy(NULL, &policy12,
                                                 EXIT_POLICY_IPV6_ENABLED |
                                                 EXIT_POLICY_REJECT_PRIVATE |
                                                 EXIT_POLICY_ADD_DEFAULT,
                                                 addr_list));
  smartlist_free(addr_list);
  addr_list = NULL;

  tt_assert(policy12);

  policy3 = smartlist_new();
  p = router_parse_addr_policy_item_from_string("reject *:*", -1,
                                                &malformed_list);
  tt_assert(p != NULL);
  smartlist_add(policy3, p);
  p = router_parse_addr_policy_item_from_string("accept *:*", -1,
                                                &malformed_list);
  tt_assert(p != NULL);
  smartlist_add(policy3, p);

  policy4 = smartlist_new();
  p = router_parse_addr_policy_item_from_string("accept *:443", -1,
                                                &malformed_list);
  tt_assert(p != NULL);
  smartlist_add(policy4, p);
  p = router_parse_addr_policy_item_from_string("accept *:443", -1,
                                                &malformed_list);
  tt_assert(p != NULL);
  smartlist_add(policy4, p);

  policy5 = smartlist_new();
  p = router_parse_addr_policy_item_from_string("reject 0.0.0.0/8:*", -1,
                                                &malformed_list);
  tt_assert(p != NULL);
  smartlist_add(policy5, p);
  p = router_parse_addr_policy_item_from_string("reject 169.254.0.0/16:*", -1,
                                                &malformed_list);
  tt_assert(p != NULL);
  smartlist_add(policy5, p);
  p = router_parse_addr_policy_item_from_string("reject 127.0.0.0/8:*", -1,
                                                &malformed_list);
  tt_assert(p != NULL);
  smartlist_add(policy5, p);
  p = router_parse_addr_policy_item_from_string("reject 192.168.0.0/16:*",
                                                -1, &malformed_list);
  tt_assert(p != NULL);
  smartlist_add(policy5, p);
  p = router_parse_addr_policy_item_from_string("reject 10.0.0.0/8:*", -1,
                                                &malformed_list);
  tt_assert(p != NULL);
  smartlist_add(policy5, p);
  p = router_parse_addr_policy_item_from_string("reject 172.16.0.0/12:*", -1,
                                                &malformed_list);
  tt_assert(p != NULL);
  smartlist_add(policy5, p);
  p = router_parse_addr_policy_item_from_string("reject 80.190.250.90:*", -1,
                                                &malformed_list);
  tt_assert(p != NULL);
  smartlist_add(policy5, p);
  p = router_parse_addr_policy_item_from_string("reject *:1-65534", -1,
                                                &malformed_list);
  tt_assert(p != NULL);
  smartlist_add(policy5, p);
  p = router_parse_addr_policy_item_from_string("reject *:65535", -1,
                                                &malformed_list);
  tt_assert(p != NULL);
  smartlist_add(policy5, p);
  p = router_parse_addr_policy_item_from_string("accept *:1-65535", -1,
                                                &malformed_list);
  tt_assert(p != NULL);
  smartlist_add(policy5, p);

  policy6 = smartlist_new();
  p = router_parse_addr_policy_item_from_string("accept 43.3.0.0/9:*", -1,
                                                &malformed_list);
  tt_assert(p != NULL);
  smartlist_add(policy6, p);

  policy7 = smartlist_new();
  p = router_parse_addr_policy_item_from_string("accept 0.0.0.0/8:*", -1,
                                                &malformed_list);
  tt_assert(p != NULL);
  smartlist_add(policy7, p);

  tt_int_op(0, OP_EQ, policies_parse_exit_policy(NULL, &policy8,
                                                 EXIT_POLICY_IPV6_ENABLED |
                                                 EXIT_POLICY_REJECT_PRIVATE |
                                                 EXIT_POLICY_ADD_DEFAULT,
                                                 NULL));

  tt_assert(policy8);

  tt_int_op(0, OP_EQ, policies_parse_exit_policy(NULL, &policy9,
                                                 EXIT_POLICY_REJECT_PRIVATE |
                                                 EXIT_POLICY_ADD_DEFAULT,
                                                 NULL));

  tt_assert(policy9);

  /* accept6 * and reject6 * produce IPv6 wildcards only */
  policy10 = smartlist_new();
  p = router_parse_addr_policy_item_from_string("accept6 *:*", -1,
                                                &malformed_list);
  tt_assert(p != NULL);
  smartlist_add(policy10, p);

  policy11 = smartlist_new();
  p = router_parse_addr_policy_item_from_string("reject6 *:*", -1,
                                                &malformed_list);
  tt_assert(p != NULL);
  smartlist_add(policy11, p);

  tt_assert(!exit_policy_is_general_exit(policy));
  tt_assert(exit_policy_is_general_exit(policy2));
  tt_assert(!exit_policy_is_general_exit(NULL));
  tt_assert(!exit_policy_is_general_exit(policy3));
  tt_assert(!exit_policy_is_general_exit(policy4));
  tt_assert(!exit_policy_is_general_exit(policy5));
  tt_assert(!exit_policy_is_general_exit(policy6));
  tt_assert(!exit_policy_is_general_exit(policy7));
  tt_assert(exit_policy_is_general_exit(policy8));
  tt_assert(exit_policy_is_general_exit(policy9));
  tt_assert(!exit_policy_is_general_exit(policy10));
  tt_assert(!exit_policy_is_general_exit(policy11));

  tt_assert(cmp_addr_policies(policy, policy2));
  tt_assert(cmp_addr_policies(policy, NULL));
  tt_assert(!cmp_addr_policies(policy2, policy2));
  tt_assert(!cmp_addr_policies(NULL, NULL));

  tt_assert(!policy_is_reject_star(policy2, AF_INET));
  tt_assert(policy_is_reject_star(policy, AF_INET));
  tt_assert(policy_is_reject_star(policy10, AF_INET));
  tt_assert(!policy_is_reject_star(policy10, AF_INET6));
  tt_assert(policy_is_reject_star(policy11, AF_INET));
  tt_assert(policy_is_reject_star(policy11, AF_INET6));
  tt_assert(policy_is_reject_star(NULL, AF_INET));
  tt_assert(policy_is_reject_star(NULL, AF_INET6));

  addr_policy_list_free(policy);
  policy = NULL;

  /* make sure compacting logic works. */
  policy = NULL;
  line.key = (char*)"foo";
  line.value = (char*)"accept *:80,reject private:*,reject *:*";
  line.next = NULL;
  tt_int_op(0, OP_EQ, policies_parse_exit_policy(&line,&policy,
                                              EXIT_POLICY_IPV6_ENABLED |
                                              EXIT_POLICY_ADD_DEFAULT, NULL));
  tt_assert(policy);

  //test_streq(policy->string, "accept *:80");
  //test_streq(policy->next->string, "reject *:*");
  tt_int_op(smartlist_len(policy),OP_EQ, 4);

  /* test policy summaries */
  /* check if we properly ignore private IP addresses */
  test_policy_summary_helper("reject 192.168.0.0/16:*,"
                             "reject 0.0.0.0/8:*,"
                             "reject 10.0.0.0/8:*,"
                             "accept *:10-30,"
                             "accept *:90,"
                             "reject *:*",
                             "accept 10-30,90");
  /* check all accept policies, and proper counting of rejects */
  test_policy_summary_helper("reject 11.0.0.0/9:80,"
                             "reject 12.0.0.0/9:80,"
                             "reject 13.0.0.0/9:80,"
                             "reject 14.0.0.0/9:80,"
                             "accept *:*", "accept 1-65535");
  test_policy_summary_helper("reject 11.0.0.0/9:80,"
                             "reject 12.0.0.0/9:80,"
                             "reject 13.0.0.0/9:80,"
                             "reject 14.0.0.0/9:80,"
                             "reject 15.0.0.0:81,"
                             "accept *:*", "accept 1-65535");
  test_policy_summary_helper("reject 11.0.0.0/9:80,"
                             "reject 12.0.0.0/9:80,"
                             "reject 13.0.0.0/9:80,"
                             "reject 14.0.0.0/9:80,"
                             "reject 15.0.0.0:80,"
                             "accept *:*",
                             "reject 80");
  /* no exits */
  test_policy_summary_helper("accept 11.0.0.0/9:80,"
                             "reject *:*",
                             "reject 1-65535");
  /* port merging */
  test_policy_summary_helper("accept *:80,"
                             "accept *:81,"
                             "accept *:100-110,"
                             "accept *:111,"
                             "reject *:*",
                             "accept 80-81,100-111");
  /* border ports */
  test_policy_summary_helper("accept *:1,"
                             "accept *:3,"
                             "accept *:65535,"
                             "reject *:*",
                             "accept 1,3,65535");
  /* holes */
  test_policy_summary_helper("accept *:1,"
                             "accept *:3,"
                             "accept *:5,"
                             "accept *:7,"
                             "reject *:*",
                             "accept 1,3,5,7");
  test_policy_summary_helper("reject *:1,"
                             "reject *:3,"
                             "reject *:5,"
                             "reject *:7,"
                             "accept *:*",
                             "reject 1,3,5,7");

  /* Short policies with unrecognized formats should get accepted. */
  test_short_policy_parse("accept fred,2,3-5", "accept 2,3-5");
  test_short_policy_parse("accept 2,fred,3", "accept 2,3");
  test_short_policy_parse("accept 2,fred,3,bob", "accept 2,3");
  test_short_policy_parse("accept 2,-3,500-600", "accept 2,500-600");
  /* Short policies with nil entries are accepted too. */
  test_short_policy_parse("accept 1,,3", "accept 1,3");
  test_short_policy_parse("accept 100-200,,", "accept 100-200");
  test_short_policy_parse("reject ,1-10,,,,30-40", "reject 1-10,30-40");

  /* Try parsing various broken short policies */
#define TT_BAD_SHORT_POLICY(s)                                          \
  do {                                                                  \
    tt_ptr_op(NULL, OP_EQ, (short_parsed = parse_short_policy((s))));      \
  } while (0)
  TT_BAD_SHORT_POLICY("accept 200-199");
  TT_BAD_SHORT_POLICY("");
  TT_BAD_SHORT_POLICY("rejekt 1,2,3");
  TT_BAD_SHORT_POLICY("reject ");
  TT_BAD_SHORT_POLICY("reject");
  TT_BAD_SHORT_POLICY("rej");
  TT_BAD_SHORT_POLICY("accept 2,3,100000");
  TT_BAD_SHORT_POLICY("accept 2,3x,4");
  TT_BAD_SHORT_POLICY("accept 2,3x,4");
  TT_BAD_SHORT_POLICY("accept 2-");
  TT_BAD_SHORT_POLICY("accept 2-x");
  TT_BAD_SHORT_POLICY("accept 1-,3");
  TT_BAD_SHORT_POLICY("accept 1-,3");

  /* Make sure that IPv4 addresses are ignored in accept6/reject6 lines. */
  p = router_parse_addr_policy_item_from_string("accept6 1.2.3.4:*", -1,
                                                &malformed_list);
  tt_assert(p == NULL);
  tt_assert(!malformed_list);

  p = router_parse_addr_policy_item_from_string("reject6 2.4.6.0/24:*", -1,
                                                &malformed_list);
  tt_assert(p == NULL);
  tt_assert(!malformed_list);

  p = router_parse_addr_policy_item_from_string("accept6 *4:*", -1,
                                                &malformed_list);
  tt_assert(p == NULL);
  tt_assert(!malformed_list);

  /* Make sure malformed policies are detected as such. */
  p = router_parse_addr_policy_item_from_string("bad_token *4:*", -1,
                                                &malformed_list);
  tt_assert(p == NULL);
  tt_assert(malformed_list);

  p = router_parse_addr_policy_item_from_string("accept6 **:*", -1,
                                                &malformed_list);
  tt_assert(p == NULL);
  tt_assert(malformed_list);

  p = router_parse_addr_policy_item_from_string("accept */15:*", -1,
                                                &malformed_list);
  tt_assert(p == NULL);
  tt_assert(malformed_list);

  p = router_parse_addr_policy_item_from_string("reject6 */:*", -1,
                                                &malformed_list);
  tt_assert(p == NULL);
  tt_assert(malformed_list);

  p = router_parse_addr_policy_item_from_string("accept 127.0.0.1/33:*", -1,
                                                &malformed_list);
  tt_assert(p == NULL);
  tt_assert(malformed_list);

  p = router_parse_addr_policy_item_from_string("accept6 [::1]/129:*", -1,
                                                &malformed_list);
  tt_assert(p == NULL);
  tt_assert(malformed_list);

  p = router_parse_addr_policy_item_from_string("reject 8.8.8.8/-1:*", -1,
                                                &malformed_list);
  tt_assert(p == NULL);
  tt_assert(malformed_list);

  p = router_parse_addr_policy_item_from_string("reject 8.8.4.4:10-5", -1,
                                                &malformed_list);
  tt_assert(p == NULL);
  tt_assert(malformed_list);

  p = router_parse_addr_policy_item_from_string("reject 1.2.3.4:-1", -1,
                                                &malformed_list);
  tt_assert(p == NULL);
  tt_assert(malformed_list);

  /* Test a too-long policy. */
  {
    int i;
    char *policy = NULL;
    smartlist_t *chunks = smartlist_new();
    smartlist_add(chunks, tor_strdup("accept "));
    for (i=1; i<10000; ++i)
      smartlist_add_asprintf(chunks, "%d,", i);
    smartlist_add(chunks, tor_strdup("20000"));
    policy = smartlist_join_strings(chunks, "", 0, NULL);
    SMARTLIST_FOREACH(chunks, char *, ch, tor_free(ch));
    smartlist_free(chunks);
    short_parsed = parse_short_policy(policy);/* shouldn't be accepted */
    tor_free(policy);
    tt_ptr_op(NULL, OP_EQ, short_parsed);
  }

  /* truncation ports */
  sm = smartlist_new();
  for (i=1; i<2000; i+=2) {
    char buf[POLICY_BUF_LEN];
    tor_snprintf(buf, sizeof(buf), "reject *:%d", i);
    smartlist_add(sm, tor_strdup(buf));
  }
  smartlist_add(sm, tor_strdup("accept *:*"));
  policy_str = smartlist_join_strings(sm, ",", 0, NULL);
  test_policy_summary_helper( policy_str,
    "accept 2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,38,40,42,44,"
    "46,48,50,52,54,56,58,60,62,64,66,68,70,72,74,76,78,80,82,84,86,88,90,"
    "92,94,96,98,100,102,104,106,108,110,112,114,116,118,120,122,124,126,128,"
    "130,132,134,136,138,140,142,144,146,148,150,152,154,156,158,160,162,164,"
    "166,168,170,172,174,176,178,180,182,184,186,188,190,192,194,196,198,200,"
    "202,204,206,208,210,212,214,216,218,220,222,224,226,228,230,232,234,236,"
    "238,240,242,244,246,248,250,252,254,256,258,260,262,264,266,268,270,272,"
    "274,276,278,280,282,284,286,288,290,292,294,296,298,300,302,304,306,308,"
    "310,312,314,316,318,320,322,324,326,328,330,332,334,336,338,340,342,344,"
    "346,348,350,352,354,356,358,360,362,364,366,368,370,372,374,376,378,380,"
    "382,384,386,388,390,392,394,396,398,400,402,404,406,408,410,412,414,416,"
    "418,420,422,424,426,428,430,432,434,436,438,440,442,444,446,448,450,452,"
    "454,456,458,460,462,464,466,468,470,472,474,476,478,480,482,484,486,488,"
    "490,492,494,496,498,500,502,504,506,508,510,512,514,516,518,520,522");

 done:
  addr_policy_list_free(policy);
  addr_policy_list_free(policy2);
  addr_policy_list_free(policy3);
  addr_policy_list_free(policy4);
  addr_policy_list_free(policy5);
  addr_policy_list_free(policy6);
  addr_policy_list_free(policy7);
  addr_policy_list_free(policy8);
  addr_policy_list_free(policy9);
  addr_policy_list_free(policy10);
  addr_policy_list_free(policy11);
  addr_policy_list_free(policy12);
  tor_free(policy_str);
  if (sm) {
    SMARTLIST_FOREACH(sm, char *, s, tor_free(s));
    smartlist_free(sm);
  }
  short_policy_free(short_parsed);
}

/** Helper: Check that policy_list contains address */
static int
test_policy_has_address_helper(const smartlist_t *policy_list,
                               const tor_addr_t *addr)
{
  int found = 0;

  tt_assert(policy_list);
  tt_assert(addr);

  SMARTLIST_FOREACH_BEGIN(policy_list, addr_policy_t*, p) {
    if (tor_addr_eq(&p->addr, addr)) {
      found = 1;
    }
  } SMARTLIST_FOREACH_END(p);

  return found;

 done:
  return 0;
}

#define TEST_IPV4_ADDR (0x01020304)
#define TEST_IPV6_ADDR ("2002::abcd")

/** Run unit tests for rejecting the configured addresses on this exit relay
 * using policies_parse_exit_policy_reject_private */
static void
test_policies_reject_exit_address(void *arg)
{
  smartlist_t *policy = NULL;
  tor_addr_t ipv4_addr, ipv6_addr;
  smartlist_t *ipv4_list, *ipv6_list, *both_list, *dupl_list;
  (void)arg;

  tor_addr_from_ipv4h(&ipv4_addr, TEST_IPV4_ADDR);
  tor_addr_parse(&ipv6_addr, TEST_IPV6_ADDR);

  ipv4_list = smartlist_new();
  ipv6_list = smartlist_new();
  both_list = smartlist_new();
  dupl_list = smartlist_new();

  smartlist_add(ipv4_list, &ipv4_addr);
  smartlist_add(both_list, &ipv4_addr);
  smartlist_add(dupl_list, &ipv4_addr);
  smartlist_add(dupl_list, &ipv4_addr);
  smartlist_add(dupl_list, &ipv4_addr);

  smartlist_add(ipv6_list, &ipv6_addr);
  smartlist_add(both_list, &ipv6_addr);
  smartlist_add(dupl_list, &ipv6_addr);
  smartlist_add(dupl_list, &ipv6_addr);

  /* IPv4-Only Exits */

  /* test that IPv4 addresses are rejected on an IPv4-only exit */
  policies_parse_exit_policy_reject_private(&policy, 0, ipv4_list, 0, 0);
  tt_assert(policy);
  tt_assert(smartlist_len(policy) == 1);
  tt_assert(test_policy_has_address_helper(policy, &ipv4_addr));
  addr_policy_list_free(policy);
  policy = NULL;

  /* test that IPv6 addresses are NOT rejected on an IPv4-only exit
   * (all IPv6 addresses are rejected by policies_parse_exit_policy_internal
   * on IPv4-only exits, so policies_parse_exit_policy_reject_private doesn't
   * need to do anything) */
  policies_parse_exit_policy_reject_private(&policy, 0, ipv6_list, 0, 0);
  tt_assert(policy == NULL);

  /* test that only IPv4 addresses are rejected on an IPv4-only exit */
  policies_parse_exit_policy_reject_private(&policy, 0, both_list, 0, 0);
  tt_assert(policy);
  tt_assert(smartlist_len(policy) == 1);
  tt_assert(test_policy_has_address_helper(policy, &ipv4_addr));
  addr_policy_list_free(policy);
  policy = NULL;

  /* Test that lists with duplicate entries produce the same results */
  policies_parse_exit_policy_reject_private(&policy, 0, dupl_list, 0, 0);
  tt_assert(policy);
  tt_assert(smartlist_len(policy) == 1);
  tt_assert(test_policy_has_address_helper(policy, &ipv4_addr));
  addr_policy_list_free(policy);
  policy = NULL;

  /* IPv4/IPv6 Exits */

  /* test that IPv4 addresses are rejected on an IPv4/IPv6 exit */
  policies_parse_exit_policy_reject_private(&policy, 1, ipv4_list, 0, 0);
  tt_assert(policy);
  tt_assert(smartlist_len(policy) == 1);
  tt_assert(test_policy_has_address_helper(policy, &ipv4_addr));
  addr_policy_list_free(policy);
  policy = NULL;

  /* test that IPv6 addresses are rejected on an IPv4/IPv6 exit */
  policies_parse_exit_policy_reject_private(&policy, 1, ipv6_list,  0, 0);
  tt_assert(policy);
  tt_assert(smartlist_len(policy) == 1);
  tt_assert(test_policy_has_address_helper(policy, &ipv6_addr));
  addr_policy_list_free(policy);
  policy = NULL;

  /* test that IPv4 and IPv6 addresses are rejected on an IPv4/IPv6 exit */
  policies_parse_exit_policy_reject_private(&policy, 1, both_list,  0, 0);
  tt_assert(policy);
  tt_assert(smartlist_len(policy) == 2);
  tt_assert(test_policy_has_address_helper(policy, &ipv4_addr));
  tt_assert(test_policy_has_address_helper(policy, &ipv6_addr));
  addr_policy_list_free(policy);
  policy = NULL;

  /* Test that lists with duplicate entries produce the same results */
  policies_parse_exit_policy_reject_private(&policy, 1, dupl_list,  0, 0);
  tt_assert(policy);
  tt_assert(smartlist_len(policy) == 2);
  tt_assert(test_policy_has_address_helper(policy, &ipv4_addr));
  tt_assert(test_policy_has_address_helper(policy, &ipv6_addr));
  addr_policy_list_free(policy);
  policy = NULL;

 done:
  addr_policy_list_free(policy);
  smartlist_free(ipv4_list);
  smartlist_free(ipv6_list);
  smartlist_free(both_list);
  smartlist_free(dupl_list);
}

static smartlist_t *test_configured_ports = NULL;
const smartlist_t *mock_get_configured_ports(void);

/** Returns test_configured_ports */
const smartlist_t *
mock_get_configured_ports(void)
{
  return test_configured_ports;
}

/** Run unit tests for rejecting publicly routable configured port addresses
 * on this exit relay using policies_parse_exit_policy_reject_private */
static void
test_policies_reject_port_address(void *arg)
{
  smartlist_t *policy = NULL;
  port_cfg_t *ipv4_port = NULL;
  port_cfg_t *ipv6_port = NULL;
  (void)arg;

  test_configured_ports = smartlist_new();

  ipv4_port = port_cfg_new(0);
  tor_addr_from_ipv4h(&ipv4_port->addr, TEST_IPV4_ADDR);
  smartlist_add(test_configured_ports, ipv4_port);

  ipv6_port = port_cfg_new(0);
  tor_addr_parse(&ipv6_port->addr, TEST_IPV6_ADDR);
  smartlist_add(test_configured_ports, ipv6_port);

  MOCK(get_configured_ports, mock_get_configured_ports);

  /* test that an IPv4 port is rejected on an IPv4-only exit, but an IPv6 port
   * is NOT rejected (all IPv6 addresses are rejected by
   * policies_parse_exit_policy_internal on IPv4-only exits, so
   * policies_parse_exit_policy_reject_private doesn't need to do anything
   * with IPv6 addresses on IPv4-only exits) */
  policies_parse_exit_policy_reject_private(&policy, 0, NULL, 0, 1);
  tt_assert(policy);
  tt_assert(smartlist_len(policy) == 1);
  tt_assert(test_policy_has_address_helper(policy, &ipv4_port->addr));
  addr_policy_list_free(policy);
  policy = NULL;

  /* test that IPv4 and IPv6 ports are rejected on an IPv4/IPv6 exit */
  policies_parse_exit_policy_reject_private(&policy, 1, NULL, 0, 1);
  tt_assert(policy);
  tt_assert(smartlist_len(policy) == 2);
  tt_assert(test_policy_has_address_helper(policy, &ipv4_port->addr));
  tt_assert(test_policy_has_address_helper(policy, &ipv6_port->addr));
  addr_policy_list_free(policy);
  policy = NULL;

 done:
  addr_policy_list_free(policy);
  if (test_configured_ports) {
    SMARTLIST_FOREACH(test_configured_ports,
                      port_cfg_t *, p, port_cfg_free(p));
    smartlist_free(test_configured_ports);
    test_configured_ports = NULL;
  }
  UNMOCK(get_configured_ports);
}

smartlist_t *mock_ipv4_addrs = NULL;
smartlist_t *mock_ipv6_addrs = NULL;

/* mock get_interface_address6_list, returning a deep copy of the template
 * address list ipv4_interface_address_list or ipv6_interface_address_list */
static smartlist_t *
mock_get_interface_address6_list(int severity,
                            sa_family_t family,
                            int include_internal)
{
  (void)severity;
  (void)include_internal;
  smartlist_t *clone_list = smartlist_new();
  smartlist_t *template_list = NULL;

  if (family == AF_INET) {
    template_list = mock_ipv4_addrs;
  } else if (family == AF_INET6) {
    template_list = mock_ipv6_addrs;
  } else {
    return NULL;
  }

  tt_assert(template_list);

  SMARTLIST_FOREACH_BEGIN(template_list, tor_addr_t *, src_addr) {
    tor_addr_t *dest_addr = malloc(sizeof(tor_addr_t));
    memset(dest_addr, 0, sizeof(*dest_addr));
    tor_addr_copy_tight(dest_addr, src_addr);
    smartlist_add(clone_list, dest_addr);
  } SMARTLIST_FOREACH_END(src_addr);

  return clone_list;

 done:
  free_interface_address6_list(clone_list);
  return NULL;
}

/** Run unit tests for rejecting publicly routable interface addresses on this
 * exit relay using policies_parse_exit_policy_reject_private */
static void
test_policies_reject_interface_address(void *arg)
{
  smartlist_t *policy = NULL;
  smartlist_t *public_ipv4_addrs =
    get_interface_address6_list(LOG_INFO, AF_INET, 0);
  smartlist_t *public_ipv6_addrs =
    get_interface_address6_list(LOG_INFO, AF_INET6, 0);
  tor_addr_t ipv4_addr, ipv6_addr;
  (void)arg;

  /* test that no addresses are rejected when none are supplied/requested */
  policies_parse_exit_policy_reject_private(&policy, 0, NULL, 0, 0);
  tt_assert(policy == NULL);

  /* test that only IPv4 interface addresses are rejected on an IPv4-only exit
   * (and allow for duplicates)
   */
  policies_parse_exit_policy_reject_private(&policy, 0, NULL, 1, 0);
  if (policy) {
    tt_assert(smartlist_len(policy) <= smartlist_len(public_ipv4_addrs));
    addr_policy_list_free(policy);
    policy = NULL;
  }

  /* test that IPv4 and IPv6 interface addresses are rejected on an IPv4/IPv6
   * exit (and allow for duplicates) */
  policies_parse_exit_policy_reject_private(&policy, 1, NULL, 1, 0);
  if (policy) {
    tt_assert(smartlist_len(policy) <= (smartlist_len(public_ipv4_addrs)
                                        + smartlist_len(public_ipv6_addrs)));
    addr_policy_list_free(policy);
    policy = NULL;
  }

  /* Now do it all again, but mocked */
  tor_addr_from_ipv4h(&ipv4_addr, TEST_IPV4_ADDR);
  mock_ipv4_addrs = smartlist_new();
  smartlist_add(mock_ipv4_addrs, (void *)&ipv4_addr);

  tor_addr_parse(&ipv6_addr, TEST_IPV6_ADDR);
  mock_ipv6_addrs = smartlist_new();
  smartlist_add(mock_ipv6_addrs, (void *)&ipv6_addr);

  MOCK(get_interface_address6_list, mock_get_interface_address6_list);

  /* test that no addresses are rejected when none are supplied/requested */
  policies_parse_exit_policy_reject_private(&policy, 0, NULL, 0, 0);
  tt_assert(policy == NULL);

  /* test that only IPv4 interface addresses are rejected on an IPv4-only exit
   */
  policies_parse_exit_policy_reject_private(&policy, 0, NULL, 1, 0);
  tt_assert(policy);
  tt_assert(smartlist_len(policy) == smartlist_len(mock_ipv4_addrs));
  addr_policy_list_free(policy);
  policy = NULL;

  /* test that IPv4 and IPv6 interface addresses are rejected on an IPv4/IPv6
   * exit */
  policies_parse_exit_policy_reject_private(&policy, 1, NULL, 1, 0);
  tt_assert(policy);
  tt_assert(smartlist_len(policy) == (smartlist_len(mock_ipv4_addrs)
                                      + smartlist_len(mock_ipv6_addrs)));
  addr_policy_list_free(policy);
  policy = NULL;

 done:
  addr_policy_list_free(policy);
  free_interface_address6_list(public_ipv4_addrs);
  free_interface_address6_list(public_ipv6_addrs);

  UNMOCK(get_interface_address6_list);
  /* we don't use free_interface_address6_list on these lists because their
   * address pointers are stack-based */
  smartlist_free(mock_ipv4_addrs);
  smartlist_free(mock_ipv6_addrs);
}

#undef TEST_IPV4_ADDR
#undef TEST_IPV6_ADDR

static void
test_dump_exit_policy_to_string(void *arg)
{
 char *ep;
 addr_policy_t *policy_entry;
 int malformed_list = -1;

 routerinfo_t *ri = tor_malloc_zero(sizeof(routerinfo_t));

 (void)arg;

 ri->policy_is_reject_star = 1;
 ri->exit_policy = NULL; // expecting "reject *:*"
 ep = router_dump_exit_policy_to_string(ri,1,1);

 tt_str_op("reject *:*",OP_EQ, ep);

 tor_free(ep);

 ri->exit_policy = smartlist_new();
 ri->policy_is_reject_star = 0;

 policy_entry = router_parse_addr_policy_item_from_string("accept *:*", -1,
                                                          &malformed_list);

 smartlist_add(ri->exit_policy,policy_entry);

 ep = router_dump_exit_policy_to_string(ri,1,1);

 tt_str_op("accept *:*",OP_EQ, ep);

 tor_free(ep);

 policy_entry = router_parse_addr_policy_item_from_string("reject *:25", -1,
                                                          &malformed_list);

 smartlist_add(ri->exit_policy,policy_entry);

 ep = router_dump_exit_policy_to_string(ri,1,1);

 tt_str_op("accept *:*\nreject *:25",OP_EQ, ep);

 tor_free(ep);

 policy_entry =
 router_parse_addr_policy_item_from_string("reject 8.8.8.8:*", -1,
                                           &malformed_list);

 smartlist_add(ri->exit_policy,policy_entry);

 ep = router_dump_exit_policy_to_string(ri,1,1);

 tt_str_op("accept *:*\nreject *:25\nreject 8.8.8.8:*",OP_EQ, ep);
 tor_free(ep);

 policy_entry =
 router_parse_addr_policy_item_from_string("reject6 [FC00::]/7:*", -1,
                                           &malformed_list);

 smartlist_add(ri->exit_policy,policy_entry);

 ep = router_dump_exit_policy_to_string(ri,1,1);

 tt_str_op("accept *:*\nreject *:25\nreject 8.8.8.8:*\n"
            "reject6 [fc00::]/7:*",OP_EQ, ep);
 tor_free(ep);

 policy_entry =
 router_parse_addr_policy_item_from_string("accept6 [c000::]/3:*", -1,
                                           &malformed_list);

 smartlist_add(ri->exit_policy,policy_entry);

 ep = router_dump_exit_policy_to_string(ri,1,1);

 tt_str_op("accept *:*\nreject *:25\nreject 8.8.8.8:*\n"
            "reject6 [fc00::]/7:*\naccept6 [c000::]/3:*",OP_EQ, ep);

 done:

 if (ri->exit_policy) {
   SMARTLIST_FOREACH(ri->exit_policy, addr_policy_t *,
                     entry, addr_policy_free(entry));
   smartlist_free(ri->exit_policy);
 }
 tor_free(ri);
 tor_free(ep);
}

static routerinfo_t *mock_desc_routerinfo = NULL;
static const routerinfo_t *
mock_router_get_my_routerinfo(void)
{
  return mock_desc_routerinfo;
}

#define DEFAULT_POLICY_STRING "reject *:*"
#define TEST_IPV4_ADDR (0x02040608)
#define TEST_IPV6_ADDR ("2003::ef01")

static or_options_t mock_options;

static const or_options_t *
mock_get_options(void)
{
  return &mock_options;
}

/** Run unit tests for generating summary lines of exit policies */
static void
test_policies_getinfo_helper_policies(void *arg)
{
  (void)arg;
  int rv = 0;
  size_t ipv4_len = 0, ipv6_len = 0;
  char *answer = NULL;
  const char *errmsg = NULL;
  routerinfo_t mock_my_routerinfo;

  rv = getinfo_helper_policies(NULL, "exit-policy/default", &answer, &errmsg);
  tt_assert(rv == 0);
  tt_assert(answer != NULL);
  tt_assert(strlen(answer) > 0);
  tor_free(answer);

  rv = getinfo_helper_policies(NULL, "exit-policy/reject-private/default",
                               &answer, &errmsg);
  tt_assert(rv == 0);
  tt_assert(answer != NULL);
  tt_assert(strlen(answer) > 0);
  tor_free(answer);

  memset(&mock_my_routerinfo, 0, sizeof(routerinfo_t));
  MOCK(router_get_my_routerinfo, mock_router_get_my_routerinfo);
  mock_my_routerinfo.exit_policy = smartlist_new();
  mock_desc_routerinfo = &mock_my_routerinfo;

  memset(&mock_options, 0, sizeof(or_options_t));
  MOCK(get_options, mock_get_options);

  rv = getinfo_helper_policies(NULL, "exit-policy/reject-private/relay",
                               &answer, &errmsg);
  tt_assert(rv == 0);
  tt_assert(answer != NULL);
  tt_assert(strlen(answer) == 0);
  tor_free(answer);

  rv = getinfo_helper_policies(NULL, "exit-policy/ipv4", &answer,
                               &errmsg);
  tt_assert(rv == 0);
  tt_assert(answer != NULL);
  ipv4_len = strlen(answer);
  tt_assert(ipv4_len == 0 || ipv4_len == strlen(DEFAULT_POLICY_STRING));
  tt_assert(ipv4_len == 0 || !strcasecmp(answer, DEFAULT_POLICY_STRING));
  tor_free(answer);

  rv = getinfo_helper_policies(NULL, "exit-policy/ipv6", &answer,
                               &errmsg);
  tt_assert(rv == 0);
  tt_assert(answer != NULL);
  ipv6_len = strlen(answer);
  tt_assert(ipv6_len == 0 || ipv6_len == strlen(DEFAULT_POLICY_STRING));
  tt_assert(ipv6_len == 0 || !strcasecmp(answer, DEFAULT_POLICY_STRING));
  tor_free(answer);

  rv = getinfo_helper_policies(NULL, "exit-policy/full", &answer,
                               &errmsg);
  tt_assert(rv == 0);
  tt_assert(answer != NULL);
  /* It's either empty or it's the default */
  tt_assert(strlen(answer) == 0 || !strcasecmp(answer, DEFAULT_POLICY_STRING));
  tor_free(answer);

  mock_my_routerinfo.addr = TEST_IPV4_ADDR;
  tor_addr_parse(&mock_my_routerinfo.ipv6_addr, TEST_IPV6_ADDR);
  append_exit_policy_string(&mock_my_routerinfo.exit_policy, "accept *4:*");
  append_exit_policy_string(&mock_my_routerinfo.exit_policy, "reject *6:*");

  mock_options.IPv6Exit = 1;
  mock_options.ExitPolicyRejectPrivate = 1;
  tor_addr_from_ipv4h(&mock_options.OutboundBindAddressIPv4_, TEST_IPV4_ADDR);
  tor_addr_parse(&mock_options.OutboundBindAddressIPv6_, TEST_IPV6_ADDR);

  rv = getinfo_helper_policies(NULL, "exit-policy/reject-private/relay",
                               &answer, &errmsg);
  tt_assert(rv == 0);
  tt_assert(answer != NULL);
  tt_assert(strlen(answer) > 0);
  tor_free(answer);

  rv = getinfo_helper_policies(NULL, "exit-policy/ipv4", &answer,
                               &errmsg);
  tt_assert(rv == 0);
  tt_assert(answer != NULL);
  ipv4_len = strlen(answer);
  tt_assert(ipv4_len > 0);
  tor_free(answer);

  rv = getinfo_helper_policies(NULL, "exit-policy/ipv6", &answer,
                               &errmsg);
  tt_assert(rv == 0);
  tt_assert(answer != NULL);
  ipv6_len = strlen(answer);
  tt_assert(ipv6_len > 0);
  tor_free(answer);

  rv = getinfo_helper_policies(NULL, "exit-policy/full", &answer,
                               &errmsg);
  tt_assert(rv == 0);
  tt_assert(answer != NULL);
  tt_assert(strlen(answer) > 0);
  tt_assert(strlen(answer) == ipv4_len + ipv6_len + 1);
  tor_free(answer);

 done:
  tor_free(answer);
  UNMOCK(get_options);
  UNMOCK(router_get_my_routerinfo);
  smartlist_free(mock_my_routerinfo.exit_policy);
}

#undef DEFAULT_POLICY_STRING
#undef TEST_IPV4_ADDR
#undef TEST_IPV6_ADDR

struct testcase_t policy_tests[] = {
  { "router_dump_exit_policy_to_string", test_dump_exit_policy_to_string, 0,
    NULL, NULL },
  { "general", test_policies_general, 0, NULL, NULL },
  { "getinfo_helper_policies", test_policies_getinfo_helper_policies, 0, NULL,
    NULL },
  { "reject_exit_address", test_policies_reject_exit_address, 0, NULL, NULL },
  { "reject_interface_address", test_policies_reject_interface_address, 0,
    NULL, NULL },
  { "reject_port_address", test_policies_reject_port_address, 0, NULL, NULL },
  END_OF_TESTCASES
};

