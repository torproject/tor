/* Copyright (c) 2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#include "router.h"
#include "routerparse.h"
#include "policies.h"
#include "test.h"

static void
test_dump_exit_policy_to_string(void *arg)
{
 char *ep;
 addr_policy_t *policy_entry;

 routerinfo_t *ri = tor_malloc_zero(sizeof(routerinfo_t));

 (void)arg;

 ri->policy_is_reject_star = 1;
 ri->exit_policy = NULL; // expecting "reject *:*"
 ep = router_dump_exit_policy_to_string(ri,1,1);

 test_streq("reject *:*",ep);

 tor_free(ep);

 ri->exit_policy = smartlist_new();
 ri->policy_is_reject_star = 0;

 policy_entry = router_parse_addr_policy_item_from_string("accept *:*",-1);

 smartlist_add(ri->exit_policy,policy_entry);

 ep = router_dump_exit_policy_to_string(ri,1,1);

 test_streq("accept *:*",ep);

 tor_free(ep);

 policy_entry = router_parse_addr_policy_item_from_string("reject *:25",-1);

 smartlist_add(ri->exit_policy,policy_entry);

 ep = router_dump_exit_policy_to_string(ri,1,1);

 test_streq("accept *:*\nreject *:25",ep);

 tor_free(ep);

 policy_entry =
 router_parse_addr_policy_item_from_string("reject 8.8.8.8:*",-1);

 smartlist_add(ri->exit_policy,policy_entry);

 ep = router_dump_exit_policy_to_string(ri,1,1);

 test_streq("accept *:*\nreject *:25\nreject 8.8.8.8:*",ep);

 policy_entry =
 router_parse_addr_policy_item_from_string("reject6 [FC00::]/7:*",-1);

 smartlist_add(ri->exit_policy,policy_entry);

 ep = router_dump_exit_policy_to_string(ri,1,1);

 test_streq("accept *:*\nreject *:25\nreject 8.8.8.8:*\n"
            "reject6 [fc00::]/7:*",ep);

 policy_entry =
 router_parse_addr_policy_item_from_string("accept6 [c000::]/3:*",-1);

 smartlist_add(ri->exit_policy,policy_entry);

 ep = router_dump_exit_policy_to_string(ri,1,1);

 test_streq("accept *:*\nreject *:25\nreject 8.8.8.8:*\n"
            "reject6 [fc00::]/7:*\naccept6 [c000::]/3:*",ep);

 done:

 SMARTLIST_FOREACH(ri->exit_policy, addr_policy_t *,
                   entry, addr_policy_free(entry));
 tor_free(ri);
 tor_free(ep);
}

struct testcase_t exit_policy_tests[] = {
  { "router_dump_exit_policy_to_string", test_dump_exit_policy_to_string, 0,
    NULL, NULL },
  END_OF_TESTCASES
};

