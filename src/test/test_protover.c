/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define PROTOVER_PRIVATE

#include "orconfig.h"
#include "test.h"

#include "protover.h"

static void
test_protover_parse(void *arg)
{
  (void) arg;
  char *re_encoded = NULL;

  const char *orig = "Foo=1,3 Bar=3 Baz= Quux=9-12,14,15-16,900";
  smartlist_t *elts = parse_protocol_list(orig);

  tt_assert(elts);
  tt_int_op(smartlist_len(elts), OP_EQ, 4);

  const proto_entry_t *e;
  const proto_range_t *r;
  e = smartlist_get(elts, 0);
  tt_str_op(e->name, OP_EQ, "Foo");
  tt_int_op(smartlist_len(e->ranges), OP_EQ, 2);
  {
    r = smartlist_get(e->ranges, 0);
    tt_int_op(r->low, OP_EQ, 1);
    tt_int_op(r->high, OP_EQ, 1);

    r = smartlist_get(e->ranges, 1);
    tt_int_op(r->low, OP_EQ, 3);
    tt_int_op(r->high, OP_EQ, 3);
  }

  e = smartlist_get(elts, 1);
  tt_str_op(e->name, OP_EQ, "Bar");
  tt_int_op(smartlist_len(e->ranges), OP_EQ, 1);
  {
    r = smartlist_get(e->ranges, 0);
    tt_int_op(r->low, OP_EQ, 3);
    tt_int_op(r->high, OP_EQ, 3);
  }

  e = smartlist_get(elts, 2);
  tt_str_op(e->name, OP_EQ, "Baz");
  tt_int_op(smartlist_len(e->ranges), OP_EQ, 0);

  e = smartlist_get(elts, 3);
  tt_str_op(e->name, OP_EQ, "Quux");
  tt_int_op(smartlist_len(e->ranges), OP_EQ, 4);
  {
    r = smartlist_get(e->ranges, 0);
    tt_int_op(r->low, OP_EQ, 9);
    tt_int_op(r->high, OP_EQ, 12);

    r = smartlist_get(e->ranges, 1);
    tt_int_op(r->low, OP_EQ, 14);
    tt_int_op(r->high, OP_EQ, 14);

    r = smartlist_get(e->ranges, 2);
    tt_int_op(r->low, OP_EQ, 15);
    tt_int_op(r->high, OP_EQ, 16);

    r = smartlist_get(e->ranges, 3);
    tt_int_op(r->low, OP_EQ, 900);
    tt_int_op(r->high, OP_EQ, 900);
  }

  re_encoded = encode_protocol_list(elts);
  tt_assert(re_encoded);
  tt_str_op(re_encoded, OP_EQ, orig);

 done:
  if (elts)
    SMARTLIST_FOREACH(elts, proto_entry_t *, ent, proto_entry_free(ent));
  smartlist_free(elts);
  tor_free(re_encoded);
}

static void
test_protover_vote(void *arg)
{
  (void) arg;

  smartlist_t *lst = smartlist_new();
  char *result = compute_protover_vote(lst, 1);

  tt_str_op(result, OP_EQ, "");
  tor_free(result);

  smartlist_add(lst, (void*) "Foo=1-10,500 Bar=1,3-7,8");
  result = compute_protover_vote(lst, 1);
  tt_str_op(result, OP_EQ, "Bar=1,3-8 Foo=1-10,500");
  tor_free(result);

  smartlist_add(lst, (void*) "Quux=123-456,78 Bar=2-6,8 Foo=9");
  result = compute_protover_vote(lst, 1);
  tt_str_op(result, OP_EQ, "Bar=1-8 Foo=1-10,500 Quux=78,123-456");
  tor_free(result);

  result = compute_protover_vote(lst, 2);
  tt_str_op(result, OP_EQ, "Bar=3-6,8 Foo=9");
  tor_free(result);

 done:
  tor_free(result);
  smartlist_free(lst);
}


#define PV_TEST(name, flags)                       \
  { #name, test_protover_ ##name, (flags), NULL, NULL }

struct testcase_t protover_tests[] = {
  PV_TEST(parse, 0),
  PV_TEST(vote, 0),
  END_OF_TESTCASES
};

