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
test_protover_parse_fail(void *arg)
{
  (void)arg;
  smartlist_t *elts;

  /* random junk */
  elts = parse_protocol_list("!!3@*");
  tt_assert(elts == NULL);

  /* Missing equals sign in an entry */
  elts = parse_protocol_list("Link=4 Haprauxymatyve Desc=9");
  tt_assert(elts == NULL);

  /* Missing word. */
  elts = parse_protocol_list("Link=4 =3 Desc=9");
  tt_assert(elts == NULL);

  /* Broken numbers */
  elts = parse_protocol_list("Link=fred");
  tt_assert(elts == NULL);
  elts = parse_protocol_list("Link=1,fred");
  tt_assert(elts == NULL);
  elts = parse_protocol_list("Link=1,fred,3");
  tt_assert(elts == NULL);

  /* Broken range */
  elts = parse_protocol_list("Link=1,9-8,3");
  tt_assert(elts == NULL);

 done:
  ;
}

static void
test_protover_vote(void *arg)
{
  (void) arg;

  smartlist_t *lst = smartlist_new();
  char *result = protover_compute_vote(lst, 1);

  tt_str_op(result, OP_EQ, "");
  tor_free(result);

  smartlist_add(lst, (void*) "Foo=1-10,500 Bar=1,3-7,8");
  result = protover_compute_vote(lst, 1);
  tt_str_op(result, OP_EQ, "Bar=1,3-8 Foo=1-10,500");
  tor_free(result);

  smartlist_add(lst, (void*) "Quux=123-456,78 Bar=2-6,8 Foo=9");
  result = protover_compute_vote(lst, 1);
  tt_str_op(result, OP_EQ, "Bar=1-8 Foo=1-10,500 Quux=78,123-456");
  tor_free(result);

  result = protover_compute_vote(lst, 2);
  tt_str_op(result, OP_EQ, "Bar=3-6,8 Foo=9");
  tor_free(result);

  /* High threshold */
  result = protover_compute_vote(lst, 3);
  tt_str_op(result, OP_EQ, "");
  tor_free(result);

  /* Bad votes: the result must be empty */
  smartlist_clear(lst);
  smartlist_add(lst, (void*) "Faux=10-5");
  result = protover_compute_vote(lst, 1);
  tt_str_op(result, OP_EQ, "");
  tor_free(result);

  /* This fails, since "-0" is not valid. */
  smartlist_clear(lst);
  smartlist_add(lst, (void*) "Faux=-0");
  result = protover_compute_vote(lst, 1);
  tt_str_op(result, OP_EQ, "");
  tor_free(result);

  /* Vote large protover lists that are just below the threshold */

  /* Just below the threshold: Rust */
  smartlist_clear(lst);
  smartlist_add(lst, (void*) "Sleen=1-500");
  result = protover_compute_vote(lst, 1);
  tt_str_op(result, OP_EQ, "Sleen=1-500");
  tor_free(result);

  /* Just below the threshold: C */
  smartlist_clear(lst);
  smartlist_add(lst, (void*) "Sleen=1-65536");
  result = protover_compute_vote(lst, 1);
  tt_str_op(result, OP_EQ, "Sleen=1-65536");
  tor_free(result);

  /* Large protover lists that exceed the threshold */

  /* By adding two votes, C allows us to exceed the limit */
  smartlist_add(lst, (void*) "Sleen=1-65536");
  smartlist_add(lst, (void*) "Sleen=100000");
  result = protover_compute_vote(lst, 1);
  tt_str_op(result, OP_EQ, "Sleen=1-65536,100000");
  tor_free(result);

  /* Large integers */
  smartlist_clear(lst);
  smartlist_add(lst, (void*) "Sleen=4294967294");
  result = protover_compute_vote(lst, 1);
  tt_str_op(result, OP_EQ, "Sleen=4294967294");
  tor_free(result);

  /* This parses, but fails at the vote stage */
  smartlist_clear(lst);
  smartlist_add(lst, (void*) "Sleen=4294967295");
  result = protover_compute_vote(lst, 1);
  tt_str_op(result, OP_EQ, "");
  tor_free(result);

  smartlist_clear(lst);
  smartlist_add(lst, (void*) "Sleen=4294967296");
  result = protover_compute_vote(lst, 1);
  tt_str_op(result, OP_EQ, "");
  tor_free(result);

 done:
  tor_free(result);
  smartlist_free(lst);
}

static void
test_protover_all_supported(void *arg)
{
  (void)arg;
  char *msg = NULL;

  tt_assert(protover_all_supported(NULL, &msg));
  tt_assert(msg == NULL);

  tt_assert(protover_all_supported("", &msg));
  tt_assert(msg == NULL);

  // Some things that we do support
  tt_assert(protover_all_supported("Link=3-4", &msg));
  tt_assert(msg == NULL);
  tt_assert(protover_all_supported("Link=3-4 Desc=2", &msg));
  tt_assert(msg == NULL);

  // Some things we don't support
  tt_assert(! protover_all_supported("Wombat=9", &msg));
  tt_str_op(msg, OP_EQ, "Wombat=9");
  tor_free(msg);
  tt_assert(! protover_all_supported("Link=999", &msg));
  tt_str_op(msg, OP_EQ, "Link=999");
  tor_free(msg);

  // Mix of things we support and things we don't
  tt_assert(! protover_all_supported("Link=3-4 Wombat=9", &msg));
  tt_str_op(msg, OP_EQ, "Wombat=9");
  tor_free(msg);
  tt_assert(! protover_all_supported("Link=3-999", &msg));
  tt_str_op(msg, OP_EQ, "Link=3-999");
  tor_free(msg);

  /* CPU/RAM DoS loop: Rust only */
  tt_assert(! protover_all_supported("Sleen=0-2147483648", &msg));
  tt_str_op(msg, OP_EQ, "Sleen=0-2147483648");
  tor_free(msg);

  /* This case is allowed. */
  tt_assert(! protover_all_supported("Sleen=0-4294967294", &msg));
  tt_str_op(msg, OP_EQ, "Sleen=0-4294967294");
  tor_free(msg);

  /* If we get an unparseable list, we say "yes, that's supported." */
#ifndef HAVE_RUST
  // XXXX let's make this section unconditional: rust should behave the
  // XXXX same as C here!
  tor_capture_bugs_(1);
  tt_assert(protover_all_supported("Fribble", &msg));
  tt_ptr_op(msg, OP_EQ, NULL);
  tor_end_capture_bugs_();

  /* This case is forbidden. Since it came from a protover_all_supported,
   * it can trigger a bug message.  */
  tor_capture_bugs_(1);
  tt_assert(protover_all_supported("Sleen=0-4294967295", &msg));
  tt_ptr_op(msg, OP_EQ, NULL);
  tor_free(msg);
  tor_end_capture_bugs_();
#endif

 done:
  tor_end_capture_bugs_();
  tor_free(msg);
}

static void
test_protover_vote_roundtrip(void *args)
{
  (void) args;
  static const struct {
    const char *input;
    const char *expected_output;
  } examples[] = {
    { "Fkrkljdsf", NULL },
    { "Zn=4294967295", NULL },
    { "Zn=4294967295-1", NULL },
    { "Zn=4294967293-4294967295", NULL },
    /* Will fail because of 4294967295. */
    { "Foo=1,3 Bar=3 Baz= Quux=9-12,14,15-16,900 Zn=0,4294967295",
       NULL },
    { "Foo=1,3 Bar=3 Baz= Quux=9-12,14,15-16,900 Zn=0,4294967294",
      "Bar=3 Foo=1,3 Quux=9-12,14-16,900 Zn=0,4294967294" },
    { "Zu16=0,65536", "Zu16=0,65536" },
    { "N-1=1,2", "N-1=1-2" },
    { "-1=4294967295", NULL },
    { "-1=3", "-1=3" },
    /* junk. */
    { "!!3@*", NULL },
    /* Missing equals sign */
    { "Link=4 Haprauxymatyve Desc=9", NULL },
    { "Link=4 Haprauxymatyve=7 Desc=9",
      "Desc=9 Haprauxymatyve=7 Link=4" },
    { "=10-11", NULL },
    { "X=10-11", "X=10-11" },
    { "Link=4 =3 Desc=9", NULL },
    { "Link=4 Z=3 Desc=9", "Desc=9 Link=4 Z=3" },
    { "Link=fred", NULL },
    { "Link=1,fred", NULL },
    { "Link=1,fred,3", NULL },
    { "Link=1,9-8,3", NULL },
    { "Faux=-0", NULL },
    { "Faux=0--0", NULL },
    // "These fail at the splitting stage in Rust, but the number parsing
    // stage in C."
    { "Faux=-1", NULL },
    { "Faux=-1-3", NULL },
    { "Faux=1--1", NULL },
    /* Large integers */
    { "Link=4294967296", NULL },
    /* Large range */
    { "Sleen=1-501", "Sleen=1-501" },
    { "Sleen=1-65537", NULL },
    /* CPU/RAM DoS Loop: Rust only. */
    { "Sleen=0-2147483648", NULL },
    /* Rust seems to experience an internal error here. */
    { "Sleen=0-4294967295", NULL },
  };
  unsigned u;
  smartlist_t *votes = smartlist_new();
  char *result = NULL;

  for (u = 0; u < ARRAY_LENGTH(examples); ++u) {
    const char *input = examples[u].input;
    const char *expected_output = examples[u].expected_output;

    smartlist_add(votes, (void*)input);
    result = protover_compute_vote(votes, 1);
    if (expected_output != NULL) {
      tt_str_op(result, OP_EQ, expected_output);
    } else {
      tt_str_op(result, OP_EQ, "");
    }

    smartlist_clear(votes);
    tor_free(result);
  }

 done:
  smartlist_free(votes);
  tor_free(result);
}

#define PV_TEST(name, flags)                       \
  { #name, test_protover_ ##name, (flags), NULL, NULL }

struct testcase_t protover_tests[] = {
  PV_TEST(parse, 0),
  PV_TEST(parse_fail, 0),
  PV_TEST(vote, 0),
  PV_TEST(all_supported, 0),
  PV_TEST(vote_roundtrip, 0),
  END_OF_TESTCASES
};

