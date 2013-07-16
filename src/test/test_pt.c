/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#define PT_PRIVATE
#include "or.h"
#include "transports.h"
#include "circuitbuild.h"
#include "test.h"

static void
reset_mp(managed_proxy_t *mp)
{
  mp->conf_state = PT_PROTO_LAUNCHED;
  SMARTLIST_FOREACH(mp->transports, transport_t *, t, transport_free(t));
  smartlist_clear(mp->transports);
}

static void
test_pt_parsing(void)
{
  char line[200];
  transport_t *transport = NULL;
  tor_addr_t test_addr;

  managed_proxy_t *mp = tor_malloc(sizeof(managed_proxy_t));
  mp->conf_state = PT_PROTO_INFANT;
  mp->transports = smartlist_new();

  /* incomplete cmethod */
  strlcpy(line,"CMETHOD trebuchet",sizeof(line));
  test_assert(parse_cmethod_line(line, mp) < 0);

  reset_mp(mp);

  /* wrong proxy type */
  strlcpy(line,"CMETHOD trebuchet dog 127.0.0.1:1999",sizeof(line));
  test_assert(parse_cmethod_line(line, mp) < 0);

  reset_mp(mp);

  /* wrong addrport */
  strlcpy(line,"CMETHOD trebuchet socks4 abcd",sizeof(line));
  test_assert(parse_cmethod_line(line, mp) < 0);

  reset_mp(mp);

  /* correct line */
  strlcpy(line,"CMETHOD trebuchet socks5 127.0.0.1:1999",sizeof(line));
  test_assert(parse_cmethod_line(line, mp) == 0);
  test_assert(smartlist_len(mp->transports) == 1);
  transport = smartlist_get(mp->transports, 0);
  /* test registered address of transport */
  tor_addr_parse(&test_addr, "127.0.0.1");
  test_assert(tor_addr_eq(&test_addr, &transport->addr));
  /* test registered port of transport */
  test_assert(transport->port == 1999);
  /* test registered SOCKS version of transport */
  test_assert(transport->socks_version == PROXY_SOCKS5);
  /* test registered name of transport */
  test_streq(transport->name, "trebuchet");

  reset_mp(mp);

  /* incomplete smethod */
  strlcpy(line,"SMETHOD trebuchet",sizeof(line));
  test_assert(parse_smethod_line(line, mp) < 0);

  reset_mp(mp);

  /* wrong addr type */
  strlcpy(line,"SMETHOD trebuchet abcd",sizeof(line));
  test_assert(parse_smethod_line(line, mp) < 0);

  reset_mp(mp);

  /* cowwect */
  strlcpy(line,"SMETHOD trebuchy 127.0.0.2:2999",sizeof(line));
  test_assert(parse_smethod_line(line, mp) == 0);
  test_assert(smartlist_len(mp->transports) == 1);
  transport = smartlist_get(mp->transports, 0);
  /* test registered address of transport */
  tor_addr_parse(&test_addr, "127.0.0.2");
  test_assert(tor_addr_eq(&test_addr, &transport->addr));
  /* test registered port of transport */
  test_assert(transport->port == 2999);
  /* test registered name of transport */
  test_streq(transport->name, "trebuchy");

  reset_mp(mp);

  /* Include some arguments. Good ones. */
  strlcpy(line,"SMETHOD trebuchet 127.0.0.1:9999 ARGS:counterweight=3,sling=snappy",
          sizeof(line));
  test_assert(parse_smethod_line(line, mp) == 0);
  tt_int_op(1, ==, smartlist_len(mp->transports));
  {
    const transport_t *transport = smartlist_get(mp->transports, 0);
    tt_assert(transport);
    tt_str_op(transport->name, ==, "trebuchet");
    tt_int_op(transport->port, ==, 9999);
    tt_str_op(fmt_addr(&transport->addr), ==, "127.0.0.1");
    tt_str_op(transport->extra_info_args, ==,
              "counterweight=3,sling=snappy");
  }
  reset_mp(mp);

  /* unsupported version */
  strlcpy(line,"VERSION 666",sizeof(line));
  test_assert(parse_version(line, mp) < 0);

  /* incomplete VERSION */
  strlcpy(line,"VERSION ",sizeof(line));
  test_assert(parse_version(line, mp) < 0);

  /* correct VERSION */
  strlcpy(line,"VERSION 1",sizeof(line));
  test_assert(parse_version(line, mp) == 0);

 done:
  tor_free(mp);
}

static void
test_pt_protocol(void)
{
  char line[200];

  managed_proxy_t *mp = tor_malloc_zero(sizeof(managed_proxy_t));
  mp->conf_state = PT_PROTO_LAUNCHED;
  mp->transports = smartlist_new();
  mp->argv = tor_malloc_zero(sizeof(char*)*2);
  mp->argv[0] = tor_strdup("<testcase>");

  /* various wrong protocol runs: */

  strlcpy(line,"VERSION 1",sizeof(line));
  handle_proxy_line(line, mp);
  test_assert(mp->conf_state == PT_PROTO_ACCEPTING_METHODS);

  strlcpy(line,"VERSION 1",sizeof(line));
  handle_proxy_line(line, mp);
  test_assert(mp->conf_state == PT_PROTO_BROKEN);

  reset_mp(mp);

  strlcpy(line,"CMETHOD trebuchet socks5 127.0.0.1:1999",sizeof(line));
  handle_proxy_line(line, mp);
  test_assert(mp->conf_state == PT_PROTO_BROKEN);

  reset_mp(mp);

  /* correct protocol run: */
  strlcpy(line,"VERSION 1",sizeof(line));
  handle_proxy_line(line, mp);
  test_assert(mp->conf_state == PT_PROTO_ACCEPTING_METHODS);

  strlcpy(line,"CMETHOD trebuchet socks5 127.0.0.1:1999",sizeof(line));
  handle_proxy_line(line, mp);
  test_assert(mp->conf_state == PT_PROTO_ACCEPTING_METHODS);

  strlcpy(line,"CMETHODS DONE",sizeof(line));
  handle_proxy_line(line, mp);
  test_assert(mp->conf_state == PT_PROTO_CONFIGURED);

 done:
  tor_free(mp);
}

static void
test_pt_get_extrainfo_string(void *arg)
{
  managed_proxy_t *mp1 = NULL, *mp2 = NULL;
  char **argv1, **argv2;
  smartlist_t *t1 = smartlist_new(), *t2 = smartlist_new();
  int r;
  char *s = NULL;
  (void) arg;

  argv1 = tor_malloc_zero(sizeof(char*)*3);
  argv1[0] = tor_strdup("ewige");
  argv1[1] = tor_strdup("Blumenkraft");
  argv1[2] = NULL;
  argv2 = tor_malloc_zero(sizeof(char*)*4);
  argv2[0] = tor_strdup("und");
  argv2[1] = tor_strdup("ewige");
  argv2[2] = tor_strdup("Schlangenkraft");
  argv2[3] = NULL;

  mp1 = managed_proxy_create(t1, argv1, 1);
  mp2 = managed_proxy_create(t2, argv2, 1);

  r = parse_smethod_line("SMETHOD hagbard 127.0.0.1:5555", mp1);
  tt_int_op(r, ==, 0);
  r = parse_smethod_line("SMETHOD celine 127.0.0.1:1723 ARGS:card=no-enemy",
                         mp2);
  tt_int_op(r, ==, 0);

  /* Force these proxies to look "completed" or they won't generate output. */
  mp1->conf_state = mp2->conf_state = PT_PROTO_COMPLETED;

  s = pt_get_extra_info_descriptor_string();
  tt_assert(s);
  tt_str_op(s, ==,
            "transport hagbard 127.0.0.1:5555\n"
            "transport celine 127.0.0.1:1723 card=no-enemy\n");

 done:
  /* XXXX clean up better */
  smartlist_free(t1);
  smartlist_free(t2);
  tor_free(s);
}

#define PT_LEGACY(name)                                               \
  { #name, legacy_test_helper, 0, &legacy_setup, test_pt_ ## name }

struct testcase_t pt_tests[] = {
  PT_LEGACY(parsing),
  PT_LEGACY(protocol),
  { "get_extrainfo_string", test_pt_get_extrainfo_string, TT_FORK,
    NULL, NULL },
  END_OF_TESTCASES
};

