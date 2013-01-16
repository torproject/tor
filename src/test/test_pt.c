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

  managed_proxy_t *mp = tor_malloc(sizeof(managed_proxy_t));
  mp->conf_state = PT_PROTO_INFANT;
  mp->transports = smartlist_new();

  /* incomplete cmethod */
  strcpy(line,"CMETHOD trebuchet");
  test_assert(parse_cmethod_line(line, mp) < 0);

  reset_mp(mp);

  /* wrong proxy type */
  strcpy(line,"CMETHOD trebuchet dog 127.0.0.1:1999");
  test_assert(parse_cmethod_line(line, mp) < 0);

  reset_mp(mp);

  /* wrong addrport */
  strcpy(line,"CMETHOD trebuchet socks4 abcd");
  test_assert(parse_cmethod_line(line, mp) < 0);

  reset_mp(mp);

  /* correct line */
  strcpy(line,"CMETHOD trebuchet socks5 127.0.0.1:1999");
  test_assert(parse_cmethod_line(line, mp) == 0);
  test_assert(smartlist_len(mp->transports));

  reset_mp(mp);

  /* incomplete smethod */
  strcpy(line,"SMETHOD trebuchet");
  test_assert(parse_smethod_line(line, mp) < 0);

  reset_mp(mp);

  /* wrong addr type */
  strcpy(line,"SMETHOD trebuchet abcd");
  test_assert(parse_smethod_line(line, mp) < 0);

  reset_mp(mp);

  /* cowwect */
  strcpy(line,"SMETHOD trebuchy 127.0.0.1:1999");
  test_assert(parse_smethod_line(line, mp) == 0);

  reset_mp(mp);

  /* unsupported version */
  strcpy(line,"VERSION 666");
  test_assert(parse_version(line, mp) < 0);

  /* incomplete VERSION */
  strcpy(line,"VERSION ");
  test_assert(parse_version(line, mp) < 0);

  /* correct VERSION */
  strcpy(line,"VERSION 1");
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

  strcpy(line,"VERSION 1");
  handle_proxy_line(line, mp);
  test_assert(mp->conf_state == PT_PROTO_ACCEPTING_METHODS);

  strcpy(line,"VERSION 1");
  handle_proxy_line(line, mp);
  test_assert(mp->conf_state == PT_PROTO_BROKEN);

  reset_mp(mp);

  strcpy(line,"CMETHOD trebuchet socks5 127.0.0.1:1999");
  handle_proxy_line(line, mp);
  test_assert(mp->conf_state == PT_PROTO_BROKEN);

  reset_mp(mp);

  /* correct protocol run: */
  strcpy(line,"VERSION 1");
  handle_proxy_line(line, mp);
  test_assert(mp->conf_state == PT_PROTO_ACCEPTING_METHODS);

  strcpy(line,"CMETHOD trebuchet socks5 127.0.0.1:1999");
  handle_proxy_line(line, mp);
  test_assert(mp->conf_state == PT_PROTO_ACCEPTING_METHODS);

  strcpy(line,"CMETHODS DONE");
  handle_proxy_line(line, mp);
  test_assert(mp->conf_state == PT_PROTO_CONFIGURED);

 done:
  tor_free(mp);
}

#define PT_LEGACY(name)                                               \
  { #name, legacy_test_helper, 0, &legacy_setup, test_pt_ ## name }

struct testcase_t pt_tests[] = {
  PT_LEGACY(parsing),
  PT_LEGACY(protocol),
  END_OF_TESTCASES
};

