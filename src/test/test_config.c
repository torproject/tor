/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include "or.h"
#include "config.h"
#include "connection_edge.h"
#include "test.h"

static void
test_config_addressmap(void)
{
  char buf[1024];
  char address[256];
  time_t expires = TIME_MAX;
  strlcpy(buf, "MapAddress .google.com .torserver.exit\n"
          "MapAddress www.torproject.org 1.1.1.1\n"
          "MapAddress other.torproject.org "
            "this.torproject.org.otherserver.exit\n"
          "MapAddress test.torproject.org 2.2.2.2\n"
          "MapAddress www.google.com 3.3.3.3\n"
          "MapAddress www.example.org 4.4.4.4\n"
          "MapAddress 4.4.4.4 5.5.5.5\n"
          "MapAddress www.infiniteloop.org 6.6.6.6\n"
          "MapAddress 6.6.6.6 www.infiniteloop.org\n"
          , sizeof(buf));

  config_get_lines(buf, &(get_options()->AddressMap));
  config_register_addressmaps(get_options());

  /* Where no mapping for FQDN match on top-level domain */
  strlcpy(address, "reader.google.com", sizeof(address));
  test_assert(addressmap_rewrite(address, sizeof(address), &expires));
  test_streq(address, "reader.google.com.torserver.exit");

  /* Where mapping for FQDN match on FQDN */
  strlcpy(address, "www.google.com", sizeof(address));
  test_assert(addressmap_rewrite(address, sizeof(address), &expires));
  test_streq(address, "3.3.3.3");

  strlcpy(address, "www.torproject.org", sizeof(address));
  test_assert(addressmap_rewrite(address, sizeof(address), &expires));
  test_streq(address, "1.1.1.1");

  strlcpy(address, "other.torproject.org", sizeof(address));
  test_assert(addressmap_rewrite(address, sizeof(address), &expires));
  test_streq(address, "this.torproject.org.otherserver.exit");

  strlcpy(address, "test.torproject.org", sizeof(address));
  test_assert(addressmap_rewrite(address, sizeof(address), &expires));
  test_streq(address, "2.2.2.2");

  /* Test a chain of address mappings */
  strlcpy(address, "www.example.org", sizeof(address));
  test_assert(addressmap_rewrite(address, sizeof(address), &expires));
  test_streq(address, "5.5.5.5");

  /* Test infinite address mapping results in no change */
  strlcpy(address, "www.infiniteloop.org", sizeof(address));
  test_assert(addressmap_rewrite(address, sizeof(address), &expires));
  test_streq(address, "www.infiniteloop.org");

  /* Test we don't find false positives */
  strlcpy(address, "www.example.com", sizeof(address));
  test_assert(!addressmap_rewrite(address, sizeof(address), &expires));

  /* Test top-level-domain matching a bit harder */
  addressmap_clear_configured();
  strlcpy(buf, "MapAddress .com .torserver.exit\n"
          "MapAddress .torproject.org 1.1.1.1\n"
          "MapAddress .net 2.2.2.2\n"
          , sizeof(buf));
  config_get_lines(buf, &(get_options()->AddressMap));
  config_register_addressmaps(get_options());

  strlcpy(address, "www.abc.com", sizeof(address));
  test_assert(addressmap_rewrite(address, sizeof(address), &expires));
  test_streq(address, "www.abc.com.torserver.exit");

  strlcpy(address, "www.def.com", sizeof(address));
  test_assert(addressmap_rewrite(address, sizeof(address), &expires));
  test_streq(address, "www.def.com.torserver.exit");

  strlcpy(address, "www.torproject.org", sizeof(address));
  test_assert(addressmap_rewrite(address, sizeof(address), &expires));
  test_streq(address, "1.1.1.1");

  strlcpy(address, "test.torproject.org", sizeof(address));
  test_assert(addressmap_rewrite(address, sizeof(address), &expires));
  test_streq(address, "1.1.1.1");

  strlcpy(address, "torproject.net", sizeof(address));
  test_assert(addressmap_rewrite(address, sizeof(address), &expires));
  test_streq(address, "2.2.2.2");

  /* We don't support '.' as a mapping directive */
  addressmap_clear_configured();
  strlcpy(buf, "MapAddress . .torserver.exit\n", sizeof(buf));
  config_get_lines(buf, &(get_options()->AddressMap));
  config_register_addressmaps(get_options());

  strlcpy(address, "www.abc.com", sizeof(address));
  test_assert(!addressmap_rewrite(address, sizeof(address), &expires));

  strlcpy(address, "www.def.net", sizeof(address));
  test_assert(!addressmap_rewrite(address, sizeof(address), &expires));

  strlcpy(address, "www.torproject.org", sizeof(address));
  test_assert(!addressmap_rewrite(address, sizeof(address), &expires));

done:
  ;
}

#define CONFIG_LEGACY(name)                                               \
  { #name, legacy_test_helper, 0, &legacy_setup, test_config_ ## name }

#define CONFIG_TEST(name, flags)                          \
  { #name, test_config_ ## name, flags, NULL, NULL }

struct testcase_t config_tests[] = {
  CONFIG_LEGACY(addressmap),
  END_OF_TESTCASES
};

