/* Copyright (c) 2014-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_helpers.c
 * \brief Some helper functions to avoid code duplication in unit tests.
 */

#define ROUTERLIST_PRIVATE
#include "orconfig.h"
#include "or.h"

#include "relay.h"
#include "routerlist.h"
#include "nodelist.h"
#include "buffers.h"

#include "test.h"
#include "test_helpers.h"

#ifdef HAVE_CFLAG_WOVERLENGTH_STRINGS
DISABLE_GCC_WARNING(overlength-strings)
/* We allow huge string constants in the unit tests, but not in the code
 * at large. */
#endif
#include "test_descriptors.inc"
#include "or.h"
#include "circuitlist.h"
#ifdef HAVE_CFLAG_WOVERLENGTH_STRINGS
ENABLE_GCC_WARNING(overlength-strings)
#endif

/* Return a statically allocated string representing yesterday's date
 * in ISO format. We use it so that state file items are not found to
 * be outdated. */
const char *
get_yesterday_date_str(void)
{
  static char buf[ISO_TIME_LEN+1];

  time_t yesterday = time(NULL) - 24*60*60;
  format_iso_time(buf, yesterday);
  return buf;
}

/* NOP replacement for router_descriptor_is_older_than() */
static int
router_descriptor_is_older_than_replacement(const routerinfo_t *router,
                                            int seconds)
{
  (void) router;
  (void) seconds;
  return 0;
}

/** Parse a file containing router descriptors and load them to our
    routerlist. This function is used to setup an artificial network
    so that we can conduct tests on it. */
void
helper_setup_fake_routerlist(void)
{
  int retval;
  routerlist_t *our_routerlist = NULL;
  smartlist_t *our_nodelist = NULL;

  /* Read the file that contains our test descriptors. */

  /* We need to mock this function otherwise the descriptors will not
     accepted as they are too old. */
  MOCK(router_descriptor_is_older_than,
       router_descriptor_is_older_than_replacement);

  /* Load all the test descriptors to the routerlist. */
  retval = router_load_routers_from_string(TEST_DESCRIPTORS,
                                           NULL, SAVED_IN_JOURNAL,
                                           NULL, 0, NULL);
  tt_int_op(retval, ==, HELPER_NUMBER_OF_DESCRIPTORS);

  /* Sanity checking of routerlist and nodelist. */
  our_routerlist = router_get_routerlist();
  tt_int_op(smartlist_len(our_routerlist->routers), ==,
              HELPER_NUMBER_OF_DESCRIPTORS);
  routerlist_assert_ok(our_routerlist);

  our_nodelist = nodelist_get_list();
  tt_int_op(smartlist_len(our_nodelist), ==, HELPER_NUMBER_OF_DESCRIPTORS);

  /* Mark all routers as non-guards but up and running! */
  SMARTLIST_FOREACH_BEGIN(our_nodelist, node_t *, node) {
    node->is_running = 1;
    node->is_valid = 1;
    node->is_possible_guard = 0;
  } SMARTLIST_FOREACH_END(node);

 done:
  UNMOCK(router_descriptor_is_older_than);
}

void
connection_write_to_buf_mock(const char *string, size_t len,
                             connection_t *conn, int zlib)
{
  (void) zlib;

  tor_assert(string);
  tor_assert(conn);

  write_to_buf(string, len, conn->outbuf);
}

/* Set up a fake origin circuit with the specified number of cells,
 * Return a pointer to the newly-created dummy circuit */
circuit_t *
dummy_origin_circuit_new(int n_cells)
{
  origin_circuit_t *circ = origin_circuit_new();
  int i;
  cell_t cell;

  for (i=0; i < n_cells; ++i) {
    crypto_rand((void*)&cell, sizeof(cell));
    cell_queue_append_packed_copy(TO_CIRCUIT(circ),
                                  &TO_CIRCUIT(circ)->n_chan_cells,
                                  1, &cell, 1, 0);
  }

  TO_CIRCUIT(circ)->purpose = CIRCUIT_PURPOSE_C_GENERAL;
  return TO_CIRCUIT(circ);
}

/** Mock-replacement. As tor_addr_lookup, but always fails on any
 * address containing a !.  This is necessary for running the unit tests
 * on networks where DNS hijackers think it's helpful to give answers
 * for things like 1.2.3.4.5 or "invalidstuff!!"
 */
int
mock_tor_addr_lookup__fail_on_bad_addrs(const char *name,
                                        uint16_t family, tor_addr_t *out)
{
  if (name && strchr(name, '!')) {
    return -1;
  }
  return tor_addr_lookup__real(name, family, out);
}

