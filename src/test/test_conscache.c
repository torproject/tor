/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#include "config.h"
#include "conscache.h"
#include "test.h"

#ifdef HAVE_UTIME_H
#include <utime.h>
#endif

static void
test_conscache_simple_usage(void *arg)
{
  (void)arg;
  consensus_cache_entry_t *ent = NULL, *ent2 = NULL;

  /* Make a temporary datadir for these tests */
  char *ddir_fname = tor_strdup(get_fname_rnd("datadir_cache"));
  tor_free(get_options_mutable()->DataDirectory);
  get_options_mutable()->DataDirectory = tor_strdup(ddir_fname);
  check_private_dir(ddir_fname, CPD_CREATE, NULL);
  consensus_cache_t *cache = consensus_cache_open("cons", 128);

  tt_assert(cache);

  /* Create object; make sure it exists. */
  config_line_t *labels = NULL;
  config_line_append(&labels, "Hello", "world");
  config_line_append(&labels, "Adios", "planetas");
  ent = consensus_cache_add(cache,
                            labels, (const uint8_t *)"A\0B\0C", 5);
  config_free_lines(labels);
  labels = NULL;
  tt_assert(ent);

  /* Make a second object */
  config_line_append(&labels, "Hello", "mundo");
  config_line_append(&labels, "Adios", "planets");
  ent2 = consensus_cache_add(cache,
                             labels, (const uint8_t *)"xyzzy", 5);
  config_free_lines(labels);
  labels = NULL;
  tt_assert(ent2);
  tt_assert(! consensus_cache_entry_is_mapped(ent2));
  consensus_cache_entry_decref(ent2);
  ent2 = NULL;

  /* Check get_value */
  tt_ptr_op(NULL, OP_EQ, consensus_cache_entry_get_value(ent, "hebbo"));
  tt_str_op("world", OP_EQ, consensus_cache_entry_get_value(ent, "Hello"));

  /* Check find_first */
  ent2 = consensus_cache_find_first(cache, "Hello", "world!");
  tt_ptr_op(ent2, OP_EQ, NULL);
  ent2 = consensus_cache_find_first(cache, "Hello", "world");
  tt_ptr_op(ent2, OP_EQ, ent);
  ent2 = consensus_cache_find_first(cache, "Hello", "mundo");
  tt_ptr_op(ent2, OP_NE, ent);

  tt_assert(! consensus_cache_entry_is_mapped(ent));

  /* Check get_body */
  const uint8_t *bp = NULL;
  size_t sz = 0;
  int r = consensus_cache_entry_get_body(ent, &bp, &sz);
  tt_int_op(r, OP_EQ, 0);
  tt_u64_op(sz, OP_EQ, 5);
  tt_mem_op(bp, OP_EQ, "A\0B\0C", 5);
  tt_assert(consensus_cache_entry_is_mapped(ent));

  /* Free and re-create the cache, to rescan the directory. */
  consensus_cache_free(cache);
  consensus_cache_entry_decref(ent);
  cache = consensus_cache_open("cons", 128);

  /* Make sure the entry is still there */
  ent = consensus_cache_find_first(cache, "Hello", "mundo");
  tt_assert(ent);
  ent2 = consensus_cache_find_first(cache, "Adios", "planets");
  tt_ptr_op(ent, OP_EQ, ent2);
  consensus_cache_entry_incref(ent);
  tt_assert(! consensus_cache_entry_is_mapped(ent));
  r = consensus_cache_entry_get_body(ent, &bp, &sz);
  tt_int_op(r, OP_EQ, 0);
  tt_u64_op(sz, OP_EQ, 5);
  tt_mem_op(bp, OP_EQ, "xyzzy", 5);
  tt_assert(consensus_cache_entry_is_mapped(ent));

  /* There should be two entries total. */
  smartlist_t *entries = smartlist_new();
  consensus_cache_find_all(entries, cache, NULL, NULL);
  int n = smartlist_len(entries);
  smartlist_free(entries);
  tt_int_op(n, OP_EQ, 2);

 done:
  consensus_cache_entry_decref(ent);
  tor_free(ddir_fname);
  consensus_cache_free(cache);
}

#define ENT(name)                                               \
  { #name, test_conscache_ ## name, TT_FORK, NULL, NULL }

struct testcase_t conscache_tests[] = {
  ENT(simple_usage),
  END_OF_TESTCASES
};

