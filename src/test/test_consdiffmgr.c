/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define CONSDIFFMGR_PRIVATE

#include "or.h"
#include "config.h"
#include "conscache.h"
#include "consdiff.h"
#include "consdiffmgr.h"
#include "cpuworker.h"
#include "networkstatus.h"
#include "workqueue.h"

#include "test.h"
#include "log_test_helpers.h"

// ============================== Setup/teardown the consdiffmgr
// These functions get run before/after each test in this module

static void *
consdiffmgr_test_setup(const struct testcase_t *arg)
{
  (void)arg;
  char *ddir_fname = tor_strdup(get_fname_rnd("datadir_cdm"));
  tor_free(get_options_mutable()->DataDirectory);
  get_options_mutable()->DataDirectory = ddir_fname; // now owns the pointer.
  check_private_dir(ddir_fname, CPD_CREATE, NULL);

  consdiff_cfg_t consdiff_cfg = { 7200, 300 };
  consdiffmgr_configure(&consdiff_cfg);
  return (void *)1; // must return something non-null.
}
static int
consdiffmgr_test_teardown(const struct testcase_t *arg, void *ignore)
{
  (void)arg;
  (void)ignore;
  consdiffmgr_free_all();
  return 1;
}
static struct testcase_setup_t setup_diffmgr = {
  consdiffmgr_test_setup,
  consdiffmgr_test_teardown
};

// ============================== NS faking functions
// These functions are for making quick fake consensus objects and
// strings that are just good enough for consdiff and consdiffmgr.

static networkstatus_t *
fake_ns_new(consensus_flavor_t flav, time_t valid_after)
{
  networkstatus_t *ns = tor_malloc_zero(sizeof(networkstatus_t));
  ns->type = NS_TYPE_CONSENSUS;
  ns->flavor = flav;
  ns->valid_after = valid_after;
  return ns;
}

static char *
fake_ns_body_new(consensus_flavor_t flav, time_t valid_after)
{
  const char *flavor_string = flav == FLAV_NS ? "" : " microdesc";
  char valid_after_string[ISO_TIME_LEN+1];

  format_iso_time(valid_after_string, valid_after);
  char *random_stuff = crypto_random_hostname(3, 25, "junk ", "");

  char *consensus;
  tor_asprintf(&consensus,
               "network-status-version 3%s\n"
               "vote-status consensus\n"
               "valid-after %s\n"
               "r name ccccccccccccccccc etc\nsample\n"
               "r name eeeeeeeeeeeeeeeee etc\nbar\n"
               "%s\n",
               flavor_string,
               valid_after_string,
               random_stuff);
  tor_free(random_stuff);
  return consensus;
}

// ============================== Cpuworker mocking code
// These mocking functions and types capture the cpuworker calls
// so we can inspect them and run them in the main thread.
static smartlist_t *fake_cpuworker_queue = NULL;
typedef struct fake_work_queue_ent_t {
  enum workqueue_reply_t (*fn)(void *, void *);
  void (*reply_fn)(void *);
  void *arg;
} fake_work_queue_ent_t;
static struct workqueue_entry_s *
mock_cpuworker_queue_work(enum workqueue_reply_t (*fn)(void *, void *),
                          void (*reply_fn)(void *),
                          void *arg)
{
  if (! fake_cpuworker_queue)
    fake_cpuworker_queue = smartlist_new();

  fake_work_queue_ent_t *ent = tor_malloc_zero(sizeof(*ent));
  ent->fn = fn;
  ent->reply_fn = reply_fn;
  ent->arg = arg;
  smartlist_add(fake_cpuworker_queue, ent);
  return (struct workqueue_entry_s *)ent;
}
static int
mock_cpuworker_run_work(void)
{
  if (! fake_cpuworker_queue)
    return 0;
  SMARTLIST_FOREACH(fake_cpuworker_queue, fake_work_queue_ent_t *, ent, {
      enum workqueue_reply_t r = ent->fn(NULL, ent->arg);
      if (r != WQ_RPL_REPLY)
        return -1;
  });
  return 0;
}
static void
mock_cpuworker_handle_replies(void)
{
  if (! fake_cpuworker_queue)
    return;
  SMARTLIST_FOREACH(fake_cpuworker_queue, fake_work_queue_ent_t *, ent, {
      ent->reply_fn(ent->arg);
  });
  smartlist_free(fake_cpuworker_queue);
  fake_cpuworker_queue = NULL;
}

// ==============================  Beginning of tests

static void
test_consdiffmgr_add(void *arg)
{
  (void) arg;
  time_t now = approx_time();

  consensus_cache_entry_t *ent = NULL;
  networkstatus_t *ns_tmp = fake_ns_new(FLAV_NS, now);
  const char *dummy = "foo";
  int r = consdiffmgr_add_consensus(dummy, ns_tmp);
  tt_int_op(r, OP_EQ, 0);

  /* If we add it again, it won't work */
  setup_capture_of_logs(LOG_INFO);
  dummy = "bar";
  r = consdiffmgr_add_consensus(dummy, ns_tmp);
  tt_int_op(r, OP_EQ, -1);
  expect_single_log_msg_containing("We already have a copy of that "
                                   "consensus");
  mock_clean_saved_logs();

  /* But it will work fine if the flavor is different */
  dummy = "baz";
  ns_tmp->flavor = FLAV_MICRODESC;
  r = consdiffmgr_add_consensus(dummy, ns_tmp);
  tt_int_op(r, OP_EQ, 0);

  /* And it will work fine if the time is different */
  dummy = "quux";
  ns_tmp->flavor = FLAV_NS;
  ns_tmp->valid_after = now - 60;
  r = consdiffmgr_add_consensus(dummy, ns_tmp);
  tt_int_op(r, OP_EQ, 0);

  /* If we add one a long long time ago, it will fail. */
  dummy = "xyzzy";
  ns_tmp->valid_after = 86400 * 100; /* A few months into 1970 */
  r = consdiffmgr_add_consensus(dummy, ns_tmp);
  tt_int_op(r, OP_EQ, -1);
  expect_single_log_msg_containing("it's too old.");

  /* Try looking up a consensuses. */
  ent = cdm_cache_lookup_consensus(FLAV_NS, now-60);
  tt_assert(ent);
  consensus_cache_entry_incref(ent);
  size_t s;
  const uint8_t *body;
  r = consensus_cache_entry_get_body(ent, &body, &s);
  tt_int_op(r, OP_EQ, 0);
  tt_int_op(s, OP_EQ, 4);
  tt_mem_op(body, OP_EQ, "quux", 4);

  /* Try looking up another entry, but fail */
  tt_assert(NULL == cdm_cache_lookup_consensus(FLAV_MICRODESC, now-60));
  tt_assert(NULL == cdm_cache_lookup_consensus(FLAV_NS, now-61));

 done:
  networkstatus_vote_free(ns_tmp);
  teardown_capture_of_logs();
  consensus_cache_entry_decref(ent);
}

static void
test_consdiffmgr_make_diffs(void *arg)
{
  (void)arg;
  networkstatus_t *ns = NULL;
  char *ns_body = NULL, *md_ns_body = NULL, *md_ns_body_2 = NULL;
  char *applied = NULL, *diff_text = NULL;
  time_t now = approx_time();
  int r;
  consensus_cache_entry_t *diff = NULL;
  uint8_t md_ns_sha3[DIGEST256_LEN];
  consdiff_status_t diff_status;

  MOCK(cpuworker_queue_work, mock_cpuworker_queue_work);

  // Try rescan with no consensuses: shouldn't crash or queue work.
  consdiffmgr_rescan();
  tt_ptr_op(NULL, OP_EQ, fake_cpuworker_queue);

  // Make two consensuses, 1 hour sec ago.
  ns = fake_ns_new(FLAV_NS, now-3600);
  ns_body = fake_ns_body_new(FLAV_NS, now-3600);
  r = consdiffmgr_add_consensus(ns_body, ns);
  networkstatus_vote_free(ns);
  tor_free(ns_body);
  tt_int_op(r, OP_EQ, 0);

  ns = fake_ns_new(FLAV_MICRODESC, now-3600);
  md_ns_body = fake_ns_body_new(FLAV_MICRODESC, now-3600);
  r = consdiffmgr_add_consensus(md_ns_body, ns);
  crypto_digest256((char*)md_ns_sha3, md_ns_body, strlen(md_ns_body),
                   DIGEST_SHA3_256);
  networkstatus_vote_free(ns);
  tt_int_op(r, OP_EQ, 0);

  // No diffs will be generated.
  consdiffmgr_rescan();
  tt_ptr_op(NULL, OP_EQ, fake_cpuworker_queue);

  // Add a MD consensus from 45 minutes ago. This should cause one diff
  // worth of work to get queued.
  ns = fake_ns_new(FLAV_MICRODESC, now-45*60);
  md_ns_body_2 = fake_ns_body_new(FLAV_MICRODESC, now-45*60);
  r = consdiffmgr_add_consensus(md_ns_body_2, ns);
  networkstatus_vote_free(ns);
  tt_int_op(r, OP_EQ, 0);

  consdiffmgr_rescan();
  tt_ptr_op(NULL, OP_NE, fake_cpuworker_queue);
  tt_int_op(1, OP_EQ, smartlist_len(fake_cpuworker_queue));
  // XXXX not working yet
  /*
  diff_status = consdiffmgr_find_diff_from(&diff, FLAV_MICRODESC,
                                           DIGEST_SHA3_256,
                                           md_ns_sha3, DIGEST256_LEN);
  tt_int_op(CONSDIFF_IN_PROGRESS, OP_EQ, diff_status);
  */

  // Now run that process and get the diff.
  r = mock_cpuworker_run_work();
  tt_int_op(r, OP_EQ, 0);
  mock_cpuworker_handle_replies();

  // At this point we should be able to get that diff.
  diff_status = consdiffmgr_find_diff_from(&diff, FLAV_MICRODESC,
                                           DIGEST_SHA3_256,
                                           md_ns_sha3, DIGEST256_LEN);
  tt_int_op(CONSDIFF_AVAILABLE, OP_EQ, diff_status);
  tt_assert(diff);

  /* Make sure applying the diff actually works */
  const uint8_t *diff_body;
  size_t diff_size;
  r = consensus_cache_entry_get_body(diff, &diff_body, &diff_size);
  tt_int_op(r, OP_EQ, 0);
  diff_text = tor_memdup_nulterm(diff_body, diff_size);
  applied = consensus_diff_apply(md_ns_body, diff_text);
  tt_assert(applied);
  tt_str_op(applied, OP_EQ, md_ns_body_2);

  /* Rescan again: no more work to do. */
  consdiffmgr_rescan();
  tt_ptr_op(NULL, OP_EQ, fake_cpuworker_queue);

 done:
  tor_free(md_ns_body);
  tor_free(md_ns_body_2);
  tor_free(diff_text);
  tor_free(applied);
}

#define TEST(name)                                      \
  { #name, test_consdiffmgr_ ## name , TT_FORK, &setup_diffmgr, NULL }

struct testcase_t consdiffmgr_tests[] = {
  TEST(add),
  TEST(make_diffs),
  // XXXX Test: deleting consensuses for being too old
  // XXXX Test: deleting diffs for not being to most recent consensus
  // XXXX Test: Objects of unrecognized doctype are not cleaned.
  // XXXX Test: Objects with bad iso time are not cleaned.
  // XXXX Test: only generate diffs to most recent consensus
  // XXXX Test: making diffs from some old consensuses, but having diffs
  //           for others.
  // XXXX Test: Failure to open cache???
  // XXXX Test: failure to create consensus diff.
  END_OF_TESTCASES
};

