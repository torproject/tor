/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file consdiffmsr.c
 *
 * \brief consensus diff manager functions
 *
 * This module is run by directory authorities and caches in order
 * to remember a number of past consensus documents, and to generate
 * and serve the diffs from those documents to the latest consensus.
 */

#define CONSDIFFMGR_PRIVATE

#include "or.h"
#include "conscache.h"
#include "consdiff.h"
#include "consdiffmgr.h"
#include "cpuworker.h"
#include "networkstatus.h"
#include "workqueue.h"

/* XXXX support compression */

/**
 * Labels to apply to items in the conscache object.
 *
 * @{
 */
/* One of DOCTYPE_CONSENSUS or DOCTYPE_CONSENSUS_DIFF */
#define LABEL_DOCTYPE "document-type"
/* The valid-after time for a consensus (or for the target consensus of a
 * diff), encoded as ISO UTC. */
#define LABEL_VALID_AFTER "consensus-valid-after"
/* A hex encoded SHA3 digest of the object after decompression. */
#define LABEL_SHA3_DIGEST "sha3-digest"
/* The flavor of the consensus or consensuses diff */
#define LABEL_FLAVOR "consensus-flavor"
/* Diff only: the SHA3 digest of the source consensus. */
#define LABEL_FROM_SHA3_DIGEST "from-sha3-digest"
/* Diff only: the SHA3 digest of the target consensus. */
#define LABEL_TARGET_SHA3_DIGEST "target-sha3-digest"
/* Diff only: the valid-after date of the source consensus. */
#define LABEL_FROM_VALID_AFTER "from-valid-after"
/** @} */

#define DOCTYPE_CONSENSUS "consensus"
#define DOCTYPE_CONSENSUS_DIFF "consensus-diff"

/**
 * Underlying directory that stores consensuses and consensus diffs.  Don't
 * use this directly: use cdm_cache_get() instead.
 */
static consensus_cache_t *cons_diff_cache = NULL;
/**
 * If true, we have learned at least one new consensus since the
 * consensus cache was last up-to-date.
 */
static int cdm_cache_dirty = 0;
/**
 * Configuration for this module
 */
static consdiff_cfg_t consdiff_cfg = {
  /* .cache_max_age_hours = */ 24 * 90,
  /* .cache_max_num = */ 1440
};

static int consensus_diff_queue_diff_work(consensus_cache_entry_t *diff_from,
                                          consensus_cache_entry_t *diff_to);

/**
 * Helper: initialize <b>cons_diff_cache</b>.
 */
static void
cdm_cache_init(void)
{
  unsigned n_entries = consdiff_cfg.cache_max_num * 2;

  tor_assert(cons_diff_cache == NULL);
  cons_diff_cache = consensus_cache_open("diff-cache", n_entries);
  if (cons_diff_cache == NULL) {
    log_err(LD_FS, "Error: Couldn't open storage for consensus diffs.");
    tor_assert_unreached();
  }
  cdm_cache_dirty = 1;
}

/**
 * Helper: return the consensus_cache_t * that backs this manager,
 * initializing it if needed.
 */
static consensus_cache_t *
cdm_cache_get(void)
{
  if (PREDICT_UNLIKELY(cons_diff_cache == NULL)) {
    cdm_cache_init();
  }
  return cons_diff_cache;
}

/**
 * Helper: given a list of labels, prepend the hex-encoded SHA3 digest
 * of the <b>bodylen</b>-byte object at <b>body</b> to those labels,
 * with LABEL_SHA3_DIGEST as its label.
 */
static void
cdm_labels_prepend_sha3(config_line_t **labels,
                        const uint8_t *body,
                        size_t bodylen)
{
  uint8_t sha3_digest[DIGEST256_LEN];
  char hexdigest[HEX_DIGEST256_LEN+1];
  crypto_digest256((char *)sha3_digest,
                   (const char *)body, bodylen, DIGEST_SHA3_256);
  base16_encode(hexdigest, sizeof(hexdigest),
                (const char *)sha3_digest, sizeof(sha3_digest));

  config_line_prepend(labels, LABEL_SHA3_DIGEST, hexdigest);
}

/**
 * Helper: look for a consensus with the given <b>flavor</b> and
 * <b>valid_after</b> time in the cache. Return that consensus if it's
 * present, or NULL if it's missing.
 */
STATIC consensus_cache_entry_t *
cdm_cache_lookup_consensus(consensus_flavor_t flavor, time_t valid_after)
{
  char formatted_time[ISO_TIME_LEN+1];
  format_iso_time_nospace(formatted_time, valid_after);
  const char *flavname = networkstatus_get_flavor_name(flavor);

  /* We'll filter by valid-after time first, since that should
   * match the fewest documents. */
  // XXXX This is stupid and it should be a hash table.
  smartlist_t *matches = smartlist_new();
  consensus_cache_find_all(matches, cdm_cache_get(),
                           LABEL_VALID_AFTER, formatted_time);
  consensus_cache_filter_list(matches, LABEL_FLAVOR, flavname);
  consensus_cache_filter_list(matches, LABEL_DOCTYPE, DOCTYPE_CONSENSUS);

  consensus_cache_entry_t *result = NULL;
  if (smartlist_len(matches) > 1) {
    log_warn(LD_BUG, "How odd; there appear to be two matching consensuses "
             "with flavor %s published at %s.",
             flavname, formatted_time);
  }
  if (smartlist_len(matches)) {
    result = smartlist_get(matches, 0);
  }
  smartlist_free(matches);

  return result;
}

/**
 * Given a string containing a networkstatus consensus, and the results of
 * having parsed that consensus, add that consensus to the cache if it is not
 * already present and not too old.  Create new consensus diffs from or to
 * that consensus as appropriate.
 *
 * Return 0 on success and -1 on failure.
 */
int
consdiffmgr_add_consensus(const char *consensus,
                          const networkstatus_t *as_parsed)
{
  if (BUG(consensus == NULL) || BUG(as_parsed == NULL))
    return -1; // LCOV_EXCL_LINE
  if (BUG(as_parsed->type != NS_TYPE_CONSENSUS))
    return -1; // LCOV_EXCL_LINE

  const consensus_flavor_t flavor = as_parsed->flavor;
  const time_t valid_after = as_parsed->valid_after;

  if (valid_after < approx_time() - 3600 * consdiff_cfg.cache_max_age_hours) {
    log_info(LD_DIRSERV, "We don't care about this consensus document; it's "
             "too old.");
    return -1;
  }

  /* Do we already have this one? */
  consensus_cache_entry_t *entry =
    cdm_cache_lookup_consensus(flavor, valid_after);
  if (entry) {
    log_info(LD_DIRSERV, "We already have a copy of that consensus");
    return -1;
  }

  /* We don't have it. Add it to the cache. */
  {
    size_t bodylen = strlen(consensus);
    config_line_t *labels = NULL;
    char formatted_time[ISO_TIME_LEN+1];
    format_iso_time_nospace(formatted_time, valid_after);
    const char *flavname = networkstatus_get_flavor_name(flavor);

    cdm_labels_prepend_sha3(&labels, (const uint8_t *)consensus, bodylen);
    config_line_prepend(&labels, LABEL_FLAVOR, flavname);
    config_line_prepend(&labels, LABEL_VALID_AFTER, formatted_time);
    config_line_prepend(&labels, LABEL_DOCTYPE, DOCTYPE_CONSENSUS);

    entry = consensus_cache_add(cdm_cache_get(),
                                labels,
                                (const uint8_t *)consensus,
                                bodylen);
    config_free_lines(labels);
  }

  if (entry)
    consensus_cache_entry_decref(entry);

  cdm_cache_dirty = 1;
  return entry ? 0 : -1;
}

/**
 * Helper: used to sort two smartlists of consensus_cache_entry_t by their
 * LABEL_VALID_AFTER labels.
 */
static int
compare_by_valid_after_(const void **a, const void **b)
{
  const consensus_cache_entry_t *e1 = *a;
  const consensus_cache_entry_t *e2 = *b;
  /* We're in luck here: sorting UTC iso-encoded values lexically will work
   * fine (until 9999). */
  return strcmp_opt(consensus_cache_entry_get_value(e1, LABEL_VALID_AFTER),
                    consensus_cache_entry_get_value(e2, LABEL_VALID_AFTER));
}

/**
 * Helper: Sort <b>lst</b> by LABEL_VALID_AFTER and return the most recent
 * entry.
 */
static consensus_cache_entry_t *
sort_and_find_most_recent(smartlist_t *lst)
{
  smartlist_sort(lst, compare_by_valid_after_);
  if (smartlist_len(lst)) {
    return smartlist_get(lst, smartlist_len(lst) - 1);
  } else {
    return NULL;
  }
}

/**
 * Look up consensus_cache_entry_t for the consensus of type <b>flavor</b>,
 * from the source consensus with the specified digest (which must be SHA3).
 *
 * If the diff is present, store it into *<b>entry_out</b> and return
 * CONSDIFF_AVAILABLE. Otherwise return CONSDIFF_NOT_FOUND or
 * CONSDIFF_IN_PROGRESS.
 */
consdiff_status_t
consdiffmgr_find_diff_from(consensus_cache_entry_t **entry_out,
                           consensus_flavor_t flavor,
                           int digest_type,
                           const uint8_t *digest,
                           size_t digestlen)
{
  // XXXX actually return IN_PROGRESS some times?
  if (BUG(digest_type != DIGEST_SHA3_256) ||
      BUG(digestlen != DIGEST256_LEN)) {
    return CONSDIFF_NOT_FOUND; // LCOV_EXCL_LINE
  }

  char hex[HEX_DIGEST256_LEN+1];
  base16_encode(hex, sizeof(hex), (const char *)digest, digestlen);
  const char *flavname = networkstatus_get_flavor_name(flavor);

  smartlist_t *matches = smartlist_new();
  consensus_cache_find_all(matches, cdm_cache_get(),
                           LABEL_FROM_SHA3_DIGEST, hex);
  consensus_cache_filter_list(matches, LABEL_FLAVOR, flavname);
  consensus_cache_filter_list(matches, LABEL_DOCTYPE, DOCTYPE_CONSENSUS_DIFF);

  *entry_out = sort_and_find_most_recent(matches);
  consdiff_status_t result =
    (*entry_out) ? CONSDIFF_AVAILABLE : CONSDIFF_NOT_FOUND;
  smartlist_free(matches);

  return result;
}

/**
 * Perform periodic cleanup tasks on the consensus diff cache.  Return
 * the number of objects marked for deletion.
 */
int
consdiffmgr_cleanup(void)
{
  smartlist_t *objects = smartlist_new();
  smartlist_t *consensuses = smartlist_new();
  smartlist_t *diffs = smartlist_new();
  int n_to_delete = 0;

  log_debug(LD_DIRSERV, "Looking for consdiffmgr entries to remove");

  // 1. Delete any consensus or diff or anything whose valid_after is too old.
  const time_t valid_after_cutoff =
    approx_time() - 3600 * consdiff_cfg.cache_max_age_hours;

  consensus_cache_find_all(objects, cdm_cache_get(),
                           NULL, NULL);
  SMARTLIST_FOREACH_BEGIN(objects, consensus_cache_entry_t *, ent) {
    const char *lv_valid_after =
      consensus_cache_entry_get_value(ent, LABEL_VALID_AFTER);
    if (! lv_valid_after) {
      log_debug(LD_DIRSERV, "Ignoring entry because it had no %s label",
                LABEL_VALID_AFTER);
      continue;
    }
    time_t valid_after = 0;
    if (parse_iso_time_nospace(lv_valid_after, &valid_after) < 0) {
      log_debug(LD_DIRSERV, "Ignoring entry because its %s value (%s) was "
                "unparseable", LABEL_VALID_AFTER, escaped(lv_valid_after));
      continue;
    }
    if (valid_after < valid_after_cutoff) {
      log_debug(LD_DIRSERV, "Deleting entry because its %s value (%s) was "
                "too old", LABEL_VALID_AFTER, lv_valid_after);
      consensus_cache_entry_mark_for_removal(ent);
      ++n_to_delete;
    }
  } SMARTLIST_FOREACH_END(ent);

  // 2. Delete all diffs that lead to a consensus whose valid-after is not the
  // latest.
  for (int flav = 0; flav < N_CONSENSUS_FLAVORS; ++flav) {
    const char *flavname = networkstatus_get_flavor_name(flav);
    /* Determine the most recent consensus of this flavor */
    consensus_cache_find_all(consensuses, cdm_cache_get(),
                             LABEL_DOCTYPE, DOCTYPE_CONSENSUS);
    consensus_cache_filter_list(consensuses, LABEL_FLAVOR, flavname);
    consensus_cache_entry_t *most_recent =
      sort_and_find_most_recent(consensuses);
    if (most_recent == NULL)
      continue;
    const char *most_recent_sha3 =
      consensus_cache_entry_get_value(most_recent, LABEL_SHA3_DIGEST);
    if (BUG(most_recent_sha3 == NULL))
      continue; // LCOV_EXCL_LINE

    /* consider all such-flavored diffs, and look to see if they match. */
    consensus_cache_find_all(diffs, cdm_cache_get(),
                             LABEL_DOCTYPE, DOCTYPE_CONSENSUS_DIFF);
    consensus_cache_filter_list(diffs, LABEL_FLAVOR, flavname);
    SMARTLIST_FOREACH_BEGIN(diffs, consensus_cache_entry_t *, diff) {
      const char *this_diff_target_sha3 =
        consensus_cache_entry_get_value(diff, LABEL_TARGET_SHA3_DIGEST);
      if (!this_diff_target_sha3)
        continue;
      if (strcmp(this_diff_target_sha3, most_recent_sha3)) {
        consensus_cache_entry_mark_for_removal(diff);
        ++n_to_delete;
      }
    } SMARTLIST_FOREACH_END(diff);
    smartlist_clear(consensuses);
    smartlist_clear(diffs);
  }

  smartlist_free(objects);
  smartlist_free(consensuses);
  smartlist_free(diffs);
  // XXXX for anything where the sha3 doesn't match -- delete it.  But not
  // XXXX here. Somewhere else?

  // Actually remove files, if they're not used.
  consensus_cache_delete_pending(cdm_cache_get());
  return n_to_delete;
}

/**
 * Initialize the consensus diff manager and its cache, and configure
 * its parameters based on the latest torrc and networkstatus parameters.
 */
void
consdiffmgr_configure(const consdiff_cfg_t *cfg)
{
  memcpy(&consdiff_cfg, cfg, sizeof(consdiff_cfg));

  (void) cdm_cache_get();
}

/**
 * Helper: build new diffs of <b>flavor</b> as needed
 */
static void
consdiffmgr_rescan_flavor_(consensus_flavor_t flavor)
{
  smartlist_t *matches = NULL;
  smartlist_t *diffs = NULL;
  smartlist_t *compute_diffs_from = NULL;
  strmap_t *have_diff_from = NULL;

  // look for the most recent consensus, and for all previous in-range
  // consensuses.  Do they all have diffs to it?
  const char *flavname = networkstatus_get_flavor_name(flavor);

  // 1. find the most recent consensus, and the ones that we might want
  //    to diff to it.
  matches = smartlist_new();
  consensus_cache_find_all(matches, cdm_cache_get(),
                           LABEL_FLAVOR, flavname);
  consensus_cache_filter_list(matches, LABEL_DOCTYPE, DOCTYPE_CONSENSUS);
  consensus_cache_entry_t *most_recent = sort_and_find_most_recent(matches);
  if (!most_recent) {
    log_info(LD_DIRSERV, "No 'most recent' %s consensus found; "
             "not making diffs", flavname);
    goto done;
  }
  tor_assert(smartlist_len(matches));
  smartlist_del(matches, smartlist_len(matches) - 1);

  const char *most_recent_valid_after =
    consensus_cache_entry_get_value(most_recent, LABEL_VALID_AFTER);
  if (BUG(most_recent_valid_after == NULL))
    goto done; //LCOV_EXCL_LINE

  // 2. Find all the relevant diffs _to_ this consensus. These are ones
  //    that we don't need to compute.
  diffs = smartlist_new();
  consensus_cache_find_all(diffs, cdm_cache_get(),
                           LABEL_VALID_AFTER, most_recent_valid_after);
  consensus_cache_filter_list(diffs, LABEL_DOCTYPE, DOCTYPE_CONSENSUS_DIFF);
  consensus_cache_filter_list(diffs, LABEL_FLAVOR, flavname);
  have_diff_from = strmap_new();
  SMARTLIST_FOREACH_BEGIN(diffs, consensus_cache_entry_t *, diff) {
    const char *va = consensus_cache_entry_get_value(diff,
                                                     LABEL_FROM_VALID_AFTER);
    if (BUG(va == NULL))
      continue; // LCOV_EXCL_LINE
    strmap_set(have_diff_from, va, diff);
  } SMARTLIST_FOREACH_END(diff);

  // 3. See which consensuses in 'matches' don't have diffs yet.
  smartlist_reverse(matches); // from newest to oldest.
  compute_diffs_from = smartlist_new();
  SMARTLIST_FOREACH_BEGIN(matches, consensus_cache_entry_t *, ent) {
    const char *va = consensus_cache_entry_get_value(ent, LABEL_VALID_AFTER);
    if (BUG(va == NULL))
      continue; // LCOV_EXCL_LINE
    if (strmap_get(have_diff_from, va) != NULL)
      continue; /* we already have this one. */
    smartlist_add(compute_diffs_from, ent);
  } SMARTLIST_FOREACH_END(ent);

  log_info(LD_DIRSERV,
           "The most recent %s consensus is valid-after %s. We have diffs to "
           "this consensus for %d/%d older %s consensuses. Generating diffs "
           "for the other %d.",
           flavname,
           most_recent_valid_after,
           smartlist_len(matches) - smartlist_len(compute_diffs_from),
           smartlist_len(matches),
           flavname,
           smartlist_len(compute_diffs_from));

  // 4. Actually launch the requests.
  SMARTLIST_FOREACH_BEGIN(compute_diffs_from, consensus_cache_entry_t *, c) {
    if (BUG(c == most_recent))
      continue; // LCOV_EXCL_LINE

    // XXXX how do we know that we are not already computing this?????
    // XXXX DO NOT MERGE UNTIL THAT ISSUE IS SOLVED.
    consensus_diff_queue_diff_work(c, most_recent);
  } SMARTLIST_FOREACH_END(c);

 done:
  smartlist_free(matches);
  smartlist_free(diffs);
  smartlist_free(compute_diffs_from);
  strmap_free(have_diff_from, NULL);
}

/**
 * Build new diffs as needed.
 */
void
consdiffmgr_rescan(void)
{
  if (cdm_cache_dirty == 0)
    return;

  // Clean up here to make room for new diffs, and to ensure that older
  // consensuses do not have any entries.
  consdiffmgr_cleanup();

  for (int flav = 0; flav < N_CONSENSUS_FLAVORS; ++flav) {
    consdiffmgr_rescan_flavor_((consensus_flavor_t) flav);
  }

  cdm_cache_dirty = 0;
}

/**
 * Called before shutdown: drop all storage held by the consdiffmgr.c module.
 */
void
consdiffmgr_free_all(void)
{
  consensus_cache_free(cons_diff_cache);
  cons_diff_cache = NULL;
}

/* =====
   Thread workers
   =====*/

/**
 * An object passed to a worker thread that will try to produce a consensus
 * diff.
 */
typedef struct consensus_diff_worker_job_t {
  /**
   * Input: The consensus to compute the diff from.  Holds a reference to the
   * cache entry, which must not be released until the job is passed back to
   * the main thread. The body must be mapped into memory in the main thread.
   */
  consensus_cache_entry_t *diff_from;
  /**
   * Input: The consensus to compute the diff to.  Holds a reference to the
   * cache entry, which must not be released until the job is passed back to
   * the main thread. The body must be mapped into memory in the main thread.
   */
  consensus_cache_entry_t *diff_to;

  /**
   * Output: Labels to store in the cache associated with this diff.
   */
  config_line_t *labels_out;
  /**
   * Output: Body of the diff
   */
  uint8_t *body_out;
  /**
   * Output: length of body_out
   */
  size_t bodylen_out;
} consensus_diff_worker_job_t;

/**
 * Worker function. This function runs inside a worker thread and receives
 * a consensus_diff_worker_job_t as its input.
 */
static workqueue_reply_t
consensus_diff_worker_threadfn(void *state_, void *work_)
{
  (void)state_;
  consensus_diff_worker_job_t *job = work_;
  const uint8_t *diff_from, *diff_to;
  size_t len_from, len_to;
  int r;
  /* We need to have the body already mapped into RAM here.
   */
  r = consensus_cache_entry_get_body(job->diff_from, &diff_from, &len_from);
  if (BUG(r < 0))
    return WQ_RPL_REPLY; // LCOV_EXCL_LINE
  r = consensus_cache_entry_get_body(job->diff_to, &diff_to, &len_to);
  if (BUG(r < 0))
    return WQ_RPL_REPLY; // LCOV_EXCL_LINE

  const char *lv_to_valid_after =
    consensus_cache_entry_get_value(job->diff_to, LABEL_VALID_AFTER);
  const char *lv_from_valid_after =
    consensus_cache_entry_get_value(job->diff_from, LABEL_VALID_AFTER);
  const char *lv_from_digest =
    consensus_cache_entry_get_value(job->diff_from, LABEL_SHA3_DIGEST);
  const char *lv_from_flavor =
    consensus_cache_entry_get_value(job->diff_from, LABEL_FLAVOR);
  const char *lv_to_flavor =
    consensus_cache_entry_get_value(job->diff_to, LABEL_FLAVOR);
  const char *lv_to_digest =
    consensus_cache_entry_get_value(job->diff_to, LABEL_SHA3_DIGEST);

  /* All these values are mandatory on the input */
  if (BUG(!lv_to_valid_after) ||
      BUG(!lv_from_valid_after) ||
      BUG(!lv_from_digest) ||
      BUG(!lv_from_flavor) ||
      BUG(!lv_to_flavor)) {
    return WQ_RPL_REPLY; // LCOV_EXCL_LINE
  }
  /* The flavors need to match */
  if (BUG(strcmp(lv_from_flavor, lv_to_flavor))) {
    return WQ_RPL_REPLY; // LCOV_EXCL_LINE
  }

  char *consensus_diff;
  {
    // XXXX the input might not be nul-terminated. And also we wanted to
    // XXXX support compression later I guess. So, we need to copy here.
    char *diff_from_nt, *diff_to_nt;
    diff_from_nt = tor_memdup_nulterm(diff_from, len_from);
    diff_to_nt = tor_memdup_nulterm(diff_to, len_to);

    // XXXX ugh; this is going to calculate the SHA3 of both its
    // XXXX inputs again, even though we already have that. Maybe it's time
    // XXXX to change the API here?
    consensus_diff = consensus_diff_generate(diff_from_nt, diff_to_nt);
    tor_free(diff_from_nt);
    tor_free(diff_to_nt);
  }
  if (!consensus_diff) {
    /* Couldn't generate consensus; we'll leave the reply blank. */
    return WQ_RPL_REPLY;
  }

  /* Send the reply */
  job->body_out = (uint8_t *) consensus_diff;
  job->bodylen_out = strlen(consensus_diff);

  cdm_labels_prepend_sha3(&job->labels_out, job->body_out, job->bodylen_out);
  config_line_prepend(&job->labels_out, LABEL_FROM_VALID_AFTER,
                      lv_from_valid_after);
  config_line_prepend(&job->labels_out, LABEL_VALID_AFTER, lv_to_valid_after);
  config_line_prepend(&job->labels_out, LABEL_FLAVOR, lv_from_flavor);
  config_line_prepend(&job->labels_out, LABEL_FROM_SHA3_DIGEST,
                      lv_from_digest);
  config_line_prepend(&job->labels_out, LABEL_TARGET_SHA3_DIGEST,
                      lv_to_digest);
  config_line_prepend(&job->labels_out, LABEL_DOCTYPE, DOCTYPE_CONSENSUS_DIFF);
  return WQ_RPL_REPLY;
}

/**
 * Helper: release all storage held in <b>job</b>.
 */
static void
consensus_diff_worker_job_free(consensus_diff_worker_job_t *job)
{
  if (!job)
    return;
  tor_free(job->body_out);
  config_free_lines(job->labels_out);
  consensus_cache_entry_decref(job->diff_from);
  consensus_cache_entry_decref(job->diff_to);
  tor_free(job);
}

/**
 * Worker function: This function runs in the main thread, and receives
 * a consensus_diff_worker_job_t that the worker thread has already
 * processed.
 */
static void
consensus_diff_worker_replyfn(void *work_)
{
  tor_assert(in_main_thread());
  tor_assert(work_);

  consensus_diff_worker_job_t *job = work_;

  const char *lv_from_digest =
    consensus_cache_entry_get_value(job->diff_from, LABEL_SHA3_DIGEST);
  const char *lv_to_digest =
    consensus_cache_entry_get_value(job->diff_to, LABEL_SHA3_DIGEST);
  if (BUG(lv_from_digest == NULL))
    lv_from_digest = "???"; // LCOV_EXCL_LINE
  if (BUG(lv_to_digest == NULL))
    lv_to_digest = "???"; // LCOV_EXCL_LINE

  if (job->body_out && job->bodylen_out && job->labels_out) {
    /* Success! Store the results */
    log_info(LD_DIRSERV, "Adding consensus diff from %s to %s",
             lv_from_digest, lv_to_digest);
    consensus_cache_add(cdm_cache_get(), job->labels_out,
                        job->body_out,
                        job->bodylen_out);
  } else {
    /* Failure! Nothing to do but complain */
    log_warn(LD_DIRSERV,
             "Worker was unable to compute consensus diff "
             "from %s to %s", lv_from_digest, lv_to_digest);
    /* XXXX Actually, we should cache this failure and not repeat the
     * attempt over and over */
  }

  consensus_diff_worker_job_free(job);
}

/**
 * Queue the job of computing the diff from <b>diff_from</b> to <b>diff_to</b>
 * in a worker thread.
 */
static int
consensus_diff_queue_diff_work(consensus_cache_entry_t *diff_from,
                               consensus_cache_entry_t *diff_to)
{
  tor_assert(in_main_thread());

  consensus_cache_entry_incref(diff_from);
  consensus_cache_entry_incref(diff_to);

  consensus_diff_worker_job_t *job = tor_malloc_zero(sizeof(*job));
  job->diff_from = diff_from;
  job->diff_to = diff_to;

  /* Make sure body is mapped. */
  const uint8_t *body;
  size_t bodylen;
  int r1 = consensus_cache_entry_get_body(diff_from, &body, &bodylen);
  int r2 = consensus_cache_entry_get_body(diff_to, &body, &bodylen);
  if (r1 < 0 || r2 < 0)
    goto err;

  workqueue_entry_t *work;
  work = cpuworker_queue_work(consensus_diff_worker_threadfn,
                              consensus_diff_worker_replyfn,
                              job);
  if (!work)
    goto err;

  return 0;
 err:
  consensus_diff_worker_job_free(job); // includes decrefs.
  return -1;
}

