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
/* A hex encoded SHA3 digest of the object, as compressed (if any) */
#define LABEL_SHA3_DIGEST "sha3-digest"
/* A hex encoded SHA3 digest of the object before compression. */
#define LABEL_SHA3_DIGEST_UNCOMPRESSED "sha3-digest-uncompressed"
/* The flavor of the consensus or consensuses diff */
#define LABEL_FLAVOR "consensus-flavor"
/* Diff only: the SHA3 digest of the source consensus. */
#define LABEL_FROM_SHA3_DIGEST "from-sha3-digest"
/* Diff only: the SHA3 digest of the target consensus. */
#define LABEL_TARGET_SHA3_DIGEST "target-sha3-digest"
/* Diff only: the valid-after date of the source consensus. */
#define LABEL_FROM_VALID_AFTER "from-valid-after"
/* What kind of compression was used? */
#define LABEL_COMPRESSION_TYPE "compression"
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
 * If true, we have scanned the cache to update our hashtable of diffs.
 */
static int cdm_cache_loaded = 0;

/**
 * Possible status values for cdm_diff_t.cdm_diff_status
 **/
typedef enum cdm_diff_status_t {
  CDM_DIFF_PRESENT=1,
  CDM_DIFF_IN_PROGRESS=2,
  CDM_DIFF_ERROR=3,
} cdm_diff_status_t;

/** Hashtable node used to remember the current status of the diff
 * from a given sha3 digest to the current consensus.  */
typedef struct cdm_diff_t {
  HT_ENTRY(cdm_diff_t) node;

  /** Consensus flavor for this diff (part of ht key) */
  consensus_flavor_t flavor;
  /** SHA3-256 digest of the consensus that this diff is _from_. (part of the
   * ht key) */
  uint8_t from_sha3[DIGEST256_LEN];

  /** One of the CDM_DIFF_* values, depending on whether this diff
   * is available, in progress, or impossible to compute. */
  cdm_diff_status_t cdm_diff_status;
  /** SHA3-256 digest of the consensus that this diff is _to. */
  uint8_t target_sha3[DIGEST256_LEN];
  /** Handle to the cache entry for this diff, if any.  We use a handle here
   * to avoid thinking too hard about cache entry lifetime issues. */
  consensus_cache_entry_handle_t *entry;
} cdm_diff_t;

/** Hashtable mapping flavor and source consensus digest to status. */
static HT_HEAD(cdm_diff_ht, cdm_diff_t) cdm_diff_ht = HT_INITIALIZER();

/**
 * Configuration for this module
 */
static consdiff_cfg_t consdiff_cfg = {
  /* .cache_max_age_hours = */ 24 * 90,
  /* .cache_max_num = */ 1440
};

static int consensus_diff_queue_diff_work(consensus_cache_entry_t *diff_from,
                                          consensus_cache_entry_t *diff_to);
static void consdiffmgr_set_cache_flags(void);

/* =====
 * Hashtable setup
 * ===== */

/** Helper: hash the key of a cdm_diff_t. */
static unsigned
cdm_diff_hash(const cdm_diff_t *diff)
{
  uint8_t tmp[DIGEST256_LEN + 1];
  memcpy(tmp, diff->from_sha3, DIGEST256_LEN);
  tmp[DIGEST256_LEN] = (uint8_t) diff->flavor;
  return (unsigned) siphash24g(tmp, sizeof(tmp));
}
/** Helper: compare two cdm_diff_t objects for key equality */
static int
cdm_diff_eq(const cdm_diff_t *diff1, const cdm_diff_t *diff2)
{
  return fast_memeq(diff1->from_sha3, diff2->from_sha3, DIGEST256_LEN) &&
    diff1->flavor == diff2->flavor;
}

HT_PROTOTYPE(cdm_diff_ht, cdm_diff_t, node, cdm_diff_hash, cdm_diff_eq)
HT_GENERATE2(cdm_diff_ht, cdm_diff_t, node, cdm_diff_hash, cdm_diff_eq,
             0.6, tor_reallocarray, tor_free_)

/** Release all storage held in <b>diff</b>. */
static void
cdm_diff_free(cdm_diff_t *diff)
{
  if (!diff)
    return;
  consensus_cache_entry_handle_free(diff->entry);
  tor_free(diff);
}

/** Create and return a new cdm_diff_t with the given values.  Does not
 * add it to the hashtable. */
static cdm_diff_t *
cdm_diff_new(consensus_flavor_t flav,
             const uint8_t *from_sha3,
             const uint8_t *target_sha3)
{
  cdm_diff_t *ent;
  ent = tor_malloc_zero(sizeof(cdm_diff_t));
  ent->flavor = flav;
  memcpy(ent->from_sha3, from_sha3, DIGEST256_LEN);
  memcpy(ent->target_sha3, target_sha3, DIGEST256_LEN);
  return ent;
}

/**
 * Examine the diff hashtable to see whether we know anything about computing
 * a diff of type <b>flav</b> between consensuses with the two provided
 * SHA3-256 digests.  If a computation is in progress, or if the computation
 * has already been tried and failed, return 1.  Otherwise, note the
 * computation as "in progress" so that we don't reattempt it later, and
 * return 0.
 */
static int
cdm_diff_ht_check_and_note_pending(consensus_flavor_t flav,
                                   const uint8_t *from_sha3,
                                   const uint8_t *target_sha3)
{
  struct cdm_diff_t search, *ent;
  memset(&search, 0, sizeof(cdm_diff_t));
  search.flavor = flav;
  memcpy(search.from_sha3, from_sha3, DIGEST256_LEN);
  ent = HT_FIND(cdm_diff_ht, &cdm_diff_ht, &search);
  if (ent) {
    tor_assert_nonfatal(ent->cdm_diff_status != CDM_DIFF_PRESENT);
    return 1;
  }
  ent = cdm_diff_new(flav, from_sha3, target_sha3);
  ent->cdm_diff_status = CDM_DIFF_IN_PROGRESS;
  HT_INSERT(cdm_diff_ht, &cdm_diff_ht, ent);
  return 0;
}

/**
 * Update the status of the diff of type <b>flav</b> between consensuses with
 * the two provided SHA3-256 digests, so that its status becomes
 * <b>status</b>, and its value becomes the <b>handle</b>.  If <b>handle</b>
 * is NULL, then the old handle (if any) is freed, and replaced with NULL.
 */
static void
cdm_diff_ht_set_status(consensus_flavor_t flav,
                       const uint8_t *from_sha3,
                       const uint8_t *to_sha3,
                       int status,
                       consensus_cache_entry_handle_t *handle)
{
  struct cdm_diff_t search, *ent;
  memset(&search, 0, sizeof(cdm_diff_t));
  search.flavor = flav;
  memcpy(search.from_sha3, from_sha3, DIGEST256_LEN);
  ent = HT_FIND(cdm_diff_ht, &cdm_diff_ht, &search);
  if (!ent) {
    ent = cdm_diff_new(flav, from_sha3, to_sha3);
    ent->cdm_diff_status = CDM_DIFF_IN_PROGRESS;
    HT_INSERT(cdm_diff_ht, &cdm_diff_ht, ent);
  } else if (fast_memneq(ent->target_sha3, to_sha3, DIGEST256_LEN)) {
    // This can happen under certain really pathological conditions
    // if we decide we don't care about a diff before it is actually
    // done computing.
    return;
  }

  tor_assert_nonfatal(ent->cdm_diff_status == CDM_DIFF_IN_PROGRESS);

  ent->cdm_diff_status = status;
  consensus_cache_entry_handle_free(ent->entry);
  ent->entry = handle;
}

/**
 * Helper: Remove from the hash table every present (actually computed) diff
 * of type <b>flav</b> whose target digest does not match
 * <b>unless_target_sha3_matches</b>.
 *
 * This function is used for the hash table to throw away references to diffs
 * that do not lead to the most given consensus of a given flavor.
 */
static void
cdm_diff_ht_purge(consensus_flavor_t flav,
                  const uint8_t *unless_target_sha3_matches)
{
  cdm_diff_t **diff, **next;
  for (diff = HT_START(cdm_diff_ht, &cdm_diff_ht); diff; diff = next) {
    cdm_diff_t *this = *diff;

    if ((*diff)->cdm_diff_status == CDM_DIFF_PRESENT &&
        flav == (*diff)->flavor) {

      if (consensus_cache_entry_handle_get((*diff)->entry) == NULL) {
        /* the underlying entry has gone away; drop this. */
        next = HT_NEXT_RMV(cdm_diff_ht, &cdm_diff_ht, diff);
        cdm_diff_free(this);
        continue;
      }

      if (unless_target_sha3_matches &&
          fast_memneq(unless_target_sha3_matches, (*diff)->target_sha3,
                      DIGEST256_LEN)) {
        /* target hash doesn't match; drop this. */
        next = HT_NEXT_RMV(cdm_diff_ht, &cdm_diff_ht, diff);
        cdm_diff_free(this);
        continue;
      }
    }
    next = HT_NEXT(cdm_diff_ht, &cdm_diff_ht, diff);
  }
}

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
    // LCOV_EXCL_START
    log_err(LD_FS, "Error: Couldn't open storage for consensus diffs.");
    tor_assert_unreached();
    // LCOV_EXCL_STOP
  } else {
    consdiffmgr_set_cache_flags();
  }
  cdm_cache_dirty = 1;
  cdm_cache_loaded = 0;
}

/**
 * Helper: return the consensus_cache_t * that backs this manager,
 * initializing it if needed.
 */
STATIC consensus_cache_t *
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
 * with <b>label</b> as its label.
 */
static void
cdm_labels_prepend_sha3(config_line_t **labels,
                        const char *label,
                        const uint8_t *body,
                        size_t bodylen)
{
  uint8_t sha3_digest[DIGEST256_LEN];
  char hexdigest[HEX_DIGEST256_LEN+1];
  crypto_digest256((char *)sha3_digest,
                   (const char *)body, bodylen, DIGEST_SHA3_256);
  base16_encode(hexdigest, sizeof(hexdigest),
                (const char *)sha3_digest, sizeof(sha3_digest));

  config_line_prepend(labels, label, hexdigest);
}

/** Helper: if there is a sha3-256 hex-encoded digest in <b>ent</b> with the
 * given label, set <b>digest_out</b> to that value (decoded), and return 0.
 *
 * Return -1 if there is no such label, and -2 if it is badly formatted. */
STATIC int
cdm_entry_get_sha3_value(uint8_t *digest_out,
                         consensus_cache_entry_t *ent,
                         const char *label)
{
  if (ent == NULL)
    return -1;

  const char *hex = consensus_cache_entry_get_value(ent, label);
  if (hex == NULL)
    return -1;

  int n = base16_decode((char*)digest_out, DIGEST256_LEN, hex, strlen(hex));
  if (n != DIGEST256_LEN)
    return -2;
  else
    return 0;
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
  /* We could add an extra hashtable here, but since we only do this scan
   * when adding a new consensus, it probably doesn't matter much. */
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

    cdm_labels_prepend_sha3(&labels, LABEL_SHA3_DIGEST,
                            (const uint8_t *)consensus, bodylen);
    cdm_labels_prepend_sha3(&labels, LABEL_SHA3_DIGEST_UNCOMPRESSED,
                            (const uint8_t *)consensus, bodylen);
    config_line_prepend(&labels, LABEL_FLAVOR, flavname);
    config_line_prepend(&labels, LABEL_VALID_AFTER, formatted_time);
    config_line_prepend(&labels, LABEL_DOCTYPE, DOCTYPE_CONSENSUS);

    entry = consensus_cache_add(cdm_cache_get(),
                                labels,
                                (const uint8_t *)consensus,
                                bodylen);
    config_free_lines(labels);
  }

  if (entry) {
    consensus_cache_entry_mark_for_aggressive_release(entry);
    consensus_cache_entry_decref(entry);
  }

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
  if (BUG(digest_type != DIGEST_SHA3_256) ||
      BUG(digestlen != DIGEST256_LEN)) {
    return CONSDIFF_NOT_FOUND; // LCOV_EXCL_LINE
  }

  // Try to look up the entry in the hashtable.
  cdm_diff_t search, *ent;
  memset(&search, 0, sizeof(search));
  search.flavor = flavor;
  memcpy(search.from_sha3, digest, DIGEST256_LEN);
  ent = HT_FIND(cdm_diff_ht, &cdm_diff_ht, &search);

  if (ent == NULL ||
      ent->cdm_diff_status == CDM_DIFF_ERROR) {
    return CONSDIFF_NOT_FOUND;
  } else if (ent->cdm_diff_status == CDM_DIFF_IN_PROGRESS) {
    return CONSDIFF_IN_PROGRESS;
  } else if (BUG(ent->cdm_diff_status != CDM_DIFF_PRESENT)) {
    return CONSDIFF_IN_PROGRESS;
  }

  *entry_out = consensus_cache_entry_handle_get(ent->entry);
  return (*entry_out) ? CONSDIFF_AVAILABLE : CONSDIFF_NOT_FOUND;

#if 0
  // XXXX Remove this.  I'm keeping it around for now in case we need to
  // XXXX debug issues in the hashtable.
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
#endif
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
      consensus_cache_entry_get_value(most_recent,
                                      LABEL_SHA3_DIGEST_UNCOMPRESSED);
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
 * Scan the consensus diff manager's cache for any grossly malformed entries,
 * and mark them as deletable.  Return 0 if no problems were found; 1
 * if problems were found and fixed.
 */
int
consdiffmgr_validate(void)
{
  /* Right now, we only check for entries that have bad sha3 values */
  int problems = 0;

  smartlist_t *objects = smartlist_new();
  consensus_cache_find_all(objects, cdm_cache_get(),
                           NULL, NULL);
  SMARTLIST_FOREACH_BEGIN(objects, consensus_cache_entry_t *, obj) {
    uint8_t sha3_expected[DIGEST256_LEN];
    uint8_t sha3_received[DIGEST256_LEN];
    int r = cdm_entry_get_sha3_value(sha3_expected, obj, LABEL_SHA3_DIGEST);
    if (r == -1) {
      /* digest isn't there; that's allowed */
      continue;
    } else if (r == -2) {
      /* digest is malformed; that's not allowed */
      problems = 1;
      consensus_cache_entry_mark_for_removal(obj);
      continue;
    }
    const uint8_t *body;
    size_t bodylen;
    consensus_cache_entry_incref(obj);
    r = consensus_cache_entry_get_body(obj, &body, &bodylen);
    if (r == 0) {
      crypto_digest256((char *)sha3_received, (const char *)body, bodylen,
                       DIGEST_SHA3_256);
    }
    consensus_cache_entry_decref(obj);
    if (r < 0)
      continue;

    if (fast_memneq(sha3_received, sha3_expected, DIGEST256_LEN)) {
      problems = 1;
      consensus_cache_entry_mark_for_removal(obj);
      continue;
    }

  } SMARTLIST_FOREACH_END(obj);
  smartlist_free(objects);
  return problems;
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
  uint8_t most_recent_sha3[DIGEST256_LEN];
  if (BUG(cdm_entry_get_sha3_value(most_recent_sha3, most_recent,
                                   LABEL_SHA3_DIGEST_UNCOMPRESSED) < 0))
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

  // 4. Update the hashtable; remove entries in this flavor to other
  //    target consensuses.
  cdm_diff_ht_purge(flavor, most_recent_sha3);

  // 5. Actually launch the requests.
  SMARTLIST_FOREACH_BEGIN(compute_diffs_from, consensus_cache_entry_t *, c) {
    if (BUG(c == most_recent))
      continue; // LCOV_EXCL_LINE

    uint8_t this_sha3[DIGEST256_LEN];
    if (BUG(cdm_entry_get_sha3_value(this_sha3, c,
                                     LABEL_SHA3_DIGEST_UNCOMPRESSED)<0))
      continue; // LCOV_EXCL_LINE
    if (cdm_diff_ht_check_and_note_pending(flavor,
                                           this_sha3, most_recent_sha3)) {
      // This is already pending, or we encountered an error.
      continue;
    }
    consensus_diff_queue_diff_work(c, most_recent);
  } SMARTLIST_FOREACH_END(c);

 done:
  smartlist_free(matches);
  smartlist_free(diffs);
  smartlist_free(compute_diffs_from);
  strmap_free(have_diff_from, NULL);
}

/**
 * Scan the cache for diffs, and add them to the hashtable.
 */
static void
consdiffmgr_diffs_load(void)
{
  smartlist_t *diffs = smartlist_new();
  consensus_cache_find_all(diffs, cdm_cache_get(),
                           LABEL_DOCTYPE, DOCTYPE_CONSENSUS_DIFF);
  SMARTLIST_FOREACH_BEGIN(diffs, consensus_cache_entry_t *, diff) {
    const char *lv_flavor =
      consensus_cache_entry_get_value(diff, LABEL_FLAVOR);
    if (!lv_flavor)
      continue;
    int flavor = networkstatus_parse_flavor_name(lv_flavor);
    if (flavor < 0)
      continue;
    uint8_t from_sha3[DIGEST256_LEN];
    uint8_t to_sha3[DIGEST256_LEN];
    if (cdm_entry_get_sha3_value(from_sha3, diff, LABEL_FROM_SHA3_DIGEST)<0)
      continue;
    if (cdm_entry_get_sha3_value(to_sha3, diff, LABEL_TARGET_SHA3_DIGEST)<0)
      continue;

    cdm_diff_ht_set_status(flavor, from_sha3, to_sha3,
                           CDM_DIFF_PRESENT,
                           consensus_cache_entry_handle_new(diff));
  } SMARTLIST_FOREACH_END(diff);
  smartlist_free(diffs);
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

  if (cdm_cache_loaded == 0) {
    consdiffmgr_diffs_load();
    cdm_cache_loaded = 1;
  }

  for (int flav = 0; flav < N_CONSENSUS_FLAVORS; ++flav) {
    consdiffmgr_rescan_flavor_((consensus_flavor_t) flav);
  }

  cdm_cache_dirty = 0;
}

/**
 * Set consensus cache flags on the objects in this consdiffmgr.
 */
static void
consdiffmgr_set_cache_flags(void)
{
  /* Right now, we just mark the consensus objects for aggressive release,
   * so that they get mmapped for as little time as possible. */
  smartlist_t *objects = smartlist_new();
  consensus_cache_find_all(objects, cdm_cache_get(), LABEL_DOCTYPE,
                           DOCTYPE_CONSENSUS);
  SMARTLIST_FOREACH_BEGIN(objects, consensus_cache_entry_t *, ent) {
    consensus_cache_entry_mark_for_aggressive_release(ent);
  } SMARTLIST_FOREACH_END(ent);
  smartlist_free(objects);
}

/**
 * Called before shutdown: drop all storage held by the consdiffmgr.c module.
 */
void
consdiffmgr_free_all(void)
{
  cdm_diff_t **diff, **next;
  for (diff = HT_START(cdm_diff_ht, &cdm_diff_ht); diff; diff = next) {
    cdm_diff_t *this = *diff;
    next = HT_NEXT_RMV(cdm_diff_ht, &cdm_diff_ht, diff);
    cdm_diff_free(this);
  }
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
    consensus_cache_entry_get_value(job->diff_from,
                                    LABEL_SHA3_DIGEST_UNCOMPRESSED);
  const char *lv_from_flavor =
    consensus_cache_entry_get_value(job->diff_from, LABEL_FLAVOR);
  const char *lv_to_flavor =
    consensus_cache_entry_get_value(job->diff_to, LABEL_FLAVOR);
  const char *lv_to_digest =
    consensus_cache_entry_get_value(job->diff_to,
                                    LABEL_SHA3_DIGEST_UNCOMPRESSED);

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

  cdm_labels_prepend_sha3(&job->labels_out, LABEL_SHA3_DIGEST,
                          job->body_out, job->bodylen_out);
  cdm_labels_prepend_sha3(&job->labels_out, LABEL_SHA3_DIGEST_UNCOMPRESSED,
                          job->body_out, job->bodylen_out);
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
    consensus_cache_entry_get_value(job->diff_from,
                                    LABEL_SHA3_DIGEST_UNCOMPRESSED);
  const char *lv_to_digest =
    consensus_cache_entry_get_value(job->diff_to,
                                    LABEL_SHA3_DIGEST_UNCOMPRESSED);
  const char *lv_flavor =
    consensus_cache_entry_get_value(job->diff_to, LABEL_FLAVOR);
  if (BUG(lv_from_digest == NULL))
    lv_from_digest = "???"; // LCOV_EXCL_LINE
  if (BUG(lv_to_digest == NULL))
    lv_to_digest = "???"; // LCOV_EXCL_LINE

  uint8_t from_sha3[DIGEST256_LEN];
  uint8_t to_sha3[DIGEST256_LEN];
  int flav = -1;
  int cache = 1;
  if (BUG(cdm_entry_get_sha3_value(from_sha3, job->diff_from,
                                   LABEL_SHA3_DIGEST_UNCOMPRESSED) < 0))
    cache = 0;
  if (BUG(cdm_entry_get_sha3_value(to_sha3, job->diff_to,
                                   LABEL_SHA3_DIGEST_UNCOMPRESSED) < 0))
    cache = 0;
  if (BUG(lv_flavor == NULL)) {
    cache = 0;
  } else if ((flav = networkstatus_parse_flavor_name(lv_flavor)) < 0) {
    cache = 0;
  }

  int status;
  consensus_cache_entry_handle_t *handle = NULL;
  if (job->body_out && job->bodylen_out && job->labels_out) {
    /* Success! Store the results */
    log_info(LD_DIRSERV, "Adding consensus diff from %s to %s",
             lv_from_digest, lv_to_digest);
    consensus_cache_entry_t *ent =
      consensus_cache_add(cdm_cache_get(), job->labels_out,
                          job->body_out,
                          job->bodylen_out);
    status = CDM_DIFF_PRESENT;
    handle = consensus_cache_entry_handle_new(ent);
    consensus_cache_entry_decref(ent);
  } else {
    /* Failure! Nothing to do but complain */
    log_warn(LD_DIRSERV,
             "Worker was unable to compute consensus diff "
             "from %s to %s", lv_from_digest, lv_to_digest);
    /* Cache this error so we don't try to compute this one again. */
    status = CDM_DIFF_ERROR;
  }

  if (cache)
    cdm_diff_ht_set_status(flav, from_sha3, to_sha3, status, handle);
  else
    consensus_cache_entry_handle_free(handle);

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

