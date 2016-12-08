/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file entrynodes.c
 * \brief Code to manage our fixed first nodes for various functions.
 *
 * Entry nodes can be guards (for general use) or bridges (for censorship
 * circumvention).
 *
 * XXXX prop271 This module is in flux, since I'm currently in the middle of
 * implementation proposal 271.  The module documentation here will describe
 * the new algorithm and data structures; the old ones should get removed as
 * proposal 271 is completed.
 *
 * In general, we use entry guards to prevent traffic-sampling attacks:
 * if we chose every circuit independently, an adversary controlling
 * some fraction of paths on the network would observe a sample of every
 * user's traffic. Using guards gives users a chance of not being
 * profiled.
 *
 * The current entry guard selection code is designed to try to avoid
 * _ever_ trying every guard on the network, to try to stick to guards
 * that we've used before, to handle hostile/broken networks, and
 * to behave sanely when the network goes up and down.
 *
 * Our algorithm works as follows: First, we maintain a SAMPLE of guards
 * we've seen in the networkstatus consensus.  We maintain this sample
 * over time, and store it persistently; it is chosen without reference
 * to our configuration or firewall rules.  Guards remain in the sample
 * as they enter and leave the consensus.  We expand this sample as
 * needed, up to a maximum size.
 *
 * As a subset of the sample, we maintain a FILTERED SET of the guards
 * that we would be willing to use if we could connect to them.  The
 * filter removes all the guards that we're excluding because they're
 * bridges (or not bridges), because we have restrictive firewall rules,
 * because of ExcludeNodes, because we of path bias restrictions,
 * because they're absent from the network at present, and so on.
 *
 * As a subset of the filtered set, we keep a REACHABLE FILTERED SET
 * (also called a "usable filtered set") of those guards that we call
 * "reachable" or "maybe reachable".  A guard is reachable if we've
 * connected to it more recently than we've failed.  A guard is "maybe
 * reachable" if we have never tried to connect to it, or if we
 * failed to connect to it so long ago that we no longer think our
 * failure means it's down.
 *
 * As a persistent ordered list whose elements are taken from the
 * sampled set, we track a CONFIRMED GUARDS LIST.  A guard becomes
 * confirmed when we successfully build a circuit through it, and decide
 * to use that circuit.  We order the guards on this list by the order
 * in which they became confirmed.
 *
 * And as a final group, we have an ordered list of PRIMARY GUARDS,
 * whose elements are taken from the filtered set. We prefer
 * confirmed guards to non-confirmed guards for this list, and place
 * other restrictions on it.  The primary guards are the ones that we
 * connect to "when nothing is wrong" -- circuits through them can be used
 * immediately.
 *
 * To build circuits, we take a primary guard if possible -- or a
 * reachable filtered confirmed guard if no primary guard is possible --
 * or a random reachable filtered guard otherwise.  If the guard is
 * primary, we can use the circuit immediately on success.  Otherwise,
 * the guard is now "pending" -- we won't use its circuit unless all
 * of the circuits we're trying to build through better guards have
 * definitely failed.
 *
 * While we're building circuits, we track a little "guard state" for
 * each circuit. We use this to keep track of whether the circuit is
 * one that we can use as soon as its done, or whether it's one that
 * we should keep around to see if we can do better.  In the latter case,
 * a periodic call to entry_guards_upgrade_waiting_circuits() will
 * eventually upgrade it.
 **/
/* DOCDOC -- expand this.
 *
 * Information invariants:
 *
 * [x] whenever a guard becomes unreachable, clear its usable_filtered flag.
 *
 * [x] Whenever a guard becomes reachable or maybe-reachable, if its filtered
 * flag is set, set its usable_filtered flag.
 *
 * [x] Whenever we get a new consensus, call update_from_consensus(). (LATER.)
 *
 * [x] Whenever the configuration changes in a relevant way, update the
 * filtered/usable flags. (LATER.)
 *
 * [x] Whenever we add a guard to the sample, make sure its filtered/usable
 * flags are set as possible.
 *
 * [x] Whenever we remove a guard from the sample, remove it from the primary
 * and confirmed lists.
 *
 * [x] When we make a guard confirmed, update the primary list.
 *
 * [x] When we make a guard filtered or unfiltered, update the primary list.
 *
 * [x] When we are about to pick a guard, make sure that the primary list is
 * full.
 *
 * [x] Before calling sample_reachable_filtered_entry_guards(), make sure
 * that the filtered, primary, and confirmed flags are up-to-date.
 *
 * [x] Call entry_guard_consider_retry every time we are about to check
 * is_usable_filtered or is_reachable, and every time we set
 * is_filtered to 1.
 *
 * [x] Call entry_guards_changed_for_guard_selection() whenever we update
 * a persistent field.
 */

#define ENTRYNODES_PRIVATE

#include "or.h"
#include "bridges.h"
#include "circpathbias.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "circuitstats.h"
#include "config.h"
#include "confparse.h"
#include "connection.h"
#include "connection_or.h"
#include "control.h"
#include "directory.h"
#include "entrynodes.h"
#include "main.h"
#include "microdesc.h"
#include "networkstatus.h"
#include "nodelist.h"
#include "policies.h"
#include "router.h"
#include "routerlist.h"
#include "routerparse.h"
#include "routerset.h"
#include "transports.h"
#include "statefile.h"

/** A list of existing guard selection contexts. */
static smartlist_t *guard_contexts = NULL;
/** The currently enabled guard selection context. */
static guard_selection_t *curr_guard_context = NULL;

/** A value of 1 means that at least one context has changed,
 * and those changes need to be flushed to disk. */
static int entry_guards_dirty = 0;

#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
static const node_t *choose_random_entry_impl(guard_selection_t *gs,
                                              cpath_build_state_t *state,
                                              int for_directory,
                                              dirinfo_type_t dirtype,
                                              int *n_options_out);
#endif
static void entry_guard_set_filtered_flags(const or_options_t *options,
                                           guard_selection_t *gs,
                                           entry_guard_t *guard);
static void pathbias_check_use_success_count(entry_guard_t *guard);
static void pathbias_check_close_success_count(entry_guard_t *guard);
static int node_is_possible_guard(const node_t *node);
static int node_passes_guard_filter(const or_options_t *options,
                                    const node_t *node);
static entry_guard_t *entry_guard_add_to_sample_impl(guard_selection_t *gs,
                               const uint8_t *rsa_id_digest,
                               const char *nickname,
                               const tor_addr_port_t *bridge_addrport);
static entry_guard_t *get_sampled_guard_by_bridge_addr(guard_selection_t *gs,
                                              const tor_addr_port_t *addrport);
static int entry_guard_obeys_restriction(const entry_guard_t *guard,
                                         const entry_guard_restriction_t *rst);

/** Return 0 if we should apply guardfraction information found in the
 *  consensus. A specific consensus can be specified with the
 *  <b>ns</b> argument, if NULL the most recent one will be picked.*/
int
should_apply_guardfraction(const networkstatus_t *ns)
{
  /* We need to check the corresponding torrc option and the consensus
   * parameter if we need to. */
  const or_options_t *options = get_options();

  /* If UseGuardFraction is 'auto' then check the same-named consensus
   * parameter. If the consensus parameter is not present, default to
   * "off". */
  if (options->UseGuardFraction == -1) {
    return networkstatus_get_param(ns, "UseGuardFraction",
                                   0, /* default to "off" */
                                   0, 1);
  }

  return options->UseGuardFraction;
}

/**
 * Try to determine the correct type for a selection named "name",
 * if <b>type</b> is GS_TYPE_INFER.
 */
STATIC guard_selection_type_t
guard_selection_infer_type(guard_selection_type_t type,
                           const char *name)
{
  if (type == GS_TYPE_INFER) {
    if (!strcmp(name, "legacy"))
      type = GS_TYPE_LEGACY;
    else if (!strcmp(name, "bridges"))
      type = GS_TYPE_BRIDGE;
    else if (!strcmp(name, "restricted"))
      type = GS_TYPE_RESTRICTED;
    else
      type = GS_TYPE_NORMAL;
  }
  return type;
}

/**
 * Allocate and return a new guard_selection_t, with the name <b>name</b>.
 */
STATIC guard_selection_t *
guard_selection_new(const char *name,
                    guard_selection_type_t type)
{
  guard_selection_t *gs;

  type = guard_selection_infer_type(type, name);

  gs = tor_malloc_zero(sizeof(*gs));
  gs->name = tor_strdup(name);
  gs->type = type;
#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
  gs->chosen_entry_guards = smartlist_new();
#endif
  gs->sampled_entry_guards = smartlist_new();
  gs->confirmed_entry_guards = smartlist_new();
  gs->primary_entry_guards = smartlist_new();

  return gs;
}

/**
 * Return the guard selection called <b>name</b>. If there is none, and
 * <b>create_if_absent</b> is true, then create and return it.  If there
 * is none, and <b>create_if_absent</b> is false, then return NULL.
 */
STATIC guard_selection_t *
get_guard_selection_by_name(const char *name,
                            guard_selection_type_t type,
                            int create_if_absent)
{
  if (!guard_contexts) {
    guard_contexts = smartlist_new();
  }
  SMARTLIST_FOREACH_BEGIN(guard_contexts, guard_selection_t *, gs) {
    if (!strcmp(gs->name, name))
      return gs;
  } SMARTLIST_FOREACH_END(gs);

  if (! create_if_absent)
    return NULL;

  log_debug(LD_GUARD, "Creating a guard selection called %s", name);
  guard_selection_t *new_selection = guard_selection_new(name, type);
  smartlist_add(guard_contexts, new_selection);

  return new_selection;
}

/**
 * Allocate the first guard context that we're planning to use,
 * and make it the current context.
 */
static void
create_initial_guard_context(void)
{
  tor_assert(! curr_guard_context);
  if (!guard_contexts) {
    guard_contexts = smartlist_new();
  }
  guard_selection_type_t type = GS_TYPE_INFER;
  const char *name = choose_guard_selection(
                             get_options(),
                             networkstatus_get_live_consensus(approx_time()),
                             NULL,
                             &type);
  tor_assert(name); // "name" can only be NULL if we had an old name.
  tor_assert(type != GS_TYPE_INFER);
  log_notice(LD_GUARD, "Starting with guard context \"%s\"", name);
  curr_guard_context = get_guard_selection_by_name(name, type, 1);
}

/** Get current default guard_selection_t, creating it if necessary */
guard_selection_t *
get_guard_selection_info(void)
{
  if (!curr_guard_context) {
    create_initial_guard_context();
  }

  return curr_guard_context;
}

#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
/** Return the list of entry guards for a guard_selection_t, creating it
 * if necessary. */
const smartlist_t *
get_entry_guards_for_guard_selection(guard_selection_t *gs)
{
  tor_assert(gs != NULL);
  tor_assert(gs->chosen_entry_guards != NULL);

  return gs->chosen_entry_guards;
}

/** Return the list of entry guards for the default guard_selection_t,
 * creating it if necessary. */
const smartlist_t *
get_entry_guards(void)
{
  return get_entry_guards_for_guard_selection(get_guard_selection_info());
}

/** Helper: mark an entry guard as not usable. */
void
entry_guard_mark_bad(entry_guard_t *guard)
{
  guard->bad_since = approx_time();
  entry_guards_changed();
}
#endif

/** Return a statically allocated human-readable description of <b>guard</b>
 */
const char *
entry_guard_describe(const entry_guard_t *guard)
{
  static char buf[256];
  tor_snprintf(buf, sizeof(buf),
               "%s ($%s)",
               guard->nickname ? guard->nickname : "[bridge]",
               hex_str(guard->identity, DIGEST_LEN));
  return buf;
}

/** Return <b>guard</b>'s 20-byte RSA identity digest */
const char *
entry_guard_get_rsa_id_digest(const entry_guard_t *guard)
{
  return guard->identity;
}

/** Return the pathbias state associated with <b>guard</b>. */
guard_pathbias_t *
entry_guard_get_pathbias_state(entry_guard_t *guard)
{
  return &guard->pb;
}

HANDLE_IMPL(entry_guard, entry_guard_t, ATTR_UNUSED STATIC)

/** Return an interval betweeen 'now' and 'max_backdate' seconds in the past,
 * chosen uniformly at random.  We use this before recording persistent
 * dates, so that we aren't leaking exactly when we recorded it.
 */
MOCK_IMPL(STATIC time_t,
randomize_time,(time_t now, time_t max_backdate))
{
  tor_assert(max_backdate > 0);

  time_t earliest = now - max_backdate;
  time_t latest = now;
  if (earliest <= 0)
    earliest = 1;
  if (latest <= earliest)
    latest = earliest + 1;

  return crypto_rand_time_range(earliest, latest);
}

/**
 * @name parameters for networkstatus algorithm
 *
 * These parameters are taken from the consensus; some are overrideable in
 * the torrc.
 */
/**@{*/
/**
 * We never let our sampled guard set grow larger than this fraction
 * of the guards on the network.
 */
STATIC double
get_max_sample_threshold(void)
{
  int32_t pct =
    networkstatus_get_param(NULL, "guard-max-sample-threshold-percent",
                            DFLT_MAX_SAMPLE_THRESHOLD_PERCENT,
                            1, 100);
  return pct / 100.0;
}
/**
 * We never let our sampled guard set grow larger than this number.
 */
STATIC int
get_max_sample_size_absolute(void)
{
  return (int) networkstatus_get_param(NULL, "guard-max-sample-size",
                                       DFLT_MAX_SAMPLE_SIZE,
                                       1, INT32_MAX);
}
/**
 * We always try to make our sample contain at least this many guards.
 *
 * XXXX prop271 spec deviation There was a MIN_SAMPLE_THRESHOLD in the
 * proposal, but I removed it in favor of MIN_FILTERED_SAMPLE_SIZE. -NM
 */
STATIC int
get_min_filtered_sample_size(void)
{
  return networkstatus_get_param(NULL, "guard-min-filtered-sample-size",
                                 DFLT_MIN_FILTERED_SAMPLE_SIZE,
                                 1, INT32_MAX);
}
/**
 * If a guard is unlisted for this many days in a row, we remove it.
 */
STATIC int
get_remove_unlisted_guards_after_days(void)
{
  return networkstatus_get_param(NULL,
                                 "guard-remove-unlisted-guards-after-days",
                                 DFLT_REMOVE_UNLISTED_GUARDS_AFTER_DAYS,
                                 1, 365*10);
}
/**
 * We remove unconfirmed guards from the sample after this many days,
 * regardless of whether they are listed or unlisted.
 */
STATIC int
get_guard_lifetime(void)
{
  if (get_options()->GuardLifetime >= 86400)
    return get_options()->GuardLifetime;
  int32_t days;
  days = networkstatus_get_param(NULL,
                                 "guard-lifetime-days",
                                 DFLT_GUARD_LIFETIME_DAYS, 1, 365*10);
  return days * 86400;
}
/**
 * We remove confirmed guards from the sample if they were sampled
 * GUARD_LIFETIME_DAYS ago and confirmed this many days ago.
 */
STATIC int
get_guard_confirmed_min_lifetime(void)
{
  if (get_options()->GuardLifetime >= 86400)
    return get_options()->GuardLifetime;
  int32_t days;
  days = networkstatus_get_param(NULL, "guard-confirmed-min-lifetime-days",
                                 DFLT_GUARD_CONFIRMED_MIN_LIFETIME_DAYS,
                                 1, 365*10);
  return days * 86400;
}
/**
 * How many guards do we try to keep on our primary guard list?
 */
STATIC int
get_n_primary_guards(void)
{
  const int n = get_options()->NumEntryGuards;
  if (n > 5) {
    return n + n / 2;
  } else if (n > 1) {
    return n * 2;
  }

  return networkstatus_get_param(NULL,
                                 "guard-n-primary-guards",
                                 DFLT_N_PRIMARY_GUARDS, 1, INT32_MAX);
}
/**
 * Return the number of the live primary guards we should look at when
 * making a circuit.
 */
STATIC int
get_n_primary_guards_to_use(void)
{
  if (get_options()->NumEntryGuards > 1) {
    return get_options()->NumEntryGuards;
  }
  return networkstatus_get_param(NULL,
                                 "guard-n-primary-guards-to-use",
                                 DFLT_N_PRIMARY_GUARDS_TO_USE, 1, INT32_MAX);
}
/**
 * If we haven't successfully built or used a circuit in this long, then
 * consider that the internet is probably down.
 */
STATIC int
get_internet_likely_down_interval(void)
{
  return networkstatus_get_param(NULL, "guard-internet-likely-down-interval",
                                 DFLT_INTERNET_LIKELY_DOWN_INTERVAL,
                                 1, INT32_MAX);
}
/**
 * If we're trying to connect to a nonprimary guard for at least this
 * many seconds, and we haven't gotten the connection to work, we will treat
 * lower-priority guards as usable.
 */
STATIC int
get_nonprimary_guard_connect_timeout(void)
{
  return networkstatus_get_param(NULL,
                                 "guard-nonprimary-guard-connect-timeout",
                                 DFLT_NONPRIMARY_GUARD_CONNECT_TIMEOUT,
                                 1, INT32_MAX);
}
/**
 * If a circuit has been sitting around in 'waiting for better guard' state
 * for at least this long, we'll expire it.
 */
STATIC int
get_nonprimary_guard_idle_timeout(void)
{
  return networkstatus_get_param(NULL,
                                 "guard-nonprimary-guard-idle-timeout",
                                 DFLT_NONPRIMARY_GUARD_IDLE_TIMEOUT,
                                 1, INT32_MAX);
}
/**
 * If our configuration retains fewer than this fraction of guards from the
 * torrc, we are in a restricted setting.
 */
STATIC double
get_meaningful_restriction_threshold(void)
{
  int32_t pct = networkstatus_get_param(NULL,
                                        "guard-meaningful-restriction-percent",
                                        DFLT_MEANINGFUL_RESTRICTION_PERCENT,
                                        1, INT32_MAX);
  return pct / 100.0;
}
/**
 * If our configuration retains fewer than this fraction of guards from the
 * torrc, we are in an extremely restricted setting, and should warn.
 */
STATIC double
get_extreme_restriction_threshold(void)
{
  int32_t pct = networkstatus_get_param(NULL,
                                        "guard-extreme-restriction-percent",
                                        DFLT_EXTREME_RESTRICTION_PERCENT,
                                        1, INT32_MAX);
  return pct / 100.0;
}
/**@}*/

/**
 * Given our options and our list of nodes, return the name of the
 * guard selection that we should use.  Return NULL for "use the
 * same selection you were using before.
 */
STATIC const char *
choose_guard_selection(const or_options_t *options,
                       const networkstatus_t *live_ns,
                       const guard_selection_t *old_selection,
                       guard_selection_type_t *type_out)
{
  tor_assert(options);
  tor_assert(type_out);
  if (options->UseDeprecatedGuardAlgorithm) {
    *type_out = GS_TYPE_LEGACY;
    return "legacy";
  }

  if (options->UseBridges) {
    *type_out = GS_TYPE_BRIDGE;
    return "bridges";
  }

  if (! live_ns) {
    /* without a networkstatus, we can't tell any more than that. */
    *type_out = GS_TYPE_NORMAL;
    return "default";
  }

  const smartlist_t *nodes = nodelist_get_list();
  int n_guards = 0, n_passing_filter = 0;
  SMARTLIST_FOREACH_BEGIN(nodes, const node_t *, node) {
    if (node_is_possible_guard(node)) {
      ++n_guards;
      if (node_passes_guard_filter(options, node)) {
        ++n_passing_filter;
      }
    }
  } SMARTLIST_FOREACH_END(node);

  /* XXXX prop271 spec deviation -- separate 'high' and 'low' thresholds
   *  to prevent flapping */
  const int meaningful_threshold_high =
    (int)(n_guards * get_meaningful_restriction_threshold() * 1.05);
  const int meaningful_threshold_mid =
    (int)(n_guards * get_meaningful_restriction_threshold());
  const int meaningful_threshold_low =
    (int)(n_guards * get_meaningful_restriction_threshold() * .95);
  const int extreme_threshold =
    (int)(n_guards * get_extreme_restriction_threshold());

  /*
    If we have no previous selection, then we're "restricted" iff we are
    below the meaningful restriction threshold.  That's easy enough.

    But if we _do_ have a previous selection, we make it a little
    "sticky": we only move from "restricted" to "default" when we find
    that we're above the threshold plus 5%, and we only move from
    "default" to "restricted" when we're below the threshold minus 5%.
    That should prevent us from flapping back and forth if we happen to
    be hovering very close to the default.

    The extreme threshold is for warning only.
  */

  static int have_warned_extreme_threshold = 0;
  if (n_passing_filter < extreme_threshold &&
      ! have_warned_extreme_threshold) {
    have_warned_extreme_threshold = 1;
    const double exclude_frac =
      (n_guards - n_passing_filter) / (double)n_guards;
    log_warn(LD_GUARD, "Your configuration excludes %d%% of all possible "
             "guards. That's likely to make you stand out from the "
             "rest of the world.", (int)(exclude_frac * 100));
  }

  /* Easy case: no previous selection. Just check if we are in restricted or
     normal guard selection. */
  if (old_selection == NULL) {
    if (n_passing_filter >= meaningful_threshold_mid) {
      *type_out = GS_TYPE_NORMAL;
      return "default";
    } else {
      *type_out = GS_TYPE_RESTRICTED;
      return "restricted";
    }
  }

  /* Trickier case: we do have a previous guard selection context. */
  tor_assert(old_selection);

  /* Use high and low thresholds to decide guard selection, and if we fall in
     the middle then keep the current guard selection context. */
  if (n_passing_filter >= meaningful_threshold_high) {
    *type_out = GS_TYPE_NORMAL;
    return "default";
  } else if (n_passing_filter < meaningful_threshold_low) {
    *type_out = GS_TYPE_RESTRICTED;
    return "restricted";
  } else {
    /* we are in the middle: maintain previous guard selection */
    *type_out = old_selection->type;
    return old_selection->name;
  }
}

/**
 * Check whether we should switch from our current guard selection to a
 * different one.  If so, switch and return 1.  Return 0 otherwise.
 *
 * On a 1 return, the caller should mark all currently live circuits unusable
 * for new streams, by calling circuit_mark_all_unused_circs() and
 * circuit_mark_all_dirty_circs_as_unusable().
 */
int
update_guard_selection_choice(const or_options_t *options)
{
  if (!curr_guard_context) {
    create_initial_guard_context();
    return 1;
  }

  guard_selection_type_t type = GS_TYPE_INFER;
  const char *new_name = choose_guard_selection(
                             options,
                             networkstatus_get_live_consensus(approx_time()),
                             curr_guard_context,
                             &type);
  tor_assert(new_name);
  tor_assert(type != GS_TYPE_INFER);

  const char *cur_name = curr_guard_context->name;
  if (! strcmp(cur_name, new_name)) {
    log_debug(LD_GUARD,
              "Staying with guard context \"%s\" (no change)", new_name);
    return 0; // No change
  }

  log_notice(LD_GUARD, "Switching to guard context \"%s\" (was using \"%s\")",
             new_name, cur_name);
  guard_selection_t *new_guard_context;
  new_guard_context = get_guard_selection_by_name(new_name, type, 1);
  tor_assert(new_guard_context);
  tor_assert(new_guard_context != curr_guard_context);
  curr_guard_context = new_guard_context;

  return 1;
}

/**
 * Return true iff <b>node</b> has all the flags needed for us to consider it
 * a possible guard when sampling guards.
 */
static int
node_is_possible_guard(const node_t *node)
{
  /* The "GUARDS" set is all nodes in the nodelist for which this predicate
   * holds. */

  /* XXXX -- prop271 spec deviation. We require node_is_dir() here. */
  tor_assert(node);
  return (node->is_possible_guard &&
          node->is_stable &&
          node->is_fast &&
          node->is_valid &&
          node_is_dir(node));
}

/**
 * Return the sampled guard with the RSA identity digest <b>rsa_id</b>, or
 * NULL if we don't have one. */
STATIC entry_guard_t *
get_sampled_guard_with_id(guard_selection_t *gs,
                          const uint8_t *rsa_id)
{
  tor_assert(gs);
  tor_assert(rsa_id);
  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
    if (tor_memeq(guard->identity, rsa_id, DIGEST_LEN))
      return guard;
  } SMARTLIST_FOREACH_END(guard);
  return NULL;
}

/** If <b>gs</b> contains a sampled entry guard matching <b>bridge</b>,
 * return that guard. Otherwise return NULL. */
static entry_guard_t *
get_sampled_guard_for_bridge(guard_selection_t *gs,
                             const bridge_info_t *bridge)
{
  const uint8_t *id = bridge_get_rsa_id_digest(bridge);
  const tor_addr_port_t *addrport = bridge_get_addr_port(bridge);
  entry_guard_t *guard;
  if (id) {
    guard = get_sampled_guard_with_id(gs, id);
    if (guard)
      return guard;
  }
  if (BUG(!addrport))
    return NULL; // LCOV_EXCL_LINE
  guard = get_sampled_guard_by_bridge_addr(gs, addrport);
  if (! guard || (id && tor_memneq(id, guard->identity, DIGEST_LEN)))
    return NULL;
  else
    return guard;
}

/** If we know a bridge_info_t matching <b>guard</b>, return that
 * bridge.  Otherwise return NULL. */
static bridge_info_t *
get_bridge_info_for_guard(const entry_guard_t *guard)
{
  if (! tor_digest_is_zero(guard->identity)) {
    bridge_info_t *bridge = find_bridge_by_digest(guard->identity);
    if (bridge)
      return bridge;
  }
  if (BUG(guard->bridge_addr == NULL))
    return NULL;
  return get_configured_bridge_by_addr_port_digest(&guard->bridge_addr->addr,
                                                     guard->bridge_addr->port,
                                                     NULL);
}

/**
 * Return true iff we have a sampled guard with the RSA identity digest
 * <b>rsa_id</b>. */
static inline int
have_sampled_guard_with_id(guard_selection_t *gs, const uint8_t *rsa_id)
{
  return get_sampled_guard_with_id(gs, rsa_id) != NULL;
}

/**
 * Allocate a new entry_guard_t object for <b>node</b>, add it to the
 * sampled entry guards in <b>gs</b>, and return it. <b>node</b> must
 * not currently be a sampled guard in <b>gs</b>.
 */
STATIC entry_guard_t *
entry_guard_add_to_sample(guard_selection_t *gs,
                          const node_t *node)
{
  log_info(LD_GUARD, "Adding %s as to the entry guard sample set.",
           node_describe(node));

  return entry_guard_add_to_sample_impl(gs,
                                        (const uint8_t*)node->identity,
                                        node_get_nickname(node),
                                        NULL);
}

/**
 * Backend: adds a new sampled guard to <b>gs</b>, with given identity,
 * nickname, and ORPort.  rsa_id_digest and bridge_addrport are optional, but
 * we need one of them. nickname is optional. The caller is responsible for
 * maintaining the size limit of the SAMPLED_GUARDS set.
 */
static entry_guard_t *
entry_guard_add_to_sample_impl(guard_selection_t *gs,
                               const uint8_t *rsa_id_digest,
                               const char *nickname,
                               const tor_addr_port_t *bridge_addrport)
{
  const int GUARD_LIFETIME = get_guard_lifetime();
  tor_assert(gs);

  // XXXX prop271 take ed25519 identity here too.

  /* make sure that the guard is not already sampled. */
  if (rsa_id_digest && BUG(have_sampled_guard_with_id(gs, rsa_id_digest)))
    return NULL; // LCOV_EXCL_LINE
  /* Make sure we can actually identify the guard. */
  if (BUG(!rsa_id_digest && !bridge_addrport))
    return NULL; // LCOV_EXCL_LINE

  entry_guard_t *guard = tor_malloc_zero(sizeof(entry_guard_t));

  /* persistent fields */
  guard->is_persistent = (rsa_id_digest != NULL);
  guard->selection_name = tor_strdup(gs->name);
  if (rsa_id_digest)
    memcpy(guard->identity, rsa_id_digest, DIGEST_LEN);
  if (nickname)
    strlcpy(guard->nickname, nickname, sizeof(guard->nickname));
  guard->sampled_on_date = randomize_time(approx_time(), GUARD_LIFETIME/10);
  tor_free(guard->sampled_by_version);
  guard->sampled_by_version = tor_strdup(VERSION);
  guard->currently_listed = 1;
  guard->confirmed_idx = -1;

  /* non-persistent fields */
  guard->is_reachable = GUARD_REACHABLE_MAYBE;
  if (bridge_addrport)
    guard->bridge_addr = tor_memdup(bridge_addrport, sizeof(*bridge_addrport));

  smartlist_add(gs->sampled_entry_guards, guard);
  guard->in_selection = gs;
  entry_guard_set_filtered_flags(get_options(), gs, guard);
  entry_guards_changed_for_guard_selection(gs);
  return guard;
}

/**
 * Add an entry guard to the "bridges" guard selection sample, with
 * information taken from <b>bridge</b>. Return that entry guard.
 */
static entry_guard_t *
entry_guard_add_bridge_to_sample(guard_selection_t *gs,
                                 const bridge_info_t *bridge)
{
  const uint8_t *id_digest = bridge_get_rsa_id_digest(bridge);
  const tor_addr_port_t *addrport = bridge_get_addr_port(bridge);

  tor_assert(addrport);

  return entry_guard_add_to_sample_impl(gs, id_digest, NULL, addrport);
}

/**
 * Return the entry_guard_t in <b>gs</b> whose address is <b>addrport</b>,
 * or NULL if none exists.
*/
static entry_guard_t *
get_sampled_guard_by_bridge_addr(guard_selection_t *gs,
                                 const tor_addr_port_t *addrport)
{
  if (! gs)
    return NULL;
  if (BUG(!addrport))
    return NULL;
  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, g) {
    if (g->bridge_addr && tor_addr_port_eq(addrport, g->bridge_addr))
      return g;
  } SMARTLIST_FOREACH_END(g);
  return NULL;
}

/** Update the guard subsystem's knowledge of the identity of the bridge
 * at <b>addrport</b>.  Idempotent.
 */
void
entry_guard_learned_bridge_identity(const tor_addr_port_t *addrport,
                                    const uint8_t *rsa_id_digest)
{
  guard_selection_t *gs = get_guard_selection_by_name("bridges",
                                                      GS_TYPE_BRIDGE,
                                                      0);
  if (!gs)
    return;

  entry_guard_t *g = get_sampled_guard_by_bridge_addr(gs, addrport);
  if (!g)
    return;

  int make_persistent = 0;

  if (tor_digest_is_zero(g->identity)) {
    memcpy(g->identity, rsa_id_digest, DIGEST_LEN);
    make_persistent = 1;
  } else if (tor_memeq(g->identity, rsa_id_digest, DIGEST_LEN)) {
    /* Nothing to see here; we learned something we already knew. */
    if (BUG(! g->is_persistent))
      make_persistent = 1;
  } else {
    char old_id[HEX_DIGEST_LEN+1];
    base16_encode(old_id, sizeof(old_id), g->identity, sizeof(g->identity));
    log_warn(LD_BUG, "We 'learned' an identity %s for a bridge at %s:%d, but "
             "we already knew a different one (%s). Ignoring the new info as "
             "possibly bogus.",
             hex_str((const char *)rsa_id_digest, DIGEST_LEN),
             fmt_and_decorate_addr(&addrport->addr), addrport->port,
             old_id);
    return; // redundant, but let's be clear: we're not making this persistent.
  }

  if (make_persistent) {
    g->is_persistent = 1;
    entry_guards_changed_for_guard_selection(gs);
  }
}

/**
 * Return the number of sampled guards in <b>gs</b> that are "filtered"
 * (that is, we're willing to connect to them) and that are "usable"
 * (that is, either "reachable" or "maybe reachable").
 *
 * If a restriction is provided in <b>rst</b>, do not count any guards that
 * violate it.
 */
STATIC int
num_reachable_filtered_guards(guard_selection_t *gs,
                              const entry_guard_restriction_t *rst)
{
  int n_reachable_filtered_guards = 0;
  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
    entry_guard_consider_retry(guard);
    if (! entry_guard_obeys_restriction(guard, rst))
      continue;
    if (guard->is_usable_filtered_guard)
      ++n_reachable_filtered_guards;
  } SMARTLIST_FOREACH_END(guard);
  return n_reachable_filtered_guards;
}

/** Return the actual maximum size for the sample in <b>gs</b>,
 * given that we know about <b>n_guards</b> total. */
static int
get_max_sample_size(guard_selection_t *gs,
                    int n_guards)
{
  const int using_bridges = (gs->type == GS_TYPE_BRIDGE);
  const int min_sample = get_min_filtered_sample_size();

  /* XXXX prop271 spec deviation with bridges, max_sample is "all of them" */
  if (using_bridges)
    return n_guards;

  const int max_sample_by_pct = (int)(n_guards * get_max_sample_threshold());
  const int max_sample_absolute = get_max_sample_size_absolute();
  const int max_sample = MIN(max_sample_by_pct, max_sample_absolute);
  if (max_sample < min_sample) // XXXX prop271 spec deviation
    return min_sample;
  else
    return max_sample;
}

/**
 * Return a smartlist of the all the guards that are not currently
 * members of the sample (GUARDS - SAMPLED_GUARDS).  The elements of
 * this list are node_t pointers in the non-bridge case, and
 * bridge_info_t pointers in the bridge case.  Set *<b>n_guards_out/b>
 * to the number of guards that we found in GUARDS, including those
 * that were already sampled.
 */
static smartlist_t *
get_eligible_guards(guard_selection_t *gs,
                    int *n_guards_out)
{
  /* Construct eligible_guards as GUARDS - SAMPLED_GUARDS */
  smartlist_t *eligible_guards = smartlist_new();
  int n_guards = 0; // total size of "GUARDS"

  if (gs->type == GS_TYPE_BRIDGE) {
    const smartlist_t *bridges = bridge_list_get();
    SMARTLIST_FOREACH_BEGIN(bridges, bridge_info_t *, bridge) {
      ++n_guards;
      if (NULL != get_sampled_guard_for_bridge(gs, bridge)) {
        continue;
      }
      smartlist_add(eligible_guards, bridge);
    } SMARTLIST_FOREACH_END(bridge);
  } else {
    const smartlist_t *nodes = nodelist_get_list();
    const int n_sampled = smartlist_len(gs->sampled_entry_guards);

    /* Build a bloom filter of our current guards: let's keep this O(N). */
    digestset_t *sampled_guard_ids = digestset_new(n_sampled);
    SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, const entry_guard_t *,
                            guard) {
      digestset_add(sampled_guard_ids, guard->identity);
    } SMARTLIST_FOREACH_END(guard);

    SMARTLIST_FOREACH_BEGIN(nodes, const node_t *, node) {
      if (! node_is_possible_guard(node))
        continue;
      ++n_guards;
      if (digestset_contains(sampled_guard_ids, node->identity))
        continue;
      smartlist_add(eligible_guards, (node_t*)node);
    } SMARTLIST_FOREACH_END(node);

    /* Now we can free that bloom filter. */
    digestset_free(sampled_guard_ids);
  }

  *n_guards_out = n_guards;
  return eligible_guards;
}

/** Helper: given a smartlist of either bridge_info_t (if gs->type is
 * GS_TYPE_BRIDGE) or node_t (otherwise), pick one that can be a guard,
 * add it as a guard, remove it from the list, and return a new
 * entry_guard_t.  Return NULL on failure. */
static entry_guard_t *
select_and_add_guard_item_for_sample(guard_selection_t *gs,
                                     smartlist_t *eligible_guards)
{
  entry_guard_t *added_guard;
  if (gs->type == GS_TYPE_BRIDGE) {
    const bridge_info_t *bridge = smartlist_choose(eligible_guards);
    if (BUG(!bridge))
      return NULL; // LCOV_EXCL_LINE
    smartlist_remove(eligible_guards, bridge);
    added_guard = entry_guard_add_bridge_to_sample(gs, bridge);
  } else {
    const node_t *node =
      node_sl_choose_by_bandwidth(eligible_guards, WEIGHT_FOR_GUARD);
    if (BUG(!node))
      return NULL; // LCOV_EXCL_LINE
    smartlist_remove(eligible_guards, node);
    added_guard = entry_guard_add_to_sample(gs, node);
  }

  return added_guard;
}

/**
 * Add new guards to the sampled guards in <b>gs</b> until there are
 * enough usable filtered guards, but never grow the sample beyond its
 * maximum size.  Return the last guard added, or NULL if none were
 * added.
 */
STATIC entry_guard_t *
entry_guards_expand_sample(guard_selection_t *gs)
{
  tor_assert(gs);
  int n_sampled = smartlist_len(gs->sampled_entry_guards);
  entry_guard_t *added_guard = NULL;
  int n_usable_filtered_guards = num_reachable_filtered_guards(gs, NULL);
  int n_guards = 0;
  smartlist_t *eligible_guards = get_eligible_guards(gs, &n_guards);

  const int max_sample = get_max_sample_size(gs, n_guards);
  const int min_filtered_sample = get_min_filtered_sample_size();

  log_info(LD_GUARD, "Expanding the sample guard set. We have %d guards "
           "in the sample, and %d eligible guards to extend it with.",
           n_sampled, smartlist_len(eligible_guards));

  while (n_usable_filtered_guards < min_filtered_sample) {
    /* Has our sample grown too large to expand? */
    if (n_sampled >= max_sample) {
      log_info(LD_GUARD, "Not expanding the guard sample any further; "
               "just hit the maximum sample threshold of %d",
               max_sample);
      goto done;
    }

    /* Did we run out of guards? */
    if (smartlist_len(eligible_guards) == 0) {
      /* LCOV_EXCL_START
         As long as MAX_SAMPLE_THRESHOLD makes can't be adjusted to
         allow all guards to be sampled, this can't be reached.
       */
      log_info(LD_GUARD, "Not expanding the guard sample any further; "
               "just ran out of eligible guards");
      goto done;
      /* LCOV_EXCL_STOP */
    }

    /* Otherwise we can add at least one new guard. */
    added_guard = select_and_add_guard_item_for_sample(gs, eligible_guards);
    if (!added_guard)
      goto done; // LCOV_EXCL_LINE -- only fails on BUG.

    ++n_sampled;

    if (added_guard->is_usable_filtered_guard)
      ++n_usable_filtered_guards;
  }

 done:
  smartlist_free(eligible_guards);
  return added_guard;
}

/**
 * Helper: <b>guard</b> has just been removed from the sampled guards:
 * also remove it from primary and confirmed. */
static void
remove_guard_from_confirmed_and_primary_lists(guard_selection_t *gs,
                                              entry_guard_t *guard)
{
  if (guard->is_primary) {
    guard->is_primary = 0;
    smartlist_remove_keeporder(gs->primary_entry_guards, guard);
  } else {
    if (BUG(smartlist_contains(gs->primary_entry_guards, guard))) {
      smartlist_remove_keeporder(gs->primary_entry_guards, guard);
    }
  }

  if (guard->confirmed_idx >= 0) {
    entry_guard_t *found_guard = NULL;
    if (guard->confirmed_idx < smartlist_len(gs->confirmed_entry_guards))
      found_guard = smartlist_get(gs->confirmed_entry_guards,
                                  guard->confirmed_idx);
    if (BUG(guard != found_guard)) {
      // LCOV_EXCL_START
      smartlist_remove_keeporder(gs->confirmed_entry_guards, guard);
      // LCOV_EXCL_STOP
    } else {
      smartlist_del_keeporder(gs->confirmed_entry_guards,
                              guard->confirmed_idx);
    }
    guard->confirmed_idx = -1;
    guard->confirmed_on_date = 0;
  } else {
    if (BUG(smartlist_contains(gs->confirmed_entry_guards, guard))) {
      // LCOV_EXCL_START
      smartlist_remove_keeporder(gs->confirmed_entry_guards, guard);
      // LCOV_EXCL_STOP
    }
  }
}

/** Return true iff <b>guard</b> is currently "listed" -- that is, it
 * appears in the consensus, or as a configured bridge (as
 * appropriate) */
MOCK_IMPL(STATIC int,
entry_guard_is_listed,(guard_selection_t *gs, const entry_guard_t *guard))
{
  if (gs->type == GS_TYPE_BRIDGE) {
    return NULL != get_bridge_info_for_guard(guard);
  } else {
    const node_t *node = node_get_by_id(guard->identity);

    return node && node_is_possible_guard(node);
  }
}

/**
 * Update the status of all sampled guards based on the arrival of a
 * new consensus networkstatus document.  This will include marking
 * some guards as listed or unlisted, and removing expired guards. */
STATIC void
sampled_guards_update_from_consensus(guard_selection_t *gs)
{
  /*XXXX prop271 consider splitting this function up. */
  tor_assert(gs);
  const int REMOVE_UNLISTED_GUARDS_AFTER =
    (get_remove_unlisted_guards_after_days() * 86400);
  const int unlisted_since_slop = REMOVE_UNLISTED_GUARDS_AFTER / 5;

  // It's important to use only a live consensus here; we don't want to
  // make changes based on anything expired or old.
  if (gs->type != GS_TYPE_BRIDGE) {
    networkstatus_t *ns = networkstatus_get_live_consensus(approx_time());

    if (! ns) {
      log_info(LD_GUARD, "No live consensus; can't update "
               "sampled entry guards.");
      return;
    } else {
      log_info(LD_GUARD, "Updating sampled guard status based on received "
               "consensus.");
    }
  }

  int n_changes = 0;

  /* First: Update listed/unlisted. */
  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
    /* XXXX prop271 check ed ID too */
    const int is_listed = entry_guard_is_listed(gs, guard);

    if (is_listed && ! guard->currently_listed) {
      ++n_changes;
      guard->currently_listed = 1;
      guard->unlisted_since_date = 0;
      log_info(LD_GUARD, "Sampled guard %s is now listed again.",
               entry_guard_describe(guard));
    } else if (!is_listed && guard->currently_listed) {
      ++n_changes;
      guard->currently_listed = 0;
      guard->unlisted_since_date = randomize_time(approx_time(),
                                                  unlisted_since_slop);
      log_info(LD_GUARD, "Sampled guard %s is now unlisted.",
               entry_guard_describe(guard));
    } else if (is_listed && guard->currently_listed) {
      log_debug(LD_GUARD, "Sampled guard %s is still listed.",
               entry_guard_describe(guard));
    } else {
      tor_assert(! is_listed && ! guard->currently_listed);
      log_debug(LD_GUARD, "Sampled guard %s is still unlisted.",
                entry_guard_describe(guard));
    }

    /* Clean up unlisted_since_date, just in case. */
    if (guard->currently_listed && guard->unlisted_since_date) {
      ++n_changes;
      guard->unlisted_since_date = 0;
      log_warn(LD_BUG, "Sampled guard %s was listed, but with "
               "unlisted_since_date set. Fixing.",
               entry_guard_describe(guard));
    } else if (!guard->currently_listed && ! guard->unlisted_since_date) {
      ++n_changes;
      guard->unlisted_since_date = randomize_time(approx_time(),
                                                  unlisted_since_slop);
      log_warn(LD_BUG, "Sampled guard %s was unlisted, but with "
               "unlisted_since_date unset. Fixing.",
               entry_guard_describe(guard));
    }
  } SMARTLIST_FOREACH_END(guard);

  const time_t remove_if_unlisted_since =
    approx_time() - REMOVE_UNLISTED_GUARDS_AFTER;
  const time_t maybe_remove_if_sampled_before =
    approx_time() - get_guard_lifetime();
  const time_t remove_if_confirmed_before =
    approx_time() - get_guard_confirmed_min_lifetime();

  /* Then: remove the ones that have been junk for too long */
  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
    int remove = 0;

    if (guard->currently_listed == 0 &&
        guard->unlisted_since_date < remove_if_unlisted_since) {
      /*
        "We have a live consensus, and {IS_LISTED} is false, and
         {FIRST_UNLISTED_AT} is over {REMOVE_UNLISTED_GUARDS_AFTER}
         days in the past."
      */
      log_info(LD_GUARD, "Removing sampled guard %s: it has been unlisted "
               "for over %d days", entry_guard_describe(guard),
               get_remove_unlisted_guards_after_days());
      remove = 1;
    } else if (guard->sampled_on_date < maybe_remove_if_sampled_before) {
      /* We have a live consensus, and {ADDED_ON_DATE} is over
        {GUARD_LIFETIME} ago, *and* {CONFIRMED_ON_DATE} is either
        "never", or over {GUARD_CONFIRMED_MIN_LIFETIME} ago.
      */
      if (guard->confirmed_on_date == 0) {
        remove = 1;
        log_info(LD_GUARD, "Removing sampled guard %s: it was sampled "
                 "over %d days ago, but never confirmed.",
                 entry_guard_describe(guard),
                 get_guard_lifetime() / 86400);
      } else if (guard->confirmed_on_date < remove_if_confirmed_before) {
        remove = 1;
        log_info(LD_GUARD, "Removing sampled guard %s: it was sampled "
                 "over %d days ago, and confirmed over %d days ago.",
                 entry_guard_describe(guard),
                 get_guard_lifetime() / 86400,
                 get_guard_confirmed_min_lifetime() / 86400);
      }
    }

    if (remove) {
      ++n_changes;
      SMARTLIST_DEL_CURRENT(gs->sampled_entry_guards, guard);
      remove_guard_from_confirmed_and_primary_lists(gs, guard);
      entry_guard_free(guard);
    }
  } SMARTLIST_FOREACH_END(guard);

  if (n_changes) {
    gs->primary_guards_up_to_date = 0;
    entry_guards_update_filtered_sets(gs);
    /* We don't need to rebuild the confirmed list right here -- we may have
     * removed confirmed guards above, but we can't have added any new
     * confirmed guards.
     */
    entry_guards_changed_for_guard_selection(gs);
  }
}

/**
 * Return true iff <b>node</b> is a Tor relay that we are configured to
 * be able to connect to. */
static int
node_passes_guard_filter(const or_options_t *options,
                         const node_t *node)
{
  /* NOTE: Make sure that this function stays in sync with
   * options_transition_affects_entry_guards */
  if (routerset_contains_node(options->ExcludeNodes, node))
    return 0;

  /* XXXX -- prop271 spec deviation -- add entrynodes to spec. */
  if (options->EntryNodes &&
      !routerset_contains_node(options->EntryNodes, node))
    return 0;

  if (!fascist_firewall_allows_node(node, FIREWALL_OR_CONNECTION, 0))
    return 0;

  if (node_is_a_configured_bridge(node))
    return 0;

  return 1;
}

/** Helper: Return true iff <b>bridge</b> passes our configuration
 * filter-- if it is a relay that we are configured to be able to
 * connect to. */
static int
bridge_passes_guard_filter(const or_options_t *options,
                           const bridge_info_t *bridge)
{
  tor_assert(bridge);
  if (!bridge)
    return 0;

  if (routerset_contains_bridge(options->ExcludeNodes, bridge))
    return 0;

  /* Ignore entrynodes */
  const tor_addr_port_t *addrport = bridge_get_addr_port(bridge);

  if (!fascist_firewall_allows_address_addr(&addrport->addr,
                                            addrport->port,
                                            FIREWALL_OR_CONNECTION,
                                            0, 0))
    return 0;

  return 1;
}

/**
 * Return true iff <b>guard</b> is a Tor relay that we are configured to
 * be able to connect to, and we haven't disabled it for omission from
 * the consensus or path bias issues. */
static int
entry_guard_passes_filter(const or_options_t *options, guard_selection_t *gs,
                          entry_guard_t *guard)
{
  if (guard->currently_listed == 0)
    return 0;
  if (guard->pb.path_bias_disabled)
    return 0;

  if (gs->type == GS_TYPE_BRIDGE) {
    const bridge_info_t *bridge = get_bridge_info_for_guard(guard);
    if (bridge == NULL)
      return 0;
    return bridge_passes_guard_filter(options, bridge);
  } else {
    const node_t *node = node_get_by_id(guard->identity);
    if (node == NULL) {
      // This can happen when currently_listed is true, and we're not updating
      // it because we don't have a live consensus.
      return 0;
    }

    return node_passes_guard_filter(options, node);
  }
}

/**
 * Return true iff <b>guard</b> obeys the restrictions defined in <b>rst</b>.
 * (If <b>rst</b> is NULL, there are no restrictions.)
 */
static int
entry_guard_obeys_restriction(const entry_guard_t *guard,
                              const entry_guard_restriction_t *rst)
{
  tor_assert(guard);
  if (! rst)
    return 1; // No restriction?  No problem.

  // Only one kind of restriction exists right now
  return tor_memneq(guard->identity, rst->exclude_id, DIGEST_LEN);
}

/**
 * Update the <b>is_filtered_guard</b> and <b>is_usable_filtered_guard</b>
 * flags on <b>guard</b>. */
void
entry_guard_set_filtered_flags(const or_options_t *options,
                               guard_selection_t *gs,
                               entry_guard_t *guard)
{
  unsigned was_filtered = guard->is_filtered_guard;
  guard->is_filtered_guard = 0;
  guard->is_usable_filtered_guard = 0;

  if (entry_guard_passes_filter(options, gs, guard)) {
    guard->is_filtered_guard = 1;

    if (guard->is_reachable != GUARD_REACHABLE_NO)
      guard->is_usable_filtered_guard = 1;

    entry_guard_consider_retry(guard);
  }
  log_debug(LD_GUARD, "Updated sampled guard %s: filtered=%d; "
            "reachable_filtered=%d.", entry_guard_describe(guard),
            guard->is_filtered_guard, guard->is_usable_filtered_guard);

  if (!bool_eq(was_filtered, guard->is_filtered_guard)) {
    /* This guard might now be primary or nonprimary. */
    gs->primary_guards_up_to_date = 0;
  }
}

/**
 * Update the <b>is_filtered_guard</b> and <b>is_usable_filtered_guard</b>
 * flag on every guard in <b>gs</b>. */
STATIC void
entry_guards_update_filtered_sets(guard_selection_t *gs)
{
  const or_options_t *options = get_options();

  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
    entry_guard_set_filtered_flags(options, gs, guard);
  } SMARTLIST_FOREACH_END(guard);
}

/**
 * Return a random guard from the reachable filtered sample guards
 * in <b>gs</b>, subject to the exclusion rules listed in <b>flags</b>.
 * Return NULL if no such guard can be found.
 *
 * Make sure that the sample is big enough, and that all the filter flags
 * are set correctly, before calling this function.
 *
 * If a restriction is provided in <b>rst</b>, do not return any guards that
 * violate it.
 **/
STATIC entry_guard_t *
sample_reachable_filtered_entry_guards(guard_selection_t *gs,
                                       const entry_guard_restriction_t *rst,
                                       unsigned flags)
{
  tor_assert(gs);
  entry_guard_t *result = NULL;
  const unsigned exclude_confirmed = flags & SAMPLE_EXCLUDE_CONFIRMED;
  const unsigned exclude_primary = flags & SAMPLE_EXCLUDE_PRIMARY;
  const unsigned exclude_pending = flags & SAMPLE_EXCLUDE_PENDING;
  const unsigned no_update_primary = flags & SAMPLE_NO_UPDATE_PRIMARY;

  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
    entry_guard_consider_retry(guard);
  } SMARTLIST_FOREACH_END(guard);

  const int n_reachable_filtered = num_reachable_filtered_guards(gs, rst);

  log_info(LD_GUARD, "Trying to sample a reachable guard: We know of %d "
           "in the USABLE_FILTERED set.", n_reachable_filtered);

  const int min_filtered_sample = get_min_filtered_sample_size();
  if (n_reachable_filtered < min_filtered_sample) {
    log_info(LD_GUARD, "  (That isn't enough. Trying to expand the sample.)");
    entry_guards_expand_sample(gs);
  }

  if (exclude_primary && !gs->primary_guards_up_to_date && !no_update_primary)
    entry_guards_update_primary(gs);

  /* Build the set of reachable filtered guards. */
  smartlist_t *reachable_filtered_sample = smartlist_new();
  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
    entry_guard_consider_retry(guard);// redundant, but cheap.
    if (! entry_guard_obeys_restriction(guard, rst))
      continue;
    if (! guard->is_usable_filtered_guard)
      continue;
    if (exclude_confirmed && guard->confirmed_idx >= 0)
      continue;
    if (exclude_primary && guard->is_primary)
      continue;
    if (exclude_pending && guard->is_pending)
      continue;
    smartlist_add(reachable_filtered_sample, guard);
  } SMARTLIST_FOREACH_END(guard);

  log_info(LD_GUARD, "  (After filters [%x], we have %d guards to consider.)",
           flags, smartlist_len(reachable_filtered_sample));

  if (smartlist_len(reachable_filtered_sample)) {
    result = smartlist_choose(reachable_filtered_sample);
    log_info(LD_GUARD, "  (Selected %s.)",
             result ? entry_guard_describe(result) : "<null>");
  }
  smartlist_free(reachable_filtered_sample);

  return result;
}

/**
 * Helper: compare two entry_guard_t by their confirmed_idx values.
 * Used to sort the confirmed list.
 */
static int
compare_guards_by_confirmed_idx(const void **a_, const void **b_)
{
  const entry_guard_t *a = *a_, *b = *b_;
  if (a->confirmed_idx < b->confirmed_idx)
    return -1;
  else if (a->confirmed_idx > b->confirmed_idx)
    return 1;
  else
    return 0;
}

/**
 * Find the confirmed guards from among the sampled guards in <b>gs</b>,
 * and put them in confirmed_entry_guards in the correct
 * order. Recalculate their indices.
 */
STATIC void
entry_guards_update_confirmed(guard_selection_t *gs)
{
  smartlist_clear(gs->confirmed_entry_guards);
  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
    if (guard->confirmed_idx >= 0)
      smartlist_add(gs->confirmed_entry_guards, guard);
  } SMARTLIST_FOREACH_END(guard);

  smartlist_sort(gs->confirmed_entry_guards, compare_guards_by_confirmed_idx);

  int any_changed = 0;
  SMARTLIST_FOREACH_BEGIN(gs->confirmed_entry_guards, entry_guard_t *, guard) {
    if (guard->confirmed_idx != guard_sl_idx) {
      any_changed = 1;
      guard->confirmed_idx = guard_sl_idx;
    }
  } SMARTLIST_FOREACH_END(guard);

  gs->next_confirmed_idx = smartlist_len(gs->confirmed_entry_guards);

  if (any_changed) {
    entry_guards_changed_for_guard_selection(gs);
  }
}

/**
 * Mark <b>guard</b> as a confirmed guard -- that is, one that we have
 * connected to, and intend to use again.
 */
STATIC void
make_guard_confirmed(guard_selection_t *gs, entry_guard_t *guard)
{
  if (BUG(guard->confirmed_on_date && guard->confirmed_idx >= 0))
    return; // LCOV_EXCL_LINE

  if (BUG(smartlist_contains(gs->confirmed_entry_guards, guard)))
    return; // LCOV_EXCL_LINE

  const int GUARD_LIFETIME = get_guard_lifetime();
  guard->confirmed_on_date = randomize_time(approx_time(), GUARD_LIFETIME/10);

  log_info(LD_GUARD, "Marking %s as a confirmed guard (index %d)",
           entry_guard_describe(guard),
           gs->next_confirmed_idx);

  guard->confirmed_idx = gs->next_confirmed_idx++;
  smartlist_add(gs->confirmed_entry_guards, guard);

  // This confirmed guard might kick something else out of the primary
  // guards.
  gs->primary_guards_up_to_date = 0;

  entry_guards_changed_for_guard_selection(gs);
}

/**
 * Recalculate the list of primary guards (the ones we'd prefer to use) from
 * the filtered sample and the confirmed list.
 */
STATIC void
entry_guards_update_primary(guard_selection_t *gs)
{
  /*XXXX prop271 consider splitting this function up. */
  tor_assert(gs);

  // prevent recursion. Recursion is potentially very bad here.
  static int running = 0;
  tor_assert(!running);
  running = 1;

  const int N_PRIMARY_GUARDS = get_n_primary_guards();

  smartlist_t *new_primary_guards = smartlist_new();
  smartlist_t *old_primary_guards = smartlist_new();
  smartlist_add_all(old_primary_guards, gs->primary_entry_guards);

  /* Set this flag now, to prevent the calls below from recursing. */
  gs->primary_guards_up_to_date = 1;

  /* First, can we fill it up with confirmed guards? */
  SMARTLIST_FOREACH_BEGIN(gs->confirmed_entry_guards, entry_guard_t *, guard) {
    if (smartlist_len(new_primary_guards) >= N_PRIMARY_GUARDS)
      break;
    if (! guard->is_filtered_guard)
      continue;
    guard->is_primary = 1;
    smartlist_add(new_primary_guards, guard);
  } SMARTLIST_FOREACH_END(guard);

  /* Can we keep any older primary guards? First remove all the ones
   * that we already kept. */
  SMARTLIST_FOREACH_BEGIN(old_primary_guards, entry_guard_t *, guard) {
    if (smartlist_contains(new_primary_guards, guard)) {
      SMARTLIST_DEL_CURRENT_KEEPORDER(old_primary_guards, guard);
    }
  } SMARTLIST_FOREACH_END(guard);

  /* Now add any that are still good. */
  SMARTLIST_FOREACH_BEGIN(old_primary_guards, entry_guard_t *, guard) {
    if (smartlist_len(new_primary_guards) >= N_PRIMARY_GUARDS)
      break;
    if (! guard->is_filtered_guard)
      continue;
    guard->is_primary = 1;
    smartlist_add(new_primary_guards, guard);
    SMARTLIST_DEL_CURRENT_KEEPORDER(old_primary_guards, guard);
  } SMARTLIST_FOREACH_END(guard);

  /* Mark the remaining previous primary guards as non-primary */
  SMARTLIST_FOREACH_BEGIN(old_primary_guards, entry_guard_t *, guard) {
    guard->is_primary = 0;
  } SMARTLIST_FOREACH_END(guard);

  /* Finally, fill out the list with sampled guards. */
  while (smartlist_len(new_primary_guards) < N_PRIMARY_GUARDS) {
    entry_guard_t *guard = sample_reachable_filtered_entry_guards(gs, NULL,
                                            SAMPLE_EXCLUDE_CONFIRMED|
                                            SAMPLE_EXCLUDE_PRIMARY|
                                            SAMPLE_NO_UPDATE_PRIMARY);
    if (!guard)
      break;
    guard->is_primary = 1;
    smartlist_add(new_primary_guards, guard);
  }

#if 1
  /* Debugging. */
  SMARTLIST_FOREACH(gs->sampled_entry_guards, entry_guard_t *, guard, {
    tor_assert_nonfatal(
                   bool_eq(guard->is_primary,
                           smartlist_contains(new_primary_guards, guard)));
  });
#endif

  int any_change = 0;
  if (smartlist_len(gs->primary_entry_guards) !=
      smartlist_len(new_primary_guards)) {
    any_change = 1;
  } else {
    SMARTLIST_FOREACH_BEGIN(gs->primary_entry_guards, entry_guard_t *, g) {
      if (g != smartlist_get(new_primary_guards, g_sl_idx)) {
        any_change = 1;
      }
    } SMARTLIST_FOREACH_END(g);
  }

  if (any_change) {
    log_info(LD_GUARD, "Primary entry guards have changed. "
             "New primary guard list is: ");
    int n = smartlist_len(new_primary_guards);
    SMARTLIST_FOREACH_BEGIN(new_primary_guards, entry_guard_t *, g) {
      log_info(LD_GUARD, "  %d/%d: %s%s%s",
               g_sl_idx+1, n, entry_guard_describe(g),
               g->confirmed_idx >= 0 ? " (confirmed)" : "",
               g->is_filtered_guard ? "" : " (excluded by filter)");
    } SMARTLIST_FOREACH_END(g);
  }

  smartlist_free(old_primary_guards);
  smartlist_free(gs->primary_entry_guards);
  gs->primary_entry_guards = new_primary_guards;
  gs->primary_guards_up_to_date = 1;
  running = 0;
}

/**
 * Return the number of seconds after the last attempt at which we should
 * retry a guard that has been failing since <b>failing_since</b>.
 */
static int
get_retry_schedule(time_t failing_since, time_t now,
                   int is_primary)
{
  const unsigned SIX_HOURS = 6 * 3600;
  const unsigned FOUR_DAYS = 4 * 86400;
  const unsigned SEVEN_DAYS = 7 * 86400;

  time_t tdiff;
  if (now > failing_since) {
    tdiff = now - failing_since;
  } else {
    tdiff = 0;
  }

  const struct {
    time_t maximum; int primary_delay; int nonprimary_delay;
  } delays[] = {
    { SIX_HOURS,    10*60,  1*60*60 },
    { FOUR_DAYS,    90*60,  4*60*60 },
    { SEVEN_DAYS, 4*60*60, 18*60*60 },
    { TIME_MAX,   9*60*60, 36*60*60 }
  };

  unsigned i;
  for (i = 0; i < ARRAY_LENGTH(delays); ++i) {
    if (tdiff <= delays[i].maximum) {
      return is_primary ? delays[i].primary_delay : delays[i].nonprimary_delay;
    }
  }
  /* LCOV_EXCL_START -- can't reach, since delays ends with TIME_MAX. */
  tor_assert_nonfatal_unreached();
  return 36*60*60;
  /* LCOV_EXCL_STOP */
}

/**
 * If <b>guard</b> is unreachable, consider whether enough time has passed
 * to consider it maybe-reachable again.
 */
STATIC void
entry_guard_consider_retry(entry_guard_t *guard)
{
  if (guard->is_reachable != GUARD_REACHABLE_NO)
    return; /* No retry needed. */

  const time_t now = approx_time();
  const int delay =
    get_retry_schedule(guard->failing_since, now, guard->is_primary);
  const time_t last_attempt = guard->last_tried_to_connect;

  if (BUG(last_attempt == 0) ||
      now >= last_attempt + delay) {
    /* We should mark this retriable. */
    char tbuf[ISO_TIME_LEN+1];
    format_local_iso_time(tbuf, last_attempt);
    log_info(LD_GUARD, "Marked %s%sguard %s for possible retry, since we "
             "haven't tried to use it since %s.",
             guard->is_primary?"primary ":"",
             guard->confirmed_idx>=0?"confirmed ":"",
             entry_guard_describe(guard),
             tbuf);

    guard->is_reachable = GUARD_REACHABLE_MAYBE;
    if (guard->is_filtered_guard)
      guard->is_usable_filtered_guard = 1;
  }
}

/** Tell the entry guards subsystem that we have confirmed that as of
 * just now, we're on the internet. */
void
entry_guards_note_internet_connectivity(guard_selection_t *gs)
{
  gs->last_time_on_internet = approx_time();
}

/**
 * Get a guard for use with a circuit.  Prefer to pick a running primary
 * guard; then a non-pending running filtered confirmed guard; then a
 * non-pending runnable filtered guard.  Update the
 * <b>last_tried_to_connect</b> time and the <b>is_pending</b> fields of the
 * guard as appropriate.  Set <b>state_out</b> to the new guard-state
 * of the circuit.
 */
STATIC entry_guard_t *
select_entry_guard_for_circuit(guard_selection_t *gs,
                               const entry_guard_restriction_t *rst,
                               unsigned *state_out)
{
  /*XXXX prop271 consider splitting this function up. */
  tor_assert(gs);
  tor_assert(state_out);

  if (!gs->primary_guards_up_to_date)
    entry_guards_update_primary(gs);

  int num_entry_guards = get_n_primary_guards_to_use();
  smartlist_t *usable_primary_guards = smartlist_new();

  /* "If any entry in PRIMARY_GUARDS has {is_reachable} status of
      <maybe> or <yes>, return the first such guard." */
  SMARTLIST_FOREACH_BEGIN(gs->primary_entry_guards, entry_guard_t *, guard) {
    entry_guard_consider_retry(guard);
    if (! entry_guard_obeys_restriction(guard, rst))
      continue;
    if (guard->is_reachable != GUARD_REACHABLE_NO) {
      *state_out = GUARD_CIRC_STATE_USABLE_ON_COMPLETION;
      guard->last_tried_to_connect = approx_time();
      smartlist_add(usable_primary_guards, guard);
      if (smartlist_len(usable_primary_guards) >= num_entry_guards)
        break;
    }
  } SMARTLIST_FOREACH_END(guard);

  if (smartlist_len(usable_primary_guards)) {
    entry_guard_t *guard = smartlist_choose(usable_primary_guards);
    smartlist_free(usable_primary_guards);
    log_info(LD_GUARD, "Selected primary guard %s for circuit.",
             entry_guard_describe(guard));
    return guard;
  }
  smartlist_free(usable_primary_guards);

  /* "Otherwise, if the ordered intersection of {CONFIRMED_GUARDS}
      and {USABLE_FILTERED_GUARDS} is nonempty, return the first
      entry in that intersection that has {is_pending} set to
      false." */
  SMARTLIST_FOREACH_BEGIN(gs->confirmed_entry_guards, entry_guard_t *, guard) {
    if (guard->is_primary)
      continue; /* we already considered this one. */
    if (! entry_guard_obeys_restriction(guard, rst))
      continue;
    entry_guard_consider_retry(guard);
    if (guard->is_usable_filtered_guard && ! guard->is_pending) {
      guard->is_pending = 1;
      guard->last_tried_to_connect = approx_time();
      *state_out = GUARD_CIRC_STATE_USABLE_IF_NO_BETTER_GUARD;
      log_info(LD_GUARD, "No primary guards available. Selected confirmed "
               "guard %s for circuit. Will try other guards before using "
               "this circuit.",
               entry_guard_describe(guard));
      return guard;
    }
  } SMARTLIST_FOREACH_END(guard);

  /* "Otherwise, if there is no such entry, select a member at
      random from {USABLE_FILTERED_GUARDS}." */
  {
    entry_guard_t *guard;
    guard = sample_reachable_filtered_entry_guards(gs,
                                                   rst,
                                                   SAMPLE_EXCLUDE_CONFIRMED |
                                                   SAMPLE_EXCLUDE_PRIMARY |
                                                   SAMPLE_EXCLUDE_PENDING);
    if (guard == NULL) {
      log_info(LD_GUARD, "Absolutely no sampled guards were available.");
      return NULL;
    }
    guard->is_pending = 1;
    guard->last_tried_to_connect = approx_time();
    *state_out = GUARD_CIRC_STATE_USABLE_IF_NO_BETTER_GUARD;
    log_info(LD_GUARD, "No primary or confirmed guards available. Selected "
             "random guard %s for circuit. Will try other guards before "
             "using this circuit.",
             entry_guard_describe(guard));
    return guard;
  }
}

/**
 * Note that we failed to connect to or build circuits through <b>guard</b>.
 * Use with a guard returned by select_entry_guard_for_circuit().
 */
STATIC void
entry_guards_note_guard_failure(guard_selection_t *gs,
                                entry_guard_t *guard)
{
  tor_assert(gs);

  guard->is_reachable = GUARD_REACHABLE_NO;
  guard->is_usable_filtered_guard = 0;

  guard->is_pending = 0;
  if (guard->failing_since == 0)
    guard->failing_since = approx_time();

  log_info(LD_GUARD, "Recorded failure for %s%sguard %s",
           guard->is_primary?"primary ":"",
           guard->confirmed_idx>=0?"confirmed ":"",
           entry_guard_describe(guard));
}

/**
 * Called when the network comes up after having seemed to be down for
 * a while: Mark the primary guards as maybe-reachable so that we'll
 * try them again.
 */
STATIC void
mark_primary_guards_maybe_reachable(guard_selection_t *gs)
{
  if (!gs->primary_guards_up_to_date)
    entry_guards_update_primary(gs);

  SMARTLIST_FOREACH_BEGIN(gs->primary_entry_guards, entry_guard_t *, guard) {
    if (guard->is_reachable != GUARD_REACHABLE_NO)
      continue;

    /* Note that we do not clear failing_since: this guard is now only
     * _maybe-reachable_. */
    guard->is_reachable = GUARD_REACHABLE_MAYBE;
    if (guard->is_filtered_guard)
      guard->is_usable_filtered_guard = 1;

  } SMARTLIST_FOREACH_END(guard);
}

/**
 * Note that we successfully connected to, and built a circuit through
 * <b>guard</b>. Given the old guard-state of the circuit in <b>old_state</b>,
 * return the new guard-state of the circuit.
 *
 * Be aware: the circuit is only usable when its guard-state becomes
 * GUARD_CIRC_STATE_COMPLETE.
 **/
STATIC unsigned
entry_guards_note_guard_success(guard_selection_t *gs,
                                entry_guard_t *guard,
                                unsigned old_state)
{
  tor_assert(gs);

  /* Save this, since we're about to overwrite it. */
  const time_t last_time_on_internet = gs->last_time_on_internet;
  gs->last_time_on_internet = approx_time();

  guard->is_reachable = GUARD_REACHABLE_YES;
  guard->failing_since = 0;
  guard->is_pending = 0;
  if (guard->is_filtered_guard)
    guard->is_usable_filtered_guard = 1;

  if (guard->confirmed_idx < 0) {
    make_guard_confirmed(gs, guard);
    if (!gs->primary_guards_up_to_date)
      entry_guards_update_primary(gs);
  }

  unsigned new_state;
  switch (old_state) {
    case GUARD_CIRC_STATE_COMPLETE:
    case GUARD_CIRC_STATE_USABLE_ON_COMPLETION:
      new_state = GUARD_CIRC_STATE_COMPLETE;
      break;
    default:
      tor_assert_nonfatal_unreached();
      /* Fall through. */
    case GUARD_CIRC_STATE_USABLE_IF_NO_BETTER_GUARD:
      if (guard->is_primary) {
        /* XXXX prop271 -- I don't actually like this logic. It seems to make
         * us a little more susceptible to evil-ISP attacks.  The mitigations
         * I'm thinking of, however, aren't local to this point, so I'll leave
         * it alone. */
        /* This guard may have become primary by virtue of being confirmed.
         * If so, the circuit for it is now complete.
         */
        new_state = GUARD_CIRC_STATE_COMPLETE;
      } else {
        new_state = GUARD_CIRC_STATE_WAITING_FOR_BETTER_GUARD;
      }
      break;
  }

  if (! guard->is_primary) {
    if (last_time_on_internet + get_internet_likely_down_interval()
        < approx_time()) {
      mark_primary_guards_maybe_reachable(gs);
    }
  }

  log_info(LD_GUARD, "Recorded success for %s%sguard %s",
           guard->is_primary?"primary ":"",
           guard->confirmed_idx>=0?"confirmed ":"",
           entry_guard_describe(guard));

  return new_state;
}

/**
 * Helper: Return true iff <b>a</b> has higher priority than <b>b</b>.
 */
STATIC int
entry_guard_has_higher_priority(entry_guard_t *a, entry_guard_t *b)
{
  tor_assert(a && b);
  if (a == b)
    return 0;

  /* Confirmed is always better than unconfirmed; lower index better
     than higher */
  if (a->confirmed_idx < 0) {
    if (b->confirmed_idx >= 0)
      return 0;
  } else {
    if (b->confirmed_idx < 0)
      return 1;

    /* Lower confirmed_idx is better than higher. */
    return (a->confirmed_idx < b->confirmed_idx);
  }

  /* If we reach this point, both are unconfirmed. If one is pending, it
   * has higher priority. */
  if (a->is_pending) {
    if (! b->is_pending)
      return 1;

    /* Both are pending: earlier last_tried_connect wins. */
    return a->last_tried_to_connect < b->last_tried_to_connect;
  } else {
    if (b->is_pending)
      return 0;

    /* Neither is pending: priorities are equal. */
    return 0; // XXXX prop271 return a tristate instead?
  }
}

/** Release all storage held in <b>restriction</b> */
static void
entry_guard_restriction_free(entry_guard_restriction_t *rst)
{
  tor_free(rst);
}

/**
 * Release all storage held in <b>state</b>.
 */
void
circuit_guard_state_free(circuit_guard_state_t *state)
{
  if (!state)
    return;
  entry_guard_restriction_free(state->restrictions);
  entry_guard_handle_free(state->guard);
  tor_free(state);
}

/**
 * Pick a suitable entry guard for a circuit in, and place that guard
 * in *<b>chosen_node_out</b>. Set *<b>guard_state_out</b> to an opaque
 * state object that will record whether the circuit is ready to be used
 * or not. Return 0 on success; on failure, return -1.
 *
 * If a restriction is provided in <b>rst</b>, do not return any guards that
 * violate it, and remember that restriction in <b>guard_state_out</b> for
 * later use. (Takes ownership of the <b>rst</b> object.)
 */
int
entry_guard_pick_for_circuit(guard_selection_t *gs,
                             entry_guard_restriction_t *rst,
                             const node_t **chosen_node_out,
                             circuit_guard_state_t **guard_state_out)
{
  tor_assert(gs);
  tor_assert(chosen_node_out);
  tor_assert(guard_state_out);
  *chosen_node_out = NULL;
  *guard_state_out = NULL;

  unsigned state = 0;
  entry_guard_t *guard = select_entry_guard_for_circuit(gs, rst, &state);
  if (! guard)
    goto fail;
  if (BUG(state == 0))
    goto fail;
  const node_t *node = node_get_by_id(guard->identity);
  // XXXX prop271 check Ed ID.
  if (! node)
    goto fail;

  *chosen_node_out = node;
  *guard_state_out = tor_malloc_zero(sizeof(circuit_guard_state_t));
  (*guard_state_out)->guard = entry_guard_handle_new(guard);
  (*guard_state_out)->state = state;
  (*guard_state_out)->state_set_at = approx_time();
  (*guard_state_out)->restrictions = rst;

  return 0;
 fail:
  entry_guard_restriction_free(rst);
  return -1;
}

/**
 * Called by the circuit building module when a circuit has succeeded: informs
 * the guards code that the guard in *<b>guard_state_p</b> is working, and
 * advances the state of the guard module.  On a GUARD_USABLE_NEVER return
 * value, the circuit is broken and should not be used.  On a GUARD_USABLE_NOW
 * return value, the circuit is ready to use.  On a GUARD_MAYBE_USABLE_LATER
 * return value, the circuit should not be used until we find out whether
 * preferred guards will work for us.
 */
guard_usable_t
entry_guard_succeeded(circuit_guard_state_t **guard_state_p)
{
  if (get_options()->UseDeprecatedGuardAlgorithm)
    return GUARD_USABLE_NOW;

  if (BUG(*guard_state_p == NULL))
    return GUARD_USABLE_NEVER;

  entry_guard_t *guard = entry_guard_handle_get((*guard_state_p)->guard);
  if (! guard || BUG(guard->in_selection == NULL))
    return GUARD_USABLE_NEVER;

  unsigned newstate =
    entry_guards_note_guard_success(guard->in_selection, guard,
                                    (*guard_state_p)->state);

  (*guard_state_p)->state = newstate;
  (*guard_state_p)->state_set_at = approx_time();

  if (newstate == GUARD_CIRC_STATE_COMPLETE) {
    return GUARD_USABLE_NOW;
  } else {
    return GUARD_MAYBE_USABLE_LATER;
  }
}

/** Cancel the selection of *<b>guard_state_p</b> without declaring
 * success or failure. It is safe to call this function if success or
 * failure _has_ already been declared. */
void
entry_guard_cancel(circuit_guard_state_t **guard_state_p)
{
  if (get_options()->UseDeprecatedGuardAlgorithm)
    return;
  if (BUG(*guard_state_p == NULL))
    return;
  entry_guard_t *guard = entry_guard_handle_get((*guard_state_p)->guard);
  if (! guard)
    return;

  /* XXXX prop271 -- last_tried_to_connect_at will be erroneous here, but this
   * function will only get called in "bug" cases anyway. */
  guard->is_pending = 0;
  circuit_guard_state_free(*guard_state_p);
  *guard_state_p = NULL;
}

/**
 * Called by the circuit building module when a circuit has succeeded:
 * informs the guards code that the guard in *<b>guard_state_p</b> is
 * not working, and advances the state of the guard module.
 */
void
entry_guard_failed(circuit_guard_state_t **guard_state_p)
{
  if (get_options()->UseDeprecatedGuardAlgorithm)
    return;

  if (BUG(*guard_state_p == NULL))
    return;

  entry_guard_t *guard = entry_guard_handle_get((*guard_state_p)->guard);
  if (! guard || BUG(guard->in_selection == NULL))
    return;

  entry_guards_note_guard_failure(guard->in_selection, guard);

  (*guard_state_p)->state = GUARD_CIRC_STATE_DEAD;
  (*guard_state_p)->state_set_at = approx_time();
}

/**
 * Run the entry_guard_failed() function on every circuit that is
 * pending on <b>chan</b>.
 */
void
entry_guard_chan_failed(channel_t *chan)
{
  if (!chan)
    return;
  if (get_options()->UseDeprecatedGuardAlgorithm)
    return;

  smartlist_t *pending = smartlist_new();
  circuit_get_all_pending_on_channel(pending, chan);
  SMARTLIST_FOREACH_BEGIN(pending, circuit_t *, circ) {
    if (!CIRCUIT_IS_ORIGIN(circ))
      continue;

    origin_circuit_t *origin_circ = TO_ORIGIN_CIRCUIT(circ);
    entry_guard_failed(&origin_circ->guard_state);
  } SMARTLIST_FOREACH_END(circ);
  smartlist_free(pending);
}

/**
 * Return true iff every primary guard in <b>gs</b> is believed to
 * be unreachable.
 */
STATIC int
entry_guards_all_primary_guards_are_down(guard_selection_t *gs)
{
  tor_assert(gs);
  if (!gs->primary_guards_up_to_date)
    entry_guards_update_primary(gs);
  SMARTLIST_FOREACH_BEGIN(gs->primary_entry_guards, entry_guard_t *, guard) {
    entry_guard_consider_retry(guard);
    if (guard->is_reachable != GUARD_REACHABLE_NO)
      return 0;
  } SMARTLIST_FOREACH_END(guard);
  return 1;
}

/** Wrapper for entry_guard_has_higher_priority that compares the
 * guard-priorities of a pair of circuits. Return 1 if <b>a</b> has higher
 * priority than <b>b</b>.
 *
 * If a restriction is provided in <b>rst</b>, then do not consider
 * <b>a</b> to have higher priority if it violates the restriction.
 */
static int
circ_state_has_higher_priority(origin_circuit_t *a,
                               const entry_guard_restriction_t *rst,
                               origin_circuit_t *b)
{
  circuit_guard_state_t *state_a = origin_circuit_get_guard_state(a);
  circuit_guard_state_t *state_b = origin_circuit_get_guard_state(b);

  tor_assert(state_a);
  tor_assert(state_b);

  entry_guard_t *guard_a = entry_guard_handle_get(state_a->guard);
  entry_guard_t *guard_b = entry_guard_handle_get(state_b->guard);

  if (! guard_a) {
    /* Unknown guard -- never higher priority. */
    return 0;
  } else if (! guard_b) {
    /* Known guard -- higher priority than any unknown guard. */
    return 1;
  } else  if (! entry_guard_obeys_restriction(guard_a, rst)) {
    /* Restriction violated; guard_a cannot have higher priority. */
    return 0;
  } else {
    /* Both known -- compare.*/
    return entry_guard_has_higher_priority(guard_a, guard_b);
  }
}

/**
 * Look at all of the origin_circuit_t * objects in <b>all_circuits_in</b>,
 * and see if any of them that were previously not ready to use for
 * guard-related reasons are now ready to use. Place those circuits
 * in <b>newly_complete_out</b>, and mark them COMPLETE.
 *
 * Return 1 if we upgraded any circuits, and 0 otherwise.
 */
int
entry_guards_upgrade_waiting_circuits(guard_selection_t *gs,
                                      const smartlist_t *all_circuits_in,
                                      smartlist_t *newly_complete_out)
{
  tor_assert(gs);
  tor_assert(all_circuits_in);
  tor_assert(newly_complete_out);

  if (! entry_guards_all_primary_guards_are_down(gs)) {
    /* We only upgrade a waiting circuit if the primary guards are all
     * down. */
    log_debug(LD_GUARD, "Considered upgrading guard-stalled circuits, "
              "but not all primary guards were definitely down.");
    return 0;
  }

  int n_waiting = 0;
  int n_complete = 0;
  int n_complete_blocking = 0;
  origin_circuit_t *best_waiting_circuit = NULL;
  smartlist_t *all_circuits = smartlist_new();
  SMARTLIST_FOREACH_BEGIN(all_circuits_in, origin_circuit_t *, circ) {
    // We filter out circuits that aren't ours, or which we can't
    // reason about.
    circuit_guard_state_t *state = origin_circuit_get_guard_state(circ);
    if (state == NULL)
      continue;
    entry_guard_t *guard = entry_guard_handle_get(state->guard);
    if (!guard || guard->in_selection != gs)
      continue;

    smartlist_add(all_circuits, circ);
  } SMARTLIST_FOREACH_END(circ);

  SMARTLIST_FOREACH_BEGIN(all_circuits, origin_circuit_t *, circ) {
    circuit_guard_state_t *state = origin_circuit_get_guard_state(circ);
    if BUG((state == NULL))
      continue;

    if (state->state == GUARD_CIRC_STATE_WAITING_FOR_BETTER_GUARD) {
      ++n_waiting;
      if (! best_waiting_circuit ||
          circ_state_has_higher_priority(circ, NULL, best_waiting_circuit)) {
        best_waiting_circuit = circ;
      }
    }
  } SMARTLIST_FOREACH_END(circ);

  if (! best_waiting_circuit) {
    log_debug(LD_GUARD, "Considered upgrading guard-stalled circuits, "
              "but didn't find any.");
    goto no_change;
  }

  /* We'll need to keep track of what restrictions were used when picking this
   * circuit, so that we don't allow any circuit without those restrictions to
   * block it. */
  const entry_guard_restriction_t *rst_on_best_waiting =
    origin_circuit_get_guard_state(best_waiting_circuit)->restrictions;

  /* First look at the complete circuits: Do any block this circuit? */
  SMARTLIST_FOREACH_BEGIN(all_circuits, origin_circuit_t *, circ) {
    circuit_guard_state_t *state = origin_circuit_get_guard_state(circ);
    if BUG((state == NULL))
      continue;
    if (state->state != GUARD_CIRC_STATE_COMPLETE)
      continue;
    ++n_complete;
    if (circ_state_has_higher_priority(circ, rst_on_best_waiting,
                                       best_waiting_circuit))
      ++n_complete_blocking;
  } SMARTLIST_FOREACH_END(circ);

  if (n_complete_blocking) {
    /* "If any circuit is <complete>, then do not use any
       <waiting_for_better_guard> or <usable_if_no_better_guard> circuits
       circuits whose guards have lower priority." */
    log_debug(LD_GUARD, "Considered upgrading guard-stalled circuits: found "
              "%d complete and %d guard-stalled. At least one complete "
              "circuit had higher priority, so not upgrading.",
              n_complete, n_waiting);
    goto no_change;
  }

  /* "If any circuit is <waiting_for_better_guard>, and every currently
     {is_pending} circuit whose guard has higher priority has been in
     state <usable_if_no_better_guard> for at least
     {NONPRIMARY_GUARD_CONNECT_TIMEOUT} seconds, and all primary guards
     have reachable status of <no>, then call that circuit <complete>."

     XXXX --- prop271 deviation. there's no such thing in the spec as
     an {is_pending circuit}; fix the spec.
  */
  int n_blockers_found = 0;
  const time_t state_set_at_cutoff =
    approx_time() - get_nonprimary_guard_connect_timeout();
  SMARTLIST_FOREACH_BEGIN(all_circuits, origin_circuit_t *, circ) {
    circuit_guard_state_t *state = origin_circuit_get_guard_state(circ);
    if (BUG(state == NULL))
      continue;
    if (state->state != GUARD_CIRC_STATE_USABLE_IF_NO_BETTER_GUARD)
      continue;
    if (state->state_set_at <= state_set_at_cutoff)
      continue;
    if (circ_state_has_higher_priority(circ, rst_on_best_waiting,
                                       best_waiting_circuit))
      ++n_blockers_found;
  } SMARTLIST_FOREACH_END(circ);

  if (n_blockers_found) {
    log_debug(LD_GUARD, "Considered upgrading guard-stalled circuits: found "
              "%d guard-stalled, but %d pending circuit(s) had higher "
              "guard priority, so not upgrading.",
              n_waiting, n_blockers_found);
    goto no_change;
  }

  /* Okay. We have a best waiting circuit, and we aren't waiting for
     anything better.  Add all circuits with that priority to the
     list, and call them COMPLETE. */
  int n_succeeded = 0;
  SMARTLIST_FOREACH_BEGIN(all_circuits, origin_circuit_t *, circ) {
    circuit_guard_state_t *state = origin_circuit_get_guard_state(circ);
    if (BUG(state == NULL))
      continue;
    if (circ != best_waiting_circuit && rst_on_best_waiting) {
      /* Can't upgrade other circ with same priority as best; might
         be blocked. */
      continue;
    }
    if (state->state != GUARD_CIRC_STATE_WAITING_FOR_BETTER_GUARD)
      continue;
    if (circ_state_has_higher_priority(best_waiting_circuit, NULL, circ))
      continue;

    state->state = GUARD_CIRC_STATE_COMPLETE;
    state->state_set_at = approx_time();
    smartlist_add(newly_complete_out, circ);
    ++n_succeeded;
  } SMARTLIST_FOREACH_END(circ);

  log_info(LD_GUARD, "Considered upgrading guard-stalled circuits: found "
           "%d guard-stalled, %d complete. %d of the guard-stalled "
           "circuit(s) had high enough priority to upgrade.",
           n_waiting, n_complete, n_succeeded);

  tor_assert_nonfatal(n_succeeded >= 1);
  smartlist_free(all_circuits);
  return 1;

 no_change:
  smartlist_free(all_circuits);
  return 0;
}

/**
 * Return true iff the circuit whose state is <b>guard_state</b> should
 * expire.
 */
int
entry_guard_state_should_expire(circuit_guard_state_t *guard_state)
{
  if (guard_state == NULL)
    return 0;
  const time_t expire_if_waiting_since =
    approx_time() - get_nonprimary_guard_idle_timeout();
  return (guard_state->state == GUARD_CIRC_STATE_WAITING_FOR_BETTER_GUARD
          && guard_state->state_set_at < expire_if_waiting_since);
}

/**
 * Update all derived pieces of the guard selection state in <b>gs</b>.
 * Return true iff we should stop using all previously generated circuits.
 */
int
entry_guards_update_all(guard_selection_t *gs)
{
  sampled_guards_update_from_consensus(gs);
  entry_guards_update_filtered_sets(gs);
  entry_guards_update_confirmed(gs);
  entry_guards_update_primary(gs);
  return 0;
}

/**
 * Return a newly allocated string for encoding the persistent parts of
 * <b>guard</b> to the state file.
 */
STATIC char *
entry_guard_encode_for_state(entry_guard_t *guard)
{
  /*
   * The meta-format we use is K=V K=V K=V... where K can be any
   * characters excepts space and =, and V can be any characters except
   * space.  The order of entries is not allowed to matter.
   * Unrecognized K=V entries are persisted; recognized but erroneous
   * entries are corrected.
   */

  smartlist_t *result = smartlist_new();
  char tbuf[ISO_TIME_LEN+1];

  tor_assert(guard);

  smartlist_add_asprintf(result, "in=%s", guard->selection_name);
  smartlist_add_asprintf(result, "rsa_id=%s",
                         hex_str(guard->identity, DIGEST_LEN));
  if (guard->bridge_addr) {
    smartlist_add_asprintf(result, "bridge_addr=%s:%d",
                           fmt_and_decorate_addr(&guard->bridge_addr->addr),
                           guard->bridge_addr->port);
  }
  if (strlen(guard->nickname) && is_legal_nickname(guard->nickname)) {
    smartlist_add_asprintf(result, "nickname=%s", guard->nickname);
  }

  format_iso_time_nospace(tbuf, guard->sampled_on_date);
  smartlist_add_asprintf(result, "sampled_on=%s", tbuf);

  if (guard->sampled_by_version) {
    smartlist_add_asprintf(result, "sampled_by=%s",
                           guard->sampled_by_version);
  }

  if (guard->unlisted_since_date > 0) {
    format_iso_time_nospace(tbuf, guard->unlisted_since_date);
    smartlist_add_asprintf(result, "unlisted_since=%s", tbuf);
  }

  smartlist_add_asprintf(result, "listed=%d",
                         (int)guard->currently_listed);

  if (guard->confirmed_idx >= 0) {
    format_iso_time_nospace(tbuf, guard->confirmed_on_date);
    smartlist_add_asprintf(result, "confirmed_on=%s", tbuf);

    smartlist_add_asprintf(result, "confirmed_idx=%d", guard->confirmed_idx);
  }

  const double EPSILON = 1.0e-6;

  /* Make a copy of the pathbias object, since we will want to update
     some of them */
  guard_pathbias_t *pb = tor_memdup(&guard->pb, sizeof(*pb));
  pb->use_successes = pathbias_get_use_success_count(guard);
  pb->successful_circuits_closed = pathbias_get_close_success_count(guard);

  #define PB_FIELD(field) do {                                          \
      if (pb->field >= EPSILON) {                                       \
        smartlist_add_asprintf(result, "pb_" #field "=%f", pb->field);  \
      }                                                                 \
    } while (0)
  PB_FIELD(use_attempts);
  PB_FIELD(use_successes);
  PB_FIELD(circ_attempts);
  PB_FIELD(circ_successes);
  PB_FIELD(successful_circuits_closed);
  PB_FIELD(collapsed_circuits);
  PB_FIELD(unusable_circuits);
  PB_FIELD(timeouts);
  tor_free(pb);
#undef PB_FIELD

  if (guard->extra_state_fields)
    smartlist_add_strdup(result, guard->extra_state_fields);

  char *joined = smartlist_join_strings(result, " ", 0, NULL);
  SMARTLIST_FOREACH(result, char *, cp, tor_free(cp));
  smartlist_free(result);

  return joined;
}

/**
 * Given a string generated by entry_guard_encode_for_state(), parse it
 * (if possible) and return an entry_guard_t object for it.  Return NULL
 * on complete failure.
 */
STATIC entry_guard_t *
entry_guard_parse_from_state(const char *s)
{
  /* Unrecognized entries get put in here. */
  smartlist_t *extra = smartlist_new();

  /* These fields get parsed from the string. */
  char *in = NULL;
  char *rsa_id = NULL;
  char *nickname = NULL;
  char *sampled_on = NULL;
  char *sampled_by = NULL;
  char *unlisted_since = NULL;
  char *listed  = NULL;
  char *confirmed_on = NULL;
  char *confirmed_idx = NULL;
  char *bridge_addr = NULL;

  // pathbias
  char *pb_use_attempts = NULL;
  char *pb_use_successes = NULL;
  char *pb_circ_attempts = NULL;
  char *pb_circ_successes = NULL;
  char *pb_successful_circuits_closed = NULL;
  char *pb_collapsed_circuits = NULL;
  char *pb_unusable_circuits = NULL;
  char *pb_timeouts = NULL;

  /* Split up the entries.  Put the ones we know about in strings and the
   * rest in "extra". */
  {
    smartlist_t *entries = smartlist_new();

    strmap_t *vals = strmap_new(); // Maps keyword to location
#define FIELD(f) \
    strmap_set(vals, #f, &f);
    FIELD(in);
    FIELD(rsa_id);
    FIELD(nickname);
    FIELD(sampled_on);
    FIELD(sampled_by);
    FIELD(unlisted_since);
    FIELD(listed);
    FIELD(confirmed_on);
    FIELD(confirmed_idx);
    FIELD(bridge_addr);
    FIELD(pb_use_attempts);
    FIELD(pb_use_successes);
    FIELD(pb_circ_attempts);
    FIELD(pb_circ_successes);
    FIELD(pb_successful_circuits_closed);
    FIELD(pb_collapsed_circuits);
    FIELD(pb_unusable_circuits);
    FIELD(pb_timeouts);
#undef FIELD

    smartlist_split_string(entries, s, " ",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);

    SMARTLIST_FOREACH_BEGIN(entries, char *, entry) {
      const char *eq = strchr(entry, '=');
      if (!eq) {
        smartlist_add(extra, entry);
        continue;
      }
      char *key = tor_strndup(entry, eq-entry);
      char **target = strmap_get(vals, key);
      if (target == NULL || *target != NULL) {
        /* unrecognized or already set */
        smartlist_add(extra, entry);
        tor_free(key);
        continue;
      }

      *target = tor_strdup(eq+1);
      tor_free(key);
      tor_free(entry);
    } SMARTLIST_FOREACH_END(entry);

    smartlist_free(entries);
    strmap_free(vals, NULL);
  }

  entry_guard_t *guard = tor_malloc_zero(sizeof(entry_guard_t));
  guard->is_persistent = 1;

  if (in == NULL) {
    log_warn(LD_CIRC, "Guard missing 'in' field");
    goto err;
  }

  guard->selection_name = in;
  in = NULL;

  if (rsa_id == NULL) {
    log_warn(LD_CIRC, "Guard missing RSA ID field");
    goto err;
  }

  /* Process the identity and nickname. */
  if (base16_decode(guard->identity, sizeof(guard->identity),
                    rsa_id, strlen(rsa_id)) != DIGEST_LEN) {
    log_warn(LD_CIRC, "Unable to decode guard identity %s", escaped(rsa_id));
    goto err;
  }

  if (nickname) {
    strlcpy(guard->nickname, nickname, sizeof(guard->nickname));
  } else {
    guard->nickname[0]='$';
    base16_encode(guard->nickname+1, sizeof(guard->nickname)-1,
                  guard->identity, DIGEST_LEN);
  }

  if (bridge_addr) {
    tor_addr_port_t res;
    memset(&res, 0, sizeof(res));
    int r = tor_addr_port_parse(LOG_WARN, bridge_addr,
                                &res.addr, &res.port, -1);
    if (r == 0)
      guard->bridge_addr = tor_memdup(&res, sizeof(res));
    /* On error, we already warned. */
  }

  /* Process the various time fields. */

#define HANDLE_TIME(field) do {                                 \
    if (field) {                                                \
      int r = parse_iso_time_nospace(field, &field ## _time);   \
      if (r < 0) {                                              \
        log_warn(LD_CIRC, "Unable to parse %s %s from guard",   \
                 #field, escaped(field));                       \
        field##_time = -1;                                      \
      }                                                         \
    }                                                           \
  } while (0)

  time_t sampled_on_time = 0;
  time_t unlisted_since_time = 0;
  time_t confirmed_on_time = 0;

  HANDLE_TIME(sampled_on);
  HANDLE_TIME(unlisted_since);
  HANDLE_TIME(confirmed_on);

  if (sampled_on_time <= 0)
    sampled_on_time = approx_time();
  if (unlisted_since_time < 0)
    unlisted_since_time = 0;
  if (confirmed_on_time < 0)
    confirmed_on_time = 0;

  #undef HANDLE_TIME

  guard->sampled_on_date = sampled_on_time;
  guard->unlisted_since_date = unlisted_since_time;
  guard->confirmed_on_date = confirmed_on_time;

  /* Take sampled_by_version verbatim. */
  guard->sampled_by_version = sampled_by;
  sampled_by = NULL; /* prevent free */
  // XXXX -- prop271 spec deviation -- we do not require sampled_by_version

  /* Listed is a boolean */
  if (listed && strcmp(listed, "0"))
    guard->currently_listed = 1;

  /* The index is a nonnegative integer. */
  guard->confirmed_idx = -1;
  if (confirmed_idx) {
    int ok=1;
    long idx = tor_parse_long(confirmed_idx, 10, 0, INT_MAX, &ok, NULL);
    if (! ok) {
      log_warn(LD_GUARD, "Guard has invalid confirmed_idx %s",
               escaped(confirmed_idx));
    } else {
      guard->confirmed_idx = (int)idx;
    }
  }

  /* Anything we didn't recognize gets crammed together */
  if (smartlist_len(extra) > 0) {
    guard->extra_state_fields = smartlist_join_strings(extra, " ", 0, NULL);
  }

  /* initialize non-persistent fields */
  guard->is_reachable = GUARD_REACHABLE_MAYBE;

#define PB_FIELD(field)                                                 \
  do {                                                                  \
    if (pb_ ## field) {                                                 \
      int ok = 1;                                                       \
      double r = tor_parse_double(pb_ ## field, 0.0, 1e9, &ok, NULL);   \
      if (! ok) {                                                       \
        log_warn(LD_CIRC, "Guard has invalid pb_%s %s",                 \
                 #field, pb_ ## field);                                 \
      } else {                                                          \
        guard->pb.field = r;                                            \
      }                                                                 \
    }                                                                   \
  } while (0)
  PB_FIELD(use_attempts);
  PB_FIELD(use_successes);
  PB_FIELD(circ_attempts);
  PB_FIELD(circ_successes);
  PB_FIELD(successful_circuits_closed);
  PB_FIELD(collapsed_circuits);
  PB_FIELD(unusable_circuits);
  PB_FIELD(timeouts);
#undef PB_FIELD

  pathbias_check_use_success_count(guard);
  pathbias_check_close_success_count(guard);

  /* We update everything on this guard later, after we've parsed
   * everything.  */

  goto done;

 err:
  // only consider it an error if the guard state was totally unparseable.
  entry_guard_free(guard);
  guard = NULL;

 done:
  tor_free(in);
  tor_free(rsa_id);
  tor_free(nickname);
  tor_free(sampled_on);
  tor_free(sampled_by);
  tor_free(unlisted_since);
  tor_free(listed);
  tor_free(confirmed_on);
  tor_free(confirmed_idx);
  tor_free(bridge_addr);
  tor_free(pb_use_attempts);
  tor_free(pb_use_successes);
  tor_free(pb_circ_attempts);
  tor_free(pb_circ_successes);
  tor_free(pb_successful_circuits_closed);
  tor_free(pb_collapsed_circuits);
  tor_free(pb_unusable_circuits);
  tor_free(pb_timeouts);

  SMARTLIST_FOREACH(extra, char *, cp, tor_free(cp));
  smartlist_free(extra);

  return guard;
}

/**
 * Replace the Guards entries in <b>state</b> with a list of all our
 * non-legacy sampled guards.
 */
static void
entry_guards_update_guards_in_state(or_state_t *state)
{
  if (!guard_contexts)
    return;
  config_line_t *lines = NULL;
  config_line_t **nextline = &lines;

  SMARTLIST_FOREACH_BEGIN(guard_contexts, guard_selection_t *, gs) {
    if (!strcmp(gs->name, "legacy"))
      continue; /* This is encoded differently. */
    SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
      if (guard->is_persistent == 0)
        continue;
      *nextline = tor_malloc_zero(sizeof(config_line_t));
      (*nextline)->key = tor_strdup("Guard");
      (*nextline)->value = entry_guard_encode_for_state(guard);
      nextline = &(*nextline)->next;
    } SMARTLIST_FOREACH_END(guard);
  } SMARTLIST_FOREACH_END(gs);

  config_free_lines(state->Guard);
  state->Guard = lines;
}

/**
 * Replace our non-legacy sampled guards from the Guards entries in
 * <b>state</b>. Return 0 on success, -1 on failure. (If <b>set</b> is
 * true, replace nothing -- only check whether replacing would work.)
 */
static int
entry_guards_load_guards_from_state(or_state_t *state, int set)
{
  const config_line_t *line = state->Guard;
  int n_errors = 0;

  if (!guard_contexts)
    guard_contexts = smartlist_new();

  /* Wipe all our existing guard info. (we shouldn't have any, but
   * let's be safe.) */
  if (set) {
    SMARTLIST_FOREACH_BEGIN(guard_contexts, guard_selection_t *, gs) {
      if (!strcmp(gs->name, "legacy"))
        continue;
      guard_selection_free(gs);
      if (curr_guard_context == gs)
        curr_guard_context = NULL;
      SMARTLIST_DEL_CURRENT(guard_contexts, gs);
    } SMARTLIST_FOREACH_END(gs);
  }

  for ( ; line != NULL; line = line->next) {
    entry_guard_t *guard = entry_guard_parse_from_state(line->value);
    if (guard == NULL) {
      ++n_errors;
      continue;
    }
    tor_assert(guard->selection_name);
    if (!strcmp(guard->selection_name, "legacy")) {
      ++n_errors;
      entry_guard_free(guard);
      continue;
    }

    if (set) {
      guard_selection_t *gs;
      gs = get_guard_selection_by_name(guard->selection_name,
                                       GS_TYPE_INFER, 1);
      tor_assert(gs);
      smartlist_add(gs->sampled_entry_guards, guard);
      guard->in_selection = gs;
    } else {
      entry_guard_free(guard);
    }
  }

  if (set) {
    SMARTLIST_FOREACH_BEGIN(guard_contexts, guard_selection_t *, gs) {
      if (!strcmp(gs->name, "legacy"))
        continue;
      entry_guards_update_all(gs);
    } SMARTLIST_FOREACH_END(gs);
  }
  return n_errors ? -1 : 0;
}

/* XXXXX ----------------------------------------------- */
/* XXXXX prop271 ----- end of new-for-prop271 code ----- */
/* XXXXX ----------------------------------------------- */

#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
/**
 * @name Constants for old (pre-prop271) guard selection algorithm.
 */

/**@{*/

/* Default number of entry guards in the case where the NumEntryGuards
 * consensus parameter is not set */
#define DEFAULT_N_GUARDS 1
/* Minimum and maximum number of entry guards (in case the NumEntryGuards
 * consensus parameter is set). */
#define MIN_N_GUARDS 1
#define MAX_N_GUARDS 10
/** Largest amount that we'll backdate chosen_on_date */
#define CHOSEN_ON_DATE_SLOP (30*86400)
/** How long (in seconds) do we allow an entry guard to be nonfunctional,
 * unlisted, excluded, or otherwise nonusable before we give up on it? */
#define ENTRY_GUARD_REMOVE_AFTER (30*24*60*60)
/**}@*/

/**
 * @name Networkstatus parameters for old (pre-prop271) guard selection
 */
/**@}*/
/** Choose how many entry guards or directory guards we'll use. If
 * <b>for_directory</b> is true, we return how many directory guards to
 * use; else we return how many entry guards to use. */
STATIC int
decide_num_guards(const or_options_t *options, int for_directory)
{
  if (for_directory) {
    int answer;
    if (options->NumDirectoryGuards != 0)
      return options->NumDirectoryGuards;
    answer = networkstatus_get_param(NULL, "NumDirectoryGuards", 0, 0, 10);
    if (answer) /* non-zero means use the consensus value */
      return answer;
  }

  if (options->NumEntryGuards)
    return options->NumEntryGuards;

  /* Use the value from the consensus, or 3 if no guidance. */
  return networkstatus_get_param(NULL, "NumEntryGuards", DEFAULT_N_GUARDS,
                                 MIN_N_GUARDS, MAX_N_GUARDS);
}

/** Check whether the entry guard <b>e</b> is usable, given the directory
 * authorities' opinion about the router (stored in <b>ri</b>) and the user's
 * configuration (in <b>options</b>). Set <b>e</b>->bad_since
 * accordingly. Return true iff the entry guard's status changes.
 *
 * If it's not usable, set *<b>reason</b> to a static string explaining why.
 */
static int
entry_guard_set_status(entry_guard_t *e, const node_t *node,
                       time_t now, const or_options_t *options,
                       const char **reason)
{
  char buf[HEX_DIGEST_LEN+1];
  int changed = 0;

  *reason = NULL;

  /* Do we want to mark this guard as bad? */
  if (!node)
    *reason = "unlisted";
  else if (!node->is_running)
    *reason = "down";
  else if (options->UseBridges && (!node->ri ||
                                   node->ri->purpose != ROUTER_PURPOSE_BRIDGE))
    *reason = "not a bridge";
  else if (options->UseBridges && !node_is_a_configured_bridge(node))
    *reason = "not a configured bridge";
  else if (!options->UseBridges && !node->is_possible_guard &&
           !routerset_contains_node(options->EntryNodes,node))
    *reason = "not recommended as a guard";
  else if (routerset_contains_node(options->ExcludeNodes, node))
    *reason = "excluded";
  /* We only care about OR connection connectivity for entry guards. */
  else if (!fascist_firewall_allows_node(node, FIREWALL_OR_CONNECTION, 0))
    *reason = "unreachable by config";
  else if (e->pb.path_bias_disabled)
    *reason = "path-biased";

  if (*reason && ! e->bad_since) {
    /* Router is newly bad. */
    base16_encode(buf, sizeof(buf), e->identity, DIGEST_LEN);
    log_info(LD_CIRC, "Entry guard %s (%s) is %s: marking as unusable.",
             e->nickname, buf, *reason);

    e->bad_since = now;
    control_event_guard(e->nickname, e->identity, "BAD");
    changed = 1;
  } else if (!*reason && e->bad_since) {
    /* There's nothing wrong with the router any more. */
    base16_encode(buf, sizeof(buf), e->identity, DIGEST_LEN);
    log_info(LD_CIRC, "Entry guard %s (%s) is no longer unusable: "
             "marking as ok.", e->nickname, buf);

    e->bad_since = 0;
    control_event_guard(e->nickname, e->identity, "GOOD");
    changed = 1;
  }

  if (node) {
    int is_dir = node_is_dir(node);
    if (options->UseBridges && node_is_a_configured_bridge(node))
      is_dir = 1;
    if (e->is_dir_cache != is_dir) {
      e->is_dir_cache = is_dir;
      changed = 1;
    }
  }

  return changed;
}

/** Return true iff enough time has passed since we last tried to connect
 * to the unreachable guard <b>e</b> that we're willing to try again. */
STATIC int
entry_is_time_to_retry(const entry_guard_t *e, time_t now)
{
  struct guard_retry_period_s {
    time_t period_duration;
    time_t interval_during_period;
  };

  struct guard_retry_period_s periods[] = {
     {    6*60*60,    60*60 }, /* For first 6 hrs., retry hourly; */
     { 3*24*60*60,  4*60*60 }, /* Then retry every 4 hrs. until the
                                  3-day mark; */
     { 7*24*60*60, 18*60*60 }, /* After 3 days, retry every 18 hours until
                                  1 week mark. */
     {   TIME_MAX, 36*60*60 }  /* After 1 week, retry every 36 hours. */
  };

  time_t ith_deadline_for_retry;
  time_t unreachable_for;
  unsigned i;

  if (e->last_attempted < e->unreachable_since)
    return 1;

  unreachable_for = now - e->unreachable_since;

  for (i = 0; i < ARRAY_LENGTH(periods); i++) {
    if (unreachable_for <= periods[i].period_duration) {
      ith_deadline_for_retry = e->last_attempted +
                               periods[i].interval_during_period;

      return (now > ith_deadline_for_retry);
    }
  }
  return 0;
}

/** Return the node corresponding to <b>e</b>, if <b>e</b> is
 * working well enough that we are willing to use it as an entry
 * right now. (Else return NULL.) In particular, it must be
 * - Listed as either up or never yet contacted;
 * - Present in the routerlist;
 * - Listed as 'stable' or 'fast' by the current dirserver consensus,
 *   if demanded by <b>need_uptime</b> or <b>need_capacity</b>
 *   (unless it's a configured EntryNode);
 * - Allowed by our current ReachableORAddresses config option; and
 * - Currently thought to be reachable by us (unless <b>assume_reachable</b>
 *   is true).
 *
 * If the answer is no, set *<b>msg</b> to an explanation of why.
 *
 * If need_descriptor is true, only return the node if we currently have
 * a descriptor (routerinfo or microdesc) for it.
 */
STATIC const node_t *
entry_is_live(const entry_guard_t *e, entry_is_live_flags_t flags,
              const char **msg)
{
  const node_t *node;
  const or_options_t *options = get_options();
  int need_uptime = (flags & ENTRY_NEED_UPTIME) != 0;
  int need_capacity = (flags & ENTRY_NEED_CAPACITY) != 0;
  const int assume_reachable = (flags & ENTRY_ASSUME_REACHABLE) != 0;
  const int need_descriptor = (flags & ENTRY_NEED_DESCRIPTOR) != 0;

  tor_assert(msg);

  if (e->pb.path_bias_disabled) {
    *msg = "path-biased";
    return NULL;
  }
  if (e->bad_since) {
    *msg = "bad";
    return NULL;
  }
  /* no good if it's unreachable, unless assume_unreachable or can_retry. */
  if (!assume_reachable && !e->can_retry &&
      e->unreachable_since && !entry_is_time_to_retry(e, time(NULL))) {
    *msg = "unreachable";
    return NULL;
  }
  node = node_get_by_id(e->identity);
  if (!node) {
    *msg = "no node info";
    return NULL;
  }
  if (need_descriptor && !node_has_descriptor(node)) {
    *msg = "no descriptor";
    return NULL;
  }
  if (get_options()->UseBridges) {
    if (node_get_purpose(node) != ROUTER_PURPOSE_BRIDGE) {
      *msg = "not a bridge";
      return NULL;
    }
    if (!node_is_a_configured_bridge(node)) {
      *msg = "not a configured bridge";
      return NULL;
    }
  } else { /* !get_options()->UseBridges */
    if (node_get_purpose(node) != ROUTER_PURPOSE_GENERAL) {
      *msg = "not general-purpose";
      return NULL;
    }
  }
  if (routerset_contains_node(options->EntryNodes, node)) {
    /* they asked for it, they get it */
    need_uptime = need_capacity = 0;
  }
  if (node_is_unreliable(node, need_uptime, need_capacity, 0)) {
    *msg = "not fast/stable";
    return NULL;
  }
  if (!fascist_firewall_allows_node(node, FIREWALL_OR_CONNECTION, 0)) {
    *msg = "unreachable by config";
    return NULL;
  }
  return node;
}

/** Return the number of entry guards that we think are usable, in the
 * context of the given guard_selection_t */
int
num_live_entry_guards_for_guard_selection(guard_selection_t *gs,
                                          int for_directory)
{
  int n = 0;
  const char *msg;

  tor_assert(gs != NULL);

  /* Set the entry node attributes we are interested in. */
  entry_is_live_flags_t entry_flags = ENTRY_NEED_CAPACITY;
  if (!for_directory) {
    entry_flags |= ENTRY_NEED_DESCRIPTOR;
  }

  if (!(gs->chosen_entry_guards)) {
    return 0;
  }

  SMARTLIST_FOREACH_BEGIN(gs->chosen_entry_guards, entry_guard_t *, entry) {
      if (for_directory && !entry->is_dir_cache)
        continue;
      if (entry_is_live(entry, entry_flags, &msg))
        ++n;
  } SMARTLIST_FOREACH_END(entry);
  return n;
}

/** Return the number of entry guards that we think are usable, for the
 * default guard selection */
int
num_live_entry_guards(int for_directory)
{
  return num_live_entry_guards_for_guard_selection(
      get_guard_selection_info(), for_directory);
}
#endif

/** If <b>digest</b> matches the identity of any node in the
 * entry_guards list for the provided guard selection state,
 return that node. Else return NULL. */
entry_guard_t *
entry_guard_get_by_id_digest_for_guard_selection(guard_selection_t *gs,
                                                 const char *digest)
{
  tor_assert(gs != NULL);

  SMARTLIST_FOREACH(gs->sampled_entry_guards, entry_guard_t *, entry,
                    if (tor_memeq(digest, entry->identity, DIGEST_LEN))
                      return entry;
                   );
#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
  SMARTLIST_FOREACH(gs->chosen_entry_guards, entry_guard_t *, entry,
                    if (tor_memeq(digest, entry->identity, DIGEST_LEN))
                      return entry;
                   );
#endif
  return NULL;
}

/** Return the node_t associated with a single entry_guard_t. May
 * return NULL if the guard is not currently in the consensus. */
const node_t *
entry_guard_find_node(const entry_guard_t *guard)
{
  tor_assert(guard);
  return node_get_by_id(guard->identity);
}

/** If <b>digest</b> matches the identity of any node in the
 * entry_guards list for the default guard selection state,
 return that node. Else return NULL. */
entry_guard_t *
entry_guard_get_by_id_digest(const char *digest)
{
  return entry_guard_get_by_id_digest_for_guard_selection(
      get_guard_selection_info(), digest);
}

#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
/** Dump a description of our list of entry guards in the given guard
 * selection context to the log at level <b>severity</b>. */
static void
log_entry_guards_for_guard_selection(guard_selection_t *gs, int severity)
{
  smartlist_t *elements = smartlist_new();
  char *s;

  /*
   * TODO this should probably log more info about prop-271 state too
   * when it's implemented.
   */

  tor_assert(gs != NULL);

  SMARTLIST_FOREACH_BEGIN(gs->chosen_entry_guards, entry_guard_t *, e)
    {
      const char *msg = NULL;
      if (entry_is_live(e, ENTRY_NEED_CAPACITY, &msg))
        smartlist_add_asprintf(elements, "%s [%s] (up %s)",
                     e->nickname,
                     hex_str(e->identity, DIGEST_LEN),
                     e->made_contact ? "made-contact" : "never-contacted");
      else
        smartlist_add_asprintf(elements, "%s [%s] (%s, %s)",
                     e->nickname,
                     hex_str(e->identity, DIGEST_LEN),
                     msg,
                     e->made_contact ? "made-contact" : "never-contacted");
    }
  SMARTLIST_FOREACH_END(e);

  s = smartlist_join_strings(elements, ",", 0, NULL);
  SMARTLIST_FOREACH(elements, char*, cp, tor_free(cp));
  smartlist_free(elements);
  log_fn(severity,LD_CIRC,"%s",s);
  tor_free(s);
}

/** Called when one or more guards that we would previously have used for some
 * purpose are no longer in use because a higher-priority guard has become
 * usable again. */
static void
control_event_guard_deferred(void)
{
  /* XXXX We don't actually have a good way to figure out _how many_ entries
   * are live for some purpose.  We need an entry_is_even_slightly_live()
   * function for this to work right.  NumEntryGuards isn't reliable: if we
   * need guards with weird properties, we can have more than that number
   * live.
   **/
#if 0
  int n = 0;
  const char *msg;
  const or_options_t *options = get_options();
  if (!entry_guards)
    return;
  SMARTLIST_FOREACH(entry_guards, entry_guard_t *, entry,
    {
      if (entry_is_live(entry, 0, 1, 0, &msg)) {
        if (n++ == options->NumEntryGuards) {
          control_event_guard(entry->nickname, entry->identity, "DEFERRED");
          return;
        }
      }
    });
#endif
}

/** Add a new (preferably stable and fast) router to our chosen_entry_guards
 * list for the supplied guard selection. Return a pointer to the router if
 * we succeed, or NULL if we can't find any more suitable entries.
 *
 * If <b>chosen</b> is defined, use that one, and if it's not
 * already in our entry_guards list, put it at the *beginning*.
 * Else, put the one we pick at the end of the list. */
STATIC const node_t *
add_an_entry_guard(guard_selection_t *gs,
                   const node_t *chosen, int reset_status, int prepend,
                   int for_discovery, int for_directory)
{
  const node_t *node;
  entry_guard_t *entry;

  tor_assert(gs != NULL);
  tor_assert(gs->chosen_entry_guards != NULL);

  if (chosen) {
    node = chosen;
    entry = entry_guard_get_by_id_digest_for_guard_selection(gs,
        node->identity);
    if (entry) {
      if (reset_status) {
        entry->bad_since = 0;
        entry->can_retry = 1;
      }
      entry->is_dir_cache = node_is_dir(node);
      if (get_options()->UseBridges && node_is_a_configured_bridge(node))
        entry->is_dir_cache = 1;

      return NULL;
    }
  } else if (!for_directory) {
    node = choose_good_entry_server(CIRCUIT_PURPOSE_C_GENERAL, NULL, NULL);
    if (!node)
      return NULL;
  } else {
    const routerstatus_t *rs;
    rs = router_pick_directory_server(MICRODESC_DIRINFO|V3_DIRINFO,
                                      PDS_FOR_GUARD);
    if (!rs)
      return NULL;
    node = node_get_by_id(rs->identity_digest);
    if (!node)
      return NULL;
  }
  if (entry_guard_get_by_id_digest_for_guard_selection(gs, node->identity)
      != NULL) {
    log_info(LD_CIRC, "I was about to add a duplicate entry guard.");
    /* This can happen if we choose a guard, then the node goes away, then
     * comes back. */
    return NULL;
  }
  entry = tor_malloc_zero(sizeof(entry_guard_t));
  entry->is_persistent = 1;
  log_info(LD_CIRC, "Chose %s as new entry guard.",
           node_describe(node));
  strlcpy(entry->nickname, node_get_nickname(node), sizeof(entry->nickname));
  memcpy(entry->identity, node->identity, DIGEST_LEN);
  entry->is_dir_cache = node_is_dir(node);
  if (get_options()->UseBridges && node_is_a_configured_bridge(node))
    entry->is_dir_cache = 1;

  /* Choose expiry time smudged over the past month. The goal here
   * is to a) spread out when Tor clients rotate their guards, so they
   * don't all select them on the same day, and b) avoid leaving a
   * precise timestamp in the state file about when we first picked
   * this guard. For details, see the Jan 2010 or-dev thread. */
  time_t now = time(NULL);
  entry->chosen_on_date = crypto_rand_time_range(now - 3600*24*30, now);
  entry->chosen_by_version = tor_strdup(VERSION);

  /* Are we picking this guard because all of our current guards are
   * down so we need another one (for_discovery is 1), or because we
   * decided we need more variety in our guard list (for_discovery is 0)?
   *
   * Currently we hack this behavior into place by setting "made_contact"
   * for guards of the latter variety, so we'll be willing to use any of
   * them right off the bat.
   */
  if (!for_discovery)
    entry->made_contact = 1;

  if (prepend)
    smartlist_insert(gs->chosen_entry_guards, 0, entry);
  else
    smartlist_add(gs->chosen_entry_guards, entry);
  entry->in_selection = gs;

  control_event_guard(entry->nickname, entry->identity, "NEW");
  control_event_guard_deferred();
  log_entry_guards_for_guard_selection(gs, LOG_INFO);

  return node;
}

/** Entry point for bridges.c to add a bridge as guard.
 *
 * XXXX prop271 refactor, bridge.*/
void
add_bridge_as_entry_guard(guard_selection_t *gs,
                          const node_t *chosen)
{
  add_an_entry_guard(gs, chosen, 1, 1, 0, 0);
}

/**
 * Return the minimum lifetime of working entry guard, in seconds,
 * as given in the consensus networkstatus.  (Plus CHOSEN_ON_DATE_SLOP,
 * so that we can do the chosen_on_date randomization while achieving the
 * desired minimum lifetime.)
 */
static int32_t
guards_get_lifetime(void)
{
  const or_options_t *options = get_options();
#define DFLT_GUARD_LIFETIME (86400 * 60)   /* Two months. */
#define MIN_GUARD_LIFETIME  (86400 * 30)   /* One months. */
#define MAX_GUARD_LIFETIME  (86400 * 1826) /* Five years. */

  if (options->GuardLifetime >= 1) {
    return CLAMP(MIN_GUARD_LIFETIME,
                 options->GuardLifetime,
                 MAX_GUARD_LIFETIME) + CHOSEN_ON_DATE_SLOP;
  }

  return networkstatus_get_param(NULL, "GuardLifetime",
                                 DFLT_GUARD_LIFETIME,
                                 MIN_GUARD_LIFETIME,
                                 MAX_GUARD_LIFETIME) + CHOSEN_ON_DATE_SLOP;
}

/** If the use of entry guards is configured, choose more entry guards
 * until we have enough in the list. */
static void
pick_entry_guards(guard_selection_t *gs,
                  const or_options_t *options,
                  int for_directory)
{
  int changed = 0;
  const int num_needed = decide_num_guards(options, for_directory);

  tor_assert(gs != NULL);
  tor_assert(gs->chosen_entry_guards != NULL);

  while (num_live_entry_guards_for_guard_selection(gs, for_directory)
         < num_needed) {
    if (!add_an_entry_guard(gs, NULL, 0, 0, 0, for_directory))
      break;
    changed = 1;
  }

  if (changed)
    entry_guards_changed_for_guard_selection(gs);
}
#endif

/** Release all storage held by <b>e</b>. */
STATIC void
entry_guard_free(entry_guard_t *e)
{
  if (!e)
    return;
  entry_guard_handles_clear(e);
#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
  tor_free(e->chosen_by_version);
#endif
  tor_free(e->sampled_by_version);
  tor_free(e->extra_state_fields);
  tor_free(e->selection_name);
  tor_free(e->bridge_addr);
  tor_free(e);
}

#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
/** Remove from a guard selection context any entry guard which was selected
 * by an unknown version of Tor, or which was selected by a version of Tor
 * that's known to select entry guards badly, or which was selected more 2
 * months ago. */
/* XXXX The "obsolete guards" and "chosen long ago guards" things should
 * probably be different functions. */
static int
remove_obsolete_entry_guards(guard_selection_t *gs, time_t now)
{
  int changed = 0, i;
  int32_t guard_lifetime = guards_get_lifetime();

  tor_assert(gs != NULL);
  if (!(gs->chosen_entry_guards)) goto done;

  for (i = 0; i < smartlist_len(gs->chosen_entry_guards); ++i) {
    entry_guard_t *entry = smartlist_get(gs->chosen_entry_guards, i);
    const char *ver = entry->chosen_by_version;
    const char *msg = NULL;
    tor_version_t v;
    int version_is_bad = 0, date_is_bad = 0;
    if (!ver) {
      msg = "does not say what version of Tor it was selected by";
      version_is_bad = 1;
    } else if (tor_version_parse(ver, &v)) {
      msg = "does not seem to be from any recognized version of Tor";
      version_is_bad = 1;
    }
    if (!version_is_bad && entry->chosen_on_date + guard_lifetime < now) {
      /* It's been too long since the date listed in our state file. */
      msg = "was selected several months ago";
      date_is_bad = 1;
    }

    if (version_is_bad || date_is_bad) { /* we need to drop it */
      char dbuf[HEX_DIGEST_LEN+1];
      tor_assert(msg);
      base16_encode(dbuf, sizeof(dbuf), entry->identity, DIGEST_LEN);
      log_fn(version_is_bad ? LOG_NOTICE : LOG_INFO, LD_CIRC,
             "Entry guard '%s' (%s) %s. (Version=%s.) Replacing it.",
             entry->nickname, dbuf, msg, ver?escaped(ver):"none");
      control_event_guard(entry->nickname, entry->identity, "DROPPED");
      entry_guard_free(entry);
      smartlist_del_keeporder(gs->chosen_entry_guards, i--);
      log_entry_guards_for_guard_selection(gs, LOG_INFO);
      changed = 1;
    }
  }

 done:
  return changed ? 1 : 0;
}

/** Remove all entry guards from this guard selection context that have
 * been down or unlisted for so long that we don't think they'll come up
 * again. Return 1 if we removed any, or 0 if we did nothing. */
static int
remove_dead_entry_guards(guard_selection_t *gs, time_t now)
{
  char dbuf[HEX_DIGEST_LEN+1];
  char tbuf[ISO_TIME_LEN+1];
  int i;
  int changed = 0;

  tor_assert(gs != NULL);
  if (!(gs->chosen_entry_guards)) goto done;

  for (i = 0; i < smartlist_len(gs->chosen_entry_guards); ) {
    entry_guard_t *entry = smartlist_get(gs->chosen_entry_guards, i);
    if (entry->bad_since &&
        ! entry->pb.path_bias_disabled &&
        entry->bad_since + ENTRY_GUARD_REMOVE_AFTER < now) {

      base16_encode(dbuf, sizeof(dbuf), entry->identity, DIGEST_LEN);
      format_local_iso_time(tbuf, entry->bad_since);
      log_info(LD_CIRC, "Entry guard '%s' (%s) has been down or unlisted "
               "since %s local time; removing.",
               entry->nickname, dbuf, tbuf);
      control_event_guard(entry->nickname, entry->identity, "DROPPED");
      entry_guard_free(entry);
      smartlist_del_keeporder(gs->chosen_entry_guards, i);
      log_entry_guards_for_guard_selection(gs, LOG_INFO);
      changed = 1;
    } else
      ++i;
  }

 done:
  return changed ? 1 : 0;
}

/** Remove all currently listed entry guards for a given guard selection
 * context */
void
remove_all_entry_guards_for_guard_selection(guard_selection_t *gs)
{
  char dbuf[HEX_DIGEST_LEN+1];

  tor_assert(gs != NULL);

  if (gs->chosen_entry_guards) {
    while (smartlist_len(gs->chosen_entry_guards)) {
      entry_guard_t *entry = smartlist_get(gs->chosen_entry_guards, 0);
      base16_encode(dbuf, sizeof(dbuf), entry->identity, DIGEST_LEN);
      log_info(LD_CIRC, "Entry guard '%s' (%s) has been dropped.",
               entry->nickname, dbuf);
      control_event_guard(entry->nickname, entry->identity, "DROPPED");
      entry_guard_free(entry);
      smartlist_del(gs->chosen_entry_guards, 0);
    }
  }

  log_entry_guards_for_guard_selection(gs, LOG_INFO);
  entry_guards_changed_for_guard_selection(gs);
}

/** Remove all currently listed entry guards. So new ones will be chosen. */
void
remove_all_entry_guards(void)
{
  // XXXX prop271 this function shouldn't exist, in the new order.
  remove_all_entry_guards_for_guard_selection(get_guard_selection_info());
}

/** A new directory or router-status has arrived; update the down/listed
 * status of the entry guards.
 *
 * An entry is 'down' if the directory lists it as nonrunning.
 * An entry is 'unlisted' if the directory doesn't include it.
 *
 * Don't call this on startup; only on a fresh download. Otherwise we'll
 * think that things are unlisted.
 */
void
entry_guards_compute_status_for_guard_selection(guard_selection_t *gs,
                                                const or_options_t *options,
                                                time_t now)
{
  int changed = 0;
  digestmap_t *reasons;

  if ((!gs) || !(gs->chosen_entry_guards))
    return;

  if (!get_options()->UseDeprecatedGuardAlgorithm)
    return;

  if (options->EntryNodes) /* reshuffle the entry guard list if needed */
    entry_nodes_should_be_added();

  reasons = digestmap_new();
  SMARTLIST_FOREACH_BEGIN(gs->chosen_entry_guards, entry_guard_t *, entry)
    {
      const node_t *r = node_get_by_id(entry->identity);
      const char *reason = NULL;
      if (entry_guard_set_status(entry, r, now, options, &reason))
        changed = 1;

      if (entry->bad_since)
        tor_assert(reason);
      if (reason)
        digestmap_set(reasons, entry->identity, (char*)reason);
    }
  SMARTLIST_FOREACH_END(entry);

  if (remove_dead_entry_guards(gs, now))
    changed = 1;
  if (remove_obsolete_entry_guards(gs, now))
    changed = 1;

  if (changed) {
    SMARTLIST_FOREACH_BEGIN(gs->chosen_entry_guards, entry_guard_t *,
                            entry) {
      const char *reason = digestmap_get(reasons, entry->identity);
      const char *live_msg = "";
      const node_t *r = entry_is_live(entry, ENTRY_NEED_CAPACITY, &live_msg);
      log_info(LD_CIRC, "Summary: Entry %s [%s] is %s, %s%s%s, and %s%s.",
               entry->nickname,
               hex_str(entry->identity, DIGEST_LEN),
               entry->unreachable_since ? "unreachable" : "reachable",
               entry->bad_since ? "unusable" : "usable",
               reason ? ", ": "",
               reason ? reason : "",
               r ? "live" : "not live / ",
               r ? "" : live_msg);
    } SMARTLIST_FOREACH_END(entry);
    log_info(LD_CIRC, "    (%d/%d entry guards are usable/new)",
             num_live_entry_guards_for_guard_selection(gs, 0),
             smartlist_len(gs->chosen_entry_guards));
    log_entry_guards_for_guard_selection(gs, LOG_INFO);
    entry_guards_changed_for_guard_selection(gs);
  }

  digestmap_free(reasons, NULL);
}

/** A new directory or router-status has arrived; update the down/listed
 * status of the entry guards.
 *
 * An entry is 'down' if the directory lists it as nonrunning.
 * An entry is 'unlisted' if the directory doesn't include it.
 *
 * Don't call this on startup; only on a fresh download. Otherwise we'll
 * think that things are unlisted.
 */
void
entry_guards_compute_status(const or_options_t *options, time_t now)
{
  entry_guards_compute_status_for_guard_selection(get_guard_selection_info(),
                                                  options, now);
}

/** Called when a connection to an OR with the identity digest <b>digest</b>
 * is established (<b>succeeded</b>==1) or has failed (<b>succeeded</b>==0).
 * If the OR is an entry, change that entry's up/down status.
 * Return 0 normally, or -1 if we want to tear down the new connection.
 *
 * If <b>mark_relay_status</b>, also call router_set_status() on this
 * relay.
 */
/* XXX We could change succeeded and mark_relay_status into 'int flags'.
 * Too many boolean arguments is a recipe for confusion.
 */
int
entry_guard_register_connect_status_for_guard_selection(
    guard_selection_t *gs, const char *digest, int succeeded,
    int mark_relay_status, time_t now)
{
  int changed = 0;
  int refuse_conn = 0;
  int first_contact = 0;
  entry_guard_t *entry = NULL;
  int idx = -1;
  char buf[HEX_DIGEST_LEN+1];

  if (!(gs) || !(gs->chosen_entry_guards)) {
    return 0;
  }

  if (! get_options()->UseDeprecatedGuardAlgorithm) {
    return 0;
  }

  SMARTLIST_FOREACH_BEGIN(gs->chosen_entry_guards, entry_guard_t *, e) {
    tor_assert(e);
    if (tor_memeq(e->identity, digest, DIGEST_LEN)) {
      entry = e;
      idx = e_sl_idx;
      break;
    }
  } SMARTLIST_FOREACH_END(e);

  if (!entry)
    return 0;

  base16_encode(buf, sizeof(buf), entry->identity, DIGEST_LEN);

  if (succeeded) {
    if (entry->unreachable_since) {
      log_info(LD_CIRC, "Entry guard '%s' (%s) is now reachable again. Good.",
               entry->nickname, buf);
      entry->can_retry = 0;
      entry->unreachable_since = 0;
      entry->last_attempted = now;
      control_event_guard(entry->nickname, entry->identity, "UP");
      changed = 1;
    }
    if (!entry->made_contact) {
      entry->made_contact = 1;
      first_contact = changed = 1;
    }
  } else { /* ! succeeded */
    if (!entry->made_contact) {
      /* We've never connected to this one. */
      log_info(LD_CIRC,
               "Connection to never-contacted entry guard '%s' (%s) failed. "
               "Removing from the list. %d/%d entry guards usable/new.",
               entry->nickname, buf,
               num_live_entry_guards_for_guard_selection(gs, 0) - 1,
               smartlist_len(gs->chosen_entry_guards)-1);
      control_event_guard(entry->nickname, entry->identity, "DROPPED");
      entry_guard_free(entry);
      smartlist_del_keeporder(gs->chosen_entry_guards, idx);
      log_entry_guards_for_guard_selection(gs, LOG_INFO);
      changed = 1;
    } else if (!entry->unreachable_since) {
      log_info(LD_CIRC, "Unable to connect to entry guard '%s' (%s). "
               "Marking as unreachable.", entry->nickname, buf);
      entry->unreachable_since = entry->last_attempted = now;
      control_event_guard(entry->nickname, entry->identity, "DOWN");
      changed = 1;
      entry->can_retry = 0; /* We gave it an early chance; no good. */
    } else {
      char tbuf[ISO_TIME_LEN+1];
      format_iso_time(tbuf, entry->unreachable_since);
      log_debug(LD_CIRC, "Failed to connect to unreachable entry guard "
                "'%s' (%s).  It has been unreachable since %s.",
                entry->nickname, buf, tbuf);
      entry->last_attempted = now;
      entry->can_retry = 0; /* We gave it an early chance; no good. */
    }
  }

  /* if the caller asked us to, also update the is_running flags for this
   * relay */
  if (mark_relay_status)
    router_set_status(digest, succeeded);

  if (first_contact) {
    /* We've just added a new long-term entry guard. Perhaps the network just
     * came back? We should give our earlier entries another try too,
     * and close this connection so we don't use it before we've given
     * the others a shot. */
    SMARTLIST_FOREACH_BEGIN(gs->chosen_entry_guards, entry_guard_t *, e) {
        if (e == entry)
          break;
        if (e->made_contact) {
          const char *msg;
          const node_t *r = entry_is_live(e,
                     ENTRY_NEED_CAPACITY | ENTRY_ASSUME_REACHABLE,
                     &msg);
          if (r && e->unreachable_since) {
            refuse_conn = 1;
            e->can_retry = 1;
          }
        }
    } SMARTLIST_FOREACH_END(e);
    if (refuse_conn) {
      log_info(LD_CIRC,
               "Connected to new entry guard '%s' (%s). Marking earlier "
               "entry guards up. %d/%d entry guards usable/new.",
               entry->nickname, buf,
               num_live_entry_guards_for_guard_selection(gs, 0),
               smartlist_len(gs->chosen_entry_guards));
      log_entry_guards_for_guard_selection(gs, LOG_INFO);
      changed = 1;
    }
  }

  if (changed)
    entry_guards_changed_for_guard_selection(gs);
  return refuse_conn ? -1 : 0;
}

/** Called when a connection to an OR with the identity digest <b>digest</b>
 * is established (<b>succeeded</b>==1) or has failed (<b>succeeded</b>==0).
 * If the OR is an entry, change that entry's up/down status in the default
 * guard selection context.
 * Return 0 normally, or -1 if we want to tear down the new connection.
 *
 * If <b>mark_relay_status</b>, also call router_set_status() on this
 * relay.
 */
int
entry_guard_register_connect_status(const char *digest, int succeeded,
                                    int mark_relay_status, time_t now)
{
  return entry_guard_register_connect_status_for_guard_selection(
      get_guard_selection_info(), digest, succeeded, mark_relay_status, now);
}

/** Called when the value of EntryNodes changes in our configuration. */
void
entry_nodes_should_be_added_for_guard_selection(guard_selection_t *gs)
{
  tor_assert(gs != NULL);

  log_info(LD_CIRC, "EntryNodes config option set. Putting configured "
           "relays at the front of the entry guard list.");
  gs->should_add_entry_nodes = 1;
}

/** Called when the value of EntryNodes changes in our configuration. */
void
entry_nodes_should_be_added(void)
{
  entry_nodes_should_be_added_for_guard_selection(
      get_guard_selection_info());
}

/** Adjust the entry guards list so that it only contains entries from
 * EntryNodes, adding new entries from EntryNodes to the list as needed. */
STATIC void
entry_guards_set_from_config(guard_selection_t *gs,
                             const or_options_t *options)
{
  smartlist_t *entry_nodes, *worse_entry_nodes, *entry_fps;
  smartlist_t *old_entry_guards_on_list, *old_entry_guards_not_on_list;
  const int numentryguards = decide_num_guards(options, 0);

  tor_assert(gs != NULL);
  tor_assert(gs->chosen_entry_guards != NULL);

  gs->should_add_entry_nodes = 0;

  if (!options->EntryNodes) {
    /* It's possible that a controller set EntryNodes, thus making
     * should_add_entry_nodes set, then cleared it again, all before the
     * call to choose_random_entry() that triggered us. If so, just return.
     */
    return;
  }

  {
    char *string = routerset_to_string(options->EntryNodes);
    log_info(LD_CIRC,"Adding configured EntryNodes '%s'.", string);
    tor_free(string);
  }

  entry_nodes = smartlist_new();
  worse_entry_nodes = smartlist_new();
  entry_fps = smartlist_new();
  old_entry_guards_on_list = smartlist_new();
  old_entry_guards_not_on_list = smartlist_new();

  /* Split entry guards into those on the list and those not. */

  routerset_get_all_nodes(entry_nodes, options->EntryNodes,
                          options->ExcludeNodes, 0);
  SMARTLIST_FOREACH(entry_nodes, const node_t *,node,
                    smartlist_add(entry_fps, (void*)node->identity));

  SMARTLIST_FOREACH(gs->chosen_entry_guards, entry_guard_t *, e, {
    if (smartlist_contains_digest(entry_fps, e->identity))
      smartlist_add(old_entry_guards_on_list, e);
    else
      smartlist_add(old_entry_guards_not_on_list, e);
  });

  /* Remove all currently configured guard nodes, excluded nodes, unreachable
   * nodes, or non-Guard nodes from entry_nodes. */
  SMARTLIST_FOREACH_BEGIN(entry_nodes, const node_t *, node) {
    if (entry_guard_get_by_id_digest_for_guard_selection(gs,
          node->identity)) {
      SMARTLIST_DEL_CURRENT(entry_nodes, node);
      continue;
    } else if (routerset_contains_node(options->ExcludeNodes, node)) {
      SMARTLIST_DEL_CURRENT(entry_nodes, node);
      continue;
    } else if (!fascist_firewall_allows_node(node, FIREWALL_OR_CONNECTION,
                                             0)) {
      SMARTLIST_DEL_CURRENT(entry_nodes, node);
      continue;
    } else if (! node->is_possible_guard) {
      smartlist_add(worse_entry_nodes, (node_t*)node);
      SMARTLIST_DEL_CURRENT(entry_nodes, node);
    }
  } SMARTLIST_FOREACH_END(node);

  /* Now build the new entry_guards list. */
  smartlist_clear(gs->chosen_entry_guards);
  /* First, the previously configured guards that are in EntryNodes. */
  smartlist_add_all(gs->chosen_entry_guards, old_entry_guards_on_list);
  /* Next, scramble the rest of EntryNodes, putting the guards first. */
  smartlist_shuffle(entry_nodes);
  smartlist_shuffle(worse_entry_nodes);
  smartlist_add_all(entry_nodes, worse_entry_nodes);

  /* Next, the rest of EntryNodes */
  SMARTLIST_FOREACH_BEGIN(entry_nodes, const node_t *, node) {
    add_an_entry_guard(gs, node, 0, 0, 1, 0);
    if (smartlist_len(gs->chosen_entry_guards) > numentryguards * 10)
      break;
  } SMARTLIST_FOREACH_END(node);
  log_notice(LD_GENERAL, "%d entries in guards",
             smartlist_len(gs->chosen_entry_guards));
  /* Finally, free the remaining previously configured guards that are not in
   * EntryNodes. */
  SMARTLIST_FOREACH(old_entry_guards_not_on_list, entry_guard_t *, e,
                    entry_guard_free(e));

  smartlist_free(entry_nodes);
  smartlist_free(worse_entry_nodes);
  smartlist_free(entry_fps);
  smartlist_free(old_entry_guards_on_list);
  smartlist_free(old_entry_guards_not_on_list);
  entry_guards_changed_for_guard_selection(gs);
}
#endif

/** Return 0 if we're fine adding arbitrary routers out of the
 * directory to our entry guard list, or return 1 if we have a
 * list already and we must stick to it.
 */
int
entry_list_is_constrained(const or_options_t *options)
{
  // XXXX prop271 look at the current selection.
  if (options->EntryNodes)
    return 1;
  if (options->UseBridges)
    return 1;
  return 0;
}

#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
/** Pick a live (up and listed) entry guard from entry_guards. If
 * <b>state</b> is non-NULL, this is for a specific circuit --
 * make sure not to pick this circuit's exit or any node in the
 * exit's family. If <b>state</b> is NULL, we're looking for a random
 * guard (likely a bridge).  If <b>dirinfo</b> is not NO_DIRINFO (zero),
 * then only select from nodes that know how to answer directory questions
 * of that type. */
const node_t *
choose_random_entry(cpath_build_state_t *state)
{
  tor_assert(get_options()->UseDeprecatedGuardAlgorithm);

  return choose_random_entry_impl(get_guard_selection_info(),
                                  state, 0, NO_DIRINFO, NULL);
}

/** Pick a live (up and listed) directory guard from entry_guards for
 * downloading information of type <b>type</b>. */
const node_t *
choose_random_dirguard(dirinfo_type_t type)
{
  tor_assert(get_options()->UseDeprecatedGuardAlgorithm);

  return choose_random_entry_impl(get_guard_selection_info(),
                                  NULL, 1, type, NULL);
}
#endif

/** Return the number of bridges that have descriptors that are marked with
 * purpose 'bridge' and are running.
 */
int
num_bridges_usable(void)
{
  int n_options = 0;

  if (get_options()->UseDeprecatedGuardAlgorithm) {
#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
    tor_assert(get_options()->UseBridges);
    (void) choose_random_entry_impl(get_guard_selection_info(),
                                    NULL, 0, 0, &n_options);
#else
    tor_assert_nonfatal_unreached();
#endif
  } else {
    /* XXXX prop271 Is this quite right? */
    tor_assert(get_options()->UseBridges);
    guard_selection_t *gs  = get_guard_selection_info();
    tor_assert(gs->type == GS_TYPE_BRIDGE);

    SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
      if (guard->is_reachable == GUARD_REACHABLE_NO)
        continue;
      if (tor_digest_is_zero(guard->identity))
        continue;
      const node_t *node = node_get_by_id(guard->identity);
      if (node && node->ri)
        ++n_options;
    } SMARTLIST_FOREACH_END(guard);
  }

  return n_options;
}

#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
/** Filter <b>all_entry_guards</b> for usable entry guards and put them
 * in <b>live_entry_guards</b>. We filter based on whether the node is
 * currently alive, and on whether it satisfies the restrictions
 * imposed by the other arguments of this function.
 *
 * We don't place more guards than NumEntryGuards in <b>live_entry_guards</b>.
 *
 * If <b>chosen_exit</b> is set, it contains the exit node of this
 * circuit. Make sure to not use it or its family as an entry guard.
 *
 * If <b>need_uptime</b> is set, we are looking for a stable entry guard.
 * if <b>need_capacity</b> is set, we are looking for a fast entry guard.
 *
 * The rest of the arguments are the same as in choose_random_entry_impl().
 *
 * Return 1 if we should choose a guard right away. Return 0 if we
 * should try to add more nodes to our list before deciding on a
 * guard.
 */
STATIC int
populate_live_entry_guards(smartlist_t *live_entry_guards,
                           const smartlist_t *all_entry_guards,
                           const node_t *chosen_exit,
                           dirinfo_type_t dirinfo_type,
                           int for_directory,
                           int need_uptime, int need_capacity)
{
  const or_options_t *options = get_options();
  const node_t *node = NULL;
  const int num_needed = decide_num_guards(options, for_directory);
  smartlist_t *exit_family = smartlist_new();
  int retval = 0;
  entry_is_live_flags_t entry_flags = 0;

  (void) dirinfo_type;

  { /* Set the flags we want our entry node to have */
    if (need_uptime) {
      entry_flags |= ENTRY_NEED_UPTIME;
    }
    if (need_capacity) {
      entry_flags |= ENTRY_NEED_CAPACITY;
    }
    if (!for_directory) {
      entry_flags |= ENTRY_NEED_DESCRIPTOR;
    }
  }

  tor_assert(all_entry_guards);

  if (chosen_exit) {
    nodelist_add_node_and_family(exit_family, chosen_exit);
  }

  SMARTLIST_FOREACH_BEGIN(all_entry_guards, const entry_guard_t *, entry) {
      const char *msg;
      node = entry_is_live(entry, entry_flags, &msg);
      if (!node)
        continue; /* down, no point */
      if (for_directory) {
        if (!entry->is_dir_cache)
          continue; /* We need a directory and didn't get one. */
      }
      if (node == chosen_exit)
        continue; /* don't pick the same node for entry and exit */
      if (smartlist_contains(exit_family, node))
        continue; /* avoid relays that are family members of our exit */
      smartlist_add(live_entry_guards, (void*)node);
      if (!entry->made_contact) {
        /* Always start with the first not-yet-contacted entry
         * guard. Otherwise we might add several new ones, pick
         * the second new one, and now we've expanded our entry
         * guard list without needing to. */
        retval = 1;
        goto done;
      }
      if (smartlist_len(live_entry_guards) >= num_needed) {
        retval = 1;
        goto done; /* We picked enough entry guards. Done! */
      }
  } SMARTLIST_FOREACH_END(entry);

 done:
  smartlist_free(exit_family);

  return retval;
}

/** Pick a node to be used as the entry guard of a circuit, relative to
 * a supplied guard selection context.
 *
 * If <b>state</b> is set, it contains the information we know about
 * the upcoming circuit.
 *
 * If <b>for_directory</b> is set, we are looking for a directory guard.
 *
 * <b>dirinfo_type</b> contains the kind of directory information we
 * are looking for in our node, or NO_DIRINFO (zero) if we are not
 * looking for any particular directory information (when set to
 * NO_DIRINFO, the <b>dirinfo_type</b> filter is ignored).
 *
 * If <b>n_options_out</b> is set, we set it to the number of
 * candidate guard nodes we had before picking a specific guard node.
 *
 * On success, return the node that should be used as the entry guard
 * of the circuit.  Return NULL if no such node could be found.
 *
 * Helper for choose_random{entry,dirguard}.
*/
static const node_t *
choose_random_entry_impl(guard_selection_t *gs,
                         cpath_build_state_t *state, int for_directory,
                         dirinfo_type_t dirinfo_type, int *n_options_out)
{
  const or_options_t *options = get_options();
  smartlist_t *live_entry_guards = smartlist_new();
  const node_t *chosen_exit =
    state?build_state_get_exit_node(state) : NULL;
  const node_t *node = NULL;
  int need_uptime = state ? state->need_uptime : 0;
  int need_capacity = state ? state->need_capacity : 0;
  int preferred_min = 0;
  const int num_needed = decide_num_guards(options, for_directory);
  int retval = 0;

  tor_assert(gs != NULL);
  tor_assert(gs->chosen_entry_guards != NULL);

  if (n_options_out)
    *n_options_out = 0;

  if (gs->should_add_entry_nodes)
    entry_guards_set_from_config(gs, options);

  if (!entry_list_is_constrained(options) &&
      smartlist_len(gs->chosen_entry_guards) < num_needed)
    pick_entry_guards(gs, options, for_directory);

 retry:
  smartlist_clear(live_entry_guards);

  /* Populate the list of live entry guards so that we pick one of
     them. */
  retval = populate_live_entry_guards(live_entry_guards,
                                      gs->chosen_entry_guards,
                                      chosen_exit,
                                      dirinfo_type,
                                      for_directory,
                                      need_uptime, need_capacity);

  if (retval == 1) { /* We should choose a guard right now. */
    goto choose_and_finish;
  }

  if (entry_list_is_constrained(options)) {
    /* If we prefer the entry nodes we've got, and we have at least
     * one choice, that's great. Use it. */
    preferred_min = 1;
  } else {
    /* Try to have at least 2 choices available. This way we don't
     * get stuck with a single live-but-crummy entry and just keep
     * using it.
     * (We might get 2 live-but-crummy entry guards, but so be it.) */
    preferred_min = 2;
  }

  if (smartlist_len(live_entry_guards) < preferred_min) {
    if (!entry_list_is_constrained(options)) {
      /* still no? try adding a new entry then */
      /* XXX if guard doesn't imply fast and stable, then we need
       * to tell add_an_entry_guard below what we want, or it might
       * be a long time til we get it. -RD */
      node = add_an_entry_guard(gs, NULL, 0, 0, 1, for_directory);
      if (node) {
        entry_guards_changed_for_guard_selection(gs);
        /* XXX we start over here in case the new node we added shares
         * a family with our exit node. There's a chance that we'll just
         * load up on entry guards here, if the network we're using is
         * one big family. Perhaps we should teach add_an_entry_guard()
         * to understand nodes-to-avoid-if-possible? -RD */
        goto retry;
      }
    }
    if (!node && need_uptime) {
      need_uptime = 0; /* try without that requirement */
      goto retry;
    }
    if (!node && need_capacity) {
      /* still no? last attempt, try without requiring capacity */
      need_capacity = 0;
      goto retry;
    }

    /* live_entry_guards may be empty below. Oh well, we tried. */
  }

 choose_and_finish:
  if (entry_list_is_constrained(options)) {
    /* We need to weight by bandwidth, because our bridges or entryguards
     * were not already selected proportional to their bandwidth. */
    node = node_sl_choose_by_bandwidth(live_entry_guards, WEIGHT_FOR_GUARD);
  } else {
    /* We choose uniformly at random here, because choose_good_entry_server()
     * already weights its choices by bandwidth, so we don't want to
     * *double*-weight our guard selection. */
    node = smartlist_choose(live_entry_guards);
  }
  if (n_options_out)
    *n_options_out = smartlist_len(live_entry_guards);
  smartlist_free(live_entry_guards);
  return node;
}
#endif

/** Check the pathbias use success count of <b>node</b> and disable it if it
 *  goes over our thresholds. */
static void
pathbias_check_use_success_count(entry_guard_t *node)
{
  const or_options_t *options = get_options();
  const double EPSILON = 1.0e-9;

  /* Note: We rely on the < comparison here to allow us to set a 0
   * rate and disable the feature entirely. If refactoring, don't
   * change to <= */
  if (node->pb.use_attempts > EPSILON &&
      pathbias_get_use_success_count(node)/node->pb.use_attempts
      < pathbias_get_extreme_use_rate(options) &&
      pathbias_get_dropguards(options)) {
    node->pb.path_bias_disabled = 1;
    log_info(LD_GENERAL,
             "Path use bias is too high (%f/%f); disabling node %s",
             node->pb.circ_successes, node->pb.circ_attempts,
             node->nickname);
  }
}

/** Check the pathbias close count of <b>node</b> and disable it if it goes
 *  over our thresholds. */
static void
pathbias_check_close_success_count(entry_guard_t *node)
{
  const or_options_t *options = get_options();
  const double EPSILON = 1.0e-9;

  /* Note: We rely on the < comparison here to allow us to set a 0
   * rate and disable the feature entirely. If refactoring, don't
   * change to <= */
  if (node->pb.circ_attempts > EPSILON &&
      pathbias_get_close_success_count(node)/node->pb.circ_attempts
      < pathbias_get_extreme_rate(options) &&
      pathbias_get_dropguards(options)) {
    node->pb.path_bias_disabled = 1;
    log_info(LD_GENERAL,
             "Path bias is too high (%f/%f); disabling node %s",
             node->pb.circ_successes, node->pb.circ_attempts,
             node->nickname);
  }
}

#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
/** Parse <b>state</b> and learn about the entry guards it describes.
 * If <b>set</b> is true, and there are no errors, replace the guard
 * list in the provided guard selection context with what we find.
 * On success, return 0. On failure, alloc into *<b>msg</b> a string
 * describing the error, and return -1.
 */
int
entry_guards_parse_state_for_guard_selection(
    guard_selection_t *gs,
    or_state_t *state, int set, char **msg)
{
  entry_guard_t *node = NULL;
  smartlist_t *new_entry_guards = smartlist_new();
  config_line_t *line;
  time_t now = time(NULL);
  const char *state_version = state->TorVersion;
  digestmap_t *added_by = digestmap_new();

  tor_assert(gs != NULL);

  *msg = NULL;
  for (line = state->EntryGuards; line; line = line->next) {
    if (!strcasecmp(line->key, "EntryGuard")) {
      smartlist_t *args = smartlist_new();
      node = tor_malloc_zero(sizeof(entry_guard_t));
      /* all entry guards on disk have been contacted */
      node->made_contact = 1;
      node->is_persistent = 1;
      smartlist_add(new_entry_guards, node);
      smartlist_split_string(args, line->value, " ",
                             SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
      if (smartlist_len(args)<2) {
        *msg = tor_strdup("Unable to parse entry nodes: "
                          "Too few arguments to EntryGuard");
      } else if (!is_legal_nickname(smartlist_get(args,0))) {
        *msg = tor_strdup("Unable to parse entry nodes: "
                          "Bad nickname for EntryGuard");
      } else {
        strlcpy(node->nickname, smartlist_get(args,0), MAX_NICKNAME_LEN+1);
        if (base16_decode(node->identity, DIGEST_LEN, smartlist_get(args,1),
                          strlen(smartlist_get(args,1))) != DIGEST_LEN) {
          *msg = tor_strdup("Unable to parse entry nodes: "
                            "Bad hex digest for EntryGuard");
        }
      }
      if (smartlist_len(args) >= 3) {
        const char *is_cache = smartlist_get(args, 2);
        if (!strcasecmp(is_cache, "DirCache")) {
          node->is_dir_cache = 1;
        } else if (!strcasecmp(is_cache, "NoDirCache")) {
          node->is_dir_cache = 0;
        } else {
          log_warn(LD_CONFIG, "Bogus third argument to EntryGuard line: %s",
                   escaped(is_cache));
        }
      }
      SMARTLIST_FOREACH(args, char*, cp, tor_free(cp));
      smartlist_free(args);
      if (*msg)
        break;
    } else if (!strcasecmp(line->key, "EntryGuardDownSince") ||
               !strcasecmp(line->key, "EntryGuardUnlistedSince")) {
      time_t when;
      time_t last_try = 0;
      if (!node) {
        *msg = tor_strdup("Unable to parse entry nodes: "
               "EntryGuardDownSince/UnlistedSince without EntryGuard");
        break;
      }
      if (parse_iso_time_(line->value, &when, 0, 0)<0) {
        *msg = tor_strdup("Unable to parse entry nodes: "
                          "Bad time in EntryGuardDownSince/UnlistedSince");
        break;
      }
      if (when > now) {
        /* It's a bad idea to believe info in the future: you can wind
         * up with timeouts that aren't allowed to happen for years. */
        continue;
      }
      if (strlen(line->value) >= ISO_TIME_LEN+ISO_TIME_LEN+1) {
        /* ignore failure */
        (void) parse_iso_time(line->value+ISO_TIME_LEN+1, &last_try);
      }
      if (!strcasecmp(line->key, "EntryGuardDownSince")) {
        node->unreachable_since = when;
        node->last_attempted = last_try;
      } else {
        node->bad_since = when;
      }
    } else if (!strcasecmp(line->key, "EntryGuardAddedBy")) {
      char d[DIGEST_LEN];
      /* format is digest version date */
      if (strlen(line->value) < HEX_DIGEST_LEN+1+1+1+ISO_TIME_LEN) {
        log_warn(LD_BUG, "EntryGuardAddedBy line is not long enough.");
        continue;
      }
      if (base16_decode(d, sizeof(d),
                        line->value, HEX_DIGEST_LEN) != sizeof(d) ||
                        line->value[HEX_DIGEST_LEN] != ' ') {
        log_warn(LD_BUG, "EntryGuardAddedBy line %s does not begin with "
                 "hex digest", escaped(line->value));
        continue;
      }
      digestmap_set(added_by, d, tor_strdup(line->value+HEX_DIGEST_LEN+1));
    } else if (!strcasecmp(line->key, "EntryGuardPathUseBias")) {
      double use_cnt, success_cnt;

      if (!node) {
        *msg = tor_strdup("Unable to parse entry nodes: "
               "EntryGuardPathUseBias without EntryGuard");
        break;
      }

      if (tor_sscanf(line->value, "%lf %lf",
                     &use_cnt, &success_cnt) != 2) {
        log_info(LD_GENERAL, "Malformed path use bias line for node %s",
                 node->nickname);
        continue;
      }

      if (use_cnt < success_cnt) {
        int severity = LOG_INFO;
        /* If this state file was written by a Tor that would have
         * already fixed it, then the overcounting bug is still there.. */
        if (tor_version_as_new_as(state_version, "0.2.4.13-alpha")) {
          severity = LOG_NOTICE;
        }
        log_fn(severity, LD_BUG,
                   "State file contains unexpectedly high usage success "
                   "counts %lf/%lf for Guard %s ($%s)",
                   success_cnt, use_cnt,
                   node->nickname, hex_str(node->identity, DIGEST_LEN));
        success_cnt = use_cnt;
      }

      node->pb.use_attempts = use_cnt;
      node->pb.use_successes = success_cnt;

      log_info(LD_GENERAL, "Read %f/%f path use bias for node %s",
               node->pb.use_successes, node->pb.use_attempts, node->nickname);

      pathbias_check_use_success_count(node);

    } else if (!strcasecmp(line->key, "EntryGuardPathBias")) {
      double hop_cnt, success_cnt, timeouts, collapsed, successful_closed,
               unusable;

      if (!node) {
        *msg = tor_strdup("Unable to parse entry nodes: "
               "EntryGuardPathBias without EntryGuard");
        break;
      }

      /* First try 3 params, then 2. */
      /* In the long run: circuit_success ~= successful_circuit_close +
       *                                     collapsed_circuits +
       *                                     unusable_circuits */
      if (tor_sscanf(line->value, "%lf %lf %lf %lf %lf %lf",
                  &hop_cnt, &success_cnt, &successful_closed,
                  &collapsed, &unusable, &timeouts) != 6) {
        int old_success, old_hops;
        if (tor_sscanf(line->value, "%u %u", &old_success, &old_hops) != 2) {
          continue;
        }
        log_info(LD_GENERAL, "Reading old-style EntryGuardPathBias %s",
                 escaped(line->value));

        success_cnt = old_success;
        successful_closed = old_success;
        hop_cnt = old_hops;
        timeouts = 0;
        collapsed = 0;
        unusable = 0;
      }

      if (hop_cnt < success_cnt) {
        int severity = LOG_INFO;
        /* If this state file was written by a Tor that would have
         * already fixed it, then the overcounting bug is still there.. */
        if (tor_version_as_new_as(state_version, "0.2.4.13-alpha")) {
          severity = LOG_NOTICE;
        }
        log_fn(severity, LD_BUG,
                "State file contains unexpectedly high success counts "
                "%lf/%lf for Guard %s ($%s)",
                success_cnt, hop_cnt,
                node->nickname, hex_str(node->identity, DIGEST_LEN));
        success_cnt = hop_cnt;
      }

      node->pb.circ_attempts = hop_cnt;
      node->pb.circ_successes = success_cnt;

      node->pb.successful_circuits_closed = successful_closed;
      node->pb.timeouts = timeouts;
      node->pb.collapsed_circuits = collapsed;
      node->pb.unusable_circuits = unusable;

      log_info(LD_GENERAL, "Read %f/%f path bias for node %s",
               node->pb.circ_successes, node->pb.circ_attempts,
               node->nickname);

      pathbias_check_close_success_count(node);
    } else {
      log_warn(LD_BUG, "Unexpected key %s", line->key);
    }
  }

  SMARTLIST_FOREACH_BEGIN(new_entry_guards, entry_guard_t *, e) {
     char *sp;
     char *val = digestmap_get(added_by, e->identity);
     if (val && (sp = strchr(val, ' '))) {
       time_t when;
       *sp++ = '\0';
       if (parse_iso_time(sp, &when)<0) {
         log_warn(LD_BUG, "Can't read time %s in EntryGuardAddedBy", sp);
       } else {
         e->chosen_by_version = tor_strdup(val);
         e->chosen_on_date = when;
       }
     } else {
       if (state_version) {
         e->chosen_on_date = crypto_rand_time_range(now - 3600*24*30, now);
         e->chosen_by_version = tor_strdup(state_version);
       }
     }
     if (e->pb.path_bias_disabled && !e->bad_since)
       e->bad_since = time(NULL);
    }
  SMARTLIST_FOREACH_END(e);

  if (*msg || !set) {
    SMARTLIST_FOREACH(new_entry_guards, entry_guard_t *, e,
                      entry_guard_free(e));
    smartlist_free(new_entry_guards);
  } else { /* !err && set */
    if (gs->chosen_entry_guards) {
      SMARTLIST_FOREACH(gs->chosen_entry_guards, entry_guard_t *, e,
                        entry_guard_free(e));
      smartlist_free(gs->chosen_entry_guards);
    }
    gs->chosen_entry_guards = new_entry_guards;
    SMARTLIST_FOREACH(new_entry_guards, entry_guard_t *, e,
                      e->in_selection = gs);

    /* XXX hand new_entry_guards to this func, and move it up a
     * few lines, so we don't have to re-dirty it */
    if (remove_obsolete_entry_guards(gs, now))
      entry_guards_dirty = 1;
  }
  digestmap_free(added_by, tor_free_);
  return *msg ? -1 : 0;
}
#endif

/** Parse <b>state</b> and learn about the entry guards it describes.
 * If <b>set</b> is true, and there are no errors, replace the guard
 * list in the default guard selection context with what we find.
 * On success, return 0. On failure, alloc into *<b>msg</b> a string
 * describing the error, and return -1.
 */
int
entry_guards_parse_state(or_state_t *state, int set, char **msg)
{
  entry_guards_dirty = 0;

  int r1 = entry_guards_load_guards_from_state(state, set);

#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
  int r2 = entry_guards_parse_state_for_guard_selection(
      get_guard_selection_by_name("legacy", GS_TYPE_LEGACY, 1),
      state, set, msg);
#else
   int r2 = 0;
#endif

  entry_guards_dirty = 0;

  if (r1 < 0 || r2 < 0) {
    if (msg && *msg == NULL) {
      *msg = tor_strdup("parsing error"); //xxxx prop271 should we try harder?
    }
    return -1;
  }
  return 0;
}

/** How long will we let a change in our guard nodes stay un-saved
 * when we are trying to avoid disk writes? */
#define SLOW_GUARD_STATE_FLUSH_TIME 600
/** How long will we let a change in our guard nodes stay un-saved
 * when we are not trying to avoid disk writes? */
#define FAST_GUARD_STATE_FLUSH_TIME 30

/** Our list of entry guards has changed for a particular guard selection
 * context, or some element of one of our entry guards has changed for one.
 * Write the changes to disk within the next few minutes.
 */
void
entry_guards_changed_for_guard_selection(guard_selection_t *gs)
{
  time_t when;

  tor_assert(gs != NULL);

  entry_guards_dirty = 1;

  if (get_options()->AvoidDiskWrites)
    when = time(NULL) + SLOW_GUARD_STATE_FLUSH_TIME;
  else
    when = time(NULL) + FAST_GUARD_STATE_FLUSH_TIME;

  /* or_state_save() will call entry_guards_update_state() and
     entry_guards_update_guards_in_state()
  */
  or_state_mark_dirty(get_or_state(), when);
}

/** Our list of entry guards has changed for the default guard selection
 * context, or some element of one of our entry guards has changed. Write
 * the changes to disk within the next few minutes.
 */
void
entry_guards_changed(void)
{
  entry_guards_changed_for_guard_selection(get_guard_selection_info());
}

/** If the entry guard info has not changed, do nothing and return.
 * Otherwise, free the EntryGuards piece of <b>state</b> and create
 * a new one out of the global entry_guards list, and then mark
 * <b>state</b> dirty so it will get saved to disk.
 */
void
entry_guards_update_state(or_state_t *state)
{
  entry_guards_dirty = 0;

  // Handles all non-legacy guard info.
  entry_guards_update_guards_in_state(state);

  entry_guards_dirty = 0;

#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
  config_line_t **next, *line;

  guard_selection_t *gs;
  gs = get_guard_selection_by_name("legacy", GS_TYPE_LEGACY, 0);
  if (!gs)
    return; // nothign to save.
  tor_assert(gs->chosen_entry_guards != NULL);

  config_free_lines(state->EntryGuards);
  next = &state->EntryGuards;
  *next = NULL;
  SMARTLIST_FOREACH_BEGIN(gs->chosen_entry_guards, entry_guard_t *, e) {
      char dbuf[HEX_DIGEST_LEN+1];
      if (!e->made_contact)
        continue; /* don't write this one to disk */
      *next = line = tor_malloc_zero(sizeof(config_line_t));
      line->key = tor_strdup("EntryGuard");
      base16_encode(dbuf, sizeof(dbuf), e->identity, DIGEST_LEN);
      tor_asprintf(&line->value, "%s %s %sDirCache", e->nickname, dbuf,
                   e->is_dir_cache ? "" : "No");
      next = &(line->next);
      if (e->unreachable_since) {
        *next = line = tor_malloc_zero(sizeof(config_line_t));
        line->key = tor_strdup("EntryGuardDownSince");
        line->value = tor_malloc(ISO_TIME_LEN+1+ISO_TIME_LEN+1);
        format_iso_time(line->value, e->unreachable_since);
        if (e->last_attempted) {
          line->value[ISO_TIME_LEN] = ' ';
          format_iso_time(line->value+ISO_TIME_LEN+1, e->last_attempted);
        }
        next = &(line->next);
      }
      if (e->bad_since) {
        *next = line = tor_malloc_zero(sizeof(config_line_t));
        line->key = tor_strdup("EntryGuardUnlistedSince");
        line->value = tor_malloc(ISO_TIME_LEN+1);
        format_iso_time(line->value, e->bad_since);
        next = &(line->next);
      }
      if (e->chosen_on_date && e->chosen_by_version &&
          !strchr(e->chosen_by_version, ' ')) {
        char d[HEX_DIGEST_LEN+1];
        char t[ISO_TIME_LEN+1];
        *next = line = tor_malloc_zero(sizeof(config_line_t));
        line->key = tor_strdup("EntryGuardAddedBy");
        base16_encode(d, sizeof(d), e->identity, DIGEST_LEN);
        format_iso_time(t, e->chosen_on_date);
        tor_asprintf(&line->value, "%s %s %s",
                     d, e->chosen_by_version, t);
        next = &(line->next);
      }
      if (e->pb.circ_attempts > 0) {
        *next = line = tor_malloc_zero(sizeof(config_line_t));
        line->key = tor_strdup("EntryGuardPathBias");
        /* In the long run: circuit_success ~= successful_circuit_close +
         *                                     collapsed_circuits +
         *                                     unusable_circuits */
        tor_asprintf(&line->value, "%f %f %f %f %f %f",
                     e->pb.circ_attempts, e->pb.circ_successes,
                     pathbias_get_close_success_count(e),
                     e->pb.collapsed_circuits,
                     e->pb.unusable_circuits, e->pb.timeouts);
        next = &(line->next);
      }
      if (e->pb.use_attempts > 0) {
        *next = line = tor_malloc_zero(sizeof(config_line_t));
        line->key = tor_strdup("EntryGuardPathUseBias");

        tor_asprintf(&line->value, "%f %f",
                     e->pb.use_attempts,
                     pathbias_get_use_success_count(e));
        next = &(line->next);
      }

  } SMARTLIST_FOREACH_END(e);
#endif
  if (!get_options()->AvoidDiskWrites)
    or_state_mark_dirty(get_or_state(), 0);
  entry_guards_dirty = 0;
}

/** If <b>question</b> is the string "entry-guards", then dump
 * to *<b>answer</b> a newly allocated string describing all of
 * the nodes in the global entry_guards list. See control-spec.txt
 * for details.
 * For backward compatibility, we also handle the string "helper-nodes".
 *
 * XXX this should be totally redesigned after prop 271 too, and that's
 * going to take some control spec work.
 * */
int
getinfo_helper_entry_guards(control_connection_t *conn,
                            const char *question, char **answer,
                            const char **errmsg)
{
  guard_selection_t *gs = get_guard_selection_info();

  tor_assert(gs != NULL);
#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
  tor_assert(gs->chosen_entry_guards != NULL);
#else
  // XXXX
  (void)question;
  (void)answer;
#endif

  (void) conn;
  (void) errmsg;

#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
  if (!strcmp(question,"entry-guards") ||
      !strcmp(question,"helper-nodes")) {
    smartlist_t *sl = smartlist_new();
    char tbuf[ISO_TIME_LEN+1];
    char nbuf[MAX_VERBOSE_NICKNAME_LEN+1];

    SMARTLIST_FOREACH_BEGIN(gs->chosen_entry_guards, entry_guard_t *, e) {
        const char *status = NULL;
        time_t when = 0;
        const node_t *node;

        if (!e->made_contact) {
          status = "never-connected";
        } else if (e->bad_since) {
          when = e->bad_since;
          status = "unusable";
        } else if (e->unreachable_since) {
          when = e->unreachable_since;
          status = "down";
        } else {
          status = "up";
        }

        node = node_get_by_id(e->identity);
        if (node) {
          node_get_verbose_nickname(node, nbuf);
        } else {
          nbuf[0] = '$';
          base16_encode(nbuf+1, sizeof(nbuf)-1, e->identity, DIGEST_LEN);
          /* e->nickname field is not very reliable if we don't know about
           * this router any longer; don't include it. */
        }

        if (when) {
          format_iso_time(tbuf, when);
          smartlist_add_asprintf(sl, "%s %s %s\n", nbuf, status, tbuf);
        } else {
          smartlist_add_asprintf(sl, "%s %s\n", nbuf, status);
        }
    } SMARTLIST_FOREACH_END(e);
    *answer = smartlist_join_strings(sl, "", 0, NULL);
    SMARTLIST_FOREACH(sl, char *, c, tor_free(c));
    smartlist_free(sl);
  }
#endif
  return 0;
}

/* Given the original bandwidth of a guard and its guardfraction,
 * calculate how much bandwidth the guard should have as a guard and
 * as a non-guard.
 *
 * Quoting from proposal236:
 *
 *   Let Wpf denote the weight from the 'bandwidth-weights' line a
 *   client would apply to N for position p if it had the guard
 *   flag, Wpn the weight if it did not have the guard flag, and B the
 *   measured bandwidth of N in the consensus.  Then instead of choosing
 *   N for position p proportionally to Wpf*B or Wpn*B, clients should
 *   choose N proportionally to F*Wpf*B + (1-F)*Wpn*B.
 *
 * This function fills the <b>guardfraction_bw</b> structure. It sets
 * <b>guard_bw</b> to F*B and <b>non_guard_bw</b> to (1-F)*B.
 */
void
guard_get_guardfraction_bandwidth(guardfraction_bandwidth_t *guardfraction_bw,
                                  int orig_bandwidth,
                                  uint32_t guardfraction_percentage)
{
  double guardfraction_fraction;

  /* Turn the percentage into a fraction. */
  tor_assert(guardfraction_percentage <= 100);
  guardfraction_fraction = guardfraction_percentage / 100.0;

  long guard_bw = tor_lround(guardfraction_fraction * orig_bandwidth);
  tor_assert(guard_bw <= INT_MAX);

  guardfraction_bw->guard_bw = (int) guard_bw;

  guardfraction_bw->non_guard_bw = orig_bandwidth - (int) guard_bw;
}

#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
/** Returns true iff the node is used as a guard in the specified guard
 * context */
int
is_node_used_as_guard_for_guard_selection(guard_selection_t *gs,
                                          const node_t *node)
{
  int res = 0;

  /*
   * We used to have a using_as_guard flag in node_t, but it had to go away
   * to allow for multiple guard selection contexts.  Instead, search the
   * guard list for a matching digest.
   */

  tor_assert(gs != NULL);
  tor_assert(node != NULL);

  SMARTLIST_FOREACH_BEGIN(gs->chosen_entry_guards, entry_guard_t *, e) {
    if (tor_memeq(e->identity, node->identity, DIGEST_LEN)) {
      res = 1;
      break;
    }
  } SMARTLIST_FOREACH_END(e);

  return res;
}

/** Returns true iff the node is used as a guard in the default guard
 * context */
MOCK_IMPL(int,
is_node_used_as_guard, (const node_t *node))
{
  return is_node_used_as_guard_for_guard_selection(
      get_guard_selection_info(), node);
}

/** Return 1 if we have at least one descriptor for an entry guard
 * (bridge or member of EntryNodes) and all descriptors we know are
 * down. Else return 0. If <b>act</b> is 1, then mark the down guards
 * up; else just observe and report. */
static int
entries_retry_helper(const or_options_t *options, int act)
{
  const node_t *node;
  int any_known = 0;
  int any_running = 0;
  int need_bridges = options->UseBridges != 0;
  guard_selection_t *gs = get_guard_selection_info();

  tor_assert(gs != NULL);
  tor_assert(gs->chosen_entry_guards != NULL);

  SMARTLIST_FOREACH_BEGIN(gs->chosen_entry_guards, entry_guard_t *, e) {
      node = node_get_by_id(e->identity);
      if (node && node_has_descriptor(node) &&
          node_is_bridge(node) == need_bridges &&
          (!need_bridges || (!e->bad_since &&
                             node_is_a_configured_bridge(node)))) {
        any_known = 1;
        if (node->is_running)
          any_running = 1; /* some entry is both known and running */
        else if (act) {
          /* Mark all current connections to this OR as unhealthy, since
           * otherwise there could be one that started 30 seconds
           * ago, and in 30 seconds it will time out, causing us to mark
           * the node down and undermine the retry attempt. We mark even
           * the established conns, since if the network just came back
           * we'll want to attach circuits to fresh conns. */
          connection_or_set_bad_connections(node->identity, 1);

          /* mark this entry node for retry */
          router_set_status(node->identity, 1);
          e->can_retry = 1;
          e->bad_since = 0;
        }
      }
  } SMARTLIST_FOREACH_END(e);
  log_debug(LD_DIR, "%d: any_known %d, any_running %d",
            act, any_known, any_running);
  return any_known && !any_running;
}

/** Do we know any descriptors for our bridges / entrynodes, and are
 * all the ones we have descriptors for down? */
int
entries_known_but_down(const or_options_t *options)
{
  tor_assert(entry_list_is_constrained(options));
  return entries_retry_helper(options, 0);
}

/** Mark all down known bridges / entrynodes up. */
void
entries_retry_all(const or_options_t *options)
{
  tor_assert(entry_list_is_constrained(options));
  entries_retry_helper(options, 1);
}
#endif

/** Helper: Update the status of all entry guards, in whatever algorithm
 * is used. Return true if we should stop using all previously generated
 * circuits, by calling circuit_mark_all_unused_circs() and
 * circuit_mark_all_dirty_circs_as_unusable().
 */
int
guards_update_all(void)
{
  int mark_circuits = 0;
  if (update_guard_selection_choice(get_options()))
    mark_circuits = 1;

  tor_assert(curr_guard_context);

  if (curr_guard_context->type == GS_TYPE_LEGACY) {
#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
    entry_guards_compute_status(get_options(), approx_time());
#else
    tor_assert_nonfatal_unreached();
#endif
  } else {
    if (entry_guards_update_all(curr_guard_context))
      mark_circuits = 1;
  }

  return mark_circuits;
}

/** Helper: pick a guard for a circuit, with whatever algorithm is
    used. */
const node_t *
guards_choose_guard(cpath_build_state_t *state,
                   circuit_guard_state_t **guard_state_out)
{
  if (get_options()->UseDeprecatedGuardAlgorithm) {
#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
    return choose_random_entry(state);
#else
    tor_assert_nonfatal_unreached();
    return NULL;
#endif
  } else {
    const node_t *r = NULL;
    const uint8_t *exit_id = NULL;
    entry_guard_restriction_t *rst = NULL;
    // XXXX prop271 spec deviation -- use of restriction here.
    if (state && (exit_id = build_state_get_exit_rsa_id(state))) {
      /* We're building to a targeted exit node, so that node can't be
       * chosen as our guard for this circuit. */
      rst = tor_malloc_zero(sizeof(entry_guard_restriction_t));
      memcpy(rst->exclude_id, exit_id, DIGEST_LEN);
    }
    if (entry_guard_pick_for_circuit(get_guard_selection_info(),
                                     rst,
                                     &r,
                                     guard_state_out) < 0) {
      tor_assert(r == NULL);
    }
    return r;
  }
}

/** Helper: pick a directory guard, with whatever algorithm is used. */
const node_t *
guards_choose_dirguard(dirinfo_type_t info,
                      circuit_guard_state_t **guard_state_out)
{
  if (get_options()->UseDeprecatedGuardAlgorithm) {
#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
    return choose_random_dirguard(info);
#else
    (void)info;
    tor_assert_nonfatal_unreached();
    return NULL;
#endif
  } else {
    /* XXXX prop271 We don't need to look at the dirinfo_type_t here,
     * apparently. If you look at the old implementation, and you follow info
     * downwards through choose_random_dirguard(), into
     * choose_random_entry_impl(), into populate_live_entry_guards()... you
     * find out that it isn't even used, and hasn't been since 0.2.7.1-alpha,
     * when we realized that every Tor on the network would support
     * microdescriptors. -NM */
    const node_t *r = NULL;
    if (entry_guard_pick_for_circuit(get_guard_selection_info(),
                                     NULL,
                                     &r,
                                     guard_state_out) < 0) {
      tor_assert(r == NULL);
    }
    return r;
  }
}

/**
 * If we're running with a constrained guard set, then maybe mark our guards
 * usable.  Return 1 if we do; 0 if we don't.
 */
int
guards_retry_optimistic(const or_options_t *options)
{
  if (! entry_list_is_constrained(options))
    return 0;

#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
  if (options->UseDeprecatedGuardAlgorithm) {
    if (entries_known_but_down(options)) {
      entries_retry_all(options);
      return 1;
    }
  }
#endif

  // XXXX prop271 -- is this correct?
  mark_primary_guards_maybe_reachable(get_guard_selection_info());

  return 1;
}

/** Free one guard selection context */
STATIC void
guard_selection_free(guard_selection_t *gs)
{
  if (!gs) return;

  tor_free(gs->name);

#ifdef ENABLE_LEGACY_GUARD_ALGORITHM
  if (gs->chosen_entry_guards) {
    SMARTLIST_FOREACH(gs->chosen_entry_guards, entry_guard_t *, e,
                      entry_guard_free(e));
    smartlist_free(gs->chosen_entry_guards);
    gs->chosen_entry_guards = NULL;
  }
#endif

  if (gs->sampled_entry_guards) {
    SMARTLIST_FOREACH(gs->sampled_entry_guards, entry_guard_t *, e,
                      entry_guard_free(e));
    smartlist_free(gs->sampled_entry_guards);
    gs->sampled_entry_guards = NULL;
  }

  smartlist_free(gs->confirmed_entry_guards);
  smartlist_free(gs->primary_entry_guards);

  tor_free(gs);
}

/** Release all storage held by the list of entry guards and related
 * memory structs. */
void
entry_guards_free_all(void)
{
  /* Null out the default */
  curr_guard_context = NULL;
  /* Free all the guard contexts */
  if (guard_contexts != NULL) {
    SMARTLIST_FOREACH_BEGIN(guard_contexts, guard_selection_t *, gs) {
      guard_selection_free(gs);
    } SMARTLIST_FOREACH_END(gs);
    smartlist_free(guard_contexts);
    guard_contexts = NULL;
  }
  circuit_build_times_free_timeouts(get_circuit_build_times_mutable());
}

