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
 **/

#define ENTRYNODES_PRIVATE

#include "or.h"
#include "bridges.h"
#include "circpathbias.h"
#include "circuitbuild.h"
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

/** All the context for guard selection on a particular client */

struct guard_selection_s {
  /**
   * A value of 1 means that guard_selection_t structures have changed
   * and those changes need to be flushed to disk.
   *
   * XXX we don't know how to flush multiple guard contexts to disk yet;
   * fix that as soon as any way to change the default exists, or at least
   * make sure this gets set on change.
   */
  int dirty;

  /**
   * A list of the sampled entry guards, as entry_guard_t structures.
   * Not in any particular order. */
  smartlist_t *sampled_entry_guards;

  /**
   * A list of our chosen entry guards, as entry_guard_t structures; this
   * preserves the pre-Prop271 behavior.
   */
  smartlist_t *chosen_entry_guards;

  /**
   * When we try to choose an entry guard, should we parse and add
   * config's EntryNodes first?  This was formerly a global.
   */
  int should_add_entry_nodes;

  int filtered_up_to_date;
};

static smartlist_t *guard_contexts = NULL;
static guard_selection_t *curr_guard_context = NULL;

static const node_t *choose_random_entry_impl(guard_selection_t *gs,
                                              cpath_build_state_t *state,
                                              int for_directory,
                                              dirinfo_type_t dirtype,
                                              int *n_options_out);
static guard_selection_t * guard_selection_new(void);

/* Default number of entry guards in the case where the NumEntryGuards
 * consensus parameter is not set */
#define DEFAULT_N_GUARDS 1
/* Minimum and maximum number of entry guards (in case the NumEntryGuards
 * consensus parameter is set). */
#define MIN_N_GUARDS 1
#define MAX_N_GUARDS 10

/** Allocate a new guard_selection_t */

static guard_selection_t *
guard_selection_new(void)
{
  guard_selection_t *gs;

  gs = tor_malloc_zero(sizeof(*gs));
  gs->chosen_entry_guards = smartlist_new();
  gs->sampled_entry_guards = smartlist_new();

  return gs;
}

/** Get current default guard_selection_t, creating it if necessary */
guard_selection_t *
get_guard_selection_info(void)
{
  if (!guard_contexts) {
    guard_contexts = smartlist_new();
  }

  if (!curr_guard_context) {
    curr_guard_context = guard_selection_new();
    smartlist_add(guard_contexts, curr_guard_context);
  }

  return curr_guard_context;
}

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

/** Return a statically allocated human-readable description of <b>guard</b>
 */
const char *
entry_guard_describe(const entry_guard_t *guard)
{
  static char buf[256];
  tor_snprintf(buf, sizeof(buf),
               "%s ($%s)",
               guard->nickname, hex_str(guard->identity, DIGEST_LEN));
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

/** Return an interval betweeen 'now' and 'max_backdate' seconds in the past,
 * chosen uniformly at random. */
STATIC time_t
randomize_time(time_t now, time_t max_backdate)
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
 * DOCDOC
 */
STATIC void
entry_guard_add_to_sample(guard_selection_t *gs,
                          node_t *node)
{
  (void) entry_guard_add_to_sample; // XXXX prop271 remove -- unused
  const int GUARD_LIFETIME = 90 * 86400; // xxxx prop271
  tor_assert(gs);
  tor_assert(node);

  // XXXX prop271 take ed25519 identity here too.

  /* make sure that the guard is not already sampled. */
   SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards,
                           entry_guard_t *, sampled) {
    if (BUG(tor_memeq(node->identity, sampled->identity, DIGEST_LEN))) {
      return;
    }
  } SMARTLIST_FOREACH_END(sampled);

  entry_guard_t *guard = tor_malloc_zero(sizeof(entry_guard_t));

  /* persistent fields */
  memcpy(guard->identity, node->identity, DIGEST_LEN);
  strlcpy(guard->nickname, node_get_nickname(node), sizeof(guard->nickname));
  guard->sampled_on_date = randomize_time(approx_time(), GUARD_LIFETIME/10);
  tor_free(guard->sampled_by_version);
  guard->sampled_by_version = tor_strdup(VERSION);
  guard->confirmed_idx = -1;

  /* non-persistent fields */
  guard->is_reachable = GUARD_REACHABLE_MAYBE;

  smartlist_add(gs->sampled_entry_guards, guard);
  gs->filtered_up_to_date = 0;

  entry_guards_changed_for_guard_selection(gs);
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

  smartlist_add_asprintf(result, "rsa_id=%s",
                         hex_str(guard->identity, DIGEST_LEN));
  if (strlen(guard->nickname)) {
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
  char *rsa_id = NULL;
  char *nickname = NULL;
  char *sampled_on = NULL;
  char *sampled_by = NULL;
  char *unlisted_since = NULL;
  char *listed  = NULL;
  char *confirmed_on = NULL;
  char *confirmed_idx = NULL;

  /* Split up the entries.  Put the ones we know about in strings and the
   * rest in "extra". */
  {
    smartlist_t *entries = smartlist_new();

    strmap_t *vals = strmap_new(); // Maps keyword to location
    strmap_set(vals, "rsa_id", &rsa_id);
    strmap_set(vals, "nickname", &nickname);
    strmap_set(vals, "sampled_on", &sampled_on);
    strmap_set(vals, "sampled_by", &sampled_by);
    strmap_set(vals, "unlisted_since", &unlisted_since);
    strmap_set(vals, "listed", &listed);
    strmap_set(vals, "confirmed_on", &confirmed_on);
    strmap_set(vals, "confirmed_idx", &confirmed_idx);

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

  /* Listed is a boolean */
  if (listed && strcmp(listed, "0"))
    guard->currently_listed = 1;

  /* The index is a nonnegative integer. */
  guard->confirmed_idx = -1;
  if (confirmed_idx) {
    int ok=1;
    long idx = tor_parse_long(confirmed_idx, 10, 0, INT_MAX, &ok, NULL);
    if (! ok) {
      log_warn(LD_CIRC, "Guard has invalid confirmed_idx %s",
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

  goto done;

 err:
  // only consider it an error if the guard state was totally unparseable.
  entry_guard_free(guard);
  guard = NULL;

 done:
  tor_free(rsa_id);
  tor_free(nickname);
  tor_free(sampled_on);
  tor_free(sampled_by);
  tor_free(unlisted_since);
  tor_free(listed);
  tor_free(confirmed_on);
  tor_free(confirmed_idx);
  SMARTLIST_FOREACH(extra, char *, cp, tor_free(cp));
  smartlist_free(extra);

  return guard;
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

/** If <b>digest</b> matches the identity of any node in the
 * entry_guards list for the provided guard selection state,
 return that node. Else return NULL. */
entry_guard_t *
entry_guard_get_by_id_digest_for_guard_selection(guard_selection_t *gs,
                                                 const char *digest)
{
  tor_assert(gs != NULL);

  SMARTLIST_FOREACH(gs->chosen_entry_guards, entry_guard_t *, entry,
                    if (tor_memeq(digest, entry->identity, DIGEST_LEN))
                      return entry;
                   );
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

/** Largest amount that we'll backdate chosen_on_date */
#define CHOSEN_ON_DATE_SLOP (30*86400)

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
    node = choose_good_entry_server(CIRCUIT_PURPOSE_C_GENERAL, NULL);
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

  control_event_guard(entry->nickname, entry->identity, "NEW");
  control_event_guard_deferred();
  log_entry_guards_for_guard_selection(gs, LOG_INFO);

  return node;
}

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

/** How long (in seconds) do we allow an entry guard to be nonfunctional,
 * unlisted, excluded, or otherwise nonusable before we give up on it? */
#define ENTRY_GUARD_REMOVE_AFTER (30*24*60*60)

/** Release all storage held by <b>e</b>. */
STATIC void
entry_guard_free(entry_guard_t *e)
{
  if (!e)
    return;
  tor_free(e->chosen_by_version);
  tor_free(e->sampled_by_version);
  tor_free(e->extra_state_fields);
  tor_free(e);
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

/** Return 0 if we're fine adding arbitrary routers out of the
 * directory to our entry guard list, or return 1 if we have a
 * list already and we must stick to it.
 */
int
entry_list_is_constrained(const or_options_t *options)
{
  if (options->EntryNodes)
    return 1;
  if (options->UseBridges)
    return 1;
  return 0;
}

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
  return choose_random_entry_impl(get_guard_selection_info(),
                                  state, 0, NO_DIRINFO, NULL);
}

/** Pick a live (up and listed) directory guard from entry_guards for
 * downloading information of type <b>type</b>. */
const node_t *
choose_random_dirguard(dirinfo_type_t type)
{
  return choose_random_entry_impl(get_guard_selection_info(),
                                  NULL, 1, type, NULL);
}

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

  if (0) entry_guard_parse_from_state(NULL); // XXXX prop271 remove -- unused
  if (0) entry_guard_add_to_sample(NULL, NULL); // XXXX prop271 remove

  tor_assert(gs != NULL);

  *msg = NULL;
  for (line = state->EntryGuards; line; line = line->next) {
    if (!strcasecmp(line->key, "EntryGuard")) {
      smartlist_t *args = smartlist_new();
      node = tor_malloc_zero(sizeof(entry_guard_t));
      /* all entry guards on disk have been contacted */
      node->made_contact = 1;
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
      const or_options_t *options = get_options();
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

      /* Note: We rely on the < comparison here to allow us to set a 0
       * rate and disable the feature entirely. If refactoring, don't
       * change to <= */
      if (pathbias_get_use_success_count(node)/node->pb.use_attempts
            < pathbias_get_extreme_use_rate(options) &&
          pathbias_get_dropguards(options)) {
        node->pb.path_bias_disabled = 1;
        log_info(LD_GENERAL,
                 "Path use bias is too high (%f/%f); disabling node %s",
                 node->pb.circ_successes, node->pb.circ_attempts,
                 node->nickname);
      }
    } else if (!strcasecmp(line->key, "EntryGuardPathBias")) {
      const or_options_t *options = get_options();
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
      /* Note: We rely on the < comparison here to allow us to set a 0
       * rate and disable the feature entirely. If refactoring, don't
       * change to <= */
      if (pathbias_get_close_success_count(node)/node->pb.circ_attempts
            < pathbias_get_extreme_rate(options) &&
          pathbias_get_dropguards(options)) {
        node->pb.path_bias_disabled = 1;
        log_info(LD_GENERAL,
                 "Path bias is too high (%f/%f); disabling node %s",
                 node->pb.circ_successes, node->pb.circ_attempts,
                 node->nickname);
      }

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
    gs->dirty = 0;
    /* XXX hand new_entry_guards to this func, and move it up a
     * few lines, so we don't have to re-dirty it */
    if (remove_obsolete_entry_guards(gs, now))
      gs->dirty = 1;
  }
  digestmap_free(added_by, tor_free_);
  return *msg ? -1 : 0;
}

/** Parse <b>state</b> and learn about the entry guards it describes.
 * If <b>set</b> is true, and there are no errors, replace the guard
 * list in the default guard selection context with what we find.
 * On success, return 0. On failure, alloc into *<b>msg</b> a string
 * describing the error, and return -1.
 */
int
entry_guards_parse_state(or_state_t *state, int set, char **msg)
{
  return entry_guards_parse_state_for_guard_selection(
      get_guard_selection_info(),
      state, set, msg);
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

  gs->dirty = 1;

  if (get_options()->AvoidDiskWrites)
    when = time(NULL) + SLOW_GUARD_STATE_FLUSH_TIME;
  else
    when = time(NULL) + FAST_GUARD_STATE_FLUSH_TIME;

  /* or_state_save() will call entry_guards_update_state(). */
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
 *
 * XXX this should get totally redesigned around storing multiple
 * entry guard contexts.  For the initial refactor we'll just
 * always use the current default.  Fix it as soon as we actually
 * have any way that default can change.
 */
void
entry_guards_update_state(or_state_t *state)
{
  config_line_t **next, *line;
  guard_selection_t *gs = get_guard_selection_info();

  if (0) entry_guard_encode_for_state(NULL); // XXXX prop271 remove -- unused

  tor_assert(gs != NULL);
  tor_assert(gs->chosen_entry_guards != NULL);

  if (!gs->dirty)
    return;

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
  if (!get_options()->AvoidDiskWrites)
    or_state_mark_dirty(get_or_state(), 0);
  gs->dirty = 0;
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
  tor_assert(gs->chosen_entry_guards != NULL);

  (void) conn;
  (void) errmsg;

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
  return 0;
}

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

/** Free one guard selection context */
static void
guard_selection_free(guard_selection_t *gs)
{
  if (!gs) return;

  if (gs->chosen_entry_guards) {
    SMARTLIST_FOREACH(gs->chosen_entry_guards, entry_guard_t *, e,
                      entry_guard_free(e));
    smartlist_free(gs->chosen_entry_guards);
    gs->chosen_entry_guards = NULL;
  }

  if (gs->sampled_entry_guards) {
    SMARTLIST_FOREACH(gs->sampled_entry_guards, entry_guard_t *, e,
                      entry_guard_free(e));
    smartlist_free(gs->sampled_entry_guards);
    gs->sampled_entry_guards = NULL;
  }

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

