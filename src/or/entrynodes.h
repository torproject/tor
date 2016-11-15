/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file entrynodes.h
 * \brief Header file for circuitbuild.c.
 **/

#ifndef TOR_ENTRYNODES_H
#define TOR_ENTRYNODES_H

/* Forward declare for guard_selection_t; entrynodes.c has the real struct */
typedef struct guard_selection_s guard_selection_t;

/* Forward declare for entry_guard_t; the real declaration is private. */
typedef struct entry_guard_t entry_guard_t;

#define GUARD_REACHABLE_NO    0
#define GUARD_REACHABLE_YES   1
#define GUARD_REACHABLE_MAYBE 2

/* Information about a guard's pathbias status.
 * These fields are used in circpathbias.c to try to detect entry
 * nodes that are failing circuits at a suspicious frequency.
 */
typedef struct guard_pathbias_t {
  unsigned int path_bias_noticed : 1; /**< Did we alert the user about path
                                       * bias for this node already? */
  unsigned int path_bias_warned : 1; /**< Did we alert the user about path bias
                                      * for this node already? */
  unsigned int path_bias_extreme : 1; /**< Did we alert the user about path
                                       * bias for this node already? */
  unsigned int path_bias_disabled : 1; /**< Have we disabled this node because
                                        * of path bias issues? */
  unsigned int path_bias_use_noticed : 1; /**< Did we alert the user about path
                                       * use bias for this node already? */
  unsigned int path_bias_use_extreme : 1; /**< Did we alert the user about path
                                       * use bias for this node already? */

  double circ_attempts; /**< Number of circuits this guard has "attempted" */
  double circ_successes; /**< Number of successfully built circuits using
                               * this guard as first hop. */
  double successful_circuits_closed; /**< Number of circuits that carried
                                        * streams successfully. */
  double collapsed_circuits; /**< Number of fully built circuits that were
                                 * remotely closed before any streams were
                                 * attempted. */
  double unusable_circuits; /**< Number of circuits for which streams were
                                *  attempted, but none succeeded. */
  double timeouts; /**< Number of 'right-censored' circuit timeouts for this
                       * guard. */
  double use_attempts; /**< Number of circuits we tried to use with streams */
  double use_successes; /**< Number of successfully used circuits using
                               * this guard as first hop. */
} guard_pathbias_t;

#if defined(ENTRYNODES_PRIVATE)
/** An entry_guard_t represents our information about a chosen long-term
 * first hop, known as a "helper" node in the literature. We can't just
 * use a node_t, since we want to remember these even when we
 * don't have any directory info. */
struct entry_guard_t {
  char nickname[MAX_HEX_NICKNAME_LEN+1];
  char identity[DIGEST_LEN];
  ed25519_public_key_t ed_id;

  /* XXXX prop271 DOCDOC document all these fields better */

  /* Persistent fields, present for all sampled guards. */
  time_t sampled_on_date;
  time_t unlisted_since_date; // can be zero
  char *sampled_by_version;
  unsigned currently_listed : 1;

  /* Persistent fields, for confirmed guards. */
  time_t confirmed_on_date; /* 0 if not confirmed */
  int confirmed_idx; /* -1 if not confirmed; otherwise the order that this
                      * item should occur in the CONFIRMED_GUARDS ordered
                      * list */

  /* ==== Non-persistent fields. */
  /* == These are used by sampled guards */
  time_t last_tried_to_connect;
  unsigned is_reachable : 2; /* One of GUARD_REACHABLE_{NO,YES,MAYBE} */
  unsigned is_pending : 1;
  time_t failing_since;

  /* These determine presence in filtered guards and usable-filtered-guards
   * respectively. */
  unsigned is_filtered_guard : 1;
  unsigned is_usable_filtered_guard : 1;

  /** This string holds any fields that we are maintaining because
   * we saw them in the state, even if we don't understand them. */
  char *extra_state_fields;
  /**
   * @name legacy guard selection algorithm fields
   *
   * These are used and maintained by the legacy (pre-prop271) entry guard
   * algorithm.  Most of them we will remove as prop271 gets implemented.
   * The rest we'll migrate over, if they are 100% semantically identical to
   * their prop271 equivalents. XXXXprop271
   */
  /**@{*/
  time_t chosen_on_date; /**< Approximately when was this guard added?
                          * "0" if we don't know. */
  char *chosen_by_version; /**< What tor version added this guard? NULL
                            * if we don't know. */
  unsigned int made_contact : 1; /**< 0 if we have never connected to this
                                  * router, 1 if we have. */
  unsigned int can_retry : 1; /**< Should we retry connecting to this entry,
                               * in spite of having it marked as unreachable?*/
  unsigned int is_dir_cache : 1; /**< Is this node a directory cache? */
  time_t bad_since; /**< 0 if this guard is currently usable, or the time at
                      * which it was observed to become (according to the
                      * directory or the user configuration) unusable. */
  time_t unreachable_since; /**< 0 if we can connect to this guard, or the
                             * time at which we first noticed we couldn't
                             * connect to it. */
  time_t last_attempted; /**< 0 if we can connect to this guard, or the time
                          * at which we last failed to connect to it. */

  /**}@*/

  /** Path bias information for this guard. */
  guard_pathbias_t pb;
};
#endif

#if 1
/* XXXX NM I would prefer that all of this stuff be private to
 * entrynodes.c. */
entry_guard_t *entry_guard_get_by_id_digest_for_guard_selection(
    guard_selection_t *gs, const char *digest);
entry_guard_t *entry_guard_get_by_id_digest(const char *digest);
void entry_guards_changed_for_guard_selection(guard_selection_t *gs);
void entry_guards_changed(void);
guard_selection_t * get_guard_selection_info(void);
const smartlist_t *get_entry_guards_for_guard_selection(
    guard_selection_t *gs);
const smartlist_t *get_entry_guards(void);
int num_live_entry_guards_for_guard_selection(
    guard_selection_t *gs,
    int for_directory);
int num_live_entry_guards(int for_directory);
#endif

const node_t *entry_guard_find_node(const entry_guard_t *guard);
void entry_guard_mark_bad(entry_guard_t *guard);
const char *entry_guard_get_rsa_id_digest(const entry_guard_t *guard);
const char *entry_guard_describe(const entry_guard_t *guard);
guard_pathbias_t *entry_guard_get_pathbias_state(entry_guard_t *guard);

/* Used by bridges.c only. */
void add_bridge_as_entry_guard(guard_selection_t *gs,
                               const node_t *chosen);
int num_bridges_usable(void);

#ifdef ENTRYNODES_PRIVATE
STATIC time_t randomize_time(time_t now, time_t max_backdate);
STATIC void entry_guard_add_to_sample(guard_selection_t *gs,
                                      node_t *node);
STATIC char *entry_guard_encode_for_state(entry_guard_t *guard);
STATIC entry_guard_t *entry_guard_parse_from_state(const char *s);
STATIC void entry_guard_free(entry_guard_t *e);

STATIC const node_t *add_an_entry_guard(guard_selection_t *gs,
                                        const node_t *chosen,
                                        int reset_status, int prepend,
                                        int for_discovery, int for_directory);
STATIC int populate_live_entry_guards(smartlist_t *live_entry_guards,
                                      const smartlist_t *all_entry_guards,
                                      const node_t *chosen_exit,
                                      dirinfo_type_t dirinfo_type,
                                      int for_directory,
                                      int need_uptime, int need_capacity);
STATIC int decide_num_guards(const or_options_t *options, int for_directory);

STATIC void entry_guards_set_from_config(guard_selection_t *gs,
                                         const or_options_t *options);

/** Flags to be passed to entry_is_live() to indicate what kind of
 * entry nodes we are looking for. */
typedef enum {
  ENTRY_NEED_UPTIME = 1<<0,
  ENTRY_NEED_CAPACITY = 1<<1,
  ENTRY_ASSUME_REACHABLE = 1<<2,
  ENTRY_NEED_DESCRIPTOR = 1<<3,
} entry_is_live_flags_t;

STATIC const node_t *entry_is_live(const entry_guard_t *e,
                                   entry_is_live_flags_t flags,
                                   const char **msg);

STATIC int entry_is_time_to_retry(const entry_guard_t *e, time_t now);

#endif

void remove_all_entry_guards_for_guard_selection(guard_selection_t *gs);
void remove_all_entry_guards(void);

void entry_guards_compute_status_for_guard_selection(
    guard_selection_t *gs, const or_options_t *options, time_t now);
void entry_guards_compute_status(const or_options_t *options, time_t now);
int entry_guard_register_connect_status_for_guard_selection(
    guard_selection_t *gs, const char *digest, int succeeded,
    int mark_relay_status, time_t now);
int entry_guard_register_connect_status(const char *digest, int succeeded,
                                        int mark_relay_status, time_t now);
void entry_nodes_should_be_added_for_guard_selection(guard_selection_t *gs);
void entry_nodes_should_be_added(void);
int entry_list_is_constrained(const or_options_t *options);
const node_t *choose_random_entry(cpath_build_state_t *state);
const node_t *choose_random_dirguard(dirinfo_type_t t);
int entry_guards_parse_state_for_guard_selection(
    guard_selection_t *gs, or_state_t *state, int set, char **msg);
int entry_guards_parse_state(or_state_t *state, int set, char **msg);
void entry_guards_update_state(or_state_t *state);
int getinfo_helper_entry_guards(control_connection_t *conn,
                                const char *question, char **answer,
                                const char **errmsg);
int is_node_used_as_guard_for_guard_selection(guard_selection_t *gs,
                                              const node_t *node);
MOCK_DECL(int, is_node_used_as_guard, (const node_t *node));

int entries_known_but_down(const or_options_t *options);
void entries_retry_all(const or_options_t *options);

void entry_guards_free_all(void);

double pathbias_get_close_success_count(entry_guard_t *guard);
double pathbias_get_use_success_count(entry_guard_t *guard);

/** Contains the bandwidth of a relay as a guard and as a non-guard
 *  after the guardfraction has been considered. */
typedef struct guardfraction_bandwidth_t {
  /** Bandwidth as a guard after guardfraction has been considered. */
  int guard_bw;
  /** Bandwidth as a non-guard after guardfraction has been considered. */
  int non_guard_bw;
} guardfraction_bandwidth_t;

int should_apply_guardfraction(const networkstatus_t *ns);

void
guard_get_guardfraction_bandwidth(guardfraction_bandwidth_t *guardfraction_bw,
                                  int orig_bandwidth,
                                  uint32_t guardfraction_percentage);

#endif

