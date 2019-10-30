/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file subsys.h
 * @brief Types used to declare a subsystem.
 **/

#ifndef TOR_SUBSYS_T
#define TOR_SUBSYS_T

#include <stdbool.h>

struct pubsub_connector_t;
struct config_format_t;

/**
 * A subsystem is a part of Tor that is initialized, shut down, configured,
 * and connected to other parts of Tor.
 *
 * All callbacks are optional -- if a callback is set to NULL, the subsystem
 * manager will treat it as a no-op.
 *
 * You should use c99 named-field initializers with this structure: we
 * will be adding more fields, often in the middle of the structure.
 **/
typedef struct subsys_fns_t {
  /**
   * The name of this subsystem.  It should be a programmer-readable
   * identifier.
   **/
  const char *name;

  /**
   * Whether this subsystem is supported -- that is, whether it is compiled
   * into Tor.  For most subsystems, this should be true.
   **/
  bool supported;

  /**
   * The 'initialization level' for the subsystem.  It should run from -100
   * through +100.  The subsystems are initialized from lowest level to
   * highest, and shut down from highest level to lowest.
   **/
  int level;

  /**
   * Initialize any global components of this subsystem.
   *
   * This function MAY rely on any lower-level subsystem being initialized.
   *
   * This function MUST NOT rely on any runtime configuration information;
   * it is only for global state or pre-configuration state.
   *
   * (If you need to do any setup that depends on configuration, you'll need
   * to declare a configuration callback. (Not yet designed))
   *
   * This function MUST NOT have any parts that can fail.
   **/
  int (*initialize)(void);

  /**
   * Connect a subsystem to the message dispatch system.
   **/
  int (*add_pubsub)(struct pubsub_connector_t *);

  /**
   * Perform any necessary pre-fork cleanup.  This function may not fail.
   */
  void (*prefork)(void);

  /**
   * Perform any necessary post-fork setup. This function may not fail.
   */
  void (*postfork)(void);

  /**
   * Free any thread-local resources held by this subsystem. Called before
   * the thread exits.
   */
  void (*thread_cleanup)(void);

  /**
   * Free all resources held by this subsystem.
   *
   * This function is not allowed to fail.
   **/
  void (*shutdown)(void);

  /**
   * A config_format_t describing all of the torrc fields owned by this
   * subsystem.
   **/
  const struct config_format_t *options_format;

  /**
   * A config_format_t describing all of the DataDir/state fields owned by
   * this subsystem.
   **/
  const struct config_format_t *state_format;

  /**
   * Receive an options object as defined by options_format. Return 0
   * on success, -1 on failure.
   *
   * It is safe to store the pointer to the object until set_options()
   * is called again. */
  int (*set_options)(void *);

  /* XXXX Add an implementation for options_act_reversible() later in this
   * branch. */

  /**
   * Receive a state object as defined by state_format. Return 0 on success,
   * -1 on failure.
   *
   * It is safe to store the pointer to the object; set_state() is only
   * called on startup.
   **/
  int (*set_state)(void *);

  /**
   * Update any information that needs to be stored in the provided state
   * object (as defined by state_format).  Return 0 on success, -1 on failure.
   *
   * The object provided here will be the same one as provided earlier to
   * set_state().  This method is called when we are about to save the state
   * to disk.
   **/
  int (*flush_state)(void *);
} subsys_fns_t;

/**
 * Lowest allowed subsystem level.
 **/
#define MIN_SUBSYS_LEVEL -100
/**
 * Highest allowed subsystem level.
 **/
#define MAX_SUBSYS_LEVEL 100

/**
 * All tor "libraries" (in src/libs) should have a subsystem level equal to or
 * less than this value.
 */
#define SUBSYS_LEVEL_LIBS -10

#endif /* !defined(TOR_SUBSYS_T) */
