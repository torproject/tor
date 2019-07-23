/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file conftypes.h
 * @brief Types used to specify configurable options.
 *
 * This header defines the types that different modules will use in order to
 * declare their configuration and state variables, and tell the configuration
 * management code about those variables.  From the individual module's point
 * of view, its configuration and state are simply data structures.
 *
 * For defining new variable types, see var_type_def_st.h.
 *
 * For the code that manipulates variables defined via this module, see
 * lib/confmgt/, especially typedvar.h and (later) structvar.h.  The
 * configuration manager is responsible for encoding, decoding, and
 * maintaining the configuration structures used by the various modules.
 *
 * STATUS NOTE: This is a work in process refactoring.  It is not yet possible
 *   for modules to define their own variables, and much of the configuration
 *   management code is still in src/app/config/.
 **/

#ifndef TOR_SRC_LIB_CONF_CONFTYPES_H
#define TOR_SRC_LIB_CONF_CONFTYPES_H

#include "lib/cc/torint.h"

/** Enumeration of types which option values can take */
typedef enum config_type_t {
  CONFIG_TYPE_STRING = 0,   /**< An arbitrary string. */
  CONFIG_TYPE_FILENAME,     /**< A filename: some prefixes get expanded. */
  CONFIG_TYPE_POSINT,       /**< A non-negative integer less than MAX_INT */
  CONFIG_TYPE_INT,          /**< Any integer. */
  CONFIG_TYPE_UINT64,       /**< A value in range 0..UINT64_MAX */
  CONFIG_TYPE_INTERVAL,     /**< A number of seconds, with optional units*/
  CONFIG_TYPE_MSEC_INTERVAL,/**< A number of milliseconds, with optional
                              * units */
  CONFIG_TYPE_MEMUNIT,      /**< A number of bytes, with optional units*/
  CONFIG_TYPE_DOUBLE,       /**< A floating-point value */
  CONFIG_TYPE_BOOL,         /**< A boolean value, expressed as 0 or 1. */
  CONFIG_TYPE_AUTOBOOL,     /**< A boolean+auto value, expressed 0 for false,
                             * 1 for true, and -1 for auto  */
  CONFIG_TYPE_ISOTIME,      /**< An ISO-formatted time relative to UTC. */
  CONFIG_TYPE_CSV,          /**< A list of strings, separated by commas and
                              * optional whitespace. */
  CONFIG_TYPE_CSV_INTERVAL, /**< A list of strings, separated by commas and
                              * optional whitespace, representing intervals in
                              * seconds, with optional units.  We allow
                              * multiple values here for legacy reasons, but
                              * ignore every value after the first. */
  CONFIG_TYPE_LINELIST,     /**< Uninterpreted config lines */
  CONFIG_TYPE_LINELIST_S,   /**< Uninterpreted, context-sensitive config lines,
                             * mixed with other keywords. */
  CONFIG_TYPE_LINELIST_V,   /**< Catch-all "virtual" option to summarize
                             * context-sensitive config lines when fetching.
                             */
  // XXXX this doesn't belong at this level of abstraction.
  CONFIG_TYPE_ROUTERSET,    /**< A list of router names, addrs, and fps,
                             * parsed into a routerset_t. */
  CONFIG_TYPE_OBSOLETE,     /**< Obsolete (ignored) option. */
} config_type_t;

#ifdef TOR_UNIT_TESTS
/**
 * Union used when building in test mode typechecking the members of a type
 * used with confparse.c.  See CONF_CHECK_VAR_TYPE for a description of how
 * it is used. */
typedef union {
  char **STRING;
  char **FILENAME;
  int *POSINT; /* yes, this is really an int, and not an unsigned int.  For
                * historical reasons, many configuration values are restricted
                * to the range [0,INT_MAX], and stored in signed ints.
                */
  uint64_t *UINT64;
  int *INT;
  int *INTERVAL;
  int *MSEC_INTERVAL;
  uint64_t *MEMUNIT;
  double *DOUBLE;
  int *BOOL;
  int *AUTOBOOL;
  time_t *ISOTIME;
  struct smartlist_t **CSV;
  int *CSV_INTERVAL;
  struct config_line_t **LINELIST;
  struct config_line_t **LINELIST_S;
  struct config_line_t **LINELIST_V;
  // XXXX this doesn't belong at this level of abstraction.
  struct routerset_t **ROUTERSET;
} confparse_dummy_values_t;
#endif /* defined(TOR_UNIT_TESTS) */

#endif /* !defined(TOR_SRC_LIB_CONF_CONFTYPES_H) */
