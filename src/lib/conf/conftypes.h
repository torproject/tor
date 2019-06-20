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
#ifdef TOR_UNIT_TESTS
#include "lib/conf/conftesting.h"
#endif

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
  CONFIG_TYPE_OBSOLETE,     /**< Obsolete (ignored) option. */
  CONFIG_TYPE_EXTENDED,     /**< Extended type; definition will appear in
                             * pointer. */
} config_type_t;

/* Forward delcaration for var_type_def_t, for extended types. */
struct var_type_def_t;

/** Structure to specify a named, typed member within a structure. */
typedef struct struct_member_t {
  /** Name of the field. */
  const char *name;
  /** Type of the field, according to the config_type_t enumeration.
   *
   * This value is CONFIG_TYPE_EXTENDED for any type not listed in
   * config_type_t.
   **/
  config_type_t type;
  /**
   * Pointer to a type definition for the type of this field. Overrides
   * <b>type</b> if not NULL.
   **/
  const struct var_type_def_t *type_def;
  /**
   * Offset of this field within the structure.  Compute this with
   * offsetof(structure, fieldname).
   **/
  int offset;
} struct_member_t;

/**
 * Structure to describe the location and preferred value of a "magic number"
 * field within a structure.
 *
 * These 'magic numbers' are 32-bit values used to tag objects to make sure
 * that they have the correct type.
 */
typedef struct struct_magic_decl_t {
  const char *typename;
  uint32_t magic_val;
  int magic_offset;
} struct_magic_decl_t;

/** A variable allowed in the configuration file or on the command line. */
typedef struct config_var_t {
  struct_member_t member; /** A struct member corresponding to this
                           * variable. */
  const char *initvalue; /**< String (or null) describing initial value. */

#ifdef TOR_UNIT_TESTS
  /** Used for compiler-magic to typecheck the corresponding field in the
   * corresponding struct. Only used in unit test mode, at compile-time. */
  confparse_dummy_values_t var_ptr_dummy;
#endif
} config_var_t;

#endif /* !defined(TOR_SRC_LIB_CONF_CONFTYPES_H) */
