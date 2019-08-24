/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file confparse.h
 *
 * \brief Header for confparse.c.
 */

#ifndef TOR_CONFPARSE_H
#define TOR_CONFPARSE_H

#include "lib/conf/conftypes.h"
#include "lib/conf/confmacros.h"
#include "lib/testsupport/testsupport.h"

/** An abbreviation for a configuration option allowed on the command line. */
typedef struct config_abbrev_t {
  const char *abbreviated;
  const char *full;
  int commandline_only;
  int warn;
} config_abbrev_t;

typedef struct config_deprecation_t {
  const char *name;
  const char *why_deprecated;
} config_deprecation_t;

/* Handy macro for declaring "In the config file or on the command line,
 * you can abbreviate <b>tok</b>s as <b>tok</b>". */
#define PLURAL(tok) { #tok, #tok "s", 0, 0 }

/** Type of a callback to validate whether a given configuration is
 * well-formed and consistent. See options_trial_assign() for documentation
 * of arguments. */
typedef int (*validate_fn_t)(void*,void*,void*,int,char**);

/** Callback to free a configuration object. */
typedef void (*free_cfg_fn_t)(void*);

/** Information on the keys, value types, key-to-struct-member mappings,
 * variable descriptions, validation functions, and abbreviations for a
 * configuration or storage format. */
typedef struct config_format_t {
  size_t size; /**< Size of the struct that everything gets parsed into. */
  struct_magic_decl_t magic; /**< Magic number info for this struct. */
  const config_abbrev_t *abbrevs; /**< List of abbreviations that we expand
                             * when parsing this format. */
  const config_deprecation_t *deprecations; /** List of deprecated options */
  const config_var_t *vars; /**< List of variables we recognize, their default
                             * values, and where we stick them in the
                             * structure. */
  validate_fn_t validate_fn; /**< Function to validate config. */
  free_cfg_fn_t free_fn; /**< Function to free the configuration. */
  /** If present, extra denotes a LINELIST variable for unrecognized
   * lines.  Otherwise, unrecognized lines are an error. */
  const struct_member_t *extra;
} config_format_t;

/** Macro: assert that <b>cfg</b> has the right magic field for format
 * <b>fmt</b>. */
#define CONFIG_CHECK(fmt, cfg) STMT_BEGIN                               \
    tor_assert(fmt);                                                    \
    struct_check_magic((cfg), &fmt->magic);                             \
  STMT_END

#define CAL_USE_DEFAULTS      (1u<<0)
#define CAL_CLEAR_FIRST       (1u<<1)
#define CAL_WARN_DEPRECATIONS (1u<<2)

void *config_new(const config_format_t *fmt);
void config_free_(const config_format_t *fmt, void *options);
#define config_free(fmt, options) do {                \
    config_free_((fmt), (options));                   \
    (options) = NULL;                                 \
  } while (0)

struct config_line_t *config_get_assigned_option(const config_format_t *fmt,
                                          const void *options, const char *key,
                                          int escape_val);
int config_is_same(const config_format_t *fmt,
                   const void *o1, const void *o2,
                   const char *name);
void config_init(const config_format_t *fmt, void *options);
void *config_dup(const config_format_t *fmt, const void *old);
char *config_dump(const config_format_t *fmt, const void *default_options,
                  const void *options, int minimal,
                  int comment_defaults);
bool config_check_ok(const config_format_t *fmt, const void *options,
                     int severity);
int config_assign(const config_format_t *fmt, void *options,
                  struct config_line_t *list,
                  unsigned flags, char **msg);
const char *config_find_deprecation(const config_format_t *fmt,
                                     const char *key);
const config_var_t *config_find_option(const config_format_t *fmt,
                                       const char *key);
const char *config_expand_abbrev(const config_format_t *fmt,
                                 const char *option,
                                 int command_line, int warn_obsolete);
void warn_deprecated_option(const char *what, const char *why);

bool config_var_is_cumulative(const config_var_t *var);
bool config_var_is_settable(const config_var_t *var);
bool config_var_is_contained(const config_var_t *var);
bool config_var_is_invisible(const config_var_t *var);
bool config_var_is_dumpable(const config_var_t *var);

/* Helper macros to compare an option across two configuration objects */
#define CFG_EQ_BOOL(a,b,opt) ((a)->opt == (b)->opt)
#define CFG_EQ_INT(a,b,opt) ((a)->opt == (b)->opt)
#define CFG_EQ_STRING(a,b,opt) (!strcmp_opt((a)->opt, (b)->opt))
#define CFG_EQ_SMARTLIST(a,b,opt) smartlist_strings_eq((a)->opt, (b)->opt)
#define CFG_EQ_LINELIST(a,b,opt) config_lines_eq((a)->opt, (b)->opt)
#define CFG_EQ_ROUTERSET(a,b,opt) routerset_equal((a)->opt, (b)->opt)

#ifdef CONFPARSE_PRIVATE
STATIC void config_reset_line(const config_format_t *fmt, void *options,
                              const char *key, int use_defaults);
#endif

#endif /* !defined(TOR_CONFPARSE_H) */
