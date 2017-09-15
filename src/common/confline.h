/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_CONFLINE_H
#define TOR_CONFLINE_H

/** Ordinary configuration line. */
#define CONFIG_LINE_NORMAL 0
/** Appends to previous configuration for the same option, even if we
 * would ordinary replace it. */
#define CONFIG_LINE_APPEND 1
/* Removes all previous configuration for an option. */
#define CONFIG_LINE_CLEAR 2

#define MAX_INCLUDE_RECURSION_LEVEL 31

/** A linked list of lines in a config file, or elsewhere */
typedef struct config_line_t {
  char *key;
  char *value;
  struct config_line_t *next;

  /** What special treatment (if any) does this line require? */
  unsigned int command:2;
  /** If true, subsequent assignments to this linelist should replace
   * it, not extend it.  Set only on the first item in a linelist in an
   * or_options_t. */
  unsigned int fragile:1;
} config_line_t;

void config_line_append(config_line_t **lst,
                        const char *key, const char *val);
void config_line_prepend(config_line_t **lst,
                         const char *key, const char *val);
config_line_t *config_lines_dup(const config_line_t *inp);
config_line_t *config_lines_dup_and_filter(const config_line_t *inp,
                                           const char *key);
const config_line_t *config_line_find(const config_line_t *lines,
                                      const char *key);
int config_lines_eq(config_line_t *a, config_line_t *b);
int config_count_key(const config_line_t *a, const char *key);
int config_get_lines(const char *string, config_line_t **result, int extended);
int config_get_lines_include(const char *string, config_line_t **result,
                             int extended, int *has_include);
void config_free_lines(config_line_t *front);
const char *parse_config_line_from_str_verbose(const char *line,
                                       char **key_out, char **value_out,
                                       const char **err_out);
#endif /* !defined(TOR_CONFLINE_H) */

