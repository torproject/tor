/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "compat.h"
#include "confline.h"
#include "torlog.h"
#include "util.h"

/** Helper: allocate a new configuration option mapping 'key' to 'val',
 * append it to *<b>lst</b>. */
void
config_line_append(config_line_t **lst,
                   const char *key,
                   const char *val)
{
  config_line_t *newline;

  newline = tor_malloc_zero(sizeof(config_line_t));
  newline->key = tor_strdup(key);
  newline->value = tor_strdup(val);
  newline->next = NULL;
  while (*lst)
    lst = &((*lst)->next);

  (*lst) = newline;
}

/** Return the line in <b>lines</b> whose key is exactly <b>key</b>, or NULL
 * if no such key exists. For handling commandline-only options only; other
 * options should be looked up in the appropriate data structure. */
const config_line_t *
config_line_find(const config_line_t *lines,
                 const char *key)
{
  const config_line_t *cl;
  for (cl = lines; cl; cl = cl->next) {
    if (!strcmp(cl->key, key))
      return cl;
  }
  return NULL;
}

/** Helper: parse the config string and strdup into key/value
 * strings. Set *result to the list, or NULL if parsing the string
 * failed.  Return 0 on success, -1 on failure. Warn and ignore any
 * misformatted lines.
 *
 * If <b>extended</b> is set, then treat keys beginning with / and with + as
 * indicating "clear" and "append" respectively. */
int
config_get_lines(const char *string, config_line_t **result, int extended)
{
  config_line_t *list = NULL, **next;
  char *k, *v;
  const char *parse_err;

  next = &list;
  do {
    k = v = NULL;
    string = parse_config_line_from_str_verbose(string, &k, &v, &parse_err);
    if (!string) {
      log_warn(LD_CONFIG, "Error while parsing configuration: %s",
               parse_err?parse_err:"<unknown>");
      config_free_lines(list);
      tor_free(k);
      tor_free(v);
      return -1;
    }
    if (k && v) {
      unsigned command = CONFIG_LINE_NORMAL;
      if (extended) {
        if (k[0] == '+') {
          char *k_new = tor_strdup(k+1);
          tor_free(k);
          k = k_new;
          command = CONFIG_LINE_APPEND;
        } else if (k[0] == '/') {
          char *k_new = tor_strdup(k+1);
          tor_free(k);
          k = k_new;
          tor_free(v);
          v = tor_strdup("");
          command = CONFIG_LINE_CLEAR;
        }
      }
      /* This list can get long, so we keep a pointer to the end of it
       * rather than using config_line_append over and over and getting
       * n^2 performance. */
      *next = tor_malloc_zero(sizeof(config_line_t));
      (*next)->key = k;
      (*next)->value = v;
      (*next)->next = NULL;
      (*next)->command = command;
      next = &((*next)->next);
    } else {
      tor_free(k);
      tor_free(v);
    }
  } while (*string);

  *result = list;
  return 0;
}

/**
 * Free all the configuration lines on the linked list <b>front</b>.
 */
void
config_free_lines(config_line_t *front)
{
  config_line_t *tmp;

  while (front) {
    tmp = front;
    front = tmp->next;

    tor_free(tmp->key);
    tor_free(tmp->value);
    tor_free(tmp);
  }
}

/** Return a newly allocated deep copy of the lines in <b>inp</b>. */
config_line_t *
config_lines_dup(const config_line_t *inp)
{
  return config_lines_dup_and_filter(inp, NULL);
}

/** Return a newly allocated deep copy of the lines in <b>inp</b>,
 * but only the ones that match <b>key</b>. */
config_line_t *
config_lines_dup_and_filter(const config_line_t *inp,
                            const char *key)
{
  config_line_t *result = NULL;
  config_line_t **next_out = &result;
  while (inp) {
    if (key && strcasecmpstart(inp->key, key)) {
      inp = inp->next;
      continue;
    }
    *next_out = tor_malloc_zero(sizeof(config_line_t));
    (*next_out)->key = tor_strdup(inp->key);
    (*next_out)->value = tor_strdup(inp->value);
    inp = inp->next;
    next_out = &((*next_out)->next);
  }
  (*next_out) = NULL;
  return result;
}

/** Return true iff a and b contain identical keys and values in identical
 * order. */
int
config_lines_eq(config_line_t *a, config_line_t *b)
{
  while (a && b) {
    if (strcasecmp(a->key, b->key) || strcmp(a->value, b->value))
      return 0;
    a = a->next;
    b = b->next;
  }
  if (a || b)
    return 0;
  return 1;
}

/** Return the number of lines in <b>a</b> whose key is <b>key</b>. */
int
config_count_key(const config_line_t *a, const char *key)
{
  int n = 0;
  while (a) {
    if (!strcasecmp(a->key, key)) {
      ++n;
    }
    a = a->next;
  }
  return n;
}

