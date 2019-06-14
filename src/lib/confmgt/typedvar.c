/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file typedvar.c
 * @brief Functions for accessing a pointer as an object of a given type.
 *
 * These functions represent a low-level API for accessing a typed variable.
 * They are used in the configuration system to examine and set fields in
 * configuration objects used by individual modules.
 *
 * Almost no code should call these directly.
 **/

#include "orconfig.h"
#include "lib/conf/conftypes.h"
#include "lib/confmgt/type_defs.h"
#include "lib/confmgt/typedvar.h"
#include "lib/encoding/confline.h"
#include "lib/log/escape.h"
#include "lib/log/log.h"
#include "lib/log/util_bug.h"
#include "lib/malloc/malloc.h"
#include "lib/string/util_string.h"

#include "lib/confmgt/var_type_def_st.h"

#include <stddef.h>
#include <string.h>

/**
 * Try to parse a string in <b>value</b> that encodes an object of the type
 * defined by <b>def</b>.
 *
 * On success, adjust the lvalue pointed to by <b>target</b> to hold that
 * value, and return 0.  On failure, set *<b>errmsg</b> to a newly allocated
 * string holding an error message, and return -1.
 **/
int
typed_var_assign_ex(void *target, const char *value, char **errmsg,
                    const var_type_def_t *def)
{
  if (BUG(!def))
    return -1;
  // clear old value if needed.
  typed_var_free_ex(target, def);

  tor_assert(def->fns->parse);
  return def->fns->parse(target, value, errmsg, def->params);
}

/**
 * Try to parse a single line from the head of<b>line</b> that encodes an
 * object of the type defined in <b>def</b>. On success and failure, behave as
 * typed_var_assign_ex().
 *
 * All types for which keys are significant should use this function.
 *
 * Note that although multiple lines may be provided in <b>line</b>,
 * only the first one is handled by this function.
 **/
int
typed_var_kvassign_ex(void *target, const config_line_t *line,
                      char **errmsg, const var_type_def_t *def)
{
  if (BUG(!def))
    return -1;

  if (def->fns->kv_parse) {
    // We do _not_ free the old value here, since linelist options
    // sometimes have append semantics.
    return def->fns->kv_parse(target, line, errmsg, def->params);
  }

  return typed_var_assign_ex(target, line->value, errmsg, def);
}

/**
 * Release storage held by a variable in <b>target</b> of type defined by
 * <b>def</b>, and set <b>target</b> to a reasonable default.
 **/
void
typed_var_free_ex(void *target, const var_type_def_t *def)
{
  if (BUG(!def))
    return;
  if (def->fns->clear) {
    def->fns->clear(target, def->params);
  }
}

/**
 * Encode a value of type <b>def</b> pointed to by <b>value</b>, and return
 * its result in a newly allocated string.  The string may need to be escaped.
 *
 * Returns NULL if this option has a NULL value, or on internal error.
 **/
char *
typed_var_encode_ex(const void *value, const var_type_def_t *def)
{
  if (BUG(!def))
    return NULL;
  tor_assert(def->fns->encode);
  return def->fns->encode(value, def->params);
}

/**
 * As typed_var_encode_ex(), but returns a newly allocated config_line_t
 * object.  The provided <b>key</b> is used as the key of the lines, unless
 * the type is one (line a linelist) that encodes its own keys.
 *
 * This function may return a list of multiple lines.
 *
 * Returns NULL if there are no lines to encode, or on internal error.
 */
config_line_t *
typed_var_kvencode_ex(const char *key, const void *value,
                      const var_type_def_t *def)
{
  if (BUG(!def))
    return NULL;
  if (def->fns->kv_encode) {
    return def->fns->kv_encode(key, value, def->params);
  }
  char *encoded_value = typed_var_encode_ex(value, def);
  if (!encoded_value)
    return NULL;

  config_line_t *result = tor_malloc_zero(sizeof(config_line_t));
  result->key = tor_strdup(key);
  result->value = encoded_value;
  return result;
}

/**
 * Set <b>dest</b> to contain the same value as <b>src</b>. Both types
 * must be as defined by <b>def</b>.
 *
 * Return 0 on success, and -1 on failure.
 **/
int
typed_var_copy_ex(void *dest, const void *src, const var_type_def_t *def)
{
  if (BUG(!def))
    return -1;
  if (def->fns->copy) {
    // If we have been provided a copy fuction, use it.
    return def->fns->copy(dest, src, def);
  }

  // Otherwise, encode 'src' and parse the result into 'def'.
  char *enc = typed_var_encode_ex(src, def);
  if (!enc) {
    typed_var_free_ex(dest, def);
    return 0;
  }
  char *err = NULL;
  int rv = typed_var_assign_ex(dest, enc, &err, def);
  if (BUG(rv < 0)) {
    log_warn(LD_BUG, "Encoded value %s was not parseable as a %s: %s",
             escaped(enc), def->name, err?err:"");
  }
  tor_free(err);
  tor_free(enc);
  return rv;
}

/**
 * Return true if <b>a</b> and <b>b</b> are semantically equivalent.
 * Both types must be as defined by <b>def</b>.
 **/
bool
typed_var_eq_ex(const void *a, const void *b, const var_type_def_t *def)
{
  if (BUG(!def))
    return false;

  if (def->fns->eq) {
    // Use a provided eq function if we got one.
    return def->fns->eq(a, b, def->params);
  }

  // Otherwise, encode the values and compare them.
  char *enc_a = typed_var_encode_ex(a, def);
  char *enc_b = typed_var_encode_ex(b, def);
  bool eq = !strcmp_opt(enc_a,enc_b);
  tor_free(enc_a);
  tor_free(enc_b);
  return eq;
}

/**
 * Check whether <b>value</b> encodes a valid value according to the
 * type definition in <b>def</b>.
 */
bool
typed_var_ok_ex(const void *value, const var_type_def_t *def)
{
  if (BUG(!def))
    return false;

  if (def->fns->ok)
    return def->fns->ok(value, def->params);

  return true;
}

/* =====
 * The functions below take a config_type_t instead of a var_type_def_t.
 * I'd like to deprecate them eventually and use var_type_def_t everywhere,
 * but for now they make migration easier.
 * ===== */

/**
 * As typed_var_assign_ex(), but look up the definition of the configuration
 * type from a provided config_type_t enum.
 */
int
typed_var_assign(void *target, const char *value, char **errmsg,
                 config_type_t type)
{
  const var_type_def_t *def = lookup_type_def(type);
  return typed_var_assign_ex(target, value, errmsg, def);
}

/**
 * As typed_var_kvassign_ex(), but look up the definition of the configuration
 * type from a provided config_type_t enum.
 */
int
typed_var_kvassign(void *target, const config_line_t *line, char **errmsg,
                   config_type_t type)
{
  const var_type_def_t *def = lookup_type_def(type);
  return typed_var_kvassign_ex(target, line, errmsg, def);
}

/**
 * As typed_var_free_ex(), but look up the definition of the configuration
 * type from a provided config_type_t enum.
 */
void
typed_var_free(void *target, config_type_t type)
{
  const var_type_def_t *def = lookup_type_def(type);
  return typed_var_free_ex(target, def);
}

/**
 * As typed_var_encode_ex(), but look up the definition of the configuration
 * type from a provided config_type_t enum.
 */
char *
typed_var_encode(const void *value, config_type_t type)
{
  const var_type_def_t *def = lookup_type_def(type);
  return typed_var_encode_ex(value, def);
}

/**
 * As typed_var_kvencode_ex(), but look up the definition of the configuration
 * type from a provided config_type_t enum.
 */
config_line_t *
typed_var_kvencode(const char *key, const void *value, config_type_t type)
{
  const var_type_def_t *def = lookup_type_def(type);
  return typed_var_kvencode_ex(key, value, def);
}

/**
 * As typed_var_copy_ex(), but look up the definition of the configuration type
 * from a provided config_type_t enum.
 */
int
typed_var_copy(void *dest, const void *src, config_type_t type)
{
  const var_type_def_t *def = lookup_type_def(type);
  return typed_var_copy_ex(dest, src, def);
}

/**
 * As typed_var_eq_ex(), but look up the definition of the configuration type
 * from a provided config_type_t enum.
 */
bool
typed_var_eq(const void *a, const void *b, config_type_t type)
{
  const var_type_def_t *def = lookup_type_def(type);
  return typed_var_eq_ex(a, b, def);
}

/**
 * As typed_var_ok_ex(), but look up the definition of the configuration type
 * from a provided config_type_t enum.
 */
bool
typed_var_ok(const void *value, config_type_t type)
{
  const var_type_def_t *def = lookup_type_def(type);
  return typed_var_ok_ex(value, def);
}
