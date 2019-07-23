/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file typedvar.h
 * @brief Header for lib/confmgt/typedvar.c
 **/

#ifndef TOR_LIB_CONFMGT_TYPEDVAR_H
#define TOR_LIB_CONFMGT_TYPEDVAR_H

#include <stdbool.h>

enum config_type_t;
struct config_line_t;

typedef struct var_type_fns_t var_type_fns_t;
typedef struct var_type_def_t var_type_def_t;

int typed_var_assign(void *target, const char *value, char **errmsg,
                     enum config_type_t type);
void typed_var_free(void *target, enum config_type_t type);
char *typed_var_encode(const void *value, enum config_type_t type);
int typed_var_copy(void *dest, const void *src, enum config_type_t type);
bool typed_var_eq(const void *a, const void *b, enum config_type_t type);
bool typed_var_ok(const void *value, enum config_type_t type);

int typed_var_kvassign(void *target, const struct config_line_t *line,
                       char **errmsg, enum config_type_t type);
struct config_line_t *typed_var_kvencode(const char *key, const void *value,
                                         enum config_type_t type);

int typed_var_assign_ex(void *target, const char *value, char **errmsg,
                        const var_type_def_t *def);
void typed_var_free_ex(void *target, const var_type_def_t *def);
char *typed_var_encode_ex(const void *value, const var_type_def_t *def);
int typed_var_copy_ex(void *dest, const void *src, const var_type_def_t *def);
bool typed_var_eq_ex(const void *a, const void *b, const var_type_def_t *def);
bool typed_var_ok_ex(const void *value, const var_type_def_t *def);

int typed_var_kvassign_ex(void *target, const struct config_line_t *line,
                           char **errmsg, const var_type_def_t *def);
struct config_line_t *typed_var_kvencode_ex(const char *key, const void *value,
                                            const var_type_def_t *def);

#endif /* !defined(TOR_LIB_CONFMGT_TYPEDVAR_H) */
