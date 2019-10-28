/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file dirauth_config.h
 * @brief Header for feature/dirauth/dirauth_config.c
 **/

#ifndef TOR_FEATURE_DIRAUTH_DIRAUTH_CONFIG_H
#define TOR_FEATURE_DIRAUTH_DIRAUTH_CONFIG_H

typedef struct or_options_t or_options_t;

int options_validate_dirauth_mode(const or_options_t *old_options,
                                  or_options_t *options,
                                  char **msg);

int options_validate_dirauth_schedule(const or_options_t *old_options,
                                      or_options_t *options,
                                      char **msg);

int options_validate_dirauth_testing(const or_options_t *old_options,
                                     or_options_t *options,
                                     char **msg);

int options_transition_affects_dirauth_timing(
                             const or_options_t *old_options,
                             const or_options_t *new_options);

int options_act_dirauth(const or_options_t *old_options);

#endif /* !defined(TOR_FEATURE_DIRAUTH_DIRAUTH_CONFIG_H) */
