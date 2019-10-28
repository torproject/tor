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

#ifdef HAVE_MODULE_DIRAUTH

int options_validate_dirauth_mode(const or_options_t *old_options,
                                  or_options_t *options,
                                  char **msg);

int options_validate_dirauth_schedule(const or_options_t *old_options,
                                      or_options_t *options,
                                      char **msg);

int options_validate_dirauth_testing(const or_options_t *old_options,
                                     or_options_t *options,
                                     char **msg);

int options_act_dirauth(const or_options_t *old_options);

#else

/** When tor is compiled with the dirauth module disabled, it can't be
 * configured as a directory authority.
 *
 * Returns -1 and sets msg to a newly allocated string, if AuthoritativeDir
 * is set in options. Otherwise returns 0. */
static inline int
options_validate_dirauth_mode(const or_options_t *old_options,
                              or_options_t *options,
                              char **msg)
{
  (void)old_options;

  /* Only check the primary option for now, #29211 will disable more
   * options. */
  if (options->AuthoritativeDir) {
    /* REJECT() this configuration */
    *msg = tor_strdup("This tor was built with dirauth mode disabled. "
                      "It can not be configured with AuthoritativeDir 1.");
    return -1;
  }

  return 0;
}

#define options_validate_dirauth_schedule(old_options, options, msg) \
  (((void)(old_options)),((void)(options)),((void)(msg)),0)

#define options_validate_dirauth_testing(old_options, options, msg) \
  (((void)(old_options)),((void)(options)),((void)(msg)),0)

#define options_validate_dirauth_testing(old_options, options, msg) \
  (((void)(old_options)),((void)(options)),((void)(msg)),0)

#define options_act_dirauth(old_options) \
  (((void)(old_options)),0)

#endif /* defined(HAVE_MODULE_DIRAUTH) */

#endif /* !defined(TOR_FEATURE_DIRAUTH_DIRAUTH_CONFIG_H) */
