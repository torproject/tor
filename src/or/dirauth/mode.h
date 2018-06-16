/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file mode.h
 * \brief Standalone header file for directory authority mode.
 **/

#ifndef TOR_DIRAUTH_MODE_H
#define TOR_DIRAUTH_MODE_H

#ifdef HAVE_MODULE_DIRAUTH

#include "router.h"

/* Return true iff we believe ourselves to be a v3 authoritative directory
 * server. */
static inline int
authdir_mode_v3(const or_options_t *options)
{
  return authdir_mode(options) && options->V3AuthoritativeDir != 0;
}

#else /* HAVE_MODULE_DIRAUTH */

/* Without the dirauth module, we can't be a v3 directory authority, ever. */

static inline int
authdir_mode_v3(const or_options_t *options)
{
  (void) options;
  return 0;
}

#endif /* HAVE_MODULE_DIRAUTH */

#endif /* TOR_MODE_H */

