/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_API_INTERNAL_H
#define TOR_API_INTERNAL_H

/* The contents of this type are private; don't mess with them from outside
 * Tor. */
struct tor_main_configuration_t {
  /** As in main() */
  int argc;
  /** As in main(). This pointer is owned by the caller */
  char **argv;
};

#endif /* !defined(TOR_API_INTERNAL_H) */

