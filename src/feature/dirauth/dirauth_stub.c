/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file dirauth_stub.c
 * @brief Stub declarations for use when dirauth module is disabled.
 **/

#include "orconfig.h"
#include "feature/dirauth/dirauth_sys.h"

const struct subsys_fns_t sys_dirauth = {
  .name = "dirauth",
  .supported = false,
  .level = 70,
};
