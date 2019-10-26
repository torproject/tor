/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file crypto_conf.c
 * @brief Stub definitions for a configuration for the crypto_ops subsystem.
 *
 * Not yet fully implemented; just an example.
 **/

#include "orconfig.h"
#include "lib/conf/conftypes.h"
#include "lib/crypt_ops/crypto_conf.h"
#include "lib/crypt_ops/crypto_options_st.h"

#include "lib/conf/confdecl.h"

#define CONF_CONTEXT LL_TABLE
#include "lib/crypt_ops/crypto_options.inc"
#undef CONF_CONTEXT

const config_format_t crypto_fmt = {
  .vars = crypto_options_t_vars
};
