/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file dirauth_options.inc
 * @brief Declare configuration options for the crypto_ops module.
 **/

/** Holds configuration about our directory authority options. */
BEGIN_CONF_STRUCT(dirauth_options_t)

/** Do not permit more than this number of servers per IP address. */
CONF_VAR(AuthDirMaxServersPerAddr, POSINT, 0, "2")

END_CONF_STRUCT(dirauth_options_t)
