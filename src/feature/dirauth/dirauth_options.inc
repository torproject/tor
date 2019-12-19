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

/** Which versions of tor should we tell users to run? */
CONF_VAR(RecommendedVersions, LINELIST, 0, NULL)

/** Which versions of tor should we tell users to run on clients? */
CONF_VAR(RecommendedClientVersions, LINELIST, 0, NULL)

/** Which versions of tor should we tell users to run on relays? */
CONF_VAR(RecommendedServerVersions, LINELIST, 0, NULL)

/** Boolean: is this an authoritative directory that's willing to recommend
 * versions? */
CONF_VAR(VersioningAuthoritativeDirectory, BOOL, 0, "0")

END_CONF_STRUCT(dirauth_options_t)
