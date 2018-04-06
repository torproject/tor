/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypto_util.h
 *
 * \brief Common functions for cryptographic routines.
 **/

#ifndef TOR_CRYPTO_UTIL_H
#define TOR_CRYPTO_UTIL_H

#include "torint.h"

/** OpenSSL-based utility functions. */
void memwipe(void *mem, uint8_t byte, size_t sz);

#ifdef CRYPTO_UTIL_PRIVATE
#ifdef TOR_UNIT_TESTS
#endif /* defined(TOR_UNIT_TESTS) */
#endif /* defined(CRYPTO_UTIL_PRIVATE) */

#endif /* !defined(TOR_CRYPTO_UTIL_H) */

