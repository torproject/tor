/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_COMPAT_OPENSSL_H
#define TOR_COMPAT_OPENSSL_H

#include "orconfig.h"

#ifdef ENABLE_OPENSSL

#include <openssl/opensslv.h>
#include "lib/crypt_ops/crypto_openssl_mgt.h"

/**
 * \file compat_openssl.h
 *
 * \brief compatibility definitions for working with different openssl forks
 **/

#if !defined(LIBRESSL_VERSION_NUMBER) && \
  OPENSSL_VERSION_NUMBER < OPENSSL_V_SERIES(1,1,1)
#error "We require OpenSSL >= 1.1.1"
#endif

#if defined(LIBRESSL_VERSION_NUMBER) && \
  LIBRESSL_VERSION_NUMBER < OPENSSL_V_SERIES(2,9,0)
#error "We require LibreSSL >= 2.9.0"
#endif

#ifndef OPENSSL_VERSION
#define OPENSSL_VERSION SSLEAY_VERSION
#endif

#ifdef LIBRESSL_VERSION_NUMBER
#define RAND_OpenSSL() RAND_SSLeay()
#define STATE_IS_SW_SERVER_HELLO(st)       \
  (((st) == SSL3_ST_SW_SRVR_HELLO_A) ||    \
   ((st) == SSL3_ST_SW_SRVR_HELLO_B))
#define OSSL_HANDSHAKE_STATE int
#define CONST_IF_OPENSSL
#else
#define STATE_IS_SW_SERVER_HELLO(st) \
  ((st) == TLS_ST_SW_SRVR_HELLO)
#define CONST_IF_OPENSSL const
#endif

#endif /* defined(ENABLE_OPENSSL) */

#endif /* !defined(TOR_COMPAT_OPENSSL_H) */
