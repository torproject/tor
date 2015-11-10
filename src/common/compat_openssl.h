/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_COMPAT_OPENSSL_H
#define TOR_COMPAT_OPENSSL_H

#include <openssl/opensslv.h> 

/**
 * \file compat_openssl.h
 *
 * \brief compatability definitions for working with different openssl forks
 **/

#if OPENSSL_VERSION_NUMBER < OPENSSL_V_SERIES(1,0,0)
#error "We require OpenSSL >= 1.0.0"
#endif

#if OPENSSL_VERSION_NUMBER < OPENSSL_V_SERIES(1,1,0)
#define OPENSSL_VERSION SSLEAY_VERSION
#define OpenSSL_version(v) SSLeay_version(v)
#define OpenSSL_version_num() SSLeay()
#define RAND_OpenSSL() RAND_SSLeay()
#define tor_ERR_remove_cur_thread_state() ERR_remove_state(0)
#ifndef SSL_get_state
#define SSL_get_state(ssl) SSL_state(ssl)
#endif
#define STATE_IS_SW_SERVER_HELLO(st)       \
  (((st) == SSL3_ST_SW_SRVR_HELLO_A) ||    \
   ((st) == SSL3_ST_SW_SRVR_HELLO_B))
#define OSSL_HANDSHAKE_STATE int
#else
#define tor_ERR_remove_cur_thread_state() ERR_remove_thread_state(NULL)
#define STATE_IS_SW_SERVER_HELLO(st) \
  ((st) == TLS_ST_SW_SRVR_HELLO)
#endif

#endif
