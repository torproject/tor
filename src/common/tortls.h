/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef _TOR_TORTLS_H
#define _TOR_TORTLS_H

/**
 * \file tortls.h
 * \brief Headers for tortls.c
 **/

#include "crypto.h"
#include "compat.h"

/* Opaque structure to hold a TLS connection. */
typedef struct tor_tls_t tor_tls_t;

/* Possible return values for most tor_tls_* functions. */
#define _MIN_TOR_TLS_ERROR_VAL     -9
#define TOR_TLS_ERROR_MISC         -9
/* Rename to unexpected close or something. XXXX */
#define TOR_TLS_ERROR_IO           -8
#define TOR_TLS_ERROR_CONNREFUSED  -7
#define TOR_TLS_ERROR_CONNRESET    -6
#define TOR_TLS_ERROR_NO_ROUTE     -5
#define TOR_TLS_ERROR_TIMEOUT      -4
#define TOR_TLS_CLOSE              -3
#define TOR_TLS_WANTREAD           -2
#define TOR_TLS_WANTWRITE          -1
#define TOR_TLS_DONE                0

/** Collection of case statements for all TLS errors that are not due to
 * underlying IO failure. */
#define CASE_TOR_TLS_ERROR_ANY_NONIO            \
  case TOR_TLS_ERROR_MISC:                      \
  case TOR_TLS_ERROR_CONNREFUSED:               \
  case TOR_TLS_ERROR_CONNRESET:                 \
  case TOR_TLS_ERROR_NO_ROUTE:                  \
  case TOR_TLS_ERROR_TIMEOUT

/** Use this macro in a switch statement to catch _any_ TLS error.  That way,
 * if more errors are added, your switches will still work. */
#define CASE_TOR_TLS_ERROR_ANY                  \
  CASE_TOR_TLS_ERROR_ANY_NONIO:                 \
  case TOR_TLS_ERROR_IO

#define TOR_TLS_IS_ERROR(rv) ((rv) < TOR_TLS_CLOSE)
const char *tor_tls_err_to_string(int err);

void tor_tls_free_all(void);
int tor_tls_context_init(int is_public_server,
                         crypto_pk_env_t *client_identity,
                         crypto_pk_env_t *server_identity,
                         unsigned int key_lifetime);
tor_tls_t *tor_tls_new(int sock, int is_server);
void tor_tls_set_logged_address(tor_tls_t *tls, const char *address);
void tor_tls_set_renegotiate_callback(tor_tls_t *tls,
                                      void (*cb)(tor_tls_t *, void *arg),
                                      void *arg);
int tor_tls_is_server(tor_tls_t *tls);
void tor_tls_free(tor_tls_t *tls);
int tor_tls_peer_has_cert(tor_tls_t *tls);
int tor_tls_verify(int severity, tor_tls_t *tls, crypto_pk_env_t **identity);
int tor_tls_check_lifetime(tor_tls_t *tls, int tolerance);
int tor_tls_read(tor_tls_t *tls, char *cp, size_t len);
int tor_tls_write(tor_tls_t *tls, const char *cp, size_t n);
int tor_tls_handshake(tor_tls_t *tls);
int tor_tls_renegotiate(tor_tls_t *tls);
void tor_tls_block_renegotiation(tor_tls_t *tls);
int tor_tls_shutdown(tor_tls_t *tls);
int tor_tls_get_pending_bytes(tor_tls_t *tls);
size_t tor_tls_get_forced_write_size(tor_tls_t *tls);

void tor_tls_get_n_raw_bytes(tor_tls_t *tls,
                             size_t *n_read, size_t *n_written);

void tor_tls_get_buffer_sizes(tor_tls_t *tls,
                              size_t *rbuf_capacity, size_t *rbuf_bytes,
                              size_t *wbuf_capacity, size_t *wbuf_bytes);

int tor_tls_used_v1_handshake(tor_tls_t *tls);

/* Log and abort if there are unhandled TLS errors in OpenSSL's error stack.
 */
#define check_no_tls_errors() _check_no_tls_errors(__FILE__,__LINE__)

void _check_no_tls_errors(const char *fname, int line);

#endif

