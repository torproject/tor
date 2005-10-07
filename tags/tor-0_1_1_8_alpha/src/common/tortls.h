/* Copyright 2003 Roger Dingledine
 * Copyright 2004-2005 Roger Dingledine, Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef _TORTLS_H
#define _TORTLS_H
#define TORTLS_H_ID "$Id$"

/**
 * \file tortls.h
 * \brief Headers for tortls.c
 **/

#include "../common/crypto.h"
#include "../common/compat.h"

/* Opaque structure to hold a TLS connection. */
typedef struct tor_tls_t tor_tls_t;

/* Possible return values for most tor_tls_* functions. */
#define TOR_TLS_ERROR       -4
#define TOR_TLS_CLOSE       -3
#define TOR_TLS_WANTREAD    -2
#define TOR_TLS_WANTWRITE   -1
#define TOR_TLS_DONE         0

void tor_tls_free_all(void);
int tor_tls_context_new(crypto_pk_env_t *rsa, int isServer,
                        const char *nickname, unsigned int key_lifetime);
tor_tls_t *tor_tls_new(int sock, int is_server, int use_no_cert);
int tor_tls_is_server(tor_tls_t *tls);
void tor_tls_free(tor_tls_t *tls);
int tor_tls_peer_has_cert(tor_tls_t *tls);
int tor_tls_get_peer_cert_nickname(tor_tls_t *tls, char *buf, size_t buflen);
int tor_tls_verify(tor_tls_t *tls, crypto_pk_env_t **identity);
int tor_tls_check_lifetime(tor_tls_t *tls, int tolerance);
int tor_tls_read(tor_tls_t *tls, char *cp, size_t len);
int tor_tls_write(tor_tls_t *tls, char *cp, size_t n);
int tor_tls_handshake(tor_tls_t *tls);
int tor_tls_shutdown(tor_tls_t *tls);
int tor_tls_get_pending_bytes(tor_tls_t *tls);

unsigned long tor_tls_get_n_bytes_read(tor_tls_t *tls);
unsigned long tor_tls_get_n_bytes_written(tor_tls_t *tls);

/* Log and abort if there are unhandled TLS errors in OpenSSL's error stack.
 */
#define check_no_tls_errors() _check_no_tls_errors(_SHORT_FILE_,__LINE__)

void _check_no_tls_errors(const char *fname, int line);

#endif

