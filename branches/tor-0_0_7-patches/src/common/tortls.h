/* Copyright 2003 Roger Dingledine */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef _TORTLS_H
#define _TORTLS_H

/**
 * \file tortls.h
 * \brief Headers for tortls.c
 **/

#include "../common/crypto.h"

/* Opaque structure to hold a TLS connection. */
typedef struct tor_tls_st tor_tls;

/* Possible return values for most tor_tls_* functions. */
#define TOR_TLS_ERROR       -4
#define TOR_TLS_CLOSE       -3
#define TOR_TLS_WANTREAD    -2
#define TOR_TLS_WANTWRITE   -1
#define TOR_TLS_DONE         0

int tor_tls_context_new(crypto_pk_env_t *rsa, int isServer,
                        const char *nickname, unsigned int key_lifetime);
tor_tls *tor_tls_new(int sock, int isServer);
void tor_tls_free(tor_tls *tls);
int tor_tls_peer_has_cert(tor_tls *tls);
int tor_tls_get_peer_cert_nickname(tor_tls *tls, char *buf, int buflen);
int tor_tls_verify(tor_tls *tls, crypto_pk_env_t *identity);
int tor_tls_read(tor_tls *tls, char *cp, int len);
int tor_tls_write(tor_tls *tls, char *cp, int n);
int tor_tls_handshake(tor_tls *tls);
int tor_tls_shutdown(tor_tls *tls);
int tor_tls_get_pending_bytes(tor_tls *tls);

unsigned long tor_tls_get_n_bytes_read(tor_tls *tls);
unsigned long tor_tls_get_n_bytes_written(tor_tls *tls);

/* Log and abort if there are unhandled TLS errors in OpenSSL's error stack.
 */
#define assert_no_tls_errors() _assert_no_tls_errors(__FILE__,__LINE__)

void _assert_no_tls_errors(const char *fname, int line);

#endif

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
