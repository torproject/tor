/* Copyright 2003 Roger Dingledine */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef _TORTLS_H
#define _TORTLS_H

#include "../common/crypto.h"

typedef struct tor_tls_context_st tor_tls_context;
typedef struct tor_tls_st tor_tls;

#define TOR_TLS_ERROR       -4
#define TOR_TLS_CLOSE       -3
#define TOR_TLS_WANTREAD    -2
#define TOR_TLS_WANTWRITE   -1
#define TOR_TLS_DONE         0

int tor_tls_write_certificate(char *certfile, crypto_pk_env_t *rsa, char *nickname);
tor_tls_context *tor_tls_context_new(char *certfile, crypto_pk_env_t *rsa, int isServer);
tor_tls *tor_tls_new(tor_tls_context *ctx, int sock, int isServer);
void tor_tls_free(tor_tls *tls);
int tor_tls_read(tor_tls *tls, char *cp, int len);
int tor_tls_write(tor_tls *tls, char *cp, int n);
int tor_tls_handshake(tor_tls *tls);
/* XXXX we need a function to check for validated, verified peer certs. */
int tor_tls_shutdown(tor_tls *tls);

#endif
