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

/* X509* tor_tls_write_certificate(char *certfile, crypto_pk_env_t *rsa, char *nickname); */
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

#endif

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
