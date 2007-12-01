/* Copyright 2003 Roger Dingledine
 * Copyright 2004-2007 Roger Dingledine, Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef _TORTLS_H
#define _TORTLS_H
#define TORTLS_H_ID "$Id$"

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
/* Rename to unexpected close or something. XXX020 */
#define TOR_TLS_ERROR_IO           -8
#define TOR_TLS_ERROR_CONNREFUSED  -7
#define TOR_TLS_ERROR_CONNRESET    -6
#define TOR_TLS_ERROR_NO_ROUTE     -5
#define TOR_TLS_ERROR_TIMEOUT      -4
#define TOR_TLS_CLOSE              -3
#define TOR_TLS_WANTREAD           -2
#define TOR_TLS_WANTWRITE          -1
#define TOR_TLS_DONE                0

/** Use this macro in a switch statement to catch _any_ TLS error.  That way,
 * if more errors are added, your switches will still work. */
#define CASE_TOR_TLS_ERROR_ANY                  \
  case TOR_TLS_ERROR_MISC:                      \
  case TOR_TLS_ERROR_IO:                        \
  case TOR_TLS_ERROR_CONNREFUSED:               \
  case TOR_TLS_ERROR_CONNRESET:                 \
  case TOR_TLS_ERROR_NO_ROUTE:                  \
  case TOR_TLS_ERROR_TIMEOUT

/**DOCDOC*/
#define TOR_TLS_RANDOM_LEN 32

#define TOR_TLS_IS_ERROR(rv) ((rv) < TOR_TLS_CLOSE)
const char *tor_tls_err_to_string(int err);

void tor_tls_free_all(void);
int tor_tls_context_new(crypto_pk_env_t *rsa,
                        const char *nickname, unsigned int key_lifetime);
tor_tls_t *tor_tls_new(int sock, int is_server);
void tor_tls_set_renegotiate_callback(tor_tls_t *tls,
                                      void (*cb)(tor_tls_t *, void *arg),
                                      void *arg);
int tor_tls_is_server(tor_tls_t *tls);
void tor_tls_free(tor_tls_t *tls);
int tor_tls_peer_has_cert(tor_tls_t *tls);
int tor_tls_get_cert_digests(tor_tls_t *tls, char *my_digest_out,
                             char *peer_digest_out);
char *tor_tls_encode_my_certificate(tor_tls_t *tls, size_t *size_out,
                                    int conn_cert);
crypto_pk_env_t *tor_tls_dup_private_key(tor_tls_t *tls);
int tor_tls_verify_v1(int severity, tor_tls_t *tls,
                      crypto_pk_env_t **identity);
#if 0
int tor_tls_verify_certs_v2(int severity, tor_tls_t *tls,
                            const char *cert_str, size_t cert_len,
                            const char *id_cert_str, size_t id_cert_len,
                            crypto_pk_env_t **cert_key_out,
                            char *conn_cert_digest_out,
                            crypto_pk_env_t **id_key_out,
                            char *id_digest_out);
#endif
int tor_tls_check_lifetime(tor_tls_t *tls, int tolerance);
int tor_tls_read(tor_tls_t *tls, char *cp, size_t len);
int tor_tls_write(tor_tls_t *tls, const char *cp, size_t n);
int tor_tls_handshake(tor_tls_t *tls);
int tor_tls_renegotiate(tor_tls_t *tls);
int tor_tls_shutdown(tor_tls_t *tls);
int tor_tls_get_pending_bytes(tor_tls_t *tls);
size_t tor_tls_get_forced_write_size(tor_tls_t *tls);

void tor_tls_get_n_raw_bytes(tor_tls_t *tls,
                             size_t *n_read, size_t *n_written);

int tor_tls_used_v1_handshake(tor_tls_t *tls);
int tor_tls_get_random_values(tor_tls_t *tls, char *client_random_out,
                              char *server_random_out);
int tor_tls_hmac_with_master_secret(tor_tls_t *tls, char *hmac_out,
                                    const char *data, size_t data_len);

/* Log and abort if there are unhandled TLS errors in OpenSSL's error stack.
 */
#define check_no_tls_errors() _check_no_tls_errors(__FILE__,__LINE__)

void _check_no_tls_errors(const char *fname, int line);

#endif

