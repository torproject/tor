/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_TORTLS_H
#define TOR_TORTLS_H

/**
 * \file tortls.h
 * \brief Headers for tortls.c
 **/

#include "lib/crypt_ops/crypto_rsa.h"
#include "lib/testsupport/testsupport.h"

/* Opaque structure to hold a TLS connection. */
typedef struct tor_tls_t tor_tls_t;

struct tor_x509_cert_t;

/* Possible return values for most tor_tls_* functions. */
#define MIN_TOR_TLS_ERROR_VAL_     -9
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

#ifdef TORTLS_PRIVATE

#ifdef ENABLE_OPENSSL
struct ssl_st;
struct ssl_ctx_st;
struct ssl_session_st;
#endif

/** Holds a SSL_CTX object and related state used to configure TLS
 * connections.
 */
typedef struct tor_tls_context_t tor_tls_context_t;

STATIC int tor_errno_to_tls_error(int e);
STATIC int tor_tls_get_error(tor_tls_t *tls, int r, int extra,
                  const char *doing, int severity, int domain);
STATIC tor_tls_t *tor_tls_get_by_ssl(const struct ssl_st *ssl);
STATIC void tor_tls_allocate_tor_tls_object_ex_data_index(void);
MOCK_DECL(STATIC void, try_to_extract_certs_from_tls,
          (int severity, tor_tls_t *tls, struct x509_st **cert_out,
           struct x509_st **id_cert_out));
#ifdef TORTLS_OPENSSL_PRIVATE
STATIC int always_accept_verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx);
STATIC int tor_tls_classify_client_ciphers(const struct ssl_st *ssl,
                                           STACK_OF(SSL_CIPHER) *peer_ciphers);
#endif
STATIC int tor_tls_client_is_using_v2_ciphers(const struct ssl_st *ssl);
#ifndef HAVE_SSL_SESSION_GET_MASTER_KEY
STATIC size_t SSL_SESSION_get_master_key(struct ssl_session_st *s,
                                         uint8_t *out,
                                         size_t len);
#endif
STATIC void tor_tls_debug_state_callback(const struct ssl_st *ssl,
                                         int type, int val);
STATIC void tor_tls_server_info_callback(const struct ssl_st *ssl,
                                         int type, int val);
#ifdef TORTLS_OPENSSL_PRIVATE
STATIC int tor_tls_session_secret_cb(struct ssl_st *ssl, void *secret,
                            int *secret_len,
                            STACK_OF(SSL_CIPHER) *peer_ciphers,
                            CONST_IF_OPENSSL_1_1_API SSL_CIPHER **cipher,
                            void *arg);
STATIC int find_cipher_by_id(const SSL *ssl, const SSL_METHOD *m,
                             uint16_t cipher);
#endif /* defined(TORTLS_OPENSSL_PRIVATE) */
STATIC tor_tls_context_t *tor_tls_context_new(crypto_pk_t *identity,
                   unsigned int key_lifetime, unsigned flags, int is_client);
STATIC int tor_tls_context_init_one(tor_tls_context_t **ppcontext,
                                    crypto_pk_t *identity,
                                    unsigned int key_lifetime,
                                    unsigned int flags,
                                    int is_client);

#ifdef TOR_UNIT_TESTS
extern int tor_tls_object_ex_data_index;
extern tor_tls_context_t *server_tls_context;
extern tor_tls_context_t *client_tls_context;
extern uint16_t v2_cipher_list[];
extern uint64_t total_bytes_written_over_tls;
extern uint64_t total_bytes_written_by_tls;

#endif /* defined(TOR_UNIT_TESTS) */

#endif /* defined(TORTLS_PRIVATE) */

const char *tor_tls_err_to_string(int err);
void tor_tls_get_state_description(tor_tls_t *tls, char *buf, size_t sz);

void tor_tls_free_all(void);

#define TOR_TLS_CTX_IS_PUBLIC_SERVER (1u<<0)
#define TOR_TLS_CTX_USE_ECDHE_P256   (1u<<1)
#define TOR_TLS_CTX_USE_ECDHE_P224   (1u<<2)

void tor_tls_init(void);
void tls_log_errors(tor_tls_t *tls, int severity, int domain,
                    const char *doing);
int tor_tls_context_init(unsigned flags,
                         crypto_pk_t *client_identity,
                         crypto_pk_t *server_identity,
                         unsigned int key_lifetime);
tor_tls_t *tor_tls_new(int sock, int is_server);
void tor_tls_set_logged_address(tor_tls_t *tls, const char *address);
void tor_tls_set_renegotiate_callback(tor_tls_t *tls,
                                      void (*cb)(tor_tls_t *, void *arg),
                                      void *arg);
int tor_tls_is_server(tor_tls_t *tls);
void tor_tls_free_(tor_tls_t *tls);
#define tor_tls_free(tls) FREE_AND_NULL(tor_tls_t, tor_tls_free_, (tls))
int tor_tls_peer_has_cert(tor_tls_t *tls);
MOCK_DECL(struct tor_x509_cert_t *,tor_tls_get_peer_cert,(tor_tls_t *tls));
MOCK_DECL(struct tor_x509_cert_t *,tor_tls_get_own_cert,(tor_tls_t *tls));
int tor_tls_verify(int severity, tor_tls_t *tls, crypto_pk_t **identity);
int tor_tls_check_lifetime(int severity,
                           tor_tls_t *tls, time_t now,
                           int past_tolerance,
                           int future_tolerance);
MOCK_DECL(int, tor_tls_read, (tor_tls_t *tls, char *cp, size_t len));
int tor_tls_write(tor_tls_t *tls, const char *cp, size_t n);
int tor_tls_handshake(tor_tls_t *tls);
int tor_tls_finish_handshake(tor_tls_t *tls);
void tor_tls_unblock_renegotiation(tor_tls_t *tls);
void tor_tls_block_renegotiation(tor_tls_t *tls);
void tor_tls_assert_renegotiation_unblocked(tor_tls_t *tls);
int tor_tls_shutdown(tor_tls_t *tls);
int tor_tls_get_pending_bytes(tor_tls_t *tls);
size_t tor_tls_get_forced_write_size(tor_tls_t *tls);

void tor_tls_get_n_raw_bytes(tor_tls_t *tls,
                             size_t *n_read, size_t *n_written);

int tor_tls_get_buffer_sizes(tor_tls_t *tls,
                              size_t *rbuf_capacity, size_t *rbuf_bytes,
                              size_t *wbuf_capacity, size_t *wbuf_bytes);

MOCK_DECL(double, tls_get_write_overhead_ratio, (void));

int tor_tls_used_v1_handshake(tor_tls_t *tls);
int tor_tls_get_num_server_handshakes(tor_tls_t *tls);
int tor_tls_server_got_renegotiate(tor_tls_t *tls);
MOCK_DECL(int,tor_tls_cert_matches_key,(const tor_tls_t *tls,
                                        const struct tor_x509_cert_t *cert));
MOCK_DECL(int,tor_tls_get_tlssecrets,(tor_tls_t *tls, uint8_t *secrets_out));
MOCK_DECL(int,tor_tls_export_key_material,(
                     tor_tls_t *tls, uint8_t *secrets_out,
                     const uint8_t *context,
                     size_t context_len,
                     const char *label));

/* Log and abort if there are unhandled TLS errors in OpenSSL's error stack.
 */
#define check_no_tls_errors() check_no_tls_errors_(__FILE__,__LINE__)

void check_no_tls_errors_(const char *fname, int line);
void tor_tls_log_one_error(tor_tls_t *tls, unsigned long err,
                           int severity, int domain, const char *doing);

int tor_tls_get_my_certs(int server,
                         const struct tor_x509_cert_t **link_cert_out,
                         const struct tor_x509_cert_t **id_cert_out);
crypto_pk_t *tor_tls_get_my_client_auth_key(void);

const char *tor_tls_get_ciphersuite_name(tor_tls_t *tls);

int evaluate_ecgroup_for_tls(const char *ecgroup);

#endif /* !defined(TOR_TORTLS_H) */
