/* Copyright (c) 2003, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file tortls_nss.c
 * \brief Wrapper functions to present a consistent interface to
 * TLS and SSL X.509 functions from NSS.
 **/

#include "orconfig.h"

#define TORTLS_PRIVATE

#ifdef _WIN32 /*wrkard for dtls1.h >= 0.9.8m of "#include <winsock.h>"*/
  #include <winsock2.h>
  #include <ws2tcpip.h>
#endif

#include "lib/crypt_ops/crypto_cipher.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/crypt_ops/crypto_dh.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/tls/x509.h"
#include "lib/tls/x509_internal.h"
#include "lib/tls/tortls.h"
#include "lib/tls/tortls_st.h"
#include "lib/tls/tortls_internal.h"
#include "lib/log/util_bug.h"

int
tor_errno_to_tls_error(int e)
{
  (void)e;
  // XXXX
  return -1;
}
int
tor_tls_get_error(tor_tls_t *tls, int r, int extra,
                  const char *doing, int severity, int domain)
{
  (void)tls;
  (void)r;
  (void)extra;
  (void)doing;
  (void)severity;
  (void)domain;
  // XXXX
  return -1;
}
MOCK_IMPL(void,
try_to_extract_certs_from_tls,(int severity, tor_tls_t *tls,
                               tor_x509_cert_impl_t **cert_out,
                               tor_x509_cert_impl_t **id_cert_out))
{
  tor_assert(tls);
  tor_assert(cert_out);
  tor_assert(id_cert_out);
  (void)severity;
  // XXXX
}

tor_tls_context_t *
tor_tls_context_new(crypto_pk_t *identity,
                    unsigned int key_lifetime, unsigned flags, int is_client)
{
  tor_assert(identity);

  tor_tls_context_t *ctx = tor_malloc_zero(sizeof(tor_tls_context_t));
  ctx->refcnt = 1;

  if (! is_client) {
    if (tor_tls_context_init_certificates(ctx, identity,
                                          key_lifetime, flags) < 0) {
      goto err;
    }
  }

  // XXXX write the main body.

  goto done;
 err:
  tor_tls_context_decref(ctx);
  ctx = NULL;
 done:
  return ctx;
}

void
tor_tls_context_impl_free(struct ssl_ctx_st *ctx)
{
  (void)ctx;
  // XXXX
  // XXXX openssl type.
}

void
tor_tls_get_state_description(tor_tls_t *tls, char *buf, size_t sz)
{
  (void)tls;
  (void)buf;
  (void)sz;
  // XXXX
}

void
tor_tls_init(void)
{
  // XXXX
}
void
tls_log_errors(tor_tls_t *tls, int severity, int domain,
               const char *doing)
{
  (void)tls;
  (void)severity;
  (void)domain;
  (void)doing;
  // XXXX
}

tor_tls_t *
tor_tls_new(int sock, int is_server)
{
  (void)sock;
  (void)is_server;
  // XXXX
  return NULL;
}
void
tor_tls_set_renegotiate_callback(tor_tls_t *tls,
                                 void (*cb)(tor_tls_t *, void *arg),
                                 void *arg)
{
  tor_assert(tls);
  (void)cb;
  (void)arg;
  // XXXX;
}

void
tor_tls_free_(tor_tls_t *tls)
{
  (void)tls;
  // XXXX
}

int
tor_tls_peer_has_cert(tor_tls_t *tls)
{
  (void)tls;
  // XXXX
  return -1;
}
MOCK_IMPL(tor_x509_cert_t *,
tor_tls_get_peer_cert,(tor_tls_t *tls))
{
  tor_assert(tls);
  // XXXX
  return NULL;
}
MOCK_IMPL(tor_x509_cert_t *,
tor_tls_get_own_cert,(tor_tls_t *tls))
{
  tor_assert(tls);
  // XXXX
  return NULL;
}
int
tor_tls_verify(int severity, tor_tls_t *tls, crypto_pk_t **identity)
{
  tor_assert(tls);
  tor_assert(identity);
  (void)severity;
  // XXXX
  return -1;
}
int
tor_tls_check_lifetime(int severity,
                       tor_tls_t *tls, time_t now,
                       int past_tolerance,
                       int future_tolerance)
{
  tor_assert(tls);
  (void)severity;
  (void)now;
  (void)past_tolerance;
  (void)future_tolerance;
  // XXXX
  return -1;
}
MOCK_IMPL(int,
tor_tls_read, (tor_tls_t *tls, char *cp, size_t len))
{
  tor_assert(tls);
  tor_assert(cp);
  (void)len;
  // XXXX
  return -1;
}
int
tor_tls_write(tor_tls_t *tls, const char *cp, size_t n)
{
  tor_assert(tls);
  tor_assert(cp);
  (void)n;
  // XXXX
  return -1;
}
int
tor_tls_handshake(tor_tls_t *tls)
{
  tor_assert(tls);
  // XXXX
  return -1;
}
int
tor_tls_finish_handshake(tor_tls_t *tls)
{
  tor_assert(tls);
  // XXXX
  return -1;
}
void
tor_tls_unblock_renegotiation(tor_tls_t *tls)
{
  tor_assert(tls);
  // XXXX
}
void
tor_tls_block_renegotiation(tor_tls_t *tls)
{
  tor_assert(tls);
  // XXXX
}
void
tor_tls_assert_renegotiation_unblocked(tor_tls_t *tls)
{
  tor_assert(tls);
  // XXXX
}
int
tor_tls_shutdown(tor_tls_t *tls)
{
  tor_assert(tls);
  // XXXX
  return -1;
}
int
tor_tls_get_pending_bytes(tor_tls_t *tls)
{
  tor_assert(tls);
  // XXXX
  return -1;
}
size_t
tor_tls_get_forced_write_size(tor_tls_t *tls)
{
  tor_assert(tls);
  // XXXX
  return 0;
}
void
tor_tls_get_n_raw_bytes(tor_tls_t *tls,
                        size_t *n_read, size_t *n_written)
{
  tor_assert(tls);
  tor_assert(n_read);
  tor_assert(n_written);
  // XXXX
}

int
tor_tls_get_buffer_sizes(tor_tls_t *tls,
                         size_t *rbuf_capacity, size_t *rbuf_bytes,
                         size_t *wbuf_capacity, size_t *wbuf_bytes)
{
  tor_assert(tls);
  tor_assert(rbuf_capacity);
  tor_assert(rbuf_bytes);
  tor_assert(wbuf_capacity);
  tor_assert(wbuf_bytes);
  // XXXX
  return -1;
}
MOCK_IMPL(double,
tls_get_write_overhead_ratio, (void))
{
  // XXXX
  return 0.0;
}

int
tor_tls_used_v1_handshake(tor_tls_t *tls)
{
  tor_assert(tls);
  // XXXX
  return -1;
}
int
tor_tls_get_num_server_handshakes(tor_tls_t *tls)
{
  tor_assert(tls);
  // XXXX
  return -1;
}
int
tor_tls_server_got_renegotiate(tor_tls_t *tls)
{
  tor_assert(tls);
  // XXXX
  return -1;
}
MOCK_IMPL(int,
tor_tls_cert_matches_key,(const tor_tls_t *tls,
                          const struct tor_x509_cert_t *cert))
{
  tor_assert(tls);
  tor_assert(cert);
  // XXXX
  return 0;
}
MOCK_IMPL(int,
tor_tls_get_tlssecrets,(tor_tls_t *tls, uint8_t *secrets_out))
{
  tor_assert(tls);
  tor_assert(secrets_out);
  // XXXX
  return -1;
}
MOCK_IMPL(int,
tor_tls_export_key_material,(tor_tls_t *tls, uint8_t *secrets_out,
                             const uint8_t *context,
                             size_t context_len,
                             const char *label))
{
  tor_assert(tls);
  tor_assert(secrets_out);
  tor_assert(context);
  tor_assert(label);
  (void)context_len;
  // XXXX
  return -1;
}

void
check_no_tls_errors_(const char *fname, int line)
{
  (void)fname;
  (void)line;
  // XXXX
}
void
tor_tls_log_one_error(tor_tls_t *tls, unsigned long err,
                      int severity, int domain, const char *doing)
{
  tor_assert(tls);
  (void)err;
  (void)severity;
  (void)domain;
  (void)doing;
  // XXXX
}

const char *
tor_tls_get_ciphersuite_name(tor_tls_t *tls)
{
  tor_assert(tls);
  // XXXX
  return NULL;
}

int
evaluate_ecgroup_for_tls(const char *ecgroup)
{
  (void)ecgroup;
  // XXXX
  return -1;
}
