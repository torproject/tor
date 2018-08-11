/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_X509_H
#define TOR_X509_H

/**
 * \file x509.h
 * \brief Headers for tortls.c
 **/

#include "lib/crypt_ops/crypto_rsa.h"
#include "lib/crypt_ops/compat_openssl.h"
#include "lib/testsupport/testsupport.h"

/* Opaque structure to hold an X509 certificate. */
typedef struct tor_x509_cert_t tor_x509_cert_t;

#ifdef ENABLE_OPENSSL
struct x509_st;
#endif

/** Structure that we use for a single certificate. */
struct tor_x509_cert_t {
#ifdef ENABLE_OPENSSL
  struct x509_st *cert;
#endif
  uint8_t *encoded;
  size_t encoded_len;
  unsigned pkey_digests_set : 1;
  common_digests_t cert_digests;
  common_digests_t pkey_digests;
};

MOCK_DECL(struct x509_st *, tor_tls_create_certificate,
                                                   (crypto_pk_t *rsa,
                                                    crypto_pk_t *rsa_sign,
                                                    const char *cname,
                                                    const char *cname_sign,
                                                  unsigned int cert_lifetime));
MOCK_DECL(tor_x509_cert_t *, tor_x509_cert_new,
          (struct x509_st *x509_cert));

#ifdef TOR_UNIT_TESTS
tor_x509_cert_t *tor_x509_cert_replace_expiration(
                                               const tor_x509_cert_t *inp,
                                               time_t new_expiration_time,
                                               crypto_pk_t *signing_key);
#endif

tor_x509_cert_t *tor_x509_cert_dup(const tor_x509_cert_t *cert);

void tor_x509_cert_free_(tor_x509_cert_t *cert);
#define tor_x509_cert_free(c) \
  FREE_AND_NULL(tor_x509_cert_t, tor_x509_cert_free_, (c))
tor_x509_cert_t *tor_x509_cert_decode(const uint8_t *certificate,
                            size_t certificate_len);
void tor_x509_cert_get_der(const tor_x509_cert_t *cert,
                      const uint8_t **encoded_out, size_t *size_out);
const common_digests_t *tor_x509_cert_get_id_digests(
                      const tor_x509_cert_t *cert);
const common_digests_t *tor_x509_cert_get_cert_digests(
                      const tor_x509_cert_t *cert);

crypto_pk_t *tor_tls_cert_get_key(tor_x509_cert_t *cert);
int tor_tls_cert_is_valid(int severity,
                          const tor_x509_cert_t *cert,
                          const tor_x509_cert_t *signing_cert,
                          time_t now,
                          int check_rsa_1024);

int check_cert_lifetime_internal(int severity, const X509 *cert,
                                   time_t now,
                                   int past_tolerance, int future_tolerance);

#endif
