/* Copyright (c) 2003, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file x509_nss.c
 * \brief Wrapper functions to present a consistent interface to
 * X.509 functions from NSS.
 **/

#define TOR_X509_PRIVATE
#include "lib/tls/x509.h"
#include "lib/tls/x509_internal.h"
#include "lib/tls/tortls.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/log/util_bug.h"

#include <pk11pub.h>
#include <cert.h>

MOCK_IMPL(tor_x509_cert_impl_t *,
tor_tls_create_certificate,(crypto_pk_t *rsa,
                            crypto_pk_t *rsa_sign,
                            const char *cname,
                            const char *cname_sign,
                            unsigned int cert_lifetime))
{
  tor_assert(rsa);
  tor_assert(rsa_sign);
  tor_assert(cname);
  tor_assert(cname_sign);
  (void) cert_lifetime;
  // XXXX
  return NULL;
}

/** Set *<b>encoded_out</b> and *<b>size_out</b> to <b>cert</b>'s encoded DER
 * representation and length, respectively. */
void
tor_x509_cert_get_der(const tor_x509_cert_t *cert,
                 const uint8_t **encoded_out, size_t *size_out)
{
  tor_assert(cert);
  tor_assert(cert->cert);
  tor_assert(encoded_out);
  tor_assert(size_out);

  const SECItem *item = &cert->cert->derCert;
  *encoded_out = item->data;
  *size_out = (size_t)item->len;
}

void
tor_x509_cert_impl_free_(tor_x509_cert_impl_t *cert)
{
  if (cert)
    CERT_DestroyCertificate(cert);
}

tor_x509_cert_t *
tor_x509_cert_dup(const tor_x509_cert_t *cert)
{
  tor_assert(cert);
  // XXXX
  return NULL;
}

tor_x509_cert_t *
tor_x509_cert_decode(const uint8_t *certificate,
                     size_t certificate_len)
{
  tor_assert(certificate);
  (void) certificate_len;
  // XXXX
  return NULL;
}

crypto_pk_t *
tor_tls_cert_get_key(tor_x509_cert_t *cert)
{
  tor_assert(cert);
  // XXXXX
  return NULL;
}

int
tor_tls_cert_is_valid(int severity,
                      const tor_x509_cert_t *cert,
                      const tor_x509_cert_t *signing_cert,
                      time_t now,
                      int check_rsa_1024)
{
  tor_assert(cert);
  tor_assert(signing_cert);
  (void)severity;
  (void)now;
  (void)check_rsa_1024;
  // XXXXX

  return 0;
}

int
tor_x509_check_cert_lifetime_internal(int severity,
                                      const tor_x509_cert_impl_t *cert,
                                      time_t now,
                                      int past_tolerance,
                                      int future_tolerance)
{
  tor_assert(cert);
  (void)severity;
  (void)now;
  (void)past_tolerance;
  (void)future_tolerance;
  // XXXX
  return -1;
}

#ifdef TOR_UNIT_TESTS
tor_x509_cert_t *
tor_x509_cert_replace_expiration(const tor_x509_cert_t *inp,
                                 time_t new_expiration_time,
                                 crypto_pk_t *signing_key)
{
  tor_assert(inp);
  tor_assert(signing_key);
  (void)new_expiration_time;

  // XXXX
  return NULL;
}
#endif
