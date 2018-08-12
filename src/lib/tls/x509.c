/* Copyright (c) 2003, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file x509_openssl.c
 * \brief Wrapper functions to present a consistent interface to
 * X.509 functions.
 **/

#define TOR_X509_PRIVATE
#include "lib/tls/x509.h"
#include "lib/log/util_bug.h"
#include "lib/crypt_ops/crypto_rand.h"

/** Choose the start and end times for a certificate */
void
tor_tls_pick_certificate_lifetime(time_t now,
                                  unsigned int cert_lifetime,
                                  time_t *start_time_out,
                                  time_t *end_time_out)
{
  time_t start_time, end_time;
  /* Make sure we're part-way through the certificate lifetime, rather
   * than having it start right now. Don't choose quite uniformly, since
   * then we might pick a time where we're about to expire. Lastly, be
   * sure to start on a day boundary. */
  /* Our certificate lifetime will be cert_lifetime no matter what, but if we
   * start cert_lifetime in the past, we'll have 0 real lifetime.  instead we
   * start up to (cert_lifetime - min_real_lifetime - start_granularity) in
   * the past. */
  const time_t min_real_lifetime = 24*3600;
  const time_t start_granularity = 24*3600;
  time_t earliest_start_time;
  /* Don't actually start in the future! */
  if (cert_lifetime <= min_real_lifetime + start_granularity) {
    earliest_start_time = now - 1;
  } else {
    earliest_start_time = now + min_real_lifetime + start_granularity
      - cert_lifetime;
  }
  start_time = crypto_rand_time_range(earliest_start_time, now);
  /* Round the start time back to the start of a day. */
  start_time -= start_time % start_granularity;

  end_time = start_time + cert_lifetime;

  *start_time_out = start_time;
  *end_time_out = end_time;
}

/** Set *<b>encoded_out</b> and *<b>size_out</b> to <b>cert</b>'s encoded DER
 * representation and length, respectively. */
void
tor_x509_cert_get_der(const tor_x509_cert_t *cert,
                 const uint8_t **encoded_out, size_t *size_out)
{
  tor_assert(cert);
  tor_assert(encoded_out);
  tor_assert(size_out);
  *encoded_out = cert->encoded;
  *size_out = cert->encoded_len;
}

/** Return the underlying implementation for <b>cert</b> */
const tor_x509_cert_impl_t *
tor_x509_cert_get_impl(const tor_x509_cert_t *cert)
{
  tor_assert(cert);
  return cert->cert;
}

/** Return a set of digests for the public key in <b>cert</b>, or NULL if this
 * cert's public key is not one we know how to take the digest of. */
const common_digests_t *
tor_x509_cert_get_id_digests(const tor_x509_cert_t *cert)
{
  if (cert->pkey_digests_set)
    return &cert->pkey_digests;
  else
    return NULL;
}

/** Return a set of digests for the public key in <b>cert</b>. */
const common_digests_t *
tor_x509_cert_get_cert_digests(const tor_x509_cert_t *cert)
{
  return &cert->cert_digests;
}

