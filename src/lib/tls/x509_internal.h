/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_X509_INTERNAL_H
#define TOR_X509_INTERNAL_H

/**
 * \file x509.h
 * \brief Internal headers for tortls.c
 **/

#include "lib/crypt_ops/crypto_rsa.h"
#include "lib/testsupport/testsupport.h"

MOCK_DECL(tor_x509_cert_impl_t *, tor_tls_create_certificate,
                                                   (crypto_pk_t *rsa,
                                                    crypto_pk_t *rsa_sign,
                                                    const char *cname,
                                                    const char *cname_sign,
                                                  unsigned int cert_lifetime));
MOCK_DECL(tor_x509_cert_t *, tor_x509_cert_new,
          (tor_x509_cert_impl_t *x509_cert));
const tor_x509_cert_impl_t *tor_x509_cert_get_impl(
                                           const tor_x509_cert_t *cert);

#endif
