/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypto_openssl.c
 *
 * \brief Block of functions related to operations from OpenSSL.
 **/

#include "compat_openssl.h"
#include "crypto_openssl_mgt.h"

DISABLE_GCC_WARNING(redundant-decls)

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/conf.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

ENABLE_GCC_WARNING(redundant-decls)

#ifndef NEW_THREAD_API
/** A number of preallocated mutexes for use by OpenSSL. */
static tor_mutex_t **openssl_mutexes_ = NULL;
/** How many mutexes have we allocated for use by OpenSSL? */
static int n_openssl_mutexes_ = 0;
#endif /* !defined(NEW_THREAD_API) */

/** Declare STATIC functions */
STATIC char * parse_openssl_version_str(const char *raw_version);
#ifndef NEW_THREAD_API
STATIC void openssl_locking_cb_(int mode, int n, const char *file, int line);
STATIC void tor_set_openssl_thread_id(CRYPTO_THREADID *threadid);
#endif

/* Returns a trimmed and human-readable version of an openssl version string
* <b>raw_version</b>. They are usually in the form of 'OpenSSL 1.0.0b 10
* May 2012' and this will parse them into a form similar to '1.0.0b' */
STATIC char *
parse_openssl_version_str(const char *raw_version)
{
  const char *end_of_version = NULL;
  /* The output should be something like "OpenSSL 1.0.0b 10 May 2012. Let's
     trim that down. */
  if (!strcmpstart(raw_version, "OpenSSL ")) {
    raw_version += strlen("OpenSSL ");
    end_of_version = strchr(raw_version, ' ');
  }

  if (end_of_version)
    return tor_strndup(raw_version,
                      end_of_version-raw_version);
  else
    return tor_strdup(raw_version);
}

static char *crypto_openssl_version_str = NULL;
/* Return a human-readable version of the run-time openssl version number. */
const char *
crypto_openssl_get_version_str(void)
{
  if (crypto_openssl_version_str == NULL) {
    const char *raw_version = OpenSSL_version(OPENSSL_VERSION);
    crypto_openssl_version_str = parse_openssl_version_str(raw_version);
  }
  return crypto_openssl_version_str;
}

static char *crypto_openssl_header_version_str = NULL;
/* Return a human-readable version of the compile-time openssl version
* number. */
const char *
crypto_openssl_get_header_version_str(void)
{
  if (crypto_openssl_header_version_str == NULL) {
    crypto_openssl_header_version_str =
                        parse_openssl_version_str(OPENSSL_VERSION_TEXT);
  }
  return crypto_openssl_header_version_str;
}

#ifndef OPENSSL_THREADS
#error OpenSSL has been built without thread support. Tor requires an \
 OpenSSL library with thread support enabled.
#endif

#ifndef NEW_THREAD_API
/** Helper: OpenSSL uses this callback to manipulate mutexes. */
STATIC void
openssl_locking_cb_(int mode, int n, const char *file, int line)
{
  (void)file;
  (void)line;
  if (!openssl_mutexes_)
    /* This is not a really good fix for the
     * "release-freed-lock-from-separate-thread-on-shutdown" problem, but
     * it can't hurt. */
    return;
  if (mode & CRYPTO_LOCK)
    tor_mutex_acquire(openssl_mutexes_[n]);
  else
    tor_mutex_release(openssl_mutexes_[n]);
}

STATIC void
tor_set_openssl_thread_id(CRYPTO_THREADID *threadid)
{
  CRYPTO_THREADID_set_numeric(threadid, tor_get_thread_id());
}
#endif /* !defined(NEW_THREAD_API) */

/** Helper: Construct mutexes, and set callbacks to help OpenSSL handle being
 * multithreaded. Returns 0. */
int
setup_openssl_threading(void)
{
#ifndef NEW_THREAD_API
  int i;
  int n = CRYPTO_num_locks();
  n_openssl_mutexes_ = n;
  openssl_mutexes_ = tor_calloc(n, sizeof(tor_mutex_t *));
  for (i=0; i < n; ++i)
    openssl_mutexes_[i] = tor_mutex_new();
  CRYPTO_set_locking_callback(openssl_locking_cb_);
  CRYPTO_THREADID_set_callback(tor_set_openssl_thread_id);
#endif /* !defined(NEW_THREAD_API) */
  return 0;
}

/** free OpenSSL variables */
void
crypto_openssl_free_all(void)
{
  tor_free(crypto_openssl_version_str);
  tor_free(crypto_openssl_header_version_str);

#ifndef NEW_THREAD_API
  if (n_openssl_mutexes_) {
    int n = n_openssl_mutexes_;
    tor_mutex_t **ms = openssl_mutexes_;
    int i;
    openssl_mutexes_ = NULL;
    n_openssl_mutexes_ = 0;
    for (i=0;i<n;++i) {
      tor_mutex_free(ms[i]);
    }
    tor_free(ms);
  }
#endif /* !defined(NEW_THREAD_API) */
}

