/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypto_init.c
 *
 * \brief Initialize and shut down Tor's crypto library and subsystem.
 **/

#include "orconfig.h"

#include "lib/crypt_ops/crypto_init.h"

#include "lib/crypt_ops/crypto_curve25519.h"
#include "lib/crypt_ops/crypto_dh.h"
#include "lib/crypt_ops/crypto_ed25519.h"
#include "lib/crypt_ops/crypto_openssl_mgt.h"
#include "lib/crypt_ops/crypto_nss_mgt.h"
#include "lib/crypt_ops/crypto_rand.h"

#include "siphash.h"

/** Boolean: has OpenSSL's crypto been initialized? */
static int crypto_early_initialized_ = 0;

/** Boolean: has OpenSSL's crypto been initialized? */
static int crypto_global_initialized_ = 0;

static int have_seeded_siphash = 0;

/** Set up the siphash key if we haven't already done so. */
int
crypto_init_siphash_key(void)
{
  struct sipkey key;
  if (have_seeded_siphash)
    return 0;

  crypto_rand((char*) &key, sizeof(key));
  siphash_set_global_key(&key);
  have_seeded_siphash = 1;
  return 0;
}

/** Initialize the crypto library.  Return 0 on success, -1 on failure.
 */
int
crypto_early_init(void)
{
  if (!crypto_early_initialized_) {

    crypto_early_initialized_ = 1;

#ifdef ENABLE_OPENSSL
    crypto_openssl_early_init();
#endif
#ifdef ENABLE_NSS
    crypto_nss_early_init();
#endif

    if (crypto_seed_rng() < 0)
      return -1;
    if (crypto_init_siphash_key() < 0)
      return -1;

    curve25519_init();
    ed25519_init();
  }
  return 0;
}

/** Initialize the crypto library.  Return 0 on success, -1 on failure.
 */
int
crypto_global_init(int useAccel, const char *accelName, const char *accelDir)
{
  if (!crypto_global_initialized_) {
    if (crypto_early_init() < 0)
      return -1;

    crypto_global_initialized_ = 1;

#ifdef ENABLE_OPENSSL
    if (crypto_openssl_late_init(useAccel, accelName, accelDir) < 0)
      return -1;
#endif
#ifdef ENABLE_NSS
    if (crypto_nss_late_init() < 0)
      return -1;
#endif
  }
  return 0;
}

/** Free crypto resources held by this thread. */
void
crypto_thread_cleanup(void)
{
#ifdef ENABLE_OPENSSL
  crypto_openssl_thread_cleanup();
#endif
}

/**
 * Uninitialize the crypto library. Return 0 on success. Does not detect
 * failure.
 */
int
crypto_global_cleanup(void)
{
  crypto_dh_free_all();

#ifdef ENABLE_OPENSSL
  crypto_openssl_global_cleanup();
#endif
#ifdef ENABLE_NSS
  crypto_nss_global_cleanup();
#endif

  crypto_early_initialized_ = 0;
  crypto_global_initialized_ = 0;
  have_seeded_siphash = 0;
  siphash_unset_global_key();

  return 0;
}

/** Run operations that the crypto library requires to be happy again
 * after forking. */
void
crypto_postfork(void)
{
#ifdef ENABLE_NSS
  crypto_nss_postfork();
#endif
}
