/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef RELAY_CRYPTO_ST_H
#define RELAY_CRYPTO_ST_H

struct relay_crypto_t {
  /* crypto environments */
  /** Encryption key and counter for cells heading towards the OR at this
   * step. */
  crypto_cipher_t *f_crypto;
  /** Encryption key and counter for cells heading back from the OR at this
   * step. */
  crypto_cipher_t *b_crypto;

  /** Digest state for cells heading towards the OR at this step. */
  crypto_digest_t *f_digest; /* for integrity checking */
  /** Digest state for cells heading away from the OR at this step. */
  crypto_digest_t *b_digest;

};

#endif

