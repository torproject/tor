/* Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/* Wrapper code for a curve25519 implementation. */

#define CRYPTO_CURVE25519_PRIVATE
#include "orconfig.h"
#include "crypto.h"
#include "crypto_curve25519.h"
#include "util.h"

/* ==============================
   Part 1: wrap a suitable curve25519 implementation as curve25519_impl
   ============================== */

#ifdef USE_CURVE25519_DONNA
int curve25519_donna(uint8_t *mypublic,
                     const uint8_t *secret, const uint8_t *basepoint);
#endif
#ifdef USE_CURVE25519_NACL
#include <crypto_scalarmult_curve25519.h>
#endif

int
curve25519_impl(uint8_t *output, const uint8_t *secret,
                const uint8_t *basepoint)
{
#ifdef USE_CURVE25519_DONNA
  return curve25519_donna(output, secret, basepoint);
#elif defined(USE_CURVE25519_NACL)
  return crypto_scalarmult_curve25519(output, secret, basepoint);
#else
#error "No implementation of curve25519 is available."
#endif
}

/* ==============================
   Part 2: Wrap curve25519_impl with some convenience types and functions.
   ============================== */

/**
 * Return true iff a curve25519_public_key_t seems valid. (It's not necessary
 * to see if the point is on the curve, since the twist is also secure, but we
 * do need to make sure that it isn't the point at infinity.) */
int
curve25519_public_key_is_ok(const curve25519_public_key_t *key)
{
  static const uint8_t zero[] =
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

  return tor_memneq(key->public_key, zero, CURVE25519_PUBKEY_LEN);
}

/** Generate a new keypair and return the secret key.  If <b>extra_strong</b>
 * is true, this key is possibly going to get used more than once, so
 * use a better-than-usual RNG. */
void
curve25519_secret_key_generate(curve25519_secret_key_t *key_out,
                               int extra_strong)
{
  (void)extra_strong;

  crypto_rand((char*)key_out->secret_key, 32);
  key_out->secret_key[0] &= 248;
  key_out->secret_key[31] &= 127;
  key_out->secret_key[31] |= 64;
}

void
curve25519_public_key_generate(curve25519_public_key_t *key_out,
                               const curve25519_secret_key_t *seckey)
{
  static const uint8_t basepoint[32] = {9};

  curve25519_impl(key_out->public_key, seckey->secret_key, basepoint);
}

/** Perform the curve25519 ECDH handshake with <b>skey</b> and <b>pkey</b>,
 * writing CURVE25519_OUTPUT_LEN bytes of output into <b>output</b>. */
void
curve25519_handshake(uint8_t *output,
                     const curve25519_secret_key_t *skey,
                     const curve25519_public_key_t *pkey)
{
  curve25519_impl(output, skey->secret_key, pkey->public_key);
}

