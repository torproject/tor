/* Copyright (c) 2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/* Wrapper code for an ed25519 implementation. */

#include "orconfig.h"
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include "crypto.h"

#include "crypto_curve25519.h"
#include "crypto_ed25519.h"
#include "torlog.h"
#include "util.h"

#include "ed25519/ref10/ed25519_ref10.h"

int
ed25519_secret_key_generate(ed25519_secret_key_t *seckey_out,
                        int extra_strong)
{
  (void) extra_strong;
  if (ed25519_ref10_seckey(seckey_out->seckey) < 0)
    return -1;
  return 0;
}

int
ed25519_public_key_generate(ed25519_public_key_t *pubkey_out,
                        const ed25519_secret_key_t *seckey)
{
  if (ed25519_ref10_pubkey(pubkey_out->pubkey, seckey->seckey) < 0)
    return -1;
  return 0;
}

/** Generate a new ed25519 keypair in <b>keypair_out</b>.  If
 * <b>extra_strong</b> is set, try to mix some system entropy into the key
 * generation process. Return 0 on success, -1 on failure. */
int
ed25519_keypair_generate(ed25519_keypair_t *keypair_out, int extra_strong)
{
  (void) extra_strong;

  if (ed25519_ref10_keygen(keypair_out->pubkey.pubkey,
                           keypair_out->seckey.seckey)<0)
    return -1;
  return 0;
}

/**
 * Set <b>signature_out</b> to a signature of the <b>len</b>-byte message
 * <b>msg</b>, using the secret and public key in <b>keypair</b>.
 */
int
ed25519_sign(ed25519_signature_t *signature_out,
             const uint8_t *msg, size_t len,
             const ed25519_keypair_t *keypair)
{
  uint8_t keys[64];
  uint8_t *tmp;
  uint64_t tmplen;

  /* XXXX Make crypto_sign in ref10 friendlier so we don't need this stupid
   * copying. */
  tor_assert(len < SIZE_T_CEILING - 64);
  tmplen = ((uint64_t)len) + 64;
  tmp = tor_malloc(tmplen);

  memcpy(keys, keypair->seckey.seckey, 32);
  memcpy(keys+32, keypair->pubkey.pubkey, 32);

  if (ed25519_ref10_sign(tmp, &tmplen, msg, len, keys) < 0) {
    tor_free(tmp);
    return -1;
  }

  memcpy(signature_out->sig, tmp, 64);
  memwipe(keys, 0, sizeof(keys));

  tor_free(tmp);

  return 0;
}

/**
 * Check whether if <b>signature</b> is a valid signature for the
 * <b>len</b>-byte message in <b>msg</b> made with the key <b>pubkey</b>.
 *
 * Return 0 if the signature is valid; -1 if it isn't.
 */
int
ed25519_checksig(const ed25519_signature_t *signature,
                 const uint8_t *msg, size_t len,
                 const ed25519_public_key_t *pubkey)
{
  uint8_t *smtmp;
  uint8_t *tmp;
  uint64_t tmplen;
  int r;

  tor_assert(len < SIZE_T_CEILING - 64);
  tmplen = len + 64;
  tmp = tor_malloc(tmplen);
  smtmp = tor_malloc(tmplen);
  memcpy(smtmp, signature->sig, 64);
  memcpy(smtmp+64, msg, len);

  r = ed25519_ref10_open(tmp, &tmplen, smtmp, tmplen, pubkey->pubkey);

  tor_free(tmp);
  tor_free(smtmp);

  return r;
}

/** Validate every signature among those in <b>checkable</b>, which contains
 * exactly <b>n_checkable</b> elements.  If <b>okay_out</b> is non-NULL, set
 * the i'th element of <b>okay_out</b> to 1 if the i'th element of
 * <b>checkable</b> is valid, and to 0 otherwise.  Return 0 if every signature
 * was valid. Otherwise return -N, where N is the number of invalid
 * signatures.
 */
int
ed25519_checksig_batch(int *okay_out,
                       const ed25519_checkable_t *checkable,
                       int n_checkable)
{
  int res, i;

  res = 0;
  for (i = 0; i < n_checkable; ++i) {
    const ed25519_checkable_t *ch = &checkable[i];
    int r = ed25519_checksig(&ch->signature, ch->msg, ch->len, ch->pubkey);
    if (r < 0)
      --res;
    if (okay_out)
      okay_out[i] = (r == 0);
  }

#if 0
  const uint8_t **ms;
  size_t *lens;
  const uint8_t **pks;
  const uint8_t **sigs;
  int *oks;

  ms = tor_malloc(sizeof(uint8_t*)*n_checkable);
  lens = tor_malloc(sizeof(size_t)*n_checkable);
  pks = tor_malloc(sizeof(uint8_t*)*n_checkable);
  sigs = tor_malloc(sizeof(uint8_t*)*n_checkable);
  oks = okay_out ? okay_out : tor_malloc(sizeof(int)*n_checkable);

  for (i = 0; i < n_checkable; ++i) {
    ms[i] = checkable[i].msg;
    lens[i] = checkable[i].len;
    pks[i] = checkable[i].pubkey->pubkey;
    sigs[i] = checkable[i].signature.sig;
    oks[i] = 0;
  }

  ed25519_sign_open_batch_donna_fb(ms, lens, pks, sigs, n_checkable, oks);

  res = 0;
  for (i = 0; i < n_checkable; ++i) {
    if (!oks[i])
      --res;
  }

  tor_free(ms);
  tor_free(lens);
  tor_free(pks);
  if (! okay_out)
    tor_free(oks);
#endif

  return res;
}

