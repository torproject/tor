/* Copyright (c) 2013-2015, The Tor Project, Inc. */
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

#include <openssl/sha.h>

/**
 * Initialize a new ed25519 secret key in <b>seckey_out</b>.  If
 * <b>extra_strong</b>, take the RNG inputs directly from the operating
 * system.  Return 0 on success, -1 on failure.
 */
int
ed25519_secret_key_generate(ed25519_secret_key_t *seckey_out,
                        int extra_strong)
{
  int r;
  uint8_t seed[32];
  if (! extra_strong || crypto_strongest_rand(seed, sizeof(seed)) < 0)
    crypto_rand((char*)seed, sizeof(seed));

  r = ed25519_ref10_seckey_expand(seckey_out->seckey, seed);
  memwipe(seed, 0, sizeof(seed));

  return r < 0 ? -1 : 0;
}

/**
 * Given a 32-byte random seed in <b>seed</b>, expand it into an ed25519
 * secret key in <b>seckey_out</b>.  Return 0 on success, -1 on failure.
 */
int
ed25519_secret_key_from_seed(ed25519_secret_key_t *seckey_out,
                             const uint8_t *seed)
{
  if (ed25519_ref10_seckey_expand(seckey_out->seckey, seed) < 0)
    return -1;
  return 0;
}

/**
 * Given a secret key in <b>seckey</b>, expand it into an
 * ed25519 public key.  Return 0 on success, -1 on failure.
 */
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
  if (ed25519_secret_key_generate(&keypair_out->seckey, extra_strong) < 0)
    return -1;
  if (ed25519_public_key_generate(&keypair_out->pubkey,
                                  &keypair_out->seckey)<0)
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

  if (ed25519_ref10_sign(signature_out->sig, msg, len,
                         keypair->seckey.seckey,
                         keypair->pubkey.pubkey) < 0) {
    return -1;
  }

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
  return
    ed25519_ref10_open(signature->sig, msg, len, pubkey->pubkey) < 0 ? -1 : 0;
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
  /* This is how we'd do it if we were using ed25519_donna.  I'll keep this
   * code around here in case we ever do that. */
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

/**
 * Given a curve25519 keypair in <b>inp</b>, generate a corresponding
 * ed25519 keypair in <b>out</b>, and set <b>signbit_out</b> to the
 * sign bit of the X coordinate of the ed25519 key.
 *
 * NOTE THAT IT IS PROBABLY NOT SAFE TO USE THE GENERATED KEY FOR ANYTHING
 * OUTSIDE OF WHAT'S PRESENTED IN PROPOSAL 228.  In particular, it's probably
 * not a great idea to use it to sign attacker-supplied anything.
 */
int
ed25519_keypair_from_curve25519_keypair(ed25519_keypair_t *out,
                                        int *signbit_out,
                                        const curve25519_keypair_t *inp)
{
  const char string[] = "Derive high part of ed25519 key from curve25519 key";
  ed25519_public_key_t pubkey_check;
  SHA512_CTX ctx;
  uint8_t sha512_output[64];

  memcpy(out->seckey.seckey, inp->seckey.secret_key, 32);
  SHA512_Init(&ctx);
  SHA512_Update(&ctx, out->seckey.seckey, 32);
  SHA512_Update(&ctx, string, sizeof(string));
  SHA512_Final(sha512_output, &ctx);
  memcpy(out->seckey.seckey + 32, sha512_output, 32);

  ed25519_public_key_generate(&out->pubkey, &out->seckey);

  *signbit_out = out->pubkey.pubkey[31] >> 7;

  ed25519_public_key_from_curve25519_public_key(&pubkey_check, &inp->pubkey,
                                                *signbit_out);

  tor_assert(fast_memeq(pubkey_check.pubkey, out->pubkey.pubkey, 32));

  memwipe(&pubkey_check, 0, sizeof(pubkey_check));
  memwipe(&ctx, 0, sizeof(ctx));
  memwipe(sha512_output, 0, sizeof(sha512_output));

  return 0;
}

/**
 * Given a curve25519 public key and sign bit of X coordinate of the ed25519
 * public key, generate the corresponding ed25519 public key.
 */
int
ed25519_public_key_from_curve25519_public_key(ed25519_public_key_t *pubkey,
                                     const curve25519_public_key_t *pubkey_in,
                                     int signbit)
{
  return ed25519_ref10_pubkey_from_curve25519_pubkey(pubkey->pubkey,
                                                     pubkey_in->public_key,
                                                     signbit);
}

/**
 * Given an ed25519 keypair in <b>inp</b>, generate a corresponding
 * ed25519 keypair in <b>out</b>, blinded by the corresponding 32-byte input
 * in 'param'.
 *
 * Tor uses key blinding for the "next-generation" hidden services design:
 * service descriptors are encrypted with a key derived from the service's
 * long-term public key, and then signed with (and stored at a position
 * indexed by) a short-term key derived by blinding the long-term keys.
 */
int
ed25519_keypair_blind(ed25519_keypair_t *out,
                      const ed25519_keypair_t *inp,
                      const uint8_t *param)
{
  ed25519_public_key_t pubkey_check;

  ed25519_ref10_blind_secret_key(out->seckey.seckey,
                                  inp->seckey.seckey, param);

  ed25519_public_blind(&pubkey_check, &inp->pubkey, param);
  ed25519_public_key_generate(&out->pubkey, &out->seckey);

  tor_assert(fast_memeq(pubkey_check.pubkey, out->pubkey.pubkey, 32));

  memwipe(&pubkey_check, 0, sizeof(pubkey_check));

  return 0;
}

/**
 * Given an ed25519 public key in <b>inp</b>, generate a corresponding blinded
 * public key in <b>out</b>, blinded with the 32-byte parameter in
 * <b>param</b>.  Return 0 on sucess, -1 on railure.
 */
int
ed25519_public_blind(ed25519_public_key_t *out,
                     const ed25519_public_key_t *inp,
                     const uint8_t *param)
{
  ed25519_ref10_blind_public_key(out->pubkey, inp->pubkey, param);
  return 0;
}

/**
 * Store seckey unencrypted to <b>filename</b>, marking it with <b>tag</b>.
 * Return 0 on success, -1 on failure.
 */
int
ed25519_seckey_write_to_file(const ed25519_secret_key_t *seckey,
                             const char *filename,
                             const char *tag)
{
  return crypto_write_tagged_contents_to_file(filename,
                                              "ed25519v1-secret",
                                              tag,
                                              seckey->seckey,
                                              sizeof(seckey->seckey));
}

/**
 * Read seckey unencrypted from <b>filename</b>, storing it into
 * <b>seckey_out</b>.  Set *<b>tag_out</> to the tag it was marked with.
 * Return 0 on success, -1 on failure.
 */
int
ed25519_seckey_read_from_file(ed25519_secret_key_t *seckey_out,
                              char **tag_out,
                              const char *filename)
{
  ssize_t len;

  len = crypto_read_tagged_contents_from_file(filename, "ed25519v1-secret",
                                              tag_out, seckey_out->seckey,
                                              sizeof(seckey_out->seckey));
  if (len != sizeof(seckey_out->seckey))
    return -1;

  return 0;
}

/**
 * Store pubkey unencrypted to <b>filename</b>, marking it with <b>tag</b>.
 * Return 0 on success, -1 on failure.
 */
int
ed25519_pubkey_write_to_file(const ed25519_public_key_t *pubkey,
                             const char *filename,
                             const char *tag)
{
  return crypto_write_tagged_contents_to_file(filename,
                                              "ed25519v1-public",
                                              tag,
                                              pubkey->pubkey,
                                              sizeof(pubkey->pubkey));
}

/**
 * Store pubkey unencrypted to <b>filename</b>, marking it with <b>tag</b>.
 * Return 0 on success, -1 on failure.
 */
int
ed25519_pubkey_read_from_file(ed25519_public_key_t *pubkey_out,
                              char **tag_out,
                              const char *filename)
{
  ssize_t len;

  len = crypto_read_tagged_contents_from_file(filename, "ed25519v1-public",
                                              tag_out, pubkey_out->pubkey,
                                              sizeof(pubkey_out->pubkey));
  if (len != sizeof(pubkey_out->pubkey))
    return -1;

  return 0;
}

