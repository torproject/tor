/* Copyright (c) 2012-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_CRYPTO_ED25519_H
#define TOR_CRYPTO_ED25519_H

#include "testsupport.h"
#include "torint.h"

#define ED25519_PUBKEY_LEN 32
#define ED25519_SECKEY_LEN 64
#define ED25519_SECKEY_SEED_LEN 32
#define ED25519_SIG_LEN 64

/** An Ed25519 signature. */
typedef struct {
  uint8_t sig[ED25519_SIG_LEN];
} ed25519_signature_t;

/** An Ed25519 public key */
typedef struct {
  uint8_t pubkey[ED25519_PUBKEY_LEN];
} ed25519_public_key_t;

/** An Ed25519 secret key */
typedef struct {
  uint8_t seckey[ED25519_SECKEY_LEN];
} ed25519_secret_key_t;

/** An Ed25519 keypair. */
typedef struct {
  ed25519_public_key_t pubkey;
  ed25519_secret_key_t seckey;
} ed25519_keypair_t;

#ifdef CURVE25519_ENABLED
int ed25519_secret_key_generate(ed25519_secret_key_t *seckey_out,
                            int extra_strong);
int ed25519_secret_key_from_seed(ed25519_secret_key_t *seckey_out,
                                 const uint8_t *seed);

int ed25519_public_key_generate(ed25519_public_key_t *pubkey_out,
                            const ed25519_secret_key_t *seckey);
int ed25519_keypair_generate(ed25519_keypair_t *keypair_out, int extra_strong);
int ed25519_sign(ed25519_signature_t *signature_out,
                 const uint8_t *msg, size_t len,
                 const ed25519_keypair_t *key);
int ed25519_checksig(const ed25519_signature_t *signature,
                     const uint8_t *msg, size_t len,
                     const ed25519_public_key_t *pubkey);

/**
 * A collection of information necessary to check an Ed25519 signature. Used
 * for batch verification.
 */
typedef struct {
  /** The public key that supposedly generated the signature. */
  ed25519_public_key_t *pubkey;
  /** The signature to check. */
  ed25519_signature_t signature;
  /** The message that the signature is supposed to have been applied to. */
  const uint8_t *msg;
  /** The length of the message. */
  size_t len;
} ed25519_checkable_t;

int ed25519_checksig_batch(int *okay_out,
                           const ed25519_checkable_t *checkable,
                           int n_checkable);
#endif

#define ED25519_BASE64_LEN 43

int ed25519_public_from_base64(ed25519_public_key_t *pkey,
                               const char *input);
int ed25519_public_to_base64(char *output,
                             const ed25519_public_key_t *pkey);

/* XXXX read encrypted, write encrypted. */

int ed25519_seckey_write_to_file(const ed25519_secret_key_t *seckey,
                                 const char *filename,
                                 const char *tag);
int ed25519_seckey_read_from_file(ed25519_secret_key_t *seckey_out,
                                  char **tag_out,
                                  const char *filename);
int ed25519_pubkey_write_to_file(const ed25519_public_key_t *pubkey,
                                 const char *filename,
                                 const char *tag);
int ed25519_pubkey_read_from_file(ed25519_public_key_t *pubkey_out,
                                  char **tag_out,
                                  const char *filename);


#endif

