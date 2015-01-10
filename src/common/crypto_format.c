/* Copyright (c) 2012-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/* Formatting and parsing code for crypto-related data structures. */

#include "orconfig.h"
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include "crypto.h"
#include "crypto_curve25519.h"
#include "crypto_ed25519.h"
#include "util.h"
#include "torlog.h"

int
curve25519_public_to_base64(char *output,
                            const curve25519_public_key_t *pkey)
{
  char buf[128];
  base64_encode(buf, sizeof(buf),
                (const char*)pkey->public_key, CURVE25519_PUBKEY_LEN);
  buf[CURVE25519_BASE64_PADDED_LEN] = '\0';
  memcpy(output, buf, CURVE25519_BASE64_PADDED_LEN+1);
  return 0;
}

int
curve25519_public_from_base64(curve25519_public_key_t *pkey,
                              const char *input)
{
  size_t len = strlen(input);
  if (len == CURVE25519_BASE64_PADDED_LEN - 1) {
    /* not padded */
    return digest256_from_base64((char*)pkey->public_key, input);
  } else if (len == CURVE25519_BASE64_PADDED_LEN) {
    char buf[128];
    if (base64_decode(buf, sizeof(buf), input, len) != CURVE25519_PUBKEY_LEN)
      return -1;
    memcpy(pkey->public_key, buf, CURVE25519_PUBKEY_LEN);
    return 0;
  } else {
    return -1;
  }
}

/** Try to decode the string <b>input</b> into an ed25519 public key. On
 * success, store the value in <b>pkey</b> and return 0. Otherwise return
 * -1. */
int
ed25519_public_from_base64(ed25519_public_key_t *pkey,
                           const char *input)
{
  return digest256_from_base64((char*)pkey->pubkey, input);
}

/** Encode the public key <b>pkey</b> into the buffer at <b>output</b>,
 * which must have space for ED25519_BASE64_LEN bytes of encoded key,
 * plus one byte for a terminating NUL.  Return 0 on success, -1 on failure.
 */
int
ed25519_public_to_base64(char *output,
                         const ed25519_public_key_t *pkey)
{
  return digest256_to_base64(output, (const char *)pkey->pubkey);
}

