/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypto_hkdf.c
 * \brief Block of functions related with HKDF utilities and operations.
 **/

#include "crypto_hkdf.h"
#include "crypto_util.h"
#include "crypto_digest.h"

/** Given <b>key_in_len</b> bytes of negotiated randomness in <b>key_in</b>
 * ("K"), expand it into <b>key_out_len</b> bytes of negotiated key material in
 * <b>key_out</b> by taking the first <b>key_out_len</b> bytes of
 *    H(K | [00]) | H(K | [01]) | ....
 *
 * This is the key expansion algorithm used in the "TAP" circuit extension
 * mechanism; it shouldn't be used for new protocols.
 *
 * Return 0 on success, -1 on failure.
 */
int
crypto_expand_key_material_TAP(const uint8_t *key_in, size_t key_in_len,
                               uint8_t *key_out, size_t key_out_len)
{
  int i, r = -1;
  uint8_t *cp, *tmp = tor_malloc(key_in_len+1);
  uint8_t digest[DIGEST_LEN];

  /* If we try to get more than this amount of key data, we'll repeat blocks.*/
  tor_assert(key_out_len <= DIGEST_LEN*256);

  memcpy(tmp, key_in, key_in_len);
  for (cp = key_out, i=0; cp < key_out+key_out_len;
       ++i, cp += DIGEST_LEN) {
    tmp[key_in_len] = i;
    if (crypto_digest((char*)digest, (const char *)tmp, key_in_len+1) < 0)
      goto exit;
    memcpy(cp, digest, MIN(DIGEST_LEN, key_out_len-(cp-key_out)));
  }

  r = 0;
 exit:
  memwipe(tmp, 0, key_in_len+1);
  tor_free(tmp);
  memwipe(digest, 0, sizeof(digest));
  return r;
}

/** Expand some secret key material according to RFC5869, using SHA256 as the
 * underlying hash.  The <b>key_in_len</b> bytes at <b>key_in</b> are the
 * secret key material; the <b>salt_in_len</b> bytes at <b>salt_in</b> and the
 * <b>info_in_len</b> bytes in <b>info_in_len</b> are the algorithm's "salt"
 * and "info" parameters respectively.  On success, write <b>key_out_len</b>
 * bytes to <b>key_out</b> and return 0.  Assert on failure.
 */
int
crypto_expand_key_material_rfc5869_sha256(
                                    const uint8_t *key_in, size_t key_in_len,
                                    const uint8_t *salt_in, size_t salt_in_len,
                                    const uint8_t *info_in, size_t info_in_len,
                                    uint8_t *key_out, size_t key_out_len)
{
  uint8_t prk[DIGEST256_LEN];
  uint8_t tmp[DIGEST256_LEN + 128 + 1];
  uint8_t mac[DIGEST256_LEN];
  int i;
  uint8_t *outp;
  size_t tmp_len;

  crypto_hmac_sha256((char*)prk,
                     (const char*)salt_in, salt_in_len,
                     (const char*)key_in, key_in_len);

  /* If we try to get more than this amount of key data, we'll repeat blocks.*/
  tor_assert(key_out_len <= DIGEST256_LEN * 256);
  tor_assert(info_in_len <= 128);
  memset(tmp, 0, sizeof(tmp));
  outp = key_out;
  i = 1;

  while (key_out_len) {
    size_t n;
    if (i > 1) {
      memcpy(tmp, mac, DIGEST256_LEN);
      memcpy(tmp+DIGEST256_LEN, info_in, info_in_len);
      tmp[DIGEST256_LEN+info_in_len] = i;
      tmp_len = DIGEST256_LEN + info_in_len + 1;
    } else {
      memcpy(tmp, info_in, info_in_len);
      tmp[info_in_len] = i;
      tmp_len = info_in_len + 1;
    }
    crypto_hmac_sha256((char*)mac,
                       (const char*)prk, DIGEST256_LEN,
                       (const char*)tmp, tmp_len);
    n = key_out_len < DIGEST256_LEN ? key_out_len : DIGEST256_LEN;
    memcpy(outp, mac, n);
    key_out_len -= n;
    outp += n;
    ++i;
  }

  memwipe(tmp, 0, sizeof(tmp));
  memwipe(mac, 0, sizeof(mac));
  return 0;
}

