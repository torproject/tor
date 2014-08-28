/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "crypto.h"
#include "util.h"
#include "compat.h"

/** Implement RFC2440-style iterated-salted S2K conversion: convert the
 * <b>secret_len</b>-byte <b>secret</b> into a <b>key_out_len</b> byte
 * <b>key_out</b>.  As in RFC2440, the first 8 bytes of s2k_specifier
 * are a salt; the 9th byte describes how much iteration to do.
 * Does not support <b>key_out_len</b> &gt; DIGEST_LEN.
 */
void
secret_to_key_rfc2440(char *key_out, size_t key_out_len, const char *secret,
              size_t secret_len, const char *s2k_specifier)
{
  crypto_digest_t *d;
  uint8_t c;
  size_t count, tmplen;
  char *tmp;
  tor_assert(key_out_len < SIZE_T_CEILING);

#define EXPBIAS 6
  c = s2k_specifier[8];
  count = ((uint32_t)16 + (c & 15)) << ((c >> 4) + EXPBIAS);
#undef EXPBIAS

  tor_assert(key_out_len <= DIGEST_LEN);

  d = crypto_digest_new();
  tmplen = 8+secret_len;
  tmp = tor_malloc(tmplen);
  memcpy(tmp,s2k_specifier,8);
  memcpy(tmp+8,secret,secret_len);
  secret_len += 8;
  while (count) {
    if (count >= secret_len) {
      crypto_digest_add_bytes(d, tmp, secret_len);
      count -= secret_len;
    } else {
      crypto_digest_add_bytes(d, tmp, count);
      count = 0;
    }
  }
  crypto_digest_get_digest(d, key_out, key_out_len);
  memwipe(tmp, 0, tmplen);
  tor_free(tmp);
  crypto_digest_free(d);
}
