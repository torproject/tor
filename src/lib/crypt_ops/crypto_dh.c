/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypto_dh.c
 * \brief Block of functions related with DH utilities and operations.
 *    over Z_p.  We aren't using this for any new crypto -- EC is more
 *    efficient.
 **/

#include "lib/crypt_ops/compat_openssl.h"
#include "lib/crypt_ops/crypto_dh.h"
#include "lib/crypt_ops/crypto_digest.h"
#include "lib/crypt_ops/crypto_hkdf.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/log/log.h"
#include "lib/log/util_bug.h"

/** Our DH 'g' parameter */
const unsigned DH_GENERATOR = 2;
/** This is the 1024-bit safe prime that Apache uses for its DH stuff; see
 * modules/ssl/ssl_engine_dh.c; Apache also uses a generator of 2 with this
 * prime.
 */
const char TLS_DH_PRIME[] =
  "D67DE440CBBBDC1936D693D34AFD0AD50C84D239A45F520BB88174CB98"
  "BCE951849F912E639C72FB13B4B4D7177E16D55AC179BA420B2A29FE324A"
  "467A635E81FF5901377BEDDCFD33168A461AAD3B72DAE8860078045B07A7"
  "DBCA7874087D1510EA9FCC9DDD330507DD62DB88AEAA747DE0F4D6E2BD68"
  "B0E7393E0F24218EB3";
/**
 * This is from rfc2409, section 6.2.  It's a safe prime, and
 * supposedly it equals:
 * 2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 }.
 */
const char OAKLEY_PRIME_2[] =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
  "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
  "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
  "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
  "49286651ECE65381FFFFFFFFFFFFFFFF";
