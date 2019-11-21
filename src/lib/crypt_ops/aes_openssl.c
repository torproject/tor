/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file aes_openssl.c
 * \brief Use OpenSSL to implement AES_CTR.
 **/

#include "orconfig.h"
#include "lib/crypt_ops/aes.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/log/util_bug.h"
#include "lib/arch/bytes.h"

#ifdef _WIN32 /*wrkard for dtls1.h >= 0.9.8m of "#include <winsock.h>"*/
  #include <winsock2.h>
  #include <ws2tcpip.h>
#endif

#include "lib/crypt_ops/compat_openssl.h"
#include <openssl/opensslv.h>
#include "lib/crypt_ops/crypto_openssl_mgt.h"

#if OPENSSL_VERSION_NUMBER < OPENSSL_V_SERIES(1,1,1)
#error "We require OpenSSL >= 1.1.1"
#endif

DISABLE_GCC_WARNING(redundant-decls)

#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/modes.h>

ENABLE_GCC_WARNING(redundant-decls)

#include "lib/crypt_ops/aes.h"
#include "lib/log/log.h"
#include "lib/ctime/di_ops.h"

/**
 * Return a newly allocated counter-mode AES128 cipher implementation,
 * using the <b>key_bits</b>-bit key <b>key</b> and the 128-bit IV <b>iv</b>.
 */
aes_cnt_cipher_t *
aes_new_cipher(const uint8_t *key, const uint8_t *iv, int key_bits)
{
  EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
  const EVP_CIPHER *c = NULL;
  switch (key_bits) {
    case 128: c = EVP_aes_128_ctr(); break;
    case 192: c = EVP_aes_192_ctr(); break;
    case 256: c = EVP_aes_256_ctr(); break;
    default: tor_assert_unreached(); // LCOV_EXCL_LINE
  }
  EVP_EncryptInit(cipher, c, key, iv);
  return (aes_cnt_cipher_t *) cipher;
}
/**
 * Release storage held by <b>cipher</b>
 */
void
aes_cipher_free_(aes_cnt_cipher_t *cipher_)
{
  if (!cipher_)
    return;
  EVP_CIPHER_CTX *cipher = (EVP_CIPHER_CTX *) cipher_;
  EVP_CIPHER_CTX_reset(cipher);
  EVP_CIPHER_CTX_free(cipher);
}
/** Encrypt <b>len</b> bytes from <b>input</b>, storing the results in place.
 * Uses the key in <b>cipher</b>, and advances the counter by <b>len</b> bytes
 * as it encrypts.
 */
void
aes_crypt_inplace(aes_cnt_cipher_t *cipher_, char *data, size_t len)
{
  int outl;
  EVP_CIPHER_CTX *cipher = (EVP_CIPHER_CTX *) cipher_;

  tor_assert(len < INT_MAX);

  EVP_EncryptUpdate(cipher, (unsigned char*)data,
                    &outl, (unsigned char*)data, (int)len);
}
