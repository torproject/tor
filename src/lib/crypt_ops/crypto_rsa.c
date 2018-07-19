/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypto_rsa.c
 * \brief Block of functions related with RSA utilities and operations.
 **/

#include "lib/crypt_ops/crypto_cipher.h"
#include "lib/crypt_ops/crypto_curve25519.h"
#include "lib/crypt_ops/crypto_digest.h"
#include "lib/crypt_ops/crypto_format.h"
#include "lib/crypt_ops/compat_openssl.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/crypt_ops/crypto_rsa.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/ctime/di_ops.h"
#include "lib/log/util_bug.h"
#include "lib/fs/files.h"

#include "lib/log/log.h"
#include "lib/encoding/binascii.h"

#include <string.h>

/** Return the number of bytes added by padding method <b>padding</b>.
 */
int
crypto_get_rsa_padding_overhead(int padding)
{
  switch (padding)
    {
    case RSA_PKCS1_OAEP_PADDING: return PKCS1_OAEP_PADDING_OVERHEAD;
    default: tor_assert(0); return -1; // LCOV_EXCL_LINE
    }
}

/** Given a padding method <b>padding</b>, return the correct OpenSSL constant.
 */
int
crypto_get_rsa_padding(int padding)
{
  switch (padding)
    {
    case PK_PKCS1_OAEP_PADDING: return RSA_PKCS1_OAEP_PADDING;
    default: tor_assert(0); return -1; // LCOV_EXCL_LINE
    }
}

/** Compare the public-key components of a and b.  Return non-zero iff
 * a==b.  A NULL key is considered to be distinct from all non-NULL
 * keys, and equal to itself.
 *
 *  Note that this may leak information about the keys through timing.
 */
int
crypto_pk_eq_keys(const crypto_pk_t *a, const crypto_pk_t *b)
{
  return (crypto_pk_cmp_keys(a, b) == 0);
}

/** Perform a hybrid (public/secret) encryption on <b>fromlen</b>
 * bytes of data from <b>from</b>, with padding type 'padding',
 * storing the results on <b>to</b>.
 *
 * Returns the number of bytes written on success, -1 on failure.
 *
 * The encrypted data consists of:
 *   - The source data, padded and encrypted with the public key, if the
 *     padded source data is no longer than the public key, and <b>force</b>
 *     is false, OR
 *   - The beginning of the source data prefixed with a 16-byte symmetric key,
 *     padded and encrypted with the public key; followed by the rest of
 *     the source data encrypted in AES-CTR mode with the symmetric key.
 *
 * NOTE that this format does not authenticate the symmetrically encrypted
 * part of the data, and SHOULD NOT BE USED for new protocols.
 */
int
crypto_pk_obsolete_public_hybrid_encrypt(crypto_pk_t *env,
                                char *to, size_t tolen,
                                const char *from,
                                size_t fromlen,
                                int padding, int force)
{
  int overhead, outlen, r;
  size_t pkeylen, symlen;
  crypto_cipher_t *cipher = NULL;
  char *buf = NULL;

  tor_assert(env);
  tor_assert(from);
  tor_assert(to);
  tor_assert(fromlen < SIZE_T_CEILING);

  overhead = crypto_get_rsa_padding_overhead(crypto_get_rsa_padding(padding));
  pkeylen = crypto_pk_keysize(env);

  if (!force && fromlen+overhead <= pkeylen) {
    /* It all fits in a single encrypt. */
    return crypto_pk_public_encrypt(env,to,
                                    tolen,
                                    from,fromlen,padding);
  }
  tor_assert(tolen >= fromlen + overhead + CIPHER_KEY_LEN);
  tor_assert(tolen >= pkeylen);

  char key[CIPHER_KEY_LEN];
  crypto_rand(key, sizeof(key)); /* generate a new key. */
  cipher = crypto_cipher_new(key);

  buf = tor_malloc(pkeylen+1);
  memcpy(buf, key, CIPHER_KEY_LEN);
  memcpy(buf+CIPHER_KEY_LEN, from, pkeylen-overhead-CIPHER_KEY_LEN);

  /* Length of symmetrically encrypted data. */
  symlen = fromlen-(pkeylen-overhead-CIPHER_KEY_LEN);

  outlen = crypto_pk_public_encrypt(env,to,tolen,buf,pkeylen-overhead,padding);
  if (outlen!=(int)pkeylen) {
    goto err;
  }
  r = crypto_cipher_encrypt(cipher, to+outlen,
                            from+pkeylen-overhead-CIPHER_KEY_LEN, symlen);

  if (r<0) goto err;
  memwipe(buf, 0, pkeylen);
  memwipe(key, 0, sizeof(key));
  tor_free(buf);
  crypto_cipher_free(cipher);
  tor_assert(outlen+symlen < INT_MAX);
  return (int)(outlen + symlen);
 err:

  memwipe(buf, 0, pkeylen);
  memwipe(key, 0, sizeof(key));
  tor_free(buf);
  crypto_cipher_free(cipher);
  return -1;
}

/** Invert crypto_pk_obsolete_public_hybrid_encrypt. Returns the number of
 * bytes written on success, -1 on failure.
 *
 * NOTE that this format does not authenticate the symmetrically encrypted
 * part of the data, and SHOULD NOT BE USED for new protocols.
 */
int
crypto_pk_obsolete_private_hybrid_decrypt(crypto_pk_t *env,
                                 char *to,
                                 size_t tolen,
                                 const char *from,
                                 size_t fromlen,
                                 int padding, int warnOnFailure)
{
  int outlen, r;
  size_t pkeylen;
  crypto_cipher_t *cipher = NULL;
  char *buf = NULL;

  tor_assert(fromlen < SIZE_T_CEILING);
  pkeylen = crypto_pk_keysize(env);

  if (fromlen <= pkeylen) {
    return crypto_pk_private_decrypt(env,to,tolen,from,fromlen,padding,
                                     warnOnFailure);
  }

  buf = tor_malloc(pkeylen);
  outlen = crypto_pk_private_decrypt(env,buf,pkeylen,from,pkeylen,padding,
                                     warnOnFailure);
  if (outlen<0) {
    log_fn(warnOnFailure?LOG_WARN:LOG_DEBUG, LD_CRYPTO,
           "Error decrypting public-key data");
    goto err;
  }
  if (outlen < CIPHER_KEY_LEN) {
    log_fn(warnOnFailure?LOG_WARN:LOG_INFO, LD_CRYPTO,
           "No room for a symmetric key");
    goto err;
  }
  cipher = crypto_cipher_new(buf);
  if (!cipher) {
    goto err;
  }
  memcpy(to,buf+CIPHER_KEY_LEN,outlen-CIPHER_KEY_LEN);
  outlen -= CIPHER_KEY_LEN;
  tor_assert(tolen - outlen >= fromlen - pkeylen);
  r = crypto_cipher_decrypt(cipher, to+outlen, from+pkeylen, fromlen-pkeylen);
  if (r<0)
    goto err;
  memwipe(buf,0,pkeylen);
  tor_free(buf);
  crypto_cipher_free(cipher);
  tor_assert(outlen + fromlen < INT_MAX);
  return (int)(outlen + (fromlen-pkeylen));
 err:
  memwipe(buf,0,pkeylen);
  tor_free(buf);
  crypto_cipher_free(cipher);
  return -1;
}

/** Given a private or public key <b>pk</b>, put a fingerprint of the
 * public key into <b>fp_out</b> (must have at least FINGERPRINT_LEN+1 bytes of
 * space).  Return 0 on success, -1 on failure.
 *
 * Fingerprints are computed as the SHA1 digest of the ASN.1 encoding
 * of the public key, converted to hexadecimal, in upper case, with a
 * space after every four digits.
 *
 * If <b>add_space</b> is false, omit the spaces.
 */
int
crypto_pk_get_fingerprint(crypto_pk_t *pk, char *fp_out, int add_space)
{
  char digest[DIGEST_LEN];
  char hexdigest[HEX_DIGEST_LEN+1];
  if (crypto_pk_get_digest(pk, digest)) {
    return -1;
  }
  base16_encode(hexdigest,sizeof(hexdigest),digest,DIGEST_LEN);
  if (add_space) {
    crypto_add_spaces_to_fp(fp_out, FINGERPRINT_LEN+1, hexdigest);
  } else {
    strncpy(fp_out, hexdigest, HEX_DIGEST_LEN+1);
  }
  return 0;
}

/** Given a private or public key <b>pk</b>, put a hashed fingerprint of
 * the public key into <b>fp_out</b> (must have at least FINGERPRINT_LEN+1
 * bytes of space).  Return 0 on success, -1 on failure.
 *
 * Hashed fingerprints are computed as the SHA1 digest of the SHA1 digest
 * of the ASN.1 encoding of the public key, converted to hexadecimal, in
 * upper case.
 */
int
crypto_pk_get_hashed_fingerprint(crypto_pk_t *pk, char *fp_out)
{
  char digest[DIGEST_LEN], hashed_digest[DIGEST_LEN];
  if (crypto_pk_get_digest(pk, digest)) {
    return -1;
  }
  if (crypto_digest(hashed_digest, digest, DIGEST_LEN) < 0) {
    return -1;
  }
  base16_encode(fp_out, FINGERPRINT_LEN + 1, hashed_digest, DIGEST_LEN);
  return 0;
}

/** Copy <b>in</b> to the <b>outlen</b>-byte buffer <b>out</b>, adding spaces
 * every four characters. */
void
crypto_add_spaces_to_fp(char *out, size_t outlen, const char *in)
{
  int n = 0;
  char *end = out+outlen;
  tor_assert(outlen < SIZE_T_CEILING);

  while (*in && out<end) {
    *out++ = *in++;
    if (++n == 4 && *in && out<end) {
      n = 0;
      *out++ = ' ';
    }
  }
  tor_assert(out<end);
  *out = '\0';
}

/** Check a siglen-byte long signature at <b>sig</b> against
 * <b>datalen</b> bytes of data at <b>data</b>, using the public key
 * in <b>env</b>. Return 0 if <b>sig</b> is a correct signature for
 * SHA1(data).  Else return -1.
 */
MOCK_IMPL(int,
crypto_pk_public_checksig_digest,(crypto_pk_t *env, const char *data,
                                  size_t datalen, const char *sig,
                                  size_t siglen))
{
  char digest[DIGEST_LEN];
  char *buf;
  size_t buflen;
  int r;

  tor_assert(env);
  tor_assert(data);
  tor_assert(sig);
  tor_assert(datalen < SIZE_T_CEILING);
  tor_assert(siglen < SIZE_T_CEILING);

  if (crypto_digest(digest,data,datalen)<0) {
    log_warn(LD_BUG, "couldn't compute digest");
    return -1;
  }
  buflen = crypto_pk_keysize(env);
  buf = tor_malloc(buflen);
  r = crypto_pk_public_checksig(env,buf,buflen,sig,siglen);
  if (r != DIGEST_LEN) {
    log_warn(LD_CRYPTO, "Invalid signature");
    tor_free(buf);
    return -1;
  }
  if (tor_memneq(buf, digest, DIGEST_LEN)) {
    log_warn(LD_CRYPTO, "Signature mismatched with digest.");
    tor_free(buf);
    return -1;
  }
  tor_free(buf);

  return 0;
}

/** Compute a SHA1 digest of <b>fromlen</b> bytes of data stored at
 * <b>from</b>; sign the data with the private key in <b>env</b>, and
 * store it in <b>to</b>.  Return the number of bytes written on
 * success, and -1 on failure.
 *
 * <b>tolen</b> is the number of writable bytes in <b>to</b>, and must be
 * at least the length of the modulus of <b>env</b>.
 */
int
crypto_pk_private_sign_digest(crypto_pk_t *env, char *to, size_t tolen,
                              const char *from, size_t fromlen)
{
  int r;
  char digest[DIGEST_LEN];
  if (crypto_digest(digest,from,fromlen)<0)
    return -1;
  r = crypto_pk_private_sign(env,to,tolen,digest,DIGEST_LEN);
  memwipe(digest, 0, sizeof(digest));
  return r;
}

/** Given a private or public key <b>pk</b>, put a SHA1 hash of the
 * public key into <b>digest_out</b> (must have DIGEST_LEN bytes of space).
 * Return 0 on success, -1 on failure.
 */
int
crypto_pk_get_digest(const crypto_pk_t *pk, char *digest_out)
{
  char *buf;
  size_t buflen;
  int len;
  int rv = -1;

  buflen = crypto_pk_keysize(pk)*2;
  buf = tor_malloc(buflen);
  len = crypto_pk_asn1_encode(pk, buf, buflen);
  if (len < 0)
    goto done;

  if (crypto_digest(digest_out, buf, len) < 0)
    goto done;

  rv = 0;
  done:
  tor_free(buf);
  return rv;
}

/** Compute all digests of the DER encoding of <b>pk</b>, and store them
 * in <b>digests_out</b>.  Return 0 on success, -1 on failure. */
int
crypto_pk_get_common_digests(crypto_pk_t *pk, common_digests_t *digests_out)
{
  char *buf;
  size_t buflen;
  int len;
  int rv = -1;

  buflen = crypto_pk_keysize(pk)*2;
  buf = tor_malloc(buflen);
  len = crypto_pk_asn1_encode(pk, buf, buflen);
  if (len < 0)
    goto done;

  if (crypto_common_digests(digests_out, (char*)buf, len) < 0)
    goto done;

  rv = 0;
 done:
  tor_free(buf);
  return rv;
}
