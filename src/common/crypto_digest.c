/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypto_digest.c
 * \brief Block of functions related with digest and xof utilities and
 * operations.
 **/

#include "container.h"
#include "crypto_digest.h"
#include "crypto_openssl_mgt.h"
#include "crypto_util.h"
#include "torlog.h"

#include "keccak-tiny/keccak-tiny.h"

DISABLE_GCC_WARNING(redundant-decls)

#include <openssl/hmac.h>
#include <openssl/sha.h>

ENABLE_GCC_WARNING(redundant-decls)

/* Crypto digest functions */

/** Compute the SHA1 digest of the <b>len</b> bytes on data stored in
 * <b>m</b>.  Write the DIGEST_LEN byte result into <b>digest</b>.
 * Return 0 on success, -1 on failure.
 */
int
crypto_digest(char *digest, const char *m, size_t len)
{
  tor_assert(m);
  tor_assert(digest);
  if (SHA1((const unsigned char*)m,len,(unsigned char*)digest) == NULL)
    return -1;
  return 0;
}

/** Compute a 256-bit digest of <b>len</b> bytes in data stored in <b>m</b>,
 * using the algorithm <b>algorithm</b>.  Write the DIGEST_LEN256-byte result
 * into <b>digest</b>.  Return 0 on success, -1 on failure. */
int
crypto_digest256(char *digest, const char *m, size_t len,
                 digest_algorithm_t algorithm)
{
  tor_assert(m);
  tor_assert(digest);
  tor_assert(algorithm == DIGEST_SHA256 || algorithm == DIGEST_SHA3_256);

  int ret = 0;
  if (algorithm == DIGEST_SHA256)
    ret = (SHA256((const uint8_t*)m,len,(uint8_t*)digest) != NULL);
  else
    ret = (sha3_256((uint8_t *)digest, DIGEST256_LEN,(const uint8_t *)m, len)
           > -1);

  if (!ret)
    return -1;
  return 0;
}

/** Compute a 512-bit digest of <b>len</b> bytes in data stored in <b>m</b>,
 * using the algorithm <b>algorithm</b>.  Write the DIGEST_LEN512-byte result
 * into <b>digest</b>.  Return 0 on success, -1 on failure. */
int
crypto_digest512(char *digest, const char *m, size_t len,
                 digest_algorithm_t algorithm)
{
  tor_assert(m);
  tor_assert(digest);
  tor_assert(algorithm == DIGEST_SHA512 || algorithm == DIGEST_SHA3_512);

  int ret = 0;
  if (algorithm == DIGEST_SHA512)
    ret = (SHA512((const unsigned char*)m,len,(unsigned char*)digest)
           != NULL);
  else
    ret = (sha3_512((uint8_t*)digest, DIGEST512_LEN, (const uint8_t*)m, len)
           > -1);

  if (!ret)
    return -1;
  return 0;
}

/** Set the common_digests_t in <b>ds_out</b> to contain every digest on the
 * <b>len</b> bytes in <b>m</b> that we know how to compute.  Return 0 on
 * success, -1 on failure. */
int
crypto_common_digests(common_digests_t *ds_out, const char *m, size_t len)
{
  tor_assert(ds_out);
  memset(ds_out, 0, sizeof(*ds_out));
  if (crypto_digest(ds_out->d[DIGEST_SHA1], m, len) < 0)
    return -1;
  if (crypto_digest256(ds_out->d[DIGEST_SHA256], m, len, DIGEST_SHA256) < 0)
    return -1;

  return 0;
}

/** Return the name of an algorithm, as used in directory documents. */
const char *
crypto_digest_algorithm_get_name(digest_algorithm_t alg)
{
  switch (alg) {
    case DIGEST_SHA1:
      return "sha1";
    case DIGEST_SHA256:
      return "sha256";
    case DIGEST_SHA512:
      return "sha512";
    case DIGEST_SHA3_256:
      return "sha3-256";
    case DIGEST_SHA3_512:
      return "sha3-512";
      // LCOV_EXCL_START
    default:
      tor_fragile_assert();
      return "??unknown_digest??";
      // LCOV_EXCL_STOP
  }
}

/** Given the name of a digest algorithm, return its integer value, or -1 if
 * the name is not recognized. */
int
crypto_digest_algorithm_parse_name(const char *name)
{
  if (!strcmp(name, "sha1"))
    return DIGEST_SHA1;
  else if (!strcmp(name, "sha256"))
    return DIGEST_SHA256;
  else if (!strcmp(name, "sha512"))
    return DIGEST_SHA512;
  else if (!strcmp(name, "sha3-256"))
    return DIGEST_SHA3_256;
  else if (!strcmp(name, "sha3-512"))
    return DIGEST_SHA3_512;
  else
    return -1;
}

/** Given an algorithm, return the digest length in bytes. */
size_t
crypto_digest_algorithm_get_length(digest_algorithm_t alg)
{
  switch (alg) {
    case DIGEST_SHA1:
      return DIGEST_LEN;
    case DIGEST_SHA256:
      return DIGEST256_LEN;
    case DIGEST_SHA512:
      return DIGEST512_LEN;
    case DIGEST_SHA3_256:
      return DIGEST256_LEN;
    case DIGEST_SHA3_512:
      return DIGEST512_LEN;
    default:
      tor_assert(0);              // LCOV_EXCL_LINE
      return 0; /* Unreachable */ // LCOV_EXCL_LINE
  }
}

/** Intermediate information about the digest of a stream of data. */
struct crypto_digest_t {
  digest_algorithm_t algorithm; /**< Which algorithm is in use? */
   /** State for the digest we're using.  Only one member of the
    * union is usable, depending on the value of <b>algorithm</b>. Note also
    * that space for other members might not even be allocated!
    */
  union {
    SHA_CTX sha1; /**< state for SHA1 */
    SHA256_CTX sha2; /**< state for SHA256 */
    SHA512_CTX sha512; /**< state for SHA512 */
    keccak_state sha3; /**< state for SHA3-[256,512] */
  } d;
};

#ifdef TOR_UNIT_TESTS

digest_algorithm_t
crypto_digest_get_algorithm(crypto_digest_t *digest)
{
  tor_assert(digest);

  return digest->algorithm;
}

#endif /* defined(TOR_UNIT_TESTS) */

/**
 * Return the number of bytes we need to malloc in order to get a
 * crypto_digest_t for <b>alg</b>, or the number of bytes we need to wipe
 * when we free one.
 */
static size_t
crypto_digest_alloc_bytes(digest_algorithm_t alg)
{
  /* Helper: returns the number of bytes in the 'f' field of 'st' */
#define STRUCT_FIELD_SIZE(st, f) (sizeof( ((st*)0)->f ))
  /* Gives the length of crypto_digest_t through the end of the field 'd' */
#define END_OF_FIELD(f) (offsetof(crypto_digest_t, f) + \
                         STRUCT_FIELD_SIZE(crypto_digest_t, f))
  switch (alg) {
    case DIGEST_SHA1:
      return END_OF_FIELD(d.sha1);
    case DIGEST_SHA256:
      return END_OF_FIELD(d.sha2);
    case DIGEST_SHA512:
      return END_OF_FIELD(d.sha512);
    case DIGEST_SHA3_256:
    case DIGEST_SHA3_512:
      return END_OF_FIELD(d.sha3);
    default:
      tor_assert(0); // LCOV_EXCL_LINE
      return 0;      // LCOV_EXCL_LINE
  }
#undef END_OF_FIELD
#undef STRUCT_FIELD_SIZE
}

/**
 * Internal function: create and return a new digest object for 'algorithm'.
 * Does not typecheck the algorithm.
 */
static crypto_digest_t *
crypto_digest_new_internal(digest_algorithm_t algorithm)
{
  crypto_digest_t *r = tor_malloc(crypto_digest_alloc_bytes(algorithm));
  r->algorithm = algorithm;

  switch (algorithm)
    {
    case DIGEST_SHA1:
      SHA1_Init(&r->d.sha1);
      break;
    case DIGEST_SHA256:
      SHA256_Init(&r->d.sha2);
      break;
    case DIGEST_SHA512:
      SHA512_Init(&r->d.sha512);
      break;
    case DIGEST_SHA3_256:
      keccak_digest_init(&r->d.sha3, 256);
      break;
    case DIGEST_SHA3_512:
      keccak_digest_init(&r->d.sha3, 512);
      break;
    default:
      tor_assert_unreached();
    }

  return r;
}

/** Allocate and return a new digest object to compute SHA1 digests.
 */
crypto_digest_t *
crypto_digest_new(void)
{
  return crypto_digest_new_internal(DIGEST_SHA1);
}

/** Allocate and return a new digest object to compute 256-bit digests
 * using <b>algorithm</b>.
 *
 * C_RUST_COUPLED: `external::crypto_digest::crypto_digest256_new`
 * C_RUST_COUPLED: `crypto::digest::Sha256::default`
 */
crypto_digest_t *
crypto_digest256_new(digest_algorithm_t algorithm)
{
  tor_assert(algorithm == DIGEST_SHA256 || algorithm == DIGEST_SHA3_256);
  return crypto_digest_new_internal(algorithm);
}

/** Allocate and return a new digest object to compute 512-bit digests
 * using <b>algorithm</b>. */
crypto_digest_t *
crypto_digest512_new(digest_algorithm_t algorithm)
{
  tor_assert(algorithm == DIGEST_SHA512 || algorithm == DIGEST_SHA3_512);
  return crypto_digest_new_internal(algorithm);
}

/** Deallocate a digest object.
 */
void
crypto_digest_free_(crypto_digest_t *digest)
{
  if (!digest)
    return;
  size_t bytes = crypto_digest_alloc_bytes(digest->algorithm);
  memwipe(digest, 0, bytes);
  tor_free(digest);
}

/** Add <b>len</b> bytes from <b>data</b> to the digest object.
 *
 * C_RUST_COUPLED: `external::crypto_digest::crypto_digest_add_bytess`
 * C_RUST_COUPLED: `crypto::digest::Sha256::process`
 */
void
crypto_digest_add_bytes(crypto_digest_t *digest, const char *data,
                        size_t len)
{
  tor_assert(digest);
  tor_assert(data);
  /* Using the SHA*_*() calls directly means we don't support doing
   * SHA in hardware. But so far the delay of getting the question
   * to the hardware, and hearing the answer, is likely higher than
   * just doing it ourselves. Hashes are fast.
   */
  switch (digest->algorithm) {
    case DIGEST_SHA1:
      SHA1_Update(&digest->d.sha1, (void*)data, len);
      break;
    case DIGEST_SHA256:
      SHA256_Update(&digest->d.sha2, (void*)data, len);
      break;
    case DIGEST_SHA512:
      SHA512_Update(&digest->d.sha512, (void*)data, len);
      break;
    case DIGEST_SHA3_256: /* FALLSTHROUGH */
    case DIGEST_SHA3_512:
      keccak_digest_update(&digest->d.sha3, (const uint8_t *)data, len);
      break;
    default:
      /* LCOV_EXCL_START */
      tor_fragile_assert();
      break;
      /* LCOV_EXCL_STOP */
  }
}

/** Compute the hash of the data that has been passed to the digest
 * object; write the first out_len bytes of the result to <b>out</b>.
 * <b>out_len</b> must be \<= DIGEST512_LEN.
 *
 * C_RUST_COUPLED: `external::crypto_digest::crypto_digest_get_digest`
 * C_RUST_COUPLED: `impl digest::FixedOutput for Sha256`
 */
void
crypto_digest_get_digest(crypto_digest_t *digest,
                         char *out, size_t out_len)
{
  unsigned char r[DIGEST512_LEN];
  crypto_digest_t tmpenv;
  tor_assert(digest);
  tor_assert(out);
  tor_assert(out_len <= crypto_digest_algorithm_get_length(digest->algorithm));

  /* The SHA-3 code handles copying into a temporary ctx, and also can handle
   * short output buffers by truncating appropriately. */
  if (digest->algorithm == DIGEST_SHA3_256 ||
      digest->algorithm == DIGEST_SHA3_512) {
    keccak_digest_sum(&digest->d.sha3, (uint8_t *)out, out_len);
    return;
  }

  const size_t alloc_bytes = crypto_digest_alloc_bytes(digest->algorithm);
  /* memcpy into a temporary ctx, since SHA*_Final clears the context */
  memcpy(&tmpenv, digest, alloc_bytes);
  switch (digest->algorithm) {
    case DIGEST_SHA1:
      SHA1_Final(r, &tmpenv.d.sha1);
      break;
    case DIGEST_SHA256:
      SHA256_Final(r, &tmpenv.d.sha2);
      break;
    case DIGEST_SHA512:
      SHA512_Final(r, &tmpenv.d.sha512);
      break;
//LCOV_EXCL_START
    case DIGEST_SHA3_256: /* FALLSTHROUGH */
    case DIGEST_SHA3_512:
    default:
      log_warn(LD_BUG, "Handling unexpected algorithm %d", digest->algorithm);
      /* This is fatal, because it should never happen. */
      tor_assert_unreached();
      break;
//LCOV_EXCL_STOP
  }
  memcpy(out, r, out_len);
  memwipe(r, 0, sizeof(r));
}

/** Allocate and return a new digest object with the same state as
 * <b>digest</b>
 *
 * C_RUST_COUPLED: `external::crypto_digest::crypto_digest_dup`
 * C_RUST_COUPLED: `impl Clone for crypto::digest::Sha256`
 */
crypto_digest_t *
crypto_digest_dup(const crypto_digest_t *digest)
{
  tor_assert(digest);
  const size_t alloc_bytes = crypto_digest_alloc_bytes(digest->algorithm);
  return tor_memdup(digest, alloc_bytes);
}

/** Temporarily save the state of <b>digest</b> in <b>checkpoint</b>.
 * Asserts that <b>digest</b> is a SHA1 digest object.
 */
void
crypto_digest_checkpoint(crypto_digest_checkpoint_t *checkpoint,
                         const crypto_digest_t *digest)
{
  const size_t bytes = crypto_digest_alloc_bytes(digest->algorithm);
  tor_assert(bytes <= sizeof(checkpoint->mem));
  memcpy(checkpoint->mem, digest, bytes);
}

/** Restore the state of  <b>digest</b> from <b>checkpoint</b>.
 * Asserts that <b>digest</b> is a SHA1 digest object. Requires that the
 * state was previously stored with crypto_digest_checkpoint() */
void
crypto_digest_restore(crypto_digest_t *digest,
                      const crypto_digest_checkpoint_t *checkpoint)
{
  const size_t bytes = crypto_digest_alloc_bytes(digest->algorithm);
  memcpy(digest, checkpoint->mem, bytes);
}

/** Replace the state of the digest object <b>into</b> with the state
 * of the digest object <b>from</b>.  Requires that 'into' and 'from'
 * have the same digest type.
 */
void
crypto_digest_assign(crypto_digest_t *into,
                     const crypto_digest_t *from)
{
  tor_assert(into);
  tor_assert(from);
  tor_assert(into->algorithm == from->algorithm);
  const size_t alloc_bytes = crypto_digest_alloc_bytes(from->algorithm);
  memcpy(into,from,alloc_bytes);
}

/** Given a list of strings in <b>lst</b>, set the <b>len_out</b>-byte digest
 * at <b>digest_out</b> to the hash of the concatenation of those strings,
 * plus the optional string <b>append</b>, computed with the algorithm
 * <b>alg</b>.
 * <b>out_len</b> must be \<= DIGEST512_LEN. */
void
crypto_digest_smartlist(char *digest_out, size_t len_out,
                        const smartlist_t *lst,
                        const char *append,
                        digest_algorithm_t alg)
{
  crypto_digest_smartlist_prefix(digest_out, len_out, NULL, lst, append, alg);
}

/** Given a list of strings in <b>lst</b>, set the <b>len_out</b>-byte digest
 * at <b>digest_out</b> to the hash of the concatenation of: the
 * optional string <b>prepend</b>, those strings,
 * and the optional string <b>append</b>, computed with the algorithm
 * <b>alg</b>.
 * <b>len_out</b> must be \<= DIGEST512_LEN. */
void
crypto_digest_smartlist_prefix(char *digest_out, size_t len_out,
                        const char *prepend,
                        const smartlist_t *lst,
                        const char *append,
                        digest_algorithm_t alg)
{
  crypto_digest_t *d = crypto_digest_new_internal(alg);
  if (prepend)
    crypto_digest_add_bytes(d, prepend, strlen(prepend));
  SMARTLIST_FOREACH(lst, const char *, cp,
                    crypto_digest_add_bytes(d, cp, strlen(cp)));
  if (append)
    crypto_digest_add_bytes(d, append, strlen(append));
  crypto_digest_get_digest(d, digest_out, len_out);
  crypto_digest_free(d);
}

/** Compute the HMAC-SHA-256 of the <b>msg_len</b> bytes in <b>msg</b>, using
 * the <b>key</b> of length <b>key_len</b>.  Store the DIGEST256_LEN-byte
 * result in <b>hmac_out</b>. Asserts on failure.
 */
void
crypto_hmac_sha256(char *hmac_out,
                   const char *key, size_t key_len,
                   const char *msg, size_t msg_len)
{
  unsigned char *rv = NULL;
  /* If we've got OpenSSL >=0.9.8 we can use its hmac implementation. */
  tor_assert(key_len < INT_MAX);
  tor_assert(msg_len < INT_MAX);
  tor_assert(hmac_out);
  rv = HMAC(EVP_sha256(), key, (int)key_len, (unsigned char*)msg, (int)msg_len,
            (unsigned char*)hmac_out, NULL);
  tor_assert(rv);
}

/** Compute a MAC using SHA3-256 of <b>msg_len</b> bytes in <b>msg</b> using a
 * <b>key</b> of length <b>key_len</b> and a <b>salt</b> of length
 * <b>salt_len</b>. Store the result of <b>len_out</b> bytes in in
 * <b>mac_out</b>. This function can't fail. */
void
crypto_mac_sha3_256(uint8_t *mac_out, size_t len_out,
                    const uint8_t *key, size_t key_len,
                    const uint8_t *msg, size_t msg_len)
{
  crypto_digest_t *digest;

  const uint64_t key_len_netorder = tor_htonll(key_len);

  tor_assert(mac_out);
  tor_assert(key);
  tor_assert(msg);

  digest = crypto_digest256_new(DIGEST_SHA3_256);

  /* Order matters here that is any subsystem using this function should
   * expect this very precise ordering in the MAC construction. */
  crypto_digest_add_bytes(digest, (const char *) &key_len_netorder,
                          sizeof(key_len_netorder));
  crypto_digest_add_bytes(digest, (const char *) key, key_len);
  crypto_digest_add_bytes(digest, (const char *) msg, msg_len);
  crypto_digest_get_digest(digest, (char *) mac_out, len_out);
  crypto_digest_free(digest);
}

/* xof functions  */

/** Internal state for a eXtendable-Output Function (XOF). */
struct crypto_xof_t {
  keccak_state s;
};

/** Allocate a new XOF object backed by SHAKE-256.  The security level
 * provided is a function of the length of the output used.  Read and
 * understand FIPS-202 A.2 "Additional Consideration for Extendable-Output
 * Functions" before using this construct.
 */
crypto_xof_t *
crypto_xof_new(void)
{
  crypto_xof_t *xof;
  xof = tor_malloc(sizeof(crypto_xof_t));
  keccak_xof_init(&xof->s, 256);
  return xof;
}

/** Absorb bytes into a XOF object.  Must not be called after a call to
 * crypto_xof_squeeze_bytes() for the same instance, and will assert
 * if attempted.
 */
void
crypto_xof_add_bytes(crypto_xof_t *xof, const uint8_t *data, size_t len)
{
  int i = keccak_xof_absorb(&xof->s, data, len);
  tor_assert(i == 0);
}

/** Squeeze bytes out of a XOF object.  Calling this routine will render
 * the XOF instance ineligible to absorb further data.
 */
void
crypto_xof_squeeze_bytes(crypto_xof_t *xof, uint8_t *out, size_t len)
{
  int i = keccak_xof_squeeze(&xof->s, out, len);
  tor_assert(i == 0);
}

/** Cleanse and deallocate a XOF object. */
void
crypto_xof_free_(crypto_xof_t *xof)
{
  if (!xof)
    return;
  memwipe(xof, 0, sizeof(crypto_xof_t));
  tor_free(xof);
}

