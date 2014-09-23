
#include "crypto.h"
#include "crypto_s2k.h"
#include "crypto_pwbox.h"
#include "di_ops.h"
#include "util.h"

/* 7 bytes "TORBOX0"
   1 byte: header len (H)
   H bytes: header, denoting secret key algorithm.
   16 bytes: IV
   Round up to multiple of 128 bytes, then encrypt:
      4 bytes: data len
      data
      zeros
   32 bytes: HMAC-SHA256 of all previous bytes.
*/

#define MAX_OVERHEAD (S2K_MAXLEN + 8 + 32 + CIPHER_IV_LEN)

/**
 * Make an authenticated passphrase-encrypted blob to encode the
 * <b>input_len</b> bytes in <b>input</b> using the passphrase
 * <b>secret</b> of <b>secret_len</b> bytes.  Allocate a new chunk of memory
 * to hold the encrypted data, and store a pointer to that memory in
 * *<b>out</b>, and its size in <b>outlen_out</b>.  Use <b>s2k_flags</b> as an
 * argument to the passphrase-hashing function.
 */
int
crypto_pwbox(uint8_t **out, size_t *outlen_out,
             const uint8_t *input, size_t input_len,
             const char *secret, size_t secret_len,
             unsigned s2k_flags)
{
  uint8_t *result, *encrypted_portion, *hmac, *iv;
  size_t encrypted_len = 128 * CEIL_DIV(input_len+4, 128);
  size_t result_len = encrypted_len + MAX_OVERHEAD;
  int spec_len;
  uint8_t keys[CIPHER_KEY_LEN + DIGEST256_LEN];

  crypto_cipher_t *cipher;
  int rv;

  /* Allocate a buffer and put things in the right place. */
  result = tor_malloc_zero(result_len);
  memcpy(result, "TORBOX0", 7);

  spec_len = secret_to_key_make_specifier(result + 8,
                                          result_len - 8,
                                          s2k_flags);
  if (spec_len < 0 || spec_len > 255)
    goto err;
  result[7] = (uint8_t) spec_len;

  tor_assert(8 + spec_len + CIPHER_IV_LEN + encrypted_len <= result_len);

  iv = result + 8 + spec_len;
  encrypted_portion = result + 8 + spec_len + CIPHER_IV_LEN;
  hmac = encrypted_portion + encrypted_len;

  set_uint32(encrypted_portion, htonl(input_len));
  memcpy(encrypted_portion+4, input, input_len);

  /* Now that all the data is in position, derive some keys, encrypt, and
   * digest */
  if (secret_to_key_derivekey(keys, sizeof(keys),
                              result+8, spec_len,
                              secret, secret_len) < 0)
    goto err;

  crypto_rand((char*)iv, CIPHER_IV_LEN);

  cipher = crypto_cipher_new_with_iv((char*)keys, (char*)iv);
  crypto_cipher_crypt_inplace(cipher, (char*)encrypted_portion, encrypted_len);
  crypto_cipher_free(cipher);

  crypto_hmac_sha256((char*)hmac,
                     (const char*)keys + CIPHER_KEY_LEN,
                                             sizeof(keys)-CIPHER_KEY_LEN,
                     (const char*)result,
                     8 + CIPHER_IV_LEN + spec_len + encrypted_len);

  *out = result;
  *outlen_out = 8 + CIPHER_IV_LEN + spec_len + encrypted_len + DIGEST256_LEN;
  rv = 0;
  goto out;

 err:
  tor_free(result);
  rv = -1;

 out:
  memwipe(keys, 0, sizeof(keys));
  return rv;
}

/**
 * Try to decrypt the passphrase-encrypted blob of <b>input_len</b> bytes in
 * <b>input</b> using the passphrase <b>secret</b> of <b>secret_len</b> bytes.
 * On success, return 0 and allocate a new chunk of memory to hold the
 * decrypted data, and store a pointer to that memory in *<b>out</b>, and its
 * size in <b>outlen_out</b>.  On failure, return UNPWBOX_BAD_SECRET if
 * the passphrase might have been wrong, and UNPWBOX_CORRUPT if the object is
 * definitely corrupt.
 */
int
crypto_unpwbox(uint8_t **out, size_t *outlen_out,
               const uint8_t *inp, size_t input_len,
               const char *secret, size_t secret_len)
{
  uint8_t *result = NULL;
  const uint8_t *encrypted, *iv;
  uint8_t keys[CIPHER_KEY_LEN + DIGEST256_LEN];
  size_t spec_bytes;
  uint8_t hmac[DIGEST256_LEN];
  uint32_t result_len;
  crypto_cipher_t *cipher = NULL;
  int rv = UNPWBOX_CORRUPTED;

  if (input_len < 32)
    goto err;

  if (tor_memneq(inp, "TORBOX0", 7))
    goto err;

  spec_bytes = inp[7];
  if (input_len < 8 + spec_bytes)
    goto err;

  /* Now derive the keys and check the hmac. */
  if (secret_to_key_derivekey(keys, sizeof(keys),
                              inp+8, spec_bytes,
                              secret, secret_len) < 0)
    goto err;

  crypto_hmac_sha256((char *)hmac,
               (const char*)keys + CIPHER_KEY_LEN, sizeof(keys)-CIPHER_KEY_LEN,
               (const char*)inp, input_len - DIGEST256_LEN);

  if (tor_memneq(hmac, inp + input_len - DIGEST256_LEN, DIGEST256_LEN)) {
    rv = UNPWBOX_BAD_SECRET;
    goto err;
  }

  iv = inp + 8 + spec_bytes;
  encrypted = inp + 8 + spec_bytes + CIPHER_IV_LEN;

  /* How long is the plaintext? */
  cipher = crypto_cipher_new_with_iv((char*)keys, (char*)iv);
  crypto_cipher_decrypt(cipher, (char*)&result_len, (char*)encrypted, 4);
  result_len = ntohl(result_len);
  if (input_len < 8 + spec_bytes + 4 + result_len + 32)
    goto err;

  /* Allocate a buffer and decrypt */
  result = tor_malloc_zero(result_len);
  crypto_cipher_decrypt(cipher, (char*)result, (char*)encrypted+4, result_len);

  *out = result;
  *outlen_out = result_len;

  rv = UNPWBOX_OKAY;
  goto out;

 err:
  tor_free(result);

 out:
  crypto_cipher_free(cipher);
  memwipe(keys, 0, sizeof(keys));
  return rv;
}

