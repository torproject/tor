/* Added for Tor. */
#include <openssl/sha.h>
#define crypto_hash_sha512(out, inp, len) \
  SHA512((inp), (len), (out))
