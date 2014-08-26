/* Added for Tor. */
#include <openssl/sha.h>
#define crypto_hash_sha512(out, inp, len) \
  SHA512((inp), (len), (out))

#define crypto_hash_sha512_2(out, inp1, len1, inp2, len2)               \
  do {                                                                  \
      SHA512_CTX sha_ctx_;                                              \
      SHA512_Init(&sha_ctx_);                                           \
      SHA512_Update(&sha_ctx_, (inp1), (len1));                         \
      SHA512_Update(&sha_ctx_, (inp2), (len2));                         \
      SHA512_Final((out), &sha_ctx_);                                   \
 } while(0)

#define crypto_hash_sha512_3(out, inp1, len1, inp2, len2, inp3, len3)   \
  do {                                                                  \
      SHA512_CTX sha_ctx_;                                              \
      SHA512_Init(&sha_ctx_);                                           \
      SHA512_Update(&sha_ctx_, (inp1), (len1));                         \
      SHA512_Update(&sha_ctx_, (inp2), (len2));                         \
      SHA512_Update(&sha_ctx_, (inp3), (len3));                         \
      SHA512_Final((out), &sha_ctx_);                                   \
 } while(0)
