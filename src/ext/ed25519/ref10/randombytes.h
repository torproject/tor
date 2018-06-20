/* Added for Tor. */
#include "common/crypto_rand.h"
#define randombytes(b, n) \
  (crypto_strongest_rand((b), (n)), 0)
