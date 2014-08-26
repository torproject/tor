/* Modified for Tor: new API, 32-byte secret keys. */
#include <string.h>
#include "randombytes.h"
#include "crypto_sign.h"
#include "crypto_hash_sha512.h"
#include "ge.h"

int
crypto_sign_seckey(unsigned char *sk)
{
  randombytes(sk,32);

  return 0;
}

int crypto_sign_pubkey(unsigned char *pk,const unsigned char *sk)
{
  unsigned char az[64];
  ge_p3 A;

  crypto_hash_sha512(az,sk,32);
  az[0] &= 248;
  az[31] &= 63;
  az[31] |= 64;

  ge_scalarmult_base(&A,az);
  ge_p3_tobytes(pk,&A);

  return 0;
}


int crypto_sign_keypair(unsigned char *pk,unsigned char *sk)
{
  crypto_sign_seckey(sk);
  crypto_sign_pubkey(pk, sk);

  return 0;
}

