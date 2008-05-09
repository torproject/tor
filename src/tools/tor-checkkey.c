
#define CRYPTO_PRIVATE

#include <stdio.h>
#include <stdlib.h>
#include "crypto.h"
#include "log.h"
#include "util.h"
#include "compat.h"
#include <openssl/bn.h>
#include <openssl/rsa.h>

int main(int c, char **v)
{
  crypto_pk_env_t *env;
  char *str;
  RSA *rsa;
  init_logging();

  if (c < 2) {
    fprintf(stderr, "Hi. I'm tor-checkkey.  Tell me a filename that has a PEM-encoded RSA public key (like in a cert) and I'll dump the modulus.\n");
    return 1;
  }

  if (crypto_global_init(0)) {
    fprintf(stderr, "Couldn't initialize crypto library.\n");
    return 1;
  }

  str = read_file_to_str(v[1], 0, NULL);
  if (!str) {
    fprintf(stderr, "Couldn't read %s\n", v[1]);
    return 1;
  }

  env = crypto_new_pk_env();
  if (crypto_pk_read_public_key_from_string(env, str, strlen(str))<0) {
    fprintf(stderr, "Couldn't parse key.\n");
    return 1;
  }
  tor_free(str);

  rsa = _crypto_pk_env_get_rsa(env);
  str = BN_bn2hex(rsa->n);

  printf("%s\n", str);

  return 0;
}
