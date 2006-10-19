/* Copyright 2006 Nick Mathewson; see LICENSE for licensing information */
/* $Id$ */

/* id_to_fp.c : Helper for directory authority ops.  When somebody sends us
 * a private key, this utility converts the private key into a fingerprint
 * so you can de-list that fingerprint.
 */

#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/pem.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define die(s) do { fprintf(stderr, "%s\n", s); goto err; } while (0)

int
main(int argc, char **argv)
{
  BIO *b = NULL;
  RSA *key = NULL;
  unsigned char *buf = NULL, *bufp;
  int len, i;
  unsigned char digest[20];
  int status = 1;

  if (argc < 2) {
    fprintf(stderr, "Reading key from stdin...\n");
    if (!(b = BIO_new_fp(stdin, BIO_NOCLOSE)))
      die("couldn't read from stdin");
  } else if (argc == 2) {
    if (strcmp(argv[1], "-h") == 0 ||
        strcmp(argv[1], "--help") == 0) {
      fprintf(stdout, "Usage: %s [keyfile]\n", argv[0]);
      status = 0;
      goto err;
    } else {
      if (!(b = BIO_new_file(argv[1], "r")))
        die("couldn't open file");
    }
  } else {
    fprintf(stderr, "Usage: %s [keyfile]\n", argv[0]);
    goto err;
  }
  if (!(key = PEM_read_bio_RSAPrivateKey(b, NULL, NULL, NULL)))
    die("couldn't parse key");

  len = i2d_RSAPublicKey(key, NULL);
  if (len < 0)
    die("Bizarre key");
  bufp = buf = malloc(len+1);
  if (!buf)
    die("Out of memory");
  len = i2d_RSAPublicKey(key, &bufp);
  if (len < 0)
    die("Bizarre key");

  SHA1(buf, len, digest);
  for (i=0; i < 20; i += 2) {
    printf("%02X%02X ", (int)digest[i], (int)digest[i+1]);
  }
  printf("\n");

  status = 0;

err:
  if (buf)
    free(buf);
  if (key)
    RSA_free(key);
  if (b)
    BIO_free(b);
  return status;
}

