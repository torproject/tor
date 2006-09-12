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

#define die(s) do { fprintf(stderr, s "\n"); return 1; } while (0)

int
main(int argc, char **argv)
{
  BIO *b;
  RSA *key;
  unsigned char *buf, *bufp;
  int len, i;
  unsigned char digest[20];

  if (argc != 2)
    die("I want a filename");
  if (!(b = BIO_new_file(argv[1], "r")))
    die("couldn't open file");

  if (!(key = PEM_read_bio_RSAPrivateKey(b, NULL, NULL, NULL)))
    die("couldn't parse key");

  len = i2d_RSAPublicKey(key, NULL);
  bufp = buf = malloc(len+1);
  len = i2d_RSAPublicKey(key, &bufp);
  if (len < 0)
    die("Bizarre key");

  SHA1(buf, len, digest);
  for (i=0; i < 20; i += 2) {
    printf("%02X%02X ", (int)digest[i], (int)digest[i+1]);
  }
  printf("\n");

  return 0;
}

