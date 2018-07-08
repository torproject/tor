/* Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include <stdio.h>
#include <time.h>

#include "ed25519_cert.h"
#include "lib/crypt_ops/crypto_format.h"
#include "common/util.h"

int
main(int argc, char **argv)
{
  ed25519_cert_t *cert = NULL;

  if (argc != 2) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "%s <path to ed25519_signing_cert file>\n", argv[0]);
    return -1;
  }

  const char *filepath = argv[1];
  char *got_tag = NULL;

  uint8_t certbuf[256];
  ssize_t cert_body_len = crypto_read_tagged_contents_from_file(
                 filepath, "ed25519v1-cert",
                 &got_tag, certbuf, sizeof(certbuf));

  if (cert_body_len <= 0) {
    fprintf(stderr, "crypto_read_tagged_contents_from_file failed with "
                    "error: %s\n", strerror(errno));
    return -2;
  }

  if (!got_tag) {
    fprintf(stderr, "Found no tag\n");
    return -3;
  }

  if (strcmp(got_tag, "type4") != 0) {
    fprintf(stderr, "Wrong tag: %s\n", got_tag);
    return -4;
  }

  tor_free(got_tag);

  ssize_t parsed = ed25519_cert_parse(&cert, certbuf, cert_body_len);
  if (parsed <= 0) {
    fprintf(stderr, "ed25519_cert_parse failed with return value %zd\n",
            parsed);
    return -5;
  }

  time_t expires_at = (time_t)cert->exp_field * 60 * 60;

  printf("Expires at: %s", ctime(&expires_at));

  ed25519_cert_free(cert);

  return 0;
}

