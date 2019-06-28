/* Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <locale.h>

#include "trunnel/ed25519_cert.h"
#include "lib/cc/torint.h"  /* TOR_PRIdSZ */
#include "lib/crypt_ops/crypto_format.h"
#include "lib/malloc/malloc.h"

int
main(int argc, char **argv)
{
  ed25519_cert_t *cert = NULL;
  char rfc822_str[64] = "";

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
    fprintf(stderr, "ed25519_cert_parse failed with return value %" TOR_PRIdSZ
                    "\n", parsed);
    return -5;
  }

  const time_t expiration = (const time_t)cert->exp_field * 60 * 60;

  const struct tm *expires_at = localtime(&expiration);


  setlocale(LC_TIME, "en_US_POSIX");

/* Yes, we're fine with RFC822 being written in 1982 and not addressing Y2K. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-y2k"
  if (strftime(rfc822_str, sizeof(rfc822_str), "%a, %d %b %y %T %z",
        expires_at) == 0) {
    fprintf(stderr, "strftime failed to format timestamp\n");
    return -6;
  }
  // Format string taken from Linux strftime(3) manpage.
#pragma GCC diagnostic pop

  printf("Expires at: %s", ctime(&expiration));
  printf("RFC 822 timestamp: %s\n", rfc822_str);
  printf("UNIX timestamp: %ld\n", (long int)expiration);

  ed25519_cert_free(cert);

  return 0;
}
