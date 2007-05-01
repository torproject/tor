/* Copyright 2007 Roger Dingledine, Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id: /tor/trunk/src/tools/tor-resolve.c 12481 2007-04-21T17:27:19.371353Z nickm  $ */

#include "orconfig.h"

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>

#include <errno.h>
#if 0
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#endif

#define CRYPTO_PRIVATE

#include "../common/compat.h"
#include "../common/util.h"
#include "../common/log.h"
#include "../common/crypto.h"

#define IDENTITY_KEY_BITS 3072
#define SIGNING_KEY_BITS 1024
#define DEFAULT_LIFETIME 12

char *identity_key_file = NULL;
char *signing_key_file = NULL;
char *certificate_file = NULL;
int verbose = 0;
int make_new_id = 0;
int months_lifetime = DEFAULT_LIFETIME;

EVP_PKEY *identity_key = NULL;
EVP_PKEY *signing_key = NULL;

/* DOCDOC */
static void
show_help(void)
{
  fprintf(stderr, "Syntax:\n"
          "tor-gencert [-h|--help] [-v] [--create-identity-key] "
          "[-i identity_key_file]\n"
          "            [-s signing_key_file] [-c certificate_file]\n");
}

/* XXXX copied from crypto.c */
static void
crypto_log_errors(int severity, const char *doing)
{
  unsigned int err;
  const char *msg, *lib, *func;
  while ((err = ERR_get_error()) != 0) {
    msg = (const char*)ERR_reason_error_string(err);
    lib = (const char*)ERR_lib_error_string(err);
    func = (const char*)ERR_func_error_string(err);
    if (!msg) msg = "(null)";
    if (!lib) lib = "(null)";
    if (!func) func = "(null)";
    if (doing) {
      log(severity, LD_CRYPTO, "crypto error while %s: %s (in %s:%s)",
          doing, msg, lib, func);
    } else {
      log(severity, LD_CRYPTO, "crypto error: %s (in %s:%s)", msg, lib, func);
    }
  }
}

/** DOCDOC */
static int
parse_commandline(int argc, char **argv)
{
  int i;
  for (i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
      show_help();
      return 1;
    } else if (!strcmp(argv[i], "-i")) {
      if (i+1>=argc) {
        fprintf(stderr, "No argument to -i\n");
        return 1;
      }
      identity_key_file = tor_strdup(argv[++i]);
    } else if (!strcmp(argv[i], "-c")) {
      if (i+1>=argc) {
        fprintf(stderr, "No argument to -c\n");
        return 1;
      }
      certificate_file = tor_strdup(argv[++i]);
    } else if (!strcmp(argv[i], "-m")) {
      if (i+1>=argc) {
        fprintf(stderr, "No argument to -m\n");
        return 1;
      }
      months_lifetime = atoi(argv[++i]);
      if (months_lifetime > 24 || months_lifetime < 0) {
        fprintf(stderr, "Lifetime (in months) was out of range.");
        return 1;
      }
    } else if (!strcmp(argv[i], "-v")) {
      verbose = 1;
    } else if (!strcmp(argv[i], "--create-identity-key")) {
      make_new_id = 1;
    } else {
      fprintf(stderr, "Unrecognized option %s\n", argv[i]);
      return 1;
    }
  }

  if (verbose) {
    add_stream_log(LOG_INFO, LOG_ERR, "<stderr>", stderr);
  } else {
    add_stream_log(LOG_NOTICE, LOG_ERR, "<stderr>", stderr);
  }

  if (!identity_key_file) {
    identity_key_file = tor_strdup("./authority_identity_key");
    log_info(LD_GENERAL, "No identity key file given; defaulting to %s",
             identity_key_file);
  }
  if (!signing_key_file) {
    signing_key_file = tor_strdup("./authority_signing_key");
    log_info(LD_GENERAL, "No signing key file given; defaulting to %s",
             signing_key_file);
  }
  if (!certificate_file) {
    certificate_file = tor_strdup("./authority_certificate");
    log_info(LD_GENERAL, "No signing key file given; defaulting to %s",
             signing_key_file);
  }
  return 0;
}

/** DOCDOC */
static int
load_identity_key(void)
{
  file_status_t status = file_status(identity_key_file);
  FILE *f;

  if (make_new_id) {
    RSA *key;
    if (status != FN_NOENT) {
      log_err(LD_GENERAL, "--create-identity-key was specified, but %s "
              "already exists.", identity_key_file);
      return 1;
    }
    log_notice(LD_GENERAL, "Generating %d-bit RSA identity key.",
               IDENTITY_KEY_BITS);
    if (!(key = RSA_generate_key(IDENTITY_KEY_BITS, 65537, NULL, NULL))) {
      log_err(LD_GENERAL, "Couldn't generate identity key.");
      crypto_log_errors(LOG_ERR, "Generating identity key");
      return 1;
    }
    identity_key = EVP_PKEY_new();
    if (!(EVP_PKEY_assign_RSA(identity_key, key))) {
      log_err(LD_GENERAL, "Couldn't assign identity key.");
      return 1;
    }

    if (!(f = fopen(identity_key_file, "w"))) {
      log_err(LD_GENERAL, "Couldn't open %s for writing: %s",
              identity_key_file, strerror(errno));
      return 1;
    }

    if (!PEM_write_PKCS8PrivateKey_nid(f, identity_key,
                                       NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                                       NULL, 0, /* no password here. */
                                       NULL, NULL)) {
      log_err(LD_GENERAL, "Couldn't write identity key to %s",
              identity_key_file);
      crypto_log_errors(LOG_ERR, "Writing identity key");
      return 1;
    }
    fclose(f);
  } else {
    if (status != FN_FILE) {
      log_err(LD_GENERAL,
              "No identity key found in %s.  To specify a location "
              "for an identity key, use -i.  To generate a new identity key, "
              "use --create-identity-key.", identity_key_file);
      return 1;
    }

    if (!(f = fopen(identity_key_file, "r"))) {
      log_err(LD_GENERAL, "Couldn't open %s for reading: %s",
              identity_key_file, strerror(errno));
      return 1;
    }

    identity_key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    if (!identity_key) {
      log_err(LD_GENERAL, "Couldn't read identity key from %s",
              identity_key_file);
      return 1;
    }
    fclose(f);
  }
  return 0;
}

/** DOCDOC */
static int
generate_signing_key(void)
{
  FILE *f;
  RSA *key;
  log_notice(LD_GENERAL, "Generating %d-bit RSA signing key.",
             SIGNING_KEY_BITS);
  if (!(key = RSA_generate_key(SIGNING_KEY_BITS, 65537, NULL, NULL))) {
    log_err(LD_GENERAL, "Couldn't generate signing key.");
    crypto_log_errors(LOG_ERR, "Generating signing key");
    return 1;
  }
  signing_key = EVP_PKEY_new();
  if (!(EVP_PKEY_assign_RSA(signing_key, key))) {
    log_err(LD_GENERAL, "Couldn't assign signing key.");
    return 1;
  }

  if (!(f = fopen(signing_key_file, "w"))) {
    log_err(LD_GENERAL, "Couldn't open %s for reading: %s",
            signing_key_file, strerror(errno));
    return 1;
  }

  /* Write signing key with no encryption. */
  if (!PEM_write_RSAPrivateKey(f, key, NULL, NULL, 0, NULL, NULL)) {
    crypto_log_errors(LOG_WARN, "writing signing key");
    return 1;
  }

  fclose(f);

  return 0;
}

static char *
key_to_string(EVP_PKEY *key)
{
  BUF_MEM *buf;
  BIO *b;
  RSA *rsa = EVP_PKEY_get1_RSA(key);
  char *result;
  if (!rsa)
    return NULL;

  b = BIO_new(BIO_s_mem());
  if (!PEM_write_bio_RSAPublicKey(b, rsa)) {
    crypto_log_errors(LOG_WARN, "writing public key to string");
    return NULL;
  }

  BIO_get_mem_ptr(b, &buf);
  (void) BIO_set_close(b, BIO_NOCLOSE);
  BIO_free(b);
  result = tor_malloc(buf->length + 1);
  memcpy(result, buf->data, buf->length);
  result[buf->length] = 0;
  BUF_MEM_free(buf);

  return result;
}

static int
get_fingerprint(EVP_PKEY *pkey, char *out)
{
  int r = 1;
  crypto_pk_env_t *pk = _crypto_new_pk_env_rsa(EVP_PKEY_get1_RSA(pkey));
  if (pk) {
    r = crypto_pk_get_fingerprint(pk, out, 0);
    crypto_free_pk_env(pk);
  }
  return r;
}

static int
generate_certificate(void)
{
  char buf[8192];
  time_t now = time(NULL);
  struct tm tm;
  char published[ISO_TIME_LEN+1];
  char expires[ISO_TIME_LEN+1];
  char fingerprint[FINGERPRINT_LEN+1];
  char *ident = key_to_string(identity_key);
  char *signing = key_to_string(signing_key);
  FILE *f;
  size_t signed_len;
  char digest[DIGEST_LEN];
  char signature[1024]; /* handles up to 8192-bit keys. */
  int r;

  get_fingerprint(identity_key, fingerprint);

  tor_localtime_r(&now, &tm);
  tm.tm_mon += months_lifetime;

  format_iso_time(published, now);
  format_iso_time(expires, mktime(&tm));

  tor_snprintf(buf, sizeof(buf),
               "dir-key-certificate-version 3\n"
               "fingerprint %s\n"
               "dir-key-published %s\n"
               "dir-key-expires %s\n"
               "dir-identity-key\n%s"
               "dir-signing-key\n%s"
               "dir-key-certification\n",
               fingerprint, published, expires, ident, signing);
  signed_len = strlen(buf);
  SHA1((const unsigned char*)buf,signed_len,(unsigned char*)digest);

  r = RSA_private_encrypt(DIGEST_LEN, (unsigned char*)digest,
                          (unsigned char*)signature,
                          EVP_PKEY_get1_RSA(identity_key),
                          RSA_PKCS1_PADDING);
  strlcat(buf, "-----BEGIN_SIGNATURE-----\n", sizeof(buf));
  signed_len = strlen(buf);
  base64_encode(buf+signed_len, sizeof(buf)-signed_len, signature, r);
  strlcat(buf, "-----END_SIGNATURE-----\n", sizeof(buf));

  if (!(f = fopen(certificate_file, "w"))) {
    log_err(LD_GENERAL, "Couldn't open %s for writing: %s",
            certificate_file, strerror(errno));
    return 1;
  }

  fputs(buf, f);
  fclose(f);
  return 0;
}


/** Entry point to tor-gencert */
int
main(int argc, char **argv)
{
  int r = 1;
  /* Don't bother using acceleration. */
  if (crypto_global_init(0)) {
    fprintf(stderr, "Couldn't initialize crypto library.\n");
    return 1;
  }
  if (crypto_seed_rng()) {
    fprintf(stderr, "Couldn't seed RNG.\n");
    goto done;
  }
  if (parse_commandline(argc, argv))
    goto done;
  if (load_identity_key())
    goto done;
  if (generate_signing_key())
    goto done;
  if (generate_certificate())
    goto done;

  r = 0;
 done:
  if (identity_key)
    EVP_PKEY_free(identity_key);
  if (signing_key)
    EVP_PKEY_free(signing_key);

  crypto_global_cleanup();
  return r;
}

