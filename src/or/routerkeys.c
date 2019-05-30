/* Copyright (c) 2014-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file routerkeys.c
 *
 * \brief Functions and structures to handle generating and maintaining the
 *  set of keypairs necessary to be an OR.
 *
 * The keys handled here now are the Ed25519 keys that Tor relays use to sign
 * descriptors, authenticate themselves on links, and identify one another
 * uniquely.  Other keys are maintained in router.c and rendservice.c.
 *
 * (TODO: The keys in router.c should go here too.)
 */

#include "or.h"
#include "config.h"
#include "crypto_util.h"
#include "router.h"
#include "crypto_pwbox.h"
#include "routerkeys.h"
#include "torcert.h"

#define ENC_KEY_HEADER "Boxed Ed25519 key"
#define ENC_KEY_TAG "master"

/* DOCDOC */
static ssize_t
do_getpass(const char *prompt, char *buf, size_t buflen,
           int twice, const or_options_t *options)
{
  if (options->keygen_force_passphrase == FORCE_PASSPHRASE_OFF) {
    tor_assert(buflen);
    buf[0] = 0;
    return 0;
  }

  char *prompt2 = NULL;
  char *buf2 = NULL;
  int fd = -1;
  ssize_t length = -1;

  if (options->use_keygen_passphrase_fd) {
    twice = 0;
    fd = options->keygen_passphrase_fd;
    length = read_all(fd, buf, buflen-1, 0);
    if (length >= 0)
      buf[length] = 0;
    goto done_reading;
  }

  if (twice) {
    const char msg[] = "One more time:";
    size_t p2len = strlen(prompt) + 1;
    if (p2len < sizeof(msg))
      p2len = sizeof(msg);
    prompt2 = tor_malloc(p2len);
    memset(prompt2, ' ', p2len);
    memcpy(prompt2 + p2len - sizeof(msg), msg, sizeof(msg));

    buf2 = tor_malloc_zero(buflen);
  }

  while (1) {
    length = tor_getpass(prompt, buf, buflen);
    if (length < 0)
      goto done_reading;

    if (! twice)
      break;

    ssize_t length2 = tor_getpass(prompt2, buf2, buflen);

    if (length != length2 || tor_memneq(buf, buf2, length)) {
      fprintf(stderr, "That didn't match.\n");
    } else {
      break;
    }
  }

 done_reading:
  if (twice) {
    tor_free(prompt2);
    memwipe(buf2, 0, buflen);
    tor_free(buf2);
  }

  if (options->keygen_force_passphrase == FORCE_PASSPHRASE_ON && length == 0)
    return -1;

  return length;
}

/* DOCDOC */
int
read_encrypted_secret_key(ed25519_secret_key_t *out,
                          const char *fname)
{
  int r = -1;
  uint8_t *secret = NULL;
  size_t secret_len = 0;
  char pwbuf[256];
  uint8_t encrypted_key[256];
  char *tag = NULL;
  int saved_errno = 0;

  ssize_t encrypted_len = crypto_read_tagged_contents_from_file(fname,
                                          ENC_KEY_HEADER,
                                          &tag,
                                          encrypted_key,
                                          sizeof(encrypted_key));
  if (encrypted_len < 0) {
    saved_errno = errno;
    log_info(LD_OR, "%s is missing", fname);
    r = 0;
    goto done;
  }
  if (strcmp(tag, ENC_KEY_TAG)) {
    saved_errno = EINVAL;
    goto done;
  }

  while (1) {
    ssize_t pwlen =
      do_getpass("Enter passphrase for master key:", pwbuf, sizeof(pwbuf), 0,
                 get_options());
    if (pwlen < 0) {
      saved_errno = EINVAL;
      goto done;
    }
    const int r_unbox = crypto_unpwbox(&secret, &secret_len,
                                       encrypted_key, encrypted_len,
                                       pwbuf, pwlen);
    if (r_unbox == UNPWBOX_CORRUPTED) {
      log_err(LD_OR, "%s is corrupted.", fname);
      saved_errno = EINVAL;
      goto done;
    } else if (r_unbox == UNPWBOX_OKAY) {
      break;
    }

    /* Otherwise, passphrase is bad, so try again till user does ctrl-c or gets
     * it right. */
  }

  if (secret_len != ED25519_SECKEY_LEN) {
    log_err(LD_OR, "%s is corrupted.", fname);
    saved_errno = EINVAL;
    goto done;
  }
  memcpy(out->seckey, secret, ED25519_SECKEY_LEN);
  r = 1;

 done:
  memwipe(encrypted_key, 0, sizeof(encrypted_key));
  memwipe(pwbuf, 0, sizeof(pwbuf));
  tor_free(tag);
  if (secret) {
    memwipe(secret, 0, secret_len);
    tor_free(secret);
  }
  if (saved_errno)
    errno = saved_errno;
  return r;
}

/* DOCDOC */
int
write_encrypted_secret_key(const ed25519_secret_key_t *key,
                           const char *fname)
{
  int r = -1;
  char pwbuf0[256];
  uint8_t *encrypted_key = NULL;
  size_t encrypted_len = 0;

  if (do_getpass("Enter new passphrase:", pwbuf0, sizeof(pwbuf0), 1,
                 get_options()) < 0) {
    log_warn(LD_OR, "NO/failed passphrase");
    return -1;
  }

  if (strlen(pwbuf0) == 0) {
    if (get_options()->keygen_force_passphrase == FORCE_PASSPHRASE_ON)
      return -1;
    else
      return 0;
  }

  if (crypto_pwbox(&encrypted_key, &encrypted_len,
                   key->seckey, sizeof(key->seckey),
                   pwbuf0, strlen(pwbuf0),  0) < 0) {
    log_warn(LD_OR, "crypto_pwbox failed!?");
    goto done;
  }
  if (crypto_write_tagged_contents_to_file(fname,
                                           ENC_KEY_HEADER,
                                           ENC_KEY_TAG,
                                           encrypted_key, encrypted_len) < 0)
    goto done;
  r = 1;
 done:
  if (encrypted_key) {
    memwipe(encrypted_key, 0, encrypted_len);
    tor_free(encrypted_key);
  }
  memwipe(pwbuf0, 0, sizeof(pwbuf0));
  return r;
}

/* DOCDOC */
static int
write_secret_key(const ed25519_secret_key_t *key, int encrypted,
                 const char *fname,
                 const char *fname_tag,
                 const char *encrypted_fname)
{
  if (encrypted) {
    int r = write_encrypted_secret_key(key, encrypted_fname);
    if (r == 1) {
      /* Success! */

      /* Try to unlink the unencrypted key, if any existed before */
      if (strcmp(fname, encrypted_fname))
        unlink(fname);
      return r;
    } else if (r != 0) {
      /* Unrecoverable failure! */
      return r;
    }

    fprintf(stderr, "Not encrypting the secret key.\n");
  }
  return ed25519_seckey_write_to_file(key, fname, fname_tag);
}

/**
 * Read an ed25519 key and associated certificates from files beginning with
 * <b>fname</b>, with certificate type <b>cert_type</b>.  On failure, return
 * NULL; on success return the keypair.
 *
 * If INIT_ED_KEY_CREATE is set in <b>flags</b>, then create the key (and
 * certificate if requested) if it doesn't exist, and save it to disk.
 *
 * If INIT_ED_KEY_NEEDCERT is set in <b>flags</b>, load/create a certificate
 * too and store it in *<b>cert_out</b>.  Fail if the cert can't be
 * found/created.  To create a certificate, <b>signing_key</b> must be set to
 * the key that should sign it; <b>now</b> to the current time, and
 * <b>lifetime</b> to the lifetime of the key.
 *
 * If INIT_ED_KEY_REPLACE is set in <b>flags</b>, then create and save new key
 * whether we can read the old one or not.
 *
 * If INIT_ED_KEY_EXTRA_STRONG is set in <b>flags</b>, set the extra_strong
 * flag when creating the secret key.
 *
 * If INIT_ED_KEY_INCLUDE_SIGNING_KEY_IN_CERT is set in <b>flags</b>, and
 * we create a new certificate, create it with the signing key embedded.
 *
 * If INIT_ED_KEY_SPLIT is set in <b>flags</b>, and we create a new key,
 * store the public key in a separate file from the secret key.
 *
 * If INIT_ED_KEY_MISSING_SECRET_OK is set in <b>flags</b>, and we find a
 * public key file but no secret key file, return successfully anyway.
 *
 * If INIT_ED_KEY_OMIT_SECRET is set in <b>flags</b>, do not try to load a
 * secret key unless no public key is found.  Do not return a secret key. (but
 * create and save one if needed).
 *
 * If INIT_ED_KEY_NO_LOAD_SECRET is set in <b>flags</b>, don't try to load
 * a secret key, no matter what.
 *
 * If INIT_ED_KEY_TRY_ENCRYPTED is set, we look for an encrypted secret key
 * and consider encrypting any new secret key.
 *
 * If INIT_ED_KEY_NO_REPAIR is set, and there is any issue loading the keys
 * from disk _other than their absence_ (full or partial), we do not try to
 * replace them.
 *
 * If INIT_ED_KEY_SUGGEST_KEYGEN is set, have log messages about failures
 * refer to the --keygen option.
 *
 * If INIT_ED_KEY_EXPLICIT_FNAME is set, use the provided file name for the
 * secret key file, encrypted or not.
 */
ed25519_keypair_t *
ed_key_init_from_file(const char *fname, uint32_t flags,
                      int severity,
                      const ed25519_keypair_t *signing_key,
                      time_t now,
                      time_t lifetime,
                      uint8_t cert_type,
                      struct tor_cert_st **cert_out)
{
  char *secret_fname = NULL;
  char *encrypted_secret_fname = NULL;
  char *public_fname = NULL;
  char *cert_fname = NULL;
  const char *loaded_secret_fname = NULL;
  int created_pk = 0, created_sk = 0, created_cert = 0;
  const int try_to_load = ! (flags & INIT_ED_KEY_REPLACE);
  const int encrypt_key = !! (flags & INIT_ED_KEY_TRY_ENCRYPTED);
  const int norepair = !! (flags & INIT_ED_KEY_NO_REPAIR);
  const int split = !! (flags & INIT_ED_KEY_SPLIT);
  const int omit_secret = !! (flags & INIT_ED_KEY_OMIT_SECRET);
  const int offline_secret = !! (flags & INIT_ED_KEY_OFFLINE_SECRET);
  const int explicit_fname = !! (flags & INIT_ED_KEY_EXPLICIT_FNAME);

  /* we don't support setting both of these flags at once. */
  tor_assert((flags & (INIT_ED_KEY_NO_REPAIR|INIT_ED_KEY_NEEDCERT)) !=
                      (INIT_ED_KEY_NO_REPAIR|INIT_ED_KEY_NEEDCERT));

  char tag[8];
  tor_snprintf(tag, sizeof(tag), "type%d", (int)cert_type);

  tor_cert_t *cert = NULL;
  char *got_tag = NULL;
  ed25519_keypair_t *keypair = tor_malloc_zero(sizeof(ed25519_keypair_t));

  if (explicit_fname) {
    secret_fname = tor_strdup(fname);
    encrypted_secret_fname = tor_strdup(fname);
  } else {
    tor_asprintf(&secret_fname, "%s_secret_key", fname);
    tor_asprintf(&encrypted_secret_fname, "%s_secret_key_encrypted", fname);
  }
  tor_asprintf(&public_fname, "%s_public_key", fname);
  tor_asprintf(&cert_fname, "%s_cert", fname);

  /* Try to read the secret key. */
  int have_secret = 0;
  int load_secret = try_to_load &&
    !offline_secret &&
    (!omit_secret || file_status(public_fname)==FN_NOENT);
  if (load_secret) {
    int rv = ed25519_seckey_read_from_file(&keypair->seckey,
                                           &got_tag, secret_fname);
    if (rv == 0) {
      have_secret = 1;
      loaded_secret_fname = secret_fname;
      tor_assert(got_tag);
    } else {
      if (errno != ENOENT && norepair) {
        tor_log(severity, LD_OR, "Unable to read %s: %s", secret_fname,
                strerror(errno));
        goto err;
      }
    }
  }

  /* Should we try for an encrypted key? */
  int have_encrypted_secret_file = 0;
  if (!have_secret && try_to_load && encrypt_key) {
    int r = read_encrypted_secret_key(&keypair->seckey,
                                      encrypted_secret_fname);
    if (r > 0) {
      have_secret = 1;
      have_encrypted_secret_file = 1;
      tor_free(got_tag); /* convince coverity we aren't leaking */
      got_tag = tor_strdup(tag);
      loaded_secret_fname = encrypted_secret_fname;
    } else if (errno != ENOENT && norepair) {
      tor_log(severity, LD_OR, "Unable to read %s: %s",
              encrypted_secret_fname, strerror(errno));
      goto err;
    }
  } else {
    if (try_to_load) {
      /* Check if it's there anyway, so we don't replace it. */
      if (file_status(encrypted_secret_fname) != FN_NOENT)
        have_encrypted_secret_file = 1;
    }
  }

  if (have_secret) {
    if (strcmp(got_tag, tag)) {
      tor_log(severity, LD_OR, "%s has wrong tag", loaded_secret_fname);
      goto err;
    }
    /* Derive the public key */
    if (ed25519_public_key_generate(&keypair->pubkey, &keypair->seckey)<0) {
      tor_log(severity, LD_OR, "%s can't produce a public key",
              loaded_secret_fname);
      goto err;
    }
  }

  /* If we do split keys here, try to read the pubkey. */
  int found_public = 0;
  if (try_to_load && (!have_secret || split)) {
    ed25519_public_key_t pubkey_tmp;
    tor_free(got_tag);
    found_public = ed25519_pubkey_read_from_file(&pubkey_tmp,
                                                 &got_tag, public_fname) == 0;
    if (!found_public && errno != ENOENT && norepair) {
      tor_log(severity, LD_OR, "Unable to read %s: %s", public_fname,
              strerror(errno));
      goto err;
    }
    if (found_public && strcmp(got_tag, tag)) {
      tor_log(severity, LD_OR, "%s has wrong tag", public_fname);
      goto err;
    }
    if (found_public) {
      if (have_secret) {
        /* If we have a secret key and we're reloading the public key,
         * the key must match! */
        if (! ed25519_pubkey_eq(&keypair->pubkey, &pubkey_tmp)) {
          tor_log(severity, LD_OR, "%s does not match %s!  If you are trying "
                  "to restore from backup, make sure you didn't mix up the "
                  "key files. If you are absolutely sure that %s is the right "
                  "key for this relay, delete %s or move it out of the way.",
                  public_fname, loaded_secret_fname,
                  loaded_secret_fname, public_fname);
          goto err;
        }
      } else {
        /* We only have the public key; better use that. */
        tor_assert(split);
        memcpy(&keypair->pubkey, &pubkey_tmp, sizeof(pubkey_tmp));
      }
    } else {
      /* We have no public key file, but we do have a secret key, make the
       * public key file! */
      if (have_secret) {
        if (ed25519_pubkey_write_to_file(&keypair->pubkey, public_fname, tag)
            < 0) {
          tor_log(severity, LD_OR, "Couldn't repair %s", public_fname);
          goto err;
        } else {
          tor_log(LOG_NOTICE, LD_OR,
                  "Found secret key but not %s. Regenerating.",
                  public_fname);
        }
      }
    }
  }

  /* If the secret key is absent and it's not allowed to be, fail. */
  if (!have_secret && found_public &&
      !(flags & INIT_ED_KEY_MISSING_SECRET_OK)) {
    if (have_encrypted_secret_file) {
      tor_log(severity, LD_OR, "We needed to load a secret key from %s, "
              "but it was encrypted. Try 'tor --keygen' instead, so you "
              "can enter the passphrase.",
              secret_fname);
    } else if (offline_secret) {
      tor_log(severity, LD_OR, "We wanted to load a secret key from %s, "
              "but you're keeping it offline. (OfflineMasterKey is set.)",
              secret_fname);
    } else {
      tor_log(severity, LD_OR, "We needed to load a secret key from %s, "
              "but couldn't find it. %s", secret_fname,
              (flags & INIT_ED_KEY_SUGGEST_KEYGEN) ?
              "If you're keeping your master secret key offline, you will "
              "need to run 'tor --keygen' to generate new signing keys." :
              "Did you forget to copy it over when you copied the rest of the "
              "signing key material?");
    }
    goto err;
  }

  /* If it's absent, and we're not supposed to make a new keypair, fail. */
  if (!have_secret && !found_public && !(flags & INIT_ED_KEY_CREATE)) {
    if (split) {
      tor_log(severity, LD_OR, "No key found in %s or %s.",
              secret_fname, public_fname);
    } else {
      tor_log(severity, LD_OR, "No key found in %s.", secret_fname);
    }
    goto err;
  }

  /* If the secret key is absent, but the encrypted key would be present,
   * that's an error */
  if (!have_secret && !found_public && have_encrypted_secret_file) {
    tor_assert(!encrypt_key);
    tor_log(severity, LD_OR, "Found an encrypted secret key, "
            "but not public key file %s!", public_fname);
    goto err;
  }

  /* if it's absent, make a new keypair... */
  if (!have_secret && !found_public) {
    tor_free(keypair);
    keypair = ed_key_new(signing_key, flags, now, lifetime,
                         cert_type, &cert);
    if (!keypair) {
      tor_log(severity, LD_OR, "Couldn't create keypair");
      goto err;
    }
    created_pk = created_sk = created_cert = 1;
  }

  /* Write it to disk if we're supposed to do with a new passphrase, or if
   * we just created it. */
  if (created_sk || (have_secret && get_options()->change_key_passphrase)) {
    if (write_secret_key(&keypair->seckey,
                         encrypt_key,
                         secret_fname, tag, encrypted_secret_fname) < 0
        ||
        (split &&
         ed25519_pubkey_write_to_file(&keypair->pubkey, public_fname, tag) < 0)
        ||
        (cert &&
         crypto_write_tagged_contents_to_file(cert_fname, "ed25519v1-cert",
                                 tag, cert->encoded, cert->encoded_len) < 0)) {
      tor_log(severity, LD_OR, "Couldn't write keys or cert to file.");
      goto err;
    }
    goto done;
  }

  /* If we're not supposed to get a cert, we're done. */
  if (! (flags & INIT_ED_KEY_NEEDCERT))
    goto done;

  /* Read a cert. */
  tor_free(got_tag);
  uint8_t certbuf[256];
  ssize_t cert_body_len = crypto_read_tagged_contents_from_file(
                 cert_fname, "ed25519v1-cert",
                 &got_tag, certbuf, sizeof(certbuf));
  if (cert_body_len >= 0 && !strcmp(got_tag, tag))
    cert = tor_cert_parse(certbuf, cert_body_len);

  /* If we got it, check it to the extent we can. */
  int bad_cert = 0;

  if (! cert) {
    tor_log(severity, LD_OR, "Cert was unparseable");
    bad_cert = 1;
  } else if (!tor_memeq(cert->signed_key.pubkey, keypair->pubkey.pubkey,
                        ED25519_PUBKEY_LEN)) {
    tor_log(severity, LD_OR, "Cert was for wrong key");
    bad_cert = 1;
  } else if (signing_key &&
             tor_cert_checksig(cert, &signing_key->pubkey, now) < 0) {
    tor_log(severity, LD_OR, "Can't check certificate: %s",
            tor_cert_describe_signature_status(cert));
    bad_cert = 1;
  } else if (cert->cert_expired) {
    tor_log(severity, LD_OR, "Certificate is expired");
    bad_cert = 1;
  } else if (signing_key && cert->signing_key_included &&
             ! ed25519_pubkey_eq(&signing_key->pubkey, &cert->signing_key)) {
    tor_log(severity, LD_OR, "Certificate signed by unexpectd key!");
    bad_cert = 1;
  }

  if (bad_cert) {
    tor_cert_free(cert);
    cert = NULL;
  }

  /* If we got a cert, we're done. */
  if (cert)
    goto done;

  /* If we didn't get a cert, and we're not supposed to make one, fail. */
  if (!signing_key || !(flags & INIT_ED_KEY_CREATE)) {
    tor_log(severity, LD_OR, "Without signing key, can't create certificate");
    goto err;
  }

  /* We have keys but not a certificate, so make one. */
  uint32_t cert_flags = 0;
  if (flags & INIT_ED_KEY_INCLUDE_SIGNING_KEY_IN_CERT)
    cert_flags |= CERT_FLAG_INCLUDE_SIGNING_KEY;
  cert = tor_cert_create(signing_key, cert_type,
                         &keypair->pubkey,
                         now, lifetime,
                         cert_flags);

  if (! cert) {
    tor_log(severity, LD_OR, "Couldn't create certificate");
    goto err;
  }

  /* Write it to disk. */
  created_cert = 1;
  if (crypto_write_tagged_contents_to_file(cert_fname, "ed25519v1-cert",
                             tag, cert->encoded, cert->encoded_len) < 0) {
    tor_log(severity, LD_OR, "Couldn't write cert to disk.");
    goto err;
  }

 done:
  if (cert_out)
    *cert_out = cert;
  else
    tor_cert_free(cert);

  goto cleanup;

 err:
  if (keypair)
    memwipe(keypair, 0, sizeof(*keypair));
  tor_free(keypair);
  tor_cert_free(cert);
  if (cert_out)
    *cert_out = NULL;
  if (created_sk)
    unlink(secret_fname);
  if (created_pk)
    unlink(public_fname);
  if (created_cert)
    unlink(cert_fname);

 cleanup:
  tor_free(encrypted_secret_fname);
  tor_free(secret_fname);
  tor_free(public_fname);
  tor_free(cert_fname);
  tor_free(got_tag);

  return keypair;
}

/**
 * Create a new signing key and (optionally) certficiate; do not read or write
 * from disk.  See ed_key_init_from_file() for more information.
 */
ed25519_keypair_t *
ed_key_new(const ed25519_keypair_t *signing_key,
           uint32_t flags,
           time_t now,
           time_t lifetime,
           uint8_t cert_type,
           struct tor_cert_st **cert_out)
{
  if (cert_out)
    *cert_out = NULL;

  const int extra_strong = !! (flags & INIT_ED_KEY_EXTRA_STRONG);
  ed25519_keypair_t *keypair = tor_malloc_zero(sizeof(ed25519_keypair_t));
  if (ed25519_keypair_generate(keypair, extra_strong) < 0)
    goto err;

  if (! (flags & INIT_ED_KEY_NEEDCERT))
    return keypair;

  tor_assert(signing_key);
  tor_assert(cert_out);
  uint32_t cert_flags = 0;
  if (flags & INIT_ED_KEY_INCLUDE_SIGNING_KEY_IN_CERT)
    cert_flags |= CERT_FLAG_INCLUDE_SIGNING_KEY;
  tor_cert_t *cert = tor_cert_create(signing_key, cert_type,
                                     &keypair->pubkey,
                                     now, lifetime,
                                     cert_flags);
  if (! cert)
    goto err;

  *cert_out = cert;
  return keypair;

 err:
  tor_free(keypair);
  return NULL;
}

static ed25519_keypair_t *master_identity_key = NULL;
static ed25519_keypair_t *master_signing_key = NULL;
static ed25519_keypair_t *current_auth_key = NULL;
static tor_cert_t *signing_key_cert = NULL;
static tor_cert_t *link_cert_cert = NULL;
static tor_cert_t *auth_key_cert = NULL;

static uint8_t *rsa_ed_crosscert = NULL;
static size_t rsa_ed_crosscert_len = 0;
static time_t rsa_ed_crosscert_expiration = 0;

/**
 * Running as a server: load, reload, or refresh our ed25519 keys and
 * certificates, creating and saving new ones as needed.
 *
 * Return -1 on failure; 0 on success if the signing key was not replaced;
 * and 1 on success if the signing key was replaced.
 */
int
load_ed_keys(const or_options_t *options, time_t now)
{
  ed25519_keypair_t *id = NULL;
  ed25519_keypair_t *sign = NULL;
  ed25519_keypair_t *auth = NULL;
  const ed25519_keypair_t *sign_signing_key_with_id = NULL;
  const ed25519_keypair_t *use_signing = NULL;
  const tor_cert_t *check_signing_cert = NULL;
  tor_cert_t *sign_cert = NULL;
  tor_cert_t *auth_cert = NULL;
  int signing_key_changed = 0;

  // It is later than 1972, since otherwise there would be no C compilers.
  // (Try to diagnose #22466.)
  tor_assert_nonfatal(now >= 2 * 365 * 86400);

#define FAIL(msg) do {                          \
    log_warn(LD_OR, (msg));                     \
    goto err;                                   \
  } while (0)
#define SET_KEY(key, newval) do {               \
    if ((key) != (newval))                      \
      ed25519_keypair_free(key);                \
    key = (newval);                             \
  } while (0)
#define SET_CERT(cert, newval) do {             \
    if ((cert) != (newval))                     \
      tor_cert_free(cert);                      \
    cert = (newval);                            \
  } while (0)
#define HAPPENS_SOON(when, interval)            \
  ((when) < now + (interval))
#define EXPIRES_SOON(cert, interval)            \
  (!(cert) || HAPPENS_SOON((cert)->valid_until, (interval)))

  /* XXXX support encrypted identity keys fully */

  /* First try to get the signing key to see how it is. */
  {
    char *fname =
      options_get_keydir_fname(options, "ed25519_signing");
    sign = ed_key_init_from_file(
               fname,
               INIT_ED_KEY_NEEDCERT|
               INIT_ED_KEY_INCLUDE_SIGNING_KEY_IN_CERT,
               LOG_INFO,
               NULL, 0, 0, CERT_TYPE_ID_SIGNING, &sign_cert);
    tor_free(fname);
    check_signing_cert = sign_cert;
    use_signing = sign;
  }

  if (use_signing) {
    /* We loaded a signing key with its certificate.  */
    if (! master_signing_key) {
      /* We didn't know one before! */
      signing_key_changed = 1;
    } else if (! ed25519_pubkey_eq(&use_signing->pubkey,
                                   &master_signing_key->pubkey) ||
               ! tor_memeq(use_signing->seckey.seckey,
                           master_signing_key->seckey.seckey,
                           ED25519_SECKEY_LEN)) {
      /* We loaded a different signing key than the one we knew before. */
      signing_key_changed = 1;
    }
  }

  if (!use_signing && master_signing_key) {
    /* We couldn't load a signing key, but we already had one loaded */
    check_signing_cert = signing_key_cert;
    use_signing = master_signing_key;
  }

  const int offline_master =
    options->OfflineMasterKey && options->command != CMD_KEYGEN;
  const int need_new_signing_key =
    NULL == use_signing ||
    EXPIRES_SOON(check_signing_cert, 0) ||
    (options->command == CMD_KEYGEN && ! options->change_key_passphrase);
  const int want_new_signing_key =
    need_new_signing_key ||
    EXPIRES_SOON(check_signing_cert, options->TestingSigningKeySlop);

  /* We can only create a master key if we haven't been told that the
   * master key will always be offline.  Also, if we have a signing key,
   * then we shouldn't make a new master ID key. */
  const int can_make_master_id_key = !offline_master &&
    NULL == use_signing;

  if (need_new_signing_key) {
    log_notice(LD_OR, "It looks like I need to generate and sign a new "
               "medium-term signing key, because %s. To do that, I "
               "need to load%s the permanent master identity key. "
               "If the master identity key was not moved or encrypted "
               "with a passphrase, this will be done automatically and "
               "no further action is required. Otherwise, provide the "
               "necessary data using 'tor --keygen' to do it manually.",
            (NULL == use_signing) ? "I don't have one" :
            EXPIRES_SOON(check_signing_cert, 0) ? "the one I have is expired" :
               "you asked me to make one with --keygen",
            can_make_master_id_key ? " (or create)" : "");
  } else if (want_new_signing_key && !offline_master) {
    log_notice(LD_OR, "It looks like I should try to generate and sign a "
               "new medium-term signing key, because the one I have is "
               "going to expire soon. To do that, I'm going to have to "
               "try to load the permanent master identity key. "
               "If the master identity key was not moved or encrypted "
               "with a passphrase, this will be done automatically and "
               "no further action is required. Otherwise, provide the "
               "necessary data using 'tor --keygen' to do it manually.");
  } else if (want_new_signing_key) {
    log_notice(LD_OR, "It looks like I should try to generate and sign a "
               "new medium-term signing key, because the one I have is "
               "going to expire soon. But OfflineMasterKey is set, so I "
               "won't try to load a permanent master identity key. You "
               "will need to use 'tor --keygen' to make a new signing "
               "key and certificate.");
  }

  {
    uint32_t flags =
      (INIT_ED_KEY_SPLIT|
       INIT_ED_KEY_EXTRA_STRONG|INIT_ED_KEY_NO_REPAIR);
    if (can_make_master_id_key)
      flags |= INIT_ED_KEY_CREATE;
    if (! need_new_signing_key)
      flags |= INIT_ED_KEY_MISSING_SECRET_OK;
    if (! want_new_signing_key || offline_master)
      flags |= INIT_ED_KEY_OMIT_SECRET;
    if (offline_master)
      flags |= INIT_ED_KEY_OFFLINE_SECRET;
    if (options->command == CMD_KEYGEN)
      flags |= INIT_ED_KEY_TRY_ENCRYPTED;

    /* Check/Create the key directory */
    if (create_keys_directory(options) < 0)
      goto err;

    char *fname;
    if (options->master_key_fname) {
      fname = tor_strdup(options->master_key_fname);
      flags |= INIT_ED_KEY_EXPLICIT_FNAME;
    } else {
      fname = options_get_keydir_fname(options, "ed25519_master_id");
    }
    id = ed_key_init_from_file(
             fname,
             flags,
             LOG_WARN, NULL, 0, 0, 0, NULL);
    tor_free(fname);
    if (!id) {
      if (need_new_signing_key) {
        if (offline_master)
          FAIL("Can't load master identity key; OfflineMasterKey is set.");
        else
          FAIL("Missing identity key");
      } else {
        log_warn(LD_OR, "Master public key was absent; inferring from "
                 "public key in signing certificate and saving to disk.");
        tor_assert(check_signing_cert);
        id = tor_malloc_zero(sizeof(*id));
        memcpy(&id->pubkey, &check_signing_cert->signing_key,
               sizeof(ed25519_public_key_t));
        fname = options_get_keydir_fname(options,
                                         "ed25519_master_id_public_key");
        if (ed25519_pubkey_write_to_file(&id->pubkey, fname, "type0") < 0) {
          log_warn(LD_OR, "Error while attempting to write master public key "
                   "to disk");
          tor_free(fname);
          goto err;
        }
        tor_free(fname);
      }
    }
    if (tor_mem_is_zero((char*)id->seckey.seckey, sizeof(id->seckey)))
      sign_signing_key_with_id = NULL;
    else
      sign_signing_key_with_id = id;
  }

  if (master_identity_key &&
      !ed25519_pubkey_eq(&id->pubkey, &master_identity_key->pubkey)) {
    FAIL("Identity key on disk does not match key we loaded earlier!");
  }

  if (need_new_signing_key && NULL == sign_signing_key_with_id)
    FAIL("Can't load master key make a new signing key.");

  if (sign_cert) {
    if (! sign_cert->signing_key_included)
      FAIL("Loaded a signing cert with no key included!");
    if (! ed25519_pubkey_eq(&sign_cert->signing_key, &id->pubkey))
      FAIL("The signing cert we have was not signed with the master key "
           "we loaded!");
    if (tor_cert_checksig(sign_cert, &id->pubkey, 0) < 0) {
      log_warn(LD_OR, "The signing cert we loaded was not signed "
               "correctly: %s!",
               tor_cert_describe_signature_status(sign_cert));
      goto err;
    }
  }

  if (want_new_signing_key && sign_signing_key_with_id) {
    uint32_t flags = (INIT_ED_KEY_CREATE|
                      INIT_ED_KEY_REPLACE|
                      INIT_ED_KEY_EXTRA_STRONG|
                      INIT_ED_KEY_NEEDCERT|
                      INIT_ED_KEY_INCLUDE_SIGNING_KEY_IN_CERT);
    char *fname =
      options_get_keydir_fname(options, "ed25519_signing");
    ed25519_keypair_free(sign);
    tor_cert_free(sign_cert);
    sign = ed_key_init_from_file(fname,
                                 flags, LOG_WARN,
                                 sign_signing_key_with_id, now,
                                 options->SigningKeyLifetime,
                                 CERT_TYPE_ID_SIGNING, &sign_cert);
    tor_free(fname);
    if (!sign)
      FAIL("Missing signing key");
    use_signing = sign;
    signing_key_changed = 1;

    tor_assert(sign_cert->signing_key_included);
    tor_assert(ed25519_pubkey_eq(&sign_cert->signing_key, &id->pubkey));
    tor_assert(ed25519_pubkey_eq(&sign_cert->signed_key, &sign->pubkey));
  } else if (want_new_signing_key) {
    static ratelim_t missing_master = RATELIM_INIT(3600);
    log_fn_ratelim(&missing_master, LOG_WARN, LD_OR,
                   "Signing key will expire soon, but I can't load the "
                   "master key to sign a new one!");
  }

  tor_assert(use_signing);

  /* At this point we no longer need our secret identity key.  So wipe
   * it, if we loaded it in the first place. */
  memwipe(id->seckey.seckey, 0, sizeof(id->seckey));

  if (options->command == CMD_KEYGEN)
    goto end;

  if (server_mode(options) &&
      (!rsa_ed_crosscert ||
       HAPPENS_SOON(rsa_ed_crosscert_expiration, 30*86400))) {
    uint8_t *crosscert;
    time_t expiration = now+6*30*86400; /* 6 months in the future. */
    ssize_t crosscert_len = tor_make_rsa_ed25519_crosscert(&id->pubkey,
                                                   get_server_identity_key(),
                                                   expiration,
                                                   &crosscert);
    tor_free(rsa_ed_crosscert);
    rsa_ed_crosscert_len = crosscert_len;
    rsa_ed_crosscert = crosscert;
    rsa_ed_crosscert_expiration = expiration;
  }

  if (!current_auth_key ||
      signing_key_changed ||
      EXPIRES_SOON(auth_key_cert, options->TestingAuthKeySlop)) {
    auth = ed_key_new(use_signing, INIT_ED_KEY_NEEDCERT,
                      now,
                      options->TestingAuthKeyLifetime,
                      CERT_TYPE_SIGNING_AUTH, &auth_cert);

    if (!auth)
      FAIL("Can't create auth key");
  }

  /* We've generated or loaded everything.  Put them in memory. */

 end:
  if (! master_identity_key) {
    SET_KEY(master_identity_key, id);
  } else {
    tor_free(id);
  }
  if (sign) {
    SET_KEY(master_signing_key, sign);
    SET_CERT(signing_key_cert, sign_cert);
  }
  if (auth) {
    SET_KEY(current_auth_key, auth);
    SET_CERT(auth_key_cert, auth_cert);
  }

  return signing_key_changed;
 err:
  ed25519_keypair_free(id);
  ed25519_keypair_free(sign);
  ed25519_keypair_free(auth);
  tor_cert_free(sign_cert);
  tor_cert_free(auth_cert);
  return -1;
}

/**
 * Retrieve our currently-in-use Ed25519 link certificate and id certificate,
 * and, if they would expire soon (based on the time <b>now</b>, generate new
 * certificates (without embedding the public part of the signing key inside).
 * If <b>force</b> is true, always generate a new certificate.
 *
 * The signed_key from the current id->signing certificate will be used to
 * sign the new key within newly generated X509 certificate.
 *
 * Returns -1 upon error.  Otherwise, returns 0 upon success (either when the
 * current certificate is still valid, or when a new certificate was
 * successfully generated, or no certificate was needed).
 */
int
generate_ed_link_cert(const or_options_t *options, time_t now,
                      int force)
{
  const tor_x509_cert_t *link_ = NULL, *id = NULL;
  tor_cert_t *link_cert = NULL;

  if (tor_tls_get_my_certs(1, &link_, &id) < 0 || link_ == NULL) {
    if (!server_mode(options)) {
        /* No need to make an Ed25519->Link cert: we are a client */
      return 0;
    }
    log_warn(LD_OR, "Can't get my x509 link cert.");
    return -1;
  }

  const common_digests_t *digests = tor_x509_cert_get_cert_digests(link_);

  if (force == 0 &&
      link_cert_cert &&
      ! EXPIRES_SOON(link_cert_cert, options->TestingLinkKeySlop) &&
      fast_memeq(digests->d[DIGEST_SHA256], link_cert_cert->signed_key.pubkey,
                 DIGEST256_LEN)) {
    return 0;
  }

  ed25519_public_key_t dummy_key;
  memcpy(dummy_key.pubkey, digests->d[DIGEST_SHA256], DIGEST256_LEN);

  link_cert = tor_cert_create(get_master_signing_keypair(),
                              CERT_TYPE_SIGNING_LINK,
                              &dummy_key,
                              now,
                              options->TestingLinkCertLifetime, 0);

  if (link_cert) {
    SET_CERT(link_cert_cert, link_cert);
  }
  return 0;
}

#undef FAIL
#undef SET_KEY
#undef SET_CERT

/**
 * Return 1 if any of the following are true:
 *
 *   - if one of our Ed25519 signing, auth, or link certificates would expire
 *     soon w.r.t. the time <b>now</b>,
 *   - if we do not currently have a link certificate, or
 *   - if our cached Ed25519 link certificate is not same as the one we're
 *     currently using.
 *
 * Otherwise, returns 0.
 */
int
should_make_new_ed_keys(const or_options_t *options, const time_t now)
{
  if (!master_identity_key ||
      !master_signing_key ||
      !current_auth_key ||
      !link_cert_cert ||
      EXPIRES_SOON(signing_key_cert, options->TestingSigningKeySlop) ||
      EXPIRES_SOON(auth_key_cert, options->TestingAuthKeySlop) ||
      EXPIRES_SOON(link_cert_cert, options->TestingLinkKeySlop))
    return 1;

  const tor_x509_cert_t *link_ = NULL, *id = NULL;

  if (tor_tls_get_my_certs(1, &link_, &id) < 0 || link_ == NULL)
    return 1;

  const common_digests_t *digests = tor_x509_cert_get_cert_digests(link_);

  if (!fast_memeq(digests->d[DIGEST_SHA256],
                  link_cert_cert->signed_key.pubkey,
                  DIGEST256_LEN)) {
    return 1;
  }

  return 0;
}

#undef EXPIRES_SOON
#undef HAPPENS_SOON

#ifdef TOR_UNIT_TESTS
/* Helper for unit tests: populate the ed25519 keys without saving or
 * loading */
void
init_mock_ed_keys(const crypto_pk_t *rsa_identity_key)
{
  routerkeys_free_all();

#define MAKEKEY(k)                                      \
  k = tor_malloc_zero(sizeof(*k));                      \
  if (ed25519_keypair_generate(k, 0) < 0) {             \
    log_warn(LD_BUG, "Couldn't make a keypair");        \
    goto err;                                           \
  }
  MAKEKEY(master_identity_key);
  MAKEKEY(master_signing_key);
  MAKEKEY(current_auth_key);
#define MAKECERT(cert, signing, signed_, type, flags)            \
  cert = tor_cert_create(signing,                                \
                         type,                                   \
                         &signed_->pubkey,                       \
                         time(NULL), 86400,                      \
                         flags);                                 \
  if (!cert) {                                                   \
    log_warn(LD_BUG, "Couldn't make a %s certificate!", #cert);  \
    goto err;                                                    \
  }

  MAKECERT(signing_key_cert,
           master_identity_key, master_signing_key, CERT_TYPE_ID_SIGNING,
           CERT_FLAG_INCLUDE_SIGNING_KEY);
  MAKECERT(auth_key_cert,
           master_signing_key, current_auth_key, CERT_TYPE_SIGNING_AUTH, 0);

  if (generate_ed_link_cert(get_options(), time(NULL), 0) < 0) {
    log_warn(LD_BUG, "Couldn't make link certificate");
    goto err;
  }

  rsa_ed_crosscert_len = tor_make_rsa_ed25519_crosscert(
                                     &master_identity_key->pubkey,
                                     rsa_identity_key,
                                     time(NULL)+86400,
                                     &rsa_ed_crosscert);

  return;

 err:
  routerkeys_free_all();
  tor_assert_nonfatal_unreached();
}
#undef MAKEKEY
#undef MAKECERT
#endif /* defined(TOR_UNIT_TESTS) */

/**
 * Print the ISO8601-formated <b>expiration</b> for a certificate with
 * some <b>description</b> to stdout.
 *
 * For example, for a signing certificate, this might print out:
 * signing-cert-expiry: 2017-07-25 08:30:15 UTC
 */
static void
print_cert_expiration(const char *expiration,
                      const char *description)
{
  fprintf(stderr, "%s-cert-expiry: %s\n", description, expiration);
}

/**
 * Log when a certificate, <b>cert</b>, with some <b>description</b> and
 * stored in a file named <b>fname</b>, is going to expire.
 */
static void
log_ed_cert_expiration(const tor_cert_t *cert,
                       const char *description,
                       const char *fname) {
  char expiration[ISO_TIME_LEN+1];

  if (BUG(!cert)) { /* If the specified key hasn't been loaded */
    log_warn(LD_OR, "No %s key loaded; can't get certificate expiration.",
             description);
  } else {
    format_local_iso_time(expiration, cert->valid_until);
    log_notice(LD_OR, "The %s certificate stored in %s is valid until %s.",
               description, fname, expiration);
    print_cert_expiration(expiration, description);
  }
}

/**
 * Log when our master signing key certificate expires.  Used when tor is given
 * the --key-expiration command-line option.
 *
 * Returns 0 on success and 1 on failure.
 */
static int
log_master_signing_key_cert_expiration(const or_options_t *options)
{
  const tor_cert_t *signing_key;
  char *fn = NULL;
  int failed = 0;
  time_t now = approx_time();

  fn = options_get_keydir_fname(options, "ed25519_signing_cert");

  /* Try to grab our cached copy of the key. */
  signing_key = get_master_signing_key_cert();

  tor_assert(server_identity_key_is_set());

  /* Load our keys from disk, if necessary. */
  if (!signing_key) {
    failed = load_ed_keys(options, now) < 0;
    signing_key = get_master_signing_key_cert();
  }

  /* If we do have a signing key, log the expiration time. */
  if (signing_key) {
    log_ed_cert_expiration(signing_key, "signing", fn);
  } else {
    log_warn(LD_OR, "Could not load signing key certificate from %s, so " \
             "we couldn't learn anything about certificate expiration.", fn);
  }

  tor_free(fn);

  return failed;
}

/**
 * Log when a key certificate expires.  Used when tor is given the
 * --key-expiration command-line option.
 *
 * If an command argument is given, which should specify the type of
 * key to get expiry information about (currently supported arguments
 * are "sign"), get info about that type of certificate.  Otherwise,
 * print info about the supported arguments.
 *
 * Returns 0 on success and -1 on failure.
 */
int
log_cert_expiration(void)
{
  const or_options_t *options = get_options();
  const char *arg = options->command_arg;

  if (!strcmp(arg, "sign")) {
    return log_master_signing_key_cert_expiration(options);
  } else {
    fprintf(stderr, "No valid argument to --key-expiration found!\n");
    fprintf(stderr, "Currently recognised arguments are: 'sign'\n");

    return -1;
  }
}

const ed25519_public_key_t *
get_master_identity_key(void)
{
  if (!master_identity_key)
    return NULL;
  return &master_identity_key->pubkey;
}

/** Return true iff <b>id</b> is our Ed25519 master identity key. */
int
router_ed25519_id_is_me(const ed25519_public_key_t *id)
{
  return id && master_identity_key &&
    ed25519_pubkey_eq(id, &master_identity_key->pubkey);
}

#ifdef TOR_UNIT_TESTS
/* only exists for the unit tests, since otherwise the identity key
 * should be used to sign nothing but the signing key. */
const ed25519_keypair_t *
get_master_identity_keypair(void)
{
  return master_identity_key;
}
#endif /* defined(TOR_UNIT_TESTS) */

const ed25519_keypair_t *
get_master_signing_keypair(void)
{
  return master_signing_key;
}

const struct tor_cert_st *
get_master_signing_key_cert(void)
{
  return signing_key_cert;
}

const ed25519_keypair_t *
get_current_auth_keypair(void)
{
  return current_auth_key;
}

const tor_cert_t *
get_current_link_cert_cert(void)
{
  return link_cert_cert;
}

const tor_cert_t *
get_current_auth_key_cert(void)
{
  return auth_key_cert;
}

void
get_master_rsa_crosscert(const uint8_t **cert_out,
                         size_t *size_out)
{
  *cert_out = rsa_ed_crosscert;
  *size_out = rsa_ed_crosscert_len;
}

/** Construct cross-certification for the master identity key with
 * the ntor onion key. Store the sign of the corresponding ed25519 public key
 * in *<b>sign_out</b>. */
tor_cert_t *
make_ntor_onion_key_crosscert(const curve25519_keypair_t *onion_key,
      const ed25519_public_key_t *master_id_key, time_t now, time_t lifetime,
      int *sign_out)
{
  tor_cert_t *cert = NULL;
  ed25519_keypair_t ed_onion_key;

  if (ed25519_keypair_from_curve25519_keypair(&ed_onion_key, sign_out,
                                              onion_key) < 0)
    goto end;

  cert = tor_cert_create(&ed_onion_key, CERT_TYPE_ONION_ID, master_id_key,
      now, lifetime, 0);

 end:
  memwipe(&ed_onion_key, 0, sizeof(ed_onion_key));
  return cert;
}

/** Construct and return an RSA signature for the TAP onion key to
 * cross-certify the RSA and Ed25519 identity keys. Set <b>len_out</b> to its
 * length. */
uint8_t *
make_tap_onion_key_crosscert(const crypto_pk_t *onion_key,
                             const ed25519_public_key_t *master_id_key,
                             const crypto_pk_t *rsa_id_key,
                             int *len_out)
{
  uint8_t signature[PK_BYTES];
  uint8_t signed_data[DIGEST_LEN + ED25519_PUBKEY_LEN];

  *len_out = 0;
  if (crypto_pk_get_digest(rsa_id_key, (char*)signed_data) < 0) {
    return NULL;
  }
  memcpy(signed_data + DIGEST_LEN, master_id_key->pubkey, ED25519_PUBKEY_LEN);

  int r = crypto_pk_private_sign(onion_key,
                               (char*)signature, sizeof(signature),
                               (const char*)signed_data, sizeof(signed_data));
  if (r < 0)
    return NULL;

  *len_out = r;

  return tor_memdup(signature, r);
}

/** Check whether an RSA-TAP cross-certification is correct. Return 0 if it
 * is, -1 if it isn't. */
MOCK_IMPL(int,
check_tap_onion_key_crosscert,(const uint8_t *crosscert,
                               int crosscert_len,
                               const crypto_pk_t *onion_pkey,
                               const ed25519_public_key_t *master_id_pkey,
                               const uint8_t *rsa_id_digest))
{
  uint8_t *cc = tor_malloc(crypto_pk_keysize(onion_pkey));
  int cc_len =
    crypto_pk_public_checksig(onion_pkey,
                              (char*)cc,
                              crypto_pk_keysize(onion_pkey),
                              (const char*)crosscert,
                              crosscert_len);
  if (cc_len < 0) {
    goto err;
  }
  if (cc_len < DIGEST_LEN + ED25519_PUBKEY_LEN) {
    log_warn(LD_DIR, "Short signature on cross-certification with TAP key");
    goto err;
  }
  if (tor_memneq(cc, rsa_id_digest, DIGEST_LEN) ||
      tor_memneq(cc + DIGEST_LEN, master_id_pkey->pubkey,
                 ED25519_PUBKEY_LEN)) {
    log_warn(LD_DIR, "Incorrect cross-certification with TAP key");
    goto err;
  }

  tor_free(cc);
  return 0;
 err:
  tor_free(cc);
  return -1;
}

void
routerkeys_free_all(void)
{
  ed25519_keypair_free(master_identity_key);
  ed25519_keypair_free(master_signing_key);
  ed25519_keypair_free(current_auth_key);
  tor_cert_free(signing_key_cert);
  tor_cert_free(link_cert_cert);
  tor_cert_free(auth_key_cert);
  tor_free(rsa_ed_crosscert);

  master_identity_key = master_signing_key = NULL;
  current_auth_key = NULL;
  signing_key_cert = link_cert_cert = auth_key_cert = NULL;
  rsa_ed_crosscert = NULL; // redundant
  rsa_ed_crosscert_len = 0;
}
