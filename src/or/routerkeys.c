/* Copyright (c) 2014, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#include "config.h"
#include "routerkeys.h"
#include "torcert.h"

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
  char *public_fname = NULL;
  char *cert_fname = NULL;
  int created_pk = 0, created_sk = 0, created_cert = 0;
  const int try_to_load = ! (flags & INIT_ED_KEY_REPLACE);

  char tag[8];
  tor_snprintf(tag, sizeof(tag), "type%d", (int)cert_type);

  tor_cert_t *cert = NULL;
  char *got_tag = NULL;
  ed25519_keypair_t *keypair = tor_malloc_zero(sizeof(ed25519_keypair_t));

  tor_asprintf(&secret_fname, "%s_secret_key", fname);
  tor_asprintf(&public_fname, "%s_public_key", fname);
  tor_asprintf(&cert_fname, "%s_cert", fname);

  /* Try to read the secret key. */
  const int have_secret = try_to_load &&
    ed25519_seckey_read_from_file(&keypair->seckey,
                                  &got_tag, secret_fname) == 0;

  if (have_secret) {
    if (strcmp(got_tag, tag)) {
      tor_log(severity, LD_OR, "%s has wrong tag", secret_fname);
      goto err;
    }
    /* Derive the public key */
    if (ed25519_public_key_generate(&keypair->pubkey, &keypair->seckey)<0) {
      tor_log(severity, LD_OR, "%s can't produce a public key", secret_fname);
      goto err;
    }
  }

  /* If it's absent and that's okay, try to read the pubkey. */
  int found_public = 0;
  if (!have_secret && try_to_load && (flags & INIT_ED_KEY_MISSING_SECRET_OK)) {
    tor_free(got_tag);
    found_public = ed25519_pubkey_read_from_file(&keypair->pubkey,
                                                 &got_tag, public_fname) == 0;
    if (found_public && strcmp(got_tag, tag)) {
      tor_log(severity, LD_OR, "%s has wrong tag", public_fname);
      goto err;
    }
  }

  /* If it's absent, and we're not supposed to make a new keypair, fail. */
  if (!have_secret && !found_public && !(flags & INIT_ED_KEY_CREATE))
    goto err;

  /* if it's absent, make a new keypair and save it. */
  if (!have_secret && !found_public) {
    const int split = !! (flags & INIT_ED_KEY_SPLIT);
    tor_free(keypair);
    keypair = ed_key_new(signing_key, flags, now, lifetime,
                         cert_type, &cert);
    if (!keypair) {
      tor_log(severity, LD_OR, "Couldn't create keypair");
      goto err;
    }

    created_pk = created_sk = created_cert = 1;
    if (ed25519_seckey_write_to_file(&keypair->seckey, secret_fname, tag) < 0
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
  uint8_t certbuf[256];
  ssize_t cert_body_len = crypto_read_tagged_contents_from_file(
                 cert_fname, "ed25519v1-cert",
                 &got_tag, certbuf, sizeof(certbuf));
  if (cert_body_len >= 0 && !strcmp(got_tag, tag))
    cert = tor_cert_parse(certbuf, cert_body_len);

  /* If we got it, check it to the extent we can. */
  if (cert) {
    int bad_cert = 0;

    if (! cert) {
      tor_log(severity, LD_OR, "Cert was unparseable");
      bad_cert = 1;
    } else if (!tor_memeq(cert->signed_key.pubkey, keypair->pubkey.pubkey,
                          ED25519_PUBKEY_LEN)) {
      tor_log(severity, LD_OR, "Cert was for wrong key");
      bad_cert = 1;
    } else if (tor_cert_checksig(cert, &signing_key->pubkey, now) < 0 &&
               (signing_key || cert->cert_expired)) {
      tor_log(severity, LD_OR, "Can't check certificate");
      bad_cert = 1;
    }

    if (bad_cert) {
      tor_cert_free(cert);
      cert = NULL;
    }
  }

  /* If we got a cert, we're done. */
  if (cert)
    goto done;

  /* If we didn't get a cert, and we're not supposed to make one, fail. */
  if (!signing_key || !(flags & INIT_ED_KEY_CREATE))
    goto err;

  /* We have keys but not a certificate, so make one. */
  uint32_t cert_flags = 0;
  if (flags & INIT_ED_KEY_INCLUDE_SIGNING_KEY_IN_CERT)
    cert_flags |= CERT_FLAG_INCLUDE_SIGNING_KEY;
  cert = tor_cert_create(signing_key, cert_type,
                         &keypair->pubkey,
                         now, lifetime,
                         cert_flags);

  if (! cert)
    goto err;

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
  tor_free(secret_fname);
  tor_free(public_fname);
  tor_free(cert_fname);

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
static ed25519_keypair_t *current_link_key = NULL;
static ed25519_keypair_t *current_auth_key = NULL;
static tor_cert_t *signing_key_cert = NULL;
static tor_cert_t *link_key_cert = NULL;
static tor_cert_t *auth_key_cert = NULL;

/**
 * Running as a server: load, reload, or refresh our ed25519 keys and
 * certificates, creating and saving new ones as needed.
 */
int
load_ed_keys(const or_options_t *options, time_t now)
{
  ed25519_keypair_t *id = NULL;
  ed25519_keypair_t *sign = NULL;
  ed25519_keypair_t *link = NULL;
  ed25519_keypair_t *auth = NULL;
  const ed25519_keypair_t *use_signing = NULL;
  tor_cert_t *sign_cert = NULL;
  tor_cert_t *link_cert = NULL;
  tor_cert_t *auth_cert = NULL;

#define FAIL(msg) do {                          \
    log_warn(LD_OR, (msg));                     \
    goto err;                                   \
  } while (0)
#define SET_KEY(key, newval) do {               \
    ed25519_keypair_free(key);                  \
    key = (newval);                             \
  } while (0)
#define SET_CERT(cert, newval) do {             \
    tor_cert_free(cert);                        \
    cert = (newval);                            \
  } while (0)
#define EXPIRES_SOON(cert, interval)            \
  (!(cert) || (cert)->valid_until < now + (interval))

  /* XXXX support encrypted identity keys fully */

  /* XXXX use options. */
  (void) options;

  id = ed_key_init_from_file(
               options_get_datadir_fname2(options, "keys", "ed25519_master_id"),
                             (INIT_ED_KEY_CREATE|INIT_ED_KEY_SPLIT|
                              INIT_ED_KEY_MISSING_SECRET_OK|
                              INIT_ED_KEY_EXTRA_STRONG),
                             LOG_WARN, NULL, 0, 0, 0, NULL);
  if (!id)
    FAIL("Missing identity key");

  if (!master_signing_key || EXPIRES_SOON(signing_key_cert, 86400/*???*/)) {
    uint32_t flags = (INIT_ED_KEY_CREATE|
                      INIT_ED_KEY_EXTRA_STRONG|
                      INIT_ED_KEY_NEEDCERT|
                      INIT_ED_KEY_INCLUDE_SIGNING_KEY_IN_CERT);
    const ed25519_keypair_t *sign_with_id = id;
    if (master_signing_key) {
      flags |= INIT_ED_KEY_REPLACE; /* it's expired, so force-replace it. */
    }
    if (tor_mem_is_zero((char*)id->seckey.seckey, sizeof(id->seckey))) {
      sign_with_id = NULL;
      flags &= ~INIT_ED_KEY_CREATE;
    }
    sign = ed_key_init_from_file(
               options_get_datadir_fname2(options, "keys", "ed25519_signing"),
                                 flags, LOG_WARN,
                                 sign_with_id, now, 30*86400/*XXX option*/,
                                 CERT_TYPE_ID_SIGNING, &sign_cert);
    if (!sign)
      FAIL("Missing signing key");
    use_signing = sign;
  } else {
    use_signing = master_signing_key;
  }

  /* At this point we no longer need our secret identity key.  So wipe
   * it, if we loaded it in the first place. */
  memwipe(id->seckey.seckey, 0, sizeof(id->seckey));

  if (!current_link_key || EXPIRES_SOON(link_key_cert, 7200/*???*/)) {
    link = ed_key_new(use_signing, INIT_ED_KEY_NEEDCERT,
                      now, 2*86400/*XXX option??*/,
                      CERT_TYPE_SIGNING_LINK, &link_cert);

    if (!link)
      FAIL("Can't create link key");
  }

  if (!current_auth_key || EXPIRES_SOON(auth_key_cert, 7200)/*???*/) {
    auth = ed_key_new(use_signing, INIT_ED_KEY_NEEDCERT,
                      now, 2*86400/*XXX option??*/,
                      CERT_TYPE_SIGNING_AUTH, &auth_cert);

    if (!auth)
      FAIL("Can't create auth key");
  }

  /* We've generated or loaded everything.  Put them in memory. */

  if (! master_identity_key) {
    SET_KEY(master_identity_key, id);
  } else {
    tor_free(id);
  }
  if (sign) {
    SET_KEY(master_signing_key, sign);
    SET_CERT(signing_key_cert, sign_cert);
  }
  if (link) {
    SET_KEY(current_link_key, link);
    SET_CERT(link_key_cert, link_cert);
  }
  if (auth) {
    SET_KEY(current_auth_key, auth);
    SET_CERT(auth_key_cert, auth_cert);
  }

  return 0;
 err:
  ed25519_keypair_free(id);
  ed25519_keypair_free(sign);
  ed25519_keypair_free(link);
  ed25519_keypair_free(auth);
  tor_cert_free(sign_cert);
  tor_cert_free(link_cert);
  tor_cert_free(auth_cert);
  return -1;
#undef FAIL
#undef SET_KEY
#undef SET_CERT
#undef EXPIRES_SOON
}

const ed25519_public_key_t *
get_master_identity_key(void)
{
  if (!master_identity_key)
    return NULL;
  return &master_identity_key->pubkey;
}

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
get_current_link_keypair(void)
{
  return current_link_key;
}

const ed25519_keypair_t *
get_current_auth_keypair(void)
{
  return current_auth_key;
}

const tor_cert_t *
get_current_link_key_cert(void)
{
  return link_key_cert;
}

const tor_cert_t *
get_current_auth_key_cert(void)
{
  return auth_key_cert;
}

void
routerkeys_free_all(void)
{
  ed25519_keypair_free(master_identity_key);
  ed25519_keypair_free(master_signing_key);
  ed25519_keypair_free(current_link_key);
  ed25519_keypair_free(current_auth_key);
  tor_cert_free(signing_key_cert);
  tor_cert_free(link_key_cert);
  tor_cert_free(auth_key_cert);

  master_identity_key = master_signing_key = NULL;
  current_link_key = current_auth_key = NULL;
  signing_key_cert = link_key_cert = auth_key_cert = NULL;
}

