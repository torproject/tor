/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/**
 * \file router.c
 * \brief OR functionality, including key maintenance, generating
 * and uploading server descriptors, retrying OR connections.
 **/

extern or_options_t options; /* command-line and config-file options */

/** Exposed for test.c. */ void get_platform_str(char *platform, int len);

/************************************************************/

/*****
 * Key management: ORs only.
 *****/

/** Private keys for this OR.  There is also an SSL key managed by tortls.c.
 */
static tor_mutex_t *key_lock=NULL;
static time_t onionkey_set_at=0; /* When was onionkey last changed? */
static crypto_pk_env_t *onionkey=NULL;
static crypto_pk_env_t *lastonionkey=NULL;
static crypto_pk_env_t *identitykey=NULL;

/** Replace the current onion key with <b>k</b>.  Does not affect lastonionkey;
 * to update onionkey correctly, call rotate_onion_key().
 */
void set_onion_key(crypto_pk_env_t *k) {
  tor_mutex_acquire(key_lock);
  onionkey = k;
  onionkey_set_at = time(NULL);
  tor_mutex_release(key_lock);
}

/** Return the current onion key.  Requires that the onion key has been
 * loaded or generated. */
crypto_pk_env_t *get_onion_key(void) {
  tor_assert(onionkey);
  return onionkey;
}

/** Return the onion key that was current before the most recent onion
 * key rotation.  If no rotation has been performed since this process
 * started, return NULL.
 */
crypto_pk_env_t *get_previous_onion_key(void) {
  return lastonionkey;
}

void dup_onion_keys(crypto_pk_env_t **key, crypto_pk_env_t **last)
{
  tor_assert(key && last);
  tor_mutex_acquire(key_lock);
  *key = crypto_pk_dup_key(onionkey);
  if (lastonionkey)
    *last = crypto_pk_dup_key(lastonionkey);
  else
    *last = NULL;
  tor_mutex_release(key_lock);
}

/** Return the time when the onion key was last set.  This is either the time
 * when the process launched, or the time of the most recent key rotation since
 * the process launched.
 */
time_t get_onion_key_set_at(void) {
  return onionkey_set_at;
}

/** Set the current identity key to k.
 */
void set_identity_key(crypto_pk_env_t *k) {
  identitykey = k;
}

/** Returns the current identity key; requires that the identity key has been
 * set.
 */
crypto_pk_env_t *get_identity_key(void) {
  tor_assert(identitykey);
  return identitykey;
}

/** Replace the previous onion key with the current onion key, and generate
 * a new previous onion key.  Immediately after calling this function,
 * the OR should:
 *   - schedule all previous cpuworkers to shut down _after_ processing
 *     pending work.  (This will cause fresh cpuworkers to be generated.)
 *   - generate and upload a fresh routerinfo.
 */
void rotate_onion_key(void)
{
  char fname[512];
  crypto_pk_env_t *prkey;
  sprintf(fname,"%s/keys/onion.key",options.DataDirectory);
  if (!(prkey = crypto_new_pk_env())) {
    log(LOG_ERR, "Error creating crypto environment.");
    goto error;
  }
  if (crypto_pk_generate_key(prkey)) {
    log(LOG_ERR, "Error generating onion key");
    goto error;
  }
  if (crypto_pk_write_private_key_to_filename(prkey, fname)) {
    log(LOG_ERR, "Couldn't write generated key to %s.", fname);
    goto error;
  }
  tor_mutex_acquire(key_lock);
  if (lastonionkey)
    crypto_free_pk_env(lastonionkey);
  log_fn(LOG_INFO, "Rotating onion key");
  lastonionkey = onionkey;
  set_onion_key(prkey);
  tor_mutex_release(key_lock);
  return;
 error:
  log_fn(LOG_WARN, "Couldn't rotate onion key.");
}

/** Try to read an RSA key from <b>fname</b>.  If <b>fname</b> doesn't exist,
 * create a new RSA key and save it in <b>fname</b>.  Return the read/created
 * key, or NULL on error.
 */
crypto_pk_env_t *init_key_from_file(const char *fname)
{
  crypto_pk_env_t *prkey = NULL;
  FILE *file = NULL;

  if (!(prkey = crypto_new_pk_env())) {
    log(LOG_ERR, "Error creating crypto environment.");
    goto error;
  }

  switch(file_status(fname)) {
  case FN_DIR:
  case FN_ERROR:
    log(LOG_ERR, "Can't read key from %s", fname);
    goto error;
  case FN_NOENT:
    log(LOG_INFO, "No key found in %s; generating fresh key.", fname);
    if (crypto_pk_generate_key(prkey)) {
      log(LOG_ERR, "Error generating onion key");
      goto error;
    }
    if (crypto_pk_check_key(prkey) <= 0) {
      log(LOG_ERR, "Generated key seems invalid");
      goto error;
    }
    log(LOG_INFO, "Generated key seems valid");
    if (crypto_pk_write_private_key_to_filename(prkey, fname)) {
      log(LOG_ERR, "Couldn't write generated key to %s.", fname);
      goto error;
    }
    return prkey;
  case FN_FILE:
    if (crypto_pk_read_private_key_from_filename(prkey, fname)) {
      log(LOG_ERR, "Error loading private key.");
      goto error;
    }
    return prkey;
  default:
    tor_assert(0);
  }

 error:
  if (prkey)
    crypto_free_pk_env(prkey);
  if (file)
    fclose(file);
  return NULL;
}

/** Initialize all OR private keys, and the TLS context, as necessary.
 * On OPs, this only initializes the tls context.
 */
int init_keys(void) {
  char keydir[512];
  char fingerprint[FINGERPRINT_LEN+MAX_NICKNAME_LEN+3];
  char *cp;
  const char *tmp, *mydesc;
  crypto_pk_env_t *prkey;

  if (!key_lock)
    key_lock = tor_mutex_new();

  /* OP's don't need keys.  Just initialize the TLS context.*/
  if (!options.ORPort) {
    tor_assert(!options.DirPort);
    if (tor_tls_context_new(NULL, 0, NULL, 0)<0) {
      log_fn(LOG_ERR, "Error creating TLS context for OP.");
      return -1;
    }
    return 0;
  }
  /* Make sure DataDirectory exists, and is private. */
  tor_assert(options.DataDirectory);
  if (strlen(options.DataDirectory) > (512-128)) {
    log_fn(LOG_ERR, "DataDirectory is too long.");
    return -1;
  }
  if (check_private_dir(options.DataDirectory, 1)) {
    return -1;
  }
  /* Check the key directory. */
  sprintf(keydir,"%s/keys",options.DataDirectory);
  if (check_private_dir(keydir, 1)) {
    return -1;
  }
  cp = keydir + strlen(keydir); /* End of string. */

  /* 1. Read identity key. Make it if none is found. */
  strcpy(cp, "/identity.key");
  log_fn(LOG_INFO,"Reading/making identity key %s...",keydir);
  prkey = init_key_from_file(keydir);
  if (!prkey) return -1;
  set_identity_key(prkey);
  /* 2. Read onion key.  Make it if none is found. */
  strcpy(cp, "/onion.key");
  log_fn(LOG_INFO,"Reading/making onion key %s...",keydir);
  prkey = init_key_from_file(keydir);
  if (!prkey) return -1;
  set_onion_key(prkey);

  /* 3. Initialize link key and TLS context. */
  if (tor_tls_context_new(get_identity_key(), 1, options.Nickname,
                          MAX_SSL_KEY_LIFETIME) < 0) {
    log_fn(LOG_ERR, "Error initializing TLS context");
    return -1;
  }
  /* 4. Dump router descriptor to 'router.desc' */
  /* Must be called after keys are initialized. */
  if (!(router_get_my_descriptor())) {
    log_fn(LOG_ERR, "Error initializing descriptor.");
    return -1;
  }
  /* We need to add our own fingerprint so it gets recognized. */
  if (dirserv_add_own_fingerprint(options.Nickname, get_identity_key())) {
    log_fn(LOG_ERR, "Error adding own fingerprint to approved set");
    return -1;
  }
  tmp = mydesc = router_get_my_descriptor();
  if (dirserv_add_descriptor(&tmp) != 1) {
    log(LOG_ERR, "Unable to add own descriptor to directory.");
    return -1;
  }
  sprintf(keydir,"%s/router.desc", options.DataDirectory);
  log_fn(LOG_INFO,"Dumping descriptor to %s...",keydir);
  if (write_str_to_file(keydir, mydesc)) {
    return -1;
  }
  /* 5. Dump fingerprint to 'fingerprint' */
  sprintf(keydir,"%s/fingerprint", options.DataDirectory);
  log_fn(LOG_INFO,"Dumping fingerprint to %s...",keydir);
  tor_assert(strlen(options.Nickname) <= MAX_NICKNAME_LEN);
  strcpy(fingerprint, options.Nickname);
  strcat(fingerprint, " ");
  if (crypto_pk_get_fingerprint(get_identity_key(),
                                fingerprint+strlen(fingerprint))<0) {
    log_fn(LOG_ERR, "Error computing fingerprint");
    return -1;
  }
  strcat(fingerprint, "\n");
  if (write_str_to_file(keydir, fingerprint))
    return -1;
  if(!options.DirPort)
    return 0;
  /* 6. [dirserver only] load approved-routers file */
  sprintf(keydir,"%s/approved-routers", options.DataDirectory);
  log_fn(LOG_INFO,"Loading approved fingerprints from %s...",keydir);
  if(dirserv_parse_fingerprint_file(keydir) < 0) {
    log_fn(LOG_ERR, "Error loading fingerprints");
    return -1;
  }
  /* 7. [dirserver only] load old directory, if it's there */
  sprintf(keydir,"%s/cached-directory", options.DataDirectory);
  log_fn(LOG_INFO,"Loading cached directory from %s...",keydir);
  cp = read_file_to_str(keydir);
  if(!cp) {
    log_fn(LOG_INFO,"Cached directory %s not present. Ok.",keydir);
  } else {
    if(dirserv_init_from_directory_string(cp) < 0) {
      log_fn(LOG_ERR, "Cached directory %s is corrupt", keydir);
      free(cp);
      return -1;
    }
    free(cp);
  }
  /* success */
  return 0;
}

/*
 * Clique maintenance
 */

/** OR only: try to open connections to all of the other ORs we know about.
 */
void router_retry_connections(void) {
  int i;
  routerinfo_t *router;
  routerlist_t *rl;

  router_get_routerlist(&rl);
  for (i=0;i < smartlist_len(rl->routers);i++) {
    router = smartlist_get(rl->routers, i);
    if(router_is_me(router))
      continue;
    if(!connection_exact_get_by_addr_port(router->addr,router->or_port)) {
      /* not in the list */
      log_fn(LOG_DEBUG,"connecting to OR %s:%u.",router->address,router->or_port);
      connection_or_connect(router);
    }
  }
}

/*
 * OR descriptor generation.
 */

/** My routerinfo. */
static routerinfo_t *desc_routerinfo = NULL;
/** String representation of my descriptor, signed by me. */
static char descriptor[8192];

/** OR only: try to upload our signed descriptor to all the directory servers
 * we know about.
 */
void router_upload_dir_desc_to_dirservers(void) {
  const char *s;

  s = router_get_my_descriptor();
  if (!s) {
    log_fn(LOG_WARN, "No descriptor; skipping upload");
    return;
  }
  directory_post_to_dirservers(DIR_PURPOSE_UPLOAD_DIR, s, strlen(s));
}

#define DEFAULT_EXIT_POLICY "reject 0.0.0.0/8,reject 169.254.0.0/16,reject 127.0.0.0/8,reject 192.168.0.0/16,reject 10.0.0.0/8,reject 172.16.0.0/12,accept *:20-22,accept *:53,accept *:79-81,accept *:110,accept *:143,accept *:443,accept *:873,accept *:993,accept *:995,accept *:1024-65535,reject *:*"

/** Set the exit policy on <b>router</b> to match the exit policy in the
 * current configuration file.  If the exit policy doesn't have a catch-all
 * rule, then append the default exit policy as well.
 */
static void router_add_exit_policy_from_config(routerinfo_t *router) {
  struct exit_policy_t *ep;
  struct config_line_t default_policy;
  config_parse_exit_policy(options.ExitPolicy, &router->exit_policy);

  for (ep = router->exit_policy; ep; ep = ep->next) {
    if (ep->msk == 0 && ep->prt_min <= 1 && ep->prt_max >= 65535) {
      /* if exitpolicy includes a *:* line, then we're done. */
      return;
    }
  }

  /* Else, append the default exitpolicy. */
  default_policy.key = NULL;
  default_policy.value = DEFAULT_EXIT_POLICY;
  default_policy.next = NULL;
  config_parse_exit_policy(&default_policy, &router->exit_policy);
}

/** OR only: Return false if my exit policy says to allow connection to
 * conn.  Else return true.
 */
int router_compare_to_my_exit_policy(connection_t *conn)
{
  tor_assert(desc_routerinfo);
  tor_assert(conn->addr); /* make sure it's resolved to something. this
                             way we can't get a 'maybe' below. */

  return router_compare_addr_to_exit_policy(conn->addr, conn->port,
                   desc_routerinfo->exit_policy);

}

/** Return true iff <b>router</b> has the same nickname as this OR.  (For an
 * OP, always returns false.)
 */
int router_is_me(routerinfo_t *router)
{
  tor_assert(router);
  return options.Nickname && !strcasecmp(router->nickname, options.Nickname);
}

/** Return a routerinfo for this OR, rebuilding a fresh one if
 * necessary.  Return NULL on error, or if called on an OP. */
routerinfo_t *router_get_my_routerinfo(void)
{
  if (!options.ORPort)
    return NULL;

  if (!desc_routerinfo) {
    if (router_rebuild_descriptor())
      return NULL;
  }
  return desc_routerinfo;
}

/** OR only: Return a signed server descriptor for this OR, rebuilding a fresh
 * one if necessary.  Return NULL on error.
 */
const char *router_get_my_descriptor(void) {
  if (!desc_routerinfo) {
    if (router_rebuild_descriptor())
      return NULL;
  }
  log_fn(LOG_DEBUG,"my desc is '%s'",descriptor);
  return descriptor;
}

/** Rebuild a fresh routerinfo and signed server descriptor for this
 * OR.  Return 0 on success, -1 on error.
 */
int router_rebuild_descriptor(void) {
  routerinfo_t *ri;
  struct in_addr addr;
  char platform[256];
  if (!tor_inet_aton(options.Address, &addr)) {
    log_fn(LOG_ERR, "options.Address didn't hold an IP.");
    return -1;
  }

  ri = tor_malloc_zero(sizeof(routerinfo_t));
  ri->address = tor_strdup(options.Address);
  ri->nickname = tor_strdup(options.Nickname);
  ri->addr = (uint32_t) ntohl(addr.s_addr);
  ri->or_port = options.ORPort;
  ri->socks_port = options.SocksPort;
  ri->dir_port = options.DirPort;
  ri->published_on = time(NULL);
  ri->onion_pkey = crypto_pk_dup_key(get_onion_key()); /* must invoke from main thread */
  ri->identity_pkey = crypto_pk_dup_key(get_identity_key());
  get_platform_str(platform, sizeof(platform));
  ri->platform = tor_strdup(platform);
  ri->bandwidthrate = options.BandwidthRate;
  ri->bandwidthburst = options.BandwidthBurst;
  ri->exit_policy = NULL; /* zero it out first */
  router_add_exit_policy_from_config(ri);
  if (desc_routerinfo)
    routerinfo_free(desc_routerinfo);
  desc_routerinfo = ri;
  if (router_dump_router_to_string(descriptor, 8192, ri, get_identity_key())<0) {
    log_fn(LOG_WARN, "Couldn't dump router to string.");
    return -1;
  }
  if (ri->dir_port)
    ri->is_trusted_dir = 1;
  return 0;
}

/** Set <b>platform</b> (max length <b>len</b>) to a NUL-terminated short
 * string describing the version of Tor and the operating system we're
 * currently running on.
 */
void get_platform_str(char *platform, int len)
{
  snprintf(platform, len-1, "Tor %s on %s", VERSION, get_uname());
  platform[len-1] = '\0';
  return;
}

/* XXX need to audit this thing and count fenceposts. maybe
 *     refactor so we don't have to keep asking if we're
 *     near the end of maxlen?
 */
#define DEBUG_ROUTER_DUMP_ROUTER_TO_STRING

/** OR only: Given a routerinfo for this router, and an identity key to sign
 * with, encode the routerinfo as a signed server descriptor and write the
 * result into <b>s</b>, using at most <b>maxlen</b> bytes.  Return -1 on
 * failure, and the number of bytes used on success.
 */
int router_dump_router_to_string(char *s, int maxlen, routerinfo_t *router,
                                 crypto_pk_env_t *ident_key) {
  char *onion_pkey; /* Onion key, PEM-encoded. */
  char *identity_pkey; /* Identity key, PEM-encoded. */
  char digest[20];
  char signature[128];
  char published[32];
  struct in_addr in;
  int onion_pkeylen, identity_pkeylen;
  int written;
  int result=0;
  struct exit_policy_t *tmpe;
#ifdef DEBUG_ROUTER_DUMP_ROUTER_TO_STRING
  char *s_tmp, *s_dup;
  const char *cp;
  routerinfo_t *ri_tmp;
#endif

  /* Make sure the identity key matches the one in the routerinfo. */
  if (crypto_pk_cmp_keys(ident_key, router->identity_pkey)) {
    log_fn(LOG_WARN,"Tried to sign a router with a private key that didn't match router's public key!");
    return -1;
  }

  /* PEM-encode the onion key */
  if(crypto_pk_write_public_key_to_string(router->onion_pkey,
                                          &onion_pkey,&onion_pkeylen)<0) {
    log_fn(LOG_WARN,"write onion_pkey to string failed!");
    return -1;
  }

  /* PEM-encode the identity key key */
  if(crypto_pk_write_public_key_to_string(router->identity_pkey,
                                          &identity_pkey,&identity_pkeylen)<0) {
    log_fn(LOG_WARN,"write identity_pkey to string failed!");
    tor_free(onion_pkey);
    return -1;
  }

  /* Encode the publication time. */
  strftime(published, 32, "%Y-%m-%d %H:%M:%S", gmtime(&router->published_on));

  /* Generate the easy portion of the router descriptor. */
  result = snprintf(s, maxlen,
                    "router %s %s %d %d %d\n"
                    "platform %s\n"
                    "published %s\n"
                    "bandwidth %d %d\n"
                    "onion-key\n%s"
                    "signing-key\n%s",
    router->nickname,
    router->address,
    router->or_port,
    router->socks_port,
    router->dir_port,
    router->platform,
    published,
    (int) router->bandwidthrate,
    (int) router->bandwidthburst,
    onion_pkey, identity_pkey);

  tor_free(onion_pkey);
  tor_free(identity_pkey);

  if(result < 0 || result >= maxlen) {
    /* apparently different glibcs do different things on snprintf error.. so check both */
    return -1;
  }
  /* From now on, we use 'written' to remember the current length of 's'. */
  written = result;

  /* Write the exit policy to the end of 's'. */
  for(tmpe=router->exit_policy; tmpe; tmpe=tmpe->next) {
    in.s_addr = htonl(tmpe->addr);
    /* Write: "accept 1.2.3.4" */
    result = snprintf(s+written, maxlen-written, "%s %s",
        tmpe->policy_type == EXIT_POLICY_ACCEPT ? "accept" : "reject",
        tmpe->msk == 0 ? "*" : inet_ntoa(in));
    if(result < 0 || result+written > maxlen) {
      /* apparently different glibcs do different things on snprintf error.. so check both */
      return -1;
    }
    written += result;
    if (tmpe->msk != 0xFFFFFFFFu && tmpe->msk != 0) {
      /* Write "/255.255.0.0" */
      in.s_addr = htonl(tmpe->msk);
      result = snprintf(s+written, maxlen-written, "/%s", inet_ntoa(in));
      if (result<0 || result+written > maxlen)
        return -1;
      written += result;
    }
    if (tmpe->prt_min == 0 && tmpe->prt_max == 65535) {
      /* There is no port set; write ":*" */
      if (written > maxlen-4)
        return -1;
      strcat(s+written, ":*\n");
      written += 3;
    } else if (tmpe->prt_min == tmpe->prt_max) {
      /* There is only one port; write ":80". */
      result = snprintf(s+written, maxlen-written, ":%d\n", tmpe->prt_min);
      if (result<0 || result+written > maxlen)
        return -1;
      written += result;
    } else {
      /* There is a range of ports; write ":79-80". */
      result = snprintf(s+written, maxlen-written, ":%d-%d\n", tmpe->prt_min,
                        tmpe->prt_max);
      if (result<0 || result+written > maxlen)
        return -1;
      written += result;
    }
  } /* end for */
  if (written > maxlen-256) /* Not enough room for signature. */
    return -1;

  /* Sign the directory */
  strcat(s+written, "router-signature\n");
  written += strlen(s+written);
  s[written] = '\0';
  if (router_get_router_hash(s, digest) < 0)
    return -1;

  if (crypto_pk_private_sign(ident_key, digest, 20, signature) < 0) {
    log_fn(LOG_WARN, "Error signing digest");
    return -1;
  }
  strcat(s+written, "-----BEGIN SIGNATURE-----\n");
  written += strlen(s+written);
  if (base64_encode(s+written, maxlen-written, signature, 128) < 0) {
    log_fn(LOG_WARN, "Couldn't base64-encode signature");
    return -1;
  }
  written += strlen(s+written);
  strcat(s+written, "-----END SIGNATURE-----\n");
  written += strlen(s+written);

  if (written > maxlen-2)
    return -1;
  /* include a last '\n' */
  s[written] = '\n';
  s[written+1] = 0;

#ifdef DEBUG_ROUTER_DUMP_ROUTER_TO_STRING
  cp = s_tmp = s_dup = tor_strdup(s);
  ri_tmp = router_parse_entry_from_string(cp, NULL);
  if (!ri_tmp) {
    log_fn(LOG_ERR, "We just generated a router descriptor we can't parse: <<%s>>",
           s);
    return -1;
  }
  free(s_dup);
  routerinfo_free(ri_tmp);
#endif

  return written+1;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
