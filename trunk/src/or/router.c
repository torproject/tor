/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

extern or_options_t options; /* command-line and config-file options */

/************************************************************/

/* private keys */
static crypto_pk_env_t *onionkey=NULL;
static crypto_pk_env_t *linkkey=NULL;
static crypto_pk_env_t *identitykey=NULL;

void set_onion_key(crypto_pk_env_t *k) {
  onionkey = k;
}

crypto_pk_env_t *get_onion_key(void) {
  assert(onionkey);
  return onionkey;
}

void set_link_key(crypto_pk_env_t *k)
{
  linkkey = k;
}

crypto_pk_env_t *get_link_key(void)
{
  assert(linkkey);
  return linkkey;
}

void set_identity_key(crypto_pk_env_t *k) {
  identitykey = k;
}

crypto_pk_env_t *get_identity_key(void) {
  assert(identitykey);
  return identitykey;
}

/************************************************************/

static crypto_pk_env_t *init_key_from_file(const char *fname)
{
  crypto_pk_env_t *prkey = NULL;
  int fd = -1;
  FILE *file = NULL;

  if (!(prkey = crypto_new_pk_env(CRYPTO_PK_RSA))) {
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
      log(LOG_ERR, "Error generating key: %s", crypto_perror());
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
    assert(0);
  }

 error:
  if (prkey)
    crypto_free_pk_env(prkey);
  if (fd >= 0 && !file)
    close(fd);
  if (file)
    fclose(file);
  return NULL;
}

int init_keys(void) {
  char keydir[512];
  char fingerprint[FINGERPRINT_LEN+MAX_NICKNAME_LEN+3];
  char *cp;
  const char *tmp, *mydesc;
  crypto_pk_env_t *prkey;

  /* OP's don't need keys.  Just initialize the TLS context.*/
  if (!options.ORPort) {
    assert(!options.DirPort);
    if (tor_tls_context_new(NULL, 0, NULL)<0) {
      log_fn(LOG_ERR, "Error creating TLS context for OP.");
      return -1;
    }
    return 0;
  }
  assert(options.DataDirectory);
  if (strlen(options.DataDirectory) > (512-128)) {
    log_fn(LOG_ERR, "DataDirectory is too long.");
    return -1;
  }
  if (check_private_dir(options.DataDirectory, 1)) {
    return -1;
  }
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
  strcpy(cp, "/link.key");
  log_fn(LOG_INFO,"Reading/making link key %s...",keydir);
  prkey = init_key_from_file(keydir);
  if (!prkey) return -1;
  set_link_key(prkey);
  if (tor_tls_context_new(prkey, 1, options.Nickname) < 0) {
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
  if (dirserv_add_descriptor(&tmp)) {
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
  assert(strlen(options.Nickname) <= MAX_NICKNAME_LEN);
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

/************************************************************/

static routerinfo_t *desc_routerinfo = NULL; /* my descriptor */
static char descriptor[8192]; /* string representation of my descriptor */

void router_retry_connections(void) {
  int i;
  routerinfo_t *router;
  routerlist_t *rl;

  router_get_routerlist(&rl);
  for (i=0;i<rl->n_routers;i++) {
    router = rl->routers[i];
    if(!connection_exact_get_by_addr_port(router->addr,router->or_port)) {
      /* not in the list */
      log_fn(LOG_DEBUG,"connecting to OR %s:%u.",router->address,router->or_port);
      connection_or_connect(router);
    }
  }
}

void router_upload_desc_to_dirservers(void) {
  int i;
  routerinfo_t *router;
  routerlist_t *rl;

  router_get_routerlist(&rl);
  if(!rl)
    return;

  if (!router_get_my_descriptor()) {
    log_fn(LOG_WARN, "No descriptor; skipping upload");
    return;
  }

  for(i=0;i<rl->n_routers;i++) {
    router = rl->routers[i];
    if(router->dir_port > 0)
      directory_initiate_command(router, DIR_CONN_STATE_CONNECTING_UPLOAD);
  }
}

static void router_add_exit_policy_from_config(routerinfo_t *router) {
  char *s = options.ExitPolicy, *e;
  int last=0;
  char line[1024];

  if(!s) {
    log_fn(LOG_INFO,"No exit policy configured. Ok.");
    return; /* nothing to see here */
  }
  if(!*s) {
    log_fn(LOG_INFO,"Exit policy is empty. Ok.");
    return; /* nothing to see here */
  }

  for(;;) {
    e = strchr(s,',');
    if(!e) {
      last = 1;
      strncpy(line,s,1023);
    } else {
      memcpy(line,s, ((e-s)<1023)?(e-s):1023);
      line[e-s] = 0;
    }
    line[1023]=0;
    log_fn(LOG_DEBUG,"Adding new entry '%s'",line);
    if(router_add_exit_policy_from_string(router,line) < 0)
      log_fn(LOG_WARN,"Malformed exit policy %s; skipping.", line);
    if(last)
      return;
    s = e+1;
  }
}

/* Return 0 if my exit policy says to allow connection to conn.
 * Else return -1.
 */
int router_compare_to_my_exit_policy(connection_t *conn) {
  assert(desc_routerinfo);
  assert(conn->addr); /* make sure it's resolved to something. this
                         way we can't get a 'maybe' below. */

  if (router_compare_addr_to_exit_policy(conn->addr, conn->port,
                                         desc_routerinfo->exit_policy) == 0)
    return 0;
  else
    return -1;
}

const char *router_get_my_descriptor(void) {
  if (!desc_routerinfo) {
    if (router_rebuild_descriptor())
      return NULL;
  }
  log_fn(LOG_DEBUG,"my desc is '%s'",descriptor);
  return descriptor;
}

int router_rebuild_descriptor(void) {
  routerinfo_t *ri;
  char localhostname[256];
  char *address = options.Address;

  if(!address) { /* if not specified in config, we find a default */
    if(gethostname(localhostname,sizeof(localhostname)) < 0) {
      log_fn(LOG_WARN,"Error obtaining local hostname");
      return -1;
    }
    address = localhostname;
    if(!strchr(address,'.')) {
      log_fn(LOG_WARN,"fqdn '%s' has only one element. Misconfigured machine?",address);
      log_fn(LOG_WARN,"Try setting the Address line in your config file.");
      return -1;
    }
  }
  ri = tor_malloc(sizeof(routerinfo_t));
  ri->address = tor_strdup(address);
  ri->nickname = tor_strdup(options.Nickname);
  /* No need to set addr. */
  ri->or_port = options.ORPort;
  ri->socks_port = options.SocksPort;
  ri->dir_port = options.DirPort;
  ri->published_on = time(NULL);
  ri->onion_pkey = crypto_pk_dup_key(get_onion_key());
  ri->link_pkey = crypto_pk_dup_key(get_link_key());
  ri->identity_pkey = crypto_pk_dup_key(get_identity_key());
  ri->bandwidth = options.TotalBandwidth;
  ri->exit_policy = NULL; /* zero it out first */
  router_add_exit_policy_from_config(ri);
  if (desc_routerinfo)
    routerinfo_free(desc_routerinfo);
  desc_routerinfo = ri;
  if (router_dump_router_to_string(descriptor, 8192, ri, get_identity_key())<0) {
    log_fn(LOG_WARN, "Couldn't dump router to string.");
    return -1;
  }
  return 0;
}

static void get_platform_str(char *platform, int len)
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
int router_dump_router_to_string(char *s, int maxlen, routerinfo_t *router,
                                 crypto_pk_env_t *ident_key) {
  char *onion_pkey;
  char *link_pkey;
  char *identity_pkey;
  struct in_addr in;
  char platform[256];
  char digest[20];
  char signature[128];
  char published[32];
  int onion_pkeylen, link_pkeylen, identity_pkeylen;
  int written;
  int result=0;
  struct exit_policy_t *tmpe;
#ifdef DEBUG_ROUTER_DUMP_ROUTER_TO_STRING
  char *s_tmp, *s_dup;
  const char *cp;
  routerinfo_t *ri_tmp;
#endif

  get_platform_str(platform, sizeof(platform));

  if (crypto_pk_cmp_keys(ident_key, router->identity_pkey)) {
    log_fn(LOG_WARN,"Tried to sign a router with a private key that didn't match router's public key!");
    return -1;
  }

  if(crypto_pk_write_public_key_to_string(router->onion_pkey,
                                          &onion_pkey,&onion_pkeylen)<0) {
    log_fn(LOG_WARN,"write onion_pkey to string failed!");
    return -1;
  }

  if(crypto_pk_write_public_key_to_string(router->identity_pkey,
                                          &identity_pkey,&identity_pkeylen)<0) {
    log_fn(LOG_WARN,"write identity_pkey to string failed!");
    return -1;
  }

  if(crypto_pk_write_public_key_to_string(router->link_pkey,
                                          &link_pkey,&link_pkeylen)<0) {
    log_fn(LOG_WARN,"write link_pkey to string failed!");
    return -1;
  }
  strftime(published, 32, "%Y-%m-%d %H:%M:%S", gmtime(&router->published_on));

  result = snprintf(s, maxlen,
                    "router %s %s %d %d %d %d\n"
                    "platform %s\n"
                    "published %s\n"
                    "onion-key\n%s"
                    "link-key\n%s"
                    "signing-key\n%s",
    router->nickname,
    router->address,
    router->or_port,
    router->socks_port,
    router->dir_port,
    (int) router->bandwidth,
    platform,
    published,
    onion_pkey, link_pkey, identity_pkey);

  free(onion_pkey);
  free(link_pkey);
  free(identity_pkey);

  if(result < 0 || result >= maxlen) {
    /* apparently different glibcs do different things on snprintf error.. so check both */
    return -1;
  }
  written = result;

  for(tmpe=router->exit_policy; tmpe; tmpe=tmpe->next) {
    in.s_addr = htonl(tmpe->addr);
    result = snprintf(s+written, maxlen-written, "%s %s",
        tmpe->policy_type == EXIT_POLICY_ACCEPT ? "accept" : "reject",
        tmpe->msk == 0 ? "*" : inet_ntoa(in));
    if(result < 0 || result+written > maxlen) {
      /* apparently different glibcs do different things on snprintf error.. so check both */
      return -1;
    }
    written += result;
    if (tmpe->msk != 0xFFFFFFFFu && tmpe->msk != 0) {
      in.s_addr = htonl(tmpe->msk);
      result = snprintf(s+written, maxlen-written, "/%s", inet_ntoa(in));
      if (result<0 || result+written > maxlen)
        return -1;
      written += result;
    }
    if (tmpe->prt_min == 1 && tmpe->prt_max == 65535) {
      if (written > maxlen-4)
        return -1;
      strcat(s+written, ":*\n");
      written += 3;
    } else if (tmpe->prt_min == tmpe->prt_max) {
      result = snprintf(s+written, maxlen-written, ":%d\n", tmpe->prt_min);
      if (result<0 || result+written > maxlen)
        return -1;
      written += result;
    } else {
      result = snprintf(s+written, maxlen-written, ":%d-%d\n", tmpe->prt_min,
                        tmpe->prt_max);
      if (result<0 || result+written > maxlen)
        return -1;
      written += result;
    }
  } /* end for */
  if (written > maxlen-256) /* Not enough room for signature. */
    return -1;

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
  ri_tmp = router_get_entry_from_string(&cp);
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
