/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char router_c_id[] =
  "$Id$";

#include "or.h"

/**
 * \file router.c
 * \brief OR functionality, including key maintenance, generating
 * and uploading server descriptors, retrying OR connections.
 **/

extern long stats_n_seconds_working;

/* Exposed for test.c. */ void get_platform_str(char *platform, size_t len);

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
static char identitykey_digest[DIGEST_LEN];

/** Replace the current onion key with <b>k</b>.  Does not affect lastonionkey;
 * to update onionkey correctly, call rotate_onion_key().
 */
static void
set_onion_key(crypto_pk_env_t *k)
{
  tor_mutex_acquire(key_lock);
  onionkey = k;
  onionkey_set_at = time(NULL);
  tor_mutex_release(key_lock);
  mark_my_descriptor_dirty();
}

/** Return the current onion key.  Requires that the onion key has been
 * loaded or generated. */
crypto_pk_env_t *
get_onion_key(void)
{
  tor_assert(onionkey);
  return onionkey;
}

/** Store a copy of the current onion key into *<b>key</b>, and a copy
 * of the most recent onion key into *<b>last</b>.
 */
void
dup_onion_keys(crypto_pk_env_t **key, crypto_pk_env_t **last)
{
  tor_assert(key);
  tor_assert(last);
  tor_mutex_acquire(key_lock);
  tor_assert(onionkey);
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
time_t
get_onion_key_set_at(void)
{
  return onionkey_set_at;
}

/** Set the current identity key to k.
 */
void
set_identity_key(crypto_pk_env_t *k)
{
  if (identitykey)
    crypto_free_pk_env(identitykey);
  identitykey = k;
  crypto_pk_get_digest(identitykey, identitykey_digest);
}

/** Returns the current identity key; requires that the identity key has been
 * set.
 */
crypto_pk_env_t *
get_identity_key(void)
{
  tor_assert(identitykey);
  return identitykey;
}

/** Return true iff the identity key has been set. */
int
identity_key_is_set(void)
{
  return identitykey != NULL;
}

/** Replace the previous onion key with the current onion key, and generate
 * a new previous onion key.  Immediately after calling this function,
 * the OR should:
 *   - schedule all previous cpuworkers to shut down _after_ processing
 *     pending work.  (This will cause fresh cpuworkers to be generated.)
 *   - generate and upload a fresh routerinfo.
 */
void
rotate_onion_key(void)
{
  char fname[512];
  char fname_prev[512];
  crypto_pk_env_t *prkey;
  or_state_t *state = get_or_state();
  time_t now;
  tor_snprintf(fname,sizeof(fname),
           "%s/keys/secret_onion_key",get_options()->DataDirectory);
  tor_snprintf(fname_prev,sizeof(fname_prev),
           "%s/keys/secret_onion_key.old",get_options()->DataDirectory);
  if (!(prkey = crypto_new_pk_env())) {
    log_err(LD_GENERAL,"Error constructing rotated onion key");
    goto error;
  }
  if (crypto_pk_generate_key(prkey)) {
    log_err(LD_BUG,"Error generating onion key");
    goto error;
  }
  if (file_status(fname) == FN_FILE) {
    if (replace_file(fname, fname_prev))
      goto error;
  }
  if (crypto_pk_write_private_key_to_filename(prkey, fname)) {
    log_err(LD_FS,"Couldn't write generated onion key to \"%s\".", fname);
    goto error;
  }
  log_info(LD_GENERAL, "Rotating onion key");
  tor_mutex_acquire(key_lock);
  if (lastonionkey)
    crypto_free_pk_env(lastonionkey);
  lastonionkey = onionkey;
  onionkey = prkey;
  now = time(NULL);
  state->LastRotatedOnionKey = onionkey_set_at = now;
  tor_mutex_release(key_lock);
  mark_my_descriptor_dirty();
  or_state_mark_dirty(state, get_options()->AvoidDiskWrites ? now+3600 : 0);
  return;
 error:
  log_warn(LD_GENERAL, "Couldn't rotate onion key.");
}

/** Try to read an RSA key from <b>fname</b>.  If <b>fname</b> doesn't exist,
 * create a new RSA key and save it in <b>fname</b>.  Return the read/created
 * key, or NULL on error.
 */
crypto_pk_env_t *
init_key_from_file(const char *fname)
{
  crypto_pk_env_t *prkey = NULL;
  FILE *file = NULL;

  if (!(prkey = crypto_new_pk_env())) {
    log_err(LD_GENERAL,"Error constructing key");
    goto error;
  }

  switch (file_status(fname)) {
    case FN_DIR:
    case FN_ERROR:
      log_err(LD_FS,"Can't read key from \"%s\"", fname);
      goto error;
    case FN_NOENT:
      log_info(LD_GENERAL, "No key found in \"%s\"; generating fresh key.",
               fname);
      if (crypto_pk_generate_key(prkey)) {
        log_err(LD_GENERAL,"Error generating onion key");
        goto error;
      }
      if (crypto_pk_check_key(prkey) <= 0) {
        log_err(LD_GENERAL,"Generated key seems invalid");
        goto error;
      }
      log_info(LD_GENERAL, "Generated key seems valid");
      if (crypto_pk_write_private_key_to_filename(prkey, fname)) {
        log_err(LD_FS,"Couldn't write generated key to \"%s\".", fname);
        goto error;
      }
      return prkey;
    case FN_FILE:
      if (crypto_pk_read_private_key_from_filename(prkey, fname)) {
        log_err(LD_GENERAL,"Error loading private key.");
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
 * On OPs, this only initializes the tls context. Return 0 on success,
 * or -1 if Tor should die.
 */
int
init_keys(void)
{
  char keydir[512];
  char fingerprint[FINGERPRINT_LEN+1];
  /*nickname<space>fp\n\0 */
  char fingerprint_line[MAX_NICKNAME_LEN+FINGERPRINT_LEN+3];
  const char *mydesc, *datadir;
  crypto_pk_env_t *prkey;
  char digest[20];
  char *cp;
  or_options_t *options = get_options();
  or_state_t *state = get_or_state();

  if (!key_lock)
    key_lock = tor_mutex_new();

  /* OP's don't need persistent keys; just make up an identity and
   * initialize the TLS context. */
  if (!server_mode(options)) {
    if (!(prkey = crypto_new_pk_env()))
      return -1;
    if (crypto_pk_generate_key(prkey))
      return -1;
    set_identity_key(prkey);
    /* Create a TLS context; default the client nickname to "client". */
    if (tor_tls_context_new(get_identity_key(),
                            options->Nickname ? options->Nickname : "client",
                            MAX_SSL_KEY_LIFETIME) < 0) {
      log_err(LD_GENERAL,"Error creating TLS context for Tor client.");
      return -1;
    }
    return 0;
  }
  /* Make sure DataDirectory exists, and is private. */
  datadir = options->DataDirectory;
  if (check_private_dir(datadir, CPD_CREATE)) {
    return -1;
  }
  /* Check the key directory. */
  tor_snprintf(keydir,sizeof(keydir),"%s/keys", datadir);
  if (check_private_dir(keydir, CPD_CREATE)) {
    return -1;
  }

  /* 1. Read identity key. Make it if none is found. */
  tor_snprintf(keydir,sizeof(keydir),"%s/keys/secret_id_key",datadir);
  log_info(LD_GENERAL,"Reading/making identity key \"%s\"...",keydir);
  prkey = init_key_from_file(keydir);
  if (!prkey) return -1;
  set_identity_key(prkey);
  /* 2. Read onion key.  Make it if none is found. */
  tor_snprintf(keydir,sizeof(keydir),"%s/keys/secret_onion_key",datadir);
  log_info(LD_GENERAL,"Reading/making onion key \"%s\"...",keydir);
  prkey = init_key_from_file(keydir);
  if (!prkey) return -1;
  set_onion_key(prkey);
  if (state->LastRotatedOnionKey > 100) { /* allow for some parsing slop. */
    onionkey_set_at = state->LastRotatedOnionKey;
  } else {
    /* We have no LastRotatedOnionKey set; either we just created the key
     * or it's a holdover from 0.1.2.4-alpha-dev or earlier.  In either case,
     * start the clock ticking now so that we will eventually rotate it even
     * if we don't stay up for a full MIN_ONION_KEY_LIFETIME. */
    state->LastRotatedOnionKey = time(NULL);
    or_state_mark_dirty(state, options->AvoidDiskWrites ? time(NULL)+3600 : 0);
  }

  tor_snprintf(keydir,sizeof(keydir),"%s/keys/secret_onion_key.old",datadir);
  if (file_status(keydir) == FN_FILE) {
    prkey = init_key_from_file(keydir);
    if (prkey)
      lastonionkey = prkey;
  }

  /* 3. Initialize link key and TLS context. */
  if (tor_tls_context_new(get_identity_key(), options->Nickname,
                          MAX_SSL_KEY_LIFETIME) < 0) {
    log_err(LD_GENERAL,"Error initializing TLS context");
    return -1;
  }
  /* 4. Build our router descriptor. */
  /* Must be called after keys are initialized. */
  mydesc = router_get_my_descriptor();
  if (authdir_mode(options)) {
    const char *m;
    /* We need to add our own fingerprint so it gets recognized. */
    if (dirserv_add_own_fingerprint(options->Nickname, get_identity_key())) {
      log_err(LD_GENERAL,"Error adding own fingerprint to approved set");
      return -1;
    }
    if (!mydesc) {
      log_err(LD_GENERAL,"Error initializing descriptor.");
      return -1;
    }
    if (dirserv_add_descriptor(mydesc, &m) < 0) {
      log_err(LD_GENERAL,"Unable to add own descriptor to directory: %s",
              m?m:"<unknown error>");
      return -1;
    }
  }

  /* 5. Dump fingerprint to 'fingerprint' */
  tor_snprintf(keydir,sizeof(keydir),"%s/fingerprint", datadir);
  log_info(LD_GENERAL,"Dumping fingerprint to \"%s\"...",keydir);
  if (crypto_pk_get_fingerprint(get_identity_key(), fingerprint, 1)<0) {
    log_err(LD_GENERAL,"Error computing fingerprint");
    return -1;
  }
  tor_assert(strlen(options->Nickname) <= MAX_NICKNAME_LEN);
  if (tor_snprintf(fingerprint_line, sizeof(fingerprint_line),
                   "%s %s\n",options->Nickname, fingerprint) < 0) {
    log_err(LD_GENERAL,"Error writing fingerprint line");
    return -1;
  }
  /* Check whether we need to write the fingerprint file. */
  cp = NULL;
  if (file_status(keydir) == FN_FILE)
    cp = read_file_to_str(keydir, 0, NULL);
  if (!cp || strcmp(cp, fingerprint_line)) {
    if (write_str_to_file(keydir, fingerprint_line, 0)) {
      log_err(LD_FS, "Error writing fingerprint line to file");
      return -1;
    }
  }
  tor_free(cp);

  log(LOG_NOTICE, LD_GENERAL,
      "Your Tor server's identity key fingerprint is '%s %s'",
      options->Nickname, fingerprint);
  if (!authdir_mode(options))
    return 0;
  /* 6. [authdirserver only] load approved-routers file */
  if (dirserv_load_fingerprint_file() < 0) {
    log_err(LD_GENERAL,"Error loading fingerprints");
    return -1;
  }
  /* 6b. [authdirserver only] add own key to approved directories. */
  crypto_pk_get_digest(get_identity_key(), digest);
  if (!router_digest_is_trusted_dir(digest)) {
    add_trusted_dir_server(options->Nickname, NULL,
                           (uint16_t)options->DirPort,
                           (uint16_t)options->ORPort,
                           digest,
                           options->V1AuthoritativeDir, /* v1 authority */
                           1, /* v2 authority */
                           options->HSAuthoritativeDir /*hidserv authority*/);
  }
  return 0; /* success */
}

/* Keep track of whether we should upload our server descriptor,
 * and what type of server we are.
 */

/** Whether we can reach our ORPort from the outside. */
static int can_reach_or_port = 0;
/** Whether we can reach our DirPort from the outside. */
static int can_reach_dir_port = 0;

/** DOCDOC */
void
router_reset_reachability(void)
{
  can_reach_or_port = can_reach_dir_port = 0;
}

/** Return 1 if ORPort is known reachable; else return 0. */
int
check_whether_orport_reachable(void)
{
  or_options_t *options = get_options();
  return options->AssumeReachable ||
         can_reach_or_port;
}

/** Return 1 if we don't have a dirport configured, or if it's reachable. */
int
check_whether_dirport_reachable(void)
{
  or_options_t *options = get_options();
  return !options->DirPort ||
         options->AssumeReachable ||
         we_are_hibernating() ||
         can_reach_dir_port;
}

/** Look at a variety of factors, and return 0 if we don't want to
 * advertise the fact that we have a DirPort open. Else return the
 * DirPort we want to advertise. */
static int
decide_to_advertise_dirport(or_options_t *options, routerinfo_t *router)
{
  if (!router->dir_port) /* short circuit the rest of the function */
    return 0;
  if (authdir_mode(options)) /* always publish */
    return router->dir_port;
  if (we_are_hibernating())
    return 0;
  if (!check_whether_dirport_reachable())
    return 0;
  /* check if we might potentially hibernate. */
  if (accounting_is_enabled(options))
    return 0;
  /* also check if we're advertising a small amount */
  if (router->bandwidthrate <= 51200)
    return 0;

  /* Sounds like a great idea. Let's publish it. */
  return router->dir_port;
}

/** Some time has passed, or we just got new directory information.
 * See if we currently believe our ORPort or DirPort to be
 * unreachable. If so, launch a new test for it.
 *
 * For ORPort, we simply try making a circuit that ends at ourselves.
 * Success is noticed in onionskin_answer().
 *
 * For DirPort, we make a connection via Tor to our DirPort and ask
 * for our own server descriptor.
 * Success is noticed in connection_dir_client_reached_eof().
 */
void
consider_testing_reachability(int test_or, int test_dir)
{
  routerinfo_t *me = router_get_my_routerinfo();
  int orport_reachable = check_whether_orport_reachable();
  if (!me)
    return;

  if (test_or && (!orport_reachable || !circuit_enough_testing_circs())) {
    log_info(LD_CIRC, "Testing %s of my ORPort: %s:%d.",
             !orport_reachable ? "reachability" : "bandwidth",
             me->address, me->or_port);
    circuit_launch_by_router(CIRCUIT_PURPOSE_TESTING, 0, me, 0, 1, 1);
    control_event_server_status(LOG_NOTICE,
                                "CHECKING_REACHABILITY ORADDRESS=%s:%d",
                                me->address, me->or_port);
  }

  if (test_dir && !check_whether_dirport_reachable() &&
      !connection_get_by_type_addr_port_purpose(
                CONN_TYPE_DIR, me->addr, me->dir_port,
                DIR_PURPOSE_FETCH_SERVERDESC)) {
    /* ask myself, via tor, for my server descriptor. */
    directory_initiate_command_router(me, DIR_PURPOSE_FETCH_SERVERDESC,
                                      1, "authority", NULL, 0);
    control_event_server_status(LOG_NOTICE,
                                "CHECKING_REACHABILITY DIRADDRESS=%s:%d",
                                me->address, me->dir_port);
  }
}

/** Annotate that we found our ORPort reachable. */
void
router_orport_found_reachable(void)
{
  if (!can_reach_or_port) {
    routerinfo_t *me = router_get_my_routerinfo();
    log_notice(LD_OR,"Self-testing indicates your ORPort is reachable from "
               "the outside. Excellent.%s",
               get_options()->PublishServerDescriptor ?
                 " Publishing server descriptor." : "");
    can_reach_or_port = 1;
    mark_my_descriptor_dirty();
    if (!me)
      return;
    control_event_server_status(LOG_NOTICE,
                                "REACHABILITY_SUCCEEDED ORADDRESS=%s:%d",
                                me->address, me->dir_port);
  }
}

/** Annotate that we found our DirPort reachable. */
void
router_dirport_found_reachable(void)
{
  if (!can_reach_dir_port) {
    routerinfo_t *me = router_get_my_routerinfo();
    log_notice(LD_DIRSERV,"Self-testing indicates your DirPort is reachable "
               "from the outside. Excellent.");
    can_reach_dir_port = 1;
    mark_my_descriptor_dirty();
    if (!me)
      return;
    control_event_server_status(LOG_NOTICE,
                                "REACHABILITY_SUCCEEDED DIRADDRESS=%s:%d",
                                me->address, me->dir_port);
  }
}

/** We have enough testing circuits open. Send a bunch of "drop"
 * cells down each of them, to exercise our bandwidth. */
void
router_perform_bandwidth_test(int num_circs, time_t now)
{
  int num_cells = (int)(get_options()->BandwidthRate * 10 / CELL_NETWORK_SIZE);
  int max_cells = num_cells < CIRCWINDOW_START ?
                    num_cells : CIRCWINDOW_START;
  int cells_per_circuit = max_cells / num_circs;
  origin_circuit_t *circ = NULL;

  log_notice(LD_OR,"Performing bandwidth self-test.");
  while ((circ = circuit_get_next_by_pk_and_purpose(circ, NULL,
                                              CIRCUIT_PURPOSE_TESTING))) {
    /* dump cells_per_circuit drop cells onto this circ */
    int i = cells_per_circuit;
    if (circ->_base.state != CIRCUIT_STATE_OPEN)
      continue;
    circ->_base.timestamp_dirty = now;
    while (i-- > 0) {
      if (connection_edge_send_command(NULL, TO_CIRCUIT(circ),
                                       RELAY_COMMAND_DROP,
                                       NULL, 0, circ->cpath->prev)<0) {
        return; /* stop if error */
      }
    }
  }
}

/** Return true iff we believe ourselves to be an authoritative
 * directory server.
 */
int
authdir_mode(or_options_t *options)
{
  return options->AuthoritativeDir != 0;
}
/** Return true iff we try to stay connected to all ORs at once.
 */
int
clique_mode(or_options_t *options)
{
  return authdir_mode(options);
}

/** Return true iff we are trying to be a server.
 */
int
server_mode(or_options_t *options)
{
  if (options->ClientOnly) return 0;
  return (options->ORPort != 0 || options->ORListenAddress);
}

/** Remember if we've advertised ourselves to the dirservers. */
static int server_is_advertised=0;

/** Return true iff we have published our descriptor lately.
 */
int
advertised_server_mode(void)
{
  return server_is_advertised;
}

/**
 * Called with a boolean: set whether we have recently published our
 * descriptor.
 */
static void
set_server_advertised(int s)
{
  server_is_advertised = s;
}

/** Return true iff we are trying to be a socks proxy. */
int
proxy_mode(or_options_t *options)
{
  return (options->SocksPort != 0 || options->SocksListenAddress);
}

/** Decide if we're a publishable server. We are a publishable server if:
 * - We don't have the ClientOnly option set
 * and
 * - We have the PublishServerDescriptor option set
 * and
 * - We have ORPort set
 * and
 * - We believe we are reachable from the outside; or
 * - We have the AuthoritativeDirectory option set.
 */
static int
decide_if_publishable_server(void)
{
  or_options_t *options = get_options();

  if (options->ClientOnly)
    return 0;
  if (!options->PublishServerDescriptor)
    return 0;
  if (!server_mode(options))
    return 0;
  if (options->AuthoritativeDir)
    return 1;

  return check_whether_orport_reachable();
}

/** Initiate server descriptor upload as reasonable (if server is publishable,
 * etc).  <b>force</b> is as for router_upload_dir_desc_to_dirservers.
 *
 * We need to rebuild the descriptor if it's dirty even if we're not
 * uploading, because our reachability testing *uses* our descriptor to
 * determine what IP address and ports to test.
 */
void
consider_publishable_server(int force)
{
  int rebuilt;

  if (!server_mode(get_options()))
    return;

  rebuilt = router_rebuild_descriptor(0);
  if (decide_if_publishable_server()) {
    set_server_advertised(1);
    if (rebuilt == 0)
      router_upload_dir_desc_to_dirservers(force);
  } else {
    set_server_advertised(0);
  }
}

/*
 * Clique maintenance -- to be phased out.
 */

/** Return true iff this OR should try to keep connections open to all
 * other ORs. */
int
router_is_clique_mode(routerinfo_t *router)
{
  if (router_digest_is_trusted_dir(router->cache_info.identity_digest))
    return 1;
  return 0;
}

/*
 * OR descriptor generation.
 */

/** My routerinfo. */
static routerinfo_t *desc_routerinfo = NULL;
/** Since when has our descriptor been "clean"?  0 if we need to regenerate it
 * now. */
static time_t desc_clean_since = 0;
/** Boolean: do we need to regenerate the above? */
static int desc_needs_upload = 0;

/** OR only: If <b>force</b> is true, or we haven't uploaded this
 * descriptor successfully yet, try to upload our signed descriptor to
 * all the directory servers we know about.
 */
void
router_upload_dir_desc_to_dirservers(int force)
{
  const char *s;

  s = router_get_my_descriptor();
  if (!s) {
    log_info(LD_GENERAL, "No descriptor; skipping upload");
    return;
  }
  if (!get_options()->PublishServerDescriptor)
    return;
  if (!force && !desc_needs_upload)
    return;
  desc_needs_upload = 0;
  directory_post_to_dirservers(DIR_PURPOSE_UPLOAD_DIR, s, strlen(s));
}

/** OR only: Check whether my exit policy says to allow connection to
 * conn.  Return 0 if we accept; non-0 if we reject.
 */
int
router_compare_to_my_exit_policy(edge_connection_t *conn)
{
  tor_assert(desc_routerinfo);

  /* make sure it's resolved to something. this way we can't get a
     'maybe' below. */
  if (!conn->_base.addr)
    return -1;

  return compare_addr_to_addr_policy(conn->_base.addr, conn->_base.port,
                   desc_routerinfo->exit_policy) != ADDR_POLICY_ACCEPTED;
}

/** Return true iff I'm a server and <b>digest</b> is equal to
 * my identity digest. */
int
router_digest_is_me(const char *digest)
{
  return identitykey && !memcmp(identitykey_digest, digest, DIGEST_LEN);
}

/** A wrapper around router_digest_is_me(). */
int
router_is_me(routerinfo_t *router)
{
  return router_digest_is_me(router->cache_info.identity_digest);
}

/** Return true iff <b>fp</b> is a hex fingerprint of my identity digest. */
int
router_fingerprint_is_me(const char *fp)
{
  char digest[DIGEST_LEN];
  if (strlen(fp) == HEX_DIGEST_LEN &&
      base16_decode(digest, sizeof(digest), fp, HEX_DIGEST_LEN) == 0)
    return router_digest_is_me(digest);

  return 0;
}

/** Return a routerinfo for this OR, rebuilding a fresh one if
 * necessary.  Return NULL on error, or if called on an OP. */
routerinfo_t *
router_get_my_routerinfo(void)
{
  if (!server_mode(get_options()))
    return NULL;
  if (router_rebuild_descriptor(0))
    return NULL;
  return desc_routerinfo;
}

/** OR only: Return a signed server descriptor for this OR, rebuilding a fresh
 * one if necessary.  Return NULL on error.
 */
const char *
router_get_my_descriptor(void)
{
  const char *body;
  if (!router_get_my_routerinfo())
    return NULL;
  /* Make sure this is nul-terminated. */
  tor_assert(desc_routerinfo->cache_info.saved_location == SAVED_NOWHERE);
  body = signed_descriptor_get_body(&desc_routerinfo->cache_info);
  tor_assert(!body[desc_routerinfo->cache_info.signed_descriptor_len]);
  log_debug(LD_GENERAL,"my desc is '%s'", body);
  return body;
}

/*DOCDOC*/
static smartlist_t *warned_nonexistent_family = NULL;

static int router_guess_address_from_dir_headers(uint32_t *guess);

/** Return our current best guess at our address, either because
 * it's configured in torrc, or because we've learned it from
 * dirserver headers. */
int
router_pick_published_address(or_options_t *options, uint32_t *addr)
{
  if (resolve_my_address(LOG_INFO, options, addr, NULL) < 0) {
    log_info(LD_CONFIG, "Could not determine our address locally. "
             "Checking if directory headers provide any hints.");
    if (router_guess_address_from_dir_headers(addr) < 0) {
      log_info(LD_CONFIG, "No hints from directory headers either. "
               "Will try again later.");
      return -1;
    }
  }
  return 0;
}

/** If <b>force</b> is true, or our descriptor is out-of-date, rebuild
 * a fresh routerinfo and signed server descriptor for this OR.
 * Return 0 on success, -1 on temporary error.
 */
int
router_rebuild_descriptor(int force)
{
  routerinfo_t *ri;
  uint32_t addr;
  char platform[256];
  int hibernating = we_are_hibernating();
  or_options_t *options = get_options();

  if (desc_clean_since && !force)
    return 0;

  if (router_pick_published_address(options, &addr) < 0) {
    /* Stop trying to rebuild our descriptor every second. We'll
     * learn that it's time to try again when server_has_changed_ip()
     * marks it dirty. */
    desc_clean_since = time(NULL);
    return -1;
  }

  ri = tor_malloc_zero(sizeof(routerinfo_t));
  ri->routerlist_index = -1;
  ri->address = tor_dup_addr(addr);
  ri->nickname = tor_strdup(options->Nickname);
  ri->addr = addr;
  ri->or_port = options->ORPort;
  ri->dir_port = options->DirPort;
  ri->cache_info.published_on = time(NULL);
  ri->onion_pkey = crypto_pk_dup_key(get_onion_key()); /* must invoke from
                                                        * main thread */
  ri->identity_pkey = crypto_pk_dup_key(get_identity_key());
  if (crypto_pk_get_digest(ri->identity_pkey,
                           ri->cache_info.identity_digest)<0) {
    routerinfo_free(ri);
    return -1;
  }
  get_platform_str(platform, sizeof(platform));
  ri->platform = tor_strdup(platform);
  ri->bandwidthrate = (int)options->BandwidthRate;
  ri->bandwidthburst = (int)options->BandwidthBurst;
  ri->bandwidthcapacity = hibernating ? 0 : rep_hist_bandwidth_assess();

  if (options->BandwidthRate > options->MaxAdvertisedBandwidth)
    ri->bandwidthrate = (int)options->MaxAdvertisedBandwidth;

  policies_parse_exit_policy(options->ExitPolicy, &ri->exit_policy,
                             options->ExitPolicyRejectPrivate);

  if (desc_routerinfo) { /* inherit values */
    ri->is_valid = desc_routerinfo->is_valid;
    ri->is_running = desc_routerinfo->is_running;
    ri->is_named = desc_routerinfo->is_named;
  }
  if (authdir_mode(options))
    ri->is_valid = ri->is_named = 1; /* believe in yourself */
  if (options->MyFamily) {
    smartlist_t *family;
    if (!warned_nonexistent_family)
      warned_nonexistent_family = smartlist_create();
    family = smartlist_create();
    ri->declared_family = smartlist_create();
    smartlist_split_string(family, options->MyFamily, ",",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    SMARTLIST_FOREACH(family, char *, name,
     {
       routerinfo_t *member;
       if (!strcasecmp(name, options->Nickname))
         member = ri;
       else
         member = router_get_by_nickname(name, 1);
       if (!member) {
         if (!smartlist_string_isin(warned_nonexistent_family, name) &&
             !is_legal_hexdigest(name)) {
           log_warn(LD_CONFIG,
                    "I have no descriptor for the router named \"%s\" "
                    "in my declared family; I'll use the nickname as is, but "
                    "this may confuse clients.", name);
           smartlist_add(warned_nonexistent_family, tor_strdup(name));
         }
         smartlist_add(ri->declared_family, name);
         name = NULL;
       } else if (router_is_me(member)) {
         /* Don't list ourself in our own family; that's redundant */
       } else {
         char *fp = tor_malloc(HEX_DIGEST_LEN+2);
         fp[0] = '$';
         base16_encode(fp+1,HEX_DIGEST_LEN+1,
                       member->cache_info.identity_digest, DIGEST_LEN);
         smartlist_add(ri->declared_family, fp);
         if (smartlist_string_isin(warned_nonexistent_family, name))
           smartlist_string_remove(warned_nonexistent_family, name);
       }
       tor_free(name);
     });

    /* remove duplicates from the list */
    smartlist_sort_strings(ri->declared_family);
    smartlist_uniq_strings(ri->declared_family);

    smartlist_free(family);
  }
  ri->cache_info.signed_descriptor_body = tor_malloc(8192);
  if (router_dump_router_to_string(ri->cache_info.signed_descriptor_body, 8192,
                                   ri, get_identity_key())<0) {
    log_warn(LD_BUG, "Couldn't allocate string for descriptor.");
    return -1;
  }
  ri->cache_info.signed_descriptor_len =
    strlen(ri->cache_info.signed_descriptor_body);
  crypto_digest(ri->cache_info.signed_descriptor_digest,
                ri->cache_info.signed_descriptor_body,
                ri->cache_info.signed_descriptor_len);

  if (desc_routerinfo)
    routerinfo_free(desc_routerinfo);
  desc_routerinfo = ri;

  desc_clean_since = time(NULL);
  desc_needs_upload = 1;
  control_event_my_descriptor_changed();
  return 0;
}

/** Mark descriptor out of date if it's older than <b>when</b> */
void
mark_my_descriptor_dirty_if_older_than(time_t when)
{
  if (desc_clean_since < when)
    mark_my_descriptor_dirty();
}

/** Call when the current descriptor is out of date. */
void
mark_my_descriptor_dirty(void)
{
  desc_clean_since = 0;
}

/** How frequently will we republish our descriptor because of large (factor
 * of 2) shifts in estimated bandwidth? */
#define MAX_BANDWIDTH_CHANGE_FREQ (20*60)

/** Check whether bandwidth has changed a lot since the last time we announced
 * bandwidth. If so, mark our descriptor dirty. */
void
check_descriptor_bandwidth_changed(time_t now)
{
  static time_t last_changed = 0;
  uint64_t prev, cur;
  if (!desc_routerinfo)
    return;

  prev = desc_routerinfo->bandwidthcapacity;
  cur = we_are_hibernating() ? 0 : rep_hist_bandwidth_assess();
  if ((prev != cur && (!prev || !cur)) ||
      cur > prev*2 ||
      cur < prev/2) {
    if (last_changed+MAX_BANDWIDTH_CHANGE_FREQ < now) {
      log_info(LD_GENERAL,
               "Measured bandwidth has changed; rebuilding descriptor.");
      mark_my_descriptor_dirty();
      last_changed = now;
    }
  }
}

static void
log_addr_has_changed(int severity, uint32_t prev, uint32_t cur)
{
  char addrbuf_prev[INET_NTOA_BUF_LEN];
  char addrbuf_cur[INET_NTOA_BUF_LEN];
  struct in_addr in_prev;
  struct in_addr in_cur;

  in_prev.s_addr = htonl(prev);
  tor_inet_ntoa(&in_prev, addrbuf_prev, sizeof(addrbuf_prev));

  in_cur.s_addr = htonl(cur);
  tor_inet_ntoa(&in_cur, addrbuf_cur, sizeof(addrbuf_cur));

  if (prev)
    log_fn(severity, LD_GENERAL,
           "Our IP Address has changed from %s to %s; "
           "rebuilding descriptor.",
           addrbuf_prev, addrbuf_cur);
  else
    log_notice(LD_GENERAL,
             "Guessed our IP address as %s.",
             addrbuf_cur);
}

/** Check whether our own address as defined by the Address configuration
 * has changed. This is for routers that get their address from a service
 * like dyndns. If our address has changed, mark our descriptor dirty. */
void
check_descriptor_ipaddress_changed(time_t now)
{
  uint32_t prev, cur;
  or_options_t *options = get_options();
  (void) now;

  if (!desc_routerinfo)
    return;

  prev = desc_routerinfo->addr;
  if (resolve_my_address(LOG_INFO, options, &cur, NULL) < 0) {
    log_info(LD_CONFIG,"options->Address didn't resolve into an IP.");
    return;
  }

  if (prev != cur) {
    log_addr_has_changed(LOG_INFO, prev, cur);
    ip_address_changed(0);
  }
}

static uint32_t last_guessed_ip = 0;

/** A directory authority told us our IP address is <b>suggestion</b>.
 * If this address is different from the one we think we are now, and
 * if our computer doesn't actually know its IP address, then switch. */
void
router_new_address_suggestion(const char *suggestion)
{
  uint32_t addr, cur = 0;
  struct in_addr in;
  or_options_t *options = get_options();

  /* first, learn what the IP address actually is */
  if (!tor_inet_aton(suggestion, &in)) {
    log_debug(LD_DIR, "Malformed X-Your-Address-Is header %s. Ignoring.",
              escaped(suggestion));
    return;
  }
  addr = ntohl(in.s_addr);

  log_debug(LD_DIR, "Got X-Your-Address-Is: %s.", suggestion);

  if (!server_mode(options)) {
    last_guessed_ip = addr; /* store it in case we need it later */
    return;
  }

  if (resolve_my_address(LOG_INFO, options, &cur, NULL) >= 0) {
    /* We're all set -- we already know our address. Great. */
    last_guessed_ip = cur; /* store it in case we need it later */
    return;
  }
  if (is_internal_IP(addr, 0)) {
    /* Don't believe anybody who says our IP is, say, 127.0.0.1. */
    return;
  }

  /* Okay.  We can't resolve our own address, and X-Your-Address-Is is giving
   * us an answer different from what we had the last time we managed to
   * resolve it. */
  if (last_guessed_ip != addr) {
    control_event_server_status(LOG_NOTICE,
                                "EXTERNAL_ADDRESS ADDRESS=%s METHOD=DIRSERV",
                                suggestion);
    log_addr_has_changed(LOG_NOTICE, last_guessed_ip, addr);
    ip_address_changed(0);
    last_guessed_ip = addr; /* router_rebuild_descriptor() will fetch it */
  }
}

/** We failed to resolve our address locally, but we'd like to build
 * a descriptor and publish / test reachability. If we have a guess
 * about our address based on directory headers, answer it and return
 * 0; else return -1. */
static int
router_guess_address_from_dir_headers(uint32_t *guess)
{
  if (last_guessed_ip) {
    *guess = last_guessed_ip;
    return 0;
  }
  return -1;
}

/** Set <b>platform</b> (max length <b>len</b>) to a NUL-terminated short
 * string describing the version of Tor and the operating system we're
 * currently running on.
 */
void
get_platform_str(char *platform, size_t len)
{
  tor_snprintf(platform, len, "Tor %s on %s",
           VERSION, get_uname());
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
int
router_dump_router_to_string(char *s, size_t maxlen, routerinfo_t *router,
                             crypto_pk_env_t *ident_key)
{
  char *onion_pkey; /* Onion key, PEM-encoded. */
  char *identity_pkey; /* Identity key, PEM-encoded. */
  char digest[DIGEST_LEN];
  char published[ISO_TIME_LEN+1];
  char fingerprint[FINGERPRINT_LEN+1];
  size_t onion_pkeylen, identity_pkeylen;
  size_t written;
  int result=0;
  addr_policy_t *tmpe;
  char *bandwidth_usage;
  char *family_line;
#ifdef DEBUG_ROUTER_DUMP_ROUTER_TO_STRING
  char *s_dup;
  const char *cp;
  routerinfo_t *ri_tmp;
#endif
  or_options_t *options = get_options();

  /* Make sure the identity key matches the one in the routerinfo. */
  if (crypto_pk_cmp_keys(ident_key, router->identity_pkey)) {
    log_warn(LD_BUG,"Tried to sign a router with a private key that didn't "
             "match router's public key!");
    return -1;
  }

  /* record our fingerprint, so we can include it in the descriptor */
  if (crypto_pk_get_fingerprint(router->identity_pkey, fingerprint, 1)<0) {
    log_err(LD_BUG,"Error computing fingerprint");
    return -1;
  }

  /* PEM-encode the onion key */
  if (crypto_pk_write_public_key_to_string(router->onion_pkey,
                                           &onion_pkey,&onion_pkeylen)<0) {
    log_warn(LD_BUG,"write onion_pkey to string failed!");
    return -1;
  }

  /* PEM-encode the identity key key */
  if (crypto_pk_write_public_key_to_string(router->identity_pkey,
                                        &identity_pkey,&identity_pkeylen)<0) {
    log_warn(LD_BUG,"write identity_pkey to string failed!");
    tor_free(onion_pkey);
    return -1;
  }

  /* Encode the publication time. */
  format_iso_time(published, router->cache_info.published_on);

  /* How busy have we been? */
  bandwidth_usage = rep_hist_get_bandwidth_lines();

  if (router->declared_family && smartlist_len(router->declared_family)) {
    size_t n;
    char *s = smartlist_join_strings(router->declared_family, " ", 0, &n);
    n += strlen("family ") + 2; /* 1 for \n, 1 for \0. */
    family_line = tor_malloc(n);
    tor_snprintf(family_line, n, "family %s\n", s);
    tor_free(s);
  } else {
    family_line = tor_strdup("");
  }

  /* Generate the easy portion of the router descriptor. */
  result = tor_snprintf(s, maxlen,
                    "router %s %s %d 0 %d\n"
                    "platform %s\n"
                    "published %s\n"
                    "opt fingerprint %s\n"
                    "uptime %ld\n"
                    "bandwidth %d %d %d\n"
                    "onion-key\n%s"
                    "signing-key\n%s"
#ifndef USE_EVENTDNS
                    "opt eventdns 0\n"
#endif
                    "%s%s%s",
    router->nickname,
    router->address,
    router->or_port,
    decide_to_advertise_dirport(options, router),
    router->platform,
    published,
    fingerprint,
    stats_n_seconds_working,
    (int) router->bandwidthrate,
    (int) router->bandwidthburst,
    (int) router->bandwidthcapacity,
    onion_pkey, identity_pkey,
    family_line, bandwidth_usage,
    we_are_hibernating() ? "opt hibernating 1\n" : "");
  tor_free(family_line);
  tor_free(onion_pkey);
  tor_free(identity_pkey);
  tor_free(bandwidth_usage);

  if (result < 0)
    return -1;
  /* From now on, we use 'written' to remember the current length of 's'. */
  written = result;

  if (options->ContactInfo && strlen(options->ContactInfo)) {
    result = tor_snprintf(s+written,maxlen-written, "contact %s\n",
                          options->ContactInfo);
    if (result<0)
      return -1;
    written += result;
  }

  /* Write the exit policy to the end of 's'. */
  tmpe = router->exit_policy;
  if (dns_seems_to_be_broken()) {
    /* DNS is screwed up; don't claim to be an exit. */
    strlcat(s+written, "reject *:*\n", maxlen-written);
    written += strlen("reject *:*\n");
    tmpe = NULL;
  }
  for ( ; tmpe; tmpe=tmpe->next) {
    result = policy_write_item(s+written, maxlen-written, tmpe);
    if (result < 0)
      return -1;
    tor_assert(result == (int)strlen(s+written));
    written += result;
    if (written+2 > maxlen)
      return -1;
    s[written++] = '\n';
  }

  if (written+256 > maxlen) /* Not enough room for signature. */
    return -1;

  /* Sign the directory */
  strlcpy(s+written, "router-signature\n", maxlen-written);
  written += strlen(s+written);
  s[written] = '\0';
  if (router_get_router_hash(s, digest) < 0)
    return -1;

  note_crypto_pk_op(SIGN_RTR);
  if (router_append_dirobj_signature(s+written,maxlen-written,
                                     digest,ident_key)<0) {
    log_warn(LD_BUG, "Couldn't sign router descriptor");
    return -1;
  }
  written += strlen(s+written);

  if (written+2 > maxlen)
    return -1;
  /* include a last '\n' */
  s[written] = '\n';
  s[written+1] = 0;

#ifdef DEBUG_ROUTER_DUMP_ROUTER_TO_STRING
  cp = s_dup = tor_strdup(s);
  ri_tmp = router_parse_entry_from_string(cp, NULL, 1);
  if (!ri_tmp) {
    log_err(LD_BUG,
            "We just generated a router descriptor we can't parse: <<%s>>",
            s);
    return -1;
  }
  tor_free(s_dup);
  routerinfo_free(ri_tmp);
#endif

  return written+1;
}

/** Return true iff <b>s</b> is a legally valid server nickname. */
int
is_legal_nickname(const char *s)
{
  size_t len;
  tor_assert(s);
  len = strlen(s);
  return len > 0 && len <= MAX_NICKNAME_LEN &&
    strspn(s,LEGAL_NICKNAME_CHARACTERS) == len;
}

/** Return true iff <b>s</b> is a legally valid server nickname or
 * hex-encoded identity-key digest. */
int
is_legal_nickname_or_hexdigest(const char *s)
{
  if (*s!='$')
    return is_legal_nickname(s);
  else
    return is_legal_hexdigest(s);
}

/** Return true iff <b>s</b> is a legally valid hex-encoded identity-key
 * digest. */
int
is_legal_hexdigest(const char *s)
{
  size_t len;
  tor_assert(s);
  if (s[0] == '$') s++;
  len = strlen(s);
  if (len > HEX_DIGEST_LEN) {
    if (s[HEX_DIGEST_LEN] == '=' ||
        s[HEX_DIGEST_LEN] == '~') {
      if (!is_legal_nickname(s+HEX_DIGEST_LEN+1))
        return 0;
    } else {
      return 0;
    }
  }
  return (len >= HEX_DIGEST_LEN &&
          strspn(s,HEX_CHARACTERS)==HEX_DIGEST_LEN);
}

/** DOCDOC buf must have MAX_VERBOSE_NICKNAME_LEN+1 bytes. */
void
router_get_verbose_nickname(char *buf, routerinfo_t *router)
{
  buf[0] = '$';
  base16_encode(buf+1, HEX_DIGEST_LEN+1, router->cache_info.identity_digest,
                DIGEST_LEN);
  buf[1+HEX_DIGEST_LEN] = router->is_named ? '=' : '~';
  strlcpy(buf+1+HEX_DIGEST_LEN+1, router->nickname, MAX_NICKNAME_LEN+1);
}

/** Forget that we have issued any router-related warnings, so that we'll
 * warn again if we see the same errors. */
void
router_reset_warnings(void)
{
  if (warned_nonexistent_family) {
    SMARTLIST_FOREACH(warned_nonexistent_family, char *, cp, tor_free(cp));
    smartlist_clear(warned_nonexistent_family);
  }
}

/** Release all static resources held in router.c */
void
router_free_all(void)
{
  if (onionkey)
    crypto_free_pk_env(onionkey);
  if (lastonionkey)
    crypto_free_pk_env(lastonionkey);
  if (identitykey)
    crypto_free_pk_env(identitykey);
  if (key_lock)
    tor_mutex_free(key_lock);
  if (desc_routerinfo)
    routerinfo_free(desc_routerinfo);
  if (warned_nonexistent_family) {
    SMARTLIST_FOREACH(warned_nonexistent_family, char *, cp, tor_free(cp));
    smartlist_free(warned_nonexistent_family);
  }
}

