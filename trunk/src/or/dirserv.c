/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/**
 * \file dirserv.c
 * \brief Directory server core implementation.
 **/

/** How far in the future do we allow a router to get? (seconds) */
#define ROUTER_ALLOW_SKEW (30*60)

extern or_options_t options; /**< command-line and config-file options */

/** Do we need to regenerate the directory when someone asks for it? */
static int the_directory_is_dirty = 1;
static int runningrouters_is_dirty = 1;

static int list_running_servers(char **nicknames_out);
static void directory_remove_unrecognized(void);

/************** Fingerprint handling code ************/

typedef struct fingerprint_entry_t {
  char *nickname;
  char *fingerprint;
} fingerprint_entry_t;

/** List of nickname-\>identity fingerprint mappings for all the routers
 * that we recognize. Used to prevent Sybil attacks. */
static smartlist_t *fingerprint_list = NULL;

/** Add the fingerprint <b>fp</b> for the nickname <b>nickname</b> to
 * the global list of recognized identity key fingerprints.
 */
void /* Should be static; exposed for testing */
add_fingerprint_to_dir(const char *nickname, const char *fp)
{
  int i;
  fingerprint_entry_t *ent;
  if (!fingerprint_list)
    fingerprint_list = smartlist_create();

  for (i = 0; i < smartlist_len(fingerprint_list); ++i) {
    ent = smartlist_get(fingerprint_list, i);
    if (!strcasecmp(ent->nickname,nickname)) {
      tor_free(ent->fingerprint);
      ent->fingerprint = tor_strdup(fp);
      return;
    }
  }
  ent = tor_malloc(sizeof(fingerprint_entry_t));
  ent->nickname = tor_strdup(nickname);
  ent->fingerprint = tor_strdup(fp);
  smartlist_add(fingerprint_list, ent);
}

/** Add the nickname and fingerprint for this OR to the recognized list.
 */
int
dirserv_add_own_fingerprint(const char *nickname, crypto_pk_env_t *pk)
{
  char fp[FINGERPRINT_LEN+1];
  if (crypto_pk_get_fingerprint(pk, fp)<0) {
    log_fn(LOG_ERR, "Error computing fingerprint");
    return -1;
  }
  add_fingerprint_to_dir(nickname, fp);
  return 0;
}

/** Parse the nickname-\>fingerprint mappings stored in the file named
 * <b>fname</b>.  The file format is line-based, with each non-blank
 * holding one nickname, some space, and a fingerprint for that
 * nickname.  On success, replace the current fingerprint list with
 * the contents of <b>fname</b> and return 0.  On failure, leave the
 * current fingerprint list untouched, and return -1. */
int
dirserv_parse_fingerprint_file(const char *fname)
{
  FILE *file;
  char line[FINGERPRINT_LEN+MAX_NICKNAME_LEN+20+1];
  char *nickname, *fingerprint;
  smartlist_t *fingerprint_list_new;
  int i, result;
  fingerprint_entry_t *ent;

  if(!(file = fopen(fname, "r"))) {
    log_fn(LOG_WARN, "Cannot open fingerprint file %s", fname);
    return -1;
  }
  fingerprint_list_new = smartlist_create();
  while( (result=parse_line_from_file(line, sizeof(line),file,&nickname,&fingerprint)) > 0) {
    if (strlen(nickname) > MAX_NICKNAME_LEN) {
      log(LOG_WARN, "Nickname %s too long in fingerprint file. Skipping.", nickname);
      continue;
    }
    if(strlen(fingerprint) != FINGERPRINT_LEN ||
       !crypto_pk_check_fingerprint_syntax(fingerprint)) {
      log_fn(LOG_WARN, "Invalid fingerprint (nickname %s, fingerprint %s). Skipping.",
             nickname, fingerprint);
      continue;
    }
    for (i = 0; i < smartlist_len(fingerprint_list_new); ++i) {
      ent = smartlist_get(fingerprint_list_new, i);
      if (0==strcasecmp(ent->nickname, nickname)) {
        log(LOG_WARN, "Duplicate nickname %s. Skipping.",nickname);
        break; /* out of the for. the 'if' below means skip to the next line. */
      }
    }
    if(i == smartlist_len(fingerprint_list_new)) { /* not a duplicate */
      ent = tor_malloc(sizeof(fingerprint_entry_t));
      ent->nickname = tor_strdup(nickname);
      ent->fingerprint = tor_strdup(fingerprint);
      smartlist_add(fingerprint_list_new, ent);
    }
  }
  fclose(file);
  if(result == 0) { /* eof; replace the global fingerprints list. */
    dirserv_free_fingerprint_list();
    fingerprint_list = fingerprint_list_new;
    /* Delete any routers whose fingerprints we no longer recognize */
    directory_remove_unrecognized();
    return 0;
  }
  /* error */
  log_fn(LOG_WARN, "Error reading from fingerprint file");
  for (i = 0; i < smartlist_len(fingerprint_list_new); ++i) {
    ent = smartlist_get(fingerprint_list_new, i);
    tor_free(ent->nickname);
    tor_free(ent->fingerprint);
    tor_free(ent);
  }
  smartlist_free(fingerprint_list_new);
  return -1;
}

/** Check whether <b>router</b> has a nickname/identity key combination that
 * we recognize from the fingerprint list.  Return 1 if router's
 * identity and nickname match, -1 if we recognize the nickname but
 * the identity key is wrong, and 0 if the nickname is not known. */
int
dirserv_router_fingerprint_is_known(const routerinfo_t *router)
{
  int i, found=0;
  fingerprint_entry_t *ent =NULL;
  char fp[FINGERPRINT_LEN+1];

  if (!fingerprint_list)
    fingerprint_list = smartlist_create();

  log_fn(LOG_DEBUG, "%d fingerprints known.", smartlist_len(fingerprint_list));
  for (i=0;i<smartlist_len(fingerprint_list);++i) {
    ent = smartlist_get(fingerprint_list, i);
    log_fn(LOG_DEBUG,"%s vs %s", router->nickname, ent->nickname);
    if (!strcasecmp(router->nickname,ent->nickname)) {
      found = 1;
      break;
    }
  }

  if (!found) { /* No such server known */
    log_fn(LOG_INFO,"no fingerprint found for %s",router->nickname);
    return 0;
  }
  if (crypto_pk_get_fingerprint(router->identity_pkey, fp)) {
    log_fn(LOG_WARN,"error computing fingerprint");
    return -1;
  }
  if (0==strcasecmp(ent->fingerprint, fp)) {
    log_fn(LOG_DEBUG,"good fingerprint for %s",router->nickname);
    return 1; /* Right fingerprint. */
  } else {
    log_fn(LOG_WARN,"mismatched fingerprint for %s",router->nickname);
    return -1; /* Wrong fingerprint. */
  }
}

/** Return true iff any router named <b>nickname</b> is in the fingerprint
 * list. */
static int
router_nickname_is_approved(const char *nickname, const char *digest)
{
  int i,j;
  fingerprint_entry_t *ent;
  char fp[FINGERPRINT_LEN+1];
  if (!fingerprint_list)
    return 0;

  for (i=j=0;i<DIGEST_LEN;++i,++j) {
    fp[i]=digest[j];
    if ((j%4)==3 && j != 19)
      fp[++i]=' ';
  }
  fp[i]='\0';

  for (i=0;i<smartlist_len(fingerprint_list);++i) {
    ent = smartlist_get(fingerprint_list, i);
    if (!strcasecmp(nickname,ent->nickname) &&
        !strcasecmp(fp,ent->fingerprint)) {
      return 1;
    }
  }
  return 0;
}

/** Clear the current fingerprint list. */
void
dirserv_free_fingerprint_list()
{
  int i;
  fingerprint_entry_t *ent;
  if (!fingerprint_list)
    return;

  for (i = 0; i < smartlist_len(fingerprint_list); ++i) {
    ent = smartlist_get(fingerprint_list, i);
    tor_free(ent->nickname);
    tor_free(ent->fingerprint);
    tor_free(ent);
  }
  smartlist_free(fingerprint_list);
  fingerprint_list = NULL;
}

/*
 *    Descriptor list
 */

/** A directory server's view of a server descriptor.  Contains both
 * parsed and unparsed versions. */
typedef struct descriptor_entry_t {
  char *nickname;
  time_t published;
  size_t desc_len;
  char *descriptor;
  int verified;
  routerinfo_t *router;
} descriptor_entry_t;

/** List of all server descriptors that this dirserv is holding. */
static smartlist_t *descriptor_list = NULL;

/** Release the storage held by <b>desc</b> */
static void free_descriptor_entry(descriptor_entry_t *desc)
{
  tor_free(desc->descriptor);
  tor_free(desc->nickname);
  routerinfo_free(desc->router);
  free(desc);
}

/** Release all storage that the dirserv is holding for server
 * descriptors. */
void
dirserv_free_descriptors()
{
  if (!descriptor_list)
    return;
  SMARTLIST_FOREACH(descriptor_list, descriptor_entry_t *, d,
                    free_descriptor_entry(d));
  smartlist_clear(descriptor_list);
}

/** Parse the server descriptor at *desc and maybe insert it into the
 * list of service descriptors, and (if the descriptor is well-formed)
 * advance *desc immediately past the descriptor's end.
 *
 * Return 1 if descriptor is well-formed and accepted;
 * 0 if well-formed and server is unapproved;
 * -1 if not well-formed or other error.
 */
int
dirserv_add_descriptor(const char **desc)
{
  descriptor_entry_t *ent = NULL;
  routerinfo_t *ri = NULL;
  int i, r, found=-1;
  char *start, *end;
  char *desc_tmp = NULL;
  const char *cp;
  size_t desc_len;
  time_t now;

  if (!descriptor_list)
    descriptor_list = smartlist_create();

  start = strstr(*desc, "router ");
  if (!start) {
    log_fn(LOG_WARN, "no 'router' line found. This is not a descriptor.");
    return -1;
  }
  if ((end = strstr(start+6, "\nrouter "))) {
    ++end; /* Include NL. */
  } else if ((end = strstr(start+6, "\ndirectory-signature"))) {
    ++end;
  } else {
    end = start+strlen(start);
  }
  desc_len = end-start;
  cp = desc_tmp = tor_strndup(start, desc_len);

  /* Check: is the descriptor syntactically valid? */
  ri = router_parse_entry_from_string(cp, NULL);
  tor_free(desc_tmp);
  if (!ri) {
    log(LOG_WARN, "Couldn't parse descriptor");
    return -1;
  }
  /* Okay.  Now check whether the fingerprint is recognized. */
  r = dirserv_router_fingerprint_is_known(ri);
  if(r<1) {
    if(r==0) {
      char fp[FINGERPRINT_LEN+1];
      log_fn(LOG_WARN, "Unknown nickname %s (%s:%d). Not adding.",
             ri->nickname, ri->address, ri->or_port);
      if (crypto_pk_get_fingerprint(ri->identity_pkey, fp) < 0) {
        log_fn(LOG_WARN, "Error computing fingerprint for %s", ri->nickname);
      } else {
        log_fn(LOG_WARN, "Fingerprint line: %s %s", ri->nickname, fp);
      }
    } else {
      log_fn(LOG_WARN, "Known nickname %s, wrong fingerprint. Not adding.", ri->nickname);
    }
    routerinfo_free(ri);
    *desc = end;
    return 0;
  }
  /* Is there too much clock skew? */
  now = time(NULL);
  if (ri->published_on > now+ROUTER_ALLOW_SKEW) {
    log_fn(LOG_WARN, "Publication time for nickname %s is too far in the future; possible clock skew. Not adding.", ri->nickname);
    routerinfo_free(ri);
    *desc = end;
    return 0;
  }
  if (ri->published_on < now-ROUTER_MAX_AGE) {
    log_fn(LOG_WARN, "Publication time for router with nickname %s is too far in the past. Not adding.", ri->nickname);
    routerinfo_free(ri);
    *desc = end;
    return 0;
  }

  /* Do we already have an entry for this router? */
  for (i = 0; i < smartlist_len(descriptor_list); ++i) {
    ent = smartlist_get(descriptor_list, i);
    if (!strcasecmp(ri->nickname, ent->nickname)) {
      found = i;
      break;
    }
  }
  if (found >= 0) {
    /* if so, decide whether to update it. */
    if (ent->published > ri->published_on) {
      /* We already have a newer descriptor */
      log_fn(LOG_INFO,"We already have a newer desc for nickname %s. Not adding.",ri->nickname);
      /* This isn't really an error; return success. */
      routerinfo_free(ri);
      *desc = end;
      return 1;
    }
    /* We don't have a newer one; we'll update this one. */
    log_fn(LOG_INFO,"Dirserv updating desc for nickname %s",ri->nickname);
    free_descriptor_entry(ent);
    smartlist_del_keeporder(descriptor_list, found);
  } else {
    /* Add at the end. */
    log_fn(LOG_INFO,"Dirserv adding desc for nickname %s",ri->nickname);
  }

  ent = tor_malloc(sizeof(descriptor_entry_t));
  ent->nickname = tor_strdup(ri->nickname);
  ent->published = ri->published_on;
  ent->desc_len = desc_len;
  ent->descriptor = tor_malloc(desc_len+1);
  strncpy(ent->descriptor, start, desc_len);
  ent->descriptor[desc_len] = '\0';
  ent->router = ri;
  ent->verified = 1; /* XXXX008 support other possibilities. */
  smartlist_add(descriptor_list, ent);

  *desc = end;
  directory_set_dirty();

  return 1;
}

/** Remove all descriptors whose nicknames or fingerprints we don't
 * recognize.  (Descriptors that used to be good can become
 * unrecognized when we reload the fingerprint list.)
 */
static void
directory_remove_unrecognized(void)
{
  int i;
  descriptor_entry_t *ent;
  if (!descriptor_list)
    descriptor_list = smartlist_create();

  for (i = 0; i < smartlist_len(descriptor_list); ++i) {
    ent = smartlist_get(descriptor_list, i);
    if (dirserv_router_fingerprint_is_known(ent->router)<=0) {
      log(LOG_INFO, "Router %s is no longer recognized",
          ent->nickname);
      free_descriptor_entry(ent);
      smartlist_del(descriptor_list, i--);
    }
  }
}

/** Mark the directory as <b>dirty</b> -- when we're next asked for a
 * directory, we will rebuild it instead of reusing the most recently
 * generated one.
 */
void
directory_set_dirty()
{
  the_directory_is_dirty = 1;
  runningrouters_is_dirty = 1;
}

/** Load all descriptors from a directory stored in the string
 * <b>dir</b>.
 */
int
dirserv_load_from_directory_string(const char *dir)
{
  const char *cp = dir;
  while(1) {
    cp = strstr(cp, "\nrouter ");
    if (!cp) break;
    ++cp;
    if (dirserv_add_descriptor(&cp) < 0) {
      return -1;
    }
    --cp; /*Back up to newline.*/
  }
  return 0;
}

/** Set *<b>nicknames_out</b> to a comma-separated list of all the ORs that we
 * believe are currently running (because we have open connections to
 * them).  Return 0 on success; -1 on error.
 */
static int
list_running_servers(char **nicknames_out)
{
  connection_t **connection_array;
  int n_conns;
  connection_t *conn;
  char *cp;
  int i;
  int length;
  smartlist_t *nicknames_up, *nicknames_down;

  *nicknames_out = NULL;
  nicknames_up = smartlist_create();
  nicknames_down = smartlist_create();
  smartlist_add(nicknames_up, tor_strdup(options.Nickname));

  get_connection_array(&connection_array, &n_conns);
  for (i = 0; i<n_conns; ++i) {
    char *name;
    conn = connection_array[i];
    if (conn->type != CONN_TYPE_OR || !conn->nickname)
      continue; /* only list ORs. */
    if (router_nickname_is_approved(conn->nickname, conn->identity_digest)) {
      name = tor_strdup(conn->nickname);
    } else {
      name = tor_malloc(HEX_DIGEST_LEN+2);
      *name = '$';
      base16_encode(name+1, HEX_DIGEST_LEN, conn->identity_digest, DIGEST_LEN);
    }

    if(conn->state == OR_CONN_STATE_OPEN)
      smartlist_add(nicknames_up, name);
    else
      smartlist_add(nicknames_down, name);
  }
  length = smartlist_len(nicknames_up) +
           2*smartlist_len(nicknames_down) + 1;
           /* spaces + EOS + !'s + 1. */
  SMARTLIST_FOREACH(nicknames_up, char *, c, length += strlen(c));
  SMARTLIST_FOREACH(nicknames_down, char *, c, length += strlen(c));
  *nicknames_out = tor_malloc_zero(length);
  cp = *nicknames_out;
  for (i = 0; i<smartlist_len(nicknames_up); ++i) {
    if (i)
      strcat(cp, " ");
    strcat(cp, (char*)smartlist_get(nicknames_up,i)); /* can't overflow */
    while (*cp)
      ++cp;
  }
  for (i = 0; i<smartlist_len(nicknames_down); ++i) {
    strcat(cp, " !");
    strcat(cp, (char*)smartlist_get(nicknames_down,i)); /* can't overflow */
    while (*cp)
      ++cp;
  }
  SMARTLIST_FOREACH(nicknames_up, char *, victim, tor_free(victim));
  SMARTLIST_FOREACH(nicknames_down, char *, victim, tor_free(victim));
  smartlist_free(nicknames_up);
  smartlist_free(nicknames_down);
  return 0;
}

/** Remove any descriptors from the directory that are more than ROUTER_MAX_AGE
 * seconds old.
 */
void
dirserv_remove_old_servers(void)
{
  int i;
  time_t cutoff;
  descriptor_entry_t *ent;
  if (!descriptor_list)
    descriptor_list = smartlist_create();

  cutoff = time(NULL) - ROUTER_MAX_AGE;
  for (i = 0; i < smartlist_len(descriptor_list); ++i) {
    ent = smartlist_get(descriptor_list, i);
    if (ent->published < cutoff) {
      /* descriptor_list[i] is too old.  Remove it. */
      free_descriptor_entry(ent);
      smartlist_del(descriptor_list, i--);
      directory_set_dirty();
    }
  }
}

/** Dump all routers currently in the directory into the string
 * <b>s</b>, using at most <b>maxlen</b> characters, and signing the
 * directory with <b>private_key</b>.  Return 0 on success, -1 on
 * failure.
 */
int
dirserv_dump_directory_to_string(char *s, unsigned int maxlen,
                                 crypto_pk_env_t *private_key)
{
  char *cp, *eos;
  char digest[20];
  char signature[128];
  char published[33];
  time_t published_on;
  int i;
  eos = s+maxlen;

  if (!descriptor_list)
    descriptor_list = smartlist_create();

  if (list_running_servers(&cp))
    return -1;
  dirserv_remove_old_servers();
  published_on = time(NULL);
  strftime(published, 32, "%Y-%m-%d %H:%M:%S", gmtime(&published_on));
  snprintf(s, maxlen,
           "signed-directory\n"
           "published %s\n"
           "recommended-software %s\n"
           "running-routers %s\n\n",
           published, options.RecommendedVersions, cp);

  free(cp);
  i = strlen(s);
  cp = s+i;

  SMARTLIST_FOREACH(descriptor_list, descriptor_entry_t *, d,
    if (strlcat(s, d->descriptor, maxlen) >= maxlen)
      goto truncated);

  /* These multiple strlcat calls are inefficient, but dwarfed by the RSA
     signature.
  */
  if (strlcat(s, "directory-signature ", maxlen) >= maxlen)
    goto truncated;
  if (strlcat(s, options.Nickname, maxlen) >= maxlen)
    goto truncated;
  if (strlcat(s, "\n", maxlen) >= maxlen)
    goto truncated;

  if (router_get_dir_hash(s,digest)) {
    log_fn(LOG_WARN,"couldn't compute digest");
    return -1;
  }
  if (crypto_pk_private_sign(private_key, digest, 20, signature) < 0) {
    log_fn(LOG_WARN,"couldn't sign digest");
    return -1;
  }
  log(LOG_DEBUG,"generated directory digest begins with %s",hex_str(digest,4));

  if (strlcat(cp, "-----BEGIN SIGNATURE-----\n", maxlen) >= maxlen)
    goto truncated;

  i = strlen(s);
  cp = s+i;
  if (base64_encode(cp, maxlen-i, signature, 128) < 0) {
    log_fn(LOG_WARN,"couldn't base64-encode signature");
    return -1;
  }
  
  if (strlcat(s, "-----END SIGNATURE-----\n", maxlen) >= maxlen)
    goto truncated;

  return 0;
 truncated:
  log_fn(LOG_WARN,"tried to exceed string length.");
  return -1;
}

/** Most recently generated encoded signed directory. */
static char *the_directory = NULL;
static int the_directory_len = -1;
static char *cached_directory = NULL; /* used only by non-auth dirservers */
static time_t cached_directory_published = 0;
static int cached_directory_len = -1;

void dirserv_set_cached_directory(const char *directory, time_t when)
{
  time_t now;
  char filename[512];
  tor_assert(!options.AuthoritativeDir);
  now = time(NULL);
  if (when>cached_directory_published &&
      when<now+ROUTER_ALLOW_SKEW) {
    tor_free(cached_directory);
    cached_directory = tor_strdup(directory);
    cached_directory_len = strlen(cached_directory);
    cached_directory_published = when;
    sprintf(filename,"%s/cached-directory", get_data_directory(&options));
    if(write_str_to_file(filename,cached_directory) < 0) {
      log_fn(LOG_WARN, "Couldn't write cached directory to disk. Ignoring.");
    }
  }
}

/** Set *<b>directory</b> to the most recently generated encoded signed
 * directory, generating a new one as necessary. */
size_t dirserv_get_directory(const char **directory)
{
  char *new_directory;
  char filename[512];
  if (!options.AuthoritativeDir) {
    if (cached_directory) {
      *directory = cached_directory;
      return (size_t) cached_directory_len;
    } else {
      /* no directory yet retrieved */
      return 0;
    }
  }
  if (the_directory_is_dirty) {
    new_directory = tor_malloc(MAX_DIR_SIZE);
    if (dirserv_dump_directory_to_string(new_directory, MAX_DIR_SIZE,
                                         get_identity_key())) {
      log(LOG_WARN, "Error creating directory.");
      free(new_directory);
      return 0;
    }
    tor_free(the_directory);
    the_directory = new_directory;
    the_directory_len = strlen(the_directory);
    log_fn(LOG_INFO,"New directory (size %d):\n%s",the_directory_len,
           the_directory);
    the_directory_is_dirty = 0;
    /* Now read the directory we just made in order to update our own
     * router lists.  This does more signature checking than is strictly
     * necessary, but safe is better than sorry. */
    new_directory = tor_strdup(the_directory);
    /* use a new copy of the dir, since get_dir_from_string scribbles on it */
    if (router_load_routerlist_from_directory(new_directory, get_identity_key())) {
      log_fn(LOG_ERR, "We just generated a directory we can't parse. Dying.");
      exit(0);
    }
    free(new_directory);
    sprintf(filename,"%s/cached-directory", get_data_directory(&options));
    if(write_str_to_file(filename,the_directory) < 0) {
      log_fn(LOG_WARN, "Couldn't write cached directory to disk. Ignoring.");
    }
  } else {
    log(LOG_INFO,"Directory still clean, reusing.");
  }
  *directory = the_directory;
  return the_directory_len;
}

static char *runningrouters_string=NULL;
static size_t runningrouters_len=0;

/** Replace the current running-routers list with a newly generated one. */
static int generate_runningrouters(crypto_pk_env_t *private_key)
{
  char *s, *cp;
  char digest[DIGEST_LEN];
  char signature[PK_BYTES];
  int i, len;
  char published[33];
  time_t published_on;

  len = 1024+MAX_NICKNAME_LEN*smartlist_len(descriptor_list);
  s = tor_malloc_zero(len);
  if (list_running_servers(&cp))
    return -1;
  published_on = time(NULL);
  strftime(published, 32, "%Y-%m-%d %H:%M:%S", gmtime(&published_on));
  sprintf(s, "network-status\n"
             "published %s\n"
             "running-routers %s\n"
             "directory-signature %s\n"
             "-----BEGIN SIGNATURE-----\n",
             published, cp, options.Nickname);
  free(cp);
  if (router_get_runningrouters_hash(s,digest)) {
    log_fn(LOG_WARN,"couldn't compute digest");
    return -1;
  }
  if (crypto_pk_private_sign(private_key, digest, 20, signature) < 0) {
    log_fn(LOG_WARN,"couldn't sign digest");
    return -1;
  }

  i = strlen(s);
  cp = s+i;
  if (base64_encode(cp, len-i, signature, 128) < 0) {
    log_fn(LOG_WARN,"couldn't base64-encode signature");
    return -1;
  }
  if (strlcat(s, "-----END SIGNATURE-----\n", len) >= len) {
    return -1;
  }

  tor_free(runningrouters_string);
  runningrouters_string = s;
  runningrouters_len = strlen(s);
  runningrouters_is_dirty = 0;
  return 0;
}

/** Set *<b>rr</b> to the most recently generated encoded signed
 * running-routers list, generating a new one as necessary. */
size_t dirserv_get_runningrouters(const char **rr)
{
  if (runningrouters_is_dirty) {
    if(generate_runningrouters(get_identity_key())) {
      log_fn(LOG_ERR, "Couldn't generate running-routers list?");
      return -1;
    }
  }
  *rr = runningrouters_string;
  return runningrouters_len;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
