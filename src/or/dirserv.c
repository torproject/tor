/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/*****
 * dirserv.c: Directory server core implementation.
 *****/

/* How old do we allow a router to get before removing it? (seconds) */
#define ROUTER_MAX_AGE (60*60*24)

/* How far in the future do we allow a router to get? (seconds) */
#define ROUTER_ALLOW_SKEW (30*60)

extern or_options_t options; /* command-line and config-file options */

/* Do we need to regenerate the directory when someone asks for it? */
static int the_directory_is_dirty = 1;

static int list_running_servers(char **nicknames_out);
static void directory_remove_unrecognized(void);

/************** Fingerprint handling code ************/

typedef struct fingerprint_entry_t {
  char *nickname;
  char *fingerprint;
} fingerprint_entry_t;

/* List of nickname->identity fingerprint mappings for all the routers
 * that we recognize. Used to prevent Sybil attacks. */
static fingerprint_entry_t fingerprint_list[MAX_ROUTERS_IN_DIR];
static int n_fingerprints = 0;

/* Add the fingerprint 'fp' for the nickname 'nickname' to the global
 * list of recognized identity key fingerprints.
 */
void /* Should be static; exposed for testing */
add_fingerprint_to_dir(const char *nickname, const char *fp)
{
  int i;
  for (i = 0; i < n_fingerprints; ++i) {
    if (!strcasecmp(fingerprint_list[i].nickname,nickname)) {
      free(fingerprint_list[i].fingerprint);
      fingerprint_list[i].fingerprint = tor_strdup(fp);
      return;
    }
  }
  fingerprint_list[n_fingerprints].nickname = tor_strdup(nickname);
  fingerprint_list[n_fingerprints].fingerprint = tor_strdup(fp);
  ++n_fingerprints;
}

/* Add the nickname and fingerprint for this OR to the recognized list.
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

/* Parse the nickname->fingerprint mappings stored in the file named
 * 'fname'.  The file format is line-based, with each non-blank
 * holding one nickname, some space, and a fingerprint for that
 * nickname.  On success, replace the current fingerprint list with
 * the contents of 'fname' and return 0.  On failure, leave the
 * current fingerprint list untouched, and return -1. */
int
dirserv_parse_fingerprint_file(const char *fname)
{
  FILE *file;
  char line[FINGERPRINT_LEN+MAX_NICKNAME_LEN+20+1];
  char *nickname, *fingerprint;
  fingerprint_entry_t fingerprint_list_tmp[MAX_ROUTERS_IN_DIR];
  int n_fingerprints_tmp = 0;
  int i, result;

  if(!(file = fopen(fname, "r"))) {
    log_fn(LOG_WARN, "Cannot open fingerprint file %s", fname);
    return -1;
  }
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
    for (i = 0; i < n_fingerprints_tmp; ++i) {
      if (0==strcasecmp(fingerprint_list_tmp[i].nickname, nickname)) {
        log(LOG_WARN, "Duplicate nickname %s. Skipping.",nickname);
        break; /* out of the for. the 'if' below means skip to the next line. */
      }
    }
    if(i == n_fingerprints_tmp) { /* not a duplicate */
      fingerprint_list_tmp[n_fingerprints_tmp].nickname = tor_strdup(nickname);
      fingerprint_list_tmp[n_fingerprints_tmp].fingerprint = tor_strdup(fingerprint);
      ++n_fingerprints_tmp;
    }
  }
  fclose(file);
  if(result == 0) { /* eof; replace the global fingerprints list. */
    dirserv_free_fingerprint_list();
    memcpy(fingerprint_list, fingerprint_list_tmp,
           sizeof(fingerprint_entry_t)*n_fingerprints_tmp);
    n_fingerprints = n_fingerprints_tmp;
    /* Delete any routers whose fingerprints we no longer recognize */
    directory_remove_unrecognized();
    return 0;
  }
  /* error */
  log_fn(LOG_WARN, "Error reading from fingerprint file");
  for (i = 0; i < n_fingerprints_tmp; ++i) {
    free(fingerprint_list_tmp[i].nickname);
    free(fingerprint_list_tmp[i].fingerprint);
  }
  return -1;
}

/* Check whether 'router' has a nickname/identity key combination that
 * we recognize from the fingerprint list.  Return 1 if router's
 * identity and nickname match, -1 if we recognize the nickname but
 * the identity key is wrong, and 0 if the nickname is not known. */
int
dirserv_router_fingerprint_is_known(const routerinfo_t *router)
{
  int i;
  fingerprint_entry_t *ent =NULL;
  char fp[FINGERPRINT_LEN+1];

  log_fn(LOG_DEBUG, "%d fingerprints known.", n_fingerprints);
  for (i=0;i<n_fingerprints;++i) {
    log_fn(LOG_DEBUG,"%s vs %s", router->nickname, fingerprint_list[i].nickname);
    if (!strcasecmp(router->nickname,fingerprint_list[i].nickname)) {
      ent = &fingerprint_list[i];
      break;
    }
  }

  if (!ent) { /* No such server known */
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

/* Clear the current fingerprint list. */
void
dirserv_free_fingerprint_list()
{
  int i;
  for (i = 0; i < n_fingerprints; ++i) {
    free(fingerprint_list[i].nickname);
    free(fingerprint_list[i].fingerprint);
  }
  n_fingerprints = 0;
}

/*
 *    Descriptor list
 */

/* A directory server's view of a server descriptor.  Contains both
 * parsed and unparsed versions. */
typedef struct descriptor_entry_t {
  char *nickname;
  time_t published;
  size_t desc_len;
  char *descriptor;
  routerinfo_t *router;
} descriptor_entry_t;

/* List of all server descriptors that this dirserv is holding. */
static descriptor_entry_t *descriptor_list[MAX_ROUTERS_IN_DIR];
static int n_descriptors = 0;

/* Release the storage held by 'desc' */
static void free_descriptor_entry(descriptor_entry_t *desc)
{
  tor_free(desc->descriptor);
  tor_free(desc->nickname);
  routerinfo_free(desc->router);
  free(desc);
}

/* Release all storage that the dirserv is holding for server
 * descriptors. */
void
dirserv_free_descriptors()
{
  int i;
  for (i = 0; i < n_descriptors; ++i) {
    free_descriptor_entry(descriptor_list[i]);
  }
  n_descriptors = 0;
}

/* Parse the server descriptor at *desc and maybe insert it into the
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
  descriptor_entry_t **desc_ent_ptr;
  routerinfo_t *ri = NULL;
  int i, r;
  char *start, *end;
  char *desc_tmp = NULL;
  const char *cp;
  size_t desc_len;
  time_t now;

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
  ri = router_get_entry_from_string(cp, NULL);
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
  desc_ent_ptr = NULL;
  for (i = 0; i < n_descriptors; ++i) {
    if (!strcasecmp(ri->nickname, descriptor_list[i]->nickname)) {
      desc_ent_ptr = &descriptor_list[i];
      break;
    }
  }
  if (desc_ent_ptr) {
    /* if so, decide whether to update it. */
    if ((*desc_ent_ptr)->published > ri->published_on) {
      /* We already have a newer descriptor */
      log_fn(LOG_INFO,"We already have a newer desc for nickname %s. Not adding.",ri->nickname);
      /* This isn't really an error; return success. */
      routerinfo_free(ri);
      *desc = end;
      return 1;
    }
    /* We don't have a newer one; we'll update this one. */
    log_fn(LOG_INFO,"Dirserv updating desc for nickname %s",ri->nickname);
    free_descriptor_entry(*desc_ent_ptr);
  } else {
    /* Add this at the end. */
    log_fn(LOG_INFO,"Dirserv adding desc for nickname %s",ri->nickname);
    desc_ent_ptr = &descriptor_list[n_descriptors++];
    /* XXX check if n_descriptors is too big */
  }

  (*desc_ent_ptr) = tor_malloc(sizeof(descriptor_entry_t));
  (*desc_ent_ptr)->nickname = tor_strdup(ri->nickname);
  (*desc_ent_ptr)->published = ri->published_on;
  (*desc_ent_ptr)->desc_len = desc_len;
  (*desc_ent_ptr)->descriptor = tor_malloc(desc_len+1);
  strncpy((*desc_ent_ptr)->descriptor, start, desc_len);
  (*desc_ent_ptr)->descriptor[desc_len] = '\0';
  (*desc_ent_ptr)->router = ri;
  *desc = end;
  directory_set_dirty();

  return 1;
}

/* Remove all descriptors whose nicknames or fingerprints we don't
 * recognize.  (Descriptors that used to be good can become
 * unrecognized when we reload the fingerprint list.)
 */
static void
directory_remove_unrecognized(void)
{
  int i;
  for (i = 0; i < n_descriptors; ++i) {
    if (dirserv_router_fingerprint_is_known(descriptor_list[i]->router)<=0) {
      log(LOG_INFO, "Router %s is no longer recognized",
          descriptor_list[i]->nickname);
      free_descriptor_entry(descriptor_list[i]);
      descriptor_list[i--] = descriptor_list[--n_descriptors];
    }
  }
}

/* Mark the directory as 'dirty' -- when we're next asked for a
 * directory, we will rebuild it instead of reusing the most recently
 * generated one.
 */
void
directory_set_dirty()
{
  the_directory_is_dirty = 1;
}

/* Load all descriptors from an earlier directory stored in the string
 * 'dir'.
 */
int
dirserv_init_from_directory_string(const char *dir)
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

/* Set *nicknames_out to a comma-separated list of all the ORs that we
 * believe are currently running (because we have open connections to
 * them).  Return 0 on success; -1 on error.
 */
static int
list_running_servers(char **nicknames_out)
{
  char *nickname_lst[MAX_ROUTERS_IN_DIR];
  connection_t **connection_array;
  int n_conns;
  connection_t *conn;
  char *cp;
  int n = 0, i;
  int length;
  *nicknames_out = NULL;
  nickname_lst[n++] = options.Nickname;

  get_connection_array(&connection_array, &n_conns);
  for (i = 0; i<n_conns; ++i) {
    conn = connection_array[i];
    if (conn->type != CONN_TYPE_OR || conn->state != OR_CONN_STATE_OPEN)
      continue; /* only list successfully handshaked OR's. */
    if(!conn->nickname) /* it's an OP, don't list it */
      continue;
    /* XXX if conn->nickname not approved, continue. otherwise when you
     * remove them from the approved list and hup, their descriptor is
     * taken out of the directory, but they're still in the running-routers
     * line. */
    nickname_lst[n++] = conn->nickname;
  }
  length = n + 1; /* spaces + EOS + 1. */
  for (i = 0; i<n; ++i) {
    length += strlen(nickname_lst[i]);
  }
  *nicknames_out = tor_malloc_zero(length);
  cp = *nicknames_out;
  for (i = 0; i<n; ++i) {
    if (i)
      strcat(cp, " ");
    strcat(cp, nickname_lst[i]); /* can't overflow */
    while (*cp)
      ++cp;
  }
  return 0;
}

/* Remove any descriptors from the directory that are more than ROUTER_MAX_AGE
 * seconds old.
 */
void
dirserv_remove_old_servers(void)
{
  int i;
  time_t cutoff;
  cutoff = time(NULL) - ROUTER_MAX_AGE;
  for (i = 0; i < n_descriptors; ++i) {
    if (descriptor_list[i]->published < cutoff) {
      /* descriptor_list[i] is too old.  Remove it. */
      free_descriptor_entry(descriptor_list[i]);
      descriptor_list[i] = descriptor_list[n_descriptors-1];
      --n_descriptors;
      directory_set_dirty();
      --i; /* Don't advance the index; consider the new value now at i. */
    }
  }
}

/* Dump all routers currently in the directory into the string <s>, using
 * at most <maxlen> characters, and signing the directory with <private_key>.
 * Return 0 on success, -1 on failure.
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

  if (list_running_servers(&cp))
    return -1;
  dirserv_remove_old_servers();
  published_on = time(NULL);
  strftime(published, 32, "%Y-%m-%d %H:%M:%S", gmtime(&published_on));
  snprintf(s, maxlen,
           "signed-directory\n"
           "published %s\n"
           "recommended-software %s\n"
           "running-routers %s\n\n", published, options.RecommendedVersions, cp);
  free(cp);
  i = strlen(s);
  cp = s+i;

  for (i = 0; i < n_descriptors; ++i) {
    if (strlcat(s, descriptor_list[i]->descriptor, maxlen) >= maxlen)
      goto truncated;
  }
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

static char *the_directory = NULL;
static int the_directory_len = -1;

size_t dirserv_get_directory(const char **directory)
{
  char *new_directory;
  char filename[512];
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
    if (router_set_routerlist_from_directory(new_directory, get_identity_key())) {
      log_fn(LOG_ERR, "We just generated a directory we can't parse. Dying.");
      exit(0);
    }
    free(new_directory);
    sprintf(filename,"%s/cached-directory", options.DataDirectory);
    if(write_str_to_file(filename,the_directory) < 0) {
      log_fn(LOG_WARN, "Couldn't write cached directory to disk. Ignoring.");
    }
  } else {
    log(LOG_INFO,"Directory still clean, reusing.");
  }
  *directory = the_directory;
  return the_directory_len;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
