/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/* How far in the future do we allow a router to get? (seconds) */
#define ROUTER_ALLOW_SKEW (30*60)

extern or_options_t options; /* command-line and config-file options */

static int the_directory_is_dirty = 1;

static int list_running_servers(char **nicknames_out);

/************** Fingerprint handling code ************/

typedef struct fingerprint_entry_t {
  char *nickname;
  char *fingerprint;
} fingerprint_entry_t;

static fingerprint_entry_t fingerprint_list[MAX_ROUTERS_IN_DIR];
static int n_fingerprints = 0;

static void
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

/* return 0 on success, -1 on failure */
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

/* return 1 if router's identity and nickname match,
 * -1 if they don't match, 0 if the nickname is not known. */
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
typedef struct descriptor_entry_t {
  char *nickname;
  time_t published;
  size_t desc_len;
  char *descriptor;
} descriptor_entry_t;

static descriptor_entry_t *descriptor_list[MAX_ROUTERS_IN_DIR];
static int n_descriptors = 0;

static void free_descriptor_entry(descriptor_entry_t *desc)
{
  tor_free(desc->descriptor);
  tor_free(desc->nickname);
  free(desc);
}

void
dirserv_free_descriptors()
{
  int i;
  for (i = 0; i < n_descriptors; ++i) {
    free_descriptor_entry(descriptor_list[i]);
  }
  n_descriptors = 0;
}

/* Return 0 if descriptor is well-formed; -1 if descriptor is not
 * well-formed.  Update *desc to point after the descriptor if the
 * descriptor is well-formed.
 */
/* XXX down the road perhaps we should return 1 for accepted, 0 for
 * well-formed but rejected, -1 for not-well-formed. So remote servers
 * can know if their submission was accepted and not just whether it
 * was well-formed. ...Or maybe we shouldn't give them that info?
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

  start = strstr(*desc, "router ");
  if (!start) {
    log(LOG_WARN, "no descriptor found.");
    goto err;
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
  if (!ri) {
    log(LOG_WARN, "Couldn't parse descriptor");
    goto err;
  }
  tor_free(desc_tmp);
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
  if (ri->published_on > time(NULL)+ROUTER_ALLOW_SKEW) {
    log_fn(LOG_WARN, "Publication time for nickname %s is too far in the future; possible clock skew. Not adding", ri->nickname);
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
      /* This isn't really an error; return. */
      routerinfo_free(ri);
      *desc = end;
      return 0;
    }
    /* We don't have a newer one; we'll update this one. */
    free_descriptor_entry(*desc_ent_ptr);
  } else {
    /* Add this at the end. */
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
  *desc = end;
  directory_set_dirty();

  routerinfo_free(ri);
  return 0;
 err:
  tor_free(desc_tmp);
  if (ri)
    routerinfo_free(ri);

  return -1;
}

void
directory_set_dirty()
{
  the_directory_is_dirty = 1;
}

int
dirserv_init_from_directory_string(const char *dir)
{
  const char *cp = dir;
  while(1) {
    cp = strstr(cp, "\nrouter ");
    if (!cp) break;
    ++cp;
    if (dirserv_add_descriptor(&cp)) {
      return -1;
    }
    --cp; /*Back up to newline.*/
  }
  return 0;
}

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
    strcat(cp, nickname_lst[i]);
    while (*cp)
      ++cp;
  }
  return 0;
}

int
dirserv_dump_directory_to_string(char *s, int maxlen,
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
    strncat(cp, descriptor_list[i]->descriptor, descriptor_list[i]->desc_len);
    /* XXX Nick: do strncat and friends null-terminate? man page is ambiguous. */
    cp += descriptor_list[i]->desc_len;
    assert(!*cp);
  }
  /* These multiple strlen calls are inefficient, but dwarfed by the RSA
     signature.
  */
  i = strlen(s);
  strncat(s, "directory-signature\n", maxlen-i);
  i = strlen(s);
  cp = s + i;

  if (router_get_dir_hash(s,digest)) {
    log_fn(LOG_WARN,"couldn't compute digest");
    return -1;
  }
  if (crypto_pk_private_sign(private_key, digest, 20, signature) < 0) {
    log_fn(LOG_WARN,"couldn't sign digest");
    return -1;
  }
  log(LOG_DEBUG,"generated directory digest begins with %02x:%02x:%02x:%02x",
      ((int)digest[0])&0xff,((int)digest[1])&0xff,
      ((int)digest[2])&0xff,((int)digest[3])&0xff);

  strncpy(cp, "-----BEGIN SIGNATURE-----\n", maxlen-i);
  cp[maxlen-i-1] = 0;

  i = strlen(s);
  cp = s+i;
  if (base64_encode(cp, maxlen-i, signature, 128) < 0) {
    log_fn(LOG_WARN,"couldn't base64-encode signature");
    return -1;
  }

  i = strlen(s);
  cp = s+i;
  strncat(cp, "-----END SIGNATURE-----\n", maxlen-i);
  i = strlen(s);
  if (i == maxlen) {
    log_fn(LOG_WARN,"tried to exceed string length.");
    return -1;
  }

  return 0;
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

