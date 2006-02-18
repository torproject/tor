/* Copyright 2001-2004 Roger Dingledine.
 * Copyright 2004-2005 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char dirserv_c_id[] = "$Id$";

#include "or.h"

/**
 * \file dirserv.c
 * \brief Directory server core implementation.
 **/

/** How far in the future do we allow a router to get? (seconds) */
#define ROUTER_ALLOW_SKEW (60*60*12) /* 12 hours */
/** How many seconds do we wait before regenerating the directory? */
#define DIR_REGEN_SLACK_TIME 5

/** Do we need to regenerate the directory when someone asks for it? */
static int the_directory_is_dirty = 1;
static int runningrouters_is_dirty = 1;

static void directory_remove_unrecognized(void);
static int dirserv_regenerate_directory(void);
/* Should be static; exposed for testing */
void add_fingerprint_to_dir(const char *nickname, const char *fp);

/************** Fingerprint handling code ************/

typedef struct fingerprint_entry_t {
  char *nickname;
  char *fingerprint; /**< Stored as HEX_DIGEST_LEN characters, followed by a NUL */
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
  tor_strstrip(ent->fingerprint, " ");
  smartlist_add(fingerprint_list, ent);
}

/** Add the nickname and fingerprint for this OR to the recognized list.
 */
int
dirserv_add_own_fingerprint(const char *nickname, crypto_pk_env_t *pk)
{
  char fp[FINGERPRINT_LEN+1];
  if (crypto_pk_get_fingerprint(pk, fp, 0)<0) {
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
  char *cf;
  char *nickname, *fingerprint;
  smartlist_t *fingerprint_list_new;
  int i, result;
  fingerprint_entry_t *ent;
  struct config_line_t *front=NULL, *list;

  cf = read_file_to_str(fname, 0);
  if (!cf) {
    log_fn(LOG_WARN, "Cannot open fingerprint file %s", fname);
    return -1;
  }
  result = config_get_lines(cf, &front);
  tor_free(cf);
  if (result < 0) {
    log_fn(LOG_WARN, "Error reading from fingerprint file");
    return -1;
  }

  fingerprint_list_new = smartlist_create();

  for (list=front; list; list=list->next) {
    nickname = list->key; fingerprint = list->value;
    if (strlen(nickname) > MAX_NICKNAME_LEN) {
      log(LOG_NOTICE, "Nickname '%s' too long in fingerprint file. Skipping.", nickname);
      continue;
    }
    if (strlen(fingerprint) != FINGERPRINT_LEN ||
        !crypto_pk_check_fingerprint_syntax(fingerprint)) {
      log_fn(LOG_NOTICE, "Invalid fingerprint (nickname '%s', fingerprint %s). Skipping.",
             nickname, fingerprint);
      continue;
    }
    if (0==strcasecmp(nickname, DEFAULT_CLIENT_NICKNAME)) {
      /* If you approved an OR called "client", then clients who use
       * the default nickname could all be rejected.  That's no good. */
      log(LOG_NOTICE,
          "Authorizing a nickname '%s' would break many clients; skipping.",
          DEFAULT_CLIENT_NICKNAME);
      continue;
    }
    for (i = 0; i < smartlist_len(fingerprint_list_new); ++i) {
      ent = smartlist_get(fingerprint_list_new, i);
      if (0==strcasecmp(ent->nickname, nickname)) {
        log(LOG_NOTICE, "Duplicate nickname '%s'. Skipping.",nickname);
        break; /* out of the for. the 'if' below means skip to the next line. */
      }
    }
    if (i == smartlist_len(fingerprint_list_new)) { /* not a duplicate */
      ent = tor_malloc(sizeof(fingerprint_entry_t));
      ent->nickname = tor_strdup(nickname);
      ent->fingerprint = tor_strdup(fingerprint);
      tor_strstrip(ent->fingerprint, " ");
      smartlist_add(fingerprint_list_new, ent);
    }
  }

  config_free_lines(front);
  dirserv_free_fingerprint_list();
  fingerprint_list = fingerprint_list_new;
  /* Delete any routers whose fingerprints we no longer recognize */
  directory_remove_unrecognized();
  return 0;
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
    log_fn(LOG_INFO,"no fingerprint found for '%s'",router->nickname);
    return 0;
  }
  if (crypto_pk_get_fingerprint(router->identity_pkey, fp, 0)) {
    log_fn(LOG_WARN,"error computing fingerprint");
    return -1;
  }
  if (0==strcasecmp(ent->fingerprint, fp)) {
    log_fn(LOG_DEBUG,"good fingerprint for '%s'",router->nickname);
    return 1; /* Right fingerprint. */
  } else {
    log_fn(LOG_WARN,"mismatched fingerprint for '%s'",router->nickname);
    return -1; /* Wrong fingerprint. */
  }
}

/** If we are an authoritative dirserver, and the list of approved
 * servers contains one whose identity key digest is <b>digest</b>,
 * return that router's nickname.  Otherwise return NULL. */
const char *dirserv_get_nickname_by_digest(const char *digest)
{
  char hexdigest[HEX_DIGEST_LEN+1];
  if (!fingerprint_list)
    return NULL;
  tor_assert(digest);

  base16_encode(hexdigest, HEX_DIGEST_LEN+1, digest, DIGEST_LEN);
  SMARTLIST_FOREACH(fingerprint_list, fingerprint_entry_t*, ent,
                    { if (!strcasecmp(hexdigest, ent->fingerprint))
                         return ent->nickname; } );
  return NULL;
}

#if 0
/** Return true iff any router named <b>nickname</b> with <b>digest</b>
 * is in the verified fingerprint list. */
static int
router_nickname_is_approved(const char *nickname, const char *digest)
{
  const char *n;

  n = dirserv_get_nickname_by_digest(digest);
  if (n && !strcasecmp(n,nickname))
    return 1;
  else
    return 0;
}
#endif

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

/** List of routerinfo_t for all server descriptors that this dirserv
 * is holding.
 * XXXX This should eventually get coalesced into routerlist.c
 */
static smartlist_t *descriptor_list = NULL;

/** Release all storage that the dirserv is holding for server
 * descriptors. */
void
dirserv_free_descriptors()
{
  if (!descriptor_list)
    return;
  SMARTLIST_FOREACH(descriptor_list, routerinfo_t *, ri,
                    routerinfo_free(ri));
  smartlist_clear(descriptor_list);
}

/** Return -1 if <b>ri</b> has a private or otherwise bad address,
 * unless we're configured to not care. Return 0 if all ok. */
static int
dirserv_router_has_valid_address(routerinfo_t *ri)
{
  struct in_addr iaddr;
  if (get_options()->DirAllowPrivateAddresses)
    return 0; /* whatever it is, we're fine with it */
  if (!tor_inet_aton(ri->address, &iaddr)) {
    log_fn(LOG_INFO,"Router '%s' published non-IP address '%s'. Refusing.",
           ri->nickname, ri->address);
    return -1;
  }
  if (is_internal_IP(ntohl(iaddr.s_addr))) {
    log_fn(LOG_INFO,"Router '%s' published internal IP address '%s'. Refusing.",
           ri->nickname, ri->address);
    return -1; /* it's a private IP, we should reject it */
  }
  return 0;
}

/** Parse the server descriptor at *desc and maybe insert it into the
 * list of server descriptors, and (if the descriptor is well-formed)
 * advance *desc immediately past the descriptor's end.  Set msg to a
 * message that should be passed back to the origin of this descriptor, or
 * to NULL.
 *
 * Return 1 if descriptor is well-formed and accepted;
 *  0 if well-formed and server is unapproved but accepted;
 * -1 if it looks vaguely like a router descriptor but rejected;
 * -2 if we can't find a router descriptor in *desc.
 */
int
dirserv_add_descriptor(const char **desc, const char **msg)
{
  routerinfo_t *ri = NULL, *ri_old=NULL;
  int i, r, found=-1;
  char *start, *end;
  char *desc_tmp = NULL;
  size_t desc_len;
  time_t now;
  int verified=1; /* whether we knew its fingerprint already */
  tor_assert(msg);
  *msg = NULL;
  if (!descriptor_list)
    descriptor_list = smartlist_create();

  start = strstr(*desc, "router ");
  if (!start) {
    log_fn(LOG_WARN, "no 'router' line found. This is not a descriptor.");
    return -2;
  }
  if ((end = strstr(start+6, "\nrouter "))) {
    ++end; /* Include NL. */
  } else if ((end = strstr(start+6, "\ndirectory-signature"))) {
    ++end;
  } else {
    end = start+strlen(start);
  }
  desc_len = end-start;
  desc_tmp = tor_strndup(start, desc_len); /* Is this strndup still needed???*/

  /* Check: is the descriptor syntactically valid? */
  ri = router_parse_entry_from_string(desc_tmp, NULL);
  tor_free(desc_tmp);
  if (!ri) {
    log(LOG_WARN, "Couldn't parse descriptor");
    *msg = "Rejected: Couldn't parse server descriptor.";
    return -1;
  }
  /* Okay.  Now check whether the fingerprint is recognized. */
  r = dirserv_router_fingerprint_is_known(ri);
  if (r==-1) {
    log_fn(LOG_WARN, "Known nickname '%s', wrong fingerprint. Not adding (ContactInfo '%s', platform '%s').",
           ri->nickname, ri->contact_info ? ri->contact_info : "",
           ri->platform ? ri->platform : "");
    *msg = "Rejected: There is already a verified server with this nickname and a different fingerprint.";
    routerinfo_free(ri);
    *desc = end;
    return -1;
  } else if (r==0) {
    char fp[FINGERPRINT_LEN+1];
    log_fn(LOG_INFO, "Unknown nickname '%s' (%s:%d). Will try to add.",
           ri->nickname, ri->address, ri->or_port);
    if (crypto_pk_get_fingerprint(ri->identity_pkey, fp, 1) < 0) {
      log_fn(LOG_WARN, "Error computing fingerprint for '%s'", ri->nickname);
    } else {
      log_fn(LOG_INFO, "Fingerprint line: %s %s", ri->nickname, fp);
    }
    verified = 0;
  }
  /* Is there too much clock skew? */
  now = time(NULL);
  if (ri->published_on > now+ROUTER_ALLOW_SKEW) {
    log_fn(LOG_NOTICE, "Publication time for nickname '%s' is too far (%d minutes) in the future; possible clock skew. Not adding (ContactInfo '%s', platform '%s').",
           ri->nickname, (int)((ri->published_on-now)/60),
           ri->contact_info ? ri->contact_info : "",
           ri->platform ? ri->platform : "");
    *msg = "Rejected: Your clock is set too far in the future, or your timezone is not correct.";
    routerinfo_free(ri);
    *desc = end;
    return -1;
  }
  if (ri->published_on < now-ROUTER_MAX_AGE) {
    log_fn(LOG_NOTICE, "Publication time for router with nickname '%s' is too far (%d minutes) in the past. Not adding (ContactInfo '%s', platform '%s').",
           ri->nickname, (int)((now-ri->published_on)/60),
           ri->contact_info ? ri->contact_info : "",
           ri->platform ? ri->platform : "");
    *msg = "Rejected: Server is expired, or your clock is too far in the past, or your timezone is not correct.";
    routerinfo_free(ri);
    *desc = end;
    return -1;
  }
  if (dirserv_router_has_valid_address(ri) < 0) {
    log_fn(LOG_NOTICE, "Router with nickname '%s' has invalid address '%s'. Not adding (ContactInfo '%s', platform '%s').",
           ri->nickname, ri->address,
           ri->contact_info ? ri->contact_info : "",
           ri->platform ? ri->platform : "");
    *msg = "Rejected: Address is not an IP, or IP is a private address.";
    routerinfo_free(ri);
    *desc = end;
    return -1;
  }

  /* Do we already have an entry for this router? */
  for (i = 0; i < smartlist_len(descriptor_list); ++i) {
    ri_old = smartlist_get(descriptor_list, i);
    if (!memcmp(ri->identity_digest, ri_old->identity_digest, DIGEST_LEN)) {
      found = i;
      break;
    }
  }
  if (found >= 0) {
    char hex_digest[HEX_DIGEST_LEN+1];
    base16_encode(hex_digest, HEX_DIGEST_LEN+1, ri->identity_digest,DIGEST_LEN);
    /* if so, decide whether to update it. */
    if (ri_old->published_on >= ri->published_on) {
      /* We already have a newer or equal-time descriptor */
      log_fn(LOG_INFO,"We already have a new enough desc for server %s (nickname '%s'). Not adding.",hex_digest,ri->nickname);
      *msg = "We already have a newer descriptor.";
      /* This isn't really an error; return success. */
      routerinfo_free(ri);
      *desc = end;
      return verified;
    }
    /* We don't alrady have a newer one; we'll update this one. */
    log_fn(LOG_INFO,"Dirserv updating desc for server %s (nickname '%s')",hex_digest,ri->nickname);
    *msg = verified?"Verified server updated":"Unverified server updated. (Have you sent us your key fingerprint?)";
    routerinfo_free(ri_old);
    smartlist_del_keeporder(descriptor_list, found);
  } else {
    /* Add at the end. */
    log_fn(LOG_INFO,"Dirserv adding desc for nickname '%s'",ri->nickname);
    *msg = verified?"Verified server added":"Unverified server added. (Have you sent us your key fingerprint?)";
  }

  ri->is_verified = verified ||
                    tor_version_as_new_as(ri->platform,"0.1.0.2-rc");
  smartlist_add(descriptor_list, ri);

  *desc = end;
  directory_set_dirty();

  return verified;
}

/** Remove all descriptors whose nicknames or fingerprints we don't
 * recognize.  (Descriptors that used to be good can become
 * unrecognized when we reload the fingerprint list.)
 */
static void
directory_remove_unrecognized(void)
{
  int i;
  int r;
  routerinfo_t *ent;
  if (!descriptor_list)
    descriptor_list = smartlist_create();

  for (i = 0; i < smartlist_len(descriptor_list); ++i) {
    ent = smartlist_get(descriptor_list, i);
    r = dirserv_router_fingerprint_is_known(ent);
    if (r<0) {
      log(LOG_INFO, "Router '%s' is now verified with a key; removing old router with same name and different key.",
          ent->nickname);
      routerinfo_free(ent);
      smartlist_del(descriptor_list, i--);
    } else if (r>0 && !ent->is_verified) {
      log(LOG_INFO, "Router '%s' is now approved.", ent->nickname);
      ent->is_verified = 1;
    } else if (r==0 && ent->is_verified) {
      log(LOG_INFO, "Router '%s' is no longer approved.", ent->nickname);
      ent->is_verified = 0;
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
  time_t now = time(NULL);

  if (!the_directory_is_dirty)
    the_directory_is_dirty = now;
  if (!runningrouters_is_dirty)
    runningrouters_is_dirty = now;
}

/** Load all descriptors from a directory stored in the string
 * <b>dir</b>.
 */
int
dirserv_load_from_directory_string(const char *dir)
{
  const char *cp = dir, *m;
  while (1) {
    cp = strstr(cp, "\nrouter ");
    if (!cp) break;
    ++cp;
    if (dirserv_add_descriptor(&cp,&m) < -1) {
      /* only fail if parsing failed; keep going if simply rejected */
      return -1;
    }
    --cp; /*Back up to newline.*/
  }
  return 0;
}

/**
 * Allocate and return a description of the status of the server <b>desc</b>,
 * for use in a router-status line.  The server is listed
 * as running iff <b>is_live</b> is true.
 */
static char *
list_single_server_status(routerinfo_t *desc, int is_live)
{
  char buf[MAX_NICKNAME_LEN+HEX_DIGEST_LEN+4]; /* !nickname=$hexdigest\0 */
  char *cp;

  tor_assert(desc);

  cp = buf;
  if (!is_live) {
    *cp++ = '!';
  }
  if (desc->is_verified) {
    strlcpy(cp, desc->nickname, sizeof(buf)-(cp-buf));
    cp += strlen(cp);
    *cp++ = '=';
  }
  *cp++ = '$';
  base16_encode(cp, HEX_DIGEST_LEN+1, desc->identity_digest,
                DIGEST_LEN);
  return tor_strdup(buf);
}

/** Based on the routerinfo_ts in <b>routers</b>, allocate the
 * contents of a router-status line, and store it in
 * *<b>router_status_out</b>.  Return 0 on success, -1 on failure.
 */
int
list_server_status(smartlist_t *routers, char **router_status_out)
{
  /* List of entries in a router-status style: An optional !, then an optional
   * equals-suffixed nickname, then a dollar-prefixed hexdigest. */
  smartlist_t *rs_entries;
  /* XXXX Really, we should merge descriptor_list into routerlist.  But
   * this is potentially tricky, since the semantics of the two lists
   * are not quite the same.  In any case, it's not for the 0.1.0.x
   * series.
   */
  int authdir_mode = get_options()->AuthoritativeDir;
  tor_assert(router_status_out);

  rs_entries = smartlist_create();

  SMARTLIST_FOREACH(routers, routerinfo_t *, ri,
  {
    int is_live;
    connection_t *conn;
    conn = connection_get_by_identity_digest(
                    ri->identity_digest, CONN_TYPE_OR);
    if (authdir_mode) {
      /* Treat a router as alive if
       *    - It's me, and I'm not hibernating.
       * or - we're connected to it. */
      is_live = (router_is_me(ri) && !we_are_hibernating()) ||
        (conn && conn->state == OR_CONN_STATE_OPEN);
    } else {
      is_live = ri->is_running;
    }
    smartlist_add(rs_entries, list_single_server_status(ri, is_live));
  });

  *router_status_out = smartlist_join_strings(rs_entries, " ", 0,NULL);

  SMARTLIST_FOREACH(rs_entries, char *, cp, tor_free(cp));
  smartlist_free(rs_entries);

  return 0;
}

/** Remove any descriptors from the directory that are more than <b>age</b>
 * seconds old.
 */
void
dirserv_remove_old_servers(int age)
{
  int i;
  time_t cutoff;
  routerinfo_t *ent;
  if (!descriptor_list)
    descriptor_list = smartlist_create();

  cutoff = time(NULL) - age;
  for (i = 0; i < smartlist_len(descriptor_list); ++i) {
    ent = smartlist_get(descriptor_list, i);
    if (ent->published_on <= cutoff) {
      /* descriptor_list[i] is too old.  Remove it. */
      routerinfo_free(ent);
      smartlist_del(descriptor_list, i--);
      directory_set_dirty();
    }
  }
}

/** Generate a new directory and write it into a newly allocated string.
 * Point *<b>dir_out</b> to the allocated string.  Sign the
 * directory with <b>private_key</b>.  Return 0 on success, -1 on
 * failure.
 */
int
dirserv_dump_directory_to_string(char **dir_out,
                                 crypto_pk_env_t *private_key)
{
  char *cp;
  char *router_status;
  char *identity_pkey; /* Identity key, DER64-encoded. */
  char *recommended_versions;
  char digest[20];
  char signature[128];
  char published[33];
  time_t published_on;
  char *buf = NULL;
  size_t buf_len;
  int i;
  size_t identity_pkey_len;

  tor_assert(dir_out);
  *dir_out = NULL;

  if (!descriptor_list)
    descriptor_list = smartlist_create();

  if (list_server_status(descriptor_list, &router_status))
    return -1;

  if (crypto_pk_write_public_key_to_string(private_key,&identity_pkey,
                                           &identity_pkey_len)<0) {
    log_fn(LOG_WARN,"write identity_pkey to string failed!");
    return -1;
  }

  {
    smartlist_t *versions;
    struct config_line_t *ln;
    versions = smartlist_create();
    for (ln = get_options()->RecommendedVersions; ln; ln = ln->next) {
      smartlist_split_string(versions, ln->value, ",",
                             SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    }
    recommended_versions = smartlist_join_strings(versions,",",0,NULL);
    SMARTLIST_FOREACH(versions,char *,s,tor_free(s));
    smartlist_free(versions);
  }

  dirserv_remove_old_servers(ROUTER_MAX_AGE);
  published_on = time(NULL);
  format_iso_time(published, published_on);

  buf_len = 2048+strlen(recommended_versions)+
    strlen(router_status);
  SMARTLIST_FOREACH(descriptor_list, routerinfo_t *, ri,
                    buf_len += strlen(ri->signed_descriptor));
  buf = tor_malloc(buf_len);
  /* We'll be comparing against buf_len throughout the rest of the
     function, though strictly speaking we shouldn't be able to exceed
     it.  This is C, after all, so we may as well check for buffer
     overruns.*/

  tor_snprintf(buf, buf_len,
           "signed-directory\n"
           "published %s\n"
           "recommended-software %s\n"
           "router-status %s\n"
           "dir-signing-key\n%s\n",
           published, recommended_versions, router_status,
           identity_pkey);

  tor_free(recommended_versions);
  tor_free(router_status);
  tor_free(identity_pkey);
  i = strlen(buf);
  cp = buf+i;

  SMARTLIST_FOREACH(descriptor_list, routerinfo_t *, ri,
    if (strlcat(buf, ri->signed_descriptor, buf_len) >= buf_len)
      goto truncated);

  /* These multiple strlcat calls are inefficient, but dwarfed by the RSA
     signature.
  */
  if (strlcat(buf, "directory-signature ", buf_len) >= buf_len)
    goto truncated;
  if (strlcat(buf, get_options()->Nickname, buf_len) >= buf_len)
    goto truncated;
  if (strlcat(buf, "\n", buf_len) >= buf_len)
    goto truncated;

  if (router_get_dir_hash(buf,digest)) {
    log_fn(LOG_WARN,"couldn't compute digest");
    tor_free(buf);
    return -1;
  }
  if (crypto_pk_private_sign(private_key, signature, digest, 20) < 0) {
    log_fn(LOG_WARN,"couldn't sign digest");
    tor_free(buf);
    return -1;
  }
  log(LOG_DEBUG,"generated directory digest begins with %s",hex_str(digest,4));

  if (strlcat(cp, "-----BEGIN SIGNATURE-----\n", buf_len) >= buf_len)
    goto truncated;

  i = strlen(buf);
  cp = buf+i;
  if (base64_encode(cp, buf_len-i, signature, 128) < 0) {
    log_fn(LOG_WARN,"couldn't base64-encode signature");
    tor_free(buf);
    return -1;
  }

  if (strlcat(buf, "-----END SIGNATURE-----\n", buf_len) >= buf_len)
    goto truncated;

  *dir_out = buf;
  return 0;
 truncated:
  log_fn(LOG_WARN,"tried to exceed string length.");
  tor_free(buf);
  return -1;
}

/** Most recently generated encoded signed directory. */
static char *the_directory = NULL;
static size_t the_directory_len = 0;
static char *the_directory_z = NULL;
static size_t the_directory_z_len = 0;

typedef struct cached_dir_t {
  char *dir;
  char *dir_z;
  size_t dir_len;
  size_t dir_z_len;
  time_t published;
} cached_dir_t;

/* used only by non-auth dirservers */
static cached_dir_t cached_directory = { NULL, NULL, 0, 0, 0 };
static cached_dir_t cached_runningrouters = { NULL, NULL, 0, 0, 0 };

/** If we have no cached directory, or it is older than <b>when</b>, then
 * replace it with <b>directory</b>, published at <b>when</b>.
 */
void dirserv_set_cached_directory(const char *directory, time_t when,
                                  int is_running_routers)
{
  time_t now;
  cached_dir_t *d;
  now = time(NULL);
  d = is_running_routers ? &cached_runningrouters : &cached_directory;
  if (when<=d->published) {
    log_fn(LOG_INFO, "Ignoring old directory; not caching.");
  } else if (when>=now+ROUTER_MAX_AGE) {
    log_fn(LOG_INFO, "Ignoring future directory; not caching.");
  } else {
    /* if (when>d->published && when<now+ROUTER_MAX_AGE) */
    log_fn(LOG_DEBUG, "Caching directory.");
    tor_free(d->dir);
    d->dir = tor_strdup(directory);
    d->dir_len = strlen(directory);
    tor_free(d->dir_z);
    if (tor_gzip_compress(&(d->dir_z), &(d->dir_z_len), d->dir, d->dir_len,
                          ZLIB_METHOD)) {
      log_fn(LOG_WARN,"Error compressing cached directory");
    }
    d->published = when;
    if (!is_running_routers) {
      char filename[512];
      tor_snprintf(filename,sizeof(filename),"%s/cached-directory", get_options()->DataDirectory);
      if (write_str_to_file(filename,cached_directory.dir,0) < 0) {
        log_fn(LOG_NOTICE, "Couldn't write cached directory to disk. Ignoring.");
      }
    }
  }
}

/** Set *<b>directory</b> to the most recently generated encoded signed
 * directory, generating a new one as necessary.  If not an authoritative
 * directory may return 0 if no directory is yet cached.*/
size_t dirserv_get_directory(const char **directory, int compress)
{
  if (!get_options()->AuthoritativeDir) {
    cached_dir_t *d = &cached_directory;
    *directory = compress ? d->dir_z : d->dir;
    if (*directory) {
      return compress ? d->dir_z_len : d->dir_len;
    } else {
      /* no directory yet retrieved */
      return 0;
    }
  }
  if (the_directory_is_dirty &&
      the_directory_is_dirty + DIR_REGEN_SLACK_TIME < time(NULL)) {
    if (dirserv_regenerate_directory())
      return 0;
  } else {
    log(LOG_INFO,"Directory still clean, reusing.");
  }
  *directory = compress ? the_directory_z : the_directory;
  return compress ? the_directory_z_len : the_directory_len;
}

/**
 * Generate a fresh directory (authdirservers only.)
 */
static int dirserv_regenerate_directory(void)
{
  char *new_directory=NULL;

  if (dirserv_dump_directory_to_string(&new_directory,
                                       get_identity_key())) {
    log(LOG_WARN, "Error creating directory.");
    tor_free(new_directory);
    return -1;
  }
  tor_free(the_directory);
  the_directory = new_directory;
  the_directory_len = strlen(the_directory);
  log_fn(LOG_INFO,"New directory (size %d):\n%s",(int)the_directory_len,
         the_directory);
  tor_free(the_directory_z);
  if (tor_gzip_compress(&the_directory_z, &the_directory_z_len,
                        the_directory, the_directory_len,
                        ZLIB_METHOD)) {
    log_fn(LOG_WARN, "Error gzipping directory.");
    return -1;
  }

#if 0
  /* Now read the directory we just made in order to update our own
   * router lists.  This does more signature checking than is strictly
   * necessary, but safe is better than sorry. */
  new_directory = tor_strdup(the_directory);
  /* use a new copy of the dir, since get_dir_from_string scribbles on it */
  if (router_load_routerlist_from_directory(new_directory,
                                            get_identity_key(), 1, 0)) {
    log_fn(LOG_ERR, "We just generated a directory we can't parse. Dying.");
    tor_cleanup();
    exit(0);
  }
  tor_free(new_directory);
#endif
  the_directory_is_dirty = 0;

  /* Save the directory to disk so we re-load it quickly on startup.
   */
  dirserv_set_cached_directory(the_directory, time(NULL), 0);

  return 0;
}

static char *the_runningrouters=NULL;
static size_t the_runningrouters_len=0;
static char *the_runningrouters_z=NULL;
static size_t the_runningrouters_z_len=0;

/** Replace the current running-routers list with a newly generated one. */
static int generate_runningrouters(crypto_pk_env_t *private_key)
{
  char *s=NULL, *cp;
  char *router_status=NULL;
  char digest[DIGEST_LEN];
  char signature[PK_BYTES];
  int i;
  char published[33];
  size_t len;
  time_t published_on;
  char *identity_pkey; /* Identity key, DER64-encoded. */
  size_t identity_pkey_len;

  if (!descriptor_list)
    descriptor_list = smartlist_create();

  if (list_server_status(descriptor_list, &router_status)) {
    goto err;
  }
  if (crypto_pk_write_public_key_to_string(private_key,&identity_pkey,
                                           &identity_pkey_len)<0) {
    log_fn(LOG_WARN,"write identity_pkey to string failed!");
    goto err;
  }
  published_on = time(NULL);
  format_iso_time(published, published_on);

  len = 2048+strlen(router_status);
  s = tor_malloc_zero(len);
  tor_snprintf(s, len, "network-status\n"
             "published %s\n"
             "router-status %s\n"
             "dir-signing-key\n%s"
             "directory-signature %s\n"
             "-----BEGIN SIGNATURE-----\n",
          published, router_status, identity_pkey, get_options()->Nickname);
  tor_free(router_status);
  tor_free(identity_pkey);
  if (router_get_runningrouters_hash(s,digest)) {
    log_fn(LOG_WARN,"couldn't compute digest");
    goto err;
  }
  if (crypto_pk_private_sign(private_key, signature, digest, 20) < 0) {
    log_fn(LOG_WARN,"couldn't sign digest");
    goto err;
  }

  i = strlen(s);
  cp = s+i;
  if (base64_encode(cp, len-i, signature, 128) < 0) {
    log_fn(LOG_WARN,"couldn't base64-encode signature");
    goto err;
  }
  if (strlcat(s, "-----END SIGNATURE-----\n", len) >= len) {
    goto err;
  }

  tor_free(the_runningrouters);
  the_runningrouters = s;
  the_runningrouters_len = strlen(s);
  tor_free(the_runningrouters_z);
  if (tor_gzip_compress(&the_runningrouters_z, &the_runningrouters_z_len,
                        the_runningrouters, the_runningrouters_len,
                        ZLIB_METHOD)) {
    log_fn(LOG_WARN, "Error gzipping runningrouters");
    return -1;
  }
  runningrouters_is_dirty = 0;

  /* We don't cache running-routers to disk, so there's no point in
   * authdirservers caching it. */
  /* dirserv_set_cached_directory(the_runningrouters, time(NULL), 1); */

  return 0;
 err:
  tor_free(s);
  tor_free(router_status);
  return -1;
}

/** Set *<b>rr</b> to the most recently generated encoded signed
 * running-routers list, generating a new one as necessary.  Return the
 * size of the directory on success, and 0 on failure. */
size_t dirserv_get_runningrouters(const char **rr, int compress)
{
  if (!get_options()->AuthoritativeDir) {
    cached_dir_t *d = &cached_runningrouters;
    *rr = compress ? d->dir_z : d->dir;
    if (*rr) {
      return compress ? d->dir_z_len : d->dir_len;
    } else {
      /* no directory yet retrieved */
      return 0;
    }
  }
  if (runningrouters_is_dirty &&
      runningrouters_is_dirty + DIR_REGEN_SLACK_TIME < time(NULL)) {
    if (generate_runningrouters(get_identity_key())) {
      log_fn(LOG_ERR, "Couldn't generate running-routers list?");
      return 0;
    }
  }
  *rr = compress ? the_runningrouters_z : the_runningrouters;
  return compress ? the_runningrouters_z_len : the_runningrouters_len;
}

/** Called when a TLS handshake has completed successfully with a
 * router listening at <b>address</b>:<b>or_port</b>, and has yielded
 * a certificate with digest <b>digest_rcvd</b> and nickname
 * <b>nickname_rcvd</b>.  When this happens, it's clear that any other
 * descriptors for that address/port combination must be unusable:
 * delete them if they are not verified.
 */
void
dirserv_orconn_tls_done(const char *address,
                        uint16_t or_port,
                        const char *digest_rcvd,
                        const char *nickname_rcvd)
{
  int i;
  tor_assert(address);
  tor_assert(digest_rcvd);
  tor_assert(nickname_rcvd);

  if (!descriptor_list)
    return;

  for (i = 0; i < smartlist_len(descriptor_list); ++i) {
    routerinfo_t *ri = smartlist_get(descriptor_list, i);
    int drop = 0;
    if (ri->is_verified)
      continue;
    if (!strcasecmp(address, ri->address) &&
        or_port == ri->or_port) {
      /* We have a router at the same address! */
      if (strcasecmp(ri->nickname, nickname_rcvd)) {
        log_fn(LOG_NOTICE, "Dropping descriptor: nickname '%s' does not match nickname '%s' in cert from %s:%d",
               ri->nickname, nickname_rcvd, address, or_port);
        drop = 1;
      } else if (memcmp(ri->identity_digest, digest_rcvd, DIGEST_LEN)) {
        log_fn(LOG_NOTICE, "Dropping descriptor: identity key does not match key in cert from %s:%d",
               address, or_port);
        drop = 1;
      }
      if (drop) {
        routerinfo_free(ri);
        smartlist_del(descriptor_list, i--);
        directory_set_dirty();
      }
    }
  }
}

void
dirserv_free_all(void)
{
  if (fingerprint_list) {
    SMARTLIST_FOREACH(fingerprint_list, fingerprint_entry_t*, fp,
                      { tor_free(fp->nickname);
                        tor_free(fp->fingerprint);
                        tor_free(fp); });
    smartlist_free(fingerprint_list);
    fingerprint_list = NULL;
  }
  if (descriptor_list) {
    SMARTLIST_FOREACH(descriptor_list, routerinfo_t *, ri,
                      routerinfo_free(ri));
    smartlist_free(descriptor_list);
    descriptor_list = NULL;
  }
  tor_free(the_directory);
  tor_free(the_directory_z);
  the_directory_len = 0;
  the_directory_z_len = 0;
  tor_free(the_runningrouters);
  tor_free(the_runningrouters_z);
  the_runningrouters_len = 0;
  the_runningrouters_z_len = 0;
  tor_free(cached_directory.dir);
  tor_free(cached_directory.dir_z);
  tor_free(cached_runningrouters.dir);
  tor_free(cached_runningrouters.dir_z);
  memset(&cached_directory, 0, sizeof(cached_directory));
  memset(&cached_runningrouters, 0, sizeof(cached_runningrouters));
}
