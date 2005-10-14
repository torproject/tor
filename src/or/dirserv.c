/* Copyright 2001-2004 Roger Dingledine.
 * Copyright 2004-2005 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char dirserv_c_id[] = "$Id$";

#include "or.h"

/**
 * \file dirserv.c
 * \brief Directory server core implementation. Manages directory
 * contents and generates directories.
 **/

/** How far in the future do we allow a router to get? (seconds) */
#define ROUTER_ALLOW_SKEW (60*60*12) /* 12 hours */
/** How many seconds do we wait before regenerating the directory? */
#define DIR_REGEN_SLACK_TIME 30

extern long stats_n_seconds_working;

typedef enum {
  FP_NAMED, /**< Listed in fingerprint file. */
  FP_VALID, /**< Unlisted but believed valid. */
  FP_INVALID, /**< Believed invalid. */
  FP_REJECT, /**< We will not publish this router. */
} router_status_t;

/** Do we need to regenerate the directory when someone asks for it? */
static int the_directory_is_dirty = 1;
static int runningrouters_is_dirty = 1;
static int the_v2_networkstatus_is_dirty = 1;

static void directory_remove_invalid(void);
static int dirserv_regenerate_directory(void);
static char *format_versions_list(config_line_t *ln);
/* Should be static; exposed for testing */
int add_fingerprint_to_dir(const char *nickname, const char *fp, smartlist_t *list);
static int router_is_general_exit(routerinfo_t *ri);
static router_status_t dirserv_router_get_status(const routerinfo_t *router,
                                                 const char **msg);
static int dirserv_thinks_router_is_reachable(routerinfo_t *router,
                                              time_t now);

/************** Fingerprint handling code ************/

static addr_policy_t *authdir_reject_policy = NULL;
static addr_policy_t *authdir_invalid_policy = NULL;

/** Parse authdir policy strings from the configuration.
 */
void
parse_authdir_policy(void)
{
  addr_policy_t *n;
  if (authdir_reject_policy) {
    addr_policy_free(authdir_reject_policy);
    authdir_reject_policy = NULL;
  }
  config_parse_addr_policy(get_options()->AuthDirReject,
                           &authdir_reject_policy, ADDR_POLICY_REJECT);
  /* ports aren't used. */
  for (n=authdir_reject_policy; n; n = n->next) {
    n->prt_min = 1;
    n->prt_max = 65535;
  }

  if (authdir_invalid_policy) {
    addr_policy_free(authdir_invalid_policy);
    authdir_invalid_policy = NULL;
  }
  config_parse_addr_policy(get_options()->AuthDirInvalid,
                           &authdir_invalid_policy, ADDR_POLICY_REJECT);
  /* ports aren't used. */
  for (n=authdir_invalid_policy; n; n = n->next) {
    n->prt_min = 1;
    n->prt_max = 65535;
  }
}

/** A member of fingerprint_list: maps a name to a fingerprint.
 **/
typedef struct fingerprint_entry_t {
  char *nickname; /**< The name of a router (if this fingerprint is bound to a
                   * name); the string "!reject" (if this fingerprint should
                   * always be rejected); or the string "!invalid" (if this
                   * fingerprint should be accepted but never marked as
                   * valid. */
  char *fingerprint; /**< Stored as HEX_DIGEST_LEN characters, followed by a NUL */
} fingerprint_entry_t;

/** List of nickname-\>identity fingerprint mappings for all the routers
 * that we name.  Used to prevent router impersonation. */
/* Should be static; exposed for testing */
smartlist_t *fingerprint_list = NULL;

/** Add the fingerprint <b>fp</b> for the nickname <b>nickname</b> to
 * the smartlist of fingerprint_entry_t's <b>list</b>. Return 0 if it's
 * new, or 1 if we replaced the old value.
 */
int /* Should be static; exposed for testing */
add_fingerprint_to_dir(const char *nickname, const char *fp, smartlist_t *list)
{
  int i;
  fingerprint_entry_t *ent;
  char *fingerprint;
  tor_assert(nickname);
  tor_assert(fp);
  tor_assert(list);

  fingerprint = tor_strdup(fp);
  tor_strstrip(fingerprint, " ");

  if (nickname[0] != '!') {
    for (i = 0; i < smartlist_len(list); ++i) {
      ent = smartlist_get(list, i);
      if (!strcasecmp(ent->nickname,nickname)) {
        tor_free(ent->fingerprint);
        ent->fingerprint = fingerprint;
        return 1;
      }
    }
  }
  ent = tor_malloc(sizeof(fingerprint_entry_t));
  ent->nickname = tor_strdup(nickname);
  ent->fingerprint = fingerprint;
  smartlist_add(list, ent);
  return 0;
}

/** Add the nickname and fingerprint for this OR to the
 * global list of recognized identity key fingerprints. */
int
dirserv_add_own_fingerprint(const char *nickname, crypto_pk_env_t *pk)
{
  char fp[FINGERPRINT_LEN+1];
  if (crypto_pk_get_fingerprint(pk, fp, 0)<0) {
    log_fn(LOG_ERR, "Error computing fingerprint");
    return -1;
  }
  if (!fingerprint_list)
    fingerprint_list = smartlist_create();
  add_fingerprint_to_dir(nickname, fp, fingerprint_list);
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
  int result;
  config_line_t *front=NULL, *list;

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
    if (!is_legal_nickname(nickname) &&
        strcasecmp(nickname, "!reject") &&
        strcasecmp(nickname, "!invalid")) {
      log(LOG_NOTICE, "Invalid nickname '%s' in fingerprint file. Skipping.", nickname);
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
    if (add_fingerprint_to_dir(nickname, fingerprint, fingerprint_list_new) != 0)
      log(LOG_NOTICE, "Duplicate nickname '%s'.", nickname);
  }

  config_free_lines(front);
  dirserv_free_fingerprint_list();
  fingerprint_list = fingerprint_list_new;
  /* Delete any routers whose fingerprints we no longer recognize */
  directory_remove_invalid();
  return 0;
}

/** Check whether <b>router</b> has a nickname/identity key combination that
 * we recognize from the fingerprint list, or an IP we automatically act on
 * according to our configuration.  Return the appropriate router status.
 *
 * If the status is 'FP_REJECT' and <b>msg</b> is provided, set
 * *<b>msg</b> to an explanation of why.
 */
static router_status_t
dirserv_router_get_status(const routerinfo_t *router, const char **msg)
{
  fingerprint_entry_t *nn_ent = NULL, *fp_ent = NULL;
  char fp[FINGERPRINT_LEN+1];

  if (!fingerprint_list)
    fingerprint_list = smartlist_create();

  if (crypto_pk_get_fingerprint(router->identity_pkey, fp, 0)) {
    log_fn(LOG_WARN,"Error computing fingerprint");
    return -1;
  }

  log_fn(LOG_DEBUG, "%d fingerprints known.", smartlist_len(fingerprint_list));
  SMARTLIST_FOREACH(fingerprint_list, fingerprint_entry_t *, ent,
  {
    if (!strcasecmp(fp,ent->fingerprint))
      fp_ent = ent;
    if (!strcasecmp(router->nickname,ent->nickname))
      nn_ent = ent;
  });

  if (fp_ent) {
    if (!strcasecmp(fp_ent->nickname, "!reject")) {
      if (msg)
        *msg = "Fingerprint is marked rejected";
      return FP_REJECT;
    } else if (!strcasecmp(fp_ent->nickname, "!invalid")) {
      if (msg)
        *msg = "Fingerprint is marged invalid";
      return FP_INVALID;
    }
  }

  if (!nn_ent) { /* No such server known with that nickname */
    addr_policy_result_t rej = router_compare_addr_to_addr_policy(
                       router->addr, router->or_port, authdir_reject_policy);
    addr_policy_result_t inv = router_compare_addr_to_addr_policy(
                       router->addr, router->or_port, authdir_invalid_policy);

    if (rej == ADDR_POLICY_PROBABLY_REJECTED || rej == ADDR_POLICY_REJECTED) {
      log_fn(LOG_INFO, "Rejecting '%s' because of address %s",
             router->nickname, router->address);
      if (msg)
        *msg = "Authdir is rejecting routers in this range.";
      return FP_REJECT;
    }
    if (inv == ADDR_POLICY_PROBABLY_REJECTED || inv == ADDR_POLICY_REJECTED) {
      log_fn(LOG_INFO, "Not marking '%s' valid because of address %s",
             router->nickname, router->address);
      return FP_INVALID;
    }
    if (tor_version_as_new_as(router->platform,"0.1.0.2-rc"))
      return FP_VALID;
    else
      return FP_INVALID;
    log_fn(LOG_INFO,"No fingerprint found for '%s'",router->nickname);
    return 0;
  }
  if (0==strcasecmp(nn_ent->fingerprint, fp)) {
    log_fn(LOG_DEBUG,"Good fingerprint for '%s'",router->nickname);
    return FP_NAMED; /* Right fingerprint. */
  } else {
    log_fn(LOG_WARN,"Mismatched fingerprint for '%s': expected '%s' got '%s'. ContactInfo '%s', platform '%s'.)",
           router->nickname, nn_ent->fingerprint, fp,
           router->contact_info ? router->contact_info : "",
           router->platform ? router->platform : "");
    if (msg)
      *msg = "Rejected: There is already a verified server with this nickname and a different fingerprint.";
    return FP_REJECT; /* Wrong fingerprint. */
  }
}

/** If we are an authoritative dirserver, and the list of approved
 * servers contains one whose identity key digest is <b>digest</b>,
 * return that router's nickname.  Otherwise return NULL. */
const char *
dirserv_get_nickname_by_digest(const char *digest)
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

/** Clear the current fingerprint list. */
void
dirserv_free_fingerprint_list(void)
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

static smartlist_t *
get_descriptor_list(void)
{
  routerlist_t *routerlist;
  router_get_routerlist(&routerlist);
  if (!routerlist)
    return NULL;
  return routerlist->routers;
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

/** Check whether we, as a directory server, want to accept <b>ri</b>.  If so,
 * return 0, and set its is_valid,named,running fields.  Otherwise, return -1.
 *
 * If the router is rejected, set *<b>msg</b> to an explanation of why.
 */
int
authdir_wants_to_reject_router(routerinfo_t *ri,
                               const char **msg)
{
  /* Okay.  Now check whether the fingerprint is recognized. */
  router_status_t status = dirserv_router_get_status(ri, msg);
  time_t now;
  tor_assert(msg);
  if (status == FP_REJECT)
    return -1; /* msg is already set. */

  /* Is there too much clock skew? */
  now = time(NULL);
  if (ri->published_on > now+ROUTER_ALLOW_SKEW) {
    log_fn(LOG_NOTICE, "Publication time for nickname '%s' is too far (%d minutes) in the future; possible clock skew. Not adding (ContactInfo '%s', platform '%s').",
           ri->nickname, (int)((ri->published_on-now)/60),
           ri->contact_info ? ri->contact_info : "",
           ri->platform ? ri->platform : "");
    *msg = "Rejected: Your clock is set too far in the future, or your timezone is not correct.";
    return -1;
  }
  if (ri->published_on < now-ROUTER_MAX_AGE) {
    log_fn(LOG_NOTICE, "Publication time for router with nickname '%s' is too far (%d minutes) in the past. Not adding (ContactInfo '%s', platform '%s').",
           ri->nickname, (int)((now-ri->published_on)/60),
           ri->contact_info ? ri->contact_info : "",
           ri->platform ? ri->platform : "");
    *msg = "Rejected: Server is expired, or your clock is too far in the past, or your timezone is not correct.";
    return -1;
  }
  if (dirserv_router_has_valid_address(ri) < 0) {
    log_fn(LOG_NOTICE, "Router with nickname '%s' has invalid address '%s'. Not adding (ContactInfo '%s', platform '%s').",
           ri->nickname, ri->address,
           ri->contact_info ? ri->contact_info : "",
           ri->platform ? ri->platform : "");
    *msg = "Rejected: Address is not an IP, or IP is a private address.";
    return -1;
  }
  /* Okay, looks like we're willing to accept this one. */
  switch (status) {
    case FP_NAMED:
      ri->is_named = ri->is_verified = 1;
      break;
    case FP_VALID:
      ri->is_named = 0;
      ri->is_verified = 1;
      break;
    case FP_INVALID:
      ri->is_named = ri->is_verified = 0;
      break;
    default:
      tor_assert(0);
  }

  return 0;
}

/** Parse the server descriptor at <b>desc</b> and maybe insert it into
 * the list of server descriptors. Set *<b>msg</b> to a message that
 * should be passed back to the origin of this descriptor.
 *
 * Return 2 if descriptor is well-formed and accepted;
 *  1 if well-formed and accepted but origin should hear *msg;
 *  0 if well-formed but redundant with one we already have;
 * -1 if it looks vaguely like a router descriptor but rejected;
 * -2 if we can't find a router descriptor in <b>desc</b>.
 */
int
dirserv_add_descriptor(const char *desc, const char **msg)
{
  int r;
  routerinfo_t *ri = NULL, *ri_old = NULL;
  tor_assert(msg);
  *msg = NULL;

  /* Check: is the descriptor syntactically valid? */
  ri = router_parse_entry_from_string(desc, NULL);
  if (!ri) {
    log(LOG_WARN, "Couldn't parse descriptor");
    *msg = "Rejected: Couldn't parse server descriptor.";
    return -2;
  }
  /* Check whether this descriptor is semantically identical to the last one
   * from this server.  (We do this here and not in router_add_to_routerlist
   * because we want to be able to accept the newest router descriptor that
   * another authority has, so we all converge on the same one.) */
  ri_old = router_get_by_digest(ri->identity_digest);
  if (ri_old && ri_old->published_on < ri->published_on &&
      router_differences_are_cosmetic(ri_old, ri)) {
    log_fn(LOG_INFO,
           "Not replacing descriptor from '%s'; differences are cosmetic.",
           ri->nickname);
    *msg = "Not replacing router descriptor; no information has changed since the last one with this identity.";
    return 0;
  }
  if ((r = router_add_to_routerlist(ri, msg, 0))<0) {
    return r == -1 ? 0 : -1;
  } else {
    smartlist_t *changed = smartlist_create();
    smartlist_add(changed, ri);
    control_event_descriptors_changed(changed);
    smartlist_free(changed);
    if (!*msg) {
      *msg =  ri->is_verified ? "Verified server descriptor accepted" :
        "Unverified server descriptor accepted";
    }
    return r == 0 ? 2 : 1;
  }
}

/** Remove all descriptors whose nicknames or fingerprints no longer
 * are allowed by our fingerprint list. (Descriptors that used to be
 * good can become bad when we reload the fingerprint list.)
 */
static void
directory_remove_invalid(void)
{
  int i;
  int changed = 0;
  smartlist_t *descriptor_list = get_descriptor_list();

  if (!descriptor_list)
    return;

  for (i = 0; i < smartlist_len(descriptor_list); ++i) {
    const char *msg;
    routerinfo_t *ent = smartlist_get(descriptor_list, i);
    router_status_t r = dirserv_router_get_status(ent, &msg);
    switch (r) {
      case FP_REJECT:
        log(LOG_INFO, "Router '%s' is now rejected: %s",
            ent->nickname, msg?msg:"");
        routerinfo_free(ent);
        smartlist_del(descriptor_list, i--);
        changed = 1;
        break;
      case FP_NAMED:
        if (!ent->is_verified || !ent->is_named) {
          log(LOG_INFO, "Router '%s' is now verified and named.", ent->nickname);
          ent->is_verified = ent->is_named = 1;
          changed = 1;
        }
        break;
      case FP_VALID:
        if (!ent->is_verified || ent->is_named) {
          log(LOG_INFO, "Router '%s' is now verified.", ent->nickname);
          ent->is_verified = 1;
          ent->is_named = 0;
          changed = 1;
        }
        break;
      case FP_INVALID:
        if (ent->is_verified || ent->is_named) {
          log(LOG_INFO, "Router '%s' is no longer verified.", ent->nickname);
          ent->is_verified = ent->is_named = 0;
          changed = 1;
        }
        break;
    }
  }
  if (changed)
    directory_set_dirty();
}

/** Write a list of unregistered descriptors into a newly allocated
 * string and return it. Used by dirserv operators to keep track of
 * fast nodes that haven't registered.
 */
char *
dirserver_getinfo_unregistered(const char *question)
{
  int i;
  router_status_t r;
  smartlist_t *answerlist;
  char buf[1024];
  char *answer;
  routerinfo_t *ent;
  int min_bw = atoi(question);
  smartlist_t *descriptor_list = get_descriptor_list();

  if (!descriptor_list)
    return tor_strdup("");

  answerlist = smartlist_create();
  for (i = 0; i < smartlist_len(descriptor_list); ++i) {
    ent = smartlist_get(descriptor_list, i);
    r = dirserv_router_get_status(ent, NULL);
    if (ent->bandwidthcapacity >= (size_t)min_bw &&
        ent->bandwidthrate >= (size_t)min_bw &&
        r != FP_NAMED) {
      /* then log this one */
      tor_snprintf(buf, sizeof(buf),
                   "%s: BW %d on '%s'.",
                   ent->nickname, ent->bandwidthcapacity,
                   ent->platform ? ent->platform : "");
      smartlist_add(answerlist, tor_strdup(buf));
    }
  }
  answer = smartlist_join_strings(answerlist, "\r\n", 0, NULL);
  SMARTLIST_FOREACH(answerlist, char *, cp, tor_free(cp));
  smartlist_free(answerlist);
  return answer;
}

/** Mark the directory as <b>dirty</b> -- when we're next asked for a
 * directory, we will rebuild it instead of reusing the most recently
 * generated one.
 */
void
directory_set_dirty(void)
{
  time_t now = time(NULL);

  if (!the_directory_is_dirty)
    the_directory_is_dirty = now;
  if (!runningrouters_is_dirty)
    runningrouters_is_dirty = now;
  if (!the_v2_networkstatus_is_dirty)
    the_v2_networkstatus_is_dirty = now;
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

#define REACHABLE_TIMEOUT (60*60) /* an hour */
/* Make sure this is 3 times the value of get_dir_fetch_period() */

/** Treat a router as alive if
 *    - It's me, and I'm not hibernating.
 * or - we're connected to it and we've found it reachable recently. */
static int
dirserv_thinks_router_is_reachable(routerinfo_t *router, time_t now)
{
  connection_t *conn;
  if (router_is_me(router) && !we_are_hibernating())
    return 1;
  conn = connection_get_by_identity_digest(router->identity_digest,
                                           CONN_TYPE_OR);
  if (conn && conn->state == OR_CONN_STATE_OPEN)
    return get_options()->AssumeReachable ||
           now < router->last_reachable + REACHABLE_TIMEOUT;
  return 0;
}

/** Return 1 if we're confident that there's a problem with
 * <b>router</b>'s reachability and its operator should be notified.
 */
int
dirserv_thinks_router_is_blatantly_unreachable(routerinfo_t *router, time_t now)
{
  connection_t *conn;
  if (router->is_hibernating)
    return 0;
  conn = connection_get_by_identity_digest(router->identity_digest,
                                           CONN_TYPE_OR);
  if (conn && conn->state == OR_CONN_STATE_OPEN &&
      now >= router->last_reachable + 2*REACHABLE_TIMEOUT &&
      router->testing_since &&
      now >= router->testing_since + 2*REACHABLE_TIMEOUT)
    return 1;
  return 0;
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
  time_t now = time(NULL);
  int authdir_mode = get_options()->AuthoritativeDir;
  tor_assert(router_status_out);

  rs_entries = smartlist_create();

  SMARTLIST_FOREACH(routers, routerinfo_t *, ri,
  {
    if (authdir_mode) {
      /* Update router status in routerinfo_t. */
      ri->is_running = dirserv_thinks_router_is_reachable(ri, now);
    }
    smartlist_add(rs_entries, list_single_server_status(ri, ri->is_running));
  });

  *router_status_out = smartlist_join_strings(rs_entries, " ", 0, NULL);

  SMARTLIST_FOREACH(rs_entries, char *, cp, tor_free(cp));
  smartlist_free(rs_entries);

  return 0;
}

/** Helper: Given pointers to two strings describing tor versions, return -1
 * if _a precedes _b, 1 if _b preceeds _a, and 0 if they are equivalent.
 * Used to sort a list of versions. */
static int
_compare_tor_version_str_ptr(const void **_a, const void **_b)
{
  const char *a = *_a, *b = *_b;
  int ca, cb;
  tor_version_t va, vb;
  ca = tor_version_parse(a, &va);
  cb = tor_version_parse(b, &vb);
  /* If they both parse, compare them. */
  if (!ca && !cb)
    return tor_version_compare(&va,&vb);
  /* If one parses, it comes first. */
  if (!ca && cb)
    return -1;
  if (ca && !cb)
    return 1;
  /* If neither parses, compare strings.  Also, the directory server admin needs
  ** to be smacked upside the head.  But Tor is tolerant and gentle. */
  return strcmp(a,b);
}

/* Given a (possibly empty) list of config_line_t, each line of which contains
 * a list of comma-separated version numbers surrounded by optional space,
 * allocate and return a new string containing the version numbers, in order,
 * separated by commas.  Used to generate Recommended(Client|Server)?Versions
 */
static char *
format_versions_list(config_line_t *ln)
{
  smartlist_t *versions;
  char *result;
  versions = smartlist_create();
  for ( ; ln; ln = ln->next) {
    smartlist_split_string(versions, ln->value, ",",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  }
  smartlist_sort(versions, _compare_tor_version_str_ptr);
  result = smartlist_join_strings(versions,",",0,NULL);
  SMARTLIST_FOREACH(versions,char *,s,tor_free(s));
  smartlist_free(versions);
  return result;
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
  char digest[DIGEST_LEN];
  char published[ISO_TIME_LEN+1];
  time_t published_on;
  char *buf = NULL;
  size_t buf_len;
  size_t identity_pkey_len;
  smartlist_t *descriptor_list = get_descriptor_list();

  tor_assert(dir_out);
  *dir_out = NULL;

  if (!descriptor_list)
    return -1;

  if (list_server_status(descriptor_list, &router_status))
    return -1;

  if (crypto_pk_write_public_key_to_string(private_key,&identity_pkey,
                                           &identity_pkey_len)<0) {
    log_fn(LOG_WARN,"write identity_pkey to string failed!");
    return -1;
  }

  recommended_versions = format_versions_list(get_options()->RecommendedVersions);

  published_on = time(NULL);
  format_iso_time(published, published_on);

  buf_len = 2048+strlen(recommended_versions)+
    strlen(router_status);
  SMARTLIST_FOREACH(descriptor_list, routerinfo_t *, ri,
                    buf_len += ri->signed_descriptor_len+1);
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

  cp = buf + strlen(buf);
  SMARTLIST_FOREACH(descriptor_list, routerinfo_t *, ri,
    {
      if (cp+ri->signed_descriptor_len+1 >= buf+buf_len)
        goto truncated;
      memcpy(cp, ri->signed_descriptor, ri->signed_descriptor_len);
      cp += ri->signed_descriptor_len;
      *cp++ = '\n'; /* add an extra newline in case somebody was depending on
                     * it. */
    });
  *cp = '\0';

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
  if (router_append_dirobj_signature(buf,buf_len,digest,private_key)<0) {
    tor_free(buf);
    return -1;
  }

  *dir_out = buf;
  return 0;
 truncated:
  log_fn(LOG_WARN,"tried to exceed string length.");
  tor_free(buf);
  return -1;
}

/** Most recently generated encoded signed directory. (auth dirservers only.)*/
static cached_dir_t the_directory = { NULL, NULL, 0, 0, 0 };

/* Used only by non-auth dirservers: The directory and runningrouters we'll
 * serve when requested. */
static cached_dir_t cached_directory = { NULL, NULL, 0, 0, 0 };
static cached_dir_t cached_runningrouters = { NULL, NULL, 0, 0, 0 };

/* Used for other dirservers' v2 network statuses.  Map from hexdigest to
 * cached_dir_t. */
static strmap_t *cached_v2_networkstatus = NULL;

/** Possibly replace the contents of <b>d</b> with the value of
 * <b>directory</b> published on <b>when</b>, unless <b>when</b> is older than
 * the last value, or too far in the future.
 *
 * Does not copy <b>directory</b>; free it if it isn't used.
 */
static void
set_cached_dir(cached_dir_t *d, char *directory, time_t when)
{
  time_t now = time(NULL);
  if (when<=d->published) {
    log_fn(LOG_INFO, "Ignoring old directory; not caching.");
    tor_free(directory);
  } else if (when>=now+ROUTER_MAX_AGE) {
    log_fn(LOG_INFO, "Ignoring future directory; not caching.");
    tor_free(directory);
  } else {
    /* if (when>d->published && when<now+ROUTER_MAX_AGE) */
    log_fn(LOG_DEBUG, "Caching directory.");
    tor_free(d->dir);
    d->dir = directory;
    d->dir_len = strlen(directory);
    tor_free(d->dir_z);
    if (tor_gzip_compress(&(d->dir_z), &(d->dir_z_len), d->dir, d->dir_len,
                          ZLIB_METHOD)) {
      log_fn(LOG_WARN,"Error compressing cached directory");
    }
    d->published = when;
  }
}

/** Remove all storage held in <b>d</b>, but do not free <b>d</b> itself. */
static void
clear_cached_dir(cached_dir_t *d)
{
  tor_free(d->dir);
  tor_free(d->dir_z);
  memset(d, 0, sizeof(cached_dir_t));
}

/** Free all storage held by the cached_dir_t in <b>d</b>. */
static void
free_cached_dir(void *_d)
{
  cached_dir_t *d = (cached_dir_t *)_d;
  clear_cached_dir(d);
  tor_free(d);
}

/** If we have no cached directory, or it is older than <b>when</b>, then
 * replace it with <b>directory</b>, published at <b>when</b>.
 */
void
dirserv_set_cached_directory(const char *directory, time_t published,
                             int is_running_routers)
{
  cached_dir_t *d;
  d = is_running_routers ? &cached_runningrouters : &cached_directory;
  set_cached_dir(d, tor_strdup(directory), published);
}

/** We've just received a v2 network-status for an authoritative directory
 * with fingerprint <b>fp</b> (hex digest, no spaces), published at
 * <b>published</b>.  Store it so we can serve it to others.  If
 * <b>directory</b> is NULL, remove the entry with the given fingerprint from
 * the cache.
 */
void
dirserv_set_cached_networkstatus_v2(const char *directory, const char *fp,
                                    time_t published)
{
  cached_dir_t *d;
  if (!cached_v2_networkstatus)
    cached_v2_networkstatus = strmap_new();

  tor_assert(strlen(fp) == HEX_DIGEST_LEN);

  if (!(d = strmap_get(cached_v2_networkstatus, fp))) {
    if (!directory)
      return;
    d = tor_malloc_zero(sizeof(cached_dir_t));
    strmap_set(cached_v2_networkstatus, fp, d);
  }

  tor_assert(d);
  if (directory) {
    set_cached_dir(d, tor_strdup(directory), published);
  } else {
    free_cached_dir(d);
    strmap_remove(cached_v2_networkstatus, fp);
  }
}

/** Helper: If we're an authority for the right directory version (the
 * directory version is determined by <b>is_v1_object</b>), try to regenerate
 * auth_src as appropriate and return it, falling back to cache_src on
 * failure.  If we're a cache, return cach_src.
 */
static cached_dir_t *
dirserv_pick_cached_dir_obj(cached_dir_t *cache_src,
                            cached_dir_t *auth_src,
                            time_t dirty, int (*regenerate)(void),
                            const char *name,
                            int is_v1_object)
{
  int authority = get_options()->AuthoritativeDir &&
    (!is_v1_object || get_options()->V1AuthoritativeDir);

  if (!authority) {
    return cache_src;
  } else {
    /* We're authoritative. */
    if (regenerate != NULL) {
      if (dirty && dirty + DIR_REGEN_SLACK_TIME < time(NULL)) {
        if (regenerate()) {
          log_fn(LOG_ERR, "Couldn't generate %s?", name);
          exit(1);
        }
      } else {
        log_fn(LOG_INFO, "The %s is still clean; reusing.", name);
      }
    }
    return auth_src ? auth_src : cache_src;
  }
}

/** Helper: If we're authoritative and <b>auth_src</b> is set, use
 * <b>auth_src</b>, otherwise use <b>cache_src</b>.  If we're using
 * <b>auth_src</b> and it's been <b>dirty</b> for at least
 * DIR_REGEN_SLACK_TIME seconds, call <b>regenerate</b>() to make a fresh one.
 * Yields the compressed version of the directory object if <b>compress</b> is
 * set; otherwise return the uncompressed version.  (In either case, sets
 * *<b>out</b> and returns the size of the buffer in *<b>out</b>.)
 *
 * Use <b>is_v1_object</b> to help determine whether we're authoritative for
 * this kind of object.
 **/
static size_t
dirserv_get_obj(const char **out, int compress,
                cached_dir_t *cache_src,
                cached_dir_t *auth_src,
                time_t dirty, int (*regenerate)(void),
                const char *name,
                int is_v1_object)
{
  cached_dir_t *d = dirserv_pick_cached_dir_obj(
      cache_src, auth_src,
      dirty, regenerate, name, is_v1_object);

  if (!d)
    return 0;
  *out = compress ? d->dir_z : d->dir;
  if (*out) {
    return compress ? d->dir_z_len : d->dir_len;
  } else {
    /* not yet available. */
    return 0;
  }
}

/** Set *<b>directory</b> to the most recently generated encoded signed
 * directory, generating a new one as necessary.  If not an authoritative
 * directory may return 0 if no directory is yet cached.*/
size_t
dirserv_get_directory(const char **directory, int compress)
{
  return dirserv_get_obj(directory, compress,
                         &cached_directory, &the_directory,
                         the_directory_is_dirty,
                         dirserv_regenerate_directory,
                         "server directory", 1);
}

/**
 * Generate a fresh directory (authdirservers only.)
 */
static int
dirserv_regenerate_directory(void)
{
  char *new_directory=NULL;

  if (dirserv_dump_directory_to_string(&new_directory,
                                       get_identity_key())) {
    log(LOG_WARN, "Error creating directory.");
    tor_free(new_directory);
    return -1;
  }
  set_cached_dir(&the_directory, new_directory, time(NULL));
  log_fn(LOG_INFO,"New directory (size %d):\n%s",(int)the_directory.dir_len,
         the_directory.dir);

  the_directory_is_dirty = 0;

  /* Save the directory to disk so we re-load it quickly on startup.
   */
  dirserv_set_cached_directory(the_directory.dir, time(NULL), 0);

  return 0;
}

/** For authoritative directories: the current (v1) network status */
static cached_dir_t the_runningrouters = { NULL, NULL, 0, 0, 0 };

/** Replace the current running-routers list with a newly generated one. */
static int
generate_runningrouters(void)
{
  char *s=NULL;
  char *router_status=NULL;
  char digest[DIGEST_LEN];
  char published[ISO_TIME_LEN+1];
  size_t len;
  crypto_pk_env_t *private_key = get_identity_key();
  char *identity_pkey; /* Identity key, DER64-encoded. */
  size_t identity_pkey_len;
  smartlist_t *descriptor_list = get_descriptor_list();

  if (list_server_status(descriptor_list, &router_status)) {
    goto err;
  }
  if (crypto_pk_write_public_key_to_string(private_key,&identity_pkey,
                                           &identity_pkey_len)<0) {
    log_fn(LOG_WARN,"write identity_pkey to string failed!");
    goto err;
  }
  format_iso_time(published, time(NULL));

  len = 2048+strlen(router_status);
  s = tor_malloc_zero(len);
  tor_snprintf(s, len,
               "network-status\n"
               "published %s\n"
               "router-status %s\n"
               "dir-signing-key\n%s"
               "directory-signature %s\n",
               published, router_status, identity_pkey, get_options()->Nickname);
  tor_free(router_status);
  tor_free(identity_pkey);
  if (router_get_runningrouters_hash(s,digest)) {
    log_fn(LOG_WARN,"couldn't compute digest");
    goto err;
  }
  if (router_append_dirobj_signature(s, len, digest, private_key)<0)
    goto err;

  set_cached_dir(&the_runningrouters, s, time(NULL));
  runningrouters_is_dirty = 0;

  return 0;
 err:
  tor_free(s);
  tor_free(router_status);
  return -1;
}

/** Set *<b>rr</b> to the most recently generated encoded signed
 * running-routers list, generating a new one as necessary.  Return the
 * size of the directory on success, and 0 on failure. */
size_t
dirserv_get_runningrouters(const char **rr, int compress)
{
  return dirserv_get_obj(rr, compress,
                         &cached_runningrouters, &the_runningrouters,
                         runningrouters_is_dirty,
                         generate_runningrouters,
                         "v1 network status list", 1);
}

/** Return true iff <b>ri</b> is "useful as an exit node", meaning
 * it allows exit to at least one /8 address space for at least
 * one of ports 80, 443, and 6667. */
static int
router_is_general_exit(routerinfo_t *ri)
{
  static const int ports[] = { 80, 443, 6667 };
  int n_allowed = 0;
  int i;
  for (i = 0; i < 3; ++i) {
    struct addr_policy_t *policy = ri->exit_policy;
    for ( ; policy; policy = policy->next) {
      if (policy->prt_min > ports[i] || policy->prt_max < ports[i])
        continue; /* Doesn't cover our port. */
      if ((policy->msk & 0x00fffffful) != 0)
        continue; /* Narrower than a /8. */
      if ((policy->addr & 0xff000000ul) == 0x7f000000ul)
        continue; /* 127.x */
      /* We have a match that is at least a /8. */
      if (policy->policy_type == ADDR_POLICY_ACCEPT)
        ++n_allowed;
      break;
    }
  }
  return n_allowed > 0;
}

/** For authoritative directories: the current (v2) network status */
static cached_dir_t the_v2_networkstatus = { NULL, NULL, 0, 0, 0 };

/** For authoritative directories only: replace the contents of
 * <b>the_v2_networkstatus</b> with a newly generated network status
 * object. */
static int
generate_v2_networkstatus(void)
{
#define LONGEST_STATUS_FLAG_NAME_LEN 7
#define N_STATUS_FLAGS 6
#define RS_ENTRY_LEN                                                    \
  ( /* first line */                                                    \
   MAX_NICKNAME_LEN+BASE64_DIGEST_LEN*2+ISO_TIME_LEN+INET_NTOA_BUF_LEN+ \
   5*2 /* ports */ + 10 /* punctuation */ +                             \
   /* second line */                                                    \
   (LONGEST_STATUS_FLAG_NAME_LEN+1)*N_STATUS_FLAGS + 2)

  int r = -1;
  size_t len, identity_pkey_len;
  char *status = NULL, *client_versions = NULL, *server_versions = NULL,
    *identity_pkey = NULL, *hostname = NULL;
  char *outp, *endp;
  or_options_t *options = get_options();
  char fingerprint[FINGERPRINT_LEN+1];
  char ipaddr[INET_NTOA_BUF_LEN+1];
  char published[ISO_TIME_LEN];
  char digest[DIGEST_LEN];
  struct in_addr in;
  uint32_t addr;
  crypto_pk_env_t *private_key = get_identity_key();
  smartlist_t *descriptor_list = get_descriptor_list();
  time_t now = time(NULL);
  int naming = options->NamingAuthoritativeDir;
  int versioning = options->VersioningAuthoritativeDir;
  const char *contact;

  if (!descriptor_list) {
    log_fn(LOG_WARN, "Couldn't get router list.");
    goto done;
  }

  if (resolve_my_address(options, &addr, &hostname)<0) {
    log_fn(LOG_WARN, "Couldn't resolve my hostname");
    goto done;
  }
  in.s_addr = htonl(addr);
  tor_inet_ntoa(&in, ipaddr, sizeof(ipaddr));

  format_iso_time(published, time(NULL));

  client_versions = format_versions_list(options->RecommendedClientVersions);
  server_versions = format_versions_list(options->RecommendedServerVersions);

  if (crypto_pk_write_public_key_to_string(private_key, &identity_pkey,
                                           &identity_pkey_len)<0) {
    log_fn(LOG_WARN,"Writing public key to string failed.");
    goto done;
  }

  if (crypto_pk_get_fingerprint(private_key, fingerprint, 0)<0) {
    log_fn(LOG_ERR, "Error computing fingerprint");
    goto done;
  }

  contact = get_options()->ContactInfo;
  if (!contact)
    contact = "(none)";

  len = 2048+strlen(client_versions)+strlen(server_versions)+identity_pkey_len*2;
  len += (RS_ENTRY_LEN)*smartlist_len(descriptor_list) ;

  status = tor_malloc(len);
  tor_snprintf(status, len,
               "network-status-version 2\n"
               "dir-source %s %s %d\n"
               "fingerprint %s\n"
               "contact %s\n"
               "published %s\n"
               "dir-options%s%s\n"
               "client-versions %s\n"
               "server-versions %s\n"
               "dir-signing-key\n%s\n",
               hostname, ipaddr, (int)options->DirPort,
               fingerprint,
               contact,
               published,
               naming ? " Names" : "",
               versioning ? " Versions" : "",
               client_versions,
               server_versions,
               identity_pkey);
  outp = status + strlen(status);
  endp = status + len;

  SMARTLIST_FOREACH(descriptor_list, routerinfo_t *, ri, {
      int f_exit = router_is_general_exit(ri);
      int f_stable = !router_is_unreliable(ri, 1, 0);
      int f_fast = !router_is_unreliable(ri, 0, 1);
      int f_running;
      int f_authority = router_digest_is_trusted_dir(ri->identity_digest);
      int f_named = naming && ri->is_named;
      int f_valid = ri->is_verified;
      char identity64[BASE64_DIGEST_LEN+1];
      char digest64[BASE64_DIGEST_LEN+1];
      if (options->AuthoritativeDir) {
        ri->is_running = dirserv_thinks_router_is_reachable(ri, now);
      }
      f_running = ri->is_running;

      format_iso_time(published, ri->published_on);

      digest_to_base64(identity64, ri->identity_digest);
      digest_to_base64(digest64, ri->signed_descriptor_digest);

      in.s_addr = htonl(ri->addr);
      tor_inet_ntoa(&in, ipaddr, sizeof(ipaddr));

      if (tor_snprintf(outp, endp-outp,
                       "r %s %s %s %s %s %d %d\n"
                       "s%s%s%s%s%s%s%s\n",
                       ri->nickname,
                       identity64,
                       digest64,
                       published,
                       ipaddr,
                       ri->or_port,
                       ri->dir_port,
                       f_authority?" Authority":"",
                       f_exit?" Exit":"",
                       f_fast?" Fast":"",
                       f_named?" Named":"",
                       f_stable?" Stable":"",
                       f_running?" Running":"",
                       f_valid?" Valid":"")<0) {
        log_fn(LOG_WARN, "Unable to print router status.");
        goto done;
        }
      outp += strlen(outp);
    });

  if (tor_snprintf(outp, endp-outp, "directory-signature %s\n",
                   get_options()->Nickname)<0) {
    log_fn(LOG_WARN, "Unable to write signature line.");
    goto done;
  }

  if (router_get_networkstatus_v2_hash(status, digest)<0) {
    log_fn(LOG_WARN, "Unable to hash network status");
    goto done;
  }

  if (router_append_dirobj_signature(outp,endp-outp,digest,private_key)<0) {
    log_fn(LOG_WARN, "Unable to sign router status.");
    goto done;
  }

  set_cached_dir(&the_v2_networkstatus, status, time(NULL));
  status = NULL; /* So it doesn't get double-freed. */
  the_v2_networkstatus_is_dirty = 0;
  router_set_networkstatus(the_v2_networkstatus.dir, time(NULL), NS_GENERATED,
                           NULL);

  r = 0;
 done:
  tor_free(client_versions);
  tor_free(server_versions);
  tor_free(status);
  tor_free(hostname);
  tor_free(identity_pkey);
  return r;
}

/** Look for a network status object as specified by <b>key</b>, which should
 * be either "authority" (to find a network status generated by us), a hex
 * identity digest (to find a network status generated by given directory), or
 * "all" (to return all the v2 network status objects we have, concatenated).
 * If <b>compress</b>, find the version compressed with zlib.  Return 0 if
 * nothing was found; otherwise set *<b>directory</b> to the matching network
 * status and return its length.
 */
int
dirserv_get_networkstatus_v2(smartlist_t *result,
                             const char *key)
{
  tor_assert(result);

  if (!cached_v2_networkstatus)
    cached_v2_networkstatus = strmap_new();

  if (!(strcmp(key,"authority"))) {
    if (get_options()->AuthoritativeDir) {
      cached_dir_t *d =
        dirserv_pick_cached_dir_obj(NULL,
                                    &the_v2_networkstatus,
                                    the_v2_networkstatus_is_dirty,
                                    generate_v2_networkstatus,
                                    "network status list", 0);
      log_fn(LOG_WARN, "Unable to generate an authoritative network stautus.");
      if (d)
        smartlist_add(result, d);
    }
  } else if (!strcmp(key, "all")) {
    strmap_iter_t *iter = strmap_iter_init(cached_v2_networkstatus);
    while (!strmap_iter_done(iter)) {
      const char *fp;
      void *val;
      strmap_iter_get(iter, &fp, &val);
      smartlist_add(result, val);
      iter = strmap_iter_next(cached_v2_networkstatus, iter);
    }
    if (smartlist_len(result) == 0)
      log_fn(LOG_WARN, "Client requested 'all' network status objects; we have none.");
  } else if (!strcmpstart(key, "fp/")) {
    smartlist_t *hexdigests = smartlist_create();
    dir_split_resource_into_fingerprints(key+3, hexdigests, NULL, 0);
    SMARTLIST_FOREACH(hexdigests, char *, cp,
        {
          cached_dir_t *cached;
          tor_strupper(cp);
          if (router_fingerprint_is_me(cp) &&
              get_options()->AuthoritativeDir &&
              the_v2_networkstatus_is_dirty &&
              the_v2_networkstatus_is_dirty + DIR_REGEN_SLACK_TIME < time(NULL))
            generate_v2_networkstatus();
          cached = strmap_get(cached_v2_networkstatus, cp);
          if (cached) {
            smartlist_add(result, cached);
          } else {
            log_fn(LOG_INFO, "Don't know about any network status with fingerprint '%s'", cp);
          }
          tor_free(cp);
        });
    smartlist_free(hexdigests);
  }
  return 0;
}

/** Add a routerinfo_t to <b>descs_out</b> for each router matching
 * <b>key</b>.  The key should be either "/tor/server/authority" for our own
 * routerinfo; "/tor/server/all" for all the routerinfos we have,
 * concatenated; or "/tor/server/FP" where FP is a plus-separated sequence of
 * hex identity digests.
 */
void
dirserv_get_routerdescs(smartlist_t *descs_out, const char *key)
{
  smartlist_t *complete_list = get_descriptor_list();
  if (!complete_list)
    return;

  if (!strcmp(key, "/tor/server/all")) {
    smartlist_add_all(descs_out, complete_list);
  } else if (!strcmp(key, "/tor/server/authority")) {
    routerinfo_t *ri = router_get_my_routerinfo();
    if (ri)
      smartlist_add(descs_out, ri);
  } else if (!strcmpstart(key, "/tor/server/d/")) {
    smartlist_t *digests = smartlist_create();
    dir_split_resource_into_fingerprints(key, digests, NULL, 1);
    key += strlen("/tor/server/d/");
    SMARTLIST_FOREACH(digests, const char *, d,
       {
         routerinfo_t *ri = router_get_by_descriptor_digest(d);
         if (ri)
           smartlist_add(descs_out,ri);
       });
    SMARTLIST_FOREACH(digests, char *, d, tor_free(d));
    smartlist_free(digests);
  } else if (!strcmpstart(key, "/tor/server/fp/")) {
    smartlist_t *digests = smartlist_create();
    key += strlen("/tor/server/fp/");
    dir_split_resource_into_fingerprints(key, digests, NULL, 1);
    SMARTLIST_FOREACH(digests, const char *, d,
       {
         if (router_digest_is_me(d)) {
           smartlist_add(descs_out, router_get_my_routerinfo());
         } else {
           routerinfo_t *ri = router_get_by_digest(d);
           if (ri)
             smartlist_add(descs_out,ri);
         }
       });
    SMARTLIST_FOREACH(digests, char *, d, tor_free(d));
    smartlist_free(digests);
  }
}

/** Called when a TLS handshake has completed successfully with a
 * router listening at <b>address</b>:<b>or_port</b>, and has yielded
 * a certificate with digest <b>digest_rcvd</b> and nickname
 * <b>nickname_rcvd</b>.  When this happens, it's clear that any other
 * descriptors for that address/port combination must be unusable:
 * delete them if they are not verified.
 *
 * Also, if as_advertised is 1, then inform the reachability checker
 * that we could get to this guy.
 */
void
dirserv_orconn_tls_done(const char *address,
                        uint16_t or_port,
                        const char *digest_rcvd,
                        const char *nickname_rcvd,
                        int as_advertised)
{
  int i;
  smartlist_t *descriptor_list = get_descriptor_list();
  tor_assert(address);
  tor_assert(digest_rcvd);
  tor_assert(nickname_rcvd);

  if (!descriptor_list)
    return;

  // XXXXNM We should really have a better solution here than dropping
  // XXXXNM whole routers; otherwise, they come back way too easily.
  for (i = 0; i < smartlist_len(descriptor_list); ++i) {
    routerinfo_t *ri = smartlist_get(descriptor_list, i);
    int drop = 0;
    if (strcasecmp(address, ri->address) || or_port != ri->or_port)
      continue;
    if (!ri->is_verified) {
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
    }
    if (drop) {
      routerinfo_free(ri);
      smartlist_del(descriptor_list, i--);
      directory_set_dirty();
    } else { /* correct nickname and digest. mark this router reachable! */
      log_fn(LOG_INFO,"Found router %s to be reachable. Yay.", ri->nickname);
      ri->last_reachable = time(NULL);
      ri->num_unreachable_notifications = 0;
    }
  }
}

/** Release all storage used by the directory server. */
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
  if (authdir_reject_policy)
    addr_policy_free(authdir_reject_policy);
  if (authdir_invalid_policy)
    addr_policy_free(authdir_invalid_policy);
  clear_cached_dir(&the_directory);
  clear_cached_dir(&the_runningrouters);
  clear_cached_dir(&cached_directory);
  clear_cached_dir(&cached_runningrouters);
  if (cached_v2_networkstatus) {
    strmap_free(cached_v2_networkstatus, free_cached_dir);
    cached_v2_networkstatus = NULL;
  }
}

