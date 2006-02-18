/* Copyright 2001 Matej Pfajfar.
 * Copyright 2001-2004 Roger Dingledine.
 * Copyright 2004-2005 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char routerparse_c_id[] = "$Id$";

/**
 * \file routerparse.c
 *
 * \brief Code to parse and validate router descriptors and directories.
 **/

#include "or.h"

/****************************************************************************/

/** Enumeration of possible token types.  The ones starting with K_
 * correspond to directory 'keywords'.  _UNRECOGNIZED is for an
 * unrecognized keyword; _ERR is an error in the tokenizing process,
 * _EOF is an end-of-file marker, and _NIL is used to encode
 * not-a-token.
 */
typedef enum {
  K_ACCEPT,
  K_DIRECTORY_SIGNATURE,
  K_RECOMMENDED_SOFTWARE,
  K_REJECT,
  K_ROUTER,
  K_SIGNED_DIRECTORY,
  K_SIGNING_KEY,
  K_ONION_KEY,
  K_ROUTER_SIGNATURE,
  K_PUBLISHED,
  K_RUNNING_ROUTERS,
  K_ROUTER_STATUS,
  K_PLATFORM,
  K_OPT,
  K_BANDWIDTH,
  K_PORTS,
  K_CONTACT,
  K_NETWORK_STATUS,
  K_UPTIME,
  K_DIR_SIGNING_KEY,
  K_FAMILY,
  K_FINGERPRINT,
  K_HIBERNATING,
  K_READ_HISTORY,
  K_WRITE_HISTORY,
  _UNRECOGNIZED,
  _ERR,
  _EOF,
  _NIL
} directory_keyword;

/** Structure to hold a single directory token.
 *
 * We parse a directory by breaking it into "tokens", each consisting
 * of a keyword, a line full of arguments, and a binary object.  The
 * arguments and object are both optional, depending on the keyword
 * type.
 */
typedef struct directory_token_t {
  directory_keyword tp;        /**< Type of the token. */
  int n_args;                  /**< Number of elements in args */
  char **args;                 /**< Array of arguments from keyword line. */
  char *object_type;           /**< -----BEGIN [object_type]-----*/
  size_t object_size;             /**< Bytes in object_body */
  char *object_body;           /**< Contents of object, base64-decoded. */
  crypto_pk_env_t *key;        /**< For public keys only. */
  const char *error;           /**< For _ERR tokens only. */
} directory_token_t;

/* ********************************************************************** */

/** We use a table of rules to decide how to parse each token type. */

/** Rules for how many arguments a keyword can take. */
typedef enum {
  NO_ARGS,     /**<    (1) no arguments, ever */
  ARGS,        /**<    (2) a list of arguments separated by spaces */
  CONCAT_ARGS, /**< or (3) the rest of the line, treated as a single argument. */
} arg_syntax;

/** Rules for whether the keyword needs an object. */
typedef enum {
  NO_OBJ,      /**<    (1) no object, ever */
  NEED_OBJ,    /**<    (2) object is required */
  NEED_KEY,    /**<    (3) object is required, and must be a public key. */
  OBJ_OK,      /**< or (4) object is optional. */
} obj_syntax;

/** Rules for where a keyword can appear. */
typedef enum {
  ANY = 0,    /**< Appears in router descriptor or in directory sections. */
  DIR_ONLY,   /**< Appears only in directory. */
  RTR_ONLY,   /**< Appears only in router descriptor or runningrouters */
} where_syntax;

/** Table mapping keywords to token value and to argument rules. */
static struct {
  const char *t; int v; arg_syntax s; obj_syntax os; where_syntax ws;
} token_table[] = {
  { "accept",              K_ACCEPT,              ARGS,    NO_OBJ,  RTR_ONLY },
  { "directory-signature", K_DIRECTORY_SIGNATURE, ARGS,    NEED_OBJ,DIR_ONLY},
  { "reject",              K_REJECT,              ARGS,    NO_OBJ,  RTR_ONLY },
  { "router",              K_ROUTER,              ARGS,    NO_OBJ,  RTR_ONLY },
  { "recommended-software",K_RECOMMENDED_SOFTWARE,ARGS,    NO_OBJ,  DIR_ONLY },
  { "signed-directory",    K_SIGNED_DIRECTORY,    NO_ARGS, NO_OBJ,  DIR_ONLY },
  { "signing-key",         K_SIGNING_KEY,         NO_ARGS, NEED_KEY,RTR_ONLY },
  { "onion-key",           K_ONION_KEY,           NO_ARGS, NEED_KEY,RTR_ONLY },
  { "router-signature",    K_ROUTER_SIGNATURE,    NO_ARGS, NEED_OBJ,RTR_ONLY },
  { "running-routers",     K_RUNNING_ROUTERS,     ARGS,    NO_OBJ,  DIR_ONLY },
  { "router-status",       K_ROUTER_STATUS,       ARGS,    NO_OBJ,  DIR_ONLY },
  { "ports",               K_PORTS,               ARGS,    NO_OBJ,  RTR_ONLY },
  { "bandwidth",           K_BANDWIDTH,           ARGS,    NO_OBJ,  RTR_ONLY },
  { "platform",            K_PLATFORM,        CONCAT_ARGS, NO_OBJ,  RTR_ONLY },
  { "published",           K_PUBLISHED,       CONCAT_ARGS, NO_OBJ,  ANY },
  { "opt",                 K_OPT,             CONCAT_ARGS, OBJ_OK,  ANY },
  { "contact",             K_CONTACT,         CONCAT_ARGS, NO_OBJ,  ANY },
  { "network-status",      K_NETWORK_STATUS,      NO_ARGS, NO_OBJ,  DIR_ONLY },
  { "uptime",              K_UPTIME,              ARGS,    NO_OBJ,  RTR_ONLY },
  { "dir-signing-key",     K_DIR_SIGNING_KEY,     ARGS,    OBJ_OK,  DIR_ONLY },
  { "family",              K_FAMILY,              ARGS,    NO_OBJ,  RTR_ONLY },
  { "fingerprint",         K_FINGERPRINT,         ARGS,    NO_OBJ,  ANY },
  { "hibernating",         K_HIBERNATING,         ARGS,    NO_OBJ,  RTR_ONLY },
  { "read-history",        K_READ_HISTORY,        ARGS,    NO_OBJ,  RTR_ONLY },
  { "write-history",       K_WRITE_HISTORY,       ARGS,    NO_OBJ,  RTR_ONLY },
  { NULL, -1, NO_ARGS, NO_OBJ, ANY }
};

/* static function prototypes */
static int router_add_exit_policy(routerinfo_t *router,directory_token_t *tok);
static addr_policy_t *router_parse_addr_policy(directory_token_t *tok);
static int router_get_hash_impl(const char *s, char *digest,
                                const char *start_str, const char *end_str);
static void token_free(directory_token_t *tok);
static smartlist_t *find_all_exitpolicy(smartlist_t *s);
static directory_token_t *find_first_by_keyword(smartlist_t *s,
                                                directory_keyword keyword);
static int tokenize_string(const char *start, const char *end,
                           smartlist_t *out, int is_dir);
static directory_token_t *get_next_token(const char **s, where_syntax where);
static int check_directory_signature(const char *digest,
                                     directory_token_t *tok,
                                     crypto_pk_env_t *pkey,
                                     crypto_pk_env_t *declared_key);
static crypto_pk_env_t *find_dir_signing_key(const char *str);
/* static */ int is_obsolete_version(const char *myversion,
                                     const char *versionlist);
static int tor_version_same_series(tor_version_t *a, tor_version_t *b);

/** Set <b>digest</b> to the SHA-1 digest of the hash of the directory in
 * <b>s</b>.  Return 0 on success, nonzero on failure.
 */
int router_get_dir_hash(const char *s, char *digest)
{
  return router_get_hash_impl(s,digest,
                              "signed-directory","\ndirectory-signature");
}

/** Set <b>digest</b> to the SHA-1 digest of the hash of the first router in
 * <b>s</b>. Return 0 on success, nonzero on failure.
 */
int router_get_router_hash(const char *s, char *digest)
{
  return router_get_hash_impl(s,digest,
                              "router ","\nrouter-signature");
}

/** Set <b>digest</b> to the SHA-1 digest of the hash of the running-routers
 * string in <b>s</b>. Return 0 on success, nonzero on failure.
 */
int router_get_runningrouters_hash(const char *s, char *digest)
{
  return router_get_hash_impl(s,digest,
                              "network-status","\ndirectory-signature");
}

/**
 * Find the first instance of "recommended-software ...\n" at the start of
 * a line; return a newly allocated string containing the "..." portion.
 * Return NULL if no such instance was found.
 */
static char *
get_recommended_software_from_directory(const char *str)
{
#define REC "recommended-software "
  const char *cp = str, *eol;
  size_t len = strlen(REC);
  cp = str;
  if (strcmpstart(str, REC)==0) {
    cp += len;
  } else {
    cp = strstr(str, "\n"REC);
    if (!cp)
      return NULL;
    cp += len+1;
  }
  eol = strchr(cp, '\n');
  if (!eol)
    return NULL;
  return tor_strndup(cp, eol-cp);
#undef REC
}

/** Return 1 if <b>myversion</b> is not in <b>versionlist</b>, and if at least
 * one version of Tor on <b>versionlist</b> is newer than <b>myversion</b>.

 * Return 1 if no version from the same series as <b>myversion</b> is
 * in <b>versionlist</b> (and <b>myversion</b> is not the newest
 * version), or if a newer version from the same series is in
 * <b>versionlist</b>.
 *
 * Otherwise return 0.
 * (versionlist is a comma-separated list of version strings,
 * optionally prefixed with "Tor".  Versions that can't be parsed are
 * ignored.) */
/* static */ int is_obsolete_version(const char *myversion,
                           const char *versionlist) {
  const char *vl;
  tor_version_t mine, other;
  int found_newer = 0, found_newer_in_series = 0, found_any_in_series = 0,
    r, ret, same;
  static int warned_too_new=0;
  smartlist_t *version_sl;
  int XXXpath;

  vl = versionlist;

  log_fn(LOG_DEBUG,"Checking whether version '%s' is in '%s'", myversion, versionlist);

  if (tor_version_parse(myversion, &mine)) {
    log_fn(LOG_ERR, "I couldn't parse my own version (%s)", myversion);
    tor_assert(0);
  }
  version_sl = smartlist_create();
  smartlist_split_string(version_sl, versionlist, ",", SPLIT_SKIP_SPACE, 0);

  SMARTLIST_FOREACH(version_sl, const char *, cp, {
    if (!strcmpstart(cp, "Tor "))
      cp += 4;

    if (tor_version_parse(cp, &other)) {
      /* Couldn't parse other; it can't be a match. */
    } else {
      same = tor_version_same_series(&mine, &other);
      if (same)
        found_any_in_series = 1;
      r = tor_version_compare(&mine, &other);
      if (r==0) {
        ret = 0;
        goto done;
      } else if (r<0) {
        found_newer = 1;
        if (same)
          found_newer_in_series = 1;
      }
    }
  });

  /* We didn't find the listed version. Is it new or old? */

  if (found_any_in_series) {
    if (!found_newer_in_series) {
      /* We belong to a series with recommended members, and we are newer than
       * any recommended member. We're probably okay. */
      if (!warned_too_new) {
        log(LOG_WARN, "This version of Tor (%s) is newer than any in the same series on the recommended list (%s)",
            myversion, versionlist);
        warned_too_new = 1;
      }
      ret = 0;
      XXXpath = 1;
    } else {
      /* We found a newer one in the same series; we're obsolete. */
      ret = 1;
      XXXpath = 2;
    }
  } else {
    if (found_newer) {
      /* We belong to a series with no recommended members, and
       * a newer series is recommended. We're obsolete. */
      ret = 1;
      XXXpath = 3;
    } else {
      /* We belong to a series with no recommended members, and it's
       * newer than any recommended series. We're probably okay. */
      if (!warned_too_new) {
        log(LOG_WARN, "This version of Tor (%s) is newer than any on the recommended list (%s)",
            myversion, versionlist);
        warned_too_new = 1;
      }
      ret = 0;
      XXXpath = 4;
    }
  }
  /*
  log_fn(LOG_DEBUG,
         "Decided that %s is %sobsolete relative to %s: %d, %d, %d\n",
         myversion, ret?"":"not ", versionlist, found_newer,
         found_any_in_series, found_newer_in_series);
  */

 done:
  SMARTLIST_FOREACH(version_sl, char *, version, tor_free(version));
  smartlist_free(version_sl);
  return ret;
}

/* Return 0 if myversion is supported; else warn and return -1. */
int check_software_version_against_directory(const char *directory)
{
  char *v;
  v = get_recommended_software_from_directory(directory);
  if (!v) {
    log_fn(LOG_WARN, "No recommended-versions string found in directory");
    return -1;
  }
  if (!is_obsolete_version(VERSION, v)) {
    tor_free(v);
    return 0;
  }
  log(LOG_WARN,
     "You are running Tor version %s, which will not work with this network.\n"
     "Please use %s%s.",
      VERSION, strchr(v,',') ? "one of " : "", v);
  tor_free(v);
  return -1;
}

/** Parse a directory from <b>str</b> and, when done, store the
 * resulting routerlist in *<b>dest</b>, freeing the old value if
 * necessary.
 *
 * If <b>pkey</b> is provided, we check the directory signature with pkey.
 *
 * If <b>check_version</b> is non-zero, then examine the
 * Recommended-versions * line in the directory, and warn or quit
 * as needed.
 *
 * If <b>write_to_cache</b> is non-zero, then store this directory in
 * memory and/or disk as well.
 */
int /* Should be static; exposed for unit tests */
router_parse_routerlist_from_directory(const char *str,
                                       routerlist_t **dest,
                                       crypto_pk_env_t *pkey,
                                       int check_version,
                                       int write_to_cache)
{
  directory_token_t *tok;
  char digest[DIGEST_LEN];
  routerlist_t *new_dir = NULL;
  char *versions = NULL;
  smartlist_t *good_nickname_list = NULL;
  time_t published_on;
  int i, r;
  const char *end, *cp;
  smartlist_t *tokens = NULL;
  char dirnickname[MAX_NICKNAME_LEN+1];
  crypto_pk_env_t *declared_key = NULL;

  if (router_get_dir_hash(str, digest)) {
    log_fn(LOG_WARN, "Unable to compute digest of directory");
    goto err;
  }
  log_fn(LOG_DEBUG,"Received directory hashes to %s",hex_str(digest,4));

  /* Check signature first, before we try to tokenize. */
  cp = str;
  while (cp && (end = strstr(cp+1, "\ndirectory-signature")))
    cp = end;
  if (cp == str || !cp) {
    log_fn(LOG_WARN, "No signature found on directory."); goto err;
  }
  ++cp;
  tokens = smartlist_create();
  if (tokenize_string(cp,strchr(cp,'\0'),tokens,1)) {
    log_fn(LOG_WARN, "Error tokenizing directory signature"); goto err;
  }
  if (smartlist_len(tokens) != 1) {
    log_fn(LOG_WARN, "Unexpected number of tokens in signature"); goto err;
  }
  tok=smartlist_get(tokens,0);
  if (tok->tp != K_DIRECTORY_SIGNATURE) {
    log_fn(LOG_WARN,"Expected a single directory signature"); goto err;
  }
  declared_key = find_dir_signing_key(str);
  if (check_directory_signature(digest, tok, pkey, declared_key)<0)
    goto err;

  /* now we know tok->n_args == 1, so it's safe to access tok->args[0] */
  if (!is_legal_nickname(tok->args[0])) {
    log_fn(LOG_WARN, "Directory nickname '%s' is misformed", tok->args[0]);
    goto err;
  }
  strlcpy(dirnickname, tok->args[0], sizeof(dirnickname));

  SMARTLIST_FOREACH(tokens, directory_token_t *, tok, token_free(tok));
  smartlist_free(tokens);
  tokens = NULL;

  /* Now that we know the signature is okay, check the version. */
  if (check_version)
    check_software_version_against_directory(str);

  /* Now try to parse the first part of the directory. */
  if ((end = strstr(str,"\nrouter "))) {
    ++end;
  } else if ((end = strstr(str, "\ndirectory-signature"))) {
    ++end;
  } else {
    end = str + strlen(str);
  }

  tokens = smartlist_create();
  if (tokenize_string(str,end,tokens,1)) {
    log_fn(LOG_WARN, "Error tokenizing directory"); goto err;
  }
  if (smartlist_len(tokens) < 1) {
    log_fn(LOG_WARN, "Impossibly short directory header"); goto err;
  }
  if ((tok = find_first_by_keyword(tokens, _UNRECOGNIZED))) {
    log_fn(LOG_WARN, "Unrecognized keyword \"%s\" in directory header; can't parse directory.",
           tok->args[0]);
    goto err;
  }

  tok = smartlist_get(tokens,0);
  if (tok->tp != K_SIGNED_DIRECTORY) {
    log_fn(LOG_WARN, "Directory doesn't start with signed-directory.");
    goto err;
  }

  if (!(tok = find_first_by_keyword(tokens, K_PUBLISHED))) {
    log_fn(LOG_WARN, "Missing published time on directory.");
    goto err;
  }
  tor_assert(tok->n_args == 1);

  if (parse_iso_time(tok->args[0], &published_on) < 0) {
     goto err;
  }

  /* Now that we know the signature is okay, and we have a
   * publication time, cache the directory. */
  if (!get_options()->AuthoritativeDir && write_to_cache)
    dirserv_set_cached_directory(str, published_on, 0);

  if (!(tok = find_first_by_keyword(tokens, K_RECOMMENDED_SOFTWARE))) {
    log_fn(LOG_WARN, "Missing recommended-software line from directory.");
    goto err;
  }
  if (tok->n_args > 1) {
    log_fn(LOG_WARN, "Invalid recommended-software line");
    goto err;
  }
  versions = tok->n_args ? tor_strdup(tok->args[0]) : tor_strdup("");

  /* Prefer router-status, then running-routers. */
  if (!(tok = find_first_by_keyword(tokens, K_ROUTER_STATUS))) {
    log_fn(LOG_WARN,
           "Missing router-status line from directory.");
    goto err;
  }

  good_nickname_list = smartlist_create();
  for (i=0; i<tok->n_args; ++i) {
    smartlist_add(good_nickname_list, tok->args[i]);
  }
  tok->n_args = 0; /* Don't free the strings in good_nickname_list yet. */

  /* Read the router list from s, advancing s up past the end of the last
   * router. */
  str = end;
  if (router_parse_list_from_string(&str, &new_dir,
                                    good_nickname_list,
                                    tok->tp==K_RUNNING_ROUTERS,
                                    published_on)) {
    log_fn(LOG_WARN, "Error reading routers from directory");
    goto err;
  }

  /* Determine if my routerinfo is considered verified. */
  {
    static int have_warned_about_unverified_status = 0;
    routerinfo_t *me = router_get_my_routerinfo();
    if (me) {
      if (router_update_status_from_smartlist(me,
            published_on, good_nickname_list)==1 &&
          me->is_verified == 0 && !have_warned_about_unverified_status) {
        log_fn(LOG_WARN,"Dirserver '%s' lists your server as unverified. Please consider sending your identity fingerprint to the tor-ops.", dirnickname);
        have_warned_about_unverified_status = 1;
      }
    }
  }

  new_dir->software_versions = versions; versions = NULL;
  new_dir->published_on = published_on;
  new_dir->running_routers = tor_malloc_zero(sizeof(running_routers_t));
  new_dir->running_routers->published_on = published_on;
  new_dir->running_routers->running_routers = good_nickname_list;

  SMARTLIST_FOREACH(tokens, directory_token_t *, tok, token_free(tok));
  smartlist_free(tokens);
  tokens = NULL;

  if (*dest)
    routerlist_free(*dest);
  *dest = new_dir;

  r = 0;
  goto done;
 err:
  r = -1;
  if (new_dir)
    routerlist_free(new_dir);
  tor_free(versions);
  if (good_nickname_list) {
    SMARTLIST_FOREACH(good_nickname_list, char *, n, tor_free(n));
    smartlist_free(good_nickname_list);
  }
 done:
  if (declared_key) crypto_free_pk_env(declared_key);
  if (tokens) {
    SMARTLIST_FOREACH(tokens, directory_token_t *, tok, token_free(tok));
    smartlist_free(tokens);
  }
  return r;
}

/** Read a signed router status statement from <b>str</b>.  On
 * success, return it, and cache the original string if
 * <b>write_to_cache</b> is set.  Otherwise, return NULL.  */
running_routers_t *
router_parse_runningrouters(const char *str, int write_to_cache)
{
  char digest[DIGEST_LEN];
  running_routers_t *new_list = NULL;
  directory_token_t *tok;
  time_t published_on;
  int i;
  crypto_pk_env_t *declared_key = NULL;
  smartlist_t *tokens = NULL;

  if (router_get_runningrouters_hash(str, digest)) {
    log_fn(LOG_WARN, "Unable to compute digest of directory");
    goto err;
  }
  tokens = smartlist_create();
  if (tokenize_string(str,str+strlen(str),tokens,1)) {
    log_fn(LOG_WARN, "Error tokenizing directory"); goto err;
  }
  if ((tok = find_first_by_keyword(tokens, _UNRECOGNIZED))) {
    log_fn(LOG_WARN, "Unrecognized keyword '%s'; can't parse running-routers",
           tok->args[0]);
    goto err;
  }
  tok = smartlist_get(tokens,0);
  if (tok->tp != K_NETWORK_STATUS) {
    log_fn(LOG_WARN, "Network-status starts with wrong token");
    goto err;
  }

  if (!(tok = find_first_by_keyword(tokens, K_PUBLISHED))) {
    log_fn(LOG_WARN, "Missing published time on directory.");
    goto err;
  }
  tor_assert(tok->n_args == 1);
  if (parse_iso_time(tok->args[0], &published_on) < 0) {
     goto err;
  }

  /* Now that we know the signature is okay, and we have a
   * publication time, cache the list. */
  if (!get_options()->AuthoritativeDir && write_to_cache)
    dirserv_set_cached_directory(str, published_on, 1);

  if (!(tok = find_first_by_keyword(tokens, K_ROUTER_STATUS))) {
    if (!(tok = find_first_by_keyword(tokens, K_RUNNING_ROUTERS))) {
      log_fn(LOG_WARN,
             "Missing running-routers/router-status line from directory.");
      goto err;
    }
  }

  new_list = tor_malloc_zero(sizeof(running_routers_t));
  new_list->published_on = published_on;
  new_list->running_routers = smartlist_create();
  for (i=0;i<tok->n_args;++i) {
    smartlist_add(new_list->running_routers, tok->args[i]);
  }
  tok->n_args = 0; /* Don't free the elements of tok->args. */

  if (!(tok = find_first_by_keyword(tokens, K_DIRECTORY_SIGNATURE))) {
    log_fn(LOG_WARN, "Missing signature on running-routers");
    goto err;
  }
  declared_key = find_dir_signing_key(str);
  if (check_directory_signature(digest, tok, NULL, declared_key) < 0)
    goto err;

  goto done;
 err:
  if (new_list) {
    running_routers_free(new_list);
    new_list = NULL;
  }
 done:
  if (declared_key) crypto_free_pk_env(declared_key);
  if (tokens) {
    SMARTLIST_FOREACH(tokens, directory_token_t *, tok, token_free(tok));
    smartlist_free(tokens);
  }
  return new_list;
}

/** Given a directory or running-routers string in <b>str</b>, try to
 * find the its dir-signing-key token (if any).  If this token is
 * present, extract and return the key.  Return NULL on failure. */
static crypto_pk_env_t *find_dir_signing_key(const char *str)
{
  const char *cp;
  directory_token_t *tok;
  crypto_pk_env_t *key = NULL;

  /* Is there a dir-signing-key in the directory? */
  cp = strstr(str, "\nopt dir-signing-key");
  if (!cp)
    cp = strstr(str, "\ndir-signing-key");
  if (!cp)
    return NULL;
  ++cp; /* Now cp points to the start of the token. */

  tok = get_next_token(&cp, DIR_ONLY);
  if (!tok) {
    log_fn(LOG_WARN, "Unparseable dir-signing-key token");
    return NULL;
  }
  if (tok->tp != K_DIR_SIGNING_KEY) {
    log_fn(LOG_WARN, "Dir-signing-key token did not parse as expected");
    return NULL;
  }

  if (tok->key) {
    key = tok->key;
    tok->key = NULL; /* steal reference. */
  } else if (tok->n_args >= 1) {
    /** XXXX Once all the directories are running 0.1.0.6-rc or later, we
     * can remove this logic. */
    key = crypto_pk_DER64_decode_public_key(tok->args[0]);
    if (!key) {
      log_fn(LOG_WARN, "Unparseable dir-signing-key argument");
      return NULL;
    }
  } else {
    log_fn(LOG_WARN, "Dir-signing-key token contained no key");
    return NULL;
  }

  token_free(tok);
  return key;
}

/** Return true iff <b>key</b> is allowed to sign directories.
 */
static int dir_signing_key_is_trusted(crypto_pk_env_t *key)
{
  char digest[DIGEST_LEN];
  if (!key) return 0;
  if (crypto_pk_get_digest(key, digest) < 0) {
    log_fn(LOG_WARN, "Error computing dir-signing-key digest");
    return 0;
  }
  if (!router_digest_is_trusted_dir(digest)) {
    log_fn(LOG_WARN, "Listed dir-signing-key is not trusted");
    return 0;
  }
  return 1;
}

/** Check whether the K_DIRECTORY_SIGNATURE token in <b>tok</b> has a
 * good signature for <b>digest</b>.
 *
 * If <b>declared_key</b> is set, the directory has declared what key
 * was used to sign it, so we will use that key only if it is an
 * authoritative directory signing key.
 *
 * Otherwise, if pkey is provided, try to use it.
 *
 * (New callers should always use <b>declared_key</b> when possible;
 * <b>pkey</b> is only for debugging.)
 */
static int check_directory_signature(const char *digest,
                                     directory_token_t *tok,
                                     crypto_pk_env_t *pkey,
                                     crypto_pk_env_t *declared_key)
{
  char signed_digest[PK_BYTES];
  crypto_pk_env_t *_pkey = NULL;

  if (tok->n_args != 1) {
    log_fn(LOG_WARN, "Too many or too few arguments to directory-signature");
    return -1;
  }

  if (declared_key) {
    if (dir_signing_key_is_trusted(declared_key))
      _pkey = declared_key;
  }
  if (!_pkey && pkey) {
    /* pkey provided for debugging purposes */
    _pkey = pkey;
  }
  if (!_pkey) {
    log_fn(LOG_WARN, "Obsolete directory format (dir signing key not present) or signing key not trusted--rejecting.");
    return -1;
  }

  if (strcmp(tok->object_type, "SIGNATURE") || tok->object_size != 128) {
    log_fn(LOG_WARN, "Bad object type or length on directory signature");
    return -1;
  }

  tor_assert(_pkey);

  if (crypto_pk_public_checksig(_pkey, signed_digest, tok->object_body, 128)
      != 20) {
    log_fn(LOG_WARN, "Error reading directory: invalid signature.");
    return -1;
  }
  log_fn(LOG_DEBUG,"Signed directory hash starts %s", hex_str(signed_digest,4));
  if (memcmp(digest, signed_digest, 20)) {
    log_fn(LOG_WARN, "Error reading directory: signature does not match.");
    return -1;
  }
  return 0;
}

/** Given a string *<b>s</b> containing a concatenated sequence of router
 * descriptors, parses them and stores the result in *<b>dest</b>.  If
 * good_nickname_list is provided, then routers are marked as
 * running/nonrunning and verified/unverified based on their status in the
 * list.  Otherwise, all routers are marked running and verified.  Advances
 * *s to a point immediately following the last router entry.  Returns 0 on
 * success and -1 on failure.
 */
int
router_parse_list_from_string(const char **s, routerlist_t **dest,
                              smartlist_t *good_nickname_list,
                              int rr_format, time_t published_on)
{
  routerinfo_t *router;
  smartlist_t *routers;
  const char *end;

  tor_assert(s);
  tor_assert(*s);

  routers = smartlist_create();

  while (1) {
    *s = eat_whitespace(*s);
    /* Don't start parsing the rest of *s unless it contains a router. */
    if (strcmpstart(*s, "router ")!=0)
      break;
    if ((end = strstr(*s+1, "\nrouter "))) {
      end++;
    } else if ((end = strstr(*s+1, "\ndirectory-signature"))) {
      end++;
    } else {
      end = *s+strlen(*s);
    }

    router = router_parse_entry_from_string(*s, end);
    *s = end;
    if (!router) {
      log_fn(LOG_WARN, "Error reading router; skipping");
      continue;
    }

    if (!good_nickname_list) {
      router->is_running = 1; /* start out assuming all dirservers are up */
      router->is_verified = 1;
      router->status_set_at = time(NULL);
    }
    smartlist_add(routers, router);
//    log_fn(LOG_DEBUG,"just added router #%d.",smartlist_len(routers));
  }

  if (good_nickname_list) {
    SMARTLIST_FOREACH(good_nickname_list, const char *, cp,
                  routers_update_status_from_entry(routers, published_on, cp));
  }

  if (*dest)
    routerlist_free(*dest);
  *dest = tor_malloc_zero(sizeof(routerlist_t));
  (*dest)->routers = routers;

  return 0;
}

/** Helper function: reads a single router entry from *<b>s</b> ...
 * *<b>end</b>.  Mallocs a new router and returns it if all goes well, else
 * returns NULL.
 */
routerinfo_t *router_parse_entry_from_string(const char *s,
                                           const char *end) {
  routerinfo_t *router = NULL;
  char signed_digest[128];
  char digest[128];
  smartlist_t *tokens = NULL, *exit_policy_tokens = NULL;
  directory_token_t *tok;
  int t;
  int ports_set, bw_set;

  if (!end) {
    end = s + strlen(s);
  }

  if (router_get_router_hash(s, digest) < 0) {
    log_fn(LOG_WARN, "Couldn't compute router hash.");
    return NULL;
  }
  tokens = smartlist_create();
  if (tokenize_string(s,end,tokens,0)) {
    log_fn(LOG_WARN, "Error tokeninzing router descriptor.");
    goto err;
  }

  if (smartlist_len(tokens) < 2) {
    log_fn(LOG_WARN, "Impossibly short router descriptor.");
    goto err;
  }
  if ((tok = find_first_by_keyword(tokens, _UNRECOGNIZED))) {
    log_fn(LOG_WARN, "Unrecognized keyword '%s'; skipping descriptor.",
           tok->args[0]);
    goto err;
  }

  tok = smartlist_get(tokens,0);
  if (tok->tp != K_ROUTER) {
    log_fn(LOG_WARN,"Entry does not start with \"router\"");
    goto err;
  }

  router = tor_malloc_zero(sizeof(routerinfo_t));
  router->signed_descriptor = tor_strndup(s, end-s);
  ports_set = bw_set = 0;

  if (tok->n_args == 2 || tok->n_args == 5 || tok->n_args == 6) {
    router->nickname = tor_strdup(tok->args[0]);
    if (!is_legal_nickname(router->nickname)) {
      log_fn(LOG_WARN,"Router nickname is invalid");
      goto err;
    }
    router->address = tor_strdup(tok->args[1]);
    router->addr = 0;

    if (tok->n_args >= 5) {
      router->or_port = (uint16_t) tor_parse_long(tok->args[2],10,0,65535,NULL,NULL);
      router->dir_port = (uint16_t) tor_parse_long(tok->args[4],10,0,65535,NULL,NULL);
      ports_set = 1;
    }
  } else {
    log_fn(LOG_WARN,"Wrong # of arguments to \"router\" (%d)",tok->n_args);
    goto err;
  }

  tok = find_first_by_keyword(tokens, K_PORTS);
  if (tok && ports_set) {
    log_fn(LOG_WARN,"Redundant ports line");
    goto err;
  } else if (tok) {
    if (tok->n_args != 3) {
      log_fn(LOG_WARN,"Wrong # of arguments to \"ports\"");
      goto err;
    }
    router->or_port = (uint16_t) tor_parse_long(tok->args[0],10,0,65535,NULL,NULL);
    router->dir_port = (uint16_t) tor_parse_long(tok->args[2],10,0,65535,NULL,NULL);
    ports_set = 1;
  }

  tok = find_first_by_keyword(tokens, K_BANDWIDTH);
  if (tok && bw_set) {
    log_fn(LOG_WARN,"Redundant bandwidth line");
    goto err;
  } else if (tok) {
    if (tok->n_args < 3) {
      /* XXXX Once 0.0.7 is *really* dead, restore this warning to its old form*/
      log_fn(LOG_WARN,"Not enough arguments to \"bandwidth\": must be an obsolete server. Rejecting one server (nickname '%s').", router->nickname);
      goto err;
    }
    router->bandwidthrate = tor_parse_long(tok->args[0],10,0,INT_MAX,NULL,NULL);
    router->bandwidthburst = tor_parse_long(tok->args[1],10,0,INT_MAX,NULL,NULL);
    router->bandwidthcapacity = tor_parse_long(tok->args[2],10,0,INT_MAX,NULL,NULL);
    bw_set = 1;
  }

  if ((tok = find_first_by_keyword(tokens, K_UPTIME))) {
    if (tok->n_args != 1) {
      log_fn(LOG_WARN, "Unrecognized number of args on K_UPTIME; skipping.");
    } else {
      router->uptime = tor_parse_long(tok->args[0],10,0,LONG_MAX,NULL,NULL);
    }
  }

  if (!(tok = find_first_by_keyword(tokens, K_PUBLISHED))) {
    log_fn(LOG_WARN, "Missing published time"); goto err;
  }
  tor_assert(tok->n_args == 1);
  if (parse_iso_time(tok->args[0], &router->published_on) < 0)
    goto err;

  if (!(tok = find_first_by_keyword(tokens, K_ONION_KEY))) {
    log_fn(LOG_WARN, "Missing onion key"); goto err;
  }
  if (crypto_pk_keysize(tok->key) != PK_BYTES) {
    log_fn(LOG_WARN, "Wrong size on onion key: %d bits!",
           (int)crypto_pk_keysize(tok->key)*8);
    goto err;
  }
  router->onion_pkey = tok->key;
  tok->key = NULL; /* Prevent free */

  if (!(tok = find_first_by_keyword(tokens, K_SIGNING_KEY))) {
    log_fn(LOG_WARN, "Missing identity key"); goto err;
  }
  if (crypto_pk_keysize(tok->key) != PK_BYTES) {
    log_fn(LOG_WARN, "Wrong size on identity key: %d bits!",
           (int)crypto_pk_keysize(tok->key)*8);
    goto err;
  }
  router->identity_pkey = tok->key;
  tok->key = NULL; /* Prevent free */
  if (crypto_pk_get_digest(router->identity_pkey,router->identity_digest)) {
    log_fn(LOG_WARN, "Couldn't calculate key digest"); goto err;
  }

  if ((tok = find_first_by_keyword(tokens, K_PLATFORM))) {
    router->platform = tor_strdup(tok->args[0]);
  }

  if ((tok = find_first_by_keyword(tokens, K_CONTACT))) {
    router->contact_info = tor_strdup(tok->args[0]);
  }

  exit_policy_tokens = find_all_exitpolicy(tokens);
  SMARTLIST_FOREACH(exit_policy_tokens, directory_token_t *, t,
                    if (router_add_exit_policy(router,t)<0) {
                      log_fn(LOG_WARN,"Error in exit policy");
                      goto err;
                    });

  if ((tok = find_first_by_keyword(tokens, K_FAMILY)) && tok->n_args) {
    int i;
    router->declared_family = smartlist_create();
    for (i=0;i<tok->n_args;++i) {
      if (!is_legal_nickname_or_hexdigest(tok->args[i])) {
        log_fn(LOG_WARN, "Illegal nickname '%s' in family line", tok->args[i]);
        goto err;
      }
      smartlist_add(router->declared_family, tor_strdup(tok->args[i]));
    }
  }

  if (!(tok = find_first_by_keyword(tokens, K_ROUTER_SIGNATURE))) {
    log_fn(LOG_WARN, "Missing router signature");
    goto err;
  }
  if (strcmp(tok->object_type, "SIGNATURE") || tok->object_size != 128) {
    log_fn(LOG_WARN, "Bad object type or length on router signature");
    goto err;
  }
  if ((t=crypto_pk_public_checksig(router->identity_pkey, signed_digest,
                                   tok->object_body, 128)) != 20) {
    log_fn(LOG_WARN, "Invalid signature %d",t);
    goto err;
  }
  if (memcmp(digest, signed_digest, 20)) {
    log_fn(LOG_WARN, "Mismatched signature");
    goto err;
  }

  if (!ports_set) {
    log_fn(LOG_WARN,"No ports declared; failing.");
    goto err;
  }
  if (!bw_set) {
    log_fn(LOG_WARN,"No bandwidth declared; failing.");
    goto err;
  }
  if (!router->or_port) {
    log_fn(LOG_WARN,"or_port unreadable or 0. Failing.");
    goto err;
  }
  if (!router->bandwidthrate) {
    log_fn(LOG_WARN,"bandwidthrate unreadable or 0. Failing.");
    goto err;
  }
  if (!router->platform) {
    router->platform = tor_strdup("<unknown>");
  }

//  log_fn(LOG_DEBUG,"or_port %d, dir_port %d, bandwidthrate %u, bandwidthburst %u.",
//    router->or_port, router->dir_port,
//    (unsigned) router->bandwidthrate, (unsigned) router->bandwidthburst);

  goto done;
  return router;

 err:
  routerinfo_free(router);
  router = NULL;
 done:
  if (tokens) {
    SMARTLIST_FOREACH(tokens, directory_token_t *, tok, token_free(tok));
    smartlist_free(tokens);
  }
  if (exit_policy_tokens) {
    smartlist_free(exit_policy_tokens);
  }
  return router;
}

/** Parse the exit policy in the string <b>s</b> and return it.
 */
addr_policy_t *
router_parse_addr_policy_from_string(const char *s)
{
  directory_token_t *tok = NULL;
  const char *cp;
  char *tmp;
  addr_policy_t *r;
  size_t len, idx;

  /* *s might not end with \n, so we need to extend it with one. */
  len = strlen(s);
  cp = tmp = tor_malloc(len+2);
  for (idx = 0; idx < len; ++idx) {
    tmp[idx] = tolower(s[idx]);
  }
  tmp[len]='\n';
  tmp[len+1]='\0';
  tok = get_next_token(&cp, RTR_ONLY);
  if (tok->tp == _ERR) {
    log_fn(LOG_WARN, "Error reading exit policy: %s", tok->error);
    goto err;
  }
  if (tok->tp != K_ACCEPT && tok->tp != K_REJECT) {
    log_fn(LOG_WARN, "Expected 'accept' or 'reject'.");
    goto err;
  }

  /* Now that we've gotten an exit policy, add it to the router. */
  r = router_parse_addr_policy(tok);
  goto done;
 err:
  r = NULL;
 done:
  tor_free(tmp);
  token_free(tok);
  return r;
}

int
router_add_exit_policy_from_string(routerinfo_t *router, const char *s)
{
  addr_policy_t *newe, *tmpe;
  newe = router_parse_addr_policy_from_string(s);
  if (!newe)
    return -1;
  for (tmpe = router->exit_policy; tmpe; tmpe=tmpe->next)
    ;
  tmpe->next = newe;

  return 0;
}

static int
router_add_exit_policy(routerinfo_t *router,directory_token_t *tok)
{
  addr_policy_t *newe, **tmpe;
  newe = router_parse_addr_policy(tok);
  if (!newe)
    return -1;
  for (tmpe = &router->exit_policy; *tmpe; tmpe=&((*tmpe)->next))
    ;
  *tmpe = newe;

  return 0;
}

/** Given a K_ACCEPT or K_REJECT token and a router, create and return
 * a new exit_policy_t corresponding to the token. */
static addr_policy_t *
router_parse_addr_policy(directory_token_t *tok) {

  addr_policy_t *newe;
//  struct in_addr in;
  char *arg;
//  char *address;
//  char buf[INET_NTOA_BUF_LEN];

  tor_assert(tok->tp == K_REJECT || tok->tp == K_ACCEPT);

  if (tok->n_args != 1)
    return NULL;
  arg = tok->args[0];

  newe = tor_malloc_zero(sizeof(addr_policy_t));

  newe->string = tor_malloc(8+strlen(arg));
  /* XXX eventually, use the code from router.c:727 to generate this */
  tor_snprintf(newe->string, 8+strlen(arg), "%s %s",
               (tok->tp == K_REJECT) ? "reject" : "accept", arg);
  newe->policy_type = (tok->tp == K_REJECT) ? ADDR_POLICY_REJECT
    : ADDR_POLICY_ACCEPT;

  if (parse_addr_and_port_range(arg, &newe->addr, &newe->msk,
                                &newe->prt_min, &newe->prt_max))
    goto policy_read_failed;

//  in.s_addr = htonl(newe->addr);
//  tor_inet_ntoa(&in, buf, sizeof(buf));
//  address = tor_strdup(buf);
//  in.s_addr = htonl(newe->msk);
//  log_fn(LOG_DEBUG,"%s %s/%s:%d-%d",
//         newe->policy_type == ADDR_POLICY_REJECT ? "reject" : "accept",
//         address, inet_ntoa(in), newe->prt_min, newe->prt_max);
//  tor_free(address);

  return newe;

policy_read_failed:
  tor_assert(newe->string);
  log_fn(LOG_WARN,"Couldn't parse line '%s'. Dropping", newe->string);
  tor_free(newe->string);
  tor_free(newe);
  return NULL;
}

void
assert_addr_policy_ok(addr_policy_t *t)
{
  addr_policy_t *t2;
  while (t) {
    tor_assert(t->policy_type == ADDR_POLICY_REJECT ||
               t->policy_type == ADDR_POLICY_ACCEPT);
    tor_assert(t->prt_min <= t->prt_max);
    t2 = router_parse_addr_policy_from_string(t->string);
    tor_assert(t2);
    tor_assert(t2->policy_type == t->policy_type);
    tor_assert(t2->addr == t->addr);
    tor_assert(t2->msk == t->msk);
    tor_assert(t2->prt_min == t->prt_min);
    tor_assert(t2->prt_max == t->prt_max);
    tor_assert(!strcmp(t2->string, t->string));
    tor_assert(t2->next == NULL);
    addr_policy_free(t2);

    t = t->next;
  }

}

/*
 * Low-level tokenizer for router descriptors and directories.
 */

/** Free all resources allocated for <b>tok</b> */
static void
token_free(directory_token_t *tok)
{
  int i;
  tor_assert(tok);
  if (tok->args) {
    for (i = 0; i < tok->n_args; ++i) {
      tor_free(tok->args[i]);
    }
    tor_free(tok->args);
  }
  tor_free(tok->object_type);
  tor_free(tok->object_body);
  if (tok->key)
    crypto_free_pk_env(tok->key);
  tor_free(tok);
}

/** Helper function: read the next token from *s, advance *s to the end
 * of the token, and return the parsed token.  If 'where' is DIR_ONLY
 * or RTR_ONLY, reject all tokens of the wrong type.
 */
static directory_token_t *
get_next_token(const char **s, where_syntax where) {
  const char *next, *obstart;
  int i, done, allocated, is_opt;
  directory_token_t *tok;
  arg_syntax a_syn;
  obj_syntax o_syn = NO_OBJ;

#define RET_ERR(msg)                                    \
  do { if (tok) token_free(tok);                        \
       tok = tor_malloc_zero(sizeof(directory_token_t));\
       tok->tp = _ERR;                                  \
       tok->error = msg;                                \
       goto done_tokenizing; } while (0)

  tok = tor_malloc_zero(sizeof(directory_token_t));
  tok->tp = _ERR;

  *s = eat_whitespace(*s);
  if (!**s) {
    tok->tp = _EOF;
    return tok;
  }
  next = find_whitespace(*s);
  if (!next) {
    tok->error = "Unexpected EOF"; return tok;
  }
  /* It's a keyword... but which one? */
  is_opt = !strncmp("opt", *s, next-*s);
  if (is_opt) {
    *s = eat_whitespace(next);
    next = NULL;
    if (**s)
      next = find_whitespace(*s);
    if (!**s || !next) {
      RET_ERR("opt without keyword");
    }
  }
  for (i = 0; token_table[i].t ; ++i) {
    if (!strncmp(token_table[i].t, *s, next-*s)) {
      /* We've found the keyword. */
      tok->tp = token_table[i].v;
      a_syn = token_table[i].s;
      o_syn = token_table[i].os;
      if (token_table[i].ws != ANY && token_table[i].ws != where) {
        if (where == DIR_ONLY) {
          RET_ERR("Found a router-only token in a directory section");
        } else {
          RET_ERR("Found a directory-only token in a router descriptor");
        }
      }
      if (a_syn == ARGS) {
        /* This keyword takes multiple arguments. */
        i = 0;
        done = (*next == '\n');
        allocated = 32;
        tok->args = tor_malloc(sizeof(char*)*32);
        *s = eat_whitespace_no_nl(next);
        while (**s != '\n' && !done) {
          next = find_whitespace(*s);
          if (*next == '\n')
            done = 1;
          if (i == allocated) {
            allocated *= 2;
            tok->args = tor_realloc(tok->args,sizeof(char*)*allocated);
          }
          tok->args[i++] = tor_strndup(*s,next-*s);
          *s = eat_whitespace_no_nl(next+1);
        }
        tok->n_args = i;
      } else if (a_syn == CONCAT_ARGS) {
        /* The keyword takes the line as a single argument */
        *s = eat_whitespace_no_nl(next);
        next = strchr(*s, '\n');
        if (!next)
          RET_ERR("Unexpected EOF");
        tok->args = tor_malloc(sizeof(char*));
        tok->args[0] = tor_strndup(*s,next-*s);
        tok->n_args = 1;
        *s = eat_whitespace_no_nl(next+1);
      } else {
        /* The keyword takes no arguments. */
        tor_assert(a_syn == NO_ARGS);
        *s = eat_whitespace_no_nl(next);
        if (**s != '\n') {
          RET_ERR("Unexpected arguments");
        }
        tok->n_args = 0;
        *s = eat_whitespace_no_nl(*s+1);
      }
      break;
    }
  }
  if (tok->tp == _ERR) {
    if (is_opt) {
      tok->tp = K_OPT;
      *s = eat_whitespace_no_nl(next);
      next = strchr(*s,'\n');
      if (!next)
        RET_ERR("Unexpected EOF");
      tok->args = tor_malloc(sizeof(char*));
      tok->args[0] = tor_strndup(*s,next-*s);
      tok->n_args = 1;
      *s = eat_whitespace_no_nl(next+1);
      o_syn = OBJ_OK;
    } else {
      tok->tp = _UNRECOGNIZED;
      next = strchr(*s, '\n');
      if (!next) {
        RET_ERR("Unexpected EOF");
      }
      tok->args = tor_malloc(sizeof(char*));
      tok->args[0] = tor_strndup(*s,next-*s);
      tok->n_args = 1;
      *s = next+1;
      o_syn = OBJ_OK;
    }
  }
  *s = eat_whitespace(*s);
  if (strcmpstart(*s, "-----BEGIN ")) {
    goto done_tokenizing;
  }
  obstart = *s;
  *s += 11; /* length of "-----BEGIN ". */
  next = strchr(*s, '\n');
  if (next-*s < 6 || strcmpstart(next-5, "-----\n")) {
    RET_ERR("Malformed object: bad begin line");
  }
  tok->object_type = tor_strndup(*s, next-*s-5);
  *s = next+1;
  next = strstr(*s, "-----END ");
  if (!next) {
    RET_ERR("Malformed object: missing end line");
  }
  if (!strcmp(tok->object_type, "RSA PUBLIC KEY")) {
    if (strcmpstart(next, "-----END RSA PUBLIC KEY-----\n"))
      RET_ERR("Malformed object: mismatched end line");
    next = strchr(next,'\n')+1;
    tok->key = crypto_new_pk_env();
    if (crypto_pk_read_public_key_from_string(tok->key, obstart, next-obstart))
      RET_ERR("Couldn't parse public key.");
    *s = next;
  } else {
    tok->object_body = tor_malloc(next-*s); /* really, this is too much RAM. */
    i = base64_decode(tok->object_body, 256, *s, next-*s);
    if (i<0) {
      RET_ERR("Malformed object: bad base64-encoded data");
    }
    tok->object_size = i;
    *s = next + 9; /* length of "-----END ". */
    i = strlen(tok->object_type);
    if (strncmp(*s, tok->object_type, i) || strcmpstart(*s+i, "-----\n")) {
      RET_ERR("Malformed object: mismatched end tag");
    }
    *s += i+6;
  }
  switch (o_syn)
    {
    case NO_OBJ:
      if (tok->object_body)
        RET_ERR("Unexpected object for keyword");
      if (tok->key)
        RET_ERR("Unexpected public key for keyword");
      break;
    case NEED_OBJ:
      if (!tok->object_body)
        RET_ERR("Missing object for keyword");
      break;
    case NEED_KEY:
      if (!tok->key)
        RET_ERR("Missing public key for keyword");
      break;
    case OBJ_OK:
      break;
    }

 done_tokenizing:

#if 0
  for (i = 0; token_table[i].t ; ++i) {
    if (token_table[i].v == tok->tp) {
      fputs(token_table[i].t, stdout);
      break;
      i = -1;
    }
  }
  if (i) {
    if (tok->tp == _UNRECOGNIZED) fputs("UNRECOGNIZED", stdout);
    if (tok->tp == _ERR) fputs("ERR",stdout);
    if (tok->tp == _EOF) fputs("EOF",stdout);
    if (tok->tp == _NIL) fputs("_NIL",stdout);
  }
  for (i = 0; i < tok->n_args; ++i) {
    fprintf(stdout," \"%s\"", tok->args[i]);
  }
  if (tok->error) { fprintf(stdout," *%s*", tok->error); }
  fputs("\n",stdout);
#endif

  return tok;
#undef RET_ERR
}

/** Read all tokens from a string between <b>start</b> and <b>end</b>, and add
 * them to <b>out</b>.  If <b>is_dir</b> is true, reject all non-directory
 * tokens; else reject all non-routerdescriptor tokens.
 */
static int
tokenize_string(const char *start, const char *end, smartlist_t *out,
                int is_dir)
{
  const char **s;
  directory_token_t *tok = NULL;
  where_syntax where = is_dir ? DIR_ONLY : RTR_ONLY;
  s = &start;
  while (*s < end && (!tok || tok->tp != _EOF)) {
    tok = get_next_token(s, where);
    if (tok->tp == _ERR) {
      log_fn(LOG_WARN, "parse error: %s", tok->error);
      return -1;
    }
    smartlist_add(out, tok);
    *s = eat_whitespace(*s);
  }

  return 0;
}

/** Find the first token in <b>s</b> whose keyword is <b>keyword</b>; return
 * NULL if no such keyword is found.
 */
static directory_token_t *
find_first_by_keyword(smartlist_t *s, directory_keyword keyword)
{
  SMARTLIST_FOREACH(s, directory_token_t *, t, if (t->tp == keyword) return t);
  return NULL;
}

/** Return a newly allocated smartlist of all accept or reject tokens in
 * <b>s</b>.
 */
static smartlist_t *
find_all_exitpolicy(smartlist_t *s)
{
  smartlist_t *out = smartlist_create();
  SMARTLIST_FOREACH(s, directory_token_t *, t,
                    if (t->tp == K_ACCEPT || t->tp == K_REJECT)
                      smartlist_add(out,t));
  return out;
}

/** Compute the SHA digest of the substring of <b>s</b> taken from the first
 * occurrence of <b>start_str</b> through the first newline after the first
 * subsequent occurrence of <b>end_str</b>; store the 20-byte result in
 * <b>digest</b>; return 0 on success.
 *
 * If no such substring exists, return -1.
 */
static int router_get_hash_impl(const char *s, char *digest,
                                const char *start_str,
                                const char *end_str)
{
  char *start, *end;
  start = strstr(s, start_str);
  if (!start) {
    log_fn(LOG_WARN,"couldn't find \"%s\"",start_str);
    return -1;
  }
  if (start != s && *(start-1) != '\n') {
    log_fn(LOG_WARN, "first occurrence of \"%s\" is not at the start of a line",
           start_str);
    return -1;
  }
  end = strstr(start+strlen(start_str), end_str);
  if (!end) {
    log_fn(LOG_WARN,"couldn't find \"%s\"",end_str);
    return -1;
  }
  end = strchr(end+strlen(end_str), '\n');
  if (!end) {
    log_fn(LOG_WARN,"couldn't find EOL");
    return -1;
  }
  ++end;

  if (crypto_digest(digest, start, end-start)) {
    log_fn(LOG_WARN,"couldn't compute digest");
    return -1;
  }

  return 0;
}

/** Parse the Tor version of the platform string <b>platform</b>,
 * and compare it to the version in <b>cutoff</b>. Return 1 if
 * the router is at least as new as the cutoff, else return 0.
 */
int tor_version_as_new_as(const char *platform, const char *cutoff) {
  tor_version_t cutoff_version, router_version;
  char *s, *start;
  char tmp[128];

  if (tor_version_parse(cutoff, &cutoff_version)<0) {
    log_fn(LOG_WARN,"Bug: cutoff version '%s' unparseable.",cutoff);
    return 0;
  }
  if (strcmpstart(platform,"Tor ")) /* nonstandard Tor; be safe and say yes */
    return 1;

  start = (char *)eat_whitespace(platform+3);
  if (!*start) return 0;
  s = (char *)find_whitespace(start); /* also finds '\0', which is fine */
  if ((size_t)(s-start+1) >= sizeof(tmp)) /* too big, no */
    return 0;
  strlcpy(tmp, start, s-start+1);

  if (tor_version_parse(tmp, &router_version)<0) {
    log_fn(LOG_INFO,"Router version '%s' unparseable.",tmp);
    return 1; /* be safe and say yes */
  }

  return tor_version_compare(&router_version, &cutoff_version) >= 0;
}

/** Parse a tor version from <b>s</b>, and store the result in <b>out</b>.
 * Return 0 on success, -1 on failure. */
int tor_version_parse(const char *s, tor_version_t *out)
{
  char *eos=NULL, *cp=NULL;
  /* Format is:
   *   "Tor " ? NUM dot NUM dot NUM [ ( pre | rc | dot ) NUM [ -cvs ] ]
   */
  tor_assert(s);
  tor_assert(out);

  memset(out, 0, sizeof(tor_version_t));

  if (!strcasecmpstart(s, "Tor "))
    s += 4;

  /* Get major. */
  out->major = strtol(s,&eos,10);
  if (!eos || eos==s || *eos != '.') return -1;
  cp = eos+1;

  /* Get minor */
  out->minor = strtol(cp,&eos,10);
  if (!eos || eos==cp || *eos != '.') return -1;
  cp = eos+1;

  /* Get micro */
  out->micro = strtol(cp,&eos,10);
  if (!eos || eos==cp) return -1;
  if (!*eos) {
    out->status = VER_RELEASE;
    out->patchlevel = 0;
    out->cvs = IS_NOT_CVS;
    return 0;
  }
  cp = eos;

  /* Get status */
  if (*cp == '.') {
    out->status = VER_RELEASE;
    ++cp;
  } else if (0==strncmp(cp, "pre", 3)) {
    out->status = VER_PRE;
    cp += 3;
  } else if (0==strncmp(cp, "rc", 2)) {
    out->status = VER_RC;
    cp += 2;
  } else {
    return -1;
  }

  /* Get patchlevel */
  out->patchlevel = strtol(cp,&eos,10);
  if (!eos || eos==cp) return -1;
  cp = eos;

  /* Get cvs status and status tag. */
  if (*cp == '-' || *cp == '.')
    ++cp;
  strlcpy(out->status_tag, cp, sizeof(out->status_tag));
  if (0==strcmp(cp, "cvs")) {
    out->cvs = IS_CVS;
  } else {
    out->cvs = IS_NOT_CVS;
  }

  return 0;
}

/** Compare two tor versions; Return <0 if a < b; 0 if a ==b, >0 if a >
 * b. */
int tor_version_compare(tor_version_t *a, tor_version_t *b)
{
  int i;
  tor_assert(a);
  tor_assert(b);
  if ((i = a->major - b->major))
    return i;
  else if ((i = a->minor - b->minor))
    return i;
  else if ((i = a->micro - b->micro))
    return i;
  else if ((i = a->status - b->status))
    return i;
  else if ((i = a->patchlevel - b->patchlevel))
    return i;

  if (a->major > 0 || a->minor > 0) {
    return strcmp(a->status_tag, b->status_tag);
  } else {
    return (a->cvs - b->cvs);
  }
}

static int
tor_version_same_series(tor_version_t *a, tor_version_t *b)
{
  tor_assert(a);
  tor_assert(b);
  return ((a->major == b->major) &&
          (a->minor == b->minor) &&
          (a->micro == b->micro));
}
