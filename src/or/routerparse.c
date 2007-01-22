/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char routerparse_c_id[] =
  "$Id$";

/**
 * \file routerparse.c
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
  K_NETWORK_STATUS_VERSION,
  K_DIR_SOURCE,
  K_DIR_OPTIONS,
  K_CLIENT_VERSIONS,
  K_SERVER_VERSIONS,
  K_R,
  K_S,
  K_V,
  K_EVENTDNS,
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
  NO_ARGS,     /**< No arguments, ever. */
  ARGS,        /**< A list of arguments separated by spaces. */
  CONCAT_ARGS, /**< The rest of the line, treated as a single argument. */
} arg_syntax;

/** Rules for whether the keyword needs an object. */
typedef enum {
  NO_OBJ,      /**< No object, ever. */
  NEED_OBJ,    /**< Object is required. */
  NEED_KEY,    /**< Object is required, and must be a public key. */
  OBJ_OK,      /**< Object is optional. */
} obj_syntax;

/** Rules for where a keyword can appear. */
typedef enum {
  DIR = 1,        /**< Appears only in directory. */
  RTR = 2,        /**< Appears only in router descriptor or runningrouters. */
  NETSTATUS = 4,  /**< v2 or later ("versioned") network status. */
  ANYSIGNED = 7,  /**< Any "full" document (that is, not a router status.) */
  RTRSTATUS = 8,  /**< Router-status portion of a versioned network status. */
  ANY = 15,       /**< Appears in any document type. */
} where_syntax;

/** Table mapping keywords to token value and to argument rules. */
static struct {
  const char *t; directory_keyword v; arg_syntax s; obj_syntax os; int ws;
} token_table[] = {
  { "accept",              K_ACCEPT,              ARGS,    NO_OBJ,  RTR },
  { "directory-signature", K_DIRECTORY_SIGNATURE, ARGS,    NEED_OBJ,
                                                           DIR|NETSTATUS},
  { "r",                   K_R,                   ARGS,    NO_OBJ, RTRSTATUS },
  { "s",                   K_S,                   ARGS,    NO_OBJ, RTRSTATUS },
  { "v",                   K_V,               CONCAT_ARGS, NO_OBJ, RTRSTATUS },
  { "reject",              K_REJECT,              ARGS,    NO_OBJ,  RTR },
  { "router",              K_ROUTER,              ARGS,    NO_OBJ,  RTR },
  { "recommended-software",K_RECOMMENDED_SOFTWARE,ARGS,    NO_OBJ,  DIR },
  { "signed-directory",    K_SIGNED_DIRECTORY,    NO_ARGS, NO_OBJ,  DIR },
  { "signing-key",         K_SIGNING_KEY,         NO_ARGS, NEED_KEY,RTR },
  { "onion-key",           K_ONION_KEY,           NO_ARGS, NEED_KEY,RTR },
  { "router-signature",    K_ROUTER_SIGNATURE,    NO_ARGS, NEED_OBJ,RTR },
  { "running-routers",     K_RUNNING_ROUTERS,     ARGS,    NO_OBJ,  DIR },
  { "router-status",       K_ROUTER_STATUS,       ARGS,    NO_OBJ,  DIR },
  { "bandwidth",           K_BANDWIDTH,           ARGS,    NO_OBJ,  RTR },
  { "platform",            K_PLATFORM,        CONCAT_ARGS, NO_OBJ,  RTR },
  { "published",           K_PUBLISHED,       CONCAT_ARGS, NO_OBJ, ANYSIGNED },
  { "opt",                 K_OPT,             CONCAT_ARGS, OBJ_OK, ANY },
  { "contact",             K_CONTACT,         CONCAT_ARGS, NO_OBJ, ANYSIGNED },
  { "network-status",      K_NETWORK_STATUS,      NO_ARGS, NO_OBJ,  DIR },
  { "uptime",              K_UPTIME,              ARGS,    NO_OBJ,  RTR },
  { "dir-signing-key",     K_DIR_SIGNING_KEY,     ARGS,    OBJ_OK,
                                                                DIR|NETSTATUS},
  { "family",              K_FAMILY,              ARGS,    NO_OBJ,  RTR },
  { "fingerprint",         K_FINGERPRINT,     CONCAT_ARGS, NO_OBJ, ANYSIGNED },
  { "hibernating",         K_HIBERNATING,         ARGS,    NO_OBJ,  RTR },
  { "read-history",        K_READ_HISTORY,        ARGS,    NO_OBJ,  RTR },
  { "write-history",       K_WRITE_HISTORY,       ARGS,    NO_OBJ,  RTR },
  { "network-status-version", K_NETWORK_STATUS_VERSION,
                                                  ARGS,    NO_OBJ, NETSTATUS },
  { "dir-source",          K_DIR_SOURCE,          ARGS,    NO_OBJ, NETSTATUS },
  { "dir-options",         K_DIR_OPTIONS,         ARGS,    NO_OBJ, NETSTATUS },
  { "client-versions",     K_CLIENT_VERSIONS,     ARGS,    NO_OBJ, NETSTATUS },
  { "server-versions",     K_SERVER_VERSIONS,     ARGS,    NO_OBJ, NETSTATUS },
  { "eventdns",            K_EVENTDNS,            ARGS,    NO_OBJ, RTR },
  { NULL, _NIL, NO_ARGS, NO_OBJ, ANY }
};

/* static function prototypes */
static int router_add_exit_policy(routerinfo_t *router,directory_token_t *tok);
static addr_policy_t *router_parse_addr_policy(directory_token_t *tok);
static addr_policy_t *router_parse_addr_policy_private(directory_token_t *tok);

static int router_get_hash_impl(const char *s, char *digest,
                                const char *start_str, const char *end_str);
static void token_free(directory_token_t *tok);
static smartlist_t *find_all_exitpolicy(smartlist_t *s);
static directory_token_t *find_first_by_keyword(smartlist_t *s,
                                                directory_keyword keyword);
static int tokenize_string(const char *start, const char *end,
                           smartlist_t *out, where_syntax where);
static directory_token_t *get_next_token(const char **s, where_syntax where);
static int check_directory_signature(const char *digest,
                                     directory_token_t *tok,
                                     crypto_pk_env_t *pkey,
                                     crypto_pk_env_t *declared_key,
                                     int check_authority);
static crypto_pk_env_t *find_dir_signing_key(const char *str);
static int tor_version_same_series(tor_version_t *a, tor_version_t *b);

/** Set <b>digest</b> to the SHA-1 digest of the hash of the directory in
 * <b>s</b>.  Return 0 on success, -1 on failure.
 */
int
router_get_dir_hash(const char *s, char *digest)
{
  return router_get_hash_impl(s,digest,
                              "signed-directory","\ndirectory-signature");
}

/** Set <b>digest</b> to the SHA-1 digest of the hash of the first router in
 * <b>s</b>. Return 0 on success, -1 on failure.
 */
int
router_get_router_hash(const char *s, char *digest)
{
  return router_get_hash_impl(s,digest,
                              "router ","\nrouter-signature");
}

/** Set <b>digest</b> to the SHA-1 digest of the hash of the running-routers
 * string in <b>s</b>. Return 0 on success, -1 on failure.
 */
int
router_get_runningrouters_hash(const char *s, char *digest)
{
  return router_get_hash_impl(s,digest,
                              "network-status","\ndirectory-signature");
}

/** Set <b>digest</b> to the SHA-1 digest of the hash of the network-status
 * string in <b>s</b>.  Return 0 on success, -1 on failure. */
int
router_get_networkstatus_v2_hash(const char *s, char *digest)
{
  return router_get_hash_impl(s,digest,
                            "network-status-version","\ndirectory-signature");
}

/** Helper: used to generate signatures for routers, directories and
 * network-status objects.  Given a digest in <b>digest</b> and a secret
 * <b>private_key</b>, generate an PKCS1-padded signature, BASE64-encode it,
 * surround it with -----BEGIN/END----- pairs, and write it to the
 * <b>buf_len</b>-byte buffer at <b>buf</b>.  Return 0 on success, -1 on
 * failure.
 */
int
router_append_dirobj_signature(char *buf, size_t buf_len, const char *digest,
                               crypto_pk_env_t *private_key)
{
  char signature[PK_BYTES];
  int i;

  if (crypto_pk_private_sign(private_key, signature, digest, DIGEST_LEN) < 0) {

    log_warn(LD_BUG,"Couldn't sign digest.");
    return -1;
  }
  if (strlcat(buf, "-----BEGIN SIGNATURE-----\n", buf_len) >= buf_len)
    goto truncated;

  i = strlen(buf);
  if (base64_encode(buf+i, buf_len-i, signature, 128) < 0) {
    log_warn(LD_BUG,"couldn't base64-encode signature");
    tor_free(buf);
    return -1;
  }

  if (strlcat(buf, "-----END SIGNATURE-----\n", buf_len) >= buf_len)
    goto truncated;

  return 0;
 truncated:
  log_warn(LD_BUG,"tried to exceed string length.");
  return -1;
}

/** Return VS_RECOMMENDED if <b>myversion</b> is contained in
 * <b>versionlist</b>.  Else, return VS_OLD if every member of
 * <b>versionlist</b> is newer than <b>myversion</b>.  Else, return
 * VS_NEW_IN_SERIES if there is at least one member of <b>versionlist</b> in
 * the same series (major.minor.micro) as <b>myversion</b>, but no such member
 * is newer than <b>myversion.</b>.  Else, return VS_NEW if every memeber of
 * <b>versionlist</b> is older than <b>myversion</b>.  Else, return
 * VS_UNRECOMMENDED.
 *
 * (versionlist is a comma-separated list of version strings,
 * optionally prefixed with "Tor".  Versions that can't be parsed are
 * ignored.)
 */
version_status_t
tor_version_is_obsolete(const char *myversion, const char *versionlist)
{
  tor_version_t mine, other;
  int found_newer = 0, found_older = 0, found_newer_in_series = 0,
    found_any_in_series = 0, r, same;
  version_status_t ret = VS_UNRECOMMENDED;
  smartlist_t *version_sl;

  log_debug(LD_CONFIG,"Checking whether version '%s' is in '%s'",
            myversion, versionlist);

  if (tor_version_parse(myversion, &mine)) {
    log_err(LD_BUG,"I couldn't parse my own version (%s)", myversion);
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
        ret = VS_RECOMMENDED;
        goto done;
      } else if (r<0) {
        found_newer = 1;
        if (same)
          found_newer_in_series = 1;
      } else if (r>0) {
        found_older = 1;
      }
    }
  });

  /* We didn't find the listed version. Is it new or old? */
  if (found_any_in_series && !found_newer_in_series) {
    ret = VS_NEW_IN_SERIES;
  } else if (found_newer && !found_older) {
    ret = VS_OLD;
  } else if (found_older && !found_newer) {
    ret = VS_NEW;
  } else {
    ret = VS_UNRECOMMENDED;
  }

 done:
  SMARTLIST_FOREACH(version_sl, char *, version, tor_free(version));
  smartlist_free(version_sl);
  return ret;
}

/** Return the combined status of the current version, given that we know of
 * one set of networkstatuses that give us status <b>a</b>, and another that
 * gives us status <b>b</b>.
 *
 * For example, if one authority thinks that we're NEW, and another thinks
 * we're OLD, we're simply UNRECOMMENDED.
 *
 * This function does not handle calculating whether we're RECOMMENDED; that
 * follows a simple majority rule.  This function simply calculates *why*
 * we're not recommended (if we're not).
 */
version_status_t
version_status_join(version_status_t a, version_status_t b)
{
  if (a == b)
    return a;
  else if (a == VS_UNRECOMMENDED || b == VS_UNRECOMMENDED)
    return VS_UNRECOMMENDED;
  else if (a == VS_RECOMMENDED)
    return b;
  else if (b == VS_RECOMMENDED)
    return a;
  /* Okay.  Neither is 'recommended' or 'unrecommended', and they differ. */
  else if (a == VS_OLD || b == VS_OLD)
    return VS_UNRECOMMENDED;
  /* One is VS_NEW, the other is VS_NEW_IN_SERIES */
  else
    return VS_NEW_IN_SERIES;
}

/** Read a signed directory from <b>str</b>.  If it's well-formed, return 0.
 * Otherwise, return -1.  If we're a directory cache, cache it.
 */
int
router_parse_directory(const char *str)
{
  directory_token_t *tok;
  char digest[DIGEST_LEN];
  time_t published_on;
  int r;
  const char *end, *cp;
  smartlist_t *tokens = NULL;
  crypto_pk_env_t *declared_key = NULL;

  /* XXXX This could be simplified a lot, but it will all go away
   * once pre-0.1.1.8 is obsolete, and for now it's better not to
   * touch it. */

  if (router_get_dir_hash(str, digest)) {
    log_warn(LD_DIR, "Unable to compute digest of directory");
    goto err;
  }
  log_debug(LD_DIR,"Received directory hashes to %s",hex_str(digest,4));

  /* Check signature first, before we try to tokenize. */
  cp = str;
  while (cp && (end = strstr(cp+1, "\ndirectory-signature")))
    cp = end;
  if (cp == str || !cp) {
    log_warn(LD_DIR, "No signature found on directory."); goto err;
  }
  ++cp;
  tokens = smartlist_create();
  if (tokenize_string(cp,strchr(cp,'\0'),tokens,DIR)) {
    log_warn(LD_DIR, "Error tokenizing directory signature"); goto err;
  }
  if (smartlist_len(tokens) != 1) {
    log_warn(LD_DIR, "Unexpected number of tokens in signature"); goto err;
  }
  tok=smartlist_get(tokens,0);
  if (tok->tp != K_DIRECTORY_SIGNATURE) {
    log_warn(LD_DIR,"Expected a single directory signature"); goto err;
  }
  declared_key = find_dir_signing_key(str);
  note_crypto_pk_op(VERIFY_DIR);
  if (check_directory_signature(digest, tok, NULL, declared_key, 1)<0)
    goto err;

  SMARTLIST_FOREACH(tokens, directory_token_t *, tok, token_free(tok));
  smartlist_free(tokens);
  tokens = NULL;

  /* Now try to parse the first part of the directory. */
  if ((end = strstr(str,"\nrouter "))) {
    ++end;
  } else if ((end = strstr(str, "\ndirectory-signature"))) {
    ++end;
  } else {
    end = str + strlen(str);
  }

  tokens = smartlist_create();
  if (tokenize_string(str,end,tokens,DIR)) {
    log_warn(LD_DIR, "Error tokenizing directory"); goto err;
  }

  if (!(tok = find_first_by_keyword(tokens, K_PUBLISHED))) {
    log_warn(LD_DIR, "Missing published time on directory.");
    goto err;
  }
  tor_assert(tok->n_args == 1);

  if (parse_iso_time(tok->args[0], &published_on) < 0) {
     goto err;
  }

  /* Now that we know the signature is okay, and we have a
   * publication time, cache the directory. */
  if (get_options()->DirPort && !get_options()->V1AuthoritativeDir)
    dirserv_set_cached_directory(str, published_on, 0);

  r = 0;
  goto done;
 err:
  r = -1;
 done:
  if (declared_key) crypto_free_pk_env(declared_key);
  if (tokens) {
    SMARTLIST_FOREACH(tokens, directory_token_t *, tok, token_free(tok));
    smartlist_free(tokens);
  }
  return r;
}

/** Read a signed router status statement from <b>str</b>.  If it's
 * well-formed, return 0.  Otherwise, return -1.  If we're a directory cache,
 * cache it.*/
int
router_parse_runningrouters(const char *str)
{
  char digest[DIGEST_LEN];
  directory_token_t *tok;
  time_t published_on;
  int r = -1;
  crypto_pk_env_t *declared_key = NULL;
  smartlist_t *tokens = NULL;

  if (router_get_runningrouters_hash(str, digest)) {
    log_warn(LD_DIR, "Unable to compute digest of running-routers");
    goto err;
  }
  tokens = smartlist_create();
  if (tokenize_string(str,str+strlen(str),tokens,DIR)) {
    log_warn(LD_DIR, "Error tokenizing running-routers"); goto err;
  }
  tok = smartlist_get(tokens,0);
  if (tok->tp != K_NETWORK_STATUS) {
    log_warn(LD_DIR, "Network-status starts with wrong token");
    goto err;
  }

  if (!(tok = find_first_by_keyword(tokens, K_PUBLISHED))) {
    log_warn(LD_DIR, "Missing published time on running-routers.");
    goto err;
  }
  tor_assert(tok->n_args == 1);
  if (parse_iso_time(tok->args[0], &published_on) < 0) {
     goto err;
  }
  if (!(tok = find_first_by_keyword(tokens, K_DIRECTORY_SIGNATURE))) {
    log_warn(LD_DIR, "Missing signature on running-routers");
    goto err;
  }
  declared_key = find_dir_signing_key(str);
  note_crypto_pk_op(VERIFY_DIR);
  if (check_directory_signature(digest, tok, NULL, declared_key, 1) < 0)
    goto err;

  /* Now that we know the signature is okay, and we have a
   * publication time, cache the list. */
  if (get_options()->DirPort && !get_options()->V1AuthoritativeDir)
    dirserv_set_cached_directory(str, published_on, 1);

  r = 0;
 err:
  if (declared_key) crypto_free_pk_env(declared_key);
  if (tokens) {
    SMARTLIST_FOREACH(tokens, directory_token_t *, tok, token_free(tok));
    smartlist_free(tokens);
  }
  return r;
}

/** Given a directory or running-routers string in <b>str</b>, try to
 * find the its dir-signing-key token (if any).  If this token is
 * present, extract and return the key.  Return NULL on failure. */
static crypto_pk_env_t *
find_dir_signing_key(const char *str)
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

  tok = get_next_token(&cp, DIR);
  if (!tok) {
    log_warn(LD_DIR, "Unparseable dir-signing-key token");
    return NULL;
  }
  if (tok->tp != K_DIR_SIGNING_KEY) {
    log_warn(LD_DIR, "Dir-signing-key token did not parse as expected");
    return NULL;
  }

  if (tok->key) {
    key = tok->key;
    tok->key = NULL; /* steal reference. */
  } else {
    log_warn(LD_DIR, "Dir-signing-key token contained no key");
    return NULL;
  }

  token_free(tok);
  return key;
}

/** Return true iff <b>key</b> is allowed to sign directories.
 */
static int
dir_signing_key_is_trusted(crypto_pk_env_t *key)
{
  char digest[DIGEST_LEN];
  if (!key) return 0;
  if (crypto_pk_get_digest(key, digest) < 0) {
    log_warn(LD_DIR, "Error computing dir-signing-key digest");
    return 0;
  }
  if (!router_digest_is_trusted_dir(digest)) {
    log_warn(LD_DIR, "Listed dir-signing-key is not trusted");
    return 0;
  }
  return 1;
}

/** Check whether the K_DIRECTORY_SIGNATURE token in <b>tok</b> has a
 * good signature for <b>digest</b>.
 *
 * If <b>declared_key</b> is set, the directory has declared what key
 * was used to sign it, so we will use that key only if it is an
 * authoritative directory signing key or if check_authority is 0.
 *
 * Otherwise, if pkey is provided, try to use it.
 *
 * (New callers should always use <b>declared_key</b> when possible;
 * <b>pkey</b> is only for debugging.)
 */
static int
check_directory_signature(const char *digest,
                          directory_token_t *tok,
                          crypto_pk_env_t *pkey,
                          crypto_pk_env_t *declared_key,
                          int check_authority)
{
  char signed_digest[PK_BYTES];
  crypto_pk_env_t *_pkey = NULL;

  if (tok->n_args != 1) {
    log_warn(LD_DIR, "Too many or too few arguments to directory-signature");
    return -1;
  }

  if (declared_key) {
    if (!check_authority || dir_signing_key_is_trusted(declared_key))
      _pkey = declared_key;
  }
  if (!_pkey && pkey) {
    /* pkey provided for debugging purposes */
    _pkey = pkey;
  }
  if (!_pkey) {
    log_warn(LD_DIR,
             "Obsolete directory format (dir signing key not present) or "
             "signing key not trusted--rejecting.");
    return -1;
  }

  if (strcmp(tok->object_type, "SIGNATURE") || tok->object_size != 128) {
    log_warn(LD_DIR, "Bad object type or length on directory signature");
    return -1;
  }

  tor_assert(_pkey);

  if (crypto_pk_public_checksig(_pkey, signed_digest, tok->object_body, 128)
      != 20) {
    log_warn(LD_DIR, "Error reading directory: invalid signature.");
    return -1;
  }
  log_debug(LD_DIR,"Signed directory hash starts %s",
            hex_str(signed_digest,4));
  if (memcmp(digest, signed_digest, DIGEST_LEN)) {
    log_warn(LD_DIR, "Error reading directory: signature does not match.");
    return -1;
  }
  return 0;
}

/** Given a string *<b>s</b> containing a concatenated sequence of router
 * descriptors, parses them and stores the result in <b>dest</b>.  All routers
 * are marked running and valid.  Advances *s to a point immediately
 * following the last router entry.  Ignore any trailing router entries that
 * are not complete.
 *
 * If <b>saved_location</b> isn't SAVED_IN_CACHE, make a local copy of each
 * descriptor in the signed_descriptor_body field of each routerinfo_t.  If it
 * isn't SAVED_NOWHERE, remember the offset of each descriptor.
 *
 * Returns 0 on success and -1 on failure.
 */
int
router_parse_list_from_string(const char **s, smartlist_t *dest,
                              saved_location_t saved_location)
{
  routerinfo_t *router;
  const char *end, *cp, *start;

  tor_assert(s);
  tor_assert(*s);
  tor_assert(dest);

  start = *s;
  while (1) {
    *s = eat_whitespace(*s);
    /* Don't start parsing the rest of *s unless it contains a router. */
    if (strcmpstart(*s, "router ")!=0)
      break;
    if ((end = strstr(*s+1, "\nrouter "))) {
      cp = end;
      end++;
    } else if ((end = strstr(*s+1, "\ndirectory-signature"))) {
      cp = end;
      end++;
    } else {
      cp = end = *s+strlen(*s);
    }

    while (cp > *s && (!*cp || TOR_ISSPACE(*cp)))
      --cp;
    /* cp now points to the last non-space character in this descriptor. */

    while (cp > *s  && *cp != '\n')
      --cp;
    /* cp now points to the first \n before the last non-blank line in this
     * descriptor */

    if (strcmpstart(cp, "\n-----END SIGNATURE-----\n")) {
      log_info(LD_DIR, "Ignoring truncated router descriptor.");
      *s = end;
      continue;
    }

    router = router_parse_entry_from_string(*s, end,
                                            saved_location != SAVED_IN_CACHE);

    if (!router) {
      log_warn(LD_DIR, "Error reading router; skipping");
      *s = end;
      continue;
    }
    if (saved_location != SAVED_NOWHERE) {
      router->cache_info.saved_location = saved_location;
      router->cache_info.saved_offset = *s - start;
    }
    *s = end;
    smartlist_add(dest, router);
  }

  return 0;
}

/* For debugging: define to count every descriptor digest we've seen so we
 * know if we need to try harder to avoid duplicate verifies. */
#undef COUNT_DISTINCT_DIGESTS

#ifdef COUNT_DISTINCT_DIGESTS
static digestmap_t *verified_digests = NULL;
#endif

void
dump_distinct_digest_count(int severity)
{
#ifdef COUNT_DISTINCT_DIGESTS
  if (!verified_digests)
    verified_digests = digestmap_new();
  log(severity, LD_GENERAL, "%d *distinct* router digests verified",
      digestmap_size(verified_digests));
#else
  (void)severity; /* suppress "unused parameter" warning */
#endif
}

/** Helper function: reads a single router entry from *<b>s</b> ...
 * *<b>end</b>.  Mallocs a new router and returns it if all goes well, else
 * returns NULL.  If <b>cache_copy</b> is true, duplicate the contents of
 * s through end into the signed_descriptor_body of the resulting
 * routerinfo_t.
 */
routerinfo_t *
router_parse_entry_from_string(const char *s, const char *end,
                               int cache_copy)
{
  routerinfo_t *router = NULL;
  char signed_digest[128];
  char digest[128];
  smartlist_t *tokens = NULL, *exit_policy_tokens = NULL;
  directory_token_t *tok;
  int t;
  struct in_addr in;

  if (!end) {
    end = s + strlen(s);
  }

  /* point 'end' to a point immediately after the final newline. */
  while (end > s+2 && *(end-1) == '\n' && *(end-2) == '\n')
    --end;

  if (router_get_router_hash(s, digest) < 0) {
    log_warn(LD_DIR, "Couldn't compute router hash.");
    return NULL;
  }
  tokens = smartlist_create();
  if (tokenize_string(s,end,tokens,RTR)) {
    log_warn(LD_DIR, "Error tokeninzing router descriptor.");
    goto err;
  }

  if (smartlist_len(tokens) < 2) {
    log_warn(LD_DIR, "Impossibly short router descriptor.");
    goto err;
  }

  tok = smartlist_get(tokens,0);
  if (tok->tp != K_ROUTER) {
    log_warn(LD_DIR,"Entry does not start with \"router\"");
    goto err;
  }

  router = tor_malloc_zero(sizeof(routerinfo_t));
  router->routerlist_index = -1;
  if (cache_copy)
    router->cache_info.signed_descriptor_body = tor_strndup(s, end-s);
  router->cache_info.signed_descriptor_len = end-s;
  memcpy(router->cache_info.signed_descriptor_digest, digest, DIGEST_LEN);

  if (tok->n_args >= 5) {
    router->nickname = tor_strdup(tok->args[0]);
    if (!is_legal_nickname(router->nickname)) {
      log_warn(LD_DIR,"Router nickname is invalid");
      goto err;
    }
    router->address = tor_strdup(tok->args[1]);
    if (!tor_inet_aton(router->address, &in)) {
      log_warn(LD_DIR,"Router address is not an IP.");
      goto err;
    }
    router->addr = ntohl(in.s_addr);

    router->or_port =
      (uint16_t) tor_parse_long(tok->args[2],10,0,65535,NULL,NULL);
    router->dir_port =
      (uint16_t) tor_parse_long(tok->args[4],10,0,65535,NULL,NULL);
  } else {
    log_warn(LD_DIR,"Wrong # of arguments to \"router\" (%d)",tok->n_args);
    goto err;
  }

  tok = find_first_by_keyword(tokens, K_BANDWIDTH);
  if (!tok) {
    log_warn(LD_DIR,"No bandwidth declared; failing.");
    goto err;
  } else {
    if (tok->n_args < 3) {
      log_warn(LD_DIR,
               "Not enough arguments to \"bandwidth\" in server descriptor.");
      goto err;
    }
    router->bandwidthrate =
      tor_parse_long(tok->args[0],10,0,INT_MAX,NULL,NULL);
    router->bandwidthburst =
      tor_parse_long(tok->args[1],10,0,INT_MAX,NULL,NULL);
    router->bandwidthcapacity =
      tor_parse_long(tok->args[2],10,0,INT_MAX,NULL,NULL);
  }

  if ((tok = find_first_by_keyword(tokens, K_UPTIME))) {
    if (tok->n_args != 1) {
      log_warn(LD_DIR, "Unrecognized number of args on K_UPTIME; skipping.");
    } else {
      router->uptime = tor_parse_long(tok->args[0],10,0,LONG_MAX,NULL,NULL);
    }
  }

  if ((tok = find_first_by_keyword(tokens, K_HIBERNATING))) {
    if (tok->n_args < 1) {
      log_warn(LD_DIR, "Too few args on 'hibernating' keyword. Skipping.");
    } else {
      router->is_hibernating
        = (tor_parse_long(tok->args[0],10,0,LONG_MAX,NULL,NULL) != 0);
    }
  }

  if (!(tok = find_first_by_keyword(tokens, K_PUBLISHED))) {
    log_warn(LD_DIR, "Missing published time on router descriptor"); goto err;
  }
  tor_assert(tok->n_args == 1);
  if (parse_iso_time(tok->args[0], &router->cache_info.published_on) < 0)
    goto err;

  if (!(tok = find_first_by_keyword(tokens, K_ONION_KEY))) {
    log_warn(LD_DIR, "Missing onion key"); goto err;
  }
  if (crypto_pk_keysize(tok->key) != PK_BYTES) {
    log_warn(LD_DIR, "Wrong size on onion key: %d bits!",
             (int)crypto_pk_keysize(tok->key)*8);
    goto err;
  }
  router->onion_pkey = tok->key;
  tok->key = NULL; /* Prevent free */

  if (!(tok = find_first_by_keyword(tokens, K_SIGNING_KEY))) {
    log_warn(LD_DIR, "Missing identity key"); goto err;
  }
  if (crypto_pk_keysize(tok->key) != PK_BYTES) {
    log_warn(LD_DIR, "Wrong size on identity key: %d bits!",
           (int)crypto_pk_keysize(tok->key)*8);
    goto err;
  }
  router->identity_pkey = tok->key;
  tok->key = NULL; /* Prevent free */
  if (crypto_pk_get_digest(router->identity_pkey,
                           router->cache_info.identity_digest)) {
    log_warn(LD_DIR, "Couldn't calculate key digest"); goto err;
  }

  if ((tok = find_first_by_keyword(tokens, K_FINGERPRINT))) {
    /* If there's a fingerprint line, it must match the identity digest. */
    char d[DIGEST_LEN];
    if (tok->n_args < 1) {
      log_warn(LD_DIR, "Too few arguments to router fingerprint");
      goto err;
    }
    tor_strstrip(tok->args[0], " ");
    if (base16_decode(d, DIGEST_LEN, tok->args[0], strlen(tok->args[0]))) {
      log_warn(LD_DIR, "Couldn't decode router fingerprint %s",
               escaped(tok->args[0]));
      goto err;
    }
    if (memcmp(d,router->cache_info.identity_digest, DIGEST_LEN)!=0) {
      log_warn(LD_DIR, "Fingerprint '%s' does not match identity digest.",
               tok->args[0]);
      goto err;
    }
  }

  if ((tok = find_first_by_keyword(tokens, K_PLATFORM))) {
    router->platform = tor_strdup(tok->args[0]);
  }

  if ((tok = find_first_by_keyword(tokens, K_CONTACT))) {
    router->contact_info = tor_strdup(tok->args[0]);
  }

  if ((tok = find_first_by_keyword(tokens, K_EVENTDNS))) {
    router->has_old_dnsworkers = tok->n_args && !strcmp(tok->args[0], "0");
  } else if (router->platform) {
    if (! tor_version_as_new_as(router->platform, "0.1.2.2-alpha"))
      router->has_old_dnsworkers = 1;
  }

  exit_policy_tokens = find_all_exitpolicy(tokens);
  SMARTLIST_FOREACH(exit_policy_tokens, directory_token_t *, t,
                    if (router_add_exit_policy(router,t)<0) {
                      log_warn(LD_DIR,"Error in exit policy");
                      goto err;
                    });

  if ((tok = find_first_by_keyword(tokens, K_FAMILY)) && tok->n_args) {
    int i;
    router->declared_family = smartlist_create();
    for (i=0;i<tok->n_args;++i) {
      if (!is_legal_nickname_or_hexdigest(tok->args[i])) {
        log_warn(LD_DIR, "Illegal nickname %s in family line",
                 escaped(tok->args[i]));
        goto err;
      }
      smartlist_add(router->declared_family, tor_strdup(tok->args[i]));
    }
  }

  if (!(tok = find_first_by_keyword(tokens, K_ROUTER_SIGNATURE))) {
    log_warn(LD_DIR, "Missing router signature");
    goto err;
  }
  if (strcmp(tok->object_type, "SIGNATURE") || tok->object_size != 128) {
    log_warn(LD_DIR, "Bad object type or length on router signature");
    goto err;
  }
  note_crypto_pk_op(VERIFY_RTR);
#ifdef COUNT_DISTINCT_DIGESTS
  if (!verified_digests)
    verified_digests = digestmap_new();
  digestmap_set(verified_digests, signed_digest, (void*)(uintptr_t)1);
#endif
  if ((t=crypto_pk_public_checksig(router->identity_pkey, signed_digest,
                                   tok->object_body, 128)) != 20) {
    log_warn(LD_DIR, "Invalid signature %d",t);
    goto err;
  }
  if (memcmp(digest, signed_digest, DIGEST_LEN)) {
    log_warn(LD_DIR, "Mismatched signature");
    goto err;
  }

  if (!router->or_port) {
    log_warn(LD_DIR,"or_port unreadable or 0. Failing.");
    goto err;
  }
  if (!router->bandwidthrate) {
    log_warn(LD_DIR,"bandwidthrate unreadable or 0. Failing.");
    goto err;
  }
  if (!router->platform) {
    router->platform = tor_strdup("<unknown>");
  }

  goto done;

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

/** Helper: given a string <b>s</b>, return the start of the next router-status
 * object (starting with "r " at the start of a line).  If none is found,
 * return the start of the next directory signature.  If none is found, return
 * the end of the string. */
static INLINE const char *
find_start_of_next_routerstatus(const char *s)
{
  const char *eos = strstr(s, "\nr ");
  if (!eos)
    eos = strstr(s, "\ndirectory-signature");
  if (eos)
    return eos+1;
  else
    return s + strlen(s);
}

/** Given a string at *<b>s</b>, containing a routerstatus object, and an
 * empty smartlist at <b>tokens</b>, parse and return the first router status
 * object in the string, and advance *<b>s</b> to just after the end of the
 * router status.  Return NULL and advance *<b>s</b> on error. */
static routerstatus_t *
routerstatus_parse_entry_from_string(const char **s, smartlist_t *tokens)
{
  const char *eos;
  routerstatus_t *rs = NULL;
  directory_token_t *tok;
  char timebuf[ISO_TIME_LEN+1];
  struct in_addr in;

  tor_assert(tokens);

  eos = find_start_of_next_routerstatus(*s);

  if (tokenize_string(*s, eos, tokens, RTRSTATUS)) {
    log_warn(LD_DIR, "Error tokenizing router status");
    goto err;
  }
  if (smartlist_len(tokens) < 1) {
    log_warn(LD_DIR, "Impossibly short router status");
    goto err;
  }
  if (!(tok = find_first_by_keyword(tokens, K_R))) {
    log_warn(LD_DIR, "Missing 'r' keywork in router status; skipping.");
    goto err;
  }
  if (tok->n_args < 8) {
    log_warn(LD_DIR,
         "Too few arguments to 'r' keywork in router status; skipping.");
  }
  rs = tor_malloc_zero(sizeof(routerstatus_t));

  if (!is_legal_nickname(tok->args[0])) {
    log_warn(LD_DIR,
             "Invalid nickname %s in router status; skipping.",
             escaped(tok->args[0]));
    goto err;
  }
  strlcpy(rs->nickname, tok->args[0], sizeof(rs->nickname));

  if (digest_from_base64(rs->identity_digest, tok->args[1])) {
    log_warn(LD_DIR, "Error decoding identity digest %s",
             escaped(tok->args[1]));
    goto err;
  }

  if (digest_from_base64(rs->descriptor_digest, tok->args[2])) {
    log_warn(LD_DIR, "Error decoding descriptor digest %s",
             escaped(tok->args[2]));
    goto err;
  }

  if (tor_snprintf(timebuf, sizeof(timebuf), "%s %s",
                   tok->args[3], tok->args[4]) < 0 ||
      parse_iso_time(timebuf, &rs->published_on)<0) {
    log_warn(LD_DIR, "Error parsing time '%s %s'",
             tok->args[3], tok->args[4]);
    goto err;
  }

  if (tor_inet_aton(tok->args[5], &in) == 0) {
    log_warn(LD_DIR, "Error parsing router address in network-status %s",
             escaped(tok->args[5]));
    goto err;
  }
  rs->addr = ntohl(in.s_addr);

  rs->or_port =(uint16_t) tor_parse_long(tok->args[6],10,0,65535,NULL,NULL);
  rs->dir_port = (uint16_t) tor_parse_long(tok->args[7],10,0,65535,NULL,NULL);

  if ((tok = find_first_by_keyword(tokens, K_S))) {
    int i;
    for (i=0; i < tok->n_args; ++i) {
      if (!strcmp(tok->args[i], "Exit"))
        rs->is_exit = 1;
      else if (!strcmp(tok->args[i], "Stable"))
        rs->is_stable = 1;
      else if (!strcmp(tok->args[i], "Fast"))
        rs->is_fast = 1;
      else if (!strcmp(tok->args[i], "Running"))
        rs->is_running = 1;
      else if (!strcmp(tok->args[i], "Named"))
        rs->is_named = 1;
      else if (!strcmp(tok->args[i], "Valid"))
        rs->is_valid = 1;
      else if (!strcmp(tok->args[i], "V2Dir"))
        rs->is_v2_dir = 1;
      else if (!strcmp(tok->args[i], "Guard"))
        rs->is_possible_guard = 1;
      else if (!strcmp(tok->args[i], "BadExit"))
        rs->is_bad_exit = 1;
      else if (!strcmp(tok->args[i], "BadDirectory"))
        rs->is_bad_directory = 1;
    }
  }
  if ((tok = find_first_by_keyword(tokens, K_V)) && tok->n_args) {
    rs->version_known = 1;
    if (strcmpstart(tok->args[0], "Tor ")) {
      rs->version_supports_begindir = 1;
    } else {
      rs->version_supports_begindir =
        tor_version_as_new_as(tok->args[0], "0.1.2.2-alpha");
    }
  }

  if (!strcasecmp(rs->nickname, UNNAMED_ROUTER_NICKNAME))
    rs->is_named = 0;

  goto done;
 err:
  if (rs)
    routerstatus_free(rs);
  rs = NULL;
 done:
  SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_free(t));
  smartlist_clear(tokens);
  *s = eos;

  return rs;
}

/** Helper to sort a smartlist of pointers to routerstatus_t */
static int
_compare_routerstatus_entries(const void **_a, const void **_b)
{
  const routerstatus_t *a = *_a, *b = *_b;
  return memcmp(a->identity_digest, b->identity_digest, DIGEST_LEN);
}

static void
_free_duplicate_routerstatus_entry(void *e)
{
  log_warn(LD_DIR,
           "Network-status has two entries for the same router. "
           "Dropping one.");
  routerstatus_free(e);
}

/** Given a versioned (v2 or later) network-status object in <b>s</b>, try to
 * parse it and return the result.  Return NULL on failure.  Check the
 * signature of the network status, but do not (yet) check the signing key for
 * authority.
 */
networkstatus_t *
networkstatus_parse_from_string(const char *s)
{
  const char *eos;
  smartlist_t *tokens = smartlist_create();
  networkstatus_t *ns = NULL;
  char ns_digest[DIGEST_LEN];
  char tmp_digest[DIGEST_LEN];
  struct in_addr in;
  directory_token_t *tok;
  int i;

  if (router_get_networkstatus_v2_hash(s, ns_digest)) {
    log_warn(LD_DIR, "Unable to compute digest of network-status");
    goto err;
  }

  eos = find_start_of_next_routerstatus(s);
  if (tokenize_string(s, eos, tokens, NETSTATUS)) {
    log_warn(LD_DIR, "Error tokenizing network-status header.");
    goto err;
  }
  ns = tor_malloc_zero(sizeof(networkstatus_t));
  memcpy(ns->networkstatus_digest, ns_digest, DIGEST_LEN);

  if (!(tok = find_first_by_keyword(tokens, K_NETWORK_STATUS_VERSION))) {
    log_warn(LD_DIR, "Couldn't find network-status-version keyword");
    goto err;
  }

  if (!(tok = find_first_by_keyword(tokens, K_DIR_SOURCE))) {
    log_warn(LD_DIR, "Couldn't find dir-source keyword");
    goto err;
  }
  if (tok->n_args < 3) {
    log_warn(LD_DIR, "Too few arguments to dir-source keyword");
    goto err;
  }
  ns->source_address = tok->args[0]; tok->args[0] = NULL;
  if (tor_inet_aton(tok->args[1], &in) == 0) {
    log_warn(LD_DIR, "Error parsing network-status source address %s",
             escaped(tok->args[1]));
    goto err;
  }
  ns->source_addr = ntohl(in.s_addr);
  ns->source_dirport =
    (uint16_t) tor_parse_long(tok->args[2],10,0,65535,NULL,NULL);
  if (ns->source_dirport == 0) {
    log_warn(LD_DIR, "Directory source without dirport; skipping.");
    goto err;
  }

  if (!(tok = find_first_by_keyword(tokens, K_FINGERPRINT))) {
    log_warn(LD_DIR, "Couldn't find fingerprint keyword");
    goto err;
  }
  if (tok->n_args < 1) {
    log_warn(LD_DIR, "Too few arguments to networkstatus fingerprint");
    goto err;
  }
  if (base16_decode(ns->identity_digest, DIGEST_LEN, tok->args[0],
                    strlen(tok->args[0]))) {
    log_warn(LD_DIR, "Couldn't decode networkstatus fingerprint %s",
             escaped(tok->args[0]));
    goto err;
  }

  if ((tok = find_first_by_keyword(tokens, K_CONTACT)) && tok->n_args) {
    ns->contact = tok->args[0];
    tok->args[0] = NULL;
  }

  if (!(tok = find_first_by_keyword(tokens, K_DIR_SIGNING_KEY)) || !tok->key) {
    log_warn(LD_DIR, "Missing dir-signing-key");
    goto err;
  }
  ns->signing_key = tok->key;
  tok->key = NULL;

  if (crypto_pk_get_digest(ns->signing_key, tmp_digest)<0) {
    log_warn(LD_DIR, "Couldn't compute signing key digest");
    goto err;
  }
  if (memcmp(tmp_digest, ns->identity_digest, DIGEST_LEN)) {
    log_warn(LD_DIR,
             "network-status fingerprint did not match dir-signing-key");
    goto err;
  }

  if ((tok = find_first_by_keyword(tokens, K_DIR_OPTIONS))) {
    for (i=0; i < tok->n_args; ++i) {
      if (!strcmp(tok->args[i], "Names"))
        ns->binds_names = 1;
      if (!strcmp(tok->args[i], "Versions"))
        ns->recommends_versions = 1;
      if (!strcmp(tok->args[i], "BadExits"))
        ns->lists_bad_exits = 1;
      if (!strcmp(tok->args[i], "BadDirectories"))
        ns->lists_bad_directories = 1;
    }
  }

  if (ns->recommends_versions) {
    if (!(tok = find_first_by_keyword(tokens, K_CLIENT_VERSIONS)) ||
        tok->n_args<1) {
      log_warn(LD_DIR, "Missing client-versions");
    }
    ns->client_versions = tok->args[0];
    tok->args[0] = NULL;

    if (!(tok = find_first_by_keyword(tokens, K_SERVER_VERSIONS)) ||
        tok->n_args<1) {
      log_warn(LD_DIR, "Missing server-versions on versioning directory");
      goto err;
    }
    ns->server_versions = tok->args[0];
    tok->args[0] = NULL;
  }

  if (!(tok = find_first_by_keyword(tokens, K_PUBLISHED))) {
    log_warn(LD_DIR, "Missing published time on network-status.");
    goto err;
  }
  tor_assert(tok->n_args == 1);
  if (parse_iso_time(tok->args[0], &ns->published_on) < 0) {
     goto err;
  }

  ns->entries = smartlist_create();
  s = eos;
  SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_free(t));
  smartlist_clear(tokens);
  while (!strcmpstart(s, "r ")) {
    routerstatus_t *rs;
    if ((rs = routerstatus_parse_entry_from_string(&s, tokens)))
      smartlist_add(ns->entries, rs);
  }
  smartlist_sort(ns->entries, _compare_routerstatus_entries);
  smartlist_uniq(ns->entries, _compare_routerstatus_entries,
                 _free_duplicate_routerstatus_entry);

  if (tokenize_string(s, NULL, tokens, NETSTATUS)) {
    log_warn(LD_DIR, "Error tokenizing network-status footer.");
    goto err;
  }
  if (smartlist_len(tokens) < 1) {
    log_warn(LD_DIR, "Too few items in network-status footer.");
    goto err;
  }
  tok = smartlist_get(tokens, smartlist_len(tokens)-1);
  if (tok->tp != K_DIRECTORY_SIGNATURE) {
    log_warn(LD_DIR,
             "Expected network-status footer to end with a signature.");
    goto err;
  }

  note_crypto_pk_op(VERIFY_DIR);
  if (check_directory_signature(ns_digest, tok, NULL, ns->signing_key, 0))
    goto err;

  goto done;
 err:
  if (ns)
    networkstatus_free(ns);
  ns = NULL;
 done:
  SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_free(t));
  smartlist_free(tokens);

  return ns;
}

/** Parse the addr policy in the string <b>s</b> and return it.  If
 * assume_action is nonnegative, then insert its action (ADDR_POLICY_ACCEPT or
 * ADDR_POLICY_REJECT) for items that specify no action.
 */
addr_policy_t *
router_parse_addr_policy_from_string(const char *s, int assume_action)
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
    tmp[idx] = TOR_TOLOWER(s[idx]);
  }
  tmp[len]='\n';
  tmp[len+1]='\0';
  while (TOR_ISSPACE(*cp))
    ++cp;
  if ((*cp == '*' || TOR_ISDIGIT(*cp)) && assume_action >= 0) {
    char *new_str = tor_malloc(len+10);
    tor_snprintf(new_str, len+10, "%s %s\n",
                 assume_action == ADDR_POLICY_ACCEPT?"accept":"reject", cp);
    tor_free(tmp);
    cp = tmp = new_str;
  }
  tok = get_next_token(&cp, RTR);
  if (tok->tp == _ERR) {
    log_warn(LD_DIR, "Error reading address policy: %s", tok->error);
    goto err;
  }
  if (tok->tp != K_ACCEPT && tok->tp != K_REJECT) {
    log_warn(LD_DIR, "Expected 'accept' or 'reject'.");
    goto err;
  }

  /* Now that we've gotten an addr policy, add it to the router. */
  r = router_parse_addr_policy(tok);
  goto done;
 err:
  r = NULL;
 done:
  tor_free(tmp);
  token_free(tok);
  return r;
}

/** Add an exit policy stored in the token <b>tok</b> to the router info in
 * <b>router</b>.  Return 0 on success, -1 on failure. */
static int
router_add_exit_policy(routerinfo_t *router, directory_token_t *tok)
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
router_parse_addr_policy(directory_token_t *tok)
{
  addr_policy_t *newe;
  char *arg;
  char buf[POLICY_BUF_LEN];

  tor_assert(tok->tp == K_REJECT || tok->tp == K_ACCEPT);

  if (tok->n_args != 1)
    return NULL;
  arg = tok->args[0];

  if (!strcmpstart(arg,"private"))
    return router_parse_addr_policy_private(tok);

  newe = tor_malloc_zero(sizeof(addr_policy_t));

  newe->policy_type = (tok->tp == K_REJECT) ? ADDR_POLICY_REJECT
    : ADDR_POLICY_ACCEPT;

  if (parse_addr_and_port_range(arg, &newe->addr, &newe->msk,
                                &newe->prt_min, &newe->prt_max))
    goto policy_read_failed;

  if (policy_write_item(buf, sizeof(buf), newe) < 0)
    goto policy_read_failed;

  newe->string = tor_strdup(buf);
  return newe;

policy_read_failed:
  log_warn(LD_DIR,"Couldn't parse line %s. Dropping", escaped(arg));
  tor_free(newe);
  return NULL;
}

/** Parse an exit policy line of the format "accept/reject private:...".
 * This didn't exist until Tor 0.1.1.15, so nobody should generate it in
 * router descriptors until earlier versions are obsolete.
 */
static addr_policy_t *
router_parse_addr_policy_private(directory_token_t *tok)
{
  static const char *private_nets[] = {
    "0.0.0.0/8", "169.254.0.0/16",
    "127.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12",NULL };
  char *arg;
  addr_policy_t *result, **nextp;
  int net;
  uint16_t port_min, port_max;

  arg = tok->args[0];
  if (strcmpstart(arg, "private"))
    return NULL;
  arg += strlen("private");
  arg = (char*) eat_whitespace(arg);
  if (!arg || *arg != ':')
    return NULL;

  if (parse_port_range(arg+1, &port_min, &port_max)<0)
    return NULL;

  nextp = &result;
  for (net = 0; private_nets[net]; ++net) {
    size_t len;
    *nextp = tor_malloc_zero(sizeof(addr_policy_t));
    (*nextp)->policy_type = (tok->tp == K_REJECT) ? ADDR_POLICY_REJECT
      : ADDR_POLICY_ACCEPT;
    len = strlen(arg)+strlen(private_nets[net])+16;
    (*nextp)->string = tor_malloc(len+1);
    tor_snprintf((*nextp)->string, len, "%s %s%s",
                 tok->tp == K_REJECT ? "reject" : "accept",
                 private_nets[net], arg);
    if (parse_addr_and_port_range((*nextp)->string + 7,
                                  &(*nextp)->addr, &(*nextp)->msk,
                                  &(*nextp)->prt_min, &(*nextp)->prt_max)) {
      log_warn(LD_BUG, "Couldn't parse an address range we generated!");
      return NULL;
    }
    nextp = &(*nextp)->next;
  }

  return result;
}

/** Log and exit if <b>t</b> is malformed */
void
assert_addr_policy_ok(addr_policy_t *t)
{
  addr_policy_t *t2;
  while (t) {
    tor_assert(t->policy_type == ADDR_POLICY_REJECT ||
               t->policy_type == ADDR_POLICY_ACCEPT);
    tor_assert(t->prt_min <= t->prt_max);
    t2 = router_parse_addr_policy_from_string(t->string, -1);
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
 * of the token, and return the parsed token.  If 'where' is DIR
 * or RTR, reject all tokens of the wrong type.
 */
static directory_token_t *
get_next_token(const char **s, where_syntax where)
{
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
      if (!(token_table[i].ws & where)) {
        if (where == DIR) {
          RET_ERR("Found an out-of-place token in a directory section");
        } else if (where == RTR) {
          RET_ERR("Found an out-of-place token in a router descriptor");
        } else if (where == NETSTATUS) {
          RET_ERR("Found an out-of-place token in a network-status header");
        } else {
          RET_ERR("Found an out-of-place token in a router status body");
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

  return tok;
#undef RET_ERR
}

/** Read all tokens from a string between <b>start</b> and <b>end</b>, and add
 * them to <b>out</b>.  If <b>is_dir</b> is true, reject all non-directory
 * tokens; else reject all non-routerdescriptor tokens.
 */
static int
tokenize_string(const char *start, const char *end, smartlist_t *out,
                where_syntax where)
{
  const char **s;
  directory_token_t *tok = NULL;
  s = &start;
  if (!end)
    end = start+strlen(start);
  while (*s < end && (!tok || tok->tp != _EOF)) {
    tok = get_next_token(s, where);
    if (tok->tp == _ERR) {
      log_warn(LD_DIR, "parse error: %s", tok->error);
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

/** Compute the SHA-1 digest of the substring of <b>s</b> taken from the first
 * occurrence of <b>start_str</b> through the first newline after the first
 * subsequent occurrence of <b>end_str</b>; store the 20-byte result in
 * <b>digest</b>; return 0 on success.
 *
 * If no such substring exists, return -1.
 */
static int
router_get_hash_impl(const char *s, char *digest,
                     const char *start_str,
                     const char *end_str)
{
  char *start, *end;
  start = strstr(s, start_str);
  if (!start) {
    log_warn(LD_DIR,"couldn't find start of hashed material \"%s\"",start_str);
    return -1;
  }
  if (start != s && *(start-1) != '\n') {
    log_warn(LD_DIR,
             "first occurrence of \"%s\" is not at the start of a line",
             start_str);
    return -1;
  }
  end = strstr(start+strlen(start_str), end_str);
  if (!end) {
    log_warn(LD_DIR,"couldn't find end of hashed material \"%s\"",end_str);
    return -1;
  }
  end = strchr(end+strlen(end_str), '\n');
  if (!end) {
    log_warn(LD_DIR,"couldn't find EOL");
    return -1;
  }
  ++end;

  if (crypto_digest(digest, start, end-start)) {
    log_warn(LD_BUG,"couldn't compute digest");
    return -1;
  }

  return 0;
}

/** Parse the Tor version of the platform string <b>platform</b>,
 * and compare it to the version in <b>cutoff</b>. Return 1 if
 * the router is at least as new as the cutoff, else return 0.
 */
int
tor_version_as_new_as(const char *platform, const char *cutoff)
{
  tor_version_t cutoff_version, router_version;
  char *s, *start;
  char tmp[128];

  tor_assert(platform);

  if (tor_version_parse(cutoff, &cutoff_version)<0) {
    log_warn(LD_DIR,"Bug: cutoff version '%s' unparseable.",cutoff);
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
    log_info(LD_DIR,"Router version '%s' unparseable.",tmp);
    return 1; /* be safe and say yes */
  }

  return tor_version_compare(&router_version, &cutoff_version) >= 0;
}

/** Parse a tor version from <b>s</b>, and store the result in <b>out</b>.
 * Return 0 on success, -1 on failure. */
int
tor_version_parse(const char *s, tor_version_t *out)
{
  char *eos=NULL, *cp=NULL;
  /* Format is:
   *   "Tor " ? NUM dot NUM dot NUM [ ( pre | rc | dot ) NUM [ - tag ] ]
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

  /* Get status tag. */
  if (*cp == '-' || *cp == '.')
    ++cp;
  strlcpy(out->status_tag, cp, sizeof(out->status_tag));

  return 0;
}

/** Compare two tor versions; Return <0 if a < b; 0 if a ==b, >0 if a >
 * b. */
int
tor_version_compare(tor_version_t *a, tor_version_t *b)
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

  return strcmp(a->status_tag, b->status_tag);
}

/** Return true iff versions <b>a</b> and <b>b</b> belong to the same series.
 */
static int
tor_version_same_series(tor_version_t *a, tor_version_t *b)
{
  tor_assert(a);
  tor_assert(b);
  return ((a->major == b->major) &&
          (a->minor == b->minor) &&
          (a->micro == b->micro));
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
  /* If neither parses, compare strings.  Also, the directory server admin
  ** needs to be smacked upside the head.  But Tor is tolerant and gentle. */
  return strcmp(a,b);
}

/** Sort a list of string-representations of versions in ascending order. */
void
sort_version_list(smartlist_t *versions, int remove_duplicates)
{
  smartlist_sort(versions, _compare_tor_version_str_ptr);

  if (remove_duplicates)
    smartlist_uniq(versions, _compare_tor_version_str_ptr, NULL);
}

