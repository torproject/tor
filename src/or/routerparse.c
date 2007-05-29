/* oCpyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2007, Roger Dingledine, Nick Mathewson. */
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
  K_ACCEPT = 0,
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
  K_EXTRA_INFO,
  K_EXTRA_INFO_DIGEST,
  K_CACHES_EXTRA_INFO,

  K_DIR_KEY_CERTIFICATE_VERSION,
  K_DIR_IDENTITY_KEY,
  K_DIR_KEY_PUBLISHED,
  K_DIR_KEY_EXPIRES,
  K_DIR_KEY_CERTIFICATION,

  K_VOTE_STATUS,
  K_VALID_UNTIL,
  K_KNOWN_FLAGS,
  K_VOTE_DIGEST,
  K_CONSENSUS_DIGEST,

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
  size_t object_size;          /**< Bytes in object_body */
  char *object_body;           /**< Contents of object, base64-decoded. */
  crypto_pk_env_t *key;        /**< For public keys only. */
  char *error;                 /**< For _ERR tokens only. */
} directory_token_t;

/* ********************************************************************** */

/** We use a table of rules to decide how to parse each token type. */

/** Rules for whether the keyword needs an object. */
typedef enum {
  NO_OBJ,        /**< No object, ever. */
  NEED_OBJ,      /**< Object is required. */
  NEED_KEY_1024, /**< Object is required, and must be a 1024 bit public key */
  NEED_KEY,      /**< Object is required, and must be a public key. */
  OBJ_OK,        /**< Object is optional. */
} obj_syntax;

#define AT_START 1
#define AT_END 1

/** Determines the parsing rules for a single token type. */
typedef struct token_rule_t {
  /** The string value of the keyword identifying the type of item. */
  const char *t;
  /** The corresponding directory_keyword enum. */
  directory_keyword v;
  /** Minimum number of arguments for this item */
  int min_args;
  /** Maximum number of arguments for this item */
  int max_args;
  /** If true, we concatenate all arguments for this item into a single
   * string. */
  int concat_args;
  /** Requirments on object syntax for this item. */
  obj_syntax os;
  /** Lowest number of times this item may appear in a document. */
  int min_cnt;
  /** Highest number of times this item may appear in a document. */
  int max_cnt;
  /** One or more of AT_START/AT_END to limit where the item may appear in a
   * document. */
  int pos;
} token_rule_t;

/*
 * Helper macros to define token tables.  's' is a string, 't' is a
 * directory_keyword, 'a' is a trio of argument multiplicities, and 'o' is an
 * object syntax.
 *
 */

/** Appears to indicate the end of a table. */
#define END_OF_TABLE { NULL, _NIL, 0,0,0, NO_OBJ, 0, INT_MAX, 0 }
/** An item with no restrictions: used for obsolete document types */
#define T(s,t,a,o)    { s, t, a, o, 0, INT_MAX, 0 }
/** An item with no restrictions on multiplicity or location. */
#define T0N(s,t,a,o)  { s, t, a, o, 0, INT_MAX, 0 }
/** An item that must appear exactly once */
#define T1(s,t,a,o)   { s, t, a, o, 1, 1, 0 }
/** An item that must appear exactly once, at the start of the document */
#define T1_START(s,t,a,o)   { s, t, a, o, 1, 1, 0, AT_START }
/** An item that must appear exactly once, at the end of the document */
#define T1_END(s,t,a,o)   { s, t, a, o, 1, 1, 0, AT_END }
/** An item that must appear one or more times */
#define T1N(s,t,a,o)  { s, t, a, o, 1, INT_MAX, 0 }
/** An item that must appear no more than once */
#define T01(s,t,a,o)  { s, t, a, o, 0, 1, 0 }

/* Argument multiplicity: any number of arguments. */
#define ARGS        0,INT_MAX,0
/* Argument multiplicity: no arguments. */
#define NO_ARGS     0,0,0
/* Argument multiplicity: concatenate all arguments. */
#define CONCAT_ARGS 1,1,1
/* Argument multiplicity: at least <b>n</b> arguments. */
#define GE(n)       n,INT_MAX,0
/* Argument multiplicity: exactly <b>n</b> arguments. */
#define EQ(n)       n,n,0

/** List of tokens allowable in router derscriptors */
static token_rule_t routerdesc_token_table[] = {
  T0N("reject",              K_REJECT,              ARGS,    NO_OBJ ),
  T0N("accept",              K_ACCEPT,              ARGS,    NO_OBJ ),
  T1( "router",              K_ROUTER,              GE(5),   NO_OBJ ),
  T1( "signing-key",         K_SIGNING_KEY,         NO_ARGS, NEED_KEY_1024 ),
  T1( "onion-key",           K_ONION_KEY,           NO_ARGS, NEED_KEY_1024 ),
  T1( "router-signature",    K_ROUTER_SIGNATURE,    NO_ARGS, NEED_OBJ ),
  T1( "published",           K_PUBLISHED,       CONCAT_ARGS, NO_OBJ ),
  T01("uptime",              K_UPTIME,              GE(1),   NO_OBJ ),
  T01("fingerprint",         K_FINGERPRINT,     CONCAT_ARGS, NO_OBJ ),
  T01("hibernating",         K_HIBERNATING,         GE(1),   NO_OBJ ),
  T01("platform",            K_PLATFORM,        CONCAT_ARGS, NO_OBJ ),
  T01("contact",             K_CONTACT,         CONCAT_ARGS, NO_OBJ ),
  T01("read-history",        K_READ_HISTORY,        ARGS,    NO_OBJ ),
  T01("write-history",       K_WRITE_HISTORY,       ARGS,    NO_OBJ ),
  T01("extra-info-digest",   K_EXTRA_INFO_DIGEST,   GE(1),   NO_OBJ ),

  T01("family",              K_FAMILY,              ARGS,    NO_OBJ ),
  T01("caches-extra-info",   K_CACHES_EXTRA_INFO,   NO_ARGS, NO_OBJ ),
  T01("eventdns",            K_EVENTDNS,            ARGS,    NO_OBJ ),

  T0N("opt",                 K_OPT,             CONCAT_ARGS, OBJ_OK ),
  T1( "bandwidth",           K_BANDWIDTH,           GE(3),   NO_OBJ ),

  END_OF_TABLE
};

/** List of tokens allowable in extra-info documents. */
static token_rule_t extrainfo_token_table[] = {
  T1( "router-signature",    K_ROUTER_SIGNATURE,    NO_ARGS, NEED_OBJ ),
  T1( "published",           K_PUBLISHED,       CONCAT_ARGS, NO_OBJ ),
  T0N("opt",                 K_OPT,             CONCAT_ARGS, OBJ_OK ),
  T01("read-history",        K_READ_HISTORY,        ARGS,    NO_OBJ ),
  T01("write-history",       K_WRITE_HISTORY,       ARGS,    NO_OBJ ),
  T1( "extra-info",          K_EXTRA_INFO,          GE(2),   NO_OBJ ),

  END_OF_TABLE
};

/** List of tokens allowable in the body part of v2 and v3 networkstatus
 * documents. */
static token_rule_t rtrstatus_token_table[] = {
  T1( "r",                   K_R,                   GE(8),   NO_OBJ ),
  T1( "s",                   K_S,                   ARGS,    NO_OBJ ),
  T01("v",                   K_V,               CONCAT_ARGS, NO_OBJ ),
  T0N("opt",                 K_OPT,             CONCAT_ARGS, OBJ_OK ),
  END_OF_TABLE
};

/** List of tokens allowable in the header part of v2 networkstatus documents.
 */
static token_rule_t netstatus_token_table[] = {
  T1( "published",           K_PUBLISHED,       CONCAT_ARGS, NO_OBJ ),
  T0N("opt",                 K_OPT,             CONCAT_ARGS, OBJ_OK ),
  T1( "contact",             K_CONTACT,         CONCAT_ARGS, NO_OBJ ),
  T1( "dir-signing-key",     K_DIR_SIGNING_KEY,  NO_ARGS,    NEED_KEY_1024 ),
  T1( "fingerprint",         K_FINGERPRINT,     CONCAT_ARGS, NO_OBJ ),
  T1( "network-status-version", K_NETWORK_STATUS_VERSION,
                                                    GE(1),   NO_OBJ ),
  T1( "dir-source",          K_DIR_SOURCE,          GE(3),   NO_OBJ ),
  T01("dir-options",         K_DIR_OPTIONS,         ARGS,    NO_OBJ ),
  T01("client-versions",     K_CLIENT_VERSIONS, CONCAT_ARGS, NO_OBJ ),
  T01("server-versions",     K_SERVER_VERSIONS, CONCAT_ARGS, NO_OBJ ),

  END_OF_TABLE
};

/** List of tokens allowable in the footer of v1/v2 directory/networkstatus
 * footers. */
static token_rule_t dir_footer_token_table[] = {
  T1("directory-signature", K_DIRECTORY_SIGNATURE, EQ(1), NEED_OBJ ),
  END_OF_TABLE
};

/** List of tokens allowable in v1 diectory headers/footers. */
static token_rule_t dir_token_table[] = {
  /* don't enforce counts; this is obsolete. */
  T( "network-status",      K_NETWORK_STATUS,      NO_ARGS, NO_OBJ ),
  T( "directory-signature", K_DIRECTORY_SIGNATURE, ARGS,    NEED_OBJ ),
  T( "recommended-software",K_RECOMMENDED_SOFTWARE,CONCAT_ARGS, NO_OBJ ),
  T( "signed-directory",    K_SIGNED_DIRECTORY,    NO_ARGS, NO_OBJ ),

  T( "running-routers",     K_RUNNING_ROUTERS,     ARGS,    NO_OBJ ),
  T( "router-status",       K_ROUTER_STATUS,       ARGS,    NO_OBJ ),
  T( "published",           K_PUBLISHED,       CONCAT_ARGS, NO_OBJ ),
  T( "opt",                 K_OPT,             CONCAT_ARGS, OBJ_OK ),
  T( "contact",             K_CONTACT,         CONCAT_ARGS, NO_OBJ ),
  T( "dir-signing-key",     K_DIR_SIGNING_KEY,     ARGS,    OBJ_OK ),
  T( "fingerprint",         K_FINGERPRINT,     CONCAT_ARGS, NO_OBJ ),

  END_OF_TABLE
};

/** List of tokens allowable in the footer of v1/v2 directory/networkstatus
 * footers. */
#define CERTIFICATE_MEMBERS                                                  \
  T1("dir-key-certificate-version", K_DIR_KEY_CERTIFICATE_VERSION,           \
                                                     GE(1),       NO_OBJ ),  \
  T1("dir-identity-key", K_DIR_IDENTITY_KEY,         NO_ARGS,     NEED_KEY ),\
  T1("dir-key-published",K_DIR_KEY_PUBLISHED,        CONCAT_ARGS, NO_OBJ),   \
  T1("dir-key-expires",  K_DIR_KEY_EXPIRES,          CONCAT_ARGS, NO_OBJ),   \
  T1("dir-signing-key",  K_DIR_SIGNING_KEY,          NO_ARGS,     NEED_KEY ),\
  T1("dir-key-certification", K_DIR_KEY_CERTIFICATION,                       \
                                                     NO_ARGS,     NEED_OBJ),

static token_rule_t dir_key_certificate_table[] = {
  CERTIFICATE_MEMBERS
  T1("fingerprint",      K_FINGERPRINT,              CONCAT_ARGS, NO_OBJ ),
  END_OF_TABLE
};

#if 0
/* XXXX This stuff is commented out for now so we can avoid warnings about
 * unused variables. */

static token_rule_t status_vote_table[] = {
  T1("network-status-version", K_NETWORK_STATUS_VERSION,
                                                   GE(1),       NO_OBJ ),
  T1("vote-status",            K_VOTE_STATUS,      GE(1),       NO_OBJ ),
  T1("published",              K_PUBLISHED,        CONCAT_ARGS, NO_OBJ ),
  T1("valid-until",            K_VALID_UNTIL,      CONCAT_ARGS, NO_OBJ ),
  T1("known-flags",            K_KNOWN_FLAGS,      CONCAT_ARGS, NO_OBJ ),
  T( "fingerprint",            K_FINGERPRINT,      CONCAT_ARGS, NO_OBJ ),

  CERTIFICATE_MEMBERS

  T0N("opt",                 K_OPT,             CONCAT_ARGS, OBJ_OK ),
  T1( "contact",             K_CONTACT,         CONCAT_ARGS, NO_OBJ ),
  T1( "dir-source",          K_DIR_SOURCE,      GE(3),       NO_OBJ ),
  T1( "dir-options",         K_DIR_OPTIONS,     ARGS,        NO_OBJ ),
  T1( "known-flags",         K_KNOWN_FLAGS,     CONCAT_ARGS, NO_OBJ ),
  T01("client-versions",     K_CLIENT_VERSIONS, CONCAT_ARGS, NO_OBJ ),
  T01("server-versions",     K_SERVER_VERSIONS, CONCAT_ARGS, NO_OBJ ),

  END_OF_TABLE
};

static token_rule_t status_consensus_table[] = {
  T1("network-status-version", K_NETWORK_STATUS_VERSION,
                                                   GE(1),       NO_OBJ ),
  T1("vote-status",            K_VOTE_STATUS,      GE(1),       NO_OBJ ),
  T1("published",              K_PUBLISHED,        CONCAT_ARGS, NO_OBJ ),
  T1("valid-until",            K_VALID_UNTIL,      CONCAT_ARGS, NO_OBJ ),

  CERTIFICATE_MEMBERS

  T0N("opt",                 K_OPT,             CONCAT_ARGS, OBJ_OK ),

  T1N("dir-source",          K_DIR_SOURCE,          GE(3),   NO_OBJ ),
  T1N("fingerprint",         K_FINGERPRINT,     CONCAT_ARGS, NO_OBJ ),
  T1N("contact",             K_CONTACT,         CONCAT_ARGS, NO_OBJ ),
  T1N("vote-digest",         K_VOTE_DIGEST,         GE(1),   NO_OBJ ),

#if 0
  T1( "dir-options",         K_DIR_OPTIONS,     ARGS,        NO_OBJ ),
  T1( "known-flags",         K_KNOWN_FLAGS,     CONCAT_ARGS, NO_OBJ ),
#endif

  T01("client-versions",     K_CLIENT_VERSIONS, CONCAT_ARGS, NO_OBJ ),
  T01("server-versions",     K_SERVER_VERSIONS, CONCAT_ARGS,    NO_OBJ ),

  END_OF_TABLE
};

static token_rule_t vote_footer_token_table[] = {
  T01("consensus-digest",    K_CONSENSUS_DIGEST,    EQ(1),   NO_OBJ ),
  T(  "directory-signature", K_DIRECTORY_SIGNATURE, GE(2),   NEED_OBJ ),
  END_OF_TABLE
};
#endif

#undef T

/* static function prototypes */
static int router_add_exit_policy(routerinfo_t *router,directory_token_t *tok);
static addr_policy_t *router_parse_addr_policy(directory_token_t *tok);
static addr_policy_t *router_parse_addr_policy_private(directory_token_t *tok);

static int router_get_hash_impl(const char *s, char *digest,
                                const char *start_str, const char *end_str,
                                char end_char);
static void token_free(directory_token_t *tok);
static smartlist_t *find_all_exitpolicy(smartlist_t *s);
static directory_token_t *find_first_by_keyword(smartlist_t *s,
                                                directory_keyword keyword);
static int tokenize_string(const char *start, const char *end,
                           smartlist_t *out,
                           token_rule_t *table);
static directory_token_t *get_next_token(const char **s,
                                         token_rule_t *table);
static int check_signature_token(const char *digest,
                                 directory_token_t *tok,
                                 crypto_pk_env_t *pkey,
                                 int check_authority,
                                 const char *doctype);
static crypto_pk_env_t *find_dir_signing_key(const char *str);
static int tor_version_same_series(tor_version_t *a, tor_version_t *b);

/** Set <b>digest</b> to the SHA-1 digest of the hash of the directory in
 * <b>s</b>.  Return 0 on success, -1 on failure.
 */
int
router_get_dir_hash(const char *s, char *digest)
{
  return router_get_hash_impl(s,digest,
                              "signed-directory","\ndirectory-signature",'\n');
}

/** Set <b>digest</b> to the SHA-1 digest of the hash of the first router in
 * <b>s</b>. Return 0 on success, -1 on failure.
 */
int
router_get_router_hash(const char *s, char *digest)
{
  return router_get_hash_impl(s,digest,
                              "router ","\nrouter-signature", '\n');
}

/** Set <b>digest</b> to the SHA-1 digest of the hash of the running-routers
 * string in <b>s</b>. Return 0 on success, -1 on failure.
 */
int
router_get_runningrouters_hash(const char *s, char *digest)
{
  return router_get_hash_impl(s,digest,
                              "network-status","\ndirectory-signature", '\n');
}

/** Set <b>digest</b> to the SHA-1 digest of the hash of the network-status
 * string in <b>s</b>.  Return 0 on success, -1 on failure. */
int
router_get_networkstatus_v2_hash(const char *s, char *digest)
{
  return router_get_hash_impl(s,digest,
                              "network-status-version","\ndirectory-signature",
                              '\n');
}

/** Set <b>digest</b> to the SHA-1 digest of the hash of the network-status
 * string in <b>s</b>.  Return 0 on success, -1 on failure. */
int
router_get_networkstatus_v3_hash(const char *s, char *digest)
{
  return router_get_hash_impl(s,digest,
                              "network-status-version","\ndirectory-signature",
                              ' ');
}

/** Set <b>digest</b> to the SHA-1 digest of the hash of the extrainfo
 * string in <b>s</b>.  Return 0 on success, -1 on failure. */
int
router_get_extrainfo_hash(const char *s, char *digest)
{
  return router_get_hash_impl(s,digest,"extra-info","\nrouter-signature",'\n');
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
  char *signature;
  int i;

  signature = tor_malloc(crypto_pk_keysize(private_key));
  if (crypto_pk_private_sign(private_key, signature, digest, DIGEST_LEN) < 0) {

    log_warn(LD_BUG,"Couldn't sign digest.");
    goto err;
  }
  if (strlcat(buf, "-----BEGIN SIGNATURE-----\n", buf_len) >= buf_len)
    goto truncated;

  i = strlen(buf);
  if (base64_encode(buf+i, buf_len-i, signature, 128) < 0) {
    log_warn(LD_BUG,"couldn't base64-encode signature");
    tor_free(buf);
    goto err;
  }

  if (strlcat(buf, "-----END SIGNATURE-----\n", buf_len) >= buf_len)
    goto truncated;

  tor_free(signature);
  return 0;

 truncated:
  log_warn(LD_BUG,"tried to exceed string length.");
 err:
  tor_free(signature);
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
  if (found_any_in_series && !found_newer_in_series && found_newer) {
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
  if (tokenize_string(cp,strchr(cp,'\0'),tokens,dir_token_table)) {
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
  if (check_signature_token(digest, tok, declared_key, 1, "directory")<0)
    goto err;

  SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_free(t));
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
  if (tokenize_string(str,end,tokens,dir_token_table)) {
    log_warn(LD_DIR, "Error tokenizing directory"); goto err;
  }

  tok = find_first_by_keyword(tokens, K_PUBLISHED);
  tor_assert(tok);
  tor_assert(tok->n_args == 1);

  if (parse_iso_time(tok->args[0], &published_on) < 0) {
     goto err;
  }

  /* Now that we know the signature is okay, and we have a
   * publication time, cache the directory. */
  if (get_options()->DirPort && !authdir_mode_v1(get_options()))
    dirserv_set_cached_directory(str, published_on, 0);

  r = 0;
  goto done;
 err:
  r = -1;
 done:
  if (declared_key) crypto_free_pk_env(declared_key);
  if (tokens) {
    SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_free(t));
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
  if (tokenize_string(str,str+strlen(str),tokens,dir_token_table)) {
    log_warn(LD_DIR, "Error tokenizing running-routers"); goto err;
  }
  tok = smartlist_get(tokens,0);
  if (tok->tp != K_NETWORK_STATUS) {
    log_warn(LD_DIR, "Network-status starts with wrong token");
    goto err;
  }

  tok = find_first_by_keyword(tokens, K_PUBLISHED);
  tor_assert(tok);
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
  if (check_signature_token(digest, tok, declared_key, 1, "running-routers")
      < 0)
    goto err;

  /* Now that we know the signature is okay, and we have a
   * publication time, cache the list. */
  if (get_options()->DirPort && !authdir_mode_v1(get_options()))
    dirserv_set_cached_directory(str, published_on, 1);

  r = 0;
 err:
  if (declared_key) crypto_free_pk_env(declared_key);
  if (tokens) {
    SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_free(t));
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

  tok = get_next_token(&cp, dir_token_table);
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

/** Check whether the object body of the token in <b>tok</b> has a good
 * signature for <b>digest</b> using key <b>pkey</b>.  If
 * <b>check_authority</b> is set, make sure that <b>pkey</b> is the key of a
 * directory authority.  Use <b>doctype</b> as the type of the document when
 * generating log messages.  Return 0 on success, negative on failure.
 */
static int
check_signature_token(const char *digest,
                      directory_token_t *tok,
                      crypto_pk_env_t *pkey,
                      int check_authority,
                      const char *doctype)
{
  char *signed_digest;

  tor_assert(pkey);
  tor_assert(tok);
  tor_assert(digest);
  tor_assert(doctype);

  if (check_authority && !dir_signing_key_is_trusted(pkey)) {
    log_warn(LD_DIR, "Key on %s did not come from an authority; rejecting",
             doctype);
    return -1;
  }

  if (strcmp(tok->object_type, "SIGNATURE")) {
    log_warn(LD_DIR, "Bad object type on %s signature", doctype);
    return -1;
  }

  signed_digest = tor_malloc(tok->object_size);
  if (crypto_pk_public_checksig(pkey, signed_digest, tok->object_body,
                                tok->object_size)
      != DIGEST_LEN) {
    log_warn(LD_DIR, "Error reading %s: invalid signature.", doctype);
    tor_free(signed_digest);
    return -1;
  }
  log_debug(LD_DIR,"Signed %s hash starts %s", doctype,
            hex_str(signed_digest,4));
  if (memcmp(digest, signed_digest, DIGEST_LEN)) {
    log_warn(LD_DIR, "Error reading %s: signature does not match.", doctype);
    tor_free(signed_digest);
    return -1;
  }
  tor_free(signed_digest);
  return 0;
}

/** Given a string *<b>s</b> containing a concatenated sequence of router
 * descriptors (or extra-info documents if <b>is_extrainfo</b> is set), parses
 * them and stores the result in <b>dest</b>.  All routers are marked running
 * and valid.  Advances *s to a point immediately following the last router
 * entry.  Ignore any trailing router entries that are not complete.
 *
 * If <b>saved_location</b> isn't SAVED_IN_CACHE, make a local copy of each
 * descriptor in the signed_descriptor_body field of each routerinfo_t.  If it
 * isn't SAVED_NOWHERE, remember the offset of each descriptor.
 *
 * Returns 0 on success and -1 on failure.
 */
int
router_parse_list_from_string(const char **s, const char *eos,
                              smartlist_t *dest,
                              saved_location_t saved_location,
                              int want_extrainfo)
{
  routerinfo_t *router;
  extrainfo_t *extrainfo;
  signed_descriptor_t *signed_desc;
  void *elt;
  const char *end, *start;
  int have_extrainfo;

  tor_assert(s);
  tor_assert(*s);
  tor_assert(dest);

  start = *s;
  if (!eos)
    eos = *s + strlen(*s);

  tor_assert(eos >= *s);

  while (1) {
    *s = eat_whitespace_eos(*s, eos);
    if ((eos - *s) < 32) /* make sure it's long enough. */
      break;

    /* Don't start parsing the rest of *s unless it contains a router. */
    if (strcmpstart(*s, "extra-info ")==0) {
      have_extrainfo = 1;
    } else  if (strcmpstart(*s, "router ")==0) {
      have_extrainfo = 0;
    } else {
      /* skip junk. */
      const char *ei = tor_memstr(*s, eos-*s, "\nextra-info ");
      const char *ri = tor_memstr(*s, eos-*s, "\nrouter ");
      if (ri && (!ei || ri < ei)) {
        have_extrainfo = 0;
        *s = ri + 1;
      } else if (ei) {
        have_extrainfo = 1;
        *s = ei + 1;
      } else {
        break;
      }
    }
    end = tor_memstr(*s, eos-*s, "\nrouter-signature");
    if (end)
      end = tor_memstr(end, eos-*s, "\n-----END SIGNATURE-----\n");
    if (end)
      end += strlen("\n-----END SIGNATURE-----\n");

    if (!end)
      break;

    if (have_extrainfo && want_extrainfo) {
      routerlist_t *rl = router_get_routerlist();
      extrainfo = extrainfo_parse_entry_from_string(*s, end,
                                       saved_location != SAVED_IN_CACHE,
                                       rl->identity_map);
      if (!extrainfo)
        continue;
      signed_desc = &extrainfo->cache_info;
      elt = extrainfo;
    } else if (!have_extrainfo && !want_extrainfo) {
      router = router_parse_entry_from_string(*s, end,
                                          saved_location != SAVED_IN_CACHE);
      if (!router)
        continue;
      signed_desc = &router->cache_info;
      elt = router;
    } else {
      *s = end;
      continue;
    }
    if (saved_location != SAVED_NOWHERE) {
      signed_desc->saved_location = saved_location;
      signed_desc->saved_offset = *s - start;
    }
    *s = end;
    smartlist_add(dest, elt);
  }

  return 0;
}

/* For debugging: define to count every descriptor digest we've seen so we
 * know if we need to try harder to avoid duplicate verifies. */
#undef COUNT_DISTINCT_DIGESTS

#ifdef COUNT_DISTINCT_DIGESTS
static digestmap_t *verified_digests = NULL;
#endif

/** Log the total count of the number of distinct router digests we've ever
 * verified.  When compared to the number of times we've verified routerdesc
 * signatures <i>in toto</i>, this will tell us if we're doing too much
 * multiple-verification. */
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
  char digest[128];
  smartlist_t *tokens = NULL, *exit_policy_tokens = NULL;
  directory_token_t *tok;
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
  if (tokenize_string(s,end,tokens,routerdesc_token_table)) {
    log_warn(LD_DIR, "Error tokenizing router descriptor.");
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
  tor_assert(tok->n_args >= 5);

  router = tor_malloc_zero(sizeof(routerinfo_t));
  router->routerlist_index = -1;
  if (cache_copy)
    router->cache_info.signed_descriptor_body = tor_strndup(s, end-s);
  router->cache_info.signed_descriptor_len = end-s;
  memcpy(router->cache_info.signed_descriptor_digest, digest, DIGEST_LEN);

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

  tok = find_first_by_keyword(tokens, K_BANDWIDTH);
  tor_assert(tok && tok->n_args >= 3);
  router->bandwidthrate =
    tor_parse_long(tok->args[0],10,0,INT_MAX,NULL,NULL);

  if (!router->bandwidthrate) {
    log_warn(LD_DIR, "bandwidthrate %s unreadable or 0. Failing.",
             escaped(tok->args[0]));
    goto err;
  }
  router->bandwidthburst =
    tor_parse_long(tok->args[1],10,0,INT_MAX,NULL,NULL);
  router->bandwidthcapacity =
    tor_parse_long(tok->args[2],10,0,INT_MAX,NULL,NULL);
  /* XXXX020 we don't error-check these values? -RD */

  if ((tok = find_first_by_keyword(tokens, K_UPTIME))) {
    tor_assert(tok->n_args >= 1);
    router->uptime = tor_parse_long(tok->args[0],10,0,LONG_MAX,NULL,NULL);
  }

  if ((tok = find_first_by_keyword(tokens, K_HIBERNATING))) {
    tor_assert(tok->n_args >= 1);
    router->is_hibernating
      = (tor_parse_long(tok->args[0],10,0,LONG_MAX,NULL,NULL) != 0);
  }

  tok = find_first_by_keyword(tokens, K_PUBLISHED);
  tor_assert(tok);
  tor_assert(tok->n_args == 1);
  if (parse_iso_time(tok->args[0], &router->cache_info.published_on) < 0)
    goto err;

  tok = find_first_by_keyword(tokens, K_ONION_KEY);
  tor_assert(tok);
  router->onion_pkey = tok->key;
  tok->key = NULL; /* Prevent free */

  tok = find_first_by_keyword(tokens, K_SIGNING_KEY);
  tor_assert(tok);
  router->identity_pkey = tok->key;
  tok->key = NULL; /* Prevent free */
  if (crypto_pk_get_digest(router->identity_pkey,
                           router->cache_info.identity_digest)) {
    log_warn(LD_DIR, "Couldn't calculate key digest"); goto err;
  }

  if ((tok = find_first_by_keyword(tokens, K_FINGERPRINT))) {
    /* If there's a fingerprint line, it must match the identity digest. */
    char d[DIGEST_LEN];
    tor_assert(tok->n_args == 1);
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

  if ((tok = find_first_by_keyword(tokens, K_CACHES_EXTRA_INFO)))
    router->caches_extra_info = 1;

  if ((tok = find_first_by_keyword(tokens, K_EXTRA_INFO_DIGEST))) {
    tor_assert(tok->n_args >= 1);
    if (strlen(tok->args[0]) == HEX_DIGEST_LEN) {
      base16_decode(router->cache_info.extra_info_digest,
                    DIGEST_LEN, tok->args[0], HEX_DIGEST_LEN);
    } else {
      log_warn(LD_DIR, "Invalid extra info digest %s", escaped(tok->args[0]));
    }
  }

  tok = find_first_by_keyword(tokens, K_ROUTER_SIGNATURE);
  tor_assert(tok);
  note_crypto_pk_op(VERIFY_RTR);
#ifdef COUNT_DISTINCT_DIGESTS
  if (!verified_digests)
    verified_digests = digestmap_new();
  digestmap_set(verified_digests, signed_digest, (void*)(uintptr_t)1);
#endif
  if (check_signature_token(digest, tok, router->identity_pkey, 0,
                            "router descriptor") < 0)
    goto err;

  if (!router->or_port) {
    log_warn(LD_DIR,"or_port unreadable or 0. Failing.");
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
    SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_free(t));
    smartlist_free(tokens);
  }
  if (exit_policy_tokens) {
    smartlist_free(exit_policy_tokens);
  }
  return router;
}

/** Parse a single extrainfo entry from the string <b>s</b>, ending at
 * <b>end</b>.  (If <b>end</b> is NULL, parse up to the end of <b>s</b>.)  If
 * <b>cache_copy</b> is true, make a copy of the extra-info document in the
 * cache_info fields of the result.  If <b>routermap</b> is provided, use it
 * as a map from router identity to routerinfo_t when looking up signing keys.
 */
extrainfo_t *
extrainfo_parse_entry_from_string(const char *s, const char *end,
                                  int cache_copy, digestmap_t *routermap)
{
  extrainfo_t *extrainfo = NULL;
  char digest[128];
  smartlist_t *tokens = NULL;
  directory_token_t *tok;
  crypto_pk_env_t *key = NULL;
  routerinfo_t *router;

  if (!end) {
    end = s + strlen(s);
  }

  /* point 'end' to a point immediately after the final newline. */
  while (end > s+2 && *(end-1) == '\n' && *(end-2) == '\n')
    --end;

  if (router_get_extrainfo_hash(s, digest) < 0) {
    log_warn(LD_DIR, "Couldn't compute router hash.");
    return NULL;
  }
  tokens = smartlist_create();
  if (tokenize_string(s,end,tokens,extrainfo_token_table)) {
    log_warn(LD_DIR, "Error tokenizing router descriptor.");
    goto err;
  }

  if (smartlist_len(tokens) < 2) {
    log_warn(LD_DIR, "Impossibly short router descriptor.");
    goto err;
  }

  tok = smartlist_get(tokens,0);
  if (tok->tp != K_EXTRA_INFO) {
    log_warn(LD_DIR,"Entry does not start with \"extra-info\"");
    goto err;
  }

  extrainfo = tor_malloc_zero(sizeof(extrainfo_t));
  extrainfo->cache_info.is_extrainfo = 1;
  if (cache_copy)
    extrainfo->cache_info.signed_descriptor_body = tor_strndup(s, end-s);
  extrainfo->cache_info.signed_descriptor_len = end-s;
  memcpy(extrainfo->cache_info.signed_descriptor_digest, digest, DIGEST_LEN);

  tor_assert(tok->n_args >= 2);
  if (!is_legal_nickname(tok->args[0])) {
    log_warn(LD_DIR,"Bad nickname %s on \"extra-info\"",escaped(tok->args[0]));
    goto err;
  }
  strlcpy(extrainfo->nickname, tok->args[0], sizeof(extrainfo->nickname));
  if (strlen(tok->args[1]) != HEX_DIGEST_LEN ||
      base16_decode(extrainfo->cache_info.identity_digest, DIGEST_LEN,
                    tok->args[1], HEX_DIGEST_LEN)) {
    log_warn(LD_DIR,"Invalid fingerprint %s on \"extra-info\"",
             escaped(tok->args[1]));
    goto err;
  }

  tok = find_first_by_keyword(tokens, K_PUBLISHED);
  tor_assert(tok);
  if (parse_iso_time(tok->args[0], &extrainfo->cache_info.published_on)) {
    log_warn(LD_DIR,"Invalid published time %s on \"extra-info\"",
             escaped(tok->args[0]));
    goto err;
  }

  if (routermap &&
      (router = digestmap_get(routermap,
                              extrainfo->cache_info.identity_digest))) {
    key = router->identity_pkey;
  }

  tok = find_first_by_keyword(tokens, K_ROUTER_SIGNATURE);
  tor_assert(tok);
  if (strcmp(tok->object_type, "SIGNATURE") ||
      tok->object_size < 128 || tok->object_size > 512) {
    log_warn(LD_DIR, "Bad object type or length on extra-info signature");
    goto err;
  }

  if (key) {
    note_crypto_pk_op(VERIFY_RTR);
    if (check_signature_token(digest, tok, key, 0, "extra-info") < 0)
      goto err;

  } else {
    extrainfo->pending_sig = tor_memdup(tok->object_body,
                                        tok->object_size);
    extrainfo->pending_sig_len = tok->object_size;
  }

  goto done;
 err:
  if (extrainfo)
    extrainfo_free(extrainfo);
  extrainfo = NULL;
 done:
  if (tokens) {
    SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_free(t));
    smartlist_free(tokens);
  }
  return extrainfo;
}

/** Free storage held in <b>cert</b>. */
void
authority_cert_free(authority_cert_t *cert)
{
  if (!cert)
    return;

  tor_free(cert->cache_info.signed_descriptor_body);
  if (cert->signing_key)
    crypto_free_pk_env(cert->signing_key);
  if (cert->identity_key)
    crypto_free_pk_env(cert->identity_key);

  tor_free(cert);
}

/** Parse a key certificate from <b>s</b>; point <b>end-of-string</b> to
 * the first character after the certificate. */
authority_cert_t *
authority_cert_parse_from_string(const char *s, const char **end_of_string)
{
  authority_cert_t *cert = NULL;
  smartlist_t *tokens = NULL;
  char digest[DIGEST_LEN];
  directory_token_t *tok;
  char fp_declared[DIGEST_LEN];
  char *eos;
  size_t len;
  trusted_dir_server_t *ds;

  s = eat_whitespace(s);
  eos = strstr(s, "\n-----END SIGNATURE-----\n");
  if (! eos) {
    log_warn(LD_DIR, "No end-of-signature found on key certificate");
    return NULL;
  }
  eos = strchr(eos+2, '\n');
  tor_assert(eos);
  ++eos;
  len = eos - s;

  tokens = smartlist_create();
  if (tokenize_string(s, eos, tokens, dir_key_certificate_table) < 0) {
    log_warn(LD_DIR, "Error tokenizing key certificate");
    goto err;
  }
  if (router_get_hash_impl(s, digest, "dir-key-certificate-version",
                           "\ndir-key-certification", '\n') < 0)
    goto err;
  tok = smartlist_get(tokens, 0);
  if (tok->tp != K_DIR_KEY_CERTIFICATE_VERSION || strcmp(tok->args[0], "3")) {
    log_warn(LD_DIR,
             "Key certificate does not begin with a recognized version (3).");
    goto err;
  }

  cert = tor_malloc_zero(sizeof(authority_cert_t));
  memcpy(cert->cache_info.signed_descriptor_digest, digest, DIGEST_LEN);

  tok = find_first_by_keyword(tokens, K_DIR_SIGNING_KEY);
  tor_assert(tok && tok->key);
  cert->signing_key = tok->key;
  tok->key = NULL;

  tok = find_first_by_keyword(tokens, K_DIR_IDENTITY_KEY);
  tor_assert(tok && tok->key);
  cert->identity_key = tok->key;
  tok->key = NULL;

  tok = find_first_by_keyword(tokens, K_FINGERPRINT);
  tor_assert(tok && tok->n_args);
  if (base16_decode(fp_declared, DIGEST_LEN, tok->args[0],
                    strlen(tok->args[0]))) {
    log_warn(LD_DIR, "Couldn't decode key certificate fingerprint %s",
             escaped(tok->args[0]));
    goto err;
  }

  if (crypto_pk_get_digest(cert->identity_key,
                           cert->cache_info.identity_digest))
    goto err;

  if (memcmp(cert->cache_info.identity_digest, fp_declared, DIGEST_LEN)) {
    log_warn(LD_DIR, "Digest of certificate key didn't match declared "
             "fingerprint");
    goto err;
  }

  tok = find_first_by_keyword(tokens, K_DIR_KEY_PUBLISHED);
  tor_assert(tok);
  if (parse_iso_time(tok->args[0], &cert->cache_info.published_on) < 0) {
     goto err;
  }
  tok = find_first_by_keyword(tokens, K_DIR_KEY_EXPIRES);
  tor_assert(tok);
  if (parse_iso_time(tok->args[0], &cert->expires) < 0) {
     goto err;
  }

  tok = smartlist_get(tokens, smartlist_len(tokens)-1);
  if (tok->tp != K_DIR_KEY_CERTIFICATION) {
    log_warn(LD_DIR, "Certificate didn't end with dir-key-certification.");
    goto err;
  }

  /* If we already have this cert, don't bother checking the signature. */
  ds = trusteddirserver_get_by_v3_auth_digest(
                                     cert->cache_info.identity_digest);
  if (ds && ds->v3_cert &&
      ds->v3_cert->cache_info.signed_descriptor_len == len &&
      ds->v3_cert->cache_info.signed_descriptor_body &&
      ! memcmp(s, ds->v3_cert->cache_info.signed_descriptor_body, len)) {
    log_debug(LD_DIR, "We already checked the signature on this certificate;"
              " no need to do so again.");
  } else {
    if (check_signature_token(digest, tok, cert->identity_key, 0,
                              "key certificate")) {
      goto err;
    }
  }

  cert->cache_info.signed_descriptor_len = len;
  cert->cache_info.signed_descriptor_body = tor_malloc(len+1);
  memcpy(cert->cache_info.signed_descriptor_body, s, len);
  cert->cache_info.signed_descriptor_body[len] = 0;
  cert->cache_info.saved_location = SAVED_NOWHERE;

  if (end_of_string) {
    *end_of_string = eat_whitespace(eos);
  }
  return cert;
 err:
  authority_cert_free(cert);
  return NULL;
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

  if (tokenize_string(*s, eos, tokens, rtrstatus_token_table)) {
    log_warn(LD_DIR, "Error tokenizing router status");
    goto err;
  }
  if (smartlist_len(tokens) < 1) {
    log_warn(LD_DIR, "Impossibly short router status");
    goto err;
  }
  tok = find_first_by_keyword(tokens, K_R);
  tor_assert(tok);
  tor_assert(tok->n_args >= 8);
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
  if ((tok = find_first_by_keyword(tokens, K_V))) {
    tor_assert(tok->n_args == 1);
    rs->version_known = 1;
    if (strcmpstart(tok->args[0], "Tor ")) {
      rs->version_supports_begindir = 1;
      rs->version_supports_extrainfo_upload = 1;
    } else {
      rs->version_supports_begindir =
        tor_version_as_new_as(tok->args[0], "0.1.2.2-alpha");
      rs->version_supports_begindir =
        tor_version_as_new_as(tok->args[0], "0.2.0.0-alpha-dev (r10070)");
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

/** Helper: used in call to _smartlist_uniq to clear out duplicate entries. */
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
  smartlist_t *footer_tokens = smartlist_create();
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
  if (tokenize_string(s, eos, tokens, netstatus_token_table)) {
    log_warn(LD_DIR, "Error tokenizing network-status header.");
    goto err;
  }
  ns = tor_malloc_zero(sizeof(networkstatus_t));
  memcpy(ns->networkstatus_digest, ns_digest, DIGEST_LEN);

  tok = find_first_by_keyword(tokens, K_NETWORK_STATUS_VERSION);
  tor_assert(tok);

  tok = find_first_by_keyword(tokens, K_DIR_SOURCE);
  tor_assert(tok);
  tor_assert(tok->n_args >= 3);
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

  tok = find_first_by_keyword(tokens, K_FINGERPRINT);
  tor_assert(tok);
  tor_assert(tok->n_args);
  if (base16_decode(ns->identity_digest, DIGEST_LEN, tok->args[0],
                    strlen(tok->args[0]))) {
    log_warn(LD_DIR, "Couldn't decode networkstatus fingerprint %s",
             escaped(tok->args[0]));
    goto err;
  }

  if ((tok = find_first_by_keyword(tokens, K_CONTACT))) {
    tor_assert(tok->n_args);
    ns->contact = tok->args[0];
    tok->args[0] = NULL;
  }

  tok = find_first_by_keyword(tokens, K_DIR_SIGNING_KEY);
  tor_assert(tok && tok->key);
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
    if (!(tok = find_first_by_keyword(tokens, K_CLIENT_VERSIONS))) {
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

  tok = find_first_by_keyword(tokens, K_PUBLISHED);
  tor_assert(tok);
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

  if (tokenize_string(s, NULL, footer_tokens, dir_footer_token_table)) {
    log_warn(LD_DIR, "Error tokenizing network-status footer.");
    goto err;
  }
  if (smartlist_len(footer_tokens) < 1) {
    log_warn(LD_DIR, "Too few items in network-status footer.");
    goto err;
  }
  tok = smartlist_get(footer_tokens, smartlist_len(footer_tokens)-1);
  if (tok->tp != K_DIRECTORY_SIGNATURE) {
    log_warn(LD_DIR,
             "Expected network-status footer to end with a signature.");
    goto err;
  }

  note_crypto_pk_op(VERIFY_DIR);
  if (check_signature_token(ns_digest, tok, ns->signing_key, 0,
                            "network-status") < 0)
    goto err;

  goto done;
 err:
  if (ns)
    networkstatus_free(ns);
  ns = NULL;
 done:
  SMARTLIST_FOREACH(tokens, directory_token_t *, t, token_free(t));
  smartlist_free(tokens);
  SMARTLIST_FOREACH(footer_tokens, directory_token_t *, t, token_free(t));
  smartlist_free(footer_tokens);

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
  tok = get_next_token(&cp, routerdesc_token_table);
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
  tor_free(tok->error);
  if (tok->key)
    crypto_free_pk_env(tok->key);
  tor_free(tok);
}

#define RET_ERR(msg)                                               \
  do {                                                             \
    if (tok) token_free(tok);                                      \
    tok = tor_malloc_zero(sizeof(directory_token_t));              \
    tok->tp = _ERR;                                                \
    tok->error = tor_strdup(msg);                                  \
    goto done_tokenizing; } while (0)

static INLINE directory_token_t *
token_check_object(const char *kwd,
                   directory_token_t *tok, obj_syntax o_syn)
{
  char ebuf[128];
  switch (o_syn) {
    case NO_OBJ:
      if (tok->object_body) {
        tor_snprintf(ebuf, sizeof(ebuf), "Unexpected object for %s", kwd);
        RET_ERR(ebuf);
      }
      if (tok->key) {
        tor_snprintf(ebuf, sizeof(ebuf), "Unexpected public key for %s", kwd);
        RET_ERR(ebuf);
      }
      break;
    case NEED_OBJ:
      if (!tok->object_body) {
        tor_snprintf(ebuf, sizeof(ebuf), "Missing object for %s", kwd);
        RET_ERR(ebuf);
      }
      break;
    case NEED_KEY_1024:
      if (tok->key && crypto_pk_keysize(tok->key) != PK_BYTES) {
        tor_snprintf(ebuf, sizeof(ebuf), "Wrong size on key for %s: %d bits",
                     kwd, (int)crypto_pk_keysize(tok->key));
        RET_ERR(ebuf);
      }
      /* fall through */
    case NEED_KEY:
      if (!tok->key) {
        tor_snprintf(ebuf, sizeof(ebuf), "Missing public key for %s", kwd);
      }
      break;
    case OBJ_OK:
      break;
  }

 done_tokenizing:
  return tok;
}

/** Helper function: read the next token from *s, advance *s to the end of the
 * token, and return the parsed token.  Parse *<b>s</b> according to the list
 * of tokens in <b>table</b>.
 */
static directory_token_t *
get_next_token(const char **s, token_rule_t *table)
{
  const char *next, *obstart;
  int i, j, done, allocated;
  directory_token_t *tok;
  obj_syntax o_syn = NO_OBJ;
  char ebuf[128];
  const char *kwd = "";

#define RET_ERR(msg)                                               \
  do {                                                             \
    if (tok) token_free(tok);                                      \
    tok = tor_malloc_zero(sizeof(directory_token_t));              \
    tok->tp = _ERR;                                                \
    tok->error = tor_strdup(msg);                                  \
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
    tok->error = tor_strdup("Unexpected EOF"); return tok;
  }
  /* It's a keyword... but which one? */
  if (!strncmp("opt", *s, next-*s)) {
    /* Skip past an "opt" at the start of the line. */
    *s = eat_whitespace(next);
    next = NULL;
    if (**s)
      next = find_whitespace(*s);
    if (!**s || !next) {
      RET_ERR("opt without keyword");
    }
  }
  /* Search the table for the appropriate entry.  (I tried a binary search
   * instead, but it wasn't any faster.) */
  for (i = 0; table[i].t ; ++i) {
    if (!strncmp(table[i].t, *s, next-*s)) {
      /* We've found the keyword. */
      kwd = table[i].t;
      tok->tp = table[i].v;
      o_syn = table[i].os;
      if (table[i].concat_args) {
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
        /* This keyword takes multiple arguments. */
        j = 0;
        done = (*next == '\n');
        allocated = 32;
        tok->args = tor_malloc(sizeof(char*)*32);
        *s = eat_whitespace_no_nl(next);
        while (**s != '\n' && !done) {
          next = find_whitespace(*s);
          if (*next == '\n')
            done = 1;
          if (j == allocated) {
            allocated *= 2;
            tok->args = tor_realloc(tok->args,sizeof(char*)*allocated);
          }
          tok->args[j++] = tor_strndup(*s,next-*s);
          *s = eat_whitespace_no_nl(next+1);
        }
        tok->n_args = j;
      }
      if (tok->n_args < table[i].min_args) {
        tor_snprintf(ebuf, sizeof(ebuf), "Too few arguments to %s", kwd);
        RET_ERR(ebuf);
      } else if (tok->n_args > table[i].max_args) {
        tor_snprintf(ebuf, sizeof(ebuf), "Too many arguments to %s", kwd);
        RET_ERR(ebuf);
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
    goto check_object;
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

 check_object:
  tok = token_check_object(kwd, tok, o_syn);

 done_tokenizing:
  return tok;

#undef RET_ERR
}

/** Read all tokens from a string between <b>start</b> and <b>end</b>, and add
 * them to <b>out</b>.  Parse according to the token rules in <b>table</b>.
 */
static int
tokenize_string(const char *start, const char *end, smartlist_t *out,
                token_rule_t *table)
{
  const char **s;
  directory_token_t *tok = NULL;
  int counts[_NIL];
  int i;

  s = &start;
  if (!end)
    end = start+strlen(start);
  for (i = 0; i < _NIL; ++i)
    counts[i] = 0;
  while (*s < end && (!tok || tok->tp != _EOF)) {
    tok = get_next_token(s, table);
    if (tok->tp == _ERR) {
      log_warn(LD_DIR, "parse error: %s", tok->error);
      return -1;
    }
    ++counts[tok->tp];
    smartlist_add(out, tok);
    *s = eat_whitespace(*s);
  }

  for (i = 0; table[i].t; ++i) {
    if (counts[table[i].v] < table[i].min_cnt) {
      log_warn(LD_DIR, "Parse error: missing %s element.", table[i].t);
      return -1;
    }
    if (counts[table[i].v] > table[i].max_cnt) {
      log_warn(LD_DIR, "Parse error: too many %s elements.", table[i].t);
      return -1;
    }
    if (table[i].pos & AT_START) {
      if (smartlist_len(out) < 1 ||
          (tok = smartlist_get(out, 0))->tp != table[i].v) {
        log_warn(LD_DIR, "Parse error: first item is not %s.", table[i].t);
        return -1;
      }
    }
    if (table[i].pos & AT_END) {
      if (smartlist_len(out) < 1 ||
          (tok = smartlist_get(out, smartlist_len(out)-1))->tp != table[i].v) {
        log_warn(LD_DIR, "Parse error: last item is not %s.", table[i].t);
        return -1;
      }
    }
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
 * occurrence of <b>start_str</b> through the first instance of c after the
 * first subsequent occurrence of <b>end_str</b>; store the 20-byte result in
 * <b>digest</b>; return 0 on success.
 *
 * If no such substring exists, return -1.
 */
static int
router_get_hash_impl(const char *s, char *digest,
                     const char *start_str,
                     const char *end_str, char end_c)
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
  end = strchr(end+strlen(end_str), end_c);
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
  char *s, *s2, *start;
  char tmp[128];

  tor_assert(platform);

  if (tor_version_parse(cutoff, &cutoff_version)<0) {
    log_warn(LD_BUG,"cutoff version '%s' unparseable.",cutoff);
    return 0;
  }
  if (strcmpstart(platform,"Tor ")) /* nonstandard Tor; be safe and say yes */
    return 1;

  start = (char *)eat_whitespace(platform+3);
  if (!*start) return 0;
  s = (char *)find_whitespace(start); /* also finds '\0', which is fine */
  s2 = (char*)eat_whitespace(s);
  if (!strcmpstart(s2, "(r"))
    s = (char*)find_whitespace(s2);

  if ((size_t)(s-start+1) >= sizeof(tmp)) /* too big, no */
    return 0;
  strlcpy(tmp, start, s-start+1);

  if (tor_version_parse(tmp, &router_version)<0) {
    log_info(LD_DIR,"Router version '%s' unparseable.",tmp);
    return 1; /* be safe and say yes */
  }

  /* Here's why we don't need to do any special handling for svn revisions:
   * - If neither has an svn revision, we're fine.
   * - If the router doesn't have an svn revision, we can't assume that it
   *   is "at least" any svn revision, so we need to return 0.
   * - If the target version doesn't have an svn revision, any svn revision
   *   (or none at all) is good enough, so return 1.
   * - If both target and router have an svn revision, we compare them.
   */

  return tor_version_compare(&router_version, &cutoff_version) >= 0;
}

/** Parse a tor version from <b>s</b>, and store the result in <b>out</b>.
 * Return 0 on success, -1 on failure. */
int
tor_version_parse(const char *s, tor_version_t *out)
{
  char *eos=NULL;
  const char *cp=NULL;
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
  eos = (char*) find_whitespace(cp);
  if (eos-cp >= (int)sizeof(out->status_tag))
    strlcpy(out->status_tag, cp, sizeof(out->status_tag));
  else {
    memcpy(out->status_tag, cp, eos-cp);
    out->status_tag[eos-cp] = 0;
  }
  cp = eat_whitespace(eos);

  if (!strcmpstart(cp, "(r")) {
    cp += 2;
    out->svn_revision = strtol(cp,&eos,10);
  }

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
  else if ((i = strcmp(a->status_tag, b->status_tag)))
    return i;
  else
    return a->svn_revision - b->svn_revision;
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

