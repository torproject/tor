/* Copyright 2001-2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#define _GNU_SOURCE
/* XXX this is required on rh7 to make strptime not complain. how bad
 * is this for portability?
 */

#include "or.h"

/****************************************************************************/

static routerlist_t *routerlist = NULL; /* router array */
extern or_options_t options; /* command-line and config-file options */

/****************************************************************************/

/* Enumeration of possible token types.  The ones starting with K_ correspond
 * to directory 'keywords'.  _SIGNATURE and _PUBLIC_KEY are self-explanatory.
 * _ERR is an error in the tokenizing process, _EOF is an end-of-file marker,
 * and _NIL is used to encode not-a-token.
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
  K_LINK_KEY,
  K_ROUTER_SIGNATURE,
  K_PUBLISHED,
  K_RUNNING_ROUTERS,
  K_PLATFORM,
  K_OPT,
  K_BANDWIDTH,
  K_PORTS,
  _UNRECOGNIZED,
  _ERR,
  _EOF,
  _NIL
} directory_keyword;

typedef struct directory_token_t {
  directory_keyword tp;        /* Type of the token. */
  int n_args;
  char **args;
  char *object_type;
  int object_size;
  char *object_body;
  crypto_pk_env_t *key;      /* For public keys only. */
  char *error;               /* For _ERR tokens only. */
} directory_token_t;

/* ********************************************************************** */

/* Every keyword takes either... */
typedef enum {
  NO_ARGS,     /*    (1) no arguments, ever */
  ARGS,        /*    (2) a list of arguments separated by spaces */
  CONCAT_ARGS, /* or (3) the rest of the line, treated as a single argument. */
} arg_syntax;

typedef enum {
  NO_OBJ,
  NEED_OBJ,
  NEED_KEY,
  OBJ_OK,
} obj_syntax;

typedef enum {
  ANY = 0,
  DIR_ONLY,
  RTR_ONLY,
} where_syntax;

/* Table mapping keywods to token value and to argument rules. */

static struct {
  char *t; int v; arg_syntax s; obj_syntax os; where_syntax ws;
} token_table[] = {
  { "accept", K_ACCEPT, ARGS, NO_OBJ, RTR_ONLY },
  { "directory-signature", K_DIRECTORY_SIGNATURE, NO_ARGS, NEED_OBJ, DIR_ONLY},
  { "reject", K_REJECT, ARGS, NO_OBJ, RTR_ONLY },
  { "router", K_ROUTER, ARGS, NO_OBJ, RTR_ONLY },
  { "recommended-software", K_RECOMMENDED_SOFTWARE, ARGS, NO_OBJ, DIR_ONLY },
  { "signed-directory", K_SIGNED_DIRECTORY, NO_ARGS, NO_OBJ, DIR_ONLY },
  { "signing-key", K_SIGNING_KEY, NO_ARGS, NEED_KEY, RTR_ONLY },
  { "onion-key", K_ONION_KEY, NO_ARGS, NEED_KEY, RTR_ONLY },
  { "link-key", K_LINK_KEY, NO_ARGS, NEED_KEY, RTR_ONLY },
  { "router-signature", K_ROUTER_SIGNATURE, NO_ARGS, NEED_OBJ, RTR_ONLY },
  { "published", K_PUBLISHED, CONCAT_ARGS, NO_OBJ, ANY },
  { "running-routers", K_RUNNING_ROUTERS, ARGS, NO_OBJ, DIR_ONLY },
  { "platform", K_PLATFORM, CONCAT_ARGS, NO_OBJ, RTR_ONLY },
  { "ports", K_PORTS, ARGS, NO_OBJ, RTR_ONLY },
  { "bandwidth", K_BANDWIDTH, ARGS, NO_OBJ, RTR_ONLY },
  { "opt", K_OPT, CONCAT_ARGS, OBJ_OK, ANY },
  
  { NULL, -1 }
};

/* ********************************************************************** */

/* static function prototypes */
static routerinfo_t *
router_pick_directory_server_impl(void);
static int
router_get_list_from_string_impl(const char **s, routerlist_t **dest,
                                 int n_good_nicknames,
                                 const char **good_nickname_lst);
static int
router_get_routerlist_from_directory_impl(const char *s, routerlist_t **dest,
                                          crypto_pk_env_t *pkey);
static int
router_add_exit_policy(routerinfo_t *router, directory_token_t *tok);
static int
router_resolve_routerlist(routerlist_t *dir);



static int router_get_hash_impl(const char *s, char *digest,
                                const char *start_str, const char *end_str);
static void token_free(directory_token_t *tok);
static smartlist_t *find_all_exitpolicy(smartlist_t *s);
static directory_token_t *find_first_by_keyword(smartlist_t *s, 
                                                directory_keyword keyword);
static int tokenize_string(const char *start, const char *end,
                           smartlist_t *out, int is_dir);
static directory_token_t *get_next_token(const char **s, where_syntax where);

/****************************************************************************/

extern int has_fetched_directory;

/* try to find a running dirserver. if there are no dirservers
 * in our routerlist, reload the routerlist and try again. */
routerinfo_t *router_pick_directory_server(void) {
  routerinfo_t *choice;

  choice = router_pick_directory_server_impl();
  if(!choice) {
    log_fn(LOG_WARN,"No dirservers known. Reloading and trying again.");
    has_fetched_directory=0; /* reset it */
    if(options.RouterFile) {
      if(router_set_routerlist_from_file(options.RouterFile) < 0)
        return NULL;
    } else {
      if(config_assign_default_dirservers() < 0)
        return NULL;
    }
    /* give it another try */
    choice = router_pick_directory_server_impl();
  }
  return choice;
}

/* pick a random running router with a positive dir_port */
static routerinfo_t *router_pick_directory_server_impl(void) {
  int i;
  routerinfo_t *router, *dirserver=NULL;
  smartlist_t *sl;

  if(!routerlist)
    return NULL;

  sl = smartlist_create(MAX_ROUTERS_IN_DIR);
  for(i=0;i<routerlist->n_routers;i++) {
    router = routerlist->routers[i];
    if(router->dir_port > 0 && router->is_running)
      smartlist_add(sl, router);
  }

  router = smartlist_choose(sl);
  smartlist_free(sl);

  if(router)
    return router;
  log_fn(LOG_INFO,"No dirservers are reachable. Trying them all again.");
  /* no running dir servers found? go through and mark them all as up,
   * and we'll cycle through the list again. */
  for(i=0;i<routerlist->n_routers;i++) {
    router = routerlist->routers[i];
    if(router->dir_port > 0) {
      router->is_running = 1;
      dirserver = router;
    }
  }
  if(!dirserver)
    log_fn(LOG_WARN,"No dirservers in directory! Returning NULL.");
  return dirserver;
}

void router_add_running_routers_to_smartlist(smartlist_t *sl) {
  routerinfo_t *router;
  int i;

  if(!routerlist)
    return;

  for(i=0;i<routerlist->n_routers;i++) {
    router = routerlist->routers[i];
    if(router->is_running &&
       (!options.ORPort ||
        connection_twin_get_by_addr_port(router->addr, router->or_port) ))
      smartlist_add(sl, router);
  }
}

routerinfo_t *router_get_by_addr_port(uint32_t addr, uint16_t port) {
  int i;
  routerinfo_t *router;

  assert(routerlist);

  for(i=0;i<routerlist->n_routers;i++) {
    router = routerlist->routers[i];
    if ((router->addr == addr) && (router->or_port == port))
      return router;
  }
  return NULL;
}

routerinfo_t *router_get_by_link_pk(crypto_pk_env_t *pk)
{
  int i;
  routerinfo_t *router;

  assert(routerlist);

  for(i=0;i<routerlist->n_routers;i++) {
    router = routerlist->routers[i];
    if (0 == crypto_pk_cmp_keys(router->link_pkey, pk))
      return router;
  }
  return NULL;
}

routerinfo_t *router_get_by_nickname(char *nickname)
{
  int i;
  routerinfo_t *router;

  assert(routerlist);

  for(i=0;i<routerlist->n_routers;i++) {
    router = routerlist->routers[i];
    if (0 == strcmp(router->nickname, nickname))
      return router;
  }
  return NULL;
}

/* a way to access routerlist outside this file */
void router_get_routerlist(routerlist_t **prouterlist) {
  *prouterlist = routerlist;
}

/* delete a router from memory */
void routerinfo_free(routerinfo_t *router)
{
  struct exit_policy_t *e;

  if (!router)
    return;

  tor_free(router->address);
  tor_free(router->nickname);
  if (router->onion_pkey)
    crypto_free_pk_env(router->onion_pkey);
  if (router->link_pkey)
    crypto_free_pk_env(router->link_pkey);
  if (router->identity_pkey)
    crypto_free_pk_env(router->identity_pkey);
  while (router->exit_policy) {
    e = router->exit_policy;
    router->exit_policy = e->next;
    tor_free(e->string);
    free(e);
  }
  free(router);
}

static void routerlist_free(routerlist_t *rl)
{
  int i;
  for (i = 0; i < rl->n_routers; ++i)
    routerinfo_free(rl->routers[i]);
  tor_free(rl->routers);
  tor_free(rl->software_versions);
  free(rl);
}

void router_mark_as_down(char *nickname) {
  routerinfo_t *router = router_get_by_nickname(nickname);
  if(!router) /* we don't seem to know about him in the first place */
    return;
  log_fn(LOG_DEBUG,"Marking %s as down.",router->nickname);
  router->is_running = 0;
}

/* ------------------------------------------------------------ */

/* Replace the current router list with the one stored in 'routerfile'. */
int router_set_routerlist_from_file(char *routerfile)
{
  char *string;

  string = read_file_to_str(routerfile);
  if(!string) {
    log_fn(LOG_WARN,"Failed to load routerfile %s.",routerfile);
    return -1;
  }

  if(router_set_routerlist_from_string(string) < 0) {
    log_fn(LOG_WARN,"The routerfile itself was corrupt.");
    free(string);
    return -1;
  }

  free(string);
  return 0;
}

/* Helper function: read routerinfo elements from s, and throw out the
 * ones that don't parse and resolve.  Replace the current
 * routerlist. */
int router_set_routerlist_from_string(const char *s)
{
  if (router_get_list_from_string_impl(&s, &routerlist, -1, NULL)) {
    log(LOG_WARN, "Error parsing router file");
    return -1;
  }
  if (router_resolve_routerlist(routerlist)) {
    log(LOG_WARN, "Error resolving routerlist");
    return -1;
  }
  return 0;
}

/* Set 'digest' to the SHA-1 digest of the hash of the directory in 's'.
 * Return 0 on success, nonzero on failure.
 */
int router_get_dir_hash(const char *s, char *digest)
{
  return router_get_hash_impl(s,digest,
                              "signed-directory","directory-signature");
}
/* Set 'digest' to the SHA-1 digest of the hash of the first router in 's'.
 * Return 0 on success, nonzero on failure.
 */
int router_get_router_hash(const char *s, char *digest)
{
  return router_get_hash_impl(s,digest,
                              "router ","router-signature");
}

/* return 0 if myversion is in versionlist. Else return -1.
 * (versionlist contains a comma-separated list of versions.) */
int compare_recommended_versions(const char *myversion,
                                 const char *versionlist) {
  int len_myversion = strlen(myversion);
  char *comma;
  const char *end = versionlist + strlen(versionlist);

  log_fn(LOG_DEBUG,"checking '%s' in '%s'.", myversion, versionlist);

  for(;;) {
    comma = strchr(versionlist, ',');
    if( ((comma ? comma : end) - versionlist == len_myversion) &&
       !strncmp(versionlist, myversion, len_myversion))
      /* only do strncmp if the length matches */
      return 0; /* success, it's there */
    if(!comma)
      return -1; /* nope */
    versionlist = comma+1;
  }
}

/* Replace the current routerlist with the routers stored in the directory
 * 's'.  If pkey is provided, make sure that 's' is signed with pkey. */
int router_set_routerlist_from_directory(const char *s, crypto_pk_env_t *pkey)
{
  if (router_get_routerlist_from_directory_impl(s, &routerlist, pkey)) {
    log_fn(LOG_WARN, "Couldn't parse directory.");
    return -1;
  }
  if (router_resolve_routerlist(routerlist)) {
    log_fn(LOG_WARN, "Error resolving routerlist");
    return -1;
  }
  if (compare_recommended_versions(VERSION, routerlist->software_versions) < 0) {
    log(options.IgnoreVersion ? LOG_WARN : LOG_ERR,
        "You are running Tor version %s, which will not work with this network.\n"
       "Please use %s%s.",
        VERSION, strchr(routerlist->software_versions,',') ? "one of " : "",
        routerlist->software_versions);
    if(options.IgnoreVersion) {
      log(LOG_WARN, "IgnoreVersion is set. If it breaks, we told you so.");
    } else {
      fflush(0);
      exit(0);
    }
  }
  return 0;
}

/* Helper function: resolve the hostname for 'router' */
static int
router_resolve(routerinfo_t *router)
{
  struct hostent *rent;

  rent = (struct hostent *)gethostbyname(router->address);
  if (!rent) {
    log_fn(LOG_WARN,"Could not get address for router %s (%s).",
           router->address, router->nickname);
    return -1;
  }
  assert(rent->h_length == 4);
  memcpy(&router->addr, rent->h_addr,rent->h_length);
  router->addr = ntohl(router->addr); /* get it back into host order */

  return 0;
}

/* Helper function: resolve every router in rl. */
static int
router_resolve_routerlist(routerlist_t *rl)
{
  int i, max, remove;
  if (!rl)
    rl = routerlist;

  max = rl->n_routers;
  for (i = 0; i < max; ++i) {
    remove = 0;
    if (router_resolve(rl->routers[i])) {
      log_fn(LOG_WARN, "Couldn't resolve router %s; not using",
             rl->routers[i]->address);
      remove = 1;
    } else if (options.Nickname &&
               !strcmp(rl->routers[i]->nickname, options.Nickname)) {
      remove = 1;
    }
    if (remove) {
      routerinfo_free(rl->routers[i]);
      rl->routers[i] = rl->routers[--max];
      --rl->n_routers;
      --i;
    }
  }

  return 0;
}

/* Addr is 0 for "IP unknown".
 *
 * Returns -1 for 'rejected', 0 for accepted, 1 for 'maybe' (since IP is
 * unknown.
 */
int router_compare_addr_to_exit_policy(uint32_t addr, uint16_t port,
                                       struct exit_policy_t *policy)
{
  int maybe_reject = 0;
  int maybe_accept = 0;
  int match = 0;
  int maybe = 0;
  struct in_addr in;
  struct exit_policy_t *tmpe;

  for(tmpe=policy; tmpe; tmpe=tmpe->next) {
    log_fn(LOG_DEBUG,"Considering exit policy %s", tmpe->string);
    maybe = 0;
    if (!addr) {
      /* Address is unknown. */
      if (port >= tmpe->prt_min && port <= tmpe->prt_max) {
        /* The port definitely matches. */
        if (tmpe->msk == 0) {
          match = 1;
        } else {
          maybe = 1;
        }
      } else if (!port) {
        /* The port maybe matches. */
        maybe = 1;
      }
    } else {
      /* Address is known */
      if ((addr & tmpe->msk) == (tmpe->addr & tmpe->msk)) {
        if (port >= tmpe->prt_min && port <= tmpe->prt_max) {
          /* Exact match for the policy */
          match = 1;
        } else if (!port) {
          maybe = 1;
        }
      }
    }
    if (maybe) {
      if (tmpe->policy_type == EXIT_POLICY_REJECT)
        maybe_reject = 1;
      else
        maybe_accept = 1;
    }
    if (match) {
      in.s_addr = htonl(addr);
      log_fn(LOG_INFO,"Address %s:%d matches exit policy '%s'",
             inet_ntoa(in), port, tmpe->string);
      if(tmpe->policy_type == EXIT_POLICY_ACCEPT) {
        /* If we already hit a clause that might trigger a 'reject', than we
         * can't be sure of this certain 'accept'.*/
        return maybe_reject ? ADDR_POLICY_UNKNOWN : ADDR_POLICY_ACCEPTED;
      } else {
        return maybe_accept ? ADDR_POLICY_UNKNOWN : ADDR_POLICY_REJECTED;
      }
    }
  }
  /* accept all by default. */
  return maybe_reject ? ADDR_POLICY_UNKNOWN : ADDR_POLICY_ACCEPTED;
}

/* return 1 if all running routers will reject addr:port, return 0 if
   any might accept it. */
int router_exit_policy_all_routers_reject(uint32_t addr, uint16_t port) {
  int i;
  routerinfo_t *router;

  for (i=0;i<routerlist->n_routers;i++) {
    router = routerlist->routers[i];
    if (router->is_running && router_compare_addr_to_exit_policy(
             addr, port, router->exit_policy) != ADDR_POLICY_REJECTED)
      return 0; /* this one could be ok. good enough. */
  }
  return 1; /* all will reject. */
}

int router_exit_policy_rejects_all(routerinfo_t *router) {
  return router_compare_addr_to_exit_policy(0, 0, router->exit_policy) 
    == ADDR_POLICY_REJECTED;
}

static int parse_time(const char *cp, time_t *t)
{
  struct tm st_tm;
#ifdef HAVE_STRPTIME
  if (!strptime(cp, "%Y-%m-%d %H:%M:%S", &st_tm)) {
    log_fn(LOG_WARN, "Published time was unparseable"); return -1;
  }
#else 
  unsigned int year=0, month=0, day=0, hour=100, minute=100, second=100;
  if (sscanf(cp, "%u-%u-%u %u:%u:%u", &year, &month, 
                &day, &hour, &minute, &second) < 6) {
        log_fn(LOG_WARN, "Published time was unparseable"); return -1;
  }
  if (year < 1970 || month < 1 || month > 12 || day < 1 || day > 31 ||
          hour > 23 || minute > 59 || second > 61) {
        log_fn(LOG_WARN, "Published time was nonsensical"); return -1;
  }
  st_tm.tm_year = year;
  st_tm.tm_mon = month-1;
  st_tm.tm_mday = day;
  st_tm.tm_hour = hour;
  st_tm.tm_min = minute;
  st_tm.tm_sec = second;
#endif
  *t = tor_timegm(&st_tm);
  return 0;
}


/* Helper function: parse a directory from 's' and, when done, store the
 * resulting routerlist in *dest, freeing the old value if necessary.
 * If pkey is provided, we check the directory signature with pkey.
 */
static int
router_get_routerlist_from_directory_impl(const char *str, 
                                          routerlist_t **dest,
                                          crypto_pk_env_t *pkey)
{
  directory_token_t *tok;
  char digest[20];
  char signed_digest[128];
  routerlist_t *new_dir = NULL;
  char *versions = NULL;
  time_t published_on;
  char *good_nickname_lst[1024];
  int n_good_nicknames = 0;
  int i, r;
  const char *end;
  smartlist_t *tokens = NULL;

  if (router_get_dir_hash(str, digest)) {
    log_fn(LOG_WARN, "Unable to compute digest of directory");
    goto err;
  }
  log(LOG_DEBUG,"Received directory hashes to %02x:%02x:%02x:%02x",
      ((int)digest[0])&0xff,((int)digest[1])&0xff,
      ((int)digest[2])&0xff,((int)digest[3])&0xff);

  if ((end = strstr(str,"\nrouter "))) {
    ++end;
  } else if ((end = strstr(str, "\ndirectory-signature"))) {
    ++end;
  } else {
    end = str + strlen(str);
  }
  
  tokens = smartlist_create(128);
  if (tokenize_string(str,end,tokens,1)) {
    log_fn(LOG_WARN, "Error tokenizing directory"); goto err;
  }
  if (tokens->num_used < 1) {
    log_fn(LOG_WARN, "Impossibly short directory header"); goto err;
  }
  if ((tok = find_first_by_keyword(tokens, _UNRECOGNIZED))) {
    log_fn(LOG_WARN, "Unrecognized keyword in \"%s\"; can't parse directory.",
           tok->args[0]);
    goto err;
  }
  
  tok = (directory_token_t*)tokens->list[0];
  if (tok->tp != K_SIGNED_DIRECTORY) {
    log_fn(LOG_WARN, "Directory doesn't start with signed-directory."); 
    goto err;
  }

  if (!(tok = find_first_by_keyword(tokens, K_PUBLISHED))) {
    log_fn(LOG_WARN, "Missing published time on directory.");
    goto err;
  }
  assert(tok->n_args == 1);
  
  if (parse_time(tok->args[0], &published_on) < 0) {
     goto err;
  }

  if (!(tok = find_first_by_keyword(tokens, K_RECOMMENDED_SOFTWARE))) {
    log_fn(LOG_WARN, "Missing recommended-software line from directory.");
    goto err;
  }
  if (tok->n_args != 1) {
    log_fn(LOG_WARN, "Invalid recommended-software line"); goto err;
  }
  versions = tor_strdup(tok->args[0]);
  
  if (!(tok = find_first_by_keyword(tokens, K_RUNNING_ROUTERS))) {
    log_fn(LOG_WARN, "Missing running-routers line from directory.");
    goto err;    
  }

  n_good_nicknames = tok->n_args;
  memcpy(good_nickname_lst, tok->args, n_good_nicknames*sizeof(char *));
  tok->n_args = 0; /* Don't free the strings in good_nickname_lst yet. */

  /* Read the router list from s, advancing s up past the end of the last
   * router. */
  str = end;
  if (router_get_list_from_string_impl(&str, &new_dir,
                                       n_good_nicknames,
                                       (const char**)good_nickname_lst)) {
    log_fn(LOG_WARN, "Error reading routers from directory");
    goto err;
  }
  for (i = 0; i < n_good_nicknames; ++i) {
    tor_free(good_nickname_lst[i]); /* now free them */
  }
  new_dir->software_versions = versions; versions = NULL;
  new_dir->published_on = published_on;
  
  for (i = 0; i < tokens->num_used; ++i) {
    token_free((directory_token_t*)tokens->list[i]);
  }
  smartlist_free(tokens);
  tokens = smartlist_create(128);
  if (tokenize_string(str,str+strlen(str),tokens,1)<0) {
    log_fn(LOG_WARN, "Error tokenizing signature"); goto err;
  }

  if (tokens->num_used != 1 || 
      ((directory_token_t*)tokens->list[0])->tp != K_DIRECTORY_SIGNATURE){
    log_fn(LOG_WARN,"Expected a single directory signature"); goto err;
  }
  tok = (directory_token_t*)tokens->list[0];
  if (strcmp(tok->object_type, "SIGNATURE") || tok->object_size != 128) {
    log_fn(LOG_WARN, "Bad object type or length on directory signature"); 
    goto err;
  }
  if (pkey) {
    if (crypto_pk_public_checksig(pkey, tok->object_body, 128, signed_digest)
        != 20) {
      log_fn(LOG_WARN, "Error reading directory: invalid signature.");
      goto err;
    }
    log(LOG_DEBUG,"Signed directory hash starts %02x:%02x:%02x:%02x",
        ((int)signed_digest[0])&0xff,((int)signed_digest[1])&0xff,
        ((int)signed_digest[2])&0xff,((int)signed_digest[3])&0xff);
    if (memcmp(digest, signed_digest, 20)) {
      log_fn(LOG_WARN, "Error reading directory: signature does not match.");
      goto err;
    }
  }

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
  for (i = 0; i < n_good_nicknames; ++i) {
    tor_free(good_nickname_lst[i]);
  }
 done:
  if (tokens) {
    for (i = 0; i < tokens->num_used; ++i) {
      token_free((directory_token_t*)tokens->list[i]);
    }
    smartlist_free(tokens);
  }
  return r;
}

/* Helper function: Given a string *s containing a concatenated
 * sequence of router descriptors, parses them and stores the result
 * in *dest.  If good_nickname_lst is provided, then routers whose
 * nicknames are not listed are marked as nonrunning.  Advances *s to
 * a point immediately following the last router entry.  Returns 0 on
 * success and -1 on failure.
 */
static int
router_get_list_from_string_impl(const char **s, routerlist_t **dest,
                                 int n_good_nicknames,
                                 const char **good_nickname_lst)
{
  routerinfo_t *router;
  routerinfo_t **rarray;
  int rarray_len = 0;
  int i;
  const char *end;

  assert(s && *s);

  rarray = (routerinfo_t **)
    tor_malloc((sizeof(routerinfo_t *))*MAX_ROUTERS_IN_DIR);

  while (1) {
    *s = eat_whitespace(*s);
    /* Don't start parsing the rest of *s unless it contains a router. */
    if (strncmp(*s, "router ", 7)!=0)
      break;
    if ((end = strstr(*s+1, "\nrouter "))) {
      end++;
    } else if ((end = strstr(*s+1, "\ndirectory-signature"))) {
      end++;
    } else {
      end = *s+strlen(*s);
    }

    router = router_get_entry_from_string(*s, end);
    *s = end;
    if (!router) {
      log_fn(LOG_WARN, "Error reading router; skipping");
      continue;
    }

    if (n_good_nicknames>=0) {
      router->is_running = 0;
      for (i = 0; i < n_good_nicknames; ++i) {
        if (0==strcasecmp(good_nickname_lst[i], router->nickname)) {
          router->is_running = 1;
          break;
        }
      }
    } else {
      router->is_running = 1; /* start out assuming all dirservers are up */
    }
    rarray[rarray_len++] = router;
    log_fn(LOG_DEBUG,"just added router #%d.",rarray_len);
  }

  if (*dest)
    routerlist_free(*dest);
  *dest = (routerlist_t *)tor_malloc(sizeof(routerlist_t));
  (*dest)->routers = rarray;
  (*dest)->n_routers = rarray_len;
  (*dest)->software_versions = NULL;
  return 0;
}


/* Helper function: reads a single router entry from *s, and advances
 * *s so it points to just after the router it just read.
 * mallocs a new router and returns it if all goes well, else returns
 * NULL.
 * 
 * DOCDOC
 */
routerinfo_t *router_get_entry_from_string(const char *s,
                                           const char *end) {
  routerinfo_t *router = NULL;
  char signed_digest[128];
  char digest[128];
  smartlist_t *tokens = NULL, *exit_policy_tokens = NULL;
  directory_token_t *tok;
  int t, i;
  int ports_set, bw_set;

  if (!end) {
    end = s + strlen(s);
  }

  if (router_get_router_hash(s, digest) < 0) {
    log_fn(LOG_WARN, "Couldn't compute router hash.");
    return NULL;
  }
  tokens = smartlist_create(128);
  if (tokenize_string(s,end,tokens,0)) {
    log_fn(LOG_WARN, "Error tokeninzing router descriptor."); goto err;
  }

  if (tokens->num_used < 2) {
    log_fn(LOG_WARN, "Impossibly short router descriptor.");
    goto err;
  }
  if ((tok = find_first_by_keyword(tokens, _UNRECOGNIZED))) {
    log_fn(LOG_WARN, "Unrecognized keyword in \"%s\"; skipping descriptor.",
           tok->args[0]);
    goto err;
  }

  tok = (directory_token_t*)tokens->list[0];
  if (tok->tp != K_ROUTER) {
    log_fn(LOG_WARN,"Entry does not start with \"router\"");
    goto err;
  }

  router = tor_malloc_zero(sizeof(routerinfo_t));
  router->onion_pkey = router->identity_pkey = router->link_pkey = NULL;
  ports_set = bw_set = 0;

  if (tok->n_args == 2 || tok->n_args == 6) {
    router->nickname = tor_strdup(tok->args[0]);
    if (strlen(router->nickname) > MAX_NICKNAME_LEN) {
      log_fn(LOG_WARN,"Router nickname too long.");
      goto err;
    }
    if (strspn(router->nickname, LEGAL_NICKNAME_CHARACTERS) !=
        strlen(router->nickname)) {
      log_fn(LOG_WARN, "Router nickname contains illegal characters.");
      goto err;
    }
    router->address = tor_strdup(tok->args[1]);
    router->addr = 0;
    
    if (tok->n_args == 6) {
      router->or_port = atoi(tok->args[2]);
      router->socks_port = atoi(tok->args[3]);
      router->dir_port = atoi(tok->args[4]);
      router->bandwidthrate = atoi(tok->args[5]);
      ports_set = bw_set = 1;
    }
  } else {
    log_fn(LOG_WARN,"Wrong # of arguments to \"router\"");
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
    router->or_port = atoi(tok->args[0]);
    router->socks_port = atoi(tok->args[1]);
    router->dir_port = atoi(tok->args[2]);
    ports_set = 1;
  }
  
  tok = find_first_by_keyword(tokens, K_BANDWIDTH);
  if (tok && bw_set) {
    log_fn(LOG_WARN,"Redundant bandwidth line");
    goto err;
  } else if (tok) {
    if (tok->n_args < 1) {
      log_fn(LOG_WARN,"Not enough arguments to \"bandwidth\"");
      goto err;
    }
    router->bandwidthrate = atoi(tok->args[0]);
    bw_set = 1;
  }

  if (!(tok = find_first_by_keyword(tokens, K_PUBLISHED))) {
    log_fn(LOG_WARN, "Missing published time"); goto err;
  }
  assert(tok->n_args == 1);
  if (parse_time(tok->args[0], &router->published_on) < 0)
          goto err;

  if (!(tok = find_first_by_keyword(tokens, K_ONION_KEY))) {
    log_fn(LOG_WARN, "Missing onion key"); goto err;
  }
  /* XXX Check key length */
  router->onion_pkey = tok->key;
  tok->key = NULL; /* Prevent free */

  if (!(tok = find_first_by_keyword(tokens, K_LINK_KEY))) {
    log_fn(LOG_WARN, "Missing onion key"); goto err;
  }
  /* XXX Check key length */
  router->link_pkey = tok->key;
  tok->key = NULL; /* Prevent free */

  if (!(tok = find_first_by_keyword(tokens, K_SIGNING_KEY))) {
    log_fn(LOG_WARN, "Missing onion key"); goto err;
  }
  /* XXX Check key length */
  router->identity_pkey = tok->key;
  tok->key = NULL; /* Prevent free */

  exit_policy_tokens = find_all_exitpolicy(tokens);
  for (i = 0; i < exit_policy_tokens->num_used; ++i) {
    if (router_add_exit_policy(router, 
                   (directory_token_t*)exit_policy_tokens->list[i])<0) {
      log_fn(LOG_WARN, "Error in exit policy"); goto err;
    }
  }
  
  if (!(tok = find_first_by_keyword(tokens, K_ROUTER_SIGNATURE))) {
    log_fn(LOG_WARN, "Missing router signature"); goto err;
  }
  if (strcmp(tok->object_type, "SIGNATURE") || tok->object_size != 128) {
    log_fn(LOG_WARN, "Bad object type or length on router signature"); 
    goto err;
  }
  if ((t=crypto_pk_public_checksig(router->identity_pkey, tok->object_body,
                                   128, signed_digest)) != 20) {
    log_fn(LOG_WARN, "Invalid signature %d",t); goto err;
  }
  if (memcmp(digest, signed_digest, 20)) {
    log_fn(LOG_WARN, "Mismatched signature"); goto err;
  }

  if (!ports_set) {
    log_fn(LOG_WARN,"No ports declared; failing."); goto err;
  }
  if (!bw_set) {
    log_fn(LOG_WARN,"No bandwidth declared; failing."); goto err;
  }
  if(!router->or_port) {
    log_fn(LOG_WARN,"or_port unreadable or 0. Failing.");
    goto err;
  }
  if (!router->bandwidthrate) {
    log_fn(LOG_WARN,"bandwidthrate unreadable or 0. Failing.");
    goto err;
  }

#if XXXBC
  router->bandwidthburst = atoi(ARGS[6]);
  if (!router->bandwidthburst) {
    log_fn(LOG_WARN,"bandwidthburst unreadable or 0. Failing.");
    goto err;
  }
#else
  router->bandwidthburst = 10*router->bandwidthrate;
#endif

  log_fn(LOG_DEBUG,"or_port %d, socks_port %d, dir_port %d, bandwidthrate %u, bandwidthburst %u.",
    router->or_port, router->socks_port, router->dir_port,
    (unsigned) router->bandwidthrate, (unsigned) router->bandwidthburst);


  goto done;
  return router;
  
 err:
  routerinfo_free(router);
  router = NULL;
 done:
  if (tokens) {
    for (i = 0; i < tokens->num_used; ++i) {
      token_free((directory_token_t*)tokens->list[i]);
    }
    smartlist_free(tokens);
  }
  if (exit_policy_tokens) {
    smartlist_free(exit_policy_tokens);
  }
  return router;
}

/* Parse the exit policy in the string 's' and add it to 'router'.
 */
int
router_add_exit_policy_from_string(routerinfo_t *router, const char *s)
{
  directory_token_t *tok = NULL;
  const char *cp;
  char *tmp;
  int r;
  int len, idx;

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
  r = router_add_exit_policy(router, tok);
  goto done;
 err:
  r = -1;
 done:
  free(tmp);
  token_free(tok);
  return r;
}

/* Given a K_ACCEPT or K_REJECT token and a router, create a new exit_policy_t
 * corresponding to the token, and add it to 'router' */
static int 
router_add_exit_policy(routerinfo_t *router, directory_token_t *tok) {

  struct exit_policy_t *tmpe, *newe;
  struct in_addr in;
  char *arg, *address, *mask, *port, *endptr;
  int bits;

  assert(tok->tp == K_REJECT || tok->tp == K_ACCEPT);

  if (tok->n_args != 1)
    return -1;
  arg = tok->args[0];

  newe = tor_malloc_zero(sizeof(struct exit_policy_t));

  newe->string = tor_malloc(8+strlen(arg));
  if (tok->tp == K_REJECT) {
    strcpy(newe->string, "reject ");
    newe->policy_type = EXIT_POLICY_REJECT;
  } else {
    strcpy(newe->string, "accept ");
    newe->policy_type = EXIT_POLICY_ACCEPT;
  }
  strcat(newe->string, arg);

  address = arg;
  mask = strchr(arg,'/');
  port = strchr(mask?mask:arg,':');
  /* Break 'arg' into separate strings.  'arg' was already strdup'd by
   * _router_get_next_token, so it's safe to modify.
   */
  if (mask)
    *mask++ = 0;
  if (port)
    *port++ = 0;

  if (strcmp(address, "*") == 0) {
    newe->addr = 0;
  } else if (tor_inet_aton(address, &in) != 0) {
    newe->addr = ntohl(in.s_addr);
  } else {
    log_fn(LOG_WARN, "Malformed IP %s in exit policy; rejecting.",
           address);
    goto policy_read_failed;
  }
  if (!mask) {
    if (strcmp(address, "*") == 0)
      newe->msk = 0;
    else
      newe->msk = 0xFFFFFFFFu;
  } else {
    endptr = NULL;
    bits = (int) strtol(mask, &endptr, 10);
    if (!*endptr) {
      /* strtol handled the whole mask. */
      newe->msk = ~((1<<(32-bits))-1);
    } else if (tor_inet_aton(mask, &in) != 0) {
      newe->msk = ntohl(in.s_addr);
    } else {
      log_fn(LOG_WARN, "Malformed mask %s on exit policy; rejecting.",
             mask);
      goto policy_read_failed;
    }
  }
  if (!port || strcmp(port, "*") == 0) {
    newe->prt_min = 0;
    newe->prt_max = 65535;
  } else {
    endptr = NULL;
    newe->prt_min = (uint16_t) strtol(port, &endptr, 10);
    if (*endptr == '-') {
      port = endptr+1;
      endptr = NULL;
      newe->prt_max = (uint16_t) strtol(port, &endptr, 10);
      if (*endptr) {
      log_fn(LOG_WARN, "Malformed port %s on exit policy; rejecting.",
             port);
      }
    } else if (*endptr) {
      log_fn(LOG_WARN, "Malformed port %s on exit policy; rejecting.",
             port);
      goto policy_read_failed;
    } else {
      newe->prt_max = newe->prt_min;
    }
  }

  in.s_addr = htonl(newe->addr);
  address = tor_strdup(inet_ntoa(in));
  in.s_addr = htonl(newe->msk);
  log_fn(LOG_DEBUG,"%s %s/%s:%d-%d",
         newe->policy_type == EXIT_POLICY_REJECT ? "reject" : "accept",
         address, inet_ntoa(in), newe->prt_min, newe->prt_max);
  tor_free(address);

  /* now link newe onto the end of exit_policy */

  if(!router->exit_policy) {
    router->exit_policy = newe;
    return 0;
  }

  for(tmpe=router->exit_policy; tmpe->next; tmpe=tmpe->next) ;
  tmpe->next = newe;

  return 0;

policy_read_failed:
  assert(newe->string);
  log_fn(LOG_WARN,"Couldn't parse line '%s'. Dropping", newe->string);
  tor_free(newe->string);
  free(newe);
  return -1;
}

/* ------------------------------------------------------------ */
/* Tokenizer for router descriptors and directories. */


/* Free any malloced resources allocated for a token.  Does not free
 *  the token itself.
 */
static void
token_free(directory_token_t *tok)
{
  int i;
  assert(tok);
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

/* Helper function: read the next token from *s, and stores it into a new
 * directory token *tok.
 */
static directory_token_t *
get_next_token(const char **s, where_syntax where) {
  const char *next, *obstart;
  int i, done, allocated;
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
  for (i = 0 ; token_table[i].t ; ++i) {
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
        tok->args = (char**)tor_malloc(sizeof(char*)*32);
        *s = eat_whitespace_no_nl(next);
        while (**s != '\n' && !done) {
          next = find_whitespace(*s);
          if (*next == '\n')
            done = 1;
          if (i == allocated) {
            allocated *= 2;
            tok->args = (char**)tor_realloc(tok->args,sizeof(char*)*allocated);
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
        tok->args = (char**) tor_malloc(sizeof(char*));
        tok->args[0] = tor_strndup(*s,next-*s);
        tok->n_args = 1;
        *s = eat_whitespace_no_nl(next+1);
      } else {
        /* The keyword takes no arguments. */
        assert(a_syn == NO_ARGS);
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
    tok->tp = _UNRECOGNIZED;
    next = strchr(*s, '\n');
    if (!next) {
      RET_ERR("Unexpected EOF");
    }    
    tok->args = (char**) tor_malloc(sizeof(char*));
    tok->args[0] = tor_strndup(*s,next-*s);
    tok->n_args = 1;
    *s = next+1;
    o_syn = OBJ_OK;
  }
  *s = eat_whitespace(*s);
  if (strncmp(*s, "-----BEGIN ", 11)) {
    goto done_tokenizing;
  }
  obstart = *s;
  *s += 11; /* length of "-----BEGIN ". */
  next = strchr(*s, '\n');
  if (next-*s < 6 || strncmp(next-5, "-----\n", 6)) {
    RET_ERR("Malformed object: bad begin line");
  }
  tok->object_type = tor_strndup(*s, next-*s-5);
  *s = next+1;
  next = strstr(*s, "-----END ");
  if (!next) {
    RET_ERR("Malformed object: missing end line");
  }
  if (!strcmp(tok->object_type, "RSA PUBLIC KEY")) {
    if (strncmp(next, "-----END RSA PUBLIC KEY-----\n", 29))
      RET_ERR("Malformed object: mismatched end line");
    next = strchr(next,'\n')+1;
    tok->key = crypto_new_pk_env(CRYPTO_PK_RSA);
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
    if (strncmp(*s, tok->object_type, i) || strncmp(*s+i, "-----\n", 6)) {
      RET_ERR("Malformed object: mismatched end tag");
    }
    *s += i+6;
  }
  switch(o_syn)
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
        RET_ERR("Missing publid key for keyword");
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
  for(i = 0; i < tok->n_args; ++i) {
    fprintf(stdout," \"%s\"", tok->args[i]);
  }
  if (tok->error) { fprintf(stdout," *%s*", tok->error); }
  fputs("\n",stdout);
#endif


  return tok;
#undef RET_ERR
}

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

static directory_token_t *
find_first_by_keyword(smartlist_t *s, directory_keyword keyword)
{
  int i;
  directory_token_t *tok;
  for (i = 0; i < s->num_used; ++i) {
    tok = (directory_token_t*) s->list[i];
    if (tok->tp == keyword) {
      return tok;
    }
  }
  return NULL;
}

static smartlist_t *
find_all_exitpolicy(smartlist_t *s)
{
  int i;
  directory_token_t *tok;
  smartlist_t *out = smartlist_create(s->num_used);
  for (i = 0; i < s->num_used; ++i) {
    tok = (directory_token_t*) s->list[i];
    if (tok->tp == K_ACCEPT || tok->tp == K_REJECT) {
      smartlist_add(out,tok);
    }
  }
  return out;
}


/* Compute the SHA digest of the substring of s taken from the first
 * occurrence of start_str through the first newline after the first
 * subsequent occurrence of end_str; store the 20-byte result in 'digest';
 * return 0 on success.
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
  end = strstr(start+strlen(start_str), end_str);
  if (!end) {
    log_fn(LOG_WARN,"couldn't find \"%s\"",end_str);
    return -1;
  }
  end = strchr(end, '\n');
  if (!end) {
    log_fn(LOG_WARN,"couldn't find EOL");
    return -1;
  }
  ++end;

  if (crypto_SHA_digest(start, end-start, digest)) {
    log_fn(LOG_WARN,"couldn't compute digest");
    return -1;
  }

  return 0;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
