/* Copyright 2001-2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/**
 * \file routerlist.c
 *
 * \brief Code to
 * maintain and access the global list of routerinfos for known
 * servers.
 **/

/****************************************************************************/

extern or_options_t options; /**< command-line and config-file options */

/* ********************************************************************** */

/* static function prototypes */
static routerinfo_t *router_pick_directory_server_impl(void);
static int router_resolve_routerlist(routerlist_t *dir);

/****************************************************************************/

/****
 * Functions to manage and access our list of known routers. (Note:
 * dirservers maintain a separate, independent list of known router
 * descriptors.)
 *****/

/** Global list of all of the routers that we, as an OR or OP, know about. */
static routerlist_t *routerlist = NULL;

extern int has_fetched_directory; /**< from main.c */

/** Try to find a running dirserver.  If there are no running dirservers
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

/** Pick a random running router with a positive dir_port from our
 * routerlist. */
static routerinfo_t *router_pick_directory_server_impl(void) {
  int i;
  routerinfo_t *router, *dirserver=NULL;
  smartlist_t *sl;

  if(!routerlist)
    return NULL;

  /* Find all the running dirservers we know about. */
  sl = smartlist_create();
  for(i=0;i< smartlist_len(routerlist->routers); i++) {
    router = smartlist_get(routerlist->routers, i);
    if(router->dir_port > 0 && router->is_running)
      smartlist_add(sl, router);
  }

  router = smartlist_choose(sl);
  smartlist_free(sl);

  if(router)
    return router;
  log_fn(LOG_INFO,"No dirservers are reachable. Trying them all again.");

  /* No running dir servers found? go through and mark them all as up,
   * so we cycle through the list again. */
  for(i=0; i < smartlist_len(routerlist->routers); i++) {
    router = smartlist_get(routerlist->routers, i);
    if(router->dir_port > 0) {
      router->is_running = 1;
      dirserver = router;
    }
  }
  if(!dirserver)
    log_fn(LOG_WARN,"No dirservers in directory! Returning NULL.");
  return dirserver;
}

/** Given a comma-and-whitespace separated list of nicknames, see which
 * nicknames in <b>list</b> name routers in our routerlist that are
 * currently running.  Add the routerinfos for those routers to <b>sl</b>.
 */
void add_nickname_list_to_smartlist(smartlist_t *sl, const char *list) {
  const char *start,*end;
  char nick[MAX_NICKNAME_LEN+1];
  routerinfo_t *router;

  tor_assert(sl);
  tor_assert(list);

  while(isspace((int)*list) || *list==',') list++;

  start = list;
  while(*start) {
    end=start; while(*end && !isspace((int)*end) && *end != ',') end++;
    memcpy(nick,start,end-start);
    nick[end-start] = 0; /* null terminate it */
    router = router_get_by_nickname(nick);
    if (router) {
      if (router->is_running)
        smartlist_add(sl,router);
      else
        log_fn(LOG_INFO,"Nickname list includes '%s' which is known but down.",nick);
    } else
      log_fn(has_fetched_directory ? LOG_WARN : LOG_INFO,
             "Nickname list includes '%s' which isn't a known router.",nick);
    while(isspace((int)*end) || *end==',') end++;
    start = end;
  }
}

/** Add every router from our routerlist that is currently running to
 * <b>sl</b>.
 */
void router_add_running_routers_to_smartlist(smartlist_t *sl) {
  routerinfo_t *router;
  int i;

  if(!routerlist)
    return;

  for(i=0;i<smartlist_len(routerlist->routers);i++) {
    router = smartlist_get(routerlist->routers, i);
    if(router->is_running &&
       (!options.ORPort ||
        connection_twin_get_by_addr_port(router->addr, router->or_port) ))
      smartlist_add(sl, router);
  }
}

/** Pick a random running router from a routerlist <b>dir</b>.  If any node
 * named in <b>preferred</b> is available, pick one of those.  Never pick a
 * node named in <b>excluded</b>, or whose routerinfo is in
 * <b>excludedsmartlist</b>, even if they are the only nodes available.
 */
routerinfo_t *router_choose_random_node(routerlist_t *dir,
                                        char *preferred, char *excluded,
                                        smartlist_t *excludedsmartlist)
{
  smartlist_t *sl, *excludednodes;
  routerinfo_t *choice;

  excludednodes = smartlist_create();
  add_nickname_list_to_smartlist(excludednodes,excluded);

  /* try the nodes in RendNodes first */
  sl = smartlist_create();
  add_nickname_list_to_smartlist(sl,preferred);
  smartlist_subtract(sl,excludednodes);
  if(excludedsmartlist)
    smartlist_subtract(sl,excludedsmartlist);
  choice = smartlist_choose(sl);
  smartlist_free(sl);
  if(!choice) {
    sl = smartlist_create();
    router_add_running_routers_to_smartlist(sl);
    smartlist_subtract(sl,excludednodes);
    if(excludedsmartlist)
      smartlist_subtract(sl,excludedsmartlist);
    choice = smartlist_choose(sl);
    smartlist_free(sl);
  }
  smartlist_free(excludednodes);
  if(!choice)
    log_fn(LOG_WARN,"No available nodes when trying to choose node. Failing.");
  return choice;
}

/** Return the router in our routerlist whose address is <b>addr</b> and
 * whose OR port is <b>port</b>. Return NULL if no such router is known.
 */
routerinfo_t *router_get_by_addr_port(uint32_t addr, uint16_t port) {
  int i;
  routerinfo_t *router;

  tor_assert(routerlist);

  for(i=0;i<smartlist_len(routerlist->routers);i++) {
    router = smartlist_get(routerlist->routers, i);
    if ((router->addr == addr) && (router->or_port == port))
      return router;
  }
  return NULL;
}

/** Return the router in our routerlist whose nickname is <b>nickname</b>
 * (case insensitive).  Return NULL if no such router is known.
 */
routerinfo_t *router_get_by_nickname(char *nickname)
{
  int i;
  routerinfo_t *router;

  tor_assert(routerlist);

  for(i=0;i<smartlist_len(routerlist->routers);i++) {
    router = smartlist_get(routerlist->routers, i);
    if (0 == strcasecmp(router->nickname, nickname))
      return router;
  }

  return NULL;
}

/** Set *<b>prouterlist</b> to the current list of all known routers. */
void router_get_routerlist(routerlist_t **prouterlist) {
  *prouterlist = routerlist;
}

/** Free all storage held by <b>router</b>. */
void routerinfo_free(routerinfo_t *router)
{
  struct exit_policy_t *e;

  if (!router)
    return;

  tor_free(router->address);
  tor_free(router->nickname);
  tor_free(router->platform);
  if (router->onion_pkey)
    crypto_free_pk_env(router->onion_pkey);
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

/** Allocate a fresh copy of <b>router</b> */
routerinfo_t *routerinfo_copy(const routerinfo_t *router)
{
  routerinfo_t *r;
  struct exit_policy_t **e, *tmp;

  r = tor_malloc(sizeof(routerinfo_t));
  memcpy(r, router, sizeof(routerinfo_t));

  r->address = tor_strdup(r->address);
  r->nickname = tor_strdup(r->nickname);
  r->platform = tor_strdup(r->platform);
  if (r->onion_pkey)
    r->onion_pkey = crypto_pk_dup_key(r->onion_pkey);
  if (r->identity_pkey)
    r->identity_pkey = crypto_pk_dup_key(r->identity_pkey);
  e = &r->exit_policy;
  while (*e) {
    tmp = tor_malloc(sizeof(struct exit_policy_t));
    memcpy(tmp,*e,sizeof(struct exit_policy_t));
    *e = tmp;
    (*e)->string = tor_strdup((*e)->string);
    e = & ((*e)->next);
  }
  return r;
}

/** Free all storage held by a routerlist <b>rl</b> */
void routerlist_free(routerlist_t *rl)
{
  SMARTLIST_FOREACH(rl->routers, routerinfo_t *, r,
                    routerinfo_free(r));
  smartlist_free(rl->routers);
  tor_free(rl->software_versions);
  tor_free(rl);
}

/** Mark the router named <b>nickname</b> as non-running in our routerlist. */
void router_mark_as_down(char *nickname) {
  routerinfo_t *router = router_get_by_nickname(nickname);
  if(!router) /* we don't seem to know about him in the first place */
    return;
  log_fn(LOG_DEBUG,"Marking %s as down.",router->nickname);
  router->is_running = 0;
}

/*
 * Code to parse router descriptors and directories.
 */

/** Replace the current router list with the one stored in
 * <b>routerfile</b>. */
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
  /* dump_onion_keys(LOG_NOTICE); */

  free(string);
  return 0;
}

/** Helper function: read routerinfo elements from s, and throw out the
 * ones that don't parse and resolve.  Replace the current
 * routerlist. */
int router_set_routerlist_from_string(const char *s)
{
  if (router_parse_list_from_string(&s, &routerlist, -1, NULL)) {
    log(LOG_WARN, "Error parsing router file");
    return -1;
  }
  if (router_resolve_routerlist(routerlist)) {
    log(LOG_WARN, "Error resolving routerlist");
    return -1;
  }
  /* dump_onion_keys(LOG_NOTICE); */

  return 0;
}

/** Return 1 if myversion is in versionlist. Else return 0.
 * (versionlist is a comma-separated list of versions.) */
int is_recommended_version(const char *myversion,
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
      return 1; /* success, it's there */
    if(!comma)
      return 0; /* nope */
    versionlist = comma+1;
  }
}

/** Replace the current routerlist with the routers stored in the
 * signed directory <b>s</b>.  If pkey is provided, make sure that <b>s</b> is
 * signed with pkey. */
int router_set_routerlist_from_directory(const char *s, crypto_pk_env_t *pkey)
{
  if (router_parse_routerlist_from_directory(s, &routerlist, pkey)) {
    log_fn(LOG_WARN, "Couldn't parse directory.");
    return -1;
  }
  if (router_resolve_routerlist(routerlist)) {
    log_fn(LOG_WARN, "Error resolving routerlist");
    return -1;
  }
  if (!is_recommended_version(VERSION, routerlist->software_versions)) {
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

/** Helper function: resolve the hostname for <b>router</b>. */
static int
router_resolve(routerinfo_t *router)
{
  if (tor_lookup_hostname(router->address, &router->addr) != 0) {
    log_fn(LOG_WARN,"Could not get address for router %s (%s).",
           router->address, router->nickname);
    return -1;
  }
  router->addr = ntohl(router->addr); /* get it back into host order */

  return 0;
}

/** Helper function: resolve every router in rl, and ensure that our own
 * routerinfo is at the front.
 */
static int
router_resolve_routerlist(routerlist_t *rl)
{
  int i, remove;
  routerinfo_t *r;
  if (!rl)
    rl = routerlist;

  i = 0;
  if ((r = router_get_my_routerinfo())) {
    smartlist_insert(rl->routers, 0, routerinfo_copy(r));
    ++i;
  }

  for ( ; i < smartlist_len(rl->routers); ++i) {
    remove = 0;
    r = smartlist_get(rl->routers,i);
    if (router_is_me(r)) {
      remove = 1;
    } else if (router_resolve(r)) {
      log_fn(LOG_WARN, "Couldn't resolve router %s; not using", r->address);
      remove = 1;
    }
    if (remove) {
      routerinfo_free(r);
      smartlist_del_keeporder(rl->routers, i--);
    }
  }

  return 0;
}

/** Decide whether a given addr:port is definitely accepted, definitely
 * rejected, or neither by a given exit policy.  If <b>addr</b> is 0, we
 * don't know the IP of the target address.
 *
 * Returns -1 for "rejected", 0 for "accepted", 1 for "maybe" (since IP is
 * unknown).
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
//    log_fn(LOG_DEBUG,"Considering exit policy %s", tmpe->string);
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
      log_fn(LOG_DEBUG,"Address %s:%d matches exit policy '%s'",
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

/** Return 1 if all running routers will reject addr:port, return 0 if
 * any might accept it. */
int router_exit_policy_all_routers_reject(uint32_t addr, uint16_t port) {
  int i;
  routerinfo_t *router;

  for (i=0;i<smartlist_len(routerlist->routers);i++) {
    router = smartlist_get(routerlist->routers, i);
    if (router->is_running && router_compare_addr_to_exit_policy(
             addr, port, router->exit_policy) != ADDR_POLICY_REJECTED)
      return 0; /* this one could be ok. good enough. */
  }
  return 1; /* all will reject. */
}

/** Return true iff <b>router</b> does not permit exit streams.
 */
int router_exit_policy_rejects_all(routerinfo_t *router) {
  return router_compare_addr_to_exit_policy(0, 0, router->exit_policy)
    == ADDR_POLICY_REJECTED;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
