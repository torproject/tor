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
static routerinfo_t *
router_pick_directory_server_impl(int requireauth, int requireothers, int fascistfirewall);
static void mark_all_authdirservers_up(void);
static int router_resolve_routerlist(routerlist_t *dir);

/****************************************************************************/

/** List of digests of keys for servers that are trusted directories. */
static smartlist_t *trusted_dir_digests = NULL;

/****
 * Functions to manage and access our list of known routers. (Note:
 * dirservers maintain a separate, independent list of known router
 * descriptors.)
 *****/

/** Global list of all of the routers that we, as an OR or OP, know about. */
static routerlist_t *routerlist = NULL;

extern int has_fetched_directory; /**< from main.c */

/** Try to find a running dirserver. If there are no running dirservers
 * in our routerlist, set all the authoritative ones as running again,
 * and pick one. If there are no dirservers at all in our routerlist,
 * reload the routerlist and try one last time. */
routerinfo_t *router_pick_directory_server(int requireauth, int requireothers) {
  routerinfo_t *choice;

  choice = router_pick_directory_server_impl(requireauth, requireothers, options.FascistFirewall);
  if(choice)
    return choice;

  log_fn(LOG_INFO,"No dirservers are reachable. Trying them all again.");
  /* mark all authdirservers as up again */
  mark_all_authdirservers_up();
  /* try again */
  choice = router_pick_directory_server_impl(requireauth, requireothers, 0);
  if(choice)
    return choice;

  log_fn(LOG_WARN,"Still no dirservers %s. Reloading and trying again.",
         options.FascistFirewall ? "reachable" : "known");
  has_fetched_directory=0; /* reset it */
  routerlist_clear_trusted_directories();
  if(options.RouterFile) {
    if(router_load_routerlist_from_file(options.RouterFile, 1) < 0)
      return NULL;
  } else {
    if(config_assign_default_dirservers() < 0)
      return NULL;
  }
  /* give it one last try */
  choice = router_pick_directory_server_impl(requireauth, requireothers, 0);
  return choice;
}

/** Pick a random running router from our routerlist. If requireauth,
 * it has to be a trusted server. If requireothers, it cannot be us.
 */
static routerinfo_t *
router_pick_directory_server_impl(int requireauth, int requireothers, int fascistfirewall)
{
  int i;
  routerinfo_t *router;
  smartlist_t *sl;
  char buf[16];

  if(!routerlist)
    return NULL;

  /* Find all the running dirservers we know about. */
  sl = smartlist_create();
  for(i=0;i< smartlist_len(routerlist->routers); i++) {
    router = smartlist_get(routerlist->routers, i);
    if(!router->is_running || !router->dir_port)
      continue;
    if(requireauth && !router->is_trusted_dir)
      continue;
    if(requireothers && router_is_me(router))
      continue;
    if(fascistfirewall) {
      sprintf(buf,"%d",router->dir_port);
      if (!smartlist_string_isin(options.FirewallPorts, buf))
        continue;
    }
    smartlist_add(sl, router);
  }

  router = smartlist_choose(sl);
  smartlist_free(sl);
  return router;
}

/** Go through and mark the auth dirservers as up */
static void mark_all_authdirservers_up(void) {
  int i;
  routerinfo_t *router;

  if(!routerlist)
    return;

  for(i=0; i < smartlist_len(routerlist->routers); i++) {
    router = smartlist_get(routerlist->routers, i);
    if(router->is_trusted_dir) {
      tor_assert(router->dir_port > 0);
      router->is_running = 1;
      router->status_set_at = time(NULL);
    }
  }
}

/** Return 0 if \exists an authoritative dirserver that's currently
 * thought to be running, else return 1.
 */
int all_directory_servers_down(void) {
  int i;
  routerinfo_t *router;
  if(!routerlist)
    return 1; /* if no dirservers, I guess they're all down */
  for(i=0;i< smartlist_len(routerlist->routers); i++) {
    router = smartlist_get(routerlist->routers, i);
    if(router->is_running && router->is_trusted_dir) {
      tor_assert(router->dir_port > 0);
      return 0;
    }
  }
  return 1;
}

/** Given a comma-and-whitespace separated list of nicknames, see which
 * nicknames in <b>list</b> name routers in our routerlist that are
 * currently running.  Add the routerinfos for those routers to <b>sl</b>.
 */
void
add_nickname_list_to_smartlist(smartlist_t *sl, const char *list, int warn_if_down)
{
  const char *start,*end;
  char nick[MAX_HEX_NICKNAME_LEN+1];
  routerinfo_t *router;

  tor_assert(sl);
  tor_assert(list);

  while(isspace((int)*list) || *list==',') list++;

  start = list;
  while(*start) {
    end=start; while(*end && !isspace((int)*end) && *end != ',') end++;
    if (end-start > MAX_HEX_NICKNAME_LEN) {
      log_fn(LOG_WARN,"Nickname too long; skipping");
      start = end;
      continue;
    }
    memcpy(nick,start,end-start);
    nick[end-start] = 0; /* null terminate it */
    router = router_get_by_nickname(nick);
    if (router) {
      if (router->is_running)
        smartlist_add(sl,router);
      else
        log_fn(warn_if_down ? LOG_WARN : LOG_DEBUG,
               "Nickname list includes '%s' which is known but down.",nick);
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
static void
router_add_running_routers_to_smartlist(smartlist_t *sl, int allow_unverified,
                                        int preferuptime, int preferbandwidth)
{
  routerinfo_t *router;
  int i;

  if(!routerlist)
    return;

  for(i=0;i<smartlist_len(routerlist->routers);i++) {
    router = smartlist_get(routerlist->routers, i);
    if(router->is_running &&
       (router->is_verified ||
       (allow_unverified &&
        !router_is_unreliable_router(router, preferuptime, preferbandwidth)))) {
      /* If it's running, and either it's verified or we're ok picking
       * unverified routers and this one is suitable.
       */
      smartlist_add(sl, router);
    }
  }
}

routerinfo_t *
routerlist_find_my_routerinfo(void) {
  routerinfo_t *router;
  int i;

  if(!routerlist)
    return NULL;

  for(i=0;i<smartlist_len(routerlist->routers);i++) {
    router = smartlist_get(routerlist->routers, i);
    if(router_is_me(router))
      return router;
  }
  return NULL;
}

/** How many seconds a router must be up before we'll use it for
 * reliability-critical node positions.
 */
#define ROUTER_REQUIRED_MIN_UPTIME 3600 /* an hour */
#define ROUTER_REQUIRED_MIN_BANDWIDTH 10000

int
router_is_unreliable_router(routerinfo_t *router, int need_uptime, int need_bw)
{
  if(need_uptime && router->uptime < ROUTER_REQUIRED_MIN_UPTIME)
    return 1;
  if(need_bw && router->bandwidthcapacity < ROUTER_REQUIRED_MIN_BANDWIDTH)
    return 1;
  return 0;
}

static void
routerlist_sl_remove_unreliable_routers(smartlist_t *sl)
{
  int i;
  routerinfo_t *router;

  for (i = 0; i < smartlist_len(sl); ++i) {
    router = smartlist_get(sl, i);
    if(router_is_unreliable_router(router, 1, 0)) {
      log(LOG_DEBUG, "Router %s has insufficient uptime; deleting.",
          router->nickname);
      smartlist_del(sl, i--);
    }
  }
}

routerinfo_t *
routerlist_sl_choose_by_bandwidth(smartlist_t *sl)
{
  int i;
  routerinfo_t *router;
  smartlist_t *bandwidths;
  uint32_t this_bw, tmp, total_bw=0, rand_bw;
  uint32_t *p;

  bandwidths = smartlist_create();
  for (i = 0; i < smartlist_len(sl); ++i) {
    router = smartlist_get(sl, i);
    /* give capacity a default, until 0.0.7 is obsolete */
    tmp = (router->bandwidthcapacity == 0) ? 200000 : router->bandwidthcapacity;
    this_bw = (tmp < router->bandwidthrate) ? tmp : router->bandwidthrate;
    if(this_bw > 800000)
      this_bw = 800000; /* if they claim something huge, don't believe it */
    p = tor_malloc(sizeof(uint32_t));
    *p = this_bw;
    smartlist_add(bandwidths, p);
    total_bw += this_bw;
//    log_fn(LOG_INFO,"Recording bw %d for node %s.", this_bw, router->nickname);
  }
  if(!total_bw)
    return NULL; 
  rand_bw = crypto_pseudo_rand_int(total_bw);
//  log_fn(LOG_INFO,"Total bw %d. Randomly chose %d.", total_bw, rand_bw);
  tmp = 0;
  for(i=0; ; i++) {
    tor_assert(i < smartlist_len(sl));
    p = smartlist_get(bandwidths, i);
    tmp += *p;
    router = smartlist_get(sl, i);
//    log_fn(LOG_INFO,"Considering %s. tmp = %d.", router->nickname, tmp);
    if(tmp >= rand_bw)
      break;
  }
  SMARTLIST_FOREACH(bandwidths, uint32_t*, p, tor_free(p));
  smartlist_free(bandwidths);
  router = smartlist_get(sl, i);
//  log_fn(LOG_INFO,"Picked %s.", router->nickname);
  return router;
}

/** Return a random running router from the routerlist.  If any node
 * named in <b>preferred</b> is available, pick one of those.  Never
 * pick a node named in <b>excluded</b>, or whose routerinfo is in
 * <b>excludedsmartlist</b>, even if they are the only nodes
 * available.  If <b>strict</b> is true, never pick any node besides
 * those in <b>preferred</b>.
 */
routerinfo_t *router_choose_random_node(char *preferred, char *excluded,
                                        smartlist_t *excludedsmartlist,
                                        int preferuptime, int preferbandwidth,
                                        int allow_unverified, int strict)
{
  smartlist_t *sl, *excludednodes;
  routerinfo_t *choice;

  excludednodes = smartlist_create();
  add_nickname_list_to_smartlist(excludednodes,excluded,0);

  /* try the preferred nodes first */
  sl = smartlist_create();
  add_nickname_list_to_smartlist(sl,preferred,1);
  smartlist_subtract(sl,excludednodes);
  if(excludedsmartlist)
    smartlist_subtract(sl,excludedsmartlist);
  if(preferuptime)
    routerlist_sl_remove_unreliable_routers(sl);
  if(preferbandwidth)
    choice = routerlist_sl_choose_by_bandwidth(sl);
  else
    choice = smartlist_choose(sl);
  smartlist_free(sl);
  if(!choice && !strict) {
    sl = smartlist_create();
    router_add_running_routers_to_smartlist(sl, allow_unverified,
                                            preferuptime, preferbandwidth);
    smartlist_subtract(sl,excludednodes);
    if(excludedsmartlist)
      smartlist_subtract(sl,excludedsmartlist);
    if(preferuptime)
      routerlist_sl_remove_unreliable_routers(sl);
    if(preferbandwidth)
      choice = routerlist_sl_choose_by_bandwidth(sl);
    else
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

/** Return true iff the digest of <b>router</b>'s identity key,
 * encoded in hexadecimal, matches <b>hexdigest</b> (which is
 * optionally prefixed with a single dollar sign).  Return false if
 * <b>hexdigest</b> is malformed, or it doesn't match.  */
static INLINE int router_hex_digest_matches(routerinfo_t *router,
                                     const char *hexdigest)
{
  char digest[DIGEST_LEN];
  tor_assert(hexdigest);
  if (hexdigest[0] == '$')
    ++hexdigest;

  if (strlen(hexdigest) != HEX_DIGEST_LEN ||
      base16_decode(digest, DIGEST_LEN, hexdigest, HEX_DIGEST_LEN)<0)
    return 0;
  else
    return (!memcmp(digest, router->identity_digest, DIGEST_LEN));
}

/* Return true if <b>router</b>'s nickname matches <b>nickname</b>
 * (case-insensitive), or if <b>router's</b> identity key digest
 * matches a hexadecimal value stored in <b>nickname</b>.  Return
 * false otherwise.*/
int router_nickname_matches(routerinfo_t *router, const char *nickname)
{
  if (nickname[0]!='$' && !strcasecmp(router->nickname, nickname))
    return 1;
  else
    return router_hex_digest_matches(router, nickname);
}

/** Return the router in our routerlist whose (case-insensitive)
 * nickname or (case-sensitive) hexadecimal key digest is
 * <b>nickname</b>.  Return NULL if no such router is known.
 */
routerinfo_t *router_get_by_nickname(const char *nickname)
{
  int i, maybedigest;
  routerinfo_t *router;
  char digest[DIGEST_LEN];

  tor_assert(nickname);
  if (!routerlist)
    return NULL;
  if (nickname[0] == '$')
    return router_get_by_hexdigest(nickname);

  maybedigest = (strlen(nickname) == HEX_DIGEST_LEN) &&
    (base16_decode(digest,DIGEST_LEN,nickname,HEX_DIGEST_LEN) == 0);

  for(i=0;i<smartlist_len(routerlist->routers);i++) {
    router = smartlist_get(routerlist->routers, i);
    if (0 == strcasecmp(router->nickname, nickname) ||
        (maybedigest && 0 == memcmp(digest, router->identity_digest,
                                    DIGEST_LEN)))
      return router;
  }

  return NULL;
}

/* XXX008 currently this trusted_dir_digests stuff is not used. */
/** Return true iff <b>digest</b> is the digest of the identity key of
 * a trusted directory. */
int router_digest_is_trusted_dir(const char *digest) {
  if (!trusted_dir_digests)
    return 0;
  SMARTLIST_FOREACH(trusted_dir_digests, char *, cp,
                    if (!memcmp(digest, cp, DIGEST_LEN)) return 1);
  return 0;
}

/** Return the router in our routerlist whose hexadecimal key digest
 * is <b>hexdigest</b>.  Return NULL if no such router is known. */
routerinfo_t *router_get_by_hexdigest(const char *hexdigest) {
  char digest[DIGEST_LEN];

  tor_assert(hexdigest);
  if (!routerlist)
    return NULL;
  if (hexdigest[0]=='$')
    ++hexdigest;
  if (strlen(hexdigest) != HEX_DIGEST_LEN ||
      base16_decode(digest,DIGEST_LEN,hexdigest,HEX_DIGEST_LEN) < 0)
    return NULL;

  return router_get_by_digest(digest);
}

/** Return the router in our routerlist whose 20-byte key digest
 * is <b>hexdigest</b>.  Return NULL if no such router is known. */
routerinfo_t *router_get_by_digest(const char *digest) {
  int i;
  routerinfo_t *router;

  tor_assert(digest);

  for(i=0;i<smartlist_len(routerlist->routers);i++) {
    router = smartlist_get(routerlist->routers, i);
    if (0 == memcmp(router->identity_digest, digest, DIGEST_LEN))
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
  if (!router)
    return;

  tor_free(router->address);
  tor_free(router->nickname);
  tor_free(router->platform);
  if (router->onion_pkey)
    crypto_free_pk_env(router->onion_pkey);
  if (router->identity_pkey)
    crypto_free_pk_env(router->identity_pkey);
  exit_policy_free(router->exit_policy);
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

/** Mark the router with ID <b>digest</b> as non-running in our routerlist. */
void router_mark_as_down(const char *digest) {
  routerinfo_t *router;
  tor_assert(digest);
  router = router_get_by_digest(digest);
  if(!router) /* we don't seem to know about him in the first place */
    return;
  log_fn(LOG_DEBUG,"Marking %s as down.",router->nickname);
  router->is_running = 0;
  router->status_set_at = time(NULL);
}

/** Add <b>router</b> to the routerlist, if we don't already have it.  Replace
 * older entries (if any) with the same name.  Note: Callers should not hold
 * their pointers to <b>router</b> after invoking this function; <b>router</b>
 * will either be inserted into the routerlist or freed.  Returns 0 if the
 * router was added; -1 if it was not.
 */
int router_add_to_routerlist(routerinfo_t *router) {
  int i;
  routerinfo_t *r;
  char id_digest[DIGEST_LEN];

  crypto_pk_get_digest(router->identity_pkey, id_digest);

  /* If we have a router with this name, and the identity key is the same,
   * choose the newer one. If the identity key has changed, drop the router.
   */
  for (i = 0; i < smartlist_len(routerlist->routers); ++i) {
    r = smartlist_get(routerlist->routers, i);
    if (!crypto_pk_cmp_keys(router->identity_pkey, r->identity_pkey)) {
      if (router->published_on > r->published_on) {
        log_fn(LOG_DEBUG, "Replacing entry for router '%s/%s' [%s]",
               router->nickname, r->nickname, hex_str(id_digest,DIGEST_LEN));
        /* Remember whether we trust this router as a dirserver. */
        if (r->is_trusted_dir)
          router->is_trusted_dir = 1;
        /* If the address hasn't changed; no need to re-resolve. */
        if (!strcasecmp(r->address, router->address))
          router->addr = r->addr;
        routerinfo_free(r);
        smartlist_set(routerlist->routers, i, router);
        return 0;
      } else {
        log_fn(LOG_DEBUG, "Skipping old entry for router '%s'",
               router->nickname);
        /* If we now trust 'router', then we trust the one in the routerlist
         * too. */
        if (router->is_trusted_dir)
          r->is_trusted_dir = 1;
        /* Update the is_running status to whatever we were told. */
        r->is_running = router->is_running;
        routerinfo_free(router);
        return -1;
      }
    } else if (!strcasecmp(router->nickname, r->nickname)) {
      /* nicknames match, keys don't. */
      if (router->is_verified) {
        /* The new verified router replaces the old one; remove the
         * old one.  And carry on to the end of the list, in case
         * there are more old unverifed routers with this nickname
         */
        /* mark-for-close connections using the old key, so we can
         * make new ones with the new key.
         */
        connection_t *conn;
        while((conn = connection_get_by_identity_digest(r->identity_digest,
                                                        CONN_TYPE_OR))) {
          log_fn(LOG_INFO,"Closing conn to obsolete router '%s'", r->nickname);
          connection_mark_for_close(conn);
        }
        routerinfo_free(r);
        smartlist_del_keeporder(routerlist->routers, i--);
      } else if (r->is_verified) {
        /* Can't replace a verified router with an unverified one. */
        log_fn(LOG_DEBUG, "Skipping unverified entry for verified router '%s'",
               router->nickname);
        routerinfo_free(router);
        return -1;
      }
    }
  }
  /* We haven't seen a router with this name before.  Add it to the end of
   * the list. */
  smartlist_add(routerlist->routers, router);
  return 0;
}

/** Remove any routers from the routerlist that are more than <b>age</b>
 * seconds old.
 *
 * (This function is just like dirserv_remove_old_servers. One day we should
 * merge them.)
 */
void
routerlist_remove_old_routers(int age)
{
  int i;
  time_t cutoff;
  routerinfo_t *router;
  if (!routerlist)
    return;

  cutoff = time(NULL) - age;
  for (i = 0; i < smartlist_len(routerlist->routers); ++i) {
    router = smartlist_get(routerlist->routers, i);
    if (router->published_on <= cutoff &&
      !router->is_trusted_dir) {
      /* Too old.  Remove it. But never remove dirservers! */
      log_fn(LOG_INFO,"Forgetting obsolete routerinfo for node %s.", router->nickname);
      routerinfo_free(router);
      smartlist_del(routerlist->routers, i--);
    }
  }
}

/*
 * Code to parse router descriptors and directories.
 */

/** Update the current router list with the one stored in
 * <b>routerfile</b>. If <b>trusted</b> is true, then we'll use
 * directory servers from the file. */
int router_load_routerlist_from_file(char *routerfile, int trusted)
{
  char *string;

  string = read_file_to_str(routerfile);
  if(!string) {
    log_fn(LOG_WARN,"Failed to load routerfile %s.",routerfile);
    return -1;
  }

  if(router_load_routerlist_from_string(string, trusted) < 0) {
    log_fn(LOG_WARN,"The routerfile itself was corrupt.");
    free(string);
    return -1;
  }
  /* dump_onion_keys(LOG_NOTICE); */

  free(string);
  return 0;
}

/** Mark all directories in the routerlist as nontrusted. */
void routerlist_clear_trusted_directories(void)
{
  if (routerlist) {
    SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, r,
                      r->is_trusted_dir = 0);
  }
  if (trusted_dir_digests) {
    SMARTLIST_FOREACH(trusted_dir_digests, char *, cp, tor_free(cp));
    smartlist_clear(trusted_dir_digests);
  }
}

/** Helper function: read routerinfo elements from s, and throw out the
 * ones that don't parse and resolve.  Add all remaining elements to the
 * routerlist.  If <b>trusted</b> is true, then we'll use
 * directory servers from the string
 */
int router_load_routerlist_from_string(const char *s, int trusted)
{
  routerlist_t *new_list=NULL;

  if (router_parse_list_from_string(&s, &new_list, NULL, 0)) {
    log(LOG_WARN, "Error parsing router file");
    return -1;
  }
  if (trusted) {
    int i;
    if (!trusted_dir_digests)
      trusted_dir_digests = smartlist_create();
    for (i=0;i<smartlist_len(new_list->routers);++i) {
      routerinfo_t *r = smartlist_get(new_list->routers, i);
      if (r->dir_port) {
        char *b;
        log_fn(LOG_DEBUG,"Trusting router %s.", r->nickname);
        r->is_trusted_dir = 1;
        b = tor_malloc(DIGEST_LEN);
        memcpy(b, r->identity_digest, DIGEST_LEN);
        smartlist_add(trusted_dir_digests, b);
      }
    }
  }
  if (routerlist) {
    SMARTLIST_FOREACH(new_list->routers, routerinfo_t *, r,
                      router_add_to_routerlist(r));
    smartlist_clear(new_list->routers);
    routerlist_free(new_list);
  } else {
    routerlist = new_list;
  }
  if (router_resolve_routerlist(routerlist)) {
    log(LOG_WARN, "Error resolving routerlist");
    return -1;
  }
  /* dump_onion_keys(LOG_NOTICE); */

  return 0;
}

/** Add to the current routerlist each router stored in the
 * signed directory <b>s</b>.  If pkey is provided, check the signature against
 * pkey; else check against the pkey of the signing directory server. */
int router_load_routerlist_from_directory(const char *s,
                                          crypto_pk_env_t *pkey)
{
  routerlist_t *new_list = NULL;
  if (router_parse_routerlist_from_directory(s, &new_list, pkey)) {
    log_fn(LOG_WARN, "Couldn't parse directory.");
    return -1;
  }
  if (routerlist) {
    SMARTLIST_FOREACH(new_list->routers, routerinfo_t *, r,
                      router_add_to_routerlist(r));
    smartlist_clear(new_list->routers);
    routerlist->published_on = new_list->published_on;
    tor_free(routerlist->software_versions);
    routerlist->software_versions = new_list->software_versions;
    new_list->software_versions = NULL;
    routerlist_free(new_list);
  } else {
    routerlist = new_list;
  }
  if (router_resolve_routerlist(routerlist)) {
    log_fn(LOG_WARN, "Error resolving routerlist");
    return -1;
  }
  if (options.AuthoritativeDir) {
    /* Learn about the descriptors in the directory. */
    dirserv_load_from_directory_string(s);
  } else {
    /* Remember the directory. */
    dirserv_set_cached_directory(s, routerlist->published_on);
  }
  return 0;
}

/** Helper function: resolve the hostname for <b>router</b>. */
static int
router_resolve(routerinfo_t *router)
{
  if (tor_lookup_hostname(router->address, &router->addr) != 0
      || !router->addr) {
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
    } else if (r->addr) {
      /* already resolved. */
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

/** Release all space held in <b>rr</b>. */
void running_routers_free(running_routers_t *rr)
{
  tor_assert(rr);
  if (rr->running_routers) {
    SMARTLIST_FOREACH(rr->running_routers, char *, s, tor_free(s));
    smartlist_free(rr->running_routers);
  }
  tor_free(rr);
}

/** Update the running/not-running status of every router in <b>list</b>, based
 * on the contents of <b>rr</b>. */
/* Note: this function is not yet used, since nobody publishes just
 * running-router lists yet. */
void routerlist_update_from_runningrouters(routerlist_t *list,
                                           running_routers_t *rr)
{
  int n_routers, i;
  routerinfo_t *router, *me = router_get_my_routerinfo();
  if (!list)
    return;
  if (list->published_on >= rr->published_on)
    return;
  if (list->running_routers_updated_on >= rr->published_on)
    return;

  if(me) { /* learn if the dirservers think I'm verified */
    router_update_status_from_smartlist(me,
                                        rr->published_on,
                                        rr->running_routers);
  }
  n_routers = smartlist_len(list->routers);
  for (i=0; i<n_routers; ++i) {
    router = smartlist_get(list->routers, i);
    router_update_status_from_smartlist(router,
                                        rr->published_on,
                                        rr->running_routers);
  }
  list->running_routers_updated_on = rr->published_on;
}

/** Update the is_running and is_verified fields of the router <b>router</b>,
 * based in its status in the list of strings stored in <b>running_list</b>.
 * All entries in <b>running_list</b> follow one of these formats:
 * <ol><li> <b>nickname</b> -- router is running and verified.
 *     <li> !<b>nickname</b> -- router is not-running and verified.
 *     <li> $<b>hexdigest</b> -- router is running and unverified.
 *     <li> !$<b>hexdigest</b> -- router is not-running and unverified.
 * </ol>
 *
 * Return 1 if we found router in running_list, else return 0.
 */
int router_update_status_from_smartlist(routerinfo_t *router,
                                        time_t list_time,
                                        smartlist_t *running_list)
{
  int n_names, i, running, approved;
  const char *name;
#if 1
  char *cp;
  int n;
  n = 0;
  for (i=0; i<smartlist_len(running_list); ++i) {
    name = smartlist_get(running_list, i);
    n += strlen(name) + 1;
  }
  cp = tor_malloc(n+2);
  cp[0] = '\0';
  for (i=0; i<smartlist_len(running_list); ++i) {
    name = smartlist_get(running_list, i);
    strlcat(cp, name, n);
    strlcat(cp, " ", n);
  }
  log_fn(LOG_DEBUG, "Updating status of %s from list \"%s\"",
         router->nickname, cp);
  tor_free(cp);
#endif

  running = approved = 0;
  n_names = smartlist_len(running_list);
  for (i=0; i<n_names; ++i) {
    name = smartlist_get(running_list, i);
    if (*name != '!') {
      if (router_nickname_matches(router, name)) {
        if (router->status_set_at < list_time) {
          router->status_set_at = list_time;
          router->is_running = 1;
        }
        router->is_verified = (name[0] != '$');
        return 1;
      }
    } else { /* *name == '!' */
      name++;
      if (router_nickname_matches(router, name)) {
        if (router->status_set_at < list_time) {
          router->status_set_at = list_time;
          router->is_running = 0;
        }
        router->is_verified = (name[0] != '$');
        return 1;
      }
    }
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
