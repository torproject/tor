/* Copyright 2001 Matej Pfajfar.
 * Copyright 2001-2004 Roger Dingledine.
 * Copyright 2004-2005 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char routerlist_c_id[] = "$Id$";

#include "or.h"

/**
 * \file routerlist.c
 *
 * \brief Code to
 * maintain and access the global list of routerinfos for known
 * servers.
 **/

/****************************************************************************/

static smartlist_t *trusted_dir_servers = NULL;

/* static function prototypes */
static routerinfo_t *
router_pick_directory_server_impl(int requireothers, int fascistfirewall,
                                  int for_runningrouters);
static trusted_dir_server_t *
router_pick_trusteddirserver_impl(int requireother, int fascistfirewall);
static void mark_all_trusteddirservers_up(void);
static int router_resolve(routerinfo_t *router);
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

/**
 * Reload the original list of trusted dirservers, and the most recent
 * cached directory (if present).
 */
int router_reload_router_list(void)
{
  char filename[512];
  int is_recent;
  struct stat st;
  char *s;
  tor_assert(get_options()->DataDirectory);

  tor_snprintf(filename,sizeof(filename),"%s/cached-directory",
               get_options()->DataDirectory);
  s = read_file_to_str(filename,0);
  if (s) {
    stat(filename, &st); /* if s is true, stat probably worked */
    log_fn(LOG_INFO, "Loading cached directory from %s", filename);
    is_recent = st.st_mtime > time(NULL) - 60*15;
    if (router_load_routerlist_from_directory(s, NULL, is_recent, 1) < 0) {
      log_fn(LOG_WARN, "Cached directory at '%s' was unparseable; ignoring.", filename);
    }
    if (routerlist &&
        ((routerlist->published_on > time(NULL) - MIN_ONION_KEY_LIFETIME/2)
         || is_recent)) {
      directory_has_arrived(st.st_mtime, NULL); /* do things we've been waiting to do */
    }
    tor_free(s);
  }
  return 0;
}

/* Set *<b>outp</b> to a smartlist containing a list of
 * trusted_dir_server_t * for all known trusted dirservers.  Callers
 * must not modify the list or its contents.
 */
void router_get_trusted_dir_servers(smartlist_t **outp)
{
  if (!trusted_dir_servers)
    trusted_dir_servers = smartlist_create();

  *outp = trusted_dir_servers;
}

/** Try to find a running dirserver. If there are no running dirservers
 * in our routerlist, set all the authoritative ones as running again,
 * and pick one. If there are no dirservers at all in our routerlist,
 * reload the routerlist and try one last time.  If for_runningrouters is
 * true, then only pick a dirserver that can answer runningrouters queries
 * (that is, a trusted dirserver, or one running 0.0.9rc5-cvs or later).
 */
routerinfo_t *router_pick_directory_server(int requireothers,
                                           int fascistfirewall,
                                           int for_runningrouters,
                                           int retry_if_no_servers) {
  routerinfo_t *choice;

  if (!routerlist)
    return NULL;

  choice = router_pick_directory_server_impl(requireothers, fascistfirewall,
                                             for_runningrouters);
  if (choice || !retry_if_no_servers)
    return choice;

  log_fn(LOG_INFO,"No reachable router entries for dirservers. Trying them all again.");
  /* mark all authdirservers as up again */
  mark_all_trusteddirservers_up();
  /* try again */
  choice = router_pick_directory_server_impl(requireothers, fascistfirewall,
                                             for_runningrouters);
  if (choice)
    return choice;

  log_fn(LOG_INFO,"Still no %s router entries. Reloading and trying again.",
         get_options()->FascistFirewall ? "reachable" : "known");
  has_fetched_directory=0; /* reset it */
  if (router_reload_router_list()) {
    return NULL;
  }
  /* give it one last try */
  choice = router_pick_directory_server_impl(requireothers, 0,
                                             for_runningrouters);
  return choice;
}

trusted_dir_server_t *router_pick_trusteddirserver(int requireothers,
                                                   int fascistfirewall,
                                                   int retry_if_no_servers) {
  trusted_dir_server_t *choice;

  choice = router_pick_trusteddirserver_impl(requireothers, fascistfirewall);
  if (choice || !retry_if_no_servers)
    return choice;

  log_fn(LOG_INFO,"No trusted dirservers are reachable. Trying them all again.");
  /* mark all authdirservers as up again */
  mark_all_trusteddirservers_up();
  /* try again */
  choice = router_pick_trusteddirserver_impl(requireothers, fascistfirewall);
  if (choice)
    return choice;

  log_fn(LOG_WARN,"Still no dirservers %s. Reloading and trying again.",
         get_options()->FascistFirewall ? "reachable" : "known");
  has_fetched_directory=0; /* reset it */
  if (router_reload_router_list()) {
    return NULL;
  }
  /* give it one last try */
  choice = router_pick_trusteddirserver_impl(requireothers, 0);
  return choice;
}

/** Pick a random running router from our routerlist. If requireauth,
 * it has to be a trusted server. If requireothers, it cannot be us.
 */
static routerinfo_t *
router_pick_directory_server_impl(int requireothers, int fascistfirewall,
                                  int for_runningrouters)
{
  int i;
  routerinfo_t *router;
  smartlist_t *sl;

  if (!routerlist)
    return NULL;

  if (get_options()->HttpProxy)
    fascistfirewall = 0;

  /* Find all the running dirservers we know about. */
  sl = smartlist_create();
  for (i=0;i < smartlist_len(routerlist->routers); i++) {
    router = smartlist_get(routerlist->routers, i);
    if (!router->is_running || !router->dir_port || !router->is_verified)
      continue;
    if (requireothers && router_is_me(router))
      continue;
    if (fascistfirewall) {
      if (!smartlist_string_num_isin(get_options()->FirewallPorts, router->dir_port))
        continue;
    }
    /* before 0.0.9rc5-cvs, only trusted dirservers served status info. */
    if (for_runningrouters &&
        !(tor_version_as_new_as(router->platform,"0.0.9rc5-cvs") ||
          router_digest_is_trusted_dir(router->identity_digest)))
      continue;
    smartlist_add(sl, router);
  }

  router = smartlist_choose(sl);
  smartlist_free(sl);
  return router;
}

static trusted_dir_server_t *
router_pick_trusteddirserver_impl(int requireother, int fascistfirewall)
{
  smartlist_t *sl;
  routerinfo_t *me;
  trusted_dir_server_t *ds;
  sl = smartlist_create();
  me = router_get_my_routerinfo();

  if (!trusted_dir_servers)
    return NULL;

  if (get_options()->HttpProxy)
    fascistfirewall = 0;

  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, d,
    {
      if (!d->is_running) continue;
      if (requireother && me &&
          !memcmp(me->identity_digest, d->digest, DIGEST_LEN))
        continue;
      if (fascistfirewall) {
        if (!smartlist_string_num_isin(get_options()->FirewallPorts, d->dir_port))
          continue;
      }
      smartlist_add(sl, d);
    });

  ds = smartlist_choose(sl);
  smartlist_free(sl);
  return ds;
}

/** Go through and mark the auth dirservers as up */
static void mark_all_trusteddirservers_up(void) {
  if (routerlist) {
    SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
                 if (router_digest_is_trusted_dir(router->identity_digest) &&
                     router->dir_port > 0) {
                   router->is_running = 1;
                   router->status_set_at = time(NULL);
                 });
  }
  if (trusted_dir_servers) {
    SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, dir,
                      dir->is_running = 1);
  }
}

/** Return 0 if \\exists an authoritative dirserver that's currently
 * thought to be running, else return 1.
 */
int all_trusted_directory_servers_down(void) {
  if (!trusted_dir_servers)
    return 1;
  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, dir,
                    if (dir->is_running) return 0);
  return 1;
}

/** Add all the family of <b>router</b> to the smartlist <b>sl</b>.
 */
void routerlist_add_family(smartlist_t *sl, routerinfo_t *router) {
  routerinfo_t *r;
  struct config_line_t *cl;

  if (!router->declared_family)
    return;

  /* Add every r such that router declares familyness with r, and r
   * declares familyhood with router. */
  SMARTLIST_FOREACH(router->declared_family, const char *, n,
    {
      if (!(r = router_get_by_nickname(n)))
        continue;
      if (!r->declared_family)
        continue;
      SMARTLIST_FOREACH(r->declared_family, const char *, n2,
        {
          if (router_nickname_matches(router, n2))
            smartlist_add(sl, r);
        });
    });

  for (cl = get_options()->NodeFamilies; cl; cl = cl->next) {
    if (router_nickname_is_in_list(router, cl->value)) {
      add_nickname_list_to_smartlist(sl, cl->value, 0);
    }
  }
}

/** List of string for nicknames we've warned about and haven't yet succeeded.
 */
static smartlist_t *warned_nicknames = NULL;

/** Given a comma-and-whitespace separated list of nicknames, see which
 * nicknames in <b>list</b> name routers in our routerlist that are
 * currently running.  Add the routerinfos for those routers to <b>sl</b>.
 */
void
add_nickname_list_to_smartlist(smartlist_t *sl, const char *list, int warn_if_down)
{
  routerinfo_t *router;
  smartlist_t *nickname_list;

  if (!list)
    return; /* nothing to do */
  tor_assert(sl);

  nickname_list = smartlist_create();
  if (!warned_nicknames)
    warned_nicknames = smartlist_create();

  smartlist_split_string(nickname_list, list, ",",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);

  SMARTLIST_FOREACH(nickname_list, const char *, nick, {
    int warned;
    if (!is_legal_nickname_or_hexdigest(nick)) {
      log_fn(LOG_WARN,"Nickname %s is misformed; skipping", nick);
      continue;
    }
    router = router_get_by_nickname(nick);
    warned = smartlist_string_isin(warned_nicknames, nick);
    if (router) {
      if (router->is_running) {
        smartlist_add(sl,router);
        if (warned)
          smartlist_string_remove(warned_nicknames, nick);
      } else {
        if (!warned) {
          log_fn(warn_if_down ? LOG_WARN : LOG_DEBUG,
                 "Nickname list includes '%s' which is known but down.",nick);
          smartlist_add(warned_nicknames, tor_strdup(nick));
        }
      }
    } else {
      if (!warned) {
        log_fn(has_fetched_directory ? LOG_WARN : LOG_INFO,
               "Nickname list includes '%s' which isn't a known router.",nick);
        smartlist_add(warned_nicknames, tor_strdup(nick));
      }
    }
  });
  SMARTLIST_FOREACH(nickname_list, char *, nick, tor_free(nick));
  smartlist_free(nickname_list);
}

/** Return 1 iff any member of the comma-separated list <b>list</b> is an
 * acceptable nickname or hexdigest for <b>router</b>.  Else return 0.
 */
int
router_nickname_is_in_list(routerinfo_t *router, const char *list)
{
  smartlist_t *nickname_list;
  int v = 0;

  if (!list)
    return 0; /* definitely not */
  tor_assert(router);

  nickname_list = smartlist_create();
  smartlist_split_string(nickname_list, list, ",",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  SMARTLIST_FOREACH(nickname_list, const char *, cp,
                    if (router_nickname_matches(router, cp)) {v=1;break;});
  SMARTLIST_FOREACH(nickname_list, char *, cp, tor_free(cp));
  smartlist_free(nickname_list);
  return v;
}

/** Add every router from our routerlist that is currently running to
 * <b>sl</b>.
 */
static void
router_add_running_routers_to_smartlist(smartlist_t *sl, int allow_unverified,
                                        int need_uptime, int need_capacity)
{
  routerinfo_t *router;
  int i;

  if (!routerlist)
    return;

  for (i=0;i<smartlist_len(routerlist->routers);i++) {
    router = smartlist_get(routerlist->routers, i);
    if (router->is_running &&
        (router->is_verified ||
        (allow_unverified &&
         !router_is_unreliable(router, need_uptime, need_capacity)))) {
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

  if (!routerlist)
    return NULL;

  for (i=0;i<smartlist_len(routerlist->routers);i++) {
    router = smartlist_get(routerlist->routers, i);
    if (router_is_me(router))
      return router;
  }
  return NULL;
}

int
router_is_unreliable(routerinfo_t *router, int need_uptime, int need_capacity)
{
  if (need_uptime && router->uptime < ROUTER_REQUIRED_MIN_UPTIME)
    return 1;
  if (need_capacity && router->bandwidthcapacity < ROUTER_REQUIRED_MIN_BANDWIDTH)
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
    if (router_is_unreliable(router, 1, 0)) {
      log(LOG_DEBUG, "Router '%s' has insufficient uptime; deleting.",
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
    this_bw = (router->bandwidthcapacity < router->bandwidthrate) ?
               router->bandwidthcapacity : router->bandwidthrate;
    if (this_bw > 2000000)
      this_bw = 2000000; /* if they claim something huge, don't believe it */
    p = tor_malloc(sizeof(uint32_t));
    *p = this_bw;
    smartlist_add(bandwidths, p);
    total_bw += this_bw;
//    log_fn(LOG_INFO,"Recording bw %d for node %s.", this_bw, router->nickname);
  }
  if (!total_bw) {
    SMARTLIST_FOREACH(bandwidths, uint32_t*, p, tor_free(p));
    smartlist_free(bandwidths);
    return smartlist_choose(sl);
  }
  rand_bw = crypto_pseudo_rand_int(total_bw);
//  log_fn(LOG_INFO,"Total bw %d. Randomly chose %d.", total_bw, rand_bw);
  tmp = 0;
  for (i=0; ; i++) {
    tor_assert(i < smartlist_len(sl));
    p = smartlist_get(bandwidths, i);
    tmp += *p;
    router = smartlist_get(sl, i);
//    log_fn(LOG_INFO,"Considering %s. tmp = %d.", router->nickname, tmp);
    if (tmp >= rand_bw)
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
routerinfo_t *router_choose_random_node(const char *preferred,
                                        const char *excluded,
                                        smartlist_t *excludedsmartlist,
                                        int need_uptime, int need_capacity,
                                        int allow_unverified, int strict)
{
  smartlist_t *sl, *excludednodes;
  routerinfo_t *choice;

  excludednodes = smartlist_create();
  add_nickname_list_to_smartlist(excludednodes,excluded,0);

  /* Try the preferred nodes first. Ignore need_uptime and need_capacity,
   * since the user explicitly asked for these nodes. */
  sl = smartlist_create();
  add_nickname_list_to_smartlist(sl,preferred,1);
  smartlist_subtract(sl,excludednodes);
  if (excludedsmartlist)
    smartlist_subtract(sl,excludedsmartlist);
#if 0
  if (need_uptime)
    routerlist_sl_remove_unreliable_routers(sl);
  if (need_capacity)
    choice = routerlist_sl_choose_by_bandwidth(sl);
  else
#endif
  choice = smartlist_choose(sl);
  smartlist_free(sl);
  if (!choice && !strict) {
    /* Then give up on our preferred choices: any node
     * will do that has the required attributes. */
    sl = smartlist_create();
    router_add_running_routers_to_smartlist(sl, allow_unverified,
                                            need_uptime, need_capacity);
    smartlist_subtract(sl,excludednodes);
    if (excludedsmartlist)
      smartlist_subtract(sl,excludedsmartlist);
    if (need_uptime)
      routerlist_sl_remove_unreliable_routers(sl);
    if (need_capacity)
      choice = routerlist_sl_choose_by_bandwidth(sl);
    else
      choice = smartlist_choose(sl);
    smartlist_free(sl);
  }
  smartlist_free(excludednodes);
  if (!choice)
    log_fn(LOG_WARN,"No available nodes when trying to choose node. Failing.");
  return choice;
}

/** Return the router in our routerlist whose address is <b>addr</b> and
 * whose OR port is <b>port</b>. Return NULL if no such router is known.
 */
routerinfo_t *router_get_by_addr_port(uint32_t addr, uint16_t port) {
  int i;
  routerinfo_t *router;

  if (!routerlist)
    return NULL;

  for (i=0;i<smartlist_len(routerlist->routers);i++) {
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
  if (server_mode(get_options()) &&
      !strcasecmp(nickname, get_options()->Nickname))
    return router_get_my_routerinfo();

  maybedigest = (strlen(nickname) == HEX_DIGEST_LEN) &&
    (base16_decode(digest,DIGEST_LEN,nickname,HEX_DIGEST_LEN) == 0);

  for (i=0;i<smartlist_len(routerlist->routers);i++) {
    router = smartlist_get(routerlist->routers, i);
    if (0 == strcasecmp(router->nickname, nickname) ||
        (maybedigest && 0 == memcmp(digest, router->identity_digest,
                                    DIGEST_LEN)))
      return router;
  }

  return NULL;
}

/** Return true iff <b>digest</b> is the digest of the identity key of
 * a trusted directory. */
int router_digest_is_trusted_dir(const char *digest) {
  if (!trusted_dir_servers)
    return 0;
  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ent,
                    if (!memcmp(digest, ent->digest, DIGEST_LEN)) return 1);
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
 * is <b>digest</b>.  Return NULL if no such router is known. */
routerinfo_t *router_get_by_digest(const char *digest) {
  int i;
  routerinfo_t *router;

  tor_assert(digest);
  if (server_mode(get_options()) &&
      (router = router_get_my_routerinfo()) &&
      !memcmp(digest, router->identity_digest, DIGEST_LEN))
    return router;
  if (!routerlist) return NULL;

  for (i=0;i<smartlist_len(routerlist->routers);i++) {
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

/** Return the publication time on the current routerlist, or 0 if we have no
 * routerlist. */
time_t routerlist_get_published_time(void) {
  return routerlist ? routerlist->published_on : 0;
}

/** Free all storage held by <b>router</b>. */
void routerinfo_free(routerinfo_t *router)
{
  if (!router)
    return;

  tor_free(router->signed_descriptor);
  tor_free(router->address);
  tor_free(router->nickname);
  tor_free(router->platform);
  tor_free(router->contact_info);
  if (router->onion_pkey)
    crypto_free_pk_env(router->onion_pkey);
  if (router->identity_pkey)
    crypto_free_pk_env(router->identity_pkey);
  if (router->declared_family) {
    SMARTLIST_FOREACH(router->declared_family, char *, s, tor_free(s));
    smartlist_free(router->declared_family);
  }
  addr_policy_free(router->exit_policy);
  tor_free(router);
}

/** Allocate a fresh copy of <b>router</b> */
routerinfo_t *routerinfo_copy(const routerinfo_t *router)
{
  routerinfo_t *r;
  addr_policy_t **e, *tmp;

  r = tor_malloc(sizeof(routerinfo_t));
  memcpy(r, router, sizeof(routerinfo_t));

  r->address = tor_strdup(r->address);
  r->nickname = tor_strdup(r->nickname);
  r->platform = tor_strdup(r->platform);
  if (r->signed_descriptor)
    r->signed_descriptor = tor_strdup(r->signed_descriptor);
  if (r->onion_pkey)
    r->onion_pkey = crypto_pk_dup_key(r->onion_pkey);
  if (r->identity_pkey)
    r->identity_pkey = crypto_pk_dup_key(r->identity_pkey);
  e = &r->exit_policy;
  while (*e) {
    tmp = tor_malloc(sizeof(addr_policy_t));
    memcpy(tmp,*e,sizeof(addr_policy_t));
    *e = tmp;
    (*e)->string = tor_strdup((*e)->string);
    e = & ((*e)->next);
  }
  if (r->declared_family) {
    r->declared_family = smartlist_create();
    SMARTLIST_FOREACH(router->declared_family, const char *, s,
                      smartlist_add(r->declared_family, tor_strdup(s)));
  }
  return r;
}

/** Free all storage held by a routerlist <b>rl</b> */
void routerlist_free(routerlist_t *rl)
{
  tor_assert(rl);
  SMARTLIST_FOREACH(rl->routers, routerinfo_t *, r,
                    routerinfo_free(r));
  smartlist_free(rl->routers);
  running_routers_free(rl->running_routers);
  tor_free(rl->software_versions);
  tor_free(rl);
}

void routerlist_free_current(void)
{
  if (routerlist)
    routerlist_free(routerlist);
  routerlist = NULL;
  if (warned_nicknames) {
    SMARTLIST_FOREACH(warned_nicknames, char *, cp, tor_free(cp));
    smartlist_free(warned_nicknames);
    warned_nicknames = NULL;
  }
}

void free_trusted_dir_servers(void)
{
  if (trusted_dir_servers) {
    SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
                      { tor_free(ds->address); tor_free(ds); });
    smartlist_free(trusted_dir_servers);
    trusted_dir_servers = NULL;
  }
}

/** Mark the router with ID <b>digest</b> as non-running in our routerlist. */
void router_mark_as_down(const char *digest) {
  routerinfo_t *router;
  tor_assert(digest);

  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, d,
                    if (!memcmp(d->digest, digest, DIGEST_LEN))
                      d->is_running = 0);

  router = router_get_by_digest(digest);
  if (!router) /* we don't seem to know about him in the first place */
    return;
  log_fn(LOG_DEBUG,"Marking router '%s' as down.",router->nickname);
  if (router_is_me(router))
    log_fn(LOG_WARN, "We just marked ourself as down. Are your external addresses reachable?");
  router->is_running = 0;
  router->status_set_at = time(NULL);
}

/** Add <b>router</b> to the routerlist, if we don't already have it.  Replace
 * older entries (if any) with the same name.  Note: Callers should not hold
 * their pointers to <b>router</b> if this function fails; <b>router</b>
 * will either be inserted into the routerlist or freed.  Returns 0 if the
 * router was added; -1 if it was not.
 *
 * DOCDOC msg
 */
static int
router_add_to_routerlist(routerinfo_t *router, const char **msg) {
  int i;
  routerinfo_t *r;
  char id_digest[DIGEST_LEN];

  tor_assert(routerlist);
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
        /* If the address hasn't changed; no need to re-resolve. */
        if (!strcasecmp(r->address, router->address))
          router->addr = r->addr;
        routerinfo_free(r);
        smartlist_set(routerlist->routers, i, router);
        return 0;
      } else {
        log_fn(LOG_DEBUG, "Skipping not-new descriptor for router '%s'",
               router->nickname);
        /* Update the is_running status to whatever we were told. */
        r->is_running = router->is_running;
        routerinfo_free(router);
        if (msg) *msg = "Router descriptor was not new.";
        return -1;
      }
    } else if (!strcasecmp(router->nickname, r->nickname)) {
      /* nicknames match, keys don't. */
      if (router->is_verified) {
        /* The new verified router replaces the old one; remove the
         * old one.  And carry on to the end of the list, in case
         * there are more old unverified routers with this nickname
         */
        /* mark-for-close connections using the old key, so we can
         * make new ones with the new key.
         */
        connection_t *conn;
        while ((conn = connection_get_by_identity_digest(r->identity_digest,
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
        if (msg) *msg = "Already have verified router with different key and same nickname";
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
    if (router->published_on <= cutoff) {
      /* Too old.  Remove it. */
      log_fn(LOG_INFO,"Forgetting obsolete routerinfo for router '%s'", router->nickname);
      routerinfo_free(router);
      smartlist_del(routerlist->routers, i--);
    }
  }
}

/*
 * Code to parse a single router descriptors and insert it into the
 * directory.  Return -1 if the descriptor was ill-formed; 0 if the
 * descriptor was well-formed but could not be added; and 1 if the
 * descriptor was added.
 */
int
router_load_single_router(const char *s, const char **msg)
{
  routerinfo_t *ri;
  tor_assert(msg);

  if (!(ri = router_parse_entry_from_string(s, NULL))) {
    log_fn(LOG_WARN, "Error parsing router descriptor; dropping.");
    *msg = "Couldn't parse router descriptor";
    return -1;
  }
  if (router_is_me(ri)) {
    log_fn(LOG_WARN, "Router's identity key matches mine; dropping.");
    *msg = "Router's identity key matches mine.";
    routerinfo_free(ri);
    return 0;
  }
  if (router_resolve(ri)<0) {
    log_fn(LOG_WARN, "Couldn't resolve router address; dropping.");
    *msg = "Couldn't resolve router address.";
    routerinfo_free(ri);
    return 0;
  }
  if (routerlist && routerlist->running_routers) {
    running_routers_t *rr = routerlist->running_routers;
    router_update_status_from_smartlist(ri,
                                        rr->published_on,
                                        rr->running_routers);
  }
  if (router_add_to_routerlist(ri, msg)<0) {
    log_fn(LOG_WARN, "Couldn't add router to list; dropping.");
    *msg = "Couldn't add router to list.";
    /* ri is already freed */
    return 0;
  } else {
    smartlist_t *changed = smartlist_create();
    smartlist_add(changed, ri);
    control_event_descriptors_changed(changed);
    smartlist_free(changed);
  }

  log_fn(LOG_DEBUG, "Added router to list");
  return 1;
}

/** Add to the current routerlist each router stored in the
 * signed directory <b>s</b>.  If pkey is provided, check the signature against
 * pkey; else check against the pkey of the signing directory server.
 *
 * If <b>dir_is_recent</b> is non-zero, then examine the
 * Recommended-versions line and take appropriate action.
 *
 * If <b>dir_is_cached</b> is non-zero, then we're reading it
 * from the cache so don't bother to re-write it to the cache.
 */
int router_load_routerlist_from_directory(const char *s,
                                          crypto_pk_env_t *pkey,
                                          int dir_is_recent,
                                          int dir_is_cached)
{
  routerlist_t *new_list = NULL;
  if (router_parse_routerlist_from_directory(s, &new_list, pkey,
                                             dir_is_recent,
                                             !dir_is_cached)) {
    log_fn(LOG_WARN, "Couldn't parse directory.");
    return -1;
  }
  if (routerlist) {
    smartlist_t *changed = smartlist_create();
    SMARTLIST_FOREACH(new_list->routers, routerinfo_t *, r,
    {
      if (router_add_to_routerlist(r,NULL)==0)
        smartlist_add(changed, r);
    });
    smartlist_clear(new_list->routers);
    routerlist->published_on = new_list->published_on;
    tor_free(routerlist->software_versions);
    routerlist->software_versions = new_list->software_versions;
    new_list->software_versions = NULL;
    routerlist_free(new_list);
    control_event_descriptors_changed(changed);
    smartlist_free(changed);
  } else {
    routerlist = new_list;
    control_event_descriptors_changed(routerlist->routers);
  }
  if (router_resolve_routerlist(routerlist)) {
    log_fn(LOG_WARN, "Error resolving routerlist");
    return -1;
  }
  if (get_options()->AuthoritativeDir) {
    /* Learn about the descriptors in the directory. */
    dirserv_load_from_directory_string(s);
  }
  return 0;
}

/** Helper function: resolve the hostname for <b>router</b>. */
static int
router_resolve(routerinfo_t *router)
{
  if (tor_lookup_hostname(router->address, &router->addr) != 0
      || !router->addr) {
    log_fn(LOG_WARN,"Could not resolve address for router '%s' at %s",
           router->nickname, router->address);
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
      log_fn(LOG_WARN, "Couldn't resolve router '%s' at '%s'; not using",
             r->nickname, r->address);
      remove = 1;
    }
    if (remove) {
      routerinfo_free(r);
      smartlist_del_keeporder(rl->routers, i--);
    }
  }

  return 0;
}

/** Decide whether a given addr:port is definitely accepted,
 * definitely rejected, probably accepted, or probably rejected by a
 * given policy.  If <b>addr</b> is 0, we don't know the IP of the
 * target address. If <b>port</b> is 0, we don't know the port of the
 * target address.
 *
 * For now, the algorithm is pretty simple: we look for definite and
 * uncertain matches.  The first definite match is what we guess; if
 * it was proceded by no uncertain matches of the opposite policy,
 * then the guess is definite; otherwise it is probable.  (If we
 * have a known addr and port, all matches are definite; if we have an
 * unknown addr/port, any address/port ranges other than "all" are
 * uncertain.)
 *
 * We could do better by assuming that some ranges never match typical
 * addresses (127.0.0.1, and so on).  But we'll try this for now.
 */
addr_policy_result_t
router_compare_addr_to_addr_policy(uint32_t addr, uint16_t port,
                                   addr_policy_t *policy)
{
  int maybe_reject = 0;
  int maybe_accept = 0;
  int match = 0;
  int maybe = 0;
  addr_policy_t *tmpe;

  for (tmpe=policy; tmpe; tmpe=tmpe->next) {
//    log_fn(LOG_DEBUG,"Considering exit policy %s", tmpe->string);
    maybe = 0;
    if (!addr) {
      /* Address is unknown. */
      if ((port >= tmpe->prt_min && port <= tmpe->prt_max) ||
           (!port && tmpe->prt_min<=1 && tmpe->prt_max>=65535)) {
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
      if (tmpe->policy_type == ADDR_POLICY_REJECT)
        maybe_reject = 1;
      else
        maybe_accept = 1;
    }
    if (match) {
//      struct in_addr in;
//      in.s_addr = htonl(addr);
//      log_fn(LOG_DEBUG,"Address %s:%d matches policy '%s'",
//             inet_ntoa(in), port, tmpe->string);
      if (tmpe->policy_type == ADDR_POLICY_ACCEPT) {
        /* If we already hit a clause that might trigger a 'reject', than we
         * can't be sure of this certain 'accept'.*/
        return maybe_reject ? ADDR_POLICY_PROBABLY_ACCEPTED : ADDR_POLICY_ACCEPTED;
      } else {
        return maybe_accept ? ADDR_POLICY_PROBABLY_REJECTED : ADDR_POLICY_REJECTED;
      }
    }
  }
  /* accept all by default. */
  return maybe_reject ? ADDR_POLICY_PROBABLY_ACCEPTED : ADDR_POLICY_ACCEPTED;
}

/** Return 1 if all running sufficiently-stable routers will reject
 * addr:port, return 0 if any might accept it. */
int router_exit_policy_all_routers_reject(uint32_t addr, uint16_t port,
                                          int need_uptime) {
  int i;
  routerinfo_t *router;
  addr_policy_result_t r;
  if (!routerlist) return 1;

  for (i=0;i<smartlist_len(routerlist->routers);i++) {
    router = smartlist_get(routerlist->routers, i);
    if (router->is_running &&
        !router_is_unreliable(router, need_uptime, 0)) {
      r = router_compare_addr_to_addr_policy(addr, port, router->exit_policy);
      if (r != ADDR_POLICY_REJECTED && r != ADDR_POLICY_PROBABLY_REJECTED)
        return 0; /* this one could be ok. good enough. */
    }
  }
  return 1; /* all will reject. */
}

/**
 * If <b>policy</b> implicitly allows connections to any port in the
 * IP set <b>addr</b>/<b>mask</b>, then set *<b>policy_out</b> to the
 * part of the policy that allows it, and return 1.  Else return 0.
 *
 * A policy allows an IP:Port combination <em>implicitly</em> if
 * it is included in a *: pattern, or in a fallback pattern.
 */
static int
policy_includes_addr_mask_implicitly(addr_policy_t *policy,
                                     uint32_t addr, uint32_t mask,
                                     addr_policy_t **policy_out)
{
  uint32_t addr2;
  tor_assert(policy_out);
  addr &= mask;
  addr2 = addr | ~mask;
  for (; policy; policy=policy->next) {
    /* Does this policy cover all of the address range we're looking at? */
    /* Boolean logic time: range X is contained in range Y if, for
     * each bit B, all possible values of B in X are values of B in Y.
     * In "addr", we have every fixed bit set to its value, and every
     * free bit set to 0.  In "addr2", we have every fixed bit set to
     * its value, and every free bit set to 1.  So if addr and addr2 are
     * both in the policy, the range is covered by the policy.
     */
    uint32_t p_addr = policy->addr & policy->msk;
    if (p_addr == (addr & policy->msk) &&
        p_addr == (addr2 & policy->msk) &&
        (policy->prt_min <= 1 && policy->prt_max == 65535)) {
      return 0;
    }
    /* Does this policy cover some of the address range we're looking at? */
    /* Boolean logic time: range X and range Y intersect if there is
     * some z such that z & Xmask == Xaddr and z & Ymask == Yaddr.
     * This is FALSE iff there is some bit b where Xmask == yMask == 1
     * and Xaddr != Yaddr.  So if X intersects with Y iff at every
     * place where Xmask&Ymask==1, Xaddr == Yaddr, or equivalently,
     * Xaddr&Xmask&Ymask == Yaddr&Xmask&Ymask.
     */
    if ((policy->addr & policy->msk & mask) == (addr & policy->msk) &&
        policy->policy_type == ADDR_POLICY_ACCEPT) {
      *policy_out = policy;
      return 1;
    }
  }
  *policy_out = NULL;
  return 1;
}

/** If <b>policy</b> implicitly allows connections to any port on
 * 127.*, 192.168.*, etc, then warn (if <b>warn</b> is set) and return
 * true.  Else return false.
 **/
int
exit_policy_implicitly_allows_local_networks(addr_policy_t *policy,
                                             int warn)
{
  addr_policy_t *p;
  int r=0,i;
  static struct {
    uint32_t addr; uint32_t mask; const char *network;
  } private_networks[] = {
    { 0x7f000000, 0xff000000, "localhost (127.x)" },
    { 0x0a000000, 0xff000000, "addresses in private network 10.x" },
    { 0xa9fe0000, 0xffff0000, "addresses in private network 169.254.x" },
    { 0xac100000, 0xfff00000, "addresses in private network 172.16.x" },
    { 0xc0a80000, 0xffff0000, "addresses in private network 192.168.x" },
    { 0,0,NULL},
  };
  for (i=0; private_networks[i].addr; ++i) {
    p = NULL;
    /* log_fn(LOG_INFO,"Checking network %s", private_networks[i].network); */
    if (policy_includes_addr_mask_implicitly(
              policy, private_networks[i].addr, private_networks[i].mask, &p)) {
      if (warn)
        log_fn(LOG_WARN, "Exit policy %s implicitly accepts %s",
               p?p->string:"(default)",
               private_networks[i].network);
      r = 1;
    }
  }

  return r;
}

/** Return true iff <b>router</b> does not permit exit streams.
 */
int router_exit_policy_rejects_all(routerinfo_t *router) {
  return router_compare_addr_to_addr_policy(0, 0, router->exit_policy)
    == ADDR_POLICY_REJECTED;
}

/** Release all space held in <b>rr</b>. */
void running_routers_free(running_routers_t *rr)
{
  if (!rr)
    return;
  if (rr->running_routers) {
    SMARTLIST_FOREACH(rr->running_routers, char *, s, tor_free(s));
    smartlist_free(rr->running_routers);
  }
  tor_free(rr);
}

/** We've just got a running routers list in <b>rr</b>; update the
 * status of the routers in <b>list</b>, and cache <b>rr</b> */
void
routerlist_set_runningrouters(routerlist_t *list, running_routers_t *rr)
{
  routerlist_update_from_runningrouters(list,rr);
  if (list->running_routers != rr) {
    running_routers_free(list->running_routers);
    list->running_routers = rr;
  }
}

/** Update the running/not-running status of every router in <b>list</b>, based
 * on the contents of <b>rr</b>. */
/* Note: this function is not yet used, since nobody publishes just
 * running-router lists yet. */
void routerlist_update_from_runningrouters(routerlist_t *list,
                                           running_routers_t *rr)
{
  routerinfo_t *me = router_get_my_routerinfo();
  smartlist_t *all_routers;
  if (!list)
    return;
  if (list->published_on >= rr->published_on)
    return;
  if (list->running_routers_updated_on >= rr->published_on)
    return;

  all_routers = smartlist_create();
  if (me) /* learn if the dirservers think I'm verified */
    smartlist_add(all_routers, me);

  smartlist_add_all(all_routers,list->routers);
  SMARTLIST_FOREACH(rr->running_routers, const char *, cp,
     routers_update_status_from_entry(all_routers, rr->published_on,
                                      cp));
  smartlist_free(all_routers);
  list->running_routers_updated_on = rr->published_on;
}

/** Update the is_running and is_verified fields of the router <b>router</b>,
 * based in its status in the list of strings stored in <b>running_list</b>.
 * All entries in <b>running_list</b> follow one of these formats:
 * <ol><li> <b>nickname</b> -- router is running and verified.
 *          (running-routers format)
 *     <li> !<b>nickname</b> -- router is not-running and verified.
 *          (running-routers format)
 *     <li> <b>nickname</b>=$<b>hexdigest</b> -- router is running and
 *          verified. (router-status format)
 *          (router-status format)
 *     <li> !<b>nickname</b>=$<b>hexdigest</b> -- router is running and
 *          verified. (router-status format)
 *     <li> !<b>nickname</b> -- router is not-running and verified.
 *     <li> $<b>hexdigest</b> -- router is running and unverified.
 *     <li> !$<b>hexdigest</b> -- router is not-running and unverified.
 * </ol>
 *
 * Return 1 if we found router in running_list, else return 0.
 */
int routers_update_status_from_entry(smartlist_t *routers,
                                     time_t list_time,
                                     const char *s)
{
  int is_running = 1;
  int is_verified = 0;
  int hex_digest_set = 0;
  char nickname[MAX_NICKNAME_LEN+1];
  char hexdigest[HEX_DIGEST_LEN+1];
  char digest[DIGEST_LEN];
  const char *cp, *end;

  /* First, parse the entry. */
  cp = s;
  if (*cp == '!') {
    is_running = 0;
    ++cp;
  }

  if (*cp != '$') {
    /* It starts with a non-dollar character; that's a nickname.  The nickname
     * entry will either extend to a NUL (old running-routers format) or to an
     * equals sign (new router-status format). */
    is_verified = 1;
    end = strchr(cp, '=');
    if (!end)
      end = strchr(cp,'\0');
    tor_assert(end);
    /* 'end' now points on character beyond the end of the nickname */
    if (end == cp || end-cp > MAX_NICKNAME_LEN) {
      log_fn(LOG_WARN, "Bad nickname length (%d) in router status entry (%s)",
             (int)(end-cp), s);
      return -1;
    }
    memcpy(nickname, cp, end-cp);
    nickname[end-cp]='\0';
    if (!is_legal_nickname(nickname)) {
      log_fn(LOG_WARN, "Bad nickname (%s) in router status entry (%s)",
             nickname, s);
      return -1;
    }
    cp = end;
    if (*cp == '=')
      ++cp;
  }
  /* 'end' now points to the start of a hex digest, or EOS. */

  /* Parse the hexdigest portion of the status. */
  if (*cp == '$') {
    hex_digest_set = 1;
    ++cp;
    if (strlen(cp) != HEX_DIGEST_LEN) {
      log_fn(LOG_WARN, "Bad length (%d) on digest in router status entry (%s)",
             (int)strlen(cp), s);
      return -1;
    }
    strlcpy(hexdigest, cp, sizeof(hexdigest));
    if (base16_decode(digest, DIGEST_LEN, hexdigest, HEX_DIGEST_LEN)<0) {
      log_fn(LOG_WARN, "Invalid digest in router status entry (%s)", s);
      return -1;
    }
  }

  /* Make sure that the entry was in the right format. */
  if (!hex_digest_set) {
    log_fn(LOG_WARN, "Invalid syntax for router-status member (%s)", s);
    return -1;
  }

  /* Okay, we're done parsing. For all routers that match, update their status.
   */
  SMARTLIST_FOREACH(routers, routerinfo_t *, r,
  {
    int nickname_matches = is_verified && !strcasecmp(r->nickname, nickname);
    int digest_matches = !memcmp(digest, r->identity_digest, DIGEST_LEN);
    if (nickname_matches && digest_matches)
      r->is_verified = 1;
    else if (digest_matches)
      r->is_verified = 0;
    if (digest_matches)
      if (r->status_set_at < list_time) {
        r->is_running = is_running;
        r->status_set_at = time(NULL);
      }
  });

  return 0;
}

/** As router_update_status_from_entry, but consider all entries in
 * running_list. */
int
router_update_status_from_smartlist(routerinfo_t *router,
                                    time_t list_time,
                                    smartlist_t *running_list)
{
  smartlist_t *rl;
  rl = smartlist_create();
  smartlist_add(rl,router);
  SMARTLIST_FOREACH(running_list, const char *, cp,
                    routers_update_status_from_entry(rl,list_time,cp));
  smartlist_free(rl);
  return 0;
}

/** Add to the list of authorized directory servers one at
 * <b>address</b>:<b>port</b>, with identity key <b>digest</b>. */
void
add_trusted_dir_server(const char *address, uint16_t port, const char *digest)
{
  trusted_dir_server_t *ent;
  uint32_t a;
  if (!trusted_dir_servers)
    trusted_dir_servers = smartlist_create();

  if (tor_lookup_hostname(address, &a)) {
    log_fn(LOG_WARN, "Unable to lookup address for directory server at %s",
           address);
    return;
  }

  ent = tor_malloc(sizeof(trusted_dir_server_t));
  ent->address = tor_strdup(address);
  ent->addr = ntohl(a);
  ent->dir_port = port;
  ent->is_running = 1;
  memcpy(ent->digest, digest, DIGEST_LEN);
  smartlist_add(trusted_dir_servers, ent);
}

/** Remove all members from the list of trusted dir servers. */
void clear_trusted_dir_servers(void)
{
  if (trusted_dir_servers) {
    SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ent,
                      { tor_free(ent->address); tor_free(ent); });
    smartlist_clear(trusted_dir_servers);
  } else {
    trusted_dir_servers = smartlist_create();
  }
}

