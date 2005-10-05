/* Copyright 2001 Matej Pfajfar.
 * Copyright 2001-2004 Roger Dingledine.
 * Copyright 2004-2005 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char routerlist_c_id[] = "$Id$";

/**
 * \file routerlist.c
 * \brief Code to
 * maintain and access the global list of routerinfos for known
 * servers.
 **/

#include "or.h"

/****************************************************************************/

/** Global list of a trusted_dir_server_t object for each trusted directory
 * server. */
static smartlist_t *trusted_dir_servers = NULL;

/* static function prototypes */
static routerinfo_t *router_pick_directory_server_impl(int requireother,
                                                       int fascistfirewall,
                                                       int for_v2_directory);
static trusted_dir_server_t *router_pick_trusteddirserver_impl(
                int need_v1_support, int requireother, int fascistfirewall);
static void mark_all_trusteddirservers_up(void);
static int router_nickname_is_in_list(routerinfo_t *router, const char *list);
static int router_nickname_matches(routerinfo_t *router, const char *nickname);
static void routerstatus_list_update_from_networkstatus(time_t now);
static void local_routerstatus_free(local_routerstatus_t *rs);

/****************************************************************************/

/****
 * Functions to manage and access our list of known routers. (Note:
 * dirservers maintain a separate, independent list of known router
 * descriptors.)
 ****/

/** Global list of all of the routers that we know about. */
static routerlist_t *routerlist = NULL;

extern int has_fetched_directory; /**< from main.c */

/** Global list of all of the current network_status documents that we know
 * about.  This list is kept sorted by published_on. */
static smartlist_t *networkstatus_list = NULL;
/** Global list of routerstatuses_t for each router, known or unknown. */
static smartlist_t *routerstatus_list = NULL;
/** True iff any member of networkstatus_list has changed since the last time
 * we called routerstatus_list_update_from_networkstatus(). */
static int networkstatus_list_has_changed = 0;
/** True iff any element of routerstatus_list has changed since the last
 * time we called routers_update_all_from_networkstatus().*/
static int routerstatus_list_has_changed = 0;

/** Repopulate our list of network_status_t objects from the list cached on
 * disk.  Return 0 on success, -1 on failure. */
int
router_reload_networkstatus(void)
{
  char filename[512];
  struct stat st;
  smartlist_t *entries;
  char *s;
  tor_assert(get_options()->DataDirectory);
  if (!networkstatus_list)
    networkstatus_list = smartlist_create();

  tor_snprintf(filename,sizeof(filename),"%s/cached-status",
               get_options()->DataDirectory);
  entries = tor_listdir(filename);
  SMARTLIST_FOREACH(entries, const char *, fn, {
      char buf[DIGEST_LEN];
      if (strlen(fn) != HEX_DIGEST_LEN ||
          base16_decode(buf, sizeof(buf), fn, strlen(fn))) {
        log_fn(LOG_INFO,
               "Skipping cached-status file with unexpected name \"%s\"",fn);
        continue;
      }
      tor_snprintf(filename,sizeof(filename),"%s/cached-status/%s",
                   get_options()->DataDirectory, fn);
      s = read_file_to_str(filename, 0);
      if (s) {
        stat(filename, &st);
        if (router_set_networkstatus(s, st.st_mtime, NS_FROM_CACHE, NULL)<0) {
          log_fn(LOG_WARN, "Couldn't load networkstatus from \"%s\"",filename);
        }
        tor_free(s);
      }
    });
  SMARTLIST_FOREACH(entries, char *, fn, tor_free(fn));
  smartlist_free(entries);
  networkstatus_list_clean(time(NULL));
  routers_update_all_from_networkstatus();
  return 0;
}

/* Router descriptor storage.
 *
 * Routerdescs are stored in a big file, named "cached-routers".  As new
 * routerdescs arrive, we append them to a journal file named
 * "cached-routers.new".
 *
 * From time to time, we replace "cached-routers" with a new file containing
 * only the live, non-superseded descriptors, and clear cached-routers.new.
 *
 * On startup, we read both files.
 */

/** The size of the router log, in bytes. */
static size_t router_journal_len = 0;
/** The size of the router store, in bytes. */
static size_t router_store_len = 0;

/** Helper: return 1 iff the router log is so big we want to rebuild the
 * store. */
static int
router_should_rebuild_store(void)
{
  if (router_store_len > (1<<16))
    return router_journal_len > router_store_len / 2;
  else
    return router_journal_len > (1<<15);
}

/** Add the <b>len</b>-type router descriptor in <b>s</b> to the router
 * journal. */
static int
router_append_to_journal(const char *s, size_t len)
{
  or_options_t *options = get_options();
  size_t fname_len = strlen(options->DataDirectory)+32;
  char *fname = tor_malloc(len);

  tor_snprintf(fname, fname_len, "%s/cached-routers.new",
               options->DataDirectory);

  if (!len)
    len = strlen(s);

  if (append_bytes_to_file(fname, s, len, 0)) {
    log_fn(LOG_WARN, "Unable to store router descriptor");
    tor_free(fname);
    return -1;
  }

  tor_free(fname);
  router_journal_len += len;
  return 0;
}

/** If the journal is too long, or if <b>force</b> is true, then atomically
 * replace the router store with the routers currently in our routerlist, and
 * clear the journal.  Return 0 on success, -1 on failure.
 */
static int
router_rebuild_store(int force)
{
  size_t len = 0;
  or_options_t *options;
  size_t fname_len;
  smartlist_t *chunk_list = NULL;
  char *fname = NULL;
  int r = -1;

  if (!force && !router_should_rebuild_store())
    return 0;
  if (!routerlist)
    return 0;

  /* Don't save deadweight. */
  routerlist_remove_old_routers(ROUTER_MAX_AGE);

  options = get_options();
  fname_len = strlen(options->DataDirectory)+32;
  fname = tor_malloc(fname_len);
  tor_snprintf(fname, fname_len, "%s/cached-routers", options->DataDirectory);
  chunk_list = smartlist_create();

  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, ri,
  {
    sized_chunk_t *c;
    if (!ri->signed_descriptor) {
      log_fn(LOG_WARN, "Bug! No descriptor stored for router '%s'.",
             ri->nickname);
      goto done;
    }
    c = tor_malloc(sizeof(sized_chunk_t));
    c->bytes = ri->signed_descriptor;
    c->len = ri->signed_descriptor_len;
    smartlist_add(chunk_list, c);
  });

  if (write_chunks_to_file(fname, chunk_list, 0)<0) {
    log_fn(LOG_WARN, "Error writing router store to disk.");
    goto done;
  }

  tor_snprintf(fname, fname_len, "%s/cached-routers.new",
               options->DataDirectory);

  write_str_to_file(fname, "", 0);

  r = 0;
  router_store_len = len;
  router_journal_len = 0;
 done:
  tor_free(fname);
  if (chunk_list) {
    SMARTLIST_FOREACH(chunk_list, sized_chunk_t *, c, tor_free(c));
    smartlist_free(chunk_list);
  }
  return r;
}

/* Load all cached router descriptors from the store. Return 0 on success and
 * -1 on failure.
 */
int
router_reload_router_list(void)
{
  or_options_t *options = get_options();
  size_t fname_len = strlen(options->DataDirectory)+32;
  char *fname = tor_malloc(fname_len);
  struct stat st;
  int j;

  if (!routerlist) {
    routerlist = tor_malloc_zero(sizeof(routerlist_t));
    routerlist->routers = smartlist_create();
  }

  router_journal_len = router_store_len = 0;

  for (j = 0; j < 2; ++j) {
    char *contents;
    tor_snprintf(fname, fname_len,
                 (j==0)?"%s/cached-routers":"%s/cached-routers.new",
                 options->DataDirectory);
    contents = read_file_to_str(fname, 0);
    if (contents) {
      stat(fname, &st);
      if (j==0)
        router_store_len = st.st_size;
      else
        router_journal_len = st.st_size;
      router_load_routers_from_string(contents, 1, NULL);
      tor_free(contents);
    }
  }
  tor_free(fname);

  /* Don't cache expired routers. */
  routerlist_remove_old_routers(ROUTER_MAX_AGE);

  if (router_journal_len) {
    /* Always clear the journal on startup.*/
    router_rebuild_store(1);
  }
  return 0;
}

/** Set *<b>outp</b> to a smartlist containing a list of
 * trusted_dir_server_t * for all known trusted dirservers.  Callers
 * must not modify the list or its contents.
 */
void
router_get_trusted_dir_servers(smartlist_t **outp)
{
  if (!trusted_dir_servers)
    trusted_dir_servers = smartlist_create();

  *outp = trusted_dir_servers;
}

/** Try to find a running dirserver. If there are no running dirservers
 * in our routerlist and <b>retry_if_no_servers</b> is non-zero,
 * set all the authoritative ones as running again, and pick one;
 * if there are then no dirservers at all in our routerlist,
 * reload the routerlist and try one last time. If for_runningrouters is
 * true, then only pick a dirserver that can answer runningrouters queries
 * (that is, a trusted dirserver, or one running 0.0.9rc5-cvs or later).
 * Other args are as in router_pick_directory_server_impl().
 */
routerinfo_t *
router_pick_directory_server(int requireother,
                             int fascistfirewall,
                             int for_v2_directory,
                             int retry_if_no_servers)
{
  routerinfo_t *choice;

  if (!routerlist)
    return NULL;

  choice = router_pick_directory_server_impl(requireother, fascistfirewall,
                                             for_v2_directory);
  if (choice || !retry_if_no_servers)
    return choice;

  log_fn(LOG_INFO,"No reachable router entries for dirservers. Trying them all again.");
  /* mark all authdirservers as up again */
  mark_all_trusteddirservers_up();
  /* try again */
  choice = router_pick_directory_server_impl(requireother, fascistfirewall,
                                             for_v2_directory);
  if (choice)
    return choice;

  log_fn(LOG_INFO,"Still no %s router entries. Reloading and trying again.",
         firewall_is_fascist() ? "reachable" : "known");
  has_fetched_directory=0; /* reset it */
  if (router_reload_router_list()) {
    return NULL;
  }
  /* give it one last try */
  choice = router_pick_directory_server_impl(requireother, 0,
                                             for_v2_directory);
  return choice;
}

trusted_dir_server_t *
router_get_trusteddirserver_by_digest(const char *digest)
{
  if (!trusted_dir_servers)
    return NULL;

  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
     {
       if (!memcmp(ds->digest, digest, DIGEST_LEN))
         return ds;
     });

  return NULL;
}

/** Try to find a running trusted dirserver. If there are no running
 * trusted dirservers and <b>retry_if_no_servers</b> is non-zero,
 * set them all as running again, and try again.
 * Other args are as in router_pick_trusteddirserver_impl().
 */
trusted_dir_server_t *
router_pick_trusteddirserver(int need_v1_support,
                             int requireother,
                             int fascistfirewall,
                             int retry_if_no_servers)
{
  trusted_dir_server_t *choice;

  choice = router_pick_trusteddirserver_impl(need_v1_support,
                                             requireother, fascistfirewall);
  if (choice || !retry_if_no_servers)
    return choice;

  log_fn(LOG_INFO,"No trusted dirservers are reachable. Trying them all again.");
  mark_all_trusteddirservers_up();
  return router_pick_trusteddirserver_impl(need_v1_support,
                                           requireother, fascistfirewall);
}

/** Pick a random running verified directory server/mirror from our
 * routerlist.
 * If <b>fascistfirewall</b> and we're not using a proxy,
 * make sure the port we pick is allowed by options-\>firewallports.
 * If <b>requireother</b>, it cannot be us.  If <b>for_v2_directory</b>,
 * choose a directory server new enough to support the v2 directory
 * functionality.
 */
static routerinfo_t *
router_pick_directory_server_impl(int requireother, int fascistfirewall,
                                  int for_v2_directory)
{
  routerinfo_t *result;
  smartlist_t *sl;

  if (!routerlist)
    return NULL;

  if (get_options()->HttpProxy)
    fascistfirewall = 0;

  /* Find all the running dirservers we know about. */
  sl = smartlist_create();
  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
  {
    if (!router->is_running || !router->dir_port || !router->is_verified)
      continue;
    if (requireother && router_is_me(router))
      continue;
    if (fascistfirewall) {
      if (!fascist_firewall_allows_address(router->addr, router->dir_port))
        continue;
    }
    /* Before 0.1.1.6-alpha, only trusted dirservers served status info.
     * Before 0.1.1.7-alpha, retrieving nonexistent server IDs could bork
     * the directory server.
     */
    if (for_v2_directory &&
        !(tor_version_as_new_as(router->platform,"0.1.1.7-alpha") ||
          router_digest_is_trusted_dir(router->identity_digest)))
      continue;
    smartlist_add(sl, router);
  });

  result = smartlist_choose(sl);
  smartlist_free(sl);
  return result;
}

/** Choose randomly from among the trusted dirservers that are up.
 * If <b>fascistfirewall</b> and we're not using a proxy,
 * make sure the port we pick is allowed by options-\>firewallports.
 * If <b>requireother</b>, it cannot be us.  If <b>need_v1_support</b>, choose
 * a trusted authority for the v1 directory system.
 */
static trusted_dir_server_t *
router_pick_trusteddirserver_impl(int need_v1_support,
                                  int requireother, int fascistfirewall)
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
      if (need_v1_support && !d->supports_v1_protocol)
        continue;
      if (requireother && me &&
          !memcmp(me->identity_digest, d->digest, DIGEST_LEN))
        continue;
      if (fascistfirewall) {
        if (!fascist_firewall_allows_address(d->addr, d->dir_port))
          continue;
      }
      smartlist_add(sl, d);
    });

  ds = smartlist_choose(sl);
  smartlist_free(sl);
  return ds;
}

/** Go through and mark the authoritative dirservers as up. */
static void
mark_all_trusteddirservers_up(void)
{
  if (routerlist) {
    SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
                 if (router_digest_is_trusted_dir(router->identity_digest) &&
                     router->dir_port > 0) {
                   router->is_running = 1;
                 });
  }
  if (trusted_dir_servers) {
    SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, dir,
    {
      dir->is_running = 1;
      dir->n_networkstatus_failures = 0;
    });
  }
}

/** Return 0 if \\exists an authoritative dirserver that's currently
 * thought to be running, else return 1.
 */
int
all_trusted_directory_servers_down(void)
{
  if (!trusted_dir_servers)
    return 1;
  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, dir,
                    if (dir->is_running) return 0);
  return 1;
}

/** Add all the family of <b>router</b> to the smartlist <b>sl</b>.
 * This is used to make sure we don't pick siblings in a single path.
 */
void
routerlist_add_family(smartlist_t *sl, routerinfo_t *router)
{
  routerinfo_t *r;
  config_line_t *cl;

  if (!router->declared_family)
    return;

  /* Add every r such that router declares familyness with r, and r
   * declares familyhood with router. */
  SMARTLIST_FOREACH(router->declared_family, const char *, n,
    {
      if (!(r = router_get_by_nickname(n, 0)))
        continue;
      if (!r->declared_family)
        continue;
      SMARTLIST_FOREACH(r->declared_family, const char *, n2,
        {
          if (router_nickname_matches(router, n2))
            smartlist_add(sl, r);
        });
    });

  /* If the user declared any families locally, honor those too. */
  for (cl = get_options()->NodeFamilies; cl; cl = cl->next) {
    if (router_nickname_is_in_list(router, cl->value)) {
      add_nickname_list_to_smartlist(sl, cl->value, 1, 1);
    }
  }
}

/** List of strings for nicknames we've already warned about and that are
 * still unknown / unavailable. */
static smartlist_t *warned_nicknames = NULL;

/** Given a comma-and-whitespace separated list of nicknames, see which
 * nicknames in <b>list</b> name routers in our routerlist that are
 * currently running.  Add the routerinfos for those routers to <b>sl</b>.
 */
void
add_nickname_list_to_smartlist(smartlist_t *sl, const char *list, int warn_if_down, int warn_if_unnamed)
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
    router = router_get_by_nickname(nick, warn_if_unnamed);
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
static int
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
  if (!routerlist)
    return;

  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
  {
    if (router->is_running &&
        (router->is_verified ||
        (allow_unverified &&
         !router_is_unreliable(router, need_uptime, need_capacity)))) {
      /* If it's running, and either it's verified or we're ok picking
       * unverified routers and this one is suitable.
       */
      smartlist_add(sl, router);
    }
  });
}

/** Look through the routerlist until we find a router that has my key.
 Return it. */
routerinfo_t *
routerlist_find_my_routerinfo(void)
{
  if (!routerlist)
    return NULL;

  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
  {
    if (router_is_me(router))
      return router;
  });
  return NULL;
}

/** Find a router that's up, that has this IP address, and
 * that allows exit to this address:port, or return NULL if there
 * isn't a good one.
 */
routerinfo_t *
router_find_exact_exit_enclave(const char *address, uint16_t port)
{
  uint32_t addr;
  struct in_addr in;

  if (!tor_inet_aton(address, &in))
    return NULL; /* it's not an IP already */
  addr = ntohl(in.s_addr);

  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
  {
    if (router->is_running &&
        router->addr == addr &&
        router_compare_addr_to_addr_policy(addr, port, router->exit_policy) ==
          ADDR_POLICY_ACCEPTED)
      return router;
  });
  return NULL;
}

/** Return 1 if <b>router</b> is not suitable for these parameters, else 0.
 * If <b>need_uptime</b> is non-zero, we require a minimum uptime.
 * If <b>need_capacity</b> is non-zero, we require a minimum advertised
 * bandwidth.
 */
int
router_is_unreliable(routerinfo_t *router, int need_uptime, int need_capacity)
{
  if (need_uptime && router->uptime < ROUTER_REQUIRED_MIN_UPTIME)
    return 1;
  if (need_capacity && router->bandwidthcapacity < ROUTER_REQUIRED_MIN_BANDWIDTH)
    return 1;
  return 0;
}

/** Remove from routerlist <b>sl</b> all routers who have a low uptime. */
static void
routerlist_sl_remove_unreliable_routers(smartlist_t *sl)
{
  int i;
  routerinfo_t *router;

  for (i = 0; i < smartlist_len(sl); ++i) {
    router = smartlist_get(sl, i);
    if (router_is_unreliable(router, 1, 0)) {
//      log(LOG_DEBUG, "Router '%s' has insufficient uptime; deleting.",
 //         router->nickname);
      smartlist_del(sl, i--);
    }
  }
}

#define MAX_BELIEVABLE_BANDWIDTH 2000000 /* 2 MB/sec */

/** Choose a random element of router list <b>sl</b>, weighted by
 * the advertised bandwidth of each router.
 */
routerinfo_t *
routerlist_sl_choose_by_bandwidth(smartlist_t *sl)
{
  int i;
  routerinfo_t *router;
  smartlist_t *bandwidths;
  uint32_t this_bw, tmp, total_bw=0, rand_bw;
  uint32_t *p;

  /* First count the total bandwidth weight, and make a smartlist
   * of each value. */
  bandwidths = smartlist_create();
  for (i = 0; i < smartlist_len(sl); ++i) {
    router = smartlist_get(sl, i);
    this_bw = (router->bandwidthcapacity < router->bandwidthrate) ?
               router->bandwidthcapacity : router->bandwidthrate;
    /* if they claim something huge, don't believe it */
    if (this_bw > MAX_BELIEVABLE_BANDWIDTH)
      this_bw = MAX_BELIEVABLE_BANDWIDTH;
    p = tor_malloc(sizeof(uint32_t));
    *p = this_bw;
    smartlist_add(bandwidths, p);
    total_bw += this_bw;
  }
  if (!total_bw) {
    SMARTLIST_FOREACH(bandwidths, uint32_t*, p, tor_free(p));
    smartlist_free(bandwidths);
    return smartlist_choose(sl);
  }
  /* Second, choose a random value from the bandwidth weights. */
  rand_bw = crypto_pseudo_rand_int(total_bw);
  /* Last, count through sl until we get to the element we picked */
  tmp = 0;
  for (i=0; ; i++) {
    tor_assert(i < smartlist_len(sl));
    p = smartlist_get(bandwidths, i);
    tmp += *p;
    if (tmp >= rand_bw)
      break;
  }
  SMARTLIST_FOREACH(bandwidths, uint32_t*, p, tor_free(p));
  smartlist_free(bandwidths);
  return (routerinfo_t *)smartlist_get(sl, i);
}

/** Return a random running router from the routerlist.  If any node
 * named in <b>preferred</b> is available, pick one of those.  Never
 * pick a node named in <b>excluded</b>, or whose routerinfo is in
 * <b>excludedsmartlist</b>, even if they are the only nodes
 * available.  If <b>strict</b> is true, never pick any node besides
 * those in <b>preferred</b>.
 * If <b>need_uptime</b> is non-zero, don't return a router with less
 * than a minimum uptime.
 * If <b>need_capacity</b> is non-zero, weight your choice by the
 * advertised capacity of each router.
 */
routerinfo_t *
router_choose_random_node(const char *preferred,
                          const char *excluded,
                          smartlist_t *excludedsmartlist,
                          int need_uptime, int need_capacity,
                          int allow_unverified, int strict)
{
  smartlist_t *sl, *excludednodes;
  routerinfo_t *choice;

  excludednodes = smartlist_create();
  add_nickname_list_to_smartlist(excludednodes,excluded,0,1);

  /* Try the preferred nodes first. Ignore need_uptime and need_capacity,
   * since the user explicitly asked for these nodes. */
  sl = smartlist_create();
  add_nickname_list_to_smartlist(sl,preferred,1,1);
  smartlist_subtract(sl,excludednodes);
  if (excludedsmartlist)
    smartlist_subtract(sl,excludedsmartlist);
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

/** Return true iff the digest of <b>router</b>'s identity key,
 * encoded in hexadecimal, matches <b>hexdigest</b> (which is
 * optionally prefixed with a single dollar sign).  Return false if
 * <b>hexdigest</b> is malformed, or it doesn't match.  */
static INLINE int
router_hex_digest_matches(routerinfo_t *router, const char *hexdigest)
{
  char digest[DIGEST_LEN];
  tor_assert(hexdigest);
  if (hexdigest[0] == '$')
    ++hexdigest;

  if (strlen(hexdigest) != HEX_DIGEST_LEN ||
      base16_decode(digest, DIGEST_LEN, hexdigest, HEX_DIGEST_LEN)<0)
    return 0;
  return (!memcmp(digest, router->identity_digest, DIGEST_LEN));
}

/** Return true if <b>router</b>'s nickname matches <b>nickname</b>
 * (case-insensitive), or if <b>router's</b> identity key digest
 * matches a hexadecimal value stored in <b>nickname</b>.  Return
 * false otherwise. */
static int
router_nickname_matches(routerinfo_t *router, const char *nickname)
{
  if (nickname[0]!='$' && !strcasecmp(router->nickname, nickname))
    return 1;
  return router_hex_digest_matches(router, nickname);
}

/** Return the router in our routerlist whose (case-insensitive)
 * nickname or (case-sensitive) hexadecimal key digest is
 * <b>nickname</b>.  Return NULL if no such router is known.
 */
routerinfo_t *
router_get_by_nickname(const char *nickname, int warn_if_unnamed)
{
  int maybedigest;
  char digest[DIGEST_LEN];
  routerinfo_t *best_match=NULL;
  int n_matches = 0;

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

  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
  {
    /* XXXX011 NM Should this restrict by Named rouers, or warn on
     * non-named routers, or something? */
    if (!strcasecmp(router->nickname, nickname)) {
      if (router->is_named)
        return router;
      else {
        ++n_matches;
        best_match = router;
      }
    } else if (maybedigest &&
               !memcmp(digest, router->identity_digest, DIGEST_LEN)) {
      return router;
    }
  });

  if (best_match) {
    if (n_matches>1) {
      smartlist_t *fps = smartlist_create();
      int any_unwarned = 0;
      SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
        {
          local_routerstatus_t *rs;
          char *desc;
          size_t dlen;
          char fp[HEX_DIGEST_LEN+1];
          if (strcasecmp(router->nickname, nickname))
            continue;
          rs=router_get_combined_status_by_digest(router->identity_digest);
          if (!rs->name_lookup_warned) {
            rs->name_lookup_warned = 1;
            any_unwarned = 1;
          }
          base16_encode(fp, sizeof(fp), router->identity_digest, DIGEST_LEN);
          dlen = 32 + HEX_DIGEST_LEN + strlen(router->address);
          desc = tor_malloc(dlen);
          tor_snprintf(desc, dlen, "\"$%s\" for the one at %s:%d",
                       fp, router->address, router->or_port);
          smartlist_add(fps, desc);
        });
      if (any_unwarned) {
        char *alternatives = smartlist_join_strings(fps, "; ",0,NULL);
        log_fn(LOG_WARN, "There are multiple matches for the nickname \"%s\","
               " but none is listed as named by the directory authories. "
               "Choosing one arbitrarily.  If you meant one in particular, "
               "you should say %s.", nickname, alternatives);
        tor_free(alternatives);
      }
      SMARTLIST_FOREACH(fps, char *, cp, tor_free(cp));
      smartlist_free(fps);
    } else if (warn_if_unnamed) {
      local_routerstatus_t *rs =
        router_get_combined_status_by_digest(best_match->identity_digest);
      if (rs && !rs->name_lookup_warned) {
        char fp[HEX_DIGEST_LEN+1];
        base16_encode(fp, sizeof(fp), best_match->identity_digest, DIGEST_LEN);
        log_fn(LOG_WARN, "You specified a server \"%s\" by name, but the "
               "directory authorities do not have a listing for this name. "
               "To make sure you get the same server in the future, refer to "
               "it by key, as \"$%s\".", nickname, fp);
        rs->name_lookup_warned = 1;
      }
    }
    return best_match;
  }

  return NULL;
}

/** Return true iff <b>digest</b> is the digest of the identity key of
 * a trusted directory. */
int
router_digest_is_trusted_dir(const char *digest)
{
  if (!trusted_dir_servers)
    return 0;
  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ent,
                    if (!memcmp(digest, ent->digest, DIGEST_LEN)) return 1);
  return 0;
}

/** Return the router in our routerlist whose hexadecimal key digest
 * is <b>hexdigest</b>.  Return NULL if no such router is known. */
routerinfo_t *
router_get_by_hexdigest(const char *hexdigest)
{
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
routerinfo_t *
router_get_by_digest(const char *digest)
{
  tor_assert(digest);

  if (!routerlist) return NULL;

  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t*, router,
  {
    if (0 == memcmp(router->identity_digest, digest, DIGEST_LEN))
      return router;
  });

  return NULL;
}

/** Set *<b>prouterlist</b> to the current list of all known routers. */
void
router_get_routerlist(routerlist_t **prouterlist)
{
  *prouterlist = routerlist;
}

/** Free all storage held by <b>router</b>. */
void
routerinfo_free(routerinfo_t *router)
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
routerinfo_t *
routerinfo_copy(const routerinfo_t *router)
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
void
routerlist_free(routerlist_t *rl)
{
  tor_assert(rl);
  SMARTLIST_FOREACH(rl->routers, routerinfo_t *, r,
                    routerinfo_free(r));
  smartlist_free(rl->routers);
  tor_free(rl);
}

/** Free all memory held by the rouerlist module */
void
routerlist_free_all(void)
{
  if (routerlist)
    routerlist_free(routerlist);
  routerlist = NULL;
  if (warned_nicknames) {
    SMARTLIST_FOREACH(warned_nicknames, char *, cp, tor_free(cp));
    smartlist_free(warned_nicknames);
    warned_nicknames = NULL;
  }
  if (trusted_dir_servers) {
    SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
                      { tor_free(ds->address); tor_free(ds); });
    smartlist_free(trusted_dir_servers);
    trusted_dir_servers = NULL;
  }
  if (networkstatus_list) {
    SMARTLIST_FOREACH(networkstatus_list, networkstatus_t *, ns,
                      networkstatus_free(ns));
    smartlist_free(networkstatus_list);
    networkstatus_list = NULL;
  }
  if (routerstatus_list) {
    SMARTLIST_FOREACH(routerstatus_list, local_routerstatus_t *, rs,
                      local_routerstatus_free(rs));
    smartlist_free(routerstatus_list);
    routerstatus_list = NULL;
  }
}

/** Free all storage held by the routerstatus object <b>rs</b>. */
void
routerstatus_free(routerstatus_t *rs)
{
  tor_free(rs);
}

/** Free all storage held by the local_routerstatus object <b>rs</b>. */
static void
local_routerstatus_free(local_routerstatus_t *rs)
{
  tor_free(rs);
}

/** Free all storage held by the networkstatus object <b>ns</b>. */
void
networkstatus_free(networkstatus_t *ns)
{
  tor_free(ns->source_address);
  tor_free(ns->contact);
  if (ns->signing_key)
    crypto_free_pk_env(ns->signing_key);
  tor_free(ns->client_versions);
  tor_free(ns->server_versions);
  if (ns->entries) {
    SMARTLIST_FOREACH(ns->entries, routerstatus_t *, rs, routerstatus_free(rs));
    smartlist_free(ns->entries);
  }
  tor_free(ns);
}

/** Mark the router with ID <b>digest</b> as non-running in our routerlist. */
void
router_mark_as_down(const char *digest)
{
  routerinfo_t *router;
  tor_assert(digest);

  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, d,
                    if (!memcmp(d->digest, digest, DIGEST_LEN))
                      d->is_running = 0);

  router = router_get_by_digest(digest);
  if (!router) /* we don't seem to know about him in the first place */
    return;
  log_fn(LOG_DEBUG,"Marking router '%s' as down.",router->nickname);
  if (router_is_me(router) && !we_are_hibernating())
    log_fn(LOG_WARN, "We just marked ourself as down. Are your external addresses reachable?");
  router->is_running = 0;
}

/** Add <b>router</b> to the routerlist, if we don't already have it.  Replace
 * older entries (if any) with the same key.  Note: Callers should not hold
 * their pointers to <b>router</b> if this function fails; <b>router</b>
 * will either be inserted into the routerlist or freed.
 *
 * Returns >= 0 if the router was added; less than 0 if it was not.
 *
 * If we're returning non-zero, then assign to *<b>msg</b> a static string
 * describing the reason for not liking the routerinfo.
 *
 * If the return value is less than -1, there was a problem with the
 * routerinfo. If the return value is equal to -1, then the routerinfo was
 * fine, but out-of-date. If the return value is equal to 1, the
 * routerinfo was accepted, but we should notify the generator of the
 * descriptor using the message *<b>msg</b>.
 *
 * This function should be called *after*
 * routers_update_status_from_networkstatus; subsequenctly, you should call
 * router_rebuild_store and control_event_descriptors_changed.
 *
 * XXXX never replace your own descriptor.
 */
int
router_add_to_routerlist(routerinfo_t *router, const char **msg,
                         int from_cache)
{
  int i;
  char id_digest[DIGEST_LEN];
  int authdir = get_options()->AuthoritativeDir;
  int authdir_verified = 0;

  tor_assert(msg);

  if (!routerlist) {
    routerlist = tor_malloc_zero(sizeof(routerlist_t));
    routerlist->routers = smartlist_create();
  }

  crypto_pk_get_digest(router->identity_pkey, id_digest);

  if (authdir) {
    if (authdir_wants_to_reject_router(router, msg))
      return -2;
    authdir_verified = router->is_verified;
  }

  /* If we have a router with this name, and the identity key is the same,
   * choose the newer one. If the identity key has changed, drop the router.
   */
  for (i = 0; i < smartlist_len(routerlist->routers); ++i) {
    routerinfo_t *old_router = smartlist_get(routerlist->routers, i);
    if (!crypto_pk_cmp_keys(router->identity_pkey,old_router->identity_pkey)) {
      if (router->published_on <= old_router->published_on) {
        /* Same key, but old */
        log_fn(LOG_DEBUG, "Skipping not-new descriptor for router '%s'",
               router->nickname);
        routerinfo_free(router);
        *msg = "Router descriptor was not new.";
        return -1;
      } else {
        /* Same key, new. */
        int unreachable = 0;
        log_fn(LOG_DEBUG, "Replacing entry for router '%s/%s' [%s]",
               router->nickname, old_router->nickname,
               hex_str(id_digest,DIGEST_LEN));
        if (router->addr == old_router->addr &&
            router->or_port == old_router->or_port) {
          /* these carry over when the address and orport are unchanged.*/
          router->last_reachable = old_router->last_reachable;
          router->testing_since = old_router->testing_since;
          router->num_unreachable_notifications =
             old_router->num_unreachable_notifications;
        }
        if (authdir &&
            dirserv_thinks_router_is_blatantly_unreachable(router, time(NULL))) {
          if (router->num_unreachable_notifications >= 3) {
            unreachable = 1;
            log_fn(LOG_NOTICE, "Notifying server '%s' that it's unreachable. (ContactInfo '%s', platform '%s').",
              router->nickname, router->contact_info ? router->contact_info : "",
              router->platform ? router->platform : "");
          } else {
            log_fn(LOG_INFO,"'%s' may be unreachable -- the %d previous descriptors were thought to be unreachable.", router->nickname, router->num_unreachable_notifications);
            router->num_unreachable_notifications++;
          }
        }
        routerinfo_free(old_router);
        smartlist_set(routerlist->routers, i, router);
        if (!from_cache)
          router_append_to_journal(router->signed_descriptor,
                                   router->signed_descriptor_len);
        directory_set_dirty();
        *msg = unreachable ? "Dirserver believes your ORPort is unreachable" :
               authdir_verified ? "Verified server updated" :
               "Unverified server updated. (Have you sent us your key fingerprint?)";
        return unreachable ? 1 : 0;
      }
    } else if (!strcasecmp(router->nickname, old_router->nickname)) {
      /* nicknames match, keys don't. */
      if (router->is_named) {
        /* The new verified router replaces the old one; remove the
         * old one.  And carry on to the end of the list, in case
         * there are more old unverified routers with this nickname
         */
        /* mark-for-close connections using the old key, so we can
         * make new ones with the new key.
         */
        connection_t *conn;
        while ((conn = connection_get_by_identity_digest(
                                old_router->identity_digest, CONN_TYPE_OR))) {
          log_fn(LOG_INFO,"Closing conn to obsolete router '%s'",
                 old_router->nickname);
          connection_mark_for_close(conn);
        }
        routerinfo_free(old_router);
        smartlist_del_keeporder(routerlist->routers, i--);
      } else if (old_router->is_named) {
        /* Can't replace a verified router with an unverified one. */
        log_fn(LOG_DEBUG, "Skipping unverified entry for verified router '%s'",
               router->nickname);
        routerinfo_free(router);
        *msg = "Already have named router with same nickname and different key.";
        return -2;
      }
    }
  }
  /* We haven't seen a router with this name before.  Add it to the end of
   * the list. */
  smartlist_add(routerlist->routers, router);
  if (!from_cache)
    router_append_to_journal(router->signed_descriptor,
                             router->signed_descriptor_len);
  directory_set_dirty();
  return 0;
}

/** Remove any routers from the routerlist that are more than <b>age</b>
 * seconds old.
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

/**
 * Code to parse a single router descriptor and insert it into the
 * routerlist.  Return -1 if the descriptor was ill-formed; 0 if the
 * descriptor was well-formed but could not be added; and 1 if the
 * descriptor was added.
 *
 * If we don't add it and <b>msg</b> is not NULL, then assign to
 * *<b>msg</b> a static string describing the reason for refusing the
 * descriptor.
 *
 * This is used only by the controller.
 */
int
router_load_single_router(const char *s, const char **msg)
{
  routerinfo_t *ri;
  tor_assert(msg);
  smartlist_t *lst;
  *msg = NULL;

  if (!(ri = router_parse_entry_from_string(s, NULL))) {
    log_fn(LOG_WARN, "Error parsing router descriptor; dropping.");
    *msg = "Couldn't parse router descriptor.";
    return -1;
  }
  if (router_is_me(ri)) {
    log_fn(LOG_WARN, "Router's identity key matches mine; dropping.");
    *msg = "Router's identity key matches mine.";
    routerinfo_free(ri);
    return 0;
  }

  lst = smartlist_create();
  smartlist_add(lst, ri);
  routers_update_status_from_networkstatus(lst, 0);

  if (router_add_to_routerlist(ri, msg, 0)<0) {
    log_fn(LOG_WARN, "Couldn't add router to list: %s Dropping.",
           *msg?*msg:"(No message).");
    /* we've already assigned to *msg now, and ri is already freed */
    smartlist_free(lst);
    return 0;
  } else {
    control_event_descriptors_changed(lst);
    smartlist_free(lst);
    log_fn(LOG_DEBUG, "Added router to list");
    return 1;
  }
}

/** Given a string <b>s</b> containing some routerdescs, parse it and put the
 * routers into our directory.  If <b>from_cache</b> is false, the routers
 * have come from the network: cache them.
 *
 * If <b>requested_fingerprints</b> is provided, it must contain a list of
 * uppercased identity fingerprints.  Do not update any router whose
 * fingerprint is not on the list; after updating a router, remove its
 * fingerprint from the list.
 */
void
router_load_routers_from_string(const char *s, int from_cache,
                                smartlist_t *requested_fingerprints)
{
  smartlist_t *routers = smartlist_create(), *changed = smartlist_create();
  char fp[HEX_DIGEST_LEN+1];
  const char *msg;

  router_parse_list_from_string(&s, routers);

  routers_update_status_from_networkstatus(routers, !from_cache);

  SMARTLIST_FOREACH(routers, routerinfo_t *, ri,
  {
    base16_encode(fp, sizeof(fp), ri->identity_digest, DIGEST_LEN);
    if (requested_fingerprints) {
      if (smartlist_string_isin(requested_fingerprints, fp)) {
        smartlist_string_remove(requested_fingerprints, fp);
      } else {
        char *requested =
          smartlist_join_strings(requested_fingerprints," ",0,NULL);
        log_fn(LOG_WARN, "We received a router descriptor with a fingerprint (%s) that we never requested. (We asked for: %s.) Dropping.", fp, requested);
        tor_free(requested);
        routerinfo_free(ri);
        continue;
      }
    }

    if (router_add_to_routerlist(ri, &msg, from_cache) >= 0)
      smartlist_add(changed, ri);
  });

  control_event_descriptors_changed(changed);

  router_rebuild_store(0);

  smartlist_free(routers);
  smartlist_free(changed);
}

/** Helper: return a newly allocated string containing the name of the filename
 * where we plan to cache <b>ns</b>. */
static char *
networkstatus_get_cache_filename(const networkstatus_t *ns)
{
  const char *datadir = get_options()->DataDirectory;
  size_t len = strlen(datadir)+64;
  char fp[HEX_DIGEST_LEN+1];
  char *fn = tor_malloc(len+1);
  base16_encode(fp, HEX_DIGEST_LEN+1, ns->identity_digest, DIGEST_LEN);
  tor_snprintf(fn, len, "%s/cached-status/%s",datadir,fp);
  return fn;
}

/** Helper for smartlist_sort: Compare two networkstatus objects by
 * publication date. */
static int
_compare_networkstatus_published_on(const void **_a, const void **_b)
{
  const networkstatus_t *a = *_a, *b = *_b;
  if (a->published_on < b->published_on)
    return -1;
  else if (a->published_on > b->published_on)
    return 1;
  else
    return 0;
}

/** How far in the future do we allow a network-status to get before removing
 * it? (seconds) */
#define NETWORKSTATUS_ALLOW_SKEW (48*60*60)
/** Given a string <b>s</b> containing a network status that we received at
 * <b>arrived_at</b> from <b>source</b>, try to parse it, see if we want to
 * store it, and put it into our cache is necessary.
 *
 * If <b>source</b> is NS_FROM_DIR or NS_FROM_CACHE, do not replace our
 * own networkstatus_t (if we're a directory server).
 *
 * If <b>source</b> is NS_FROM_CACHE, do not write our networkstatus_t to the
 * cache.
 *
 * If <b>requested_fingerprints</b> is provided, it must contain a list of
 * uppercased identity fingerprints.  Do not update any networkstatus whose
 * fingerprint is not on the list; after updating a networkstatus, remove its
 * fingerprint from the list.
 *
 * Return 0 on success, -1 on failure.
 *
 * Callers should make sure that routers_update_all_from_networkstatus() is
 * invoked after this function succeeds.
 */
int
router_set_networkstatus(const char *s, time_t arrived_at,
            networkstatus_source_t source, smartlist_t *requested_fingerprints)
{
  networkstatus_t *ns;
  int i, found;
  time_t now;
  int skewed = 0;
  trusted_dir_server_t *trusted_dir;
  char fp[HEX_DIGEST_LEN+1];
  char published[ISO_TIME_LEN+1];

  ns = networkstatus_parse_from_string(s);
  if (!ns) {
    log_fn(LOG_WARN, "Couldn't parse network status.");
    return -1;
  }
  if (!(trusted_dir=router_get_trusteddirserver_by_digest(ns->identity_digest))) {
    log_fn(LOG_INFO, "Network status was signed, but not by an authoritative directory we recognize.");
    networkstatus_free(ns);
    return -1;
  }
  now = time(NULL);
  if (arrived_at > now)
    arrived_at = now;

  ns->received_on = arrived_at;

  format_iso_time(published, ns->published_on);

  if (ns->published_on > now + NETWORKSTATUS_ALLOW_SKEW) {
    log_fn(LOG_WARN, "Network status from %s was published in the future (%s GMT). Somebody is skewed here: check your clock. Not caching.", trusted_dir->description, published);
    skewed = 1;
  }

  if (!networkstatus_list)
    networkstatus_list = smartlist_create();

  if (source == NS_FROM_DIR && router_digest_is_me(ns->identity_digest)) {
    /* Don't replace our own networkstatus when we get it from somebody else. */
    networkstatus_free(ns);
    return 0;
  }

  base16_encode(fp, HEX_DIGEST_LEN+1, ns->identity_digest, DIGEST_LEN);

  if (requested_fingerprints) {
    if (smartlist_string_isin(requested_fingerprints, fp)) {
      smartlist_string_remove(requested_fingerprints, fp);
    } else {
      char *requested = smartlist_join_strings(requested_fingerprints," ",0,NULL);
      log_fn(LOG_WARN, "We received a network status with a fingerprint (%s) that we never requested. (We asked for: %s.) Dropping.", fp, requested);
      tor_free(requested);
      return 0;
    }
  }

  if (source != NS_FROM_CACHE)
    trusted_dir->n_networkstatus_failures = 0;

  found = 0;
  for (i=0; i < smartlist_len(networkstatus_list); ++i) {
    networkstatus_t *old_ns = smartlist_get(networkstatus_list, i);

    if (!memcmp(old_ns->identity_digest, ns->identity_digest, DIGEST_LEN)) {
      if (!memcmp(old_ns->networkstatus_digest,
                  ns->networkstatus_digest, DIGEST_LEN)) {
        /* Same one we had before. */
        networkstatus_free(ns);
        log_fn(LOG_INFO,
               "Not replacing network-status from %s (published %s); "
               "we already have it.",
               trusted_dir->description, published);
        if (old_ns->received_on < arrived_at) {
          if (source != NS_FROM_CACHE) {
            char *fn = networkstatus_get_cache_filename(old_ns);
            /* We use mtime to tell when it arrived, so update that. */
            touch_file(fn);
            tor_free(fn);
          }
          old_ns->received_on = arrived_at;
        }
        return 0;
      } else if (old_ns->published_on >= ns->published_on) {
        char old_published[ISO_TIME_LEN+1];
        format_iso_time(old_published, old_ns->published_on);
        log_fn(LOG_INFO,
               "Not replacing network-status from %s (published %s);"
               " we have a newer one (published %s) for this authority.",
               trusted_dir->description, published,
               old_published);
        networkstatus_free(ns);
        return 0;
      } else {
        networkstatus_free(old_ns);
        smartlist_set(networkstatus_list, i, ns);
        found = 1;
        break;
      }
    }
  }

  if (!found)
    smartlist_add(networkstatus_list, ns);

  log_fn(LOG_INFO, "Setting networkstatus %s %s (published %s)",
         source == NS_FROM_CACHE?"cached from":
         (source==NS_FROM_DIR?"downloaded from":"generated for"),
         trusted_dir->description, published);
  networkstatus_list_has_changed = 1;

  smartlist_sort(networkstatus_list, _compare_networkstatus_published_on);

  if (source != NS_FROM_CACHE && !skewed) {
    char *fn = networkstatus_get_cache_filename(ns);
    if (write_str_to_file(fn, s, 0)<0) {
      log_fn(LOG_NOTICE, "Couldn't write cached network status to \"%s\"", fn);
    }
    tor_free(fn);
  }

  networkstatus_list_update_recent(now);

  if (get_options()->DirPort && !skewed)
    dirserv_set_cached_networkstatus_v2(s, fp, ns->published_on);

  return 0;
}

/** How old do we allow a network-status to get before removing it completely? */
#define MAX_NETWORKSTATUS_AGE (10*24*60*60)
/** Remove all very-old network_status_t objects from memory and from the
 * disk cache. */
void
networkstatus_list_clean(time_t now)
{
  int i;
  if (!networkstatus_list)
    return;

  for (i = 0; i < smartlist_len(networkstatus_list); ++i) {
    networkstatus_t *ns = smartlist_get(networkstatus_list, i);
    char *fname = NULL;;
    if (ns->published_on + MAX_NETWORKSTATUS_AGE > now)
      continue;
    /* Okay, this one is too old.  Remove it from the list, and delete it
     * from the cache. */
    smartlist_del(networkstatus_list, i--);
    fname = networkstatus_get_cache_filename(ns);
    if (file_status(fname) == FN_FILE) {
      log_fn(LOG_INFO, "Removing too-old networkstatus in %s", fname);
      unlink(fname);
    }
    tor_free(fname);
    if (get_options()->DirPort) {
      char fp[HEX_DIGEST_LEN+1];
      base16_encode(fp, sizeof(fp), ns->identity_digest, DIGEST_LEN);
      dirserv_set_cached_networkstatus_v2(NULL, fp, 0);
    }
    networkstatus_free(ns);
  }
}

/** Helper for bsearching a list of routerstatus_t pointers.*/
static int
_compare_digest_to_routerstatus_entry(const void *_key, const void **_member)
{
  const char *key = _key;
  const routerstatus_t *rs = *_member;
  return memcmp(key, rs->identity_digest, DIGEST_LEN);
}

/** Return the entry in <b>ns</b> for the identity digest <b>digest</b>, or
 * NULL if none was found. */
static routerstatus_t *
networkstatus_find_entry(networkstatus_t *ns, const char *digest)
{
  return smartlist_bsearch(ns->entries, digest,
                           _compare_digest_to_routerstatus_entry);
}

/** Return the consensus view of the status of the router whose digest is
 * <b>digest</b>, or NULL if we don't know about any such router. */
local_routerstatus_t *
router_get_combined_status_by_digest(const char *digest)
{
  if (!routerstatus_list)
    return NULL;
  return smartlist_bsearch(routerstatus_list, digest,
                           _compare_digest_to_routerstatus_entry);
}

/* XXXX These should be configurable, perhaps? NM */
#define AUTHORITY_NS_CACHE_INTERVAL 10*60
#define NONAUTHORITY_NS_CACHE_INTERVAL 15*60
/** We are a directory server, and so cache network_status documents.
 * Initiate downloads as needed to update them.  For authorities, this means
 * asking each trusted directory for its network-status.  For caches, this means
 * asking a random authority for all network-statuses.
 */
void
update_networkstatus_cache_downloads(time_t now)
{
  static time_t last_downloaded = 0;
  int authority = authdir_mode(get_options());
  int interval =
    authority ? AUTHORITY_NS_CACHE_INTERVAL : NONAUTHORITY_NS_CACHE_INTERVAL;

  /*XXXXX NM we should retry on failure. */
  if (last_downloaded + interval >= now)
    return;
  if (!trusted_dir_servers)
    return;

  last_downloaded = now;

  if (authority) {
    /* An authority launches a separate connection for everybody. */
    SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
       {
         char resource[HEX_DIGEST_LEN+6];
         if (router_digest_is_me(ds->digest))
           continue;
         if (connection_get_by_type_addr_port_purpose(
                CONN_TYPE_DIR, ds->addr, ds->dir_port,
                DIR_PURPOSE_FETCH_NETWORKSTATUS)) {
           /* We are already fetching this one. */
           continue;
         }
         strlcpy(resource, "fp/", sizeof(resource));
         base16_encode(resource+3, sizeof(resource)-3, ds->digest, DIGEST_LEN);
         strlcat(resource, ".z", sizeof(resource));
         directory_get_from_dirserver(DIR_PURPOSE_FETCH_NETWORKSTATUS,resource,1);
       });
  } else {
    /* A non-authority cache launches one connection to a random authority. */
    /* (Check whether we're currently fetching network-status objects.) */
    if (!connection_get_by_type_purpose(CONN_TYPE_DIR,
                                        DIR_PURPOSE_FETCH_NETWORKSTATUS))
      directory_get_from_dirserver(DIR_PURPOSE_FETCH_NETWORKSTATUS,"all.z",1);
  }
}

/*XXXX Should these be configurable? NM*/
/** How old (in seconds) can a network-status be before we try replacing it? */
#define NETWORKSTATUS_MAX_VALIDITY (48*60*60)
/** How long (in seconds) does a client wait after getting a network status
 * before downloading the next in sequence? */
#define NETWORKSTATUS_CLIENT_DL_INTERVAL (30*60)
/* How many times do we allow a networkstatus download to fail before we
 * assume that the authority isn't publishing? */
#define NETWORKSTATUS_N_ALLOWABLE_FAILURES 3
/** We are not a directory cache or authority.  Update our network-status list
 * by launching a new directory fetch for enough network-status documents "as
 * necessary".  See function comments for implementation details.
 */
void
update_networkstatus_client_downloads(time_t now)
{
  int n_live = 0, needed = 0, n_running_dirservers, n_dirservers, i;
  int most_recent_idx = -1;
  trusted_dir_server_t *most_recent = NULL;
  time_t most_recent_received = 0;
  char *resource, *cp;
  size_t resource_len;

  if (connection_get_by_type_purpose(CONN_TYPE_DIR,
                                     DIR_PURPOSE_FETCH_NETWORKSTATUS))
    return;

  /* This is a little tricky.  We want to download enough network-status
   * objects so that we have at least half of them under
   * NETWORKSTATUS_MAX_VALIDITY publication time.  We want to download a new
   * *one* if the most recent one's publication time is under
   * NETWORKSTATUS_CLIENT_DL_INTERVAL.
   */
  if (!trusted_dir_servers || !smartlist_len(trusted_dir_servers))
    return;
  n_dirservers = n_running_dirservers = smartlist_len(trusted_dir_servers);
  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
     {
       networkstatus_t *ns = networkstatus_get_by_digest(ds->digest);
       if (!ns)
         continue;
       if (ds->n_networkstatus_failures > NETWORKSTATUS_N_ALLOWABLE_FAILURES) {
         --n_running_dirservers;
         continue;
       }
       if (ns->published_on > now-NETWORKSTATUS_MAX_VALIDITY)
         ++n_live;
       if (!most_recent || ns->received_on > most_recent_received) {
         most_recent_idx = ds_sl_idx; /* magic variable from FOREACH */
         most_recent = ds;
         most_recent_received = ns->received_on;
       }
     });

  /* Download enough so we have at least half live, but no more than all the
   * trusted dirservers we know.
   */
  if (n_live < (n_dirservers/2)+1)
    needed = (n_dirservers/2)+1-n_live;
  if (needed > n_running_dirservers)
    needed = n_running_dirservers;

  if (needed)
    log_fn(LOG_INFO, "For %d/%d running directory servers, we have %d live"
           " network-status documents. Downloading %d.",
           n_running_dirservers, n_dirservers, n_live, needed);

  /* Also, download at least 1 every NETWORKSTATUS_CLIENT_DL_INTERVAL. */
  if (n_running_dirservers &&
      most_recent_received < now-NETWORKSTATUS_CLIENT_DL_INTERVAL && needed < 1) {
    log_fn(LOG_INFO, "Our most recent network-status document (from %s) "
           "is %d seconds old; downloading another.",
           most_recent?most_recent->description:"nobody",
           (int)(now-most_recent_received));
    needed = 1;
  }

  if (!needed)
    return;

  /* If no networkstatus was found, choose a dirserver at random as "most
   * recent". */
  if (most_recent_idx<0)
    most_recent_idx = crypto_pseudo_rand_int(n_dirservers);

  /* Build a request string for all the resources we want. */
  resource_len = needed * (HEX_DIGEST_LEN+1) + 6;
  resource = tor_malloc(resource_len);
  memcpy(resource, "fp/", 3);
  cp = resource+3;
  for (i = most_recent_idx+1; needed; ++i) {
    trusted_dir_server_t *ds;
    if (i >= n_dirservers)
      i = 0;
    ds = smartlist_get(trusted_dir_servers, i);
    if (ds->n_networkstatus_failures > NETWORKSTATUS_N_ALLOWABLE_FAILURES)
      continue;
    base16_encode(cp, HEX_DIGEST_LEN+1, ds->digest, DIGEST_LEN);
    cp += HEX_DIGEST_LEN;
    --needed;
    if (needed)
      *cp++ = '+';
  }
  memcpy(cp, ".z", 3);
  directory_get_from_dirserver(DIR_PURPOSE_FETCH_NETWORKSTATUS, resource, 1);
  tor_free(resource);
}

/** Decide whether a given addr:port is definitely accepted,
 * definitely rejected, probably accepted, or probably rejected by a
 * given policy.  If <b>addr</b> is 0, we don't know the IP of the
 * target address. If <b>port</b> is 0, we don't know the port of the
 * target address.
 *
 * For now, the algorithm is pretty simple: we look for definite and
 * uncertain matches.  The first definite match is what we guess; if
 * it was preceded by no uncertain matches of the opposite policy,
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
int
router_exit_policy_all_routers_reject(uint32_t addr, uint16_t port,
                                          int need_uptime)
{
  addr_policy_result_t r;
  if (!routerlist) return 1;

  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
  {
    if (router->is_running &&
        !router_is_unreliable(router, need_uptime, 0)) {
      r = router_compare_addr_to_addr_policy(addr, port, router->exit_policy);
      if (r != ADDR_POLICY_REJECTED && r != ADDR_POLICY_PROBABLY_REJECTED)
        return 0; /* this one could be ok. good enough. */
    }
  });
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
    { 0x7f000000, 0xff000000, "localhost (127.0.0.0/8)" },
    { 0x0a000000, 0xff000000, "addresses in private network 10.0.0.0/8" },
    { 0xa9fe0000, 0xffff0000, "addresses in private network 169.254.0.0/16" },
    { 0xac100000, 0xfff00000, "addresses in private network 172.16.0.0/12" },
    { 0xc0a80000, 0xffff0000, "addresses in private network 192.168.0.0/16" },
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
int
router_exit_policy_rejects_all(routerinfo_t *router)
{
  return router_compare_addr_to_addr_policy(0, 0, router->exit_policy)
    == ADDR_POLICY_REJECTED;
}

/** Add to the list of authorized directory servers one at
 * <b>address</b>:<b>port</b>, with identity key <b>digest</b>.  If
 * <b>address</b> is NULL, add ourself. */
void
add_trusted_dir_server(const char *nickname, const char *address,
                       uint16_t port, const char *digest, int supports_v1)
{
  trusted_dir_server_t *ent;
  uint32_t a;
  char *hostname = NULL;
  size_t dlen;
  if (!trusted_dir_servers)
    trusted_dir_servers = smartlist_create();

  if (!address) { /* The address is us; we should guess. */
    if (resolve_my_address(get_options(), &a, &hostname) < 0) {
      log_fn(LOG_WARN, "Couldn't find a suitable address. Returning.");
      return;
    }
  } else {
    if (tor_lookup_hostname(address, &a)) {
      log_fn(LOG_WARN, "Unable to lookup address for directory server at %s",
             address);
      return;
    }
    hostname = tor_strdup(address);
    a = ntohl(a);
  }

  ent = tor_malloc_zero(sizeof(trusted_dir_server_t));
  ent->nickname = nickname ? tor_strdup(nickname) : NULL;
  ent->address = hostname;
  ent->addr = a;
  ent->dir_port = port;
  ent->is_running = 1;
  ent->supports_v1_protocol = supports_v1;
  memcpy(ent->digest, digest, DIGEST_LEN);

  dlen = 64 + strlen(hostname) + (nickname?strlen(nickname):0);
  ent->description = tor_malloc(dlen);
  if (nickname)
    tor_snprintf(ent->description, dlen, "directory server \"%s\" at %s:%d",
                 nickname, hostname, (int)port);
  else
    tor_snprintf(ent->description, dlen, "directory server at %s:%d",
                 hostname, (int)port);

  smartlist_add(trusted_dir_servers, ent);
}

/** Remove all members from the list of trusted dir servers. */
void
clear_trusted_dir_servers(void)
{
  if (trusted_dir_servers) {
    SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ent,
      {
        tor_free(ent->nickname);
        tor_free(ent->description);
        tor_free(ent->address);
        tor_free(ent);
      });
    smartlist_clear(trusted_dir_servers);
  } else {
    trusted_dir_servers = smartlist_create();
  }
}

/** Return the network status with a given identity digest. */
networkstatus_t *
networkstatus_get_by_digest(const char *digest)
{
  SMARTLIST_FOREACH(networkstatus_list, networkstatus_t *, ns,
    {
      if (!memcmp(ns->identity_digest, digest, DIGEST_LEN))
        return ns;
    });
  return NULL;
}

/** If the network-status list has changed since the last time we called this
 * function, update the status of every router from the network-status list.
 */
void
routers_update_all_from_networkstatus(void)
{
#define SELF_OPINION_INTERVAL 90*60
  static int have_warned_about_unverified_status = 0;
  static int have_warned_about_old_version = 0;
  static int have_warned_about_new_version = 0;
  routerinfo_t *me;
  time_t now;
  if (!routerlist || !networkstatus_list ||
      (!networkstatus_list_has_changed && !routerstatus_list_has_changed))
    return;

  now = time(NULL);
  if (networkstatus_list_has_changed)
    routerstatus_list_update_from_networkstatus(now);

  routers_update_status_from_networkstatus(routerlist->routers, 0);

  me = router_get_my_routerinfo();
  if (me && !have_warned_about_unverified_status) {
    int n_recent = 0, n_listing = 0, n_valid = 0, n_named = 0;
    routerstatus_t *rs;
    SMARTLIST_FOREACH(networkstatus_list, networkstatus_t *, ns,
    {
      if (ns->received_on + SELF_OPINION_INTERVAL < now)
        continue;
      ++n_recent;
      if (!(rs = networkstatus_find_entry(ns, me->identity_digest)))
        continue;
      ++n_listing;
      if (rs->is_valid)
        ++n_valid;
      if (rs->is_named)
        ++n_named;
    });

    if (n_recent >= 2 && n_listing >= 2) {
      if (n_valid <= n_recent/2)  {
        log_fn(LOG_WARN, "%d/%d recent directory servers list us as invalid. Please consider sending your identity fingerprint to the tor-ops.",
               n_recent-n_valid, n_recent);
        have_warned_about_unverified_status = 1;
      } else if (n_named <= n_recent/2)  {
        log_fn(LOG_WARN, "%d/%d recent directory servers list us as unnamed. Please consider sending your identity fingerprint to the tor-ops.",
               n_recent-n_valid, n_recent);
        have_warned_about_unverified_status = 1;
      }
    }
  }

  helper_nodes_set_status_from_directory();

  if (!have_warned_about_old_version) {
    int n_recent = 0;
    int n_recommended = 0;
    int is_server = server_mode(get_options());
    version_status_t consensus = VS_RECOMMENDED;
    SMARTLIST_FOREACH(networkstatus_list, networkstatus_t *, ns,
    {
      version_status_t vs;
      if (!ns->recommends_versions ||
          ns->received_on + SELF_OPINION_INTERVAL < now )
        continue;
      vs = tor_version_is_obsolete(
              VERSION, is_server ? ns->server_versions : ns->client_versions);
      if (vs == VS_RECOMMENDED)
        ++n_recommended;
      if (n_recent++ == 0) {
        consensus = vs;
      } else if (consensus != vs) {
        consensus = version_status_join(consensus, vs);
      }
    });
    if (n_recent > 2 && n_recommended < n_recent/2) {
      if (consensus == VS_NEW || consensus == VS_NEW_IN_SERIES) {
        if (!have_warned_about_new_version) {
          log_fn(LOG_NOTICE, "This version of Tor (%s) is newer than any recommended version%s, according to %d/%d recent network statuses.",
                 VERSION, consensus == VS_NEW_IN_SERIES ? " in its series" : "",
                 n_recent-n_recommended, n_recent);
          have_warned_about_new_version = 1;
        }
      } else {
        log_fn(LOG_NOTICE, "This version of Tor (%s) is %s, according to %d/%d recent network statuses.",
               VERSION, consensus == VS_OLD ? "obsolete" : "not recommended",
               n_recent-n_recommended, n_recent);
        have_warned_about_old_version = 1;
      }
    } else {
      log_fn(LOG_INFO, "%d/%d recent directories think my version is ok.",
             n_recommended, n_recent);
    }
  }

  routerstatus_list_has_changed = 0;
}

/** Allow any network-status newer than this to influence our view of who's
 * running. */
#define DEFAULT_RUNNING_INTERVAL 60*60
/** If possible, always allow at least this many network-statuses to influence
 * our view of who's running. */
#define MIN_TO_INFLUENCE_RUNNING 3

/** Change the is_recent field of each member of networkstatus_list so that
 * all members more recent than DEFAULT_RUNNING_INTERVAL are recent, and
 * at least the MIN_TO_INFLUENCE_RUNNING most recent members are resent, and no
 * others are recent.  Set networkstatus_list_has_changed if anything happeed.
 */
void
networkstatus_list_update_recent(time_t now)
{
  int n_statuses, n_recent, changed, i;
  char published[ISO_TIME_LEN+1];

  if (!networkstatus_list)
    return;

  n_statuses = smartlist_len(networkstatus_list);
  n_recent = 0;
  changed = 0;
  for (i=n_statuses-1; i >= 0; --i) {
    networkstatus_t *ns = smartlist_get(networkstatus_list, i);
    trusted_dir_server_t *ds =
      router_get_trusteddirserver_by_digest(ns->identity_digest);
    const char *src = ds?ds->description:ns->source_address;
    if (n_recent < MIN_TO_INFLUENCE_RUNNING ||
        ns->published_on + DEFAULT_RUNNING_INTERVAL > now) {
      if (!ns->is_recent) {
        format_iso_time(published, ns->published_on);
        log_fn(LOG_INFO,
               "Networkstatus from %s (published %s) is now \"recent\"",
               src, published);
        changed = 1;
      }
      ns->is_recent = 1;
      ++n_recent;
    } else {
      if (ns->is_recent) {
        format_iso_time(published, ns->published_on);
        log_fn(LOG_INFO,
               "Networkstatus from %s (published %s) is no longer \"recent\"",
               src, published);
        changed = 1;
        ns->is_recent = 0;
      }
    }
  }
  if (changed)
    networkstatus_list_has_changed = 1;
}

/** Update our view of router status (as stored in routerstatus_list) from
 * the current set of network status documents (as stored in networkstatus_list).
 * Do nothing unless the network status list has changed since the last time
 * this function was called.
 */
static void
routerstatus_list_update_from_networkstatus(time_t now)
{
  int n_trusted, n_statuses, n_recent=0, n_naming=0;
  int n_distinct = 0;
  int i;
  int *index, *size;
  networkstatus_t **networkstatus;
  smartlist_t *result;
  strmap_t *name_map;
  char conflict[DIGEST_LEN];

  networkstatus_list_update_recent(now);

  if (!networkstatus_list_has_changed)
    return;
  if (!networkstatus_list)
    networkstatus_list = smartlist_create();
  if (!routerstatus_list)
    routerstatus_list = smartlist_create();
  if (!trusted_dir_servers)
    trusted_dir_servers = smartlist_create();

  n_trusted = smartlist_len(trusted_dir_servers);
  n_statuses = smartlist_len(networkstatus_list);

  if (n_statuses < (n_trusted/2)+1) {
    /* Not enough statuses to adjust status. */
    log_fn(LOG_NOTICE,"Not enough statuses to update router status list. (%d/%d)",
           n_statuses, n_trusted);
    return;
  }

  log_fn(LOG_INFO, "Rebuilding router status list.");

  index = tor_malloc(sizeof(int)*n_statuses);
  size = tor_malloc(sizeof(int)*n_statuses);
  networkstatus = tor_malloc(sizeof(networkstatus_t *)*n_statuses);
  for (i = 0; i < n_statuses; ++i) {
    index[i] = 0;
    networkstatus[i] = smartlist_get(networkstatus_list, i);
    size[i] = smartlist_len(networkstatus[i]->entries);
    if (networkstatus[i]->binds_names)
      ++n_naming;
    if (networkstatus[i]->is_recent)
      ++n_recent;
  }

  name_map = strmap_new();
  memset(conflict, 0xff, sizeof(conflict));
  for (i = 0; i < n_statuses; ++i) {
    if (!networkstatus[i]->binds_names)
      continue;
    SMARTLIST_FOREACH(networkstatus[i]->entries, routerstatus_t *, rs,
    {
      const char *other_digest;
      if (!rs->is_named)
        continue;
      other_digest = strmap_get_lc(name_map, rs->nickname);
      if (!other_digest)
        strmap_set_lc(name_map, rs->nickname, rs->identity_digest);
      else if (memcmp(other_digest, rs->identity_digest, DIGEST_LEN) &&
               other_digest != conflict) {
        /*XXXX011 rate-limit this?*/
        char fp1[HEX_DIGEST_LEN+1];
        char fp2[HEX_DIGEST_LEN+1];
        base16_encode(fp1, sizeof(fp1), other_digest, DIGEST_LEN);
        base16_encode(fp2, sizeof(fp2), rs->identity_digest, DIGEST_LEN);
        log_fn(LOG_WARN,
               "Naming authorities disagree about which key goes with %s. ($%s vs $%s)",
               rs->nickname, fp1, fp2);
        strmap_set_lc(name_map, rs->nickname, conflict);
      }
    });
  }

  result = smartlist_create();

  /* Iterate through all of the sorted routerstatus lists in step.
   * Invariants:
   *  - For 0 <= i < n_statuses: index[i] is an index into
   *    networkstatus[i]->entries, which has size[i] elements.
   *  - For i1, i2, j such that 0 <= i1 < n_statuses, 0 <= i2 < n_statues, 0 <=
   *    j < index[i1], networkstatus[i1]->entries[j]->identity_digest <
   *    networkstatus[i2]->entries[index[i2]]->identity_digest.
   *
   *    (That is, the indices are always advanced past lower digest before
   *    higher.)
   */
  while (1) {
    int n_running=0, n_named=0, n_valid=0, n_listing=0;
    const char *the_name = NULL;
    local_routerstatus_t *rs_out, *rs_old;
    routerstatus_t *rs, *most_recent;
    networkstatus_t *ns;
    const char *lowest = NULL;
    /* Find out which of the digests appears first. */
    for (i = 0; i < n_statuses; ++i) {
      if (index[i] < size[i]) {
        rs = smartlist_get(networkstatus[i]->entries, index[i]);
        if (!lowest || memcmp(rs->identity_digest, lowest, DIGEST_LEN)<0)
          lowest = rs->identity_digest;
      }
    }
    if (!lowest) {
      /* We're out of routers. Great! */
      break;
    }
    /* Okay. The routers at networkstatus[i]->entries[index[i]] whose digests
     * match "lowest" are next in order. Iterate over them, incrementing those
     * index[i] as we go. */
    ++n_distinct;
    most_recent = NULL;
    for (i = 0; i < n_statuses; ++i) {
      if (index[i] >= size[i])
        continue;
      ns = networkstatus[i];
      rs = smartlist_get(ns->entries, index[i]);
      if (memcmp(rs->identity_digest, lowest, DIGEST_LEN))
        continue;
      ++index[i];
      ++n_listing;
      if (!most_recent || rs->published_on > most_recent->published_on)
        most_recent = rs;
      if (rs->is_named && ns->binds_names) {
        if (!the_name)
          the_name = rs->nickname;
        if (!strcasecmp(rs->nickname, the_name)) {
          ++n_named;
        } else if (strcmp(the_name,"**mismatch**")) {
          char hd[HEX_DIGEST_LEN+1];
          base16_encode(hd, HEX_DIGEST_LEN+1, rs->identity_digest, DIGEST_LEN);
          log_fn(LOG_WARN, "Naming authorities disagree about nicknames for $%s (\"%s\" vs \"%s\")",
                 hd, the_name, rs->nickname);
          the_name = "**mismatch**";
        }
      }
      if (rs->is_valid)
        ++n_valid;
      if (rs->is_running && ns->is_recent)
        ++n_running;
    }
    rs_out = tor_malloc_zero(sizeof(local_routerstatus_t));
    memcpy(&rs_out->status, most_recent, sizeof(routerstatus_t));
    if ((rs_old = router_get_combined_status_by_digest(lowest))) {
      rs_out->n_download_failures = rs_old->n_download_failures;
      rs_out->next_attempt_at = rs_old->next_attempt_at;
      rs_out->name_lookup_warned = rs_old->name_lookup_warned;
    }
    smartlist_add(result, rs_out);
    log_fn(LOG_DEBUG, "Router '%s' is listed by %d/%d directories, "
           "named by %d/%d, validated by %d/%d, and %d/%d recent directories "
           "think it's running.",
           rs_out->status.nickname,
           n_listing, n_statuses, n_named, n_naming, n_valid, n_statuses,
           n_running, n_recent);
    rs_out->status.is_named  = 0;
    if (the_name && strcmp(the_name, "**mismatch**") && n_named > 0) {
      const char *d = strmap_get_lc(name_map, the_name);
      if (d && d != conflict)
        rs_out->status.is_named = 1;
    }
    if (rs_out->status.is_named)
      strlcpy(rs_out->status.nickname, the_name, sizeof(rs_out->status.nickname));
    rs_out->status.is_valid = n_valid > n_statuses/2;
    rs_out->status.is_running = n_running > n_recent/2;
  }
  SMARTLIST_FOREACH(routerstatus_list, local_routerstatus_t *, rs,
                    local_routerstatus_free(rs));
  smartlist_free(routerstatus_list);
  routerstatus_list = result;

  tor_free(networkstatus);
  tor_free(index);
  tor_free(size);
  strmap_free(name_map, NULL);

  networkstatus_list_has_changed = 0;
  routerstatus_list_has_changed = 1;
}

/** Given a list <b>routers</b> of routerinfo_t *, update each routers's
 * is_named, is_verified, and is_running fields according to our current
 * networkstatus_t documents. */
void
routers_update_status_from_networkstatus(smartlist_t *routers, int reset_failures)
{
  trusted_dir_server_t *ds;
  local_routerstatus_t *rs;
  or_options_t *options = get_options();
  int authdir = options->AuthoritativeDir;
  int namingdir = options->AuthoritativeDir &&
    options->NamingAuthoritativeDir;

  if (!routerstatus_list)
    return;

  SMARTLIST_FOREACH(routers, routerinfo_t *, router,
  {
    rs = router_get_combined_status_by_digest(router->identity_digest);
    ds = router_get_trusteddirserver_by_digest(router->identity_digest);

    if (!rs)
      continue;

    if (reset_failures) {
      rs->n_download_failures = 0;
      rs->next_attempt_at = 0;
    }

    if (!namingdir)
      router->is_named = rs->status.is_named;

    if (!authdir) {
      /* If we're an authdir, don't believe others. */
      router->is_verified = rs->status.is_valid;
      router->is_running = rs->status.is_running;

      if (router->is_running && ds) {
        /* XXXX011 NM Hm. What about authorities? When do they reset
         * n_networkstatus_failures? */
        ds->n_networkstatus_failures = 0;
      }
    }
  });
}

/** Return new list of ID fingerprints for superseded routers.  A router is
 * superseded if any network-status has a router with a different digest
 * published more recently, or if it is listed in the network-status but not
 * in the router list.
 */
static smartlist_t *
router_list_downloadable(void)
{
#define MAX_OLD_SERVER_DOWNLOAD_RATE 2*60*60
  int n_conns, i, n_downloadable = 0;
  int n_uptodate=0,n_skip_old=0;
  connection_t **carray;
  smartlist_t *superseded = smartlist_create();
  smartlist_t *downloading;
  time_t now = time(NULL);
  int mirror = server_mode(get_options()) && get_options()->DirPort;

  if (!routerstatus_list)
    return superseded;

  get_connection_array(&carray, &n_conns);

  routerstatus_list_update_from_networkstatus(now);

  SMARTLIST_FOREACH(routerstatus_list, local_routerstatus_t *, rs,
  {
    if (rs->next_attempt_at < now) {
      rs->should_download = 1;
      ++n_downloadable;
    } else {
      /*
      char fp[HEX_DIGEST_LEN+1];
      base16_encode(fp, HEX_DIGEST_LEN+1, rs->status.identity_digest, DIGEST_LEN);
      log_fn(LOG_NOTICE, "Not yet ready to download %s (%d more seconds)", fp,
             (int)(rs->next_attempt_at-now));
      */
      rs->should_download = 0;
    }
  });

  downloading = smartlist_create();
  for (i = 0; i < n_conns; ++i) {
    connection_t *conn = carray[i];
    if (conn->type == CONN_TYPE_DIR &&
        conn->purpose == DIR_PURPOSE_FETCH_SERVERDESC &&
        !conn->marked_for_close) {
      if (!strcmpstart(conn->requested_resource, "all"))
        n_downloadable = 0;
      dir_split_resource_into_fingerprints(conn->requested_resource,
                                           downloading, NULL);
    }
  }

  /*
  log_fn(LOG_NOTICE, "%d downloads already in progress",
         smartlist_len(downloading));
  smartlist_sort_strings(downloading);
  */
  if (n_downloadable) {
    SMARTLIST_FOREACH(downloading, const char *, dl,
    {
      char d[DIGEST_LEN];
      local_routerstatus_t *rs;
      base16_decode(d, DIGEST_LEN, dl, strlen(dl));
      if ((rs = router_get_combined_status_by_digest(d)) && rs->should_download) {
        rs->should_download = 0;
        --n_downloadable;
        // log_fn(LOG_NOTICE, "%s is in-progress; not fetching", dl);
      }
    });
  }
  SMARTLIST_FOREACH(downloading, char *, cp, tor_free(cp));
  smartlist_free(downloading);
  if (!n_downloadable)
    return superseded;

  if (routerlist) {
    SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, ri,
    {
      local_routerstatus_t *rs;
      if (!(rs = router_get_combined_status_by_digest(ri->identity_digest)) ||
          !rs->should_download) {
        // log_fn(LOG_NOTICE, "No status for %s", fp);
        continue;
      }
      /* Change this "or" to be an "and" once dirs generate hashes right.
       * Remove the version check once older versions are uncommon.
       * XXXXX. NM */
      if (!memcmp(ri->signed_descriptor_digest, rs->status.descriptor_digest,
                  DIGEST_LEN) ||
          rs->status.published_on <= ri->published_on) {
        ++n_uptodate;
        rs->should_download = 0;
        --n_downloadable;
      } else if (!mirror &&
                 ri->platform &&
                 !tor_version_as_new_as(ri->platform, "0.1.1.6-alpha") &&
                 ri->published_on + MAX_OLD_SERVER_DOWNLOAD_RATE > now)  {
        /* Same digest, or date is up-to-date, or we have a comparatively recent
         * server with an old version.
         * No need to download it. */
        // log_fn(LOG_NOTICE, "Up-to-date status for %s", fp);
        ++n_skip_old;
        rs->should_download = 0;
        --n_downloadable;
      } /* else {
        char t1[ISO_TIME_LEN+1];
        char t2[ISO_TIME_LEN+1];
        format_iso_time(t1, rs->satus.published_on);
        format_iso_time(t2, ri->published_on);
        log_fn(LOG_NOTICE, "Out-of-date status for %s %s (%d %d) [%s %s]", fp,
               ri->nickname,
               !memcmp(ri->signed_descriptor_digest,rs->status.descriptor_digest,
                       DIGEST_LEN),
               rs->published_on < ri->published_on,
               t1, t2);
      } */
    });
  }

  if (n_skip_old)
    log_fn(LOG_INFO, "Skipped %d updatable pre-0.1.1.6 servers.", n_skip_old);

  if (!n_downloadable)
    return superseded;

  SMARTLIST_FOREACH(routerstatus_list, local_routerstatus_t *, rs,
  {
    if (rs->should_download) {
      char *fp = tor_malloc(HEX_DIGEST_LEN+1);
      base16_encode(fp, HEX_DIGEST_LEN+1, rs->status.identity_digest, DIGEST_LEN);
      smartlist_add(superseded, fp);
    }
  });

  return superseded;
}

/** Initiate new router downloads as needed.
 *
 * We only allow one router descriptor download at a time.
 * If we have less than two network-status documents, we ask
 * a directory for "all descriptors."
 * Otherwise, we ask for all descriptors that we think are different
 * from what we have.
 */
void
update_router_descriptor_downloads(time_t now)
{
#define MAX_DL_PER_REQUEST 128
#define MIN_DL_PER_REQUEST 4
#define MIN_REQUESTS 3
#define MAX_DL_TO_DELAY 16
#define MAX_CLIENT_INTERVAL_WITHOUT_REQUEST 10*60
#define MAX_SERVER_INTERVAL_WITHOUT_REQUEST 1*60
  smartlist_t *downloadable = NULL;
  int get_all = 0;
  int dirserv = server_mode(get_options()) && get_options()->DirPort;
  int should_delay, n_downloadable;
  static time_t last_download_attempted = 0;
  if (!networkstatus_list || smartlist_len(networkstatus_list)<2)
    get_all = 1;

  if (get_all) {
    log_fn(LOG_NOTICE, "Launching request for all routers");
    last_download_attempted = now;
    directory_get_from_dirserver(DIR_PURPOSE_FETCH_SERVERDESC,"all.z",1);
    return;
  }

  downloadable = router_list_downloadable();
  n_downloadable = smartlist_len(downloadable);
  if (n_downloadable >= MAX_DL_TO_DELAY)
    should_delay = 0;
  else if (n_downloadable == 0)
    should_delay = 1;
  else if (dirserv)
    should_delay = (last_download_attempted +
                    MAX_SERVER_INTERVAL_WITHOUT_REQUEST) < now;
  else
    should_delay = (last_download_attempted +
                    MAX_CLIENT_INTERVAL_WITHOUT_REQUEST) < now;

  if (! should_delay) {
    int i, j, n_per_request=MAX_DL_PER_REQUEST;
    size_t r_len = MAX_DL_PER_REQUEST*(HEX_DIGEST_LEN+1)+16;
    char *resource = tor_malloc(r_len);

    if (! dirserv) {
      n_per_request = (n_downloadable+MIN_REQUESTS-1) / MIN_REQUESTS;
      if (n_per_request > MAX_DL_PER_REQUEST)
        n_per_request = MAX_DL_PER_REQUEST;
      if (n_per_request < MIN_DL_PER_REQUEST)
        n_per_request = MIN_DL_PER_REQUEST;
    }
    log_fn(LOG_INFO, "Launching %d request%s for %d router%s, %d at a time",
           (n_downloadable+n_per_request-1)/n_per_request,
           n_downloadable>n_per_request?"s":"",
           n_downloadable, n_downloadable>1?"s":"", n_per_request);
    for (i=0; i < n_downloadable; i += n_per_request) {
      char *cp = resource;
      memcpy(resource, "fp/", 3);
      cp = resource + 3;
      for (j=i; j < i+n_per_request && j < n_downloadable; ++j) {
        memcpy(cp, smartlist_get(downloadable, j), HEX_DIGEST_LEN);
        cp += HEX_DIGEST_LEN;
        *cp++ = '+';
      }
      memcpy(cp-1, ".z", 3);
      directory_get_from_dirserver(DIR_PURPOSE_FETCH_SERVERDESC,resource,1);
    }
    last_download_attempted = now;
    tor_free(resource);
  }
  SMARTLIST_FOREACH(downloadable, char *, c, tor_free(c));
  smartlist_free(downloadable);
}

/** Return true iff we have enough networkstatus and router information to
 * start building circuits.  Right now, this means "at least 2 networkstatus
 * documents, and at least 1/4 of expected routers." */
int
router_have_minimum_dir_info(void)
{
  int tot = 0, avg;
  if (!networkstatus_list || smartlist_len(networkstatus_list)<2 ||
      !routerlist)
    return 0;
  SMARTLIST_FOREACH(networkstatus_list, networkstatus_t *, ns,
                    tot += smartlist_len(ns->entries));
  avg = tot / smartlist_len(networkstatus_list);
  return smartlist_len(routerlist->routers) > (avg/4);
}

/** Reset the descriptor download failure count on all routers, so that we
 * can retry any long-failed routers immediately.
 */
void
router_reset_descriptor_download_failures(void)
{
  if (!routerstatus_list)
    return;
  SMARTLIST_FOREACH(routerstatus_list, local_routerstatus_t *, rs,
  {
    rs->n_download_failures = 0;
    rs->next_attempt_at = 0;
  });
}

