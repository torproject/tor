/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char routerlist_c_id[] =
  "$Id$";

/**
 * \file routerlist.c
 * \brief Code to
 * maintain and access the global list of routerinfos for known
 * servers.
 **/

#include "or.h"

/****************************************************************************/

/* static function prototypes */
static routerstatus_t *router_pick_directory_server_impl(int requireother,
                                                         int fascistfirewall,
                                                         int for_v2_directory);
static routerstatus_t *router_pick_trusteddirserver_impl(
                 int need_v1_authority, int requireother, int fascistfirewall);
static void mark_all_trusteddirservers_up(void);
static int router_nickname_is_in_list(routerinfo_t *router, const char *list);
static int router_nickname_matches(routerinfo_t *router, const char *nickname);
static void routerstatus_list_update_from_networkstatus(time_t now);
static void local_routerstatus_free(local_routerstatus_t *rs);
static void trusted_dir_server_free(trusted_dir_server_t *ds);
static void update_networkstatus_cache_downloads(time_t now);
static void update_networkstatus_client_downloads(time_t now);
static int signed_desc_digest_is_recognized(signed_descriptor_t *desc);
static void routerlist_assert_ok(routerlist_t *rl);
static int have_tried_downloading_all_statuses(void);
static routerstatus_t *networkstatus_find_entry(networkstatus_t *ns,
                                                const char *digest);

/****************************************************************************/

/** Global list of a trusted_dir_server_t object for each trusted directory
 * server. */
static smartlist_t *trusted_dir_servers = NULL;

/** Global list of all of the routers that we know about. */
static routerlist_t *routerlist = NULL;

/** Global list of all of the current network_status documents that we know
 * about.  This list is kept sorted by published_on. */
static smartlist_t *networkstatus_list = NULL;

/** Global list of local_routerstatus_t for each router, known or unknown. */
static smartlist_t *routerstatus_list = NULL;

/** True iff any member of networkstatus_list has changed since the last time
 * we called routerstatus_list_update_from_networkstatus(). */
static int networkstatus_list_has_changed = 0;

/** True iff any element of routerstatus_list has changed since the last
 * time we called routers_update_all_from_networkstatus().*/
static int routerstatus_list_has_changed = 0;

/** List of strings for nicknames we've already warned about and that are
 * still unknown / unavailable. */
static smartlist_t *warned_nicknames = NULL;

/** List of strings for nicknames or fingerprints we've already warned about
 * and that are still conflicted. */
static smartlist_t *warned_conflicts = NULL;

/** The last time we tried to download any routerdesc, or 0 for "never".  We
 * use this to rate-limit download attempts when the number of routerdescs to
 * download is low. */
static time_t last_routerdesc_download_attempted = 0;

/** The last time we tried to download a networkstatus, or 0 for "never".  We
 * use this to rate-limit download attempts for directory caches (including
 * mirrors).  Clients don't use this now. */
static time_t last_networkstatus_download_attempted = 0;

/** True iff we have logged a warning about this OR not being valid or
 * not being named. */
static int have_warned_about_invalid_status = 0;
/** True iff we have logged a warning about this OR's version being older than
 * listed by the authorities  */
static int have_warned_about_old_version = 0;
/** True iff we have logged a warning about this OR's version being newer than
 * listed by the authorities  */
static int have_warned_about_new_version = 0;

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
        log_info(LD_DIR,
                 "Skipping cached-status file with unexpected name \"%s\"",fn);
        continue;
      }
      tor_snprintf(filename,sizeof(filename),"%s/cached-status/%s",
                   get_options()->DataDirectory, fn);
      s = read_file_to_str(filename, 0);
      if (s) {
        stat(filename, &st);
        if (router_set_networkstatus(s, st.st_mtime, NS_FROM_CACHE, NULL)<0) {
          log_warn(LD_FS, "Couldn't load networkstatus from \"%s\"",filename);
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
/** Total bytes dropped since last rebuild. */
static size_t router_bytes_dropped = 0;

/** Helper: return 1 iff the router log is so big we want to rebuild the
 * store. */
static int
router_should_rebuild_store(void)
{
  if (router_store_len > (1<<16))
    return (router_journal_len > router_store_len / 2 ||
            router_bytes_dropped > router_store_len / 2);
  else
    return router_journal_len > (1<<15);
}

/** Add the <b>len</b>-type router descriptor in <b>s</b> to the router
 * journal. */
static int
router_append_to_journal(signed_descriptor_t *desc)
{
  or_options_t *options = get_options();
  size_t fname_len = strlen(options->DataDirectory)+32;
  char *fname = tor_malloc(fname_len);
  const char *body = signed_descriptor_get_body(desc);
  size_t len = desc->signed_descriptor_len;

  tor_snprintf(fname, fname_len, "%s/cached-routers.new",
               options->DataDirectory);

  tor_assert(len == strlen(body));

  if (append_bytes_to_file(fname, body, len, 0)) {
    log_warn(LD_FS, "Unable to store router descriptor");
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
  int r = -1, i;

  if (!force && !router_should_rebuild_store())
    return 0;
  if (!routerlist)
    return 0;

  /* Don't save deadweight. */
  routerlist_remove_old_routers();

  options = get_options();
  fname_len = strlen(options->DataDirectory)+32;
  fname = tor_malloc(fname_len);
  tor_snprintf(fname, fname_len, "%s/cached-routers", options->DataDirectory);
  chunk_list = smartlist_create();

  for (i = 0; i < 2; ++i) {
    smartlist_t *lst = (i == 0) ? routerlist->old_routers :
                                  routerlist->routers;
    SMARTLIST_FOREACH(lst, void *, ptr,
    {
      signed_descriptor_t *sd = (i==0) ?
        ((signed_descriptor_t*)ptr): &((routerinfo_t*)ptr)->cache_info;
      sized_chunk_t *c;
      const char *body = signed_descriptor_get_body(sd);
      if (!body) {
        log_warn(LD_BUG, "Bug! No descriptor available for router.");
        goto done;
      }
      c = tor_malloc(sizeof(sized_chunk_t));
      c->bytes = body;
      c->len = sd->signed_descriptor_len;
      smartlist_add(chunk_list, c);
    });
  }
  if (write_chunks_to_file(fname, chunk_list, 0)<0) {
    log_warn(LD_FS, "Error writing router store to disk.");
    goto done;
  }

  tor_snprintf(fname, fname_len, "%s/cached-routers.new",
               options->DataDirectory);

  write_str_to_file(fname, "", 0);

  r = 0;
  router_store_len = len;
  router_journal_len = 0;
  router_bytes_dropped = 0;
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

  if (!routerlist)
    router_get_routerlist(); /* mallocs and inits it in place */

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

  if (router_journal_len) {
    /* Always clear the journal on startup.*/
    router_rebuild_store(1);
  } else {
    /* Don't cache expired routers. (This is in an else because
     * router_rebuild_store() also calls remove_old_routers().) */
    routerlist_remove_old_routers();
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
 * Don't pick an authority if any non-authority is viable.
 * Other args are as in router_pick_directory_server_impl().
 */
routerstatus_t *
router_pick_directory_server(int requireother,
                             int fascistfirewall,
                             int for_v2_directory,
                             int retry_if_no_servers)
{
  routerstatus_t *choice;

  if (!routerlist)
    return NULL;

  choice = router_pick_directory_server_impl(requireother, fascistfirewall,
                                             for_v2_directory);
  if (choice || !retry_if_no_servers)
    return choice;

  log_info(LD_DIR,
           "No reachable router entries for dirservers. "
           "Trying them all again.");
  /* mark all authdirservers as up again */
  mark_all_trusteddirservers_up();
  /* try again */
  choice = router_pick_directory_server_impl(requireother, fascistfirewall,
                                             for_v2_directory);
  if (choice)
    return choice;

  log_info(LD_DIR,"Still no %s router entries. Reloading and trying again.",
           fascistfirewall ? "reachable" : "known");
  if (router_reload_router_list()) {
    return NULL;
  }
  /* give it one last try */
  choice = router_pick_directory_server_impl(requireother, fascistfirewall,
                                             for_v2_directory);
  return choice;
}

/** Return the trusted_dir_server_t for the directory authority whose identity
 * key hashes to <b>digest</b>, or NULL if no such authority is known.
 */
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
 * If <b>need_v1_authority</b> is set, return only trusted servers
 * that are authorities for the V1 directory protocol.
 * Other args are as in router_pick_trusteddirserver_impl().
 */
routerstatus_t *
router_pick_trusteddirserver(int need_v1_authority,
                             int requireother,
                             int fascistfirewall,
                             int retry_if_no_servers)
{
  routerstatus_t *choice;

  choice = router_pick_trusteddirserver_impl(need_v1_authority,
                                             requireother, fascistfirewall);
  if (choice || !retry_if_no_servers)
    return choice;

  log_info(LD_DIR,
           "No trusted dirservers are reachable. Trying them all again.");
  mark_all_trusteddirservers_up();
  return router_pick_trusteddirserver_impl(need_v1_authority,
                                           requireother, fascistfirewall);
}

/** Pick a random running valid directory server/mirror from our
 * routerlist.  Don't pick an authority if any non-authorities are viable.
 * If <b>fascistfirewall</b>,
 * make sure the router we pick is allowed by our firewall options.
 * If <b>requireother</b>, it cannot be us.  If <b>for_v2_directory</b>,
 * choose a directory server new enough to support the v2 directory
 * functionality.
 */
static routerstatus_t *
router_pick_directory_server_impl(int requireother, int fascistfirewall,
                                  int for_v2_directory)
{
  routerstatus_t *result;
  smartlist_t *sl;
  smartlist_t *trusted;

  if (!routerstatus_list)
    return NULL;

  /* Find all the running dirservers we know about. */
  sl = smartlist_create();
  trusted = smartlist_create();
  SMARTLIST_FOREACH(routerstatus_list, local_routerstatus_t *, _local_status,
  {
    routerstatus_t *status = &(_local_status->status);
    int is_trusted;
    if (!status->is_running || !status->dir_port || !status->is_valid)
      continue;
    if (requireother && router_digest_is_me(status->identity_digest))
      continue;
    if (fascistfirewall) {
      if (!fascist_firewall_allows_address_dir(status->addr, status->dir_port))
        continue;
    }
    is_trusted = router_digest_is_trusted_dir(status->identity_digest);
    if (for_v2_directory && !(status->is_v2_dir || is_trusted))
      continue;
    smartlist_add(is_trusted ? trusted : sl, status);
  });

  if (smartlist_len(sl))
    result = smartlist_choose(sl);
  else
    result = smartlist_choose(trusted);
  smartlist_free(sl);
  smartlist_free(trusted);
  return result;
}

/** Choose randomly from among the trusted dirservers that are up.  If
 * <b>fascistfirewall</b>, make sure the port we pick is allowed by our
 * firewall options.  If <b>requireother</b>, it cannot be us.  If
 * <b>need_v1_authority</b>, choose a trusted authority for the v1 directory
 * system.
 */
static routerstatus_t *
router_pick_trusteddirserver_impl(int need_v1_authority,
                                  int requireother, int fascistfirewall)
{
  smartlist_t *sl;
  routerinfo_t *me;
  routerstatus_t *rs;
  sl = smartlist_create();
  me = router_get_my_routerinfo();

  if (!trusted_dir_servers)
    return NULL;

  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, d,
    {
      if (!d->is_running) continue;
      if (need_v1_authority && !d->is_v1_authority)
        continue;
      if (requireother && me && router_digest_is_me(d->digest))
          continue;
      if (fascistfirewall) {
        if (!fascist_firewall_allows_address_dir(d->addr, d->dir_port))
          continue;
      }
      smartlist_add(sl, &d->fake_status);
    });

  rs = smartlist_choose(sl);
  smartlist_free(sl);
  return rs;
}

/** Go through and mark the authoritative dirservers as up. */
static void
mark_all_trusteddirservers_up(void)
{
  if (routerlist) {
    SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
       if (router_digest_is_trusted_dir(router->cache_info.identity_digest) &&
         router->dir_port > 0) {
         router->is_running = 1;
       });
  }
  if (trusted_dir_servers) {
    SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, dir,
    {
      local_routerstatus_t *rs;
      dir->is_running = 1;
      dir->n_networkstatus_failures = 0;
      rs = router_get_combined_status_by_digest(dir->digest);
      if (rs)
        rs->status.is_running = 1;
    });
  }
  last_networkstatus_download_attempted = 0;
}

/** Reset all internal variables used to count failed downloads of network
 * status objects. */
void
router_reset_status_download_failures(void)
{
  mark_all_trusteddirservers_up();
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
      add_nickname_list_to_smartlist(sl, cl->value, 0, 1, 1);
    }
  }
}

/** Given a comma-and-whitespace separated list of nicknames, see which
 * nicknames in <b>list</b> name routers in our routerlist that are
 * currently running.  Add the routerinfos for those routers to <b>sl</b>.
 */
void
add_nickname_list_to_smartlist(smartlist_t *sl, const char *list,
                               int must_be_running,
                               int warn_if_down, int warn_if_unnamed)
{
  routerinfo_t *router;
  smartlist_t *nickname_list;
  int have_dir_info = router_have_minimum_dir_info();

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
      log_warn(LD_CONFIG, "Nickname '%s' is misformed; skipping", nick);
      continue;
    }
    router = router_get_by_nickname(nick, warn_if_unnamed);
    warned = smartlist_string_isin(warned_nicknames, nick);
    if (router) {
      if (!must_be_running || router->is_running) {
        smartlist_add(sl,router);
        if (warned)
          smartlist_string_remove(warned_nicknames, nick);
      } else {
        if (!warned) {
          log_fn(warn_if_down ? LOG_WARN : LOG_DEBUG, LD_CONFIG,
                 "Nickname list includes '%s' which is known but down.",nick);
          smartlist_add(warned_nicknames, tor_strdup(nick));
        }
      }
    } else {
      if (!warned) {
        log_fn(have_dir_info ? LOG_WARN : LOG_INFO, LD_CONFIG,
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
 * <b>sl</b>, so that we can pick a node for a circuit.
 */
static void
router_add_running_routers_to_smartlist(smartlist_t *sl, int allow_invalid,
                                        int need_uptime, int need_capacity,
                                        int need_guard)
{
  if (!routerlist)
    return;

  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
  {
    if (router->is_running &&
        router->purpose == ROUTER_PURPOSE_GENERAL &&
        (router->is_valid ||
        (allow_invalid &&
         !router_is_unreliable(router, need_uptime,
                               need_capacity, need_guard)))) {
      /* If it's running, and either it's valid or we're ok picking
       * invalid routers and this one is suitable.
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
        compare_addr_to_addr_policy(addr, port, router->exit_policy) ==
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
router_is_unreliable(routerinfo_t *router, int need_uptime,
                     int need_capacity, int need_guard)
{
  if (need_uptime && !router->is_stable)
    return 1;
  if (need_capacity && !router->is_fast)
    return 1;
  if (need_guard && !router->is_possible_guard)
    return 1;
  return 0;
}

/** Remove from routerlist <b>sl</b> all routers that are not
 * sufficiently stable. */
static void
routerlist_sl_remove_unreliable_routers(smartlist_t *sl, int need_uptime,
                                        int need_capacity, int need_guard)
{
  int i;
  routerinfo_t *router;

  for (i = 0; i < smartlist_len(sl); ++i) {
    router = smartlist_get(sl, i);
    if (router_is_unreliable(router, need_uptime,
                             need_capacity, need_guard)) {
//      log(LOG_DEBUG, "Router '%s' has insufficient uptime; deleting.",
 //         router->nickname);
      smartlist_del(sl, i--);
    }
  }
}

/** Return the smaller of the router's configured BandwidthRate
 * and its advertised capacity. */
uint32_t
router_get_advertised_bandwidth(routerinfo_t *router)
{
  if (router->bandwidthcapacity < router->bandwidthrate)
    return router->bandwidthcapacity;
  return router->bandwidthrate;
}

#define MAX_BELIEVABLE_BANDWIDTH 1500000 /* 1.5 MB/sec */

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
    this_bw = router_get_advertised_bandwidth(router);
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
  rand_bw = crypto_rand_int(total_bw);
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
 * If <b>need_uptime</b> is non-zero and any router has more than
 * a minimum uptime, return one of those.
 * If <b>need_capacity</b> is non-zero, weight your choice by the
 * advertised capacity of each router.
 */
routerinfo_t *
router_choose_random_node(const char *preferred,
                          const char *excluded,
                          smartlist_t *excludedsmartlist,
                          int need_uptime, int need_capacity,
                          int need_guard,
                          int allow_invalid, int strict)
{
  smartlist_t *sl, *excludednodes;
  routerinfo_t *choice = NULL;

  excludednodes = smartlist_create();
  add_nickname_list_to_smartlist(excludednodes,excluded,0,0,1);

  /* Try the preferred nodes first. Ignore need_uptime and need_capacity
   * and need_guard, since the user explicitly asked for these nodes. */
  if (preferred) {
    sl = smartlist_create();
    add_nickname_list_to_smartlist(sl,preferred,1,1,1);
    smartlist_subtract(sl,excludednodes);
    if (excludedsmartlist)
      smartlist_subtract(sl,excludedsmartlist);
    choice = smartlist_choose(sl);
    smartlist_free(sl);
  }
  if (!choice && !strict) {
    /* Then give up on our preferred choices: any node
     * will do that has the required attributes. */
    sl = smartlist_create();
    router_add_running_routers_to_smartlist(sl, allow_invalid,
                                            need_uptime, need_capacity,
                                            need_guard);
    smartlist_subtract(sl,excludednodes);
    if (excludedsmartlist)
      smartlist_subtract(sl,excludedsmartlist);
    routerlist_sl_remove_unreliable_routers(sl, need_uptime,
                                            need_capacity, need_guard);
    if (need_capacity)
      choice = routerlist_sl_choose_by_bandwidth(sl);
    else
      choice = smartlist_choose(sl);
    smartlist_free(sl);
    if (!choice && (need_uptime || need_capacity || need_guard)) {
      /* try once more -- recurse but with fewer restrictions. */
      log_info(LD_CIRC,
               "We couldn't find any live%s%s%s routers; falling back "
               "to list of all routers.",
               need_capacity?", fast":"",
               need_uptime?", stable":"",
               need_guard?", guard":"");
      choice = router_choose_random_node(
        NULL, excluded, excludedsmartlist, 0, 0, 0, allow_invalid, 0);
    }
  }
  smartlist_free(excludednodes);
  if (!choice)
    log_warn(LD_CIRC,
             "No available nodes when trying to choose node. Failing.");
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
  return (!memcmp(digest, router->cache_info.identity_digest, DIGEST_LEN));
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
    if (!strcasecmp(router->nickname, nickname)) {
      if (router->is_named)
        return router;
      else {
        ++n_matches;
        best_match = router;
      }
    } else if (maybedigest &&
               !memcmp(digest, router->cache_info.identity_digest, DIGEST_LEN)
               ) {
      return router;
    }
  });

  if (best_match) {
    if (warn_if_unnamed && n_matches > 1) {
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
          rs = router_get_combined_status_by_digest(
                                          router->cache_info.identity_digest);
          if (!rs->name_lookup_warned) {
            rs->name_lookup_warned = 1;
            any_unwarned = 1;
          }
          base16_encode(fp, sizeof(fp),
                        router->cache_info.identity_digest, DIGEST_LEN);
          dlen = 32 + HEX_DIGEST_LEN + strlen(router->address);
          desc = tor_malloc(dlen);
          tor_snprintf(desc, dlen, "\"$%s\" for the one at %s:%d",
                       fp, router->address, router->or_port);
          smartlist_add(fps, desc);
        });
      if (any_unwarned) {
        char *alternatives = smartlist_join_strings(fps, "; ",0,NULL);
        log_warn(LD_CONFIG,
                 "There are multiple matches for the nickname \"%s\","
                 " but none is listed as named by the directory authories. "
                 "Choosing one arbitrarily.  If you meant one in particular, "
                 "you should say %s.", nickname, alternatives);
        tor_free(alternatives);
      }
      SMARTLIST_FOREACH(fps, char *, cp, tor_free(cp));
      smartlist_free(fps);
    } else if (warn_if_unnamed) {
      local_routerstatus_t *rs = router_get_combined_status_by_digest(
          best_match->cache_info.identity_digest);
      if (rs && !rs->name_lookup_warned) {
        char fp[HEX_DIGEST_LEN+1];
        base16_encode(fp, sizeof(fp),
                      best_match->cache_info.identity_digest, DIGEST_LEN);
        log_warn(LD_CONFIG, "You specified a server \"%s\" by name, but the "
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

/** Try to find a routerinfo for <b>digest</b>. If we don't have one,
 * return 1. If we do, ask tor_version_as_new_as() for the answer.
 */
int
router_digest_version_as_new_as(const char *digest, const char *cutoff)
{
  routerinfo_t *router = router_get_by_digest(digest);
  if (!router)
    return 1;
  return tor_version_as_new_as(router->platform, cutoff);
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

  // routerlist_assert_ok(routerlist);

  return digestmap_get(routerlist->identity_map, digest);
}

/** Return the router in our routerlist whose 20-byte descriptor
 * is <b>digest</b>.  Return NULL if no such router is known. */
signed_descriptor_t *
router_get_by_descriptor_digest(const char *digest)
{
  tor_assert(digest);

  if (!routerlist) return NULL;

  return digestmap_get(routerlist->desc_digest_map, digest);
}

const char *
signed_descriptor_get_body(signed_descriptor_t *desc)
{
  return desc->signed_descriptor_body;
}

/** Return the current list of all known routers. */
routerlist_t *
router_get_routerlist(void)
{
  if (!routerlist) {
    routerlist = tor_malloc_zero(sizeof(routerlist_t));
    routerlist->routers = smartlist_create();
    routerlist->old_routers = smartlist_create();
    routerlist->identity_map = digestmap_new();
    routerlist->desc_digest_map = digestmap_new();
  }
  return routerlist;
}

/** Free all storage held by <b>router</b>. */
void
routerinfo_free(routerinfo_t *router)
{
  if (!router)
    return;

  tor_free(router->cache_info.signed_descriptor_body);
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

/** Release storage held by <b>sd</b>. */
static void
signed_descriptor_free(signed_descriptor_t *sd)
{
  tor_free(sd->signed_descriptor_body);
  tor_free(sd);
}

/** Extract a signed_descriptor_t from a routerinfo, and free the routerinfo.
 */
static signed_descriptor_t *
signed_descriptor_from_routerinfo(routerinfo_t *ri)
{
  signed_descriptor_t *sd = tor_malloc_zero(sizeof(signed_descriptor_t));
  memcpy(sd, &(ri->cache_info), sizeof(signed_descriptor_t));
  ri->cache_info.signed_descriptor_body = NULL;
  routerinfo_free(ri);
  return sd;
}

/** Free all storage held by a routerlist <b>rl</b> */
void
routerlist_free(routerlist_t *rl)
{
  tor_assert(rl);
  digestmap_free(rl->identity_map, NULL);
  digestmap_free(rl->desc_digest_map, NULL);
  SMARTLIST_FOREACH(rl->routers, routerinfo_t *, r,
                    routerinfo_free(r));
  SMARTLIST_FOREACH(rl->old_routers, signed_descriptor_t *, sd,
                    signed_descriptor_free(sd));
  smartlist_free(rl->routers);
  smartlist_free(rl->old_routers);
  tor_free(rl);
}

void
dump_routerlist_mem_usage(int severity)
{
  uint64_t livedescs = 0;
  uint64_t olddescs = 0;
  if (!routerlist)
    return;
  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, r,
                    livedescs += r->cache_info.signed_descriptor_len);
  SMARTLIST_FOREACH(routerlist->old_routers, signed_descriptor_t *, sd,
                    olddescs += sd->signed_descriptor_len);

  log(severity, LD_GENERAL,
      "In %d live descriptors: "U64_FORMAT" bytes.  "
      "In %d old descriptors: "U64_FORMAT" bytes.",
      smartlist_len(routerlist->routers), U64_PRINTF_ARG(livedescs),
      smartlist_len(routerlist->old_routers), U64_PRINTF_ARG(olddescs));
}

/** Return the greatest number of routerdescs we'll hold for any given router.
 */
static int
max_descriptors_per_router(void)
{
  int n_authorities = 0;
  if (trusted_dir_servers)
    n_authorities = smartlist_len(trusted_dir_servers);
  return (n_authorities < 5) ? 5 : n_authorities;
}

/** Return non-zero if we have a lot of extra descriptors in our
 * routerlist, and should get rid of some of them. Else return 0.
 *
 * We should be careful to not return true too eagerly, since we
 * could churn. By using "+1" below, we make sure this function
 * only returns true at most every smartlist_len(rl-\>routers)
 * new descriptors.
 */
static INLINE int
routerlist_is_overfull(routerlist_t *rl)
{
  return smartlist_len(rl->old_routers) >
    smartlist_len(rl->routers)*(max_descriptors_per_router()+1);
}

static INLINE int
_routerlist_find_elt(smartlist_t *sl, void *ri, int idx)
{
  if (idx < 0 || smartlist_get(sl, idx) != ri) {
    idx = -1;
    SMARTLIST_FOREACH(sl, routerinfo_t *, r,
                      if (r == ri) {
                        idx = r_sl_idx;
                        break;
                      });
  }
  return idx;
}

/** Insert an item <b>ri</b> into the routerlist <b>rl</b>, updating indices
 * as needed. */
static void
routerlist_insert(routerlist_t *rl, routerinfo_t *ri)
{
  digestmap_set(rl->identity_map, ri->cache_info.identity_digest, ri);
  digestmap_set(rl->desc_digest_map, ri->cache_info.signed_descriptor_digest,
                &(ri->cache_info));
  smartlist_add(rl->routers, ri);
  // routerlist_assert_ok(rl);
}

static void
routerlist_insert_old(routerlist_t *rl, routerinfo_t *ri)
{
  if (get_options()->DirPort &&
      !digestmap_get(rl->desc_digest_map,
                     ri->cache_info.signed_descriptor_digest)) {
    signed_descriptor_t *sd = signed_descriptor_from_routerinfo(ri);
    digestmap_set(rl->desc_digest_map, sd->signed_descriptor_digest, sd);
    smartlist_add(rl->old_routers, sd);
  } else {
    routerinfo_free(ri);
  }
  // routerlist_assert_ok(rl);
}

/** Remove an item <b>ri</b> from the routerlist <b>rl</b>, updating indices
 * as needed. If <b>idx</b> is nonnegative and smartlist_get(rl-&gt;routers,
 * idx) == ri, we don't need to do a linear search over the list to decide
 * which to remove.  We fill the gap in rl-&gt;routers with a later element in
 * the list, if any exists. <b>ri</b> is freed. */
void
routerlist_remove(routerlist_t *rl, routerinfo_t *ri, int idx, int make_old)
{
  routerinfo_t *ri_tmp;
  idx = _routerlist_find_elt(rl->routers, ri, idx);
  if (idx < 0)
    return;
  smartlist_del(rl->routers, idx);
  ri_tmp = digestmap_remove(rl->identity_map, ri->cache_info.identity_digest);
  tor_assert(ri_tmp == ri);
  if (make_old && get_options()->DirPort) {
    signed_descriptor_t *sd;
    sd = signed_descriptor_from_routerinfo(ri);
    smartlist_add(rl->old_routers, sd);
    digestmap_set(rl->desc_digest_map, sd->signed_descriptor_digest, sd);
  } else {
    ri_tmp = digestmap_remove(rl->desc_digest_map,
                              ri->cache_info.signed_descriptor_digest);
    tor_assert(ri_tmp == ri);
    router_bytes_dropped += ri->cache_info.signed_descriptor_len;
    routerinfo_free(ri);
  }
  // routerlist_assert_ok(rl);
}

static void
routerlist_remove_old(routerlist_t *rl, signed_descriptor_t *sd, int idx)
{
  signed_descriptor_t *sd_tmp;
  idx = _routerlist_find_elt(rl->old_routers, sd, idx);
  if (idx < 0)
    return;
  smartlist_del(rl->old_routers, idx);
  sd_tmp = digestmap_remove(rl->desc_digest_map,
                            sd->signed_descriptor_digest);
  tor_assert(sd_tmp == sd);
  router_bytes_dropped += sd->signed_descriptor_len;
  signed_descriptor_free(sd);
  // routerlist_assert_ok(rl);
}

/** Remove <b>ri_old</b> from the routerlist <b>rl</b>, and replace it with
 * <b>ri_new</b>, updating all index info.  If <b>idx</b> is nonnegative and
 * smartlist_get(rl-&gt;routers, idx) == ri, we don't need to do a linear
 * search over the list to decide which to remove.  We put ri_new in the same
 * index as ri_old, if possible.  ri is freed as appropriate. */
static void
routerlist_replace(routerlist_t *rl, routerinfo_t *ri_old,
                   routerinfo_t *ri_new, int idx, int make_old)
{
  tor_assert(ri_old != ri_new);
  idx = _routerlist_find_elt(rl->routers, ri_old, idx);
  if (idx >= 0) {
    smartlist_set(rl->routers, idx, ri_new);
  } else {
    log_warn(LD_BUG, "Appending entry from routerlist_replace.");
    routerlist_insert(rl, ri_new);
    return;
  }
  if (memcmp(ri_old->cache_info.identity_digest,
             ri_new->cache_info.identity_digest, DIGEST_LEN)) {
    /* digests don't match; digestmap_set won't replace */
    digestmap_remove(rl->identity_map, ri_old->cache_info.identity_digest);
  }
  digestmap_set(rl->identity_map, ri_new->cache_info.identity_digest, ri_new);
  digestmap_set(rl->desc_digest_map,
          ri_new->cache_info.signed_descriptor_digest, &(ri_new->cache_info));

  if (make_old && get_options()->DirPort) {
    signed_descriptor_t *sd = signed_descriptor_from_routerinfo(ri_old);
    smartlist_add(rl->old_routers, sd);
    digestmap_set(rl->desc_digest_map, sd->signed_descriptor_digest, sd);
  } else {
    if (memcmp(ri_old->cache_info.signed_descriptor_digest,
               ri_new->cache_info.signed_descriptor_digest,
               DIGEST_LEN)) {
      /* digests don't match; digestmap_set didn't replace */
      digestmap_remove(rl->desc_digest_map,
                       ri_old->cache_info.signed_descriptor_digest);
    }
    routerinfo_free(ri_old);
  }
  // routerlist_assert_ok(rl);
}

/** Free all memory held by the routerlist module. */
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
  if (warned_conflicts) {
    SMARTLIST_FOREACH(warned_conflicts, char *, cp, tor_free(cp));
    smartlist_free(warned_conflicts);
    warned_conflicts = NULL;
  }
  if (trusted_dir_servers) {
    SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
                      trusted_dir_server_free(ds));
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
    SMARTLIST_FOREACH(ns->entries, routerstatus_t *, rs,
                      routerstatus_free(rs));
    smartlist_free(ns->entries);
  }
  tor_free(ns);
}

/** Forget that we have issued any router-related warnings, so that we'll
 * warn again if we see the same errors. */
void
routerlist_reset_warnings(void)
{
  if (!warned_nicknames)
    warned_nicknames = smartlist_create();
  SMARTLIST_FOREACH(warned_nicknames, char *, cp, tor_free(cp));
  smartlist_clear(warned_nicknames); /* now the list is empty. */

  if (!warned_conflicts)
    warned_conflicts = smartlist_create();
  SMARTLIST_FOREACH(warned_conflicts, char *, cp, tor_free(cp));
  smartlist_clear(warned_conflicts); /* now the list is empty. */

  if (!routerstatus_list)
    routerstatus_list = smartlist_create();
  SMARTLIST_FOREACH(routerstatus_list, local_routerstatus_t *, rs,
                    rs->name_lookup_warned = 0);

  have_warned_about_invalid_status = 0;
  have_warned_about_old_version = 0;
  have_warned_about_new_version = 0;
}

/** Mark the router with ID <b>digest</b> as running or non-running
 * in our routerlist. */
void
router_set_status(const char *digest, int up)
{
  routerinfo_t *router;
  local_routerstatus_t *status;
  tor_assert(digest);

  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, d,
                    if (!memcmp(d->digest, digest, DIGEST_LEN))
                      d->is_running = up);

  router = router_get_by_digest(digest);
  if (router) {
    log_debug(LD_DIR,"Marking router '%s' as %s.",
              router->nickname, up ? "up" : "down");
    if (!up && router_is_me(router) && !we_are_hibernating())
      log_warn(LD_NET, "We just marked ourself as down. Are your external "
               "addresses reachable?");
    router->is_running = up;
  }
  status = router_get_combined_status_by_digest(digest);
  if (status) {
    status->status.is_running = up;
  }
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
 * If <b>from_cache</b>, this descriptor came from our disk cache. If
 * <b>from_fetch</b>, we received it in response to a request we made.
 * (If both are false, that means it was uploaded to us as an auth dir
 * server or via the controller.)
 *
 * This function should be called *after*
 * routers_update_status_from_networkstatus; subsequently, you should call
 * router_rebuild_store and control_event_descriptors_changed.
 *
 * XXXX never replace your own descriptor.
 */
int
router_add_to_routerlist(routerinfo_t *router, const char **msg,
                         int from_cache, int from_fetch)
{
  int i;
  const char *id_digest;
  int authdir = get_options()->AuthoritativeDir;
  int authdir_believes_valid = 0;

  tor_assert(msg);

  if (!routerlist)
    router_get_routerlist();
  if (!networkstatus_list)
    networkstatus_list = smartlist_create();

  id_digest = router->cache_info.identity_digest;

  /* Make sure that we haven't already got this exact descriptor. */
  if (digestmap_get(routerlist->desc_digest_map,
                    router->cache_info.signed_descriptor_digest)) {
    log_info(LD_DIR,
             "Dropping descriptor that we already have for router '%s'",
             router->nickname);
    *msg = "Router descriptor was not new.";
    routerinfo_free(router);
    return -1;
  }

  if (routerlist_is_overfull(routerlist))
    routerlist_remove_old_routers();

  if (authdir) {
    if (authdir_wants_to_reject_router(router, msg,
                                       !from_cache && !from_fetch)) {
      tor_assert(*msg);
      routerinfo_free(router);
      return -2;
    }
    authdir_believes_valid = router->is_valid;
  } else if (from_fetch) {
    /* Only check the descriptor digest against the network statuses when
     * we are receiving in response to a fetch. */
    if (!signed_desc_digest_is_recognized(&router->cache_info)) {
      log_warn(LD_DIR, "Dropping unrecognized descriptor for router '%s'",
               router->nickname);
      *msg = "Router descriptor is not referenced by any network-status.";
      routerinfo_free(router);
      return -1;
    }
  }

  /* We no longer need a router with this descriptor digest. */
  SMARTLIST_FOREACH(networkstatus_list, networkstatus_t *, ns,
  {
    routerstatus_t *rs =
      networkstatus_find_entry(ns, router->cache_info.identity_digest);
    if (rs && !memcmp(rs->descriptor_digest,
                      router->cache_info.signed_descriptor_digest,
                      DIGEST_LEN))
      rs->need_to_mirror = 0;
  });

  /* If we have a router with this name, and the identity key is the same,
   * choose the newer one. If the identity key has changed, and one of the
   * routers is named, drop the unnamed ones. (If more than one are named,
   * drop the old ones.)
   */
  for (i = 0; i < smartlist_len(routerlist->routers); ++i) {
    routerinfo_t *old_router = smartlist_get(routerlist->routers, i);
    if (!crypto_pk_cmp_keys(router->identity_pkey,old_router->identity_pkey)) {
      if (router->cache_info.published_on <=
          old_router->cache_info.published_on) {
        /* Same key, but old */
        log_debug(LD_DIR, "Skipping not-new descriptor for router '%s'",
                  router->nickname);
        /* Only journal this desc if we'll be serving it. */
        if (!from_cache && get_options()->DirPort)
          router_append_to_journal(&router->cache_info);
        routerlist_insert_old(routerlist, router);
        *msg = "Router descriptor was not new.";
        return -1;
      } else {
        /* Same key, new. */
        int unreachable = 0;
        log_debug(LD_DIR, "Replacing entry for router '%s/%s' [%s]",
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
        if (authdir && !from_cache && !from_fetch &&
            router_have_minimum_dir_info() &&
            dirserv_thinks_router_is_blatantly_unreachable(router,
                                                           time(NULL))) {
          if (router->num_unreachable_notifications >= 3) {
            unreachable = 1;
            log_notice(LD_DIR, "Notifying server '%s' that it's unreachable. "
                       "(ContactInfo '%s', platform '%s').",
                       router->nickname,
                       router->contact_info ? router->contact_info : "",
                       router->platform ? router->platform : "");
          } else {
            log_info(LD_DIR,"'%s' may be unreachable -- the %d previous "
                     "descriptors were thought to be unreachable.",
                     router->nickname, router->num_unreachable_notifications);
            router->num_unreachable_notifications++;
          }
        }
        routerlist_replace(routerlist, old_router, router, i, 1);
        if (!from_cache) {
          router_append_to_journal(&router->cache_info);
        }
        directory_set_dirty();
        *msg = unreachable ? "Dirserver believes your ORPort is unreachable" :
               authdir_believes_valid ? "Valid server updated" :
                ("Invalid server updated. (This dirserver is marking your "
                 "server as unapproved.)");
        return unreachable ? 1 : 0;
      }
    } else if (!strcasecmp(router->nickname, old_router->nickname)) {
      /* nicknames match, keys don't. */
      if (router->is_named) {
        /* The new named router replaces the old one; remove the
         * old one.  And carry on to the end of the list, in case
         * there are more old unnamed routers with this nickname.
         */
        /* mark-for-close connections using the old key, so we can
         * make new ones with the new key.
         */
        connection_t *conn;
        while ((conn = connection_or_get_by_identity_digest(
                      old_router->cache_info.identity_digest))) {
          log_info(LD_DIR,"Closing conn to router '%s'; there is now a named "
                   "router with that name.",
                   old_router->nickname);
          connection_mark_for_close(conn);
        }
        routerlist_remove(routerlist, old_router, i--, 0);
      } else if (old_router->is_named) {
        /* Can't replace a named router with an unnamed one. */
        log_debug(LD_DIR, "Skipping unnamed entry for named router '%s'",
                  router->nickname);
        routerinfo_free(router);
        *msg =
          "Already have named router with same nickname and different key.";
        return -2;
      }
    }
  }
  /* We haven't seen a router with this name before.  Add it to the end of
   * the list. */
  routerlist_insert(routerlist, router);
  if (!from_cache)
    router_append_to_journal(&router->cache_info);
  directory_set_dirty();
  return 0;
}

static int
_compare_old_routers_by_identity(const void **_a, const void **_b)
{
  int i;
  const signed_descriptor_t *r1 = *_a, *r2 = *_b;
  if ((i = memcmp(r1->identity_digest, r2->identity_digest, DIGEST_LEN)))
    return i;
  return r1->published_on - r2->published_on;
}

struct duration_idx_t {
  int duration;
  int idx;
  int old;
};

static int
_compare_duration_idx(const void *_d1, const void *_d2)
{
  const struct duration_idx_t *d1 = _d1;
  const struct duration_idx_t *d2 = _d2;
  return d1->duration - d2->duration;
}

/** The range <b>lo</b> through <b>hi</b> inclusive of routerlist->old_routers
 * must contain routerinfo_t with the same identity and with publication time
 * in ascending order.  Remove members from this range until there are no more
 * than max_descriptors_per_router() remaining.  Start by removing the oldest
 * members from before <b>cutoff</b>, then remove members which were current
 * for the lowest amount of time.  The order of members of old_routers at
 * indices <b>lo</b> or higher may be changed.
 */
static void
routerlist_remove_old_cached_routers_with_id(time_t cutoff, int lo, int hi,
                                             digestmap_t *retain)
{
  int i, n = hi-lo+1, n_extra;
  int n_rmv = 0;
  struct duration_idx_t *lifespans;
  uint8_t *rmv, *must_keep;
  smartlist_t *lst = routerlist->old_routers;
#if 1
  const char *ident;
  tor_assert(hi < smartlist_len(lst));
  tor_assert(lo <= hi);
  ident = ((signed_descriptor_t*)smartlist_get(lst, lo))->identity_digest;
  for (i = lo+1; i <= hi; ++i) {
    signed_descriptor_t *r = smartlist_get(lst, i);
    tor_assert(!memcmp(ident, r->identity_digest, DIGEST_LEN));
  }
#endif

  /* Check whether we need to do anything at all. */
  n_extra = n - max_descriptors_per_router();
  if (n_extra <= 0)
    return;

  lifespans = tor_malloc_zero(sizeof(struct duration_idx_t)*n);
  rmv = tor_malloc_zero(sizeof(uint8_t)*n);
  must_keep = tor_malloc_zero(sizeof(uint8_t)*n);
  /* Set lifespans to contain the lifespan and index of each server. */
  /* Set rmv[i-lo]=1 if we're going to remove a server for being too old. */
  for (i = lo; i <= hi; ++i) {
    signed_descriptor_t *r = smartlist_get(lst, i);
    signed_descriptor_t *r_next;
    lifespans[i-lo].idx = i;
    if (retain && digestmap_get(retain, r->signed_descriptor_digest)) {
      must_keep[i-lo] = 1;
    }
    if (i < hi) {
      r_next = smartlist_get(lst, i+1);
      tor_assert(r->published_on <= r_next->published_on);
      lifespans[i-lo].duration = (r_next->published_on - r->published_on);
    } else {
      r_next = NULL;
      lifespans[i-lo].duration = INT_MAX;
    }
    if (!must_keep[i-lo] && r->published_on < cutoff && n_rmv < n_extra) {
      ++n_rmv;
      lifespans[i-lo].old = 1;
      rmv[i-lo] = 1;
    }
  }

  if (n_rmv < n_extra) {
    /**
     * We aren't removing enough servers for being old.  Sort lifespans by
     * the duration of liveness, and remove the ones we're not already going to
     * remove based on how long they were alive.
     **/
    qsort(lifespans, n, sizeof(struct duration_idx_t), _compare_duration_idx);
    for (i = 0; i < n && n_rmv < n_extra; ++i) {
      if (!must_keep[lifespans[i].idx-lo] && !lifespans[i].old) {
        rmv[lifespans[i].idx-lo] = 1;
        ++n_rmv;
      }
    }
  }

  for (i = hi; i >= lo; --i) {
    if (rmv[i-lo])
      routerlist_remove_old(routerlist, smartlist_get(lst, i), i);
  }
  tor_free(must_keep);
  tor_free(rmv);
  tor_free(lifespans);
}

/** Deactivate any routers from the routerlist that are more than
 * ROUTER_MAX_AGE seconds old; remove old routers from the list of
 * cached routers if we have too many.
 */
void
routerlist_remove_old_routers(void)
{
  int i, hi=-1;
  const char *cur_id = NULL;
  time_t now = time(NULL);
  time_t cutoff;
  routerinfo_t *router;
  signed_descriptor_t *sd;
  digestmap_t *retain;
  or_options_t *options = get_options();
  if (!routerlist || !networkstatus_list)
    return;

  retain = digestmap_new();
  cutoff = now - OLD_ROUTER_DESC_MAX_AGE;
  if (server_mode(options) && options->DirPort) {
    SMARTLIST_FOREACH(networkstatus_list, networkstatus_t *, ns,
      {
        SMARTLIST_FOREACH(ns->entries, routerstatus_t *, rs,
          if (rs->published_on >= cutoff)
            digestmap_set(retain, rs->descriptor_digest, (void*)1));
      });
  }

  cutoff = now - ROUTER_MAX_AGE;
  /* Remove too-old members of routerlist->routers. */
  for (i = 0; i < smartlist_len(routerlist->routers); ++i) {
    router = smartlist_get(routerlist->routers, i);
    if (router->cache_info.published_on <= cutoff &&
        !digestmap_get(retain, router->cache_info.signed_descriptor_digest)) {
      /* Too old.  Remove it. */
      log_info(LD_DIR,
               "Forgetting obsolete (too old) routerinfo for router '%s'",
               router->nickname);
      routerlist_remove(routerlist, router, i--, 1);
    }
  }

  /* Remove far-too-old members of routerlist->old_routers. */
  cutoff = now - OLD_ROUTER_DESC_MAX_AGE;
  for (i = 0; i < smartlist_len(routerlist->old_routers); ++i) {
    sd = smartlist_get(routerlist->old_routers, i);
    if (sd->published_on <= cutoff &&
        !digestmap_get(retain, sd->signed_descriptor_digest)) {
      /* Too old.  Remove it. */
      routerlist_remove_old(routerlist, sd, i--);
    }
  }

  /* Now we're looking at routerlist->old_routers for extraneous
   * members. (We'd keep all the members if we could, but we'd like to save
   * space.) First, check whether we have too many router descriptors, total.
   * We're okay with having too many for some given router, so long as the
   * total number doesn't approach max_descriptors_per_router()*len(router).
   */
  if (smartlist_len(routerlist->old_routers) <
      smartlist_len(routerlist->routers) * (max_descriptors_per_router() - 1))
    goto done;

  smartlist_sort(routerlist->old_routers, _compare_old_routers_by_identity);

  /* Iterate through the list from back to front, so when we remove descriptors
   * we don't mess up groups we haven't gotten to. */
  for (i = smartlist_len(routerlist->old_routers)-1; i >= 0; --i) {
    signed_descriptor_t *r = smartlist_get(routerlist->old_routers, i);
    if (!cur_id) {
      cur_id = r->identity_digest;
      hi = i;
    }
    if (memcmp(cur_id, r->identity_digest, DIGEST_LEN)) {
      routerlist_remove_old_cached_routers_with_id(cutoff, i+1, hi, retain);
      cur_id = r->identity_digest;
      hi = i;
    }
  }
  if (hi>=0)
    routerlist_remove_old_cached_routers_with_id(cutoff, 0, hi, retain);
  routerlist_assert_ok(routerlist);

 done:
  digestmap_free(retain, NULL);
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
router_load_single_router(const char *s, uint8_t purpose, const char **msg)
{
  routerinfo_t *ri;
  int r;
  smartlist_t *lst;
  tor_assert(msg);
  *msg = NULL;

  if (!(ri = router_parse_entry_from_string(s, NULL))) {
    log_warn(LD_DIR, "Error parsing router descriptor; dropping.");
    *msg = "Couldn't parse router descriptor.";
    return -1;
  }
  ri->purpose = purpose;
  if (router_is_me(ri)) {
    log_warn(LD_DIR, "Router's identity key matches mine; dropping.");
    *msg = "Router's identity key matches mine.";
    routerinfo_free(ri);
    return 0;
  }

  lst = smartlist_create();
  smartlist_add(lst, ri);
  routers_update_status_from_networkstatus(lst, 0);

  if ((r=router_add_to_routerlist(ri, msg, 0, 0))<0) {
    /* we've already assigned to *msg now, and ri is already freed */
    tor_assert(*msg);
    if (r < -1)
      log_warn(LD_DIR, "Couldn't add router to list: %s Dropping.", *msg);
    smartlist_free(lst);
    return 0;
  } else {
    control_event_descriptors_changed(lst);
    smartlist_free(lst);
    log_debug(LD_DIR, "Added router to list");
    return 1;
  }
}

/** Given a string <b>s</b> containing some routerdescs, parse it and put the
 * routers into our directory.  If <b>from_cache</b> is false, the routers
 * are in response to a query to the network: cache them.
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

  log_info(LD_DIR, "%d elements to add", smartlist_len(routers));

  SMARTLIST_FOREACH(routers, routerinfo_t *, ri,
  {
    base16_encode(fp, sizeof(fp), ri->cache_info.signed_descriptor_digest,
                  DIGEST_LEN);
    if (requested_fingerprints) {
      if (smartlist_string_isin(requested_fingerprints, fp)) {
        smartlist_string_remove(requested_fingerprints, fp);
      } else {
        char *requested =
          smartlist_join_strings(requested_fingerprints," ",0,NULL);
        log_warn(LD_DIR,
                 "We received a router descriptor with a fingerprint (%s) "
                 "that we never requested. (We asked for: %s.) Dropping.",
                 fp, requested);
        tor_free(requested);
        routerinfo_free(ri);
        continue;
      }
    }

    if (router_add_to_routerlist(ri, &msg, from_cache, !from_cache) >= 0)
      smartlist_add(changed, ri);
  });

  if (smartlist_len(changed))
    control_event_descriptors_changed(changed);

  routerlist_assert_ok(routerlist);
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

/** Add the parsed neworkstatus in <b>ns</b> (with original document in
 * <b>s</b> to the disk cache (and the in-memory directory server cache) as
 * appropriate. */
static int
add_networkstatus_to_cache(const char *s,
                           networkstatus_source_t source,
                           networkstatus_t *ns)
{
  if (source != NS_FROM_CACHE) {
    char *fn = networkstatus_get_cache_filename(ns);
    if (write_str_to_file(fn, s, 0)<0) {
      log_notice(LD_FS, "Couldn't write cached network status to \"%s\"", fn);
    }
    tor_free(fn);
  }

  if (get_options()->DirPort)
    dirserv_set_cached_networkstatus_v2(s,
                                        ns->identity_digest,
                                        ns->published_on);

  return 0;
}

/** How far in the future do we allow a network-status to get before removing
 * it? (seconds) */
#define NETWORKSTATUS_ALLOW_SKEW (24*60*60)
/** Given a string <b>s</b> containing a network status that we received at
 * <b>arrived_at</b> from <b>source</b>, try to parse it, see if we want to
 * store it, and put it into our cache as necessary.
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
  trusted_dir_server_t *trusted_dir = NULL;
  const char *source_desc = NULL;
  char fp[HEX_DIGEST_LEN+1];
  char published[ISO_TIME_LEN+1];

  ns = networkstatus_parse_from_string(s);
  if (!ns) {
    log_warn(LD_DIR, "Couldn't parse network status.");
    return -1;
  }
  base16_encode(fp, HEX_DIGEST_LEN+1, ns->identity_digest, DIGEST_LEN);
  if (!(trusted_dir =
        router_get_trusteddirserver_by_digest(ns->identity_digest))) {
    log_info(LD_DIR, "Network status was signed, but not by an authoritative "
             "directory we recognize.");
    if (!get_options()->DirPort) {
      networkstatus_free(ns);
      return 0;
    }
    source_desc = fp;
  } else {
    source_desc = trusted_dir->description;
  }
  now = time(NULL);
  if (arrived_at > now)
    arrived_at = now;

  ns->received_on = arrived_at;

  format_iso_time(published, ns->published_on);

  if (ns->published_on > now + NETWORKSTATUS_ALLOW_SKEW) {
    log_warn(LD_GENERAL, "Network status from %s was published in the future "
             "(%s GMT). Somebody is skewed here: check your clock. "
             "Not caching.",
             source_desc, published);
    skewed = 1;
  }

  if (!networkstatus_list)
    networkstatus_list = smartlist_create();

  if (source == NS_FROM_DIR && router_digest_is_me(ns->identity_digest)) {
    /* Don't replace our own networkstatus when we get it from somebody else.*/
    networkstatus_free(ns);
    return 0;
  }

  if (requested_fingerprints) {
    if (smartlist_string_isin(requested_fingerprints, fp)) {
      smartlist_string_remove(requested_fingerprints, fp);
    } else {
      char *requested =
        smartlist_join_strings(requested_fingerprints," ",0,NULL);
      log_warn(LD_DIR,
               "We received a network status with a fingerprint (%s) that we "
               "never requested. (We asked for: %s.) Dropping.",
               fp, requested);
      tor_free(requested);
      return 0;
    }
  }

  if (!trusted_dir) {
    if (!skewed && get_options()->DirPort) {
      /* We got a non-trusted networkstatus, and we're a directory cache.
       * This means that we asked an authority, and it told us about another
       * authority we didn't recognize. */
      add_networkstatus_to_cache(s, source, ns);
      networkstatus_free(ns);
    }
    return 0;
  }

  if (source != NS_FROM_CACHE && trusted_dir)
    trusted_dir->n_networkstatus_failures = 0;

  found = 0;
  for (i=0; i < smartlist_len(networkstatus_list); ++i) {
    networkstatus_t *old_ns = smartlist_get(networkstatus_list, i);

    if (!memcmp(old_ns->identity_digest, ns->identity_digest, DIGEST_LEN)) {
      if (!memcmp(old_ns->networkstatus_digest,
                  ns->networkstatus_digest, DIGEST_LEN)) {
        /* Same one we had before. */
        networkstatus_free(ns);
        log_info(LD_DIR,
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
        log_info(LD_DIR,
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

  SMARTLIST_FOREACH(ns->entries, routerstatus_t *, rs,
    {
      if (!router_get_by_descriptor_digest(rs->descriptor_digest))
        rs->need_to_mirror = 1;
    });

  log_info(LD_DIR, "Setting networkstatus %s %s (published %s)",
           source == NS_FROM_CACHE?"cached from":
           (source==NS_FROM_DIR?"downloaded from":"generated for"),
           trusted_dir->description, published);
  networkstatus_list_has_changed = 1;

  smartlist_sort(networkstatus_list, _compare_networkstatus_published_on);

  if (!skewed)
    add_networkstatus_to_cache(s, source, ns);

  networkstatus_list_update_recent(now);

  return 0;
}

/** How old do we allow a network-status to get before removing it
 * completely? */
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
      log_info(LD_DIR, "Removing too-old networkstatus in %s", fname);
      unlink(fname);
    }
    tor_free(fname);
    if (get_options()->DirPort) {
      dirserv_set_cached_networkstatus_v2(NULL, ns->identity_digest, 0);
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

/** Return true iff any networkstatus includes a descriptor whose digest
 * is that of <b>desc</b>. */
static int
signed_desc_digest_is_recognized(signed_descriptor_t *desc)
{
  routerstatus_t *rs;
  if (!networkstatus_list)
    return 0;

  SMARTLIST_FOREACH(networkstatus_list, networkstatus_t *, ns,
  {
    if (!(rs = networkstatus_find_entry(ns, desc->identity_digest)))
      continue;
    if (!memcmp(rs->descriptor_digest,
                desc->signed_descriptor_digest, DIGEST_LEN))
      return 1;
  });
  return 0;
}

/** How frequently do directory authorities re-download fresh networkstatus
 * documents? */
#define AUTHORITY_NS_CACHE_INTERVAL (5*60)

/** How frequently do non-authority directory caches re-download fresh
 * networkstatus documents? */
#define NONAUTHORITY_NS_CACHE_INTERVAL (15*60)

/** We are a directory server, and so cache network_status documents.
 * Initiate downloads as needed to update them.  For authorities, this means
 * asking each trusted directory for its network-status.  For caches, this
 * means asking a random authority for all network-statuses.
 */
static void
update_networkstatus_cache_downloads(time_t now)
{
  int authority = authdir_mode(get_options());
  int interval =
    authority ? AUTHORITY_NS_CACHE_INTERVAL : NONAUTHORITY_NS_CACHE_INTERVAL;

  if (last_networkstatus_download_attempted + interval >= now)
    return;
  if (!trusted_dir_servers)
    return;

  last_networkstatus_download_attempted = now;

  if (authority) {
    /* An authority launches a separate connection for everybody. */
    SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
       {
         char resource[HEX_DIGEST_LEN+6]; /* fp/hexdigit.z\0 */
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
         directory_initiate_command_routerstatus(
               &ds->fake_status, DIR_PURPOSE_FETCH_NETWORKSTATUS,
               0, /* Not private */
               resource,
               NULL, 0 /* No payload. */);
       });
  } else {
    /* A non-authority cache launches one connection to a random authority. */
    /* (Check whether we're currently fetching network-status objects.) */
    if (!connection_get_by_type_purpose(CONN_TYPE_DIR,
                                        DIR_PURPOSE_FETCH_NETWORKSTATUS))
      directory_get_from_dirserver(DIR_PURPOSE_FETCH_NETWORKSTATUS,"all.z",1);
  }
}

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
static void
update_networkstatus_client_downloads(time_t now)
{
  int n_live = 0, n_dirservers, n_running_dirservers, needed = 0;
  int fetch_latest = 0;
  int most_recent_idx = -1;
  trusted_dir_server_t *most_recent = NULL;
  time_t most_recent_received = 0;
  char *resource, *cp;
  size_t resource_len;
  smartlist_t *missing;

  if (connection_get_by_type_purpose(CONN_TYPE_DIR,
                                     DIR_PURPOSE_FETCH_NETWORKSTATUS))
    return;

  /* This is a little tricky.  We want to download enough network-status
   * objects so that we have all of them under
   * NETWORKSTATUS_MAX_AGE publication time.  We want to download a new
   * *one* if the most recent one's publication time is under
   * NETWORKSTATUS_CLIENT_DL_INTERVAL.
   */
  if (!trusted_dir_servers || !smartlist_len(trusted_dir_servers))
    return;
  n_dirservers = n_running_dirservers = smartlist_len(trusted_dir_servers);
  missing = smartlist_create();
  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
     {
       networkstatus_t *ns = networkstatus_get_by_digest(ds->digest);
       if (ds->n_networkstatus_failures > NETWORKSTATUS_N_ALLOWABLE_FAILURES) {
         --n_running_dirservers;
         continue;
       }
       if (ns && ns->published_on > now-NETWORKSTATUS_MAX_AGE)
         ++n_live;
       else
         smartlist_add(missing, ds->digest);
       if (ns && (!most_recent || ns->received_on > most_recent_received)) {
         most_recent_idx = ds_sl_idx; /* magic variable from FOREACH */
         most_recent = ds;
         most_recent_received = ns->received_on;
       }
     });

  /* Also, download at least 1 every NETWORKSTATUS_CLIENT_DL_INTERVAL. */
  if (!smartlist_len(missing) &&
      most_recent_received < now-NETWORKSTATUS_CLIENT_DL_INTERVAL) {
    log_info(LD_DIR, "Our most recent network-status document (from %s) "
             "is %d seconds old; downloading another.",
             most_recent?most_recent->description:"nobody",
             (int)(now-most_recent_received));
    fetch_latest = 1;
    needed = 1;
  } else if (smartlist_len(missing)) {
    log_info(LD_DIR, "For %d/%d running directory servers, we have %d live"
             " network-status documents. Downloading %d.",
             n_running_dirservers, n_dirservers, n_live,
             smartlist_len(missing));
    needed = smartlist_len(missing);
  } else {
    smartlist_free(missing);
    return;
  }

  /* If no networkstatus was found, choose a dirserver at random as "most
   * recent". */
  if (most_recent_idx<0)
    most_recent_idx = crypto_rand_int(n_dirservers);

  if (fetch_latest) {
    int i;
    for (i = most_recent_idx + 1; i; ++i) {
      trusted_dir_server_t *ds;
      if (i >= n_dirservers)
        i = 0;
      ds = smartlist_get(trusted_dir_servers, i);
      if (ds->n_networkstatus_failures > NETWORKSTATUS_N_ALLOWABLE_FAILURES)
        continue;
      smartlist_add(missing, ds->digest);
      break;
    }
  }

  /* Build a request string for all the resources we want. */
  resource_len = smartlist_len(missing) * (HEX_DIGEST_LEN+1) + 6;
  resource = tor_malloc(resource_len);
  memcpy(resource, "fp/", 3);
  cp = resource+3;
  needed = smartlist_len(missing);
  SMARTLIST_FOREACH(missing, const char *, d,
    {
      base16_encode(cp, HEX_DIGEST_LEN+1, d, DIGEST_LEN);
      cp += HEX_DIGEST_LEN;
      --needed;
      if (needed)
        *cp++ = '+';
    });
  memcpy(cp, ".z", 3);
  directory_get_from_dirserver(DIR_PURPOSE_FETCH_NETWORKSTATUS, resource, 1);
  tor_free(resource);
  smartlist_free(missing);
}

/** Launch requests for networkstatus documents as appropriate. */
void
update_networkstatus_downloads(time_t now)
{
  or_options_t *options = get_options();
  if (server_mode(options) && options->DirPort)
      update_networkstatus_cache_downloads(time(NULL));
    else
      update_networkstatus_client_downloads(time(NULL));
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
        !router_is_unreliable(router, need_uptime, 0, 0)) {
      r = compare_addr_to_addr_policy(addr, port, router->exit_policy);
      if (r != ADDR_POLICY_REJECTED && r != ADDR_POLICY_PROBABLY_REJECTED)
        return 0; /* this one could be ok. good enough. */
    }
  });
  return 1; /* all will reject. */
}

/** Return true iff <b>router</b> does not permit exit streams.
 */
int
router_exit_policy_rejects_all(routerinfo_t *router)
{
  return compare_addr_to_addr_policy(0, 0, router->exit_policy)
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
      log_warn(LD_CONFIG,
               "Couldn't find a suitable address when adding ourself as a "
               "trusted directory server.");
      return;
    }
  } else {
    if (tor_lookup_hostname(address, &a)) {
      log_warn(LD_CONFIG,
               "Unable to lookup address for directory server at '%s'",
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
  ent->is_v1_authority = supports_v1;
  memcpy(ent->digest, digest, DIGEST_LEN);

  dlen = 64 + strlen(hostname) + (nickname?strlen(nickname):0);
  ent->description = tor_malloc(dlen);
  if (nickname)
    tor_snprintf(ent->description, dlen, "directory server \"%s\" at %s:%d",
                 nickname, hostname, (int)port);
  else
    tor_snprintf(ent->description, dlen, "directory server at %s:%d",
                 hostname, (int)port);

  ent->fake_status.addr = ent->addr;
  memcpy(ent->fake_status.identity_digest, digest, DIGEST_LEN);
  if (nickname)
    strlcpy(ent->fake_status.nickname, nickname,
            sizeof(ent->fake_status.nickname));
  else
    ent->fake_status.nickname[0] = '\0';
  ent->fake_status.dir_port = ent->dir_port;

  smartlist_add(trusted_dir_servers, ent);
}

/** Free storage held in <b>ds</b> */
void
trusted_dir_server_free(trusted_dir_server_t *ds)
{
  tor_free(ds->nickname);
  tor_free(ds->description);
  tor_free(ds->address);
  tor_free(ds);
}

/** Remove all members from the list of trusted dir servers. */
void
clear_trusted_dir_servers(void)
{
  if (trusted_dir_servers) {
    SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ent,
                      trusted_dir_server_free(ent));
    smartlist_clear(trusted_dir_servers);
  } else {
    trusted_dir_servers = smartlist_create();
  }
}

/** Return 1 if any trusted dir server supports v1 directories,
 * else return 0. */
int
any_trusted_dir_supports_v1(void)
{
  if (trusted_dir_servers)
    SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ent,
                      if (ent->is_v1_authority) return 1);
  return 0;
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

/** We believe networkstatuses more recent than this when they tell us that
 * our server is broken, invalid, obsolete, etc. */
#define SELF_OPINION_INTERVAL (90*60)

/** Return a string naming the versions of Tor recommended by
 * at least n_needed versioning networkstatuses */
static char *
compute_recommended_versions(time_t now, int client)
{
  int n_seen;
  char *current;
  smartlist_t *combined, *recommended;
  int n_recent;
  char *result;

  if (!networkstatus_list)
    return tor_strdup("<none>");

  combined = smartlist_create();
  n_recent = 0;
  SMARTLIST_FOREACH(networkstatus_list, networkstatus_t *, ns,
    {
      const char *vers;
      if (! ns->recommends_versions)
        continue;
      if (ns->received_on + SELF_OPINION_INTERVAL < now)
        continue;
      n_recent++;
      vers = client ? ns->client_versions : ns->server_versions;
      if (!vers)
        continue;
      /* XXX Attack: a single dirserver can make a version recommended
       * by repeating it many times in his recommended list. -RD */
      smartlist_split_string(combined, vers, ",",
                             SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    });

  sort_version_list(combined);

  current = NULL;
  n_seen = 0;
  recommended = smartlist_create();
  SMARTLIST_FOREACH(combined, char *, cp,
    {
      if (current && !strcmp(cp, current)) {
        ++n_seen;
      } else {
        if (n_seen >= n_recent/2 && current)
          smartlist_add(recommended, current);
        n_seen = 0;
        current = cp;
      }
    });
  if (n_seen >= n_recent/2 && current)
    smartlist_add(recommended, current);

  result = smartlist_join_strings(recommended, ", ", 0, NULL);

  SMARTLIST_FOREACH(combined, char *, cp, tor_free(cp));
  smartlist_free(combined);
  smartlist_free(recommended);

  return result;
}

/** If the network-status list has changed since the last time we called this
 * function, update the status of every routerinfo from the network-status
 * list.
 */
void
routers_update_all_from_networkstatus(void)
{
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
  if (me && !have_warned_about_invalid_status) {
    int n_recent = 0, n_listing = 0, n_valid = 0, n_named = 0, n_naming = 0;
    routerstatus_t *rs;
    SMARTLIST_FOREACH(networkstatus_list, networkstatus_t *, ns,
    {
      if (ns->received_on + SELF_OPINION_INTERVAL < now)
        continue;
      ++n_recent;
      if (ns->binds_names)
        ++n_naming;
      if (!(rs = networkstatus_find_entry(ns, me->cache_info.identity_digest)))
        continue;
      ++n_listing;
      if (rs->is_valid)
        ++n_valid;
      if (rs->is_named)
        ++n_named;
    });

    if (n_recent >= 2 && n_listing >= 2 &&
        have_tried_downloading_all_statuses()) {
      if (n_valid <= n_recent/2)  {
        log_warn(LD_GENERAL,
                 "%d/%d recent statements from directory authorities list us "
                 "as unapproved. Are you misconfigured?",
                 n_recent-n_valid, n_recent);
        have_warned_about_invalid_status = 1;
      } else if (n_naming && !n_named) {
        log_warn(LD_GENERAL, "0/%d name-binding directory authorities "
                 "recognize your nickname. Please consider sending your "
                 "nickname and identity fingerprint to the tor-ops.",
                 n_naming);
        have_warned_about_invalid_status = 1;
      }
    }
  }

  entry_guards_set_status_from_directory();

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
/* XXX Should this be n_recommended <= n_recent/2 ? -RD */
      if (consensus == VS_NEW || consensus == VS_NEW_IN_SERIES) {
        if (!have_warned_about_new_version) {
          char *rec = compute_recommended_versions(now, !is_server);
          log_notice(LD_GENERAL, "This version of Tor (%s) is newer than any "
                 "recommended version%s, according to %d/%d recent network "
                 "statuses.  Versions recommended by at least %d recent "
                 "authorit%s are: %s",
                 VERSION,
                 consensus == VS_NEW_IN_SERIES ? " in its series" : "",
                 n_recent-n_recommended, n_recent, n_recent/2,
                 n_recent/2 > 1 ? "ies" : "y", rec);
          have_warned_about_new_version = 1;
          tor_free(rec);
        }
      } else {
        char *rec = compute_recommended_versions(now, !is_server);
        log_warn(LD_GENERAL, "Please upgrade! "
                 "This version of Tor (%s) is %s, according to "
                 "%d/%d recent network statuses.  Versions recommended by "
                 "at least %d recent authorit%s are: %s",
                 VERSION, consensus == VS_OLD ? "obsolete" : "not recommended",
                 n_recent-n_recommended, n_recent, n_recent/2,
                 n_recent/2 > 1 ? "ies" : "y", rec);
        have_warned_about_old_version = 1;
        tor_free(rec);
      }
    } else {
      log_info(LD_GENERAL, "%d/%d recently downloaded statements from "
               "directory authorities say my version is ok.",
               n_recommended, n_recent);
    }
  }

  routerstatus_list_has_changed = 0;
}

/** Allow any network-status newer than this to influence our view of who's
 * running. */
#define DEFAULT_RUNNING_INTERVAL (60*60)
/** If possible, always allow at least this many network-statuses to influence
 * our view of who's running. */
#define MIN_TO_INFLUENCE_RUNNING 3

/** Change the is_recent field of each member of networkstatus_list so that
 * all members more recent than DEFAULT_RUNNING_INTERVAL are recent, and
 * at least the MIN_TO_INFLUENCE_RUNNING most recent members are recent, and no
 * others are recent.  Set networkstatus_list_has_changed if anything happened.
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
        log_info(LD_DIR,
                 "Networkstatus from %s (published %s) is now \"recent\"",
                 src, published);
        changed = 1;
      }
      ns->is_recent = 1;
      ++n_recent;
    } else {
      if (ns->is_recent) {
        format_iso_time(published, ns->published_on);
        log_info(LD_DIR,
                 "Networkstatus from %s (published %s) is "
                 "no longer \"recent\"",
                 src, published);
        changed = 1;
        ns->is_recent = 0;
      }
    }
  }
  if (changed)
    networkstatus_list_has_changed = 1;
}

/** Helper for routerstatus_list_update_from_networkstatus: remember how many
 * authorities recommend a given descriptor digest. */
typedef struct {
  routerstatus_t *rs;
  int count;
} desc_digest_count_t;

/** Update our view of router status (as stored in routerstatus_list) from the
 * current set of network status documents (as stored in networkstatus_list).
 * Do nothing unless the network status list has changed since the last time
 * this function was called.
 */
static void
routerstatus_list_update_from_networkstatus(time_t now)
{
  or_options_t *options = get_options();
  int n_trusted, n_statuses, n_recent = 0, n_naming = 0;
  int i, j, warned;
  int *index, *size;
  networkstatus_t **networkstatus;
  smartlist_t *result;
  strmap_t *name_map;
  char conflict[DIGEST_LEN]; /* Sentinel value */
  desc_digest_count_t *digest_counts = NULL;

  /* compute which network statuses will have a vote now */
  networkstatus_list_update_recent(now);

  if (!networkstatus_list_has_changed)
    return;
  if (!networkstatus_list)
    networkstatus_list = smartlist_create();
  if (!routerstatus_list)
    routerstatus_list = smartlist_create();
  if (!trusted_dir_servers)
    trusted_dir_servers = smartlist_create();
  if (!warned_conflicts)
    warned_conflicts = smartlist_create();

  n_trusted = smartlist_len(trusted_dir_servers);
  n_statuses = smartlist_len(networkstatus_list);

  if (n_statuses < (n_trusted/2)+1) {
    /* Not enough statuses to adjust status. */
    log_notice(LD_DIR,
               "Not enough statuses to update router status list. (%d/%d)",
               n_statuses, n_trusted);
    return;
  }

  log_info(LD_DIR, "Rebuilding router status list.");

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

  /** Iterate over all entries in all networkstatuses, and build
   * name_map as a map from lc nickname to identity digest.  If there
   * is a conflict on that nickname, map the lc nickname to conflict.
   */
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
      warned = smartlist_string_isin(warned_conflicts, rs->nickname);
      if (!other_digest) {
        strmap_set_lc(name_map, rs->nickname, rs->identity_digest);
        if (warned)
          smartlist_string_remove(warned_conflicts, rs->nickname);
      } else if (memcmp(other_digest, rs->identity_digest, DIGEST_LEN) &&
                 other_digest != conflict) {
        if (!warned) {
          int should_warn = options->DirPort && options->AuthoritativeDir;
          char fp1[HEX_DIGEST_LEN+1];
          char fp2[HEX_DIGEST_LEN+1];
          base16_encode(fp1, sizeof(fp1), other_digest, DIGEST_LEN);
          base16_encode(fp2, sizeof(fp2), rs->identity_digest, DIGEST_LEN);
          log_fn(should_warn ? LOG_WARN : LOG_INFO, LD_DIR,
                 "Naming authorities disagree about which key goes with %s. "
                 "($%s vs $%s)",
                 rs->nickname, fp1, fp2);
          strmap_set_lc(name_map, rs->nickname, conflict);
          smartlist_add(warned_conflicts, tor_strdup(rs->nickname));
        }
      } else {
        if (warned)
          smartlist_string_remove(warned_conflicts, rs->nickname);
      }
    });
  }

  result = smartlist_create();
  digest_counts = tor_malloc_zero(sizeof(desc_digest_count_t)*n_statuses);

  /* Iterate through all of the sorted routerstatus lists in lockstep.
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
    int n_v2_dir=0, n_fast=0, n_stable=0, n_exit=0, n_guard=0;
    int n_desc_digests=0, highest_count=0;
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
    for (i = 0; i < n_statuses; ++i) {
      if (index[i] >= size[i])
        continue;
      ns = networkstatus[i];
      rs = smartlist_get(ns->entries, index[i]);
      if (memcmp(rs->identity_digest, lowest, DIGEST_LEN))
        continue;
      /* At this point, we know that we're looking at a routersatus with
       * identity "lowest".
       */
      ++index[i];
      ++n_listing;
      /* Should we name this router? Only if all the names from naming
       * authorities match. */
      if (rs->is_named && ns->binds_names) {
        if (!the_name)
          the_name = rs->nickname;
        if (!strcasecmp(rs->nickname, the_name)) {
          ++n_named;
        } else if (strcmp(the_name,"**mismatch**")) {
          char hd[HEX_DIGEST_LEN+1];
          base16_encode(hd, HEX_DIGEST_LEN+1, rs->identity_digest, DIGEST_LEN);
          if (! smartlist_string_isin(warned_conflicts, hd)) {
            log_warn(LD_DIR,
                     "Naming authorities disagree about nicknames for $%s "
                     "(\"%s\" vs \"%s\")",
                     hd, the_name, rs->nickname);
            smartlist_add(warned_conflicts, tor_strdup(hd));
          }
          the_name = "**mismatch**";
        }
      }
      /* Keep a running count of how often which descriptor digests
       * appear. */
      for (j = 0; j < n_desc_digests; ++j) {
        if (!memcmp(rs->descriptor_digest,
                    digest_counts[j].rs->descriptor_digest, DIGEST_LEN)) {
          if (++digest_counts[j].count > highest_count)
            highest_count = digest_counts[j].count;
          goto found;
        }
      }
      digest_counts[n_desc_digests].rs = rs;
      digest_counts[n_desc_digests].count = 1;
      if (!highest_count)
        highest_count = 1;
      ++n_desc_digests;
    found:
      /* Now tally up the easily-tallied flags. */
      if (rs->is_valid)
        ++n_valid;
      if (rs->is_running && ns->is_recent)
        ++n_running;
      if (rs->is_exit)
        ++n_exit;
      if (rs->is_fast)
        ++n_fast;
      if (rs->is_possible_guard)
        ++n_guard;
      if (rs->is_stable)
        ++n_stable;
      if (rs->is_v2_dir)
        ++n_v2_dir;
    }
    /* Go over the descriptor digests and figure out which descriptor we
     * want. */
    most_recent = NULL;
    for (i = 0; i < n_desc_digests; ++i) {
      /* If any digest appears twice or more, ignore those that don't.*/
      if (highest_count >= 2 && digest_counts[i].count < 2)
        continue;
      if (!most_recent ||
          digest_counts[i].rs->published_on > most_recent->published_on)
        most_recent = digest_counts[i].rs;
    }
    rs_out = tor_malloc_zero(sizeof(local_routerstatus_t));
    memcpy(&rs_out->status, most_recent, sizeof(routerstatus_t));
    /* Copy status info about this router, if we had any before. */
    if ((rs_old = router_get_combined_status_by_digest(lowest))) {
      if (!memcmp(rs_out->status.descriptor_digest,
                  most_recent->descriptor_digest, DIGEST_LEN)) {
        rs_out->n_download_failures = rs_old->n_download_failures;
        rs_out->next_attempt_at = rs_old->next_attempt_at;
      }
      rs_out->name_lookup_warned = rs_old->name_lookup_warned;
    }
    smartlist_add(result, rs_out);
    log_debug(LD_DIR, "Router '%s' is listed by %d/%d directories, "
              "named by %d/%d, validated by %d/%d, and %d/%d recent "
              "directories think it's running.",
              rs_out->status.nickname,
              n_listing, n_statuses, n_named, n_naming, n_valid, n_statuses,
              n_running, n_recent);
    rs_out->status.is_named  = 0;
    if (the_name && strcmp(the_name, "**mismatch**") && n_named > 0) {
      const char *d = strmap_get_lc(name_map, the_name);
      if (d && d != conflict)
        rs_out->status.is_named = 1;
      if (smartlist_string_isin(warned_conflicts, rs_out->status.nickname))
        smartlist_string_remove(warned_conflicts, rs_out->status.nickname);
    }
    if (rs_out->status.is_named)
      strlcpy(rs_out->status.nickname, the_name,
              sizeof(rs_out->status.nickname));
    rs_out->status.is_valid = n_valid > n_statuses/2;
    rs_out->status.is_running = n_running > n_recent/2;
    rs_out->status.is_exit = n_exit > n_statuses/2;
    rs_out->status.is_fast = n_fast > n_statuses/2;
    rs_out->status.is_possible_guard = n_guard > n_statuses/2;
    rs_out->status.is_stable = n_stable > n_statuses/2;
    rs_out->status.is_v2_dir = n_v2_dir > n_statuses/2;
  }
  SMARTLIST_FOREACH(routerstatus_list, local_routerstatus_t *, rs,
                    local_routerstatus_free(rs));
  smartlist_free(routerstatus_list);
  routerstatus_list = result;

  tor_free(networkstatus);
  tor_free(index);
  tor_free(size);
  tor_free(digest_counts);
  strmap_free(name_map, NULL);

  networkstatus_list_has_changed = 0;
  routerstatus_list_has_changed = 1;
}

/** Given a list <b>routers</b> of routerinfo_t *, update each routers's
 * is_named, is_valid, and is_running fields according to our current
 * networkstatus_t documents. */
void
routers_update_status_from_networkstatus(smartlist_t *routers,
                                         int reset_failures)
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
    const char *digest = router->cache_info.identity_digest;
    rs = router_get_combined_status_by_digest(digest);
    ds = router_get_trusteddirserver_by_digest(digest);

    if (!rs)
      continue;

    if (!namingdir)
      router->is_named = rs->status.is_named;

    if (!authdir) {
      /* If we're not an authdir, believe others. */
      router->is_valid = rs->status.is_valid;
      router->is_running = rs->status.is_running;
      router->is_fast = rs->status.is_fast;
      router->is_stable = rs->status.is_stable;
      router->is_possible_guard = rs->status.is_possible_guard;
    }
    if (router->is_running && ds) {
      ds->n_networkstatus_failures = 0;
    }
    if (reset_failures) {
      rs->n_download_failures = 0;
      rs->next_attempt_at = 0;
    }
  });
}

/** For every router descriptor we are currently downloading by descriptor
 * digest, set result[d] to 1. */
static void
list_pending_descriptor_downloads(digestmap_t *result)
{
  const char *prefix = "d/";
  size_t p_len = strlen(prefix);
  int i, n_conns;
  connection_t **carray;
  smartlist_t *tmp = smartlist_create();

  tor_assert(result);
  get_connection_array(&carray, &n_conns);

  for (i = 0; i < n_conns; ++i) {
    connection_t *conn = carray[i];
    if (conn->type == CONN_TYPE_DIR &&
        conn->purpose == DIR_PURPOSE_FETCH_SERVERDESC &&
        !conn->marked_for_close) {
      if (!strcmpstart(conn->requested_resource, prefix))
        dir_split_resource_into_fingerprints(conn->requested_resource+p_len,
                                             tmp, NULL, 1);
    }
  }
  SMARTLIST_FOREACH(tmp, char *, d,
                    {
                      digestmap_set(result, d, (void*)1);
                      tor_free(d);
                    });
  smartlist_free(tmp);
}

/** Launch downloads for all the descriptors whose digests are listed
 * as digests[i] for lo <= i < hi.  (Lo and hi may be out of range.)
 * If <b>source</b> is given, download from <b>source</b>; otherwise,
 * download from an appropriate random directory server.
 */
static void
initiate_descriptor_downloads(routerstatus_t *source,
                              smartlist_t *digests,
                              int lo, int hi)
{
  int i, n = hi-lo;
  char *resource, *cp;
  size_t r_len;
  if (n <= 0)
    return;
  if (lo < 0)
    lo = 0;
  if (hi > smartlist_len(digests))
    hi = smartlist_len(digests);

  r_len = 8 + (HEX_DIGEST_LEN+1)*n;
  cp = resource = tor_malloc(r_len);
  memcpy(cp, "d/", 2);
  cp += 2;
  for (i = lo; i < hi; ++i) {
    base16_encode(cp, r_len-(cp-resource),
                  smartlist_get(digests,i), DIGEST_LEN);
    cp += HEX_DIGEST_LEN;
    *cp++ = '+';
  }
  memcpy(cp-1, ".z", 3);

  if (source) {
    /* We know which authority we want. */
    directory_initiate_command_routerstatus(source,
                                            DIR_PURPOSE_FETCH_SERVERDESC,
                                            0, /* not private */
                                            resource, NULL, 0);
  } else {
    directory_get_from_dirserver(DIR_PURPOSE_FETCH_SERVERDESC,
                                 resource,
                                 1);
  }
  tor_free(resource);
}

/** Clients don't download any descriptor this recent, since it will probably
 * not have propageted to enough caches. */
#define ESTIMATED_PROPAGATION_TIME (10*60)

/** Return new list of ID fingerprints for routers that we (as a client) would
 * like to download.
 */
static smartlist_t *
router_list_client_downloadable(void)
{
  int n_downloadable = 0;
  smartlist_t *downloadable = smartlist_create();
  digestmap_t *downloading;
  time_t now = time(NULL);
  /* these are just used for logging */
  int n_not_ready = 0, n_in_progress = 0, n_uptodate = 0,
    n_obsolete = 0, n_too_young = 0, n_wouldnt_use = 0;

  if (!routerstatus_list)
    return downloadable;

  downloading = digestmap_new();
  list_pending_descriptor_downloads(downloading);

  routerstatus_list_update_from_networkstatus(now);
  SMARTLIST_FOREACH(routerstatus_list, local_routerstatus_t *, rs,
  {
    routerinfo_t *ri;
    if (rs->status.published_on + ROUTER_MAX_AGE < now) {
      /* This one is too old to consider. */
      ++n_obsolete;
    } else if (digestmap_get(downloading, rs->status.descriptor_digest)) {
      /* We're downloading this one now. */
      ++n_in_progress;
    } else if (!rs->status.is_running) {
      /* If we had this router descriptor, we wouldn't even bother using it. */
      ++n_wouldnt_use;
    } else if (router_get_by_descriptor_digest(rs->status.descriptor_digest)) {
      /* We have the 'best' descriptor for this router. */
      ++n_uptodate;
    } else if ((ri = router_get_by_digest(rs->status.identity_digest)) &&
               ri->cache_info.published_on > rs->status.published_on) {
      /* Oddly, we have a descriptor more recent than the 'best' one, but it
         was once best. So that's okay. */
      ++n_uptodate;
    } else if (rs->status.published_on + ESTIMATED_PROPAGATION_TIME > now) {
      /* Most caches probably don't have this descriptor yet. */
      ++n_too_young;
    } else if (rs->next_attempt_at > now) {
      /* We failed too recently to try again. */
      ++n_not_ready;
    } else {
      /* Okay, time to try it. */
      smartlist_add(downloadable, rs->status.descriptor_digest);
      ++n_downloadable;
    }
  });

#if 0
  log_info(LD_DIR,
       "%d router descriptors are downloadable. %d are too old to consider. "
       "%d are in progress. %d are up-to-date. %d are too young to consider. "
       "%d are non-useful. %d failed too recently to retry.",
       n_downloadable, n_obsolete, n_in_progress, n_uptodate, n_too_young,
       n_wouldnt_use, n_not_ready);
#endif

  digestmap_free(downloading, NULL);
  return downloadable;
}

/** Initiate new router downloads as needed, using the strategy for
 * non-directory-servers.
 *
 * We only allow one router descriptor download at a time.
 * If we have less than two network-status documents, we ask
 * a directory for "all descriptors."
 * Otherwise, we ask for all descriptors that we think are different
 * from what we have.
 */
static void
update_router_descriptor_client_downloads(time_t now)
{
  /* Max amount of hashes to download per request.
   * Since squid does not like URLs >= 4096 bytes we limit it to 96.
   *   4096 - strlen(http://255.255.255.255/tor/server/d/.z) == 4058
   *   4058/41 (40 for the hash and 1 for the + that separates them) => 98
   *   So use 96 because it's a nice number.
   */
#define MAX_DL_PER_REQUEST 96
  /** Don't split our requests so finely that we are requesting fewer than
   * this number per server. */
#define MIN_DL_PER_REQUEST 4
  /** To prevent a single screwy cache from confusing us by selective reply,
   * try to split our requests into at least this this many requests. */
#define MIN_REQUESTS 3
  /** If we want fewer than this many descriptors, wait until we
   * want more, or until MAX_(CLIENT|SERVER)_INTERVAL_WITHOUT_REQUEST has
   * passed. */
#define MAX_DL_TO_DELAY 16
  /** When directory clients have only a few servers to request, they batch
   * them until they have more, or until this amount of time has passed. */
#define MAX_CLIENT_INTERVAL_WITHOUT_REQUEST (10*60)
  smartlist_t *downloadable = NULL;
  int should_delay, n_downloadable;
  or_options_t *options = get_options();

  if (server_mode(options) && options->DirPort) {
    log_warn(LD_BUG,
             "Called router_descriptor_client_downloads() on a mirror?");
  }

  /* XXX here's another magic 2 that probably should be replaced
   * by <= smartlist_len(trusted_dir_servers)/2
   * or by a function returning same.  -- weasel */
  if (networkstatus_list && smartlist_len(networkstatus_list) < 2) {
    log_info(LD_DIR,
             "Not enough networkstatus documents to launch requests.");
  }

  downloadable = router_list_client_downloadable();
  n_downloadable = smartlist_len(downloadable);
  if (n_downloadable >= MAX_DL_TO_DELAY) {
    log_debug(LD_DIR,
              "There are enough downloadable routerdescs to launch requests.");
    should_delay = 0;
  } else if (n_downloadable == 0) {
//    log_debug(LD_DIR, "No routerdescs need to be downloaded.");
    should_delay = 1;
  } else {
    should_delay = (last_routerdesc_download_attempted +
                    MAX_CLIENT_INTERVAL_WITHOUT_REQUEST) > now;
    if (!should_delay) {
      if (last_routerdesc_download_attempted) {
        log_info(LD_DIR,
           "There are not many downloadable routerdescs, but we've "
           "been waiting long enough (%d seconds). Downloading.",
           (int)(now-last_routerdesc_download_attempted));
      } else {
        log_info(LD_DIR,
           "There are not many downloadable routerdescs, but we've "
           "never downloaded descriptors before.  Downloading.");
      }
    }
  }

  if (! should_delay) {
    int i, n_per_request;
    n_per_request = (n_downloadable+MIN_REQUESTS-1) / MIN_REQUESTS;
    if (n_per_request > MAX_DL_PER_REQUEST)
      n_per_request = MAX_DL_PER_REQUEST;
    if (n_per_request < MIN_DL_PER_REQUEST)
      n_per_request = MIN_DL_PER_REQUEST;

    log_info(LD_DIR,
             "Launching %d request%s for %d router%s, %d at a time",
             (n_downloadable+n_per_request-1)/n_per_request,
             n_downloadable>n_per_request?"s":"",
             n_downloadable, n_downloadable>1?"s":"", n_per_request);
    for (i=0; i < n_downloadable; i += n_per_request) {
      initiate_descriptor_downloads(NULL, downloadable, i, i+n_per_request);
    }
    last_routerdesc_download_attempted = now;
  }
  smartlist_free(downloadable);
}

/** Launch downloads for router status as needed, using the strategy used by
 * authorities and caches: download every descriptor we don't have but would
 * serve from a random authoritiy that lists it. */
static void
update_router_descriptor_cache_downloads(time_t now)
{
  smartlist_t **downloadable; /* For each authority, what can we dl from it? */
  smartlist_t **download_from; /*          ... and, what will we dl from it? */
  digestmap_t *map; /* Which descs are in progress, or assigned? */
  int i, j, n;
  int n_download;
  or_options_t *options = get_options();

  if (!(server_mode(options) && options->DirPort)) {
    log_warn(LD_BUG, "Called update_router_descriptor_cache_downloads() "
             "on a non-mirror?");
  }

  if (!networkstatus_list || !smartlist_len(networkstatus_list))
    return;

  map = digestmap_new();
  n = smartlist_len(networkstatus_list);

  downloadable = tor_malloc_zero(sizeof(smartlist_t*) * n);
  download_from = tor_malloc_zero(sizeof(smartlist_t*) * n);

  /* Set map[d]=1 for the digest of every descriptor that we are currently
   * downloading. */
  list_pending_descriptor_downloads(map);

  /* For the digest of every descriptor that we don't have, and that we aren't
   * downloading, add d to downloadable[i] if the i'th networkstatus knows
   * about that descriptor, and we haven't already failed to get that
   * descriptor from the corresponding authority.
   */
  n_download = 0;
  SMARTLIST_FOREACH(networkstatus_list, networkstatus_t *, ns,
    {
      smartlist_t *dl = smartlist_create();
      downloadable[ns_sl_idx] = dl;
      download_from[ns_sl_idx] = smartlist_create();
      SMARTLIST_FOREACH(ns->entries, routerstatus_t * , rs,
        {
          if (!rs->need_to_mirror)
            continue;
          if (router_get_by_descriptor_digest(rs->descriptor_digest)) {
            log_warn(LD_BUG,
                     "We have a router descriptor, but need_to_mirror=1.");
            rs->need_to_mirror = 0;
            continue;
          }
          if (options->AuthoritativeDir && dirserv_would_reject_router(rs)) {
            rs->need_to_mirror = 0;
            continue;
          }
          if (digestmap_get(map, rs->descriptor_digest)) {
            /* We're downloading it already. */
            continue;
          } else {
            /* We could download it from this guy. */
            smartlist_add(dl, rs->descriptor_digest);
            ++n_download;
          }
        });
    });

  /* At random, assign descriptors to authorities such that:
   * - if d is a member of some downloadable[x], d is a member of some
   *   download_from[y].  (Everything we want to download, we try to download
   *   from somebody.)
   * - If d is a member of download_from[y], d is a member of downloadable[y].
   *   (We only try to download descriptors from authorities who claim to have
   *   them.)
   * - No d is a member of download_from[x] and download_from[y] s.t. x != y.
   *   (We don't try to download anything from two authorities concurrently.)
   */
  while (n_download) {
    int which_ns = crypto_rand_int(n);
    smartlist_t *dl = downloadable[which_ns];
    int idx;
    char *d;
    tor_assert(dl);
    if (!smartlist_len(dl))
      continue;
    idx = crypto_rand_int(smartlist_len(dl));
    d = smartlist_get(dl, idx);
    if (! digestmap_get(map, d)) {
      smartlist_add(download_from[which_ns], d);
      digestmap_set(map, d, (void*) 1);
    }
    smartlist_del(dl, idx);
    --n_download;
  }

  /* Now, we can actually launch our requests. */
  for (i=0; i<n; ++i) {
    networkstatus_t *ns = smartlist_get(networkstatus_list, i);
    trusted_dir_server_t *ds =
      router_get_trusteddirserver_by_digest(ns->identity_digest);
    smartlist_t *dl = download_from[i];
    if (!ds) {
      log_warn(LD_BUG, "Networkstatus with no corresponding authority!");
      continue;
    }
    if (! smartlist_len(dl))
      continue;
    log_info(LD_DIR, "Requesting %d descriptors from authority \"%s\"",
             smartlist_len(dl), ds->nickname);
    for (j=0; j < smartlist_len(dl); j += MAX_DL_PER_REQUEST) {
      initiate_descriptor_downloads(&(ds->fake_status), dl, j,
                                    j+MAX_DL_PER_REQUEST);
    }
  }

  for (i=0; i<n; ++i) {
    smartlist_free(download_from[i]);
    smartlist_free(downloadable[i]);
  }
  tor_free(download_from);
  tor_free(downloadable);
  digestmap_free(map,NULL);
}

/** Launch downloads for router status as needed. */
void
update_router_descriptor_downloads(time_t now)
{
  or_options_t *options = get_options();
  if (server_mode(options) && options->DirPort) {
    update_router_descriptor_cache_downloads(now);
  } else {
    update_router_descriptor_client_downloads(now);
  }
}

/** Return true iff we have enough networkstatus and router information to
 * start building circuits.  Right now, this means "more than half the
 * networkstatus documents, and at least 1/4 of expected routers." */
//XXX should consider whether we have enough exiting nodes here.
int
router_have_minimum_dir_info(void)
{
  int tot = 0, num_running = 0;
  int n_ns, n_tried, n_authorities, res, avg;
  static int have_ever_tried_all = 0;
  static int have_enough = 0;
  if (!networkstatus_list || !routerlist) {
    res = 0;
    goto done;
  }
  n_authorities = smartlist_len(trusted_dir_servers);
  n_ns = smartlist_len(networkstatus_list);
  if (n_ns<=n_authorities/2) {
    log_info(LD_DIR,
             "We have %d of %d network statuses, and we want "
             "more than %d.", n_ns, n_authorities, n_authorities/2);
    res = 0;
    goto done;
  }
  if (!have_ever_tried_all) {
    n_tried=n_ns;
    SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
                      if (ds->n_networkstatus_failures) ++n_tried);
    if (n_tried < n_authorities) {
      log_info(LD_DIR,
               "We have only tried downloading %d/%d network statuses.",
               n_tried, n_authorities);
      res = 0;
      goto done;
    } else {
      have_ever_tried_all = 1;
    }
  }
  SMARTLIST_FOREACH(networkstatus_list, networkstatus_t *, ns,
                    tot += smartlist_len(ns->entries));
  avg = tot / n_ns;
  SMARTLIST_FOREACH(routerstatus_list, local_routerstatus_t *, rs,
     {
       if (rs->status.is_running)
         num_running++;
     });
  res = smartlist_len(routerlist->routers) >= (avg/4) && num_running > 2;
 done:
  if (res && !have_enough) {
    log(LOG_NOTICE, LD_DIR,
        "We now have enough directory information to build circuits.");
  }
  if (!res && have_enough) {
    log(LOG_NOTICE, LD_DIR,"Our directory information is no longer up-to-date "
        "enough to build circuits.%s",
        num_running > 2 ? "" : " (Not enough servers seem reachable -- "
        "is your network connection down?)");
  }
  have_enough = res;
  return res;
}

/** Return true iff we have downloaded, or attempted to download, a network
 * status for each authority. */
static int
have_tried_downloading_all_statuses(void)
{
  if (!trusted_dir_servers)
    return 0;

  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
    {
      /* If we don't have the status, and we haven't failed to get the status,
       * we haven't tried to get the status. */
      if (!networkstatus_get_by_digest(ds->digest) &&
          !ds->n_networkstatus_failures)
        return 0;
    });

  return 1;
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
  tor_assert(networkstatus_list);
  SMARTLIST_FOREACH(networkstatus_list, networkstatus_t *, ns,
     SMARTLIST_FOREACH(ns->entries, routerstatus_t *, rs,
       {
         if (!router_get_by_descriptor_digest(rs->descriptor_digest))
           rs->need_to_mirror = 1;
       }));
  last_routerdesc_download_attempted = 0;
}

/** Any changes in a router descriptor's publication time larger than this are
 * automatically non-cosmetic. */
#define ROUTER_MAX_COSMETIC_TIME_DIFFERENCE (12*60*60)

/** Return true iff the only differences between r1 and r2 are such that
 * would not cause a recent (post 0.1.1.6) dirserver to republish.
 */
int
router_differences_are_cosmetic(routerinfo_t *r1, routerinfo_t *r2)
{
  time_t r1pub, r2pub;
  tor_assert(r1 && r2);

  /* r1 should be the one that was published first. */
  if (r1->cache_info.published_on > r2->cache_info.published_on) {
    routerinfo_t *ri_tmp = r2;
    r2 = r1;
    r1 = ri_tmp;
  }

  /* If any key fields differ, they're different. */
  if (strcasecmp(r1->address, r2->address) ||
      strcasecmp(r1->nickname, r2->nickname) ||
      r1->or_port != r2->or_port ||
      r1->dir_port != r2->dir_port ||
      crypto_pk_cmp_keys(r1->onion_pkey, r2->onion_pkey) ||
      crypto_pk_cmp_keys(r1->identity_pkey, r2->identity_pkey) ||
      strcasecmp(r1->platform, r2->platform) ||
      (r1->contact_info && !r2->contact_info) || /* contact_info is optional */
      (!r1->contact_info && r2->contact_info) ||
      (r1->contact_info && r2->contact_info &&
       strcasecmp(r1->contact_info, r2->contact_info)) ||
      r1->is_hibernating != r2->is_hibernating ||
      cmp_addr_policies(r1->exit_policy, r2->exit_policy))
    return 0;
  if ((r1->declared_family == NULL) != (r2->declared_family == NULL))
    return 0;
  if (r1->declared_family && r2->declared_family) {
    int i, n;
    if (smartlist_len(r1->declared_family)!=smartlist_len(r2->declared_family))
      return 0;
    n = smartlist_len(r1->declared_family);
    for (i=0; i < n; ++i) {
      if (strcasecmp(smartlist_get(r1->declared_family, i),
                     smartlist_get(r2->declared_family, i)))
        return 0;
    }
  }

  /* Did bandwidth change a lot? */
  if ((r1->bandwidthcapacity < r2->bandwidthcapacity/2) ||
      (r2->bandwidthcapacity < r1->bandwidthcapacity/2))
    return 0;

  /* Did more than 12 hours pass? */
  if (r1->cache_info.published_on + ROUTER_MAX_COSMETIC_TIME_DIFFERENCE
      < r2->cache_info.published_on)
    return 0;

  /* Did uptime fail to increase by approximately the amount we would think,
   * give or take 30 minutes? */
  r1pub = r1->cache_info.published_on;
  r2pub = r2->cache_info.published_on;
  if (abs(r2->uptime - (r1->uptime + (r2pub - r1pub))))
    return 0;

  /* Otherwise, the difference is cosmetic. */
  return 1;
}

static void
routerlist_assert_ok(routerlist_t *rl)
{
  digestmap_iter_t *iter;
  routerinfo_t *r2;
  signed_descriptor_t *sd2;
  if (!routerlist)
    return;
  SMARTLIST_FOREACH(rl->routers, routerinfo_t *, r,
  {
    r2 = digestmap_get(rl->identity_map, r->cache_info.identity_digest);
    tor_assert(r == r2);
    sd2 = digestmap_get(rl->desc_digest_map,
                        r->cache_info.signed_descriptor_digest);
    tor_assert(&(r->cache_info) == sd2);
  });
  SMARTLIST_FOREACH(rl->old_routers, signed_descriptor_t *, sd,
  {
    r2 = digestmap_get(rl->identity_map, sd->identity_digest);
    tor_assert(sd != &(r2->cache_info));
    sd2 = digestmap_get(rl->desc_digest_map, sd->signed_descriptor_digest);
    tor_assert(sd == sd2);
  });
  iter = digestmap_iter_init(rl->identity_map);
  while (!digestmap_iter_done(iter)) {
    const char *d;
    void *_r;
    routerinfo_t *r;
    digestmap_iter_get(iter, &d, &_r);
    r = _r;
    tor_assert(!memcmp(r->cache_info.identity_digest, d, DIGEST_LEN));
    iter = digestmap_iter_next(rl->identity_map, iter);
  }
  iter = digestmap_iter_init(rl->desc_digest_map);
  while (!digestmap_iter_done(iter)) {
    const char *d;
    void *_sd;
    signed_descriptor_t *sd;
    digestmap_iter_get(iter, &d, &_sd);
    sd = _sd;
    tor_assert(!memcmp(sd->signed_descriptor_digest, d, DIGEST_LEN));
    iter = digestmap_iter_next(rl->desc_digest_map, iter);
  }
}

/** Allocate and return a new string representing the contact info
 * and platform string for <b>router</b>,
 * surrounded by quotes and using standard C escapes.
 *
 * THIS FUNCTION IS NOT REENTRANT.  Don't call it from outside the main
 * thread.  Also, each call invalidates the last-returned value, so don't
 * try log_warn(LD_GENERAL, "%s %s", esc_router_info(a), esc_router_info(b));
 */
const char *
esc_router_info(routerinfo_t *router)
{
  static char *info;
  char *esc_contact, *esc_platform;
  size_t len;
  if (info)
    tor_free(info);

  esc_contact = esc_for_log(router->contact_info);
  esc_platform = esc_for_log(router->platform);

  len = strlen(esc_contact)+strlen(esc_platform)+32;
  info = tor_malloc(len);
  tor_snprintf(info, len, "Contact %s, Platform %s", esc_contact,
               esc_platform);
  tor_free(esc_contact);
  tor_free(esc_platform);

  return info;
}

