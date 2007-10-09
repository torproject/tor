/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2007, Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char networkstatus_c_id[] =
  "$Id$";

/**
 * DOCDOC
 */

#include "or.h"

/** Global list of routerstatus_t for each router, known or unknown.
 * Kept sorted by digest. */
static smartlist_t *routerstatus_list = NULL;
/** Map from descriptor digest to a member of routerstatus_list: used to
 * update download status when a download fails. */
static digestmap_t *routerstatus_by_desc_digest_map = NULL;
/** True iff any element of routerstatus_list has changed since the last
 * time we called routers_update_all_from_networkstatus().*/
static int routerstatus_list_has_changed = 0;
/** Map from lowercase nickname to digest of named server, if any. */
static strmap_t *named_server_map = NULL;

/** Global list of all of the current network_status documents that we know
 * about.  This list is kept sorted by published_on. */
static smartlist_t *networkstatus_list = NULL;

/** Most recently received and validated v3 consensus network status. */
static networkstatus_vote_t *current_consensus = NULL;

/** A v3 consensus networkstatus that we've received, but which we don't
 * have enough certificates to be happy about. */
static networkstatus_vote_t *consensus_waiting_for_certs = NULL;
static char *consensus_waiting_for_certs_body = NULL;

/** True iff any member of networkstatus_list has changed since the last time
 * we called routerstatus_list_update_from_networkstatus(). */
static int networkstatus_list_has_changed = 0;

/** The last time we tried to download a networkstatus, or 0 for "never".  We
 * use this to rate-limit download attempts for directory caches (including
 * mirrors).  Clients don't use this now. */
static time_t last_networkstatus_download_attempted = 0;

/** The last time we tried to download a networkstatus, or 0 for "never".  We
 * use this to rate-limit download attempts for directory caches (including
 * mirrors).  Clients don't use this now. */
static time_t last_consensus_networkstatus_download_attempted = 0;
/**DOCDOC*/
static time_t time_to_download_next_consensus = 0;

/** List of strings for nicknames or fingerprints we've already warned about
 * and that are still conflicted. */ /*XXXX020 obsoleted by v3 dirs? */
static smartlist_t *warned_conflicts = NULL;

/** True iff we have logged a warning about this OR not being valid or
 * not being named. */
static int have_warned_about_invalid_status = 0;
/** True iff we have logged a warning about this OR's version being older than
 * listed by the authorities  */
static int have_warned_about_old_version = 0;
/** True iff we have logged a warning about this OR's version being newer than
 * listed by the authorities  */
static int have_warned_about_new_version = 0;

static int have_tried_downloading_all_statuses(int n_failures);

/** DOCDOC */
void
networkstatus_reset_warnings(void)
{
  if (!routerstatus_list)
    routerstatus_list = smartlist_create();
  SMARTLIST_FOREACH(routerstatus_list, routerstatus_t *, rs,
                    rs->name_lookup_warned = 0);

  if (!warned_conflicts)
    warned_conflicts = smartlist_create();
  SMARTLIST_FOREACH(warned_conflicts, char *, cp, tor_free(cp));
  smartlist_clear(warned_conflicts); /* now the list is empty. */

  have_warned_about_invalid_status = 0;
  have_warned_about_old_version = 0;
  have_warned_about_new_version = 0;
}

/** Repopulate our list of network_status_t objects from the list cached on
 * disk.  Return 0 on success, -1 on failure. */
int
router_reload_networkstatus(void)
{
  char filename[512];
  smartlist_t *entries;
  struct stat st;
  char *s;
  tor_assert(get_options()->DataDirectory);
  if (!networkstatus_list)
    networkstatus_list = smartlist_create();

  tor_snprintf(filename,sizeof(filename),"%s"PATH_SEPARATOR"cached-status",
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
      tor_snprintf(filename,sizeof(filename),
                   "%s"PATH_SEPARATOR"cached-status"PATH_SEPARATOR"%s",
                   get_options()->DataDirectory, fn);
      s = read_file_to_str(filename, 0, &st);
      if (s) {
        if (router_set_networkstatus(s, st.st_mtime, NS_FROM_CACHE, NULL)<0) {
          log_warn(LD_FS, "Couldn't load networkstatus from \"%s\"",filename);
        }
        tor_free(s);
      }
    });
  SMARTLIST_FOREACH(entries, char *, fn, tor_free(fn));
  smartlist_free(entries);
  networkstatus_list_clean(time(NULL));
  routers_update_all_from_networkstatus(time(NULL));
  return 0;
}

/** Read the cached v3 consensus networkstatus from the disk. */
int
router_reload_consensus_networkstatus(void)
{
  char filename[512];
  char *s;

  /* XXXX020 Suppress warnings if cached consensus is bad. */

  tor_snprintf(filename,sizeof(filename),"%s"PATH_SEPARATOR"cached-consensus",
               get_options()->DataDirectory);
  s = read_file_to_str(filename, RFTS_IGNORE_MISSING, NULL);
  if (s) {
    if (networkstatus_set_current_consensus(s, 1, 0)) {
      log_warn(LD_FS, "Couldn't load consensus networkstatus from \"%s\"",
               filename);
    }
    tor_free(s);
  }

  tor_snprintf(filename,sizeof(filename),
               "%s"PATH_SEPARATOR"unverified-consensus",
               get_options()->DataDirectory);
  s = read_file_to_str(filename, RFTS_IGNORE_MISSING, NULL);
  if (s) {
    if (networkstatus_set_current_consensus(s, 1, 1)) {
      log_warn(LD_FS, "Couldn't load consensus networkstatus from \"%s\"",
               filename);
    }
    tor_free(s);
  }

  return 0;
}

/** Free all storage held by the routerstatus object <b>rs</b>. */
void
routerstatus_free(routerstatus_t *rs)
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

/** Helper: return a newly allocated string containing the name of the filename
 * where we plan to cache the network status with the given identity digest. */
char *
networkstatus_get_cache_filename(const char *identity_digest)
{
  const char *datadir = get_options()->DataDirectory;
  size_t len = strlen(datadir)+64;
  char fp[HEX_DIGEST_LEN+1];
  char *fn = tor_malloc(len+1);
  base16_encode(fp, HEX_DIGEST_LEN+1, identity_digest, DIGEST_LEN);
  tor_snprintf(fn, len, "%s"PATH_SEPARATOR"cached-status"PATH_SEPARATOR"%s",
               datadir,fp);
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
    char *fn = networkstatus_get_cache_filename(ns->identity_digest);
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
 * own networkstatus_t (if we're an authoritative directory server).
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
        router_get_trusteddirserver_by_digest(ns->identity_digest)) ||
      !(trusted_dir->type & V2_AUTHORITY)) {
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
    control_event_general_status(LOG_WARN,
                                 "CLOCK_SKEW SOURCE=NETWORKSTATUS:%s:%d",
                                 ns->source_address, ns->source_dirport);
    skewed = 1;
  }

  if (!networkstatus_list)
    networkstatus_list = smartlist_create();

  if ( (source == NS_FROM_DIR_BY_FP || source == NS_FROM_DIR_ALL) &&
       router_digest_is_me(ns->identity_digest)) {
    /* Don't replace our own networkstatus when we get it from somebody else.*/
    networkstatus_free(ns);
    return 0;
  }

  if (requested_fingerprints) {
    if (smartlist_string_isin(requested_fingerprints, fp)) {
      smartlist_string_remove(requested_fingerprints, fp);
    } else {
      if (source != NS_FROM_DIR_ALL) {
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
  }

  if (!trusted_dir) {
    if (!skewed && get_options()->DirPort) {
      /* We got a non-trusted networkstatus, and we're a directory cache.
       * This means that we asked an authority, and it told us about another
       * authority we didn't recognize. */
      log_info(LD_DIR,
               "We do not recognize authority (%s) but we are willing "
               "to cache it.", fp);
      add_networkstatus_to_cache(s, source, ns);
      networkstatus_free(ns);
    }
    return 0;
  }

  found = 0;
  for (i=0; i < smartlist_len(networkstatus_list); ++i) {
    networkstatus_t *old_ns = smartlist_get(networkstatus_list, i);

    if (!memcmp(old_ns->identity_digest, ns->identity_digest, DIGEST_LEN)) {
      if (!memcmp(old_ns->networkstatus_digest,
                  ns->networkstatus_digest, DIGEST_LEN)) {
        /* Same one we had before. */
        networkstatus_free(ns);
        tor_assert(trusted_dir);
        log_info(LD_DIR,
                 "Not replacing network-status from %s (published %s); "
                 "we already have it.",
                 trusted_dir->description, published);
        if (old_ns->received_on < arrived_at) {
          if (source != NS_FROM_CACHE) {
            char *fn;
            fn = networkstatus_get_cache_filename(old_ns->identity_digest);
            /* We use mtime to tell when it arrived, so update that. */
            touch_file(fn);
            tor_free(fn);
          }
          old_ns->received_on = arrived_at;
        }
        download_status_failed(&trusted_dir->v2_ns_dl_status, 0);
        return 0;
      } else if (old_ns->published_on >= ns->published_on) {
        char old_published[ISO_TIME_LEN+1];
        format_iso_time(old_published, old_ns->published_on);
        tor_assert(trusted_dir);
        log_info(LD_DIR,
                 "Not replacing network-status from %s (published %s);"
                 " we have a newer one (published %s) for this authority.",
                 trusted_dir->description, published,
                 old_published);
        networkstatus_free(ns);
        download_status_failed(&trusted_dir->v2_ns_dl_status, 0);
        return 0;
      } else {
        networkstatus_free(old_ns);
        smartlist_set(networkstatus_list, i, ns);
        found = 1;
        break;
      }
    }
  }

  if (source != NS_FROM_CACHE && trusted_dir) {
    download_status_reset(&trusted_dir->v2_ns_dl_status);
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
           ((source == NS_FROM_DIR_BY_FP || source == NS_FROM_DIR_ALL) ?
             "downloaded from":"generated for"),
           trusted_dir->description, published);
  networkstatus_list_has_changed = 1;
  router_dir_info_changed();

  smartlist_sort(networkstatus_list, _compare_networkstatus_published_on);

  if (!skewed)
    add_networkstatus_to_cache(s, source, ns);

  networkstatus_list_update_recent(now);

  return 0;
}

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
    char *fname = NULL;
    if (ns->published_on + MAX_NETWORKSTATUS_AGE > now)
      continue;
    /* Okay, this one is too old.  Remove it from the list, and delete it
     * from the cache. */
    smartlist_del(networkstatus_list, i--);
    fname = networkstatus_get_cache_filename(ns->identity_digest);
    if (file_status(fname) == FN_FILE) {
      log_info(LD_DIR, "Removing too-old networkstatus in %s", fname);
      unlink(fname);
    }
    tor_free(fname);
    if (get_options()->DirPort) {
      dirserv_set_cached_networkstatus_v2(NULL, ns->identity_digest, 0);
    }
    networkstatus_free(ns);
    router_dir_info_changed();
  }

  /* And now go through the directory cache for any cached untrusted
   * networkstatuses and other network info. */
  dirserv_clear_old_networkstatuses(now - MAX_NETWORKSTATUS_AGE);
  dirserv_clear_old_v1_info(now);
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
routerstatus_t *
networkstatus_find_entry(networkstatus_t *ns, const char *digest)
{
  return smartlist_bsearch(ns->entries, digest,
                           _compare_digest_to_routerstatus_entry);
}

/** DOCDOC */
const smartlist_t *
networkstatus_get_v2_list(void)
{
  if (!networkstatus_list)
    networkstatus_list = smartlist_create();
  return networkstatus_list;
}

/** DOCDOC list of routerstatus_t */
const smartlist_t *
networkstatus_get_all_statuses(void)
{
  if (!routerstatus_list)
    routerstatus_list = smartlist_create();
  return routerstatus_list;
}

/** Return the consensus view of the status of the router whose identity
 * digest is <b>digest</b>, or NULL if we don't know about any such router. */
routerstatus_t *
router_get_combined_status_by_digest(const char *digest)
{
  if (!routerstatus_list)
    return NULL;
  return smartlist_bsearch(routerstatus_list, digest,
                           _compare_digest_to_routerstatus_entry);
}

/** Return the consensus view of the status of the router whose current
 * <i>descriptor</i> digest is <b>digest</b>, or NULL if no such router is
 * known. */
routerstatus_t *
router_get_combined_status_by_descriptor_digest(const char *digest)
{
  if (!routerstatus_by_desc_digest_map)
    return NULL;
  return digestmap_get(routerstatus_by_desc_digest_map, digest);
}

/** Given a nickname (possibly verbose, possibly a hexadecimal digest), return
 * the corresponding routerstatus_t, or NULL if none exists.  Warn the
 * user if <b>warn_if_unnamed</b> is set, and they have specified a router by
 * nickname, but the Named flag isn't set for that router. */
routerstatus_t *
router_get_combined_status_by_nickname(const char *nickname,
                                       int warn_if_unnamed)
{
  char digest[DIGEST_LEN];
  routerstatus_t *best=NULL;
  smartlist_t *matches=NULL;

  if (!routerstatus_list || !nickname)
    return NULL;

  if (nickname[0] == '$') {
    if (base16_decode(digest, DIGEST_LEN, nickname+1, strlen(nickname))<0)
      return NULL;
    return router_get_combined_status_by_digest(digest);
  } else if (strlen(nickname) == HEX_DIGEST_LEN &&
       (base16_decode(digest, DIGEST_LEN, nickname+1, strlen(nickname))==0)) {
    return router_get_combined_status_by_digest(digest);
  }

  matches = smartlist_create();
  SMARTLIST_FOREACH(routerstatus_list, routerstatus_t *, lrs,
    {
      if (!strcasecmp(lrs->nickname, nickname)) {
        if (lrs->is_named) {
          smartlist_free(matches);
          return lrs;
        } else {
          smartlist_add(matches, lrs);
          best = lrs;
        }
      }
    });

  if (smartlist_len(matches)>1 && warn_if_unnamed) {
    int any_unwarned=0;
    SMARTLIST_FOREACH(matches, routerstatus_t *, lrs,
      {
        if (! lrs->name_lookup_warned) {
          lrs->name_lookup_warned=1;
          any_unwarned=1;
        }
      });
    if (any_unwarned) {
      log_warn(LD_CONFIG,"There are multiple matches for the nickname \"%s\","
               " but none is listed as named by the directory authorites. "
               "Choosing one arbitrarily.", nickname);
    }
  } else if (warn_if_unnamed && best && !best->name_lookup_warned) {
    char fp[HEX_DIGEST_LEN+1];
    base16_encode(fp, sizeof(fp),
                  best->identity_digest, DIGEST_LEN);
    log_warn(LD_CONFIG,
         "When looking up a status, you specified a server \"%s\" by name, "
         "but the directory authorities do not have any key registered for "
         "this nickname -- so it could be used by any server, "
         "not just the one you meant. "
         "To make sure you get the same server in the future, refer to "
         "it by key, as \"$%s\".", nickname, fp);
    best->name_lookup_warned = 1;
  }
  smartlist_free(matches);
  return best;
}

/** DOCDOC */
const char *
networkstatus_get_router_digest_by_nickname(const char *nickname)
{
  if (!named_server_map)
    return NULL;
  return strmap_get_lc(named_server_map, nickname);
}

#if 0
/** Find a routerstatus_t that corresponds to <b>hexdigest</b>, if
 * any. Prefer ones that belong to authorities. */
routerstatus_t *
routerstatus_get_by_hexdigest(const char *hexdigest)
{
  char digest[DIGEST_LEN];
  routerstatus_t *rs;
  trusted_dir_server_t *ds;

  if (strlen(hexdigest) < HEX_DIGEST_LEN ||
      base16_decode(digest,DIGEST_LEN,hexdigest,HEX_DIGEST_LEN) < 0)
    return NULL;
  if ((ds = router_get_trusteddirserver_by_digest(digest)))
    return &ds->fake_status;
  if ((rs = router_get_combined_status_by_digest(digest)))
    return rs;
  return NULL;
}
#endif

/** How frequently do directory authorities re-download fresh networkstatus
 * documents? */
#define AUTHORITY_NS_CACHE_INTERVAL (5*60)

/** How frequently do non-authority directory caches re-download fresh
 * networkstatus documents? */
#define NONAUTHORITY_NS_CACHE_INTERVAL (15*60)

/** We are a directory server, and so cache network_status documents.
 * Initiate downloads as needed to update them.  For v2 authorities,
 * this means asking each trusted directory for its network-status.
 * For caches, this means asking a random v2 authority for all
 * network-statuses.
 */
static void
update_networkstatus_cache_downloads(time_t now)
{
  int authority = authdir_mode_v2(get_options());
  int interval =
    authority ? AUTHORITY_NS_CACHE_INTERVAL : NONAUTHORITY_NS_CACHE_INTERVAL;
  const smartlist_t *trusted_dir_servers = router_get_trusted_dir_servers();

  if (last_networkstatus_download_attempted + interval >= now)
    return;

  last_networkstatus_download_attempted = now;

  if (authority) {
    /* An authority launches a separate connection for everybody. */
    SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
       {
         char resource[HEX_DIGEST_LEN+6]; /* fp/hexdigit.z\0 */
         if (!(ds->type & V2_AUTHORITY))
           continue;
         if (router_digest_is_me(ds->digest))
           continue;
         if (connection_get_by_type_addr_port_purpose(
                CONN_TYPE_DIR, ds->addr, ds->dir_port,
                DIR_PURPOSE_FETCH_NETWORKSTATUS)) {
           /* XXX020 the above dir_port won't be accurate if we're
            * doing a tunneled conn. In that case it should be or_port.
            * How to guess from here? Maybe make the function less general
            * and have it know that it's looking for dir conns. -RD */
           /* We are already fetching this one. */
           continue;
         }
         strlcpy(resource, "fp/", sizeof(resource));
         base16_encode(resource+3, sizeof(resource)-3, ds->digest, DIGEST_LEN);
         strlcat(resource, ".z", sizeof(resource));
         directory_initiate_command_routerstatus(
               &ds->fake_status, DIR_PURPOSE_FETCH_NETWORKSTATUS,
               ROUTER_PURPOSE_GENERAL,
               0, /* Not private */
               resource,
               NULL, 0 /* No payload. */);
       });
  } else {
    /* A non-authority cache launches one connection to a random authority. */
    /* (Check whether we're currently fetching network-status objects.) */
    if (!connection_get_by_type_purpose(CONN_TYPE_DIR,
                                        DIR_PURPOSE_FETCH_NETWORKSTATUS))
      directory_get_from_dirserver(DIR_PURPOSE_FETCH_NETWORKSTATUS,
                                   ROUTER_PURPOSE_GENERAL, "all.z",1);
  }
}

/** How long (in seconds) does a client wait after getting a network status
 * before downloading the next in sequence? */
#define NETWORKSTATUS_CLIENT_DL_INTERVAL (30*60)
/** How many times do we allow a networkstatus download to fail before we
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
  const smartlist_t *trusted_dir_servers = router_get_trusted_dir_servers();

  if (connection_get_by_type_purpose(CONN_TYPE_DIR,
                                     DIR_PURPOSE_FETCH_NETWORKSTATUS))
    return;

  /* This is a little tricky.  We want to download enough network-status
   * objects so that we have all of them under
   * NETWORKSTATUS_MAX_AGE publication time.  We want to download a new
   * *one* if the most recent one's publication time is under
   * NETWORKSTATUS_CLIENT_DL_INTERVAL.
   */
  if (!get_n_authorities(V2_AUTHORITY))
    return;
  n_dirservers = n_running_dirservers = 0;
  missing = smartlist_create();
  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
     {
       networkstatus_t *ns = networkstatus_get_by_digest(ds->digest);
       if (!(ds->type & V2_AUTHORITY))
         continue;
       ++n_dirservers;
       if (!download_status_is_ready(&ds->v2_ns_dl_status, now,
                                     NETWORKSTATUS_N_ALLOWABLE_FAILURES))
         continue;
       ++n_running_dirservers;
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
    most_recent_idx = crypto_rand_int(smartlist_len(trusted_dir_servers));

  if (fetch_latest) {
    int i;
    int n_failed = 0;
    for (i = most_recent_idx + 1; 1; ++i) {
      trusted_dir_server_t *ds;
      if (i >= smartlist_len(trusted_dir_servers))
        i = 0;
      ds = smartlist_get(trusted_dir_servers, i);
      if (!(ds->type & V2_AUTHORITY))
        continue;
      if (n_failed >= n_dirservers) {
        log_info(LD_DIR, "All authorities have failed. Not trying any.");
        smartlist_free(missing);
        return;
      }
      if (ds->v2_ns_dl_status.n_download_failures >
          NETWORKSTATUS_N_ALLOWABLE_FAILURES) {
        ++n_failed;
        continue;
      }
      smartlist_add(missing, ds->digest);
      break;
    }
  }

  /* Build a request string for all the resources we want. */
  resource_len = smartlist_len(missing) * (HEX_DIGEST_LEN+1) + 6;
  resource = tor_malloc(resource_len);
  memcpy(resource, "fp/", 3);
  cp = resource+3;
  smartlist_sort_digests(missing);
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
  directory_get_from_dirserver(DIR_PURPOSE_FETCH_NETWORKSTATUS,
                               ROUTER_PURPOSE_GENERAL, resource, 1);
  tor_free(resource);
  smartlist_free(missing);
}

/** DOCDOC */
static void
update_consensus_networkstatus_downloads(time_t now)
{
  or_options_t *options = get_options();
  if (!options->DirPort) /*XXXX020 remove this. */
    return;
  if (time_to_download_next_consensus > now)
    return;
  if (authdir_mode_v3(options))
    return;
  if (connection_get_by_type_purpose(CONN_TYPE_DIR,
                                     DIR_PURPOSE_FETCH_CONSENSUS))
    return;
  /* XXXX020 on failure, delay until next retry. */

  last_consensus_networkstatus_download_attempted = now;/*XXXX020 use this*/
  directory_get_from_dirserver(DIR_PURPOSE_FETCH_CONSENSUS,
                               ROUTER_PURPOSE_GENERAL, NULL, 1);
  // XXXX020 time_to_download_next_consensus = put it off for a while?
}

/** DOCDOC */
static void
update_consensus_networkstatus_fetch_time(time_t now)
{
  or_options_t *options = get_options();
  /* XXXX020 call this when DirPort switches on or off. NMNM */
  if (current_consensus) {
    const networkstatus_vote_t *c = current_consensus;
    time_t start;
    long interval;
    if (options->DirPort) {
      start = c->valid_after + 120; /*XXXX020 make this a macro. */
      /* XXXX020 too much magic. */
      interval = (c->fresh_until - c->valid_after) / 2;
    } else {
      start = c->fresh_until;
      /* XXXX020 too much magic. */
      interval = (c->valid_until - c->fresh_until) * 7 / 8;
    }
    if (interval < 1)
      interval = 1;
    tor_assert(start+interval < c->valid_until);
    time_to_download_next_consensus = start + crypto_rand_int(interval);
  } else {
    time_to_download_next_consensus = now;
  }
}

/** Return 1 if there's a reason we shouldn't try any directory
 * fetches yet (e.g. we demand bridges and none are yet known).
 * Else return 0. */
int
should_delay_dir_fetches(or_options_t *options)
{
  if (options->UseBridges && !any_bridge_descriptors_known()) {
    log_info(LD_DIR, "delaying dir fetches");
    return 1;
  }
  return 0;
}

/** Launch requests for networkstatus documents as appropriate. */
void
update_networkstatus_downloads(time_t now)
{
  or_options_t *options = get_options();
  if (should_delay_dir_fetches(options))
    return;
  if (options->DirPort)
    update_networkstatus_cache_downloads(now);
  else
    update_networkstatus_client_downloads(now);
  update_consensus_networkstatus_downloads(now);
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

/** Return the most recent consensus that we have downloaded, or NULL if we
 * don't have one. */
networkstatus_vote_t *
networkstatus_get_latest_consensus(void)
{
  return current_consensus;
}

/** Return the most recent consensus that we have downloaded, or NULL if it is
 * no longer live. */
networkstatus_vote_t *
networkstatus_get_live_consensus(time_t now)
{
  if (current_consensus &&
      current_consensus->valid_after <= now &&
      now <= current_consensus->valid_until)
    return current_consensus;
  else
    return NULL;
}

/** Try to replace the current cached v3 networkstatus with the one in
 * <b>consensus</b>.  If we don't have enough certificates to validate it,
 * store it in consensus_waiting_for_certs and launch a certificate fetch.
 *
 * Return 0 on success, -1 on failure. */
int
networkstatus_set_current_consensus(const char *consensus, int from_cache,
                                    int was_waiting_for_certs)
{
  networkstatus_vote_t *c;
  int r;
  time_t now = time(NULL);

  /* Make sure it's parseable. */
  c = networkstatus_parse_vote_from_string(consensus, NULL, 0);
  if (!c) {
    log_warn(LD_DIR, "Unable to parse networkstatus consensus");
    return -1;
  }

  /* Make sure it's signed enough. */
  if ((r=networkstatus_check_consensus_signature(c, 1))<0) {
    if (r == -1 && !was_waiting_for_certs) {
      /* Okay, so it _might_ be signed enough if we get more certificates. */
      if (!was_waiting_for_certs)
        log_notice(LD_DIR, "Not enough certificates to check networkstatus "
                   "consensus");
      if (!current_consensus ||
          c->valid_after > current_consensus->valid_after) {
        if (consensus_waiting_for_certs)
          networkstatus_vote_free(consensus_waiting_for_certs);
        tor_free(consensus_waiting_for_certs_body);
        consensus_waiting_for_certs = c;
        consensus_waiting_for_certs_body = tor_strdup(consensus);
        /*XXXX020 delay next update. NMNM */
        if (!from_cache) {
          or_options_t *options = get_options();
          char filename[512];
          tor_snprintf(filename, sizeof(filename),
                       "%s"PATH_SEPARATOR"unverified-consensus",
                       options->DataDirectory);
          write_str_to_file(filename, consensus, 0);
        }
        /* XXXX this test isn't quite right; see below. */
        if (!connection_get_by_type_purpose(CONN_TYPE_DIR,
                                            DIR_PURPOSE_FETCH_CERTIFICATE))
          authority_certs_fetch_missing(c);
      }
      return 0;
    } else {
      if (!was_waiting_for_certs)
        log_warn(LD_DIR, "Not enough good signatures on networkstatus "
                 "consensus");
      networkstatus_vote_free(c);
      return -1;
    }
  }

  /* Are we missing any certificates at all? */
  /* XXXX The test for 'are we downloading' should be 'are we downloading
   *    these certificates', and it should get pushed into
   *    authority_certs_fetch_missing. */
  if (r != 1 && !connection_get_by_type_purpose(CONN_TYPE_DIR,
                                                DIR_PURPOSE_FETCH_CERTIFICATE))
    authority_certs_fetch_missing(c);

  if (current_consensus)
    networkstatus_vote_free(current_consensus);

  if (consensus_waiting_for_certs &&
      consensus_waiting_for_certs->valid_after <= c->valid_after) {
    networkstatus_vote_free(consensus_waiting_for_certs);
    consensus_waiting_for_certs = NULL;
    if (consensus != consensus_waiting_for_certs_body)
      tor_free(consensus_waiting_for_certs_body);
  }

  current_consensus = c;

  update_consensus_networkstatus_fetch_time(now);

  if (!from_cache) {
    or_options_t *options = get_options();
    char filename[512];
    tor_snprintf(filename, sizeof(filename),
                 "%s"PATH_SEPARATOR"cached-consensus",
                 options->DataDirectory);
    write_str_to_file(filename, consensus, 0);
  }

  if (get_options()->DirPort)
    dirserv_set_cached_networkstatus_v3(consensus, c->valid_after);

  return 0;
}

/** DOCDOC */
void
networkstatus_note_certs_arrived(void)
{
  if (consensus_waiting_for_certs) {
    if (networkstatus_check_consensus_signature(
                                    consensus_waiting_for_certs, 0)<0) {
      if (!networkstatus_set_current_consensus(
                                 consensus_waiting_for_certs_body, 0, 1)) {
        tor_free(consensus_waiting_for_certs_body);
      }
    }
  }
}

/** How many times do we have to fail at getting a networkstatus we can't find
 * before we're willing to believe it's okay to set up router statuses? */
#define N_NS_ATTEMPTS_TO_SET_ROUTERS 4
/** How many times do we have to fail at getting a networkstatus we can't find
 * before we're willing to believe it's okay to check our version? */
#define N_NS_ATTEMPTS_TO_CHECK_VERSION 4
/** We believe networkstatuses more recent than this when they tell us that
 * our server is broken, invalid, obsolete, etc. */
#define SELF_OPINION_INTERVAL (90*60)

/** If the network-status list has changed since the last time we called this
 * function, update the status of every routerinfo from the network-status
 * list.
 */
void
routers_update_all_from_networkstatus(time_t now)
{
  routerinfo_t *me;
  routerlist_t *rl = router_get_routerlist();
  if (!networkstatus_list ||
      (!networkstatus_list_has_changed && !routerstatus_list_has_changed))
    return;

  router_dir_info_changed();

  if (networkstatus_list_has_changed)
    routerstatus_list_update_from_networkstatus(now);

  routers_update_status_from_networkstatus(rl->routers, 0);

  me = router_get_my_routerinfo();
  if (me && !have_warned_about_invalid_status &&
      have_tried_downloading_all_statuses(N_NS_ATTEMPTS_TO_SET_ROUTERS)) {
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

    if (n_listing) {
      if (n_valid <= n_listing/2)  {
        log_info(LD_GENERAL,
                 "%d/%d recent statements from directory authorities list us "
                 "as unapproved. Are you misconfigured?",
                 n_listing-n_valid, n_listing);
        have_warned_about_invalid_status = 1;
      } else if (n_naming && !n_named) {
        log_info(LD_GENERAL, "0/%d name-binding directory authorities "
                 "recognize your nickname. Please consider sending your "
                 "nickname and identity fingerprint to the tor-ops.",
                 n_naming);
        have_warned_about_invalid_status = 1;
      }
    }
  }

  entry_guards_compute_status();

  if (!have_warned_about_old_version &&
      have_tried_downloading_all_statuses(N_NS_ATTEMPTS_TO_CHECK_VERSION)) {
    combined_version_status_t st;
    int is_server = server_mode(get_options());
    char *recommended;

    recommended = compute_recommended_versions(now, !is_server, VERSION, &st);

    if (st.n_versioning) {
      if (st.consensus == VS_RECOMMENDED) {
        log_info(LD_GENERAL, "%d/%d statements from version-listing "
                 "directory authorities say my version is ok.",
                 st.n_concurring, st.n_versioning);
      } else if (st.consensus == VS_NEW || st.consensus == VS_NEW_IN_SERIES) {
        if (!have_warned_about_new_version) {
          log_notice(LD_GENERAL, "This version of Tor (%s) is newer than any "
                 "recommended version%s, according to %d/%d version-listing "
                 "network statuses. Versions recommended by more than %d "
                 "authorit%s are: %s",
                 VERSION,
                 st.consensus == VS_NEW_IN_SERIES ? " in its series" : "",
                 st.n_concurring, st.n_versioning, st.n_versioning/2,
                 st.n_versioning/2 > 1 ? "ies" : "y", recommended);
          have_warned_about_new_version = 1;
          control_event_general_status(LOG_WARN, "DANGEROUS_VERSION "
                 "CURRENT=%s REASON=%s RECOMMENDED=\"%s\"",
                 VERSION, "NEW", recommended);
        }
      } else {
        log_warn(LD_GENERAL, "Please upgrade! "
                 "This version of Tor (%s) is %s, according to %d/%d version-"
                 "listing network statuses. Versions recommended by "
                 "at least %d authorit%s are: %s",
                 VERSION,
                 st.consensus == VS_OLD ? "obsolete" : "not recommended",
                 st.n_concurring, st.n_versioning, st.n_versioning/2,
                 st.n_versioning/2 > 1 ? "ies" : "y", recommended);
        have_warned_about_old_version = 1;
        control_event_general_status(LOG_WARN, "DANGEROUS_VERSION "
                 "CURRENT=%s REASON=%s RECOMMENDED=\"%s\"",
                 VERSION, st.consensus == VS_OLD ? "OLD" : "UNRECOMMENDED",
                 recommended);
      }
    }
    tor_free(recommended);
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
  if (changed) {
    networkstatus_list_has_changed = 1;
    router_dir_info_changed();
  }
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
void
routerstatus_list_update_from_networkstatus(time_t now)
{
  or_options_t *options = get_options();
  int n_trusted, n_statuses, n_recent = 0, n_naming = 0;
  int n_listing_bad_exits = 0, n_listing_bad_directories = 0;
  int i, j, warned;
  int *index, *size;
  networkstatus_t **networkstatus;
  smartlist_t *result, *changed_list;
  strmap_t *name_map;
  char conflict[DIGEST_LEN]; /* Sentinel value */
  desc_digest_count_t *digest_counts = NULL;

  /* compute which network statuses will have a vote now */
  networkstatus_list_update_recent(now);
  router_dir_info_changed();

  if (!networkstatus_list_has_changed)
    return;
  if (!networkstatus_list)
    networkstatus_list = smartlist_create();
  if (!routerstatus_list)
    routerstatus_list = smartlist_create();
  if (!warned_conflicts)
    warned_conflicts = smartlist_create();

  n_statuses = smartlist_len(networkstatus_list);
  n_trusted = get_n_authorities(V2_AUTHORITY);

  if (n_statuses <= n_trusted/2) {
    /* Not enough statuses to adjust status. */
    log_info(LD_DIR,
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
    if (networkstatus[i]->lists_bad_exits)
      ++n_listing_bad_exits;
    if (networkstatus[i]->lists_bad_directories)
      ++n_listing_bad_directories;
  }

  /** Iterate over all entries in all networkstatuses, and build
   * name_map as a map from lc nickname to identity digest.  If there
   * is a conflict on that nickname, map the lc nickname to conflict.
   */
  name_map = strmap_new();
  /* Clear the global map... */
  if (named_server_map)
    strmap_free(named_server_map, _tor_free);
  named_server_map = strmap_new();
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
        strmap_set_lc(named_server_map, rs->nickname,
                      tor_memdup(rs->identity_digest, DIGEST_LEN));
        if (warned)
          smartlist_string_remove(warned_conflicts, rs->nickname);
      } else if (memcmp(other_digest, rs->identity_digest, DIGEST_LEN) &&
                 other_digest != conflict) {
        if (!warned) {
          char *d;
          int should_warn = options->DirPort && authdir_mode(options);
          char fp1[HEX_DIGEST_LEN+1];
          char fp2[HEX_DIGEST_LEN+1];
          base16_encode(fp1, sizeof(fp1), other_digest, DIGEST_LEN);
          base16_encode(fp2, sizeof(fp2), rs->identity_digest, DIGEST_LEN);
          log_fn(should_warn ? LOG_WARN : LOG_INFO, LD_DIR,
                 "Naming authorities disagree about which key goes with %s. "
                 "($%s vs $%s)",
                 rs->nickname, fp1, fp2);
          strmap_set_lc(name_map, rs->nickname, conflict);
          d = strmap_remove_lc(named_server_map, rs->nickname);
          tor_free(d);
          smartlist_add(warned_conflicts, tor_strdup(rs->nickname));
        }
      } else {
        if (warned)
          smartlist_string_remove(warned_conflicts, rs->nickname);
      }
    });
  }

  result = smartlist_create();
  changed_list = smartlist_create();
  digest_counts = tor_malloc_zero(sizeof(desc_digest_count_t)*n_statuses);

  /* Iterate through all of the sorted routerstatus lists in lockstep.
   * Invariants:
   *  - For 0 <= i < n_statuses: index[i] is an index into
   *    networkstatus[i]->entries, which has size[i] elements.
   *  - For i1, i2, j such that 0 <= i1 < n_statuses, 0 <= i2 < n_statues, 0 <=
   *    j < index[i1]: networkstatus[i1]->entries[j]->identity_digest <
   *    networkstatus[i2]->entries[index[i2]]->identity_digest.
   *
   *    (That is, the indices are always advanced past lower digest before
   *    higher.)
   */
  while (1) {
    int n_running=0, n_named=0, n_valid=0, n_listing=0;
    int n_v2_dir=0, n_fast=0, n_stable=0, n_exit=0, n_guard=0, n_bad_exit=0;
    int n_bad_directory=0;
    int n_version_known=0, n_supports_begindir=0;
    int n_supports_extrainfo_upload=0;
    int n_desc_digests=0, highest_count=0;
    const char *the_name = NULL;
    routerstatus_t *rs_out, *rs_old;
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
      if (rs->is_bad_exit)
        ++n_bad_exit;
      if (rs->is_bad_directory)
        ++n_bad_directory;
      if (rs->version_known)
        ++n_version_known;
      if (rs->version_supports_begindir)
        ++n_supports_begindir;
      if (rs->version_supports_extrainfo_upload)
        ++n_supports_extrainfo_upload;
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
    rs_out = tor_malloc_zero(sizeof(routerstatus_t));
    memcpy(rs_out, most_recent, sizeof(routerstatus_t));
    /* Copy status info about this router, if we had any before. */
    if ((rs_old = router_get_combined_status_by_digest(lowest))) {
      if (!memcmp(rs_out->descriptor_digest,
                  most_recent->descriptor_digest, DIGEST_LEN)) {
        rs_out->dl_status.n_download_failures =
          rs_old->dl_status.n_download_failures;
        rs_out->dl_status.next_attempt_at = rs_old->dl_status.next_attempt_at;
      }
      rs_out->name_lookup_warned = rs_old->name_lookup_warned;
      rs_out->last_dir_503_at = rs_old->last_dir_503_at;
    }
    smartlist_add(result, rs_out);
    log_debug(LD_DIR, "Router '%s' is listed by %d/%d directories, "
              "named by %d/%d, validated by %d/%d, and %d/%d recent "
              "directories think it's running.",
              rs_out->nickname,
              n_listing, n_statuses, n_named, n_naming, n_valid, n_statuses,
              n_running, n_recent);
    rs_out->is_named  = 0;
    if (the_name && strcmp(the_name, "**mismatch**") && n_named > 0) {
      const char *d = strmap_get_lc(name_map, the_name);
      if (d && d != conflict)
        rs_out->is_named = 1;
      if (smartlist_string_isin(warned_conflicts, rs_out->nickname))
        smartlist_string_remove(warned_conflicts, rs_out->nickname);
    }
    if (rs_out->is_named)
      strlcpy(rs_out->nickname, the_name,
              sizeof(rs_out->nickname));
    rs_out->is_valid = n_valid > n_statuses/2;
    rs_out->is_running = n_running > n_recent/2;
    rs_out->is_exit = n_exit > n_statuses/2;
    rs_out->is_fast = n_fast > n_statuses/2;
    rs_out->is_possible_guard = n_guard > n_statuses/2;
    rs_out->is_stable = n_stable > n_statuses/2;
    rs_out->is_v2_dir = n_v2_dir > n_statuses/2;
    rs_out->is_bad_exit = n_bad_exit > n_listing_bad_exits/2;
    rs_out->is_bad_directory =
      n_bad_directory > n_listing_bad_directories/2;
    rs_out->version_known = n_version_known > 0;
    rs_out->version_supports_begindir =
      n_supports_begindir > n_version_known/2;
    rs_out->version_supports_extrainfo_upload =
      n_supports_extrainfo_upload > n_version_known/2;
    if (!rs_old || memcmp(rs_old, rs_out, sizeof(routerstatus_t)))
      smartlist_add(changed_list, rs_out);
  }
  SMARTLIST_FOREACH(routerstatus_list, routerstatus_t *, rs,
                    routerstatus_free(rs));

  smartlist_free(routerstatus_list);
  routerstatus_list = result;

  if (routerstatus_by_desc_digest_map)
    digestmap_free(routerstatus_by_desc_digest_map, NULL);
  routerstatus_by_desc_digest_map = digestmap_new();
  SMARTLIST_FOREACH(routerstatus_list, routerstatus_t *, rs,
                    digestmap_set(routerstatus_by_desc_digest_map,
                                  rs->descriptor_digest,
                                  rs));

  tor_free(networkstatus);
  tor_free(index);
  tor_free(size);
  tor_free(digest_counts);
  strmap_free(name_map, NULL);

  networkstatus_list_has_changed = 0;
  routerstatus_list_has_changed = 1;

  control_event_networkstatus_changed(changed_list);
  smartlist_free(changed_list);
}

/** Given a list <b>routers</b> of routerinfo_t *, update each routers's
 * is_named, is_valid, and is_running fields according to our current
 * networkstatus_t documents. */  /* XXXX020 obsoleted by v3 */
void
routers_update_status_from_networkstatus(smartlist_t *routers,
                                         int reset_failures)
{
  trusted_dir_server_t *ds;
  routerstatus_t *rs;
  or_options_t *options = get_options();
  int authdir = authdir_mode_v2(options);
  int namingdir = authdir && options->NamingAuthoritativeDir;

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
      router->is_named = rs->is_named;

    if (!authdir) {
      /* If we're not an authdir, believe others. */
      router->is_valid = rs->is_valid;
      router->is_running = rs->is_running;
      router->is_fast = rs->is_fast;
      router->is_stable = rs->is_stable;
      router->is_possible_guard = rs->is_possible_guard;
      router->is_exit = rs->is_exit;
      router->is_bad_exit = rs->is_bad_exit;
    }
    if (router->is_running && ds) {
      download_status_reset(&ds->v2_ns_dl_status);
    }
    if (reset_failures) {
      download_status_reset(&rs->dl_status);
    }
  });
  router_dir_info_changed();
}

/** Return true iff we have downloaded, or attempted to download at least
 * n_failures times, a network status for each authority. */
static int
have_tried_downloading_all_statuses(int n_failures)
{
  smartlist_t *trusted_dir_servers = router_get_trusted_dir_servers();

  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
    {
      if (!(ds->type & V2_AUTHORITY))
        continue;
      /* If we don't have the status, and we haven't failed to get the status,
       * we haven't tried to get the status. */
      if (!networkstatus_get_by_digest(ds->digest) &&
          ds->v2_ns_dl_status.n_download_failures <= n_failures)
        return 0;
    });

  return 1;
}

/** Generate networkstatus lines for a single routerstatus_t object, and
 * return the result in a newly allocated string.  Used only by controller
 * interface (for now.) */
char *
networkstatus_getinfo_helper_single(routerstatus_t *rs)
{
  char buf[256];
  routerstatus_format_entry(buf, sizeof(buf), rs, NULL, 0);
  return tor_strdup(buf);
}

/** If <b>question</b> is a string beginning with "ns/" in a format the
 * control interface expects for a GETINFO question, set *<b>answer</b> to a
 * newly-allocated string containing networkstatus lines for the appropriate
 * ORs.  Return 0 on success, -1 on unrecognized question format. */
int
getinfo_helper_networkstatus(control_connection_t *conn,
                             const char *question, char **answer)
{
  routerstatus_t *status;
  (void) conn;

  if (!routerstatus_list) {
    *answer = tor_strdup("");
    return 0;
  }

  if (!strcmp(question, "ns/all")) {
    smartlist_t *statuses = smartlist_create();
    SMARTLIST_FOREACH(routerstatus_list, routerstatus_t *, rs,
      {
        smartlist_add(statuses, networkstatus_getinfo_helper_single(rs));
      });
    *answer = smartlist_join_strings(statuses, "", 0, NULL);
    SMARTLIST_FOREACH(statuses, char *, cp, tor_free(cp));
    smartlist_free(statuses);
    return 0;
  } else if (!strcmpstart(question, "ns/id/")) {
    char d[DIGEST_LEN];

    if (base16_decode(d, DIGEST_LEN, question+6, strlen(question+6)))
      return -1;
    status = router_get_combined_status_by_digest(d);
  } else if (!strcmpstart(question, "ns/name/")) {
    status = router_get_combined_status_by_nickname(question+8, 0);
  } else {
    return -1;
  }

  if (status) {
    *answer = networkstatus_getinfo_helper_single(status);
  }
  return 0;
}

/** DOCDOC */
void
networkstatus_free_all(void)
{
  /* XXXX !!!! CALLME */
  if (networkstatus_list) {
    SMARTLIST_FOREACH(networkstatus_list, networkstatus_t *, ns,
                      networkstatus_free(ns));
    smartlist_free(networkstatus_list);
    networkstatus_list = NULL;
  }
  if (routerstatus_list) {
    SMARTLIST_FOREACH(routerstatus_list, routerstatus_t *, rs,
                      routerstatus_free(rs));
    smartlist_free(routerstatus_list);
    routerstatus_list = NULL;
  }
  if (routerstatus_by_desc_digest_map) {
    digestmap_free(routerstatus_by_desc_digest_map, NULL);
    routerstatus_by_desc_digest_map = NULL;
  }
  if (current_consensus) {
    networkstatus_vote_free(current_consensus);
    current_consensus = NULL;
  }
  if (consensus_waiting_for_certs) {
    networkstatus_vote_free(current_consensus);
    current_consensus = NULL;
  }
  tor_free(consensus_waiting_for_certs_body);
  if (warned_conflicts) {
    SMARTLIST_FOREACH(warned_conflicts, char *, cp, tor_free(cp));
    smartlist_free(warned_conflicts);
    warned_conflicts = NULL;
  }
  if (named_server_map) {
    strmap_free(named_server_map, _tor_free);
  }
}

