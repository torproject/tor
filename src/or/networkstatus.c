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

/** XXXXX020 are all these still needed */

/** DOCDOC */
static digestmap_t *v2_download_status_map = NULL;

/** Map from lowercase nickname to digest of named server, if any. */
static strmap_t *named_server_map = NULL;

/** Global list of all of the current v2 network_status documents that we know
 * about.  This list is kept sorted by published_on. */
static smartlist_t *networkstatus_v2_list = NULL;

/** Most recently received and validated v3 consensus network status. */
static networkstatus_vote_t *current_consensus = NULL;

/** A v3 consensus networkstatus that we've received, but which we don't
 * have enough certificates to be happy about. */
static networkstatus_vote_t *consensus_waiting_for_certs = NULL;
static char *consensus_waiting_for_certs_body = NULL;

/** True iff any member of networkstatus_v2_list has changed since the last
 * time we called routerstatus_list_update_from_networkstatus(). */
static int networkstatus_v2_list_has_changed = 0;

/** The last time we tried to download a networkstatus, or 0 for "never".  We
 * use this to rate-limit download attempts for directory caches (including
 * mirrors).  Clients don't use this now. */
static time_t last_networkstatus_download_attempted = 0;

/**DOCDOC*/
static time_t time_to_download_next_consensus = 0;
/**DOCDOC*/
static download_status_t consensus_dl_status = { 0, 0};

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

static void routerstatus_list_update_from_v2_networkstatus(void);
static void routerstatus_list_update_named_server_map(void);

/** DOCDOC */
void
networkstatus_reset_warnings(void)
{
  if (current_consensus) {
    SMARTLIST_FOREACH(current_consensus->routerstatus_list,
                      routerstatus_t *, rs,
                      rs->name_lookup_warned = 0);
  }

  if (!warned_conflicts)
    warned_conflicts = smartlist_create();
  SMARTLIST_FOREACH(warned_conflicts, char *, cp, tor_free(cp));
  smartlist_clear(warned_conflicts); /* now the list is empty. */

  have_warned_about_invalid_status = 0;
  have_warned_about_old_version = 0;
  have_warned_about_new_version = 0;
}

/** Reset the descriptor download failure count on all networkstatus docs, so
 * that we can retry any long-failed documents immediately.
 */
void
networkstatus_reset_download_failures(void)
{
  const smartlist_t *networkstatus_v2_list = networkstatus_get_v2_list();
  SMARTLIST_FOREACH(networkstatus_v2_list, networkstatus_v2_t *, ns,
     SMARTLIST_FOREACH(ns->entries, routerstatus_t *, rs,
       {
         if (!router_get_by_descriptor_digest(rs->descriptor_digest))
           rs->need_to_mirror = 1;
       }));;

  download_status_reset(&consensus_dl_status);
  if (v2_download_status_map) {
    digestmap_iter_t *iter;
    digestmap_t *map = v2_download_status_map;
    const char *key;
    void *val;
    download_status_t *dls;
    for (iter = digestmap_iter_init(map); !digestmap_iter_done(iter);
         iter = digestmap_iter_next(map, iter) ) {
      digestmap_iter_get(iter, &key, &val);
      dls = val;
      download_status_reset(dls);
    }
  }
}

/** Repopulate our list of network_status_t objects from the list cached on
 * disk.  Return 0 on success, -1 on failure. */
int
router_reload_v2_networkstatus(void)
{
  smartlist_t *entries;
  struct stat st;
  char *s;
  char *filename = get_datadir_fname("cached-status");
  if (!networkstatus_v2_list)
    networkstatus_v2_list = smartlist_create();

  entries = tor_listdir(filename);
  tor_free(filename);
  SMARTLIST_FOREACH(entries, const char *, fn, {
      char buf[DIGEST_LEN];
      if (strlen(fn) != HEX_DIGEST_LEN ||
          base16_decode(buf, sizeof(buf), fn, strlen(fn))) {
        log_info(LD_DIR,
                 "Skipping cached-status file with unexpected name \"%s\"",fn);
        continue;
      }
      filename = get_datadir_fname2("cached-status", fn);
      s = read_file_to_str(filename, 0, &st);
      if (s) {
        if (router_set_networkstatus_v2(s, st.st_mtime, NS_FROM_CACHE,
                                        NULL)<0) {
          log_warn(LD_FS, "Couldn't load networkstatus from \"%s\"",filename);
        }
        tor_free(s);
      }
      tor_free(filename);
    });
  SMARTLIST_FOREACH(entries, char *, fn, tor_free(fn));
  smartlist_free(entries);
  networkstatus_v2_list_clean(time(NULL));
  routers_update_all_from_networkstatus(time(NULL));
  return 0;
}

/** Read the cached v3 consensus networkstatus from the disk. */
int
router_reload_consensus_networkstatus(void)
{
  char *filename;
  char *s;

  /* XXXX020 Suppress warnings if cached consensus is bad. */

  filename = get_datadir_fname("cached-consensus");
  s = read_file_to_str(filename, RFTS_IGNORE_MISSING, NULL);
  if (s) {
    if (networkstatus_set_current_consensus(s, 1, 0)) {
      log_warn(LD_FS, "Couldn't load consensus networkstatus from \"%s\"",
               filename);
    }
    tor_free(s);
  }
  tor_free(filename);

  filename = get_datadir_fname("unverified-consensus");
  s = read_file_to_str(filename, RFTS_IGNORE_MISSING, NULL);
  if (s) {
    if (networkstatus_set_current_consensus(s, 1, 1)) {
      log_warn(LD_FS, "Couldn't load consensus networkstatus from \"%s\"",
               filename);
    }
    tor_free(s);
  }
  tor_free(filename);

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
networkstatus_v2_free(networkstatus_v2_t *ns)
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
  char fp[HEX_DIGEST_LEN+1];
  base16_encode(fp, HEX_DIGEST_LEN+1, identity_digest, DIGEST_LEN);
  return get_datadir_fname2("cached-status", fp);
}

/** Helper for smartlist_sort: Compare two networkstatus objects by
 * publication date. */
static int
_compare_networkstatus_v2_published_on(const void **_a, const void **_b)
{
  const networkstatus_v2_t *a = *_a, *b = *_b;
  if (a->published_on < b->published_on)
    return -1;
  else if (a->published_on > b->published_on)
    return 1;
  else
    return 0;
}

/** Add the parsed neworkstatus in <b>ns</b> (with original document in
 * <b>s</b>) to the disk cache (and the in-memory directory server cache) as
 * appropriate. */
static int
add_networkstatus_to_cache(const char *s,
                           networkstatus_source_t source,
                           networkstatus_v2_t *ns)
{
  if (source != NS_FROM_CACHE) {
    char *fn = networkstatus_get_cache_filename(ns->identity_digest);
    if (write_str_to_file(fn, s, 0)<0) {
      log_notice(LD_FS, "Couldn't write cached network status to \"%s\"", fn);
    }
    tor_free(fn);
  }

  if (dirserver_mode(get_options()))
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
router_set_networkstatus_v2(const char *s, time_t arrived_at,
            networkstatus_source_t source, smartlist_t *requested_fingerprints)
{
  networkstatus_v2_t *ns;
  int i, found;
  time_t now;
  int skewed = 0;
  trusted_dir_server_t *trusted_dir = NULL;
  const char *source_desc = NULL;
  char fp[HEX_DIGEST_LEN+1];
  char published[ISO_TIME_LEN+1];

  if (!dirserver_mode(get_options()))
    return 0; /* Don't bother storing it. */

  ns = networkstatus_v2_parse_from_string(s);
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
    if (!dirserver_mode(get_options())) {
      networkstatus_v2_free(ns);
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
             "(%s GMT). Check your system clock! "
             "Not caching.",
             source_desc, published);
    control_event_general_status(LOG_WARN,
                                 "CLOCK_SKEW SOURCE=NETWORKSTATUS:%s:%d",
                                 ns->source_address, ns->source_dirport);
    skewed = 1;
  }

  if (!networkstatus_v2_list)
    networkstatus_v2_list = smartlist_create();

  if ( (source == NS_FROM_DIR_BY_FP || source == NS_FROM_DIR_ALL) &&
       router_digest_is_me(ns->identity_digest)) {
    /* Don't replace our own networkstatus when we get it from somebody else.*/
    networkstatus_v2_free(ns);
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
    if (!skewed && dirserver_mode(get_options())) {
      /* We got a non-trusted networkstatus, and we're a directory cache.
       * This means that we asked an authority, and it told us about another
       * authority we didn't recognize. */
      log_info(LD_DIR,
               "We do not recognize authority (%s) but we are willing "
               "to cache it.", fp);
      add_networkstatus_to_cache(s, source, ns);
      networkstatus_v2_free(ns);
    }
    return 0;
  }

  found = 0;
  for (i=0; i < smartlist_len(networkstatus_v2_list); ++i) {
    networkstatus_v2_t *old_ns = smartlist_get(networkstatus_v2_list, i);

    if (!memcmp(old_ns->identity_digest, ns->identity_digest, DIGEST_LEN)) {
      if (!memcmp(old_ns->networkstatus_digest,
                  ns->networkstatus_digest, DIGEST_LEN)) {
        /* Same one we had before. */
        networkstatus_v2_free(ns);
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
        networkstatus_v2_free(ns);
        download_status_failed(&trusted_dir->v2_ns_dl_status, 0);
        return 0;
      } else {
        networkstatus_v2_free(old_ns);
        smartlist_set(networkstatus_v2_list, i, ns);
        found = 1;
        break;
      }
    }
  }

  if (source != NS_FROM_CACHE && trusted_dir) {
    download_status_reset(&trusted_dir->v2_ns_dl_status);
  }

  if (!found)
    smartlist_add(networkstatus_v2_list, ns);

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
  networkstatus_v2_list_has_changed = 1;
  router_dir_info_changed();

  smartlist_sort(networkstatus_v2_list,
                 _compare_networkstatus_v2_published_on);

  if (!skewed)
    add_networkstatus_to_cache(s, source, ns);

  return 0;
}

/** Remove all very-old network_status_t objects from memory and from the
 * disk cache. */
void
networkstatus_v2_list_clean(time_t now)
{
  int i;
  if (!networkstatus_v2_list)
    return;

  for (i = 0; i < smartlist_len(networkstatus_v2_list); ++i) {
    networkstatus_v2_t *ns = smartlist_get(networkstatus_v2_list, i);
    char *fname = NULL;
    if (ns->published_on + MAX_NETWORKSTATUS_AGE > now)
      continue;
    /* Okay, this one is too old.  Remove it from the list, and delete it
     * from the cache. */
    smartlist_del(networkstatus_v2_list, i--);
    fname = networkstatus_get_cache_filename(ns->identity_digest);
    if (file_status(fname) == FN_FILE) {
      log_info(LD_DIR, "Removing too-old networkstatus in %s", fname);
      unlink(fname);
    }
    tor_free(fname);
    if (dirserver_mode(get_options())) {
      dirserv_set_cached_networkstatus_v2(NULL, ns->identity_digest, 0);
    }
    networkstatus_v2_free(ns);
    router_dir_info_changed();
  }

  /* And now go through the directory cache for any cached untrusted
   * networkstatuses and other network info. */
  dirserv_clear_old_networkstatuses(now - MAX_NETWORKSTATUS_AGE);
  dirserv_clear_old_v1_info(now);
}

/** Helper for bsearching a list of routerstatus_t pointers: compare a
 * digest in the key to the identity digest of a routerstatus_t. */
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
networkstatus_v2_find_entry(networkstatus_v2_t *ns, const char *digest)
{
  return smartlist_bsearch(ns->entries, digest,
                           _compare_digest_to_routerstatus_entry);
}

/** Return the entry in <b>ns</b> for the identity digest <b>digest</b>, or
 * NULL if none was found. */
routerstatus_t *
networkstatus_vote_find_entry(networkstatus_vote_t *ns, const char *digest)
{
  return smartlist_bsearch(ns->routerstatus_list, digest,
                           _compare_digest_to_routerstatus_entry);
}

/** DOCDOC */
const smartlist_t *
networkstatus_get_v2_list(void)
{
  if (!networkstatus_v2_list)
    networkstatus_v2_list = smartlist_create();
  return networkstatus_v2_list;
}

/** Return the consensus view of the status of the router whose current
 * <i>descriptor</i> digest is <b>digest</b>, or NULL if no such router is
 * known. */
routerstatus_t *
router_get_consensus_status_by_descriptor_digest(const char *digest)
{
  if (!current_consensus) return NULL;
  if (!current_consensus->desc_digest_map) {
    digestmap_t * m = current_consensus->desc_digest_map = digestmap_new();
    SMARTLIST_FOREACH(current_consensus->routerstatus_list,
                      routerstatus_t *, rs,
     {
       digestmap_set(m, rs->descriptor_digest, rs);
     });
  }
  return digestmap_get(current_consensus->desc_digest_map, digest);
}

/** DOCDOC */
download_status_t *
router_get_dl_status_by_descriptor_digest(const char *d)
{
  routerstatus_t *rs;
  if ((rs = router_get_consensus_status_by_descriptor_digest(d)))
    return &rs->dl_status;
  if (v2_download_status_map)
    return digestmap_get(v2_download_status_map, d);

  return NULL;
}

/** Return the consensus view of the status of the router whose identity
 * digest is <b>digest</b>, or NULL if we don't know about any such router. */
routerstatus_t *
router_get_consensus_status_by_id(const char *digest)
{
  if (!current_consensus)
    return NULL;
  return smartlist_bsearch(current_consensus->routerstatus_list, digest,
                           _compare_digest_to_routerstatus_entry);
}

/** Given a nickname (possibly verbose, possibly a hexadecimal digest), return
 * the corresponding routerstatus_t, or NULL if none exists.  Warn the
 * user if <b>warn_if_unnamed</b> is set, and they have specified a router by
 * nickname, but the Named flag isn't set for that router. */
routerstatus_t *
router_get_consensus_status_by_nickname(const char *nickname,
                                       int warn_if_unnamed)
{
  char digest[DIGEST_LEN];
  routerstatus_t *best=NULL;
  smartlist_t *matches=NULL;
  const char *named_id=NULL;

  if (!current_consensus || !nickname)
    return NULL;

  if (nickname[0] == '$') {
    if (base16_decode(digest, DIGEST_LEN, nickname+1, strlen(nickname))<0)
      return NULL;
    return networkstatus_vote_find_entry(current_consensus, digest);
  } else if (strlen(nickname) == HEX_DIGEST_LEN &&
       (base16_decode(digest, DIGEST_LEN, nickname+1, strlen(nickname))==0)) {
    return networkstatus_vote_find_entry(current_consensus, digest);
  }

  if (named_server_map)
    named_id = strmap_get_lc(named_server_map, nickname);
  if (named_id)
    return networkstatus_vote_find_entry(current_consensus, named_id);

  /*XXXX020 is this behavior really what we want? */
  matches = smartlist_create();
  SMARTLIST_FOREACH(current_consensus->routerstatus_list,
                    routerstatus_t *, lrs,
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
update_v2_networkstatus_cache_downloads(time_t now)
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

/** DOCDOC */
static void
update_consensus_networkstatus_downloads(time_t now)
{
  or_options_t *options = get_options();
  if (!networkstatus_get_live_consensus(now))
    time_to_download_next_consensus = now;
  if (time_to_download_next_consensus > now)
    return;
  if (authdir_mode_v3(options))
    return;
  if (!download_status_is_ready(&consensus_dl_status, now, 8))
    return; /*XXXX020 magic number 8.*/
  if (connection_get_by_type_purpose(CONN_TYPE_DIR,
                                     DIR_PURPOSE_FETCH_CONSENSUS))
    return;

  directory_get_from_dirserver(DIR_PURPOSE_FETCH_CONSENSUS,
                               ROUTER_PURPOSE_GENERAL, NULL, 1);
}

/** DOCDOC */
void
networkstatus_consensus_download_failed(int status_code)
{
  download_status_failed(&consensus_dl_status, status_code);
  /* Retry immediately, if appropriate. */
  update_consensus_networkstatus_downloads(time(NULL));
}

/** DOCDOC */
static void
update_consensus_networkstatus_fetch_time(time_t now)
{
  or_options_t *options = get_options();
  /* XXXX020 call this when DirPort switches on or off. NMNM */
  networkstatus_vote_t *c = networkstatus_get_live_consensus(now);
  if (c) {
    time_t start;
    long interval;
    if (dirserver_mode(options)) {
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
    {
      char tbuf[ISO_TIME_LEN+1];
      format_local_iso_time(tbuf, time_to_download_next_consensus);
      log_info(LD_DIR, "Have a live consensus; fetching next one at %s.",tbuf);
    }
  } else {
    time_to_download_next_consensus = now;
    log_info(LD_DIR, "No live consensus; we should fetch one immediately.");
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

/** Launch requests for networkstatus documents and authority certificates as
 * appropriate. */
void
update_networkstatus_downloads(time_t now)
{
  or_options_t *options = get_options();
  if (should_delay_dir_fetches(options))
    return;
  if (dirserver_mode(options))
    update_v2_networkstatus_cache_downloads(now);
  update_consensus_networkstatus_downloads(now);
  if (consensus_waiting_for_certs)
    authority_certs_fetch_missing(consensus_waiting_for_certs, now);
  else
    authority_certs_fetch_missing(current_consensus, now);
}

/** Return the network status with a given identity digest. */
networkstatus_v2_t *
networkstatus_v2_get_by_digest(const char *digest)
{
  SMARTLIST_FOREACH(networkstatus_v2_list, networkstatus_v2_t *, ns,
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

/** DOCDOC */
static void
networkstatus_copy_old_consensus_info(networkstatus_vote_t *new_c,
                                      const networkstatus_vote_t *old_c)
{
  int idx = 0;
  const routerstatus_t *rs_old;
  if (old_c == new_c)
    return;
  if (!smartlist_len(old_c->routerstatus_list))
    return;

  rs_old = smartlist_get(old_c->routerstatus_list, idx);
  SMARTLIST_FOREACH(new_c->routerstatus_list, routerstatus_t *, rs_new,
  {
    int r;
    while ((r = memcmp(rs_old->identity_digest, rs_new->identity_digest,
                       DIGEST_LEN))<0) {
      if (++idx == smartlist_len(old_c->routerstatus_list))
        goto done;
      rs_old = smartlist_get(old_c->routerstatus_list, idx);
    }
    if (r>0)
      continue;
    tor_assert(r==0);

    /* Okay, so we're looking at the same identity. */
    rs_new->name_lookup_warned = rs_old->name_lookup_warned;
    rs_new->last_dir_503_at = rs_old->last_dir_503_at;

    if (!memcmp(rs_old->descriptor_digest, rs_new->descriptor_digest,
                DIGEST_LEN)) {
      /* And the same descriptor too! */
      rs_new->need_to_mirror = rs_old->need_to_mirror; /*XXXX020 NM ????? */
      memcpy(&rs_new->dl_status, &rs_old->dl_status,sizeof(download_status_t));
    }
  });

 done:
  return;
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
  int r, result=-1;
  time_t now = time(NULL);
  char *unverified_fname = NULL, *consensus_fname = NULL;

  /* Make sure it's parseable. */
  c = networkstatus_parse_vote_from_string(consensus, NULL, 0);
  if (!c) {
    log_warn(LD_DIR, "Unable to parse networkstatus consensus");
    goto done;
  }

  consensus_fname = get_datadir_fname("cached-consensus");
  unverified_fname = get_datadir_fname("unverified-consensus");

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
          write_str_to_file(unverified_fname, consensus, 0);
        }
        authority_certs_fetch_missing(c, now);
      } else {
        /* Even if we had enough signatures, we'd never use this as the
         * latest consensus. */
        if (was_waiting_for_certs && from_cache)
          unlink(unverified_fname);
      }
      download_status_reset(&consensus_dl_status); /*XXXX020 not quite right.*/
      result = 0;
      goto done;
    } else {
      /* This can never be signed enough Kill it. */
      if (!was_waiting_for_certs)
        log_warn(LD_DIR, "Not enough good signatures on networkstatus "
                 "consensus");
      if (was_waiting_for_certs && from_cache)
        unlink(unverified_fname);
      networkstatus_vote_free(c);
      goto done;
    }
  }

  download_status_reset(&consensus_dl_status); /*XXXX020 not quite right.*/

  /* Are we missing any certificates at all? */
  if (r != 1)
    authority_certs_fetch_missing(c, now);

  if (current_consensus) {
    networkstatus_copy_old_consensus_info(c, current_consensus);
    networkstatus_vote_free(current_consensus);
  }

  if (consensus_waiting_for_certs &&
      consensus_waiting_for_certs->valid_after <= c->valid_after) {
    networkstatus_vote_free(consensus_waiting_for_certs);
    consensus_waiting_for_certs = NULL;
    if (consensus != consensus_waiting_for_certs_body)
      tor_free(consensus_waiting_for_certs_body);
    unlink(unverified_fname);
  }

  current_consensus = c;

  update_consensus_networkstatus_fetch_time(now);
  dirvote_recalculate_timing(now);
  routerstatus_list_update_named_server_map();

  if (!from_cache) {
    write_str_to_file(consensus_fname, consensus, 0);
  }

  if (dirserver_mode(get_options()))
    dirserv_set_cached_networkstatus_v3(consensus, c->valid_after);

  router_dir_info_changed();

  result = 0;
 done:
  tor_free(consensus_fname);
  tor_free(unverified_fname);
  return result;
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

/** If the network-status list has changed since the last time we called this
 * function, update the status of every routerinfo from the network-status
 * list.
 */
void
routers_update_all_from_networkstatus(time_t now)
{
  routerinfo_t *me;
  routerlist_t *rl = router_get_routerlist();
  networkstatus_vote_t *consensus = networkstatus_get_live_consensus(now);

  router_dir_info_changed(); /*XXXX020 really? */

  if (networkstatus_v2_list_has_changed) {
    routerstatus_list_update_from_v2_networkstatus();
    networkstatus_v2_list_has_changed = 0;
  }

  if (!consensus)
    return;

  routers_update_status_from_consensus_networkstatus(rl->routers, 0);
  SMARTLIST_FOREACH(rl->routers, routerinfo_t *, ri,
                    ri->routerlist_index = ri_sl_idx);
  entry_guards_compute_status();

  me = router_get_my_routerinfo();
  if (me && !have_warned_about_invalid_status) {
    routerstatus_t *rs = networkstatus_vote_find_entry(consensus,
                                        me->cache_info.identity_digest);

    if (!rs) {
      log_info(LD_GENERAL, "The latest consensus does not list us."
               "Are you misconfigured?");
      have_warned_about_invalid_status = 1;
    } else if (!rs->is_named) {
      /*XXXX020 this isn't a correct warning. */
      log_info(LD_GENERAL,  "The directory authorities do not recognize "
               "your nickname. Please consider sending your "
               "nickname and identity fingerprint to the tor-ops.");
      have_warned_about_invalid_status = 1;
    }
  }

  if (!have_warned_about_old_version) {
    int is_server = server_mode(get_options());
    version_status_t status;
    const char *recommended = is_server ?
      consensus->server_versions : consensus->client_versions;
    status = tor_version_is_obsolete(VERSION, recommended);

    if (status == VS_RECOMMENDED) {
      log_info(LD_GENERAL, "The directory authorities say my version is ok.");
    } else if (status == VS_NEW || status == VS_NEW_IN_SERIES) {
      if (!have_warned_about_new_version) {
        log_notice(LD_GENERAL, "This version of Tor (%s) is newer than any "
                   "recommended version%s, according to the directory "
                   "authorities. Recommended versions are: %s",
                   VERSION,
                   status == VS_NEW_IN_SERIES ? " in its series" : "",
                   recommended);
        have_warned_about_new_version = 1;
        control_event_general_status(LOG_WARN, "DANGEROUS_VERSION "
                                     "CURRENT=%s REASON=%s RECOMMENDED=\"%s\"",
                                     VERSION, "NEW", recommended);
      }
    } else {
      log_warn(LD_GENERAL, "Please upgrade! "
               "This version of Tor (%s) is %s, according to the directory "
               "authorities. Recommended versions are: %s",
               VERSION,
               status == VS_OLD ? "obsolete" : "not recommended",
               recommended);
      have_warned_about_old_version = 1;
      control_event_general_status(LOG_WARN, "DANGEROUS_VERSION "
           "CURRENT=%s REASON=%s RECOMMENDED=\"%s\"",
           VERSION, status == VS_OLD ? "OLD" : "UNRECOMMENDED",
           recommended);
    }
  }
}

/** DOCDOC */
static void
routerstatus_list_update_from_v2_networkstatus(void)
{
  digestmap_t *dl_status;
  if (!networkstatus_v2_list)
    return;
  if (!v2_download_status_map)
    v2_download_status_map = digestmap_new();

  dl_status = digestmap_new();
  SMARTLIST_FOREACH(networkstatus_v2_list, networkstatus_v2_t *, ns,
  {
    SMARTLIST_FOREACH(ns->entries, routerstatus_t *, rs,
    {
      const char *d = rs->descriptor_digest;
      download_status_t *s;
      if (digestmap_get(dl_status, d))
        continue;
      if (!(s = digestmap_remove(v2_download_status_map, d))) {
        s = tor_malloc_zero(sizeof(download_status_t));
      }
      digestmap_set(dl_status, d, s);
    });
  });
  digestmap_free(v2_download_status_map, _tor_free);
  v2_download_status_map = dl_status;
}

/** Update our view of router status (as stored in routerstatus_list) from the
 * current set of network status documents (as stored in networkstatus_list).
 * Do nothing unless the network status list has changed since the last time
 * this function was called. DOCDOC
 */
static void
routerstatus_list_update_named_server_map(void)
{
  if (!current_consensus)
    return;

  if (named_server_map)
    strmap_free(named_server_map, _tor_free);
  named_server_map = strmap_new();
  SMARTLIST_FOREACH(current_consensus->routerstatus_list, routerstatus_t *, rs,
    {
      if (rs->is_named) {
        strmap_set(named_server_map, rs->nickname,
                   tor_memdup(rs->identity_digest, DIGEST_LEN));
      }
    });
}

/** Given a list <b>routers</b> of routerinfo_t *, update each routers's
 * is_named, is_valid, and is_running fields according to our current
 * networkstatus_t documents.  May re-order <b>router</b>. DOCDOC */
void
routers_update_status_from_consensus_networkstatus(smartlist_t *routers,
                                                   int reset_failures)
{
  trusted_dir_server_t *ds;
  routerstatus_t *rs;
  or_options_t *options = get_options();
  int authdir = authdir_mode_v2(options) || authdir_mode_v3(options);
  int namingdir = authdir && options->NamingAuthoritativeDir;
  networkstatus_vote_t *ns = current_consensus;
  int idx;
  if (!ns || !smartlist_len(ns->routerstatus_list))
    return;

  routers_sort_by_identity(routers);
  /* Now routers and ns->routerstatus_list are both in ascending order
   * of identity digest. */
  idx = 0;
  rs = smartlist_get(ns->routerstatus_list, idx);

  SMARTLIST_FOREACH(routers, routerinfo_t *, router,
  {
    const char *digest = router->cache_info.identity_digest;
    int r;
    while ((r = memcmp(rs->identity_digest, digest, DIGEST_LEN))<0) {
      if (++idx == smartlist_len(ns->routerstatus_list)) {
        /* We're out of routerstatuses. Bail. */
        goto done;
      }
      rs = smartlist_get(ns->routerstatus_list, idx);
    }
    if (r>0) {
      /* We have no routerstatus for this router. Clear flags and skip it. */
      if (!namingdir)
        router->is_named = 0;
      if (!authdir) {
        if (router->purpose == ROUTER_PURPOSE_GENERAL) {
          router->is_valid = router->is_running =
            router->is_fast = router->is_stable =
            router->is_possible_guard = router->is_exit =
            router->is_bad_exit = 0;
        }
      }
      continue;
    }
    tor_assert(r==0);

    ds = router_get_trusteddirserver_by_digest(digest);

    if (!namingdir) {
      if (rs->is_named && !strcasecmp(router->nickname, rs->nickname))
        router->is_named = 1;
      else
        router->is_named = 0;
    }

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

 done:
  router_dir_info_changed();
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

  if (!current_consensus) {
    *answer = tor_strdup("");
    return 0;
  }

  if (!strcmp(question, "ns/all")) {
    smartlist_t *statuses = smartlist_create();
    SMARTLIST_FOREACH(current_consensus->routerstatus_list,
                      routerstatus_t *, rs,
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
    status = router_get_consensus_status_by_id(d);
  } else if (!strcmpstart(question, "ns/name/")) {
    status = router_get_consensus_status_by_nickname(question+8, 0);
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
  if (networkstatus_v2_list) {
    SMARTLIST_FOREACH(networkstatus_v2_list, networkstatus_v2_t *, ns,
                      networkstatus_v2_free(ns));
    smartlist_free(networkstatus_v2_list);
    networkstatus_v2_list = NULL;
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

