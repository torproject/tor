/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2007, Roger Dingledine, Nick Mathewson. */
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

// #define DEBUG_ROUTERLIST

/****************************************************************************/

/* static function prototypes */
static routerstatus_t *router_pick_directory_server_impl(int requireother,
                                                     int fascistfirewall,
                                                     int prefer_tunnel,
                                                     authority_type_t auth);
static routerstatus_t *router_pick_trusteddirserver_impl(
                 authority_type_t type, int requireother,
                 int fascistfirewall, int prefer_tunnel);
static void mark_all_trusteddirservers_up(void);
static int router_nickname_matches(routerinfo_t *router, const char *nickname);
static void trusted_dir_server_free(trusted_dir_server_t *ds);
static void launch_router_descriptor_downloads(smartlist_t *downloadable,
                                               time_t now);
static void update_consensus_router_descriptor_downloads(time_t now);
static int signed_desc_digest_is_recognized(signed_descriptor_t *desc);
static void update_router_have_minimum_dir_info(void);
static const char *signed_descriptor_get_body_impl(signed_descriptor_t *desc,
                                                   int with_annotations);
static void list_pending_downloads(digestmap_t *result,
                                   int purpose, const char *prefix);

DECLARE_TYPED_DIGESTMAP_FNS(sdmap_, digest_sd_map_t, signed_descriptor_t)
DECLARE_TYPED_DIGESTMAP_FNS(rimap_, digest_ri_map_t, routerinfo_t)
DECLARE_TYPED_DIGESTMAP_FNS(eimap_, digest_ei_map_t, extrainfo_t)

/****************************************************************************/

/** Global list of a trusted_dir_server_t object for each trusted directory
 * server. */
static smartlist_t *trusted_dir_servers = NULL;
/** True iff the key certificate in at least one member of
 * <b>trusted_dir_server_t</b> has changed since we last flushed the
 * certificates to disk. */
static int trusted_dir_servers_certs_changed = 0;

/** Global list of all of the routers that we know about. */
static routerlist_t *routerlist = NULL;

/** List of strings for nicknames we've already warned about and that are
 * still unknown / unavailable. */
static smartlist_t *warned_nicknames = NULL;

/** The last time we tried to download any routerdesc, or 0 for "never".  We
 * use this to rate-limit download attempts when the number of routerdescs to
 * download is low. */
static time_t last_routerdesc_download_attempted = 0;

/** Return the number of directory authorities whose type matches some bit set
 * in <b>type</b>  */
int
get_n_authorities(authority_type_t type)
{
  int n = 0;
  if (!trusted_dir_servers)
    return 0;
  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
                    if (ds->type & type)
                      ++n);
  return n;
}

#define get_n_v2_authorities() get_n_authorities(V2_AUTHORITY)

/** Reload the cached v3 key certificates from the cached-certs file in
 * the data directory. Return 0 on success, -1 on failure. */
int
trusted_dirs_reload_certs(void)
{
  char filename[512];
  char *contents;
  int r;

  tor_snprintf(filename,sizeof(filename),"%s"PATH_SEPARATOR"cached-certs",
               get_options()->DataDirectory);
  contents = read_file_to_str(filename, RFTS_IGNORE_MISSING, NULL);
  if (!contents)
    return 0;
  r = trusted_dirs_load_certs_from_string(contents, 1);
  log_notice(LD_DIR, "Loaded %d certs from cache.", r);
  tor_free(contents);
  return r;
}

/** Load a bunch of new key certificates from the string <b>contents</b>.  If
 * <b>from_store</b> is true, the certificates are from the cache, and we
 * don't need to flush them to disk.  If <b>from_store</b> is false, we need
 * to flush any changed certificates to disk.  Return 0 on success, -1 on
 * failure. */
int
trusted_dirs_load_certs_from_string(const char *contents, int from_store)
{
  trusted_dir_server_t *ds;
  const char *s, *eos;

  for (s = contents; *s; s = eos) {
    authority_cert_t *cert = authority_cert_parse_from_string(s, &eos);
    int found = 0;
    if (!cert)
      break;
    ds = trusteddirserver_get_by_v3_auth_digest(
                                       cert->cache_info.identity_digest);
    if (!ds) {
      log_info(LD_DIR, "Found cached certificate whose key didn't match "
               "any v3 authority we recognized; skipping.");
      authority_cert_free(cert);
      continue;
    }
    if (!ds->v3_certs)
      ds->v3_certs = smartlist_create();

    SMARTLIST_FOREACH(ds->v3_certs, authority_cert_t *, c,
      {
        if (!memcmp(c->cache_info.signed_descriptor_digest,
                    cert->cache_info.signed_descriptor_digest,
                    DIGEST_LEN)) {
          /* we already have this one. continue. */
          authority_cert_free(cert);
          found = 1;
          break;
        }
      });

    if (found)
      continue;

    cert->cache_info.signed_descriptor_body = tor_strndup(s, eos-s);
    cert->cache_info.signed_descriptor_len = eos-s;
    smartlist_add(ds->v3_certs, cert);

    if (!from_store)
      trusted_dir_servers_certs_changed = 1;
  }

  trusted_dirs_flush_certs_to_disk();

  networkstatus_note_certs_arrived();
  return 0;
}

/** Save all v3 key certifiacates to the cached-certs file. */
void
trusted_dirs_flush_certs_to_disk(void)
{
  char filename[512];
  smartlist_t *chunks;

  if (!trusted_dir_servers_certs_changed)
    return;

  chunks = smartlist_create();

  tor_snprintf(filename,sizeof(filename),"%s"PATH_SEPARATOR"cached-certs",
               get_options()->DataDirectory);
  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
  {
      if (ds->v3_certs) {
        SMARTLIST_FOREACH(ds->v3_certs, authority_cert_t *, cert,
          {
            sized_chunk_t *c = tor_malloc(sizeof(sized_chunk_t));
            c->bytes = cert->cache_info.signed_descriptor_body;
            c->len = cert->cache_info.signed_descriptor_len;
            smartlist_add(chunks, c);
          });
      }
  });
  if (write_chunks_to_file(filename, chunks, 0)) {
    log_warn(LD_FS, "Error writing certificates to disk.");
  }
  SMARTLIST_FOREACH(chunks, sized_chunk_t *, c, tor_free(c));
  smartlist_free(chunks);

  trusted_dir_servers_certs_changed = 0;
}

/** Remove all v3 authority certificates that have been superseded for more
 * than 48 hours.  (If the most recent cert was published more than 48 hours
 * ago, then we aren't going to get any consensuses signed with older
 * keys.) */
static void
trusted_dirs_remove_old_certs(void)
{
#define OLD_CERT_LIFETIME (48*60*60)
  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
    {
      authority_cert_t *newest = NULL;
      if (!ds->v3_certs)
        continue;
      SMARTLIST_FOREACH(ds->v3_certs, authority_cert_t *, cert,
          if (!newest || (cert->cache_info.published_on >
                          newest->cache_info.published_on))
            newest = cert);
      SMARTLIST_FOREACH(ds->v3_certs, authority_cert_t *, cert,
          if (newest && (newest->cache_info.published_on >
                         cert->cache_info.published_on + OLD_CERT_LIFETIME)) {
            SMARTLIST_DEL_CURRENT(ds->v3_certs, cert);
            authority_cert_free(cert);
            trusted_dir_servers_certs_changed = 1;
          });
    });
#undef OLD_CERT_LIFETIME

  trusted_dirs_flush_certs_to_disk();
}

/** Return the newest v3 authority certificate whose v3 authority identity key
 * has digest <b>id_digest</b>.  Return NULL if no such authority is known,
 * or it has no certificate. */
authority_cert_t *
authority_cert_get_newest_by_id(const char *id_digest)
{
  trusted_dir_server_t *ds = trusteddirserver_get_by_v3_auth_digest(id_digest);
  authority_cert_t *best = NULL;
  if (!ds || !ds->v3_certs)
    return NULL;
  SMARTLIST_FOREACH(ds->v3_certs, authority_cert_t *, cert,
  {
    if (!best || cert->cache_info.published_on > best->cache_info.published_on)
      best = cert;
  });
  return best;
}

/** Return the newest v3 authority certificate whose directory signing key has
 * giest <sk_digest</b>. Return NULL if no such certificate is known.
 */
authority_cert_t *
authority_cert_get_by_sk_digest(const char *sk_digest)
{
  if (!trusted_dir_servers)
    return NULL;
  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
  {
    if (!ds->v3_certs)
      continue;
    SMARTLIST_FOREACH(ds->v3_certs, authority_cert_t *, cert,
    {
      if (!memcmp(cert->signing_key_digest, sk_digest, DIGEST_LEN))
        return cert;
    });
  });
  return NULL;
}

/** Return the v3 authority certificate with signing key matching
 * <b>sk_digest</b>, for the authority with identity digest <b>id_digest</b>.
 * Return NULL if no such authority is known. */
authority_cert_t *
authority_cert_get_by_digests(const char *id_digest,
                              const char *sk_digest)
{
  trusted_dir_server_t *ds = trusteddirserver_get_by_v3_auth_digest(id_digest);

  if (!ds || !ds->v3_certs)
    return NULL;
  SMARTLIST_FOREACH(ds->v3_certs, authority_cert_t *, cert,
    if (!memcmp(cert->signing_key_digest, sk_digest, DIGEST_LEN))
      return cert; );

  return NULL;
}

/** How many times will we try to fetch a certificate before giving up? */
#define MAX_CERT_DL_FAILURES 8

/** Try to download any v3 authority certificates that we may be missing.  If
 * <b>status</b> is provided, try to get all the ones that were used to sign
 * <b>status</b>.  Additionally, try to have a non-expired certificate for
 * every V3 authority in trusted_dir_servers.  Don't fetch certificates we
 * already have.
 **/
void
authority_certs_fetch_missing(networkstatus_vote_t *status, time_t now)
{
  digestmap_t *pending = digestmap_new();
  smartlist_t *missing_digests = smartlist_create();
  char *resource = NULL;

  list_pending_downloads(pending, DIR_PURPOSE_FETCH_CERTIFICATE, "fp/");
  if (status) {
    SMARTLIST_FOREACH(status->voters, networkstatus_voter_info_t *, voter,
      {
        trusted_dir_server_t *ds
          = trusteddirserver_get_by_v3_auth_digest(voter->identity_digest);
        if (!ds)
          continue;
        if (authority_cert_get_by_digests(voter->identity_digest,
                                          voter->signing_key_digest)) {
          download_status_reset(&ds->cert_dl_status);
          continue;
        }
        if (download_status_is_ready(&ds->cert_dl_status, now,
                                     MAX_CERT_DL_FAILURES))
          smartlist_add(missing_digests, voter->identity_digest);
      });
  }
  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
    {
      int found = 0;
      if (!(ds->type & V3_AUTHORITY))
        continue;
      if (smartlist_digest_isin(missing_digests, ds->v3_identity_digest))
        continue;
      if (!ds->v3_certs)
        ds->v3_certs = smartlist_create();
      SMARTLIST_FOREACH(ds->v3_certs, authority_cert_t *, cert,
        {
          if (!ftime_definitely_after(now, cert->expires)) {
            /* It's not expired, and we weren't looking for something to
             * verify a consensus with.  Call it done. */
            download_status_reset(&ds->cert_dl_status);
            found = 1;
            break;
          }
        });
      if (!found && download_status_is_ready(&ds->cert_dl_status, now,
                                             MAX_CERT_DL_FAILURES))
        smartlist_add(missing_digests, ds->v3_identity_digest);
    });

  if (!smartlist_len(missing_digests)) {
    goto done;
  } else {
    smartlist_t *fps = smartlist_create();
    smartlist_add(fps, tor_strdup("fp/"));
    SMARTLIST_FOREACH(missing_digests, const char *, d, {
        char *fp;
        if (digestmap_get(pending, d))
          continue;
        fp = tor_malloc(HEX_DIGEST_LEN+2);
        base16_encode(fp, HEX_DIGEST_LEN+1, d, DIGEST_LEN);
        fp[HEX_DIGEST_LEN] = '+';
        fp[HEX_DIGEST_LEN+1] = '\0';
        smartlist_add(fps, fp);
      });
    resource = smartlist_join_strings(fps, "", 0, NULL);
    resource[strlen(resource)-1] = '\0';
    SMARTLIST_FOREACH(fps, char *, cp, tor_free(cp));
    smartlist_free(fps);
  }
  log_notice(LD_DIR, "Launching request for %d missing certificates",
             smartlist_len(missing_digests));
  directory_get_from_dirserver(DIR_PURPOSE_FETCH_CERTIFICATE, 0,
                               resource, 1);

 done:
  tor_free(resource);
  smartlist_free(missing_digests);
  digestmap_free(pending, NULL);
}

/* Router descriptor storage.
 *
 * Routerdescs are stored in a big file, named "cached-descriptors".  As new
 * routerdescs arrive, we append them to a journal file named
 * "cached-descriptors.new".
 *
 * From time to time, we replace "cached-descriptors" with a new file
 * containing only the live, non-superseded descriptors, and clear
 * cached-routers.new.
 *
 * On startup, we read both files.
 */

/** Helper: return 1 iff the router log is so big we want to rebuild the
 * store. */
static int
router_should_rebuild_store(desc_store_t *store)
{
  if (store->store_len > (1<<16))
    return (store->journal_len > store->store_len / 2 ||
            store->bytes_dropped > store->store_len / 2);
  else
    return store->journal_len > (1<<15);
}

static INLINE desc_store_t *
desc_get_store(routerlist_t *rl, signed_descriptor_t *sd)
{
  if (sd->is_extrainfo)
    return &rl->extrainfo_store;
  else
    return &rl->desc_store;
}

static INLINE desc_store_t *
router_get_store(routerlist_t *rl, routerinfo_t *ri)
{
  return desc_get_store(rl, &ri->cache_info);
}

/** Add the signed_descriptor_t in <b>desc</b> to the router
 * journal; change its saved_location to SAVED_IN_JOURNAL and set its
 * offset appropriately.
 *
 * If <b>purpose</b> isn't ROUTER_PURPOSE_GENERAL or
 * EXTRAINFO_PURPOSE_GENERAL, just do nothing. */
static int
signed_desc_append_to_journal(signed_descriptor_t *desc,
                              desc_store_t *store,
                              int purpose) // XXXX NM Nuke purpose.
{
  or_options_t *options = get_options();
  size_t fname_len = strlen(options->DataDirectory)+32;
  char *fname;
  const char *body = signed_descriptor_get_body_impl(desc,1);
  size_t len = desc->signed_descriptor_len + desc->annotations_len;

  /* XXXX020 remove this; we can now cache things with weird purposes. */
  if (purpose != ROUTER_PURPOSE_GENERAL &&
      purpose != EXTRAINFO_PURPOSE_GENERAL) {
    /* we shouldn't cache it. be happy and return. */
    return 0;
  }

  fname = tor_malloc(fname_len);
  tor_snprintf(fname, fname_len, "%s"PATH_SEPARATOR"%s.new",
               options->DataDirectory, store->fname_base);

  tor_assert(len == strlen(body));

  if (append_bytes_to_file(fname, body, len, 1)) {
    log_warn(LD_FS, "Unable to store router descriptor");
    tor_free(fname);
    return -1;
  }
  desc->saved_location = SAVED_IN_JOURNAL;
  tor_free(fname);

  desc->saved_offset = store->journal_len;
  store->journal_len += len;

  return 0;
}

/** Sorting helper: return &lt;0, 0, or &gt;0 depending on whether the
 * signed_descriptor_t* in *<b>a</b> is older, the same age as, or newer than
 * the signed_descriptor_t* in *<b>b</b>. */
static int
_compare_signed_descriptors_by_age(const void **_a, const void **_b)
{
  const signed_descriptor_t *r1 = *_a, *r2 = *_b;
  return r1->published_on - r2->published_on;
}

/** If the journal is too long, or if <b>force</b> is true, then atomically
 * replace the router store with the routers currently in our routerlist, and
 * clear the journal.  Return 0 on success, -1 on failure.
 *
 * If <b>extrainfo</b> is true, rebuild the extrainfo store; else rebuild the
 * router descriptor store.
 */
static int
router_rebuild_store(int force, desc_store_t *store)
{
  or_options_t *options;
  size_t fname_len;
  smartlist_t *chunk_list = NULL;
  char *fname = NULL, *fname_tmp = NULL;
  int r = -1;
  off_t offset = 0;
  smartlist_t *signed_descriptors = NULL;

  if (!force && !router_should_rebuild_store(store))
    return 0;
  if (!routerlist)
    return 0;

  routerlist_assert_ok(routerlist);

  /* Don't save deadweight. */
  routerlist_remove_old_routers();

  log_info(LD_DIR, "Rebuilding %s cache", store->description);

  options = get_options();
  fname_len = strlen(options->DataDirectory)+32;
  fname = tor_malloc(fname_len);
  fname_tmp = tor_malloc(fname_len);
  tor_snprintf(fname, fname_len, "%s"PATH_SEPARATOR"%s",
               options->DataDirectory, store->fname_base);
  tor_snprintf(fname_tmp, fname_len, "%s"PATH_SEPARATOR"%s.tmp",
               options->DataDirectory, store->fname_base);

  chunk_list = smartlist_create();

  /* We sort the routers by age to enhance locality on disk. */
  signed_descriptors = smartlist_create();
  if (store->type == EXTRAINFO_STORE) {
    eimap_iter_t *iter;
    for (iter = eimap_iter_init(routerlist->extra_info_map);
         !eimap_iter_done(iter);
         iter = eimap_iter_next(routerlist->extra_info_map, iter)) {
      const char *key;
      extrainfo_t *ei;
      eimap_iter_get(iter, &key, &ei);
      smartlist_add(signed_descriptors, &ei->cache_info);
    }
  } else {
    SMARTLIST_FOREACH(routerlist->old_routers, signed_descriptor_t *, sd,
                      if (desc_get_store(routerlist, sd) == store)
                        smartlist_add(signed_descriptors, sd));
    SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, ri,
                      if (router_get_store(routerlist, ri) == store)
                        smartlist_add(signed_descriptors, &ri->cache_info));
  }

  smartlist_sort(signed_descriptors, _compare_signed_descriptors_by_age);

  /* Now, add the appropriate members to chunk_list */
  SMARTLIST_FOREACH(signed_descriptors, signed_descriptor_t *, sd,
    {
      sized_chunk_t *c;
      const char *body = signed_descriptor_get_body_impl(sd, 1);
      if (!body) {
        log_warn(LD_BUG, "No descriptor available for router.");
        goto done;
      }
      if (sd->do_not_cache)
        continue;
      c = tor_malloc(sizeof(sized_chunk_t));
      c->bytes = body;
      c->len = sd->signed_descriptor_len + sd->annotations_len;
      smartlist_add(chunk_list, c);
    });

  if (write_chunks_to_file(fname_tmp, chunk_list, 1)<0) {
    log_warn(LD_FS, "Error writing router store to disk.");
    goto done;
  }

  /* Our mmap is now invalid. */
  if (store->mmap) {
    tor_munmap_file(store->mmap);
    store->mmap = NULL;
  }

  if (replace_file(fname_tmp, fname)<0) {
    log_warn(LD_FS, "Error replacing old router store.");
    goto done;
  }

  store->mmap = tor_mmap_file(fname);
  if (! store->mmap)
    log_warn(LD_FS, "Unable to mmap new descriptor file at '%s'.",fname);

  log_info(LD_DIR, "Reconstructing pointers into cache");

  offset = 0;
  SMARTLIST_FOREACH(signed_descriptors, signed_descriptor_t *, sd,
    {
      if (sd->do_not_cache)
        continue;
      sd->saved_location = SAVED_IN_CACHE;
      if (store->mmap) {
        tor_free(sd->signed_descriptor_body); // sets it to null
        sd->saved_offset = offset;
      }
      offset += sd->signed_descriptor_len + sd->annotations_len;
      signed_descriptor_get_body(sd); /* reconstruct and assert */
    });

  tor_snprintf(fname, fname_len, "%s"PATH_SEPARATOR"%s.new",
               options->DataDirectory, store->fname_base);

  write_str_to_file(fname, "", 1);

  r = 0;
  store->store_len = (size_t) offset;
  store->journal_len = 0;
  store->bytes_dropped = 0;
 done:
  if (signed_descriptors)
    smartlist_free(signed_descriptors);
  tor_free(fname);
  tor_free(fname_tmp);
  SMARTLIST_FOREACH(chunk_list, sized_chunk_t *, c, tor_free(c));
  smartlist_free(chunk_list);

  return r;
}

/** Helper: Reload a cache file and its associated journal, setting metadata
 * appropriately.  If <b>extrainfo</b> is true, reload the extrainfo store;
 * else reload the router descriptor store. */
static int
router_reload_router_list_impl(desc_store_t *store)
{
  or_options_t *options = get_options();
  size_t fname_len = strlen(options->DataDirectory)+32;
  char *fname = tor_malloc(fname_len), *altname = NULL,
    *contents = NULL;
  struct stat st;
  int read_from_old_location = 0;
  int extrainfo = (store->type == EXTRAINFO_STORE);
  store->journal_len = store->store_len = 0;

  tor_snprintf(fname, fname_len, "%s"PATH_SEPARATOR"%s",
               options->DataDirectory, store->fname_base);
  if (store->fname_alt_base) {
    altname = tor_malloc(fname_len);
    tor_snprintf(altname, fname_len, "%s"PATH_SEPARATOR"%s",
                 options->DataDirectory, store->fname_alt_base);
  }

  if (store->mmap) /* get rid of it first */
    tor_munmap_file(store->mmap);
  store->mmap = NULL;

  store->mmap = tor_mmap_file(fname);
  if (!store->mmap && altname && file_status(altname) == FN_FILE) {
    read_from_old_location = 1;
    log_notice(LD_DIR, "Couldn't read %s; trying to load routers from old "
               "location %s.", fname, altname);
    if ((store->mmap = tor_mmap_file(altname)))
      read_from_old_location = 1;
  }
  if (store->mmap) {
    store->store_len = store->mmap->size;
    if (extrainfo)
      router_load_extrainfo_from_string(store->mmap->data,
                                        store->mmap->data+store->mmap->size,
                                        SAVED_IN_CACHE, NULL, 0);
    else
      router_load_routers_from_string(store->mmap->data,
                                      store->mmap->data+store->mmap->size,
                                      SAVED_IN_CACHE, NULL, 0, NULL);
  }

  tor_snprintf(fname, fname_len, "%s"PATH_SEPARATOR"%s.new",
               options->DataDirectory, store->fname_base);
  if (file_status(fname) == FN_FILE)
    contents = read_file_to_str(fname, RFTS_BIN|RFTS_IGNORE_MISSING, &st);
  if (!contents && read_from_old_location) {
    tor_snprintf(altname, fname_len, "%s"PATH_SEPARATOR"%s.new",
                 options->DataDirectory, store->fname_alt_base);
    contents = read_file_to_str(altname, RFTS_BIN|RFTS_IGNORE_MISSING, &st);
  }
  if (contents) {
    if (extrainfo)
      router_load_extrainfo_from_string(contents, NULL,SAVED_IN_JOURNAL,
                                        NULL, 0);
    else
      router_load_routers_from_string(contents, NULL, SAVED_IN_JOURNAL,
                                      NULL, 0, NULL);
    store->journal_len = (size_t) st.st_size;
    tor_free(contents);
  }

  tor_free(fname);
  tor_free(altname);

  if (store->journal_len || read_from_old_location) {
    /* Always clear the journal on startup.*/
    router_rebuild_store(1, store);
  } else if (!extrainfo) {
    /* Don't cache expired routers. (This is in an else because
     * router_rebuild_store() also calls remove_old_routers().) */
    routerlist_remove_old_routers();
  }

  return 0;
}

/** Load all cached router descriptors and extra-info documents from the
 * store. Return 0 on success and -1 on failure.
 */
int
router_reload_router_list(void)
{
  routerlist_t *rl = router_get_routerlist();
  if (router_reload_router_list_impl(&rl->desc_store))
    return -1;
  if (router_reload_router_list_impl(&rl->extrainfo_store))
    return -1;
  if (trusted_dirs_reload_certs())
    return -1;
  return 0;
}

/** Return a smartlist containing a list of trusted_dir_server_t * for all
 * known trusted dirservers.  Callers must not modify the list or its
 * contents.
 */
smartlist_t *
router_get_trusted_dir_servers(void)
{
  if (!trusted_dir_servers)
    trusted_dir_servers = smartlist_create();

  return trusted_dir_servers;
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
                             authority_type_t type,
                             int retry_if_no_servers)
{
  routerstatus_t *choice;
  int prefer_tunnel = get_options()->PreferTunneledDirConns;

  if (!routerlist)
    return NULL;

  choice = router_pick_directory_server_impl(requireother, fascistfirewall,
                                             prefer_tunnel, type);
  if (choice || !retry_if_no_servers)
    return choice;

  log_info(LD_DIR,
           "No reachable router entries for dirservers. "
           "Trying them all again.");
  /* mark all authdirservers as up again */
  mark_all_trusteddirservers_up();
  /* try again */
  choice = router_pick_directory_server_impl(requireother, fascistfirewall,
                                             prefer_tunnel, type);
  if (choice)
    return choice;

  log_info(LD_DIR,"Still no %s router entries. Reloading and trying again.",
           fascistfirewall ? "reachable" : "known");
  if (router_reload_router_list()) {
    return NULL;
  }
  /* give it one last try */
  choice = router_pick_directory_server_impl(requireother, fascistfirewall,
                                             prefer_tunnel, type);
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

/** Return the trusted_dir_server_t for the directory authority whose identity
 * key hashes to <b>digest</b>, or NULL if no such authority is known.
 */
trusted_dir_server_t *
trusteddirserver_get_by_v3_auth_digest(const char *digest)
{
  if (!trusted_dir_servers)
    return NULL;

  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
     {
       if (!memcmp(ds->v3_identity_digest, digest, DIGEST_LEN))
         return ds;
     });

  return NULL;
}

/** Try to find a running trusted dirserver. If there are no running
 * trusted dirservers and <b>retry_if_no_servers</b> is non-zero,
 * set them all as running again, and try again.
 * <b>type> specifies the type of authoritative dir we require.
 * Other args are as in router_pick_trusteddirserver_impl().
 */
routerstatus_t *
router_pick_trusteddirserver(authority_type_t type,
                             int requireother,
                             int fascistfirewall,
                             int retry_if_no_servers)
{
  routerstatus_t *choice;
  int prefer_tunnel = get_options()->PreferTunneledDirConns;

  choice = router_pick_trusteddirserver_impl(type, requireother,
                                fascistfirewall, prefer_tunnel);
  if (choice || !retry_if_no_servers)
    return choice;

  log_info(LD_DIR,
           "No trusted dirservers are reachable. Trying them all again.");
  mark_all_trusteddirservers_up();
  return router_pick_trusteddirserver_impl(type, requireother,
                              fascistfirewall, prefer_tunnel);
}

/** How long do we avoid using a directory server after it's given us a 503? */
#define DIR_503_TIMEOUT (60*60)

/** Pick a random running valid directory server/mirror from our
 * routerlist.
 *
 * If <b>fascistfirewall</b>, make sure the router we pick is allowed
 * by our firewall options.
 * If <b>requireother</b>, it cannot be us. If <b>for_v2_directory</b>,
 * choose a directory server new enough to support the v2 directory
 * functionality.
 * If <b>prefer_tunnel</b>, choose a directory server that is reachable
 * and supports BEGIN_DIR cells, if possible.
 *
 * Don't pick an authority if any non-authorities are viable. Try to
 * avoid using servers that are overloaded (have returned 503 recently).
 */
static routerstatus_t *
router_pick_directory_server_impl(int requireother, int fascistfirewall,
                                  int prefer_tunnel, authority_type_t type)
{
  routerstatus_t *result;
  smartlist_t *direct, *tunnel;
  smartlist_t *trusted_direct, *trusted_tunnel;
  smartlist_t *overloaded_direct, *overloaded_tunnel;
  time_t now = time(NULL);
  const smartlist_t *routerstatus_list = networkstatus_get_all_statuses();

  direct = smartlist_create();
  tunnel = smartlist_create();
  trusted_direct = smartlist_create();
  trusted_tunnel = smartlist_create();
  overloaded_direct = smartlist_create();
  overloaded_tunnel = smartlist_create();

  /* Find all the running dirservers we know about. */
  SMARTLIST_FOREACH(routerstatus_list, routerstatus_t *, status,
  {
    int is_trusted;
    int is_overloaded = status->last_dir_503_at + DIR_503_TIMEOUT > now;
    if (!status->is_running || !status->dir_port || !status->is_valid)
      continue;
    if (status->is_bad_directory)
      continue;
    if (requireother && router_digest_is_me(status->identity_digest))
      continue;
    if (type & V3_AUTHORITY) {
      if (!(status->version_supports_v3_dir ||
            router_digest_is_trusted_dir_type(status->identity_digest,
                                              V3_AUTHORITY)))
        continue;
    }
    is_trusted = router_digest_is_trusted_dir(status->identity_digest);
    if ((type & V2_AUTHORITY) && !(status->is_v2_dir || is_trusted))
      continue;
    if ((type & EXTRAINFO_CACHE) &&
        !router_supports_extrainfo(status->identity_digest, 0))
      continue;
    if (prefer_tunnel &&
        status->version_supports_begindir &&
        (!fascistfirewall ||
         fascist_firewall_allows_address_or(status->addr, status->or_port)))
      smartlist_add(is_trusted ? trusted_tunnel :
                      is_overloaded ? overloaded_tunnel : tunnel, status);
    else if (!fascistfirewall ||
             fascist_firewall_allows_address_dir(status->addr,
                                                 status->dir_port))
      smartlist_add(is_trusted ? trusted_direct :
                      is_overloaded ? overloaded_direct : direct, status);
  });

  if (smartlist_len(tunnel)) {
    result = routerstatus_sl_choose_by_bandwidth(tunnel);
  } else if (smartlist_len(overloaded_tunnel)) {
    result = routerstatus_sl_choose_by_bandwidth(overloaded_tunnel);
  } else if (smartlist_len(trusted_tunnel)) {
    /* FFFF We don't distinguish between trusteds and overloaded trusteds
     * yet. Maybe one day we should. */
    /* FFFF We also don't load balance over authorities yet. I think this
     * is a feature, but it could easily be a bug. -RD */
    result = smartlist_choose(trusted_tunnel);
  } else if (smartlist_len(direct)) {
    result = routerstatus_sl_choose_by_bandwidth(direct);
  } else if (smartlist_len(overloaded_direct)) {
    result = routerstatus_sl_choose_by_bandwidth(overloaded_direct);
  } else {
    result = smartlist_choose(trusted_direct);
  }
  smartlist_free(direct);
  smartlist_free(tunnel);
  smartlist_free(trusted_direct);
  smartlist_free(trusted_tunnel);
  smartlist_free(overloaded_direct);
  smartlist_free(overloaded_tunnel);
  return result;
}

/** Choose randomly from among the trusted dirservers that are up.  If
 * <b>fascistfirewall</b>, make sure the port we pick is allowed by our
 * firewall options.  If <b>requireother</b>, it cannot be us.
 * <b>type> specifies the type of authoritative dir we require.
 */
static routerstatus_t *
router_pick_trusteddirserver_impl(authority_type_t type,
                                  int requireother, int fascistfirewall,
                                  int prefer_tunnel)
{
  smartlist_t *direct, *tunnel;
  smartlist_t *overloaded_direct, *overloaded_tunnel;
  routerinfo_t *me = router_get_my_routerinfo();
  routerstatus_t *result;
  time_t now = time(NULL);

  direct = smartlist_create();
  tunnel = smartlist_create();
  overloaded_direct = smartlist_create();
  overloaded_tunnel = smartlist_create();

  if (!trusted_dir_servers)
    return NULL;

  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, d,
    {
      int is_overloaded =
          d->fake_status.last_dir_503_at + DIR_503_TIMEOUT > now;
      if (!d->is_running) continue;
      if ((type & d->type) == 0)
        continue;
      if ((type & EXTRAINFO_CACHE) &&
          !router_supports_extrainfo(d->digest, 1))
        continue;
      if (requireother && me && router_digest_is_me(d->digest))
          continue;
      if (prefer_tunnel &&
          d->or_port &&
          (!fascistfirewall ||
           fascist_firewall_allows_address_or(d->addr, d->or_port)))
        smartlist_add(is_overloaded ? overloaded_tunnel : tunnel,
                      &d->fake_status);
      else if (!fascistfirewall ||
               fascist_firewall_allows_address_dir(d->addr, d->dir_port))
        smartlist_add(is_overloaded ? overloaded_direct : direct,
                      &d->fake_status);
    });

  if (smartlist_len(tunnel)) {
    result = smartlist_choose(tunnel);
  } else if (smartlist_len(overloaded_tunnel)) {
    result = smartlist_choose(overloaded_tunnel);
  } else if (smartlist_len(direct)) {
    result = smartlist_choose(direct);
  } else {
    result = smartlist_choose(overloaded_direct);
  }

  smartlist_free(direct);
  smartlist_free(tunnel);
  smartlist_free(overloaded_direct);
  smartlist_free(overloaded_tunnel);
  return result;
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
      routerstatus_t *rs;
      dir->is_running = 1;
      download_status_reset(&dir->v2_ns_dl_status);
      rs = router_get_combined_status_by_digest(dir->digest);
      if (rs && !rs->is_running) {
        rs->is_running = 1;
        rs->last_dir_503_at = 0;
        control_event_networkstatus_changed_single(rs);
      }
    });
  }
  // last_networkstatus_download_attempted = 0; // XXXX !!!!
  router_dir_info_changed();
}

/** Reset all internal variables used to count failed downloads of network
 * status objects. */
void
router_reset_status_download_failures(void)
{
  mark_all_trusteddirservers_up();
}

/** Look through the routerlist and identify routers that
 * advertise the same /16 network address as <b>router</b>.
 * Add each of them to <b>sl</b>.
 */
static void
routerlist_add_network_family(smartlist_t *sl, routerinfo_t *router)
{
  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, r,
  {
    if (router != r &&
        (router->addr & 0xffff0000) == (r->addr & 0xffff0000))
      smartlist_add(sl, r);
  });
}

/** Add all the family of <b>router</b> to the smartlist <b>sl</b>.
 * This is used to make sure we don't pick siblings in a single path.
 */
void
routerlist_add_family(smartlist_t *sl, routerinfo_t *router)
{
  routerinfo_t *r;
  config_line_t *cl;
  or_options_t *options = get_options();

  /* First, add any routers with similar network addresses. */
  if (options->EnforceDistinctSubnets)
    routerlist_add_network_family(sl, router);

  if (router->declared_family) {
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
  }

  /* If the user declared any families locally, honor those too. */
  for (cl = get_options()->NodeFamilies; cl; cl = cl->next) {
    if (router_nickname_is_in_list(router, cl->value)) {
      add_nickname_list_to_smartlist(sl, cl->value, 0);
    }
  }
}

/** Given a (possibly NULL) comma-and-whitespace separated list of nicknames,
 * see which nicknames in <b>list</b> name routers in our routerlist, and add
 * the routerinfos for those routers to <b>sl</b>.  If <b>must_be_running</b>,
 * only include routers that we think are running.
 * Warn if any non-Named routers are specified by nickname.
 */
void
add_nickname_list_to_smartlist(smartlist_t *sl, const char *list,
                               int must_be_running)
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
    router = router_get_by_nickname(nick, 1);
    warned = smartlist_string_isin(warned_nicknames, nick);
    if (router) {
      if (!must_be_running || router->is_running) {
        smartlist_add(sl,router);
      }
    } else if (!router_get_combined_status_by_nickname(nick,1)) {
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

/** Return 1 iff any member of the (possibly NULL) comma-separated list
 * <b>list</b> is an acceptable nickname or hexdigest for <b>router</b>.  Else
 * return 0.
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

/** Add every suitable router from our routerlist to <b>sl</b>, so that
 * we can pick a node for a circuit.
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
        (router->is_valid || allow_invalid) &&
        !router_is_unreliable(router, need_uptime,
                              need_capacity, need_guard)) {
      /* If it's running, and it's suitable according to the
       * other flags we had in mind */
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
 * If <b>need_guard</b>, we require that the router is a possible entry guard.
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

/** Return the smaller of the router's configured BandwidthRate
 * and its advertised capacity. */
uint32_t
router_get_advertised_bandwidth(routerinfo_t *router)
{
  if (router->bandwidthcapacity < router->bandwidthrate)
    return router->bandwidthcapacity;
  return router->bandwidthrate;
}

/** Do not weight any declared bandwidth more than this much when picking
 * routers by bandwidth. */
#define DEFAULT_MAX_BELIEVABLE_BANDWIDTH 10000000 /* 10 MB/sec */

/** Eventually, the number we return will come from the directory
 * consensus, so clients can dynamically update to better numbers.
 *
 * But for now, or in case there is no consensus available, just return
 * a sufficient default. */
static uint32_t
get_max_believable_bandwidth(void)
{
  return DEFAULT_MAX_BELIEVABLE_BANDWIDTH;
}

/** Helper function:
 * choose a random element of smartlist <b>sl</b>, weighted by
 * the advertised bandwidth of each element.
 *
 * If <b>statuses</b> is zero, then <b>sl</b> is a list of
 * routerinfo_t's. Otherwise it's a list of routerstatus_t's.
 *
 * If <b>for_exit</b>, we're picking an exit node: consider all nodes'
 * bandwidth equally regardless of their Exit status, since there may be
 * some in the list because they exit to obscure ports. If not <b>for_exit</b>,
 * we're picking a non-exit node: weight exit-node's bandwidth less
 * depending on the smallness of the fraction of Exit-to-total bandwidth.
 *
 * If <b>for_guard</b>, we're picking a guard node: consider all guard's
 * bandwidth equally. Otherwise, weight guards proportionally less.
 *
 */
static void *
smartlist_choose_by_bandwidth(smartlist_t *sl, bandwidth_weight_rule_t rule,
                              int statuses)
{
  unsigned int i;
  routerinfo_t *router;
  routerstatus_t *status=NULL;
  int32_t *bandwidths;
  int is_exit;
  int is_guard;
  uint64_t total_nonexit_bw = 0, total_exit_bw = 0, total_bw = 0;
  uint64_t total_nonguard_bw = 0, total_guard_bw = 0;
  uint64_t rand_bw, tmp;
  double exit_weight;
  double guard_weight;
  int n_unknown = 0;
  bitarray_t *exit_bits;
  bitarray_t *guard_bits;
  uint32_t max_believable_bw = get_max_believable_bandwidth();

  /* Can't choose exit and guard at same time */
  tor_assert(rule == NO_WEIGHTING ||
             rule == WEIGHT_FOR_EXIT ||
             rule == WEIGHT_FOR_GUARD);

  /* First count the total bandwidth weight, and make a list
   * of each value.  <0 means "unknown; no routerinfo."  We use the
   * bits of negative values to remember whether the router was fast (-x)&1
   * and whether it was an exit (-x)&2 or guard (-x)&4.  Yes, it's a hack. */
  bandwidths = tor_malloc(sizeof(int32_t)*smartlist_len(sl));
  exit_bits = bitarray_init_zero(smartlist_len(sl));
  guard_bits = bitarray_init_zero(smartlist_len(sl));

  /* Iterate over all the routerinfo_t or routerstatus_t, and */
  for (i = 0; i < (unsigned)smartlist_len(sl); ++i) {
    /* first, learn what bandwidth we think i has */
    int is_known = 1;
    int32_t flags = 0;
    uint32_t this_bw = 0;
    if (statuses) {
      /* need to extract router info */
      status = smartlist_get(sl, i);
      router = router_get_by_digest(status->identity_digest);
      is_exit = status->is_exit;
      is_guard = status->is_possible_guard;
      if (router) {
        this_bw = router_get_advertised_bandwidth(router);
      } else { /* guess */
        is_known = 0;
        flags = status->is_fast ? 1 : 0;
        flags |= is_exit ? 2 : 0;
        flags |= is_guard ? 4 : 0;
      }
    } else {
      router = smartlist_get(sl, i);
      is_exit = router->is_exit;
      is_guard = router->is_possible_guard;
      this_bw = router_get_advertised_bandwidth(router);
    }
    if (is_exit)
      bitarray_set(exit_bits, i);
    if (is_guard)
      bitarray_set(guard_bits, i);
    /* if they claim something huge, don't believe it */
    if (this_bw > max_believable_bw) {
      char fp[HEX_DIGEST_LEN+1];
      base16_encode(fp, sizeof(fp), statuses ?
                      status->identity_digest :
                      router->cache_info.identity_digest,
                    DIGEST_LEN);
      log_fn(LOG_PROTOCOL_WARN, LD_DIR,
             "Bandwidth %d for router %s (%s) exceeds allowed max %d, capping",
             this_bw, router ? router->nickname : "(null)",
             fp, max_believable_bw);
      this_bw = max_believable_bw;
    }
    if (is_known) {
      bandwidths[i] = (int32_t) this_bw; // safe since MAX_BELIEVABLE<INT32_MAX
      if (is_guard)
        total_guard_bw += this_bw;
      else
        total_nonguard_bw += this_bw;
      if (is_exit)
        total_exit_bw += this_bw;
      else
        total_nonexit_bw += this_bw;
    } else {
      ++n_unknown;
      bandwidths[i] = -flags;
    }
  }

  /* Now, fill in the unknown values. */
  if (n_unknown) {
    int32_t avg_fast, avg_slow;
    if (total_exit_bw+total_nonexit_bw) {
      /* if there's some bandwidth, there's at least one known router,
       * so no worries about div by 0 here */
      int n_known = smartlist_len(sl)-n_unknown;
      avg_fast = avg_slow = (int32_t)
        ((total_exit_bw+total_nonexit_bw)/((uint64_t) n_known));
    } else {
      avg_fast = 40000;
      avg_slow = 20000;
    }
    for (i=0; i<(unsigned)smartlist_len(sl); ++i) {
      int32_t bw = bandwidths[i];
      if (bw>=0)
        continue;
      is_exit = ((-bw)&2);
      is_guard = ((-bw)&4);
      bandwidths[i] = ((-bw)&1) ? avg_fast : avg_slow;
      if (is_exit)
        total_exit_bw += bandwidths[i];
      else
        total_nonexit_bw += bandwidths[i];
      if (is_guard)
        total_guard_bw += bandwidths[i];
      else
        total_nonguard_bw += bandwidths[i];
    }
  }

  /* If there's no bandwidth at all, pick at random. */
  if (!(total_exit_bw+total_nonexit_bw)) {
    tor_free(bandwidths);
    tor_free(exit_bits);
    tor_free(guard_bits);
    return smartlist_choose(sl);
  }

  /* Figure out how to weight exits and guards */
  {
    double all_bw = U64_TO_DBL(total_exit_bw+total_nonexit_bw);
    double exit_bw = U64_TO_DBL(total_exit_bw);
    double guard_bw = U64_TO_DBL(total_guard_bw);
    /*
     * For detailed derivation of this formula, see
     *   http://archives.seul.org/or/dev/Jul-2007/msg00056.html
     */
    if (rule == WEIGHT_FOR_EXIT)
      exit_weight = 1.0;
    else
      exit_weight = 1.0 - all_bw/(3.0*exit_bw);

    if (rule == WEIGHT_FOR_GUARD)
      guard_weight = 1.0;
    else
      guard_weight = 1.0 - all_bw/(3.0*guard_bw);

    if (exit_weight <= 0.0)
      exit_weight = 0.0;

    if (guard_weight <= 0.0)
      guard_weight = 0.0;

    total_bw = 0;
    for (i=0; i < (unsigned)smartlist_len(sl); i++) {
      is_exit = bitarray_is_set(exit_bits, i);
      is_guard = bitarray_is_set(guard_bits, i);
      if (is_exit && is_guard)
        total_bw += ((uint64_t)(bandwidths[i] * exit_weight * guard_weight));
      else if (is_guard)
        total_bw += ((uint64_t)(bandwidths[i] * guard_weight));
      else if (is_exit)
        total_bw += ((uint64_t)(bandwidths[i] * exit_weight));
      else
        total_bw += bandwidths[i];
    }
  }
  log_debug(LD_CIRC, "Total bw = "U64_FORMAT
            ", exit bw = "U64_FORMAT
            ", nonexit bw = "U64_FORMAT", exit weight = %lf "
            "(for exit == %d)"
            ", guard bw = "U64_FORMAT
            ", nonguard bw = "U64_FORMAT", guard weight = %lf "
            "(for guard == %d)",
            U64_PRINTF_ARG(total_bw),
            U64_PRINTF_ARG(total_exit_bw), U64_PRINTF_ARG(total_nonexit_bw),
            exit_weight, (int)(rule == WEIGHT_FOR_EXIT),
            U64_PRINTF_ARG(total_guard_bw), U64_PRINTF_ARG(total_nonguard_bw),
            guard_weight, (int)(rule == WEIGHT_FOR_GUARD));

  /* Almost done: choose a random value from the bandwidth weights. */
  rand_bw = crypto_rand_uint64(total_bw);

  /* Last, count through sl until we get to the element we picked */
  tmp = 0;
  for (i=0; i < (unsigned)smartlist_len(sl); i++) {
    is_exit = bitarray_is_set(exit_bits, i);
    is_guard = bitarray_is_set(guard_bits, i);

    /* Weights can be 0 if not counting guards/exits */
    if (is_exit && is_guard)
      tmp += ((uint64_t)(bandwidths[i] * exit_weight * guard_weight));
    else if (is_guard)
      tmp += ((uint64_t)(bandwidths[i] * guard_weight));
    else if (is_exit)
      tmp += ((uint64_t)(bandwidths[i] * exit_weight));
    else
      tmp += bandwidths[i];

    if (tmp >= rand_bw)
      break;
  }
  if (i == (unsigned)smartlist_len(sl)) {
    /* This was once possible due to round-off error, but shouldn't be able
     * to occur any longer. */
    tor_fragile_assert();
    --i;
    log_warn(LD_BUG, "Round-off error in computing bandwidth had an effect on "
             " which router we chose. Please tell the developers. "
             U64_FORMAT " " U64_FORMAT " " U64_FORMAT, U64_PRINTF_ARG(tmp),
             U64_PRINTF_ARG(rand_bw), U64_PRINTF_ARG(total_bw));
  }
  tor_free(bandwidths);
  tor_free(exit_bits);
  tor_free(guard_bits);
  return smartlist_get(sl, i);
}

/** Choose a random element of router list <b>sl</b>, weighted by
 * the advertised bandwidth of each router.
 */
routerinfo_t *
routerlist_sl_choose_by_bandwidth(smartlist_t *sl,
                                  bandwidth_weight_rule_t rule)
{
  return smartlist_choose_by_bandwidth(sl, rule, 0);
}

/** Choose a random element of status list <b>sl</b>, weighted by
 * the advertised bandwidth of each status.
 */
routerstatus_t *
routerstatus_sl_choose_by_bandwidth(smartlist_t *sl)
{
  /* We are choosing neither exit nor guard here. Weight accordingly. */
  return smartlist_choose_by_bandwidth(sl, NO_WEIGHTING, 1);
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
 * If ! <b>allow_invalid</b>, consider only Valid routers.
 * If <b>need_guard</b>, consider only Guard routers.
 * If <b>weight_for_exit</b>, we weight bandwidths as if picking an exit node,
 * otherwise we weight bandwidths for picking a relay node (that is, possibly
 * discounting exit nodes).
 */
routerinfo_t *
router_choose_random_node(const char *preferred,
                          const char *excluded,
                          smartlist_t *excludedsmartlist,
                          int need_uptime, int need_capacity,
                          int need_guard,
                          int allow_invalid, int strict,
                          int weight_for_exit)
{
  smartlist_t *sl, *excludednodes;
  routerinfo_t *choice = NULL;
  bandwidth_weight_rule_t rule;

  tor_assert(!(weight_for_exit && need_guard));
  rule = weight_for_exit ? WEIGHT_FOR_EXIT :
    (need_guard ? WEIGHT_FOR_GUARD : NO_WEIGHTING);

  excludednodes = smartlist_create();
  add_nickname_list_to_smartlist(excludednodes,excluded,0);

  /* Try the preferred nodes first. Ignore need_uptime and need_capacity
   * and need_guard, since the user explicitly asked for these nodes. */
  if (preferred) {
    sl = smartlist_create();
    add_nickname_list_to_smartlist(sl,preferred,1);
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

    if (need_capacity || need_guard)
      choice = routerlist_sl_choose_by_bandwidth(sl, rule);
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
        NULL, excluded, excludedsmartlist,
        0, 0, 0, allow_invalid, 0, weight_for_exit);
    }
  }
  smartlist_free(excludednodes);
  if (!choice) {
    if (strict) {
      log_warn(LD_CIRC, "All preferred nodes were down when trying to choose "
               "node, and the Strict[...]Nodes option is set. Failing.");
    } else {
      log_warn(LD_CIRC,
               "No available nodes when trying to choose node. Failing.");
    }
  }
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
  size_t len;
  tor_assert(hexdigest);
  if (hexdigest[0] == '$')
    ++hexdigest;

  len = strlen(hexdigest);
  if (len < HEX_DIGEST_LEN)
    return 0;
  else if (len > HEX_DIGEST_LEN &&
           (hexdigest[HEX_DIGEST_LEN] == '=' ||
            hexdigest[HEX_DIGEST_LEN] == '~')) {
    if (strcasecmp(hexdigest+HEX_DIGEST_LEN+1, router->nickname))
      return 0;
    if (hexdigest[HEX_DIGEST_LEN] == '=' && !router->is_named)
      return 0;
  }

  if (base16_decode(digest, DIGEST_LEN, hexdigest, HEX_DIGEST_LEN)<0)
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
  const char *named_digest = NULL;

  tor_assert(nickname);
  if (!routerlist)
    return NULL;
  if (nickname[0] == '$')
    return router_get_by_hexdigest(nickname);
  if (!strcasecmp(nickname, UNNAMED_ROUTER_NICKNAME))
    return NULL;
  if (server_mode(get_options()) &&
      !strcasecmp(nickname, get_options()->Nickname))
    return router_get_my_routerinfo();

  maybedigest = (strlen(nickname) >= HEX_DIGEST_LEN) &&
    (base16_decode(digest,DIGEST_LEN,nickname,HEX_DIGEST_LEN) == 0);

  if ((named_digest = networkstatus_get_router_digest_by_nickname(nickname))) {
    return rimap_get(routerlist->identity_map, named_digest);
  }

  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
  {
    if (!strcasecmp(router->nickname, nickname)) {
      ++n_matches;
      if (n_matches <= 1 || router->is_running)
        best_match = router;
    } else if (maybedigest &&
               !memcmp(digest, router->cache_info.identity_digest, DIGEST_LEN)
               ) {
      if (router_hex_digest_matches(router, nickname))
        return router;
      else
        best_match = router; // XXXX020 NM not exactly right.
    }
  });

  if (best_match) {
    if (warn_if_unnamed && n_matches > 1) {
      smartlist_t *fps = smartlist_create();
      int any_unwarned = 0;
      SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
        {
          routerstatus_t *rs;
          char *desc;
          size_t dlen;
          char fp[HEX_DIGEST_LEN+1];
          if (strcasecmp(router->nickname, nickname))
            continue;
          rs = router_get_combined_status_by_digest(
                                          router->cache_info.identity_digest);
          if (rs && !rs->name_lookup_warned) {
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
                 " but none is listed as named by the directory authorities. "
                 "Choosing one arbitrarily. If you meant one in particular, "
                 "you should say %s.", nickname, alternatives);
        tor_free(alternatives);
      }
      SMARTLIST_FOREACH(fps, char *, cp, tor_free(cp));
      smartlist_free(fps);
    } else if (warn_if_unnamed) {
      routerstatus_t *rs = router_get_combined_status_by_digest(
          best_match->cache_info.identity_digest);
      if (rs && !rs->name_lookup_warned) {
        char fp[HEX_DIGEST_LEN+1];
        base16_encode(fp, sizeof(fp),
                      best_match->cache_info.identity_digest, DIGEST_LEN);
        log_warn(LD_CONFIG, "You specified a server \"%s\" by name, but this "
             "name is not registered, so it could be used by any server, "
             "not just the one you meant. "
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

/** Return true iff <b>digest</b> is the digest of the identity key of a
 * trusted directory matching at least one bit of <b>type</b>.  If <b>type</b>
 * is zero, any authority is okay. */
int
router_digest_is_trusted_dir_type(const char *digest, authority_type_t type)
{
  if (!trusted_dir_servers)
    return 0;
  if (authdir_mode(get_options()) && router_digest_is_me(digest))
    return 1;
  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ent,
    if (!memcmp(digest, ent->digest, DIGEST_LEN)) {
      return (!type) || ((type & ent->type) != 0);
    });
  return 0;
}

/** Return true iff <b>addr</b> is the address of one of our trusted
 * directory authorities. */
int
router_addr_is_trusted_dir(uint32_t addr)
{
  if (!trusted_dir_servers)
    return 0;
  SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ent,
    if (ent->addr == addr)
      return 1;
    );
  return 0;
}

/** If hexdigest is correctly formed, base16_decode it into
 * digest, which must have DIGEST_LEN space in it.
 * Return 0 on success, -1 on failure.
 */
int
hexdigest_to_digest(const char *hexdigest, char *digest)
{
  if (hexdigest[0]=='$')
    ++hexdigest;
  if (strlen(hexdigest) < HEX_DIGEST_LEN ||
      base16_decode(digest,DIGEST_LEN,hexdigest,HEX_DIGEST_LEN) < 0)
    return -1;
  return 0;
}

/** Return the router in our routerlist whose hexadecimal key digest
 * is <b>hexdigest</b>.  Return NULL if no such router is known. */
routerinfo_t *
router_get_by_hexdigest(const char *hexdigest)
{
  char digest[DIGEST_LEN];
  size_t len;
  routerinfo_t *ri;

  tor_assert(hexdigest);
  if (!routerlist)
    return NULL;
  if (hexdigest[0]=='$')
    ++hexdigest;
  len = strlen(hexdigest);
  if (hexdigest_to_digest(hexdigest, digest) < 0)
    return NULL;

  ri = router_get_by_digest(digest);

  if (len > HEX_DIGEST_LEN) {
    if (hexdigest[HEX_DIGEST_LEN] == '=') {
      if (strcasecmp(ri->nickname, hexdigest+HEX_DIGEST_LEN+1) ||
          !ri->is_named)
        return NULL;
    } else if (hexdigest[HEX_DIGEST_LEN] == '~') {
      if (strcasecmp(ri->nickname, hexdigest+HEX_DIGEST_LEN+1))
        return NULL;
    } else {
      return NULL;
    }
  }

  return ri;
}

/** Return the router in our routerlist whose 20-byte key digest
 * is <b>digest</b>.  Return NULL if no such router is known. */
routerinfo_t *
router_get_by_digest(const char *digest)
{
  tor_assert(digest);

  if (!routerlist) return NULL;

  // routerlist_assert_ok(routerlist);

  return rimap_get(routerlist->identity_map, digest);
}

/** Return the router in our routerlist whose 20-byte descriptor
 * is <b>digest</b>.  Return NULL if no such router is known. */
signed_descriptor_t *
router_get_by_descriptor_digest(const char *digest)
{
  tor_assert(digest);

  if (!routerlist) return NULL;

  return sdmap_get(routerlist->desc_digest_map, digest);
}

/** Return the signed descriptor for the router in our routerlist whose
 * 20-byte extra-info digest is <b>digest</b>.  Return NULL if no such router
 * is known. */
signed_descriptor_t *
router_get_by_extrainfo_digest(const char *digest)
{
  tor_assert(digest);

  if (!routerlist) return NULL;

  return sdmap_get(routerlist->desc_by_eid_map, digest);
}

/** Return the signed descriptor for the extrainfo_t in our routerlist whose
 * extra-info-digest is <b>digest</b>. Return NULL if no such extra-info
 * document is known. */
signed_descriptor_t *
extrainfo_get_by_descriptor_digest(const char *digest)
{
  extrainfo_t *ei;
  tor_assert(digest);
  if (!routerlist) return NULL;
  ei = eimap_get(routerlist->extra_info_map, digest);
  return ei ? &ei->cache_info : NULL;
}

/** Return a pointer to the signed textual representation of a descriptor.
 * The returned string is not guaranteed to be NUL-terminated: the string's
 * length will be in desc-\>signed_descriptor_len.
 *
 * If with_annotations is set, the returned string will include the annotations
 * (if any) preceding the descriptor.  This will increase the length of the
 * string by desc-\>annotations_len.
 *
 * The caller must not free the string returned.
 */
static const char *
signed_descriptor_get_body_impl(signed_descriptor_t *desc,
                                int with_annotations)
{
  const char *r = NULL;
  size_t len = desc->signed_descriptor_len;
  off_t offset = desc->saved_offset;
  if (with_annotations)
    len += desc->annotations_len;
  else
    offset += desc->annotations_len;

  tor_assert(len > 32);
  if (desc->saved_location == SAVED_IN_CACHE && routerlist) {
    desc_store_t *store = desc_get_store(router_get_routerlist(), desc);
    if (store && store->mmap) {
      tor_assert(desc->saved_offset + len <= store->mmap->size);
      r = store->mmap->data + offset;
    }
  }
  if (!r) /* no mmap, or not in cache. */
    r = desc->signed_descriptor_body +
      (with_annotations ? 0 : desc->annotations_len);

  tor_assert(r);
  if (!with_annotations) {
    if (memcmp("router ", r, 7) && memcmp("extra-info ", r, 11)) {
      log_err(LD_DIR, "descriptor at %p begins with unexpected string %s",
              desc, tor_strndup(r, 64));
    }
    tor_assert(!memcmp("router ", r, 7) || !memcmp("extra-info ", r, 11));
  }

  return r;
}

/** Return a pointer to the signed textual representation of a descriptor.
 * The returned string is not guaranteed to be NUL-terminated: the string's
 * length will be in desc-\>signed_descriptor_len.
 *
 * The caller must not free the string returned.
 */
const char *
signed_descriptor_get_body(signed_descriptor_t *desc)
{
  return signed_descriptor_get_body_impl(desc, 0);
}

/** Return the current list of all known routers. */
routerlist_t *
router_get_routerlist(void)
{
  if (PREDICT_UNLIKELY(!routerlist)) {
    routerlist = tor_malloc_zero(sizeof(routerlist_t));
    routerlist->routers = smartlist_create();
    routerlist->old_routers = smartlist_create();
    routerlist->identity_map = rimap_new();
    routerlist->desc_digest_map = sdmap_new();
    routerlist->desc_by_eid_map = sdmap_new();
    routerlist->extra_info_map = eimap_new();

    routerlist->desc_store.fname_base = "cached-descriptors";
    routerlist->desc_store.fname_alt_base = "cached-routers";
    routerlist->extrainfo_store.fname_base = "cached-extrainfo";

    routerlist->desc_store.type = ROUTER_STORE;
    routerlist->extrainfo_store.type = EXTRAINFO_STORE;

    routerlist->desc_store.description = "router descriptors";
    routerlist->extrainfo_store.description = "extra-info documents";
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

  /* XXXX020 Remove once 414/417 is fixed. But I have a hunch... */
  memset(router, 77, sizeof(routerinfo_t));

  tor_free(router);
}

/** Release all storage held by <b>extrainfo</b> */
void
extrainfo_free(extrainfo_t *extrainfo)
{
  if (!extrainfo)
    return;
  tor_free(extrainfo->cache_info.signed_descriptor_body);
  tor_free(extrainfo->pending_sig);

  /* XXXX020 remove this once more bugs go away. */
  memset(extrainfo, 88, sizeof(extrainfo_t)); /* debug bad memory usage */
  tor_free(extrainfo);
}

/** Release storage held by <b>sd</b>. */
static void
signed_descriptor_free(signed_descriptor_t *sd)
{
  tor_free(sd->signed_descriptor_body);

  /* XXXX020 remove this once more bugs go away. */
  memset(sd, 99, sizeof(signed_descriptor_t)); /* Debug bad mem usage */
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

/** Helper: free the storage held by the extrainfo_t in <b>e</b>. */
static void
_extrainfo_free(void *e)
{
  extrainfo_free(e);
}

/** Free all storage held by a routerlist <b>rl</b>. */
void
routerlist_free(routerlist_t *rl)
{
  tor_assert(rl);
  rimap_free(rl->identity_map, NULL);
  sdmap_free(rl->desc_digest_map, NULL);
  sdmap_free(rl->desc_by_eid_map, NULL);
  eimap_free(rl->extra_info_map, _extrainfo_free);
  SMARTLIST_FOREACH(rl->routers, routerinfo_t *, r,
                    routerinfo_free(r));
  SMARTLIST_FOREACH(rl->old_routers, signed_descriptor_t *, sd,
                    signed_descriptor_free(sd));
  smartlist_free(rl->routers);
  smartlist_free(rl->old_routers);
  if (routerlist->desc_store.mmap)
    tor_munmap_file(routerlist->desc_store.mmap);
  if (routerlist->extrainfo_store.mmap)
    tor_munmap_file(routerlist->extrainfo_store.mmap);
  tor_free(rl);

  router_dir_info_changed();
}

/** DOCDOC */
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
  int n_authorities = get_n_v2_authorities();
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
  if (idx < 0) {
    idx = -1;
    SMARTLIST_FOREACH(sl, routerinfo_t *, r,
                      if (r == ri) {
                        idx = r_sl_idx;
                        break;
                      });
  } else {
    tor_assert(idx < smartlist_len(sl));
    tor_assert(smartlist_get(sl, idx) == ri);
  };
  return idx;
}

/** Insert an item <b>ri</b> into the routerlist <b>rl</b>, updating indices
 * as needed.  There must be no previous member of <b>rl</b> with the same
 * identity digest as <b>ri</b>: If there is, call routerlist_replace
 * instead.
 */
static void
routerlist_insert(routerlist_t *rl, routerinfo_t *ri)
{
  routerinfo_t *ri_old;
  {
    /* XXXX020 remove this code once bug 417/404 is fixed. */
    routerinfo_t *ri_generated = router_get_my_routerinfo();
    tor_assert(ri_generated != ri);
  }
  tor_assert(ri->routerlist_index == -1);

  ri_old = rimap_set(rl->identity_map, ri->cache_info.identity_digest, ri);
  tor_assert(!ri_old);
  sdmap_set(rl->desc_digest_map, ri->cache_info.signed_descriptor_digest,
            &(ri->cache_info));
  if (!tor_digest_is_zero(ri->cache_info.extra_info_digest))
    sdmap_set(rl->desc_by_eid_map, ri->cache_info.extra_info_digest,
              &ri->cache_info);
  smartlist_add(rl->routers, ri);
  ri->routerlist_index = smartlist_len(rl->routers) - 1;
  router_dir_info_changed();
#ifdef DEBUG_ROUTERLIST
  routerlist_assert_ok(rl);
#endif
}

/** Adds the extrainfo_t <b>ei</b> to the routerlist <b>rl</b>, if there is a
 * corresponding router in rl-\>routers or rl-\>old_routers.  Return true iff
 * we actually inserted <b>ei</b>.  Free <b>ei</b> if it isn't inserted. */
static int
extrainfo_insert(routerlist_t *rl, extrainfo_t *ei)
{
  int r = 0;
  routerinfo_t *ri = rimap_get(rl->identity_map,
                               ei->cache_info.identity_digest);
  signed_descriptor_t *sd;
  extrainfo_t *ei_tmp;

  {
    /* XXXX020 remove this code once bug 417/404 is fixed. */
    extrainfo_t *ei_generated = router_get_my_extrainfo();
    tor_assert(ei_generated != ei);
  }

  if (!ri) {
    /* This router is unknown; we can't even verify the signature. Give up.*/
    goto done;
  }
  if (routerinfo_incompatible_with_extrainfo(ri, ei, NULL)) {
    if (ei->bad_sig) /* If the signature didn't check, it's just wrong. */
      goto done;
    sd = sdmap_get(rl->desc_by_eid_map,
                   ei->cache_info.signed_descriptor_digest);
    if (!sd ||
        memcmp(sd->identity_digest, ei->cache_info.identity_digest,
               DIGEST_LEN) ||
        sd->published_on != ei->cache_info.published_on)
      goto done;
  }

  /* Okay, if we make it here, we definitely have a router corresponding to
   * this extrainfo. */

  ei_tmp = eimap_set(rl->extra_info_map,
                     ei->cache_info.signed_descriptor_digest,
                     ei);
  r = 1;
  if (ei_tmp) {
    rl->extrainfo_store.bytes_dropped +=
      ei_tmp->cache_info.signed_descriptor_len;
    extrainfo_free(ei_tmp);
  }

 done:
  if (r == 0)
    extrainfo_free(ei);

#ifdef DEBUG_ROUTERLIST
  routerlist_assert_ok(rl);
#endif
  return r;
}

#define should_cache_old_descriptors() dirserver_mode(get_options())

/** If we're a directory cache and routerlist <b>rl</b> doesn't have
 * a copy of router <b>ri</b> yet, add it to the list of old (not
 * recommended but still served) descriptors. Else free it. */
static void
routerlist_insert_old(routerlist_t *rl, routerinfo_t *ri)
{
  {
    /* XXXX020 remove this code once bug 417/404 is fixed. */
    routerinfo_t *ri_generated = router_get_my_routerinfo();
    tor_assert(ri_generated != ri);
  }
  tor_assert(ri->routerlist_index == -1);

  if (should_cache_old_descriptors() &&
      ri->purpose == ROUTER_PURPOSE_GENERAL &&
      !sdmap_get(rl->desc_digest_map,
                 ri->cache_info.signed_descriptor_digest)) {
    signed_descriptor_t *sd = signed_descriptor_from_routerinfo(ri);
    sdmap_set(rl->desc_digest_map, sd->signed_descriptor_digest, sd);
    smartlist_add(rl->old_routers, sd);
    if (!tor_digest_is_zero(sd->extra_info_digest))
      sdmap_set(rl->desc_by_eid_map, sd->extra_info_digest, sd);
  } else {
    routerinfo_free(ri);
  }
#ifdef DEBUG_ROUTERLIST
  routerlist_assert_ok(rl);
#endif
}

/** Remove an item <b>ri</b> from the routerlist <b>rl</b>, updating indices
 * as needed. If <b>idx</b> is nonnegative and smartlist_get(rl-&gt;routers,
 * idx) == ri, we don't need to do a linear search over the list to decide
 * which to remove.  We fill the gap in rl-&gt;routers with a later element in
 * the list, if any exists. <b>ri</b> is freed.
 *
 * If <b>make_old</b> is true, instead of deleting the router, we try adding
 * it to rl-&gt;old_routers. */
void
routerlist_remove(routerlist_t *rl, routerinfo_t *ri, int make_old)
{
  routerinfo_t *ri_tmp;
  extrainfo_t *ei_tmp;
  int idx = ri->routerlist_index;
  tor_assert(0 <= idx && idx < smartlist_len(rl->routers));
  tor_assert(smartlist_get(rl->routers, idx) == ri);

  ri->routerlist_index = -1;
  smartlist_del(rl->routers, idx);
  if (idx < smartlist_len(rl->routers)) {
    routerinfo_t *r = smartlist_get(rl->routers, idx);
    r->routerlist_index = idx;
  }

  ri_tmp = rimap_remove(rl->identity_map, ri->cache_info.identity_digest);
  router_dir_info_changed();
  tor_assert(ri_tmp == ri);

  if (make_old && should_cache_old_descriptors() &&
      ri->purpose == ROUTER_PURPOSE_GENERAL) {
    signed_descriptor_t *sd;
    sd = signed_descriptor_from_routerinfo(ri);
    smartlist_add(rl->old_routers, sd);
    sdmap_set(rl->desc_digest_map, sd->signed_descriptor_digest, sd);
    if (!tor_digest_is_zero(sd->extra_info_digest))
      sdmap_set(rl->desc_by_eid_map, sd->extra_info_digest, sd);
  } else {
    signed_descriptor_t *sd_tmp;
    desc_store_t *store = router_get_store(rl, ri);
    sd_tmp = sdmap_remove(rl->desc_digest_map,
                          ri->cache_info.signed_descriptor_digest);
    tor_assert(sd_tmp == &(ri->cache_info));
    if (store)
      store->bytes_dropped += ri->cache_info.signed_descriptor_len;
    ei_tmp = eimap_remove(rl->extra_info_map,
                          ri->cache_info.extra_info_digest);
    if (ei_tmp) {
      rl->extrainfo_store.bytes_dropped +=
        ei_tmp->cache_info.signed_descriptor_len;
      extrainfo_free(ei_tmp);
    }
    if (!tor_digest_is_zero(ri->cache_info.extra_info_digest))
      sdmap_remove(rl->desc_by_eid_map, ri->cache_info.extra_info_digest);
    routerinfo_free(ri);
  }
#ifdef DEBUG_ROUTERLIST
  routerlist_assert_ok(rl);
#endif
}

/** Remove a signed_descriptor_t <b>sd</b> from <b>rl</b>-\>old_routers, and
 * adjust <b>rl</b> as appropriate.  <b>idx</i> is -1, or the index of
 * <b>sd</b>. */
static void
routerlist_remove_old(routerlist_t *rl, signed_descriptor_t *sd, int idx)
{
  signed_descriptor_t *sd_tmp;
  extrainfo_t *ei_tmp;
  desc_store_t *store;
  tor_assert(0 <= idx && idx < smartlist_len(rl->old_routers));
  tor_assert(smartlist_get(rl->old_routers, idx) == sd);

  smartlist_del(rl->old_routers, idx);
  sd_tmp = sdmap_remove(rl->desc_digest_map,
                        sd->signed_descriptor_digest);
  tor_assert(sd_tmp == sd);
  store = desc_get_store(rl, sd);
  if (store)
    store->bytes_dropped += sd->signed_descriptor_len;

  ei_tmp = eimap_remove(rl->extra_info_map,
                        sd->extra_info_digest);
  if (ei_tmp) {
    rl->extrainfo_store.bytes_dropped +=
      ei_tmp->cache_info.signed_descriptor_len;
    extrainfo_free(ei_tmp);
  }
  if (!tor_digest_is_zero(sd->extra_info_digest))
    sdmap_remove(rl->desc_by_eid_map, sd->extra_info_digest);

  signed_descriptor_free(sd);
#ifdef DEBUG_ROUTERLIST
  routerlist_assert_ok(rl);
#endif
}

/** Remove <b>ri_old</b> from the routerlist <b>rl</b>, and replace it with
 * <b>ri_new</b>, updating all index info.  If <b>idx</b> is nonnegative and
 * smartlist_get(rl-&gt;routers, idx) == ri, we don't need to do a linear
 * search over the list to decide which to remove.  We put ri_new in the same
 * index as ri_old, if possible.  ri is freed as appropriate.
 *
 * If <b>make_old</b> is true, instead of deleting the router, we try adding
 * it to rl-&gt;old_routers. */
static void
routerlist_replace(routerlist_t *rl, routerinfo_t *ri_old,
                   routerinfo_t *ri_new)
{
  int idx;

  routerinfo_t *ri_tmp;
  extrainfo_t *ei_tmp;
  {
    /* XXXX020 remove this code once bug 417/404 is fixed. */
    routerinfo_t *ri_generated = router_get_my_routerinfo();
    tor_assert(ri_generated != ri_new);
  }
  tor_assert(ri_old != ri_new);
  tor_assert(ri_new->routerlist_index == -1);

  idx = ri_old->routerlist_index;
  tor_assert(0 <= idx && idx < smartlist_len(rl->routers));
  tor_assert(smartlist_get(rl->routers, idx) == ri_old);

  router_dir_info_changed();
  if (idx >= 0) {
    smartlist_set(rl->routers, idx, ri_new);
    ri_old->routerlist_index = -1;
    ri_new->routerlist_index = idx;
    /* Check that ri_old is not in rl->routers anymore: */
    tor_assert( _routerlist_find_elt(rl->routers, ri_old, -1) == -1 );
  } else {
    log_warn(LD_BUG, "Appending entry from routerlist_replace.");
    routerlist_insert(rl, ri_new);
    return;
  }
  if (memcmp(ri_old->cache_info.identity_digest,
             ri_new->cache_info.identity_digest, DIGEST_LEN)) {
    /* digests don't match; digestmap_set won't replace */
    rimap_remove(rl->identity_map, ri_old->cache_info.identity_digest);
  }
  ri_tmp = rimap_set(rl->identity_map,
                     ri_new->cache_info.identity_digest, ri_new);
  tor_assert(!ri_tmp || ri_tmp == ri_old);
  sdmap_set(rl->desc_digest_map,
            ri_new->cache_info.signed_descriptor_digest,
            &(ri_new->cache_info));

  if (!tor_digest_is_zero(ri_new->cache_info.extra_info_digest)) {
    sdmap_set(rl->desc_by_eid_map, ri_new->cache_info.extra_info_digest,
              &ri_new->cache_info);
  }

  if (should_cache_old_descriptors() &&
      ri_old->purpose == ROUTER_PURPOSE_GENERAL) {
    signed_descriptor_t *sd = signed_descriptor_from_routerinfo(ri_old);
    smartlist_add(rl->old_routers, sd);
    sdmap_set(rl->desc_digest_map, sd->signed_descriptor_digest, sd);
    if (!tor_digest_is_zero(sd->extra_info_digest))
      sdmap_set(rl->desc_by_eid_map, sd->extra_info_digest, sd);
  } else {
    desc_store_t *store;
    if (memcmp(ri_old->cache_info.signed_descriptor_digest,
               ri_new->cache_info.signed_descriptor_digest,
               DIGEST_LEN)) {
      /* digests don't match; digestmap_set didn't replace */
      sdmap_remove(rl->desc_digest_map,
                   ri_old->cache_info.signed_descriptor_digest);
    }

    ei_tmp = eimap_remove(rl->extra_info_map,
                          ri_old->cache_info.extra_info_digest);
    if (ei_tmp) {
      rl->extrainfo_store.bytes_dropped +=
        ei_tmp->cache_info.signed_descriptor_len;
      extrainfo_free(ei_tmp);
    }
    if (!tor_digest_is_zero(ri_old->cache_info.extra_info_digest)) {
      sdmap_remove(rl->desc_by_eid_map,
                   ri_old->cache_info.extra_info_digest);
    }
    store = router_get_store(rl, ri_old);
    if (store)
      store->bytes_dropped += ri_old->cache_info.signed_descriptor_len;
    routerinfo_free(ri_old);
  }
#ifdef DEBUG_ROUTERLIST
  routerlist_assert_ok(rl);
#endif
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
  if (trusted_dir_servers) {
    SMARTLIST_FOREACH(trusted_dir_servers, trusted_dir_server_t *, ds,
                      trusted_dir_server_free(ds));
    smartlist_free(trusted_dir_servers);
    trusted_dir_servers = NULL;
  }
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

  networkstatus_reset_warnings();
}

/** Mark the router with ID <b>digest</b> as running or non-running
 * in our routerlist. */
void
router_set_status(const char *digest, int up)
{
  routerinfo_t *router;
  routerstatus_t *status;
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
  if (status && status->is_running != up) {
    status->is_running = up;
    control_event_networkstatus_changed_single(status);
  }
  router_dir_info_changed();
}

/** Add <b>router</b> to the routerlist, if we don't already have it.  Replace
 * older entries (if any) with the same key.  Note: Callers should not hold
 * their pointers to <b>router</b> if this function fails; <b>router</b>
 * will either be inserted into the routerlist or freed. Similarly, even
 * if this call succeeds, they should not hold their pointers to
 * <b>router</b> after subsequent calls with other routerinfo's -- they
 * might cause the original routerinfo to get freed.
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
 * router_rebuild_store and routerlist_descriptors_added.
 */
int
router_add_to_routerlist(routerinfo_t *router, const char **msg,
                         int from_cache, int from_fetch)
{
  const char *id_digest;
  int authdir = authdir_mode(get_options());
  int authdir_believes_valid = 0;
  routerinfo_t *old_router;
  /* router_have_minimum_dir_info() has side effects, so do it before we
   * start the real work */
  int authdir_may_warn_about_unreachable_server =
    authdir && !from_cache && !from_fetch &&
    router_have_minimum_dir_info();
  const smartlist_t *networkstatus_list = networkstatus_get_v2_list();

  tor_assert(msg);

  if (!routerlist)
    router_get_routerlist();

  id_digest = router->cache_info.identity_digest;

  /* Make sure that we haven't already got this exact descriptor. */
  if (sdmap_get(routerlist->desc_digest_map,
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

    if (!signed_desc_digest_is_recognized(&router->cache_info) &&
        !routerinfo_is_a_configured_bridge(router)) {
      /* We asked for it, so some networkstatus must have listed it when we
       * did.  Save it if we're a cache in case somebody else asks for it. */
      log_info(LD_DIR,
               "Received a no-longer-recognized descriptor for router '%s'",
               router->nickname);
      *msg = "Router descriptor is not referenced by any network-status.";

      /* Only journal this desc if we'll be serving it. */
      if (!from_cache && should_cache_old_descriptors())
        signed_desc_append_to_journal(&router->cache_info,
                                      router_get_store(routerlist, router),
                                      router->purpose);
      routerlist_insert_old(routerlist, router);
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

  /* If we have a router with the same identity key, choose the newer one. */
  old_router = rimap_get(routerlist->identity_map,
                         router->cache_info.identity_digest);
  if (old_router) {
    if (router->cache_info.published_on <=
        old_router->cache_info.published_on) {
      /* Same key, but old */
      log_debug(LD_DIR, "Skipping not-new descriptor for router '%s'",
                router->nickname);
      /* Only journal this desc if we'll be serving it. */
      if (!from_cache && should_cache_old_descriptors())
        signed_desc_append_to_journal(&router->cache_info,
                                      router_get_store(routerlist, router),
                                      router->purpose);
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
      if (authdir_may_warn_about_unreachable_server &&
          dirserv_thinks_router_is_blatantly_unreachable(router, time(NULL))) {
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
      routerlist_replace(routerlist, old_router, router);
      if (!from_cache) {
        signed_desc_append_to_journal(&router->cache_info,
                                      router_get_store(routerlist, router),
                                      router->purpose);
      }
      directory_set_dirty();
      *msg = unreachable ? "Dirserver believes your ORPort is unreachable" :
        authdir_believes_valid ? "Valid server updated" :
        ("Invalid server updated. (This dirserver is marking your "
         "server as unapproved.)");
      return unreachable ? 1 : 0;
    }
  }

  /* We haven't seen a router with this identity before. Add it to the end of
   * the list. */
  routerlist_insert(routerlist, router);
  if (!from_cache)
    signed_desc_append_to_journal(&router->cache_info,
                                  router_get_store(routerlist, router),
                                  router->purpose);
  directory_set_dirty();
  return 0;
}

/** Insert <b>ei</b> into the routerlist, or free it. Other arguments are
 * as for router_add_to_routerlist(). */
void
router_add_extrainfo_to_routerlist(extrainfo_t *ei, const char **msg,
                                   int from_cache, int from_fetch)
{
  int inserted;
  (void)from_fetch;
  if (msg) *msg = NULL;

  inserted = extrainfo_insert(router_get_routerlist(), ei);

  if (inserted && !from_cache)
    signed_desc_append_to_journal(&ei->cache_info,
                                  &routerlist->extrainfo_store,
                                  EXTRAINFO_PURPOSE_GENERAL);
}

/** Sorting helper: return &lt;0, 0, or &gt;0 depending on whether the
 * signed_descriptor_t* in *<b>a</b> has an identity digest preceding, equal
 * to, or later than that of *<b>b</b>. */
static int
_compare_old_routers_by_identity(const void **_a, const void **_b)
{
  int i;
  const signed_descriptor_t *r1 = *_a, *r2 = *_b;
  if ((i = memcmp(r1->identity_digest, r2->identity_digest, DIGEST_LEN)))
    return i;
  return r1->published_on - r2->published_on;
}

/** Internal type used to represent how long an old descriptor was valid,
 * where it appeared in the list of old descriptors, and whether it's extra
 * old. Used only by routerlist_remove_old_cached_routers_with_id(). */
struct duration_idx_t {
  int duration;
  int idx;
  int old;
};

/** Sorting helper: compare two duration_idx_t by their duration. */
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
  int i, n = hi-lo+1;
  unsigned n_extra, n_rmv = 0;
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
  {
    int mdpr = max_descriptors_per_router();
    if (n <= mdpr)
      return;
    n_extra = n - mdpr;
  }

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

  i = hi;
  do {
    if (rmv[i-lo])
      routerlist_remove_old(routerlist, smartlist_get(lst, i), i);
  } while (--i >= lo);
  tor_free(must_keep);
  tor_free(rmv);
  tor_free(lifespans);
}

/** Deactivate any routers from the routerlist that are more than
 * ROUTER_MAX_AGE seconds old and not recommended by any networkstatuses;
 * remove old routers from the list of cached routers if we have too many.
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
  const smartlist_t *networkstatus_list = networkstatus_get_v2_list();

  trusted_dirs_remove_old_certs();

  if (!routerlist || !networkstatus_list)
    return;

  routerlist_assert_ok(routerlist);

  retain = digestmap_new();
  cutoff = now - OLD_ROUTER_DESC_MAX_AGE;
  /* Build a list of all the descriptors that _anybody_ recommends. */
  SMARTLIST_FOREACH(networkstatus_list, networkstatus_t *, ns,
    {
      /* XXXX The inner loop here gets pretty expensive, and actually shows up
       * on some profiles.  It may be the reason digestmap_set shows up in
       * profiles too.  If instead we kept a per-descriptor digest count of
       * how many networkstatuses recommended each descriptor, and changed
       * that only when the networkstatuses changed, that would be a speed
       * improvement, possibly 1-4% if it also removes digestmap_set from the
       * profile.  Not worth it for 0.1.2.x, though.  The new directory
       * system will obsolete this whole thing in 0.2.0.x. */
      SMARTLIST_FOREACH(ns->entries, routerstatus_t *, rs,
        if (rs->published_on >= cutoff)
          digestmap_set(retain, rs->descriptor_digest, (void*)1));
    });

  /* If we have a bunch of networkstatuses, we should consider pruning current
   * routers that are too old and that nobody recommends.  (If we don't have
   * enough networkstatuses, then we should get more before we decide to kill
   * routers.) */
  if (smartlist_len(networkstatus_list) > get_n_v2_authorities() / 2) {
    cutoff = now - ROUTER_MAX_AGE;
    /* Remove too-old unrecommended members of routerlist->routers. */
    for (i = 0; i < smartlist_len(routerlist->routers); ++i) {
      router = smartlist_get(routerlist->routers, i);
      if (router->cache_info.published_on <= cutoff &&
          !digestmap_get(retain,router->cache_info.signed_descriptor_digest)) {
        /* Too old: remove it.  (If we're a cache, just move it into
         * old_routers.) */
        log_info(LD_DIR,
                 "Forgetting obsolete (too old) routerinfo for router '%s'",
                 router->nickname);
        routerlist_remove(routerlist, router, 1);
        i--;
      }
    }
  }

  routerlist_assert_ok(routerlist);

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

  routerlist_assert_ok(routerlist);

  /* Now we might have to look at routerlist->old_routers for extraneous
   * members. (We'd keep all the members if we could, but we need to save
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

/** We just added a new descriptor that isn't of purpose
 * ROUTER_PURPOSE_GENERAL. Take whatever extra steps we need. */
static void
routerlist_descriptors_added(smartlist_t *sl)
{
  tor_assert(sl);
  control_event_descriptors_changed(sl);
  SMARTLIST_FOREACH(sl, routerinfo_t *, ri,
    if (ri->purpose == ROUTER_PURPOSE_BRIDGE)
      learned_bridge_descriptor(ri);
  );
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
  char annotation_buf[256];
  tor_assert(msg);
  *msg = NULL;

  tor_snprintf(annotation_buf, sizeof(annotation_buf),
               "@source controller\n"
               "@purpose %s\n", router_purpose_to_string(purpose));

  if (!(ri = router_parse_entry_from_string(s, NULL, 1, 0, annotation_buf))) {
    log_warn(LD_DIR, "Error parsing router descriptor; dropping.");
    *msg = "Couldn't parse router descriptor.";
    return -1;
  }
  tor_assert(ri->purpose == purpose);
  if (ri->purpose != ROUTER_PURPOSE_GENERAL)
    ri->cache_info.do_not_cache = 1;
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
    routerlist_descriptors_added(lst);
    smartlist_free(lst);
    log_debug(LD_DIR, "Added router to list");
    return 1;
  }
}

/** Given a string <b>s</b> containing some routerdescs, parse it and put the
 * routers into our directory.  If saved_location is SAVED_NOWHERE, the routers
 * are in response to a query to the network: cache them by adding them to
 * the journal.
 *
 * If <b>requested_fingerprints</b> is provided, it must contain a list of
 * uppercased fingerprints.  Do not update any router whose
 * fingerprint is not on the list; after updating a router, remove its
 * fingerprint from the list.
 *
 * If <b>descriptor_digests</b> is non-zero, then the requested_fingerprints
 * are descriptor digests. Otherwise they are identity digests.
 */
void
router_load_routers_from_string(const char *s, const char *eos,
                                saved_location_t saved_location,
                                smartlist_t *requested_fingerprints,
                                int descriptor_digests,
                                const char *prepend_annotations)
{
  smartlist_t *routers = smartlist_create(), *changed = smartlist_create();
  char fp[HEX_DIGEST_LEN+1];
  const char *msg;
  int from_cache = (saved_location != SAVED_NOWHERE);
  int allow_annotations = (saved_location != SAVED_NOWHERE);

  router_parse_list_from_string(&s, eos, routers, saved_location, 0,
                                allow_annotations, prepend_annotations);

  routers_update_status_from_networkstatus(routers, !from_cache);

  log_info(LD_DIR, "%d elements to add", smartlist_len(routers));

  SMARTLIST_FOREACH(routers, routerinfo_t *, ri,
  {
    if (requested_fingerprints) {
      base16_encode(fp, sizeof(fp), descriptor_digests ?
                      ri->cache_info.signed_descriptor_digest :
                      ri->cache_info.identity_digest,
                    DIGEST_LEN);
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

    if (ri->purpose != ROUTER_PURPOSE_GENERAL) /* XXXX020 wrong. */
      ri->cache_info.do_not_cache = 1;

    if (router_add_to_routerlist(ri, &msg, from_cache, !from_cache) >= 0) {
      smartlist_add(changed, ri);
      routerlist_descriptors_added(changed);
      smartlist_clear(changed);
    }
  });

  routerlist_assert_ok(routerlist);

  router_rebuild_store(0, &routerlist->desc_store);

  smartlist_free(routers);
  smartlist_free(changed);
}

/** Parse one or more extrainfos from <b>s</b> (ending immediately before
 * <b>eos</b> if <b>eos</b> is present).  Other arguments are as for
 * router_load_routers_from_string(). */
void
router_load_extrainfo_from_string(const char *s, const char *eos,
                                  saved_location_t saved_location,
                                  smartlist_t *requested_fingerprints,
                                  int descriptor_digests)
{
  smartlist_t *extrainfo_list = smartlist_create();
  const char *msg;
  int from_cache = (saved_location != SAVED_NOWHERE);

  router_parse_list_from_string(&s, eos, extrainfo_list, saved_location, 1, 0,
                                NULL);

  log_info(LD_DIR, "%d elements to add", smartlist_len(extrainfo_list));

  SMARTLIST_FOREACH(extrainfo_list, extrainfo_t *, ei, {
      if (requested_fingerprints) {
        char fp[HEX_DIGEST_LEN+1];
        base16_encode(fp, sizeof(fp), descriptor_digests ?
                        ei->cache_info.signed_descriptor_digest :
                        ei->cache_info.identity_digest,
                      DIGEST_LEN);
        smartlist_string_remove(requested_fingerprints, fp);
        /* XXX020 We silently let people stuff us with extrainfos we
         * didn't ask for. Is this a problem? -RD */
      }
      router_add_extrainfo_to_routerlist(ei, &msg, from_cache, !from_cache);
    });

  routerlist_assert_ok(routerlist);
  router_rebuild_store(0, &router_get_routerlist()->extrainfo_store);

  smartlist_free(extrainfo_list);
}

/** Return true iff any networkstatus includes a descriptor whose digest
 * is that of <b>desc</b>. */
static int
signed_desc_digest_is_recognized(signed_descriptor_t *desc)
{
  routerstatus_t *rs;
  const smartlist_t *networkstatus_list = networkstatus_get_v2_list();

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

/** Clear all our timeouts for fetching v2 and v3 directory stuff, and then
 * give it all a try again. */
void
routerlist_retry_directory_downloads(time_t now)
{
  router_reset_status_download_failures();
  router_reset_descriptor_download_failures();
  update_networkstatus_downloads(now);
  update_router_descriptor_downloads(now);
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
                       uint16_t dir_port, uint16_t or_port,
                       const char *digest, const char *v3_auth_digest,
                       authority_type_t type)
{
  trusted_dir_server_t *ent;
  uint32_t a;
  char *hostname = NULL;
  size_t dlen;
  if (!trusted_dir_servers)
    trusted_dir_servers = smartlist_create();

  if (!address) { /* The address is us; we should guess. */
    if (resolve_my_address(LOG_WARN, get_options(), &a, &hostname) < 0) {
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
  }

  ent = tor_malloc_zero(sizeof(trusted_dir_server_t));
  ent->nickname = nickname ? tor_strdup(nickname) : NULL;
  ent->address = hostname;
  ent->addr = a;
  ent->dir_port = dir_port;
  ent->or_port = or_port;
  ent->is_running = 1;
  ent->type = type;
  memcpy(ent->digest, digest, DIGEST_LEN);
  if (v3_auth_digest && (type & V3_AUTHORITY))
    memcpy(ent->v3_identity_digest, v3_auth_digest, DIGEST_LEN);

  dlen = 64 + strlen(hostname) + (nickname?strlen(nickname):0);
  ent->description = tor_malloc(dlen);
  if (nickname)
    tor_snprintf(ent->description, dlen, "directory server \"%s\" at %s:%d",
                 nickname, hostname, (int)dir_port);
  else
    tor_snprintf(ent->description, dlen, "directory server at %s:%d",
                 hostname, (int)dir_port);

  ent->fake_status.addr = ent->addr;
  memcpy(ent->fake_status.identity_digest, digest, DIGEST_LEN);
  if (nickname)
    strlcpy(ent->fake_status.nickname, nickname,
            sizeof(ent->fake_status.nickname));
  else
    ent->fake_status.nickname[0] = '\0';
  ent->fake_status.dir_port = ent->dir_port;
  ent->fake_status.or_port = ent->or_port;

  if (ent->or_port)
    ent->fake_status.version_supports_begindir = 1;

  smartlist_add(trusted_dir_servers, ent);
  router_dir_info_changed();
}

/** Free storage held in <b>ds</b>. */
static void
trusted_dir_server_free(trusted_dir_server_t *ds)
{
  if (ds->v3_certs) {
    SMARTLIST_FOREACH(ds->v3_certs, authority_cert_t *, cert,
                      authority_cert_free(cert));
    smartlist_free(ds->v3_certs);
  }
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
  router_dir_info_changed();
}

/** Return 1 if any trusted dir server supports v1 directories,
 * else return 0. */
int
any_trusted_dir_is_v1_authority(void)
{
  if (trusted_dir_servers)
    return get_n_authorities(V1_AUTHORITY) > 0;

  return 0;
}

/** Return a newly allocated string naming the versions of Tor recommended by
 * more than half the versioning networkstatuses. */
char *
compute_recommended_versions(time_t now, int client,
                             const char *my_version,
                             combined_version_status_t *status_out)
{
  int n_seen;
  char *current;
  smartlist_t *combined, *recommended;
  int n_versioning, n_recommending;
  char *result;
  /** holds the compromise status taken among all non-recommending
   * authorities */
  version_status_t consensus = VS_RECOMMENDED;
  const smartlist_t *networkstatus_list = networkstatus_get_v2_list();
  (void) now; /* right now, we consider *all* statuses, regardless of age. */

  tor_assert(my_version);
  tor_assert(status_out);

  memset(status_out, 0, sizeof(combined_version_status_t));

  if (!networkstatus_list)
    return tor_strdup("<none>");

  combined = smartlist_create();
  n_versioning = n_recommending = 0;
  SMARTLIST_FOREACH(networkstatus_list, networkstatus_t *, ns,
    {
      const char *vers;
      smartlist_t *versions;
      version_status_t status;
      if (! ns->recommends_versions)
        continue;
      n_versioning++;
      vers = client ? ns->client_versions : ns->server_versions;
      if (!vers)
        continue;
      versions = smartlist_create();
      smartlist_split_string(versions, vers, ",",
                             SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
      sort_version_list(versions, 1);
      smartlist_add_all(combined, versions);
      smartlist_free(versions);

      /* now, check _our_ version */
      status = tor_version_is_obsolete(my_version, vers);
      if (status == VS_RECOMMENDED)
        n_recommending++;
      consensus = version_status_join(status, consensus);
    });

  sort_version_list(combined, 0);

  current = NULL;
  n_seen = 0;
  recommended = smartlist_create();
  SMARTLIST_FOREACH(combined, char *, cp,
    {
      if (current && !strcmp(cp, current)) {
        ++n_seen;
      } else {
        if (current)
          log_info(LD_DIR,"version %s is recommended by %d authorities",
                    current, n_seen);
        if (n_seen > n_versioning/2 && current) {
          smartlist_add(recommended, current);
        }
        n_seen = 1;
        current = cp;
      }
    });
  if (current)
    log_info(LD_DIR,"version %s is recommended by %d authorities",
             current, n_seen);
  if (n_seen > n_versioning/2 && current)
    smartlist_add(recommended, current);

  result = smartlist_join_strings(recommended, ", ", 0, NULL);

  SMARTLIST_FOREACH(combined, char *, cp, tor_free(cp));
  smartlist_free(combined);
  smartlist_free(recommended);

  status_out->n_versioning = n_versioning;
  if (n_recommending > n_versioning/2) {
    status_out->consensus = VS_RECOMMENDED;
    status_out->n_concurring = n_recommending;
  } else {
    status_out->consensus = consensus;
    status_out->n_concurring = n_versioning - n_recommending;
  }

  return result;
}

/** DOCDOC */
static void
list_pending_downloads(digestmap_t *result,
                       int purpose, const char *prefix)
{
  const size_t p_len = strlen(prefix);
  smartlist_t *tmp = smartlist_create();
  smartlist_t *conns = get_connection_array();

  tor_assert(result);

  SMARTLIST_FOREACH(conns, connection_t *, conn,
  {
    if (conn->type == CONN_TYPE_DIR &&
        conn->purpose == purpose &&
        !conn->marked_for_close) {
      const char *resource = TO_DIR_CONN(conn)->requested_resource;
      if (!strcmpstart(resource, prefix))
        dir_split_resource_into_fingerprints(resource + p_len,
                                             tmp, NULL, 1, 0);
    }
  });
  SMARTLIST_FOREACH(tmp, char *, d,
                    {
                      digestmap_set(result, d, (void*)1);
                      tor_free(d);
                    });
  smartlist_free(tmp);
}

/** For every router descriptor (or extra-info document if <b>extrainfo</b> is
 * true) we are currently downloading by descriptor digest, set result[d] to
 * (void*)1. */
static void
list_pending_descriptor_downloads(digestmap_t *result, int extrainfo)
{
  int purpose =
    extrainfo ? DIR_PURPOSE_FETCH_EXTRAINFO : DIR_PURPOSE_FETCH_SERVERDESC;
  list_pending_downloads(result, purpose, "d/");
}

/** Launch downloads for all the descriptors whose digests are listed
 * as digests[i] for lo <= i < hi.  (Lo and hi may be out of range.)
 * If <b>source</b> is given, download from <b>source</b>; otherwise,
 * download from an appropriate random directory server.
 */
static void
initiate_descriptor_downloads(routerstatus_t *source,
                              int purpose,
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
    directory_initiate_command_routerstatus(source, purpose,
                                            ROUTER_PURPOSE_GENERAL,
                                            0, /* not private */
                                            resource, NULL, 0);
  } else {
    directory_get_from_dirserver(purpose, ROUTER_PURPOSE_GENERAL, resource, 1);
  }
  tor_free(resource);
}

/** Clients don't download any descriptor this recent, since it will probably
 * not have propagated to enough caches. */
#define ESTIMATED_PROPAGATION_TIME (10*60)

/** Return 0 if this routerstatus is obsolete, too new, isn't
 * running, or otherwise not a descriptor that we would make any
 * use of even if we had it. Else return 1. */
static INLINE int
client_would_use_router(routerstatus_t *rs, time_t now, or_options_t *options)
{
  if (!rs->is_running && !options->FetchUselessDescriptors) {
    /* If we had this router descriptor, we wouldn't even bother using it.
     * But, if we want to have a complete list, fetch it anyway. */
    return 0;
  }
  if (rs->published_on + ESTIMATED_PROPAGATION_TIME > now) {
    /* Most caches probably don't have this descriptor yet. */
    return 0;
  }
  return 1;
}

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
  int n_not_ready = 0, n_in_progress = 0, n_uptodate = 0, n_wouldnt_use = 0;
  or_options_t *options = get_options();
  const smartlist_t *routerstatus_list = networkstatus_get_all_statuses();

  if (!smartlist_len(routerstatus_list))
    return downloadable;

  downloading = digestmap_new();
  list_pending_descriptor_downloads(downloading, 0);

  routerstatus_list_update_from_networkstatus(now);
  SMARTLIST_FOREACH(routerstatus_list, routerstatus_t *, rs,
  {
    routerinfo_t *ri;
    if (router_get_by_descriptor_digest(rs->descriptor_digest)) {
      /* We have the 'best' descriptor for this router. */
      ++n_uptodate;
    } else if (!client_would_use_router(rs, now, options)) {
      /* We wouldn't want this descriptor even if we got it. */
      ++n_wouldnt_use;
    } else if (digestmap_get(downloading, rs->descriptor_digest)) {
      /* We're downloading this one now. */
      ++n_in_progress;
    } else if ((ri = router_get_by_digest(rs->identity_digest)) &&
               ri->cache_info.published_on > rs->published_on) {
      /* Oddly, we have a descriptor more recent than the 'best' one, but it
         was once best. So that's okay. */
      ++n_uptodate;
    } else if (!download_status_is_ready(&rs->dl_status, now,
                                         MAX_ROUTERDESC_DOWNLOAD_FAILURES)) {
      /* We failed too recently to try again. */
      ++n_not_ready;
    } else {
      /* Okay, time to try it. */
      smartlist_add(downloadable, rs->descriptor_digest);
      ++n_downloadable;
    }
  });

#if 0
  log_info(LD_DIR,
       "%d router descriptors are downloadable. "
       "%d are in progress. %d are up-to-date. "
       "%d are non-useful. %d failed too recently to retry.",
       n_downloadable, n_in_progress, n_uptodate,
       n_wouldnt_use, n_not_ready);
#endif

  digestmap_free(downloading, NULL);
  return downloadable;
}

/** Initiate new router downloads as needed, using the strategy for
 * non-directory-servers.
 *
 * We don't launch any downloads if there are fewer than MAX_DL_TO_DELAY
 * descriptors to get and less than MAX_CLIENT_INTERVAL_WITHOUT_REQUEST
 * seconds have passed.
 *
 * Otherwise, we ask for all descriptors that we think are different from what
 * we have, and that we don't currently have an in-progress download attempt
 * for. */
static void
update_router_descriptor_client_downloads(time_t now)
{
  /** Max amount of hashes to download per request.
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
   * want more, or until MAX_CLIENT_INTERVAL_WITHOUT_REQUEST has
   * passed. */
#define MAX_DL_TO_DELAY 16
  /** When directory clients have only a few servers to request, they batch
   * them until they have more, or until this amount of time has passed. */
#define MAX_CLIENT_INTERVAL_WITHOUT_REQUEST (10*60)
  smartlist_t *downloadable = NULL;
  or_options_t *options = get_options();
  const smartlist_t *networkstatus_list = networkstatus_get_v2_list();

  if (dirserver_mode(options)) {
    log_warn(LD_BUG,
             "Called router_descriptor_client_downloads() on a dir mirror?");
  }

  if (rep_hist_circbuilding_dormant(now)) {
//    log_info(LD_CIRC, "Skipping descriptor downloads: we haven't needed "
//             "any circuits lately.");
    return;
  }

  if (networkstatus_list &&
      smartlist_len(networkstatus_list) <= get_n_v2_authorities()/2) {
    log_info(LD_DIR,
             "Not enough networkstatus documents to launch requests.");
    return;
  }

  downloadable = router_list_client_downloadable();
  launch_router_descriptor_downloads(downloadable, now);
  smartlist_free(downloadable);
}

/** DOCDOC */
static void
launch_router_descriptor_downloads(smartlist_t *downloadable, time_t now)
{
  int should_delay = 0, n_downloadable;
  or_options_t *options = get_options();

  n_downloadable = smartlist_len(downloadable);
  if (!dirserver_mode(options)) {
    if (n_downloadable >= MAX_DL_TO_DELAY) {
      log_debug(LD_DIR,
             "There are enough downloadable routerdescs to launch requests.");
      should_delay = 0;
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
                 "There are not many downloadable routerdescs, but we haven't "
                 "tried downloading descriptors recently. Downloading.");
        }
      }
    }
  }

  if (! should_delay) {
    int i, n_per_request;
    const char *req_plural = "", *rtr_plural = "";
    n_per_request = (n_downloadable+MIN_REQUESTS-1) / MIN_REQUESTS;
    if (n_per_request > MAX_DL_PER_REQUEST)
      n_per_request = MAX_DL_PER_REQUEST;
    if (n_per_request < MIN_DL_PER_REQUEST)
      n_per_request = MIN_DL_PER_REQUEST;

    if (n_downloadable > n_per_request)
      req_plural = rtr_plural = "s";
    else if (n_downloadable > 1)
      rtr_plural = "s";

    log_info(LD_DIR,
             "Launching %d request%s for %d router%s, %d at a time",
             (n_downloadable+n_per_request-1)/n_per_request,
             req_plural, n_downloadable, rtr_plural, n_per_request);
    smartlist_sort_digests(downloadable);
    for (i=0; i < n_downloadable; i += n_per_request) {
      initiate_descriptor_downloads(NULL, DIR_PURPOSE_FETCH_SERVERDESC,
                                    downloadable, i, i+n_per_request);
    }
    last_routerdesc_download_attempted = now;
  }
}

/** Launch downloads for router status as needed, using the strategy used by
 * authorities and caches: download every descriptor we don't have but would
 * serve, from a random authority that lists it. */
static void
update_router_descriptor_cache_downloads(time_t now)
{
  smartlist_t **downloadable; /* For each authority, what can we dl from it? */
  smartlist_t **download_from; /*          ... and, what will we dl from it? */
  digestmap_t *map; /* Which descs are in progress, or assigned? */
  int i, j, n;
  int n_download;
  or_options_t *options = get_options();
  const smartlist_t *networkstatus_list = networkstatus_get_v2_list();

  if (! dirserver_mode(options)) {
    log_warn(LD_BUG, "Called update_router_descriptor_cache_downloads() "
             "on a non-dir-mirror?");
  }

  if (!networkstatus_list || !smartlist_len(networkstatus_list))
    return;

  map = digestmap_new();
  n = smartlist_len(networkstatus_list);

  downloadable = tor_malloc_zero(sizeof(smartlist_t*) * n);
  download_from = tor_malloc_zero(sizeof(smartlist_t*) * n);

  /* Set map[d]=1 for the digest of every descriptor that we are currently
   * downloading. */
  list_pending_descriptor_downloads(map, 0);

  /* For the digest of every descriptor that we don't have, and that we aren't
   * downloading, add d to downloadable[i] if the i'th networkstatus knows
   * about that descriptor, and we haven't already failed to get that
   * descriptor from the corresponding authority.
   */
  n_download = 0;
  SMARTLIST_FOREACH(networkstatus_list, networkstatus_t *, ns,
    {
      trusted_dir_server_t *ds;
      smartlist_t *dl;
      dl = downloadable[ns_sl_idx] = smartlist_create();
      download_from[ns_sl_idx] = smartlist_create();
      if (ns->published_on + MAX_NETWORKSTATUS_AGE+10*60 < now) {
        /* Don't download if the networkstatus is almost ancient. */
        /* Actually, I suspect what's happening here is that we ask
         * for the descriptor when we have a given networkstatus,
         * and then we get a newer networkstatus, and then we receive
         * the descriptor. Having a networkstatus actually expire is
         * probably a rare event, and we'll probably be happiest if
         * we take this clause out. -RD */
        continue;
      }

      /* Don't try dirservers that we think are down -- we might have
       * just tried them and just marked them as down. */
      ds = router_get_trusteddirserver_by_digest(ns->identity_digest);
      if (ds && !ds->is_running)
        continue;

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
          if (authdir_mode(options) && dirserv_would_reject_router(rs)) {
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
      initiate_descriptor_downloads(&(ds->fake_status),
                                    DIR_PURPOSE_FETCH_SERVERDESC, dl, j,
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

/** DOCDOC */
static void
update_consensus_router_descriptor_downloads(time_t now)
{
  or_options_t *options = get_options();
  digestmap_t *map = NULL;
  smartlist_t *downloadable = smartlist_create();
  int authdir = authdir_mode(options);
  int dirserver = dirserver_mode(options);
  networkstatus_vote_t *consensus = networkstatus_get_latest_consensus();

  if (!dirserver) {
    if (rep_hist_circbuilding_dormant(now))
      return;
  }
  if (!consensus)
    return;

  map = digestmap_new();
  list_pending_descriptor_downloads(map, 0);
  SMARTLIST_FOREACH(consensus->routerstatus_list, routerstatus_t *, rs,
    {
      /* ????020 need-to-mirror? */
      /* XXXX rate-limit retries. */
      if (router_get_by_descriptor_digest(rs->descriptor_digest))
        continue; /* We have it already. */
      if (authdir && dirserv_would_reject_router(rs))
        continue; /* We would throw it out immediately. */
      if (!dirserver && !client_would_use_router(rs, now, options))
        continue; /* We would never use it ourself. */
      if (digestmap_get(map, rs->descriptor_digest))
        continue; /* We have an in-progress download. */
      smartlist_add(downloadable, rs->descriptor_digest);
    });

  launch_router_descriptor_downloads(downloadable, now);

  smartlist_free(downloadable);
  digestmap_free(map, NULL);
}

/** Launch downloads for router status as needed. */
void
update_router_descriptor_downloads(time_t now)
{
  or_options_t *options = get_options();
  if (should_delay_dir_fetches(options))
    return;
  if (dirserver_mode(options)) {
    update_router_descriptor_cache_downloads(now);
    update_consensus_router_descriptor_downloads(now); /*XXXX020 clients too*/
  } else {
    update_router_descriptor_client_downloads(now);
  }
}

/** Return true iff <b>sd</b> is the descriptor for a router descriptor that
 * has an extrainfo that we don't currently have, are not currently
 * downloading, and have not recently tried to download. */
static INLINE int
should_download_extrainfo(signed_descriptor_t *sd,
                          const routerlist_t *rl,
                          const digestmap_t *pending,
                          time_t now)
{
  const char *d = sd->extra_info_digest;
  return (!sd->is_extrainfo &&
          !tor_digest_is_zero(d) &&
          download_status_is_ready(&sd->ei_dl_status, now,
                                   MAX_ROUTERDESC_DOWNLOAD_FAILURES) &&
          !eimap_get(rl->extra_info_map, d) &&
          !digestmap_get(pending, d));
}

/** Launch extrainfo downloads as needed. */
void
update_extrainfo_downloads(time_t now)
{
  or_options_t *options = get_options();
  routerlist_t *rl;
  smartlist_t *wanted;
  digestmap_t *pending;
  int i;
  if (! options->DownloadExtraInfo)
    return;
  if (should_delay_dir_fetches(options))
    return;

  pending = digestmap_new();
  list_pending_descriptor_downloads(pending, 1);
  rl = router_get_routerlist();
  wanted = smartlist_create();
  SMARTLIST_FOREACH(rl->routers, routerinfo_t *, ri, {
      if (should_download_extrainfo(&ri->cache_info, rl, pending, now)) {
        smartlist_add(wanted, ri->cache_info.extra_info_digest);
      }
    });
  if (dirserver_mode(options)) {
    SMARTLIST_FOREACH(rl->old_routers, signed_descriptor_t *, sd, {
        if (should_download_extrainfo(sd, rl, pending, now)) {
          smartlist_add(wanted, sd->extra_info_digest);
        }
    });
  }
  digestmap_free(pending, NULL);

  smartlist_shuffle(wanted);
  for (i = 0; i < smartlist_len(wanted); i += MAX_DL_PER_REQUEST) {
    initiate_descriptor_downloads(NULL, DIR_PURPOSE_FETCH_EXTRAINFO,
                                  wanted, i, i + MAX_DL_PER_REQUEST);
  }

  smartlist_free(wanted);
}

/** Return the number of routerstatus_t in <b>entries</b> that we'd actually
 * use. */
static int
routerstatus_count_usable_entries(smartlist_t *entries)
{
  int count = 0;
  time_t now = time(NULL);
  or_options_t *options = get_options();
  SMARTLIST_FOREACH(entries, routerstatus_t *, rs,
                    if (client_would_use_router(rs, now, options)) count++);
  return count;
}

/** True iff, the last time we checked whether we had enough directory info
 * to build circuits, the answer was "yes". */
static int have_min_dir_info = 0;
/** True iff enough has changed since the last time we checked whether we had
 * enough directory info to build circuits that our old answer can no longer
 * be trusted. */
static int need_to_update_have_min_dir_info = 1;

/** Return true iff we have enough networkstatus and router information to
 * start building circuits.  Right now, this means "more than half the
 * networkstatus documents, and at least 1/4 of expected routers." */
//XXX should consider whether we have enough exiting nodes here.
int
router_have_minimum_dir_info(void)
{
  if (PREDICT_UNLIKELY(need_to_update_have_min_dir_info)) {
    update_router_have_minimum_dir_info();
    need_to_update_have_min_dir_info = 0;
  }
  return have_min_dir_info;
}

/** Called when our internal view of the directory has changed.  This can be
 * when the authorities change, networkstatuses change, the list of routerdescs
 * changes, or number of running routers changes.
 */
void
router_dir_info_changed(void)
{
  need_to_update_have_min_dir_info = 1;
}

/** Change the value of have_min_dir_info, setting it true iff we have enough
 * network and router information to build circuits.  Clear the value of
 * need_to_update_have_min_dir_info. */
static void
update_router_have_minimum_dir_info(void)
{
  int tot = 0, num_running = 0;
  int n_ns, n_authorities, res, avg;
  time_t now = time(NULL);
  const smartlist_t *routerstatus_list = networkstatus_get_all_statuses();
  const smartlist_t *networkstatus_list = networkstatus_get_v2_list();

  if (!routerlist) {
    res = 0;
    goto done;
  }
  routerlist_remove_old_routers();
  networkstatus_list_clean(now);

  if (should_delay_dir_fetches(get_options())) {
    log_notice(LD_DIR, "no known bridge descriptors running yet; stalling");
    res = 0;
    goto done;
  }

  n_authorities = get_n_v2_authorities();
  n_ns = smartlist_len(networkstatus_list);
  if (n_ns<=n_authorities/2) {
    log_info(LD_DIR,
             "We have %d of %d network statuses, and we want "
             "more than %d.", n_ns, n_authorities, n_authorities/2);
    res = 0;
    goto done;
  }
  SMARTLIST_FOREACH(networkstatus_list, networkstatus_t *, ns,
                    tot += routerstatus_count_usable_entries(ns->entries));
  avg = tot / n_ns;
  SMARTLIST_FOREACH(routerstatus_list, routerstatus_t *, rs,
     {
       if (rs->is_running)
         num_running++;
     });
  res = smartlist_len(routerlist->routers) >= (avg/4) && num_running > 2;
 done:
  if (res && !have_min_dir_info) {
    log(LOG_NOTICE, LD_DIR,
        "We now have enough directory information to build circuits.");
    control_event_client_status(LOG_NOTICE, "ENOUGH_DIR_INFO");
  }
  if (!res && have_min_dir_info) {
    log(LOG_NOTICE, LD_DIR,"Our directory information is no longer up-to-date "
        "enough to build circuits.%s",
        num_running > 2 ? "" : " (Not enough servers seem reachable -- "
        "is your network connection down?)");
    control_event_client_status(LOG_NOTICE, "NOT_ENOUGH_DIR_INFO");
  }
  have_min_dir_info = res;
}

/** Reset the descriptor download failure count on all routers, so that we
 * can retry any long-failed routers immediately.
 */
void
router_reset_descriptor_download_failures(void)
{
  const smartlist_t *networkstatus_list = networkstatus_get_v2_list();
  const smartlist_t *routerstatus_list = networkstatus_get_all_statuses();
  SMARTLIST_FOREACH(routerstatus_list, routerstatus_t *, rs,
  {
    download_status_reset(&rs->dl_status);
  });
  SMARTLIST_FOREACH(networkstatus_list, networkstatus_t *, ns,
     SMARTLIST_FOREACH(ns->entries, routerstatus_t *, rs,
       {
         if (!router_get_by_descriptor_digest(rs->descriptor_digest))
           rs->need_to_mirror = 1;
       }));
  last_routerdesc_download_attempted = 0;
  if (!routerlist)
    return;
  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, ri,
  {
    download_status_reset(&ri->cache_info.ei_dl_status);
  });
  SMARTLIST_FOREACH(routerlist->old_routers, signed_descriptor_t *, sd,
  {
    download_status_reset(&sd->ei_dl_status);
  });
}

/** Any changes in a router descriptor's publication time larger than this are
 * automatically non-cosmetic. */
#define ROUTER_MAX_COSMETIC_TIME_DIFFERENCE (12*60*60)

/** We allow uptime to vary from how much it ought to be by this much. */
#define ROUTER_ALLOW_UPTIME_DRIFT (6*60*60)

/** Return true iff the only differences between r1 and r2 are such that
 * would not cause a recent (post 0.1.1.6) dirserver to republish.
 */
int
router_differences_are_cosmetic(routerinfo_t *r1, routerinfo_t *r2)
{
  time_t r1pub, r2pub;
  int time_difference;
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
      r1->has_old_dnsworkers != r2->has_old_dnsworkers ||
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
   * give or take some slop? */
  r1pub = r1->cache_info.published_on;
  r2pub = r2->cache_info.published_on;
  time_difference = abs(r2->uptime - (r1->uptime + (r2pub - r1pub)));
  if (time_difference > ROUTER_ALLOW_UPTIME_DRIFT &&
      time_difference > r1->uptime * .05 &&
      time_difference > r2->uptime * .05)
    return 0;

  /* Otherwise, the difference is cosmetic. */
  return 1;
}

/** Check whether <b>ri</b> is a router compatible with the extrainfo document
 * <b>ei</b>.  If no router is compatible with <b>ei</b>, <b>ei</b> should be
 * dropped.  Return 0 for "compatible", return 1 for "reject, and inform
 * whoever uploaded <b>ei</b>, and return -1 for "reject silently.".  If
 * <b>msg</b> is present, set *<b>msg</b> to a description of the
 * incompatibility (if any). */
int
routerinfo_incompatible_with_extrainfo(routerinfo_t *ri, extrainfo_t *ei,
                                       const char **msg)
{
  tor_assert(ri);
  tor_assert(ei);

  if (ei->bad_sig) {
    if (msg) *msg = "Extrainfo signature was bad, or signed with wrong key.";
    return 1;
  }

  /* The nickname must match exactly to have been generated at the same time
   * by the same router. */
  if (strcmp(ri->nickname, ei->nickname) ||
      memcmp(ri->cache_info.identity_digest, ei->cache_info.identity_digest,
             DIGEST_LEN)) {
    if (msg) *msg = "Extrainfo nickname or identity did not match routerinfo";
    return 1; /* different servers */
  }

  if (ei->pending_sig) {
    char signed_digest[128];
    if (crypto_pk_public_checksig(ri->identity_pkey, signed_digest,
                       ei->pending_sig, ei->pending_sig_len) != DIGEST_LEN ||
        memcmp(signed_digest, ei->cache_info.signed_descriptor_digest,
               DIGEST_LEN)) {
      ei->bad_sig = 1;
      tor_free(ei->pending_sig);
      if (msg) *msg = "Extrainfo signature bad, or signed with wrong key";
      return 1; /* Bad signature, or no match. */
    }

    tor_free(ei->pending_sig);
  }

  if (ei->cache_info.published_on < ri->cache_info.published_on) {
    if (msg) *msg = "Extrainfo published time did not match routerdesc";
    return 1;
  } else if (ei->cache_info.published_on > ri->cache_info.published_on) {
    if (msg) *msg = "Extrainfo published time did not match routerdesc";
    return -1;
  }

  if (memcmp(ei->cache_info.signed_descriptor_digest,
             ri->cache_info.extra_info_digest, DIGEST_LEN)) {
    if (msg) *msg = "Extrainfo digest did not match value from routerdesc";
    return 1; /* Digest doesn't match declared value. */
  }

  return 0;
}

/** Assert that the internal representation of <b>rl</b> is
 * self-consistent. */
void
routerlist_assert_ok(routerlist_t *rl)
{
  digestmap_iter_t *iter; /* XXXX020 use the appropriate iter type. */
  routerinfo_t *r2;
  signed_descriptor_t *sd2;
  if (!rl)
    return;
  SMARTLIST_FOREACH(rl->routers, routerinfo_t *, r,
  {
    r2 = rimap_get(rl->identity_map, r->cache_info.identity_digest);
    tor_assert(r == r2);
    sd2 = sdmap_get(rl->desc_digest_map,
                    r->cache_info.signed_descriptor_digest);
    tor_assert(&(r->cache_info) == sd2);
    tor_assert(r->routerlist_index == r_sl_idx);
#if 0
    /* XXXX020.
     *
     *   Hoo boy.  We need to fix this one, and the fix is a bit tricky, so
     * commenting this out is just a band-aid.
     *
     *   The problem is that, although well-behaved router descriptors
     * should never have the same value for their extra_info_digest, it's
     * possible for ill-behaved routers to claim whatever they like there.
     *
     *   The real answer is to trash desc_by_eid_map and instead have
     * something that indicates for a given extra-info digest we want,
     * what its download status is.  We'll do that as a part of routerlist
     * refactoring once consensus directories are in.  For now,
     * this rep violation is probably harmless: an adversary can make us
     * reset our retry count for an extrainfo, but that's not the end
     * of the world.
     */
    if (!tor_digest_is_zero(r->cache_info.extra_info_digest)) {
      signed_descriptor_t *sd3 =
        sdmap_get(rl->desc_by_eid_map, r->cache_info.extra_info_digest);
      tor_assert(sd3 == &(r->cache_info));
    }
#endif
  });
  SMARTLIST_FOREACH(rl->old_routers, signed_descriptor_t *, sd,
  {
    r2 = rimap_get(rl->identity_map, sd->identity_digest);
    tor_assert(sd != &(r2->cache_info));
    sd2 = sdmap_get(rl->desc_digest_map, sd->signed_descriptor_digest);
    tor_assert(sd == sd2);
#if 0
    /* XXXX020 see above. */
    if (!tor_digest_is_zero(sd->extra_info_digest)) {
      signed_descriptor_t *sd3 =
        sdmap_get(rl->desc_by_eid_map, sd->extra_info_digest);
      tor_assert(sd3 == sd);
    }
#endif
  });

  iter = digestmap_iter_init((digestmap_t*)rl->identity_map);
  while (!digestmap_iter_done(iter)) {
    const char *d;
    void *_r;
    routerinfo_t *r;
    digestmap_iter_get(iter, &d, &_r);
    r = _r;
    tor_assert(!memcmp(r->cache_info.identity_digest, d, DIGEST_LEN));
    iter = digestmap_iter_next((digestmap_t*)rl->identity_map, iter);
  }
  iter = digestmap_iter_init((digestmap_t*)rl->desc_digest_map);
  while (!digestmap_iter_done(iter)) {
    const char *d;
    void *_sd;
    signed_descriptor_t *sd;
    digestmap_iter_get(iter, &d, &_sd);
    sd = _sd;
    tor_assert(!memcmp(sd->signed_descriptor_digest, d, DIGEST_LEN));
    iter = digestmap_iter_next((digestmap_t*)rl->desc_digest_map, iter);
  }
  iter = digestmap_iter_init((digestmap_t*)rl->desc_by_eid_map);
  while (!digestmap_iter_done(iter)) {
    const char *d;
    void *_sd;
    signed_descriptor_t *sd;
    digestmap_iter_get(iter, &d, &_sd);
    sd = _sd;
    tor_assert(!tor_digest_is_zero(d));
    tor_assert(sd);
    tor_assert(!memcmp(sd->extra_info_digest, d, DIGEST_LEN));
    iter = digestmap_iter_next((digestmap_t*)rl->desc_by_eid_map, iter);
  }
  iter = digestmap_iter_init((digestmap_t*)rl->extra_info_map);
  while (!digestmap_iter_done(iter)) {
    const char *d;
    void *_ei;
    extrainfo_t *ei;
    signed_descriptor_t *sd;
    digestmap_iter_get(iter, &d, &_ei);
    ei = _ei;
    tor_assert(!memcmp(ei->cache_info.signed_descriptor_digest,
                       d, DIGEST_LEN));
    sd = sdmap_get(rl->desc_by_eid_map,
                   ei->cache_info.signed_descriptor_digest);
    // tor_assert(sd); // XXXX020 see above
    if (sd) {
      tor_assert(!memcmp(ei->cache_info.signed_descriptor_digest,
                         sd->extra_info_digest, DIGEST_LEN));
    }
    iter = digestmap_iter_next((digestmap_t*)rl->extra_info_map, iter);
  }
}

/** Allocate and return a new string representing the contact info
 * and platform string for <b>router</b>,
 * surrounded by quotes and using standard C escapes.
 *
 * THIS FUNCTION IS NOT REENTRANT.  Don't call it from outside the main
 * thread.  Also, each call invalidates the last-returned value, so don't
 * try log_warn(LD_GENERAL, "%s %s", esc_router_info(a), esc_router_info(b));
 *
 * If <b>router</b> is NULL, it just frees its internal memory and returns.
 */
const char *
esc_router_info(routerinfo_t *router)
{
  static char *info=NULL;
  char *esc_contact, *esc_platform;
  size_t len;
  if (info)
    tor_free(info);
  if (!router)
    return NULL; /* we're exiting; just free the memory we use */

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

