/* Copyright (c) 2009, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"

/** DOCDOC everything here. */

#define MICRODESC_IN_CONSENSUS 1
#define MICRODESC_IN_VOTE 2

struct microdesc_cache_t {
  HT_HEAD(microdesc_map, microdesc_t) map;

  char *cache_fname;
  char *journal_fname;
  tor_mmap_t *cache_content;
  size_t journal_len;
};

static INLINE unsigned int
_microdesc_hash(microdesc_t *md)
{
  unsigned *d = (unsigned*)md->digest;
#if SIZEOF_INT == 4
  return d[0] ^ d[1] ^ d[2] ^ d[3] ^ d[4] ^ d[5] ^ d[6] ^ d[7];
#else
  return d[0] ^ d[1] ^ d[2] ^ d[3];
#endif
}

static INLINE int
_microdesc_eq(microdesc_t *a, microdesc_t *b)
{
  return !memcmp(a->digest, b->digest, DIGEST256_LEN);
}

HT_PROTOTYPE(microdesc_map, microdesc_t, node,
             _microdesc_hash, _microdesc_eq);
HT_GENERATE(microdesc_map, microdesc_t, node,
             _microdesc_hash, _microdesc_eq, 0.6,
             _tor_malloc, _tor_realloc, _tor_free);

static int
dump_microdescriptor(FILE *f, microdesc_t *md)
{
  /* XXXX drops unkown annotations. */
  if (md->last_listed) {
    char buf[ISO_TIME_LEN+1];
    format_iso_time(buf, md->last_listed);
    fprintf(f, "@last-listed %s\n", buf);
  }

  md->off = (off_t) ftell(f);
  fwrite(md->body, 1, md->bodylen, f);
  return 0;
}

static microdesc_cache_t *the_microdesc_cache = NULL;

microdesc_cache_t *
get_microdesc_cache(void)
{
  if (PREDICT_UNLIKELY(the_microdesc_cache==NULL)) {
    microdesc_cache_t *cache = tor_malloc_zero(sizeof(microdesc_cache_t));
    HT_INIT(microdesc_map, &cache->map);
    cache->cache_fname = get_datadir_fname("cached-microdescs");
    cache->journal_fname = get_datadir_fname("cached-microdescs.new");
    microdesc_cache_reload(cache);
    the_microdesc_cache = cache;
  }
  return the_microdesc_cache;
}

/* There are three sources of microdescriptors:
   1) Generated us while acting as a directory authority.
   2) Loaded from the cache on disk.
   3) Downloaded.
*/

/* Returns list of added microdesc_t. */
smartlist_t *
microdescs_add_to_cache(microdesc_cache_t *cache,
                        const char *s, const char *eos, saved_location_t where,
                        int no_save)
{
  /*XXXX need an argument that sets last_listed as appropriate. */

  smartlist_t *descriptors, *added;
  const int allow_annotations = (where != SAVED_NOWHERE);
  const int copy_body = (where != SAVED_IN_CACHE);

  descriptors = microdescs_parse_from_string(s, eos,
                                             allow_annotations,
                                             copy_body);

  added = microdescs_add_list_to_cache(cache, descriptors, where, no_save);
  smartlist_free(descriptors);
  return added;
}

/* Returns list of added microdesc_t. Frees any not added. */
smartlist_t *
microdescs_add_list_to_cache(microdesc_cache_t *cache,
                             smartlist_t *descriptors, saved_location_t where,
                             int no_save)
{
  smartlist_t *added;
  open_file_t *open_file = NULL;
  FILE *f = NULL;
  //  int n_added = 0;

  if (where == SAVED_NOWHERE && !no_save) {
    f = start_writing_to_stdio_file(cache->journal_fname, OPEN_FLAGS_APPEND,
                                    0600, &open_file);
    if (!f)
      log_warn(LD_DIR, "Couldn't append to journal in %s",
               cache->journal_fname);
  }

  added = smartlist_create();
  SMARTLIST_FOREACH_BEGIN(descriptors, microdesc_t *, md) {
    microdesc_t *md2;
    md2 = HT_FIND(microdesc_map, &cache->map, md);
    if (md2) {
      /* We already had this one. */
      if (md2->last_listed < md->last_listed)
        md2->last_listed = md->last_listed;
      microdesc_free(md);
      continue;
    }

    /* Okay, it's a new one. */
    if (f) {
      dump_microdescriptor(f, md);
      md->saved_location = SAVED_IN_JOURNAL;
    } else {
      md->saved_location = where;
    }

    md->no_save = no_save;

    HT_INSERT(microdesc_map, &cache->map, md);
    smartlist_add(added, md);
  } SMARTLIST_FOREACH_END(md);

  finish_writing_to_file(open_file); /*XXX Check me.*/
  return added;
}

void
microdesc_cache_clear(microdesc_cache_t *cache)
{
  microdesc_t **entry, **next;
  for (entry = HT_START(microdesc_map, &cache->map); entry; entry = next) {
    next = HT_NEXT_RMV(microdesc_map, &cache->map, entry);
    microdesc_free(*entry);
  }
  if (cache->cache_content) {
    tor_munmap_file(cache->cache_content);
    cache->cache_content = NULL;
  }
}

int
microdesc_cache_reload(microdesc_cache_t *cache)
{
  struct stat st;
  char *journal_content;
  smartlist_t *added;
  tor_mmap_t *mm;
  int total = 0;

  microdesc_cache_clear(cache);

  mm = cache->cache_content = tor_mmap_file(cache->cache_fname);
  if (mm) {
    added = microdescs_add_to_cache(cache, mm->data, mm->data+mm->size,
                                    SAVED_IN_CACHE, 0);
    total += smartlist_len(added);
    smartlist_free(added);
  }

  journal_content = read_file_to_str(cache->journal_fname,
                                     RFTS_IGNORE_MISSING, &st);
  if (journal_content) {
    added = microdescs_add_to_cache(cache, journal_content,
                                    journal_content+st.st_size,
                                    SAVED_IN_JOURNAL, 0);
    total += smartlist_len(added);
    smartlist_free(added);
    tor_free(journal_content);
  }
  log_notice(LD_DIR, "Reloaded microdescriptor cache.  Found %d descriptors.",
             total);
  return 0;
}

int
microdesc_cache_rebuild(microdesc_cache_t *cache)
{
  open_file_t *open_file;
  FILE *f;
  microdesc_t **mdp;
  smartlist_t *wrote;

  f = start_writing_to_stdio_file(cache->cache_fname, OPEN_FLAGS_REPLACE,
                                  0600, &open_file);
  if (!f)
    return -1;

  wrote = smartlist_create();

  HT_FOREACH(mdp, microdesc_map, &cache->map) {
    microdesc_t *md = *mdp;
    if (md->no_save)
      continue;

    dump_microdescriptor(f, md);
    if (md->saved_location != SAVED_IN_CACHE) {
      tor_free(md->body);
      md->saved_location = SAVED_IN_CACHE;
    }

    smartlist_add(wrote, md);
  }

  finish_writing_to_file(open_file); /*XXX Check me.*/

  if (cache->cache_content)
    tor_munmap_file(cache->cache_content);
  cache->cache_content = tor_mmap_file(cache->cache_fname);
  if (!cache->cache_content && smartlist_len(wrote)) {
    log_err(LD_DIR, "Couldn't map file that we just wrote to %s!",
            cache->cache_fname);
    return -1;
  }
  SMARTLIST_FOREACH_BEGIN(wrote, microdesc_t *, md) {
    if (md->no_save)
      continue;
    tor_assert(md->saved_location == SAVED_IN_CACHE);
    md->body = (char*)cache->cache_content->data + md->off;
    tor_assert(!memcmp(md->body, "onion-key", 9));
  } SMARTLIST_FOREACH_END(wrote);

  smartlist_free(wrote);

  return 0;
}

void
microdesc_free(microdesc_t *md)
{
  /* Must be removed from hash table! */
  if (md->onion_pkey)
    crypto_free_pk_env(md->onion_pkey);
  if (md->body && md->saved_location != SAVED_IN_CACHE)
    tor_free(md->body);

  if (md->family) {
    SMARTLIST_FOREACH(md->family, char *, cp, tor_free(cp));
    smartlist_free(md->family);
  }
  tor_free(md->exitsummary);

  tor_free(md);
}

