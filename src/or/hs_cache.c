/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_cache.c
 * \brief Handle hidden service descriptor caches.
 **/

/* For unit tests.*/
#define HS_CACHE_PRIVATE

#include "hs_cache.h"

#include "or.h"
#include "config.h"
#include "hs_common.h"
#include "hs_descriptor.h"
#include "rendcache.h"

/* Directory descriptor cache. Map indexed by blinded key. */
static digest256map_t *hs_cache_v3_dir;

/* Remove a given descriptor from our cache. */
static void
remove_v3_desc_as_dir(const hs_cache_dir_descriptor_t *desc)
{
  tor_assert(desc);
  digest256map_remove(hs_cache_v3_dir, desc->key);
}

/* Store a given descriptor in our cache. */
static void
store_v3_desc_as_dir(hs_cache_dir_descriptor_t *desc)
{
  tor_assert(desc);
  digest256map_set(hs_cache_v3_dir, desc->key, desc);
}

/* Query our cache and return the entry or NULL if not found. */
static hs_cache_dir_descriptor_t *
lookup_v3_desc_as_dir(const uint8_t *key)
{
  tor_assert(key);
  return digest256map_get(hs_cache_v3_dir, key);
}

/* Free a directory descriptor object. */
static void
cache_dir_desc_free(hs_cache_dir_descriptor_t *desc)
{
  if (desc == NULL) {
    return;
  }
  hs_desc_plaintext_data_free(desc->plaintext_data);
  tor_free(desc->encoded_desc);
  tor_free(desc);
}

/* Helper function: Use by the free all function using the digest256map
 * interface to cache entries. */
static void
cache_dir_desc_free_(void *ptr)
{
  hs_cache_dir_descriptor_t *desc = ptr;
  cache_dir_desc_free(desc);
}

/* Create a new directory cache descriptor object from a encoded descriptor.
 * On success, return the heap-allocated cache object, otherwise return NULL if
 * we can't decode the descriptor. */
static hs_cache_dir_descriptor_t *
cache_dir_desc_new(const char *desc)
{
  hs_cache_dir_descriptor_t *dir_desc;

  tor_assert(desc);

  dir_desc = tor_malloc_zero(sizeof(hs_cache_dir_descriptor_t));
  dir_desc->plaintext_data =
    tor_malloc_zero(sizeof(hs_desc_plaintext_data_t));
  dir_desc->encoded_desc = tor_strdup(desc);

  if (hs_desc_decode_plaintext(desc, dir_desc->plaintext_data) < 0) {
    log_debug(LD_DIR, "Unable to decode descriptor. Rejecting.");
    goto err;
  }

  /* The blinded pubkey is the indexed key. */
  dir_desc->key = dir_desc->plaintext_data->blinded_kp.pubkey.pubkey;
  dir_desc->created_ts = time(NULL);
  return dir_desc;

 err:
  cache_dir_desc_free(dir_desc);
  return NULL;
}

/* Return the size of a cache entry in bytes. */
static size_t
cache_get_entry_size(const hs_cache_dir_descriptor_t *entry)
{
  return (sizeof(*entry) + hs_desc_plaintext_obj_size(entry->plaintext_data)
          + strlen(entry->encoded_desc));
}

/* Try to store a valid version 3 descriptor in the directory cache. Return 0
 * on success else a negative value is returned indicating that we have a
 * newer version in our cache. On error, caller is responsible to free the
 * given descriptor desc. */
static int
cache_store_v3_as_dir(hs_cache_dir_descriptor_t *desc)
{
  hs_cache_dir_descriptor_t *cache_entry;

  tor_assert(desc);

  /* Verify if we have an entry in the cache for that key and if yes, check
   * if we should replace it? */
  cache_entry = lookup_v3_desc_as_dir(desc->key);
  if (cache_entry != NULL) {
    /* Only replace descriptor if revision-counter is greater than the one
     * in our cache */
    if (cache_entry->plaintext_data->revision_counter >=
        desc->plaintext_data->revision_counter) {
      log_info(LD_REND, "Descriptor revision counter in our cache is "
                        "greater or equal than the one we received. "
                        "Rejecting!");
      goto err;
    }
    /* We now know that the descriptor we just received is a new one so
     * remove the entry we currently have from our cache so we can then
     * store the new one. */
    remove_v3_desc_as_dir(cache_entry);
    rend_cache_decrement_allocation(cache_get_entry_size(cache_entry));
    cache_dir_desc_free(cache_entry);
  }
  /* Store the descriptor we just got. We are sure here that either we
   * don't have the entry or we have a newer descriptor and the old one
   * has been removed from the cache. */
  store_v3_desc_as_dir(desc);

  /* Update our total cache size with this entry for the OOM. This uses the
   * old HS protocol cache subsystem for which we are tied with. */
  rend_cache_increment_allocation(cache_get_entry_size(desc));

  /* XXX: Update HS statistics. We should have specific stats for v3. */

  return 0;

 err:
  return -1;
}

/* Using the query which is the base64 encoded blinded key of a version 3
 * descriptor, lookup in our directory cache the entry. If found, 1 is
 * returned and desc_out is populated with a newly allocated string being the
 * encoded descriptor. If not found, 0 is returned and desc_out is untouched.
 * On error, a negative value is returned and desc_out is untouched. */
static int
cache_lookup_v3_as_dir(const char *query, const char **desc_out)
{
  int found = 0;
  ed25519_public_key_t blinded_key;
  const hs_cache_dir_descriptor_t *entry;

  tor_assert(query);

  /* Decode blinded key using the given query value. */
  if (ed25519_public_from_base64(&blinded_key, query) < 0) {
    log_info(LD_REND, "Unable to decode the v3 HSDir query %s.",
             safe_str_client(query));
    goto err;
  }

  entry = lookup_v3_desc_as_dir(blinded_key.pubkey);
  if (entry != NULL) {
    found = 1;
    if (desc_out) {
      *desc_out = entry->encoded_desc;
    }
  }

  return found;

 err:
  return -1;
}

/* Clean the v3 cache by removing any entry that has expired using the
 * <b>global_cutoff</b> value. If <b>global_cutoff</b> is 0, the cleaning
 * process will use the lifetime found in the plaintext data section. Return
 * the number of bytes cleaned. */
STATIC size_t
cache_clean_v3_as_dir(time_t now, time_t global_cutoff)
{
  size_t bytes_removed = 0;

  /* Code flow error if this ever happens. */
  tor_assert(global_cutoff >= 0);

  if (!hs_cache_v3_dir) { /* No cache to clean. Just return. */
    return 0;
  }

  DIGEST256MAP_FOREACH_MODIFY(hs_cache_v3_dir, key,
                              hs_cache_dir_descriptor_t *, entry) {
    size_t entry_size;
    time_t cutoff = global_cutoff;
    if (!cutoff) {
      /* Cutoff is the lifetime of the entry found in the descriptor. */
      cutoff = now - entry->plaintext_data->lifetime_sec;
    }

    /* If the entry has been created _after_ the cutoff, not expired so
     * continue to the next entry in our v3 cache. */
    if (entry->created_ts > cutoff) {
      continue;
    }
    /* Here, our entry has expired, remove and free. */
    MAP_DEL_CURRENT(key);
    entry_size = cache_get_entry_size(entry);
    bytes_removed += entry_size;
    /* Entry is not in the cache anymore, destroy it. */
    cache_dir_desc_free(entry);
    /* Update our cache entry allocation size for the OOM. */
    rend_cache_decrement_allocation(entry_size);
    /* Logging. */
    {
      char key_b64[BASE64_DIGEST256_LEN + 1];
      base64_encode(key_b64, sizeof(key_b64), (const char *) key,
                    DIGEST256_LEN, 0);
      log_info(LD_REND, "Removing v3 descriptor '%s' from HSDir cache",
               safe_str_client(key_b64));
    }
  } DIGEST256MAP_FOREACH_END;

  return bytes_removed;
}

/* Given an encoded descriptor, store it in the directory cache depending on
 * which version it is. Return a negative value on error. On success, 0 is
 * returned. */
int
hs_cache_store_as_dir(const char *desc)
{
  hs_cache_dir_descriptor_t *dir_desc = NULL;

  tor_assert(desc);

  /* Create a new cache object. This can fail if the descriptor plaintext data
   * is unparseable which in this case a log message will be triggered. */
  dir_desc = cache_dir_desc_new(desc);
  if (dir_desc == NULL) {
    goto err;
  }

  /* Call the right function against the descriptor version. At this point,
   * we are sure that the descriptor's version is supported else the
   * decoding would have failed. */
  switch (dir_desc->plaintext_data->version) {
  case HS_VERSION_THREE:
  default:
    if (cache_store_v3_as_dir(dir_desc) < 0) {
      goto err;
    }
    break;
  }
  return 0;

 err:
  cache_dir_desc_free(dir_desc);
  return -1;
}

/* Using the query, lookup in our directory cache the entry. If found, 1 is
 * returned and desc_out is populated with a newly allocated string being
 * the encoded descriptor. If not found, 0 is returned and desc_out is
 * untouched. On error, a negative value is returned and desc_out is
 * untouched. */
int
hs_cache_lookup_as_dir(uint32_t version, const char *query,
                       const char **desc_out)
{
  int found;

  tor_assert(query);
  /* This should never be called with an unsupported version. */
  tor_assert(hs_desc_is_supported_version(version));

  switch (version) {
  case HS_VERSION_THREE:
  default:
    found = cache_lookup_v3_as_dir(query, desc_out);
    break;
  }

  return found;
}

/* Clean all directory caches using the current time now. */
void
hs_cache_clean_as_dir(time_t now)
{
  time_t cutoff;

  /* Start with v2 cache cleaning. */
  cutoff = now - rend_cache_max_entry_lifetime();
  rend_cache_clean_v2_descs_as_dir(cutoff);

  /* Now, clean the v3 cache. Set the cutoff to 0 telling the cleanup function
   * to compute the cutoff by itself using the lifetime value. */
  cache_clean_v3_as_dir(now, 0);
}

/* Do a round of OOM cleanup on all directory caches. Return the amount of
 * removed bytes. It is possible that the returned value is lower than
 * min_remove_bytes if the caches get emptied out so the caller should be
 * aware of this. */
size_t
hs_cache_handle_oom(time_t now, size_t min_remove_bytes)
{
  time_t k;
  size_t bytes_removed = 0;

  /* Our OOM handler called with 0 bytes to remove is a code flow error. */
  tor_assert(min_remove_bytes != 0);

  /* The algorithm is as follow. K is the oldest expected descriptor age.
   *
   *   1) Deallocate all entries from v2 cache that are older than K hours.
   *      1.1) If the amount of remove bytes has been reached, stop.
   *   2) Deallocate all entries from v3 cache that are older than K hours
   *      2.1) If the amount of remove bytes has been reached, stop.
   *   3) Set K = K - RendPostPeriod and repeat process until K is < 0.
   *
   * This ends up being O(Kn).
   */

  /* Set K to the oldest expected age in seconds which is the maximum
   * lifetime of a cache entry. We'll use the v2 lifetime because it's much
   * bigger than the v3 thus leading to cleaning older descriptors. */
  k = rend_cache_max_entry_lifetime();

  do {
    time_t cutoff;

    /* If K becomes negative, it means we've empty the caches so stop and
     * return what we were able to cleanup. */
    if (k < 0) {
      break;
    }
    /* Compute a cutoff value with K and the current time. */
    cutoff = now - k;

    /* Start by cleaning the v2 cache with that cutoff. */
    bytes_removed += rend_cache_clean_v2_descs_as_dir(cutoff);

    if (bytes_removed < min_remove_bytes) {
      /* We haven't remove enough bytes so clean v3 cache. */
      bytes_removed += cache_clean_v3_as_dir(now, cutoff);
      /* Decrement K by a post period to shorten the cutoff. */
      k -= get_options()->RendPostPeriod;
    }
  } while (bytes_removed < min_remove_bytes);

  return bytes_removed;
}

/* Initialize the hidden service cache subsystem. */
void
hs_cache_init(void)
{
  /* Calling this twice is very wrong code flow. */
  tor_assert(!hs_cache_v3_dir);
  hs_cache_v3_dir = digest256map_new();
}

/* Cleanup the hidden service cache subsystem. */
void
hs_cache_free_all(void)
{
  digest256map_free(hs_cache_v3_dir, cache_dir_desc_free_);
  hs_cache_v3_dir = NULL;
}

