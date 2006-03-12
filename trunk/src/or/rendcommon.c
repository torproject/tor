/* Copyright 2004-2006 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char rendcommon_c_id[] =
  "$Id$";

/**
 * \file rendcommon.c
 * \brief Rendezvous implementation: shared code between
 * introducers, services, clients, and rendezvous points.
 **/

#include "or.h"

/** Return 0 if one and two are the same service ids, else -1 or 1 */
int
rend_cmp_service_ids(const char *one, const char *two)
{
  return strcasecmp(one,two);
}

/** Free the storage held by the service descriptor <b>desc</b>.
 */
void
rend_service_descriptor_free(rend_service_descriptor_t *desc)
{
  int i;
  if (desc->pk)
    crypto_free_pk_env(desc->pk);
  if (desc->intro_points) {
    for (i=0; i < desc->n_intro_points; ++i) {
      tor_free(desc->intro_points[i]);
    }
    tor_free(desc->intro_points);
  }
  if (desc->intro_point_extend_info) {
    for (i=0; i < desc->n_intro_points; ++i) {
      if (desc->intro_point_extend_info[i])
        extend_info_free(desc->intro_point_extend_info[i]);
    }
    tor_free(desc->intro_point_extend_info);
  }
  tor_free(desc);
}

/** Encode a service descriptor for <b>desc</b>, and sign it with
 * <b>key</b>. Store the descriptor in *<b>str_out</b>, and set
 * *<b>len_out</b> to its length.
 */
int
rend_encode_service_descriptor(rend_service_descriptor_t *desc,
                               int version,
                               crypto_pk_env_t *key,
                               char **str_out, size_t *len_out)
{
  char *cp;
  char *end;
  int i;
  size_t asn1len;
  size_t buflen = PK_BYTES*2*(desc->n_intro_points+2);/*Too long, but ok*/
  cp = *str_out = tor_malloc(buflen);
  end = cp + PK_BYTES*2*(desc->n_intro_points+1);
  if (version) {
    *(uint8_t*)cp = (uint8_t)0xff;
    *(uint8_t*)(cp+1) = (uint8_t)version;
    cp += 2;
  }
  asn1len = crypto_pk_asn1_encode(desc->pk, cp+2, end-(cp+2));
  set_uint16(cp, htons((uint16_t)asn1len));
  cp += 2+asn1len;
  set_uint32(cp, htonl((uint32_t)desc->timestamp));
  cp += 4;
  if (version == 1) {
    set_uint16(cp, htons(desc->protocols));
    cp += 2;
  }
  set_uint16(cp, htons((uint16_t)desc->n_intro_points));
  cp += 2;
  if (version == 0) {
    for (i=0; i < desc->n_intro_points; ++i) {
      char *ipoint = (char*)desc->intro_points[i];
      strlcpy(cp, ipoint, buflen-(cp-*str_out));
      cp += strlen(ipoint)+1;
    }
  } else {
    if (desc->n_intro_points)
      tor_assert(desc->intro_point_extend_info);
    for (i=0; i < desc->n_intro_points; ++i) {
      extend_info_t *info = desc->intro_point_extend_info[i];
      int klen;
      set_uint32(cp, htonl(info->addr));
      set_uint16(cp+4, htons(info->port));
      memcpy(cp+6, info->identity_digest, DIGEST_LEN);
      klen = crypto_pk_asn1_encode(info->onion_key, cp+6+DIGEST_LEN+2,
                                   (end-(cp+6+DIGEST_LEN+2)));
      set_uint16(cp+6+DIGEST_LEN, htons((uint16_t)klen));
      cp += 6+DIGEST_LEN+2+klen;
    }
  }
  i = crypto_pk_private_sign_digest(key, cp, *str_out, cp-*str_out);
  if (i<0) {
    tor_free(*str_out);
    return -1;
  }
  cp += i;
  *len_out = (size_t)(cp-*str_out);
  return 0;
}

/** Parse a service descriptor at <b>str</b> (<b>len</b> bytes).  On
 * success, return a newly alloced service_descriptor_t.  On failure,
 * return NULL.
 */
rend_service_descriptor_t *
rend_parse_service_descriptor(const char *str, size_t len)
{
  rend_service_descriptor_t *result = NULL;
  int i;
  size_t keylen, asn1len;
  const char *end, *cp, *eos;
  int version = 0;

  result = tor_malloc_zero(sizeof(rend_service_descriptor_t));
  cp = str;
  end = str+len;
  if (end-cp<2) goto truncated;
  if (*(uint8_t*)cp == 0xff) {
    result->version = version = *(uint8_t*)(cp+1);
    cp += 2;
  } else {
    result->version = version = 0;
  }
  if (end-cp < 2) goto truncated;
  asn1len = ntohs(get_uint16(cp));
  cp += 2;
  if ((size_t)(end-cp) < asn1len) goto truncated;
  result->pk = crypto_pk_asn1_decode(cp, asn1len);
  if (!result->pk) goto truncated;
  cp += asn1len;
  if (end-cp < 4) goto truncated;
  result->timestamp = (time_t) ntohl(get_uint32(cp));
  cp += 4;
  if (version == 1) {
    if (end-cp < 2) goto truncated;
    result->protocols = ntohs(get_uint16(cp));
    cp += 2;
  } else {
    result->protocols = 1;
  }
  if (end-cp < 2) goto truncated;
  result->n_intro_points = ntohs(get_uint16(cp));
  cp += 2;

  if (version == 0 && result->n_intro_points != 0) {
    result->intro_points =
      tor_malloc_zero(sizeof(char*)*result->n_intro_points);
    for (i=0;i<result->n_intro_points;++i) {
      if (end-cp < 2) goto truncated;
      eos = (const char *)memchr(cp,'\0',end-cp);
      if (!eos) goto truncated;
      result->intro_points[i] = tor_strdup(cp);
      cp = eos+1;
    }
  } else if (version != 0 && result->n_intro_points != 0) {
    result->intro_point_extend_info =
      tor_malloc_zero(sizeof(extend_info_t*)*result->n_intro_points);
    result->intro_points =
      tor_malloc_zero(sizeof(char*)*result->n_intro_points);
    for (i=0;i<result->n_intro_points;++i) {
      extend_info_t *info = result->intro_point_extend_info[i] =
        tor_malloc_zero(sizeof(extend_info_t));
      int klen;
      if (end-cp < 8+DIGEST_LEN) goto truncated;
      info->addr = ntohl(get_uint32(cp));
      info->port = ntohs(get_uint16(cp+4));
      memcpy(info->identity_digest, cp+6, DIGEST_LEN);
      info->nickname[0] = '$';
      base16_encode(info->nickname+1, sizeof(info->nickname)-1,
                    info->identity_digest, DIGEST_LEN);
      result->intro_points[i] = tor_strdup(info->nickname);
      klen = ntohs(get_uint16(cp+6+DIGEST_LEN));
      cp += 8+DIGEST_LEN;
      if (end-cp < klen) goto truncated;
      if (!(info->onion_key = crypto_pk_asn1_decode(cp,klen))) {
        log_warn(LD_PROTOCOL,
                 "Internal error decoding onion key for intro point.");
        goto error;
      }
      cp += klen;
    }
  }
  keylen = crypto_pk_keysize(result->pk);
  tor_assert(end-cp >= 0);
  if ((size_t)(end-cp) < keylen) goto truncated;
  if ((size_t)(end-cp) > keylen) {
    log_warn(LD_PROTOCOL,
             "Signature is %d bytes too long on service descriptor.",
             (int)((size_t)(end-cp) - keylen));
    goto error;
  }
  if (crypto_pk_public_checksig_digest(result->pk,
                                       (char*)str,cp-str, /* data */
                                       (char*)cp,end-cp  /* signature*/
                                       )<0) {
    log_warn(LD_PROTOCOL, "Bad signature on service descriptor.");
    goto error;
  }

  return result;
 truncated:
  log_warn(LD_PROTOCOL, "Truncated service descriptor.");
 error:
  rend_service_descriptor_free(result);
  return NULL;
}

/** Sets <b>out</b> to the first 10 bytes of the digest of <b>pk</b>,
 * base32 encoded.  NUL-terminates out.  (We use this string to
 * identify services in directory requests and .onion URLs.)
 */
int
rend_get_service_id(crypto_pk_env_t *pk, char *out)
{
  char buf[DIGEST_LEN];
  tor_assert(pk);
  if (crypto_pk_get_digest(pk, buf) < 0)
    return -1;
  base32_encode(out, REND_SERVICE_ID_LEN+1, buf, 10);
  return 0;
}

/* ==== Rendezvous service descriptor cache. */

/** How old do we let hidden service descriptors get discarding them as too
 * old? */
#define REND_CACHE_MAX_AGE (2*24*60*60)
/** How wrong to we assume our clock may be when checking whether hidden
 * services are too old or too new? */
#define REND_CACHE_MAX_SKEW (24*60*60)

/** Map from service id (as generated by rend_get_service_id) to
 * rend_cache_entry_t. */
static strmap_t *rend_cache = NULL;

/** Initializes the service descriptor cache.
 */
void
rend_cache_init(void)
{
  rend_cache = strmap_new();
}

/** Helper: free storage held by a single service descriptor cache entry. */
static void
_rend_cache_entry_free(void *p)
{
  rend_cache_entry_t *e = p;
  rend_service_descriptor_free(e->parsed);
  tor_free(e->desc);
  tor_free(e);
}

/** Free all storage held by the service descriptor cache. */
void
rend_cache_free_all(void)
{
  strmap_free(rend_cache, _rend_cache_entry_free);
  rend_cache = NULL;
}

/** Removes all old entries from the service descriptor cache.
 */
void
rend_cache_clean(void)
{
  strmap_iter_t *iter;
  const char *key;
  void *val;
  rend_cache_entry_t *ent;
  time_t cutoff;
  cutoff = time(NULL) - REND_CACHE_MAX_AGE - REND_CACHE_MAX_SKEW;
  for (iter = strmap_iter_init(rend_cache); !strmap_iter_done(iter); ) {
    strmap_iter_get(iter, &key, &val);
    ent = (rend_cache_entry_t*)val;
    if (ent->parsed->timestamp < cutoff) {
      iter = strmap_iter_next_rmv(rend_cache, iter);
      _rend_cache_entry_free(ent);
    } else {
      iter = strmap_iter_next(rend_cache, iter);
    }
  }
}

/** Return true iff <b>query</b> is a syntactically valid service ID (as
 * generated by rend_get_service_id).  */
int
rend_valid_service_id(const char *query)
{
  if (strlen(query) != REND_SERVICE_ID_LEN)
    return 0;

  if (strspn(query, BASE32_CHARS) != REND_SERVICE_ID_LEN)
    return 0;

  return 1;
}

/** If we have a cached rend_cache_entry_t for the service ID <b>query</b>,
 * set *<b>e</b> to that entry and return 1.  Else return 0.  If
 * <b>version</b> is nonnegative, only return an entry in that descriptor
 * format version. Otherwise (if <b>version</b> is negative), return the most
 * recent format we have.
 */
int
rend_cache_lookup_entry(const char *query, int version, rend_cache_entry_t **e)
{
  char key[REND_SERVICE_ID_LEN+2];
  tor_assert(rend_cache);
  if (!rend_valid_service_id(query))
    return -1;
  *e = NULL;
  if (version != 0) {
    tor_snprintf(key, sizeof(key), "1%s", query);
    *e = strmap_get_lc(rend_cache, key);
  }
  if (!*e && version != 1) {
    tor_snprintf(key, sizeof(key), "0%s", query);
    *e = strmap_get_lc(rend_cache, key);
  }
  if (!*e)
    return 0;
  return 1;
}

/** <b>query</b> is a base-32'ed service id. If it's malformed, return -1.
 * Else look it up.
 *   - If it is found, point *desc to it, and write its length into
 *     *desc_len, and return 1.
 *   - If it is not found, return 0.
 * Note: calls to rend_cache_clean or rend_cache_store may invalidate
 * *desc.
 */
int
rend_cache_lookup_desc(const char *query, int version, const char **desc,
                       size_t *desc_len)
{
  rend_cache_entry_t *e;
  int r;
  r = rend_cache_lookup_entry(query,version,&e);
  if (r <= 0) return r;
  *desc = e->desc;
  *desc_len = e->len;
  return 1;
}

/** Parse *desc, calculate its service id, and store it in the cache.
 * If we have a newer descriptor with the same ID, ignore this one.
 * If we have an older descriptor with the same ID, replace it.
 * Return -1 if it's malformed or otherwise rejected; return 0 if
 * it's the same or older than one we've already got; return 1 if
 * it's novel.
 */
int
rend_cache_store(const char *desc, size_t desc_len)
{
  rend_cache_entry_t *e;
  rend_service_descriptor_t *parsed;
  char query[REND_SERVICE_ID_LEN+1];
  char key[REND_SERVICE_ID_LEN+2];
  time_t now;

  tor_assert(rend_cache);
  parsed = rend_parse_service_descriptor(desc,desc_len);
  if (!parsed) {
    log_warn(LD_PROTOCOL,"Couldn't parse service descriptor.");
    return -1;
  }
  if (rend_get_service_id(parsed->pk, query)<0) {
    log_warn(LD_BUG,"Couldn't compute service ID.");
    rend_service_descriptor_free(parsed);
    return -1;
  }
  tor_snprintf(key, sizeof(key), "%c%s", parsed->version?'1':'0', query);
  now = time(NULL);
  if (parsed->timestamp < now-REND_CACHE_MAX_AGE-REND_CACHE_MAX_SKEW) {
    log_fn(LOG_PROTOCOL_WARN, LD_REND,
           "Service descriptor %s is too old.", safe_str(query));
    rend_service_descriptor_free(parsed);
    return -1;
  }
  if (parsed->timestamp > now+REND_CACHE_MAX_SKEW) {
    log_fn(LOG_PROTOCOL_WARN, LD_REND,
           "Service descriptor %s is too far in the future.", safe_str(query));
    rend_service_descriptor_free(parsed);
    return -1;
  }
  e = (rend_cache_entry_t*) strmap_get_lc(rend_cache, key);
  if (e && e->parsed->timestamp > parsed->timestamp) {
    log_info(LD_REND,"We already have a newer service descriptor %s with the "
             "same ID and version.", safe_str(query));
    rend_service_descriptor_free(parsed);
    return 0;
  }
  if (e && e->len == desc_len && !memcmp(desc,e->desc,desc_len)) {
    log_info(LD_REND,"We already have this service descriptor %s.",
             safe_str(query));
    e->received = time(NULL);
    rend_service_descriptor_free(parsed);
    return 0;
  }
  if (!e) {
    e = tor_malloc_zero(sizeof(rend_cache_entry_t));
    strmap_set_lc(rend_cache, key, e);
  } else {
    rend_service_descriptor_free(e->parsed);
    tor_free(e->desc);
  }
  e->received = time(NULL);
  e->parsed = parsed;
  e->len = desc_len;
  e->desc = tor_malloc(desc_len);
  memcpy(e->desc, desc, desc_len);

  log_debug(LD_REND,"Successfully stored rend desc '%s', len %d.",
            safe_str(query), (int)desc_len);
  return 1;
}

/** Called when we get a rendezvous-related relay cell on circuit
 * <b>circ</b>.  Dispatch on rendezvous relay command. */
void
rend_process_relay_cell(circuit_t *circ, int command, size_t length,
                        const char *payload)
{
  int r;
  switch (command) {
    case RELAY_COMMAND_ESTABLISH_INTRO:
      r = rend_mid_establish_intro(circ,payload,length);
      break;
    case RELAY_COMMAND_ESTABLISH_RENDEZVOUS:
      r = rend_mid_establish_rendezvous(circ,payload,length);
      break;
    case RELAY_COMMAND_INTRODUCE1:
      r = rend_mid_introduce(circ,payload,length);
      break;
    case RELAY_COMMAND_INTRODUCE2:
      r = rend_service_introduce(circ,payload,length);
      break;
    case RELAY_COMMAND_INTRODUCE_ACK:
      r = rend_client_introduction_acked(circ,payload,length);
      break;
    case RELAY_COMMAND_RENDEZVOUS1:
      r = rend_mid_rendezvous(circ,payload,length);
      break;
    case RELAY_COMMAND_RENDEZVOUS2:
      r = rend_client_receive_rendezvous(circ,payload,length);
      break;
    case RELAY_COMMAND_INTRO_ESTABLISHED:
      r = rend_service_intro_established(circ,payload,length);
      break;
    case RELAY_COMMAND_RENDEZVOUS_ESTABLISHED:
      r = rend_client_rendezvous_acked(circ,payload,length);
      break;
    default:
      tor_assert(0);
  }
}

