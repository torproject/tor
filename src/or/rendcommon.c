/* Copyright 2004-2007 Roger Dingledine, Nick Mathewson. */
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

/* Length of a binary-encoded rendezvous service ID. */
#define REND_SERVICE_ID_BINARY 10

/* Length of the time period that is used to encode the secret ID part of
 * versioned hidden service descriptors. */
#define REND_TIME_PERIOD_BINARY 4

/* Length of the descriptor cookie that is used for versioned hidden
 * service descriptors. */
#define REND_DESC_COOKIE_BINARY 16

/* Length of the replica number that is used to determine the secret ID
 * part of versioned hidden service descriptors. */
#define REND_REPLICA_BINARY 1

/* Length of the base32-encoded secret ID part of versioned hidden service
 * descriptors. */
#define REND_SECRET_ID_PART_BASE32 32

/* Compute the descriptor ID for <b>service_id</b> of length
 * <b>REND_SERVICE_ID_BINARY</b> and <b>secret_id_part</b> of length
 * <b>DIGEST_LEN</b>, and write it to <b>descriptor_id_out</b> of length
 * <b>DIGEST_LEN</b>. */
void
rend_get_descriptor_id_bytes(char *descriptor_id_out,
                             const char *service_id,
                             const char *secret_id_part)
{
  crypto_digest_env_t *digest = crypto_new_digest_env();
  crypto_digest_add_bytes(digest, service_id, REND_SERVICE_ID_BINARY);
  crypto_digest_add_bytes(digest, secret_id_part, DIGEST_LEN);
  crypto_digest_get_digest(digest, descriptor_id_out, DIGEST_LEN);
  crypto_free_digest_env(digest);
}

/* Compute the secret ID part for <b>time_period</b> of length
 * <b>REND_TIME_PERIOD_BINARY</b>, <b>descriptor_cookie</b> of length
 * <b>REND_DESC_COOKIE_BINARY</b> which may also be <b>NULL</b> if no
 * descriptor_cookie shall be used, and <b>replica</b>, and write it to
 * <b>secret_id_part</b> of length DIGEST_LEN. */
static void
get_secret_id_part_bytes(char *secret_id_part, const char *time_period,
                         const char *descriptor_cookie, uint8_t replica)
{
  crypto_digest_env_t *digest = crypto_new_digest_env();
  crypto_digest_add_bytes(digest, time_period, REND_TIME_PERIOD_BINARY);
  if (descriptor_cookie) {
    crypto_digest_add_bytes(digest, descriptor_cookie,
                            REND_DESC_COOKIE_BINARY);
  }
  crypto_digest_add_bytes(digest, (const char *)&replica, REND_REPLICA_BINARY);
  crypto_digest_get_digest(digest, secret_id_part, DIGEST_LEN);
  crypto_free_digest_env(digest);
}

/* Compute the time period bytes for time <b>now</b> plus a potentially
 * intended <b>deviation</b> of one or more periods, and the first byte of
 * <b>service_id</b>, and write it to <b>time_period</b> of length 4. */
static void
get_time_period_bytes(char *time_period, time_t now, uint8_t deviation,
                      const char *service_id)
{
  uint32_t host_order =
    (uint32_t)
    (now + ((uint8_t) *service_id) * REND_TIME_PERIOD_V2_DESC_VALIDITY / 256)
    / REND_TIME_PERIOD_V2_DESC_VALIDITY + deviation;
  uint32_t network_order = htonl(host_order);
  set_uint32(time_period, network_order);
}

/* Compute the time in seconds that a descriptor that is generated
 * <b>now</b> for <b>service_id</b> will be valid. */
static uint32_t
get_seconds_valid(time_t now, const char *service_id)
{
  uint32_t result = REND_TIME_PERIOD_V2_DESC_VALIDITY -
    (uint32_t)
    (now + ((uint8_t) *service_id) * REND_TIME_PERIOD_V2_DESC_VALIDITY / 256)
    % REND_TIME_PERIOD_V2_DESC_VALIDITY;
  return result;
}

/* Compute the binary <b>desc_id</b> for a given base32-encoded
 * <b>service_id</b> and binary encoded <b>descriptor_cookie</b> of length
 * 16 that may be <b>NULL</b> at time <b>now</b> for replica number
 * <b>replica</b>. <b>desc_id</b> needs to have <b>DIGEST_LEN</b> bytes
 * free. Return 0 for success, -1 otherwise. */
int
rend_compute_v2_desc_id(char *desc_id_out, const char *service_id,
                        const char *descriptor_cookie, time_t now,
                        uint8_t replica)
{
  char service_id_binary[REND_SERVICE_ID_BINARY];
  char time_period[REND_TIME_PERIOD_BINARY];
  char secret_id_part[DIGEST_LEN];
  if (!service_id ||
      strlen(service_id) != REND_SERVICE_ID_LEN) {
    log_warn(LD_REND, "Could not compute v2 descriptor ID: "
                      "Illegal service ID: %s", service_id);
    return -1;
  }
  if (replica >= REND_NUMBER_OF_NON_CONSECUTIVE_REPLICAS) {
    log_warn(LD_REND, "Could not compute v2 descriptor ID: "
                      "Replica number out of range: %d", replica);
    return -1;
  }
  /* Convert service ID to binary. */
  if (base32_decode(service_id_binary, REND_SERVICE_ID_BINARY,
                    service_id, REND_SERVICE_ID_LEN) < 0) {
    log_warn(LD_REND, "Could not compute v2 descriptor ID: "
                      "Illegal characters in service ID: %s",
             service_id);
    return -1;
  }
  /* Calculate current time-period. */
  get_time_period_bytes(time_period, now, 0, service_id_binary);
  /* Calculate secret-id-part = h(time-period + replica). */
  get_secret_id_part_bytes(secret_id_part, time_period, descriptor_cookie,
                           replica);
  /* Calculate descriptor ID. */
  rend_get_descriptor_id_bytes(desc_id_out, service_id_binary, secret_id_part);
  return 0;
}

/* Encode the introduction points in <b>desc</b>, optionally encrypt them
 * with <b>descriptor_cookie</b> of length 16 that may also be <b>NULL</b>,
 * write them to a newly allocated string, and write a pointer to it to
 * <b>ipos_base64</b>. Return 0 for success, -1 otherwise. */
static int
rend_encode_v2_intro_points(char **ipos_base64,
                            rend_service_descriptor_t *desc,
                            const char *descriptor_cookie)
{
  size_t unenc_len;
  char *unenc;
  size_t unenc_written = 0;
  char *enc;
  int enclen;
  int i;
  crypto_cipher_env_t *cipher;
  /* Assemble unencrypted list of introduction points. */
  unenc_len = desc->n_intro_points * 1000; /* too long, but ok. */
  unenc = tor_malloc_zero(unenc_len);
  for (i = 0; i < desc->n_intro_points; i++) {
    char id_base32[32 + 1];
    char *onion_key;
    size_t onion_key_len;
    crypto_pk_env_t *intro_key;
    char *service_key;
    size_t service_key_len;
    int res;
    char hex_digest[HEX_DIGEST_LEN+2];
    /* Obtain extend info with introduction point details. */
    extend_info_t *info = desc->intro_point_extend_info[i];
    /* Encode introduction point ID. */
    base32_encode(id_base32, 32 + 1, info->identity_digest, DIGEST_LEN);
    /* Encode onion key. */
    if (crypto_pk_write_public_key_to_string(info->onion_key, &onion_key,
                                             &onion_key_len) < 0) {
      log_warn(LD_REND, "Could not write onion key.");
      if (onion_key) tor_free(onion_key);
      tor_free(unenc);
      return -1;
    }
    /* Encode intro key. */
    hex_digest[0] = '$';
    base16_encode(hex_digest+1, HEX_DIGEST_LEN+1,
                  info->identity_digest,
                  DIGEST_LEN);
    intro_key = strmap_get(desc->intro_keys, hex_digest);
    if (!intro_key ||
      crypto_pk_write_public_key_to_string(intro_key, &service_key,
                                           &service_key_len) < 0) {
      log_warn(LD_REND, "Could not write intro key.");
      if (service_key) tor_free(service_key);
      tor_free(onion_key);
      tor_free(unenc);
      return -1;
    }
    /* Assemble everything for this introduction point. */
    res = tor_snprintf(unenc + unenc_written, unenc_len - unenc_written,
                         "introduction-point %s\n"
                         "ip-address %s\n"
                         "onion-port %d\n"
                         "onion-key\n%s"
                         "service-key\n%s",
                       id_base32,
                       tor_dup_addr(info->addr),
                       info->port,
                       onion_key,
                       service_key);
    tor_free(onion_key);
    tor_free(service_key);
    if (res < 0) {
      log_warn(LD_REND, "Not enough space for writing introduction point "
                        "string.");
      tor_free(unenc);
      return -1;
    }
    /* Update total number of written bytes for unencrypted intro points. */
    unenc_written += res;
  }
  /* Finalize unencrypted introduction points. */
  if (unenc_len < unenc_written + 2) {
    log_warn(LD_REND, "Not enough space for finalizing introduction point "
                      "string.");
    tor_free(unenc);
    return -1;
  }
  unenc[unenc_written++] = '\n';
  unenc[unenc_written++] = 0;
  /* If a descriptor cookie is passed, encrypt introduction points. */
  if (descriptor_cookie) {
    enc = tor_malloc_zero(unenc_written + 16);
    cipher = crypto_create_init_cipher(descriptor_cookie, 1);
    enclen = crypto_cipher_encrypt_with_iv(cipher, enc, unenc_written + 16,
                                           unenc, unenc_written);
    crypto_free_cipher_env(cipher);
    tor_free(unenc);
    if (enclen < 0) {
      log_warn(LD_REND, "Could not encrypt introduction point string.");
      if (enc) tor_free(enc);
      return -1;
    }
    /* Replace original string by encrypted one. */
    unenc = enc;
    unenc_written = enclen;
  }
  /* Base64-encode introduction points. */
  *ipos_base64 = tor_malloc_zero(unenc_written * 2);
  if (base64_encode(*ipos_base64, unenc_written * 2, unenc, unenc_written)
      < 0) {
    log_warn(LD_REND, "Could not encode introduction point string to "
                      "base64.");
    tor_free(unenc);
    tor_free(ipos_base64);
    return -1;
  }
  tor_free(unenc);
  return 0;
}

/** Attempt to parse the given <b>desc_str</b> and return true if this
 * succeeds, false otherwise. */
static int
rend_desc_v2_is_parsable(const char *desc_str)
{
  rend_service_descriptor_t *test_parsed;
  char test_desc_id[DIGEST_LEN];
  char *test_intro_content;
  size_t test_intro_size;
  size_t test_encoded_size;
  const char *test_next;
  int res = rend_parse_v2_service_descriptor(&test_parsed, test_desc_id,
                                         &test_intro_content,
                                         &test_intro_size,
                                         &test_encoded_size,
                                         &test_next, desc_str);
  tor_free(test_parsed);
  tor_free(test_intro_content);
  return (res >= 0);
}

/** Encode a set of new service descriptors for <b>desc</b> at time
 * <b>now</b> using <b>descriptor_cookie</b> (may be <b>NULL</b> if
 * introduction points shall not be encrypted) and <b>period</b> (e.g. 0
 * for the current period, 1 for the next period, etc.), write the
 * ASCII-encoded outputs to newly allocated strings and add them to the
 * existing <b>desc_strs</b>, and write the descriptor IDs to newly
 * allocated strings and add them to the existing <b>desc_ids</b>; return
 * the number of seconds that the descriptors will be found under those
 * <b>desc_ids</b> by clients, or -1 if the encoding was not successful. */
int
rend_encode_v2_descriptors(smartlist_t *desc_strs_out,
                           smartlist_t *desc_ids_out,
                           rend_service_descriptor_t *desc, time_t now,
                           const char *descriptor_cookie, uint8_t period)
{
  char service_id[DIGEST_LEN];
  char time_period[REND_TIME_PERIOD_BINARY];
  char *ipos_base64 = NULL;
  int k;
  uint32_t seconds_valid;
  if (!desc) {
    log_warn(LD_REND, "Could not encode v2 descriptor: No desc given.");
    return -1;
  }
  /* Obtain service_id from public key. */
  crypto_pk_get_digest(desc->pk, service_id);
  /* Calculate current time-period. */
  get_time_period_bytes(time_period, now, period, service_id);
  /* Determine how many seconds the descriptor will be valid. */
  seconds_valid = period * REND_TIME_PERIOD_V2_DESC_VALIDITY +
                  get_seconds_valid(now, service_id);
  /* Assemble, possibly encrypt, and encode introduction points. */
  if (rend_encode_v2_intro_points(&ipos_base64, desc, descriptor_cookie) < 0) {
    log_warn(LD_REND, "Encoding of introduction points did not succeed.");
    if (ipos_base64) tor_free(ipos_base64);
    return -1;
  }
  /* Encode REND_NUMBER_OF_NON_CONSECUTIVE_REPLICAS descriptors. */
  for (k = 0; k < REND_NUMBER_OF_NON_CONSECUTIVE_REPLICAS; k++) {
    char secret_id_part[DIGEST_LEN];
    char secret_id_part_base32[REND_SECRET_ID_PART_BASE32 + 1];
    char *desc_id;
    char desc_id_base32[REND_DESC_ID_V2_BASE32 + 1];
    char *permanent_key;
    size_t permanent_key_len;
    char published[ISO_TIME_LEN+1];
    int i;
    char protocol_versions_string[16]; /* max len: "0,1,2,3,4,5,6,7\0" */
    size_t protocol_versions_written;
    size_t desc_len;
    char *desc_str;
    int result = 0;
    size_t written = 0;
    char desc_digest[DIGEST_LEN];
    /* Calculate secret-id-part = h(time-period + cookie + replica). */
    get_secret_id_part_bytes(secret_id_part, time_period, descriptor_cookie,
                             k);
    base32_encode(secret_id_part_base32, REND_SECRET_ID_PART_BASE32 + 1,
                  secret_id_part, DIGEST_LEN);
    /* Calculate descriptor ID. */
    desc_id = tor_malloc_zero(DIGEST_LEN);
    rend_get_descriptor_id_bytes(desc_id, service_id, secret_id_part);
    smartlist_add(desc_ids_out, desc_id);
    base32_encode(desc_id_base32, REND_DESC_ID_V2_BASE32 + 1,
                  desc_id, DIGEST_LEN);
    /* PEM-encode the public key */
    if (crypto_pk_write_public_key_to_string(desc->pk, &permanent_key,
                                             &permanent_key_len) < 0) {
      log_warn(LD_BUG, "Could not write public key to string.");
      if (permanent_key) tor_free(permanent_key);
      goto err;
    }
    /* Encode timestamp. */
    format_iso_time(published, desc->timestamp);
    /* Write protocol-versions bitmask to comma-separated value string. */
    protocol_versions_written = 0;
    for (i = 0; i < 8; i++) {
      if (desc->protocols & 1 << i) {
        tor_snprintf(protocol_versions_string + protocol_versions_written,
                     16 - protocol_versions_written, "%d,", i);
        protocol_versions_written += 2;
      }
    }
    protocol_versions_string[protocol_versions_written - 1] = 0;
    /* Assemble complete descriptor. */
    desc_len = 2000 + desc->n_intro_points * 1000; /* far too long, but ok. */
    desc_str = tor_malloc_zero(desc_len);
    result = tor_snprintf(desc_str, desc_len,
             "rendezvous-service-descriptor %s\n"
             "version 2\n"
             "permanent-key\n%s"
             "secret-id-part %s\n"
             "publication-time %s\n"
             "protocol-versions %s\n"
             "introduction-points\n"
             "-----BEGIN MESSAGE-----\n%s"
             "-----END MESSAGE-----\n",
        desc_id_base32,
        permanent_key,
        secret_id_part_base32,
        published,
        protocol_versions_string,
        ipos_base64);
    tor_free(permanent_key);
    if (result < 0) {
      log_warn(LD_BUG, "Descriptor ran out of room.");
      if (desc_str) tor_free(desc_str);
      goto err;
    }
    written = result;
    /* Add signature. */
    strlcpy(desc_str + written, "signature\n", desc_len - written);
    written += strlen(desc_str + written);
    desc_str[written] = '\0';
    if (crypto_digest(desc_digest, desc_str, written) < 0) {
      log_warn(LD_BUG, "could not create digest.");
      tor_free(desc_str);
      goto err;
    }
    if (router_append_dirobj_signature(desc_str + written,
                                       desc_len - written,
                                       desc_digest, desc->pk) < 0) {
      log_warn(LD_BUG, "Couldn't sign desc.");
      tor_free(desc_str);
      goto err;
    }
    written += strlen(desc_str+written);
    if (written+2 > desc_len) {
        log_warn(LD_BUG, "Could not finish desc.");
        tor_free(desc_str);
        goto err;
    }
    desc_str[written++] = '\n';
    desc_str[written++] = 0;
    /* Check if we can parse our own descriptor. */
    if (!rend_desc_v2_is_parsable(desc_str)) {
      log_warn(LD_BUG, "Could not parse my own descriptor: %s", desc_str);
      tor_free(desc_str);
      goto err;
    }
    smartlist_add(desc_strs_out, desc_str);
  }

  log_info(LD_REND, "Successfully encoded a v2 descriptor and "
                      "confirmed that it is parsable.");
  goto done;

 err:
  SMARTLIST_FOREACH(desc_ids_out, void *, id, tor_free(id));
  smartlist_clear(desc_ids_out);
  SMARTLIST_FOREACH(desc_strs_out, void *, str, tor_free(str));
  smartlist_clear(desc_strs_out);
  seconds_valid = -1;

 done:
  tor_free(ipos_base64);
  return seconds_valid;
}

/** Encode a service descriptor for <b>desc</b>, and sign it with
 * <b>key</b>. Store the descriptor in *<b>str_out</b>, and set
 * *<b>len_out</b> to its length.
 */
int
rend_encode_service_descriptor(rend_service_descriptor_t *desc,
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
  asn1len = crypto_pk_asn1_encode(desc->pk, cp+2, end-(cp+2));
  set_uint16(cp, htons((uint16_t)asn1len));
  cp += 2+asn1len;
  set_uint32(cp, htonl((uint32_t)desc->timestamp));
  cp += 4;
  set_uint16(cp, htons((uint16_t)desc->n_intro_points));
  cp += 2;
  for (i=0; i < desc->n_intro_points; ++i) {
    char *ipoint = (char*)desc->intro_points[i];
    strlcpy(cp, ipoint, buflen-(cp-*str_out));
    cp += strlen(ipoint)+1;
  }
  note_crypto_pk_op(REND_SERVER);
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

  result = tor_malloc_zero(sizeof(rend_service_descriptor_t));
  cp = str;
  end = str+len;
  if (end-cp<2) goto truncated;
  result->version = 0;
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
  result->protocols = 1<<2; /* always use intro format 2 */
  if (end-cp < 2) goto truncated;
  result->n_intro_points = ntohs(get_uint16(cp));
  cp += 2;

  if (result->n_intro_points != 0) {
    result->intro_points =
      tor_malloc_zero(sizeof(char*)*result->n_intro_points);
    for (i=0;i<result->n_intro_points;++i) {
      if (end-cp < 2) goto truncated;
      eos = (const char *)memchr(cp,'\0',end-cp);
      if (!eos) goto truncated;
      result->intro_points[i] = tor_strdup(cp);
      cp = eos+1;
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
  note_crypto_pk_op(REND_CLIENT);
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

/** How old do we let hidden service descriptors get before discarding
 * them as too old? */
#define REND_CACHE_MAX_AGE (2*24*60*60)
/** How wrong do we assume our clock may be when checking whether hidden
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

/** If we have a cached rend_cache_entry_t for the service ID <b>query</b>
 * with <b>version</b>, set *<b>e</b> to that entry and return 1.
 * Else return 0.
 */
int
rend_cache_lookup_entry(const char *query, int version, rend_cache_entry_t **e)
{
  char key[REND_SERVICE_ID_LEN+2]; /* <version><query>\0 */
  tor_assert(rend_cache);
  tor_assert(!version);
  if (!rend_valid_service_id(query))
    return -1;
  tor_snprintf(key, sizeof(key), "%d%s", version, query);
  *e = strmap_get_lc(rend_cache, key);
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
 * it's novel. The published flag tells us if we store the descriptor
 * in our role as directory (1) or if we cache it as client (0).
 */
int
rend_cache_store(const char *desc, size_t desc_len, int published)
{
  rend_cache_entry_t *e;
  rend_service_descriptor_t *parsed;
  char query[REND_SERVICE_ID_LEN+1];
  char key[REND_SERVICE_ID_LEN+2]; /* 0<query>\0 */
  time_t now;
  or_options_t *options = get_options();
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
  tor_snprintf(key, sizeof(key), "0%s", query);
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
  /* report novel publication to statistics */
  if (published && options->HSAuthorityRecordStats) {
    hs_usage_note_publish_total(query, now);
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
    /* report novel publication to statistics */
    if (published && options->HSAuthorityRecordStats) {
      hs_usage_note_publish_novel(query, now);
    }
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
  or_circuit_t *or_circ = NULL;
  origin_circuit_t *origin_circ = NULL;
  int r = -2;
  if (CIRCUIT_IS_ORIGIN(circ))
    origin_circ = TO_ORIGIN_CIRCUIT(circ);
  else
    or_circ = TO_OR_CIRCUIT(circ);

  switch (command) {
    case RELAY_COMMAND_ESTABLISH_INTRO:
      if (or_circ)
        r = rend_mid_establish_intro(or_circ,payload,length);
      break;
    case RELAY_COMMAND_ESTABLISH_RENDEZVOUS:
      if (or_circ)
        r = rend_mid_establish_rendezvous(or_circ,payload,length);
      break;
    case RELAY_COMMAND_INTRODUCE1:
      if (or_circ)
        r = rend_mid_introduce(or_circ,payload,length);
      break;
    case RELAY_COMMAND_INTRODUCE2:
      if (origin_circ)
        r = rend_service_introduce(origin_circ,payload,length);
      break;
    case RELAY_COMMAND_INTRODUCE_ACK:
      if (origin_circ)
        r = rend_client_introduction_acked(origin_circ,payload,length);
      break;
    case RELAY_COMMAND_RENDEZVOUS1:
      if (or_circ)
        r = rend_mid_rendezvous(or_circ,payload,length);
      break;
    case RELAY_COMMAND_RENDEZVOUS2:
      if (origin_circ)
        r = rend_client_receive_rendezvous(origin_circ,payload,length);
      break;
    case RELAY_COMMAND_INTRO_ESTABLISHED:
      if (origin_circ)
        r = rend_service_intro_established(origin_circ,payload,length);
      break;
    case RELAY_COMMAND_RENDEZVOUS_ESTABLISHED:
      if (origin_circ)
        r = rend_client_rendezvous_acked(origin_circ,payload,length);
      break;
    default:
      tor_fragile_assert();
  }

  if (r == -2)
    log_info(LD_PROTOCOL, "Dropping cell (type %d) for wrong circuit type.",
             command);
}

/** Return the number of entries in our rendezvous descriptor cache. */
int
rend_cache_size(void)
{
  return strmap_size(rend_cache);
}

