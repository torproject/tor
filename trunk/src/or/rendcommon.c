/* Copyright 2004 Roger Dingledine */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

void rend_service_descriptor_free(rend_service_descriptor_t *desc)
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
  tor_free(desc);
}

int
rend_encode_service_descriptor(rend_service_descriptor_t *desc,
			       crypto_pk_env_t *key,
			       char **str_out, int *len_out)
{
  char *buf, *cp, *ipoint;
  int i, keylen, asn1len;
  char digest[CRYPTO_SHA1_DIGEST_LEN];
  keylen = crypto_pk_keysize(desc->pk);
  buf = tor_malloc(keylen*2); /* XXXX */
  asn1len = crypto_pk_asn1_encode(desc->pk, buf, keylen*2);
  if (asn1len<0) {
    tor_free(buf);
    return -1;
  }
  *len_out = 2 + asn1len + 4 + 2 + keylen;
  for (i = 0; i < desc->n_intro_points; ++i) {
    *len_out += strlen(desc->intro_points[i]) + 1;
  }
  cp = *str_out = tor_malloc(*len_out);
  set_uint16(cp, (uint16_t)asn1len);
  cp += 2;
  memcpy(cp, buf, asn1len);
  tor_free(buf);
  cp += asn1len;
  set_uint32(cp, (uint32_t)desc->timestamp);
  cp += 4;
  set_uint16(cp, (uint16_t)desc->n_intro_points);
  cp += 2;
  for (i=0; i < desc->n_intro_points; ++i) {
    ipoint = (char*)desc->intro_points[i];
    strcpy(cp, ipoint);
    cp += strlen(ipoint)+1;
  }
  i = crypto_SHA_digest(*str_out, cp-*str_out, digest);
  if (i<0) {
    tor_free(*str_out);
    return -1;
  }
  i = crypto_pk_private_sign(key, digest, CRYPTO_SHA1_DIGEST_LEN, cp);
  if (i<0) {
    tor_free(*str_out);
    return -1;
  }
  cp += i;
  assert(*len_out == (cp-*str_out));
  return 0;
}


rend_service_descriptor_t *rend_parse_service_descriptor(
				       const char *str, int len)
{
  rend_service_descriptor_t *result = NULL;
  int keylen, asn1len, i;
  const char *end, *cp, *eos;
  char *signed_data=NULL;
  char digest_expected[CRYPTO_SHA1_DIGEST_LEN];
  result = tor_malloc_zero(sizeof(rend_service_descriptor_t));
  cp = str;
  end = str+len;
  if (end-cp < 2) goto truncated;
  asn1len = get_uint16(cp);
  cp += 2;
  if (end-cp < asn1len) goto truncated;
  result->pk = crypto_pk_asn1_decode(cp, asn1len);
  if (!result->pk) goto truncated;
  cp += asn1len;
  if (end-cp < 4) goto truncated;
  result->timestamp = (time_t) get_uint32(cp);
  cp += 4;
  if (end-cp < 2) goto truncated;
  result->n_intro_points = get_uint16(cp);
  result->intro_points = tor_malloc_zero(sizeof(char*)*result->n_intro_points);
  cp += 2;
  for (i=0;i<result->n_intro_points;++i) {
    if (end-cp < 2) goto truncated;
    eos = (const char *)memchr(cp,'\0',end-cp);
    if (!eos) goto truncated;
    result->intro_points[i] = tor_strdup(cp);
    cp = eos+1;
  }
  keylen = crypto_pk_keysize(result->pk);
  if (end-cp != keylen) goto truncated;
  if (crypto_SHA_digest(str, cp-str, digest_expected)<0) {
    log_fn(LOG_WARN, "Error computing SHA1 digest.");
    goto error;
  }
  signed_data = tor_malloc(keylen+1);
  i = crypto_pk_public_checksig(result->pk, (char*)cp, end-cp, signed_data);
  if (i<0) {
    log_fn(LOG_WARN, "Invalid signature on service descriptor");
    goto error;
  }
  if (i != CRYPTO_SHA1_DIGEST_LEN ||
      memcmp(signed_data, digest_expected, CRYPTO_SHA1_DIGEST_LEN)) {
    log_fn(LOG_WARN, "Mismatched signature on service descriptor");
    goto error;
  }
  tor_free(signed_data);

  return result;
 truncated:
  log_fn(LOG_WARN, "Truncated service descriptor");
 error:
  tor_free(signed_data);
  rend_service_descriptor_free(result);
  return NULL;
}

