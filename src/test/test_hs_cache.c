/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_cache.c
 * \brief Test hidden service caches.
 */

#define HS_CACHE_PRIVATE

#include "ed25519_cert.h"
#include "hs_cache.h"
#include "rendcache.h"
#include "test.h"

/* Build an intro point using a blinded key and an address. */
static hs_desc_intro_point_t *
helper_build_intro_point(const ed25519_keypair_t *blinded_kp,
                         const char *addr)
{
  int ret;
  ed25519_keypair_t auth_kp;
  hs_desc_intro_point_t *intro_point = NULL;
  hs_desc_intro_point_t *ip = tor_malloc_zero(sizeof(*ip));
  ip->link_specifiers = smartlist_new();

  {
    hs_desc_link_specifier_t *ls = tor_malloc_zero(sizeof(*ls));
    ls->u.ap.port = 9001;
    int family = tor_addr_parse(&ls->u.ap.addr, addr);
    switch (family) {
    case AF_INET:
      ls->type = LS_IPV4;
      break;
    case AF_INET6:
      ls->type = LS_IPV6;
      break;
    default:
      /* Stop the test, not suppose to have an error. */
      tt_int_op(family, OP_EQ, AF_INET);
    }
    smartlist_add(ip->link_specifiers, ls);
  }

  ret = ed25519_keypair_generate(&auth_kp, 0);
  tt_int_op(ret, ==, 0);
  ip->auth_key_cert = tor_cert_create(blinded_kp, CERT_TYPE_HS_IP_AUTH,
                                      &auth_kp.pubkey, time(NULL),
                                      HS_DESC_CERT_LIFETIME,
                                      CERT_FLAG_INCLUDE_SIGNING_KEY);
  tt_assert(ip->auth_key_cert);

  ret = curve25519_keypair_generate(&ip->enc_key.curve25519, 0);
  tt_int_op(ret, ==, 0);
  ip->enc_key_type = HS_DESC_KEY_TYPE_CURVE25519;
  intro_point = ip;
done:
  return intro_point;
}

/* Return a valid hs_descriptor_t object. */
static hs_descriptor_t *
helper_build_hs_desc(uint64_t revision_counter, uint32_t lifetime,
                     ed25519_keypair_t *blinded_kp)
{
  int ret;
  hs_descriptor_t *descp = NULL, *desc = tor_malloc_zero(sizeof(*desc));

  desc->plaintext_data.version = HS_DESC_SUPPORTED_FORMAT_VERSION_MAX;
  ret = ed25519_keypair_generate(&desc->plaintext_data.signing_kp, 0);
  tt_int_op(ret, ==, 0);
  if (blinded_kp) {
    memcpy(&desc->plaintext_data.blinded_kp, blinded_kp,
           sizeof(ed25519_keypair_t));
  } else {
    ret = ed25519_keypair_generate(&desc->plaintext_data.blinded_kp, 0);
    tt_int_op(ret, ==, 0);
  }

  desc->plaintext_data.signing_key_cert =
    tor_cert_create(&desc->plaintext_data.blinded_kp,
                    CERT_TYPE_HS_DESC_SIGN,
                    &desc->plaintext_data.signing_kp.pubkey, time(NULL),
                    3600, CERT_FLAG_INCLUDE_SIGNING_KEY);
  tt_assert(desc->plaintext_data.signing_key_cert);
  desc->plaintext_data.revision_counter = revision_counter;
  desc->plaintext_data.lifetime_sec = lifetime;

  /* Setup encrypted data section. */
  desc->encrypted_data.create2_ntor = 1;
  desc->encrypted_data.auth_types = smartlist_new();
  smartlist_add(desc->encrypted_data.auth_types, strdup("ed25519"));
  desc->encrypted_data.intro_points = smartlist_new();
  /* Add an intro point. */
  smartlist_add(desc->encrypted_data.intro_points,
                helper_build_intro_point(&desc->plaintext_data.blinded_kp,
                                         "1.2.3.4"));

  descp = desc;
done:
  return descp;
}

/* Static variable used to encoded the HSDir query. */
static char query_b64[256];

/* Build an HSDir query using a ed25519 keypair. */
static const char *
helper_get_hsdir_query(const hs_descriptor_t *desc)
{
  ed25519_public_to_base64(query_b64,
                           &desc->plaintext_data.blinded_kp.pubkey);
  return query_b64;
}

static void
init_test(void)
{
  /* Always needed. Initialize the subsystem. */
  hs_cache_init();
  /* We need the v2 cache since our OOM and cache cleanup does poke at it. */
  rend_cache_init();
}

static void
test_directory(void *arg)
{
  int ret;
  size_t oom_size;
  char *desc_out, *desc1_str;
  hs_descriptor_t *desc1;

  (void) arg;

  init_test();
  /* Generate a valid descriptor with normal values. */
  desc1 = helper_build_hs_desc(42, 3 * 60 * 60, NULL);
  tt_assert(desc1);
  ret = hs_desc_encode_descriptor(desc1, &desc1_str);
  tt_int_op(ret, OP_EQ, 0);

  /* Very first basic test, should be able to be stored, survive a
   * clean, found with a lookup and then cleaned by our OOM. */
  {
    ret = hs_cache_store_as_dir(desc1_str);
    tt_int_op(ret, OP_EQ, 0);
    /* Re-add, it should fail since we already have it. */
    ret = hs_cache_store_as_dir(desc1_str);
    tt_int_op(ret, OP_EQ, -1);
    /* Try to clean now which should be fine, there is at worst few seconds
     * between the store and this call. */
    hs_cache_clean_as_dir(time(NULL));
    /* We should find it in our cache. */
    ret = hs_cache_lookup_as_dir(3, helper_get_hsdir_query(desc1), &desc_out);
    tt_int_op(ret, OP_EQ, 1);
    tt_str_op(desc_out, OP_EQ, desc1_str);
    tor_free(desc_out);
    /* Tell our OOM to run and to at least remove a byte which will result in
     * removing the descriptor from our cache. */
    oom_size = hs_cache_handle_oom(time(NULL), 1);
    tt_int_op(oom_size, >=, 1);
    ret = hs_cache_lookup_as_dir(3, helper_get_hsdir_query(desc1), NULL);
    tt_int_op(ret, OP_EQ, 0);
  }

  /* Store two descriptors and remove the expiring one only. */
  {
    hs_descriptor_t *desc_zero_lifetime = helper_build_hs_desc(1, 0, NULL);
    tt_assert(desc_zero_lifetime);
    char *desc_zero_lifetime_str;
    ret = hs_desc_encode_descriptor(desc_zero_lifetime,
                                    &desc_zero_lifetime_str);
    tt_int_op(ret, OP_EQ, 0);

    ret = hs_cache_store_as_dir(desc1_str);
    tt_int_op(ret, OP_EQ, 0);
    ret = hs_cache_store_as_dir(desc_zero_lifetime_str);
    tt_int_op(ret, OP_EQ, 0);
    /* This one should clear out our zero lifetime desc. */
    hs_cache_clean_as_dir(time(NULL));
    /* We should find desc1 in our cache. */
    ret = hs_cache_lookup_as_dir(3, helper_get_hsdir_query(desc1), &desc_out);
    tt_int_op(ret, OP_EQ, 1);
    tt_str_op(desc_out, OP_EQ, desc1_str);
    tor_free(desc_out);
    /* We should NOT find our zero lifetime desc in our cache. */
    ret = hs_cache_lookup_as_dir(3,
                                 helper_get_hsdir_query(desc_zero_lifetime),
                                 NULL);
    tt_int_op(ret, OP_EQ, 0);
    /* Cleanup our entire cache. */
    oom_size = hs_cache_handle_oom(time(NULL), 1);
    tt_int_op(oom_size, >=, 1);
  }

  /* Throw junk at it. */
  {
    ret = hs_cache_store_as_dir("blah");
    tt_int_op(ret, OP_EQ, -1);
    /* Poor attempt at tricking the decoding. */
    ret = hs_cache_store_as_dir("hs-descriptor 3\nJUNK");
    tt_int_op(ret, OP_EQ, -1);
    /* Undecodable base64 query. */
    ret = hs_cache_lookup_as_dir(3, "blah", NULL);
    tt_int_op(ret, OP_EQ, -1);
    /* Decodable base64 query but wrong ed25519 size. */
    ret = hs_cache_lookup_as_dir(3, "dW5pY29ybg==", NULL);
    tt_int_op(ret, OP_EQ, -1);
  }

  /* Test descriptor replacement with revision counter. */
  {
    char *new_desc_str;

    /* Add a descriptor. */
    ret = hs_cache_store_as_dir(desc1_str);
    tt_int_op(ret, OP_EQ, 0);
    ret = hs_cache_lookup_as_dir(3, helper_get_hsdir_query(desc1), &desc_out);
    tt_int_op(ret, OP_EQ, 1);
    tor_free(desc_out);
    /* Bump revision counter. */
    desc1->plaintext_data.revision_counter++;
    ret = hs_desc_encode_descriptor(desc1, &new_desc_str);
    tt_int_op(ret, OP_EQ, 0);
    ret = hs_cache_store_as_dir(new_desc_str);
    tt_int_op(ret, OP_EQ, 0);
    /* Look it up, it should have been replaced. */
    ret = hs_cache_lookup_as_dir(3, helper_get_hsdir_query(desc1), &desc_out);
    tt_int_op(ret, OP_EQ, 1);
    tt_str_op(desc_out, OP_EQ, new_desc_str);
    tor_free(desc_out);
    tor_free(new_desc_str);
  }

 done:
  ;
}

static void
test_clean_as_dir(void *arg)
{
  size_t ret;
  char *desc1_str = NULL;
  time_t now = time(NULL);
  hs_descriptor_t *desc1 = NULL;

  (void) arg;

  init_test();

  /* Generate a valid descriptor with values. */
  desc1 = helper_build_hs_desc(42, 3 * 60 * 60, NULL);
  tt_assert(desc1);
  ret = hs_desc_encode_descriptor(desc1, &desc1_str);
  tt_int_op(ret, OP_EQ, 0);
	ret = hs_cache_store_as_dir(desc1_str);
	tt_int_op(ret, OP_EQ, 0);

  /* With the lifetime being 3 hours, a cleanup shouldn't remove it. */
  ret = cache_clean_v3_as_dir(now, 0);
  tt_int_op(ret, ==, 0);
  /* Should be present after clean up. */
  ret = hs_cache_lookup_as_dir(3, helper_get_hsdir_query(desc1), NULL);
  tt_int_op(ret, OP_EQ, 1);
  /* Set a cutoff 100 seconds in the past. It should not remove the entry
   * since the entry is still recent enough. */
  ret = cache_clean_v3_as_dir(now, now - 100);
  tt_int_op(ret, ==, 0);
  /* Should be present after clean up. */
  ret = hs_cache_lookup_as_dir(3, helper_get_hsdir_query(desc1), NULL);
  tt_int_op(ret, OP_EQ, 1);
  /* Set a cutoff of 100 seconds in the future. It should remove the entry
   * that we've just added since it's not too old for the cutoff. */
  ret = cache_clean_v3_as_dir(now, now + 100);
  tt_int_op(ret, >, 0);
  /* Shouldn't be present after clean up. */
  ret = hs_cache_lookup_as_dir(3, helper_get_hsdir_query(desc1), NULL);
  tt_int_op(ret, OP_EQ, 0);

 done:
  hs_descriptor_free(desc1);
  tor_free(desc1_str);
}

struct testcase_t hs_cache[] = {
  /* Encoding tests. */
  { "directory", test_directory, TT_FORK,
    NULL, NULL },
  { "clean_as_dir", test_clean_as_dir, TT_FORK,
    NULL, NULL },

  END_OF_TESTCASES
};
