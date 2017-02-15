/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_cache.c
 * \brief Test hidden service caches.
 */

#define CONNECTION_PRIVATE
#define HS_CACHE_PRIVATE

#include "ed25519_cert.h"
#include "hs_cache.h"
#include "rendcache.h"
#include "directory.h"
#include "connection.h"

#include "test_helpers.h"
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
  ip->auth_key_cert = tor_cert_create(blinded_kp, CERT_TYPE_AUTH_HS_IP_KEY,
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
                     ed25519_public_key_t *signing_pubkey)
{
  int ret;
  ed25519_keypair_t blinded_kp;
  hs_descriptor_t *descp = NULL, *desc = tor_malloc_zero(sizeof(*desc));

  desc->plaintext_data.version = HS_DESC_SUPPORTED_FORMAT_VERSION_MAX;

  /* Copy only the public key into the descriptor. */
  memcpy(&desc->plaintext_data.signing_pubkey, signing_pubkey,
         sizeof(ed25519_public_key_t));

  ret = ed25519_keypair_generate(&blinded_kp, 0);
  tt_int_op(ret, ==, 0);
  /* Copy only the public key into the descriptor. */
  memcpy(&desc->plaintext_data.blinded_pubkey, &blinded_kp.pubkey,
         sizeof(ed25519_public_key_t));

  desc->plaintext_data.signing_key_cert =
    tor_cert_create(&blinded_kp, CERT_TYPE_SIGNING_HS_DESC, signing_pubkey,
                    time(NULL), 3600, CERT_FLAG_INCLUDE_SIGNING_KEY);
  tt_assert(desc->plaintext_data.signing_key_cert);
  desc->plaintext_data.revision_counter = revision_counter;
  desc->plaintext_data.lifetime_sec = lifetime;

  /* Setup encrypted data section. */
  desc->encrypted_data.create2_ntor = 1;
  desc->encrypted_data.auth_types = smartlist_new();
  smartlist_add(desc->encrypted_data.auth_types, tor_strdup("ed25519"));
  desc->encrypted_data.intro_points = smartlist_new();
  /* Add an intro point. */
  smartlist_add(desc->encrypted_data.intro_points,
                helper_build_intro_point(&blinded_kp, "1.2.3.4"));

  descp = desc;
 done:
  return descp;
}

/* Static variable used to encoded the HSDir query. */
static char query_b64[256];

/* Build an HSDir query using a ed25519 public key. */
static const char *
helper_get_hsdir_query(const hs_descriptor_t *desc)
{
  ed25519_public_to_base64(query_b64, &desc->plaintext_data.blinded_pubkey);
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
  char *desc1_str = NULL;
  const char *desc_out;
  ed25519_keypair_t signing_kp1;
  hs_descriptor_t *desc1 = NULL;

  (void) arg;

  init_test();
  /* Generate a valid descriptor with normal values. */
  ret = ed25519_keypair_generate(&signing_kp1, 0);
  tt_int_op(ret, ==, 0);
  desc1 = helper_build_hs_desc(42, 3 * 60 * 60, &signing_kp1.pubkey);
  tt_assert(desc1);
  ret = hs_desc_encode_descriptor(desc1, &signing_kp1, &desc1_str);
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
    /* Tell our OOM to run and to at least remove a byte which will result in
     * removing the descriptor from our cache. */
    oom_size = hs_cache_handle_oom(time(NULL), 1);
    tt_int_op(oom_size, >=, 1);
    ret = hs_cache_lookup_as_dir(3, helper_get_hsdir_query(desc1), NULL);
    tt_int_op(ret, OP_EQ, 0);
  }

  /* Store two descriptors and remove the expiring one only. */
  {
    ed25519_keypair_t signing_kp_zero;
    ret = ed25519_keypair_generate(&signing_kp_zero, 0);
    tt_int_op(ret, ==, 0);
    hs_descriptor_t *desc_zero_lifetime;
    desc_zero_lifetime = helper_build_hs_desc(1, 0, &signing_kp_zero.pubkey);
    tt_assert(desc_zero_lifetime);
    char *desc_zero_lifetime_str;
    ret = hs_desc_encode_descriptor(desc_zero_lifetime, &signing_kp_zero,
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
    /* We should NOT find our zero lifetime desc in our cache. */
    ret = hs_cache_lookup_as_dir(3,
                                 helper_get_hsdir_query(desc_zero_lifetime),
                                 NULL);
    tt_int_op(ret, OP_EQ, 0);
    /* Cleanup our entire cache. */
    oom_size = hs_cache_handle_oom(time(NULL), 1);
    tt_int_op(oom_size, >=, 1);
    hs_descriptor_free(desc_zero_lifetime);
    tor_free(desc_zero_lifetime_str);
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
    /* Bump revision counter. */
    desc1->plaintext_data.revision_counter++;
    ret = hs_desc_encode_descriptor(desc1, &signing_kp1, &new_desc_str);
    tt_int_op(ret, OP_EQ, 0);
    ret = hs_cache_store_as_dir(new_desc_str);
    tt_int_op(ret, OP_EQ, 0);
    /* Look it up, it should have been replaced. */
    ret = hs_cache_lookup_as_dir(3, helper_get_hsdir_query(desc1), &desc_out);
    tt_int_op(ret, OP_EQ, 1);
    tt_str_op(desc_out, OP_EQ, new_desc_str);
    tor_free(new_desc_str);
  }

 done:
  hs_descriptor_free(desc1);
  tor_free(desc1_str);
}

static void
test_clean_as_dir(void *arg)
{
  size_t ret;
  char *desc1_str = NULL;
  time_t now = time(NULL);
  hs_descriptor_t *desc1 = NULL;
  ed25519_keypair_t signing_kp1;

  (void) arg;

  init_test();

  /* Generate a valid descriptor with values. */
  ret = ed25519_keypair_generate(&signing_kp1, 0);
  tt_int_op(ret, ==, 0);
  desc1 = helper_build_hs_desc(42, 3 * 60 * 60, &signing_kp1.pubkey);
  tt_assert(desc1);
  ret = hs_desc_encode_descriptor(desc1, &signing_kp1, &desc1_str);
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

/* Test helper: Fetch an HS descriptor from an HSDir (for the hidden service
   with <b>blinded_key</b>. Return the received descriptor string. */
static char *
helper_fetch_desc_from_hsdir(const ed25519_public_key_t *blinded_key)
{
  int retval;

  char *received_desc = NULL;
  char *hsdir_query_str = NULL;

  /* The dir conn we are going to simulate */
  dir_connection_t *conn = NULL;

  /* First extract the blinded public key that we are going to use in our
     query, and then build the actual query string. */
  {
    char hsdir_cache_key[ED25519_BASE64_LEN+1];

    retval = ed25519_public_to_base64(hsdir_cache_key,
                                      blinded_key);
    tt_int_op(retval, ==, 0);
    tor_asprintf(&hsdir_query_str, GET("/tor/hs/3/%s"), hsdir_cache_key);
  }

  /* Simulate an HTTP GET request to the HSDir */
  conn = dir_connection_new(AF_INET);
  tor_addr_from_ipv4h(&conn->base_.addr, 0x7f000001);
  TO_CONN(conn)->linked = 1;/* Pretend the conn is encrypted :) */
  retval = directory_handle_command_get(conn, hsdir_query_str,
                                        NULL, 0);
  tt_int_op(retval, OP_EQ, 0);

  /* Read the descriptor that the HSDir just served us */
  {
    char *headers = NULL;
    size_t body_used = 0;

    fetch_from_buf_http(TO_CONN(conn)->outbuf, &headers, MAX_HEADERS_SIZE,
                        &received_desc, &body_used, 10000, 0);
    tor_free(headers);
  }

 done:
  tor_free(hsdir_query_str);
  if (conn)
    connection_free_(TO_CONN(conn));

  return received_desc;
}

/* Publish a descriptor to the HSDir, then fetch it. Check that the received
   descriptor matches the published one. */
static void
test_upload_and_download_hs_desc(void *arg)
{
  int retval;
  hs_descriptor_t *published_desc = NULL;

  char *published_desc_str = NULL;
  char *received_desc_str = NULL;

  (void) arg;

  /* Initialize HSDir cache subsystem */
  init_test();

  /* Test a descriptor not found in the directory cache. */
  {
    ed25519_public_key_t blinded_key;
    memset(&blinded_key.pubkey, 'A', sizeof(blinded_key.pubkey));
    received_desc_str = helper_fetch_desc_from_hsdir(&blinded_key);
    tt_int_op(strlen(received_desc_str), OP_EQ, 0);
    tor_free(received_desc_str);
  }

  /* Generate a valid descriptor with normal values. */
  {
    ed25519_keypair_t signing_kp;
    retval = ed25519_keypair_generate(&signing_kp, 0);
    tt_int_op(retval, ==, 0);
    published_desc = helper_build_hs_desc(42, 3 * 60 * 60, &signing_kp.pubkey);
    tt_assert(published_desc);
    retval = hs_desc_encode_descriptor(published_desc, &signing_kp,
                                       &published_desc_str);
    tt_int_op(retval, OP_EQ, 0);
  }

  /* Publish descriptor to the HSDir */
  {
    retval = handle_post_hs_descriptor("/tor/hs/3/publish",published_desc_str);
    tt_int_op(retval, ==, 200);
  }

  /* Simulate a fetch of the previously published descriptor */
  {
    const ed25519_public_key_t *blinded_key;
    blinded_key = &published_desc->plaintext_data.blinded_pubkey;
    received_desc_str = helper_fetch_desc_from_hsdir(blinded_key);
  }

  /* Verify we received the exact same descriptor we published earlier */
  tt_str_op(received_desc_str, OP_EQ, published_desc_str);
  tor_free(received_desc_str);

  /* With a valid descriptor in the directory cache, try again an invalid. */
  {
    ed25519_public_key_t blinded_key;
    memset(&blinded_key.pubkey, 'A', sizeof(blinded_key.pubkey));
    received_desc_str = helper_fetch_desc_from_hsdir(&blinded_key);
    tt_int_op(strlen(received_desc_str), OP_EQ, 0);
  }

 done:
  tor_free(received_desc_str);
  tor_free(published_desc_str);
  hs_descriptor_free(published_desc);
}

/* Test that HSDirs reject outdated descriptors based on their revision
 * counter. Also test that HSDirs correctly replace old descriptors with newer
 * descriptors. */
static void
test_hsdir_revision_counter_check(void *arg)
{
  int retval;

  ed25519_keypair_t signing_kp;

  hs_descriptor_t *published_desc = NULL;
  char *published_desc_str = NULL;

  char *received_desc_str = NULL;
  hs_descriptor_t *received_desc = NULL;

  (void) arg;

  /* Initialize HSDir cache subsystem */
  init_test();

  /* Generate a valid descriptor with normal values. */
  {
    retval = ed25519_keypair_generate(&signing_kp, 0);
    tt_int_op(retval, ==, 0);
    published_desc = helper_build_hs_desc(1312, 3 * 60 * 60,
                                          &signing_kp.pubkey);
    tt_assert(published_desc);
    retval = hs_desc_encode_descriptor(published_desc, &signing_kp,
                                       &published_desc_str);
    tt_int_op(retval, OP_EQ, 0);
  }

  /* Publish descriptor to the HSDir */
  {
    retval = handle_post_hs_descriptor("/tor/hs/3/publish",published_desc_str);
    tt_int_op(retval, ==, 200);
  }

  /* Try publishing again with the same revision counter: Should fail. */
  {
    retval = handle_post_hs_descriptor("/tor/hs/3/publish",published_desc_str);
    tt_int_op(retval, ==, 400);
  }

  /* Fetch the published descriptor and validate the revision counter. */
  {
    const ed25519_public_key_t *blinded_key;

    blinded_key = &published_desc->plaintext_data.blinded_pubkey;
    received_desc_str = helper_fetch_desc_from_hsdir(blinded_key);

    retval = hs_desc_decode_descriptor(received_desc_str,NULL, &received_desc);
    tt_int_op(retval, ==, 0);
    tt_assert(received_desc);

    /* Check that the revision counter is correct */
    tt_u64_op(received_desc->plaintext_data.revision_counter, ==, 1312);

    hs_descriptor_free(received_desc);
    received_desc = NULL;
    tor_free(received_desc_str);
  }

  /* Increment the revision counter and try again. Should work. */
  {
    published_desc->plaintext_data.revision_counter = 1313;
    tor_free(published_desc_str);
    retval = hs_desc_encode_descriptor(published_desc, &signing_kp,
                                       &published_desc_str);
    tt_int_op(retval, OP_EQ, 0);

    retval = handle_post_hs_descriptor("/tor/hs/3/publish",published_desc_str);
    tt_int_op(retval, ==, 200);
  }

  /* Again, fetch the published descriptor and perform the revision counter
     validation. The revision counter must have changed. */
  {
    const ed25519_public_key_t *blinded_key;

    blinded_key = &published_desc->plaintext_data.blinded_pubkey;
    received_desc_str = helper_fetch_desc_from_hsdir(blinded_key);

    retval = hs_desc_decode_descriptor(received_desc_str,NULL, &received_desc);
    tt_int_op(retval, ==, 0);
    tt_assert(received_desc);

    /* Check that the revision counter is the latest */
    tt_u64_op(received_desc->plaintext_data.revision_counter, ==, 1313);
  }

 done:
  hs_descriptor_free(published_desc);
  hs_descriptor_free(received_desc);
  tor_free(received_desc_str);
  tor_free(published_desc_str);
}

struct testcase_t hs_cache[] = {
  /* Encoding tests. */
  { "directory", test_directory, TT_FORK,
    NULL, NULL },
  { "clean_as_dir", test_clean_as_dir, TT_FORK,
    NULL, NULL },
  { "hsdir_revision_counter_check", test_hsdir_revision_counter_check, TT_FORK,
    NULL, NULL },
  { "upload_and_download_hs_desc", test_upload_and_download_hs_desc, TT_FORK,
    NULL, NULL },

  END_OF_TESTCASES
};

