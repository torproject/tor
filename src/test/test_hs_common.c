/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_hs_common.c
 * \brief Test hidden service common functionalities.
 */

#define HS_COMMON_PRIVATE
#define HS_SERVICE_PRIVATE

#include "test.h"
#include "test_helpers.h"
#include "log_test_helpers.h"
#include "hs_test_helpers.h"

#include "connection_edge.h"
#include "hs_common.h"
#include "hs_service.h"
#include "config.h"
#include "networkstatus.h"
#include "directory.h"
#include "nodelist.h"
#include "routerlist.h"
#include "statefile.h"

/** Test the validation of HS v3 addresses */
static void
test_validate_address(void *arg)
{
  int ret;

  (void) arg;

  /* Address too short and too long. */
  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_address_is_valid("blah");
  tt_int_op(ret, OP_EQ, 0);
  expect_log_msg_containing("has an invalid length");
  teardown_capture_of_logs();

  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_address_is_valid(
           "p3xnclpu4mu22dwaurjtsybyqk4xfjmcfz6z62yl24uwmhjatiwnlnadb");
  tt_int_op(ret, OP_EQ, 0);
  expect_log_msg_containing("has an invalid length");
  teardown_capture_of_logs();

  /* Invalid checksum (taken from prop224) */
  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_address_is_valid(
           "l5satjgud6gucryazcyvyvhuxhr74u6ygigiuyixe3a6ysis67ororad");
  tt_int_op(ret, OP_EQ, 0);
  expect_log_msg_containing("invalid checksum");
  teardown_capture_of_logs();

  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_address_is_valid(
           "btojiu7nu5y5iwut64eufevogqdw4wmqzugnoluw232r4t3ecsfv37ad");
  tt_int_op(ret, OP_EQ, 0);
  expect_log_msg_containing("invalid checksum");
  teardown_capture_of_logs();

  /* Non base32 decodable string. */
  setup_full_capture_of_logs(LOG_WARN);
  ret = hs_address_is_valid(
           "????????????????????????????????????????????????????????");
  tt_int_op(ret, OP_EQ, 0);
  expect_log_msg_containing("can't be decoded");
  teardown_capture_of_logs();

  /* Valid address. */
  ret = hs_address_is_valid(
           "p3xnclpu4mu22dwaurjtsybyqk4xfjmcfz6z62yl24uwmhjatiwnlnad");
  tt_int_op(ret, OP_EQ, 1);

 done:
  ;
}

static int
mock_write_str_to_file(const char *path, const char *str, int bin)
{
  (void)bin;
  tt_str_op(path, OP_EQ, "/double/five"PATH_SEPARATOR"squared");
  tt_str_op(str, OP_EQ,
           "ijbeeqscijbeeqscijbeeqscijbeeqscijbeeqscijbeeqscijbezhid.onion\n");

 done:
  return 0;
}

/** Test building HS v3 onion addresses */
static void
test_build_address(void *arg)
{
  int ret;
  char onion_addr[HS_SERVICE_ADDR_LEN_BASE32 + 1];
  ed25519_public_key_t pubkey;
  hs_service_t *service = NULL;

  (void) arg;

  MOCK(write_str_to_file, mock_write_str_to_file);

  /* The following has been created with hs_build_address.py script that
   * follows proposal 224 specification to build an onion address. */
  static const char *test_addr =
    "ijbeeqscijbeeqscijbeeqscijbeeqscijbeeqscijbeeqscijbezhid";

  /* Let's try to build the same onion address that the script can do. Key is
   * a long set of very random \x42 :). */
  memset(&pubkey, '\x42', sizeof(pubkey));
  hs_build_address(&pubkey, HS_VERSION_THREE, onion_addr);
  tt_str_op(test_addr, OP_EQ, onion_addr);
  /* Validate that address. */
  ret = hs_address_is_valid(onion_addr);
  tt_int_op(ret, OP_EQ, 1);

  service = tor_malloc_zero(sizeof(hs_service_t));
  memcpy(service->onion_address, onion_addr, sizeof(service->onion_address));
  tor_asprintf(&service->config.directory_path, "/double/five");
  ret = write_address_to_file(service, "squared");
  tt_int_op(ret, OP_EQ, 0);

 done:
  hs_service_free(service);
}

/** Test that our HS time period calculation functions work properly */
static void
test_time_period(void *arg)
{
  (void) arg;
  uint64_t tn;
  int retval;
  time_t fake_time, correct_time, start_time;

  /* Let's do the example in prop224 section [TIME-PERIODS] */
  retval = parse_rfc1123_time("Wed, 13 Apr 2016 11:00:00 UTC",
                              &fake_time);
  tt_int_op(retval, OP_EQ, 0);

  /* Check that the time period number is right */
  tn = hs_get_time_period_num(fake_time);
  tt_u64_op(tn, OP_EQ, 16903);

  /* Increase current time to 11:59:59 UTC and check that the time period
     number is still the same */
  fake_time += 3599;
  tn = hs_get_time_period_num(fake_time);
  tt_u64_op(tn, OP_EQ, 16903);

  { /* Check start time of next time period */
    retval = parse_rfc1123_time("Wed, 13 Apr 2016 12:00:00 UTC",
                                &correct_time);
    tt_int_op(retval, OP_EQ, 0);

    start_time = hs_get_start_time_of_next_time_period(fake_time);
    tt_int_op(start_time, OP_EQ, correct_time);
  }

  /* Now take time to 12:00:00 UTC and check that the time period rotated */
  fake_time += 1;
  tn = hs_get_time_period_num(fake_time);
  tt_u64_op(tn, OP_EQ, 16904);

  /* Now also check our hs_get_next_time_period_num() function */
  tn = hs_get_next_time_period_num(fake_time);
  tt_u64_op(tn, OP_EQ, 16905);

  { /* Check start time of next time period again */
    retval = parse_rfc1123_time("Wed, 14 Apr 2016 12:00:00 UTC",
                                &correct_time);
    tt_int_op(retval, OP_EQ, 0);

    start_time = hs_get_start_time_of_next_time_period(fake_time);
    tt_int_op(start_time, OP_EQ, correct_time);
  }

  /* Now do another sanity check: The time period number at the start of the
   * next time period, must be the same time period number as the one returned
   * from hs_get_next_time_period_num() */
  {
    time_t next_tp_start = hs_get_start_time_of_next_time_period(fake_time);
    tt_u64_op(hs_get_time_period_num(next_tp_start), OP_EQ,
              hs_get_next_time_period_num(fake_time));
  }

 done:
  ;
}

/** Test that we can correctly find the start time of the next time period */
static void
test_start_time_of_next_time_period(void *arg)
{
  (void) arg;
  int retval;
  time_t fake_time;
  char tbuf[ISO_TIME_LEN + 1];
  time_t next_tp_start_time;

  /* Do some basic tests */
  retval = parse_rfc1123_time("Wed, 13 Apr 2016 11:00:00 UTC",
                              &fake_time);
  tt_int_op(retval, OP_EQ, 0);
  next_tp_start_time = hs_get_start_time_of_next_time_period(fake_time);
  /* Compare it with the correct result */
  format_iso_time(tbuf, next_tp_start_time);
  tt_str_op("2016-04-13 12:00:00", OP_EQ, tbuf);

  /* Another test with an edge-case time (start of TP) */
  retval = parse_rfc1123_time("Wed, 13 Apr 2016 12:00:00 UTC",
                              &fake_time);
  tt_int_op(retval, OP_EQ, 0);
  next_tp_start_time = hs_get_start_time_of_next_time_period(fake_time);
  format_iso_time(tbuf, next_tp_start_time);
  tt_str_op("2016-04-14 12:00:00", OP_EQ, tbuf);

  {
    /* Now pretend we are on a testing network and alter the voting schedule to
       be every 10 seconds. This means that a time period has length 10*24
       seconds (4 minutes). It also means that we apply a rotational offset of
       120 seconds to the time period, so that it starts at 00:02:00 instead of
       00:00:00. */
    or_options_t *options = get_options_mutable();
    options->TestingTorNetwork = 1;
    options->V3AuthVotingInterval = 10;
    options->TestingV3AuthInitialVotingInterval = 10;

    retval = parse_rfc1123_time("Wed, 13 Apr 2016 00:00:00 UTC",
                                &fake_time);
    tt_int_op(retval, OP_EQ, 0);
    next_tp_start_time = hs_get_start_time_of_next_time_period(fake_time);
    /* Compare it with the correct result */
    format_iso_time(tbuf, next_tp_start_time);
    tt_str_op("2016-04-13 00:02:00", OP_EQ, tbuf);

    retval = parse_rfc1123_time("Wed, 13 Apr 2016 00:02:00 UTC",
                                &fake_time);
    tt_int_op(retval, OP_EQ, 0);
    next_tp_start_time = hs_get_start_time_of_next_time_period(fake_time);
    /* Compare it with the correct result */
    format_iso_time(tbuf, next_tp_start_time);
    tt_str_op("2016-04-13 00:06:00", OP_EQ, tbuf);
  }

 done:
  ;
}

/** Test that our HS overlap period functions work properly. */
static void
test_desc_overlap_period(void *arg)
{
  (void) arg;
  int retval;
  time_t now = time(NULL);
  networkstatus_t *dummy_consensus = NULL;

  /* First try with a consensus just inside the overlap period */
  dummy_consensus = tor_malloc_zero(sizeof(networkstatus_t));
  retval = parse_rfc1123_time("Wed, 13 Apr 2016 00:00:00 UTC",
                              &dummy_consensus->valid_after);
  tt_int_op(retval, OP_EQ, 0);

  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, OP_EQ, 1);

  /* Now increase the valid_after so that it goes to 11:00:00 UTC. Overlap
     period is still active. */
  dummy_consensus->valid_after += 3600*11;
  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, OP_EQ, 1);

  /* Now increase the valid_after so that it goes to 11:59:59 UTC. Overlap
     period is still active. */
  dummy_consensus->valid_after += 3599;
  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, OP_EQ, 1);

  /* Now increase the valid_after so that it drifts to noon, and check that
     overlap mode is not active anymore. */
  dummy_consensus->valid_after += 1;
  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, OP_EQ, 0);

  /* Check that overlap mode is also inactive at 23:59:59 UTC */
  retval = parse_rfc1123_time("Wed, 13 Apr 2016 23:59:59 UTC",
                              &dummy_consensus->valid_after);
  tt_int_op(retval, OP_EQ, 0);
  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, OP_EQ, 0);

 done:
  tor_free(dummy_consensus);
}

/* Test the overlap period functions on a testnet with altered voting
 * schedule */
static void
test_desc_overlap_period_testnet(void *arg)
{
  int retval;
  time_t now = approx_time();
  networkstatus_t *dummy_consensus = NULL;
  or_options_t *options = get_options_mutable();

  (void) arg;

  /* Set the testnet option and a 10-second voting interval */
  options->TestingTorNetwork = 1;
  options->V3AuthVotingInterval = 10;
  options->TestingV3AuthInitialVotingInterval = 10;

  dummy_consensus = tor_malloc_zero(sizeof(networkstatus_t));

  /* A 10-second voting interval means that the lengths of an SRV run and of a
   * time period are both 10*24 seconds (4 minutes). The SRV gets published at
   * 00:00:00 and the TP starts at 00:02:00 (rotation offset: 2 mins). Those
   * two minutes between SRV publish and TP start is the overlap period
   * window. Let's test it: */
  retval = parse_rfc1123_time("Wed, 13 Apr 2016 00:00:00 UTC",
                              &dummy_consensus->valid_after);
  tt_int_op(retval, OP_EQ, 0);
  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, OP_EQ, 1);

  retval = parse_rfc1123_time("Wed, 13 Apr 2016 00:01:59 UTC",
                              &dummy_consensus->valid_after);
  tt_int_op(retval, OP_EQ, 0);
  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, OP_EQ, 1);

  retval = parse_rfc1123_time("Wed, 13 Apr 2016 00:02:00 UTC",
                              &dummy_consensus->valid_after);
  tt_int_op(retval, OP_EQ, 0);
  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, OP_EQ, 0);

  retval = parse_rfc1123_time("Wed, 13 Apr 2016 00:04:00 UTC",
                              &dummy_consensus->valid_after);
  tt_int_op(retval, OP_EQ, 0);
  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, OP_EQ, 1);

  retval = parse_rfc1123_time("Wed, 13 Apr 2016 00:05:59 UTC",
                              &dummy_consensus->valid_after);
  tt_int_op(retval, OP_EQ, 0);
  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, OP_EQ, 1);

  retval = parse_rfc1123_time("Wed, 13 Apr 2016 00:06:00 UTC",
                              &dummy_consensus->valid_after);
  tt_int_op(retval, OP_EQ, 0);
  retval = hs_overlap_mode_is_active(dummy_consensus, now);
  tt_int_op(retval, OP_EQ, 0);

 done:
  tor_free(dummy_consensus);
}

static void
helper_add_hsdir_to_networkstatus(networkstatus_t *ns,
                                  int identity_idx,
                                  const char *nickname,
                                  int is_hsdir)
{
  routerstatus_t *rs = tor_malloc_zero(sizeof(routerstatus_t));
  routerinfo_t *ri = tor_malloc_zero(sizeof(routerinfo_t));
  uint8_t identity[DIGEST_LEN];
  uint8_t curr_hsdir_index[DIGEST256_LEN];
  tor_addr_t ipv4_addr;

  memset(identity, identity_idx, sizeof(identity));
  memset(curr_hsdir_index, identity_idx, sizeof(curr_hsdir_index));

  memcpy(rs->identity_digest, identity, DIGEST_LEN);
  rs->is_hs_dir = is_hsdir;
  rs->supports_v3_hsdir = 1;
  strlcpy(rs->nickname, nickname, sizeof(rs->nickname));
  tor_addr_parse(&ipv4_addr, "1.2.3.4");
  ri->addr = tor_addr_to_ipv4h(&ipv4_addr);
  rs->addr = tor_addr_to_ipv4h(&ipv4_addr);
  ri->nickname = tor_strdup(nickname);
  ri->protocol_list = tor_strdup("HSDir=1-2 LinkAuth=3");
  memcpy(ri->cache_info.identity_digest, identity, DIGEST_LEN);
  tt_assert(nodelist_set_routerinfo(ri, NULL));
  node_t *node = node_get_mutable_by_id(ri->cache_info.identity_digest);
  tt_assert(node);
  node->rs = rs;
  memcpy(node->hsdir_index->fetch, curr_hsdir_index,
         sizeof(node->hsdir_index->fetch));
  smartlist_add(ns->routerstatus_list, rs);

 done:
  routerinfo_free(ri);
}

static networkstatus_t *mock_ns = NULL;

static networkstatus_t *
mock_networkstatus_get_latest_consensus(void)
{
  time_t now = approx_time();

  /* If initialized, return it */
  if (mock_ns) {
    return mock_ns;
  }

  /* Initialize fake consensus */
  mock_ns = tor_malloc_zero(sizeof(networkstatus_t));

  /* This consensus is live */
  mock_ns->valid_after = now-1;
  mock_ns->fresh_until = now+1;
  mock_ns->valid_until = now+2;
  /* Create routerstatus list */
  mock_ns->routerstatus_list = smartlist_new();
  mock_ns->type = NS_TYPE_CONSENSUS;

  return mock_ns;
}

/** Test the responsible HSDirs calculation function */
static void
test_responsible_hsdirs(void *arg)
{
  time_t now = approx_time();
  smartlist_t *responsible_dirs = smartlist_new();
  networkstatus_t *ns = NULL;
  int retval;

  (void) arg;

  hs_init();

  MOCK(networkstatus_get_latest_consensus,
       mock_networkstatus_get_latest_consensus);

  ns = networkstatus_get_latest_consensus();

  { /* First router: HSdir */
    helper_add_hsdir_to_networkstatus(ns, 1, "igor", 1);
  }

  { /* Second HSDir */
    helper_add_hsdir_to_networkstatus(ns, 2, "victor", 1);
  }

  { /* Third relay but not HSDir */
    helper_add_hsdir_to_networkstatus(ns, 3, "spyro", 0);
  }

  ed25519_keypair_t kp;
  retval = ed25519_keypair_generate(&kp, 0);
  tt_int_op(retval, OP_EQ , 0);

  uint64_t time_period_num = hs_get_time_period_num(now);
  hs_get_responsible_hsdirs(&kp.pubkey, time_period_num,
                            0, 0, responsible_dirs);

  /* Make sure that we only found 2 responsible HSDirs.
   * The third relay was not an hsdir! */
  tt_int_op(smartlist_len(responsible_dirs), OP_EQ, 2);

  /** TODO: Build a bigger network and do more tests here */

 done:
  SMARTLIST_FOREACH(ns->routerstatus_list,
                    routerstatus_t *, rs, routerstatus_free(rs));
  smartlist_free(responsible_dirs);
  smartlist_clear(ns->routerstatus_list);
  networkstatus_vote_free(mock_ns);
}

static void
mock_directory_initiate_request(directory_request_t *req)
{
  (void)req;
  return;
}

static int
mock_hs_desc_encode_descriptor(const hs_descriptor_t *desc,
                           const ed25519_keypair_t *signing_kp,
                           char **encoded_out)
{
  (void)desc;
  (void)signing_kp;

  tor_asprintf(encoded_out, "lulu");
  return 0;
}

static or_state_t dummy_state;

/* Mock function to get fake or state (used for rev counters) */
static or_state_t *
get_or_state_replacement(void)
{
  return &dummy_state;
}

static int
mock_router_have_minimum_dir_info(void)
{
  return 1;
}

/** Test that we correctly detect when the HSDir hash ring changes so that we
 *  reupload our descriptor. */
static void
test_desc_reupload_logic(void *arg)
{
  networkstatus_t *ns = NULL;

  (void) arg;

  hs_init();

  MOCK(router_have_minimum_dir_info,
       mock_router_have_minimum_dir_info);
  MOCK(get_or_state,
       get_or_state_replacement);
  MOCK(networkstatus_get_latest_consensus,
       mock_networkstatus_get_latest_consensus);
  MOCK(directory_initiate_request,
       mock_directory_initiate_request);
  MOCK(hs_desc_encode_descriptor,
       mock_hs_desc_encode_descriptor);

  ns = networkstatus_get_latest_consensus();

  /** Test logic:
   *  1) Upload descriptor to HSDirs
   *     CHECK that previous_hsdirs list was populated.
   *  2) Then call router_dir_info_changed() without an HSDir set change.
   *     CHECK that no reuplod occurs.
   *  3) Now change the HSDir set, and call dir_info_changed() again.
   *     CHECK that reupload occurs.
   *  4) Finally call service_desc_schedule_upload().
   *     CHECK that previous_hsdirs list was cleared.
   **/

  /* Let's start by building our descriptor and service */
  hs_service_descriptor_t *desc = service_descriptor_new();
  hs_service_t *service = NULL;
  char onion_addr[HS_SERVICE_ADDR_LEN_BASE32 + 1];
  ed25519_public_key_t pubkey;
  memset(&pubkey, '\x42', sizeof(pubkey));
  hs_build_address(&pubkey, HS_VERSION_THREE, onion_addr);
  service = tor_malloc_zero(sizeof(hs_service_t));
  memcpy(service->onion_address, onion_addr, sizeof(service->onion_address));
  ed25519_secret_key_generate(&service->keys.identity_sk, 0);
  ed25519_public_key_generate(&service->keys.identity_pk,
                              &service->keys.identity_sk);
  service->desc_current = desc;
  /* Also add service to service map */
  hs_service_ht *service_map = get_hs_service_map();
  tt_assert(service_map);
  tt_int_op(hs_service_get_num_services(), OP_EQ, 0);
  register_service(service_map, service);
  tt_int_op(hs_service_get_num_services(), OP_EQ, 1);

  /* Now let's create our hash ring: */
  {
    helper_add_hsdir_to_networkstatus(ns, 1, "dingus", 1);
    helper_add_hsdir_to_networkstatus(ns, 2, "clive", 1);
    helper_add_hsdir_to_networkstatus(ns, 3, "aaron", 1);
    helper_add_hsdir_to_networkstatus(ns, 4, "lizzie", 1);
    helper_add_hsdir_to_networkstatus(ns, 5, "daewon", 1);
    helper_add_hsdir_to_networkstatus(ns, 6, "clarke", 1);
  }

  /* Now let's upload our desc to all hsdirs */
  upload_descriptor_to_all(service, desc, 0);
  /* Check that previous hsdirs were populated */
  tt_int_op(smartlist_len(desc->previous_hsdirs), OP_EQ, 6);

  /* Poison next upload time so that we can see if it was changed by
   * router_dir_info_changed(). No changes in hash ring so far, so the upload
   * time should stay as is. */
  desc->next_upload_time = 42;
  router_dir_info_changed();
  tt_int_op(desc->next_upload_time, OP_EQ, 42);

  /* Now change the HSDir hash ring by swapping nora for aaron.
   * Start by clearing the hash ring */
  {
    SMARTLIST_FOREACH(ns->routerstatus_list,
                      routerstatus_t *, rs, routerstatus_free(rs));
    smartlist_clear(ns->routerstatus_list);
    nodelist_free_all();
    routerlist_free_all();
  }

  { /* Now add back all the nodes */
    helper_add_hsdir_to_networkstatus(ns, 1, "dingus", 1);
    helper_add_hsdir_to_networkstatus(ns, 2, "clive", 1);
    helper_add_hsdir_to_networkstatus(ns, 4, "lizzie", 1);
    helper_add_hsdir_to_networkstatus(ns, 5, "daewon", 1);
    helper_add_hsdir_to_networkstatus(ns, 6, "clarke", 1);
    helper_add_hsdir_to_networkstatus(ns, 7, "nora", 1);
  }

  /* Now call service_desc_hsdirs_changed() and see that it detected the hash
     ring change */
  time_t now = approx_time();
  tt_assert(now);
  tt_int_op(service_desc_hsdirs_changed(service, desc), OP_EQ, 1);
  tt_int_op(smartlist_len(desc->previous_hsdirs), OP_EQ, 6);

  /* Now order another upload and see that we keep having 6 prev hsdirs */
  upload_descriptor_to_all(service, desc, 0);
  /* Check that previous hsdirs were populated */
  tt_int_op(smartlist_len(desc->previous_hsdirs), OP_EQ, 6);

  /* Now restore the HSDir hash ring to its original state by swapping back
     aaron for nora */
  /* First clear up the hash ring */
  {
    SMARTLIST_FOREACH(ns->routerstatus_list,
                      routerstatus_t *, rs, routerstatus_free(rs));
    smartlist_clear(ns->routerstatus_list);
    nodelist_free_all();
    routerlist_free_all();
  }

  { /* Now populate the hash ring again */
    helper_add_hsdir_to_networkstatus(ns, 1, "dingus", 1);
    helper_add_hsdir_to_networkstatus(ns, 2, "clive", 1);
    helper_add_hsdir_to_networkstatus(ns, 3, "aaron", 1);
    helper_add_hsdir_to_networkstatus(ns, 4, "lizzie", 1);
    helper_add_hsdir_to_networkstatus(ns, 5, "daewon", 1);
    helper_add_hsdir_to_networkstatus(ns, 6, "clarke", 1);
  }

  /* Check that our algorithm catches this change of hsdirs */
  tt_int_op(service_desc_hsdirs_changed(service, desc), OP_EQ, 1);

  /* Now pretend that the descriptor changed, and order a reupload to all
     HSDirs. Make sure that the set of previous HSDirs was cleared. */
  service_desc_schedule_upload(desc, now, 1);
  tt_int_op(smartlist_len(desc->previous_hsdirs), OP_EQ, 0);

  /* Now reupload again: see that the prev hsdir set got populated again. */
  upload_descriptor_to_all(service, desc, 0);
  tt_int_op(smartlist_len(desc->previous_hsdirs), OP_EQ, 6);

 done:
  SMARTLIST_FOREACH(ns->routerstatus_list,
                    routerstatus_t *, rs, routerstatus_free(rs));
  smartlist_clear(ns->routerstatus_list);
  networkstatus_vote_free(ns);
  nodelist_free_all();
  hs_free_all();
}

/** Test disaster SRV computation and caching */
static void
test_disaster_srv(void *arg)
{
  uint8_t *cached_disaster_srv_one = NULL;
  uint8_t *cached_disaster_srv_two = NULL;
  uint8_t srv_one[DIGEST256_LEN] = {0};
  uint8_t srv_two[DIGEST256_LEN] = {0};
  uint8_t srv_three[DIGEST256_LEN] = {0};
  uint8_t srv_four[DIGEST256_LEN] = {0};
  uint8_t srv_five[DIGEST256_LEN] = {0};

  (void) arg;

  /* Get the cached SRVs: we gonna use them later for verification */
  cached_disaster_srv_one = get_first_cached_disaster_srv();
  cached_disaster_srv_two = get_second_cached_disaster_srv();

  /* Compute some srvs */
  get_disaster_srv(1, srv_one);
  get_disaster_srv(2, srv_two);

  /* Check that the cached ones where updated */
  tt_mem_op(cached_disaster_srv_one, OP_EQ, srv_one, DIGEST256_LEN);
  tt_mem_op(cached_disaster_srv_two, OP_EQ, srv_two, DIGEST256_LEN);

  /* Ask for an SRV that has already been computed */
  get_disaster_srv(2, srv_two);
  /* and check that the cache entries have not changed */
  tt_mem_op(cached_disaster_srv_one, OP_EQ, srv_one, DIGEST256_LEN);
  tt_mem_op(cached_disaster_srv_two, OP_EQ, srv_two, DIGEST256_LEN);

  /* Ask for a new SRV */
  get_disaster_srv(3, srv_three);
  tt_mem_op(cached_disaster_srv_one, OP_EQ, srv_three, DIGEST256_LEN);
  tt_mem_op(cached_disaster_srv_two, OP_EQ, srv_two, DIGEST256_LEN);

  /* Ask for another SRV: none of the original SRVs should now be cached */
  get_disaster_srv(4, srv_four);
  tt_mem_op(cached_disaster_srv_one, OP_EQ, srv_three, DIGEST256_LEN);
  tt_mem_op(cached_disaster_srv_two, OP_EQ, srv_four, DIGEST256_LEN);

  /* Ask for yet another SRV */
  get_disaster_srv(5, srv_five);
  tt_mem_op(cached_disaster_srv_one, OP_EQ, srv_five, DIGEST256_LEN);
  tt_mem_op(cached_disaster_srv_two, OP_EQ, srv_four, DIGEST256_LEN);

 done:
  ;
}

/** Test our HS descriptor request tracker by making various requests and
 *  checking whether they get tracked properly. */
static void
test_hid_serv_request_tracker(void *arg)
{
  (void) arg;
  time_t retval;
  routerstatus_t *hsdir = NULL, *hsdir2 = NULL, *hsdir3 = NULL;
  time_t now = approx_time();

  const char *req_key_str_first =
 "vd4zb6zesaubtrjvdqcr2w7x7lhw2up4Xnw4526ThUNbL5o1go+EdUuEqlKxHkNbnK41pRzizzs";
  const char *req_key_str_second =
 "g53o7iavcd62oihswhr24u6czmqws5kpXnw4526ThUNbL5o1go+EdUuEqlKxHkNbnK41pRzizzs";
  const char *req_key_str_small = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";

  /*************************** basic test *******************************/

  /* Get request tracker and make sure it's empty */
  strmap_t *request_tracker = get_last_hid_serv_requests();
  tt_int_op(strmap_size(request_tracker),OP_EQ, 0);

  /* Let's register a hid serv request */
  hsdir = tor_malloc_zero(sizeof(routerstatus_t));
  memset(hsdir->identity_digest, 'Z', DIGEST_LEN);
  retval = hs_lookup_last_hid_serv_request(hsdir, req_key_str_first,
                                           now, 1);
  tt_int_op(retval, OP_EQ, now);
  tt_int_op(strmap_size(request_tracker),OP_EQ, 1);

  /* Let's lookup a non-existent hidserv request */
  retval = hs_lookup_last_hid_serv_request(hsdir, req_key_str_second,
                                           now+1, 0);
  tt_int_op(retval, OP_EQ, 0);
  tt_int_op(strmap_size(request_tracker),OP_EQ, 1);

  /* Let's lookup a real hidserv request */
  retval = hs_lookup_last_hid_serv_request(hsdir, req_key_str_first,
                                           now+2, 0);
  tt_int_op(retval, OP_EQ, now); /* we got it */
  tt_int_op(strmap_size(request_tracker),OP_EQ, 1);

  /**********************************************************************/

  /* Let's add another request for the same HS but on a different HSDir. */
  hsdir2 = tor_malloc_zero(sizeof(routerstatus_t));
  memset(hsdir2->identity_digest, 2, DIGEST_LEN);
  retval = hs_lookup_last_hid_serv_request(hsdir2, req_key_str_first,
                                           now+3, 1);
  tt_int_op(retval, OP_EQ, now+3);
  tt_int_op(strmap_size(request_tracker),OP_EQ, 2);

  /* Check that we can clean the first request based on time */
  hs_clean_last_hid_serv_requests(now+3+REND_HID_SERV_DIR_REQUERY_PERIOD);
  tt_int_op(strmap_size(request_tracker),OP_EQ, 1);
  /* Check that it doesn't exist anymore */
  retval = hs_lookup_last_hid_serv_request(hsdir, req_key_str_first,
                                           now+2, 0);
  tt_int_op(retval, OP_EQ, 0);

  /* Now let's add a smaller req key str */
  hsdir3 = tor_malloc_zero(sizeof(routerstatus_t));
  memset(hsdir3->identity_digest, 3, DIGEST_LEN);
  retval = hs_lookup_last_hid_serv_request(hsdir3, req_key_str_small,
                                           now+4, 1);
  tt_int_op(retval, OP_EQ, now+4);
  tt_int_op(strmap_size(request_tracker),OP_EQ, 2);

  /*************************** deleting entries **************************/

  /* Add another request with very short key */
  retval = hs_lookup_last_hid_serv_request(hsdir, "l",  now, 1);
  tt_int_op(strmap_size(request_tracker),OP_EQ, 3);

  /* Try deleting entries with a dummy key. Check that our previous requests
   * are still there */
  tor_capture_bugs_(1);
  hs_purge_hid_serv_from_last_hid_serv_requests("a");
  tt_int_op(strmap_size(request_tracker),OP_EQ, 3);
  tor_end_capture_bugs_();

  /* Try another dummy key. Check that requests are still there */
  {
    char dummy[2000];
    memset(dummy, 'Z', 2000);
    dummy[1999] = '\x00';
    hs_purge_hid_serv_from_last_hid_serv_requests(dummy);
    tt_int_op(strmap_size(request_tracker),OP_EQ, 3);
  }

  /* Another dummy key! */
  hs_purge_hid_serv_from_last_hid_serv_requests(req_key_str_second);
  tt_int_op(strmap_size(request_tracker),OP_EQ, 3);

  /* Now actually delete a request! */
  hs_purge_hid_serv_from_last_hid_serv_requests(req_key_str_first);
  tt_int_op(strmap_size(request_tracker),OP_EQ, 2);

  /* Purge it all! */
  hs_purge_last_hid_serv_requests();
  request_tracker = get_last_hid_serv_requests();
  tt_int_op(strmap_size(request_tracker),OP_EQ, 0);

 done:
  tor_free(hsdir);
  tor_free(hsdir2);
  tor_free(hsdir3);
}

static void
test_parse_extended_hostname(void *arg)
{
  (void) arg;

  char address1[] = "fooaddress.onion";
  char address2[] = "aaaaaaaaaaaaaaaa.onion";
  char address3[] = "fooaddress.exit";
  char address4[] = "www.torproject.org";
  char address5[] = "foo.abcdefghijklmnop.onion";
  char address6[] = "foo.bar.abcdefghijklmnop.onion";
  char address7[] = ".abcdefghijklmnop.onion";
  char address8[] =
    "www.p3xnclpu4mu22dwaurjtsybyqk4xfjmcfz6z62yl24uwmhjatiwnlnad.onion";

  tt_assert(BAD_HOSTNAME == parse_extended_hostname(address1));
  tt_assert(ONION_V2_HOSTNAME == parse_extended_hostname(address2));
  tt_str_op(address2,OP_EQ, "aaaaaaaaaaaaaaaa");
  tt_assert(EXIT_HOSTNAME == parse_extended_hostname(address3));
  tt_assert(NORMAL_HOSTNAME == parse_extended_hostname(address4));
  tt_assert(ONION_V2_HOSTNAME == parse_extended_hostname(address5));
  tt_str_op(address5,OP_EQ, "abcdefghijklmnop");
  tt_assert(ONION_V2_HOSTNAME == parse_extended_hostname(address6));
  tt_str_op(address6,OP_EQ, "abcdefghijklmnop");
  tt_assert(BAD_HOSTNAME == parse_extended_hostname(address7));
  tt_assert(ONION_V3_HOSTNAME == parse_extended_hostname(address8));
  tt_str_op(address8, OP_EQ,
            "p3xnclpu4mu22dwaurjtsybyqk4xfjmcfz6z62yl24uwmhjatiwnlnad");

 done: ;
}

struct testcase_t hs_common_tests[] = {
  { "build_address", test_build_address, TT_FORK,
    NULL, NULL },
  { "validate_address", test_validate_address, TT_FORK,
    NULL, NULL },
  { "time_period", test_time_period, TT_FORK,
    NULL, NULL },
  { "start_time_of_next_time_period", test_start_time_of_next_time_period,
    TT_FORK, NULL, NULL },
  { "desc_overlap_period", test_desc_overlap_period, TT_FORK,
    NULL, NULL },
  { "desc_overlap_period_testnet", test_desc_overlap_period_testnet, TT_FORK,
    NULL, NULL },
  { "responsible_hsdirs", test_responsible_hsdirs, TT_FORK,
    NULL, NULL },
  { "desc_reupload_logic", test_desc_reupload_logic, TT_FORK,
    NULL, NULL },
  { "disaster_srv", test_disaster_srv, TT_FORK,
    NULL, NULL },
  { "hid_serv_request_tracker", test_hid_serv_request_tracker, TT_FORK,
    NULL, NULL },
  { "parse_extended_hostname", test_parse_extended_hostname, TT_FORK,
    NULL, NULL },

  END_OF_TESTCASES
};

