/* Copyright (c) 2015-2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define CONTROL_PRIVATE
#include "or.h"
#include "control.h"
#include "networkstatus.h"
#include "rendservice.h"
#include "test.h"

static void
test_add_onion_helper_keyarg(void *arg)
{
  crypto_pk_t *pk = NULL;
  crypto_pk_t *pk2 = NULL;
  const char *key_new_alg = NULL;
  char *key_new_blob = NULL;
  char *err_msg = NULL;
  char *encoded = NULL;
  char *arg_str = NULL;

  (void) arg;

  /* Test explicit RSA1024 key generation. */
  pk = add_onion_helper_keyarg("NEW:RSA1024", 0, &key_new_alg, &key_new_blob,
                               &err_msg);
  tt_assert(pk);
  tt_str_op(key_new_alg, OP_EQ, "RSA1024");
  tt_assert(key_new_blob);
  tt_assert(!err_msg);

  /* Test "BEST" key generation (Assumes BEST = RSA1024). */
  crypto_pk_free(pk);
  tor_free(key_new_blob);
  pk = add_onion_helper_keyarg("NEW:BEST", 0, &key_new_alg, &key_new_blob,
                               &err_msg);
  tt_assert(pk);
  tt_str_op(key_new_alg, OP_EQ, "RSA1024");
  tt_assert(key_new_blob);
  tt_assert(!err_msg);

  /* Test discarding the private key. */
  crypto_pk_free(pk);
  tor_free(key_new_blob);
  pk = add_onion_helper_keyarg("NEW:BEST", 1, &key_new_alg, &key_new_blob,
                               &err_msg);
  tt_assert(pk);
  tt_assert(!key_new_alg);
  tt_assert(!key_new_blob);
  tt_assert(!err_msg);

  /* Test generating a invalid key type. */
  crypto_pk_free(pk);
  pk = add_onion_helper_keyarg("NEW:RSA512", 0, &key_new_alg, &key_new_blob,
                               &err_msg);
  tt_assert(!pk);
  tt_assert(!key_new_alg);
  tt_assert(!key_new_blob);
  tt_assert(err_msg);

  /* Test loading a RSA1024 key. */
  tor_free(err_msg);
  pk = pk_generate(0);
  tt_int_op(0, OP_EQ, crypto_pk_base64_encode(pk, &encoded));
  tor_asprintf(&arg_str, "RSA1024:%s", encoded);
  pk2 = add_onion_helper_keyarg(arg_str, 0, &key_new_alg, &key_new_blob,
                                &err_msg);
  tt_assert(pk2);
  tt_assert(!key_new_alg);
  tt_assert(!key_new_blob);
  tt_assert(!err_msg);
  tt_assert(crypto_pk_cmp_keys(pk, pk2) == 0);

  /* Test loading a invalid key type. */
  tor_free(arg_str);
  crypto_pk_free(pk); pk = NULL;
  tor_asprintf(&arg_str, "RSA512:%s", encoded);
  pk = add_onion_helper_keyarg(arg_str, 0, &key_new_alg, &key_new_blob,
                               &err_msg);
  tt_assert(!pk);
  tt_assert(!key_new_alg);
  tt_assert(!key_new_blob);
  tt_assert(err_msg);

  /* Test loading a invalid key. */
  tor_free(arg_str);
  crypto_pk_free(pk); pk = NULL;
  tor_free(err_msg);
  encoded[strlen(encoded)/2] = '\0';
  tor_asprintf(&arg_str, "RSA1024:%s", encoded);
  pk = add_onion_helper_keyarg(arg_str, 0, &key_new_alg, &key_new_blob,
                               &err_msg);
  tt_assert(!pk);
  tt_assert(!key_new_alg);
  tt_assert(!key_new_blob);
  tt_assert(err_msg);

 done:
  crypto_pk_free(pk);
  crypto_pk_free(pk2);
  tor_free(key_new_blob);
  tor_free(err_msg);
  tor_free(encoded);
  tor_free(arg_str);
}

static void
test_rend_service_parse_port_config(void *arg)
{
  const char *sep = ",";
  rend_service_port_config_t *cfg = NULL;
  char *err_msg = NULL;

  (void)arg;

  /* Test "VIRTPORT" only. */
  cfg = rend_service_parse_port_config("80", sep, &err_msg);
  tt_assert(cfg);
  tt_assert(!err_msg);

  /* Test "VIRTPORT,TARGET" (Target is port). */
  rend_service_port_config_free(cfg);
  cfg = rend_service_parse_port_config("80,8080", sep, &err_msg);
  tt_assert(cfg);
  tt_assert(!err_msg);

  /* Test "VIRTPORT,TARGET" (Target is IPv4:port). */
  rend_service_port_config_free(cfg);
  cfg = rend_service_parse_port_config("80,192.0.2.1:8080", sep, &err_msg);
  tt_assert(cfg);
  tt_assert(!err_msg);

  /* Test "VIRTPORT,TARGET" (Target is IPv6:port). */
  rend_service_port_config_free(cfg);
  cfg = rend_service_parse_port_config("80,[2001:db8::1]:8080", sep, &err_msg);
  tt_assert(cfg);
  tt_assert(!err_msg);

  /* XXX: Someone should add tests for AF_UNIX targets if supported. */

  /* Test empty config. */
  rend_service_port_config_free(cfg);
  cfg = rend_service_parse_port_config("", sep, &err_msg);
  tt_assert(!cfg);
  tt_assert(err_msg);

  /* Test invalid port. */
  tor_free(err_msg);
  cfg = rend_service_parse_port_config("90001", sep, &err_msg);
  tt_assert(!cfg);
  tt_assert(err_msg);

 done:
  rend_service_port_config_free(cfg);
  tor_free(err_msg);
}

static void
test_add_onion_helper_clientauth(void *arg)
{
  rend_authorized_client_t *client = NULL;
  char *err_msg = NULL;
  int created = 0;

  (void)arg;

  /* Test "ClientName" only. */
  client = add_onion_helper_clientauth("alice", &created, &err_msg);
  tt_assert(client);
  tt_assert(created);
  tt_assert(!err_msg);
  rend_authorized_client_free(client);

  /* Test "ClientName:Blob" */
  client = add_onion_helper_clientauth("alice:475hGBHPlq7Mc0cRZitK/B",
                                       &created, &err_msg);
  tt_assert(client);
  tt_assert(!created);
  tt_assert(!err_msg);
  rend_authorized_client_free(client);

  /* Test invalid client names */
  client = add_onion_helper_clientauth("no*asterisks*allowed", &created,
                                       &err_msg);
  tt_assert(!client);
  tt_assert(err_msg);
  tor_free(err_msg);

  /* Test invalid auth cookie */
  client = add_onion_helper_clientauth("alice:12345", &created, &err_msg);
  tt_assert(!client);
  tt_assert(err_msg);
  tor_free(err_msg);

  /* Test invalid syntax */
  client = add_onion_helper_clientauth(":475hGBHPlq7Mc0cRZitK/B", &created,
                                       &err_msg);
  tt_assert(!client);
  tt_assert(err_msg);
  tor_free(err_msg);

 done:
  rend_authorized_client_free(client);
  tor_free(err_msg);
}

/* Mocks and data/variables used for GETINFO download status tests */

static const download_status_t dl_status_default =
  { 0, 0, 0, DL_SCHED_CONSENSUS, DL_WANT_ANY_DIRSERVER,
    DL_SCHED_INCREMENT_FAILURE, DL_SCHED_RANDOM_EXPONENTIAL, 0, 0 };
static download_status_t ns_dl_status[N_CONSENSUS_FLAVORS];
static download_status_t ns_dl_status_bootstrap[N_CONSENSUS_FLAVORS];
static download_status_t ns_dl_status_running[N_CONSENSUS_FLAVORS];

/*
 * These should explore all the possible cases of download_status_to_string()
 * in control.c
 */
static const download_status_t dls_sample_1 =
  { 1467163900, 0, 0, DL_SCHED_GENERIC, DL_WANT_ANY_DIRSERVER,
    DL_SCHED_INCREMENT_FAILURE, DL_SCHED_DETERMINISTIC, 0, 0 };
static const char * dls_sample_1_str =
    "next-attempt-at 2016-06-29 01:31:40\n"
    "n-download-failures 0\n"
    "n-download-attempts 0\n"
    "schedule DL_SCHED_GENERIC\n"
    "want-authority DL_WANT_ANY_DIRSERVER\n"
    "increment-on DL_SCHED_INCREMENT_FAILURE\n"
    "backoff DL_SCHED_DETERMINISTIC\n";
static const download_status_t dls_sample_2 =
  { 1467164400, 1, 2, DL_SCHED_CONSENSUS, DL_WANT_AUTHORITY,
    DL_SCHED_INCREMENT_FAILURE, DL_SCHED_DETERMINISTIC, 0, 0 };
static const char * dls_sample_2_str =
    "next-attempt-at 2016-06-29 01:40:00\n"
    "n-download-failures 1\n"
    "n-download-attempts 2\n"
    "schedule DL_SCHED_CONSENSUS\n"
    "want-authority DL_WANT_AUTHORITY\n"
    "increment-on DL_SCHED_INCREMENT_FAILURE\n"
    "backoff DL_SCHED_DETERMINISTIC\n";
static const download_status_t dls_sample_3 =
  { 1467154400, 12, 25, DL_SCHED_BRIDGE, DL_WANT_ANY_DIRSERVER,
    DL_SCHED_INCREMENT_ATTEMPT, DL_SCHED_DETERMINISTIC, 0, 0 };
static const char * dls_sample_3_str =
    "next-attempt-at 2016-06-28 22:53:20\n"
    "n-download-failures 12\n"
    "n-download-attempts 25\n"
    "schedule DL_SCHED_BRIDGE\n"
    "want-authority DL_WANT_ANY_DIRSERVER\n"
    "increment-on DL_SCHED_INCREMENT_ATTEMPT\n"
    "backoff DL_SCHED_DETERMINISTIC\n";
static const download_status_t dls_sample_4 =
  { 1467166600, 3, 0, DL_SCHED_GENERIC, DL_WANT_ANY_DIRSERVER,
    DL_SCHED_INCREMENT_FAILURE, DL_SCHED_RANDOM_EXPONENTIAL, 0, 0 };
static const char * dls_sample_4_str =
    "next-attempt-at 2016-06-29 02:16:40\n"
    "n-download-failures 3\n"
    "n-download-attempts 0\n"
    "schedule DL_SCHED_GENERIC\n"
    "want-authority DL_WANT_ANY_DIRSERVER\n"
    "increment-on DL_SCHED_INCREMENT_FAILURE\n"
    "backoff DL_SCHED_RANDOM_EXPONENTIAL\n"
    "last-backoff-position 0\n"
    "last-delay-used 0\n";
static const download_status_t dls_sample_5 =
  { 1467164600, 3, 7, DL_SCHED_CONSENSUS, DL_WANT_ANY_DIRSERVER,
    DL_SCHED_INCREMENT_FAILURE, DL_SCHED_RANDOM_EXPONENTIAL, 1, 2112, };
static const char * dls_sample_5_str =
    "next-attempt-at 2016-06-29 01:43:20\n"
    "n-download-failures 3\n"
    "n-download-attempts 7\n"
    "schedule DL_SCHED_CONSENSUS\n"
    "want-authority DL_WANT_ANY_DIRSERVER\n"
    "increment-on DL_SCHED_INCREMENT_FAILURE\n"
    "backoff DL_SCHED_RANDOM_EXPONENTIAL\n"
    "last-backoff-position 1\n"
    "last-delay-used 2112\n";
static const download_status_t dls_sample_6 =
  { 1467164200, 4, 9, DL_SCHED_CONSENSUS, DL_WANT_AUTHORITY,
    DL_SCHED_INCREMENT_ATTEMPT, DL_SCHED_RANDOM_EXPONENTIAL, 3, 432 };
static const char * dls_sample_6_str =
    "next-attempt-at 2016-06-29 01:36:40\n"
    "n-download-failures 4\n"
    "n-download-attempts 9\n"
    "schedule DL_SCHED_CONSENSUS\n"
    "want-authority DL_WANT_AUTHORITY\n"
    "increment-on DL_SCHED_INCREMENT_ATTEMPT\n"
    "backoff DL_SCHED_RANDOM_EXPONENTIAL\n"
    "last-backoff-position 3\n"
    "last-delay-used 432\n";

static void
reset_mocked_dl_statuses(void)
{
  int i;

  for (i = 0; i < N_CONSENSUS_FLAVORS; ++i) {
    memcpy(&(ns_dl_status[i]), &dl_status_default,
           sizeof(download_status_t));
    memcpy(&(ns_dl_status_bootstrap[i]), &dl_status_default,
           sizeof(download_status_t));
    memcpy(&(ns_dl_status_running[i]), &dl_status_default,
           sizeof(download_status_t));
  }
}

static download_status_t *
ns_dl_status_mock(consensus_flavor_t flavor)
{
  return &(ns_dl_status[flavor]);
}

static download_status_t *
ns_dl_status_bootstrap_mock(consensus_flavor_t flavor)
{
  return &(ns_dl_status_bootstrap[flavor]);
}

static download_status_t *
ns_dl_status_running_mock(consensus_flavor_t flavor)
{
  return &(ns_dl_status_running[flavor]);
}

static void
setup_ns_mocks(void)
{
  MOCK(networkstatus_get_dl_status_by_flavor, ns_dl_status_mock);
  MOCK(networkstatus_get_dl_status_by_flavor_bootstrap,
       ns_dl_status_bootstrap_mock);
  MOCK(networkstatus_get_dl_status_by_flavor_running,
       ns_dl_status_running_mock);
  reset_mocked_dl_statuses();
}

static void
clear_ns_mocks(void)
{
  UNMOCK(networkstatus_get_dl_status_by_flavor);
  UNMOCK(networkstatus_get_dl_status_by_flavor_bootstrap);
  UNMOCK(networkstatus_get_dl_status_by_flavor_running);
}

static void
test_download_status_consensus(void *arg)
{
  /* We just need one of these to pass, it doesn't matter what's in it */
  control_connection_t dummy;
  /* Get results out */
  char *answer = NULL;
  const char *errmsg = NULL;

  (void)arg;

  /* Check that the unknown prefix case works; no mocks needed yet */
  getinfo_helper_downloads(&dummy, "downloads/foo", &answer, &errmsg);
  tt_assert(answer == NULL);
  tt_str_op(errmsg, OP_EQ, "Unknown download status query");

  setup_ns_mocks();

  /*
   * Check returning serialized dlstatuses, and implicitly also test
   * download_status_to_string().
   */

  /* Case 1 default/FLAV_NS*/
  memcpy(&(ns_dl_status[FLAV_NS]), &dls_sample_1,
         sizeof(download_status_t));
  getinfo_helper_downloads(&dummy, "downloads/networkstatus/ns",
                           &answer, &errmsg);
  tt_assert(answer != NULL);
  tt_assert(errmsg == NULL);
  tt_str_op(answer, OP_EQ, dls_sample_1_str);
  tor_free(answer);
  errmsg = NULL;

  /* Case 2 default/FLAV_MICRODESC */
  memcpy(&(ns_dl_status[FLAV_MICRODESC]), &dls_sample_2,
         sizeof(download_status_t));
  getinfo_helper_downloads(&dummy, "downloads/networkstatus/microdesc",
                           &answer, &errmsg);
  tt_assert(answer != NULL);
  tt_assert(errmsg == NULL);
  tt_str_op(answer, OP_EQ, dls_sample_2_str);
  tor_free(answer);
  errmsg = NULL;

  /* Case 3 bootstrap/FLAV_NS */
  memcpy(&(ns_dl_status_bootstrap[FLAV_NS]), &dls_sample_3,
         sizeof(download_status_t));
  getinfo_helper_downloads(&dummy, "downloads/networkstatus/ns/bootstrap",
                           &answer, &errmsg);
  tt_assert(answer != NULL);
  tt_assert(errmsg == NULL);
  tt_str_op(answer, OP_EQ, dls_sample_3_str);
  tor_free(answer);
  errmsg = NULL;

  /* Case 4 bootstrap/FLAV_MICRODESC */
  memcpy(&(ns_dl_status_bootstrap[FLAV_MICRODESC]), &dls_sample_4,
         sizeof(download_status_t));
  getinfo_helper_downloads(&dummy,
                           "downloads/networkstatus/microdesc/bootstrap",
                           &answer, &errmsg);
  tt_assert(answer != NULL);
  tt_assert(errmsg == NULL);
  tt_str_op(answer, OP_EQ, dls_sample_4_str);
  tor_free(answer);
  errmsg = NULL;

  /* Case 5 running/FLAV_NS */
  memcpy(&(ns_dl_status_running[FLAV_NS]), &dls_sample_5,
         sizeof(download_status_t));
  getinfo_helper_downloads(&dummy,
                           "downloads/networkstatus/ns/running",
                           &answer, &errmsg);
  tt_assert(answer != NULL);
  tt_assert(errmsg == NULL);
  tt_str_op(answer, OP_EQ, dls_sample_5_str);
  tor_free(answer);
  errmsg = NULL;

  /* Case 6 running/FLAV_MICRODESC */
  memcpy(&(ns_dl_status_running[FLAV_MICRODESC]), &dls_sample_6,
         sizeof(download_status_t));
  getinfo_helper_downloads(&dummy,
                           "downloads/networkstatus/microdesc/running",
                           &answer, &errmsg);
  tt_assert(answer != NULL);
  tt_assert(errmsg == NULL);
  tt_str_op(answer, OP_EQ, dls_sample_6_str);
  tor_free(answer);
  errmsg = NULL;

  /* Now check the error case */
  getinfo_helper_downloads(&dummy, "downloads/networkstatus/foo",
                           &answer, &errmsg);
  tt_assert(answer == NULL);
  tt_assert(errmsg != NULL);
  tt_str_op(errmsg, OP_EQ, "Unknown flavor");
  errmsg = NULL;

 done:
  clear_ns_mocks();
  tor_free(answer);

  return;
}

struct testcase_t controller_tests[] = {
  { "add_onion_helper_keyarg", test_add_onion_helper_keyarg, 0, NULL, NULL },
  { "rend_service_parse_port_config", test_rend_service_parse_port_config, 0,
    NULL, NULL },
  { "add_onion_helper_clientauth", test_add_onion_helper_clientauth, 0, NULL,
    NULL },
  { "download_status_consensus", test_download_status_consensus, 0, NULL,
    NULL },
  END_OF_TESTCASES
};

