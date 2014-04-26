/* Copyright (c) 2010-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include "or.h"

#include "config.h"
#include "microdesc.h"

#include "test.h"

#ifdef _WIN32
/* For mkdir() */
#include <direct.h>
#else
#include <dirent.h>
#endif

static const char test_md1[] =
  "onion-key\n"
  "-----BEGIN RSA PUBLIC KEY-----\n"
  "MIGJAoGBAMjlHH/daN43cSVRaHBwgUfnszzAhg98EvivJ9Qxfv51mvQUxPjQ07es\n"
  "gV/3n8fyh3Kqr/ehi9jxkdgSRfSnmF7giaHL1SLZ29kA7KtST+pBvmTpDtHa3ykX\n"
  "Xorc7hJvIyTZoc1HU+5XSynj3gsBE5IGK1ZRzrNS688LnuZMVp1tAgMBAAE=\n"
  "-----END RSA PUBLIC KEY-----\n";

static const char test_md2[] =
  "onion-key\n"
  "-----BEGIN RSA PUBLIC KEY-----\n"
  "MIGJAoGBAMIixIowh2DyPmDNMDwBX2DHcYcqdcH1zdIQJZkyV6c6rQHnvbcaDoSg\n"
  "jgFSLJKpnGmh71FVRqep+yVB0zI1JY43kuEnXry2HbZCD9UDo3d3n7t015X5S7ON\n"
  "bSSYtQGPwOr6Epf96IF6DoQxy4iDnPUAlejuhAG51s1y6/rZQ3zxAgMBAAE=\n"
  "-----END RSA PUBLIC KEY-----\n";

static const char test_md3[] =
  "@last-listed 2009-06-22\n"
  "onion-key\n"
  "-----BEGIN RSA PUBLIC KEY-----\n"
  "MIGJAoGBAMH3340d4ENNGrqx7UxT+lB7x6DNUKOdPEOn4teceE11xlMyZ9TPv41c\n"
  "qj2fRZzfxlc88G/tmiaHshmdtEpklZ740OFqaaJVj4LjPMKFNE+J7Xc1142BE9Ci\n"
  "KgsbjGYe2RY261aADRWLetJ8T9QDMm+JngL4288hc8pq1uB/3TAbAgMBAAE=\n"
  "-----END RSA PUBLIC KEY-----\n"
  "p accept 1-700,800-1000\n"
  "family nodeX nodeY nodeZ\n";

static void
test_md_cache(void *data)
{
  or_options_t *options = NULL;
  microdesc_cache_t *mc = NULL ;
  smartlist_t *added = NULL, *wanted = NULL;
  microdesc_t *md1, *md2, *md3;
  char d1[DIGEST256_LEN], d2[DIGEST256_LEN], d3[DIGEST256_LEN];
  const char *test_md3_noannotation = strchr(test_md3, '\n')+1;
  time_t time1, time2, time3;
  char *fn = NULL, *s = NULL;
  (void)data;

  options = get_options_mutable();
  tt_assert(options);

  time1 = time(NULL);
  time2 = time(NULL) - 2*24*60*60;
  time3 = time(NULL) - 15*24*60*60;

  /* Possibly, turn this into a test setup/cleanup pair */
  tor_free(options->DataDirectory);
  options->DataDirectory = tor_strdup(get_fname("md_datadir_test"));
#ifdef _WIN32
  tt_int_op(0, ==, mkdir(options->DataDirectory));
#else
  tt_int_op(0, ==, mkdir(options->DataDirectory, 0700));
#endif

  tt_assert(!strcmpstart(test_md3_noannotation, "onion-key"));

  crypto_digest256(d1, test_md1, strlen(test_md1), DIGEST_SHA256);
  crypto_digest256(d2, test_md2, strlen(test_md1), DIGEST_SHA256);
  crypto_digest256(d3, test_md3_noannotation, strlen(test_md3_noannotation),
                   DIGEST_SHA256);

  mc = get_microdesc_cache();

  added = microdescs_add_to_cache(mc, test_md1, NULL, SAVED_NOWHERE, 0,
                                  time1, NULL);
  tt_int_op(1, ==, smartlist_len(added));
  md1 = smartlist_get(added, 0);
  smartlist_free(added);
  added = NULL;

  wanted = smartlist_new();
  added = microdescs_add_to_cache(mc, test_md2, NULL, SAVED_NOWHERE, 0,
                                  time2, wanted);
  /* Should fail, since we didn't list test_md2's digest in wanted */
  tt_int_op(0, ==, smartlist_len(added));
  smartlist_free(added);
  added = NULL;

  smartlist_add(wanted, tor_memdup(d2, DIGEST256_LEN));
  smartlist_add(wanted, tor_memdup(d3, DIGEST256_LEN));
  added = microdescs_add_to_cache(mc, test_md2, NULL, SAVED_NOWHERE, 0,
                                  time2, wanted);
  /* Now it can work. md2 should have been added */
  tt_int_op(1, ==, smartlist_len(added));
  md2 = smartlist_get(added, 0);
  /* And it should have gotten removed from 'wanted' */
  tt_int_op(smartlist_len(wanted), ==, 1);
  test_mem_op(smartlist_get(wanted, 0), ==, d3, DIGEST256_LEN);
  smartlist_free(added);
  added = NULL;

  added = microdescs_add_to_cache(mc, test_md3, NULL,
                                  SAVED_NOWHERE, 0, -1, NULL);
  /* Must fail, since SAVED_NOWHERE precludes annotations */
  tt_int_op(0, ==, smartlist_len(added));
  smartlist_free(added);
  added = NULL;

  added = microdescs_add_to_cache(mc, test_md3_noannotation, NULL,
                                  SAVED_NOWHERE, 0, time3, NULL);
  /* Now it can work */
  tt_int_op(1, ==, smartlist_len(added));
  md3 = smartlist_get(added, 0);
  smartlist_free(added);
  added = NULL;

  /* Okay.  We added 1...3.  Let's poke them to see how they look, and make
   * sure they're really in the journal. */
  tt_ptr_op(md1, ==, microdesc_cache_lookup_by_digest256(mc, d1));
  tt_ptr_op(md2, ==, microdesc_cache_lookup_by_digest256(mc, d2));
  tt_ptr_op(md3, ==, microdesc_cache_lookup_by_digest256(mc, d3));

  tt_int_op(md1->last_listed, ==, time1);
  tt_int_op(md2->last_listed, ==, time2);
  tt_int_op(md3->last_listed, ==, time3);

  tt_int_op(md1->saved_location, ==, SAVED_IN_JOURNAL);
  tt_int_op(md2->saved_location, ==, SAVED_IN_JOURNAL);
  tt_int_op(md3->saved_location, ==, SAVED_IN_JOURNAL);

  tt_int_op(md1->bodylen, ==, strlen(test_md1));
  tt_int_op(md2->bodylen, ==, strlen(test_md2));
  tt_int_op(md3->bodylen, ==, strlen(test_md3_noannotation));
  test_mem_op(md1->body, ==, test_md1, strlen(test_md1));
  test_mem_op(md2->body, ==, test_md2, strlen(test_md2));
  test_mem_op(md3->body, ==, test_md3_noannotation,
              strlen(test_md3_noannotation));

  tor_asprintf(&fn, "%s"PATH_SEPARATOR"cached-microdescs.new",
               options->DataDirectory);
  s = read_file_to_str(fn, RFTS_BIN, NULL);
  tt_assert(s);
  test_mem_op(md1->body, ==, s + md1->off, md1->bodylen);
  test_mem_op(md2->body, ==, s + md2->off, md2->bodylen);
  test_mem_op(md3->body, ==, s + md3->off, md3->bodylen);

  tt_ptr_op(md1->family, ==, NULL);
  tt_ptr_op(md3->family, !=, NULL);
  tt_int_op(smartlist_len(md3->family), ==, 3);
  tt_str_op(smartlist_get(md3->family, 0), ==, "nodeX");

  /* Now rebuild the cache! */
  tt_int_op(microdesc_cache_rebuild(mc, 1), ==, 0);

  tt_int_op(md1->saved_location, ==, SAVED_IN_CACHE);
  tt_int_op(md2->saved_location, ==, SAVED_IN_CACHE);
  tt_int_op(md3->saved_location, ==, SAVED_IN_CACHE);

  /* The journal should be empty now */
  tor_free(s);
  s = read_file_to_str(fn, RFTS_BIN, NULL);
  tt_str_op(s, ==, "");
  tor_free(s);
  tor_free(fn);

  /* read the cache. */
  tor_asprintf(&fn, "%s"PATH_SEPARATOR"cached-microdescs",
               options->DataDirectory);
  s = read_file_to_str(fn, RFTS_BIN, NULL);
  test_mem_op(md1->body, ==, s + md1->off, strlen(test_md1));
  test_mem_op(md2->body, ==, s + md2->off, strlen(test_md2));
  test_mem_op(md3->body, ==, s + md3->off, strlen(test_md3_noannotation));

  /* Okay, now we are going to forget about the cache entirely, and reload it
   * from the disk. */
  microdesc_free_all();
  mc = get_microdesc_cache();
  md1 = microdesc_cache_lookup_by_digest256(mc, d1);
  md2 = microdesc_cache_lookup_by_digest256(mc, d2);
  md3 = microdesc_cache_lookup_by_digest256(mc, d3);
  test_assert(md1);
  test_assert(md2);
  test_assert(md3);
  test_mem_op(md1->body, ==, s + md1->off, strlen(test_md1));
  test_mem_op(md2->body, ==, s + md2->off, strlen(test_md2));
  test_mem_op(md3->body, ==, s + md3->off, strlen(test_md3_noannotation));

  tt_int_op(md1->last_listed, ==, time1);
  tt_int_op(md2->last_listed, ==, time2);
  tt_int_op(md3->last_listed, ==, time3);

  /* Okay, now we are going to clear out everything older than a week old.
   * In practice, that means md3 */
  microdesc_cache_clean(mc, time(NULL)-7*24*60*60, 1/*force*/);
  tt_ptr_op(md1, ==, microdesc_cache_lookup_by_digest256(mc, d1));
  tt_ptr_op(md2, ==, microdesc_cache_lookup_by_digest256(mc, d2));
  tt_ptr_op(NULL, ==, microdesc_cache_lookup_by_digest256(mc, d3));
  md3 = NULL; /* it's history now! */

  /* rebuild again, make sure it stays gone. */
  tt_int_op(microdesc_cache_rebuild(mc, 1), ==, 0);
  tt_ptr_op(md1, ==, microdesc_cache_lookup_by_digest256(mc, d1));
  tt_ptr_op(md2, ==, microdesc_cache_lookup_by_digest256(mc, d2));
  tt_ptr_op(NULL, ==, microdesc_cache_lookup_by_digest256(mc, d3));

  /* Re-add md3, and make sure we can rebuild the cache. */
  added = microdescs_add_to_cache(mc, test_md3_noannotation, NULL,
                                  SAVED_NOWHERE, 0, time3, NULL);
  tt_int_op(1, ==, smartlist_len(added));
  md3 = smartlist_get(added, 0);
  smartlist_free(added);
  added = NULL;
  tt_int_op(md1->saved_location, ==, SAVED_IN_CACHE);
  tt_int_op(md2->saved_location, ==, SAVED_IN_CACHE);
  tt_int_op(md3->saved_location, ==, SAVED_IN_JOURNAL);

  tt_int_op(microdesc_cache_rebuild(mc, 1), ==, 0);
  tt_int_op(md3->saved_location, ==, SAVED_IN_CACHE);

 done:
  if (options)
    tor_free(options->DataDirectory);
  microdesc_free_all();

  smartlist_free(added);
  if (wanted)
    SMARTLIST_FOREACH(wanted, char *, cp, tor_free(cp));
  smartlist_free(wanted);
  tor_free(s);
  tor_free(fn);
}

static const char truncated_md[] =
  "@last-listed 2013-08-08 19:02:59\n"
  "onion-key\n"
  "-----BEGIN RSA PUBLIC KEY-----\n"
  "MIGJAoGBAM91vLFNaM+gGhnRIdz2Cm/Kl7Xz0cOobIdVzhS3cKUJfk867hCuTipS\n"
  "NveLBzNopvgXKruAAzEj3cACxk6Q8lv5UWOGCD1UolkgsWSE62RBjap44g+oc9J1\n"
  "RI9968xOTZw0VaBQg9giEILNXl0djoikQ+5tQRUvLDDa67gpa5Q1AgMBAAE=\n"
  "-----END RSA PUBLIC KEY-----\n"
  "family @\n";

static void
test_md_cache_broken(void *data)
{
  or_options_t *options;
  char *fn=NULL;
  microdesc_cache_t *mc = NULL;

  (void)data;

  options = get_options_mutable();
  tt_assert(options);
  tor_free(options->DataDirectory);
  options->DataDirectory = tor_strdup(get_fname("md_datadir_test2"));

#ifdef _WIN32
  tt_int_op(0, ==, mkdir(options->DataDirectory));
#else
  tt_int_op(0, ==, mkdir(options->DataDirectory, 0700));
#endif

  tor_asprintf(&fn, "%s"PATH_SEPARATOR"cached-microdescs",
               options->DataDirectory);

  write_str_to_file(fn, truncated_md, 1);

  mc = get_microdesc_cache();
  tt_assert(mc);

 done:
  if (options)
    tor_free(options->DataDirectory);
  tor_free(fn);
  microdesc_free_all();
}

struct testcase_t microdesc_tests[] = {
  { "cache", test_md_cache, TT_FORK, NULL, NULL },
  { "broken_cache", test_md_cache_broken, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};

