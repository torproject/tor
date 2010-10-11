/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#define CONTROL_PRIVATE
#define MEMPOOL_PRIVATE
#define UTIL_PRIVATE
#include "or.h"
#include "config.h"
#include "control.h"
#include "test.h"
#include "mempool.h"
#include "memarea.h"

static void
test_util_time(void)
{
  struct timeval start, end;
  struct tm a_time;
  char timestr[RFC1123_TIME_LEN+1];
  time_t t_res;
  int i;

  start.tv_sec = 5;
  start.tv_usec = 5000;

  end.tv_sec = 5;
  end.tv_usec = 5000;

  test_eq(0L, tv_udiff(&start, &end));

  end.tv_usec = 7000;

  test_eq(2000L, tv_udiff(&start, &end));

  end.tv_sec = 6;

  test_eq(1002000L, tv_udiff(&start, &end));

  end.tv_usec = 0;

  test_eq(995000L, tv_udiff(&start, &end));

  end.tv_sec = 4;

  test_eq(-1005000L, tv_udiff(&start, &end));

  end.tv_usec = 999990;
  start.tv_sec = 1;
  start.tv_usec = 500;

  /* The test values here are confirmed to be correct on a platform
   * with a working timegm. */
  a_time.tm_year = 2003-1900;
  a_time.tm_mon = 7;
  a_time.tm_mday = 30;
  a_time.tm_hour = 6;
  a_time.tm_min = 14;
  a_time.tm_sec = 55;
  test_eq((time_t) 1062224095UL, tor_timegm(&a_time));
  a_time.tm_year = 2004-1900; /* Try a leap year, after feb. */
  test_eq((time_t) 1093846495UL, tor_timegm(&a_time));
  a_time.tm_mon = 1;          /* Try a leap year, in feb. */
  a_time.tm_mday = 10;
  test_eq((time_t) 1076393695UL, tor_timegm(&a_time));

  format_rfc1123_time(timestr, 0);
  test_streq("Thu, 01 Jan 1970 00:00:00 GMT", timestr);
  format_rfc1123_time(timestr, (time_t)1091580502UL);
  test_streq("Wed, 04 Aug 2004 00:48:22 GMT", timestr);

  t_res = 0;
  i = parse_rfc1123_time(timestr, &t_res);
  test_eq(i,0);
  test_eq(t_res, (time_t)1091580502UL);
  test_eq(-1, parse_rfc1123_time("Wed, zz Aug 2004 99-99x99 GMT", &t_res));

  tor_gettimeofday(&start);
  /* now make sure time works. */
  tor_gettimeofday(&end);
  /* We might've timewarped a little. */
  tt_int_op(tv_udiff(&start, &end), >=, -5000);

 done:
  ;
}

static void
test_util_config_line(void)
{
  char buf[1024];
  char *k=NULL, *v=NULL;
  const char *str;

  /* Test parse_config_line_from_str */
  strlcpy(buf, "k v\n" " key    value with spaces   \n" "keykey val\n"
          "k2\n"
          "k3 \n" "\n" "   \n" "#comment\n"
          "k4#a\n" "k5#abc\n" "k6 val #with comment\n"
          "kseven   \"a quoted 'string\"\n"
          "k8 \"a \\x71uoted\\n\\\"str\\\\ing\\t\\001\\01\\1\\\"\"\n"
          "k9 a line that\\\n spans two lines.\n\n"
          "k10 more than\\\n one contin\\\nuation\n"
          "k11  \\\ncontinuation at the start\n"
          "k12 line with a\\\n#comment\n embedded\n"
          "k13\\\ncontinuation at the very start\n"
          "k14 a line that has a comment and # ends with a slash \\\n"
          "k15 this should be the next new line\n"
          "k16 a line that has a comment and # ends without a slash \n"
          "k17 this should be the next new line\n"
          , sizeof(buf));
  str = buf;

  str = parse_config_line_from_str(str, &k, &v);
  test_streq(k, "k");
  test_streq(v, "v");
  tor_free(k); tor_free(v);
  test_assert(!strcmpstart(str, "key    value with"));

  str = parse_config_line_from_str(str, &k, &v);
  test_streq(k, "key");
  test_streq(v, "value with spaces");
  tor_free(k); tor_free(v);
  test_assert(!strcmpstart(str, "keykey"));

  str = parse_config_line_from_str(str, &k, &v);
  test_streq(k, "keykey");
  test_streq(v, "val");
  tor_free(k); tor_free(v);
  test_assert(!strcmpstart(str, "k2\n"));

  str = parse_config_line_from_str(str, &k, &v);
  test_streq(k, "k2");
  test_streq(v, "");
  tor_free(k); tor_free(v);
  test_assert(!strcmpstart(str, "k3 \n"));

  str = parse_config_line_from_str(str, &k, &v);
  test_streq(k, "k3");
  test_streq(v, "");
  tor_free(k); tor_free(v);
  test_assert(!strcmpstart(str, "#comment"));

  str = parse_config_line_from_str(str, &k, &v);
  test_streq(k, "k4");
  test_streq(v, "");
  tor_free(k); tor_free(v);
  test_assert(!strcmpstart(str, "k5#abc"));

  str = parse_config_line_from_str(str, &k, &v);
  test_streq(k, "k5");
  test_streq(v, "");
  tor_free(k); tor_free(v);
  test_assert(!strcmpstart(str, "k6"));

  str = parse_config_line_from_str(str, &k, &v);
  test_streq(k, "k6");
  test_streq(v, "val");
  tor_free(k); tor_free(v);
  test_assert(!strcmpstart(str, "kseven"));

  str = parse_config_line_from_str(str, &k, &v);
  test_streq(k, "kseven");
  test_streq(v, "a quoted \'string");
  tor_free(k); tor_free(v);
  test_assert(!strcmpstart(str, "k8 "));

  str = parse_config_line_from_str(str, &k, &v);
  test_streq(k, "k8");
  test_streq(v, "a quoted\n\"str\\ing\t\x01\x01\x01\"");
  tor_free(k); tor_free(v);

  str = parse_config_line_from_str(str, &k, &v);
  test_streq(k, "k9");
  test_streq(v, "a line that spans two lines.");
  tor_free(k); tor_free(v);

  str = parse_config_line_from_str(str, &k, &v);
  test_streq(k, "k10");
  test_streq(v, "more than one continuation");
  tor_free(k); tor_free(v);

  str = parse_config_line_from_str(str, &k, &v);
  test_streq(k, "k11");
  test_streq(v, "continuation at the start");
  tor_free(k); tor_free(v);

  str = parse_config_line_from_str(str, &k, &v);
  test_streq(k, "k12");
  test_streq(v, "line with a embedded");
  tor_free(k); tor_free(v);

  str = parse_config_line_from_str(str, &k, &v);
  test_streq(k, "k13");
  test_streq(v, "continuation at the very start");
  tor_free(k); tor_free(v);

  str = parse_config_line_from_str(str, &k, &v);
  test_streq(k, "k14");
  test_streq(v, "a line that has a comment and" );
  tor_free(k); tor_free(v);

  str = parse_config_line_from_str(str, &k, &v);
  test_streq(k, "k15");
  test_streq(v, "this should be the next new line");
  tor_free(k); tor_free(v);

  str = parse_config_line_from_str(str, &k, &v);
  test_streq(k, "k16");
  test_streq(v, "a line that has a comment and" );
  tor_free(k); tor_free(v);

  str = parse_config_line_from_str(str, &k, &v);
  test_streq(k, "k17");
  test_streq(v, "this should be the next new line");
  tor_free(k); tor_free(v);

  test_streq(str, "");

 done:
  tor_free(k);
  tor_free(v);
}

/** Test basic string functionality. */
static void
test_util_strmisc(void)
{
  char buf[1024];
  int i;
  char *cp;

  /* Tests for corner cases of strl operations */
  test_eq(5, strlcpy(buf, "Hello", 0));
  strlcpy(buf, "Hello", sizeof(buf));
  test_eq(10, strlcat(buf, "Hello", 5));

  /* Test tor_strstrip() */
  strlcpy(buf, "Testing 1 2 3", sizeof(buf));
  tor_strstrip(buf, ",!");
  test_streq(buf, "Testing 1 2 3");
  strlcpy(buf, "!Testing 1 2 3?", sizeof(buf));
  tor_strstrip(buf, "!? ");
  test_streq(buf, "Testing123");

  /* Test tor_parse_long. */
  test_eq(10L, tor_parse_long("10",10,0,100,NULL,NULL));
  test_eq(0L, tor_parse_long("10",10,50,100,NULL,NULL));
  test_eq(-50L, tor_parse_long("-50",10,-100,100,NULL,NULL));

  /* Test tor_parse_ulong */
  test_eq(10UL, tor_parse_ulong("10",10,0,100,NULL,NULL));
  test_eq(0UL, tor_parse_ulong("10",10,50,100,NULL,NULL));

  /* Test tor_parse_uint64. */
  test_assert(U64_LITERAL(10) == tor_parse_uint64("10 x",10,0,100, &i, &cp));
  test_assert(i == 1);
  test_streq(cp, " x");
  test_assert(U64_LITERAL(12345678901) ==
              tor_parse_uint64("12345678901",10,0,UINT64_MAX, &i, &cp));
  test_assert(i == 1);
  test_streq(cp, "");
  test_assert(U64_LITERAL(0) ==
              tor_parse_uint64("12345678901",10,500,INT32_MAX, &i, &cp));
  test_assert(i == 0);

  {
  /* Test tor_parse_double. */
  double d = tor_parse_double("10", 0, UINT64_MAX,&i,NULL);
  test_assert(i == 1);
  test_assert(DBL_TO_U64(d) == 10);
  d = tor_parse_double("0", 0, UINT64_MAX,&i,NULL);
  test_assert(i == 1);
  test_assert(DBL_TO_U64(d) == 0);
  d = tor_parse_double(" ", 0, UINT64_MAX,&i,NULL);
  test_assert(i == 0);
  d = tor_parse_double(".0a", 0, UINT64_MAX,&i,NULL);
  test_assert(i == 0);
  d = tor_parse_double(".0a", 0, UINT64_MAX,&i,&cp);
  test_assert(i == 1);
  d = tor_parse_double("-.0", 0, UINT64_MAX,&i,NULL);
  test_assert(i == 1);
  }

  /* Test failing snprintf cases */
  test_eq(-1, tor_snprintf(buf, 0, "Foo"));
  test_eq(-1, tor_snprintf(buf, 2, "Foo"));

  /* Test printf with uint64 */
  tor_snprintf(buf, sizeof(buf), "x!"U64_FORMAT"!x",
               U64_PRINTF_ARG(U64_LITERAL(12345678901)));
  test_streq(buf, "x!12345678901!x");

  /* Test for strcmpstart and strcmpend. */
  test_assert(strcmpstart("abcdef", "abcdef")==0);
  test_assert(strcmpstart("abcdef", "abc")==0);
  test_assert(strcmpstart("abcdef", "abd")<0);
  test_assert(strcmpstart("abcdef", "abb")>0);
  test_assert(strcmpstart("ab", "abb")<0);

  test_assert(strcmpend("abcdef", "abcdef")==0);
  test_assert(strcmpend("abcdef", "def")==0);
  test_assert(strcmpend("abcdef", "deg")<0);
  test_assert(strcmpend("abcdef", "dee")>0);
  test_assert(strcmpend("ab", "abb")<0);

  test_assert(strcasecmpend("AbcDEF", "abcdef")==0);
  test_assert(strcasecmpend("abcdef", "dEF")==0);
  test_assert(strcasecmpend("abcDEf", "deg")<0);
  test_assert(strcasecmpend("abcdef", "DEE")>0);
  test_assert(strcasecmpend("ab", "abB")<0);

  /* Test mem_is_zero */
  memset(buf,0,128);
  buf[128] = 'x';
  test_assert(tor_digest_is_zero(buf));
  test_assert(tor_mem_is_zero(buf, 10));
  test_assert(tor_mem_is_zero(buf, 20));
  test_assert(tor_mem_is_zero(buf, 128));
  test_assert(!tor_mem_is_zero(buf, 129));
  buf[60] = (char)255;
  test_assert(!tor_mem_is_zero(buf, 128));
  buf[0] = (char)1;
  test_assert(!tor_mem_is_zero(buf, 10));

  /* Test 'escaped' */
  test_streq("\"\"", escaped(""));
  test_streq("\"abcd\"", escaped("abcd"));
  test_streq("\"\\\\\\n\\r\\t\\\"\\'\"", escaped("\\\n\r\t\"\'"));
  test_streq("\"z\\001abc\\277d\"", escaped("z\001abc\277d"));
  test_assert(NULL == escaped(NULL));

  /* Test strndup and memdup */
  {
    const char *s = "abcdefghijklmnopqrstuvwxyz";
    cp = tor_strndup(s, 30);
    test_streq(cp, s); /* same string, */
    test_neq(cp, s); /* but different pointers. */
    tor_free(cp);

    cp = tor_strndup(s, 5);
    test_streq(cp, "abcde");
    tor_free(cp);

    s = "a\0b\0c\0d\0e\0";
    cp = tor_memdup(s,10);
    test_memeq(cp, s, 10); /* same ram, */
    test_neq(cp, s); /* but different pointers. */
    tor_free(cp);
  }

  /* Test str-foo functions */
  cp = tor_strdup("abcdef");
  test_assert(tor_strisnonupper(cp));
  cp[3] = 'D';
  test_assert(!tor_strisnonupper(cp));
  tor_strupper(cp);
  test_streq(cp, "ABCDEF");
  test_assert(tor_strisprint(cp));
  cp[3] = 3;
  test_assert(!tor_strisprint(cp));
  tor_free(cp);

  /* Test eat_whitespace. */
  {
    const char *s = "  \n a";
    test_eq_ptr(eat_whitespace(s), s+4);
    s = "abcd";
    test_eq_ptr(eat_whitespace(s), s);
    s = "#xyz\nab";
    test_eq_ptr(eat_whitespace(s), s+5);
  }

  /* Test memmem and memstr */
  {
    const char *haystack = "abcde";
    tor_assert(!tor_memmem(haystack, 5, "ef", 2));
    test_eq_ptr(tor_memmem(haystack, 5, "cd", 2), haystack + 2);
    test_eq_ptr(tor_memmem(haystack, 5, "cde", 3), haystack + 2);
    haystack = "ababcad";
    test_eq_ptr(tor_memmem(haystack, 7, "abc", 3), haystack + 2);
    test_eq_ptr(tor_memstr(haystack, 7, "abc"), haystack + 2);
    test_assert(!tor_memstr(haystack, 7, "fe"));
    test_assert(!tor_memstr(haystack, 7, "longerthantheoriginal"));
  }

  /* Test wrap_string */
  {
    smartlist_t *sl = smartlist_create();
    wrap_string(sl, "This is a test of string wrapping functionality: woot.",
                10, "", "");
    cp = smartlist_join_strings(sl, "", 0, NULL);
    test_streq(cp,
            "This is a\ntest of\nstring\nwrapping\nfunctional\nity: woot.\n");
    tor_free(cp);
    SMARTLIST_FOREACH(sl, char *, cp, tor_free(cp));
    smartlist_clear(sl);

    wrap_string(sl, "This is a test of string wrapping functionality: woot.",
                16, "### ", "# ");
    cp = smartlist_join_strings(sl, "", 0, NULL);
    test_streq(cp,
             "### This is a\n# test of string\n# wrapping\n# functionality:\n"
             "# woot.\n");

    tor_free(cp);
    SMARTLIST_FOREACH(sl, char *, cp, tor_free(cp));
    smartlist_free(sl);
  }
 done:
  ;
}

static void
test_util_pow2(void)
{
  /* Test tor_log2(). */
  test_eq(tor_log2(64), 6);
  test_eq(tor_log2(65), 6);
  test_eq(tor_log2(63), 5);
  test_eq(tor_log2(1), 0);
  test_eq(tor_log2(2), 1);
  test_eq(tor_log2(3), 1);
  test_eq(tor_log2(4), 2);
  test_eq(tor_log2(5), 2);
  test_eq(tor_log2(U64_LITERAL(40000000000000000)), 55);
  test_eq(tor_log2(UINT64_MAX), 63);

  /* Test round_to_power_of_2 */
  test_eq(round_to_power_of_2(120), 128);
  test_eq(round_to_power_of_2(128), 128);
  test_eq(round_to_power_of_2(130), 128);
  test_eq(round_to_power_of_2(U64_LITERAL(40000000000000000)),
          U64_LITERAL(1)<<55);
  test_eq(round_to_power_of_2(0), 2);

 done:
  ;
}

/** mutex for thread test to stop the threads hitting data at the same time. */
static tor_mutex_t *_thread_test_mutex = NULL;
/** mutexes for the thread test to make sure that the threads have to
 * interleave somewhat. */
static tor_mutex_t *_thread_test_start1 = NULL,
                   *_thread_test_start2 = NULL;
/** Shared strmap for the thread test. */
static strmap_t *_thread_test_strmap = NULL;
/** The name of thread1 for the thread test */
static char *_thread1_name = NULL;
/** The name of thread2 for the thread test */
static char *_thread2_name = NULL;

static void _thread_test_func(void* _s) ATTR_NORETURN;

/** How many iterations have the threads in the unit test run? */
static int t1_count = 0, t2_count = 0;

/** Helper function for threading unit tests: This function runs in a
 * subthread. It grabs its own mutex (start1 or start2) to make sure that it
 * should start, then it repeatedly alters _test_thread_strmap protected by
 * _thread_test_mutex. */
static void
_thread_test_func(void* _s)
{
  char *s = _s;
  int i, *count;
  tor_mutex_t *m;
  char buf[64];
  char **cp;
  if (!strcmp(s, "thread 1")) {
    m = _thread_test_start1;
    cp = &_thread1_name;
    count = &t1_count;
  } else {
    m = _thread_test_start2;
    cp = &_thread2_name;
    count = &t2_count;
  }

  tor_snprintf(buf, sizeof(buf), "%lu", tor_get_thread_id());
  *cp = tor_strdup(buf);

  tor_mutex_acquire(m);

  for (i=0; i<10000; ++i) {
    tor_mutex_acquire(_thread_test_mutex);
    strmap_set(_thread_test_strmap, "last to run", *cp);
    ++*count;
    tor_mutex_release(_thread_test_mutex);
  }
  tor_mutex_acquire(_thread_test_mutex);
  strmap_set(_thread_test_strmap, s, *cp);
  tor_mutex_release(_thread_test_mutex);

  tor_mutex_release(m);

  spawn_exit();
}

/** Run unit tests for threading logic. */
static void
test_util_threads(void)
{
  char *s1 = NULL, *s2 = NULL;
  int done = 0, timedout = 0;
  time_t started;
#ifndef MS_WINDOWS
  struct timeval tv;
  tv.tv_sec=0;
  tv.tv_usec=10;
#endif
#ifndef TOR_IS_MULTITHREADED
  /* Skip this test if we aren't threading. We should be threading most
   * everywhere by now. */
  if (1)
    return;
#endif
  _thread_test_mutex = tor_mutex_new();
  _thread_test_start1 = tor_mutex_new();
  _thread_test_start2 = tor_mutex_new();
  _thread_test_strmap = strmap_new();
  s1 = tor_strdup("thread 1");
  s2 = tor_strdup("thread 2");
  tor_mutex_acquire(_thread_test_start1);
  tor_mutex_acquire(_thread_test_start2);
  spawn_func(_thread_test_func, s1);
  spawn_func(_thread_test_func, s2);
  tor_mutex_release(_thread_test_start2);
  tor_mutex_release(_thread_test_start1);
  started = time(NULL);
  while (!done) {
    tor_mutex_acquire(_thread_test_mutex);
    strmap_assert_ok(_thread_test_strmap);
    if (strmap_get(_thread_test_strmap, "thread 1") &&
        strmap_get(_thread_test_strmap, "thread 2")) {
      done = 1;
    } else if (time(NULL) > started + 25) {
      timedout = done = 1;
    }
    tor_mutex_release(_thread_test_mutex);
#ifndef MS_WINDOWS
    /* Prevent the main thread from starving the worker threads. */
    select(0, NULL, NULL, NULL, &tv);
#endif
  }
  tor_mutex_acquire(_thread_test_start1);
  tor_mutex_release(_thread_test_start1);
  tor_mutex_acquire(_thread_test_start2);
  tor_mutex_release(_thread_test_start2);

  tor_mutex_free(_thread_test_mutex);

  if (timedout) {
    printf("\nTimed out: %d %d", t1_count, t2_count);
    test_assert(strmap_get(_thread_test_strmap, "thread 1"));
    test_assert(strmap_get(_thread_test_strmap, "thread 2"));
    test_assert(!timedout);
  }

  /* different thread IDs. */
  test_assert(strcmp(strmap_get(_thread_test_strmap, "thread 1"),
                     strmap_get(_thread_test_strmap, "thread 2")));
  test_assert(!strcmp(strmap_get(_thread_test_strmap, "thread 1"),
                      strmap_get(_thread_test_strmap, "last to run")) ||
              !strcmp(strmap_get(_thread_test_strmap, "thread 2"),
                      strmap_get(_thread_test_strmap, "last to run")));

 done:
  tor_free(s1);
  tor_free(s2);
  tor_free(_thread1_name);
  tor_free(_thread2_name);
  if (_thread_test_strmap)
    strmap_free(_thread_test_strmap, NULL);
  if (_thread_test_start1)
    tor_mutex_free(_thread_test_start1);
  if (_thread_test_start2)
    tor_mutex_free(_thread_test_start2);
}

/** Run unit tests for compression functions */
static void
test_util_gzip(void)
{
  char *buf1=NULL, *buf2=NULL, *buf3=NULL, *cp1, *cp2;
  const char *ccp2;
  size_t len1, len2;
  tor_zlib_state_t *state = NULL;

  buf1 = tor_strdup("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZAAAAAAAAAAAAAAAAAAAZ");
  test_assert(detect_compression_method(buf1, strlen(buf1)) == UNKNOWN_METHOD);
  if (is_gzip_supported()) {
    test_assert(!tor_gzip_compress(&buf2, &len1, buf1, strlen(buf1)+1,
                                   GZIP_METHOD));
    test_assert(buf2);
    test_assert(!memcmp(buf2, "\037\213", 2)); /* Gzip magic. */
    test_assert(detect_compression_method(buf2, len1) == GZIP_METHOD);

    test_assert(!tor_gzip_uncompress(&buf3, &len2, buf2, len1,
                                     GZIP_METHOD, 1, LOG_INFO));
    test_assert(buf3);
    test_streq(buf1,buf3);

    tor_free(buf2);
    tor_free(buf3);
  }

  test_assert(!tor_gzip_compress(&buf2, &len1, buf1, strlen(buf1)+1,
                                 ZLIB_METHOD));
  test_assert(buf2);
  test_assert(!memcmp(buf2, "\x78\xDA", 2)); /* deflate magic. */
  test_assert(detect_compression_method(buf2, len1) == ZLIB_METHOD);

  test_assert(!tor_gzip_uncompress(&buf3, &len2, buf2, len1,
                                   ZLIB_METHOD, 1, LOG_INFO));
  test_assert(buf3);
  test_streq(buf1,buf3);

  /* Check whether we can uncompress concatenated, compressed strings. */
  tor_free(buf3);
  buf2 = tor_realloc(buf2, len1*2);
  memcpy(buf2+len1, buf2, len1);
  test_assert(!tor_gzip_uncompress(&buf3, &len2, buf2, len1*2,
                                   ZLIB_METHOD, 1, LOG_INFO));
  test_eq(len2, (strlen(buf1)+1)*2);
  test_memeq(buf3,
             "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZAAAAAAAAAAAAAAAAAAAZ\0"
             "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZAAAAAAAAAAAAAAAAAAAZ\0",
             (strlen(buf1)+1)*2);

  tor_free(buf1);
  tor_free(buf2);
  tor_free(buf3);

  /* Check whether we can uncompress partial strings. */
  buf1 =
    tor_strdup("String with low redundancy that won't be compressed much.");
  test_assert(!tor_gzip_compress(&buf2, &len1, buf1, strlen(buf1)+1,
                                 ZLIB_METHOD));
  tor_assert(len1>16);
  /* when we allow an incomplete string, we should succeed.*/
  tor_assert(!tor_gzip_uncompress(&buf3, &len2, buf2, len1-16,
                                  ZLIB_METHOD, 0, LOG_INFO));
  buf3[len2]='\0';
  tor_assert(len2 > 5);
  tor_assert(!strcmpstart(buf1, buf3));

  /* when we demand a complete string, this must fail. */
  tor_free(buf3);
  tor_assert(tor_gzip_uncompress(&buf3, &len2, buf2, len1-16,
                                 ZLIB_METHOD, 1, LOG_INFO));
  tor_assert(!buf3);

  /* Now, try streaming compression. */
  tor_free(buf1);
  tor_free(buf2);
  tor_free(buf3);
  state = tor_zlib_new(1, ZLIB_METHOD);
  tor_assert(state);
  cp1 = buf1 = tor_malloc(1024);
  len1 = 1024;
  ccp2 = "ABCDEFGHIJABCDEFGHIJ";
  len2 = 21;
  test_assert(tor_zlib_process(state, &cp1, &len1, &ccp2, &len2, 0)
              == TOR_ZLIB_OK);
  test_eq(len2, 0); /* Make sure we compressed it all. */
  test_assert(cp1 > buf1);

  len2 = 0;
  cp2 = cp1;
  test_assert(tor_zlib_process(state, &cp1, &len1, &ccp2, &len2, 1)
              == TOR_ZLIB_DONE);
  test_eq(len2, 0);
  test_assert(cp1 > cp2); /* Make sure we really added something. */

  tor_assert(!tor_gzip_uncompress(&buf3, &len2, buf1, 1024-len1,
                                  ZLIB_METHOD, 1, LOG_WARN));
  test_streq(buf3, "ABCDEFGHIJABCDEFGHIJ"); /*Make sure it compressed right.*/

 done:
  if (state)
    tor_zlib_free(state);
  tor_free(buf2);
  tor_free(buf3);
  tor_free(buf1);
}

/** Run unit tests for mmap() wrapper functionality. */
static void
test_util_mmap(void)
{
  char *fname1 = tor_strdup(get_fname("mapped_1"));
  char *fname2 = tor_strdup(get_fname("mapped_2"));
  char *fname3 = tor_strdup(get_fname("mapped_3"));
  const size_t buflen = 17000;
  char *buf = tor_malloc(17000);
  tor_mmap_t *mapping = NULL;

  crypto_rand(buf, buflen);

  mapping = tor_mmap_file(fname1);
  test_assert(! mapping);

  write_str_to_file(fname1, "Short file.", 1);
  write_bytes_to_file(fname2, buf, buflen, 1);
  write_bytes_to_file(fname3, buf, 16384, 1);

  mapping = tor_mmap_file(fname1);
  test_assert(mapping);
  test_eq(mapping->size, strlen("Short file."));
  test_streq(mapping->data, "Short file.");
#ifdef MS_WINDOWS
  tor_munmap_file(mapping);
  mapping = NULL;
  test_assert(unlink(fname1) == 0);
#else
  /* make sure we can unlink. */
  test_assert(unlink(fname1) == 0);
  test_streq(mapping->data, "Short file.");
  tor_munmap_file(mapping);
  mapping = NULL;
#endif

  /* Now a zero-length file. */
  write_str_to_file(fname1, "", 1);
  mapping = tor_mmap_file(fname1);
  test_eq(mapping, NULL);
  test_eq(ERANGE, errno);
  unlink(fname1);

  /* Make sure that we fail to map a no-longer-existent file. */
  mapping = tor_mmap_file(fname1);
  test_assert(mapping == NULL);

  /* Now try a big file that stretches across a few pages and isn't aligned */
  mapping = tor_mmap_file(fname2);
  test_assert(mapping);
  test_eq(mapping->size, buflen);
  test_memeq(mapping->data, buf, buflen);
  tor_munmap_file(mapping);
  mapping = NULL;

  /* Now try a big aligned file. */
  mapping = tor_mmap_file(fname3);
  test_assert(mapping);
  test_eq(mapping->size, 16384);
  test_memeq(mapping->data, buf, 16384);
  tor_munmap_file(mapping);
  mapping = NULL;

 done:
  unlink(fname1);
  unlink(fname2);
  unlink(fname3);

  tor_free(fname1);
  tor_free(fname2);
  tor_free(fname3);
  tor_free(buf);

  if (mapping)
    tor_munmap_file(mapping);
}

/** Run unit tests for escaping/unescaping data for use by controllers. */
static void
test_util_control_formats(void)
{
  char *out = NULL;
  const char *inp =
    "..This is a test\r\nof the emergency \nbroadcast\r\n..system.\r\nZ.\r\n";
  size_t sz;

  sz = read_escaped_data(inp, strlen(inp), &out);
  test_streq(out,
             ".This is a test\nof the emergency \nbroadcast\n.system.\nZ.\n");
  test_eq(sz, strlen(out));

 done:
  tor_free(out);
}

static void
test_util_sscanf(void)
{
  unsigned u1, u2, u3;
  char s1[10], s2[10], s3[10], ch;
  int r;

  r = tor_sscanf("hello world", "hello world"); /* String match: success */
  test_eq(r, 0);
  r = tor_sscanf("hello world 3", "hello worlb %u", &u1); /* String fail */
  test_eq(r, 0);
  r = tor_sscanf("12345", "%u", &u1); /* Simple number */
  test_eq(r, 1);
  test_eq(u1, 12345u);
  r = tor_sscanf("", "%u", &u1); /* absent number */
  test_eq(r, 0);
  r = tor_sscanf("A", "%u", &u1); /* bogus number */
  test_eq(r, 0);
  r = tor_sscanf("4294967295", "%u", &u1); /* UINT32_MAX should work. */
  test_eq(r, 1);
  test_eq(u1, 4294967295u);
  r = tor_sscanf("4294967296", "%u", &u1); /* Always say -1 at 32 bits. */
  test_eq(r, 0);
  r = tor_sscanf("123456", "%2u%u", &u1, &u2); /* Width */
  test_eq(r, 2);
  test_eq(u1, 12u);
  test_eq(u2, 3456u);
  r = tor_sscanf("!12:3:456", "!%2u:%2u:%3u", &u1, &u2, &u3); /* separators */
  test_eq(r, 3);
  test_eq(u1, 12u);
  test_eq(u2, 3u);
  test_eq(u3, 456u);
  r = tor_sscanf("12:3:045", "%2u:%2u:%3u", &u1, &u2, &u3); /* 0s */
  test_eq(r, 3);
  test_eq(u1, 12u);
  test_eq(u2, 3u);
  test_eq(u3, 45u);
  /* %u does not match space.*/
  r = tor_sscanf("12:3: 45", "%2u:%2u:%3u", &u1, &u2, &u3);
  test_eq(r, 2);
  /* %u does not match negative numbers. */
  r = tor_sscanf("12:3:-4", "%2u:%2u:%3u", &u1, &u2, &u3);
  test_eq(r, 2);
  /* Arbitrary amounts of 0-padding are okay */
  r = tor_sscanf("12:03:000000000000000099", "%2u:%2u:%u", &u1, &u2, &u3);
  test_eq(r, 3);
  test_eq(u1, 12u);
  test_eq(u2, 3u);
  test_eq(u3, 99u);

  /* %x should work. */
  r = tor_sscanf("1234 02aBcdEf", "%x %x", &u1, &u2);
  test_eq(r, 2);
  test_eq(u1, 0x1234);
  test_eq(u2, 0x2ABCDEF);
  /* Width works on %x */
  r = tor_sscanf("f00dcafe444", "%4x%4x%u", &u1, &u2, &u3);
  test_eq(r, 3);
  test_eq(u1, 0xf00d);
  test_eq(u2, 0xcafe);
  test_eq(u3, 444);

  r = tor_sscanf("99% fresh", "%3u%% fresh", &u1); /* percents are scannable.*/
  test_eq(r, 1);
  test_eq(u1, 99);

  r = tor_sscanf("hello", "%s", s1); /* %s needs a number. */
  test_eq(r, -1);

  r = tor_sscanf("hello", "%3s%7s", s1, s2); /* %s matches characters. */
  test_eq(r, 2);
  test_streq(s1, "hel");
  test_streq(s2, "lo");
  r = tor_sscanf("WD40", "%2s%u", s3, &u1); /* %s%u */
  test_eq(r, 2);
  test_streq(s3, "WD");
  test_eq(u1, 40);
  r = tor_sscanf("76trombones", "%6u%9s", &u1, s1); /* %u%s */
  test_eq(r, 2);
  test_eq(u1, 76);
  test_streq(s1, "trombones");
  r = tor_sscanf("hello world", "%9s %9s", s1, s2); /* %s doesn't eat space. */
  test_eq(r, 2);
  test_streq(s1, "hello");
  test_streq(s2, "world");
  r = tor_sscanf("hi", "%9s%9s%3s", s1, s2, s3); /* %s can be empty. */
  test_eq(r, 3);
  test_streq(s1, "hi");
  test_streq(s2, "");
  test_streq(s3, "");

  r = tor_sscanf("1.2.3", "%u.%u.%u%c", &u1, &u2, &u3, &ch);
  test_eq(r, 3);
  r = tor_sscanf("1.2.3 foobar", "%u.%u.%u%c", &u1, &u2, &u3, &ch);
  test_eq(r, 4);

 done:
  ;
}

/** Run unittests for memory pool allocator */
static void
test_util_mempool(void)
{
  mp_pool_t *pool = NULL;
  smartlist_t *allocated = NULL;
  int i;

  pool = mp_pool_new(1, 100);
  test_assert(pool);
  test_assert(pool->new_chunk_capacity >= 100);
  test_assert(pool->item_alloc_size >= sizeof(void*)+1);
  mp_pool_destroy(pool);
  pool = NULL;

  pool = mp_pool_new(241, 2500);
  test_assert(pool);
  test_assert(pool->new_chunk_capacity >= 10);
  test_assert(pool->item_alloc_size >= sizeof(void*)+241);
  test_eq(pool->item_alloc_size & 0x03, 0);
  test_assert(pool->new_chunk_capacity < 60);

  allocated = smartlist_create();
  for (i = 0; i < 20000; ++i) {
    if (smartlist_len(allocated) < 20 || crypto_rand_int(2)) {
      void *m = mp_pool_get(pool);
      memset(m, 0x09, 241);
      smartlist_add(allocated, m);
      //printf("%d: %p\n", i, m);
      //mp_pool_assert_ok(pool);
    } else {
      int idx = crypto_rand_int(smartlist_len(allocated));
      void *m = smartlist_get(allocated, idx);
      //printf("%d: free %p\n", i, m);
      smartlist_del(allocated, idx);
      mp_pool_release(m);
      //mp_pool_assert_ok(pool);
    }
    if (crypto_rand_int(777)==0)
      mp_pool_clean(pool, 1, 1);

    if (i % 777)
      mp_pool_assert_ok(pool);
  }

 done:
  if (allocated) {
    SMARTLIST_FOREACH(allocated, void *, m, mp_pool_release(m));
    mp_pool_assert_ok(pool);
    mp_pool_clean(pool, 0, 0);
    mp_pool_assert_ok(pool);
    smartlist_free(allocated);
  }

  if (pool)
    mp_pool_destroy(pool);
}

/** Run unittests for memory area allocator */
static void
test_util_memarea(void)
{
  memarea_t *area = memarea_new();
  char *p1, *p2, *p3, *p1_orig;
  void *malloced_ptr = NULL;
  int i;

  test_assert(area);

  p1_orig = p1 = memarea_alloc(area,64);
  p2 = memarea_alloc_zero(area,52);
  p3 = memarea_alloc(area,11);

  test_assert(memarea_owns_ptr(area, p1));
  test_assert(memarea_owns_ptr(area, p2));
  test_assert(memarea_owns_ptr(area, p3));
  /* Make sure we left enough space. */
  test_assert(p1+64 <= p2);
  test_assert(p2+52 <= p3);
  /* Make sure we aligned. */
  test_eq(((uintptr_t)p1) % sizeof(void*), 0);
  test_eq(((uintptr_t)p2) % sizeof(void*), 0);
  test_eq(((uintptr_t)p3) % sizeof(void*), 0);
  test_assert(!memarea_owns_ptr(area, p3+8192));
  test_assert(!memarea_owns_ptr(area, p3+30));
  test_assert(tor_mem_is_zero(p2, 52));
  /* Make sure we don't overalign. */
  p1 = memarea_alloc(area, 1);
  p2 = memarea_alloc(area, 1);
  test_eq(p1+sizeof(void*), p2);
  {
    malloced_ptr = tor_malloc(64);
    test_assert(!memarea_owns_ptr(area, malloced_ptr));
    tor_free(malloced_ptr);
  }

  /* memarea_memdup */
  {
    malloced_ptr = tor_malloc(64);
    crypto_rand((char*)malloced_ptr, 64);
    p1 = memarea_memdup(area, malloced_ptr, 64);
    test_assert(p1 != malloced_ptr);
    test_memeq(p1, malloced_ptr, 64);
    tor_free(malloced_ptr);
  }

  /* memarea_strdup. */
  p1 = memarea_strdup(area,"");
  p2 = memarea_strdup(area, "abcd");
  test_assert(p1);
  test_assert(p2);
  test_streq(p1, "");
  test_streq(p2, "abcd");

  /* memarea_strndup. */
  {
    const char *s = "Ad ogni porta batte la morte e grida: il nome!";
    /* (From Turandot, act 3.) */
    size_t len = strlen(s);
    p1 = memarea_strndup(area, s, 1000);
    p2 = memarea_strndup(area, s, 10);
    test_streq(p1, s);
    test_assert(p2 >= p1 + len + 1);
    test_memeq(s, p2, 10);
    test_eq(p2[10], '\0');
    p3 = memarea_strndup(area, s, len);
    test_streq(p3, s);
    p3 = memarea_strndup(area, s, len-1);
    test_memeq(s, p3, len-1);
    test_eq(p3[len-1], '\0');
  }

  memarea_clear(area);
  p1 = memarea_alloc(area, 1);
  test_eq(p1, p1_orig);
  memarea_clear(area);

  /* Check for running over an area's size. */
  for (i = 0; i < 512; ++i) {
    p1 = memarea_alloc(area, crypto_rand_int(5)+1);
    test_assert(memarea_owns_ptr(area, p1));
  }
  memarea_assert_ok(area);
  /* Make sure we can allocate a too-big object. */
  p1 = memarea_alloc_zero(area, 9000);
  p2 = memarea_alloc_zero(area, 16);
  test_assert(memarea_owns_ptr(area, p1));
  test_assert(memarea_owns_ptr(area, p2));

 done:
  memarea_drop_all(area);
  tor_free(malloced_ptr);
}

/** Run unit tests for utility functions to get file names relative to
 * the data directory. */
static void
test_util_datadir(void)
{
  char buf[1024];
  char *f = NULL;
  char *temp_dir = NULL;

  temp_dir = get_datadir_fname(NULL);
  f = get_datadir_fname("state");
  tor_snprintf(buf, sizeof(buf), "%s"PATH_SEPARATOR"state", temp_dir);
  test_streq(f, buf);
  tor_free(f);
  f = get_datadir_fname2("cache", "thingy");
  tor_snprintf(buf, sizeof(buf),
               "%s"PATH_SEPARATOR"cache"PATH_SEPARATOR"thingy", temp_dir);
  test_streq(f, buf);
  tor_free(f);
  f = get_datadir_fname2_suffix("cache", "thingy", ".foo");
  tor_snprintf(buf, sizeof(buf),
               "%s"PATH_SEPARATOR"cache"PATH_SEPARATOR"thingy.foo", temp_dir);
  test_streq(f, buf);
  tor_free(f);
  f = get_datadir_fname_suffix("cache", ".foo");
  tor_snprintf(buf, sizeof(buf), "%s"PATH_SEPARATOR"cache.foo",
               temp_dir);
  test_streq(f, buf);

 done:
  tor_free(f);
  tor_free(temp_dir);
}

static void
test_util_strtok(void)
{
  char buf[128];
  char buf2[128];
  char *cp1, *cp2;
  strlcpy(buf, "Graved on the dark in gestures of descent", sizeof(buf));
  strlcpy(buf2, "they.seemed;their!own;most.perfect;monument", sizeof(buf2));
  /*  -- "Year's End", Richard Wilbur */

  test_streq("Graved", tor_strtok_r_impl(buf, " ", &cp1));
  test_streq("they", tor_strtok_r_impl(buf2, ".!..;!", &cp2));
#define S1() tor_strtok_r_impl(NULL, " ", &cp1)
#define S2() tor_strtok_r_impl(NULL, ".!..;!", &cp2)
  test_streq("on", S1());
  test_streq("the", S1());
  test_streq("dark", S1());
  test_streq("seemed", S2());
  test_streq("their", S2());
  test_streq("own", S2());
  test_streq("in", S1());
  test_streq("gestures", S1());
  test_streq("of", S1());
  test_streq("most", S2());
  test_streq("perfect", S2());
  test_streq("descent", S1());
  test_streq("monument", S2());
  test_assert(NULL == S1());
  test_assert(NULL == S2());
 done:
  ;
}

static void
test_util_find_str_at_start_of_line(void *ptr)
{
  const char *long_string =
    "hello world. hello world. hello hello. howdy.\n"
    "hello hello world\n";

  (void)ptr;

  /* not-found case. */
  tt_assert(! find_str_at_start_of_line(long_string, "fred"));

  /* not-found case where haystack doesn't end with \n */
  tt_assert(! find_str_at_start_of_line("foobar\nbaz", "fred"));

  /* start-of-string case */
  tt_assert(long_string ==
            find_str_at_start_of_line(long_string, "hello world."));

  /* start-of-line case */
  tt_assert(strchr(long_string,'\n')+1 ==
            find_str_at_start_of_line(long_string, "hello hello"));
 done:
  ;
}

static void
test_util_asprintf(void *ptr)
{
#define LOREMIPSUM                                              \
  "Lorem ipsum dolor sit amet, consectetur adipisicing elit"
  char *cp=NULL, *cp2=NULL;
  int r;
  (void)ptr;

  /* empty string. */
  r = tor_asprintf(&cp, "%s", "");
  tt_assert(cp);
  tt_int_op(r, ==, strlen(cp));
  tt_str_op(cp, ==, "");

  /* Short string with some printing in it. */
  r = tor_asprintf(&cp2, "First=%d, Second=%d", 101, 202);
  tt_assert(cp2);
  tt_int_op(r, ==, strlen(cp2));
  tt_str_op(cp2, ==, "First=101, Second=202");
  tt_assert(cp != cp2);
  tor_free(cp);
  tor_free(cp2);

  /* Glass-box test: a string exactly 128 characters long. */
  r = tor_asprintf(&cp, "Lorem1: %sLorem2: %s", LOREMIPSUM, LOREMIPSUM);
  tt_assert(cp);
  tt_int_op(r, ==, 128);
  tt_assert(cp[128] == '\0');
  tt_str_op(cp, ==,
            "Lorem1: "LOREMIPSUM"Lorem2: "LOREMIPSUM);
  tor_free(cp);

  /* String longer than 128 characters */
  r = tor_asprintf(&cp, "1: %s 2: %s 3: %s",
                   LOREMIPSUM, LOREMIPSUM, LOREMIPSUM);
  tt_assert(cp);
  tt_int_op(r, ==, strlen(cp));
  tt_str_op(cp, ==, "1: "LOREMIPSUM" 2: "LOREMIPSUM" 3: "LOREMIPSUM);

 done:
  tor_free(cp);
  tor_free(cp2);
}

static void
test_util_listdir(void *ptr)
{
  smartlist_t *dir_contents = NULL;
  char *fname1=NULL, *fname2=NULL, *dirname=NULL;
  (void)ptr;

  fname1 = tor_strdup(get_fname("hopscotch"));
  fname2 = tor_strdup(get_fname("mumblety-peg"));
  dirname = tor_strdup(get_fname(NULL));

  tt_int_op(write_str_to_file(fname1, "X\n", 0), ==, 0);
  tt_int_op(write_str_to_file(fname2, "Y\n", 0), ==, 0);

  dir_contents = tor_listdir(dirname);
  tt_assert(dir_contents);
  /* make sure that each filename is listed. */
  tt_assert(smartlist_string_isin_case(dir_contents, "hopscotch"));
  tt_assert(smartlist_string_isin_case(dir_contents, "mumblety-peg"));

  tt_assert(!smartlist_string_isin(dir_contents, "."));
  tt_assert(!smartlist_string_isin(dir_contents, ".."));

 done:
  tor_free(fname1);
  tor_free(fname2);
  tor_free(dirname);
  if (dir_contents) {
    SMARTLIST_FOREACH(dir_contents, char *, cp, tor_free(cp));
    smartlist_free(dir_contents);
  }
}

#ifdef MS_WINDOWS
static void
test_util_load_win_lib(void *ptr)
{
  HANDLE h = load_windows_system_library("advapi32.dll");

  tt_assert(h);
 done:
  if (h)
    CloseHandle(h);
}
#endif

static void
clear_hex_errno(char *hex_errno)
{
  memset(hex_errno, '\0', HEX_ERRNO_SIZE + 1);
}

static void
test_util_exit_status(void *ptr)
{
  /* Leave an extra byte for a \0 so we can do string comparison */
  char hex_errno[HEX_ERRNO_SIZE + 1];

  (void)ptr;

  clear_hex_errno(hex_errno);
  format_helper_exit_status(0, 0, hex_errno);
  tt_str_op(hex_errno, ==, "         0/0\n");

  clear_hex_errno(hex_errno);
  format_helper_exit_status(0, 0x7FFFFFFF, hex_errno);
  tt_str_op(hex_errno, ==, "  0/7FFFFFFF\n");

  clear_hex_errno(hex_errno);
  format_helper_exit_status(0xFF, -0x80000000, hex_errno);
  tt_str_op(hex_errno, ==, "FF/-80000000\n");

  clear_hex_errno(hex_errno);
  format_helper_exit_status(0x7F, 0, hex_errno);
  tt_str_op(hex_errno, ==, "        7F/0\n");

  clear_hex_errno(hex_errno);
  format_helper_exit_status(0x08, -0x242, hex_errno);
  tt_str_op(hex_errno, ==, "      8/-242\n");

 done:
  ;
}

#ifndef MS_WINDOWS
/** Check that fgets waits until a full line, and not return a partial line, on
 * a EAGAIN with a non-blocking pipe */
static void
test_util_fgets_eagain(void *ptr)
{
  int test_pipe[2] = {-1, -1};
  int retval;
  ssize_t retlen;
  char *retptr;
  FILE *test_stream = NULL;
  char buf[10];

  (void)ptr;

  /* Set up a pipe to test on */
  retval = pipe(test_pipe);
  tt_int_op(retval, >=, 0);

  /* Set up the read-end to be non-blocking */
  retval = fcntl(test_pipe[0], F_SETFL, O_NONBLOCK);
  tt_int_op(retval, >=, 0);

  /* Open it as a stdio stream */
  test_stream = fdopen(test_pipe[0], "r");
  tt_ptr_op(test_stream, !=, NULL);

  /* Send in a partial line */
  retlen = write(test_pipe[1], "A", 1);
  tt_int_op(retlen, ==, 1);
  retptr = fgets(buf, sizeof(buf), test_stream);
  tt_want(retptr == NULL);
  tt_int_op(errno, ==, EAGAIN);

  /* Send in the rest */
  retlen = write(test_pipe[1], "B\n", 2);
  tt_int_op(retlen, ==, 2);
  retptr = fgets(buf, sizeof(buf), test_stream);
  tt_ptr_op(retptr, ==, buf);
  tt_str_op(buf, ==, "AB\n");

  /* Send in a full line */
  retlen = write(test_pipe[1], "CD\n", 3);
  tt_int_op(retlen, ==, 3);
  retptr = fgets(buf, sizeof(buf), test_stream);
  tt_ptr_op(retptr, ==, buf);
  tt_str_op(buf, ==, "CD\n");

  /* Send in a partial line */
  retlen = write(test_pipe[1], "E", 1);
  tt_int_op(retlen, ==, 1);
  retptr = fgets(buf, sizeof(buf), test_stream);
  tt_ptr_op(retptr, ==, NULL);
  tt_int_op(errno, ==, EAGAIN);

  /* Send in the rest */
  retlen = write(test_pipe[1], "F\n", 2);
  tt_int_op(retlen, ==, 2);
  retptr = fgets(buf, sizeof(buf), test_stream);
  tt_ptr_op(retptr, ==, buf);
  tt_str_op(buf, ==, "EF\n");

  /* Send in a full line and close */
  retlen = write(test_pipe[1], "GH", 2);
  tt_int_op(retlen, ==, 2);
  retval = close(test_pipe[1]);
  test_pipe[1] = -1;
  tt_int_op(retval, ==, 0);
  retptr = fgets(buf, sizeof(buf), test_stream);
  tt_ptr_op(retptr, ==, buf);
  tt_str_op(buf, ==, "GH");

  /* Check for EOF */
  retptr = fgets(buf, sizeof(buf), test_stream);
  tt_ptr_op(retptr, ==, NULL);
  tt_int_op(feof(test_stream), >, 0);

 done:
  if (test_stream != NULL)
    fclose(test_stream);
  if (test_pipe[0] != -1)
    close(test_pipe[0]);
  if (test_pipe[1] != -1)
    close(test_pipe[1]);
}
#endif

#ifndef MS_WINDOWS
/** Helper function for testing tor_spawn_background */
static void
run_util_spawn_background(const char *argv[], const char *expected_out,
                          const char *expected_err, int expected_exit)
{
  int stdout_pipe=-1, stderr_pipe=-1;
  int retval, stat_loc;
  pid_t pid;
  ssize_t pos;
  char stdout_buf[100], stderr_buf[100];

  /* Start the program */
  retval = tor_spawn_background(argv[0], &stdout_pipe, &stderr_pipe, argv);
  tt_int_op(retval, >, 0);
  tt_int_op(stdout_pipe, >, 0);
  tt_int_op(stderr_pipe, >, 0);
  pid = retval;

  /* Check stdout */
  pos = read(stdout_pipe, stdout_buf, sizeof(stdout_buf) - 1);
  stdout_buf[pos] = '\0';
  tt_int_op(pos, ==, strlen(expected_out));
  tt_str_op(stdout_buf, ==, expected_out);

  /* Check it terminated correctly */
  retval = waitpid(pid, &stat_loc, 0);
  tt_int_op(retval, ==, pid);
  tt_assert(WIFEXITED(stat_loc));
  tt_int_op(WEXITSTATUS(stat_loc), ==, expected_exit);
  tt_assert(!WIFSIGNALED(stat_loc));
  tt_assert(!WIFSTOPPED(stat_loc));

  /* Check stderr */
  pos = read(stderr_pipe, stderr_buf, sizeof(stderr_buf) - 1);
  stderr_buf[pos] = '\0';
  tt_int_op(pos, ==, strlen(expected_err));
  tt_str_op(stderr_buf, ==, expected_err);

 done:
  ;
}

/** Check that we can launch a process and read the output */
static void
test_util_spawn_background_ok(void *ptr)
{
  const char *argv[] = {BUILDDIR "/src/test/test-child", "--test", NULL};
  const char *expected_out = "OUT\n--test\nDONE\n";
  const char *expected_err = "ERR\n";

  (void)ptr;

  run_util_spawn_background(argv, expected_out, expected_err, 0);
}

/** Check that failing to find the executable works as expected */
static void
test_util_spawn_background_fail(void *ptr)
{
  const char *argv[] = {BUILDDIR "/src/test/no-such-file", "--test", NULL};
  const char *expected_out = "ERR: Failed to spawn background process "
                             "- code          9/2\n";
  const char *expected_err = "";

  (void)ptr;

  run_util_spawn_background(argv, expected_out, expected_err, 255);
}
#endif

#define UTIL_LEGACY(name)                                               \
  { #name, legacy_test_helper, 0, &legacy_setup, test_util_ ## name }

#define UTIL_TEST(name, flags)                          \
  { #name, test_util_ ## name, flags, NULL, NULL }

struct testcase_t util_tests[] = {
  UTIL_LEGACY(time),
  UTIL_LEGACY(config_line),
  UTIL_LEGACY(strmisc),
  UTIL_LEGACY(pow2),
  UTIL_LEGACY(gzip),
  UTIL_LEGACY(datadir),
  UTIL_LEGACY(mempool),
  UTIL_LEGACY(memarea),
  UTIL_LEGACY(control_formats),
  UTIL_LEGACY(mmap),
  UTIL_LEGACY(threads),
  UTIL_LEGACY(sscanf),
  UTIL_LEGACY(strtok),
  UTIL_TEST(find_str_at_start_of_line, 0),
  UTIL_TEST(asprintf, 0),
  UTIL_TEST(listdir, 0),
#ifdef MS_WINDOWS
  UTIL_TEST(load_win_lib, 0),
#endif
  UTIL_TEST(exit_status, 0),
#ifndef MS_WINDOWS
  UTIL_TEST(fgets_eagain, TT_SKIP),
  UTIL_TEST(spawn_background_ok, 0),
  UTIL_TEST(spawn_background_fail, 0),
#endif
  END_OF_TESTCASES
};

