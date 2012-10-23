/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/* Ordinarily defined in tor_main.c; this bit is just here to provide one
 * since we're not linking to tor_main.c */
const char tor_git_revision[] = "";

/**
 * \file test.c
 * \brief Unit tests for many pieces of the lower level Tor modules.
 **/

#include "orconfig.h"

#include <stdio.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef _WIN32
/* For mkdir() */
#include <direct.h>
#else
#include <dirent.h>
#endif

/* These macros pull in declarations for some functions and structures that
 * are typically file-private. */
#define BUFFERS_PRIVATE
#define CONFIG_PRIVATE
#define GEOIP_PRIVATE
#define ROUTER_PRIVATE
#define CIRCUITSTATS_PRIVATE

/*
 * Linux doesn't provide lround in math.h by default, but mac os does...
 * It's best just to leave math.h out of the picture entirely.
 */
//#include <math.h>
long int lround(double x);
double fabs(double x);

#include "or.h"
#include "buffers.h"
#include "circuitstats.h"
#include "config.h"
#include "connection_edge.h"
#include "geoip.h"
#include "rendcommon.h"
#include "test.h"
#include "torgzip.h"
#include "mempool.h"
#include "memarea.h"
#include "onion.h"
#include "policies.h"
#include "rephist.h"
#include "routerparse.h"

#ifdef USE_DMALLOC
#include <dmalloc.h>
#include <openssl/crypto.h>
#include "main.h"
#endif

/** Set to true if any unit test has failed.  Mostly, this is set by the macros
 * in test.h */
int have_failed = 0;

/** Temporary directory (set up by setup_directory) under which we store all
 * our files during testing. */
static char temp_dir[256];
#ifdef _WIN32
#define pid_t int
#endif
static pid_t temp_dir_setup_in_pid = 0;

/** Select and create the temporary directory we'll use to run our unit tests.
 * Store it in <b>temp_dir</b>.  Exit immediately if we can't create it.
 * idempotent. */
static void
setup_directory(void)
{
  static int is_setup = 0;
  int r;
  if (is_setup) return;

#ifdef _WIN32
  {
    char buf[MAX_PATH];
    const char *tmp = buf;
    /* If this fails, we're probably screwed anyway */
    if (!GetTempPathA(sizeof(buf),buf))
      tmp = "c:\\windows\\temp";
    tor_snprintf(temp_dir, sizeof(temp_dir),
                 "%s\\tor_test_%d", tmp, (int)getpid());
    r = mkdir(temp_dir);
  }
#else
  tor_snprintf(temp_dir, sizeof(temp_dir), "/tmp/tor_test_%d", (int) getpid());
  r = mkdir(temp_dir, 0700);
#endif
  if (r) {
    fprintf(stderr, "Can't create directory %s:", temp_dir);
    perror("");
    exit(1);
  }
  is_setup = 1;
  temp_dir_setup_in_pid = getpid();
}

/** Return a filename relative to our testing temporary directory */
const char *
get_fname(const char *name)
{
  static char buf[1024];
  setup_directory();
  if (!name)
    return temp_dir;
  tor_snprintf(buf,sizeof(buf),"%s/%s",temp_dir,name);
  return buf;
}

/* Remove a directory and all of its subdirectories */
static void
rm_rf(const char *dir)
{
  struct stat st;
  smartlist_t *elements;

  elements = tor_listdir(dir);
  if (elements) {
    SMARTLIST_FOREACH_BEGIN(elements, const char *, cp) {
         char *tmp = NULL;
         tor_asprintf(&tmp, "%s"PATH_SEPARATOR"%s", dir, cp);
         if (0 == stat(tmp,&st) && (st.st_mode & S_IFDIR)) {
           rm_rf(tmp);
         } else {
           if (unlink(tmp)) {
             fprintf(stderr, "Error removing %s: %s\n", tmp, strerror(errno));
           }
         }
         tor_free(tmp);
    } SMARTLIST_FOREACH_END(cp);
    SMARTLIST_FOREACH(elements, char *, cp, tor_free(cp));
    smartlist_free(elements);
  }
  if (rmdir(dir))
    fprintf(stderr, "Error removing directory %s: %s\n", dir, strerror(errno));
}

/** Remove all files stored under the temporary directory, and the directory
 * itself.  Called by atexit(). */
static void
remove_directory(void)
{
  if (getpid() != temp_dir_setup_in_pid) {
    /* Only clean out the tempdir when the main process is exiting. */
    return;
  }

  rm_rf(temp_dir);
}

/** Define this if unit tests spend too much time generating public keys*/
#undef CACHE_GENERATED_KEYS

static crypto_pk_t *pregen_keys[5] = {NULL, NULL, NULL, NULL, NULL};
#define N_PREGEN_KEYS ((int)(sizeof(pregen_keys)/sizeof(pregen_keys[0])))

/** Generate and return a new keypair for use in unit tests.  If we're using
 * the key cache optimization, we might reuse keys: we only guarantee that
 * keys made with distinct values for <b>idx</b> are different.  The value of
 * <b>idx</b> must be at least 0, and less than N_PREGEN_KEYS. */
crypto_pk_t *
pk_generate(int idx)
{
#ifdef CACHE_GENERATED_KEYS
  tor_assert(idx < N_PREGEN_KEYS);
  if (! pregen_keys[idx]) {
    pregen_keys[idx] = crypto_pk_new();
    tor_assert(!crypto_pk_generate_key(pregen_keys[idx]));
  }
  return crypto_pk_dup_key(pregen_keys[idx]);
#else
  crypto_pk_t *result;
  (void) idx;
  result = crypto_pk_new();
  tor_assert(!crypto_pk_generate_key(result));
  return result;
#endif
}

/** Free all storage used for the cached key optimization. */
static void
free_pregenerated_keys(void)
{
  unsigned idx;
  for (idx = 0; idx < N_PREGEN_KEYS; ++idx) {
    if (pregen_keys[idx]) {
      crypto_pk_free(pregen_keys[idx]);
      pregen_keys[idx] = NULL;
    }
  }
}

typedef struct socks_test_data_t {
  socks_request_t *req;
  buf_t *buf;
} socks_test_data_t;

static void *
socks_test_setup(const struct testcase_t *testcase)
{
  socks_test_data_t *data = tor_malloc(sizeof(socks_test_data_t));
  (void)testcase;
  data->buf = buf_new_with_capacity(256);
  data->req = socks_request_new();
  config_register_addressmaps(get_options());
  return data;
}
static int
socks_test_cleanup(const struct testcase_t *testcase, void *ptr)
{
  socks_test_data_t *data = ptr;
  (void)testcase;
  buf_free(data->buf);
  socks_request_free(data->req);
  tor_free(data);
  return 1;
}

const struct testcase_setup_t socks_setup = {
  socks_test_setup, socks_test_cleanup
};

#define SOCKS_TEST_INIT()                       \
  socks_test_data_t *testdata = ptr;            \
  buf_t *buf = testdata->buf;                   \
  socks_request_t *socks = testdata->req;
#define ADD_DATA(buf, s)                                        \
  write_to_buf(s, sizeof(s)-1, buf)

static void
socks_request_clear(socks_request_t *socks)
{
  tor_free(socks->username);
  tor_free(socks->password);
  memset(socks, 0, sizeof(socks_request_t));
}

/** Perform unsupported SOCKS 4 commands */
static void
test_socks_4_unsupported_commands(void *ptr)
{
  SOCKS_TEST_INIT();

  /* SOCKS 4 Send BIND [02] to IP address 2.2.2.2:4369 */
  ADD_DATA(buf, "\x04\x02\x11\x11\x02\x02\x02\x02\x00");
  test_assert(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                   get_options()->SafeSocks) == -1);
  test_eq(4, socks->socks_version);
  test_eq(0, socks->replylen); /* XXX: shouldn't tor reply? */

 done:
  ;
}

/** Perform supported SOCKS 4 commands */
static void
test_socks_4_supported_commands(void *ptr)
{
  SOCKS_TEST_INIT();

  test_eq(0, buf_datalen(buf));

  /* SOCKS 4 Send CONNECT [01] to IP address 2.2.2.2:4370 */
  ADD_DATA(buf, "\x04\x01\x11\x12\x02\x02\x02\x03\x00");
  test_assert(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                   get_options()->SafeSocks) == 1);
  test_eq(4, socks->socks_version);
  test_eq(0, socks->replylen); /* XXX: shouldn't tor reply? */
  test_eq(SOCKS_COMMAND_CONNECT, socks->command);
  test_streq("2.2.2.3", socks->address);
  test_eq(4370, socks->port);
  test_assert(socks->got_auth == 0);
  test_assert(! socks->username);

  test_eq(0, buf_datalen(buf));
  socks_request_clear(socks);

  /* SOCKS 4 Send CONNECT [01] to IP address 2.2.2.2:4369 with userid*/
  ADD_DATA(buf, "\x04\x01\x11\x12\x02\x02\x02\x04me\x00");
  test_assert(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                   get_options()->SafeSocks) == 1);
  test_eq(4, socks->socks_version);
  test_eq(0, socks->replylen); /* XXX: shouldn't tor reply? */
  test_eq(SOCKS_COMMAND_CONNECT, socks->command);
  test_streq("2.2.2.4", socks->address);
  test_eq(4370, socks->port);
  test_assert(socks->got_auth == 1);
  test_assert(socks->username);
  test_eq(2, socks->usernamelen);
  test_memeq("me", socks->username, 2);

  test_eq(0, buf_datalen(buf));
  socks_request_clear(socks);

  /* SOCKS 4a Send RESOLVE [F0] request for torproject.org */
  ADD_DATA(buf, "\x04\xF0\x01\x01\x00\x00\x00\x02me\x00torproject.org\x00");
  test_assert(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                   get_options()->SafeSocks) == 1);
  test_eq(4, socks->socks_version);
  test_eq(0, socks->replylen); /* XXX: shouldn't tor reply? */
  test_streq("torproject.org", socks->address);

  test_eq(0, buf_datalen(buf));

 done:
  ;
}

/**  Perform unsupported SOCKS 5 commands */
static void
test_socks_5_unsupported_commands(void *ptr)
{
  SOCKS_TEST_INIT();

  /* SOCKS 5 Send unsupported BIND [02] command */
  ADD_DATA(buf, "\x05\x02\x00\x01");

  test_eq(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                               get_options()->SafeSocks), 0);
  test_eq(0, buf_datalen(buf));
  test_eq(5, socks->socks_version);
  test_eq(2, socks->replylen);
  test_eq(5, socks->reply[0]);
  test_eq(0, socks->reply[1]);
  ADD_DATA(buf, "\x05\x02\x00\x01\x02\x02\x02\x01\x01\x01");
  test_eq(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                               get_options()->SafeSocks), -1);
  /* XXX: shouldn't tor reply 'command not supported' [07]? */

  buf_clear(buf);
  socks_request_clear(socks);

  /* SOCKS 5 Send unsupported UDP_ASSOCIATE [03] command */
  ADD_DATA(buf, "\x05\x03\x00\x01\x02");
  test_eq(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                               get_options()->SafeSocks), 0);
  test_eq(5, socks->socks_version);
  test_eq(2, socks->replylen);
  test_eq(5, socks->reply[0]);
  test_eq(0, socks->reply[1]);
  ADD_DATA(buf, "\x05\x03\x00\x01\x02\x02\x02\x01\x01\x01");
  test_eq(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                               get_options()->SafeSocks), -1);
  /* XXX: shouldn't tor reply 'command not supported' [07]? */

 done:
  ;
}

/** Perform supported SOCKS 5 commands */
static void
test_socks_5_supported_commands(void *ptr)
{
  SOCKS_TEST_INIT();

  /* SOCKS 5 Send CONNECT [01] to IP address 2.2.2.2:4369 */
  ADD_DATA(buf, "\x05\x01\x00");
  test_eq(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                   get_options()->SafeSocks), 0);
  test_eq(5, socks->socks_version);
  test_eq(2, socks->replylen);
  test_eq(5, socks->reply[0]);
  test_eq(0, socks->reply[1]);

  ADD_DATA(buf, "\x05\x01\x00\x01\x02\x02\x02\x02\x11\x11");
  test_eq(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                   get_options()->SafeSocks), 1);
  test_streq("2.2.2.2", socks->address);
  test_eq(4369, socks->port);

  test_eq(0, buf_datalen(buf));
  socks_request_clear(socks);

  /* SOCKS 5 Send CONNECT [01] to FQDN torproject.org:4369 */
  ADD_DATA(buf, "\x05\x01\x00");
  ADD_DATA(buf, "\x05\x01\x00\x03\x0Etorproject.org\x11\x11");
  test_eq(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                   get_options()->SafeSocks), 1);

  test_eq(5, socks->socks_version);
  test_eq(2, socks->replylen);
  test_eq(5, socks->reply[0]);
  test_eq(0, socks->reply[1]);
  test_streq("torproject.org", socks->address);
  test_eq(4369, socks->port);

  test_eq(0, buf_datalen(buf));
  socks_request_clear(socks);

  /* SOCKS 5 Send RESOLVE [F0] request for torproject.org:4369 */
  ADD_DATA(buf, "\x05\x01\x00");
  ADD_DATA(buf, "\x05\xF0\x00\x03\x0Etorproject.org\x01\x02");
  test_assert(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                   get_options()->SafeSocks) == 1);
  test_eq(5, socks->socks_version);
  test_eq(2, socks->replylen);
  test_eq(5, socks->reply[0]);
  test_eq(0, socks->reply[1]);
  test_streq("torproject.org", socks->address);

  test_eq(0, buf_datalen(buf));
  socks_request_clear(socks);

  /* SOCKS 5 Send RESOLVE_PTR [F1] for IP address 2.2.2.5 */
  ADD_DATA(buf, "\x05\x01\x00");
  ADD_DATA(buf, "\x05\xF1\x00\x01\x02\x02\x02\x05\x01\x03");
  test_assert(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                   get_options()->SafeSocks) == 1);
  test_eq(5, socks->socks_version);
  test_eq(2, socks->replylen);
  test_eq(5, socks->reply[0]);
  test_eq(0, socks->reply[1]);
  test_streq("2.2.2.5", socks->address);

  test_eq(0, buf_datalen(buf));

 done:
  ;
}

/**  Perform SOCKS 5 authentication */
static void
test_socks_5_no_authenticate(void *ptr)
{
  SOCKS_TEST_INIT();

  /*SOCKS 5 No Authentication */
  ADD_DATA(buf,"\x05\x01\x00");
  test_assert(!fetch_from_buf_socks(buf, socks,
                                    get_options()->TestSocks,
                                    get_options()->SafeSocks));
  test_eq(2, socks->replylen);
  test_eq(5, socks->reply[0]);
  test_eq(SOCKS_NO_AUTH, socks->reply[1]);

  test_eq(0, buf_datalen(buf));

  /*SOCKS 5 Send username/password anyway - pretend to be broken */
  ADD_DATA(buf,"\x01\x02\x01\x01\x02\x01\x01");
  test_assert(!fetch_from_buf_socks(buf, socks,
                                    get_options()->TestSocks,
                                    get_options()->SafeSocks));
  test_eq(5, socks->socks_version);
  test_eq(2, socks->replylen);
  test_eq(5, socks->reply[0]);
  test_eq(0, socks->reply[1]);

  test_eq(2, socks->usernamelen);
  test_eq(2, socks->passwordlen);

  test_memeq("\x01\x01", socks->username, 2);
  test_memeq("\x01\x01", socks->password, 2);

 done:
  ;
}

/** Perform SOCKS 5 authentication */
static void
test_socks_5_authenticate(void *ptr)
{
  SOCKS_TEST_INIT();

  /* SOCKS 5 Negotiate username/password authentication */
  ADD_DATA(buf, "\x05\x01\x02");

  test_assert(!fetch_from_buf_socks(buf, socks,
                                   get_options()->TestSocks,
                                   get_options()->SafeSocks));
  test_eq(2, socks->replylen);
  test_eq(5, socks->reply[0]);
  test_eq(SOCKS_USER_PASS, socks->reply[1]);
  test_eq(5, socks->socks_version);

  test_eq(0, buf_datalen(buf));

  /* SOCKS 5 Send username/password */
  ADD_DATA(buf, "\x01\x02me\x08mypasswd");
  test_assert(!fetch_from_buf_socks(buf, socks,
                                   get_options()->TestSocks,
                                   get_options()->SafeSocks));
  test_eq(5, socks->socks_version);
  test_eq(2, socks->replylen);
  test_eq(5, socks->reply[0]);
  test_eq(0, socks->reply[1]);

  test_eq(2, socks->usernamelen);
  test_eq(8, socks->passwordlen);

  test_memeq("me", socks->username, 2);
  test_memeq("mypasswd", socks->password, 8);

 done:
  ;
}

/** Perform SOCKS 5 authentication and send data all in one go */
static void
test_socks_5_authenticate_with_data(void *ptr)
{
  SOCKS_TEST_INIT();

  /* SOCKS 5 Negotiate username/password authentication */
  ADD_DATA(buf, "\x05\x01\x02");

  test_assert(!fetch_from_buf_socks(buf, socks,
                                   get_options()->TestSocks,
                                   get_options()->SafeSocks));
  test_eq(2, socks->replylen);
  test_eq(5, socks->reply[0]);
  test_eq(SOCKS_USER_PASS, socks->reply[1]);
  test_eq(5, socks->socks_version);

  test_eq(0, buf_datalen(buf));

  /* SOCKS 5 Send username/password */
  /* SOCKS 5 Send CONNECT [01] to IP address 2.2.2.2:4369 */
  ADD_DATA(buf, "\x01\x02me\x03you\x05\x01\x00\x01\x02\x02\x02\x02\x11\x11");
  test_assert(fetch_from_buf_socks(buf, socks,
                                   get_options()->TestSocks,
                                   get_options()->SafeSocks) == 1);
  test_eq(5, socks->socks_version);
  test_eq(2, socks->replylen);
  test_eq(5, socks->reply[0]);
  test_eq(0, socks->reply[1]);

  test_streq("2.2.2.2", socks->address);
  test_eq(4369, socks->port);

  test_eq(2, socks->usernamelen);
  test_eq(3, socks->passwordlen);
  test_memeq("me", socks->username, 2);
  test_memeq("you", socks->password, 3);

 done:
  ;
}

/** Perform SOCKS 5 authentication before method negotiated */
static void
test_socks_5_auth_before_negotiation(void *ptr)
{
  SOCKS_TEST_INIT();

  /* SOCKS 5 Send username/password */
  ADD_DATA(buf, "\x01\x02me\x02me");
  test_assert(fetch_from_buf_socks(buf, socks,
                                   get_options()->TestSocks,
                                   get_options()->SafeSocks) == -1);
  test_eq(0, socks->socks_version);
  test_eq(0, socks->replylen);
  test_eq(0, socks->reply[0]);
  test_eq(0, socks->reply[1]);

 done:
  ;
}

static void
test_buffer_copy(void *arg)
{
  generic_buffer_t *buf=NULL, *buf2=NULL;
  const char *s;
  size_t len;
  char b[256];
  int i;
  (void)arg;

  buf = generic_buffer_new();
  tt_assert(buf);

  /* Copy an empty buffer. */
  tt_int_op(0, ==, generic_buffer_set_to_copy(&buf2, buf));
  tt_assert(buf2);
  tt_int_op(0, ==, generic_buffer_len(buf2));

  /* Now try with a short buffer. */
  s = "And now comes an act of enormous enormance!";
  len = strlen(s);
  generic_buffer_add(buf, s, len);
  tt_int_op(len, ==, generic_buffer_len(buf));
  /* Add junk to buf2 so we can test replacing.*/
  generic_buffer_add(buf2, "BLARG", 5);
  tt_int_op(0, ==, generic_buffer_set_to_copy(&buf2, buf));
  tt_int_op(len, ==, generic_buffer_len(buf2));
  generic_buffer_get(buf2, b, len);
  test_mem_op(b, ==, s, len);
  /* Now free buf2 and retry so we can test allocating */
  generic_buffer_free(buf2);
  buf2 = NULL;
  tt_int_op(0, ==, generic_buffer_set_to_copy(&buf2, buf));
  tt_int_op(len, ==, generic_buffer_len(buf2));
  generic_buffer_get(buf2, b, len);
  test_mem_op(b, ==, s, len);
  /* Clear buf for next test */
  generic_buffer_get(buf, b, len);
  tt_int_op(generic_buffer_len(buf),==,0);

  /* Okay, now let's try a bigger buffer. */
  s = "Quis autem vel eum iure reprehenderit qui in ea voluptate velit "
    "esse quam nihil molestiae consequatur, vel illum qui dolorem eum "
    "fugiat quo voluptas nulla pariatur?";
  len = strlen(s);
  for (i = 0; i < 256; ++i) {
    b[0]=i;
    generic_buffer_add(buf, b, 1);
    generic_buffer_add(buf, s, len);
  }
  tt_int_op(0, ==, generic_buffer_set_to_copy(&buf2, buf));
  tt_int_op(generic_buffer_len(buf2), ==, generic_buffer_len(buf));
  for (i = 0; i < 256; ++i) {
    generic_buffer_get(buf2, b, len+1);
    tt_int_op((unsigned char)b[0],==,i);
    test_mem_op(b+1, ==, s, len);
  }

 done:
  if (buf)
    generic_buffer_free(buf);
  if (buf2)
    generic_buffer_free(buf2);
}

/** Run unit tests for buffers.c */
static void
test_buffers(void)
{
  char str[256];
  char str2[256];

  buf_t *buf = NULL, *buf2 = NULL;
  const char *cp;

  int j;
  size_t r;

  /****
   * buf_new
   ****/
  if (!(buf = buf_new()))
    test_fail();

  //test_eq(buf_capacity(buf), 4096);
  test_eq(buf_datalen(buf), 0);

  /****
   * General pointer frobbing
   */
  for (j=0;j<256;++j) {
    str[j] = (char)j;
  }
  write_to_buf(str, 256, buf);
  write_to_buf(str, 256, buf);
  test_eq(buf_datalen(buf), 512);
  fetch_from_buf(str2, 200, buf);
  test_memeq(str, str2, 200);
  test_eq(buf_datalen(buf), 312);
  memset(str2, 0, sizeof(str2));

  fetch_from_buf(str2, 256, buf);
  test_memeq(str+200, str2, 56);
  test_memeq(str, str2+56, 200);
  test_eq(buf_datalen(buf), 56);
  memset(str2, 0, sizeof(str2));
  /* Okay, now we should be 512 bytes into the 4096-byte buffer.  If we add
   * another 3584 bytes, we hit the end. */
  for (j=0;j<15;++j) {
    write_to_buf(str, 256, buf);
  }
  assert_buf_ok(buf);
  test_eq(buf_datalen(buf), 3896);
  fetch_from_buf(str2, 56, buf);
  test_eq(buf_datalen(buf), 3840);
  test_memeq(str+200, str2, 56);
  for (j=0;j<15;++j) {
    memset(str2, 0, sizeof(str2));
    fetch_from_buf(str2, 256, buf);
    test_memeq(str, str2, 256);
  }
  test_eq(buf_datalen(buf), 0);
  buf_free(buf);
  buf = NULL;

  /* Okay, now make sure growing can work. */
  buf = buf_new_with_capacity(16);
  //test_eq(buf_capacity(buf), 16);
  write_to_buf(str+1, 255, buf);
  //test_eq(buf_capacity(buf), 256);
  fetch_from_buf(str2, 254, buf);
  test_memeq(str+1, str2, 254);
  //test_eq(buf_capacity(buf), 256);
  assert_buf_ok(buf);
  write_to_buf(str, 32, buf);
  //test_eq(buf_capacity(buf), 256);
  assert_buf_ok(buf);
  write_to_buf(str, 256, buf);
  assert_buf_ok(buf);
  //test_eq(buf_capacity(buf), 512);
  test_eq(buf_datalen(buf), 33+256);
  fetch_from_buf(str2, 33, buf);
  test_eq(*str2, str[255]);

  test_memeq(str2+1, str, 32);
  //test_eq(buf_capacity(buf), 512);
  test_eq(buf_datalen(buf), 256);
  fetch_from_buf(str2, 256, buf);
  test_memeq(str, str2, 256);

  /* now try shrinking: case 1. */
  buf_free(buf);
  buf = buf_new_with_capacity(33668);
  for (j=0;j<67;++j) {
    write_to_buf(str,255, buf);
  }
  //test_eq(buf_capacity(buf), 33668);
  test_eq(buf_datalen(buf), 17085);
  for (j=0; j < 40; ++j) {
    fetch_from_buf(str2, 255,buf);
    test_memeq(str2, str, 255);
  }

  /* now try shrinking: case 2. */
  buf_free(buf);
  buf = buf_new_with_capacity(33668);
  for (j=0;j<67;++j) {
    write_to_buf(str,255, buf);
  }
  for (j=0; j < 20; ++j) {
    fetch_from_buf(str2, 255,buf);
    test_memeq(str2, str, 255);
  }
  for (j=0;j<80;++j) {
    write_to_buf(str,255, buf);
  }
  //test_eq(buf_capacity(buf),33668);
  for (j=0; j < 120; ++j) {
    fetch_from_buf(str2, 255,buf);
    test_memeq(str2, str, 255);
  }

  /* Move from buf to buf. */
  buf_free(buf);
  buf = buf_new_with_capacity(4096);
  buf2 = buf_new_with_capacity(4096);
  for (j=0;j<100;++j)
    write_to_buf(str, 255, buf);
  test_eq(buf_datalen(buf), 25500);
  for (j=0;j<100;++j) {
    r = 10;
    move_buf_to_buf(buf2, buf, &r);
    test_eq(r, 0);
  }
  test_eq(buf_datalen(buf), 24500);
  test_eq(buf_datalen(buf2), 1000);
  for (j=0;j<3;++j) {
    fetch_from_buf(str2, 255, buf2);
    test_memeq(str2, str, 255);
  }
  r = 8192; /*big move*/
  move_buf_to_buf(buf2, buf, &r);
  test_eq(r, 0);
  r = 30000; /* incomplete move */
  move_buf_to_buf(buf2, buf, &r);
  test_eq(r, 13692);
  for (j=0;j<97;++j) {
    fetch_from_buf(str2, 255, buf2);
    test_memeq(str2, str, 255);
  }
  buf_free(buf);
  buf_free(buf2);
  buf = buf2 = NULL;

  buf = buf_new_with_capacity(5);
  cp = "Testing. This is a moderately long Testing string.";
  for (j = 0; cp[j]; j++)
    write_to_buf(cp+j, 1, buf);
  test_eq(0, buf_find_string_offset(buf, "Testing", 7));
  test_eq(1, buf_find_string_offset(buf, "esting", 6));
  test_eq(1, buf_find_string_offset(buf, "est", 3));
  test_eq(39, buf_find_string_offset(buf, "ing str", 7));
  test_eq(35, buf_find_string_offset(buf, "Testing str", 11));
  test_eq(32, buf_find_string_offset(buf, "ng ", 3));
  test_eq(43, buf_find_string_offset(buf, "string.", 7));
  test_eq(-1, buf_find_string_offset(buf, "shrdlu", 6));
  test_eq(-1, buf_find_string_offset(buf, "Testing thing", 13));
  test_eq(-1, buf_find_string_offset(buf, "ngx", 3));
  buf_free(buf);
  buf = NULL;

 done:
  if (buf)
    buf_free(buf);
  if (buf2)
    buf_free(buf2);
}

/** Run unit tests for the onion handshake code. */
static void
test_onion_handshake(void)
{
  /* client-side */
  crypto_dh_t *c_dh = NULL;
  char c_buf[ONIONSKIN_CHALLENGE_LEN];
  char c_keys[40];

  /* server-side */
  char s_buf[ONIONSKIN_REPLY_LEN];
  char s_keys[40];

  /* shared */
  crypto_pk_t *pk = NULL;

  pk = pk_generate(0);

  /* client handshake 1. */
  memset(c_buf, 0, ONIONSKIN_CHALLENGE_LEN);
  test_assert(! onion_skin_create(pk, &c_dh, c_buf));

  /* server handshake */
  memset(s_buf, 0, ONIONSKIN_REPLY_LEN);
  memset(s_keys, 0, 40);
  test_assert(! onion_skin_server_handshake(c_buf, pk, NULL,
                                            s_buf, s_keys, 40));

  /* client handshake 2 */
  memset(c_keys, 0, 40);
  test_assert(! onion_skin_client_handshake(c_dh, s_buf, c_keys, 40));

  if (memcmp(c_keys, s_keys, 40)) {
    puts("Aiiiie");
    exit(1);
  }
  test_memeq(c_keys, s_keys, 40);
  memset(s_buf, 0, 40);
  test_memneq(c_keys, s_buf, 40);

 done:
  if (c_dh)
    crypto_dh_free(c_dh);
  if (pk)
    crypto_pk_free(pk);
}

static void
test_circuit_timeout(void)
{
  /* Plan:
   *  1. Generate 1000 samples
   *  2. Estimate parameters
   *  3. If difference, repeat
   *  4. Save state
   *  5. load state
   *  6. Estimate parameters
   *  7. compare differences
   */
  circuit_build_times_t initial;
  circuit_build_times_t estimate;
  circuit_build_times_t final;
  double timeout1, timeout2;
  or_state_t state;
  int i, runs;
  double close_ms;
  circuit_build_times_init(&initial);
  circuit_build_times_init(&estimate);
  circuit_build_times_init(&final);

  memset(&state, 0, sizeof(or_state_t));

  circuitbuild_running_unit_tests();
#define timeout0 (build_time_t)(30*1000.0)
  initial.Xm = 3000;
  circuit_build_times_initial_alpha(&initial,
                                    CBT_DEFAULT_QUANTILE_CUTOFF/100.0,
                                    timeout0);
  close_ms = MAX(circuit_build_times_calculate_timeout(&initial,
                             CBT_DEFAULT_CLOSE_QUANTILE/100.0),
                 CBT_DEFAULT_TIMEOUT_INITIAL_VALUE);
  do {
    for (i=0; i < CBT_DEFAULT_MIN_CIRCUITS_TO_OBSERVE; i++) {
      build_time_t sample = circuit_build_times_generate_sample(&initial,0,1);

      if (sample > close_ms) {
        circuit_build_times_add_time(&estimate, CBT_BUILD_ABANDONED);
      } else {
        circuit_build_times_add_time(&estimate, sample);
      }
    }
    circuit_build_times_update_alpha(&estimate);
    timeout1 = circuit_build_times_calculate_timeout(&estimate,
                                  CBT_DEFAULT_QUANTILE_CUTOFF/100.0);
    circuit_build_times_set_timeout(&estimate);
    log_notice(LD_CIRC, "Timeout1 is %f, Xm is %d", timeout1, estimate.Xm);
           /* 2% error */
  } while (fabs(circuit_build_times_cdf(&initial, timeout0) -
                circuit_build_times_cdf(&initial, timeout1)) > 0.02);

  test_assert(estimate.total_build_times <= CBT_NCIRCUITS_TO_OBSERVE);

  circuit_build_times_update_state(&estimate, &state);
  test_assert(circuit_build_times_parse_state(&final, &state) == 0);

  circuit_build_times_update_alpha(&final);
  timeout2 = circuit_build_times_calculate_timeout(&final,
                                 CBT_DEFAULT_QUANTILE_CUTOFF/100.0);

  circuit_build_times_set_timeout(&final);
  log_notice(LD_CIRC, "Timeout2 is %f, Xm is %d", timeout2, final.Xm);

  /* 5% here because some accuracy is lost due to histogram conversion */
  test_assert(fabs(circuit_build_times_cdf(&initial, timeout0) -
                   circuit_build_times_cdf(&initial, timeout2)) < 0.05);

  for (runs = 0; runs < 50; runs++) {
    int build_times_idx = 0;
    int total_build_times = 0;

    final.close_ms = final.timeout_ms = CBT_DEFAULT_TIMEOUT_INITIAL_VALUE;
    estimate.close_ms = estimate.timeout_ms
                      = CBT_DEFAULT_TIMEOUT_INITIAL_VALUE;

    for (i = 0; i < CBT_DEFAULT_RECENT_CIRCUITS*2; i++) {
      circuit_build_times_network_circ_success(&estimate);
      circuit_build_times_add_time(&estimate,
            circuit_build_times_generate_sample(&estimate, 0,
                CBT_DEFAULT_QUANTILE_CUTOFF/100.0));

      circuit_build_times_network_circ_success(&estimate);
      circuit_build_times_add_time(&final,
            circuit_build_times_generate_sample(&final, 0,
                CBT_DEFAULT_QUANTILE_CUTOFF/100.0));
    }

    test_assert(!circuit_build_times_network_check_changed(&estimate));
    test_assert(!circuit_build_times_network_check_changed(&final));

    /* Reset liveness to be non-live */
    final.liveness.network_last_live = 0;
    estimate.liveness.network_last_live = 0;

    build_times_idx = estimate.build_times_idx;
    total_build_times = estimate.total_build_times;

    test_assert(circuit_build_times_network_check_live(&estimate));
    test_assert(circuit_build_times_network_check_live(&final));

    circuit_build_times_count_close(&estimate, 0,
            (time_t)(approx_time()-estimate.close_ms/1000.0-1));
    circuit_build_times_count_close(&final, 0,
            (time_t)(approx_time()-final.close_ms/1000.0-1));

    test_assert(!circuit_build_times_network_check_live(&estimate));
    test_assert(!circuit_build_times_network_check_live(&final));

    log_info(LD_CIRC, "idx: %d %d, tot: %d %d",
             build_times_idx, estimate.build_times_idx,
             total_build_times, estimate.total_build_times);

    /* Check rollback index. Should match top of loop. */
    test_assert(build_times_idx == estimate.build_times_idx);
    // This can fail if estimate.total_build_times == 1000, because
    // in that case, rewind actually causes us to lose timeouts
    if (total_build_times != CBT_NCIRCUITS_TO_OBSERVE)
      test_assert(total_build_times == estimate.total_build_times);

    /* Now simulate that the network has become live and we need
     * a change */
    circuit_build_times_network_is_live(&estimate);
    circuit_build_times_network_is_live(&final);

    for (i = 0; i < CBT_DEFAULT_MAX_RECENT_TIMEOUT_COUNT; i++) {
      circuit_build_times_count_timeout(&estimate, 1);

      if (i < CBT_DEFAULT_MAX_RECENT_TIMEOUT_COUNT-1) {
        circuit_build_times_count_timeout(&final, 1);
      }
    }

    test_assert(estimate.liveness.after_firsthop_idx == 0);
    test_assert(final.liveness.after_firsthop_idx ==
                CBT_DEFAULT_MAX_RECENT_TIMEOUT_COUNT-1);

    test_assert(circuit_build_times_network_check_live(&estimate));
    test_assert(circuit_build_times_network_check_live(&final));

    circuit_build_times_count_timeout(&final, 1);
  }

 done:
  return;
}

/* Helper: assert that short_policy parses and writes back out as itself,
   or as <b>expected</b> if that's provided. */
static void
test_short_policy_parse(const char *input,
                        const char *expected)
{
  short_policy_t *short_policy = NULL;
  char *out = NULL;

  if (expected == NULL)
    expected = input;

  short_policy = parse_short_policy(input);
  tt_assert(short_policy);
  out = write_short_policy(short_policy);
  tt_str_op(out, ==, expected);

 done:
  tor_free(out);
  short_policy_free(short_policy);
}

/** Helper: Parse the exit policy string in <b>policy_str</b>, and make sure
 * that policies_summarize() produces the string <b>expected_summary</b> from
 * it. */
static void
test_policy_summary_helper(const char *policy_str,
                           const char *expected_summary)
{
  config_line_t line;
  smartlist_t *policy = smartlist_new();
  char *summary = NULL;
  char *summary_after = NULL;
  int r;
  short_policy_t *short_policy = NULL;

  line.key = (char*)"foo";
  line.value = (char *)policy_str;
  line.next = NULL;

  r = policies_parse_exit_policy(&line, &policy, 0, NULL, 1);
  test_eq(r, 0);
  summary = policy_summarize(policy);

  test_assert(summary != NULL);
  test_streq(summary, expected_summary);

  short_policy = parse_short_policy(summary);
  tt_assert(short_policy);
  summary_after = write_short_policy(short_policy);
  test_streq(summary, summary_after);

 done:
  tor_free(summary_after);
  tor_free(summary);
  if (policy)
    addr_policy_list_free(policy);
  short_policy_free(short_policy);
}

/** Run unit tests for generating summary lines of exit policies */
static void
test_policies(void)
{
  int i;
  smartlist_t *policy = NULL, *policy2 = NULL, *policy3 = NULL,
              *policy4 = NULL, *policy5 = NULL, *policy6 = NULL,
              *policy7 = NULL;
  addr_policy_t *p;
  tor_addr_t tar;
  config_line_t line;
  smartlist_t *sm = NULL;
  char *policy_str = NULL;

  policy = smartlist_new();

  p = router_parse_addr_policy_item_from_string("reject 192.168.0.0/16:*",-1);
  test_assert(p != NULL);
  test_eq(ADDR_POLICY_REJECT, p->policy_type);
  tor_addr_from_ipv4h(&tar, 0xc0a80000u);
  test_eq(0, tor_addr_compare(&p->addr, &tar, CMP_EXACT));
  test_eq(16, p->maskbits);
  test_eq(1, p->prt_min);
  test_eq(65535, p->prt_max);

  smartlist_add(policy, p);

  tor_addr_from_ipv4h(&tar, 0x01020304u);
  test_assert(ADDR_POLICY_ACCEPTED ==
          compare_tor_addr_to_addr_policy(&tar, 2, policy));
  tor_addr_make_unspec(&tar);
  test_assert(ADDR_POLICY_PROBABLY_ACCEPTED ==
          compare_tor_addr_to_addr_policy(&tar, 2, policy));
  tor_addr_from_ipv4h(&tar, 0xc0a80102);
  test_assert(ADDR_POLICY_REJECTED ==
          compare_tor_addr_to_addr_policy(&tar, 2, policy));

  test_assert(0 == policies_parse_exit_policy(NULL, &policy2, 1, NULL, 1));
  test_assert(policy2);

  policy3 = smartlist_new();
  p = router_parse_addr_policy_item_from_string("reject *:*",-1);
  test_assert(p != NULL);
  smartlist_add(policy3, p);
  p = router_parse_addr_policy_item_from_string("accept *:*",-1);
  test_assert(p != NULL);
  smartlist_add(policy3, p);

  policy4 = smartlist_new();
  p = router_parse_addr_policy_item_from_string("accept *:443",-1);
  test_assert(p != NULL);
  smartlist_add(policy4, p);
  p = router_parse_addr_policy_item_from_string("accept *:443",-1);
  test_assert(p != NULL);
  smartlist_add(policy4, p);

  policy5 = smartlist_new();
  p = router_parse_addr_policy_item_from_string("reject 0.0.0.0/8:*",-1);
  test_assert(p != NULL);
  smartlist_add(policy5, p);
  p = router_parse_addr_policy_item_from_string("reject 169.254.0.0/16:*",-1);
  test_assert(p != NULL);
  smartlist_add(policy5, p);
  p = router_parse_addr_policy_item_from_string("reject 127.0.0.0/8:*",-1);
  test_assert(p != NULL);
  smartlist_add(policy5, p);
  p = router_parse_addr_policy_item_from_string("reject 192.168.0.0/16:*",-1);
  test_assert(p != NULL);
  smartlist_add(policy5, p);
  p = router_parse_addr_policy_item_from_string("reject 10.0.0.0/8:*",-1);
  test_assert(p != NULL);
  smartlist_add(policy5, p);
  p = router_parse_addr_policy_item_from_string("reject 172.16.0.0/12:*",-1);
  test_assert(p != NULL);
  smartlist_add(policy5, p);
  p = router_parse_addr_policy_item_from_string("reject 80.190.250.90:*",-1);
  test_assert(p != NULL);
  smartlist_add(policy5, p);
  p = router_parse_addr_policy_item_from_string("reject *:1-65534",-1);
  test_assert(p != NULL);
  smartlist_add(policy5, p);
  p = router_parse_addr_policy_item_from_string("reject *:65535",-1);
  test_assert(p != NULL);
  smartlist_add(policy5, p);
  p = router_parse_addr_policy_item_from_string("accept *:1-65535",-1);
  test_assert(p != NULL);
  smartlist_add(policy5, p);

  policy6 = smartlist_new();
  p = router_parse_addr_policy_item_from_string("accept 43.3.0.0/9:*",-1);
  test_assert(p != NULL);
  smartlist_add(policy6, p);

  policy7 = smartlist_new();
  p = router_parse_addr_policy_item_from_string("accept 0.0.0.0/8:*",-1);
  test_assert(p != NULL);
  smartlist_add(policy7, p);

  test_assert(!exit_policy_is_general_exit(policy));
  test_assert(exit_policy_is_general_exit(policy2));
  test_assert(!exit_policy_is_general_exit(NULL));
  test_assert(!exit_policy_is_general_exit(policy3));
  test_assert(!exit_policy_is_general_exit(policy4));
  test_assert(!exit_policy_is_general_exit(policy5));
  test_assert(!exit_policy_is_general_exit(policy6));
  test_assert(!exit_policy_is_general_exit(policy7));

  test_assert(cmp_addr_policies(policy, policy2));
  test_assert(cmp_addr_policies(policy, NULL));
  test_assert(!cmp_addr_policies(policy2, policy2));
  test_assert(!cmp_addr_policies(NULL, NULL));

  test_assert(!policy_is_reject_star(policy2));
  test_assert(policy_is_reject_star(policy));
  test_assert(policy_is_reject_star(NULL));

  addr_policy_list_free(policy);
  policy = NULL;

  /* make sure compacting logic works. */
  policy = NULL;
  line.key = (char*)"foo";
  line.value = (char*)"accept *:80,reject private:*,reject *:*";
  line.next = NULL;
  test_assert(0 == policies_parse_exit_policy(&line, &policy, 0, NULL, 1));
  test_assert(policy);
  //test_streq(policy->string, "accept *:80");
  //test_streq(policy->next->string, "reject *:*");
  test_eq(smartlist_len(policy), 2);

  /* test policy summaries */
  /* check if we properly ignore private IP addresses */
  test_policy_summary_helper("reject 192.168.0.0/16:*,"
                             "reject 0.0.0.0/8:*,"
                             "reject 10.0.0.0/8:*,"
                             "accept *:10-30,"
                             "accept *:90,"
                             "reject *:*",
                             "accept 10-30,90");
  /* check all accept policies, and proper counting of rejects */
  test_policy_summary_helper("reject 11.0.0.0/9:80,"
                             "reject 12.0.0.0/9:80,"
                             "reject 13.0.0.0/9:80,"
                             "reject 14.0.0.0/9:80,"
                             "accept *:*", "accept 1-65535");
  test_policy_summary_helper("reject 11.0.0.0/9:80,"
                             "reject 12.0.0.0/9:80,"
                             "reject 13.0.0.0/9:80,"
                             "reject 14.0.0.0/9:80,"
                             "reject 15.0.0.0:81,"
                             "accept *:*", "accept 1-65535");
  test_policy_summary_helper("reject 11.0.0.0/9:80,"
                             "reject 12.0.0.0/9:80,"
                             "reject 13.0.0.0/9:80,"
                             "reject 14.0.0.0/9:80,"
                             "reject 15.0.0.0:80,"
                             "accept *:*",
                             "reject 80");
  /* no exits */
  test_policy_summary_helper("accept 11.0.0.0/9:80,"
                             "reject *:*",
                             "reject 1-65535");
  /* port merging */
  test_policy_summary_helper("accept *:80,"
                             "accept *:81,"
                             "accept *:100-110,"
                             "accept *:111,"
                             "reject *:*",
                             "accept 80-81,100-111");
  /* border ports */
  test_policy_summary_helper("accept *:1,"
                             "accept *:3,"
                             "accept *:65535,"
                             "reject *:*",
                             "accept 1,3,65535");
  /* holes */
  test_policy_summary_helper("accept *:1,"
                             "accept *:3,"
                             "accept *:5,"
                             "accept *:7,"
                             "reject *:*",
                             "accept 1,3,5,7");
  test_policy_summary_helper("reject *:1,"
                             "reject *:3,"
                             "reject *:5,"
                             "reject *:7,"
                             "accept *:*",
                             "reject 1,3,5,7");

  /* Short policies with unrecognized formats should get accepted. */
  test_short_policy_parse("accept fred,2,3-5", "accept 2,3-5");
  test_short_policy_parse("accept 2,fred,3", "accept 2,3");
  test_short_policy_parse("accept 2,fred,3,bob", "accept 2,3");
  test_short_policy_parse("accept 2,-3,500-600", "accept 2,500-600");
  /* Short policies with nil entries are accepted too. */
  test_short_policy_parse("accept 1,,3", "accept 1,3");
  test_short_policy_parse("accept 100-200,,", "accept 100-200");
  test_short_policy_parse("reject ,1-10,,,,30-40", "reject 1-10,30-40");

  /* Try parsing various broken short policies */
  tt_ptr_op(NULL, ==, parse_short_policy("accept 200-199"));
  tt_ptr_op(NULL, ==, parse_short_policy(""));
  tt_ptr_op(NULL, ==, parse_short_policy("rejekt 1,2,3"));
  tt_ptr_op(NULL, ==, parse_short_policy("reject "));
  tt_ptr_op(NULL, ==, parse_short_policy("reject"));
  tt_ptr_op(NULL, ==, parse_short_policy("rej"));
  tt_ptr_op(NULL, ==, parse_short_policy("accept 2,3,100000"));
  tt_ptr_op(NULL, ==, parse_short_policy("accept 2,3x,4"));
  tt_ptr_op(NULL, ==, parse_short_policy("accept 2,3x,4"));
  tt_ptr_op(NULL, ==, parse_short_policy("accept 2-"));
  tt_ptr_op(NULL, ==, parse_short_policy("accept 2-x"));
  tt_ptr_op(NULL, ==, parse_short_policy("accept 1-,3"));
  tt_ptr_op(NULL, ==, parse_short_policy("accept 1-,3"));
  /* Test a too-long policy. */
  {
    int i;
    char *policy = NULL;
    smartlist_t *chunks = smartlist_new();
    smartlist_add(chunks, tor_strdup("accept "));
    for (i=1; i<10000; ++i)
      smartlist_add_asprintf(chunks, "%d,", i);
    smartlist_add(chunks, tor_strdup("20000"));
    policy = smartlist_join_strings(chunks, "", 0, NULL);
    SMARTLIST_FOREACH(chunks, char *, ch, tor_free(ch));
    smartlist_free(chunks);
    tt_ptr_op(NULL, ==, parse_short_policy(policy));/* shouldn't be accepted */
    tor_free(policy); /* could leak. */
  }

  /* truncation ports */
  sm = smartlist_new();
  for (i=1; i<2000; i+=2) {
    char buf[POLICY_BUF_LEN];
    tor_snprintf(buf, sizeof(buf), "reject *:%d", i);
    smartlist_add(sm, tor_strdup(buf));
  }
  smartlist_add(sm, tor_strdup("accept *:*"));
  policy_str = smartlist_join_strings(sm, ",", 0, NULL);
  test_policy_summary_helper( policy_str,
    "accept 2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,38,40,42,44,"
    "46,48,50,52,54,56,58,60,62,64,66,68,70,72,74,76,78,80,82,84,86,88,90,"
    "92,94,96,98,100,102,104,106,108,110,112,114,116,118,120,122,124,126,128,"
    "130,132,134,136,138,140,142,144,146,148,150,152,154,156,158,160,162,164,"
    "166,168,170,172,174,176,178,180,182,184,186,188,190,192,194,196,198,200,"
    "202,204,206,208,210,212,214,216,218,220,222,224,226,228,230,232,234,236,"
    "238,240,242,244,246,248,250,252,254,256,258,260,262,264,266,268,270,272,"
    "274,276,278,280,282,284,286,288,290,292,294,296,298,300,302,304,306,308,"
    "310,312,314,316,318,320,322,324,326,328,330,332,334,336,338,340,342,344,"
    "346,348,350,352,354,356,358,360,362,364,366,368,370,372,374,376,378,380,"
    "382,384,386,388,390,392,394,396,398,400,402,404,406,408,410,412,414,416,"
    "418,420,422,424,426,428,430,432,434,436,438,440,442,444,446,448,450,452,"
    "454,456,458,460,462,464,466,468,470,472,474,476,478,480,482,484,486,488,"
    "490,492,494,496,498,500,502,504,506,508,510,512,514,516,518,520,522");

 done:
  addr_policy_list_free(policy);
  addr_policy_list_free(policy2);
  addr_policy_list_free(policy3);
  addr_policy_list_free(policy4);
  addr_policy_list_free(policy5);
  addr_policy_list_free(policy6);
  addr_policy_list_free(policy7);
  tor_free(policy_str);
  if (sm) {
    SMARTLIST_FOREACH(sm, char *, s, tor_free(s));
    smartlist_free(sm);
  }
}

/** Test encoding and parsing of rendezvous service descriptors. */
static void
test_rend_fns(void)
{
  rend_service_descriptor_t *generated = NULL, *parsed = NULL;
  char service_id[DIGEST_LEN];
  char service_id_base32[REND_SERVICE_ID_LEN_BASE32+1];
  const char *next_desc;
  smartlist_t *descs = smartlist_new();
  char computed_desc_id[DIGEST_LEN];
  char parsed_desc_id[DIGEST_LEN];
  crypto_pk_t *pk1 = NULL, *pk2 = NULL;
  time_t now;
  char *intro_points_encrypted = NULL;
  size_t intro_points_size;
  size_t encoded_size;
  int i;
  char address1[] = "fooaddress.onion";
  char address2[] = "aaaaaaaaaaaaaaaa.onion";
  char address3[] = "fooaddress.exit";
  char address4[] = "www.torproject.org";

  test_assert(BAD_HOSTNAME == parse_extended_hostname(address1));
  test_assert(ONION_HOSTNAME == parse_extended_hostname(address2));
  test_assert(EXIT_HOSTNAME == parse_extended_hostname(address3));
  test_assert(NORMAL_HOSTNAME == parse_extended_hostname(address4));

  pk1 = pk_generate(0);
  pk2 = pk_generate(1);
  generated = tor_malloc_zero(sizeof(rend_service_descriptor_t));
  generated->pk = crypto_pk_dup_key(pk1);
  crypto_pk_get_digest(generated->pk, service_id);
  base32_encode(service_id_base32, REND_SERVICE_ID_LEN_BASE32+1,
                service_id, REND_SERVICE_ID_LEN);
  now = time(NULL);
  generated->timestamp = now;
  generated->version = 2;
  generated->protocols = 42;
  generated->intro_nodes = smartlist_new();

  for (i = 0; i < 3; i++) {
    rend_intro_point_t *intro = tor_malloc_zero(sizeof(rend_intro_point_t));
    crypto_pk_t *okey = pk_generate(2 + i);
    intro->extend_info = tor_malloc_zero(sizeof(extend_info_t));
    intro->extend_info->onion_key = okey;
    crypto_pk_get_digest(intro->extend_info->onion_key,
                         intro->extend_info->identity_digest);
    //crypto_rand(info->identity_digest, DIGEST_LEN); /* Would this work? */
    intro->extend_info->nickname[0] = '$';
    base16_encode(intro->extend_info->nickname + 1,
                  sizeof(intro->extend_info->nickname) - 1,
                  intro->extend_info->identity_digest, DIGEST_LEN);
    /* Does not cover all IP addresses. */
    tor_addr_from_ipv4h(&intro->extend_info->addr, crypto_rand_int(65536));
    intro->extend_info->port = 1 + crypto_rand_int(65535);
    intro->intro_key = crypto_pk_dup_key(pk2);
    smartlist_add(generated->intro_nodes, intro);
  }
  test_assert(rend_encode_v2_descriptors(descs, generated, now, 0,
                                         REND_NO_AUTH, NULL, NULL) > 0);
  test_assert(rend_compute_v2_desc_id(computed_desc_id, service_id_base32,
                                      NULL, now, 0) == 0);
  test_memeq(((rend_encoded_v2_service_descriptor_t *)
             smartlist_get(descs, 0))->desc_id, computed_desc_id, DIGEST_LEN);
  test_assert(rend_parse_v2_service_descriptor(&parsed, parsed_desc_id,
                                               &intro_points_encrypted,
                                               &intro_points_size,
                                               &encoded_size,
                                               &next_desc,
                                     ((rend_encoded_v2_service_descriptor_t *)
                                     smartlist_get(descs, 0))->desc_str) == 0);
  test_assert(parsed);
  test_memeq(((rend_encoded_v2_service_descriptor_t *)
             smartlist_get(descs, 0))->desc_id, parsed_desc_id, DIGEST_LEN);
  test_eq(rend_parse_introduction_points(parsed, intro_points_encrypted,
                                         intro_points_size), 3);
  test_assert(!crypto_pk_cmp_keys(generated->pk, parsed->pk));
  test_eq(parsed->timestamp, now);
  test_eq(parsed->version, 2);
  test_eq(parsed->protocols, 42);
  test_eq(smartlist_len(parsed->intro_nodes), 3);
  for (i = 0; i < smartlist_len(parsed->intro_nodes); i++) {
    rend_intro_point_t *par_intro = smartlist_get(parsed->intro_nodes, i),
      *gen_intro = smartlist_get(generated->intro_nodes, i);
    extend_info_t *par_info = par_intro->extend_info;
    extend_info_t *gen_info = gen_intro->extend_info;
    test_assert(!crypto_pk_cmp_keys(gen_info->onion_key, par_info->onion_key));
    test_memeq(gen_info->identity_digest, par_info->identity_digest,
               DIGEST_LEN);
    test_streq(gen_info->nickname, par_info->nickname);
    test_assert(tor_addr_eq(&gen_info->addr, &par_info->addr));
    test_eq(gen_info->port, par_info->port);
  }

  rend_service_descriptor_free(parsed);
  rend_service_descriptor_free(generated);
  parsed = generated = NULL;

 done:
  if (descs) {
    for (i = 0; i < smartlist_len(descs); i++)
      rend_encoded_v2_service_descriptor_free(smartlist_get(descs, i));
    smartlist_free(descs);
  }
  if (parsed)
    rend_service_descriptor_free(parsed);
  if (generated)
    rend_service_descriptor_free(generated);
  if (pk1)
    crypto_pk_free(pk1);
  if (pk2)
    crypto_pk_free(pk2);
  tor_free(intro_points_encrypted);
}

/** Run unit tests for GeoIP code. */
static void
test_geoip(void)
{
  int i, j;
  time_t now = 1281533250; /* 2010-08-11 13:27:30 UTC */
  char *s = NULL;
  const char *bridge_stats_1 =
      "bridge-stats-end 2010-08-12 13:27:30 (86400 s)\n"
      "bridge-ips zz=24,xy=8\n",
  *dirreq_stats_1 =
      "dirreq-stats-end 2010-08-12 13:27:30 (86400 s)\n"
      "dirreq-v3-ips ab=8\n"
      "dirreq-v2-ips \n"
      "dirreq-v3-reqs ab=8\n"
      "dirreq-v2-reqs \n"
      "dirreq-v3-resp ok=0,not-enough-sigs=0,unavailable=0,not-found=0,"
          "not-modified=0,busy=0\n"
      "dirreq-v2-resp ok=0,unavailable=0,not-found=0,not-modified=0,"
          "busy=0\n"
      "dirreq-v3-direct-dl complete=0,timeout=0,running=0\n"
      "dirreq-v2-direct-dl complete=0,timeout=0,running=0\n"
      "dirreq-v3-tunneled-dl complete=0,timeout=0,running=0\n"
      "dirreq-v2-tunneled-dl complete=0,timeout=0,running=0\n",
  *dirreq_stats_2 =
      "dirreq-stats-end 2010-08-12 13:27:30 (86400 s)\n"
      "dirreq-v3-ips \n"
      "dirreq-v2-ips \n"
      "dirreq-v3-reqs \n"
      "dirreq-v2-reqs \n"
      "dirreq-v3-resp ok=0,not-enough-sigs=0,unavailable=0,not-found=0,"
          "not-modified=0,busy=0\n"
      "dirreq-v2-resp ok=0,unavailable=0,not-found=0,not-modified=0,"
          "busy=0\n"
      "dirreq-v3-direct-dl complete=0,timeout=0,running=0\n"
      "dirreq-v2-direct-dl complete=0,timeout=0,running=0\n"
      "dirreq-v3-tunneled-dl complete=0,timeout=0,running=0\n"
      "dirreq-v2-tunneled-dl complete=0,timeout=0,running=0\n",
  *dirreq_stats_3 =
      "dirreq-stats-end 2010-08-12 13:27:30 (86400 s)\n"
      "dirreq-v3-ips \n"
      "dirreq-v2-ips \n"
      "dirreq-v3-reqs \n"
      "dirreq-v2-reqs \n"
      "dirreq-v3-resp ok=8,not-enough-sigs=0,unavailable=0,not-found=0,"
          "not-modified=0,busy=0\n"
      "dirreq-v2-resp ok=0,unavailable=0,not-found=0,not-modified=0,"
          "busy=0\n"
      "dirreq-v3-direct-dl complete=0,timeout=0,running=0\n"
      "dirreq-v2-direct-dl complete=0,timeout=0,running=0\n"
      "dirreq-v3-tunneled-dl complete=0,timeout=0,running=0\n"
      "dirreq-v2-tunneled-dl complete=0,timeout=0,running=0\n",
  *dirreq_stats_4 =
      "dirreq-stats-end 2010-08-12 13:27:30 (86400 s)\n"
      "dirreq-v3-ips \n"
      "dirreq-v2-ips \n"
      "dirreq-v3-reqs \n"
      "dirreq-v2-reqs \n"
      "dirreq-v3-resp ok=8,not-enough-sigs=0,unavailable=0,not-found=0,"
          "not-modified=0,busy=0\n"
      "dirreq-v2-resp ok=0,unavailable=0,not-found=0,not-modified=0,"
          "busy=0\n"
      "dirreq-v3-direct-dl complete=0,timeout=0,running=0\n"
      "dirreq-v2-direct-dl complete=0,timeout=0,running=0\n"
      "dirreq-v3-tunneled-dl complete=0,timeout=0,running=4\n"
      "dirreq-v2-tunneled-dl complete=0,timeout=0,running=0\n",
  *entry_stats_1 =
      "entry-stats-end 2010-08-12 13:27:30 (86400 s)\n"
      "entry-ips ab=8\n",
  *entry_stats_2 =
      "entry-stats-end 2010-08-12 13:27:30 (86400 s)\n"
      "entry-ips \n";
  tor_addr_t addr;

  /* Populate the DB a bit.  Add these in order, since we can't do the final
   * 'sort' step.  These aren't very good IP addresses, but they're perfectly
   * fine uint32_t values. */
  test_eq(0, geoip_parse_entry("10,50,AB"));
  test_eq(0, geoip_parse_entry("52,90,XY"));
  test_eq(0, geoip_parse_entry("95,100,AB"));
  test_eq(0, geoip_parse_entry("\"105\",\"140\",\"ZZ\""));
  test_eq(0, geoip_parse_entry("\"150\",\"190\",\"XY\""));
  test_eq(0, geoip_parse_entry("\"200\",\"250\",\"AB\""));

  /* We should have 4 countries: ??, ab, xy, zz. */
  test_eq(4, geoip_get_n_countries());
  /* Make sure that country ID actually works. */
#define NAMEFOR(x) geoip_get_country_name(geoip_get_country_by_ip(x))
  test_streq("??", NAMEFOR(3));
  test_eq(0, geoip_get_country_by_ip(3));
  test_streq("ab", NAMEFOR(32));
  test_streq("??", NAMEFOR(5));
  test_streq("??", NAMEFOR(51));
  test_streq("xy", NAMEFOR(150));
  test_streq("xy", NAMEFOR(190));
  test_streq("??", NAMEFOR(2000));
#undef NAMEFOR

  get_options_mutable()->BridgeRelay = 1;
  get_options_mutable()->BridgeRecordUsageByCountry = 1;
  /* Put 9 observations in AB... */
  for (i=32; i < 40; ++i) {
    tor_addr_from_ipv4h(&addr, (uint32_t) i);
    geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, now-7200);
  }
  tor_addr_from_ipv4h(&addr, (uint32_t) 225);
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, now-7200);
  /* and 3 observations in XY, several times. */
  for (j=0; j < 10; ++j)
    for (i=52; i < 55; ++i) {
      tor_addr_from_ipv4h(&addr, (uint32_t) i);
      geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, now-3600);
    }
  /* and 17 observations in ZZ... */
  for (i=110; i < 127; ++i) {
    tor_addr_from_ipv4h(&addr, (uint32_t) i);
    geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, now);
  }
  s = geoip_get_client_history(GEOIP_CLIENT_CONNECT);
  test_assert(s);
  test_streq("zz=24,ab=16,xy=8", s);
  tor_free(s);

  /* Now clear out all the AB observations. */
  geoip_remove_old_clients(now-6000);
  s = geoip_get_client_history(GEOIP_CLIENT_CONNECT);
  test_assert(s);
  test_streq("zz=24,xy=8", s);

  /* Start testing bridge statistics by making sure that we don't output
   * bridge stats without initializing them. */
  s = geoip_format_bridge_stats(now + 86400);
  test_assert(!s);

  /* Initialize stats and generate the bridge-stats history string out of
   * the connecting clients added above. */
  geoip_bridge_stats_init(now);
  s = geoip_format_bridge_stats(now + 86400);
  test_streq(bridge_stats_1, s);
  tor_free(s);

  /* Stop collecting bridge stats and make sure we don't write a history
   * string anymore. */
  geoip_bridge_stats_term();
  s = geoip_format_bridge_stats(now + 86400);
  test_assert(!s);

  /* Stop being a bridge and start being a directory mirror that gathers
   * directory request statistics. */
  geoip_bridge_stats_term();
  get_options_mutable()->BridgeRelay = 0;
  get_options_mutable()->BridgeRecordUsageByCountry = 0;
  get_options_mutable()->DirReqStatistics = 1;

  /* Start testing dirreq statistics by making sure that we don't collect
   * dirreq stats without initializing them. */
  tor_addr_from_ipv4h(&addr, (uint32_t) 100);
  geoip_note_client_seen(GEOIP_CLIENT_NETWORKSTATUS, &addr, now);
  s = geoip_format_dirreq_stats(now + 86400);
  test_assert(!s);

  /* Initialize stats, note one connecting client, and generate the
   * dirreq-stats history string. */
  geoip_dirreq_stats_init(now);
  tor_addr_from_ipv4h(&addr, (uint32_t) 100);
  geoip_note_client_seen(GEOIP_CLIENT_NETWORKSTATUS, &addr, now);
  s = geoip_format_dirreq_stats(now + 86400);
  test_streq(dirreq_stats_1, s);
  tor_free(s);

  /* Stop collecting stats, add another connecting client, and ensure we
   * don't generate a history string. */
  geoip_dirreq_stats_term();
  tor_addr_from_ipv4h(&addr, (uint32_t) 101);
  geoip_note_client_seen(GEOIP_CLIENT_NETWORKSTATUS, &addr, now);
  s = geoip_format_dirreq_stats(now + 86400);
  test_assert(!s);

  /* Re-start stats, add a connecting client, reset stats, and make sure
   * that we get an all empty history string. */
  geoip_dirreq_stats_init(now);
  tor_addr_from_ipv4h(&addr, (uint32_t) 100);
  geoip_note_client_seen(GEOIP_CLIENT_NETWORKSTATUS, &addr, now);
  geoip_reset_dirreq_stats(now);
  s = geoip_format_dirreq_stats(now + 86400);
  test_streq(dirreq_stats_2, s);
  tor_free(s);

  /* Note a successful network status response and make sure that it
   * appears in the history string. */
  geoip_note_ns_response(GEOIP_CLIENT_NETWORKSTATUS, GEOIP_SUCCESS);
  s = geoip_format_dirreq_stats(now + 86400);
  test_streq(dirreq_stats_3, s);
  tor_free(s);

  /* Start a tunneled directory request. */
  geoip_start_dirreq((uint64_t) 1, 1024, GEOIP_CLIENT_NETWORKSTATUS,
                     DIRREQ_TUNNELED);
  s = geoip_format_dirreq_stats(now + 86400);
  test_streq(dirreq_stats_4, s);

  /* Stop collecting directory request statistics and start gathering
   * entry stats. */
  geoip_dirreq_stats_term();
  get_options_mutable()->DirReqStatistics = 0;
  get_options_mutable()->EntryStatistics = 1;

  /* Start testing entry statistics by making sure that we don't collect
   * anything without initializing entry stats. */
  tor_addr_from_ipv4h(&addr, (uint32_t) 100);
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, now);
  s = geoip_format_entry_stats(now + 86400);
  test_assert(!s);

  /* Initialize stats, note one connecting client, and generate the
   * entry-stats history string. */
  geoip_entry_stats_init(now);
  tor_addr_from_ipv4h(&addr, (uint32_t) 100);
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, now);
  s = geoip_format_entry_stats(now + 86400);
  test_streq(entry_stats_1, s);
  tor_free(s);

  /* Stop collecting stats, add another connecting client, and ensure we
   * don't generate a history string. */
  geoip_entry_stats_term();
  tor_addr_from_ipv4h(&addr, (uint32_t) 101);
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, now);
  s = geoip_format_entry_stats(now + 86400);
  test_assert(!s);

  /* Re-start stats, add a connecting client, reset stats, and make sure
   * that we get an all empty history string. */
  geoip_entry_stats_init(now);
  tor_addr_from_ipv4h(&addr, (uint32_t) 100);
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, &addr, now);
  geoip_reset_entry_stats(now);
  s = geoip_format_entry_stats(now + 86400);
  test_streq(entry_stats_2, s);
  tor_free(s);

  /* Stop collecting entry statistics. */
  geoip_entry_stats_term();
  get_options_mutable()->EntryStatistics = 0;

 done:
  tor_free(s);
}

/** Run unit tests for stats code. */
static void
test_stats(void)
{
  time_t now = 1281533250; /* 2010-08-11 13:27:30 UTC */
  char *s = NULL;
  int i;

  /* Start with testing exit port statistics; we shouldn't collect exit
   * stats without initializing them. */
  rep_hist_note_exit_stream_opened(80);
  rep_hist_note_exit_bytes(80, 100, 10000);
  s = rep_hist_format_exit_stats(now + 86400);
  test_assert(!s);

  /* Initialize stats, note some streams and bytes, and generate history
   * string. */
  rep_hist_exit_stats_init(now);
  rep_hist_note_exit_stream_opened(80);
  rep_hist_note_exit_bytes(80, 100, 10000);
  rep_hist_note_exit_stream_opened(443);
  rep_hist_note_exit_bytes(443, 100, 10000);
  rep_hist_note_exit_bytes(443, 100, 10000);
  s = rep_hist_format_exit_stats(now + 86400);
  test_streq("exit-stats-end 2010-08-12 13:27:30 (86400 s)\n"
             "exit-kibibytes-written 80=1,443=1,other=0\n"
             "exit-kibibytes-read 80=10,443=20,other=0\n"
             "exit-streams-opened 80=4,443=4,other=0\n", s);
  tor_free(s);

  /* Add a few bytes on 10 more ports and ensure that only the top 10
   * ports are contained in the history string. */
  for (i = 50; i < 60; i++) {
    rep_hist_note_exit_bytes(i, i, i);
    rep_hist_note_exit_stream_opened(i);
  }
  s = rep_hist_format_exit_stats(now + 86400);
  test_streq("exit-stats-end 2010-08-12 13:27:30 (86400 s)\n"
             "exit-kibibytes-written 52=1,53=1,54=1,55=1,56=1,57=1,58=1,"
             "59=1,80=1,443=1,other=1\n"
             "exit-kibibytes-read 52=1,53=1,54=1,55=1,56=1,57=1,58=1,"
             "59=1,80=10,443=20,other=1\n"
             "exit-streams-opened 52=4,53=4,54=4,55=4,56=4,57=4,58=4,"
             "59=4,80=4,443=4,other=4\n", s);
  tor_free(s);

  /* Stop collecting stats, add some bytes, and ensure we don't generate
   * a history string. */
  rep_hist_exit_stats_term();
  rep_hist_note_exit_bytes(80, 100, 10000);
  s = rep_hist_format_exit_stats(now + 86400);
  test_assert(!s);

  /* Re-start stats, add some bytes, reset stats, and see what history we
   * get when observing no streams or bytes at all. */
  rep_hist_exit_stats_init(now);
  rep_hist_note_exit_stream_opened(80);
  rep_hist_note_exit_bytes(80, 100, 10000);
  rep_hist_reset_exit_stats(now);
  s = rep_hist_format_exit_stats(now + 86400);
  test_streq("exit-stats-end 2010-08-12 13:27:30 (86400 s)\n"
             "exit-kibibytes-written other=0\n"
             "exit-kibibytes-read other=0\n"
             "exit-streams-opened other=0\n", s);
  tor_free(s);

  /* Continue with testing connection statistics; we shouldn't collect
   * conn stats without initializing them. */
  rep_hist_note_or_conn_bytes(1, 20, 400, now);
  s = rep_hist_format_conn_stats(now + 86400);
  test_assert(!s);

  /* Initialize stats, note bytes, and generate history string. */
  rep_hist_conn_stats_init(now);
  rep_hist_note_or_conn_bytes(1, 30000, 400000, now);
  rep_hist_note_or_conn_bytes(1, 30000, 400000, now + 5);
  rep_hist_note_or_conn_bytes(2, 400000, 30000, now + 10);
  rep_hist_note_or_conn_bytes(2, 400000, 30000, now + 15);
  s = rep_hist_format_conn_stats(now + 86400);
  test_streq("conn-bi-direct 2010-08-12 13:27:30 (86400 s) 0,0,1,0\n", s);
  tor_free(s);

  /* Stop collecting stats, add some bytes, and ensure we don't generate
   * a history string. */
  rep_hist_conn_stats_term();
  rep_hist_note_or_conn_bytes(2, 400000, 30000, now + 15);
  s = rep_hist_format_conn_stats(now + 86400);
  test_assert(!s);

  /* Re-start stats, add some bytes, reset stats, and see what history we
   * get when observing no bytes at all. */
  rep_hist_conn_stats_init(now);
  rep_hist_note_or_conn_bytes(1, 30000, 400000, now);
  rep_hist_note_or_conn_bytes(1, 30000, 400000, now + 5);
  rep_hist_note_or_conn_bytes(2, 400000, 30000, now + 10);
  rep_hist_note_or_conn_bytes(2, 400000, 30000, now + 15);
  rep_hist_reset_conn_stats(now);
  s = rep_hist_format_conn_stats(now + 86400);
  test_streq("conn-bi-direct 2010-08-12 13:27:30 (86400 s) 0,0,0,0\n", s);
  tor_free(s);

  /* Continue with testing buffer statistics; we shouldn't collect buffer
   * stats without initializing them. */
  rep_hist_add_buffer_stats(2.0, 2.0, 20);
  s = rep_hist_format_buffer_stats(now + 86400);
  test_assert(!s);

  /* Initialize stats, add statistics for a single circuit, and generate
   * the history string. */
  rep_hist_buffer_stats_init(now);
  rep_hist_add_buffer_stats(2.0, 2.0, 20);
  s = rep_hist_format_buffer_stats(now + 86400);
  test_streq("cell-stats-end 2010-08-12 13:27:30 (86400 s)\n"
             "cell-processed-cells 20,0,0,0,0,0,0,0,0,0\n"
             "cell-queued-cells 2.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,"
                               "0.00,0.00\n"
             "cell-time-in-queue 2,0,0,0,0,0,0,0,0,0\n"
             "cell-circuits-per-decile 1\n", s);
  tor_free(s);

  /* Add nineteen more circuit statistics to the one that's already in the
   * history to see that the math works correctly. */
  for (i = 21; i < 30; i++)
    rep_hist_add_buffer_stats(2.0, 2.0, i);
  for (i = 20; i < 30; i++)
    rep_hist_add_buffer_stats(3.5, 3.5, i);
  s = rep_hist_format_buffer_stats(now + 86400);
  test_streq("cell-stats-end 2010-08-12 13:27:30 (86400 s)\n"
             "cell-processed-cells 29,28,27,26,25,24,23,22,21,20\n"
             "cell-queued-cells 2.75,2.75,2.75,2.75,2.75,2.75,2.75,2.75,"
                               "2.75,2.75\n"
             "cell-time-in-queue 3,3,3,3,3,3,3,3,3,3\n"
             "cell-circuits-per-decile 2\n", s);
  tor_free(s);

  /* Stop collecting stats, add statistics for one circuit, and ensure we
   * don't generate a history string. */
  rep_hist_buffer_stats_term();
  rep_hist_add_buffer_stats(2.0, 2.0, 20);
  s = rep_hist_format_buffer_stats(now + 86400);
  test_assert(!s);

  /* Re-start stats, add statistics for one circuit, reset stats, and make
   * sure that the history has all zeros. */
  rep_hist_buffer_stats_init(now);
  rep_hist_add_buffer_stats(2.0, 2.0, 20);
  rep_hist_reset_buffer_stats(now);
  s = rep_hist_format_buffer_stats(now + 86400);
  test_streq("cell-stats-end 2010-08-12 13:27:30 (86400 s)\n"
             "cell-processed-cells 0,0,0,0,0,0,0,0,0,0\n"
             "cell-queued-cells 0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,"
                               "0.00,0.00\n"
             "cell-time-in-queue 0,0,0,0,0,0,0,0,0,0\n"
             "cell-circuits-per-decile 0\n", s);

 done:
  tor_free(s);
}

static void *
legacy_test_setup(const struct testcase_t *testcase)
{
  return testcase->setup_data;
}

void
legacy_test_helper(void *data)
{
  void (*fn)(void) = data;
  fn();
}

static int
legacy_test_cleanup(const struct testcase_t *testcase, void *ptr)
{
  (void)ptr;
  (void)testcase;
  return 1;
}

const struct testcase_setup_t legacy_setup = {
  legacy_test_setup, legacy_test_cleanup
};

#define ENT(name)                                                       \
  { #name, legacy_test_helper, 0, &legacy_setup, test_ ## name }
#define SUBENT(group, name)                                             \
  { #group "_" #name, legacy_test_helper, 0, &legacy_setup,             \
      test_ ## group ## _ ## name }
#define DISABLED(name)                                                  \
  { #name, legacy_test_helper, TT_SKIP, &legacy_setup, test_ ## name }
#define FORK(name)                                                      \
  { #name, legacy_test_helper, TT_FORK, &legacy_setup, test_ ## name }

static struct testcase_t test_array[] = {
  ENT(buffers),
  { "buffer_copy", test_buffer_copy, 0, NULL, NULL },
  ENT(onion_handshake),
  ENT(circuit_timeout),
  ENT(policies),
  ENT(rend_fns),
  ENT(geoip),
  FORK(stats),

  END_OF_TESTCASES
};

#define SOCKSENT(name)                                  \
  { #name, test_socks_##name, TT_FORK, &socks_setup, NULL }

static struct testcase_t socks_tests[] = {
  SOCKSENT(4_unsupported_commands),
  SOCKSENT(4_supported_commands),

  SOCKSENT(5_unsupported_commands),
  SOCKSENT(5_supported_commands),
  SOCKSENT(5_no_authenticate),
  SOCKSENT(5_auth_before_negotiation),
  SOCKSENT(5_authenticate),
  SOCKSENT(5_authenticate_with_data),

  END_OF_TESTCASES
};

extern struct testcase_t addr_tests[];
extern struct testcase_t crypto_tests[];
extern struct testcase_t container_tests[];
extern struct testcase_t util_tests[];
extern struct testcase_t dir_tests[];
extern struct testcase_t microdesc_tests[];
extern struct testcase_t pt_tests[];
extern struct testcase_t config_tests[];
extern struct testcase_t introduce_tests[];
extern struct testcase_t replaycache_tests[];

static struct testgroup_t testgroups[] = {
  { "", test_array },
  { "socks/", socks_tests },
  { "addr/", addr_tests },
  { "crypto/", crypto_tests },
  { "container/", container_tests },
  { "util/", util_tests },
  { "dir/", dir_tests },
  { "dir/md/", microdesc_tests },
  { "pt/", pt_tests },
  { "config/", config_tests },
  { "replaycache/", replaycache_tests },
  { "introduce/", introduce_tests },
  END_OF_GROUPS
};

/** Main entry point for unit test code: parse the command line, and run
 * some unit tests. */
int
main(int c, const char **v)
{
  or_options_t *options;
  char *errmsg = NULL;
  int i, i_out;
  int loglevel = LOG_ERR;

#ifdef USE_DMALLOC
  {
    int r = CRYPTO_set_mem_ex_functions(tor_malloc_, tor_realloc_, tor_free_);
    tor_assert(r);
  }
#endif

  update_approx_time(time(NULL));
  options = options_new();
  tor_threads_init();
  init_logging();

  for (i_out = i = 1; i < c; ++i) {
    if (!strcmp(v[i], "--warn")) {
      loglevel = LOG_WARN;
    } else if (!strcmp(v[i], "--notice")) {
      loglevel = LOG_NOTICE;
    } else if (!strcmp(v[i], "--info")) {
      loglevel = LOG_INFO;
    } else if (!strcmp(v[i], "--debug")) {
      loglevel = LOG_DEBUG;
    } else {
      v[i_out++] = v[i];
    }
  }
  c = i_out;

  {
    log_severity_list_t s;
    memset(&s, 0, sizeof(s));
    set_log_severity_config(loglevel, LOG_ERR, &s);
    add_stream_log(&s, "", fileno(stdout));
  }

  options->command = CMD_RUN_UNITTESTS;
  if (crypto_global_init(0, NULL, NULL)) {
    printf("Can't initialize crypto subsystem; exiting.\n");
    return 1;
  }
  crypto_set_tls_dh_prime(NULL);
  rep_hist_init();
  network_init();
  setup_directory();
  options_init(options);
  options->DataDirectory = tor_strdup(temp_dir);
  options->EntryStatistics = 1;
  if (set_options(options, &errmsg) < 0) {
    printf("Failed to set initial options: %s\n", errmsg);
    tor_free(errmsg);
    return 1;
  }

  crypto_seed_rng(1);

  atexit(remove_directory);

  have_failed = (tinytest_main(c, v, testgroups) != 0);

  free_pregenerated_keys();
#ifdef USE_DMALLOC
  tor_free_all(0);
  dmalloc_log_unfreed();
#endif

  if (have_failed)
    return 1;
  else
    return 0;
}

