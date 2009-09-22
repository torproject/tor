/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2009, The Tor Project, Inc. */
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

#ifdef MS_WINDOWS
/* For mkdir() */
#include <direct.h>
#else
#include <dirent.h>
#endif

/* These macros pull in declarations for some functions and structures that
 * are typically file-private. */
#define BUFFERS_PRIVATE
#define CONFIG_PRIVATE
#define DIRSERV_PRIVATE
#define DIRVOTE_PRIVATE
#define GEOIP_PRIVATE
#define ROUTER_PRIVATE
#define CIRCUIT_PRIVATE

/*
 * Linux doesn't provide lround in math.h by default, but mac os does...
 * It's best just to leave math.h out of the picture entirely.
 */
//#include <math.h>
long int lround(double x);
double fabs(double x);

#include "or.h"
#include "test.h"
#include "torgzip.h"
#include "mempool.h"
#include "memarea.h"

#ifdef USE_DMALLOC
#include <dmalloc.h>
#include <openssl/crypto.h>
#endif

/** Set to true if any unit test has failed.  Mostly, this is set by the macros
 * in test.h */
int have_failed = 0;

/** Temporary directory (set up by setup_directory) under which we store all
 * our files during testing. */
static char temp_dir[256];

/** Select and create the temporary directory we'll use to run our unit tests.
 * Store it in <b>temp_dir</b>.  Exit immediately if we can't create it.
 * idempotent. */
static void
setup_directory(void)
{
  static int is_setup = 0;
  int r;
  if (is_setup) return;

#ifdef MS_WINDOWS
  // XXXX
  tor_snprintf(temp_dir, sizeof(temp_dir),
               "c:\\windows\\temp\\tor_test_%d", (int)getpid());
  r = mkdir(temp_dir);
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
}

/** Return a filename relative to our testing temporary directory */
const char *
get_fname(const char *name)
{
  static char buf[1024];
  setup_directory();
  tor_snprintf(buf,sizeof(buf),"%s/%s",temp_dir,name);
  return buf;
}

/** Remove all files stored under the temporary directory, and the directory
 * itself. */
static void
remove_directory(void)
{
  smartlist_t *elements = tor_listdir(temp_dir);
  if (elements) {
    SMARTLIST_FOREACH(elements, const char *, cp,
       {
         size_t len = strlen(cp)+strlen(temp_dir)+16;
         char *tmp = tor_malloc(len);
         tor_snprintf(tmp, len, "%s"PATH_SEPARATOR"%s", temp_dir, cp);
         unlink(tmp);
         tor_free(tmp);
       });
    SMARTLIST_FOREACH(elements, char *, cp, tor_free(cp));
    smartlist_free(elements);
  }
  rmdir(temp_dir);
}

/** Define this if unit tests spend too much time generating public keys*/
#undef CACHE_GENERATED_KEYS

static crypto_pk_env_t *pregen_keys[5] = {NULL, NULL, NULL, NULL, NULL};
#define N_PREGEN_KEYS ((int)(sizeof(pregen_keys)/sizeof(pregen_keys[0])))

/** Generate and return a new keypair for use in unit tests.  If we're using
 * the key cache optimization, we might reuse keys: we only guarantee that
 * keys made with distinct values for <b>idx</b> are different.  The value of
 * <b>idx</b> must be at least 0, and less than N_PREGEN_KEYS. */
crypto_pk_env_t *
pk_generate(int idx)
{
#ifdef CACHE_GENERATED_KEYS
  tor_assert(idx < N_PREGEN_KEYS);
  if (! pregen_keys[idx]) {
    pregen_keys[idx] = crypto_new_pk_env();
    tor_assert(!crypto_pk_generate_key(pregen_keys[idx]));
  }
  return crypto_pk_dup_key(pregen_keys[idx]);
#else
  crypto_pk_env_t *result;
  (void) idx;
  result = crypto_new_pk_env();
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
      crypto_free_pk_env(pregen_keys[idx]);
      pregen_keys[idx] = NULL;
    }
  }
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

#if 0
  {
  int s;
  int eof;
  int i;
  buf_t *buf2;
  /****
   * read_to_buf
   ****/
  s = open(get_fname("data"), O_WRONLY|O_CREAT|O_TRUNC, 0600);
  write(s, str, 256);
  close(s);

  s = open(get_fname("data"), O_RDONLY, 0);
  eof = 0;
  errno = 0; /* XXXX */
  i = read_to_buf(s, 10, buf, &eof);
  printf("%s\n", strerror(errno));
  test_eq(i, 10);
  test_eq(eof, 0);
  //test_eq(buf_capacity(buf), 4096);
  test_eq(buf_datalen(buf), 10);

  test_memeq(str, (char*)_buf_peek_raw_buffer(buf), 10);

  /* Test reading 0 bytes. */
  i = read_to_buf(s, 0, buf, &eof);
  //test_eq(buf_capacity(buf), 512*1024);
  test_eq(buf_datalen(buf), 10);
  test_eq(eof, 0);
  test_eq(i, 0);

  /* Now test when buffer is filled exactly. */
  buf2 = buf_new_with_capacity(6);
  i = read_to_buf(s, 6, buf2, &eof);
  //test_eq(buf_capacity(buf2), 6);
  test_eq(buf_datalen(buf2), 6);
  test_eq(eof, 0);
  test_eq(i, 6);
  test_memeq(str+10, (char*)_buf_peek_raw_buffer(buf2), 6);
  buf_free(buf2);
  buf2 = NULL;

  /* Now test when buffer is filled with more data to read. */
  buf2 = buf_new_with_capacity(32);
  i = read_to_buf(s, 128, buf2, &eof);
  //test_eq(buf_capacity(buf2), 128);
  test_eq(buf_datalen(buf2), 32);
  test_eq(eof, 0);
  test_eq(i, 32);
  buf_free(buf2);
  buf2 = NULL;

  /* Now read to eof. */
  test_assert(buf_capacity(buf) > 256);
  i = read_to_buf(s, 1024, buf, &eof);
  test_eq(i, (256-32-10-6));
  test_eq(buf_capacity(buf), MAX_BUF_SIZE);
  test_eq(buf_datalen(buf), 256-6-32);
  test_memeq(str, (char*)_buf_peek_raw_buffer(buf), 10); /* XXX Check rest. */
  test_eq(eof, 0);

  i = read_to_buf(s, 1024, buf, &eof);
  test_eq(i, 0);
  test_eq(buf_capacity(buf), MAX_BUF_SIZE);
  test_eq(buf_datalen(buf), 256-6-32);
  test_eq(eof, 1);
  }
#endif

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
  crypto_dh_env_t *c_dh = NULL;
  char c_buf[ONIONSKIN_CHALLENGE_LEN];
  char c_keys[40];

  /* server-side */
  char s_buf[ONIONSKIN_REPLY_LEN];
  char s_keys[40];

  /* shared */
  crypto_pk_env_t *pk = NULL;

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
    crypto_free_pk_env(pk);
}

/** Run unit tests for router descriptor generation logic. */
static void
test_dir_format(void)
{
  char buf[8192], buf2[8192];
  char platform[256];
  char fingerprint[FINGERPRINT_LEN+1];
  char *pk1_str = NULL, *pk2_str = NULL, *pk3_str = NULL, *cp;
  size_t pk1_str_len, pk2_str_len, pk3_str_len;
  routerinfo_t *r1=NULL, *r2=NULL;
  crypto_pk_env_t *pk1 = NULL, *pk2 = NULL, *pk3 = NULL;
  routerinfo_t *rp1 = NULL;
  addr_policy_t *ex1, *ex2;
  routerlist_t *dir1 = NULL, *dir2 = NULL;
  tor_version_t ver1;

  pk1 = pk_generate(0);
  pk2 = pk_generate(1);
  pk3 = pk_generate(2);

  test_assert( is_legal_nickname("a"));
  test_assert(!is_legal_nickname(""));
  test_assert(!is_legal_nickname("abcdefghijklmnopqrst")); /* 20 chars */
  test_assert(!is_legal_nickname("hyphen-")); /* bad char */
  test_assert( is_legal_nickname("abcdefghijklmnopqrs")); /* 19 chars */
  test_assert(!is_legal_nickname("$AAAAAAAA01234AAAAAAAAAAAAAAAAAAAAAAAAAAA"));
  /* valid */
  test_assert( is_legal_nickname_or_hexdigest(
                                 "$AAAAAAAA01234AAAAAAAAAAAAAAAAAAAAAAAAAAA"));
  test_assert( is_legal_nickname_or_hexdigest(
                         "$AAAAAAAA01234AAAAAAAAAAAAAAAAAAAAAAAAAAA=fred"));
  test_assert( is_legal_nickname_or_hexdigest(
                         "$AAAAAAAA01234AAAAAAAAAAAAAAAAAAAAAAAAAAA~fred"));
  /* too short */
  test_assert(!is_legal_nickname_or_hexdigest(
                                 "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
  /* illegal char */
  test_assert(!is_legal_nickname_or_hexdigest(
                                 "$AAAAAAzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
  /* hex part too long */
  test_assert(!is_legal_nickname_or_hexdigest(
                         "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
  test_assert(!is_legal_nickname_or_hexdigest(
                         "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=fred"));
  /* Bad nickname */
  test_assert(!is_legal_nickname_or_hexdigest(
                         "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
  test_assert(!is_legal_nickname_or_hexdigest(
                         "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~"));
  test_assert(!is_legal_nickname_or_hexdigest(
                       "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~hyphen-"));
  test_assert(!is_legal_nickname_or_hexdigest(
                       "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~"
                       "abcdefghijklmnoppqrst"));
  /* Bad extra char. */
  test_assert(!is_legal_nickname_or_hexdigest(
                         "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!"));
  test_assert(is_legal_nickname_or_hexdigest("xyzzy"));
  test_assert(is_legal_nickname_or_hexdigest("abcdefghijklmnopqrs"));
  test_assert(!is_legal_nickname_or_hexdigest("abcdefghijklmnopqrst"));

  get_platform_str(platform, sizeof(platform));
  r1 = tor_malloc_zero(sizeof(routerinfo_t));
  r1->address = tor_strdup("18.244.0.1");
  r1->addr = 0xc0a80001u; /* 192.168.0.1 */
  r1->cache_info.published_on = 0;
  r1->or_port = 9000;
  r1->dir_port = 9003;
  r1->onion_pkey = crypto_pk_dup_key(pk1);
  r1->identity_pkey = crypto_pk_dup_key(pk2);
  r1->bandwidthrate = 1000;
  r1->bandwidthburst = 5000;
  r1->bandwidthcapacity = 10000;
  r1->exit_policy = NULL;
  r1->nickname = tor_strdup("Magri");
  r1->platform = tor_strdup(platform);

  ex1 = tor_malloc_zero(sizeof(addr_policy_t));
  ex2 = tor_malloc_zero(sizeof(addr_policy_t));
  ex1->policy_type = ADDR_POLICY_ACCEPT;
  tor_addr_from_ipv4h(&ex1->addr, 0);
  ex1->maskbits = 0;
  ex1->prt_min = ex1->prt_max = 80;
  ex2->policy_type = ADDR_POLICY_REJECT;
  tor_addr_from_ipv4h(&ex2->addr, 18<<24);
  ex2->maskbits = 8;
  ex2->prt_min = ex2->prt_max = 24;
  r2 = tor_malloc_zero(sizeof(routerinfo_t));
  r2->address = tor_strdup("1.1.1.1");
  r2->addr = 0x0a030201u; /* 10.3.2.1 */
  r2->platform = tor_strdup(platform);
  r2->cache_info.published_on = 5;
  r2->or_port = 9005;
  r2->dir_port = 0;
  r2->onion_pkey = crypto_pk_dup_key(pk2);
  r2->identity_pkey = crypto_pk_dup_key(pk1);
  r2->bandwidthrate = r2->bandwidthburst = r2->bandwidthcapacity = 3000;
  r2->exit_policy = smartlist_create();
  smartlist_add(r2->exit_policy, ex2);
  smartlist_add(r2->exit_policy, ex1);
  r2->nickname = tor_strdup("Fred");

  test_assert(!crypto_pk_write_public_key_to_string(pk1, &pk1_str,
                                                    &pk1_str_len));
  test_assert(!crypto_pk_write_public_key_to_string(pk2 , &pk2_str,
                                                    &pk2_str_len));
  test_assert(!crypto_pk_write_public_key_to_string(pk3 , &pk3_str,
                                                    &pk3_str_len));

  memset(buf, 0, 2048);
  test_assert(router_dump_router_to_string(buf, 2048, r1, pk2)>0);

  strlcpy(buf2, "router Magri 18.244.0.1 9000 0 9003\n"
          "platform Tor "VERSION" on ", sizeof(buf2));
  strlcat(buf2, get_uname(), sizeof(buf2));
  strlcat(buf2, "\n"
          "opt protocols Link 1 2 Circuit 1\n"
          "published 1970-01-01 00:00:00\n"
          "opt fingerprint ", sizeof(buf2));
  test_assert(!crypto_pk_get_fingerprint(pk2, fingerprint, 1));
  strlcat(buf2, fingerprint, sizeof(buf2));
  strlcat(buf2, "\nuptime 0\n"
  /* XXX the "0" above is hard-coded, but even if we made it reflect
   * uptime, that still wouldn't make it right, because the two
   * descriptors might be made on different seconds... hm. */
         "bandwidth 1000 5000 10000\n"
          "opt extra-info-digest 0000000000000000000000000000000000000000\n"
          "onion-key\n", sizeof(buf2));
  strlcat(buf2, pk1_str, sizeof(buf2));
  strlcat(buf2, "signing-key\n", sizeof(buf2));
  strlcat(buf2, pk2_str, sizeof(buf2));
  strlcat(buf2, "opt hidden-service-dir\n", sizeof(buf2));
  strlcat(buf2, "reject *:*\nrouter-signature\n", sizeof(buf2));
  buf[strlen(buf2)] = '\0'; /* Don't compare the sig; it's never the same
                             * twice */

  test_streq(buf, buf2);

  test_assert(router_dump_router_to_string(buf, 2048, r1, pk2)>0);
  cp = buf;
  rp1 = router_parse_entry_from_string((const char*)cp,NULL,1,0,NULL);
  test_assert(rp1);
  test_streq(rp1->address, r1->address);
  test_eq(rp1->or_port, r1->or_port);
  //test_eq(rp1->dir_port, r1->dir_port);
  test_eq(rp1->bandwidthrate, r1->bandwidthrate);
  test_eq(rp1->bandwidthburst, r1->bandwidthburst);
  test_eq(rp1->bandwidthcapacity, r1->bandwidthcapacity);
  test_assert(crypto_pk_cmp_keys(rp1->onion_pkey, pk1) == 0);
  test_assert(crypto_pk_cmp_keys(rp1->identity_pkey, pk2) == 0);
  //test_assert(rp1->exit_policy == NULL);

#if 0
  /* XXX Once we have exit policies, test this again. XXX */
  strlcpy(buf2, "router tor.tor.tor 9005 0 0 3000\n", sizeof(buf2));
  strlcat(buf2, pk2_str, sizeof(buf2));
  strlcat(buf2, "signing-key\n", sizeof(buf2));
  strlcat(buf2, pk1_str, sizeof(buf2));
  strlcat(buf2, "accept *:80\nreject 18.*:24\n\n", sizeof(buf2));
  test_assert(router_dump_router_to_string(buf, 2048, &r2, pk2)>0);
  test_streq(buf, buf2);

  cp = buf;
  rp2 = router_parse_entry_from_string(&cp,1);
  test_assert(rp2);
  test_streq(rp2->address, r2.address);
  test_eq(rp2->or_port, r2.or_port);
  test_eq(rp2->dir_port, r2.dir_port);
  test_eq(rp2->bandwidth, r2.bandwidth);
  test_assert(crypto_pk_cmp_keys(rp2->onion_pkey, pk2) == 0);
  test_assert(crypto_pk_cmp_keys(rp2->identity_pkey, pk1) == 0);
  test_eq(rp2->exit_policy->policy_type, EXIT_POLICY_ACCEPT);
  test_streq(rp2->exit_policy->string, "accept *:80");
  test_streq(rp2->exit_policy->address, "*");
  test_streq(rp2->exit_policy->port, "80");
  test_eq(rp2->exit_policy->next->policy_type, EXIT_POLICY_REJECT);
  test_streq(rp2->exit_policy->next->string, "reject 18.*:24");
  test_streq(rp2->exit_policy->next->address, "18.*");
  test_streq(rp2->exit_policy->next->port, "24");
  test_assert(rp2->exit_policy->next->next == NULL);

  /* Okay, now for the directories. */
  {
    fingerprint_list = smartlist_create();
    crypto_pk_get_fingerprint(pk2, buf, 1);
    add_fingerprint_to_dir("Magri", buf, fingerprint_list);
    crypto_pk_get_fingerprint(pk1, buf, 1);
    add_fingerprint_to_dir("Fred", buf, fingerprint_list);
  }

  {
  char d[DIGEST_LEN];
  const char *m;
  /* XXXX NM re-enable. */
  /* Make sure routers aren't too far in the past any more. */
  r1->cache_info.published_on = time(NULL);
  r2->cache_info.published_on = time(NULL)-3*60*60;
  test_assert(router_dump_router_to_string(buf, 2048, r1, pk2)>0);
  test_eq(dirserv_add_descriptor(buf,&m,""), ROUTER_ADDED_NOTIFY_GENERATOR);
  test_assert(router_dump_router_to_string(buf, 2048, r2, pk1)>0);
  test_eq(dirserv_add_descriptor(buf,&m,""), ROUTER_ADDED_NOTIFY_GENERATOR);
  get_options()->Nickname = tor_strdup("DirServer");
  test_assert(!dirserv_dump_directory_to_string(&cp,pk3, 0));
  crypto_pk_get_digest(pk3, d);
  test_assert(!router_parse_directory(cp));
  test_eq(2, smartlist_len(dir1->routers));
  tor_free(cp);
  }
#endif
  dirserv_free_fingerprint_list();

  /* Try out version parsing functionality */
  test_eq(0, tor_version_parse("0.3.4pre2-cvs", &ver1));
  test_eq(0, ver1.major);
  test_eq(3, ver1.minor);
  test_eq(4, ver1.micro);
  test_eq(VER_PRE, ver1.status);
  test_eq(2, ver1.patchlevel);
  test_eq(0, tor_version_parse("0.3.4rc1", &ver1));
  test_eq(0, ver1.major);
  test_eq(3, ver1.minor);
  test_eq(4, ver1.micro);
  test_eq(VER_RC, ver1.status);
  test_eq(1, ver1.patchlevel);
  test_eq(0, tor_version_parse("1.3.4", &ver1));
  test_eq(1, ver1.major);
  test_eq(3, ver1.minor);
  test_eq(4, ver1.micro);
  test_eq(VER_RELEASE, ver1.status);
  test_eq(0, ver1.patchlevel);
  test_eq(0, tor_version_parse("1.3.4.999", &ver1));
  test_eq(1, ver1.major);
  test_eq(3, ver1.minor);
  test_eq(4, ver1.micro);
  test_eq(VER_RELEASE, ver1.status);
  test_eq(999, ver1.patchlevel);
  test_eq(0, tor_version_parse("0.1.2.4-alpha", &ver1));
  test_eq(0, ver1.major);
  test_eq(1, ver1.minor);
  test_eq(2, ver1.micro);
  test_eq(4, ver1.patchlevel);
  test_eq(VER_RELEASE, ver1.status);
  test_streq("alpha", ver1.status_tag);
  test_eq(0, tor_version_parse("0.1.2.4", &ver1));
  test_eq(0, ver1.major);
  test_eq(1, ver1.minor);
  test_eq(2, ver1.micro);
  test_eq(4, ver1.patchlevel);
  test_eq(VER_RELEASE, ver1.status);
  test_streq("", ver1.status_tag);

#define tt_versionstatus_op(vs1, op, vs2)                               \
  tt_assert_test_type(vs1,vs2,#vs1" "#op" "#vs2,version_status_t,       \
                      (_val1 op _val2),"%d")
#define test_v_i_o(val, ver, lst)                                       \
  tt_versionstatus_op(val, ==, tor_version_is_obsolete(ver, lst))

  /* make sure tor_version_is_obsolete() works */
  test_v_i_o(VS_OLD, "0.0.1", "Tor 0.0.2");
  test_v_i_o(VS_OLD, "0.0.1", "0.0.2, Tor 0.0.3");
  test_v_i_o(VS_OLD, "0.0.1", "0.0.2,Tor 0.0.3");
  test_v_i_o(VS_OLD, "0.0.1","0.0.3,BetterTor 0.0.1");
  test_v_i_o(VS_RECOMMENDED, "0.0.2", "Tor 0.0.2,Tor 0.0.3");
  test_v_i_o(VS_NEW_IN_SERIES, "0.0.2", "Tor 0.0.2pre1,Tor 0.0.3");
  test_v_i_o(VS_OLD, "0.0.2", "Tor 0.0.2.1,Tor 0.0.3");
  test_v_i_o(VS_NEW, "0.1.0", "Tor 0.0.2,Tor 0.0.3");
  test_v_i_o(VS_RECOMMENDED, "0.0.7rc2", "0.0.7,Tor 0.0.7rc2,Tor 0.0.8");
  test_v_i_o(VS_OLD, "0.0.5.0", "0.0.5.1-cvs");
  test_v_i_o(VS_NEW_IN_SERIES, "0.0.5.1-cvs", "0.0.5, 0.0.6");
  /* Not on list, but newer than any in same series. */
  test_v_i_o(VS_NEW_IN_SERIES, "0.1.0.3",
             "Tor 0.1.0.2,Tor 0.0.9.5,Tor 0.1.1.0");
  /* Series newer than any on list. */
  test_v_i_o(VS_NEW, "0.1.2.3", "Tor 0.1.0.2,Tor 0.0.9.5,Tor 0.1.1.0");
  /* Series older than any on list. */
  test_v_i_o(VS_OLD, "0.0.1.3", "Tor 0.1.0.2,Tor 0.0.9.5,Tor 0.1.1.0");
  /* Not on list, not newer than any on same series. */
  test_v_i_o(VS_UNRECOMMENDED, "0.1.0.1",
             "Tor 0.1.0.2,Tor 0.0.9.5,Tor 0.1.1.0");
  /* On list, not newer than any on same series. */
  test_v_i_o(VS_UNRECOMMENDED,
             "0.1.0.1", "Tor 0.1.0.2,Tor 0.0.9.5,Tor 0.1.1.0");
  test_eq(0, tor_version_as_new_as("Tor 0.0.5", "0.0.9pre1-cvs"));
  test_eq(1, tor_version_as_new_as(
          "Tor 0.0.8 on Darwin 64-121-192-100.c3-0."
          "sfpo-ubr1.sfrn-sfpo.ca.cable.rcn.com Power Macintosh",
          "0.0.8rc2"));
  test_eq(0, tor_version_as_new_as(
          "Tor 0.0.8 on Darwin 64-121-192-100.c3-0."
          "sfpo-ubr1.sfrn-sfpo.ca.cable.rcn.com Power Macintosh", "0.0.8.2"));

  /* Now try svn revisions. */
  test_eq(1, tor_version_as_new_as("Tor 0.2.1.0-dev (r100)",
                                   "Tor 0.2.1.0-dev (r99)"));
  test_eq(1, tor_version_as_new_as("Tor 0.2.1.0-dev (r100) on Banana Jr",
                                   "Tor 0.2.1.0-dev (r99) on Hal 9000"));
  test_eq(1, tor_version_as_new_as("Tor 0.2.1.0-dev (r100)",
                                   "Tor 0.2.1.0-dev on Colossus"));
  test_eq(0, tor_version_as_new_as("Tor 0.2.1.0-dev (r99)",
                                   "Tor 0.2.1.0-dev (r100)"));
  test_eq(0, tor_version_as_new_as("Tor 0.2.1.0-dev (r99) on MCP",
                                   "Tor 0.2.1.0-dev (r100) on AM"));
  test_eq(0, tor_version_as_new_as("Tor 0.2.1.0-dev",
                                   "Tor 0.2.1.0-dev (r99)"));
  test_eq(1, tor_version_as_new_as("Tor 0.2.1.1",
                                   "Tor 0.2.1.0-dev (r99)"));

  /* Now try git revisions */
  test_eq(0, tor_version_parse("0.5.6.7 (git-ff00ff)", &ver1));
  test_eq(0, ver1.major);
  test_eq(5, ver1.minor);
  test_eq(6, ver1.micro);
  test_eq(7, ver1.patchlevel);
  test_eq(3, ver1.git_tag_len);
  test_memeq(ver1.git_tag, "\xff\x00\xff", 3);
  test_eq(-1, tor_version_parse("0.5.6.7 (git-ff00xx)", &ver1));
  test_eq(-1, tor_version_parse("0.5.6.7 (git-ff00fff)", &ver1));
  test_eq(0, tor_version_parse("0.5.6.7 (git ff00fff)", &ver1));

 done:
  if (r1)
    routerinfo_free(r1);
  if (r2)
    routerinfo_free(r2);

  tor_free(pk1_str);
  tor_free(pk2_str);
  tor_free(pk3_str);
  if (pk1) crypto_free_pk_env(pk1);
  if (pk2) crypto_free_pk_env(pk2);
  if (pk3) crypto_free_pk_env(pk3);
  if (rp1) routerinfo_free(rp1);
  tor_free(dir1); /* XXXX And more !*/
  tor_free(dir2); /* And more !*/
}

/** Run unit tests for misc directory functions. */
static void
test_dirutil(void)
{
  smartlist_t *sl = smartlist_create();
  fp_pair_t *pair;

  dir_split_resource_into_fingerprint_pairs(
       /* Two pairs, out of order, with one duplicate. */
       "73656372657420646174612E0000000000FFFFFF-"
       "557365204145532d32353620696e73746561642e+"
       "73656372657420646174612E0000000000FFFFFF-"
       "557365204145532d32353620696e73746561642e+"
       "48657861646563696d616c2069736e277420736f-"
       "676f6f6420666f7220686964696e6720796f7572.z", sl);

  test_eq(smartlist_len(sl), 2);
  pair = smartlist_get(sl, 0);
  test_memeq(pair->first,  "Hexadecimal isn't so", DIGEST_LEN);
  test_memeq(pair->second, "good for hiding your", DIGEST_LEN);
  pair = smartlist_get(sl, 1);
  test_memeq(pair->first,  "secret data.\0\0\0\0\0\xff\xff\xff", DIGEST_LEN);
  test_memeq(pair->second, "Use AES-256 instead.", DIGEST_LEN);

 done:
  SMARTLIST_FOREACH(sl, fp_pair_t *, pair, tor_free(pair));
  smartlist_free(sl);
}

static void
test_dirutil_measured_bw(void)
{
  measured_bw_line_t mbwl;
  int i;
  const char *lines_pass[] = {
    "node_id=$557365204145532d32353620696e73746561642e bw=1024\n",
    "node_id=$557365204145532d32353620696e73746561642e\t  bw=1024 \n",
    " node_id=$557365204145532d32353620696e73746561642e  bw=1024\n",
    "\tnoise\tnode_id=$557365204145532d32353620696e73746561642e  "
                "bw=1024 junk=007\n",
    "misc=junk node_id=$557365204145532d32353620696e73746561642e  "
                "bw=1024 junk=007\n",
    "end"
  };
  const char *lines_fail[] = {
    /* Test possible python stupidity on input */
    "node_id=None bw=1024\n",
    "node_id=$None bw=1024\n",
    "node_id=$557365204145532d32353620696e73746561642e bw=None\n",
    "node_id=$557365204145532d32353620696e73746561642e bw=1024.0\n",
    "node_id=$557365204145532d32353620696e73746561642e bw=.1024\n",
    "node_id=$557365204145532d32353620696e73746561642e bw=1.024\n",
    "node_id=$557365204145532d32353620696e73746561642e bw=1024 bw=0\n",
    "node_id=$557365204145532d32353620696e73746561642e bw=1024 bw=None\n",
    "node_id=$557365204145532d32353620696e73746561642e bw=-1024\n",
    /* Test incomplete writes due to race conditions, partial copies, etc */
    "node_i",
    "node_i\n",
    "node_id=",
    "node_id=\n",
    "node_id=$557365204145532d32353620696e73746561642e bw=",
    "node_id=$557365204145532d32353620696e73746561642e bw=1024",
    "node_id=$557365204145532d32353620696e73746561642e bw=\n",
    "node_id=$557365204145532d32353620696e7374",
    "node_id=$557365204145532d32353620696e7374\n",
    "",
    "\n",
    " \n ",
    " \n\n",
    /* Test assorted noise */
    " node_id= ",
    "node_id==$557365204145532d32353620696e73746561642e bw==1024\n",
    "node_id=$55736520414552d32353620696e73746561642e bw=1024\n",
    "node_id=557365204145532d32353620696e73746561642e bw=1024\n",
    "node_id= $557365204145532d32353620696e73746561642e bw=0.23\n",
    "end"
  };

  for (i = 0; strcmp(lines_fail[i], "end"); i++) {
    //fprintf(stderr, "Testing: %s\n", lines_fail[i]);
    test_assert(measured_bw_line_parse(&mbwl, lines_fail[i]) == -1);
  }

  for (i = 0; strcmp(lines_pass[i], "end"); i++) {
    //fprintf(stderr, "Testing: %s %d\n", lines_pass[i], TOR_ISSPACE('\n'));
    test_assert(measured_bw_line_parse(&mbwl, lines_pass[i]) == 0);
    test_assert(mbwl.bw == 1024);
    test_assert(strcmp(mbwl.node_hex,
                "557365204145532d32353620696e73746561642e") == 0);
  }

done:
  return;
}

static void
test_dirutil_param_voting(void)
{
  networkstatus_t vote1, vote2, vote3, vote4;
  smartlist_t *votes = smartlist_create();
  char *res = NULL;

  /* dirvote_compute_params only looks at the net_params field of the votes,
     so that's all we need to set.
   */
  memset(&vote1, 0, sizeof(vote1));
  memset(&vote2, 0, sizeof(vote2));
  memset(&vote3, 0, sizeof(vote3));
  memset(&vote4, 0, sizeof(vote4));
  vote1.net_params = smartlist_create();
  vote2.net_params = smartlist_create();
  vote3.net_params = smartlist_create();
  vote4.net_params = smartlist_create();
  smartlist_split_string(vote1.net_params,
                         "ab=90 abcd=20 cw=50 x-yz=-99", NULL, 0, 0);
  smartlist_split_string(vote2.net_params,
                         "ab=27 cw=5 x-yz=88", NULL, 0, 0);
  smartlist_split_string(vote3.net_params,
                         "abcd=20 c=60 cw=500 x-yz=-9 zzzzz=101", NULL, 0, 0);
  smartlist_split_string(vote4.net_params,
                         "ab=900 abcd=200 c=1 cw=51 x-yz=100", NULL, 0, 0);
  test_eq(100, networkstatus_get_param(&vote4, "x-yz", 50));
  test_eq(222, networkstatus_get_param(&vote4, "foobar", 222));

  smartlist_add(votes, &vote1);
  smartlist_add(votes, &vote2);
  smartlist_add(votes, &vote3);
  smartlist_add(votes, &vote4);

  res = dirvote_compute_params(votes);
  test_streq(res,
             "ab=90 abcd=20 c=1 cw=50 x-yz=-9 zzzzz=101");

 done:
  tor_free(res);
  SMARTLIST_FOREACH(vote1.net_params, char *, cp, tor_free(cp));
  SMARTLIST_FOREACH(vote2.net_params, char *, cp, tor_free(cp));
  SMARTLIST_FOREACH(vote3.net_params, char *, cp, tor_free(cp));
  SMARTLIST_FOREACH(vote4.net_params, char *, cp, tor_free(cp));
  smartlist_free(vote1.net_params);
  smartlist_free(vote2.net_params);
  smartlist_free(vote3.net_params);
  smartlist_free(vote4.net_params);

  return;
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
  char *msg;
  int i, runs;
  circuit_build_times_init(&initial);
  circuit_build_times_init(&estimate);
  circuit_build_times_init(&final);

  memset(&state, 0, sizeof(or_state_t));

  circuitbuild_running_unit_tests();
#define timeout0 (build_time_t)(30*1000.0)
  initial.Xm = 750;
  circuit_build_times_initial_alpha(&initial, BUILDTIMEOUT_QUANTILE_CUTOFF,
                                    timeout0);
  do {
    int n = 0;
    for (i=0; i < MIN_CIRCUITS_TO_OBSERVE; i++) {
      if (circuit_build_times_add_time(&estimate,
              circuit_build_times_generate_sample(&initial, 0, 1)) == 0) {
        n++;
      }
    }
    circuit_build_times_update_alpha(&estimate);
    timeout1 = circuit_build_times_calculate_timeout(&estimate,
                                  BUILDTIMEOUT_QUANTILE_CUTOFF);
    circuit_build_times_set_timeout(&estimate);
    log_warn(LD_CIRC, "Timeout is %lf, Xm is %d", timeout1, estimate.Xm);
    /* XXX: 5% distribution error may not be the right metric */
  } while (fabs(circuit_build_times_cdf(&initial, timeout0) -
                circuit_build_times_cdf(&initial, timeout1)) > 0.05
                /* 5% error */
           && estimate.total_build_times < NCIRCUITS_TO_OBSERVE);

  test_assert(estimate.total_build_times < NCIRCUITS_TO_OBSERVE);

  circuit_build_times_update_state(&estimate, &state);
  test_assert(circuit_build_times_parse_state(&final, &state, &msg) == 0);

  circuit_build_times_update_alpha(&final);
  timeout2 = circuit_build_times_calculate_timeout(&final,
                                 BUILDTIMEOUT_QUANTILE_CUTOFF);

  circuit_build_times_set_timeout(&final);
  log_warn(LD_CIRC, "Timeout is %lf, Xm is %d", timeout2, final.Xm);

  test_assert(fabs(circuit_build_times_cdf(&initial, timeout0) -
                   circuit_build_times_cdf(&initial, timeout2)) < 0.05);

  for (runs = 0; runs < 50; runs++) {
    int build_times_idx = 0;
    int total_build_times = 0;

    final.timeout_ms = BUILD_TIMEOUT_INITIAL_VALUE;
    estimate.timeout_ms = BUILD_TIMEOUT_INITIAL_VALUE;

    for (i = 0; i < RECENT_CIRCUITS*2; i++) {
      circuit_build_times_network_circ_success(&estimate);
      circuit_build_times_add_time(&estimate,
            circuit_build_times_generate_sample(&estimate, 0,
                BUILDTIMEOUT_QUANTILE_CUTOFF));
      estimate.have_computed_timeout = 1;
      circuit_build_times_network_circ_success(&estimate);
      circuit_build_times_add_time(&final,
            circuit_build_times_generate_sample(&final, 0,
                BUILDTIMEOUT_QUANTILE_CUTOFF));
      final.have_computed_timeout = 1;
    }

    test_assert(!circuit_build_times_network_check_changed(&estimate));
    test_assert(!circuit_build_times_network_check_changed(&final));

    /* Reset liveness to be non-live */
    final.liveness.network_last_live = 0;
    estimate.liveness.network_last_live = 0;

    build_times_idx = estimate.build_times_idx;
    total_build_times = estimate.total_build_times;
    for (i = 0; i < NETWORK_NONLIVE_TIMEOUT_COUNT; i++) {
      test_assert(circuit_build_times_network_check_live(&estimate));
      test_assert(circuit_build_times_network_check_live(&final));

      if (circuit_build_times_add_timeout(&estimate, 0,
                 (time_t)(approx_time()-estimate.timeout_ms/1000.0-1)))
        estimate.have_computed_timeout = 1;
      if (circuit_build_times_add_timeout(&final, 0,
                 (time_t)(approx_time()-final.timeout_ms/1000.0-1)))
        final.have_computed_timeout = 1;
    }

    test_assert(!circuit_build_times_network_check_live(&estimate));
    test_assert(!circuit_build_times_network_check_live(&final));

    for ( ; i < NETWORK_NONLIVE_DISCARD_COUNT; i++) {
      if (circuit_build_times_add_timeout(&estimate, 0,
                (time_t)(approx_time()-estimate.timeout_ms/1000.0-1)))
        estimate.have_computed_timeout = 1;

      if (i < NETWORK_NONLIVE_DISCARD_COUNT-1) {
        if (circuit_build_times_add_timeout(&final, 0,
                (time_t)(approx_time()-final.timeout_ms/1000.0-1)))
          final.have_computed_timeout = 1;
      }
    }

    test_assert(!circuit_build_times_network_check_live(&estimate));
    test_assert(!circuit_build_times_network_check_live(&final));

    log_info(LD_CIRC, "idx: %d %d, tot: %d %d",
             build_times_idx, estimate.build_times_idx,
             total_build_times, estimate.total_build_times);

    /* Check rollback index. Should match top of loop. */
    test_assert(build_times_idx == estimate.build_times_idx);
    test_assert(total_build_times == estimate.total_build_times);

    /* Now simulate that the network has become live and we need
     * a change */
    circuit_build_times_network_is_live(&estimate);
    circuit_build_times_network_is_live(&final);

    for (i = 0; i < MAX_RECENT_TIMEOUT_COUNT; i++) {
      if (circuit_build_times_add_timeout(&estimate, 1, approx_time()-1))
        estimate.have_computed_timeout = 1;

      if (i < MAX_RECENT_TIMEOUT_COUNT-1) {
        if (circuit_build_times_add_timeout(&final, 1, approx_time()-1))
          final.have_computed_timeout = 1;
      }
    }

    test_assert(estimate.liveness.after_firsthop_idx == 0);
    test_assert(final.liveness.after_firsthop_idx ==
                MAX_RECENT_TIMEOUT_COUNT-1);

    test_assert(circuit_build_times_network_check_live(&estimate));
    test_assert(circuit_build_times_network_check_live(&final));

    if (circuit_build_times_add_timeout(&final, 1, approx_time()-1))
      final.have_computed_timeout = 1;

  }

done:
  return;
}

extern const char AUTHORITY_CERT_1[];
extern const char AUTHORITY_SIGNKEY_1[];
extern const char AUTHORITY_CERT_2[];
extern const char AUTHORITY_SIGNKEY_2[];
extern const char AUTHORITY_CERT_3[];
extern const char AUTHORITY_SIGNKEY_3[];

/** Helper: Test that two networkstatus_voter_info_t do in fact represent the
 * same voting authority, and that they do in fact have all the same
 * information. */
static void
test_same_voter(networkstatus_voter_info_t *v1,
                networkstatus_voter_info_t *v2)
{
  test_streq(v1->nickname, v2->nickname);
  test_memeq(v1->identity_digest, v2->identity_digest, DIGEST_LEN);
  test_streq(v1->address, v2->address);
  test_eq(v1->addr, v2->addr);
  test_eq(v1->dir_port, v2->dir_port);
  test_eq(v1->or_port, v2->or_port);
  test_streq(v1->contact, v2->contact);
  test_memeq(v1->vote_digest, v2->vote_digest, DIGEST_LEN);
 done:
  ;
}

/** Helper: Make a new routerinfo containing the right information for a
 * given vote_routerstatus_t. */
static routerinfo_t *
generate_ri_from_rs(const vote_routerstatus_t *vrs)
{
  routerinfo_t *r;
  const routerstatus_t *rs = &vrs->status;
  static time_t published = 0;

  r = tor_malloc_zero(sizeof(routerinfo_t));
  memcpy(r->cache_info.identity_digest, rs->identity_digest, DIGEST_LEN);
  memcpy(r->cache_info.signed_descriptor_digest, rs->descriptor_digest,
         DIGEST_LEN);
  r->cache_info.do_not_cache = 1;
  r->cache_info.routerlist_index = -1;
  r->cache_info.signed_descriptor_body =
    tor_strdup("123456789012345678901234567890123");
  r->cache_info.signed_descriptor_len =
    strlen(r->cache_info.signed_descriptor_body);
  r->exit_policy = smartlist_create();
  r->cache_info.published_on = ++published + time(NULL);
  return r;
}

/** Run unit tests for generating and parsing V3 consensus networkstatus
 * documents. */
static void
test_v3_networkstatus(void)
{
  authority_cert_t *cert1=NULL, *cert2=NULL, *cert3=NULL;
  crypto_pk_env_t *sign_skey_1=NULL, *sign_skey_2=NULL, *sign_skey_3=NULL;
  crypto_pk_env_t *sign_skey_leg1=NULL;
  const char *msg=NULL;

  time_t now = time(NULL);
  networkstatus_voter_info_t *voter;
  networkstatus_t *vote=NULL, *v1=NULL, *v2=NULL, *v3=NULL, *con=NULL;
  vote_routerstatus_t *vrs;
  routerstatus_t *rs;
  char *v1_text=NULL, *v2_text=NULL, *v3_text=NULL, *consensus_text=NULL, *cp;
  smartlist_t *votes = smartlist_create();

  /* For generating the two other consensuses. */
  char *detached_text1=NULL, *detached_text2=NULL;
  char *consensus_text2=NULL, *consensus_text3=NULL;
  networkstatus_t *con2=NULL, *con3=NULL;
  ns_detached_signatures_t *dsig1=NULL, *dsig2=NULL;

  /* Parse certificates and keys. */
  cert1 = authority_cert_parse_from_string(AUTHORITY_CERT_1, NULL);
  test_assert(cert1);
  test_assert(cert1->is_cross_certified);
  cert2 = authority_cert_parse_from_string(AUTHORITY_CERT_2, NULL);
  test_assert(cert2);
  cert3 = authority_cert_parse_from_string(AUTHORITY_CERT_3, NULL);
  test_assert(cert3);
  sign_skey_1 = crypto_new_pk_env();
  sign_skey_2 = crypto_new_pk_env();
  sign_skey_3 = crypto_new_pk_env();
  sign_skey_leg1 = pk_generate(4);

  test_assert(!crypto_pk_read_private_key_from_string(sign_skey_1,
                                                      AUTHORITY_SIGNKEY_1));
  test_assert(!crypto_pk_read_private_key_from_string(sign_skey_2,
                                                      AUTHORITY_SIGNKEY_2));
  test_assert(!crypto_pk_read_private_key_from_string(sign_skey_3,
                                                      AUTHORITY_SIGNKEY_3));

  test_assert(!crypto_pk_cmp_keys(sign_skey_1, cert1->signing_key));
  test_assert(!crypto_pk_cmp_keys(sign_skey_2, cert2->signing_key));

  /*
   * Set up a vote; generate it; try to parse it.
   */
  vote = tor_malloc_zero(sizeof(networkstatus_t));
  vote->type = NS_TYPE_VOTE;
  vote->published = now;
  vote->valid_after = now+1000;
  vote->fresh_until = now+2000;
  vote->valid_until = now+3000;
  vote->vote_seconds = 100;
  vote->dist_seconds = 200;
  vote->supported_methods = smartlist_create();
  smartlist_split_string(vote->supported_methods, "1 2 3", NULL, 0, -1);
  vote->client_versions = tor_strdup("0.1.2.14,0.1.2.15");
  vote->server_versions = tor_strdup("0.1.2.14,0.1.2.15,0.1.2.16");
  vote->known_flags = smartlist_create();
  smartlist_split_string(vote->known_flags,
                     "Authority Exit Fast Guard Running Stable V2Dir Valid",
                     0, SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  vote->voters = smartlist_create();
  voter = tor_malloc_zero(sizeof(networkstatus_voter_info_t));
  voter->nickname = tor_strdup("Voter1");
  voter->address = tor_strdup("1.2.3.4");
  voter->addr = 0x01020304;
  voter->dir_port = 80;
  voter->or_port = 9000;
  voter->contact = tor_strdup("voter@example.com");
  crypto_pk_get_digest(cert1->identity_key, voter->identity_digest);
  smartlist_add(vote->voters, voter);
  vote->cert = authority_cert_dup(cert1);
  vote->net_params = smartlist_create();
  smartlist_split_string(vote->net_params, "circuitwindow=101 foo=990",
                         NULL, 0, 0);
  vote->routerstatus_list = smartlist_create();
  /* add the first routerstatus. */
  vrs = tor_malloc_zero(sizeof(vote_routerstatus_t));
  rs = &vrs->status;
  vrs->version = tor_strdup("0.1.2.14");
  rs->published_on = now-1500;
  strlcpy(rs->nickname, "router2", sizeof(rs->nickname));
  memset(rs->identity_digest, 3, DIGEST_LEN);
  memset(rs->descriptor_digest, 78, DIGEST_LEN);
  rs->addr = 0x99008801;
  rs->or_port = 443;
  rs->dir_port = 8000;
  /* all flags but running cleared */
  rs->is_running = 1;
  smartlist_add(vote->routerstatus_list, vrs);
  test_assert(router_add_to_routerlist(generate_ri_from_rs(vrs), &msg,0,0)>=0);

  /* add the second routerstatus. */
  vrs = tor_malloc_zero(sizeof(vote_routerstatus_t));
  rs = &vrs->status;
  vrs->version = tor_strdup("0.2.0.5");
  rs->published_on = now-1000;
  strlcpy(rs->nickname, "router1", sizeof(rs->nickname));
  memset(rs->identity_digest, 5, DIGEST_LEN);
  memset(rs->descriptor_digest, 77, DIGEST_LEN);
  rs->addr = 0x99009901;
  rs->or_port = 443;
  rs->dir_port = 0;
  rs->is_exit = rs->is_stable = rs->is_fast = rs->is_running =
    rs->is_valid = rs->is_v2_dir = rs->is_possible_guard = 1;
  smartlist_add(vote->routerstatus_list, vrs);
  test_assert(router_add_to_routerlist(generate_ri_from_rs(vrs), &msg,0,0)>=0);

  /* add the third routerstatus. */
  vrs = tor_malloc_zero(sizeof(vote_routerstatus_t));
  rs = &vrs->status;
  vrs->version = tor_strdup("0.1.0.3");
  rs->published_on = now-1000;
  strlcpy(rs->nickname, "router3", sizeof(rs->nickname));
  memset(rs->identity_digest, 33, DIGEST_LEN);
  memset(rs->descriptor_digest, 79, DIGEST_LEN);
  rs->addr = 0xAA009901;
  rs->or_port = 400;
  rs->dir_port = 9999;
  rs->is_authority = rs->is_exit = rs->is_stable = rs->is_fast =
    rs->is_running = rs->is_valid = rs->is_v2_dir = rs->is_possible_guard = 1;
  smartlist_add(vote->routerstatus_list, vrs);
  test_assert(router_add_to_routerlist(generate_ri_from_rs(vrs), &msg,0,0)>=0);

  /* add a fourth routerstatus that is not running. */
  vrs = tor_malloc_zero(sizeof(vote_routerstatus_t));
  rs = &vrs->status;
  vrs->version = tor_strdup("0.1.6.3");
  rs->published_on = now-1000;
  strlcpy(rs->nickname, "router4", sizeof(rs->nickname));
  memset(rs->identity_digest, 34, DIGEST_LEN);
  memset(rs->descriptor_digest, 48, DIGEST_LEN);
  rs->addr = 0xC0000203;
  rs->or_port = 500;
  rs->dir_port = 1999;
  /* Running flag (and others) cleared */
  smartlist_add(vote->routerstatus_list, vrs);
  test_assert(router_add_to_routerlist(generate_ri_from_rs(vrs), &msg,0,0)>=0);

  /* dump the vote and try to parse it. */
  v1_text = format_networkstatus_vote(sign_skey_1, vote);
  test_assert(v1_text);
  v1 = networkstatus_parse_vote_from_string(v1_text, NULL, NS_TYPE_VOTE);
  test_assert(v1);

  /* Make sure the parsed thing was right. */
  test_eq(v1->type, NS_TYPE_VOTE);
  test_eq(v1->published, vote->published);
  test_eq(v1->valid_after, vote->valid_after);
  test_eq(v1->fresh_until, vote->fresh_until);
  test_eq(v1->valid_until, vote->valid_until);
  test_eq(v1->vote_seconds, vote->vote_seconds);
  test_eq(v1->dist_seconds, vote->dist_seconds);
  test_streq(v1->client_versions, vote->client_versions);
  test_streq(v1->server_versions, vote->server_versions);
  test_assert(v1->voters && smartlist_len(v1->voters));
  voter = smartlist_get(v1->voters, 0);
  test_streq(voter->nickname, "Voter1");
  test_streq(voter->address, "1.2.3.4");
  test_eq(voter->addr, 0x01020304);
  test_eq(voter->dir_port, 80);
  test_eq(voter->or_port, 9000);
  test_streq(voter->contact, "voter@example.com");
  test_assert(v1->cert);
  test_assert(!crypto_pk_cmp_keys(sign_skey_1, v1->cert->signing_key));
  cp = smartlist_join_strings(v1->known_flags, ":", 0, NULL);
  test_streq(cp, "Authority:Exit:Fast:Guard:Running:Stable:V2Dir:Valid");
  tor_free(cp);
  test_eq(smartlist_len(v1->routerstatus_list), 4);
  /* Check the first routerstatus. */
  vrs = smartlist_get(v1->routerstatus_list, 0);
  rs = &vrs->status;
  test_streq(vrs->version, "0.1.2.14");
  test_eq(rs->published_on, now-1500);
  test_streq(rs->nickname, "router2");
  test_memeq(rs->identity_digest,
             "\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3",
             DIGEST_LEN);
  test_memeq(rs->descriptor_digest, "NNNNNNNNNNNNNNNNNNNN", DIGEST_LEN);
  test_eq(rs->addr, 0x99008801);
  test_eq(rs->or_port, 443);
  test_eq(rs->dir_port, 8000);
  test_eq(vrs->flags, U64_LITERAL(16)); // no flags except "running"
  /* Check the second routerstatus. */
  vrs = smartlist_get(v1->routerstatus_list, 1);
  rs = &vrs->status;
  test_streq(vrs->version, "0.2.0.5");
  test_eq(rs->published_on, now-1000);
  test_streq(rs->nickname, "router1");
  test_memeq(rs->identity_digest,
             "\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5",
             DIGEST_LEN);
  test_memeq(rs->descriptor_digest, "MMMMMMMMMMMMMMMMMMMM", DIGEST_LEN);
  test_eq(rs->addr, 0x99009901);
  test_eq(rs->or_port, 443);
  test_eq(rs->dir_port, 0);
  test_eq(vrs->flags, U64_LITERAL(254)); // all flags except "authority."

  {
    measured_bw_line_t mbw;
    memset(mbw.node_id, 33, sizeof(mbw.node_id));
    mbw.bw = 1024;
    test_assert(measured_bw_line_apply(&mbw,
                v1->routerstatus_list) == 1);
    vrs = smartlist_get(v1->routerstatus_list, 2);
    test_assert(vrs->status.has_measured_bw &&
                vrs->status.measured_bw == 1024);
  }

  /* Generate second vote. It disagrees on some of the times,
   * and doesn't list versions, and knows some crazy flags */
  vote->published = now+1;
  vote->fresh_until = now+3005;
  vote->dist_seconds = 300;
  authority_cert_free(vote->cert);
  vote->cert = authority_cert_dup(cert2);
  vote->net_params = smartlist_create();
  smartlist_split_string(vote->net_params, "bar=2000000000 circuitwindow=20",
                         NULL, 0, 0);
  tor_free(vote->client_versions);
  tor_free(vote->server_versions);
  voter = smartlist_get(vote->voters, 0);
  tor_free(voter->nickname);
  tor_free(voter->address);
  voter->nickname = tor_strdup("Voter2");
  voter->address = tor_strdup("2.3.4.5");
  voter->addr = 0x02030405;
  crypto_pk_get_digest(cert2->identity_key, voter->identity_digest);
  smartlist_add(vote->known_flags, tor_strdup("MadeOfCheese"));
  smartlist_add(vote->known_flags, tor_strdup("MadeOfTin"));
  smartlist_sort_strings(vote->known_flags);
  vrs = smartlist_get(vote->routerstatus_list, 2);
  smartlist_del_keeporder(vote->routerstatus_list, 2);
  tor_free(vrs->version);
  tor_free(vrs);
  vrs = smartlist_get(vote->routerstatus_list, 0);
  vrs->status.is_fast = 1;
  /* generate and parse. */
  v2_text = format_networkstatus_vote(sign_skey_2, vote);
  test_assert(v2_text);
  v2 = networkstatus_parse_vote_from_string(v2_text, NULL, NS_TYPE_VOTE);
  test_assert(v2);
  /* Check that flags come out right.*/
  cp = smartlist_join_strings(v2->known_flags, ":", 0, NULL);
  test_streq(cp, "Authority:Exit:Fast:Guard:MadeOfCheese:MadeOfTin:"
             "Running:Stable:V2Dir:Valid");
  tor_free(cp);
  vrs = smartlist_get(v2->routerstatus_list, 1);
  /* 1023 - authority(1) - madeofcheese(16) - madeoftin(32) */
  test_eq(vrs->flags, U64_LITERAL(974));

  /* Generate the third vote. */
  vote->published = now;
  vote->fresh_until = now+2003;
  vote->dist_seconds = 250;
  authority_cert_free(vote->cert);
  vote->cert = authority_cert_dup(cert3);
  vote->net_params = smartlist_create();
  smartlist_split_string(vote->net_params, "circuitwindow=80 foo=660",
                         NULL, 0, 0);
  smartlist_add(vote->supported_methods, tor_strdup("4"));
  vote->client_versions = tor_strdup("0.1.2.14,0.1.2.17");
  vote->server_versions = tor_strdup("0.1.2.10,0.1.2.15,0.1.2.16");
  voter = smartlist_get(vote->voters, 0);
  tor_free(voter->nickname);
  tor_free(voter->address);
  voter->nickname = tor_strdup("Voter3");
  voter->address = tor_strdup("3.4.5.6");
  voter->addr = 0x03040506;
  crypto_pk_get_digest(cert3->identity_key, voter->identity_digest);
  /* This one has a legacy id. */
  memset(voter->legacy_id_digest, (int)'A', DIGEST_LEN);
  vrs = smartlist_get(vote->routerstatus_list, 0);
  smartlist_del_keeporder(vote->routerstatus_list, 0);
  tor_free(vrs->version);
  tor_free(vrs);
  vrs = smartlist_get(vote->routerstatus_list, 0);
  memset(vrs->status.descriptor_digest, (int)'Z', DIGEST_LEN);
  test_assert(router_add_to_routerlist(generate_ri_from_rs(vrs), &msg,0,0)>=0);

  v3_text = format_networkstatus_vote(sign_skey_3, vote);
  test_assert(v3_text);

  v3 = networkstatus_parse_vote_from_string(v3_text, NULL, NS_TYPE_VOTE);
  test_assert(v3);

  /* Compute a consensus as voter 3. */
  smartlist_add(votes, v3);
  smartlist_add(votes, v1);
  smartlist_add(votes, v2);
  consensus_text = networkstatus_compute_consensus(votes, 3,
                                                   cert3->identity_key,
                                                   sign_skey_3,
                                                   "AAAAAAAAAAAAAAAAAAAA",
                                                   sign_skey_leg1);
  test_assert(consensus_text);
  con = networkstatus_parse_vote_from_string(consensus_text, NULL,
                                             NS_TYPE_CONSENSUS);
  test_assert(con);
  //log_notice(LD_GENERAL, "<<%s>>\n<<%s>>\n<<%s>>\n",
  //           v1_text, v2_text, v3_text);

  /* Check consensus contents. */
  test_assert(con->type == NS_TYPE_CONSENSUS);
  test_eq(con->published, 0); /* this field only appears in votes. */
  test_eq(con->valid_after, now+1000);
  test_eq(con->fresh_until, now+2003); /* median */
  test_eq(con->valid_until, now+3000);
  test_eq(con->vote_seconds, 100);
  test_eq(con->dist_seconds, 250); /* median */
  test_streq(con->client_versions, "0.1.2.14");
  test_streq(con->server_versions, "0.1.2.15,0.1.2.16");
  cp = smartlist_join_strings(v2->known_flags, ":", 0, NULL);
  test_streq(cp, "Authority:Exit:Fast:Guard:MadeOfCheese:MadeOfTin:"
             "Running:Stable:V2Dir:Valid");
  tor_free(cp);
  cp = smartlist_join_strings(con->net_params, ":", 0, NULL);
  test_streq(cp, "bar=2000000000:circuitwindow=80:foo=660");
  tor_free(cp);

  test_eq(4, smartlist_len(con->voters)); /*3 voters, 1 legacy key.*/
  /* The voter id digests should be in this order. */
  test_assert(memcmp(cert2->cache_info.identity_digest,
                     cert1->cache_info.identity_digest,DIGEST_LEN)<0);
  test_assert(memcmp(cert1->cache_info.identity_digest,
                     cert3->cache_info.identity_digest,DIGEST_LEN)<0);
  test_same_voter(smartlist_get(con->voters, 1),
                  smartlist_get(v2->voters, 0));
  test_same_voter(smartlist_get(con->voters, 2),
                  smartlist_get(v1->voters, 0));
  test_same_voter(smartlist_get(con->voters, 3),
                  smartlist_get(v3->voters, 0));

  test_assert(!con->cert);
  test_eq(2, smartlist_len(con->routerstatus_list));
  /* There should be two listed routers: one with identity 3, one with
   * identity 5. */
  /* This one showed up in 2 digests. */
  rs = smartlist_get(con->routerstatus_list, 0);
  test_memeq(rs->identity_digest,
             "\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3\x3",
             DIGEST_LEN);
  test_memeq(rs->descriptor_digest, "NNNNNNNNNNNNNNNNNNNN", DIGEST_LEN);
  test_assert(!rs->is_authority);
  test_assert(!rs->is_exit);
  test_assert(!rs->is_fast);
  test_assert(!rs->is_possible_guard);
  test_assert(!rs->is_stable);
  test_assert(rs->is_running); /* If it wasn't running it wouldn't be here */
  test_assert(!rs->is_v2_dir);
  test_assert(!rs->is_valid);
  test_assert(!rs->is_named);
  /* XXXX check version */

  rs = smartlist_get(con->routerstatus_list, 1);
  /* This one showed up in 3 digests. Twice with ID 'M', once with 'Z'.  */
  test_memeq(rs->identity_digest,
             "\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5\x5",
             DIGEST_LEN);
  test_streq(rs->nickname, "router1");
  test_memeq(rs->descriptor_digest, "MMMMMMMMMMMMMMMMMMMM", DIGEST_LEN);
  test_eq(rs->published_on, now-1000);
  test_eq(rs->addr, 0x99009901);
  test_eq(rs->or_port, 443);
  test_eq(rs->dir_port, 0);
  test_assert(!rs->is_authority);
  test_assert(rs->is_exit);
  test_assert(rs->is_fast);
  test_assert(rs->is_possible_guard);
  test_assert(rs->is_stable);
  test_assert(rs->is_running);
  test_assert(rs->is_v2_dir);
  test_assert(rs->is_valid);
  test_assert(!rs->is_named);
  /* XXXX check version */
  // x231
  // x213

  /* Check signatures.  the first voter is a pseudo-entry with a legacy key.
   * The second one hasn't signed.  The fourth one has signed: validate it. */
  voter = smartlist_get(con->voters, 1);
  test_assert(!voter->signature);
  test_assert(!voter->good_signature);
  test_assert(!voter->bad_signature);

  voter = smartlist_get(con->voters, 3);
  test_assert(voter->signature);
  test_assert(!voter->good_signature);
  test_assert(!voter->bad_signature);
  test_assert(!networkstatus_check_voter_signature(con,
                                               smartlist_get(con->voters, 3),
                                               cert3));
  test_assert(voter->signature);
  test_assert(voter->good_signature);
  test_assert(!voter->bad_signature);

  {
    const char *msg=NULL;
    /* Compute the other two signed consensuses. */
    smartlist_shuffle(votes);
    consensus_text2 = networkstatus_compute_consensus(votes, 3,
                                                      cert2->identity_key,
                                                      sign_skey_2, NULL,NULL);
    smartlist_shuffle(votes);
    consensus_text3 = networkstatus_compute_consensus(votes, 3,
                                                      cert1->identity_key,
                                                      sign_skey_1, NULL,NULL);
    test_assert(consensus_text2);
    test_assert(consensus_text3);
    con2 = networkstatus_parse_vote_from_string(consensus_text2, NULL,
                                                NS_TYPE_CONSENSUS);
    con3 = networkstatus_parse_vote_from_string(consensus_text3, NULL,
                                                NS_TYPE_CONSENSUS);
    test_assert(con2);
    test_assert(con3);

    /* All three should have the same digest. */
    test_memeq(con->networkstatus_digest, con2->networkstatus_digest,
               DIGEST_LEN);
    test_memeq(con->networkstatus_digest, con3->networkstatus_digest,
               DIGEST_LEN);

    /* Extract a detached signature from con3. */
    detached_text1 = networkstatus_get_detached_signatures(con3);
    tor_assert(detached_text1);
    /* Try to parse it. */
    dsig1 = networkstatus_parse_detached_signatures(detached_text1, NULL);
    tor_assert(dsig1);

    /* Are parsed values as expected? */
    test_eq(dsig1->valid_after, con3->valid_after);
    test_eq(dsig1->fresh_until, con3->fresh_until);
    test_eq(dsig1->valid_until, con3->valid_until);
    test_memeq(dsig1->networkstatus_digest, con3->networkstatus_digest,
               DIGEST_LEN);
    test_eq(1, smartlist_len(dsig1->signatures));
    voter = smartlist_get(dsig1->signatures, 0);
    test_memeq(voter->identity_digest, cert1->cache_info.identity_digest,
               DIGEST_LEN);

    /* Try adding it to con2. */
    detached_text2 = networkstatus_get_detached_signatures(con2);
    test_eq(1, networkstatus_add_detached_signatures(con2, dsig1, &msg));
    tor_free(detached_text2);
    detached_text2 = networkstatus_get_detached_signatures(con2);
    //printf("\n<%s>\n", detached_text2);
    dsig2 = networkstatus_parse_detached_signatures(detached_text2, NULL);
    test_assert(dsig2);
    /*
    printf("\n");
    SMARTLIST_FOREACH(dsig2->signatures, networkstatus_voter_info_t *, vi, {
        char hd[64];
        base16_encode(hd, sizeof(hd), vi->identity_digest, DIGEST_LEN);
        printf("%s\n", hd);
      });
    */
    test_eq(2, smartlist_len(dsig2->signatures));

    /* Try adding to con2 twice; verify that nothing changes. */
    test_eq(0, networkstatus_add_detached_signatures(con2, dsig1, &msg));

    /* Add to con. */
    test_eq(2, networkstatus_add_detached_signatures(con, dsig2, &msg));
    /* Check signatures */
    test_assert(!networkstatus_check_voter_signature(con,
                                               smartlist_get(con->voters, 1),
                                               cert2));
    test_assert(!networkstatus_check_voter_signature(con,
                                               smartlist_get(con->voters, 2),
                                               cert1));

  }

 done:
  smartlist_free(votes);
  tor_free(v1_text);
  tor_free(v2_text);
  tor_free(v3_text);
  tor_free(consensus_text);

  if (vote)
    networkstatus_vote_free(vote);
  if (v1)
    networkstatus_vote_free(v1);
  if (v2)
    networkstatus_vote_free(v2);
  if (v3)
    networkstatus_vote_free(v3);
  if (con)
    networkstatus_vote_free(con);
  if (sign_skey_1)
    crypto_free_pk_env(sign_skey_1);
  if (sign_skey_2)
    crypto_free_pk_env(sign_skey_2);
  if (sign_skey_3)
    crypto_free_pk_env(sign_skey_3);
  if (sign_skey_leg1)
    crypto_free_pk_env(sign_skey_leg1);
  if (cert1)
    authority_cert_free(cert1);
  if (cert2)
    authority_cert_free(cert2);
  if (cert3)
    authority_cert_free(cert3);

  tor_free(consensus_text2);
  tor_free(consensus_text3);
  tor_free(detached_text1);
  tor_free(detached_text2);
  if (con2)
    networkstatus_vote_free(con2);
  if (con3)
    networkstatus_vote_free(con3);
  if (dsig1)
    ns_detached_signatures_free(dsig1);
  if (dsig2)
    ns_detached_signatures_free(dsig2);
}

/** Helper: Parse the exit policy string in <b>policy_str</b>, and make sure
 * that policies_summarize() produces the string <b>expected_summary</b> from
 * it. */
static void
test_policy_summary_helper(const char *policy_str,
                           const char *expected_summary)
{
  config_line_t line;
  smartlist_t *policy = smartlist_create();
  char *summary = NULL;
  int r;

  line.key = (char*)"foo";
  line.value = (char *)policy_str;
  line.next = NULL;

  r = policies_parse_exit_policy(&line, &policy, 0, NULL);
  test_eq(r, 0);
  summary = policy_summarize(policy);

  test_assert(summary != NULL);
  test_streq(summary, expected_summary);

 done:
  tor_free(summary);
  if (policy)
    addr_policy_list_free(policy);
}

/** Run unit tests for generating summary lines of exit policies */
static void
test_policies(void)
{
  int i;
  smartlist_t *policy = NULL, *policy2 = NULL;
  addr_policy_t *p;
  tor_addr_t tar;
  config_line_t line;
  smartlist_t *sm = NULL;
  char *policy_str = NULL;

  policy = smartlist_create();

  p = router_parse_addr_policy_item_from_string("reject 192.168.0.0/16:*",-1);
  test_assert(p != NULL);
  test_eq(ADDR_POLICY_REJECT, p->policy_type);
  tor_addr_from_ipv4h(&tar, 0xc0a80000u);
  test_eq(0, tor_addr_compare(&p->addr, &tar, CMP_EXACT));
  test_eq(16, p->maskbits);
  test_eq(1, p->prt_min);
  test_eq(65535, p->prt_max);

  smartlist_add(policy, p);

  test_assert(ADDR_POLICY_ACCEPTED ==
          compare_addr_to_addr_policy(0x01020304u, 2, policy));
  test_assert(ADDR_POLICY_PROBABLY_ACCEPTED ==
          compare_addr_to_addr_policy(0, 2, policy));
  test_assert(ADDR_POLICY_REJECTED ==
          compare_addr_to_addr_policy(0xc0a80102, 2, policy));

  policy2 = NULL;
  test_assert(0 == policies_parse_exit_policy(NULL, &policy2, 1, NULL));
  test_assert(policy2);

  test_assert(!exit_policy_is_general_exit(policy));
  test_assert(exit_policy_is_general_exit(policy2));
  test_assert(!exit_policy_is_general_exit(NULL));

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
  test_assert(0 == policies_parse_exit_policy(&line, &policy, 0, NULL));
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

  /* truncation ports */
  sm = smartlist_create();
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
  if (policy)
    addr_policy_list_free(policy);
  if (policy2)
    addr_policy_list_free(policy2);
  tor_free(policy_str);
  if (sm) {
    SMARTLIST_FOREACH(sm, char *, s, tor_free(s));
    smartlist_free(sm);
  }
}

/** Run AES performance benchmarks. */
static void
bench_aes(void)
{
  int len, i;
  char *b1, *b2;
  crypto_cipher_env_t *c;
  struct timeval start, end;
  const int iters = 100000;
  uint64_t nsec;
  c = crypto_new_cipher_env();
  crypto_cipher_generate_key(c);
  crypto_cipher_encrypt_init_cipher(c);
  for (len = 1; len <= 8192; len *= 2) {
    b1 = tor_malloc_zero(len);
    b2 = tor_malloc_zero(len);
    tor_gettimeofday(&start);
    for (i = 0; i < iters; ++i) {
      crypto_cipher_encrypt(c, b1, b2, len);
    }
    tor_gettimeofday(&end);
    tor_free(b1);
    tor_free(b2);
    nsec = (uint64_t) tv_udiff(&start,&end);
    nsec *= 1000;
    nsec /= (iters*len);
    printf("%d bytes: "U64_FORMAT" nsec per byte\n", len,
           U64_PRINTF_ARG(nsec));
  }
  crypto_free_cipher_env(c);
}

/** Run digestmap_t performance benchmarks. */
static void
bench_dmap(void)
{
  smartlist_t *sl = smartlist_create();
  smartlist_t *sl2 = smartlist_create();
  struct timeval start, end, pt2, pt3, pt4;
  const int iters = 10000;
  const int elts = 4000;
  const int fpostests = 1000000;
  char d[20];
  int i,n=0, fp = 0;
  digestmap_t *dm = digestmap_new();
  digestset_t *ds = digestset_new(elts);

  for (i = 0; i < elts; ++i) {
    crypto_rand(d, 20);
    smartlist_add(sl, tor_memdup(d, 20));
  }
  for (i = 0; i < elts; ++i) {
    crypto_rand(d, 20);
    smartlist_add(sl2, tor_memdup(d, 20));
  }
  printf("nbits=%d\n", ds->mask+1);

  tor_gettimeofday(&start);
  for (i = 0; i < iters; ++i) {
    SMARTLIST_FOREACH(sl, const char *, cp, digestmap_set(dm, cp, (void*)1));
  }
  tor_gettimeofday(&pt2);
  for (i = 0; i < iters; ++i) {
    SMARTLIST_FOREACH(sl, const char *, cp, digestmap_get(dm, cp));
    SMARTLIST_FOREACH(sl2, const char *, cp, digestmap_get(dm, cp));
  }
  tor_gettimeofday(&pt3);
  for (i = 0; i < iters; ++i) {
    SMARTLIST_FOREACH(sl, const char *, cp, digestset_add(ds, cp));
  }
  tor_gettimeofday(&pt4);
  for (i = 0; i < iters; ++i) {
    SMARTLIST_FOREACH(sl, const char *, cp, n += digestset_isin(ds, cp));
    SMARTLIST_FOREACH(sl2, const char *, cp, n += digestset_isin(ds, cp));
  }
  tor_gettimeofday(&end);

  for (i = 0; i < fpostests; ++i) {
    crypto_rand(d, 20);
    if (digestset_isin(ds, d)) ++fp;
  }

  printf("%ld\n",(unsigned long)tv_udiff(&start, &pt2));
  printf("%ld\n",(unsigned long)tv_udiff(&pt2, &pt3));
  printf("%ld\n",(unsigned long)tv_udiff(&pt3, &pt4));
  printf("%ld\n",(unsigned long)tv_udiff(&pt4, &end));
  printf("-- %d\n", n);
  printf("++ %f\n", fp/(double)fpostests);
  digestmap_free(dm, NULL);
  digestset_free(ds);
  SMARTLIST_FOREACH(sl, char *, cp, tor_free(cp));
  SMARTLIST_FOREACH(sl2, char *, cp, tor_free(cp));
  smartlist_free(sl);
  smartlist_free(sl2);
}


/** Test encoding and parsing of rendezvous service descriptors. */
static void
test_rend_fns(void)
{
  rend_service_descriptor_t *generated = NULL, *parsed = NULL;
  char service_id[DIGEST_LEN];
  char service_id_base32[REND_SERVICE_ID_LEN_BASE32+1];
  const char *next_desc;
  smartlist_t *descs = smartlist_create();
  char computed_desc_id[DIGEST_LEN];
  char parsed_desc_id[DIGEST_LEN];
  crypto_pk_env_t *pk1 = NULL, *pk2 = NULL;
  time_t now;
  char *intro_points_encrypted = NULL;
  size_t intro_points_size;
  size_t encoded_size;
  int i;
  char address1[] = "fooaddress.onion";
  char address2[] = "aaaaaaaaaaaaaaaa.onion";
  char address3[] = "fooaddress.exit";
  char address4[] = "www.torproject.org";

  test_assert(BAD_HOSTNAME == parse_extended_hostname(address1, 1));
  test_assert(ONION_HOSTNAME == parse_extended_hostname(address2, 1));
  test_assert(EXIT_HOSTNAME == parse_extended_hostname(address3, 1));
  test_assert(NORMAL_HOSTNAME == parse_extended_hostname(address4, 1));

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
  generated->intro_nodes = smartlist_create();

  for (i = 0; i < 3; i++) {
    rend_intro_point_t *intro = tor_malloc_zero(sizeof(rend_intro_point_t));
    crypto_pk_env_t *okey = pk_generate(2 + i);
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
    intro->extend_info->port = crypto_rand_int(65536);
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
    crypto_free_pk_env(pk1);
  if (pk2)
    crypto_free_pk_env(pk2);
  tor_free(intro_points_encrypted);
}

/** Run unit tests for GeoIP code. */
static void
test_geoip(void)
{
  int i, j;
  time_t now = time(NULL);
  char *s = NULL;

  /* Populate the DB a bit.  Add these in order, since we can't do the final
   * 'sort' step.  These aren't very good IP addresses, but they're perfectly
   * fine uint32_t values. */
  test_eq(0, geoip_parse_entry("10,50,AB"));
  test_eq(0, geoip_parse_entry("52,90,XY"));
  test_eq(0, geoip_parse_entry("95,100,AB"));
  test_eq(0, geoip_parse_entry("\"105\",\"140\",\"ZZ\""));
  test_eq(0, geoip_parse_entry("\"150\",\"190\",\"XY\""));
  test_eq(0, geoip_parse_entry("\"200\",\"250\",\"AB\""));

  /* We should have 3 countries: ab, xy, zz. */
  test_eq(3, geoip_get_n_countries());
  /* Make sure that country ID actually works. */
#define NAMEFOR(x) geoip_get_country_name(geoip_get_country_by_ip(x))
  test_streq("ab", NAMEFOR(32));
  test_streq("??", NAMEFOR(5));
  test_streq("??", NAMEFOR(51));
  test_streq("xy", NAMEFOR(150));
  test_streq("xy", NAMEFOR(190));
  test_streq("??", NAMEFOR(2000));
#undef NAMEFOR

  get_options()->BridgeRelay = 1;
  get_options()->BridgeRecordUsageByCountry = 1;
  /* Put 9 observations in AB... */
  for (i=32; i < 40; ++i)
    geoip_note_client_seen(GEOIP_CLIENT_CONNECT, i, now-7200);
  geoip_note_client_seen(GEOIP_CLIENT_CONNECT, 225, now-7200);
  /* and 3 observations in XY, several times. */
  for (j=0; j < 10; ++j)
    for (i=52; i < 55; ++i)
      geoip_note_client_seen(GEOIP_CLIENT_CONNECT, i, now-3600);
  /* and 17 observations in ZZ... */
  for (i=110; i < 127; ++i)
    geoip_note_client_seen(GEOIP_CLIENT_CONNECT, i, now);
  s = geoip_get_client_history_bridge(now+5*24*60*60,
                                      GEOIP_CLIENT_CONNECT);
  test_assert(s);
  test_streq("zz=24,ab=16,xy=8", s);
  tor_free(s);

  /* Now clear out all the AB observations. */
  geoip_remove_old_clients(now-6000);
  s = geoip_get_client_history_bridge(now+5*24*60*60,
                                      GEOIP_CLIENT_CONNECT);
  test_assert(s);
  test_streq("zz=24,xy=8", s);

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
  { #name, legacy_test_helper, TT_SKIP, &legacy_setup, name }

static struct testcase_t test_array[] = {
  ENT(buffers),
  ENT(onion_handshake),
  ENT(dir_format),
  ENT(dirutil),
  SUBENT(dirutil, measured_bw),
  SUBENT(dirutil, param_voting),
  ENT(circuit_timeout),
  ENT(v3_networkstatus),
  ENT(policies),
  ENT(rend_fns),
  ENT(geoip),

  DISABLED(bench_aes),
  DISABLED(bench_dmap),
  END_OF_TESTCASES
};

extern struct testcase_t addr_tests[];
extern struct testcase_t crypto_tests[];
extern struct testcase_t container_tests[];
extern struct testcase_t util_tests[];

static struct testgroup_t testgroups[] = {
  { "", test_array },
  { "addr/", addr_tests },
  { "crypto/", crypto_tests },
  { "container/", container_tests },
  { "util/", util_tests },
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
    int r = CRYPTO_set_mem_ex_functions(_tor_malloc, _tor_realloc, _tor_free);
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
  crypto_global_init(0, NULL, NULL);
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

  have_failed = (tinytest_main(c, v, testgroups) < 0);

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

