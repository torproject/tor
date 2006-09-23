/* Copyright 2001-2004 Roger Dingledine.
 * Copyright 2004-2006 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char test_c_id[] =
  "$Id$";

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

#include "or.h"
#include "../common/test.h"
#include "../common/torgzip.h"

int have_failed = 0;

/* These functions are file-local, but are exposed so we can test. */
void add_fingerprint_to_dir(const char *nickname, const char *fp,
                            smartlist_t *list);
void get_platform_str(char *platform, size_t len);
size_t read_escaped_data(const char *data, size_t len, int translate_newlines,
                         char **out);
or_options_t *options_new(void);

static char temp_dir[256];

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

static const char *
get_fname(const char *name)
{
  static char buf[1024];
  setup_directory();
  tor_snprintf(buf,sizeof(buf),"%s/%s",temp_dir,name);
  return buf;
}

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

static void
test_buffers(void)
{
  char str[256];
  char str2[256];

  buf_t *buf;

  int j;

  /****
   * buf_new
   ****/
  if (!(buf = buf_new()))
    test_fail();

  test_eq(buf_capacity(buf), 4096);
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

  /* Okay, now make sure growing can work. */
  buf = buf_new_with_capacity(16);
  test_eq(buf_capacity(buf), 16);
  write_to_buf(str+1, 255, buf);
  test_eq(buf_capacity(buf), 256);
  fetch_from_buf(str2, 254, buf);
  test_memeq(str+1, str2, 254);
  test_eq(buf_capacity(buf), 256);
  assert_buf_ok(buf);
  write_to_buf(str, 32, buf);
  test_eq(buf_capacity(buf), 256);
  assert_buf_ok(buf);
  write_to_buf(str, 256, buf);
  assert_buf_ok(buf);
  test_eq(buf_capacity(buf), 512);
  test_eq(buf_datalen(buf), 33+256);
  fetch_from_buf(str2, 33, buf);
  test_eq(*str2, str[255]);

  test_memeq(str2+1, str, 32);
  test_eq(buf_capacity(buf), 512);
  test_eq(buf_datalen(buf), 256);
  fetch_from_buf(str2, 256, buf);
  test_memeq(str, str2, 256);

  /* now try shrinking: case 1. */
  buf_free(buf);
  buf = buf_new_with_capacity(33668);
  for (j=0;j<67;++j) {
    write_to_buf(str,255, buf);
  }
  test_eq(buf_capacity(buf), 33668);
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
  test_eq(buf_capacity(buf),33668);
  for (j=0; j < 120; ++j) {
    fetch_from_buf(str2, 255,buf);
    test_memeq(str2, str, 255);
  }

#if 0
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
  test_eq(buf_capacity(buf), 4096);
  test_eq(buf_datalen(buf), 10);

  test_memeq(str, (char*)_buf_peek_raw_buffer(buf), 10);

  /* Test reading 0 bytes. */
  i = read_to_buf(s, 0, buf, &eof);
  test_eq(buf_capacity(buf), 512*1024);
  test_eq(buf_datalen(buf), 10);
  test_eq(eof, 0);
  test_eq(i, 0);

  /* Now test when buffer is filled exactly. */
  buf2 = buf_new_with_capacity(6);
  i = read_to_buf(s, 6, buf2, &eof);
  test_eq(buf_capacity(buf2), 6);
  test_eq(buf_datalen(buf2), 6);
  test_eq(eof, 0);
  test_eq(i, 6);
  test_memeq(str+10, (char*)_buf_peek_raw_buffer(buf2), 6);
  buf_free(buf2);

  /* Now test when buffer is filled with more data to read. */
  buf2 = buf_new_with_capacity(32);
  i = read_to_buf(s, 128, buf2, &eof);
  test_eq(buf_capacity(buf2), 128);
  test_eq(buf_datalen(buf2), 32);
  test_eq(eof, 0);
  test_eq(i, 32);
  buf_free(buf2);

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
#endif

  buf_free(buf);
}

static void
test_crypto_dh(void)
{
  crypto_dh_env_t *dh1, *dh2;
  char p1[DH_BYTES];
  char p2[DH_BYTES];
  char s1[DH_BYTES];
  char s2[DH_BYTES];
  int s1len, s2len;

  dh1 = crypto_dh_new();
  dh2 = crypto_dh_new();
  test_eq(crypto_dh_get_bytes(dh1), DH_BYTES);
  test_eq(crypto_dh_get_bytes(dh2), DH_BYTES);

  memset(p1, 0, DH_BYTES);
  memset(p2, 0, DH_BYTES);
  test_memeq(p1, p2, DH_BYTES);
  test_assert(! crypto_dh_get_public(dh1, p1, DH_BYTES));
  test_memneq(p1, p2, DH_BYTES);
  test_assert(! crypto_dh_get_public(dh2, p2, DH_BYTES));
  test_memneq(p1, p2, DH_BYTES);

  memset(s1, 0, DH_BYTES);
  memset(s2, 0xFF, DH_BYTES);
  s1len = crypto_dh_compute_secret(dh1, p2, DH_BYTES, s1, 50);
  s2len = crypto_dh_compute_secret(dh2, p1, DH_BYTES, s2, 50);
  test_assert(s1len > 0);
  test_eq(s1len, s2len);
  test_memeq(s1, s2, s1len);

  crypto_dh_free(dh1);
  crypto_dh_free(dh2);
}

static void
test_crypto(void)
{
  crypto_cipher_env_t *env1, *env2;
  crypto_pk_env_t *pk1, *pk2;
  char *data1, *data2, *data3, *cp;
  int i, j, p, len;
  size_t size;

  data1 = tor_malloc(1024);
  data2 = tor_malloc(1024);
  data3 = tor_malloc(1024);
  test_assert(data1 && data2 && data3);

  /* Try out RNG. */
  test_assert(! crypto_seed_rng());
  crypto_rand(data1, 100);
  crypto_rand(data2, 100);
  test_memneq(data1,data2,100);

#if 0
  /* Try out identity ciphers. */
  env1 = crypto_new_cipher_env(CRYPTO_CIPHER_IDENTITY);
  test_neq(env1, 0);
  test_eq(crypto_cipher_generate_key(env1), 0);
  test_eq(crypto_cipher_encrypt_init_cipher(env1), 0);
  for (i = 0; i < 1024; ++i) {
    data1[i] = (char) i*73;
  }
  crypto_cipher_encrypt(env1, data2, data1, 1024);
  test_memeq(data1, data2, 1024);
  crypto_free_cipher_env(env1);
#endif

  /* Now, test encryption and decryption with stream cipher. */
  data1[0]='\0';
  for (i = 1023; i>0; i -= 35)
    strncat(data1, "Now is the time for all good onions", i);

  memset(data2, 0, 1024);
  memset(data3, 0, 1024);
  env1 = crypto_new_cipher_env();
  test_neq(env1, 0);
  env2 = crypto_new_cipher_env();
  test_neq(env2, 0);
  j = crypto_cipher_generate_key(env1);
  crypto_cipher_set_key(env2, crypto_cipher_get_key(env1));
  crypto_cipher_encrypt_init_cipher(env1);
  crypto_cipher_decrypt_init_cipher(env2);

  /* Try encrypting 512 chars. */
  crypto_cipher_encrypt(env1, data2, data1, 512);
  crypto_cipher_decrypt(env2, data3, data2, 512);
  test_memeq(data1, data3, 512);
  test_memneq(data1, data2, 512);

  /* Now encrypt 1 at a time, and get 1 at a time. */
  for (j = 512; j < 560; ++j) {
    crypto_cipher_encrypt(env1, data2+j, data1+j, 1);
  }
  for (j = 512; j < 560; ++j) {
    crypto_cipher_decrypt(env2, data3+j, data2+j, 1);
  }
  test_memeq(data1, data3, 560);
  /* Now encrypt 3 at a time, and get 5 at a time. */
  for (j = 560; j < 1024-5; j += 3) {
    crypto_cipher_encrypt(env1, data2+j, data1+j, 3);
  }
  for (j = 560; j < 1024-5; j += 5) {
    crypto_cipher_decrypt(env2, data3+j, data2+j, 5);
  }
  test_memeq(data1, data3, 1024-5);
  /* Now make sure that when we encrypt with different chunk sizes, we get
     the same results. */
  crypto_free_cipher_env(env2);

  memset(data3, 0, 1024);
  env2 = crypto_new_cipher_env();
  test_neq(env2, 0);
  crypto_cipher_set_key(env2, crypto_cipher_get_key(env1));
  crypto_cipher_encrypt_init_cipher(env2);
  for (j = 0; j < 1024-16; j += 17) {
    crypto_cipher_encrypt(env2, data3+j, data1+j, 17);
  }
  for (j= 0; j < 1024-16; ++j) {
    if (data2[j] != data3[j]) {
      printf("%d:  %d\t%d\n", j, (int) data2[j], (int) data3[j]);
    }
  }
  test_memeq(data2, data3, 1024-16);
  crypto_free_cipher_env(env1);
  crypto_free_cipher_env(env2);

  /* Test vectors for stream ciphers. */
  /* XXXX Look up some test vectors for the ciphers and make sure we match. */

  /* Test SHA-1 with a test vector from the specification. */
  i = crypto_digest(data1, "abc", 3);
  test_memeq(data1,
             "\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E\x25\x71\x78"
             "\x50\xC2\x6C\x9C\xD0\xD8\x9D", 20);

  /* Public-key ciphers */
  pk1 = crypto_new_pk_env();
  pk2 = crypto_new_pk_env();
  test_assert(pk1 && pk2);
  test_assert(! crypto_pk_generate_key(pk1));
  test_assert(! crypto_pk_write_public_key_to_string(pk1, &cp, &size));
  test_assert(! crypto_pk_read_public_key_from_string(pk2, cp, size));
  test_eq(0, crypto_pk_cmp_keys(pk1, pk2));
  tor_free(cp);

  test_eq(128, crypto_pk_keysize(pk1));
  test_eq(128, crypto_pk_keysize(pk2));

  test_eq(128, crypto_pk_public_encrypt(pk2, data1, "Hello whirled.", 15,
                                        PK_PKCS1_OAEP_PADDING));
  test_eq(128, crypto_pk_public_encrypt(pk1, data2, "Hello whirled.", 15,
                                        PK_PKCS1_OAEP_PADDING));
  /* oaep padding should make encryption not match */
  test_memneq(data1, data2, 128);
  test_eq(15, crypto_pk_private_decrypt(pk1, data3, data1, 128,
                                        PK_PKCS1_OAEP_PADDING,1));
  test_streq(data3, "Hello whirled.");
  memset(data3, 0, 1024);
  test_eq(15, crypto_pk_private_decrypt(pk1, data3, data2, 128,
                                        PK_PKCS1_OAEP_PADDING,1));
  test_streq(data3, "Hello whirled.");
  /* Can't decrypt with public key. */
  test_eq(-1, crypto_pk_private_decrypt(pk2, data3, data2, 128,
                                        PK_PKCS1_OAEP_PADDING,1));
  /* Try again with bad padding */
  memcpy(data2+1, "XYZZY", 5);  /* This has fails ~ once-in-2^40 */
  test_eq(-1, crypto_pk_private_decrypt(pk1, data3, data2, 128,
                                        PK_PKCS1_OAEP_PADDING,1));

  /* File operations: save and load private key */
  test_assert(! crypto_pk_write_private_key_to_filename(pk1,
                                                        get_fname("pkey1")));

  test_assert(! crypto_pk_read_private_key_from_filename(pk2,
                                                         get_fname("pkey1")));
  test_eq(15, crypto_pk_private_decrypt(pk2, data3, data1, 128,
                                        PK_PKCS1_OAEP_PADDING,1));

  /* Now try signing. */
  strcpy(data1, "Ossifrage");
  test_eq(128, crypto_pk_private_sign(pk1, data2, data1, 10));
  test_eq(10, crypto_pk_public_checksig(pk1, data3, data2, 128));
  test_streq(data3, "Ossifrage");
  /* Try signing digests. */
  test_eq(128, crypto_pk_private_sign_digest(pk1, data2, data1, 10));
  test_eq(20, crypto_pk_public_checksig(pk1, data3, data2, 128));
  test_eq(0, crypto_pk_public_checksig_digest(pk1, data1, 10, data2, 128));
  test_eq(-1, crypto_pk_public_checksig_digest(pk1, data1, 11, data2, 128));
  /*XXXX test failed signing*/

  /* Try encoding */
  crypto_free_pk_env(pk2);
  pk2 = NULL;
  i = crypto_pk_asn1_encode(pk1, data1, 1024);
  test_assert(i>0);
  pk2 = crypto_pk_asn1_decode(data1, i);
  test_assert(crypto_pk_cmp_keys(pk1,pk2) == 0);

  /* Try with hybrid encryption wrappers. */
  crypto_rand(data1, 1024);
  for (i = 0; i < 3; ++i) {
    for (j = 85; j < 140; ++j) {
      memset(data2,0,1024);
      memset(data3,0,1024);
      if (i == 0 && j < 129)
        continue;
      p = (i==0)?PK_NO_PADDING:
        (i==1)?PK_PKCS1_PADDING:PK_PKCS1_OAEP_PADDING;
      len = crypto_pk_public_hybrid_encrypt(pk1,data2,data1,j,p,0);
      test_assert(len>=0);
      len = crypto_pk_private_hybrid_decrypt(pk1,data3,data2,len,p,1);
      test_eq(len,j);
      test_memeq(data1,data3,j);
    }
  }
  crypto_free_pk_env(pk1);
  crypto_free_pk_env(pk2);

  /* Base64 tests */
  strcpy(data1, "Test string that contains 35 chars.");
  strcat(data1, " 2nd string that contains 35 chars.");

  i = base64_encode(data2, 1024, data1, 71);
  j = base64_decode(data3, 1024, data2, i);
  test_streq(data3, data1);
  test_eq(j, 71);
  test_assert(data2[i] == '\0');

  crypto_rand(data1, DIGEST_LEN);
  memset(data2, 100, 1024);
  digest_to_base64(data2, data1);
  test_eq(BASE64_DIGEST_LEN, strlen(data2));
  test_eq(100, data2[BASE64_DIGEST_LEN+2]);
  memset(data3, 99, 1024);
  digest_from_base64(data3, data2);
  test_memeq(data1, data3, DIGEST_LEN);
  test_eq(99, data3[DIGEST_LEN+1]);

  /* Base32 tests */
  strcpy(data1, "5chrs");
  /* bit pattern is:  [35 63 68 72 73] ->
   *        [00110101 01100011 01101000 01110010 01110011]
   * By 5s: [00110 10101 10001 10110 10000 11100 10011 10011]
   */
  base32_encode(data2, 9, data1, 5);
  test_streq(data2, "gvrwq4tt");

  strcpy(data1, "\xFF\xF5\x6D\x44\xAE\x0D\x5C\xC9\x62\xC4");
  base32_encode(data2, 30, data1, 10);
  test_streq(data2, "772w2rfobvomsywe");

  /* Base16 tests */
  strcpy(data1, "6chrs\xff");
  base16_encode(data2, 13, data1, 6);
  test_streq(data2, "3663687273FF");

  strcpy(data1, "f0d678affc000100");
  i = base16_decode(data2, 8, data1, 16);
  test_eq(i,0);
  test_memeq(data2, "\xf0\xd6\x78\xaf\xfc\x00\x01\x00",8);

  tor_free(data1);
  tor_free(data2);
  tor_free(data3);
}

static void
test_crypto_s2k(void)
{
  char buf[29];
  char buf2[29];
  char *buf3;
  int i;

  memset(buf, 0, sizeof(buf));
  memset(buf2, 0, sizeof(buf2));
  buf3 = tor_malloc(65536);
  memset(buf3, 0, 65536);

  secret_to_key(buf+9, 20, "", 0, buf);
  crypto_digest(buf2+9, buf3, 1024);
  test_memeq(buf, buf2, 29);

  memcpy(buf,"vrbacrda",8);
  memcpy(buf2,"vrbacrda",8);
  buf[8] = 96;
  buf2[8] = 96;
  secret_to_key(buf+9, 20, "12345678", 8, buf);
  for (i = 0; i < 65536; i += 16) {
    memcpy(buf3+i, "vrbacrda12345678", 16);
  }
  crypto_digest(buf2+9, buf3, 65536);
  test_memeq(buf, buf2, 29);
}

static int
_compare_strs(const void **a, const void **b)
{
  const char *s1 = *a, *s2 = *b;
  return strcmp(s1, s2);
}

static int
_compare_without_first_ch(const void *a, const void **b)
{
  const char *s1 = a, *s2 = *b;
  return strcasecmp(s1+1, s2);
}

static void
test_util(void)
{
  struct timeval start, end;
  struct tm a_time;
  smartlist_t *sl;
  char timestr[RFC1123_TIME_LEN+1];
  char buf[1024];
  time_t t_res;
  int i;
  uint32_t u32;
  uint16_t u16;
  char *cp, *k, *v;

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

  /* Test smartlist */
  sl = smartlist_create();
  smartlist_add(sl, (void*)1);
  smartlist_add(sl, (void*)2);
  smartlist_add(sl, (void*)3);
  smartlist_add(sl, (void*)4);
  smartlist_del_keeporder(sl, 1);
  smartlist_insert(sl, 1, (void*)22);
  smartlist_insert(sl, 0, (void*)0);
  smartlist_insert(sl, 5, (void*)555);
  test_eq_ptr((void*)0,   smartlist_get(sl,0));
  test_eq_ptr((void*)1,   smartlist_get(sl,1));
  test_eq_ptr((void*)22,  smartlist_get(sl,2));
  test_eq_ptr((void*)3,   smartlist_get(sl,3));
  test_eq_ptr((void*)4,   smartlist_get(sl,4));
  test_eq_ptr((void*)555, smartlist_get(sl,5));

  smartlist_clear(sl);
  smartlist_split_string(sl, "abc", ":", 0, 0);
  test_eq(1, smartlist_len(sl));
  test_streq("abc", smartlist_get(sl, 0));
  smartlist_split_string(sl, "a::bc::", "::", 0, 0);
  test_eq(4, smartlist_len(sl));
  test_streq("a", smartlist_get(sl, 1));
  test_streq("bc", smartlist_get(sl, 2));
  test_streq("", smartlist_get(sl, 3));
  cp = smartlist_join_strings(sl, "", 0, NULL);
  test_streq(cp, "abcabc");
  tor_free(cp);
  cp = smartlist_join_strings(sl, "!", 0, NULL);
  test_streq(cp, "abc!a!bc!");
  tor_free(cp);
  cp = smartlist_join_strings(sl, "XY", 0, NULL);
  test_streq(cp, "abcXYaXYbcXY");
  tor_free(cp);
  cp = smartlist_join_strings(sl, "XY", 1, NULL);
  test_streq(cp, "abcXYaXYbcXYXY");
  tor_free(cp);
  cp = smartlist_join_strings(sl, "", 1, NULL);
  test_streq(cp, "abcabc");
  tor_free(cp);

  smartlist_split_string(sl, "/def/  /ghijk", "/", 0, 0);
  test_eq(8, smartlist_len(sl));
  test_streq("", smartlist_get(sl, 4));
  test_streq("def", smartlist_get(sl, 5));
  test_streq("  ", smartlist_get(sl, 6));
  test_streq("ghijk", smartlist_get(sl, 7));
  SMARTLIST_FOREACH(sl, char *, cp, tor_free(cp));
  smartlist_clear(sl);

  smartlist_split_string(sl, "a,bbd,cdef", ",", SPLIT_SKIP_SPACE, 0);
  test_eq(3, smartlist_len(sl));
  test_streq("a", smartlist_get(sl,0));
  test_streq("bbd", smartlist_get(sl,1));
  test_streq("cdef", smartlist_get(sl,2));
  smartlist_split_string(sl, " z <> zhasd <>  <> bnud<>   ", "<>",
                         SPLIT_SKIP_SPACE, 0);
  test_eq(8, smartlist_len(sl));
  test_streq("z", smartlist_get(sl,3));
  test_streq("zhasd", smartlist_get(sl,4));
  test_streq("", smartlist_get(sl,5));
  test_streq("bnud", smartlist_get(sl,6));
  test_streq("", smartlist_get(sl,7));

  SMARTLIST_FOREACH(sl, char *, cp, tor_free(cp));
  smartlist_clear(sl);

  smartlist_split_string(sl, " ab\tc \td ef  ", NULL,
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  test_eq(4, smartlist_len(sl));
  test_streq("ab", smartlist_get(sl,0));
  test_streq("c", smartlist_get(sl,1));
  test_streq("d", smartlist_get(sl,2));
  test_streq("ef", smartlist_get(sl,3));
  smartlist_split_string(sl, "ghi\tj", NULL,
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  test_eq(6, smartlist_len(sl));
  test_streq("ghi", smartlist_get(sl,4));
  test_streq("j", smartlist_get(sl,5));

  SMARTLIST_FOREACH(sl, char *, cp, tor_free(cp));
  smartlist_clear(sl);

  cp = smartlist_join_strings(sl, "XY", 0, NULL);
  test_streq(cp, "");
  tor_free(cp);
  cp = smartlist_join_strings(sl, "XY", 1, NULL);
  test_streq(cp, "XY");
  tor_free(cp);

  smartlist_split_string(sl, " z <> zhasd <>  <> bnud<>   ", "<>",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  test_eq(3, smartlist_len(sl));
  test_streq("z", smartlist_get(sl, 0));
  test_streq("zhasd", smartlist_get(sl, 1));
  test_streq("bnud", smartlist_get(sl, 2));
  smartlist_split_string(sl, " z <> zhasd <>  <> bnud<>   ", "<>",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 2);
  test_eq(5, smartlist_len(sl));
  test_streq("z", smartlist_get(sl, 3));
  test_streq("zhasd <>  <> bnud<>", smartlist_get(sl, 4));
  SMARTLIST_FOREACH(sl, char *, cp, tor_free(cp));
  smartlist_clear(sl);

  smartlist_split_string(sl, "abcd\n", "\n",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  test_eq(1, smartlist_len(sl));
  test_streq("abcd", smartlist_get(sl, 0));
  smartlist_split_string(sl, "efgh", "\n",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  test_eq(2, smartlist_len(sl));
  test_streq("efgh", smartlist_get(sl, 1));

  SMARTLIST_FOREACH(sl, char *, cp, tor_free(cp));
  smartlist_clear(sl);

  /* Test smartlist sorting. */
  smartlist_split_string(sl, "the,onion,router,by,arma,and,nickm", ",", 0, 0);
  test_eq(7, smartlist_len(sl));
  smartlist_sort(sl, _compare_strs);
  cp = smartlist_join_strings(sl, ",", 0, NULL);
  test_streq(cp,"and,arma,by,nickm,onion,router,the");
  tor_free(cp);

  test_streq("nickm", smartlist_bsearch(sl, "zNicKM",
                                        _compare_without_first_ch));
  test_streq("and", smartlist_bsearch(sl, " AND", _compare_without_first_ch));
  test_eq_ptr(NULL, smartlist_bsearch(sl, " ANz", _compare_without_first_ch));

  /* Test reverse() and pop_last() */
  smartlist_reverse(sl);
  cp = smartlist_join_strings(sl, ",", 0, NULL);
  test_streq(cp,"the,router,onion,nickm,by,arma,and");
  tor_free(cp);
  cp = smartlist_pop_last(sl);
  test_streq(cp, "and");
  tor_free(cp);
  test_eq(smartlist_len(sl), 6);

  /* Test tor_strstrip() */
  strcpy(buf, "Testing 1 2 3");
  test_eq(0, tor_strstrip(buf, ",!"));
  test_streq(buf, "Testing 1 2 3");
  strcpy(buf, "!Testing 1 2 3?");
  test_eq(5, tor_strstrip(buf, "!? "));
  test_streq(buf, "Testing123");

  /* Test tor_strpartition() */
  test_assert(! tor_strpartition(buf, sizeof(buf), "abcdefg", "##", 3,
                                 TERMINATE_IF_EVEN));
  test_streq(buf, "abc##def##g");
  test_assert(! tor_strpartition(buf, sizeof(buf), "abcdefg", "##", 3,
                                 ALWAYS_TERMINATE));
  test_streq(buf, "abc##def##g##");
  test_assert(! tor_strpartition(buf, sizeof(buf), "abcdefghi", "##", 3,
                                 TERMINATE_IF_EVEN));
  test_streq(buf, "abc##def##ghi##");
  test_assert(! tor_strpartition(buf, sizeof(buf), "abcdefghi", "##", 3,
                                 NEVER_TERMINATE));
  test_streq(buf, "abc##def##ghi");

  /* Test parse_addr_port */
  cp = NULL; u32 = 3; u16 = 3;
  test_assert(!parse_addr_port(LOG_WARN, "1.2.3.4", &cp, &u32, &u16));
  test_streq(cp, "1.2.3.4");
  test_eq(u32, 0x01020304u);
  test_eq(u16, 0);
  tor_free(cp);
  test_assert(!parse_addr_port(LOG_WARN, "4.3.2.1:99", &cp, &u32, &u16));
  test_streq(cp, "4.3.2.1");
  test_eq(u32, 0x04030201u);
  test_eq(u16, 99);
  tor_free(cp);
  test_assert(!parse_addr_port(LOG_WARN, "nonexistent.address:4040",
                               &cp, NULL, &u16));
  test_streq(cp, "nonexistent.address");
  test_eq(u16, 4040);
  tor_free(cp);
  test_assert(!parse_addr_port(LOG_WARN, "localhost:9999", &cp, &u32, &u16));
  test_streq(cp, "localhost");
  test_eq(u32, 0x7f000001u);
  test_eq(u16, 9999);
  tor_free(cp);
  u32 = 3;
  test_assert(!parse_addr_port(LOG_WARN, "localhost", NULL, &u32, &u16));
  test_eq(cp, NULL);
  test_eq(u32, 0x7f000001u);
  test_eq(u16, 0);
  tor_free(cp);
  test_eq(0, addr_mask_get_bits(0x0u));
  test_eq(32, addr_mask_get_bits(0xFFFFFFFFu));
  test_eq(16, addr_mask_get_bits(0xFFFF0000u));
  test_eq(31, addr_mask_get_bits(0xFFFFFFFEu));
  test_eq(1, addr_mask_get_bits(0x80000000u));

  /* Test tor_parse_long. */
  test_eq(10L, tor_parse_long("10",10,0,100,NULL,NULL));
  test_eq(0L, tor_parse_long("10",10,50,100,NULL,NULL));

  /* Test parse_line_from_str */
  strlcpy(buf, "k v\n" " key    value with spaces   \n" "keykey val\n"
          "k2\n"
          "k3 \n" "\n" "   \n" "#comment\n"
          "k4#a\n" "k5#abc\n" "k6 val #with comment\n", sizeof(buf));
  cp = buf;

  cp = parse_line_from_str(cp, &k, &v);
  test_streq(k, "k");
  test_streq(v, "v");
  test_assert(!strcmpstart(cp, " key    value with"));

  cp = parse_line_from_str(cp, &k, &v);
  test_streq(k, "key");
  test_streq(v, "value with spaces");
  test_assert(!strcmpstart(cp, "keykey"));

  cp = parse_line_from_str(cp, &k, &v);
  test_streq(k, "keykey");
  test_streq(v, "val");
  test_assert(!strcmpstart(cp, "k2\n"));

  cp = parse_line_from_str(cp, &k, &v);
  test_streq(k, "k2");
  test_streq(v, "");
  test_assert(!strcmpstart(cp, "k3 \n"));

  cp = parse_line_from_str(cp, &k, &v);
  test_streq(k, "k3");
  test_streq(v, "");
  test_assert(!strcmpstart(cp, "\n   \n"));

  cp = parse_line_from_str(cp, &k, &v);
  test_streq(k, "k4");
  test_streq(v, "");
  test_assert(!strcmpstart(cp, "k5#abc"));

  cp = parse_line_from_str(cp, &k, &v);
  test_streq(k, "k5");
  test_streq(v, "");
  test_assert(!strcmpstart(cp, "k6"));

  cp = parse_line_from_str(cp, &k, &v);
  test_streq(k, "k6");
  test_streq(v, "val");
  test_streq(cp, "");

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

  {
    char tmpbuf[INET_NTOA_BUF_LEN];
    struct in_addr in;
    tor_inet_aton("18.244.0.188",&in);
    tor_inet_ntoa(&in, tmpbuf, sizeof(tmpbuf));
    test_streq(tmpbuf, "18.244.0.188");
  }

  /* Test 'escaped' */
  test_streq("\"\"", escaped(""));
  test_streq("\"abcd\"", escaped("abcd"));
  test_streq("\"\\\\\\n\\r\\t\\\"\\'\"", escaped("\\\n\r\t\"\'"));
  test_streq("\"z\\001abc\\277d\"", escaped("z\001abc\277d"));

  /* XXXX test older functions. */
  smartlist_free(sl);
}

static int
_compare_strings_for_pqueue(const void *s1, const void *s2)
{
  return strcmp((const char*)s1, (const char*)s2);
}

static void
test_pqueue(void)
{
  smartlist_t *sl;
  int (*cmp)(const void *, const void*);
#define OK() smartlist_pqueue_assert_ok(sl, cmp)

  cmp = _compare_strings_for_pqueue;

  sl = smartlist_create();
  smartlist_pqueue_add(sl, cmp, (char*)"cows");
  smartlist_pqueue_add(sl, cmp, (char*)"zebras");
  smartlist_pqueue_add(sl, cmp, (char*)"fish");
  smartlist_pqueue_add(sl, cmp, (char*)"frogs");
  smartlist_pqueue_add(sl, cmp, (char*)"apples");
  smartlist_pqueue_add(sl, cmp, (char*)"squid");
  smartlist_pqueue_add(sl, cmp, (char*)"daschunds");
  smartlist_pqueue_add(sl, cmp, (char*)"eggplants");
  smartlist_pqueue_add(sl, cmp, (char*)"weissbier");
  smartlist_pqueue_add(sl, cmp, (char*)"lobsters");
  smartlist_pqueue_add(sl, cmp, (char*)"roquefort");

  OK();

  test_eq(smartlist_len(sl), 11);
  test_streq(smartlist_get(sl, 0), "apples");
  test_streq(smartlist_pqueue_pop(sl, cmp), "apples");
  test_eq(smartlist_len(sl), 10);
  OK();
  test_streq(smartlist_pqueue_pop(sl, cmp), "cows");
  test_streq(smartlist_pqueue_pop(sl, cmp), "daschunds");
  smartlist_pqueue_add(sl, cmp, (char*)"chinchillas");
  OK();
  smartlist_pqueue_add(sl, cmp, (char*)"fireflies");
  OK();
  test_streq(smartlist_pqueue_pop(sl, cmp), "chinchillas");
  test_streq(smartlist_pqueue_pop(sl, cmp), "eggplants");
  test_streq(smartlist_pqueue_pop(sl, cmp), "fireflies");
  OK();
  test_streq(smartlist_pqueue_pop(sl, cmp), "fish");
  test_streq(smartlist_pqueue_pop(sl, cmp), "frogs");
  test_streq(smartlist_pqueue_pop(sl, cmp), "lobsters");
  test_streq(smartlist_pqueue_pop(sl, cmp), "roquefort");
  OK();
  test_eq(smartlist_len(sl), 3);
  test_streq(smartlist_pqueue_pop(sl, cmp), "squid");
  test_streq(smartlist_pqueue_pop(sl, cmp), "weissbier");
  test_streq(smartlist_pqueue_pop(sl, cmp), "zebras");
  test_eq(smartlist_len(sl), 0);
  OK();
#undef OK
  smartlist_free(sl);
}

static void
test_gzip(void)
{
  char *buf1, *buf2=NULL, *buf3=NULL, *cp1, *cp2;
  const char *ccp2;
  size_t len1, len2;
  tor_zlib_state_t *state;

  buf1 = tor_strdup("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZAAAAAAAAAAAAAAAAAAAZ");
  test_eq(detect_compression_method(buf1, strlen(buf1)), 0);
  if (is_gzip_supported()) {
    test_assert(!tor_gzip_compress(&buf2, &len1, buf1, strlen(buf1)+1,
                                   GZIP_METHOD));
    test_assert(buf2);
    test_assert(!memcmp(buf2, "\037\213", 2)); /* Gzip magic. */
    test_eq(detect_compression_method(buf2, len1), GZIP_METHOD);

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
  test_eq(detect_compression_method(buf2, len1), ZLIB_METHOD);

  test_assert(!tor_gzip_uncompress(&buf3, &len2, buf2, len1,
                                   ZLIB_METHOD, 1, LOG_INFO));
  test_assert(buf3);
  test_streq(buf1,buf3);

  /* Check whether we can uncompress concatenated, compresed strings. */
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
  /* when we allow an uncomplete string, we should succeed.*/
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
  tor_free(buf3);

  tor_zlib_free(state);

  tor_free(buf2);
  tor_free(buf3);
  tor_free(buf1);
}

static void
test_strmap(void)
{
  strmap_t *map;
//  strmap_iter_t *iter;
//  const char *k;
  void *v;

  map = strmap_new();
  v = strmap_set(map, "K1", (void*)99);
  test_eq(v, NULL);
  v = strmap_set(map, "K2", (void*)101);
  test_eq(v, NULL);
  v = strmap_set(map, "K1", (void*)100);
  test_eq(v, (void*)99);
  test_eq_ptr(strmap_get(map,"K1"), (void*)100);
  test_eq_ptr(strmap_get(map,"K2"), (void*)101);
  test_eq_ptr(strmap_get(map,"K-not-there"), NULL);
  strmap_assert_ok(map);

  v = strmap_remove(map,"K2");
  strmap_assert_ok(map);
  test_eq_ptr(v, (void*)101);
  test_eq_ptr(strmap_get(map,"K2"), NULL);
  test_eq_ptr(strmap_remove(map,"K2"), NULL);

  strmap_set(map, "K2", (void*)101);
  strmap_set(map, "K3", (void*)102);
  strmap_set(map, "K4", (void*)103);
  strmap_assert_ok(map);
  strmap_set(map, "K5", (void*)104);
  strmap_set(map, "K6", (void*)105);
  strmap_assert_ok(map);

#if 0
  iter = strmap_iter_init(map);
  strmap_iter_get(iter,&k,&v);
  test_streq(k, "K1");
  test_eq(v, (void*)10000);
  iter = strmap_iter_next(map,iter);
  strmap_iter_get(iter,&k,&v);
  test_streq(k, "K2");
  test_eq(v, (void*)10201);
  iter = strmap_iter_next_rmv(map,iter);
  strmap_iter_get(iter,&k,&v);
  test_streq(k, "K3");
  test_eq(v, (void*)10404);
  iter = strmap_iter_next(map,iter); /* K5 */
  test_assert(!strmap_iter_done(iter));
  iter = strmap_iter_next(map,iter); /* K6 */
  test_assert(!strmap_iter_done(iter));
  iter = strmap_iter_next(map,iter); /* done */
  test_assert(strmap_iter_done(iter));

  /* Make sure we removed K2, but not the others. */
  test_eq_ptr(strmap_get(map, "K2"), NULL);
  test_eq_ptr(strmap_get(map, "K5"), (void*)10816);
#endif

  strmap_assert_ok(map);
  /* Clean up after ourselves. */
  strmap_free(map, NULL);

  /* Now try some lc functions. */
  map = strmap_new();
  strmap_set_lc(map,"Ab.C", (void*)1);
  test_eq_ptr(strmap_get(map,"ab.c"), (void*)1);
  strmap_assert_ok(map);
  test_eq_ptr(strmap_get_lc(map,"AB.C"), (void*)1);
  test_eq_ptr(strmap_get(map,"AB.C"), NULL);
  test_eq_ptr(strmap_remove_lc(map,"aB.C"), (void*)1);
  strmap_assert_ok(map);
  test_eq_ptr(strmap_get_lc(map,"AB.C"), NULL);
  strmap_free(map,NULL);
}

static void
test_control_formats(void)
{
  char *out;
  const char *inp =
    "..This is a test\r\nof the emergency \nbroadcast\r\n..system.\r\nZ.\r\n";
  size_t sz;

  sz = read_escaped_data(inp, strlen(inp), 1, &out);
  test_streq(out,
             ".This is a test\nof the emergency \nbroadcast\n.system.\nZ.\n");

  tor_free(out);
}

static void
test_onion(void)
{
#if 0
  char **names;
  int i,num;

  names = parse_nickname_list("  foo bar\t baz quux  ", &num);
  test_eq(num,4);
  test_streq(names[0],"foo");
  test_streq(names[1],"bar");
  test_streq(names[2],"baz");
  test_streq(names[3],"quux");
  for (i=0;i<num;i++)
    tor_free(names[i]);
  tor_free(names);
#endif
}

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

  pk = crypto_new_pk_env();
  test_assert(! crypto_pk_generate_key(pk));

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

  crypto_dh_free(c_dh);

  if (memcmp(c_keys, s_keys, 40)) {
    puts("Aiiiie");
    exit(1);
  }
  test_memeq(c_keys, s_keys, 40);
  memset(s_buf, 0, 40);
  test_memneq(c_keys, s_buf, 40);
  crypto_free_pk_env(pk);
}

extern smartlist_t *fingerprint_list;

static void
test_dir_format(void)
{
  char buf[8192], buf2[8192];
  char platform[256];
  char fingerprint[FINGERPRINT_LEN+1];
  char *pk1_str = NULL, *pk2_str = NULL, *pk3_str = NULL, *cp;
  size_t pk1_str_len, pk2_str_len, pk3_str_len;
  routerinfo_t r1, r2;
  crypto_pk_env_t *pk1 = NULL, *pk2 = NULL, *pk3 = NULL;
  routerinfo_t *rp1 = NULL, *rp2 = NULL;
  addr_policy_t ex1, ex2;
  routerlist_t *dir1 = NULL, *dir2 = NULL;
  tor_version_t ver1;
  char *bw_lines = NULL;

  test_assert( (pk1 = crypto_new_pk_env()) );
  test_assert( (pk2 = crypto_new_pk_env()) );
  test_assert( (pk3 = crypto_new_pk_env()) );
  test_assert(! crypto_pk_generate_key(pk1));
  test_assert(! crypto_pk_generate_key(pk2));
  test_assert(! crypto_pk_generate_key(pk3));

  test_assert( is_legal_nickname("a"));
  test_assert(!is_legal_nickname(""));
  test_assert(!is_legal_nickname("abcdefghijklmnopqrst")); /* 20 chars */
  test_assert(!is_legal_nickname("abcdefghijklmnopqrst")); /* 20 chars */
  test_assert(!is_legal_nickname("hyphen-")); /* bad char */
  test_assert( is_legal_nickname("abcdefghijklmnopqrs")); /* 19 chars */
  test_assert(!is_legal_nickname("$AAAAAAAA01234AAAAAAAAAAAAAAAAAAAAAAAAAAA"));
  /* valid */
  test_assert( is_legal_nickname_or_hexdigest(
                                 "$AAAAAAAA01234AAAAAAAAAAAAAAAAAAAAAAAAAAA"));
  /* too short */
  test_assert(!is_legal_nickname_or_hexdigest(
                                 "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
  /* illegal char */
  test_assert(!is_legal_nickname_or_hexdigest(
                                 "$AAAAAAzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
  test_assert(is_legal_nickname_or_hexdigest("xyzzy"));
  test_assert(is_legal_nickname_or_hexdigest("abcdefghijklmnopqrs"));
  test_assert(!is_legal_nickname_or_hexdigest("abcdefghijklmnopqrst"));

  get_platform_str(platform, sizeof(platform));
  memset(&r1,0,sizeof(r1));
  memset(&r2,0,sizeof(r2));
  r1.address = tor_strdup("18.244.0.1");
  r1.addr = 0xc0a80001u; /* 192.168.0.1 */
  r1.cache_info.published_on = 0;
  r1.or_port = 9000;
  r1.dir_port = 9003;
  r1.onion_pkey = pk1;
  r1.identity_pkey = pk2;
  r1.bandwidthrate = 1000;
  r1.bandwidthburst = 5000;
  r1.bandwidthcapacity = 10000;
  r1.exit_policy = NULL;
  r1.nickname = tor_strdup("Magri");
  r1.platform = tor_strdup(platform);

  ex1.policy_type = ADDR_POLICY_ACCEPT;
  ex1.string = NULL;
  ex1.addr = 0;
  ex1.msk = 0;
  ex1.prt_min = ex1.prt_max = 80;
  ex1.next = &ex2;
  ex2.policy_type = ADDR_POLICY_REJECT;
  ex2.addr = 18 << 24;
  ex2.msk = 0xFF000000u;
  ex2.prt_min = ex2.prt_max = 24;
  ex2.next = NULL;
  r2.address = tor_strdup("1.1.1.1");
  r2.addr = 0x0a030201u; /* 10.3.2.1 */
  r2.platform = tor_strdup(platform);
  r2.cache_info.published_on = 5;
  r2.or_port = 9005;
  r2.dir_port = 0;
  r2.onion_pkey = pk2;
  r2.identity_pkey = pk1;
  r2.bandwidthrate = r2.bandwidthburst = r2.bandwidthcapacity = 3000;
  r2.exit_policy = &ex1;
  r2.nickname = tor_strdup("Fred");

  bw_lines = rep_hist_get_bandwidth_lines();
  test_assert(bw_lines);
  test_assert(!strcmpstart(bw_lines, "opt write-history "));

  test_assert(!crypto_pk_write_public_key_to_string(pk1, &pk1_str,
                                                    &pk1_str_len));
  test_assert(!crypto_pk_write_public_key_to_string(pk2 , &pk2_str,
                                                    &pk2_str_len));
  test_assert(!crypto_pk_write_public_key_to_string(pk3 , &pk3_str,
                                                    &pk3_str_len));

  memset(buf, 0, 2048);
  test_assert(router_dump_router_to_string(buf, 2048, &r1, pk2)>0);

  strcpy(buf2, "router Magri 18.244.0.1 9000 0 0\n"
         "platform Tor "VERSION" on ");
  strcat(buf2, get_uname());
  strcat(buf2, "\n"
         "published 1970-01-01 00:00:00\n"
         "opt fingerprint ");
  test_assert(!crypto_pk_get_fingerprint(pk2, fingerprint, 1));
  strcat(buf2, fingerprint);
  strcat(buf2, "\nuptime 0\n"
  /* XXX the "0" above is hardcoded, but even if we made it reflect
   * uptime, that still wouldn't make it right, because the two
   * descriptors might be made on different seconds... hm. */
         "bandwidth 1000 5000 10000\n"
         "onion-key\n");
  strcat(buf2, pk1_str);
  strcat(buf2, "signing-key\n");
  strcat(buf2, pk2_str);
#ifdef USE_EVENTDNS
  strcat(buf2, "opt eventdns 1\n");
#else
  strcat(buf2, "opt eventdns 0\n");
#endif
  strcat(buf2, bw_lines);
  strcat(buf2, "router-signature\n");
  buf[strlen(buf2)] = '\0'; /* Don't compare the sig; it's never the same
                             * twice */

  test_streq(buf, buf2);
  tor_free(bw_lines);

  test_assert(router_dump_router_to_string(buf, 2048, &r1, pk2)>0);
  cp = buf;
  rp1 = router_parse_entry_from_string((const char*)cp,NULL,1);
  test_assert(rp1);
  test_streq(rp1->address, r1.address);
  test_eq(rp1->or_port, r1.or_port);
  //test_eq(rp1->dir_port, r1.dir_port);
  test_eq(rp1->bandwidthrate, r1.bandwidthrate);
  test_eq(rp1->bandwidthburst, r1.bandwidthburst);
  test_eq(rp1->bandwidthcapacity, r1.bandwidthcapacity);
  test_assert(crypto_pk_cmp_keys(rp1->onion_pkey, pk1) == 0);
  test_assert(crypto_pk_cmp_keys(rp1->identity_pkey, pk2) == 0);
  test_assert(rp1->exit_policy == NULL);

#if 0
  /* XXX Once we have exit policies, test this again. XXX */
  strcpy(buf2, "router tor.tor.tor 9005 0 0 3000\n");
  strcat(buf2, pk2_str);
  strcat(buf2, "signing-key\n");
  strcat(buf2, pk1_str);
  strcat(buf2, "accept *:80\nreject 18.*:24\n\n");
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
#endif

  /* Okay, now for the directories. */
  {
    fingerprint_list = smartlist_create();
    crypto_pk_get_fingerprint(pk2, buf, 1);
    add_fingerprint_to_dir("Magri", buf, fingerprint_list);
    crypto_pk_get_fingerprint(pk1, buf, 1);
    add_fingerprint_to_dir("Fred", buf, fingerprint_list);
  }
#if 0
  {
  char d[DIGEST_LEN];
  const char *m;
  /* XXXX NM re-enable. */
  /* Make sure routers aren't too far in the past any more. */
  r1.cache_info.published_on = time(NULL);
  r2.cache_info.published_on = time(NULL)-3*60*60;
  test_assert(router_dump_router_to_string(buf, 2048, &r1, pk2)>0);
  test_eq(dirserv_add_descriptor(buf,&m), 2);
  test_assert(router_dump_router_to_string(buf, 2048, &r2, pk1)>0);
  test_eq(dirserv_add_descriptor(buf,&m), 2);
  get_options()->Nickname = tor_strdup("DirServer");
  test_assert(!dirserv_dump_directory_to_string(&cp,pk3, 0));
  crypto_pk_get_digest(pk3, d);
  test_assert(!router_parse_directory(cp));
  test_eq(2, smartlist_len(dir1->routers));
  tor_free(cp);
  }
#endif
  dirserv_free_fingerprint_list();

  tor_free(pk1_str);
  tor_free(pk2_str);
  if (pk1) crypto_free_pk_env(pk1);
  if (pk2) crypto_free_pk_env(pk2);
  if (rp1) routerinfo_free(rp1);
  if (rp2) routerinfo_free(rp2);
  tor_free(dir1); /* XXXX And more !*/
  tor_free(dir2); /* And more !*/

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

#define test_eq_vs(vs1, vs2) test_eq_type(version_status_t, "%d", (vs1), (vs2))
#define test_v_i_o(val, ver, lst) \
  test_eq_vs(val, tor_version_is_obsolete(ver, lst))

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
  test_v_i_o(VS_NEW_IN_SERIES, "0.0.5.1-cvs", "0.0.5");
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

}

static void
test_exit_policies(void)
{
  addr_policy_t *policy;

  policy = router_parse_addr_policy_from_string("reject 192.168.0.0/16:*",-1);
  test_eq(NULL, policy->next);
  test_eq(ADDR_POLICY_REJECT, policy->policy_type);
  test_eq(0xc0a80000u, policy->addr);
  test_eq(0xffff0000u, policy->msk);
  test_eq(1, policy->prt_min);
  test_eq(65535, policy->prt_max);
  test_streq("reject 192.168.0.0/16:*", policy->string);

//  test_assert(exit_policy_implicitly_allows_local_networks(policy, 0));
  test_assert(ADDR_POLICY_ACCEPTED ==
          compare_addr_to_addr_policy(0x01020304u, 2, policy));
  test_assert(ADDR_POLICY_PROBABLY_ACCEPTED ==
          compare_addr_to_addr_policy(0, 2, policy));
  test_assert(ADDR_POLICY_REJECTED ==
          compare_addr_to_addr_policy(0xc0a80102, 2, policy));

  addr_policy_free(policy);

#if 0
  /* Copied from router.c */
  policy = NULL;
  options_append_default_exit_policy(&policy);
  test_assert(policy);
  test_assert(!exit_policy_implicitly_allows_local_networks(policy, 1));

  addr_policy_free(policy);
#endif

}

static void
test_rend_fns(void)
{
  char address1[] = "fooaddress.onion";
  char address2[] = "aaaaaaaaaaaaaaaa.onion";
  char address3[] = "fooaddress.exit";
  char address4[] = "tor.eff.org";
  rend_service_descriptor_t *d1, *d2;
  char *encoded;
  size_t len;
  crypto_pk_env_t *pk1, *pk2;
  time_t now;
  pk1 = crypto_new_pk_env();
  pk2 = crypto_new_pk_env();
  test_assert(!crypto_pk_generate_key(pk1));
  test_assert(!crypto_pk_generate_key(pk2));

  /* Test unversioned descriptor */
  d1 = tor_malloc_zero(sizeof(rend_service_descriptor_t));
  d1->pk = crypto_pk_dup_key(pk1);
  now = time(NULL);
  d1->timestamp = now;
  d1->n_intro_points = 3;
  d1->version = 0;
  d1->intro_points = tor_malloc(sizeof(char*)*3);
  d1->intro_points[0] = tor_strdup("tom");
  d1->intro_points[1] = tor_strdup("crow");
  d1->intro_points[2] = tor_strdup("joel");
  test_assert(! rend_encode_service_descriptor(d1, 0, pk1, &encoded, &len));
  d2 = rend_parse_service_descriptor(encoded, len);
  test_assert(d2);

  test_assert(!crypto_pk_cmp_keys(d1->pk, d2->pk));
  test_eq(d2->timestamp, now);
  test_eq(d2->version, 0);
  test_eq(d2->protocols, 1);
  test_eq(d2->n_intro_points, 3);
  test_streq(d2->intro_points[0], "tom");
  test_streq(d2->intro_points[1], "crow");
  test_streq(d2->intro_points[2], "joel");
  test_eq(NULL, d2->intro_point_extend_info);

  rend_service_descriptor_free(d1);
  rend_service_descriptor_free(d2);
  tor_free(encoded);

  /* Test versioned descriptor. */
  d1 = tor_malloc_zero(sizeof(rend_service_descriptor_t));
  d1->pk = crypto_pk_dup_key(pk1);
  now = time(NULL);
  d1->timestamp = now;
  d1->n_intro_points = 2;
  d1->version = 1;
  d1->protocols = 60;
  d1->intro_points = tor_malloc(sizeof(char*)*2);
  d1->intro_point_extend_info = tor_malloc(sizeof(extend_info_t*)*2);
  d1->intro_points[0] = tor_strdup("tom");
  d1->intro_points[1] = tor_strdup("crow");
  d1->intro_point_extend_info[0] = tor_malloc_zero(sizeof(extend_info_t));
  strcpy(d1->intro_point_extend_info[0]->nickname, "tom");
  d1->intro_point_extend_info[0]->addr = 1234;
  d1->intro_point_extend_info[0]->port = 4567;
  d1->intro_point_extend_info[0]->onion_key = crypto_pk_dup_key(pk1);
  memset(d1->intro_point_extend_info[0]->identity_digest, 'a', DIGEST_LEN);

  d1->intro_point_extend_info[1] = tor_malloc_zero(sizeof(extend_info_t));
  strcpy(d1->intro_point_extend_info[1]->nickname, "crow");
  d1->intro_point_extend_info[1]->addr = 6060842;
  d1->intro_point_extend_info[1]->port = 8000;
  d1->intro_point_extend_info[1]->onion_key = crypto_pk_dup_key(pk2);
  memset(d1->intro_point_extend_info[1]->identity_digest, 'b', DIGEST_LEN);

  test_assert(! rend_encode_service_descriptor(d1, 1, pk1, &encoded, &len));
  d2 = rend_parse_service_descriptor(encoded, len);
  test_assert(d2);

  test_assert(!crypto_pk_cmp_keys(d1->pk, d2->pk));
  test_eq(d2->timestamp, now);
  test_eq(d2->version, 1);
  test_eq(d2->protocols, 60);
  test_eq(d2->n_intro_points, 2);
  test_streq(d2->intro_points[0], d2->intro_point_extend_info[0]->nickname);
  test_streq(d2->intro_points[1], d2->intro_point_extend_info[1]->nickname);
  test_eq(d2->intro_point_extend_info[0]->addr, 1234);
  test_eq(d2->intro_point_extend_info[0]->port, 4567);
  test_assert(!crypto_pk_cmp_keys(pk1,
                                  d2->intro_point_extend_info[0]->onion_key));
  test_memeq(d2->intro_point_extend_info[0]->identity_digest,
             d1->intro_point_extend_info[0]->identity_digest, DIGEST_LEN);
  test_eq(d2->intro_point_extend_info[1]->addr, 6060842);
  test_eq(d2->intro_point_extend_info[1]->port, 8000);

  test_memeq(d2->intro_point_extend_info[1]->identity_digest,
             d1->intro_point_extend_info[1]->identity_digest, DIGEST_LEN);

  test_assert(BAD_HOSTNAME == parse_extended_hostname(address1));
  test_assert(ONION_HOSTNAME == parse_extended_hostname(address2));
  test_assert(EXIT_HOSTNAME == parse_extended_hostname(address3));
  test_assert(NORMAL_HOSTNAME == parse_extended_hostname(address4));

  rend_service_descriptor_free(d1);
  rend_service_descriptor_free(d2);
  crypto_free_pk_env(pk1);
  crypto_free_pk_env(pk2);
}

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

int
main(int c, char**v)
{
  or_options_t *options = options_new();
  char *errmsg = NULL;
  (void) c;
  (void) v;
  options->command = CMD_RUN_UNITTESTS;
  network_init();
  setup_directory();
  options_init(options);
  options->DataDirectory = tor_strdup(temp_dir);
  if (set_options(options, &errmsg) < 0) {
    printf("Failed to set initial options: %s\n", errmsg);
    tor_free(errmsg);
    return 1;
  }

  crypto_seed_rng();

  if (0) {
    bench_aes();
    return 0;
  }

  rep_hist_init();
  atexit(remove_directory);

  printf("Running Tor unit tests on %s\n", get_uname());

  puts("========================== Buffers =========================");
  test_buffers();
  puts("\n========================== Crypto ==========================");
  // add_stream_log(LOG_DEBUG, LOG_ERR, "<stdout>", stdout);
  test_crypto();
  test_crypto_dh();
  test_crypto_s2k();
  puts("\n========================= Util ============================");
  test_gzip();
  test_util();
  test_strmap();
  test_control_formats();
  test_pqueue();
  puts("\n========================= Onion Skins =====================");
  test_onion();
  test_onion_handshake();
  puts("\n========================= Directory Formats ===============");
  test_dir_format();
  puts("\n========================= Exit policies ===================");
  test_exit_policies();
  puts("\n========================= Rendezvous functionality ========");
  test_rend_fns();
  puts("");

  if (have_failed)
    return 1;
  else
    return 0;
}

