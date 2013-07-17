/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define BUFFERS_PRIVATE
#include "or.h"
#include "buffers.h"
#include "test.h"

/** Run unit tests for buffers.c */
static void
test_buffers_basic(void *arg)
{
  char str[256];
  char str2[256];

  buf_t *buf = NULL, *buf2 = NULL;
  const char *cp;

  int j;
  size_t r;
  (void) arg;

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

  /* Try adding a string too long for any freelist. */
  {
    char *cp = tor_malloc_zero(65536);
    buf = buf_new();
    write_to_buf(cp, 65536, buf);
    tor_free(cp);

    tt_int_op(buf_datalen(buf), ==, 65536);
    buf_free(buf);
    buf = NULL;
  }

 done:
  if (buf)
    buf_free(buf);
  if (buf2)
    buf_free(buf2);
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

struct testcase_t buffer_tests[] = {
  { "basic", test_buffers_basic, 0, NULL, NULL },
  { "copy", test_buffer_copy, 0, NULL, NULL },
  END_OF_TESTCASES
};

