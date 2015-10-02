/* Copyright (c) 2010-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include "or.h"

#include "test.h"

#define UTIL_FORMAT_PRIVATE
#include "util_format.h"

#define NS_MODULE util_format

static void
test_util_format_base64_encode(void *ignored)
{
  (void)ignored;
  int res;
  int i;
  char *src;
  char *dst;

  src = tor_malloc_zero(256);
  dst = tor_malloc_zero(1000);

  for (i=0;i<256;i++) {
    src[i] = (char)i;
  }

  res = base64_encode(NULL, 1, src, 1, 0);
  tt_int_op(res, OP_EQ, -1);

  res = base64_encode(dst, 1, NULL, 1, 0);
  tt_int_op(res, OP_EQ, -1);

  res = base64_encode(dst, 1, src, 10, 0);
  tt_int_op(res, OP_EQ, -1);

  res = base64_encode(dst, SSIZE_MAX-1, src, 1, 0);
  tt_int_op(res, OP_EQ, -1);

  res = base64_encode(dst, SSIZE_MAX-1, src, 10, 0);
  tt_int_op(res, OP_EQ, -1);

  res = base64_encode(dst, 1000, src, 256, 0);
  tt_int_op(res, OP_EQ, 344);
  tt_str_op(dst, OP_EQ, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh"
            "8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZH"
            "SElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3"
            "BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeY"
            "mZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wM"
            "HCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp"
            "6uvs7e7v8PHy8/T19vf4+fr7/P3+/w==");

  res = base64_encode(dst, 1000, src, 256, BASE64_ENCODE_MULTILINE);
  tt_int_op(res, OP_EQ, 350);
  tt_str_op(dst, OP_EQ,
          "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\n"
          "MDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f\n"
          "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P\n"
          "kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/\n"
          "wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v\n"
          "8PHy8/T19vf4+fr7/P3+/w==\n");

  res = base64_encode(dst, 1000, src+1, 255, BASE64_ENCODE_MULTILINE);
  tt_int_op(res, OP_EQ, 346);

  for (i = 0;i<50;i++) {
    src[i] = 0;
  }
  src[50] = 255;
  src[51] = 255;
  src[52] = 255;
  src[53] = 255;

  res = base64_encode(dst, 1000, src, 54, BASE64_ENCODE_MULTILINE);
  tt_int_op(res, OP_EQ, 74);

  res = base64_encode(dst, 1000, src+1, 53, BASE64_ENCODE_MULTILINE);
  tt_int_op(res, OP_EQ, 74);

  res = base64_encode(dst, 1000, src+2, 52, BASE64_ENCODE_MULTILINE);
  tt_int_op(res, OP_EQ, 74);

  res = base64_encode(dst, 1000, src+3, 51, BASE64_ENCODE_MULTILINE);
  tt_int_op(res, OP_EQ, 70);

  res = base64_encode(dst, 1000, src+4, 50, BASE64_ENCODE_MULTILINE);
  tt_int_op(res, OP_EQ, 70);

  res = base64_encode(dst, 1000, src+5, 49, BASE64_ENCODE_MULTILINE);
  tt_int_op(res, OP_EQ, 70);

  res = base64_encode(dst, 1000, src+6, 48, BASE64_ENCODE_MULTILINE);
  tt_int_op(res, OP_EQ, 65);

  res = base64_encode(dst, 1000, src+7, 47, BASE64_ENCODE_MULTILINE);
  tt_int_op(res, OP_EQ, 65);

  res = base64_encode(dst, 1000, src+8, 46, BASE64_ENCODE_MULTILINE);
  tt_int_op(res, OP_EQ, 65);

 done:
  tor_free(src);
  tor_free(dst);
}

static void
test_util_format_base64_decode_nopad(void *ignored)
{
  (void)ignored;
  int res;
  int i;
  char *src;
  uint8_t *dst;

  src = tor_malloc_zero(256);
  dst = tor_malloc_zero(1000);

  for (i=0;i<256;i++) {
    src[i] = (char)i;
  }

  res = base64_decode_nopad(dst, 1, src, SIZE_T_CEILING);
  tt_int_op(res, OP_EQ, -1);

  res = base64_decode_nopad(dst, 1, src, 5);
  tt_int_op(res, OP_EQ, -1);

  const char *s = "SGVsbG8gd29ybGQ";
  res = base64_decode_nopad(dst, 1000, s, strlen(s));
  tt_int_op(res, OP_EQ, 11);
  tt_mem_op(dst, OP_EQ, "Hello world", 11);

  s = "T3BhIG11bmRv";
  res = base64_decode_nopad(dst, 9, s, strlen(s));
  tt_int_op(res, OP_EQ, 9);
  tt_mem_op(dst, OP_EQ, "Opa mundo", 9);

 done:
  tor_free(src);
  tor_free(dst);
}

static void
test_util_format_base64_decode(void *ignored)
{
  (void)ignored;
  int res;
  int i;
  char *src;
  char *dst;

  src = tor_malloc_zero(256);
  dst = tor_malloc_zero(1000);

  for (i=0;i<256;i++) {
    src[i] = (char)i;
  }

  res = base64_decode(dst, 1, src, SIZE_T_CEILING);
  tt_int_op(res, OP_EQ, -1);

  res = base64_decode(dst, SIZE_T_CEILING+1, src, 10);
  tt_int_op(res, OP_EQ, -1);

  const char *s = "T3BhIG11bmRv";
  res = base64_decode(dst, 9, s, strlen(s));
  tt_int_op(res, OP_EQ, 9);
  tt_mem_op(dst, OP_EQ, "Opa mundo", 9);

  memset(dst, 0, 1000);
  res = base64_decode(dst, 100, s, strlen(s));
  tt_int_op(res, OP_EQ, 9);
  tt_mem_op(dst, OP_EQ, "Opa mundo", 9);

  s = "SGVsbG8gd29ybGQ=";
  res = base64_decode(dst, 100, s, strlen(s));
  tt_int_op(res, OP_EQ, 11);
  tt_mem_op(dst, OP_EQ, "Hello world", 11);

 done:
  tor_free(src);
  tor_free(dst);
}

static void
test_util_format_base16_decode(void *ignored)
{
  (void)ignored;
  int res;
  int i;
  char *src;
  char *dst;

  src = tor_malloc_zero(256);
  dst = tor_malloc_zero(1000);

  for (i=0;i<256;i++) {
    src[i] = (char)i;
  }

  res = base16_decode(dst, 3, src, 3);
  tt_int_op(res, OP_EQ, -1);

  res = base16_decode(dst, 1, src, 10);
  tt_int_op(res, OP_EQ, -1);

  res = base16_decode(dst, SIZE_T_CEILING+2, src, 10);
  tt_int_op(res, OP_EQ, -1);

  res = base16_decode(dst, 1000, "", 0);
  tt_int_op(res, OP_EQ, 0);

  res = base16_decode(dst, 1000, "aabc", 4);
  tt_int_op(res, OP_EQ, 0);
  tt_mem_op(dst, OP_EQ, "\xaa\xbc", 2);

  res = base16_decode(dst, 1000, "aabcd", 6);
  tt_int_op(res, OP_EQ, -1);

  res = base16_decode(dst, 1000, "axxx", 4);
  tt_int_op(res, OP_EQ, -1);

 done:
  tor_free(src);
  tor_free(dst);
}

struct testcase_t util_format_tests[] = {
  { "base64_encode", test_util_format_base64_encode, 0, NULL, NULL },
  { "base64_decode_nopad", test_util_format_base64_decode_nopad, 0,
    NULL, NULL },
  { "base64_decode", test_util_format_base64_decode, 0, NULL, NULL },
  { "base16_decode", test_util_format_base16_decode, 0, NULL, NULL },
  END_OF_TESTCASES
};

