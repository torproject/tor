/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include <stdio.h>
#include <fcntl.h>

#include "or.h"
#include "../common/test.h"

void
setup_directory() {
  char buf[256];
  sprintf(buf, "/tmp/tor_test");
  if (mkdir(buf, 0700) && errno != EEXIST)
    fprintf(stderr, "Can't create directory %s", buf);
}

void
test_buffers() {
  char str[256];
  char str2[256];

  char *buf;
  int buflen, buf_datalen;

  char *buf2;
  int buf2len, buf2_datalen;

  int s, i, j, eof;
  z_compression *comp;
  z_decompression *decomp;

  /****
   * buf_new
   ****/
  if (buf_new(&buf, &buflen, &buf_datalen))
    test_fail();

  test_eq(buflen, MAX_BUF_SIZE);
  test_eq(buf_datalen, 0);

  /****
   * read_to_buf
   ****/
  s = open("/tmp/tor_test/data", O_WRONLY|O_CREAT|O_TRUNC, 0600);
  for (j=0;j<256;++j) {
    str[j] = (char)j;
  }
  write(s, str, 256);
  close(s);
  
  s = open("/tmp/tor_test/data", O_RDONLY, 0);
  eof = 0;
  i = read_to_buf(s, 10, &buf, &buflen, &buf_datalen, &eof);
  test_eq(buflen, MAX_BUF_SIZE);
  test_eq(buf_datalen, 10);
  test_eq(eof, 0);
  test_eq(i, 10);
  test_memeq(str, buf, 10);

  /* Test reading 0 bytes. */
  i = read_to_buf(s, 0, &buf, &buflen, &buf_datalen, &eof);
  test_eq(buflen, MAX_BUF_SIZE);
  test_eq(buf_datalen, 10);
  test_eq(eof, 0);
  test_eq(i, 0);

  /* Now test when buffer is filled exactly. */
  buflen = 16;
  i = read_to_buf(s, 6, &buf, &buflen, &buf_datalen, &eof);
  test_eq(buflen, 16);
  test_eq(buf_datalen, 16);
  test_eq(eof, 0);
  test_eq(i, 6);
  test_memeq(str, buf, 16);
  
  /* Now test when buffer is filled with more data to read. */
  buflen = 32;
  i = read_to_buf(s, 128, &buf, &buflen, &buf_datalen, &eof);
  test_eq(buflen, 32);
  test_eq(buf_datalen, 32);
  test_eq(eof, 0);
  test_eq(i, 16);
  test_memeq(str, buf, 32);

  /* Now read to eof. */
  buflen = MAX_BUF_SIZE;
  test_assert(buflen > 256);
  i = read_to_buf(s, 1024, &buf, &buflen, &buf_datalen, &eof);
  test_eq(i, (256-32));
  test_eq(buflen, MAX_BUF_SIZE);
  test_eq(buf_datalen, 256);
  test_memeq(str, buf, 256);
  test_eq(eof, 0);

  i = read_to_buf(s, 1024, &buf, &buflen, &buf_datalen, &eof);
  test_eq(i, 0);
  test_eq(buflen, MAX_BUF_SIZE);
  test_eq(buf_datalen, 256);
  test_eq(eof, 1);

  close(s);

  /**** 
   * find_on_inbuf
   ****/

  test_eq(((int)'d') + 1, find_on_inbuf("abcd", 4, buf, buf_datalen));
  test_eq(-1, find_on_inbuf("xyzzy", 5, buf, buf_datalen));
  /* Make sure we don't look off the end of the buffef */
  buf[256] = 'A';
  buf[257] = 'X';
  test_eq(-1, find_on_inbuf("\xff" "A", 2, buf, buf_datalen));
  test_eq(-1, find_on_inbuf("AX", 2, buf, buf_datalen));
  /* Make sure we use the string length */
  test_eq(((int)'d')+1, find_on_inbuf("abcdX", 4, buf, buf_datalen));

  /****
   * fetch_from_buf
   ****/
  memset(str2, 255, 256);
  test_eq(246, fetch_from_buf(str2, 10, &buf, &buflen, &buf_datalen));
  test_memeq(str2, str, 10);
  test_memeq(str+10,buf,246);
  test_eq(buf_datalen,246);

  test_eq(-1, fetch_from_buf(str2, 247, &buf, &buflen, &buf_datalen));
  test_memeq(str+10,buf,246);
  test_eq(buf_datalen, 246);
  
  test_eq(0, fetch_from_buf(str2, 246, &buf, &buflen, &buf_datalen));
  test_memeq(str2, str+10, 246);
  test_eq(buflen,MAX_BUF_SIZE);
  test_eq(buf_datalen,0);

  /****
   * write_to_buf
   ****/
  memset(buf, (int)'-', 256);
  i = write_to_buf("Hello world", 11, &buf, &buflen, &buf_datalen);
  test_eq(i, 11);
  test_eq(buf_datalen, 11);
  test_memeq(buf, "Hello world", 11);
  i = write_to_buf("XYZZY", 5, &buf, &buflen, &buf_datalen);
  test_eq(i, 16);
  test_eq(buf_datalen, 16);
  test_memeq(buf, "Hello worldXYZZY", 16);
  /* Test when buffer is overfull. */
  buflen = 18;
  test_eq(-1, write_to_buf("This string will not fit.", 25, 
                           &buf, &buflen, &buf_datalen));
  test_eq(buf_datalen, 16);
  test_memeq(buf, "Hello worldXYZZY--", 18);
  buflen = MAX_BUF_SIZE;

  /****
   * flush_buf
   ****/

  /***
   * compress_from_buf (simple)
   ***/
  buf_datalen = 0;
  comp = compression_new();
  for (i = 0; i < 20; ++i) {
    write_to_buf("Hello world.  ", 14, &buf, &buflen, &buf_datalen);
  }
  i = compress_from_buf(str, 256, &buf, &buflen, &buf_datalen, comp, 1);
  test_eq(buf_datalen, 0);
  /*
  for (j = 0; j <i ; ++j) {
    printf("%x '%c'\n", ((int) str[j])&0xff, str[j]);
  }
  */
  /* Now try decompressing. */
  decomp = decompression_new();
  if (buf_new(&buf2, &buf2len, &buf2_datalen))
    test_fail();
  buf_datalen = 0;
  test_eq(i, write_to_buf(str, i, &buf, &buflen, &buf_datalen));
  j = decompress_buf_to_buf(&buf, &buflen, &buf_datalen,
                            &buf2, &buf2len, &buf2_datalen,
                            decomp, 1);
  /*XXXX check result */
  
  /* Now compress more, into less room. */
  for (i = 0; i < 20; ++i) {
    write_to_buf("Hello wxrlx.  ", 14, &buf, &buflen, &buf_datalen);
  }
  i = compress_from_buf(str, 256, &buf, &buflen, &buf_datalen, comp, 1);
  
  test_eq(buf_datalen, 0);
  
  

  compression_free(comp);
  decompression_free(decomp);
  
  

  buf_free(buf);
  buf_free(buf2);
}


int main(int c, char**v) {
  setup_directory();

  test_buffers();

  printf("\n");
  return 0;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
