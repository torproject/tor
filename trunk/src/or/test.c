/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"
#include "../common/test.h"

void
test_buffers() {
  char *buf;
  int buflen, buf_datalen;

  if (buf_new(&buf, &buflen, &buf_datalen)) {
    test_fail();
  }

  test_eq(buflen, MAX_BUF_SIZE);
  test_eq(buf_datalen, 0);

  

  buf_free(buf);
}


int main(int c, char**v) {
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
