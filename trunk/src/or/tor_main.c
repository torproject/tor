/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

/*****
 * tor_main.c: Entry point for tor binary.  (We keep main() in a
 * separate file so that our unit tests can use functions from main.c)
 *****/

int tor_main(int argc, char *argv[]);

int main(int argc, char *argv[])
{
  return tor_main(argc, argv);
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
