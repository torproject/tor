/* Copyright 2001-2004 Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file tor_main.c
 * \brief Stub module containing a main() function.
 *
 * We keep the main function in a separate module so that the unit
 * tests, which have their own main()s, can link against main.c.
 **/

int tor_main(int argc, char *argv[]);

/** We keep main() in a separate file so that our unit tests can use
 * functions from main.c.
 */
int
main(int argc, char *argv[])
{
  int r = tor_main(argc, argv);
  if (r < 0 || r > 255)
    return 1;
  else
    return r;
}

