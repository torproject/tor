#include <stdio.h>

/** Trivial test program which prints out its command line arguments so we can
 * check if tor_spawn_background() works */
int
main(int argc, char **argv)
{
  int i;

  fprintf(stdout, "OUT\n");
  fprintf(stderr, "ERR\n");
  for (i = 0; i < argc; i++)
    fprintf(stdout, "%s\n", argv[i]);
  fprintf(stdout, "DONE\n");

  return 0;
}

