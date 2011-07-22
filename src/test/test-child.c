#include <stdio.h>
#include "orconfig.h"
#ifdef MS_WINDOWS
#define WINDOWS_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#endif

/** Trivial test program which prints out its command line arguments so we can
 * check if tor_spawn_background() works */
int
main(int argc, char **argv)
{
  int i;

  fprintf(stdout, "OUT\n");
  fprintf(stderr, "ERR\n");
  for (i = 1; i < argc; i++)
    fprintf(stdout, "%s\n", argv[i]);
  fprintf(stdout, "SLEEPING\n");
#ifdef MS_WINDOWS
  Sleep(1000);
#else
  sleep(1);
#endif
  fprintf(stdout, "DONE\n");
#ifdef MS_WINDOWS
  Sleep(1000);
#else
  sleep(1);
#endif

  return 0;
}

