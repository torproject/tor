#include "or.h"

int main(int ac, char **av)
{
   or_options_t options;
   int argc, rtn_val, failures, total;
   char fname[512];
   FILE *pipe;
   char *argv[] = { "or", "-v", "-f", fname, NULL };
   argc = 4;
   failures = total = 0;
   printf("Config file test suite...\n\n");
   pipe = popen("ls -1 ../config/*orrc","r");
   while ( fgets(fname,sizeof(fname),pipe) )
   {
      fname[strlen(fname)-1] = '\0';
      printf("%s\n--------------------\n", fname);
      rtn_val = getoptions(argc,argv,&options);
      ++total;
      if ( rtn_val)
      {
         ++failures;
         printf("Test failed!\n\n");
      }
      else
         printf("Test succeeded\n\n");
   }
   printf("%6.2f percent. %d failures.\n",(total - failures)*100/(float)total,failures);
   return failures;
}
