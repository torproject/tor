/**
 * args.c 
 * Routines for processing command-line arguments.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.3  2002/01/27 00:42:50  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.2  2002/01/04 10:05:28  badbytes
 * Completed.
 *
 * Revision 1.1  2002/01/03 10:23:43  badbytes
 * Code based on that in op. Needs to be modified.
 */

#include "or.h"

/* prints help on using or */
void print_usage()
{
  char *program = "or";
  printf("\n%s - Onion Router.\nUsage : %s -f config [-l loglevel -h]\n-h : display this help\n-f config : config file\n-l loglevel : logging threshold; one of alert|crit|err|warning|notice|info|debug\n\n", program,program);
}


/* get command-line arguments */
int getargs(int argc,char *argv[], char *args, char **conf_filename, int *loglevel)
{
  char c; /* next option character */
  int gotf=0;

  if ((!args) || (!conf_filename) || (!loglevel))
    return -1;
  
  while ((c = getopt(argc,argv,args)) != -1)
  {
    switch(c)
    {
     case 'f': /* config file */
      *conf_filename = optarg;
      gotf=1;
      break;
     case 'h':
      print_usage(argv[0]);
      exit(0);
     case 'l':
      if (!strcmp(optarg,"emerg"))
	*loglevel = LOG_EMERG;
      else if (!strcmp(optarg,"alert"))
	*loglevel = LOG_ALERT;
      else if (!strcmp(optarg,"crit"))
	*loglevel = LOG_CRIT;
      else if (!strcmp(optarg,"err"))
	*loglevel = LOG_ERR;
      else if (!strcmp(optarg,"warning"))
	*loglevel = LOG_WARNING;
      else if (!strcmp(optarg,"notice"))
	*loglevel = LOG_NOTICE;
      else if (!strcmp(optarg,"info"))
	*loglevel = LOG_INFO;
      else if (!strcmp(optarg,"debug"))
	*loglevel = LOG_DEBUG;
      else
      {
	log(LOG_ERR,"Error : argument to -l must be one of alert|crit|err|warning|notice|info|debug.");
	print_usage(argv[0]);
	return -1;
      }
      break;
     case '?':
      if (isprint(c))
	log(LOG_ERR,"Missing argument or unknown option '-%c'. See help (-h).",optopt);
      else
	log(LOG_ERR,"Unknown option character 'x%x'. See help (-h).",optopt);
      print_usage(argv[0]);
      return -1;
      break;
     default:
      return -1;
    }
  }
  
  /* the -f option is mandatory */
  if (!gotf)
  {
    log(LOG_ERR,"You must specify a config file with the -f option. See help (-h).");
    return -1;
  }
  
  return 0;
}
