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
 * Revision 1.3  2002/01/26 22:08:40  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.2  2001/12/14 11:26:23  badbytes
 * Tested
 *
 * Revision 1.1  2001/12/13 15:15:10  badbytes
 * Started coding the onion proxy.
 *
 */

#include <unistd.h>
#include <ctype.h>

#include "../common/log.h"
#include "args.h"

/* prints help on using op */
void print_usage()
{
  char *program = "op";
  
  printf("\n%s - Onion Proxy for Onion Routing.\nUsage : %s -f config -p port [-l loglevel -h]\n-h : display this help\n-f config : config file\n-p port : port number which %s should bind to\n-l loglevel : logging threshold; one of alert|crit|err|warning|notice|info|debug\n\n", program,program,program);
}

/* get command-line arguments */
int getargs(int argc, char *argv[], char *args, unsigned short *p, char **conf_filename, int *loglevel)
{
  char c; /* next option character */
  char *errtest = NULL; /* for detecting strtoul() errors */
  int gotf=0; int gotp=0;
  
  if ((!args) || (!conf_filename) || (!loglevel)) /* invalid parameters */
    return -1;
  
  while ((c = getopt(argc,argv,args)) != -1)
  {
    switch(c)
    {
     case 'f': /* config file */
      *conf_filename = optarg;
      gotf=1;
      break;
     case 'p':
      *p = (u_short)strtoul(optarg,&errtest,0);
      if (errtest == optarg) /* error */
      {
	log(LOG_ERR,"Error : -p must be followed by an unsigned positive integer value. See help (-h).");
        return -1;
      }
      gotp=1;
      break;
     case 'h':
      print_usage();
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
	print_usage();
	return -1;
      }
      break;
     case '?':
      if (isprint(c))
	log(LOG_ERR,"Missing argument or unknown option '-%c'. See help (-h).",optopt);
      else
	log(LOG_ERR,"Unknown option character 'x%x'. See help (-h).",optopt);
      print_usage();
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
  
  /* the -p option is mandatory */
  if (!gotp)
  {
    log(LOG_ERR,"You must specify a port with the -p option. See help (-h).");
    return -1;
  }
    
  return 0;
}
