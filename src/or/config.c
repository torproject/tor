/**
 * config.c 
 * Routines for loading the configuration file.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.3  2002/04/02 14:28:24  badbytes
 * Final finishes.
 *
 * Revision 1.2  2002/01/27 00:42:50  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.1  2002/01/03 10:24:05  badbytes
 * COde based on that in op. Needs to be modified.
 *
 */

#include "or.h"

/* loads the configuration file */
int getconfig(char *conf_filename, config_opt_t *options)
{
  FILE *cf = NULL;
  int retval = 0;
  
  if ((!conf_filename) || (!options))
    return -1;
  
  /* load config file */
  cf = open_config(conf_filename);
  if (!cf)
  {
    log(LOG_ERR,"Could not open configuration file %s.",conf_filename);
    return -1;
  }
  retval = parse_config(cf,options);
  if (retval)
    return -1;

  return 0;
}

