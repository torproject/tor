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
 * Revision 1.3  2002/04/02 14:28:01  badbytes
 * Final finishes.
 *
 * Revision 1.2  2002/01/26 22:09:53  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.1  2001/12/13 15:15:10  badbytes
 * Started coding the onion proxy.
 *
 */

#include "config.h"
#include "../common/log.h"

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
