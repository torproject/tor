/**
 * config.h 
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
 * Revision 1.4  2002/04/02 14:28:01  badbytes
 * Final finishes.
 *
 * Revision 1.3  2002/01/26 22:55:11  mp292
 * *** empty log message ***
 *
 * Revision 1.2  2002/01/26 22:22:09  mp292
 * Prevented duplicate definitions.
 *
 * Revision 1.1  2001/12/13 15:15:10  badbytes
 * Started coding the onion proxy.
 *
 */
#include "../common/config.h"

/* loads the configuration file */
int getconfig(char *filename, config_opt_t *options);
