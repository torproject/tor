/*
 * log.h
 * Logging facilities.
 * 
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.5  2002/01/26 18:52:00  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.4  2001/12/18 10:37:47  badbytes
 * Header files now only apply if they were not previously included from somewhere else.
 *
 * Revision 1.3  2001/12/07 09:38:03  badbytes
 * Tested.
 *
 * Revision 1.2  2001/12/06 15:43:50  badbytes
 * config.c compiles. Proceeding to test it.
 *
 * Revision 1.1  2001/11/21 23:03:41  mp292
 * log function coded and tested.
 * Top-level makefile.
 *
 */

#ifndef __LOG_H

#include <syslog.h>

/* Outputs a message to stdout and also logs the same message using syslog. */
void log(int severity, const char *format, ...);

# define __LOG_H
#endif
