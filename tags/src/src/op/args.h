/**
 * args.h 
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
 * Revision 1.4  2002/01/26 22:22:09  mp292
 * Prevented duplicate definitions.
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

#ifndef __ARGS_H

#define __ARGS_H

#include <stdlib.h>
#include <stdio.h>

/* print help */
void print_usage();

/* get command-line arguments */
int getargs(int argc,char *argv[], char *args, unsigned short *p, char **conf_filename, int *loglevel);

#endif
