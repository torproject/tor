/**
 * ss.h
 * Standard structure processing.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.1  2002/04/02 14:28:01  badbytes
 * Final finishes.
 *
 */


#include "../common/ss.h"

int process_ss(int s, struct timeval *conn_toutp, ss_t **ssp, char **addrp, int *addrlenp, char **portp, int *portlenp);
