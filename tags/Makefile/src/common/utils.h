/*
 * utils.h
 * Miscellaneous utils.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.8  2002/03/21 07:20:59  badbytes
 * Added a dependency to <sys/time.h>.
 *
 * Revision 1.7  2002/03/03 00:06:45  mp292
 * Modifications to support re-transmission.
 *
 * Revision 1.6  2002/01/29 02:22:41  mp292
 * Bugfix.
 *
 * Revision 1.5  2002/01/29 00:58:23  mp292
 * Timeout parametes to read_tout() and write_tout() are now pointers.
 *
 * Revision 1.4  2002/01/27 19:24:16  mp292
 * Added read_tout(), write_tout() which read/write from a blocking socket but
 * impose a timeout on the I/O operation.
 *
 * Revision 1.3  2002/01/26 19:30:09  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.2  2001/12/18 10:37:47  badbytes
 * Header files now only apply if they were not previously included from somewhere else.
 *
 * Revision 1.1  2001/12/14 09:18:00  badbytes
 * *** empty log message ***
 *
 */

#ifndef __UTILS_H

#include <sys/types.h>
#include <sys/un.h>
#include <sys/time.h>

unsigned char *stolower(unsigned char *str);
int read_tout(int s, unsigned char *buf, size_t buflen, int flags, struct timeval *conn_tout);
int write_tout(int s, unsigned char *buf, size_t buflen, struct timeval *conn_tout);

#define __UTILS_H

#endif
