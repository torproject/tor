/*
 * ss.h
 * Standard structure and related definitions.
 * 
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.5  2002/04/02 14:27:11  badbytes
 * Final finishes.
 *
 * Revision 1.4  2002/01/26 22:45:34  mp292
 * Added ss-related error codes.
 *
 * Revision 1.3  2002/01/26 19:30:09  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.2  2001/12/18 10:37:47  badbytes
 * Header files now only apply if they were not previously included from somewhere else.
 *
 * Revision 1.1  2001/12/14 13:14:03  badbytes
 * Split types.h into routent.h and ss.h. Keeping them all in one file created unnecesary dependencies.
 *
 * Revision 1.2  2001/12/11 16:31:03  badbytes
 * Changed type from ss to SS.
 *
 * Revision 1.1  2001/12/07 11:15:28  badbytes
 * Added the definition for the standard structure.
 *
 */

#ifndef __SS_H

/* protocol types, as used in the standard structure */
#define SS_PROTOCOL_TELNET 1
#define SS_PROTOCOL_HTTP   2
#define SS_PROTOCOL_SMTP   3

/* address format types, as used in the standard structure */
#define SS_ADDR_FMT_ASCII_HOST_PORT 1

/* error codes returned by the onion proxy */
#define SS_ERROR_SUCCESS 0
#define SS_ERROR_VERSION_UNSUPPORTED 1
#define SS_ERROR_ADDR_FMT_UNSUPPORTED 2
#define SS_ERROR_INVALID_ADDRESS 3
#define SS_ERROR_INVALID_PORT 4

/* standard structure */
typedef struct
{
  unsigned char version; /* version */
  unsigned char protocol; /* protocol */
  unsigned char retry_count; /* retry count */
  unsigned char addr_fmt; /* address format */
} ss_t;
#define __SS_H
#endif
